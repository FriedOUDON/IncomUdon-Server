package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDirectoryDocumentSortsAndValidatesCSV(t *testing.T) {
	dir := t.TempDir()
	channelsPath := filepath.Join(dir, "channels.csv")
	speakersPath := filepath.Join(dir, "speakers.csv")
	if err := os.WriteFile(channelsPath, []byte("channel_id,name\n102,Maintenance\n101,Operations\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(speakersPath, []byte("channel_id,sender_id,name\n102,2001,Maintenance Lead\n101,1002,Field Team\n101,1001,Dispatch\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	document, err := loadDirectoryDocument(channelsPath, speakersPath, time.Unix(1000, 0), 90*time.Second)
	if err != nil {
		t.Fatalf("loadDirectoryDocument() error = %v", err)
	}
	if document.Version != directoryProtocolVersion || document.ExpiresAt != 1090 || len(document.Revision) != 64 {
		t.Fatalf("unexpected document metadata: %#v", document)
	}
	if got := document.Channels[0]; got.ChannelID != 101 || got.Name != "Operations" {
		t.Fatalf("channels were not sorted: %#v", document.Channels)
	}
	if got := document.Speakers[0]; got.ChannelID != 101 || got.SenderID != 1001 || got.Name != "Dispatch" {
		t.Fatalf("speakers were not sorted: %#v", document.Speakers)
	}
}

func TestLoadDirectoryDocumentRejectsUnknownSpeakerChannel(t *testing.T) {
	dir := t.TempDir()
	channelsPath := filepath.Join(dir, "channels.csv")
	speakersPath := filepath.Join(dir, "speakers.csv")
	if err := os.WriteFile(channelsPath, []byte("101,Operations\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(speakersPath, []byte("102,1001,Dispatch\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDirectoryDocument(channelsPath, speakersPath, time.Now(), time.Minute); err == nil {
		t.Fatal("loadDirectoryDocument() accepted an unknown speaker channel")
	}
}

func TestLoadDirectoryDocumentExpandsAllSpeakerNamesWithChannelOverrides(t *testing.T) {
	dir := t.TempDir()
	channelsPath := filepath.Join(dir, "channels.csv")
	speakersPath := filepath.Join(dir, "speakers.csv")
	if err := os.WriteFile(channelsPath, []byte("101,Operations\n102,Maintenance\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(speakersPath, []byte("all,1001,Dispatch\nall,1002,Field Team\n101,1003,Operations Lead\n102,1001,Maintenance Dispatch\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	document, err := loadDirectoryDocument(channelsPath, speakersPath, time.Unix(1000, 0), 90*time.Second)
	if err != nil {
		t.Fatalf("loadDirectoryDocument() error = %v", err)
	}
	want := []directorySpeaker{
		{ChannelID: 101, SenderID: 1001, Name: "Dispatch"},
		{ChannelID: 101, SenderID: 1002, Name: "Field Team"},
		{ChannelID: 101, SenderID: 1003, Name: "Operations Lead"},
		{ChannelID: 102, SenderID: 1001, Name: "Maintenance Dispatch"},
		{ChannelID: 102, SenderID: 1002, Name: "Field Team"},
	}
	if len(document.Speakers) != len(want) {
		t.Fatalf("speaker count = %d, want %d: %#v", len(document.Speakers), len(want), document.Speakers)
	}
	for index := range want {
		if document.Speakers[index] != want[index] {
			t.Fatalf("speaker %d = %#v, want %#v", index, document.Speakers[index], want[index])
		}
	}
}

func TestLoadDirectoryDocumentRejectsDuplicateAllSpeaker(t *testing.T) {
	dir := t.TempDir()
	channelsPath := filepath.Join(dir, "channels.csv")
	speakersPath := filepath.Join(dir, "speakers.csv")
	if err := os.WriteFile(channelsPath, []byte("101,Operations\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(speakersPath, []byte("all,1001,Dispatch\nall,1001,Duplicate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDirectoryDocument(channelsPath, speakersPath, time.Now(), time.Minute); err == nil {
		t.Fatal("loadDirectoryDocument() accepted duplicate all/sender_id")
	}
}
