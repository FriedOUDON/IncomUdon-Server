package main

import (
	"encoding/json"
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

func TestDirectoryPublisherRequiresExplicitEnablement(t *testing.T) {
	publisher, err := newDirectoryPublisher(directoryPublisherConfig{
		ChannelsCSV: "unexpected.csv",
	})
	if err != nil || publisher != nil {
		t.Fatalf("disabled directory publisher = (%#v, %v), want (nil, nil)", publisher, err)
	}

	if _, err := newDirectoryPublisher(directoryPublisherConfig{Enabled: true}); err == nil {
		t.Fatal("enabled directory publisher accepted incomplete configuration")
	}
}

func TestDirectoryParticipantsExcludesAddressesAndSorts(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	srv := &server{
		channels: map[uint32]*channel{
			200: {
				peers: map[string]*peer{
					"newer": {senderId: 20, lastSeen: now.Add(2 * time.Second)},
					"older": {senderId: 20, lastSeen: now},
					"first": {senderId: 10, lastSeen: now.Add(time.Second)},
				},
				activeTalkers: map[uint32]time.Time{20: now},
			},
			100: {
				peers: map[string]*peer{
					"other": {senderId: 30, lastSeen: now.Add(3 * time.Second)},
				},
				activeTalkers: map[uint32]time.Time{},
			},
		},
	}

	got := srv.directoryParticipants()
	want := []directoryParticipant{
		{ChannelID: 100, SenderID: 30, LastSeenAt: now.Add(3 * time.Second).Unix()},
		{ChannelID: 200, SenderID: 10, LastSeenAt: now.Add(time.Second).Unix()},
		{ChannelID: 200, SenderID: 20, LastSeenAt: now.Add(2 * time.Second).Unix(), Talking: true},
	}
	if len(got) != len(want) {
		t.Fatalf("participant count = %d, want %d: %#v", len(got), len(want), got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("participant %d = %#v, want %#v", index, got[index], want[index])
		}
	}
}

func TestDirectoryPublisherAcceptsAuthenticatedPullOnce(t *testing.T) {
	psk := []byte("01234567890123456789012345678901")
	now := time.Now()
	request := directoryRequest{
		Version:   directoryProtocolVersion,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(10 * time.Second).Unix(),
	}
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := sealDirectoryEnvelope(psk, "pwa-1", []byte("directory-epoch!"), 1, request.ExpiresAt, payload, directoryEnvelopeRequest)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	publisher := &directoryPublisher{psk: psk, keyID: "pwa-1", replay: make(map[string]directoryReplayState)}
	if err := publisher.openRequest(packet); err != nil {
		t.Fatalf("openRequest() error = %v", err)
	}
	if err := publisher.openRequest(packet); err == nil {
		t.Fatal("openRequest() accepted replayed request")
	}
}
