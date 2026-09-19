package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func directoryV3TestMaterial(t *testing.T) directoryKeyMaterial {
	t.Helper()
	passwordKey, err := hex.DecodeString("6c63ca4d97d0866372c0a8e13b4a79db4970b48687964d0445c6354e39c41005")
	if err != nil {
		t.Fatal(err)
	}
	channelKey, err := hkdfSHA256(passwordKey, nil, directoryChannelInfo, 32)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(channelKey), "174209da75aa25b4f917342071659c2e4d15a1b3b38fd82fad83d519c32cf17e"; got != want {
		t.Fatalf("directory_channel_key = %s, want %s", got, want)
	}
	material, err := newDirectoryKeyMaterial(channelKey)
	if err != nil {
		t.Fatal(err)
	}
	return material
}

func TestDirectoryV3OpensCanonicalRequestAndBindsTransport(t *testing.T) {
	material := directoryV3TestMaterial(t)
	keys := directoryKeyStore{111: material}
	datagram := []byte(`{"v":3,"type":"request","channelId":111,"epoch":"ZGlyZWN0b3J5LWVwb2NoIQ","sequence":1,"expiresAt":1700000010,"ciphertext":"b6RluZd8-5m8N7Rr5HzmyiOpYbvdbGuXHyEGROE_TRXK3NAgynTVfJC1VW1flLE9eTKGCFw7sAm078TCmGBLZh28eZhDUmig6nNaE7nCZoD0dO0vkhHdxG08X-JarQUXOWGWJV2wSaXv9fNHkIeLGXq8O-kM5T4EECpAPmvKv80Q3w5SDXXrEUs"}`)
	now := time.Unix(1700000001, 0)
	opened, err := openDirectoryDatagram(datagram, directoryTransportDedicated, keys, now)
	if err != nil {
		t.Fatalf("open canonical dedicated request: %v", err)
	}
	if opened.request == nil || opened.request.RequestID != "AAECAwQFBgcICQoLDA0ODw" || opened.request.Resource != "participants" {
		t.Fatalf("opened request = %#v", opened.request)
	}
	if _, err := openDirectoryDatagram(datagram, directoryTransportMedia, keys, now); err == nil {
		t.Fatal("dedicated datagram authenticated with media-port binding")
	}
}

func TestDirectoryV3SealsCanonicalMediaFragment(t *testing.T) {
	material := directoryV3TestMaterial(t)
	epoch, err := decodeCanonicalDirectoryID("cmVsYXktZGlyZWN0b3J5IQ")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"version":3,"issuedAt":1700000000,"expiresAt":1700000090,"requestId":"AAECAwQFBgcICQoLDA0ODw","fragment":{"responseId":"EBESExQVFhcYGRobHB0eHw","index":0,"count":3},"participants":[{"channelId":111,"senderId":1001,"lastSeenAt":1700000000,"talking":false}]}`)
	got, err := sealDirectoryDatagram(plaintext, "participants", 111, material, epoch, 10, 1700000090, directoryTransportMedia)
	if err != nil {
		t.Fatalf("seal media fragment: %v", err)
	}
	if !bytes.HasPrefix(got, append(append([]byte(nil), directoryCarrierMagic...), byte(directoryCarrierVersion))) {
		t.Fatalf("media carrier = %x", got[:5])
	}
	var envelope directoryEnvelope
	if err := json.Unmarshal(got[5:], &envelope); err != nil {
		t.Fatal(err)
	}
	const expectedCiphertext = "OKzOYXDVfi8BdDo-9KaosHFo1woiqeMnM5P3DtdquoipDsvulKkgPtiZT5eh55NfmT2sjmrI2snusHanEvBnEN71naLUqeTkE2JkFnVDoSXsC4uLRXarmc1wEksX9uCL91-3JKtcs0FNnYZ9hCRWHx82XJbhDsa9-0MAHB_VX6miKspxHvDWnXydNjcweBkkGNVVLHNxft2UIUh5PcFpjfoPf4l0QJhis2S_8jTk4iW6qct-wJ73hQSF8On2u_EM7907AyJ2nZvjKQIG1F9IQsSpTDDStsbqO6R63hBnp-G6ra5sOKl1OZbo_t5MV4jT8fvOmEu9DUIV_G1jj4YANSE9PBE3VbpN_IE4NDL7WEyh"
	if envelope.Ciphertext != expectedCiphertext {
		t.Fatalf("ciphertext = %s, want %s", envelope.Ciphertext, expectedCiphertext)
	}
	if len(got) != 500 {
		t.Fatalf("carrier datagram length = %d, want 500", len(got))
	}
}

func TestDirectoryV3CanonicalIdentifiers(t *testing.T) {
	for _, test := range []struct {
		value string
		valid bool
	}{
		{"ZGlyZWN0b3J5LWVwb2NoIQ", true},
		{"ZGlyZWN0b3J5LWVwb2NoIR", false},
		{"AAECAwQFBgcICQoLDA0ODw=", false},
		{"AAECAwQFBgcICQoLDA0O", false},
	} {
		_, err := decodeCanonicalDirectoryID(test.value)
		if (err == nil) != test.valid {
			t.Errorf("decodeCanonicalDirectoryID(%q) error=%v, valid=%t", test.value, err, test.valid)
		}
	}
}

func TestDirectoryV3ReplayWindowBoundaries(t *testing.T) {
	state := directoryReplayState{initialized: true, highest: 100, seen: 1}
	if !state.accept(37) {
		t.Fatal("oldest sequence inside 64-entry window was rejected")
	}
	if state.accept(36) {
		t.Fatal("sequence outside 64-entry window was accepted")
	}
	if state.accept(37) {
		t.Fatal("duplicate sequence was accepted")
	}
}

func TestLoadDirectoryKeyStore(t *testing.T) {
	key := make([]byte, 32)
	for index := range key {
		key[index] = byte(index + 1)
	}
	path := filepath.Join(t.TempDir(), "directory-keys.csv")
	contents := "# relay-only directory key\nchannel_id,directory_channel_key_base64url\n111," + base64.RawURLEncoding.EncodeToString(key) + "\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := loadDirectoryKeyStore(path, secretFilePermissionsOff)
	if err != nil {
		t.Fatalf("loadDirectoryKeyStore: %v", err)
	}
	if _, found := keys[111]; !found {
		t.Fatal("channel 111 key missing")
	}
}

func TestDirectoryV3RejectsMetadataBeyondLogicalLimits(t *testing.T) {
	directory := t.TempDir()
	channelsPath := filepath.Join(directory, "channels.csv")
	speakersPath := filepath.Join(directory, "speakers.csv")

	var channels bytes.Buffer
	channels.WriteString("channel_id,name\n")
	for index := 0; index <= directoryMaxChannels; index++ {
		channels.WriteString(strconv.Itoa(index + 1))
		channels.WriteString(",Channel\n")
	}
	if err := os.WriteFile(channelsPath, channels.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(speakersPath, []byte("channel_id,sender_id,name\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDirectoryMetadata(channelsPath, speakersPath); err == nil {
		t.Fatal("accepted more channels than the Directory v3 limit")
	}

	if err := os.WriteFile(channelsPath, []byte("channel_id,name\n111,Operations\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var speakers bytes.Buffer
	speakers.WriteString("channel_id,sender_id,name\n")
	for index := 0; index <= directoryMaxSpeakers; index++ {
		speakers.WriteString("111,")
		speakers.WriteString(strconv.Itoa(index + 1))
		speakers.WriteString(",Speaker\n")
	}
	if err := os.WriteFile(speakersPath, speakers.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadDirectoryMetadata(channelsPath, speakersPath); err == nil {
		t.Fatal("accepted more speakers than the Directory v3 limit")
	}
}

func newDirectoryV3TestService(t *testing.T, transport directoryTransport, participants []directoryParticipantRow) (*directoryV3, *net.UDPConn, directoryKeyMaterial) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	material := directoryV3TestMaterial(t)
	directory := &directoryV3{
		keys:          directoryKeyStore{111: material},
		metadata:      directoryMetadata{channels: map[uint32]directoryChannelRow{111: {ChannelID: 111, Name: "Operations"}}, speakers: make(map[uint32]map[uint32]directorySpeakerRow), fallback: make(map[uint32]directorySpeakerRow)},
		transport:     transport,
		conn:          conn,
		participants:  func(uint32) []directoryParticipantRow { return append([]directoryParticipantRow(nil), participants...) },
		publishEvery:  time.Hour,
		freshnessTTL:  directoryDefaultFreshnessTTL,
		now:           time.Now,
		random:        rand.Reader,
		jobs:          make(chan directoryInboundJob, 4),
		stop:          make(chan struct{}),
		registrations: make(map[directoryRegistrationKey]directoryRegistration),
		replay:        make(map[directoryReplayKey]directoryReplayRecord),
		cursors:       make(map[string]directorySnapshotCursor),
		preauth:       make(map[string]directoryRateState),
	}
	directory.start()
	t.Cleanup(func() {
		directory.close()
		_ = conn.Close()
	})
	return directory, conn, material
}

func TestDirectoryV3HandlesMediaPortRequest(t *testing.T) {
	directory, conn, material := newDirectoryV3TestService(t, directoryTransportMediaPort, []directoryParticipantRow{{ChannelID: 111, SenderID: 1001, LastSeenAt: uint64(time.Now().Unix()), Talking: true}})
	relay := newServer(conn, true, false, false, 0, false, 1)
	relay.configureDirectory(directory)
	runDone := make(chan struct{})
	go func() {
		relay.run()
		close(runDone)
	}()
	t.Cleanup(func() {
		directory.close()
		_ = conn.Close()
		select {
		case <-runDone:
		case <-time.After(2 * time.Second):
			t.Error("relay media-port loop did not stop")
		}
	})

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	now := uint64(time.Now().Unix())
	plaintext, err := json.Marshal(directoryRequestPayload{Version: 3, IssuedAt: now, ExpiresAt: now + 10, RequestID: "AAECAwQFBgcICQoLDA0ODw", Resource: "participants"})
	if err != nil {
		t.Fatal(err)
	}
	epoch := [16]byte{1}
	request, err := sealDirectoryClientDatagram(plaintext, "request", 111, material, epoch, 1, now+10, directoryTransportMedia)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(request, conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send Directory media-port carrier: %v", err)
	}

	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxUDPDatagramBytes)
	n, _, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read Directory response: %v", err)
	}
	response := buffer[:n]
	if len(response) < 6 || !bytes.Equal(response[:4], directoryCarrierMagic) || response[4] != directoryCarrierVersion {
		t.Fatalf("unexpected media-port carrier: %x", response)
	}
	var envelope directoryEnvelope
	if err := json.Unmarshal(response[5:], &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Type != "participants" || envelope.ChannelID != 111 {
		t.Fatalf("response envelope = %#v", envelope)
	}
	responseEpoch, err := decodeCanonicalDirectoryID(envelope.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	key, err := directoryEpochKey(material.r2c[:], responseEpoch)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := gcm.Open(nil, directoryNonce(envelope.Sequence), ciphertext, directoryAAD(envelope, responseEpoch, directoryTransportMedia))
	if err != nil {
		t.Fatalf("authenticate Directory response: %v", err)
	}
	var payload directoryParticipantsPayload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.RequestID != "AAECAwQFBgcICQoLDA0ODw" || len(payload.Participants) != 1 || payload.Participants[0].SenderID != 1001 {
		t.Fatalf("response payload = %#v", payload)
	}
}

func TestDirectoryV3HandlesDedicatedRequest(t *testing.T) {
	_, conn, material := newDirectoryV3TestService(t, directoryTransportDedicatedUDP, nil)
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	now := uint64(time.Now().Unix())
	plaintext, err := json.Marshal(directoryRequestPayload{Version: 3, IssuedAt: now, ExpiresAt: now + 10, RequestID: "AAECAwQFBgcICQoLDA0ODw", Resource: "participants"})
	if err != nil {
		t.Fatal(err)
	}
	request, err := sealDirectoryClientDatagram(plaintext, "request", 111, material, [16]byte{2}, 1, now+10, directoryTransportDedicated)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.HasPrefix(request, directoryCarrierMagic) {
		t.Fatal("dedicated request unexpectedly has a media-port carrier")
	}
	if _, err := client.WriteToUDP(request, conn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("send Directory dedicated request: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxUDPDatagramBytes)
	n, _, err := client.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read Directory dedicated response: %v", err)
	}
	if bytes.HasPrefix(buffer[:n], directoryCarrierMagic) {
		t.Fatal("dedicated response unexpectedly has a media-port carrier")
	}
	var envelope directoryEnvelope
	if err := json.Unmarshal(buffer[:n], &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Type != "participants" || envelope.ChannelID != 111 {
		t.Fatalf("response envelope = %#v", envelope)
	}
}

func TestDirectoryV3FragmentsParticipantResponseWithinDatagramLimit(t *testing.T) {
	material := directoryV3TestMaterial(t)
	rows := make([]directoryParticipantRow, 128)
	for index := range rows {
		rows[index] = directoryParticipantRow{ChannelID: 111, SenderID: uint32(index + 1), LastSeenAt: 1700000000, Talking: index%2 == 0}
	}
	epoch := [16]byte{3}
	const responseID = "EBESExQVFhcYGRobHB0eHw"
	groups, err := packDirectoryRows(rows, func(index int, count int, group []directoryParticipantRow) ([]byte, error) {
		return json.Marshal(directoryParticipantsPayload{
			Version: 3, IssuedAt: 1700000000, ExpiresAt: 1700000090, RequestID: "AAECAwQFBgcICQoLDA0ODw",
			Fragment: directoryFragment{ResponseID: responseID, Index: index, Count: count}, Participants: group,
		})
	}, func(index int, count int, payload []byte) bool {
		_, err := sealDirectoryDatagram(payload, "participants", 111, material, epoch, uint64(index+1), 1700000090, directoryTransportMedia)
		return err == nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) < 2 || len(groups) > directoryMaxFragments {
		t.Fatalf("fragment count = %d", len(groups))
	}
	for index, group := range groups {
		payload, err := json.Marshal(directoryParticipantsPayload{
			Version: 3, IssuedAt: 1700000000, ExpiresAt: 1700000090, RequestID: "AAECAwQFBgcICQoLDA0ODw",
			Fragment: directoryFragment{ResponseID: responseID, Index: index, Count: len(groups)}, Participants: group,
		})
		if err != nil {
			t.Fatal(err)
		}
		datagram, err := sealDirectoryDatagram(payload, "participants", 111, material, epoch, uint64(index+1), 1700000090, directoryTransportMedia)
		if err != nil {
			t.Fatalf("fragment %d: %v", index, err)
		}
		if len(datagram) > maxUDPDatagramBytes {
			t.Fatalf("fragment %d size = %d", index, len(datagram))
		}
	}
}

func TestDirectoryV3SnapshotPackingCanReserveChannelOnlyFragment(t *testing.T) {
	material := directoryV3TestMaterial(t)
	channel := directoryChannelRow{ChannelID: 111, Name: strings.Repeat("\U0001f600", 80)}
	rows := []directorySpeakerRow{{ChannelID: 111, SenderID: 1001, Name: strings.Repeat("\U0001f600", 80)}}
	epoch := [16]byte{4}
	encode := func(index int, count int, speakers []directorySpeakerRow) ([]byte, error) {
		channels := []directoryChannelRow{}
		if index == 0 {
			channels = []directoryChannelRow{channel}
		}
		return json.Marshal(directorySnapshotPayload{
			Version: 3, IssuedAt: 1700000000, ExpiresAt: 1700000090, RequestID: "AAECAwQFBgcICQoLDA0ODw",
			Fragment: directoryFragment{ResponseID: "EBESExQVFhcYGRobHB0eHw", Index: index, Count: count}, Revision: strings.Repeat("a", 64),
			Page: directorySnapshotPage{Index: 0, Count: 1}, Channels: channels, Speakers: speakers,
		})
	}
	groups, err := packDirectorySnapshotRows(rows, encode, func(index int, count int, payload []byte) bool {
		_, err := sealDirectoryDatagram(payload, "snapshot", 111, material, epoch, uint64(index+1), 1700000090, directoryTransportMedia)
		return err == nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 || len(groups[0]) != 0 || len(groups[1]) != 1 {
		t.Fatalf("snapshot groups = %#v", groups)
	}
	for index, speakers := range groups {
		payload, err := encode(index, len(groups), speakers)
		if err != nil {
			t.Fatal(err)
		}
		datagram, err := sealDirectoryDatagram(payload, "snapshot", 111, material, epoch, uint64(index+1), 1700000090, directoryTransportMedia)
		if err != nil {
			t.Fatalf("fragment %d: %v", index, err)
		}
		if len(datagram) > maxUDPDatagramBytes {
			t.Fatalf("fragment %d size = %d", index, len(datagram))
		}
	}
}

func TestDirectoryV3RegistrationLifecycle(t *testing.T) {
	now := time.Unix(100, 0)
	directory := &directoryV3{
		registrations: make(map[directoryRegistrationKey]directoryRegistration),
		replay:        make(map[directoryReplayKey]directoryReplayRecord),
		cursors:       make(map[string]directorySnapshotCursor),
		preauth:       make(map[string]directoryRateState),
		now:           func() time.Time { return now },
	}
	instanceID, err := decodeCanonicalDirectoryID("ICEiIyQlJicoKSorLC0uLw")
	if err != nil {
		t.Fatal(err)
	}
	epoch := [16]byte{2}
	endpoint := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 40000}
	opened := func(packetType string, sequence uint64) directoryOpenedDatagram {
		return directoryOpenedDatagram{
			envelope:     directoryEnvelope{Type: packetType, ChannelID: 111, Sequence: sequence, ExpiresAt: uint64(now.Unix() + 30)},
			epoch:        epoch,
			binding:      directoryTransportMedia,
			registration: &directoryRegistrationPayload{InstanceID: "ICEiIyQlJicoKSorLC0uLw"},
		}
	}
	directory.commitInbound(opened("register", 1), endpoint)
	key := directoryRegistrationKey{channelID: 111, instanceID: instanceID}
	registration, found := directory.registrations[key]
	if !found || !registration.deadline.Equal(time.Unix(190, 0)) {
		t.Fatalf("registration = %#v, found=%t", registration, found)
	}
	now = time.Unix(120, 0)
	directory.commitInbound(opened("heartbeat", 2), endpoint)
	registration = directory.registrations[key]
	if !registration.deadline.Equal(time.Unix(210, 0)) {
		t.Fatalf("heartbeat deadline = %s, want 210", registration.deadline)
	}
	now = time.Unix(211, 0)
	directory.commitInbound(opened("heartbeat", 3), endpoint)
	if _, found := directory.registrations[key]; found {
		t.Fatal("expired heartbeat recreated or retained a registration")
	}
}

func TestDirectoryV3RejectsNullRequiredEnvelopeField(t *testing.T) {
	material := directoryV3TestMaterial(t)
	_, err := openDirectoryDatagram([]byte(`{"v":3,"type":"request","channelId":null,"epoch":"ZGlyZWN0b3J5LWVwb2NoIQ","sequence":1,"expiresAt":1700000010,"ciphertext":"AA"}`), directoryTransportDedicated, directoryKeyStore{111: material}, time.Unix(1700000000, 0))
	if err == nil {
		t.Fatal("null channelId was accepted")
	}
}
