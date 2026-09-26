package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// sseTestResponseRecorder permits a streaming handler and the test to inspect
// the response concurrently without racing on httptest.ResponseRecorder.
type sseTestResponseRecorder struct {
	mu        sync.Mutex
	recorder  *httptest.ResponseRecorder
	flushed   chan struct{}
	flushOnce sync.Once
}

func newSSETestResponseRecorder() *sseTestResponseRecorder {
	return &sseTestResponseRecorder{
		recorder: httptest.NewRecorder(),
		flushed:  make(chan struct{}),
	}
}

func (r *sseTestResponseRecorder) Header() http.Header {
	return r.recorder.Header()
}

func (r *sseTestResponseRecorder) WriteHeader(statusCode int) {
	r.mu.Lock()
	r.recorder.WriteHeader(statusCode)
	r.mu.Unlock()
}

func (r *sseTestResponseRecorder) Write(data []byte) (int, error) {
	r.mu.Lock()
	n, err := r.recorder.Write(data)
	r.mu.Unlock()
	return n, err
}

func (r *sseTestResponseRecorder) Flush() {
	r.mu.Lock()
	r.recorder.Flush()
	r.mu.Unlock()
	r.flushOnce.Do(func() { close(r.flushed) })
}

func (r *sseTestResponseRecorder) statusCode() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.recorder.Code
}

func newTestUDPConn(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func receiveTestPacket(t *testing.T, conn *net.UDPConn) parsedPacket {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 2048)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("read UDP: %v", err)
	}
	packet, ok := parsePacket(buffer[:n], true)
	if !ok {
		t.Fatal("received invalid packet")
	}
	return packet
}

func expectNoTestPacket(t *testing.T, conn *net.UDPConn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buffer := make([]byte, 2048)
	if _, _, err := conn.ReadFromUDP(buffer); err == nil {
		t.Fatal("unexpected UDP packet")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read UDP: %v", err)
	}
}

func TestDuplicatePttOnOnlyRegrantsRequester(t *testing.T) {
	relay := newTestUDPConn(t)
	requester := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 41
	const requesterID uint32 = 1001

	s := newServer(relay, true, false, false, 0, true, 2)
	grantedAt := time.Now().Add(-250 * time.Millisecond)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			"requester": {addr: requester.LocalAddr().(*net.UDPAddr), senderId: requesterID},
			"listener":  {addr: listener.LocalAddr().(*net.UDPAddr), senderId: 1002},
		},
		activeTalkers: map[uint32]time.Time{requesterID: grantedAt},
		codecConfigs:  make(map[uint32][]byte),
	}

	s.handlePttOn(channelID, requesterID)
	packet := receiveTestPacket(t, requester)
	if packet.Header.Type != pktTalkGrant {
		t.Fatalf("expected grant, got type=%d", packet.Header.Type)
	}
	if got := s.channels[channelID].activeTalkers[requesterID]; !got.Equal(grantedAt) {
		t.Fatalf("duplicate PTT_ON reset deadline: got=%s want=%s", got, grantedAt)
	}
	expectNoTestPacket(t, listener)
}

func TestTalkReleaseCarriesClientPttOffReason(t *testing.T) {
	relay := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 46
	const talkerID uint32 = 6001

	s := newServer(relay, true, false, false, 0, false, 1)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			"listener": {addr: listener.LocalAddr().(*net.UDPAddr), senderId: 6002},
		},
		activeTalkers: map[uint32]time.Time{talkerID: time.Now()},
		codecConfigs:  make(map[uint32][]byte),
	}

	s.handlePttOff(channelID, talkerID)
	packet := receiveTestPacket(t, listener)
	if packet.Header.Type != pktTalkRelease {
		t.Fatalf("expected release, got type=%d", packet.Header.Type)
	}
	if len(packet.Payload) != 5 {
		t.Fatalf("release payload length = %d, want 5", len(packet.Payload))
	}
	if got := binary.BigEndian.Uint32(packet.Payload[:4]); got != talkerID {
		t.Fatalf("release talker ID = %d, want %d", got, talkerID)
	}
	if got := packet.Payload[4]; got != talkReleaseClientPttOff {
		t.Fatalf("release reason = %d, want %d", got, talkReleaseClientPttOff)
	}
}

func TestServerConfigUsesEffectiveTalkerLimit(t *testing.T) {
	relay := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 47
	const listenerID uint32 = 7001

	s := newServer(relay, true, false, false, 60*time.Second, false, maxActiveTalkersV1)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			"listener": {addr: listener.LocalAddr().(*net.UDPAddr), senderId: listenerID},
		},
		activeTalkers: make(map[uint32]time.Time),
		codecConfigs:  make(map[uint32][]byte),
	}
	s.sendServerConfig(channelID, listenerID)
	packet := receiveTestPacket(t, listener)
	if packet.Header.Type != pktServerCfg || len(packet.Payload) != 8 {
		t.Fatalf("unexpected server config packet: type=%d payload=%v", packet.Header.Type, packet.Payload)
	}
	if got, want := hex.EncodeToString(packet.Payload), "003c0001001e000a"; got != want {
		t.Fatalf("SERVER_CONFIG payload = %s, want %s", got, want)
	}
	if got := packet.Payload[3]; got != 1 {
		t.Fatalf("single-talk server config limit = %d, want 1", got)
	}
	if got := binary.BigEndian.Uint16(packet.Payload[4:6]); got != 30 {
		t.Fatalf("membership lease = %d, want 30", got)
	}
	if got := binary.BigEndian.Uint16(packet.Payload[6:8]); got != 10 {
		t.Fatalf("keepalive interval = %d, want 10", got)
	}

	s = newServer(relay, true, false, false, 0, true, maxActiveTalkersV1+10)
	if s.maxActiveTalkers != maxActiveTalkersV1 {
		t.Fatalf("max active talkers = %d, want clamp %d", s.maxActiveTalkers, maxActiveTalkersV1)
	}
}

func TestCodecConfigUsesU32BitrateAndRequiredAESGCMV2Policy(t *testing.T) {
	const channelID uint32 = 48
	state, key := newRequiredControlAuthState(t, channelID)
	s := newServer(newTestUDPConn(t), false, false, false, 0, false, 1)
	s.configureControlAuth(state)
	s.channels[channelID] = &channel{
		peers:             make(map[string]*peer),
		activeTalkers:     make(map[uint32]time.Time),
		codecConfigs:      make(map[uint32][]byte),
		mediaCodecConfigs: make(map[uint32]codecConfigState),
	}

	valid := append([]byte{0, 2, 0, 1, 0xf4, 0x00, 0}, make([]byte, 12)...)
	copy(valid[7:], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	if pcmOnly, codecID, bitrate, ok := parseCodecConfigPayload(valid); !ok || pcmOnly || codecID != 2 || bitrate != 128000 {
		t.Fatalf("CODEC_CONFIG parse = pcm=%t codec=%d bitrate=%d ok=%t", pcmOnly, codecID, bitrate, ok)
	}
	if _, ok := s.cacheCodecConfig(channelID, 9001, valid[:18], 1, true); ok {
		t.Fatal("short CODEC_CONFIG was accepted")
	}
	zeroBase := append([]byte(nil), valid...)
	clear(zeroBase[7:])
	if _, ok := s.cacheCodecConfig(channelID, 9001, zeroBase, 1, true); ok {
		t.Fatal("required policy accepted zero media nonce base")
	}
	if _, ok := s.cacheCodecConfig(channelID, 9001, valid, 1, false); ok {
		t.Fatal("required policy accepted unauthenticated AES-GCM v2 config")
	}
	config, ok := s.cacheCodecConfig(channelID, 9001, valid, 1, true)
	if !ok || config.controlKeyID != 1 || config.mediaKeyID != 2 {
		t.Fatalf("authenticated AES-GCM v2 CODEC_CONFIG = %#v, ok=%t", config, ok)
	}
	if len(key) != 32 {
		t.Fatal("test control key was not initialized")
	}
}

func TestMaximumTalkSecondsV1Range(t *testing.T) {
	for _, seconds := range []int{0, 1, maxTalkMaximumSecondsV1} {
		if !validMaximumTalkSeconds(seconds) {
			t.Fatalf("valid talk maximum %d was rejected", seconds)
		}
	}
	for _, seconds := range []int{-1, maxTalkMaximumSecondsV1 + 1} {
		if validMaximumTalkSeconds(seconds) {
			t.Fatalf("invalid talk maximum %d was accepted", seconds)
		}
	}
}

func TestOptionalConfiguredControlAuthAllowsAuthenticatedCompatibilityMedia(t *testing.T) {
	relay := newTestUDPConn(t)
	sender := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 481
	const senderID uint32 = 8101
	const listenerID uint32 = 8102
	const sessionID uint32 = 0x33445566
	key := []byte("0123456789abcdef0123456789abcdef")
	state, err := newControlAuthState(
		controlAuthOptional,
		controlKeyStore{channelID: {1: key}},
		[]byte("abcdefghijklmnopqrstuvwxyz012345"),
	)
	if err != nil {
		t.Fatalf("new optional control auth state: %v", err)
	}

	s := newServer(relay, true, false, false, 0, true, 2)
	s.configureControlAuth(state)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(sender.LocalAddr().(*net.UDPAddr)): {
				addr: sender.LocalAddr().(*net.UDPAddr), senderId: senderID, authenticated: true,
				controlSessionID: sessionID, controlKeyID: 1, controlHighest: 1, controlSeenWindow: 1,
				membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute),
			},
			peerMapKey(listener.LocalAddr().(*net.UDPAddr)): {
				addr: listener.LocalAddr().(*net.UDPAddr), senderId: listenerID, authenticated: true,
				controlSessionID: 0x778899aa, controlKeyID: 1, controlHighest: 1, controlSeenWindow: 1,
				membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute),
			},
		},
		activeTalkers:     map[uint32]time.Time{senderID: time.Now()},
		codecConfigs:      make(map[uint32][]byte),
		mediaCodecConfigs: make(map[uint32]codecConfigState),
	}

	compatibilityConfig := append([]byte{0, 2, 0, 0, 0x3e, 0x80, 0}, make([]byte, 12)...)
	if _, ok := s.cacheCodecConfig(channelID, senderID, compatibilityConfig, 0, false); ok {
		t.Fatal("optional configured channel accepted unauthenticated compatibility CODEC_CONFIG")
	}
	configRaw := buildAuthenticatedControlPacket(pktCodecConfig, channelID, senderID, compatibilityConfig, 1, key, uint64(sessionID)<<32|2)
	config, ok := parsePacket(configRaw, true)
	if !ok {
		t.Fatal("parse authenticated compatibility CODEC_CONFIG")
	}
	s.handlePacket(config, sender.LocalAddr().(*net.UDPAddr))

	forwardedConfig := receiveTestPacket(t, listener)
	if forwardedConfig.Header.Type != pktCodecConfig || !verifyControlAuthPacket(forwardedConfig, key) {
		t.Fatal("compatibility CODEC_CONFIG was not Relay-reauthenticated")
	}
	if !bytes.Equal(forwardedConfig.Payload, compatibilityConfig) {
		t.Fatalf("forwarded compatibility CODEC_CONFIG payload = %x, want %x", forwardedConfig.Payload, compatibilityConfig)
	}

	noCryptoRaw := buildRelayControlPacket(pktAudio, channelID, senderID, []byte{0, 1, 0x42}, true, 3)
	noCrypto, ok := parsePacket(noCryptoRaw, true)
	if !ok {
		t.Fatal("parse no-crypto media")
	}
	if !s.mediaMatchesCodecConfig(noCrypto) {
		t.Fatal("authenticated optional channel rejected no-crypto media after compatibility CODEC_CONFIG")
	}
	s.handlePacket(noCrypto, sender.LocalAddr().(*net.UDPAddr))
	if forwarded := receiveTestPacket(t, listener); !bytes.Equal(forwarded.Raw, noCryptoRaw) {
		t.Fatal("authenticated optional channel did not forward no-crypto media")
	}

	legacyRaw := buildRelayControlPacket(pktAudio, channelID, senderID, []byte{0, 2, 0x43}, false, 4)
	binary.BigEndian.PutUint32(legacyRaw[24:28], 1)
	legacy, ok := parsePacket(legacyRaw, true)
	if !ok {
		t.Fatal("parse legacy-xor media")
	}
	s.handlePacket(legacy, sender.LocalAddr().(*net.UDPAddr))
	if forwarded := receiveTestPacket(t, listener); !bytes.Equal(forwarded.Raw, legacyRaw) {
		t.Fatal("authenticated optional channel did not forward legacy-xor media")
	}
	legacyUnknownFlagRaw := append([]byte(nil), legacyRaw...)
	binary.BigEndian.PutUint16(legacyUnknownFlagRaw[14:16], 0x8000)
	legacyUnknownFlagPacket, ok := parsePacket(legacyUnknownFlagRaw, true)
	if !ok {
		t.Fatal("parse legacy-xor media with unknown flag")
	}
	s.handlePacket(legacyUnknownFlagPacket, sender.LocalAddr().(*net.UDPAddr))
	if forwarded := receiveTestPacket(t, listener); !bytes.Equal(forwarded.Raw, legacyUnknownFlagRaw) {
		t.Fatal("legacy-xor media with an unknown flag was not forwarded")
	}

	unknownFlagRaw := buildRelayControlPacket(pktAudio, channelID, senderID, []byte{0, 3, 0x44}, true, 5)
	binary.BigEndian.PutUint16(unknownFlagRaw[14:16], 0x8000)
	unknownFlagPacket, ok := parsePacket(unknownFlagRaw, true)
	if !ok {
		t.Fatal("parse compatibility media with unknown flag")
	}
	s.handlePacket(unknownFlagPacket, sender.LocalAddr().(*net.UDPAddr))
	if forwarded := receiveTestPacket(t, listener); !bytes.Equal(forwarded.Raw, unknownFlagRaw) {
		t.Fatal("compatibility media with an unknown flag was not forwarded")
	}
}

func TestUDPDatagramSizeLimit(t *testing.T) {
	if !acceptsUDPDatagramSize(maxUDPDatagramBytes) {
		t.Fatalf("%d-byte datagram should be accepted", maxUDPDatagramBytes)
	}
	if acceptsUDPDatagramSize(maxUDPDatagramBytes + 1) {
		t.Fatalf("oversize datagram should be rejected")
	}
}

func TestJoinSyncSendsCodecConfigBeforeGrant(t *testing.T) {
	relay := newTestUDPConn(t)
	joiner := newTestUDPConn(t)
	const channelID uint32 = 42
	const talkerID uint32 = 2001
	const joinerID uint32 = 2002
	codecConfig := []byte{0, 2, 0, 0, 0x2e, 0xe0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	s := newServer(relay, true, false, false, 0, true, 2)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			"joiner": {addr: joiner.LocalAddr().(*net.UDPAddr), senderId: joinerID},
		},
		activeTalkers: map[uint32]time.Time{talkerID: time.Now()},
		codecConfigs:  map[uint32][]byte{talkerID: codecConfig},
	}

	s.sendCurrentTalkState(channelID, joinerID)
	configPacket := receiveTestPacket(t, joiner)
	grantPacket := receiveTestPacket(t, joiner)
	if configPacket.Header.Type != pktCodecConfig || configPacket.Header.SenderId != talkerID {
		t.Fatalf("expected talker codec config first, got type=%d sender=%d", configPacket.Header.Type, configPacket.Header.SenderId)
	}
	if string(configPacket.Payload) != string(codecConfig) {
		t.Fatalf("unexpected codec config payload: %v", configPacket.Payload)
	}
	if grantPacket.Header.Type != pktTalkGrant || grantPacket.Header.SenderId != talkerID {
		t.Fatalf("expected talker grant second, got type=%d sender=%d", grantPacket.Header.Type, grantPacket.Header.SenderId)
	}
}

func TestFecRequiresActiveTalker(t *testing.T) {
	relay := newTestUDPConn(t)
	sender := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 43
	const senderID uint32 = 3001

	s := newServer(relay, true, false, false, 0, true, 2)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(sender.LocalAddr().(*net.UDPAddr)):   {addr: sender.LocalAddr().(*net.UDPAddr), senderId: senderID, membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute)},
			peerMapKey(listener.LocalAddr().(*net.UDPAddr)): {addr: listener.LocalAddr().(*net.UDPAddr), senderId: 3002, membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute)},
		},
		activeTalkers: make(map[uint32]time.Time),
		codecConfigs:  make(map[uint32][]byte),
	}

	raw := buildControlPacket(pktFec, channelID, senderID, []byte{0, 0, 6, 0, 1}, true)
	packet, ok := parsePacket(raw, true)
	if !ok {
		t.Fatal("failed to build FEC test packet")
	}
	s.handlePacket(packet, sender.LocalAddr().(*net.UDPAddr))
	expectNoTestPacket(t, listener)

	s.channels[channelID].activeTalkers[senderID] = time.Now()
	s.handlePacket(packet, sender.LocalAddr().(*net.UDPAddr))
	forwarded := receiveTestPacket(t, listener)
	if forwarded.Header.Type != pktFec {
		t.Fatalf("expected FEC packet, got type=%d", forwarded.Header.Type)
	}
}

func TestForwardsAESGCMV2MediaPacketWithoutChangingAuthenticatedHeader(t *testing.T) {
	relay := newTestUDPConn(t)
	sender := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 44
	const senderID uint32 = 4001

	s := newServer(relay, false, false, false, 0, true, 2)
	state, _ := newRequiredControlAuthState(t, channelID)
	s.configureControlAuth(state)
	mediaBase := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(sender.LocalAddr().(*net.UDPAddr)):   {addr: sender.LocalAddr().(*net.UDPAddr), senderId: senderID, authenticated: true, controlSessionID: 1, controlKeyID: 1, membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute)},
			peerMapKey(listener.LocalAddr().(*net.UDPAddr)): {addr: listener.LocalAddr().(*net.UDPAddr), senderId: 4002, membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute)},
		},
		activeTalkers:     map[uint32]time.Time{senderID: time.Now()},
		codecConfigs:      make(map[uint32][]byte),
		mediaCodecConfigs: map[uint32]codecConfigState{senderID: {mediaNonceBase: mediaBase, mediaKeyID: 2}},
	}

	// The Relay does not decrypt media. It must preserve the v2 AAD bytes
	// exactly so receivers can authenticate the forwarded packet.
	raw := make([]byte, aesGCMV2HeaderSize+3+authTagSize)
	raw[0] = protocolVersion
	raw[1] = pktAudio
	binary.BigEndian.PutUint16(raw[2:4], aesGCMV2HeaderSize)
	binary.BigEndian.PutUint32(raw[4:8], channelID)
	binary.BigEndian.PutUint32(raw[8:12], senderID)
	binary.BigEndian.PutUint16(raw[14:16], packetFlagAESGCMV2HeaderAAD)
	copy(raw[16:28], mediaBase[:])
	binary.BigEndian.PutUint32(raw[28:32], 7)
	binary.BigEndian.PutUint32(raw[32:36], 2)
	copy(raw[aesGCMV2HeaderSize:], []byte{1, 2, 3})
	packet, ok := parsePacket(raw, false)
	if !ok {
		t.Fatal("failed to parse v2 media packet")
	}
	s.handlePacket(packet, sender.LocalAddr().(*net.UDPAddr))

	forwarded := receiveTestPacket(t, listener)
	if forwarded.Header.Flags&packetFlagAESGCMV2HeaderAAD == 0 {
		t.Fatal("Relay removed AES-GCM-v2 header-authentication flag")
	}
	if string(forwarded.Raw) != string(raw) {
		t.Fatal("Relay modified v2 media packet bytes")
	}
}

func TestAESGCMV2MediaIsRejectedWithoutControlAuthentication(t *testing.T) {
	relay := newTestUDPConn(t)
	sender := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 441
	const senderID uint32 = 4011

	s := newServer(relay, false, false, false, 0, true, 2)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(sender.LocalAddr().(*net.UDPAddr)):   {addr: sender.LocalAddr().(*net.UDPAddr), senderId: senderID, membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute)},
			peerMapKey(listener.LocalAddr().(*net.UDPAddr)): {addr: listener.LocalAddr().(*net.UDPAddr), senderId: 4012, membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute)},
		},
		activeTalkers: map[uint32]time.Time{senderID: time.Now()},
		codecConfigs:  make(map[uint32][]byte),
	}

	raw := buildAESGCMV2MediaPacket(pktAudio, channelID, senderID, [12]byte{1}, 1, []byte{1})
	packet, ok := parsePacket(raw, false)
	if !ok {
		t.Fatal("failed to parse AES-GCM v2 media")
	}
	s.handlePacket(packet, sender.LocalAddr().(*net.UDPAddr))
	expectNoTestPacket(t, listener)
}

func TestPingRepliesOnlyToRegisteredEndpoint(t *testing.T) {
	relay := newTestUDPConn(t)
	requester := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	unknown := newTestUDPConn(t)
	const channelID uint32 = 45
	const requesterID uint32 = 5001
	nonce := []byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}

	s := newServer(relay, true, false, false, 0, true, 2)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(requester.LocalAddr().(*net.UDPAddr)): {addr: requester.LocalAddr().(*net.UDPAddr), senderId: requesterID},
			peerMapKey(listener.LocalAddr().(*net.UDPAddr)):  {addr: listener.LocalAddr().(*net.UDPAddr), senderId: 5002},
		},
		activeTalkers: make(map[uint32]time.Time),
		codecConfigs:  make(map[uint32][]byte),
	}

	payload := append([]byte(nil), nonce...)
	raw := buildControlPacket(pktPing, channelID, requesterID, payload, true)
	pkt, ok := parsePacket(raw, true)
	if !ok {
		t.Fatal("failed to parse ping test packet")
	}
	s.handlePacket(pkt, requester.LocalAddr().(*net.UDPAddr))

	pong := receiveTestPacket(t, requester)
	if pong.Header.Type != pktPong {
		t.Fatalf("expected pong, got type=%d", pong.Header.Type)
	}
	if pong.Header.ChannelId != channelID || pong.Header.SenderId != requesterID {
		t.Fatalf("unexpected pong header: channel=%d sender=%d", pong.Header.ChannelId, pong.Header.SenderId)
	}
	if pong.Header.Seq != 0 {
		t.Fatalf("PONG Relay sequence = %d, want 0", pong.Header.Seq)
	}
	if string(pong.Payload) != string(nonce) {
		t.Fatalf("pong nonce mismatch: got=%x want=%x", pong.Payload, nonce)
	}
	expectNoTestPacket(t, listener)

	unknownRaw := buildControlPacket(pktPing, channelID, 5999, nonce, true)
	unknownPkt, ok := parsePacket(unknownRaw, true)
	if !ok {
		t.Fatal("failed to parse unknown ping test packet")
	}
	s.handlePacket(unknownPkt, unknown.LocalAddr().(*net.UDPAddr))
	expectNoTestPacket(t, unknown)
}

func newRequiredControlAuthState(t *testing.T, channelID uint32) (*controlAuthState, []byte) {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	keys := controlKeyStore{channelID: {1: key}}
	state, err := newControlAuthState(controlAuthRequired, keys, []byte("abcdefghijklmnopqrstuvwxyz012345"))
	if err != nil {
		t.Fatalf("new control auth state: %v", err)
	}
	return state, key
}

func buildIdentityAdmissionTicket(t *testing.T, issuerPrivate ed25519.PrivateKey, issuer string, audience string, channelID uint32, senderID uint32, clientPublicKey ed25519.PublicKey, permissions uint8, priority *uint8) string {
	t.Helper()
	digest := sha256.Sum256(clientPublicKey)
	header, err := json.Marshal(identityTicketHeader{Algorithm: "EdDSA", KeyID: "test-kid", Type: "incomudon-admission+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := identityTicketClaims{
		Issuer: issuer, Audience: audience, Subject: "identity-test-subject", TicketID: "identity-test-ticket",
		IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(),
		ChannelID: channelID, SenderID: senderID, Permissions: permissions, Priority: priority,
	}
	claims.Confirmation.JWKThumbprint = base64.RawURLEncoding.EncodeToString(digest[:])
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(issuerPrivate, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func identityBeginPayload(ticket string, publicKey ed25519.PublicKey) []byte {
	payload := make([]byte, 2+len(ticket)+len(publicKey))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(ticket)))
	copy(payload[2:], []byte(ticket))
	copy(payload[2+len(ticket):], publicKey)
	return payload
}

func buildServiceAdmissionGrant(t *testing.T, issuerPrivate ed25519.PrivateKey, issuer string, audience string, channelID uint32, senderID uint32, servicePublicKey ed25519.PublicKey, role string, permissions uint8, priority *uint8, graceSeconds *uint16) string {
	t.Helper()
	digest := sha256.Sum256(servicePublicKey)
	header, err := json.Marshal(serviceGrantHeader{Algorithm: "EdDSA", KeyID: "test-service-kid", Type: "incomudon-service-admission+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := serviceGrantClaims{
		Issuer: issuer, Audience: audience, ServiceID: "recorder-test-01", GrantID: "service-grant-test-0001",
		IssuedAt: now.Add(-time.Second).Unix(), ExpiresAt: now.Add(2 * time.Minute).Unix(),
		ChannelID: channelID, SenderID: senderID, Role: role, Permissions: permissions, Priority: priority, GraceSeconds: graceSeconds,
	}
	claims.Confirmation.JWKThumbprint = base64.RawURLEncoding.EncodeToString(digest[:])
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(issuerPrivate, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func serviceAdmissionBeginPayload(grant string, publicKey ed25519.PublicKey) []byte {
	payload := make([]byte, 2+len(grant)+len(publicKey))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(grant)))
	copy(payload[2:], []byte(grant))
	copy(payload[2+len(grant):], publicKey)
	return payload
}

func TestControlAuthV1Vectors(t *testing.T) {
	key, err := hex.DecodeString("f7bf50ee89a0e406253d1a31040a54ac9681e6bacdd4346251b365a757bd5153")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString("0102001c00000064000003ea002a0002123456780000000200000001f4df8ba41610f2a6f4a592620e51130a")
	if err != nil {
		t.Fatal(err)
	}
	pkt, ok := parsePacket(raw, false)
	if !ok || !verifyControlAuthPacket(pkt, key) {
		t.Fatal("control-auth-v1 deterministic packet vector was rejected")
	}
	tampered := append([]byte(nil), raw...)
	tampered[4] ^= 0x01
	tamperedPkt, ok := parsePacket(tampered, false)
	if !ok || verifyControlAuthPacket(tamperedPkt, key) {
		t.Fatal("tampered control-auth-v1 packet was accepted")
	}

	secret, err := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	state, err := newControlAuthState(controlAuthRequired, controlKeyStore{100: {1: key}}, secret)
	if err != nil {
		t.Fatalf("new control auth state: %v", err)
	}
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50001}
	wantCookie, err := hex.DecodeString("164304de5e5b6a7782f9657740ba0eaf")
	if err != nil {
		t.Fatal(err)
	}
	if got := state.cookie(100, 1002, 1, 0x12345678, 1694498816, addr); string(got) != string(wantCookie) {
		t.Fatalf("cookie vector mismatch: got=%x want=%x", got, wantCookie)
	}
}

func TestControlAuthChallengeIsSourceBoundAndSingleUse(t *testing.T) {
	const channelID uint32 = 100
	const senderID uint32 = 1002
	const sessionID uint32 = 0x55667788
	state, key := newRequiredControlAuthState(t, channelID)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 50001}
	helloRaw := buildAuthenticatedControlPacket(pktAuthHello, channelID, senderID, nil, 1, key, uint64(sessionID)<<32)
	hello, ok := parsePacket(helloRaw, false)
	if !ok {
		t.Fatal("parse AUTH_HELLO")
	}
	meta := controlAuthMeta{keyID: 1, sessionID: sessionID, counter: 0}
	challenge, err := state.createChallenge(hello, addr, meta)
	if err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	joinRaw := buildAuthenticatedControlPacket(pktJoin, channelID, senderID, challenge, 1, key, uint64(sessionID)<<32|1)
	join, ok := parsePacket(joinRaw, false)
	if !ok {
		t.Fatal("parse JOIN")
	}
	joinMeta := controlAuthMeta{keyID: 1, sessionID: sessionID, counter: 1}
	wrongAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 11), Port: 50001}
	if _, ok := state.consumeJoinChallenge(join, wrongAddr, joinMeta); ok {
		t.Fatal("source-address mismatched cookie was accepted")
	}
	if _, ok := state.consumeJoinChallenge(join, addr, joinMeta); !ok {
		t.Fatal("valid challenge cookie was rejected")
	}
	if _, ok := state.consumeJoinChallenge(join, addr, joinMeta); ok {
		t.Fatal("reused challenge cookie was accepted")
	}

	expired := append([]byte(nil), challenge...)
	binary.BigEndian.PutUint32(expired[:4], uint32(time.Now().Add(-time.Second).Unix()))
	expiredJoinRaw := buildAuthenticatedControlPacket(pktJoin, channelID, senderID, expired, 1, key, uint64(sessionID)<<32|1)
	expiredJoin, ok := parsePacket(expiredJoinRaw, false)
	if !ok {
		t.Fatal("parse expired JOIN")
	}
	if _, ok := state.consumeJoinChallenge(expiredJoin, addr, joinMeta); ok {
		t.Fatal("expired challenge cookie was accepted")
	}
}

func TestControlAuthReplayWindowAndPolicy(t *testing.T) {
	const channelID uint32 = 100
	const senderID uint32 = 1002
	const sessionID uint32 = 0x11223344
	state, key := newRequiredControlAuthState(t, channelID)
	if !state.requires(channelID) || !state.requires(channelID+1) {
		t.Fatal("required policy did not apply to all channels")
	}
	optional, err := newControlAuthState(controlAuthOptional, state.keys, state.cookieSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !optional.requires(channelID) || optional.requires(channelID+1) {
		t.Fatal("optional policy did not select configured channels")
	}
	off, err := newControlAuthState(controlAuthOff, state.keys, state.cookieSecret)
	if err != nil {
		t.Fatal(err)
	}
	if off.requires(channelID) {
		t.Fatal("off policy requires control authentication")
	}

	relay := newTestUDPConn(t)
	client := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	s.configureControlAuth(state)
	s.upsertAuthenticatedPeer(channelID, senderID, client.LocalAddr().(*net.UDPAddr), controlAuthMeta{keyID: 1, sessionID: sessionID, counter: 1})
	packetRaw := buildAuthenticatedControlPacket(pktKeepalive, channelID, senderID, nil, 1, key, uint64(sessionID)<<32|2)
	pkt, ok := parsePacket(packetRaw, false)
	if !ok {
		t.Fatal("parse authenticated KEEPALIVE")
	}
	meta, ok := s.verifyIncomingControl(pkt)
	if !ok || !s.acceptAuthenticatedPeerControl(pkt, client.LocalAddr().(*net.UDPAddr), meta) {
		t.Fatal("new authenticated control counter was rejected")
	}
	if s.acceptAuthenticatedPeerControl(pkt, client.LocalAddr().(*net.UDPAddr), meta) {
		t.Fatal("replayed authenticated control counter was accepted")
	}
	wrongSessionRaw := buildAuthenticatedControlPacket(pktKeepalive, channelID, senderID, nil, 1, key, uint64(sessionID+1)<<32|3)
	wrongSession, ok := parsePacket(wrongSessionRaw, false)
	if !ok {
		t.Fatal("parse wrong-session KEEPALIVE")
	}
	wrongMeta, ok := s.verifyIncomingControl(wrongSession)
	if !ok || s.acceptAuthenticatedPeerControl(wrongSession, client.LocalAddr().(*net.UDPAddr), wrongMeta) {
		t.Fatal("different authenticated client session was accepted")
	}
}

func TestControlAuthHandshakeRegistersAuthenticatedPeer(t *testing.T) {
	relay := newTestUDPConn(t)
	client := newTestUDPConn(t)
	const channelID uint32 = 77
	const senderID uint32 = 7001
	const sessionID uint32 = 0x11223344

	s := newServer(relay, false, false, false, 0, false, 1)
	state, key := newRequiredControlAuthState(t, channelID)
	s.configureControlAuth(state)

	helloRaw := buildAuthenticatedControlPacket(pktAuthHello, channelID, senderID, nil, 1, key, uint64(sessionID)<<32)
	hello, ok := parsePacket(helloRaw, false)
	if !ok {
		t.Fatal("failed to parse authenticated AUTH_HELLO")
	}
	s.handlePacket(hello, client.LocalAddr().(*net.UDPAddr))
	challenge := receiveTestPacket(t, client)
	if challenge.Header.Type != pktAuthChallenge || len(challenge.Payload) != 20 {
		t.Fatalf("unexpected challenge type=%d payload=%x", challenge.Header.Type, challenge.Payload)
	}

	joinRaw := buildAuthenticatedControlPacket(pktJoin, channelID, senderID, challenge.Payload, 1, key, uint64(sessionID)<<32|1)
	join, ok := parsePacket(joinRaw, false)
	if !ok {
		t.Fatal("failed to parse authenticated JOIN")
	}
	s.handlePacket(join, client.LocalAddr().(*net.UDPAddr))
	serverConfig := receiveTestPacket(t, client)
	if serverConfig.Header.Type != pktServerCfg || serverConfig.Header.Flags&packetFlagControlAuthV1 == 0 {
		t.Fatalf("expected authenticated SERVER_CONFIG, got type=%d flags=%x", serverConfig.Header.Type, serverConfig.Header.Flags)
	}
	if !s.isAuthenticatedPeer(channelID, senderID, client.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("authenticated JOIN did not register peer")
	}
}

func TestAuthenticatedMediaRequiresMatchingCodecConfig(t *testing.T) {
	relay := newTestUDPConn(t)
	sender := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 78
	const senderID uint32 = 7101
	const listenerID uint32 = 7102
	const sessionID uint32 = 0x22334455
	base := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

	s := newServer(relay, false, false, false, 0, true, 2)
	state, key := newRequiredControlAuthState(t, channelID)
	s.configureControlAuth(state)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(sender.LocalAddr().(*net.UDPAddr)): {
				addr: sender.LocalAddr().(*net.UDPAddr), senderId: senderID, authenticated: true,
				controlSessionID: sessionID, controlKeyID: 1, controlHighest: 1, controlSeenWindow: 1,
				membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute),
			},
			peerMapKey(listener.LocalAddr().(*net.UDPAddr)): {
				addr: listener.LocalAddr().(*net.UDPAddr), senderId: listenerID, authenticated: true,
				controlSessionID: 0x55667788, controlKeyID: 1, controlHighest: 1, controlSeenWindow: 1,
				membershipLease: 30 * time.Second, membershipDeadline: time.Now().Add(time.Minute),
			},
		},
		activeTalkers:     map[uint32]time.Time{senderID: time.Now()},
		codecConfigs:      make(map[uint32][]byte),
		mediaCodecConfigs: make(map[uint32]codecConfigState),
	}

	configPayload := []byte{0, 2, 0, 0, 0x3e, 0x80, 0}
	configPayload = append(configPayload, base[:]...)
	configRaw := buildAuthenticatedControlPacket(pktCodecConfig, channelID, senderID, configPayload, 1, key, uint64(sessionID)<<32|2)
	config, ok := parsePacket(configRaw, false)
	if !ok {
		t.Fatal("failed to parse authenticated CODEC_CONFIG")
	}
	s.handlePacket(config, sender.LocalAddr().(*net.UDPAddr))
	// The Relay re-signs config for both the source and listeners.
	_ = receiveTestPacket(t, sender)
	relayedConfig := receiveTestPacket(t, listener)
	if relayedConfig.Header.Type != pktCodecConfig || relayedConfig.Header.Flags&packetFlagControlAuthV1 == 0 {
		t.Fatal("CODEC_CONFIG was not re-signed by Relay")
	}

	matchingRaw := buildAESGCMV2MediaPacket(pktAudio, channelID, senderID, base, 3, []byte{1, 2, 3})
	matching, ok := parsePacket(matchingRaw, false)
	if !ok {
		t.Fatal("failed to parse matching AES-GCM v2 media")
	}
	s.handlePacket(matching, sender.LocalAddr().(*net.UDPAddr))
	forwarded := receiveTestPacket(t, listener)
	if string(forwarded.Raw) != string(matchingRaw) {
		t.Fatal("matching AES-GCM v2 media was not forwarded byte-for-byte")
	}

	wrongBase := base
	wrongBase[11]++
	mismatchedRaw := buildAESGCMV2MediaPacket(pktAudio, channelID, senderID, wrongBase, 4, []byte{4, 5, 6})
	mismatched, ok := parsePacket(mismatchedRaw, false)
	if !ok {
		t.Fatal("failed to parse mismatched AES-GCM v2 media")
	}
	s.handlePacket(mismatched, sender.LocalAddr().(*net.UDPAddr))
	expectNoTestPacket(t, listener)
}

func buildAESGCMV2MediaPacket(packetType uint8, channelID uint32, senderID uint32, base [12]byte, counter uint32, ciphertext []byte) []byte {
	packet := make([]byte, aesGCMV2HeaderSize+len(ciphertext)+authTagSize)
	packet[0] = protocolVersion
	packet[1] = packetType
	binary.BigEndian.PutUint16(packet[2:4], aesGCMV2HeaderSize)
	binary.BigEndian.PutUint32(packet[4:8], channelID)
	binary.BigEndian.PutUint32(packet[8:12], senderID)
	binary.BigEndian.PutUint16(packet[14:16], packetFlagAESGCMV2HeaderAAD)
	copy(packet[16:28], base[:])
	binary.BigEndian.PutUint32(packet[28:32], counter)
	binary.BigEndian.PutUint32(packet[32:36], 2)
	copy(packet[aesGCMV2HeaderSize:], ciphertext)
	return packet
}

func TestRelayOutboundControlUsesIncrementingSequence(t *testing.T) {
	relay := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 79
	const listenerID uint32 = 7201

	s := newServer(relay, true, false, false, 0, false, 1)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(listener.LocalAddr().(*net.UDPAddr)): {
				addr:               listener.LocalAddr().(*net.UDPAddr),
				senderId:           listenerID,
				membershipLease:    30 * time.Second,
				keepaliveInterval:  10 * time.Second,
				membershipDeadline: time.Now().Add(time.Minute),
			},
		},
		activeTalkers: make(map[uint32]time.Time),
		codecConfigs:  make(map[uint32][]byte),
	}

	s.sendServerConfig(channelID, listenerID)
	first := receiveTestPacket(t, listener)
	s.sendServerConfig(channelID, listenerID)
	second := receiveTestPacket(t, listener)
	if first.Header.Seq != 0 || second.Header.Seq != 1 {
		t.Fatalf("Relay sequence values = %d, %d; want 0, 1", first.Header.Seq, second.Header.Seq)
	}
}

func TestRelayReauthenticatedCodecConfigPreservesVerifiedControlKeyID(t *testing.T) {
	relay := newTestUDPConn(t)
	talker := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 80
	const talkerID uint32 = 7301
	const listenerID uint32 = 7302
	const sessionID uint32 = 0x10203040
	keyOne := []byte("0123456789abcdef0123456789abcdef")
	keyTwo := []byte("abcdefghijklmnopqrstuvwxyz012345")
	state, err := newControlAuthState(controlAuthRequired, controlKeyStore{channelID: {1: keyOne, 2: keyTwo}}, []byte("relay-cookie-secret-must-have-at-least-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}

	s := newServer(relay, false, false, false, 0, true, 2)
	s.configureControlAuth(state)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(talker.LocalAddr().(*net.UDPAddr)): {
				addr: talker.LocalAddr().(*net.UDPAddr), senderId: talkerID, authenticated: true,
				controlSessionID: sessionID, controlKeyID: 1, controlHighest: 1, controlSeenWindow: 1,
				membershipLease: 30 * time.Second, keepaliveInterval: 10 * time.Second, membershipDeadline: time.Now().Add(time.Minute),
			},
			peerMapKey(listener.LocalAddr().(*net.UDPAddr)): {
				addr: listener.LocalAddr().(*net.UDPAddr), senderId: listenerID, authenticated: true,
				controlSessionID: 0x50607080, controlKeyID: 2, controlHighest: 1, controlSeenWindow: 1,
				membershipLease: 30 * time.Second, keepaliveInterval: 10 * time.Second, membershipDeadline: time.Now().Add(time.Minute),
			},
		},
		activeTalkers:     make(map[uint32]time.Time),
		codecConfigs:      make(map[uint32][]byte),
		mediaCodecConfigs: make(map[uint32]codecConfigState),
	}

	base := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	payload := append([]byte{0, 2, 0, 0, 0x2e, 0xe0, 0}, base[:]...)
	raw := buildAuthenticatedControlPacket(pktCodecConfig, channelID, talkerID, payload, 1, keyOne, uint64(sessionID)<<32|2)
	pkt, ok := parsePacket(raw, false)
	if !ok {
		t.Fatal("parse CODEC_CONFIG")
	}
	s.handlePacket(pkt, talker.LocalAddr().(*net.UDPAddr))
	_ = receiveTestPacket(t, talker)
	forwarded := receiveTestPacket(t, listener)
	if forwarded.Sec.KeyID != 1 {
		t.Fatalf("forwarded control_key_id = %d, want verified source key 1", forwarded.Sec.KeyID)
	}
	if !verifyControlAuthPacket(forwarded, keyOne) || verifyControlAuthPacket(forwarded, keyTwo) {
		t.Fatal("forwarded CODEC_CONFIG was not reauthenticated with the source control key")
	}
	if forwarded.Sec.ControlNonce == pkt.Sec.ControlNonce {
		t.Fatal("forwarded CODEC_CONFIG reused the client control-authentication nonce")
	}
}

func TestControlAuthRelayNonceRolloverDoesNotWrap(t *testing.T) {
	state, _ := newRequiredControlAuthState(t, 81)
	state.mu.Lock()
	state.relayInstanceID = 0x12345678
	state.usedRelayInstanceIDs[0x12345678] = struct{}{}
	state.relayCounter = ^uint32(0)
	state.relayCounterExhausted = false
	state.mu.Unlock()

	last, ok := state.nextRelayNonce()
	if !ok || last != 0x12345678ffffffff {
		t.Fatalf("final nonce = %016x, ok=%t", last, ok)
	}
	next, ok := state.nextRelayNonce()
	if !ok {
		t.Fatal("nonce rollover failed closed despite available CSPRNG")
	}
	if uint32(next) != 0 {
		t.Fatalf("rollover counter = %d, want 0", uint32(next))
	}
	if uint32(next>>32) == 0x12345678 || uint32(next>>32) == 0 {
		t.Fatalf("rollover instance ID = %08x", uint32(next>>32))
	}
}

func TestControlAuthProvisionalReplayWindowPromotesPreJoinCounters(t *testing.T) {
	const channelID uint32 = 82
	const senderID uint32 = 7401
	const sessionID uint32 = 0x66778899
	state, key := newRequiredControlAuthState(t, channelID)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 50002}

	helloRaw := buildAuthenticatedControlPacket(pktAuthHello, channelID, senderID, nil, 1, key, uint64(sessionID)<<32)
	hello, ok := parsePacket(helloRaw, false)
	if !ok {
		t.Fatal("parse AUTH_HELLO")
	}
	challenge, err := state.createChallenge(hello, addr, controlAuthMeta{keyID: 1, sessionID: sessionID, counter: 0})
	if err != nil {
		t.Fatal(err)
	}
	beginRaw := buildAuthenticatedControlPacket(0x12, channelID, senderID, []byte{1}, 1, key, uint64(sessionID)<<32|1)
	begin, ok := parsePacket(beginRaw, false)
	if !ok || !state.acceptPreJoinControl(begin, addr, controlAuthMeta{keyID: 1, sessionID: sessionID, counter: 1}) {
		t.Fatal("pre-JOIN authenticated counter was rejected")
	}
	if state.acceptPreJoinControl(begin, addr, controlAuthMeta{keyID: 1, sessionID: sessionID, counter: 1}) {
		t.Fatal("replayed pre-JOIN counter was accepted")
	}
	joinRaw := buildAuthenticatedControlPacket(pktJoin, channelID, senderID, challenge, 1, key, uint64(sessionID)<<32|2)
	join, ok := parsePacket(joinRaw, false)
	if !ok {
		t.Fatal("parse JOIN")
	}
	replay, ok := state.consumeJoinChallenge(join, addr, controlAuthMeta{keyID: 1, sessionID: sessionID, counter: 2})
	if !ok || replay.highest != 2 || replay.seen&0x7 != 0x7 {
		t.Fatalf("JOIN did not promote counters 0..2: %#v ok=%t", replay, ok)
	}
}

func TestMembershipRefreshEligibilityAndSenderZeroRejection(t *testing.T) {
	relay := newTestUDPConn(t)
	client := newTestUDPConn(t)
	const channelID uint32 = 83
	const senderID uint32 = 7501
	s := newServer(relay, true, false, false, 0, false, 1)
	deadline := time.Now().Add(20 * time.Second)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(client.LocalAddr().(*net.UDPAddr)): {
				addr: client.LocalAddr().(*net.UDPAddr), senderId: senderID,
				membershipLease: 30 * time.Second, keepaliveInterval: 10 * time.Second, membershipDeadline: deadline,
			},
		},
		activeTalkers: make(map[uint32]time.Time),
		codecConfigs:  make(map[uint32][]byte),
	}

	pingRaw := buildControlPacket(pktPing, channelID, senderID, make([]byte, 8), true)
	ping, ok := parsePacket(pingRaw, true)
	if !ok {
		t.Fatal("parse PING")
	}
	s.handlePacket(ping, client.LocalAddr().(*net.UDPAddr))
	_ = receiveTestPacket(t, client)
	if got := s.channels[channelID].peers[peerMapKey(client.LocalAddr().(*net.UDPAddr))].membershipDeadline; !got.Equal(deadline) {
		t.Fatalf("PING changed membership deadline: got=%s want=%s", got, deadline)
	}

	keepaliveRaw := buildControlPacket(pktKeepalive, channelID, senderID, nil, true)
	keepalive, ok := parsePacket(keepaliveRaw, true)
	if !ok {
		t.Fatal("parse KEEPALIVE")
	}
	s.handlePacket(keepalive, client.LocalAddr().(*net.UDPAddr))
	if got := s.channels[channelID].peers[peerMapKey(client.LocalAddr().(*net.UDPAddr))].membershipDeadline; !got.After(deadline) {
		t.Fatalf("KEEPALIVE did not refresh membership: got=%s old=%s", got, deadline)
	}

	zeroRaw := buildControlPacket(pktPttOn, channelID+1, 0, nil, true)
	zero, ok := parsePacket(zeroRaw, true)
	if !ok {
		t.Fatal("parse zero-sender packet")
	}
	s.handlePacket(zero, client.LocalAddr().(*net.UDPAddr))
	if _, found := s.channels[channelID+1]; found {
		t.Fatal("sender_id=0 endpoint packet created channel state")
	}
}

func TestMembershipExpiryReleasesTalkerAndClearsCodecState(t *testing.T) {
	relay := newTestUDPConn(t)
	expired := newTestUDPConn(t)
	listener := newTestUDPConn(t)
	const channelID uint32 = 84
	const expiredSenderID uint32 = 7601
	const listenerID uint32 = 7602

	s := newServer(relay, true, false, false, 0, false, 1)
	codec := append([]byte{0, 2, 0, 0, 0x2e, 0xe0, 0}, make([]byte, 12)...)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(expired.LocalAddr().(*net.UDPAddr)): {
				addr: expired.LocalAddr().(*net.UDPAddr), senderId: expiredSenderID,
				membershipLease: 30 * time.Second, keepaliveInterval: 10 * time.Second, membershipDeadline: time.Now().Add(-time.Second),
			},
			peerMapKey(listener.LocalAddr().(*net.UDPAddr)): {
				addr: listener.LocalAddr().(*net.UDPAddr), senderId: listenerID,
				membershipLease: 30 * time.Second, keepaliveInterval: 10 * time.Second, membershipDeadline: time.Now().Add(time.Minute),
			},
		},
		activeTalkers: map[uint32]time.Time{expiredSenderID: time.Now()},
		codecConfigs:  map[uint32][]byte{expiredSenderID: codec},
		mediaCodecConfigs: map[uint32]codecConfigState{
			expiredSenderID: {payload: codec, mediaKeyID: 2},
		},
	}

	s.emitMembershipExpirations(channelID)
	packet := receiveTestPacket(t, listener)
	if packet.Header.Type != pktTalkRelease || packet.Header.SenderId != expiredSenderID || len(packet.Payload) != 5 || packet.Payload[4] != talkReleaseMembershipTimeout {
		t.Fatalf("membership expiry release = type=%d sender=%d payload=%x", packet.Header.Type, packet.Header.SenderId, packet.Payload)
	}
	ch := s.channels[channelID]
	if _, exists := ch.peers[peerMapKey(expired.LocalAddr().(*net.UDPAddr))]; exists {
		t.Fatal("expired member was retained")
	}
	if _, exists := ch.activeTalkers[expiredSenderID]; exists {
		t.Fatal("expired talker remained active")
	}
	if _, exists := ch.codecConfigs[expiredSenderID]; exists {
		t.Fatal("expired sender CODEC_CONFIG cache was retained")
	}
	if _, exists := ch.mediaCodecConfigs[expiredSenderID]; exists {
		t.Fatal("expired sender media CODEC_CONFIG cache was retained")
	}
}

func TestIdentityAdmissionRequiredHandshakeAuthorizesTalk(t *testing.T) {
	relay := newTestUDPConn(t)
	client := newTestUDPConn(t)
	const channelID uint32 = 85
	const senderID uint32 = 7701
	const sessionID uint32 = 0x55667788
	issuer := "https://access.example.test"
	audience := "relay-test"
	issuerPrivate := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	issuerPublic := issuerPrivate.Public().(ed25519.PublicKey)
	clientPrivate := ed25519.NewKeyFromSeed([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	clientPublic := clientPrivate.Public().(ed25519.PublicKey)

	control, key := newRequiredControlAuthState(t, channelID)
	identity, err := newIdentityAdmissionState(identityAdmissionRequired, issuer, audience, identitySigningKeyStore{"test-kid": issuerPublic})
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(relay, false, false, false, 0, false, 1)
	s.configureControlAuth(control)
	s.configureIdentityAdmission(identity, false)

	helloRaw := buildAuthenticatedControlPacket(pktAuthHello, channelID, senderID, nil, 1, key, uint64(sessionID)<<32)
	hello, ok := parsePacket(helloRaw, false)
	if !ok {
		t.Fatal("parse AUTH_HELLO")
	}
	s.handlePacket(hello, client.LocalAddr().(*net.UDPAddr))
	authChallenge := receiveTestPacket(t, client)
	if authChallenge.Header.Type != pktAuthChallenge || !verifyControlAuthPacket(authChallenge, key) {
		t.Fatal("expected authenticated AUTH_CHALLENGE")
	}

	ticket := buildIdentityAdmissionTicket(t, issuerPrivate, issuer, audience, channelID, senderID, clientPublic, identityPermissionListen|identityPermissionTalk, nil)
	beginRaw := buildAuthenticatedControlPacket(pktIdentityBegin, channelID, senderID, identityBeginPayload(ticket, clientPublic), 1, key, uint64(sessionID)<<32|1)
	begin, ok := parsePacket(beginRaw, false)
	if !ok {
		t.Fatal("parse IDENTITY_BEGIN")
	}
	s.handlePacket(begin, client.LocalAddr().(*net.UDPAddr))
	identityChallenge := receiveTestPacket(t, client)
	if identityChallenge.Header.Type != pktIdentityChallenge || len(identityChallenge.Payload) != 36 || !verifyControlAuthPacket(identityChallenge, key) {
		t.Fatal("expected authenticated IDENTITY_CHALLENGE")
	}
	var challenge [32]byte
	copy(challenge[:], identityChallenge.Payload[4:])
	ticketHash := sha256.Sum256([]byte(ticket))
	proofMessage := identityProofMessage(challenge, channelID, senderID, ticketHash)
	proofRaw := buildAuthenticatedControlPacket(pktIdentityProof, channelID, senderID, ed25519.Sign(clientPrivate, proofMessage[:]), 1, key, uint64(sessionID)<<32|2)
	proof, ok := parsePacket(proofRaw, false)
	if !ok {
		t.Fatal("parse IDENTITY_PROOF")
	}
	s.handlePacket(proof, client.LocalAddr().(*net.UDPAddr))
	expectNoTestPacket(t, client)

	joinRaw := buildAuthenticatedControlPacket(pktJoin, channelID, senderID, authChallenge.Payload, 1, key, uint64(sessionID)<<32|3)
	join, ok := parsePacket(joinRaw, false)
	if !ok {
		t.Fatal("parse authenticated JOIN")
	}
	s.handlePacket(join, client.LocalAddr().(*net.UDPAddr))
	serverConfig := receiveTestPacket(t, client)
	if serverConfig.Header.Type != pktServerCfg || !verifyControlAuthPacket(serverConfig, key) {
		t.Fatal("identity-admitted JOIN did not receive authenticated SERVER_CONFIG")
	}
	peer := s.channels[channelID].peers[peerMapKey(client.LocalAddr().(*net.UDPAddr))]
	if peer == nil || peer.identityAdmission == nil || peer.identityAdmission.permissions != identityPermissionListen|identityPermissionTalk {
		t.Fatal("identity admission was not attached to the joined peer")
	}

	pttRaw := buildAuthenticatedControlPacket(pktPttOn, channelID, senderID, nil, 1, key, uint64(sessionID)<<32|4)
	ptt, ok := parsePacket(pttRaw, false)
	if !ok {
		t.Fatal("parse authenticated PTT_ON")
	}
	s.handlePacket(ptt, client.LocalAddr().(*net.UDPAddr))
	grant := receiveTestPacket(t, client)
	if grant.Header.Type != pktTalkGrant || !verifyControlAuthPacket(grant, key) || !s.isTalker(channelID, senderID) {
		t.Fatal("talk-permitted identity admission did not receive TALK_GRANT")
	}
}

func TestFloorInterruptPreemptsDeterministicLowestPriority(t *testing.T) {
	relay := newTestUDPConn(t)
	requesterAddr := newTestUDPConn(t)
	firstVictimAddr := newTestUDPConn(t)
	secondVictimAddr := newTestUDPConn(t)
	thirdVictimAddr := newTestUDPConn(t)
	observerAddr := newTestUDPConn(t)
	const channelID uint32 = 86
	const requesterID uint32 = 7800
	const firstVictimID uint32 = 1001
	const secondVictimID uint32 = 1005
	const thirdVictimID uint32 = 1003
	control, key := newRequiredControlAuthState(t, channelID)
	identity, err := newIdentityAdmissionState(identityAdmissionRequired, "issuer", "audience", identitySigningKeyStore{"test": ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef")).Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	admission := func(priority uint8) *identityAdmission {
		return &identityAdmission{permissions: identityPermissionListen | identityPermissionTalk | identityPermissionInterrupt, priority: priority, expiresAt: now.Add(time.Minute)}
	}
	peerFor := func(addr *net.UDPAddr, senderID uint32, sessionID uint32, priority uint8) *peer {
		return &peer{addr: addr, senderId: senderID, authenticated: true, controlSessionID: sessionID, controlKeyID: 1, controlHighest: 3, controlSeenWindow: 1, identityAdmission: admission(priority), membershipLease: 30 * time.Second, keepaliveInterval: 10 * time.Second, membershipDeadline: now.Add(time.Minute)}
	}
	s := newServer(relay, false, false, false, 0, true, 3)
	s.configureControlAuth(control)
	s.configureIdentityAdmission(identity, true)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(requesterAddr.LocalAddr().(*net.UDPAddr)):    peerFor(requesterAddr.LocalAddr().(*net.UDPAddr), requesterID, 0x11111111, 80),
			peerMapKey(firstVictimAddr.LocalAddr().(*net.UDPAddr)):  peerFor(firstVictimAddr.LocalAddr().(*net.UDPAddr), firstVictimID, 0x22222222, 20),
			peerMapKey(secondVictimAddr.LocalAddr().(*net.UDPAddr)): peerFor(secondVictimAddr.LocalAddr().(*net.UDPAddr), secondVictimID, 0x33333333, 20),
			peerMapKey(thirdVictimAddr.LocalAddr().(*net.UDPAddr)):  peerFor(thirdVictimAddr.LocalAddr().(*net.UDPAddr), thirdVictimID, 0x44444444, 40),
			peerMapKey(observerAddr.LocalAddr().(*net.UDPAddr)):     peerFor(observerAddr.LocalAddr().(*net.UDPAddr), 7801, 0x55555555, 1),
		},
		activeTalkers: map[uint32]time.Time{firstVictimID: now, secondVictimID: now, thirdVictimID: now},
		codecConfigs:  make(map[uint32][]byte),
	}

	raw := buildAuthenticatedControlPacket(pktPttRequest, channelID, requesterID, []byte{0x01}, 1, key, uint64(0x11111111)<<32|4)
	pkt, ok := parsePacket(raw, false)
	if !ok {
		t.Fatal("parse authenticated PTT_REQUEST")
	}
	s.handlePacket(pkt, requesterAddr.LocalAddr().(*net.UDPAddr))
	release := receiveTestPacket(t, observerAddr)
	grant := receiveTestPacket(t, observerAddr)
	if release.Header.Type != pktTalkRelease || release.Header.SenderId != firstVictimID || len(release.Payload) != 5 || release.Payload[4] != talkReleasePreempted {
		t.Fatalf("preemption release = type=%d sender=%d payload=%x", release.Header.Type, release.Header.SenderId, release.Payload)
	}
	if grant.Header.Type != pktTalkGrant || grant.Header.SenderId != requesterID {
		t.Fatalf("preemption grant = type=%d sender=%d", grant.Header.Type, grant.Header.SenderId)
	}
	if !verifyControlAuthPacket(release, key) || !verifyControlAuthPacket(grant, key) {
		t.Fatal("Floor Interrupt relay packets were not authenticated")
	}
	active := s.channels[channelID].activeTalkers
	if _, exists := active[firstVictimID]; exists {
		t.Fatal("lower sender ID among equal lowest priorities was not preempted")
	}
	if _, exists := active[secondVictimID]; !exists {
		t.Fatal("Floor Interrupt preempted more than one active talker")
	}
	if _, exists := active[requesterID]; !exists {
		t.Fatal("Floor Interrupt requester was not granted")
	}
	_, counters := s.relayDiagnosticsSnapshot()
	if counters.PTTRequestsTotal != 1 || counters.GrantsTotal != 1 || counters.PreemptionsTotal != 1 || counters.DenialsTotal != 0 || counters.UnauthorizedRejectionsTotal != 0 {
		t.Fatalf("Floor Interrupt preemption counters = %+v", counters)
	}
}

func TestFloorInterruptDeniesTalkOnlyAdmission(t *testing.T) {
	relay := newTestUDPConn(t)
	requesterAddr := newTestUDPConn(t)
	victimAddr := newTestUDPConn(t)
	const channelID uint32 = 87
	const requesterID uint32 = 7900
	const victimID uint32 = 7901
	control, key := newRequiredControlAuthState(t, channelID)
	identity, err := newIdentityAdmissionState(identityAdmissionRequired, "issuer", "audience", identitySigningKeyStore{"test": ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef")).Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	peerFor := func(addr *net.UDPAddr, senderID uint32, sessionID uint32, permissions uint8, priority uint8) *peer {
		return &peer{addr: addr, senderId: senderID, authenticated: true, controlSessionID: sessionID, controlKeyID: 1, controlHighest: 3, controlSeenWindow: 1, identityAdmission: &identityAdmission{permissions: permissions, priority: priority, expiresAt: now.Add(time.Minute)}, membershipLease: 30 * time.Second, keepaliveInterval: 10 * time.Second, membershipDeadline: now.Add(time.Minute)}
	}
	s := newServer(relay, false, false, false, 0, false, 1)
	s.configureControlAuth(control)
	s.configureIdentityAdmission(identity, true)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(requesterAddr.LocalAddr().(*net.UDPAddr)): peerFor(requesterAddr.LocalAddr().(*net.UDPAddr), requesterID, 0x11111111, identityPermissionListen|identityPermissionTalk, 0),
			peerMapKey(victimAddr.LocalAddr().(*net.UDPAddr)):    peerFor(victimAddr.LocalAddr().(*net.UDPAddr), victimID, 0x22222222, identityPermissionListen|identityPermissionTalk|identityPermissionInterrupt, 10),
		},
		activeTalkers: map[uint32]time.Time{victimID: now},
		codecConfigs:  make(map[uint32][]byte),
	}

	raw := buildAuthenticatedControlPacket(pktPttRequest, channelID, requesterID, []byte{0x01}, 1, key, uint64(0x11111111)<<32|4)
	pkt, ok := parsePacket(raw, false)
	if !ok {
		t.Fatal("parse authenticated PTT_REQUEST")
	}
	s.handlePacket(pkt, requesterAddr.LocalAddr().(*net.UDPAddr))
	deny := receiveTestPacket(t, requesterAddr)
	if deny.Header.Type != pktTalkDeny || !verifyControlAuthPacket(deny, key) {
		t.Fatal("talk-only PTT_REQUEST did not receive an authenticated TALK_DENY")
	}
	if !s.isTalker(channelID, victimID) || s.isTalker(channelID, requesterID) {
		t.Fatal("denied PTT_REQUEST changed active talk state")
	}
	_, counters := s.relayDiagnosticsSnapshot()
	if counters.PTTRequestsTotal != 1 || counters.GrantsTotal != 0 || counters.DenialsTotal != 0 || counters.PreemptionsTotal != 0 || counters.UnauthorizedRejectionsTotal != 1 {
		t.Fatalf("Floor Interrupt unauthorized counters = %+v", counters)
	}
}

func TestFloorInterruptCountsAuthorizedNoPreemptionDeny(t *testing.T) {
	relay := newTestUDPConn(t)
	requesterAddr := newTestUDPConn(t)
	victimAddr := newTestUDPConn(t)
	const channelID uint32 = 88
	const requesterID uint32 = 8000
	const victimID uint32 = 8001
	control, key := newRequiredControlAuthState(t, channelID)
	identity, err := newIdentityAdmissionState(identityAdmissionRequired, "issuer", "audience", identitySigningKeyStore{"test": ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef")).Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	peerFor := func(addr *net.UDPAddr, senderID uint32, priority uint8) *peer {
		return &peer{
			addr:               addr,
			senderId:           senderID,
			authenticated:      true,
			controlKeyID:       1,
			identityAdmission:  &identityAdmission{permissions: identityPermissionListen | identityPermissionTalk | identityPermissionInterrupt, priority: priority, expiresAt: now.Add(time.Minute)},
			membershipDeadline: now.Add(time.Minute),
		}
	}
	s := newServer(relay, false, false, false, 0, false, 1)
	s.configureControlAuth(control)
	s.configureIdentityAdmission(identity, true)
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			peerMapKey(requesterAddr.LocalAddr().(*net.UDPAddr)): peerFor(requesterAddr.LocalAddr().(*net.UDPAddr), requesterID, 20),
			peerMapKey(victimAddr.LocalAddr().(*net.UDPAddr)):    peerFor(victimAddr.LocalAddr().(*net.UDPAddr), victimID, 20),
		},
		activeTalkers: map[uint32]time.Time{victimID: now},
		codecConfigs:  make(map[uint32][]byte),
	}
	if !s.handlePttRequest(channelID, requesterID, requesterAddr.LocalAddr().(*net.UDPAddr)) {
		t.Fatal("authorized no-preemption request did not preserve membership eligibility")
	}
	deny := receiveTestPacket(t, requesterAddr)
	if deny.Header.Type != pktTalkDeny || !verifyControlAuthPacket(deny, key) {
		t.Fatal("authorized no-preemption request did not receive TALK_DENY")
	}
	_, counters := s.relayDiagnosticsSnapshot()
	if counters.PTTRequestsTotal != 1 || counters.GrantsTotal != 0 || counters.DenialsTotal != 1 || counters.PreemptionsTotal != 0 || counters.UnauthorizedRejectionsTotal != 0 {
		t.Fatalf("Floor Interrupt no-preemption counters = %+v", counters)
	}
}

func TestIdentityAdmissionRejectsPriorityWithoutInterrupt(t *testing.T) {
	issuerPrivate := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	issuerPublic := issuerPrivate.Public().(ed25519.PublicKey)
	clientPrivate := ed25519.NewKeyFromSeed([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	clientPublic := clientPrivate.Public().(ed25519.PublicKey)
	priority := uint8(20)
	state, err := newIdentityAdmissionState(identityAdmissionRequired, "issuer", "audience", identitySigningKeyStore{"test-kid": issuerPublic})
	if err != nil {
		t.Fatal(err)
	}
	ticket := buildIdentityAdmissionTicket(t, issuerPrivate, "issuer", "audience", 88, 7902, clientPublic, identityPermissionListen|identityPermissionTalk, &priority)
	if _, reason := state.validateTicket(ticket, clientPublic, 88, 7902, time.Now()); reason != identityDenyPermissionDenied {
		t.Fatalf("priority without interrupt = denial reason %d, want %d", reason, identityDenyPermissionDenied)
	}
}

func TestIdentityAdmissionCanonicalVector(t *testing.T) {
	issuerPublic, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, err := hex.DecodeString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
	if err != nil {
		t.Fatal(err)
	}
	state, err := newIdentityAdmissionState(identityAdmissionRequired, "https://access.example.test", "incomudon-relay-test", identitySigningKeyStore{"test-ed25519-1": ed25519.PublicKey(issuerPublic)})
	if err != nil {
		t.Fatal(err)
	}
	const ticket = "eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3QtZWQyNTUxOS0xIiwidHlwIjoiaW5jb211ZG9uLWFkbWlzc2lvbitqd3QifQ.eyJhdWQiOiJpbmNvbXVkb24tcmVsYXktdGVzdCIsImNoIjoxMDAsImNuZiI6eyJqa3QiOiJPZmNUMEtaRUpUOEVVcFFodWZVYm13aVhuUWdwV1ZuRTg1a081aGYxRTU4In0sImV4cCI6MTcwMDAwMDMwMCwiaWF0IjoxNzAwMDAwMDAwLCJpc3MiOiJodHRwczovL2FjY2Vzcy5leGFtcGxlLnRlc3QiLCJqdGkiOiJ0ZXN0LXRpY2tldC0wMDAxIiwicGVybSI6Mywic2lkIjoxMDAxLCJzdWIiOiJ1c2VyLXRlc3QtMTAwMSJ9.Y1A17MPwesje1zWhPXaXXuUVatokMqbS_sYJylDqICqvb5sfybY1GR9zKaWuI8SYuRQtfFrj5AMYom19brFyCQ"
	admission, reason := state.validateTicket(ticket, ed25519.PublicKey(clientPublic), 100, 1001, time.Unix(1700000010, 0))
	if reason != 0 || admission.permissions != identityPermissionListen|identityPermissionTalk || admission.expiresAt.Unix() != 1700000300 {
		t.Fatalf("canonical admission = %+v, denial reason = %d", admission, reason)
	}

	challengeRaw, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	var challenge [32]byte
	copy(challenge[:], challengeRaw)
	message := identityProofMessage(challenge, 100, 1001, admission.ticketHash)
	if got := hex.EncodeToString(message[:]); got != "61ac99aabf2270d5497ddd17452efd49ca768d6787ceb9ffc96797f26ae7697c" {
		t.Fatalf("canonical proof message = %s", got)
	}
	proof, err := hex.DecodeString("44a06fc1eecfab3a598c42ae5805e23532b1439c8b6803ec0e2e60f54453b056f6fc99296c81e8c67657beb74ce7fe072a6f6cdb4d581fc466756673befab005")
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(clientPublic), message[:], proof) {
		t.Fatal("canonical identity proof did not verify")
	}
}

func TestManagedServiceAdmissionRequiredHandshakeAuthorizesReceiveOnlyJoin(t *testing.T) {
	relay := newTestUDPConn(t)
	service := newTestUDPConn(t)
	const channelID uint32 = 89
	const senderID uint32 = 8001
	const sessionID uint32 = 0x55667799
	issuer := "https://management.example.test"
	audience := "relay-test"
	issuerPrivate := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	issuerPublic := issuerPrivate.Public().(ed25519.PublicKey)
	servicePrivate := ed25519.NewKeyFromSeed([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	servicePublic := servicePrivate.Public().(ed25519.PublicKey)

	control, key := newRequiredControlAuthState(t, channelID)
	identity, err := newIdentityAdmissionState(identityAdmissionRequired, "identity-issuer", audience, identitySigningKeyStore{"identity": issuerPublic})
	if err != nil {
		t.Fatal(err)
	}
	serviceState, err := newServiceAdmissionState(serviceAdmissionEnabled, issuer, audience, serviceSigningKeyStore{"test-service-kid": issuerPublic})
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(relay, false, false, false, 0, false, 1)
	s.configureControlAuth(control)
	s.configureIdentityAdmission(identity, false)
	s.configureServiceAdmission(serviceState)

	helloRaw := buildAuthenticatedControlPacket(pktAuthHello, channelID, senderID, nil, 1, key, uint64(sessionID)<<32)
	hello, ok := parsePacket(helloRaw, false)
	if !ok {
		t.Fatal("parse AUTH_HELLO")
	}
	s.handlePacket(hello, service.LocalAddr().(*net.UDPAddr))
	authChallenge := receiveTestPacket(t, service)
	if authChallenge.Header.Type != pktAuthChallenge || !verifyControlAuthPacket(authChallenge, key) {
		t.Fatal("expected authenticated AUTH_CHALLENGE")
	}

	graceSeconds := uint16(120)
	grant := buildServiceAdmissionGrant(t, issuerPrivate, issuer, audience, channelID, senderID, servicePublic, "recorder", identityPermissionListen, nil, &graceSeconds)
	beginRaw := buildAuthenticatedControlPacket(pktServiceBegin, channelID, senderID, serviceAdmissionBeginPayload(grant, servicePublic), 1, key, uint64(sessionID)<<32|1)
	begin, ok := parsePacket(beginRaw, false)
	if !ok {
		t.Fatal("parse SERVICE_ADMISSION_BEGIN")
	}
	s.handlePacket(begin, service.LocalAddr().(*net.UDPAddr))
	challengePacket := receiveTestPacket(t, service)
	if challengePacket.Header.Type != pktServiceChallenge || len(challengePacket.Payload) != 36 || !verifyControlAuthPacket(challengePacket, key) {
		t.Fatal("expected authenticated SERVICE_ADMISSION_CHALLENGE")
	}
	var challenge [32]byte
	copy(challenge[:], challengePacket.Payload[4:])
	grantHash := sha256.Sum256([]byte(grant))
	proofMessage := serviceProofMessage(challenge, channelID, senderID, grantHash)
	proofRaw := buildAuthenticatedControlPacket(pktServiceProof, channelID, senderID, ed25519.Sign(servicePrivate, proofMessage[:]), 1, key, uint64(sessionID)<<32|2)
	proof, ok := parsePacket(proofRaw, false)
	if !ok {
		t.Fatal("parse SERVICE_ADMISSION_PROOF")
	}
	s.handlePacket(proof, service.LocalAddr().(*net.UDPAddr))
	expectNoTestPacket(t, service)

	joinRaw := buildAuthenticatedControlPacket(pktJoin, channelID, senderID, authChallenge.Payload, 1, key, uint64(sessionID)<<32|3)
	join, ok := parsePacket(joinRaw, false)
	if !ok {
		t.Fatal("parse authenticated JOIN")
	}
	s.handlePacket(join, service.LocalAddr().(*net.UDPAddr))
	serverConfig := receiveTestPacket(t, service)
	if serverConfig.Header.Type != pktServerCfg || !verifyControlAuthPacket(serverConfig, key) {
		t.Fatal("service-admitted JOIN did not receive authenticated SERVER_CONFIG")
	}
	peer := s.channels[channelID].peers[peerMapKey(service.LocalAddr().(*net.UDPAddr))]
	if peer == nil || peer.serviceAdmission == nil || peer.serviceAdmission.permissions != identityPermissionListen {
		t.Fatal("service admission was not attached to the joined peer")
	}

	pttRaw := buildAuthenticatedControlPacket(pktPttOn, channelID, senderID, nil, 1, key, uint64(sessionID)<<32|4)
	ptt, ok := parsePacket(pttRaw, false)
	if !ok {
		t.Fatal("parse authenticated PTT_ON")
	}
	s.handlePacket(ptt, service.LocalAddr().(*net.UDPAddr))
	expectNoTestPacket(t, service)
	if s.isTalker(channelID, senderID) {
		t.Fatal("receive-only service admission was allowed to talk")
	}
}

func TestManagedServiceAdmissionCanonicalVector(t *testing.T) {
	issuerPublic, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	servicePublic, err := hex.DecodeString("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
	if err != nil {
		t.Fatal(err)
	}
	state, err := newServiceAdmissionState(serviceAdmissionEnabled, "https://management.example.test", "incomudon-relay-test", serviceSigningKeyStore{"test-management-ed25519-1": ed25519.PublicKey(issuerPublic)})
	if err != nil {
		t.Fatal(err)
	}
	const grant = "eyJhbGciOiJFZERTQSIsImtpZCI6InRlc3QtbWFuYWdlbWVudC1lZDI1NTE5LTEiLCJ0eXAiOiJpbmNvbXVkb24tc2VydmljZS1hZG1pc3Npb24rand0In0.eyJhdWQiOiJpbmNvbXVkb24tcmVsYXktdGVzdCIsImNoIjoxMDAsImNuZiI6eyJqa3QiOiJPZmNUMEtaRUpUOEVVcFFodWZVYm13aVhuUWdwV1ZuRTg1a081aGYxRTU4In0sImV4cCI6MTcwMDAwMDYwMCwiZ3JhY2Vfc2Vjb25kcyI6MzAwLCJpYXQiOjE3MDAwMDAwMDAsImlzcyI6Imh0dHBzOi8vbWFuYWdlbWVudC5leGFtcGxlLnRlc3QiLCJqdGkiOiJ0ZXN0LXNlcnZpY2UtZ3JhbnQtMDAwMSIsInBlcm0iOjEsInJvbGUiOiJyZWNvcmRlciIsInNpZCI6MjAwMSwic3ZjIjoicmVjb3JkZXItdGVzdC0wMSJ9.zrmPPWN2UgrFsp-jn9uHlTTllplR98_WPChtiMemnMBTjsTz4QNRZ9aESxmGoyXVDYKIw2PK7UEEF1hH7qrYBg"
	admission, reason := state.validateGrant(grant, ed25519.PublicKey(servicePublic), 100, 2001, time.Unix(1700000010, 0))
	if reason != 0 || admission.permissions != identityPermissionListen || admission.grace != 300*time.Second || admission.grantExpires.Unix() != 1700000600 {
		t.Fatalf("canonical service admission = %+v, denial reason = %d", admission, reason)
	}

	challengeRaw, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	var challenge [32]byte
	copy(challenge[:], challengeRaw)
	message := serviceProofMessage(challenge, 100, 2001, admission.grantHash)
	if got := hex.EncodeToString(message[:]); got != "a92131d64a7f26ea8cec733ae2d6974cc8a95cbea5d2cc48c3ff0989f48ceb35" {
		t.Fatalf("canonical service proof message = %s", got)
	}
	proof, err := hex.DecodeString("c95380808129f3e774413c77394f4c694d2b31fab7c7e56d2c79c086b5533f3cf4222ba30a47e2cf27c86ed9ec507488c365b78487f86a25d1d85f2636658302")
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(servicePublic), message[:], proof) {
		t.Fatal("canonical service proof did not verify")
	}
}

func TestManagedServiceAdmissionRejectsUnknownGrantClaims(t *testing.T) {
	issuer := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	servicePrivate := ed25519.NewKeyFromSeed([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	servicePublic := servicePrivate.Public().(ed25519.PublicKey)
	state, err := newServiceAdmissionState(serviceAdmissionEnabled, "issuer", "audience", serviceSigningKeyStore{"test": issuer.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	header, err := json.Marshal(serviceGrantHeader{Algorithm: "EdDSA", KeyID: "test", Type: "incomudon-service-admission+jwt"})
	if err != nil {
		t.Fatal(err)
	}
	keyDigest := sha256.Sum256(servicePublic)
	claims := map[string]any{
		"iss": "issuer", "aud": "audience", "svc": "recorder-01", "jti": "service-grant-0001",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Minute).Unix(), "ch": 100, "sid": 2001,
		"role": "recorder", "perm": 1, "cnf": map[string]string{"jkt": base64.RawURLEncoding.EncodeToString(keyDigest[:])},
		"unexpected": true,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	grant := signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuer, []byte(signingInput)))
	if _, reason := state.validateGrant(grant, servicePublic, 100, 2001, time.Now()); reason != serviceDenyInvalidGrant {
		t.Fatalf("unknown claim denial reason = %d", reason)
	}
}

func TestManagedServiceAdmissionExpiryReasonsAndGrace(t *testing.T) {
	now := time.Now()
	peer := &peer{membershipDeadline: now.Add(5 * time.Second), serviceAdmission: &serviceAdmission{permissions: identityPermissionListen | identityPermissionTalk, grantExpires: now.Add(-time.Second)}}
	if reason, expired := membershipExpired(peer, now); !expired || reason != talkReleaseServiceExpired {
		t.Fatalf("service-first expiry = reason %d expired %t", reason, expired)
	}
	deadline := now.Add(-time.Second)
	peer.membershipDeadline = deadline
	peer.serviceAdmission.grantExpires = deadline
	if reason, expired := membershipExpired(peer, now); !expired || reason != talkReleaseMembershipTimeout {
		t.Fatalf("equal expiry = reason %d expired %t", reason, expired)
	}
	peer.membershipDeadline = now.Add(time.Minute)
	peer.serviceAdmission = &serviceAdmission{permissions: identityPermissionListen, grantExpires: now.Add(-time.Second), grace: 30 * time.Second}
	if _, expired := membershipExpired(peer, now); expired {
		t.Fatal("receive-only service grace did not retain membership")
	}
}

func TestIdentityExpiryReasonPrefersNormalMembershipOnTie(t *testing.T) {
	now := time.Now()
	peer := &peer{membershipDeadline: now.Add(5 * time.Second), identityAdmission: &identityAdmission{expiresAt: now.Add(-time.Second)}}
	if reason, expired := membershipExpired(peer, now); !expired || reason != talkReleaseIdentityExpired {
		t.Fatalf("identity-first expiry = reason %d expired %t", reason, expired)
	}
	deadline := now.Add(-time.Second)
	peer.membershipDeadline = deadline
	peer.identityAdmission.expiresAt = deadline
	if reason, expired := membershipExpired(peer, now); !expired || reason != talkReleaseMembershipTimeout {
		t.Fatalf("equal expiry = reason %d expired %t", reason, expired)
	}
}

func TestFloorInterruptControlAuthenticationVectors(t *testing.T) {
	key, err := hex.DecodeString("f7bf50ee89a0e406253d1a31040a54ac9681e6bacdd4346251b365a757bd5153")
	if err != nil {
		t.Fatal(err)
	}
	requestExpected, err := hex.DecodeString("011a001c0000006f000003ea002d000212345678000000040000000101c107ff2f229865a400b023975bdf0b12")
	if err != nil {
		t.Fatal(err)
	}
	request := buildAuthenticatedControlPacketWithSeq(pktPttRequest, 111, 1002, []byte{0x01}, 1, key, 0x1234567800000004, 45)
	if string(request) != string(requestExpected) {
		t.Fatalf("PTT_REQUEST vector mismatch: got=%x want=%x", request, requestExpected)
	}
	parsedRequest, ok := parsePacket(request, false)
	if !ok || !verifyControlAuthPacket(parsedRequest, key) {
		t.Fatal("PTT_REQUEST vector did not verify")
	}

	releaseExpected, err := hex.DecodeString("0108001c0000006f000003e900020002876543210000000200000001000003e907518224376c042d8280ae23ce40528737")
	if err != nil {
		t.Fatal(err)
	}
	release := buildAuthenticatedControlPacketWithSeq(pktTalkRelease, 111, 1001, talkReleasePayload(1001, talkReleasePreempted), 1, key, 0x8765432100000002, 2)
	if string(release) != string(releaseExpected) {
		t.Fatalf("PREEMPTED TALK_RELEASE vector mismatch: got=%x want=%x", release, releaseExpected)
	}
	parsedRelease, ok := parsePacket(release, false)
	if !ok || !verifyControlAuthPacket(parsedRelease, key) {
		t.Fatal("PREEMPTED TALK_RELEASE vector did not verify")
	}
}

func newTestManagementPlane(t *testing.T, server *server, apiRole string) (*managementPlane, *managementService, ed25519.PrivateKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed([]byte("0123456789abcdef0123456789abcdef"))
	service := &managementService{serviceID: "recorder-01", apiRole: apiRole, enabled: true, global: make(map[string]bool)}
	policy := managementPolicy{
		byCertificate: map[string]*managementService{}, byService: map[string]*managementService{service.serviceID: service},
		acls: map[string]map[uint32]map[uint32]managementChannelACL{
			service.serviceID: {
				100: {9001: {serviceID: service.serviceID, channelID: 100, senderID: 9001, admissionRole: "recorder", allowListen: true, enabled: true}},
			},
		},
	}
	plane, err := newManagementPlane(server, policy, managementGrantSigner{keyID: "management-test-key", key: privateKey}, "https://management.example.test", "relay-test", managementEventDeliveryLive)
	if err != nil {
		t.Fatal(err)
	}
	server.management = plane
	return plane, service, privateKey
}

func TestManagementPlaneIssuesVerifiableServiceGrant(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	plane, service, privateKey := newTestManagementPlane(t, s, "recorder")
	verificationState, err := newServiceAdmissionState(serviceAdmissionEnabled, "https://management.example.test", "relay-test", serviceSigningKeyStore{"management-test-key": privateKey.Public().(ed25519.PublicKey)})
	if err != nil {
		t.Fatal(err)
	}
	servicePrivate := ed25519.NewKeyFromSeed([]byte("abcdefghijklmnopqrstuvwxyz012345"))
	servicePublic := servicePrivate.Public().(ed25519.PublicKey)
	grant, expiresAt, permissions, priority, err := plane.issueGrant(service, serviceGrantRequest{ChannelID: 100, SenderID: 9001, Role: "recorder", ServicePublicKey: base64.RawURLEncoding.EncodeToString(servicePublic)})
	if err != nil {
		t.Fatal(err)
	}
	if permissions != identityPermissionListen || priority != 0 || !expiresAt.After(time.Now()) {
		t.Fatalf("issued grant metadata = permissions %d priority %d expires %s", permissions, priority, expiresAt)
	}
	admission, reason := verificationState.validateGrant(grant, servicePublic, 100, 9001, time.Now())
	if reason != 0 || admission.serviceID != service.serviceID || admission.permissions != identityPermissionListen {
		t.Fatalf("issued grant did not verify: %+v reason=%d", admission, reason)
	}
	if _, _, _, _, err := plane.issueGrant(service, serviceGrantRequest{ChannelID: 100, SenderID: 9001, Role: "recorder", RequestTalk: true, ServicePublicKey: base64.RawURLEncoding.EncodeToString(servicePublic)}); err == nil {
		t.Fatal("receive-only recorder ACL issued a talk-capable grant")
	}
}

func TestEmbeddedManagementPlaneDisablesAuditRetrieval(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	plane, service, _ := newTestManagementPlane(t, s, "auditor")
	request := httptest.NewRequest(http.MethodGet, "/v1/audit-records", nil)
	response := httptest.NewRecorder()
	plane.handleAuditRecords(response, request, service)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled audit retrieval status = %d", response.Code)
	}
}

func TestManagementGlobalPermissionsUseCanonicalRegistry(t *testing.T) {
	directory := t.TempDir()
	servicesPath := filepath.Join(directory, "management-services.csv")
	aclPath := filepath.Join(directory, "management-channel-acl.csv")
	permissionsPath := filepath.Join(directory, "management-global-permissions.csv")
	certificateDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := os.WriteFile(servicesPath, []byte("service_id,certificate_sha256,api_role,enabled\nmanagement-admin,"+certificateDigest+",admin,true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(aclPath, []byte("service_id,channel_id,sender_id,admission_role,allow_listen,allow_talk,allow_interrupt,interrupt_priority,enabled\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(permissionsPath, []byte("service_id,permission,enabled\nmanagement-admin,health.read,true\nmanagement-admin,service_admission.revoke,true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	policy, err := loadManagementPolicy(servicesPath, aclPath, permissionsPath)
	if err != nil {
		t.Fatal(err)
	}
	service := policy.byService["management-admin"]
	if service == nil || !service.global["health.read"] || !service.global["service_admission.revoke"] {
		t.Fatalf("global permissions = %#v", service)
	}

	if err := os.WriteFile(permissionsPath, []byte("service_id,permission,enabled\nmanagement-admin,audit.read,true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManagementPolicy(servicesPath, aclPath, permissionsPath); err == nil {
		t.Fatal("obsolete audit.read permission was accepted")
	}
}

func TestEmbeddedManagementPlaneDoesNotExposeRecordingJobs(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	plane, _, _ := newTestManagementPlane(t, s, "recorder")
	for _, path := range []string{"/v1/recording-jobs", "/v1/recording-jobs/example/stop"} {
		response := httptest.NewRecorder()
		plane.handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("recording endpoint %q status = %d, want %d", path, response.Code, http.StatusNotFound)
		}
	}
}

func TestEmbeddedManagementPlaneAdvertisesLiveOnlyCapabilities(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	plane, service, _ := newTestManagementPlane(t, s, "viewer")
	service.global["health.read"] = true
	response := httptest.NewRecorder()
	plane.handleHealth(response, httptest.NewRequest(http.MethodGet, "/v1/health", nil), service)
	if response.Code != http.StatusOK {
		t.Fatalf("health status = %d", response.Code)
	}
	var health struct {
		Status       string `json:"status"`
		Capabilities struct {
			EventDelivery  string `json:"event_delivery"`
			AuditRetrieval bool   `json:"audit_retrieval"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health.Status != "healthy" || health.Capabilities.EventDelivery != "live" || health.Capabilities.AuditRetrieval {
		t.Fatalf("unexpected health capabilities: %+v", health)
	}

	plane.publishEvent("talk_started", uint32Pointer(100), uint32Pointer(9001), nil, nil, nil, nil)
	plane.appendAudit(managementAuditRecord{ActorType: "service", ActorID: "controller", ChannelID: uint32Pointer(100), Action: "recording_start", Result: "success"})
	if len(plane.events) != 0 || len(plane.audit) != 0 {
		t.Fatalf("live-only plane retained events=%d audits=%d", len(plane.events), len(plane.audit))
	}
}

func TestEmbeddedManagementPlaneRejectsCursorsAndCanDisableEvents(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	plane, service, _ := newTestManagementPlane(t, s, "viewer")
	response := httptest.NewRecorder()
	plane.handleEvents(response, httptest.NewRequest(http.MethodGet, "/v1/events?since=1", nil), service)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("live cursor status = %d", response.Code)
	}
	response = httptest.NewRecorder()
	plane.handleEvents(response, httptest.NewRequest(http.MethodGet, "/v1/events?since=", nil), service)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("live empty cursor status = %d", response.Code)
	}
	plane.eventDelivery = managementEventDeliveryDisabled
	response = httptest.NewRecorder()
	plane.handleEvents(response, httptest.NewRequest(http.MethodGet, "/v1/events", nil), service)
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled event status = %d", response.Code)
	}
}

func TestEmbeddedManagementPlaneLiveEventsIgnoreLastEventID(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	plane, service, _ := newTestManagementPlane(t, s, "viewer")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response := newSSETestResponseRecorder()
	done := make(chan struct{})
	request := httptest.NewRequest(http.MethodGet, "/v1/events", nil).WithContext(ctx)
	request.Header.Set("Last-Event-ID", "not-a-replay-cursor")
	go func() {
		plane.handleEvents(response, request, service)
		close(done)
	}()

	deadline := time.Now().Add(time.Second)
	for {
		plane.mu.Lock()
		subscribed := len(plane.subscribers) == 1
		plane.mu.Unlock()
		if subscribed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("live event request with Last-Event-ID was not accepted")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-response.flushed:
	case <-time.After(time.Second):
		t.Fatal("live event response was not flushed")
	}
	if response.statusCode() != http.StatusOK {
		t.Fatalf("live Last-Event-ID status = %d", response.statusCode())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("live event handler did not stop")
	}
}

func TestManagementEventAuthorizationScopes(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	plane, service, _ := newTestManagementPlane(t, s, "auditor")
	if !plane.eventAllowed(service, managementEvent{Type: "talk_started", ChannelID: uint32Pointer(100)}) || plane.eventAllowed(service, managementEvent{Type: "talk_started", ChannelID: uint32Pointer(101)}) {
		t.Fatal("channel-scoped event ACL filtering is incorrect")
	}
	if plane.eventAllowed(service, managementEvent{Type: "relay_health_changed", ChannelID: nil}) {
		t.Fatal("channel-scoped auditor role incorrectly received global health event")
	}
	service.global["health.read"] = true
	if !plane.eventAllowed(service, managementEvent{Type: "relay_health_changed", ChannelID: nil}) || plane.eventAllowed(service, managementEvent{Type: "talk_started", ChannelID: uint32Pointer(101)}) {
		t.Fatal("explicit health.read did not preserve global/channel event separation")
	}
}

func TestNewServerDoesNotCreateManagementRetentionSink(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	if s.management != nil {
		t.Fatal("new Relay unexpectedly created a Management retention sink")
	}
}

func TestManagementDisabledACLDoesNotAuthorizeChannelScope(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	plane, service, _ := newTestManagementPlane(t, s, "viewer")
	acl := plane.policy.acls[service.serviceID][100][9001]
	acl.enabled = false
	plane.policy.acls[service.serviceID][100][9001] = acl
	if plane.canViewChannel(service, 100) || plane.hasAnyChannelACL(service.serviceID) {
		t.Fatal("disabled Management ACL granted channel visibility")
	}
	response := httptest.NewRecorder()
	plane.handleChannels(response, httptest.NewRequest(http.MethodGet, "/v1/channels", nil), service)
	if response.Code != http.StatusForbidden {
		t.Fatalf("disabled Management ACL list status = %d", response.Code)
	}
}

func TestManagedServiceRevocationRemovesMembership(t *testing.T) {
	relay := newTestUDPConn(t)
	serviceAddr := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	now := time.Now()
	s.configureServiceAdmission(&serviceAdmissionState{mode: serviceAdmissionEnabled, pending: make(map[serviceAdmissionKey]servicePendingAdmission), verified: make(map[serviceAdmissionKey]serviceAdmission), failed: make(map[serviceAdmissionKey]serviceAdmissionFailure), denied: make(map[serviceAdmissionDenyRule]time.Time)})
	s.channels[100] = &channel{peers: map[string]*peer{peerMapKey(serviceAddr.LocalAddr().(*net.UDPAddr)): {addr: serviceAddr.LocalAddr().(*net.UDPAddr), senderId: 9001, membershipDeadline: now.Add(time.Minute), serviceAdmission: &serviceAdmission{serviceID: "recorder-01", permissions: identityPermissionListen | identityPermissionTalk, grantExpires: now.Add(time.Minute)}}}, activeTalkers: map[uint32]time.Time{9001: now}, codecConfigs: make(map[uint32][]byte), mediaCodecConfigs: make(map[uint32]codecConfigState)}
	result, applied := s.revokeManagedServiceAdmission(serviceAdmissionRevocationTarget{channelID: 100, serviceID: "recorder-01"}, now.Add(time.Minute), now)
	if !applied || result.affectedMemberships != 1 || result.talkReleases != 1 {
		t.Fatalf("revocation result = %+v, applied=%t", result, applied)
	}
	if channel := s.channels[100]; channel != nil {
		if _, found := channel.peers[peerMapKey(serviceAddr.LocalAddr().(*net.UDPAddr))]; found || s.isTalker(100, 9001) {
			t.Fatal("revocation retained the managed service membership or active talker")
		}
	}
}

func newTestPrivateControlLink(t *testing.T, server *server) *privateControlLink {
	t.Helper()
	link, err := newPrivateControlLink(server, privateControlPolicy{byCertificate: map[string]string{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "management-main",
	}}, "relay-test", filepath.Join(t.TempDir(), "private-control-state.json"))
	if err != nil {
		t.Fatalf("new private control link: %v", err)
	}
	return link
}

func TestPrivateControlExportsLifecycleEvents(t *testing.T) {
	relay := newTestUDPConn(t)
	server := newServer(relay, false, false, false, 0, false, 1)
	link := newTestPrivateControlLink(t, server)
	server.privateControl = link
	session := &privateControlSession{
		serviceID:       "management-main",
		lifecycleEvents: true,
		send:            make(chan any, 1),
		done:            make(chan struct{}),
	}
	link.addSession(session)
	t.Cleanup(func() { link.removeSession(session) })

	server.publishManagementEvent("talk_started", uint32Pointer(100), uint32Pointer(9001), nil, nil, nil, nil)
	message := <-session.send
	event, ok := message.(privateControlLifecycleEvent)
	if !ok {
		t.Fatalf("lifecycle message type = %T", message)
	}
	if event.SchemaVersion != privateControlSchemaVersion || event.Type != privateControlLifecycleEventType || event.EventType != "talk_started" {
		t.Fatalf("unexpected lifecycle event: %+v", event)
	}
	if event.ChannelID == nil || *event.ChannelID != 100 || event.SenderID == nil || *event.SenderID != 9001 {
		t.Fatalf("lifecycle event routing fields = %+v", event)
	}
	if !validPrivateControlID(event.MessageID) {
		t.Fatalf("lifecycle message_id is not canonical: %q", event.MessageID)
	}
	if _, err := time.Parse(time.RFC3339, event.OccurredAt); err != nil {
		t.Fatalf("lifecycle occurred_at = %q: %v", event.OccurredAt, err)
	}
}

func TestPrivateControlDropsInsteadOfBlockingLifecycleEvents(t *testing.T) {
	relay := newTestUDPConn(t)
	server := newServer(relay, false, false, false, 0, false, 1)
	link := newTestPrivateControlLink(t, server)
	server.privateControl = link
	session := &privateControlSession{
		serviceID:       "management-main",
		lifecycleEvents: true,
		send:            make(chan any, 1),
		done:            make(chan struct{}),
	}
	link.addSession(session)
	t.Cleanup(func() { link.removeSession(session) })

	server.publishManagementEvent("talk_started", uint32Pointer(100), uint32Pointer(9001), nil, nil, nil, nil)
	started := time.Now()
	server.publishManagementEvent("talk_ended", uint32Pointer(100), uint32Pointer(9001), nil, nil, nil, stringPointer("CLIENT_PTT_OFF"))
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("full private control queue blocked Relay for %s", elapsed)
	}
	link.mu.Lock()
	dropped := link.dropped
	link.mu.Unlock()
	if dropped != 1 {
		t.Fatalf("dropped lifecycle events = %d, want 1", dropped)
	}
}

func TestPrivateControlFrameValidation(t *testing.T) {
	var frame bytes.Buffer
	payload := []byte(`{"schema_version":"private-control-link-v1","schema_version":"private-control-link-v1"}`)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	frame.Write(length[:])
	frame.Write(payload)
	if _, err := readPrivateControlFrame(&frame); err == nil {
		t.Fatal("duplicate JSON member was accepted")
	}
	if validPrivateControlID("AAAAAAAAAAAAAAAAAAAAAB") {
		t.Fatal("noncanonical 16-byte Base64URL ID was accepted")
	}
}

func TestPrivateControlPolicyRejectsDuplicateDisabledCertificate(t *testing.T) {
	path := t.TempDir() + "/private-control-services.csv"
	contents := "management_service_id,certificate_sha256,enabled\n" +
		"management-main,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,true\n" +
		"management-disabled,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,false\n"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("write policy CSV: %v", err)
	}
	if _, err := loadPrivateControlPolicy(path); err == nil {
		t.Fatal("duplicate certificate digest was accepted")
	}
}

func newPrivateControlTestTLSConfigs(t *testing.T) (*tls.Config, *tls.Config, string) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("create test CA key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create test CA certificate: %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse test CA certificate: %v", err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	serverCertificate, _ := newPrivateControlTestLeaf(t, caCertificate, caKey, 2, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"relay.test"})
	clientCertificate, clientDER := newPrivateControlTestLeaf(t, caCertificate, caKey, 3, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append test CA")
	}
	serverConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    roots,
	}
	clientConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{clientCertificate},
		RootCAs:      roots,
		ServerName:   "relay.test",
	}
	digest := sha256.Sum256(clientDER)
	return serverConfig, clientConfig, hex.EncodeToString(digest[:])
}

func newPrivateControlTestLeaf(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, serial int64, usages []x509.ExtKeyUsage, dnsNames []string) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("create test leaf key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("create test leaf certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal test leaf key: %v", err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("load test leaf key pair: %v", err)
	}
	return certificate, der
}

func TestPrivateControlMTLSHelloExportsOnlyAcceptedCapabilities(t *testing.T) {
	relay := newTestUDPConn(t)
	server := newServer(relay, false, false, false, 0, false, 1)
	server.configureServiceAdmission(&serviceAdmissionState{mode: serviceAdmissionEnabled, pending: make(map[serviceAdmissionKey]servicePendingAdmission), verified: make(map[serviceAdmissionKey]serviceAdmission), failed: make(map[serviceAdmissionKey]serviceAdmissionFailure), denied: make(map[serviceAdmissionDenyRule]time.Time)})
	serverConfig, clientConfig, clientDigest := newPrivateControlTestTLSConfigs(t)
	link, err := newPrivateControlLink(server, privateControlPolicy{byCertificate: map[string]string{clientDigest: "management-main"}}, "relay-test", filepath.Join(t.TempDir(), "private-control-state.json"))
	if err != nil {
		t.Fatalf("new private control link: %v", err)
	}
	serverRaw, clientRaw := net.Pipe()
	finished := make(chan struct{})
	go func() {
		link.handleConnection(tls.Server(serverRaw, serverConfig))
		close(finished)
	}()
	client := tls.Client(clientRaw, clientConfig)
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-finished:
		case <-time.After(time.Second):
			t.Error("private control connection did not close")
		}
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}
	helloID, err := newPrivateControlID()
	if err != nil {
		t.Fatalf("hello ID: %v", err)
	}
	wantEvents, wantAuditInputs, wantDiagnostics := true, true, true
	if err := writePrivateControlFrame(client, privateControlHello{
		SchemaVersion:       privateControlSchemaVersion,
		Type:                "hello",
		MessageID:           helloID,
		ManagementServiceID: "management-main",
		WantLifecycleEvents: &wantEvents,
		WantAuditInputs:     &wantAuditInputs,
		WantDiagnostics:     &wantDiagnostics,
	}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	rawAck, err := readPrivateControlFrame(client)
	if err != nil {
		t.Fatalf("read hello_ack: %v", err)
	}
	var ack privateControlHelloAck
	if err := decodePrivateControlJSON(rawAck, &ack); err != nil {
		t.Fatalf("decode hello_ack: %v", err)
	}
	if ack.Type != "hello_ack" || ack.InReplyTo != helloID || ack.RelayID != "relay-test" || !ack.LifecycleEventsAccepted || !ack.AuditInputsAccepted || !ack.DiagnosticsAccepted {
		t.Fatalf("unexpected hello_ack: %+v", ack)
	}
	rawHealth, err := readPrivateControlFrame(client)
	if err != nil {
		t.Fatalf("read initial health event: %v", err)
	}
	var health privateControlLifecycleEvent
	if err := decodePrivateControlJSON(rawHealth, &health); err != nil {
		t.Fatalf("decode initial health event: %v", err)
	}
	if health.Type != privateControlLifecycleEventType || health.EventType != "relay_health_changed" || health.ChannelID != nil || health.State == nil || *health.State != "healthy" {
		t.Fatalf("unexpected initial health event: %+v", health)
	}
	diagnosticsID, err := newPrivateControlID()
	if err != nil {
		t.Fatalf("diagnostics ID: %v", err)
	}
	if err := writePrivateControlFrame(client, privateControlGetRelayDiagnostics{SchemaVersion: privateControlSchemaVersion, Type: "get_relay_diagnostics", MessageID: diagnosticsID}); err != nil {
		t.Fatalf("write diagnostics request: %v", err)
	}
	rawDiagnostics, err := readPrivateControlFrame(client)
	if err != nil {
		t.Fatalf("read diagnostics snapshot: %v", err)
	}
	var diagnostics privateControlRelayDiagnosticsSnapshot
	if err := decodePrivateControlJSON(rawDiagnostics, &diagnostics); err != nil {
		t.Fatalf("decode diagnostics snapshot: %v", err)
	}
	if diagnostics.Type != "relay_diagnostics_snapshot" || diagnostics.InReplyTo != diagnosticsID || diagnostics.RelayID != "relay-test" || !validPrivateControlID(diagnostics.CounterEpoch) || diagnostics.FloorInterrupt != (relayFloorInterruptCounters{}) {
		t.Fatalf("unexpected diagnostics snapshot: %+v", diagnostics)
	}
	if _, err := time.Parse(time.RFC3339Nano, diagnostics.ObservedAt); err != nil {
		t.Fatalf("diagnostics observed_at: %v", err)
	}
	secondDiagnosticsID, err := newPrivateControlID()
	if err != nil {
		t.Fatalf("second diagnostics ID: %v", err)
	}
	if err := writePrivateControlFrame(client, privateControlGetRelayDiagnostics{SchemaVersion: privateControlSchemaVersion, Type: "get_relay_diagnostics", MessageID: secondDiagnosticsID}); err != nil {
		t.Fatalf("write rate-limited diagnostics request: %v", err)
	}
	rawRateLimited, err := readPrivateControlFrame(client)
	if err != nil {
		t.Fatalf("read rate-limited diagnostics error: %v", err)
	}
	var rateLimited privateControlError
	if err := decodePrivateControlJSON(rawRateLimited, &rateLimited); err != nil {
		t.Fatalf("decode rate-limited diagnostics error: %v", err)
	}
	if rateLimited.Type != "error" || rateLimited.InReplyTo != secondDiagnosticsID || rateLimited.Code != "overloaded" {
		t.Fatalf("unexpected diagnostics rate limit: %+v", rateLimited)
	}

	grantIDHash := sha256.Sum256([]byte("private-control-test-grant"))
	revocation := privateControlRevokeServiceAdmission{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "revoke_service_admission",
		MessageID:     "MDEyMzQ1Njc4OTo7PD0-Pw",
		ChannelID:     111,
		ServiceID:     "recorder-01",
		GrantIDHash:   base64.RawURLEncoding.EncodeToString(grantIDHash[:]),
		Reason:        "grant_revoked",
		DenyUntil:     time.Now().Add(time.Minute).Unix(),
	}
	if err := writePrivateControlFrame(client, revocation); err != nil {
		t.Fatalf("write revocation: %v", err)
	}
	rawRevocationAck, err := readPrivateControlFrame(client)
	if err != nil {
		t.Fatalf("read revocation ack: %v", err)
	}
	var revocationAck privateControlAck
	if err := decodePrivateControlJSON(rawRevocationAck, &revocationAck); err != nil {
		t.Fatalf("decode revocation ack: %v", err)
	}
	if revocationAck.Type != "ack" || revocationAck.InReplyTo != revocation.MessageID || revocationAck.Outcome != "applied" || revocationAck.DenyUntil != revocation.DenyUntil || revocationAck.AffectedMembershipCount != 0 || revocationAck.TalkReleaseCount != 0 {
		t.Fatalf("unexpected revocation ack: %+v", revocationAck)
	}
}
