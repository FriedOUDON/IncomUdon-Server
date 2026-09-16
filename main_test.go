package main

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

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
	if forwarded.Header.Seq == pkt.Header.Seq {
		t.Fatal("forwarded CODEC_CONFIG reused the client fixed-header sequence")
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
