package main

import (
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
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			"requester": {addr: requester.LocalAddr().(*net.UDPAddr), senderId: requesterID},
			"listener":  {addr: listener.LocalAddr().(*net.UDPAddr), senderId: 1002},
		},
		activeTalkers: map[uint32]time.Time{requesterID: time.Now()},
		codecConfigs:  make(map[uint32][]byte),
	}

	s.handlePttOn(channelID, requesterID)
	packet := receiveTestPacket(t, requester)
	if packet.Header.Type != pktTalkGrant {
		t.Fatalf("expected grant, got type=%d", packet.Header.Type)
	}
	expectNoTestPacket(t, listener)
}

func TestJoinSyncSendsCodecConfigBeforeGrant(t *testing.T) {
	relay := newTestUDPConn(t)
	joiner := newTestUDPConn(t)
	const channelID uint32 = 42
	const talkerID uint32 = 2001
	const joinerID uint32 = 2002
	codecConfig := []byte{0, 1, 0x06, 0x40}

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
			"sender":   {addr: sender.LocalAddr().(*net.UDPAddr), senderId: senderID},
			"listener": {addr: listener.LocalAddr().(*net.UDPAddr), senderId: 3002},
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
	s.channels[channelID] = &channel{
		peers: map[string]*peer{
			"sender":   {addr: sender.LocalAddr().(*net.UDPAddr), senderId: senderID},
			"listener": {addr: listener.LocalAddr().(*net.UDPAddr), senderId: 4002},
		},
		activeTalkers: map[uint32]time.Time{senderID: time.Now()},
		codecConfigs:  make(map[uint32][]byte),
	}

	// The Relay does not decrypt media. It must preserve the v2 AAD bytes
	// exactly so receivers can authenticate the forwarded packet.
	raw := buildControlPacket(pktAudio, channelID, senderID, []byte{1, 2, 3}, false)
	raw[14] = byte(packetFlagAESGCMV2HeaderAAD >> 8)
	raw[15] = byte(packetFlagAESGCMV2HeaderAAD)
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
