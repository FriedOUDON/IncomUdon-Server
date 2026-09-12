package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	controlAuthHeaderSize = 12
	controlAuthPacketSize = fixedHeaderSize + controlAuthHeaderSize
	controlAuthCookieTTL  = 30 * time.Second
	controlReplayWindow   = 64
)

type controlAuthPolicy string

const (
	controlAuthOff      controlAuthPolicy = "off"
	controlAuthOptional controlAuthPolicy = "optional"
	controlAuthRequired controlAuthPolicy = "required"
)

type controlKeyStore map[uint32]map[uint32][]byte

type controlAuthState struct {
	mu              sync.Mutex
	policy          controlAuthPolicy
	keys            controlKeyStore
	cookieSecret    []byte
	relayInstanceID uint32
	relayCounter    uint32
	challenges      map[authChallengeKey]time.Time
}

type authChallengeKey struct {
	channelID uint32
	senderID  uint32
	keyID     uint32
	sessionID uint32
	address   string
	expiresAt uint32
	cookie    [authTagSize]byte
}

type controlAuthMeta struct {
	keyID     uint32
	sessionID uint32
	counter   uint32
}

func newControlAuthState(policy controlAuthPolicy, keys controlKeyStore, cookieSecret []byte) (*controlAuthState, error) {
	if policy != controlAuthOff && policy != controlAuthOptional && policy != controlAuthRequired {
		return nil, fmt.Errorf("unsupported control authentication policy %q", policy)
	}
	if keys == nil {
		keys = make(controlKeyStore)
	}
	if policy == controlAuthRequired && len(keys) == 0 {
		return nil, errors.New("control authentication required but no control keys are configured")
	}
	if len(keys) > 0 && len(cookieSecret) < 32 {
		return nil, errors.New("configured control authentication requires a cookie secret of at least 32 bytes")
	}

	state := &controlAuthState{
		policy:       policy,
		keys:         keys,
		cookieSecret: append([]byte(nil), cookieSecret...),
		challenges:   make(map[authChallengeKey]time.Time),
	}
	if policy != controlAuthOff {
		var instance [4]byte
		if _, err := rand.Read(instance[:]); err != nil {
			return nil, fmt.Errorf("generate relay control instance ID: %w", err)
		}
		state.relayInstanceID = binary.BigEndian.Uint32(instance[:])
		if state.relayInstanceID == 0 {
			state.relayInstanceID = 1
		}
	}
	return state, nil
}

func parseControlAuthPolicy(value string) (controlAuthPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(controlAuthOff):
		return controlAuthOff, nil
	case string(controlAuthOptional):
		return controlAuthOptional, nil
	case string(controlAuthRequired):
		return controlAuthRequired, nil
	default:
		return "", fmt.Errorf("must be off, optional, or required")
	}
}

func loadControlKeyStore(path string) (controlKeyStore, error) {
	keys := make(controlKeyStore)
	if strings.TrimSpace(path) == "" {
		return keys, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open control key file: %w", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read control key CSV: %w", err)
	}
	for index, record := range records {
		if len(record) == 0 || (len(record) == 1 && strings.TrimSpace(record[0]) == "") {
			continue
		}
		if len(record) != 3 {
			return nil, fmt.Errorf("control key CSV row %d must contain channel_id,key_id,control_key_base64", index+1)
		}
		if index == 0 && strings.EqualFold(strings.TrimSpace(record[0]), "channel_id") {
			continue
		}
		channelID, err := parseUint32(record[0])
		if err != nil {
			return nil, fmt.Errorf("control key CSV row %d channel_id: %w", index+1, err)
		}
		keyID, err := parseUint32(record[1])
		if err != nil || keyID == 0 {
			if err == nil {
				err = errors.New("must be non-zero")
			}
			return nil, fmt.Errorf("control key CSV row %d key_id: %w", index+1, err)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(record[2]))
		if err != nil || len(key) != 32 {
			if err == nil {
				err = fmt.Errorf("must decode to 32 bytes")
			}
			return nil, fmt.Errorf("control key CSV row %d control_key_base64: %w", index+1, err)
		}
		if keys[channelID] == nil {
			keys[channelID] = make(map[uint32][]byte)
		}
		if _, exists := keys[channelID][keyID]; exists {
			return nil, fmt.Errorf("duplicate control key CSV entry for channel %d key ID %d", channelID, keyID)
		}
		keys[channelID][keyID] = append([]byte(nil), key...)
	}
	return keys, nil
}

func parseUint32(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(parsed), nil
}

func loadCookieSecret(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read control cookie secret: %w", err)
	}
	value := strings.TrimSpace(string(data))
	if decoded, err := base64.StdEncoding.DecodeString(value); err == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	if len(data) < 32 {
		return nil, errors.New("control cookie secret must contain at least 32 raw bytes or base64-decoded bytes")
	}
	return append([]byte(nil), data...), nil
}

func (a *controlAuthState) requires(channelID uint32) bool {
	if a == nil {
		return false
	}
	switch a.policy {
	case controlAuthRequired:
		return true
	case controlAuthOptional:
		return len(a.keys[channelID]) > 0
	default:
		return false
	}
}

func (a *controlAuthState) key(channelID uint32, keyID uint32) []byte {
	if a == nil || keyID == 0 {
		return nil
	}
	return a.keys[channelID][keyID]
}

func controlAuthTag(key []byte, packetWithoutTag []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("incomudon-control-auth-v1\x00"))
	mac.Write(packetWithoutTag)
	return mac.Sum(nil)[:authTagSize]
}

func verifyControlAuthPacket(pkt parsedPacket, key []byte) bool {
	if len(key) != 32 || pkt.Header.HeaderLen != controlAuthPacketSize ||
		pkt.Header.Flags&packetFlagControlAuthV1 == 0 ||
		pkt.Header.Flags&packetFlagAESGCMV2HeaderAAD != 0 ||
		pkt.Sec.ControlNonce == 0 || pkt.Sec.KeyID == 0 || len(pkt.Tag) != authTagSize ||
		len(pkt.Raw) < controlAuthPacketSize+authTagSize {
		return false
	}
	want := controlAuthTag(key, pkt.Raw[:len(pkt.Raw)-authTagSize])
	return subtle.ConstantTimeCompare(want, pkt.Tag) == 1
}

func buildAuthenticatedControlPacket(pktType uint8, channelID uint32, senderID uint32, payload []byte, keyID uint32, key []byte, nonce uint64) []byte {
	packet := make([]byte, controlAuthPacketSize+len(payload)+authTagSize)
	packet[0] = protocolVersion
	packet[1] = pktType
	binary.BigEndian.PutUint16(packet[2:4], controlAuthPacketSize)
	binary.BigEndian.PutUint32(packet[4:8], channelID)
	binary.BigEndian.PutUint32(packet[8:12], senderID)
	binary.BigEndian.PutUint16(packet[12:14], 0)
	binary.BigEndian.PutUint16(packet[14:16], packetFlagControlAuthV1)
	binary.BigEndian.PutUint64(packet[16:24], nonce)
	binary.BigEndian.PutUint32(packet[24:28], keyID)
	copy(packet[28:28+len(payload)], payload)
	copy(packet[len(packet)-authTagSize:], controlAuthTag(key, packet[:len(packet)-authTagSize]))
	return packet
}

func (a *controlAuthState) nextRelayNonce() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	nonce := uint64(a.relayInstanceID)<<32 | uint64(a.relayCounter)
	a.relayCounter++
	return nonce
}

func (a *controlAuthState) createChallenge(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta) ([]byte, error) {
	if meta.counter != 0 || meta.sessionID == 0 || addr == nil {
		return nil, errors.New("invalid AUTH_HELLO session nonce")
	}
	key := a.key(pkt.Header.ChannelId, meta.keyID)
	if len(key) != 32 {
		return nil, errors.New("unknown control key")
	}
	expiresAt := uint32(time.Now().Add(controlAuthCookieTTL).Unix())
	cookie := a.cookie(pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, meta.sessionID, expiresAt, addr)
	challengeKey := authChallengeKey{
		channelID: pkt.Header.ChannelId, senderID: pkt.Header.SenderId, keyID: meta.keyID,
		sessionID: meta.sessionID, address: peerMapKey(addr), expiresAt: expiresAt,
	}
	copy(challengeKey.cookie[:], cookie)

	a.mu.Lock()
	now := time.Now()
	for candidate, deadline := range a.challenges {
		if !deadline.After(now) {
			delete(a.challenges, candidate)
		}
	}
	a.challenges[challengeKey] = time.Unix(int64(expiresAt), 0)
	a.mu.Unlock()

	payload := make([]byte, 20)
	binary.BigEndian.PutUint32(payload[:4], expiresAt)
	copy(payload[4:], cookie)
	return payload, nil
}

func (a *controlAuthState) consumeJoinChallenge(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta) bool {
	if meta.counter != 1 || meta.sessionID == 0 || addr == nil || len(pkt.Payload) != 20 {
		return false
	}
	expiresAt := binary.BigEndian.Uint32(pkt.Payload[:4])
	if expiresAt < uint32(time.Now().Unix()) {
		return false
	}
	want := a.cookie(pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, meta.sessionID, expiresAt, addr)
	if subtle.ConstantTimeCompare(want, pkt.Payload[4:]) != 1 {
		return false
	}
	challengeKey := authChallengeKey{
		channelID: pkt.Header.ChannelId, senderID: pkt.Header.SenderId, keyID: meta.keyID,
		sessionID: meta.sessionID, address: peerMapKey(addr), expiresAt: expiresAt,
	}
	copy(challengeKey.cookie[:], pkt.Payload[4:])
	a.mu.Lock()
	defer a.mu.Unlock()
	deadline, found := a.challenges[challengeKey]
	if !found || !deadline.After(time.Now()) {
		delete(a.challenges, challengeKey)
		return false
	}
	delete(a.challenges, challengeKey)
	return true
}

func (a *controlAuthState) cookie(channelID uint32, senderID uint32, keyID uint32, sessionID uint32, expiresAt uint32, addr *net.UDPAddr) []byte {
	input := make([]byte, 0, 64)
	input = append(input, []byte("incomudon-control-cookie-v1\x00")...)
	ip := addr.IP.To16()
	if ipv4 := addr.IP.To4(); ipv4 != nil {
		// The wire format requires IPv4-mapped IPv6, not a zero-extended IPv4
		// address. net.UDPAddr may expose either four- or sixteen-byte IPv4.
		ip = net.IPv4(ipv4[0], ipv4[1], ipv4[2], ipv4[3]).To16()
	}
	if ip == nil {
		ip = make([]byte, 16)
	}
	input = append(input, ip...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(addr.Port))
	input = append(input, port...)
	for _, value := range []uint32{channelID, senderID, keyID, sessionID, expiresAt} {
		field := make([]byte, 4)
		binary.BigEndian.PutUint32(field, value)
		input = append(input, field...)
	}
	mac := hmac.New(sha256.New, a.cookieSecret)
	mac.Write(input)
	return mac.Sum(nil)[:authTagSize]
}

func controlNonceParts(nonce uint64) (sessionID uint32, counter uint32) {
	return uint32(nonce >> 32), uint32(nonce)
}

func (s *server) controlAuthRequired(channelID uint32) bool {
	return s.controlAuth != nil && s.controlAuth.requires(channelID)
}

func (s *server) verifyIncomingControl(pkt parsedPacket) (controlAuthMeta, bool) {
	if s.controlAuth == nil {
		return controlAuthMeta{}, false
	}
	key := s.controlAuth.key(pkt.Header.ChannelId, pkt.Sec.KeyID)
	if !verifyControlAuthPacket(pkt, key) {
		return controlAuthMeta{}, false
	}
	sessionID, counter := controlNonceParts(pkt.Sec.ControlNonce)
	if sessionID == 0 {
		return controlAuthMeta{}, false
	}
	return controlAuthMeta{keyID: pkt.Sec.KeyID, sessionID: sessionID, counter: counter}, true
}

func (s *server) upsertAuthenticatedPeer(channelID uint32, senderID uint32, addr *net.UDPAddr, meta controlAuthMeta) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.getOrCreateChannel(channelID)
	key := peerMapKey(addr)
	if key == "" {
		return
	}
	p := ch.peers[key]
	if p == nil {
		p = &peer{addr: addr}
		ch.peers[key] = p
	}
	p.senderId = senderID
	p.addr = addr
	p.lastSeen = time.Now()
	p.authenticated = true
	p.controlSessionID = meta.sessionID
	p.controlKeyID = meta.keyID
	p.controlHighest = meta.counter
	p.controlSeenWindow = 1
}

func (s *server) acceptAuthenticatedPeerControl(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[pkt.Header.ChannelId]
	if ch == nil || addr == nil {
		return false
	}
	p := ch.peers[peerMapKey(addr)]
	if p == nil || !p.authenticated || p.senderId != pkt.Header.SenderId ||
		p.controlKeyID != meta.keyID || p.controlSessionID != meta.sessionID {
		return false
	}
	if !acceptReplayCounter(&p.controlHighest, &p.controlSeenWindow, meta.counter) {
		return false
	}
	p.lastSeen = time.Now()
	return true
}

func acceptReplayCounter(highest *uint32, seen *uint64, counter uint32) bool {
	if counter > *highest {
		delta := counter - *highest
		if delta >= controlReplayWindow {
			*seen = 1
		} else {
			*seen = (*seen << delta) | 1
		}
		*highest = counter
		return true
	}
	delta := *highest - counter
	if delta >= controlReplayWindow {
		return false
	}
	mask := uint64(1) << delta
	if *seen&mask != 0 {
		return false
	}
	*seen |= mask
	return true
}

func (s *server) isAuthenticatedPeer(channelID uint32, senderID uint32, addr *net.UDPAddr) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[channelID]
	if ch == nil || addr == nil {
		return false
	}
	p := ch.peers[peerMapKey(addr)]
	return p != nil && p.authenticated && p.senderId == senderID
}

func (s *server) mediaMatchesCodecConfig(pkt parsedPacket) bool {
	if pkt.Header.HeaderLen != aesGCMV2HeaderSize ||
		pkt.Header.Flags&packetFlagAESGCMV2HeaderAAD == 0 ||
		pkt.Sec.KeyID != 2 {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[pkt.Header.ChannelId]
	if ch == nil {
		return false
	}
	config, found := ch.mediaCodecConfigs[pkt.Header.SenderId]
	return found && config.mediaKeyID == pkt.Sec.KeyID && config.mediaNonceBase == pkt.Sec.MediaNonceBase
}

func (s *server) sendAuthenticatedChallenge(addr *net.UDPAddr, channelID uint32, senderID uint32, keyID uint32, payload []byte) {
	if s.controlAuth == nil || addr == nil {
		return
	}
	key := s.controlAuth.key(channelID, keyID)
	if len(key) != 32 {
		return
	}
	packet := buildAuthenticatedControlPacket(pktAuthChallenge, channelID, senderID, payload, keyID, key, s.controlAuth.nextRelayNonce())
	if _, err := s.conn.WriteToUDP(packet, addr); err != nil {
		log.Printf("auth_challenge send failed ch=%d sender=%d: %v", channelID, senderID, err)
	}
}

func (s *server) relayControlForPeer(channelID uint32, peer *peer, packetType uint8, senderID uint32, payload []byte) []byte {
	if !s.controlAuthRequired(channelID) {
		return buildControlPacket(packetType, channelID, senderID, payload, s.noCrypto)
	}
	if s.controlAuth == nil || peer == nil || !peer.authenticated {
		return nil
	}
	keyID := peer.controlKeyID
	key := s.controlAuth.key(channelID, keyID)
	if len(key) != 32 {
		return nil
	}
	return buildAuthenticatedControlPacket(packetType, channelID, senderID, payload, keyID, key, s.controlAuth.nextRelayNonce())
}

func (s *server) sendRelayControlTo(channelID uint32, targetSenderID uint32, packetType uint8, senderID uint32, payload []byte) {
	s.mu.Lock()
	ch := s.channels[channelID]
	peers := make([]*peer, 0)
	if ch != nil {
		for _, peer := range ch.peers {
			if peer.senderId == targetSenderID {
				peers = append(peers, peer)
			}
		}
	}
	s.mu.Unlock()
	for _, peer := range peers {
		if packet := s.relayControlForPeer(channelID, peer, packetType, senderID, payload); len(packet) > 0 {
			s.conn.WriteToUDP(packet, peer.addr)
		}
	}
}

func (s *server) broadcastRelayControl(channelID uint32, packetType uint8, senderID uint32, payload []byte) {
	s.mu.Lock()
	ch := s.channels[channelID]
	peers := make([]*peer, 0)
	if ch != nil {
		for _, peer := range ch.peers {
			peers = append(peers, peer)
		}
	}
	s.mu.Unlock()
	for _, peer := range peers {
		if packet := s.relayControlForPeer(channelID, peer, packetType, senderID, payload); len(packet) > 0 {
			s.conn.WriteToUDP(packet, peer.addr)
		}
	}
}
