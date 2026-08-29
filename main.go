package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

const (
	protocolVersion    = 1
	fixedHeaderSize    = 16
	securityHeaderSize = 12
	authTagSize        = 16
)

const (
	pktAudio       = 0x01
	pktPttOn       = 0x02
	pktPttOff      = 0x03
	pktKeepalive   = 0x04
	pktJoin        = 0x05
	pktLeave       = 0x06
	pktTalkGrant   = 0x07
	pktTalkRelease = 0x08
	pktTalkDeny    = 0x09
	pktKeyExchange = 0x0A
	pktCodecConfig = 0x0B
	pktFec         = 0x0C
	pktServerCfg   = 0x0D
)

const (
	udpWarnPayloadBytes = 1200
	udpFragPayloadBytes = 1472
)

type packetHeader struct {
	Version   uint8
	Type      uint8
	HeaderLen uint16
	ChannelId uint32
	SenderId  uint32
	Seq       uint16
	Flags     uint16
}

type securityHeader struct {
	Nonce uint64
	KeyId uint32
}

type parsedPacket struct {
	Header  packetHeader
	Sec     securityHeader
	Payload []byte
	Tag     []byte
	Raw     []byte
}

type peer struct {
	senderId uint32
	addr     *net.UDPAddr
	lastSeen time.Time
}

type channel struct {
	peers         map[string]*peer
	activeTalkers map[uint32]time.Time
	codecConfigs  map[uint32][]byte
}

type server struct {
	mu                  sync.Mutex
	channels            map[uint32]*channel
	conn                *net.UDPConn
	noCrypto            bool
	logPackets          bool
	logAudio            bool
	sizeWindowStart     time.Time
	sizeWindowMax       int
	sizeWindowMaxType   uint8
	sizeWindowMaxCh     uint32
	sizeWindowMaxSender uint32
	sizeWindowOverWarn  int
	sizeWindowOverFrag  int
	lastWarnLog         time.Time
	lastFragLog         time.Time
	talkMax             time.Duration
	multiTalk           bool
	maxActiveTalkers    int
}

func peerMapKey(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func newServer(conn *net.UDPConn, noCrypto bool, logPackets bool, logAudio bool, talkMax time.Duration, multiTalk bool, maxActiveTalkers int) *server {
	if maxActiveTalkers < 1 {
		maxActiveTalkers = 1
	}
	return &server{
		channels:         make(map[uint32]*channel),
		conn:             conn,
		noCrypto:         noCrypto,
		logPackets:       logPackets,
		logAudio:         logAudio,
		sizeWindowStart:  time.Now(),
		talkMax:          talkMax,
		multiTalk:        multiTalk,
		maxActiveTalkers: maxActiveTalkers,
	}
}

// directoryParticipants returns the relay's current peer view without exposing
// endpoint addresses. The directory publisher owns serialization and encrypts
// this data before it leaves the relay process.
func (s *server) directoryParticipants() []directoryParticipant {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	byIdentity := make(map[[2]uint32]directoryParticipant)
	for channelID, ch := range s.channels {
		for _, peer := range ch.peers {
			if peer == nil || peer.senderId == 0 || peer.lastSeen.Before(now.Add(-directoryMaxValidity)) {
				continue
			}
			key := [2]uint32{channelID, peer.senderId}
			candidate := directoryParticipant{
				ChannelID:  channelID,
				SenderID:   peer.senderId,
				LastSeenAt: peer.lastSeen.Unix(),
				Talking:    false,
			}
			if _, active := ch.activeTalkers[peer.senderId]; active {
				candidate.Talking = true
			}
			if previous, exists := byIdentity[key]; !exists || candidate.LastSeenAt > previous.LastSeenAt {
				byIdentity[key] = candidate
			}
		}
	}

	participants := make([]directoryParticipant, 0, len(byIdentity))
	for _, participant := range byIdentity {
		participants = append(participants, participant)
	}
	sort.Slice(participants, func(i, j int) bool {
		if participants[i].ChannelID != participants[j].ChannelID {
			return participants[i].ChannelID < participants[j].ChannelID
		}
		return participants[i].SenderID < participants[j].SenderID
	})
	return participants
}

func (s *server) run() {
	buf := make([]byte, 2048)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("read error: %v", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		pkt, ok := parsePacket(data, s.noCrypto)
		if !ok {
			continue
		}

		if s.logPackets {
			s.logPacket(pkt, addr, n)
		}
		s.observePacketSize(pkt, addr, n)

		s.handlePacket(pkt, addr)
	}
}

func (s *server) handlePacket(pkt parsedPacket, addr *net.UDPAddr) {
	if pkt.Header.Version != protocolVersion {
		return
	}

	if releasedTalkerIDs := s.expireTalkIfNeeded(pkt.Header.ChannelId); len(releasedTalkerIDs) > 0 {
		for _, releasedTalkerID := range releasedTalkerIDs {
			log.Printf("talk_timeout ch=%d talker=%d max=%s",
				pkt.Header.ChannelId,
				releasedTalkerID,
				s.talkMax)
			s.broadcast(pkt.Header.ChannelId, buildTalkPacket(pktTalkRelease, pkt.Header.ChannelId, releasedTalkerID, s.noCrypto))
		}
	}

	s.mu.Lock()
	ch := s.getOrCreateChannel(pkt.Header.ChannelId)
	s.upsertPeer(ch, pkt.Header.SenderId, addr)
	s.mu.Unlock()

	switch pkt.Header.Type {
	case pktJoin:
		log.Printf("join ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
		s.broadcastExceptAddr(pkt.Header.ChannelId, addr, pkt.Raw)
		s.sendTo(pkt.Header.ChannelId, pkt.Header.SenderId, pkt.Raw)
		s.sendServerConfig(pkt.Header.ChannelId, pkt.Header.SenderId)
		s.sendCurrentTalkState(pkt.Header.ChannelId, pkt.Header.SenderId)
	case pktLeave:
		log.Printf("leave ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
		s.removePeer(pkt.Header.ChannelId, pkt.Header.SenderId, addr)
		s.broadcastExceptAddr(pkt.Header.ChannelId, addr, pkt.Raw)
		s.releaseTalkIfNeeded(pkt.Header.ChannelId, pkt.Header.SenderId)
	case pktPttOn:
		log.Printf("ptt_on ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
		s.handlePttOn(pkt.Header.ChannelId, pkt.Header.SenderId)
	case pktPttOff:
		log.Printf("ptt_off ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
		s.handlePttOff(pkt.Header.ChannelId, pkt.Header.SenderId)
	case pktCodecConfig:
		s.cacheCodecConfig(pkt.Header.ChannelId, pkt.Header.SenderId, pkt.Payload)
		s.broadcastExceptAddr(pkt.Header.ChannelId, addr, pkt.Raw)
	case pktAudio, pktFec:
		// FEC belongs to the same authorized media stream as audio.
		if s.isTalker(pkt.Header.ChannelId, pkt.Header.SenderId) {
			s.broadcastExceptAddr(pkt.Header.ChannelId, addr, pkt.Raw)
		}
	default:
		s.broadcastExceptAddr(pkt.Header.ChannelId, addr, pkt.Raw)
	}
}

func (s *server) getOrCreateChannel(channelId uint32) *channel {
	ch, ok := s.channels[channelId]
	if !ok {
		ch = &channel{
			peers:         make(map[string]*peer),
			activeTalkers: make(map[uint32]time.Time),
			codecConfigs:  make(map[uint32][]byte),
		}
		s.channels[channelId] = ch
	}
	return ch
}

func sortedActiveTalkers(ch *channel) []uint32 {
	if ch == nil || len(ch.activeTalkers) == 0 {
		return nil
	}

	talkers := make([]uint32, 0, len(ch.activeTalkers))
	for senderID := range ch.activeTalkers {
		talkers = append(talkers, senderID)
	}
	sort.Slice(talkers, func(i, j int) bool { return talkers[i] < talkers[j] })
	return talkers
}

func firstActiveTalker(ch *channel) uint32 {
	talkers := sortedActiveTalkers(ch)
	if len(talkers) == 0 {
		return 0
	}
	return talkers[0]
}

func (s *server) cacheCodecConfig(channelId uint32, senderId uint32, payload []byte) {
	if len(payload) < 3 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ch := s.channels[channelId]
	if ch == nil {
		return
	}
	if ch.codecConfigs == nil {
		ch.codecConfigs = make(map[uint32][]byte)
	}
	ch.codecConfigs[senderId] = append(ch.codecConfigs[senderId][:0], payload...)
}

func (s *server) upsertPeer(ch *channel, senderId uint32, addr *net.UDPAddr) {
	key := peerMapKey(addr)
	if key == "" {
		return
	}

	p, ok := ch.peers[key]
	if !ok {
		p = &peer{addr: addr}
		ch.peers[key] = p
	}
	p.senderId = senderId
	p.addr = addr
	p.lastSeen = time.Now()
}

func (s *server) removePeer(channelId uint32, senderId uint32, addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := s.channels[channelId]
	if ch == nil {
		return
	}

	removed := false
	key := peerMapKey(addr)
	if key != "" {
		if p, ok := ch.peers[key]; ok && (senderId == 0 || p.senderId == senderId) {
			delete(ch.peers, key)
			removed = true
		}
	}
	if !removed && senderId != 0 {
		for k, p := range ch.peers {
			if p.senderId == senderId {
				delete(ch.peers, k)
				break
			}
		}
	}

	if len(ch.peers) == 0 {
		delete(s.channels, channelId)
	}
}

func (s *server) isTalker(channelId uint32, senderId uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := s.channels[channelId]
	if ch == nil {
		return false
	}
	_, ok := ch.activeTalkers[senderId]
	return ok
}

func (s *server) handlePttOn(channelId uint32, senderId uint32) {
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil {
		s.mu.Unlock()
		return
	}

	now := time.Now()
	if _, ok := ch.activeTalkers[senderId]; ok {
		ch.activeTalkers[senderId] = now
		s.mu.Unlock()
		log.Printf("talk_grant ch=%d talker=%d (already granted)", channelId, senderId)
		// A duplicated PTT_ON should only repair a lost grant for its sender.
		// Broadcasting it resets remote receivers' per-talker playout state.
		s.sendTo(channelId, senderId, buildTalkPacket(pktTalkGrant, channelId, senderId, s.noCrypto))
		return
	}

	limit := 1
	if s.multiTalk {
		limit = s.maxActiveTalkers
	}
	if limit < 1 {
		limit = 1
	}

	if len(ch.activeTalkers) < limit {
		ch.activeTalkers[senderId] = now
		activeCount := len(ch.activeTalkers)
		s.mu.Unlock()
		log.Printf("talk_grant ch=%d talker=%d active=%d/%d multi=%t", channelId, senderId, activeCount, limit, s.multiTalk)
		s.broadcast(channelId, buildTalkPacket(pktTalkGrant, channelId, senderId, s.noCrypto))
		return
	}

	current := firstActiveTalker(ch)
	activeCount := len(ch.activeTalkers)
	s.mu.Unlock()
	log.Printf("talk_deny ch=%d requester=%d current=%d active=%d/%d multi=%t", channelId, senderId, current, activeCount, limit, s.multiTalk)
	s.sendTo(channelId, senderId, buildTalkPacket(pktTalkDeny, channelId, current, s.noCrypto))
}

func (s *server) handlePttOff(channelId uint32, senderId uint32) {
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil {
		s.mu.Unlock()
		return
	}

	if _, ok := ch.activeTalkers[senderId]; !ok {
		s.mu.Unlock()
		return
	}

	delete(ch.activeTalkers, senderId)
	s.mu.Unlock()
	log.Printf("talk_release ch=%d talker=%d", channelId, senderId)
	s.broadcast(channelId, buildTalkPacket(pktTalkRelease, channelId, senderId, s.noCrypto))
}

func (s *server) releaseTalkIfNeeded(channelId uint32, senderId uint32) {
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil {
		s.mu.Unlock()
		return
	}

	if _, ok := ch.activeTalkers[senderId]; !ok {
		s.mu.Unlock()
		return
	}

	delete(ch.activeTalkers, senderId)
	s.mu.Unlock()
	log.Printf("talk_release ch=%d talker=%d (peer_left)", channelId, senderId)
	s.broadcast(channelId, buildTalkPacket(pktTalkRelease, channelId, senderId, s.noCrypto))
}

func (s *server) expireTalkIfNeeded(channelId uint32) []uint32 {
	if s.talkMax <= 0 {
		return nil
	}

	now := time.Now()
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil || len(ch.activeTalkers) == 0 {
		s.mu.Unlock()
		return nil
	}

	released := make([]uint32, 0, len(ch.activeTalkers))
	for senderID, startedAt := range ch.activeTalkers {
		if startedAt.IsZero() {
			ch.activeTalkers[senderID] = now
			continue
		}
		if now.Sub(startedAt) < s.talkMax {
			continue
		}
		delete(ch.activeTalkers, senderID)
		released = append(released, senderID)
	}
	s.mu.Unlock()
	sort.Slice(released, func(i, j int) bool { return released[i] < released[j] })
	return released
}

func durationToSecondsClamped(d time.Duration) uint16 {
	if d <= 0 {
		return 0
	}
	sec := int(d / time.Second)
	if sec <= 0 {
		sec = 1
	}
	if sec > 0xFFFF {
		sec = 0xFFFF
	}
	return uint16(sec)
}

func (s *server) sendServerConfig(channelId uint32, senderId uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload, durationToSecondsClamped(s.talkMax))
	if s.multiTalk {
		payload[2] |= 0x01
	}
	limit := s.maxActiveTalkers
	if limit < 1 {
		limit = 1
	}
	if limit > 0xFF {
		limit = 0xFF
	}
	payload[3] = byte(limit)
	packet := buildControlPacket(pktServerCfg, channelId, 0, payload, s.noCrypto)
	s.sendTo(channelId, senderId, packet)
}

type talkerSyncState struct {
	talkerID    uint32
	codecConfig []byte
}

func (s *server) sendCurrentTalkState(channelId uint32, senderId uint32) {
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil {
		s.mu.Unlock()
		return
	}
	talkers := sortedActiveTalkers(ch)
	states := make([]talkerSyncState, 0, len(talkers))
	for _, talkerID := range talkers {
		states = append(states, talkerSyncState{
			talkerID:    talkerID,
			codecConfig: append([]byte(nil), ch.codecConfigs[talkerID]...),
		})
	}
	s.mu.Unlock()

	for _, state := range states {
		// Configure the per-talker decoder before announcing that audio may arrive.
		if len(state.codecConfig) >= 3 {
			s.sendTo(channelId, senderId,
				buildControlPacket(pktCodecConfig, channelId, state.talkerID, state.codecConfig, s.noCrypto))
		}
		log.Printf("join_sync_talker ch=%d to=%d talker=%d codec_config=%t", channelId, senderId, state.talkerID, len(state.codecConfig) >= 3)
		s.sendTo(channelId, senderId, buildTalkPacket(pktTalkGrant, channelId, state.talkerID, s.noCrypto))
	}
}

func (s *server) broadcast(channelId uint32, data []byte) {
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil {
		s.mu.Unlock()
		return
	}

	peers := make([]*peer, 0, len(ch.peers))
	for _, p := range ch.peers {
		peers = append(peers, p)
	}
	s.mu.Unlock()

	for _, p := range peers {
		s.conn.WriteToUDP(data, p.addr)
	}
}

func (s *server) broadcastExceptAddr(channelId uint32, excludeAddr *net.UDPAddr, data []byte) {
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil {
		s.mu.Unlock()
		return
	}

	excludeKey := peerMapKey(excludeAddr)
	peers := make([]*peer, 0, len(ch.peers))
	for key, p := range ch.peers {
		if excludeKey != "" && key == excludeKey {
			continue
		}
		peers = append(peers, p)
	}
	s.mu.Unlock()

	for _, p := range peers {
		s.conn.WriteToUDP(data, p.addr)
	}
}

func (s *server) sendTo(channelId uint32, senderId uint32, data []byte) {
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil {
		s.mu.Unlock()
		return
	}

	peers := make([]*peer, 0, len(ch.peers))
	for _, p := range ch.peers {
		if p.senderId == senderId {
			peers = append(peers, p)
		}
	}
	s.mu.Unlock()

	for _, p := range peers {
		s.conn.WriteToUDP(data, p.addr)
	}
}

func (s *server) cleanupLoop(timeout time.Duration) {
	ticker := time.NewTicker(timeout / 2)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()

		s.mu.Lock()
		for channelId, ch := range s.channels {
			releasedTalkers := make([]uint32, 0)
			for key, p := range ch.peers {
				if now.Sub(p.lastSeen) > timeout {
					delete(ch.peers, key)
					if _, ok := ch.activeTalkers[p.senderId]; ok {
						delete(ch.activeTalkers, p.senderId)
						releasedTalkers = append(releasedTalkers, p.senderId)
					}
				}
			}
			if s.talkMax > 0 {
				for senderID, startedAt := range ch.activeTalkers {
					if startedAt.IsZero() {
						ch.activeTalkers[senderID] = now
						continue
					}
					if now.Sub(startedAt) < s.talkMax {
						continue
					}
					delete(ch.activeTalkers, senderID)
					releasedTalkers = append(releasedTalkers, senderID)
				}
			}
			if len(ch.peers) == 0 {
				delete(s.channels, channelId)
			}
			if len(releasedTalkers) > 0 {
				sort.Slice(releasedTalkers, func(i, j int) bool { return releasedTalkers[i] < releasedTalkers[j] })
				s.mu.Unlock()
				for _, talker := range releasedTalkers {
					log.Printf("talk_release ch=%d talker=%d (cleanup)", channelId, talker)
					s.broadcast(channelId, buildTalkPacket(pktTalkRelease, channelId, talker, s.noCrypto))
				}
				s.mu.Lock()
			}
		}
		s.mu.Unlock()
	}
}

func (s *server) logPacket(pkt parsedPacket, addr *net.UDPAddr, size int) {
	if pkt.Header.Type == pktAudio && !s.logAudio {
		return
	}
	extra := ""
	if pkt.Header.Type == pktCodecConfig {
		if pcmOnly, codecId, mode, ok := parseCodecConfigPayload(pkt.Payload); ok {
			extra = fmt.Sprintf(" codec_id=%d(%s) mode=%d pcm_only=%t", codecId, codecName(codecId), mode, pcmOnly)
		} else {
			extra = fmt.Sprintf(" codec_config_payload_invalid len=%d", len(pkt.Payload))
		}
	}
	log.Printf("rx type=%s ch=%d sender=%d seq=%d hlen=%d key=%d nonce=%d from=%s size=%d%s",
		pktTypeName(pkt.Header.Type),
		pkt.Header.ChannelId,
		pkt.Header.SenderId,
		pkt.Header.Seq,
		pkt.Header.HeaderLen,
		pkt.Sec.KeyId,
		pkt.Sec.Nonce,
		addr.String(),
		size,
		extra)
}

func parseCodecConfigPayload(payload []byte) (pcmOnly bool, codecId uint8, mode uint16, ok bool) {
	if len(payload) < 3 {
		return false, 0, 0, false
	}

	flags := payload[0]
	pcmOnly = (flags & 0x01) != 0

	// Backward compatibility:
	// old: [flags][mode_hi][mode_lo]
	// new: [flags][codec_id][mode_hi][mode_lo]
	if len(payload) >= 4 {
		codecId = payload[1]
		mode = binary.BigEndian.Uint16(payload[2:4])
	} else {
		codecId = 1 // codec2
		mode = binary.BigEndian.Uint16(payload[1:3])
	}
	if pcmOnly {
		codecId = 0
	}
	return pcmOnly, codecId, mode, true
}

func codecName(codecId uint8) string {
	switch codecId {
	case 0:
		return "pcm"
	case 1:
		return "codec2"
	case 2:
		return "opus"
	default:
		return "unknown"
	}
}

func (s *server) observePacketSize(pkt parsedPacket, addr *net.UDPAddr, size int) {
	now := time.Now()
	if s.sizeWindowStart.IsZero() {
		s.sizeWindowStart = now
	}

	if size > s.sizeWindowMax {
		s.sizeWindowMax = size
		s.sizeWindowMaxType = pkt.Header.Type
		s.sizeWindowMaxCh = pkt.Header.ChannelId
		s.sizeWindowMaxSender = pkt.Header.SenderId
	}

	isRealtimeMedia := pkt.Header.Type == pktAudio || pkt.Header.Type == pktFec
	if isRealtimeMedia && size > udpWarnPayloadBytes {
		s.sizeWindowOverWarn++
		if now.Sub(s.lastWarnLog) >= 3*time.Second {
			log.Printf("udp_size_warn type=%s size=%dB ch=%d sender=%d from=%s threshold=%dB",
				pktTypeName(pkt.Header.Type),
				size,
				pkt.Header.ChannelId,
				pkt.Header.SenderId,
				addr.String(),
				udpWarnPayloadBytes)
			s.lastWarnLog = now
		}
	}

	if isRealtimeMedia && size > udpFragPayloadBytes {
		s.sizeWindowOverFrag++
		if now.Sub(s.lastFragLog) >= 3*time.Second {
			log.Printf("udp_fragment_risk type=%s size=%dB ch=%d sender=%d from=%s threshold=%dB",
				pktTypeName(pkt.Header.Type),
				size,
				pkt.Header.ChannelId,
				pkt.Header.SenderId,
				addr.String(),
				udpFragPayloadBytes)
			s.lastFragLog = now
		}
	}

	if now.Sub(s.sizeWindowStart) >= 30*time.Second {
		if s.sizeWindowMax > 0 {
			log.Printf("udp_size_stats window=30s max=%dB max_type=%s max_ch=%d max_sender=%d over_%dB=%d over_%dB=%d",
				s.sizeWindowMax,
				pktTypeName(s.sizeWindowMaxType),
				s.sizeWindowMaxCh,
				s.sizeWindowMaxSender,
				udpWarnPayloadBytes, s.sizeWindowOverWarn,
				udpFragPayloadBytes, s.sizeWindowOverFrag)
		}
		s.sizeWindowStart = now
		s.sizeWindowMax = 0
		s.sizeWindowMaxType = 0
		s.sizeWindowMaxCh = 0
		s.sizeWindowMaxSender = 0
		s.sizeWindowOverWarn = 0
		s.sizeWindowOverFrag = 0
	}
}

func pktTypeName(t uint8) string {
	switch t {
	case pktAudio:
		return "audio"
	case pktPttOn:
		return "ptt_on"
	case pktPttOff:
		return "ptt_off"
	case pktKeepalive:
		return "keepalive"
	case pktJoin:
		return "join"
	case pktLeave:
		return "leave"
	case pktTalkGrant:
		return "talk_grant"
	case pktTalkRelease:
		return "talk_release"
	case pktTalkDeny:
		return "talk_deny"
	case pktKeyExchange:
		return "key_exchange"
	case pktCodecConfig:
		return "codec_config"
	case pktFec:
		return "fec"
	case pktServerCfg:
		return "server_config"
	default:
		return "unknown"
	}
}

func parsePacket(data []byte, noCrypto bool) (parsedPacket, bool) {
	if len(data) < fixedHeaderSize {
		return parsedPacket{}, false
	}

	header := packetHeader{}
	header.Version = data[0]
	header.Type = data[1]
	header.HeaderLen = binary.BigEndian.Uint16(data[2:4])
	header.ChannelId = binary.BigEndian.Uint32(data[4:8])
	header.SenderId = binary.BigEndian.Uint32(data[8:12])
	header.Seq = binary.BigEndian.Uint16(data[12:14])
	header.Flags = binary.BigEndian.Uint16(data[14:16])

	if len(data) >= fixedHeaderSize+securityHeaderSize+authTagSize &&
		header.HeaderLen >= fixedHeaderSize+securityHeaderSize {
		sec := securityHeader{}
		sec.Nonce = binary.BigEndian.Uint64(data[16:24])
		sec.KeyId = binary.BigEndian.Uint32(data[24:28])

		payloadOffset := fixedHeaderSize + securityHeaderSize
		payloadLen := len(data) - payloadOffset - authTagSize
		if payloadLen < 0 {
			return parsedPacket{}, false
		}

		payload := make([]byte, payloadLen)
		copy(payload, data[payloadOffset:payloadOffset+payloadLen])

		tag := make([]byte, authTagSize)
		copy(tag, data[payloadOffset+payloadLen:])

		return parsedPacket{
			Header:  header,
			Sec:     sec,
			Payload: payload,
			Tag:     tag,
			Raw:     data,
		}, true
	}

	if !noCrypto {
		return parsedPacket{}, false
	}

	payloadOffset := fixedHeaderSize
	payloadLen := len(data) - payloadOffset
	if payloadLen < 0 {
		return parsedPacket{}, false
	}

	payload := make([]byte, payloadLen)
	copy(payload, data[payloadOffset:])

	return parsedPacket{
		Header:  header,
		Payload: payload,
		Tag:     nil,
		Raw:     data,
	}, true
}

func buildControlPacket(pktType uint8, channelId uint32, senderId uint32, payload []byte, noCrypto bool) []byte {
	header := make([]byte, fixedHeaderSize)
	header[0] = protocolVersion
	header[1] = pktType
	headerLen := fixedHeaderSize
	if !noCrypto {
		headerLen = fixedHeaderSize + securityHeaderSize
	}
	binary.BigEndian.PutUint16(header[2:4], uint16(headerLen))
	binary.BigEndian.PutUint32(header[4:8], channelId)
	binary.BigEndian.PutUint32(header[8:12], senderId)
	binary.BigEndian.PutUint16(header[12:14], 0)
	binary.BigEndian.PutUint16(header[14:16], 0)

	if noCrypto {
		packet := make([]byte, 0, len(header)+len(payload))
		packet = append(packet, header...)
		packet = append(packet, payload...)
		return packet
	}

	sec := make([]byte, securityHeaderSize)
	tag := make([]byte, authTagSize)

	packet := make([]byte, 0, len(header)+len(sec)+len(payload)+len(tag))
	packet = append(packet, header...)
	packet = append(packet, sec...)
	packet = append(packet, payload...)
	packet = append(packet, tag...)
	return packet
}

func buildTalkPacket(pktType uint8, channelId uint32, talkerId uint32, noCrypto bool) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, talkerId)
	return buildControlPacket(pktType, channelId, talkerId, payload, noCrypto)
}

func main() {
	port := flag.Int("port", 50000, "UDP listen port")
	timeout := flag.Duration("timeout", 30*time.Second, "peer timeout")
	talkMaxSecDefault := 0
	if raw := os.Getenv("INCOMUDON_TALK_MAX_SEC"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			talkMaxSecDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_TALK_MAX_SEC=%q (using 0)", raw)
		}
	}
	talkMaxSec := flag.Int("talk-max-sec", talkMaxSecDefault, "max TX hold time in seconds (0 disables timeout)")
	multiTalkDefault := false
	if raw := os.Getenv("INCOMUDON_MULTI_TALK"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			multiTalkDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_MULTI_TALK=%q (using false)", raw)
		}
	}
	maxActiveTalkersDefault := 2
	if raw := os.Getenv("INCOMUDON_MAX_ACTIVE_TALKERS"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			maxActiveTalkersDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_MAX_ACTIVE_TALKERS=%q (using 2)", raw)
		}
	}
	multiTalk := flag.Bool("multi-talk", multiTalkDefault, "allow multiple simultaneous talkers")
	maxActiveTalkers := flag.Int("max-active-talkers", maxActiveTalkersDefault, "maximum simultaneous active talkers when multi-talk is enabled")
	directoryEnabledDefault := false
	if raw := os.Getenv("INCOMUDON_DIRECTORY_ENABLED"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			directoryEnabledDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_DIRECTORY_ENABLED=%q (using false)", raw)
		}
	}
	directoryEnabled := flag.Bool("directory-enabled", directoryEnabledDefault, "enable PSK-protected directory publishing and pull requests")
	directoryChannelsCSV := flag.String("directory-channels-csv", os.Getenv("INCOMUDON_DIRECTORY_CHANNELS_CSV"), "CSV file containing channel_id,name for PSK directory publishing")
	directorySpeakersCSV := flag.String("directory-speakers-csv", os.Getenv("INCOMUDON_DIRECTORY_SPEAKERS_CSV"), "CSV file containing channel_id,sender_id,name for PSK directory publishing")
	directoryUDPTarget := flag.String("directory-udp-target", os.Getenv("INCOMUDON_DIRECTORY_UDP_TARGET"), "PWA UDP target for PSK directory snapshots")
	directoryUDPListenDefault := os.Getenv("INCOMUDON_DIRECTORY_UDP_LISTEN")
	if directoryUDPListenDefault == "" {
		directoryUDPListenDefault = ":51000"
	}
	directoryUDPListen := flag.String("directory-udp-listen", directoryUDPListenDefault, "UDP listen address for authenticated directory pull requests")
	directoryPSKFile := flag.String("directory-psk-file", os.Getenv("INCOMUDON_DIRECTORY_PSK_FILE"), "path to base64url directory PSK file")
	directoryKeyID := flag.String("directory-key-id", os.Getenv("INCOMUDON_DIRECTORY_KEY_ID"), "directory PSK recipient key ID (default pwa-1)")
	directoryRequestAllowCIDRs := flag.String("directory-request-allow-cidrs", os.Getenv("INCOMUDON_DIRECTORY_REQUEST_ALLOW_CIDRS"), "optional comma-separated source CIDRs allowed to request directory snapshots")
	directoryPublishInterval := flag.Duration("directory-publish-interval", directoryDurationFromEnv("INCOMUDON_DIRECTORY_PUBLISH_INTERVAL", directoryDefaultInterval), "directory snapshot publish interval")
	directoryTTL := flag.Duration("directory-ttl", directoryDurationFromEnv("INCOMUDON_DIRECTORY_TTL", directoryDefaultTTL), "directory snapshot validity")
	noCrypto := flag.Bool("no-crypto", false, "accept/send packets without security header/tag")
	logPackets := flag.Bool("log-packets", false, "log received packets")
	logAudio := flag.Bool("log-audio", false, "log audio packets too (requires -log-packets)")
	flag.Parse()

	if *talkMaxSec < 0 {
		*talkMaxSec = 0
	}
	if *maxActiveTalkers < 1 {
		*maxActiveTalkers = 1
	}
	talkMax := time.Duration(*talkMaxSec) * time.Second

	addr := &net.UDPAddr{Port: *port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	defer conn.Close()
	srv := newServer(conn, *noCrypto, *logPackets, *logAudio, talkMax, *multiTalk, *maxActiveTalkers)

	directoryPublisher, err := newDirectoryPublisher(directoryPublisherConfig{
		Enabled:           *directoryEnabled,
		ChannelsCSV:       *directoryChannelsCSV,
		SpeakersCSV:       *directorySpeakersCSV,
		Target:            *directoryUDPTarget,
		ListenAddress:     *directoryUDPListen,
		PSKFile:           *directoryPSKFile,
		KeyID:             *directoryKeyID,
		Interval:          *directoryPublishInterval,
		TTL:               *directoryTTL,
		RequestAllowCIDRs: *directoryRequestAllowCIDRs,
		Participants:      srv.directoryParticipants,
	})
	if err != nil {
		log.Fatalf("invalid directory publishing configuration: %v", err)
	}
	if directoryPublisher != nil {
		defer directoryPublisher.Close()
		log.Printf("PSK directory enabled: target=%s listen=%s interval=%s ttl=%s", *directoryUDPTarget, *directoryUDPListen, *directoryPublishInterval, *directoryTTL)
		if len(directoryPublisher.allowed) == 0 {
			log.Printf("PSK directory request source CIDR filtering is disabled; configure -directory-request-allow-cidrs to reduce unauthenticated UDP load")
		}
		go directoryPublisher.Run()
	}

	mode := "encrypted"
	if *noCrypto {
		mode = "no-crypto"
	}
	log.Printf("IncomUdon relay listening on udp :%d (%s, talk_max=%ds, multi_talk=%t, max_active_talkers=%d)", *port, mode, *talkMaxSec, *multiTalk, *maxActiveTalkers)

	if *logAudio {
		*logPackets = true
	}
	go srv.cleanupLoop(*timeout)
	srv.run()
}
