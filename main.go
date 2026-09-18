package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	protocolVersion                    = 1
	fixedHeaderSize                    = 16
	securityHeaderExtensionSize        = 12
	aesGCMV2MediaHeaderSize            = 20
	aesGCMV2HeaderSize                 = fixedHeaderSize + aesGCMV2MediaHeaderSize
	authTagSize                        = 16
	packetFlagAESGCMV2HeaderAAD uint16 = 1 << 0
	packetFlagControlAuthV1     uint16 = 1 << 1
	maxUDPDatagramBytes                = 1200
	maxActiveTalkersV1                 = 16
	udpNearLimitBytes                  = 1150
	defaultMembershipLease             = 30 * time.Second
	defaultKeepaliveInterval           = 10 * time.Second
	minimumMembershipLease             = 15 * time.Second
	maximumMembershipLease             = 300 * time.Second
	minimumKeepaliveInterval           = time.Second
)

const (
	pktAudio             = 0x01
	pktPttOn             = 0x02
	pktPttOff            = 0x03
	pktKeepalive         = 0x04
	pktJoin              = 0x05
	pktLeave             = 0x06
	pktTalkGrant         = 0x07
	pktTalkRelease       = 0x08
	pktTalkDeny          = 0x09
	pktKeyExchange       = 0x0A
	pktCodecConfig       = 0x0B
	pktFec               = 0x0C
	pktServerCfg         = 0x0D
	pktPing              = 0x0E
	pktPong              = 0x0F
	pktAuthHello         = 0x10
	pktAuthChallenge     = 0x11
	pktIdentityBegin     = 0x12
	pktIdentityChallenge = 0x13
	pktIdentityProof     = 0x14
	pktIdentityDeny      = 0x15
	pktServiceBegin      = 0x16
	pktServiceChallenge  = 0x17
	pktServiceProof      = 0x18
	pktServiceDeny       = 0x19
	pktPttRequest        = 0x1A
)

const (
	talkReleaseClientPttOff      = 0x00
	talkReleaseServerTimeout     = 0x01
	talkReleaseMembershipTimeout = 0x02
	talkReleaseClientLeave       = 0x03
	talkReleaseServerPolicy      = 0x04
	talkReleaseIdentityExpired   = 0x05
	talkReleaseServiceRevoked    = 0x06
	talkReleasePreempted         = 0x07
	talkReleaseServiceExpired    = 0x08
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
	ControlNonce   uint64
	MediaNonceBase [12]byte
	MediaCounter   uint32
	KeyID          uint32
}

type parsedPacket struct {
	Header  packetHeader
	Sec     securityHeader
	Payload []byte
	Tag     []byte
	Raw     []byte
}

type peer struct {
	senderId           uint32
	addr               *net.UDPAddr
	lastSeen           time.Time
	authenticated      bool
	controlSessionID   uint32
	controlKeyID       uint32
	controlHighest     uint32
	controlSeenWindow  uint64
	identityAdmission  *identityAdmission
	serviceAdmission   *serviceAdmission
	membershipLease    time.Duration
	keepaliveInterval  time.Duration
	membershipDeadline time.Time
}

type codecConfigState struct {
	payload        []byte
	mediaNonceBase [12]byte
	mediaKeyID     uint32
	controlKeyID   uint32
}

type channel struct {
	peers             map[string]*peer
	activeTalkers     map[uint32]time.Time
	codecConfigs      map[uint32][]byte
	mediaCodecConfigs map[uint32]codecConfigState
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
	lastWarnLog         time.Time
	talkMax             time.Duration
	multiTalk           bool
	maxActiveTalkers    int
	controlAuth         *controlAuthState
	identityAdmission   *identityAdmissionState
	serviceAdmission    *serviceAdmissionState
	directory           *directoryV3
	management          *managementPlane
	floorInterrupt      bool
	membershipLease     time.Duration
	keepaliveInterval   time.Duration
	outboundMu          sync.Mutex
	outboundSeq         uint16
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
	if maxActiveTalkers > maxActiveTalkersV1 {
		maxActiveTalkers = maxActiveTalkersV1
	}
	server := &server{
		channels:          make(map[uint32]*channel),
		conn:              conn,
		noCrypto:          noCrypto,
		logPackets:        logPackets,
		logAudio:          logAudio,
		sizeWindowStart:   time.Now(),
		talkMax:           talkMax,
		multiTalk:         multiTalk,
		maxActiveTalkers:  maxActiveTalkers,
		membershipLease:   defaultMembershipLease,
		keepaliveInterval: defaultKeepaliveInterval,
	}
	// Retain redacted audit data even when the optional HTTPS Management Plane
	// listener is disabled. Enabling the listener later promotes this sink.
	server.management = newManagementAuditSink(server)
	return server
}

func (s *server) configureControlAuth(state *controlAuthState) {
	s.controlAuth = state
}

func (s *server) configureIdentityAdmission(state *identityAdmissionState, floorInterrupt bool) {
	s.identityAdmission = state
	s.floorInterrupt = floorInterrupt
}

func (s *server) configureServiceAdmission(state *serviceAdmissionState) {
	s.serviceAdmission = state
}

func (s *server) configureDirectory(directory *directoryV3) {
	s.directory = directory
}

func validMembershipTiming(lease time.Duration, keepalive time.Duration) bool {
	if lease < minimumMembershipLease || lease > maximumMembershipLease ||
		lease%time.Second != 0 || keepalive < minimumKeepaliveInterval ||
		keepalive%time.Second != 0 {
		return false
	}
	return keepalive <= lease/3
}

func (s *server) configureMembershipTiming(lease time.Duration, keepalive time.Duration) error {
	if !validMembershipTiming(lease, keepalive) {
		return fmt.Errorf("invalid membership timing lease=%s keepalive=%s", lease, keepalive)
	}
	s.mu.Lock()
	s.membershipLease = lease
	s.keepaliveInterval = keepalive
	s.mu.Unlock()
	return nil
}

func (s *server) nextRelaySequence() uint16 {
	s.outboundMu.Lock()
	defer s.outboundMu.Unlock()
	sequence := s.outboundSeq
	s.outboundSeq++
	return sequence
}

func (s *server) directoryParticipants(channelID uint32) []directoryParticipantRow {
	if s == nil {
		return nil
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[channelID]
	if ch == nil {
		return nil
	}
	participants := make([]directoryParticipantRow, 0, len(ch.peers))
	for _, peer := range ch.peers {
		if peer == nil || peer.senderId == 0 || (!peer.membershipDeadline.IsZero() && !peer.membershipDeadline.After(now)) {
			continue
		}
		lastSeen := peer.lastSeen.Unix()
		if lastSeen < 1 {
			continue
		}
		_, talking := ch.activeTalkers[peer.senderId]
		participants = append(participants, directoryParticipantRow{
			ChannelID: channelID, SenderID: peer.senderId, LastSeenAt: uint64(lastSeen), Talking: talking,
		})
	}
	sort.Slice(participants, func(i, j int) bool { return participants[i].SenderID < participants[j].SenderID })
	return participants
}

func (s *server) run() {
	// A Version 1 Relay never parses or forwards an over-limit datagram.
	// Reading one extra byte also detects datagrams truncated by the socket read.
	buf := make([]byte, maxUDPDatagramBytes+1)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("read error: %v", err)
			continue
		}

		data := make([]byte, n)
		copy(data, buf[:n])
		if !acceptsUDPDatagramSize(n) {
			if s.logPackets {
				log.Printf("udp_datagram_drop reason=oversize size=%d max=%d from=%s", n, maxUDPDatagramBytes, addr)
			}
			continue
		}
		if len(data) >= len(directoryCarrierMagic) && bytes.Equal(data[:len(directoryCarrierMagic)], directoryCarrierMagic) {
			if s.directory != nil && s.directory.transport == directoryTransportMediaPort &&
				len(data) >= len(directoryCarrierMagic)+1 && data[len(directoryCarrierMagic)] == directoryCarrierVersion {
				s.directory.enqueue(data[len(directoryCarrierMagic)+1:], addr, directoryTransportMedia)
			}
			// A Directory carrier is never interpreted as binary media/control.
			// Disabled and dedicated-UDP configurations discard it without reply.
			continue
		}

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

func acceptsUDPDatagramSize(size int) bool {
	return size >= 0 && size <= maxUDPDatagramBytes
}

func (s *server) handlePacket(pkt parsedPacket, addr *net.UDPAddr) {
	if pkt.Header.Version != protocolVersion || pkt.Header.SenderId == 0 {
		return
	}
	s.emitMembershipExpirations(pkt.Header.ChannelId)
	if pkt.Header.Type == pktAudio || pkt.Header.Type == pktFec {
		s.handleMediaPacket(pkt, addr)
		return
	}

	requiresAuth := s.controlAuthRequired(pkt.Header.ChannelId)
	if pkt.Header.Type == pktAuthHello {
		if !requiresAuth {
			return
		}
		meta, ok := s.verifyIncomingControl(pkt)
		if !ok || len(pkt.Payload) != 0 {
			return
		}
		challenge, err := s.controlAuth.createChallenge(pkt, addr, meta)
		if err != nil {
			return
		}
		s.sendAuthenticatedChallenge(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, challenge)
		return
	}
	// PING is an endpoint-liveness probe, not a channel message. It must not
	// create or rebind a peer entry, including on compatibility channels.
	if pkt.Header.Type == pktPing {
		if requiresAuth {
			meta, ok := s.verifyIncomingControl(pkt)
			if !ok || !s.acceptAuthenticatedPeerControl(pkt, addr, meta) {
				return
			}
		}
		if len(pkt.Payload) != 8 || !s.touchKnownPeer(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
			return
		}
		s.sendPong(addr, pkt.Header.ChannelId, pkt.Header.SenderId, pkt.Payload)
		return
	}
	if (pkt.Header.Type == pktIdentityBegin || pkt.Header.Type == pktIdentityProof) && s.identityAdmission != nil {
		if !requiresAuth {
			return
		}
		meta, ok := s.verifyIncomingControl(pkt)
		if !ok {
			return
		}
		existingPeer := s.isAuthenticatedPeer(pkt.Header.ChannelId, pkt.Header.SenderId, addr)
		if existingPeer {
			if !s.acceptAuthenticatedPeerControl(pkt, addr, meta) {
				return
			}
		} else if !s.controlAuth.acceptPreJoinControl(pkt, addr, meta) {
			return
		}
		now := time.Now()
		switch pkt.Header.Type {
		case pktIdentityBegin:
			challenge, denyReason := s.identityAdmission.begin(pkt, addr, meta, now)
			if denyReason != 0 {
				s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, pktIdentityDeny, []byte{denyReason})
				return
			}
			s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, pktIdentityChallenge, challenge)
		case pktIdentityProof:
			if denyReason := s.identityAdmission.proof(pkt, addr, meta, now); denyReason != 0 {
				s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, pktIdentityDeny, []byte{denyReason})
			} else if existingPeer {
				admission, found := s.identityAdmission.takeVerifiedAdmission(pkt, addr, meta, now)
				if !found || !s.setPeerIdentityAdmission(pkt.Header.ChannelId, pkt.Header.SenderId, addr, admission) {
					s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, pktIdentityDeny, []byte{identityDenyInvalidProof})
				}
			}
		}
		return
	}
	if (pkt.Header.Type == pktServiceBegin || pkt.Header.Type == pktServiceProof) && s.serviceAdmission != nil {
		if !requiresAuth {
			return
		}
		meta, ok := s.verifyIncomingControl(pkt)
		if !ok {
			return
		}
		existingPeer := s.isAuthenticatedPeer(pkt.Header.ChannelId, pkt.Header.SenderId, addr)
		if existingPeer {
			if !s.acceptAuthenticatedPeerControl(pkt, addr, meta) {
				return
			}
		} else if !s.controlAuth.acceptPreJoinControl(pkt, addr, meta) {
			return
		}
		now := time.Now()
		switch pkt.Header.Type {
		case pktServiceBegin:
			challenge, denyReason := s.serviceAdmission.begin(pkt, addr, meta, now)
			if denyReason != 0 {
				s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, pktServiceDeny, []byte{denyReason})
				return
			}
			s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, pktServiceChallenge, challenge)
		case pktServiceProof:
			if denyReason := s.serviceAdmission.proof(pkt, addr, meta, now); denyReason != 0 {
				s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, pktServiceDeny, []byte{denyReason})
			} else if existingPeer {
				if s.peerHasIdentityAdmission(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
					// Consume the completed proof so it cannot be reused after this
					// endpoint's existing identity-authorized membership ends.
					_, _ = s.serviceAdmission.takeVerifiedAdmission(pkt, addr, meta, now)
					s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, pktServiceDeny, []byte{serviceDenyScopeMismatch})
					return
				}
				admission, found := s.serviceAdmission.takeVerifiedAdmission(pkt, addr, meta, now)
				if !found || !s.setPeerServiceAdmission(pkt.Header.ChannelId, pkt.Header.SenderId, addr, admission) {
					s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, pktServiceDeny, []byte{serviceDenyInvalidProof})
				}
			}
		}
		return
	}

	if pkt.Header.Type == pktJoin && requiresAuth {
		meta, ok := s.verifyIncomingControl(pkt)
		replay, ok := s.controlAuth.consumeJoinChallenge(pkt, addr, meta)
		if !ok {
			return
		}
		identity, service, admitted, denyPacketType, denyReason := s.resolveJoinAdmission(pkt, addr, meta, time.Now())
		if !admitted {
			s.sendAuthenticatedControl(addr, pkt.Header.ChannelId, pkt.Header.SenderId, meta.keyID, denyPacketType, []byte{denyReason})
			return
		}
		s.upsertAuthenticatedPeerWithReplay(pkt.Header.ChannelId, pkt.Header.SenderId, addr, meta, replay)
		if !identity.expiresAt.IsZero() && !s.setPeerIdentityAdmission(pkt.Header.ChannelId, pkt.Header.SenderId, addr, identity) {
			return
		}
		if !service.grantExpires.IsZero() && !s.setPeerServiceAdmission(pkt.Header.ChannelId, pkt.Header.SenderId, addr, service) {
			return
		}
		if !s.startMembership(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
			return
		}
	} else if pkt.Header.Type == pktJoin {
		if len(pkt.Payload) != 0 {
			return
		}
		s.mu.Lock()
		ch := s.getOrCreateChannel(pkt.Header.ChannelId)
		s.upsertPeer(ch, pkt.Header.SenderId, addr)
		s.mu.Unlock()
		if !s.startMembership(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
			return
		}
	} else if requiresAuth {
		meta, ok := s.verifyIncomingControl(pkt)
		if !ok || !s.acceptAuthenticatedPeerControl(pkt, addr, meta) {
			return
		}
	} else {
		if !s.acceptUnauthenticatedPeerControl(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
			return
		}
	}

	if releasedTalkerIDs := s.expireTalkIfNeeded(pkt.Header.ChannelId); len(releasedTalkerIDs) > 0 {
		for _, releasedTalkerID := range releasedTalkerIDs {
			log.Printf("talk_timeout ch=%d talker=%d max=%s",
				pkt.Header.ChannelId,
				releasedTalkerID,
				s.talkMax)
			s.broadcastRelayControl(pkt.Header.ChannelId, pktTalkRelease, releasedTalkerID, talkReleasePayload(releasedTalkerID, talkReleaseServerTimeout))
			s.publishManagementEvent("talk_ended", uint32Pointer(pkt.Header.ChannelId), uint32Pointer(releasedTalkerID), nil, nil, nil, stringPointer("SERVER_TALK_TIMEOUT"))
		}
	}

	switch pkt.Header.Type {
	case pktJoin:
		log.Printf("join ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
		s.publishManagementEvent("participant_joined", uint32Pointer(pkt.Header.ChannelId), uint32Pointer(pkt.Header.SenderId), nil, nil, nil, nil)
		s.sendServerConfig(pkt.Header.ChannelId, pkt.Header.SenderId)
		s.sendCurrentTalkState(pkt.Header.ChannelId, pkt.Header.SenderId)
	case pktLeave:
		if len(pkt.Payload) != 0 {
			return
		}
		log.Printf("leave ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
		s.releaseTalkIfNeeded(pkt.Header.ChannelId, pkt.Header.SenderId, talkReleaseClientLeave)
		s.removePeer(pkt.Header.ChannelId, pkt.Header.SenderId, addr)
		s.publishManagementEvent("participant_left", uint32Pointer(pkt.Header.ChannelId), uint32Pointer(pkt.Header.SenderId), nil, nil, nil, stringPointer("CLIENT_LEAVE"))
	case pktKeepalive:
		if len(pkt.Payload) != 0 {
			return
		}
		s.refreshMembership(pkt.Header.ChannelId, pkt.Header.SenderId, addr)
	case pktPttOn:
		if len(pkt.Payload) != 0 {
			return
		}
		if !s.peerAllowsTalk(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
			return
		}
		log.Printf("ptt_on ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
		s.refreshMembership(pkt.Header.ChannelId, pkt.Header.SenderId, addr)
		s.handlePttOn(pkt.Header.ChannelId, pkt.Header.SenderId)
	case pktPttRequest:
		if len(pkt.Payload) != 1 || pkt.Payload[0] != 0x01 || !s.handlePttRequest(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
			return
		}
		s.refreshMembership(pkt.Header.ChannelId, pkt.Header.SenderId, addr)
	case pktPttOff:
		if len(pkt.Payload) != 0 {
			return
		}
		log.Printf("ptt_off ch=%d sender=%d from=%s", pkt.Header.ChannelId, pkt.Header.SenderId, addr.String())
		s.refreshMembership(pkt.Header.ChannelId, pkt.Header.SenderId, addr)
		s.handlePttOff(pkt.Header.ChannelId, pkt.Header.SenderId)
	case pktCodecConfig:
		controlKeyID := uint32(0)
		if requiresAuth {
			controlKeyID = pkt.Sec.KeyID
		}
		config, ok := s.cacheCodecConfig(pkt.Header.ChannelId, pkt.Header.SenderId, pkt.Payload, controlKeyID, requiresAuth)
		if !ok {
			return
		}
		s.refreshMembership(pkt.Header.ChannelId, pkt.Header.SenderId, addr)
		s.sendRelayCodecConfig(pkt.Header.ChannelId, pkt.Header.SenderId, config)
	default:
		// Unknown or extension-owned packet types are not accepted as ordinary
		// membership activity. Their extension handler must opt in explicitly.
	}
}

func (s *server) handleMediaPacket(pkt parsedPacket, addr *net.UDPAddr) {
	if !s.isActiveTalkerEndpoint(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
		return
	}
	if !s.peerAllowsTalk(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
		return
	}
	if pkt.Header.Flags&packetFlagAESGCMV2HeaderAAD != 0 &&
		!s.controlAuthRequired(pkt.Header.ChannelId) {
		// AES-GCM v2 always requires Control Authentication v1. Optional and
		// off policy modes may still serve no-crypto and legacy-xor channels.
		return
	}
	if s.controlAuthRequired(pkt.Header.ChannelId) {
		if !s.isAuthenticatedPeer(pkt.Header.ChannelId, pkt.Header.SenderId, addr) || !s.mediaMatchesCodecConfig(pkt) {
			return
		}
	}
	if !s.refreshMembership(pkt.Header.ChannelId, pkt.Header.SenderId, addr) {
		return
	}
	// The Relay intentionally forwards authenticated media byte-for-byte. The
	// receiver owns final AEAD authentication and replay-window enforcement.
	s.broadcastExceptAddr(pkt.Header.ChannelId, addr, pkt.Raw)
}

func (s *server) getOrCreateChannel(channelId uint32) *channel {
	ch, ok := s.channels[channelId]
	if !ok {
		ch = &channel{
			peers:             make(map[string]*peer),
			activeTalkers:     make(map[uint32]time.Time),
			codecConfigs:      make(map[uint32][]byte),
			mediaCodecConfigs: make(map[uint32]codecConfigState),
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

func (s *server) cacheCodecConfig(channelId uint32, senderId uint32, payload []byte, controlKeyID uint32, authenticated bool) (codecConfigState, bool) {
	if len(payload) != 19 {
		return codecConfigState{}, false
	}
	var zeroBase [12]byte
	var announcedBase [12]byte
	copy(announcedBase[:], payload[7:19])
	hasAESGCMV2Base := announcedBase != zeroBase
	if hasAESGCMV2Base {
		// AES-GCM v2 always needs authenticated control and a configured
		// Control Authentication channel, even outside required policy.
		if !authenticated || controlKeyID == 0 || !s.controlAuthRequired(channelId) {
			return codecConfigState{}, false
		}
	} else if s.controlAuthRequired(channelId) {
		// The required policy is the AES-GCM-v2-only profile. A zero base is
		// the no-crypto/legacy-xor compatibility form and is not selectable.
		return codecConfigState{}, false
	}

	state := codecConfigState{
		payload:        append([]byte(nil), payload...),
		mediaNonceBase: announcedBase,
		mediaKeyID:     2,
		controlKeyID:   controlKeyID,
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ch := s.channels[channelId]
	if ch == nil {
		return codecConfigState{}, false
	}
	if ch.codecConfigs == nil {
		ch.codecConfigs = make(map[uint32][]byte)
	}
	ch.codecConfigs[senderId] = append(ch.codecConfigs[senderId][:0], payload...)
	if ch.mediaCodecConfigs == nil {
		ch.mediaCodecConfigs = make(map[uint32]codecConfigState)
	}
	if hasAESGCMV2Base {
		ch.mediaCodecConfigs[senderId] = state
	} else {
		delete(ch.mediaCodecConfigs, senderId)
	}
	return state, true
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

// touchKnownPeer refreshes a peer only when both its sender ID and source UDP
// endpoint match a prior JOIN-derived registration.  Unlike normal packets,
// a PING must never create or rebind a peer entry.
func (s *server) touchKnownPeer(channelId uint32, senderId uint32, addr *net.UDPAddr) bool {
	if senderId == 0 || addr == nil {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	ch := s.channels[channelId]
	if ch == nil {
		return false
	}

	peerKey := peerMapKey(addr)
	p := ch.peers[peerKey]
	if p == nil {
		// The primary key is the address string.  The fallback keeps this check
		// robust for in-process users and tests that construct peer maps directly.
		for _, candidate := range ch.peers {
			if candidate == nil || candidate.addr == nil {
				continue
			}
			if candidate.addr.Port == addr.Port && candidate.addr.Zone == addr.Zone && candidate.addr.IP.Equal(addr.IP) {
				p = candidate
				break
			}
		}
	}
	if p == nil || p.senderId != senderId {
		return false
	}

	p.lastSeen = time.Now()
	return true
}

func (s *server) acceptUnauthenticatedPeerControl(channelId uint32, senderId uint32, addr *net.UDPAddr) bool {
	if senderId == 0 || addr == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[channelId]
	if ch == nil {
		return false
	}
	peer := ch.peers[peerMapKey(addr)]
	if peer == nil || peer.senderId != senderId {
		return false
	}
	peer.lastSeen = time.Now()
	return true
}

func (s *server) startMembership(channelId uint32, senderId uint32, addr *net.UDPAddr) bool {
	if senderId == 0 || addr == nil {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[channelId]
	if ch == nil {
		return false
	}
	peer := ch.peers[peerMapKey(addr)]
	if peer == nil || peer.senderId != senderId {
		return false
	}
	peer.membershipLease = s.membershipLease
	peer.keepaliveInterval = s.keepaliveInterval
	peer.membershipDeadline = now.Add(peer.membershipLease)
	peer.lastSeen = now
	return true
}

func (s *server) refreshMembership(channelId uint32, senderId uint32, addr *net.UDPAddr) bool {
	if senderId == 0 || addr == nil {
		return false
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[channelId]
	if ch == nil {
		return false
	}
	peer := ch.peers[peerMapKey(addr)]
	if peer == nil || peer.senderId != senderId || peer.membershipDeadline.IsZero() || !peer.membershipDeadline.After(now) {
		return false
	}
	peer.membershipDeadline = now.Add(peer.membershipLease)
	peer.lastSeen = now
	return true
}

func (s *server) membershipTimingForPeer(channelId uint32, senderId uint32) (time.Duration, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch := s.channels[channelId]; ch != nil {
		for _, peer := range ch.peers {
			if peer.senderId == senderId && peer.membershipLease > 0 && peer.keepaliveInterval > 0 {
				return peer.membershipLease, peer.keepaliveInterval
			}
		}
	}
	return s.membershipLease, s.keepaliveInterval
}

func (s *server) isActiveTalkerEndpoint(channelId uint32, senderId uint32, addr *net.UDPAddr) bool {
	if senderId == 0 || addr == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[channelId]
	if ch == nil {
		return false
	}
	peer := ch.peers[peerMapKey(addr)]
	if peer == nil || peer.senderId != senderId {
		return false
	}
	_, active := ch.activeTalkers[senderId]
	return active
}

func (s *server) sendPong(addr *net.UDPAddr, channelId uint32, senderId uint32, nonce []byte) {
	if addr == nil || len(nonce) != 8 {
		return
	}
	if !s.controlAuthRequired(channelId) {
		packet := buildRelayControlPacket(pktPong, channelId, senderId, nonce, s.noCrypto, s.nextRelaySequence())
		_, _ = s.conn.WriteToUDP(packet, addr)
		return
	}

	s.mu.Lock()
	ch := s.channels[channelId]
	var target *peer
	if ch != nil {
		target = ch.peers[peerMapKey(addr)]
	}
	s.mu.Unlock()
	if packet := s.relayControlForPeer(channelId, target, pktPong, senderId, nonce); len(packet) > 0 {
		_, _ = s.conn.WriteToUDP(packet, addr)
	}
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
				removed = true
				break
			}
		}
	}
	if removed && senderId != 0 {
		// A later endpoint that receives the same sender ID must publish a fresh
		// configuration before its media can be accepted or replayed downstream.
		delete(ch.codecConfigs, senderId)
		delete(ch.mediaCodecConfigs, senderId)
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

// resolveJoinAdmission consumes any completed admission flow for this endpoint
// and enforces the required-mode rule that exactly one current identity or
// service admission authorizes a managed endpoint.
func (s *server) resolveJoinAdmission(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta, now time.Time) (identityAdmission, serviceAdmission, bool, uint8, uint8) {
	identity, identityAllowed, identityReason := s.identityAdmission.admissionForJoin(pkt, addr, meta, now)
	service, serviceAllowed, serviceReason := s.serviceAdmission.admissionForJoin(pkt, addr, meta, now)
	if !serviceAllowed {
		return identityAdmission{}, serviceAdmission{}, false, pktServiceDeny, serviceReason
	}
	serviceCurrent := !service.grantExpires.IsZero()
	if !identityAllowed && !(identityReason == identityDenyAdmissionRequired && serviceCurrent) {
		return identityAdmission{}, serviceAdmission{}, false, pktIdentityDeny, identityReason
	}
	identityCurrent := !identity.expiresAt.IsZero()
	if identityCurrent && serviceCurrent {
		// A peer must use one admission path per membership. This avoids an
		// ambiguous authority/expiry domain when both flows complete pre-JOIN.
		return identityAdmission{}, serviceAdmission{}, false, pktIdentityDeny, identityDenyScopeMismatch
	}
	if s.identityAdmission != nil && s.identityAdmission.isRequired() && !identityCurrent && !serviceCurrent {
		return identityAdmission{}, serviceAdmission{}, false, pktIdentityDeny, identityDenyAdmissionRequired
	}
	return identity, service, true, 0, 0
}

func (s *server) peerAllowsTalk(channelId uint32, senderId uint32, addr *net.UDPAddr) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[channelId]
	if ch == nil || addr == nil {
		return false
	}
	peer := ch.peers[peerMapKey(addr)]
	if peer == nil || peer.senderId != senderId {
		return false
	}
	required := s.identityAdmission != nil && s.identityAdmission.isRequired()
	if peer.identityAdmission != nil {
		return admissionAllowsTalk(peer.identityAdmission, now, required)
	}
	if peer.serviceAdmission != nil {
		return peer.serviceAdmission.membershipCurrent(now) && peer.serviceAdmission.permissions&identityPermissionTalk != 0
	}
	return !required
}

func (s *server) peerHasIdentityAdmission(channelID uint32, senderID uint32, addr *net.UDPAddr) bool {
	if addr == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := s.channels[channelID]
	if ch == nil {
		return false
	}
	peer := ch.peers[peerMapKey(addr)]
	return peer != nil && peer.senderId == senderID && peer.identityAdmission != nil
}

func activeTalkerPriority(ch *channel, senderId uint32, now time.Time) uint8 {
	if ch == nil {
		return 0
	}
	for _, peer := range ch.peers {
		if peer == nil || peer.senderId != senderId {
			continue
		}
		if peer.identityAdmission != nil && peer.identityAdmission.expiresAt.After(now) {
			return peer.identityAdmission.priority
		}
		if peer.serviceAdmission != nil && peer.serviceAdmission.membershipCurrent(now) {
			return peer.serviceAdmission.priority
		}
	}
	return 0
}

func peerAllowsInterrupt(peer *peer, now time.Time) bool {
	if peer == nil {
		return false
	}
	if peer.identityAdmission != nil {
		return admissionAllowsInterrupt(peer.identityAdmission, now)
	}
	if peer.serviceAdmission != nil {
		return peer.serviceAdmission.membershipCurrent(now) &&
			peer.serviceAdmission.permissions&identityPermissionTalk != 0 &&
			peer.serviceAdmission.permissions&identityPermissionInterrupt != 0 && peer.serviceAdmission.priority != 0
	}
	return false
}

func peerInterruptPriority(peer *peer, now time.Time) uint8 {
	if !peerAllowsInterrupt(peer, now) {
		return 0
	}
	if peer.identityAdmission != nil {
		return peer.identityAdmission.priority
	}
	return peer.serviceAdmission.priority
}

func peerAdmissionPriority(peer *peer, now time.Time) uint8 {
	if peer == nil {
		return 0
	}
	if peer.identityAdmission != nil && peer.identityAdmission.expiresAt.After(now) {
		return peer.identityAdmission.priority
	}
	if peer.serviceAdmission != nil && peer.serviceAdmission.membershipCurrent(now) {
		return peer.serviceAdmission.priority
	}
	return 0
}

// denyPttRequest deliberately uses the ordinary TALK_DENY shape without
// exposing whether policy, authorization, or current floor state caused it.
func (s *server) denyPttRequest(channelId uint32, senderId uint32) {
	s.mu.Lock()
	ch := s.channels[channelId]
	current := firstActiveTalker(ch)
	s.mu.Unlock()
	s.sendRelayControlTo(channelId, senderId, pktTalkDeny, current, talkPayload(current))
}

// handlePttRequest applies the Floor Interrupt selection algorithm. Its return
// value means that the authenticated request was authorized and therefore may
// refresh the requester's membership even when the floor decision is a deny.
func (s *server) handlePttRequest(channelId uint32, senderId uint32, addr *net.UDPAddr) bool {
	if !s.floorInterrupt || s.identityAdmission == nil || !s.identityAdmission.isRequired() || !s.controlAuthRequired(channelId) {
		s.denyPttRequest(channelId, senderId)
		return false
	}
	now := time.Now()
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil || addr == nil {
		s.mu.Unlock()
		s.denyPttRequest(channelId, senderId)
		return false
	}
	requester := ch.peers[peerMapKey(addr)]
	if requester == nil || requester.senderId != senderId || requester.membershipDeadline.IsZero() || !requester.membershipDeadline.After(now) ||
		!peerAllowsInterrupt(requester, now) {
		priority := peerAdmissionPriority(requester, now)
		s.mu.Unlock()
		s.auditFloorInterrupt(channelId, requester, priority, "denied", nil, nil)
		s.denyPttRequest(channelId, senderId)
		return false
	}
	if _, active := ch.activeTalkers[senderId]; active {
		priority := peerInterruptPriority(requester, now)
		s.mu.Unlock()
		s.auditFloorInterrupt(channelId, requester, priority, "success", nil, nil)
		s.sendRelayControlTo(channelId, senderId, pktTalkGrant, senderId, talkPayload(senderId))
		return true
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
		priority := peerInterruptPriority(requester, now)
		s.mu.Unlock()
		s.auditFloorInterrupt(channelId, requester, priority, "success", nil, nil)
		s.broadcastRelayControl(channelId, pktTalkGrant, senderId, talkPayload(senderId))
		s.publishManagementEvent("talk_started", uint32Pointer(channelId), uint32Pointer(senderId), nil, nil, nil, nil)
		return true
	}

	var victim uint32
	victimPriority := uint8(0xff)
	for activeSenderID := range ch.activeTalkers {
		priority := activeTalkerPriority(ch, activeSenderID, now)
		if victim == 0 || priority < victimPriority || (priority == victimPriority && activeSenderID < victim) {
			victim = activeSenderID
			victimPriority = priority
		}
	}
	requesterPriority := peerInterruptPriority(requester, now)
	if victim == 0 || requesterPriority <= victimPriority {
		current := firstActiveTalker(ch)
		s.mu.Unlock()
		s.auditFloorInterrupt(channelId, requester, requesterPriority, "denied", nil, nil)
		s.sendRelayControlTo(channelId, senderId, pktTalkDeny, current, talkPayload(current))
		return true
	}
	delete(ch.activeTalkers, victim)
	ch.activeTalkers[senderId] = now
	s.mu.Unlock()

	// Release is sent first to minimize the time a replacement overlaps queued
	// old media. Receivers still must tolerate UDP reordering.
	s.broadcastRelayControl(channelId, pktTalkRelease, victim, talkReleasePayload(victim, talkReleasePreempted))
	s.broadcastRelayControl(channelId, pktTalkGrant, senderId, talkPayload(senderId))
	s.auditFloorInterrupt(channelId, requester, requesterPriority, "success", uint32Pointer(victim), uint8Pointer(victimPriority))
	s.publishManagementEvent("talk_ended", uint32Pointer(channelId), uint32Pointer(victim), nil, nil, nil, stringPointer("PREEMPTED"))
	s.publishManagementEvent("talk_started", uint32Pointer(channelId), uint32Pointer(senderId), nil, nil, nil, nil)
	return true
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
		s.mu.Unlock()
		log.Printf("talk_grant ch=%d talker=%d (already granted)", channelId, senderId)
		// A duplicated PTT_ON should only repair a lost grant for its sender.
		// Broadcasting it resets remote receivers' per-talker playout state.
		s.sendRelayControlTo(channelId, senderId, pktTalkGrant, senderId, talkPayload(senderId))
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
		s.broadcastRelayControl(channelId, pktTalkGrant, senderId, talkPayload(senderId))
		s.publishManagementEvent("talk_started", uint32Pointer(channelId), uint32Pointer(senderId), nil, nil, nil, nil)
		return
	}

	current := firstActiveTalker(ch)
	activeCount := len(ch.activeTalkers)
	s.mu.Unlock()
	log.Printf("talk_deny ch=%d requester=%d current=%d active=%d/%d multi=%t", channelId, senderId, current, activeCount, limit, s.multiTalk)
	s.sendRelayControlTo(channelId, senderId, pktTalkDeny, current, talkPayload(current))
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
	s.broadcastRelayControl(channelId, pktTalkRelease, senderId, talkReleasePayload(senderId, talkReleaseClientPttOff))
	s.publishManagementEvent("talk_ended", uint32Pointer(channelId), uint32Pointer(senderId), nil, nil, nil, stringPointer("CLIENT_PTT_OFF"))
}

func (s *server) releaseTalkIfNeeded(channelId uint32, senderId uint32, reason uint8) {
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
	log.Printf("talk_release ch=%d talker=%d reason=%d (peer_left)", channelId, senderId, reason)
	s.broadcastRelayControl(channelId, pktTalkRelease, senderId, talkReleasePayload(senderId, reason))
	s.publishManagementEvent("talk_ended", uint32Pointer(channelId), uint32Pointer(senderId), nil, nil, nil, stringPointer(talkReleaseReasonName(reason)))
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

type membershipExpiry struct {
	senderId uint32
	reason   uint8
	active   bool
}

func membershipExpired(peer *peer, now time.Time) (uint8, bool) {
	if peer == nil {
		return 0, false
	}
	normalExpired := !peer.membershipDeadline.IsZero() && !peer.membershipDeadline.After(now)
	identityExpired := peer.identityAdmission != nil && !peer.identityAdmission.expiresAt.After(now)
	serviceExpired := peer.serviceAdmission != nil && !peer.serviceAdmission.expiryDeadline().After(now)
	if !normalExpired && !identityExpired && !serviceExpired {
		return 0, false
	}
	if identityExpired && (!normalExpired || peer.membershipDeadline.IsZero() || peer.identityAdmission.expiresAt.Before(peer.membershipDeadline)) {
		return talkReleaseIdentityExpired, true
	}
	if serviceExpired && (!normalExpired || peer.membershipDeadline.IsZero() || peer.serviceAdmission.expiryDeadline().Before(peer.membershipDeadline)) {
		return talkReleaseServiceExpired, true
	}
	return talkReleaseMembershipTimeout, true
}

func (s *server) expireMembershipIfNeeded(channelId uint32) []membershipExpiry {
	now := time.Now()
	s.mu.Lock()
	ch := s.channels[channelId]
	if ch == nil {
		s.mu.Unlock()
		return nil
	}
	released := make([]membershipExpiry, 0)
	for key, peer := range ch.peers {
		reason, expired := membershipExpired(peer, now)
		if !expired {
			continue
		}
		delete(ch.peers, key)
		delete(ch.codecConfigs, peer.senderId)
		delete(ch.mediaCodecConfigs, peer.senderId)
		active := false
		if _, active = ch.activeTalkers[peer.senderId]; active {
			delete(ch.activeTalkers, peer.senderId)
		}
		released = append(released, membershipExpiry{senderId: peer.senderId, reason: reason, active: active})
	}
	if len(ch.peers) == 0 {
		delete(s.channels, channelId)
	}
	s.mu.Unlock()
	sort.Slice(released, func(i, j int) bool { return released[i].senderId < released[j].senderId })
	return released
}

func (s *server) emitMembershipExpirations(channelId uint32) {
	for _, expiry := range s.expireMembershipIfNeeded(channelId) {
		if expiry.active {
			log.Printf("talk_release ch=%d talker=%d reason=%d (membership_expiry)", channelId, expiry.senderId, expiry.reason)
			s.broadcastRelayControl(channelId, pktTalkRelease, expiry.senderId, talkReleasePayload(expiry.senderId, expiry.reason))
			s.publishManagementEvent("talk_ended", uint32Pointer(channelId), uint32Pointer(expiry.senderId), nil, nil, nil, stringPointer(talkReleaseReasonName(expiry.reason)))
		}
		s.publishManagementEvent("participant_left", uint32Pointer(channelId), uint32Pointer(expiry.senderId), nil, nil, nil, stringPointer(talkReleaseReasonName(expiry.reason)))
	}
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
	lease, keepalive := s.membershipTimingForPeer(channelId, senderId)
	payload := make([]byte, 8)
	binary.BigEndian.PutUint16(payload, durationToSecondsClamped(s.talkMax))
	if s.multiTalk {
		payload[2] |= 0x01
	}
	limit := 1
	if s.multiTalk {
		limit = s.maxActiveTalkers
		if limit < 1 {
			limit = 1
		}
		if limit > maxActiveTalkersV1 {
			limit = maxActiveTalkersV1
		}
	}
	payload[3] = byte(limit)
	binary.BigEndian.PutUint16(payload[4:6], durationToSecondsClamped(lease))
	binary.BigEndian.PutUint16(payload[6:8], durationToSecondsClamped(keepalive))
	s.sendRelayControlTo(channelId, senderId, pktServerCfg, 0, payload)
}

type talkerSyncState struct {
	talkerID uint32
	codec    codecConfigState
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
		codec := ch.mediaCodecConfigs[talkerID]
		if len(codec.payload) == 0 {
			codec.payload = append([]byte(nil), ch.codecConfigs[talkerID]...)
		}
		states = append(states, talkerSyncState{
			talkerID: talkerID,
			codec:    codec,
		})
	}
	s.mu.Unlock()

	for _, state := range states {
		// Configure the per-talker decoder before announcing that audio may arrive.
		if len(state.codec.payload) == 19 {
			s.sendRelayCodecConfigTo(channelId, senderId, state.talkerID, state.codec)
		}
		log.Printf("join_sync_talker ch=%d to=%d talker=%d codec_config=%t", channelId, senderId, state.talkerID, len(state.codec.payload) == 19)
		s.sendRelayControlTo(channelId, senderId, pktTalkGrant, state.talkerID, talkPayload(state.talkerID))
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
	interval := timeout / 2
	if interval <= 0 {
		interval = time.Second
	}
	if interval > time.Second {
		interval = time.Second
	}
	// Check monotonic talk deadlines independently of peer expiry.  Waiting for
	// the normal 15-second peer cleanup interval would forward stale talk media
	// after a short server-managed PTT lease has expired.
	if s.talkMax > 0 && interval > 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		type releaseEvent struct {
			channelID uint32
			talkerID  uint32
			reason    uint8
		}
		type departureEvent struct {
			channelID uint32
			senderID  uint32
			reason    uint8
		}
		releases := make([]releaseEvent, 0)
		departures := make([]departureEvent, 0)

		s.mu.Lock()
		for channelId, ch := range s.channels {
			releaseReasons := make(map[uint32]uint8)
			for key, p := range ch.peers {
				if reason, expired := membershipExpired(p, now); expired {
					delete(ch.peers, key)
					delete(ch.codecConfigs, p.senderId)
					delete(ch.mediaCodecConfigs, p.senderId)
					departures = append(departures, departureEvent{channelID: channelId, senderID: p.senderId, reason: reason})
					if _, ok := ch.activeTalkers[p.senderId]; ok {
						delete(ch.activeTalkers, p.senderId)
						releaseReasons[p.senderId] = reason
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
					if _, releasedForMembership := releaseReasons[senderID]; !releasedForMembership {
						releaseReasons[senderID] = talkReleaseServerTimeout
					}
				}
			}
			if len(ch.peers) == 0 {
				delete(s.channels, channelId)
			}
			for talkerID, reason := range releaseReasons {
				releases = append(releases, releaseEvent{channelID: channelId, talkerID: talkerID, reason: reason})
			}
		}
		s.mu.Unlock()

		sort.Slice(releases, func(i, j int) bool {
			if releases[i].channelID != releases[j].channelID {
				return releases[i].channelID < releases[j].channelID
			}
			return releases[i].talkerID < releases[j].talkerID
		})
		for _, release := range releases {
			log.Printf("talk_release ch=%d talker=%d reason=%d (cleanup)", release.channelID, release.talkerID, release.reason)
			s.broadcastRelayControl(release.channelID, pktTalkRelease, release.talkerID, talkReleasePayload(release.talkerID, release.reason))
			s.publishManagementEvent("talk_ended", uint32Pointer(release.channelID), uint32Pointer(release.talkerID), nil, nil, nil, stringPointer(talkReleaseReasonName(release.reason)))
		}
		sort.Slice(departures, func(i, j int) bool {
			if departures[i].channelID != departures[j].channelID {
				return departures[i].channelID < departures[j].channelID
			}
			return departures[i].senderID < departures[j].senderID
		})
		for _, departure := range departures {
			s.publishManagementEvent("participant_left", uint32Pointer(departure.channelID), uint32Pointer(departure.senderID), nil, nil, nil, stringPointer(talkReleaseReasonName(departure.reason)))
		}
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
	log.Printf("rx type=%s ch=%d sender=%d seq=%d hlen=%d key=%d control_nonce=%d media_counter=%d from=%s size=%d%s",
		pktTypeName(pkt.Header.Type),
		pkt.Header.ChannelId,
		pkt.Header.SenderId,
		pkt.Header.Seq,
		pkt.Header.HeaderLen,
		pkt.Sec.KeyID,
		pkt.Sec.ControlNonce,
		pkt.Sec.MediaCounter,
		addr.String(),
		size,
		extra)
}

func parseCodecConfigPayload(payload []byte) (pcmOnly bool, codecId uint8, mode uint32, ok bool) {
	if len(payload) != 19 {
		return false, 0, 0, false
	}

	flags := payload[0]
	pcmOnly = (flags & 0x01) != 0
	codecId = payload[1]
	mode = binary.BigEndian.Uint32(payload[2:6])
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
	if isRealtimeMedia && size > udpNearLimitBytes {
		s.sizeWindowOverWarn++
		if now.Sub(s.lastWarnLog) >= 3*time.Second {
			log.Printf("udp_size_near_limit type=%s size=%dB ch=%d sender=%d from=%s threshold=%dB",
				pktTypeName(pkt.Header.Type),
				size,
				pkt.Header.ChannelId,
				pkt.Header.SenderId,
				addr.String(),
				udpNearLimitBytes)
			s.lastWarnLog = now
		}
	}

	if now.Sub(s.sizeWindowStart) >= 30*time.Second {
		if s.sizeWindowMax > 0 {
			log.Printf("udp_size_stats window=30s max=%dB max_type=%s max_ch=%d max_sender=%d near_%dB=%d",
				s.sizeWindowMax,
				pktTypeName(s.sizeWindowMaxType),
				s.sizeWindowMaxCh,
				s.sizeWindowMaxSender,
				udpNearLimitBytes, s.sizeWindowOverWarn)
		}
		s.sizeWindowStart = now
		s.sizeWindowMax = 0
		s.sizeWindowMaxType = 0
		s.sizeWindowMaxCh = 0
		s.sizeWindowMaxSender = 0
		s.sizeWindowOverWarn = 0
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
	case pktPttRequest:
		return "ptt_request"
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
	case pktAuthHello:
		return "auth_hello"
	case pktAuthChallenge:
		return "auth_challenge"
	case pktIdentityBegin:
		return "identity_begin"
	case pktIdentityChallenge:
		return "identity_challenge"
	case pktIdentityProof:
		return "identity_proof"
	case pktIdentityDeny:
		return "identity_deny"
	case pktServiceBegin:
		return "service_admission_begin"
	case pktServiceChallenge:
		return "service_admission_challenge"
	case pktServiceProof:
		return "service_admission_proof"
	case pktServiceDeny:
		return "service_admission_deny"
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

	if (header.Type == pktAudio || header.Type == pktFec) &&
		header.Flags&packetFlagAESGCMV2HeaderAAD != 0 {
		if header.HeaderLen != aesGCMV2HeaderSize || len(data) < aesGCMV2HeaderSize+authTagSize {
			return parsedPacket{}, false
		}
		sec := securityHeader{KeyID: binary.BigEndian.Uint32(data[32:36]), MediaCounter: binary.BigEndian.Uint32(data[28:32])}
		copy(sec.MediaNonceBase[:], data[16:28])
		return parsePacketPayload(data, header, sec, aesGCMV2HeaderSize)
	}

	if header.HeaderLen == fixedHeaderSize+securityHeaderExtensionSize {
		if len(data) < fixedHeaderSize+securityHeaderExtensionSize+authTagSize {
			return parsedPacket{}, false
		}
		sec := securityHeader{
			ControlNonce: binary.BigEndian.Uint64(data[16:24]),
			KeyID:        binary.BigEndian.Uint32(data[24:28]),
		}
		return parsePacketPayload(data, header, sec, fixedHeaderSize+securityHeaderExtensionSize)
	}

	if header.HeaderLen != fixedHeaderSize || !noCrypto {
		return parsedPacket{}, false
	}
	payload := append([]byte(nil), data[fixedHeaderSize:]...)
	return parsedPacket{Header: header, Payload: payload, Raw: data}, true
}

func parsePacketPayload(data []byte, header packetHeader, sec securityHeader, payloadOffset int) (parsedPacket, bool) {
	payloadLen := len(data) - payloadOffset - authTagSize
	if payloadLen < 0 {
		return parsedPacket{}, false
	}
	payload := append([]byte(nil), data[payloadOffset:payloadOffset+payloadLen]...)
	tag := append([]byte(nil), data[payloadOffset+payloadLen:]...)
	return parsedPacket{Header: header, Sec: sec, Payload: payload, Tag: tag, Raw: data}, true
}

func buildControlPacket(pktType uint8, channelId uint32, senderId uint32, payload []byte, noCrypto bool) []byte {
	return buildRelayControlPacket(pktType, channelId, senderId, payload, noCrypto, 0)
}

func buildRelayControlPacket(pktType uint8, channelId uint32, senderId uint32, payload []byte, noCrypto bool, sequence uint16) []byte {
	header := make([]byte, fixedHeaderSize)
	header[0] = protocolVersion
	header[1] = pktType
	headerLen := fixedHeaderSize
	if !noCrypto {
		headerLen = fixedHeaderSize + securityHeaderExtensionSize
	}
	binary.BigEndian.PutUint16(header[2:4], uint16(headerLen))
	binary.BigEndian.PutUint32(header[4:8], channelId)
	binary.BigEndian.PutUint32(header[8:12], senderId)
	binary.BigEndian.PutUint16(header[12:14], sequence)
	binary.BigEndian.PutUint16(header[14:16], 0)

	if noCrypto {
		packet := make([]byte, 0, len(header)+len(payload))
		packet = append(packet, header...)
		packet = append(packet, payload...)
		return packet
	}

	sec := make([]byte, securityHeaderExtensionSize)
	tag := make([]byte, authTagSize)

	packet := make([]byte, 0, len(header)+len(sec)+len(payload)+len(tag))
	packet = append(packet, header...)
	packet = append(packet, sec...)
	packet = append(packet, payload...)
	packet = append(packet, tag...)
	return packet
}

func buildTalkPacket(pktType uint8, channelId uint32, talkerId uint32, noCrypto bool) []byte {
	return buildControlPacket(pktType, channelId, talkerId, talkPayload(talkerId), noCrypto)
}

func buildTalkReleasePacket(channelId uint32, talkerId uint32, reason uint8, noCrypto bool) []byte {
	return buildControlPacket(pktTalkRelease, channelId, talkerId, talkReleasePayload(talkerId, reason), noCrypto)
}

func talkPayload(talkerId uint32) []byte {
	payload := make([]byte, 5)
	binary.BigEndian.PutUint32(payload, talkerId)
	return payload[:4]
}

func talkReleasePayload(talkerId uint32, reason uint8) []byte {
	payload := make([]byte, 5)
	binary.BigEndian.PutUint32(payload, talkerId)
	payload[4] = reason
	return payload
}

func talkReleaseReasonName(reason uint8) string {
	switch reason {
	case talkReleaseClientPttOff:
		return "CLIENT_PTT_OFF"
	case talkReleaseServerTimeout:
		return "SERVER_TALK_TIMEOUT"
	case talkReleaseMembershipTimeout:
		return "MEMBERSHIP_TIMEOUT"
	case talkReleaseClientLeave:
		return "CLIENT_LEAVE"
	case talkReleaseServerPolicy:
		return "SERVER_POLICY"
	case talkReleaseIdentityExpired:
		return "IDENTITY_EXPIRED"
	case talkReleaseServiceRevoked:
		return "SERVICE_ADMISSION_REVOKED"
	case talkReleasePreempted:
		return "PREEMPTED"
	case talkReleaseServiceExpired:
		return "SERVICE_ADMISSION_EXPIRED"
	default:
		return "UNKNOWN"
	}
}

func main() {
	port := flag.Int("port", 50000, "UDP listen port")
	membershipLeaseDefault := int(defaultMembershipLease / time.Second)
	if raw := os.Getenv("INCOMUDON_MEMBERSHIP_LEASE_SEC"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			membershipLeaseDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_MEMBERSHIP_LEASE_SEC=%q (using %d)", raw, membershipLeaseDefault)
		}
	}
	keepaliveIntervalDefault := int(defaultKeepaliveInterval / time.Second)
	if raw := os.Getenv("INCOMUDON_KEEPALIVE_INTERVAL_SEC"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			keepaliveIntervalDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_KEEPALIVE_INTERVAL_SEC=%q (using %d)", raw, keepaliveIntervalDefault)
		}
	}
	membershipLeaseSec := flag.Int("membership-lease-sec", membershipLeaseDefault, "membership lease in seconds (15..300)")
	keepaliveIntervalSec := flag.Int("keepalive-interval-sec", keepaliveIntervalDefault, "idle keepalive interval in seconds (1..lease/3)")
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
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 1 && parsed <= maxActiveTalkersV1 {
			maxActiveTalkersDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_MAX_ACTIVE_TALKERS=%q (using 2; allowed range is 1..%d)", raw, maxActiveTalkersV1)
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
	directoryEnabled := flag.Bool("directory-enabled", directoryEnabledDefault, "enable Directory UDP v3")
	directoryTransportFlag := flag.String("directory-transport", os.Getenv("INCOMUDON_DIRECTORY_TRANSPORT"), "Directory UDP transport: media-port or dedicated-udp")
	directoryKeyFile := flag.String("directory-key-file", os.Getenv("INCOMUDON_DIRECTORY_KEY_FILE"), "CSV file containing channel_id,directory_channel_key_base64url")
	directoryChannelsCSV := flag.String("directory-channels-csv", os.Getenv("INCOMUDON_DIRECTORY_CHANNELS_CSV"), "CSV file containing channel_id,name")
	directorySpeakersCSV := flag.String("directory-speakers-csv", os.Getenv("INCOMUDON_DIRECTORY_SPEAKERS_CSV"), "CSV file containing channel_id,sender_id,name")
	directoryDedicatedListen := flag.String("directory-dedicated-listen", os.Getenv("INCOMUDON_DIRECTORY_DEDICATED_LISTEN"), "Directory UDP v3 dedicated listener address")
	directoryPublishDefault := directoryDefaultPublishInterval
	if raw := os.Getenv("INCOMUDON_DIRECTORY_PUBLISH_INTERVAL"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			directoryPublishDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_DIRECTORY_PUBLISH_INTERVAL=%q (using %s)", raw, directoryPublishDefault)
		}
	}
	directoryFreshnessDefault := directoryDefaultFreshnessTTL
	if raw := os.Getenv("INCOMUDON_DIRECTORY_FRESHNESS_TTL"); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil {
			directoryFreshnessDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_DIRECTORY_FRESHNESS_TTL=%q (using %s)", raw, directoryFreshnessDefault)
		}
	}
	directoryPublishInterval := flag.Duration("directory-publish-interval", directoryPublishDefault, "Directory UDP v3 participant publication interval (1s..)")
	directoryFreshnessTTL := flag.Duration("directory-freshness-ttl", directoryFreshnessDefault, "Directory UDP v3 response freshness TTL (1s..90s)")
	controlAuthPolicyDefault := os.Getenv("INCOMUDON_CONTROL_AUTH_POLICY")
	if controlAuthPolicyDefault == "" {
		controlAuthPolicyDefault = string(controlAuthOff)
	}
	controlAuthPolicyFlag := flag.String("control-auth-policy", controlAuthPolicyDefault, "control authentication policy: off, optional, or required")
	controlKeyFile := flag.String("control-key-file", os.Getenv("INCOMUDON_CONTROL_KEY_FILE"), "CSV file containing channel_id,key_id,control_key_base64")
	controlCookieSecretFile := flag.String("control-cookie-secret-file", os.Getenv("INCOMUDON_CONTROL_COOKIE_SECRET_FILE"), "file containing the Relay control cookie secret")
	identityAdmissionModeDefault := os.Getenv("INCOMUDON_IDENTITY_ADMISSION_MODE")
	if identityAdmissionModeDefault == "" {
		identityAdmissionModeDefault = string(identityAdmissionOff)
	}
	identityAdmissionModeFlag := flag.String("identity-admission-mode", identityAdmissionModeDefault, "identity admission policy: off, optional, or required")
	identityIssuer := flag.String("identity-issuer", os.Getenv("INCOMUDON_IDENTITY_ISSUER"), "expected Identity Admission ticket issuer")
	identityAudience := flag.String("identity-audience", os.Getenv("INCOMUDON_IDENTITY_AUDIENCE"), "expected Identity Admission ticket audience")
	identitySigningKeyFile := flag.String("identity-signing-key-file", os.Getenv("INCOMUDON_IDENTITY_SIGNING_KEY_FILE"), "CSV file containing kid,ed25519_public_key_base64")
	serviceAdmissionModeDefault := os.Getenv("INCOMUDON_SERVICE_ADMISSION_MODE")
	if serviceAdmissionModeDefault == "" {
		serviceAdmissionModeDefault = string(serviceAdmissionOff)
	}
	serviceAdmissionModeFlag := flag.String("service-admission-mode", serviceAdmissionModeDefault, "managed service admission policy: off or enabled")
	serviceAdmissionIssuer := flag.String("service-admission-issuer", os.Getenv("INCOMUDON_SERVICE_ADMISSION_ISSUER"), "expected Managed Service Admission grant issuer")
	serviceAdmissionAudience := flag.String("service-admission-audience", os.Getenv("INCOMUDON_SERVICE_ADMISSION_AUDIENCE"), "expected Managed Service Admission grant audience")
	serviceAdmissionSigningKeyFile := flag.String("service-admission-signing-key-file", os.Getenv("INCOMUDON_SERVICE_ADMISSION_SIGNING_KEY_FILE"), "CSV file containing kid,ed25519_public_key_base64")
	managementEnabledDefault := false
	if raw := os.Getenv("INCOMUDON_MANAGEMENT_ENABLED"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			managementEnabledDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_MANAGEMENT_ENABLED=%q (using false)", raw)
		}
	}
	managementEnabled := flag.Bool("management-enabled", managementEnabledDefault, "enable the mTLS-protected Management Plane v1 listener")
	managementListen := flag.String("management-listen", os.Getenv("INCOMUDON_MANAGEMENT_LISTEN"), "Management Plane HTTPS listen address")
	managementCertificateFile := flag.String("management-cert-file", os.Getenv("INCOMUDON_MANAGEMENT_CERT_FILE"), "Management Plane server certificate PEM file")
	managementPrivateKeyFile := flag.String("management-key-file", os.Getenv("INCOMUDON_MANAGEMENT_KEY_FILE"), "Management Plane server private key PEM file")
	managementClientCAFile := flag.String("management-client-ca-file", os.Getenv("INCOMUDON_MANAGEMENT_CLIENT_CA_FILE"), "Management Plane trusted client CA PEM file")
	managementServicesCSV := flag.String("management-services-csv", os.Getenv("INCOMUDON_MANAGEMENT_SERVICES_CSV"), "Management Plane services CSV")
	managementChannelACLCSV := flag.String("management-channel-acl-csv", os.Getenv("INCOMUDON_MANAGEMENT_CHANNEL_ACL_CSV"), "Management Plane channel ACL CSV")
	managementGlobalPermissionsCSV := flag.String("management-global-permissions-csv", os.Getenv("INCOMUDON_MANAGEMENT_GLOBAL_PERMISSIONS_CSV"), "Management Plane explicit global permissions CSV")
	managementSigningKeyFile := flag.String("management-signing-key-file", os.Getenv("INCOMUDON_MANAGEMENT_SIGNING_KEY_FILE"), "Management Plane Ed25519 private signing key CSV")
	floorInterruptDefault := false
	if raw := os.Getenv("INCOMUDON_FLOOR_INTERRUPT_ENABLED"); raw != "" {
		if parsed, err := strconv.ParseBool(raw); err == nil {
			floorInterruptDefault = parsed
		} else {
			log.Printf("invalid INCOMUDON_FLOOR_INTERRUPT_ENABLED=%q (using false)", raw)
		}
	}
	floorInterrupt := flag.Bool("floor-interrupt", floorInterruptDefault, "enable Identity Admission-authorized Floor Interrupt v1")
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
	if *maxActiveTalkers > maxActiveTalkersV1 {
		log.Printf("max-active-talkers=%d exceeds Version 1 limit; clamping to %d", *maxActiveTalkers, maxActiveTalkersV1)
		*maxActiveTalkers = maxActiveTalkersV1
	}
	membershipLease := time.Duration(*membershipLeaseSec) * time.Second
	keepaliveInterval := time.Duration(*keepaliveIntervalSec) * time.Second
	if !validMembershipTiming(membershipLease, keepaliveInterval) {
		log.Fatalf("invalid membership timing: lease must be 15..300 seconds and keepalive must be 1..floor(lease/3) seconds (got lease=%ds keepalive=%ds)", *membershipLeaseSec, *keepaliveIntervalSec)
	}
	talkMax := time.Duration(*talkMaxSec) * time.Second
	controlPolicy, err := parseControlAuthPolicy(*controlAuthPolicyFlag)
	if err != nil {
		log.Fatalf("invalid control authentication policy: %v", err)
	}
	if *noCrypto && controlPolicy == controlAuthRequired {
		log.Fatal("-no-crypto cannot be used with required control authentication")
	}
	controlKeys, err := loadControlKeyStore(*controlKeyFile)
	if err != nil {
		log.Fatalf("invalid control key configuration: %v", err)
	}
	cookieSecret, err := loadCookieSecret(*controlCookieSecretFile)
	if err != nil {
		log.Fatalf("invalid control cookie secret: %v", err)
	}
	controlAuth, err := newControlAuthState(controlPolicy, controlKeys, cookieSecret)
	if err != nil {
		log.Fatalf("invalid control authentication configuration: %v", err)
	}
	identityMode, err := parseIdentityAdmissionMode(*identityAdmissionModeFlag)
	if err != nil {
		log.Fatalf("invalid identity admission policy: %v", err)
	}
	identityKeys := make(identitySigningKeyStore)
	if identityMode != identityAdmissionOff {
		identityKeys, err = loadIdentitySigningKeys(*identitySigningKeyFile)
		if err != nil {
			log.Fatalf("invalid identity signing key configuration: %v", err)
		}
	}
	if identityMode == identityAdmissionRequired && controlPolicy != controlAuthRequired {
		log.Fatal("identity admission required requires control-auth-policy=required")
	}
	identityAdmission, err := newIdentityAdmissionState(identityMode, *identityIssuer, *identityAudience, identityKeys)
	if err != nil {
		log.Fatalf("invalid identity admission configuration: %v", err)
	}
	if *floorInterrupt && (identityAdmission == nil || !identityAdmission.isRequired() || controlPolicy != controlAuthRequired) {
		log.Fatal("floor-interrupt requires identity-admission-mode=required and control-auth-policy=required")
	}
	serviceMode, err := parseServiceAdmissionMode(*serviceAdmissionModeFlag)
	if err != nil {
		log.Fatalf("invalid managed service admission policy: %v", err)
	}
	serviceKeys := make(serviceSigningKeyStore)
	if serviceMode != serviceAdmissionOff {
		if controlPolicy == controlAuthOff || len(controlKeys) == 0 {
			log.Fatal("managed service admission requires configured Control Authentication keys")
		}
		serviceKeys, err = loadServiceSigningKeys(*serviceAdmissionSigningKeyFile)
		if err != nil {
			log.Fatalf("invalid managed service signing key configuration: %v", err)
		}
	}
	serviceAdmission, err := newServiceAdmissionState(serviceMode, *serviceAdmissionIssuer, *serviceAdmissionAudience, serviceKeys)
	if err != nil {
		log.Fatalf("invalid managed service admission configuration: %v", err)
	}

	addr := &net.UDPAddr{Port: *port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	defer conn.Close()
	srv := newServer(conn, *noCrypto, *logPackets, *logAudio, talkMax, *multiTalk, *maxActiveTalkers)
	if err := srv.configureMembershipTiming(membershipLease, keepaliveInterval); err != nil {
		log.Fatalf("invalid membership timing: %v", err)
	}
	srv.configureControlAuth(controlAuth)
	srv.configureIdentityAdmission(identityAdmission, *floorInterrupt)
	srv.configureServiceAdmission(serviceAdmission)
	if *directoryEnabled {
		directoryTransport, err := parseDirectoryTransport(*directoryTransportFlag)
		if err != nil {
			log.Fatalf("invalid Directory UDP transport: %v", err)
		}
		directoryConn := conn
		if directoryTransport == directoryTransportDedicatedUDP {
			if strings.TrimSpace(*directoryDedicatedListen) == "" {
				log.Fatal("-directory-dedicated-listen is required for directory-transport=dedicated-udp")
			}
			directoryAddr, err := net.ResolveUDPAddr("udp", *directoryDedicatedListen)
			if err != nil {
				log.Fatalf("invalid Directory UDP dedicated listener: %v", err)
			}
			directoryConn, err = net.ListenUDP("udp", directoryAddr)
			if err != nil {
				log.Fatalf("Directory UDP dedicated listen error: %v", err)
			}
		}
		directory, err := newDirectoryV3(directoryV3Config{
			Enabled: *directoryEnabled, Transport: directoryTransport, KeyFile: *directoryKeyFile,
			ChannelsCSV: *directoryChannelsCSV, SpeakersCSV: *directorySpeakersCSV, Conn: directoryConn,
			PublishInterval: *directoryPublishInterval, FreshnessTTL: *directoryFreshnessTTL,
			Participants: srv.directoryParticipants,
		})
		if err != nil {
			if directoryConn != conn {
				_ = directoryConn.Close()
			}
			log.Fatalf("invalid Directory UDP v3 configuration: %v", err)
		}
		srv.configureDirectory(directory)
		defer directory.close()
		directory.start()
		log.Printf("Directory UDP v3 enabled transport=%s", directoryTransport)
	}
	if *managementEnabled {
		if _, err := startManagementPlane(srv, managementPlaneConfig{
			listenAddress: *managementListen, certificateFile: *managementCertificateFile, privateKeyFile: *managementPrivateKeyFile,
			clientCAFile: *managementClientCAFile, servicesCSV: *managementServicesCSV, channelACLCSV: *managementChannelACLCSV,
			globalPermissionsCSV: *managementGlobalPermissionsCSV, signingKeyFile: *managementSigningKeyFile,
			issuer: *serviceAdmissionIssuer, audience: *serviceAdmissionAudience,
		}); err != nil {
			log.Fatalf("invalid Management Plane configuration: %v", err)
		}
		log.Printf("Management Plane HTTPS listener enabled at %s", *managementListen)
	}

	mode := "encrypted"
	if *noCrypto {
		mode = "no-crypto"
	}
	log.Printf("IncomUdon relay listening on udp :%d (%s, control_auth=%s, identity_admission=%s, service_admission=%s, floor_interrupt=%t, talk_max=%ds, membership_lease=%ds, keepalive_interval=%ds, multi_talk=%t, max_active_talkers=%d)", *port, mode, controlPolicy, identityMode, serviceMode, *floorInterrupt, *talkMaxSec, *membershipLeaseSec, *keepaliveIntervalSec, *multiTalk, *maxActiveTalkers)

	if *logAudio {
		*logPackets = true
	}
	go srv.cleanupLoop(membershipLease)
	srv.run()
}
