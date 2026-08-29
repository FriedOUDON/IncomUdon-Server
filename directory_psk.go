package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	directoryProtocolVersion      = 1
	directoryEnvelopeSnapshot     = "snapshot"
	directoryEnvelopeParticipants = "participants"
	directoryEnvelopeRequest      = "request"
	directoryEnvelopeRegister     = "register"
	directoryEnvelopeHeartbeat    = "heartbeat"
	directoryPSKBytes             = 32
	directoryEpochBytes           = 16
	directoryMaxDatagramBytes     = 1200
	directoryMaxChannels          = 256
	directoryMaxSpeakers          = 4096
	directoryMaxParticipants      = 128
	directoryMaxClients           = 64
	directoryMaxNameRunes         = 128
	directoryMaxKeyIDBytes        = 64
	directoryMaxValidity          = 5 * time.Minute
	directoryDefaultKeyID         = "pwa-1"
	directoryDefaultInterval      = 30 * time.Second
	directoryDefaultTTL           = 90 * time.Second
	directoryDefaultClientTTL     = 90 * time.Second
	directoryRequestTTL           = 30 * time.Second
	directoryKeyDerivationLabel   = "IncomUdon directory PSK v1 relay-to-pwa"
	directoryAllChannels          = "all"
)

type directoryChannel struct {
	ChannelID uint32 `json:"channelId"`
	Name      string `json:"name"`
}

type directorySpeaker struct {
	ChannelID uint32 `json:"channelId"`
	SenderID  uint32 `json:"senderId"`
	Name      string `json:"name"`
}

type directoryDocument struct {
	Version   int                `json:"version"`
	Revision  string             `json:"revision"`
	IssuedAt  int64              `json:"issuedAt"`
	ExpiresAt int64              `json:"expiresAt"`
	Channels  []directoryChannel `json:"channels"`
	Speakers  []directorySpeaker `json:"speakers"`
}

// directoryParticipant intentionally omits network addresses and cryptographic
// material. It is safe to provision to an authenticated UI or a future native
// client while still describing who is currently present on a channel.
type directoryParticipant struct {
	ChannelID  uint32 `json:"channelId"`
	SenderID   uint32 `json:"senderId"`
	LastSeenAt int64  `json:"lastSeenAt"`
	Talking    bool   `json:"talking"`
}

type directoryParticipantsDocument struct {
	Version      int                    `json:"version"`
	Revision     string                 `json:"revision"`
	IssuedAt     int64                  `json:"issuedAt"`
	ExpiresAt    int64                  `json:"expiresAt"`
	Participants []directoryParticipant `json:"participants"`
}

type directoryRequest struct {
	Version   int   `json:"version"`
	IssuedAt  int64 `json:"issuedAt"`
	ExpiresAt int64 `json:"expiresAt"`
}

// directoryRegistration identifies a PWA or native directory consumer without
// carrying an address. The Relay always records the authenticated UDP source
// address rather than trusting anything supplied in this payload.
type directoryRegistration struct {
	Version    int    `json:"version"`
	InstanceID string `json:"instanceId"`
	IssuedAt   int64  `json:"issuedAt"`
	ExpiresAt  int64  `json:"expiresAt"`
}

type directoryEnvelope struct {
	Version    int    `json:"v"`
	Type       string `json:"type"`
	KeyID      string `json:"keyId"`
	Epoch      string `json:"epoch"`
	Sequence   uint64 `json:"sequence"`
	ExpiresAt  int64  `json:"expiresAt"`
	Ciphertext string `json:"ciphertext"`
}

type directoryPublisherConfig struct {
	Enabled           bool
	ChannelsCSV       string
	SpeakersCSV       string
	Target            string
	ListenAddress     string
	PSKFile           string
	KeyID             string
	Interval          time.Duration
	TTL               time.Duration
	RequestAllowCIDRs string
	DynamicClients    bool
	ClientTTL         time.Duration
	ClientAllowCIDRs  string
	Participants      func() []directoryParticipant
}

type directoryRegisteredClient struct {
	Address   *net.UDPAddr
	ExpiresAt time.Time
}

type directoryPublisher struct {
	channelsCSV   string
	speakersCSV   string
	conn          *net.UDPConn
	target        *net.UDPAddr
	psk           []byte
	keyID         string
	epoch         []byte
	interval      time.Duration
	ttl           time.Duration
	allowed       []*net.IPNet
	dynamic       bool
	clientTTL     time.Duration
	clientAllowed []*net.IPNet
	participants  func() []directoryParticipant
	sequenceMu    sync.Mutex
	sequence      uint64
	replayMu      sync.Mutex
	replay        map[string]directoryReplayState
	clientsMu     sync.Mutex
	clients       map[string]directoryRegisteredClient
}

type directoryReplayState struct {
	Sequence  uint64
	ExpiresAt int64
}

func newDirectoryPublisher(config directoryPublisherConfig) (*directoryPublisher, error) {
	config.ChannelsCSV = strings.TrimSpace(config.ChannelsCSV)
	config.SpeakersCSV = strings.TrimSpace(config.SpeakersCSV)
	config.Target = strings.TrimSpace(config.Target)
	config.ListenAddress = strings.TrimSpace(config.ListenAddress)
	config.PSKFile = strings.TrimSpace(config.PSKFile)
	config.KeyID = strings.TrimSpace(config.KeyID)
	if config.KeyID == "" {
		config.KeyID = directoryDefaultKeyID
	}

	if !config.Enabled {
		return nil, nil
	}
	if config.ChannelsCSV == "" || config.SpeakersCSV == "" || config.ListenAddress == "" || config.PSKFile == "" {
		return nil, fmt.Errorf("directory publishing requires channels CSV, speakers CSV, UDP listen address, and PSK file")
	}
	if config.Target == "" && !config.DynamicClients {
		return nil, fmt.Errorf("directory publishing requires a UDP target unless dynamic clients are enabled")
	}
	if err := validateDirectoryKeyID(config.KeyID); err != nil {
		return nil, err
	}
	if config.Interval <= 0 {
		config.Interval = directoryDefaultInterval
	}
	if config.TTL <= 0 {
		config.TTL = directoryDefaultTTL
	}
	if config.Interval < time.Second {
		return nil, fmt.Errorf("directory publish interval must be at least 1s")
	}
	if config.TTL < 5*time.Second || config.TTL > directoryMaxValidity {
		return nil, fmt.Errorf("directory TTL must be between 5s and %s", directoryMaxValidity)
	}
	if config.ClientTTL <= 0 {
		config.ClientTTL = directoryDefaultClientTTL
	}
	if config.ClientTTL < 5*time.Second || config.ClientTTL > directoryMaxValidity {
		return nil, fmt.Errorf("directory client TTL must be between 5s and %s", directoryMaxValidity)
	}

	psk, err := loadDirectoryPSK(config.PSKFile)
	if err != nil {
		return nil, err
	}
	var target *net.UDPAddr
	if config.Target != "" {
		target, err = net.ResolveUDPAddr("udp", config.Target)
		if err != nil {
			return nil, fmt.Errorf("resolve directory UDP target: %w", err)
		}
	}
	allowed, err := parseDirectoryAllowCIDRs(config.RequestAllowCIDRs)
	if err != nil {
		return nil, err
	}
	clientAllowed, err := parseDirectoryAllowCIDRs(config.ClientAllowCIDRs)
	if err != nil {
		return nil, err
	}
	listenAddress, err := net.ResolveUDPAddr("udp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf("resolve directory UDP listener: %w", err)
	}
	conn, err := net.ListenUDP("udp", listenAddress)
	if err != nil {
		return nil, fmt.Errorf("listen for directory UDP: %w", err)
	}
	epoch := make([]byte, directoryEpochBytes)
	if _, err := rand.Read(epoch); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("generate directory epoch: %w", err)
	}

	return &directoryPublisher{
		channelsCSV:   config.ChannelsCSV,
		speakersCSV:   config.SpeakersCSV,
		conn:          conn,
		target:        target,
		psk:           psk,
		keyID:         config.KeyID,
		epoch:         epoch,
		interval:      config.Interval,
		ttl:           config.TTL,
		allowed:       allowed,
		dynamic:       config.DynamicClients,
		clientTTL:     config.ClientTTL,
		clientAllowed: clientAllowed,
		participants:  config.Participants,
		replay:        make(map[string]directoryReplayState),
		clients:       make(map[string]directoryRegisteredClient),
	}, nil
}

func (p *directoryPublisher) Close() error {
	if p == nil || p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

func (p *directoryPublisher) Run() {
	if p == nil {
		return
	}
	go p.serveRequests()
	p.publishAll("startup")
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for range ticker.C {
		p.publishAll("periodic")
	}
}

func (p *directoryPublisher) serveRequests() {
	if p == nil || p.conn == nil {
		return
	}
	buffer := make([]byte, directoryMaxDatagramBytes+1)
	for {
		n, source, err := p.conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Printf("directory request read error: %v", err)
				continue
			}
			return
		}
		if n > directoryMaxDatagramBytes {
			continue
		}
		envelopeType, err := directoryPacketEnvelopeType(buffer[:n])
		if err != nil {
			continue
		}
		switch envelopeType {
		case directoryEnvelopeRequest:
			if !p.sourceAllowed(source) {
				continue
			}
			if err := p.openRequest(buffer[:n]); err != nil {
				log.Printf("directory request rejected from %s: %v", source, err)
				continue
			}
			p.publishTo(source, "pull")

		case directoryEnvelopeRegister, directoryEnvelopeHeartbeat:
			if !p.dynamic || !p.clientSourceAllowed(source) {
				continue
			}
			registration, err := p.openRegistration(buffer[:n], envelopeType)
			if err != nil {
				log.Printf("directory client %s rejected from %s: %v", envelopeType, source, err)
				continue
			}
			if p.registerClient(registration, source) {
				p.publishTo(source, "register")
			}
		}
	}
}

func (p *directoryPublisher) publishAll(reason string) {
	if p == nil {
		return
	}
	targets := make(map[string]*net.UDPAddr)
	if p.target != nil {
		targets[p.target.String()] = p.target
	}
	for _, target := range p.activeClientTargets(time.Now()) {
		targets[target.String()] = target
	}
	for _, target := range targets {
		p.publishTo(target, reason)
	}
}

func (p *directoryPublisher) publishTo(target *net.UDPAddr, reason string) {
	if p == nil || p.conn == nil || target == nil {
		return
	}
	now := time.Now()
	document, err := loadDirectoryDocument(p.channelsCSV, p.speakersCSV, now, p.ttl)
	if err != nil {
		log.Printf("directory snapshot skipped (%s): %v", reason, err)
		return
	}
	if err := p.writeDocument(target, directoryEnvelopeSnapshot, document.ExpiresAt, document, reason); err != nil {
		log.Printf("directory snapshot skipped (%s): %v", reason, err)
		return
	}

	participants := make([]directoryParticipant, 0)
	if p.participants != nil {
		participants = p.participants()
	}
	if len(participants) > directoryMaxParticipants {
		log.Printf("directory participants skipped (%s): %d participants exceeds maximum %d", reason, len(participants), directoryMaxParticipants)
		return
	}
	for _, participant := range participants {
		if participant.ChannelID == 0 || participant.SenderID == 0 || participant.LastSeenAt <= 0 {
			log.Printf("directory participants skipped (%s): invalid participant snapshot", reason)
			return
		}
	}
	participantDocument := directoryParticipantsDocument{
		Version:      directoryProtocolVersion,
		IssuedAt:     now.Unix(),
		ExpiresAt:    now.Add(p.ttl).Unix(),
		Participants: participants,
	}
	participantDocument.Revision = directoryParticipantsDocumentRevision(participantDocument)
	if err := p.writeDocument(target, directoryEnvelopeParticipants, participantDocument.ExpiresAt, participantDocument, reason); err != nil {
		log.Printf("directory participants skipped (%s): %v", reason, err)
	}
}

func (p *directoryPublisher) writeDocument(target *net.UDPAddr, envelopeType string, expiresAt int64, document any, reason string) error {
	payload, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	sequence := p.nextSequence()
	envelope, err := sealDirectoryEnvelope(p.psk, p.keyID, p.epoch, sequence, expiresAt, payload, envelopeType)
	if err != nil {
		return fmt.Errorf("encrypt payload: %w", err)
	}
	packet, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	if len(packet) > directoryMaxDatagramBytes {
		return fmt.Errorf("packet is %d bytes (maximum %d)", len(packet), directoryMaxDatagramBytes)
	}
	if _, err := p.conn.WriteToUDP(packet, target); err != nil {
		return fmt.Errorf("send failed: %w", err)
	}
	switch typed := document.(type) {
	case directoryDocument:
		log.Printf("directory snapshot sent: reason=%s revision=%s channels=%d speakers=%d bytes=%d", reason, typed.Revision[:12], len(typed.Channels), len(typed.Speakers), len(packet))
	case directoryParticipantsDocument:
		log.Printf("directory participants sent: reason=%s revision=%s participants=%d bytes=%d", reason, typed.Revision[:12], len(typed.Participants), len(packet))
	}
	return nil
}

func (p *directoryPublisher) nextSequence() uint64 {
	p.sequenceMu.Lock()
	p.sequence++
	sequence := p.sequence
	p.sequenceMu.Unlock()
	return sequence
}

func sealDirectoryEnvelope(psk []byte, keyID string, epoch []byte, sequence uint64, expiresAt int64, payload []byte, envelopeType string) (directoryEnvelope, error) {
	if len(epoch) != directoryEpochBytes {
		return directoryEnvelope{}, fmt.Errorf("invalid directory epoch")
	}
	if !isDirectoryEnvelopeType(envelopeType) {
		return directoryEnvelope{}, fmt.Errorf("invalid directory envelope type")
	}
	envelope := directoryEnvelope{
		Version:   directoryProtocolVersion,
		Type:      envelopeType,
		KeyID:     keyID,
		Epoch:     base64.RawURLEncoding.EncodeToString(epoch),
		Sequence:  sequence,
		ExpiresAt: expiresAt,
	}
	key := deriveDirectoryKey(psk, epoch)
	block, err := aes.NewCipher(key)
	if err != nil {
		return directoryEnvelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return directoryEnvelope{}, err
	}
	aad, err := directoryEnvelopeAAD(envelope, epoch)
	if err != nil {
		return directoryEnvelope{}, err
	}
	sealed := aead.Seal(nil, directoryNonce(sequence), payload, aad)
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(sealed)
	return envelope, nil
}

func (p *directoryPublisher) openRequest(packet []byte) error {
	envelope, plaintext, err := openDirectoryEnvelope(p.psk, p.keyID, packet, directoryEnvelopeRequest)
	if err != nil {
		return err
	}
	now := time.Now()
	if envelope.ExpiresAt <= now.Unix() || envelope.ExpiresAt > now.Add(directoryRequestTTL).Unix() {
		return fmt.Errorf("expired or excessive request validity")
	}
	var request directoryRequest
	if err := decodeDirectoryJSON(plaintext, &request); err != nil {
		return fmt.Errorf("invalid request: %w", err)
	}
	if request.Version != directoryProtocolVersion || request.ExpiresAt != envelope.ExpiresAt || request.IssuedAt > now.Add(30*time.Second).Unix() || request.IssuedAt < now.Add(-directoryRequestTTL).Unix() || request.ExpiresAt <= request.IssuedAt {
		return fmt.Errorf("invalid request metadata")
	}
	if !p.acceptRequestSequence(envelope, now.Unix()) {
		return fmt.Errorf("replayed request")
	}
	return nil
}

func (p *directoryPublisher) openRegistration(packet []byte, envelopeType string) (directoryRegistration, error) {
	if envelopeType != directoryEnvelopeRegister && envelopeType != directoryEnvelopeHeartbeat {
		return directoryRegistration{}, fmt.Errorf("invalid directory client envelope type")
	}
	envelope, plaintext, err := openDirectoryEnvelope(p.psk, p.keyID, packet, envelopeType)
	if err != nil {
		return directoryRegistration{}, err
	}
	now := time.Now()
	if envelope.ExpiresAt <= now.Unix() || envelope.ExpiresAt > now.Add(directoryRequestTTL).Unix() {
		return directoryRegistration{}, fmt.Errorf("expired or excessive client registration validity")
	}
	var registration directoryRegistration
	if err := decodeDirectoryJSON(plaintext, &registration); err != nil {
		return directoryRegistration{}, fmt.Errorf("invalid client registration: %w", err)
	}
	if registration.Version != directoryProtocolVersion || registration.ExpiresAt != envelope.ExpiresAt || registration.IssuedAt > now.Add(30*time.Second).Unix() || registration.IssuedAt < now.Add(-directoryRequestTTL).Unix() || registration.ExpiresAt <= registration.IssuedAt {
		return directoryRegistration{}, fmt.Errorf("invalid client registration metadata")
	}
	if err := validateDirectoryInstanceID(registration.InstanceID); err != nil {
		return directoryRegistration{}, err
	}
	if !p.acceptRequestSequence(envelope, now.Unix()) {
		return directoryRegistration{}, fmt.Errorf("replayed client registration")
	}
	return registration, nil
}

func openDirectoryEnvelope(psk []byte, keyID string, packet []byte, expectedType string) (directoryEnvelope, []byte, error) {
	var envelope directoryEnvelope
	if err := decodeDirectoryJSON(packet, &envelope); err != nil {
		return directoryEnvelope{}, nil, fmt.Errorf("invalid envelope: %w", err)
	}
	if envelope.Version != directoryProtocolVersion || envelope.Type != expectedType || envelope.KeyID != keyID || envelope.Sequence == 0 {
		return directoryEnvelope{}, nil, fmt.Errorf("unsupported envelope")
	}
	epoch, err := base64.RawURLEncoding.DecodeString(envelope.Epoch)
	if err != nil || len(epoch) != directoryEpochBytes {
		return directoryEnvelope{}, nil, fmt.Errorf("invalid envelope epoch")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) < aes.BlockSize+16 {
		return directoryEnvelope{}, nil, fmt.Errorf("invalid envelope ciphertext")
	}
	block, err := aes.NewCipher(deriveDirectoryKey(psk, epoch))
	if err != nil {
		return directoryEnvelope{}, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return directoryEnvelope{}, nil, err
	}
	aad, err := directoryEnvelopeAAD(envelope, epoch)
	if err != nil {
		return directoryEnvelope{}, nil, err
	}
	plaintext, err := aead.Open(nil, directoryNonce(envelope.Sequence), ciphertext, aad)
	if err != nil {
		return directoryEnvelope{}, nil, fmt.Errorf("authentication failed")
	}
	return envelope, plaintext, nil
}

func (p *directoryPublisher) acceptRequestSequence(envelope directoryEnvelope, now int64) bool {
	key := envelope.KeyID + ":" + envelope.Epoch
	p.replayMu.Lock()
	defer p.replayMu.Unlock()
	for replayKey, state := range p.replay {
		if state.ExpiresAt <= now {
			delete(p.replay, replayKey)
		}
	}
	if previous, ok := p.replay[key]; ok && envelope.Sequence <= previous.Sequence {
		return false
	}
	if len(p.replay) >= 64 {
		oldestKey := ""
		var oldestExpiry int64
		for replayKey, state := range p.replay {
			if oldestKey == "" || state.ExpiresAt < oldestExpiry {
				oldestKey = replayKey
				oldestExpiry = state.ExpiresAt
			}
		}
		delete(p.replay, oldestKey)
	}
	p.replay[key] = directoryReplayState{Sequence: envelope.Sequence, ExpiresAt: envelope.ExpiresAt}
	return true
}

// registerClient returns true when the registration is new or the observed UDP
// endpoint changed. Only those transitions trigger an immediate snapshot; later
// heartbeats are served by the normal periodic publisher.
func (p *directoryPublisher) registerClient(registration directoryRegistration, source *net.UDPAddr) bool {
	if p == nil || source == nil || source.IP == nil || source.Port <= 0 {
		return false
	}
	key := p.keyID + ":" + registration.InstanceID
	now := time.Now()
	address := cloneDirectoryUDPAddr(source)
	p.clientsMu.Lock()
	defer p.clientsMu.Unlock()
	for clientKey, client := range p.clients {
		if !client.ExpiresAt.After(now) {
			delete(p.clients, clientKey)
		}
	}
	previous, exists := p.clients[key]
	if !exists && len(p.clients) >= directoryMaxClients {
		oldestKey := ""
		var oldestExpiry time.Time
		for clientKey, client := range p.clients {
			if oldestKey == "" || client.ExpiresAt.Before(oldestExpiry) {
				oldestKey = clientKey
				oldestExpiry = client.ExpiresAt
			}
		}
		delete(p.clients, oldestKey)
	}
	p.clients[key] = directoryRegisteredClient{Address: address, ExpiresAt: now.Add(p.clientTTL)}
	return !exists || !directoryUDPAddrEqual(previous.Address, address)
}

func (p *directoryPublisher) activeClientTargets(now time.Time) []*net.UDPAddr {
	if p == nil || !p.dynamic {
		return nil
	}
	p.clientsMu.Lock()
	defer p.clientsMu.Unlock()
	targets := make([]*net.UDPAddr, 0, len(p.clients))
	for key, client := range p.clients {
		if !client.ExpiresAt.After(now) {
			delete(p.clients, key)
			continue
		}
		targets = append(targets, cloneDirectoryUDPAddr(client.Address))
	}
	return targets
}

func cloneDirectoryUDPAddr(address *net.UDPAddr) *net.UDPAddr {
	if address == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), address.IP...), Port: address.Port, Zone: address.Zone}
}

func directoryUDPAddrEqual(left, right *net.UDPAddr) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Port == right.Port && left.Zone == right.Zone && left.IP.Equal(right.IP)
}

func (p *directoryPublisher) sourceAllowed(source *net.UDPAddr) bool {
	if len(p.allowed) == 0 || source == nil {
		return source != nil
	}
	for _, cidr := range p.allowed {
		if cidr.Contains(source.IP) {
			return true
		}
	}
	return false
}

func (p *directoryPublisher) clientSourceAllowed(source *net.UDPAddr) bool {
	if len(p.clientAllowed) == 0 || source == nil {
		return source != nil
	}
	for _, cidr := range p.clientAllowed {
		if cidr.Contains(source.IP) {
			return true
		}
	}
	return false
}

func parseDirectoryAllowCIDRs(raw string) ([]*net.IPNet, error) {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	allowed := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("invalid directory allowed CIDR %q: %w", part, err)
		}
		allowed = append(allowed, cidr)
	}
	return allowed, nil
}

func decodeDirectoryJSON(payload []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("trailing JSON data")
	}
	return nil
}

func directoryPacketEnvelopeType(packet []byte) (string, error) {
	var envelope directoryEnvelope
	if err := decodeDirectoryJSON(packet, &envelope); err != nil {
		return "", fmt.Errorf("invalid envelope: %w", err)
	}
	if envelope.Version != directoryProtocolVersion || !isDirectoryEnvelopeType(envelope.Type) {
		return "", fmt.Errorf("unsupported envelope")
	}
	return envelope.Type, nil
}

func isDirectoryEnvelopeType(value string) bool {
	switch value {
	case directoryEnvelopeSnapshot, directoryEnvelopeParticipants, directoryEnvelopeRequest, directoryEnvelopeRegister, directoryEnvelopeHeartbeat:
		return true
	default:
		return false
	}
}

func loadDirectoryDocument(channelsCSV, speakersCSV string, now time.Time, ttl time.Duration) (directoryDocument, error) {
	channels, err := loadDirectoryChannels(channelsCSV)
	if err != nil {
		return directoryDocument{}, err
	}
	speakers, err := loadDirectorySpeakers(speakersCSV, channels)
	if err != nil {
		return directoryDocument{}, err
	}
	document := directoryDocument{
		Version:   directoryProtocolVersion,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		Channels:  channels,
		Speakers:  speakers,
	}
	document.Revision = directoryDocumentRevision(document)
	return document, nil
}

func directoryDocumentRevision(document directoryDocument) string {
	channels := append([]directoryChannel(nil), document.Channels...)
	speakers := append([]directorySpeaker(nil), document.Speakers...)
	sort.Slice(channels, func(i, j int) bool { return channels[i].ChannelID < channels[j].ChannelID })
	sort.Slice(speakers, func(i, j int) bool {
		if speakers[i].ChannelID != speakers[j].ChannelID {
			return speakers[i].ChannelID < speakers[j].ChannelID
		}
		return speakers[i].SenderID < speakers[j].SenderID
	})
	payload, _ := json.Marshal(struct {
		Channels []directoryChannel `json:"channels"`
		Speakers []directorySpeaker `json:"speakers"`
	}{channels, speakers})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func directoryParticipantsDocumentRevision(document directoryParticipantsDocument) string {
	participants := append([]directoryParticipant(nil), document.Participants...)
	sort.Slice(participants, func(i, j int) bool {
		if participants[i].ChannelID != participants[j].ChannelID {
			return participants[i].ChannelID < participants[j].ChannelID
		}
		return participants[i].SenderID < participants[j].SenderID
	})
	payload, _ := json.Marshal(struct {
		Participants []directoryParticipant `json:"participants"`
	}{participants})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func loadDirectoryChannels(path string) ([]directoryChannel, error) {
	rows, err := readDirectoryCSV(path)
	if err != nil {
		return nil, fmt.Errorf("read channels CSV: %w", err)
	}
	channels := make([]directoryChannel, 0, len(rows))
	seen := make(map[uint32]struct{})
	for index, row := range rows {
		if index == 0 && isDirectoryHeader(row, "channel_id", "name") {
			continue
		}
		if len(row) != 2 {
			return nil, fmt.Errorf("channels CSV row %d must contain channel_id,name", index+1)
		}
		channelID, err := parseDirectoryID(row[0])
		if err != nil {
			return nil, fmt.Errorf("channels CSV row %d: %w", index+1, err)
		}
		name, err := validateDirectoryName(row[1])
		if err != nil {
			return nil, fmt.Errorf("channels CSV row %d: %w", index+1, err)
		}
		if _, ok := seen[channelID]; ok {
			return nil, fmt.Errorf("channels CSV row %d: duplicate channel_id %d", index+1, channelID)
		}
		seen[channelID] = struct{}{}
		channels = append(channels, directoryChannel{ChannelID: channelID, Name: name})
		if len(channels) > directoryMaxChannels {
			return nil, fmt.Errorf("channels CSV exceeds maximum of %d entries", directoryMaxChannels)
		}
	}
	if len(channels) == 0 {
		return nil, fmt.Errorf("channels CSV has no channel entries")
	}
	sort.Slice(channels, func(i, j int) bool { return channels[i].ChannelID < channels[j].ChannelID })
	return channels, nil
}

func loadDirectorySpeakers(path string, channels []directoryChannel) ([]directorySpeaker, error) {
	rows, err := readDirectoryCSV(path)
	if err != nil {
		return nil, fmt.Errorf("read speakers CSV: %w", err)
	}
	channelIDs := make(map[uint32]struct{}, len(channels))
	for _, channel := range channels {
		channelIDs[channel.ChannelID] = struct{}{}
	}
	globalNames := make(map[uint32]string)
	channelNames := make(map[[2]uint32]string)
	for index, row := range rows {
		if index == 0 && isDirectoryHeader(row, "channel_id", "sender_id", "name") {
			continue
		}
		if len(row) != 3 {
			return nil, fmt.Errorf("speakers CSV row %d must contain channel_id,sender_id,name", index+1)
		}
		senderID, err := parseDirectoryID(row[1])
		if err != nil {
			return nil, fmt.Errorf("speakers CSV row %d: sender_id: %w", index+1, err)
		}
		name, err := validateDirectoryName(row[2])
		if err != nil {
			return nil, fmt.Errorf("speakers CSV row %d: %w", index+1, err)
		}
		if strings.EqualFold(strings.TrimSpace(row[0]), directoryAllChannels) {
			if _, exists := globalNames[senderID]; exists {
				return nil, fmt.Errorf("speakers CSV row %d: duplicate all/sender_id %s/%d", index+1, directoryAllChannels, senderID)
			}
			globalNames[senderID] = name
			continue
		}

		channelID, err := parseDirectoryID(row[0])
		if err != nil {
			return nil, fmt.Errorf("speakers CSV row %d: channel_id: %w", index+1, err)
		}
		if _, ok := channelIDs[channelID]; !ok {
			return nil, fmt.Errorf("speakers CSV row %d: unknown channel_id %d", index+1, channelID)
		}
		key := [2]uint32{channelID, senderID}
		if _, exists := channelNames[key]; exists {
			return nil, fmt.Errorf("speakers CSV row %d: duplicate channel_id/sender_id %d/%d", index+1, channelID, senderID)
		}
		channelNames[key] = name
	}

	speakers := make([]directorySpeaker, 0, len(channelNames)+len(globalNames)*len(channels))
	for _, channel := range channels {
		for senderID, name := range globalNames {
			key := [2]uint32{channel.ChannelID, senderID}
			if _, overridden := channelNames[key]; overridden {
				continue
			}
			speakers = append(speakers, directorySpeaker{ChannelID: channel.ChannelID, SenderID: senderID, Name: name})
		}
	}
	for key, name := range channelNames {
		speakers = append(speakers, directorySpeaker{ChannelID: key[0], SenderID: key[1], Name: name})
	}
	if len(speakers) > directoryMaxSpeakers {
		return nil, fmt.Errorf("speakers CSV exceeds maximum of %d entries", directoryMaxSpeakers)
	}
	sort.Slice(speakers, func(i, j int) bool {
		if speakers[i].ChannelID != speakers[j].ChannelID {
			return speakers[i].ChannelID < speakers[j].ChannelID
		}
		return speakers[i].SenderID < speakers[j].SenderID
	})
	return speakers, nil
}

func readDirectoryCSV(path string) ([][]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := csv.NewReader(bufio.NewReader(file))
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = true
	reader.Comment = '#'
	var rows [][]string
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		for index := range row {
			row[index] = strings.TrimSpace(row[index])
			if len(rows) == 0 && index == 0 {
				row[index] = strings.TrimPrefix(row[index], "\ufeff")
			}
		}
		empty := true
		for _, value := range row {
			if value != "" {
				empty = false
				break
			}
		}
		if !empty {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func isDirectoryHeader(row []string, columns ...string) bool {
	if len(row) != len(columns) {
		return false
	}
	for index, column := range columns {
		if strings.EqualFold(strings.TrimSpace(row[index]), column) {
			continue
		}
		return false
	}
	return true
}

func parseDirectoryID(value string) (uint32, error) {
	parsed, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || parsed == 0 || parsed > math.MaxUint32 {
		return 0, fmt.Errorf("ID must be an integer between 1 and %d", uint64(math.MaxUint32))
	}
	return uint32(parsed), nil
}

func validateDirectoryName(value string) (string, error) {
	name := strings.TrimSpace(value)
	if name == "" {
		return "", fmt.Errorf("name must not be empty")
	}
	if !utf8.ValidString(name) || strings.ContainsAny(name, "\r\n\x00") {
		return "", fmt.Errorf("name contains invalid characters")
	}
	if utf8.RuneCountInString(name) > directoryMaxNameRunes {
		return "", fmt.Errorf("name exceeds %d characters", directoryMaxNameRunes)
	}
	return name, nil
}

func loadDirectoryPSK(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read directory PSK file: %w", err)
	}
	encoded := strings.TrimSpace(string(raw))
	psk, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		psk, err = base64.URLEncoding.DecodeString(encoded)
	}
	if err != nil || len(psk) != directoryPSKBytes {
		return nil, fmt.Errorf("directory PSK file must contain one base64url-encoded %d-byte key", directoryPSKBytes)
	}
	return psk, nil
}

func validateDirectoryKeyID(keyID string) error {
	if keyID == "" || len(keyID) > directoryMaxKeyIDBytes {
		return fmt.Errorf("directory key ID must be 1 to %d ASCII characters", directoryMaxKeyIDBytes)
	}
	for _, value := range []byte(keyID) {
		if (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '-' || value == '_' || value == '.' {
			continue
		}
		return fmt.Errorf("directory key ID contains unsupported characters")
	}
	return nil
}

func validateDirectoryInstanceID(instanceID string) error {
	decoded, err := base64.RawURLEncoding.DecodeString(instanceID)
	if err != nil || len(decoded) != directoryEpochBytes {
		return fmt.Errorf("invalid directory client instance ID")
	}
	return nil
}

func deriveDirectoryKey(psk, epoch []byte) []byte {
	mac := hmac.New(sha256.New, psk)
	_, _ = mac.Write([]byte(directoryKeyDerivationLabel))
	_, _ = mac.Write(epoch)
	return mac.Sum(nil)
}

func directoryNonce(sequence uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:4], []byte{'I', 'D', 'P', '1'})
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func directoryEnvelopeAAD(envelope directoryEnvelope, epoch []byte) ([]byte, error) {
	if len(epoch) != directoryEpochBytes {
		return nil, fmt.Errorf("invalid directory epoch")
	}
	if err := validateDirectoryKeyID(envelope.KeyID); err != nil {
		return nil, err
	}
	if len(envelope.Type) > 32 {
		return nil, fmt.Errorf("invalid directory envelope type")
	}
	buffer := make([]byte, 0, 64+len(envelope.KeyID)+len(envelope.Type))
	buffer = append(buffer, []byte("IncomUdon Directory Envelope AAD v1\x00")...)
	buffer = append(buffer, byte(envelope.Version))
	buffer = append(buffer, byte(len(envelope.Type)))
	buffer = append(buffer, envelope.Type...)
	buffer = append(buffer, byte(len(envelope.KeyID)))
	buffer = append(buffer, envelope.KeyID...)
	buffer = append(buffer, epoch...)
	sequence := make([]byte, 8)
	binary.BigEndian.PutUint64(sequence, envelope.Sequence)
	buffer = append(buffer, sequence...)
	expiresAt := make([]byte, 8)
	binary.BigEndian.PutUint64(expiresAt, uint64(envelope.ExpiresAt))
	buffer = append(buffer, expiresAt...)
	return buffer, nil
}
func directoryDurationFromEnv(name string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil || parsed <= 0 {
		log.Printf("invalid %s=%q (using %s)", name, raw, fallback)
		return fallback
	}
	return parsed
}
