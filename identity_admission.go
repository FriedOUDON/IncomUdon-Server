package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	identityTicketMaxBytes             = 768
	identityChallengeTTL               = 30 * time.Second
	identityPermissionListen     uint8 = 1 << 0
	identityPermissionTalk       uint8 = 1 << 1
	identityPermissionInterrupt  uint8 = 1 << 2
	maxPendingIdentityAdmissions       = 1024

	identityDenyAdmissionRequired = 0x00
	identityDenyInvalidTicket     = 0x01
	identityDenyTicketExpired     = 0x02
	identityDenyScopeMismatch     = 0x03
	identityDenyPermissionDenied  = 0x04
	identityDenyInvalidProof      = 0x05
)

type identityAdmissionMode string

const (
	identityAdmissionOff      identityAdmissionMode = "off"
	identityAdmissionOptional identityAdmissionMode = "optional"
	identityAdmissionRequired identityAdmissionMode = "required"
)

type identitySigningKeyStore map[string]ed25519.PublicKey

type identityAdmissionState struct {
	mu       sync.Mutex
	mode     identityAdmissionMode
	issuer   string
	audience string
	keys     identitySigningKeyStore
	pending  map[identityAdmissionKey]identityPendingAdmission
	verified map[identityAdmissionKey]identityAdmission
	failed   map[identityAdmissionKey]identityAdmissionFailure
}

type identityAdmissionKey struct {
	channelID uint32
	senderID  uint32
	sessionID uint32
	address   string
}

type identityAdmission struct {
	permissions uint8
	priority    uint8
	expiresAt   time.Time
	ticketHash  [sha256.Size]byte
	actorIDHash [16]byte
}

type identityPendingAdmission struct {
	admission identityAdmission
	publicKey ed25519.PublicKey
	challenge [32]byte
	expiresAt time.Time
}

type identityAdmissionFailure struct {
	reason    uint8
	expiresAt time.Time
}

type identityTicketHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type identityTicketClaims struct {
	Issuer       string `json:"iss"`
	Audience     string `json:"aud"`
	Subject      string `json:"sub"`
	TicketID     string `json:"jti"`
	IssuedAt     int64  `json:"iat"`
	ExpiresAt    int64  `json:"exp"`
	ChannelID    uint32 `json:"ch"`
	SenderID     uint32 `json:"sid"`
	Permissions  uint8  `json:"perm"`
	Priority     *uint8 `json:"pri"`
	Confirmation struct {
		JWKThumbprint string `json:"jkt"`
	} `json:"cnf"`
}

func parseIdentityAdmissionMode(value string) (identityAdmissionMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(identityAdmissionOff):
		return identityAdmissionOff, nil
	case string(identityAdmissionOptional):
		return identityAdmissionOptional, nil
	case string(identityAdmissionRequired):
		return identityAdmissionRequired, nil
	default:
		return "", errors.New("must be off, optional, or required")
	}
}

func loadIdentitySigningKeys(path string) (identitySigningKeyStore, error) {
	keys := make(identitySigningKeyStore)
	if strings.TrimSpace(path) == "" {
		return keys, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open identity signing key file: %w", err)
	}
	defer file.Close()

	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read identity signing key CSV: %w", err)
	}
	for index, record := range records {
		if len(record) == 0 || (len(record) == 1 && strings.TrimSpace(record[0]) == "") {
			continue
		}
		if len(record) != 2 {
			return nil, fmt.Errorf("identity signing key CSV row %d must contain kid,ed25519_public_key_base64", index+1)
		}
		if index == 0 && strings.EqualFold(strings.TrimSpace(record[0]), "kid") {
			continue
		}
		keyID := strings.TrimSpace(record[0])
		if keyID == "" || len(keyID) > 128 {
			return nil, fmt.Errorf("identity signing key CSV row %d kid is invalid", index+1)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(record[1]))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			if err == nil {
				err = fmt.Errorf("must decode to %d bytes", ed25519.PublicKeySize)
			}
			return nil, fmt.Errorf("identity signing key CSV row %d public key: %w", index+1, err)
		}
		if _, exists := keys[keyID]; exists {
			return nil, fmt.Errorf("duplicate identity signing key ID %q", keyID)
		}
		keys[keyID] = ed25519.PublicKey(append([]byte(nil), decoded...))
	}
	return keys, nil
}

func newIdentityAdmissionState(mode identityAdmissionMode, issuer string, audience string, keys identitySigningKeyStore) (*identityAdmissionState, error) {
	if mode == identityAdmissionOff {
		return nil, nil
	}
	if mode != identityAdmissionOptional && mode != identityAdmissionRequired {
		return nil, fmt.Errorf("unsupported identity admission mode %q", mode)
	}
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" {
		return nil, errors.New("identity admission requires a configured issuer and audience")
	}
	if len(keys) == 0 {
		return nil, errors.New("identity admission requires at least one Ed25519 signing key")
	}
	return &identityAdmissionState{
		mode:     mode,
		issuer:   issuer,
		audience: audience,
		keys:     keys,
		pending:  make(map[identityAdmissionKey]identityPendingAdmission),
		verified: make(map[identityAdmissionKey]identityAdmission),
		failed:   make(map[identityAdmissionKey]identityAdmissionFailure),
	}, nil
}

func identityKeyForPacket(pkt parsedPacket, addr *net.UDPAddr, sessionID uint32) identityAdmissionKey {
	return identityAdmissionKey{
		channelID: pkt.Header.ChannelId,
		senderID:  pkt.Header.SenderId,
		sessionID: sessionID,
		address:   peerMapKey(addr),
	}
}

func strictBase64URL(value string) ([]byte, bool) {
	if value == "" || strings.Contains(value, "=") {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	return decoded, true
}

func (a *identityAdmissionState) validateTicket(ticket string, publicKey ed25519.PublicKey, channelID uint32, senderID uint32, now time.Time) (identityAdmission, uint8) {
	if len(ticket) == 0 || len(ticket) > identityTicketMaxBytes || len(publicKey) != ed25519.PublicKeySize {
		return identityAdmission{}, identityDenyInvalidTicket
	}
	for _, value := range []byte(ticket) {
		if value > 0x7f {
			return identityAdmission{}, identityDenyInvalidTicket
		}
	}
	segments := strings.Split(ticket, ".")
	if len(segments) != 3 {
		return identityAdmission{}, identityDenyInvalidTicket
	}
	headerRaw, ok := strictBase64URL(segments[0])
	if !ok {
		return identityAdmission{}, identityDenyInvalidTicket
	}
	payloadRaw, ok := strictBase64URL(segments[1])
	if !ok {
		return identityAdmission{}, identityDenyInvalidTicket
	}
	signature, ok := strictBase64URL(segments[2])
	if !ok || len(signature) != ed25519.SignatureSize {
		return identityAdmission{}, identityDenyInvalidTicket
	}
	var header identityTicketHeader
	var claims identityTicketClaims
	if json.Unmarshal(headerRaw, &header) != nil || json.Unmarshal(payloadRaw, &claims) != nil {
		return identityAdmission{}, identityDenyInvalidTicket
	}
	issuerKey := a.keys[header.KeyID]
	if header.Algorithm != "EdDSA" || header.Type != "incomudon-admission+jwt" || len(issuerKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(issuerKey, []byte(segments[0]+"."+segments[1]), signature) {
		return identityAdmission{}, identityDenyInvalidTicket
	}
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt || claims.ExpiresAt-claims.IssuedAt > 300 ||
		!time.Unix(claims.ExpiresAt, 0).After(now) || time.Unix(claims.IssuedAt, 0).After(now.Add(30*time.Second)) {
		return identityAdmission{}, identityDenyTicketExpired
	}
	if claims.Issuer != a.issuer || claims.Audience != a.audience || claims.ChannelID != channelID || claims.SenderID != senderID || claims.SenderID == 0 {
		return identityAdmission{}, identityDenyScopeMismatch
	}
	if claims.Subject == "" || claims.TicketID == "" || claims.Permissions&^uint8(0x07) != 0 || claims.Permissions&identityPermissionListen == 0 {
		return identityAdmission{}, identityDenyPermissionDenied
	}
	if claims.Permissions&identityPermissionInterrupt != 0 &&
		(claims.Permissions&identityPermissionTalk == 0 || claims.Priority == nil || *claims.Priority == 0) {
		return identityAdmission{}, identityDenyPermissionDenied
	}
	if claims.Permissions&identityPermissionInterrupt == 0 && claims.Priority != nil {
		return identityAdmission{}, identityDenyPermissionDenied
	}
	digest := sha256.Sum256(publicKey)
	if claims.Confirmation.JWKThumbprint == "" || subtle.ConstantTimeCompare([]byte(claims.Confirmation.JWKThumbprint), []byte(base64.RawURLEncoding.EncodeToString(digest[:]))) != 1 {
		return identityAdmission{}, identityDenyScopeMismatch
	}
	ticketHash := sha256.Sum256([]byte(ticket))
	subjectHash := sha256.Sum256([]byte(claims.Subject))
	priority := uint8(0)
	if claims.Priority != nil {
		priority = *claims.Priority
	}
	return identityAdmission{
		permissions: claims.Permissions,
		priority:    priority,
		expiresAt:   time.Unix(claims.ExpiresAt, 0),
		ticketHash:  ticketHash,
		actorIDHash: [16]byte(subjectHash[:16]),
	}, 0
}

func (a *identityAdmissionState) cleanupLocked(now time.Time) {
	for key, pending := range a.pending {
		if !pending.expiresAt.After(now) {
			delete(a.pending, key)
		}
	}
	for key, admission := range a.verified {
		if !admission.expiresAt.After(now) {
			delete(a.verified, key)
		}
	}
	for key, failure := range a.failed {
		if !failure.expiresAt.After(now) {
			delete(a.failed, key)
		}
	}
}

func (a *identityAdmissionState) begin(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta, now time.Time) ([]byte, uint8) {
	if a == nil || len(pkt.Payload) < 2+ed25519.PublicKeySize {
		return nil, identityDenyInvalidTicket
	}
	ticketLength := int(binary.BigEndian.Uint16(pkt.Payload[:2]))
	if ticketLength < 1 || ticketLength > identityTicketMaxBytes || len(pkt.Payload) != 2+ticketLength+ed25519.PublicKeySize {
		return nil, identityDenyInvalidTicket
	}
	ticket := string(pkt.Payload[2 : 2+ticketLength])
	publicKey := ed25519.PublicKey(append([]byte(nil), pkt.Payload[2+ticketLength:]...))
	admission, denyReason := a.validateTicket(ticket, publicKey, pkt.Header.ChannelId, pkt.Header.SenderId, now)
	key := identityKeyForPacket(pkt, addr, meta.sessionID)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	if denyReason != 0 {
		a.failed[key] = identityAdmissionFailure{reason: denyReason, expiresAt: now.Add(identityChallengeTTL)}
		return nil, denyReason
	}
	if len(a.pending) >= maxPendingIdentityAdmissions {
		a.failed[key] = identityAdmissionFailure{reason: identityDenyInvalidTicket, expiresAt: now.Add(identityChallengeTTL)}
		return nil, identityDenyInvalidTicket
	}
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, identityDenyInvalidTicket
	}
	challengeExpiry := now.Add(identityChallengeTTL)
	if admission.expiresAt.Before(challengeExpiry) {
		challengeExpiry = admission.expiresAt
	}
	a.pending[key] = identityPendingAdmission{admission: admission, publicKey: publicKey, challenge: challenge, expiresAt: challengeExpiry}
	delete(a.failed, key)
	payload := make([]byte, 4+len(challenge))
	binary.BigEndian.PutUint32(payload[:4], uint32(challengeExpiry.Unix()))
	copy(payload[4:], challenge[:])
	return payload, 0
}

func identityProofMessage(challenge [32]byte, channelID uint32, senderID uint32, ticketHash [sha256.Size]byte) [sha256.Size]byte {
	input := make([]byte, 0, 32+len("incomudon-identity-admission-v1\x00")+8+sha256.Size)
	input = append(input, []byte("incomudon-identity-admission-v1\x00")...)
	input = append(input, challenge[:]...)
	fields := make([]byte, 8)
	binary.BigEndian.PutUint32(fields[:4], channelID)
	binary.BigEndian.PutUint32(fields[4:], senderID)
	input = append(input, fields...)
	input = append(input, ticketHash[:]...)
	return sha256.Sum256(input)
}

func (a *identityAdmissionState) proof(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta, now time.Time) uint8 {
	if a == nil || len(pkt.Payload) != ed25519.SignatureSize {
		return identityDenyInvalidProof
	}
	key := identityKeyForPacket(pkt, addr, meta.sessionID)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	pending, found := a.pending[key]
	if !found || !pending.expiresAt.After(now) {
		a.failed[key] = identityAdmissionFailure{reason: identityDenyInvalidProof, expiresAt: now.Add(identityChallengeTTL)}
		return identityDenyInvalidProof
	}
	message := identityProofMessage(pending.challenge, pkt.Header.ChannelId, pkt.Header.SenderId, pending.admission.ticketHash)
	if !ed25519.Verify(pending.publicKey, message[:], pkt.Payload) {
		delete(a.pending, key)
		a.failed[key] = identityAdmissionFailure{reason: identityDenyInvalidProof, expiresAt: now.Add(identityChallengeTTL)}
		return identityDenyInvalidProof
	}
	delete(a.pending, key)
	delete(a.failed, key)
	a.verified[key] = pending.admission
	return 0
}

func (a *identityAdmissionState) takeVerifiedAdmission(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta, now time.Time) (identityAdmission, bool) {
	if a == nil {
		return identityAdmission{}, false
	}
	key := identityKeyForPacket(pkt, addr, meta.sessionID)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	admission, found := a.verified[key]
	if !found || !admission.expiresAt.After(now) {
		return identityAdmission{}, false
	}
	delete(a.verified, key)
	return admission, true
}

func (a *identityAdmissionState) admissionForJoin(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta, now time.Time) (identityAdmission, bool, uint8) {
	if a == nil {
		return identityAdmission{}, true, 0
	}
	key := identityKeyForPacket(pkt, addr, meta.sessionID)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	if admission, found := a.verified[key]; found && admission.expiresAt.After(now) {
		delete(a.verified, key)
		return admission, true, 0
	}
	if failure, found := a.failed[key]; found {
		return identityAdmission{}, false, failure.reason
	}
	if _, pending := a.pending[key]; pending {
		return identityAdmission{}, false, identityDenyInvalidProof
	}
	if a.mode == identityAdmissionRequired {
		return identityAdmission{}, false, identityDenyAdmissionRequired
	}
	return identityAdmission{}, true, 0
}

func (a *identityAdmissionState) isRequired() bool {
	return a != nil && a.mode == identityAdmissionRequired
}

func (a *identityAdmissionState) isEnabled() bool {
	return a != nil && a.mode != identityAdmissionOff
}

func admissionAllowsTalk(admission *identityAdmission, now time.Time, required bool) bool {
	if admission == nil {
		return !required
	}
	return admission.expiresAt.After(now) && admission.permissions&identityPermissionTalk != 0
}

func admissionAllowsInterrupt(admission *identityAdmission, now time.Time) bool {
	return admission != nil && admission.expiresAt.After(now) &&
		admission.permissions&identityPermissionTalk != 0 &&
		admission.permissions&identityPermissionInterrupt != 0 && admission.priority != 0
}
