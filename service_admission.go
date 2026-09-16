package main

import (
	"bytes"
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
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	serviceGrantMaxBytes             = 768
	serviceChallengeTTL              = 30 * time.Second
	maxPendingServiceAdmissions      = 1024
	maximumServiceGrantLifetime      = 3600
	minimumServiceGrantLifetime      = 60
	maximumServiceAdmissionGraceSecs = 1800

	serviceDenyAdmissionRequired = 0x00
	serviceDenyInvalidGrant      = 0x01
	serviceDenyGrantExpired      = 0x02
	serviceDenyScopeMismatch     = 0x03
	serviceDenyPermissionDenied  = 0x04
	serviceDenyInvalidProof      = 0x05
	serviceDenyDisabled          = 0x06
	serviceDenyRevoked           = 0x07
)

type serviceAdmissionMode string

const (
	serviceAdmissionOff     serviceAdmissionMode = "off"
	serviceAdmissionEnabled serviceAdmissionMode = "enabled"
)

type serviceSigningKeyStore map[string]ed25519.PublicKey

type serviceAdmissionState struct {
	mu              sync.Mutex
	mode            serviceAdmissionMode
	issuer          string
	audience        string
	keys            serviceSigningKeyStore
	pending         map[serviceAdmissionKey]servicePendingAdmission
	verified        map[serviceAdmissionKey]serviceAdmission
	failed          map[serviceAdmissionKey]serviceAdmissionFailure
	revoked         map[[sha256.Size]byte]time.Time
	revokedServices map[string]time.Time
}

type serviceAdmissionKey struct {
	channelID uint32
	senderID  uint32
	sessionID uint32
	address   string
}

type serviceAdmission struct {
	serviceID    string
	role         string
	permissions  uint8
	priority     uint8
	grantExpires time.Time
	grace        time.Duration
	grantHash    [sha256.Size]byte
	grantIDHash  [16]byte
	actorIDHash  [16]byte
}

type servicePendingAdmission struct {
	admission serviceAdmission
	publicKey ed25519.PublicKey
	challenge [32]byte
	expiresAt time.Time
}

type serviceAdmissionFailure struct {
	reason    uint8
	expiresAt time.Time
}

type serviceGrantHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	Type      string `json:"typ"`
}

type serviceGrantClaims struct {
	Issuer       string  `json:"iss"`
	Audience     string  `json:"aud"`
	ServiceID    string  `json:"svc"`
	GrantID      string  `json:"jti"`
	IssuedAt     int64   `json:"iat"`
	ExpiresAt    int64   `json:"exp"`
	ChannelID    uint32  `json:"ch"`
	SenderID     uint32  `json:"sid"`
	Role         string  `json:"role"`
	Permissions  uint8   `json:"perm"`
	Priority     *uint8  `json:"pri"`
	GraceSeconds *uint16 `json:"grace_seconds"`
	Confirmation struct {
		JWKThumbprint string `json:"jkt"`
	} `json:"cnf"`
}

var serviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
var serviceGrantIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

func parseServiceAdmissionMode(value string) (serviceAdmissionMode, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(serviceAdmissionOff):
		return serviceAdmissionOff, nil
	case string(serviceAdmissionEnabled):
		return serviceAdmissionEnabled, nil
	default:
		return "", errors.New("must be off or enabled")
	}
}

func loadServiceSigningKeys(path string) (serviceSigningKeyStore, error) {
	keys := make(serviceSigningKeyStore)
	if strings.TrimSpace(path) == "" {
		return keys, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open service signing key file: %w", err)
	}
	defer file.Close()
	records, err := csv.NewReader(file).ReadAll()
	if err != nil {
		return nil, fmt.Errorf("read service signing key CSV: %w", err)
	}
	for index, record := range records {
		if len(record) == 0 || (len(record) == 1 && strings.TrimSpace(record[0]) == "") {
			continue
		}
		if len(record) != 2 {
			return nil, fmt.Errorf("service signing key CSV row %d must contain kid,ed25519_public_key_base64", index+1)
		}
		if index == 0 && strings.EqualFold(strings.TrimSpace(record[0]), "kid") {
			continue
		}
		keyID := strings.TrimSpace(record[0])
		if keyID == "" || len(keyID) > 128 {
			return nil, fmt.Errorf("service signing key CSV row %d kid is invalid", index+1)
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(record[1]))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			if err == nil {
				err = fmt.Errorf("must decode to %d bytes", ed25519.PublicKeySize)
			}
			return nil, fmt.Errorf("service signing key CSV row %d public key: %w", index+1, err)
		}
		if _, exists := keys[keyID]; exists {
			return nil, fmt.Errorf("duplicate service signing key ID %q", keyID)
		}
		keys[keyID] = ed25519.PublicKey(append([]byte(nil), decoded...))
	}
	return keys, nil
}

func newServiceAdmissionState(mode serviceAdmissionMode, issuer string, audience string, keys serviceSigningKeyStore) (*serviceAdmissionState, error) {
	if mode == serviceAdmissionOff {
		return nil, nil
	}
	if mode != serviceAdmissionEnabled {
		return nil, fmt.Errorf("unsupported service admission mode %q", mode)
	}
	if strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" {
		return nil, errors.New("managed service admission requires a configured issuer and audience")
	}
	if len(keys) == 0 {
		return nil, errors.New("managed service admission requires at least one Ed25519 signing key")
	}
	return &serviceAdmissionState{
		mode: mode, issuer: issuer, audience: audience, keys: keys,
		pending:         make(map[serviceAdmissionKey]servicePendingAdmission),
		verified:        make(map[serviceAdmissionKey]serviceAdmission),
		failed:          make(map[serviceAdmissionKey]serviceAdmissionFailure),
		revoked:         make(map[[sha256.Size]byte]time.Time),
		revokedServices: make(map[string]time.Time),
	}, nil
}

func serviceKeyForPacket(pkt parsedPacket, addr *net.UDPAddr, sessionID uint32) serviceAdmissionKey {
	return serviceAdmissionKey{channelID: pkt.Header.ChannelId, senderID: pkt.Header.SenderId, sessionID: sessionID, address: peerMapKey(addr)}
}

func (admission serviceAdmission) expiryDeadline() time.Time {
	if admission.permissions == identityPermissionListen && admission.grace > 0 {
		return admission.grantExpires.Add(admission.grace)
	}
	return admission.grantExpires
}

func (admission serviceAdmission) grantCurrent(now time.Time) bool {
	return admission.grantExpires.After(now)
}

func (admission serviceAdmission) membershipCurrent(now time.Time) bool {
	return admission.expiryDeadline().After(now)
}

func (a *serviceAdmissionState) validateGrant(grant string, publicKey ed25519.PublicKey, channelID uint32, senderID uint32, now time.Time) (serviceAdmission, uint8) {
	if len(grant) == 0 || len(grant) > serviceGrantMaxBytes || len(publicKey) != ed25519.PublicKeySize {
		return serviceAdmission{}, serviceDenyInvalidGrant
	}
	for _, value := range []byte(grant) {
		if value > 0x7f {
			return serviceAdmission{}, serviceDenyInvalidGrant
		}
	}
	segments := strings.Split(grant, ".")
	if len(segments) != 3 {
		return serviceAdmission{}, serviceDenyInvalidGrant
	}
	headerRaw, ok := strictBase64URL(segments[0])
	if !ok {
		return serviceAdmission{}, serviceDenyInvalidGrant
	}
	payloadRaw, ok := strictBase64URL(segments[1])
	if !ok {
		return serviceAdmission{}, serviceDenyInvalidGrant
	}
	signature, ok := strictBase64URL(segments[2])
	if !ok || len(signature) != ed25519.SignatureSize {
		return serviceAdmission{}, serviceDenyInvalidGrant
	}
	var header serviceGrantHeader
	var claims serviceGrantClaims
	if decodeStrictServiceJSON(headerRaw, &header) != nil || decodeStrictServiceJSON(payloadRaw, &claims) != nil {
		return serviceAdmission{}, serviceDenyInvalidGrant
	}
	issuerKey := a.keys[header.KeyID]
	if header.Algorithm != "EdDSA" || header.Type != "incomudon-service-admission+jwt" || len(issuerKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(issuerKey, []byte(segments[0]+"."+segments[1]), signature) {
		return serviceAdmission{}, serviceDenyInvalidGrant
	}
	lifetime := claims.ExpiresAt - claims.IssuedAt
	if claims.IssuedAt < 0 || claims.ExpiresAt <= claims.IssuedAt || lifetime < minimumServiceGrantLifetime || lifetime > maximumServiceGrantLifetime ||
		!time.Unix(claims.ExpiresAt, 0).After(now) || time.Unix(claims.IssuedAt, 0).After(now.Add(30*time.Second)) {
		return serviceAdmission{}, serviceDenyGrantExpired
	}
	if claims.Issuer != a.issuer || claims.Audience != a.audience || claims.ChannelID != channelID || claims.SenderID != senderID || claims.SenderID == 0 {
		return serviceAdmission{}, serviceDenyScopeMismatch
	}
	if !serviceIDPattern.MatchString(claims.ServiceID) || !serviceGrantIDPattern.MatchString(claims.GrantID) {
		return serviceAdmission{}, serviceDenyInvalidGrant
	}
	if claims.Permissions != 1 && claims.Permissions != 3 && claims.Permissions != 7 || claims.Permissions&identityPermissionListen == 0 {
		return serviceAdmission{}, serviceDenyPermissionDenied
	}
	if claims.Permissions == 7 && (claims.Priority == nil || *claims.Priority == 0) {
		return serviceAdmission{}, serviceDenyPermissionDenied
	}
	if claims.Permissions != 7 && claims.Priority != nil {
		return serviceAdmission{}, serviceDenyPermissionDenied
	}
	if (claims.Role == "recorder" || claims.Role == "observer") && claims.Permissions != 1 {
		return serviceAdmission{}, serviceDenyPermissionDenied
	}
	if claims.Role != "recorder" && claims.Role != "observer" && claims.Role != "automation" {
		return serviceAdmission{}, serviceDenyPermissionDenied
	}
	graceSeconds := uint16(0)
	if claims.GraceSeconds != nil {
		graceSeconds = *claims.GraceSeconds
	}
	if graceSeconds > maximumServiceAdmissionGraceSecs || (claims.Permissions != 1 && graceSeconds != 0) {
		return serviceAdmission{}, serviceDenyPermissionDenied
	}
	digest := sha256.Sum256(publicKey)
	if claims.Confirmation.JWKThumbprint == "" || subtle.ConstantTimeCompare([]byte(claims.Confirmation.JWKThumbprint), []byte(base64.RawURLEncoding.EncodeToString(digest[:]))) != 1 {
		return serviceAdmission{}, serviceDenyScopeMismatch
	}
	grantHash := sha256.Sum256([]byte(grant))
	grantIDHash := sha256.Sum256([]byte(claims.GrantID))
	serviceHash := sha256.Sum256([]byte(claims.ServiceID))
	priority := uint8(0)
	if claims.Priority != nil {
		priority = *claims.Priority
	}
	return serviceAdmission{
		serviceID: claims.ServiceID, role: claims.Role, permissions: claims.Permissions, priority: priority,
		grantExpires: time.Unix(claims.ExpiresAt, 0), grace: time.Duration(graceSeconds) * time.Second,
		grantHash: grantHash, grantIDHash: [16]byte(grantIDHash[:16]), actorIDHash: [16]byte(serviceHash[:16]),
	}, 0
}

// decodeStrictServiceJSON enforces the grant schema's closed JSON objects.
func decodeStrictServiceJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON value must contain one object")
	}
	return nil
}

func (a *serviceAdmissionState) cleanupLocked(now time.Time) {
	for key, pending := range a.pending {
		if !pending.expiresAt.After(now) {
			delete(a.pending, key)
		}
	}
	for key, admission := range a.verified {
		if !admission.grantCurrent(now) {
			delete(a.verified, key)
		}
	}
	for key, failure := range a.failed {
		if !failure.expiresAt.After(now) {
			delete(a.failed, key)
		}
	}
	for grantHash, expiry := range a.revoked {
		if !expiry.After(now) {
			delete(a.revoked, grantHash)
		}
	}
	for serviceID, expiry := range a.revokedServices {
		if !expiry.After(now) {
			delete(a.revokedServices, serviceID)
		}
	}
}

func (a *serviceAdmissionState) begin(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta, now time.Time) ([]byte, uint8) {
	if a == nil || len(pkt.Payload) < 2+ed25519.PublicKeySize {
		return nil, serviceDenyDisabled
	}
	grantLength := int(binary.BigEndian.Uint16(pkt.Payload[:2]))
	if grantLength < 1 || grantLength > serviceGrantMaxBytes || len(pkt.Payload) != 2+grantLength+ed25519.PublicKeySize {
		return nil, serviceDenyInvalidGrant
	}
	grant := string(pkt.Payload[2 : 2+grantLength])
	publicKey := ed25519.PublicKey(append([]byte(nil), pkt.Payload[2+grantLength:]...))
	admission, denyReason := a.validateGrant(grant, publicKey, pkt.Header.ChannelId, pkt.Header.SenderId, now)
	key := serviceKeyForPacket(pkt, addr, meta.sessionID)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	if denyReason == 0 {
		if _, revoked := a.revoked[admission.grantHash]; revoked || a.revokedServices[admission.serviceID].After(now) {
			denyReason = serviceDenyRevoked
		}
	}
	if denyReason != 0 {
		a.failed[key] = serviceAdmissionFailure{reason: denyReason, expiresAt: now.Add(serviceChallengeTTL)}
		return nil, denyReason
	}
	if len(a.pending) >= maxPendingServiceAdmissions {
		a.failed[key] = serviceAdmissionFailure{reason: serviceDenyInvalidGrant, expiresAt: now.Add(serviceChallengeTTL)}
		return nil, serviceDenyInvalidGrant
	}
	var challenge [32]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, serviceDenyInvalidGrant
	}
	challengeExpiry := now.Add(serviceChallengeTTL)
	if admission.grantExpires.Before(challengeExpiry) {
		challengeExpiry = admission.grantExpires
	}
	a.pending[key] = servicePendingAdmission{admission: admission, publicKey: publicKey, challenge: challenge, expiresAt: challengeExpiry}
	delete(a.failed, key)
	payload := make([]byte, 4+len(challenge))
	binary.BigEndian.PutUint32(payload[:4], uint32(challengeExpiry.Unix()))
	copy(payload[4:], challenge[:])
	return payload, 0
}

func serviceProofMessage(challenge [32]byte, channelID uint32, senderID uint32, grantHash [sha256.Size]byte) [sha256.Size]byte {
	input := make([]byte, 0, 32+len("incomudon-managed-service-admission-v1\x00")+8+sha256.Size)
	input = append(input, []byte("incomudon-managed-service-admission-v1\x00")...)
	input = append(input, challenge[:]...)
	fields := make([]byte, 8)
	binary.BigEndian.PutUint32(fields[:4], channelID)
	binary.BigEndian.PutUint32(fields[4:], senderID)
	input = append(input, fields...)
	input = append(input, grantHash[:]...)
	return sha256.Sum256(input)
}

func (a *serviceAdmissionState) proof(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta, now time.Time) uint8 {
	if a == nil || len(pkt.Payload) != ed25519.SignatureSize {
		return serviceDenyInvalidProof
	}
	key := serviceKeyForPacket(pkt, addr, meta.sessionID)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	pending, found := a.pending[key]
	if !found || !pending.expiresAt.After(now) {
		a.failed[key] = serviceAdmissionFailure{reason: serviceDenyInvalidProof, expiresAt: now.Add(serviceChallengeTTL)}
		return serviceDenyInvalidProof
	}
	if _, revoked := a.revoked[pending.admission.grantHash]; revoked || a.revokedServices[pending.admission.serviceID].After(now) {
		delete(a.pending, key)
		a.failed[key] = serviceAdmissionFailure{reason: serviceDenyRevoked, expiresAt: now.Add(serviceChallengeTTL)}
		return serviceDenyRevoked
	}
	message := serviceProofMessage(pending.challenge, pkt.Header.ChannelId, pkt.Header.SenderId, pending.admission.grantHash)
	if !ed25519.Verify(pending.publicKey, message[:], pkt.Payload) {
		delete(a.pending, key)
		a.failed[key] = serviceAdmissionFailure{reason: serviceDenyInvalidProof, expiresAt: now.Add(serviceChallengeTTL)}
		return serviceDenyInvalidProof
	}
	delete(a.pending, key)
	delete(a.failed, key)
	a.verified[key] = pending.admission
	return 0
}

func (a *serviceAdmissionState) takeVerifiedAdmission(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta, now time.Time) (serviceAdmission, bool) {
	if a == nil {
		return serviceAdmission{}, false
	}
	key := serviceKeyForPacket(pkt, addr, meta.sessionID)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	admission, found := a.verified[key]
	if !found || !admission.grantCurrent(now) {
		return serviceAdmission{}, false
	}
	delete(a.verified, key)
	return admission, true
}

func (a *serviceAdmissionState) admissionForJoin(pkt parsedPacket, addr *net.UDPAddr, meta controlAuthMeta, now time.Time) (serviceAdmission, bool, uint8) {
	if a == nil {
		return serviceAdmission{}, true, 0
	}
	key := serviceKeyForPacket(pkt, addr, meta.sessionID)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	if admission, found := a.verified[key]; found && admission.grantCurrent(now) {
		delete(a.verified, key)
		return admission, true, 0
	}
	if failure, found := a.failed[key]; found {
		return serviceAdmission{}, false, failure.reason
	}
	if _, pending := a.pending[key]; pending {
		return serviceAdmission{}, false, serviceDenyInvalidProof
	}
	return serviceAdmission{}, true, 0
}

func (a *serviceAdmissionState) revoke(grantHash *[sha256.Size]byte, serviceID string, now time.Time) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cleanupLocked(now)
	if grantHash != nil {
		a.revoked[*grantHash] = now.Add(maximumServiceAdmissionGraceSecs * time.Second)
	}
	if serviceID != "" {
		a.revokedServices[serviceID] = now.Add(maximumServiceGrantLifetime * time.Second)
	}
	for key, pending := range a.pending {
		if (grantHash != nil && pending.admission.grantHash == *grantHash) || (serviceID != "" && pending.admission.serviceID == serviceID) {
			delete(a.pending, key)
		}
	}
	for key, admission := range a.verified {
		if (grantHash != nil && admission.grantHash == *grantHash) || (serviceID != "" && admission.serviceID == serviceID) {
			delete(a.verified, key)
		}
	}
}
