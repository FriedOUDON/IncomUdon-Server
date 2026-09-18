package main

import (
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
	"errors"
	"fmt"
	"io"
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
	directoryV3Version                     = 3
	directoryTransportDedicated     uint8  = 0
	directoryTransportMedia         uint8  = 1
	directoryCarrierVersion                = 1
	directoryMaxChannels                   = 256
	directoryMaxSpeakers                   = 4096
	directoryMaxParticipants               = 128
	directoryMaxFragments                  = 32
	directoryMaxSnapshotPages              = 256
	directoryReplayWindowSize              = 64
	directoryMaxReplayDomains              = 1024
	directoryMaxRegistrations              = 64
	directoryRegistrationTTL               = 90 * time.Second
	directoryClientLifetime                = 30 * time.Second
	directoryDefaultPublishInterval        = 30 * time.Second
	directoryDefaultFreshnessTTL           = 90 * time.Second
	directoryMaxFreshnessTTL               = 90 * time.Second
	directoryMaxJSONInteger         uint64 = 9007199254740991
)

var directoryCarrierMagic = []byte("IDP3")
var directoryAADPrefix = []byte("IncomUdon Directory Envelope AAD v3\x00")
var directoryChannelInfo = []byte("incomudon-directory-channel-v3")
var directoryC2RInfo = []byte("incomudon-directory-channel-v3 client-to-relay")
var directoryR2CInfo = []byte("incomudon-directory-channel-v3 relay-to-client")
var directoryEnvelopeInfo = []byte("incomudon-directory-envelope-v3")

type directoryTransport string

const (
	directoryTransportMediaPort    directoryTransport = "media-port"
	directoryTransportDedicatedUDP directoryTransport = "dedicated-udp"
)

func parseDirectoryTransport(value string) (directoryTransport, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(directoryTransportMediaPort):
		return directoryTransportMediaPort, nil
	case string(directoryTransportDedicatedUDP):
		return directoryTransportDedicatedUDP, nil
	default:
		return "", errors.New("must be media-port or dedicated-udp")
	}
}

func (t directoryTransport) binding() uint8 {
	if t == directoryTransportMediaPort {
		return directoryTransportMedia
	}
	return directoryTransportDedicated
}

type directoryKeyMaterial struct {
	channel [32]byte
	c2r     [32]byte
	r2c     [32]byte
}

type directoryKeyStore map[uint32]directoryKeyMaterial

func newDirectoryKeyMaterial(channelKey []byte) (directoryKeyMaterial, error) {
	if len(channelKey) != 32 {
		return directoryKeyMaterial{}, errors.New("directory_channel_key must be 32 bytes")
	}
	material := directoryKeyMaterial{}
	copy(material.channel[:], channelKey)
	c2r, err := hkdfSHA256(material.channel[:], nil, directoryC2RInfo, 32)
	if err != nil {
		return directoryKeyMaterial{}, err
	}
	r2c, err := hkdfSHA256(material.channel[:], nil, directoryR2CInfo, 32)
	if err != nil {
		return directoryKeyMaterial{}, err
	}
	copy(material.c2r[:], c2r)
	copy(material.r2c[:], r2c)
	return material, nil
}

// hkdfSHA256 is the RFC 5869 extract-and-expand construction used by the
// Directory v3 derivation. All current calls request a single 32-byte block.
func hkdfSHA256(ikm, salt, info []byte, length int) ([]byte, error) {
	if length < 0 || length > 255*sha256.Size {
		return nil, errors.New("invalid HKDF output length")
	}
	if salt == nil {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(ikm)
	prk := extract.Sum(nil)

	output := make([]byte, 0, length)
	previous := []byte(nil)
	for counter := byte(1); len(output) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		remaining := length - len(output)
		if remaining > len(previous) {
			remaining = len(previous)
		}
		output = append(output, previous[:remaining]...)
	}
	return output, nil
}

func loadDirectoryKeyStore(path string) (directoryKeyStore, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("directory key file is required")
	}
	rows, err := readDirectoryCSV(path)
	if err != nil {
		return nil, fmt.Errorf("read directory key CSV: %w", err)
	}
	if len(rows) == 0 {
		return nil, errors.New("directory key CSV is empty")
	}

	if isDirectoryHeader(rows[0], []string{"channel_id", "directory_channel_key_base64url"}) {
		rows = rows[1:]
	}
	if len(rows) == 0 {
		return nil, errors.New("directory key CSV has no key rows")
	}

	keys := make(directoryKeyStore, len(rows))
	for index, row := range rows {
		if len(row) != 2 {
			return nil, fmt.Errorf("directory key CSV row %d must contain channel_id,directory_channel_key_base64url", index+1)
		}
		channelID, err := parseDirectoryU32(row[0], false)
		if err != nil {
			return nil, fmt.Errorf("directory key CSV row %d channel_id: %w", index+1, err)
		}
		encoded := strings.TrimSpace(row[1])
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			return nil, fmt.Errorf("directory key CSV row %d directory_channel_key_base64url must be canonical unpadded Base64URL for 32 bytes", index+1)
		}
		allZero := true
		for _, value := range decoded {
			allZero = allZero && value == 0
		}
		if allZero {
			return nil, fmt.Errorf("directory key CSV row %d directory_channel_key_base64url must not be all zero", index+1)
		}
		if _, exists := keys[channelID]; exists {
			return nil, fmt.Errorf("duplicate directory key CSV entry for channel %d", channelID)
		}
		material, err := newDirectoryKeyMaterial(decoded)
		if err != nil {
			return nil, fmt.Errorf("directory key CSV row %d: %w", index+1, err)
		}
		keys[channelID] = material
	}
	return keys, nil
}

type directoryChannelRow struct {
	ChannelID uint32 `json:"channelId"`
	Name      string `json:"name"`
}

type directorySpeakerRow struct {
	ChannelID uint32 `json:"channelId"`
	SenderID  uint32 `json:"senderId"`
	Name      string `json:"name"`
}

type directoryParticipantRow struct {
	ChannelID  uint32 `json:"channelId"`
	SenderID   uint32 `json:"senderId"`
	LastSeenAt uint64 `json:"lastSeenAt"`
	Talking    bool   `json:"talking"`
}

type directoryMetadata struct {
	channels map[uint32]directoryChannelRow
	speakers map[uint32]map[uint32]directorySpeakerRow
	fallback map[uint32]directorySpeakerRow
}

func loadDirectoryMetadata(channelsPath string, speakersPath string) (directoryMetadata, error) {
	if strings.TrimSpace(channelsPath) == "" || strings.TrimSpace(speakersPath) == "" {
		return directoryMetadata{}, errors.New("directory channels and speakers CSV files are required")
	}
	channelsRows, err := readDirectoryCSV(channelsPath)
	if err != nil {
		return directoryMetadata{}, fmt.Errorf("read channels CSV: %w", err)
	}
	if len(channelsRows) > 0 && isDirectoryHeader(channelsRows[0], []string{"channel_id", "name"}) {
		channelsRows = channelsRows[1:]
	}
	if len(channelsRows) == 0 {
		return directoryMetadata{}, errors.New("channels CSV must contain at least one channel")
	}
	if len(channelsRows) > directoryMaxChannels {
		return directoryMetadata{}, fmt.Errorf("channels CSV exceeds the %d-channel Directory limit", directoryMaxChannels)
	}

	metadata := directoryMetadata{
		channels: make(map[uint32]directoryChannelRow, len(channelsRows)),
		speakers: make(map[uint32]map[uint32]directorySpeakerRow),
		fallback: make(map[uint32]directorySpeakerRow),
	}
	for index, row := range channelsRows {
		if len(row) != 2 {
			return directoryMetadata{}, fmt.Errorf("channels CSV row %d must contain channel_id,name", index+1)
		}
		channelID, err := parseDirectoryU32(row[0], false)
		if err != nil {
			return directoryMetadata{}, fmt.Errorf("channels CSV row %d channel_id: %w", index+1, err)
		}
		if !validDirectoryName(row[1]) {
			return directoryMetadata{}, fmt.Errorf("channels CSV row %d name must be non-empty valid UTF-8 with at most 128 code points", index+1)
		}
		if _, exists := metadata.channels[channelID]; exists {
			return directoryMetadata{}, fmt.Errorf("duplicate channels CSV entry for channel %d", channelID)
		}
		metadata.channels[channelID] = directoryChannelRow{ChannelID: channelID, Name: row[1]}
	}

	speakerRows, err := readDirectoryCSV(speakersPath)
	if err != nil {
		return directoryMetadata{}, fmt.Errorf("read speakers CSV: %w", err)
	}
	if len(speakerRows) > 0 && isDirectoryHeader(speakerRows[0], []string{"channel_id", "sender_id", "name"}) {
		speakerRows = speakerRows[1:]
	}
	if len(speakerRows) > directoryMaxSpeakers {
		return directoryMetadata{}, fmt.Errorf("speakers CSV exceeds the %d-speaker Directory limit", directoryMaxSpeakers)
	}
	for index, row := range speakerRows {
		if len(row) != 3 {
			return directoryMetadata{}, fmt.Errorf("speakers CSV row %d must contain channel_id,sender_id,name", index+1)
		}
		senderID, err := parseDirectoryU32(row[1], true)
		if err != nil {
			return directoryMetadata{}, fmt.Errorf("speakers CSV row %d sender_id: %w", index+1, err)
		}
		if !validDirectoryName(row[2]) {
			return directoryMetadata{}, fmt.Errorf("speakers CSV row %d name must be non-empty valid UTF-8 with at most 128 code points", index+1)
		}
		if strings.EqualFold(strings.TrimSpace(row[0]), "all") {
			if _, exists := metadata.fallback[senderID]; exists {
				return directoryMetadata{}, fmt.Errorf("duplicate speakers CSV fallback entry for sender %d", senderID)
			}
			metadata.fallback[senderID] = directorySpeakerRow{SenderID: senderID, Name: row[2]}
			continue
		}
		channelID, err := parseDirectoryU32(row[0], false)
		if err != nil {
			return directoryMetadata{}, fmt.Errorf("speakers CSV row %d channel_id: %w", index+1, err)
		}
		if _, exists := metadata.channels[channelID]; !exists {
			return directoryMetadata{}, fmt.Errorf("speakers CSV row %d channel %d is not configured", index+1, channelID)
		}
		if metadata.speakers[channelID] == nil {
			metadata.speakers[channelID] = make(map[uint32]directorySpeakerRow)
		}
		if _, exists := metadata.speakers[channelID][senderID]; exists {
			return directoryMetadata{}, fmt.Errorf("duplicate speakers CSV entry for channel %d sender %d", channelID, senderID)
		}
		metadata.speakers[channelID][senderID] = directorySpeakerRow{ChannelID: channelID, SenderID: senderID, Name: row[2]}
	}
	return metadata, nil
}

func (m directoryMetadata) resolvedSpeakers(channelID uint32) []directorySpeakerRow {
	resolved := make(map[uint32]directorySpeakerRow, len(m.fallback)+len(m.speakers[channelID]))
	for senderID, row := range m.fallback {
		row.ChannelID = channelID
		resolved[senderID] = row
	}
	for senderID, row := range m.speakers[channelID] {
		resolved[senderID] = row
	}
	rows := make([]directorySpeakerRow, 0, len(resolved))
	for _, row := range resolved {
		rows = append(rows, row)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].SenderID < rows[j].SenderID })
	return rows
}

func (m directoryMetadata) revision(channelID uint32) (string, bool) {
	channel, ok := m.channels[channelID]
	if !ok {
		return "", false
	}
	payload := struct {
		Channel  directoryChannelRow   `json:"channel"`
		Speakers []directorySpeakerRow `json:"speakers"`
	}{Channel: channel, Speakers: m.resolvedSpeakers(channelID)}
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), true
}

func readDirectoryCSV(path string) ([][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(data, []byte{0xef, 0xbb, 0xbf}) {
		return nil, errors.New("UTF-8 BOM is not permitted")
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		kept = append(kept, line)
	}
	if len(kept) == 0 {
		return nil, nil
	}
	reader := csv.NewReader(strings.NewReader(strings.Join(kept, "\n")))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	return records, nil
}

func isDirectoryHeader(row []string, expected []string) bool {
	if len(row) != len(expected) {
		return false
	}
	for index, name := range expected {
		if !strings.EqualFold(strings.TrimSpace(row[index]), name) {
			return false
		}
	}
	return true
}

func parseDirectoryU32(value string, nonzero bool) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "xX") {
		return 0, errors.New("must be an unsigned decimal integer")
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, errors.New("must be an unsigned decimal integer")
	}
	if nonzero && parsed == 0 {
		return 0, errors.New("must be non-zero")
	}
	return uint32(parsed), nil
}

func validDirectoryName(value string) bool {
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= 128
}

type directoryEnvelope struct {
	Version    uint64 `json:"v"`
	Type       string `json:"type"`
	ChannelID  uint32 `json:"channelId"`
	Epoch      string `json:"epoch"`
	Sequence   uint64 `json:"sequence"`
	ExpiresAt  uint64 `json:"expiresAt"`
	Ciphertext string `json:"ciphertext"`
}

type directoryEnvelopeInput struct {
	Version    *uint64 `json:"v"`
	Type       *string `json:"type"`
	ChannelID  *uint32 `json:"channelId"`
	Epoch      *string `json:"epoch"`
	Sequence   *uint64 `json:"sequence"`
	ExpiresAt  *uint64 `json:"expiresAt"`
	Ciphertext *string `json:"ciphertext"`
}

type directoryRequestPayload struct {
	Version   uint64  `json:"version"`
	IssuedAt  uint64  `json:"issuedAt"`
	ExpiresAt uint64  `json:"expiresAt"`
	RequestID string  `json:"requestId"`
	Resource  string  `json:"resource"`
	Cursor    *string `json:"cursor,omitempty"`
}

type directoryRequestInput struct {
	Version   *uint64         `json:"version"`
	IssuedAt  *uint64         `json:"issuedAt"`
	ExpiresAt *uint64         `json:"expiresAt"`
	RequestID *string         `json:"requestId"`
	Resource  *string         `json:"resource"`
	Cursor    json.RawMessage `json:"cursor"`
}

type directoryRegistrationPayload struct {
	Version    uint64 `json:"version"`
	IssuedAt   uint64 `json:"issuedAt"`
	ExpiresAt  uint64 `json:"expiresAt"`
	InstanceID string `json:"instanceId"`
}

type directoryRegistrationInput struct {
	Version    *uint64 `json:"version"`
	IssuedAt   *uint64 `json:"issuedAt"`
	ExpiresAt  *uint64 `json:"expiresAt"`
	InstanceID *string `json:"instanceId"`
}

type directoryOpenedDatagram struct {
	envelope     directoryEnvelope
	epoch        [16]byte
	binding      uint8
	request      *directoryRequestPayload
	registration *directoryRegistrationPayload
}

func openDirectoryDatagram(data []byte, binding uint8, keys directoryKeyStore, now time.Time) (directoryOpenedDatagram, error) {
	if !acceptsUDPDatagramSize(len(data)) {
		return directoryOpenedDatagram{}, errors.New("datagram exceeds 1200-byte limit")
	}
	if binding != directoryTransportDedicated && binding != directoryTransportMedia {
		return directoryOpenedDatagram{}, errors.New("invalid transport binding")
	}
	var envelopeInput directoryEnvelopeInput
	if err := decodeDirectoryJSON(data, &envelopeInput); err != nil {
		return directoryOpenedDatagram{}, fmt.Errorf("invalid envelope: %w", err)
	}
	if envelopeInput.Version == nil || envelopeInput.Type == nil || envelopeInput.ChannelID == nil || envelopeInput.Epoch == nil ||
		envelopeInput.Sequence == nil || envelopeInput.ExpiresAt == nil || envelopeInput.Ciphertext == nil {
		return directoryOpenedDatagram{}, errors.New("Directory envelope has missing or null required fields")
	}
	envelope := directoryEnvelope{
		Version: *envelopeInput.Version, Type: *envelopeInput.Type, ChannelID: *envelopeInput.ChannelID,
		Epoch: *envelopeInput.Epoch, Sequence: *envelopeInput.Sequence, ExpiresAt: *envelopeInput.ExpiresAt,
		Ciphertext: *envelopeInput.Ciphertext,
	}
	if envelope.Version != directoryV3Version {
		return directoryOpenedDatagram{}, errors.New("unsupported Directory version")
	}
	if !isDirectoryClientType(envelope.Type) {
		return directoryOpenedDatagram{}, errors.New("invalid client-to-Relay Directory type")
	}
	if envelope.Sequence == 0 || envelope.Sequence > directoryMaxJSONInteger || envelope.ExpiresAt == 0 || envelope.ExpiresAt > directoryMaxJSONInteger {
		return directoryOpenedDatagram{}, errors.New("sequence and expiresAt must be positive JavaScript-safe integers")
	}
	if envelope.ExpiresAt <= uint64(now.Unix()) {
		return directoryOpenedDatagram{}, errors.New("envelope is expired")
	}
	epoch, err := decodeCanonicalDirectoryID(envelope.Epoch)
	if err != nil {
		return directoryOpenedDatagram{}, fmt.Errorf("invalid epoch: %w", err)
	}
	material, found := keys[envelope.ChannelID]
	if !found {
		return directoryOpenedDatagram{}, errors.New("channel has no Directory key")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil || len(ciphertext) < 16 {
		return directoryOpenedDatagram{}, errors.New("invalid ciphertext")
	}
	key, err := directoryEpochKey(material.c2r[:], epoch)
	if err != nil {
		return directoryOpenedDatagram{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return directoryOpenedDatagram{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return directoryOpenedDatagram{}, err
	}
	plaintext, err := gcm.Open(nil, directoryNonce(envelope.Sequence), ciphertext, directoryAAD(envelope, epoch, binding))
	if err != nil {
		return directoryOpenedDatagram{}, errors.New("Directory authentication failed")
	}

	opened := directoryOpenedDatagram{envelope: envelope, epoch: epoch, binding: binding}
	switch envelope.Type {
	case "request":
		var input directoryRequestInput
		if err := decodeDirectoryJSON(plaintext, &input); err != nil {
			return directoryOpenedDatagram{}, fmt.Errorf("invalid request payload: %w", err)
		}
		if input.Version == nil || input.IssuedAt == nil || input.ExpiresAt == nil || input.RequestID == nil || input.Resource == nil {
			return directoryOpenedDatagram{}, errors.New("Directory request payload has missing or null required fields")
		}
		request := directoryRequestPayload{Version: *input.Version, IssuedAt: *input.IssuedAt, ExpiresAt: *input.ExpiresAt, RequestID: *input.RequestID, Resource: *input.Resource}
		if err := validateDirectoryClientPayload(request.Version, request.IssuedAt, request.ExpiresAt, envelope.ExpiresAt, now); err != nil {
			return directoryOpenedDatagram{}, err
		}
		if _, err := decodeCanonicalDirectoryID(request.RequestID); err != nil {
			return directoryOpenedDatagram{}, fmt.Errorf("invalid requestId: %w", err)
		}
		if request.Resource != "participants" && request.Resource != "snapshot" {
			return directoryOpenedDatagram{}, errors.New("invalid request resource")
		}
		if input.Cursor != nil {
			if bytes.Equal(input.Cursor, []byte("null")) {
				return directoryOpenedDatagram{}, errors.New("invalid request cursor")
			}
			var cursor string
			if err := json.Unmarshal(input.Cursor, &cursor); err != nil || request.Resource != "snapshot" || cursor == "" || len(cursor) > 512 {
				return directoryOpenedDatagram{}, errors.New("invalid request cursor")
			}
			request.Cursor = &cursor
		}
		opened.request = &request
	case "register", "heartbeat":
		var input directoryRegistrationInput
		if err := decodeDirectoryJSON(plaintext, &input); err != nil {
			return directoryOpenedDatagram{}, fmt.Errorf("invalid registration payload: %w", err)
		}
		if input.Version == nil || input.IssuedAt == nil || input.ExpiresAt == nil || input.InstanceID == nil {
			return directoryOpenedDatagram{}, errors.New("Directory registration payload has missing or null required fields")
		}
		registration := directoryRegistrationPayload{Version: *input.Version, IssuedAt: *input.IssuedAt, ExpiresAt: *input.ExpiresAt, InstanceID: *input.InstanceID}
		if err := validateDirectoryClientPayload(registration.Version, registration.IssuedAt, registration.ExpiresAt, envelope.ExpiresAt, now); err != nil {
			return directoryOpenedDatagram{}, err
		}
		if _, err := decodeCanonicalDirectoryID(registration.InstanceID); err != nil {
			return directoryOpenedDatagram{}, fmt.Errorf("invalid instanceId: %w", err)
		}
		opened.registration = &registration
	}
	return opened, nil
}

func sealDirectoryDatagram(plaintext []byte, envelopeType string, channelID uint32, material directoryKeyMaterial, epoch [16]byte, sequence uint64, expiresAt uint64, binding uint8) ([]byte, error) {
	if !isDirectoryRelayType(envelopeType) {
		return nil, errors.New("invalid Relay-to-client Directory type")
	}
	return sealDirectoryEnvelope(plaintext, envelopeType, channelID, material.r2c[:], epoch, sequence, expiresAt, binding)
}

func sealDirectoryClientDatagram(plaintext []byte, envelopeType string, channelID uint32, material directoryKeyMaterial, epoch [16]byte, sequence uint64, expiresAt uint64, binding uint8) ([]byte, error) {
	if !isDirectoryClientType(envelopeType) {
		return nil, errors.New("invalid client-to-Relay Directory type")
	}
	return sealDirectoryEnvelope(plaintext, envelopeType, channelID, material.c2r[:], epoch, sequence, expiresAt, binding)
}

func sealDirectoryEnvelope(plaintext []byte, envelopeType string, channelID uint32, directionalKey []byte, epoch [16]byte, sequence uint64, expiresAt uint64, binding uint8) ([]byte, error) {
	if sequence == 0 || sequence > directoryMaxJSONInteger || expiresAt == 0 || expiresAt > directoryMaxJSONInteger {
		return nil, errors.New("sequence and expiresAt must be positive JavaScript-safe integers")
	}
	if binding != directoryTransportDedicated && binding != directoryTransportMedia {
		return nil, errors.New("invalid transport binding")
	}
	key, err := directoryEpochKey(directionalKey, epoch)
	if err != nil {
		return nil, err
	}
	encodedEpoch := base64.RawURLEncoding.EncodeToString(epoch[:])
	envelope := directoryEnvelope{Version: directoryV3Version, Type: envelopeType, ChannelID: channelID, Epoch: encodedEpoch, Sequence: sequence, ExpiresAt: expiresAt}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, directoryNonce(sequence), plaintext, directoryAAD(envelope, epoch, binding))
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
	datagram, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	if binding == directoryTransportMedia {
		datagram = append(append(append([]byte(nil), directoryCarrierMagic...), byte(directoryCarrierVersion)), datagram...)
	}
	if !acceptsUDPDatagramSize(len(datagram)) {
		return nil, errors.New("Directory datagram exceeds 1200-byte limit")
	}
	return datagram, nil
}

func directoryEpochKey(directionalKey []byte, epoch [16]byte) ([]byte, error) {
	return hkdfSHA256(directionalKey, epoch[:], directoryEnvelopeInfo, 32)
}

func directoryNonce(sequence uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, directoryCarrierMagic)
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func directoryAAD(envelope directoryEnvelope, epoch [16]byte, binding uint8) []byte {
	aad := make([]byte, 0, len(directoryAADPrefix)+1+1+1+len(envelope.Type)+4+len(epoch)+8+8)
	aad = append(aad, directoryAADPrefix...)
	aad = append(aad, byte(envelope.Version), binding, byte(len(envelope.Type)))
	aad = append(aad, envelope.Type...)
	var number [8]byte
	binary.BigEndian.PutUint32(number[:4], envelope.ChannelID)
	aad = append(aad, number[:4]...)
	aad = append(aad, epoch[:]...)
	binary.BigEndian.PutUint64(number[:], envelope.Sequence)
	aad = append(aad, number[:]...)
	binary.BigEndian.PutUint64(number[:], envelope.ExpiresAt)
	aad = append(aad, number[:]...)
	return aad
}

func decodeCanonicalDirectoryID(value string) ([16]byte, error) {
	var decodedID [16]byte
	if len(value) != 22 || strings.Contains(value, "=") {
		return decodedID, errors.New("must be unpadded Base64URL for exactly 16 bytes")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return decodedID, errors.New("must be Base64URL")
	}
	if len(decoded) != len(decodedID) {
		return decodedID, errors.New("must decode to exactly 16 bytes")
	}
	if base64.RawURLEncoding.EncodeToString(decoded) != value {
		return decodedID, errors.New("must use canonical Base64URL")
	}
	copy(decodedID[:], decoded)
	return decodedID, nil
}

func decodeDirectoryJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func validateDirectoryClientPayload(version uint64, issuedAt uint64, expiresAt uint64, envelopeExpiresAt uint64, now time.Time) error {
	if version != directoryV3Version || issuedAt == 0 || issuedAt > directoryMaxJSONInteger || expiresAt == 0 || expiresAt > directoryMaxJSONInteger {
		return errors.New("invalid Directory payload version or timestamps")
	}
	if issuedAt >= expiresAt || expiresAt != envelopeExpiresAt || expiresAt-issuedAt > uint64(directoryClientLifetime/time.Second) {
		return errors.New("invalid Directory payload lifetime")
	}
	if expiresAt <= uint64(now.Unix()) {
		return errors.New("Directory payload is expired")
	}
	return nil
}

func isDirectoryClientType(value string) bool {
	return value == "request" || value == "register" || value == "heartbeat"
}

func isDirectoryRelayType(value string) bool {
	return value == "snapshot" || value == "participants" || value == "error"
}

type directoryReplayKey struct {
	ChannelID uint32
	Epoch     [16]byte
}

type directoryReplayState struct {
	initialized bool
	highest     uint64
	seen        uint64
}

type directoryReplayRecord struct {
	state   directoryReplayState
	expires time.Time
}

func (s *directoryReplayState) accept(sequence uint64) bool {
	if !s.initialized {
		s.initialized = true
		s.highest = sequence
		s.seen = 1
		return true
	}
	if sequence > s.highest {
		delta := sequence - s.highest
		if delta >= directoryReplayWindowSize {
			s.seen = 1
		} else {
			s.seen = s.seen<<delta | 1
		}
		s.highest = sequence
		return true
	}
	delta := s.highest - sequence
	if delta >= directoryReplayWindowSize {
		return false
	}
	mask := uint64(1) << delta
	if s.seen&mask != 0 {
		return false
	}
	s.seen |= mask
	return true
}

type directoryV3Config struct {
	Enabled         bool
	Transport       directoryTransport
	KeyFile         string
	ChannelsCSV     string
	SpeakersCSV     string
	Conn            *net.UDPConn
	PublishInterval time.Duration
	FreshnessTTL    time.Duration
	Participants    func(uint32) []directoryParticipantRow
}

type directoryRegistrationKey struct {
	channelID  uint32
	instanceID [16]byte
}

type directoryRegistration struct {
	addr     *net.UDPAddr
	binding  uint8
	deadline time.Time
}

type directoryInboundJob struct {
	data    []byte
	addr    *net.UDPAddr
	binding uint8
}

type directoryRateState struct {
	window time.Time
	count  int
}

type directorySnapshotSession struct {
	channel  directoryChannelRow
	speakers []directorySpeakerRow
	revision string
	expires  time.Time
}

type directorySnapshotCursor struct {
	session *directorySnapshotSession
	page    int
}

type directoryV3 struct {
	mu            sync.Mutex
	keys          directoryKeyStore
	metadata      directoryMetadata
	transport     directoryTransport
	conn          *net.UDPConn
	participants  func(uint32) []directoryParticipantRow
	publishEvery  time.Duration
	freshnessTTL  time.Duration
	now           func() time.Time
	random        io.Reader
	jobs          chan directoryInboundJob
	stop          chan struct{}
	registrations map[directoryRegistrationKey]directoryRegistration
	replay        map[directoryReplayKey]directoryReplayRecord
	cursors       map[string]directorySnapshotCursor
	preauth       map[string]directoryRateState
	responseRate  directoryRateState
}

func newDirectoryV3(config directoryV3Config) (*directoryV3, error) {
	if !config.Enabled {
		return nil, nil
	}
	if config.Conn == nil {
		return nil, errors.New("Directory UDP connection is required")
	}
	transport, err := parseDirectoryTransport(string(config.Transport))
	if err != nil {
		return nil, err
	}
	if config.Participants == nil {
		return nil, errors.New("Directory participant source is required")
	}
	if config.PublishInterval == 0 {
		config.PublishInterval = directoryDefaultPublishInterval
	}
	if config.FreshnessTTL == 0 {
		config.FreshnessTTL = directoryDefaultFreshnessTTL
	}
	if config.PublishInterval < time.Second || config.FreshnessTTL < time.Second || config.FreshnessTTL > directoryMaxFreshnessTTL {
		return nil, fmt.Errorf("invalid Directory timing publish_interval=%s freshness_ttl=%s", config.PublishInterval, config.FreshnessTTL)
	}
	keys, err := loadDirectoryKeyStore(config.KeyFile)
	if err != nil {
		return nil, err
	}
	metadata, err := loadDirectoryMetadata(config.ChannelsCSV, config.SpeakersCSV)
	if err != nil {
		return nil, err
	}
	for channelID := range keys {
		if _, found := metadata.channels[channelID]; !found {
			return nil, fmt.Errorf("directory key configured for channel %d without metadata", channelID)
		}
	}
	for channelID := range metadata.channels {
		if _, found := keys[channelID]; !found {
			return nil, fmt.Errorf("directory metadata configured for channel %d without a Directory key", channelID)
		}
	}
	return &directoryV3{
		keys:          keys,
		metadata:      metadata,
		transport:     transport,
		conn:          config.Conn,
		participants:  config.Participants,
		publishEvery:  config.PublishInterval,
		freshnessTTL:  config.FreshnessTTL,
		now:           time.Now,
		random:        rand.Reader,
		jobs:          make(chan directoryInboundJob, 32),
		stop:          make(chan struct{}),
		registrations: make(map[directoryRegistrationKey]directoryRegistration),
		replay:        make(map[directoryReplayKey]directoryReplayRecord),
		cursors:       make(map[string]directorySnapshotCursor),
		preauth:       make(map[string]directoryRateState),
	}, nil
}

func (d *directoryV3) start() {
	if d == nil {
		return
	}
	for worker := 0; worker < 2; worker++ {
		go d.worker()
	}
	go d.publishLoop()
	go d.cleanupLoop()
	if d.transport == directoryTransportDedicatedUDP {
		go d.dedicatedReadLoop()
	}
}

func (d *directoryV3) close() {
	if d == nil {
		return
	}
	select {
	case <-d.stop:
		return
	default:
		close(d.stop)
	}
	if d.transport == directoryTransportDedicatedUDP && d.conn != nil {
		_ = d.conn.Close()
	}
}

func (d *directoryV3) dedicatedReadLoop() {
	buf := make([]byte, maxUDPDatagramBytes+1)
	for {
		n, addr, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.stop:
				return
			default:
				return
			}
		}
		if !acceptsUDPDatagramSize(n) {
			continue
		}
		d.enqueue(buf[:n], addr, directoryTransportDedicated)
	}
}

func (d *directoryV3) enqueue(data []byte, addr *net.UDPAddr, binding uint8) {
	if d == nil || addr == nil || !d.allowPreauthentication(addr) {
		return
	}
	job := directoryInboundJob{data: append([]byte(nil), data...), addr: cloneUDPAddr(addr), binding: binding}
	select {
	case d.jobs <- job:
	default:
		// Directory is best effort. A full bounded queue is dropped rather than
		// delaying media or ordinary Relay control processing.
	}
}

func (d *directoryV3) worker() {
	for {
		select {
		case <-d.stop:
			return
		case job := <-d.jobs:
			d.handle(job)
		}
	}
}

func (d *directoryV3) handle(job directoryInboundJob) {
	opened, err := openDirectoryDatagram(job.data, job.binding, d.keys, d.now())
	if err != nil {
		return
	}
	request := d.commitInbound(opened, job.addr)
	if request != nil {
		d.serveRequest(opened.envelope.ChannelID, *request, job.addr)
	}
}

func (d *directoryV3) commitInbound(opened directoryOpenedDatagram, addr *net.UDPAddr) *directoryRequestPayload {
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.purgeLocked(now)
	replayKey := directoryReplayKey{ChannelID: opened.envelope.ChannelID, Epoch: opened.epoch}
	replay, found := d.replay[replayKey]
	if !found && len(d.replay) >= directoryMaxReplayDomains {
		// An authenticated but unbounded stream of fresh epochs must not turn
		// replay tracking into an unbounded allocation.
		return nil
	}
	if !replay.state.accept(opened.envelope.Sequence) {
		return nil
	}
	payloadExpiry := time.Unix(int64(opened.envelope.ExpiresAt), 0)
	if replay.expires.Before(payloadExpiry) {
		replay.expires = payloadExpiry
	}
	d.replay[replayKey] = replay

	switch opened.envelope.Type {
	case "request":
		request := *opened.request
		return &request
	case "register":
		instanceID, _ := decodeCanonicalDirectoryID(opened.registration.InstanceID)
		key := directoryRegistrationKey{channelID: opened.envelope.ChannelID, instanceID: instanceID}
		if _, exists := d.registrations[key]; !exists && len(d.registrations) >= directoryMaxRegistrations {
			return nil
		}
		d.registrations[key] = directoryRegistration{
			addr: cloneUDPAddr(addr), binding: opened.binding, deadline: now.Add(directoryRegistrationTTL),
		}
	case "heartbeat":
		instanceID, _ := decodeCanonicalDirectoryID(opened.registration.InstanceID)
		key := directoryRegistrationKey{channelID: opened.envelope.ChannelID, instanceID: instanceID}
		registration, found := d.registrations[key]
		if !found || registration.binding != opened.binding || !sameUDPEndpoint(registration.addr, addr) {
			return nil
		}
		registration.deadline = now.Add(directoryRegistrationTTL)
		d.registrations[key] = registration
	}
	return nil
}

func (d *directoryV3) allowPreauthentication(addr *net.UDPAddr) bool {
	now := d.now()
	key := addr.IP.String()
	d.mu.Lock()
	defer d.mu.Unlock()
	state, found := d.preauth[key]
	if !found && len(d.preauth) >= 1024 {
		return false
	}
	if state.window.IsZero() || now.Sub(state.window) >= time.Second {
		state = directoryRateState{window: now}
	}
	// The value is implementation-local; the required property is that parsing
	// cannot be driven without a bounded source budget.
	if state.count >= 16 {
		d.preauth[key] = state
		return false
	}
	state.count++
	d.preauth[key] = state
	return true
}

func (d *directoryV3) consumeResponseBudget(packetCount int) bool {
	if packetCount < 1 {
		return false
	}
	now := d.now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.responseRate.window.IsZero() || now.Sub(d.responseRate.window) >= time.Second {
		d.responseRate = directoryRateState{window: now}
	}
	if d.responseRate.count+packetCount > 64 {
		return false
	}
	d.responseRate.count += packetCount
	return true
}

func (d *directoryV3) purgeLocked(now time.Time) {
	for key, registration := range d.registrations {
		if !registration.deadline.After(now) {
			delete(d.registrations, key)
		}
	}
	for cursor, session := range d.cursors {
		if !session.session.expires.After(now) {
			delete(d.cursors, cursor)
		}
	}
	for key, replay := range d.replay {
		if !replay.expires.After(now) {
			delete(d.replay, key)
		}
	}
	for source, state := range d.preauth {
		if now.Sub(state.window) >= 2*time.Second {
			delete(d.preauth, source)
		}
	}
}

func (d *directoryV3) publishLoop() {
	ticker := time.NewTicker(d.publishEvery)
	defer ticker.Stop()
	for {
		select {
		case <-d.stop:
			return
		case <-ticker.C:
			d.publishParticipants()
		}
	}
}

func (d *directoryV3) cleanupLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-d.stop:
			return
		case <-ticker.C:
			d.mu.Lock()
			d.purgeLocked(d.now())
			d.mu.Unlock()
		}
	}
}

func (d *directoryV3) publishParticipants() {
	now := d.now()
	d.mu.Lock()
	d.purgeLocked(now)
	registrations := make(map[uint32][]directoryRegistration)
	for key, registration := range d.registrations {
		registrations[key.channelID] = append(registrations[key.channelID], registration)
	}
	d.mu.Unlock()
	for channelID, targets := range registrations {
		rows := d.participants(channelID)
		for _, target := range targets {
			d.sendParticipants(channelID, "", rows, target.addr, target.binding)
		}
	}
}

func (d *directoryV3) serveRequest(channelID uint32, request directoryRequestPayload, addr *net.UDPAddr) {
	if request.Resource == "participants" {
		if request.Cursor != nil {
			return
		}
		d.sendParticipants(channelID, request.RequestID, d.participants(channelID), addr, d.transport.binding())
		return
	}
	d.sendSnapshot(channelID, request, addr, d.transport.binding())
}

type directoryFragment struct {
	ResponseID string `json:"responseId"`
	Index      int    `json:"index"`
	Count      int    `json:"count"`
}

type directoryParticipantsPayload struct {
	Version      uint64                    `json:"version"`
	IssuedAt     uint64                    `json:"issuedAt"`
	ExpiresAt    uint64                    `json:"expiresAt"`
	RequestID    string                    `json:"requestId,omitempty"`
	Fragment     directoryFragment         `json:"fragment"`
	Participants []directoryParticipantRow `json:"participants"`
}

type directorySnapshotPage struct {
	Index      int     `json:"index"`
	Count      int     `json:"count"`
	NextCursor *string `json:"nextCursor"`
}

type directorySnapshotPayload struct {
	Version   uint64                `json:"version"`
	IssuedAt  uint64                `json:"issuedAt"`
	ExpiresAt uint64                `json:"expiresAt"`
	RequestID string                `json:"requestId,omitempty"`
	Fragment  directoryFragment     `json:"fragment"`
	Revision  string                `json:"revision"`
	Page      directorySnapshotPage `json:"page"`
	Channels  []directoryChannelRow `json:"channels"`
	Speakers  []directorySpeakerRow `json:"speakers"`
}

type directoryErrorPayload struct {
	Version   uint64 `json:"version"`
	IssuedAt  uint64 `json:"issuedAt"`
	ExpiresAt uint64 `json:"expiresAt"`
	RequestID string `json:"requestId"`
	Code      string `json:"code"`
}

func (d *directoryV3) sendParticipants(channelID uint32, requestID string, rows []directoryParticipantRow, addr *net.UDPAddr, binding uint8) {
	if len(rows) > directoryMaxParticipants {
		d.sendError(channelID, requestID, "RESPONSE_TOO_LARGE", addr, binding)
		return
	}
	material, found := d.keys[channelID]
	if !found {
		return
	}
	now := d.now()
	issuedAt := uint64(now.Unix())
	expiresAt := uint64(now.Add(d.freshnessTTL).Unix())
	epoch, err := d.randomID()
	if err != nil {
		return
	}
	responseID, err := d.randomIDText()
	if err != nil {
		return
	}
	groups, err := packDirectoryRows(rows, func(index int, count int, group []directoryParticipantRow) ([]byte, error) {
		payload := directoryParticipantsPayload{
			Version: directoryV3Version, IssuedAt: issuedAt, ExpiresAt: expiresAt, RequestID: requestID,
			Fragment: directoryFragment{ResponseID: responseID, Index: index, Count: count}, Participants: group,
		}
		return json.Marshal(payload)
	}, func(index int, count int, payload []byte) bool {
		_, err := sealDirectoryDatagram(payload, "participants", channelID, material, epoch, uint64(index+1), expiresAt, binding)
		return err == nil
	})
	if err != nil {
		d.sendError(channelID, requestID, "RESPONSE_TOO_LARGE", addr, binding)
		return
	}
	datagrams := make([][]byte, 0, len(groups))
	for index, group := range groups {
		payload, err := json.Marshal(directoryParticipantsPayload{
			Version: directoryV3Version, IssuedAt: issuedAt, ExpiresAt: expiresAt, RequestID: requestID,
			Fragment: directoryFragment{ResponseID: responseID, Index: index, Count: len(groups)}, Participants: group,
		})
		if err != nil {
			return
		}
		datagram, err := sealDirectoryDatagram(payload, "participants", channelID, material, epoch, uint64(index+1), expiresAt, binding)
		if err != nil {
			d.sendError(channelID, requestID, "RESPONSE_TOO_LARGE", addr, binding)
			return
		}
		datagrams = append(datagrams, datagram)
	}
	d.sendDatagrams(datagrams, addr)
}

func packDirectoryRows(rows []directoryParticipantRow, encode func(index int, count int, group []directoryParticipantRow) ([]byte, error), fits func(index int, count int, payload []byte) bool) ([][]directoryParticipantRow, error) {
	if len(rows) == 0 {
		return [][]directoryParticipantRow{{}}, nil
	}
	guess := 1
	for attempt := 0; attempt < 6; attempt++ {
		groups := make([][]directoryParticipantRow, 0, guess)
		for start := 0; start < len(rows); {
			group := make([]directoryParticipantRow, 0, len(rows)-start)
			for next := start; next < len(rows); next++ {
				candidate := append(append([]directoryParticipantRow(nil), group...), rows[next])
				payload, err := encode(len(groups), guess, candidate)
				if err != nil {
					return nil, err
				}
				if !fits(len(groups), guess, payload) {
					if len(group) == 0 {
						return nil, errors.New("individual participant record exceeds Directory datagram limit")
					}
					break
				}
				group = candidate
			}
			groups = append(groups, group)
			start += len(group)
		}
		if len(groups) > directoryMaxFragments {
			return nil, errors.New("participant response exceeds maximum fragment count")
		}
		if len(groups) == guess {
			return groups, nil
		}
		guess = len(groups)
	}
	return nil, errors.New("unable to stabilize Directory fragment packing")
}

// packDirectorySnapshotRows uses a conservative final-count estimate so a
// channel row can occupy fragment zero alone when a maximum-length name would
// otherwise make it overflow. Snapshot pages reserve one fragment for that
// channel row and therefore contain at most 31 speaker rows.
func packDirectorySnapshotRows(rows []directorySpeakerRow, encode func(index int, count int, group []directorySpeakerRow) ([]byte, error), fits func(index int, count int, payload []byte) bool) ([][]directorySpeakerRow, error) {
	if len(rows) == 0 {
		return [][]directorySpeakerRow{{}}, nil
	}

	groups := make([][]directorySpeakerRow, 0, directoryMaxFragments)
	for start := 0; start < len(rows); {
		index := len(groups)
		group := make([]directorySpeakerRow, 0, len(rows)-start)
		for next := start; next < len(rows); next++ {
			candidate := append(append([]directorySpeakerRow(nil), group...), rows[next])
			payload, err := encode(index, directoryMaxFragments, candidate)
			if err != nil {
				return nil, err
			}
			if !fits(index, directoryMaxFragments, payload) {
				break
			}
			group = candidate
		}
		if len(group) == 0 {
			if index != 0 {
				return nil, errors.New("individual speaker record exceeds Directory datagram limit")
			}
			payload, err := encode(0, directoryMaxFragments, nil)
			if err != nil || !fits(0, directoryMaxFragments, payload) {
				return nil, errors.New("individual channel record exceeds Directory datagram limit")
			}
			groups = append(groups, []directorySpeakerRow{})
			continue
		}
		groups = append(groups, group)
		start += len(group)
		if len(groups) > directoryMaxFragments {
			return nil, errors.New("snapshot page exceeds maximum fragment count")
		}
	}
	return groups, nil
}

func (d *directoryV3) sendSnapshot(channelID uint32, request directoryRequestPayload, addr *net.UDPAddr, binding uint8) {
	if request.Cursor != nil {
		d.sendSnapshotCursor(channelID, request.RequestID, *request.Cursor, addr, binding)
		return
	}
	d.mu.Lock()
	channel, found := d.metadata.channels[channelID]
	revision, revisionFound := d.metadata.revision(channelID)
	speakers := append([]directorySpeakerRow(nil), d.metadata.resolvedSpeakers(channelID)...)
	d.mu.Unlock()
	if !found || !revisionFound {
		d.sendError(channelID, request.RequestID, "RESPONSE_TOO_LARGE", addr, binding)
		return
	}
	pages := splitDirectorySnapshotPages(speakers)
	if len(pages) > directoryMaxSnapshotPages {
		d.sendError(channelID, request.RequestID, "RESPONSE_TOO_LARGE", addr, binding)
		return
	}
	session := &directorySnapshotSession{channel: channel, speakers: speakers, revision: revision, expires: d.now().Add(30 * time.Second)}
	d.sendSnapshotPage(channelID, request.RequestID, session, 0, addr, binding)
}

func (d *directoryV3) sendSnapshotCursor(channelID uint32, requestID string, cursor string, addr *net.UDPAddr, binding uint8) {
	d.mu.Lock()
	d.purgeLocked(d.now())
	entry, found := d.cursors[cursor]
	if found {
		delete(d.cursors, cursor)
	}
	d.mu.Unlock()
	if !found {
		d.sendError(channelID, requestID, "INVALID_CURSOR", addr, binding)
		return
	}
	if !entry.session.expires.After(d.now()) {
		d.sendError(channelID, requestID, "PAGING_SESSION_EXPIRED", addr, binding)
		return
	}
	d.sendSnapshotPage(channelID, requestID, entry.session, entry.page, addr, binding)
}

func (d *directoryV3) storeSnapshotCursor(session *directorySnapshotSession, page int) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.purgeLocked(d.now())
	for attempt := 0; attempt < 4; attempt++ {
		cursor, err := d.randomIDText()
		if err != nil {
			return "", err
		}
		if _, exists := d.cursors[cursor]; !exists {
			d.cursors[cursor] = directorySnapshotCursor{session: session, page: page}
			return cursor, nil
		}
	}
	return "", errors.New("unable to allocate snapshot cursor")
}

func splitDirectorySnapshotPages(rows []directorySpeakerRow) [][]directorySpeakerRow {
	if len(rows) == 0 {
		return [][]directorySpeakerRow{{}}
	}
	pageSpeakerLimit := directoryMaxFragments - 1
	pages := make([][]directorySpeakerRow, 0, (len(rows)+pageSpeakerLimit-1)/pageSpeakerLimit)
	for start := 0; start < len(rows); start += pageSpeakerLimit {
		end := start + pageSpeakerLimit
		if end > len(rows) {
			end = len(rows)
		}
		pages = append(pages, append([]directorySpeakerRow(nil), rows[start:end]...))
	}
	return pages
}

func (d *directoryV3) sendSnapshotPage(channelID uint32, requestID string, session *directorySnapshotSession, pageIndex int, addr *net.UDPAddr, binding uint8) {
	pages := splitDirectorySnapshotPages(session.speakers)
	if pageIndex < 0 || pageIndex >= len(pages) {
		d.sendError(channelID, requestID, "INVALID_CURSOR", addr, binding)
		return
	}
	material, found := d.keys[channelID]
	if !found {
		return
	}
	var nextCursor *string
	if pageIndex+1 < len(pages) {
		cursor, err := d.storeSnapshotCursor(session, pageIndex+1)
		if err != nil {
			return
		}
		nextCursor = &cursor
	}
	now := d.now()
	issuedAt := uint64(now.Unix())
	expiresAt := uint64(now.Add(d.freshnessTTL).Unix())
	epoch, err := d.randomID()
	if err != nil {
		return
	}
	responseID, err := d.randomIDText()
	if err != nil {
		return
	}
	pageRows := pages[pageIndex]
	encode := func(index int, count int, speakers []directorySpeakerRow) ([]byte, error) {
		channels := []directoryChannelRow{}
		if index == 0 {
			channels = []directoryChannelRow{session.channel}
		}
		return json.Marshal(directorySnapshotPayload{
			Version: directoryV3Version, IssuedAt: issuedAt, ExpiresAt: expiresAt, RequestID: requestID,
			Fragment: directoryFragment{ResponseID: responseID, Index: index, Count: count}, Revision: session.revision,
			Page: directorySnapshotPage{Index: pageIndex, Count: len(pages), NextCursor: nextCursor}, Channels: channels, Speakers: speakers,
		})
	}
	groups, err := packDirectorySnapshotRows(pageRows, encode, func(index int, count int, payload []byte) bool {
		_, err := sealDirectoryDatagram(payload, "snapshot", channelID, material, epoch, uint64(index+1), expiresAt, binding)
		return err == nil
	})
	if err != nil {
		d.sendError(channelID, requestID, "RESPONSE_TOO_LARGE", addr, binding)
		return
	}
	datagrams := make([][]byte, 0, len(groups))
	for index, speakers := range groups {
		payload, err := encode(index, len(groups), speakers)
		if err != nil {
			return
		}
		datagram, err := sealDirectoryDatagram(payload, "snapshot", channelID, material, epoch, uint64(index+1), expiresAt, binding)
		if err != nil {
			d.sendError(channelID, requestID, "RESPONSE_TOO_LARGE", addr, binding)
			return
		}
		datagrams = append(datagrams, datagram)
	}
	d.sendDatagrams(datagrams, addr)
}

func (d *directoryV3) sendError(channelID uint32, requestID string, code string, addr *net.UDPAddr, binding uint8) {
	if requestID == "" || (code != "RESPONSE_TOO_LARGE" && code != "INVALID_CURSOR" && code != "PAGING_SESSION_EXPIRED") {
		return
	}
	material, found := d.keys[channelID]
	if !found {
		return
	}
	now := d.now()
	issuedAt := uint64(now.Unix())
	expiresAt := uint64(now.Add(d.freshnessTTL).Unix())
	epoch, err := d.randomID()
	if err != nil {
		return
	}
	payload, err := json.Marshal(directoryErrorPayload{Version: directoryV3Version, IssuedAt: issuedAt, ExpiresAt: expiresAt, RequestID: requestID, Code: code})
	if err != nil {
		return
	}
	datagram, err := sealDirectoryDatagram(payload, "error", channelID, material, epoch, 1, expiresAt, binding)
	if err != nil {
		return
	}
	d.sendDatagrams([][]byte{datagram}, addr)
}

func (d *directoryV3) sendDatagrams(datagrams [][]byte, addr *net.UDPAddr) {
	if len(datagrams) == 0 || addr == nil || !d.consumeResponseBudget(len(datagrams)) {
		return
	}
	for index, datagram := range datagrams {
		if index > 0 {
			// Pacing is confined to Directory workers and never blocks the media
			// receive loop. Directory is intentionally best effort.
			time.Sleep(2 * time.Millisecond)
		}
		_, _ = d.conn.WriteToUDP(datagram, addr)
	}
}

func (d *directoryV3) randomID() ([16]byte, error) {
	var value [16]byte
	if _, err := io.ReadFull(d.random, value[:]); err != nil {
		return value, err
	}
	return value, nil
}

func (d *directoryV3) randomIDText() (string, error) {
	value, err := d.randomID()
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func cloneUDPAddr(value *net.UDPAddr) *net.UDPAddr {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.IP = append(net.IP(nil), value.IP...)
	return &cloned
}

func sameUDPEndpoint(left *net.UDPAddr, right *net.UDPAddr) bool {
	return left != nil && right != nil && left.Port == right.Port && left.Zone == right.Zone && left.IP.Equal(right.IP)
}
