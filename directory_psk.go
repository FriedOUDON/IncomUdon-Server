package main

import (
	"bufio"
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
	"time"
	"unicode/utf8"
)

const (
	directoryProtocolVersion    = 1
	directoryEnvelopeSnapshot   = "snapshot"
	directoryPSKBytes           = 32
	directoryEpochBytes         = 16
	directoryMaxDatagramBytes   = 1200
	directoryMaxChannels        = 256
	directoryMaxSpeakers        = 4096
	directoryMaxNameRunes       = 128
	directoryMaxKeyIDBytes      = 64
	directoryMaxValidity        = 5 * time.Minute
	directoryDefaultKeyID       = "pwa-1"
	directoryDefaultInterval    = 30 * time.Second
	directoryDefaultTTL         = 90 * time.Second
	directoryKeyDerivationLabel = "IncomUdon directory PSK v1 relay-to-pwa"
	directoryAllChannels        = "all"
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
	ChannelsCSV string
	SpeakersCSV string
	Target      string
	PSKFile     string
	KeyID       string
	Interval    time.Duration
	TTL         time.Duration
}

type directoryPublisher struct {
	channelsCSV string
	speakersCSV string
	conn        *net.UDPConn
	psk         []byte
	keyID       string
	epoch       []byte
	interval    time.Duration
	ttl         time.Duration
	sequence    uint64
}

func newDirectoryPublisher(config directoryPublisherConfig) (*directoryPublisher, error) {
	config.ChannelsCSV = strings.TrimSpace(config.ChannelsCSV)
	config.SpeakersCSV = strings.TrimSpace(config.SpeakersCSV)
	config.Target = strings.TrimSpace(config.Target)
	config.PSKFile = strings.TrimSpace(config.PSKFile)
	config.KeyID = strings.TrimSpace(config.KeyID)
	if config.KeyID == "" {
		config.KeyID = directoryDefaultKeyID
	}

	configured := config.ChannelsCSV != "" || config.SpeakersCSV != "" || config.Target != "" || config.PSKFile != ""
	if !configured {
		return nil, nil
	}
	if config.ChannelsCSV == "" || config.SpeakersCSV == "" || config.Target == "" || config.PSKFile == "" {
		return nil, fmt.Errorf("directory publishing requires channels CSV, speakers CSV, UDP target, and PSK file")
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

	psk, err := loadDirectoryPSK(config.PSKFile)
	if err != nil {
		return nil, err
	}
	target, err := net.ResolveUDPAddr("udp", config.Target)
	if err != nil {
		return nil, fmt.Errorf("resolve directory UDP target: %w", err)
	}
	conn, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return nil, fmt.Errorf("dial directory UDP target: %w", err)
	}
	epoch := make([]byte, directoryEpochBytes)
	if _, err := rand.Read(epoch); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("generate directory epoch: %w", err)
	}

	return &directoryPublisher{
		channelsCSV: config.ChannelsCSV,
		speakersCSV: config.SpeakersCSV,
		conn:        conn,
		psk:         psk,
		keyID:       config.KeyID,
		epoch:       epoch,
		interval:    config.Interval,
		ttl:         config.TTL,
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
	p.publish()
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for range ticker.C {
		p.publish()
	}
}

func (p *directoryPublisher) publish() {
	now := time.Now()
	document, err := loadDirectoryDocument(p.channelsCSV, p.speakersCSV, now, p.ttl)
	if err != nil {
		log.Printf("directory snapshot skipped: %v", err)
		return
	}
	payload, err := json.Marshal(document)
	if err != nil {
		log.Printf("directory snapshot skipped: marshal payload: %v", err)
		return
	}

	p.sequence++
	envelope, err := sealDirectoryEnvelope(p.psk, p.keyID, p.epoch, p.sequence, document.ExpiresAt, payload)
	if err != nil {
		log.Printf("directory snapshot skipped: encrypt payload: %v", err)
		return
	}
	packet, err := json.Marshal(envelope)
	if err != nil {
		log.Printf("directory snapshot skipped: marshal envelope: %v", err)
		return
	}
	if len(packet) > directoryMaxDatagramBytes {
		log.Printf("directory snapshot skipped: packet is %d bytes (maximum %d); shorten names or split the directory", len(packet), directoryMaxDatagramBytes)
		return
	}
	if _, err := p.conn.Write(packet); err != nil {
		log.Printf("directory snapshot send failed: %v", err)
		return
	}
	log.Printf("directory snapshot sent: revision=%s channels=%d speakers=%d bytes=%d", document.Revision[:12], len(document.Channels), len(document.Speakers), len(packet))
}

func sealDirectoryEnvelope(psk []byte, keyID string, epoch []byte, sequence uint64, expiresAt int64, payload []byte) (directoryEnvelope, error) {
	if len(epoch) != directoryEpochBytes {
		return directoryEnvelope{}, fmt.Errorf("invalid directory epoch")
	}
	envelope := directoryEnvelope{
		Version:   directoryProtocolVersion,
		Type:      directoryEnvelopeSnapshot,
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

func loadDirectoryDocument(channelsCSV, speakersCSV string, now time.Time, ttl time.Duration) (directoryDocument, error) {
	channels, err := loadDirectoryChannels(channelsCSV)
	if err != nil {
		return directoryDocument{}, err
	}
	speakers, err := loadDirectorySpeakers(speakersCSV, channels)
	if err != nil {
		return directoryDocument{}, err
	}
	revisionPayload, err := json.Marshal(struct {
		Channels []directoryChannel `json:"channels"`
		Speakers []directorySpeaker `json:"speakers"`
	}{Channels: channels, Speakers: speakers})
	if err != nil {
		return directoryDocument{}, err
	}
	revision := sha256.Sum256(revisionPayload)
	return directoryDocument{
		Version:   directoryProtocolVersion,
		Revision:  hex.EncodeToString(revision[:]),
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		Channels:  channels,
		Speakers:  speakers,
	}, nil
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
