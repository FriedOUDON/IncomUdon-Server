package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	privateControlSchemaVersion                = "private-control-link-v1"
	privateControlMaxFrameBytes                = 65536
	privateControlMaxJSONInteger         int64 = 9007199254740991
	privateControlSessionQueueDepth            = 256
	privateControlHelloDeadline                = 5 * time.Second
	privateControlTLSMinVersion                = tls.VersionTLS13
	privateControlLifecycleEventType           = "relay_lifecycle_event"
	privateControlAuditInputType               = "relay_audit_input"
	privateControlUnsupportedMessage           = "unsupported_message"
	privateControlIdentityMismatch             = "identity_mismatch"
	privateControlMalformedConnection          = "malformed private control frame"
	privateControlIdempotencyTTL               = 10 * time.Minute
	privateControlMaxDenyPeriod                = 90 * time.Minute
	privateControlDiagnosticsMinInterval       = 10 * time.Second
	privateControlMaxIdempotency               = 1024
	privateControlMaxCommands                  = 32
	privateControlMaxConnections               = 64
	privateControlFailureWindow                = time.Minute
	privateControlMaxFailures                  = 8
	privateControlMaxFailureSources            = 1024
)

type privateControlConfig struct {
	listenAddress     string
	certificateFile   string
	privateKeyFile    string
	clientCAFile      string
	servicesCSV       string
	relayID           string
	stateFile         string
	secretPermissions secretFilePermissionPolicy
}

type privateControlPolicy struct {
	byCertificate map[string]string
}

type privateControlLink struct {
	server       *server
	relayID      string
	policy       privateControlPolicy
	mu           sync.Mutex
	sessions     map[string]*privateControlSession
	dropped      uint64
	failures     map[string]privateControlFailureState
	idempotency  map[privateControlIdempotencyKey]*privateControlIdempotencyEntry
	stateFile    string
	commandSlots chan struct{}
	connections  chan struct{}
}

type privateControlSession struct {
	serviceID       string
	lifecycleEvents bool
	auditInputs     bool
	diagnostics     bool
	lastDiagnostics time.Time
	send            chan any
	done            chan struct{}
	closeOnce       sync.Once
}

type privateControlFailureState struct {
	windowStarted time.Time
	count         uint8
	lastSeen      time.Time
}

type privateControlIdempotencyKey struct {
	serviceID string
	messageID string
}

type privateControlIdempotencyEntry struct {
	bodyHash  [sha256.Size]byte
	ack       *privateControlAck
	done      chan struct{}
	expiresAt time.Time
	completed bool
}

type privateControlHello struct {
	SchemaVersion       string `json:"schema_version"`
	Type                string `json:"type"`
	MessageID           string `json:"message_id"`
	ManagementServiceID string `json:"management_service_id"`
	WantLifecycleEvents *bool  `json:"want_lifecycle_events"`
	WantAuditInputs     *bool  `json:"want_audit_inputs"`
	WantDiagnostics     *bool  `json:"want_diagnostics"`
}

type privateControlPing struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
}

type privateControlRevokeServiceAdmission struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
	ChannelID     uint32 `json:"channel_id"`
	ServiceID     string `json:"service_id,omitempty"`
	GrantIDHash   string `json:"grant_id_hash,omitempty"`
	Reason        string `json:"reason"`
	DenyUntil     int64  `json:"deny_until"`
}

type privateControlAck struct {
	SchemaVersion           string `json:"schema_version"`
	Type                    string `json:"type"`
	MessageID               string `json:"message_id"`
	InReplyTo               string `json:"in_reply_to"`
	Outcome                 string `json:"outcome"`
	DenyUntil               int64  `json:"deny_until"`
	AffectedMembershipCount uint32 `json:"affected_membership_count"`
	TalkReleaseCount        uint32 `json:"talk_release_count"`
}

type privateControlCommandEnvelope struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
}

type privateControlHelloAck struct {
	SchemaVersion           string `json:"schema_version"`
	Type                    string `json:"type"`
	MessageID               string `json:"message_id"`
	InReplyTo               string `json:"in_reply_to"`
	SessionID               string `json:"session_id"`
	RelayID                 string `json:"relay_id"`
	LifecycleEventsAccepted bool   `json:"lifecycle_events_accepted"`
	AuditInputsAccepted     bool   `json:"audit_inputs_accepted"`
	DiagnosticsAccepted     bool   `json:"diagnostics_accepted"`
}

type privateControlPong struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
	InReplyTo     string `json:"in_reply_to"`
}

type privateControlGetRelayDiagnostics struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
}

type privateControlRelayDiagnosticsSnapshot struct {
	SchemaVersion  string                      `json:"schema_version"`
	Type           string                      `json:"type"`
	MessageID      string                      `json:"message_id"`
	InReplyTo      string                      `json:"in_reply_to"`
	RelayID        string                      `json:"relay_id"`
	CounterEpoch   string                      `json:"counter_epoch"`
	ObservedAt     string                      `json:"observed_at"`
	FloorInterrupt relayFloorInterruptCounters `json:"floor_interrupt"`
}

type privateControlError struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
	InReplyTo     string `json:"in_reply_to,omitempty"`
	Code          string `json:"code"`
}

type privateControlLifecycleEvent struct {
	SchemaVersion  string  `json:"schema_version"`
	Type           string  `json:"type"`
	MessageID      string  `json:"message_id"`
	OccurredAt     string  `json:"occurred_at"`
	EventType      string  `json:"event_type"`
	ChannelID      *uint32 `json:"channel_id"`
	SenderID       *uint32 `json:"sender_id,omitempty"`
	ServiceID      *string `json:"service_id,omitempty"`
	RecordingJobID *string `json:"recording_job_id,omitempty"`
	State          *string `json:"state,omitempty"`
	Reason         *string `json:"reason,omitempty"`
}

type privateControlFloorInterruptAudit struct {
	RequesterPriority uint8   `json:"requester_priority"`
	ReplacedSenderID  *uint32 `json:"replaced_sender_id"`
	ReplacedPriority  *uint8  `json:"replaced_priority"`
}

type privateControlAuditInput struct {
	SchemaVersion  string                             `json:"schema_version"`
	Type           string                             `json:"type"`
	MessageID      string                             `json:"message_id"`
	OccurredAt     string                             `json:"occurred_at"`
	Action         string                             `json:"action"`
	ActorType      string                             `json:"actor_type"`
	ActorID        string                             `json:"actor_id"`
	ChannelID      *uint32                            `json:"channel_id"`
	Result         string                             `json:"result"`
	FloorInterrupt *privateControlFloorInterruptAudit `json:"floor_interrupt,omitempty"`
}

func loadPrivateControlPolicy(path string) (privateControlPolicy, error) {
	if strings.TrimSpace(path) == "" {
		return privateControlPolicy{}, errors.New("private control services CSV is required")
	}
	rows, err := strictCSVRows(path, []string{"management_service_id", "certificate_sha256", "enabled"})
	if err != nil {
		return privateControlPolicy{}, err
	}
	policy := privateControlPolicy{byCertificate: make(map[string]string)}
	byService := make(map[string]struct{})
	byCertificate := make(map[string]struct{})
	for index, row := range rows {
		if !managedServiceIDPattern.MatchString(row[0]) || !managementHexPattern.MatchString(row[1]) {
			return privateControlPolicy{}, fmt.Errorf("private control services CSV row %d is invalid", index+2)
		}
		enabled, err := parseManagementBool(row[2])
		if err != nil {
			return privateControlPolicy{}, fmt.Errorf("private control services CSV row %d enabled: %w", index+2, err)
		}
		if _, exists := byService[row[0]]; exists {
			return privateControlPolicy{}, fmt.Errorf("private control services CSV row %d duplicates management_service_id", index+2)
		}
		if _, exists := byCertificate[row[1]]; exists {
			return privateControlPolicy{}, fmt.Errorf("private control services CSV row %d duplicates certificate_sha256", index+2)
		}
		byService[row[0]] = struct{}{}
		byCertificate[row[1]] = struct{}{}
		if enabled {
			policy.byCertificate[row[1]] = row[0]
		}
	}
	if len(policy.byCertificate) == 0 {
		return privateControlPolicy{}, errors.New("private control services CSV has no enabled service")
	}
	return policy, nil
}

func newPrivateControlLink(server *server, policy privateControlPolicy, relayID string, stateFile string) (*privateControlLink, error) {
	if server == nil || strings.TrimSpace(relayID) == "" || len(relayID) > 128 || len(policy.byCertificate) == 0 {
		return nil, errors.New("invalid private control link configuration")
	}
	return &privateControlLink{
		server: server, relayID: relayID, policy: policy, stateFile: stateFile, sessions: make(map[string]*privateControlSession),
		failures: make(map[string]privateControlFailureState), idempotency: make(map[privateControlIdempotencyKey]*privateControlIdempotencyEntry),
		commandSlots: make(chan struct{}, privateControlMaxCommands), connections: make(chan struct{}, privateControlMaxConnections),
	}, nil
}

func newPrivateControlID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func validPrivateControlID(value string) bool {
	if len(value) != 22 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 16 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validatePrivateControlJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return errors.New("invalid UTF-8 JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanPrivateControlJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func scanPrivateControlJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object member %q", key)
			}
			seen[key] = struct{}{}
			if err := scanPrivateControlJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			if err != nil {
				return err
			}
			return errors.New("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanPrivateControlJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			if err != nil {
				return err
			}
			return errors.New("JSON array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func decodePrivateControlJSON(raw []byte, target any) error {
	if err := validatePrivateControlJSON(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
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

func decodePrivateControlGrantIDHash(value string) (*[sha256.Size]byte, bool) {
	if value == "" {
		return nil, true
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, false
	}
	var hash [sha256.Size]byte
	copy(hash[:], decoded)
	return &hash, true
}

func validPrivateControlRevocation(message privateControlRevokeServiceAdmission) (serviceAdmissionRevocationTarget, bool) {
	if message.SchemaVersion != privateControlSchemaVersion || message.Type != "revoke_service_admission" ||
		!validPrivateControlID(message.MessageID) || message.DenyUntil < 1 || message.DenyUntil > privateControlMaxJSONInteger ||
		(message.ServiceID != "" && !managedServiceIDPattern.MatchString(message.ServiceID)) ||
		(message.Reason != "acl_removed" && message.Reason != "service_disabled" && message.Reason != "grant_revoked") {
		return serviceAdmissionRevocationTarget{}, false
	}
	grantIDHash, valid := decodePrivateControlGrantIDHash(message.GrantIDHash)
	if !valid || (message.ServiceID == "" && grantIDHash == nil) {
		return serviceAdmissionRevocationTarget{}, false
	}
	return serviceAdmissionRevocationTarget{channelID: message.ChannelID, serviceID: message.ServiceID, grantIDHash: grantIDHash}, true
}

func privateControlRevocationDigest(message privateControlRevokeServiceAdmission) ([sha256.Size]byte, error) {
	canonical, err := json.Marshal(message)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(canonical), nil
}

func (l *privateControlLink) cleanupIdempotencyLocked(now time.Time) {
	for key, entry := range l.idempotency {
		if entry.completed && entry.ack != nil && !entry.expiresAt.After(now) {
			delete(l.idempotency, key)
		}
	}
	for source, state := range l.failures {
		if now.Sub(state.lastSeen) > privateControlFailureWindow {
			delete(l.failures, source)
		}
	}
}

// beginRevocation returns a cached acknowledgement, a pending completion signal,
// or authority for this caller to execute the command exactly once.
func (l *privateControlLink) beginRevocation(serviceID string, messageID string, bodyHash [sha256.Size]byte, now time.Time) (cached *privateControlAck, pending <-chan struct{}, execute bool, conflict bool, overloaded bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupIdempotencyLocked(now)
	key := privateControlIdempotencyKey{serviceID: serviceID, messageID: messageID}
	if entry, found := l.idempotency[key]; found {
		if entry.bodyHash != bodyHash {
			return nil, nil, false, true, false
		}
		if entry.completed && entry.ack != nil {
			copy := *entry.ack
			return &copy, nil, false, false, false
		}
		return nil, entry.done, false, false, false
	}
	if len(l.idempotency) >= privateControlMaxIdempotency {
		return nil, nil, false, false, true
	}
	l.idempotency[key] = &privateControlIdempotencyEntry{bodyHash: bodyHash, done: make(chan struct{}), expiresAt: now.Add(privateControlIdempotencyTTL)}
	return nil, nil, true, false, false
}

// completeRevocation makes the acknowledgement and the matching deny rule
// durable before making a duplicate command observable as completed.
func (l *privateControlLink) completeRevocation(serviceID string, messageID string, bodyHash [sha256.Size]byte, ack *privateControlAck, now time.Time) error {
	l.mu.Lock()
	key := privateControlIdempotencyKey{serviceID: serviceID, messageID: messageID}
	entry := l.idempotency[key]
	if entry == nil || entry.bodyHash != bodyHash || entry.completed {
		l.mu.Unlock()
		return errors.New("private control idempotency entry is unavailable")
	}
	copy := *ack
	entry.ack = &copy
	// The state write occurs before the ACK is released. Reserve the complete
	// minimum cache interval after that write so a slow filesystem cannot make
	// the post-ACK retention shorter than the required ten minutes.
	entry.expiresAt = privateControlIdempotencyExpiry(copy, now.Add(privateControlIdempotencyTTL))
	l.mu.Unlock()

	if err := l.persistState(now); err != nil {
		l.abandonRevocation(serviceID, messageID, bodyHash)
		return fmt.Errorf("persist private control revocation: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	entry = l.idempotency[key]
	if entry == nil || entry.bodyHash != bodyHash || entry.completed || entry.ack == nil {
		return errors.New("private control idempotency entry changed during persistence")
	}
	entry.completed = true
	close(entry.done)
	return nil
}

func (l *privateControlLink) abandonRevocation(serviceID string, messageID string, bodyHash [sha256.Size]byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := privateControlIdempotencyKey{serviceID: serviceID, messageID: messageID}
	entry := l.idempotency[key]
	if entry == nil || entry.bodyHash != bodyHash || entry.completed {
		return
	}
	delete(l.idempotency, key)
	close(entry.done)
}

func (l *privateControlLink) cachedCompletedRevocation(serviceID string, messageID string, bodyHash [sha256.Size]byte) *privateControlAck {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry := l.idempotency[privateControlIdempotencyKey{serviceID: serviceID, messageID: messageID}]
	if entry == nil || entry.bodyHash != bodyHash || !entry.completed || entry.ack == nil {
		return nil
	}
	copy := *entry.ack
	return &copy
}

func (l *privateControlLink) acquireCommand() bool {
	select {
	case l.commandSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *privateControlLink) releaseCommand() {
	<-l.commandSlots
}

func (l *privateControlLink) acquireConnection() bool {
	select {
	case l.connections <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *privateControlLink) releaseConnection() {
	<-l.connections
}

func privateControlFailureSource(connection net.Conn) string {
	if connection == nil || connection.RemoteAddr() == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(connection.RemoteAddr().String())
	if err == nil && host != "" {
		return host
	}
	return connection.RemoteAddr().Network()
}

func (l *privateControlLink) allowConnectionAttempt(source string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupIdempotencyLocked(now)
	state, found := l.failures[source]
	if !found || now.Sub(state.windowStarted) >= privateControlFailureWindow {
		return true
	}
	return state.count < privateControlMaxFailures
}

func (l *privateControlLink) recordConnectionFailure(source string, reasonClass string) {
	now := time.Now()
	l.mu.Lock()
	l.cleanupIdempotencyLocked(now)
	state := l.failures[source]
	if state.windowStarted.IsZero() || now.Sub(state.windowStarted) >= privateControlFailureWindow {
		if len(l.failures) >= privateControlMaxFailureSources {
			var oldestSource string
			var oldestSeen time.Time
			for candidate, existing := range l.failures {
				if oldestSeen.IsZero() || existing.lastSeen.Before(oldestSeen) {
					oldestSource, oldestSeen = candidate, existing.lastSeen
				}
			}
			if oldestSource != "" {
				delete(l.failures, oldestSource)
			}
		}
		state = privateControlFailureState{windowStarted: now}
	}
	if state.count < ^uint8(0) {
		state.count++
	}
	state.lastSeen = now
	l.failures[source] = state
	count := state.count
	l.mu.Unlock()
	log.Printf("private_control_failure class=%s count=%d", reasonClass, count)
}

func readPrivateControlFrame(reader io.Reader) ([]byte, error) {
	var lengthBytes [4]byte
	if _, err := io.ReadFull(reader, lengthBytes[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(lengthBytes[:])
	if length < 2 || length > privateControlMaxFrameBytes {
		return nil, errors.New(privateControlMalformedConnection)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	if err := validatePrivateControlJSON(payload); err != nil {
		return nil, fmt.Errorf("%s: %w", privateControlMalformedConnection, err)
	}
	return payload, nil
}

func writePrivateControlFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) < 2 || len(payload) > privateControlMaxFrameBytes {
		return errors.New("private control outgoing frame size is invalid")
	}
	var lengthBytes [4]byte
	binary.BigEndian.PutUint32(lengthBytes[:], uint32(len(payload)))
	if err := writePrivateControlBytes(writer, lengthBytes[:]); err != nil {
		return err
	}
	return writePrivateControlBytes(writer, payload)
}

func writePrivateControlBytes(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func (s *privateControlSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
	})
}

func (s *privateControlSession) enqueue(message any) bool {
	select {
	case <-s.done:
		return false
	default:
	}
	select {
	case s.send <- message:
		return true
	default:
		return false
	}
}

func (l *privateControlLink) addSession(session *privateControlSession) {
	l.mu.Lock()
	previous := l.sessions[session.serviceID]
	l.sessions[session.serviceID] = session
	l.mu.Unlock()
	if previous != nil {
		previous.close()
	}
}

func (l *privateControlLink) removeSession(session *privateControlSession) {
	l.mu.Lock()
	if l.sessions[session.serviceID] == session {
		delete(l.sessions, session.serviceID)
	}
	l.mu.Unlock()
	session.close()
}

func (l *privateControlLink) enqueueLifecycleEvent(event privateControlLifecycleEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, session := range l.sessions {
		if session.lifecycleEvents && !session.enqueue(event) {
			l.dropped++
		}
	}
}

func (l *privateControlLink) enqueueAuditInput(input privateControlAuditInput) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, session := range l.sessions {
		if session.auditInputs && !session.enqueue(input) {
			l.dropped++
		}
	}
}

func (l *privateControlLink) publishLifecycleEvent(eventType string, channelID *uint32, senderID *uint32, serviceID *string, jobID *string, state *string, reason *string) {
	event, err := newPrivateControlLifecycleEvent(eventType, channelID, senderID, serviceID, jobID, state, reason)
	if err != nil {
		log.Printf("private control lifecycle event ID failed: %v", err)
		return
	}
	l.enqueueLifecycleEvent(event)
}

func (l *privateControlLink) publishFloorInterruptAudit(actorType string, actorID string, channelID uint32, requesterPriority uint8, result string, replacedSenderID *uint32, replacedPriority *uint8) {
	if actorType != "identity" && actorType != "service" || actorID == "" || (result != "success" && result != "denied" && result != "failed") {
		return
	}
	messageID, err := newPrivateControlID()
	if err != nil {
		log.Printf("private control audit input ID failed: %v", err)
		return
	}
	l.enqueueAuditInput(privateControlAuditInput{
		SchemaVersion: privateControlSchemaVersion,
		Type:          privateControlAuditInputType,
		MessageID:     messageID,
		OccurredAt:    time.Now().UTC().Format(time.RFC3339),
		Action:        "floor_interrupt",
		ActorType:     actorType,
		ActorID:       actorID,
		ChannelID:     uint32Pointer(channelID),
		Result:        result,
		FloorInterrupt: &privateControlFloorInterruptAudit{
			RequesterPriority: requesterPriority,
			ReplacedSenderID:  replacedSenderID,
			ReplacedPriority:  replacedPriority,
		},
	})
}

func newPrivateControlLifecycleEvent(eventType string, channelID *uint32, senderID *uint32, serviceID *string, jobID *string, state *string, reason *string) (privateControlLifecycleEvent, error) {
	messageID, err := newPrivateControlID()
	if err != nil {
		return privateControlLifecycleEvent{}, err
	}
	return privateControlLifecycleEvent{
		SchemaVersion:  privateControlSchemaVersion,
		Type:           privateControlLifecycleEventType,
		MessageID:      messageID,
		OccurredAt:     time.Now().UTC().Format(time.RFC3339),
		EventType:      eventType,
		ChannelID:      channelID,
		SenderID:       senderID,
		ServiceID:      serviceID,
		RecordingJobID: jobID,
		State:          state,
		Reason:         reason,
	}, nil
}

func (l *privateControlLink) startListener(config privateControlConfig) error {
	if err := validateSecretFilePermissions(config.privateKeyFile, "Private Control Link TLS private key", config.secretPermissions); err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(config.certificateFile, config.privateKeyFile)
	if err != nil {
		return fmt.Errorf("load private control server certificate: %w", err)
	}
	caData, err := os.ReadFile(config.clientCAFile)
	if err != nil {
		return fmt.Errorf("read private control client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caData) {
		return errors.New("private control client CA contains no certificates")
	}
	listener, err := net.Listen("tcp", config.listenAddress)
	if err != nil {
		return fmt.Errorf("private control listener: %w", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		MinVersion:   privateControlTLSMinVersion,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	})
	go l.acceptLoop(tlsListener)
	return nil
}

func (l *privateControlLink) acceptLoop(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Printf("private control listener failed: %v", err)
			return
		}
		if !l.acquireConnection() {
			_ = connection.Close()
			continue
		}
		go func(connection net.Conn) {
			defer l.releaseConnection()
			l.handleConnection(connection)
		}(connection)
	}
}

func privateControlServiceForConnection(connection *tls.Conn, policy privateControlPolicy) (string, error) {
	state := connection.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return "", errors.New("private control client certificate is missing")
	}
	digest := sha256.Sum256(state.PeerCertificates[0].Raw)
	serviceID, found := policy.byCertificate[hex.EncodeToString(digest[:])]
	if !found {
		return "", errors.New("private control client certificate is not authorized")
	}
	return serviceID, nil
}

func validPrivateControlHello(message privateControlHello) bool {
	return message.SchemaVersion == privateControlSchemaVersion && message.Type == "hello" &&
		validPrivateControlID(message.MessageID) && managedServiceIDPattern.MatchString(message.ManagementServiceID) &&
		message.WantLifecycleEvents != nil && message.WantAuditInputs != nil && message.WantDiagnostics != nil
}

func validPrivateControlPing(message privateControlPing) bool {
	return message.SchemaVersion == privateControlSchemaVersion && message.Type == "ping" && validPrivateControlID(message.MessageID)
}

func validPrivateControlGetRelayDiagnostics(message privateControlGetRelayDiagnostics) bool {
	return message.SchemaVersion == privateControlSchemaVersion && message.Type == "get_relay_diagnostics" && validPrivateControlID(message.MessageID)
}

func decodePrivateControlSelector(raw []byte) (privateControlCommandEnvelope, error) {
	var selector privateControlCommandEnvelope
	if err := json.Unmarshal(raw, &selector); err != nil {
		return privateControlCommandEnvelope{}, err
	}
	if selector.SchemaVersion != privateControlSchemaVersion || !validPrivateControlID(selector.MessageID) || selector.Type == "" {
		return privateControlCommandEnvelope{}, errors.New("private control message envelope is invalid")
	}
	return selector, nil
}

func (l *privateControlLink) handleRevocation(session *privateControlSession, raw []byte, selector privateControlCommandEnvelope) (any, bool) {
	var command privateControlRevokeServiceAdmission
	if err := decodePrivateControlJSON(raw, &command); err != nil {
		return nil, true
	}
	target, valid := validPrivateControlRevocation(command)
	if !valid {
		return nil, true
	}
	bodyHash, err := privateControlRevocationDigest(command)
	if err != nil {
		return nil, true
	}
	cached, pending, execute, conflict, overloaded := l.beginRevocation(session.serviceID, selector.MessageID, bodyHash, time.Now())
	if conflict {
		// Reusing a message ID with a different command body is a protocol error.
		return nil, true
	}
	if cached != nil {
		return *cached, false
	}
	if overloaded {
		response, err := newPrivateControlError(selector.MessageID, "overloaded")
		return response, err != nil
	}
	if pending != nil {
		select {
		case <-pending:
			if ack := l.cachedCompletedRevocation(session.serviceID, selector.MessageID, bodyHash); ack != nil {
				return *ack, false
			}
		case <-time.After(privateControlHelloDeadline):
		}
		response, err := newPrivateControlError(selector.MessageID, "overloaded")
		return response, err != nil
	}
	if !execute {
		response, err := newPrivateControlError(selector.MessageID, "overloaded")
		return response, err != nil
	}
	if !l.acquireCommand() {
		l.abandonRevocation(session.serviceID, selector.MessageID, bodyHash)
		response, err := newPrivateControlError(selector.MessageID, "overloaded")
		return response, err != nil
	}
	defer l.releaseCommand()

	if l.server == nil || l.server.serviceAdmission == nil || l.server.serviceAdmission.mode == serviceAdmissionOff {
		l.abandonRevocation(session.serviceID, selector.MessageID, bodyHash)
		response, err := newPrivateControlError(selector.MessageID, "unauthorized")
		return response, err != nil
	}
	now := time.Now()
	denyUntil := time.Unix(command.DenyUntil, 0)
	if denyUntil.After(now.Add(privateControlMaxDenyPeriod)) {
		l.abandonRevocation(session.serviceID, selector.MessageID, bodyHash)
		response, err := newPrivateControlError(selector.MessageID, "invalid_revocation_deadline")
		return response, err != nil
	}
	ackID, err := newPrivateControlID()
	if err != nil {
		l.abandonRevocation(session.serviceID, selector.MessageID, bodyHash)
		return nil, true
	}
	ack := privateControlAck{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "ack",
		MessageID:     ackID,
		InReplyTo:     selector.MessageID,
		DenyUntil:     command.DenyUntil,
	}
	if !denyUntil.After(now) {
		ack.Outcome = "already_expired"
	} else {
		result, applied := l.server.revokeManagedServiceAdmission(target, denyUntil, now)
		if !applied {
			l.abandonRevocation(session.serviceID, selector.MessageID, bodyHash)
			response, err := newPrivateControlError(selector.MessageID, "overloaded")
			return response, err != nil
		}
		ack.Outcome = "applied"
		ack.AffectedMembershipCount = result.affectedMemberships
		ack.TalkReleaseCount = result.talkReleases
	}
	if err := l.completeRevocation(session.serviceID, selector.MessageID, bodyHash, &ack, now); err != nil {
		response, responseErr := newPrivateControlError(selector.MessageID, "overloaded")
		return response, responseErr != nil
	}
	return ack, false
}

func (l *privateControlLink) handleRelayDiagnostics(session *privateControlSession, raw []byte, selector privateControlCommandEnvelope) (any, bool) {
	var request privateControlGetRelayDiagnostics
	if err := decodePrivateControlJSON(raw, &request); err != nil || !validPrivateControlGetRelayDiagnostics(request) {
		return nil, true
	}
	if !session.diagnostics {
		response, err := newPrivateControlError(selector.MessageID, privateControlUnsupportedMessage)
		return response, err != nil
	}
	now := time.Now()
	if !session.lastDiagnostics.IsZero() && now.Sub(session.lastDiagnostics) < privateControlDiagnosticsMinInterval {
		response, err := newPrivateControlError(selector.MessageID, "overloaded")
		return response, err != nil
	}
	if l.server == nil {
		response, err := newPrivateControlError(selector.MessageID, "internal_error")
		return response, err != nil
	}
	messageID, err := newPrivateControlID()
	if err != nil {
		response, responseErr := newPrivateControlError(selector.MessageID, "internal_error")
		return response, responseErr != nil
	}
	counterEpoch, counters := l.server.relayDiagnosticsSnapshot()
	session.lastDiagnostics = now
	return privateControlRelayDiagnosticsSnapshot{
		SchemaVersion:  privateControlSchemaVersion,
		Type:           "relay_diagnostics_snapshot",
		MessageID:      messageID,
		InReplyTo:      request.MessageID,
		RelayID:        l.relayID,
		CounterEpoch:   counterEpoch,
		ObservedAt:     now.UTC().Format(time.RFC3339Nano),
		FloorInterrupt: counters,
	}, false
}

func (l *privateControlLink) handleConnection(rawConnection net.Conn) {
	defer rawConnection.Close()
	connection, ok := rawConnection.(*tls.Conn)
	if !ok {
		return
	}
	source := privateControlFailureSource(connection)
	if !l.allowConnectionAttempt(source, time.Now()) {
		return
	}
	if err := connection.SetDeadline(time.Now().Add(privateControlHelloDeadline)); err != nil {
		return
	}
	if err := connection.Handshake(); err != nil {
		l.recordConnectionFailure(source, "handshake")
		return
	}
	serviceID, err := privateControlServiceForConnection(connection, l.policy)
	if err != nil {
		l.recordConnectionFailure(source, "authorization")
		return
	}
	rawHello, err := readPrivateControlFrame(connection)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			l.recordConnectionFailure(source, "frame")
		}
		return
	}
	var hello privateControlHello
	if err := decodePrivateControlJSON(rawHello, &hello); err != nil || !validPrivateControlHello(hello) {
		l.recordConnectionFailure(source, "hello")
		return
	}
	if hello.ManagementServiceID != serviceID {
		if response, err := newPrivateControlError(hello.MessageID, privateControlIdentityMismatch); err == nil {
			_ = l.writeDirect(connection, response)
		}
		return
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		return
	}
	session := &privateControlSession{
		serviceID:       serviceID,
		lifecycleEvents: *hello.WantLifecycleEvents,
		auditInputs:     *hello.WantAuditInputs,
		diagnostics:     *hello.WantDiagnostics,
		send:            make(chan any, privateControlSessionQueueDepth),
		done:            make(chan struct{}),
	}
	l.addSession(session)
	defer l.removeSession(session)
	go l.writeSession(connection, session)

	sessionID, err := newPrivateControlID()
	if err != nil {
		return
	}
	ackID, err := newPrivateControlID()
	if err != nil {
		return
	}
	if !session.enqueue(privateControlHelloAck{
		SchemaVersion:           privateControlSchemaVersion,
		Type:                    "hello_ack",
		MessageID:               ackID,
		InReplyTo:               hello.MessageID,
		SessionID:               sessionID,
		RelayID:                 l.relayID,
		LifecycleEventsAccepted: *hello.WantLifecycleEvents,
		AuditInputsAccepted:     *hello.WantAuditInputs,
		DiagnosticsAccepted:     *hello.WantDiagnostics,
	}) {
		return
	}
	if *hello.WantLifecycleEvents {
		health, err := newPrivateControlLifecycleEvent("relay_health_changed", nil, nil, nil, nil, stringPointer("healthy"), nil)
		if err != nil || !session.enqueue(health) {
			return
		}
	}

	for {
		rawMessage, err := readPrivateControlFrame(connection)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				l.recordConnectionFailure(source, "frame")
			}
			return
		}
		selector, err := decodePrivateControlSelector(rawMessage)
		if err != nil {
			l.recordConnectionFailure(source, "frame")
			return
		}
		switch selector.Type {
		case "ping":
			var ping privateControlPing
			if err := decodePrivateControlJSON(rawMessage, &ping); err != nil || !validPrivateControlPing(ping) {
				l.recordConnectionFailure(source, "schema")
				return
			}
			pongID, err := newPrivateControlID()
			if err != nil || !session.enqueue(privateControlPong{
				SchemaVersion: privateControlSchemaVersion,
				Type:          "pong",
				MessageID:     pongID,
				InReplyTo:     ping.MessageID,
			}) {
				return
			}
		case "revoke_service_admission":
			response, closeConnection := l.handleRevocation(session, rawMessage, selector)
			if closeConnection || response == nil || !session.enqueue(response) {
				if closeConnection {
					l.recordConnectionFailure(source, "command")
				}
				return
			}
		case "get_relay_diagnostics":
			response, closeConnection := l.handleRelayDiagnostics(session, rawMessage, selector)
			if closeConnection || response == nil || !session.enqueue(response) {
				if closeConnection {
					l.recordConnectionFailure(source, "command")
				}
				return
			}
		default:
			response, err := newPrivateControlError(selector.MessageID, privateControlUnsupportedMessage)
			if err != nil || !session.enqueue(response) {
				return
			}
		}
	}
}

func newPrivateControlError(inReplyTo string, code string) (privateControlError, error) {
	messageID, err := newPrivateControlID()
	if err != nil {
		return privateControlError{}, err
	}
	return privateControlError{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "error",
		MessageID:     messageID,
		InReplyTo:     inReplyTo,
		Code:          code,
	}, nil
}

func (l *privateControlLink) writeDirect(connection net.Conn, message any) error {
	return writePrivateControlFrame(connection, message)
}

func (l *privateControlLink) writeSession(connection net.Conn, session *privateControlSession) {
	defer connection.Close()
	for {
		select {
		case <-session.done:
			return
		case message := <-session.send:
			if err := writePrivateControlFrame(connection, message); err != nil {
				return
			}
		}
	}
}

func startPrivateControlLink(server *server, config privateControlConfig) (*privateControlLink, error) {
	if strings.TrimSpace(config.listenAddress) == "" || strings.TrimSpace(config.certificateFile) == "" ||
		strings.TrimSpace(config.privateKeyFile) == "" || strings.TrimSpace(config.clientCAFile) == "" ||
		strings.TrimSpace(config.servicesCSV) == "" || strings.TrimSpace(config.relayID) == "" {
		return nil, errors.New("private control listener, TLS certificate/key, client CA, services CSV, and relay ID are required")
	}
	revocationEnabled := server != nil && server.serviceAdmission != nil && server.serviceAdmission.mode != serviceAdmissionOff
	if revocationEnabled && strings.TrimSpace(config.stateFile) == "" {
		return nil, errors.New("private control state file is required when managed service admission is enabled")
	}
	policy, err := loadPrivateControlPolicy(config.servicesCSV)
	if err != nil {
		return nil, err
	}
	link, err := newPrivateControlLink(server, policy, config.relayID, config.stateFile)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(config.stateFile) != "" {
		if err := link.restorePersistentState(time.Now()); err != nil {
			return nil, err
		}
	}
	if err := link.startListener(config); err != nil {
		return nil, err
	}
	server.privateControl = link
	return link, nil
}
