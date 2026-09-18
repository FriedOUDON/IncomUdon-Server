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
)

const (
	privateControlSchemaVersion       = "private-control-link-v1"
	privateControlMaxFrameBytes       = 65536
	privateControlSessionQueueDepth   = 256
	privateControlHelloDeadline       = 5 * time.Second
	privateControlTLSMinVersion       = tls.VersionTLS13
	privateControlLifecycleEventType  = "relay_lifecycle_event"
	privateControlUnsupportedMessage  = "unsupported_message"
	privateControlIdentityMismatch    = "identity_mismatch"
	privateControlMalformedConnection = "malformed private control frame"
)

type privateControlConfig struct {
	listenAddress   string
	certificateFile string
	privateKeyFile  string
	clientCAFile    string
	servicesCSV     string
	relayID         string
}

type privateControlPolicy struct {
	byCertificate map[string]string
}

type privateControlLink struct {
	relayID  string
	policy   privateControlPolicy
	mu       sync.Mutex
	sessions map[string]*privateControlSession
	dropped  uint64
}

type privateControlSession struct {
	serviceID       string
	lifecycleEvents bool
	send            chan any
	done            chan struct{}
	closeOnce       sync.Once
}

type privateControlHello struct {
	SchemaVersion       string `json:"schema_version"`
	Type                string `json:"type"`
	MessageID           string `json:"message_id"`
	ManagementServiceID string `json:"management_service_id"`
	WantLifecycleEvents *bool  `json:"want_lifecycle_events"`
	WantAuditInputs     *bool  `json:"want_audit_inputs"`
}

type privateControlPing struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
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
}

type privateControlPong struct {
	SchemaVersion string `json:"schema_version"`
	Type          string `json:"type"`
	MessageID     string `json:"message_id"`
	InReplyTo     string `json:"in_reply_to"`
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
		if !managementServiceIDPattern.MatchString(row[0]) || !managementHexPattern.MatchString(row[1]) {
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

func newPrivateControlLink(server *server, policy privateControlPolicy, relayID string) (*privateControlLink, error) {
	if server == nil || strings.TrimSpace(relayID) == "" || len(relayID) > 128 || len(policy.byCertificate) == 0 {
		return nil, errors.New("invalid private control link configuration")
	}
	return &privateControlLink{relayID: relayID, policy: policy, sessions: make(map[string]*privateControlSession)}, nil
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

func (l *privateControlLink) publishLifecycleEvent(eventType string, channelID *uint32, senderID *uint32, serviceID *string, jobID *string, state *string, reason *string) {
	event, err := newPrivateControlLifecycleEvent(eventType, channelID, senderID, serviceID, jobID, state, reason)
	if err != nil {
		log.Printf("private control lifecycle event ID failed: %v", err)
		return
	}
	l.enqueueLifecycleEvent(event)
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
		go l.handleConnection(connection)
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
		validPrivateControlID(message.MessageID) && managementServiceIDPattern.MatchString(message.ManagementServiceID) &&
		message.WantLifecycleEvents != nil && message.WantAuditInputs != nil
}

func validPrivateControlPing(message privateControlPing) bool {
	return message.SchemaVersion == privateControlSchemaVersion && message.Type == "ping" && validPrivateControlID(message.MessageID)
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

func (l *privateControlLink) handleConnection(rawConnection net.Conn) {
	defer rawConnection.Close()
	connection, ok := rawConnection.(*tls.Conn)
	if !ok {
		return
	}
	if err := connection.SetDeadline(time.Now().Add(privateControlHelloDeadline)); err != nil {
		return
	}
	if err := connection.Handshake(); err != nil {
		return
	}
	serviceID, err := privateControlServiceForConnection(connection, l.policy)
	if err != nil {
		return
	}
	rawHello, err := readPrivateControlFrame(connection)
	if err != nil {
		return
	}
	var hello privateControlHello
	if err := decodePrivateControlJSON(rawHello, &hello); err != nil || !validPrivateControlHello(hello) {
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
		AuditInputsAccepted:     false,
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
			return
		}
		selector, err := decodePrivateControlSelector(rawMessage)
		if err != nil {
			return
		}
		switch selector.Type {
		case "ping":
			var ping privateControlPing
			if err := decodePrivateControlJSON(rawMessage, &ping); err != nil || !validPrivateControlPing(ping) {
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
	policy, err := loadPrivateControlPolicy(config.servicesCSV)
	if err != nil {
		return nil, err
	}
	link, err := newPrivateControlLink(server, policy, config.relayID)
	if err != nil {
		return nil, err
	}
	if err := link.startListener(config); err != nil {
		return nil, err
	}
	server.privateControl = link
	return link, nil
}
