package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	managementEventRetention = 4096
	managementAuditRetention = 10000
	managementGrantLifetime  = 5 * time.Minute
)

type managementService struct {
	serviceID string
	apiRole   string
	enabled   bool
	global    map[string]bool
}

type managementChannelACL struct {
	serviceID         string
	channelID         uint32
	senderID          uint32
	admissionRole     string
	allowListen       bool
	allowTalk         bool
	allowInterrupt    bool
	interruptPriority uint8
	enabled           bool
}

type managementPolicy struct {
	byCertificate map[string]*managementService
	byService     map[string]*managementService
	acls          map[string]map[uint32]map[uint32]managementChannelACL
}

type managementGrantSigner struct {
	keyID string
	key   ed25519.PrivateKey
}

type managementPlaneConfig struct {
	listenAddress        string
	certificateFile      string
	privateKeyFile       string
	clientCAFile         string
	servicesCSV          string
	channelACLCSV        string
	globalPermissionsCSV string
	signingKeyFile       string
	issuer               string
	audience             string
}

type managementEvent struct {
	SchemaVersion  string  `json:"schema_version"`
	EventID        string  `json:"event_id"`
	OccurredAt     string  `json:"occurred_at"`
	Type           string  `json:"type"`
	ChannelID      *uint32 `json:"channel_id"`
	SenderID       *uint32 `json:"sender_id,omitempty"`
	ServiceID      *string `json:"service_id,omitempty"`
	RecordingJobID *string `json:"recording_job_id,omitempty"`
	State          *string `json:"state,omitempty"`
	Reason         *string `json:"reason,omitempty"`
}

type managementFloorInterruptAudit struct {
	RequesterPriority uint8   `json:"requester_priority"`
	ReplacedSenderID  *uint32 `json:"replaced_sender_id"`
	ReplacedPriority  *uint8  `json:"replaced_priority"`
}

type managementRecordingJobAudit struct {
	JobID             string `json:"job_id"`
	RecorderServiceID string `json:"recorder_service_id"`
}

type managementAuditRecord struct {
	RecordID       string                         `json:"record_id"`
	Timestamp      string                         `json:"timestamp"`
	ActorType      string                         `json:"actor_type"`
	ActorID        string                         `json:"actor_id"`
	ChannelID      *uint32                        `json:"channel_id"`
	Action         string                         `json:"action"`
	Result         string                         `json:"result"`
	FloorInterrupt *managementFloorInterruptAudit `json:"floor_interrupt,omitempty"`
	RecordingJob   *managementRecordingJobAudit   `json:"recording_job,omitempty"`
	sequence       uint64
}

type managementRecordingJob struct {
	jobID             string
	channelID         uint32
	recorderServiceID string
	state             string
}

type managementSubscriber struct {
	service *managementService
	ch      chan managementEvent
}

type managementPlane struct {
	mu          sync.Mutex
	server      *server
	policy      managementPolicy
	signer      managementGrantSigner
	issuer      string
	audience    string
	events      []managementEvent
	eventNext   uint64
	subscribers map[uint64]managementSubscriber
	subscriberN uint64
	audit       []managementAuditRecord
	auditNext   uint64
	jobs        map[string]managementRecordingJob
	jobNext     uint64
	cursorKey   [32]byte
}

var managementServiceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var managementHexPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var managementActionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func strictCSVRows(path string, header []string) ([][]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	rows, err := csv.NewReader(file).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 || len(rows[0]) != len(header) {
		return nil, errors.New("missing or invalid CSV header")
	}
	for index, name := range header {
		if rows[0][index] != name {
			return nil, fmt.Errorf("CSV header column %d must be %q", index+1, name)
		}
	}
	for index, row := range rows[1:] {
		if len(row) != len(header) {
			return nil, fmt.Errorf("CSV row %d has %d fields; want %d", index+2, len(row), len(header))
		}
		for _, value := range row {
			if value == "" {
				return nil, fmt.Errorf("CSV row %d contains an empty field", index+2)
			}
		}
	}
	return rows[1:], nil
}

func parseManagementBool(value string) (bool, error) {
	if value == "true" {
		return true, nil
	}
	if value == "false" {
		return false, nil
	}
	return false, errors.New("must be lowercase true or false")
}

func parseManagementU32(value string, nonzero bool) (uint32, error) {
	if value == "" || strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "xX") {
		return 0, errors.New("must be an unsigned decimal integer")
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("must be an unsigned decimal integer")
	}
	if nonzero && parsed == 0 {
		return 0, errors.New("must be non-zero")
	}
	return uint32(parsed), nil
}

func loadManagementPolicy(servicesPath string, aclPath string, globalPermissionsPath string) (managementPolicy, error) {
	if strings.TrimSpace(servicesPath) == "" || strings.TrimSpace(aclPath) == "" {
		return managementPolicy{}, errors.New("management services and channel ACL CSV files are required")
	}
	policy := managementPolicy{
		byCertificate: make(map[string]*managementService),
		byService:     make(map[string]*managementService),
		acls:          make(map[string]map[uint32]map[uint32]managementChannelACL),
	}
	services, err := strictCSVRows(servicesPath, []string{"service_id", "certificate_sha256", "api_role", "enabled"})
	if err != nil {
		return managementPolicy{}, fmt.Errorf("management-services.csv: %w", err)
	}
	for index, row := range services {
		if !managementServiceIDPattern.MatchString(row[0]) || !managementHexPattern.MatchString(row[1]) {
			return managementPolicy{}, fmt.Errorf("management-services.csv row %d has invalid service ID or certificate digest", index+2)
		}
		if row[2] != "viewer" && row[2] != "recorder" && row[2] != "operator" && row[2] != "auditor" && row[2] != "admin" {
			return managementPolicy{}, fmt.Errorf("management-services.csv row %d has invalid api_role", index+2)
		}
		enabled, err := parseManagementBool(row[3])
		if err != nil {
			return managementPolicy{}, fmt.Errorf("management-services.csv row %d enabled: %w", index+2, err)
		}
		if _, exists := policy.byService[row[0]]; exists {
			return managementPolicy{}, fmt.Errorf("management-services.csv row %d duplicates service_id", index+2)
		}
		if _, exists := policy.byCertificate[row[1]]; exists {
			return managementPolicy{}, fmt.Errorf("management-services.csv row %d duplicates certificate_sha256", index+2)
		}
		service := &managementService{serviceID: row[0], apiRole: row[2], enabled: enabled, global: make(map[string]bool)}
		policy.byService[row[0]] = service
		policy.byCertificate[row[1]] = service
	}
	acls, err := strictCSVRows(aclPath, []string{"service_id", "channel_id", "sender_id", "admission_role", "allow_listen", "allow_talk", "allow_interrupt", "interrupt_priority", "enabled"})
	if err != nil {
		return managementPolicy{}, fmt.Errorf("management-channel-acl.csv: %w", err)
	}
	for index, row := range acls {
		service := policy.byService[row[0]]
		if service == nil || !service.enabled {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d references an unknown or disabled service", index+2)
		}
		channelID, err := parseManagementU32(row[1], false)
		if err != nil {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d channel_id: %w", index+2, err)
		}
		senderID, err := parseManagementU32(row[2], true)
		if err != nil {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d sender_id: %w", index+2, err)
		}
		if row[3] != "recorder" && row[3] != "observer" && row[3] != "automation" {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d admission_role is invalid", index+2)
		}
		listen, err := parseManagementBool(row[4])
		if err != nil {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d allow_listen: %w", index+2, err)
		}
		talk, err := parseManagementBool(row[5])
		if err != nil {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d allow_talk: %w", index+2, err)
		}
		interrupt, err := parseManagementBool(row[6])
		if err != nil {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d allow_interrupt: %w", index+2, err)
		}
		priority64, err := strconv.ParseUint(row[7], 10, 8)
		if err != nil || strconv.FormatUint(priority64, 10) != row[7] {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d interrupt_priority is invalid", index+2)
		}
		enabled, err := parseManagementBool(row[8])
		if err != nil {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d enabled: %w", index+2, err)
		}
		priority := uint8(priority64)
		if !listen || interrupt && (!talk || priority == 0) || !interrupt && priority != 0 ||
			((row[3] == "recorder" || row[3] == "observer") && (talk || interrupt || priority != 0)) {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d violates admission permission constraints", index+2)
		}
		if policy.acls[row[0]] == nil {
			policy.acls[row[0]] = make(map[uint32]map[uint32]managementChannelACL)
		}
		if policy.acls[row[0]][channelID] == nil {
			policy.acls[row[0]][channelID] = make(map[uint32]managementChannelACL)
		}
		if _, exists := policy.acls[row[0]][channelID][senderID]; exists {
			return managementPolicy{}, fmt.Errorf("management-channel-acl.csv row %d duplicates service/channel/sender", index+2)
		}
		policy.acls[row[0]][channelID][senderID] = managementChannelACL{serviceID: row[0], channelID: channelID, senderID: senderID, admissionRole: row[3], allowListen: listen, allowTalk: talk, allowInterrupt: interrupt, interruptPriority: priority, enabled: enabled}
	}
	if strings.TrimSpace(globalPermissionsPath) != "" {
		rows, err := strictCSVRows(globalPermissionsPath, []string{"service_id", "permission", "enabled"})
		if err != nil {
			return managementPolicy{}, fmt.Errorf("management-global-permissions.csv: %w", err)
		}
		for index, row := range rows {
			service := policy.byService[row[0]]
			if service == nil || !service.enabled || (row[1] != "health.read" && row[1] != "audit.read") {
				return managementPolicy{}, fmt.Errorf("management-global-permissions.csv row %d is invalid", index+2)
			}
			enabled, err := parseManagementBool(row[2])
			if err != nil {
				return managementPolicy{}, fmt.Errorf("management-global-permissions.csv row %d enabled: %w", index+2, err)
			}
			if _, exists := service.global[row[1]]; exists {
				return managementPolicy{}, fmt.Errorf("management-global-permissions.csv row %d duplicates service/permission", index+2)
			}
			service.global[row[1]] = enabled
		}
	}
	return policy, nil
}

func loadManagementGrantSigner(path string) (managementGrantSigner, error) {
	rows, err := strictCSVRows(path, []string{"kid", "ed25519_private_key_base64"})
	if err != nil {
		return managementGrantSigner{}, fmt.Errorf("management signing key: %w", err)
	}
	if len(rows) != 1 || rows[0][0] == "" || len(rows[0][0]) > 128 {
		return managementGrantSigner{}, errors.New("management signing key must contain exactly one valid key row")
	}
	decoded, err := base64.StdEncoding.DecodeString(rows[0][1])
	if err != nil {
		return managementGrantSigner{}, errors.New("management signing key must be standard Base64")
	}
	var privateKey ed25519.PrivateKey
	switch len(decoded) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(decoded)
	case ed25519.PrivateKeySize:
		privateKey = ed25519.PrivateKey(append([]byte(nil), decoded...))
	default:
		return managementGrantSigner{}, fmt.Errorf("management signing key must decode to %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
	return managementGrantSigner{keyID: rows[0][0], key: privateKey}, nil
}

func newManagementPlane(server *server, policy managementPolicy, signer managementGrantSigner, issuer string, audience string) (*managementPlane, error) {
	if server == nil || len(signer.key) != ed25519.PrivateKeySize || strings.TrimSpace(issuer) == "" || strings.TrimSpace(audience) == "" {
		return nil, errors.New("invalid management plane configuration")
	}
	plane := &managementPlane{server: server, policy: policy, signer: signer, issuer: issuer, audience: audience, subscribers: make(map[uint64]managementSubscriber), jobs: make(map[string]managementRecordingJob)}
	if _, err := rand.Read(plane.cursorKey[:]); err != nil {
		return nil, fmt.Errorf("generate management cursor key: %w", err)
	}
	return plane, nil
}

func newManagementAuditSink(server *server) *managementPlane {
	plane := &managementPlane{server: server, subscribers: make(map[uint64]managementSubscriber), jobs: make(map[string]managementRecordingJob)}
	// The cursor key is unused until a configured HTTPS listener replaces this
	// private in-process sink. Keep the sink available even on RNG failure.
	_, _ = rand.Read(plane.cursorKey[:])
	return plane
}

func (p *managementPlane) copyRetainedDataFrom(previous *managementPlane) {
	if p == nil || previous == nil || p == previous {
		return
	}
	previous.mu.Lock()
	defer previous.mu.Unlock()
	p.events = append(p.events, previous.events...)
	p.eventNext = previous.eventNext
	p.audit = append(p.audit, previous.audit...)
	p.auditNext = previous.auditNext
}

func startManagementPlane(server *server, config managementPlaneConfig) (*managementPlane, error) {
	if strings.TrimSpace(config.listenAddress) == "" || strings.TrimSpace(config.certificateFile) == "" || strings.TrimSpace(config.privateKeyFile) == "" || strings.TrimSpace(config.clientCAFile) == "" || strings.TrimSpace(config.signingKeyFile) == "" {
		return nil, errors.New("management listener, TLS certificate/key, client CA, and signing key files are required")
	}
	policy, err := loadManagementPolicy(config.servicesCSV, config.channelACLCSV, config.globalPermissionsCSV)
	if err != nil {
		return nil, err
	}
	signer, err := loadManagementGrantSigner(config.signingKeyFile)
	if err != nil {
		return nil, err
	}
	if server.serviceAdmission == nil {
		return nil, errors.New("direct Management Plane grant issuance requires managed service admission enabled")
	}
	verificationKey := server.serviceAdmission.keys[signer.keyID]
	if len(verificationKey) != ed25519.PublicKeySize || !bytes.Equal(verificationKey, signer.key.Public().(ed25519.PublicKey)) {
		return nil, errors.New("management signing key is not configured as a managed-service verification key")
	}
	certificate, err := tls.LoadX509KeyPair(config.certificateFile, config.privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load management server certificate: %w", err)
	}
	caData, err := os.ReadFile(config.clientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read management client CA: %w", err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caData) {
		return nil, errors.New("management client CA contains no certificates")
	}
	plane, err := newManagementPlane(server, policy, signer, config.issuer, config.audience)
	if err != nil {
		return nil, err
	}
	plane.copyRetainedDataFrom(server.management)
	server.management = plane
	httpServer := &http.Server{
		Addr:              config.listenAddress,
		Handler:           plane.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs},
	}
	go func() {
		if err := httpServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("management HTTPS listener failed: %v", err)
		}
	}()
	plane.publishEvent("relay_health_changed", nil, nil, nil, nil, stringPointer("healthy"), nil)
	return plane, nil
}

func (p *managementPlane) serviceForRequest(r *http.Request) (*managementService, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, false
	}
	digest := sha256.Sum256(r.TLS.PeerCertificates[0].Raw)
	p.mu.Lock()
	defer p.mu.Unlock()
	service := p.policy.byCertificate[hex.EncodeToString(digest[:])]
	return service, service != nil && service.enabled
}

func (p *managementPlane) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", p.withService(p.handleHealth))
	mux.HandleFunc("/v1/channels", p.withService(p.handleChannels))
	mux.HandleFunc("/v1/channels/", p.withService(p.handleParticipants))
	mux.HandleFunc("/v1/events", p.withService(p.handleEvents))
	mux.HandleFunc("/v1/audit-records", p.withService(p.handleAuditRecords))
	mux.HandleFunc("/v1/service-admission-grants", p.withService(p.handleServiceGrants))
	mux.HandleFunc("/v1/recording-jobs", p.withService(p.handleRecordingJobs))
	mux.HandleFunc("/v1/recording-jobs/", p.withService(p.handleRecordingJobStop))
	return mux
}

func (p *managementPlane) withService(next func(http.ResponseWriter, *http.Request, *managementService)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		service, ok := p.serviceForRequest(r)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r, service)
	}
}

func stringPointer(value string) *string { return &value }
func uint32Pointer(value uint32) *uint32 { return &value }
func uint8Pointer(value uint8) *uint8    { return &value }

func (p *managementPlane) hasChannelACL(serviceID string, channelID uint32) bool {
	for _, acl := range p.policy.acls[serviceID][channelID] {
		if acl.enabled && acl.allowListen {
			return true
		}
	}
	return false
}

func (p *managementPlane) hasAnyChannelACL(serviceID string) bool {
	for channelID := range p.policy.acls[serviceID] {
		if p.hasChannelACL(serviceID, channelID) {
			return true
		}
	}
	return false
}

func canView(service *managementService) bool {
	return service.apiRole == "viewer" || service.apiRole == "recorder" || service.apiRole == "operator"
}

func (p *managementPlane) canViewChannel(service *managementService, channelID uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return canView(service) && p.hasChannelACL(service.serviceID, channelID)
}

func (p *managementPlane) canAuditChannel(service *managementService, channelID uint32) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return service.apiRole == "auditor" && p.hasChannelACL(service.serviceID, channelID)
}

func (p *managementPlane) canGlobal(service *managementService, permission string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return service.global[permission]
}

func (p *managementPlane) eventAllowed(service *managementService, event managementEvent) bool {
	if event.ChannelID == nil {
		return event.Type == "relay_health_changed" && p.canGlobal(service, "health.read")
	}
	return p.canViewChannel(service, *event.ChannelID) || p.canAuditChannel(service, *event.ChannelID)
}

func (p *managementPlane) publishEvent(eventType string, channelID *uint32, senderID *uint32, serviceID *string, jobID *string, state *string, reason *string) {
	p.mu.Lock()
	p.eventNext++
	event := managementEvent{SchemaVersion: "management-event-v1", EventID: strconv.FormatUint(p.eventNext, 10), OccurredAt: time.Now().UTC().Format(time.RFC3339), Type: eventType, ChannelID: channelID, SenderID: senderID, ServiceID: serviceID, RecordingJobID: jobID, State: state, Reason: reason}
	p.events = append(p.events, event)
	if len(p.events) > managementEventRetention {
		p.events = append([]managementEvent(nil), p.events[len(p.events)-managementEventRetention:]...)
	}
	subscribers := make([]managementSubscriber, 0, len(p.subscribers))
	for _, subscriber := range p.subscribers {
		subscribers = append(subscribers, subscriber)
	}
	p.mu.Unlock()
	for _, subscriber := range subscribers {
		if p.eventAllowed(subscriber.service, event) {
			select {
			case subscriber.ch <- event:
			default:
			}
		}
	}
}

func (p *managementPlane) appendAudit(record managementAuditRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.auditNext++
	record.sequence = p.auditNext
	record.RecordID = fmt.Sprintf("audit-%012d", p.auditNext)
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	p.audit = append(p.audit, record)
	if len(p.audit) > managementAuditRetention {
		p.audit = append([]managementAuditRecord(nil), p.audit[len(p.audit)-managementAuditRetention:]...)
	}
}

func (p *managementPlane) handleHealth(w http.ResponseWriter, r *http.Request, service *managementService) {
	if r.Method != http.MethodGet || !p.canGlobal(service, "health.read") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	writeManagementJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (p *managementPlane) handleChannels(w http.ResponseWriter, r *http.Request, service *managementService) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	if !canView(service) || !p.hasAnyChannelACL(service.serviceID) {
		p.mu.Unlock()
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p.server.mu.Lock()
	channels := make([]map[string]uint32, 0)
	for channelID, channel := range p.server.channels {
		if p.hasChannelACL(service.serviceID, channelID) {
			channels = append(channels, map[string]uint32{"channel_id": channelID, "participant_count": uint32(len(channel.peers))})
		}
	}
	p.server.mu.Unlock()
	p.mu.Unlock()
	sort.Slice(channels, func(i, j int) bool { return channels[i]["channel_id"] < channels[j]["channel_id"] })
	writeManagementJSON(w, http.StatusOK, map[string]any{"channels": channels})
}

func (p *managementPlane) handleParticipants(w http.ResponseWriter, r *http.Request, service *managementService) {
	if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/participants") {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/channels/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != "participants" {
		http.NotFound(w, r)
		return
	}
	channelID, err := parseManagementU32(parts[0], false)
	if err != nil || !p.canViewChannel(service, channelID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p.server.mu.Lock()
	participants := make([]map[string]any, 0)
	if channel := p.server.channels[channelID]; channel != nil {
		for _, peer := range channel.peers {
			state := "idle"
			if _, talking := channel.activeTalkers[peer.senderId]; talking {
				state = "talking"
			}
			participants = append(participants, map[string]any{"sender_id": peer.senderId, "state": state})
		}
	}
	p.server.mu.Unlock()
	sort.Slice(participants, func(i, j int) bool {
		return participants[i]["sender_id"].(uint32) < participants[j]["sender_id"].(uint32)
	})
	writeManagementJSON(w, http.StatusOK, map[string]any{"channel_id": channelID, "participants": participants})
}

func (p *managementPlane) selectedEventCursor(r *http.Request) (uint64, bool, int) {
	value := r.Header.Get("Last-Event-ID")
	if value == "" {
		value = r.URL.Query().Get("since")
	}
	if value == "" {
		return 0, false, 0
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != value {
		return 0, true, http.StatusBadRequest
	}
	return parsed, true, 0
}

func (p *managementPlane) handleEvents(w http.ResponseWriter, r *http.Request, service *managementService) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p.mu.Lock()
	canStream := service.global["health.read"] || (canView(service) || service.apiRole == "auditor") && p.hasAnyChannelACL(service.serviceID)
	p.mu.Unlock()
	if !canStream {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	cursor, selected, status := p.selectedEventCursor(r)
	if status != 0 {
		http.Error(w, "invalid cursor", status)
		return
	}
	p.mu.Lock()
	if selected {
		found := false
		for _, event := range p.events {
			if event.EventID == strconv.FormatUint(cursor, 10) {
				found = true
				break
			}
		}
		if !found {
			p.mu.Unlock()
			http.Error(w, "cursor gone", http.StatusGone)
			return
		}
	}
	replay := make([]managementEvent, 0)
	if selected {
		for _, event := range p.events {
			id, _ := strconv.ParseUint(event.EventID, 10, 64)
			if id > cursor {
				replay = append(replay, event)
			}
		}
	}
	p.subscriberN++
	subscriberID := p.subscriberN
	subscriber := managementSubscriber{service: service, ch: make(chan managementEvent, 64)}
	p.subscribers[subscriberID] = subscriber
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		delete(p.subscribers, subscriberID)
		p.mu.Unlock()
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unavailable", http.StatusInternalServerError)
		return
	}
	for _, event := range replay {
		if p.eventAllowed(service, event) {
			writeManagementSSE(w, event)
		}
	}
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case event := <-subscriber.ch:
			writeManagementSSE(w, event)
			flusher.Flush()
		}
	}
}

func writeManagementSSE(w http.ResponseWriter, event managementEvent) {
	data, _ := json.Marshal(event)
	fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", event.EventID, event.Type, data)
}

func writeManagementJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

type managementAuditFilter struct {
	channelID *uint32
	since     *time.Time
	until     *time.Time
	action    string
	result    string
}

type managementAuditCursor struct {
	ServiceID string `json:"s"`
	Filter    string `json:"f"`
	Snapshot  uint64 `json:"n"`
	Offset    int    `json:"o"`
}

func parseManagementAuditFilter(r *http.Request) (managementAuditFilter, int) {
	query := r.URL.Query()
	filter := managementAuditFilter{action: query.Get("action"), result: query.Get("result")}
	if raw := query.Get("channel_id"); raw != "" {
		channelID, err := parseManagementU32(raw, false)
		if err != nil {
			return managementAuditFilter{}, http.StatusBadRequest
		}
		filter.channelID = uint32Pointer(channelID)
	}
	if raw := query.Get("since"); raw != "" {
		value, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return managementAuditFilter{}, http.StatusBadRequest
		}
		filter.since = &value
	}
	if raw := query.Get("until"); raw != "" {
		value, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return managementAuditFilter{}, http.StatusBadRequest
		}
		filter.until = &value
	}
	if filter.since != nil && filter.until != nil && !filter.since.Before(*filter.until) {
		return managementAuditFilter{}, http.StatusBadRequest
	}
	if filter.action != "" && !managementActionPattern.MatchString(filter.action) {
		return managementAuditFilter{}, http.StatusBadRequest
	}
	if filter.result != "" && filter.result != "success" && filter.result != "denied" && filter.result != "failed" {
		return managementAuditFilter{}, http.StatusBadRequest
	}
	return filter, 0
}

func (filter managementAuditFilter) key() string {
	channel := ""
	if filter.channelID != nil {
		channel = strconv.FormatUint(uint64(*filter.channelID), 10)
	}
	since, until := "", ""
	if filter.since != nil {
		since = filter.since.UTC().Format(time.RFC3339)
	}
	if filter.until != nil {
		until = filter.until.UTC().Format(time.RFC3339)
	}
	return strings.Join([]string{channel, since, until, filter.action, filter.result}, "\x00")
}

func (p *managementPlane) encodeAuditCursor(cursor managementAuditCursor) (string, error) {
	payload, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, p.cursorKey[:])
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (p *managementPlane) decodeAuditCursor(value string) (managementAuditCursor, bool) {
	segments := strings.Split(value, ".")
	if len(segments) != 2 {
		return managementAuditCursor{}, false
	}
	payload, ok := strictBase64URL(segments[0])
	if !ok {
		return managementAuditCursor{}, false
	}
	tag, ok := strictBase64URL(segments[1])
	if !ok || len(tag) != sha256.Size {
		return managementAuditCursor{}, false
	}
	mac := hmac.New(sha256.New, p.cursorKey[:])
	mac.Write(payload)
	if !hmac.Equal(tag, mac.Sum(nil)) {
		return managementAuditCursor{}, false
	}
	var cursor managementAuditCursor
	if json.Unmarshal(payload, &cursor) != nil || cursor.ServiceID == "" || cursor.Filter == "" || cursor.Snapshot == 0 || cursor.Offset < 0 {
		return managementAuditCursor{}, false
	}
	return cursor, true
}

func (p *managementPlane) canAuditRecordLocked(service *managementService, record managementAuditRecord) bool {
	if service.apiRole != "auditor" {
		return false
	}
	if record.ChannelID == nil {
		return service.global["audit.read"]
	}
	return p.hasChannelACL(service.serviceID, *record.ChannelID)
}

func recordMatchesAuditFilter(record managementAuditRecord, filter managementAuditFilter) bool {
	if filter.channelID != nil && (record.ChannelID == nil || *record.ChannelID != *filter.channelID) {
		return false
	}
	if filter.action != "" && record.Action != filter.action || filter.result != "" && record.Result != filter.result {
		return false
	}
	timestamp, err := time.Parse(time.RFC3339, record.Timestamp)
	if err != nil {
		return false
	}
	if filter.since != nil && timestamp.Before(*filter.since) || filter.until != nil && !timestamp.Before(*filter.until) {
		return false
	}
	return true
}

func (p *managementPlane) handleAuditRecords(w http.ResponseWriter, r *http.Request, service *managementService) {
	if r.Method != http.MethodGet || service.apiRole != "auditor" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	filter, status := parseManagementAuditFilter(r)
	if status != 0 {
		http.Error(w, "invalid audit query", status)
		return
	}
	if filter.channelID != nil && !p.canAuditChannel(service, *filter.channelID) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > 1000 {
			http.Error(w, "invalid audit limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	filterKey := filter.key()
	offset := 0
	p.mu.Lock()
	snapshot := p.auditNext
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		cursor, ok := p.decodeAuditCursor(raw)
		if !ok || cursor.ServiceID != service.serviceID || cursor.Filter != filterKey {
			p.mu.Unlock()
			http.Error(w, "invalid audit cursor", http.StatusBadRequest)
			return
		}
		if len(p.audit) > 0 && cursor.Snapshot < p.audit[0].sequence {
			p.mu.Unlock()
			http.Error(w, "audit cursor gone", http.StatusGone)
			return
		}
		snapshot, offset = cursor.Snapshot, cursor.Offset
	}
	records := make([]managementAuditRecord, 0)
	for index := len(p.audit) - 1; index >= 0; index-- {
		record := p.audit[index]
		if record.sequence <= snapshot && p.canAuditRecordLocked(service, record) && recordMatchesAuditFilter(record, filter) {
			records = append(records, record)
		}
	}
	p.mu.Unlock()
	if offset > len(records) {
		http.Error(w, "invalid audit cursor", http.StatusBadRequest)
		return
	}
	end := offset + limit
	if end > len(records) {
		end = len(records)
	}
	page := records[offset:end]
	var nextCursor *string
	if end < len(records) {
		encoded, err := p.encodeAuditCursor(managementAuditCursor{ServiceID: service.serviceID, Filter: filterKey, Snapshot: snapshot, Offset: end})
		if err != nil {
			http.Error(w, "audit cursor failure", http.StatusInternalServerError)
			return
		}
		nextCursor = &encoded
	}
	writeManagementJSON(w, http.StatusOK, map[string]any{"schema_version": "audit-retrieval-v1", "records": page, "next_cursor": nextCursor})
}

func decodeManagementJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

type serviceGrantRequest struct {
	ChannelID        uint32 `json:"channel_id"`
	SenderID         uint32 `json:"sender_id"`
	Role             string `json:"role"`
	RequestTalk      bool   `json:"request_talk"`
	RequestInterrupt bool   `json:"request_interrupt"`
	ServicePublicKey string `json:"service_public_key"`
}

func (p *managementPlane) issueGrant(service *managementService, request serviceGrantRequest) (string, time.Time, uint8, uint8, error) {
	if request.SenderID == 0 || request.Role != "recorder" && request.Role != "observer" && request.Role != "automation" {
		return "", time.Time{}, 0, 0, errors.New("invalid service grant request")
	}
	publicKeyRaw, ok := strictBase64URL(request.ServicePublicKey)
	if !ok || len(publicKeyRaw) != ed25519.PublicKeySize {
		return "", time.Time{}, 0, 0, errors.New("invalid service public key")
	}
	p.mu.Lock()
	acl := p.policy.acls[service.serviceID][request.ChannelID][request.SenderID]
	p.mu.Unlock()
	if !acl.enabled || acl.admissionRole != request.Role || !(service.apiRole == "recorder" || service.apiRole == "operator") || service.apiRole == "recorder" && request.Role != "recorder" {
		return "", time.Time{}, 0, 0, errors.New("service is not authorized for this grant")
	}
	if request.RequestTalk && !acl.allowTalk || request.RequestInterrupt && (!request.RequestTalk || !acl.allowInterrupt) {
		return "", time.Time{}, 0, 0, errors.New("requested permissions exceed the channel ACL")
	}
	permissions := uint8(identityPermissionListen)
	priority := uint8(0)
	if request.RequestTalk {
		permissions |= identityPermissionTalk
	}
	if request.RequestInterrupt {
		permissions |= identityPermissionInterrupt
		priority = acl.interruptPriority
	}
	if (request.Role == "recorder" || request.Role == "observer") && permissions != identityPermissionListen {
		return "", time.Time{}, 0, 0, errors.New("receive-only role cannot receive talk permissions")
	}
	var jtiBytes [16]byte
	if _, err := rand.Read(jtiBytes[:]); err != nil {
		return "", time.Time{}, 0, 0, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(managementGrantLifetime)
	digest := sha256.Sum256(publicKeyRaw)
	header, err := json.Marshal(serviceGrantHeader{Algorithm: "EdDSA", KeyID: p.signer.keyID, Type: "incomudon-service-admission+jwt"})
	if err != nil {
		return "", time.Time{}, 0, 0, err
	}
	claims := serviceGrantClaims{Issuer: p.issuer, Audience: p.audience, ServiceID: service.serviceID, GrantID: base64.RawURLEncoding.EncodeToString(jtiBytes[:]), IssuedAt: now.Unix(), ExpiresAt: expiresAt.Unix(), ChannelID: request.ChannelID, SenderID: request.SenderID, Role: request.Role, Permissions: permissions}
	if permissions == 7 {
		claims.Priority = &priority
	}
	claims.Confirmation.JWKThumbprint = base64.RawURLEncoding.EncodeToString(digest[:])
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, 0, 0, err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	grant := signingInput + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(p.signer.key, []byte(signingInput)))
	if len(grant) > serviceGrantMaxBytes {
		return "", time.Time{}, 0, 0, errors.New("generated service grant exceeds the protocol limit")
	}
	return grant, expiresAt, permissions, priority, nil
}

func (p *managementPlane) handleServiceGrants(w http.ResponseWriter, r *http.Request, service *managementService) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request serviceGrantRequest
	if err := decodeManagementJSON(r, &request); err != nil {
		http.Error(w, "invalid service grant request", http.StatusBadRequest)
		return
	}
	grant, expiresAt, _, _, err := p.issueGrant(service, request)
	if err != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p.appendAudit(managementAuditRecord{ActorType: "service", ActorID: service.serviceID, ChannelID: uint32Pointer(request.ChannelID), Action: "service_admission_issued", Result: "success"})
	p.publishEvent("service_admission_issued", uint32Pointer(request.ChannelID), uint32Pointer(request.SenderID), stringPointer(service.serviceID), nil, nil, nil)
	w.Header().Set("Cache-Control", "no-store")
	writeManagementJSON(w, http.StatusCreated, map[string]string{"grant": grant, "expires_at": expiresAt.Format(time.RFC3339)})
}

type recordingJobRequest struct {
	ChannelID uint32 `json:"channel_id"`
}

func (p *managementPlane) recordingAllowedLocked(service *managementService, channelID uint32) bool {
	return (service.apiRole == "recorder" || service.apiRole == "operator") && p.hasChannelACL(service.serviceID, channelID)
}

func (p *managementPlane) handleRecordingJobs(w http.ResponseWriter, r *http.Request, service *managementService) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var request recordingJobRequest
	if err := decodeManagementJSON(r, &request); err != nil {
		http.Error(w, "invalid recording request", http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	if !p.recordingAllowedLocked(service, request.ChannelID) {
		p.mu.Unlock()
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	p.jobNext++
	job := managementRecordingJob{jobID: fmt.Sprintf("recording-%012d", p.jobNext), channelID: request.ChannelID, recorderServiceID: service.serviceID, state: "starting"}
	p.jobs[job.jobID] = job
	p.mu.Unlock()
	p.appendAudit(managementAuditRecord{ActorType: "service", ActorID: service.serviceID, ChannelID: uint32Pointer(job.channelID), Action: "recording_create", Result: "success", RecordingJob: &managementRecordingJobAudit{JobID: job.jobID, RecorderServiceID: job.recorderServiceID}})
	p.publishEvent("recording_state_changed", uint32Pointer(job.channelID), nil, stringPointer(service.serviceID), stringPointer(job.jobID), stringPointer(job.state), nil)
	writeManagementJSON(w, http.StatusCreated, map[string]string{"job_id": job.jobID, "state": job.state})
}

func (p *managementPlane) handleRecordingJobStop(w http.ResponseWriter, r *http.Request, service *managementService) {
	if r.Method != http.MethodPost || !strings.HasSuffix(r.URL.Path, "/stop") {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jobID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/recording-jobs/"), "/stop")
	if jobID == "" || strings.Contains(jobID, "/") {
		http.NotFound(w, r)
		return
	}
	p.mu.Lock()
	job, exists := p.jobs[jobID]
	if !exists || !p.recordingAllowedLocked(service, job.channelID) {
		p.mu.Unlock()
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	job.state = "stopping"
	p.jobs[jobID] = job
	p.mu.Unlock()
	p.appendAudit(managementAuditRecord{ActorType: "service", ActorID: service.serviceID, ChannelID: uint32Pointer(job.channelID), Action: "recording_stop", Result: "success", RecordingJob: &managementRecordingJobAudit{JobID: job.jobID, RecorderServiceID: job.recorderServiceID}})
	p.publishEvent("recording_state_changed", uint32Pointer(job.channelID), nil, stringPointer(service.serviceID), stringPointer(job.jobID), stringPointer(job.state), nil)
	w.WriteHeader(http.StatusAccepted)
}

func (s *server) publishManagementEvent(eventType string, channelID *uint32, senderID *uint32, serviceID *string, jobID *string, state *string, reason *string) {
	if s.management != nil {
		s.management.publishEvent(eventType, channelID, senderID, serviceID, jobID, state, reason)
	}
}

func managementAdmissionActor(peer *peer) (string, string, bool) {
	if peer == nil {
		return "", "", false
	}
	if peer.identityAdmission != nil {
		return "identity", base64.RawURLEncoding.EncodeToString(peer.identityAdmission.actorIDHash[:]), true
	}
	if peer.serviceAdmission != nil {
		return "service", peer.serviceAdmission.serviceID, true
	}
	return "", "", false
}

func (s *server) auditFloorInterrupt(channelID uint32, requester *peer, priority uint8, result string, replacedSenderID *uint32, replacedPriority *uint8) {
	if s.management == nil {
		return
	}
	s.mu.Lock()
	actorType, actorID, ok := managementAdmissionActor(requester)
	s.mu.Unlock()
	if !ok {
		return
	}
	s.management.appendAudit(managementAuditRecord{ActorType: actorType, ActorID: actorID, ChannelID: uint32Pointer(channelID), Action: "floor_interrupt", Result: result, FloorInterrupt: &managementFloorInterruptAudit{RequesterPriority: priority, ReplacedSenderID: replacedSenderID, ReplacedPriority: replacedPriority}})
}

// revokeManagedServiceAdmission is the Relay-side target for a private,
// authenticated Management Service revocation update. The HTTPS API does not
// expose this privileged operation; deployments invoke it through their private
// management control link or policy reload path.
func (s *server) revokeManagedServiceAdmission(serviceID string, grantHash *[sha256.Size]byte) {
	if s.serviceAdmission != nil {
		s.serviceAdmission.revoke(grantHash, serviceID, time.Now())
	}
	type revokedPeer struct {
		channelID uint32
		senderID  uint32
		serviceID string
		active    bool
	}
	s.mu.Lock()
	revoked := make([]revokedPeer, 0)
	for channelID, channel := range s.channels {
		for key, peer := range channel.peers {
			if peer.serviceAdmission == nil ||
				(serviceID != "" && peer.serviceAdmission.serviceID != serviceID) ||
				(grantHash != nil && peer.serviceAdmission.grantHash != *grantHash) {
				continue
			}
			active := false
			if _, active = channel.activeTalkers[peer.senderId]; active {
				delete(channel.activeTalkers, peer.senderId)
			}
			revoked = append(revoked, revokedPeer{channelID: channelID, senderID: peer.senderId, serviceID: peer.serviceAdmission.serviceID, active: active})
			delete(channel.peers, key)
			delete(channel.codecConfigs, peer.senderId)
			delete(channel.mediaCodecConfigs, peer.senderId)
		}
		if len(channel.peers) == 0 {
			delete(s.channels, channelID)
		}
	}
	s.mu.Unlock()
	for _, peer := range revoked {
		if s.management != nil {
			s.management.appendAudit(managementAuditRecord{ActorType: "relay", ActorID: "relay", ChannelID: uint32Pointer(peer.channelID), Action: "service_admission_revoked", Result: "success"})
		}
		if peer.active {
			s.broadcastRelayControl(peer.channelID, pktTalkRelease, peer.senderID, talkReleasePayload(peer.senderID, talkReleaseServiceRevoked))
			s.publishManagementEvent("talk_ended", uint32Pointer(peer.channelID), uint32Pointer(peer.senderID), stringPointer(peer.serviceID), nil, nil, stringPointer("SERVICE_ADMISSION_REVOKED"))
		}
		s.publishManagementEvent("participant_left", uint32Pointer(peer.channelID), uint32Pointer(peer.senderID), stringPointer(peer.serviceID), nil, nil, stringPointer("SERVICE_ADMISSION_REVOKED"))
		s.publishManagementEvent("service_admission_revoked", uint32Pointer(peer.channelID), uint32Pointer(peer.senderID), stringPointer(peer.serviceID), nil, nil, stringPointer("SERVICE_ADMISSION_REVOKED"))
	}
}
