package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func newTestServiceAdmissionState() *serviceAdmissionState {
	return &serviceAdmissionState{
		mode:     serviceAdmissionEnabled,
		pending:  make(map[serviceAdmissionKey]servicePendingAdmission),
		verified: make(map[serviceAdmissionKey]serviceAdmission),
		failed:   make(map[serviceAdmissionKey]serviceAdmissionFailure),
		denied:   make(map[serviceAdmissionDenyRule]time.Time),
	}
}

func newTestServicePeer(addr *net.UDPAddr, senderID uint32, serviceID string, grantIDHash [sha256.Size]byte, activeUntil time.Time) *peer {
	return &peer{
		addr:               addr,
		senderId:           senderID,
		membershipDeadline: activeUntil,
		serviceAdmission: &serviceAdmission{
			serviceID:    serviceID,
			permissions:  identityPermissionListen | identityPermissionTalk,
			grantExpires: activeUntil,
			grantIDHash:  grantIDHash,
		},
	}
}

func TestPrivateControlRevocationIsChannelScopedAndIdempotent(t *testing.T) {
	relay := newTestUDPConn(t)
	endpointA := newTestUDPConn(t)
	endpointB := newTestUDPConn(t)
	endpointC := newTestUDPConn(t)
	endpointD := newTestUDPConn(t)
	s := newServer(relay, true, false, false, 0, false, 1)
	s.configureServiceAdmission(newTestServiceAdmissionState())
	until := time.Now().Add(time.Minute)
	grantA := sha256.Sum256([]byte("grant-a"))
	grantB := sha256.Sum256([]byte("grant-b"))

	matching := newTestServicePeer(endpointA.LocalAddr().(*net.UDPAddr), 1001, "recorder-01", grantA, until)
	serviceOnly := newTestServicePeer(endpointB.LocalAddr().(*net.UDPAddr), 1002, "recorder-01", grantB, until)
	grantOnly := newTestServicePeer(endpointC.LocalAddr().(*net.UDPAddr), 1003, "recorder-02", grantA, until)
	otherChannel := newTestServicePeer(endpointD.LocalAddr().(*net.UDPAddr), 1004, "recorder-01", grantA, until)
	s.channels[111] = &channel{
		peers: map[string]*peer{
			peerMapKey(matching.addr):    matching,
			peerMapKey(serviceOnly.addr): serviceOnly,
			peerMapKey(grantOnly.addr):   grantOnly,
		},
		activeTalkers:     map[uint32]time.Time{1001: time.Now(), 1002: time.Now(), 1003: time.Now()},
		codecConfigs:      make(map[uint32][]byte),
		mediaCodecConfigs: make(map[uint32]codecConfigState),
	}
	s.channels[222] = &channel{
		peers:             map[string]*peer{peerMapKey(otherChannel.addr): otherChannel},
		activeTalkers:     map[uint32]time.Time{1004: time.Now()},
		codecConfigs:      make(map[uint32][]byte),
		mediaCodecConfigs: make(map[uint32]codecConfigState),
	}

	link := newTestPrivateControlLink(t, s)
	command := privateControlRevokeServiceAdmission{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "revoke_service_admission",
		MessageID:     "MDEyMzQ1Njc4OTo7PD0-Pw",
		ChannelID:     111,
		ServiceID:     "recorder-01",
		GrantIDHash:   base64.RawURLEncoding.EncodeToString(grantA[:]),
		Reason:        "grant_revoked",
		DenyUntil:     time.Now().Add(time.Minute).Unix(),
	}
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	response, closeConnection := link.handleRevocation(&privateControlSession{serviceID: "management-main"}, raw, privateControlCommandEnvelope{SchemaVersion: privateControlSchemaVersion, Type: command.Type, MessageID: command.MessageID})
	if closeConnection {
		t.Fatal("valid revocation closed the private control session")
	}
	ack, ok := response.(privateControlAck)
	if !ok || ack.Outcome != "applied" || ack.DenyUntil != command.DenyUntil || ack.AffectedMembershipCount != 1 || ack.TalkReleaseCount != 1 {
		t.Fatalf("revocation acknowledgement = %#v", response)
	}
	release := receiveTestPacket(t, endpointA)
	if release.Header.Type != pktTalkRelease || release.Header.ChannelId != 111 || release.Header.SenderId != 1001 || len(release.Payload) != 5 || release.Payload[4] != talkReleaseServiceRevoked {
		t.Fatalf("revoked service release = type=%d channel=%d sender=%d payload=%x", release.Header.Type, release.Header.ChannelId, release.Header.SenderId, release.Payload)
	}
	if _, found := s.channels[111].peers[peerMapKey(matching.addr)]; found {
		t.Fatal("intersection-matching membership was retained")
	}
	for _, retained := range []*peer{serviceOnly, grantOnly} {
		if _, found := s.channels[111].peers[peerMapKey(retained.addr)]; !found {
			t.Fatal("intersection revocation widened to a partial target match")
		}
	}
	if _, found := s.channels[222].peers[peerMapKey(otherChannel.addr)]; !found {
		t.Fatal("channel-scoped revocation removed another channel membership")
	}

	repeated, closeConnection := link.handleRevocation(&privateControlSession{serviceID: "management-main"}, raw, privateControlCommandEnvelope{SchemaVersion: privateControlSchemaVersion, Type: command.Type, MessageID: command.MessageID})
	if closeConnection {
		t.Fatal("idempotent duplicate closed the private control session")
	}
	cached, ok := repeated.(privateControlAck)
	if !ok || cached.MessageID != ack.MessageID || cached.TalkReleaseCount != 1 {
		t.Fatalf("duplicate acknowledgement = %#v", repeated)
	}

	command.DenyUntil++
	changedRaw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	_, closeConnection = link.handleRevocation(&privateControlSession{serviceID: "management-main"}, changedRaw, privateControlCommandEnvelope{SchemaVersion: privateControlSchemaVersion, Type: command.Type, MessageID: command.MessageID})
	if !closeConnection {
		t.Fatal("message ID reuse with a different revocation body was accepted")
	}
}

func TestPrivateControlRevocationRestoresDurableIdempotency(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, true, false, false, 0, false, 1)
	s.configureServiceAdmission(newTestServiceAdmissionState())
	link := newTestPrivateControlLink(t, s)
	command := privateControlRevokeServiceAdmission{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "revoke_service_admission",
		MessageID:     "QkNERUZHSElKS0xNTk9QUQ",
		ChannelID:     111,
		ServiceID:     "recorder-01",
		Reason:        "service_disabled",
		DenyUntil:     time.Now().Add(time.Hour).Unix(),
	}
	raw, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	first, closeConnection := link.handleRevocation(&privateControlSession{serviceID: "management-main"}, raw, privateControlCommandEnvelope{SchemaVersion: privateControlSchemaVersion, Type: command.Type, MessageID: command.MessageID})
	if closeConnection {
		t.Fatal("initial durable revocation closed the session")
	}
	firstAck, ok := first.(privateControlAck)
	if !ok || firstAck.Outcome != "applied" || firstAck.DenyUntil != command.DenyUntil {
		t.Fatalf("initial durable acknowledgement = %#v", first)
	}

	restarted, err := newPrivateControlLink(s, link.policy, link.relayID, link.stateFile)
	if err != nil {
		t.Fatalf("recreate private control link: %v", err)
	}
	if err := restarted.restorePersistentState(time.Now()); err != nil {
		t.Fatalf("restore private control state: %v", err)
	}
	repeated, closeConnection := restarted.handleRevocation(&privateControlSession{serviceID: "management-main"}, raw, privateControlCommandEnvelope{SchemaVersion: privateControlSchemaVersion, Type: command.Type, MessageID: command.MessageID})
	if closeConnection {
		t.Fatal("restored duplicate closed the session")
	}
	repeatedAck, ok := repeated.(privateControlAck)
	if !ok || repeatedAck.MessageID != firstAck.MessageID || repeatedAck.DenyUntil != command.DenyUntil || repeatedAck.Outcome != "applied" {
		t.Fatalf("restored duplicate acknowledgement = %#v", repeated)
	}
	rules := s.serviceAdmission.activeDenyRules(time.Now())
	if len(rules) != 1 || rules[0].expiresAt.Unix() != command.DenyUntil {
		t.Fatalf("restored deny rules = %#v", rules)
	}
}

func TestPrivateControlRevocationDeadlineSemantics(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, true, false, false, 0, false, 1)
	s.configureServiceAdmission(newTestServiceAdmissionState())
	link := newTestPrivateControlLink(t, s)
	session := &privateControlSession{serviceID: "management-main"}

	expiredID, err := newPrivateControlID()
	if err != nil {
		t.Fatal(err)
	}
	expired := privateControlRevokeServiceAdmission{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "revoke_service_admission",
		MessageID:     expiredID,
		ChannelID:     111,
		ServiceID:     "recorder-01",
		Reason:        "grant_revoked",
		DenyUntil:     time.Now().Add(-time.Minute).Unix(),
	}
	rawExpired, err := json.Marshal(expired)
	if err != nil {
		t.Fatal(err)
	}
	response, closeConnection := link.handleRevocation(session, rawExpired, privateControlCommandEnvelope{SchemaVersion: privateControlSchemaVersion, Type: expired.Type, MessageID: expired.MessageID})
	if closeConnection {
		t.Fatal("expired revocation closed the session")
	}
	ack, ok := response.(privateControlAck)
	if !ok || ack.Outcome != "already_expired" || ack.DenyUntil != expired.DenyUntil || ack.AffectedMembershipCount != 0 || ack.TalkReleaseCount != 0 {
		t.Fatalf("expired revocation acknowledgement = %#v", response)
	}

	tooFarID, err := newPrivateControlID()
	if err != nil {
		t.Fatal(err)
	}
	tooFar := expired
	tooFar.MessageID = tooFarID
	tooFar.DenyUntil = time.Now().Add(privateControlMaxDenyPeriod + time.Minute).Unix()
	rawTooFar, err := json.Marshal(tooFar)
	if err != nil {
		t.Fatal(err)
	}
	response, closeConnection = link.handleRevocation(session, rawTooFar, privateControlCommandEnvelope{SchemaVersion: privateControlSchemaVersion, Type: tooFar.Type, MessageID: tooFar.MessageID})
	if closeConnection {
		t.Fatal("invalid deadline closed the session")
	}
	protocolError, ok := response.(privateControlError)
	if !ok || protocolError.Code != "invalid_revocation_deadline" {
		t.Fatalf("invalid deadline response = %#v", response)
	}
}

func TestManagedServiceIDGrammarIsSharedByPCL(t *testing.T) {
	for _, serviceID := range []string{"recorder", "recorder-east", "recorder.east_01", "R1"} {
		if !managedServiceIDPattern.MatchString(serviceID) {
			t.Fatalf("valid Management Service ID rejected: %q", serviceID)
		}
	}
	for _, serviceID := range []string{"", ".recorder", "_recorder", ":recorder", "recorder:east", "recorder east", string(make([]byte, 129))} {
		if managedServiceIDPattern.MatchString(serviceID) {
			t.Fatalf("invalid Management Service ID accepted: %q", serviceID)
		}
	}
	value := true
	invalidServiceID := "recorder:east"
	if validPrivateControlHello(privateControlHello{SchemaVersion: privateControlSchemaVersion, Type: "hello", MessageID: "MDEyMzQ1Njc4OTo7PD0-Pw", ManagementServiceID: invalidServiceID, WantLifecycleEvents: &value, WantAuditInputs: &value, WantDiagnostics: &value}) {
		t.Fatal("PCL hello accepted a noncanonical Management Service ID")
	}
	if _, valid := validPrivateControlRevocation(privateControlRevokeServiceAdmission{SchemaVersion: privateControlSchemaVersion, Type: "revoke_service_admission", MessageID: "MDEyMzQ1Njc4OTo7PD0-Pw", ChannelID: 111, ServiceID: invalidServiceID, Reason: "service_disabled", DenyUntil: time.Now().Add(time.Minute).Unix()}); valid {
		t.Fatal("PCL revocation accepted a noncanonical Management Service ID")
	}
	if _, valid := validPrivateControlRevocation(privateControlRevokeServiceAdmission{SchemaVersion: privateControlSchemaVersion, Type: "revoke_service_admission", MessageID: "MDEyMzQ1Njc4OTo7PD0-Pw", ChannelID: 111, ServiceID: "recorder-01", Reason: "service_disabled", DenyUntil: 0}); valid {
		t.Fatal("PCL revocation accepted a non-schema Unix timestamp")
	}
}

func TestPrivateControlRevocationDenyRuleExpires(t *testing.T) {
	state := newTestServiceAdmissionState()
	grantIDHash := sha256.Sum256([]byte("grant-a"))
	target := serviceAdmissionRevocationTarget{channelID: 111, serviceID: "recorder-01", grantIDHash: &grantIDHash}
	now := time.Now()
	if !state.installRevocation(target, now.Add(time.Second), now) {
		t.Fatal("install revocation deny rule")
	}
	admission := serviceAdmission{serviceID: "recorder-01", grantIDHash: grantIDHash}
	state.mu.Lock()
	denied := state.deniedLocked(111, admission)
	state.cleanupLocked(now.Add(2 * time.Second))
	expired := state.deniedLocked(111, admission)
	state.mu.Unlock()
	if !denied || expired {
		t.Fatalf("deny rule state denied=%t expired=%t", denied, expired)
	}
}

func TestServiceMembershipAttachmentRejectsInstalledDenyRule(t *testing.T) {
	relay := newTestUDPConn(t)
	endpoint := newTestUDPConn(t)
	s := newServer(relay, true, false, false, 0, false, 1)
	state := newTestServiceAdmissionState()
	s.configureServiceAdmission(state)
	now := time.Now()
	grantIDHash := sha256.Sum256([]byte("grant-a"))
	admission := serviceAdmission{serviceID: "recorder-01", grantIDHash: grantIDHash, grantExpires: now.Add(time.Minute)}
	address := endpoint.LocalAddr().(*net.UDPAddr)
	s.channels[111] = &channel{
		peers:             map[string]*peer{peerMapKey(address): {addr: address, senderId: 1001}},
		activeTalkers:     make(map[uint32]time.Time),
		codecConfigs:      make(map[uint32][]byte),
		mediaCodecConfigs: make(map[uint32]codecConfigState),
	}
	if !state.installRevocation(serviceAdmissionRevocationTarget{channelID: 111, serviceID: "recorder-01", grantIDHash: &grantIDHash}, now.Add(time.Minute), now) {
		t.Fatal("install deny rule")
	}
	if s.setPeerServiceAdmission(111, 1001, address, admission) {
		t.Fatal("service membership attached after matching deny rule")
	}
}

func TestPrivateControlFrameRejectsInvalidUTF8(t *testing.T) {
	payload := []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
	var frame bytes.Buffer
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(payload)))
	frame.Write(length[:])
	frame.Write(payload)
	if _, err := readPrivateControlFrame(&frame); err == nil {
		t.Fatal("invalid UTF-8 private control frame was accepted")
	}
}

func TestPrivateControlFailureRateLimitExpires(t *testing.T) {
	relay := newTestUDPConn(t)
	link := newTestPrivateControlLink(t, newServer(relay, false, false, false, 0, false, 1))
	now := time.Now()
	link.failures["test"] = privateControlFailureState{windowStarted: now, lastSeen: now, count: privateControlMaxFailures}
	if link.allowConnectionAttempt("test", now) {
		t.Fatal("failure-limited source was allowed immediately")
	}
	if !link.allowConnectionAttempt("test", now.Add(privateControlFailureWindow)) {
		t.Fatal("failure-limited source remained blocked after its rate window")
	}
}

func TestPrivateControlExportsFloorInterruptAuditInput(t *testing.T) {
	relay := newTestUDPConn(t)
	s := newServer(relay, false, false, false, 0, false, 1)
	link := newTestPrivateControlLink(t, s)
	s.privateControl = link
	session := &privateControlSession{serviceID: "management-main", auditInputs: true, send: make(chan any, 1), done: make(chan struct{})}
	link.addSession(session)
	t.Cleanup(func() { link.removeSession(session) })

	replacedSenderID := uint32(1002)
	replacedPriority := uint8(100)
	link.publishFloorInterruptAudit("service", "opaque-service-id", 111, 200, "success", &replacedSenderID, &replacedPriority)
	message := <-session.send
	audit, ok := message.(privateControlAuditInput)
	if !ok || audit.Type != privateControlAuditInputType || audit.Action != "floor_interrupt" || audit.ActorType != "service" || audit.ActorID != "opaque-service-id" || audit.ChannelID == nil || *audit.ChannelID != 111 || audit.FloorInterrupt == nil || audit.FloorInterrupt.RequesterPriority != 200 || audit.FloorInterrupt.ReplacedSenderID == nil || *audit.FloorInterrupt.ReplacedSenderID != 1002 {
		t.Fatalf("floor interrupt audit input = %#v", message)
	}
}

func TestPeerAdmissionAuditActorUsesServiceID(t *testing.T) {
	grantIDHash := sha256.Sum256([]byte("grant-a"))
	peer := newTestServicePeer(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 20000}, 1001, "automation-01", grantIDHash, time.Now().Add(time.Minute))
	actorType, actorID, ok := peerAdmissionAuditActor(peer)
	if !ok || actorType != "service" || actorID != "automation-01" {
		t.Fatalf("service audit actor = (%q, %q, %t)", actorType, actorID, ok)
	}
}
