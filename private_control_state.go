package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const privateControlStateSchemaVersion = "private-control-link-state-v1"

type privateControlPersistentRule struct {
	ChannelID   uint32 `json:"channel_id"`
	ServiceID   string `json:"service_id,omitempty"`
	GrantIDHash string `json:"grant_id_hash,omitempty"`
	DenyUntil   int64  `json:"deny_until"`
}

type privateControlPersistentIdempotency struct {
	ManagementServiceID string            `json:"management_service_id"`
	MessageID           string            `json:"message_id"`
	BodySHA256          string            `json:"body_sha256"`
	Ack                 privateControlAck `json:"ack"`
	ExpiresAt           int64             `json:"expires_at"`
}

type privateControlPersistentState struct {
	SchemaVersion string                                `json:"schema_version"`
	Rules         []privateControlPersistentRule        `json:"rules"`
	Idempotency   []privateControlPersistentIdempotency `json:"idempotency"`
}

func privateControlIdempotencyExpiry(ack privateControlAck, now time.Time) time.Time {
	expiresAt := now.Add(privateControlIdempotencyTTL)
	if ack.Outcome == "applied" {
		denyUntil := time.Unix(ack.DenyUntil, 0)
		if denyUntil.After(expiresAt) {
			expiresAt = denyUntil
		}
	}
	return expiresAt
}

func validPrivateControlAck(ack privateControlAck) bool {
	return ack.SchemaVersion == privateControlSchemaVersion && ack.Type == "ack" &&
		validPrivateControlID(ack.MessageID) && validPrivateControlID(ack.InReplyTo) &&
		(ack.Outcome == "applied" || ack.Outcome == "already_expired") && ack.DenyUntil >= 1 && ack.DenyUntil <= privateControlMaxJSONInteger &&
		(ack.Outcome != "already_expired" || (ack.AffectedMembershipCount == 0 && ack.TalkReleaseCount == 0))
}

func persistentRuleTarget(rule privateControlPersistentRule) (serviceAdmissionRevocationTarget, bool) {
	if rule.DenyUntil < 1 || rule.DenyUntil > privateControlMaxJSONInteger || (rule.ServiceID != "" && !managedServiceIDPattern.MatchString(rule.ServiceID)) {
		return serviceAdmissionRevocationTarget{}, false
	}
	grantIDHash, valid := decodePrivateControlGrantIDHash(rule.GrantIDHash)
	if !valid || (rule.ServiceID == "" && grantIDHash == nil) {
		return serviceAdmissionRevocationTarget{}, false
	}
	return serviceAdmissionRevocationTarget{channelID: rule.ChannelID, serviceID: rule.ServiceID, grantIDHash: grantIDHash}, true
}

func privateControlPersistentRuleFromEntry(entry serviceAdmissionDenyRuleEntry) privateControlPersistentRule {
	rule := privateControlPersistentRule{
		ChannelID: entry.rule.channelID,
		ServiceID: entry.rule.serviceID,
		DenyUntil: entry.expiresAt.Unix(),
	}
	if entry.rule.hasGrantIDHash {
		rule.GrantIDHash = base64.RawURLEncoding.EncodeToString(entry.rule.grantIDHash[:])
	}
	return rule
}

func decodePersistentBodyHash(value string) ([32]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return [32]byte{}, false
	}
	var digest [32]byte
	copy(digest[:], decoded)
	return digest, true
}

func loadPrivateControlPersistentState(path string) (privateControlPersistentState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return privateControlPersistentState{SchemaVersion: privateControlStateSchemaVersion}, nil
	}
	if err != nil {
		return privateControlPersistentState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state privateControlPersistentState
	if err := decoder.Decode(&state); err != nil {
		return privateControlPersistentState{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return privateControlPersistentState{}, errors.New("private control state contains multiple JSON values")
	}
	if state.SchemaVersion != privateControlStateSchemaVersion {
		return privateControlPersistentState{}, errors.New("unsupported private control state version")
	}
	return state, nil
}

func writePrivateControlPersistentState(path string, state privateControlPersistentState) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("private control state file is required")
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".private-control-state-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func (l *privateControlLink) persistentStateSnapshot(now time.Time) (privateControlPersistentState, error) {
	if l == nil || l.server == nil || l.server.serviceAdmission == nil {
		return privateControlPersistentState{}, errors.New("service admission state is unavailable")
	}
	state := privateControlPersistentState{SchemaVersion: privateControlStateSchemaVersion}
	for _, entry := range l.server.serviceAdmission.activeDenyRules(now) {
		state.Rules = append(state.Rules, privateControlPersistentRuleFromEntry(entry))
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupIdempotencyLocked(now)
	for key, entry := range l.idempotency {
		// An acknowledgement is written before its waiter is released. This
		// makes the command durable before a duplicate can observe completion.
		if entry.ack == nil || !entry.expiresAt.After(now) {
			continue
		}
		state.Idempotency = append(state.Idempotency, privateControlPersistentIdempotency{
			ManagementServiceID: key.serviceID,
			MessageID:           key.messageID,
			BodySHA256:          base64.RawURLEncoding.EncodeToString(entry.bodyHash[:]),
			Ack:                 *entry.ack,
			ExpiresAt:           entry.expiresAt.Unix(),
		})
	}
	return state, nil
}

func (l *privateControlLink) persistState(now time.Time) error {
	state, err := l.persistentStateSnapshot(now)
	if err != nil {
		return err
	}
	return writePrivateControlPersistentState(l.stateFile, state)
}

func (l *privateControlLink) restorePersistentState(now time.Time) error {
	if l == nil || strings.TrimSpace(l.stateFile) == "" {
		return errors.New("private control state file is required")
	}
	state, err := loadPrivateControlPersistentState(l.stateFile)
	if err != nil {
		return fmt.Errorf("read private control state: %w", err)
	}
	if len(state.Rules) > 0 && (l.server == nil || l.server.serviceAdmission == nil) {
		return errors.New("private control state requires managed service admission")
	}
	for _, rule := range state.Rules {
		target, valid := persistentRuleTarget(rule)
		if !valid {
			return errors.New("private control state contains an invalid deny rule")
		}
		denyUntil := time.Unix(rule.DenyUntil, 0)
		if !denyUntil.After(now) {
			continue
		}
		if !l.server.serviceAdmission.installRevocation(target, denyUntil, now) {
			return errors.New("restore private control deny rule")
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, persisted := range state.Idempotency {
		if !managedServiceIDPattern.MatchString(persisted.ManagementServiceID) || !validPrivateControlID(persisted.MessageID) ||
			!validPrivateControlAck(persisted.Ack) || persisted.Ack.InReplyTo != persisted.MessageID || persisted.ExpiresAt <= now.Unix() {
			return errors.New("private control state contains an invalid idempotency entry")
		}
		bodyHash, valid := decodePersistentBodyHash(persisted.BodySHA256)
		if !valid {
			return errors.New("private control state contains an invalid command digest")
		}
		key := privateControlIdempotencyKey{serviceID: persisted.ManagementServiceID, messageID: persisted.MessageID}
		if _, found := l.idempotency[key]; found {
			return errors.New("private control state contains duplicate idempotency entries")
		}
		ack := persisted.Ack
		done := make(chan struct{})
		close(done)
		l.idempotency[key] = &privateControlIdempotencyEntry{bodyHash: bodyHash, ack: &ack, done: done, expiresAt: time.Unix(persisted.ExpiresAt, 0), completed: true}
	}
	return nil
}
