package main

import (
	"encoding/json"
	"errors"
	"sort"
)

const (
	privateControlSnapshotMaxChunks = 64
	// Leave room for frame metadata and future optional fields below the 64 KiB
	// PCL frame ceiling.
	privateControlSnapshotMaxJSONBytes = privateControlMaxFrameBytes - 1024
)

var errPrivateControlSnapshotTooLarge = errors.New("private control state snapshot exceeds bounded response limits")

// handleRelayStateSnapshot serializes snapshot chunks ahead of lifecycle
// events. This preserves a state boundary: mutations observed after capture
// are queued after the complete snapshot.
func (l *privateControlLink) handleRelayStateSnapshot(session *privateControlSession, raw []byte, selector privateControlCommandEnvelope) bool {
	var request privateControlGetRelayStateSnapshot
	if err := decodePrivateControlJSON(raw, &request); err != nil || !validPrivateControlGetRelayStateSnapshot(request) {
		return false
	}
	if l.server == nil {
		response, err := newPrivateControlError(selector.MessageID, "internal_error")
		return err == nil && session.enqueue(response)
	}

	l.eventMu.Lock()
	defer l.eventMu.Unlock()
	chunks, err := l.server.privateControlSnapshotChunks()
	if err != nil {
		response, responseErr := newPrivateControlError(selector.MessageID, "overloaded")
		return responseErr == nil && session.enqueue(response)
	}
	snapshotID, err := newPrivateControlID()
	if err != nil {
		return false
	}
	for index, channels := range chunks {
		messageID, err := newPrivateControlID()
		if err != nil {
			return false
		}
		if !session.enqueue(privateControlRelayStateSnapshot{
			SchemaVersion: privateControlSchemaVersion,
			Type:          "relay_state_snapshot",
			MessageID:     messageID,
			InReplyTo:     request.MessageID,
			SnapshotID:    snapshotID,
			ChunkIndex:    uint16(index),
			ChunkCount:    uint16(len(chunks)),
			Channels:      channels,
		}) {
			return false
		}
	}
	return true
}

func (s *server) privateControlSnapshotChunks() ([][]privateControlSnapshotChannel, error) {
	s.mu.Lock()
	channelIDs := make([]uint32, 0, len(s.channels))
	for channelID := range s.channels {
		channelIDs = append(channelIDs, channelID)
	}
	sort.Slice(channelIDs, func(i, j int) bool { return channelIDs[i] < channelIDs[j] })

	entries := make([]privateControlSnapshotChannel, 0, len(channelIDs))
	for _, channelID := range channelIDs {
		channel := s.channels[channelID]
		if channel == nil {
			continue
		}
		senderIDs := make([]uint32, 0, len(channel.peers))
		for _, peer := range channel.peers {
			if peer != nil {
				senderIDs = append(senderIDs, peer.senderId)
			}
		}
		sort.Slice(senderIDs, func(i, j int) bool { return senderIDs[i] < senderIDs[j] })
		participants := make([]privateControlSnapshotParticipant, 0, len(senderIDs))
		for _, senderID := range senderIDs {
			state := "idle"
			if _, talking := channel.activeTalkers[senderID]; talking {
				state = "talking"
			}
			participants = append(participants, privateControlSnapshotParticipant{SenderID: senderID, State: state})
		}
		entries = append(entries, privateControlSnapshotChannel{ChannelID: channelID, Participants: participants})
	}
	s.mu.Unlock()

	return privateControlChunkSnapshotEntries(entries)
}

func privateControlChunkSnapshotEntries(entries []privateControlSnapshotChannel) ([][]privateControlSnapshotChannel, error) {
	chunks := make([][]privateControlSnapshotChannel, 0, 1)
	current := make([]privateControlSnapshotChannel, 0, 1)
	appendChunk := func(entry privateControlSnapshotChannel) error {
		candidate := append(append([]privateControlSnapshotChannel(nil), current...), entry)
		if privateControlSnapshotChannelsFit(candidate) {
			current = candidate
			return nil
		}
		if len(current) == 0 {
			return errPrivateControlSnapshotTooLarge
		}
		chunks = append(chunks, current)
		current = []privateControlSnapshotChannel{entry}
		if !privateControlSnapshotChannelsFit(current) {
			return errPrivateControlSnapshotTooLarge
		}
		return nil
	}

	for _, entry := range entries {
		if len(entry.Participants) == 0 {
			if err := appendChunk(entry); err != nil {
				return nil, err
			}
			continue
		}
		batch := privateControlSnapshotChannel{ChannelID: entry.ChannelID}
		for _, participant := range entry.Participants {
			candidate := batch
			candidate.Participants = append(append([]privateControlSnapshotParticipant(nil), batch.Participants...), participant)
			if privateControlSnapshotChannelsFit([]privateControlSnapshotChannel{candidate}) {
				batch = candidate
				continue
			}
			if len(batch.Participants) == 0 {
				return nil, errPrivateControlSnapshotTooLarge
			}
			if err := appendChunk(batch); err != nil {
				return nil, err
			}
			batch = privateControlSnapshotChannel{ChannelID: entry.ChannelID, Participants: []privateControlSnapshotParticipant{participant}}
		}
		if err := appendChunk(batch); err != nil {
			return nil, err
		}
	}
	if len(current) > 0 {
		chunks = append(chunks, current)
	}
	if len(chunks) == 0 {
		chunks = append(chunks, []privateControlSnapshotChannel{})
	}
	if len(chunks) > privateControlSnapshotMaxChunks {
		return nil, errPrivateControlSnapshotTooLarge
	}
	return chunks, nil
}

func privateControlSnapshotChannelsFit(channels []privateControlSnapshotChannel) bool {
	probe := privateControlRelayStateSnapshot{
		SchemaVersion: privateControlSchemaVersion,
		Type:          "relay_state_snapshot",
		MessageID:     "AAAAAAAAAAAAAAAAAAAAAA",
		InReplyTo:     "AAAAAAAAAAAAAAAAAAAAAA",
		SnapshotID:    "AAAAAAAAAAAAAAAAAAAAAA",
		ChunkIndex:    privateControlSnapshotMaxChunks - 1,
		ChunkCount:    privateControlSnapshotMaxChunks,
		Channels:      channels,
	}
	payload, err := json.Marshal(probe)
	return err == nil && len(payload) <= privateControlSnapshotMaxJSONBytes
}
