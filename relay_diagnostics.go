package main

import (
	"fmt"
	"sync"
)

const relayDiagnosticsCounterMaximum uint64 = 9007199254740991

// relayFloorInterruptCounters is deliberately exhaustive: it is the complete
// redacted Floor Interrupt diagnostic surface exposed through the PCL.
type relayFloorInterruptCounters struct {
	PTTRequestsTotal            uint64 `json:"ptt_requests_total"`
	GrantsTotal                 uint64 `json:"grants_total"`
	DenialsTotal                uint64 `json:"denials_total"`
	PreemptionsTotal            uint64 `json:"preemptions_total"`
	UnauthorizedRejectionsTotal uint64 `json:"unauthorized_rejections_total"`
}

type relayFloorInterruptCounterDelta struct {
	pttRequests            uint64
	grants                 uint64
	denials                uint64
	preemptions            uint64
	unauthorizedRejections uint64
}

type relayDiagnosticsState struct {
	mu             sync.Mutex
	counterEpoch   string
	floorInterrupt relayFloorInterruptCounters
}

func newRelayDiagnosticsState() relayDiagnosticsState {
	counterEpoch, err := newPrivateControlID()
	if err != nil {
		// A PCL counter epoch must be generated from cryptographic randomness.
		// Continuing without one would violate the diagnostics identity contract.
		panic(fmt.Sprintf("generate Relay diagnostics counter epoch: %v", err))
	}
	return relayDiagnosticsState{counterEpoch: counterEpoch}
}

func (c relayFloorInterruptCounters) canAdd(delta relayFloorInterruptCounterDelta) bool {
	return delta.pttRequests <= relayDiagnosticsCounterMaximum-c.PTTRequestsTotal &&
		delta.grants <= relayDiagnosticsCounterMaximum-c.GrantsTotal &&
		delta.denials <= relayDiagnosticsCounterMaximum-c.DenialsTotal &&
		delta.preemptions <= relayDiagnosticsCounterMaximum-c.PreemptionsTotal &&
		delta.unauthorizedRejections <= relayDiagnosticsCounterMaximum-c.UnauthorizedRejectionsTotal
}

func (d *relayDiagnosticsState) observeFloorInterrupt(delta relayFloorInterruptCounterDelta) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.floorInterrupt.canAdd(delta) {
		counterEpoch, err := newPrivateControlID()
		if err != nil {
			panic(fmt.Sprintf("reset Relay diagnostics counter epoch: %v", err))
		}
		d.counterEpoch = counterEpoch
		d.floorInterrupt = relayFloorInterruptCounters{}
	}
	d.floorInterrupt.PTTRequestsTotal += delta.pttRequests
	d.floorInterrupt.GrantsTotal += delta.grants
	d.floorInterrupt.DenialsTotal += delta.denials
	d.floorInterrupt.PreemptionsTotal += delta.preemptions
	d.floorInterrupt.UnauthorizedRejectionsTotal += delta.unauthorizedRejections
}

func (d *relayDiagnosticsState) snapshot() (string, relayFloorInterruptCounters) {
	if d == nil {
		return "", relayFloorInterruptCounters{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.counterEpoch, d.floorInterrupt
}

func (d *relayDiagnosticsState) snapshotEpochOnly() (string, relayFloorInterruptCounters) {
	if d == nil {
		return "", relayFloorInterruptCounters{}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.counterEpoch, relayFloorInterruptCounters{}
}

func (s *server) observeFloorInterruptDiagnostics(delta relayFloorInterruptCounterDelta) {
	if s == nil || !s.floorInterrupt {
		return
	}
	s.diagnostics.observeFloorInterrupt(delta)
}

func (s *server) relayDiagnosticsSnapshot() (string, relayFloorInterruptCounters) {
	if s == nil {
		return "", relayFloorInterruptCounters{}
	}
	if !s.floorInterrupt {
		return s.diagnostics.snapshotEpochOnly()
	}
	return s.diagnostics.snapshot()
}
