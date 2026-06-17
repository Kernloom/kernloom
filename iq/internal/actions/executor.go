// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actions

import (
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/klshield/client"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/pep"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

// ShieldActionExecutor is the ONLY component in KLIQ authorised to call
// shieldpep.Adapter.TransitionV4 and TransitionV6.
//
// It receives an already-authorised ActionResolution from the PolicyResolver
// and translates it into the corresponding PEP call. It never makes policy
// decisions — that is the resolver's job.
//
// Additional PEP adapters (e.g. netfilter) register as PEPSidecar instances
// and are notified after every authorized transition.
type ShieldActionExecutor struct {
	adapter  *shieldpep.Adapter
	sidecars []PEPSidecar
}

// NewShieldActionExecutor creates an executor backed by the given Shield PEP adapter.
// Pass nil for adapter to run without Shield (netfilter-only mode).
func NewShieldActionExecutor(adapter *shieldpep.Adapter, sidecars ...PEPSidecar) *ShieldActionExecutor {
	return &ShieldActionExecutor{adapter: adapter, sidecars: sidecars}
}

// AddSidecar registers an additional PEP adapter to receive enforcement notifications.
func (e *ShieldActionExecutor) AddSidecar(s PEPSidecar) {
	e.sidecars = append(e.sidecars, s)
}

// Apply4 applies an authorised ActionResolution to an IPv4 source.
//
// This is the ONLY function in KLIQ that calls shieldpep.Adapter.TransitionV4.
//
// When r.Allowed is false the source is moved to LevelObserve (de-enforced) so
// that previously applied BPF entries are cleared. Keeping a denied source in an
// enforced state would be wrong: the policy said "no", so no enforcement.
func (e *ShieldActionExecutor) Apply4(
	ip [4]byte,
	st fsm.State,
	r ActionResolution,
	params shieldpep.EnforcementParams,
	now time.Time,
) (fsm.State, ActionResult) {
	result := ActionResult{
		ProposalID: r.ProposalID,
		DecisionID: r.DecisionID,
		Action:     r.RequestedAction,
		AppliedAt:  now,
	}

	if !r.Allowed {
		result.Status = "denied"
		result.Reason = r.DenyReason
		var newSt fsm.State
		if e.adapter != nil {
			newSt = e.adapter.TransitionV4(ip, st, fsm.LevelObserve, now, params) // ← authorized call
		} else {
			newSt = st
			newSt.Level = fsm.LevelObserve
		}
		e.notifySidecars4(ip, st.Level, fsm.LevelObserve, r.TTL)
		return newSt, result
	}

	level := ParseFSMLevel(r.ExecutableLevel)
	var newSt fsm.State
	if e.adapter != nil {
		newSt = e.adapter.TransitionV4(ip, st, level, now, params) // ← authorized call
	} else {
		newSt = st
		newSt.Level = level
	}
	e.notifySidecars4(ip, st.Level, level, r.TTL)

	if r.DenyReason != "" {
		result.Status = "downgraded"
	} else {
		result.Status = "applied"
	}
	result.Action = r.ExecutableAction
	result.Reason = r.DenyReason
	return newSt, result
}

func (e *ShieldActionExecutor) notifySidecars4(ip [4]byte, prev, next fsm.Level, ttl time.Duration) {
	for _, s := range e.sidecars {
		s.NotifyTransition4(ip, prev, next, ttl)
	}
}

// Apply6 applies an authorised ActionResolution to an IPv6 source.
//
// This is the ONLY function in KLIQ that calls shieldpep.Adapter.TransitionV6.
func (e *ShieldActionExecutor) Apply6(
	ip [16]byte,
	st fsm.State,
	r ActionResolution,
	params shieldpep.EnforcementParams,
	now time.Time,
) (fsm.State, ActionResult) {
	result := ActionResult{
		ProposalID: r.ProposalID,
		DecisionID: r.DecisionID,
		Action:     r.RequestedAction,
		AppliedAt:  now,
	}

	if !r.Allowed {
		result.Status = "denied"
		result.Reason = r.DenyReason
		var newSt fsm.State
		if e.adapter != nil {
			newSt = e.adapter.TransitionV6(ip, st, fsm.LevelObserve, now, params) // ← authorized call
		} else {
			newSt = st
			newSt.Level = fsm.LevelObserve
		}
		e.notifySidecars6(ip, st.Level, fsm.LevelObserve, r.TTL)
		return newSt, result
	}

	level := ParseFSMLevel(r.ExecutableLevel)
	var newSt fsm.State
	if e.adapter != nil {
		newSt = e.adapter.TransitionV6(ip, st, level, now, params) // ← authorized call
	} else {
		newSt = st
		newSt.Level = level
	}
	e.notifySidecars6(ip, st.Level, level, r.TTL)

	if r.DenyReason != "" {
		result.Status = "downgraded"
	} else {
		result.Status = "applied"
	}
	result.Action = r.ExecutableAction
	result.Reason = r.DenyReason
	return newSt, result
}

func (e *ShieldActionExecutor) notifySidecars6(ip [16]byte, prev, next fsm.Level, ttl time.Duration) {
	for _, s := range e.sidecars {
		s.NotifyTransition6(ip, prev, next, ttl)
	}
}

// ApplyDeEnforce4 moves an IPv4 source to LevelObserve unconditionally.
// Used for whitelist and feedback de-enforcement — always safe, always authorized,
// bypasses the resolver since removing enforcement never needs policy approval.
func (e *ShieldActionExecutor) ApplyDeEnforce4(
	ip [4]byte,
	st fsm.State,
	params shieldpep.EnforcementParams,
	now time.Time,
) fsm.State {
	var newSt fsm.State
	if e.adapter != nil {
		newSt = e.adapter.TransitionV4(ip, st, fsm.LevelObserve, now, params) // ← authorized call
	} else {
		newSt = st
		newSt.Level = fsm.LevelObserve
	}
	e.notifySidecars4(ip, st.Level, fsm.LevelObserve, 0)
	return newSt
}

// ApplyDeEnforce6 moves an IPv6 source to LevelObserve unconditionally.
func (e *ShieldActionExecutor) ApplyDeEnforce6(
	ip [16]byte,
	st fsm.State,
	params shieldpep.EnforcementParams,
	now time.Time,
) fsm.State {
	var newSt fsm.State
	if e.adapter != nil {
		newSt = e.adapter.TransitionV6(ip, st, fsm.LevelObserve, now, params) // ← authorized call
	} else {
		newSt = st
		newSt.Level = fsm.LevelObserve
	}
	e.notifySidecars6(ip, st.Level, fsm.LevelObserve, 0)
	return newSt
}

// ApplyTuple4 applies an authorized edge/tuple deny for an IPv4 (src, dst_port, proto)
// triple. Tuple enforcement is binary: block or nothing — there is no tuple-level
// rate-limiting yet. If the resolution downgrades below block the call is skipped.
//
// This is the ONLY function in KLIQ that calls shieldpep.Adapter.DenyEdge4.
func (e *ShieldActionExecutor) ApplyTuple4(
	key shieldclient.Edge4Key,
	r ActionResolution,
	now time.Time,
) ActionResult {
	result := ActionResult{
		ProposalID: r.ProposalID,
		Action:     r.RequestedAction,
		AppliedAt:  now,
	}

	if !r.Allowed {
		result.Status = "denied"
		result.Reason = r.DenyReason
		return result
	}

	if r.ExecutableLevel != "block" {
		// Policy downgraded below block — tuple-level RL not supported yet; skip.
		result.Status = "skipped"
		result.Reason = r.DenyReason
		return result
	}

	if err := e.adapter.DenyEdge4(key); err != nil { // ← authorized call
		result.Status = "failed"
		result.Reason = err.Error()
		return result
	}
	result.Status = "applied"
	result.Action = r.ExecutableAction
	return result
}
