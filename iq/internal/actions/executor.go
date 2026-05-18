// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actions

import (
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/shieldpep"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/shieldclient"
)

// ShieldActionExecutor is the ONLY component in KLIQ authorised to call
// shieldpep.Adapter.TransitionV4 and TransitionV6.
//
// It receives an already-authorised ActionResolution from the PolicyResolver
// and translates it into the corresponding PEP call. It never makes policy
// decisions — that is the resolver's job.
type ShieldActionExecutor struct {
	adapter *shieldpep.Adapter
}

// NewShieldActionExecutor creates an executor backed by the given Shield PEP adapter.
func NewShieldActionExecutor(adapter *shieldpep.Adapter) *ShieldActionExecutor {
	return &ShieldActionExecutor{adapter: adapter}
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
		// Policy denied the action — de-enforce to observe so no stale BPF entry remains.
		result.Status = "denied"
		result.Reason = r.DenyReason
		newSt := e.adapter.TransitionV4(ip, st, fsm.LevelObserve, now, params) // ← authorized call
		return newSt, result
	}

	level := ParseFSMLevel(r.ExecutableLevel)
	newSt := e.adapter.TransitionV4(ip, st, level, now, params) // ← authorized call

	if r.DenyReason != "" {
		result.Status = "downgraded"
	} else {
		result.Status = "applied"
	}
	result.Action = r.ExecutableAction
	result.Reason = r.DenyReason
	return newSt, result
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
		newSt := e.adapter.TransitionV6(ip, st, fsm.LevelObserve, now, params) // ← authorized call
		return newSt, result
	}

	level := ParseFSMLevel(r.ExecutableLevel)
	newSt := e.adapter.TransitionV6(ip, st, level, now, params) // ← authorized call

	if r.DenyReason != "" {
		result.Status = "downgraded"
	} else {
		result.Status = "applied"
	}
	result.Action = r.ExecutableAction
	result.Reason = r.DenyReason
	return newSt, result
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
	return e.adapter.TransitionV4(ip, st, fsm.LevelObserve, now, params) // ← authorized call
}

// ApplyDeEnforce6 moves an IPv6 source to LevelObserve unconditionally.
func (e *ShieldActionExecutor) ApplyDeEnforce6(
	ip [16]byte,
	st fsm.State,
	params shieldpep.EnforcementParams,
	now time.Time,
) fsm.State {
	return e.adapter.TransitionV6(ip, st, fsm.LevelObserve, now, params) // ← authorized call
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
