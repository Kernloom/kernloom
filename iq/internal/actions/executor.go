// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actions

import (
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

// SourceActionExecutor is the ONLY component in KLIQ authorised to call a
// runtime PEP's source transition methods.
//
// It receives an already-authorised ActionResolution from the PolicyResolver
// and translates it into the corresponding PEP call. It never makes policy
// decisions — that is the resolver's job.
//
// Additional PEP adapters (e.g. netfilter) register as PEPSidecar instances
// and are notified after every authorized transition.
type SourceActionExecutor struct {
	adapter  adapterruntime.SourcePEP
	sidecars []PEPSidecar
}

// NewSourceActionExecutor creates an executor backed by the given source PEP.
// Pass nil for adapter to run observation-only or sidecar-only.
func NewSourceActionExecutor(adapter adapterruntime.SourcePEP, sidecars ...PEPSidecar) *SourceActionExecutor {
	return &SourceActionExecutor{adapter: adapter, sidecars: sidecars}
}

// AddSidecar registers an additional PEP adapter to receive enforcement notifications.
func (e *SourceActionExecutor) AddSidecar(s PEPSidecar) {
	e.sidecars = append(e.sidecars, s)
}

// ApplySource applies an authorised ActionResolution to an opaque source target.
//
// This is the ONLY function in KLIQ that calls the adapter source PEP.
//
// When r.Allowed is false the source is moved to LevelObserve (de-enforced) so
// that previously applied BPF entries are cleared. Keeping a denied source in an
// enforced state would be wrong: the policy said "no", so no enforcement.
func (e *SourceActionExecutor) ApplySource(
	target adapterruntime.SourceTarget,
	st fsm.State,
	r ActionResolution,
	params adapterruntime.EnforcementParams,
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
			var err error
			newSt, err = e.adapter.TransitionSource(target, st, fsm.LevelObserve, now, params) // ← authorized call
			if err != nil {
				result.Status = "failed"
				result.Reason = err.Error()
				return st, result
			}
		} else {
			newSt = st
			newSt.Level = fsm.LevelObserve
		}
		e.notifySidecars(target, st.Level, fsm.LevelObserve, r.TTL)
		return newSt, result
	}

	level := ParseFSMLevel(r.ExecutableLevel)
	var newSt fsm.State
	if e.adapter != nil {
		var err error
		newSt, err = e.adapter.TransitionSource(target, st, level, now, params) // ← authorized call
		if err != nil {
			result.Status = "failed"
			result.Reason = err.Error()
			return st, result
		}
	} else {
		newSt = st
		newSt.Level = level
	}
	e.notifySidecars(target, st.Level, level, r.TTL)

	if r.DenyReason != "" {
		result.Status = "downgraded"
	} else {
		result.Status = "applied"
	}
	result.Action = r.ExecutableAction
	result.Reason = r.DenyReason
	return newSt, result
}

func (e *SourceActionExecutor) notifySidecars(target adapterruntime.SourceTarget, prev, next fsm.Level, ttl time.Duration) {
	for _, s := range e.sidecars {
		s.NotifySourceTransition(target, prev, next, ttl)
	}
}

// ApplyDeEnforceSource moves a source to LevelObserve unconditionally.
// Used for whitelist and feedback de-enforcement — always safe, always authorized,
// bypasses the resolver since removing enforcement never needs policy approval.
func (e *SourceActionExecutor) ApplyDeEnforceSource(
	target adapterruntime.SourceTarget,
	st fsm.State,
	params adapterruntime.EnforcementParams,
	now time.Time,
) fsm.State {
	var newSt fsm.State
	if e.adapter != nil {
		var err error
		newSt, err = e.adapter.TransitionSource(target, st, fsm.LevelObserve, now, params) // ← authorized call
		if err != nil {
			return st
		}
	} else {
		newSt = st
		newSt.Level = fsm.LevelObserve
	}
	e.notifySidecars(target, st.Level, fsm.LevelObserve, 0)
	return newSt
}
