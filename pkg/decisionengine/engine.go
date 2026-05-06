// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package decisionengine bridges signals and FSM state to Decisions and PEP receipts.
// It is additive: it wraps existing FSM/PEP plumbing with an audit trail and
// enables signal-driven enforcement independently of the heuristic FSM.
package decisionengine

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/core/decision"
	"github.com/adrianenderlin/kernloom/pkg/core/fsm"
	"github.com/adrianenderlin/kernloom/pkg/core/observation"
	"github.com/adrianenderlin/kernloom/pkg/core/reason"
	"github.com/adrianenderlin/kernloom/pkg/core/signal"
)

var logger = log.New(os.Stderr, "[decision-engine] ", log.LstdFlags)

// LocalPolicy is the pre-Forge, config-driven policy used by the engine.
// When Forge arrives it will populate this from a signed PolicyPack instead of
// CLI flags; the struct is intentionally forward-compatible.
type LocalPolicy struct {
	NodeID string
	DryRun bool

	// MaxAction caps what the engine may enforce locally.
	MaxAction decision.ActionType

	// Per-level action mapping for FSM transitions.
	LevelSoft  decision.ActionType
	LevelHard  decision.ActionType
	LevelBlock decision.ActionType

	// TTLs carried into Decision for audit and PEP expiry.
	SoftTTL  time.Duration
	HardTTL  time.Duration
	BlockTTL time.Duration

	// Graph freeze policy.
	GraphFreezeAction decision.ActionType
	GraphFreezeTTL    time.Duration

	// AllowLocalBlock gates whether block decisions are permitted without Forge approval.
	// When false, MaxAction is effectively capped at rate_limit.
	AllowLocalBlock bool

	// MinSeverityForBlock is the minimum signal score (0-100) required before
	// a block decision is allowed.
	MinSeverityForBlock int
}

// PEPAdapter is the interface the engine uses to enforce a decision.
// shieldbridge.ShieldBridge implements this; future adapters (nginx, ziti) may too.
type PEPAdapter interface {
	// EnforceDecision applies a decision and returns its receipt.
	// Must be safe for concurrent use.
	EnforceDecision(ctx context.Context, dec *decision.Decision) (*decision.EnforcementReceipt, error)
}

// Engine is KLIQ's local decision engine.
// It translates Signals and FSM transitions into auditable Decisions and drives
// the PEP adapter for enforcement.
type Engine struct {
	mu     sync.RWMutex
	policy LocalPolicy
	pep    PEPAdapter
}

// New creates a new Engine with the provided policy and PEP adapter.
func New(policy LocalPolicy, pep PEPAdapter) *Engine {
	e := &Engine{pep: pep}
	e.policy = applyDefaults(policy)
	return e
}

// EvaluateSignal handles a signal from the event bus.
//
// For graph.new_edge_after_freeze signals the engine produces an audit Decision.
// Enforcement is always handled by the main tick loop via FSM strike injection
// (graphStrikeCh). The FSM is the single enforcement authority for both modes:
//   - frozen-observe (score=70): normal strike accumulation → gradual escalation.
//   - frozen-enforce (score=95): forceBlock flag set → FSM jumps to BLOCK in next tick.
//
// Returns nil, nil, nil for unhandled signal types.
func (e *Engine) EvaluateSignal(_ context.Context, sig signal.Signal) (*decision.Decision, *decision.EnforcementReceipt, error) {
	if sig.Type != signal.SignalGraphNewEdgeAfterFreeze {
		return nil, nil, nil
	}

	e.mu.RLock()
	pol := e.policy
	e.mu.RUnlock()

	action := capAction(pol.GraphFreezeAction, pol)

	enfVia := "fsm_strikes"
	if sig.Score >= pol.MinSeverityForBlock && pol.MinSeverityForBlock > 0 {
		enfVia = "fsm_force_block"
	}

	dec := decision.NewDecision(
		decision.DeciderKLIQ,
		pol.NodeID,
		sig.Subject,
		decision.Action{
			Type:       action,
			Capability: capabilityFor(action),
			Params: map[string]string{
				"source": sig.Subject.ID,
			},
		},
	)
	dec.SetSeverity(sig.Score).
		AddReasonCode(reason.GraphNewEdgeAfterFreeze).
		SetDryRun(pol.DryRun).
		SetAttribute("enforcement_via", enfVia)
	for _, rc := range sig.ReasonCodes {
		dec.AddReasonCode(rc)
	}

	logger.Printf("GRAPH-DECISION id=%s subject=%s score=%d action=%s dry_run=%v → %s",
		dec.ID, sig.Subject.ID, sig.Score, action, pol.DryRun, enfVia)

	return dec, nil, nil
}

// RecordFSMTransition produces a Decision for audit purposes when the FSM changes level.
// It does NOT call the PEP — the caller (processCandidate4/6) drives enforcement via
// its existing doTransition callback. This method adds the audit trail only.
func (e *Engine) RecordFSMTransition(
	subject observation.EntityRef,
	from, to fsm.Level,
	severity float64,
	reasons ...string,
) *decision.Decision {
	e.mu.RLock()
	pol := e.policy
	e.mu.RUnlock()

	action, ttl := fsmLevelToAction(to, pol)
	action = capAction(action, pol)

	dec := decision.NewDecision(
		decision.DeciderKLIQ,
		pol.NodeID,
		subject,
		decision.Action{
			Type:       action,
			Capability: capabilityFor(action),
			Params: map[string]string{
				"source": subject.ID,
			},
		},
	)

	sevInt := int(severity * 100)
	if sevInt > 100 {
		sevInt = 100
	}
	dec.SetSeverity(sevInt).
		SetDryRun(pol.DryRun).
		SetAttribute("fsm_from", from.String()).
		SetAttribute("fsm_to", to.String())

	if ttl > 0 {
		dec.SetExpiryDuration(ttl)
	}

	for _, rc := range reasons {
		dec.AddReasonCode(rc)
	}

	logger.Printf("DECISION id=%s action=%s subject=%s severity=%d dry_run=%v fsm=%s->%s reasons=%v",
		dec.ID, dec.Action.Type, dec.Subject.ID, dec.Severity, dec.DryRun,
		from.String(), to.String(), dec.ReasonCodes)

	return dec
}

// UpdatePolicy atomically replaces the active policy (called from autotune goroutine).
func (e *Engine) UpdatePolicy(p LocalPolicy) {
	e.mu.Lock()
	e.policy = applyDefaults(p)
	e.mu.Unlock()
}

// Policy returns a snapshot of the current policy.
func (e *Engine) Policy() LocalPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy
}

/* ---- internal helpers ---- */

// actionWeight assigns a numeric weight so MaxAction enforcement is comparable.
func actionWeight(a decision.ActionType) int {
	switch a {
	case decision.ActionObserve:
		return 0
	case decision.ActionSignal:
		return 1
	case decision.ActionRateLimit:
		return 2
	case decision.ActionBlock:
		return 3
	default:
		return 0
	}
}

// capAction enforces the MaxAction ceiling and the AllowLocalBlock gate.
func capAction(action decision.ActionType, pol LocalPolicy) decision.ActionType {
	if !pol.AllowLocalBlock && action == decision.ActionBlock {
		action = decision.ActionRateLimit
	}
	if actionWeight(action) > actionWeight(pol.MaxAction) {
		action = pol.MaxAction
	}
	return action
}

// fsmLevelToAction maps an FSM target level to an ActionType and enforcement TTL.
func fsmLevelToAction(level fsm.Level, pol LocalPolicy) (decision.ActionType, time.Duration) {
	switch level {
	case fsm.LevelSoft:
		a := pol.LevelSoft
		if a == "" {
			a = decision.ActionRateLimit
		}
		return a, pol.SoftTTL
	case fsm.LevelHard:
		a := pol.LevelHard
		if a == "" {
			a = decision.ActionRateLimit
		}
		return a, pol.HardTTL
	case fsm.LevelBlock:
		a := pol.LevelBlock
		if a == "" {
			a = decision.ActionBlock
		}
		return a, pol.BlockTTL
	default:
		return decision.ActionObserve, 0
	}
}

// capabilityFor returns the standard capability ID for an action.
func capabilityFor(action decision.ActionType) string {
	switch action {
	case decision.ActionBlock:
		return "network.block_source"
	case decision.ActionRateLimit:
		return "network.rate_limit_source"
	case decision.ActionAllow:
		return "network.allow_source"
	case decision.ActionSignal:
		return "signal.emit_local_risk"
	default:
		return "network.observe_flow"
	}
}

// applyDefaults fills in safe zero-values so callers don't have to.
func applyDefaults(pol LocalPolicy) LocalPolicy {
	if pol.MaxAction == "" {
		pol.MaxAction = decision.ActionRateLimit
	}
	if pol.GraphFreezeAction == "" {
		pol.GraphFreezeAction = decision.ActionSignal
	}
	if pol.GraphFreezeTTL == 0 {
		pol.GraphFreezeTTL = 10 * time.Minute
	}
	if pol.LevelSoft == "" {
		pol.LevelSoft = decision.ActionRateLimit
	}
	if pol.LevelHard == "" {
		pol.LevelHard = decision.ActionRateLimit
	}
	if pol.LevelBlock == "" {
		pol.LevelBlock = decision.ActionBlock
	}
	return pol
}
