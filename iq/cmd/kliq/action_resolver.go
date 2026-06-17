// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/pep"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/policy"
)

// buildPolicyResolver creates an actions.PolicyResolver from the current cfg.
// Called once after the PolicyPack is loaded, then reused throughout the session.
func (c cfg) buildPolicyResolver() *actions.PolicyResolver {
	return &actions.PolicyResolver{
		Mode:                c.Mode,
		HasPolicyPack:       c.HasPolicyPack,
		PolicyMaxAction:     c.PolicyMaxAction,
		CapabilitiesAllowed: c.CapabilitiesRequired,
	}
}

// buildExecutor creates the ShieldActionExecutor — the only component allowed
// to call shieldpep.TransitionV4/V6. Pass nil for adapter to run without Shield.
// Additional PEP sidecars (e.g. netfilter) can be registered via AddSidecar.
func buildExecutor(adapter *shieldpep.Adapter) *actions.ShieldActionExecutor {
	return actions.NewShieldActionExecutor(adapter)
}

// resolveLevel is a thin cfg-level wrapper around the PolicyResolver.
// It is used in legacy code paths (housekeeping doT) that don't yet carry
// a full resolver instance, and in tests. New code should use the resolver directly.
func (c cfg) resolveLevel(proposed fsm.Level) (level fsm.Level, reason string) {
	r := c.buildPolicyResolver()
	res := r.Resolve(actions.ActionProposal{
		DesiredLevel: actions.FsmLevelName(proposed),
	})
	return actions.ParseFSMLevel(res.ExecutableLevel), res.DenyReason
}

// resolveDecisionAction applies the same authority rules to a decision.ActionType.
// Used to align the decision engine's LocalPolicy.MaxAction with the resolver.
func (c cfg) resolveDecisionAction(proposed decision.ActionType) decision.ActionType {
	if c.Mode == string(policy.ModeManaged) && !c.HasPolicyPack {
		return decision.ActionObserve
	}
	switch c.PolicyMaxAction {
	case "observe":
		return decision.ActionObserve
	case "rate_limit":
		// Cap at rate-limit (soft): block and signal downgrade to rate_limit.
		if actionWeight(proposed) > actionWeight(decision.ActionRateLimit) {
			return decision.ActionRateLimit
		}
	case "rate_limit_hard":
		// Cap at hard rate-limit: block downgrades to rate_limit; signal passes.
		if actionWeight(proposed) > actionWeight(decision.ActionBlock) {
			return decision.ActionRateLimit
		}
		if proposed == decision.ActionBlock {
			return decision.ActionRateLimit
		}
	}
	return proposed
}

// actionWeight returns the enforcement severity of a decision.ActionType.
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
