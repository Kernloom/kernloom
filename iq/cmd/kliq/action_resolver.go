// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actionbroker"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/policy"
)

// buildPolicyResolver creates an actions.PolicyResolver from the current cfg.
// Called once after the PolicyPack is loaded, then reused throughout the session.
func (c cfg) buildPolicyResolver() *actions.PolicyResolver {
	return &actions.PolicyResolver{
		Mode:                     c.Mode,
		HasPolicyPack:            c.HasPolicyPack,
		PolicyMaxAction:          c.PolicyMaxAction,
		CapabilitiesAllowed:      c.CapabilitiesRequired,
		RuntimeGuardrails:        append([]contracts.RuntimeGuardrail(nil), c.RuntimeGuardrails...),
		RuntimeAutonomyLifecycle: c.RuntimeAutonomyLifecycle,
	}
}

func syncPolicyResolverFromCfg(c cfg, resolver *actions.PolicyResolver) {
	if resolver == nil {
		return
	}
	next := c.buildPolicyResolver()
	*resolver = *next
}

func runtimeAutonomyAllowances(lifecycle *contracts.RuntimeAutonomyLifecycleSpec) []contracts.RuntimeAutonomyAllowance {
	if lifecycle == nil || len(lifecycle.Allow) == 0 {
		return nil
	}
	return append([]contracts.RuntimeAutonomyAllowance(nil), lifecycle.Allow...)
}

func runtimeAutonomyMaxRenewals(lifecycle *contracts.RuntimeAutonomyLifecycleSpec) int {
	if lifecycle == nil || lifecycle.MaxRenewals <= 0 {
		return 0
	}
	return lifecycle.MaxRenewals
}

func runtimeAutonomyRequiresAudit(lifecycle *contracts.RuntimeAutonomyLifecycleSpec) bool {
	return lifecycle != nil && lifecycle.RequiresAudit
}

func syncActionBrokerAutonomyFromCfg(c cfg, brokers ...*actionbroker.Broker) {
	allowances := runtimeAutonomyAllowances(c.RuntimeAutonomyLifecycle)
	maxRenewals := runtimeAutonomyMaxRenewals(c.RuntimeAutonomyLifecycle)
	requiresAudit := runtimeAutonomyRequiresAudit(c.RuntimeAutonomyLifecycle)
	for _, broker := range brokers {
		if broker != nil {
			broker.UpdateAutonomyConstraints(allowances, maxRenewals, requiresAudit)
		}
	}
}

// buildExecutor creates the source action executor. Pass nil for adapter to run
// without a primary source PEP; sidecars may still mirror transitions.
// Additional PEP sidecars (e.g. netfilter) can be registered via AddSidecar.
func buildExecutor(adapter adapterruntime.SourcePEP) *actions.SourceActionExecutor {
	return actions.NewSourceActionExecutor(adapter)
}

type sourcePEPSidecar struct {
	id     string
	pep    adapterruntime.SourcePEP
	params func() adapterruntime.EnforcementParams
}

func (s sourcePEPSidecar) NotifySourceTransition(target adapterruntime.SourceTarget, prev, next fsm.Level, ttl time.Duration) {
	if s.pep == nil {
		return
	}
	params := adapterruntime.EnforcementParams{}
	if s.params != nil {
		params = s.params()
	}
	params = paramsWithSidecarTTL(params, next, ttl)
	if _, err := s.pep.TransitionSource(target, fsm.State{Level: prev}, next, time.Now(), params); err != nil {
		kliqLog.Printf("source PEP sidecar %s transition %s->%s target=%s failed: %v",
			s.id, prev, next, target.SourceID, err)
	}
}

func paramsWithSidecarTTL(params adapterruntime.EnforcementParams, level fsm.Level, ttl time.Duration) adapterruntime.EnforcementParams {
	if ttl <= 0 {
		return params
	}
	switch level {
	case fsm.LevelSoft:
		params.SoftTTL = ttl
	case fsm.LevelHard:
		params.HardTTL = ttl
	case fsm.LevelBlock:
		params.BlockTTL = ttl
	}
	return params
}

// resolveLevel is a thin cfg-level wrapper around the PolicyResolver.
// It is used by focused resolver tests. Runtime enforcement paths should use
// RuntimePDP decisions resolved through the broker pipeline.
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
