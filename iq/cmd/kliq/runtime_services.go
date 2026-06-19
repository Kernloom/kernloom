// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/decisionengine"
)

type runtimePDPServiceConfig struct {
	NodeID        string
	Mode          string
	PolicyFile    string
	StartupPack   *contracts.RuntimePolicyPack
	PackUpdates   <-chan contracts.RuntimePolicyPack
	Bus           adapterruntime.EventBus
	Resolver      *actions.PolicyResolver
	Executor      *brokeredActionExecutor
	Params        func() adapterruntime.EnforcementParams
	Facts         runtimePDPFactProvider
	ProposalDepth int
}

func startRuntimePDPService(ctx context.Context, cfg runtimePDPServiceConfig) (*shadowPDPRunner, error) {
	runner := newShadowPDPRunner(cfg.NodeID, log.New(os.Stderr, "[runtime-pdp] ", log.LstdFlags))
	if cfg.ProposalDepth <= 0 {
		cfg.ProposalDepth = 256
	}
	if cfg.Params == nil {
		cfg.Params = func() adapterruntime.EnforcementParams { return adapterruntime.EnforcementParams{} }
	}

	if cfg.Mode == string(PDPModeActive) {
		proposals := make(chan actions.ActionProposal, cfg.ProposalDepth)
		runner.SetMode(PDPModeActive, proposals)
		go runRuntimePDPProposalApplier(ctx, proposals, cfg)
		kliqLog.Printf("RuntimePDP mode: ACTIVE — RuntimePDP is authoritative; FSM/analyzers provide facts only")
	} else {
		runner.SetMode(PDPModeShadow, nil)
		kliqLog.Printf("RuntimePDP mode: SHADOW — decisions logged only (--runtime-pdp-mode=active to enforce)")
	}

	if cfg.StartupPack != nil {
		if err := runner.UpdatePack(*cfg.StartupPack); err != nil {
			return nil, fmt.Errorf("compile runtime policy file %s: %w", cfg.PolicyFile, err)
		}
	}

	go runRuntimePolicyPackUpdates(ctx, runner, cfg.PackUpdates)
	startShadowPDP(ctx, cfg.Bus, runner, cfg.Facts)
	return runner, nil
}

func runRuntimePDPProposalApplier(ctx context.Context, proposals <-chan actions.ActionProposal, cfg runtimePDPServiceConfig) {
	for {
		select {
		case <-ctx.Done():
			return
		case prop, ok := <-proposals:
			if !ok {
				return
			}
			res := cfg.Resolver.Resolve(prop)
			if !res.Allowed {
				kliqLog.Printf("[runtime-pdp:active] proposal denied: %s", res.DenyReason)
				continue
			}
			if !applyResolvedAction(res, cfg.Executor, cfg.Params(), time.Now()) {
				kliqLog.Printf("[runtime-pdp:active] proposal skipped: unsupported target %s:%q", res.Target.Granularity, res.Target.Value)
			}
		}
	}
}

func runRuntimePolicyPackUpdates(ctx context.Context, runner *shadowPDPRunner, updates <-chan contracts.RuntimePolicyPack) {
	for {
		select {
		case <-ctx.Done():
			return
		case pack, ok := <-updates:
			if !ok {
				return
			}
			if err := runner.UpdatePack(pack); err != nil {
				kliqLog.Printf("runtime policy pack update rejected: %v", err)
			}
		}
	}
}

type runtimeSignalConsumerConfig struct {
	NodeID            string
	Bus               adapterruntime.EventBus
	DecisionEngine    *decisionengine.Engine
	GraphStrikeCh     chan<- graphStrikeMsg
	TupleEnforcement  bool
	RelationshipPEP   adapterruntime.RelationshipPEP
	RuntimeRunner     *shadowPDPRunner
	RuntimeFacts      runtimePDPFactProvider
	Resolver          *actions.PolicyResolver
	Executor          *brokeredActionExecutor
	SubscriptionDepth int
}

func startKLIQSignalConsumer(ctx context.Context, cfg runtimeSignalConsumerConfig) {
	depth := cfg.SubscriptionDepth
	if depth <= 0 {
		depth = 256
	}
	sigCh := cfg.Bus.SubscribeSignals(depth)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case sig, ok := <-sigCh:
				if !ok {
					return
				}
				handleRuntimeSignal(ctx, sig, cfg)
			}
		}
	}()
}

func handleRuntimeSignal(ctx context.Context, sig signal.Signal, cfg runtimeSignalConsumerConfig) {
	logRuntimeSignal(sig)

	if cfg.DecisionEngine != nil {
		if _, _, err := cfg.DecisionEngine.EvaluateSignal(ctx, sig); err != nil {
			kliqLog.Printf("SIGNAL decision error: %v", err)
		}
	}

	if sig.Type == signal.SignalGraphNewEdgeAfterFreeze && sig.Subject.ID != "" {
		sendStrike(cfg.GraphStrikeCh, sig.Subject.ID, graphStrikesFromScore(sig.Score), sig.Score >= 90, true, sig.Score)
		maybeApplyRuntimeGraphRelationship(sig, cfg)
	}

	if isGraphBaselineSignal(sig.Type) && sig.Subject.ID != "" {
		sendStrike(cfg.GraphStrikeCh, sig.Subject.ID, 0, false, true, sig.Score)
	}
}

func logRuntimeSignal(sig signal.Signal) {
	logLine := fmt.Sprintf("SIGNAL type=%s subject=%s score=%d confidence=%d ttl=%s reasons=%v",
		sig.Type, formatSubject(sig.Subject), sig.Score, sig.Confidence, sig.TTL, sig.ReasonCodes)
	if len(sig.Attributes) > 0 {
		keys := make([]string, 0, len(sig.Attributes))
		for k := range sig.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			logLine += fmt.Sprintf(" %s=%s", k, sig.Attributes[k])
		}
	}
	kliqLog.Print(logLine)
}

func maybeApplyRuntimeGraphRelationship(sig signal.Signal, cfg runtimeSignalConsumerConfig) {
	if !cfg.TupleEnforcement || sig.Score < 90 || cfg.RelationshipPEP == nil || !cfg.RelationshipPEP.RelationshipAvailable() {
		return
	}
	relTarget, ok := relationshipActionTargetFromSignal(sig)
	if !ok {
		return
	}
	now := time.Now()
	input := runtimePDPInputForSignal(cfg.NodeID, sig, cfg.RuntimeFacts, now)
	dec, matched, loaded, err := cfg.RuntimeRunner.decide(input)
	mode, _ := cfg.RuntimeRunner.getMode()
	prefix := runtimePDPDecisionLogPrefix(mode)
	if err != nil {
		kliqLog.Printf("%s graph relationship decide error %s: %v", prefix, relTarget.Label, err)
		return
	}
	if !loaded {
		if mode == PDPModeActive {
			kliqLog.Printf("%s graph relationship held %s: no policy pack loaded", prefix, relTarget.Label)
		} else {
			kliqLog.Printf("%s graph relationship observed %s (no policy pack)", prefix, relTarget.Label)
		}
		return
	}
	if !matched {
		return
	}
	if mode == PDPModeShadow {
		kliqLog.Printf("%s graph relationship decision %s effect=%s reasons=%v (observe-only)",
			prefix, relTarget.Label, dec.Effect, dec.ReasonCodes)
		return
	}

	fallback := relTarget.Proposal
	prop, ok, reason := runtimeDecisionToActionProposalWithFallbackTarget(dec, sig.Subject.ID, &fallback, float64(sig.Confidence)/100.0, now)
	if !ok {
		kliqLog.Printf("%s graph relationship decision skipped %s reason=%s", prefix, relTarget.Label, reason)
		return
	}
	res := cfg.Resolver.Resolve(prop)
	if res.DenyReason != "" {
		kliqLog.Printf("ACTION-RESOLVER runtime-pdp relationship %s %s->%s reason=%q",
			relTarget.Label, prop.DesiredLevel, res.ExecutableLevel, res.DenyReason)
	}
	result := cfg.Executor.ApplyRelationship(relTarget.PEP, res, now)
	switch result.Status {
	case "applied":
		kliqLog.Printf("RELATIONSHIP deny edge: %s (runtime-pdp graph decision)", relTarget.Label)
	case "failed":
		kliqLog.Printf("RELATIONSHIP deny edge %s failed: %s", relTarget.Label, result.Reason)
	}
}
