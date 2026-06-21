// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/sourcefilters"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

func TestRuntimeReactionWindowedDetectionAppliesResponseAction(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	c := newReactionTestCfg(PDPModeActive)

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	state := fsm.State{}
	m := reactionDeniedAccessMetrics()

	state = engine.EvaluateCandidate(m, state, now, c, c.buildPolicyResolver(), executor, "node-test")
	if state.Level != fsm.LevelObserve || len(pep.levels) != 0 {
		t.Fatalf("first event should only fill the window, state=%s levels=%#v", state.Level, pep.levels)
	}

	state = engine.EvaluateCandidate(m, state, now.Add(time.Minute), c, c.buildPolicyResolver(), executor, "node-test")
	if state.Level != fsm.LevelSoft {
		t.Fatalf("second event should rate-limit, got %s", state.Level)
	}
	if len(pep.levels) != 1 || pep.levels[0] != fsm.LevelSoft {
		t.Fatalf("PEP levels = %#v, want one soft transition", pep.levels)
	}
}

func TestRuntimeReactionShadowModeDoesNotApplyResponseAction(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 5, 0, 0, time.UTC)
	c := newReactionTestCfg(PDPModeShadow)

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	state := fsm.State{}
	m := reactionDeniedAccessMetrics()

	state = engine.EvaluateCandidate(m, state, now, c, c.buildPolicyResolver(), executor, "node-test")
	state = engine.EvaluateCandidate(m, state, now.Add(time.Minute), c, c.buildPolicyResolver(), executor, "node-test")
	if state.Level != fsm.LevelObserve {
		t.Fatalf("shadow response should keep observe, got %s", state.Level)
	}
	if len(pep.levels) != 0 {
		t.Fatalf("shadow response should not call PEP, levels=%#v", pep.levels)
	}
}

func TestRuntimeReactionIntegratedWithCandidateLoop(t *testing.T) {
	now := time.Date(2026, 6, 21, 10, 10, 0, 0, time.UTC)
	c := newReactionTestCfg(PDPModeActive)

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	engine := newRuntimeReactionEngine()
	sources := newSourceStates()
	cands := []metrics{reactionDeniedAccessMetrics()}
	wl := sourcefilters.NewWhitelist("")
	fb := sourcefilters.NewFeedback("")

	sources.processCandidates(cands, now, c, wl, fb, c.buildPolicyResolver(), executor, nil, false, nil, "node-test", nil, engine)
	processed := sources.processCandidates(cands, now.Add(time.Minute), c, wl, fb, c.buildPolicyResolver(), executor, nil, false, nil, "node-test", nil, engine)

	if !processed["10.0.0.8"] {
		t.Fatal("candidate should be processed")
	}
	if got := sources.entries["10.0.0.8"].state.Level; got != fsm.LevelSoft {
		t.Fatalf("candidate reaction state = %s, want soft", got)
	}
}

func newReactionTestCfg(mode runtimePDPMode) cfg {
	c := newTestCfg("")
	c.RuntimePDPMode = string(mode)
	c.RuntimeDetectionRules = []contracts.RuntimeDetectionRule{{
		ID:          "denied-access-ziti-controller",
		Type:        "access.denied_threshold",
		ResourceRef: "ziti-controller",
		Threshold:   2,
		Window:      contracts.NewDuration(15 * time.Minute),
		Scope:       "source",
	}}
	c.RuntimeResponseRules = []contracts.RuntimeResponseRule{{
		ID: "rate-limit-denied-access",
		When: contracts.RuntimeResponseTrigger{
			Detection: "denied-access-ziti-controller",
		},
		Then: []contracts.RuntimeResponseAction{{
			ID:  "enforce.traffic.rate_limit",
			TTL: contracts.NewDuration(5 * time.Minute),
			Target: contracts.RuntimeResponseTarget{
				Scope: "source",
			},
		}},
	}}
	return c
}

func reactionDeniedAccessMetrics() metrics {
	return metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: "10.0.0.8",
			Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.8"},
			Attributes: map[string]string{
				"resource.ref": "ziti-controller",
			},
		},
		Signals: map[string]float64{
			"access.denied": 1,
		},
	}
}
