// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"log"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actionbroker"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/iq/internal/sourcefilters"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

func TestRuntimePDPActiveOwnsNetworkCandidateAction(t *testing.T) {
	now := time.Date(2026, 6, 19, 13, 0, 0, 0, time.UTC)
	c := newTestCfg("")
	c.RuntimePDPMode = string(PDPModeActive)
	c.TrigPPS = 1000
	c.TrigSyn = 100
	c.TrigScan = 10

	runner := newShadowPDPRunner("node-test", log.New(testWriter{t}, "", 0))
	runner.SetMode(PDPModeActive, nil)
	if err := runner.UpdatePack(runtimeCandidateTestPack(
		"metrics.network.packets_per_second > baseline.network.packets_per_second * 2.0 && fsm.proposed_level == 'block'",
		"enforce.traffic.rate_limit",
		"hard",
	)); err != nil {
		t.Fatalf("update runtime pack: %v", err)
	}

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	m := metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: "10.0.0.1",
			Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.1"},
		},
		Score: 99,
		Signals: map[string]float64{
			adapterruntime.MetricNetworkPacketsPerSecond: 5000,
			adapterruntime.MetricNetworkSynRate:          500,
		},
	}
	state := processCandidateRuntimePDP(
		m,
		fsm.State{},
		now,
		c,
		sourcefilters.NewWhitelist(""),
		sourcefilters.NewFeedback(""),
		c.buildPolicyResolver(),
		executor,
		nil,
		false,
		runner,
		"node-test",
		nil,
	)

	if state.Level != fsm.LevelHard {
		t.Fatalf("runtime PDP should choose hard, got %s", state.Level)
	}
	if len(pep.levels) != 1 || pep.levels[0] != fsm.LevelHard {
		t.Fatalf("PEP transitions = %#v, want one hard transition", pep.levels)
	}
}

func TestRuntimePDPShadowObservesNetworkCandidateOnly(t *testing.T) {
	now := time.Date(2026, 6, 19, 13, 5, 0, 0, time.UTC)
	c := newTestCfg("")
	c.RuntimePDPMode = string(PDPModeShadow)
	c.TrigPPS = 1000

	runner := newShadowPDPRunner("node-test", log.New(testWriter{t}, "", 0))
	runner.SetMode(PDPModeShadow, nil)
	if err := runner.UpdatePack(runtimeCandidateTestPack(
		"fsm.proposed_level == 'block'",
		"enforce.access.deny",
		"block",
	)); err != nil {
		t.Fatalf("update runtime pack: %v", err)
	}

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	state := processCandidateRuntimePDP(
		highSeverityRuntimeMetrics(),
		fsm.State{},
		now,
		c,
		sourcefilters.NewWhitelist(""),
		sourcefilters.NewFeedback(""),
		c.buildPolicyResolver(),
		executor,
		nil,
		false,
		runner,
		"node-test",
		nil,
	)

	if state.Level != fsm.LevelObserve {
		t.Fatalf("shadow mode must keep actual state observe, got %s", state.Level)
	}
	if state.Strikes == 0 {
		t.Fatal("shadow mode should still update FSM intent facts")
	}
	if len(pep.levels) != 0 {
		t.Fatalf("shadow mode must not call PEP, got transitions %#v", pep.levels)
	}
}

func TestRuntimePDPInputIncludesLearnedBaselineGraphAndLocalRisk(t *testing.T) {
	now := time.Date(2026, 6, 19, 13, 10, 0, 0, time.UTC)
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	subjectID := "10.0.0.1"
	subjectStableID := sstore.StableEntityID("ip", subjectID, "")
	objectStableID := sstore.StableEntityID("service", "payroll", "")
	if err := store.UpsertBaseline(context.Background(), sstore.BaselineRow{
		Key: baseline.Key{
			MetricID:        adapterruntime.MetricNetworkPacketsPerSecond,
			ScopeType:       "source",
			SubjectEntityID: subjectStableID,
			SourceClass:     "test",
			TruthClass:      "observed",
			WindowSeconds:   60,
		},
		State: "learned",
		EWMAState: map[string]any{
			"ewma":       123.0,
			"peak":       250.0,
			"confidence": 0.9,
		},
		Observations: 42,
		LastUpdated:  now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("upsert baseline: %v", err)
	}
	dims := map[string]string{"service": "payroll"}
	if err := store.UpsertRelationship(context.Background(), relationship.Relationship{
		ID:              "rel-1",
		NodeID:          "node-test",
		SubjectEntityID: subjectStableID,
		Predicate:       "ziti.dials",
		ObjectEntityID:  objectStableID,
		ScopeType:       "service",
		ScopeID:         "payroll",
		Dimensions:      dims,
		DimensionsHash:  sstore.DimensionsHash(dims),
		State:           relationship.StateFrozen,
		Weight:          1,
		Confidence:      0.95,
		SeenCount:       7,
		SourceAdapter:   "test-adapter",
		LastSeenAt:      now.Add(-30 * time.Second),
	}); err != nil {
		t.Fatalf("upsert relationship: %v", err)
	}

	input := runtimePDPInputForCandidate(
		"node-test",
		metrics{
			Target: adapterruntime.SourceTarget{
				SourceID: subjectID,
				Subject:  observation.EntityRef{Kind: "ip", ID: subjectID},
			},
			Score: 70,
			Signals: map[string]float64{
				adapterruntime.MetricNetworkPacketsPerSecond: 500,
			},
		},
		fsm.State{},
		fsmIntent{ProposedLevel: fsm.LevelHard},
		newTestCfg(""),
		newRuntimePDPFactStore(store),
		now,
	)

	if got := input.Context.Baseline[adapterruntime.MetricNetworkPacketsPerSecond]; got != 123.0 {
		t.Fatalf("learned baseline fact = %#v, want 123", got)
	}
	if got := input.Context.Graph["relationship_count"]; got != 1 {
		t.Fatalf("relationship_count = %#v, want 1", got)
	}
	if got := input.Context.Graph["frozen_count"]; got != 1 {
		t.Fatalf("frozen_count = %#v, want 1", got)
	}
	if input.Risk.Model != "kliq.candidate.v1" || len(input.Risk.Contributions) == 0 {
		t.Fatalf("risk assessment not produced from localrisk: %#v", input.Risk)
	}
}

func TestRuntimePDPInputTreatsEnforcementFeedbackAsHighRiskWhenEnforced(t *testing.T) {
	now := time.Date(2026, 6, 19, 13, 15, 0, 0, time.UTC)
	c := newTestCfg("")
	c.NonCompDrop = 1

	input := runtimePDPInputForCandidate(
		"node-test",
		metrics{
			Target: adapterruntime.SourceTarget{
				SourceID: "10.0.0.1",
				Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			},
			Score: 12,
			Signals: map[string]float64{
				adapterruntime.MetricNetworkRateLimitDropRate: 2,
			},
		},
		fsm.State{Level: fsm.LevelHard},
		fsmIntent{ProposedLevel: fsm.LevelObserve},
		c,
		nil,
		now,
	)

	if input.Risk.Level != contracts.RiskHigh || input.Risk.Score < 61 {
		t.Fatalf("enforcement feedback should hold high risk, got level=%s score=%d", input.Risk.Level, input.Risk.Score)
	}
	found := false
	for _, contribution := range input.Risk.Contributions {
		if contribution.SignalType == "source.rate_limit_drops_sustained" {
			found = true
			if contribution.Score < 61 {
				t.Fatalf("drop contribution score too low: %#v", contribution)
			}
		}
	}
	if !found {
		t.Fatalf("missing rate-limit drop contribution: %#v", input.Risk.Contributions)
	}
	if got := input.Context.Signals["enforcement_feedback_rate"]; got != 2.0 {
		t.Fatalf("enforcement feedback fact = %#v, want 2", got)
	}
}

func TestRuntimePDPInputDoesNotPromoteIdleFeedbackToHighRisk(t *testing.T) {
	now := time.Date(2026, 6, 19, 13, 20, 0, 0, time.UTC)
	input := runtimePDPInputForCandidate(
		"node-test",
		metrics{
			Target: adapterruntime.SourceTarget{
				SourceID: "10.0.0.1",
				Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			},
			Score: 12,
			Signals: map[string]float64{
				adapterruntime.MetricNetworkRateLimitDropRate: 2,
			},
		},
		fsm.State{Level: fsm.LevelObserve},
		fsmIntent{ProposedLevel: fsm.LevelObserve},
		newTestCfg(""),
		nil,
		now,
	)

	if input.Risk.Level == contracts.RiskHigh || input.Risk.Level == contracts.RiskCritical {
		t.Fatalf("observe-only feedback should not promote risk, got level=%s score=%d", input.Risk.Level, input.Risk.Score)
	}
}

func runtimeCandidateTestPack(expr, capability, level string) contracts.RuntimePolicyPack {
	return contracts.RuntimePolicyPack{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimePolicyPack,
		},
		Metadata: contracts.ObjectMeta{Name: "runtime-candidate-test"},
		Spec: contracts.RuntimePolicyPackSpec{
			DefaultEffect: "deny",
			Rules: []contracts.RuntimePolicyRule{{
				ID:   "candidate-rule",
				When: expr,
				Then: contracts.RuntimeActionSpec{
					Capability: capability,
					Level:      level,
					TTL:        contracts.NewDuration(time.Minute),
				},
				ReasonCodes: []string{"candidate_policy"},
			}},
		},
	}
}

func highSeverityRuntimeMetrics() metrics {
	return metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: "10.0.0.1",
			Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.1"},
		},
		Score: 99,
		Signals: map[string]float64{
			adapterruntime.MetricNetworkPacketsPerSecond: 5000,
			adapterruntime.MetricNetworkSynRate:          500,
		},
	}
}

func newRuntimePDPTestExecutor(t *testing.T, pep *recordingSourcePEP, c cfg) (*brokeredActionExecutor, func()) {
	t.Helper()
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	sourceExecutor := actions.NewSourceActionExecutor(pep)
	brokerPEP := newBrokeredSourcePEP(sourceExecutor, func() adapterruntime.EnforcementParams {
		return c.toPEPParams()
	})
	broker, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-test",
		Store:  store,
		PEP:    brokerPEP,
		Now:    func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		store.Close()
		t.Fatalf("new broker: %v", err)
	}
	return newBrokeredActionExecutor(sourceExecutor, broker, brokerPEP, nil, nil, store, "node-test"), func() {
		store.Close()
	}
}

type recordingSourcePEP struct {
	levels []fsm.Level
}

func (p *recordingSourcePEP) TransitionSource(_ adapterruntime.SourceTarget, st fsm.State, target fsm.Level, now time.Time, params adapterruntime.EnforcementParams) (fsm.State, error) {
	p.levels = append(p.levels, target)
	st.Level = target
	switch target {
	case fsm.LevelSoft:
		st.ExpiresAt = now.Add(params.SoftTTL)
	case fsm.LevelHard:
		st.ExpiresAt = now.Add(params.HardTTL)
	case fsm.LevelBlock:
		st.ExpiresAt = now.Add(params.BlockTTL)
	default:
		st.ExpiresAt = time.Time{}
	}
	return st, nil
}

type testWriter struct {
	t *testing.T
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

var _ adapterruntime.SourcePEP = (*recordingSourcePEP)(nil)
