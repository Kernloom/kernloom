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
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
	"github.com/kernloom/kernloom/iq/internal/sourcefilters"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/core/signal"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

func TestShouldLogRuntimePDPNoMatchRequiresRiskScore(t *testing.T) {
	lowRisk := runtimepdp.Input{
		Risk: contracts.LocalRiskAssessment{Score: 0},
	}
	if shouldLogRuntimePDPNoMatch(lowRisk, fsmIntent{Transitioned: true}) {
		t.Fatal("low-risk FSM transition should not emit no-match trace spam")
	}

	highRisk := runtimepdp.Input{
		Risk: contracts.LocalRiskAssessment{Score: 30},
	}
	if !shouldLogRuntimePDPNoMatch(highRisk, fsmIntent{}) {
		t.Fatal("high-risk no-match should remain visible")
	}
}

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
		nil,
	)

	if state.Level != fsm.LevelHard {
		t.Fatalf("runtime PDP should choose hard, got %s", state.Level)
	}
	if len(pep.levels) != 1 || pep.levels[0] != fsm.LevelHard {
		t.Fatalf("PEP transitions = %#v, want one hard transition", pep.levels)
	}
}

func TestRuntimePDPActiveSignalWindowQueuesProposal(t *testing.T) {
	runner := newShadowPDPRunner("node-test", log.New(testWriter{t}, "", 0))
	proposals := make(chan actions.ActionProposal, 1)
	runner.SetMode(PDPModeActive, proposals)
	if err := runner.UpdatePack(runtimeCandidateTestPack(
		"risk.level in ['high', 'critical']",
		"enforce.traffic.rate_limit",
		"hard",
	)); err != nil {
		t.Fatalf("update runtime pack: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	bus := adapterruntime.NewBus(8)
	startShadowPDP(ctx, bus, runner, nil)

	subject := observation.EntityRef{Kind: observation.KindIP, ID: "10.0.0.1"}
	sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, signal.SignalSYNRateHigh, subject).
		SetScore(100).
		SetConfidence(85).
		SetTTL(time.Minute).
		AddReasonCode("syn_rate_high").
		SetAttribute("syn_rate", "5000")
	if err := bus.PublishSignal(context.Background(), *sig); err != nil {
		t.Fatalf("publish signal: %v", err)
	}
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case prop := <-proposals:
		if prop.DesiredAction != "enforce.traffic.rate_limit" || prop.DesiredLevel != "hard" {
			t.Fatalf("proposal action = %s/%s, want rate_limit/hard", prop.DesiredAction, prop.DesiredLevel)
		}
		if prop.Target.Granularity != actions.TargetGranularitySource || prop.Target.Value != "10.0.0.1" {
			t.Fatalf("proposal target = %#v, want source 10.0.0.1", prop.Target)
		}
	case <-time.After(time.Second):
		t.Fatal("active signal-window RuntimePDP did not queue proposal")
	}
}

func TestRuntimePDPActiveRenewalKeepsEffectiveLeaseState(t *testing.T) {
	start := time.Date(2026, 6, 20, 9, 15, 0, 0, time.UTC)
	c := newTestCfg("")
	c.RuntimePDPMode = string(PDPModeActive)
	c.HardTTL = 30 * time.Second

	runner := newShadowPDPRunner("node-test", log.New(testWriter{t}, "", 0))
	runner.SetMode(PDPModeActive, nil)
	if err := runner.UpdatePack(runtimeCandidateTestPack(
		"device.posture.status == 'unknown'",
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
		start,
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
		nil,
	)
	if state.Level != fsm.LevelBlock {
		t.Fatalf("initial runtime decision should block, got %s", state.Level)
	}

	coolMetrics := metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: "10.0.0.1",
			Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.1"},
		},
		Score:   0,
		Signals: map[string]float64{},
	}
	state = processCandidateRuntimePDP(
		coolMetrics,
		state,
		start.Add(2*time.Second),
		c,
		sourcefilters.NewWhitelist(""),
		sourcefilters.NewFeedback(""),
		c.buildPolicyResolver(),
		executor,
		nil,
		true,
		runner,
		"node-test",
		nil,
		nil,
	)
	if state.Level != fsm.LevelBlock {
		t.Fatalf("renewed active lease should keep visible state block, got %s", state.Level)
	}
	if len(pep.levels) != 1 {
		t.Fatalf("renewed lease should not call PEP transition again, transitions=%#v", pep.levels)
	}
}

func TestRuntimePDPActiveProjectsBrokerLeaseIntoVisibleState(t *testing.T) {
	now := time.Date(2026, 6, 23, 0, 10, 0, 0, time.UTC)
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()
	if err := store.UpsertActionLease(context.Background(), decision.ActionLease{
		LeaseID:      "lease-rate-limit",
		DecisionID:   "decision-rate-limit",
		NodeID:       "node-test",
		AdapterID:    "kliq-source-pep",
		Target:       "source:10.0.0.1",
		Action:       "enforce.traffic.rate_limit",
		Level:        "hard",
		Status:       decision.ActionLeaseActive,
		FencingToken: "token-rate-limit",
		AppliedAt:    now.Add(-10 * time.Second),
		ExpiresAt:    now.Add(time.Minute),
		Metadata:     map[string]string{"param.execution_dry_run": "false"},
	}); err != nil {
		t.Fatalf("insert lease: %v", err)
	}

	projected := projectRuntimePDPLeaseState(
		fsm.State{},
		metrics{
			Target: adapterruntime.SourceTarget{
				SourceID: "10.0.0.1",
				Subject:  observation.EntityRef{Kind: observation.KindIP, ID: "10.0.0.1"},
			},
		},
		"node-test",
		newRuntimePDPFactStore(store),
		now,
	)
	if projected.Level != fsm.LevelHard {
		t.Fatalf("projected runtime lease state = %s, want hard", projected.Level)
	}
	if !projected.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("projected expiry = %s, want %s", projected.ExpiresAt, now.Add(time.Minute))
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

func TestRuntimePDPInputIncludesActiveActionLeaseFacts(t *testing.T) {
	now := time.Date(2026, 6, 19, 13, 12, 0, 0, time.UTC)
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	if err := store.UpsertActionLease(context.Background(), decision.ActionLease{
		LeaseID:    "lease-rate-limit",
		DecisionID: "decision-rate-limit",
		NodeID:     "node-test",
		AdapterID:  "klshield",
		Target:     "source:10.0.0.1",
		Action:     "enforce.traffic.rate_limit",
		Level:      "hard",
		Status:     decision.ActionLeaseActive,
		AppliedAt:  now.Add(-time.Minute),
		ExpiresAt:  now.Add(5 * time.Minute),
		Metadata:   map[string]string{"param.execution_dry_run": "true"},
	}); err != nil {
		t.Fatalf("upsert action lease: %v", err)
	}

	input := runtimePDPInputForCandidate(
		"node-test",
		metrics{
			Target: adapterruntime.SourceTarget{
				SourceID: "10.0.0.1",
				Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.1"},
			},
			Score:   70,
			Signals: map[string]float64{},
		},
		fsm.State{},
		fsmIntent{ProposedLevel: fsm.LevelHard},
		newTestCfg(""),
		newRuntimePDPFactStore(store),
		now,
	)

	action, ok := input.Context.Actions["enforce_traffic_rate_limit"].(map[string]any)
	if !ok || action["active"] != true {
		t.Fatalf("active action fact missing: %#v", input.Context.Actions)
	}
	if got := action["level"]; got != "hard" {
		t.Fatalf("action level = %#v, want hard", got)
	}
	if got := action["dry_run"]; got != true {
		t.Fatalf("action dry_run = %#v, want true", got)
	}
	if got, ok := action["elapsed_seconds"].(float64); !ok || got < 60 {
		t.Fatalf("action elapsed_seconds = %#v, want >= 60", action["elapsed_seconds"])
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
	enforcement, ok := input.Context.Signals["enforcement"].(map[string]any)
	if !ok {
		t.Fatalf("missing nested enforcement facts: %#v", input.Context.Signals)
	}
	if got := enforcement["feedback_rate"]; got != 2.0 {
		t.Fatalf("enforcement.feedback_rate = %#v, want 2", got)
	}
	if got := enforcement["drop_rate"]; got != 2.0 {
		t.Fatalf("enforcement.drop_rate = %#v, want 2", got)
	}
	if got := enforcement["deny_rate"]; got != 0.0 {
		t.Fatalf("enforcement.deny_rate = %#v, want 0", got)
	}
	if got := enforcement["throttle_rate"]; got != 0.0 {
		t.Fatalf("enforcement.throttle_rate = %#v, want 0", got)
	}
	if got := enforcement["active"]; got != true {
		t.Fatalf("enforcement.active = %#v, want true", got)
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

func TestRuntimePDPInputForSignalIncludesNestedEnforcementFacts(t *testing.T) {
	now := time.Date(2026, 6, 19, 13, 25, 0, 0, time.UTC)
	sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, signal.SignalRateLimitDropsSustained, observation.EntityRef{
		Kind: observation.KindIP,
		ID:   "10.0.0.1",
	}).
		SetScore(75).
		SetConfidence(90).
		SetAttribute("drop_rl_rate", "3.5")

	input := runtimePDPInputForSignal("node-test", *sig, nil, now)
	if got := input.Context.Signals["enforcement_feedback_rate"]; got != 3.5 {
		t.Fatalf("enforcement feedback fact = %#v, want 3.5", got)
	}
	enforcement, ok := input.Context.Signals["enforcement"].(map[string]any)
	if !ok {
		t.Fatalf("missing nested enforcement facts: %#v", input.Context.Signals)
	}
	if got := enforcement["feedback_rate"]; got != 3.5 {
		t.Fatalf("enforcement.feedback_rate = %#v, want 3.5", got)
	}
	if got := enforcement["drop_rate"]; got != 3.5 {
		t.Fatalf("enforcement.drop_rate = %#v, want 3.5", got)
	}
	if got := enforcement["active"]; got != true {
		t.Fatalf("enforcement.active = %#v, want true", got)
	}

	groupFacts := runtimeSignalGroupFacts([]signal.Signal{*sig})
	groupEnforcement, ok := groupFacts["enforcement"].(map[string]any)
	if !ok {
		t.Fatalf("missing signal-group enforcement facts: %#v", groupFacts)
	}
	if got := groupEnforcement["drop_rate"]; got != 3.5 {
		t.Fatalf("group enforcement.drop_rate = %#v, want 3.5", got)
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
	prev   []fsm.Level
	levels []fsm.Level
	params []adapterruntime.EnforcementParams
}

func (p *recordingSourcePEP) TransitionSource(_ adapterruntime.SourceTarget, st fsm.State, target fsm.Level, now time.Time, params adapterruntime.EnforcementParams) (fsm.State, error) {
	p.prev = append(p.prev, st.Level)
	p.levels = append(p.levels, target)
	p.params = append(p.params, params)
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
