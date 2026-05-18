// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package decisionengine_test

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/reason"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/decisionengine"
)

/* ---- helpers ---- */

func basePolicy() decisionengine.LocalPolicy {
	return decisionengine.LocalPolicy{
		NodeID:              "test-node",
		DryRun:              false,
		MaxAction:           decision.ActionBlock,
		AllowLocalBlock:     true,
		GraphFreezeAction:   decision.ActionRateLimit,
		GraphFreezeTTL:      5 * time.Minute,
		LevelSoft:           decision.ActionRateLimit,
		LevelHard:           decision.ActionRateLimit,
		LevelBlock:          decision.ActionBlock,
		SoftTTL:             2 * time.Minute,
		HardTTL:             5 * time.Minute,
		BlockTTL:            10 * time.Minute,
		MinSeverityForBlock: 70,
	}
}

func graphSignal(subjectID string, score int) signal.Signal {
	return signal.Signal{
		ID:          "sig-test-1",
		Time:        time.Now().UTC(),
		Producer:    signal.ProducerKLIQ,
		Scope:       signal.ScopeLocal,
		Type:        signal.SignalGraphNewEdgeAfterFreeze,
		Subject:     observation.EntityRef{Kind: observation.KindIP, ID: subjectID},
		Score:       score,
		Confidence:  80,
		TTL:         10 * time.Minute,
		ReasonCodes: []string{reason.GraphNewEdgeAfterFreeze},
	}
}

/* ---- EvaluateSignal tests ---- */

// EvaluateSignal is always audit-only: it returns a Decision for the audit trail
// but never calls a PEP directly. Enforcement is handled by the main tick loop
// via FSM strike injection (graphStrikeCh). The enforcement_via attribute indicates
// whether the signal will trigger normal FSM strike accumulation (fsm_strikes) or
// an immediate forced BLOCK transition (fsm_force_block).

func TestEvaluateSignal_GraphFreezeRateLimit(t *testing.T) {
	pol := basePolicy()
	pol.GraphFreezeAction = decision.ActionRateLimit
	eng := decisionengine.New(pol)

	sig := graphSignal("203.0.113.1", 80)
	dec, receipt, err := eng.EvaluateSignal(context.Background(), sig)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected a decision, got nil")
	}
	if receipt != nil {
		t.Errorf("expected no receipt (audit-only), got %+v", receipt)
	}
	if dec.Action.Type != decision.ActionRateLimit {
		t.Errorf("expected action rate_limit, got %s", dec.Action.Type)
	}
}

func TestEvaluateSignal_GraphFreezeSignalOnly(t *testing.T) {
	pol := basePolicy()
	pol.GraphFreezeAction = decision.ActionSignal
	eng := decisionengine.New(pol)

	sig := graphSignal("203.0.113.2", 75)
	dec, receipt, err := eng.EvaluateSignal(context.Background(), sig)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected an audit decision, got nil")
	}
	if receipt != nil {
		t.Errorf("expected no receipt (audit-only), got %+v", receipt)
	}
}

func TestEvaluateSignal_BlockBelowMinSeverity(t *testing.T) {
	pol := basePolicy()
	pol.GraphFreezeAction = decision.ActionBlock
	pol.AllowLocalBlock = true
	pol.MaxAction = decision.ActionBlock
	pol.MinSeverityForBlock = 80
	eng := decisionengine.New(pol)

	sig := graphSignal("203.0.113.3", 60)
	dec, receipt, err := eng.EvaluateSignal(context.Background(), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected an audit decision, got nil")
	}
	if receipt != nil {
		t.Errorf("expected no receipt (audit-only), got %+v", receipt)
	}
	if dec.Attributes["enforcement_via"] != "fsm_strikes" {
		t.Errorf("expected enforcement_via=fsm_strikes, got %s", dec.Attributes["enforcement_via"])
	}
}

func TestEvaluateSignal_BlockAboveMinSeverity(t *testing.T) {
	pol := basePolicy()
	pol.GraphFreezeAction = decision.ActionBlock
	pol.AllowLocalBlock = true
	pol.MaxAction = decision.ActionBlock
	pol.MinSeverityForBlock = 80
	eng := decisionengine.New(pol)

	sig := graphSignal("203.0.113.4", 85)
	dec, receipt, err := eng.EvaluateSignal(context.Background(), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected a decision, got nil")
	}
	if receipt != nil {
		t.Errorf("expected no receipt (audit-only), got %+v", receipt)
	}
	if dec.Attributes["enforcement_via"] != "fsm_force_block" {
		t.Errorf("expected enforcement_via=fsm_force_block, got %s", dec.Attributes["enforcement_via"])
	}
}

func TestEvaluateSignal_AllowLocalBlockFalse_CapsToRateLimit(t *testing.T) {
	pol := basePolicy()
	pol.GraphFreezeAction = decision.ActionBlock
	pol.AllowLocalBlock = false
	pol.MaxAction = decision.ActionBlock
	eng := decisionengine.New(pol)

	sig := graphSignal("203.0.113.5", 90)
	dec, _, err := eng.EvaluateSignal(context.Background(), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected a decision, got nil")
	}
	if dec.Action.Type != decision.ActionRateLimit {
		t.Errorf("expected action rate_limit (capped), got %s", dec.Action.Type)
	}
}

func TestEvaluateSignal_MaxActionCap(t *testing.T) {
	pol := basePolicy()
	pol.GraphFreezeAction = decision.ActionBlock
	pol.AllowLocalBlock = true
	pol.MaxAction = decision.ActionRateLimit
	eng := decisionengine.New(pol)

	sig := graphSignal("203.0.113.6", 90)
	dec, _, err := eng.EvaluateSignal(context.Background(), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected a decision, got nil")
	}
	if dec.Action.Type != decision.ActionRateLimit {
		t.Errorf("expected rate_limit (MaxAction cap), got %s", dec.Action.Type)
	}
}

func TestEvaluateSignal_NonGraphSignal_ReturnsNil(t *testing.T) {
	eng := decisionengine.New(basePolicy())

	sig := signal.Signal{
		Type:    signal.SignalCampaignDistributedScan,
		Subject: observation.EntityRef{Kind: observation.KindIP, ID: "203.0.113.7"},
		Score:   90,
	}
	dec, receipt, err := eng.EvaluateSignal(context.Background(), sig)
	if err != nil || dec != nil || receipt != nil {
		t.Errorf("expected nil, nil, nil for non-graph signal; got dec=%v receipt=%v err=%v", dec, receipt, err)
	}
}

func TestEvaluateSignal_DryRun(t *testing.T) {
	pol := basePolicy()
	pol.DryRun = true
	pol.GraphFreezeAction = decision.ActionRateLimit
	eng := decisionengine.New(pol)

	sig := graphSignal("203.0.113.8", 80)
	dec, _, err := eng.EvaluateSignal(context.Background(), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected decision in dry-run mode")
	}
	if !dec.DryRun {
		t.Error("expected DryRun=true on decision")
	}
}

func TestEvaluateSignal_ReasonCodePropagated(t *testing.T) {
	pol := basePolicy()
	pol.GraphFreezeAction = decision.ActionRateLimit
	eng := decisionengine.New(pol)

	sig := graphSignal("203.0.113.9", 80)
	sig.ReasonCodes = []string{reason.GraphNewEdgeAfterFreeze, reason.GraphNewPeer}
	dec, _, err := eng.EvaluateSignal(context.Background(), sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dec == nil {
		t.Fatal("expected a decision")
	}

	found := 0
	for _, rc := range dec.ReasonCodes {
		if rc == reason.GraphNewEdgeAfterFreeze || rc == reason.GraphNewPeer {
			found++
		}
	}
	if found < 2 {
		t.Errorf("expected both reason codes propagated, got %v", dec.ReasonCodes)
	}
}

/* ---- RecordFSMTransition tests ---- */

func TestRecordFSMTransition_ObserveToSoft(t *testing.T) {
	eng := decisionengine.New(basePolicy())

	subj := observation.EntityRef{Kind: observation.KindIP, ID: "10.0.0.1"}
	dec := eng.RecordFSMTransition(subj, fsm.LevelObserve, fsm.LevelSoft, 0.6, reason.PPSHigh)

	if dec == nil {
		t.Fatal("expected a decision")
	}
	if dec.Action.Type != decision.ActionRateLimit {
		t.Errorf("expected rate_limit for soft level, got %s", dec.Action.Type)
	}
	if dec.Subject.ID != "10.0.0.1" {
		t.Errorf("expected subject 10.0.0.1, got %s", dec.Subject.ID)
	}
}
