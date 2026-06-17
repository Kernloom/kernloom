// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package shieldheuristic_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/klshield/signalengine"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

var subject = observation.EntityRef{Kind: observation.KindIP, ID: "203.0.113.1"}

func baseConfig() shieldheuristic.Config {
	return shieldheuristic.Config{
		NodeID:    "node-test",
		TrigPPS:   1000,
		TrigSyn:   200,
		TrigScan:  20,
		WPPS:      0.5,
		WSyn:      0.3,
		WScan:     0.2,
		SevCap:    3.0,
		SignalTTL: 2 * time.Minute,
	}
}

func TestEvaluate_NoSignals_BelowThreshold(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	m, sigs := e.Evaluate(subject, 500, 50000, 100, 10, 0)
	if len(sigs) != 0 {
		t.Errorf("expected no signals below threshold, got %d", len(sigs))
	}
	if m.PPS != 500 {
		t.Errorf("expected PPS=500 in metrics, got %.1f", m.PPS)
	}
}

func TestEvaluate_PPSHigh_Signal(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	_, sigs := e.Evaluate(subject, 1000, 0, 0, 0, 0)

	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	if sigs[0].Type != signal.SignalPPSHigh {
		t.Errorf("expected %s, got %s", signal.SignalPPSHigh, sigs[0].Type)
	}
	if sigs[0].Score < 50 {
		t.Errorf("score at threshold should be >= 50, got %d", sigs[0].Score)
	}
}

func TestEvaluate_SYNRateHigh_Signal(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	_, sigs := e.Evaluate(subject, 0, 0, 200, 0, 0)

	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	if sigs[0].Type != signal.SignalSYNRateHigh {
		t.Errorf("expected %s, got %s", signal.SignalSYNRateHigh, sigs[0].Type)
	}
}

func TestEvaluate_ScanSuspected_Signal(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	_, sigs := e.Evaluate(subject, 0, 0, 0, 20, 0)

	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	if sigs[0].Type != signal.SignalScanSuspected {
		t.Errorf("expected %s, got %s", signal.SignalScanSuspected, sigs[0].Type)
	}
}

func TestEvaluate_DropRL_Signal(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	_, sigs := e.Evaluate(subject, 0, 0, 0, 0, 1.5)

	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal, got %d", len(sigs))
	}
	if sigs[0].Type != signal.SignalRateLimitDropsSustained {
		t.Errorf("expected %s, got %s", signal.SignalRateLimitDropsSustained, sigs[0].Type)
	}
	if sigs[0].Confidence != 90 {
		t.Errorf("expected confidence=90 for RL drops, got %d", sigs[0].Confidence)
	}
}

func TestEvaluate_MultipleSignals(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	// All three primary metrics above threshold plus RL drops.
	_, sigs := e.Evaluate(subject, 2000, 200000, 400, 40, 5)

	if len(sigs) != 4 {
		t.Fatalf("expected 4 signals (pps+syn+scan+rl), got %d", len(sigs))
	}

	types := make(map[signal.SignalType]bool)
	for _, s := range sigs {
		types[s.Type] = true
	}
	for _, want := range []signal.SignalType{
		signal.SignalPPSHigh,
		signal.SignalSYNRateHigh,
		signal.SignalScanSuspected,
		signal.SignalRateLimitDropsSustained,
	} {
		if !types[want] {
			t.Errorf("missing expected signal type %s", want)
		}
	}
}

func TestEvaluate_ZeroTrigger_DisablesMetric(t *testing.T) {
	cfg := baseConfig()
	cfg.TrigPPS = 0 // disabled
	e := shieldheuristic.New(cfg)

	_, sigs := e.Evaluate(subject, 999999, 0, 0, 0, 0)
	for _, s := range sigs {
		if s.Type == signal.SignalPPSHigh {
			t.Error("pps_high should not fire when TrigPPS=0")
		}
	}
}

func TestEvaluate_MetricsFilledCorrectly(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	m, _ := e.Evaluate(subject, 123, 456, 78, 9, 1)

	if m.PPS != 123 {
		t.Errorf("PPS: want 123, got %.0f", m.PPS)
	}
	if m.Bps != 456 {
		t.Errorf("Bps: want 456, got %.0f", m.Bps)
	}
	if m.SynRate != 78 {
		t.Errorf("SynRate: want 78, got %.0f", m.SynRate)
	}
	if m.ScanRate != 9 {
		t.Errorf("ScanRate: want 9, got %.0f", m.ScanRate)
	}
	if m.DropRLRate != 1 {
		t.Errorf("DropRLRate: want 1, got %.0f", m.DropRLRate)
	}
	if m.Severity < 0 || m.Severity > 1 {
		t.Errorf("Severity out of [0,1]: got %.3f", m.Severity)
	}
}

func TestEvaluate_ScoreAtThreshold_Is50(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	// Exactly at TrigPPS=1000 with no other metrics.
	_, sigs := e.Evaluate(subject, 1000, 0, 0, 0, 0)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal")
	}
	if sigs[0].Score != 50 {
		t.Errorf("score at exact threshold should be 50, got %d", sigs[0].Score)
	}
}

func TestEvaluate_ScoreAtCap_Is100(t *testing.T) {
	e := shieldheuristic.New(baseConfig()) // SevCap=3.0
	// norm = 3000/1000 = 3.0 = SevCap → score should be 100.
	_, sigs := e.Evaluate(subject, 3000, 0, 0, 0, 0)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal")
	}
	if sigs[0].Score != 100 {
		t.Errorf("score at SevCap should be 100, got %d", sigs[0].Score)
	}
}

func TestEvaluate_ScoreAboveCap_Clamped(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	_, sigs := e.Evaluate(subject, 99999, 0, 0, 0, 0)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal")
	}
	if sigs[0].Score > 100 {
		t.Errorf("score must not exceed 100, got %d", sigs[0].Score)
	}
}

func TestEvaluate_SignalTTL_Applied(t *testing.T) {
	cfg := baseConfig()
	cfg.SignalTTL = 7 * time.Minute
	e := shieldheuristic.New(cfg)
	_, sigs := e.Evaluate(subject, 1000, 0, 0, 0, 0)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal")
	}
	if sigs[0].TTL != 7*time.Minute {
		t.Errorf("expected TTL=7m, got %v", sigs[0].TTL)
	}
}

func TestEvaluate_SignalSubjectMatchesInput(t *testing.T) {
	e := shieldheuristic.New(baseConfig())
	sub := observation.EntityRef{Kind: observation.KindIP, ID: "198.51.100.42"}
	_, sigs := e.Evaluate(sub, 1000, 0, 0, 0, 0)
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signal")
	}
	if sigs[0].Subject.ID != "198.51.100.42" {
		t.Errorf("signal subject mismatch: got %s", sigs[0].Subject.ID)
	}
}

func TestUpdateConfig_ChangesThresholds(t *testing.T) {
	cfg := baseConfig()
	cfg.TrigPPS = 5000 // starts high — 1000 pps will not fire
	e := shieldheuristic.New(cfg)

	_, sigs := e.Evaluate(subject, 1000, 0, 0, 0, 0)
	if len(sigs) != 0 {
		t.Errorf("before UpdateConfig: expected 0 signals, got %d", len(sigs))
	}

	// Lower the threshold so 1000 pps now fires.
	newCfg := cfg
	newCfg.TrigPPS = 500
	e.UpdateConfig(newCfg)

	_, sigs = e.Evaluate(subject, 1000, 0, 0, 0, 0)
	if len(sigs) != 1 || sigs[0].Type != signal.SignalPPSHigh {
		t.Errorf("after UpdateConfig: expected pps_high signal, got %v", sigs)
	}
}

func TestDefaultsApplied_ZeroConfig(t *testing.T) {
	// Zero config should still produce a usable engine with defaults.
	e := shieldheuristic.New(shieldheuristic.Config{})
	cfg := e.Config()
	if cfg.SevCap <= 0 {
		t.Errorf("SevCap default not applied: got %.1f", cfg.SevCap)
	}
	if cfg.SignalTTL <= 0 {
		t.Errorf("SignalTTL default not applied: got %v", cfg.SignalTTL)
	}
}
