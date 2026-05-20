// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package riskaggregator_test

import (
	"testing"

	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/riskaggregator"
)

func makeSig(subjectID string, score int, sigType signal.SignalType) signal.Signal {
	s := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, sigType,
		observation.EntityRef{Kind: observation.KindIP, ID: subjectID})
	s.SetScore(score)
	return *s
}

func TestAggregate_Empty(t *testing.T) {
	results := riskaggregator.Aggregate(riskaggregator.DefaultConfig(), nil)
	if len(results) != 0 {
		t.Errorf("expected empty results, got %d", len(results))
	}
}

func TestAggregate_Passthrough_OnePerSignal(t *testing.T) {
	sigs := []signal.Signal{
		makeSig("10.0.0.1", 70, signal.SignalPPSHigh),
		makeSig("10.0.0.1", 85, signal.SignalSYNRateHigh),
	}
	results := riskaggregator.Aggregate(riskaggregator.Config{Mode: riskaggregator.ModePassthrough}, sigs)
	if len(results) != 2 {
		t.Errorf("passthrough: expected 2 results, got %d", len(results))
	}
}

func TestAggregate_MaxScore_GroupsBySubject(t *testing.T) {
	sigs := []signal.Signal{
		makeSig("10.0.0.1", 70, signal.SignalPPSHigh),
		makeSig("10.0.0.1", 85, signal.SignalSYNRateHigh),
		makeSig("10.0.0.2", 60, signal.SignalScanSuspected),
	}
	results := riskaggregator.Aggregate(riskaggregator.Config{Mode: riskaggregator.ModeMaxScore}, sigs)
	if len(results) != 2 {
		t.Errorf("max_score: expected 2 results (one per subject), got %d", len(results))
	}

	bySubject := make(map[string]riskaggregator.Result)
	for _, r := range results {
		bySubject[r.SubjectID] = r
	}

	r1 := bySubject["10.0.0.1"]
	if r1.ShadowRisk != 85 {
		t.Errorf("expected top score=85 for 10.0.0.1, got %d", r1.ShadowRisk)
	}
	if r1.TopSignal.Type != signal.SignalSYNRateHigh {
		t.Errorf("expected top signal to be SYN_RATE_HIGH, got %v", r1.TopSignal.Type)
	}
	if len(r1.AllSignals) != 2 {
		t.Errorf("expected AllSignals to have 2 entries for 10.0.0.1, got %d", len(r1.AllSignals))
	}

	r2 := bySubject["10.0.0.2"]
	if r2.ShadowRisk != 60 {
		t.Errorf("expected score=60 for 10.0.0.2, got %d", r2.ShadowRisk)
	}
}

func TestAggregate_DefaultConfig_IsPassthrough(t *testing.T) {
	cfg := riskaggregator.DefaultConfig()
	if cfg.Mode != riskaggregator.ModePassthrough {
		t.Errorf("default config should be passthrough, got %s", cfg.Mode)
	}
}
