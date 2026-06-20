// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package klshieldruntime

import (
	"context"
	"testing"
	"time"

	shieldheuristic "github.com/kernloom/kernloom/pkg/adapters/klshield/signalengine"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

type recordingSourceBaseline struct {
	updates   int
	anomalous []bool
}

func (b *recordingSourceBaseline) Update(_ string, _, _, _, _ float64, anomalous bool, _ time.Time) {
	b.updates++
	b.anomalous = append(b.anomalous, anomalous)
}

func (b *recordingSourceBaseline) EffectiveTrigPPS(_ string, global float64) float64 {
	return global
}

func (b *recordingSourceBaseline) EffectiveTrigBPS(_ string, global float64) float64 {
	return global
}

func (b *recordingSourceBaseline) EffectiveTrigSyn(_ string, global float64) float64 {
	return global
}

func (b *recordingSourceBaseline) EffectiveTrigScan(_ string, global float64) float64 {
	return global
}

func TestObservationForLearnsCleanSourceBaselineSample(t *testing.T) {
	baseline := &recordingSourceBaseline{}
	adapter := New(Config{
		Engine:   configForObservationTest(100, 100, 100, 0),
		Baseline: baseline,
	})
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

	obs := adapter.observationFor(context.Background(), now, observation.EntityRef{ID: "10.0.0.1"}, "4", rateSample{
		PPS:      10,
		BPS:      1000,
		SynRate:  1,
		ScanRate: 1,
	})

	if obs.SourceID != "10.0.0.1" {
		t.Fatalf("observation source = %q", obs.SourceID)
	}
	if baseline.updates != 1 || baseline.anomalous[0] {
		t.Fatalf("clean sample should be learned, updates=%d anomalous=%v", baseline.updates, baseline.anomalous)
	}
	if obs.Attributes[AttributeTrigPPS] != "100.000000" {
		t.Fatalf("effective pps trigger attribute = %q", obs.Attributes[AttributeTrigPPS])
	}
	if obs.Attributes[AttributeBaselineLearnSkipped] != "false" {
		t.Fatalf("learn skipped attribute = %q", obs.Attributes[AttributeBaselineLearnSkipped])
	}
}

func TestObservationForSkipsSignalingSourceBaselineSample(t *testing.T) {
	baseline := &recordingSourceBaseline{}
	adapter := New(Config{
		Engine:   configForObservationTest(100, 100, 100, 0),
		Baseline: baseline,
	})
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)

	obs := adapter.observationFor(context.Background(), now, observation.EntityRef{ID: "10.0.0.1"}, "4", rateSample{
		PPS:      150,
		BPS:      1000,
		SynRate:  1,
		ScanRate: 1,
	})

	if len(obs.Signals) == 0 {
		t.Fatal("expected threshold-crossing sample to emit a signal")
	}
	if baseline.updates != 1 || !baseline.anomalous[0] {
		t.Fatalf("signaling sample should not be learned, updates=%d anomalous=%v", baseline.updates, baseline.anomalous)
	}
	if obs.Attributes[AttributeBaselineLearnSkipped] != "true" {
		t.Fatalf("learn skipped attribute = %q", obs.Attributes[AttributeBaselineLearnSkipped])
	}
	if obs.Attributes[AttributeBaselineSkipReason] != "signal_emitted" {
		t.Fatalf("skip reason = %q", obs.Attributes[AttributeBaselineSkipReason])
	}
}

func configForObservationTest(pps, syn, scan, bps float64) shieldheuristic.Config {
	return shieldheuristic.Config{
		TrigPPS:  pps,
		TrigSyn:  syn,
		TrigScan: scan,
		TrigBPS:  bps,
		WPPS:     1,
		WSyn:     1,
		WScan:    1,
		WBps:     1,
	}
}
