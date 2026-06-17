// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package klshieldguard_test

import (
	"context"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/guard"
	"github.com/kernloom/kernloom/pkg/core/metric"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

func emptyInput() adapterruntime.LearningGuardInput {
	return adapterruntime.LearningGuardInput{
		Timestamp: time.Now(),
	}
}

func TestGuard_CleanWindow_NotSuspicious(t *testing.T) {
	g := klshieldguard.New(klshieldguard.DefaultConfig())
	dec := g.IsSuspicious(context.Background(), emptyInput())
	if dec.Suspicious {
		t.Errorf("clean window should not be suspicious, reasons: %v", dec.ReasonCodes)
	}
}

func TestGuard_Name(t *testing.T) {
	g := klshieldguard.New(klshieldguard.DefaultConfig())
	if g.Name() != "klshield" {
		t.Errorf("expected name 'klshield', got %q", g.Name())
	}
}

func TestGuard_ActiveEnforcement_Suspicious(t *testing.T) {
	g := klshieldguard.New(klshieldguard.DefaultConfig())
	input := emptyInput()
	input.FSMSnapshot = map[string]adapterruntime.FSMStateSnapshot{
		"10.0.0.1": {Level: "block", Strikes: 5},
	}
	dec := g.IsSuspicious(context.Background(), input)
	if !dec.Suspicious {
		t.Error("source in BLOCK should trigger suspicious window")
	}
}

func TestGuard_SoftEnforcement_Suspicious(t *testing.T) {
	g := klshieldguard.New(klshieldguard.DefaultConfig())
	input := emptyInput()
	input.FSMSnapshot = map[string]adapterruntime.FSMStateSnapshot{
		"10.0.0.2": {Level: "soft"},
	}
	dec := g.IsSuspicious(context.Background(), input)
	if !dec.Suspicious {
		t.Error("source in SOFT should trigger suspicious window")
	}
}

func TestGuard_PPSHighSignal_Suspicious(t *testing.T) {
	g := klshieldguard.New(klshieldguard.DefaultConfig())
	input := emptyInput()
	sig := signal.NewSignal(signal.ProducerKLIQ, signal.ScopeLocal, signal.SignalPPSHigh,
		signal.Signal{}.Subject)
	input.Signals = []signal.Signal{*sig}
	dec := g.IsSuspicious(context.Background(), input)
	if !dec.Suspicious {
		t.Error("active PPS_HIGH signal should trigger suspicious window")
	}
}

func TestGuard_HighDropRatio_Suspicious(t *testing.T) {
	g := klshieldguard.New(klshieldguard.DefaultConfig())
	input := emptyInput()
	m := metric.New("network.rate_limit_drop_rate", "klshield", metric.ScopeSourceIP,
		metric.Subject{Type: "node", Value: "node-1"}, 0.8, 10)
	batch := metric.NewBatch("klshield", time.Now(), time.Now())
	batch.Add(m)
	input.Metrics = batch
	dec := g.IsSuspicious(context.Background(), input)
	if !dec.Suspicious {
		t.Error("drop_ratio=0.8 should trigger suspicious window (threshold=0.5)")
	}
}

func TestGuard_BelowDropRatio_NotSuspicious(t *testing.T) {
	g := klshieldguard.New(klshieldguard.DefaultConfig())
	input := emptyInput()
	m := metric.New("network.rate_limit_drop_rate", "klshield", metric.ScopeSourceIP,
		metric.Subject{Type: "node", Value: "node-1"}, 0.1, 10)
	batch := metric.NewBatch("klshield", time.Now(), time.Now())
	batch.Add(m)
	input.Metrics = batch
	dec := g.IsSuspicious(context.Background(), input)
	if dec.Suspicious {
		t.Error("drop_ratio=0.1 should not be suspicious (below threshold)")
	}
}

func TestGuard_ObserveLevel_NotSuspicious(t *testing.T) {
	g := klshieldguard.New(klshieldguard.DefaultConfig())
	input := emptyInput()
	input.FSMSnapshot = map[string]adapterruntime.FSMStateSnapshot{
		"10.0.0.3": {Level: "observe"},
	}
	dec := g.IsSuspicious(context.Background(), input)
	if dec.Suspicious {
		t.Error("source in OBSERVE should not be suspicious")
	}
}

// compile-time interface check
var _ adapterruntime.LearningGuard = (*klshieldguard.Guard)(nil)
