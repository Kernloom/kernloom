// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package signalengine_test

import (
	"context"
	"testing"

	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/signalengine"
)

// fakeEngine is a test-only implementation that satisfies the Engine interface.
type fakeEngine struct {
	name string
}

func (f *fakeEngine) Name() string { return f.name }

func (f *fakeEngine) Evaluate(_ context.Context, input signalengine.Input) ([]signal.Signal, error) {
	// Emit one signal per observation that has a severity hint above zero.
	var signals []signal.Signal
	for _, obs := range input.Observations {
		if obs.SeverityHint > 0 {
			s := signal.NewSignal(
				signal.ProducerKLIQ,
				signal.ScopeLocal,
				signal.SignalPPSHigh,
				obs.Subject,
			)
			signals = append(signals, *s)
		}
	}
	return signals, nil
}

// compile-time interface check
var _ signalengine.Engine = (*fakeEngine)(nil)

func TestFakeEngine_Interface(t *testing.T) {
	eng := &fakeEngine{name: "fake"}
	if eng.Name() != "fake" {
		t.Errorf("Name: got %q, want %q", eng.Name(), "fake")
	}
}

func TestFakeEngine_Evaluate_Empty(t *testing.T) {
	eng := &fakeEngine{name: "fake"}
	signals, err := eng.Evaluate(context.Background(), signalengine.Input{})
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("expected 0 signals for empty input, got %d", len(signals))
	}
}

func TestFakeEngine_Evaluate_WithObservations(t *testing.T) {
	eng := &fakeEngine{name: "fake"}

	obs := observation.NewObservation(observation.SourceShield, observation.TypeFlow, "node-1",
		observation.EntityRef{Kind: observation.KindIP, ID: "10.0.0.5"})
	obs.SetSeverityHint(70)

	input := signalengine.Input{
		Observations: []observation.Observation{*obs},
	}
	signals, err := eng.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}
	if len(signals) != 1 {
		t.Errorf("expected 1 signal, got %d", len(signals))
	}
}
