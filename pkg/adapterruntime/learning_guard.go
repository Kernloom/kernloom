// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapterruntime

import (
	"context"
	"time"

	"github.com/kernloom/kernloom/pkg/core/metric"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

// FSMStateSnapshot is a lightweight view of the FSM state for a subject.
// Passed to LearningGuard so it can check whether a source is already being enforced.
type FSMStateSnapshot struct {
	// Level is the current enforcement level: observe|soft|hard|block.
	Level string

	// Strikes is the current strike count.
	Strikes int
}

// LearningGuardInput is the full context for one anti-poisoning decision.
type LearningGuardInput struct {
	// Observations are the raw observations for this evaluation window.
	Observations []observation.Observation

	// Metrics are the computed metrics for this window.
	Metrics metric.Batch

	// Signals are the signals produced by signal engines this window.
	Signals []signal.Signal

	// FSMSnapshot is the current FSM state for the primary subject (optional).
	// Keyed by subject value (e.g. IP address string).
	FSMSnapshot map[string]FSMStateSnapshot

	// Timestamp is the wall time for this evaluation.
	Timestamp time.Time
}

// LearningGuardDecision is the outcome of one anti-poisoning check.
type LearningGuardDecision struct {
	// Suspicious is true when this window should not be learned into the baseline.
	Suspicious bool

	// ReasonCodes explain why the window is suspicious.
	ReasonCodes []string

	// Confidence is how certain the guard is (0.0–1.0).
	Confidence float64
}

// LearningGuard decides whether a metric window is safe to learn from.
// Each domain (KLShield, HTTP, OpenZiti, …) implements its own guard.
// The generic metric baseline engine accepts the Suspicious flag from the guard —
// it does not decide suspiciousness itself.
//
// Anti-poisoning is domain-specific: what makes an HTTP window suspicious
// (high auth_fail_rate + many login attempts) is completely different from
// what makes a network window suspicious (severity spike, active blocks).
//
// Do not implement global suspicious logic in the baseline engine.
// Implement it here, per domain.
type LearningGuard interface {
	// Name returns the guard's unique identifier (e.g. "klshield", "http").
	Name() string

	// IsSuspicious evaluates whether the current window should be skipped for learning.
	IsSuspicious(ctx context.Context, input LearningGuardInput) LearningGuardDecision
}

// PassthroughLearningGuard always returns not-suspicious. Useful as a no-op
// guard when anti-poisoning is not yet implemented for a domain.
type PassthroughLearningGuard struct {
	name string
}

// NewPassthroughGuard creates a learning guard that never marks windows suspicious.
func NewPassthroughGuard(name string) LearningGuard {
	return &PassthroughLearningGuard{name: name}
}

func (g *PassthroughLearningGuard) Name() string { return g.name }

func (g *PassthroughLearningGuard) IsSuspicious(_ context.Context, _ LearningGuardInput) LearningGuardDecision {
	return LearningGuardDecision{Suspicious: false, Confidence: 1.0}
}
