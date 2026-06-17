// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package klshieldguard implements the LearningGuard for the KLShield adapter.
// It wraps existing KLShield-specific anti-poisoning semantics so the generic
// metric baseline engine can skip suspicious windows without the baseline engine
// knowing anything about network heuristics.
//
// This is a wrapper — it does NOT change existing autotune/source-baseline behavior.
// The existing learnSevGT / learnFracGT / drop-ratio logic in kliq.go remains
// the authoritative anti-poisoning path for the existing KLShield path.
// This guard only provides the same semantics to the shadow generic pipeline.
package klshieldguard

import (
	"context"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

// Config controls the thresholds for the KLShield learning guard.
// Fields mirror the existing kliq anti-poisoning flags (LearnSevGT, etc.).
type Config struct {
	// MaxSeverityToLearn is the severity ceiling below which learning is allowed.
	// Windows with severity >= MaxSeverityToLearn are marked suspicious.
	// Mirrors existing LearnSevGT (default: skip if sev >= 0.4).
	MaxSeverityToLearn float64

	// MaxDropRatio is the maximum rate-limit drop ratio allowed during learning.
	// Mirrors existing LearnMaxDropRatio.
	MaxDropRatio float64

	// BlockLevelNames are FSM level strings that indicate active enforcement.
	// A source in any of these levels should not be learned from.
	BlockLevelNames []string
}

// DefaultConfig returns safe defaults matching the existing kliq CLI defaults.
func DefaultConfig() Config {
	return Config{
		MaxSeverityToLearn: 0.4,
		MaxDropRatio:       0.5,
		BlockLevelNames:    []string{"soft", "hard", "block"},
	}
}

// Guard implements LearningGuard for KLShield telemetry windows.
// It checks FSM state and active signals to determine whether a window is safe to learn.
type Guard struct {
	cfg Config
}

// New creates a KLShield learning guard with the given config.
func New(cfg Config) adapterruntime.LearningGuard {
	return &Guard{cfg: cfg}
}

func (g *Guard) Name() string { return "klshield" }

// IsSuspicious returns true when the current window should not be learned.
// Suspicious conditions:
//   - source is already in SOFT/HARD/BLOCK FSM level
//   - PPS_HIGH or SYN_RATE_HIGH signal is active (indicates attack-level traffic)
//   - drop-ratio metric exceeds configured threshold
func (g *Guard) IsSuspicious(_ context.Context, input adapterruntime.LearningGuardInput) adapterruntime.LearningGuardDecision {
	var reasons []string

	// Check FSM state: if any subject is being enforced, mark window suspicious.
	for subjectID, fsm := range input.FSMSnapshot {
		for _, blocked := range g.cfg.BlockLevelNames {
			if fsm.Level == blocked {
				reasons = append(reasons, "source_in_enforcement:"+subjectID)
				break
			}
		}
	}

	// Check signals: high-severity heuristic signals indicate active attack.
	for _, sig := range input.Signals {
		if sig.Type == signal.SignalPPSHigh || sig.Type == signal.SignalSYNRateHigh || sig.Type == signal.SignalBPSHigh {
			reasons = append(reasons, "active_signal:"+string(sig.Type))
		}
	}

	// Check drop-ratio metric: high sustained drops suggest active RL enforcement.
	for _, m := range input.Metrics.Metrics {
		if m.ID == "network.rate_limit_drop_rate" && g.cfg.MaxDropRatio > 0 && m.Value > g.cfg.MaxDropRatio {
			reasons = append(reasons, "drop_ratio_exceeded")
		}
	}

	return adapterruntime.LearningGuardDecision{
		Suspicious:  len(reasons) > 0,
		ReasonCodes: reasons,
		Confidence:  1.0,
	}
}
