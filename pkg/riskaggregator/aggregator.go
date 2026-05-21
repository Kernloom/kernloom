// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package riskaggregator merges signals from multiple signal engines into a
// single risk score per subject. Initial implementation supports two modes:
//
//   - passthrough: returns the single input signal unchanged (no aggregation)
//   - maxscore: returns the highest scoring signal per subject group
//
// The risk aggregator is shadow-only in Track C: it does not generate real
// ActionProposals and has no FSM integration. Integration with the existing
// KLShield severity+FSM path is deferred to Track D.
package riskaggregator

import (
	"github.com/kernloom/kernloom/pkg/core/signal"
)

// Mode controls aggregation behavior.
type Mode string

const (
	// ModePassthrough returns signals unchanged — no aggregation.
	ModePassthrough Mode = "passthrough"

	// ModeMaxScore groups signals by subject and returns the highest scorer per group.
	ModeMaxScore Mode = "max_score"
)

// Config controls the aggregator.
type Config struct {
	Mode Mode
}

// DefaultConfig returns shadow-mode passthrough defaults.
func DefaultConfig() Config {
	return Config{Mode: ModePassthrough}
}

// Result holds the aggregated output for one subject.
type Result struct {
	// SubjectID is the subject value (e.g. source IP).
	SubjectID string

	// TopSignal is the highest-scoring signal for this subject.
	TopSignal signal.Signal

	// AllSignals are all signals for this subject (for audit logging).
	AllSignals []signal.Signal

	// ShadowRisk is the aggregated risk score 0–100.
	ShadowRisk int
}

// Aggregate merges the given signals according to cfg.Mode.
// Returns one Result per unique subject.
func Aggregate(cfg Config, signals []signal.Signal) []Result {
	if len(signals) == 0 {
		return nil
	}
	switch cfg.Mode {
	case ModeMaxScore:
		return aggregateMaxScore(signals)
	default: // ModePassthrough
		return aggregatePassthrough(signals)
	}
}

// aggregatePassthrough returns one Result per signal (no merging).
func aggregatePassthrough(signals []signal.Signal) []Result {
	results := make([]Result, 0, len(signals))
	for _, sig := range signals {
		results = append(results, Result{
			SubjectID:  sig.Subject.ID,
			TopSignal:  sig,
			AllSignals: []signal.Signal{sig},
			ShadowRisk: sig.Score,
		})
	}
	return results
}

// aggregateMaxScore groups by subject.ID and picks the highest-scoring signal.
func aggregateMaxScore(signals []signal.Signal) []Result {
	groups := make(map[string][]signal.Signal)
	for _, sig := range signals {
		groups[sig.Subject.ID] = append(groups[sig.Subject.ID], sig)
	}

	results := make([]Result, 0, len(groups))
	for subjectID, sigs := range groups {
		top := sigs[0]
		for _, s := range sigs[1:] {
			if s.Score > top.Score {
				top = s
			}
		}
		results = append(results, Result{
			SubjectID:  subjectID,
			TopSignal:  top,
			AllSignals: sigs,
			ShadowRisk: top.Score,
		})
	}
	return results
}
