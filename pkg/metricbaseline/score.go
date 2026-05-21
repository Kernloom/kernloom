// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package metricbaseline

import "math"

// Result is returned by Engine.Update for every metric processed.
// It contains both the scoring outcome and a snapshot of the profile state.
type Result struct {
	// Key identifies which profile this result belongs to.
	Key Key

	// Value is the metric value that was processed.
	Value float64

	// Expected is the EWMA (learned mean) at the time of this update.
	Expected float64

	// Sigma is the effective standard deviation (sqrt of EWMA variance).
	Sigma float64

	// DeviationScore is a normalised deviation score 0–100.
	// 0   = value exactly at the expected mean.
	// 100 = value is DeviationThreshold sigmas or more above the mean.
	// The score is symmetric: negative deviations use abs(value - expected).
	// Score is 0 when the profile is not yet promoted (insufficient data).
	DeviationScore float64

	// Confidence is the profile's confidence score 0.0–1.0.
	// Lower confidence means the baseline has less data and is less reliable.
	Confidence float64

	// Learned is true when this update modified the EWMA (non-suspicious).
	Learned bool

	// Suspicious is true when the caller marked this update as suspicious.
	// The EWMA was not updated but the metric was still scored.
	Suspicious bool

	// Promoted is true when the profile has met MinCount and is trusted.
	Promoted bool
}

// score computes the deviation score given the current profile state and value.
// Returns 0 if the profile is not yet promoted.
func score(p *Profile, value float64, cfg Config) float64 {
	if !p.Promoted {
		return 0
	}
	sigma := p.sigma(cfg.SigmaFloor)
	deviation := math.Abs(value - p.EWMA)
	// Normalise: score = min((deviation / sigma) / threshold * 100, 100)
	s := (deviation / sigma) / cfg.DeviationThreshold * 100
	return math.Min(s, 100)
}

// resultFromProfile builds a Result from the current profile state after an update.
func resultFromProfile(p *Profile, value float64, suspicious bool, learned bool, cfg Config) Result {
	return Result{
		Key:            p.Key,
		Value:          value,
		Expected:       p.EWMA,
		Sigma:          p.sigma(cfg.SigmaFloor),
		DeviationScore: score(p, value, cfg),
		Confidence:     p.Confidence,
		Learned:        learned,
		Suspicious:     suspicious,
		Promoted:       p.Promoted,
	}
}
