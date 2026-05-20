// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package metricbaseline

import "time"

// Config controls the behaviour of the metric baseline Engine.
type Config struct {
	// Alpha is the EWMA adaptation speed for new (unpromoted) profiles.
	// Lower = slower learning. Default: 0.10 (~7 obs half-life).
	Alpha float64

	// AlphaPromoted is the slower EWMA speed after a profile is promoted.
	// Default: 0.02 (~35 obs half-life) — stable baselines adapt slowly.
	AlphaPromoted float64

	// MinCount is the number of non-suspicious learned values required before
	// a profile is promoted and Confidence starts growing meaningfully.
	// Default: 30.
	MinCount uint64

	// MaxProfiles is the maximum number of baseline profiles held in memory.
	// When reached, the engine evicts the lowest-confidence profiles first.
	// Default: 10_000.
	MaxProfiles int

	// ProfileTTL is how long a profile may go without an update before it is
	// eligible for TTL eviction. Default: 24h.
	ProfileTTL time.Duration

	// SelectedLabels is the list of label keys used for baseline keying.
	// IMPORTANT: default is empty, which means labels are ignored for keying
	// and all variants of a metric share one profile. This prevents cardinality
	// explosion when adapters attach high-cardinality labels (paths, user-agents).
	//
	// Only add labels here that have bounded cardinality, e.g. "host", "route_group".
	// Never add: path, full_url, user_agent, session_id, request_id.
	SelectedLabels []string

	// DeviationThreshold is the number of sigma units above the mean that
	// constitutes a notable deviation (used for score normalisation).
	// A value at mean+DeviationThreshold*sigma produces score ~100.
	// Default: 4.0 (4-sigma event = score 100).
	DeviationThreshold float64

	// SigmaFloor is the minimum sigma used in deviation scoring to prevent
	// division-by-zero when the variance is very small (e.g. perfectly stable metric).
	// Default: 0.01 (1% of typical metric scale is a reasonable floor).
	SigmaFloor float64
}

// DefaultConfig returns safe production defaults.
// metric_pipeline.enabled must be set separately in KLIQ config.
func DefaultConfig() Config {
	return Config{
		Alpha:              0.10,
		AlphaPromoted:      0.02,
		MinCount:           30,
		MaxProfiles:        10_000,
		ProfileTTL:         24 * time.Hour,
		SelectedLabels:     nil, // empty = no label keying (cardinality-safe default)
		DeviationThreshold: 4.0,
		SigmaFloor:         0.01,
	}
}
