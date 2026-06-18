// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package baseline defines adapter-neutral baseline identity and profile
// snapshots. Concrete adapters decide which metric IDs and dimensions they
// publish; core only stores numeric baseline state for those metrics.
package baseline

// State describes the learning maturity of a baseline profile.
type State string

const (
	// StateCandidate means the profile has not yet accumulated enough
	// observations to be considered stable. Deviation checks are suppressed.
	StateCandidate State = "candidate"

	// StateLearned means the profile has converged. Deviation and peak checks
	// may be active for the metric.
	StateLearned State = "learned"
)

// MetricProfile holds EWMA statistics for one metric bucket. The metric bucket
// itself is identified by Key, including adapter/source class, subject/object
// entities, dimensions hash, measurement type, truth class and window.
type MetricProfile struct {
	MetricID string

	// EWMA statistics for the metric value. Median is the smoothed center value;
	// MAD is the smoothed mean absolute deviation around that center.
	Median float64
	MAD    float64

	// Peak is the highest observed value after promotion. Optional decay may be
	// applied by the learning engine before persisting a snapshot.
	Peak float64

	// Observations is the total number of EWMA updates applied to this profile.
	Observations uint64

	// State is the current learning maturity of this profile.
	State State
}

// ProfileSet groups all learned metric profiles for one scoped subject/object
// bucket. Relationship-scoped baselines use Dimensions to describe the edge
// semantics; for a network adapter that may include protocol/destination_port,
// while an identity adapter may include service/identity/role dimensions.
type ProfileSet struct {
	Key        Key
	Dimensions map[string]string
	Metrics    map[string]MetricProfile
}

// Summary combines a baseline key, optional human-readable dimensions and one
// profile snapshot. It is intended for display/export code and does not encode
// any network-specific fields.
type Summary struct {
	Key        Key
	Dimensions map[string]string
	Profile    MetricProfile
}
