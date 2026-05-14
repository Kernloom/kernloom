// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package baseline defines the shared types for per-edge traffic baselines.
// The actual EWMA update logic lives in pkg/adapters/graphlearner; the
// persistence layer is in pkg/graphstore/sqlite. This package provides the
// data model used by both.
package baseline

// State describes the learning maturity of an edge baseline profile.
type State string

const (
	// StateCandidate means the edge has not yet accumulated enough observations
	// for its EWMA to be considered stable. Deviation checks are suppressed.
	StateCandidate State = "candidate"

	// StateLearned means the EWMA has converged. Deviation and peak checks are
	// active; signals are emitted when traffic exceeds the learned profile.
	StateLearned State = "learned"
)

// EdgeProfile holds the EWMA traffic statistics for a single graph edge.
// These values are stored in-band with the graph edge (graph_edges.bl_* columns).
type EdgeProfile struct {
	// EWMA statistics (exponentially weighted moving average + mean absolute deviation).
	PPSMedian   float64
	PPSMad      float64
	BytesMedian float64
	BytesMad    float64

	// Running peak values (highest observed PPS/BPS after the profile is promoted).
	// Optional half-life decay can be applied to prevent a single spike from
	// permanently capping burst detection (see graphlearner BaselinePeakDecayHalfLife).
	PPSPeak float64
	BPSPeak float64

	// Observations is the total number of EWMA updates applied to this profile.
	Observations uint64

	// State is the current learning maturity of this profile.
	State State
}

// Summary combines the key fields of a graph edge with its baseline profile.
// Returned by ListEdgeBaselines for display and export purposes.
type Summary struct {
	SourceID        string
	DestinationID   string
	Protocol        string
	DestinationPort uint16
	Direction       string
	GraphState      string
	Profile         EdgeProfile
}
