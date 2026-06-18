// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package featureset defines the runtime feature profiles for KLIQ.
// Each profile enables a specific combination of capabilities so that
// users can run a lightweight DoS-prevention setup without paying for
// graph learning, SQLite or source baselines.
package featureset

// RuntimeProfile identifies the active feature profile.
type RuntimeProfile string

const (
	// ProfileDOSLight: source heuristic + global autotune. No graph or SQLite.
	ProfileDOSLight RuntimeProfile = "dos-light"
	// ProfileIQLearning: adds per-source EWMA baseline (generic engine) on top of dos-light.
	ProfileIQLearning RuntimeProfile = "iq-learning"
	// ProfileGraphLearning: full graph + edge baseline + flow telemetry + SQLite.
	ProfileGraphLearning RuntimeProfile = "graph-learning"
	// ProfileGraphEnforce: graph-learning + tuple-based enforcement.
	ProfileGraphEnforce RuntimeProfile = "graph-enforce"
	// ProfileFullLearningExperimental: generic baselines + generic relationship learner
	// for all adapters (network, HTTP, Ziti, Trust).  Intended for test/lab use.
	ProfileFullLearningExperimental RuntimeProfile = "full-learning-experimental"
)

// FeatureSet describes which KLIQ capabilities are active.
// Only features listed as true are allowed to start their respective
// goroutines, open databases or emit observations.
type FeatureSet struct {
	PrimaryEnforcement bool
	UserspaceIQ        bool
	SourceHeuristic    bool
	GlobalAutotune     bool
	SourceBaseline     bool
	FlowTelemetry      bool
	GraphLearning      bool
	EdgeBaseline       bool
	SQLite             bool
	TupleEnforcement   bool

	// GenericBaseline enables UpdateWithBaselineKey in the metric baseline engine
	// and persists baselines to the state store (statestore/sqlite).
	GenericBaseline bool

	// GenericRelationshipLearner enables the pkg/relationshiplearner pipeline
	// alongside (or instead of) the L3/L4-specific graphstore path.
	GenericRelationshipLearner bool

	// StateStore enables opening pkg/statestore/sqlite alongside (or instead of)
	// the existing graphstore/sqlite.
	StateStore bool
}

// FeaturesFor returns the FeatureSet for a given RuntimeProfile.
// Unknown profiles fall back to ProfileDOSLight.
func FeaturesFor(profile RuntimeProfile) FeatureSet {
	switch profile {
	case ProfileDOSLight:
		return FeatureSet{
			PrimaryEnforcement: true,
			UserspaceIQ:        true,
			SourceHeuristic:    true,
			GlobalAutotune:     true,
		}

	case ProfileIQLearning:
		return FeatureSet{
			PrimaryEnforcement: true,
			UserspaceIQ:        true,
			SourceHeuristic:    true,
			GlobalAutotune:     true,
			SourceBaseline:     true,
			GenericBaseline:    true,
			StateStore:         true,
		}

	case ProfileGraphLearning:
		return FeatureSet{
			PrimaryEnforcement:         true,
			UserspaceIQ:                true,
			SourceHeuristic:            true,
			GlobalAutotune:             true,
			SourceBaseline:             true,
			FlowTelemetry:              true,
			GraphLearning:              true,
			EdgeBaseline:               true,
			SQLite:                     true,
			GenericBaseline:            true,
			GenericRelationshipLearner: true,
			StateStore:                 true,
		}

	case ProfileGraphEnforce:
		return FeatureSet{
			PrimaryEnforcement:         true,
			UserspaceIQ:                true,
			SourceHeuristic:            true,
			GlobalAutotune:             true,
			SourceBaseline:             true,
			FlowTelemetry:              true,
			GraphLearning:              true,
			EdgeBaseline:               true,
			SQLite:                     true,
			TupleEnforcement:           true,
			GenericBaseline:            true,
			GenericRelationshipLearner: true,
			StateStore:                 true,
		}

	case ProfileFullLearningExperimental:
		return FeatureSet{
			PrimaryEnforcement:         true,
			UserspaceIQ:                true,
			SourceHeuristic:            true,
			GlobalAutotune:             true,
			SourceBaseline:             true,
			FlowTelemetry:              true,
			GraphLearning:              true,
			EdgeBaseline:               true,
			SQLite:                     true,
			GenericBaseline:            true,
			GenericRelationshipLearner: true,
			StateStore:                 true,
		}

	default:
		return FeaturesFor(ProfileDOSLight)
	}
}
