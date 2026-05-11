// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package featureset defines the runtime feature profiles for KLIQ.
// Each profile enables a specific combination of capabilities so that
// users can run a lightweight DoS-prevention setup without paying for
// graph learning, SQLite or source baselines.
package featureset

// RuntimeProfile identifies the active feature profile.
type RuntimeProfile string

const (
	// ProfileKLShieldLight: XDP only. No kliq process needed or useful.
	// Run klshield attach-xdp and manage deny/allow/RL via klshield CLI directly.
	ProfileKLShieldLight RuntimeProfile = "klshield-light"
	// ProfileDOSLight: source heuristic + global autotune. No graph or SQLite.
	ProfileDOSLight RuntimeProfile = "dos-light"
	// ProfileIQLearning: adds per-source baseline on top of dos-light.
	ProfileIQLearning RuntimeProfile = "iq-learning"
	// ProfileGraphLearning: full graph + edge baseline + flow telemetry + SQLite.
	ProfileGraphLearning RuntimeProfile = "graph-learning"
	// ProfileGraphEnforce: graph-learning + future tuple-based enforcement.
	ProfileGraphEnforce RuntimeProfile = "graph-enforce"
)

// FeatureSet describes which KLIQ capabilities are active.
// Only features listed as true are allowed to start their respective
// goroutines, open databases or emit observations.
type FeatureSet struct {
	ShieldXDP        bool
	UserspaceIQ      bool
	SourceHeuristic  bool
	GlobalAutotune   bool
	SourceBaseline   bool
	FlowTelemetry    bool
	GraphLearning    bool
	EdgeBaseline     bool
	SQLite           bool
	TupleEnforcement bool
}

// FeaturesFor returns the FeatureSet for a given RuntimeProfile.
// Unknown profiles fall back to ProfileDOSLight.
func FeaturesFor(profile RuntimeProfile) FeatureSet {
	switch profile {
	case ProfileKLShieldLight:
		return FeatureSet{ShieldXDP: true}

	case ProfileDOSLight:
		return FeatureSet{
			ShieldXDP:       true,
			UserspaceIQ:     true,
			SourceHeuristic: true,
			GlobalAutotune:  true,
		}

	case ProfileIQLearning:
		return FeatureSet{
			ShieldXDP:       true,
			UserspaceIQ:     true,
			SourceHeuristic: true,
			GlobalAutotune:  true,
			SourceBaseline:  true,
		}

	case ProfileGraphLearning:
		return FeatureSet{
			ShieldXDP:       true,
			UserspaceIQ:     true,
			SourceHeuristic: true,
			GlobalAutotune:  true,
			SourceBaseline:  true,
			FlowTelemetry:   true,
			GraphLearning:   true,
			EdgeBaseline:    true,
			SQLite:          true,
		}

	case ProfileGraphEnforce:
		return FeatureSet{
			ShieldXDP:        true,
			UserspaceIQ:      true,
			SourceHeuristic:  true,
			GlobalAutotune:   true,
			SourceBaseline:   true,
			FlowTelemetry:    true,
			GraphLearning:    true,
			EdgeBaseline:     true,
			SQLite:           true,
			TupleEnforcement: true,
		}

	default:
		return FeaturesFor(ProfileDOSLight)
	}
}
