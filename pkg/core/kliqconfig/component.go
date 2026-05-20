// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package kliqconfig

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const (
	ComponentConfigAPIVersion = "kernloom.io/v1alpha1"
	ComponentConfigKind       = "KliqComponentConfig"
)

// KliqComponentConfig declares which local engines and adapters are active on
// this node. It is evaluated by Forge during enrollment to verify that the
// declared component inventory matches the runtime inventory.
//
// Note: signal engine thresholds and FSM parameters belong in PDPConfig, not
// here. KliqComponentConfig only controls which engines are enabled, not how
// they are tuned.
type KliqComponentConfig struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Metadata   ComponentMetadata `yaml:"metadata"`
	Spec       ComponentSpec     `yaml:"spec"`
}

type ComponentMetadata struct {
	Name string `yaml:"name"`
}

type ComponentSpec struct {
	Adapters  []AdapterConfig `yaml:"adapters,omitempty"`
	Analyzers AnalyzerConfigs `yaml:"analyzers,omitempty"`
}

// AdapterConfig describes a single local PEP or sensor adapter.
type AdapterConfig struct {
	ID      string         `yaml:"id"`
	Plugin  string         `yaml:"plugin"` // e.g. "builtin-klshield"
	Enabled bool           `yaml:"enabled"`
	Config  map[string]any `yaml:"config,omitempty"`
}

// AnalyzerConfigs groups all local analyzer settings.
type AnalyzerConfigs struct {
	Baseline       BaselineAnalyzerConfig       `yaml:"baseline,omitempty"`
	Graph          GraphAnalyzerConfig          `yaml:"graph,omitempty"`
	MetricPipeline MetricPipelineConfig         `yaml:"metric_pipeline,omitempty"`
	MetricBaseline MetricBaselineAnalyzerConfig `yaml:"metric_baseline,omitempty"`
}

type BaselineAnalyzerConfig struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

// GraphAnalyzerConfig controls the graph learner. Mode mirrors the kliq
// --graph-mode flag values (learn, frozen-observe, frozen-enforce).
type GraphAnalyzerConfig struct {
	Enabled *bool  `yaml:"enabled,omitempty"`
	Mode    string `yaml:"mode,omitempty"`
	Store   string `yaml:"store,omitempty"`
}

// MetricPipelineConfig is the top-level gate for the generic adapter metric
// pipeline (Track A/B). Disabled by default — enabling it has no effect until
// Track B is implemented and at least one adapter registers a FeatureExtractor.
type MetricPipelineConfig struct {
	// Enabled controls whether the generic metric pipeline runs alongside the
	// existing KLShield path. Default: false (no behavior change).
	Enabled *bool `yaml:"enabled,omitempty"`
}

// MetricBaselineAnalyzerConfig tunes the in-memory generic EWMA baseline engine
// (pkg/metricbaseline). All fields are optional; defaults mirror DefaultConfig().
type MetricBaselineAnalyzerConfig struct {
	// Enabled enables the generic baseline engine when the metric pipeline is
	// active. Default: false.
	Enabled *bool `yaml:"enabled,omitempty"`

	// Alpha is the EWMA learning rate for new (unpromoted) profiles.
	// Default: 0.10 (~7 obs half-life).
	Alpha float64 `yaml:"alpha,omitempty"`

	// AlphaPromoted is the slower EWMA learning rate after promotion.
	// Default: 0.02 (~35 obs half-life).
	AlphaPromoted float64 `yaml:"alpha_promoted,omitempty"`

	// MinCount is the number of non-suspicious learned values required before
	// a profile is promoted. Default: 30.
	MinCount uint64 `yaml:"min_count,omitempty"`

	// MaxProfiles is the maximum number of in-memory baseline profiles.
	// When reached, the engine evicts the lowest-confidence profiles first.
	// Default: 10000.
	MaxProfiles int `yaml:"max_profiles,omitempty"`

	// ProfileTTL is how long a profile may go without an update before eviction.
	// Use Go duration syntax, e.g. "24h". Default: 24h.
	ProfileTTL string `yaml:"profile_ttl,omitempty"`

	// SelectedLabels is the list of metric label keys used for baseline keying.
	// IMPORTANT: default is empty — all label variants share one profile.
	// Only add labels with bounded cardinality (e.g. "host", "route_group").
	// Never add: path, full_url, user_agent, session_id, request_id.
	SelectedLabels []string `yaml:"selected_labels,omitempty"`

	// DeviationThreshold is the number of sigma units that produces score=100.
	// Default: 4.0 (4-sigma event maps to score 100).
	DeviationThreshold float64 `yaml:"deviation_threshold,omitempty"`

	// SigmaFloor is the minimum sigma to prevent division-by-zero for
	// very stable metrics. Default: 0.01.
	SigmaFloor float64 `yaml:"sigma_floor,omitempty"`
}

// LoadComponentConfig reads and unmarshals a KliqComponentConfig YAML file.
func LoadComponentConfig(path string) (*KliqComponentConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c KliqComponentConfig
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse component config: %w", err)
	}
	if c.Kind != ComponentConfigKind && c.Kind != "" {
		return nil, fmt.Errorf("unexpected kind %q (want %s)", c.Kind, ComponentConfigKind)
	}
	return &c, nil
}
