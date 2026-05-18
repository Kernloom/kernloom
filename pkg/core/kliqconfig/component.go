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
	Baseline BaselineAnalyzerConfig `yaml:"baseline,omitempty"`
	Graph    GraphAnalyzerConfig    `yaml:"graph,omitempty"`
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
