// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package shieldpep

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// CapabilityParams holds the Shield-specific parameters for each abstract
// capability level. These are PEP implementation details — they do NOT belong
// in the PolicyPack. The PolicyPack says "rate_limit"; the adapter manifest
// says "rate_limit means 20 pps / 40 burst for the soft level".
type CapabilityParams struct {
	SoftRatePPS uint64
	SoftBurst   uint64
	HardRatePPS uint64
	HardBurst   uint64
	Cooldown    time.Duration
}

// DefaultCapabilityParams returns built-in safe defaults equivalent to the
// former ziti-controller profile values.
func DefaultCapabilityParams() CapabilityParams {
	return CapabilityParams{
		SoftRatePPS: 20,
		SoftBurst:   40,
		HardRatePPS: 5,
		HardBurst:   10,
		Cooldown:    5 * time.Second,
	}
}

// adapterManifest is the raw YAML structure for an adapter manifest file.
type adapterManifest struct {
	Kind         string                     `yaml:"kind"`
	Adapter      string                     `yaml:"adapter"`
	Version      string                     `yaml:"version"`
	Capabilities map[string]capabilityEntry `yaml:"capabilities"`
}

type capabilityEntry struct {
	Params map[string]interface{} `yaml:"params"`
}

// LoadManifest parses a shield-pep adapter manifest YAML file and returns the
// resolved CapabilityParams. Unknown fields are ignored; missing fields fall
// back to DefaultCapabilityParams values.
func LoadManifest(path string) (CapabilityParams, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CapabilityParams{}, fmt.Errorf("adapter manifest: read %s: %w", path, err)
	}
	var m adapterManifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return CapabilityParams{}, fmt.Errorf("adapter manifest: parse %s: %w", path, err)
	}

	p := DefaultCapabilityParams()

	if rl, ok := m.Capabilities["network.rate_limit_source"]; ok {
		if soft, ok := rl.Params["soft"].(map[string]interface{}); ok {
			if v, ok := toUint64(soft["rate_pps"]); ok {
				p.SoftRatePPS = v
			}
			if v, ok := toUint64(soft["burst"]); ok {
				p.SoftBurst = v
			}
		}
		if hard, ok := rl.Params["hard"].(map[string]interface{}); ok {
			if v, ok := toUint64(hard["rate_pps"]); ok {
				p.HardRatePPS = v
			}
			if v, ok := toUint64(hard["burst"]); ok {
				p.HardBurst = v
			}
		}
	}

	if blk, ok := m.Capabilities["network.block_source"]; ok {
		if s, ok := blk.Params["cooldown"].(string); ok {
			if d, err := time.ParseDuration(s); err == nil {
				p.Cooldown = d
			}
		}
	}

	return p, nil
}

// toUint64 converts an interface{} YAML value (int or float64) to uint64.
func toUint64(v interface{}) (uint64, bool) {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return uint64(x), true
		}
	case float64:
		if x >= 0 {
			return uint64(x), true
		}
	}
	return 0, false
}
