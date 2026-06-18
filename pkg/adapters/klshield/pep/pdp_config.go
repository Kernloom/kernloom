// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package shieldpep

import (
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/core/pdp"
)

const PDPAdapterKey = "shield_pep"

// PDPAdapterConfig is the KLShield PEP section in PDPConfig.spec.adapters.
type PDPAdapterConfig struct {
	SoftRatePPS uint64 `yaml:"soft_rate_pps"`
	SoftBurst   uint64 `yaml:"soft_burst"`
	HardRatePPS uint64 `yaml:"hard_rate_pps"`
	HardBurst   uint64 `yaml:"hard_burst"`

	SoftRateFactor float64 `yaml:"soft_rate_factor,omitempty"`
	HardRateFactor float64 `yaml:"hard_rate_factor,omitempty"`

	Cooldown Duration `yaml:"cooldown"`
}

// Duration is a YAML-serialisable wrapper around time.Duration.
type Duration struct{ D time.Duration }

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("klshield pep: invalid duration %q: %w", s, err)
	}
	d.D = parsed
	return nil
}

// PDPAdapterConfigFrom decodes the adapter-owned shield_pep section.
func PDPAdapterConfigFrom(adapters pdp.AdaptersSpec) (PDPAdapterConfig, bool, error) {
	var cfg PDPAdapterConfig
	found, err := adapters.Decode(PDPAdapterKey, &cfg)
	if err != nil {
		return PDPAdapterConfig{}, found, err
	}
	return cfg, found, nil
}
