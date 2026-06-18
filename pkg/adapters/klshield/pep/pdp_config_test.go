// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package shieldpep_test

import (
	"testing"

	shieldpep "github.com/kernloom/kernloom/pkg/adapters/klshield/pep"
	"github.com/kernloom/kernloom/pkg/core/pdp"
	"gopkg.in/yaml.v3"
)

func TestPDPAdapterConfigFrom(t *testing.T) {
	var adapters pdp.AdaptersSpec
	raw := []byte(`
shield_pep:
  soft_rate_pps: 600
  soft_burst: 1500
  hard_rate_pps: 150
  hard_burst: 300
  soft_rate_factor: 0.5
  hard_rate_factor: 0.1
  cooldown: "30s"
`)
	if err := yaml.Unmarshal(raw, &adapters); err != nil {
		t.Fatalf("unmarshal adapters: %v", err)
	}

	cfg, found, err := shieldpep.PDPAdapterConfigFrom(adapters)
	if err != nil {
		t.Fatalf("PDPAdapterConfigFrom: %v", err)
	}
	if !found {
		t.Fatal("expected shield_pep section")
	}
	if cfg.SoftRatePPS != 600 || cfg.HardRatePPS != 150 {
		t.Fatalf("unexpected rates: soft=%d hard=%d", cfg.SoftRatePPS, cfg.HardRatePPS)
	}
	if cfg.SoftRateFactor != 0.5 || cfg.HardRateFactor != 0.1 {
		t.Fatalf("unexpected factors: soft=%f hard=%f", cfg.SoftRateFactor, cfg.HardRateFactor)
	}
	if cfg.Cooldown.D.Seconds() != 30 {
		t.Fatalf("unexpected cooldown: %s", cfg.Cooldown.D)
	}
}

func TestPDPAdapterConfigFrom_Missing(t *testing.T) {
	cfg, found, err := shieldpep.PDPAdapterConfigFrom(nil)
	if err != nil {
		t.Fatalf("PDPAdapterConfigFrom: %v", err)
	}
	if found {
		t.Fatal("missing section should not be found")
	}
	if cfg.SoftRatePPS != 0 {
		t.Fatalf("missing section should return zero config: %+v", cfg)
	}
}
