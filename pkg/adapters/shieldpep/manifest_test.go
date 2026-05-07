// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package shieldpep_test

import (
	"os"
	"testing"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/adapters/shieldpep"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "manifest-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestDefaultCapabilityParams(t *testing.T) {
	p := shieldpep.DefaultCapabilityParams()
	if p.SoftRatePPS != 20 {
		t.Errorf("expected SoftRatePPS=20, got %d", p.SoftRatePPS)
	}
	if p.SoftBurst != 40 {
		t.Errorf("expected SoftBurst=40, got %d", p.SoftBurst)
	}
	if p.HardRatePPS != 5 {
		t.Errorf("expected HardRatePPS=5, got %d", p.HardRatePPS)
	}
	if p.Cooldown != 5*time.Second {
		t.Errorf("expected Cooldown=5s, got %s", p.Cooldown)
	}
}

func TestLoadManifest_Valid(t *testing.T) {
	yaml := `
kind: AdapterManifest
adapter: shield-pep
version: "1"
capabilities:
  network.rate_limit_source:
    params:
      soft:
        rate_pps: 100
        burst: 200
      hard:
        rate_pps: 25
        burst: 50
  network.block_source:
    params:
      cooldown: "10s"
`
	p, err := shieldpep.LoadManifest(writeYAML(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.SoftRatePPS != 100 {
		t.Errorf("expected SoftRatePPS=100, got %d", p.SoftRatePPS)
	}
	if p.SoftBurst != 200 {
		t.Errorf("expected SoftBurst=200, got %d", p.SoftBurst)
	}
	if p.HardRatePPS != 25 {
		t.Errorf("expected HardRatePPS=25, got %d", p.HardRatePPS)
	}
	if p.Cooldown != 10*time.Second {
		t.Errorf("expected Cooldown=10s, got %s", p.Cooldown)
	}
}

func TestLoadManifest_FallsBackToDefaults(t *testing.T) {
	// Manifest with no capabilities section — all fields fall back to defaults.
	yaml := `
kind: AdapterManifest
adapter: shield-pep
version: "1"
`
	p, err := shieldpep.LoadManifest(writeYAML(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	def := shieldpep.DefaultCapabilityParams()
	if p.SoftRatePPS != def.SoftRatePPS {
		t.Errorf("expected default SoftRatePPS=%d, got %d", def.SoftRatePPS, p.SoftRatePPS)
	}
}

func TestLoadManifest_NotFound(t *testing.T) {
	_, err := shieldpep.LoadManifest("/nonexistent/path/manifest.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
