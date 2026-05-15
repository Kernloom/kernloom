// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package pdp_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom/pkg/core/pdp"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "pdp-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

const validPDPYAML = `
apiVersion: kernloom.io/v1alpha1
kind: PDPConfig
metadata:
  name: test-pdp
spec:
  signal_engine:
    pps_trigger: 80.0
    syn_trigger: 20.0
    scan_trigger: 5.0
    weights:
      pps: 0.35
      syn: 0.40
      scan: 0.25
      cap: 3.0
  progressive_enforcement:
    soft_at: 1
    hard_at: 3
    block_at: 9
    up_need: 2
    down_need: 6
    block_min_sev: 2.0
    block_min_dur: "15s"
    min_hold_soft: "15s"
    min_hold_hard: "30s"
  non_compliance:
    at: 8
    drop: 1.0
    sev: 1.5
    reset: 0.30
`

func TestLoadFromFile_Valid(t *testing.T) {
	path := writeYAML(t, validPDPYAML)
	c, err := pdp.LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Metadata.Name != "test-pdp" {
		t.Errorf("expected name test-pdp, got %s", c.Metadata.Name)
	}
	if c.Spec.SignalEngine.PPSTrigger != 80.0 {
		t.Errorf("expected pps_trigger 80.0, got %f", c.Spec.SignalEngine.PPSTrigger)
	}
	if c.Spec.ProgressiveEnforcement.BlockAt != 9 {
		t.Errorf("expected block_at 9, got %d", c.Spec.ProgressiveEnforcement.BlockAt)
	}
	if c.Spec.ProgressiveEnforcement.BlockMinDur.D.Seconds() != 15 {
		t.Errorf("expected block_min_dur 15s, got %s", c.Spec.ProgressiveEnforcement.BlockMinDur.D)
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := pdp.LoadFromFile(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidate_ZeroPPSTrigger(t *testing.T) {
	yaml := `
apiVersion: kernloom.io/v1alpha1
kind: PDPConfig
metadata:
  name: bad
spec:
  signal_engine:
    pps_trigger: 0
    syn_trigger: 20
    scan_trigger: 5
    weights: {pps: 0.35, syn: 0.40, scan: 0.25, cap: 3.0}
  progressive_enforcement:
    soft_at: 1
    hard_at: 3
    block_at: 9
`
	_, err := pdp.LoadFromFile(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for pps_trigger=0")
	}
}

func TestValidate_InvalidGraphMode(t *testing.T) {
	yaml := `
apiVersion: kernloom.io/v1alpha1
kind: PDPConfig
metadata:
  name: bad-mode
spec:
  signal_engine:
    pps_trigger: 80
    syn_trigger: 20
    scan_trigger: 5
    weights: {pps: 0.35, syn: 0.40, scan: 0.25, cap: 3.0}
  progressive_enforcement:
    soft_at: 1
    hard_at: 3
    block_at: 9
  graph:
    mode: invalid-mode
`
	_, err := pdp.LoadFromFile(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for invalid graph mode")
	}
}

func TestValidate_ValidGraphMode(t *testing.T) {
	for _, mode := range []string{"learn", "frozen-observe", "frozen-enforce", ""} {
		yaml := `
apiVersion: kernloom.io/v1alpha1
kind: PDPConfig
metadata:
  name: valid-mode
spec:
  signal_engine:
    pps_trigger: 80
    syn_trigger: 20
    scan_trigger: 5
    weights: {pps: 0.35, syn: 0.40, scan: 0.25, cap: 3.0}
  progressive_enforcement:
    soft_at: 1
    hard_at: 3
    block_at: 9
  graph:
    mode: "` + mode + `"
`
		if _, err := pdp.LoadFromFile(writeYAML(t, yaml)); err != nil {
			t.Errorf("mode %q should be valid, got error: %v", mode, err)
		}
	}
}

func TestAdapters_ShieldPEP_Parsed(t *testing.T) {
	yaml := `
apiVersion: kernloom.io/v1alpha1
kind: PDPConfig
metadata:
  name: adapter-test
spec:
  signal_engine:
    pps_trigger: 80
    syn_trigger: 20
    scan_trigger: 5
    weights: {pps: 0.35, syn: 0.40, scan: 0.25, cap: 3.0}
  progressive_enforcement:
    soft_at: 1
    hard_at: 3
    block_at: 9
  adapters:
    shield_pep:
      soft_rate_pps: 600
      soft_burst:    1500
      hard_rate_pps: 150
      hard_burst:    300
      cooldown:      "30s"
`
	c, err := pdp.LoadFromFile(writeYAML(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	a := c.Spec.Adapters.ShieldPEP
	if a.SoftRatePPS != 600 {
		t.Errorf("expected soft_rate_pps=600, got %d", a.SoftRatePPS)
	}
	if a.HardRatePPS != 150 {
		t.Errorf("expected hard_rate_pps=150, got %d", a.HardRatePPS)
	}
	if a.Cooldown.D.Seconds() != 30 {
		t.Errorf("expected cooldown=30s, got %s", a.Cooldown.D)
	}
}

func TestGraphPromotion_Parsed(t *testing.T) {
	yaml := `
apiVersion: kernloom.io/v1alpha1
kind: PDPConfig
metadata:
  name: graph-test
spec:
  signal_engine:
    pps_trigger: 80
    syn_trigger: 20
    scan_trigger: 5
    weights: {pps: 0.35, syn: 0.40, scan: 0.25, cap: 3.0}
  progressive_enforcement:
    soft_at: 1
    hard_at: 3
    block_at: 9
  graph:
    enabled: true
    mode: learn
    store: /tmp/test.db
    promotion:
      min_seen_count: 5
      min_windows: 3
      min_age: "10m"
      expire_ttl: "720h"
    exclude:
      broadcast: true
      loopback: true
`
	c, err := pdp.LoadFromFile(writeYAML(t, yaml))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !c.Spec.Graph.Enabled {
		t.Error("expected graph.enabled=true")
	}
	if c.Spec.Graph.Promotion.MinSeenCount != 5 {
		t.Errorf("expected min_seen_count=5, got %d", c.Spec.Graph.Promotion.MinSeenCount)
	}
	if c.Spec.Graph.Promotion.MinAge.D.Minutes() != 10 {
		t.Errorf("expected min_age=10m, got %s", c.Spec.Graph.Promotion.MinAge.D)
	}
}
