// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle_test

import (
	"testing"

	"github.com/kernloom/kernloom/pkg/core/bundle"
)

const minimalBundle = `
apiVersion: kernloom.io/managed/v1alpha1
kind: RuntimeBundle
metadata:
  node_id: test-node
  generation: 1
  issued_at: "2026-05-20T12:00:00Z"
spec:
  feature_profile: graph-enforce
  bootstrap_autotune:
    enabled: true
    window: "336h"
    floors:
      pps: 100.0
      syn: 50.0
      scan: 20.0
  graph_lifecycle:
    enabled: true
    mode: managed
    learning:
      duration: "336h"
      min_clean_learning: "240h"
      min_learned_edges: 5
      min_baseline_coverage: 0.70
  enforcement_bounds:
    max_action_during_bootstrap: observe
    max_action_during_frozen_observe: observe
    max_action_during_frozen_enforce: rate_limit
  failover:
    behavior: fail_static
    allow_learning_while_offline: true
signature:
  algorithm: ed25519
  value: "placeholder"
`

func TestParse_Valid(t *testing.T) {
	b, err := bundle.Parse([]byte(minimalBundle))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if b.Metadata.NodeID != "test-node" {
		t.Errorf("NodeID: got %q, want %q", b.Metadata.NodeID, "test-node")
	}
	if b.Metadata.Generation != 1 {
		t.Errorf("Generation: got %d, want 1", b.Metadata.Generation)
	}
	if !b.Spec.BootstrapAutotune.Enabled {
		t.Error("BootstrapAutotune.Enabled should be true")
	}
	if b.Spec.BootstrapAutotune.Floors.PPS != 100.0 {
		t.Errorf("Floors.PPS: got %.1f, want 100.0", b.Spec.BootstrapAutotune.Floors.PPS)
	}
	if b.Spec.GraphLifecycle.Learning.MinLearnedEdges != 5 {
		t.Errorf("MinLearnedEdges: got %d, want 5", b.Spec.GraphLifecycle.Learning.MinLearnedEdges)
	}
	if b.Spec.EnforcementBounds.MaxActionDuringBootstrap != "observe" {
		t.Errorf("MaxActionDuringBootstrap: got %q", b.Spec.EnforcementBounds.MaxActionDuringBootstrap)
	}
	if b.Spec.Failover.Behavior != "fail_static" {
		t.Errorf("Failover.Behavior: got %q", b.Spec.Failover.Behavior)
	}
}

func TestParse_InvalidYAML(t *testing.T) {
	_, err := bundle.Parse([]byte("not: valid: yaml: ["))
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestValidate_MissingNodeID(t *testing.T) {
	b := &bundle.RuntimeBundle{
		Metadata: bundle.BundleMetadata{
			Generation: 1,
			IssuedAt:   "2026-05-20T12:00:00Z",
		},
	}
	if err := b.Validate(); err == nil {
		t.Error("expected validation error for missing node_id")
	}
}

func TestValidate_MissingGeneration(t *testing.T) {
	b := &bundle.RuntimeBundle{
		Metadata: bundle.BundleMetadata{
			NodeID:   "test",
			IssuedAt: "2026-05-20T12:00:00Z",
		},
	}
	if err := b.Validate(); err == nil {
		t.Error("expected validation error for generation=0")
	}
}

func TestValidate_InvalidIssuedAt(t *testing.T) {
	b := &bundle.RuntimeBundle{
		Metadata: bundle.BundleMetadata{
			NodeID:     "test",
			Generation: 1,
			IssuedAt:   "not-a-date",
		},
	}
	if err := b.Validate(); err == nil {
		t.Error("expected validation error for invalid issued_at")
	}
}

func TestParseIssuedAt(t *testing.T) {
	b, _ := bundle.Parse([]byte(minimalBundle))
	ts, ok := b.Metadata.ParseIssuedAt()
	if !ok {
		t.Fatal("ParseIssuedAt returned false")
	}
	if ts.Year() != 2026 {
		t.Errorf("unexpected year %d", ts.Year())
	}
}

func TestIsExpired_NotExpired(t *testing.T) {
	b := &bundle.RuntimeBundle{
		Metadata: bundle.BundleMetadata{ExpiresAt: "2099-01-01T00:00:00Z"},
	}
	if b.IsExpired() {
		t.Error("bundle should not be expired")
	}
}

func TestIsExpired_NoExpiry(t *testing.T) {
	b := &bundle.RuntimeBundle{}
	if b.IsExpired() {
		t.Error("bundle without ExpiresAt should not be considered expired")
	}
}

func TestWindowDuration(t *testing.T) {
	plan := bundle.BootstrapAutotunePlan{Window: "336h"}
	d, err := plan.WindowDuration()
	if err != nil {
		t.Fatalf("WindowDuration: %v", err)
	}
	if d != 14*24*3600*1e9 {
		t.Errorf("unexpected duration %v", d)
	}
}

func TestWindowDuration_Default(t *testing.T) {
	plan := bundle.BootstrapAutotunePlan{}
	d, err := plan.WindowDuration()
	if err != nil {
		t.Fatalf("WindowDuration: %v", err)
	}
	if d != 14*24*3600*1e9 {
		t.Errorf("default should be 14d, got %v", d)
	}
}
