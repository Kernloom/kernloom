// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package bundle defines the RuntimeBundle schema — the single signed artifact
// that Forge distributes to KLIQ nodes in managed mode. It replaces the
// simpler PolicyPack-only flow with a richer lifecycle envelope.
//
// Separation of concerns:
//
//	RuntimeBundle = how KLIQ behaves (lifecycle, thresholds, bounds)
//	PolicyPack    = what effects are authorised (embedded inside the bundle)
//	LearnedState  = what KLIQ discovered locally (never in the bundle)
//
// A bundle is Ed25519-signed by Forge. KLIQ rejects unsigned bundles in
// managed mode. Generation numbers prevent silent rollback.
package bundle

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	BundleAPIVersion = "kernloom.io/managed/v1alpha1"
	BundleKind       = "RuntimeBundle"

	ProposalAPIVersion = "kernloom.io/managed/v1alpha1"
	ProposalKind       = "BaselineProposal"
)

// ── RuntimeBundle ─────────────────────────────────────────────────────────────

// RuntimeBundle is the signed lifecycle envelope distributed by Forge.
type RuntimeBundle struct {
	APIVersion string          `yaml:"apiVersion" json:"apiVersion"`
	Kind       string          `yaml:"kind"       json:"kind"`
	Metadata   BundleMetadata  `yaml:"metadata"   json:"metadata"`
	Spec       BundleSpec      `yaml:"spec"       json:"spec"`
	Signature  BundleSignature `yaml:"signature"  json:"signature"`
}

type BundleMetadata struct {
	NodeID     string `yaml:"node_id"    json:"node_id"`
	Generation int    `yaml:"generation" json:"generation"`
	IssuedAt   string `yaml:"issued_at"  json:"issued_at"`
	ExpiresAt  string `yaml:"expires_at" json:"expires_at"`
}

type BundleSpec struct {
	FeatureProfile    string                `yaml:"feature_profile,omitempty"     json:"feature_profile,omitempty"`
	PolicyPack        EmbeddedPackRef       `yaml:"policy_pack,omitempty"         json:"policy_pack,omitempty"`
	PDPConfig         EmbeddedConfigRef     `yaml:"pdp_config,omitempty"          json:"pdp_config,omitempty"`
	BootstrapAutotune BootstrapAutotunePlan `yaml:"bootstrap_autotune,omitempty"  json:"bootstrap_autotune,omitempty"`
	SourceBaseline    SourceBaselinePlan    `yaml:"source_baseline,omitempty"     json:"source_baseline,omitempty"`
	GraphLifecycle    GraphLifecyclePlan    `yaml:"graph_lifecycle,omitempty"     json:"graph_lifecycle,omitempty"`
	EdgeBaseline      EdgeBaselinePlan      `yaml:"edge_baseline,omitempty"       json:"edge_baseline,omitempty"`
	EnforcementBounds EnforcementBounds     `yaml:"enforcement_bounds,omitempty"  json:"enforcement_bounds,omitempty"`
	Failover          FailoverConfig        `yaml:"failover,omitempty"            json:"failover,omitempty"`
	ManagedExemptions ManagedExemptions     `yaml:"managed_exemptions,omitempty"  json:"managed_exemptions,omitempty"`
}

type EmbeddedPackRef struct {
	Name       string `yaml:"name,omitempty"       json:"name,omitempty"`
	Generation int    `yaml:"generation,omitempty" json:"generation,omitempty"`
	Content    string `yaml:"content,omitempty"    json:"content,omitempty"` // base64-encoded signed YAML when embedded
}

type EmbeddedConfigRef struct {
	Content string `yaml:"content,omitempty" json:"content,omitempty"` // base64-encoded YAML when embedded
}

type BundleSignature struct {
	Algorithm string `yaml:"algorithm" json:"algorithm"`
	Value     string `yaml:"value"     json:"value"`
}

// ── Bootstrap / Autotune plan ─────────────────────────────────────────────────

type BootstrapAutotunePlan struct {
	Enabled                   bool                   `yaml:"enabled"                              json:"enabled"`
	Window                    string                 `yaml:"window,omitempty"                     json:"window,omitempty"`
	RequireCleanRuntime       bool                   `yaml:"require_clean_runtime,omitempty"      json:"require_clean_runtime,omitempty"`
	CountOnlyCleanSeconds     bool                   `yaml:"count_only_clean_seconds,omitempty"   json:"count_only_clean_seconds,omitempty"`
	AllowBlockDuringBootstrap bool                   `yaml:"allow_block_during_bootstrap,omitempty" json:"allow_block_during_bootstrap,omitempty"`
	MinWindowsBeforeDownscale int                    `yaml:"min_windows_before_downscale,omitempty" json:"min_windows_before_downscale,omitempty"`
	MinSourcesBeforeDownscale int                    `yaml:"min_sources_before_downscale,omitempty" json:"min_sources_before_downscale,omitempty"`
	Floors                    BootstrapFloors        `yaml:"floors,omitempty"                     json:"floors,omitempty"`
	Phases                    []BootstrapPhaseConfig `yaml:"phases,omitempty"                    json:"phases,omitempty"`
	Steady                    SteadyAutotuneConfig   `yaml:"steady,omitempty"                     json:"steady,omitempty"`
}

type BootstrapFloors struct {
	PPS  float64 `yaml:"pps,omitempty"  json:"pps,omitempty"`
	SYN  float64 `yaml:"syn,omitempty"  json:"syn,omitempty"`
	Scan float64 `yaml:"scan,omitempty" json:"scan,omitempty"`
	BPS  float64 `yaml:"bps,omitempty"  json:"bps,omitempty"`
}

type BootstrapPhaseConfig struct {
	Name     string  `yaml:"name"              json:"name"`
	Until    string  `yaml:"until,omitempty"   json:"until,omitempty"`
	Interval string  `yaml:"interval,omitempty" json:"interval,omitempty"`
	K        float64 `yaml:"k,omitempty"       json:"k,omitempty"`
	MaxUp    float64 `yaml:"max_up,omitempty"  json:"max_up,omitempty"`
	MaxDown  float64 `yaml:"max_down,omitempty" json:"max_down,omitempty"`
	Alpha    float64 `yaml:"alpha,omitempty"   json:"alpha,omitempty"`
}

type SteadyAutotuneConfig struct {
	Interval string  `yaml:"interval,omitempty" json:"interval,omitempty"`
	MaxUp    float64 `yaml:"max_up,omitempty"   json:"max_up,omitempty"`
	MaxDown  float64 `yaml:"max_down,omitempty" json:"max_down,omitempty"`
	Alpha    float64 `yaml:"alpha,omitempty"    json:"alpha,omitempty"`
}

// WindowDuration parses the Window field as a Go duration.
func (p *BootstrapAutotunePlan) WindowDuration() (time.Duration, error) {
	if p.Window == "" {
		return 14 * 24 * time.Hour, nil
	}
	return time.ParseDuration(p.Window)
}

// ── Source baseline plan ──────────────────────────────────────────────────────

type SourceBaselinePlan struct {
	Enabled         bool    `yaml:"enabled,omitempty"          json:"enabled,omitempty"`
	AlphaBootstrap  float64 `yaml:"alpha_bootstrap,omitempty"  json:"alpha_bootstrap,omitempty"`
	AlphaStable     float64 `yaml:"alpha_stable,omitempty"     json:"alpha_stable,omitempty"`
	MinObservations int     `yaml:"min_observations,omitempty" json:"min_observations,omitempty"`
	MaxSources      int     `yaml:"max_sources,omitempty"      json:"max_sources,omitempty"`
	MinConfidence   float64 `yaml:"min_confidence,omitempty"   json:"min_confidence,omitempty"`
	PeakMultiplier  float64 `yaml:"peak_multiplier,omitempty"  json:"peak_multiplier,omitempty"`
}

// ── Graph lifecycle plan ──────────────────────────────────────────────────────

type GraphLifecyclePlan struct {
	Enabled  bool                `yaml:"enabled,omitempty"  json:"enabled,omitempty"`
	Mode     string              `yaml:"mode,omitempty"     json:"mode,omitempty"` // managed | local-auto
	Learning GraphLearningConfig `yaml:"learning,omitempty" json:"learning,omitempty"`
	Freeze   GraphFreezeConfig   `yaml:"freeze,omitempty"   json:"freeze,omitempty"`
	Rollout  GraphRolloutConfig  `yaml:"rollout,omitempty"  json:"rollout,omitempty"`
}

type GraphLearningConfig struct {
	Duration                string  `yaml:"duration,omitempty"                  json:"duration,omitempty"`
	MinCleanLearning        string  `yaml:"min_clean_learning,omitempty"        json:"min_clean_learning,omitempty"`
	MinLearnedEdges         int     `yaml:"min_learned_edges,omitempty"         json:"min_learned_edges,omitempty"`
	MinBaselineCoverage     float64 `yaml:"min_baseline_coverage,omitempty"     json:"min_baseline_coverage,omitempty"`
	RequireAutotunePhase    string  `yaml:"require_autotune_phase,omitempty"    json:"require_autotune_phase,omitempty"`
	RequireNoBlockEventsFor string  `yaml:"require_no_block_events_for,omitempty" json:"require_no_block_events_for,omitempty"`
}

type GraphFreezeConfig struct {
	AutoFreeze           bool   `yaml:"auto_freeze,omitempty"            json:"auto_freeze,omitempty"`
	Approval             string `yaml:"approval,omitempty"               json:"approval,omitempty"` // forge-auto | forge-manual | local
	ProposalUpload       bool   `yaml:"proposal_upload,omitempty"        json:"proposal_upload,omitempty"`
	IncludeEdgeBaselines bool   `yaml:"include_edge_baselines,omitempty" json:"include_edge_baselines,omitempty"`
}

type GraphRolloutConfig struct {
	AfterFreezePhase   string `yaml:"after_freeze_phase,omitempty"   json:"after_freeze_phase,omitempty"`
	ObserveAfterFreeze string `yaml:"observe_after_freeze,omitempty" json:"observe_after_freeze,omitempty"`
	FinalPhase         string `yaml:"final_phase,omitempty"          json:"final_phase,omitempty"`
}

// ── Edge baseline plan ────────────────────────────────────────────────────────

type EdgeBaselinePlan struct {
	Enabled            bool    `yaml:"enabled,omitempty"             json:"enabled,omitempty"`
	MinObservations    int     `yaml:"min_observations,omitempty"    json:"min_observations,omitempty"`
	AlphaBootstrap     float64 `yaml:"alpha_bootstrap,omitempty"     json:"alpha_bootstrap,omitempty"`
	AlphaStable        float64 `yaml:"alpha_stable,omitempty"        json:"alpha_stable,omitempty"`
	DeviationThreshold float64 `yaml:"deviation_threshold,omitempty" json:"deviation_threshold,omitempty"`
	PeakTolerance      float64 `yaml:"peak_tolerance,omitempty"      json:"peak_tolerance,omitempty"`
}

// ── Enforcement bounds ────────────────────────────────────────────────────────

type EnforcementBounds struct {
	MaxActionDuringBootstrap     string `yaml:"max_action_during_bootstrap,omitempty"      json:"max_action_during_bootstrap,omitempty"`
	MaxActionDuringFrozenObserve string `yaml:"max_action_during_frozen_observe,omitempty" json:"max_action_during_frozen_observe,omitempty"`
	MaxActionDuringFrozenEnforce string `yaml:"max_action_during_frozen_enforce,omitempty" json:"max_action_during_frozen_enforce,omitempty"`
	AllowBlock                   bool   `yaml:"allow_block,omitempty"                      json:"allow_block,omitempty"`
}

// ── Failover config ───────────────────────────────────────────────────────────

type FailoverConfig struct {
	Behavior                          string `yaml:"behavior,omitempty"                              json:"behavior,omitempty"`
	AllowLearningWhileOffline         bool   `yaml:"allow_learning_while_offline,omitempty"          json:"allow_learning_while_offline,omitempty"`
	AllowLocalFreezeWhileOffline      bool   `yaml:"allow_local_freeze_while_offline,omitempty"      json:"allow_local_freeze_while_offline,omitempty"`
	AllowEnforcePromotionWhileOffline bool   `yaml:"allow_enforce_promotion_while_offline,omitempty" json:"allow_enforce_promotion_while_offline,omitempty"`
}

// ── Managed exemptions ────────────────────────────────────────────────────────

type ManagedExemptions struct {
	Whitelist []ExemptionEntry `yaml:"whitelist,omitempty" json:"whitelist,omitempty"`
	Feedback  []ExemptionEntry `yaml:"feedback,omitempty"  json:"feedback,omitempty"`
}

type ExemptionEntry struct {
	Kind   string `yaml:"kind"             json:"kind"` // ip | cidr
	Value  string `yaml:"value"            json:"value"`
	TTL    string `yaml:"ttl,omitempty"    json:"ttl,omitempty"`
	Action string `yaml:"action,omitempty" json:"action,omitempty"`
	Reason string `yaml:"reason,omitempty" json:"reason,omitempty"`
}

// ── Metadata helpers ──────────────────────────────────────────────────────────

// ParseIssuedAt parses the IssuedAt field as time.Time.
func (m *BundleMetadata) ParseIssuedAt() (time.Time, bool) {
	if m.IssuedAt == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, m.IssuedAt)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// ParseExpiresAt parses the ExpiresAt field as time.Time.
func (m *BundleMetadata) ParseExpiresAt() (time.Time, bool) {
	if m.ExpiresAt == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, m.ExpiresAt)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// IsExpired returns true if the bundle's ExpiresAt is in the past.
// Returns false when ExpiresAt is absent (no expiry enforced).
func (b *RuntimeBundle) IsExpired() bool {
	t, ok := b.Metadata.ParseExpiresAt()
	if !ok {
		return false
	}
	return time.Now().After(t)
}

// ── Load ──────────────────────────────────────────────────────────────────────

// Parse unmarshals a RuntimeBundle from YAML bytes.
func Parse(data []byte) (*RuntimeBundle, error) {
	var b RuntimeBundle
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse runtime bundle: %w", err)
	}
	if b.Kind != BundleKind && b.Kind != "" {
		return nil, fmt.Errorf("unexpected kind %q (want %s)", b.Kind, BundleKind)
	}
	return &b, nil
}

// Load reads and parses a RuntimeBundle from a file.
func Load(path string) (*RuntimeBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load runtime bundle: %w", err)
	}
	return Parse(data)
}

// Validate performs basic structural checks on the bundle.
func (b *RuntimeBundle) Validate() error {
	if b.Metadata.NodeID == "" {
		return fmt.Errorf("bundle: metadata.node_id is required")
	}
	if b.Metadata.Generation <= 0 {
		return fmt.Errorf("bundle: metadata.generation must be > 0")
	}
	if b.Metadata.IssuedAt == "" {
		return fmt.Errorf("bundle: metadata.issued_at is required")
	}
	if _, ok := b.Metadata.ParseIssuedAt(); !ok {
		return fmt.Errorf("bundle: metadata.issued_at is not valid RFC3339")
	}
	return nil
}
