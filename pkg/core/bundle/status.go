// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import "time"

// ── Runtime status ────────────────────────────────────────────────────────────

// RuntimeStatus is the rich heartbeat payload KLIQ sends to Forge.
// It replaces the minimal pack-name heartbeat with full lifecycle telemetry.
type RuntimeStatus struct {
	NodeID            string                  `json:"node_id"`
	BundleGeneration  int                     `json:"bundle_generation"`
	BundleHash        string                  `json:"bundle_hash,omitempty"`
	Applied           bool                    `json:"applied"`
	DriftDetected     bool                    `json:"drift_detected"`
	ErrorDetail       string                  `json:"error_detail,omitempty"`
	ReportedAt        time.Time               `json:"reported_at"`
	FeatureProfile    string                  `json:"feature_profile,omitempty"`
	ActiveComponents  map[string]bool         `json:"active_components,omitempty"`
	BootstrapAutotune BootstrapAutotuneStatus `json:"bootstrap_autotune_status,omitempty"`
	GraphLifecycle    GraphLifecycleStatus    `json:"graph_lifecycle_status,omitempty"`
	SourceBaseline    SourceBaselineStatus    `json:"source_baseline_status,omitempty"`
	ExemptionStatus   ExemptionStatus         `json:"exemption_status,omitempty"`
}

// TriggerSet holds the four primary trigger thresholds.
type TriggerSet struct {
	PPS  float64 `json:"pps"`
	SYN  float64 `json:"syn"`
	Scan float64 `json:"scan"`
	BPS  float64 `json:"bps"`
}

// BootstrapAutotuneStatus describes the current autotune lifecycle state.
type BootstrapAutotuneStatus struct {
	Enabled          bool       `json:"enabled"`
	Phase            string     `json:"phase"`
	ObservedSeconds  uint64     `json:"observed_seconds"`
	RequiredSeconds  uint64     `json:"required_seconds"`
	CleanRatio       float64    `json:"clean_ratio"`
	CompletedWindows int        `json:"completed_windows"`
	ActiveTriggers   TriggerSet `json:"active_triggers"`
	LastUpdateAt     time.Time  `json:"last_update_at,omitempty"`
	ReadyForSteady   bool       `json:"ready_for_steady"`
}

// GraphLifecycleStatus describes the graph learner's current state.
type GraphLifecycleStatus struct {
	Phase                string    `json:"phase"`
	StartedAt            time.Time `json:"started_at,omitempty"`
	CleanLearningSeconds uint64    `json:"clean_learning_seconds"`
	LearnedEdges         int       `json:"learned_edges"`
	CandidateEdges       int       `json:"candidate_edges"`
	BaselineCoverage     float64   `json:"baseline_coverage"`
	ReadyToFreeze        bool      `json:"ready_to_freeze"`
	FreezeBlockedBy      []string  `json:"freeze_blocked_by,omitempty"`
}

// SourceBaselineStatus summarises the per-source EWMA baseline engine.
type SourceBaselineStatus struct {
	TrackedSources        int `json:"tracked_sources"`
	MaxSources            int `json:"max_sources"`
	HighConfidenceSources int `json:"high_confidence_sources"`
}

// ExemptionStatus summarises active exemptions (hashes, not individual IPs).
type ExemptionStatus struct {
	LocalWhitelistHash    string `json:"local_whitelist_hash,omitempty"`
	ManagedWhitelistHash  string `json:"managed_whitelist_hash,omitempty"`
	FeedbackEntriesActive int    `json:"feedback_entries_active"`
}

// ── Baseline proposal ─────────────────────────────────────────────────────────

// BaselineProposal is uploaded by KLIQ to Forge when freeze readiness is reached.
// Forge validates and optionally signs a BaselinePack in response.
type BaselineProposal struct {
	APIVersion string               `yaml:"apiVersion" json:"apiVersion"`
	Kind       string               `yaml:"kind"       json:"kind"`
	Metadata   ProposalMetadata     `yaml:"metadata"   json:"metadata"`
	Spec       BaselineProposalSpec `yaml:"spec"       json:"spec"`
}

type ProposalMetadata struct {
	NodeID      string    `yaml:"node_id"      json:"node_id"`
	GeneratedAt time.Time `yaml:"generated_at" json:"generated_at"`
}

type BaselineProposalSpec struct {
	BootstrapAutotune     BootstrapProposalSummary `yaml:"bootstrap_autotune,omitempty"    json:"bootstrap_autotune,omitempty"`
	SourceBaselineSummary SourceProposalSummary    `yaml:"source_baseline_summary,omitempty" json:"source_baseline_summary,omitempty"`
	GraphSummary          GraphProposalSummary     `yaml:"graph_summary,omitempty"         json:"graph_summary,omitempty"`
	EdgeBaselineSummary   EdgeProposalSummary      `yaml:"edge_baseline_summary,omitempty" json:"edge_baseline_summary,omitempty"`
	GraphEdges            []GraphEdgeEntry         `yaml:"graph_edges,omitempty"           json:"graph_edges,omitempty"`
}

type BootstrapProposalSummary struct {
	Phase           string     `yaml:"phase"            json:"phase"`
	ObservedSeconds uint64     `yaml:"observed_seconds" json:"observed_seconds"`
	CleanRatio      float64    `yaml:"clean_ratio"      json:"clean_ratio"`
	Triggers        TriggerSet `yaml:"triggers"         json:"triggers"`
}

type SourceProposalSummary struct {
	TrackedSources        int     `yaml:"tracked_sources"         json:"tracked_sources"`
	HighConfidenceSources int     `yaml:"high_confidence_sources" json:"high_confidence_sources"`
	AverageConfidence     float64 `yaml:"average_confidence"      json:"average_confidence"`
}

type GraphProposalSummary struct {
	CandidateEdges int `yaml:"candidate_edges" json:"candidate_edges"`
	LearnedEdges   int `yaml:"learned_edges"   json:"learned_edges"`
	ApprovedEdges  int `yaml:"approved_edges"  json:"approved_edges"`
	DeniedEdges    int `yaml:"denied_edges"    json:"denied_edges"`
	FrozenEdges    int `yaml:"frozen_edges"    json:"frozen_edges"`
}

type EdgeProposalSummary struct {
	EdgesWithBaseline int     `yaml:"edges_with_baseline" json:"edges_with_baseline"`
	BaselineCoverage  float64 `yaml:"baseline_coverage"   json:"baseline_coverage"`
}

type GraphEdgeEntry struct {
	Source          EdgeEntity          `yaml:"source"                    json:"source"`
	Destination     EdgeEntity          `yaml:"destination"               json:"destination"`
	Protocol        string              `yaml:"protocol,omitempty"        json:"protocol,omitempty"`
	DestinationPort int                 `yaml:"destination_port,omitempty" json:"destination_port,omitempty"`
	State           string              `yaml:"state,omitempty"           json:"state,omitempty"`
	Baseline        *EdgeBaselineValues `yaml:"baseline,omitempty"        json:"baseline,omitempty"`
}

type EdgeEntity struct {
	Kind string `yaml:"kind" json:"kind"`
	ID   string `yaml:"id"   json:"id"`
}

type EdgeBaselineValues struct {
	PPSEwma      float64 `yaml:"pps_ewma"     json:"pps_ewma"`
	BPSEwma      float64 `yaml:"bps_ewma"     json:"bps_ewma"`
	Observations int     `yaml:"observations" json:"observations"`
}
