// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package policy defines the LocalPolicyPack format used by kliq in standalone
// mode. The format is a Forge-compatible subset: when Kernloom Forge is
// integrated it will push cryptographically signed PolicyPacks using the same
// schema instead of reading a local file.
//
// Architecture:
//
//	PolicyPack (this file) — abstract, PEP-agnostic policy rules
//	AdapterManifest (pkg/adapters/shieldpep/manifest.go) — PEP-specific capability params
//	profiles.go in iq/cmd/kliq — PDP (kliq) internal FSM behavior defaults
package policy

import (
	"fmt"
	"time"
)

// Mode controls how kliq obtains its policy.
type Mode string

const (
	// ModeStandalone loads policy from a local file or built-in profile.
	ModeStandalone Mode = "standalone"
	// ModeManaged signals that Forge will push policy. Currently falls back to
	// standalone; the Forge client is not yet implemented.
	ModeManaged Mode = "managed"
)

// PolicyPack is the top-level struct for a LocalPolicyPack YAML file.
// It mirrors the Forge-compatible API object layout so that the same file
// can later be signed and distributed by Forge without schema changes.
type PolicyPack struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata holds the policy identity fields.
type Metadata struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
}

// Spec is the policy body.
// It is intentionally PEP-agnostic: it references abstract capability IDs
// (network.rate_limit_source, network.block_source) rather than Shield-specific
// parameters (rate_pps, burst). The concrete PEP parameters live in the
// adapter manifest (pkg/adapters/shieldpep/manifest.go).
type Spec struct {
	// TargetSelector is used by Forge to match this policy to nodes.
	// Ignored in standalone mode but preserved for forward-compatibility.
	TargetSelector TargetSelectorSpec `yaml:"target_selector,omitempty"`

	// CapabilitiesRequired lists the abstract capability IDs that this policy
	// needs. Forge validates that the target node's PEP adapters provide all
	// required capabilities before distributing the pack.
	CapabilitiesRequired []string `yaml:"capabilities_required,omitempty"`

	// Autonomy defines what kliq is permitted to enforce locally without Forge
	// approval. In managed mode Forge can further restrict these.
	Autonomy AutonomySpec `yaml:"autonomy"`

	// Heuristics consolidates all PDP (kliq) evaluation parameters: signal
	// thresholds, weights, FSM escalation, anti-flap, block gate, non-compliance.
	// These are PDP-internal and do not belong in the adapter manifest.
	Heuristics HeuristicsSpec `yaml:"heuristics"`

	// Rules express the enforcement policy as when/then pairs:
	// "when the FSM reaches level X, apply abstract action Y via capability Z".
	// The PDP evaluates rules and the PEP adapter translates the abstract action
	// into its concrete implementation.
	Rules []RuleSpec `yaml:"rules"`

	// Graph covers graph learning and freeze-enforcement policy.
	Graph GraphSpec `yaml:"graph"`

	// Exports configures where kliq sends telemetry, decisions and receipts.
	// All targets are disabled by default in standalone mode.
	Exports ExportsSpec `yaml:"exports,omitempty"`
}

// TargetSelectorSpec matches nodes for policy delivery (Forge use).
type TargetSelectorSpec struct {
	MatchLabels map[string]string `yaml:"match_labels,omitempty"`
}

// AutonomySpec defines what kliq is permitted to enforce locally.
type AutonomySpec struct {
	// DryRun disables all eBPF map writes; decisions are logged only.
	DryRun bool `yaml:"dry_run"`

	// MaxAction is the ceiling on enforcement actions.
	// Valid values: observe, signal, rate_limit, block.
	MaxAction string `yaml:"max_action"`

	// AllowLocalBlock permits block decisions without Forge approval.
	// When false MaxAction is effectively capped at rate_limit.
	AllowLocalBlock bool `yaml:"allow_local_block"`
}

// HeuristicsSpec consolidates all PDP evaluation parameters.
type HeuristicsSpec struct {
	// Signal engine baseline trigger levels. Autotune will override these
	// once enough samples are collected; these are the cold-start defaults.
	PPSTrigger  float64     `yaml:"pps_trigger"`
	SynTrigger  float64     `yaml:"syn_trigger"`
	ScanTrigger float64     `yaml:"scan_trigger"`
	Weights     WeightsSpec `yaml:"weights"`

	// Progressive enforcement defines how the FSM escalates through levels.
	Progressive ProgressiveSpec `yaml:"progressive_enforcement"`

	// NonCompliance defines escalation for sources that ignore rate limits.
	NonCompliance NonComplianceSpec `yaml:"non_compliance"`
}

// WeightsSpec controls how each signal type contributes to the composite severity.
type WeightsSpec struct {
	PPS  float64 `yaml:"pps"`
	Syn  float64 `yaml:"syn"`
	Scan float64 `yaml:"scan"`
	// Cap is the maximum composite severity score (e.g. 3.0).
	Cap float64 `yaml:"cap"`
}

// ProgressiveSpec defines FSM escalation thresholds and guard conditions.
type ProgressiveSpec struct {
	// FSM escalation thresholds (strike counts — PDP internal).
	SoftAt  int `yaml:"soft_at"`
	HardAt  int `yaml:"hard_at"`
	BlockAt int `yaml:"block_at"`

	// Anti-flap: consecutive ticks required before escalating or de-escalating.
	UpNeed   int `yaml:"up_need"`
	DownNeed int `yaml:"down_need"`

	// Block gate: the FSM only transitions to BLOCK if severity has been above
	// BlockMinSev for at least BlockMinDur. Prevents block on transient spikes.
	BlockMinSev float64  `yaml:"block_min_sev"`
	BlockMinDur Duration `yaml:"block_min_dur"`

	// Minimum time the FSM must hold a level before de-escalating.
	MinHoldSoft Duration `yaml:"min_hold_soft"`
	MinHoldHard Duration `yaml:"min_hold_hard"`
}

// NonComplianceSpec defines escalation for sources that continue sending
// traffic despite an active rate limit.
type NonComplianceSpec struct {
	At    int     `yaml:"at"`
	Drop  float64 `yaml:"drop"`
	Sev   float64 `yaml:"sev"`
	Reset float64 `yaml:"reset"`
}

// RuleSpec expresses a single enforcement rule as a when/then pair.
// The PDP evaluates the when condition; when matched it invokes the PEP adapter
// with the abstract action and capability. The adapter translates this into
// its concrete implementation (e.g. writing to eBPF maps, nginx config, etc.).
type RuleSpec struct {
	Name string   `yaml:"name"`
	When WhenSpec `yaml:"when"`
	Then ThenSpec `yaml:"then"`
}

// WhenSpec describes the condition that triggers a rule.
type WhenSpec struct {
	// FsmLevel matches when the FSM reaches a given level: soft | hard | block.
	FsmLevel string `yaml:"fsm_level,omitempty"`
	// Signal matches a specific signal type (e.g. graph.new_edge_after_freeze).
	Signal string `yaml:"signal,omitempty"`
}

// ThenSpec describes the enforcement action to take when a rule matches.
type ThenSpec struct {
	// Action is the abstract enforcement action: observe | signal | rate_limit | block.
	Action string `yaml:"action"`
	// Capability is the abstract capability ID the PEP adapter must implement.
	Capability string `yaml:"capability"`
	// TTL is how long the enforcement entry should remain active.
	TTL Duration `yaml:"ttl,omitempty"`
	// Params are optional capability-specific parameters (passed to the adapter).
	Params map[string]string `yaml:"params,omitempty"`
}

// GraphSpec covers graph learning and freeze-enforcement policy.
type GraphSpec struct {
	Enabled   bool               `yaml:"enabled"`
	Mode      string             `yaml:"mode"`
	Store     string             `yaml:"store,omitempty"`
	Promotion GraphPromotionSpec `yaml:"promotion"`
	Freeze    GraphFreezeSpec    `yaml:"freeze"`
	Exclude   GraphExcludeSpec   `yaml:"exclude,omitempty"`
}

type GraphPromotionSpec struct {
	MinSeenCount int      `yaml:"min_seen_count"`
	MinWindows   int      `yaml:"min_windows"`
	MinAge       Duration `yaml:"min_age"`
	ExpireTTL    Duration `yaml:"expire_ttl,omitempty"`
}

type GraphFreezeSpec struct {
	Action              string   `yaml:"action"`
	TTL                 Duration `yaml:"ttl"`
	MaxAction           string   `yaml:"max_action"`
	AllowBlock          bool     `yaml:"allow_block"`
	MinSeverityForBlock int      `yaml:"min_severity_for_block"`
}

type GraphExcludeSpec struct {
	SourceCIDRs []string `yaml:"source_cidrs,omitempty"`
	Broadcast   bool     `yaml:"broadcast"`
	Loopback    bool     `yaml:"loopback"`
}

// ExportsSpec configures telemetry export destinations.
type ExportsSpec struct {
	Correlate ExportTargetSpec `yaml:"correlate,omitempty"`
	Forge     ExportTargetSpec `yaml:"forge,omitempty"`
}

type ExportTargetSpec struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint,omitempty"`
}

// Duration is a YAML-serialisable wrapper around time.Duration.
// It marshals as a human-readable string (e.g. "30m", "10s").
type Duration struct{ D time.Duration }

func (d Duration) MarshalYAML() (interface{}, error) {
	return d.D.String(), nil
}

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("policy: invalid duration %q: %w", s, err)
	}
	d.D = parsed
	return nil
}

const (
	expectedAPIVersion = "kernloom.io/v1alpha1"
	expectedKind       = "LocalPolicyPack"
)

// Validate checks required fields and structural constraints.
func (p *PolicyPack) Validate() error {
	if p.APIVersion != expectedAPIVersion {
		return fmt.Errorf("unsupported apiVersion %q (want %q)", p.APIVersion, expectedAPIVersion)
	}
	if p.Kind != expectedKind {
		return fmt.Errorf("unsupported kind %q (want %q)", p.Kind, expectedKind)
	}
	if p.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if p.Spec.Heuristics.PPSTrigger <= 0 {
		return fmt.Errorf("spec.heuristics.pps_trigger must be > 0")
	}
	prog := p.Spec.Heuristics.Progressive
	if prog.SoftAt <= 0 || prog.HardAt <= 0 || prog.BlockAt <= 0 {
		return fmt.Errorf("spec.heuristics.progressive_enforcement.soft_at, hard_at, block_at must all be > 0")
	}
	validActions := map[string]bool{"observe": true, "signal": true, "rate_limit": true, "block": true, "": true}
	if !validActions[p.Spec.Autonomy.MaxAction] {
		return fmt.Errorf("spec.autonomy.max_action %q is not valid (observe|signal|rate_limit|block)", p.Spec.Autonomy.MaxAction)
	}
	validModes := map[string]bool{"learn": true, "frozen-observe": true, "frozen-enforce": true, "": true}
	if !validModes[p.Spec.Graph.Mode] {
		return fmt.Errorf("spec.graph.mode %q is not valid (learn|frozen-observe|frozen-enforce)", p.Spec.Graph.Mode)
	}
	if len(p.Spec.Rules) == 0 {
		return fmt.Errorf("spec.rules must contain at least one rule")
	}
	return nil
}
