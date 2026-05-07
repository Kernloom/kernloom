// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package policy defines the LocalPolicyPack format used by kliq in standalone
// mode. The format is a Forge-compatible subset: when Kernloom Forge is
// integrated it will push signed PolicyPacks using the same schema instead of
// reading a local file.
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

// Spec is the policy body. Each sub-section maps to a distinct concern.
// The top-level layout mirrors the Forge PolicyPack spec so that the same
// file can be signed and distributed by Forge without schema changes.
type Spec struct {
	// TargetSelector is used by Forge to match this policy to nodes.
	// Ignored in standalone mode but preserved for forward-compatibility.
	TargetSelector TargetSelectorSpec `yaml:"target_selector,omitempty"`

	// Capabilities lists the capability IDs that this node's PEP adapters
	// provide. Forge uses this to validate that a policy's required capabilities
	// are available on the target node.
	Capabilities []string `yaml:"capabilities,omitempty"`

	// Autonomy defines what kliq is allowed to enforce locally without Forge
	// approval. This replaces scattered flags like --dry-run, --graph-freeze-allow-block.
	Autonomy AutonomySpec `yaml:"autonomy"`

	// Heuristic, FSM, Enforcement, BlockGate, AntiFlap, NonCompliance define
	// the signal-engine and FSM parameters.
	Heuristic     HeuristicSpec     `yaml:"heuristic"`
	FSM           FSMSpec           `yaml:"fsm"`
	Enforcement   EnforcementSpec   `yaml:"enforcement"`
	BlockGate     BlockGateSpec     `yaml:"block_gate"`
	AntiFlap      AntiFlapSpec      `yaml:"anti_flap"`
	NonCompliance NonComplianceSpec `yaml:"non_compliance"`

	// Graph covers graph learning and freeze-enforcement policy.
	// Replaces the former Decision section's graph_freeze_* fields.
	Graph GraphSpec `yaml:"graph"`

	// Exports configures where kliq sends telemetry, decisions and receipts.
	// All targets are optional and disabled by default in standalone mode.
	Exports ExportsSpec `yaml:"exports,omitempty"`
}

// TargetSelectorSpec matches nodes for policy delivery (Forge use).
type TargetSelectorSpec struct {
	MatchLabels map[string]string `yaml:"match_labels,omitempty"`
}

// AutonomySpec defines what kliq is permitted to enforce locally.
// In managed mode Forge can narrow these permissions; in standalone mode
// they express the operator's intent directly.
type AutonomySpec struct {
	// DryRun disables all eBPF map writes; decisions are logged only.
	DryRun bool `yaml:"dry_run"`

	// MaxAction is the ceiling on enforcement actions: observe, signal,
	// rate_limit, or block.
	MaxAction string `yaml:"max_action"`

	// AllowLocalBlock permits block decisions without Forge approval.
	// When false MaxAction is effectively capped at rate_limit.
	AllowLocalBlock bool `yaml:"allow_local_block"`

	// MinSeverityForBlock is the minimum signal score (0-100) required
	// before a block decision is allowed.
	MinSeverityForBlock int `yaml:"min_severity_for_block"`
}

// GraphSpec covers graph learning mode, promotion criteria, and what to do
// when a new edge is detected after a freeze.
type GraphSpec struct {
	// Enabled mirrors the --graph flag.
	Enabled bool `yaml:"enabled"`

	// Mode: learn | frozen-observe | frozen-enforce
	Mode string `yaml:"mode"`

	// Store is the path to the SQLite graph database.
	Store string `yaml:"store,omitempty"`

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
	// Action on a new edge: signal | rate_limit | block
	Action string `yaml:"action"`
	// TTL of the freeze enforcement entry.
	TTL Duration `yaml:"ttl"`
	// MaxAction caps what the freeze path may enforce.
	MaxAction string `yaml:"max_action"`
	// AllowBlock permits block from freeze violations.
	AllowBlock bool `yaml:"allow_block"`
	// MinSeverityForBlock: minimum score before block is allowed from freeze.
	MinSeverityForBlock int `yaml:"min_severity_for_block"`
}

type GraphExcludeSpec struct {
	// SourceCIDRs are excluded from graph learning (e.g. NAT gateways).
	SourceCIDRs []string `yaml:"source_cidrs,omitempty"`
	Broadcast   bool     `yaml:"broadcast"`
	Loopback    bool     `yaml:"loopback"`
}

// ExportsSpec configures telemetry export destinations.
// All targets are stubs until Correlate and Forge are implemented.
type ExportsSpec struct {
	Correlate ExportTargetSpec `yaml:"correlate,omitempty"`
	Forge     ExportTargetSpec `yaml:"forge,omitempty"`
}

type ExportTargetSpec struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint,omitempty"`
}

// HeuristicSpec holds the signal-engine thresholds and weights.
type HeuristicSpec struct {
	TrigPPS  float64 `yaml:"trig_pps"`
	TrigSyn  float64 `yaml:"trig_syn"`
	TrigScan float64 `yaml:"trig_scan"`
	WPPS     float64 `yaml:"w_pps"`
	WSyn     float64 `yaml:"w_syn"`
	WScan    float64 `yaml:"w_scan"`
	SevCap   float64 `yaml:"sev_cap"`
}

// FSMSpec controls when the FSM escalates between levels.
type FSMSpec struct {
	SoftAt  int `yaml:"soft_at"`
	HardAt  int `yaml:"hard_at"`
	BlockAt int `yaml:"block_at"`
}

// EnforcementSpec holds per-level rate-limit parameters and TTLs.
type EnforcementSpec struct {
	SoftRate  uint64   `yaml:"soft_rate"`
	SoftBurst uint64   `yaml:"soft_burst"`
	SoftTTL   Duration `yaml:"soft_ttl"`
	HardRate  uint64   `yaml:"hard_rate"`
	HardBurst uint64   `yaml:"hard_burst"`
	HardTTL   Duration `yaml:"hard_ttl"`
	BlockTTL  Duration `yaml:"block_ttl"`
	Cooldown  Duration `yaml:"cooldown"`
}

// BlockGateSpec defines the sustained-severity requirement before a BLOCK transition.
type BlockGateSpec struct {
	MinSeverity float64  `yaml:"min_severity"`
	MinDuration Duration `yaml:"min_duration"`
}

// AntiFlapSpec controls streak counters and minimum hold times.
type AntiFlapSpec struct {
	UpNeed      int      `yaml:"up_need"`
	DownNeed    int      `yaml:"down_need"`
	MinHoldSoft Duration `yaml:"min_hold_soft"`
	MinHoldHard Duration `yaml:"min_hold_hard"`
}

// NonComplianceSpec defines escalation behaviour for sources that ignore rate limits.
type NonComplianceSpec struct {
	At    int     `yaml:"at"`
	Drop  float64 `yaml:"drop"`
	Sev   float64 `yaml:"sev"`
	Reset float64 `yaml:"reset"`
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
	if p.Spec.Heuristic.TrigPPS <= 0 {
		return fmt.Errorf("spec.heuristic.trig_pps must be > 0")
	}
	if p.Spec.FSM.SoftAt <= 0 || p.Spec.FSM.HardAt <= 0 || p.Spec.FSM.BlockAt <= 0 {
		return fmt.Errorf("spec.fsm.soft_at, hard_at, block_at must all be > 0")
	}
	validActions := map[string]bool{"observe": true, "signal": true, "rate_limit": true, "block": true, "": true}
	if !validActions[p.Spec.Autonomy.MaxAction] {
		return fmt.Errorf("spec.autonomy.max_action %q is not valid (observe|signal|rate_limit|block)", p.Spec.Autonomy.MaxAction)
	}
	validModes := map[string]bool{"learn": true, "frozen-observe": true, "frozen-enforce": true, "": true}
	if !validModes[p.Spec.Graph.Mode] {
		return fmt.Errorf("spec.graph.mode %q is not valid (learn|frozen-observe|frozen-enforce)", p.Spec.Graph.Mode)
	}
	return nil
}
