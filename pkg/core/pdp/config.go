// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package pdp defines the PDPConfig format: all kliq-internal operational
// parameters in a single file.
//
// Architecture — two files per node role, both Forge-distributable:
//
//	PolicyPack  (pkg/core/policy) — WHAT to enforce: abstract rules,
//	            capability requirements, autonomy gates. PEP-agnostic.
//	            Forge signs and distributes this.
//
//	PDPConfig   (this package)    — HOW kliq operates: signal engine,
//	            progressive enforcement, graph learning, and the concrete
//	            parameters for each built-in adapter (shield_pep, etc.).
//	            Forge signs and distributes this too.
//
// Autotune overrides SignalEngine thresholds at runtime as kliq learns
// the node's normal traffic baseline.
package pdp

import (
	"fmt"
	"time"
)

const (
	expectedAPIVersion = "kernloom.io/v1alpha1"
	expectedKind       = "PDPConfig"
)

// Config is the top-level struct for a PDPConfig YAML file.
type Config struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata holds the config identity fields.
type Metadata struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
}

// Spec is the full PDP operational body.
type Spec struct {
	// SignalEngine controls how raw telemetry (PPS, SYN/s, scan/s) is
	// translated into severity scores. Cold-start defaults; autotune
	// overwrites the trigger values at runtime.
	SignalEngine SignalEngineSpec `yaml:"signal_engine"`

	// ProgressiveEnforcement defines how kliq escalates and de-escalates
	// enforcement levels (observe → soft → hard → block).
	ProgressiveEnforcement ProgressiveEnforcementSpec `yaml:"progressive_enforcement"`

	// NonCompliance defines additional escalation for sources that continue
	// sending traffic despite an active rate limit.
	NonCompliance NonComplianceSpec `yaml:"non_compliance"`

	// Graph controls graph learning and freeze-violation detection.
	// The enforcement ACTION for violations is expressed as a rule in the
	// PolicyPack (signal: graph.new_edge_after_freeze → action: …).
	Graph GraphSpec `yaml:"graph,omitempty"`

	// Baseline controls per-source traffic baseline learning and deviation detection.
	Baseline BaselineSpec `yaml:"baseline,omitempty"`

	// Adapters holds the concrete parameters for each built-in PEP adapter.
	// These are the values the adapter uses to implement abstract capabilities
	// (network.rate_limit_source, network.block_source) requested by the policy.
	Adapters AdaptersSpec `yaml:"adapters,omitempty"`
}

// ─── Baseline ─────────────────────────────────────────────────────────────────

// BaselineSpec controls per-edge traffic baseline learning.
// Baseline is automatically active when graph learning is enabled.
type BaselineSpec struct {
	// MinObservations before an edge profile is promoted from candidate to
	// learned and used for anomaly detection.
	MinObservations uint64 `yaml:"min_observations"`

	// Alpha is the stable long-run EWMA adaptation speed (0.0–1.0).
	// Lower = slower / more stable. Recommended: 0.01–0.05.
	Alpha float64 `yaml:"alpha"`

	// AlphaBootstrap is the faster EWMA speed used while obs < MinObservations.
	// Allows quick initial convergence; switches to Alpha after promotion.
	// Recommended: 0.05–0.15. Default (0) uses 0.10.
	AlphaBootstrap float64 `yaml:"alpha_bootstrap,omitempty"`

	// DeviationThreshold is the MAD multiplier that triggers a signal.
	// 5.0 = very conservative; lower values = more sensitive.
	DeviationThreshold float64 `yaml:"deviation_threshold"`
}

// ─── Signal engine ────────────────────────────────────────────────────────────

// SignalEngineSpec holds signal thresholds and scoring weights.
type SignalEngineSpec struct {
	// Cold-start trigger levels; autotune learns these from observed traffic.
	PPSTrigger  float64     `yaml:"pps_trigger"`
	SynTrigger  float64     `yaml:"syn_trigger"`
	ScanTrigger float64     `yaml:"scan_trigger"`
	BPSTrigger  float64     `yaml:"bps_trigger,omitempty"` // 0 = disabled
	Weights     WeightsSpec `yaml:"weights"`
}

// WeightsSpec controls how each signal contributes to the composite severity.
type WeightsSpec struct {
	PPS  float64 `yaml:"pps"`
	Syn  float64 `yaml:"syn"`
	Scan float64 `yaml:"scan"`
	BPS  float64 `yaml:"bps,omitempty"` // 0 = disabled
	// Cap is the maximum composite severity score (e.g. 3.0).
	Cap float64 `yaml:"cap"`
}

// ─── Progressive enforcement ──────────────────────────────────────────────────

// ProgressiveEnforcementSpec defines when kliq escalates, how it guards against
// block on transient spikes, and how long it holds each level.
type ProgressiveEnforcementSpec struct {
	// Strike thresholds: how many strikes to accumulate before transitioning.
	SoftAt  int `yaml:"soft_at"`
	HardAt  int `yaml:"hard_at"`
	BlockAt int `yaml:"block_at"`

	// Anti-flap: consecutive high/low ticks required before escalating or
	// de-escalating. Prevents flip-flop on bursty-but-legitimate traffic.
	UpNeed   int `yaml:"up_need"`
	DownNeed int `yaml:"down_need"`

	// Block gate: the FSM only reaches BLOCK if severity has been above
	// BlockMinSev for at least BlockMinDur. Prevents blocking on short spikes.
	BlockMinSev float64  `yaml:"block_min_sev"`
	BlockMinDur Duration `yaml:"block_min_dur"`

	// Minimum hold times before de-escalating from soft or hard.
	MinHoldSoft Duration `yaml:"min_hold_soft"`
	MinHoldHard Duration `yaml:"min_hold_hard"`
}

// NonComplianceSpec defines escalation for sources ignoring rate limits.
type NonComplianceSpec struct {
	At    int     `yaml:"at"`
	Drop  float64 `yaml:"drop"`
	Sev   float64 `yaml:"sev"`
	Reset float64 `yaml:"reset"`
}

// ─── Graph ────────────────────────────────────────────────────────────────────

// GraphSpec controls graph learning and freeze-violation detection.
type GraphSpec struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"` // learn | frozen-observe | frozen-enforce
	Store   string `yaml:"store,omitempty"`

	Promotion GraphPromotionSpec `yaml:"promotion,omitempty"`
	Freeze    GraphFreezeSpec    `yaml:"freeze,omitempty"`
	Exclude   GraphExcludeSpec   `yaml:"exclude,omitempty"`
}

// GraphPromotionSpec controls when candidate edges are promoted to learned.
type GraphPromotionSpec struct {
	MinSeenCount int      `yaml:"min_seen_count"`
	MinWindows   int      `yaml:"min_windows"`
	MinAge       Duration `yaml:"min_age"`
	ExpireTTL    Duration `yaml:"expire_ttl,omitempty"`
}

// GraphFreezeSpec defines autonomy gates for graph freeze enforcement.
// The enforcement action itself lives in the PolicyPack rules.
type GraphFreezeSpec struct {
	MaxAction           string `yaml:"max_action"`
	AllowBlock          bool   `yaml:"allow_block"`
	MinSeverityForBlock int    `yaml:"min_severity_for_block"`
}

// GraphExcludeSpec lists source addresses to skip during graph learning.
type GraphExcludeSpec struct {
	SourceCIDRs []string `yaml:"source_cidrs,omitempty"`
	Broadcast   bool     `yaml:"broadcast"`
	Loopback    bool     `yaml:"loopback"`
}

// ─── Adapters ─────────────────────────────────────────────────────────────────

// AdaptersSpec holds concrete parameters for each built-in PEP adapter.
// These translate abstract policy actions (rate_limit, block) into the
// specific values the adapter writes to its enforcement backend.
type AdaptersSpec struct {
	// ShieldPEP configures the built-in Kernloom Shield XDP/eBPF adapter.
	ShieldPEP ShieldPEPAdapterSpec `yaml:"shield_pep,omitempty"`
}

// ShieldPEPAdapterSpec is the Shield-specific implementation of the abstract
// network.rate_limit_source and network.block_source capabilities.
type ShieldPEPAdapterSpec struct {
	// Soft level: applied when the FSM first triggers enforcement.
	SoftRatePPS uint64 `yaml:"soft_rate_pps"`
	SoftBurst   uint64 `yaml:"soft_burst"`

	// Hard level: applied when soft enforcement is insufficient.
	HardRatePPS uint64 `yaml:"hard_rate_pps"`
	HardBurst   uint64 `yaml:"hard_burst"`

	// Cooldown is the minimum time between FSM level transitions.
	Cooldown Duration `yaml:"cooldown"`
}

// ─── Duration ─────────────────────────────────────────────────────────────────

// Duration is a YAML-serialisable wrapper around time.Duration.
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
		return fmt.Errorf("pdp: invalid duration %q: %w", s, err)
	}
	d.D = parsed
	return nil
}

// ─── Validation ───────────────────────────────────────────────────────────────

// Validate checks required fields and structural constraints.
func (c *Config) Validate() error {
	if c.APIVersion != expectedAPIVersion {
		return fmt.Errorf("unsupported apiVersion %q (want %q)", c.APIVersion, expectedAPIVersion)
	}
	if c.Kind != expectedKind {
		return fmt.Errorf("unsupported kind %q (want %q)", c.Kind, expectedKind)
	}
	if c.Metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}
	if c.Spec.SignalEngine.PPSTrigger <= 0 {
		return fmt.Errorf("spec.signal_engine.pps_trigger must be > 0")
	}
	pe := c.Spec.ProgressiveEnforcement
	if pe.SoftAt <= 0 || pe.HardAt <= 0 || pe.BlockAt <= 0 {
		return fmt.Errorf("spec.progressive_enforcement.soft_at, hard_at, block_at must all be > 0")
	}
	validModes := map[string]bool{"learn": true, "frozen-observe": true, "frozen-enforce": true, "": true}
	if !validModes[c.Spec.Graph.Mode] {
		return fmt.Errorf("spec.graph.mode %q is not valid (learn|frozen-observe|frozen-enforce)", c.Spec.Graph.Mode)
	}
	return nil
}
