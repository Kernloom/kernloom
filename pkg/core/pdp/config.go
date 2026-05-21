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

	// Autotune controls how kliq learns trigger thresholds (TrigPPS/TrigSyn/
	// TrigScan/TrigBPS) from observed traffic via reservoir sampling + Median+MAD.
	// Includes the three-phase bootstrap schedule for the initial learning window.
	Autotune AutotuneSpec `yaml:"autotune,omitempty"`
}

// ─── Autotune / Bootstrap ──────────────────────────────────────────────────────

// AutotuneSpec controls all autotune behaviour including the bootstrap schedule.
type AutotuneSpec struct {
	// Enabled turns autotune on or off.
	Enabled bool `yaml:"enabled"`

	// MinSamples is the minimum number of reservoir samples required before
	// autotune applies a new trigger value.
	MinSamples int `yaml:"min_samples,omitempty"`

	// Floors are the minimum allowed trigger values after autotune.
	// Autotune will never set a trigger below its floor.
	Floors AutotuneFloorsSpec `yaml:"floors,omitempty"`

	// Bootstrap defines the multi-phase learning schedule for the first
	// BootstrapWindow after kliq starts on a new node. Omit to use CLI defaults.
	Bootstrap BootstrapSpec `yaml:"bootstrap,omitempty"`
}

// AutotuneFloorsSpec sets the minimum allowed trigger values.
type AutotuneFloorsSpec struct {
	PPS  float64 `yaml:"pps,omitempty"`  // minimum TrigPPS (default 100)
	Syn  float64 `yaml:"syn,omitempty"`  // minimum TrigSyn (default 50)
	Scan float64 `yaml:"scan,omitempty"` // minimum TrigScan (default 20)
	BPS  float64 `yaml:"bps,omitempty"`  // minimum TrigBPS (default 0 = disabled)
}

// BootstrapSpec describes the multi-phase autotune schedule.
// K interpolates linearly from KStart (day 0) to KFinal (end of Window).
// TrigPPS = max(floor, median + K × MAD), then capped by MaxUp/MaxDown.
type BootstrapSpec struct {
	// Window is the total bootstrap duration. After this, Steady applies.
	Window Duration `yaml:"window,omitempty"`

	// K interpolation: conservative at start, tighter at end.
	KStart float64 `yaml:"k_start,omitempty"` // K on day 0 (more conservative)
	KFinal float64 `yaml:"k_final,omitempty"` // K at end of Window (final value)

	// Phase durations (measured from bootstrap start time).
	// Phase 1 ends at Phase1End; Phase 2 ends at Phase2End.
	// Phase 3 runs from Phase2End to Window.
	Phase1End Duration `yaml:"phase1_end,omitempty"`
	Phase2End Duration `yaml:"phase2_end,omitempty"`

	Phase1 BootstrapPhaseSpec `yaml:"phase1,omitempty"`
	Phase2 BootstrapPhaseSpec `yaml:"phase2,omitempty"`
	Phase3 BootstrapPhaseSpec `yaml:"phase3,omitempty"`
	Steady BootstrapPhaseSpec `yaml:"steady,omitempty"`
}

// BootstrapPhaseSpec defines autotune behaviour within one phase.
type BootstrapPhaseSpec struct {
	// Interval is how often autotune recalculates triggers in this phase.
	Interval Duration `yaml:"interval,omitempty"`

	// MaxUp / MaxDown cap the relative change per autotune cycle.
	// 0.10 = TrigPPS may rise at most 10% per cycle.
	MaxUp   float64 `yaml:"max_up,omitempty"`
	MaxDown float64 `yaml:"max_down,omitempty"`

	// Alpha is the EWMA smoothing applied when writing the new trigger value.
	// Lower = more gradual transition. 0 = no smoothing (instant).
	Alpha float64 `yaml:"alpha,omitempty"`
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

	// MinObsTimeBased and MinAge enable time-based promotion: an edge is promoted
	// to learned when obs >= MinObsTimeBased AND edge age >= MinAge, even if
	// obs < MinObservations. Useful for low-frequency traffic (weekly jobs).
	// 0 values disable time-based promotion.
	MinObsTimeBased uint64   `yaml:"min_obs_time_based,omitempty"`
	MinAge          Duration `yaml:"min_age_time_based,omitempty"`

	// DeviationThreshold is the MAD multiplier that triggers a signal.
	// 5.0 = very conservative; lower values = more sensitive.
	DeviationThreshold float64 `yaml:"deviation_threshold"`

	// MinUpdatePPS / MinUpdateBPS filter out very-low-traffic ticks from EWMA
	// updates. Useful for bimodal sources (idle keepalives + response bursts).
	// 0 = disabled.
	MinUpdatePPS float64 `yaml:"min_update_pps,omitempty"`
	MinUpdateBPS float64 `yaml:"min_update_bps,omitempty"`

	// PeakTolerance is the multiplier above the learned peak that triggers a
	// peak-exceeded signal. Default (0) uses 1.5 (50% above learned max).
	PeakTolerance float64 `yaml:"peak_tolerance,omitempty"`

	// PeakDecayHalfLife enables Sprint-5 decaying peaks.
	// A peak from one half-life ago is worth 50% of its original value.
	// Recommended: 336h (14 days). 0 disables decay.
	PeakDecayHalfLife Duration `yaml:"peak_decay_half_life,omitempty"`
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

	// Netfilter configures the kernloom.netfilter adapter.
	// Active when --adapter includes "netfilter" (NAS/legacy systems without XDP).
	Netfilter NetfilterAdapterSpec `yaml:"netfilter,omitempty"`
}

// ShieldPEPAdapterSpec is the Shield-specific implementation of the abstract
// network.rate_limit_source and network.block_source capabilities.
type ShieldPEPAdapterSpec struct {
	// Static rate/burst: used when adaptive mode is disabled (factors = 0).
	SoftRatePPS uint64 `yaml:"soft_rate_pps"`
	SoftBurst   uint64 `yaml:"soft_burst"`
	HardRatePPS uint64 `yaml:"hard_rate_pps"`
	HardBurst   uint64 `yaml:"hard_burst"`

	// Adaptive rate factors: when > 0, the effective rate is computed as
	// trig_pps × factor, updated every autotune cycle. This keeps enforcement
	// proportional to the learned traffic baseline instead of using fixed values.
	//
	//   soft_rate = trig_pps × SoftRateFactor  (e.g. 0.5 = 50% of normal)
	//   hard_rate = trig_pps × HardRateFactor  (e.g. 0.1 = 10% of normal)
	//
	// Burst is derived as rate × 2 (two seconds of headroom).
	// Static rate/burst fields are ignored when the corresponding factor is set.
	SoftRateFactor float64 `yaml:"soft_rate_factor,omitempty"`
	HardRateFactor float64 `yaml:"hard_rate_factor,omitempty"`

	// Cooldown is the minimum time between FSM level transitions.
	Cooldown Duration `yaml:"cooldown"`
}

// ─── Netfilter adapter ────────────────────────────────────────────────────────

// NetfilterAdapterSpec configures the kernloom.netfilter PEP adapter.
// Used when --adapter includes "netfilter" (e.g. NAS/legacy systems without XDP).
type NetfilterAdapterSpec struct {
	// Backend pins the Netfilter backend. Empty = auto-select (preferred).
	// Values: "nftables" | "iptables-nft" | "iptables-legacy"
	// Set to "iptables-legacy" on Synology/QNAP-like systems.
	Backend string `yaml:"backend,omitempty"`

	// Directions controls which Netfilter hooks Kernloom installs rules in.
	Directions struct {
		Input   bool `yaml:"input"`   // default: true
		Forward bool `yaml:"forward"` // default: false
		Output  bool `yaml:"output"`  // default: false
	} `yaml:"directions,omitempty"`

	// RateLimit configures default enforcement rates for SOFT/HARD levels.
	// Per-source rates: falls back to hashlimit (iptables) or meter (nftables).
	RateLimit struct {
		SoftRatePPS uint64 `yaml:"soft_rate_pps,omitempty"` // default: 100
		HardRatePPS uint64 `yaml:"hard_rate_pps,omitempty"` // default: 20
	} `yaml:"rate_limit,omitempty"`

	// Observation configures conntrack-based flow telemetry for GraphLearner.
	Observation struct {
		// ConntrackSnapshot enables periodic conntrack -L polling.
		ConntrackSnapshot bool `yaml:"conntrack_snapshot,omitempty"` // default: true
		// ConntrackPollInterval is the polling frequency.
		ConntrackPollInterval Duration `yaml:"conntrack_poll_interval,omitempty"` // default: 5s
	} `yaml:"observation,omitempty"`

	// Safety controls lockout-prevention behaviour.
	Safety struct {
		// ManagementAllowlist are CIDRs that must never be blocked.
		// Applied as RETURN rules before all Kernloom deny rules.
		// Recommended: set to management/admin subnet on production systems.
		ManagementAllowlist []string `yaml:"management_allowlist,omitempty"`
	} `yaml:"safety,omitempty"`
}

// ─── Duration ─────────────────────────────────────────────────────────────────

// Duration is a YAML-serialisable wrapper around time.Duration.
type Duration struct{ D time.Duration }

func (d Duration) MarshalYAML() (any, error) {
	return d.D.String(), nil
}

func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
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
