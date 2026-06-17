// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/shieldpep"
	celeval "github.com/kernloom/kernloom/pkg/core/cel"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

/* ---------------- CLI configuration ---------------- */

type cfg struct {
	// General
	Interval time.Duration
	TopN     int
	MinPPS   float64
	MinSev   float64

	// Deployment config (KliqDeploymentConfig + KliqComponentConfig files)
	DeploymentConfigPath string
	ComponentConfigPath  string

	// PolicyVerifyKeyPath is the path to the Ed25519 public key used to verify
	// the signature on LocalPolicyPack files. Required in managed mode when a
	// policy file is loaded — unsigned packs are rejected (CLAUDE.md rule #8).
	PolicyVerifyKeyPath string

	// CELRules holds compiled v1.2 CEL rules from the active policy pack.
	// Populated by rulesFromPolicyPack; evaluated per-source-IP on every tick.
	CELRules []*celeval.CompiledRule

	// Forge control-plane coordinates.
	ForgeURL         string
	ForgeEnrollToken string // one-time enrollment token (consumed at enrollment, replaced by session token)
	ForgeCAPath      string // path to CA certificate for TLS verification (PEM); empty = system roots
	ForgeHeartbeat   time.Duration
	FailMode         string // fail_static | fail_open

	// Mode + policy + pdp config
	Mode       string // "standalone" or "managed"
	PolicyFile string // path to LocalPolicyPack YAML (abstract enforcement rules)
	PDPConfig  string // path to PDPConfig YAML (kliq signal engine + FSM behavior)

	// Adapters is the comma-separated list of PEP adapters to activate.
	// Valid values: klshield, netfilter. Default: "klshield".
	// Example: --adapter=klshield,netfilter  or  --adapter=netfilter
	Adapters string

	// Profiles + persistence
	ProfileName string
	StatePath   string
	MaxStateAge time.Duration
	HistoryKeep int

	// Whitelist
	WhitelistPath   string
	WhitelistReload time.Duration
	WhitelistLearn  bool

	// Feedback
	FeedbackPath          string
	FeedbackReload        time.Duration
	FeedbackLearn         bool
	FeedbackCIDRDeenforce bool
	FeedbackCIDREvery     time.Duration
	FeedbackCIDRMax       int

	// Bootstrap
	Bootstrap         bool
	BootstrapWindow   time.Duration
	BootstrapP1End    time.Duration
	BootstrapP2End    time.Duration
	BootstrapEvery1   time.Duration
	BootstrapEvery2   time.Duration
	BootstrapEvery3   time.Duration
	SteadyEvery       time.Duration
	BootstrapKStart   float64
	BootstrapKFinal   float64
	BootstrapMaxUp1   float64
	BootstrapMaxDown1 float64
	BootstrapMaxUp2   float64
	BootstrapMaxDown2 float64
	BootstrapMaxUp3   float64
	BootstrapMaxDown3 float64
	BootstrapAlpha1   float64
	BootstrapAlpha2   float64
	BootstrapAlpha3   float64

	// Bootstrap safety guards (Sprint 2).
	// BootstrapAllowBlock: when false (default), the FSM caps BLOCK → RATE_HARD
	// during the active bootstrap window to avoid premature hard blocks on quiet starts.
	BootstrapAllowBlock bool
	// BootstrapMinWindowsBeforeDownscale: autotune will not lower triggers until
	// at least this many active autotune windows have been completed. Prevents
	// quiet-start threshold collapse when real traffic hasn't been observed yet.
	BootstrapMinWindowsBeforeDownscale int
	// BootstrapMinSourcesBeforeDownscale: autotune will not lower triggers until
	// at least this many distinct source IPs have been seen in the learning window.
	BootstrapMinSourcesBeforeDownscale int

	// BootstrapActive is set at runtime (not a CLI flag) to indicate the
	// current bootstrap phase is still active. Used by FSM to cap BLOCK level.
	BootstrapActive bool

	// Feature profile (Sprint 1) — controls which subsystems are active.
	// Values: dos-light, iq-learning, graph-learning, graph-enforce.
	// Default: automatically derived from --graph flag for backward compatibility.
	FeatureProfile string

	// Source baseline (Sprint 3) — per-source EWMA + peak tracking.
	// Active when FeatureProfile is iq-learning or graph-*.
	SrcBaselineAlpha       float64
	SrcBaselineAlphaStable float64
	SrcBaselineMinPPS      float64
	SrcBaselineMinObs      uint64
	SrcBaselineMaxSources  int
	SrcBaselinePeakMul     float64
	SrcBaselineMinConf     float64

	// Autotune
	AutoTune       bool
	AutoEvery      time.Duration
	AutoMinSamples int
	AutoK          float64
	AutoMaxChange  float64
	AutoMaxUp      float64
	AutoMaxDown    float64
	AutoAlpha      float64
	AutoFloorPPS   float64
	AutoFloorSyn   float64
	AutoFloorScan  float64
	AutoFloorBPS   float64

	// Anti-poisoning
	LearnSevGT        float64
	LearnFracGT       float64
	LearnMaxSev       float64
	LearnSkipIfBlocks bool
	LearnMaxDropRatio float64

	// Severity thresholds
	TrigPPS  float64
	TrigSyn  float64
	TrigScan float64
	TrigBPS  float64
	WPPS     float64
	WSyn     float64
	WScan    float64
	WBps     float64
	SevCap   float64

	// Strike mapping
	SevStep1      float64
	SevStep2      float64
	SevStep3      float64
	SevDelta1     int
	SevDelta2     int
	SevDelta3     int
	SevDecayBelow float64

	// FSM thresholds
	SoftAt  int
	HardAt  int
	BlockAt int

	// Enforcement TTLs: how long the PDP holds each level (PDP scheduling).
	// Set from policy rules or profile defaults; no longer CLI flags.
	SoftTTL  time.Duration
	HardTTL  time.Duration
	BlockTTL time.Duration
	// Cooldown: min time between FSM level changes. Set from adapter manifest.
	Cooldown time.Duration

	// PolicyMaxAction is the ceiling on enforcement actions set by the Forge
	// PolicyPack (autonomy.max_action). Applied to ALL enforcement transitions.
	//   ""            = no cap, full enforcement allowed (default)
	//   "rate_limit"  = cap at LevelSoft; no hard or block transitions
	//   "observe"     = no enforcement (equivalent to dry_run for FSM)
	PolicyMaxAction string

	// HasPolicyPack is true when a valid LocalPolicyPack was loaded at startup.
	// In managed mode, enforcement is capped to observe if no valid pack is present.
	HasPolicyPack bool

	// CapabilitiesRequired is the set of Forge capability IDs explicitly listed
	// in the PolicyPack's capabilities_required field. In managed mode the
	// ActionResolver will deny any capability not in this set.
	// Nil means "all capabilities allowed" (standalone and packs without the field).
	CapabilitiesRequired map[string]bool

	// Per-level Forge capability IDs read from PolicyPack rules (then.capability).
	// Used for logging and future capability-based adapter dispatch.
	// Values are normalised to KLIQ internal IDs via normalizeCapabilityID.
	SoftCapability  string
	HardCapability  string
	BlockCapability string

	// Adaptive rate factors (Phase 6a): when > 0, rates = trig_pps × factor.
	// 0 means static mode — adapterParams rates are used as-is.
	SoftRateFactor float64
	HardRateFactor float64

	// Directive rates (Phase 6b): explicit req/s from the PolicyPack's then.params.
	// Priority: Directive > Adaptive > Static.
	// When set, the pack is in access-control mode — FSM still runs but the rate
	// limit strength is fixed by policy, not derived locally.
	SoftDirectiveRatePPS uint64
	HardDirectiveRatePPS uint64

	// adapterParams holds the Shield PEP adapter capability parameters,
	// loaded from PDPConfig.Adapters.ShieldPEP or DefaultCapabilityParams().
	adapterParams shieldpep.CapabilityParams

	// Block gating
	BlockMinSev float64
	BlockMinDur time.Duration

	// Anti-flap
	UpNeed      int
	DownNeed    int
	MinHoldSoft time.Duration
	MinHoldHard time.Duration

	// Non-compliance
	NonCompAt         int
	NonCompDrop       float64
	NonCompSev        float64
	NonCompResetBelow float64

	// Housekeeping
	PrevTTL  time.Duration
	StateTTL time.Duration
	DryRun   bool

	// BPF filesystem root (default /sys/fs/bpf)
	BPFfsRoot string

	// State store (statestore/sqlite) for generic baselines, relationships,
	// learning exclusions, evidence.  Defaults to a sidecar file next to the
	// graph store.  The graph store (GraphStorePath) remains the source of truth
	// for L3/L4 edges; the state store holds the generic pipeline state.
	StateStorePath string

	// Graph learning
	GraphEnabled           bool
	GraphStorePath         string // runtime state — /var/lib/kernloom/iq/
	GraphFrozenPath        string // IMA-attested static baseline — /opt/kernloom/attested/etc/
	GraphMode              string
	GraphNodeID            string
	GraphPromoteInterval   time.Duration
	GraphMinSeenCount      uint64
	GraphMinWindows        int
	GraphMinAge            time.Duration
	GraphExpireTTL         time.Duration
	GraphMinPackets        uint64
	GraphMinBytes          uint64
	GraphExcludeBcast      bool
	GraphExcludeLoopback   bool
	GraphExcludeSourceCIDR string // comma-separated CIDRs to exclude from graph learning

	// Graph freeze enforcement (decision engine).
	GraphFreezeAction      string        // "signal", "rate_limit", "block"
	GraphFreezeTTL         time.Duration // enforcement TTL for freeze violations
	GraphFreezeMaxAction   string        // upper bound on freeze enforcement action
	GraphFreezeAllowBlock  bool          // permit block decisions from freeze violations
	GraphFreezeMinSeverity int           // minimum signal score (0-100) before enforcement

	// Baseline engine (per-edge EWMA traffic learning, active when GraphEnabled=true).
	BaselineMinObservations    uint64
	BaselineAlpha              float64
	BaselineAlphaBootstrap     float64
	BaselineMinObsTimeBased    uint64
	BaselineMinAge             time.Duration
	BaselineDeviationThreshold float64
	BaselineMinUpdatePPS       float64
	BaselineMinUpdateBPS       float64
	BaselinePeakTolerance      float64
	BaselinePeakDecayHalfLife  time.Duration
}

// hasAdapter reports whether name is in the --adapter list.
func (c cfg) hasAdapter(name string) bool {
	for _, a := range strings.Split(c.Adapters, ",") {
		if strings.TrimSpace(a) == name {
			return true
		}
	}
	return false
}

// WantsKLShield returns true when klshield is in the adapter list.
func (c cfg) WantsKLShield() bool { return c.hasAdapter("klshield") }

// WantsNetfilter returns true when netfilter is in the adapter list.
func (c cfg) WantsNetfilter() bool { return c.hasAdapter("netfilter") }

// toFSMConfig converts the relevant cfg fields to an fsm.Config.
func (c cfg) toFSMConfig() fsm.Config {
	return fsm.Config{
		SevStep1:          c.SevStep1,
		SevStep2:          c.SevStep2,
		SevStep3:          c.SevStep3,
		SevDelta1:         c.SevDelta1,
		SevDelta2:         c.SevDelta2,
		SevDelta3:         c.SevDelta3,
		SevDecayBelow:     c.SevDecayBelow,
		SoftAt:            c.SoftAt,
		HardAt:            c.HardAt,
		BlockAt:           c.BlockAt,
		UpNeed:            c.UpNeed,
		DownNeed:          c.DownNeed,
		MinHoldSoft:       c.MinHoldSoft,
		MinHoldHard:       c.MinHoldHard,
		BlockMinSev:       c.BlockMinSev,
		BlockMinDur:       c.BlockMinDur,
		Cooldown:          c.Cooldown,
		SoftTTL:           c.SoftTTL,
		HardTTL:           c.HardTTL,
		BlockTTL:          c.BlockTTL,
		NonCompAt:         c.NonCompAt,
		NonCompDrop:       c.NonCompDrop,
		NonCompSev:        c.NonCompSev,
		NonCompResetBelow: c.NonCompResetBelow,
		LearnMaxSev:       c.LearnMaxSev,
	}
}

// toPEPParams assembles EnforcementParams from adapter config and TTLs.
//
// Three-tier priority for rate/burst (highest wins):
//
//  1. Directive  — SoftDirectiveRatePPS/HardDirectiveRatePPS from PolicyPack
//     then.params.rate_pps. Fixed by Forge; used for access-control policies.
//  2. Adaptive   — TrigPPS × factor (Phase 6a). Tracks autotune baseline.
//  3. Static     — adapterParams from PDPConfig or DefaultCapabilityParams().
//
// Called every tick so adaptive rates follow autotune changes automatically.
func (c cfg) toPEPParams() shieldpep.EnforcementParams {
	softRate := c.adapterParams.SoftRatePPS
	softBurst := c.adapterParams.SoftBurst
	hardRate := c.adapterParams.HardRatePPS
	hardBurst := c.adapterParams.HardBurst

	// Priority 2: adaptive — rates derived from autotune-learned TrigPPS.
	if c.SoftRateFactor > 0 && c.TrigPPS > 0 {
		r := uint64(c.TrigPPS * c.SoftRateFactor)
		if r < 1 {
			r = 1
		}
		softRate, softBurst = r, r*2
	}
	if c.HardRateFactor > 0 && c.TrigPPS > 0 {
		r := uint64(c.TrigPPS * c.HardRateFactor)
		if r < 1 {
			r = 1
		}
		hardRate, hardBurst = r, r*2
	}

	// Priority 1: directive — explicit rate from PolicyPack, overrides everything.
	if c.SoftDirectiveRatePPS > 0 {
		softRate, softBurst = c.SoftDirectiveRatePPS, c.SoftDirectiveRatePPS*2
	}
	if c.HardDirectiveRatePPS > 0 {
		hardRate, hardBurst = c.HardDirectiveRatePPS, c.HardDirectiveRatePPS*2
	}

	return shieldpep.EnforcementParams{
		SoftRate:  softRate,
		SoftBurst: softBurst,
		SoftTTL:   c.SoftTTL,
		HardRate:  hardRate,
		HardBurst: hardBurst,
		HardTTL:   c.HardTTL,
		BlockTTL:  c.BlockTTL,
		Cooldown:  c.adapterParams.Cooldown,
	}
}

func parseFlags() cfg {
	var c cfg

	// Write help to stdout so it can be piped and grepped.
	flag.CommandLine.SetOutput(os.Stdout)
	flag.Usage = func() {
		fmt.Fprintf(os.Stdout, `Kernloom IQ — local intelligence and enforcement agent

USAGE
  kliq [flags]                      run the kliq agent
  kliq status                       show node status: bootstrap phase, autotune triggers, graph/baseline summary
  kliq runtime status [profile]     show active feature set for a runtime profile
                                    profiles: dos-light  iq-learning  graph-learning  graph-enforce  klshield-light
  kliq graph <subcommand>           manage the communication graph and edge baselines

GRAPH SUBCOMMANDS
  kliq graph edges [--all] [--sort=last|state|src|port|seen] [store] [node-id]
      Show learned communication edges and their state.
      --all    show all edges (default: first 30)
      --sort=  sort by: last (default), state, src, port, seen

  kliq graph baselines [--all] [--sort=obs|state|src|port|pps|bps] [store] [node-id]
      Show per-edge EWMA traffic baselines (src, dst, proto, port, pps, bps).
      --all    show all edges (default: first 40)
      --sort=  sort by: obs (default), state, src, port, pps, bps

  kliq graph baselines reset [store] [node-id]
      Zero all per-edge baseline stats so EWMA learning restarts from scratch.

  kliq graph export [--format=json] [store] [node-id]
      Export full graph as YAML (or JSON) to stdout.

  kliq graph freeze [store] [node-id] [frozen-file]
      Freeze all learned/approved edges and write frozen-graph.yaml.

  kliq graph reset [--all] [store] [node-id]
      Delete candidate/learned/expired edges so the graph re-learns.
      --all   also wipe frozen and approved edges (full reset).

  kliq graph approve-ip <ip> [store] [node-id]
      Mark all edges from <ip> as approved (stops freeze-violation signals).

  kliq graph deny-ip <ip> [store] [node-id]
      Mark all edges from <ip> as denied.

AGENT FLAGS
`)
		flag.PrintDefaults()
	}

	flag.DurationVar(&c.Interval, "interval", 1*time.Second, "poll interval")
	flag.IntVar(&c.TopN, "top", 200, "top N sources by severity")
	flag.Float64Var(&c.MinPPS, "min-pps", 3, "ignore sources below this PPS for FSM; autotune also samples below this floor")
	flag.Float64Var(&c.MinSev, "min-sev", 0.0, "include candidates with severity >= min-sev")

	flag.StringVar(&c.DeploymentConfigPath, "deployment-config", "", "path to a KliqDeploymentConfig YAML (node identity, mode, runtime paths, Forge URL); overrides flag defaults when set")
	flag.StringVar(&c.ComponentConfigPath, "component-config", "", "path to a KliqComponentConfig YAML (enabled adapters and analyzers); reserved for future use")
	flag.StringVar(&c.PolicyVerifyKeyPath, "policy-verify-key", "", "path to Ed25519 public key for verifying LocalPolicyPack signatures; required in managed mode")
	flag.StringVar(&c.ForgeURL, "forge-url", "", "forge serve base URL (e.g. https://forge.example.com:8443); enables enrollment and heartbeat when set")
	flag.StringVar(&c.ForgeEnrollToken, "forge-enroll-token", "", "one-time enrollment token issued by 'forge token create' (consumed on first enrollment)")
	flag.StringVar(&c.ForgeCAPath, "forge-ca", "", "path to PEM CA certificate for TLS verification of forge serve; empty = system roots")
	flag.DurationVar(&c.ForgeHeartbeat, "forge-heartbeat", 5*time.Minute, "heartbeat interval to forge serve")

	flag.StringVar(&c.Adapters, "adapter", "klshield",
		`comma-separated PEP adapters to activate: klshield, netfilter (e.g. --adapter=klshield,netfilter or --adapter=netfilter)`)
	flag.StringVar(&c.Mode, "mode", "standalone", `agent mode: standalone (local policy) or managed (Forge-managed; currently logs a warning and runs as standalone)`)
	flag.StringVar(&c.PolicyFile, "policy-file", "", "path to a LocalPolicyPack YAML (abstract enforcement rules: autonomy, rules, graph, exports)")
	flag.StringVar(&c.PDPConfig, "pdp-config", "", "path to a PDPConfig YAML (kliq signal engine + FSM behavior); overrides --profile when set")
	flag.StringVar(&c.ProfileName, "profile", "generic", "built-in PDP behavior profile (ignored when --pdp-config is set)")
	// Runtime state — mutable, not under IMA measurement.
	flag.StringVar(&c.StatePath, "state-file", "/var/lib/kernloom/iq/state.json", "autotune state file (runtime, not IMA-attested)")
	flag.DurationVar(&c.MaxStateAge, "max-state-age", 14*24*time.Hour, "ignore persisted state older than this (0 disables)")
	flag.IntVar(&c.HistoryKeep, "state-history", 30, "keep last N history entries")

	// IMA-attested: static policy file, seldom changed, measured by IMA on read.
	flag.StringVar(&c.WhitelistPath, "whitelist", "/opt/kernloom/attested/etc/whitelist.txt", "whitelist file (IPv4/IPv6/CIDR), one per line; empty disables (IMA-attested)")
	flag.DurationVar(&c.WhitelistReload, "whitelist-reload", 10*time.Second, "reload whitelist if file changed (0 disables)")
	flag.BoolVar(&c.WhitelistLearn, "whitelist-learn", false, "if true, whitelisted IPs may contribute to learning; default false")

	// Runtime state — temporary exemptions, changes frequently, not under IMA.
	flag.StringVar(&c.FeedbackPath, "feedback-file", "/var/lib/kernloom/iq/feedback.json", "feedback file for temporary forgive/whitelist entries (runtime, not IMA-attested); empty disables")
	flag.DurationVar(&c.FeedbackReload, "feedback-reload", 10*time.Second, "reload feedback file if changed (0 disables)")
	flag.BoolVar(&c.FeedbackLearn, "feedback-learn", false, "if true, feedback-exempt IPs may contribute to learning; default false")
	flag.BoolVar(&c.FeedbackCIDRDeenforce, "feedback-deenforce-cidr", true, "if true, CIDR feedback entries will actively de-enforce existing deny/rl map entries by scanning maps periodically (best effort)")
	flag.DurationVar(&c.FeedbackCIDREvery, "feedback-cidr-every", 30*time.Second, "how often to scan maps to de-enforce CIDR feedback entries (0 disables)")
	flag.IntVar(&c.FeedbackCIDRMax, "feedback-cidr-max", 5000, "max number of entries to delete per CIDR de-enforce scan (bounds cost)")

	flag.StringVar(&c.FeatureProfile, "feature-profile", "", `runtime feature profile: dos-light, iq-learning, graph-learning, graph-enforce (default: auto from --graph)`)

	flag.BoolVar(&c.Bootstrap, "bootstrap", true, "enable bootstrap autotune schedule (frequent early, slower later)")
	flag.DurationVar(&c.BootstrapWindow, "bootstrap-window", 14*24*time.Hour, "bootstrap duration (suggest 14d)")
	flag.DurationVar(&c.BootstrapP1End, "bootstrap-phase1-end", 48*time.Hour, "end of phase1 since bootstrap start")
	flag.DurationVar(&c.BootstrapP2End, "bootstrap-phase2-end", 5*24*time.Hour, "end of phase2 since bootstrap start")
	flag.DurationVar(&c.BootstrapEvery1, "bootstrap-every1", 1*time.Hour, "autotune interval during phase1")
	flag.DurationVar(&c.BootstrapEvery2, "bootstrap-every2", 6*time.Hour, "autotune interval during phase2")
	flag.DurationVar(&c.BootstrapEvery3, "bootstrap-every3", 24*time.Hour, "autotune interval during phase3 (until bootstrap-window)")
	flag.DurationVar(&c.SteadyEvery, "steady-every", 84*time.Hour, "autotune interval after bootstrap (e.g. 84h ~ 2x/week)")
	flag.Float64Var(&c.BootstrapKStart, "bootstrap-k-start", 4.0, "bootstrap starting k (higher => fewer false positives)")
	flag.Float64Var(&c.BootstrapKFinal, "bootstrap-k-final", 3.5, "bootstrap final k at end of bootstrap-window")
	flag.Float64Var(&c.BootstrapMaxUp1, "bootstrap-max-up1", 0.10, "phase1 max relative increase per update")
	flag.Float64Var(&c.BootstrapMaxDown1, "bootstrap-max-down1", 0.02, "phase1 max relative decrease per update")
	flag.Float64Var(&c.BootstrapMaxUp2, "bootstrap-max-up2", 0.08, "phase2 max relative increase per update")
	flag.Float64Var(&c.BootstrapMaxDown2, "bootstrap-max-down2", 0.03, "phase2 max relative decrease per update")
	flag.Float64Var(&c.BootstrapMaxUp3, "bootstrap-max-up3", 0.05, "phase3 max relative increase per update")
	flag.Float64Var(&c.BootstrapMaxDown3, "bootstrap-max-down3", 0.05, "phase3 max relative decrease per update")
	flag.Float64Var(&c.BootstrapAlpha1, "bootstrap-alpha1", 0.10, "phase1 smoothing alpha")
	flag.Float64Var(&c.BootstrapAlpha2, "bootstrap-alpha2", 0.15, "phase2 smoothing alpha")
	flag.Float64Var(&c.BootstrapAlpha3, "bootstrap-alpha3", 0.20, "phase3 smoothing alpha")

	// Bootstrap safety guards.
	flag.BoolVar(&c.BootstrapAllowBlock, "bootstrap-allow-block", false, "allow BLOCK enforcement during bootstrap (default false — caps at RATE_HARD)")
	// bootstrap-min-windows=0 disables the downscale guard (default). The floor
	// (autotune-floor-pps) is the primary protection against threshold collapse.
	// Set > 0 only on nodes that start during dead-quiet periods and you want
	// extra protection before the first real traffic has been seen.
	flag.IntVar(&c.BootstrapMinWindowsBeforeDownscale, "bootstrap-min-windows", 0, "min completed autotune windows before allowing downscale (0=disabled; the floor is the primary guard)")
	flag.IntVar(&c.BootstrapMinSourcesBeforeDownscale, "bootstrap-min-sources", 0, "min distinct sources required before downscale (0=disabled)")

	// Source baseline flags (active when feature-profile >= iq-learning).
	flag.Float64Var(&c.SrcBaselineAlpha, "srcbl-alpha", 0.10, "source baseline EWMA speed during learning (default 0.10 ≈ 7-obs half-life)")
	flag.Float64Var(&c.SrcBaselineAlphaStable, "srcbl-alpha-stable", 0.02, "source baseline EWMA speed after promotion")
	flag.Float64Var(&c.SrcBaselineMinPPS, "srcbl-min-pps", 3, "skip source baseline update when pps < this (filters idle ticks)")
	flag.Uint64Var(&c.SrcBaselineMinObs, "srcbl-min-obs", 30, "observations before a source profile is promoted")
	flag.IntVar(&c.SrcBaselineMaxSources, "srcbl-max-sources", 100000, "max source profiles held in memory")
	flag.Float64Var(&c.SrcBaselinePeakMul, "srcbl-peak-mul", 1.2, "effective trigger = max(global, peak*multiplier) for known sources")
	flag.Float64Var(&c.SrcBaselineMinConf, "srcbl-min-conf", 0.4, "min confidence required to use source baseline as effective trigger")

	flag.BoolVar(&c.AutoTune, "autotune", true, "enable autotune of trig-* using median+MAD")
	flag.DurationVar(&c.AutoEvery, "autotune-every", 24*time.Hour, "how often to write new trig-* state")
	flag.IntVar(&c.AutoMinSamples, "autotune-min-samples", 500, "minimum samples per feature before tuning (lower on quiet nodes)")
	flag.Float64Var(&c.AutoK, "autotune-k", 3.5, "k for trig = median + k*mad (k=3.5 ~ p99)")
	flag.Float64Var(&c.AutoMaxChange, "autotune-max-change", 0.05, "max relative change per update (e.g. 0.05 => ±5%)")
	flag.Float64Var(&c.AutoMaxUp, "autotune-max-change-up", 0, "max relative increase per update (0 => use autotune-max-change)")
	flag.Float64Var(&c.AutoMaxDown, "autotune-max-change-down", 0, "max relative decrease per update (0 => use autotune-max-change)")
	flag.Float64Var(&c.AutoAlpha, "autotune-alpha", 0.2, "smoothing alpha (0 disables)")
	flag.Float64Var(&c.AutoFloorPPS, "autotune-floor-pps", 100, "minimum trig-pps")
	flag.Float64Var(&c.AutoFloorSyn, "autotune-floor-syn", 50, "minimum trig-syn")
	flag.Float64Var(&c.AutoFloorScan, "autotune-floor-scan", 20, "minimum trig-scan")
	flag.Float64Var(&c.AutoFloorBPS, "autotune-floor-bps", 0, "minimum trig-bps (0 disables BPS autotuning)")

	flag.Float64Var(&c.LearnSevGT, "learn-sev-gt", 1.0, "tick is 'dirty' if sev>=learn-sev-gt fraction is too high")
	flag.Float64Var(&c.LearnFracGT, "learn-frac-gt", 0.005, "max fraction of sources with sev>=learn-sev-gt to consider tick 'clean'")
	flag.Float64Var(&c.LearnMaxSev, "learn-max-sev", 0.8, "only add samples from sources with severity <= this")
	flag.BoolVar(&c.LearnSkipIfBlocks, "learn-skip-if-blocks", true, "if any IP is in BLOCK, skip learning for this tick")
	flag.Float64Var(&c.LearnMaxDropRatio, "learn-max-drop-ratio", 0.02, "skip learning if total_drop/(total_pass+total_drop) exceeds this (0 disables)")

	flag.Float64Var(&c.TrigPPS, "trig-pps", 0, "PPS trigger threshold (0 => from profile/state)")
	flag.Float64Var(&c.TrigSyn, "trig-syn", 0, "SYN/s trigger threshold (0 => from profile/state)")
	flag.Float64Var(&c.TrigScan, "trig-scan", 0, "scan/s trigger threshold (0 => from profile/state)")
	flag.Float64Var(&c.TrigBPS, "trig-bps", 0, "bytes/s trigger threshold (0 => from profile; 0 disables BPS scoring)")
	flag.Float64Var(&c.WPPS, "w-pps", 0, "weight for PPS (0 => from profile)")
	flag.Float64Var(&c.WSyn, "w-syn", 0, "weight for SYN/s (0 => from profile)")
	flag.Float64Var(&c.WScan, "w-scan", 0, "weight for scan/s (0 => from profile)")
	flag.Float64Var(&c.WBps, "w-bps", 0, "weight for bytes/s (0 => from profile; 0 disables BPS scoring)")
	flag.Float64Var(&c.SevCap, "sev-cap", 0, "cap for normalized metrics (0 => from profile)")

	flag.Float64Var(&c.SevStep1, "sev-step1", 1.0, "severity >= step1 -> add delta1 strikes")
	flag.Float64Var(&c.SevStep2, "sev-step2", 2.0, "severity >= step2 -> add delta2 strikes")
	flag.Float64Var(&c.SevStep3, "sev-step3", 3.0, "severity >= step3 -> add delta3 strikes")
	flag.IntVar(&c.SevDelta1, "sev-delta1", 1, "strike delta at step1")
	flag.IntVar(&c.SevDelta2, "sev-delta2", 2, "strike delta at step2")
	flag.IntVar(&c.SevDelta3, "sev-delta3", 3, "strike delta at step3")
	flag.Float64Var(&c.SevDecayBelow, "sev-decay-below", 0.25, "if severity < this, strikes may decay")

	flag.IntVar(&c.SoftAt, "soft-at", 0, "strikes >= soft-at -> SOFT (0 => from profile)")
	flag.IntVar(&c.HardAt, "hard-at", 0, "strikes >= hard-at -> HARD (0 => from profile)")
	flag.IntVar(&c.BlockAt, "block-at", 0, "strikes >= block-at -> BLOCK (0 => from profile)")

	// TTLs are PDP scheduling parameters set from policy rules or profile defaults.
	flag.DurationVar(&c.SoftTTL, "soft-ttl", 0, "soft enforcement TTL (0 => from policy rule or profile)")
	flag.DurationVar(&c.HardTTL, "hard-ttl", 0, "hard enforcement TTL (0 => from policy rule or profile)")
	flag.DurationVar(&c.BlockTTL, "block-ttl", 0, "block TTL (0 => from policy rule or profile)")
	// Rate/burst/cooldown come from PDPConfig.adapters.shield_pep, not CLI flags.

	c.BlockMinSev = math.NaN() // sentinel: use profile default
	flag.Float64Var(&c.BlockMinSev, "block-min-sev", math.NaN(), "only allow BLOCK if severity >= this (NaN => from profile, 0 disables)")
	c.BlockMinDur = -1 // sentinel: use profile default
	flag.DurationVar(&c.BlockMinDur, "block-min-dur", -1, "require sev>=block-min-sev for at least this duration (-1 => from profile, 0 disables)")

	flag.IntVar(&c.UpNeed, "up-need", 0, "require N consecutive high ticks before escalating (0 => from profile)")
	flag.IntVar(&c.DownNeed, "down-need", 0, "require N consecutive low ticks before de-escalation/decay (0 => from profile)")
	flag.DurationVar(&c.MinHoldSoft, "min-hold-soft", 0, "minimum time in SOFT before stepping down (0 => from profile)")
	flag.DurationVar(&c.MinHoldHard, "min-hold-hard", 0, "minimum time in HARD before stepping down (0 => from profile)")

	flag.IntVar(&c.NonCompAt, "noncomp-at", 0, "if NonCompTicks reaches this while in HARD -> BLOCK faster (0 => from profile)")
	flag.Float64Var(&c.NonCompDrop, "noncomp-drop", 0, "count as non-compliance if DropRL/s >= this (0 => from profile)")
	flag.Float64Var(&c.NonCompSev, "noncomp-sev", 0, "count as non-compliance if severity >= this (0 => from profile)")
	flag.Float64Var(&c.NonCompResetBelow, "noncomp-reset-below", 0, "reset NonCompTicks if severity < this AND DropRL/s==0 (0 => from profile)")

	flag.DurationVar(&c.PrevTTL, "prev-ttl", 10*time.Minute, "forget prev entries if not seen (bounds mem)")
	flag.DurationVar(&c.StateTTL, "state-ttl", 60*time.Minute, "forget OBSERVE-only state if not seen for this long")
	flag.BoolVar(&c.DryRun, "dry-run", true, "if true: no enforcement, only logs")
	flag.StringVar(&c.BPFfsRoot, "bpffs-root", "/sys/fs/bpf", "bpffs mount root")
	flag.Float64Var(&c.SoftRateFactor, "soft-rate-factor", 0,
		"adaptive soft rate limit: effective rate = trig_pps × factor (e.g. 0.5). "+
			"0 disables adaptive mode and uses --pdp-config soft_rate_pps instead")
	flag.Float64Var(&c.HardRateFactor, "hard-rate-factor", 0,
		"adaptive hard rate limit: effective rate = trig_pps × factor (e.g. 0.1). "+
			"0 disables adaptive mode and uses --pdp-config hard_rate_pps instead")

	flag.BoolVar(&c.GraphEnabled, "graph", false, "enable graph learning")
	// Runtime state — combined SQLite DB for graph edges and source baselines.
	// --db is the canonical state store path (used by both the runtime and all CLI subcommands).
	// --state-db is an alias kept for backward compatibility.
	flag.StringVar(&c.StateStorePath, "db", "/var/lib/kernloom/iq/kliq-state.db", "state store (relationships, baselines, exclusions, evidence)")
	flag.StringVar(&c.StateStorePath, "state-db", "/var/lib/kernloom/iq/kliq-state.db", "alias for --db")
	// IMA-attested: written once by 'kliq graph freeze', then static until next freeze.
	flag.StringVar(&c.GraphFrozenPath, "graph-frozen", "/opt/kernloom/attested/etc/frozen-graph.yaml", "frozen graph baseline written by 'kliq graph freeze' (IMA-attested if activated)")
	flag.StringVar(&c.GraphMode, "graph-mode", "learn", "graph mode: learn or frozen-observe")
	flag.StringVar(&c.GraphNodeID, "graph-node-id", "", "node ID for graph edges (defaults to hostname)")
	flag.DurationVar(&c.GraphPromoteInterval, "graph-promote-interval", 5*time.Minute, "how often to promote candidate edges to learned")
	flag.Uint64Var(&c.GraphMinSeenCount, "graph-min-seen", 5, "min observations before candidate is promoted to learned")
	flag.IntVar(&c.GraphMinWindows, "graph-min-windows", 3, "min distinct tick windows before promotion")
	flag.DurationVar(&c.GraphMinAge, "graph-min-age", 10*time.Minute, "min edge age before promotion")
	flag.DurationVar(&c.GraphExpireTTL, "graph-expire-ttl", 30*24*time.Hour, "mark edges expired after this idle time (0 disables)")
	flag.Uint64Var(&c.GraphMinPackets, "graph-min-packets", 0, "min packets per tick to record a graph edge (0 disables)")
	flag.Uint64Var(&c.GraphMinBytes, "graph-min-bytes", 0, "min bytes per tick to record a graph edge (0 disables)")
	flag.BoolVar(&c.GraphExcludeBcast, "graph-exclude-broadcast", true, "exclude broadcast/multicast destination addresses from graph")
	flag.BoolVar(&c.GraphExcludeLoopback, "graph-exclude-loopback", true, "exclude loopback addresses from graph")
	flag.StringVar(&c.GraphExcludeSourceCIDR, "graph-exclude-source-cidrs", "", "comma-separated CIDRs whose source IPs are excluded from graph learning (e.g. 172.16.0.0/12)")

	flag.StringVar(&c.GraphFreezeAction, "graph-freeze-action", "signal", "action on new edge after freeze: signal, rate_limit, block")
	flag.DurationVar(&c.GraphFreezeTTL, "graph-freeze-ttl", 10*time.Minute, "enforcement TTL for graph freeze violations")
	flag.StringVar(&c.GraphFreezeMaxAction, "graph-freeze-max-action", "rate_limit", "maximum allowed action for graph freeze enforcement")
	flag.BoolVar(&c.GraphFreezeAllowBlock, "graph-freeze-allow-block", false, "permit block decisions from graph freeze violations")
	flag.IntVar(&c.GraphFreezeMinSeverity, "graph-freeze-min-severity", 70, "minimum signal score (0-100) required before enforcing on a graph freeze violation")

	// Per-edge baseline (active when --graph is enabled; no separate flag).
	flag.Uint64Var(&c.BaselineMinObservations, "baseline-min-obs", 30, "edge observations before EWMA profile is promoted to learned")
	flag.Float64Var(&c.BaselineAlpha, "baseline-alpha", 0.02, "EWMA stable adaptation speed after bootstrap (0.0=never, 1.0=instant; recommended 0.01–0.05)")
	flag.Float64Var(&c.BaselineAlphaBootstrap, "baseline-alpha-bootstrap", 0.10, "EWMA bootstrap adaptation speed while obs < baseline-min-obs (faster initial convergence)")
	flag.Uint64Var(&c.BaselineMinObsTimeBased, "baseline-min-obs-time", 5, "min observations for time-based promotion (0 disables); promotes edge after baseline-min-age even if obs < baseline-min-obs")
	flag.DurationVar(&c.BaselineMinAge, "baseline-min-age", 7*24*time.Hour, "min edge age for time-based promotion (e.g. 168h for weekly jobs)")
	flag.Float64Var(&c.BaselineDeviationThreshold, "baseline-threshold", 5.0, "MAD multiplier that triggers an edge baseline deviation signal")
	flag.Float64Var(&c.BaselineMinUpdatePPS, "baseline-min-update-pps", 0, "skip EWMA update when pps below this (filters idle keepalive ticks; 0=disabled)")
	flag.Float64Var(&c.BaselineMinUpdateBPS, "baseline-min-update-bps", 0, "skip EWMA update when bps below this (0=disabled)")
	flag.Float64Var(&c.BaselinePeakTolerance, "baseline-peak-tolerance", 1.5, "factor above learned peak that triggers a signal (1.5 = 50% above max)")
	flag.DurationVar(&c.BaselinePeakDecayHalfLife, "baseline-peak-decay-half-life", 0, "half-life for peak decay (e.g. 336h = 14d); 0 disables decay (running max, original behaviour)")

	flag.Parse()
	return c
}

// applyProfileDefaults fills zero-valued cfg fields from the profile.
func applyProfileDefaults(c *cfg, p profile) {
	if c.TrigPPS == 0 {
		c.TrigPPS = p.TrigPPS
	}
	if c.TrigSyn == 0 {
		c.TrigSyn = p.TrigSyn
	}
	if c.TrigScan == 0 {
		c.TrigScan = p.TrigScan
	}
	if c.TrigBPS == 0 {
		c.TrigBPS = p.TrigBPS
	}
	if c.WPPS == 0 {
		c.WPPS = p.WPPS
	}
	if c.WSyn == 0 {
		c.WSyn = p.WSyn
	}
	if c.WScan == 0 {
		c.WScan = p.WScan
	}
	if c.WBps == 0 {
		c.WBps = p.WBps
	}
	if c.SevCap == 0 {
		c.SevCap = p.SevCap
	}
	if c.SoftAt == 0 {
		c.SoftAt = p.SoftAt
	}
	if c.HardAt == 0 {
		c.HardAt = p.HardAt
	}
	if c.BlockAt == 0 {
		c.BlockAt = p.BlockAt
	}
	// TTLs: from policy rules (set before applyProfileDefaults) or profile defaults.
	if c.SoftTTL == 0 {
		c.SoftTTL = p.SoftTTL
	}
	if c.HardTTL == 0 {
		c.HardTTL = p.HardTTL
	}
	if c.BlockTTL == 0 {
		c.BlockTTL = p.BlockTTL
	}
	// Cooldown is populated from the adapter manifest in kliq.go after this call.
	if math.IsNaN(c.BlockMinSev) {
		c.BlockMinSev = p.BlockMinSev
	}
	if c.BlockMinDur < 0 {
		c.BlockMinDur = p.BlockMinDur
	}
	if c.UpNeed == 0 {
		c.UpNeed = p.UpNeed
	}
	if c.DownNeed == 0 {
		c.DownNeed = p.DownNeed
	}
	if c.MinHoldSoft == 0 {
		c.MinHoldSoft = p.MinHoldSoft
	}
	if c.MinHoldHard == 0 {
		c.MinHoldHard = p.MinHoldHard
	}
	if c.NonCompAt == 0 {
		c.NonCompAt = p.NonCompAt
	}
	if c.NonCompDrop == 0 {
		c.NonCompDrop = p.NonCompDrop
	}
	if c.NonCompSev == 0 {
		c.NonCompSev = p.NonCompSev
	}
	if c.NonCompResetBelow == 0 {
		c.NonCompResetBelow = p.NonCompReset
	}
}
