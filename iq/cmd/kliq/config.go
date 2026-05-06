// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"flag"
	"math"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/adapters/shieldpep"
	"github.com/adrianenderlin/kernloom/pkg/core/fsm"
)

/* ---------------- CLI configuration ---------------- */

type cfg struct {
	// General
	Interval time.Duration
	TopN     int
	MinPPS   float64
	MinSev   float64

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
	WPPS     float64
	WSyn     float64
	WScan    float64
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

	// Enforcement actions
	SoftRate  uint64
	SoftBurst uint64
	SoftTTL   time.Duration
	HardRate  uint64
	HardBurst uint64
	HardTTL   time.Duration
	BlockTTL  time.Duration
	Cooldown  time.Duration

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
}

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

// toPEPParams converts the relevant cfg fields to shieldpep.EnforcementParams.
func (c cfg) toPEPParams() shieldpep.EnforcementParams {
	return shieldpep.EnforcementParams{
		SoftRate:  c.SoftRate,
		SoftBurst: c.SoftBurst,
		SoftTTL:   c.SoftTTL,
		HardRate:  c.HardRate,
		HardBurst: c.HardBurst,
		HardTTL:   c.HardTTL,
		BlockTTL:  c.BlockTTL,
		Cooldown:  c.Cooldown,
	}
}

func parseFlags() cfg {
	var c cfg

	flag.DurationVar(&c.Interval, "interval", 1*time.Second, "poll interval")
	flag.IntVar(&c.TopN, "top", 200, "top N sources by severity")
	flag.Float64Var(&c.MinPPS, "min-pps", 10, "ignore sources below this PPS")
	flag.Float64Var(&c.MinSev, "min-sev", 0.0, "include candidates with severity >= min-sev")

	flag.StringVar(&c.ProfileName, "profile", "controller", "initial profile name (aliases apply)")
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

	flag.BoolVar(&c.AutoTune, "autotune", true, "enable autotune of trig-* using median+MAD")
	flag.DurationVar(&c.AutoEvery, "autotune-every", 24*time.Hour, "how often to write new trig-* state")
	flag.IntVar(&c.AutoMinSamples, "autotune-min-samples", 5000, "minimum samples per feature before tuning")
	flag.Float64Var(&c.AutoK, "autotune-k", 3.5, "k for trig = median + k*mad (k=3.5 ~ p99)")
	flag.Float64Var(&c.AutoMaxChange, "autotune-max-change", 0.05, "max relative change per update (e.g. 0.05 => ±5%)")
	flag.Float64Var(&c.AutoMaxUp, "autotune-max-change-up", 0, "max relative increase per update (0 => use autotune-max-change)")
	flag.Float64Var(&c.AutoMaxDown, "autotune-max-change-down", 0, "max relative decrease per update (0 => use autotune-max-change)")
	flag.Float64Var(&c.AutoAlpha, "autotune-alpha", 0.2, "smoothing alpha (0 disables)")
	flag.Float64Var(&c.AutoFloorPPS, "autotune-floor-pps", 100, "minimum trig-pps")
	flag.Float64Var(&c.AutoFloorSyn, "autotune-floor-syn", 50, "minimum trig-syn")
	flag.Float64Var(&c.AutoFloorScan, "autotune-floor-scan", 20, "minimum trig-scan")

	flag.Float64Var(&c.LearnSevGT, "learn-sev-gt", 1.0, "tick is 'dirty' if sev>=learn-sev-gt fraction is too high")
	flag.Float64Var(&c.LearnFracGT, "learn-frac-gt", 0.005, "max fraction of sources with sev>=learn-sev-gt to consider tick 'clean'")
	flag.Float64Var(&c.LearnMaxSev, "learn-max-sev", 0.8, "only add samples from sources with severity <= this")
	flag.BoolVar(&c.LearnSkipIfBlocks, "learn-skip-if-blocks", true, "if any IP is in BLOCK, skip learning for this tick")
	flag.Float64Var(&c.LearnMaxDropRatio, "learn-max-drop-ratio", 0.02, "skip learning if total_drop/(total_pass+total_drop) exceeds this (0 disables)")

	flag.Float64Var(&c.TrigPPS, "trig-pps", 0, "PPS trigger threshold (0 => from profile/state)")
	flag.Float64Var(&c.TrigSyn, "trig-syn", 0, "SYN/s trigger threshold (0 => from profile/state)")
	flag.Float64Var(&c.TrigScan, "trig-scan", 0, "scan/s trigger threshold (0 => from profile/state)")
	flag.Float64Var(&c.WPPS, "w-pps", 0, "weight for PPS (0 => from profile)")
	flag.Float64Var(&c.WSyn, "w-syn", 0, "weight for SYN/s (0 => from profile)")
	flag.Float64Var(&c.WScan, "w-scan", 0, "weight for scan/s (0 => from profile)")
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

	flag.Uint64Var(&c.SoftRate, "soft-rate", 0, "soft rate limit pps (0 => from profile)")
	flag.Uint64Var(&c.SoftBurst, "soft-burst", 0, "soft burst tokens (0 => from profile)")
	flag.DurationVar(&c.SoftTTL, "soft-ttl", 0, "soft TTL (0 => from profile)")
	flag.Uint64Var(&c.HardRate, "hard-rate", 0, "hard rate limit pps (0 => from profile)")
	flag.Uint64Var(&c.HardBurst, "hard-burst", 0, "hard burst tokens (0 => from profile)")
	flag.DurationVar(&c.HardTTL, "hard-ttl", 0, "hard TTL (0 => from profile)")
	flag.DurationVar(&c.BlockTTL, "block-ttl", 0, "block TTL (0 => from profile)")
	flag.DurationVar(&c.Cooldown, "cooldown", 0, "min time between level changes (0 => from profile)")

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

	flag.BoolVar(&c.GraphEnabled, "graph", false, "enable graph learning")
	// Runtime state — SQLite DB updated every tick, not under IMA.
	flag.StringVar(&c.GraphStorePath, "graph-store", "/var/lib/kernloom/iq/graph.db", "graph SQLite database (runtime, not IMA-attested)")
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
	if c.WPPS == 0 {
		c.WPPS = p.WPPS
	}
	if c.WSyn == 0 {
		c.WSyn = p.WSyn
	}
	if c.WScan == 0 {
		c.WScan = p.WScan
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
	if c.SoftRate == 0 {
		c.SoftRate = p.SoftRate
	}
	if c.SoftBurst == 0 {
		c.SoftBurst = p.SoftBurst
	}
	if c.SoftTTL == 0 {
		c.SoftTTL = p.SoftTTL
	}
	if c.HardRate == 0 {
		c.HardRate = p.HardRate
	}
	if c.HardBurst == 0 {
		c.HardBurst = p.HardBurst
	}
	if c.HardTTL == 0 {
		c.HardTTL = p.HardTTL
	}
	if c.BlockTTL == 0 {
		c.BlockTTL = p.BlockTTL
	}
	if c.Cooldown == 0 {
		c.Cooldown = p.Cooldown
	}
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
