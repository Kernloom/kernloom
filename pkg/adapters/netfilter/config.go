// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package netfilter implements a Kernloom PEP adapter for Linux Netfilter.
// It supports iptables-legacy, iptables-nft and nftables as interchangeable
// backends under a single adapter identity: kernloom.netfilter.
//
// This adapter is a compatibility/legacy PEP for systems where klshield/XDP
// is unavailable (older kernels, NAS appliances). It is NOT a replacement
// for klshield — telemetry fidelity and enforcement performance are lower.
//
// Architecture:
//
//	KLIQ / Forge Policy Pack
//	        │
//	        ▼
//	kernloom.netfilter adapter  (this package)
//	        │
//	        ├── iptables backend  (pkg/adapters/netfilter/backends/iptables)
//	        └── nftables backend  (pkg/adapters/netfilter/backends/nftables)
package netfilter

import "time"

// BackendType identifies which Netfilter backend is in use.
type BackendType string

const (
	BackendAuto           BackendType = "auto"
	BackendNFTables       BackendType = "nftables"
	BackendIPTablesNFT    BackendType = "iptables-nft"
	BackendIPTablesLegacy BackendType = "iptables-legacy"
)

// Mode controls enforcement behaviour.
type Mode string

const (
	ModeObserve Mode = "observe" // counters/conntrack only, no rule changes
	ModeEnforce Mode = "enforce" // apply deny/allow/rate-limit rules
	ModeDryRun  Mode = "dry-run" // log planned operations, never apply
)

// Config is the runtime configuration for the netfilter adapter.
// It maps to the YAML structure loaded from the RuntimeBundle or PDPConfig.
type Config struct {
	// Mode controls whether rules are actually applied.
	// Default: dry-run (safe for first boot).
	Mode Mode `yaml:"mode"`

	// Backend selects the Netfilter implementation.
	// "auto" probes at startup and picks the best available backend.
	Backend BackendType `yaml:"backend"`

	Ownership   OwnershipConfig   `yaml:"ownership"`
	Directions  DirectionsConfig  `yaml:"directions"`
	Selectors   SelectorsConfig   `yaml:"selectors"`
	Enforcement EnforcementConfig `yaml:"enforcement"`
	Observation ObservationConfig `yaml:"observation"`
	Safety      SafetyConfig      `yaml:"safety"`
}

// OwnershipConfig defines the naming prefix for all Kernloom-owned objects.
// The adapter only modifies objects with these prefixes — never foreign rules.
type OwnershipConfig struct {
	// TableName is the nftables table name (nftables backend only).
	// Default: "kernloom"
	TableName string `yaml:"table_name"`

	// ChainPrefix is prepended to all iptables chain names.
	// Default: "KERNLOOM"
	ChainPrefix string `yaml:"chain_prefix"`

	// CommentPrefix is prepended to all rule comments for identification.
	// Default: "kernloom"
	CommentPrefix string `yaml:"comment_prefix"`

	// CleanupOnExit removes all Kernloom rules when the adapter stops.
	// Default: false (rules persist across KLIQ restarts for safety).
	CleanupOnExit bool `yaml:"cleanup_on_exit"`
}

// DirectionsConfig controls which Netfilter hooks are used.
type DirectionsConfig struct {
	Input   bool `yaml:"input"`
	Forward bool `yaml:"forward"`
	Output  bool `yaml:"output"`
}

// SelectorsConfig limits which interfaces the adapter manages.
type SelectorsConfig struct {
	Interfaces InterfaceSelector `yaml:"interfaces"`
}

// InterfaceSelector includes/excludes interfaces from enforcement.
type InterfaceSelector struct {
	Include []string `yaml:"include"` // empty = all interfaces
	Exclude []string `yaml:"exclude"` // default: [lo]
}

// EnforcementConfig controls enforcement behaviour and limits.
type EnforcementConfig struct {
	// DefaultPolicy is the action when no Kernloom rule matches.
	// Must be "pass" — Kernloom never changes the host default policy.
	DefaultPolicy string `yaml:"default_policy"`

	// PreferSets uses ipset/nft sets for deny/allow lists instead of
	// individual rules. Strongly recommended for more than ~10 entries.
	PreferSets bool `yaml:"prefer_sets"`

	EnableAllowlist bool `yaml:"enable_allowlist"`
	EnableDenylist  bool `yaml:"enable_denylist"`
	EnableRateLimit bool `yaml:"enable_rate_limit"`

	// MaxDynamicEntries caps the size of ipset/nft sets.
	MaxDynamicEntries int `yaml:"max_dynamic_entries"`

	// MaxRulesWithoutSet is the upper limit of individual rules when sets
	// are unavailable. Requests beyond this limit are refused.
	MaxRulesWithoutSet int `yaml:"max_rules_without_set"`

	MinTTL time.Duration `yaml:"min_ttl"`
	MaxTTL time.Duration `yaml:"max_ttl"`

	// RateLimitFallback controls what happens when rate-limit primitives
	// (hashlimit / nft meters) are not available on the host.
	RateLimitFallback RateLimitFallbackConfig `yaml:"rate_limit_fallback"`
}

// RateLimitFallbackConfig defines behaviour when rate-limit is unsupported.
type RateLimitFallbackConfig struct {
	// WhenUnsupported: "observe_only" | "block_if_high_severity" | "disabled"
	WhenUnsupported  string        `yaml:"when_unsupported"`
	BlockMinSeverity float64       `yaml:"block_min_severity"`
	BlockMinDuration time.Duration `yaml:"block_min_duration"`
}

// ObservationConfig controls telemetry collection.
type ObservationConfig struct {
	Enabled bool `yaml:"enabled"`

	// Counters reads rule/set hit counters each poll cycle.
	Counters bool `yaml:"counters"`

	// ConntrackSnapshot periodically lists all flows for GraphLearner.
	ConntrackSnapshot bool `yaml:"conntrack_snapshot"`

	// ConntrackEvents listens for NEW/DESTROY conntrack events (higher overhead).
	ConntrackEvents bool `yaml:"conntrack_events"`

	ConntrackPollInterval time.Duration `yaml:"conntrack_poll_interval"`

	// EnableConntrackAccountingIfDisabled controls whether the adapter may
	// enable nf_conntrack_acct. Default false — only report, never silently change.
	EnableConntrackAccountingIfDisabled bool `yaml:"enable_conntrack_accounting_if_disabled"`

	MaxObservationsPerTick int `yaml:"max_observations_per_tick"`
}

// SafetyConfig controls lockout-prevention and failure behaviour.
type SafetyConfig struct {
	// FailClosed drops all traffic if the adapter enters a fatal error state.
	// Default: false — fail open (pass) is safer for unexpected failures.
	FailClosed bool `yaml:"fail_closed"`

	// RestoreBackupOnError reverts to the pre-apply state if iptables-restore
	// or nft -f returns an error.
	RestoreBackupOnError bool `yaml:"restore_backup_on_error"`

	// ManagementAllowlist are CIDRs that must never be blocked, regardless of
	// policy. Applied before all Kernloom deny rules.
	ManagementAllowlist []string `yaml:"management_allowlist"`
}

// DefaultConfig returns safe defaults for the netfilter adapter.
// All defaults are conservative: dry-run, input only, loopback excluded.
func DefaultConfig() Config {
	return Config{
		Mode:    ModeDryRun,
		Backend: BackendAuto,
		Ownership: OwnershipConfig{
			TableName:     "kernloom",
			ChainPrefix:   "KERNLOOM",
			CommentPrefix: "kernloom",
			CleanupOnExit: false,
		},
		Directions: DirectionsConfig{
			Input:   true,
			Forward: false,
			Output:  false,
		},
		Selectors: SelectorsConfig{
			Interfaces: InterfaceSelector{
				Exclude: []string{"lo"},
			},
		},
		Enforcement: EnforcementConfig{
			DefaultPolicy:      "pass",
			PreferSets:         true,
			EnableAllowlist:    true,
			EnableDenylist:     true,
			EnableRateLimit:    true,
			MaxDynamicEntries:  50000,
			MaxRulesWithoutSet: 500,
			MinTTL:             30 * time.Second,
			MaxTTL:             24 * time.Hour,
			RateLimitFallback: RateLimitFallbackConfig{
				WhenUnsupported:  "observe_only",
				BlockMinSeverity: 0.95,
				BlockMinDuration: 5 * time.Minute,
			},
		},
		Observation: ObservationConfig{
			Enabled:                true,
			Counters:               true,
			ConntrackSnapshot:      true,
			ConntrackEvents:        false,
			ConntrackPollInterval:  5 * time.Second,
			MaxObservationsPerTick: 10000,
		},
		Safety: SafetyConfig{
			FailClosed:           false,
			RestoreBackupOnError: true,
		},
	}
}
