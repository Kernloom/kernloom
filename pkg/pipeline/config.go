// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package pipeline provides the generic adapter metric pipeline runner.
// The pipeline is opt-in and disabled by default (metric_pipeline.enabled=false).
// In shadow mode it runs alongside the existing KLShield path without affecting
// any enforcement decision.
//
// Lifecycle:
//
//	disabled → no-op, zero allocations
//	shadow   → read data, produce metrics, learn baselines, emit shadow signals
//	audit    → shadow + dry-run ActionProposals logged but not executed
//	enforce  → production-grade; deferred until a real second adapter exists
package pipeline

import "time"

// Mode controls the pipeline's operational level.
type Mode string

const (
	// ModeDisabled is the default. The pipeline does nothing.
	ModeDisabled Mode = "disabled"

	// ModeShadow reads and learns without affecting enforcement.
	// No real ActionProposals are created.
	ModeShadow Mode = "shadow"

	// ModeAudit extends shadow with dry-run ActionProposal logging.
	// Proposals are passed through the ActionResolver in dry-run mode only.
	ModeAudit Mode = "audit"

	// ModeEnforce enables real ActionProposals through the ActionResolver.
	// Not used until a real second adapter (e.g. NGINX) is proven.
	ModeEnforce Mode = "enforce"
)

// Config is the pipeline runner configuration.
// Corresponds to the metric_pipeline section in KliqComponentConfig.
type Config struct {
	// Enabled gates the entire pipeline. Default: false.
	Enabled bool

	// Mode controls the operational level. Default: shadow.
	Mode Mode

	// Window is the evaluation window for feature extraction. Default: 10s.
	Window time.Duration

	// ActionProposals controls whether proposals are generated.
	ActionProposals ActionProposalConfig
}

// ActionProposalConfig controls dry-run action proposal generation.
type ActionProposalConfig struct {
	// Enabled enables proposal generation. Default: false.
	// Only used in audit and enforce modes.
	Enabled bool

	// DryRun means proposals are logged but not executed. Default: true.
	DryRun bool
}

// DefaultConfig returns a disabled-by-default pipeline config.
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		Mode:    ModeShadow,
		Window:  10 * time.Second,
		ActionProposals: ActionProposalConfig{
			Enabled: false,
			DryRun:  true,
		},
	}
}

// IsActive returns true when the pipeline should actually run.
func (c Config) IsActive() bool {
	return c.Enabled && c.Mode != ModeDisabled
}
