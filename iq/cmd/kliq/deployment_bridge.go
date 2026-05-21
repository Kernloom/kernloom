// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"path/filepath"

	"github.com/kernloom/kernloom/pkg/core/kliqconfig"
)

// applyDeploymentConfig writes KliqDeploymentConfig fields into cfg.
// Only fields that were NOT explicitly set via CLI flags are overridden.
// This mirrors the priority order: explicit CLI flag > deployment config > flag default.
func applyDeploymentConfig(dc *kliqconfig.KliqDeploymentConfig, c *cfg, explicit map[string]bool) {
	s := dc.Spec

	// Node identity and mode.
	if s.Node.ID != "" && !explicit["graph-node-id"] {
		c.GraphNodeID = s.Node.ID
	}
	if s.Node.Mode != "" && !explicit["mode"] {
		c.Mode = s.Node.Mode
	}

	// Forge coordinates (stored for future enrollment; not used until forge serve).
	if s.Forge.URL != "" {
		c.ForgeURL = s.Forge.URL
	}

	// Runtime: dry_run — pointer distinguishes explicit-false from absent.
	if s.Runtime.DryRun != nil && !explicit["dry-run"] {
		c.DryRun = *s.Runtime.DryRun
	}

	// Runtime: bpffs root.
	if s.Runtime.BPFfsRoot != "" && !explicit["bpffs-root"] {
		c.BPFfsRoot = s.Runtime.BPFfsRoot
	}

	// Runtime: derive state and feedback paths from state_dir when not explicit.
	if s.Runtime.StateDir != "" {
		if !explicit["state-file"] {
			c.StatePath = filepath.Join(s.Runtime.StateDir, "state.json")
		}
		if !explicit["feedback-file"] {
			c.FeedbackPath = filepath.Join(s.Runtime.StateDir, "feedback.json")
		}
	}

	// Runtime: IMA-attested whitelist.
	if s.Runtime.WhitelistPath != "" && !explicit["whitelist"] {
		c.WhitelistPath = s.Runtime.WhitelistPath
	}

	// Runtime: policy and PDP config files.
	if s.Runtime.PolicyFile != "" && !explicit["policy-file"] {
		c.PolicyFile = s.Runtime.PolicyFile
	}
	if s.Runtime.PDPConfigFile != "" && !explicit["pdp-config"] {
		c.PDPConfig = s.Runtime.PDPConfigFile
	}

	// Fail mode (stored; behaviour not yet wired).
	if s.Runtime.FailMode != "" {
		c.FailMode = s.Runtime.FailMode
	}
}
