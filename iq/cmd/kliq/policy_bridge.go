// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import "github.com/adrianenderlin/kernloom/pkg/core/policy"

// policyPackToProfile converts a PolicyPack loaded from a YAML file into the
// internal profile struct. The profile type lives in the main package so this
// conversion cannot be a method on PolicyPack itself.
func policyPackToProfile(pp *policy.PolicyPack) profile {
	s := pp.Spec
	return profile{
		Name:         pp.Metadata.Name,
		TrigPPS:      s.Heuristic.TrigPPS,
		TrigSyn:      s.Heuristic.TrigSyn,
		TrigScan:     s.Heuristic.TrigScan,
		WPPS:         s.Heuristic.WPPS,
		WSyn:         s.Heuristic.WSyn,
		WScan:        s.Heuristic.WScan,
		SevCap:       s.Heuristic.SevCap,
		SoftAt:       s.FSM.SoftAt,
		HardAt:       s.FSM.HardAt,
		BlockAt:      s.FSM.BlockAt,
		SoftRate:     s.Enforcement.SoftRate,
		SoftBurst:    s.Enforcement.SoftBurst,
		SoftTTL:      s.Enforcement.SoftTTL.D,
		HardRate:     s.Enforcement.HardRate,
		HardBurst:    s.Enforcement.HardBurst,
		HardTTL:      s.Enforcement.HardTTL.D,
		BlockTTL:     s.Enforcement.BlockTTL.D,
		Cooldown:     s.Enforcement.Cooldown.D,
		BlockMinSev:  s.BlockGate.MinSeverity,
		BlockMinDur:  s.BlockGate.MinDuration.D,
		UpNeed:       s.AntiFlap.UpNeed,
		DownNeed:     s.AntiFlap.DownNeed,
		MinHoldSoft:  s.AntiFlap.MinHoldSoft.D,
		MinHoldHard:  s.AntiFlap.MinHoldHard.D,
		NonCompAt:    s.NonCompliance.At,
		NonCompDrop:  s.NonCompliance.Drop,
		NonCompSev:   s.NonCompliance.Sev,
		NonCompReset: s.NonCompliance.Reset,
	}
}

// applyPolicyPackToCfg writes all policy-controlled fields from a PolicyPack
// into cfg. This covers autonomy (dry-run, max-action, block gates) and graph
// learning/freeze configuration. Called before applyProfileDefaults so that
// explicit CLI flag overrides still win for any field left at its zero value.
func applyPolicyPackToCfg(pp *policy.PolicyPack, c *cfg) {
	s := pp.Spec

	// --- Autonomy ---
	c.DryRun = s.Autonomy.DryRun
	if s.Autonomy.MaxAction != "" {
		c.GraphFreezeMaxAction = s.Autonomy.MaxAction
	}
	c.GraphFreezeAllowBlock = s.Autonomy.AllowLocalBlock
	if s.Autonomy.MinSeverityForBlock > 0 {
		c.GraphFreezeMinSeverity = s.Autonomy.MinSeverityForBlock
	}

	// --- Graph ---
	if s.Graph.Enabled {
		c.GraphEnabled = true
	}
	if s.Graph.Mode != "" {
		c.GraphMode = s.Graph.Mode
	}
	if s.Graph.Store != "" {
		c.GraphStorePath = s.Graph.Store
	}
	if s.Graph.Promotion.MinSeenCount > 0 {
		c.GraphMinSeenCount = uint64(s.Graph.Promotion.MinSeenCount)
	}
	if s.Graph.Promotion.MinWindows > 0 {
		c.GraphMinWindows = s.Graph.Promotion.MinWindows
	}
	if s.Graph.Promotion.MinAge.D > 0 {
		c.GraphMinAge = s.Graph.Promotion.MinAge.D
	}
	if s.Graph.Promotion.ExpireTTL.D > 0 {
		c.GraphExpireTTL = s.Graph.Promotion.ExpireTTL.D
	}

	// Graph freeze enforcement
	if s.Graph.Freeze.Action != "" {
		c.GraphFreezeAction = s.Graph.Freeze.Action
	}
	if s.Graph.Freeze.TTL.D > 0 {
		c.GraphFreezeTTL = s.Graph.Freeze.TTL.D
	}
	if s.Graph.Freeze.MaxAction != "" {
		c.GraphFreezeMaxAction = s.Graph.Freeze.MaxAction
	}
	c.GraphFreezeAllowBlock = s.Graph.Freeze.AllowBlock
	if s.Graph.Freeze.MinSeverityForBlock > 0 {
		c.GraphFreezeMinSeverity = s.Graph.Freeze.MinSeverityForBlock
	}

	// Graph exclusions
	if len(s.Graph.Exclude.SourceCIDRs) > 0 {
		// join as comma-separated string to match existing flag format
		joined := ""
		for i, cidr := range s.Graph.Exclude.SourceCIDRs {
			if i > 0 {
				joined += ","
			}
			joined += cidr
		}
		c.GraphExcludeSourceCIDR = joined
	}
	if s.Graph.Exclude.Broadcast {
		c.GraphExcludeBcast = true
	}
	if s.Graph.Exclude.Loopback {
		c.GraphExcludeLoopback = true
	}
}
