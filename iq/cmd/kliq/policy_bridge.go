// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import "github.com/adrianenderlin/kernloom/pkg/core/policy"

// policyPackToProfile converts the Heuristics section of a PolicyPack into the
// internal profile struct. Only PDP-internal parameters live here (signal
// thresholds, FSM escalation, anti-flap, block gate, non-compliance). PEP-specific
// parameters (rate_pps, burst, cooldown) come from the adapter manifest.
func policyPackToProfile(pp *policy.PolicyPack) profile {
	h := pp.Spec.Heuristics
	prog := h.Progressive
	nc := h.NonCompliance
	return profile{
		Name:         pp.Metadata.Name,
		TrigPPS:      h.PPSTrigger,
		TrigSyn:      h.SynTrigger,
		TrigScan:     h.ScanTrigger,
		WPPS:         h.Weights.PPS,
		WSyn:         h.Weights.Syn,
		WScan:        h.Weights.Scan,
		SevCap:       h.Weights.Cap,
		SoftAt:       prog.SoftAt,
		HardAt:       prog.HardAt,
		BlockAt:      prog.BlockAt,
		BlockMinSev:  prog.BlockMinSev,
		BlockMinDur:  prog.BlockMinDur.D,
		UpNeed:       prog.UpNeed,
		DownNeed:     prog.DownNeed,
		MinHoldSoft:  prog.MinHoldSoft.D,
		MinHoldHard:  prog.MinHoldHard.D,
		NonCompAt:    nc.At,
		NonCompDrop:  nc.Drop,
		NonCompSev:   nc.Sev,
		NonCompReset: nc.Reset,
	}
}

// rulesFromPolicyPack extracts enforcement TTLs and action types from the
// Rules section and writes them into cfg. The PEP-specific rate/burst values
// are NOT here — those come from the adapter manifest.
func rulesFromPolicyPack(pp *policy.PolicyPack, c *cfg) {
	for _, rule := range pp.Spec.Rules {
		switch rule.When.FsmLevel {
		case "soft":
			if rule.Then.TTL.D > 0 {
				c.SoftTTL = rule.Then.TTL.D
			}
		case "hard":
			if rule.Then.TTL.D > 0 {
				c.HardTTL = rule.Then.TTL.D
			}
		case "block":
			if rule.Then.TTL.D > 0 {
				c.BlockTTL = rule.Then.TTL.D
			}
		}
		if rule.When.Signal == "graph.new_edge_after_freeze" {
			if rule.Then.TTL.D > 0 {
				c.GraphFreezeTTL = rule.Then.TTL.D
			}
			if rule.Then.Action != "" {
				c.GraphFreezeAction = rule.Then.Action
			}
		}
	}
}

// applyPolicyPackToCfg writes all policy-controlled fields from a PolicyPack
// into cfg: autonomy gates and graph learning/freeze configuration.
// Called before applyProfileDefaults so that explicit CLI flag overrides
// still win for any field left at its zero value after both calls.
func applyPolicyPackToCfg(pp *policy.PolicyPack, c *cfg) {
	s := pp.Spec

	// --- Autonomy ---
	c.DryRun = s.Autonomy.DryRun
	if s.Autonomy.MaxAction != "" {
		c.GraphFreezeMaxAction = s.Autonomy.MaxAction
	}
	c.GraphFreezeAllowBlock = s.Autonomy.AllowLocalBlock

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
