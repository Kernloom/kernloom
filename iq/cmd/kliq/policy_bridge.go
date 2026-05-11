// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"github.com/adrianenderlin/kernloom/pkg/adapters/shieldpep"
	"github.com/adrianenderlin/kernloom/pkg/core/pdp"
	"github.com/adrianenderlin/kernloom/pkg/core/policy"
)

// pdpConfigToProfile converts a PDPConfig into the internal profile struct.
func pdpConfigToProfile(c *pdp.Config) profile {
	s := c.Spec
	pe := s.ProgressiveEnforcement
	return profile{
		Name:         c.Metadata.Name,
		TrigPPS:      s.SignalEngine.PPSTrigger,
		TrigSyn:      s.SignalEngine.SynTrigger,
		TrigScan:     s.SignalEngine.ScanTrigger,
		TrigBPS:      s.SignalEngine.BPSTrigger,
		WPPS:         s.SignalEngine.Weights.PPS,
		WSyn:         s.SignalEngine.Weights.Syn,
		WScan:        s.SignalEngine.Weights.Scan,
		WBps:         s.SignalEngine.Weights.BPS,
		SevCap:       s.SignalEngine.Weights.Cap,
		SoftAt:       pe.SoftAt,
		HardAt:       pe.HardAt,
		BlockAt:      pe.BlockAt,
		BlockMinSev:  pe.BlockMinSev,
		BlockMinDur:  pe.BlockMinDur.D,
		UpNeed:       pe.UpNeed,
		DownNeed:     pe.DownNeed,
		MinHoldSoft:  pe.MinHoldSoft.D,
		MinHoldHard:  pe.MinHoldHard.D,
		NonCompAt:    s.NonCompliance.At,
		NonCompDrop:  s.NonCompliance.Drop,
		NonCompSev:   s.NonCompliance.Sev,
		NonCompReset: s.NonCompliance.Reset,
	}
}

// adapterParamsFromPDPConfig extracts Shield PEP adapter parameters from the
// PDPConfig. Returns defaults for any field that is zero (not configured).
func adapterParamsFromPDPConfig(c *pdp.Config) shieldpep.CapabilityParams {
	p := shieldpep.DefaultCapabilityParams()
	a := c.Spec.Adapters.ShieldPEP
	if a.SoftRatePPS > 0 {
		p.SoftRatePPS = a.SoftRatePPS
	}
	if a.SoftBurst > 0 {
		p.SoftBurst = a.SoftBurst
	}
	if a.HardRatePPS > 0 {
		p.HardRatePPS = a.HardRatePPS
	}
	if a.HardBurst > 0 {
		p.HardBurst = a.HardBurst
	}
	if a.Cooldown.D > 0 {
		p.Cooldown = a.Cooldown.D
	}
	return p
}

// rulesFromPolicyPack extracts enforcement TTLs and action types from the
// Rules section and writes them into cfg. PEP-specific rate/burst values
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

// applyPolicyPackToCfg writes policy-controlled fields from a PolicyPack into
// cfg. Only autonomy gates live here — graph config moved to PDPConfig.
func applyPolicyPackToCfg(pp *policy.PolicyPack, c *cfg) {
	s := pp.Spec
	c.DryRun = s.Autonomy.DryRun
	if s.Autonomy.MaxAction != "" {
		c.GraphFreezeMaxAction = s.Autonomy.MaxAction
	}
	c.GraphFreezeAllowBlock = s.Autonomy.AllowLocalBlock
}

// applyPDPBaselineToCfg writes baseline engine configuration from a PDPConfig.
func applyPDPBaselineToCfg(dc *pdp.Config, c *cfg) {
	b := dc.Spec.Baseline
	// BaselineEnabled removed — baseline is always active when graph is enabled.
	if b.MinObservations > 0 {
		c.BaselineMinObservations = b.MinObservations
	}
	if b.Alpha > 0 {
		c.BaselineAlpha = b.Alpha
	}
	if b.AlphaBootstrap > 0 {
		c.BaselineAlphaBootstrap = b.AlphaBootstrap
	}
	if b.DeviationThreshold > 0 {
		c.BaselineDeviationThreshold = b.DeviationThreshold
	}
}

// applyPDPGraphToCfg writes graph learning and freeze configuration from a
// PDPConfig into cfg. Separated from pdpConfigToProfile because graph params
// are operational config, not profile (signal engine / FSM) behavior.
func applyPDPGraphToCfg(dc *pdp.Config, c *cfg) {
	g := dc.Spec.Graph
	if g.Enabled {
		c.GraphEnabled = true
	}
	if g.Mode != "" {
		c.GraphMode = g.Mode
	}
	if g.Store != "" {
		c.GraphStorePath = g.Store
	}
	if g.Promotion.MinSeenCount > 0 {
		c.GraphMinSeenCount = uint64(g.Promotion.MinSeenCount)
	}
	if g.Promotion.MinWindows > 0 {
		c.GraphMinWindows = g.Promotion.MinWindows
	}
	if g.Promotion.MinAge.D > 0 {
		c.GraphMinAge = g.Promotion.MinAge.D
	}
	if g.Promotion.ExpireTTL.D > 0 {
		c.GraphExpireTTL = g.Promotion.ExpireTTL.D
	}
	if g.Freeze.MaxAction != "" {
		c.GraphFreezeMaxAction = g.Freeze.MaxAction
	}
	c.GraphFreezeAllowBlock = g.Freeze.AllowBlock
	if g.Freeze.MinSeverityForBlock > 0 {
		c.GraphFreezeMinSeverity = g.Freeze.MinSeverityForBlock
	}
	if len(g.Exclude.SourceCIDRs) > 0 {
		joined := ""
		for i, cidr := range g.Exclude.SourceCIDRs {
			if i > 0 {
				joined += ","
			}
			joined += cidr
		}
		c.GraphExcludeSourceCIDR = joined
	}
	if g.Exclude.Broadcast {
		c.GraphExcludeBcast = true
	}
	if g.Exclude.Loopback {
		c.GraphExcludeLoopback = true
	}
}
