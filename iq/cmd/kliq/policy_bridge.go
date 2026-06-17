// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"strconv"

	"github.com/kernloom/kernloom/pkg/adapters/klshield/pep"
	celeval "github.com/kernloom/kernloom/pkg/core/cel"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/pdp"
	"github.com/kernloom/kernloom/pkg/core/policy"
)

// forgeCapabilityToKLIQ maps Forge vocabulary capability IDs to KLIQ's internal
// abstract capability IDs (used in the well-known capability registry).
//
// This is the initial PluginTranslationCatalog for the KLShield adapter.
// It bridges the Forge standard vocabulary and KLIQ's existing capability naming
// until a shared SDK or full Plugin Adapter framework is in place.
//
// Forge vocabulary:       KLIQ internal:
//
//	enforce.traffic.rate_limit  →  network.rate_limit_source
//	enforce.access.deny         →  network.block_source
//	enforce.access.allow        →  network.allow_source
var forgeCapabilityToKLIQ = map[string]string{
	// Generic access control
	"enforce.access.deny":         "network.block_source",
	"enforce.access.allow":        "network.allow_source",
	"enforce.access.default_deny": "network.enforce_allowlist",

	// Generic traffic control
	"enforce.traffic.rate_limit":       "network.rate_limit_source",
	"enforce.traffic.connection_limit": "network.rate_limit_source",
	"enforce.traffic.bandwidth_limit":  "network.rate_limit_source",
	"enforce.traffic.drop":             "network.block_source",
	"enforce.traffic.quarantine":       "network.block_source",
	"enforce.traffic.tarpit":           "network.rate_limit_source",

	// Legacy enforce.network.* (Forge maintains these for backward compatibility)
	"enforce.network.deny":         "network.block_source",
	"enforce.network.rate_limit":   "network.rate_limit_source",
	"enforce.network.default_deny": "network.enforce_allowlist",
	"enforce.network.quarantine":   "network.block_source",
	"enforce.network.syn_protect":  "network.rate_limit_source",
}

// normalizeCapabilityID converts a Forge capability ID to KLIQ's internal
// capability ID. Returns the input unchanged if it is already a KLIQ ID or
// is unknown (forward-compatibility: unknown IDs pass through for logging).
func normalizeCapabilityID(id string) string {
	if kliq, ok := forgeCapabilityToKLIQ[id]; ok {
		return kliq
	}
	return id
}

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

// applyPDPAdaptiveRatesToCfg reads the adaptive rate factors from PDPConfig and
// writes them into cfg. Only non-zero values override CLI defaults (0 = disabled).
func applyPDPAdaptiveRatesToCfg(dc *pdp.Config, c *cfg) {
	a := dc.Spec.Adapters.ShieldPEP
	if a.SoftRateFactor > 0 {
		c.SoftRateFactor = a.SoftRateFactor
	}
	if a.HardRateFactor > 0 {
		c.HardRateFactor = a.HardRateFactor
	}
}

// rulesFromPolicyPack extracts enforcement TTLs and capabilities from the Rules
// section and writes them into cfg.
// Supports v1.1 (when.capability) and v1.0 (when.fsm_level) packs.
func rulesFromPolicyPack(pp *policy.PolicyPack, c *cfg) {
	for _, rule := range pp.Spec.Rules {
		// v1.1: derive FSM level from when.capability; fall back to when.fsm_level.
		fsmLevel := rule.When.FsmLevel
		if rule.When.Capability != "" {
			fsmLevel = capabilityToFsmLevel(rule.When.Capability)
		}

		switch fsmLevel {
		case "soft":
			if rule.Then.TTL.D > 0 {
				c.SoftTTL = rule.Then.TTL.D
			}
			if rule.Then.Capability != "" {
				c.SoftCapability = normalizeCapabilityID(rule.Then.Capability)
			}
			if v := parseRatePPS(rule.Then.Params); v > 0 {
				c.SoftDirectiveRatePPS = v
			}
		case "hard":
			if rule.Then.TTL.D > 0 {
				c.HardTTL = rule.Then.TTL.D
			}
			if rule.Then.Capability != "" {
				c.HardCapability = normalizeCapabilityID(rule.Then.Capability)
			}
			if v := parseRatePPS(rule.Then.Params); v > 0 {
				c.HardDirectiveRatePPS = v
			}
		case "block":
			if rule.Then.TTL.D > 0 {
				c.BlockTTL = rule.Then.TTL.D
			}
			if rule.Then.Capability != "" {
				c.BlockCapability = normalizeCapabilityID(rule.Then.Capability)
			}
		}

		if rule.When.Signal == "graph.new_edge_after_freeze" {
			if rule.Then.TTL.D > 0 {
				c.GraphFreezeTTL = rule.Then.TTL.D
			}
			// v1.0 compat: then.action carried the graph-freeze action string.
			if rule.Then.Action != "" {
				c.GraphFreezeAction = rule.Then.Action
			}
		}
	}

	// Compile v1.2 CEL rules. These are evaluated per-source-IP on every tick
	// independently of the FSM-level rules above.
	c.CELRules = nil
	for i, rule := range pp.Spec.Rules {
		if rule.When.Language != "cel" || rule.When.Expression == "" {
			continue
		}
		level := capabilityToFsmLevel(rule.Then.Capability)
		compiled, err := celeval.Compile(
			rule.Name,
			rule.Then.Capability,
			level,
			rule.Then.TTL.D.String(),
			rule.Then.Params,
			rule.When,
		)
		if err != nil {
			kliqLog.Printf("WARNING: pack rule[%d] %q CEL compile error: %v — rule skipped", i, rule.Name, err)
			continue
		}
		c.CELRules = append(c.CELRules, compiled)
		kliqLog.Printf("Policy pack: CEL rule %q compiled (capability=%s level=%s)", rule.Name, rule.Then.Capability, level)
	}

	// Log enforcement mode so operators can verify pack intent after all rules are read.
	if len(c.CELRules) > 0 {
		kliqLog.Printf("Policy pack: %d CEL rule(s) active (v1.2 expression-based enforcement)", len(c.CELRules))
	} else if c.SoftDirectiveRatePPS > 0 || c.HardDirectiveRatePPS > 0 {
		kliqLog.Printf("Policy pack: directive mode — soft=%dpps hard=%dpps (access-control, fixed rate from pack)",
			c.SoftDirectiveRatePPS, c.HardDirectiveRatePPS)
	} else {
		kliqLog.Printf("Policy pack: autonomy mode — rates derived from autotune/static config (DoS-protection)")
	}
}

// capEnforcementLevel caps the FSM target level based on the PolicyPack's
// autonomy.max_action ceiling. This allows Forge to prevent KLIQ from
// enforcing more aggressively than the policy authorises.
//
//	""            → no cap (full enforcement, default behaviour)
//	"rate_limit"  → cap at LevelSoft; hard and block become soft
//	"observe"     → no enforcement; all levels become observe
//
// Any other value is treated as no cap (forward-compatible: unknown values
// are ignored rather than preventing enforcement).
func capEnforcementLevel(target fsm.Level, maxAction string) fsm.Level {
	switch maxAction {
	case "observe":
		return fsm.LevelObserve
	case "rate_limit":
		if target > fsm.LevelSoft {
			return fsm.LevelSoft
		}
	}
	return target
}

// applyPolicyPackToCfg writes policy-controlled fields from a PolicyPack into
// cfg. Reads action_authorization (v1.1) first, falls back to autonomy (v1.0).
func applyPolicyPackToCfg(pp *policy.PolicyPack, c *cfg) {
	s := pp.Spec

	// dry_run in the policy pack is deprecated: move to KliqDeploymentConfig.
	if s.Autonomy.DryRun {
		kliqLog.Printf("WARNING: policy pack sets autonomy.dry_run=true — move dry_run to KliqDeploymentConfig; field will be removed in a future pack version")
		c.DryRun = true
	}

	if len(s.ActionAuthorization.AllowedCapabilities) > 0 {
		// ── v1.1 path: action_authorization ──────────────────────────────────
		c.CapabilitiesRequired = make(map[string]bool, len(s.ActionAuthorization.AllowedCapabilities))
		for _, cap := range s.ActionAuthorization.AllowedCapabilities {
			c.CapabilitiesRequired[cap] = true
		}
		// Derive enforcement ceiling and block permission from the allowed list.
		c.PolicyMaxAction = deriveMaxAction(s.ActionAuthorization.AllowedCapabilities)
		c.GraphFreezeAllowBlock = isBlockAllowed(s.ActionAuthorization.AllowedCapabilities)
		c.GraphFreezeMaxAction = c.PolicyMaxAction
	} else {
		// ── v1.0 path: autonomy (backward compat) ─────────────────────────────
		if s.Autonomy.MaxAction != "" {
			c.PolicyMaxAction = s.Autonomy.MaxAction
			c.GraphFreezeMaxAction = s.Autonomy.MaxAction
		}
		c.GraphFreezeAllowBlock = s.Autonomy.AllowLocalBlock
		if len(s.CapabilitiesRequired) > 0 {
			c.CapabilitiesRequired = make(map[string]bool, len(s.CapabilitiesRequired))
			for _, cap := range s.CapabilitiesRequired {
				c.CapabilitiesRequired[cap] = true
			}
		}
	}

	c.HasPolicyPack = true
}

// parseRatePPS extracts a "rate_pps" value from a then.params map.
// Returns 0 when absent or unparseable — callers treat 0 as "not set".
func parseRatePPS(params map[string]string) uint64 {
	if params == nil {
		return 0
	}
	s, ok := params["rate_pps"]
	if !ok {
		return 0
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return 0
	}
	return v
}

// capabilitySeverityKLIQ maps Forge capability IDs to enforcement severity.
// 0=observe, 1=soft, 2=hard, 3=block. Mirrors render.go's capabilitySeverity
// so KLIQ can derive ceilings from action_authorization.allowed_capabilities.
var capabilitySeverityKLIQ = map[string]int{
	"enforce.access.allow": 0,

	"enforce.traffic.rate_limit":       1,
	"enforce.traffic.connection_limit": 1,
	"enforce.traffic.bandwidth_limit":  1,
	"enforce.network.rate_limit":       1,
	"enforce.network.syn_protect":      1,

	"enforce.traffic.tarpit": 2,

	"enforce.access.deny":          3,
	"enforce.access.default_deny":  3,
	"enforce.traffic.drop":         3,
	"enforce.traffic.quarantine":   3,
	"enforce.network.deny":         3,
	"enforce.network.default_deny": 3,
	"enforce.network.quarantine":   3,
}

// deriveMaxAction returns the PolicyMaxAction string for the highest-severity
// capability in caps. Used when reading action_authorization.allowed_capabilities.
func deriveMaxAction(caps []string) string {
	maxSev := 0
	for _, cap := range caps {
		if s := capabilitySeverityKLIQ[cap]; s > maxSev {
			maxSev = s
		}
	}
	switch maxSev {
	case 0:
		return "observe"
	case 1:
		return "rate_limit"
	case 2:
		return "rate_limit_hard"
	default:
		return "" // block = no cap
	}
}

// isBlockAllowed returns true when any block-level capability is in caps.
func isBlockAllowed(caps []string) bool {
	for _, cap := range caps {
		if capabilitySeverityKLIQ[cap] >= 3 {
			return true
		}
	}
	return false
}

// capabilityToFsmLevel maps a Forge capability ID to the KLIQ FSM level name
// used in rulesFromPolicyPack. Mirrors capabilitySeverityKLIQ but returns the
// level string the cfg fields expect.
func capabilityToFsmLevel(forgeCapID string) string {
	switch capabilitySeverityKLIQ[forgeCapID] {
	case 3:
		return "block"
	case 2:
		return "hard"
	case 1:
		return "soft"
	default:
		return "observe"
	}
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
	if b.MinObsTimeBased > 0 {
		c.BaselineMinObsTimeBased = b.MinObsTimeBased
	}
	if b.MinAge.D > 0 {
		c.BaselineMinAge = b.MinAge.D
	}
	if b.DeviationThreshold > 0 {
		c.BaselineDeviationThreshold = b.DeviationThreshold
	}
	if b.MinUpdatePPS > 0 {
		c.BaselineMinUpdatePPS = b.MinUpdatePPS
	}
	if b.MinUpdateBPS > 0 {
		c.BaselineMinUpdateBPS = b.MinUpdateBPS
	}
	if b.PeakTolerance > 0 {
		c.BaselinePeakTolerance = b.PeakTolerance
	}
	if b.PeakDecayHalfLife.D > 0 {
		c.BaselinePeakDecayHalfLife = b.PeakDecayHalfLife.D
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

// applyPDPAutotuneToCfg writes autotune and bootstrap configuration from a
// PDPConfig into cfg. Only non-zero values override CLI defaults.
func applyPDPAutotuneToCfg(dc *pdp.Config, c *cfg) {
	a := dc.Spec.Autotune
	if !a.Enabled {
		c.AutoTune = false
	}
	if a.MinSamples > 0 {
		c.AutoMinSamples = a.MinSamples
	}
	if a.Floors.PPS > 0 {
		c.AutoFloorPPS = a.Floors.PPS
	}
	if a.Floors.Syn > 0 {
		c.AutoFloorSyn = a.Floors.Syn
	}
	if a.Floors.Scan > 0 {
		c.AutoFloorScan = a.Floors.Scan
	}
	if a.Floors.BPS > 0 {
		c.AutoFloorBPS = a.Floors.BPS
	}

	b := a.Bootstrap
	if b.Window.D > 0 {
		c.BootstrapWindow = b.Window.D
	}
	if b.KStart > 0 {
		c.BootstrapKStart = b.KStart
	}
	if b.KFinal > 0 {
		c.BootstrapKFinal = b.KFinal
	}
	if b.Phase1End.D > 0 {
		c.BootstrapP1End = b.Phase1End.D
	}
	if b.Phase2End.D > 0 {
		c.BootstrapP2End = b.Phase2End.D
	}
	if b.Phase1.Interval.D > 0 {
		c.BootstrapEvery1 = b.Phase1.Interval.D
	}
	if b.Phase1.MaxUp > 0 {
		c.BootstrapMaxUp1 = b.Phase1.MaxUp
	}
	if b.Phase1.MaxDown > 0 {
		c.BootstrapMaxDown1 = b.Phase1.MaxDown
	}
	if b.Phase1.Alpha > 0 {
		c.BootstrapAlpha1 = b.Phase1.Alpha
	}
	if b.Phase2.Interval.D > 0 {
		c.BootstrapEvery2 = b.Phase2.Interval.D
	}
	if b.Phase2.MaxUp > 0 {
		c.BootstrapMaxUp2 = b.Phase2.MaxUp
	}
	if b.Phase2.MaxDown > 0 {
		c.BootstrapMaxDown2 = b.Phase2.MaxDown
	}
	if b.Phase2.Alpha > 0 {
		c.BootstrapAlpha2 = b.Phase2.Alpha
	}
	if b.Phase3.Interval.D > 0 {
		c.BootstrapEvery3 = b.Phase3.Interval.D
	}
	if b.Phase3.MaxUp > 0 {
		c.BootstrapMaxUp3 = b.Phase3.MaxUp
	}
	if b.Phase3.MaxDown > 0 {
		c.BootstrapMaxDown3 = b.Phase3.MaxDown
	}
	if b.Phase3.Alpha > 0 {
		c.BootstrapAlpha3 = b.Phase3.Alpha
	}
	if b.Steady.Interval.D > 0 {
		c.SteadyEvery = b.Steady.Interval.D
	}
	if b.Steady.MaxUp > 0 {
		c.AutoMaxUp = b.Steady.MaxUp
	}
	if b.Steady.MaxDown > 0 {
		c.AutoMaxDown = b.Steady.MaxDown
	}
	if b.Steady.Alpha > 0 {
		c.AutoAlpha = b.Steady.Alpha
	}
}
