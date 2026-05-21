// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actions

import (
	"fmt"

	"github.com/kernloom/kernloom/pkg/core/fsm"
)

// PolicyResolver is the central enforcement authority in KLIQ.
// It applies Forge policy rules to every ActionProposal before any PEP is touched.
//
// Rules applied in order:
//  1. Standalone mode: all actions pass through (backward compatible).
//  2. Managed mode, no valid policy pack: observe only (fail-safe).
//  3. PolicyMaxAction ceiling: downgrade if proposed action exceeds the pack limit.
//  4. CapabilitiesAllowed: deny if the executable action is not in the pack's allowlist.
type PolicyResolver struct {
	// Mode is "standalone" or "managed".
	Mode string

	// HasPolicyPack is true when a valid LocalPolicyPack is loaded.
	// In managed mode, no pack means observe-only.
	HasPolicyPack bool

	// PolicyMaxAction is the enforcement ceiling from autonomy.max_action.
	// "" or "block" = no cap; "rate_limit" = cap at soft; "observe" = no enforcement.
	PolicyMaxAction string

	// CapabilitiesAllowed is the set of Forge capability IDs that the pack
	// explicitly allows (from capabilities_required). Nil or empty = all allowed.
	// Only enforced in managed mode.
	CapabilitiesAllowed map[string]bool
}

// Resolve evaluates a proposal and returns an authorized (or denied/downgraded) resolution.
// It never mutates any PEP — the executor handles that.
func (r *PolicyResolver) Resolve(p ActionProposal) ActionResolution {
	base := ActionResolution{
		ProposalID:      p.ID,
		RequestedAction: p.DesiredAction,
		RequestedLevel:  p.DesiredLevel,
		Target:          p.Target,
		Parameters:      p.Parameters,
		TTL:             p.TTL,
	}

	// Rule 1: standalone mode — full pass-through (preserves existing behavior).
	if r.Mode != "managed" {
		base.Allowed = true
		base.ExecutableAction = p.DesiredAction
		base.ExecutableLevel = p.DesiredLevel
		return base
	}

	// Rule 2: managed mode without a valid policy pack — observe only.
	if !r.HasPolicyPack {
		base.Allowed = true
		base.ExecutableAction = ""
		base.ExecutableLevel = "observe"
		base.DenyReason = "managed_no_policy_pack"
		return base
	}

	execAction := p.DesiredAction
	execLevel := p.DesiredLevel
	downgradeReason := ""

	// Rule 3: PolicyMaxAction ceiling — downgrade if proposed action exceeds cap.
	switch r.PolicyMaxAction {
	case "observe":
		base.Allowed = true
		base.ExecutableAction = ""
		base.ExecutableLevel = "observe"
		if p.DesiredLevel != "observe" {
			base.DenyReason = "policy_max_action_observe"
		}
		return base

	case "rate_limit":
		// Cap at soft: block and hard both downgrade to soft.
		if execLevel == "block" || execLevel == "hard" {
			execAction = "enforce.traffic.rate_limit"
			execLevel = "soft"
			downgradeReason = "policy_max_action_ceiling"
		}

	case "rate_limit_hard":
		// Cap at hard: only block downgrades; hard and below pass through.
		if execLevel == "block" {
			execAction = "enforce.traffic.rate_limit"
			execLevel = "hard"
			downgradeReason = "policy_max_action_ceiling"
		}
	}

	// Rule 4: CapabilitiesAllowed check — only in managed mode with a non-empty allowlist.
	if len(r.CapabilitiesAllowed) > 0 && execAction != "" {
		if !r.CapabilitiesAllowed[execAction] {
			base.Allowed = false
			base.DenyReason = fmt.Sprintf("capability_not_in_policy_pack(%s)", execAction)
			// De-enforce: unauthorized capability → move to observe
			base.ExecutableAction = ""
			base.ExecutableLevel = "observe"
			return base
		}
	}

	base.Allowed = true
	base.ExecutableAction = execAction
	base.ExecutableLevel = execLevel
	base.DenyReason = downgradeReason
	return base
}

// ── FSM level helpers ─────────────────────────────────────────────────────────

// FsmLevelToCapability maps a FSM enforcement level to the corresponding
// Forge capability ID for use in ActionProposals.
func FsmLevelToCapability(level fsm.Level) string {
	switch level {
	case fsm.LevelSoft, fsm.LevelHard:
		return "enforce.traffic.rate_limit"
	case fsm.LevelBlock:
		return "enforce.access.deny"
	default:
		return ""
	}
}

// FsmLevelName returns the string name of a FSM level for use in proposals.
func FsmLevelName(level fsm.Level) string {
	switch level {
	case fsm.LevelSoft:
		return "soft"
	case fsm.LevelHard:
		return "hard"
	case fsm.LevelBlock:
		return "block"
	default:
		return "observe"
	}
}

// ParseFSMLevel converts a level string (from ActionResolution) back to fsm.Level.
func ParseFSMLevel(s string) fsm.Level {
	switch s {
	case "soft":
		return fsm.LevelSoft
	case "hard":
		return fsm.LevelHard
	case "block":
		return fsm.LevelBlock
	default:
		return fsm.LevelObserve
	}
}
