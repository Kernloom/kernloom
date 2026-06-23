// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package actions

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

// PolicyResolver is the final safety gate before any PEP is touched.
// RuntimePDP owns the decision; the resolver applies deployment ceilings and
// capability allowlists to the resulting ActionProposal.
//
// Rules applied in order:
//  1. Standalone mode: actions pass through unless a local ceiling is configured elsewhere.
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

	// RuntimeGuardrails are safety invariants compiled by Forge. They are
	// evaluated after action ceilings and capability checks, before any PEP
	// mutation is authorized.
	RuntimeGuardrails []contracts.RuntimeGuardrail

	// RuntimeAutonomyLifecycle carries customer autonomy boundaries compiled by
	// Forge. Stateless gates are enforced here; stateful lease checks live in
	// the action broker.
	RuntimeAutonomyLifecycle *contracts.RuntimeAutonomyLifecycleSpec
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

	// Rule 1: standalone mode — full pass-through.
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

	if reason := r.guardrailDenyReason(execAction, execLevel, p.Target); reason != "" {
		base.Allowed = false
		base.DenyReason = reason
		base.ExecutableAction = ""
		base.ExecutableLevel = "observe"
		return base
	}
	if reason := actionBlastRadiusDenyReason(p.Parameters, execAction, execLevel, p.Target); reason != "" {
		base.Allowed = false
		base.DenyReason = reason
		base.ExecutableAction = ""
		base.ExecutableLevel = "observe"
		return base
	}
	if reason := r.autonomySubjectAllowanceDenyReason(execAction, p); reason != "" {
		base.Allowed = false
		base.DenyReason = reason
		base.ExecutableAction = ""
		base.ExecutableLevel = "observe"
		return base
	}
	if reason := r.autonomyApprovalDenyReason(execAction, p.Parameters); reason != "" {
		base.Allowed = false
		base.DenyReason = reason
		base.ExecutableAction = ""
		base.ExecutableLevel = "observe"
		return base
	}

	if maxDuration := r.autonomyMaxActionDuration(execAction); maxDuration > 0 && base.TTL > maxDuration {
		base.TTL = maxDuration
		downgradeReason = appendResolutionReason(downgradeReason, "autonomy_max_action_duration_clamped")
	}
	if r.autonomyRequiresAudit() {
		base.Parameters = ensureAnyMap(base.Parameters)
		base.Parameters["requires_audit_receipt"] = true
	}

	base.Allowed = true
	base.ExecutableAction = execAction
	base.ExecutableLevel = execLevel
	base.DenyReason = downgradeReason
	return base
}

func (r *PolicyResolver) autonomySubjectAllowanceDenyReason(action string, p ActionProposal) string {
	lifecycle := r.RuntimeAutonomyLifecycle
	if lifecycle == nil || action == "" {
		return ""
	}
	for _, allowance := range lifecycle.Allow {
		if strings.TrimSpace(allowance.Action) != action {
			continue
		}
		if allowance.Subject.Type == "" && allowance.Subject.Ref == "" {
			continue
		}
		if allowance.Subject.Type != "source" || allowance.Subject.Ref != "unknown" {
			continue
		}
		if sourceClassifiesAsUnknown(p) {
			return ""
		}
		return "autonomy_subject_not_allowed(source:unknown)"
	}
	return ""
}

func (r *PolicyResolver) autonomyApprovalDenyReason(action string, params map[string]any) string {
	lifecycle := r.RuntimeAutonomyLifecycle
	if lifecycle == nil || action == "" {
		return ""
	}
	for _, req := range lifecycle.ApprovalRequired {
		if strings.TrimSpace(req.Action) != action {
			continue
		}
		if approvalGranted(params) {
			return ""
		}
		return "autonomy_approval_required(" + action + ")"
	}
	return ""
}

func sourceClassifiesAsUnknown(p ActionProposal) bool {
	for _, raw := range []any{
		p.Parameters["source_class"],
		p.Parameters["source_selector"],
		p.Parameters["selector"],
		p.Target.Attributes["source_class"],
		p.Target.Attributes["source_selector"],
		p.Target.Attributes["selector"],
	} {
		value := strings.TrimSpace(fmt.Sprint(raw))
		switch value {
		case "unknown", "unknown_source":
			return true
		}
	}
	return false
}

func (r *PolicyResolver) autonomyMaxActionDuration(action string) time.Duration {
	lifecycle := r.RuntimeAutonomyLifecycle
	if lifecycle == nil || action == "" {
		return 0
	}
	for _, limit := range lifecycle.MaxActionDuration {
		if strings.TrimSpace(limit.Action) == action && limit.Duration.Duration > 0 {
			return limit.Duration.Duration
		}
	}
	return 0
}

func (r *PolicyResolver) autonomyRequiresAudit() bool {
	return r.RuntimeAutonomyLifecycle != nil && r.RuntimeAutonomyLifecycle.RequiresAudit
}

func approvalGranted(params map[string]any) bool {
	for _, key := range []string{"approval_granted", "operator_approved", "approved"} {
		if boolAny(params[key]) {
			return true
		}
	}
	return false
}

func ensureAnyMap(values map[string]any) map[string]any {
	if values != nil {
		return values
	}
	return map[string]any{}
}

func appendResolutionReason(existing, reason string) string {
	if existing == "" {
		return reason
	}
	return existing + "," + reason
}

func boolAny(raw any) bool {
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		return err == nil && parsed
	default:
		return false
	}
}

func actionBlastRadiusDenyReason(params map[string]any, action, level string, target ActionTarget) string {
	subjects, unknownBehavior := actionBlastRadiusSubjects(params)
	if len(subjects) == 0 {
		return ""
	}
	for _, subject := range subjects {
		matched, unknown := guardrailSubjectMatch(subject, target)
		if matched {
			return "blast_radius_protected_subject"
		}
		if unknown && blastRadiusUnknownRejects(unknownBehavior, action, level) {
			return "blast_radius_unknown_target"
		}
	}
	return ""
}

func actionBlastRadiusSubjects(params map[string]any) ([]contracts.RuntimeGuardrailSubject, string) {
	if len(params) == 0 {
		return nil, ""
	}
	var subjects []contracts.RuntimeGuardrailSubject
	unknownBehavior := ""
	if raw, ok := params["blast_radius"]; ok {
		if m, ok := raw.(map[string]any); ok {
			unknownBehavior = strings.TrimSpace(fmt.Sprint(m["unknown_behavior"]))
			subjects = append(subjects, actionBlastRadiusSubjectList(m["excludes"])...)
		}
	}
	if group := strings.TrimSpace(fmt.Sprint(params["requires_target_excludes_group"])); group != "" && group != "<nil>" {
		subjects = append(subjects, contracts.RuntimeGuardrailSubject{Type: "group", Ref: group})
		if unknownBehavior == "" {
			unknownBehavior = "reject_hard_action"
		}
	}
	return subjects, unknownBehavior
}

func actionBlastRadiusSubjectList(raw any) []contracts.RuntimeGuardrailSubject {
	var out []contracts.RuntimeGuardrailSubject
	switch values := raw.(type) {
	case []map[string]string:
		for _, item := range values {
			out = append(out, contracts.RuntimeGuardrailSubject{Type: item["type"], Ref: item["ref"]})
		}
	case []map[string]any:
		for _, item := range values {
			out = append(out, contracts.RuntimeGuardrailSubject{Type: fmt.Sprint(item["type"]), Ref: fmt.Sprint(item["ref"])})
		}
	case []any:
		for _, item := range values {
			if typed, ok := item.(map[string]any); ok {
				out = append(out, contracts.RuntimeGuardrailSubject{Type: fmt.Sprint(typed["type"]), Ref: fmt.Sprint(typed["ref"])})
			}
		}
	}
	cleaned := out[:0]
	for _, subject := range out {
		subject.Type = strings.TrimSpace(subject.Type)
		subject.Ref = strings.TrimSpace(subject.Ref)
		if subject.Type != "" && subject.Ref != "" {
			cleaned = append(cleaned, subject)
		}
	}
	return cleaned
}

func blastRadiusUnknownRejects(behavior, action, level string) bool {
	if behavior == "" {
		behavior = "reject_hard_action"
	}
	behavior = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(behavior)), "-", "_")
	if behavior == "reject_action" {
		return true
	}
	return behavior == "reject_hard_action" && isHardRuntimeAction(action, level)
}

func (r *PolicyResolver) guardrailDenyReason(action, level string, target ActionTarget) string {
	if action == "" || level == "observe" {
		return ""
	}
	for _, g := range r.RuntimeGuardrails {
		if strings.TrimSpace(g.Type) != "never" {
			continue
		}
		if !guardrailForbidsAction(g, action, level) {
			continue
		}
		matched, unknown := guardrailSubjectMatch(g.Subject, target)
		if matched {
			return fmt.Sprintf("guardrail_violation(%s)", g.ID)
		}
		if unknown && guardrailUnknownRejectsHardAction(g, action, level) {
			return fmt.Sprintf("guardrail_unknown_match_for_hard_action(%s)", g.ID)
		}
	}
	return ""
}

func guardrailForbidsAction(g contracts.RuntimeGuardrail, action, level string) bool {
	for _, forbidden := range g.ForbiddenActions {
		if guardrailActionMatches(forbidden, action, level) {
			return true
		}
	}
	return false
}

func guardrailActionMatches(forbidden, action, level string) bool {
	forbidden = normalizeGuardrailAction(forbidden)
	action = normalizeGuardrailAction(action)
	if forbidden == "" {
		return false
	}
	if forbidden == "auto_block" {
		return level == "block" || action == "enforce.access.deny" ||
			action == "enforce.traffic.drop" ||
			action == "enforce.network.quarantine" ||
			action == "enforce.identity.disable"
	}
	return forbidden == action
}

func normalizeGuardrailAction(action string) string {
	action = strings.TrimSpace(strings.ReplaceAll(action, " ", "_"))
	switch action {
	case "network.flow_deny", "network.block_source", "deny", "network_deny":
		return "enforce.access.deny"
	case "auto_block":
		return "auto_block"
	case "block", "temporary_block":
		return "enforce.traffic.drop"
	case "quarantine", "network_quarantine":
		return "enforce.network.quarantine"
	case "disable_identity", "identity_disable", "identity.disable":
		return "enforce.identity.disable"
	default:
		return action
	}
}

func guardrailSubjectMatch(subject contracts.RuntimeGuardrailSubject, target ActionTarget) (matched bool, unknown bool) {
	if subject.Type == "" || subject.Ref == "" {
		return false, false
	}
	if target.Granularity == "subject" {
		if target.Value == subject.Ref || target.Value == subject.Type+":"+subject.Ref {
			return true, false
		}
	}
	attrs := target.Attributes
	if attrs == nil {
		return false, true
	}
	subjectType := firstAttr(attrs, "subject_type", "subject.type", "subjectType")
	subjectRef := firstAttr(attrs, "subject_ref", "subject.ref", "subjectRef")
	if subjectType != "" || subjectRef != "" {
		return subjectType == subject.Type && subjectRef == subject.Ref, false
	}
	if subject.Type == "group" {
		groups := firstAttr(attrs, "subject.groups", "subject_groups", "subjectGroups", "group")
		if groups != "" {
			return listContains(groups, subject.Ref), false
		}
	}
	return false, true
}

func guardrailUnknownRejectsHardAction(g contracts.RuntimeGuardrail, action, level string) bool {
	behavior := g.Enforcement.UnknownBehavior
	if behavior == "" {
		behavior = "reject_hard_action"
	}
	if behavior != "reject_hard_action" && behavior != "reject_action" {
		return false
	}
	return behavior == "reject_action" || isHardRuntimeAction(action, level)
}

func isHardRuntimeAction(action, level string) bool {
	if level == "hard" || level == "block" {
		return true
	}
	switch normalizeGuardrailAction(action) {
	case "enforce.access.deny", "enforce.traffic.drop", "enforce.network.quarantine", "enforce.identity.disable":
		return true
	default:
		return false
	}
}

func firstAttr(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if v := strings.TrimSpace(attrs[key]); v != "" {
			return v
		}
	}
	return ""
}

func listContains(values, want string) bool {
	for _, part := range strings.FieldsFunc(values, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	}) {
		if strings.TrimSpace(part) == want {
			return true
		}
	}
	return false
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
