// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/iq/internal/runtimepdp"
)

func runtimeDecisionToActionProposal(
	dec contracts.RuntimeDecision,
	fallbackSubjectID string,
	confidence float64,
	now time.Time,
) (actions.ActionProposal, bool, string) {
	return runtimeDecisionToActionProposalWithFallbackTarget(dec, fallbackSubjectID, nil, confidence, now)
}

func runtimeDecisionToActionProposalWithFallbackTarget(
	dec contracts.RuntimeDecision,
	fallbackSubjectID string,
	fallbackTarget *actions.ActionTarget,
	confidence float64,
	now time.Time,
) (actions.ActionProposal, bool, string) {
	if dec.Effect != "apply" && dec.Effect != "restrict" {
		return actions.ActionProposal{}, false, "runtime_decision_effect_not_enforcing"
	}

	level := runtimeActionLevel(dec.Action)
	if level == "" {
		return actions.ActionProposal{}, false, "runtime_decision_non_enforcing_level"
	}
	capability := normalizeCapabilityID(dec.Action.Capability)
	if capability == "" && level != "observe" {
		return actions.ActionProposal{}, false, "runtime_decision_missing_capability"
	}
	target, ok, reason := runtimeDecisionTarget(dec, fallbackSubjectID)
	if fallbackTarget != nil && shouldUseRuntimeFallbackTarget(dec, target, ok) {
		target = *fallbackTarget
		ok = true
		reason = ""
	}
	if !ok {
		return actions.ActionProposal{}, false, reason
	}

	reasonText := "runtime_pdp"
	if len(dec.ReasonCodes) > 0 {
		reasonText = "runtime_pdp:" + strings.Join(dec.ReasonCodes, ",")
	}

	return actions.ActionProposal{
		ID:            dec.Metadata.ID,
		Source:        "runtime-pdp",
		Reason:        reasonText,
		DesiredAction: capability,
		DesiredLevel:  level,
		Target:        target,
		Parameters:    copyAnyMap(dec.Action.Params),
		TTL:           runtimeDecisionTTL(dec, now),
		Confidence:    confidence,
		CreatedAt:     now,
	}, true, ""
}

func runtimePDPActionProposalWithEvidence(prop actions.ActionProposal, input runtimepdp.Input) actions.ActionProposal {
	if dropRate := runtimePDPDropRateEvidence(input); dropRate > 0 {
		if prop.Parameters == nil {
			prop.Parameters = map[string]any{}
		}
		prop.Parameters["evidence_drop_rl_rate"] = dropRate
	}
	return prop
}

func runtimePDPDropRateEvidence(input runtimepdp.Input) float64 {
	if enforcement, ok := input.Context.Signals["enforcement"].(map[string]any); ok {
		if value := floatAnyParam(enforcement, "drop_rate"); value > 0 {
			return value
		}
	}
	return floatAnyParam(input.Context.Signals,
		"network.rate_limit_drop_rate",
		"rate_limit_drop_rate",
		"drop_rate",
		"drop_rl_rate",
	)
}

func shouldUseRuntimeFallbackTarget(dec contracts.RuntimeDecision, target actions.ActionTarget, targetOK bool) bool {
	if !targetOK {
		return true
	}
	if strings.ToLower(stringParam(dec.Action.Params, "target_granularity")) == actions.TargetGranularityRelationship {
		return target.Granularity != actions.TargetGranularityRelationship
	}
	capability := normalizeCapabilityID(dec.Action.Capability)
	return capability == "enforce.access.deny" && target.Granularity != actions.TargetGranularityRelationship
}

func runtimeActionLevel(action contracts.RuntimeActionSpec) string {
	if level := strings.TrimSpace(action.Level); level != "" {
		return level
	}
	switch capabilitySeverityKLIQ[normalizeCapabilityID(action.Capability)] {
	case 3:
		return "block"
	case 2:
		return "hard"
	case 1:
		return "soft"
	default:
		return ""
	}
}

func runtimeDecisionTTL(dec contracts.RuntimeDecision, now time.Time) time.Duration {
	if dec.Action.TTL.Duration > 0 {
		return dec.Action.TTL.Duration
	}
	if dec.ValidUntil.After(now) {
		return dec.ValidUntil.Sub(now)
	}
	return 30 * time.Second
}

func runtimeDecisionTarget(dec contracts.RuntimeDecision, fallbackSubjectID string) (actions.ActionTarget, bool, string) {
	params := dec.Action.Params
	switch strings.ToLower(stringParam(params, "target_granularity")) {
	case actions.TargetGranularityRelationship:
		sourceID := firstStringParam(params,
			actions.TargetAttrSubjectID,
			actions.TargetAttrSourceID,
			"source",
			"source_ip",
		)
		if sourceID == "" {
			sourceID = firstNonEmpty(dec.Subject.ID, fallbackSubjectID)
		}
		attrs := map[string]string{}
		for k, v := range params {
			if strings.HasPrefix(k, actions.TargetAttrDimensionPrefix) {
				attrs[k] = fmt.Sprint(v)
			}
		}
		if targetID := firstStringParam(params, actions.TargetAttrTargetID, "target", "object_id", "service_id"); targetID != "" {
			attrs[actions.TargetAttrTargetID] = targetID
		}
		relTarget, ok := relationshipActionTargetFromAttributes(sourceID, attrs)
		if !ok {
			return actions.ActionTarget{}, false, "runtime_relationship_target_invalid"
		}
		return relTarget.Proposal, true, ""

	case "", actions.TargetGranularitySource:
		sourceID := firstStringParam(params,
			actions.TargetAttrSourceID,
			"source",
			"source_ip",
			"ip",
			actions.TargetAttrSubjectID,
		)
		if sourceID == "" {
			sourceID = firstNonEmpty(dec.Subject.ID, fallbackSubjectID)
		}
		if sourceID == "" {
			return actions.ActionTarget{}, false, "runtime_source_target_missing"
		}
		return actions.ActionTarget{
			Granularity: actions.TargetGranularitySource,
			Value:       sourceID,
			Attributes:  copyStringParams(params),
		}, true, ""

	default:
		return actions.ActionTarget{}, false, "runtime_target_granularity_unsupported"
	}
}

func firstStringParam(params map[string]any, keys ...string) string {
	for _, key := range keys {
		if v := stringParam(params, key); v != "" {
			return v
		}
	}
	return ""
}

func stringParam(params map[string]any, key string) string {
	if len(params) == 0 {
		return ""
	}
	v, ok := params[key]
	if !ok {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if v := strings.TrimSpace(value); v != "" {
			return v
		}
	}
	return ""
}

func copyAnyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyStringParams(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = fmt.Sprint(v)
	}
	return out
}
