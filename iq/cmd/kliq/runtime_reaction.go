// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
)

type runtimeReactionEngine struct {
	windows      map[string][]reactionSample
	lastFire     map[string]time.Time
	lastResponse map[string]time.Time
}

type reactionSample struct {
	at    time.Time
	count int
}

type reactionDetectionEvent struct {
	Rule        contracts.RuntimeDetectionRule
	Key         string
	SourceID    string
	Count       int
	Window      time.Duration
	ObservedAt  time.Time
	SourceAttrs map[string]string
}

func newRuntimeReactionEngine() *runtimeReactionEngine {
	return &runtimeReactionEngine{
		windows:      map[string][]reactionSample{},
		lastFire:     map[string]time.Time{},
		lastResponse: map[string]time.Time{},
	}
}

func (e *runtimeReactionEngine) EvaluateCandidate(
	m metrics,
	st fsm.State,
	now time.Time,
	c cfg,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	nodeID string,
) fsm.State {
	if e == nil || len(c.RuntimeDetectionRules) == 0 || len(c.RuntimeResponseRules) == 0 {
		return st
	}
	var out = st
	for _, detection := range c.RuntimeDetectionRules {
		event, ok := e.observeDetection(detection, m, now)
		if !ok {
			continue
		}
		out = e.applyResponses(event, out, c, resolver, executor, nodeID, now)
	}
	return out
}

func (e *runtimeReactionEngine) observeDetection(rule contracts.RuntimeDetectionRule, m metrics, now time.Time) (reactionDetectionEvent, bool) {
	if strings.TrimSpace(rule.ID) == "" || !reactionSubjectMatches(rule.Subject, m.Target) || !reactionResourceMatches(rule.ResourceRef, m.Target.Attributes) {
		return reactionDetectionEvent{}, false
	}
	count := reactionObservationCount(rule, m)
	if count <= 0 {
		return reactionDetectionEvent{}, false
	}
	window := rule.Window.Duration
	if window <= 0 {
		window = time.Minute
	}
	threshold := rule.Threshold
	if threshold <= 0 {
		threshold = 1
	}
	key := reactionDetectionKey(rule, m)
	samples := append(e.windows[key], reactionSample{at: now, count: count})
	cutoff := now.Add(-window)
	total := 0
	kept := samples[:0]
	for _, sample := range samples {
		if sample.at.Before(cutoff) {
			continue
		}
		total += sample.count
		kept = append(kept, sample)
	}
	e.windows[key] = kept
	if total < threshold {
		return reactionDetectionEvent{}, false
	}
	if last := e.lastFire[key]; !last.IsZero() && now.Sub(last) < window {
		return reactionDetectionEvent{}, false
	}
	e.lastFire[key] = now
	return reactionDetectionEvent{
		Rule:        rule,
		Key:         key,
		SourceID:    m.sourceID(),
		Count:       total,
		Window:      window,
		ObservedAt:  now,
		SourceAttrs: copyStringMap(m.Target.Attributes),
	}, true
}

func (e *runtimeReactionEngine) applyResponses(
	event reactionDetectionEvent,
	st fsm.State,
	c cfg,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	nodeID string,
	now time.Time,
) fsm.State {
	out := st
	for _, rule := range c.RuntimeResponseRules {
		if !reactionResponseMatches(rule.When, event.Rule.ID) {
			continue
		}
		for _, action := range rule.Then {
			if action.ID == "notify.alert.emit" {
				e.emitAlert(rule, action, event, now)
				continue
			}
			next, applied := e.applyRuntimeAction(rule, action, event, out, c, resolver, executor, nodeID, now)
			if applied {
				out = next
			}
		}
	}
	return out
}

func (e *runtimeReactionEngine) emitAlert(rule contracts.RuntimeResponseRule, action contracts.RuntimeResponseAction, event reactionDetectionEvent, now time.Time) {
	dedupe := action.Dedupe.Duration
	if dedupe <= 0 {
		dedupe = time.Minute
	}
	key := "alert|" + rule.ID + "|" + action.Route + "|" + event.Key
	if last := e.lastResponse[key]; !last.IsZero() && now.Sub(last) < dedupe {
		return
	}
	e.lastResponse[key] = now
	kliqLog.Printf("REACTION alert detection=%s response=%s route=%s severity=%s source=%s count=%d window=%s",
		event.Rule.ID, rule.ID, action.Route, action.Severity, event.SourceID, event.Count, event.Window)
}

func (e *runtimeReactionEngine) applyRuntimeAction(
	rule contracts.RuntimeResponseRule,
	action contracts.RuntimeResponseAction,
	event reactionDetectionEvent,
	st fsm.State,
	c cfg,
	resolver *actions.PolicyResolver,
	executor *brokeredActionExecutor,
	nodeID string,
	now time.Time,
) (fsm.State, bool) {
	if c.RuntimePDPMode != string(PDPModeActive) {
		kliqLog.Printf("[reaction:shadow] response=%s detection=%s action=%s source=%s observe-only",
			rule.ID, event.Rule.ID, action.ID, event.SourceID)
		return st, false
	}
	if action.TTL.Duration <= 0 {
		kliqLog.Printf("[reaction:active] response=%s detection=%s action=%s skipped: missing ttl",
			rule.ID, event.Rule.ID, action.ID)
		return st, false
	}
	prop, ok := reactionActionProposal(nodeID, rule, action, event, now)
	if !ok {
		kliqLog.Printf("[reaction:active] response=%s detection=%s action=%s skipped: unsupported action",
			rule.ID, event.Rule.ID, action.ID)
		return st, false
	}
	res := resolver.Resolve(prop)
	if res.DenyReason != "" {
		kliqLog.Printf("ACTION-RESOLVER reaction %s %s->%s reason=%q",
			event.SourceID, prop.DesiredLevel, res.ExecutableLevel, res.DenyReason)
	}
	if !res.Allowed {
		return st, false
	}
	switch res.Target.Granularity {
	case "", actions.TargetGranularitySource:
		target := sourceTargetFromID(event.SourceID)
		if res.Target.Value != "" {
			target = sourceTargetFromID(res.Target.Value)
		}
		target.Attributes = copyStringMap(res.Target.Attributes)
		next, result := executor.ApplySource(target, st, res, c.toPEPParams(), now)
		if result.Status == "failed" {
			kliqLog.Printf("[reaction:active] source action failed source=%s response=%s reason=%s", event.SourceID, rule.ID, result.Reason)
			return st, false
		}
		kliqLog.Printf("[reaction:active] source action source=%s response=%s detection=%s action=%s level=%s ttl=%s",
			event.SourceID, rule.ID, event.Rule.ID, res.ExecutableAction, res.ExecutableLevel, res.TTL)
		return next, true
	default:
		kliqLog.Printf("[reaction:active] response=%s detection=%s unsupported target %s:%q",
			rule.ID, event.Rule.ID, res.Target.Granularity, res.Target.Value)
		return st, false
	}
}

func reactionActionProposal(
	nodeID string,
	rule contracts.RuntimeResponseRule,
	action contracts.RuntimeResponseAction,
	event reactionDetectionEvent,
	now time.Time,
) (actions.ActionProposal, bool) {
	capability := normalizeCapabilityID(action.ID)
	level := reactionActionLevel(action, capability)
	if capability == "" || level == "" || level == "observe" {
		return actions.ActionProposal{}, false
	}
	target := reactionActionTarget(action.Target, event)
	params := copyAnyMap(action.Params)
	if params == nil {
		params = map[string]any{}
	}
	params["node_id"] = nodeID
	params["response_rule_id"] = rule.ID
	params["detection_rule_id"] = event.Rule.ID
	params["detection_count"] = event.Count
	params["detection_window"] = event.Window.String()
	params["runtime_action_id"] = action.ID
	params["runtime_action_from"] = "response_policy"
	return actions.ActionProposal{
		ID:            fmt.Sprintf("reaction-%s-%s-%d", sanitizeReactionID(rule.ID), sanitizeReactionID(event.SourceID), now.UnixNano()),
		Source:        "reaction",
		Reason:        "reaction:" + event.Rule.ID,
		DesiredAction: capability,
		DesiredLevel:  level,
		Target:        target,
		Parameters:    params,
		TTL:           action.TTL.Duration,
		Confidence:    1,
		CreatedAt:     now,
	}, true
}

func reactionActionLevel(action contracts.RuntimeResponseAction, capability string) string {
	switch strings.TrimSpace(action.Severity) {
	case "soft", "hard", "block":
		return action.Severity
	}
	return capabilityToFsmLevel(capability)
}

func reactionActionTarget(target contracts.RuntimeResponseTarget, event reactionDetectionEvent) actions.ActionTarget {
	scope := strings.TrimSpace(target.Scope)
	value := strings.TrimSpace(target.Ref)
	if value == "" {
		value = event.SourceID
	}
	switch scope {
	case "", "source", "source.ip", "source.identity_or_ip":
		return actions.ActionTarget{
			Granularity: actions.TargetGranularitySource,
			Value:       value,
			Attributes:  copyStringMap(event.SourceAttrs),
		}
	default:
		return actions.ActionTarget{
			Granularity: scope,
			Value:       value,
			Attributes:  copyStringMap(event.SourceAttrs),
		}
	}
}

func reactionResponseMatches(trigger contracts.RuntimeResponseTrigger, detectionID string) bool {
	if trigger.Detection == "" {
		return false
	}
	if trigger.Detection == detectionID {
		return true
	}
	return strings.HasSuffix(trigger.Detection, "/"+detectionID)
}

func reactionObservationCount(rule contracts.RuntimeDetectionRule, m metrics) int {
	switch strings.TrimSpace(rule.Type) {
	case "access.denied_threshold", "access_denied":
		return firstPositiveSignalCount(m, "access.denied", "access.denied_count", "access_denied", "events.access_denied", "security.access_denied")
	case "network.rate_limit_drop_threshold", "source.rate_limit_drops_sustained":
		return int(math.Ceil(m.enforcementFeedbackRate()))
	case "metric.threshold":
		return metricThresholdCount(rule, m)
	default:
		return metricThresholdCount(rule, m)
	}
}

func firstPositiveSignalCount(m metrics, keys ...string) int {
	for _, key := range keys {
		value := m.signalValue(key)
		if value <= 0 {
			continue
		}
		if value < 1 {
			return 1
		}
		return int(math.Ceil(value))
	}
	return 0
}

func metricThresholdCount(rule contracts.RuntimeDetectionRule, m metrics) int {
	metricID := stringAnyParam(rule.Params, "metric", "signal", "key")
	if metricID == "" {
		return 0
	}
	value := m.signalValue(metricID)
	threshold := floatAnyParam(rule.Params, "value", "threshold")
	op := stringAnyParam(rule.Params, "operator", "op")
	if op == "" {
		op = "gt"
	}
	if compareFloat(value, op, threshold) {
		return 1
	}
	return 0
}

func compareFloat(left float64, op string, right float64) bool {
	switch op {
	case "eq":
		return left == right
	case "neq":
		return left != right
	case "gte":
		return left >= right
	case "lte":
		return left <= right
	case "lt":
		return left < right
	default:
		return left > right
	}
}

func reactionDetectionKey(rule contracts.RuntimeDetectionRule, m metrics) string {
	scope := strings.TrimSpace(rule.Scope)
	if scope == "" {
		scope = "source"
	}
	return rule.ID + "|" + scope + "|" + m.sourceID()
}

func reactionSubjectMatches(subject contracts.RuntimeDetectionSubject, target adapterruntime.SourceTarget) bool {
	if subject.Type == "" && subject.Ref == "" && subject.Selector == "" {
		return true
	}
	if subject.Selector == "unknown_source" {
		return target.Subject.ID == "" || target.Subject.Kind == ""
	}
	if subject.Ref == "" {
		return true
	}
	if target.Subject.ID == subject.Ref || target.SourceID == subject.Ref {
		return true
	}
	if subject.Type == "group" {
		groups := firstStringAttr(target.Attributes, "subject.groups", "subject_groups", "subjectGroups", "group")
		return reactionListContains(groups, subject.Ref)
	}
	return false
}

func reactionResourceMatches(resourceRef string, attrs map[string]string) bool {
	resourceRef = strings.TrimSpace(resourceRef)
	if resourceRef == "" {
		return true
	}
	resource := firstStringAttr(attrs, "resource.ref", "resource_ref", "resource", "service", "service_id", "target", "target_id")
	if resource == "" {
		return false
	}
	return resource == resourceRef
}

func firstStringAttr(attrs map[string]string, keys ...string) string {
	for _, key := range keys {
		if attrs[key] != "" {
			return attrs[key]
		}
	}
	return ""
}

func reactionListContains(values, want string) bool {
	if values == "" || want == "" {
		return false
	}
	for _, part := range strings.Split(values, ",") {
		if strings.TrimSpace(part) == want {
			return true
		}
	}
	return false
}

func stringAnyParam(params map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := params[key]; ok {
			return strings.TrimSpace(fmt.Sprint(value))
		}
	}
	return ""
}

func floatAnyParam(params map[string]any, keys ...string) float64 {
	for _, key := range keys {
		value, ok := params[key]
		if !ok {
			continue
		}
		switch v := value.(type) {
		case float64:
			return v
		case float32:
			return float64(v)
		case int:
			return float64(v)
		case int64:
			return float64(v)
		case uint64:
			return float64(v)
		case string:
			parsed, _ := strconv.ParseFloat(v, 64)
			return parsed
		default:
			parsed, _ := strconv.ParseFloat(fmt.Sprint(v), 64)
			return parsed
		}
	}
	return 0
}

func sanitizeReactionID(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var out strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			out.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			out.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(out.String(), "-")
}
