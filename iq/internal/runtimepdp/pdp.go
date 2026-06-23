// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package runtimepdp evaluates Forge/KLIQ RuntimePolicyPack rules against local
// risk and context snapshots.
package runtimepdp

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	contracts "github.com/kernloom/kernloom-contracts"
)

const deciderName = "kliq.runtimepdp"

type ContextSnapshot struct {
	Device   map[string]any
	Session  map[string]any
	Features map[string]any

	// Generic decision facts. Adapters/analyzers own the semantics of these
	// values; RuntimePDP only exposes them to CEL policy rules.
	Metrics    map[string]any
	Signals    map[string]any
	Baseline   map[string]any
	Graph      map[string]any
	Adapter    map[string]any
	FSM        map[string]any
	Detections map[string]any
	Actions    map[string]any
}

type Input struct {
	NodeID  string
	Subject contracts.EntityRef
	Risk    contracts.LocalRiskAssessment
	Context ContextSnapshot
	Now     time.Time
}

type PDP struct {
	pack  contracts.RuntimePolicyPack
	rules []compiledRule
}

type compiledRule struct {
	rule    contracts.RuntimePolicyRule
	program cel.Program
}

// RuleTrace is a compact per-rule evaluation diagnostic for policy operators.
type RuleTrace struct {
	ID     string
	Action string
	Level  string

	Matched bool
	Skipped bool
	Error   string
}

func Compile(pack contracts.RuntimePolicyPack) (*PDP, error) {
	if pack.APIVersion != contracts.RuntimeAPIVersion {
		return nil, fmt.Errorf("runtimepdp: unsupported policy apiVersion %q", pack.APIVersion)
	}
	if pack.Kind != contracts.KindRuntimePolicyPack {
		return nil, fmt.Errorf("runtimepdp: unsupported policy kind %q", pack.Kind)
	}
	env, err := celEnv()
	if err != nil {
		return nil, err
	}
	effectiveRules := EffectiveRules(pack)
	rules := make([]compiledRule, 0, len(effectiveRules))
	for _, rule := range effectiveRules {
		if rule.When == "" {
			return nil, fmt.Errorf("runtimepdp: rule %q has empty when expression", rule.ID)
		}
		ast, iss := env.Parse(rule.When)
		if iss.Err() != nil {
			return nil, fmt.Errorf("runtimepdp: parse rule %q: %w", rule.ID, iss.Err())
		}
		program, err := env.Program(ast)
		if err != nil {
			return nil, fmt.Errorf("runtimepdp: build rule %q: %w", rule.ID, err)
		}
		rules = append(rules, compiledRule{rule: rule, program: program})
	}
	return &PDP{pack: pack, rules: rules}, nil
}

// EffectiveRules returns the executable rules KLIQ evaluates for a policy pack.
// It prepends structured autonomy lifecycle rules to authored CEL rules so
// lifecycle holds win equal-precedence ties without requiring operators to write
// internal FSM expressions.
func EffectiveRules(pack contracts.RuntimePolicyPack) []contracts.RuntimePolicyRule {
	autonomyRules := autonomyLifecycleRules(pack)
	if len(autonomyRules) == 0 {
		return append([]contracts.RuntimePolicyRule(nil), pack.Spec.Rules...)
	}
	rules := make([]contracts.RuntimePolicyRule, 0, len(autonomyRules)+len(pack.Spec.Rules))
	rules = append(rules, autonomyRules...)
	rules = append(rules, pack.Spec.Rules...)
	return rules
}

func EffectiveRuleCount(pack contracts.RuntimePolicyPack) int {
	return len(EffectiveRules(pack))
}

func autonomyLifecycleRules(pack contracts.RuntimePolicyPack) []contracts.RuntimePolicyRule {
	lifecycle := pack.Spec.AutonomyLifecycle
	if lifecycle == nil {
		return nil
	}
	var rules []contracts.RuntimePolicyRule
	for _, hold := range lifecycle.Hold {
		if !hold.While.EnforcementFeedbackActive {
			continue
		}
		id := strings.TrimSpace(hold.ID)
		if id == "" {
			id = "hold-" + sanitizeRuleID(hold.Action.Capability)
		}
		reasons := append([]string{"autonomy_lifecycle_hold"}, lifecycle.ReasonCodes...)
		reasons = append(reasons, hold.ReasonCodes...)
		rules = append(rules, contracts.RuntimePolicyRule{
			ID:          "autonomy-" + id,
			When:        autonomyHoldExpression(hold.While),
			Then:        hold.Action,
			ReasonCodes: compactStrings(reasons),
		})
	}
	return rules
}

func autonomyHoldExpression(cond contracts.RuntimeAutonomyHoldCondition) string {
	levels := compactStrings(cond.Levels)
	if len(levels) == 0 {
		levels = []string{"soft", "hard", "block"}
	}
	return fmt.Sprintf("fsm.current_level in [%s] && signals.enforcement.active", celStringList(levels))
}

func celStringList(values []string) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		parts = append(parts, fmt.Sprintf("%q", value))
	}
	return strings.Join(parts, ", ")
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func sanitizeRuleID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "rule"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(value) {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "rule"
	}
	return out
}

func (p *PDP) Decide(input Input) (contracts.RuntimeDecision, bool, error) {
	dec, matched, _, err := p.decide(input, false)
	return dec, matched, err
}

func (p *PDP) DecideWithTrace(input Input) (contracts.RuntimeDecision, bool, []RuleTrace, error) {
	return p.decide(input, true)
}

func (p *PDP) decide(input Input, includeTrace bool) (contracts.RuntimeDecision, bool, []RuleTrace, error) {
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if input.Subject.ID == "" {
		input.Subject = input.Risk.Subject
	}
	vars := map[string]any{
		"risk":       riskVars(input.Risk, now),
		"device":     deviceVars(input.Context.Device),
		"session":    sessionVars(input.Context.Session),
		"features":   factMapVars(input.Context.Features, nil),
		"metrics":    factMapVars(input.Context.Metrics, nil),
		"signals":    factMapVars(input.Context.Signals, nil),
		"baseline":   factMapVars(input.Context.Baseline, nil),
		"graph":      factMapVars(input.Context.Graph, nil),
		"adapter":    factMapVars(input.Context.Adapter, nil),
		"fsm":        factMapVars(input.Context.FSM, nil),
		"detections": factMapVars(input.Context.Detections, nil),
		"actions":    factMapVars(input.Context.Actions, nil),
	}
	selected := -1
	selectedRank := 0
	traces := make([]RuleTrace, 0, len(p.rules))
	for idx, rule := range p.rules {
		trace := RuleTrace{
			ID:     rule.rule.ID,
			Action: rule.rule.Then.Capability,
			Level:  rule.rule.Then.Level,
		}
		out, _, err := rule.program.Eval(vars)
		if err != nil {
			if isMissingFactKeyError(err) {
				if includeTrace {
					trace.Skipped = true
					trace.Error = err.Error()
					traces = append(traces, trace)
				}
				continue
			}
			if includeTrace {
				trace.Error = err.Error()
				traces = append(traces, trace)
			}
			return contracts.RuntimeDecision{}, false, traces, fmt.Errorf("runtimepdp: eval rule %q: %w", rule.rule.ID, err)
		}
		matched, ok := out.Value().(bool)
		if !ok {
			err := fmt.Errorf("runtimepdp: rule %q returned non-bool", rule.rule.ID)
			if includeTrace {
				trace.Error = err.Error()
				traces = append(traces, trace)
			}
			return contracts.RuntimeDecision{}, false, traces, err
		}
		trace.Matched = matched
		if includeTrace {
			traces = append(traces, trace)
		}
		if !matched {
			continue
		}
		rank := runtimeActionPrecedence(rule.rule.Then)
		if selected < 0 || rank > selectedRank {
			selected = idx
			selectedRank = rank
		}
	}
	if selected >= 0 {
		return p.decisionForRule(p.rules[selected].rule, input, now), true, traces, nil
	}
	return p.defaultDecision(input, now), false, traces, nil
}

func runtimeActionPrecedence(action contracts.RuntimeActionSpec) int {
	if weight := runtimeLevelPrecedence(action.Level); weight > 0 {
		return weight
	}
	switch strings.TrimSpace(action.Capability) {
	case "enforce.access.deny", "enforce.traffic.drop", "enforce.network.quarantine", "enforce.identity.disable":
		return 300
	case "enforce.traffic.rate_limit":
		return 200
	default:
		return 0
	}
}

func runtimeLevelPrecedence(level string) int {
	switch strings.TrimSpace(level) {
	case "block":
		return 300
	case "hard":
		return 200
	case "soft":
		return 100
	default:
		return 0
	}
}

func (p *PDP) decisionForRule(rule contracts.RuntimePolicyRule, input Input, now time.Time) contracts.RuntimeDecision {
	validUntil := input.Risk.ValidUntil
	if validUntil.IsZero() {
		validUntil = now.Add(rule.Then.TTL.Duration)
	}
	if rule.Then.TTL.Duration > 0 {
		actionUntil := now.Add(rule.Then.TTL.Duration)
		if validUntil.IsZero() || actionUntil.Before(validUntil) {
			validUntil = actionUntil
		}
	}
	risk := input.Risk
	return contracts.RuntimeDecision{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimeDecision,
		},
		Metadata: contracts.ObjectMeta{
			NodeID:   input.NodeID,
			IssuedAt: now,
		},
		Subject:     input.Subject,
		Action:      rule.Then,
		Effect:      "apply",
		Decider:     deciderName,
		Risk:        &risk,
		ReasonCodes: rule.ReasonCodes,
		ValidUntil:  validUntil,
	}
}

func (p *PDP) defaultDecision(input Input, now time.Time) contracts.RuntimeDecision {
	effect := p.pack.Spec.DefaultEffect
	if effect == "" {
		effect = "deny"
	}
	risk := input.Risk
	return contracts.RuntimeDecision{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimeDecision,
		},
		Metadata: contracts.ObjectMeta{
			NodeID:   input.NodeID,
			IssuedAt: now,
		},
		Subject:    input.Subject,
		Effect:     effect,
		Decider:    deciderName,
		Risk:       &risk,
		ValidUntil: input.Risk.ValidUntil,
	}
}

func celEnv() (*cel.Env, error) {
	env, err := cel.NewEnv(
		cel.Variable("risk", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("device", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("session", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("features", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("metrics", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("signals", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("baseline", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("graph", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("adapter", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("fsm", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("detections", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("actions", cel.MapType(cel.StringType, cel.DynType)),
	)
	if err != nil {
		return nil, fmt.Errorf("runtimepdp: create cel env: %w", err)
	}
	return env, nil
}

func riskVars(risk contracts.LocalRiskAssessment, now time.Time) map[string]any {
	ageSeconds := 1e12
	if !risk.Metadata.IssuedAt.IsZero() {
		ageSeconds = now.Sub(risk.Metadata.IssuedAt.UTC()).Seconds()
		if ageSeconds < 0 {
			ageSeconds = 0
		}
	}
	validForSeconds := 0.0
	if !risk.ValidUntil.IsZero() {
		validForSeconds = risk.ValidUntil.Sub(now).Seconds()
	}
	return map[string]any{
		"level":                    string(risk.Level),
		"score":                    risk.Score,
		"confidence":               risk.Confidence,
		"completeness":             risk.Completeness,
		"domains":                  risk.Domains,
		"independent_signal_count": independentSignalCount(risk),
		"independent_signal_types": independentSignalTypes(risk),
		"model":                    risk.Model,
		"age_seconds":              ageSeconds,
		"valid_for_seconds":        validForSeconds,
	}
}

func independentSignalCount(risk contracts.LocalRiskAssessment) int {
	return len(independentSignalTypes(risk))
}

func independentSignalTypes(risk contracts.LocalRiskAssessment) []string {
	seen := map[string]bool{}
	for _, contribution := range risk.Contributions {
		key := strings.TrimSpace(contribution.SignalType)
		if key == "" {
			key = strings.TrimSpace(contribution.SignalID)
		}
		if key == "" {
			key = strings.TrimSpace(contribution.Domain)
		}
		if key != "" {
			seen[key] = true
		}
	}
	if len(seen) == 0 {
		for _, domain := range risk.Domains {
			if domain = strings.TrimSpace(domain); domain != "" {
				seen[domain] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for key := range seen {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func deviceVars(in map[string]any) map[string]any {
	out := factMapVars(in, map[string]any{
		"posture": map[string]any{
			"status": "unknown",
		},
	})
	insertPrefixedNestedFacts(out, in, "device.")
	return out
}

func sessionVars(in map[string]any) map[string]any {
	out := factMapVars(in, map[string]any{
		"authentication": map[string]any{
			"strength": "unknown",
		},
	})
	insertPrefixedNestedFacts(out, in, "session.")
	return out
}

func factMapVars(in map[string]any, defaults map[string]any) map[string]any {
	out := copyFactMap(defaults)
	mergeFactMap(out, in)
	for key, value := range in {
		if strings.Contains(key, ".") {
			insertNestedFact(out, key, value)
		}
	}
	return out
}

func copyFactMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range in {
		if nested, ok := value.(map[string]any); ok {
			out[key] = copyFactMap(nested)
			continue
		}
		out[key] = value
	}
	return out
}

func mergeFactMap(base map[string]any, extra map[string]any) {
	for key, value := range extra {
		if left, ok := base[key].(map[string]any); ok {
			if right, ok := value.(map[string]any); ok {
				mergeFactMap(left, right)
				continue
			}
		}
		if nested, ok := value.(map[string]any); ok {
			base[key] = copyFactMap(nested)
			continue
		}
		base[key] = value
	}
}

func insertNestedFact(out map[string]any, dotted string, value any) {
	parts := strings.Split(dotted, ".")
	if len(parts) < 2 {
		return
	}
	cursor := out
	for _, part := range parts[:len(parts)-1] {
		if part == "" {
			return
		}
		next, ok := cursor[part].(map[string]any)
		if !ok {
			next = map[string]any{}
			cursor[part] = next
		}
		cursor = next
	}
	last := parts[len(parts)-1]
	if last != "" {
		cursor[last] = value
	}
}

func insertPrefixedNestedFacts(out map[string]any, in map[string]any, prefix string) {
	for key, value := range in {
		if strings.HasPrefix(key, prefix) {
			insertNestedFact(out, strings.TrimPrefix(key, prefix), value)
		}
	}
}

func isMissingFactKeyError(err error) bool {
	return strings.Contains(err.Error(), "no such key")
}
