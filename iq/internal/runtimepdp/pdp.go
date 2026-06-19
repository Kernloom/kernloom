// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package runtimepdp evaluates Forge/KLIQ RuntimePolicyPack rules against local
// risk and context snapshots.
package runtimepdp

import (
	"fmt"
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
	Metrics  map[string]any
	Signals  map[string]any
	Baseline map[string]any
	Graph    map[string]any
	Adapter  map[string]any
	FSM      map[string]any
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
	rules := make([]compiledRule, 0, len(pack.Spec.Rules))
	for _, rule := range pack.Spec.Rules {
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

func (p *PDP) Decide(input Input) (contracts.RuntimeDecision, bool, error) {
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if input.Subject.ID == "" {
		input.Subject = input.Risk.Subject
	}
	vars := map[string]any{
		"risk":     riskVars(input.Risk),
		"device":   deviceVars(input.Context.Device),
		"session":  sessionVars(input.Context.Session),
		"features": factMapVars(input.Context.Features, nil),
		"metrics":  factMapVars(input.Context.Metrics, nil),
		"signals":  factMapVars(input.Context.Signals, nil),
		"baseline": factMapVars(input.Context.Baseline, nil),
		"graph":    factMapVars(input.Context.Graph, nil),
		"adapter":  factMapVars(input.Context.Adapter, nil),
		"fsm":      factMapVars(input.Context.FSM, nil),
	}
	for _, rule := range p.rules {
		out, _, err := rule.program.Eval(vars)
		if err != nil {
			if isMissingFactKeyError(err) {
				continue
			}
			return contracts.RuntimeDecision{}, false, fmt.Errorf("runtimepdp: eval rule %q: %w", rule.rule.ID, err)
		}
		matched, ok := out.Value().(bool)
		if !ok {
			return contracts.RuntimeDecision{}, false, fmt.Errorf("runtimepdp: rule %q returned non-bool", rule.rule.ID)
		}
		if !matched {
			continue
		}
		return p.decisionForRule(rule.rule, input, now), true, nil
	}
	return p.defaultDecision(input, now), false, nil
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
	)
	if err != nil {
		return nil, fmt.Errorf("runtimepdp: create cel env: %w", err)
	}
	return env, nil
}

func riskVars(risk contracts.LocalRiskAssessment) map[string]any {
	return map[string]any{
		"level":        string(risk.Level),
		"score":        risk.Score,
		"confidence":   risk.Confidence,
		"completeness": risk.Completeness,
		"domains":      risk.Domains,
		"model":        risk.Model,
	}
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
