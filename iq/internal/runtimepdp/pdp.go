// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package runtimepdp evaluates Forge/KLIQ RuntimePolicyPack rules against local
// risk and context snapshots.
package runtimepdp

import (
	"fmt"
	"time"

	"github.com/google/cel-go/cel"
	contracts "github.com/kernloom/kernloom-contracts"
)

const deciderName = "kliq.runtimepdp"

type ContextSnapshot struct {
	Device   map[string]any
	Session  map[string]any
	Features map[string]any
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
		"device":   safeMap(input.Context.Device),
		"session":  safeMap(input.Context.Session),
		"features": safeMap(input.Context.Features),
	}
	for _, rule := range p.rules {
		out, _, err := rule.program.Eval(vars)
		if err != nil {
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

func safeMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	return in
}
