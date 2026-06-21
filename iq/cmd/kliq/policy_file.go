// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	corepolicy "github.com/kernloom/kernloom/pkg/core/policy"
	"gopkg.in/yaml.v3"
)

const (
	policyFileKindLocalRuntime = "LocalPolicyPack"
)

type loadedPolicyFile struct {
	Kind    string
	Local   *corepolicy.PolicyPack
	Runtime *contracts.RuntimePolicyPack
}

func loadPolicyFile(path string, pubKey ed25519.PublicKey) (loadedPolicyFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return loadedPolicyFile{}, fmt.Errorf("policy: read %s: %w", path, err)
	}
	return loadPolicyBytes(raw, path, pubKey)
}

func loadPolicyBytes(raw []byte, source string, pubKey ed25519.PublicKey) (loadedPolicyFile, error) {
	if pubKey != nil {
		if err := corepolicy.VerifyPack(raw, pubKey); err != nil {
			return loadedPolicyFile{}, fmt.Errorf("policy: %s: %w", source, err)
		}
	}
	content, _, _ := corepolicy.SplitSignature(raw)

	var meta struct {
		Kind string `yaml:"kind"`
	}
	if err := yaml.Unmarshal(content, &meta); err != nil {
		return loadedPolicyFile{}, fmt.Errorf("policy: parse kind %s: %w", source, err)
	}

	switch meta.Kind {
	case policyFileKindLocalRuntime:
		var pp corepolicy.PolicyPack
		if err := yaml.Unmarshal(content, &pp); err != nil {
			return loadedPolicyFile{}, fmt.Errorf("policy: parse %s: %w", source, err)
		}
		if err := pp.Validate(); err != nil {
			return loadedPolicyFile{}, fmt.Errorf("policy: validate %s: %w", source, err)
		}
		return loadedPolicyFile{Kind: meta.Kind, Local: &pp}, nil

	case contracts.KindRuntimePolicyPack:
		pack, err := parseRuntimePolicyPack(content)
		if err != nil {
			return loadedPolicyFile{}, fmt.Errorf("policy: parse runtime pack %s: %w", source, err)
		}
		return loadedPolicyFile{Kind: meta.Kind, Runtime: &pack}, nil

	default:
		return loadedPolicyFile{}, fmt.Errorf("policy: unsupported kind %q in %s", meta.Kind, source)
	}
}

func parseRuntimePolicyPack(content []byte) (contracts.RuntimePolicyPack, error) {
	jsonBytes, err := yamlBytesToJSON(content)
	if err != nil {
		return contracts.RuntimePolicyPack{}, err
	}
	var pack contracts.RuntimePolicyPack
	if err := json.Unmarshal(jsonBytes, &pack); err != nil {
		return contracts.RuntimePolicyPack{}, err
	}
	if pack.APIVersion != contracts.RuntimeAPIVersion {
		return contracts.RuntimePolicyPack{}, fmt.Errorf("unsupported apiVersion %q (want %q)", pack.APIVersion, contracts.RuntimeAPIVersion)
	}
	if pack.Kind != contracts.KindRuntimePolicyPack {
		return contracts.RuntimePolicyPack{}, fmt.Errorf("unsupported kind %q (want %q)", pack.Kind, contracts.KindRuntimePolicyPack)
	}
	return pack, nil
}

func yamlBytesToJSON(content []byte) ([]byte, error) {
	var v any
	if err := yaml.Unmarshal(content, &v); err != nil {
		return nil, err
	}
	out, err := json.Marshal(normalizeYAMLValue(v))
	if err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeYAMLValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[k] = normalizeYAMLValue(v)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, v := range x {
			out[fmt.Sprint(k)] = normalizeYAMLValue(v)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = normalizeYAMLValue(v)
		}
		return out
	default:
		return x
	}
}

func (p loadedPolicyFile) Name() string {
	switch {
	case p.Local != nil:
		return p.Local.Metadata.Name
	case p.Runtime != nil:
		return p.Runtime.Metadata.Name
	default:
		return ""
	}
}

func (p loadedPolicyFile) IssuedAt() (time.Time, bool) {
	switch {
	case p.Local != nil:
		return p.Local.Metadata.ParseIssuedAt()
	case p.Runtime != nil && !p.Runtime.Metadata.IssuedAt.IsZero():
		return p.Runtime.Metadata.IssuedAt, true
	default:
		return time.Time{}, false
	}
}

func applyLoadedPolicyToCfg(p loadedPolicyFile, c *cfg) {
	switch {
	case p.Local != nil:
		applyPolicyPackToCfg(p.Local, c)
		rulesFromPolicyPack(p.Local, c)
	case p.Runtime != nil:
		applyRuntimePolicyPackToCfg(*p.Runtime, c)
	}
}

func applyRuntimePolicyPackToCfg(pack contracts.RuntimePolicyPack, c *cfg) {
	c.RuntimeGuardrails = append([]contracts.RuntimeGuardrail(nil), pack.Spec.Guardrails...)
	caps := runtimePolicyCapabilities(pack)
	if len(caps) > 0 {
		c.CapabilitiesRequired = make(map[string]bool, len(caps))
		for _, cap := range caps {
			c.CapabilitiesRequired[cap] = true
		}
		c.PolicyMaxAction = deriveRuntimePolicyMaxAction(pack, caps)
		c.GraphFreezeAllowBlock = runtimePolicyAllowsBlock(pack, caps)
		c.GraphFreezeMaxAction = c.PolicyMaxAction
	}
	c.HasPolicyPack = true
}

func runtimePolicyAllowsBlock(pack contracts.RuntimePolicyPack, caps []string) bool {
	if isBlockAllowed(caps) {
		return true
	}
	for _, rule := range pack.Spec.Rules {
		if runtimeActionLevel(rule.Then) == "block" {
			return true
		}
	}
	return false
}

func runtimePolicyCapabilities(pack contracts.RuntimePolicyPack) []string {
	seen := make(map[string]bool)
	var out []string
	add := func(cap string) {
		cap = normalizeCapabilityID(cap)
		if cap == "" || seen[cap] {
			return
		}
		seen[cap] = true
		out = append(out, cap)
	}
	for _, cap := range pack.Spec.CapabilitiesRequired {
		add(cap)
	}
	for _, rule := range pack.Spec.Rules {
		add(rule.Then.Capability)
	}
	return out
}

func deriveRuntimePolicyMaxAction(pack contracts.RuntimePolicyPack, caps []string) string {
	maxSev := 0
	for _, cap := range caps {
		if sev := capabilitySeverityKLIQ[cap]; sev > maxSev {
			maxSev = sev
		}
	}
	for _, rule := range pack.Spec.Rules {
		sev := capabilitySeverityKLIQ[normalizeCapabilityID(rule.Then.Capability)]
		switch runtimeActionLevel(rule.Then) {
		case "block":
			sev = 3
		case "hard":
			if sev < 2 {
				sev = 2
			}
		case "soft":
			if sev < 1 {
				sev = 1
			}
		}
		if sev > maxSev {
			maxSev = sev
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
		return ""
	}
}
