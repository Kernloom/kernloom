// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom/pkg/core/policy"
)

func writeYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "policy-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

const validPolicyYAML = `
apiVersion: kernloom.io/kliq/v1alpha1
kind: LocalPolicyPack
metadata:
  name: test-policy
spec:
  autonomy:
    dry_run: false
    max_action: block
    allow_local_block: true
  rules:
    - name: soft
      when:
        fsm_level: soft
      then:
        action: rate_limit
        capability: network.rate_limit_source
        ttl: "60s"
    - name: block
      when:
        fsm_level: block
      then:
        action: block
        capability: network.block_source
        ttl: "30m"
`

func TestLoadFromFile_Valid(t *testing.T) {
	path := writeYAML(t, validPolicyYAML)
	pp, err := policy.LoadFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pp.Metadata.Name != "test-policy" {
		t.Errorf("expected name test-policy, got %s", pp.Metadata.Name)
	}
	if len(pp.Spec.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(pp.Spec.Rules))
	}
	if pp.Spec.Rules[0].Then.TTL.D.Seconds() != 60 {
		t.Errorf("expected soft TTL 60s, got %s", pp.Spec.Rules[0].Then.TTL.D)
	}
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := policy.LoadFromFile(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestValidate_MissingName(t *testing.T) {
	yaml := `
apiVersion: kernloom.io/kliq/v1alpha1
kind: LocalPolicyPack
metadata:
  name: ""
spec:
  rules:
    - name: r
      when: {fsm_level: soft}
      then: {action: rate_limit, capability: net.rl}
`
	_, err := policy.LoadFromFile(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for missing name")
	}
}

func TestValidate_NoRules(t *testing.T) {
	yaml := `
apiVersion: kernloom.io/kliq/v1alpha1
kind: LocalPolicyPack
metadata:
  name: empty
spec:
  rules: []
`
	_, err := policy.LoadFromFile(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for empty rules")
	}
}

func TestValidate_InvalidMaxAction(t *testing.T) {
	yaml := `
apiVersion: kernloom.io/kliq/v1alpha1
kind: LocalPolicyPack
metadata:
  name: bad-action
spec:
  autonomy:
    max_action: nuke
  rules:
    - name: r
      when: {fsm_level: soft}
      then: {action: rate_limit, capability: net.rl}
`
	_, err := policy.LoadFromFile(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for invalid max_action")
	}
}

func TestValidate_WrongKind(t *testing.T) {
	yaml := `
apiVersion: kernloom.io/kliq/v1alpha1
kind: WrongKind
metadata:
  name: x
spec:
  rules:
    - name: r
      when: {fsm_level: soft}
      then: {action: rate_limit, capability: net.rl}
`
	_, err := policy.LoadFromFile(writeYAML(t, yaml))
	if err == nil {
		t.Fatal("expected validation error for wrong kind")
	}
}

func TestRulesTTLParsed(t *testing.T) {
	path := writeYAML(t, validPolicyYAML)
	pp, err := policy.LoadFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blockRule := pp.Spec.Rules[1]
	if blockRule.Then.TTL.D.Minutes() != 30 {
		t.Errorf("expected block TTL 30m, got %s", blockRule.Then.TTL.D)
	}
}
