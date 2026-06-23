// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	contracts "github.com/kernloom/kernloom-contracts"
)

const runtimePolicyYAML = `apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
metadata:
  name: runtime-pack
  issued_at: "2026-06-19T10:00:00Z"
spec:
  default_effect: deny
  capabilities_required:
    - enforce.traffic.rate_limit
  autonomy_lifecycle:
    hold:
      - id: hold-enforcement-feedback
        while:
          enforcement_feedback_active: true
          levels: [soft, hard, block]
        action:
          capability: enforce.traffic.rate_limit
          level: hard
          ttl: "30s"
          params:
            rate_pps: 100
        reason_codes:
          - enforcement_hold
    step_down:
      clean_after: "30s"
      observe_after: "2m"
    max_renewals: 3
  guardrails:
    - id: never-auto-block-admins
      type: never
      subject:
        type: group
        ref: kernloom-admins
      forbidden_actions:
        - enforce.access.deny
      enforcement:
        violation_behavior: reject_action
        unknown_behavior: reject_hard_action
  detection_rules:
    - id: admin-deny
      type: access.denied_threshold
      subject:
        type: group
        ref: kernloom-admins
      resource_ref: ziti-controller
      threshold: 5
      window: 15m
      scope: source
  response_rules:
    - id: denied-access-alert
      when:
        detection: admin-deny
      then:
        - id: notify.alert.emit
          route: alert-route.security-ops
          severity: medium
          dedupe: 15m
  alert_routes:
    - id: alert-route.security-ops
      channels:
        - type: slack
          ref: channel.security-ops
      default_severity: medium
  rules:
    - id: high-risk
      when: "risk.level == 'high'"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "2m"
      reason_codes:
        - risk_high
`

func TestLoadPolicyBytesRecognizesRuntimePolicyPack(t *testing.T) {
	loaded, err := loadPolicyBytes([]byte(runtimePolicyYAML), "runtime-policy.yaml", nil)
	if err != nil {
		t.Fatalf("loadPolicyBytes: %v", err)
	}
	if loaded.Kind != contracts.KindRuntimePolicyPack || loaded.Runtime == nil {
		t.Fatalf("expected runtime policy pack, got kind=%q local=%v runtime=%v", loaded.Kind, loaded.Local != nil, loaded.Runtime != nil)
	}
	if loaded.Runtime.Metadata.Name != "runtime-pack" {
		t.Fatalf("name: %q", loaded.Runtime.Metadata.Name)
	}

	var c cfg
	applyLoadedPolicyToCfg(loaded, &c)
	if !c.HasPolicyPack {
		t.Fatal("runtime policy pack should satisfy managed policy gate")
	}
	if !c.CapabilitiesRequired["enforce.traffic.rate_limit"] {
		t.Fatalf("capabilities not applied: %#v", c.CapabilitiesRequired)
	}
	if c.PolicyMaxAction != "rate_limit_hard" {
		t.Fatalf("max action: %q", c.PolicyMaxAction)
	}
	if len(c.RuntimeGuardrails) != 1 || c.RuntimeGuardrails[0].ID != "never-auto-block-admins" {
		t.Fatalf("guardrails not applied: %#v", c.RuntimeGuardrails)
	}
	if len(c.RuntimeDetectionRules) != 1 || c.RuntimeDetectionRules[0].ID != "admin-deny" {
		t.Fatalf("detection rules not applied: %#v", c.RuntimeDetectionRules)
	}
	if len(c.RuntimeResponseRules) != 1 || c.RuntimeResponseRules[0].When.Detection != "admin-deny" || c.RuntimeResponseRules[0].Then[0].Route != "alert-route.security-ops" {
		t.Fatalf("response rules not applied: %#v", c.RuntimeResponseRules)
	}
	if len(c.RuntimeAlertRoutes) != 1 || c.RuntimeAlertRoutes[0].ID != "alert-route.security-ops" {
		t.Fatalf("alert routes not applied: %#v", c.RuntimeAlertRoutes)
	}
	if c.RuntimeAutonomyLifecycle == nil || len(c.RuntimeAutonomyLifecycle.Hold) != 1 {
		t.Fatalf("autonomy lifecycle not applied: %#v", c.RuntimeAutonomyLifecycle)
	}
	if got := c.RuntimeAutonomyLifecycle.Hold[0].Action.TTL.Duration.String(); got != "30s" {
		t.Fatalf("autonomy hold ttl: %s", got)
	}
}

func TestLoadPolicyBytesVerifiesSignedRuntimePolicyPack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed := signPolicyBytesForTest([]byte(runtimePolicyYAML), priv)

	if _, err := loadPolicyBytes(signed, "runtime-policy.yaml", pub); err != nil {
		t.Fatalf("signed runtime policy should verify: %v", err)
	}
	tampered := append([]byte{}, signed...)
	tampered[0] = 'X'
	if _, err := loadPolicyBytes(tampered, "runtime-policy.yaml", pub); err == nil {
		t.Fatal("tampered signed runtime policy should fail")
	}
}

func TestLoadPolicyBytesRejectsUnsupportedKind(t *testing.T) {
	_, err := loadPolicyBytes([]byte("apiVersion: kernloom.io/runtime/v1alpha1\nkind: Nope\n"), "bad.yaml", nil)
	if err == nil {
		t.Fatal("expected unsupported kind error")
	}
}

func signPolicyBytesForTest(content []byte, priv ed25519.PrivateKey) []byte {
	if len(content) == 0 || content[len(content)-1] != '\n' {
		content = append(content, '\n')
	}
	sig := ed25519.Sign(priv, content)
	out := append([]byte{}, content...)
	out = append(out, []byte("signature: "+base64.StdEncoding.EncodeToString(sig)+"\n")...)
	return out
}
