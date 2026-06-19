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
