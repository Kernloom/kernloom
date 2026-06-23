// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package conformance_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	registries "github.com/kernloom/kernloom-registries"
	"github.com/kernloom/kernloom/iq/internal/conformance"
)

func TestValidateRuntimeBundleSignedFixture(t *testing.T) {
	pub, priv := keypair(t)
	bundle := signBundle(t, validBundle("shadow", "enforce.traffic.rate_limit", "soft", "fail_static"), priv)

	err := conformance.ValidateRuntimeBundle(bundle, pub, nodeRuntime("rate_limit"))
	if err != nil {
		t.Fatalf("valid signed fixture rejected: %v", err)
	}
}

func TestValidateRuntimeBundleRejectsUnsupportedSchema(t *testing.T) {
	pub, priv := keypair(t)
	bundle := validBundle("shadow", "enforce.traffic.rate_limit", "soft", "fail_static")
	bundle.APIVersion = "kernloom.io/runtime/v9"
	bundle = signBundle(t, bundle, priv)

	err := conformance.ValidateRuntimeBundle(bundle, pub, nodeRuntime("rate_limit"))
	if err == nil || !strings.Contains(err.Error(), "apiVersion") {
		t.Fatalf("expected unsupported apiVersion error, got %v", err)
	}
}

func TestValidateRuntimeBundleRejectsMissingCapability(t *testing.T) {
	pub, priv := keypair(t)
	bundle := signBundle(t, validBundle("shadow", "enforce.traffic.rate_limit", "soft", "fail_static"), priv)
	node := nodeRuntime("rate_limit")
	node.Capabilities = map[string]bool{"enforce.access.allow": true}

	err := conformance.ValidateRuntimeBundle(bundle, pub, node)
	if err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("expected missing capability error, got %v", err)
	}
}

func TestValidateRuntimeBundleRejectsUnsupportedCapability(t *testing.T) {
	pub, priv := keypair(t)
	bundle := signBundle(t, validBundle("shadow", "enforce.unknown.magic", "soft", "fail_static"), priv)
	node := nodeRuntime("rate_limit")
	node.Capabilities["enforce.unknown.magic"] = true

	err := conformance.ValidateRuntimeBundle(bundle, pub, node)
	if err == nil || !strings.Contains(err.Error(), "unknown runtime action capability") {
		t.Fatalf("expected unsupported capability error, got %v", err)
	}
}

func TestValidateRuntimeBundleRejectsActionAboveBounds(t *testing.T) {
	pub, priv := keypair(t)
	bundle := signBundle(t, validBundle("shadow", "enforce.access.deny", "block", "fail_static"), priv)
	node := nodeRuntime("rate_limit")
	node.Capabilities["enforce.access.deny"] = true

	err := conformance.ValidateRuntimeBundle(bundle, pub, node)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected action bounds error, got %v", err)
	}
}

func TestValidateRuntimeBundleRejectsUnsupportedMode(t *testing.T) {
	pub, priv := keypair(t)
	bundle := signBundle(t, validBundle("active", "enforce.traffic.rate_limit", "soft", "fail_static"), priv)
	node := nodeRuntime("rate_limit")
	node.SupportedPDPModes = map[string]bool{"shadow": true}

	err := conformance.ValidateRuntimeBundle(bundle, pub, node)
	if err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("expected unsupported mode error, got %v", err)
	}
}

func TestValidateRuntimePolicyPackAcceptsGenericFactVariables(t *testing.T) {
	pack := validBundle("active", "enforce.traffic.rate_limit", "hard", "fail_static").Spec.RuntimePolicyPack
	pack.Spec.Rules[0].When = strings.Join([]string{
		"risk.score >= 70",
		"metrics.network.packets_per_second > baseline.network.packets_per_second * 2.0",
		"baseline.profile_count >= 1",
		"graph.relationship_count >= 1",
		"adapter.subject_kind == 'ip'",
		"fsm.proposed_level == 'hard'",
		"features.runtime_pdp_mode == 'active'",
	}, " && ")

	err := conformance.ValidateRuntimePolicyPack(pack, nodeRuntime("rate_limit_hard"))
	if err != nil {
		t.Fatalf("generic fact policy rejected: %v", err)
	}
}

func TestValidateRuntimePolicyPackAcceptsAutonomyLifecycleAction(t *testing.T) {
	pack := validBundle("active", "enforce.traffic.rate_limit", "soft", "fail_static").Spec.RuntimePolicyPack
	pack.Spec.CapabilitiesRequired = nil
	pack.Spec.Rules = nil
	pack.Spec.AutonomyLifecycle = &contracts.RuntimeAutonomyLifecycleSpec{
		Hold: []contracts.RuntimeAutonomyHoldRule{{
			ID: "hold-enforcement-feedback",
			While: contracts.RuntimeAutonomyHoldCondition{
				EnforcementFeedbackActive: true,
				Levels:                    []string{"soft", "hard", "block"},
			},
			Action: contracts.RuntimeActionSpec{
				Capability: "enforce.traffic.rate_limit",
				Level:      "hard",
				TTL:        contracts.NewDuration(30 * time.Second),
			},
			ReasonCodes: []string{"enforcement_hold"},
		}},
	}

	err := conformance.ValidateRuntimePolicyPack(pack, nodeRuntime("rate_limit_hard"))
	if err != nil {
		t.Fatalf("autonomy lifecycle policy rejected: %v", err)
	}
}

func TestValidateRuntimePolicyPackRejectsUnknownContextKey(t *testing.T) {
	pack := validBundle("active", "enforce.traffic.rate_limit", "soft", "fail_static").Spec.RuntimePolicyPack
	pack.Spec.Rules[0].When = "device.magic.foo == true"

	err := conformance.ValidateRuntimePolicyPack(pack, nodeRuntime("rate_limit"))
	if err == nil || !strings.Contains(err.Error(), "unknown context key") {
		t.Fatalf("expected unknown context key error, got %v", err)
	}
}

func TestValidateRuntimePolicyPackRejectsRuntimeActionWithoutTTL(t *testing.T) {
	pack := validBundle("active", "enforce.traffic.rate_limit", "soft", "fail_static").Spec.RuntimePolicyPack
	pack.Spec.Rules[0].Then.TTL = contracts.Duration{}

	err := conformance.ValidateRuntimePolicyPack(pack, nodeRuntime("rate_limit"))
	if err == nil || !strings.Contains(err.Error(), "requires ttl") {
		t.Fatalf("expected missing ttl error, got %v", err)
	}
}

func TestValidateRuntimePolicyPackRejectsGrantingRuntimeAction(t *testing.T) {
	pack := validBundle("active", "enforce.traffic.rate_limit", "soft", "fail_static").Spec.RuntimePolicyPack
	pack.Spec.CapabilitiesRequired = []string{"enforce.network.allow"}
	pack.Spec.Rules[0].Then = contracts.RuntimeActionSpec{
		Capability: "enforce.network.allow",
		Level:      "observe",
		TTL:        contracts.NewDuration(time.Minute),
	}
	node := nodeRuntime("")
	node.Capabilities = nil

	err := conformance.ValidateRuntimePolicyPack(pack, node)
	if err == nil || !strings.Contains(err.Error(), "not a runtime action") {
		t.Fatalf("expected grant/runtime-action error, got %v", err)
	}
}

func TestValidateRuntimePolicyPackRejectsInvalidResponseAction(t *testing.T) {
	pack := validBundle("active", "enforce.traffic.rate_limit", "soft", "fail_static").Spec.RuntimePolicyPack
	pack.Spec.DetectionRules = []contracts.RuntimeDetectionRule{{
		ID:   "unknown-source-heavy-deny",
		Type: "access.denied_threshold",
	}}
	pack.Spec.ResponseRules = []contracts.RuntimeResponseRule{{
		ID:   "drop-without-ttl",
		When: contracts.RuntimeResponseTrigger{Detection: "unknown-source-heavy-deny"},
		Then: []contracts.RuntimeResponseAction{{
			ID: "enforce.traffic.drop",
		}},
	}}
	node := nodeRuntime("")
	node.Capabilities["enforce.traffic.drop"] = true

	err := conformance.ValidateRuntimePolicyPack(pack, node)
	if err == nil || !strings.Contains(err.Error(), "requires ttl") {
		t.Fatalf("expected response ttl error, got %v", err)
	}
}

func TestValidateOfflineLastKnownGoodRequiresFailStatic(t *testing.T) {
	pub, priv := keypair(t)
	good := signBundle(t, validBundle("shadow", "enforce.traffic.rate_limit", "soft", "fail_static"), priv)
	if err := conformance.ValidateOfflineLastKnownGood(good, pub, nodeRuntime("rate_limit")); err != nil {
		t.Fatalf("valid LKG rejected: %v", err)
	}

	bad := signBundle(t, validBundle("shadow", "enforce.traffic.rate_limit", "soft", "fail_open"), priv)
	err := conformance.ValidateOfflineLastKnownGood(bad, pub, nodeRuntime("rate_limit"))
	if err == nil || !strings.Contains(err.Error(), "fail_static") {
		t.Fatalf("expected fail_static error, got %v", err)
	}
}

func keypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	return pub, priv
}

func nodeRuntime(maxAction string) conformance.NodeRuntime {
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		panic(err)
	}
	return conformance.NodeRuntime{
		NodeID: "node-1",
		Capabilities: map[string]bool{
			"enforce.traffic.rate_limit": true,
		},
		MaxAction:         maxAction,
		SupportedPDPModes: map[string]bool{"shadow": true, "active": true},
		RegistrySnapshot:  snapshot,
		Now:               time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
	}
}

func validBundle(mode, capability, level, failover string) contracts.RuntimeBundle {
	now := time.Date(2026, 6, 19, 9, 0, 0, 0, time.UTC)
	return contracts.RuntimeBundle{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimeBundle,
		},
		Metadata: contracts.ObjectMeta{
			Name:       "fixture",
			NodeID:     "node-1",
			Generation: 1,
			IssuedAt:   now,
			ExpiresAt:  now.Add(24 * time.Hour),
		},
		Spec: contracts.RuntimeBundleSpec{
			Registry:         snapshotForTest().Ref,
			RegistrySnapshot: snapshotForTest(),
			RuntimePDPProfile: contracts.RuntimePDPProfile{
				Name: "fixture-profile",
				Mode: mode,
			},
			RuntimePolicyPack: contracts.RuntimePolicyPack{
				TypeMeta: contracts.TypeMeta{
					APIVersion: contracts.RuntimeAPIVersion,
					Kind:       contracts.KindRuntimePolicyPack,
				},
				Metadata: contracts.ObjectMeta{Name: "fixture-pack", IssuedAt: now},
				Spec: contracts.RuntimePolicyPackSpec{
					CapabilitiesRequired: []string{capability},
					DefaultEffect:        "deny",
					Rules: []contracts.RuntimePolicyRule{{
						ID:   "risk-rule",
						When: "risk.level in ['high', 'critical']",
						Then: contracts.RuntimeActionSpec{
							Capability: capability,
							Level:      level,
							TTL:        contracts.NewDuration(time.Minute),
						},
						ReasonCodes: []string{"risk_high"},
					}},
				},
			},
			Failover: contracts.FailoverConfig{Behavior: failover},
		},
	}
}

func snapshotForTest() contracts.RegistrySnapshot {
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		panic(err)
	}
	return snapshot
}

func signBundle(t *testing.T, bundle contracts.RuntimeBundle, priv ed25519.PrivateKey) contracts.RuntimeBundle {
	t.Helper()
	signed, err := contracts.SignRuntimeBundle(bundle, "test-key", priv)
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	return signed
}
