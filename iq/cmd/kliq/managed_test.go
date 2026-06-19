// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	registries "github.com/kernloom/kernloom-registries"
	"github.com/kernloom/kernloom/iq/internal/lifecycle/bootstrapautotune"
	lgraph "github.com/kernloom/kernloom/iq/internal/lifecycle/graph"
	corepolicy "github.com/kernloom/kernloom/pkg/core/policy"
)

func TestApplyBundleUpdate_ManagedRejectsUnsignedBundle(t *testing.T) {
	c, _, ms, bsCtl, graphCtl := managedBundleTestHarness(t)
	unsigned := contractsRuntimeBundleFixture(t, 1)
	unsigned.Signature = contracts.Signature{}
	raw, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal unsigned bundle: %v", err)
	}

	applyBundleUpdate(raw, c, &bsCtl, &graphCtl, ms, nil, nil)

	if ms.BundleGeneration != 0 {
		t.Fatalf("unsigned bundle applied generation=%d", ms.BundleGeneration)
	}
	if c.PolicyMaxAction != "" {
		t.Fatalf("unsigned bundle changed PolicyMaxAction=%q", c.PolicyMaxAction)
	}
}

func TestApplyBundleUpdate_RejectsSameGenerationDifferentHash(t *testing.T) {
	c, priv, ms, bsCtl, graphCtl := managedBundleTestHarness(t)
	first := signContractsRuntimeBundleFixture(t, contractsRuntimeBundleFixture(t, 1), priv)

	applyBundleUpdate(first, c, &bsCtl, &graphCtl, ms, nil, nil)

	if ms.BundleGeneration != 1 {
		t.Fatalf("first bundle did not apply generation=%d", ms.BundleGeneration)
	}
	firstHash := ms.BundleHash
	firstMaxAction := c.PolicyMaxAction

	mutated := contractsRuntimeBundleFixture(t, 1)
	mutated.Spec.EnforcementBounds.MaxActionDuringBootstrap = "block"
	applyBundleUpdate(signContractsRuntimeBundleFixture(t, mutated, priv), c, &bsCtl, &graphCtl, ms, nil, nil)

	if ms.BundleHash != firstHash {
		t.Fatalf("same-generation mutation changed hash: got %s want %s", ms.BundleHash, firstHash)
	}
	if c.PolicyMaxAction != firstMaxAction {
		t.Fatalf("same-generation mutation changed max action: got %q", c.PolicyMaxAction)
	}
}

func TestApplyBundleUpdate_AppliesSignedNewGeneration(t *testing.T) {
	c, priv, ms, bsCtl, graphCtl := managedBundleTestHarness(t)

	applyBundleUpdate(signContractsRuntimeBundleFixture(t, contractsRuntimeBundleFixture(t, 1), priv), c, &bsCtl, &graphCtl, ms, nil, nil)
	next := contractsRuntimeBundleFixture(t, 2)
	next.Spec.EnforcementBounds.MaxActionDuringBootstrap = "rate_limit"
	applyBundleUpdate(signContractsRuntimeBundleFixture(t, next, priv), c, &bsCtl, &graphCtl, ms, nil, nil)

	if ms.BundleGeneration != 2 {
		t.Fatalf("new generation did not apply: got %d", ms.BundleGeneration)
	}
	if c.PolicyMaxAction != "rate_limit" {
		t.Fatalf("new generation max action: got %q", c.PolicyMaxAction)
	}
}

func TestApplyBundleUpdate_AppliesSignedContractsRuntimeBundle(t *testing.T) {
	c, priv, ms, bsCtl, graphCtl := managedBundleTestHarness(t)
	updates := make(chan contracts.RuntimePolicyPack, 1)

	raw := signContractsRuntimeBundleFixture(t, contractsRuntimeBundleFixture(t, 1), priv)
	applyBundleUpdate(raw, c, &bsCtl, &graphCtl, ms, nil, updates)

	if ms.BundleGeneration != 1 {
		t.Fatalf("contracts bundle did not apply generation=%d", ms.BundleGeneration)
	}
	if c.HasPolicyPack != true {
		t.Fatalf("contracts bundle did not mark policy pack active")
	}
	if c.PolicyMaxAction != "rate_limit_hard" {
		t.Fatalf("runtime pack max action: got %q", c.PolicyMaxAction)
	}
	if c.ProfileName != "contracts-runtime" {
		t.Fatalf("runtime PDP profile not applied: got %q", c.ProfileName)
	}
	if c.Adapters != "klshield" {
		t.Fatalf("adapter selector not applied: got %q", c.Adapters)
	}
	if c.FailMode != "fail_static" {
		t.Fatalf("failover not applied: got %q", c.FailMode)
	}
	if graphCtl.Phase() != lgraph.PhaseLearning {
		t.Fatalf("graph lifecycle phase: got %q", graphCtl.Phase())
	}
	select {
	case pack := <-updates:
		if len(pack.Spec.Rules) != 1 {
			t.Fatalf("queued pack rule count=%d", len(pack.Spec.Rules))
		}
	case <-time.After(time.Second):
		t.Fatal("runtime policy pack was not queued")
	}
}

func managedBundleTestHarness(t *testing.T) (*cfg, ed25519.PrivateKey, *managedState, *bootstrapautotune.Controller, *lgraph.Controller) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "forge.pub")
	if err := os.WriteFile(keyPath, encodePublicKeyPEM(pub), 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	c := &cfg{
		Mode:                string(corepolicy.ModeManaged),
		PolicyVerifyKeyPath: keyPath,
	}
	ms := &managedState{}
	bsCtl := bootstrapautotune.New(bootstrapautotune.DefaultConfig(), nil)
	graphCtl := lgraph.New(lgraph.DefaultConfig(), "", time.Time{})
	return c, priv, ms, bsCtl, graphCtl
}

func contractsRuntimeBundleFixture(t *testing.T, generation int) contracts.RuntimeBundle {
	t.Helper()
	issued := time.Now().UTC().Add(-time.Hour)
	return contracts.RuntimeBundle{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimeBundle,
		},
		Metadata: contracts.ObjectMeta{
			Name:       "contracts-fixture",
			NodeID:     "node-test",
			Generation: generation,
			IssuedAt:   issued,
			ExpiresAt:  issued.Add(24 * time.Hour),
		},
		Spec: contracts.RuntimeBundleSpec{
			Registry:         registrySnapshotFixture(t).Ref,
			RegistrySnapshot: registrySnapshotFixture(t),
			RuntimePDPProfile: contracts.RuntimePDPProfile{
				Name: "contracts-runtime",
				Mode: "active",
			},
			AdapterSelector: contracts.AdapterSelector{
				PreferredAdapters: []string{"klshield"},
				RequiredCapabilities: []string{
					"enforce.traffic.rate_limit",
				},
			},
			RuntimePolicyPack: contracts.RuntimePolicyPack{
				TypeMeta: contracts.TypeMeta{
					APIVersion: contracts.RuntimeAPIVersion,
					Kind:       contracts.KindRuntimePolicyPack,
				},
				Metadata: contracts.ObjectMeta{Name: "contracts-pack", IssuedAt: issued},
				Spec: contracts.RuntimePolicyPackSpec{
					CapabilitiesRequired: []string{"enforce.traffic.rate_limit"},
					DefaultEffect:        "deny",
					Rules: []contracts.RuntimePolicyRule{{
						ID:   "risk-high",
						When: "risk.level in ['high', 'critical']",
						Then: contracts.RuntimeActionSpec{
							Capability: "enforce.traffic.rate_limit",
							Level:      "hard",
							TTL:        contracts.NewDuration(time.Minute),
						},
					}},
				},
			},
			BaselineLifecycle: contracts.BaselineLifecycle{
				Mode:           "managed",
				LearningWindow: contracts.NewDuration(48 * time.Hour),
			},
			GraphLifecycle: contracts.GraphLifecycle{
				Mode:                "managed",
				MinCleanLearning:    contracts.NewDuration(12 * time.Hour),
				MinLearnedEdges:     5,
				ObserveAfterFreeze:  contracts.NewDuration(24 * time.Hour),
				FinalPhase:          lgraph.PhaseFrozenEnforce,
				FreezeApproval:      "forge-auto",
				RequireNoBlockFor:   contracts.NewDuration(time.Hour),
				MinBaselineCoverage: 0.7,
			},
			EnforcementBounds: contracts.EnforcementBounds{
				AllowBlock: false,
			},
			Failover: contracts.FailoverConfig{Behavior: "fail_static"},
		},
	}
}

func registrySnapshotFixture(t *testing.T) contracts.RegistrySnapshot {
	t.Helper()
	snapshot, err := registries.EmbeddedSnapshot()
	if err != nil {
		t.Fatalf("registry snapshot: %v", err)
	}
	return snapshot
}

func signContractsRuntimeBundleFixture(t *testing.T, b contracts.RuntimeBundle, priv ed25519.PrivateKey) []byte {
	t.Helper()
	signed, err := contracts.SignRuntimeBundle(b, "test-key", priv)
	if err != nil {
		t.Fatalf("sign contracts bundle: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal contracts bundle: %v", err)
	}
	return raw
}

func encodePublicKeyPEM(pub ed25519.PublicKey) []byte {
	return []byte("-----BEGIN KERNLOOM ED25519 PUBLIC KEY-----\n" +
		base64.StdEncoding.EncodeToString(pub) + "\n" +
		"-----END KERNLOOM ED25519 PUBLIC KEY-----\n")
}
