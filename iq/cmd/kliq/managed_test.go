// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/lifecycle/bootstrapautotune"
	lgraph "github.com/kernloom/kernloom/iq/internal/lifecycle/graph"
	"github.com/kernloom/kernloom/pkg/core/bundle"
	corepolicy "github.com/kernloom/kernloom/pkg/core/policy"
	"gopkg.in/yaml.v3"
)

func TestApplyBundleUpdate_ManagedRejectsUnsignedBundle(t *testing.T) {
	c, _, ms, bsCtl, graphCtl := managedBundleTestHarness(t)
	unsigned := runtimeBundleFixture(t, 1)
	unsigned.Signature = bundle.BundleSignature{}
	raw, err := yaml.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal unsigned bundle: %v", err)
	}

	applyBundleUpdate(raw, c, &bsCtl, &graphCtl, ms, nil)

	if ms.BundleGeneration != 0 {
		t.Fatalf("unsigned bundle applied generation=%d", ms.BundleGeneration)
	}
	if c.PolicyMaxAction != "" {
		t.Fatalf("unsigned bundle changed PolicyMaxAction=%q", c.PolicyMaxAction)
	}
}

func TestApplyBundleUpdate_RejectsSameGenerationDifferentHash(t *testing.T) {
	c, priv, ms, bsCtl, graphCtl := managedBundleTestHarness(t)
	first := signRuntimeBundleFixture(t, runtimeBundleFixture(t, 1), priv)

	applyBundleUpdate(first, c, &bsCtl, &graphCtl, ms, nil)

	if ms.BundleGeneration != 1 {
		t.Fatalf("first bundle did not apply generation=%d", ms.BundleGeneration)
	}
	firstHash := ms.BundleHash

	mutated := runtimeBundleFixture(t, 1)
	mutated.Spec.EnforcementBounds.MaxActionDuringBootstrap = "block"
	applyBundleUpdate(signRuntimeBundleFixture(t, mutated, priv), c, &bsCtl, &graphCtl, ms, nil)

	if ms.BundleHash != firstHash {
		t.Fatalf("same-generation mutation changed hash: got %s want %s", ms.BundleHash, firstHash)
	}
	if c.PolicyMaxAction != "observe" {
		t.Fatalf("same-generation mutation changed max action: got %q", c.PolicyMaxAction)
	}
}

func TestApplyBundleUpdate_AppliesSignedNewGeneration(t *testing.T) {
	c, priv, ms, bsCtl, graphCtl := managedBundleTestHarness(t)

	applyBundleUpdate(signRuntimeBundleFixture(t, runtimeBundleFixture(t, 1), priv), c, &bsCtl, &graphCtl, ms, nil)
	next := runtimeBundleFixture(t, 2)
	next.Spec.EnforcementBounds.MaxActionDuringBootstrap = "rate_limit"
	applyBundleUpdate(signRuntimeBundleFixture(t, next, priv), c, &bsCtl, &graphCtl, ms, nil)

	if ms.BundleGeneration != 2 {
		t.Fatalf("new generation did not apply: got %d", ms.BundleGeneration)
	}
	if c.PolicyMaxAction != "rate_limit" {
		t.Fatalf("new generation max action: got %q", c.PolicyMaxAction)
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

func runtimeBundleFixture(t *testing.T, generation int) *bundle.RuntimeBundle {
	t.Helper()
	issued := time.Now().UTC().Add(-time.Hour)
	return &bundle.RuntimeBundle{
		APIVersion: bundle.BundleAPIVersion,
		Kind:       bundle.BundleKind,
		Metadata: bundle.BundleMetadata{
			NodeID:     "node-test",
			Generation: generation,
			IssuedAt:   issued.Add(time.Duration(generation) * time.Minute).Format(time.RFC3339),
			ExpiresAt:  issued.Add(24 * time.Hour).Format(time.RFC3339),
		},
		Spec: bundle.BundleSpec{
			EnforcementBounds: bundle.EnforcementBounds{
				MaxActionDuringBootstrap: "observe",
			},
		},
	}
}

func signRuntimeBundleFixture(t *testing.T, b *bundle.RuntimeBundle, priv ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := b.SigningPayload()
	if err != nil {
		t.Fatalf("signing payload: %v", err)
	}
	b.Signature = bundle.BundleSignature{
		Algorithm: "ed25519",
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	}
	raw, err := yaml.Marshal(b)
	if err != nil {
		t.Fatalf("marshal signed bundle: %v", err)
	}
	return raw
}

func encodePublicKeyPEM(pub ed25519.PublicKey) []byte {
	return []byte("-----BEGIN KERNLOOM ED25519 PUBLIC KEY-----\n" +
		base64.StdEncoding.EncodeToString(pub) + "\n" +
		"-----END KERNLOOM ED25519 PUBLIC KEY-----\n")
}
