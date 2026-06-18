// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// VerifyRuntimeBundle parses data as a RuntimeBundle and verifies its Ed25519
// signature over the canonical unsigned bundle payload.
func VerifyRuntimeBundle(data []byte, pubKey ed25519.PublicKey) (*RuntimeBundle, error) {
	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("runtime bundle: invalid public key size: got %d bytes, want %d", len(pubKey), ed25519.PublicKeySize)
	}

	b, err := Parse(data)
	if err != nil {
		return nil, err
	}
	if err := b.Verify(pubKey); err != nil {
		return nil, err
	}
	return b, nil
}

// Verify verifies the bundle signature over the canonical unsigned payload.
func (b *RuntimeBundle) Verify(pubKey ed25519.PublicKey) error {
	if !strings.EqualFold(b.Signature.Algorithm, "ed25519") {
		if b.Signature.Algorithm == "" {
			return fmt.Errorf("runtime bundle is not signed (signature.algorithm missing)")
		}
		return fmt.Errorf("runtime bundle: unsupported signature algorithm %q", b.Signature.Algorithm)
	}
	if b.Signature.Value == "" {
		return fmt.Errorf("runtime bundle is not signed (signature.value missing)")
	}

	sig, err := base64.StdEncoding.DecodeString(b.Signature.Value)
	if err != nil {
		return fmt.Errorf("runtime bundle: decode signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("runtime bundle: invalid signature size: got %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	payload, err := b.SigningPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubKey, payload, sig) {
		return fmt.Errorf("runtime bundle signature verification failed")
	}
	return nil
}

// SigningPayload returns the canonical bytes signed by Forge.
func (b *RuntimeBundle) SigningPayload() ([]byte, error) {
	unsigned := struct {
		APIVersion string         `yaml:"apiVersion" json:"apiVersion"`
		Kind       string         `yaml:"kind"       json:"kind"`
		Metadata   BundleMetadata `yaml:"metadata"   json:"metadata"`
		Spec       BundleSpec     `yaml:"spec"       json:"spec"`
	}{
		APIVersion: b.APIVersion,
		Kind:       b.Kind,
		Metadata:   b.Metadata,
		Spec:       b.Spec,
	}
	payload, err := yaml.Marshal(unsigned)
	if err != nil {
		return nil, fmt.Errorf("runtime bundle: canonicalize signing payload: %w", err)
	}
	return payload, nil
}
