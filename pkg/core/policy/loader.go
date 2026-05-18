// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package policy

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadFromFile reads a LocalPolicyPack from a YAML file, validates it, and
// returns the parsed struct. Signature lines are parsed but NOT verified —
// use LoadAndVerify when signature verification is required.
func LoadFromFile(path string) (*PolicyPack, error) {
	return loadFromFile(path, nil)
}

// LoadAndVerify reads a LocalPolicyPack and verifies its Ed25519 signature
// against pubKey. Returns an error when the pack is unsigned or the signature
// is invalid. Use this in managed mode where pack authenticity is mandatory.
func LoadAndVerify(path string, pubKey ed25519.PublicKey) (*PolicyPack, error) {
	return loadFromFile(path, pubKey)
}

func loadFromFile(path string, pubKey ed25519.PublicKey) (*PolicyPack, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}

	// Signature verification before parsing (covers the full pack content).
	if pubKey != nil {
		if err := VerifyPack(raw, pubKey); err != nil {
			return nil, fmt.Errorf("policy: %s: %w", path, err)
		}
	}

	// Strip signature line before YAML parsing — yaml.v3 would reject an
	// unknown top-level field if strict mode is used, and it's not part of
	// the pack schema.
	content, _, _ := SplitSignature(raw)

	var pp PolicyPack
	if err := yaml.Unmarshal(content, &pp); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", path, err)
	}
	if err := pp.Validate(); err != nil {
		return nil, fmt.Errorf("policy: validate %s: %w", path, err)
	}
	return &pp, nil
}
