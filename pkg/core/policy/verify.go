// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	pubKeyPEMType  = "KERNLOOM ED25519 PUBLIC KEY"
	privKeyPEMType = "KERNLOOM ED25519 PRIVATE KEY"
)

// signatureMarker is the YAML key that carries the pack signature.
// It must be the last line of a signed pack file.
const signatureMarker = "\nsignature: "

// SplitSignature separates the raw content bytes (what was signed) from the
// base64-encoded Ed25519 signature appended by Forge.
//
// Returns (content, sig, true) when a signature line is found, or
// (data, nil, false) when the file is unsigned.
func SplitSignature(data []byte) (content, sig []byte, found bool) {
	marker := []byte(signatureMarker)
	idx := bytes.LastIndex(data, marker)
	if idx < 0 {
		return data, nil, false
	}
	content = data[:idx+1] // include the \n that precedes "signature:"
	sigLine := bytes.TrimRight(data[idx+len(marker):], "\n\r ")
	decoded, err := base64.StdEncoding.DecodeString(string(sigLine))
	if err != nil {
		return data, nil, false
	}
	return content, decoded, true
}

// VerifyPack verifies the Ed25519 signature of a raw pack file.
// data is the full file content (including the signature line).
// Returns nil if the signature is valid, an error otherwise.
func VerifyPack(data []byte, pubKey ed25519.PublicKey) error {
	content, sig, found := SplitSignature(data)
	if !found {
		return fmt.Errorf("policy pack is not signed (signature line missing)")
	}
	if !ed25519.Verify(pubKey, content, sig) {
		return fmt.Errorf("policy pack signature verification failed")
	}
	return nil
}

// LoadPublicKey reads a PEM-encoded Ed25519 public key from path.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read public key %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pubKeyPEMType {
		return nil, fmt.Errorf("invalid public key file %s: expected PEM type %q", path, pubKeyPEMType)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: got %d bytes, want %d", len(block.Bytes), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(block.Bytes), nil
}
