// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package policy_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom/pkg/core/policy"
)

// signBytes replicates Forge's signing: sign content, append signature line.
// Content must end with \n (yaml.v3 guarantees this); the split marker
// "\nsignature: " uses that trailing \n as the split point.
func signBytes(content []byte, key ed25519.PrivateKey) []byte {
	if len(content) > 0 && content[len(content)-1] != '\n' {
		content = append(content, '\n')
	}
	sig := ed25519.Sign(key, content)
	line := []byte("signature: " + base64.StdEncoding.EncodeToString(sig) + "\n")
	return append(content, line...)
}

func genKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

const minimalPack = `apiVersion: kernloom.io/v1alpha1
kind: LocalPolicyPack
metadata:
  name: test-pack
spec:
  action_authorization:
    allowed_capabilities:
      - enforce.traffic.rate_limit
    default_effect: deny
  rules:
    - when:
        capability: enforce.traffic.rate_limit
      then:
        capability: enforce.traffic.rate_limit
        ttl: 10m
`

func TestSplitSignature_Unsigned(t *testing.T) {
	data := []byte(minimalPack)
	content, sig, found := policy.SplitSignature(data)
	if found {
		t.Error("unsigned file should not have a signature")
	}
	if string(content) != string(data) {
		t.Error("content should be unchanged for unsigned file")
	}
	if sig != nil {
		t.Error("sig should be nil for unsigned file")
	}
}

func TestSplitSignature_Signed(t *testing.T) {
	_, priv := genKeyPair(t)
	content := []byte(minimalPack)
	signed := signBytes(content, priv)

	extracted, sig, found := policy.SplitSignature(signed)
	if !found {
		t.Fatal("should find signature in signed file")
	}
	if string(extracted) != string(content) {
		t.Error("extracted content should match original unsigned content")
	}
	if len(sig) != ed25519.SignatureSize {
		t.Errorf("signature size: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
}

func TestVerifyPack_Valid(t *testing.T) {
	pub, priv := genKeyPair(t)
	signed := signBytes([]byte(minimalPack), priv)
	if err := policy.VerifyPack(signed, pub); err != nil {
		t.Errorf("valid pack should verify: %v", err)
	}
}

func TestVerifyPack_WrongKey(t *testing.T) {
	_, priv := genKeyPair(t)
	otherPub, _ := genKeyPair(t)
	signed := signBytes([]byte(minimalPack), priv)
	if err := policy.VerifyPack(signed, otherPub); err == nil {
		t.Error("verification with wrong key should fail")
	}
}

func TestVerifyPack_Unsigned(t *testing.T) {
	pub, _ := genKeyPair(t)
	if err := policy.VerifyPack([]byte(minimalPack), pub); err == nil {
		t.Error("unsigned pack should fail verification")
	}
}

func TestLoadAndVerify_Valid(t *testing.T) {
	pub, priv := genKeyPair(t)
	signed := signBytes([]byte(minimalPack), priv)

	f, _ := os.CreateTemp("", "pack-*.yaml")
	defer os.Remove(f.Name())
	f.Write(signed)
	f.Close()

	pp, err := policy.LoadAndVerify(f.Name(), pub)
	if err != nil {
		t.Fatalf("LoadAndVerify: %v", err)
	}
	if pp.Metadata.Name != "test-pack" {
		t.Errorf("name: got %q", pp.Metadata.Name)
	}
}

func TestLoadAndVerify_Unsigned_Fails(t *testing.T) {
	pub, _ := genKeyPair(t)
	f, _ := os.CreateTemp("", "pack-*.yaml")
	defer os.Remove(f.Name())
	f.WriteString(minimalPack)
	f.Close()

	if _, err := policy.LoadAndVerify(f.Name(), pub); err == nil {
		t.Error("unsigned pack should fail LoadAndVerify")
	}
}

func TestLoadPublicKey_RoundTrip(t *testing.T) {
	pub, priv := genKeyPair(t)

	// Write public key in PEM format (matching Forge's SavePublicKey).
	const pubKeyPEMType = "KERNLOOM ED25519 PUBLIC KEY"
	import_pem := writePEMKey(t, pubKeyPEMType, []byte(pub))

	loaded, err := policy.LoadPublicKey(import_pem)
	if err != nil {
		t.Fatalf("LoadPublicKey: %v", err)
	}

	// Verify with loaded key works end-to-end.
	signed := signBytes([]byte(minimalPack), priv)
	if err := policy.VerifyPack(signed, loaded); err != nil {
		t.Errorf("verify with loaded key: %v", err)
	}
}

func writePEMKey(t *testing.T, pemType string, keyBytes []byte) string {
	t.Helper()
	import_encoding_pem := "-----BEGIN " + pemType + "-----\n" +
		base64.StdEncoding.EncodeToString(keyBytes) + "\n" +
		"-----END " + pemType + "-----\n"
	path := filepath.Join(t.TempDir(), "key.pub")
	os.WriteFile(path, []byte(import_encoding_pem), 0o644)
	return path
}
