// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sourcefilters

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWhitelistMatchesGenericSubjectAndIPRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "whitelist.txt")
	if err := os.WriteFile(path, []byte("ziti.identity:alice\n10.0.0.0/24\n"), 0o600); err != nil {
		t.Fatalf("write whitelist: %v", err)
	}

	w := NewWhitelist(path)
	if err := w.Load(); err != nil {
		t.Fatalf("load whitelist: %v", err)
	}

	if !w.MatchSource("ziti.identity:alice") {
		t.Fatal("expected generic subject match")
	}
	if !w.MatchSource("10.0.0.7") {
		t.Fatal("expected CIDR source match")
	}
	if w.MatchSource("ziti.identity:bob") {
		t.Fatal("unexpected subject match")
	}
}

func TestFeedbackMatchesGenericSubjectWithTTL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "feedback.json")
	raw := `[{"target":"ziti.identity:alice","action":"forgive","ttl":"1h"}]`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write feedback: %v", err)
	}

	f := NewFeedback(path)
	if err := f.Load(time.Now()); err != nil {
		t.Fatalf("load feedback: %v", err)
	}

	if !f.MatchSource("ziti.identity:alice") {
		t.Fatal("expected generic feedback match")
	}
	if f.MatchSource("ziti.identity:bob") {
		t.Fatal("unexpected feedback match")
	}
}
