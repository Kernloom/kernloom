// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"strings"
	"testing"
)

func TestDecorateRuntimeLevels(t *testing.T) {
	got := decorateRuntimeLevels("subject=10.0.0.1 level=block observe->hard current=soft")
	for _, want := range []string{"🟥 BLOCK", "👁 OBSERVE", "🟨 HARD", "🟦 SOFT"} {
		if !strings.Contains(got, want) {
			t.Fatalf("decorated log missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "autoblock") {
		t.Fatalf("decorated unrelated words: %q", got)
	}
}

func TestColorLogTagKeepsPlainWhenDisabled(t *testing.T) {
	prev := kliqColorEnabled
	t.Cleanup(func() { kliqColorEnabled = prev })
	kliqColorEnabled = false
	if got := colorLogTag("decision"); got != "DECISION" {
		t.Fatalf("plain tag = %q", got)
	}
	kliqColorEnabled = true
	if got := colorLogTag("decision"); !strings.Contains(got, "🧠 DECISION") {
		t.Fatalf("visual tag = %q", got)
	}
}
