// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import "testing"

func TestAdapterNamesCanonicalizeAndDedupeCatalogAliases(t *testing.T) {
	c := cfg{Adapters: "klshield-runtime, klshield, netfilter, none, netfilter"}

	got := c.adapterNames()
	want := []string{"klshield", "netfilter", "none"}
	if len(got) != len(want) {
		t.Fatalf("adapterNames length: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("adapterNames[%d]: got %q want %q (all=%v)", i, got[i], want[i], got)
		}
	}
}

func TestBindingAdapterNamesExcludeSpecialAdapters(t *testing.T) {
	c := cfg{Adapters: "none, netfilter, klshield"}

	got := c.bindingAdapterNames()
	if len(got) != 1 || got[0] != "klshield" {
		t.Fatalf("bindingAdapterNames: got %v want [klshield]", got)
	}
}
