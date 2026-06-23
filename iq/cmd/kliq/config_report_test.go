// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import "testing"

func TestParseNodeLabels(t *testing.T) {
	labels := parseNodeLabels(" role = edge-gateway,env=production,service=payment-api,invalid")
	if labels["role"] != "edge-gateway" {
		t.Fatalf("role label = %q", labels["role"])
	}
	if labels["env"] != "production" {
		t.Fatalf("env label = %q", labels["env"])
	}
	if labels["service"] != "payment-api" {
		t.Fatalf("service label = %q", labels["service"])
	}
	if _, ok := labels["invalid"]; ok {
		t.Fatalf("invalid label entry was preserved")
	}
}

func TestApplyNodeLabelsMergesWithInventoryLabels(t *testing.T) {
	inv := buildEmptyInventory("node-test")
	inv.Labels = map[string]string{
		"env":  "staging",
		"role": "worker",
	}

	applyNodeLabels(&inv, map[string]string{
		"env":     "production",
		"service": "payment-api",
	})

	if inv.Labels["env"] != "production" {
		t.Fatalf("env label = %q", inv.Labels["env"])
	}
	if inv.Labels["role"] != "worker" {
		t.Fatalf("role label = %q", inv.Labels["role"])
	}
	if inv.Labels["service"] != "payment-api" {
		t.Fatalf("service label = %q", inv.Labels["service"])
	}
}
