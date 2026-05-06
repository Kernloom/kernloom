// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package capability

import (
	"testing"
)

func TestNewCapability(t *testing.T) {
	cap := NewCapability(
		"network.block_source", "v1",
		TypeEnforcement, LayerL3L4, DirectionOutput,
		"Block traffic from a source IP or CIDR",
	)

	if cap.ID != "network.block_source" {
		t.Errorf("expected ID=network.block_source, got %s", cap.ID)
	}
	if cap.Version != "v1" {
		t.Errorf("expected Version=v1, got %s", cap.Version)
	}
	if cap.Type != TypeEnforcement {
		t.Errorf("expected Type=enforcement, got %s", cap.Type)
	}
	if cap.Layer != LayerL3L4 {
		t.Errorf("expected Layer=L3L4, got %s", cap.Layer)
	}
	if cap.Direction != DirectionOutput {
		t.Errorf("expected Direction=output, got %s", cap.Direction)
	}
}

func TestCapabilityAddParam(t *testing.T) {
	cap := NewCapability(
		"network.rate_limit_source", "v1",
		TypeEnforcement, LayerL3L4, DirectionOutput,
		"Apply rate limit",
	).
		AddParam("source", "entity.ip", true, "Source IP to limit").
		AddParam("rate_pps", "integer", true, "Packets per second").
		AddParam("ttl", "duration", false, "How long to limit")

	if len(cap.Params) != 3 {
		t.Errorf("expected 3 params, got %d", len(cap.Params))
	}
	if cap.Params[0].Name != "source" {
		t.Errorf("expected first param name=source, got %s", cap.Params[0].Name)
	}
	if cap.Params[0].Type != "entity.ip" {
		t.Errorf("expected first param type=entity.ip, got %s", cap.Params[0].Type)
	}
	if !cap.Params[0].Required {
		t.Error("expected first param to be required")
	}
	if cap.Params[2].Required {
		t.Error("expected third param to not be required")
	}
}

func TestCapabilityAddTag(t *testing.T) {
	cap := NewCapability(
		"network.block_source", "v1",
		TypeEnforcement, LayerL3L4, DirectionOutput,
		"Block source",
	).
		AddTag("network").
		AddTag("enforcement").
		AddTag("critical")

	if len(cap.Tags) != 3 {
		t.Errorf("expected 3 tags, got %d", len(cap.Tags))
	}
	if cap.Tags[0] != "network" {
		t.Errorf("expected first tag=network, got %s", cap.Tags[0])
	}
	if cap.Tags[2] != "critical" {
		t.Errorf("expected third tag=critical, got %s", cap.Tags[2])
	}
}

func TestCapabilityTypes(t *testing.T) {
	types := []CapabilityType{
		TypeTelemetry, TypeEnforcement, TypeSignal, TypePolicy, TypeManagement, TypeAnalysis, TypeExport,
	}

	for _, capType := range types {
		cap := NewCapability("test.cap", "v1", capType, LayerL3L4, DirectionOutput, "test")
		if cap.Type != capType {
			t.Errorf("expected type=%s, got %s", capType, cap.Type)
		}
	}
}

func TestCapabilityLayers(t *testing.T) {
	layers := []Layer{
		LayerL3L4, LayerL7, LayerContext, LayerTrust, LayerPolicy, LayerManagement,
	}

	for _, layer := range layers {
		cap := NewCapability("test.cap", "v1", TypeTelemetry, layer, DirectionOutput, "test")
		if cap.Layer != layer {
			t.Errorf("expected layer=%s, got %s", layer, cap.Layer)
		}
	}
}

func TestCapabilityDirections(t *testing.T) {
	directions := []Direction{DirectionInput, DirectionOutput, DirectionBoth}

	for _, dir := range directions {
		cap := NewCapability("test.cap", "v1", TypeTelemetry, LayerL3L4, dir, "test")
		if cap.Direction != dir {
			t.Errorf("expected direction=%s, got %s", dir, cap.Direction)
		}
	}
}

func TestCapabilityVersioning(t *testing.T) {
	cap := NewCapability("test.cap", "v2", TypeTelemetry, LayerL3L4, DirectionOutput, "test")

	if cap.Version != "v2" {
		t.Errorf("expected version=v2, got %s", cap.Version)
	}
}

func TestCapabilityAdapter(t *testing.T) {
	cap := NewCapability("test.cap", "v1", TypeTelemetry, LayerL3L4, DirectionOutput, "test")

	// Initially empty
	if cap.Adapter != "" {
		t.Errorf("expected empty Adapter initially, got %s", cap.Adapter)
	}

	// Can be set for reporting
	cap.Adapter = "shield-telemetry"
	if cap.Adapter != "shield-telemetry" {
		t.Errorf("expected Adapter=shield-telemetry, got %s", cap.Adapter)
	}
}
