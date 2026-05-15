// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package adapterruntime defines the interfaces and lifecycle for Kernloom adapters.
// Adapters are the extensibility mechanism: they connect KLIQ to telemetry sources,
// PEPs (enforcement points), signal feeds, and export targets.
package adapterruntime

import (
	"context"

	"github.com/kernloom/kernloom/pkg/core/capability"
)

// AdapterKind classifies the role of an adapter.
type AdapterKind string

const (
	// AdapterTelemetry observes and forwards raw telemetry (e.g., Shield flow counters).
	AdapterTelemetry AdapterKind = "telemetry"

	// AdapterSignal receives pre-scored signals from external sources (e.g., Correlate).
	AdapterSignal AdapterKind = "signal"

	// AdapterPEP applies enforcement decisions to a policy enforcement point.
	AdapterPEP AdapterKind = "pep"

	// AdapterExport sends observations, signals, decisions and receipts to external systems.
	AdapterExport AdapterKind = "export"
)

// HealthStatus reports the operational state of an adapter.
type HealthStatus struct {
	// Healthy is true when the adapter is operating normally.
	Healthy bool `json:"healthy"`

	// Message provides a human-readable explanation when unhealthy.
	Message string `json:"message,omitempty"`
}

// AdapterConfig holds generic adapter configuration as key-value pairs.
// Each adapter validates and interprets its own keys.
type AdapterConfig map[string]any

// Adapter is the base interface all adapters must implement.
// Specific adapter kinds (Telemetry, PEP, Signal, Export) extend this interface.
type Adapter interface {
	// ID returns the unique adapter identifier (e.g., "shield-telemetry", "shield-pep").
	ID() string

	// Kind returns the adapter category.
	Kind() AdapterKind

	// Capabilities returns the set of capabilities this adapter provides.
	// Called by the registry after Init to register the adapter's capabilities.
	Capabilities() []*capability.Capability

	// Init validates config and prepares internal state. Not yet active.
	Init(ctx context.Context, cfg AdapterConfig) error

	// Start begins adapter operation and connects to the event bus.
	// Must return promptly; long-running work runs in goroutines.
	Start(ctx context.Context, bus EventBus) error

	// Health returns the current operational status.
	Health(ctx context.Context) HealthStatus

	// Stop shuts the adapter down gracefully.
	Stop(ctx context.Context) error
}
