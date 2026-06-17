// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package signalengine defines the generic interface for domain-specific signal
// engines. A signal engine receives observations, pre-computed metrics, and
// metric baseline results, and produces scored signals for the decision engine.
//
// The existing pkg/adapters/klshield/signalengine implements the KLShield-specific
// heuristic logic. It does NOT implement this interface in Track A — that
// migration is Track B work and requires a real second adapter to drive the
// correct abstraction boundary.
//
// Concrete implementations live alongside their adapter:
//   - pkg/adapters/klshield/signalengine  — KLShield/XDP domain (existing, Track B)
//   - pkg/adapters/nginx/signalengine     — future NGINX/HTTP domain
//   - pkg/adapters/openziti/signalengine  — future OpenZiti domain
package signalengine

import (
	"context"

	"github.com/kernloom/kernloom/pkg/core/metric"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
	"github.com/kernloom/kernloom/pkg/metricbaseline"
)

// Input is the combined input passed to a signal engine for one evaluation tick.
type Input struct {
	// Observations are the raw normalized observations from one or more sources.
	Observations []observation.Observation

	// Metrics are pre-computed metric values derived from observations (via Extractor).
	Metrics []metric.Metric

	// Baselines are the scored baseline results for each metric in Metrics.
	// Each element corresponds to the result of Engine.Update for that metric.
	Baselines []metricbaseline.Result
}

// Engine evaluates domain-specific signals from combined observations and metrics.
// Multiple signal engines may run in parallel; each produces independent signals
// that are merged by the local risk aggregator before the decision engine.
type Engine interface {
	// Name returns the unique name of this signal engine, e.g. "shield", "nginx".
	Name() string

	// Evaluate processes one tick of input and returns the resulting signals.
	// The returned slice may be empty if no notable signals are detected.
	Evaluate(ctx context.Context, input Input) ([]signal.Signal, error)
}
