// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package featureextractor defines the interface for converting raw observations
// into normalized, scored metrics suitable for the generic baseline engine.
//
// Each adapter domain (KLShield, NGINX, OpenZiti, Trust, …) provides its own
// concrete Extractor implementation. The interface is intentionally minimal:
// extractors must not make enforcement decisions — they only translate raw
// observations into the metric.Batch format for downstream scoring.
//
// Track A — interface only. No concrete extractor is registered here.
// The first concrete implementation will live alongside its adapter, e.g.
// pkg/adapters/nginxtelemetry/extractor.go implements Extractor for NGINX.
package featureextractor

import (
	"context"

	"github.com/kernloom/kernloom/pkg/core/metric"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

// Extractor converts raw observations into a normalized metric batch.
// Each observation source (shield, nginx, ziti, …) provides its own Extractor.
type Extractor interface {
	// Name returns the unique name of this extractor, e.g. "shield", "nginx".
	Name() string

	// AppliesTo returns the observation types this extractor handles.
	// The pipeline skips observations whose type is not in this list.
	AppliesTo() []observation.ObservationType

	// Extract converts a slice of matching observations into a metric batch.
	// The returned batch may be empty if no meaningful metrics can be derived.
	// Errors are returned for structural failures (bad input, missing fields).
	Extract(ctx context.Context, observations []observation.Observation) (metric.Batch, error)
}
