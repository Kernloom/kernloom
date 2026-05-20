// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapterruntime_test

import (
	"testing"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/metric"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/registry"
)

func TestKLShieldManifest_ValidatesAgainstDefaultBundle(t *testing.T) {
	b := registry.DefaultBundle()
	result := adapterruntime.KLShieldManifest.Validate(b)
	if !result.Valid {
		t.Errorf("KLShield manifest should be valid against default bundle: unknownMetrics=%v unknownSignals=%v unknownActions=%v forbiddenLabels=%v",
			result.UnknownMetrics, result.UnknownSignals, result.UnknownActions, result.ForbiddenLabels)
	}
}

func TestManifest_NilBundle_AlwaysValid(t *testing.T) {
	m := adapterruntime.AdapterManifest{
		ID:   "test",
		Type: adapterruntime.ManifestTypeObservation,
		Provides: adapterruntime.AdapterProvides{
			Metrics: []metric.MetricID{"totally.unknown.metric"},
		},
	}
	result := m.Validate(nil)
	if !result.Valid {
		t.Error("nil bundle should always produce Valid=true (standalone permissive mode)")
	}
}

func TestManifest_DetectsUnknownMetric(t *testing.T) {
	b := registry.DefaultBundle()
	m := adapterruntime.AdapterManifest{
		ID:   "bad-adapter",
		Type: adapterruntime.ManifestTypeExtractor,
		Provides: adapterruntime.AdapterProvides{
			Metrics: []metric.MetricID{"network.packets_per_second", "unknown.totally.new"},
		},
	}
	result := m.Validate(b)
	if result.Valid {
		t.Error("expected validation failure for unknown metric")
	}
	if len(result.UnknownMetrics) != 1 || result.UnknownMetrics[0] != "unknown.totally.new" {
		t.Errorf("unexpected unknown metrics: %v", result.UnknownMetrics)
	}
}

func TestManifest_DetectsForbiddenLabel(t *testing.T) {
	b := registry.DefaultBundle()
	m := adapterruntime.AdapterManifest{
		ID:   "careless-adapter",
		Type: adapterruntime.ManifestTypeExtractor,
		LabelPolicy: adapterruntime.AdapterLabelPolicy{
			DefaultSelectedLabels: []string{"host", "path"}, // path is forbidden
		},
	}
	result := m.Validate(b)
	if result.Valid {
		t.Error("expected validation failure for forbidden label 'path'")
	}
	if len(result.ForbiddenLabels) != 1 || result.ForbiddenLabels[0] != "path" {
		t.Errorf("unexpected forbidden labels: %v", result.ForbiddenLabels)
	}
}

func TestManifest_DetectsUnknownAction(t *testing.T) {
	b := registry.DefaultBundle()
	m := adapterruntime.AdapterManifest{
		ID:   "pep-adapter",
		Type: adapterruntime.ManifestTypePEP,
		Consumes: adapterruntime.AdapterConsumes{
			Actions: []string{"enforce.network.rate_limit", "enforce.nginx.some_unknown_action"},
		},
	}
	result := m.Validate(b)
	if result.Valid {
		t.Error("expected validation failure for unknown action")
	}
	if len(result.UnknownActions) != 1 {
		t.Errorf("expected 1 unknown action, got %v", result.UnknownActions)
	}
}

func TestManifest_EmptyProvides_IsValid(t *testing.T) {
	b := registry.DefaultBundle()
	m := adapterruntime.AdapterManifest{
		ID:   "minimal",
		Type: adapterruntime.ManifestTypeExport,
		Consumes: adapterruntime.AdapterConsumes{
			Observations: []observation.ObservationType{observation.TypeFlow},
		},
	}
	result := m.Validate(b)
	if !result.Valid {
		t.Errorf("minimal manifest with no provides should be valid: %+v", result)
	}
}
