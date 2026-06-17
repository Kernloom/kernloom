// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package metricbaseline

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"

	corebaseline "github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/core/metric"
)

// Key identifies a unique baseline profile. It combines the metric ID,
// scope, subject, and an optional hash of selected labels.
//
// Two metrics with the same Key share one learned baseline profile.
// Label hashing is controlled by Config.SelectedLabels — only labels
// whose keys appear in that list contribute to the hash.
// When SelectedLabels is empty (the default), all metrics of the same
// ID+scope+subject share one profile regardless of their labels.
type Key struct {
	MetricID  metric.MetricID `json:"metric_id"`
	Scope     metric.Scope    `json:"scope"`
	Subject   metric.Subject  `json:"subject"`
	LabelHash string          `json:"label_hash,omitempty"`
}

// String returns a stable string representation for map lookups and logging.
func (k Key) String() string {
	if k.LabelHash == "" {
		return fmt.Sprintf("%s|%s|%s|%s", k.MetricID, k.Scope, k.Subject.Type, k.Subject.Value)
	}
	return fmt.Sprintf("%s|%s|%s|%s|%s", k.MetricID, k.Scope, k.Subject.Type, k.Subject.Value, k.LabelHash)
}

// keyFromMetric builds a Key from a Metric using the given selected labels.
// If selectedLabels is empty, LabelHash is left empty — all label variants
// of the same metric share one profile (cardinality-safe default).
func keyFromMetric(m metric.Metric, selectedLabels []string) Key {
	k := Key{
		MetricID: m.ID,
		Scope:    m.Scope,
		Subject:  m.Subject,
	}
	if len(selectedLabels) > 0 && len(m.Labels) > 0 {
		k.LabelHash = hashLabels(m.Labels, selectedLabels)
	}
	return k
}

// hashLabels produces a stable 8-char hex hash of the selected label values.
// Only labels whose keys appear in selected are included; missing keys are
// treated as empty strings. The sort ensures key order does not affect the hash.
func hashLabels(labels map[string]string, selected []string) string {
	sorted := make([]string, len(selected))
	copy(sorted, selected)
	sort.Strings(sorted)

	var sb strings.Builder
	for _, k := range sorted {
		sb.WriteString(k)
		sb.WriteByte('=')
		sb.WriteString(labels[k]) // empty string if key absent
		sb.WriteByte(';')
	}
	h := sha256.Sum256([]byte(sb.String()))
	return fmt.Sprintf("%x", h[:4]) // 8 hex chars is enough for label hashing
}

// syntheticKey converts a corebaseline.Key to the Key type used by Profile/Result,
// allowing profiles created via UpdateWithBaselineKey to coexist in the same map.
func syntheticKey(k corebaseline.Key) Key {
	return Key{
		MetricID: metric.MetricID(k.MetricID),
		Scope:    metric.Scope(k.ScopeType + ":" + k.ScopeID),
		Subject: metric.Subject{
			Type:  k.SourceClass,
			Value: k.SubjectEntityID,
		},
		LabelHash: k.DimensionsHash,
	}
}
