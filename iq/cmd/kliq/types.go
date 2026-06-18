// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
)

// metrics holds one opaque source candidate for an observation window.
// Adapter metric semantics stay in Signals as canonical metric IDs.
type metrics struct {
	Target adapterruntime.SourceTarget

	Score   float64
	Signals map[string]float64
}

func (m metrics) sourceID() string {
	if m.Target.SourceID != "" {
		return m.Target.SourceID
	}
	return m.Target.Subject.ID
}

func metricsFromObservation(obs adapterruntime.SourceObservation) (metrics, bool) {
	sourceID := obs.SourceID
	if sourceID == "" {
		sourceID = obs.Subject.ID
	}
	if sourceID == "" {
		return metrics{}, false
	}
	return metrics{
		Target: adapterruntime.SourceTarget{
			SourceID:   sourceID,
			Subject:    obs.Subject,
			Attributes: copyStringMap(obs.Attributes),
		},
		Score:   obs.Score,
		Signals: copyMetricValues(obs.Metrics),
	}, true
}

func copyStringMap(values map[string]string) map[string]string {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]string, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}

func copyMetricValues(values map[string]float64) map[string]float64 {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]float64, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}

func (m metrics) signalValue(id string) float64 {
	if m.Signals == nil {
		return 0
	}
	return m.Signals[id]
}

func (m metrics) score() float64 {
	return m.Score
}

func (m metrics) primarySortValue() float64 {
	return m.signalValue(adapterruntime.MetricNetworkPacketsPerSecond)
}

func (m metrics) hasLearningSignal() bool {
	return m.signalValue(adapterruntime.MetricNetworkPacketsPerSecond) > 0 ||
		m.signalValue(adapterruntime.MetricNetworkSynRate) > 0 ||
		m.signalValue(adapterruntime.MetricNetworkDestinationPortChanges) > 0
}

func (m metrics) enforcementFeedbackRate() float64 {
	return m.signalValue(adapterruntime.MetricNetworkRateLimitDropRate)
}

func (m metrics) signalsSummary() string {
	if len(m.Signals) == 0 {
		return "signals{}"
	}
	keys := make([]string, 0, len(m.Signals))
	for key := range m.Signals {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%.1f", key, m.Signals[key]))
	}
	return "signals{" + strings.Join(parts, " ") + "}"
}
