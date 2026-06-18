// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/catalog"
	"github.com/kernloom/kernloom/pkg/pipeline/graphpipeline"
)

const graphBaselineTriggerPurpose = "graph.baseline.triggers"

func runtimeAdapterSpec(adapterID string, nodeID string, c cfg, telemetryHandle any, sourceBaseline any) adapterruntime.RuntimeAdapterSpec {
	return adapterruntime.RuntimeAdapterSpec{
		ID:       adapterID,
		NodeID:   nodeID,
		Interval: c.Interval,
		StateTTL: c.PrevTTL,
		MinRate:  c.MinPPS,
		MinScore: c.MinSev,
		DryRun:   c.DryRun,
		Config: adapterruntime.AdapterConfig{
			adapterruntime.ConfigScoring: adapterruntime.RuntimeScoringConfig{
				Triggers: map[string]float64{
					adapterruntime.MetricNetworkPacketsPerSecond:       c.TrigPPS,
					adapterruntime.MetricNetworkSynRate:                c.TrigSyn,
					adapterruntime.MetricNetworkDestinationPortChanges: c.TrigScan,
					adapterruntime.MetricNetworkBytesPerSecond:         c.TrigBPS,
				},
				Weights: map[string]float64{
					adapterruntime.MetricNetworkPacketsPerSecond:       c.WPPS,
					adapterruntime.MetricNetworkSynRate:                c.WSyn,
					adapterruntime.MetricNetworkDestinationPortChanges: c.WScan,
					adapterruntime.MetricNetworkBytesPerSecond:         c.WBps,
				},
				SeverityCap: c.SevCap,
			},
		},
		Resources: map[string]any{
			adapterruntime.ResourceTelemetryHandle: telemetryHandle,
			adapterruntime.ResourceSourceBaseline:  sourceBaseline,
		},
	}
}

func runtimeSourceBaseline(adapterID string, enabled bool, c cfg) (catalog.SourceBaseline, string, error) {
	if !enabled {
		return nil, "", nil
	}
	baseline, err := catalog.NewSourceBaseline(adapterID, catalog.SourceBaselineConfig{
		Alpha:         c.SrcBaselineAlpha,
		AlphaPromoted: c.SrcBaselineAlphaStable,
		MinUpdateRates: map[string]float64{
			adapterruntime.MetricNetworkPacketsPerSecond: c.SrcBaselineMinPPS,
		},
		MinObs:         c.SrcBaselineMinObs,
		MaxSources:     c.SrcBaselineMaxSources,
		PeakMultiplier: c.SrcBaselinePeakMul,
		MinConfidence:  c.SrcBaselineMinConf,
	})
	if err != nil {
		return nil, "", err
	}
	summary := fmt.Sprintf("min_rate=%.1f min_obs=%d max_sources=%d peak_mul=%.2f",
		c.SrcBaselineMinPPS, c.SrcBaselineMinObs, c.SrcBaselineMaxSources, c.SrcBaselinePeakMul)
	return baseline, summary, nil
}

func evictRuntimeSourceBaseline(baseline catalog.SourceBaseline, cutoff time.Time) {
	if baseline != nil {
		baseline.Evict(cutoff)
	}
}

func startRuntimeAdapter(
	ctx context.Context,
	factory func(context.Context, adapterruntime.RuntimeAdapterSpec) (adapterruntime.ObservingAdapter, error),
	spec adapterruntime.RuntimeAdapterSpec,
	bus adapterruntime.EventBus,
) (adapterruntime.ObservingAdapter, error) {
	if spec.Resources == nil {
		return nil, nil
	}
	adapter, err := factory(ctx, spec)
	if err != nil {
		return nil, err
	}
	if err := adapter.Start(ctx, bus); err != nil {
		return nil, err
	}
	return adapter, nil
}

func runtimeSummary(adapter adapterruntime.ObservingAdapter) string {
	if updatable, ok := adapter.(adapterruntime.RuntimeUpdatable); ok {
		return updatable.RuntimeSummary()
	}
	return "adapter-tuning=unavailable"
}

func runtimeAdaptersSummary(adapters []adapterruntime.ObservingAdapter) string {
	if len(adapters) == 0 {
		return "adapter-tuning=unavailable"
	}
	parts := make([]string, 0, len(adapters))
	for _, adapter := range adapters {
		if adapter == nil {
			continue
		}
		parts = append(parts, adapter.ID()+": "+runtimeSummary(adapter))
	}
	if len(parts) == 0 {
		return "adapter-tuning=unavailable"
	}
	return strings.Join(parts, "; ")
}

func applyRuntimeUpdate(ctx context.Context, adapter adapterruntime.ObservingAdapter, update adapterruntime.RuntimeUpdate) error {
	if updatable, ok := adapter.(adapterruntime.RuntimeUpdatable); ok {
		return updatable.ApplyRuntimeUpdate(ctx, update)
	}
	return nil
}

func applyAutotuneRuntimeUpdate(ctx context.Context, adapter adapterruntime.ObservingAdapter, result any) error {
	values := map[string]any{}
	if r, ok := result.(adapterruntime.TuningResult); ok {
		values[adapterruntime.MetricNetworkPacketsPerSecond] = r.NewThresholds.PacketsPerSecond
		values[adapterruntime.MetricNetworkSynRate] = r.NewThresholds.SynRate
		values[adapterruntime.MetricNetworkDestinationPortChanges] = r.NewThresholds.DestinationPortChanges
		values[adapterruntime.MetricNetworkBytesPerSecond] = r.NewThresholds.BytesPerSecond
	}
	return applyRuntimeUpdate(ctx, adapter, adapterruntime.RuntimeUpdate{
		Kind:   "autotune.thresholds",
		Values: values,
		Raw:    result,
	})
}

func applyAutotuneRuntimeUpdateToAdapters(ctx context.Context, adapters []adapterruntime.ObservingAdapter, result any) {
	for _, adapter := range adapters {
		if adapter == nil {
			continue
		}
		if err := applyAutotuneRuntimeUpdate(ctx, adapter, result); err != nil {
			kliqLog.Printf("autotune runtime update adapter=%s: %v", adapter.ID(), err)
		}
	}
}

func applyGraphRuntimeValues(config *graphpipeline.Config, adapter adapterruntime.ObservingAdapter) {
	updatable, ok := adapter.(adapterruntime.RuntimeUpdatable)
	if !ok {
		return
	}
	values := updatable.RuntimeValues(graphBaselineTriggerPurpose)
	config.BaselineTriggers = copyRuntimeFloatValues(values)
}

func applyGraphRuntimeValuesFromAdapters(config *graphpipeline.Config, adapters []adapterruntime.ObservingAdapter) {
	if values, ok := graphRuntimeValuesFromAdapters(adapters); ok {
		config.BaselineTriggers = values
	}
}

func graphRuntimeValues(adapter adapterruntime.ObservingAdapter) (map[string]float64, bool) {
	updatable, hasValues := adapter.(adapterruntime.RuntimeUpdatable)
	if !hasValues {
		return nil, false
	}
	values := updatable.RuntimeValues(graphBaselineTriggerPurpose)
	return copyRuntimeFloatValues(values), true
}

func graphRuntimeValuesFromAdapters(adapters []adapterruntime.ObservingAdapter) (map[string]float64, bool) {
	merged := map[string]float64{}
	for _, adapter := range adapters {
		values, ok := graphRuntimeValues(adapter)
		if !ok {
			continue
		}
		for k, v := range values {
			if v <= 0 {
				continue
			}
			if cur, exists := merged[k]; !exists || v < cur {
				merged[k] = v
			}
		}
	}
	if len(merged) == 0 {
		return nil, false
	}
	return merged, true
}

func graphBaselineMinUpdates(c cfg) map[string]float64 {
	return map[string]float64{
		adapterruntime.MetricNetworkPacketsPerSecond: c.BaselineMinUpdatePacketRate,
		adapterruntime.MetricNetworkBytesPerSecond:   c.BaselineMinUpdateByteRate,
	}
}

func graphObservationMinValues(c cfg) map[string]float64 {
	return map[string]float64{
		adapterruntime.MetricNetworkFlowPackets: float64(c.GraphMinPackets),
		adapterruntime.MetricNetworkFlowBytes:   float64(c.GraphMinBytes),
	}
}

func copyRuntimeFloatValues(values map[string]float64) map[string]float64 {
	if len(values) == 0 {
		return nil
	}
	out := make(map[string]float64, len(values))
	for k, v := range values {
		out[k] = v
	}
	return out
}
