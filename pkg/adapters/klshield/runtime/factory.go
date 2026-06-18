// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package klshieldruntime

import (
	"context"
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/client"
	shieldheuristic "github.com/kernloom/kernloom/pkg/adapters/klshield/signalengine"
)

const (
	ResourceMaps = "klshield.maps"

	ConfigTriggerPPS  = "trigger_packets_per_second"
	ConfigTriggerSyn  = "trigger_syn_rate"
	ConfigTriggerScan = "trigger_scan_rate"
	ConfigTriggerBPS  = "trigger_bytes_per_second"
	ConfigWeightPPS   = "weight_packets_per_second"
	ConfigWeightSyn   = "weight_syn_rate"
	ConfigWeightScan  = "weight_scan_rate"
	ConfigWeightBPS   = "weight_bytes_per_second"
	ConfigSeverityCap = "severity_cap"
	ConfigSignalTTL   = "signal_ttl"
)

// NewFromRuntimeSpec constructs a KLShield runtime adapter from the generic
// adapterruntime spec. All KLShield-specific resource/config interpretation is
// contained here, not in the KLIQ orchestrator.
func NewFromRuntimeSpec(_ context.Context, spec adapterruntime.RuntimeAdapterSpec) (*Adapter, error) {
	maps, _ := spec.Resources[adapterruntime.ResourceTelemetryHandle].(*shieldclient.Maps)
	if maps == nil {
		maps, _ = spec.Resources[ResourceMaps].(*shieldclient.Maps)
	}
	if maps == nil {
		return nil, fmt.Errorf("klshield runtime: missing telemetry handle resource")
	}
	baseline, _ := spec.Resources[adapterruntime.ResourceSourceBaseline].(SourceBaseline)
	scoring := scoringConfig(spec.Config)
	return New(Config{
		NodeID:      spec.NodeID,
		Interval:    spec.Interval,
		PrevTTL:     spec.StateTTL,
		MinPPS:      spec.MinRate,
		MinSeverity: spec.MinScore,
		Maps:        maps,
		DryRun:      spec.DryRun,
		Baseline:    baseline,
		Engine: shieldheuristic.Config{
			NodeID:    spec.NodeID,
			TrigPPS:   scoring.Triggers[adapterruntime.MetricNetworkPacketsPerSecond],
			TrigSyn:   scoring.Triggers[adapterruntime.MetricNetworkSynRate],
			TrigScan:  scoring.Triggers[adapterruntime.MetricNetworkDestinationPortChanges],
			TrigBPS:   scoring.Triggers[adapterruntime.MetricNetworkBytesPerSecond],
			WPPS:      scoring.Weights[adapterruntime.MetricNetworkPacketsPerSecond],
			WSyn:      scoring.Weights[adapterruntime.MetricNetworkSynRate],
			WScan:     scoring.Weights[adapterruntime.MetricNetworkDestinationPortChanges],
			WBps:      scoring.Weights[adapterruntime.MetricNetworkBytesPerSecond],
			SevCap:    scoring.SeverityCap,
			SignalTTL: scoring.SignalTTL,
		},
	}), nil
}

func scoringConfig(cfg adapterruntime.AdapterConfig) adapterruntime.RuntimeScoringConfig {
	if s, ok := cfg[adapterruntime.ConfigScoring].(adapterruntime.RuntimeScoringConfig); ok {
		return s
	}
	return adapterruntime.RuntimeScoringConfig{
		Triggers: map[string]float64{
			adapterruntime.MetricNetworkPacketsPerSecond:       floatConfig(cfg, ConfigTriggerPPS),
			adapterruntime.MetricNetworkSynRate:                floatConfig(cfg, ConfigTriggerSyn),
			adapterruntime.MetricNetworkDestinationPortChanges: floatConfig(cfg, ConfigTriggerScan),
			adapterruntime.MetricNetworkBytesPerSecond:         floatConfig(cfg, ConfigTriggerBPS),
		},
		Weights: map[string]float64{
			adapterruntime.MetricNetworkPacketsPerSecond:       floatConfig(cfg, ConfigWeightPPS),
			adapterruntime.MetricNetworkSynRate:                floatConfig(cfg, ConfigWeightSyn),
			adapterruntime.MetricNetworkDestinationPortChanges: floatConfig(cfg, ConfigWeightScan),
			adapterruntime.MetricNetworkBytesPerSecond:         floatConfig(cfg, ConfigWeightBPS),
		},
		SeverityCap: floatConfig(cfg, ConfigSeverityCap),
		SignalTTL:   durationConfig(cfg, ConfigSignalTTL),
	}
}

func floatConfig(cfg adapterruntime.AdapterConfig, key string) float64 {
	switch v := cfg[key].(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case uint64:
		return float64(v)
	default:
		return 0
	}
}

func durationConfig(cfg adapterruntime.AdapterConfig, key string) time.Duration {
	switch v := cfg[key].(type) {
	case time.Duration:
		return v
	case string:
		d, _ := time.ParseDuration(v)
		return d
	default:
		return 0
	}
}
