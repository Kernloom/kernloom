// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package klshieldruntime

import (
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
)

const (
	MetricPacketsPerSecond       = adapterruntime.MetricNetworkPacketsPerSecond
	MetricBytesPerSecond         = adapterruntime.MetricNetworkBytesPerSecond
	MetricSynRate                = adapterruntime.MetricNetworkSynRate
	MetricDestinationPortChanges = adapterruntime.MetricNetworkDestinationPortChanges
	MetricRateLimitDropRate      = adapterruntime.MetricNetworkRateLimitDropRate
)

type counterSnapshot struct {
	Pkts, Bytes, Syn, DportChanges, DropRL uint64
	LastWall                               time.Time
}

type rateSample struct {
	PPS        float64
	BPS        float64
	SynRate    float64
	ScanRate   float64
	DropRLRate float64
}

func calculateRates(prev, curr counterSnapshot, fallbackInterval time.Duration) (rateSample, bool) {
	if curr.Pkts < prev.Pkts || curr.Bytes < prev.Bytes || curr.Syn < prev.Syn ||
		curr.DportChanges < prev.DportChanges || curr.DropRL < prev.DropRL {
		return rateSample{}, false
	}
	sec := curr.LastWall.Sub(prev.LastWall).Seconds()
	if sec <= 0 {
		sec = fallbackInterval.Seconds()
		if sec <= 0 {
			sec = 1
		}
	}
	return rateSample{
		PPS:        float64(curr.Pkts-prev.Pkts) / sec,
		BPS:        float64(curr.Bytes-prev.Bytes) / sec,
		SynRate:    float64(curr.Syn-prev.Syn) / sec,
		ScanRate:   float64(curr.DportChanges-prev.DportChanges) / sec,
		DropRLRate: float64(curr.DropRL-prev.DropRL) / sec,
	}, true
}

func sampleMetrics(s rateSample) map[string]float64 {
	return map[string]float64{
		MetricPacketsPerSecond:       s.PPS,
		MetricBytesPerSecond:         s.BPS,
		MetricSynRate:                s.SynRate,
		MetricDestinationPortChanges: s.ScanRate,
		MetricRateLimitDropRate:      s.DropRLRate,
	}
}

func formatFloat(v float64) string {
	return fmt.Sprintf("%.6f", v)
}

func valueFloat(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case uint64:
		return float64(x)
	default:
		return 0
	}
}
