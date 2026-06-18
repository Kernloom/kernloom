// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package catalog

import (
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	klshieldruntime "github.com/kernloom/kernloom/pkg/adapters/klshield/runtime"
	"github.com/kernloom/kernloom/pkg/sourcebaseline"
)

type SourceBaselineConfig struct {
	Alpha          float64
	AlphaPromoted  float64
	MinUpdateRates map[string]float64
	MinObs         uint64
	MaxSources     int
	PeakMultiplier float64
	MinConfidence  float64
}

type SourceBaseline interface {
	Evict(cutoff time.Time) int
}

func NewSourceBaseline(adapterID string, cfg SourceBaselineConfig) (SourceBaseline, error) {
	switch adapterID {
	case "", DefaultAdapterID, klshieldruntime.AdapterID:
		return sourcebaseline.New(sourcebaseline.Config{
			Alpha:          cfg.Alpha,
			AlphaPromoted:  cfg.AlphaPromoted,
			MinUpdatePPS:   cfg.MinUpdateRates[adapterruntime.MetricNetworkPacketsPerSecond],
			MinObs:         cfg.MinObs,
			MaxSources:     cfg.MaxSources,
			PeakMultiplier: cfg.PeakMultiplier,
			MinConfidence:  cfg.MinConfidence,
		}), nil
	default:
		return nil, fmt.Errorf("unknown source baseline adapter %q", adapterID)
	}
}
