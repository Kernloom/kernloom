// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package catalog

import (
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/autotuner"
	klshieldruntime "github.com/kernloom/kernloom/pkg/adapters/klshield/runtime"
)

func NewTuner(adapterID string, initial adapterruntime.TuningThresholds, cfg adapterruntime.TuningConfig, reservoirCap int) (adapterruntime.Tuner, error) {
	switch adapterID {
	case "", "klshield", klshieldruntime.AdapterID:
		return &klshieldTuner{
			inner: autotuner.New(toKLThresholds(initial), toKLConfig(cfg), reservoirCap),
		}, nil
	default:
		return nil, fmt.Errorf("unknown tuner adapter %q", adapterID)
	}
}

type klshieldTuner struct {
	inner *autotuner.Autotuner
}

func (t *klshieldTuner) RecordSample(sample adapterruntime.TuningSample) {
	t.inner.RecordSample(
		sample.PacketsPerSecond,
		sample.SynRate,
		sample.DestinationPortChanges,
		sample.BytesPerSecond,
		sample.SourceID,
		sample.Accepted,
	)
}

func (t *klshieldTuner) SampleCount() int {
	return t.inner.SampleCount()
}

func (t *klshieldTuner) CurrentThresholds() adapterruntime.TuningThresholds {
	return fromKLThresholds(t.inner.CurrentThresholds())
}

func (t *klshieldTuner) Tick(now time.Time, policy adapterruntime.TuningPolicy, cleanRatio float64) (adapterruntime.TuningResult, bool) {
	result, ok := t.inner.Tick(now, autotuner.Policy{
		Active:  policy.Active,
		Every:   policy.Every,
		K:       policy.K,
		MaxUp:   policy.MaxUp,
		MaxDown: policy.MaxDown,
		Alpha:   policy.Alpha,
		Phase:   policy.Phase,
	}, cleanRatio)
	return fromKLResult(result), ok
}

func (t *klshieldTuner) LogResult(logger interface{ Printf(string, ...any) }, result adapterruntime.TuningResult, k, dropRatio float64, clean bool) {
	autotuner.TickResult{
		OldThresholds: autotuner.Thresholds{
			TrigPPS:  result.OldThresholds.PacketsPerSecond,
			TrigSyn:  result.OldThresholds.SynRate,
			TrigScan: result.OldThresholds.DestinationPortChanges,
			TrigBPS:  result.OldThresholds.BytesPerSecond,
		},
		NewThresholds: autotuner.Thresholds{
			TrigPPS:  result.NewThresholds.PacketsPerSecond,
			TrigSyn:  result.NewThresholds.SynRate,
			TrigScan: result.NewThresholds.DestinationPortChanges,
			TrigBPS:  result.NewThresholds.BytesPerSecond,
		},
		SampleCount: result.SampleCount,
		CleanRatio:  result.CleanRatio,
		Phase:       result.Phase,
	}.LogWithK(logger, k, dropRatio, clean)
}

func toKLThresholds(t adapterruntime.TuningThresholds) autotuner.Thresholds {
	return autotuner.Thresholds{
		TrigPPS:  t.PacketsPerSecond,
		TrigSyn:  t.SynRate,
		TrigScan: t.DestinationPortChanges,
		TrigBPS:  t.BytesPerSecond,
	}
}

func fromKLThresholds(t autotuner.Thresholds) adapterruntime.TuningThresholds {
	return adapterruntime.TuningThresholds{
		PacketsPerSecond:       t.TrigPPS,
		SynRate:                t.TrigSyn,
		DestinationPortChanges: t.TrigScan,
		BytesPerSecond:         t.TrigBPS,
	}
}

func toKLConfig(c adapterruntime.TuningConfig) autotuner.Config {
	return autotuner.Config{
		MinSamples:                c.MinSamples,
		FloorPPS:                  c.FloorPPS,
		FloorSyn:                  c.FloorSyn,
		FloorScan:                 c.FloorScan,
		FloorBPS:                  c.FloorBPS,
		MinWindowsBeforeDownscale: c.MinWindowsBeforeDownscale,
		MinSourcesBeforeDownscale: c.MinSourcesBeforeDownscale,
	}
}

func fromKLResult(r autotuner.TickResult) adapterruntime.TuningResult {
	return adapterruntime.TuningResult{
		OldThresholds:    fromKLThresholds(r.OldThresholds),
		NewThresholds:    fromKLThresholds(r.NewThresholds),
		AdapterStats:     r.AdapterStats(),
		SampleCount:      r.SampleCount,
		CleanRatio:       r.CleanRatio,
		CompletedWindows: r.CompletedWindows,
		Phase:            r.Phase,
		Skipped:          r.Skipped,
		SkipReason:       r.SkipReason,
	}
}
