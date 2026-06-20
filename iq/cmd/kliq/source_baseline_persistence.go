// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	corebaseline "github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/core/measurement"
	"github.com/kernloom/kernloom/pkg/sourcebaseline"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

const (
	sourceBaselineScopeType   = "source"
	sourceBaselineScopeID     = "klshield-source"
	sourceBaselineSourceClass = "xdp"
	sourceBaselineScanRate    = "network.scan_rate"
)

type sourceBaselineSnapshotter interface {
	Snapshot() []sourcebaseline.Snapshot
	SnapshotDirty() []sourcebaseline.Snapshot
}

type sourceBaselineRestorer interface {
	Restore([]sourcebaseline.Snapshot) int
}

func startRuntimeSourceBaselineFlush(ctx context.Context, baseline any, store *sstore.Store, interval time.Duration) {
	if baseline == nil || store == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				if n, err := flushRuntimeSourceBaselines(context.Background(), baseline, store, interval, false); err != nil {
					kliqLog.Printf("WARN: shutdown flush source baselines: %v", err)
				} else if n > 0 {
					kliqLog.Printf("Source baseline shutdown flush: baselines=%d", n)
				}
				return
			case <-ticker.C:
				if n, err := flushRuntimeSourceBaselines(context.Background(), baseline, store, interval, false); err != nil {
					kliqLog.Printf("WARN: flush source baselines: %v", err)
				} else if n > 0 {
					kliqLog.Printf("Source baseline flush: baselines=%d", n)
				}
			}
		}
	}()
}

func loadRuntimeSourceBaselines(ctx context.Context, baseline any, store *sstore.Store, interval time.Duration) (int, error) {
	restorer, ok := baseline.(sourceBaselineRestorer)
	if !ok || store == nil {
		return 0, nil
	}
	rows, err := store.ListBaselinesByScope(ctx, sourceBaselineScopeType, sourceBaselineScopeID)
	if err != nil {
		return 0, err
	}
	snapshots := sourceBaselineSnapshotsFromRows(rows, sourceBaselineWindowSeconds(interval))
	return restorer.Restore(snapshots), nil
}

func flushRuntimeSourceBaselines(ctx context.Context, baseline any, store *sstore.Store, interval time.Duration, all bool) (int, error) {
	snapshotter, ok := baseline.(sourceBaselineSnapshotter)
	if !ok || store == nil {
		return 0, nil
	}
	snapshots := snapshotter.SnapshotDirty()
	if all {
		snapshots = snapshotter.Snapshot()
	}
	if len(snapshots) == 0 {
		return 0, nil
	}
	windowSeconds := sourceBaselineWindowSeconds(interval)
	flushed := 0
	var firstErr error
	for _, snapshot := range snapshots {
		for _, row := range sourceBaselineRows(snapshot, windowSeconds) {
			if err := store.UpsertBaseline(ctx, row); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			flushed++
		}
	}
	return flushed, firstErr
}

func sourceBaselineRows(snapshot sourcebaseline.Snapshot, windowSeconds int) []sstore.BaselineRow {
	p := snapshot.Profile
	if snapshot.SourceID == "" || p.ObsCount == 0 {
		return nil
	}
	state := string(corebaseline.StateCandidate)
	if p.Promoted {
		state = string(corebaseline.StateLearned)
	}
	base := corebaseline.Key{
		ScopeType:       sourceBaselineScopeType,
		ScopeID:         sourceBaselineScopeID,
		SubjectEntityID: snapshot.SourceID,
		SourceClass:     sourceBaselineSourceClass,
		VisibilityPoint: string(measurement.VisibilityPreStackIngress),
		MeasurementType: string(measurement.TypeCounterDelta),
		TruthClass:      string(measurement.TruthPrimaryPacketObservation),
		WindowSeconds:   windowSeconds,
	}
	metrics := []struct {
		id        string
		ewma      float64
		peak      float64
		global    float64
		effective float64
	}{
		{id: adapterruntime.MetricNetworkPacketsPerSecond, ewma: p.EWMAPPS, peak: p.PeakPPS, global: p.GlobalPPS, effective: p.EffectivePPS},
		{id: adapterruntime.MetricNetworkBytesPerSecond, ewma: p.EWMABPS, peak: p.PeakBPS, global: p.GlobalBPS, effective: p.EffectiveBPS},
		{id: adapterruntime.MetricNetworkSynRate, ewma: p.EWMASyn, peak: p.PeakSyn, global: p.GlobalSyn, effective: p.EffectiveSyn},
		{id: sourceBaselineScanRate, ewma: p.EWMAScan, peak: p.PeakScan, global: p.GlobalScan, effective: p.EffectiveScan},
	}

	rows := make([]sstore.BaselineRow, 0, len(metrics))
	for _, metric := range metrics {
		key := base
		key.MetricID = metric.id
		rows = append(rows, sstore.BaselineRow{
			Key:   key,
			State: state,
			EWMAState: map[string]any{
				"ewma":              metric.ewma,
				"baseline":          metric.ewma,
				"peak":              metric.peak,
				"global_trigger":    metric.global,
				"effective_trigger": metric.effective,
				"confidence":        p.Confidence,
				"windows":           p.Windows,
			},
			Observations: int64(p.ObsCount),
			LastUpdated:  p.LastSeen,
			CreatedAt:    p.FirstSeen,
		})
	}
	return rows
}

func sourceBaselineSnapshotsFromRows(rows []sstore.BaselineRow, windowSeconds int) []sourcebaseline.Snapshot {
	bySource := map[string]*sourcebaseline.Profile{}
	for _, row := range rows {
		if row.Key.ScopeType != sourceBaselineScopeType ||
			row.Key.ScopeID != sourceBaselineScopeID ||
			row.Key.SourceClass != sourceBaselineSourceClass ||
			row.Key.WindowSeconds != windowSeconds {
			continue
		}
		sourceID := row.Key.SubjectEntityID
		if sourceID == "" {
			continue
		}
		p := bySource[sourceID]
		if p == nil {
			p = &sourcebaseline.Profile{}
			bySource[sourceID] = p
		}
		ewma := numericBaselineState(row.EWMAState, "ewma", "baseline", "median")
		peak := numericBaselineState(row.EWMAState, "peak")
		globalTrigger := numericBaselineState(row.EWMAState, "global_trigger")
		effectiveTrigger := numericBaselineState(row.EWMAState, "effective_trigger")
		switch row.Key.MetricID {
		case adapterruntime.MetricNetworkPacketsPerSecond:
			p.EWMAPPS = ewma
			p.PeakPPS = peak
			p.GlobalPPS = globalTrigger
			p.EffectivePPS = effectiveTrigger
		case adapterruntime.MetricNetworkBytesPerSecond:
			p.EWMABPS = ewma
			p.PeakBPS = peak
			p.GlobalBPS = globalTrigger
			p.EffectiveBPS = effectiveTrigger
		case adapterruntime.MetricNetworkSynRate:
			p.EWMASyn = ewma
			p.PeakSyn = peak
			p.GlobalSyn = globalTrigger
			p.EffectiveSyn = effectiveTrigger
		case sourceBaselineScanRate:
			p.EWMAScan = ewma
			p.PeakScan = peak
			p.GlobalScan = globalTrigger
			p.EffectiveScan = effectiveTrigger
		default:
			continue
		}
		if row.Observations > int64(p.ObsCount) {
			p.ObsCount = uint64(row.Observations)
		}
		if windows := numericBaselineState(row.EWMAState, "windows"); windows > float64(p.Windows) {
			p.Windows = uint64(windows)
		}
		if confidence := numericBaselineState(row.EWMAState, "confidence"); confidence > p.Confidence {
			p.Confidence = confidence
		}
		if row.State == string(corebaseline.StateLearned) || row.State == "approved" {
			p.Promoted = true
		}
		if !row.CreatedAt.IsZero() && (p.FirstSeen.IsZero() || row.CreatedAt.Before(p.FirstSeen)) {
			p.FirstSeen = row.CreatedAt
		}
		if row.LastUpdated.After(p.LastSeen) {
			p.LastSeen = row.LastUpdated
		}
	}

	out := make([]sourcebaseline.Snapshot, 0, len(bySource))
	for sourceID, profile := range bySource {
		if profile.ObsCount == 0 {
			continue
		}
		if profile.Windows == 0 {
			profile.Windows = profile.ObsCount
		}
		if profile.Promoted {
			if profile.PeakSyn == 0 && profile.EWMASyn > 0 {
				profile.PeakSyn = profile.EWMASyn * 1.5
			}
			if profile.PeakScan == 0 && profile.EWMAScan > 0 {
				profile.PeakScan = profile.EWMAScan * 1.5
			}
		}
		out = append(out, sourcebaseline.Snapshot{
			SourceID: sourceID,
			Profile:  *profile,
		})
	}
	return out
}

func numericBaselineState(values map[string]any, keys ...string) float64 {
	for _, key := range keys {
		switch v := values[key].(type) {
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
		}
	}
	return 0
}

func sourceBaselineWindowSeconds(interval time.Duration) int {
	if interval <= 0 {
		return 1
	}
	seconds := int(interval / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
