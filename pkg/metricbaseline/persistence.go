// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package metricbaseline

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	corebaseline "github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

// baselineKeyString returns a stable map key for a baseline.Key.
// Uses a distinct prefix ("bk:") to avoid collisions with metric.Key strings.
func baselineKeyString(k corebaseline.Key) string {
	h := sha256.Sum256([]byte(fmt.Sprintf(
		"%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d",
		k.MetricID, k.ScopeType, k.ScopeID,
		k.SubjectEntityID, k.ObjectEntityID, k.DimensionsHash,
		k.SourceClass, k.VisibilityPoint, k.MeasurementType, k.TruthClass,
		k.WindowSeconds,
	)))
	return "bk:" + fmt.Sprintf("%x", h)
}

// UpdateWithBaselineKey is the generic entry point that accepts a full baseline.Key
// with measurement semantics embedded.  The key ensures that baselines from different
// adapters, truth classes, or visibility points are NEVER mixed into the same profile.
//
// Use this method from adapters that have explicit measurement semantics (conntrack,
// nginx, ziti).  The existing Update(metric.Metric) method remains for the klshield
// path which derives the key from metric.Metric + Config.SelectedLabels.
func (e *Engine) UpdateWithBaselineKey(k corebaseline.Key, value float64, opts UpdateOptions) Result {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	ks := baselineKeyString(k)

	e.mu.Lock()
	defer e.mu.Unlock()

	p, ok := e.profiles[ks]
	if !ok {
		if len(e.profiles) >= e.cfg.MaxProfiles {
			e.evictLocked()
		}
		p = &Profile{
			// Store the baseline.Key in the Profile's generic Key field via a
			// synthetic metric.Key so existing Profile/Result code works unchanged.
			Key:       syntheticKey(k),
			FirstSeen: now,
		}
		e.profiles[ks] = p
	}

	p.update(value, opts.Suspicious, now, e.cfg.Alpha, e.cfg.AlphaPromoted, e.cfg.MinCount)
	result := resultFromProfile(p, value, opts.Suspicious, !opts.Suspicious, e.cfg)

	// Mark dirty for persistence flush.
	if e.dirty == nil {
		e.dirty = make(map[string]corebaseline.Key)
	}
	e.dirty[ks] = k

	return result
}

// FlushDirty persists all dirty baseline profiles to the SQLite state store.
// Call this on a timer (e.g. every 30s) from the KLIQ main loop.
// Returns the number of profiles flushed and the first error encountered (if any).
func (e *Engine) FlushDirty(ctx context.Context, store *sqlite.Store) (int, error) {
	e.mu.Lock()
	dirty := e.dirty
	e.dirty = nil
	e.mu.Unlock()

	if len(dirty) == 0 {
		return 0, nil
	}

	flushed := 0
	var firstErr error
	for ks, k := range dirty {
		e.mu.Lock()
		p, ok := e.profiles[ks]
		if !ok {
			e.mu.Unlock()
			continue
		}
		snapshot := *p
		e.mu.Unlock()

		state := "candidate"
		if snapshot.Promoted {
			state = "learned"
		}
		row := sqlite.BaselineRow{
			Key:   k,
			State: state,
			EWMAState: map[string]any{
				"ewma":          snapshot.EWMA,
				"ewma_variance": snapshot.EWMAVariance,
				"peak":          snapshot.Peak,
				"confidence":    snapshot.Confidence,
			},
			Observations: int64(snapshot.Count),
			LastUpdated:  snapshot.LastSeen,
		}
		if err := store.UpsertBaseline(ctx, row); err != nil && firstErr == nil {
			firstErr = err
		} else {
			flushed++
		}
	}
	return flushed, firstErr
}

// LoadFromStore restores all baseline profiles for a given subject entity from SQLite.
// Call this at KLIQ startup to warm the in-memory engine from the last saved snapshot.
func (e *Engine) LoadFromStore(ctx context.Context, store *sqlite.Store, subjectEntityID string) error {
	rows, err := store.ListBaselinesBySubject(ctx, subjectEntityID)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, row := range rows {
		ks := baselineKeyString(row.Key)
		if _, exists := e.profiles[ks]; exists {
			continue // in-memory is newer; don't overwrite
		}
		if len(e.profiles) >= e.cfg.MaxProfiles {
			break
		}

		p := &Profile{
			Key:       syntheticKey(row.Key),
			FirstSeen: row.CreatedAt,
			LastSeen:  row.LastUpdated,
			Count:     uint64(row.Observations),
			Promoted:  row.State == "learned" || row.State == "approved",
		}
		if ewma, ok := row.EWMAState["ewma"].(float64); ok {
			p.EWMA = ewma
		}
		if v, ok := row.EWMAState["ewma_variance"].(float64); ok {
			p.EWMAVariance = v
		}
		if pk, ok := row.EWMAState["peak"].(float64); ok {
			p.Peak = pk
		}
		if conf, ok := row.EWMAState["confidence"].(float64); ok {
			p.Confidence = conf
		}
		if p.FirstSeen.IsZero() {
			p.FirstSeen = now
		}
		if p.LastSeen.IsZero() {
			p.LastSeen = now
		}
		p.LearnedCount = p.Count // conservative: treat all historical as learned
		e.profiles[ks] = p
	}
	return nil
}
