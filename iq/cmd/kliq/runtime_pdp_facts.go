// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

type runtimePDPFactSnapshot struct {
	Subject    map[string]any
	Device     map[string]any
	Session    map[string]any
	Resource   map[string]any
	Workload   map[string]any
	Baseline   map[string]any
	Graph      map[string]any
	Detections map[string]any
	Actions    map[string]any
}

type runtimePDPFactProvider interface {
	CandidateFacts(context.Context, string, metrics, time.Time) (runtimePDPFactSnapshot, error)
}

type runtimePDPFactStore struct {
	store *sqlite.Store
}

type runtimePDPCompositeFactProvider struct {
	providers []runtimePDPFactProvider
}

func newRuntimePDPFactStore(store *sqlite.Store) *runtimePDPFactStore {
	if store == nil {
		return nil
	}
	return &runtimePDPFactStore{store: store}
}

func newRuntimePDPCompositeFactProvider(providers ...runtimePDPFactProvider) runtimePDPFactProvider {
	out := runtimePDPCompositeFactProvider{}
	for _, provider := range providers {
		if provider != nil {
			out.providers = append(out.providers, provider)
		}
	}
	if len(out.providers) == 0 {
		return nil
	}
	return out
}

func (p runtimePDPCompositeFactProvider) CandidateFacts(ctx context.Context, nodeID string, m metrics, now time.Time) (runtimePDPFactSnapshot, error) {
	var merged runtimePDPFactSnapshot
	var errs []error
	for _, provider := range p.providers {
		snapshot, err := provider.CandidateFacts(ctx, nodeID, m, now)
		merged.Subject = mergeFactMaps(merged.Subject, snapshot.Subject)
		merged.Device = mergeFactMaps(merged.Device, snapshot.Device)
		merged.Session = mergeFactMaps(merged.Session, snapshot.Session)
		merged.Resource = mergeFactMaps(merged.Resource, snapshot.Resource)
		merged.Workload = mergeFactMaps(merged.Workload, snapshot.Workload)
		merged.Baseline = mergeFactMaps(merged.Baseline, snapshot.Baseline)
		merged.Graph = mergeFactMaps(merged.Graph, snapshot.Graph)
		merged.Detections = mergeFactMaps(merged.Detections, snapshot.Detections)
		merged.Actions = mergeFactMaps(merged.Actions, snapshot.Actions)
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return merged, fmt.Errorf("runtime pdp composite fact lookup: %v", errs)
	}
	return merged, nil
}

func (p *runtimePDPFactStore) CandidateFacts(ctx context.Context, nodeID string, m metrics, now time.Time) (runtimePDPFactSnapshot, error) {
	if p == nil || p.store == nil {
		return runtimePDPFactSnapshot{}, nil
	}

	var errs []error
	baselineRowsByID := map[string]sqlite.BaselineRow{}
	relationshipsByID := map[string]relationship.Relationship{}

	for _, subjectID := range runtimePDPSubjectEntityIDs(m) {
		rows, err := p.store.ListBaselinesBySubject(ctx, subjectID)
		if err != nil {
			errs = append(errs, err)
		}
		for _, row := range rows {
			baselineRowsByID[row.ID] = row
		}

		rels, err := p.store.ListRelationshipsBySubject(ctx, nodeID, subjectID)
		if err != nil {
			errs = append(errs, err)
		}
		for _, rel := range rels {
			relationshipsByID[rel.ID] = rel
		}
	}

	baselineRows := make([]sqlite.BaselineRow, 0, len(baselineRowsByID))
	for _, row := range baselineRowsByID {
		baselineRows = append(baselineRows, row)
	}
	sort.Slice(baselineRows, func(i, j int) bool {
		if baselineRows[i].Key.MetricID == baselineRows[j].Key.MetricID {
			return baselineRows[i].LastUpdated.After(baselineRows[j].LastUpdated)
		}
		return baselineRows[i].Key.MetricID < baselineRows[j].Key.MetricID
	})

	rels := make([]relationship.Relationship, 0, len(relationshipsByID))
	for _, rel := range relationshipsByID {
		rels = append(rels, rel)
	}
	sort.Slice(rels, func(i, j int) bool {
		if rels[i].LastSeenAt.Equal(rels[j].LastSeenAt) {
			return rels[i].ID < rels[j].ID
		}
		return rels[i].LastSeenAt.After(rels[j].LastSeenAt)
	})

	snapshot := runtimePDPFactSnapshot{
		Baseline: runtimePDPBaselineFacts(baselineRows, now),
		Graph:    runtimePDPRelationshipFacts(rels, now),
		Actions:  runtimePDPActionLeaseFacts(p.store, ctx, m, now),
	}
	if len(errs) > 0 {
		return snapshot, fmt.Errorf("runtime pdp fact lookup: %v", errs)
	}
	return snapshot, nil
}

func runtimePDPActionLeaseFacts(store *sqlite.Store, ctx context.Context, m metrics, now time.Time) map[string]any {
	if store == nil {
		return nil
	}
	leases, err := store.ListActionLeasesByStatus(ctx, decision.ActionLeaseActive)
	if err != nil {
		return map[string]any{"lookup_error": err.Error()}
	}
	sourceID := m.sourceID()
	out := map[string]any{}
	activeCount := 0
	for _, lease := range leases {
		if !lease.ExpiresAt.IsZero() && !now.Before(lease.ExpiresAt) {
			continue
		}
		if sourceID != "" && !actionLeaseMatchesSource(lease, sourceID) {
			continue
		}
		key := runtimePDPFactKey(lease.Action)
		if key == "" {
			continue
		}
		fact := map[string]any{
			"active":     true,
			"action":     lease.Action,
			"level":      lease.Level,
			"target":     lease.Target,
			"adapter_id": lease.AdapterID,
			"lease_id":   lease.LeaseID,
			"applied_at": lease.AppliedAt.UTC().Format(time.RFC3339Nano),
			"expires_at": lease.ExpiresAt.UTC().Format(time.RFC3339Nano),
		}
		if !lease.AppliedAt.IsZero() {
			fact["elapsed_seconds"] = now.Sub(lease.AppliedAt).Seconds()
		}
		if !lease.ExpiresAt.IsZero() {
			fact["remaining_seconds"] = lease.ExpiresAt.Sub(now).Seconds()
		}
		if dryRun, ok := actionLeaseBoolMetadata(lease, "param.execution_dry_run"); ok {
			fact["dry_run"] = dryRun
		}
		out[key] = fact
		activeCount++
	}
	out["active_count"] = activeCount
	return out
}

func actionLeaseBoolMetadata(lease decision.ActionLease, key string) (bool, bool) {
	raw := strings.TrimSpace(lease.Metadata[key])
	if raw == "" {
		return false, false
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, false
	}
	return value, true
}

func actionLeaseMatchesSource(lease decision.ActionLease, sourceID string) bool {
	if sourceID == "" {
		return true
	}
	if lease.Target == sourceID || strings.HasSuffix(lease.Target, ":"+sourceID) {
		return true
	}
	for _, key := range []string{"target_value", "target_attr.source_id", "target_attr.subject_id", "param.source_id", "param.subject_id"} {
		if lease.Metadata[key] == sourceID {
			return true
		}
	}
	return false
}

func runtimePDPSubjectEntityIDs(m metrics) []string {
	seen := map[string]bool{}
	out := []string{}
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}

	sourceID := m.sourceID()
	subject := m.Target.Subject
	if subject.ID != "" {
		if subject.Kind != "" {
			add(sqlite.StableEntityID(string(subject.Kind), subject.ID, subject.Namespace))
		}
		add(subject.ID)
	}
	if sourceID != "" {
		add(sqlite.StableEntityID("ip", sourceID, ""))
		add(sqlite.StableEntityID("source", sourceID, ""))
		add(sourceID)
	}
	for _, key := range []string{"stable_id", "subject_entity_id", "entity_stable_id"} {
		add(m.Target.Attributes[key])
	}
	return out
}

func runtimePDPBaselineFacts(rows []sqlite.BaselineRow, now time.Time) map[string]any {
	out := map[string]any{}
	if len(rows) == 0 {
		return out
	}
	profiles := make([]map[string]any, 0, len(rows))
	byMetric := map[string]any{}
	learned := map[string]any{}
	states := map[string]int{}

	for _, row := range rows {
		states[row.State]++
		baselineValue, hasBaseline := baselineCenterValue(row.EWMAState)
		peakValue, hasPeak := numericStateValue(row.EWMAState, "peak")
		confidence, hasConfidence := numericStateValue(row.EWMAState, "confidence")

		profile := map[string]any{
			"id":                row.ID,
			"metric_id":         row.Key.MetricID,
			"state":             row.State,
			"scope_type":        row.Key.ScopeType,
			"scope_id":          row.Key.ScopeID,
			"subject_entity_id": row.Key.SubjectEntityID,
			"object_entity_id":  row.Key.ObjectEntityID,
			"dimensions_hash":   row.Key.DimensionsHash,
			"source_class":      row.Key.SourceClass,
			"visibility_point":  row.Key.VisibilityPoint,
			"measurement_type":  row.Key.MeasurementType,
			"truth_class":       row.Key.TruthClass,
			"window_seconds":    row.Key.WindowSeconds,
			"observations":      row.Observations,
		}
		if !row.LastUpdated.IsZero() {
			profile["last_updated_at"] = row.LastUpdated.UTC().Format(time.RFC3339Nano)
			if !now.IsZero() {
				profile["freshness_seconds"] = now.Sub(row.LastUpdated).Seconds()
			}
		}
		if hasBaseline {
			profile["baseline"] = baselineValue
			learned[row.Key.MetricID] = baselineValue
			insertNestedFact(learned, row.Key.MetricID, baselineValue)
			out[row.Key.MetricID] = baselineValue
			insertNestedFact(out, row.Key.MetricID, baselineValue)
		}
		if hasPeak {
			profile["peak"] = peakValue
		}
		if hasConfidence {
			profile["confidence"] = confidence
		}
		profiles = append(profiles, profile)

		current, ok := byMetric[row.Key.MetricID].(map[string]any)
		if !ok || moreRelevantBaselineProfile(profile, current) {
			byMetric[row.Key.MetricID] = profile
		}
	}

	out["profiles"] = profiles
	out["by_metric"] = byMetric
	out["learned"] = learned
	out["profile_count"] = len(profiles)
	out["states"] = states
	return out
}

func runtimePDPRelationshipFacts(rels []relationship.Relationship, now time.Time) map[string]any {
	out := map[string]any{}
	if len(rels) == 0 {
		return out
	}
	rows := make([]map[string]any, 0, len(rels))
	states := map[string]int{}
	predicates := map[string]int{}
	sourceAdapters := map[string]int{}

	for _, rel := range rels {
		state := string(rel.State)
		states[state]++
		predicates[rel.Predicate]++
		sourceAdapters[rel.SourceAdapter]++
		row := map[string]any{
			"id":                rel.ID,
			"subject_entity_id": rel.SubjectEntityID,
			"predicate":         rel.Predicate,
			"object_entity_id":  rel.ObjectEntityID,
			"scope_type":        rel.ScopeType,
			"scope_id":          rel.ScopeID,
			"dimensions_hash":   rel.DimensionsHash,
			"state":             state,
			"weight":            rel.Weight,
			"confidence":        rel.Confidence,
			"seen_count":        rel.SeenCount,
			"distinct_windows":  rel.DistinctWindows,
			"learned_by":        string(rel.LearnedBy),
			"source_adapter":    rel.SourceAdapter,
		}
		if len(rel.Dimensions) > 0 {
			dims := map[string]any{}
			for k, v := range rel.Dimensions {
				dims[k] = v
			}
			row["dimensions"] = dims
		}
		if !rel.LastSeenAt.IsZero() {
			row["last_seen_at"] = rel.LastSeenAt.UTC().Format(time.RFC3339Nano)
			if !now.IsZero() {
				row["freshness_seconds"] = now.Sub(rel.LastSeenAt).Seconds()
			}
		}
		rows = append(rows, row)
	}

	out["relationships"] = rows
	out["relationship_count"] = len(rows)
	out["states"] = states
	out["predicates"] = predicates
	out["source_adapters"] = sourceAdapters
	for state, count := range states {
		out[state+"_count"] = count
		out["has_"+state] = count > 0
	}
	return out
}

func baselineCenterValue(state map[string]any) (float64, bool) {
	return numericStateValue(state, "ewma", "baseline", "median")
}

func numericStateValue(state map[string]any, keys ...string) (float64, bool) {
	if len(state) == 0 {
		return 0, false
	}
	for _, key := range keys {
		value, ok := state[key]
		if !ok {
			continue
		}
		switch v := value.(type) {
		case float64:
			return v, true
		case float32:
			return float64(v), true
		case int:
			return float64(v), true
		case int64:
			return float64(v), true
		case uint64:
			return float64(v), true
		case json.Number:
			if f, err := strconv.ParseFloat(v.String(), 64); err == nil {
				return f, true
			}
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				return f, true
			}
		}
	}
	return 0, false
}

func runtimePDPFactKey(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var out strings.Builder
	for _, r := range value {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			out.WriteRune(r)
			continue
		}
		out.WriteByte('_')
	}
	key := strings.Trim(out.String(), "_")
	if key == "" {
		return ""
	}
	if key[0] >= '0' && key[0] <= '9' {
		return "v_" + key
	}
	return key
}

func moreRelevantBaselineProfile(candidate, current map[string]any) bool {
	cObs, _ := candidate["observations"].(int64)
	curObs, _ := current["observations"].(int64)
	if cObs != curObs {
		return cObs > curObs
	}
	cFresh, cOK := candidate["freshness_seconds"].(float64)
	curFresh, curOK := current["freshness_seconds"].(float64)
	if cOK && curOK {
		return cFresh < curFresh
	}
	return false
}

func mergeFactMaps(base map[string]any, extra map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		if left, ok := out[k].(map[string]any); ok {
			if right, ok := v.(map[string]any); ok {
				out[k] = mergeFactMaps(left, right)
				continue
			}
		}
		out[k] = v
	}
	return out
}

func thresholdFactsWithSnapshot(t adapterruntime.TuningThresholds) map[string]any {
	thresholds := thresholdFactMap(t)
	out := mergeFactMaps(nil, thresholds)
	out["thresholds"] = thresholds
	return out
}
