// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
)

/* ---------------- Persistence (state.json) ---------------- */

const (
	tuningScopeNetwork = "network"
)

type tuningScopeRef struct {
	AdapterID string
	Scope     string
	Key       string
}

func newTuningScopeRef(adapterID, scope string) tuningScopeRef {
	key := adapterID
	if scope != "" {
		key += ":" + scope
	}
	return tuningScopeRef{AdapterID: adapterID, Scope: scope, Key: key}
}

type trigState struct {
	TrigPPS  float64 `json:"trig_pps"`
	TrigSyn  float64 `json:"trig_syn"`
	TrigScan float64 `json:"trig_scan"`
	TrigBPS  float64 `json:"trig_bps,omitempty"` // 0 = disabled; absent in older state files
}

type tuneMeta struct {
	Method      string  `json:"method"`
	Window      string  `json:"window"`
	K           float64 `json:"k"`
	SigmaFactor float64 `json:"sigma_factor"`
}

type tuningMetricState struct {
	Threshold float64 `json:"threshold"`
}

type tuningScopeState struct {
	AdapterID   string                       `json:"adapter_id"`
	Scope       string                       `json:"scope"`
	Profile     string                       `json:"profile,omitempty"`
	Revision    int                          `json:"revision,omitempty"`
	UpdatedAt   time.Time                    `json:"updated_at,omitempty"`
	Metrics     map[string]tuningMetricState `json:"metrics,omitempty"`
	Tune        tuneMeta                     `json:"tune,omitempty"`
	SampleCount int                          `json:"sample_count,omitempty"`
	CleanRatio  float64                      `json:"clean_ratio,omitempty"`
	Notes       string                       `json:"notes,omitempty"`
}

type bootstrapInfo struct {
	Enabled   bool      `json:"enabled"`
	StartedAt time.Time `json:"started_at"`
	Window    string    `json:"window,omitempty"`
	Phase     string    `json:"phase,omitempty"`

	// ObservedSeconds counts only the seconds during which kliq was actually
	// running and processing valid (clean) telemetry. Offline time between
	// process restarts does not count. When > 0 this value is used instead of
	// wall-clock (now - StartedAt) to determine the current bootstrap phase.
	// Falls back to wall-clock for state files that pre-date this field.
	ObservedSeconds uint64 `json:"observed_seconds,omitempty"`
}

type stateActive struct {
	Profile   string    `json:"profile"`
	Revision  int       `json:"revision"`
	UpdatedAt time.Time `json:"updated_at"`
	// Trig is a legacy KLShield/network mirror used only when reading old
	// state files. New writes use TuningScopes so adapter-specific metrics do
	// not leak across KLIQ deployments.
	Trig         *trigState                  `json:"trig,omitempty"`
	Tune         tuneMeta                    `json:"tune"`
	TuningScopes map[string]tuningScopeState `json:"tuning_scopes,omitempty"`
	Bootstrap    bootstrapInfo               `json:"bootstrap,omitempty"`
	SampleCount  int                         `json:"sample_count"`
	CleanRatio   float64                     `json:"clean_ratio"`
	Notes        string                      `json:"notes,omitempty"`

	// ConfigHash is a short hash of autotune-relevant configuration values.
	// A mismatch between the hash in state.json and the current config causes
	// the bootstrap state to be invalidated so learning starts fresh.
	ConfigHash string `json:"config_hash,omitempty"`

	// ── Forge control-plane state ─────────────────────────────────────────────
	// These fields persist the Forge session across restarts so KLIQ does not
	// need to re-enroll after a restart (enrollment tokens are single-use).

	// ForgeSessionToken is the per-node token returned by Forge after enrollment.
	// Persisted so KLIQ can resume heartbeats and pack-pulls after restart
	// without consuming a new enrollment token.
	ForgeSessionToken string `json:"forge_session_token,omitempty"`

	// ForgePackName is the name of the last successfully applied policy pack.
	ForgePackName string `json:"forge_pack_name,omitempty"`

	// ForgePackIssuedAt is the issued_at timestamp of the last applied pack.
	// Used for rollback protection (CLAUDE.md rule #9): a pack with an earlier
	// IssuedAt is rejected even after a restart.
	ForgePackIssuedAt time.Time `json:"forge_pack_issued_at,omitempty"`

	// ForgePackHash is the SHA-256 hex digest of the last applied pack bytes.
	// Used for drift detection: if the running config differs from the last
	// applied pack, KLIQ reports drift_detected=true in the next heartbeat.
	ForgePackHash string `json:"forge_pack_hash,omitempty"`

	// ForgeBundleGeneration is the generation number of the last applied RuntimeBundle.
	ForgeBundleGeneration int `json:"forge_bundle_generation,omitempty"`

	// ForgeBundleHash is the content hash of the last applied RuntimeBundle.
	ForgeBundleHash string `json:"forge_bundle_hash,omitempty"`

	// GraphLifecyclePhase is the persisted managed-mode graph lifecycle phase
	// (learning, freeze_ready, frozen_observe, frozen_enforce).
	GraphLifecyclePhase string `json:"graph_lifecycle_phase,omitempty"`

	// GraphLifecycleStartedAt is when the current graph lifecycle session started.
	GraphLifecycleStartedAt time.Time `json:"graph_lifecycle_started_at,omitempty"`
}

type stateHistory struct {
	Revision int       `json:"revision"`
	At       time.Time `json:"at"`
	// Trig is a legacy KLShield/network mirror used only when reading old
	// histories. MetricThresholds is the generic representation keyed by
	// adapterruntime metric IDs.
	Trig             *trigState         `json:"trig,omitempty"`
	TuningScope      string             `json:"tuning_scope,omitempty"`
	MetricThresholds map[string]float64 `json:"metric_thresholds,omitempty"`
	// AdapterStats holds adapter-specific statistics for this autotune window.
	// Generic map keeps state.go free of adapter-domain field names.
	AdapterStats map[string]float64 `json:"adapter_stats,omitempty"`
	SampleCount  int                `json:"sample_count"`
	CleanRatio   float64            `json:"clean_ratio"`
	Notes        string             `json:"notes,omitempty"`
}

type integrity struct {
	SHA256 string `json:"sha256"`
}

type stateFile struct {
	Version   int            `json:"version"`
	Generated time.Time      `json:"generated_at"`
	Active    stateActive    `json:"active"`
	History   []stateHistory `json:"history"`
	Integrity integrity      `json:"integrity"`
}

// bootstrapConfigHash returns a short (16-char) hex digest of the autotune
// configuration fields that — if changed — would invalidate a persisted
// bootstrap session. Only fields that affect the learning outcome are included:
// changing cosmetic options (TopN, DryRun, log verbosity) does not reset.
func bootstrapConfigHash(c *cfg) string {
	scopeKey := "none"
	if scope, ok := c.tuningScopeRef(); ok {
		scopeKey = scope.Key
	}
	key := fmt.Sprintf("%s|%s|%s|%.2f|%.2f|%.2f|%.2f",
		scopeKey,
		c.BPFfsRoot,
		c.BootstrapWindow.String(),
		c.AutoFloorPPS, c.AutoFloorSyn, c.AutoFloorScan, c.AutoFloorBPS)
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:8]) // 16 hex chars — collision-safe for this use case
}

func computeSHA256NoIntegrity(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func writeStateAtomic(path string, st *stateFile) error {
	st.Generated = time.Now() // must be set on st before hashing

	tmp := *st
	tmp.Integrity = integrity{}

	rawNoInt, err := json.MarshalIndent(&tmp, "", "  ")
	if err != nil {
		return err
	}

	st.Integrity = integrity{SHA256: computeSHA256NoIntegrity(rawNoInt)}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	tmpPath := path + ".tmp"
	bakPath := path + ".bak"

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	if _, err := os.Stat(path); err == nil {
		_ = os.Rename(path, bakPath)
	}

	return os.Rename(tmpPath, path)
}

func loadState(path string, maxAge time.Duration) (*stateFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var st stateFile
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}

	tmp := st
	tmp.Integrity = integrity{}
	rawNoInt, _ := json.MarshalIndent(&tmp, "", "  ")
	want := computeSHA256NoIntegrity(rawNoInt)
	if st.Integrity.SHA256 != "" && st.Integrity.SHA256 != want {
		return nil, fmt.Errorf("state integrity mismatch")
	}

	if maxAge > 0 && !st.Active.UpdatedAt.IsZero() {
		if time.Since(st.Active.UpdatedAt) > maxAge {
			return nil, fmt.Errorf("state too old (%s)", time.Since(st.Active.UpdatedAt).String())
		}
	}
	return &st, nil
}

func applyAutotuneStateUpdate(
	st *stateFile,
	profileName string,
	scope tuningScopeRef,
	bs bootstrapInfo,
	cfgHash string,
	historyKeep int,
	result adapterruntime.TuningResult,
	k float64,
	dropRatio float64,
) *stateFile {
	if st == nil {
		st = &stateFile{Version: 1}
	}
	rev := st.Active.Revision + 1
	stats := result.AdapterStats
	if stats == nil {
		stats = map[string]float64{}
	}
	stats["k"] = k
	t := result.NewThresholds
	updatedAt := time.Now()
	st.History = append(st.History, stateHistory{
		Revision:         rev,
		At:               updatedAt,
		TuningScope:      scope.Key,
		MetricThresholds: thresholdsToMetricThresholds(t),
		AdapterStats:     stats,
		SampleCount:      result.SampleCount,
		CleanRatio:       result.CleanRatio,
		Notes:            fmt.Sprintf("autotune dropRatio=%.4f phase=%s", dropRatio, result.Phase),
	})
	if len(st.History) > historyKeep && historyKeep > 0 {
		st.History = st.History[len(st.History)-historyKeep:]
	}
	scopes := cloneTuningScopes(st.Active.TuningScopes)
	if scope.Key != "" {
		scopes[scope.Key] = tuningScopeState{
			AdapterID:   scope.AdapterID,
			Scope:       scope.Scope,
			Profile:     profileName,
			Revision:    rev,
			UpdatedAt:   updatedAt,
			Metrics:     thresholdsToTuningMetrics(t),
			Tune:        tuneMeta{Method: "median_mad", Window: "reservoir", K: k, SigmaFactor: 1.4826},
			SampleCount: result.SampleCount,
			CleanRatio:  result.CleanRatio,
			Notes:       "autotune",
		}
	}
	st.Active = stateActive{
		Profile:      profileName,
		Revision:     rev,
		UpdatedAt:    updatedAt,
		Tune:         tuneMeta{Method: "median_mad", Window: "reservoir", K: k, SigmaFactor: 1.4826},
		TuningScopes: scopes,
		Bootstrap:    bs,
		ConfigHash:   cfgHash,
		SampleCount:  result.SampleCount,
		CleanRatio:   result.CleanRatio,
		Notes:        "autotune",
	}
	return st
}

func newBootstrapStateActive(profileName string, c cfg, bs bootstrapInfo, cfgHash string) stateActive {
	t := c.tuningThresholds()
	scopes := map[string]tuningScopeState{}
	if scope, ok := c.tuningScopeRef(); ok {
		scopes[scope.Key] = tuningScopeState{
			AdapterID:   scope.AdapterID,
			Scope:       scope.Scope,
			Profile:     profileName,
			Revision:    0,
			UpdatedAt:   time.Time{},
			Metrics:     thresholdsToTuningMetrics(t),
			Tune:        tuneMeta{Method: "median_mad", Window: "reservoir", K: c.AutoK, SigmaFactor: 1.4826},
			SampleCount: 0,
			CleanRatio:  1.0,
			Notes:       "bootstrap initialized",
		}
	}
	return stateActive{
		Profile:      profileName,
		Revision:     0,
		UpdatedAt:    time.Time{},
		Tune:         tuneMeta{Method: "median_mad", Window: "reservoir", K: c.AutoK, SigmaFactor: 1.4826},
		TuningScopes: scopes,
		Bootstrap:    bs,
		ConfigHash:   cfgHash,
		SampleCount:  0,
		CleanRatio:   1.0,
		Notes:        "bootstrap initialized",
	}
}

func thresholdsToTrigState(t adapterruntime.TuningThresholds) trigState {
	return trigState{
		TrigPPS:  t.PacketsPerSecond,
		TrigSyn:  t.SynRate,
		TrigScan: t.DestinationPortChanges,
		TrigBPS:  t.BytesPerSecond,
	}
}

func thresholdsToTuningMetrics(t adapterruntime.TuningThresholds) map[string]tuningMetricState {
	out := make(map[string]tuningMetricState, 4)
	if t.PacketsPerSecond > 0 {
		out[adapterruntime.MetricNetworkPacketsPerSecond] = tuningMetricState{Threshold: t.PacketsPerSecond}
	}
	if t.SynRate > 0 {
		out[adapterruntime.MetricNetworkSynRate] = tuningMetricState{Threshold: t.SynRate}
	}
	if t.DestinationPortChanges > 0 {
		out[adapterruntime.MetricNetworkDestinationPortChanges] = tuningMetricState{Threshold: t.DestinationPortChanges}
	}
	if t.BytesPerSecond > 0 {
		out[adapterruntime.MetricNetworkBytesPerSecond] = tuningMetricState{Threshold: t.BytesPerSecond}
	}
	return out
}

func thresholdsToMetricThresholds(t adapterruntime.TuningThresholds) map[string]float64 {
	out := make(map[string]float64, 4)
	for k, v := range thresholdsToTuningMetrics(t) {
		out[k] = v.Threshold
	}
	return out
}

func metricThresholdsToThresholds(metrics map[string]float64) (adapterruntime.TuningThresholds, bool) {
	if len(metrics) == 0 {
		return adapterruntime.TuningThresholds{}, false
	}
	t := adapterruntime.TuningThresholds{
		PacketsPerSecond:       metrics[adapterruntime.MetricNetworkPacketsPerSecond],
		SynRate:                metrics[adapterruntime.MetricNetworkSynRate],
		DestinationPortChanges: metrics[adapterruntime.MetricNetworkDestinationPortChanges],
		BytesPerSecond:         metrics[adapterruntime.MetricNetworkBytesPerSecond],
	}
	return t, t.PacketsPerSecond > 0 || t.SynRate > 0 || t.DestinationPortChanges > 0 || t.BytesPerSecond > 0
}

func tuningMetricsToThresholds(metrics map[string]tuningMetricState) (adapterruntime.TuningThresholds, bool) {
	if len(metrics) == 0 {
		return adapterruntime.TuningThresholds{}, false
	}
	t := adapterruntime.TuningThresholds{
		PacketsPerSecond:       metrics[adapterruntime.MetricNetworkPacketsPerSecond].Threshold,
		SynRate:                metrics[adapterruntime.MetricNetworkSynRate].Threshold,
		DestinationPortChanges: metrics[adapterruntime.MetricNetworkDestinationPortChanges].Threshold,
		BytesPerSecond:         metrics[adapterruntime.MetricNetworkBytesPerSecond].Threshold,
	}
	return t, t.PacketsPerSecond > 0 || t.SynRate > 0 || t.DestinationPortChanges > 0 || t.BytesPerSecond > 0
}

func trigStateToThresholds(trig *trigState) (adapterruntime.TuningThresholds, bool) {
	if trig == nil {
		return adapterruntime.TuningThresholds{}, false
	}
	t := adapterruntime.TuningThresholds{
		PacketsPerSecond:       trig.TrigPPS,
		SynRate:                trig.TrigSyn,
		DestinationPortChanges: trig.TrigScan,
		BytesPerSecond:         trig.TrigBPS,
	}
	return t, t.PacketsPerSecond > 0 || t.SynRate > 0 || t.DestinationPortChanges > 0 || t.BytesPerSecond > 0
}

func cloneTuningScopes(in map[string]tuningScopeState) map[string]tuningScopeState {
	out := make(map[string]tuningScopeState, len(in)+1)
	for k, v := range in {
		if v.Metrics != nil {
			m := make(map[string]tuningMetricState, len(v.Metrics))
			for mk, mv := range v.Metrics {
				m[mk] = mv
			}
			v.Metrics = m
		}
		out[k] = v
	}
	return out
}
