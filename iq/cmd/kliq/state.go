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
)

/* ---------------- Persistence (state.json) ---------------- */

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
	Profile     string        `json:"profile"`
	Revision    int           `json:"revision"`
	UpdatedAt   time.Time     `json:"updated_at"`
	Trig        trigState     `json:"trig"`
	Tune        tuneMeta      `json:"tune"`
	Bootstrap   bootstrapInfo `json:"bootstrap,omitempty"`
	SampleCount int           `json:"sample_count"`
	CleanRatio  float64       `json:"clean_ratio"`
	Notes       string        `json:"notes,omitempty"`

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
}

type stateHistory struct {
	Revision    int       `json:"revision"`
	At          time.Time `json:"at"`
	Trig        trigState `json:"trig"`
	MedianPPS   float64   `json:"median_pps"`
	MadPPS      float64   `json:"mad_pps"`
	MedianSyn   float64   `json:"median_syn"`
	MadSyn      float64   `json:"mad_syn"`
	MedianScan  float64   `json:"median_scan"`
	MadScan     float64   `json:"mad_scan"`
	MedianBPS   float64   `json:"median_bps,omitempty"`
	MadBPS      float64   `json:"mad_bps,omitempty"`
	SampleCount int       `json:"sample_count"`
	CleanRatio  float64   `json:"clean_ratio"`
	Notes       string    `json:"notes,omitempty"`
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
	key := fmt.Sprintf("%s|%s|%.2f|%.2f|%.2f|%.2f",
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
