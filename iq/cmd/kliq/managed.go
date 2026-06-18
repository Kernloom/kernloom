// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package main — managed.go contains the RuntimeBundle apply logic and the
// managed-mode state persistence helpers. It is compiled only as part of the
// kliq binary, not as a separate library.
//
// The managed lifecycle is driven by the heartbeat goroutine (which sends raw
// bundle bytes over bundleUpdateCh) and consumed in the main tick loop via
// applyBundleUpdate(). The main loop remains the single writer to cfg and the
// lifecycle controllers — no locking is required because both live on the same
// goroutine.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/kernloom/kernloom/iq/internal/lifecycle/bootstrapautotune"
	lgraph "github.com/kernloom/kernloom/iq/internal/lifecycle/graph"
	"github.com/kernloom/kernloom/pkg/core/bundle"
	corepolicy "github.com/kernloom/kernloom/pkg/core/policy"
)

// managedState holds the bundle-related runtime state that is persisted
// alongside the autotune state in state.json and in managed/current-bundle.yaml.
type managedState struct {
	BundleGeneration    int       `json:"bundle_generation,omitempty"`
	BundleHash          string    `json:"bundle_hash,omitempty"`
	GraphLifecyclePhase string    `json:"graph_lifecycle_phase,omitempty"`
	GraphLifecycleStart time.Time `json:"graph_lifecycle_started_at,omitempty"`
}

// applyBundleUpdate is called by the main tick loop when a new bundle arrives
// over bundleUpdateCh. It parses the bundle, updates the controllers and cfg,
// writes the last-known-good bundle file, and persists managed state.
//
// It is intentionally called synchronously in the main goroutine — no locks needed.
func applyBundleUpdate(
	rawBundle []byte,
	c *cfg,
	bsCtl **bootstrapautotune.Controller,
	graphCtl **lgraph.Controller,
	ms *managedState,
	stFile *stateFile,
) {
	// Skip if the bundle hasn't changed — prevents repeated log spam every heartbeat.
	newHash := fmt.Sprintf("%x", hashBundleBytes(rawBundle))[:16]
	if newHash == ms.BundleHash {
		return
	}

	b, err := parseTrustedRuntimeBundle(rawBundle, c)
	if err != nil {
		kliqLog.Printf("BUNDLE apply: trust/parse failed: %v", err)
		return
	}
	if err := b.Validate(); err != nil {
		kliqLog.Printf("BUNDLE apply: validation failed: %v", err)
		return
	}
	if b.IsExpired() {
		kliqLog.Printf("BUNDLE apply: bundle generation=%d is expired — ignoring", b.Metadata.Generation)
		return
	}
	// Rollback protection: reject bundles with an older generation.
	if ms.BundleGeneration > 0 && b.Metadata.Generation < ms.BundleGeneration {
		kliqLog.Printf("BUNDLE apply: rollback rejected gen=%d < current=%d", b.Metadata.Generation, ms.BundleGeneration)
		return
	}
	if ms.BundleGeneration > 0 && b.Metadata.Generation == ms.BundleGeneration && ms.BundleHash != "" && newHash != ms.BundleHash {
		kliqLog.Printf("BUNDLE apply: same-generation mutation rejected gen=%d current_hash=%s new_hash=%s",
			b.Metadata.Generation, ms.BundleHash, newHash)
		return
	}

	// Apply bootstrap autotune plan.
	if b.Spec.BootstrapAutotune.Enabled {
		newBsCfg := bootstrapautotune.FromBundle(b.Spec.BootstrapAutotune)
		// Apply floor values back to cfg so existing autotune math uses them.
		if newBsCfg.FloorPPS > 0 {
			c.AutoFloorPPS = newBsCfg.FloorPPS
		}
		if newBsCfg.FloorSYN > 0 {
			c.AutoFloorSyn = newBsCfg.FloorSYN
		}
		if newBsCfg.FloorScan > 0 {
			c.AutoFloorScan = newBsCfg.FloorScan
		}
		if newBsCfg.FloorBPS > 0 {
			c.AutoFloorBPS = newBsCfg.FloorBPS
		}
		// Rebuild controller with new config, preserving accumulated state.
		savedState := (*bsCtl).SaveState()
		*bsCtl = bootstrapautotune.New(newBsCfg, &savedState)
		kliqLog.Printf("BUNDLE: bootstrap autotune plan applied (window=%v)", newBsCfg.Window)
	}

	// Apply enforcement bounds.
	bounds := b.Spec.EnforcementBounds
	graphPhase := (*graphCtl).Phase()
	if maxAct := (*graphCtl).MaxAction(bounds); maxAct != "" {
		c.PolicyMaxAction = maxAct
	}

	// Apply graph lifecycle plan.
	if b.Spec.GraphLifecycle.Enabled {
		newGraphCfg := lgraph.FromBundle(b.Spec.GraphLifecycle)
		// Rebuild graph controller with new config, preserving current phase.
		*graphCtl = lgraph.New(newGraphCfg, graphPhase, (*graphCtl).StartedAt())
		kliqLog.Printf("BUNDLE: graph lifecycle plan applied (phase=%s)", graphPhase)
	}

	// Apply managed exemptions to cfg (whitelist/feedback are reloaded from managed bundle).
	if len(b.Spec.ManagedExemptions.Whitelist) > 0 || len(b.Spec.ManagedExemptions.Feedback) > 0 {
		kliqLog.Printf("BUNDLE: %d managed whitelist + %d feedback exemptions received",
			len(b.Spec.ManagedExemptions.Whitelist), len(b.Spec.ManagedExemptions.Feedback))
		// Exemptions are stored for status reporting; actual enforcement is via
		// the existing whitelist/feedback reload mechanisms.
	}

	// Persist the last-known-good bundle.
	bundleHash := fmt.Sprintf("%x", hashBundleBytes(rawBundle))[:16]
	ms.BundleGeneration = b.Metadata.Generation
	ms.BundleHash = bundleHash

	if c.StatePath != "" {
		managedDir := filepath.Join(filepath.Dir(c.StatePath), "managed")
		if err := os.MkdirAll(managedDir, 0o755); err == nil {
			bundlePath := filepath.Join(managedDir, "current-bundle.yaml")
			_ = os.WriteFile(bundlePath, rawBundle, 0o644)
		}
	}

	if b.Spec.PDPProfile != "" {
		c.ProfileName = b.Spec.PDPProfile
	}

	if b.Spec.Adapters != "" {
		c.Adapters = b.Spec.Adapters
	}

	kliqLog.Printf("BUNDLE applied: node=%s gen=%d feature_profile=%s pdp_profile=%s adapters=%s max_action=%s hash=%s",
		b.Metadata.NodeID, b.Metadata.Generation,
		b.Spec.FeatureProfile, c.ProfileName, c.Adapters, c.PolicyMaxAction, bundleHash)
}

// loadLastKnownGoodBundle attempts to read the persisted bundle from
// managed/current-bundle.yaml. Returns nil if absent or unreadable.
func loadLastKnownGoodBundle(statePath string) []byte {
	if statePath == "" {
		return nil
	}
	p := filepath.Join(filepath.Dir(statePath), "managed", "current-bundle.yaml")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return data
}

func parseTrustedRuntimeBundle(rawBundle []byte, c *cfg) (*bundle.RuntimeBundle, error) {
	if c.Mode != string(corepolicy.ModeManaged) {
		return bundle.Parse(rawBundle)
	}
	if c.PolicyVerifyKeyPath == "" {
		return nil, fmt.Errorf("managed mode requires --policy-verify-key to verify runtime bundle signature")
	}
	pubKey, err := corepolicy.LoadPublicKey(c.PolicyVerifyKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load runtime bundle verify key: %w", err)
	}
	return bundle.VerifyRuntimeBundle(rawBundle, pubKey)
}

// buildRuntimeStatus assembles the rich heartbeat payload for Forge.
func buildRuntimeStatus(
	nodeID string,
	ms managedState,
	bsCtl *bootstrapautotune.Controller,
	graphCtl *lgraph.Controller,
	graphStats lgraph.GraphStats,
	c *cfg,
	tupleActive bool,
) bundle.RuntimeStatus {
	triggers := bundle.TriggerSet{PPS: c.TrigPPS, SYN: c.TrigSyn, Scan: c.TrigScan, BPS: c.TrigBPS}
	status := bundle.RuntimeStatus{
		NodeID:                 nodeID,
		BundleGeneration:       ms.BundleGeneration,
		BundleHash:             ms.BundleHash,
		Applied:                ms.BundleGeneration > 0,
		ReportedAt:             time.Now().UTC(),
		FeatureProfile:         c.FeatureProfile,
		TupleEnforcementActive: tupleActive,
		BootstrapAutotune:      bsCtl.StatusReport(triggers, time.Now()),
		GraphLifecycle:         graphCtl.StatusReport(graphStats, time.Now()),
	}
	return status
}

// uploadBaselineProposal marshals and uploads the proposal to Forge.
// Returns the proposal ID from Forge, or empty string on failure.
func uploadBaselineProposal(
	ctx context.Context,
	fc *forgeClient,
	nodeID string,
	graphCtl *lgraph.Controller,
	bsCtl *bootstrapautotune.Controller,
	graphStats lgraph.GraphStats,
	c *cfg,
) string {
	triggers := bundle.TriggerSet{PPS: c.TrigPPS, SYN: c.TrigSyn, Scan: c.TrigScan, BPS: c.TrigBPS}
	proposal := graphCtl.BuildProposal(
		nodeID, graphStats, nil,
		triggers, bsCtl.ObservedSeconds(), bsCtl.CleanRatio(),
	)
	raw, err := yaml.Marshal(&proposal)
	if err != nil {
		kliqLog.Printf("MANAGED: proposal marshal failed: %v", err)
		return ""
	}
	id, err := fc.UploadBaselineProposal(ctx, raw)
	if err != nil {
		kliqLog.Printf("MANAGED: proposal upload failed: %v", err)
		return ""
	}
	kliqLog.Printf("MANAGED: baseline proposal uploaded id=%s", id)
	return id
}

// reportBundleStatus sends the rich status to Forge.
func reportBundleStatus(ctx context.Context, fc *forgeClient, status bundle.RuntimeStatus) {
	statusJSON, _ := json.Marshal(status)
	if err := fc.ReportBundleStatus(ctx,
		status.BundleGeneration,
		status.Applied,
		status.DriftDetected,
		string(statusJSON),
		status.ErrorDetail,
	); err != nil {
		kliqLog.Printf("MANAGED: bundle status report failed: %v", err)
	}
}

func hashBundleBytes(b []byte) [32]byte { return sha256.Sum256(b) }
