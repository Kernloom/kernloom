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
	"strings"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/lifecycle/bootstrapautotune"
	lgraph "github.com/kernloom/kernloom/iq/internal/lifecycle/graph"
	"github.com/kernloom/kernloom/pkg/core/bundle"
	corepolicy "github.com/kernloom/kernloom/pkg/core/policy"
	"gopkg.in/yaml.v3"
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
	runtimePolicyUpdates chan<- contracts.RuntimePolicyPack,
) {
	// Skip if the bundle hasn't changed — prevents repeated log spam every heartbeat.
	newHash := fmt.Sprintf("%x", hashBundleBytes(rawBundle))[:16]
	if newHash == ms.BundleHash {
		return
	}

	b, runtimePack, err := parseTrustedRuntimeBundle(rawBundle, c)
	if err != nil {
		kliqLog.Printf("BUNDLE apply: trust/parse failed: %v", err)
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

	if runtimePack != nil {
		applyRuntimePolicyPackToCfg(*runtimePack, c)
	}

	// Apply baseline lifecycle.
	if baselineLifecycleConfigured(b.Spec.BaselineLifecycle) {
		newBsCfg := bootstrapautotune.FromBaselineLifecycle(b.Spec.BaselineLifecycle)
		// Rebuild controller with new config, preserving accumulated state.
		savedState := (*bsCtl).SaveState()
		*bsCtl = bootstrapautotune.New(newBsCfg, &savedState)
		kliqLog.Printf("BUNDLE: baseline lifecycle applied (window=%v)", newBsCfg.Window)
	}

	graphPhase := (*graphCtl).Phase()

	// Apply graph lifecycle plan.
	if graphLifecycleConfigured(b.Spec.GraphLifecycle) {
		newGraphCfg := lgraph.FromBundle(b.Spec.GraphLifecycle)
		persistedPhase := graphPhase
		if persistedPhase == lgraph.PhaseDisabled && newGraphCfg.Enabled {
			persistedPhase = ""
		}
		// Rebuild graph controller with new config, preserving current phase.
		*graphCtl = lgraph.New(newGraphCfg, persistedPhase, (*graphCtl).StartedAt())
		kliqLog.Printf("BUNDLE: graph lifecycle plan applied (phase=%s)", (*graphCtl).Phase())
	}

	applyEnforcementBoundsToCfg(b.Spec.EnforcementBounds, *graphCtl, c)
	applyFailoverToCfg(b.Spec.Failover, c)

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

	if profileName := runtimeBundlePDPProfileName(b); profileName != "" {
		c.ProfileName = profileName
	}

	if adapters := runtimeBundleAdapters(b); adapters != "" {
		c.Adapters = adapters
	}

	if runtimePack != nil {
		if runtimePolicyUpdates != nil {
			select {
			case runtimePolicyUpdates <- *runtimePack:
				kliqLog.Printf("BUNDLE: runtime policy pack queued for RuntimePDP (rules=%d)", len(runtimePack.Spec.Rules))
			default:
				kliqLog.Printf("BUNDLE: runtime policy update channel full; dropping bundle pack")
			}
		}
	}

	kliqLog.Printf("BUNDLE applied: node=%s gen=%d feature_profile=%s pdp_profile=%s adapters=%s max_action=%s hash=%s",
		b.Metadata.NodeID, b.Metadata.Generation,
		c.FeatureProfile, c.ProfileName, c.Adapters, c.PolicyMaxAction, bundleHash)
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

func parseTrustedRuntimeBundle(rawBundle []byte, c *cfg) (*contracts.RuntimeBundle, *contracts.RuntimePolicyPack, error) {
	jsonBytes, err := yamlBytesToJSON(rawBundle)
	if err != nil {
		return nil, nil, fmt.Errorf("parse contracts runtime bundle: %w", err)
	}
	var rb contracts.RuntimeBundle
	if err := json.Unmarshal(jsonBytes, &rb); err != nil {
		return nil, nil, fmt.Errorf("parse contracts runtime bundle: %w", err)
	}

	now := time.Now().UTC()
	if c.Mode == string(corepolicy.ModeManaged) || c.PolicyVerifyKeyPath != "" {
		if c.PolicyVerifyKeyPath == "" {
			return nil, nil, fmt.Errorf("managed mode requires --policy-verify-key to verify runtime bundle signature")
		}
		pubKey, err := corepolicy.LoadPublicKey(c.PolicyVerifyKeyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load runtime bundle verify key: %w", err)
		}
		if err := contracts.VerifyRuntimeBundle(rb, pubKey, now); err != nil {
			return nil, nil, err
		}
	} else if err := contracts.ValidateRuntimeBundle(rb, now); err != nil {
		return nil, nil, err
	}
	if rb.Spec.RegistrySnapshot.Ref.Name == "" {
		return nil, nil, fmt.Errorf("contracts runtime bundle registry snapshot is required")
	}
	capabilitySeverityKLIQ = capabilitySeverityFromSnapshot(rb.Spec.RegistrySnapshot)

	pack := rb.Spec.RuntimePolicyPack
	return &rb, &pack, nil
}

func baselineLifecycleConfigured(plan contracts.BaselineLifecycle) bool {
	return strings.TrimSpace(plan.Mode) != ""
}

func graphLifecycleEnabled(plan contracts.GraphLifecycle) bool {
	return lifecycleModeEnabled(plan.Mode)
}

func graphLifecycleConfigured(plan contracts.GraphLifecycle) bool {
	return strings.TrimSpace(plan.Mode) != ""
}

func lifecycleModeEnabled(mode string) bool {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "", "disabled", "off", "none":
		return false
	default:
		return true
	}
}

func runtimeBundlePDPProfileName(b *contracts.RuntimeBundle) string {
	if b == nil {
		return ""
	}
	return b.Spec.RuntimePDPProfile.Name
}

func runtimeBundleAdapters(b *contracts.RuntimeBundle) string {
	if b == nil {
		return ""
	}
	return strings.Join(b.Spec.AdapterSelector.PreferredAdapters, ",")
}

func applyEnforcementBoundsToCfg(bounds contracts.EnforcementBounds, graphCtl *lgraph.Controller, c *cfg) {
	if !bounds.AllowBlock && c.PolicyMaxAction == "" {
		c.PolicyMaxAction = "rate_limit_hard"
	}
	if !bounds.AllowBlock {
		c.GraphFreezeAllowBlock = false
	}
	if graphCtl == nil {
		return
	}
	if maxAct := graphCtl.MaxAction(bounds); maxAct != "" {
		c.PolicyMaxAction = maxAct
	}
}

func applyFailoverToCfg(failover contracts.FailoverConfig, c *cfg) {
	if failover.Behavior != "" {
		c.FailMode = failover.Behavior
	}
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
