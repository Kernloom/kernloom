// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/catalog"
	"github.com/kernloom/kernloom/pkg/componentinventory"
	"github.com/kernloom/kernloom/pkg/core/featureset"
	"github.com/kernloom/kernloom/pkg/core/policy"
)

// buildConfigAssetReport constructs a KliqConfigAssetReport from the current
// effective configuration. Called once after all config sources (flags, PDP
// config, policy pack) have been applied.
//
// No secret values are included — enrollment keys and certificate paths belong
// in the deployment config, not in a report that may be logged or transmitted.
func buildConfigAssetReport(c cfg, nodeID string, features featureset.FeatureSet, activeAdapters map[string]bool) componentinventory.KliqConfigAssetReport {
	r := componentinventory.KliqConfigAssetReport{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "KliqConfigAssetReport",
	}
	r.Metadata.NodeID = nodeID
	r.Metadata.Timestamp = time.Now().UTC()

	r.Mode = c.Mode
	r.HasPolicyPack = c.HasPolicyPack
	r.PolicyMaxAction = c.PolicyMaxAction
	r.AllowLocalBlock = c.GraphFreezeAllowBlock
	r.DryRun = c.DryRun

	// Autonomous enforcement = standalone mode without a policy pack in effect.
	r.AutonomousEnforcement = c.Mode != string(policy.ModeManaged)

	if c.Mode == string(policy.ModeManaged) {
		r.PolicyAuthority = "forge"
	} else {
		r.PolicyAuthority = "local"
	}

	// Allowed capabilities from the loaded pack.
	for cap := range c.CapabilitiesRequired {
		r.AllowedCapabilities = append(r.AllowedCapabilities, cap)
	}

	r.Adapters = adapterSummaries(c, nodeID, activeAdapters)

	// Analyzers active based on feature profile.
	if features.SourceBaseline {
		r.Analyzers = append(r.Analyzers, "source_baseline")
	}
	if features.GraphLearning {
		r.Analyzers = append(r.Analyzers, "graph_learner")
	}
	r.Analyzers = append(r.Analyzers, "fsm_heuristic")

	r.Safety = componentinventory.SafetyConfig{
		DefaultIfNoPolicyPack: "observe",
		MaxActionWithoutForge: "observe",
	}

	// Rate enforcement mode and effective rates at startup.
	// Priority: directive > adaptive > static (mirrors toPEPParams logic).
	pepParams := c.toPEPParams()
	if c.SoftDirectiveRatePPS > 0 || c.HardDirectiveRatePPS > 0 {
		r.EnforcementMode = "directive"
		r.SoftDirectiveRatePPS = c.SoftDirectiveRatePPS
		r.HardDirectiveRatePPS = c.HardDirectiveRatePPS
	} else if c.SoftRateFactor > 0 || c.HardRateFactor > 0 {
		r.EnforcementMode = "autonomy"
		r.SoftRateFactor = c.SoftRateFactor
		r.HardRateFactor = c.HardRateFactor
		r.InitialTrigPPS = c.TrigPPS
	} else {
		r.EnforcementMode = "autonomy"
	}
	r.EffectiveSoftRatePPS = pepParams.SoftRate
	r.EffectiveHardRatePPS = pepParams.HardRate

	return r
}

func adapterSummaries(c cfg, nodeID string, activeAdapters map[string]bool) []componentinventory.AdapterSummary {
	var out []componentinventory.AdapterSummary
	for _, name := range c.adapterNames() {
		if name == "none" {
			continue
		}
		id := name
		if catalog.IsBindingAdapter(name) {
			id = catalog.CanonicalAdapterID(name)
		}
		out = append(out, componentinventory.AdapterSummary{
			ID:      id + "-" + nodeID,
			Plugin:  "builtin-" + id,
			Enabled: activeAdapters[id],
		})
	}
	return out
}

// reportSidecarPath returns the path of the runtime-report sidecar file,
// derived from the state file path (replace "state.json" → "report.json").
func reportSidecarPath(statePath string) string {
	if statePath == "" {
		return ""
	}
	dir := filepath.Dir(statePath)
	return filepath.Join(dir, "kliq-report.json")
}

// runtimeReport is the combined sidecar written at startup.
type runtimeReport struct {
	Inventory    componentinventory.ComponentRuntimeInventory `json:"inventory"`
	ConfigReport componentinventory.KliqConfigAssetReport     `json:"config_report"`
}

// updateSidecarPack rewrites the sidecar to reflect that a policy pack was
// applied after startup (e.g. pulled from Forge on first heartbeat).
func updateSidecarPack(statePath, packName, maxAction string) {
	sidecar := reportSidecarPath(statePath)
	if sidecar == "" {
		return
	}
	data, err := os.ReadFile(sidecar)
	if err != nil {
		return
	}
	var rep runtimeReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return
	}
	rep.ConfigReport.HasPolicyPack = true
	rep.ConfigReport.PolicyMaxAction = maxAction
	if updated, err := json.MarshalIndent(rep, "", "  "); err == nil {
		_ = os.WriteFile(sidecar, updated, 0o644)
	}
}

// buildEmptyInventory returns a minimal ComponentRuntimeInventory for nodes
// that start without a catalog adapter inventory (netfilter-only or observation-only deployments).
func buildEmptyInventory(nodeID string) componentinventory.ComponentRuntimeInventory {
	var inv componentinventory.ComponentRuntimeInventory
	inv.APIVersion = "kernloom.io/v1alpha1"
	inv.Kind = "ComponentInventory"
	inv.Metadata.ID = nodeID
	return inv
}

func parseNodeLabels(raw string) map[string]string {
	labels := map[string]string{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		labels[key] = strings.TrimSpace(value)
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func applyNodeLabels(inv *componentinventory.ComponentRuntimeInventory, labels map[string]string) {
	if inv == nil || len(labels) == 0 {
		return
	}
	if inv.Labels == nil {
		inv.Labels = map[string]string{}
	}
	for key, value := range labels {
		inv.Labels[key] = value
	}
}

// logInventoryAndReport logs a summary of the inventory and policy config, and
// saves the full report as JSON to a sidecar file for "kliq status".
func logInventoryAndReport(
	inv componentinventory.ComponentRuntimeInventory,
	report componentinventory.KliqConfigAssetReport,
	statePath string,
) {
	// Compact startup log.
	capIDs := make([]string, 0, len(inv.EffectiveCapabilities))
	for _, c := range inv.EffectiveCapabilities {
		capIDs = append(capIDs, c.ID)
	}
	kliqLog.Printf("INVENTORY node=%s mode=%s policy_pack=%v max_action=%q capabilities=%v",
		report.Metadata.NodeID, report.Mode, report.HasPolicyPack, report.PolicyMaxAction, capIDs)

	// Save full report to sidecar for kliq status.
	sidecar := reportSidecarPath(statePath)
	if sidecar == "" {
		return
	}
	combined := runtimeReport{Inventory: inv, ConfigReport: report}
	if data, err := json.MarshalIndent(combined, "", "  "); err == nil {
		_ = os.WriteFile(sidecar, data, 0o644)
	}
}
