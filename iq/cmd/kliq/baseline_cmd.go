// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

// runBaselineStatus shows per-edge baselines from the generic state store.
// Delegates to runBaselinesGenericList, which reads metric_baselines filtered
// to source_class=xdp and scope_type=relationship.
func runBaselineStatus(storePath, nodeID string, showAll bool, sortBy string) {
	// The new generic baselines are keyed by (metric_id, scope, source_class, ...).
	// For graph edge baselines: metric_id=network.xdp.edge.*, source_class=xdp.
	// Delegate to the generic baseline list command.
	runBaselinesGenericList(storePath, "network.xdp.edge", "relationship", "xdp", "metric")
}

// runBaselineReset resets edge baselines.
// In the new generic store, baselines are pruned by the GC loop (TTL-based).
// A manual reset deletes all metric_baselines rows for xdp/relationship scope.
func runBaselineReset(storePath, nodeID string) {
	// Use the storage cleanup which runs the GC.  For a targeted reset, users
	// can use 'kliq storage cleanup' or delete kliq-state.db directly.
	runStorageCleanup(storePath, false)
}
