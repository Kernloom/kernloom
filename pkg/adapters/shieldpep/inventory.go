// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package shieldpep

import (
	"time"

	"github.com/kernloom/kernloom/pkg/componentinventory"
)

// BuildInventory returns a ComponentRuntimeInventory describing which Forge
// capabilities are actually available on this KLShield instance based on the
// maps that are currently open and the dry-run flag.
//
// Called once at KLIQ startup and included in enrollment/heartbeat payloads.
func (a *Adapter) BuildInventory(nodeID string) componentinventory.ComponentRuntimeInventory {
	inv := componentinventory.ComponentRuntimeInventory{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "ComponentRuntimeInventory",
	}
	inv.Metadata.ID = "klshield-" + nodeID
	inv.Metadata.Timestamp = time.Now().UTC()
	inv.ControlledBy.NodeID = nodeID
	inv.ControlledBy.PluginAdapter = "builtin-klshield"
	inv.Component.Product = "kernloom-shield"
	inv.Roles = []string{"pep", "sensor"}
	inv.Profiles = []string{"network.l3_l4_filter"}

	avail := func(id string, granularity ...string) componentinventory.CapabilityStatus {
		return componentinventory.CapabilityStatus{ID: id, Status: "available", Granularity: granularity}
	}
	degraded := func(id, reason string, granularity ...string) componentinventory.CapabilityStatus {
		return componentinventory.CapabilityStatus{ID: id, Status: "degraded", Granularity: granularity, Reason: reason}
	}
	unavail := func(id, reason string) componentinventory.CapabilityStatus {
		return componentinventory.CapabilityStatus{ID: id, Status: "unavailable", Reason: reason}
	}

	// Observation capabilities — available as long as the src4 telemetry map is open.
	if a.maps != nil && a.maps.Src4 != nil {
		inv.EffectiveCapabilities = append(inv.EffectiveCapabilities,
			avail("observe.network.connection", "src_ip", "dst_port", "protocol"),
			avail("observe.network.packet_summary", "src_ip"),
		)
	} else {
		inv.UnavailableCapabilities = append(inv.UnavailableCapabilities,
			unavail("observe.network.connection", "src4_map_not_available"),
			unavail("observe.network.packet_summary", "src4_map_not_available"),
		)
	}

	// Enforcement capabilities — degraded in dry-run, unavailable when maps missing.
	if a.dryRun {
		inv.EffectiveCapabilities = append(inv.EffectiveCapabilities,
			degraded("enforce.traffic.rate_limit", "dry_run", "src_ip"),
			degraded("enforce.access.deny", "dry_run", "src_ip"),
		)
	} else {
		if a.maps != nil && a.maps.RL4 != nil {
			inv.EffectiveCapabilities = append(inv.EffectiveCapabilities,
				avail("enforce.traffic.rate_limit", "src_ip"),
			)
		} else {
			inv.UnavailableCapabilities = append(inv.UnavailableCapabilities,
				unavail("enforce.traffic.rate_limit", "rl4_map_not_available"),
			)
		}
		if a.maps != nil && a.maps.Deny4 != nil {
			inv.EffectiveCapabilities = append(inv.EffectiveCapabilities,
				avail("enforce.access.deny", "src_ip"),
			)
		} else {
			inv.UnavailableCapabilities = append(inv.UnavailableCapabilities,
				unavail("enforce.access.deny", "deny4_map_not_available"),
			)
		}
	}

	// Tuple enforcement — only when XDP edge maps are loaded.
	if a.TupleAvailable() {
		inv.EffectiveCapabilities = append(inv.EffectiveCapabilities,
			avail("enforce.relation.deny", "tuple_src_dst_port"),
		)
	} else {
		inv.UnavailableCapabilities = append(inv.UnavailableCapabilities,
			unavail("enforce.relation.deny", "tuple_maps_not_available"),
		)
	}

	return inv
}
