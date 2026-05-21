// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package netfilter

import (
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

// Manifest is the static pipeline manifest for the netfilter adapter.
// It declares what the adapter consumes and provides for pipeline wiring
// and Forge registry validation.
//
// Note: capability availability is dynamic (probe-dependent). This manifest
// declares the full set of possible capabilities; the runtime Capabilities()
// method returns only what is actually supported after probing.
var Manifest = adapterruntime.AdapterManifest{
	ID:      "kernloom.netfilter",
	Type:    adapterruntime.ManifestTypePEP,
	Version: "0.1.0",

	Provides: adapterruntime.AdapterProvides{
		Observations: []observation.ObservationType{
			observation.TypeFlow, // conntrack snapshot (when available)
			observation.TypeDrop, // rule counter hits
		},
		Signals: []signal.SignalType{
			signal.SignalPPSHigh, // derived from counters (low fidelity)
		},
	},

	Consumes: adapterruntime.AdapterConsumes{
		Actions: []string{
			"enforce.network.deny",
			"enforce.network.allow",
			"enforce.network.rate_limit",
		},
	},

	// No default labels — cardinality-safe default per adapterruntime convention.
	LabelPolicy: adapterruntime.AdapterLabelPolicy{
		DefaultSelectedLabels: []string{},
	},
}
