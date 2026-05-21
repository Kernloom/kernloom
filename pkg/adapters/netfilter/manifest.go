// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package netfilter

import "github.com/kernloom/kernloom/pkg/adapterruntime"

// Manifest is the static pipeline manifest for the netfilter adapter.
// The netfilter adapter is enforcement-only — it provides no telemetry.
// Graph learning requires klshield (XDP) for accurate per-packet telemetry.
var Manifest = adapterruntime.AdapterManifest{
	ID:      "kernloom.netfilter",
	Type:    adapterruntime.ManifestTypePEP,
	Version: "0.1.0",

	// No Provides: netfilter does not emit observations or signals.
	// Telemetry requires klshield.

	Consumes: adapterruntime.AdapterConsumes{
		Actions: []string{
			"enforce.network.deny",
			"enforce.network.allow",
			"enforce.network.rate_limit",
		},
	},

	LabelPolicy: adapterruntime.AdapterLabelPolicy{
		DefaultSelectedLabels: []string{},
	},
}
