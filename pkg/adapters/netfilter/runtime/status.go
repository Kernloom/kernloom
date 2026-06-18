// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package runtime

import (
	"context"
	"fmt"
	"text/tabwriter"

	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
)

func PrintStatus(w *tabwriter.Writer) {
	probe := netfilter.Probe(context.Background())
	if probe.Selected == "" {
		fmt.Fprintf(w, "netfilter:\tnot available (nft/iptables not found)\n")
		return
	}
	conntrackStatus := "no"
	if probe.Conntrack.Available {
		conntrackStatus = "yes"
		if probe.Conntrack.Accounting {
			conntrackStatus = "yes (accounting enabled)"
		}
	}
	fmt.Fprintf(w, "netfilter:\tbackend=%s  ipset=%v  hashlimit=%v  conntrack=%s\n",
		probe.Selected,
		probe.IPTables.IPSet.Available,
		probe.IPTables.HasLimit,
		conntrackStatus,
	)
}
