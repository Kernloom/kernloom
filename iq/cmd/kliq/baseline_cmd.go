// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/adrianenderlin/kernloom/pkg/core/baseline"
	gstore "github.com/adrianenderlin/kernloom/pkg/graphstore/sqlite"
)

// runBaselineStatus prints per-edge baseline stats (stored in graph_edges.bl_*).
func runBaselineStatus(storePath, nodeID string, showAll bool, sortBy string) {
	s, err := gstore.Open(storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	edges, err := s.ListEdgeBaselines(nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list edge baselines: %v\n", err)
		os.Exit(1)
	}

	// Sort edges.
	switch strings.ToLower(sortBy) {
	case "state":
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].Profile.State != edges[j].Profile.State {
				return edges[i].Profile.State < edges[j].Profile.State // learned < candidate alphabetically reversed
			}
			return edges[i].Profile.Observations > edges[j].Profile.Observations
		})
	case "src":
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].SourceID != edges[j].SourceID {
				return edges[i].SourceID < edges[j].SourceID
			}
			return edges[i].DestinationPort < edges[j].DestinationPort
		})
	case "port":
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].DestinationPort != edges[j].DestinationPort {
				return edges[i].DestinationPort < edges[j].DestinationPort
			}
			return edges[i].SourceID < edges[j].SourceID
		})
	case "pps":
		sort.Slice(edges, func(i, j int) bool {
			return edges[i].Profile.PPSMedian > edges[j].Profile.PPSMedian
		})
	case "bps":
		sort.Slice(edges, func(i, j int) bool {
			return edges[i].Profile.BytesMedian > edges[j].Profile.BytesMedian
		})
	default: // "obs"
		sort.Slice(edges, func(i, j int) bool {
			return edges[i].Profile.Observations > edges[j].Profile.Observations
		})
	}

	fmt.Printf("Baseline status for node: %s\n\n", nodeID)

	// State summary.
	candidateN, learnedN := 0, 0
	for _, e := range edges {
		if e.Profile.State == baseline.StateLearned {
			learnedN++
		} else {
			candidateN++
		}
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  STATE\tCOUNT")
	if candidateN > 0 {
		fmt.Fprintf(w, "  candidate\t%d\n", candidateN)
	}
	if learnedN > 0 {
		fmt.Fprintf(w, "  learned\t%d\n", learnedN)
	}
	w.Flush()

	// Per-edge table.
	fmt.Printf("\nEdge baselines (%d total):\n\n", len(edges))
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "BL\tGRAPH\tSOURCE\tDST\tPROTO\tPORT\tOBS\tPPS_MED\tPPS_MAD\tPPS_PEAK\tBPS_MED\tBPS_MAD\tBPS_PEAK")

	shown := edges
	const defaultCap = 40
	if !showAll && len(shown) > defaultCap {
		shown = shown[:defaultCap]
	}
	for _, e := range shown {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%.1f\t%.1f\t%.0f\t%.0f\t%.0f\t%.0f\n",
			e.Profile.State, e.GraphState,
			e.SourceID, e.DestinationID, e.Protocol, e.DestinationPort,
			e.Profile.Observations, e.Profile.PPSMedian, e.Profile.PPSMad, e.Profile.PPSPeak,
			e.Profile.BytesMedian, e.Profile.BytesMad, e.Profile.BPSPeak,
		)
	}
	w.Flush()
	if !showAll && len(edges) > defaultCap {
		fmt.Printf("\n... and %d more (use --all to show everything)\n", len(edges)-defaultCap)
	}
}

// runBaselineReset clears all per-edge baseline stats by zeroing the bl_*
// columns in graph_edges. The edges themselves and their graph state are
// preserved — only the learned EWMA traffic profiles are wiped.
func runBaselineReset(storePath, nodeID string) {
	s, err := gstore.Open(storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	n, err := s.ResetEdgeBaselines(nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reset baseline: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Reset baseline stats for %d edge(s) on node %s.\n", n, nodeID)
	fmt.Println("Edges will rebuild their EWMA profiles from the next clean ticks.")
}
