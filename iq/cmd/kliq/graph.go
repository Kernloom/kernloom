// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kernloom/kernloom/pkg/core/graph"
	gstore "github.com/kernloom/kernloom/pkg/graphstore/sqlite"
	"gopkg.in/yaml.v3"
)

// runGraphStatus prints a summary of graph edges for the given store and nodeID.
func runGraphStatus(storePath, nodeID string, showAll bool, sortBy string) {
	s, err := gstore.Open(storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open graph store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	stats, err := s.Stats(nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: stats: %v\n", err)
		os.Exit(1)
	}

	edges, err := s.ListByNode(nodeID, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list edges: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Graph + Baseline status for node: %s\n\n", nodeID)

	// Graph edge summary
	fmt.Println("Graph edges:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  STATE\tCOUNT")
	for _, state := range []graph.EdgeState{
		graph.EdgeCandidate, graph.EdgeLearned, graph.EdgeApproved,
		graph.EdgeFrozen, graph.EdgeDenied, graph.EdgeExpired,
	} {
		if n := stats[state]; n > 0 {
			fmt.Fprintf(w, "  %s\t%d\n", state, n)
		}
	}
	w.Flush()

	// Sort edges.
	switch strings.ToLower(sortBy) {
	case "state":
		sort.Slice(edges, func(i, j int) bool {
			oi, oj := stateOrder(edges[i].State), stateOrder(edges[j].State)
			if oi != oj {
				return oi < oj
			}
			return edges[i].LastSeenAt.After(edges[j].LastSeenAt)
		})
	case "src":
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].Source.ID != edges[j].Source.ID {
				return edges[i].Source.ID < edges[j].Source.ID
			}
			return edges[i].DestinationPort < edges[j].DestinationPort
		})
	case "port":
		sort.Slice(edges, func(i, j int) bool {
			if edges[i].DestinationPort != edges[j].DestinationPort {
				return edges[i].DestinationPort < edges[j].DestinationPort
			}
			return edges[i].Source.ID < edges[j].Source.ID
		})
	case "seen":
		sort.Slice(edges, func(i, j int) bool {
			return edges[i].SeenCount > edges[j].SeenCount
		})
	default: // "last"
		sort.Slice(edges, func(i, j int) bool {
			return edges[i].LastSeenAt.After(edges[j].LastSeenAt)
		})
	}

	const defaultCap = 30
	fmt.Printf("\nEdges (%d total):\n\n", len(edges))
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATE\tSRC\tDST\tPROTO\tPORT\tSEEN\tLAST SEEN")
	shown := edges
	if !showAll && len(shown) > defaultCap {
		shown = shown[:defaultCap]
	}
	for _, e := range shown {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			e.State,
			e.Source.ID,
			e.Destination.ID,
			e.Protocol,
			e.DestinationPort,
			e.SeenCount,
			e.LastSeenAt.Format(time.RFC3339),
		)
	}
	w.Flush()
	if !showAll && len(edges) > defaultCap {
		fmt.Printf("\n... and %d more (use --all or 'kliq graph export' for full list)\n", len(edges)-defaultCap)
	}
}

// graphProposalEdge is the YAML export format (§21 of the roadmap).
type graphProposalEdge struct {
	ID              string            `yaml:"id"`
	State           string            `yaml:"state"`
	Source          graphEntityRef    `yaml:"source"`
	Destination     graphEntityRef    `yaml:"destination"`
	Protocol        string            `yaml:"protocol"`
	DestinationPort uint16            `yaml:"destination_port,omitempty"`
	Direction       string            `yaml:"direction"`
	FirstSeenAt     time.Time         `yaml:"first_seen_at"`
	LastSeenAt      time.Time         `yaml:"last_seen_at"`
	SeenCount       uint64            `yaml:"seen_count"`
	Confidence      int               `yaml:"confidence"`
	Attributes      map[string]string `yaml:"attributes,omitempty"`
}

type graphEntityRef struct {
	Kind string `yaml:"kind"`
	ID   string `yaml:"id"`
}

type graphProposalSummary struct {
	CandidateEdges  int `yaml:"candidate_edges"`
	LearnedEdges    int `yaml:"learned_edges"`
	ApprovedEdges   int `yaml:"approved_edges"`
	FrozenEdges     int `yaml:"frozen_edges"`
	SuspiciousEdges int `yaml:"suspicious_edges"`
}

type graphProposal struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		NodeID      string    `yaml:"node_id"`
		GeneratedAt time.Time `yaml:"generated_at"`
		GeneratedBy string    `yaml:"generated_by"`
		Mode        string    `yaml:"mode"`
	} `yaml:"metadata"`
	Spec struct {
		Summary graphProposalSummary `yaml:"summary"`
		Edges   []graphProposalEdge  `yaml:"edges"`
	} `yaml:"spec"`
}

// buildProposal constructs a graphProposal from a list of edges and stats.
func buildProposal(nodeID string, edges []*graph.Edge, stats map[graph.EdgeState]int) graphProposal {
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].State != edges[j].State {
			return stateOrder(edges[i].State) < stateOrder(edges[j].State)
		}
		return edges[i].LastSeenAt.After(edges[j].LastSeenAt)
	})

	proposal := graphProposal{APIVersion: "kernloom.io/v1alpha1", Kind: "GraphProposal"}
	proposal.Metadata.NodeID = nodeID
	proposal.Metadata.GeneratedAt = time.Now().UTC()
	proposal.Metadata.GeneratedBy = "kliq"
	proposal.Metadata.Mode = "learned"
	proposal.Spec.Summary = graphProposalSummary{
		CandidateEdges: stats[graph.EdgeCandidate],
		LearnedEdges:   stats[graph.EdgeLearned],
		ApprovedEdges:  stats[graph.EdgeApproved],
		FrozenEdges:    stats[graph.EdgeFrozen],
	}
	for _, e := range edges {
		if e.State == graph.EdgeExpired {
			continue
		}
		proposal.Spec.Edges = append(proposal.Spec.Edges, graphProposalEdge{
			ID:              e.ID,
			State:           string(e.State),
			Source:          graphEntityRef{Kind: string(e.Source.Kind), ID: e.Source.ID},
			Destination:     graphEntityRef{Kind: string(e.Destination.Kind), ID: e.Destination.ID},
			Protocol:        e.Protocol,
			DestinationPort: e.DestinationPort,
			Direction:       string(e.Direction),
			FirstSeenAt:     e.FirstSeenAt,
			LastSeenAt:      e.LastSeenAt,
			SeenCount:       e.SeenCount,
			Confidence:      e.Confidence,
			Attributes:      e.Attributes,
		})
	}
	return proposal
}

// runGraphExport writes the full graph as a YAML proposal to stdout.
func runGraphExport(storePath, nodeID, outputFormat string) {
	s, err := gstore.Open(storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open graph store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	edges, err := s.ListByNode(nodeID, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list edges: %v\n", err)
		os.Exit(1)
	}
	stats, err := s.Stats(nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: stats: %v\n", err)
		os.Exit(1)
	}

	proposal := buildProposal(nodeID, edges, stats)

	switch outputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(proposal); err != nil {
			fmt.Fprintf(os.Stderr, "error: encode json: %v\n", err)
			os.Exit(1)
		}
	default:
		out, err := yaml.Marshal(proposal)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: encode yaml: %v\n", err)
			os.Exit(1)
		}
		os.Stdout.Write(out)
	}
}

func stateOrder(s graph.EdgeState) int {
	switch s {
	case graph.EdgeFrozen:
		return 0
	case graph.EdgeApproved:
		return 1
	case graph.EdgeLearned:
		return 2
	case graph.EdgeCandidate:
		return 3
	case graph.EdgeDenied:
		return 4
	default:
		return 5
	}
}

const graphUsage = `usage: kliq graph <subcommand> [flags] [store] [node-id]

  edges    [--all] [--sort=last|state|src|port|seen]  show graph edges
  baselines [--all] [--sort=obs|state|src|port|pps|bps]  show edge baselines
  baselines reset                                      zero baseline stats
  export   [--format=json]                             export full graph as YAML/JSON
  freeze   [frozen-file]                               freeze learned edges
  reset    [--all]                                     delete edges (--all: incl. frozen/approved)
  approve-ip <ip>                                      mark all edges from IP as approved
  deny-ip  <ip>                                        mark all edges from IP as denied`

// handleGraphSubcommand checks os.Args for graph subcommands and runs them
// without starting the main kliq loop. Returns true if a subcommand was handled.
//
// Usage:
//
//	kliq graph status  [store]  [node-id]
//	kliq graph export  [store]  [node-id]  [--format=json]
//	kliq graph freeze  [store]  [node-id]  [frozen-out]
func handleGraphSubcommand(storePath, frozenPath, nodeID string) bool {
	args := os.Args[1:]
	if len(args) < 2 || args[0] != "graph" {
		return false
	}

	if nodeID == "" {
		if h, err := os.Hostname(); err == nil {
			nodeID = h
		} else {
			nodeID = "local"
		}
	}

	// Strip flags before positional arg parsing — any --flag that lands in the
	// wrong position would otherwise be treated as a store path or node-id.
	// Unknown --flags are silently dropped (they may come from shell completion
	// or old hints in error messages like the former --graph-export suggestion).
	showAll := false
	format := "yaml"
	sortBy := "last"
	dryRun := false
	filtered := args[:0]
	for _, a := range args {
		switch {
		case a == "--all" || a == "-all":
			showAll = true
		case a == "--dry-run" || a == "-dry-run":
			dryRun = true
		case a == "--format=json" || a == "-json":
			format = "json"
		case a == "--format=yaml":
			format = "yaml"
		case strings.HasPrefix(a, "--sort="):
			sortBy = strings.TrimPrefix(a, "--sort=")
		case len(a) > 1 && a[0] == '-':
			// unknown flag — drop silently
		default:
			filtered = append(filtered, a)
		}
	}
	args = filtered

	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, graphUsage)
		os.Exit(1)
	}

	getArg := func(idx int, def string) string {
		if len(args) > idx {
			return args[idx]
		}
		return def
	}

	switch args[1] {
	case "edges", "status": // "status" kept as backward-compat alias
		runGraphStatus(getArg(2, storePath), getArg(3, nodeID), showAll, sortBy)
		return true

	case "baselines":
		if len(args) > 2 && args[2] == "reset" {
			runBaselineReset(getArg(3, storePath), getArg(4, nodeID))
		} else {
			runBaselineStatus(getArg(2, storePath), getArg(3, nodeID), showAll, sortBy)
		}
		return true

	case "export":
		runGraphExport(getArg(2, storePath), getArg(3, nodeID), format)
		return true

	case "freeze":
		if dryRun {
			runGraphFreezeDryRun(getArg(2, storePath), getArg(3, nodeID))
		} else {
			runGraphFreeze(getArg(2, storePath), getArg(3, nodeID), getArg(4, frozenPath))
		}
		return true

	case "approve-ip":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: kliq graph approve-ip <ip> [store] [node-id]")
			os.Exit(1)
		}
		runGraphApproveIP(args[2], getArg(3, storePath), getArg(4, nodeID))
		return true

	case "deny-ip":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: kliq graph deny-ip <ip> [store] [node-id]")
			os.Exit(1)
		}
		runGraphSetIPState(args[2], getArg(3, storePath), getArg(4, nodeID), graph.EdgeDenied, "denied")
		return true

	case "reset":
		runGraphReset(getArg(2, storePath), getArg(3, nodeID), showAll)
		return true

	default:
		fmt.Fprintf(os.Stderr, "unknown graph subcommand: %s\n", args[1])
		fmt.Fprintln(os.Stderr, graphUsage)
		os.Exit(1)
	}
	return false
}

// runGraphFreeze marks all learned/approved edges as frozen in the store and
// writes the frozen baseline as YAML to frozenPath (IMA-attested location).
// This is the preparation step before switching to frozen-observe mode.
func runGraphFreeze(storePath, nodeID, frozenPath string) {
	s, err := gstore.Open(storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open graph store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	edges, err := s.ListByNode(nodeID, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list edges: %v\n", err)
		os.Exit(1)
	}

	frozen := 0
	for _, e := range edges {
		if e.State == graph.EdgeLearned || e.State == graph.EdgeApproved {
			if err := s.UpdateState(e.ID, graph.EdgeFrozen, graph.LearnedByAdmin); err != nil {
				fmt.Fprintf(os.Stderr, "error: freeze edge %s: %v\n", e.ID, err)
				os.Exit(1)
			}
			frozen++
		}
	}

	fmt.Printf("Frozen %d edges for node %s.\n", frozen, nodeID)

	// Write the frozen baseline YAML to the IMA-attested path.
	if frozenPath != "" {
		if err := os.MkdirAll(dirOf(frozenPath), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not create directory for %s: %v\n", frozenPath, err)
		} else {
			runGraphExportToFile(storePath, nodeID, frozenPath)
			fmt.Printf("Frozen baseline written to %s (IMA-attested).\n", frozenPath)
		}
	}

	fmt.Println("Switch kliq to --graph-mode=frozen-observe to detect new edges.")
}

// runGraphFreezeDryRun prints a readiness summary without modifying the store.
// Usage: kliq graph freeze --dry-run [store] [node-id]
func runGraphFreezeDryRun(storePath, nodeID string) {
	s, err := gstore.Open(storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open graph store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	edges, err := s.ListByNode(nodeID, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list edges: %v\n", err)
		os.Exit(1)
	}

	var wouldFreeze, candidate, lowSeen, singleSeen int
	for _, e := range edges {
		switch e.State {
		case graph.EdgeLearned, graph.EdgeApproved:
			wouldFreeze++
			if e.SeenCount < 5 {
				lowSeen++
			}
			if e.SeenCount == 1 {
				singleSeen++
			}
		case graph.EdgeCandidate:
			candidate++
		}
	}

	fmt.Printf("Freeze readiness for node: %s\n\n", nodeID)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  Would freeze:\t%d edges (learned + approved)\n", wouldFreeze)
	fmt.Fprintf(w, "  Candidates not ready:\t%d edges (still accumulating observations)\n", candidate)
	fmt.Fprintf(w, "  Low-confidence (seen < 5):\t%d edges\n", lowSeen)
	fmt.Fprintf(w, "  Seen only once:\t%d edges\n", singleSeen)
	w.Flush()
	fmt.Println()

	if candidate > 0 {
		fmt.Printf("  Recommendation: %d candidate edge(s) are not mature yet.\n", candidate)
		fmt.Printf("  Wait for them to be promoted or deny them before freezing.\n")
	}
	if lowSeen > 0 {
		fmt.Printf("  Warning: %d edge(s) have been seen fewer than 5 times — consider waiting.\n", lowSeen)
	}
	if wouldFreeze == 0 {
		fmt.Println("  No learned/approved edges to freeze — run in learn mode first.")
	} else if candidate == 0 && lowSeen == 0 {
		fmt.Println("  Graph looks ready to freeze.")
		fmt.Println("  Run 'kliq graph freeze' to proceed.")
	}
}

// runGraphExportToFile writes the graph proposal YAML to a file instead of stdout.
func runGraphExportToFile(storePath, nodeID, path string) {
	s, err := gstore.Open(storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open graph store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	edges, err := s.ListByNode(nodeID, graph.EdgeFrozen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list frozen edges: %v\n", err)
		os.Exit(1)
	}
	stats, _ := s.Stats(nodeID)

	proposal := buildProposal(nodeID, edges, stats)
	out, err := yaml.Marshal(proposal)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshal yaml: %v\n", err)
		os.Exit(1)
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write %s: %v\n", tmp, err)
		os.Exit(1)
	}
	if err := os.Rename(tmp, path); err != nil {
		fmt.Fprintf(os.Stderr, "error: rename to %s: %v\n", path, err)
		os.Exit(1)
	}
}

// runGraphReset removes graph edges for a node. By default only candidate,
// learned and expired edges are deleted — frozen and approved edges (explicit
// admin decisions) are kept. Pass --all to wipe everything.
func runGraphReset(storePath, nodeID string, all bool) {
	s, err := gstore.Open(storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open graph store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	keepAdminStates := !all
	n, err := s.ResetEdges(nodeID, keepAdminStates)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reset graph: %v\n", err)
		os.Exit(1)
	}

	if keepAdminStates {
		fmt.Printf("Deleted %d edge(s) for node %s (frozen/approved kept).\n", n, nodeID)
		fmt.Println("Graph will re-learn from the next observed traffic.")
		fmt.Println("Use --all to also wipe frozen and approved edges.")
	} else {
		fmt.Printf("Deleted %d edge(s) for node %s (full wipe).\n", n, nodeID)
		fmt.Println("Graph will re-learn from scratch.")
	}
}

// runGraphApproveIP marks all edges from sourceIP as approved so the graph
// learner stops emitting new_edge_after_freeze signals for them.
func runGraphApproveIP(sourceIP, storePath, nodeID string) {
	runGraphSetIPState(sourceIP, storePath, nodeID, graph.EdgeApproved, "approved")
}

// runGraphSetIPState updates all edges from sourceIP to the given state.
func runGraphSetIPState(sourceIP, storePath, nodeID string, state graph.EdgeState, label string) {
	s, err := gstore.Open(storePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open graph store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	edges, err := s.ListByNode(nodeID, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list edges: %v\n", err)
		os.Exit(1)
	}

	updated := 0
	for _, e := range edges {
		if e.Source.ID != sourceIP {
			continue
		}
		if e.State == state {
			continue
		}
		if err := s.UpdateState(e.ID, state, graph.LearnedByAdmin); err != nil {
			fmt.Fprintf(os.Stderr, "error: update edge %s: %v\n", e.ID, err)
			os.Exit(1)
		}
		updated++
	}

	if updated == 0 {
		fmt.Printf("No edges found for source %s on node %s.\n", sourceIP, nodeID)
	} else {
		fmt.Printf("Marked %d edge(s) from %s as %s.\n", updated, sourceIP, label)
	}
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
