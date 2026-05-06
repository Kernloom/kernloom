// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/core/graph"
	gstore "github.com/adrianenderlin/kernloom/pkg/graphstore/sqlite"
	"gopkg.in/yaml.v3"
)

// runGraphStatus prints a summary of graph edges for the given store and nodeID.
func runGraphStatus(storePath, nodeID string) {
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

	fmt.Printf("Graph status for node: %s\n\n", nodeID)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATE\tCOUNT")
	for _, state := range []graph.EdgeState{
		graph.EdgeCandidate, graph.EdgeLearned, graph.EdgeApproved,
		graph.EdgeFrozen, graph.EdgeDenied, graph.EdgeExpired,
	} {
		if n := stats[state]; n > 0 {
			fmt.Fprintf(w, "%s\t%d\n", state, n)
		}
	}
	w.Flush()

	fmt.Printf("\nRecent edges (%d total):\n\n", len(edges))
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATE\tSRC\tDST\tPROTO\tPORT\tSEEN\tLAST SEEN")
	shown := edges
	if len(shown) > 30 {
		shown = shown[:30]
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
	if len(edges) > 30 {
		fmt.Printf("\n... and %d more (use --graph-export for full list)\n", len(edges)-30)
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

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].State != edges[j].State {
			return stateOrder(edges[i].State) < stateOrder(edges[j].State)
		}
		return edges[i].LastSeenAt.After(edges[j].LastSeenAt)
	})

	proposal := graphProposal{
		APIVersion: "kernloom.io/v1alpha1",
		Kind:       "GraphProposal",
	}
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
		pe := graphProposalEdge{
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
		}
		proposal.Spec.Edges = append(proposal.Spec.Edges, pe)
	}

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

// handleGraphSubcommand checks os.Args for "graph status" or "graph export"
// and runs them without starting the main kliq loop.
// Returns true if a subcommand was handled.
func handleGraphSubcommand(storePath, nodeID string) bool {
	args := os.Args[1:]
	if len(args) < 2 || args[0] != "graph" {
		return false
	}

	// Resolve nodeID (may be overridden by --graph-node-id flag, but flags
	// aren't parsed yet at this point — we accept it as a positional arg too).
	if nodeID == "" {
		if h, err := os.Hostname(); err == nil {
			nodeID = h
		} else {
			nodeID = "local"
		}
	}

	// Allow overriding store path and node-id via simple positional args:
	// kliq graph status [store-path] [node-id]
	// kliq graph export [store-path] [node-id] [--format=json]
	getArg := func(idx int, def string) string {
		if len(args) > idx {
			return args[idx]
		}
		return def
	}

	switch args[1] {
	case "status":
		sp := getArg(2, storePath)
		nid := getArg(3, nodeID)
		runGraphStatus(sp, nid)
		return true

	case "export":
		sp := getArg(2, storePath)
		nid := getArg(3, nodeID)
		format := "yaml"
		for _, a := range args[4:] {
			if a == "--format=json" || a == "-json" {
				format = "json"
			}
		}
		runGraphExport(sp, nid, format)
		return true

	case "freeze":
		sp := getArg(2, storePath)
		nid := getArg(3, nodeID)
		runGraphFreeze(sp, nid)
		return true

	default:
		fmt.Fprintf(os.Stderr, "unknown graph subcommand: %s\n", args[1])
		fmt.Fprintln(os.Stderr, "usage: kliq graph {status|export|freeze} [store-path] [node-id]")
		os.Exit(1)
	}
	return false
}

// runGraphFreeze marks all learned/approved edges as frozen and prints the count.
// This is a preparation step before switching to frozen-observe mode.
func runGraphFreeze(storePath, nodeID string) {
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

	fmt.Printf("Frozen %s edges for node %s.\n", strconv.Itoa(frozen), nodeID)
	fmt.Println("Switch kliq to --graph-mode=frozen-observe to detect new edges.")
}
