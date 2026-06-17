// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kernloom/kernloom/pkg/core/entity"
	"github.com/kernloom/kernloom/pkg/core/relationship"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"
	"gopkg.in/yaml.v3"
)

// openStateStoreForGraph opens the state store for CLI graph commands.
func openStateStoreForGraph(path string) *sstore.Store {
	s, err := sstore.Open(sstore.DefaultConfig(path))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store %q: %v\n", path, err)
		os.Exit(1)
	}
	return s
}

// entityCache resolves stable_id → raw IP lazily for display purposes.
type entityCache struct {
	store *sstore.Store
	cache map[string]string // stable_id → display label
}

func newEntityCache(s *sstore.Store) *entityCache {
	return &entityCache{store: s, cache: make(map[string]string)}
}

func (c *entityCache) label(stableID string) string {
	if v, ok := c.cache[stableID]; ok {
		return v
	}
	e, _ := c.store.GetEntityByStableID(context.Background(), stableID)
	label := shortID(stableID)
	if e != nil {
		label = e.ID
	}
	c.cache[stableID] = label
	return label
}

// runGraphStatus prints a summary of network.connects_to relationships.
func runGraphStatus(storePath, nodeID string, showAll bool, sortBy string) {
	s := openStateStoreForGraph(storePath)
	defer s.Close()

	ctx := context.Background()
	stats, err := s.RelationshipStats(ctx, nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: stats: %v\n", err)
		os.Exit(1)
	}
	rels, err := s.ListRelationships(ctx, nodeID, "network.connects_to", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list relationships: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Graph status for node: %s\n\n", nodeID)
	fmt.Println("Relationships (network.connects_to):")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  STATE\tCOUNT")
	for _, st := range []relationship.State{
		relationship.StateCandidate, relationship.StateLearned,
		relationship.StateApproved, relationship.StateFrozen,
		relationship.StateDenied, relationship.StateExpired,
	} {
		if n := stats[string(st)]; n > 0 {
			fmt.Fprintf(w, "  %s\t%d\n", st, n)
		}
	}
	w.Flush()

	// Sort
	switch strings.ToLower(sortBy) {
	case "state":
		sort.Slice(rels, func(i, j int) bool {
			oi, oj := relStateOrder(rels[i].State), relStateOrder(rels[j].State)
			if oi != oj {
				return oi < oj
			}
			return rels[i].LastSeenAt.After(rels[j].LastSeenAt)
		})
	case "seen":
		sort.Slice(rels, func(i, j int) bool { return rels[i].SeenCount > rels[j].SeenCount })
	case "port":
		sort.Slice(rels, func(i, j int) bool {
			pi, _ := strconv.Atoi(rels[i].Dimensions["destination_port"])
			pj, _ := strconv.Atoi(rels[j].Dimensions["destination_port"])
			return pi < pj
		})
	default: // "last"
		sort.Slice(rels, func(i, j int) bool { return rels[i].LastSeenAt.After(rels[j].LastSeenAt) })
	}

	const defaultCap = 30
	fmt.Printf("\nEdges (%d total):\n\n", len(rels))
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATE\tSRC\tPROTO\tPORT\tDIR\tSEEN\tLAST SEEN")
	ec := newEntityCache(s)
	shown := rels
	if !showAll && len(shown) > defaultCap {
		shown = shown[:defaultCap]
	}
	for _, r := range shown {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			r.State,
			ec.label(r.SubjectEntityID),
			r.Dimensions["protocol"],
			r.Dimensions["destination_port"],
			r.Dimensions["direction"],
			r.SeenCount,
			r.LastSeenAt.UTC().Format(time.RFC3339),
		)
	}
	w.Flush()
	if !showAll && len(rels) > defaultCap {
		fmt.Printf("\n... and %d more (use --all or 'kliq graph export' for full list)\n", len(rels)-defaultCap)
	}
}

// graphProposalEdge is the YAML export format.
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
	Confidence      float64           `yaml:"confidence"`
}

type graphEntityRef struct {
	Kind string `yaml:"kind"`
	ID   string `yaml:"id"`
}

type graphProposalSummary struct {
	CandidateEdges int `yaml:"candidate_edges"`
	LearnedEdges   int `yaml:"learned_edges"`
	ApprovedEdges  int `yaml:"approved_edges"`
	FrozenEdges    int `yaml:"frozen_edges"`
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

func buildProposal(nodeID string, rels []relationship.Relationship, stats map[string]int64, ec *entityCache) graphProposal {
	sort.Slice(rels, func(i, j int) bool {
		oi, oj := relStateOrder(rels[i].State), relStateOrder(rels[j].State)
		if oi != oj {
			return oi < oj
		}
		return rels[i].LastSeenAt.After(rels[j].LastSeenAt)
	})
	p := graphProposal{APIVersion: "kernloom.io/v1alpha1", Kind: "GraphProposal"}
	p.Metadata.NodeID = nodeID
	p.Metadata.GeneratedAt = time.Now().UTC()
	p.Metadata.GeneratedBy = "kliq"
	p.Metadata.Mode = "learned"
	p.Spec.Summary = graphProposalSummary{
		CandidateEdges: int(stats[string(relationship.StateCandidate)]),
		LearnedEdges:   int(stats[string(relationship.StateLearned)]),
		ApprovedEdges:  int(stats[string(relationship.StateApproved)]),
		FrozenEdges:    int(stats[string(relationship.StateFrozen)]),
	}
	for _, r := range rels {
		if r.State == relationship.StateExpired {
			continue
		}
		dport := uint16(0)
		if p2, err := strconv.ParseUint(r.Dimensions["destination_port"], 10, 16); err == nil {
			dport = uint16(p2)
		}
		p.Spec.Edges = append(p.Spec.Edges, graphProposalEdge{
			ID:              r.ID,
			State:           string(r.State),
			Source:          graphEntityRef{Kind: "ip", ID: ec.label(r.SubjectEntityID)},
			Destination:     graphEntityRef{Kind: "ip", ID: ec.label(r.ObjectEntityID)},
			Protocol:        r.Dimensions["protocol"],
			DestinationPort: dport,
			Direction:       r.Dimensions["direction"],
			FirstSeenAt:     r.FirstSeenAt,
			LastSeenAt:      r.LastSeenAt,
			SeenCount:       r.SeenCount,
			Confidence:      r.Confidence,
		})
	}
	return p
}

// runGraphExport writes the full graph as YAML/JSON to stdout.
func runGraphExport(storePath, nodeID, outputFormat string) {
	s := openStateStoreForGraph(storePath)
	defer s.Close()
	ctx := context.Background()
	rels, err := s.ListRelationships(ctx, nodeID, "network.connects_to", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list relationships: %v\n", err)
		os.Exit(1)
	}
	stats, _ := s.RelationshipStats(ctx, nodeID)
	proposal := buildProposal(nodeID, rels, stats, newEntityCache(s))

	switch outputFormat {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(proposal)
	default:
		out, _ := yaml.Marshal(proposal)
		os.Stdout.Write(out)
	}
}

// runGraphFreeze marks all learned/approved relationships as frozen.
func runGraphFreeze(storePath, nodeID, frozenPath string) {
	s := openStateStoreForGraph(storePath)
	defer s.Close()

	n, err := s.FreezeRelationships(context.Background(), nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: freeze: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Frozen %d relationships for node %s.\n", n, nodeID)

	if frozenPath != "" {
		if err := os.MkdirAll(dirOf(frozenPath), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "warning: mkdir %s: %v\n", frozenPath, err)
		} else {
			runGraphExportToFile(storePath, nodeID, frozenPath)
			fmt.Printf("Frozen baseline written to %s.\n", frozenPath)
		}
	}
	fmt.Println("Switch kliq to --graph-mode=frozen-observe to detect new edges.")
}

// runGraphFreezeDryRun prints readiness without modifying the store.
func runGraphFreezeDryRun(storePath, nodeID string) {
	s := openStateStoreForGraph(storePath)
	defer s.Close()
	ctx := context.Background()
	rels, err := s.ListRelationships(ctx, nodeID, "network.connects_to", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list: %v\n", err)
		os.Exit(1)
	}
	var wouldFreeze, candidate, lowSeen int
	for _, r := range rels {
		switch r.State {
		case relationship.StateLearned, relationship.StateApproved:
			wouldFreeze++
			if r.SeenCount < 5 {
				lowSeen++
			}
		case relationship.StateCandidate:
			candidate++
		}
	}
	fmt.Printf("Freeze readiness for node: %s\n\n", nodeID)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  Would freeze:\t%d relationships\n", wouldFreeze)
	fmt.Fprintf(w, "  Candidates not ready:\t%d\n", candidate)
	fmt.Fprintf(w, "  Low-confidence (seen < 5):\t%d\n", lowSeen)
	w.Flush()
	if wouldFreeze == 0 {
		fmt.Println("\n  No learned/approved relationships — run in learn mode first.")
	} else if candidate == 0 && lowSeen == 0 {
		fmt.Println("\n  Graph looks ready. Run 'kliq graph freeze' to proceed.")
	}
}

func runGraphExportToFile(storePath, nodeID, path string) {
	s := openStateStoreForGraph(storePath)
	defer s.Close()
	ctx := context.Background()
	rels, _ := s.ListRelationships(ctx, nodeID, "network.connects_to", string(relationship.StateFrozen))
	stats, _ := s.RelationshipStats(ctx, nodeID)
	proposal := buildProposal(nodeID, rels, stats, newEntityCache(s))
	out, _ := yaml.Marshal(proposal)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "error: write %s: %v\n", tmp, err)
		os.Exit(1)
	}
	if err := os.Rename(tmp, path); err != nil {
		fmt.Fprintf(os.Stderr, "error: rename %s: %v\n", path, err)
		os.Exit(1)
	}
}

// runGraphReset deletes relationships. By default keeps frozen/approved.
func runGraphReset(storePath, nodeID string, all bool) {
	s := openStateStoreForGraph(storePath)
	defer s.Close()

	var keep []relationship.State
	if !all {
		keep = []relationship.State{relationship.StateFrozen, relationship.StateApproved}
	}
	n, err := s.DeleteRelationships(context.Background(), nodeID, keep)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reset: %v\n", err)
		os.Exit(1)
	}
	if !all {
		fmt.Printf("Deleted %d relationship(s) for node %s (frozen/approved kept).\n", n, nodeID)
	} else {
		fmt.Printf("Deleted %d relationship(s) for node %s (full wipe).\n", n, nodeID)
	}
}

// runGraphApproveIP marks all relationships from sourceIP as approved.
func runGraphApproveIP(sourceIP, storePath, nodeID string) {
	runGraphSetIPState(sourceIP, storePath, nodeID, relationship.StateApproved, "approved")
}

func runGraphSetIPState(sourceIP, storePath, nodeID string, state relationship.State, label string) {
	s := openStateStoreForGraph(storePath)
	defer s.Close()
	ctx := context.Background()

	// Resolve IP → stable_id
	entity, err := s.GetEntity(ctx, entity.KindIP, sourceIP, "")
	if err != nil || entity == nil {
		fmt.Fprintf(os.Stderr, "entity not found for IP %s\n", sourceIP)
		os.Exit(1)
	}

	rels, err := s.ListRelationships(ctx, nodeID, "network.connects_to", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list: %v\n", err)
		os.Exit(1)
	}
	n := 0
	for _, r := range rels {
		if r.SubjectEntityID != entity.StableID || r.State == state {
			continue
		}
		if err := s.SetRelationshipState(ctx, r.ID, state, r.Confidence); err != nil {
			fmt.Fprintf(os.Stderr, "error: update %s: %v\n", r.ID, err)
			os.Exit(1)
		}
		n++
	}
	if n == 0 {
		fmt.Printf("No relationships found for source %s on node %s.\n", sourceIP, nodeID)
	} else {
		fmt.Printf("Marked %d relationship(s) from %s as %s.\n", n, sourceIP, label)
	}
}

func relStateOrder(s relationship.State) int {
	switch s {
	case relationship.StateFrozen:
		return 0
	case relationship.StateApproved:
		return 1
	case relationship.StateLearned:
		return 2
	case relationship.StateCandidate:
		return 3
	case relationship.StateDenied:
		return 4
	default:
		return 5
	}
}

const graphUsage = `usage: kliq graph <subcommand> [flags] [state-db] [node-id]

  edges     [--all] [--sort=last|state|port|seen]   show graph relationships
  export    [--format=json]                          export graph as YAML/JSON
  freeze    [frozen-file]                            freeze learned relationships
  freeze    --dry-run                                show freeze readiness
  reset     [--all]                                  delete relationships (--all: incl. frozen)
  approve-ip <ip>                                    mark all relationships from IP as approved
  deny-ip   <ip>                                     mark all relationships from IP as denied`

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
	case "edges", "status":
		runGraphStatus(getArg(2, storePath), getArg(3, nodeID), showAll, sortBy)
	case "export":
		runGraphExport(getArg(2, storePath), getArg(3, nodeID), format)
	case "freeze":
		if dryRun {
			runGraphFreezeDryRun(getArg(2, storePath), getArg(3, nodeID))
		} else {
			runGraphFreeze(getArg(2, storePath), getArg(3, nodeID), getArg(4, frozenPath))
		}
	case "approve-ip":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: kliq graph approve-ip <ip> [state-db] [node-id]")
			os.Exit(1)
		}
		runGraphApproveIP(args[2], getArg(3, storePath), getArg(4, nodeID))
	case "deny-ip":
		if len(args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: kliq graph deny-ip <ip> [state-db] [node-id]")
			os.Exit(1)
		}
		runGraphSetIPState(args[2], getArg(3, storePath), getArg(4, nodeID), relationship.StateDenied, "denied")
	case "reset":
		runGraphReset(getArg(2, storePath), getArg(3, nodeID), showAll)
	default:
		fmt.Fprintf(os.Stderr, "unknown graph subcommand: %s\n\n%s\n", args[1], graphUsage)
		os.Exit(1)
	}
	return true
}

func dirOf(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[:i]
		}
	}
	return "."
}
