// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kernloom/kernloom/pkg/core/relationship"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

const relationshipsUsage = `usage: kliq relationships <subcommand> [args]

Subcommands:
  list   [--db <path>] [--node <id>] [--predicate <pred>] [--state <state>]
         [--sort=state|predicate|subject|object|seen|last]
             List generic relationships from the state store.
  freeze [--db <path>] [--node <id>]
             Freeze all learned/approved relationships (no new learning).
  stats  [--db <path>] [--node <id>]
             Print relationship counts per state.
`

// handleRelationshipsSubcommand handles "kliq relationships <sub> ..." commands.
// Returns true if it consumed the command, false if it should be handled elsewhere.
func handleRelationshipsSubcommand(defaultDB, defaultNodeID string) bool {
	args := os.Args[1:]
	if len(args) < 1 || args[0] != "relationships" {
		return false
	}

	nodeID := defaultNodeID
	if nodeID == "" {
		if h, err := os.Hostname(); err == nil {
			nodeID = h
		} else {
			nodeID = "local"
		}
	}

	dbPath := defaultDB
	predicate := ""
	state := ""
	sortSpec := "state"
	sub := ""

	// Parse flags and positional args.
	filtered := args[1:]
	positional := filtered[:0]
	for i := 0; i < len(filtered); i++ {
		a := filtered[i]
		switch {
		case a == "--db" && i+1 < len(filtered):
			i++
			dbPath = filtered[i]
		case strings.HasPrefix(a, "--db="):
			dbPath = strings.TrimPrefix(a, "--db=")
		case a == "--node" && i+1 < len(filtered):
			i++
			nodeID = filtered[i]
		case strings.HasPrefix(a, "--node="):
			nodeID = strings.TrimPrefix(a, "--node=")
		case a == "--predicate" && i+1 < len(filtered):
			i++
			predicate = filtered[i]
		case strings.HasPrefix(a, "--predicate="):
			predicate = strings.TrimPrefix(a, "--predicate=")
		case a == "--state" && i+1 < len(filtered):
			i++
			state = filtered[i]
		case strings.HasPrefix(a, "--state="):
			state = strings.TrimPrefix(a, "--state=")
		case a == "--sort" && i+1 < len(filtered):
			i++
			sortSpec = filtered[i]
		case strings.HasPrefix(a, "--sort="):
			sortSpec = strings.TrimPrefix(a, "--sort=")
		case len(a) > 0 && a[0] != '-':
			positional = append(positional, a)
		}
	}

	if len(positional) > 0 {
		sub = positional[0]
	}

	switch sub {
	case "list", "":
		runRelationshipsList(dbPath, nodeID, predicate, state, sortSpec)
	case "freeze":
		runRelationshipsFreeze(dbPath, nodeID)
	case "stats":
		runRelationshipsStats(dbPath, nodeID)
	default:
		fmt.Fprintf(os.Stderr, "unknown relationships subcommand %q\n\n%s", sub, relationshipsUsage)
		os.Exit(1)
	}
	return true
}

func openStateStore(path string) *sqlite.Store {
	s, err := sqlite.Open(sqlite.DefaultConfig(path))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store %q: %v\n", path, err)
		os.Exit(1)
	}
	return s
}

func runRelationshipsList(dbPath, nodeID, predicate, state, sortSpec string) {
	s := openStateStore(dbPath)
	defer s.Close()

	rels, err := s.ListRelationships(context.Background(), nodeID, predicate, state)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: list relationships: %v\n", err)
		os.Exit(1)
	}

	if len(rels) == 0 {
		fmt.Println("(no relationships found)")
		return
	}
	sortKey, sortDesc, err := parseRelationshipSortSpec(sortSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, relationshipsUsage)
		os.Exit(1)
	}
	sortRelationships(rels, sortKey, sortDesc)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATE\tPREDICATE\tSUBJECT\tOBJECT\tSEEN\tLAST SEEN")
	for _, r := range rels {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\n",
			r.State, r.Predicate,
			shortID(r.SubjectEntityID), shortID(r.ObjectEntityID),
			r.SeenCount, r.LastSeenAt.UTC().Format(time.RFC3339),
		)
	}
	w.Flush()
	fmt.Printf("\nTotal: %d relationship(s)\n", len(rels))
}

func parseRelationshipSortSpec(spec string) (key string, desc bool, err error) {
	key = strings.TrimSpace(spec)
	if key == "" {
		key = "state"
	}
	if strings.HasPrefix(key, "-") {
		desc = true
		key = strings.TrimPrefix(key, "-")
	}
	if strings.HasPrefix(key, "+") {
		key = strings.TrimPrefix(key, "+")
	}
	if strings.HasSuffix(key, ":desc") {
		desc = true
		key = strings.TrimSuffix(key, ":desc")
	}
	if strings.HasSuffix(key, ":asc") {
		key = strings.TrimSuffix(key, ":asc")
	}
	key = strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	switch key {
	case "state", "predicate", "subject", "object", "seen", "last", "last_seen":
		return key, desc, nil
	default:
		return "", false, fmt.Errorf("unsupported relationship sort %q", spec)
	}
}

func sortRelationships(rels []relationship.Relationship, key string, desc bool) {
	sort.SliceStable(rels, func(i, j int) bool {
		cmp := compareRelationships(rels[i], rels[j], key)
		if cmp == 0 {
			cmp = compareString(rels[i].Predicate, rels[j].Predicate)
		}
		if cmp == 0 {
			cmp = compareString(rels[i].SubjectEntityID, rels[j].SubjectEntityID)
		}
		if cmp == 0 {
			cmp = compareString(rels[i].ObjectEntityID, rels[j].ObjectEntityID)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func compareRelationships(a, b relationship.Relationship, key string) int {
	switch key {
	case "state":
		return compareString(string(a.State), string(b.State))
	case "predicate":
		return compareString(a.Predicate, b.Predicate)
	case "subject":
		return compareString(a.SubjectEntityID, b.SubjectEntityID)
	case "object":
		return compareString(a.ObjectEntityID, b.ObjectEntityID)
	case "seen":
		return compareUint64(a.SeenCount, b.SeenCount)
	case "last", "last_seen":
		return compareTime(a.LastSeenAt, b.LastSeenAt)
	default:
		return compareString(string(a.State), string(b.State))
	}
}

func runRelationshipsFreeze(dbPath, nodeID string) {
	s := openStateStore(dbPath)
	defer s.Close()

	n, err := s.FreezeRelationships(context.Background(), nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: freeze relationships: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Frozen %d relationship(s) for node %q\n", n, nodeID)
}

func runRelationshipsStats(dbPath, nodeID string) {
	s := openStateStore(dbPath)
	defer s.Close()

	stats, err := s.RelationshipStats(context.Background(), nodeID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: relationship stats: %v\n", err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Relationship state summary — node: %s\n\n", nodeID)
	fmt.Fprintln(w, "STATE\tCOUNT")
	for _, st := range []relationship.State{
		relationship.StateCandidate, relationship.StateLearned,
		relationship.StateApproved, relationship.StateFrozen,
		relationship.StateDenied, relationship.StateExpired,
	} {
		if n := stats[string(st)]; n > 0 {
			fmt.Fprintf(w, "%s\t%d\n", st, n)
		}
	}
	w.Flush()
}

// shortID returns the last 12 hex chars of a stable_id for display.
func shortID(id string) string {
	if len(id) > 12 {
		return "…" + id[len(id)-12:]
	}
	return id
}
