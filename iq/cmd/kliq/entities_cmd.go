// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

const entitiesUsage = `usage: kliq entities <subcommand> [args]

Subcommands:
  list [--db <path>] [--kind <kind>] [--node <id>]
           List all known entities.
`

func handleEntitiesSubcommand(defaultDB string) bool {
	args := os.Args[1:]
	if len(args) < 1 || args[0] != "entities" {
		return false
	}

	dbPath := defaultDB
	kindFilter := ""

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
		case a == "--kind" && i+1 < len(filtered):
			i++
			kindFilter = filtered[i]
		case strings.HasPrefix(a, "--kind="):
			kindFilter = strings.TrimPrefix(a, "--kind=")
		case len(a) > 0 && a[0] != '-':
			positional = append(positional, a)
		}
	}

	sub := "list"
	if len(positional) > 0 {
		sub = positional[0]
	}

	switch sub {
	case "list", "":
		runEntitiesList(dbPath, kindFilter)
	default:
		fmt.Fprintf(os.Stderr, "unknown entities subcommand %q\n\n%s", sub, entitiesUsage)
		os.Exit(1)
	}
	return true
}

func runEntitiesList(dbPath, kindFilter string) {
	s, err := sqlite.Open(sqlite.DefaultConfig(dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	q := `SELECT stable_id, kind, id, namespace, source_adapter, confidence,
	             first_seen_at, last_seen_at
	      FROM entities`
	args := []any{}
	if kindFilter != "" {
		q += " WHERE kind=?"
		args = append(args, kindFilter)
	}
	q += " ORDER BY kind, id"

	rows, err := s.DB().QueryContext(context.Background(), q, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: query entities: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KIND\tID\tSOURCE\tCONF\tFIRST SEEN\tLAST SEEN")

	count := 0
	for rows.Next() {
		var stableID, kind, id, ns, src, firstSeen, lastSeen string
		var conf float64
		if err := rows.Scan(&stableID, &kind, &id, &ns, &src, &conf, &firstSeen, &lastSeen); err != nil {
			continue
		}
		displayID := id
		if id == stableID {
			// Entity stub with only the hash as id — show shortened hash
			displayID = "?" + shortID(stableID)
		}
		if ns != "" {
			displayID = displayID + " (" + ns + ")"
		}
		t, _ := time.Parse(time.RFC3339Nano, firstSeen)
		tLast, _ := time.Parse(time.RFC3339Nano, lastSeen)
		fmt.Fprintf(w, "%s\t%s\t%s\t%.2f\t%s\t%s\n",
			kind, displayID, src, conf,
			t.UTC().Format("2006-01-02T15:04"),
			tLast.UTC().Format("2006-01-02T15:04"),
		)
		count++
	}
	w.Flush()

	if count == 0 {
		fmt.Println("(no entities found)")
		return
	}
	fmt.Printf("\nTotal: %d entity(ies)\n", count)
}
