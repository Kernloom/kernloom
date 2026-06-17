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

const baselinesGenericUsage = `usage: kliq baselines <subcommand> [args]

Subcommands:
  list [--db <path>] [--node <id>] [--metric <id>] [--scope <type>] [--source-class <class>]
           List generic metric baselines from the state store.
`

// handleBaselinesGenericSubcommand handles "kliq baselines <sub> ..." commands.
func handleBaselinesGenericSubcommand(defaultDB string) bool {
	args := os.Args[1:]
	if len(args) < 1 || args[0] != "baselines" {
		return false
	}

	dbPath := defaultDB
	metricFilter := ""
	scopeFilter := ""
	sourceClassFilter := ""
	sub := "list"

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
		case a == "--metric" && i+1 < len(filtered):
			i++
			metricFilter = filtered[i]
		case strings.HasPrefix(a, "--metric="):
			metricFilter = strings.TrimPrefix(a, "--metric=")
		case a == "--scope" && i+1 < len(filtered):
			i++
			scopeFilter = filtered[i]
		case strings.HasPrefix(a, "--scope="):
			scopeFilter = strings.TrimPrefix(a, "--scope=")
		case a == "--source-class" && i+1 < len(filtered):
			i++
			sourceClassFilter = filtered[i]
		case strings.HasPrefix(a, "--source-class="):
			sourceClassFilter = strings.TrimPrefix(a, "--source-class=")
		case len(a) > 0 && a[0] != '-':
			positional = append(positional, a)
		}
	}

	if len(positional) > 0 {
		sub = positional[0]
	}

	switch sub {
	case "list", "":
		runBaselinesGenericList(dbPath, metricFilter, scopeFilter, sourceClassFilter)
	default:
		fmt.Fprintf(os.Stderr, "unknown baselines subcommand %q\n\n%s", sub, baselinesGenericUsage)
		os.Exit(1)
	}
	return true
}

func runBaselinesGenericList(dbPath, metricFilter, scopeFilter, sourceClassFilter string) {
	s, err := sqlite.Open(sqlite.DefaultConfig(dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store %q: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer s.Close()

	// Join with entities to resolve subject_entity_id → human-readable IP.
	rows, err := s.DB().QueryContext(context.Background(), `
		SELECT b.metric_id, b.scope_type, b.scope_id, b.source_class, b.visibility_point,
		       b.truth_class, b.window_seconds, b.state, b.observations, b.last_updated_at,
		       COALESCE(e.id, '') as entity_display
		FROM metric_baselines b
		LEFT JOIN entities e ON e.stable_id = b.subject_entity_id
		ORDER BY b.metric_id, b.source_class, b.scope_type, b.scope_id
	`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: query baselines: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "METRIC\tSUBJECT\tSOURCE\tSCOPE\tTRUTH\tWIN\tSTATE\tOBS\tLAST UPDATED")

	count := 0
	for rows.Next() {
		var metricID, scopeType, scopeID, sourceClass, visPoint, truthClass, state, lastUpdated, entityDisplay string
		var windowSec, obs int64
		if err := rows.Scan(&metricID, &scopeType, &scopeID, &sourceClass, &visPoint,
			&truthClass, &windowSec, &state, &obs, &lastUpdated, &entityDisplay); err != nil {
			continue
		}
		if metricFilter != "" && !strings.Contains(metricID, metricFilter) {
			continue
		}
		if scopeFilter != "" && scopeType != scopeFilter {
			continue
		}
		if sourceClassFilter != "" && sourceClass != sourceClassFilter {
			continue
		}
		scope := scopeType
		if scopeID != "" {
			scope = scopeType + ":" + shortID(scopeID)
		}
		subject := entityDisplay
		if subject == "" || subject == scopeID {
			subject = shortID(scopeID)
		}
		t, _ := time.Parse(time.RFC3339Nano, lastUpdated)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%ds\t%s\t%d\t%s\n",
			metricID, subject, sourceClass, scope, shortTruth(truthClass),
			windowSec, state, obs, t.UTC().Format("2006-01-02T15:04"))
		count++
	}
	w.Flush()

	if count == 0 {
		fmt.Println("(no baselines found)")
		return
	}
	fmt.Printf("\nTotal: %d baseline(s)\n", count)
}

func shortTruth(tc string) string {
	switch tc {
	case "primary_packet_observation":
		return "xdp"
	case "sampled_state":
		return "conntrack"
	case "application_observed":
		return "app"
	case "identity_observed":
		return "identity"
	case "trust_observed":
		return "trust"
	case "derived":
		return "derived"
	default:
		if len(tc) > 10 {
			return tc[:10] + "…"
		}
		return tc
	}
}
