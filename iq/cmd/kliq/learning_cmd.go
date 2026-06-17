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

const learningUsage = `usage: kliq learning <subcommand> [args]

Subcommands:
  exclusions list  [--db <path>] [--entity <id>]
                       List active learning exclusions.
  exclusions clear --entity <id> [--db <path>]
                       Revoke all active exclusions for an entity.
`

// handleLearningSubcommand handles "kliq learning <sub> ..." commands.
func handleLearningSubcommand(defaultDB string) bool {
	args := os.Args[1:]
	if len(args) < 1 || args[0] != "learning" {
		return false
	}

	if len(args) < 2 {
		fmt.Fprint(os.Stderr, learningUsage)
		os.Exit(1)
	}

	dbPath := defaultDB
	entityFilter := ""

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
		case a == "--entity" && i+1 < len(filtered):
			i++
			entityFilter = filtered[i]
		case strings.HasPrefix(a, "--entity="):
			entityFilter = strings.TrimPrefix(a, "--entity=")
		case len(a) > 0 && a[0] != '-':
			positional = append(positional, a)
		}
	}

	// Expect "exclusions <list|clear>"
	if len(positional) < 1 || positional[0] != "exclusions" {
		fmt.Fprintf(os.Stderr, "unknown learning subcommand\n\n%s", learningUsage)
		os.Exit(1)
	}

	sub := "list"
	if len(positional) > 1 {
		sub = positional[1]
	}

	switch sub {
	case "list", "":
		runLearningExclusionsList(dbPath, entityFilter)
	case "clear":
		if entityFilter == "" {
			fmt.Fprintln(os.Stderr, "error: --entity <id> required for exclusions clear")
			os.Exit(1)
		}
		runLearningExclusionsClear(dbPath, entityFilter)
	default:
		fmt.Fprintf(os.Stderr, "unknown exclusions subcommand %q\n\n%s", sub, learningUsage)
		os.Exit(1)
	}
	return true
}

func runLearningExclusionsList(dbPath, entityFilter string) {
	s, err := sqlite.Open(sqlite.DefaultConfig(dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	q := `SELECT id, entity_id, entity_kind, reason, severity, applies_to,
	             starts_at, expires_at, source_component, status
	      FROM learning_exclusions WHERE status='active' AND expires_at > ?`
	args := []any{time.Now().UTC().Format(time.RFC3339Nano)}
	if entityFilter != "" {
		q += " AND entity_id=?"
		args = append(args, entityFilter)
	}
	q += " ORDER BY expires_at"

	rows, err := s.DB().QueryContext(context.Background(), q, args...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: query exclusions: %v\n", err)
		os.Exit(1)
	}
	defer rows.Close()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ENTITY\tKIND\tREASON\tSEV\tAPPLIES\tEXPIRES\tSOURCE")
	count := 0
	for rows.Next() {
		var id, entityID, entityKind, reason, appliesTo, startsAt, expiresAt, sourceComp, status string
		var severity float64
		if err := rows.Scan(&id, &entityID, &entityKind, &reason, &severity, &appliesTo,
			&startsAt, &expiresAt, &sourceComp, &status); err != nil {
			continue
		}
		exp, _ := time.Parse(time.RFC3339Nano, expiresAt)
		fmt.Fprintf(w, "%s\t%s\t%s\t%.1f\t%s\t%s\t%s\n",
			entityID, entityKind, reason, severity,
			shortApplies(appliesTo), exp.UTC().Format("2006-01-02T15:04"), sourceComp)
		count++
	}
	w.Flush()

	if count == 0 {
		fmt.Println("(no active exclusions)")
		return
	}
	fmt.Printf("\nTotal: %d active exclusion(s)\n", count)
}

func runLearningExclusionsClear(dbPath, entityID string) {
	s, err := sqlite.Open(sqlite.DefaultConfig(dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store: %v\n", err)
		os.Exit(1)
	}
	defer s.Close()

	// Revoke all active exclusions for this entity.
	res, err := s.DB().ExecContext(context.Background(),
		`UPDATE learning_exclusions SET status='revoked' WHERE entity_id=? AND status='active'`,
		entityID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: revoke exclusions: %v\n", err)
		os.Exit(1)
	}
	n, _ := res.RowsAffected()
	fmt.Printf("Revoked %d active exclusion(s) for entity %q\n", n, entityID)
}

func shortApplies(applies string) string {
	applies = strings.ReplaceAll(applies, `"metric_baseline"`, "metric")
	applies = strings.ReplaceAll(applies, `"relationship_learning"`, "rel")
	applies = strings.ReplaceAll(applies, `"graph_acceptance"`, "graph")
	applies = strings.ReplaceAll(applies, `"entity_promotion"`, "entity")
	applies = strings.Trim(applies, "[]")
	if applies == "" {
		return "all"
	}
	return applies
}
