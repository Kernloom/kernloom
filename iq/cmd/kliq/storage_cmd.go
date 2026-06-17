// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

const storageUsage = `usage: kliq storage <subcommand> [args]

Subcommands:
  status  [--db <path>]
              Print row counts and schema version for the state store.
  cleanup [--db <path>] [--dry-run]
              Prune expired evidence, signals, decisions, and exclusions.
`

// handleStorageSubcommand handles "kliq storage <sub> ..." commands.
func handleStorageSubcommand(defaultDB string) bool {
	args := os.Args[1:]
	if len(args) < 1 || args[0] != "storage" {
		return false
	}

	dbPath := defaultDB
	dryRun := false
	sub := "status"

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
		case a == "--dry-run" || a == "-dry-run":
			dryRun = true
		case len(a) > 0 && a[0] != '-':
			positional = append(positional, a)
		}
	}

	if len(positional) > 0 {
		sub = positional[0]
	}

	switch sub {
	case "status", "":
		runStorageStatus(dbPath)
	case "cleanup":
		runStorageCleanup(dbPath, dryRun)
	default:
		fmt.Fprintf(os.Stderr, "unknown storage subcommand %q\n\n%s", sub, storageUsage)
		os.Exit(1)
	}
	return true
}

func runStorageStatus(dbPath string) {
	s, err := sqlite.Open(sqlite.DefaultConfig(dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store %q: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer s.Close()

	fmt.Printf("State store: %s\n\n", dbPath)

	tables := []string{
		"entities", "relationships", "metric_baselines",
		"learning_exclusions", "evidence", "signals", "decisions",
		"adapter_state", "registry_versions",
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TABLE\tROWS")
	for _, t := range tables {
		var n int64
		row := s.DB().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM "+t)
		_ = row.Scan(&n)
		fmt.Fprintf(w, "%s\t%d\n", t, n)
	}
	w.Flush()

	var version int64
	row := s.DB().QueryRowContext(context.Background(),
		"SELECT COALESCE(MAX(version),0) FROM schema_migrations")
	_ = row.Scan(&version)
	fmt.Printf("\nSchema version: %d\n", version)

	var pageCount, pageSize int64
	_ = s.DB().QueryRowContext(context.Background(), "PRAGMA page_count").Scan(&pageCount)
	_ = s.DB().QueryRowContext(context.Background(), "PRAGMA page_size").Scan(&pageSize)
	sizeMB := float64(pageCount*pageSize) / (1024 * 1024)
	fmt.Printf("Database size:  %.2f MB\n", sizeMB)
}

func runStorageCleanup(dbPath string, dryRun bool) {
	s, err := sqlite.Open(sqlite.DefaultConfig(dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store %q: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer s.Close()

	if dryRun {
		// Count what would be deleted without doing it.
		tables := []struct{ table, col string }{
			{"evidence", "expires_at"},
			{"signals", "expires_at"},
			{"decisions", "expires_at"},
		}
		ctx := context.Background()
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TABLE\tEXPIRED ROWS (would delete)")
		for _, t := range tables {
			var n int64
			row := s.DB().QueryRowContext(ctx,
				fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE %s < datetime('now')", t.table, t.col))
			_ = row.Scan(&n)
			fmt.Fprintf(w, "%s\t%d\n", t.table, n)
		}
		var exclN int64
		_ = s.DB().QueryRowContext(ctx,
			`SELECT COUNT(*) FROM learning_exclusions WHERE status='active' AND expires_at < datetime('now')`).
			Scan(&exclN)
		fmt.Fprintf(w, "learning_exclusions\t%d (expire → 'expired')\n", exclN)
		w.Flush()
		fmt.Println("\n(dry-run: no changes made)")
		return
	}

	if err := s.GC(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "error: cleanup: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Cleanup complete.")
}
