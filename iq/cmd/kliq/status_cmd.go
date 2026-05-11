// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"errors"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/core/graph"
	gstore "github.com/adrianenderlin/kernloom/pkg/graphstore/sqlite"
)

// handleStatusSubcommand handles "kliq status [state-file] [db]" without
// starting the main kliq loop. Returns true if handled.
func handleStatusSubcommand(defaultStateFile, defaultDB string) bool {
	args := os.Args[1:]
	if len(args) < 1 || args[0] != "status" {
		return false
	}

	statePath := defaultStateFile
	dbPath := defaultDB

	// Positional args override defaults; flags are dropped.
	filtered := args[:0]
	for _, a := range args {
		if len(a) > 0 && a[0] == '-' {
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered
	if len(args) > 1 {
		statePath = args[1]
	}
	if len(args) > 2 {
		dbPath = args[2]
	}

	runStatus(statePath, dbPath)
	return true
}

func runStatus(statePath, dbPath string) {
	hostname, _ := os.Hostname()
	fmt.Printf("Kernloom IQ — status\n\n")

	// ── State file ───────────────────────────────────────────────────────────
	st, err := loadState(statePath, 0) // 0 = no age limit for display
	if err != nil || st == nil {
		if f, ferr := os.Open(statePath); ferr == nil {
			f.Close()
		} else if errors.Is(ferr, os.ErrPermission) {
			fmt.Printf("Autotune:  permission denied — run with sudo to read %s\n", statePath)
		} else {
			fmt.Printf("Autotune:  no state found — start kliq to begin learning\n")
		}
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "Node:\t%s\n", hostname)
		fmt.Fprintf(w, "Profile:\t%s\n", st.Active.Profile)

		bs := st.Active.Bootstrap
		if bs.Enabled && bs.Phase != "" && bs.Phase != "steady" {
			since := ""
			if !bs.StartedAt.IsZero() {
				since = fmt.Sprintf("  (started %s ago)", fmtAge(time.Since(bs.StartedAt)))
			}
			fmt.Fprintf(w, "Bootstrap:\t%s%s\n", bs.Phase, since)
		} else {
			fmt.Fprintf(w, "Bootstrap:\tsteady\n")
		}

		if !st.Active.UpdatedAt.IsZero() {
			fmt.Fprintf(w, "Last tuned:\trev %d  %s ago  samples=%d  clean=%.1f%%\n",
				st.Active.Revision,
				fmtAge(time.Since(st.Active.UpdatedAt)),
				st.Active.SampleCount,
				st.Active.CleanRatio*100,
			)
		}
		w.Flush()

		fmt.Printf("\nAutotune triggers:\n")
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  pps\t%.1f\n", st.Active.Trig.TrigPPS)
		fmt.Fprintf(w, "  syn\t%.1f\n", st.Active.Trig.TrigSyn)
		fmt.Fprintf(w, "  scan\t%.1f\n", st.Active.Trig.TrigScan)
		if st.Active.Trig.TrigBPS > 0 {
			fmt.Fprintf(w, "  bps\t%.0f\n", st.Active.Trig.TrigBPS)
		} else {
			fmt.Fprintf(w, "  bps\toff\n")
		}
		w.Flush()

		if n := len(st.History); n > 0 {
			fmt.Printf("\nTune history (last %d of %d):\n", min3(n, 3), n)
			w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  REV\tDATE\tPPS\tSYN\tSCAN\tBPS")
			start := 0
			if n > 3 {
				start = n - 3
			}
			for _, h := range st.History[start:] {
				bpsStr := "off"
				if h.Trig.TrigBPS > 0 {
					bpsStr = fmt.Sprintf("%.0f", h.Trig.TrigBPS)
				}
				fmt.Fprintf(w, "  %d\t%s\t%.1f\t%.1f\t%.1f\t%s\n",
					h.Revision, h.At.Format("2006-01-02 15:04"),
					h.Trig.TrigPPS, h.Trig.TrigSyn, h.Trig.TrigScan, bpsStr)
			}
			w.Flush()
		}
	}

	// ── Graph DB ─────────────────────────────────────────────────────────────
	s, err := gstore.Open(dbPath)
	if err != nil {
		fmt.Printf("\nGraph:     db not accessible (%s)\n", dbPath)
		return
	}
	defer s.Close()

	stats, _ := s.Stats(hostname)

	total := 0
	for _, n := range stats {
		total += n
	}

	fmt.Printf("\nGraph:     ")
	if total == 0 {
		fmt.Println("no edges yet")
	} else {
		fmt.Printf("%d edges total\n", total)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, state := range []graph.EdgeState{
			graph.EdgeFrozen, graph.EdgeApproved, graph.EdgeLearned,
			graph.EdgeCandidate, graph.EdgeDenied, graph.EdgeExpired,
		} {
			if n := stats[state]; n > 0 {
				fmt.Fprintf(w, "  %s\t%d\n", state, n)
			}
		}
		w.Flush()
	}

	// ── Baselines ────────────────────────────────────────────────────────────
	bl, err := s.ListEdgeBaselines(hostname)
	if err == nil && len(bl) > 0 {
		candidate, learned := 0, 0
		for _, e := range bl {
			if e.BLState == "learned" {
				learned++
			} else {
				candidate++
			}
		}
		fmt.Printf("\nBaselines: %d learned  %d candidate\n", learned, candidate)
	}
}

func fmtAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(d.Hours()/24), int(d.Hours())%24)
	}
}

func min3(a, b int) int {
	if a < b {
		return a
	}
	return b
}
