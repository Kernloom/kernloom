// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kernloom/kernloom/pkg/core/baseline"
	"github.com/kernloom/kernloom/pkg/core/featureset"
	"github.com/kernloom/kernloom/pkg/core/graph"
	gstore "github.com/kernloom/kernloom/pkg/graphstore/sqlite"
)

// handleStatusSubcommand handles "kliq status" and "kliq runtime status"
// without starting the main kliq loop. Returns true if handled.
func handleStatusSubcommand(defaultStateFile, defaultDB string) bool {
	args := os.Args[1:]
	if len(args) < 1 {
		return false
	}

	// "kliq runtime status [profile]"
	if args[0] == "runtime" && len(args) >= 2 && args[1] == "status" {
		profile := featureset.ProfileDOSLight
		if len(args) >= 3 {
			profile = featureset.RuntimeProfile(args[2])
		}
		runRuntimeStatus(profile)
		return true
	}

	if args[0] != "status" {
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
			nextIn := ""
			if interval := phaseInterval(st.Active.Bootstrap.Phase); interval > 0 {
				remaining := interval - time.Since(st.Active.UpdatedAt)
				if remaining < 0 {
					remaining = 0
				}
				nextIn = fmt.Sprintf("  next ~%s", fmtAge(remaining))
			}
			fmt.Fprintf(w, "Last tuned:\trev %d  %s ago  samples=%d  clean=%.1f%%%s\n",
				st.Active.Revision,
				fmtAge(time.Since(st.Active.UpdatedAt)),
				st.Active.SampleCount,
				st.Active.CleanRatio*100,
				nextIn,
			)
		} else {
			fmt.Fprintf(w, "Last tuned:\tnever\n")
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

	// ── Policy / Inventory (from runtime sidecar) ────────────────────────────
	printRuntimeReport(statePath)

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
			if e.Profile.State == baseline.StateLearned {
				learned++
			} else {
				candidate++
			}
		}
		fmt.Printf("\nBaselines: %d learned  %d candidate\n", learned, candidate)
	}
}

// printRuntimeReport reads the kliq-report.json sidecar (written at startup)
// and prints a formatted policy + inventory summary.
func printRuntimeReport(statePath string) {
	sidecar := reportSidecarPath(statePath)
	if sidecar == "" {
		return
	}
	data, err := os.ReadFile(sidecar)
	if err != nil {
		return // not yet written (kliq not started), silently skip
	}
	var rep runtimeReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return
	}
	cr := rep.ConfigReport
	fmt.Println()

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Mode:\t%s\n", cr.Mode)
	fmt.Fprintf(w, "Policy authority:\t%s\n", cr.PolicyAuthority)
	if cr.HasPolicyPack {
		maxA := cr.PolicyMaxAction
		if maxA == "" {
			maxA = "block (no cap)"
		}
		fmt.Fprintf(w, "Policy pack:\tloaded  max_action=%s  allow_block=%v\n", maxA, cr.AllowLocalBlock)
	} else {
		fmt.Fprintf(w, "Policy pack:\tnone")
		if cr.Mode == "managed" {
			fmt.Fprint(w, "  ← observe-only until pack loaded")
		}
		fmt.Fprintln(w)
	}
	if cr.DryRun {
		fmt.Fprintf(w, "Dry-run:\tenabled — no BPF map writes\n")
	}
	fmt.Fprintf(w, "Rate mode:\t%s\n", cr.EnforcementMode)
	w.Flush()

	// Rate details block — different presentation per mode.
	fmt.Printf("\nEnforcement rates:\n")
	w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	switch cr.EnforcementMode {
	case "directive":
		if cr.SoftDirectiveRatePPS > 0 {
			fmt.Fprintf(w, "  soft:\t%d pps  (policy: fixed)\n", cr.SoftDirectiveRatePPS)
		}
		if cr.HardDirectiveRatePPS > 0 {
			fmt.Fprintf(w, "  hard:\t%d pps  (policy: fixed)\n", cr.HardDirectiveRatePPS)
		}
	case "autonomy":
		if cr.SoftRateFactor > 0 {
			fmt.Fprintf(w, "  soft:\t%d pps  (adaptive: trig=%.0f × %.2f)\n",
				cr.EffectiveSoftRatePPS, cr.InitialTrigPPS, cr.SoftRateFactor)
		} else if cr.EffectiveSoftRatePPS > 0 {
			fmt.Fprintf(w, "  soft:\t%d pps  (static)\n", cr.EffectiveSoftRatePPS)
		}
		if cr.HardRateFactor > 0 {
			fmt.Fprintf(w, "  hard:\t%d pps  (adaptive: trig=%.0f × %.2f)\n",
				cr.EffectiveHardRatePPS, cr.InitialTrigPPS, cr.HardRateFactor)
		} else if cr.EffectiveHardRatePPS > 0 {
			fmt.Fprintf(w, "  hard:\t%d pps  (static)\n", cr.EffectiveHardRatePPS)
		}
	}
	w.Flush()

	inv := rep.Inventory
	if len(inv.EffectiveCapabilities) > 0 {
		fmt.Println()
		fmt.Printf("Capabilities (%s):\n", inv.Metadata.ID)
		w = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		for _, cap := range inv.EffectiveCapabilities {
			g := strings.Join(cap.Granularity, ", ")
			extra := ""
			if cap.Reason != "" {
				extra = "  [" + cap.Reason + "]"
			}
			fmt.Fprintf(w, "  %s\t%s\t%s%s\n", cap.ID, cap.Status, g, extra)
		}
		for _, cap := range inv.UnavailableCapabilities {
			fmt.Fprintf(w, "  %s\t%s\t%s\n", cap.ID, cap.Status, cap.Reason)
		}
		w.Flush()
	}
}

// phaseInterval returns the default autotune cycle interval for a bootstrap phase.
func phaseInterval(phase string) time.Duration {
	switch phase {
	case "bootstrap-1":
		return time.Hour
	case "bootstrap-2":
		return 6 * time.Hour
	case "bootstrap-3":
		return 24 * time.Hour
	default:
		return 0
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

// runRuntimeStatus prints the active FeatureSet for a given profile.
// Usage: kliq runtime status [profile]
func runRuntimeStatus(profile featureset.RuntimeProfile) {
	// klshield-light means XDP only — KLIQ is not part of this setup at all.
	if profile == featureset.ProfileKLShieldLight {
		fmt.Println("Profile: klshield-light")
		fmt.Println()
		fmt.Println("  This profile runs klshield (XDP) only — no kliq needed.")
		fmt.Println("  Static deny lists, optional default rate limit, no autotune.")
		fmt.Println()
		fmt.Println("  Setup:")
		fmt.Println("    sudo klshield attach-xdp --iface eth0")
		fmt.Println("    sudo klshield set-default-rl --rate 1000 --burst 2000  # optional")
		fmt.Println("    sudo klshield add-deny-ip <ip>                          # manual blocks")
		fmt.Println()
		fmt.Println("  Do not start kliq — it is not needed and adds no value here.")
		return
	}

	fs := featureset.FeaturesFor(profile)
	fmt.Printf("Profile: %s\n\n", profile)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	enabled := func(b bool) string {
		if b {
			return "enabled"
		}
		return "disabled"
	}
	fmt.Fprintln(w, "  Shield XDP:\t"+enabled(fs.ShieldXDP))
	fmt.Fprintln(w, "  Userspace IQ (kliq):\t"+enabled(fs.UserspaceIQ))
	fmt.Fprintln(w, "  Source heuristic:\t"+enabled(fs.SourceHeuristic))
	fmt.Fprintln(w, "  Global autotune:\t"+enabled(fs.GlobalAutotune))
	fmt.Fprintln(w, "  Source baseline:\t"+enabled(fs.SourceBaseline))
	fmt.Fprintln(w, "  Flow telemetry:\t"+enabled(fs.FlowTelemetry))
	fmt.Fprintln(w, "  Graph learning:\t"+enabled(fs.GraphLearning))
	fmt.Fprintln(w, "  Edge baseline:\t"+enabled(fs.EdgeBaseline))
	fmt.Fprintln(w, "  SQLite:\t"+enabled(fs.SQLite))
	fmt.Fprintln(w, "  Tuple enforcement:\t"+enabled(fs.TupleEnforcement))
	w.Flush()
	fmt.Println()
	fmt.Println("kliq profiles (all require kliq + klshield):")
	fmt.Println("  dos-light      source heuristic + autotune, no graph, no SQLite")
	fmt.Println("  iq-learning    dos-light + per-source EWMA baseline")
	fmt.Println("  graph-learning iq-learning + flow telemetry + graph + edge baseline + SQLite")
	fmt.Println("  graph-enforce  graph-learning + XDP tuple enforcement")
	fmt.Println()
	fmt.Println("klshield-only profile (no kliq needed):")
	fmt.Println("  klshield-light XDP only — static deny/allow, optional default RL")
}
