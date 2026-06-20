// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

const baselinesGenericUsage = `usage: kliq baselines <subcommand> [args]

Subcommands:
  list [--db <path>] [--node <id>] [--metric <id>] [--scope <type>] [--source-class <class>]
       [--sort=metric|subject|source|scope|truth|window|state|baseline|peak|global-trigger|effective-trigger|confidence|obs|updated]
           List generic metric baselines from the state store.
  reset|delete [--db <path>] [--id <baseline-id>] [--metric <id-fragment>]
               [--scope <type>] [--scope-id <id>] [--source-class <class>]
               [--subject <id|display|stable-id>] [--state <state>] [--dry-run] [--all]
           Delete matching metric baselines. Requires at least one filter unless --all is set.
`

type baselineDeleteFilters struct {
	ID          string
	Metric      string
	Scope       string
	ScopeID     string
	SourceClass string
	Subject     string
	State       string
	DryRun      bool
	All         bool
}

func (f baselineDeleteFilters) hasSelector() bool {
	return f.All ||
		f.ID != "" ||
		f.Metric != "" ||
		f.Scope != "" ||
		f.ScopeID != "" ||
		f.SourceClass != "" ||
		f.Subject != "" ||
		f.State != ""
}

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
	sortSpec := "metric"
	deleteFilters := baselineDeleteFilters{}
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
			deleteFilters.Metric = metricFilter
		case strings.HasPrefix(a, "--metric="):
			metricFilter = strings.TrimPrefix(a, "--metric=")
			deleteFilters.Metric = metricFilter
		case a == "--scope" && i+1 < len(filtered):
			i++
			scopeFilter = filtered[i]
			deleteFilters.Scope = scopeFilter
		case strings.HasPrefix(a, "--scope="):
			scopeFilter = strings.TrimPrefix(a, "--scope=")
			deleteFilters.Scope = scopeFilter
		case a == "--scope-id" && i+1 < len(filtered):
			i++
			deleteFilters.ScopeID = filtered[i]
		case strings.HasPrefix(a, "--scope-id="):
			deleteFilters.ScopeID = strings.TrimPrefix(a, "--scope-id=")
		case a == "--source-class" && i+1 < len(filtered):
			i++
			sourceClassFilter = filtered[i]
			deleteFilters.SourceClass = sourceClassFilter
		case strings.HasPrefix(a, "--source-class="):
			sourceClassFilter = strings.TrimPrefix(a, "--source-class=")
			deleteFilters.SourceClass = sourceClassFilter
		case a == "--sort" && i+1 < len(filtered):
			i++
			sortSpec = filtered[i]
		case strings.HasPrefix(a, "--sort="):
			sortSpec = strings.TrimPrefix(a, "--sort=")
		case a == "--id" && i+1 < len(filtered):
			i++
			deleteFilters.ID = filtered[i]
		case strings.HasPrefix(a, "--id="):
			deleteFilters.ID = strings.TrimPrefix(a, "--id=")
		case a == "--subject" && i+1 < len(filtered):
			i++
			deleteFilters.Subject = filtered[i]
		case strings.HasPrefix(a, "--subject="):
			deleteFilters.Subject = strings.TrimPrefix(a, "--subject=")
		case a == "--state" && i+1 < len(filtered):
			i++
			deleteFilters.State = filtered[i]
		case strings.HasPrefix(a, "--state="):
			deleteFilters.State = strings.TrimPrefix(a, "--state=")
		case a == "--dry-run" || a == "-dry-run":
			deleteFilters.DryRun = true
		case a == "--all" || a == "-all":
			deleteFilters.All = true
		case len(a) > 0 && a[0] != '-':
			positional = append(positional, a)
		}
	}

	if len(positional) > 0 {
		sub = positional[0]
	}

	switch sub {
	case "list", "":
		runBaselinesGenericList(dbPath, metricFilter, scopeFilter, sourceClassFilter, sortSpec)
	case "reset", "delete":
		runBaselinesGenericDelete(dbPath, deleteFilters)
	default:
		fmt.Fprintf(os.Stderr, "unknown baselines subcommand %q\n\n%s", sub, baselinesGenericUsage)
		os.Exit(1)
	}
	return true
}

func runBaselinesGenericDelete(dbPath string, filters baselineDeleteFilters) {
	s, err := sqlite.Open(sqlite.DefaultConfig(dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store %q: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer s.Close()

	n, err := deleteMetricBaselines(context.Background(), s, filters)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: delete baselines: %v\n", err)
		os.Exit(1)
	}
	if filters.DryRun {
		fmt.Printf("Would delete %d metric baseline(s).\n", n)
		return
	}
	fmt.Printf("Deleted %d metric baseline(s).\n", n)
}

func deleteMetricBaselines(ctx context.Context, s *sqlite.Store, filters baselineDeleteFilters) (int64, error) {
	if !filters.hasSelector() {
		return 0, fmt.Errorf("refusing to delete baselines without a filter; use --all for a full wipe")
	}

	where, args := baselineDeleteWhere(filters)
	countSQL := `
		SELECT COUNT(*)
		FROM metric_baselines b
		LEFT JOIN entities e ON e.stable_id = b.subject_entity_id
		WHERE ` + where

	var n int64
	if err := s.DB().QueryRowContext(ctx, countSQL, args...).Scan(&n); err != nil {
		return 0, err
	}
	if filters.DryRun || n == 0 {
		return n, nil
	}

	deleteSQL := `
		DELETE FROM metric_baselines
		WHERE id IN (
			SELECT b.id
			FROM metric_baselines b
			LEFT JOIN entities e ON e.stable_id = b.subject_entity_id
			WHERE ` + where + `
		)`
	res, err := s.DB().ExecContext(ctx, deleteSQL, args...)
	if err != nil {
		return 0, err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return n, nil
	}
	return deleted, nil
}

func baselineDeleteWhere(filters baselineDeleteFilters) (string, []any) {
	clauses := []string{"1=1"}
	args := []any{}
	if filters.ID != "" {
		clauses = append(clauses, "b.id = ?")
		args = append(args, filters.ID)
	}
	if filters.Metric != "" {
		clauses = append(clauses, "b.metric_id LIKE ?")
		args = append(args, "%"+filters.Metric+"%")
	}
	if filters.Scope != "" {
		clauses = append(clauses, "b.scope_type = ?")
		args = append(args, filters.Scope)
	}
	if filters.ScopeID != "" {
		clauses = append(clauses, "b.scope_id = ?")
		args = append(args, filters.ScopeID)
	}
	if filters.SourceClass != "" {
		clauses = append(clauses, "b.source_class = ?")
		args = append(args, filters.SourceClass)
	}
	if filters.Subject != "" {
		clauses = append(clauses, "(b.subject_entity_id = ? OR e.id = ? OR e.display_name = ?)")
		args = append(args, filters.Subject, filters.Subject, filters.Subject)
	}
	if filters.State != "" {
		clauses = append(clauses, "b.state = ?")
		args = append(args, filters.State)
	}
	return strings.Join(clauses, " AND "), args
}

type baselineListRow struct {
	MetricID             string
	Subject              string
	SourceClass          string
	Scope                string
	Truth                string
	WindowSeconds        int64
	State                string
	Baseline             float64
	BaselineDisplay      string
	Peak                 float64
	PeakDisplay          string
	GlobalTrigger        float64
	GlobalTriggerText    string
	EffectiveTrigger     float64
	EffectiveTriggerText string
	Confidence           float64
	ConfidenceText       string
	Observations         int64
	LastUpdated          time.Time
}

func runBaselinesGenericList(dbPath, metricFilter, scopeFilter, sourceClassFilter, sortSpec string) {
	s, err := sqlite.Open(sqlite.DefaultConfig(dbPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: open state store %q: %v\n", dbPath, err)
		os.Exit(1)
	}
	defer s.Close()

	// Join with entities to resolve subject_entity_id → human-readable IP.
	rows, err := s.DB().QueryContext(context.Background(), `
		SELECT b.metric_id, b.scope_type, b.scope_id, b.subject_entity_id, b.source_class, b.visibility_point,
		       b.truth_class, b.window_seconds, b.state, b.ewma_state, b.observations, b.last_updated_at,
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

	outRows := []baselineListRow{}
	sortKey, sortDesc, err := parseBaselineSortSpec(sortSpec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n\n%s", err, baselinesGenericUsage)
		os.Exit(1)
	}

	count := 0
	for rows.Next() {
		var metricID, scopeType, scopeID, subjectEntityID, sourceClass, visPoint, truthClass, state, ewmaState, lastUpdated, entityDisplay string
		var windowSec, obs int64
		if err := rows.Scan(&metricID, &scopeType, &scopeID, &subjectEntityID, &sourceClass, &visPoint,
			&truthClass, &windowSec, &state, &ewmaState, &obs, &lastUpdated, &entityDisplay); err != nil {
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
		subject := baselineSubjectDisplay(entityDisplay, subjectEntityID, scopeID)
		baselineState := parseBaselineState(ewmaState)
		t, _ := time.Parse(time.RFC3339Nano, lastUpdated)
		outRows = append(outRows, baselineListRow{
			MetricID:             metricID,
			Subject:              subject,
			SourceClass:          sourceClass,
			Scope:                scope,
			Truth:                shortTruth(truthClass),
			WindowSeconds:        windowSec,
			State:                state,
			Baseline:             baselineState.Baseline,
			BaselineDisplay:      baselineState.BaselineText,
			Peak:                 baselineState.Peak,
			PeakDisplay:          baselineState.PeakText,
			GlobalTrigger:        baselineState.GlobalTrigger,
			GlobalTriggerText:    baselineState.GlobalTriggerText,
			EffectiveTrigger:     baselineState.EffectiveTrigger,
			EffectiveTriggerText: baselineState.EffectiveTriggerText,
			Confidence:           baselineState.Confidence,
			ConfidenceText:       baselineState.ConfidenceText,
			Observations:         obs,
			LastUpdated:          t,
		})
		count++
	}
	sortBaselineListRows(outRows, sortKey, sortDesc)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "METRIC\tSUBJECT\tSOURCE\tSCOPE\tTRUTH\tWIN\tSTATE\tBASELINE\tPEAK\tGTRIG\tETRIG\tCONF\tOBS\tLAST UPDATED")

	for _, row := range outRows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%ds\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			row.MetricID, row.Subject, row.SourceClass, row.Scope, row.Truth,
			row.WindowSeconds, row.State, row.BaselineDisplay, row.PeakDisplay,
			row.GlobalTriggerText, row.EffectiveTriggerText, row.ConfidenceText, row.Observations, row.LastUpdated.UTC().Format("2006-01-02T15:04"))
	}
	w.Flush()

	if count == 0 {
		fmt.Println("(no baselines found)")
		return
	}
	fmt.Printf("\nTotal: %d baseline(s)\n", count)
}

func baselineSubjectDisplay(entityDisplay, subjectEntityID, scopeID string) string {
	switch {
	case entityDisplay != "" && entityDisplay != scopeID:
		return entityDisplay
	case subjectEntityID != "":
		return subjectEntityID
	case scopeID != "":
		return shortID(scopeID)
	default:
		return ""
	}
}

type baselineStateValues struct {
	Baseline             float64
	BaselineText         string
	Peak                 float64
	PeakText             string
	GlobalTrigger        float64
	GlobalTriggerText    string
	EffectiveTrigger     float64
	EffectiveTriggerText string
	Confidence           float64
	ConfidenceText       string
}

func parseBaselineState(raw string) baselineStateValues {
	out := baselineStateValues{
		BaselineText:         "-",
		PeakText:             "-",
		GlobalTriggerText:    "-",
		EffectiveTriggerText: "-",
		ConfidenceText:       "-",
	}
	if strings.TrimSpace(raw) == "" {
		return out
	}
	var state map[string]float64
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return out
	}
	if v, ok := state["ewma"]; ok {
		out.Baseline = v
		out.BaselineText = formatBaselineNumber(v)
	}
	if v, ok := state["peak"]; ok {
		out.Peak = v
		out.PeakText = formatOptionalBaselineNumber(v)
	}
	if v, ok := state["global_trigger"]; ok {
		out.GlobalTrigger = v
		out.GlobalTriggerText = formatOptionalBaselineNumber(v)
	}
	if v, ok := state["effective_trigger"]; ok {
		out.EffectiveTrigger = v
		out.EffectiveTriggerText = formatOptionalBaselineNumber(v)
	}
	if v, ok := state["confidence"]; ok {
		out.Confidence = v
		out.ConfidenceText = fmt.Sprintf("%.2f", v)
	}
	return out
}

func formatBaselineState(raw string) (baseline, peak, confidence string) {
	state := parseBaselineState(raw)
	return state.BaselineText, state.PeakText, state.ConfidenceText
}

func parseBaselineSortSpec(spec string) (key string, desc bool, err error) {
	key = strings.TrimSpace(spec)
	if key == "" {
		key = "metric"
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
	case "metric", "subject", "source", "scope", "truth", "window", "win", "state", "baseline", "peak", "global_trigger", "gtrig", "effective_trigger", "etrig", "confidence", "conf", "observations", "obs", "updated", "last_updated", "last":
		return key, desc, nil
	default:
		return "", false, fmt.Errorf("unsupported baseline sort %q", spec)
	}
}

func sortBaselineListRows(rows []baselineListRow, key string, desc bool) {
	sort.SliceStable(rows, func(i, j int) bool {
		cmp := compareBaselineRows(rows[i], rows[j], key)
		if cmp == 0 {
			cmp = compareString(rows[i].MetricID, rows[j].MetricID)
		}
		if cmp == 0 {
			cmp = compareString(rows[i].Subject, rows[j].Subject)
		}
		if cmp == 0 {
			cmp = compareString(rows[i].Scope, rows[j].Scope)
		}
		if desc {
			return cmp > 0
		}
		return cmp < 0
	})
}

func compareBaselineRows(a, b baselineListRow, key string) int {
	switch key {
	case "metric":
		return compareString(a.MetricID, b.MetricID)
	case "subject":
		return compareString(a.Subject, b.Subject)
	case "source":
		return compareString(a.SourceClass, b.SourceClass)
	case "scope":
		return compareString(a.Scope, b.Scope)
	case "truth":
		return compareString(a.Truth, b.Truth)
	case "window", "win":
		return compareInt64(a.WindowSeconds, b.WindowSeconds)
	case "state":
		return compareString(a.State, b.State)
	case "baseline":
		return compareFloat64(a.Baseline, b.Baseline)
	case "peak":
		return compareFloat64(a.Peak, b.Peak)
	case "global_trigger", "gtrig":
		return compareFloat64(a.GlobalTrigger, b.GlobalTrigger)
	case "effective_trigger", "etrig":
		return compareFloat64(a.EffectiveTrigger, b.EffectiveTrigger)
	case "confidence", "conf":
		return compareFloat64(a.Confidence, b.Confidence)
	case "observations", "obs":
		return compareInt64(a.Observations, b.Observations)
	case "updated", "last_updated", "last":
		return compareTime(a.LastUpdated, b.LastUpdated)
	default:
		return compareString(a.MetricID, b.MetricID)
	}
}

func formatBaselineNumber(v float64) string {
	switch {
	case v == 0:
		return "0"
	case v >= 100:
		return fmt.Sprintf("%.0f", v)
	case v >= 10:
		return fmt.Sprintf("%.1f", v)
	default:
		return fmt.Sprintf("%.2f", v)
	}
}

func formatOptionalBaselineNumber(v float64) string {
	if v <= 0 {
		return "-"
	}
	return formatBaselineNumber(v)
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
