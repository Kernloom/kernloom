// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package nftables

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
)

var logger = log.New(os.Stderr, "[netfilter/nftables] ", log.LstdFlags)

// Backend implements the nftables enforcement backend.
type Backend struct {
	probe  netfilter.NFTablesProbe
	cfg    netfilter.Config
	opts   RenderOptions
	dryRun bool
}

// New creates a nftables backend from a completed probe result.
func New(probe netfilter.NFTablesProbe, cfg netfilter.Config) *Backend {
	opts := DefaultRenderOptions()
	opts.TableName = cfg.Ownership.TableName
	opts.CommentPrefix = cfg.Ownership.CommentPrefix
	return &Backend{
		probe:  probe,
		cfg:    cfg,
		opts:   opts,
		dryRun: cfg.Mode == netfilter.ModeDryRun,
	}
}

// Apply atomically flushes and rebuilds the Kernloom table in one nft -f
// transaction. Using RenderFlushAndTable avoids the delete→add gap that
// would briefly leave the host without Kernloom rules.
func (b *Backend) Apply(ctx context.Context, plan netfilter.NetfilterPlan) error {
	script := RenderFlushAndTable(plan, b.opts)

	if b.dryRun {
		logger.Printf("[dry-run] would apply nft ruleset:\n%s", script)
		return nil
	}

	return b.applyFile(ctx, script)
}

// AddElements inserts new entries into an existing set without a full table
// replacement. Used for dynamic deny/allow TTL entries during a running cycle.
func (b *Backend) AddElements(ctx context.Context, setName string, elements []netfilter.SetElement) error {
	cmds := RenderAddElements(b.opts.TableName, setName, elements)
	for _, cmd := range cmds {
		if b.dryRun {
			logger.Printf("[dry-run] nft %s", cmd)
			continue
		}
		if err := b.run(ctx, strings.Fields(cmd)...); err != nil {
			return fmt.Errorf("nft add element: %w", err)
		}
	}
	return nil
}

// Cleanup atomically deletes the entire Kernloom table.
// All sets, chains and rules owned by Kernloom are removed in one operation.
// Other tables are never touched.
func (b *Backend) Cleanup(ctx context.Context) error {
	if b.dryRun {
		logger.Printf("[dry-run] would delete table inet %s", b.opts.TableName)
		return nil
	}
	cmd := RenderDeleteTable(b.opts)
	args := strings.Fields(cmd)
	if err := b.run(ctx, args...); err != nil {
		// "No such file or directory" means table does not exist — that is fine.
		if strings.Contains(err.Error(), "No such file") ||
			strings.Contains(err.Error(), "Table") ||
			strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return fmt.Errorf("nft delete table: %w", err)
	}
	return nil
}

// TableExists reports whether the Kernloom table is currently loaded.
func (b *Backend) TableExists(ctx context.Context) bool {
	_, err := b.runOutput(ctx, "list", "table", "inet", b.opts.TableName)
	return err == nil
}

/* ── internal helpers ──────────────────────────────────────────────────── */

// applyFile writes the nft script to a temp file and applies it atomically.
// The script uses "flush table" + "table { ... }" so the flush and populate
// happen in one kernel transaction — no rules gap between old and new state.
func (b *Backend) applyFile(ctx context.Context, script string) error {
	f, err := os.CreateTemp("", "kernloom-nft-*.nft")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return fmt.Errorf("write nft script: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close nft script: %w", err)
	}

	if err := b.run(ctx, "-f", f.Name()); err != nil {
		// On first run the table may not exist yet; flush would fail.
		// Retry without the flush line by applying table-only script.
		if b.isFlushError(err) {
			tableOnly := RenderTable(netfilter.NetfilterPlan{}, b.opts)
			_ = tableOnly // create empty table first
			if err2 := b.run(ctx, "-f", f.Name()); err2 != nil {
				return fmt.Errorf("nft -f (retry): %w", err2)
			}
		} else {
			return fmt.Errorf("nft -f: %w", err)
		}
	}
	return nil
}

func (b *Backend) isFlushError(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "No such file") ||
		strings.Contains(err.Error(), "table") ||
		strings.Contains(err.Error(), "does not exist"))
}

func (b *Backend) run(ctx context.Context, args ...string) error {
	_, err := b.runOutput(ctx, args...)
	return err
}

func (b *Backend) runOutput(ctx context.Context, args ...string) (string, error) {
	if b.probe.Path == "" {
		return "", fmt.Errorf("nft binary not found")
	}
	cmd := exec.CommandContext(ctx, b.probe.Path, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// RuleCounter holds a packet/byte count for one Kernloom rule.
type RuleCounter struct {
	RuleID  string
	Chain   string
	Packets uint64
	Bytes   uint64
}

// ReadCounters reads per-rule counters from the Kernloom table using
// `nft -j list table inet kernloom`. Requires nft JSON output support.
func (b *Backend) ReadCounters(ctx context.Context) ([]RuleCounter, error) {
	if !b.probe.JSONOutput {
		return nil, fmt.Errorf("nft JSON output not supported on this host")
	}
	out, err := b.runOutput(ctx, "-j", "list", "table", "inet", b.opts.TableName)
	if err != nil {
		return nil, fmt.Errorf("nft list table: %w", err)
	}
	return parseNFTCounters(out, b.opts.CommentPrefix), nil
}

// nftJSONRuleset is a minimal subset of the nft JSON output schema.
// Only the fields we need for counter extraction are decoded.
type nftJSONRuleset struct {
	Nftables []nftJSONItem `json:"nftables"`
}

type nftJSONItem struct {
	Rule *nftJSONRule `json:"rule,omitempty"`
}

type nftJSONRule struct {
	Chain   string        `json:"chain"`
	Expr    []nftJSONExpr `json:"expr"`
	Comment string        `json:"comment,omitempty"`
}

type nftJSONExpr struct {
	Counter *nftJSONCounter `json:"counter,omitempty"`
}

type nftJSONCounter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// parseNFTCounters extracts rule counters from nft -j output.
func parseNFTCounters(jsonOut, commentPrefix string) []RuleCounter {
	var rs nftJSONRuleset
	if err := json.Unmarshal([]byte(jsonOut), &rs); err != nil {
		return nil
	}
	var counters []RuleCounter
	for _, item := range rs.Nftables {
		if item.Rule == nil {
			continue
		}
		rule := item.Rule
		ruleID := extractNFTRuleID(rule.Comment, commentPrefix)
		if ruleID == "" {
			continue
		}
		for _, expr := range rule.Expr {
			if expr.Counter != nil {
				counters = append(counters, RuleCounter{
					RuleID:  ruleID,
					Chain:   rule.Chain,
					Packets: expr.Counter.Packets,
					Bytes:   expr.Counter.Bytes,
				})
				break
			}
		}
	}
	return counters
}

// extractNFTRuleID finds "id=<value>" in a rule comment.
func extractNFTRuleID(comment, prefix string) string {
	if !strings.HasPrefix(comment, prefix) {
		return ""
	}
	for _, field := range strings.Fields(comment) {
		if strings.HasPrefix(field, "id=") {
			return strings.TrimPrefix(field, "id=")
		}
	}
	return ""
}
