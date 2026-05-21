// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package nftables

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
)

var update = flag.Bool("update", false, "rewrite golden files")

func TestRenderTable_DenySrcIP(t *testing.T) {
	port := uint16(443)
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{
			{Name: "input", Hook: "input"},
		},
		Rules: []netfilter.RulePlan{
			{
				ID: "abc12300",
				Selector: netfilter.Selector{
					SrcIP:   "192.0.2.10",
					Proto:   "tcp",
					DstPort: &port,
				},
				Verdict: netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "deny_src_ip", RenderTable(plan, DefaultRenderOptions()))
}

func TestRenderTable_DenySrcCIDR(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{{Name: "input", Hook: "input"}},
		Rules: []netfilter.RulePlan{
			{
				ID:       "abc12300",
				Selector: netfilter.Selector{SrcCIDR: "10.0.0.0/8"},
				Verdict:  netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "deny_src_cidr", RenderTable(plan, DefaultRenderOptions()))
}

func TestRenderTable_AllowReturn(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{{Name: "input", Hook: "input"}},
		Rules: []netfilter.RulePlan{
			{
				ID:       "abc12300",
				Selector: netfilter.Selector{SrcCIDR: "192.168.1.0/24"},
				Verdict:  netfilter.VerdictReturn,
			},
		},
	}
	assertGolden(t, "allow_return", RenderTable(plan, DefaultRenderOptions()))
}

func TestRenderTable_DenySet(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{{Name: "input", Hook: "input"}},
		Sets: []netfilter.SetPlan{
			{Name: "deny4", Family: "ipv4", Timeout: true, Counters: true},
		},
		Rules: []netfilter.RulePlan{
			{
				ID:       "abc12300",
				Selector: netfilter.Selector{SetName: "deny4", SetDir: "src"},
				Verdict:  netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "deny_set", RenderTable(plan, DefaultRenderOptions()))
}

func TestRenderTable_DenySetWithElements(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{{Name: "input", Hook: "input"}},
		Sets: []netfilter.SetPlan{
			{
				Name:     "deny4",
				Family:   "ipv4",
				Timeout:  true,
				Counters: true,
				Elements: []netfilter.SetElement{
					{Value: "192.0.2.10", TTL: 600 * time.Second},
					{Value: "192.0.2.11"},
				},
			},
		},
		Rules: []netfilter.RulePlan{
			{
				ID:       "abc12300",
				Selector: netfilter.Selector{SetName: "deny4", SetDir: "src"},
				Verdict:  netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "deny_set_with_elements", RenderTable(plan, DefaultRenderOptions()))
}

func TestRenderTable_MultiChain(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{
			{Name: "input", Hook: "input"},
			{Name: "forward", Hook: "forward"},
		},
		Rules: []netfilter.RulePlan{
			{
				ID:       "abc12300",
				Selector: netfilter.Selector{SrcIP: "192.0.2.10", Direction: "input"},
				Verdict:  netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "multi_chain", RenderTable(plan, DefaultRenderOptions()))
}

func TestRenderTable_IPv6Deny(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{{Name: "input", Hook: "input"}},
		Rules: []netfilter.RulePlan{
			{
				ID:       "abc12300",
				Selector: netfilter.Selector{SrcIP: "2001:db8::1"},
				Verdict:  netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "ipv6_deny", RenderTable(plan, DefaultRenderOptions()))
}

func TestRenderTable_RateLimit(t *testing.T) {
	port := uint16(443)
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{{Name: "input", Hook: "input"}},
		Rules: []netfilter.RulePlan{
			{
				ID: "abc12300",
				Selector: netfilter.Selector{
					SrcIP:   "192.0.2.10",
					Proto:   "tcp",
					DstPort: &port,
				},
				Verdict: netfilter.VerdictDrop,
				Comment: "",
				Constraints: map[string]any{
					"capability": "enforce.network.rate_limit",
				},
			},
		},
	}
	// For the golden test we use a custom comment prefix to distinguish this case.
	opts := DefaultRenderOptions()
	opts.CommentPrefix = "kernloom"
	plan.Rules[0].ID = "abc12300"
	// Override the comment to match the rate_limit action label.
	plan.Rules[0].Comment = ""

	// Build a plan that represents a rate_limit verdict (still DROP in nft basic form).
	// Full meter support (Phase 4) will extend this — for now DROP is the fallback.
	got := RenderTable(plan, opts)

	// For rate_limit golden we accept the same DROP output — meters added in Phase 4.
	assertGolden(t, "rate_limit", got)
}

func TestRenderTable_EmptyPlan(t *testing.T) {
	plan := netfilter.NetfilterPlan{}
	got := RenderTable(plan, DefaultRenderOptions())
	if !strings.HasPrefix(got, "table inet kernloom {") {
		t.Errorf("empty plan should produce table header, got:\n%s", got)
	}
	if !strings.HasSuffix(strings.TrimSpace(got), "}") {
		t.Errorf("empty plan should close table brace, got:\n%s", got)
	}
}

func TestRenderTable_StableOutput(t *testing.T) {
	port := uint16(80)
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{{Name: "input", Hook: "input"}},
		Rules: []netfilter.RulePlan{
			{ID: "r2", Selector: netfilter.Selector{SrcCIDR: "10.0.0.0/8"}, Verdict: netfilter.VerdictDrop},
			{ID: "r1", Selector: netfilter.Selector{SrcIP: "1.2.3.4", Proto: "tcp", DstPort: &port}, Verdict: netfilter.VerdictDrop},
		},
	}
	opts := DefaultRenderOptions()
	first := RenderTable(plan, opts)
	second := RenderTable(plan, opts)
	if first != second {
		t.Errorf("nftables render is not stable:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestRenderTable_RulePriority(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		Chains: []netfilter.ChainPlan{{Name: "input", Hook: "input"}},
		Rules: []netfilter.RulePlan{
			{ID: "low", Selector: netfilter.Selector{SrcIP: "10.0.0.2"}, Verdict: netfilter.VerdictDrop, Priority: 10},
			{ID: "high", Selector: netfilter.Selector{SrcIP: "10.0.0.1"}, Verdict: netfilter.VerdictDrop, Priority: 1},
		},
	}
	got := RenderTable(plan, DefaultRenderOptions())
	posHigh := strings.Index(got, "10.0.0.1")
	posLow := strings.Index(got, "10.0.0.2")
	if posHigh > posLow {
		t.Errorf("priority 1 rule should appear before priority 10 rule")
	}
}

func TestRenderAddElements_WithTTL(t *testing.T) {
	els := []netfilter.SetElement{
		{Value: "192.0.2.10", TTL: 600 * time.Second},
		{Value: "192.0.2.11"},
	}
	cmds := RenderAddElements("kernloom", "deny4", els)
	if len(cmds) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(cmds))
	}
	if !strings.Contains(cmds[0], "timeout 600s") {
		t.Errorf("expected timeout in first command, got: %s", cmds[0])
	}
	if strings.Contains(cmds[1], "timeout") {
		t.Errorf("second element has no TTL, should not contain timeout, got: %s", cmds[1])
	}
}

func TestRenderDeleteTable(t *testing.T) {
	opts := DefaultRenderOptions()
	got := RenderDeleteTable(opts)
	want := "delete table inet kernloom\n"
	if got != want {
		t.Errorf("want %q, got %q", want, got)
	}
}

func TestRenderTable_CustomTableName(t *testing.T) {
	opts := DefaultRenderOptions()
	opts.TableName = "myapp"
	plan := netfilter.NetfilterPlan{}
	got := RenderTable(plan, opts)
	if !strings.Contains(got, "table inet myapp") {
		t.Errorf("expected custom table name 'myapp', got:\n%s", got)
	}
}

/* ── golden file helpers ─────────────────────────────────────────────────── */

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", "golden", name+".golden")

	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden %s: %v", path, err)
		}
		t.Logf("updated golden file: %s", path)
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v — run with -update to create it", path, err)
	}
	if got != string(want) {
		t.Errorf("render mismatch for %s\nwant:\n%s\ngot:\n%s", name, string(want), got)
	}
}
