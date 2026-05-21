// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package iptables

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernloom/kernloom/pkg/adapters/netfilter"
)

// -update rewrites golden files instead of comparing against them.
var update = flag.Bool("update", false, "rewrite golden files")

func TestRender_DenySrcIP(t *testing.T) {
	port := uint16(443)
	plan := netfilter.NetfilterPlan{
		TableName: "filter",
		Chains: []netfilter.ChainPlan{
			{Name: "KERNLOOM_INPUT", Hook: "input", Policy: "accept"},
		},
		Rules: []netfilter.RulePlan{
			{
				ID:    "abc12300",
				Chain: "KERNLOOM_INPUT",
				Selector: netfilter.Selector{
					SrcIP:   "192.0.2.10",
					Proto:   "tcp",
					DstPort: &port,
				},
				Verdict: netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "deny_src_ip", Render(plan, DefaultRenderOptions()))
}

func TestRender_DenySrcCIDR(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		TableName: "filter",
		Chains: []netfilter.ChainPlan{
			{Name: "KERNLOOM_INPUT", Hook: "input", Policy: "accept"},
		},
		Rules: []netfilter.RulePlan{
			{
				ID:    "abc12300",
				Chain: "KERNLOOM_INPUT",
				Selector: netfilter.Selector{
					SrcCIDR: "10.0.0.0/8",
				},
				Verdict: netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "deny_src_cidr", Render(plan, DefaultRenderOptions()))
}

func TestRender_AllowReturn(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		TableName: "filter",
		Chains: []netfilter.ChainPlan{
			{Name: "KERNLOOM_INPUT", Hook: "input", Policy: "accept"},
		},
		Rules: []netfilter.RulePlan{
			{
				ID:    "abc12300",
				Chain: "KERNLOOM_INPUT",
				Selector: netfilter.Selector{
					SrcCIDR: "192.168.1.0/24",
				},
				Verdict: netfilter.VerdictReturn,
			},
		},
	}
	assertGolden(t, "allow_return", Render(plan, DefaultRenderOptions()))
}

func TestRender_IPSetDeny(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		TableName: "filter",
		Chains: []netfilter.ChainPlan{
			{Name: "KERNLOOM_INPUT", Hook: "input", Policy: "accept"},
		},
		Rules: []netfilter.RulePlan{
			{
				ID:    "abc12300",
				Chain: "KERNLOOM_INPUT",
				Selector: netfilter.Selector{
					SetName: "kernloom_deny4",
					SetDir:  "src",
				},
				Verdict: netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "ipset_deny", Render(plan, DefaultRenderOptions()))
}

func TestRender_MultiDirection(t *testing.T) {
	plan := netfilter.NetfilterPlan{
		TableName: "filter",
		Chains: []netfilter.ChainPlan{
			{Name: "KERNLOOM_INPUT", Hook: "input", Policy: "accept"},
			{Name: "KERNLOOM_FORWARD", Hook: "forward", Policy: "accept"},
		},
		Rules: []netfilter.RulePlan{
			{
				ID:    "abc12300",
				Chain: "KERNLOOM_INPUT",
				Selector: netfilter.Selector{
					SrcIP: "192.0.2.10",
				},
				Verdict: netfilter.VerdictDrop,
			},
		},
	}
	assertGolden(t, "multi_direction", Render(plan, DefaultRenderOptions()))
}

func TestRender_EmptyPlan(t *testing.T) {
	plan := netfilter.NetfilterPlan{TableName: "filter"}
	got := Render(plan, DefaultRenderOptions())
	if !strings.Contains(got, filterTable) || !strings.Contains(got, commitMarker) {
		t.Errorf("empty plan should still produce valid iptables-restore frame, got:\n%s", got)
	}
}

func TestRender_RulePriority(t *testing.T) {
	// Lower priority value = rendered first.
	plan := netfilter.NetfilterPlan{
		TableName: "filter",
		Chains:    []netfilter.ChainPlan{{Name: "KERNLOOM_INPUT", Hook: "input"}},
		Rules: []netfilter.RulePlan{
			{ID: "zzz", Chain: "KERNLOOM_INPUT", Selector: netfilter.Selector{SrcIP: "10.0.0.2"}, Verdict: netfilter.VerdictDrop, Priority: 10},
			{ID: "aaa", Chain: "KERNLOOM_INPUT", Selector: netfilter.Selector{SrcIP: "10.0.0.1"}, Verdict: netfilter.VerdictDrop, Priority: 1},
		},
	}
	got := Render(plan, DefaultRenderOptions())
	pos10_0_0_1 := strings.Index(got, "10.0.0.1")
	pos10_0_0_2 := strings.Index(got, "10.0.0.2")
	if pos10_0_0_1 > pos10_0_0_2 {
		t.Errorf("priority 1 rule should appear before priority 10 rule")
	}
}

func TestRender_StableOutput(t *testing.T) {
	// Same plan rendered twice must produce identical output.
	port := uint16(80)
	plan := netfilter.NetfilterPlan{
		TableName: "filter",
		Chains:    []netfilter.ChainPlan{{Name: "KERNLOOM_INPUT", Hook: "input"}},
		Rules: []netfilter.RulePlan{
			{ID: "r1", Chain: "KERNLOOM_INPUT", Selector: netfilter.Selector{SrcIP: "1.2.3.4", Proto: "tcp", DstPort: &port}, Verdict: netfilter.VerdictDrop},
			{ID: "r2", Chain: "KERNLOOM_INPUT", Selector: netfilter.Selector{SrcCIDR: "10.0.0.0/8"}, Verdict: netfilter.VerdictDrop},
		},
	}
	opts := DefaultRenderOptions()
	first := Render(plan, opts)
	second := Render(plan, opts)
	if first != second {
		t.Errorf("render output is not stable:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

func TestRenderSetOps_Basic(t *testing.T) {
	sets := []netfilter.SetPlan{
		{
			Name:     "kernloom_deny4",
			Family:   "ipv4",
			Timeout:  true,
			Counters: true,
			Elements: []netfilter.SetElement{
				{Value: "192.0.2.10", TTL: 600e9}, // 600s
				{Value: "192.0.2.11"},
			},
		},
	}
	cmds := RenderSetOps(sets)
	if len(cmds) == 0 {
		t.Fatal("expected at least one ipset command")
	}
	// First command must create the set.
	if !strings.Contains(cmds[0], "create kernloom_deny4") {
		t.Errorf("first command should be 'create', got: %s", cmds[0])
	}
	// Must include both elements.
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "192.0.2.10") || !strings.Contains(joined, "192.0.2.11") {
		t.Errorf("expected both IPs in set commands, got:\n%s", joined)
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
		t.Errorf("render output does not match golden file %s\n\nwant:\n%s\ngot:\n%s",
			name, string(want), got)
	}
}
