// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package netfilter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/kernloom/kernloom/pkg/core/fsm"
)

type captureBackend struct {
	plans []NetfilterPlan
}

func (b *captureBackend) Apply(_ context.Context, plan NetfilterPlan) error {
	b.plans = append(b.plans, plan)
	return nil
}

func (b *captureBackend) Cleanup(context.Context) error { return nil }

func TestBuildPlanAppliesRulesToConfiguredDirections(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Directions.Forward = true
	cfg.Safety.ManagementAllowlist = []string{"192.168.1.0/24"}
	cfg.Enforcement.SoftRatePPS = 222

	backend := &captureBackend{}
	adapter := New(cfg)
	adapter.SetBackend(ProbeResult{
		Selected: BackendNFTables,
		NFTables: NFTablesProbe{
			Available: true,
			Meters:    true,
		},
	}, backend)
	if err := adapter.Init(context.Background(), nil); err != nil {
		t.Fatalf("init adapter: %v", err)
	}

	adapter.NotifyTransition4([4]byte{10, 0, 0, 1}, fsm.LevelObserve, fsm.LevelSoft, 0)
	if len(backend.plans) != 1 {
		t.Fatalf("expected one applied plan, got %d", len(backend.plans))
	}
	plan := backend.plans[0]
	if len(plan.Chains) != 2 {
		t.Fatalf("expected input and forward chains, got %#v", plan.Chains)
	}

	managementByChain := map[string]bool{}
	rateByChain := map[string]uint64{}
	for _, rule := range plan.Rules {
		if rule.Verdict == VerdictReturn && rule.Selector.SrcCIDR == "192.168.1.0/24" {
			managementByChain[rule.Chain] = true
		}
		if rule.Verdict == VerdictRateLimit && rule.Selector.SrcIP == "10.0.0.1" {
			if rule.RateLimit == nil {
				t.Fatalf("rate-limit rule missing params: %#v", rule)
			}
			rateByChain[rule.Chain] = rule.RateLimit.RatePPS
		}
	}
	for _, chain := range []string{"KERNLOOM_INPUT", "KERNLOOM_FORWARD"} {
		if !managementByChain[chain] {
			t.Fatalf("missing management allowlist rule for %s in %#v", chain, plan.Rules)
		}
		if rateByChain[chain] != 222 {
			t.Fatalf("expected soft rate 222 for %s, got %d", chain, rateByChain[chain])
		}
	}
}

func TestLoadAndApplyPDPAdapterSpec(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pdp.yaml")
	raw := []byte(`
apiVersion: kernloom.io/v1alpha1
kind: PDPConfig
spec:
  adapters:
    netfilter:
      backend: iptables-legacy
      directions:
        input: false
        forward: true
      rate_limit:
        soft_rate_pps: 200
        hard_rate_pps: 50
      observation:
        conntrack_snapshot: false
        conntrack_poll_interval: "10s"
      safety:
        management_allowlist:
          - 192.168.1.0/24
`)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	spec, ok, err := LoadPDPAdapterSpec(path)
	if err != nil {
		t.Fatalf("load adapter spec: %v", err)
	}
	if !ok {
		t.Fatal("expected netfilter adapter spec")
	}

	cfg, err := ApplyAdapterSpec(DefaultConfig(), spec)
	if err != nil {
		t.Fatalf("apply adapter spec: %v", err)
	}
	if cfg.Backend != BackendIPTablesLegacy {
		t.Fatalf("expected iptables-legacy backend, got %q", cfg.Backend)
	}
	if cfg.Directions.Input || !cfg.Directions.Forward {
		t.Fatalf("directions not applied: %#v", cfg.Directions)
	}
	if cfg.Enforcement.SoftRatePPS != 200 || cfg.Enforcement.HardRatePPS != 50 {
		t.Fatalf("rate limits not applied: %#v", cfg.Enforcement)
	}
	if cfg.Observation.ConntrackSnapshot {
		t.Fatal("conntrack snapshot should be disabled")
	}
	if cfg.Observation.ConntrackPollInterval.String() != "10s" {
		t.Fatalf("poll interval not applied: %s", cfg.Observation.ConntrackPollInterval)
	}
	if len(cfg.Safety.ManagementAllowlist) != 1 || cfg.Safety.ManagementAllowlist[0] != "192.168.1.0/24" {
		t.Fatalf("management allowlist not applied: %#v", cfg.Safety.ManagementAllowlist)
	}
}
