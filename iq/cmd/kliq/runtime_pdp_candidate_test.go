// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"log"
	"testing"
	"time"

	contracts "github.com/kernloom/kernloom-contracts"
	"github.com/kernloom/kernloom/iq/internal/actionbroker"
	"github.com/kernloom/kernloom/iq/internal/actions"
	"github.com/kernloom/kernloom/iq/internal/sourcefilters"
	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
	sstore "github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

func TestRuntimePDPActiveOwnsNetworkCandidateAction(t *testing.T) {
	now := time.Date(2026, 6, 19, 13, 0, 0, 0, time.UTC)
	c := newTestCfg("")
	c.RuntimePDPMode = string(PDPModeActive)
	c.TrigPPS = 1000
	c.TrigSyn = 100
	c.TrigScan = 10

	runner := newShadowPDPRunner("node-test", log.New(testWriter{t}, "", 0))
	runner.SetMode(PDPModeActive, nil)
	if err := runner.UpdatePack(runtimeCandidateTestPack(
		"metrics.network.packets_per_second > baseline.network.packets_per_second * 2.0 && fsm.proposed_level == 'block'",
		"enforce.traffic.rate_limit",
		"hard",
	)); err != nil {
		t.Fatalf("update runtime pack: %v", err)
	}

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	m := metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: "10.0.0.1",
			Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.1"},
		},
		Score: 99,
		Signals: map[string]float64{
			adapterruntime.MetricNetworkPacketsPerSecond: 5000,
			adapterruntime.MetricNetworkSynRate:          500,
		},
	}
	state := processCandidateRuntimePDP(
		m,
		fsm.State{},
		now,
		c,
		sourcefilters.NewWhitelist(""),
		sourcefilters.NewFeedback(""),
		c.buildPolicyResolver(),
		executor,
		nil,
		false,
		runner,
		"node-test",
	)

	if state.Level != fsm.LevelHard {
		t.Fatalf("runtime PDP should choose hard, got %s", state.Level)
	}
	if len(pep.levels) != 1 || pep.levels[0] != fsm.LevelHard {
		t.Fatalf("PEP transitions = %#v, want one hard transition", pep.levels)
	}
}

func TestRuntimePDPShadowObservesNetworkCandidateOnly(t *testing.T) {
	now := time.Date(2026, 6, 19, 13, 5, 0, 0, time.UTC)
	c := newTestCfg("")
	c.RuntimePDPMode = string(PDPModeShadow)
	c.TrigPPS = 1000

	runner := newShadowPDPRunner("node-test", log.New(testWriter{t}, "", 0))
	runner.SetMode(PDPModeShadow, nil)
	if err := runner.UpdatePack(runtimeCandidateTestPack(
		"fsm.proposed_level == 'block'",
		"enforce.access.deny",
		"block",
	)); err != nil {
		t.Fatalf("update runtime pack: %v", err)
	}

	pep := &recordingSourcePEP{}
	executor, cleanup := newRuntimePDPTestExecutor(t, pep, c)
	defer cleanup()

	state := processCandidateRuntimePDP(
		highSeverityRuntimeMetrics(),
		fsm.State{},
		now,
		c,
		sourcefilters.NewWhitelist(""),
		sourcefilters.NewFeedback(""),
		c.buildPolicyResolver(),
		executor,
		nil,
		false,
		runner,
		"node-test",
	)

	if state.Level != fsm.LevelObserve {
		t.Fatalf("shadow mode must keep actual state observe, got %s", state.Level)
	}
	if state.Strikes == 0 {
		t.Fatal("shadow mode should still update FSM intent facts")
	}
	if len(pep.levels) != 0 {
		t.Fatalf("shadow mode must not call PEP, got transitions %#v", pep.levels)
	}
}

func runtimeCandidateTestPack(expr, capability, level string) contracts.RuntimePolicyPack {
	return contracts.RuntimePolicyPack{
		TypeMeta: contracts.TypeMeta{
			APIVersion: contracts.RuntimeAPIVersion,
			Kind:       contracts.KindRuntimePolicyPack,
		},
		Metadata: contracts.ObjectMeta{Name: "runtime-candidate-test"},
		Spec: contracts.RuntimePolicyPackSpec{
			DefaultEffect: "deny",
			Rules: []contracts.RuntimePolicyRule{{
				ID:   "candidate-rule",
				When: expr,
				Then: contracts.RuntimeActionSpec{
					Capability: capability,
					Level:      level,
					TTL:        contracts.NewDuration(time.Minute),
				},
				ReasonCodes: []string{"candidate_policy"},
			}},
		},
	}
}

func highSeverityRuntimeMetrics() metrics {
	return metrics{
		Target: adapterruntime.SourceTarget{
			SourceID: "10.0.0.1",
			Subject:  observation.EntityRef{Kind: "ip", ID: "10.0.0.1"},
		},
		Score: 99,
		Signals: map[string]float64{
			adapterruntime.MetricNetworkPacketsPerSecond: 5000,
			adapterruntime.MetricNetworkSynRate:          500,
		},
	}
}

func newRuntimePDPTestExecutor(t *testing.T, pep *recordingSourcePEP, c cfg) (*brokeredActionExecutor, func()) {
	t.Helper()
	store, err := sstore.Open(sstore.DefaultConfig(":memory:"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	sourceExecutor := actions.NewSourceActionExecutor(pep)
	brokerPEP := newBrokeredSourcePEP(sourceExecutor, func() adapterruntime.EnforcementParams {
		return c.toPEPParams()
	})
	broker, err := actionbroker.New(actionbroker.Config{
		NodeID: "node-test",
		Store:  store,
		PEP:    brokerPEP,
		Now:    func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		store.Close()
		t.Fatalf("new broker: %v", err)
	}
	return newBrokeredActionExecutor(sourceExecutor, broker, brokerPEP, nil, nil, store, "node-test"), func() {
		store.Close()
	}
}

type recordingSourcePEP struct {
	levels []fsm.Level
}

func (p *recordingSourcePEP) TransitionSource(_ adapterruntime.SourceTarget, st fsm.State, target fsm.Level, now time.Time, params adapterruntime.EnforcementParams) (fsm.State, error) {
	p.levels = append(p.levels, target)
	st.Level = target
	switch target {
	case fsm.LevelSoft:
		st.ExpiresAt = now.Add(params.SoftTTL)
	case fsm.LevelHard:
		st.ExpiresAt = now.Add(params.HardTTL)
	case fsm.LevelBlock:
		st.ExpiresAt = now.Add(params.BlockTTL)
	default:
		st.ExpiresAt = time.Time{}
	}
	return st, nil
}

type testWriter struct {
	t *testing.T
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

var _ adapterruntime.SourcePEP = (*recordingSourcePEP)(nil)
