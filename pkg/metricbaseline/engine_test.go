// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package metricbaseline_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/metric"
	"github.com/kernloom/kernloom/pkg/metricbaseline"
)

// makeMetric is a test helper.
func makeMetric(id metric.MetricID, subject, value string, f float64) metric.Metric {
	_ = value
	return metric.New(id, "test", metric.ScopeSourceIP,
		metric.Subject{Type: "ip", Value: subject}, f, time.Second)
}

func opts(suspicious bool) metricbaseline.UpdateOptions {
	return metricbaseline.UpdateOptions{Suspicious: suspicious}
}

// ── Golden test 1: Normal learning ───────────────────────────────────────────

func TestGolden_NormalLearning(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.MinCount = 10 // lower threshold for test speed
	e := metricbaseline.New(cfg)

	m := makeMetric("http.auth_fail_rate", "10.0.0.1", "", 0.03)

	// Feed 100 values around 0.03 — confidence should increase.
	for i := 0; i < 100; i++ {
		e.Update(m, opts(false))
	}

	r := e.Update(m, opts(false))

	if !r.Promoted {
		t.Error("profile should be promoted after 100 updates with MinCount=10")
	}
	if r.Confidence <= 0.3 {
		t.Errorf("confidence should be > 0.3 after 100 updates, got %.3f", r.Confidence)
	}
	// Expected should be near 0.03
	if r.Expected < 0.025 || r.Expected > 0.035 {
		t.Errorf("Expected (EWMA) should be near 0.03, got %.4f", r.Expected)
	}
}

// ── Golden test 2: Spike scoring ─────────────────────────────────────────────

func TestGolden_SpikeScoring(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.MinCount = 10
	e := metricbaseline.New(cfg)

	normal := makeMetric("http.auth_fail_rate", "10.0.0.2", "", 0.03)
	spike := makeMetric("http.auth_fail_rate", "10.0.0.2", "", 0.42)

	// Establish baseline.
	for i := 0; i < 60; i++ {
		e.Update(normal, opts(false))
	}

	// Score a spike.
	r := e.Update(spike, opts(false))

	if r.DeviationScore < 50 {
		t.Errorf("DeviationScore should be high for spike 0.42 vs baseline 0.03, got %.1f", r.DeviationScore)
	}
	t.Logf("spike score=%.1f expected=%.4f sigma=%.4f", r.DeviationScore, r.Expected, r.Sigma)
}

// ── Golden test 3: Anti-poisoning ─────────────────────────────────────────────

func TestGolden_AntiPoisoning(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.MinCount = 10
	e := metricbaseline.New(cfg)

	normal := makeMetric("http.auth_fail_rate", "10.0.0.3", "", 0.03)
	attack := makeMetric("http.auth_fail_rate", "10.0.0.3", "", 0.42)

	// Establish a stable baseline.
	for i := 0; i < 80; i++ {
		e.Update(normal, opts(false))
	}
	baseline, _ := e.Get(normal)
	originalEWMA := baseline.EWMA

	// Feed attack values with Suspicious=true — EWMA must not shift significantly.
	for i := 0; i < 20; i++ {
		r := e.Update(attack, opts(true))
		if !r.Suspicious {
			t.Error("Result.Suspicious should be true")
		}
	}

	after, _ := e.Get(normal)

	// EWMA must stay close to the original value.
	shift := after.EWMA - originalEWMA
	if shift > 0.005 {
		t.Errorf("EWMA shifted by %.5f after suspicious updates; should be ≤ 0.005", shift)
	}
	t.Logf("EWMA before=%.5f after=%.5f shift=%.6f", originalEWMA, after.EWMA, shift)
}

// ── Golden test 4: Cardinality control — selected_labels=[] ──────────────────

func TestGolden_CardinalityControl_NoLabels(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.SelectedLabels = nil // empty = ignore labels (default)
	e := metricbaseline.New(cfg)

	// Same metric ID+subject but different label values.
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		m := metric.New("http.rps", "nginx", metric.ScopeSourceIP,
			metric.Subject{Type: "ip", Value: "1.2.3.4"}, 10.0, time.Second).
			WithLabel("host", host)
		e.Update(m, opts(false))
	}

	// All three should share one profile (label ignored).
	if e.Len() != 1 {
		t.Errorf("with empty SelectedLabels, expected 1 profile, got %d", e.Len())
	}
}

func TestGolden_CardinalityControl_WithLabels(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.SelectedLabels = []string{"host"}
	e := metricbaseline.New(cfg)

	hosts := []string{"a.example.com", "b.example.com", "c.example.com"}
	for _, host := range hosts {
		m := metric.New("http.rps", "nginx", metric.ScopeSourceIP,
			metric.Subject{Type: "ip", Value: "1.2.3.4"}, 10.0, time.Second).
			WithLabel("host", host)
		e.Update(m, opts(false))
	}

	// Each host gets its own profile.
	if e.Len() != len(hosts) {
		t.Errorf("with SelectedLabels=[host], expected %d profiles, got %d", len(hosts), e.Len())
	}
}

// ── Golden test 5: TTL eviction ───────────────────────────────────────────────

func TestGolden_TTLEviction(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.ProfileTTL = 10 * time.Millisecond
	e := metricbaseline.New(cfg)

	for i := 0; i < 5; i++ {
		m := metric.New("network.pps", "shield", metric.ScopeSourceIP,
			metric.Subject{Type: "ip", Value: fmt.Sprintf("10.0.0.%d", i)}, 100.0, time.Second)
		e.Update(m, opts(false))
	}

	if e.Len() != 5 {
		t.Fatalf("expected 5 profiles before eviction, got %d", e.Len())
	}

	time.Sleep(20 * time.Millisecond) // wait for TTL to expire
	removed := e.EvictByTTL()

	if removed != 5 {
		t.Errorf("expected 5 profiles evicted, got %d", removed)
	}
	if e.Len() != 0 {
		t.Errorf("expected 0 profiles after eviction, got %d", e.Len())
	}
}

// ── Golden test 6: Max profile eviction ──────────────────────────────────────

func TestGolden_MaxProfileEviction(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.MaxProfiles = 5
	e := metricbaseline.New(cfg)

	// Insert 6 profiles — the 6th triggers eviction of the lowest-confidence one.
	for i := 0; i < 6; i++ {
		m := metric.New("network.pps", "shield", metric.ScopeSourceIP,
			metric.Subject{Type: "ip", Value: fmt.Sprintf("10.0.1.%d", i)}, 10.0, time.Second)
		// Give profiles different amounts of data so confidence varies.
		updates := i + 1
		for u := 0; u < updates; u++ {
			e.Update(m, opts(false))
		}
	}

	if e.Len() > cfg.MaxProfiles {
		t.Errorf("profile count %d exceeds MaxProfiles %d", e.Len(), cfg.MaxProfiles)
	}
}

// ── Unit tests ────────────────────────────────────────────────────────────────

func TestUnpromoted_ScoreIsZero(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.MinCount = 100 // high threshold — won't promote in this test
	e := metricbaseline.New(cfg)

	m := makeMetric("network.pps", "10.0.0.9", "", 9999)
	r := e.Update(m, opts(false))

	if r.Promoted {
		t.Error("should not be promoted with only one update and MinCount=100")
	}
	if r.DeviationScore != 0 {
		t.Errorf("unpromoted profile should have score=0, got %.1f", r.DeviationScore)
	}
}

func TestMultipleMetricIDs(t *testing.T) {
	e := metricbaseline.New(metricbaseline.DefaultConfig())
	subj := metric.Subject{Type: "ip", Value: "10.0.0.5"}

	for _, id := range []metric.MetricID{"network.pps", "network.syn_rate", "http.rps"} {
		m := metric.New(id, "test", metric.ScopeSourceIP, subj, 10.0, time.Second)
		e.Update(m, opts(false))
	}

	if e.Len() != 3 {
		t.Errorf("expected 3 profiles for 3 different metric IDs, got %d", e.Len())
	}
}

func TestGet_UnknownMetric(t *testing.T) {
	e := metricbaseline.New(metricbaseline.DefaultConfig())
	m := makeMetric("nonexistent.metric", "1.2.3.4", "", 1.0)
	_, ok := e.Get(m)
	if ok {
		t.Error("Get on unknown metric should return false")
	}
}

func TestSuspiciousCount(t *testing.T) {
	cfg := metricbaseline.DefaultConfig()
	cfg.MinCount = 5
	e := metricbaseline.New(cfg)

	m := makeMetric("http.auth_fail_rate", "10.0.0.8", "", 0.03)

	for i := 0; i < 10; i++ {
		e.Update(m, opts(false))
	}
	for i := 0; i < 3; i++ {
		r := e.Update(makeMetric("http.auth_fail_rate", "10.0.0.8", "", 0.99), opts(true))
		if r.Learned {
			t.Error("Suspicious update must not set Learned=true")
		}
	}

	p, _ := e.Get(m)
	if p.SuspiciousCount != 3 {
		t.Errorf("SuspiciousCount: got %d, want 3", p.SuspiciousCount)
	}
}
