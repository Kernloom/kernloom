// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Whitebox tests for edge baseline logic (package sqlite, not sqlite_test).
// Whitebox access is required to call adaptivePeakHalfLife directly and to
// manipulate bl_pps_peak_ts via raw SQL for time-based decay assertions.
package sqlite

import (
	"math"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/core/graph"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func openStoreWB(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func makeEdgeWB(nodeID, srcIP string, port uint16) *graph.Edge {
	return graph.NewEdge(
		nodeID,
		observation.EntityRef{Kind: observation.KindIP, ID: srcIP},
		observation.EntityRef{Kind: observation.KindIP, ID: "10.0.0.1"},
		"tcp", port, graph.DirectionIngress, time.Now(),
	)
}

// setPeakTS sets bl_pps_peak_ts directly so tests can simulate elapsed time
// without real sleeps.
func (s *Store) setPeakTS(key graph.EdgeKey, ts float64) {
	s.db.Exec(`
		UPDATE graph_edges SET bl_pps_peak_ts=?, bl_bps_peak_ts=?
		WHERE node_id=? AND source_kind=? AND source_id=?
		  AND destination_kind=? AND destination_id=?
		  AND protocol=? AND destination_port=? AND direction=?`,
		ts, ts,
		key.NodeID, string(key.SourceKind), key.SourceID,
		string(key.DestinationKind), key.DestinationID,
		key.Protocol, key.DestinationPort, string(key.Direction),
	)
}

func (s *Store) readPeak(key graph.EdgeKey) (pps, bps float64) {
	s.db.QueryRow(`
		SELECT bl_pps_peak, bl_bps_peak FROM graph_edges
		WHERE node_id=? AND source_kind=? AND source_id=?
		  AND destination_kind=? AND destination_id=?
		  AND protocol=? AND destination_port=? AND direction=?`,
		key.NodeID, string(key.SourceKind), key.SourceID,
		string(key.DestinationKind), key.DestinationID,
		key.Protocol, key.DestinationPort, string(key.Direction),
	).Scan(&pps, &bps)
	return
}

// ── adaptivePeakHalfLife unit tests ──────────────────────────────────────────

func TestAdaptivePeakHalfLife_ContinuousTraffic(t *testing.T) {
	configured := 336 * time.Hour
	nowUnix := float64(time.Now().Unix())
	// 7 days of history, active 100% of the time → density = 1.0
	firstSeenNano := int64((nowUnix - 7*24*3600) * 1e9)
	obs := uint64(7 * 24 * 3600) // one observation per second

	got := adaptivePeakHalfLife(configured, obs, firstSeenNano, nowUnix)
	if got != configured {
		t.Errorf("continuous traffic: want %v, got %v", configured, got)
	}
}

func TestAdaptivePeakHalfLife_SparseTraffic(t *testing.T) {
	configured := 336 * time.Hour
	nowUnix := float64(time.Now().Unix())
	// 28 days of history, active only 1% of the time (weekly 2h backup)
	elapsed := 28 * 24 * 3600.0
	firstSeenNano := int64((nowUnix - elapsed) * 1e9)
	obs := uint64(elapsed * 0.01) // 1% duty cycle

	got := adaptivePeakHalfLife(configured, obs, firstSeenNano, nowUnix)

	// Sparse edge must get a substantially longer half-life.
	if got <= configured*2 {
		t.Errorf("sparse traffic: got %v, want > 2× configured (%v)", got, 2*configured)
	}
	// Must not exceed maxMultiplier × configured.
	max := time.Duration(float64(configured) * 10.0)
	if got > max {
		t.Errorf("sparse traffic: got %v, exceeds max %v", got, max)
	}
}

func TestAdaptivePeakHalfLife_WarmupShortHistory(t *testing.T) {
	configured := 336 * time.Hour
	nowUnix := float64(time.Now().Unix())
	// Only 30 minutes of history — below the 1h minimum.
	firstSeenNano := int64((nowUnix - 1800) * 1e9)

	got := adaptivePeakHalfLife(configured, 100, firstSeenNano, nowUnix)
	if got != configured {
		t.Errorf("short history: want %v, got %v", configured, got)
	}
}

func TestAdaptivePeakHalfLife_WarmupFewObs(t *testing.T) {
	configured := 336 * time.Hour
	nowUnix := float64(time.Now().Unix())
	firstSeenNano := int64((nowUnix - 7*24*3600) * 1e9)

	// Fewer than minObsForDensity (20) observations.
	got := adaptivePeakHalfLife(configured, 5, firstSeenNano, nowUnix)
	if got != configured {
		t.Errorf("few obs: want %v, got %v", configured, got)
	}
}

func TestAdaptivePeakHalfLife_MonotonicallyIncreasing(t *testing.T) {
	// More sparse → longer half-life (monotone property).
	configured := 336 * time.Hour
	nowUnix := float64(time.Now().Unix())
	elapsed := 28 * 24 * 3600.0
	firstSeenNano := int64((nowUnix - elapsed) * 1e9)

	duties := []float64{0.90, 0.50, 0.10, 0.02}
	prev := time.Duration(0)
	for _, d := range duties {
		obs := uint64(elapsed * d)
		hl := adaptivePeakHalfLife(configured, obs, firstSeenNano, nowUnix)
		if prev > 0 && hl <= prev {
			t.Errorf("duty %.0f%%: half-life %v not greater than previous %v", d*100, hl, prev)
		}
		prev = hl
	}
}

// ── double-decay regression test ─────────────────────────────────────────────

// TestPeakDecay_NoDoubleDecay is a regression test for the bug where
// bl_pps_peak_ts was only updated when a new peak was set, causing every
// subsequent call to re-decay from the original peak timestamp.  With the fix,
// each call advances bl_pps_peak_ts so that decay accumulates linearly.
//
// Setup: peak set to 100 PPS.  bl_pps_peak_ts is then backdated 24 h via raw
// SQL.  One UpdateEdgeBaselineDecay call with low traffic follows.
//
// Expected: peak ≈ 100 × 0.5^(24/336) ≈ 95.2 (one linear half-life step).
// With the old bug a second call would have applied 2× the elapsed time,
// yielding ≈ 90.7.
func TestPeakDecay_NoDoubleDecay(t *testing.T) {
	s := openStoreWB(t)
	e := makeEdgeWB("node-1", "1.2.3.4", 443)
	e.State = graph.EdgeLearned
	if _, err := s.Upsert(e); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	halfLife := 336 * time.Hour
	// obs count is kept below minObsForDensity so adaptive decay does not apply.
	const alpha = 0.1

	// Call 1: pps=100 sets the peak.
	if err := s.UpdateEdgeBaselineDecay(e.Key(), 100, 0, alpha, alpha, 30, 0, 0, halfLife); err != nil {
		t.Fatalf("set peak: %v", err)
	}

	// Backdate bl_pps_peak_ts by exactly 24 h to simulate elapsed time.
	nowUnix := float64(time.Now().UnixNano()) / 1e9
	s.setPeakTS(e.Key(), nowUnix-24*3600)

	// Call 2: pps=1 (far below peak) — should apply exactly one 24 h decay step.
	if err := s.UpdateEdgeBaselineDecay(e.Key(), 1, 0, alpha, alpha, 30, 0, 0, halfLife); err != nil {
		t.Fatalf("decay call: %v", err)
	}

	peak, _ := s.readPeak(e.Key())
	expected := 100 * math.Pow(0.5, 24.0/336.0) // ≈ 95.2

	// Allow ±2 PPS tolerance for sub-second timing imprecision between the
	// backdating SQL and the UpdateEdgeBaselineDecay nowUnix value.
	if math.Abs(peak-expected) > 2 {
		t.Errorf("peak after one 24h decay step: got %.2f, want ≈%.2f", peak, expected)
	}
}

// TestPeakDecay_SecondCallDoesNotReDecay verifies that a second call immediately
// after the first does not compound the decay.
func TestPeakDecay_SecondCallDoesNotReDecay(t *testing.T) {
	s := openStoreWB(t)
	e := makeEdgeWB("node-1", "2.3.4.5", 80)
	e.State = graph.EdgeLearned
	if _, err := s.Upsert(e); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	halfLife := 336 * time.Hour
	const alpha = 0.1

	// Set peak to 100.
	if err := s.UpdateEdgeBaselineDecay(e.Key(), 100, 0, alpha, alpha, 30, 0, 0, halfLife); err != nil {
		t.Fatalf("set peak: %v", err)
	}

	// Backdate 24 h.
	nowUnix := float64(time.Now().UnixNano()) / 1e9
	s.setPeakTS(e.Key(), nowUnix-24*3600)

	// First decay call.
	if err := s.UpdateEdgeBaselineDecay(e.Key(), 1, 0, alpha, alpha, 30, 0, 0, halfLife); err != nil {
		t.Fatalf("first decay call: %v", err)
	}
	peakAfterFirst, _ := s.readPeak(e.Key())

	// Immediate second call with the same low traffic — elapsed since last
	// ppsPeakTS update is ~0 s, so essentially no additional decay.
	if err := s.UpdateEdgeBaselineDecay(e.Key(), 1, 0, alpha, alpha, 30, 0, 0, halfLife); err != nil {
		t.Fatalf("second decay call: %v", err)
	}
	peakAfterSecond, _ := s.readPeak(e.Key())

	// Second call must not reduce the peak further (elapsed ≈ 0 s).
	if peakAfterSecond < peakAfterFirst-0.5 {
		t.Errorf("second immediate call re-decayed peak: first=%.2f second=%.2f",
			peakAfterFirst, peakAfterSecond)
	}
}

// TestPeakDecay_AdaptiveSlowerForSparse verifies that a sparse edge retains
// its peak better than a continuous edge given the same elapsed time and
// configured half-life.
//
// Observation counts and first_seen_at are set directly via SQL to avoid
// looping millions of times through UpdateEdgeBaselineDecay.
func TestPeakDecay_AdaptiveSlowerForSparse(t *testing.T) {
	s := openStoreWB(t)
	halfLife := 336 * time.Hour
	const alpha = 0.05

	nowUnix := float64(time.Now().UnixNano()) / 1e9
	elapsed28d := 28 * 24 * 3600.0
	firstSeenNano := int64((nowUnix - elapsed28d) * 1e9)

	setupEdge := func(srcIP string, port uint16, obsCount uint64) graph.EdgeKey {
		e := graph.NewEdge("node-1",
			observation.EntityRef{Kind: observation.KindIP, ID: srcIP},
			observation.EntityRef{Kind: observation.KindIP, ID: "10.0.0.1"},
			"tcp", port, graph.DirectionIngress,
			time.Unix(0, firstSeenNano),
		)
		e.State = graph.EdgeLearned
		if _, err := s.Upsert(e); err != nil {
			t.Fatalf("upsert %s: %v", srcIP, err)
		}
		// Set bl_obs and first_seen_at directly so adaptivePeakHalfLife sees
		// the intended density without running millions of loop iterations.
		s.db.Exec(`UPDATE graph_edges SET bl_obs=?, first_seen_at=? WHERE source_id=?`,
			obsCount, firstSeenNano, srcIP)
		// Set peak to 100 and backdate peak timestamp 7 days.
		s.db.Exec(`UPDATE graph_edges SET bl_pps_peak=100 WHERE source_id=?`, srcIP)
		s.setPeakTS(e.Key(), nowUnix-7*24*3600)
		return e.Key()
	}

	// Continuous: obs ≈ elapsed seconds (100% duty cycle).
	contKey := setupEdge("10.10.10.1", 443, uint64(elapsed28d))
	// Sparse: 1% duty cycle (e.g. weekly 2 h backup over 28 days).
	sparseKey := setupEdge("10.10.10.2", 444, uint64(elapsed28d*0.01))

	// One decay call each with pps far below the peak.
	for _, key := range []graph.EdgeKey{contKey, sparseKey} {
		if err := s.UpdateEdgeBaselineDecay(key, 1, 0, alpha, alpha, 30, 0, 0, halfLife); err != nil {
			t.Fatalf("decay: %v", err)
		}
	}

	contPeak, _ := s.readPeak(contKey)
	sparsePeak, _ := s.readPeak(sparseKey)

	if sparsePeak <= contPeak {
		t.Errorf("sparse peak (%.2f) should be higher than continuous peak (%.2f)",
			sparsePeak, contPeak)
	}
	t.Logf("continuous peak after 7d: %.2f / sparse peak: %.2f", contPeak, sparsePeak)
}
