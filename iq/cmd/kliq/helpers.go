// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

// formatSubject returns "kind:id" for log lines.
// IPs show as plain "id" to keep the existing log format; other kinds show "user:xyz" etc.
func formatSubject(s observation.EntityRef) string {
	if s.Kind == "" || s.Kind == observation.KindIP {
		return s.ID
	}
	return string(s.Kind) + ":" + s.ID
}

func isGraphBaselineSignal(t signal.SignalType) bool {
	switch t {
	case signal.SignalGraphEdgeMetricDeviation,
		signal.SignalGraphEdgeMetricPeakExceeds:
		return true
	default:
		return false
	}
}

/* ---------------- misc helpers ---------------- */

// fmtBPS formats a bytes/s trigger for log output.
// Returns "off" when the trigger is disabled (0), otherwise the numeric value.
func fmtBPS(v float64) string {
	if v <= 0 {
		return "off"
	}
	return fmt.Sprintf("%.0f", v)
}

func capChange(old, target, maxRel float64) float64 {
	if maxRel <= 0 {
		return target
	}
	lo := old * (1 - maxRel)
	hi := old * (1 + maxRel)
	if target < lo {
		return lo
	}
	if target > hi {
		return hi
	}
	return target
}

// capChangeDir applies different relative caps depending on direction.
// - If target > old: maxUp is used.
// - If target < old: maxDown is used.
func capChangeDir(old, target, maxUp, maxDown float64) float64 {
	if target >= old {
		return capChange(old, target, maxUp)
	}
	return capChange(old, target, maxDown)
}

/* ---------------- Bootstrap ---------------- */

type bootstrapPolicy struct {
	Active  bool
	Phase   string
	Every   time.Duration
	K       float64
	MaxUp   float64
	MaxDown float64
	Alpha   float64
}

func bootstrapEffective(now time.Time, info bootstrapInfo, window, p1End, p2End time.Duration,
	every1, every2, every3 time.Duration,
	kStart, kFinal float64,
	maxUp1, maxDown1, maxUp2, maxDown2, maxUp3, maxDown3 float64,
	alpha1, alpha2, alpha3 float64,
	steadyEvery time.Duration, steadyK, steadyUp, steadyDown, steadyAlpha float64,
) bootstrapPolicy {
	if !info.Enabled || info.StartedAt.IsZero() || window <= 0 {
		return bootstrapPolicy{Active: false, Phase: "steady", Every: steadyEvery, K: steadyK, MaxUp: steadyUp, MaxDown: steadyDown, Alpha: steadyAlpha}
	}

	// Use observed_seconds (real active runtime) when available.
	// Falls back to wall-clock for older state files that pre-date this field.
	var age time.Duration
	if info.ObservedSeconds > 0 {
		age = time.Duration(info.ObservedSeconds) * time.Second
	} else {
		age = now.Sub(info.StartedAt)
	}
	if age < 0 {
		age = 0
	}
	progress := float64(age) / float64(window)
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}
	k := kStart + (kFinal-kStart)*progress

	if age < p1End {
		return bootstrapPolicy{Active: true, Phase: "bootstrap-1", Every: every1, K: k, MaxUp: maxUp1, MaxDown: maxDown1, Alpha: alpha1}
	}
	if age < p2End {
		return bootstrapPolicy{Active: true, Phase: "bootstrap-2", Every: every2, K: k, MaxUp: maxUp2, MaxDown: maxDown2, Alpha: alpha2}
	}
	if age < window {
		return bootstrapPolicy{Active: true, Phase: "bootstrap-3", Every: every3, K: k, MaxUp: maxUp3, MaxDown: maxDown3, Alpha: alpha3}
	}
	return bootstrapPolicy{Active: false, Phase: "steady", Every: steadyEvery, K: steadyK, MaxUp: steadyUp, MaxDown: steadyDown, Alpha: steadyAlpha}
}

/* ---------------- Utility ---------------- */

// graphStrikesFromScore converts a graph signal score (0-100) to FSM strike credits.
// Higher confidence violations escalate the FSM faster.
func graphStrikesFromScore(score int) int {
	switch {
	case score >= 90:
		return 3
	case score >= 75:
		return 2
	default:
		return 1
	}
}

// sendStrike sends a graphStrikeMsg to ch for an opaque source ID.
// addToCands=true: the source is added to cands so the FSM processes it this tick
// even without source-level adapter telemetry.
// No-op if the source ID is empty or the channel is full.
func sendStrike(ch chan<- graphStrikeMsg, subjectID string, n int, forceBlock, addToCands bool, signalScore int) {
	if subjectID == "" {
		return
	}
	msg := graphStrikeMsg{
		sourceID:    subjectID,
		n:           n,
		signalScore: signalScore,
		forceBlock:  forceBlock,
		addToCands:  addToCands,
	}
	select {
	case ch <- msg:
	default:
		kliqLog.Printf("STRIKE dropped (channel full) subject=%s", subjectID)
	}
}

func minInt(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}
