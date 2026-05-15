// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package shieldheuristic implements the heuristic signal engine for Shield
// telemetry. It converts per-source rate metrics (pps, syn/s, scan/s,
// drop-rl/s) into standardised Signals, decoupling severity computation and
// signal production from the kliq main loop.
//
// Design:
//
//	Observation/Metrics ──► Engine.Evaluate() ──► (fsm.Metrics, []Signal)
//	                                                       │
//	                                              Caller publishes to Bus
//	                                              Caller passes Metrics to FSM
//
// The engine is synchronous and stateless per call. It is safe for concurrent
// use; Config can be replaced atomically at any time (e.g. from autotune).
package shieldheuristic

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/reason"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

// Config holds all tunable parameters for the heuristic engine.
// All fields are safe to replace at runtime via UpdateConfig.
type Config struct {
	// NodeID is included in every emitted signal's attributes.
	NodeID string

	// Trigger thresholds: a metric exactly at its trigger produces a
	// normalised value of 1.0 (score ~50). Zero disables that metric.
	TrigPPS  float64
	TrigSyn  float64
	TrigScan float64
	TrigBPS  float64 // bytes/s trigger; 0 disables BPS scoring

	// Weights for the composite severity score.
	// BPS weight is additive — existing PPS/SYN/scan weights need not sum to 1.
	WPPS  float64
	WSyn  float64
	WScan float64
	WBps  float64 // 0 disables BPS contribution to severity

	// SevCap is the maximum normalised value per component (default 3.0).
	// Normalised values above this are clamped before weighting.
	SevCap float64

	// SignalTTL is the advisory lifetime for emitted signals (default 2m).
	SignalTTL time.Duration
}

// Engine converts per-source flow metrics into Signals and fsm.Metrics.
//
// Typical usage in the KLIQ main loop:
//
//	fsmM, sigs := engine.Evaluate(subject, pps, bps, synRate, scanRate, dropRL)
//	for _, sig := range sigs {
//	    _ = bus.PublishSignal(ctx, sig)
//	}
//	cands = append(cands, metricsFrom(fsmM, ip))
type Engine struct {
	mu  sync.RWMutex
	cfg Config
}

// New creates a new Engine with the given Config.
// Zero values are replaced with safe defaults.
func New(cfg Config) *Engine {
	applyDefaults(&cfg)
	return &Engine{cfg: cfg}
}

// UpdateConfig replaces the engine configuration atomically.
// Safe to call concurrently from the autotune goroutine while Evaluate runs.
func (e *Engine) UpdateConfig(cfg Config) {
	applyDefaults(&cfg)
	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()
}

// Config returns a snapshot of the current configuration.
func (e *Engine) Config() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// EvaluateAt computes severity using explicitly provided trigger thresholds.
// Used by iq-learning+ profiles where per-source baselines raise the effective
// trigger for known high-traffic sources above the global guardrail.
// Pass trigBPS = 0 to disable BPS scoring for this call.
func (e *Engine) EvaluateAt(
	subject observation.EntityRef,
	pps, bps, synRate, scanRate, dropRLRate float64,
	trigPPS, trigSyn, trigScan, trigBPS float64,
) (fsm.Metrics, []signal.Signal) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	cfg.TrigPPS = trigPPS
	cfg.TrigSyn = trigSyn
	cfg.TrigScan = trigScan
	cfg.TrigBPS = trigBPS
	return evaluateWith(cfg, subject, pps, bps, synRate, scanRate, dropRLRate)
}

// Evaluate computes composite severity and emits typed signals for a single
// source during one observation window.
//
// Parameters:
//   - subject: the source entity (typically an IP EntityRef)
//   - pps, bps: packet and byte rates per second
//   - synRate: SYN packet rate per second
//   - scanRate: distinct destination port changes per second
//   - dropRLRate: rate-limit drop rate per second
//
// Returns:
//   - m: fsm.Metrics with Severity filled in; pass directly to fsm.Advance
//   - sigs: signals for metrics that crossed their trigger threshold;
//     empty when all metrics are below threshold (no signal spam)
func (e *Engine) Evaluate(
	subject observation.EntityRef,
	pps, bps, synRate, scanRate, dropRLRate float64,
) (fsm.Metrics, []signal.Signal) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	return evaluateWith(cfg, subject, pps, bps, synRate, scanRate, dropRLRate)
}

// evaluateWith is the shared implementation for Evaluate and EvaluateAt.
func evaluateWith(
	cfg Config,
	subject observation.EntityRef,
	pps, bps, synRate, scanRate, dropRLRate float64,
) (fsm.Metrics, []signal.Signal) {
	sev := fsm.CalcSeverity(
		pps, synRate, scanRate, bps,
		cfg.TrigPPS, cfg.TrigSyn, cfg.TrigScan, cfg.TrigBPS,
		cfg.WPPS, cfg.WSyn, cfg.WScan, cfg.WBps,
		cfg.SevCap,
	)

	m := fsm.Metrics{
		PPS:        pps,
		Bps:        bps,
		SynRate:    synRate,
		ScanRate:   scanRate,
		DropRLRate: dropRLRate,
		Severity:   sev,
	}

	var sigs []signal.Signal

	// source.pps_high — emitted when pps reaches or exceeds trigger.
	if cfg.TrigPPS > 0 && pps >= cfg.TrigPPS {
		sigs = append(sigs, *signal.NewSignal(
			signal.ProducerKLIQ, signal.ScopeLocal,
			signal.SignalPPSHigh, subject,
		).
			SetScore(normToScore(pps/cfg.TrigPPS, cfg.SevCap)).
			SetConfidence(80).
			SetTTL(cfg.SignalTTL).
			AddReasonCode(reason.PPSHigh).
			SetAttribute("pps", fmt.Sprintf("%.1f", pps)).
			SetAttribute("trig_pps", fmt.Sprintf("%.1f", cfg.TrigPPS)).
			SetAttribute("severity", fmt.Sprintf("%.3f", sev)).
			SetAttribute("node_id", cfg.NodeID))
	}

	// source.syn_rate_high — emitted when SYN/s reaches or exceeds trigger.
	if cfg.TrigSyn > 0 && synRate >= cfg.TrigSyn {
		sigs = append(sigs, *signal.NewSignal(
			signal.ProducerKLIQ, signal.ScopeLocal,
			signal.SignalSYNRateHigh, subject,
		).
			SetScore(normToScore(synRate/cfg.TrigSyn, cfg.SevCap)).
			SetConfidence(85).
			SetTTL(cfg.SignalTTL).
			AddReasonCode(reason.SYNRateHigh).
			SetAttribute("syn_rate", fmt.Sprintf("%.1f", synRate)).
			SetAttribute("trig_syn", fmt.Sprintf("%.1f", cfg.TrigSyn)).
			SetAttribute("severity", fmt.Sprintf("%.3f", sev)).
			SetAttribute("node_id", cfg.NodeID))
	}

	// source.bps_high — emitted when bytes/s reaches or exceeds trigger.
	// Catches large-packet floods and slow exfiltration that stay under PPS radar.
	if cfg.TrigBPS > 0 && cfg.WBps > 0 && bps >= cfg.TrigBPS {
		sigs = append(sigs, *signal.NewSignal(
			signal.ProducerKLIQ, signal.ScopeLocal,
			signal.SignalBPSHigh, subject,
		).
			SetScore(normToScore(bps/cfg.TrigBPS, cfg.SevCap)).
			SetConfidence(75).
			SetTTL(cfg.SignalTTL).
			AddReasonCode(reason.BPSHigh).
			SetAttribute("bps", fmt.Sprintf("%.0f", bps)).
			SetAttribute("trig_bps", fmt.Sprintf("%.0f", cfg.TrigBPS)).
			SetAttribute("severity", fmt.Sprintf("%.3f", sev)).
			SetAttribute("node_id", cfg.NodeID))
	}

	// source.scan_suspected — emitted when port diversity reaches trigger.
	if cfg.TrigScan > 0 && scanRate >= cfg.TrigScan {
		sigs = append(sigs, *signal.NewSignal(
			signal.ProducerKLIQ, signal.ScopeLocal,
			signal.SignalScanSuspected, subject,
		).
			SetScore(normToScore(scanRate/cfg.TrigScan, cfg.SevCap)).
			SetConfidence(75).
			SetTTL(cfg.SignalTTL).
			AddReasonCode(reason.ScanRateHigh).
			SetAttribute("scan_rate", fmt.Sprintf("%.1f", scanRate)).
			SetAttribute("trig_scan", fmt.Sprintf("%.1f", cfg.TrigScan)).
			SetAttribute("severity", fmt.Sprintf("%.3f", sev)).
			SetAttribute("node_id", cfg.NodeID))
	}

	// source.rate_limit_drops_sustained — emitted whenever RL drops are observed.
	// Confidence is high because drops are a direct eBPF counter, not inferred.
	if dropRLRate > 0 {
		compositeScore := int(math.Min(sev/cfg.SevCap*100, 100))
		sigs = append(sigs, *signal.NewSignal(
			signal.ProducerKLIQ, signal.ScopeLocal,
			signal.SignalRateLimitDropsSustained, subject,
		).
			SetScore(clamp(compositeScore+15, 0, 100)).
			SetConfidence(90).
			SetTTL(cfg.SignalTTL).
			AddReasonCode(reason.RateLimitDropsSustained).
			SetAttribute("drop_rl_rate", fmt.Sprintf("%.2f", dropRLRate)).
			SetAttribute("severity", fmt.Sprintf("%.3f", sev)).
			SetAttribute("node_id", cfg.NodeID))
	}

	return m, sigs
}

/* ---------------- helpers ------------------------------------------------ */

// normToScore maps a normalised metric value to a signal score 0–100.
//
//	norm = metric / trigger  (1.0 = exactly at threshold)
//	score = 50 at threshold, 100 at SevCap, linear in between.
func normToScore(norm, cap float64) int {
	if cap <= 1 {
		cap = 3.0
	}
	// Linear: 50 at norm=1, 100 at norm=cap.
	score := 50.0 + (norm-1.0)/(cap-1.0)*50.0
	return clamp(int(score), 0, 100)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func applyDefaults(cfg *Config) {
	if cfg.SevCap <= 0 {
		cfg.SevCap = 3.0
	}
	if cfg.SignalTTL <= 0 {
		cfg.SignalTTL = 2 * time.Minute
	}
}
