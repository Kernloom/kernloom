// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package klshieldshadow mirrors existing KLShield telemetry into the generic
// metric pipeline without changing the existing enforcement path.
//
// The wrapper takes per-source telemetry values (pps, bps, syn_rate, scan_rate,
// drop_rl_rate) that the existing shieldheuristic+FSM path already processes,
// and produces equivalent metric.Metric values for the shadow generic pipeline.
//
// IMPORTANT: This wrapper reads from values already computed by the existing path.
// It does NOT touch shieldheuristic, sourcebaseline, FSM, or ActionResolver.
// The existing behavior is preserved byte-for-byte.
package klshieldshadow

import (
	"time"

	"github.com/kernloom/kernloom/pkg/core/metric"
)

// TelemetrySample holds one per-source telemetry reading from KLShield.
// Populated from existing kliq.go candidate data — no new BPF reads.
type TelemetrySample struct {
	// SourceIP is the source IP string (IPv4 or IPv6).
	SourceIP string

	// PPS is packets per second.
	PPS float64

	// BPS is bytes per second.
	BPS float64

	// SYNRate is SYN packets per second.
	SYNRate float64

	// ScanRate is estimated scan rate (port diversity metric).
	ScanRate float64

	// DropRLRate is the rate-limit drop counter rate (drops per second).
	DropRLRate float64

	// Window is the measurement window duration.
	Window time.Duration

	// Timestamp is when the sample was collected.
	Timestamp time.Time
}

// SampleToMetrics converts one TelemetrySample into a metric.Batch.
// Only non-zero values are included to avoid polluting the baseline with
// sources that have no traffic for a given metric.
func SampleToMetrics(s TelemetrySample) metric.Batch {
	now := s.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	window := s.Window
	if window <= 0 {
		window = time.Second
	}
	subj := metric.Subject{Type: "ip", Value: s.SourceIP}
	batch := metric.NewBatch("klshield-shadow", now, now.Add(window))

	if s.PPS > 0 {
		batch.Add(metric.New("network.packets_per_second", "klshield-shadow", metric.ScopeSourceIP, subj, s.PPS, window))
	}
	if s.BPS > 0 {
		batch.Add(metric.New("network.bytes_per_second", "klshield-shadow", metric.ScopeSourceIP, subj, s.BPS, window))
	}
	if s.SYNRate > 0 {
		batch.Add(metric.New("network.syn_rate", "klshield-shadow", metric.ScopeSourceIP, subj, s.SYNRate, window))
	}
	if s.ScanRate > 0 {
		batch.Add(metric.New("network.scan_rate", "klshield-shadow", metric.ScopeSourceIP, subj, s.ScanRate, window))
	}
	if s.DropRLRate > 0 {
		batch.Add(metric.New("network.rate_limit_drop_rate", "klshield-shadow", metric.ScopeSourceIP, subj, s.DropRLRate, window))
	}
	return batch
}

// BatchSamplesToObservations converts multiple telemetry samples into a flat
// metric.Batch suitable for submission to the pipeline runner via
// a synthetic observation path (direct metric submission).
//
// Since KLShield telemetry is already in numeric form, it bypasses the
// Observation→FeatureExtractor step and goes directly into metrics.
func BatchSamplesToMetrics(samples []TelemetrySample) metric.Batch {
	if len(samples) == 0 {
		return metric.NewBatch("klshield-shadow", time.Now(), time.Now())
	}
	from := samples[0].Timestamp
	to := samples[len(samples)-1].Timestamp
	result := metric.NewBatch("klshield-shadow", from, to)
	for _, s := range samples {
		batch := SampleToMetrics(s)
		for _, m := range batch.Metrics {
			result.Add(m)
		}
	}
	return result
}
