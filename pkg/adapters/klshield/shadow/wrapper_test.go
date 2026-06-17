// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package klshieldshadow_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/klshield/shadow"
)

func TestSampleToMetrics_BasicMapping(t *testing.T) {
	s := klshieldshadow.TelemetrySample{
		SourceIP:  "10.0.0.1",
		PPS:       1500,
		BPS:       900000,
		SYNRate:   200,
		ScanRate:  5,
		Window:    time.Second,
		Timestamp: time.Now(),
	}
	batch := klshieldshadow.SampleToMetrics(s)
	if batch.Len() != 4 {
		t.Errorf("expected 4 metrics, got %d", batch.Len())
	}
	ids := make(map[string]bool)
	for _, m := range batch.Metrics {
		ids[string(m.ID)] = true
	}
	for _, want := range []string{
		"network.packets_per_second",
		"network.bytes_per_second",
		"network.syn_rate",
		"network.scan_rate",
	} {
		if !ids[want] {
			t.Errorf("expected metric %q in batch", want)
		}
	}
}

func TestSampleToMetrics_ZeroValuesOmitted(t *testing.T) {
	s := klshieldshadow.TelemetrySample{
		SourceIP:  "10.0.0.2",
		PPS:       500,
		BPS:       0, // should be omitted
		SYNRate:   0, // should be omitted
		Window:    time.Second,
		Timestamp: time.Now(),
	}
	batch := klshieldshadow.SampleToMetrics(s)
	if batch.Len() != 1 {
		t.Errorf("expected 1 metric (only PPS), got %d", batch.Len())
	}
}

func TestSampleToMetrics_DropRLRate(t *testing.T) {
	s := klshieldshadow.TelemetrySample{
		SourceIP:   "10.0.0.3",
		DropRLRate: 0.7,
		Window:     time.Second,
		Timestamp:  time.Now(),
	}
	batch := klshieldshadow.SampleToMetrics(s)
	if batch.Len() != 1 {
		t.Errorf("expected 1 metric (drop_rate), got %d", batch.Len())
	}
	if batch.Metrics[0].ID != "network.rate_limit_drop_rate" {
		t.Errorf("unexpected metric ID: %s", batch.Metrics[0].ID)
	}
}

func TestSampleToMetrics_SourceIPPreserved(t *testing.T) {
	s := klshieldshadow.TelemetrySample{
		SourceIP:  "192.168.1.100",
		PPS:       100,
		Window:    time.Second,
		Timestamp: time.Now(),
	}
	batch := klshieldshadow.SampleToMetrics(s)
	if batch.Len() != 1 {
		t.Fatalf("expected 1 metric, got %d", batch.Len())
	}
	if batch.Metrics[0].Subject.Value != "192.168.1.100" {
		t.Errorf("subject not preserved: got %q", batch.Metrics[0].Subject.Value)
	}
}

func TestBatchSamplesToMetrics_MultipleSourceIPs(t *testing.T) {
	samples := []klshieldshadow.TelemetrySample{
		{SourceIP: "10.0.0.1", PPS: 100, Window: time.Second, Timestamp: time.Now()},
		{SourceIP: "10.0.0.2", PPS: 200, BPS: 50000, Window: time.Second, Timestamp: time.Now()},
		{SourceIP: "10.0.0.3", SYNRate: 50, Window: time.Second, Timestamp: time.Now()},
	}
	batch := klshieldshadow.BatchSamplesToMetrics(samples)
	// 1 + 2 + 1 = 4 metrics total
	if batch.Len() != 4 {
		t.Errorf("expected 4 metrics for 3 sources, got %d", batch.Len())
	}
}

func TestBatchSamplesToMetrics_Empty(t *testing.T) {
	batch := klshieldshadow.BatchSamplesToMetrics(nil)
	if batch.Len() != 0 {
		t.Errorf("expected 0 metrics for nil input, got %d", batch.Len())
	}
}
