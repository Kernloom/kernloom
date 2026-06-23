// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package klshieldruntime

import (
	"testing"
	"time"
)

func TestCalculateRates(t *testing.T) {
	now := time.Unix(100, 0)
	prev := counterSnapshot{Pkts: 100, Bytes: 1000, Syn: 10, DportChanges: 2, Pass: 90, DropAllow: 1, DropDeny: 2, DropRL: 1, LastWall: now}
	curr := counterSnapshot{Pkts: 160, Bytes: 2200, Syn: 16, DportChanges: 5, Pass: 140, DropAllow: 3, DropDeny: 8, DropRL: 3, LastWall: now.Add(2 * time.Second)}

	got, ok := calculateRates(prev, curr, time.Second)
	if !ok {
		t.Fatal("expected valid sample")
	}
	if got.PPS != 30 || got.BPS != 600 || got.SynRate != 3 || got.ScanRate != 1.5 ||
		got.PassRate != 25 || got.DropAllowRate != 1 || got.DropDenyRate != 3 ||
		got.DropRLRate != 1 || got.DropTotalRate != 5 {
		t.Fatalf("unexpected rates: %+v", got)
	}
}

func TestCalculateRatesRejectsCounterReset(t *testing.T) {
	now := time.Unix(100, 0)
	prev := counterSnapshot{Pkts: 100, Bytes: 1000, LastWall: now}
	curr := counterSnapshot{Pkts: 99, Bytes: 1200, LastWall: now.Add(time.Second)}

	if _, ok := calculateRates(prev, curr, time.Second); ok {
		t.Fatal("expected counter reset to be rejected")
	}
}

func TestCalculateRatesUsesFallbackInterval(t *testing.T) {
	now := time.Unix(100, 0)
	prev := counterSnapshot{Pkts: 100, LastWall: now}
	curr := counterSnapshot{Pkts: 130, LastWall: now}

	got, ok := calculateRates(prev, curr, 3*time.Second)
	if !ok {
		t.Fatal("expected valid sample")
	}
	if got.PPS != 10 {
		t.Fatalf("PPS = %v, want 10", got.PPS)
	}
}
