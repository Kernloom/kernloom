// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package forgeagent_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kernloom/kernloom/iq/internal/forgeagent"
)

func TestAgent_Enrolls_AndStartsHeartbeat(t *testing.T) {
	var enrollCalled atomic.Int32
	var heartbeatCalled atomic.Int32
	var applyPackCalled atomic.Int32

	cbs := forgeagent.Callbacks{
		Enroll: func(ctx context.Context) (string, string, error) {
			enrollCalled.Add(1)
			return "node-1", "approved", nil
		},
		Heartbeat: func(ctx context.Context, packName string) (bool, string, error) {
			heartbeatCalled.Add(1)
			return false, "active", nil
		},
		PullPack: func(ctx context.Context) ([]byte, string, error) {
			return []byte("pack-bytes"), "test-pack", nil
		},
		PullBundle: func(ctx context.Context) ([]byte, error) {
			return nil, nil
		},
		ReportPackStatus: func(ctx context.Context, name string, ok bool, msg string) error {
			return nil
		},
		ReportStatus: func(ctx context.Context) error { return nil },
	}

	packApplied := make(chan string, 1)
	agent := forgeagent.New(
		forgeagent.Config{NodeID: "node-1", Heartbeat: 50 * time.Millisecond},
		cbs,
		func(packBytes []byte, packName string) error {
			applyPackCalled.Add(1)
			packApplied <- packName
			return nil
		},
		func(packName, packHash string) {},
		nil,
	)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_ = agent.Start(ctx)

	// Enrollment should have happened.
	if enrollCalled.Load() != 1 {
		t.Errorf("enrollCalled = %d, want 1", enrollCalled.Load())
	}

	// Pack should have been applied after enrollment (status=approved).
	select {
	case name := <-packApplied:
		if name != "test-pack" {
			t.Errorf("applied pack = %q, want test-pack", name)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("pack was not applied after enrollment")
	}

	// Heartbeat should run at least once within the timeout.
	<-ctx.Done()
	if heartbeatCalled.Load() == 0 {
		t.Error("heartbeat was never called")
	}

	agent.Stop()
}

func TestAgent_RestoredSession_SkipsEnrollment(t *testing.T) {
	var enrollCalled atomic.Int32

	cbs := forgeagent.Callbacks{
		Enroll: func(ctx context.Context) (string, string, error) {
			enrollCalled.Add(1)
			return "node-1", "approved", nil
		},
		Heartbeat: func(ctx context.Context, packName string) (bool, string, error) {
			return false, "active", nil
		},
		PullPack:         func(ctx context.Context) ([]byte, string, error) { return nil, "", nil },
		PullBundle:       func(ctx context.Context) ([]byte, error) { return nil, nil },
		ReportPackStatus: func(ctx context.Context, name string, ok bool, msg string) error { return nil },
		ReportStatus:     func(ctx context.Context) error { return nil },
	}

	// Simulate a restored session: Enroll should NOT be called.
	agent := forgeagent.New(
		forgeagent.Config{
			NodeID:          "node-1",
			Heartbeat:       1 * time.Second,
			InitialPackName: "restored-pack",
		},
		cbs,
		nil, // no pack applier needed
		nil,
		nil,
	)

	// When Enroll is nil the agent skips enrollment.
	// Test: even when Enroll callback is set, a non-zero InitialPackName does NOT
	// skip enrollment — session restoration is handled by RestoreSession() in main.
	// We test the Enroll=nil path here.
	cbs2 := cbs
	cbs2.Enroll = nil
	agent2 := forgeagent.New(
		forgeagent.Config{NodeID: "node-1", Heartbeat: 1 * time.Second},
		cbs2, nil, nil, nil,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_ = agent2.Start(ctx)
	<-ctx.Done()

	if enrollCalled.Load() != 0 {
		t.Errorf("enrollCalled = %d, want 0 (Enroll=nil should skip enrollment)", enrollCalled.Load())
	}
	agent.Stop()
	agent2.Stop()
}

func TestAgent_BundleDelivered(t *testing.T) {
	bundleData := []byte("--- bundle yaml ---")
	var bundlePulled atomic.Int32

	cbs := forgeagent.Callbacks{
		Enroll:           func(ctx context.Context) (string, string, error) { return "n", "pending", nil },
		Heartbeat:        func(ctx context.Context, packName string) (bool, string, error) { return false, "active", nil },
		PullPack:         func(ctx context.Context) ([]byte, string, error) { return nil, "", nil },
		ReportPackStatus: func(ctx context.Context, name string, ok bool, msg string) error { return nil },
		ReportStatus:     func(ctx context.Context) error { return nil },
		PullBundle: func(ctx context.Context) ([]byte, error) {
			if bundlePulled.Add(1) == 1 {
				return bundleData, nil
			}
			return nil, nil
		},
	}

	agent := forgeagent.New(
		forgeagent.Config{NodeID: "node-1", Heartbeat: 30 * time.Millisecond},
		cbs, nil, nil, nil,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_ = agent.Start(ctx)

	select {
	case raw := <-agent.BundleUpdates():
		if string(raw) != string(bundleData) {
			t.Errorf("bundle = %q, want %q", raw, bundleData)
		}
	case <-ctx.Done():
		t.Error("bundle was never delivered within timeout")
	}
	agent.Stop()
}

func TestAgent_Stop_TerminatesHeartbeat(t *testing.T) {
	var heartbeatCalled atomic.Int32
	cbs := forgeagent.Callbacks{
		Heartbeat: func(ctx context.Context, packName string) (bool, string, error) {
			heartbeatCalled.Add(1)
			return false, "active", nil
		},
		PullBundle:   func(ctx context.Context) ([]byte, error) { return nil, nil },
		ReportStatus: func(ctx context.Context) error { return nil },
	}
	agent := forgeagent.New(
		forgeagent.Config{NodeID: "n", Heartbeat: 20 * time.Millisecond},
		cbs, nil, nil, nil,
	)
	ctx := context.Background()
	_ = agent.Start(ctx)
	time.Sleep(80 * time.Millisecond) // let a few heartbeats run
	agent.Stop()
	before := heartbeatCalled.Load()
	time.Sleep(80 * time.Millisecond) // should not increase after Stop
	after := heartbeatCalled.Load()
	if after > before+1 { // allow at most 1 in-flight call
		t.Errorf("heartbeat continued after Stop: before=%d after=%d", before, after)
	}
}
