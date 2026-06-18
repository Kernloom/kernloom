// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package forgeagent encapsulates the Forge enrollment and heartbeat lifecycle.
//
// It handles:
//   - initial enrollment (one-time at startup)
//   - periodic heartbeat loop
//   - RuntimeBundle polling and delivery via BundleUpdates() channel
//   - LocalPolicyPack polling and callback on update
//   - state persistence via callbacks
//
// The agent does NOT apply bundles or packs itself. It delivers raw bytes and
// calls back into the caller so that bundle/pack application logic stays in
// the main loop (single writer to kliq runtime state, no locking required).
//
// All Forge client calls are passed as callbacks. This keeps the agent
// independent of the concrete forgeClient type and its dependencies.
package forgeagent

import (
	"context"
	"log"
	"sync"
	"time"
)

// Callbacks groups all Forge API operations as closures.
// The main package creates these by capturing *forgeClient.
type Callbacks struct {
	// Enroll performs initial node enrollment.
	// Returns nodeID, status ("approved"/"pending"/"rejected"), error.
	Enroll func(ctx context.Context) (nodeID, status string, err error)

	// Heartbeat sends a periodic heartbeat and returns whether a pack update
	// is available and the current node status string.
	Heartbeat func(ctx context.Context, packName string) (packUpdated bool, nodeStatus string, err error)

	// PullPack downloads the current LocalPolicyPack bytes and name.
	PullPack func(ctx context.Context) (packBytes []byte, packName string, err error)

	// PullBundle downloads the current signed RuntimeBundle bytes.
	PullBundle func(ctx context.Context) (bundleBytes []byte, err error)

	// ReportPackStatus reports pack apply success or failure to Forge.
	ReportPackStatus func(ctx context.Context, packName string, applied bool, errDetail string) error

	// ReportStatus reports rich runtime status to Forge (non-fatal if it fails).
	ReportStatus func(ctx context.Context) error
}

// PackApplier is called when a new LocalPolicyPack is available.
// Return non-nil to signal a failed apply (Forge will be notified).
type PackApplier func(packBytes []byte, packName string) error

// StatePersister is called after enrollment and after each successful pack
// update so the caller can persist Forge state to its state file.
type StatePersister func(packName, packHash string)

// Config carries startup parameters for the agent.
type Config struct {
	NodeID    string
	Heartbeat time.Duration

	// Initial state from previous run (avoids re-enrollment on restart).
	InitialPackName string
	InitialPackHash string
}

// Agent manages the Forge enrollment and heartbeat lifecycle.
type Agent struct {
	mu     sync.RWMutex
	cfg    Config
	cbs    Callbacks
	logger *log.Logger

	applyPack    PackApplier
	persistState StatePersister

	enrolledPackName string
	activePackHash   string
	lastNodeStatus   string

	bundleUpdateCh chan []byte
	stopOnce       sync.Once
	stopCh         chan struct{}
}

// New creates a new Agent. Call Start() to begin the lifecycle.
func New(
	cfg Config,
	cbs Callbacks,
	applyPack PackApplier,
	persistState StatePersister,
	logger *log.Logger,
) *Agent {
	if logger == nil {
		logger = log.Default()
	}
	if cfg.Heartbeat == 0 {
		cfg.Heartbeat = 60 * time.Second
	}
	a := &Agent{
		cfg:              cfg,
		cbs:              cbs,
		logger:           logger,
		applyPack:        applyPack,
		persistState:     persistState,
		enrolledPackName: cfg.InitialPackName,
		activePackHash:   cfg.InitialPackHash,
		lastNodeStatus:   "pending",
		bundleUpdateCh:   make(chan []byte, 1),
		stopCh:           make(chan struct{}),
	}
	return a
}

// Start enrolls with Forge (if not already enrolled) then launches the
// heartbeat goroutine. Returns immediately.
func (a *Agent) Start(ctx context.Context) error {
	if a.cbs.Enroll != nil {
		if err := a.enroll(ctx); err != nil {
			a.logger.Printf("[forge-agent] enrollment failed: %v — continuing with local config", err)
			// Non-fatal: KLIQ continues with last-known-good local config.
		}
	}
	go a.heartbeatLoop(ctx)
	return nil
}

// BundleUpdates returns the channel that receives raw RuntimeBundle YAML bytes.
// The channel has capacity 1; if the consumer is slow the next heartbeat retries.
func (a *Agent) BundleUpdates() <-chan []byte { return a.bundleUpdateCh }

// Stop signals the heartbeat goroutine to exit.
func (a *Agent) Stop() {
	a.stopOnce.Do(func() { close(a.stopCh) })
}

// EnrolledPackName returns the currently enrolled policy pack name.
func (a *Agent) EnrolledPackName() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.enrolledPackName
}

// SetPackHash lets the main loop update the hash after applying a pack.
func (a *Agent) SetPackHash(hash string) {
	a.mu.Lock()
	a.activePackHash = hash
	a.mu.Unlock()
}

// ── internal ────────────────────────────────────────────────────────────────

func (a *Agent) enroll(ctx context.Context) error {
	enrollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	nodeID, status, err := a.cbs.Enroll(enrollCtx)
	if err != nil {
		return err
	}
	a.logger.Printf("[forge-agent] enrolled: node=%s status=%s", nodeID, status)
	if status == "approved" {
		a.pullAndApplyPack(ctx)
	}
	return nil
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.Heartbeat)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.runHeartbeat(ctx)
		}
	}
}

func (a *Agent) runHeartbeat(ctx context.Context) {
	a.mu.RLock()
	packName := a.enrolledPackName
	a.mu.RUnlock()

	if a.cbs.Heartbeat == nil {
		return
	}
	packUpdated, nodeStatus, err := a.cbs.Heartbeat(ctx, packName)
	if err != nil {
		a.logger.Printf("[forge-agent] heartbeat failed: %v", err)
		return
	}
	if nodeStatus != "" && nodeStatus != a.lastNodeStatus {
		a.logger.Printf("[forge-agent] node status: %s → %s", a.lastNodeStatus, nodeStatus)
		a.lastNodeStatus = nodeStatus
	}
	a.logger.Printf("[forge-agent] heartbeat ok: pack=%s updated=%v status=%s",
		packName, packUpdated, nodeStatus)

	if a.cbs.ReportStatus != nil {
		if err := a.cbs.ReportStatus(ctx); err != nil {
			a.logger.Printf("[forge-agent] report status: %v", err)
		}
	}

	if a.cbs.PullBundle != nil {
		if bundleBytes, bundleErr := a.cbs.PullBundle(ctx); bundleErr == nil && len(bundleBytes) > 0 {
			select {
			case a.bundleUpdateCh <- bundleBytes:
			default: // consumer not ready — next heartbeat retries
			}
		}
	}

	if packUpdated {
		a.pullAndApplyPack(ctx)
	}
}

func (a *Agent) pullAndApplyPack(ctx context.Context) {
	if a.cbs.PullPack == nil {
		return
	}
	packBytes, packName, err := a.cbs.PullPack(ctx)
	if err != nil {
		a.logger.Printf("[forge-agent] pack pull failed: %v", err)
		return
	}
	if len(packBytes) == 0 {
		return
	}
	if a.applyPack == nil {
		a.logger.Printf("[forge-agent] no pack applier configured — skipping pack %s", packName)
		return
	}
	if err := a.applyPack(packBytes, packName); err != nil {
		a.logger.Printf("[forge-agent] pack apply failed: %v", err)
		if a.cbs.ReportPackStatus != nil {
			_ = a.cbs.ReportPackStatus(ctx, packName, false, err.Error())
		}
		return
	}
	a.logger.Printf("[forge-agent] pack applied: %s", packName)
	if a.cbs.ReportPackStatus != nil {
		_ = a.cbs.ReportPackStatus(ctx, packName, true, "")
	}
	a.mu.Lock()
	a.enrolledPackName = packName
	a.mu.Unlock()
	if a.persistState != nil {
		a.persistState(packName, a.activePackHash)
	}
}
