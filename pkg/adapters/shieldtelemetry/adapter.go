// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

// Package shieldtelemetry implements the Shield telemetry adapter.
// It reads per-source statistics from the Kernloom Shield pinned eBPF maps on
// a regular interval, computes rate-of-change deltas and publishes normalised
// Observation events onto the event bus.
package shieldtelemetry

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/adrianenderlin/kernloom/pkg/adapterruntime"
	"github.com/adrianenderlin/kernloom/pkg/core/capability"
	"github.com/adrianenderlin/kernloom/pkg/core/observation"
	"github.com/adrianenderlin/kernloom/pkg/shieldclient"
)

// Config holds the configuration for the Shield telemetry adapter.
type Config struct {
	// BPFfsRoot is the bpffs mount point (default: /sys/fs/bpf).
	BPFfsRoot string

	// Interval is how often to sample the Shield maps.
	Interval time.Duration

	// NodeID is the Kernloom node identifier included in every Observation.
	NodeID string

	// PrevTTL controls how long to keep previous-tick snapshots for sources
	// that have not been seen recently (bounds memory).
	PrevTTL time.Duration
}

// prevSnapshot stores the counters from the previous polling tick for one source.
type prevSnapshot struct {
	Pkts, Bytes, Syn, Scan, DropRL uint64
	LastWall                       time.Time
}

// Adapter is the Shield telemetry adapter.
type Adapter struct {
	cfg    Config
	maps   *shieldclient.Maps
	cancel context.CancelFunc

	mu    sync.Mutex
	prev4 map[[4]byte]prevSnapshot
	prev6 map[[16]byte]prevSnapshot

	healthy uint32 // atomic: 1 = ok
	initErr error
}

// New creates a new Shield telemetry adapter with the given configuration.
func New(cfg Config) *Adapter {
	if cfg.BPFfsRoot == "" {
		cfg.BPFfsRoot = "/sys/fs/bpf"
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.PrevTTL <= 0 {
		cfg.PrevTTL = 10 * time.Minute
	}
	return &Adapter{
		cfg:   cfg,
		prev4: make(map[[4]byte]prevSnapshot, 64_000),
		prev6: make(map[[16]byte]prevSnapshot, 64_000),
	}
}

/* ---------------- adapterruntime.Adapter interface ----------------------- */

// ID returns the unique adapter identifier.
func (a *Adapter) ID() string { return "shield-telemetry" }

// Kind returns AdapterTelemetry.
func (a *Adapter) Kind() adapterruntime.AdapterKind { return adapterruntime.AdapterTelemetry }

// Capabilities returns the capabilities provided by this adapter.
func (a *Adapter) Capabilities() []*capability.Capability {
	return []*capability.Capability{
		adapterruntime.WellKnownNetworkObserveFlow(),
		adapterruntime.WellKnownNetworkObserveScan(),
	}
}

// Init opens the Shield telemetry maps (read-only; dryRun=true so enforcement
// maps are not required).
func (a *Adapter) Init(_ context.Context, _ adapterruntime.AdapterConfig) error {
	m, err := shieldclient.Open(a.cfg.BPFfsRoot, true /* dryRun – only telemetry maps */)
	if err != nil {
		a.initErr = fmt.Errorf("shield-telemetry: open maps: %w", err)
		atomic.StoreUint32(&a.healthy, 0)
		return a.initErr
	}
	a.maps = m
	atomic.StoreUint32(&a.healthy, 1)
	return nil
}

// Start launches the polling goroutine.  It must be called after Init.
func (a *Adapter) Start(ctx context.Context, bus adapterruntime.EventBus) error {
	if a.maps == nil {
		return fmt.Errorf("shield-telemetry: not initialised (call Init first)")
	}
	pctx, cancel := context.WithCancel(ctx)
	a.cancel = cancel

	go a.run(pctx, bus)
	return nil
}

// Health reports whether the adapter is operating normally.
func (a *Adapter) Health(_ context.Context) adapterruntime.HealthStatus {
	if atomic.LoadUint32(&a.healthy) == 1 {
		return adapterruntime.HealthStatus{Healthy: true}
	}
	msg := "shield-telemetry: unhealthy"
	if a.initErr != nil {
		msg = a.initErr.Error()
	}
	return adapterruntime.HealthStatus{Healthy: false, Message: msg}
}

// Stop cancels the polling goroutine and closes the map handles.
func (a *Adapter) Stop(_ context.Context) error {
	if a.cancel != nil {
		a.cancel()
	}
	if a.maps != nil {
		a.maps.Close()
		a.maps = nil
	}
	return nil
}

/* ---------------- polling goroutine -------------------------------------- */

func (a *Adapter) run(ctx context.Context, bus adapterruntime.EventBus) {
	ticker := time.NewTicker(a.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case nowWall := <-ticker.C:
			a.poll(ctx, bus, nowWall)
		}
	}
}

func (a *Adapter) poll(ctx context.Context, bus adapterruntime.EventBus, nowWall time.Time) {
	a.mu.Lock()
	defer a.mu.Unlock()

	intervalSec := a.cfg.Interval.Seconds()

	// ----- IPv4 sources -----
	it4 := a.maps.Src4.Iterate()
	var k4 [4]byte
	var v4 shieldclient.SrcStatsV4

	for it4.Next(&k4, &v4) {
		pv, ok := a.prev4[k4]
		if !ok {
			a.prev4[k4] = prevSnapshot{
				Pkts:     v4.Pkts,
				Bytes:    v4.Bytes,
				Syn:      v4.Syn,
				Scan:     v4.DportChanges,
				DropRL:   v4.DropRL,
				LastWall: nowWall,
			}
			continue
		}

		sec := nowWall.Sub(pv.LastWall).Seconds()
		if sec <= 0 {
			sec = intervalSec
			if sec <= 0 {
				sec = 1
			}
		}

		pps := float64(v4.Pkts-pv.Pkts) / sec
		bps := float64(v4.Bytes-pv.Bytes) / sec
		synRate := float64(v4.Syn-pv.Syn) / sec
		scanRate := float64(v4.DportChanges-pv.Scan) / sec
		dropRLRate := float64(v4.DropRL-pv.DropRL) / sec

		a.prev4[k4] = prevSnapshot{
			Pkts:     v4.Pkts,
			Bytes:    v4.Bytes,
			Syn:      v4.Syn,
			Scan:     v4.DportChanges,
			DropRL:   v4.DropRL,
			LastWall: nowWall,
		}

		obs := observation.NewObservation(
			observation.SourceShield,
			observation.TypeFlow,
			a.cfg.NodeID,
			observation.EntityRef{Kind: observation.KindIP, ID: ip4String(k4)},
		)
		obs.SetMetric("pps", pps)
		obs.SetMetric("bps", bps)
		obs.SetMetric("syn_rate", synRate)
		obs.SetMetric("scan_rate", scanRate)
		obs.SetMetric("drop_rl_rate", dropRLRate)
		obs.SetAttribute("ip_version", "4")

		if err := bus.PublishObservation(ctx, *obs); err != nil {
			log.Printf("shield-telemetry: publish v4 obs: %v", err)
		}
	}
	if err := it4.Err(); err != nil {
		log.Printf("shield-telemetry: iterate src4: %v", err)
		atomic.StoreUint32(&a.healthy, 0)
	} else {
		atomic.StoreUint32(&a.healthy, 1)
	}

	// ----- IPv6 sources -----
	if a.maps.Src6 != nil {
		it6 := a.maps.Src6.Iterate()
		var k6 shieldclient.Src6Key
		var v6 shieldclient.SrcStatsV6

		for it6.Next(&k6, &v6) {
			ip6 := k6.IP
			pv, ok := a.prev6[ip6]
			if !ok {
				a.prev6[ip6] = prevSnapshot{
					Pkts:     v6.Pkts,
					Bytes:    v6.Bytes,
					Syn:      v6.Syn,
					Scan:     v6.DportChanges,
					DropRL:   v6.DropRL,
					LastWall: nowWall,
				}
				continue
			}

			sec := nowWall.Sub(pv.LastWall).Seconds()
			if sec <= 0 {
				sec = intervalSec
				if sec <= 0 {
					sec = 1
				}
			}

			pps := float64(v6.Pkts-pv.Pkts) / sec
			bps := float64(v6.Bytes-pv.Bytes) / sec
			synRate := float64(v6.Syn-pv.Syn) / sec
			scanRate := float64(v6.DportChanges-pv.Scan) / sec
			dropRLRate := float64(v6.DropRL-pv.DropRL) / sec

			a.prev6[ip6] = prevSnapshot{
				Pkts:     v6.Pkts,
				Bytes:    v6.Bytes,
				Syn:      v6.Syn,
				Scan:     v6.DportChanges,
				DropRL:   v6.DropRL,
				LastWall: nowWall,
			}

			obs := observation.NewObservation(
				observation.SourceShield,
				observation.TypeFlow,
				a.cfg.NodeID,
				observation.EntityRef{Kind: observation.KindIP, ID: ip6String(ip6)},
			)
			obs.SetMetric("pps", pps)
			obs.SetMetric("bps", bps)
			obs.SetMetric("syn_rate", synRate)
			obs.SetMetric("scan_rate", scanRate)
			obs.SetMetric("drop_rl_rate", dropRLRate)
			obs.SetAttribute("ip_version", "6")

			if err := bus.PublishObservation(ctx, *obs); err != nil {
				log.Printf("shield-telemetry: publish v6 obs: %v", err)
			}
		}
		if err := it6.Err(); err != nil {
			log.Printf("shield-telemetry: iterate src6: %v", err)
		}
	}

	// ----- Housekeeping: drop stale prev entries -----
	for ip, pv := range a.prev4 {
		if nowWall.Sub(pv.LastWall) > a.cfg.PrevTTL {
			delete(a.prev4, ip)
		}
	}
	for ip, pv := range a.prev6 {
		if nowWall.Sub(pv.LastWall) > a.cfg.PrevTTL {
			delete(a.prev6, ip)
		}
	}
}

/* ---------------- helpers ------------------------------------------------ */

func ip4String(k [4]byte) string  { return net.IPv4(k[0], k[1], k[2], k[3]).String() }
func ip6String(k [16]byte) string { return net.IP(k[:]).String() }
