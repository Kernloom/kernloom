// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package klshieldruntime contains the KLShield runtime adapter used by KLIQ.
// It owns KLShield eBPF map snapshots, packet-rate feature calculation and the
// KLShield signal engine so the KLIQ command can stay a generic orchestrator.
package klshieldruntime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/autotuner"
	"github.com/kernloom/kernloom/pkg/adapters/klshield/client"
	shieldheuristic "github.com/kernloom/kernloom/pkg/adapters/klshield/signalengine"
	"github.com/kernloom/kernloom/pkg/core/capability"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

const (
	AdapterID = "klshield-runtime"

	AttributeIPVersion = "ip_version"
	AttributePPS       = "klshield.pps"
	AttributeBPS       = "klshield.bps"
	AttributeSynRate   = "klshield.syn_rate"
	AttributeScanRate  = "klshield.scan_rate"
	AttributeDropRL    = "klshield.drop_rl_rate"
	AttributeSeverity  = "klshield.severity"
)

type SourceBaseline interface {
	Update(sourceID string, pps, bps, synRate, scanRate float64, anomalous bool, now time.Time)
	EffectiveTrigPPS(sourceID string, global float64) float64
	EffectiveTrigBPS(sourceID string, global float64) float64
}

type Config struct {
	NodeID      string
	Interval    time.Duration
	PrevTTL     time.Duration
	MinPPS      float64
	MinSeverity float64
	Maps        *shieldclient.Maps
	DryRun      bool
	Engine      shieldheuristic.Config
	Baseline    SourceBaseline
}

type Adapter struct {
	cfg    Config
	engine *shieldheuristic.Engine
	bus    adapterruntime.EventBus

	mu    sync.Mutex
	prev4 map[[4]byte]counterSnapshot
	prev6 map[[16]byte]counterSnapshot

	healthy uint32
}

func New(cfg Config) *Adapter {
	applyDefaults(&cfg)
	if cfg.Engine.NodeID == "" {
		cfg.Engine.NodeID = cfg.NodeID
	}
	return &Adapter{
		cfg:     cfg,
		engine:  shieldheuristic.New(cfg.Engine),
		prev4:   make(map[[4]byte]counterSnapshot, 64_000),
		prev6:   make(map[[16]byte]counterSnapshot, 64_000),
		healthy: 1,
	}
}

func (a *Adapter) ID() string { return AdapterID }

func (a *Adapter) Kind() adapterruntime.AdapterKind { return adapterruntime.AdapterTelemetry }

func (a *Adapter) Capabilities() []*capability.Capability {
	return nil
}

func (a *Adapter) Init(_ context.Context, _ adapterruntime.AdapterConfig) error {
	if a.cfg.Maps == nil {
		atomic.StoreUint32(&a.healthy, 0)
		return fmt.Errorf("klshield runtime: maps are not configured")
	}
	atomic.StoreUint32(&a.healthy, 1)
	return nil
}

func (a *Adapter) Start(_ context.Context, bus adapterruntime.EventBus) error {
	a.bus = bus
	return nil
}

func (a *Adapter) Health(_ context.Context) adapterruntime.HealthStatus {
	if atomic.LoadUint32(&a.healthy) == 1 {
		return adapterruntime.HealthStatus{Healthy: true}
	}
	return adapterruntime.HealthStatus{Healthy: false, Message: "klshield runtime maps unavailable"}
}

func (a *Adapter) Stop(_ context.Context) error {
	return nil
}

func (a *Adapter) ApplyRuntimeConfig(_ context.Context, _, _ []byte) error {
	return nil
}

func (a *Adapter) Observe(ctx context.Context, tick adapterruntime.RuntimeTick) ([]adapterruntime.SourceObservation, adapterruntime.AdapterStats, error) {
	if tick.Now.IsZero() {
		tick.Now = time.Now()
	}
	if tick.Interval <= 0 {
		tick.Interval = a.cfg.Interval
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	var out []adapterruntime.SourceObservation
	emitted := 0
	if a.cfg.Maps == nil {
		atomic.StoreUint32(&a.healthy, 0)
		return nil, a.stats(0, 0), fmt.Errorf("klshield runtime: maps unavailable")
	}
	if a.cfg.Maps.Src4 != nil {
		obs, sigs, err := a.observe4(ctx, tick)
		if err != nil {
			return out, a.stats(len(out), emitted), err
		}
		out = append(out, obs...)
		emitted += sigs
	}
	if a.cfg.Maps.Src6 != nil {
		obs, sigs, err := a.observe6(ctx, tick)
		if err != nil {
			return out, a.stats(len(out), emitted), err
		}
		out = append(out, obs...)
		emitted += sigs
	}
	a.evictPrev(tick.Now)
	atomic.StoreUint32(&a.healthy, 1)
	return out, a.stats(len(out), emitted), nil
}

func (a *Adapter) Enforce(_ context.Context, _ adapterruntime.EnforcementDecision) error {
	return fmt.Errorf("klshield runtime: enforcement is provided by the klshield PEP adapter")
}

func (a *Adapter) MarshalRuntimeState() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return json.Marshal(struct {
		Prev4 int `json:"prev4_entries"`
		Prev6 int `json:"prev6_entries"`
	}{Prev4: len(a.prev4), Prev6: len(a.prev6)})
}

func (a *Adapter) UnmarshalRuntimeState([]byte) error {
	return nil
}

func (a *Adapter) UpdateEngineConfig(cfg shieldheuristic.Config) {
	if cfg.NodeID == "" {
		cfg.NodeID = a.cfg.NodeID
	}
	a.engine.UpdateConfig(cfg)
	a.cfg.Engine = cfg
}

func (a *Adapter) ApplyAutotuneResult(result autotuner.TickResult) {
	cfg := a.engine.Config()
	cfg.TrigPPS = result.NewThresholds.TrigPPS
	cfg.TrigSyn = result.NewThresholds.TrigSyn
	cfg.TrigScan = result.NewThresholds.TrigScan
	cfg.TrigBPS = result.NewThresholds.TrigBPS
	a.UpdateEngineConfig(cfg)
}

func (a *Adapter) ApplyRuntimeUpdate(_ context.Context, update adapterruntime.RuntimeUpdate) error {
	switch update.Kind {
	case "autotune.thresholds":
		if result, ok := update.Raw.(autotuner.TickResult); ok {
			a.ApplyAutotuneResult(result)
			return nil
		}
		cfg := a.engine.Config()
		if v, ok := update.Values[MetricPacketsPerSecond]; ok {
			cfg.TrigPPS = valueFloat(v)
		}
		if v, ok := update.Values[MetricBytesPerSecond]; ok {
			cfg.TrigBPS = valueFloat(v)
		}
		if v, ok := update.Values[MetricSynRate]; ok {
			cfg.TrigSyn = valueFloat(v)
		}
		if v, ok := update.Values[MetricDestinationPortChanges]; ok {
			cfg.TrigScan = valueFloat(v)
		}
		a.UpdateEngineConfig(cfg)
		return nil
	default:
		return nil
	}
}

func (a *Adapter) GraphTriggerRates() (packetRate, byteRate float64) {
	cfg := a.engine.Config()
	return cfg.TrigPPS, cfg.TrigBPS
}

func (a *Adapter) RuntimeValues(purpose string) map[string]float64 {
	cfg := a.engine.Config()
	switch purpose {
	case "graph.baseline.triggers":
		return map[string]float64{
			MetricPacketsPerSecond: cfg.TrigPPS,
			MetricBytesPerSecond:   cfg.TrigBPS,
		}
	default:
		return map[string]float64{
			MetricPacketsPerSecond:       cfg.TrigPPS,
			MetricBytesPerSecond:         cfg.TrigBPS,
			MetricSynRate:                cfg.TrigSyn,
			MetricDestinationPortChanges: cfg.TrigScan,
		}
	}
}

func (a *Adapter) TuningSummary() string {
	cfg := a.engine.Config()
	return fmt.Sprintf("thresholds{pps=%.0f bps=%.0f syn=%.0f scan=%.0f} weights{pps=%.2f bps=%.2f syn=%.2f scan=%.2f} cap=%.1f",
		cfg.TrigPPS, cfg.TrigBPS, cfg.TrigSyn, cfg.TrigScan,
		cfg.WPPS, cfg.WBps, cfg.WSyn, cfg.WScan, cfg.SevCap)
}

func (a *Adapter) RuntimeSummary() string { return a.TuningSummary() }

func (a *Adapter) stats(sources, signals int) adapterruntime.AdapterStats {
	return adapterruntime.AdapterStats{
		AdapterID:       AdapterID,
		ObservedSources: sources,
		EmittedSignals:  signals,
		Health:          a.Health(context.Background()),
	}
}

func (a *Adapter) observe4(ctx context.Context, tick adapterruntime.RuntimeTick) ([]adapterruntime.SourceObservation, int, error) {
	it := a.cfg.Maps.Src4.Iterate()
	var key [4]byte
	var val shieldclient.SrcStatsV4
	var out []adapterruntime.SourceObservation
	emitted := 0

	for it.Next(&key, &val) {
		curr := counterSnapshot{
			Pkts: val.Pkts, Bytes: val.Bytes, Syn: val.Syn,
			DportChanges: val.DportChanges, DropRL: val.DropRL,
			LastWall: tick.Now,
		}
		prev, ok := a.prev4[key]
		if !ok {
			a.prev4[key] = curr
			continue
		}
		sample, valid := calculateRates(prev, curr, tick.Interval)
		a.prev4[key] = curr
		if !valid {
			continue
		}

		subject := observation.EntityRef{Kind: observation.KindIP, ID: ip4String(key)}
		obs := a.observationFor(ctx, tick.Now, subject, "4", sample)
		if obs.SourceID == "" {
			continue
		}
		out = append(out, obs)
		emitted += len(obs.Signals)
	}
	if err := it.Err(); err != nil {
		return out, emitted, fmt.Errorf("iterate klshield src4 map: %w", err)
	}
	return out, emitted, nil
}

func (a *Adapter) observe6(ctx context.Context, tick adapterruntime.RuntimeTick) ([]adapterruntime.SourceObservation, int, error) {
	it := a.cfg.Maps.Src6.Iterate()
	var key shieldclient.Src6Key
	var val shieldclient.SrcStatsV6
	var out []adapterruntime.SourceObservation
	emitted := 0

	for it.Next(&key, &val) {
		ip := key.IP
		curr := counterSnapshot{
			Pkts: val.Pkts, Bytes: val.Bytes, Syn: val.Syn,
			DportChanges: val.DportChanges, DropRL: val.DropRL,
			LastWall: tick.Now,
		}
		prev, ok := a.prev6[ip]
		if !ok {
			a.prev6[ip] = curr
			continue
		}
		sample, valid := calculateRates(prev, curr, tick.Interval)
		a.prev6[ip] = curr
		if !valid {
			continue
		}

		subject := observation.EntityRef{Kind: observation.KindIP, ID: net.IP(ip[:]).String()}
		obs := a.observationFor(ctx, tick.Now, subject, "6", sample)
		if obs.SourceID == "" {
			continue
		}
		out = append(out, obs)
		emitted += len(obs.Signals)
	}
	if err := it.Err(); err != nil {
		return out, emitted, fmt.Errorf("iterate klshield src6 map: %w", err)
	}
	return out, emitted, nil
}

func (a *Adapter) observationFor(ctx context.Context, now time.Time, subject observation.EntityRef, ipVersion string, sample rateSample) adapterruntime.SourceObservation {
	cfg := a.engine.Config()
	if a.cfg.Baseline != nil {
		a.cfg.Baseline.Update(subject.ID, sample.PPS, sample.BPS, sample.SynRate, sample.ScanRate, false, now)
		cfg.TrigPPS = a.cfg.Baseline.EffectiveTrigPPS(subject.ID, cfg.TrigPPS)
		cfg.TrigBPS = a.cfg.Baseline.EffectiveTrigBPS(subject.ID, cfg.TrigBPS)
	}

	fsmMetrics, sigs := a.engine.EvaluateAt(subject,
		sample.PPS, sample.BPS, sample.SynRate, sample.ScanRate, sample.DropRLRate,
		cfg.TrigPPS, cfg.TrigSyn, cfg.TrigScan, cfg.TrigBPS)
	for _, sig := range sigs {
		if a.bus != nil {
			_ = a.bus.PublishSignal(ctx, sig)
		}
	}

	severity := fsmMetrics.Severity
	if sample.PPS < a.cfg.MinPPS && !(a.cfg.MinSeverity > 0 && severity >= a.cfg.MinSeverity) && sample.DropRLRate == 0 {
		return adapterruntime.SourceObservation{}
	}

	return adapterruntime.SourceObservation{
		SourceID:   subject.ID,
		AdapterID:  AdapterID,
		Subject:    subject,
		ObservedAt: now,
		Score:      severity,
		Confidence: 1,
		Metrics:    sampleMetrics(sample),
		Attributes: map[string]string{
			AttributeIPVersion: ipVersion,
			AttributePPS:       formatFloat(sample.PPS),
			AttributeBPS:       formatFloat(sample.BPS),
			AttributeSynRate:   formatFloat(sample.SynRate),
			AttributeScanRate:  formatFloat(sample.ScanRate),
			AttributeDropRL:    formatFloat(sample.DropRLRate),
			AttributeSeverity:  formatFloat(severity),
		},
		Signals: sigs,
	}
}

func (a *Adapter) evictPrev(now time.Time) {
	if a.cfg.PrevTTL <= 0 {
		return
	}
	cutoff := now.Add(-a.cfg.PrevTTL)
	for ip, prev := range a.prev4 {
		if prev.LastWall.Before(cutoff) {
			delete(a.prev4, ip)
		}
	}
	for ip, prev := range a.prev6 {
		if prev.LastWall.Before(cutoff) {
			delete(a.prev6, ip)
		}
	}
}

func applyDefaults(cfg *Config) {
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.PrevTTL <= 0 {
		cfg.PrevTTL = 10 * time.Minute
	}
}

func ip4String(ip [4]byte) string {
	return net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
}

var _ adapterruntime.ObservingAdapter = (*Adapter)(nil)
var _ adapterruntime.RuntimeUpdatable = (*Adapter)(nil)
