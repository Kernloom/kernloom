// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package adapterruntime

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/core/fsm"
	"github.com/kernloom/kernloom/pkg/core/observation"
	"github.com/kernloom/kernloom/pkg/core/signal"
)

const (
	ConfigScoring = "scoring"

	ResourceTelemetryHandle = "telemetry_handle"
	ResourceSourceBaseline  = "source_baseline"

	MetricNetworkPacketsPerSecond       = "network.packets_per_second"
	MetricNetworkBytesPerSecond         = "network.bytes_per_second"
	MetricNetworkSynRate                = "network.syn_rate"
	MetricNetworkDestinationPortChanges = "network.destination_port_change_rate"
	MetricNetworkRateLimitDropRate      = "network.rate_limit_drop_rate"
	MetricNetworkFlowPackets            = "network.flow.packets"
	MetricNetworkFlowBytes              = "network.flow.bytes"
)

// RuntimeTick describes one orchestrator observation window.
type RuntimeTick struct {
	Now      time.Time
	Interval time.Duration
}

// RuntimeAdapterSpec is the generic construction contract for runtime
// adapters. Adapter-specific packages may interpret Config and Resources, but
// KLIQ should pass only through this neutral shape.
type RuntimeAdapterSpec struct {
	ID        string
	NodeID    string
	Interval  time.Duration
	StateTTL  time.Duration
	MinRate   float64
	MinScore  float64
	DryRun    bool
	Config    AdapterConfig
	Resources map[string]any
}

// RuntimeScoringConfig describes generic threshold/weight based local scoring
// over canonical metric IDs.
type RuntimeScoringConfig struct {
	Triggers    map[string]float64
	Weights     map[string]float64
	SeverityCap float64
	SignalTTL   time.Duration
}

// LegacyNetworkScoring carries the standalone KLIQ network scoring knobs in a
// command-local, adapter-neutral type. Concrete adapters translate these values
// to their own signal engine configuration.
type LegacyNetworkScoring struct {
	TrigPPS   float64
	TrigSyn   float64
	TrigScan  float64
	TrigBPS   float64
	WPPS      float64
	WSyn      float64
	WScan     float64
	WBps      float64
	SevCap    float64
	SignalTTL time.Duration
}

// TuningConfig describes adapter-neutral autotune floors and safety guards.
type TuningConfig struct {
	MinSamples                int
	FloorPPS                  float64
	FloorSyn                  float64
	FloorScan                 float64
	FloorBPS                  float64
	MinWindowsBeforeDownscale int
	MinSourcesBeforeDownscale int
}

// TuningPolicy describes when and how a tuner may adjust thresholds.
type TuningPolicy struct {
	Active  bool
	Every   time.Duration
	K       float64
	MaxUp   float64
	MaxDown float64
	Alpha   float64
	Phase   string
}

// TuningThresholds is intentionally metric-shaped rather than adapter-shaped.
type TuningThresholds struct {
	PacketsPerSecond       float64
	SynRate                float64
	DestinationPortChanges float64
	BytesPerSecond         float64
}

func (t TuningThresholds) Summary() string {
	return fmt.Sprintf("thresholds{pps=%.0f bps=%.0f syn=%.0f scan=%.0f}",
		t.PacketsPerSecond, t.BytesPerSecond, t.SynRate, t.DestinationPortChanges)
}

// TuningSample is one source observation considered for learning.
type TuningSample struct {
	PacketsPerSecond       float64
	SynRate                float64
	DestinationPortChanges float64
	BytesPerSecond         float64
	SourceID               string
	Accepted               bool
}

// TuningResult contains the portable result of an autotune run.
type TuningResult struct {
	OldThresholds    TuningThresholds
	NewThresholds    TuningThresholds
	AdapterStats     map[string]float64
	SampleCount      int
	CleanRatio       float64
	CompletedWindows int
	Phase            string
	Skipped          bool
	SkipReason       string
}

// Tuner is implemented by adapter-owned local tuning mechanisms.
type Tuner interface {
	RecordSample(TuningSample)
	SampleCount() int
	CurrentThresholds() TuningThresholds
	Tick(now time.Time, policy TuningPolicy, cleanRatio float64) (TuningResult, bool)
	LogResult(logger interface{ Printf(string, ...any) }, result TuningResult, k, dropRatio float64, clean bool)
}

// SourceObservation is the generic output of an observing runtime adapter.
// Adapter-specific counter names stay in the adapter package; shared callers
// consume canonical metric IDs, score, subject and evidence signals.
type SourceObservation struct {
	SourceID   string
	AdapterID  string
	Subject    observation.EntityRef
	ObservedAt time.Time
	Score      float64
	Confidence float64
	Metrics    map[string]float64
	Attributes map[string]string
	Signals    []signal.Signal
}

// EnforcementDecision is a generic adapter-facing runtime action request.
// KLIQ's Runtime PDP and Action Broker remain responsible for deciding and
// authorising; adapters only execute declared effects.
type EnforcementDecision struct {
	DecisionID string
	Capability string
	Intensity  string
	Target     observation.EntityRef
	TTL        time.Duration
	Params     map[string]any
	CreatedAt  time.Time
}

// EnforcementParams carries generic per-level enforcement tuning. Adapter
// packages decide how these rates and TTLs map to their concrete PEP backend.
type EnforcementParams struct {
	SoftRate  uint64
	SoftBurst uint64
	SoftTTL   time.Duration

	HardRate  uint64
	HardBurst uint64
	HardTTL   time.Duration

	BlockTTL time.Duration
	Cooldown time.Duration
}

// CapabilityParams contains generic rate-limit parameters resolved from an
// adapter profile or manifest.
type CapabilityParams struct {
	SoftRatePPS uint64
	SoftBurst   uint64
	HardRatePPS uint64
	HardBurst   uint64
	Cooldown    time.Duration
}

// SourceTarget is the adapter-neutral identity passed to source PEPs. The
// orchestrator treats SourceID as opaque; concrete adapters decide whether it
// is an IP, identity ID, workload name, device handle or something else.
type SourceTarget struct {
	SourceID   string
	Subject    observation.EntityRef
	Attributes map[string]string
}

// SourcePEP is the generic synchronous PEP contract used by the legacy FSM
// path. Concrete adapters own the actual enforcement backend and key formats.
type SourcePEP interface {
	TransitionSource(target SourceTarget, st fsm.State, level fsm.Level, now time.Time, params EnforcementParams) (fsm.State, error)
}

const (
	RelationshipDimensionPrefix = "dimension."
)

// RelationshipKey is the adapter-neutral identity for a relationship action.
// SubjectID is the actor, TargetID is the object of the relationship, and
// Dimension carries adapter-owned channel details such as service, route,
// posture, namespace or any future relationship discriminator.
type RelationshipKey struct {
	SubjectID string
	TargetID  string
	Dimension map[string]string
}

// Canonical returns a stable key for logging, storage and proposal indexing.
func (r RelationshipKey) Canonical() string {
	parts := []string{
		"subject=" + strconv.Quote(r.SubjectID),
		"target=" + strconv.Quote(r.TargetID),
	}
	if len(r.Dimension) > 0 {
		keys := make([]string, 0, len(r.Dimension))
		for k := range r.Dimension {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, "dimension."+strconv.Quote(k)+"="+strconv.Quote(r.Dimension[k]))
		}
	}
	return strings.Join(parts, "|")
}

// RelationshipTarget describes an adapter-neutral relationship action. The
// orchestrator treats Key as opaque; concrete adapters decode Dimension for
// their own platform.
type RelationshipTarget struct {
	RelationshipKey
	Attributes map[string]string
}

// RelationshipPEP is implemented by adapters that can enforce relationship
// decisions such as graph-freeze denials, tuple blocks, service revocations or
// allowlist sync.
type RelationshipPEP interface {
	RelationshipAvailable() bool
	SetRelationshipEnforcement(on bool) error
	DenyRelationship(target RelationshipTarget) error
	AllowRelationship(target RelationshipTarget) error
}

// AdapterStats reports the health and amount of work performed by an adapter
// during one observation/enforcement cycle.
type AdapterStats struct {
	AdapterID           string
	ObservedSources     int
	EmittedSignals      int
	AppliedActions      int
	DroppedObservations int
	Health              HealthStatus
}

// RuntimeUpdate is a generic runtime-state/config update delivered by the
// orchestrator to an adapter. Raw may carry an adapter-owned typed value when
// both sides are linked in-process; portable adapters should prefer Values.
type RuntimeUpdate struct {
	Kind   string
	Values map[string]any
	Raw    any
}

// RuntimeUpdatable is optional. Adapters implement it when runtime-learned
// state can update their local scoring/enforcement parameters.
type RuntimeUpdatable interface {
	ApplyRuntimeUpdate(ctx context.Context, update RuntimeUpdate) error
	RuntimeSummary() string
	RuntimeValues(purpose string) map[string]float64
}

// ObservingAdapter is the narrow runtime interface KLIQ needs from a component
// that can provide local facts and optionally execute temporary actions.
type ObservingAdapter interface {
	Adapter

	ApplyRuntimeConfig(ctx context.Context, pdpConfig, policyPack []byte) error
	Observe(ctx context.Context, tick RuntimeTick) ([]SourceObservation, AdapterStats, error)
	Enforce(ctx context.Context, decision EnforcementDecision) error
	MarshalRuntimeState() ([]byte, error)
	UnmarshalRuntimeState([]byte) error
}
