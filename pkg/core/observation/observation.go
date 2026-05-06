// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package observation

import (
	"time"
)

// ObservationSource describes where an observation originates.
type ObservationSource string

const (
	SourceShield  ObservationSource = "shield"   // eBPF/XDP telemetry
	SourceNginx   ObservationSource = "nginx"    // HTTP/access logs
	SourceZiti    ObservationSource = "ziti"     // OpenZiti session events
	SourceTrustd  ObservationSource = "trustd"   // Local trust daemon
	SourceApp     ObservationSource = "app"      // Application instrumentation
	SourceSyslog  ObservationSource = "syslog"   // Syslog/journald
	SourceCilium  ObservationSource = "cilium"   // Cilium eBPF
	SourceCorrelate ObservationSource = "correlate" // Correlate global signals as obs
)

// ObservationType categorizes what is being observed.
type ObservationType string

const (
	// Network flow observations
	TypeFlow      ObservationType = "flow"      // Bidirectional or unidirectional traffic
	TypeDrop      ObservationType = "drop"      // Packet drop (policy, rate-limit, error)
	TypeScan      ObservationType = "scan"      // Port/host scan behavior
	TypeRateLimit ObservationType = "rate_limit" // Rate-limit drop

	// Application observations
	TypeHTTP      ObservationType = "http"      // HTTP status codes, redirects
	TypeDNS       ObservationType = "dns"       // DNS queries, responses
	TypeAuth      ObservationType = "auth"      // Authentication success/failure
	TypeProcess   ObservationType = "process"   // Process creation, termination, hash change

	// Trust and integrity observations
	TypeTrust     ObservationType = "trust"     // Trust state change, attestation result
	TypeIntegrity ObservationType = "integrity" // IMA violation, binary hash change

	// Service/connection observations
	TypeConnection ObservationType = "connection" // New service connection, disconnection
)

// EntityKind describes the type of entity in an EntityRef.
type EntityKind string

const (
	KindIP       EntityKind = "ip"       // Single IPv4 or IPv6 address
	KindCIDR     EntityKind = "cidr"     // IPv4 or IPv6 CIDR range
	KindNode     EntityKind = "node"     // Physical/virtual node with a node_id
	KindService  EntityKind = "service"  // Logical service (e.g., "postgres", "api-gateway")
	KindUser     EntityKind = "user"     // User identity (e.g., unix uid, LDAP user)
	KindWorkload EntityKind = "workload" // Container, pod, process group
	KindProcess  EntityKind = "process"  // Individual process
	KindNamespace EntityKind = "namespace" // Kubernetes/OS namespace
)

// EntityRef is a reference to an entity (IP, service, node, user, etc.)
// It is used as subject and object in observations and signals.
type EntityRef struct {
	// Kind describes the type of entity
	Kind EntityKind `json:"kind"`

	// ID is the unique identifier within its kind (IP string, node ID, service name, etc.)
	ID string `json:"id"`

	// Optional: additional context
	// Examples: "role": "public-api", "namespace": "default", "container_id": "abc123"
	Labels map[string]string `json:"labels,omitempty"`
}

// Observation is a normalized, timestamped observation about activity in the system.
// Observations come from various sources (shield, nginx, syslog, etc.) and are normalized
// into a common schema for processing by KLIQ, Forge, Correlate, and other components.
type Observation struct {
	// ID is a unique identifier for this observation (UUIDv4 recommended).
	ID string `json:"id"`

	// Time is the wall-clock time when the observation occurred.
	Time time.Time `json:"time"`

	// NodeID is the ID of the node where the observation occurred.
	NodeID string `json:"node_id"`

	// Source is the component/system that produced this observation.
	Source ObservationSource `json:"source"`

	// Type categorizes the observation (flow, drop, auth, trust, etc.)
	Type ObservationType `json:"type"`

	// Subject is the primary entity involved (source of traffic, user, process, etc.)
	Subject EntityRef `json:"subject"`

	// Object is the secondary entity (destination, service, etc.) - optional.
	Object EntityRef `json:"object,omitempty"`

	// Metrics are numeric measurements associated with the observation.
	// Examples for flow observations:
	//   "packets": 42
	//   "bytes": 4096
	//   "syn_count": 5
	//   "duration_seconds": 10.5
	// Examples for rate-limit observations:
	//   "pps_observed": 5000
	//   "pps_threshold": 1000
	//   "drops": 42
	Metrics map[string]float64 `json:"metrics,omitempty"`

	// Attributes are string key-value pairs for context.
	// Examples:
	//   "protocol": "tcp"
	//   "destination_port": "443"
	//   "http_method": "GET"
	//   "http_status": "401"
	//   "reason": "authentication_failure"
	Attributes map[string]string `json:"attributes,omitempty"`

	// SeverityHint is an optional severity score hint from the source (0-100).
	// This is a suggestion only; risk engines may recalculate severity.
	SeverityHint int `json:"severity_hint,omitempty"`
}

// NewObservation creates a new observation with required fields set.
// ID and Time are generated if empty.
func NewObservation(source ObservationSource, obsType ObservationType, nodeID string, subject EntityRef) *Observation {
	return &Observation{
		ID:         generateID(),
		Time:       time.Now().UTC(),
		NodeID:     nodeID,
		Source:     source,
		Type:       obsType,
		Subject:    subject,
		Metrics:    make(map[string]float64),
		Attributes: make(map[string]string),
	}
}

// SetObject sets the object entity reference.
func (o *Observation) SetObject(obj EntityRef) *Observation {
	o.Object = obj
	return o
}

// SetMetric adds or updates a metric value.
func (o *Observation) SetMetric(key string, value float64) *Observation {
	if o.Metrics == nil {
		o.Metrics = make(map[string]float64)
	}
	o.Metrics[key] = value
	return o
}

// SetAttribute adds or updates an attribute.
func (o *Observation) SetAttribute(key, value string) *Observation {
	if o.Attributes == nil {
		o.Attributes = make(map[string]string)
	}
	o.Attributes[key] = value
	return o
}

// SetSeverityHint sets the severity hint.
func (o *Observation) SetSeverityHint(severity int) *Observation {
	if severity < 0 {
		severity = 0
	}
	if severity > 100 {
		severity = 100
	}
	o.SeverityHint = severity
	return o
}

// Batch is a collection of observations, typically from one node for a time window.
// Used for exporting to Correlate or other systems.
type Batch struct {
	NodeID       string
	From         time.Time
	To           time.Time
	Observations []Observation
}

// generateID generates a unique observation ID (simplified; use UUIDv4 in production).
// This is a placeholder; real implementation should use crypto/rand or uuid.
func generateID() string {
	return "" // TODO: implement proper UUID generation
}
