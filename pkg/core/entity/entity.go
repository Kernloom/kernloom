// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package entity defines the canonical entity model shared across KLIQ, Correlate, and Forge.
// An Entity is any addressable, observable subject or object in the Kernloom trust graph.
package entity

import "time"

// Kind describes the type of entity.
type Kind string

const (
	KindIP          Kind = "ip"           // Single IPv4 or IPv6 address
	KindCIDR        Kind = "cidr"         // IPv4 or IPv6 CIDR range
	KindNode        Kind = "node"         // Physical/virtual node with a node_id
	KindService     Kind = "service"      // Logical service (e.g. "postgres", "api-gateway")
	KindUser        Kind = "user"         // User identity (unix uid, LDAP user, etc.)
	KindWorkload    Kind = "workload"     // Container, pod, process group
	KindProcess     Kind = "process"      // Individual process
	KindNamespace   Kind = "namespace"    // Kubernetes/OS namespace
	KindHTTPRoute   Kind = "http_route"   // HTTP method + path pattern
	KindSocket      Kind = "socket"       // Unix domain socket
	KindZitiService Kind = "ziti_service" // OpenZiti service identity
	KindTrustState  Kind = "trust_state"  // Keylime/trust attestation state
)

// Ref is a lightweight, serialisable pointer to an entity.
// Used as subject/object in observations, signals, relationships, and decisions.
type Ref struct {
	Kind      Kind              `json:"kind"`
	ID        string            `json:"id"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

// Entity is the full entity record as stored in the state store.
// Ref is the minimal form; Entity is the persistent, enriched form.
type Entity struct {
	ID            string
	Kind          Kind
	StableID      string // deterministic hash of Kind+ID+Namespace, used as DB PK
	Namespace     string
	DisplayName   string
	Labels        map[string]string
	SourceAdapter string
	Confidence    float64
	FirstSeenAt   time.Time
	LastSeenAt    time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
