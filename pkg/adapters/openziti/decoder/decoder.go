// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package decoder translates raw OpenZiti vendor events into typed VendorFacts.
//
// This is the only package allowed to reference OpenZiti-specific field names.
// Downstream packages (mapping, signal engine, risk engine) receive only the
// canonical observation types from pkg/core/observation/.
//
// Priority namespaces (spec §6.3 P0):
//   - authentication
//   - apiSession
//   - session
//   - usage
//   - sdk
package decoder

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/openziti/eventsource"
)

// VendorFact is a decoded, typed OpenZiti event still in vendor semantics.
// It is never promoted to canonical observations without an explicit mapping.
// All field names use the vendor's own naming convention, prefixed by namespace.
type VendorFact struct {
	// Namespace mirrors RawVendorEvent.Namespace.
	Namespace string

	// EventType mirrors RawVendorEvent.EventType.
	EventType string

	// ObservedAt is when the event was received.
	ObservedAt time.Time

	// IdentityID is the OpenZiti identity ID when present.
	// Empty when the event is not identity-attributed (e.g. aggregated service metrics).
	IdentityID string

	// IdentityName is the human-readable identity name from enrichment (may be empty).
	IdentityName string

	// ServiceID is the OpenZiti service ID when present.
	ServiceID string

	// ServiceName is the human-readable service name from enrichment (may be empty).
	ServiceName string

	// SessionType is "Dial" or "Bind" for session namespace events.
	SessionType string

	// AuthSuccess is true for successful authentication events.
	AuthSuccess bool

	// AuthMethod is the authentication method string (e.g. "cert", "updb", "jwt").
	AuthMethod string

	// FailureReason is the failure reason string for failed events.
	FailureReason string

	// SDKOnline is true when an SDK online event was received.
	SDKOnline *bool

	// UsageBytesRx / UsageBytesTx are the usage interval byte counts.
	UsageBytesRx int64
	UsageBytesTx int64

	// SemanticStatus classifies how well the event was decoded.
	// "ok" | "partial" | "unknown_version" | "unknown_namespace"
	SemanticStatus string

	// RawEvent is the original vendor event retained for audit.
	RawEvent eventsource.RawVendorEvent
}

// Decode translates a RawVendorEvent into a VendorFact.
// Unknown namespaces or versions produce a VendorFact with SemanticStatus
// "unknown_namespace" or "unknown_version" — never a silent wrong signal.
func Decode(ev eventsource.RawVendorEvent) (VendorFact, error) {
	fact := VendorFact{
		Namespace:      ev.Namespace,
		EventType:      ev.EventType,
		ObservedAt:     ev.ObservedAt,
		SemanticStatus: "ok",
		RawEvent:       ev,
	}

	switch ev.Namespace {
	case "authentication":
		return decodeAuthentication(ev, fact)
	case "apiSession":
		return decodeAPISession(ev, fact)
	case "session":
		return decodeSession(ev, fact)
	case "usage":
		return decodeUsage(ev, fact)
	case "sdk":
		return decodeSDK(ev, fact)
	default:
		fact.SemanticStatus = "unknown_namespace"
		return fact, nil
	}
}

// ── Namespace decoders ─────────────────────────────────────────────────────

func decodeAuthentication(ev eventsource.RawVendorEvent, fact VendorFact) (VendorFact, error) {
	var raw struct {
		Namespace  string `json:"namespace"`
		EventType  string `json:"event_type"`
		Timestamp  string `json:"timestamp"`
		Success    bool   `json:"success"`
		Method     string `json:"method"`
		IdentityID string `json:"identity_id"`
		Reason     string `json:"reason"`
	}
	if err := json.Unmarshal(ev.Payload, &raw); err != nil {
		fact.SemanticStatus = "partial"
		return fact, fmt.Errorf("decode authentication: %w", err)
	}
	fact.IdentityID = raw.IdentityID
	fact.AuthSuccess = raw.Success
	fact.AuthMethod = raw.Method
	fact.FailureReason = raw.Reason
	return fact, nil
}

func decodeAPISession(ev eventsource.RawVendorEvent, fact VendorFact) (VendorFact, error) {
	var raw struct {
		Namespace  string `json:"namespace"`
		EventType  string `json:"event_type"`
		IdentityID string `json:"identity_id"`
		// Note: JWT/OIDC sessions may not carry a legacy identity_id.
		// Do NOT treat absence as offline status (spec §5.3).
	}
	if err := json.Unmarshal(ev.Payload, &raw); err != nil {
		fact.SemanticStatus = "partial"
		return fact, fmt.Errorf("decode apiSession: %w", err)
	}
	fact.IdentityID = raw.IdentityID
	return fact, nil
}

func decodeSession(ev eventsource.RawVendorEvent, fact VendorFact) (VendorFact, error) {
	var raw struct {
		Namespace   string `json:"namespace"`
		EventType   string `json:"event_type"`
		SessionType string `json:"session_type"` // "Dial" | "Bind"
		IdentityID  string `json:"identity_id"`
		ServiceID   string `json:"service_id"`
	}
	if err := json.Unmarshal(ev.Payload, &raw); err != nil {
		fact.SemanticStatus = "partial"
		return fact, fmt.Errorf("decode session: %w", err)
	}
	fact.IdentityID = raw.IdentityID
	fact.ServiceID = raw.ServiceID
	fact.SessionType = raw.SessionType
	return fact, nil
}

func decodeUsage(ev eventsource.RawVendorEvent, fact VendorFact) (VendorFact, error) {
	// Usage v3 tags carry clientId / hostId / serviceId.
	// Spec §7.3: usage.v3 tags.clientId/serviceId → access.usage.interval
	var raw struct {
		Namespace string `json:"namespace"`
		EventType string `json:"event_type"`
		Tags      struct {
			ClientID  string `json:"clientId"`
			ServiceID string `json:"serviceId"`
			HostID    string `json:"hostId"`
		} `json:"tags"`
		RxBytes int64 `json:"rx_bytes"`
		TxBytes int64 `json:"tx_bytes"`
	}
	if err := json.Unmarshal(ev.Payload, &raw); err != nil {
		fact.SemanticStatus = "partial"
		return fact, fmt.Errorf("decode usage: %w", err)
	}
	// clientId maps to identity — use it as IdentityID when present.
	fact.IdentityID = raw.Tags.ClientID
	fact.ServiceID = raw.Tags.ServiceID
	fact.UsageBytesRx = raw.RxBytes
	fact.UsageBytesTx = raw.TxBytes
	return fact, nil
}

func decodeSDK(ev eventsource.RawVendorEvent, fact VendorFact) (VendorFact, error) {
	var raw struct {
		Namespace  string `json:"namespace"`
		EventType  string `json:"event_type"` // "sdk-online" | "sdk-offline" | "sdk-status-unknown"
		IdentityID string `json:"identity_id"`
	}
	if err := json.Unmarshal(ev.Payload, &raw); err != nil {
		fact.SemanticStatus = "partial"
		return fact, fmt.Errorf("decode sdk: %w", err)
	}
	fact.IdentityID = raw.IdentityID
	if raw.EventType == "sdk-online" {
		t := true
		fact.SDKOnline = &t
	} else if raw.EventType == "sdk-offline" {
		f := false
		fact.SDKOnline = &f
	}
	return fact, nil
}
