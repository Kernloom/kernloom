// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package mapping translates OpenZiti VendorFacts into canonical Observations.
//
// This is the last package allowed to reference OpenZiti-specific semantics.
// Downstream packages (signal engine, risk engine, graph learner) receive only
// canonical observation types and must never reference OpenZiti field names.
//
// Mapping table (spec §7.3):
//
//	authentication.fail   → observation.TypeAuth (source=SourceZiti, attribute reason=failure)
//	authentication.ok     → observation.TypeAuth (source=SourceZiti, attribute reason=success)
//	apiSession.*          → observation.TypeConnection (session activity)
//	session.created Dial  → observation.TypeConnection (strong basis for graph learning)
//	session.created Bind  → observation.TypeConnection (service host, distinct from user dial)
//	usage.v3              → observation.TypeFlow (bytes rx/tx, identity-attributed)
//	sdk.online/offline    → observation.TypeConnection (connectivity status)
//
// CRITICAL: service.dial.fail is NOT mapped here — it is an aggregated service
// metric, not an identity-attributed event. Mapping it to identity risk would
// violate spec §7.4. It produces a resource-scoped observation only.
package mapping

import (
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/openziti/decoder"
	"github.com/kernloom/kernloom/pkg/core/entity"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

const (
	// adapterSourceName is the canonical source string for all OpenZiti observations.
	// Defined here so adapters pass their own string, not a core constant (see doc 17).
	adapterSourceName observation.ObservationSource = "openziti"
	nodeIDPlaceholder                               = "openziti-node"
)

// ToObservations converts an OpenZiti VendorFact into zero or more canonical
// Observations. Returns nil when the fact has no canonical mapping.
//
// Identity attribution rules:
//   - Only map to KindUser/KindWorkload when IdentityID is explicitly present in the fact.
//   - Never fabricate a subject identity from aggregated service metrics.
func ToObservations(fact decoder.VendorFact, nodeID string) []observation.Observation {
	if nodeID == "" {
		nodeID = nodeIDPlaceholder
	}
	switch fact.Namespace {
	case "authentication":
		return mapAuthentication(fact, nodeID)
	case "apiSession":
		return mapAPISession(fact, nodeID)
	case "session":
		return mapSession(fact, nodeID)
	case "usage":
		return mapUsage(fact, nodeID)
	case "sdk":
		return mapSDK(fact, nodeID)
	default:
		return nil
	}
}

func mapAuthentication(fact decoder.VendorFact, nodeID string) []observation.Observation {
	subject := entity.Ref{Kind: entity.KindUser, ID: fact.IdentityID}
	if fact.IdentityID == "" {
		// Authentication failure without identity (e.g. unknown identity attempt).
		// Scope to source, not to an identity (spec §7.4 / §10.4).
		subject = entity.Ref{Kind: entity.KindNode, ID: "unresolved"}
	}
	obs := observation.NewObservation(adapterSourceName, observation.TypeAuth, nodeID,
		observation.EntityRef(subject))
	if fact.AuthSuccess {
		obs.SetAttribute("reason", "success")
	} else {
		obs.SetAttribute("reason", "failure")
		obs.SetAttribute("failure_reason", fact.FailureReason)
	}
	obs.SetAttribute("auth_method", fact.AuthMethod)
	obs.Time = fact.ObservedAt
	return []observation.Observation{*obs}
}

func mapAPISession(fact decoder.VendorFact, nodeID string) []observation.Observation {
	if fact.IdentityID == "" {
		// OIDC/JWT sessions may not have a legacy identity_id — skip rather than
		// treating absence as an offline signal (spec §5.3).
		return nil
	}
	subject := entity.Ref{Kind: entity.KindUser, ID: fact.IdentityID}
	obs := observation.NewObservation(adapterSourceName, observation.TypeConnection, nodeID,
		observation.EntityRef(subject))
	obs.SetAttribute("session_event", fact.EventType)
	obs.Time = fact.ObservedAt
	return []observation.Observation{*obs}
}

func mapSession(fact decoder.VendorFact, nodeID string) []observation.Observation {
	if fact.IdentityID == "" || fact.ServiceID == "" {
		return nil
	}
	subject := entity.Ref{Kind: entity.KindUser, ID: fact.IdentityID}
	object := entity.Ref{Kind: entity.KindService, ID: fact.ServiceID}
	obs := observation.NewObservation(adapterSourceName, observation.TypeConnection, nodeID,
		observation.EntityRef(subject))
	obs.SetObject(observation.EntityRef(object))
	obs.SetAttribute("session_type", fact.SessionType) // "Dial" or "Bind"
	obs.Time = fact.ObservedAt

	// Dial sessions are the primary source for graph learning.
	// Bind sessions indicate service hosting — distinct semantics, don't conflate.
	obs.SetAttribute("is_dial", boolStr(fact.SessionType == "Dial"))
	obs.SetAttribute("is_bind", boolStr(fact.SessionType == "Bind"))
	return []observation.Observation{*obs}
}

func mapUsage(fact decoder.VendorFact, nodeID string) []observation.Observation {
	if fact.IdentityID == "" {
		// Usage without clientId — cannot attribute to an identity.
		// Spec §7.3: usage v3 tags.clientId is required for identity-aware usage.
		return nil
	}
	subject := entity.Ref{Kind: entity.KindUser, ID: fact.IdentityID}
	obs := observation.NewObservation(adapterSourceName, observation.TypeFlow, nodeID,
		observation.EntityRef(subject))
	if fact.ServiceID != "" {
		obs.SetObject(observation.EntityRef(entity.Ref{Kind: entity.KindService, ID: fact.ServiceID}))
	}
	obs.SetMetric("bytes_rx", float64(fact.UsageBytesRx))
	obs.SetMetric("bytes_tx", float64(fact.UsageBytesTx))
	obs.Time = fact.ObservedAt
	return []observation.Observation{*obs}
}

func mapSDK(fact decoder.VendorFact, nodeID string) []observation.Observation {
	if fact.IdentityID == "" {
		return nil
	}
	subject := entity.Ref{Kind: entity.KindUser, ID: fact.IdentityID}
	obs := observation.NewObservation(adapterSourceName, observation.TypeConnection, nodeID,
		observation.EntityRef(subject))
	if fact.SDKOnline != nil {
		if *fact.SDKOnline {
			obs.SetAttribute("connectivity_status", "online")
		} else {
			obs.SetAttribute("connectivity_status", "offline")
		}
	} else {
		obs.SetAttribute("connectivity_status", "unknown")
	}
	obs.Time = fact.ObservedAt
	return []observation.Observation{*obs}
}

// boolStr converts a bool to "true"/"false" for observation attributes.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// CurrentTime returns the current UTC time. Exported for testing.
func CurrentTime() time.Time { return time.Now().UTC() }
