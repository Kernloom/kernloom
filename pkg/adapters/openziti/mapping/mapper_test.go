// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package mapping_test

import (
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/openziti/decoder"
	"github.com/kernloom/kernloom/pkg/adapters/openziti/mapping"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

func fact(ns, evt, identityID, serviceID, sessionType string) decoder.VendorFact {
	return decoder.VendorFact{
		Namespace:      ns,
		EventType:      evt,
		ObservedAt:     time.Now().UTC(),
		IdentityID:     identityID,
		ServiceID:      serviceID,
		SessionType:    sessionType,
		SemanticStatus: "ok",
	}
}

// TestMappingNoVendorFieldNames is the contract test: canonical observations
// must not contain any OpenZiti-specific field names as attribute keys.
func TestMappingNoVendorFieldNames(t *testing.T) {
	forbidden := []string{
		"zitiIdentityId", "zitiServiceId", "zitiSessionId",
		"openziti.identity_id", "ziti_identity", "zitiDialFailure",
		"zitiPostureCheck", "openzitiNamespace",
	}

	facts := []decoder.VendorFact{
		fact("session", "created", "id-alice", "svc-pay", "Dial"),
		fact("authentication", "create", "id-alice", "", ""),
		fact("usage", "usage", "id-alice", "svc-pay", ""),
		fact("sdk", "sdk-online", "id-alice", "", ""),
	}

	for _, f := range facts {
		if f.Namespace == "usage" {
			f.UsageBytesRx = 4096
		}
		if f.Namespace == "sdk" {
			t2 := true
			f.SDKOnline = &t2
		}
		obs := mapping.ToObservations(f, "node-1")
		for _, o := range obs {
			for k := range o.Attributes {
				for _, banned := range forbidden {
					if k == banned {
						t.Errorf("observation attribute %q is a vendor-specific field name", k)
					}
				}
			}
		}
	}
}

func TestMapSession_Dial_ProducesObservation(t *testing.T) {
	f := fact("session", "created", "id-alice", "svc-payroll", "Dial")
	obs := mapping.ToObservations(f, "node-1")
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	o := obs[0]
	if o.Type != observation.TypeConnection {
		t.Errorf("Type = %v, want TypeConnection", o.Type)
	}
	if o.Subject.ID != "id-alice" {
		t.Errorf("Subject.ID = %q, want id-alice", o.Subject.ID)
	}
	if o.Object.ID != "svc-payroll" {
		t.Errorf("Object.ID = %q, want svc-payroll", o.Object.ID)
	}
	if o.Attributes["is_dial"] != "true" {
		t.Errorf("is_dial = %q, want true", o.Attributes["is_dial"])
	}
}

func TestMapSession_Bind_IsDistinct(t *testing.T) {
	f := fact("session", "created", "id-host", "svc-payroll", "Bind")
	obs := mapping.ToObservations(f, "node-1")
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	if obs[0].Attributes["is_bind"] != "true" {
		t.Error("Bind session should have is_bind=true")
	}
	if obs[0].Attributes["is_dial"] == "true" {
		t.Error("Bind session must not have is_dial=true")
	}
}

func TestMapAuth_FailureWithoutIdentity(t *testing.T) {
	// Auth failure without an identity_id → scoped to "unresolved", not fabricated
	f := decoder.VendorFact{
		Namespace:      "authentication",
		EventType:      "create",
		ObservedAt:     time.Now().UTC(),
		AuthSuccess:    false,
		FailureReason:  "invalid_credentials",
		SemanticStatus: "ok",
	}
	obs := mapping.ToObservations(f, "node-1")
	if len(obs) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(obs))
	}
	o := obs[0]
	// Subject must NOT be a fabricated identity ID
	if o.Subject.ID != "unresolved" {
		t.Errorf("Subject.ID = %q, want unresolved (no identity_id in event)", o.Subject.ID)
	}
}

func TestMapUsage_NoClientID_ProducesNothing(t *testing.T) {
	// Usage without clientId cannot be identity-attributed (spec §7.3)
	f := decoder.VendorFact{
		Namespace:      "usage",
		EventType:      "usage",
		ObservedAt:     time.Now().UTC(),
		ServiceID:      "svc-payroll",
		UsageBytesRx:   1024,
		SemanticStatus: "ok",
		// IdentityID deliberately empty
	}
	obs := mapping.ToObservations(f, "node-1")
	if len(obs) != 0 {
		t.Errorf("usage without clientId should produce 0 observations, got %d", len(obs))
	}
}

func TestMapUnknownNamespace_ProducesNothing(t *testing.T) {
	f := decoder.VendorFact{
		Namespace:      "future_namespace_v99",
		SemanticStatus: "unknown_namespace",
		ObservedAt:     time.Now().UTC(),
	}
	obs := mapping.ToObservations(f, "node-1")
	if len(obs) != 0 {
		t.Errorf("unknown namespace should produce 0 observations, got %d", len(obs))
	}
}
