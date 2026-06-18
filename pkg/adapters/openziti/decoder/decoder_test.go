// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package decoder_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/kernloom/kernloom/pkg/adapters/openziti/decoder"
	"github.com/kernloom/kernloom/pkg/adapters/openziti/eventsource"
)

func rawEvent(namespace, eventType string, payload map[string]any) eventsource.RawVendorEvent {
	b, _ := json.Marshal(payload)
	return eventsource.RawVendorEvent{
		EventID:    "test-" + namespace,
		Namespace:  namespace,
		EventType:  eventType,
		ObservedAt: time.Now().UTC(),
		Payload:    b,
	}
}

func TestDecodeAuthentication_Success(t *testing.T) {
	ev := rawEvent("authentication", "create", map[string]any{
		"namespace":   "authentication",
		"event_type":  "create",
		"success":     true,
		"method":      "cert",
		"identity_id": "id-alice",
	})
	fact, err := decoder.Decode(ev)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if fact.IdentityID != "id-alice" {
		t.Errorf("IdentityID = %q, want id-alice", fact.IdentityID)
	}
	if !fact.AuthSuccess {
		t.Error("AuthSuccess should be true")
	}
	if fact.AuthMethod != "cert" {
		t.Errorf("AuthMethod = %q, want cert", fact.AuthMethod)
	}
	if fact.SemanticStatus != "ok" {
		t.Errorf("SemanticStatus = %q, want ok", fact.SemanticStatus)
	}
}

func TestDecodeAuthentication_Failure(t *testing.T) {
	ev := rawEvent("authentication", "create", map[string]any{
		"namespace":  "authentication",
		"event_type": "create",
		"success":    false,
		"method":     "updb",
		"reason":     "invalid_credentials",
	})
	fact, err := decoder.Decode(ev)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if fact.AuthSuccess {
		t.Error("AuthSuccess should be false")
	}
	if fact.FailureReason != "invalid_credentials" {
		t.Errorf("FailureReason = %q, want invalid_credentials", fact.FailureReason)
	}
	// Identity may be empty on failure (no identity_id in payload).
	if fact.IdentityID != "" {
		t.Logf("IdentityID present: %s", fact.IdentityID)
	}
}

func TestDecodeSession_Dial(t *testing.T) {
	ev := rawEvent("session", "created", map[string]any{
		"namespace":    "session",
		"event_type":   "created",
		"session_type": "Dial",
		"identity_id":  "id-alice",
		"service_id":   "svc-payroll",
	})
	fact, err := decoder.Decode(ev)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if fact.IdentityID != "id-alice" {
		t.Errorf("IdentityID = %q, want id-alice", fact.IdentityID)
	}
	if fact.ServiceID != "svc-payroll" {
		t.Errorf("ServiceID = %q, want svc-payroll", fact.ServiceID)
	}
	if fact.SessionType != "Dial" {
		t.Errorf("SessionType = %q, want Dial", fact.SessionType)
	}
}

func TestDecodeSession_Bind(t *testing.T) {
	ev := rawEvent("session", "created", map[string]any{
		"namespace":    "session",
		"event_type":   "created",
		"session_type": "Bind",
		"identity_id":  "id-host",
		"service_id":   "svc-payroll",
	})
	fact, err := decoder.Decode(ev)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if fact.SessionType != "Bind" {
		t.Errorf("SessionType = %q, want Bind", fact.SessionType)
	}
}

func TestDecodeUsage_V3(t *testing.T) {
	ev := rawEvent("usage", "usage", map[string]any{
		"namespace":  "usage",
		"event_type": "usage",
		"tags": map[string]any{
			"clientId":  "id-alice",
			"serviceId": "svc-payroll",
			"hostId":    "id-host",
		},
		"rx_bytes": 8192,
		"tx_bytes": 1024,
	})
	fact, err := decoder.Decode(ev)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if fact.IdentityID != "id-alice" {
		t.Errorf("IdentityID = %q, want id-alice (from tags.clientId)", fact.IdentityID)
	}
	if fact.UsageBytesRx != 8192 {
		t.Errorf("UsageBytesRx = %d, want 8192", fact.UsageBytesRx)
	}
}

func TestDecodeSDK_Online(t *testing.T) {
	ev := rawEvent("sdk", "sdk-online", map[string]any{
		"namespace":   "sdk",
		"event_type":  "sdk-online",
		"identity_id": "id-alice",
	})
	fact, err := decoder.Decode(ev)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if fact.SDKOnline == nil || !*fact.SDKOnline {
		t.Error("SDKOnline should be true")
	}
}

func TestDecodeSDK_Offline(t *testing.T) {
	ev := rawEvent("sdk", "sdk-offline", map[string]any{
		"namespace":   "sdk",
		"event_type":  "sdk-offline",
		"identity_id": "id-alice",
	})
	fact, err := decoder.Decode(ev)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if fact.SDKOnline == nil || *fact.SDKOnline {
		t.Error("SDKOnline should be false")
	}
}

// TestDecodeUnknownNamespace verifies that unknown namespaces produce
// SemanticStatus=unknown_namespace, not an error or silent wrong signal.
func TestDecodeUnknownNamespace(t *testing.T) {
	ev := rawEvent("future_unknown_event_v99", "create", map[string]any{"foo": "bar"})
	fact, err := decoder.Decode(ev)
	if err != nil {
		t.Fatalf("unknown namespace should not return error: %v", err)
	}
	if fact.SemanticStatus != "unknown_namespace" {
		t.Errorf("SemanticStatus = %q, want unknown_namespace", fact.SemanticStatus)
	}
}

// TestDecodeToleratesUnknownFields verifies that extra fields in the payload
// do not cause a decode failure (tolerant reader spec §5.2).
func TestDecodeToleratesUnknownFields(t *testing.T) {
	ev := rawEvent("authentication", "create", map[string]any{
		"namespace":       "authentication",
		"event_type":      "create",
		"success":         true,
		"method":          "cert",
		"identity_id":     "id-alice",
		"future_field_v5": "some_value",
		"nested_future":   map[string]any{"x": 1, "y": 2},
	})
	fact, err := decoder.Decode(ev)
	if err != nil {
		t.Fatalf("tolerant reader: unknown fields should not cause error: %v", err)
	}
	if fact.SemanticStatus != "ok" {
		t.Errorf("SemanticStatus = %q, want ok", fact.SemanticStatus)
	}
}
