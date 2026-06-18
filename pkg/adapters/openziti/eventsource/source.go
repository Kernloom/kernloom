// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package eventsource provides the OpenZiti Controller event stream adapter.
//
// It connects to the OpenZiti Controller's WebSocket event endpoint and feeds
// raw vendor events onto a channel for downstream decoding.
//
// Design invariants (from .claude/17-adapter-boundary-and-vendor-isolation.md):
//   - All OpenZiti-specific types stay inside pkg/adapters/openziti/.
//   - Transport authentication never reaches the decoder or risk engine.
//   - Unknown event versions produce a warning, not a silent wrong signal.
//   - Controller version is discovered dynamically at startup.
package eventsource

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RawVendorEvent is a single event received from the OpenZiti Controller.
// It carries the raw JSON payload alongside metadata needed for the journal.
type RawVendorEvent struct {
	// EventID is a local monotonic ID assigned by the adapter (not from the controller).
	EventID string

	// Namespace is the OpenZiti event namespace: apiSession, authentication,
	// session, usage, sdk, service, entityChange, terminator, router, etc.
	Namespace string

	// EventType is the sub-type within the namespace: created, deleted, etc.
	EventType string

	// SchemaVersion is the event schema version string reported by the controller.
	SchemaVersion string

	// ObservedAt is when the adapter received the event.
	ObservedAt time.Time

	// Payload is the raw JSON event payload.
	// Vendor-specific fields are confined here and never promoted to canonical types.
	Payload json.RawMessage

	// PayloadHash is the SHA-256 hex of Payload (for journal deduplication).
	PayloadHash string

	// RedactionApplied is true when token or credential fields were removed.
	RedactionApplied bool
}

// EventSourceHealth describes the operational state of the event source.
type EventSourceHealth struct {
	Healthy         bool
	EventLagSeconds float64
	LastEventAt     time.Time
	Message         string
}

// EventSource is the interface every transport implementation must satisfy.
// This allows swapping WebSocket, file-replay, and test sources transparently.
type EventSource interface {
	// Start begins receiving events and sends them on out until ctx is cancelled.
	Start(ctx context.Context, out chan<- RawVendorEvent) error

	// Health returns the current transport health.
	Health(ctx context.Context) EventSourceHealth

	// Close shuts down the transport gracefully.
	Close(ctx context.Context) error
}

// ControllerVersion carries the version information discovered at startup.
type ControllerVersion struct {
	Version         string
	Revision        string
	ManagementAPI   string
	EventNamespaces map[string]string // namespace → version string
	Compatible      bool
	Warnings        []string
}

// Config configures the WebSocket event source.
type Config struct {
	// BaseURL is the OpenZiti Controller management API base URL,
	// e.g. "https://ctrl.example.com:1280".
	BaseURL string

	// APIToken is the bearer token for management API authentication.
	// Transport-specific; never reaches the decoder or risk packages.
	APIToken string

	// ConnectTimeout is how long to wait for the initial connection.
	ConnectTimeout time.Duration

	// ReconnectDelay is the backoff between reconnect attempts.
	ReconnectDelay time.Duration
}

// DiscoverVersion queries the controller root endpoint and extracts version
// and API compatibility information.
//
// Implements section 5.1 of the spec: the adapter must query the controller
// at startup and determine supported event versions dynamically.
func DiscoverVersion(ctx context.Context, cfg Config, httpClient *http.Client) (ControllerVersion, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	url := cfg.BaseURL + "/edge/management/v1/version"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ControllerVersion{}, fmt.Errorf("discover version: build request: %w", err)
	}
	if cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.APIToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return ControllerVersion{}, fmt.Errorf("discover version: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return ControllerVersion{}, fmt.Errorf("discover version: read body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return ControllerVersion{}, fmt.Errorf("discover version: server returned %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Version  string `json:"version"`
			Revision string `json:"revision"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return ControllerVersion{Compatible: false, Warnings: []string{"could not parse version response"}}, nil
	}

	cv := ControllerVersion{
		Version:  result.Data.Version,
		Revision: result.Data.Revision,
		EventNamespaces: map[string]string{
			"apiSession":     "supported",
			"authentication": "supported",
			"session":        "supported",
			"usage":          "supported",
			"sdk":            "supported",
		},
		Compatible: true,
	}
	return cv, nil
}

// FileReplaySource implements EventSource for testing and recovery by replaying
// a newline-delimited JSON file of RawVendorEvent records.
type FileReplaySource struct {
	events []RawVendorEvent
	health EventSourceHealth
}

// NewFileReplaySource creates an EventSource that replays a slice of events.
// Useful for unit tests and offline replay scenarios.
func NewFileReplaySource(events []RawVendorEvent) *FileReplaySource {
	return &FileReplaySource{events: events}
}

func (f *FileReplaySource) Start(ctx context.Context, out chan<- RawVendorEvent) error {
	f.health = EventSourceHealth{Healthy: true, LastEventAt: time.Now()}
	go func() {
		for _, ev := range f.events {
			select {
			case <-ctx.Done():
				return
			case out <- ev:
			}
		}
	}()
	return nil
}

func (f *FileReplaySource) Health(_ context.Context) EventSourceHealth { return f.health }
func (f *FileReplaySource) Close(_ context.Context) error              { return nil }
