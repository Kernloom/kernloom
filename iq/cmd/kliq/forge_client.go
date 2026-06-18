// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kernloom/kernloom/pkg/componentinventory"
	corepolicy "github.com/kernloom/kernloom/pkg/core/policy"
)

// forgeClient is a minimal HTTP client for the forge serve control-plane API.
type forgeClient struct {
	baseURL      string
	enrollToken  string // one-time token used only for the initial enrollment request
	sessionToken string // per-node token returned by Forge after enrollment; used for all subsequent requests
	nodeID       string
	httpClient   *http.Client
}

// newForgeClient creates a forgeClient.
// caPath is the path to a PEM CA certificate for TLS; empty means system roots.
// Returns an error only when caPath is non-empty but cannot be loaded.
func newForgeClient(baseURL, enrollToken, nodeID, caPath string) (*forgeClient, error) {
	transport := http.DefaultTransport
	if caPath != "" {
		pemBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("forge-ca: read %s: %w", caPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("forge-ca: no valid certificates found in %s", caPath)
		}
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		}
	}
	return &forgeClient{
		baseURL:     baseURL,
		enrollToken: enrollToken,
		nodeID:      nodeID,
		httpClient:  &http.Client{Transport: transport, Timeout: 15 * time.Second},
	}, nil
}

// ── request builder ───────────────────────────────────────────────────────────

// do sends an authenticated HTTP request.
// After enrollment, sessionToken is used for all requests.
// Before enrollment (the enrollment request itself), enrollToken is used.
func (c *forgeClient) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	switch {
	case c.sessionToken != "":
		req.Header.Set("Authorization", "Bearer "+c.sessionToken)
	case c.enrollToken != "":
		req.Header.Set("Authorization", "Bearer "+c.enrollToken)
	}
	return c.httpClient.Do(req)
}

// ── Enroll ────────────────────────────────────────────────────────────────────

type enrollRequest struct {
	NodeID       string `json:"node_id"`
	Mode         string `json:"mode"`
	KLIQVersion  string `json:"kliq_version,omitempty"`
	Inventory    any    `json:"inventory,omitempty"`
	ConfigReport any    `json:"config_report,omitempty"`
}

type enrollResponse struct {
	NodeID       string `json:"node_id"`
	Status       string `json:"status"`
	SessionToken string `json:"session_token"` // stored and used for all subsequent requests
	Message      string `json:"message,omitempty"`
}

// SessionToken returns the active session token (empty before enrollment).
func (c *forgeClient) SessionToken() string { return c.sessionToken }

// RestoreSession sets the session token from a persisted state without re-enrolling.
// Call this on startup when a valid session token was saved in the state file.
func (c *forgeClient) RestoreSession(token string) { c.sessionToken = token }

// Enroll sends POST /api/v1/nodes/enroll with the node's inventory and config.
// Returns the node status ("pending", "approved", "rejected").
func (c *forgeClient) Enroll(
	ctx context.Context,
	mode string,
	inv componentinventory.ComponentRuntimeInventory,
	report componentinventory.KliqConfigAssetReport,
) (enrollResponse, error) {
	resp, err := c.do(ctx, http.MethodPost, "/api/v1/nodes/enroll", enrollRequest{
		NodeID:       c.nodeID,
		Mode:         mode,
		KLIQVersion:  "0.4.0",
		Inventory:    inv,
		ConfigReport: report,
	})
	if err != nil {
		return enrollResponse{}, fmt.Errorf("enroll: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return enrollResponse{}, fmt.Errorf("enroll: server returned %d: %s", resp.StatusCode, string(body))
	}
	var er enrollResponse
	if err := json.Unmarshal(body, &er); err != nil {
		return enrollResponse{}, fmt.Errorf("enroll: decode response: %w", err)
	}
	// Store the session token — all subsequent requests use it instead of the one-time token.
	if er.SessionToken != "" {
		c.sessionToken = er.SessionToken
	}
	return er, nil
}

// ── Heartbeat ─────────────────────────────────────────────────────────────────

type heartbeatRequest struct {
	NodeID        string    `json:"node_id"`
	Timestamp     time.Time `json:"timestamp"`
	PackName      string    `json:"pack_name,omitempty"`
	PackVersion   string    `json:"pack_version,omitempty"`
	DriftDetected bool      `json:"drift_detected"`
}

type heartbeatResponse struct {
	PackUpdated bool   `json:"pack_updated"`
	NodeStatus  string `json:"node_status,omitempty"`
	Message     string `json:"message,omitempty"`
}

// Heartbeat sends POST /api/v1/nodes/{id}/heartbeat.
// Returns pack_updated and the node status from Forge.
func (c *forgeClient) Heartbeat(ctx context.Context, packName string, drift bool) (packUpdated bool, nodeStatus string, err error) {
	resp, err := c.do(ctx, http.MethodPost,
		"/api/v1/nodes/"+c.nodeID+"/heartbeat",
		heartbeatRequest{
			NodeID:        c.nodeID,
			Timestamp:     time.Now().UTC(),
			PackName:      packName,
			DriftDetected: drift,
		},
	)
	if err != nil {
		return false, "", fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, "", fmt.Errorf("heartbeat: server returned %d: %s", resp.StatusCode, string(body))
	}
	var hr heartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return false, "", nil // non-fatal
	}
	return hr.PackUpdated, hr.NodeStatus, nil
}

// ── Pull pack ─────────────────────────────────────────────────────────────────

// PullPack fetches GET /api/v1/nodes/{id}/policy-pack.
// Returns the raw signed YAML bytes, or nil if no pack is assigned.
// Returns ErrNotApproved if the node is still pending.
func (c *forgeClient) PullPack(ctx context.Context) ([]byte, string, error) {
	resp, err := c.do(ctx, http.MethodGet,
		"/api/v1/nodes/"+c.nodeID+"/policy-pack", nil)
	if err != nil {
		return nil, "", fmt.Errorf("pull-pack: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, "", fmt.Errorf("pull-pack: read body: %w", err)
		}
		packName := resp.Header.Get("X-Pack-Name")
		return b, packName, nil
	case http.StatusForbidden:
		return nil, "", nil // still pending — not an error, just wait
	case http.StatusNotFound:
		return nil, "", nil // no pack assigned yet
	default:
		return nil, "", fmt.Errorf("pull-pack: server returned %d", resp.StatusCode)
	}
}

// ── Pack status ───────────────────────────────────────────────────────────────

// ReportPackStatus sends POST /api/v1/nodes/{id}/policy-pack/status.
func (c *forgeClient) ReportPackStatus(ctx context.Context, packName string, applied bool, errDetail string) error {
	_, err := c.do(ctx, http.MethodPost,
		"/api/v1/nodes/"+c.nodeID+"/policy-pack/status",
		map[string]any{
			"node_id":      c.nodeID,
			"pack_name":    packName,
			"applied":      applied,
			"error_detail": errDetail,
		},
	)
	return err
}

// ── Runtime bundle ────────────────────────────────────────────────────────────

// PullBundle fetches GET /api/v1/nodes/{id}/runtime-bundle.
// Returns the raw signed YAML bytes and bundle generation, or nil if none assigned.
func (c *forgeClient) PullBundle(ctx context.Context) ([]byte, int, error) {
	resp, err := c.do(ctx, http.MethodGet,
		"/api/v1/nodes/"+c.nodeID+"/runtime-bundle", nil)
	if err != nil {
		return nil, 0, fmt.Errorf("pull-bundle: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, 0, fmt.Errorf("pull-bundle: read body: %w", err)
		}
		gen := 0
		if s := resp.Header.Get("X-Bundle-Generation"); s != "" {
			fmt.Sscanf(s, "%d", &gen)
		}
		return b, gen, nil
	case http.StatusNotFound:
		return nil, 0, nil // no bundle assigned yet
	case http.StatusForbidden:
		return nil, 0, nil // pending or revoked
	default:
		return nil, 0, fmt.Errorf("pull-bundle: server returned %d", resp.StatusCode)
	}
}

// ReportBundleStatus sends POST /api/v1/nodes/{id}/runtime-bundle/status.
func (c *forgeClient) ReportBundleStatus(ctx context.Context, generation int, applied, drift bool, statusJSON, errDetail string) error {
	_, err := c.do(ctx, http.MethodPost,
		"/api/v1/nodes/"+c.nodeID+"/runtime-bundle/status",
		map[string]any{
			"node_id":           c.nodeID,
			"bundle_generation": generation,
			"applied":           applied,
			"drift_detected":    drift,
			"status_json":       statusJSON,
			"error_detail":      errDetail,
		},
	)
	return err
}

// UploadReceipts sends POST /api/v1/nodes/{id}/receipts with a batch of
// EnforcementReceipt objects encoded as JSON. Returns the IDs that the server
// accepted so the caller can mark them uploaded in the local store.
func (c *forgeClient) UploadReceipts(ctx context.Context, receipts []any) ([]string, error) {
	body, err := json.Marshal(map[string]any{"receipts": receipts})
	if err != nil {
		return nil, fmt.Errorf("upload-receipts: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/nodes/"+c.nodeID+"/receipts", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("upload-receipts: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.sessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.sessionToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upload-receipts: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("upload-receipts: server returned %d", resp.StatusCode)
	}
	var result struct {
		Accepted []string `json:"accepted"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	if len(result.Accepted) == 0 {
		// Server didn't return accepted IDs — assume all were accepted.
		ids := make([]string, 0, len(receipts))
		for _, r := range receipts {
			if m, ok := r.(map[string]any); ok {
				if id, ok := m["id"].(string); ok {
					ids = append(ids, id)
				}
			}
		}
		return ids, nil
	}
	return result.Accepted, nil
}

// UploadBaselineProposal sends POST /api/v1/nodes/{id}/baseline-proposals
// with the raw YAML proposal bytes.
func (c *forgeClient) UploadBaselineProposal(ctx context.Context, proposalYAML []byte) (string, error) {
	var bodyReader io.Reader = bytes.NewReader(proposalYAML)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/nodes/"+c.nodeID+"/baseline-proposals", bodyReader)
	if err != nil {
		return "", fmt.Errorf("upload-proposal: %w", err)
	}
	req.Header.Set("Content-Type", "application/yaml")
	if c.sessionToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.sessionToken)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("upload-proposal: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("upload-proposal: server returned %d", resp.StatusCode)
	}
	var result struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&result)
	return result.ID, nil
}

// ── Pack application ──────────────────────────────────────────────────────────

// PackHash returns the SHA-256 hex digest of the given pack bytes.
// Used for drift detection: stored on apply, compared on heartbeat.
func PackHash(packBytes []byte) string {
	h := sha256.Sum256(packBytes)
	return hex.EncodeToString(h[:])
}

// applyForgePack saves the received pack bytes to a temp file, optionally
// verifies the signature, then applies it to cfg via applyPolicyPackToCfg +
// rulesFromPolicyPack. This mirrors the --policy-file path in main().
//
// activeIssuedAt tracks the IssuedAt of the currently running pack. If non-nil
// and non-zero, packs with an earlier IssuedAt are rejected (rollback protection,
// CLAUDE.md rule #9). On success, *activeIssuedAt is updated to the new value.
func applyForgePack(packBytes []byte, packName, verifyKeyPath string, c *cfg, activeIssuedAt *time.Time) error {
	// Write to a temp file so LoadFromFile / LoadAndVerify can read it.
	dir := os.TempDir()
	if c.StatePath != "" {
		dir = filepath.Dir(c.StatePath)
	}
	tmp, err := os.CreateTemp(dir, "forge-pack-*.yaml")
	if err != nil {
		return fmt.Errorf("create temp pack file: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(packBytes); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp pack: %w", err)
	}
	tmp.Close()

	var pp *corepolicy.PolicyPack
	if verifyKeyPath != "" {
		pubKey, err := corepolicy.LoadPublicKey(verifyKeyPath)
		if err != nil {
			return fmt.Errorf("load verify key: %w", err)
		}
		pp, err = corepolicy.LoadAndVerify(tmp.Name(), pubKey)
		if err != nil {
			return fmt.Errorf("load+verify forge pack %s: %w", packName, err)
		}
	} else {
		var err error
		pp, err = corepolicy.LoadFromFile(tmp.Name())
		if err != nil {
			return fmt.Errorf("load forge pack %s: %w", packName, err)
		}
	}

	// Rollback protection: reject a pack whose IssuedAt predates the active pack.
	if activeIssuedAt != nil && !activeIssuedAt.IsZero() {
		if newAt, ok := pp.Metadata.ParseIssuedAt(); ok {
			if newAt.Before(*activeIssuedAt) {
				return fmt.Errorf("rollback rejected: pack %s issued_at %s is before active pack issued_at %s",
					packName, newAt.Format(time.RFC3339), activeIssuedAt.Format(time.RFC3339))
			}
		}
	}

	applyPolicyPackToCfg(pp, c)
	rulesFromPolicyPack(pp, c)

	// Log a human-readable summary of what the pack contains.
	caps := pp.Spec.ActionAuthorization.AllowedCapabilities
	if len(caps) == 0 {
		caps = pp.Spec.CapabilitiesRequired
	}
	kliqLog.Printf("PACK loaded: name=%s rules=%d capabilities=%v default_effect=%s issued=%s",
		packName, len(pp.Spec.Rules), caps,
		pp.Spec.ActionAuthorization.DefaultEffect,
		func() string {
			if t, ok := pp.Metadata.ParseIssuedAt(); ok {
				return t.Format("2006-01-02T15:04Z")
			}
			return "unknown"
		}(),
	)

	// Update the caller's issued_at tracking on success.
	if activeIssuedAt != nil {
		if newAt, ok := pp.Metadata.ParseIssuedAt(); ok {
			*activeIssuedAt = newAt
		}
	}
	return nil
}
