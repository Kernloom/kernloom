// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"bytes"
	"context"
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
	baseURL    string
	enrollKey  string
	nodeID     string
	httpClient *http.Client
}

func newForgeClient(baseURL, enrollKey, nodeID string) *forgeClient {
	return &forgeClient{
		baseURL:    baseURL,
		enrollKey:  enrollKey,
		nodeID:     nodeID,
		httpClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// ── request builder ───────────────────────────────────────────────────────────

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
	if c.enrollKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.enrollKey)
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
	NodeID  string `json:"node_id"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

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

	var er enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return enrollResponse{}, fmt.Errorf("enroll: decode response: %w", err)
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
	Message     string `json:"message,omitempty"`
}

// Heartbeat sends POST /api/v1/nodes/{id}/heartbeat.
// Returns true if Forge signals a new pack is available.
func (c *forgeClient) Heartbeat(ctx context.Context, packName string, drift bool) (bool, error) {
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
		return false, fmt.Errorf("heartbeat: %w", err)
	}
	defer resp.Body.Close()

	var hr heartbeatResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return false, nil // non-fatal
	}
	return hr.PackUpdated, nil
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

// ── Pack application ──────────────────────────────────────────────────────────

// applyForgePack saves the received pack bytes to a temp file, optionally
// verifies the signature, then applies it to cfg via applyPolicyPackToCfg +
// rulesFromPolicyPack. This mirrors the --policy-file path in main().
func applyForgePack(packBytes []byte, packName, verifyKeyPath string, c *cfg) error {
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

	applyPolicyPackToCfg(pp, c)
	rulesFromPolicyPack(pp, c)
	return nil
}
