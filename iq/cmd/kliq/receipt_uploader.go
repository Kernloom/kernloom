// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

// receiptUploader is the offline-queue goroutine that periodically reads
// pending EnforcementReceipts from the SQLite store and uploads them to Forge.
//
// Receipts are persisted by brokeredActionExecutor.persistReceipt() immediately
// after enforcement. The uploader picks them up asynchronously so that a Forge
// outage never blocks the enforcement hot path.
//
// The uploader only runs when a Forge client is available (managed mode).
// In standalone mode the receipts remain in the DB and are uploaded once a
// Forge connection is established.

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/kernloom/kernloom/pkg/core/decision"
	"github.com/kernloom/kernloom/pkg/statestore/sqlite"
)

const (
	receiptUploadBatchSize = 50
	receiptUploadInterval  = 30 * time.Second
	receiptRetentionPeriod = 7 * 24 * time.Hour // prune uploaded receipts after 7 days
)

// receiptUploadStore is the minimal store interface needed by the uploader.
type receiptUploadStore interface {
	ListPendingReceipts(ctx context.Context, limit int) ([]decision.EnforcementReceipt, error)
	MarkReceiptsUploaded(ctx context.Context, ids []string) error
	MarkReceiptsFailed(ctx context.Context, ids []string) error
	PruneUploadedReceipts(ctx context.Context, cutoff time.Time) (int64, error)
}

// receiptUploader provides UploadReceipts compatible with *forgeClient.
type receiptUploader interface {
	UploadReceipts(ctx context.Context, receipts []any) ([]string, error)
}

// startReceiptUploader launches the background upload goroutine.
// It terminates when ctx is cancelled.
func startReceiptUploader(
	ctx context.Context,
	store *sqlite.Store,
	client receiptUploader,
	logger *log.Logger,
) {
	if store == nil || client == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(receiptUploadInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				uploadPendingReceipts(ctx, store, client, logger)
				pruneOldReceipts(ctx, store, logger)
			}
		}
	}()
}

func uploadPendingReceipts(
	ctx context.Context,
	store receiptUploadStore,
	client receiptUploader,
	logger *log.Logger,
) {
	receipts, err := store.ListPendingReceipts(ctx, receiptUploadBatchSize)
	if err != nil {
		logger.Printf("[receipt-uploader] list pending: %v", err)
		return
	}
	if len(receipts) == 0 {
		return
	}

	// Convert to generic map slice for JSON encoding so the wire format
	// matches contracts.EnforcementReceipt without a hard import dependency.
	payload := make([]any, 0, len(receipts))
	ids := make([]string, 0, len(receipts))
	for _, r := range receipts {
		b, err := json.Marshal(r)
		if err != nil {
			logger.Printf("[receipt-uploader] marshal receipt %s: %v", r.ID, err)
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			continue
		}
		payload = append(payload, m)
		ids = append(ids, r.ID)
	}

	accepted, err := client.UploadReceipts(ctx, payload)
	if err != nil {
		logger.Printf("[receipt-uploader] upload %d receipts failed: %v", len(ids), err)
		_ = store.MarkReceiptsFailed(ctx, ids)
		return
	}

	if err := store.MarkReceiptsUploaded(ctx, accepted); err != nil {
		logger.Printf("[receipt-uploader] mark uploaded: %v", err)
	}
	logger.Printf("[receipt-uploader] uploaded %d/%d receipts", len(accepted), len(ids))
}

func pruneOldReceipts(ctx context.Context, store receiptUploadStore, logger *log.Logger) {
	cutoff := time.Now().Add(-receiptRetentionPeriod)
	n, err := store.PruneUploadedReceipts(ctx, cutoff)
	if err != nil {
		logger.Printf("[receipt-uploader] prune: %v", err)
		return
	}
	if n > 0 {
		logger.Printf("[receipt-uploader] pruned %d uploaded receipts", n)
	}
}
