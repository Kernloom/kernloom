// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package componentinventory keeps the historical KLIQ import path for runtime
// inventory types. The wire contracts live in kernloom-contracts.
package componentinventory

import contracts "github.com/kernloom/kernloom-contracts"

type CapabilityStatus = contracts.ComponentCapabilityStatus
type ComponentRuntimeInventory = contracts.ComponentInventory
