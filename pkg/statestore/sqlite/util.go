// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package sqlite

import "database/sql"

func isNoRows(err error) bool {
	return err == sql.ErrNoRows
}
