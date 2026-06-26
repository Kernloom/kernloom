// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package main

import (
	"strings"
)

func resolveRuntimeAlertFile(c cfg) string {
	value := strings.TrimSpace(c.AlertFile)
	switch strings.ToLower(value) {
	case "none", "off", "disabled", "false":
		return ""
	case "":
		return ""
	default:
		return value
	}
}
