// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package graphpipeline

import (
	"log"
	"net"
	"strings"
)

func ParseExcludeSourceCIDRs(s string) []net.IPNet {
	if s == "" {
		return nil
	}
	var out []net.IPNet
	for _, raw := range strings.Split(s, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			log.Printf("graph: ignoring invalid exclude CIDR %q: %v", raw, err)
			continue
		}
		out = append(out, *cidr)
	}
	return out
}
