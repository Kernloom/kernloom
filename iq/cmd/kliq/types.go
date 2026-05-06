// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import "net"

// metrics holds the computed per-source rates for one observation window.
// IP address and version are kept here because kliq uses them for sorting,
// logging and routing to the correct FSM state map.
// Pure FSM logic (strikes, levels, etc.) lives in pkg/core/fsm.
type metrics struct {
	IPVer uint8
	IP4   [4]byte
	IP6   [16]byte

	PPS        float64
	Bps        float64
	SynRate    float64
	ScanRate   float64
	DropRLRate float64
	Severity   float64
}

func (m metrics) ipString() string {
	if m.IPVer == 6 {
		return net.IP(m.IP6[:]).String()
	}
	return net.IPv4(m.IP4[0], m.IP4[1], m.IP4[2], m.IP4[3]).String()
}
