// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Adrian Enderlin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cilium/ebpf"
)

// Egress BPF map pin paths.
const (
	pinEgressTotals    = "/sys/fs/bpf/kernloom_egress_totals"
	pinEgressDst4Stats = "/sys/fs/bpf/kernloom_egress_dst4_stats"
)

// egressLinkPin returns the sentinel file path used to track TC egress
// attachment state for a given interface.
// The file's existence indicates the interface has an active TC egress filter.
func egressLinkPin(iface string) string {
	return bpfRoot + "/kernloom_egress_link_" + ifaceSafe(iface)
}

// listAttachedEgressIfaces scans bpffs for active TC egress sentinel files.
func listAttachedEgressIfaces() []string {
	entries, _ := os.ReadDir(bpfRoot)
	const prefix = "kernloom_egress_link_"
	var ifaces []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			ifaces = append(ifaces, strings.TrimPrefix(e.Name(), prefix))
		}
	}
	return ifaces
}

// attachEgress attaches the TC egress BPF program to iface.
// It is observe-only: the program never drops or modifies packets.
func attachEgress(iface, obj string, force bool) {
	sentinel := egressLinkPin(iface)

	if exists(sentinel) {
		if !force {
			fmt.Printf("TC egress already attached to %s (sentinel at %s — detach first or use --force)\n", iface, sentinel)
			return
		}
		_ = detachEgressFromIface(iface)
	}

	// Load BPF collection spec.
	spec, err := ebpf.LoadCollectionSpec(obj)
	must(err, "load TC egress BPF object")

	// Reuse pinned maps if they already exist (e.g. from a previous attach).
	repl := map[string]*ebpf.Map{}
	for name, pin := range map[string]string{
		"kernloom_egress_totals":     pinEgressTotals,
		"kernloom_egress_dst4_stats": pinEgressDst4Stats,
	} {
		if m, err := ebpf.LoadPinnedMap(pin, nil); err == nil {
			repl[name] = m
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		MapReplacements: repl,
	})
	must(err, "create TC egress BPF collection")
	defer coll.Close()

	// Pin maps so kliq can read egress telemetry.
	for name, pin := range map[string]string{
		"kernloom_egress_totals":     pinEgressTotals,
		"kernloom_egress_dst4_stats": pinEgressDst4Stats,
	} {
		if _, exists := repl[name]; exists {
			continue // already pinned
		}
		m := coll.Maps[name]
		if m == nil {
			must(fmt.Errorf("map %s not found in BPF object", name), "pin egress map")
		}
		if err := m.Pin(pin); err != nil {
			must(err, "pin egress map "+name)
		}
	}

	// Safety check: warn if interface already has a clsact qdisc (e.g. Cilium).
	out, _ := execCommandOutput("tc", "qdisc", "show", "dev", iface)
	if strings.Contains(out, "clsact") && !force {
		must(fmt.Errorf("interface %s already has a clsact qdisc (Cilium?); use --force to override", iface), "attach TC egress")
	}

	// Create clsact qdisc (idempotent with || true).
	_ = execCommand("tc", "qdisc", "add", "dev", iface, "clsact")

	// Attach TC egress filter using the pinned program.
	// We pin the program so tc can reference it by path.
	progPin := bpfRoot + "/kernloom_egress_prog_" + ifaceSafe(iface)
	_ = os.Remove(progPin)
	prog := coll.Programs["tc_egress"]
	if prog == nil {
		must(fmt.Errorf("tc_egress program not found in BPF object"), "attach TC egress")
	}
	must(prog.Pin(progPin), "pin TC egress program")

	must(
		execCommand("tc", "filter", "add", "dev", iface,
			"egress", "bpf", "direct-action", "pinned", progPin),
		"attach TC egress filter",
	)

	// Write sentinel file to track attachment.
	f, err := os.OpenFile(sentinel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	must(err, "create egress sentinel")
	_ = f.Close()

	fmt.Printf("Attached TC egress to %s (sentinel at %s)\n", iface, sentinel)
}

// detachEgress detaches the TC egress filter from iface.
// When iface is empty it auto-detects if exactly one interface is attached.
func detachEgress(iface string) {
	if iface == "" {
		attached := listAttachedEgressIfaces()
		switch len(attached) {
		case 0:
			fmt.Println("No TC egress interface found.")
			return
		case 1:
			iface = attached[0]
		default:
			fmt.Fprintf(os.Stderr, "Multiple egress interfaces attached: %v\nUse: klshield detach-egress --iface <iface>\n", attached)
			os.Exit(1)
		}
	}
	if err := detachEgressFromIface(iface); err != nil {
		fmt.Fprintf(os.Stderr, "detach-egress: %v\n", err)
		os.Exit(1)
	}
}

// detachEgressFromIface removes the TC egress filter and clsact qdisc from iface.
func detachEgressFromIface(iface string) error {
	sentinel := egressLinkPin(iface)
	if !exists(sentinel) {
		fmt.Printf("No TC egress sentinel found for %s (already detached?)\n", iface)
		return nil
	}

	// Remove TC filter and qdisc. Removing the qdisc removes all filters.
	_ = execCommand("tc", "qdisc", "del", "dev", iface, "clsact")

	// Remove pinned program.
	progPin := bpfRoot + "/kernloom_egress_prog_" + ifaceSafe(iface)
	_ = os.Remove(progPin)

	// Remove sentinel.
	_ = os.Remove(sentinel)

	fmt.Printf("Detached TC egress from %s.\n", iface)
	return nil
}

// cleanupEgressMaps removes the shared egress map pins from bpffs.
// Only call when no interface has TC egress attached.
func cleanupEgressMaps() {
	_ = os.Remove(pinEgressTotals)
	_ = os.Remove(pinEgressDst4Stats)
}

// execCommandOutput runs a command and returns its combined output.
func execCommandOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// egressStats prints aggregate egress counters and top destinations.
func egressStats() {
	fmt.Println("=== Egress Totals ===")
	m, err := ebpf.LoadPinnedMap(pinEgressTotals, nil)
	if err != nil {
		fmt.Printf("egress_totals not available (%v) — is klshield attach-egress running?\n", err)
		return
	}
	defer m.Close()

	type totals struct {
		Pkts  uint64
		Bytes uint64
		TCP   uint64
		UDP   uint64
		ICMP  uint64
		Other uint64
	}
	var sum totals
	var key uint32
	var vals []totals
	if err := m.Lookup(&key, &vals); err == nil {
		for _, v := range vals {
			sum.Pkts += v.Pkts
			sum.Bytes += v.Bytes
			sum.TCP += v.TCP
			sum.UDP += v.UDP
			sum.ICMP += v.ICMP
			sum.Other += v.Other
		}
	}
	fmt.Printf("pkts=%d bytes=%d tcp=%d udp=%d icmp=%d other=%d\n",
		sum.Pkts, sum.Bytes, sum.TCP, sum.UDP, sum.ICMP, sum.Other)

	// Top 10 destinations by bytes.
	dm, err := ebpf.LoadPinnedMap(pinEgressDst4Stats, nil)
	if err != nil {
		return
	}
	defer dm.Close()

	type dstStat struct {
		ip    [4]byte
		pkts  uint64
		bytes uint64
	}
	type dstVal struct {
		Pkts  uint64
		Bytes uint64
	}

	var top []dstStat
	it := dm.Iterate()
	var k [4]byte
	var v dstVal
	for it.Next(&k, &v) {
		top = append(top, dstStat{ip: k, pkts: v.Pkts, bytes: v.Bytes})
	}
	if len(top) == 0 {
		return
	}

	// Sort by bytes descending (simple insertion sort for small N).
	for i := 1; i < len(top); i++ {
		for j := i; j > 0 && top[j].bytes > top[j-1].bytes; j-- {
			top[j], top[j-1] = top[j-1], top[j]
		}
	}

	n := len(top)
	if n > 10 {
		n = 10
	}
	fmt.Printf("\nTop %d egress destinations by bytes:\n", n)
	fmt.Printf("  %-18s %10s %12s\n", "DST_IP", "PKTS", "BYTES")
	for _, d := range top[:n] {
		fmt.Printf("  %-18s %10d %12d\n",
			fmt.Sprintf("%d.%d.%d.%d", d.ip[0], d.ip[1], d.ip[2], d.ip[3]),
			d.pkts, d.bytes)
	}
}
