// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

// Package conntrack provides a Conntrack-based flow observer for the Kernloom
// Netfilter adapter. It periodically snapshots active connections from
// conntrack(8) and publishes them as flow observations on the KLIQ event bus.
//
// Primary consumers:
//   - GraphLearner: receives flow edges (src→dst:port/proto) for learning.
//
// This observer does NOT replace klshield PPS/SYN telemetry — conntrack is
// connection-oriented and cannot provide per-packet rates. It is designed
// for systems where klshield is unavailable.
package conntrack

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/kernloom/kernloom/pkg/adapterruntime"
	"github.com/kernloom/kernloom/pkg/core/observation"
)

var logger = log.New(os.Stderr, "[conntrack] ", log.LstdFlags)

// Config controls the conntrack observer.
type Config struct {
	// ConntrackPath is the path to the conntrack binary.
	// Empty = auto-detected via PATH.
	ConntrackPath string

	// ProcPath is an explicit path to /proc/net/nf_conntrack or /proc/net/ip_conntrack.
	// Used as fallback when the conntrack binary is absent (e.g. Synology DSM).
	// Empty = auto-detected by New() when binary not found.
	ProcPath string

	// PollInterval controls how often conntrack -L is run.
	// Default: 5s.
	PollInterval time.Duration

	// MaxFlows caps the number of flows emitted per poll cycle.
	// Default: 10000.
	MaxFlows int

	// NodeID is attached to every observation for correlation.
	NodeID string
}

// DefaultConfig returns safe defaults.
func DefaultConfig() Config {
	return Config{
		PollInterval: 5 * time.Second,
		MaxFlows:     10000,
	}
}

// procPaths lists the known locations of the kernel conntrack proc file.
var procPaths = []string{
	"/proc/net/nf_conntrack",
	"/proc/net/ip_conntrack", // older kernels
}

// Observer polls conntrack and publishes flow observations on the event bus.
// It prefers the conntrack(8) binary but falls back to reading the kernel
// proc file (/proc/net/nf_conntrack) directly when the binary is absent.
// This makes it usable on Synology DSM and other minimal Linux systems.
type Observer struct {
	cfg      Config
	path     string // conntrack binary path (empty when using proc)
	procPath string // /proc/net/nf_conntrack path (empty when using binary)
}

// New creates a new Observer.
// Priority: conntrack binary > /proc/net/nf_conntrack > /proc/net/ip_conntrack.
// Returns an error only when neither source is available.
func New(cfg Config) (*Observer, error) {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = DefaultConfig().PollInterval
	}
	if cfg.MaxFlows == 0 {
		cfg.MaxFlows = DefaultConfig().MaxFlows
	}

	// Try the binary first.
	binPath := cfg.ConntrackPath
	if binPath == "" {
		binPath, _ = exec.LookPath("conntrack")
	} else if _, err := exec.LookPath(binPath); err != nil {
		binPath = ""
	}
	if binPath != "" {
		return &Observer{cfg: cfg, path: binPath}, nil
	}

	// Fall back to proc file — either explicitly configured or auto-detected.
	candidates := procPaths
	if cfg.ProcPath != "" {
		candidates = []string{cfg.ProcPath}
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			logger.Printf("conntrack binary not found — reading %s directly", p)
			return &Observer{cfg: cfg, procPath: p}, nil
		}
	}

	return nil, fmt.Errorf("conntrack unavailable: binary not found and /proc/net/nf_conntrack does not exist")
}

// Source returns a human-readable description of the data source.
func (o *Observer) Source() string {
	if o.path != "" {
		return "conntrack-binary:" + o.path
	}
	return "proc:" + o.procPath
}

// Start runs the poll loop until ctx is cancelled.
// Observations are published on bus. Errors are logged and retried next cycle.
func (o *Observer) Start(ctx context.Context, bus adapterruntime.EventBus) {
	ticker := time.NewTicker(o.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			o.poll(ctx, bus)
		}
	}
}

func (o *Observer) poll(ctx context.Context, bus adapterruntime.EventBus) {
	flows, err := o.snapshot(ctx)
	if err != nil {
		logger.Printf("snapshot error: %v", err)
		return
	}

	emitted := 0
	for _, f := range flows {
		if emitted >= o.cfg.MaxFlows {
			break
		}
		obs := flowToObservation(f, o.cfg.NodeID)
		if err := bus.PublishObservation(ctx, obs); err != nil {
			return // bus full or shutting down
		}
		emitted++
	}
}

// snapshot returns all current flows from the best available source.
func (o *Observer) snapshot(ctx context.Context) ([]Flow, error) {
	if o.procPath != "" {
		return o.snapshotFromProc()
	}
	return o.snapshotFromBinary(ctx)
}

// snapshotFromProc reads /proc/net/nf_conntrack directly.
func (o *Observer) snapshotFromProc() ([]Flow, error) {
	f, err := os.Open(o.procPath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", o.procPath, err)
	}
	defer f.Close()

	var flows []Flow
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if f, ok := parseNFConntrackLine(line); ok {
			flows = append(flows, f)
		}
	}
	return flows, scanner.Err()
}

// snapshotFromBinary runs "conntrack -L" and returns parsed flows.
func (o *Observer) snapshotFromBinary(ctx context.Context) ([]Flow, error) {
	cmd := exec.CommandContext(ctx, o.path, "-L")
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var flows []Flow
	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if f, ok := parseLine(line); ok {
			flows = append(flows, f)
		}
	}
	_ = cmd.Wait()
	return flows, scanner.Err()
}

// Flow is a parsed conntrack entry.
type Flow struct {
	Proto   string
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	State   string // "ESTABLISHED", "TIME_WAIT", etc. (TCP only)
	Packets uint64
	Bytes   uint64
}

// flowToObservation converts a conntrack Flow into an observation.Observation
// that the GraphLearner can process.
func flowToObservation(f Flow, nodeID string) observation.Observation {
	src := observation.EntityRef{Kind: observation.KindIP, ID: f.SrcIP}
	obs := *observation.NewObservation(
		"netfilter-conntrack",
		observation.TypeFlow,
		nodeID,
		src,
	)

	dstID := f.DstIP
	if f.DstPort > 0 {
		dstID = f.DstIP + ":" + strconv.Itoa(int(f.DstPort))
	}
	obs.SetObject(observation.EntityRef{
		Kind: observation.KindService,
		ID:   dstID,
	})

	// Attribute names match what graphlearner.handleObservation expects.
	obs.SetAttribute("protocol", f.Proto)
	obs.SetAttribute("destination_port", strconv.Itoa(int(f.DstPort)))
	obs.SetAttribute("source_port", strconv.Itoa(int(f.SrcPort)))
	obs.SetAttribute("state", f.State)
	// packets and bytes go into Metrics (float64) not Attributes.
	if f.Packets > 0 {
		obs.SetMetric("packets", float64(f.Packets))
	}
	if f.Bytes > 0 {
		obs.SetMetric("bytes", float64(f.Bytes))
	}
	return obs
}

// parseNFConntrackLine parses one line from /proc/net/nf_conntrack.
//
// The proc format prepends two extra fields vs. conntrack -L:
//
//	ipv4  2  tcp  6  431988 ESTABLISHED src=10.0.0.2 dst=10.0.0.1 ...
//	ipv4  2  udp  17  30 src=10.0.0.2 dst=8.8.8.8 ...
//
// Fields [0] and [1] are the L3 family name/number — we strip them and
// delegate to parseLine which handles the rest identically.
func parseNFConntrackLine(line string) (Flow, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Flow{}, false
	}
	fields := strings.Fields(line)
	// Need at least: l3proto l3num l4proto l4num timeout [fields...]
	if len(fields) < 6 {
		return Flow{}, false
	}
	// Reconstruct the line from field [2] (l4proto) onwards.
	return parseLine(strings.Join(fields[2:], " "))
}

// parseLine parses one line of "conntrack -L" output.
//
// Example conntrack -L lines:
//
//	tcp  6  431999 ESTABLISHED src=10.0.0.2 dst=10.0.0.1 sport=54321 dport=8080 ...
//	udp  17  30 src=10.0.0.2 dst=8.8.8.8 sport=12345 dport=53 ...
func parseLine(line string) (Flow, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return Flow{}, false
	}

	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Flow{}, false
	}

	f := Flow{Proto: strings.ToLower(fields[0])}
	if f.Proto != "tcp" && f.Proto != "udp" && f.Proto != "icmp" {
		return Flow{}, false
	}

	// Parse key=value fields (conntrack -L format).
	// We pick the FIRST occurrence of src/dst/sport/dport (original direction).
	srcSeen, dstSeen := false, false
	for _, field := range fields[3:] {
		kv := strings.SplitN(field, "=", 2)
		if len(kv) != 2 {
			// State word (e.g. "ESTABLISHED") — no "=" sign.
			if f.State == "" && isConnState(field) {
				f.State = field
			}
			continue
		}
		key, val := kv[0], kv[1]
		switch key {
		case "src":
			if !srcSeen {
				f.SrcIP = val
				srcSeen = true
			}
		case "dst":
			if !dstSeen {
				f.DstIP = val
				dstSeen = true
			}
		case "sport":
			if f.SrcPort == 0 {
				if p, err := strconv.ParseUint(val, 10, 16); err == nil {
					f.SrcPort = uint16(p)
				}
			}
		case "dport":
			if f.DstPort == 0 {
				if p, err := strconv.ParseUint(val, 10, 16); err == nil {
					f.DstPort = uint16(p)
				}
			}
		case "packets":
			if f.Packets == 0 {
				if n, err := strconv.ParseUint(val, 10, 64); err == nil {
					f.Packets = n
				}
			}
		case "bytes":
			if f.Bytes == 0 {
				if n, err := strconv.ParseUint(val, 10, 64); err == nil {
					f.Bytes = n
				}
			}
		}
	}

	if f.SrcIP == "" || f.DstIP == "" {
		return Flow{}, false
	}
	return f, true
}

func isConnState(s string) bool {
	switch s {
	case "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT",
		"CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "LISTEN",
		"NEW", "RELATED", "UNREPLIED":
		return true
	}
	return false
}
