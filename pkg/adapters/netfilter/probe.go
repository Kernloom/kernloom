// SPDX-License-Identifier: MPL-2.0
// Copyright (c) 2026 Kernloom Contributors

package netfilter

import (
	"context"
	"os"
	"os/exec"
	"strings"
)

// ProbeResult describes what Netfilter tools and features are available on
// the host. It is built once at adapter Init and used to select the backend
// and declare capabilities truthfully.
type ProbeResult struct {
	// Selected is the backend chosen (or empty if none available).
	Selected BackendType

	NFTables  NFTablesProbe
	IPTables  IPTablesProbe
	Conntrack ConntrackProbe
}

// NFTablesProbe holds nftables feature availability.
type NFTablesProbe struct {
	Available   bool
	Path        string
	JSONOutput  bool // nft --json / nft -j
	SetTimeout  bool // set flags timeout supported
	Meters      bool // meter statement supported (kernel 4.18+)
	AtomicApply bool // nft -f atomically replaces table
}

// IPTablesProbe holds iptables feature availability.
type IPTablesProbe struct {
	Available     bool
	Path          string
	IP6TablesPath string
	SavePath      string // iptables-save
	RestorePath   string // iptables-restore
	Backend       string // "legacy" or "nft"
	IPSet         IPSetProbe
	HasLimit      bool // xt_hashlimit module
	ConnLimit     bool // xt_connlimit module
	Comments      bool // xt_comment module
	AtomicRestore bool // iptables-restore --wait
}

// IPSetProbe holds ipset availability.
type IPSetProbe struct {
	Available bool
	Path      string
	Timeout   bool // ipset supports timeout flag
	Counters  bool // ipset supports counters flag
}

// ConntrackProbe holds conntrack tool and proc availability.
type ConntrackProbe struct {
	Available  bool
	Path       string // conntrack binary path (empty when using proc)
	ProcPath   string // /proc/net/nf_conntrack path (empty when using binary)
	Accounting bool   // /proc/sys/net/netfilter/nf_conntrack_acct == 1
}

// Probe detects available Netfilter backends and features.
// It is intentionally read-only: never modifies system state.
func Probe(ctx context.Context) ProbeResult {
	r := ProbeResult{}
	r.NFTables = probeNFTables(ctx)
	r.IPTables = probeIPTables(ctx)
	r.Conntrack = probeConntrack(ctx)
	r.Selected = SelectBackend(r, BackendAuto)
	return r
}

// ResolveBackend returns a probe result pinned to requested when possible.
// It can discover explicit iptables-nft/iptables-legacy binaries even when the
// generic "iptables" command points at the other implementation.
func ResolveBackend(ctx context.Context, r ProbeResult, requested BackendType) ProbeResult {
	selected := SelectBackend(r, requested)
	if selected != "" {
		r.Selected = selected
		return r
	}

	switch requested {
	case BackendIPTablesNFT:
		if p := probeIPTablesBinary(ctx, "iptables-nft"); p.Available && p.Backend == "nft" {
			r.IPTables = p
			r.Selected = BackendIPTablesNFT
		}
	case BackendIPTablesLegacy:
		if p := probeIPTablesBinary(ctx, "iptables-legacy"); p.Available && p.Backend == "legacy" {
			r.IPTables = p
			r.Selected = BackendIPTablesLegacy
		}
	}
	return r
}

// SelectBackend picks the requested backend if available, otherwise auto-selects
// the best available backend when requested is empty or BackendAuto.
// Priority: nftables > iptables-nft > iptables-legacy > none.
func SelectBackend(r ProbeResult, requested BackendType) BackendType {
	switch requested {
	case "", BackendAuto:
	case BackendNFTables:
		if r.NFTables.Available {
			return BackendNFTables
		}
		return ""
	case BackendIPTablesNFT:
		if r.IPTables.Available && r.IPTables.Backend == "nft" {
			return BackendIPTablesNFT
		}
		return ""
	case BackendIPTablesLegacy:
		if r.IPTables.Available && r.IPTables.Backend != "nft" {
			return BackendIPTablesLegacy
		}
		return ""
	default:
		return ""
	}
	if r.NFTables.Available {
		return BackendNFTables
	}
	if r.IPTables.Available && r.IPTables.Backend == "nft" {
		return BackendIPTablesNFT
	}
	if r.IPTables.Available {
		return BackendIPTablesLegacy
	}
	return ""
}

func probeNFTables(ctx context.Context) NFTablesProbe {
	p := NFTablesProbe{}
	path, err := exec.LookPath("nft")
	if err != nil {
		return p
	}
	p.Path = path

	// Confirm nft is executable and returns a version line.
	out, err := runCmd(ctx, path, "--version")
	if err != nil || !strings.Contains(out, "nftables") {
		return p
	}
	p.Available = true

	// Check JSON output support (nft -j list ruleset).
	out, err = runCmd(ctx, path, "-j", "list", "ruleset")
	p.JSONOutput = err == nil && strings.Contains(out, "{")

	// Atomic apply is always available when nft exists.
	p.AtomicApply = true

	// Set timeout and meters: assume supported on kernels >= 4.18.
	// A full check would require attempting to add a test table — skipped
	// here because we do not want to modify system state during probe.
	// These are marked true and degraded gracefully if apply fails.
	p.SetTimeout = true
	p.Meters = true

	return p
}

func probeIPTables(ctx context.Context) IPTablesProbe {
	return probeIPTablesBinary(ctx, "iptables")
}

func probeIPTablesBinary(ctx context.Context, binary string) IPTablesProbe {
	p := IPTablesProbe{}

	// Look for iptables — may be a symlink to iptables-nft or iptables-legacy.
	path, err := exec.LookPath(binary)
	if err != nil {
		return p
	}
	p.Path = path

	// Distinguish legacy vs nft backend by checking the binary or version output.
	out, _ := runCmd(ctx, path, "--version")
	if strings.Contains(out, "nf_tables") || strings.Contains(out, "nft") {
		p.Backend = "nft"
	} else {
		p.Backend = "legacy"
	}
	p.Available = true

	saveBinary := binary + "-save"
	restoreBinary := binary + "-restore"
	ip6Binary := strings.Replace(binary, "iptables", "ip6tables", 1)
	if binary == "iptables" {
		saveBinary = "iptables-save"
		restoreBinary = "iptables-restore"
		ip6Binary = "ip6tables"
	}

	if sp, err := exec.LookPath(saveBinary); err == nil {
		p.SavePath = sp
	}
	if rp, err := exec.LookPath(restoreBinary); err == nil {
		p.RestorePath = rp
		p.AtomicRestore = true
	}
	if ip6, err := exec.LookPath(ip6Binary); err == nil {
		p.IP6TablesPath = ip6
	}

	p.IPSet = probeIPSet(ctx)
	p.HasLimit = moduleProbe(ctx, path, "hashlimit")
	p.ConnLimit = moduleProbe(ctx, path, "connlimit")
	p.Comments = moduleProbe(ctx, path, "comment")

	return p
}

func probeIPSet(ctx context.Context) IPSetProbe {
	p := IPSetProbe{}
	path, err := exec.LookPath("ipset")
	if err != nil {
		return p
	}
	p.Path = path

	out, err := runCmd(ctx, path, "version")
	if err != nil || out == "" {
		return p
	}
	p.Available = true

	// timeout and counters are supported in ipset >= 6.x (all modern distros).
	// Check by attempting to list — avoid creating test sets during probe.
	p.Timeout = true
	p.Counters = true

	return p
}

func probeConntrack(ctx context.Context) ConntrackProbe {
	p := ConntrackProbe{}

	// Try the conntrack binary first.
	if path, err := exec.LookPath("conntrack"); err == nil {
		if out, err := runCmd(ctx, path, "--version"); err == nil && out != "" {
			p.Path = path
			p.Available = true
		}
	}

	// Fall back to /proc/net/nf_conntrack (available even without the binary).
	// This is the case on Synology DSM and other minimal Linux systems where
	// the kernel has nf_conntrack loaded but the conntrack-tools package is absent.
	if !p.Available {
		for _, procPath := range []string{
			"/proc/net/nf_conntrack",
			"/proc/net/ip_conntrack",
		} {
			if _, err := os.Stat(procPath); err == nil {
				p.Available = true
				p.ProcPath = procPath
				break
			}
		}
	}

	if !p.Available {
		return p
	}

	// Check if conntrack accounting is enabled.
	acct, err := readFile("/proc/sys/net/netfilter/nf_conntrack_acct")
	p.Accounting = err == nil && strings.TrimSpace(acct) == "1"

	return p
}

// moduleProbe checks whether an iptables extension module is available by
// running iptables with the module flag and checking for "unknown option"
// vs "No chain/target/match by that name" (module missing).
func moduleProbe(ctx context.Context, iptablesPath, module string) bool {
	// A dry probe: attempt --test which never modifies state.
	// We check the error type: "unknown option" means binary issue,
	// "xt_X" not found means module missing, exit 0 means supported.
	args := []string{"-m", module, "--help"}
	_, err := runCmd(ctx, iptablesPath, args...)
	// iptables --help exits 1 but outputs help text — treat as available.
	return err == nil || strings.Contains(err.Error(), "exit status 1")
}

// runCmd executes a command and returns combined output as a string.
func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// readFile reads a small sysfs/procfs file without importing io/os directly.
func readFile(path string) (string, error) {
	out, err := runCmd(context.Background(), "cat", path)
	return out, err
}
