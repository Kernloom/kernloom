# Kernloom

[![CI](https://github.com/adrianenderlin/kernloom/actions/workflows/ci.yml/badge.svg)](https://github.com/adrianenderlin/kernloom/actions/workflows/ci.yml)

Kernloom is a Linux network security system built on XDP/eBPF. It provides DoS prevention and traffic microsegmentation without touching application code or adding a sidecar proxy.

Two components, one mission:

- **`klshield`** — XDP/eBPF data plane. Attached to a network interface, it enforces deny/rate-limit decisions in the kernel packet path at line rate.
- **`kliq`** — userspace intelligence agent. Reads Shield telemetry, learns traffic baselines, runs the progressive enforcement FSM, manages the communication graph, and writes enforcement decisions back into Shield maps.

Official docs: https://kernloom.com/

---

## Two use cases

Choose your scenario before you start. The operational model is fundamentally different.

### Scenario A — DoS Prevention (public-facing nodes)

**When to use:** The node is reachable from the internet, or from a large number of unknown clients. Think: Ziti controller, Ziti router, public web server, reverse proxy.

**What it does:** kliq learns your node's normal PPS/SYN/scan rates via autotune and rate-limits or blocks sources that deviate significantly. No graph learning, no SQLite, minimal overhead.

**What it does not do:** Microsegmentation. With thousands of rotating internet client IPs, graph learning never converges and would be meaningless.

### Scenario B — Microsegmentation (internal nodes)

**When to use:** The node communicates with a small, known set of internal services. Think: IDP (Keycloak), database, internal API, NAS.

**What it does:** kliq learns the full communication graph (who talks to whom, on which port and protocol). After the graph is frozen, any new or unexpected connection is detected and blocked — optionally down to the exact `(src_ip, port, proto)` tuple in XDP with zero race window.

**What it does not do:** Scale to public internet cardinality. The flow telemetry map holds 32k entries; a public node with 10k+ clients fills it instantly.

---

## Architecture

```
╔═══════════════════════════════════════════════════════════╗
║                   Kernloom IQ  (kliq)                    ║
║                                                          ║
║  Signal Engine      Graph Learner      Source Baseline   ║
║  (autotune PPS/     (edge states,      (per-source EWMA, ║
║   SYN/scan/BPS)      EWMA baseline,    effective trig)   ║
║         │            peak decay)             │            ║
║         └──────────────────┬────────────────┘            ║
║                    Decision Engine                        ║
║                    (FSM + LocalPolicy)                    ║
║                            │                             ║
║                    Shield PEP Adapter                     ║
╚════════════════════════════╪═════════════════════════════╝
                             │ writes eBPF maps
╔════════════════════════════╪═════════════════════════════╗
║           Kernloom Shield  │ (XDP/eBPF)                  ║
║                            │                             ║
║  allowlist → denylist → rate-limit → PASS/DROP           ║
║                                                          ║
║  New in this release: tuple enforcement (edge4_deny /    ║
║  edge4_allow) for per-(src,port,proto) decisions         ║
╚══════════════════════════════════════════════════════════╝
```

---

## Runtime profiles

Kernloom is **modular by design**. Heavy subsystems (graph learning, SQLite, flow telemetry, tuple enforcement) are off by default and enabled explicitly via a runtime profile. This keeps the default hot path minimal.

| Profile | Requires | Active subsystems |
|---|---|---|
| `klshield-light` | klshield only, no kliq | XDP enforce + telemetry. No autotune, no learning. |
| `dos-light` | klshield + kliq | Source heuristic + autotune. No graph, no SQLite. |
| `iq-learning` | klshield + kliq | dos-light + per-source EWMA baseline (lower false positives for busy sources). |
| `graph-learning` | klshield + kliq | iq-learning + flow telemetry + graph learning + edge baselines + SQLite. |
| `graph-enforce` | klshield + kliq | graph-learning + XDP tuple enforcement (edge4_deny / edge4_allow). |

The profile is auto-derived from the `--graph` flag and PDPConfig. Set it explicitly with `--feature-profile` if needed.

```bash
kliq runtime status dos-light        # show what a profile activates
kliq runtime status graph-enforce
kliq runtime status klshield-light   # → no kliq needed
```

---

## Build

### Prerequisites

- Linux with bpffs at `/sys/fs/bpf`
- `clang` ≥ 15, `llvm`, `iproute2`
- Go toolchain matching `go.mod`

```bash
sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
```

### Build

```bash
# BPF object
make -C shield/bpf
# → shield/bpf/out/xdp_kernloom_shield.bpf.o

# Binaries
go build -o klshield ./shield/cmd/klshield
go build -o kliq     ./iq/cmd/kliq

# Tests
go test ./...
```

---

## Quick start — DoS Prevention (Scenario A)

```bash
# 1. Attach Shield to your NIC
sudo ./klshield attach-xdp --iface eth0 \
  --obj shield/bpf/out/xdp_kernloom_shield.bpf.o

# 2. (Optional) Set a global per-source rate limit in XDP
#    Applied instantly by the kernel, before KLIQ reacts.
sudo ./klshield set-default-rl --rate 1000 --burst 2000

# 3. Choose a PDPConfig for your node role
sudo cp configs/pdp/ziti-controller-bootstrap.yaml \
        /opt/kernloom/attested/etc/pdp/node.yaml

# 4. Whitelist monitoring and management IPs
sudo tee /opt/kernloom/attested/etc/whitelist.txt << EOF
203.0.113.10      # monitoring
192.168.1.0/24    # management
EOF

# 5. Bootstrap: 14 days dry-run, autotune learns thresholds
sudo ./kliq \
  --pdp-config=/opt/kernloom/attested/etc/pdp/node.yaml \
  --dry-run=true \
  --whitelist-learn=true

# 6. Watch triggers converge
./kliq status

# 7. Go live
sudo ./kliq \
  --pdp-config=/opt/kernloom/attested/etc/pdp/node.yaml \
  --dry-run=false \
  --whitelist-learn=true
```

See `configs/pdp/` for all PDPConfig profiles. Each file header shows the minimum feature profile and the exact start command.

---

## Quick start — Microsegmentation (Scenario B)

```bash
# 1. Attach Shield
sudo ./klshield attach-xdp --iface eth0 \
  --obj shield/bpf/out/xdp_kernloom_shield.bpf.o

# 2. Choose a PDPConfig for your node role
sudo cp configs/pdp/idp-bootstrap.yaml \
        /opt/kernloom/attested/etc/pdp/node.yaml

# 3. Phase 1 — learn the communication graph (14 days dry-run)
sudo ./kliq \
  --pdp-config=/opt/kernloom/attested/etc/pdp/node.yaml \
  --graph --graph-mode=learn \
  --dry-run=true --whitelist-learn=true

# Monitor
./kliq status
./kliq graph edges --sort=state
./kliq graph baselines --sort=obs

# 4. Phase 2 — review and freeze
./kliq graph freeze --dry-run          # check readiness
sudo ./kliq graph approve-ip 10.0.1.50 # protect known sources
sudo ./kliq graph freeze

# 5. Phase 3 — validate (still dry-run)
sudo ./kliq \
  --pdp-config=/opt/kernloom/attested/etc/pdp/node.yaml \
  --graph --graph-mode=frozen-observe \
  --dry-run=true

# 6a. Go live (source-level enforcement)
sudo ./kliq \
  --pdp-config=/opt/kernloom/attested/etc/pdp/node.yaml \
  --graph --graph-mode=frozen-enforce \
  --dry-run=false

# 6b. Go live (tuple-level enforcement — no first-packet race window)
#     Requires Shield reloaded with edge map support (new .bpf.o)
sudo ./klshield attach-xdp --iface eth0 --force  # reload with new BPF
sudo ./kliq \
  --pdp-config=/opt/kernloom/attested/etc/pdp/node.yaml \
  --feature-profile=graph-enforce \
  --graph --graph-mode=frozen-enforce \
  --dry-run=false
# KLIQ auto-populates edge4_allow on startup from frozen edges.
# Then activate default-deny in XDP:
sudo ./klshield tuple-enforce allow
```

---

## Configuration

### Two axes

**PDPConfig** (`--pdp-config`) — *what* to measure and how aggressively to enforce:
- Signal engine trigger thresholds (cold-start values; autotune refines them)
- Autotune schedule (bootstrap phases, max change per cycle)
- Progressive enforcement parameters (soft_at, hard_at, block_at, TTLs)
- Shield PEP adapter parameters (rate limit values, burst sizes)

**Feature profile** (`--feature-profile`) — *which* subsystems are active (see table above). Auto-derived from `--graph` flag; override explicitly if needed.

### PDPConfig profiles

All profiles live in `configs/pdp/`. Each file header shows:
- Minimum and recommended feature profile
- Ready-to-use start command

| Bootstrap profile | Production profile | Role |
|---|---|---|
| `ziti-controller-bootstrap` | `ziti-controller` | Public Ziti controller |
| `ziti-router-bootstrap` | `ziti-router` | Public Ziti router / NAT gateway |
| `web-server-bootstrap` | `web-server` | Public web server |
| `reverse-proxy-bootstrap` | `reverse-proxy` | Public reverse proxy / load balancer |
| `idp-bootstrap` | `idp` | Identity provider (Keycloak, Authentik, …) |
| `database-bootstrap` | `database` | Database server (PostgreSQL, MySQL, …) |
| `api-server-bootstrap` | `api-server` | Internal API / microservice |
| `nas-bootstrap` | `nas` | NAS / storage (Synology, TrueNAS, …) |

Bootstrap profiles use conservative cold-start values, fast autotune convergence (`max_down: 0.10` in phase 1), and graph learning enabled where appropriate. Production profiles expect a populated `state.json` from bootstrap.

The bootstrap window counts **actual kliq runtime**, not wall-clock time. Process restarts and downtime do not advance the bootstrap phase — the 14-day window only progresses while kliq is actively running and processing clean telemetry. The accumulated runtime is persisted in `state.json` (`observed_seconds`) and survives restarts.

Use `configs/pdp/reference.yaml` as documentation for every available option.

---

## How learning works

### Autotune (all modes)

kliq samples PPS, SYN/s, scan rate, and optionally BPS into a reservoir. Every poll interval (1h in phase 1, 6h in phase 2, 24h in phase 3) it computes `median + K × MAD` and applies a smoothed update to the trigger values. The floor prevents collapse to zero on quiet nodes.

The first hour after startup is critical: triggers start at the cold-start values in the PDPConfig. They only begin to drop after the first autotune cycle. The default rate limit in XDP (`set-default-rl`) provides kernel-level protection before KLIQ reacts.

### Source baseline (iq-learning+)

Per-source IP EWMA tracking of PPS and BPS. Known high-traffic sources get an *effective trigger* (`max(global_trigger, source_peak × 1.2)`) so they don't trip the global guardrail. Unknown sources fall back to the global trigger.

### Edge baseline (graph-learning+)

Per-edge `(src→dst:port/proto)` EWMA with two-phase alpha:
- Bootstrap phase (obs < 30): `alpha = 0.10` (fast convergence)
- Stable phase (obs ≥ 30): `alpha = 0.02` (resistant to short-term spikes)

Running peak per edge with optional half-life decay (`peak_decay_half_life: "336h"`) — a historical spike from two weeks ago is worth 50% of its original value.

### Anti-poisoning

Three independent layers prevent attacks from corrupting baselines:
1. **TrigPPS cap** — observations above the host-level trigger are never written to the baseline buffer
2. **SuspiciousRegistry** — once a signal fires for a source/edge, all buffered observations are retroactively dropped
3. **30s pending buffer** — baseline updates are delayed 30s and dropped if the source/edge was flagged in that window

### Graph lifecycle

```
candidate ──► learned ──► approved ──► frozen
    │             │            │           │
  expired       denied       denied    violation if unknown edge appears
```

**deny-mode** (default after freeze): unknown edges are blacklisted in `edge4_deny` after the first packet passes (~1s poll delay).

**allow-mode** (default-deny): KLIQ populates `edge4_allow` with all frozen/approved edges at startup and every 5 minutes. `tuple-enforce allow` in XDP drops any unknown tuple immediately — no first-packet race window.

---

## klshield command reference

```bash
# Attach / detach
klshield attach-xdp  --iface eth0 [--obj bpf/klshield.bpf.o] [--force]
klshield detach-xdp              [--iface <iface>]   # auto-detects when only one interface is attached
klshield status                # XDP state, RL config, deny counts, tuple mode

# Source allow / deny
klshield add-allow-cidr  <cidr>
klshield list-allow
klshield add-deny-ip     <ip>
klshield del-deny-ip     <ip>
klshield list-deny
klshield enforce-allow   on|off    # drop all sources not in allowlist

# Default kernel rate limit (no KLIQ needed)
klshield set-default-rl  --rate <pps> --burst <n>
klshield disable-default-rl
klshield rl-set-ip       --rate <pps> --burst <n> <ip>
klshield rl-unset-ip     <ip>
klshield list-rl

# Tuple enforcement (requires Shield reload with edge map support)
klshield tuple-enforce   on       # deny-mode: blacklist unknown tuples
klshield tuple-enforce   allow    # allow-mode: block unknown tuples immediately
klshield tuple-enforce   off      # disable tuple checks

# Deny-mode blacklist management
klshield add-edge-deny   --src <ip> --port <n> --proto tcp|udp|icmp
klshield del-edge-deny   --src <ip> --port <n> --proto tcp|udp|icmp
klshield list-edge-deny

# Allow-mode whitelist management
klshield add-edge-allow  --src <ip> --port <n> --proto tcp|udp|icmp
klshield del-edge-allow  --src <ip> --port <n> --proto tcp|udp|icmp
klshield list-edge-allow

# Per-tuple rate limit
klshield set-edge-rl     --src <ip> --port <n> --proto tcp|udp|icmp \
                         --rate <pps> --burst <n>

# Misc
klshield reset            # clear all deny and RL entries
klshield stats            # XDP packet/drop counters
klshield top-src [-n 20] [-by pkts|bytes|drops|droprl]
klshield events           # live XDP ringbuf event stream
```

**After `klshield reset`:** send `SIGUSR1` to kliq to sync FSM state:
```bash
sudo kill -USR1 $(pgrep kliq)
```

---

## kliq command reference

### Subcommands

```bash
kliq status                           # bootstrap phase, autotune triggers, graph summary
kliq runtime status [profile]         # show active feature set for a profile

kliq graph edges [--all] [--sort=last|state|src|port|seen]
kliq graph baselines [--all] [--sort=obs|state|src|port|pps|bps]
kliq graph baselines reset            # zero EWMA stats, keep graph edges
kliq graph freeze [--dry-run]         # freeze learned edges (--dry-run: readiness report)
kliq graph export [--format=json]
kliq graph reset [--all]              # delete candidate/learned edges
kliq graph approve-ip <ip>
kliq graph deny-ip    <ip>
```

### Key flags

| Flag | Default | Description |
|---|---|---|
| `--pdp-config` | `""` | PDPConfig YAML (signal engine, enforcement, graph, adapter params) |
| `--feature-profile` | auto | Runtime feature profile (`dos-light`, `iq-learning`, `graph-learning`, `graph-enforce`) |
| `--graph` | from PDPConfig | Enable graph learning |
| `--graph-mode` | from PDPConfig | `learn`, `frozen-observe`, `frozen-enforce` |
| `--dry-run` | `true` | Observe only; no eBPF map writes |
| `--whitelist` | `/opt/kernloom/attested/etc/whitelist.txt` | IPs never blocked; contribute to autotune |
| `--whitelist-learn` | `false` | Whitelisted IPs contribute to autotune learning |
| `--state-file` | `/var/lib/kernloom/iq/state.json` | Learned autotune trigger values |
| `--bootstrap-allow-block` | `false` | Allow BLOCK during bootstrap (default: cap at RATE_HARD) |

Full flag list: `kliq --help`

---

## Map limits

All eBPF maps are loaded when `klshield attach-xdp` runs, regardless of which kliq feature profile is active.

| Map | Type | Entries | Used by |
|---|---|---|---|
| `xdp_src4_stats` | LRU | 128k IPv4 | Always — source telemetry |
| `xdp_deny_hash` | Hash | 1M IPv4 | Always — source blocklist |
| `xdp_rl_policy4` | Hash | 256k IPv4 | KLIQ rate-limit decisions |
| `xdp_rl_state4` | LRU | 256k IPv4 | XDP token bucket state |
| `xdp_flow4_stats` | LRU | **32k tuples** | Always (written by XDP); read only by graph-learning+ |
| `edge4_deny` | LRU | 65k tuples | tuple-enforce deny-mode |
| `edge4_allow` | LRU | 65k tuples | tuple-enforce allow-mode |
| `edge4_rl_policy` | Hash | 65k tuples | per-edge rate limit |

**Critical limit for graph learning:** `xdp_flow4_stats` holds 32k `(src_ip, dst_port, proto)` entries. A public-facing node with 10k+ concurrent internet clients fills this instantly. Graph learning is only practical when the number of distinct source IPs is well below 32k — i.e. internal nodes with controlled clients.

**Tuple enforcement capacity:** 65k entries covers thousands of edge denies or allowlist entries. For an internal node with 20 known services on 3 ports each, that's 60 entries — far below the limit.

Total locked kernel memory: ~97 MB for all maps combined.

---

## Repo layout

```
kernloom/
├── iq/cmd/kliq/               # Kernloom IQ agent
│   ├── kliq.go                # main loop, adapter wiring, autotune
│   ├── config.go              # CLI flags
│   ├── fsm.go                 # per-source FSM (processCandidate4/6)
│   ├── graph.go               # graph subcommands
│   └── ...
├── shield/
│   ├── bpf/
│   │   └── xdp_kernloom_shield.bpf.c   # XDP program
│   └── cmd/klshield/          # klshield CLI
├── pkg/
│   ├── core/
│   │   ├── featureset/        # RuntimeProfile + FeatureSet
│   │   ├── fsm/               # FSM levels, State, Advance()
│   │   ├── graph/             # GraphEdge model
│   │   ├── signal/            # Signal type catalog
│   │   ├── observation/       # Observation model
│   │   ├── decision/          # Decision + EnforcementReceipt
│   │   ├── enforcement/       # EnforcementTarget (source / edge)
│   │   ├── suspicious/        # SuspiciousRegistry (source + edge level)
│   │   ├── pdp/               # PDPConfig schema + loader
│   │   ├── policy/            # LocalPolicyPack schema + loader
│   │   └── reason/            # Signal reason code constants
│   ├── adapters/
│   │   ├── graphlearner/      # Graph learning + edge baseline adapter
│   │   ├── shieldtelemetry/   # eBPF maps → Observations
│   │   ├── shieldpep/         # Shield PEP: writes deny/rl/allow maps
│   │   └── sourcebaseline/    # Per-source EWMA baseline cache
│   ├── graphstore/sqlite/     # SQLite-backed graph edge store
│   ├── shieldclient/          # Go client for Shield pinned eBPF maps
│   ├── signalengine/
│   │   └── shieldheuristic/   # PPS/SYN/scan/BPS signal engine
│   └── decisionengine/        # Decision engine + LocalPolicy
└── configs/
    ├── pdp/                   # PDPConfig profiles (16 profiles, all roles)
    └── policies/              # LocalPolicyPack examples
```

---

## License

MPL-2.0 — see `LICENSE`.
