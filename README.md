# Kernloom Shield + Kernloom IQ

Kernloom consists of two core components:

- **Kernloom Shield** (`klshield`) — the **XDP/eBPF data plane** (ingress enforcement + telemetry)
- **Kernloom IQ** (`kliq`) — the **userspace intelligence agent** (scoring, graph learning, decision engine, progressive enforcement)

Official docs:
- https://kernloom.com/kernloom-shield/
- https://kernloom.com/kernloom-iq/

---

## Architecture

```
 ┌─────────────────────────────────────────────────────────┐
 │                     Kernloom IQ (kliq)                  │
 │                                                         │
 │  Shield Telemetry Adapter  →  Signal Engine             │
 │                                    │                    │
 │                             Graph Learner               │
 │                                    │                    │
 │                            Decision Engine              │
 │                                    │                    │
 │                           Shield PEP Adapter            │
 └─────────────────────────────────────────────────────────┘
               reads maps ↑        ↓ writes maps
 ┌─────────────────────────────────────────────────────────┐
 │              Kernloom Shield (XDP/eBPF)                 │
 │  allowlist  →  denylist  →  rate-limit  →  PASS/DROP   │
 └─────────────────────────────────────────────────────────┘
```

### Shield (XDP ingress pipeline)

Packet processing order:

1. **Allowlist** (CIDR LPM trie) — optional allowlist enforcement
2. **Denylist** (IP hash map)
3. **Rate limit** (token-bucket per source; global defaults + per-IP overrides)
4. PASS / DROP

Telemetry collected:

- per-CPU packet/byte totals
- per-source stats (IPv4 + IPv6, separate maps)
- port/packet-length histograms
- optional ringbuf drop events (sampled) for scan hints

### IQ (intelligence agent)

Every tick, IQ runs the following pipeline:

1. **Telemetry ingest** — reads per-source deltas from Shield eBPF maps
2. **Signal engine** — computes heuristic signals: PPS spike, SYN rate, port-scan detection, rate-limit drop pressure
3. **Graph learner** — records observed flows as graph edges; promotes candidates to learned over time; optionally emits `graph.new_edge_after_freeze` signals when in frozen-observe mode
4. **Decision engine** — translates signals and FSM transitions into auditable `Decision` structs with reason codes; enforces through the PEP adapter; logs every decision
5. **FSM** — per-IP state machine: `OBSERVE → RATE_SOFT → RATE_HARD → BLOCK` driven by severity scores
6. **Shield PEP adapter** — writes enforcement decisions back to Shield maps (deny4/deny6, rl-override)

---

## Repo layout

```text
kernloom/
├── iq/
│   └── cmd/kliq/               # Kernloom IQ CLI
│       ├── kliq.go             # main loop, adapter wiring
│       ├── config.go           # all CLI flags + Config struct
│       ├── fsm.go              # per-IP FSM transitions
│       ├── state.go            # autotune state persistence
│       ├── profiles.go         # built-in config profiles
│       ├── whitelist.go        # whitelist/feedback file loading
│       ├── reservoir.go        # signal reservoir / rolling window
│       ├── helpers.go          # IP helpers, CIDR parsing
│       ├── feedback.go         # feedback file handling
│       └── types.go            # internal types
├── shield/
│   ├── bpf/
│   │   ├── xdp_kernloom_shield.bpf.c   # XDP program
│   │   └── include/vmlinux.h
│   └── cmd/klshield/           # Kernloom Shield CLI
└── pkg/
    ├── core/
    │   ├── observation/        # Observation model (flows, auth, drops, …)
    │   ├── signal/             # Signal model + signal type catalog
    │   ├── decision/           # Decision + EnforcementReceipt models
    │   ├── reason/             # standardised reason code constants
    │   ├── capability/         # Capability model
    │   ├── graph/              # GraphEdge model, PromotionConfig, EdgeState
    │   └── fsm/                # FSM level definitions
    ├── adapterruntime/         # Adapter interface, EventBus, well-known capabilities
    ├── adapters/
    │   ├── graphlearner/       # Graph learning adapter (flow obs → edges, freeze signals)
    │   └── shieldtelemetry/    # Shield telemetry adapter (eBPF maps → Observations)
    ├── decisionengine/         # Decision Engine (signal → Decision → PEP receipt)
    │   ├── engine.go
    │   ├── shieldbridge.go     # Shield PEP adapter implementation
    │   └── engine_test.go
    ├── graphstore/sqlite/      # SQLite-backed graph edge store
    ├── shieldclient/           # Go client for Shield pinned eBPF maps
    └── signalengine/
        └── shieldheuristic/    # PPS / SYN / scan / drop-RL heuristic engine
```

---

## Build

### Prerequisites

- Linux with bpffs at `/sys/fs/bpf`
- Tools: `clang`, `llvm`, `bpftool`, `iproute2`
- Go toolchain matching `go.mod`

Mount bpffs if needed:
```bash
sudo mount -t bpf bpf /sys/fs/bpf || true
```

### Build the BPF object (Shield)

```bash
make -C shield/bpf
```

Output: `shield/bpf/out/xdp_kernloom_shield.bpf.o`

Manual equivalent:
```bash
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -c shield/bpf/xdp_kernloom_shield.bpf.c \
  -o shield/bpf/out/xdp_kernloom_shield.bpf.o
```

### Build the CLIs

```bash
mkdir -p bin
go build -o bin/klshield ./shield/cmd/klshield
go build -o bin/kliq    ./iq/cmd/kliq
```

### Run tests

```bash
go test ./...
```

---

## Quick start

### 1. Attach Shield to a network interface

```bash
sudo ./bin/klshield attach-xdp -iface eth0 -obj shield/bpf/out/xdp_kernloom_shield.bpf.o -force
```

Verify:
```bash
sudo ./bin/klshield stats
sudo ./bin/klshield top-src -n 20 -by pkts
```

### 2. Optional: Add allowlist / deny entries

```bash
# Allowlist mode (recommended for public-facing nodes)
sudo ./bin/klshield add-allow-cidr 203.0.113.0/24
sudo ./bin/klshield enforce-allow on

# Deny a single IP
sudo ./bin/klshield add-deny-ip 203.0.113.55

# Rate limit (global)
sudo ./bin/klshield rl-set -rate 1200 -burst 2400
```

### 3. Prepare IQ directories

```bash
sudo mkdir -p /etc/kernloom/iq /var/lib/kernloom/iq
sudo touch /etc/kernloom/iq/whitelist.txt
sudo chmod 644 /etc/kernloom/iq/whitelist.txt
echo "[]" | sudo tee /var/lib/kernloom/iq/feedback.json > /dev/null
sudo chmod 600 /var/lib/kernloom/iq/feedback.json
```

For graph learning:
```bash
sudo mkdir -p /var/lib/kernloom/iq    # graph.db lives here
```

### 4. Run IQ

**Observe only (no enforcement):**
```bash
sudo ./bin/kliq -dry-run=true -interval 1s
```

**Enforce (heuristic FSM only):**
```bash
sudo ./bin/kliq -dry-run=false -interval 1s
```

**With graph learning enabled:**
```bash
sudo ./bin/kliq -dry-run=false -interval 1s \
  -graph=true \
  -graph-mode=learn \
  -graph-node-id=node-web-01
```

**With graph in frozen-observe mode (signals new edges, no block):**
```bash
sudo ./bin/kliq -dry-run=false -interval 1s \
  -graph=true \
  -graph-mode=frozen-observe \
  -graph-freeze-action=signal \
  -graph-node-id=node-web-01
```

**Exclude a NAT gateway / WSL host from graph learning:**
```bash
sudo ./bin/kliq -graph=true -graph-exclude-source-cidrs=172.16.0.0/12
```

---

## Graph learning

The graph learner records every observed flow as a directed edge between a source IP and destination. Edges graduate through states over time:

```
candidate  →  learned  →  (frozen)
    ↓             ↓
  expired       denied
```

| State | Meaning |
|---|---|
| `candidate` | Seen, but not enough evidence yet |
| `learned` | Promoted: meets `min-seen`, `min-windows`, `min-age` criteria |
| `expired` | Not seen for `graph-expire-ttl`; restarts as candidate if traffic resumes |
| `denied` | Explicitly blocked; never overwritten by new observations |

When `--graph-mode=frozen-observe`, new edges after the freeze emit a `graph.new_edge_after_freeze` signal. The decision engine then enforces the `--graph-freeze-action` policy (default: `signal`).

### Attack protection during learning

The graph learner integrates with the signal engine: when a heuristic signal fires for a source IP (PPS spike, SYN flood, port scan), the learner:

1. Marks the source as suspicious for the signal's TTL.
2. **Retroactively expires** all candidate edges from that source (so attacker IPs don't pollute the learned baseline).

### Relevant flags

| Flag | Default | Description |
|---|---|---|
| `-graph` | `false` | Enable graph learning |
| `-graph-mode` | `learn` | `learn` or `frozen-observe` |
| `-graph-node-id` | hostname | Node identifier for edges |
| `-graph-store` | `/var/lib/kernloom/iq/graph.db` | SQLite database path |
| `-graph-min-seen` | `5` | Min observations before promotion |
| `-graph-min-windows` | `3` | Min distinct tick windows before promotion |
| `-graph-min-age` | `10m` | Min edge age before promotion |
| `-graph-expire-ttl` | `720h` | Idle TTL before expiry (0 = disabled) |
| `-graph-exclude-broadcast` | `true` | Exclude multicast/broadcast destinations |
| `-graph-exclude-loopback` | `true` | Exclude loopback addresses |
| `-graph-exclude-source-cidrs` | `""` | Comma-separated CIDRs to exclude from learning (e.g. `172.16.0.0/12` for WSL gateway) |
| `-graph-freeze-action` | `signal` | Action on new edge after freeze: `signal`, `rate_limit`, `block` |
| `-graph-freeze-ttl` | `10m` | Enforcement TTL for freeze violations |
| `-graph-freeze-max-action` | `rate_limit` | Upper bound on freeze enforcement |
| `-graph-freeze-allow-block` | `false` | Permit block actions from freeze violations |
| `-graph-freeze-min-severity` | `70` | Minimum signal score before block is allowed |

---

## Decision engine

Every enforcement action in IQ passes through the decision engine, which:

- translates signals and FSM transitions into `Decision` structs
- enforces through the Shield PEP adapter
- logs every decision with reason codes and severity

```
Signal (graph.new_edge_after_freeze, pps_high, …)
         │
         ▼
  Decision Engine  ←  LocalPolicy (MaxAction, TTLs, AllowLocalBlock, …)
         │
         ▼
  Shield PEP Adapter  →  eBPF maps (deny / rate-limit)
         │
         ▼
  EnforcementReceipt  (audit trail)
```

`LocalPolicy` enforces ceilings: even if a signal score is high, the engine will not exceed `MaxAction`. When Forge (the policy management component) is integrated in a future release, `LocalPolicy` will be populated from signed PolicyPacks.

---

## Whitelist and feedback

### Whitelist file

Default path: `/etc/kernloom/iq/whitelist.txt`

Format: one entry per line — IPv4, IPv6, IPv4 CIDR, or IPv6 CIDR. Lines starting with `#` are comments.

```text
# monitoring host
203.0.113.7
# office network
198.51.100.0/24
# IPv6 test
2001:db8::1
2001:db8:abcd::/48
```

### Feedback file (temporary exemptions)

Default path: `/var/lib/kernloom/iq/feedback.json`

```json
[
  {"target":"203.0.113.7","action":"forgive","ttl":"24h","notes":"partner NAT"},
  {"target":"198.51.100.0/24","action":"whitelist","until":"2026-06-01T00:00:00Z"},
  {"target":"2001:db8::1","action":"forgive","ttl":"6h"}
]
```

`forgive` lowers the current severity for the IP. `whitelist` exempts it entirely until the TTL or `until` timestamp expires.

---

## CLI reference

### klshield

```text
Commands:
  attach-xdp    -iface eth0 [-obj <path>] [-force]
  detach-xdp

  add-allow-cidr  <cidr>
  list-allow
  enforce-allow   on|off

  add-deny-ip     <ip>
  del-deny-ip     <ip>
  list-deny

  rl-set          -rate <pps> -burst <n>
  rl-set-ip       -ip <ip> -rate <pps> -burst <n>
  rl-unset-ip     <ip>
  list-rl

  set-sampling    <mask>    (0 = off, 1 ≈ 50%, 3 ≈ 25%, 1023 ≈ 0.1%)

  stats
  top-src         [-n 20] [-by pkts|bytes|drops|droprl]
  events
```

### kliq (key flags)

| Flag | Default | Description |
|---|---|---|
| `-dry-run` | `true` | Observe only; no eBPF map writes |
| `-interval` | `1s` | Telemetry poll interval |
| `-profile` | `default` | Initial config profile |
| `-state-file` | `/var/lib/kernloom/iq/state.json` | Autotune state (atomic write) |
| `-whitelist` | `/etc/kernloom/iq/whitelist.txt` | Whitelist file |
| `-feedback-file` | `/var/lib/kernloom/iq/feedback.json` | Temporary exemptions |
| `-bootstrap` | `true` | Aggressive autotune schedule at startup |
| `-graph` | `false` | Enable graph learning |
| `-graph-mode` | `learn` | `learn` or `frozen-observe` |
| `-graph-exclude-source-cidrs` | `""` | CIDRs excluded from graph learning |
| `-graph-freeze-action` | `signal` | `signal`, `rate_limit`, or `block` |

Full flag list: `kliq --help`

---

## Troubleshooting

### bpffs / pinned maps

```bash
mount | grep /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
sudo ls -la /sys/fs/bpf | grep kernloom
```

### Driver XDP vs Generic XDP

If the NIC driver does not support native XDP, Shield falls back to generic mode. Check `klshield attach-xdp` output.

### Graph candidate not promoted

Check promotion criteria — all three must be met:

- `seen_count >= graph-min-seen` (default 5)
- `distinct_windows >= graph-min-windows` (default 3)
- edge age >= `graph-min-age` (default 10m)

Run `klshield top-src` to see recent flows, and inspect the graph DB directly:

```bash
sqlite3 /var/lib/kernloom/iq/graph.db "SELECT source_id, destination_id, destination_port, state, seen_count, distinct_windows FROM graph_edges ORDER BY last_seen_at DESC LIMIT 20;"
```

### NAT gateway / WSL host appearing in graph

Use `--graph-exclude-source-cidrs`:

```bash
-graph-exclude-source-cidrs=172.16.0.0/12
```

---

## License

See:
- `LICENSE` (repo root)
- `shield/LICENSE` and `iq/LICENSE`
- Additional texts under `LICENSES/`
