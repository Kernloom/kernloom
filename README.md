# Kernloom Shield + Kernloom IQ

Kernloom consists of two core components:

- **Kernloom Shield** (`klshield`) — the **XDP/eBPF data plane** (ingress enforcement + telemetry)
- **Kernloom IQ** (`kliq`) — the **local intelligence agent** (heuristic scoring, graph learning, decision engine, progressive enforcement)

Official docs: https://kernloom.com/

---

## Architecture

### kliq as local PDP

`kliq` is a **local Policy Decision Point (PDP)**. It consumes telemetry from one or more adapters, runs the signal engine and graph learner, and enforces decisions through **PEP adapters** (Policy Enforcement Points). Today the only built-in PEP is Kernloom Shield (XDP/eBPF). Future releases will add adapters for nginx, nftables, OpenZiti and others.

```
 ┌──────────────────────────────────────────────────────────────┐
 │                      Kernloom IQ (kliq)                      │
 │                                                              │
 │  [Telemetry Adapters]         [Signal Adapters]              │
 │   Shield Telemetry  ──────►  Signal Engine                   │
 │   (future: nginx log,         │                              │
 │    syslog, OTel, …)           │                              │
 │                         Graph Learner                        │
 │                               │                              │
 │                        Decision Engine                       │
 │                         (LocalPolicy)                        │
 │                               │                              │
 │                        [PEP Adapters]                        │
 │                    Shield PEP  (today)                       │
 │                    nginx PEP   (future)                      │
 │                    nftables    (future)                      │
 └──────────────────────────────────────────────────────────────┘
        reads maps ↑                  ↓ writes maps
 ┌──────────────────────────────────────────────────────────────┐
 │                Kernloom Shield (XDP/eBPF)                    │
 │   allowlist  →  denylist  →  rate-limit  →  PASS/DROP       │
 └──────────────────────────────────────────────────────────────┘
```

### Future: Kernloom Forge integration

**Kernloom Forge** (in development in a separate repo) is the **Policy Management System (PMS)** and control plane for Kernloom. When integrated, Forge will:

- compile and sign **PolicyPacks** (versioned, auditable policy bundles)
- distribute PolicyPacks to registered `kliq` instances
- replace the locally configured `LocalPolicy` with Forge-issued, cryptographically signed policy
- receive enforcement receipts back from each node for fleet-wide audit

Until Forge is available, `kliq` operates in **standalone mode**: policy is configured through CLI flags, built-in profiles, or local YAML files. The configuration is split into two Forge-compatible files:

| File | Kind | Controls |
|---|---|---|
| `configs/policies/*.yaml` | `LocalPolicyPack` | **What** to enforce: abstract rules, capability requirements, autonomy gates. PEP-agnostic, Forge-distributable. |
| `configs/pdp/*.yaml` | `PDPConfig` | **How** kliq operates: signal engine thresholds, progressive enforcement, graph learning, Shield PEP adapter parameters. Also Forge-distributable. |

When Forge is integrated it will sign and distribute both files to registered `kliq` nodes.

---

## Repo layout

```text
kernloom/
├── iq/
│   └── cmd/kliq/               # Kernloom IQ CLI
│       ├── kliq.go             # main loop, adapter wiring, signal consumer
│       ├── config.go           # all CLI flags + Config struct
│       ├── fsm.go              # per-IP FSM transitions (processCandidate4/6)
│       ├── graph.go            # graph subcommands (status/export/freeze/approve-ip/deny-ip)
│       ├── state.go            # autotune state persistence
│       ├── profiles.go         # built-in config profiles
│       ├── whitelist.go        # whitelist/feedback file loading
│       ├── reservoir.go        # rolling sample reservoir for autotune
│       ├── helpers.go          # IP helpers, CIDR parsing, graphStrikesFromScore
│       ├── feedback.go         # feedback file (temporary exemptions)
│       └── types.go            # internal metrics/state types
├── shield/
│   ├── bpf/
│   │   ├── xdp_kernloom_shield.bpf.c   # XDP program
│   │   └── include/
│   └── cmd/klshield/           # Kernloom Shield CLI
└── pkg/
    ├── core/
    │   ├── observation/        # Observation model (flows, auth, drops, …)
    │   ├── signal/             # Signal model + signal type catalog
    │   ├── decision/           # Decision + EnforcementReceipt models
    │   ├── reason/             # standardised reason code constants
    │   ├── capability/         # Capability model
    │   ├── graph/              # GraphEdge, EdgeState, PromotionConfig
    │   ├── fsm/                # FSM levels, State, Config, Advance()
    │   ├── policy/             # LocalPolicyPack schema + loader (abstract enforcement rules)
    │   └── pdp/                # PDPConfig schema + loader (signal engine, progressive enforcement, graph, adapters)
    ├── adapterruntime/         # Adapter interface, EventBus, well-known capabilities
    ├── adapters/
    │   ├── graphlearner/       # Graph learning adapter
    │   └── shieldtelemetry/    # Shield telemetry adapter (eBPF maps → Observations)
    ├── decisionengine/         # Decision Engine
    │   ├── engine.go           # EvaluateSignal, RecordFSMTransition, LocalPolicy
    │   ├── shieldbridge.go     # Shield PEP bridge (EnforceDecision → eBPF maps)
    │   └── engine_test.go
    ├── graphstore/sqlite/      # SQLite-backed graph edge store
    ├── shieldclient/           # Go client for Shield pinned eBPF maps
    └── signalengine/
        └── shieldheuristic/    # PPS / SYN / scan / drop-RL signal engine
```

---

## Build

### Prerequisites

- Linux with bpffs at `/sys/fs/bpf`
- Tools: `clang`, `llvm`, `bpftool`, `iproute2`
- Go toolchain matching `go.mod`

```bash
sudo mount -t bpf bpf /sys/fs/bpf || true
```

### Build

```bash
# BPF object (Shield)
make -C shield/bpf
# Output: shield/bpf/out/xdp_kernloom_shield.bpf.o

# CLIs
mkdir -p bin
go build -o bin/klshield ./shield/cmd/klshield
go build -o bin/kliq     ./iq/cmd/kliq

# Tests
go test ./...
```

---

## Quick start

### 1. Attach Shield to a network interface

```bash
sudo ./bin/klshield attach-xdp -iface eth0 \
  -obj shield/bpf/out/xdp_kernloom_shield.bpf.o -force
sudo ./bin/klshield stats
```

### 2. Prepare directories

```bash
sudo mkdir -p /etc/kernloom/iq /var/lib/kernloom/iq
sudo touch /etc/kernloom/iq/whitelist.txt
echo "[]" | sudo tee /var/lib/kernloom/iq/feedback.json > /dev/null
```

### 3. Run IQ in dry-run first

```bash
sudo ./bin/kliq --dry-run=true --interval=1s --profile=public-web
```

Watch the logs: you'll see `TOP` lines for each source and `TICK#N` summaries. No enforcement is applied in dry-run.

---

## Bootstrap phase

### What bootstrap mode does

On first startup, `kliq` has no baseline for what "normal" traffic looks like. The bootstrap phase runs an **accelerated autotune schedule** that learns trigger thresholds (PPS, SYN/s, scan rate) faster than the steady-state schedule.

Bootstrap automatically ends when the learning window expires (default: 4 hours divided into three phases). After bootstrap, autotune switches to slower, more conservative updates.

Bootstrap affects **only** the heuristic signal engine thresholds. The graph learner runs independently.

### Bootstrap vs graph learning

| | Bootstrap | Graph learning |
|---|---|---|
| **What it learns** | Numeric thresholds for PPS, SYN/s, scan rate | Which source IPs communicate to which destination IPs/ports |
| **Output** | `TrigPPS`, `TrigSyn`, `TrigScan` stored in `state.json` | Edge records in `graph.db` |
| **Used for** | Deciding when heuristic severity > threshold | Detecting unknown communication paths |
| **Required** | Yes, always active | Optional (`--graph` flag) |
| **Duration** | Finite bootstrap window, then steady-state | Ongoing; freeze manually when baseline is stable |

### Best practices: bootstrap phase

- Run with `--dry-run=true` during bootstrap to avoid blocking legitimate traffic before thresholds are calibrated.
- Use a **bootstrap profile** (`--profile=ziti-router-bootstrap`, `--profile=nas-bootstrap`, etc.) which sets conservative thresholds to prevent false positives.
- Keep bootstrap active for **at least one full traffic cycle** (e.g. 24h for a NAS to capture backup windows, business hours, etc.).
- Check `state.json` or watch for `AUTOTUNE` log lines to see when thresholds stabilise.
- Switch to the production profile once thresholds look reasonable:

```bash
# Transition from bootstrap to production profile
sudo ./bin/kliq --dry-run=false --profile=ziti-router
```

---

## Graph learning workflow

The graph learner records each observed flow as a directed communication edge and tracks its state over time:

```
candidate  →  learned  →  frozen
    ↓             ↓           ↓
  expired       denied    violation if new edge appears
```

| State | Meaning |
|---|---|
| `candidate` | Seen, but not enough evidence yet |
| `learned` | Promoted: meets seen-count, window, and age criteria |
| `approved` | Explicitly approved (admin or via `approve-ip`) |
| `frozen` | Part of the locked baseline; new edges trigger signals or blocks |
| `denied` | Explicitly blocked; never overwritten by new observations |
| `expired` | Not seen for `graph-expire-ttl`; restarts as candidate if traffic resumes |

### Phase 1: Learn

Start with graph learning enabled and let it observe normal traffic:

```bash
sudo ./bin/kliq --dry-run=false --graph --graph-mode=learn \
  --graph-exclude-source-cidrs=172.16.0.0/12   # exclude NAT/WSL gateway
```

Watch progress:

```bash
./bin/kliq graph status
```

Wait until candidate edges promote to `learned`. Default promotion criteria (all must be met):
- `seen_count >= 5` (`--graph-min-seen`)
- `distinct_windows >= 3` (`--graph-min-windows`)
- edge age >= 10m (`--graph-min-age`)

**Best practices during learning:**
- Run for at least one full daily cycle so all regular peers appear.
- Keep `--dry-run=false` so the heuristic FSM still protects against active attacks (graph learning and FSM operate independently).
- Suspicious sources (PPS spike, SYN flood, port scan) are **automatically excluded** from the learned baseline — their candidate edges are retroactively expired when a heuristic signal fires.
- Exclude known NAT gateways and infrastructure IPs with `--graph-exclude-source-cidrs` to keep the graph clean.

### Phase 2: Review and freeze

Inspect the learned graph:

```bash
# Summary
./bin/kliq graph status

# Full export as YAML
./bin/kliq graph export > graph-baseline.yaml
```

Review the YAML. Then freeze:

```bash
# Marks all learned/approved edges as frozen in the DB
sudo ./bin/kliq graph freeze
# Optional: also write the frozen baseline to a file
sudo ./bin/kliq graph freeze /var/lib/kernloom/iq/graph.db $(hostname) \
  /etc/kernloom/iq/frozen-graph.yaml
```

### Phase 3: Frozen-observe (safe)

Switch to frozen-observe. New edges emit `graph.new_edge_after_freeze` signals and inject FSM strikes, but enforcement is gradual (same FSM gates as heuristic signals):

```bash
sudo ./bin/kliq --dry-run=false --graph --graph-mode=frozen-observe
```

Watch for signals:

```
[graph-learner] new_edge_after_freeze src=203.0.113.55 dst=...
[decision-engine] GRAPH-DECISION ... → fsm_strikes
```

### Phase 4: Frozen-enforce (strict)

Any source with a non-frozen edge is forced to FSM BLOCK immediately, bypassing the normal accumulation gates:

```bash
sudo ./bin/kliq --dry-run=false --graph --graph-mode=frozen-enforce
```

Signal log shows `→ fsm_force_block`. The IP is blocked for `BlockTTL` (30 min for `ziti-controller` profile) via the deny eBPF map.

**Best practice:** Use frozen-observe first for a few days to identify false positives before switching to frozen-enforce.

### Managing the frozen graph

**Approve an IP** (whitelist it in the graph — stops freeze signals for all its edges):

```bash
./bin/kliq graph approve-ip 172.21.112.1
# With explicit store/node:
./bin/kliq graph approve-ip 172.21.112.1 /var/lib/kernloom/iq/graph.db mynode
```

Use `approve-ip` when a legitimate IP is being blocked by frozen-enforce (e.g. a known gateway, monitoring host, or new service that wasn't present during the learning phase). This is preferred over the FSM whitelist because it stops graph signals at the source rather than just overriding enforcement after the fact.

**Deny an IP** (mark all its edges as denied — rejected even if previously frozen):

```bash
./bin/kliq graph deny-ip 203.0.113.55
```

**Direct SQLite access** for bulk operations:

```bash
# Approve a specific port/proto combination
sqlite3 /var/lib/kernloom/iq/graph.db \
  "UPDATE graph_edges SET state='approved'
   WHERE source_id='172.21.112.1' AND protocol='tcp' AND destination_port=443;"

# List all frozen edges
sqlite3 /var/lib/kernloom/iq/graph.db \
  "SELECT source_id, destination_id, protocol, destination_port, seen_count
   FROM graph_edges WHERE state='frozen' ORDER BY last_seen_at DESC;"
```

---

## klshield command reference

```
attach-xdp    -iface <iface> [-obj <path>] [-force]
detach-xdp

add-allow-cidr  <cidr>       Add CIDR to allowlist LPM trie
list-allow                   Show allowlist entries
enforce-allow   on|off       Enable/disable allowlist-only mode

add-deny-ip     <ip>         Add IP to deny map
del-deny-ip     <ip>         Remove IP from deny map
list-deny                    List all denied IPs

rl-set          -rate <pps> -burst <n>       Set global rate limit
rl-set-ip       -rate <pps> -burst <n> <ip> Set per-IP rate limit
rl-unset-ip     <ip>         Remove per-IP rate limit
list-rl                      List all per-IP rate limits

reset                        Clear all deny and rate-limit map entries
                             (use with: sudo kill -USR1 $(pidof kliq) to sync kliq state)

set-sampling    <mask>       Event ringbuf sampling (0=off, 1≈50%, 1023≈0.1%)

stats                        Show global packet counters
top-src [-n 20] [-by pkts|bytes|drops|droprl]   Top sources
events                       Stream drop events from ringbuf
```

### Sync kliq after a manual reset

When you run `klshield reset`, the eBPF maps are cleared but `kliq`'s in-memory FSM state still shows those IPs as rate-limited or blocked. Send `SIGUSR1` to de-escalate all enforced IPs back to `OBSERVE`:

```bash
sudo ./bin/klshield reset
sudo kill -USR1 $(pidof kliq)
# kliq logs: RESET via SIGUSR1: de-escalated N enforced IPs to OBSERVE
```

---

## kliq command reference

### Subcommands

```bash
# Graph management (no running kliq required)
kliq graph status   [store] [node-id]
kliq graph export   [store] [node-id] [--format=json]
kliq graph freeze   [store] [node-id] [frozen-out-path]
kliq graph approve-ip  <ip> [store] [node-id]
kliq graph deny-ip     <ip> [store] [node-id]
```

### Key flags

| Flag | Default | Description |
|---|---|---|
| `--mode` | `standalone` | `standalone` or `managed` (Forge integration pending) |
| `--policy-file` | `""` | Path to `LocalPolicyPack` YAML — abstract enforcement rules |
| `--pdp-config` | `""` | Path to `PDPConfig` YAML — signal engine, progressive enforcement, graph, adapter params |
| `--profile` | `ziti-controller` | Built-in PDP behavior profile; ignored when `--pdp-config` is set |
| `--dry-run` | `true` | Observe only; no eBPF map writes |
| `--interval` | `1s` | Telemetry poll interval |
| `--state-file` | `/var/lib/kernloom/iq/state.json` | Autotune state |
| `--whitelist` | `/etc/kernloom/iq/whitelist.txt` | FSM whitelist (bypasses enforcement) |
| `--feedback-file` | `/var/lib/kernloom/iq/feedback.json` | Temporary exemptions |
| `--bootstrap` | `true` | Accelerated autotune at startup |
| `--graph` | `false` | Enable graph learning (CLI override; prefer `pdp.graph.enabled`) |
| `--graph-mode` | `learn` | `learn`, `frozen-observe`, `frozen-enforce` (CLI override) |

Full flag list: `kliq --help`

### Configuration files (preferred over flags)

**Two files per node role**, both forward-compatible with Kernloom Forge:

```bash
# Full file-based configuration:
sudo kliq \
  --pdp-config=configs/pdp/ziti-controller.yaml \
  --policy-file=configs/policies/ziti-controller.yaml

# Standalone (built-in profile, no files):
sudo kliq --profile=ziti-controller
```

| File | `kind` | What it controls |
|---|---|---|
| `configs/policies/ziti-controller.yaml` | `LocalPolicyPack` | Autonomy, enforcement rules (when FSM level → action + capability + TTL), exports |
| `configs/pdp/ziti-controller.yaml` | `PDPConfig` | Signal engine, progressive enforcement, graph learning, Shield adapter params |

The **PolicyPack** is PEP-agnostic — it references abstract capability IDs (`network.rate_limit_source`, `network.block_source`) not Shield-specific values. The concrete rate/burst values live in `PDPConfig.adapters.shield_pep`.

### PolicyPack — enforcement rules

```yaml
rules:
  - name: soft-rate-limit
    when: {fsm_level: soft}
    then: {action: rate_limit, capability: network.rate_limit_source, ttl: "60s"}
  - name: block
    when: {fsm_level: block}
    then: {action: block, capability: network.block_source, ttl: "30m"}
  - name: graph-freeze-violation
    when: {signal: graph.new_edge_after_freeze}
    then: {action: signal, capability: signal.emit_local_risk, ttl: "10m"}
```

### PDPConfig — progressive enforcement + Shield adapter

```yaml
progressive_enforcement:    # was: fsm (renamed for clarity)
  soft_at: 1
  hard_at: 3
  block_at: 9
  block_min_sev: 2.0
  block_min_dur: "15s"
  ...

adapters:
  shield_pep:               # Shield-specific rate/burst values
    soft_rate_pps: 20
    soft_burst:    40
    hard_rate_pps: 5
    hard_burst:    10
    cooldown:      "5s"
```

### Built-in profiles

| Profile | Use case |
|---|---|
| `ziti-controller` | Public OpenZiti controller / enrolment endpoint |
| `ziti-router` | OpenZiti router (high throughput, NAT-friendly) |
| `ziti-controller-bootstrap` | Bootstrap variant: tolerant, no blocks |
| `ziti-router-bootstrap` | Bootstrap variant: high PPS tolerance |
| `public-web` | Public HTTP/HTTPS endpoint |
| `public-api` | Public JSON API (bursty) |
| `idp` | Identity provider / auth endpoint |
| `internal-app` | East-west / internal service; no auto-block |
| `nas` | NAS (Synology, QNAP, TrueNAS); strict on SYN/scan, 24h block TTL |
| `nas-bootstrap` | NAS bootstrap: tolerant, rate-limit only |
| `ssh-bastion` | SSH jump host |

---

## Whitelist and feedback

### FSM whitelist

File: `/etc/kernloom/iq/whitelist.txt`

```text
# monitoring host
203.0.113.7
# office subnet
198.51.100.0/24
```

The FSM whitelist bypasses **heuristic enforcement** (FSM never escalates above OBSERVE for these IPs). It does **not** suppress graph signals in frozen-observe/frozen-enforce mode. Use `kliq graph approve-ip` instead when the goal is to allow an IP past graph enforcement.

### Feedback file (temporary exemptions)

File: `/var/lib/kernloom/iq/feedback.json`

```json
[
  {"target":"203.0.113.7","action":"forgive","ttl":"24h","notes":"partner NAT"},
  {"target":"198.51.100.0/24","action":"whitelist","until":"2026-06-01T00:00:00Z"}
]
```

`forgive` reduces current severity. `whitelist` exempts the IP entirely until TTL/`until` expires.

---

## Building a custom adapter

Adapters plug into `kliq` via the `adapterruntime.Adapter` interface defined in `pkg/adapterruntime/adapter.go`. There are four adapter kinds:

| Kind | Interface | Purpose |
|---|---|---|
| `telemetry` | `Start(ctx, bus)` publishes `Observation` to `bus` | Feed raw flow/event data to the engine |
| `signal` | `Start(ctx, bus)` publishes `Signal` to `bus` | Feed pre-scored signals (e.g. from Correlate) |
| `pep` | `EnforceDecision(ctx, dec)` | Apply enforcement decisions |
| `export` | `ExportDecision(ctx, dec)` etc. | Forward decisions/receipts to SIEM/OTel |

### Minimal telemetry adapter skeleton

```go
package myadapter

import (
    "context"
    "github.com/adrianenderlin/kernloom/pkg/adapterruntime"
    "github.com/adrianenderlin/kernloom/pkg/core/observation"
)

type Adapter struct{}

func (a *Adapter) ID() string                       { return "my-adapter" }
func (a *Adapter) Kind() adapterruntime.AdapterKind { return adapterruntime.AdapterTelemetry }
func (a *Adapter) Capabilities() []*capability.Capability { return nil }
func (a *Adapter) Init(_ context.Context, _ adapterruntime.AdapterConfig) error { return nil }
func (a *Adapter) Health(_ context.Context) adapterruntime.HealthStatus {
    return adapterruntime.HealthStatus{Healthy: true}
}
func (a *Adapter) Stop(_ context.Context) error { return nil }

func (a *Adapter) Start(ctx context.Context, bus adapterruntime.EventBus) error {
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            default:
                obs := observation.Observation{ /* fill fields */ }
                _ = bus.PublishObservation(ctx, obs)
            }
        }
    }()
    return nil
}
```

### Minimal PEP adapter skeleton

```go
func (a *MyPEP) EnforceDecision(ctx context.Context, dec *decision.Decision) (*decision.EnforcementReceipt, error) {
    switch dec.Action.Type {
    case decision.ActionBlock:
        // apply block in your system
    case decision.ActionRateLimit:
        // apply rate limit
    }
    return decision.NewEnforcementReceipt(dec.ID, nodeID, a.ID(), decision.StatusApplied), nil
}
```

### Wiring a new adapter into kliq

1. Create your adapter package under `pkg/adapters/<name>/`.
2. In `iq/cmd/kliq/kliq.go`, instantiate and start it alongside the existing adapters:

```go
// After the graph learner block (around line 350):
myAdapter := myadapter.New(myadapter.Config{...})
if err := myAdapter.Start(ctx, mainBus); err != nil {
    log.Fatalf("start my-adapter: %v", err)
}
defer myAdapter.Stop(context.Background())
```

For a PEP adapter that should receive enforcement decisions, pass it to the decision engine:

```go
decisionEng := decisionengine.New(decPolicy, myPEPAdapter)
```

The `EnforceDecision` method will be called for every enforcement action the decision engine produces.

---

## Decision engine and LocalPolicy

`pkg/decisionengine/engine.go` is the enforcement brain. It translates signals and FSM transitions into `Decision` structs and enforces them through the active PEP adapter.

```
Signal (graph.new_edge_after_freeze, pps_high, …)
         │
         ▼
  Decision Engine  ←  LocalPolicy
         │              MaxAction, AllowLocalBlock, TTLs,
         │              GraphFreezeAction, MinSeverityForBlock
         ▼
  PEP Adapter  →  eBPF maps / nginx / nftables / …
         │
         ▼
  EnforcementReceipt  (audit trail, reason codes)
```

`LocalPolicy` is the local enforcement ceiling — it caps what the engine may do without Forge approval. Key fields:

| Field | Purpose |
|---|---|
| `MaxAction` | Global ceiling: `observe → signal → rate_limit → block` |
| `AllowLocalBlock` | Gate: must be `true` for any block to happen |
| `MinSeverityForBlock` | Score threshold before block is allowed |
| `GraphFreezeAction` | Action for graph freeze violations |
| `GraphFreezeTTL` | How long a freeze-enforcement entry lasts |

When Kernloom Forge is integrated, `LocalPolicy` will be populated from a signed PolicyPack received from Forge instead of from CLI flags.

---

## Troubleshooting

### Verify maps are pinned

```bash
sudo ls /sys/fs/bpf | grep kernloom
# expect: kernloom_src4_stats, kernloom_deny4_hash, kernloom_rl_policy4, …
```

### Candidate edges not promoting

All three criteria must be met simultaneously:

```bash
sqlite3 /var/lib/kernloom/iq/graph.db \
  "SELECT source_id, destination_port, state, seen_count,
          distinct_windows, first_seen_at
   FROM graph_edges
   WHERE state='candidate'
   ORDER BY last_seen_at DESC LIMIT 20;"
```

Increase `--graph-min-seen` if legitimate peers are promoted too aggressively, or lower it if well-known peers take too long.

### NAT gateway appearing in graph

Exclude it before starting the learner:

```bash
--graph-exclude-source-cidrs=172.16.0.0/12,10.0.0.0/8
```

### Approved IP still getting blocked

If `kliq graph approve-ip` was run but blocks continue, check whether the old `ForceBlock` state is still active in-memory. Restart `kliq` or send `SIGUSR1` to clear FSM state:

```bash
sudo kill -USR1 $(pidof kliq)
```

### Generic XDP vs driver XDP

If the NIC does not support native XDP, Shield falls back to generic mode (software path, higher CPU). Check `ip link show dev eth0` for `xdpgeneric` vs `xdp` flag after attach.

---

## License

- `LICENSE` (repo root) — MPL-2.0
- `shield/LICENSE`, `iq/LICENSE`
- Additional texts under `LICENSES/`
