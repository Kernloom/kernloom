# Kernloom

[![CI](https://github.com/Kernloom/kernloom/actions/workflows/ci.yml/badge.svg)](https://github.com/Kernloom/kernloom/actions/workflows/ci.yml)

Kernloom is a modular, open Zero Trust and anomaly detection platform for Linux workloads. The local runtime consists of two tightly integrated components:

- **`klshield`** — XDP/eBPF data plane. Attached to a network interface, it enforces deny/rate-limit decisions in the kernel packet path at line rate.
- **`kliq`** — userspace intelligence agent. Reads Shield telemetry, learns traffic baselines and communication graphs, runs the progressive enforcement FSM, and enforces decisions via PEP adapters.

Official docs: https://kernloom.com/

---

## Architecture

```
Forge (policy compiler)  ←──────── Git / Enterprise PAP
    │ signed RuntimeBundle
    ↓
┌─────────────────────────────────────────────────────┐
│                   KLIQ (kliq)                       │
│                                                     │
│  PIP adapters        Pipeline              PDP      │
│  ─────────────       ────────────────   ────────    │
│  KLShield telemetry  graph learning    CEL rules    │
│  netfilter conntrack metric baseline   risk engine  │
│  OpenZiti events*    signal engines    decisions    │
│                            │                        │
│                       Action Broker                 │
│                            │                        │
│  PEP adapters ─────────────┘                        │
│  KLShield PEP (eBPF maps)                           │
│  netfilter PEP (nftables)                           │
│  OpenZiti Action Adapter*                           │
└─────────────────────────────────────────────────────┘
    │ writes eBPF maps
┌───────────────────────────────────────┐
│  KLShield (XDP/eBPF)                  │
│  allowlist → denylist → rate-limit    │
│  → PASS / DROP                        │
└───────────────────────────────────────┘

* OpenZiti adapter: under development
```

---

## Two use cases

### Scenario A — DoS Prevention (public-facing nodes)

**When:** Internet-facing nodes — Ziti controller, Ziti router, public web server, reverse proxy.

**What:** KLIQ learns your node's normal PPS/SYN/scan rates and rate-limits or blocks sources that deviate significantly. No graph learning, no SQLite, minimal overhead.

### Scenario B — Microsegmentation (internal nodes)

**When:** Internal nodes communicating with a small, known set of services — database, IdP, internal API, NAS.

**What:** KLIQ learns the full communication graph. After freeze, any unexpected connection is detected and blocked down to the exact `(src_ip, port, proto)` tuple in XDP with zero race window.

---

## Runtime profiles

| Profile | Active subsystems |
|---|---|
| `dos-light` | Source heuristics + autotune. No graph, no SQLite. |
| `iq-learning` | dos-light + per-source EWMA baseline. |
| `graph-learning` | iq-learning + flow telemetry + graph learning + edge baselines + SQLite. |
| `graph-enforce` | graph-learning + XDP tuple enforcement. |

---

## Build

```bash
# Prerequisites: Linux + bpffs, clang ≥ 15, Go matching go.mod
sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

# BPF object
make -C shield/bpf

# Binaries
go build -o klshield ./shield/cmd/klshield
go build -o kliq     ./iq/cmd/kliq

# Tests
go test ./...
```

---

## Quick start — DoS Prevention

```bash
sudo ./klshield attach-xdp --iface eth0 \
  --obj shield/bpf/out/xdp_kernloom_shield.bpf.o
sudo cp configs/pdp/ziti-controller-bootstrap.yaml \
        /opt/kernloom/attested/etc/pdp/node.yaml
sudo ./kliq \
  --pdp-config=/opt/kernloom/attested/etc/pdp/node.yaml \
  --dry-run=true --whitelist-learn=true
./kliq status
```

See `configs/pdp/` for all PDPConfig profiles.

---

## Quick start — Microsegmentation

```bash
# Phase 1 — learn (14 days dry-run)
sudo ./kliq --pdp-config=configs/pdp/idp-bootstrap.yaml \
  --graph --graph-mode=learn --dry-run=true --whitelist-learn=true

./kliq graph edges --sort=state
./kliq graph freeze --dry-run
sudo ./kliq graph freeze

# Phase 2 — enforce
sudo ./kliq --pdp-config=configs/pdp/idp-bootstrap.yaml \
  --graph --graph-mode=frozen-enforce --dry-run=false
```

---

## Repository layout

```
kernloom/
├── iq/cmd/kliq/               KLIQ agent main loop and CLI subcommands
├── iq/internal/
│   ├── actionbroker/          Action lease journal + receipt/revert handling
│   ├── actions/               Action proposal/resolution/executor contracts
│   └── lifecycle/             Bootstrap autotune and graph lifecycle helpers
├── shield/
│   ├── bpf/                   XDP/eBPF program (C)
│   └── cmd/klshield/          klshield CLI
├── pkg/
│   ├── core/
│   │   ├── observation/       Canonical observation model
│   │   ├── signal/            Signal type catalog
│   │   ├── decision/          Decision, ActionLease + EnforcementReceipt
│   │   ├── entity/            Entity model (Kind, Ref)
│   │   ├── graph/             Graph edge model + lifecycle
│   │   ├── evidence/          Evidence records
│   │   ├── learning/          Learning guard contracts + exclusions
│   │   ├── baseline/          Baseline key + profile types
│   │   ├── metric/            Metric model
│   │   ├── measurement/       Measurement model
│   │   ├── featureset/        RuntimeProfile + FeatureSet
│   │   ├── fsm/               FSM levels, State, Advance()
│   │   ├── policy/            LocalPolicyPack schema + loader
│   │   ├── pdp/               PDPConfig schema + loader
│   │   ├── cel/               CEL evaluator for policy rules
│   │   ├── reason/            Signal reason code constants
│   │   └── suspicious/        SuspiciousRegistry
│   ├── adapters/              Vendor/product integrations ONLY
│   │   ├── klshield/          KLShield adapter package
│   │   │   ├── client/        eBPF map client
│   │   │   ├── guard/         anti-poisoning learning guard
│   │   │   ├── pep/           PEP (writes eBPF maps)
│   │   │   ├── shadow/        shadow/dry-run metric wrapper
│   │   │   ├── signalengine/  KLShield heuristic signal engine
│   │   │   └── telemetry/     telemetry → observations
│   │   └── netfilter/         netfilter PEP (nftables + iptables)
│   ├── pipeline/
│   │   ├── runner.go          Generic pipeline runner
│   │   └── graphpipeline/     Graph learning pipeline component
│   ├── sourcebaseline/        Per-source EWMA baseline cache
│   ├── metricbaseline/        Generic metric baseline engine (EWMA)
│   ├── learningguard/         Learning guard (anti-poisoning)
│   ├── featureextractor/      Feature extractor interface
│   ├── signalengine/          Signal engine interface
│   ├── relationshiplearner/   Relationship extractor interface + implementations
│   │   ├── network/           Generic L3/L4 network relationships
│   │   ├── http/              Generic HTTP relationships
│   │   └── ziti/              OpenZiti stub (TO MOVE: → pkg/adapters/openziti/)
│   ├── riskaggregator/        Signal risk aggregation
│   ├── decisionengine/        Decision engine (FSM + signals → decisions)
│   ├── adapterruntime/        Adapter lifecycle interface + EventBus
│   └── statestore/sqlite/     SQLite state store + action lease journal
└── configs/
    ├── pdp/                   PDPConfig profiles (16 profiles, all node roles)
    └── policies/              LocalPolicyPack examples
```

> **Note:** Items marked `TO MOVE` are vendor-specific code that should be in `pkg/adapters/<vendor>/`. See `.claude/17-adapter-boundary-and-vendor-isolation.md` for the full list of planned fixes.

---

## Vendor adapter contract

`pkg/adapters/` is reserved for vendor/product integrations. Generic pipeline components (no external system dependency) live in `pkg/pipeline/` or other shared packages.

A complete vendor adapter package contains all product-specific code in one directory:
`eventsource`, `decoder`, `mapping`, `extractor`, `signalengine`, `learningguard`, `relationshiplearner`, `pep`, `actions`.

The core packages (`pkg/core/`, `pkg/pipeline/`, etc.) must never contain vendor names as Go identifiers.

---

## Action leases and receipts

KLIQ records TTL-bounded enforcement actions as action leases before calling a PEP. Each lease carries a fencing token, expiry time and revert state. On expiry, the action broker checks the current fencing token before reverting; a mismatch is recorded as `conflict` and no blind revert is attempted.

Receipts are emitted from the same model and include apply/revert status, lease ID, target, action, expiry and fencing token. This keeps future KLShield, netfilter and OpenZiti enforcement paths behind one auditable boundary.

---

## Forge integration

Forge produces signed `RuntimeBundle` artifacts. KLIQ:
1. Downloads the bundle from Forge
2. Verifies the Ed25519 signature and generation monotonicity
3. Activates the embedded `RuntimePolicyPack` in its Runtime PDP
4. Reports `BundleAck`, `LocalRiskAssessment`, `EnforcementReceipt`, and `RuntimeFinding` back to Forge

Shared protocol schemas are planned for `pkg/contracts/` / a pinned contracts module (schema version: `kernloom.io/runtime/v1alpha1`). The current repository still carries the local runtime models in `pkg/core/`.

---

## License

MPL-2.0 — see `LICENSE`.
