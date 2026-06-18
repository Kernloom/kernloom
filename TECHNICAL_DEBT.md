# Kernloom Technical Debt Review

Date: 2026-06-18

Scope: static code and architecture review of `kernloom`, with `.claude/00-agent-brief.md`,
`.claude/14-ai-implementation-backlog.md`, `.claude/15-migration-from-current-codebase.md`,
and `.claude/17-adapter-boundary-and-vendor-isolation.md` as the architectural baseline.

This is not a full security audit. It is a prioritized backlog of issues that currently weaken
the intended KLIQ runtime architecture.

## Priority Legend

- P0: Fix before adding more runtime features.
- P1: Fix soon; it blocks clean integration or will spread coupling.
- P2: Cleanup; important, but less likely to invalidate the next milestones.

## P0 - Fix First

### 1. RuntimeBundle trust contract still needs Forge/KLIQ conformance

Status: KLIQ now verifies RuntimeBundle Ed25519 signatures in managed mode before applying a bundle,
rejects unsigned bundles, rejects expired bundles, rejects older generations, and rejects
same-generation bundles with different content hashes.

Relevant files:

- `iq/cmd/kliq/managed.go`
- `iq/cmd/kliq/forge_client.go`
- `pkg/core/bundle/bundle.go`
- `pkg/core/bundle/verify.go`

Risk:

- Forge-side signing is not present in this repo, so the canonical signing payload still needs an
  explicit conformance fixture shared by Forge and KLIQ.
- Trust-root rotation, key IDs, and multi-key verification are not modeled yet.

Recommended fix:

- Add shared Forge/KLIQ fixtures for canonical RuntimeBundle signing bytes.
- Add key ID and key rotation semantics to the RuntimeBundle trust model.
- Add end-to-end managed-mode tests once Forge emits signed RuntimeBundles.

### 2. Core still contains adapter/vendor concepts

`.claude/17-adapter-boundary-and-vendor-isolation.md` states that vendor or product identifiers in
core/generic packages are boundary violations.

Status: the exported core `KindZitiService`, vendor observation sources,
`ProfileKLShieldLight`, and `ShieldPEPAdapterSpec` have been removed. KLShield and OpenZiti now own
their adapter source strings/config parsing, and OpenZiti relationship extraction uses the generic
service entity kind.

Remaining relevant files:

- `iq/cmd/kliq/status_cmd.go`: `klshield-light` runtime special case

Risk:

- KLIQ still keeps `klshield-light` as a CLI-only compatibility alias.

Recommended fix:

- Keep `klshield-light` as a CLI-only compatibility alias or replace it with a capability view once
  runtime profiles are capability-based.

### 3. Action Broker is only partially live

`iq/internal/actionbroker` now models leases, receipts, and fencing-aware revert behavior. KLIQ now
routes TTL-bounded FSM/CEL source enforcement through a brokered executor that journals leases and
logs receipts before delegating to the existing KLShield/netfilter PEP path.

Relevant files:

- `iq/internal/actionbroker/broker.go`
- `iq/internal/actions/executor.go`
- `iq/cmd/kliq/kliq.go`
- `pkg/statestore/sqlite/action_leases.go`
- `pkg/core/decision/decision.go`

Risk:

- Tuple enforcement and explicit de-enforcement are still lease-less compatibility paths.
- Receipts are logged but not yet persisted/uploaded as a durable Forge-facing queue.
- Expiry revert is modeled, but full runtime-state-map revert wiring still needs a dedicated pass.

Recommended fix:

- Persist receipts or an upload queue, not only lease records.
- Route tuple enforcement through a broker-compatible PEP once tuple leases have a target model.
- Wire expiry revert to runtime FSM state maps or make lease expiry explicitly advisory.

## P1 - High Priority

### 4. Shared contracts module is new but not fully adopted

`github.com/kernloom/kernloom-contracts` now defines the shared runtime wire contracts and signing
fixtures. KLIQ imports it for `internal/localrisk` and `internal/runtimepdp`, but the older managed
bundle and Forge client paths still mainly use local core models.

Relevant areas:

- `pkg/core/bundle`
- `pkg/core/policy`
- `pkg/core/decision`
- `github.com/kernloom/kernloom-contracts`

Risk:

- Forge and KLIQ can still drift where older core models remain in the live control-plane path.
- Runtime bundle ingestion still needs migration from `pkg/core/bundle` to contracts.

Recommended fix:

- Keep internal domain types separate only where they add runtime-only behavior.
- Migrate managed RuntimeBundle ingestion and Forge status/upload payloads to `kernloom-contracts`.

### 5. KLIQ command package is doing too much

`iq/cmd/kliq/kliq.go` still orchestrates Forge pull, telemetry, graph, metric pipeline, policy,
FSM, shadow risk, PEP behavior, and feedback/proposal logic in one command package.

Risk:

- The canonical pipeline from `.claude/14-ai-implementation-backlog.md` is hard to enforce.
- Feature additions will keep increasing command-level coupling.
- Runtime PDP and Action Broker integrations will be harder to test in isolation.

Recommended fix:

- Extract runtime services into internal packages:
  - `internal/forgeagent`
  - `internal/runtimepdp`
  - `internal/riskengine`
  - `internal/actionbroker`
  - `internal/proposals`
- Keep `cmd/kliq` as composition, config loading, and CLI surface.

### 6. Local risk assessment is not yet live-wired into Runtime PDP

`iq/internal/localrisk` now turns riskaggregator output into an explainable assessment with level,
confidence, completeness, domains, contributions, missing inputs, validity window, and model
reference. It can now convert to `contracts.LocalRiskAssessment`. The current runtime tick does not
yet feed this into Runtime PDP.

Risk:

- Runtime PDP decisions are not active in the live KLIQ loop yet.
- Missing inputs and confidence are not yet surfaced to Forge or feedback/proposal flows.

Recommended fix:

- Feed pipeline risk outputs into `iq/internal/runtimepdp`.
- Surface the resulting `contracts.RuntimeDecision` and risk assessment in Forge reports.

### 7. Runtime PDP is not yet live

`iq/internal/runtimepdp` now evaluates `contracts.RuntimePolicyPack` CEL expressions over
`contracts.LocalRiskAssessment` and context snapshots, producing `contracts.RuntimeDecision`. The
live KLIQ loop still uses the legacy PolicyPack/FSM/CEL bridge.

Relevant files:

- `pkg/core/policy/pack.go`
- `pkg/core/pdp/config.go`
- `iq/cmd/kliq/kliq.go`

Risk:

- Forge-produced RuntimePolicyPacks are not yet the live decision source.
- The legacy FSM/CEL path and Runtime PDP path can diverge until bridged.

Recommended fix:

- Keep compatibility with existing policy pack fields only at the migration boundary.
- Add a live runtime-PDP shadow mode before replacing enforcement decisions.

### 8. Lease and state-store hardening is incomplete

The SQLite state store now has `action_leases`, but the lease lifecycle needs more operational
coverage.

Risk:

- `pending` leases after crash are not reconciled.
- Receipt upload/persistence is not guaranteed.
- Store opening is still coupled to existing feature paths in places that should become runtime-wide.

Recommended fix:

- Add startup reconciliation for `pending`, `active`, `expired`, `reverted`, `failed`, and `conflict`
  states.
- Persist receipt envelopes and upload status.
- Add migration tests for empty DB, old DB, and interrupted migration scenarios.

### 9. Adapter role split is only partially complete

KLShield code has been moved into adapter subpackages, but the runtime still carries historical
assumptions around telemetry, PEP sidecars, feedback, and action execution.

Relevant files:

- `pkg/adapters/klshield/telemetry`
- `pkg/adapters/klshield/pep`
- `iq/internal/actions/executor.go`
- `iq/cmd/kliq/feedback.go`

Risk:

- PIP and PEP responsibilities remain blurred.
- Future OpenZiti and netfilter enforcement paths may copy KLShield-specific assumptions.

Recommended fix:

- Make adapter manifests explicit about roles: telemetry/PIP, PEP, context provider, proposal source.
- Route enforcement through the Action Broker interface rather than KLShield-specific executor types.

## P2 - Cleanup

### 10. README contains stale migration notes

Status: fixed. The repository layout now points vendor extractors at `pkg/adapters/` and lists the
OpenZiti adapter package.

Relevant file:

- `README.md`

Recommended fix:

- Keep README layout updates in the same commits as future package moves.

### 11. Historical config and naming remains visible

The docs call for clearer RuntimeBundle, Runtime Policy Pack, and Runtime PDP terminology, but
current config and docs still expose old names such as `LocalPolicyPack` and `PDPConfig`.

Relevant files:

- `pkg/core/policy/pack.go`
- `pkg/core/pdp/config.go`
- `configs/pdp/reference.yaml`
- `README.md`

Recommended fix:

- Introduce new names at boundaries first.
- Keep deprecated aliases only with explicit comments and removal criteria.

### 12. Tracked release artifacts and ignored paths need a decision

Several generated or binary-like artifacts appear to be tracked while also being covered by ignore
rules.

Observed examples:

- `bin/`
- `dist/`
- root `kliq`
- root `klshield`
- `kernloom-repo.zip`
- `.claude/archive/*.Zone.Identifier`

Risk:

- Repository clones and diffs carry large or platform-specific artifacts.
- Future generated files can be accidentally hidden by `.gitignore` while historical tracked files
  remain in place.

Recommended fix:

- Decide whether release artifacts belong in Git.
- If not, remove them in a dedicated cleanup commit and document the release build path.
- Remove Windows `Zone.Identifier` sidecar files unless they are intentionally archived evidence.

### 13. Generic comments and examples still lean on old vendor names

Some generic packages use KLShield, Nginx, Ziti, or Cilium examples in comments and tests. Examples
are less severe than exported identifiers, but they keep the old mental model alive.

Relevant areas:

- `pkg/core/metric`
- `pkg/core/learning`
- `pkg/metricbaseline`
- `pkg/core/relationship`

Recommended fix:

- After the exported identifier cleanup, update examples to neutral language or adapter-local tests.

## Recommended Immediate Order

1. Migrate managed RuntimeBundle ingestion to `github.com/kernloom/kernloom-contracts`.
2. Add live Runtime PDP shadow mode fed by `iq/internal/localrisk`.
3. Persist/upload enforcement receipts and finish broker support for tuple/de-enforce paths.
4. Replace legacy PolicyPack/FSM decision source only after shadow parity is proven.
