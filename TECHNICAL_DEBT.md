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

### 4. Shared contracts package is missing

The README and `.claude` docs describe Forge-facing shared contracts, but the repo still mainly uses
local core models.

Relevant areas:

- `pkg/core/bundle`
- `pkg/core/policy`
- `pkg/core/decision`
- README references to `pkg/contracts`

Risk:

- Forge and KLIQ can drift silently on schema semantics.
- Runtime bundles, policy packs, decisions, receipts, and risk assessments are not validated against
  one canonical protocol surface.

Recommended fix:

- Introduce `pkg/contracts` for the Forge/KLIQ wire-level types.
- Keep internal domain types separate only where they add runtime-only behavior.
- Add round-trip fixtures for bundle, receipt, proposal, and risk assessment schemas.

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

### 6. Local risk assessment is not yet wired into Runtime PDP

`iq/internal/localrisk` now turns riskaggregator output into an explainable assessment with level,
confidence, completeness, domains, contributions, missing inputs, validity window, and model
reference. The current runtime does not yet feed this into a Runtime PDP.

Risk:

- Runtime PDP cannot consume the assessment until that package exists.
- Missing inputs and confidence are not yet surfaced to Forge or feedback/proposal flows.

Recommended fix:

- Feed `iq/internal/localrisk.Assessment` into `internal/runtimepdp`.
- Map the internal assessment to shared contracts once the contracts package/module is decided.

### 7. Runtime PDP is not yet a generic runtime decision service

Policy evaluation still uses historical naming and KLShield-specific pathways. `LocalPolicyPack` and
`PDPConfig` remain as implementation names, while the docs want Runtime Policy Pack and Runtime PDP
semantics.

Relevant files:

- `pkg/core/policy/pack.go`
- `pkg/core/pdp/config.go`
- `iq/cmd/kliq/kliq.go`

Risk:

- Policy evaluation stays tied to existing adapter history.
- Forge-produced RuntimeBundles cannot be consumed as a clean runtime decision source.

Recommended fix:

- Add `internal/runtimepdp` that accepts a Runtime Policy Pack, local risk assessment, and context
  snapshot, then produces a runtime decision.
- Keep compatibility with existing policy pack fields only at the migration boundary.

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

1. Add Forge/KLIQ conformance fixtures for signed RuntimeBundles and trust-root rotation.
2. Add `pkg/contracts` and fixture tests so Forge and KLIQ share one schema contract.
3. Extract `internal/runtimepdp` and feed it `iq/internal/localrisk.Assessment`.
4. Persist/upload enforcement receipts and finish broker support for tuple/de-enforce paths.
