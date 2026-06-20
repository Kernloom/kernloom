# Kernloom Technical Debt Review

Date: 2026-06-19

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

### 3. Action Broker is live, but operational hardening remains

`iq/internal/actionbroker` now models leases, receipts, and fencing-aware revert behavior. KLIQ now
routes TTL-bounded RuntimePDP/CEL source enforcement through a brokered executor that journals leases and
logs/persists receipts before delegating to the configured source PEP path. Relationship/tuple
enforcement uses the same broker/receipt/revert path when an adapter exposes a RelationshipPEP. Explicit
operator cleanup paths such as SIGUSR1 reset and feedback de-enforcement now produce observe-override
receipts instead of silently calling the PEP.

Relevant files:

- `iq/internal/actionbroker/broker.go`
- `iq/internal/actions/executor.go`
- `iq/cmd/kliq/brokered_executor.go`
- `iq/cmd/kliq/kliq.go`
- `pkg/statestore/sqlite/action_leases.go`
- `pkg/statestore/sqlite/receipts.go`
- `pkg/core/decision/decision.go`

Risk:

- Operator cleanup receipts are intentionally lease-less because they revert enforcement to `observe`;
  they are audit records, not expiring leases.
- Receipt upload retry is now durable for `pending` and `failed`, but needs managed-mode integration
  coverage against Forge outages and restarts.
- Expired leases are reverted by the broker, but state-map reconciliation after out-of-band adapter
  changes still needs deeper runtime tests.

Recommended fix:

- Add restart/outage integration tests for pending/failed receipt upload retry.
- Add adapter-state reconciliation tests for source and relationship lease expiry.
- Keep non-expiring operator cleanup as explicit override receipts unless Forge introduces a first-class
  operator-decision contract.

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
FSM, PEP behavior, and feedback/proposal logic in one command package. The RuntimePDP mode setup,
proposal applier, policy-pack update watcher, and signal/graph-anomaly consumer have been pulled into
`iq/cmd/kliq/runtime_services.go`, so `kliq.go` is now closer to composition for that path.

Risk:

- The canonical pipeline from `.claude/14-ai-implementation-backlog.md` is hard to enforce.
- Feature additions will keep increasing command-level coupling.
- Forge bundle application, graph pipeline setup, adapter startup, and the main tick still share one
  orchestration scope, which keeps integration tests broad and refactors riskier than needed.

Recommended fix:

- Continue extracting runtime services into smaller units:
  - `runtime_services.go` already owns RuntimePDP startup, proposal application, pack updates, and the
    signal consumer.
  - Next: move graph pipeline lifecycle/setup out of `kliq.go`.
  - Next: move adapter binding/startup into a runtime adapter service.
  - Next: move the tick body into a service that accepts already-built dependencies.
- Longer term, move mature units into internal packages:
  - `internal/forgeagent`
  - `internal/runtimepdp`
  - `internal/riskengine`
  - `internal/actionbroker`
  - `internal/proposals`
- Keep `cmd/kliq` as composition, config loading, and CLI surface.

### 6. Local risk assessment is live-wired, but still local-only

`iq/internal/localrisk` now turns riskaggregator output into an explainable assessment with level,
confidence, completeness, domains, contributions, missing inputs, validity window, and model
reference. KLIQ now feeds this into RuntimePDP both from the bus-based signal window and from the
synchronous candidate path; candidate metrics are converted into generic local signals before producing a
`contracts.LocalRiskAssessment`.

Risk:

- Risk semantics are still code-configured (`max_score`, fixed level thresholds, local signal scoring);
  there is no signed/declarative `RuntimeRiskModel` artifact yet.
- Missing inputs are still not populated from an explicit required-context registry.
- Forge reporting does not yet expose the full local-risk contribution list for every decision path.
- Cross-node/global risk is still outside the local RuntimePDP input path.

Recommended fix:

- Define a contracts-based `RuntimeRiskModel` that declares level thresholds, domain weights, signal
  overrides, freshness, missing-input handling, and model version.
- Define a context registry that can mark required risk inputs as present/missing.
- Surface RuntimeDecision risk contributions in Forge findings/receipts where useful.
- Keep global/correlate risk as additional signals feeding the same localrisk aggregation model.

### 7. Runtime PDP live path still needs broader contract hardening

`iq/internal/runtimepdp` now evaluates `contracts.RuntimePolicyPack` CEL expressions over
`contracts.LocalRiskAssessment` and context snapshots, producing `contracts.RuntimeDecision`. In
`--runtime-pdp-mode=active`, KLIQ now evaluates runtime policy synchronously for source candidates:
network metrics, baseline thresholds, graph facts, adapter attributes, and FSM hysteresis state are
generic PDP inputs. `--runtime-pdp-mode=shadow` is observe-only, and the live source/relationship
paths no longer use the old FSM or graph logic as an enforcement authority.

Relevant files:

- `iq/cmd/kliq/kliq.go`
- `iq/cmd/kliq/runtime_services.go`
- `iq/cmd/kliq/runtime_pdp_candidate.go`
- `iq/internal/runtimepdp/pdp.go`

Remaining risk:

- More adapters need to populate rich generic facts so RuntimePDP policies can cover identity,
  application, DLP, and trust domains as completely as network candidates.
- The fact maps are generic at runtime, but there is not yet a formal schema registry describing which
  adapter emits which fact keys.
- Runtime bundle ingestion still needs to move fully to `kernloom-contracts` so Forge/KLIQ conformance is
  checked before activation in every managed-mode path.

Recommended fix:

- Extend adapter fact producers instead of adding adapter-specific logic to KLIQ.
- Add a runtime context/fact registry with compatibility checks for adapter facts, baseline scopes, graph
  predicates, and action targets.
- Continue adding conformance fixtures around generic fact variables, unsupported capabilities, LKG/offline
  behavior, and source/relationship RuntimeDecision mapping.

### 8. Natural intent response rules need deterministic compiler priority

Natural policy intent can express several response rules for the same protected resource, for example
alert at a low threshold, rate limit at a higher threshold, and temporarily drop or deny when risk and
enforcement feedback keep rising. Operators should be allowed to write those rules in a readable order,
including mild-to-hard escalation order.

Current risk:

- KLIQ RuntimePDP evaluates `RuntimePolicyPack.spec.rules[]` in order and returns the first matching
  rule.
- If Forge emits natural `when ... then ...` rules in author order, a broad mild rule such as
  `denied access exceeds 5 then alert` can shadow a stricter rule such as
  `denied access exceeds 20 then rate_limit`.
- The natural intent parser currently recognizes response intent text only as warnings and does not yet
  emit a response-rule IR, runtime rules, priorities, or side-effect notifications.
- "Also alert" semantics should not become a second competing enforcement decision. Alerting should be a
  side effect/export/finding attached to the matched enforcement rule, or a separate non-enforcing rule
  with explicit priority behavior.

Recommended fix:

- Introduce a Forge response-rule IR for natural intent before emitting `RuntimePolicyPack` rules.
- Give every response rule an explicit compiler priority derived from registry semantics:
  action severity/level, threshold, risk predicate, specificity, and optional author override.
- Compile stricter/more specific rules before softer/broader rules when targeting the current
  first-match RuntimePDP contract.
- Consider adding an explicit `priority` or `order` field to the shared `RuntimePolicyRule` contract so
  rule ordering is visible and auditable instead of only implied by list position.
- Add compiler diagnostics for shadowed rules and ambiguous equal-priority rules.
- Add tests for common escalation policies: alert-only, rate limit, drop/deny with TTL, sustained
  rate-limit drops, and `also alert` side effects.

Relevant areas:

- `kernloom-forge/pkg/core/naturalintent`
- `kernloom-forge/pkg/bundler`
- `github.com/kernloom/kernloom-contracts.RuntimePolicyRule`
- `iq/internal/runtimepdp`
- `kernloom-registries/registries/actions/runtime-action-contracts.yaml`

### 9. RuntimePDP active mode needs a first-class effective state view

Status: partly fixed.

Done:

- Renewed source leases now return the active lease state.
- Expired lease reverts now run after the candidate/sweep step, so a matching
  RuntimePDP decision can renew before revert.
- This reduces `BLOCK -> OBSERVE -> BLOCK` bounce at TTL boundaries.

Remaining debt:

- The visible source `STATE` line and some in-memory FSM state can still follow
  instantaneous signal/FSM state instead of active lease state.
- KLIQ needs one clear effective state view:
  `active lease state > matched RuntimePDP decision state > signal/FSM observe state`.

Observed symptom:

- `ACTION ip=<source> OBSERVE->BLOCK` applies a runtime decision.
- `ACTION-RECEIPT ... message="lease renewed"` keeps the block lease alive.
- A later `STATE <source> BLOCK->OBSERVE authority=runtime-pdp` appears because the signal/FSM view cooled
  down, even though the effective enforcement lease is still active.

Risk:

- Operators see apparent oscillation even when the PEP lease is stable.
- Future hold/escalation behavior may be modeled in policy intent by mistake, even though lease hold is a
  runtime action contract concern.
- Active RuntimePDP semantics remain split between "decision/lease state" and "source FSM state".

Recommended fix:

- Add a small effective enforcement state view in KLIQ:
  `active lease state > matched RuntimePDP decision state > signal/FSM observe state`.
- Derive visible source state from active Action Broker leases while they are active, including renewed
  leases.
- Map canonical runtime actions to source levels:
  `enforce.traffic.rate_limit` -> soft/hard rate limit, `enforce.access.deny`,
  `enforce.network.deny`, and traffic drop actions -> block.
- Keep FSM/analyzers as fact producers in active RuntimePDP mode; do not let the signal-only FSM state
  override an active lease.
- Add tests for block/rate-limit staying visible while metrics cool down, and for returning to observe only
  after lease expiry/revert.

Estimated effort:

- Clean first implementation: about one day.
- Minimal log-only patch: a few hours, but less useful because it does not make the runtime state model
  explicit.

Relevant areas:

- `iq/cmd/kliq/source_fsm.go`
- `iq/cmd/kliq/runtime_pdp_candidate.go`
- `iq/cmd/kliq/brokered_executor.go`
- `iq/internal/actionbroker`
- `pkg/statestore/sqlite/action_leases.go`

### 10. Lease and state-store hardening is incomplete

The SQLite state store now has `action_leases` and `action_receipts`. The runtime reconciles pending
leases at startup, reverts expired source/relationship leases during the tick, persists receipts, uploads
pending/failed receipts in managed mode, and prunes uploaded receipts.

Risk:

- Receipt upload retry has unit coverage through the store path, but needs full managed-mode outage tests.
- Store opening is still coupled to existing command composition in places that should become runtime-wide.
- Migration tests do not yet cover all old DB versions and interrupted migrations.

Recommended fix:

- Add managed-mode integration tests for receipt upload failure/retry/prune.
- Add migration tests for empty DB, old DB, and interrupted migration scenarios.

### 11. Adapter role split is only partially complete

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

### 12. README contains stale migration notes

Status: fixed. The repository layout now points vendor extractors at `pkg/adapters/` and lists the
OpenZiti adapter package.

Relevant file:

- `README.md`

Recommended fix:

- Keep README layout updates in the same commits as future package moves.

### 13. Historical config and naming remains visible

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

### 14. Tracked release artifacts and ignored paths need a decision

Several generated or binary-like artifacts appear to be tracked while also being covered by ignore
rules.

Observed examples:

- `bin/`
- `dist/`
- root `kliq`
- root `klshield`

Risk:

- Repository clones and diffs carry large or platform-specific artifacts.
- Future generated files can be accidentally hidden by `.gitignore` while historical tracked files
  remain in place.

Recommended fix:

- Decide whether release artifacts belong in Git.
- If not, remove them in a dedicated cleanup commit and document the release build path.
- Remove Windows `Zone.Identifier` sidecar files unless they are intentionally archived evidence.

### 15. Generic comments and examples still lean on old vendor names

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
2. Introduce a runtime fact/context registry for metrics, baselines, graph predicates, adapter facts, and
   required/missing context.
3. Define the Forge response-rule IR and deterministic priority rules before compiling natural
   `when ... then ...` escalation policies into RuntimePolicyPacks.
4. Finish the RuntimePDP effective enforcement state view so active leases drive visible source state everywhere.
5. Extend non-network adapters to publish rich generic facts and relationships against that registry.
6. Continue shrinking `iq/cmd/kliq`: graph pipeline setup, adapter startup, and the main tick body are the
   next high-value extraction targets after RuntimePDP/signal handling.
7. Add managed-mode outage/restart integration tests for bundle validation, receipt retry, and lease
   reconciliation.
