#!/usr/bin/env bash
# Scenario 12: RuntimePolicyPack and Natural Intent contract smoke.
#
# No XDP/root network setup is needed. The scenario verifies that:
#   - Forge converts productive Natural Intent into a KLShield RuntimePolicyPack
#   - kliq run accepts the generated kind: RuntimePolicyPack via --policy-file
#   - the RuntimePDP compiles the generated pack in shadow mode
#   - loader, mapper, broker, and conformance fixtures remain green
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

RESULTS_DIR="$KLT_ARTIFACT_DIR/12"
mkdir -p "$RESULTS_DIR"

GO_LOG="$RESULTS_DIR/go-contract-tests.log"
NATURAL_INTENT="$KLT_ROOT/tests/integration/fixtures/policies/klshield-edge-autonomy-hold.intent"
NATURAL_OUT="$RESULTS_DIR/natural-intent"
NATURAL_POLICY="$RESULTS_DIR/klshield-natural-runtime-policy.yaml"
CONVERT_LOG="$RESULTS_DIR/forge-intent-convert.log"
EXPORT_LOG="$RESULTS_DIR/forge-export-runtime-policy.log"
SUPPORT_REPORT="$RESULTS_DIR/forge-intent-support.yaml"
NATURAL_RUN_LOG="$RESULTS_DIR/kliq-natural-runtime-policy.log"
NATURAL_WHITELIST="$RESULTS_DIR/natural-whitelist.txt"
NATURAL_FEEDBACK="$RESULTS_DIR/natural-feedback.json"
NATURAL_STATE="$RESULTS_DIR/natural-state.json"
NATURAL_DB="$RESULTS_DIR/natural-kliq-state.db"

[[ -x "$KLT_FORGE" ]] || fail "forge binary not found: $KLT_FORGE"
[[ -f "$NATURAL_INTENT" ]] || fail "natural intent fixture not found: $NATURAL_INTENT"
[[ -d "$KLT_FORGE_ADAPTERS" ]] || fail "adapter examples not found: $KLT_FORGE_ADAPTERS"
[[ -d "$KLT_FORGE_PROFILES" ]] || fail "profile examples not found: $KLT_FORGE_PROFILES"

"$KLT_FORGE" intent convert \
  --input "$NATURAL_INTENT" \
  --output-dir "$NATURAL_OUT" \
  --emit-policy-intent \
  --compile-target klshield-local \
  --show-notes \
  > "$CONVERT_LOG" 2>&1

assert_file_exists "$NATURAL_OUT/policy-intent.yaml"
assert_file_exists "$NATURAL_OUT/detections.yaml"
assert_file_exists "$NATURAL_OUT/responses.yaml"
assert_file_exists "$NATURAL_OUT/guardrails.yaml"
assert_file_exists "$NATURAL_OUT/capabilities.yaml"
assert_contains "$CONVERT_LOG" "response rule \"on-risk-elevated-enforce-traffic-rate-limit\""
assert_contains "$CONVERT_LOG" "ENFORCED response rule"
assert_contains "$CONVERT_LOG" "requires previous action \"enforce.traffic.rate_limit\" to be active"
assert_contains "$CONVERT_LOG" "may use local enforcement state as previous-action evidence"
assert_contains "$CONVERT_LOG" "requires risk confidence at least high"
assert_contains "$CONVERT_LOG" "requires risk signal fresher than 2m0s"
assert_contains "$CONVERT_LOG" "requires at least 2 independent signals before block"
assert_contains "$CONVERT_LOG" "autonomy hold \"hold-rate-limit-while-enforcement-feedback-active\""
assert_contains "$CONVERT_LOG" "ENFORCED autonomy hold"
assert_contains "$CONVERT_LOG" "ENFORCED autonomy allowance for \"enforce.traffic.drop\""
assert_contains "$CONVERT_LOG" "ENFORCED autonomy max duration for \"enforce.traffic.drop\""
assert_contains "$CONVERT_LOG" "autonomy audit receipt requirement"
assert_contains "$NATURAL_OUT/policy-intent.yaml" "target: klshield-local"
assert_contains "$NATURAL_OUT/policy-intent.yaml" "digest: sha256:"
assert_contains "$NATURAL_OUT/policy-intent.yaml" "autonomyLifecycle:"
assert_contains "$NATURAL_OUT/policy-intent.yaml" "enforcement_feedback_active: true"
assert_contains "$NATURAL_OUT/policy-intent.yaml" "requires_previous_action: enforce.traffic.rate_limit"
assert_contains "$NATURAL_OUT/policy-intent.yaml" "max_action_duration:"
assert_contains "$NATURAL_OUT/policy-intent.yaml" "requires_audit: true"
assert_contains "$NATURAL_OUT/responses.yaml" "previousAction:"
assert_contains "$NATURAL_OUT/responses.yaml" "local_runtime_state"
assert_contains "$NATURAL_OUT/responses.yaml" "unknownBehavior: reject_hard_action"
assert_contains "$NATURAL_OUT/responses.yaml" "rate_pps: 100"
assert_contains "$NATURAL_OUT/responses.yaml" "min_risk_confidence: 0\\.8"
assert_contains "$NATURAL_OUT/responses.yaml" "max_risk_age_seconds: 120"
assert_contains "$NATURAL_OUT/responses.yaml" "min_independent_signals: 2"
assert_contains "$NATURAL_OUT/capabilities.yaml" "capability: enforce.traffic.rate_limit"
assert_contains "$NATURAL_OUT/capabilities.yaml" "capability: enforce.traffic.drop"
assert_contains "$NATURAL_OUT/capabilities.yaml" "behavior: fail"
assert_contains "$NATURAL_OUT/capabilities.yaml" "behavior: require_approval"

"$KLT_FORGE" intent support \
  --input "$NATURAL_INTENT" \
  --target klshield-local \
  --output "$SUPPORT_REPORT"

assert_file_not_empty "$SUPPORT_REPORT"
assert_contains "$SUPPORT_REPORT" "kind: NaturalIntentSupportReport"
assert_contains "$SUPPORT_REPORT" "target: klshield-local"
assert_contains "$SUPPORT_REPORT" "status: enforced"
assert_contains "$SUPPORT_REPORT" "warnings: 0"

pass "12.1: productive Natural Intent converts to digest-pinned policy documents and runtime autonomy"

"$KLT_FORGE" export-runtime-policy \
  --intent "$NATURAL_OUT/policy-intent.yaml" \
  --adapters "$KLT_FORGE_ADAPTERS" \
  --profiles "$KLT_FORGE_PROFILES" \
  --target klshield-local \
  --ttl 1m \
  --output "$NATURAL_POLICY" \
  > "$EXPORT_LOG" 2>&1

assert_file_not_empty "$NATURAL_POLICY"
assert_contains "$NATURAL_POLICY" "kind: RuntimePolicyPack"
assert_contains "$NATURAL_POLICY" "forge.kernloom.io/adapter: klshield"
assert_contains "$NATURAL_POLICY" "forge.kernloom.io/target: klshield-local"
assert_contains "$NATURAL_POLICY" "autonomy_lifecycle:"
assert_contains "$NATURAL_POLICY" "id: hold-rate-limit-while-enforcement-feedback-active"
assert_contains "$NATURAL_POLICY" "enforcement_feedback_active: true"
assert_contains "$NATURAL_POLICY" "requires_previous_action: enforce.traffic.rate_limit"
assert_contains "$NATURAL_POLICY" "max_action_duration:"
assert_contains "$NATURAL_POLICY" "duration: 15m"
assert_contains "$NATURAL_POLICY" "requires_audit: true"
assert_contains "$NATURAL_POLICY" "rate_pps: 100"
assert_contains "$NATURAL_POLICY" "enforce.traffic.rate_limit"
assert_contains "$NATURAL_POLICY" "enforce.traffic.drop"
assert_contains "$NATURAL_POLICY" "id: response-on-risk-elevated-enforce-traffic-rate-limit-enforce-traffic-rate-limit"
assert_contains "$NATURAL_POLICY" "when: risk\\.level in \\['medium', 'high', 'critical'\\]"
assert_contains "$NATURAL_POLICY" "id: response-on-sustained-pressure-enforce-traffic-drop-enforce-traffic-drop"
assert_contains "$NATURAL_POLICY" "detections\\.sustained_pressure\\.active == true"
assert_contains "$NATURAL_POLICY" "actions\\.enforce_traffic_rate_limit\\.active == true"
assert_contains "$NATURAL_POLICY" "actions\\.enforce_traffic_rate_limit\\.elapsed_seconds >= 60"
assert_contains "$NATURAL_POLICY" "fsm\\.current_level in \\['soft', 'hard'\\]"
assert_contains "$NATURAL_POLICY" "risk\\.confidence >= 0\\.8"
assert_contains "$NATURAL_POLICY" "risk\\.age_seconds <= 120"
assert_contains "$NATURAL_POLICY" "risk\\.independent_signal_count >= 2"
assert_contains "$NATURAL_POLICY" "previous_action_id: enforce.traffic.rate_limit"
assert_contains "$NATURAL_POLICY" "requires_target_excludes_group: kernloom-admins"
assert_contains "$NATURAL_POLICY" "id: never-auto-block-kernloom-admins"
assert_contains "$NATURAL_POLICY" "id: risk-elevated"
assert_contains "$NATURAL_POLICY" "id: unknown-source-deny"
assert_contains "$NATURAL_POLICY" "id: sustained-pressure"

pass "12.2: Forge exports Natural Intent as KLShield RuntimePolicyPack with hold, guardrails, and broker-enforced autonomy bounds"

: > "$NATURAL_WHITELIST"
printf '[]\n' > "$NATURAL_FEEDBACK"

set +e
timeout 4s "$KLT_KLIQ" run \
  --adapter=none \
  --policy-file="$NATURAL_POLICY" \
  --runtime-pdp-mode=shadow \
  --feature-profile=dos-light \
  --dry-run=true \
  --bootstrap=false \
  --autotune=false \
  --whitelist="$NATURAL_WHITELIST" \
  --feedback-file="$NATURAL_FEEDBACK" \
  --state-file="$NATURAL_STATE" \
  --db="$NATURAL_DB" \
  --interval=1s \
  > "$NATURAL_RUN_LOG" 2>&1
NATURAL_RUN_RC=$?
set -e

if [[ "$NATURAL_RUN_RC" -ne 0 && "$NATURAL_RUN_RC" -ne 124 ]]; then
  cat "$NATURAL_RUN_LOG" >&2
  fail "12.3: kliq run with Natural Intent RuntimePolicyPack exited with $NATURAL_RUN_RC"
fi

assert_contains "$NATURAL_RUN_LOG" "Policy loaded: file=.*klshield-natural-runtime-policy.yaml kind=RuntimePolicyPack name=klshield-edge-autonomy-hold-intent-klshield-local"
assert_contains "$NATURAL_RUN_LOG" "RuntimePDP mode: SHADOW"
assert_contains "$NATURAL_RUN_LOG" "pack loaded: 4 rules"
assert_contains "$NATURAL_RUN_LOG" "Kernloom IQ started"
assert_not_contains "$NATURAL_RUN_LOG" "unsupported kind|compile error|parse runtime pack|panic"

pass "12.3: kliq accepts the Forge-generated KLShield policy pack"

assert_cmd_success "$KLT_GO" version

run_contract_tests() {
  local go_cache="$RESULTS_DIR/go-build"
  local test_regex='TestLoadPolicyBytesRecognizesRuntimePolicyPack|TestLoadPolicyBytesVerifiesSignedRuntimePolicyPack|TestApplyBundleUpdate_AppliesSignedContractsRuntimeBundle|TestRuntimeDecisionToActionProposal|TestBrokeredRelationshipApplyAndRevert|TestBrokeredSourceFencingPreventsOlderLeaseRevertingNewerLevel|TestApplyRenewsMatchingActiveLease|TestValidateRuntimeBundle|TestValidateOfflineLastKnownGood'

  if [[ "$(id -u)" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
    chown -R "$SUDO_UID:$SUDO_GID" "$RESULTS_DIR"
    sudo -u "#$SUDO_UID" env GOCACHE="$go_cache" "$KLT_GO" test \
      ./iq/cmd/kliq \
      ./iq/internal/actionbroker \
      ./iq/internal/conformance \
      -run "$test_regex"
    return
  fi

  GOCACHE="$go_cache" "$KLT_GO" test \
    ./iq/cmd/kliq \
    ./iq/internal/actionbroker \
    ./iq/internal/conformance \
    -run "$test_regex"
}

run_contract_tests > "$GO_LOG" 2>&1 || {
  cat "$GO_LOG" >&2
  fail "12.4: RuntimePolicyPack contract tests failed"
}

assert_contains "$GO_LOG" "ok[[:space:]]+github.com/kernloom/kernloom/iq/cmd/kliq"
assert_contains "$GO_LOG" "ok[[:space:]]+github.com/kernloom/kernloom/iq/internal/actionbroker"
assert_contains "$GO_LOG" "ok[[:space:]]+github.com/kernloom/kernloom/iq/internal/conformance"

pass "12.4: RuntimePDP loader, mapper, broker, and conformance fixtures pass"
pass "12: RuntimePolicyPack integration contract complete"
