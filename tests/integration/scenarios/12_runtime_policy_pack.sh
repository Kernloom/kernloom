#!/usr/bin/env bash
# Scenario 12: RuntimePolicyPack contract smoke.
#
# No XDP/root network setup is needed. The scenario verifies that:
#   - kliq run accepts kind: RuntimePolicyPack via --policy-file
#   - the RuntimePDP compiles the pack in shadow mode
#   - loader, mapper, broker, and conformance fixtures remain green
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

RESULTS_DIR="$KLT_ARTIFACT_DIR/12"
mkdir -p "$RESULTS_DIR"

POLICY="$RESULTS_DIR/runtime-policy.yaml"
RUN_LOG="$RESULTS_DIR/kliq-runtime-policy.log"
GO_LOG="$RESULTS_DIR/go-contract-tests.log"
WHITELIST="$RESULTS_DIR/whitelist.txt"
FEEDBACK="$RESULTS_DIR/feedback.json"
STATE="$RESULTS_DIR/state.json"
DB="$RESULTS_DIR/kliq-state.db"

: > "$WHITELIST"
printf '[]\n' > "$FEEDBACK"

cat > "$POLICY" <<'YAML'
apiVersion: kernloom.io/runtime/v1alpha1
kind: RuntimePolicyPack
metadata:
  name: it-runtime-policy
  issued_at: "2026-06-19T10:00:00Z"
spec:
  default_effect: deny
  capabilities_required:
    - enforce.traffic.rate_limit
  rules:
    - id: hold-enforcement-while-drops
      when: "fsm.current_level in ['soft', 'hard', 'block'] && signals.enforcement_feedback_rate > 0"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
        params:
          rate_pps: 100
      reason_codes:
        - rate_limit_drops_sustained
        - enforcement_hold
    - id: high-risk-rate-limit
      when: "risk.level in ['high', 'critical']"
      then:
        capability: enforce.traffic.rate_limit
        level: hard
        ttl: "30s"
        params:
          rate_pps: 100
      reason_codes:
        - integration_runtime_policy
YAML

set +e
timeout 4s "$KLT_KLIQ" run \
  --adapter=none \
  --policy-file="$POLICY" \
  --runtime-pdp-mode=shadow \
  --feature-profile=dos-light \
  --dry-run=true \
  --bootstrap=false \
  --autotune=false \
  --whitelist="$WHITELIST" \
  --feedback-file="$FEEDBACK" \
  --state-file="$STATE" \
  --db="$DB" \
  --interval=1s \
  > "$RUN_LOG" 2>&1
RUN_RC=$?
set -e

if [[ "$RUN_RC" -ne 0 && "$RUN_RC" -ne 124 ]]; then
  cat "$RUN_LOG" >&2
  fail "12.1: kliq run with RuntimePolicyPack exited with $RUN_RC"
fi

assert_contains "$RUN_LOG" "Policy loaded: file=.*runtime-policy.yaml kind=RuntimePolicyPack name=it-runtime-policy"
assert_contains "$RUN_LOG" "RuntimePDP mode: SHADOW"
assert_contains "$RUN_LOG" "pack loaded: 2 rules"
assert_contains "$RUN_LOG" "Kernloom IQ started"
assert_not_contains "$RUN_LOG" "unsupported kind|compile error|parse runtime pack|panic"

pass "12.1: kliq loads and compiles RuntimePolicyPack via --policy-file"

assert_cmd_success "$KLT_GO" version

run_contract_tests() {
  local go_cache="$RESULTS_DIR/go-build"
  local test_regex='TestLoadPolicyBytesRecognizesRuntimePolicyPack|TestLoadPolicyBytesVerifiesSignedRuntimePolicyPack|TestRuntimeDecisionToActionProposal|TestBrokeredRelationshipApplyAndRevert|TestBrokeredSourceFencingPreventsOlderLeaseRevertingNewerLevel|TestApplyRenewsMatchingActiveLease|TestValidateRuntimeBundle|TestValidateOfflineLastKnownGood'

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
  fail "12.2: RuntimePolicyPack contract tests failed"
}

assert_contains "$GO_LOG" "ok[[:space:]]+github.com/kernloom/kernloom/iq/cmd/kliq"
assert_contains "$GO_LOG" "ok[[:space:]]+github.com/kernloom/kernloom/iq/internal/actionbroker"
assert_contains "$GO_LOG" "ok[[:space:]]+github.com/kernloom/kernloom/iq/internal/conformance"

pass "12.2: RuntimePDP loader, mapper, broker, and conformance fixtures pass"
pass "12: RuntimePolicyPack integration contract complete"
