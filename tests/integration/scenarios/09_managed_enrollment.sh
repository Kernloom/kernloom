#!/usr/bin/env bash
# Scenario 09: Forge managed-mode API contract.
#
# Does NOT require XDP/eBPF. Exercises the current Forge MVP API that KLIQ
# talks to in managed mode:
#   - serve starts with adapter/profile examples
#   - /healthz is available
#   - node enrollment returns a session token
#   - runtime-bundle is pullable when adapters+profiles are configured
#   - bundle acks, receipts, findings and baseline proposals are accepted
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"

NODE_ID="it-node-09"
RESULTS_DIR="$KLT_ARTIFACT_DIR/09"
mkdir -p "$RESULTS_DIR"

stop_forge 2>/dev/null || true

start_forge
assert_contains "$KLT_FORGE_LOG" "forge API server listening"

HEALTH_OUT="$RESULTS_DIR/healthz.txt"
curl -sf "$KLT_FORGE_URL/healthz" > "$HEALTH_OUT"
assert_contains "$HEALTH_OUT" "^ok$"
pass "09.1: forge health endpoint is ready"

ENROLL_RESP="$RESULTS_DIR/enroll.json"
forge_simulate_enroll "$NODE_ID" > "$ENROLL_RESP"
cat "$ENROLL_RESP"
assert_contains "$ENROLL_RESP" "\"node_id\""
assert_contains "$ENROLL_RESP" "\"session_token\""
assert_contains "$ENROLL_RESP" "mvp-token-$NODE_ID"
pass "09.2: node enrollment returns MVP session token"

BUNDLE_OUT="$RESULTS_DIR/runtime-bundle.yaml"
forge_pull_bundle "$NODE_ID" > "$BUNDLE_OUT"
cat "$BUNDLE_OUT"
assert_contains "$BUNDLE_OUT" "RuntimeBundle"
assert_contains "$BUNDLE_OUT" "$NODE_ID"
assert_contains "$BUNDLE_OUT" "\"generation\":1|generation.*1"
pass "09.3: runtime bundle is pullable"

ACK_HTTP=$(curl -s -o "$RESULTS_DIR/bundle-ack.txt" -w "%{http_code}" \
  -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/bundle-acks" \
  -H "Content-Type: application/json" \
  -d '{"status":"activated","generation":1}')
[[ "$ACK_HTTP" == "200" ]] || fail "bundle ack returned HTTP $ACK_HTTP"
pass "09.4: bundle ack accepted"

RECEIPTS_OUT="$RESULTS_DIR/receipts.json"
forge_post_receipts "$NODE_ID" > "$RECEIPTS_OUT"
cat "$RECEIPTS_OUT"
assert_contains "$RECEIPTS_OUT" "receipt-it-1"
pass "09.5: receipt upload accepted and IDs returned"

FINDINGS_HTTP=$(curl -s -o "$RESULTS_DIR/findings.txt" -w "%{http_code}" \
  -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/findings" \
  -H "Content-Type: application/json" \
  -d '[{"id":"finding-it-1","severity":"info"}]')
[[ "$FINDINGS_HTTP" == "200" ]] || fail "findings upload returned HTTP $FINDINGS_HTTP"
pass "09.6: findings upload accepted"

PROPOSAL_OUT="$RESULTS_DIR/baseline-proposal.json"
forge_post_baseline_proposal "$NODE_ID" > "$PROPOSAL_OUT"
cat "$PROPOSAL_OUT"
assert_contains "$PROPOSAL_OUT" "proposal-$NODE_ID"
pass "09.7: baseline proposal accepted"

stop_forge
pass "09: Forge managed-mode API contract complete"
