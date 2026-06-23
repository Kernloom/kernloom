#!/usr/bin/env bash
# Scenario 09: Forge managed-mode API contract.
#
# Does NOT require XDP/eBPF. Exercises the current Forge MVP API that KLIQ
# talks to in managed mode:
#   - serve starts with adapter/profile examples
#   - /healthz is available
#   - node enrollment returns a session token
#   - runtime-bundle is pullable when adapters+profiles are configured
#   - label-based assignments can select the correct intent for the node
#   - bundle acks, receipts, findings, proposals and status reports are accepted
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"

NODE_ID="it-node-09"
RESULTS_DIR="$KLT_ARTIFACT_DIR/09"
mkdir -p "$RESULTS_DIR"

stop_forge 2>/dev/null || true

if [[ -z "${KLT_FORGE_ASSIGNMENTS:-}" ]]; then
  INTENT_SRC="$RESULTS_DIR/label-placement.intent"
  INTENT_OUT="$RESULTS_DIR/label-placement"
  ASSIGNMENTS="$RESULTS_DIR/label-placement-assignments.yaml"
  cat > "$INTENT_SRC" <<'EOF'
intent "it-label-placement"

protect service "ziti-controller" in "production"

compose:
  access "it-label-placement"

access "it-label-placement":
  allow all
EOF
  "$KLT_FORGE" intent convert \
    --input "$INTENT_SRC" \
    --output-dir "$INTENT_OUT" \
    --emit-policy-intent \
    --compile-target klshield-local \
    >/dev/null
  cat > "$ASSIGNMENTS" <<EOF
apiVersion: kernloom.io/v1alpha1
kind: NodePolicyAssignments
metadata:
  name: it-label-placement
spec:
  assignments:
    - id: it-label-klshield
      intent: label-placement/policy-intent.yaml
      target: klshield-local
      nodeSelector:
        labels:
          role: edge-gateway
          env: production
          service: ziti-controller
        adapters:
          - klshield
        capabilities:
          - enforce.traffic.rate_limit
EOF
  export KLT_FORGE_ASSIGNMENTS="$ASSIGNMENTS"
fi
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
SESSION_TOKEN=$(sed -n 's/.*"session_token":"\([^"]*\)".*/\1/p' "$ENROLL_RESP")
[[ -n "$SESSION_TOKEN" ]] || fail "session_token was empty"
pass "09.2: node enrollment with labels returns approved session token"

BUNDLE_OUT="$RESULTS_DIR/runtime-bundle.yaml"
forge_pull_bundle "$NODE_ID" "$SESSION_TOKEN" > "$BUNDLE_OUT"
cat "$BUNDLE_OUT"
assert_contains "$BUNDLE_OUT" "RuntimeBundle"
assert_contains "$BUNDLE_OUT" "$NODE_ID"
assert_contains "$BUNDLE_OUT" "\"generation\":1|generation.*1"
if [[ -n "${KLT_FORGE_ASSIGNMENTS:-}" ]]; then
  assert_contains "$KLT_FORGE_LOG" "assignment=it-label-klshield"
  assert_contains "$KLT_FORGE_LOG" "target=klshield-local"
fi
pass "09.3: label-matched runtime bundle is pullable"

ACK_HTTP=$(curl -s -o "$RESULTS_DIR/bundle-ack.txt" -w "%{http_code}" \
  -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/bundle-acks" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"activated","generation":1}')
[[ "$ACK_HTTP" == "200" ]] || fail "bundle ack returned HTTP $ACK_HTTP"
pass "09.4: bundle ack accepted"

RECEIPTS_OUT="$RESULTS_DIR/receipts.json"
forge_post_receipts "$NODE_ID" "$SESSION_TOKEN" > "$RECEIPTS_OUT"
cat "$RECEIPTS_OUT"
assert_contains "$RECEIPTS_OUT" "receipt-it-1"
pass "09.5: receipt upload accepted and IDs returned"

FINDINGS_HTTP=$(curl -s -o "$RESULTS_DIR/findings.txt" -w "%{http_code}" \
  -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/findings" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{"apiVersion":"kernloom.io/runtime/v1alpha1","kind":"RuntimeFinding","metadata":{"id":"finding-it-1"},"severity":"info","title":"integration finding","subject":{"kind":"source","id":"10.42.0.66"}}]')
[[ "$FINDINGS_HTTP" == "200" ]] || fail "findings upload returned HTTP $FINDINGS_HTTP"
pass "09.6: findings upload accepted"

PROPOSAL_OUT="$RESULTS_DIR/baseline-proposal.json"
forge_post_baseline_proposal "$NODE_ID" "$SESSION_TOKEN" > "$PROPOSAL_OUT"
cat "$PROPOSAL_OUT"
assert_contains "$PROPOSAL_OUT" "proposal-$NODE_ID"
pass "09.7: baseline proposal accepted"

GRAPH_OUT="$RESULTS_DIR/graph-proposal.json"
forge_post_graph_proposal "$NODE_ID" "$SESSION_TOKEN" > "$GRAPH_OUT"
cat "$GRAPH_OUT"
assert_contains "$GRAPH_OUT" "graph-proposal-$NODE_ID"
pass "09.8: graph proposal accepted"

forge_post_risk_assessment "$NODE_ID" "$SESSION_TOKEN" > "$RESULTS_DIR/risk-assessments.txt"
forge_post_health_report "$NODE_ID" "$SESSION_TOKEN" > "$RESULTS_DIR/health-reports.txt"
forge_post_decision_summary "$NODE_ID" "$SESSION_TOKEN" > "$RESULTS_DIR/decision-summaries.txt"
forge_post_adapter_status "$NODE_ID" "$SESSION_TOKEN" > "$RESULTS_DIR/adapter-status.txt"
forge_post_failover_status "$NODE_ID" "$SESSION_TOKEN" > "$RESULTS_DIR/failover-status.txt"
pass "09.9: typed runtime feedback reports accepted"

stop_forge
pass "09: Forge managed-mode API contract complete"
