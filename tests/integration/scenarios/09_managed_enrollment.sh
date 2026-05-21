#!/usr/bin/env bash
# Scenario 09: Managed enrollment — Forge + KLIQ control-plane flow.
# Does NOT require XDP/eBPF. Simulates KLIQ via curl.
#
# Tests:
#   - forge serve starts and seeds adapter definitions
#   - enrollment token creation and one-time use
#   - node enrollment with inventory (builtin-klshield plugin)
#   - session token returned and reusable
#   - node approval by operator
#   - policy pack registration and assignment
#   - runtime bundle creation and assignment
#   - heartbeat delivers bundle (X-Bundle-Generation header)
#   - second use of enrollment token is rejected (one-time guarantee)
#   - session token persists across forge restart (DB-backed)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"

NODE_ID="it-node-09"
RESULTS_DIR="$KLT_ARTIFACT_DIR/09"
mkdir -p "$RESULTS_DIR"

stop_forge 2>/dev/null || true

# ── 1. Start forge serve ──────────────────────────────────────────────────────

start_forge

assert_contains "$KLT_FORGE_LOG" "listening on"
echo "[09] forge started"

# ── 2. Adapter definitions auto-seeded ───────────────────────────────────────

ADAPTERS_OUT="$RESULTS_DIR/adapters.txt"
"$KLT_FORGE" adapter list --db "$KLT_FORGE_DB" > "$ADAPTERS_OUT"
assert_contains "$ADAPTERS_OUT" "klshield"
assert_contains "$ADAPTERS_OUT" "kliq"
echo "[09] adapter definitions registered: $(grep -c '^\w' "$ADAPTERS_OUT") definitions"

pass "09.1: adapter definitions auto-seeded on startup"

# ── 3. Enrollment token — one-time use ───────────────────────────────────────

TOKEN=$(forge_create_token "$NODE_ID")
[[ -n "$TOKEN" ]] || fail "token creation returned empty"
echo "[09] enrollment token: ${TOKEN:0:20}..."

pass "09.2: enrollment token created"

# ── 4. Node enrollment ────────────────────────────────────────────────────────

ENROLL_RESP="$RESULTS_DIR/enroll.json"
forge_simulate_enroll "$NODE_ID" "$TOKEN" "builtin-klshield" > "$ENROLL_RESP"
cat "$ENROLL_RESP"

assert_contains "$ENROLL_RESP" '"node_id"'
assert_contains "$ENROLL_RESP" '"session_token"'
assert_contains "$ENROLL_RESP" '"pending"'

SESSION_TOKEN=$(jq -r .session_token "$ENROLL_RESP")
[[ -n "$SESSION_TOKEN" && "$SESSION_TOKEN" != "null" ]] || fail "no session token in enrollment response"

pass "09.3: node enrolled, session token received"

# ── 5. Token is single-use ────────────────────────────────────────────────────

REUSE_HTTP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$KLT_FORGE_URL/api/v1/nodes/enroll" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"node_id\": \"other-node\", \"mode\": \"managed\"}")
[[ "$REUSE_HTTP" == "401" ]] || fail "reuse of enrollment token should return 401, got $REUSE_HTTP"

pass "09.4: enrollment token is single-use (second use → 401)"

# ── 6. Node approve ───────────────────────────────────────────────────────────

forge_admin -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/approve" > /dev/null
NODES_OUT="$RESULTS_DIR/nodes.txt"
"$KLT_FORGE" nodes list --db "$KLT_FORGE_DB" > "$NODES_OUT"
assert_contains "$NODES_OUT" "approved"
assert_contains "$NODES_OUT" "$NODE_ID"

pass "09.5: node approved"

# ── 7. Pack registration and assignment ───────────────────────────────────────
# Write a minimal LocalPolicyPack directly — no compile/sign needed for this test.
# Forge stores the raw content and delivers it to KLIQ; signature is verified by KLIQ,
# not Forge. The test only checks that the delivery API works (HTTP 200).

PACK_FILE="$RESULTS_DIR/test.pack.yaml"
cat > "$PACK_FILE" << 'YAML'
apiVersion: kernloom.io/kliq/v1alpha1
kind: LocalPolicyPack
metadata:
  name: it-test-pack
  issued_at: "2026-01-01T00:00:00Z"
spec:
  mode: managed
  autonomy:
    max_action: observe
  rules: []
YAML

"$KLT_FORGE" pack register "$PACK_FILE" \
  --db "$KLT_FORGE_DB"

forge_admin -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/assign-pack?pack=it-test-pack" > /dev/null

PACK_HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/policy-pack" \
  -H "Authorization: Bearer $SESSION_TOKEN")
[[ "$PACK_HTTP" == "200" ]] || fail "policy pack pull returned $PACK_HTTP, expected 200"

pass "09.6: pack registered, assigned, and pullable"

# ── 8. RuntimeBundle registration and assignment ──────────────────────────────

BUNDLE_FILE="$RESULTS_DIR/test-bundle.yaml"
"$KLT_FORGE" bundle create \
  --node-id "$NODE_ID" \
  --feature-profile graph-enforce \
  --generation 1 \
  -o "$BUNDLE_FILE" 2>/dev/null

BUNDLE_REG="$RESULTS_DIR/bundle-reg.json"
forge_admin -X POST "$KLT_FORGE_URL/api/v1/bundles?node_id=$NODE_ID" \
  -H "Content-Type: application/yaml" \
  --data-binary "@$BUNDLE_FILE" > "$BUNDLE_REG"
cat "$BUNDLE_REG"

BUNDLE_ID=$(jq -r .id "$BUNDLE_REG")
[[ -n "$BUNDLE_ID" && "$BUNDLE_ID" != "null" ]] || fail "bundle registration returned no id"

forge_admin -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/assign-bundle?bundle=$BUNDLE_ID" > /dev/null

# Pull bundle via session token.
BUNDLE_PULL_HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/runtime-bundle" \
  -H "Authorization: Bearer $SESSION_TOKEN")
[[ "$BUNDLE_PULL_HTTP" == "200" ]] || fail "bundle pull returned $BUNDLE_PULL_HTTP, expected 200"

# Check generation header.
BUNDLE_GEN=$(curl -sf \
  "$KLT_FORGE_URL/api/v1/nodes/$NODE_ID/runtime-bundle" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -I | grep -i "X-Bundle-Generation" | tr -d '[:space:]\r' | cut -d: -f2)
[[ "$BUNDLE_GEN" == "1" ]] || fail "expected X-Bundle-Generation: 1, got '$BUNDLE_GEN'"

pass "09.7: bundle registered, assigned, pullable (gen=1)"

# ── 9. Heartbeat with session token ───────────────────────────────────────────

HB_RESP="$RESULTS_DIR/heartbeat.json"
forge_simulate_heartbeat "$NODE_ID" "$SESSION_TOKEN" > "$HB_RESP"
cat "$HB_RESP"

# Heartbeat must succeed (no error response).
assert_not_contains "$HB_RESP" '"error"'

pass "09.8: heartbeat accepted with session token"

# ── 10. Session token persists across forge restart ───────────────────────────

stop_forge
sleep 0.5
start_forge

HB_AFTER_RESTART="$RESULTS_DIR/heartbeat-after-restart.json"
forge_simulate_heartbeat "$NODE_ID" "$SESSION_TOKEN" > "$HB_AFTER_RESTART"
assert_not_contains "$HB_AFTER_RESTART" '"error"'

pass "09.9: session token valid after forge restart (DB-backed)"

# ── 11. Revoked node cannot pull pack ─────────────────────────────────────────

NODE_REVOKE="it-revoke-09"
TOKEN2=$(forge_create_token "$NODE_REVOKE")
ENROLL2=$(forge_simulate_enroll "$NODE_REVOKE" "$TOKEN2")
SESSION2=$(echo "$ENROLL2" | jq -r .session_token)
forge_admin -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_REVOKE/approve" > /dev/null
forge_admin -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_REVOKE/revoke" > /dev/null

REVOKE_HTTP=$(curl -s -o /dev/null -w "%{http_code}" \
  "$KLT_FORGE_URL/api/v1/nodes/$NODE_REVOKE/policy-pack" \
  -H "Authorization: Bearer $SESSION2")
[[ "$REVOKE_HTTP" == "401" || "$REVOKE_HTTP" == "403" ]] \
  || fail "revoked node pack pull should return 401 or 403, got $REVOKE_HTTP"

pass "09.10: revoked node cannot pull pack (→ $REVOKE_HTTP)"

stop_forge
pass "09: managed enrollment scenario complete"
