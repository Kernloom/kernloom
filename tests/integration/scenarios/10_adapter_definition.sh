#!/usr/bin/env bash
# Scenario 10: Adapter definition — seeding, auto-assign, nodes list.
# Does NOT require XDP/eBPF.
#
# Tests:
#   - forge serve auto-seeds registries/adapters/ on startup
#   - forge adapter list shows klshield, kliq, tcp-proxy from DB
#   - enrolling with builtin-klshield inventory matches klshield definition
#   - forge adapter auto-assign matches stored inventory without re-enrollment
#   - forge nodes list shows ADAPTER and AUTO-ENROLL columns correctly
#   - manual assign overrides existing definition
#   - enable-auto flag persists and shows in nodes list
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"

NODE_SHIELD="it-shield-10"
NODE_PROXY="it-proxy-10"
RESULTS_DIR="$KLT_ARTIFACT_DIR/10"
mkdir -p "$RESULTS_DIR"

stop_forge 2>/dev/null || true

# ── 1. Start forge — adapter definitions auto-seeded ─────────────────────────

start_forge

assert_contains "$KLT_FORGE_LOG" "adapter definitions"

ADAPTER_LIST="$RESULTS_DIR/adapters-db.txt"
"$KLT_FORGE" adapter list --db "$KLT_FORGE_DB" > "$ADAPTER_LIST"
assert_contains "$ADAPTER_LIST" "klshield"
assert_contains "$ADAPTER_LIST" "kliq"
assert_contains "$ADAPTER_LIST" "tcp-proxy"
echo "[10] registered definitions:"
cat "$ADAPTER_LIST"

pass "10.1: adapter definitions auto-seeded (klshield, kliq, tcp-proxy)"

# ── 2. forge adapter list without --db reads from filesystem ──────────────────

FS_LIST="$RESULTS_DIR/adapters-fs.txt"
"$KLT_FORGE" adapter list \
  --adapters "${KLT_FORGE_ADAPTERS}" > "$FS_LIST"
assert_contains "$FS_LIST" "klshield"
assert_contains "$FS_LIST" "kliq"
assert_contains "$FS_LIST" "FILE"   # filesystem list shows FILE column, not HASH
echo "[10] filesystem adapter list:"
cat "$FS_LIST"

pass "10.2: forge adapter list (no --db) reads from filesystem"

# ── 3. forge adapter show returns YAML ────────────────────────────────────────

SHOW_OUT="$RESULTS_DIR/klshield-show.yaml"
"$KLT_FORGE" adapter show klshield --db "$KLT_FORGE_DB" > "$SHOW_OUT"
assert_contains "$SHOW_OUT" "plugin_match"
assert_contains "$SHOW_OUT" "builtin-klshield"
assert_contains "$SHOW_OUT" "enforce.traffic.rate_limit"

pass "10.3: forge adapter show klshield contains plugin_match and capabilities"

# ── 4. Auto-assign at enrollment (auto_eligible = true) ──────────────────────

TOKEN_SHIELD=$(forge_create_token "$NODE_SHIELD")
ENROLL_SHIELD="$RESULTS_DIR/enroll-shield.json"
forge_simulate_enroll "$NODE_SHIELD" "$TOKEN_SHIELD" "builtin-klshield" \
  > "$ENROLL_SHIELD"
SESSION_SHIELD=$(jq -r .session_token "$ENROLL_SHIELD")

# Enable auto-assignment before re-checking.
"$KLT_FORGE" adapter enable-auto "$NODE_SHIELD" --db "$KLT_FORGE_DB" 2>/dev/null

# Simulate auto-assign from stored inventory.
AUTO_OUT="$RESULTS_DIR/auto-assign-shield.txt"
"$KLT_FORGE" adapter auto-assign "$NODE_SHIELD" \
  --db "$KLT_FORGE_DB" > "$AUTO_OUT" 2>&1
assert_contains "$AUTO_OUT" "klshield"
assert_contains "$AUTO_OUT" "builtin-klshield"

pass "10.4: auto-assign matched builtin-klshield → klshield definition"

# ── 5. forge nodes list shows ADAPTER and AUTO-ENROLL ────────────────────────

forge_admin -X POST "$KLT_FORGE_URL/api/v1/nodes/$NODE_SHIELD/approve" > /dev/null

NODES_OUT="$RESULTS_DIR/nodes.txt"
"$KLT_FORGE" nodes list --db "$KLT_FORGE_DB" > "$NODES_OUT"
echo "[10] nodes list:"
cat "$NODES_OUT"

assert_contains "$NODES_OUT" "AUTO-ENROLL"
assert_contains "$NODES_OUT" "$NODE_SHIELD"
assert_contains "$NODES_OUT" "klshield"
assert_contains "$NODES_OUT" "yes"   # AUTO-ENROLL = yes after enable-auto

pass "10.5: nodes list shows ADAPTER=klshield AUTO-ENROLL=yes"

# ── 6. Different plugin → different definition ────────────────────────────────

TOKEN_PROXY=$(forge_create_token "$NODE_PROXY")
forge_simulate_enroll "$NODE_PROXY" "$TOKEN_PROXY" "builtin-tcp-proxy" \
  > /dev/null

PROXY_AUTO="$RESULTS_DIR/auto-assign-proxy.txt"
"$KLT_FORGE" adapter auto-assign "$NODE_PROXY" \
  --db "$KLT_FORGE_DB" > "$PROXY_AUTO" 2>&1
assert_contains "$PROXY_AUTO" "tcp-proxy"

pass "10.6: auto-assign matched builtin-tcp-proxy → tcp-proxy definition"

# ── 7. Unknown plugin → no match, clear error ────────────────────────────────

TOKEN_UNK="$(forge_create_token)"
UNK_NODE="it-unknown-plugin-10"
forge_simulate_enroll "$UNK_NODE" "$TOKEN_UNK" "builtin-unknown-adapter" \
  > /dev/null

UNK_OUT="$RESULTS_DIR/auto-assign-unknown.txt"
"$KLT_FORGE" adapter auto-assign "$UNK_NODE" \
  --db "$KLT_FORGE_DB" > "$UNK_OUT" 2>&1 || true
assert_contains "$UNK_OUT" "no matching definition"

pass "10.7: unknown plugin → no match, clear error message"

# ── 8. Manual assign overrides auto-assigned definition ──────────────────────

# Manually override klshield → kliq on NODE_SHIELD.
"$KLT_FORGE" adapter assign "$NODE_SHIELD" \
  --definition kliq \
  --db "$KLT_FORGE_DB" 2>/dev/null

OVERRIDE_OUT="$RESULTS_DIR/nodes-override.txt"
"$KLT_FORGE" nodes list --db "$KLT_FORGE_DB" > "$OVERRIDE_OUT"
# After manual assignment: should show kliq (not klshield).
assert_contains "$OVERRIDE_OUT" "kliq"

pass "10.8: manual assign overrides auto-assigned definition"

# ── 9. Already-assigned node: auto-assign warns, does not overwrite ───────────

ALREADY_OUT="$RESULTS_DIR/auto-assign-already.txt"
"$KLT_FORGE" adapter auto-assign "$NODE_SHIELD" \
  --db "$KLT_FORGE_DB" > "$ALREADY_OUT" 2>&1
assert_contains "$ALREADY_OUT" "already has definition"
# Definition must still be kliq (not reverted to klshield).
FINAL_OUT="$RESULTS_DIR/nodes-final.txt"
"$KLT_FORGE" nodes list --db "$KLT_FORGE_DB" > "$FINAL_OUT"
assert_contains "$FINAL_OUT" "kliq"

pass "10.9: auto-assign warns when definition already set, does not overwrite"

stop_forge
pass "10: adapter definition scenario complete"
