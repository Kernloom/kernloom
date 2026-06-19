#!/usr/bin/env bash
# Scenario 03: RuntimePDP active mode — bad source triggers enforcement.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

stop_kliq  # stop dry-run instance from scenario 02 if still running

start_kliq_enforce

# Good traffic — should remain clean.
good_http_many 5

# Bad burst to trigger RuntimePDP enforcement via generic FSM intent facts.
bad_http_burst 300

# Give kliq multiple ticks to escalate.
sleep 8

# Good client must still be reachable.
assert_http_ok "$KLT_NS_GOOD" "$(api_url)"

# kliq must have logged enforcement decisions for the bad source.
assert_contains "$KLT_LOG_KLIQ" "${KLT_IP_BAD}"
assert_contains "$KLT_LOG_KLIQ" "STATE ${KLT_IP_BAD} .*->(RATE_SOFT|RATE_HARD|BLOCK)|ACTION-RECEIPT.*${KLT_IP_BAD}"

# Shield stats must show drops (rate-limit or deny) for the bad source.
STATS="$KLT_ARTIFACT_DIR/stats-03.txt"
sudo "$KLT_KLSHIELD" stats > "$STATS" 2>&1
cat "$STATS"
# At least one of drop_rl or drop_deny must be > 0.
RL=$(grep -oE "drop_rl=[0-9]+" "$STATS" | cut -d= -f2 || echo 0)
DN=$(grep -oE "drop_deny=[0-9]+" "$STATS" | cut -d= -f2 || echo 0)
[[ "$RL" -gt 0 || "$DN" -gt 0 ]] \
  || fail "expected drop_rl or drop_deny > 0, got drop_rl=$RL drop_deny=$DN"

pass "03: RuntimePDP active mode — bad source escalated, good source unaffected"
