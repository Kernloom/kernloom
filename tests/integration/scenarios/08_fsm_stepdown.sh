#!/usr/bin/env bash
# Scenario 08: FSM stepdown after attack stops.
#
# Verifies that a blocked/rate-limited source recovers to OBSERVE after
# the enforcement TTL expires and enough clean ticks pass.
# Without the maintenance sweep fix, sources stayed stuck in HARD/BLOCK
# forever once traffic stopped (Advance() was never called).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

stop_kliq

sudo mkdir -p "$KLT_STATE_DIR" "$KLT_ETC_DIR"
sudo cp "$KLT_ROOT/tests/integration/testdata/whitelist.txt" "$KLT_ETC_DIR/whitelist.txt"
sudo cp "$KLT_ROOT/tests/integration/testdata/feedback.json" "$KLT_STATE_DIR/feedback.json"
sudo rm -f "$KLT_STATE_DIR/state.json"

STEPDOWN_LOG="$KLT_ARTIFACT_DIR/kliq-08.log"

# Start kliq with very short TTLs so stepdown happens within the test window.
#   soft-ttl=5s hard-ttl=5s block-ttl=5s down-need=2 min-hold-hard=0
sudo "$KLT_KLIQ" \
  --state-file="$KLT_STATE_DIR/state.json" \
  --feedback-file="$KLT_STATE_DIR/feedback.json" \
  --whitelist="$KLT_ETC_DIR/whitelist.txt" \
  --db="$KLT_STATE_DIR/kliq.db" \
  --bpffs-root=/sys/fs/bpf \
  --interval=1s \
  --dry-run=false \
  --bootstrap=false \
  --autotune=false \
  --min-pps=1 \
  --trig-pps=5 \
  --trig-syn=5 \
  --trig-scan=3 \
  --soft-at=2 \
  --hard-at=4 \
  --block-at=6 \
  --up-need=1 \
  --down-need=2 \
  --soft-ttl=5s \
  --hard-ttl=5s \
  --block-ttl=5s \
  --min-hold-hard=0s \
  > "$STEPDOWN_LOG" 2>&1 &
echo "$!" > "$KLT_ARTIFACT_DIR/kliq.pid"
sleep 2

echo "[08] phase 1: generating bad traffic to trigger enforcement"
bad_http_burst 200
sleep 6

# Verify enforcement was applied.
assert_contains "$STEPDOWN_LOG" "${KLT_IP_BAD}"
assert_contains "$STEPDOWN_LOG" "ACTION ip=${KLT_IP_BAD}"

echo "[08] phase 2: bad traffic stopped — waiting for recovery (TTL=5s + 2 clean ticks)"
# TTL=5s + down-need=2 ticks + margin = ~10s
sleep 12

echo "[08] phase 3: verifying bad source can reach API again"
RECOVER_OK=0
for _ in $(seq 1 5); do
  if sudo ip netns exec "$KLT_NS_BAD" \
       curl -fsS --max-time 3 "$(api_url)" >/dev/null 2>&1; then
    RECOVER_OK=$((RECOVER_OK + 1))
  fi
  sleep 0.5
done

echo "[08] recovery checks: $RECOVER_OK/5 succeeded"
cat "$STEPDOWN_LOG" | grep -E "STATE|OBSERVE|stepdown|decay|fsm" | tail -10 || true

# At least 4/5 requests must succeed after recovery.
[[ "$RECOVER_OK" -ge 4 ]] \
  || fail "08: bad source did not recover after attack stopped ($RECOVER_OK/5 requests succeeded)"

# Log must show a downward FSM transition (e.g. HARD->SOFT or SOFT->OBSERVE or BLOCK->HARD).
# Log shows RATE_SOFT->OBSERVE or RATE_HARD->OBSERVE on stepdown.
assert_contains "$STEPDOWN_LOG" "->OBSERVE"

pass "08: FSM stepped down after attack stopped — source recovered in ~$(( 5 + 2 ))s"
