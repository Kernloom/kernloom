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

# Clear any deny/rate-limit entries left by previous scenarios so the bad
# source is not already blocked when this scenario starts.
sudo "$KLT_KLSHIELD" reset 2>/dev/null || true

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

echo "[08] phase 1: generating bad traffic for 15s to trigger enforcement"
sudo ip netns exec "$KLT_NS_BAD" bash -c "
  while true; do
    curl -s --max-time 1 http://$KLT_IP_API:$KLT_API_PORT/ >/dev/null 2>&1 || true
    sleep 0.05
  done
" &
BAD_PID=$!

# Give kliq time to escalate (TTL=5s, soft-at=2 → ~3 ticks).
sleep 8

# Verify enforcement was applied while traffic is still running.
assert_contains "$STEPDOWN_LOG" "${KLT_IP_BAD}"
assert_contains "$STEPDOWN_LOG" "ACTION ip=${KLT_IP_BAD}"

echo "[08] phase 2: stopping bad traffic — waiting for recovery (TTL=5s + 2 clean ticks)"
sudo kill "$BAD_PID" 2>/dev/null || true
wait "$BAD_PID" 2>/dev/null || true
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
grep -E -- "STATE|OBSERVE|stepdown|decay|fsm" "$STEPDOWN_LOG" | tail -10 || true

# At least 4/5 requests must succeed after recovery.
[[ "$RECOVER_OK" -ge 4 ]] \
  || fail "08: bad source did not recover after attack stopped ($RECOVER_OK/5 requests succeeded)"

# Log must show a downward FSM transition (e.g. HARD->SOFT or SOFT->OBSERVE or BLOCK->HARD).
# Log shows RATE_SOFT->OBSERVE or RATE_HARD->OBSERVE on stepdown.
assert_contains "$STEPDOWN_LOG" "->OBSERVE"

pass "08: FSM stepped down after attack stopped — source recovered in ~$(( 5 + 2 ))s"
