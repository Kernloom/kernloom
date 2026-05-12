#!/usr/bin/env bash
# Scenario 05: Restart recovery — kliq and klshield restart cleanly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

# Good traffic must work before restart.
assert_http_ok "$KLT_NS_GOOD" "$(api_url)"

# Restart kliq.
stop_kliq
sleep 1
start_kliq_dryrun

assert_http_ok "$KLT_NS_GOOD" "$(api_url)"
assert_contains "$KLT_LOG_KLIQ" "TICK"

# Detach and reattach XDP.
detach_xdp
sleep 1
attach_xdp

assert_http_ok "$KLT_NS_GOOD" "$(api_url)"

STATS="$KLT_ARTIFACT_DIR/stats-05.txt"
sudo "$KLT_KLSHIELD" stats > "$STATS" 2>&1
assert_stats_field_gt "$STATS" "pkts" 0

pass "05: kliq and klshield restarted cleanly, API reachable"
