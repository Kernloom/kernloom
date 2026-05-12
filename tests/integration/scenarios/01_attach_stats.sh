#!/usr/bin/env bash
# Scenario 01: Attach XDP, send good traffic, verify Shield sees packets.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/netns.sh"
source "$SCRIPT_DIR/../lib/processes.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

setup_topology
start_http_server
attach_xdp

# Verify good client can reach the API.
assert_http_ok "$KLT_NS_GOOD" "$(api_url)"

# Send several requests to accumulate counters.
good_http_many 10

# Capture stats.
STATS="$KLT_ARTIFACT_DIR/stats-01.txt"
sudo "$KLT_KLSHIELD" stats > "$STATS" 2>&1
cat "$STATS"

# XDP must have seen packets.
assert_stats_field_gt "$STATS" "pkts" 0
assert_stats_field_gt "$STATS" "pass" 0

# API still reachable after XDP attach.
assert_http_ok "$KLT_NS_GOOD" "$(api_url)"

pass "01: XDP attached, Shield sees traffic, API reachable"
