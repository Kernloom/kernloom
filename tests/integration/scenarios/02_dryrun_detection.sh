#!/usr/bin/env bash
# Scenario 02: kliq dry-run — bad traffic is detected but not blocked.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

start_kliq_dryrun

# Good traffic first (establishes baseline / clean ticks).
good_http_many 5

# Bad traffic burst to trigger detection.
bad_http_burst 200

# Give kliq time to process the ticks.
sleep 5

# Both good and bad sources must still reach API in dry-run.
assert_http_ok "$KLT_NS_GOOD" "$(api_url)"
assert_http_ok "$KLT_NS_BAD"  "$(api_url)"

# kliq must have logged something about the bad source.
assert_contains "$KLT_LOG_KLIQ" "TICK"
assert_contains "$KLT_LOG_KLIQ" "${KLT_IP_BAD}"

# Must NOT have written any actual enforcement (dry-run).
# In dry-run no ACTION lines with dry_run=false should appear.
assert_not_contains "$KLT_LOG_KLIQ" "dry_run=false"

pass "02: dry-run detected bad source, no enforcement, API reachable for both"
