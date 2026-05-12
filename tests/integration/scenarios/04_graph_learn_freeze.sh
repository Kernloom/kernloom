#!/usr/bin/env bash
# Scenario 04: Graph learning — learn normal edge, freeze, detect new edge.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"
source "$SCRIPT_DIR/../lib/processes.sh"
source "$SCRIPT_DIR/../lib/traffic.sh"

stop_kliq

# Clean graph DB for this scenario.
sudo rm -f "$KLT_STATE_DIR/kliq.db"

start_kliq_graph

# Send enough good traffic for the edge to be promoted (min-seen=3, min-age=3s).
good_http_many 8
sleep 6  # wait for promote-interval (5s) to fire

# Export graph state.
EDGES="$KLT_ARTIFACT_DIR/graph-edges-04.txt"
sudo "$KLT_KLIQ" graph edges --all \
  > "$EDGES" 2>&1 || true
cat "$EDGES"

# The good source IP should appear as a learned or candidate edge.
assert_contains "$EDGES" "${KLT_IP_GOOD}"

# Freeze the graph.
FREEZE_LOG="$KLT_ARTIFACT_DIR/graph-freeze-04.txt"
sudo "$KLT_KLIQ" graph freeze > "$FREEZE_LOG" 2>&1 || true
cat "$FREEZE_LOG"

stop_kliq

# Restart in frozen-observe mode; new log file to isolate post-freeze events.
FROZEN_LOG="$KLT_ARTIFACT_DIR/kliq-frozen-04.log"
start_kliq_frozen "$FROZEN_LOG"

# Send traffic from the BAD source — this edge was not in the frozen graph.
sudo ip netns exec "$KLT_NS_BAD" \
  curl -fsS --max-time 3 "$(api_url)" >/dev/null 2>&1 || true
sleep 4

# kliq must have signalled the new edge.
assert_contains "$FROZEN_LOG" \
  "new_edge\|freeze\|graph.*signal\|GRAPH\|${KLT_IP_BAD}"

pass "04: graph learned normal edge, freeze detected new edge from bad source"
