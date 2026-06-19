#!/usr/bin/env bash
# Scenario 00: Smoke — verify binaries and BPF object exist and respond.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

assert_file_exists "$KLT_KLSHIELD"
assert_file_exists "$KLT_KLIQ"
assert_file_exists "$KLT_BPF_OBJ"

# kliq --help exits 2 (Go flag default) — capture output separately.
HELP_OUT=$("$KLT_KLIQ" --help 2>&1 || true)
echo "$HELP_OUT" | grep -qi "Kernloom\|USAGE\|kliq" \
  || fail "kliq --help produced unexpected output"
echo "$HELP_OUT" | grep -q "kliq run" \
  || fail "kliq --help does not advertise the run subcommand"

RUN_HELP_OUT=$("$KLT_KLIQ" run --help 2>&1 || true)
echo "$RUN_HELP_OUT" | grep -q "feature-profile" \
  || fail "kliq run --help does not show runtime flags"
echo "$RUN_HELP_OUT" | grep -q "runtime-pdp-mode" \
  || fail "kliq run --help does not show runtime PDP mode"

GRAPH_HELP_OUT=$("$KLT_KLIQ" graph --help 2>&1 || true)
echo "$GRAPH_HELP_OUT" | grep -q "freeze" \
  || fail "kliq graph --help does not show graph subcommands"

pass "smoke: binaries and BPF object present"
