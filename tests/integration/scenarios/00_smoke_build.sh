#!/usr/bin/env bash
# Scenario 00: Smoke — verify binaries and BPF object exist and respond.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/assert.sh"

assert_file_exists "$KLT_KLSHIELD"
assert_file_exists "$KLT_KLIQ"
assert_file_exists "$KLT_BPF_OBJ"

# kliq --help must exit 0 and print something meaningful.
"$KLT_KLIQ" --help 2>&1 | grep -qi "Kernloom\|USAGE\|kliq" \
  || fail "kliq --help produced unexpected output"

pass "smoke: binaries and BPF object present"
