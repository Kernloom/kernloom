#!/usr/bin/env bash
# Explicit cleanup target — also called by run.sh on EXIT.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../env.sh"
source "$SCRIPT_DIR/../lib/cleanup.sh"

cleanup_all
