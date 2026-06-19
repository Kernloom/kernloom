#!/usr/bin/env bash
# Central environment for Kernloom integration tests.
# Source this file in every script and scenario.

set -euo pipefail

export KLT_RUN_ID="${KLT_RUN_ID:-$$}"
export KLT_ROOT="${KLT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

KLT_ARTIFACT_OWNER_ID="${SUDO_UID:-$(id -u)}"
export KLT_ARTIFACT_BASE_DIR="${KLT_ARTIFACT_BASE_DIR:-/tmp/kernloom-integration-artifacts-$KLT_ARTIFACT_OWNER_ID}"
export KLT_ARTIFACT_DIR="${KLT_ARTIFACT_DIR:-$KLT_ARTIFACT_BASE_DIR/$KLT_RUN_ID}"

if [[ -z "${KLT_GO:-}" ]]; then
  if command -v go >/dev/null 2>&1; then
    export KLT_GO="$(command -v go)"
  elif [[ -x /usr/local/go/bin/go ]]; then
    export KLT_GO="/usr/local/go/bin/go"
  else
    export KLT_GO="go"
  fi
fi

# Binaries
export KLT_KLSHIELD="${KLT_KLSHIELD:-$KLT_ROOT/bin/klshield}"
export KLT_KLIQ="${KLT_KLIQ:-$KLT_ROOT/bin/kliq}"
export KLT_BPF_OBJ="${KLT_BPF_OBJ:-$KLT_ROOT/shield/bpf/out/xdp_kernloom_shield.bpf.o}"
export KLT_FORGE="${KLT_FORGE:-$KLT_ROOT/bin/forge}"

# Forge control-plane (no-XDP integration tests)
export KLT_FORGE_ADDR="${KLT_FORGE_ADDR:-127.0.0.1:17443}"
export KLT_FORGE_URL="http://$KLT_FORGE_ADDR"
export KLT_FORGE_DB="${KLT_FORGE_DB:-$KLT_ARTIFACT_DIR/forge-it.db}"
export KLT_FORGE_ADMIN_KEY="${KLT_FORGE_ADMIN_KEY:-it-admin-key-$$}"
export KLT_FORGE_LOG="$KLT_ARTIFACT_DIR/forge.log"
# kernloom-forge repo expected as sibling of kernloom repo
export KLT_FORGE_ROOT="${KLT_FORGE_ROOT:-$(cd "$KLT_ROOT/../kernloom-forge" 2>/dev/null && pwd || echo "")}"
if [[ -z "${KLT_FORGE_ADAPTERS:-}" ]]; then
  if [[ -n "$KLT_FORGE_ROOT" && -d "$KLT_FORGE_ROOT/registries/adapters" ]]; then
    export KLT_FORGE_ADAPTERS="$KLT_FORGE_ROOT/registries/adapters"
  elif [[ -n "$KLT_FORGE_ROOT" && -d "$KLT_FORGE_ROOT/examples/adapters" ]]; then
    export KLT_FORGE_ADAPTERS="$KLT_FORGE_ROOT/examples/adapters"
  else
    export KLT_FORGE_ADAPTERS="$KLT_FORGE_ROOT/registries/adapters"
  fi
fi
if [[ -z "${KLT_FORGE_PROFILES:-}" ]]; then
  if [[ -n "$KLT_FORGE_ROOT" && -d "$KLT_FORGE_ROOT/examples/profiles" ]]; then
    export KLT_FORGE_PROFILES="$KLT_FORGE_ROOT/examples/profiles"
  else
    export KLT_FORGE_PROFILES="$KLT_FORGE_ROOT/examples/profiles"
  fi
fi
export KLT_FORGE_SIGNING_KEY="$KLT_ARTIFACT_DIR/forge-signing.key"

# Network namespaces and IPs
export KLT_BR="${KLT_BR:-br-klt}"
export KLT_NS_GOOD="${KLT_NS_GOOD:-klt-good}"
export KLT_NS_BAD="${KLT_NS_BAD:-klt-bad}"
export KLT_NS_API="${KLT_NS_API:-klt-api}"
export KLT_IP_GOOD="${KLT_IP_GOOD:-10.42.0.11}"
export KLT_IP_BAD="${KLT_IP_BAD:-10.42.0.66}"
export KLT_IP_API="${KLT_IP_API:-10.42.0.20}"
export KLT_API_PORT="${KLT_API_PORT:-8080}"

# veth interface names (host side / namespace side)
export KLT_VETH_GOOD_HOST="veth-good-h"
export KLT_VETH_BAD_HOST="veth-bad-h"
export KLT_VETH_API_HOST="veth-api-h"
export KLT_IF_GOOD="good0"
export KLT_IF_BAD="bad0"
export KLT_IF_API="api0"

# XDP attaches to the HOST-side veths of the client namespaces.
# veth-good-h sees ingress from klt-good (10.42.0.11).
# veth-bad-h  sees ingress from klt-bad  (10.42.0.66).
# Both run in the host namespace — no ip netns exec needed, and both
# client IPs appear correctly in kliq telemetry. Shared maps mean one
# kliq instance handles both interfaces (multi-interface / Variante A).
export KLT_XDP_IFACE1="$KLT_VETH_GOOD_HOST"
export KLT_XDP_IFACE2="$KLT_VETH_BAD_HOST"

# Runtime directories — kept inside the per-run artifact dir so every run
# is fully self-contained and cleanup never touches global system paths.
export KLT_STATE_DIR="${KLT_STATE_DIR:-$KLT_ARTIFACT_DIR/state}"
export KLT_ETC_DIR="${KLT_ETC_DIR:-$KLT_ARTIFACT_DIR/etc}"

# Log files (created inside artifact dir)
export KLT_LOG_KLIQ="$KLT_ARTIFACT_DIR/kliq.log"
export KLT_LOG_SHIELD="$KLT_ARTIFACT_DIR/klshield.log"
export KLT_LOG_SERVER="$KLT_ARTIFACT_DIR/server.log"
