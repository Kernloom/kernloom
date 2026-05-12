#!/usr/bin/env bash
# Central environment for Kernloom integration tests.
# Source this file in every script and scenario.

set -euo pipefail

export KLT_RUN_ID="${KLT_RUN_ID:-$$}"
export KLT_ROOT="${KLT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"

export KLT_ARTIFACT_DIR="${KLT_ARTIFACT_DIR:-$KLT_ROOT/tests/integration/artifacts/$KLT_RUN_ID}"

# Binaries
export KLT_KLSHIELD="$KLT_ROOT/bin/klshield"
export KLT_KLIQ="$KLT_ROOT/bin/kliq"
export KLT_BPF_OBJ="$KLT_ROOT/shield/bpf/out/xdp_kernloom_shield.bpf.o"

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

# XDP attaches to api0 inside the klt-api network namespace so ingress
# traffic from clients is seen correctly. The bpffs mount is shared with
# the host (ip netns exec only switches network ns, not mount ns), so
# kliq and klshield stats read the same pins from the host namespace.
export KLT_XDP_IFACE="$KLT_IF_API"
export KLT_XDP_NS="$KLT_NS_API"

# Runtime directories (separate from production paths)
export KLT_STATE_DIR="${KLT_STATE_DIR:-/var/lib/kernloom/iq-it}"
export KLT_ETC_DIR="${KLT_ETC_DIR:-/etc/kernloom-it}"

# Log files (created inside artifact dir)
export KLT_LOG_KLIQ="$KLT_ARTIFACT_DIR/kliq.log"
export KLT_LOG_SHIELD="$KLT_ARTIFACT_DIR/klshield.log"
export KLT_LOG_SERVER="$KLT_ARTIFACT_DIR/server.log"
