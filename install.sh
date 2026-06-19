#!/usr/bin/env sh
set -eu

# Kernloom installer
#
# Examples:
#   curl -fsSL https://raw.githubusercontent.com/Kernloom/kernloom/master/install.sh | sudo sh
#   curl -fsSL https://raw.githubusercontent.com/Kernloom/kernloom/master/install.sh | sudo sh -s -- klshield
#   curl -fsSL https://raw.githubusercontent.com/Kernloom/kernloom/master/install.sh | sudo KERNLOOM_VERSION=v0.0.1 sh
#   curl -fsSL https://raw.githubusercontent.com/Kernloom/kernloom/master/install.sh | sh -s -- --prefix "$HOME/.local/bin"

REPO="Kernloom/kernloom"
COMPONENT="all"            # all | kliq | klshield
KERNLOOM_VERSION="${KERNLOOM_VERSION:-latest}"
PREFIX="${PREFIX:-}"

# /opt/kernloom/ holds files that may be IMA-attested by Keylime:
#   bin/       — executables
#   bpf/       — BPF object (architecture-independent bytecode)
#   attested/  — config files measured by IMA (whitelist, frozen graph, policy/pdp YAML)
# /var/lib/kernloom/iq/ holds runtime state that changes frequently (not attested):
#   state.json, feedback.json, kliq-state.db
# Everything under /opt/kernloom/attested/ is IMA-measured by Keylime:
#   kliq, klshield        — executables (Keylime attests the binaries)
#   bpf/                  — BPF object
#   etc/                  — config files (whitelist, frozen graph, policy/pdp YAML)
# /var/lib/kernloom/iq/   — runtime state (changes frequently, not attested)
OPT_DIR="${OPT_DIR:-/opt/kernloom}"
ATTESTED_DIR="${ATTESTED_DIR:-$OPT_DIR/attested}"
SHARE_DIR="${SHARE_DIR:-$ATTESTED_DIR/bpf}"
IQ_ATTESTED_DIR="${IQ_ATTESTED_DIR:-$ATTESTED_DIR/etc}"
IQ_VAR_DIR="${IQ_VAR_DIR:-/var/lib/kernloom/iq}"
IQ_POLICY_DIR="${IQ_POLICY_DIR:-$ATTESTED_DIR/etc/policies}"
IQ_PDP_DIR="${IQ_PDP_DIR:-$ATTESTED_DIR/etc/pdp}"

# Keep legacy name for backward compat with ensure_iq_layout
IQ_ETC_DIR="$IQ_ATTESTED_DIR"
TMPDIR=""

usage() {
  cat <<USAGE
Kernloom installer

Usage:
  sh install.sh [all|kliq|klshield]
  sh install.sh [--version TAG] [--prefix DIR] [all|kliq|klshield]

Options:
  --version TAG   Install a specific release tag (default: latest)
  --prefix DIR    Install directory (default: /opt/kernloom/attested when root,
                  otherwise ~/.local/bin)
  -h, --help      Show this help

Environment:
  KERNLOOM_VERSION   Same as --version
  OPT_DIR            Base directory    (default: /opt/kernloom)
  ATTESTED_DIR       IMA-attested root (default: /opt/kernloom/attested)
  PREFIX             Binaries dir      (default: /opt/kernloom/attested when root)
  SHARE_DIR          BPF object        (default: /opt/kernloom/attested/bpf)
  IQ_ATTESTED_DIR    Attested config   (default: /opt/kernloom/attested/etc)
  IQ_POLICY_DIR      LocalPolicyPack or RuntimePolicyPack YAML
                     (default: /opt/kernloom/attested/etc/policies)
  IQ_PDP_DIR         PDPConfig files   (default: /opt/kernloom/attested/etc/pdp)
  IQ_VAR_DIR         Runtime state     (default: /var/lib/kernloom/iq)
USAGE
}

cleanup() {
  if [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ]; then
    rm -rf "$TMPDIR"
  fi
}
trap cleanup EXIT INT TERM

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Error: missing required command: $1" >&2
    exit 1
  }
}

resolve_latest_version() {
  location="$({
    curl -fsSI "https://github.com/$REPO/releases/latest" || exit 1
  } | tr -d '\r' | awk 'tolower($1)=="location:" {print $2}' | tail -n 1)"

  tag="${location##*/}"
  if [ -z "$tag" ] || [ "$tag" = "latest" ]; then
    echo "Error: could not resolve latest Kernloom release" >&2
    exit 1
  fi
  printf '%s\n' "$tag"
}

pick_prefix() {
  if [ -n "$PREFIX" ]; then
    return 0
  fi

  if [ "$(id -u)" -eq 0 ]; then
    PREFIX="$OPT_DIR/attested"
  else
    PREFIX="$HOME/.local/bin"
  fi
}

install_executable() {
  src="$1"
  dst="$2"

  if command -v install >/dev/null 2>&1; then
    install -m 0755 "$src" "$dst"
  else
    cp "$src" "$dst"
    chmod 0755 "$dst"
  fi
}

install_data_file() {
  src="$1"
  dst="$2"
  mode="$3"

  if command -v install >/dev/null 2>&1; then
    install -m "$mode" "$src" "$dst"
  else
    cp "$src" "$dst"
    chmod "$mode" "$dst"
  fi
}

verify_asset() {
  asset="$1"
  file="$2"
  expected="$(grep "  $asset$" "$TMPDIR/SHA256SUMS.txt" | awk '{print $1}' || true)"

  if [ -z "$expected" ]; then
    echo "Error: checksum for $asset not found in SHA256SUMS.txt" >&2
    exit 1
  fi

  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$file" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$file" | awk '{print $1}')"
  elif command -v openssl >/dev/null 2>&1; then
    actual="$(openssl dgst -sha256 "$file" | awk '{print $NF}')"
  else
    echo "Warning: no SHA-256 tool found; skipping checksum verification" >&2
    return 0
  fi

  if [ "$actual" != "$expected" ]; then
    echo "Error: checksum mismatch for $asset" >&2
    exit 1
  fi
}

download_release_file() {
  remote_name="$1"
  out="$2"
  url="https://github.com/$REPO/releases/download/$KERNLOOM_VERSION/$remote_name"

  curl -fL --retry 3 --connect-timeout 10 -o "$out" "$url"
}

extract_archive() {
  archive="$1"
  extract_dir="$2"
  mkdir -p "$extract_dir"
  tar -xzf "$archive" -C "$extract_dir"
}

install_klshield_bpf() {
  extract_dir="$1"
  exact="$extract_dir/xdp_kernloom_shield.bpf.o"
  found=""

  if [ -f "$exact" ]; then
    found="$exact"
  else
    found="$(find "$extract_dir" -type f -name 'xdp_kernloom_shield.bpf.o' | head -n 1 || true)"
    if [ -z "$found" ]; then
      found="$(find "$extract_dir" -type f -name '*.bpf.o' | head -n 1 || true)"
    fi
  fi

  if [ -z "$found" ]; then
    echo "Warning: no .bpf.o file found in klshield archive; skipping BPF object install" >&2
    return 0
  fi

  mkdir -p "$SHARE_DIR"
  target="$SHARE_DIR/xdp_kernloom_shield.bpf.o"

  echo "==> Installing BPF object to $target"
  install_data_file "$found" "$target" 0644
}

install_binary() {
  bin="$1"
  asset="${bin}_${KERNLOOM_VERSION}_linux_${ARCH}.tar.gz"
  archive="$TMPDIR/$asset"
  extract_dir="$TMPDIR/extract-$bin"

  echo "==> Downloading $asset"
  if ! download_release_file "$asset" "$archive"; then
    echo "Error: failed to download $asset" >&2
    echo "       Check whether release '$KERNLOOM_VERSION' contains Linux/$ARCH assets." >&2
    exit 1
  fi

  verify_asset "$asset" "$archive"
  extract_archive "$archive" "$extract_dir"

  found="$(find "$extract_dir" -type f -name "$bin" | head -n 1 || true)"
  if [ -z "$found" ]; then
    echo "Error: could not find binary '$bin' inside $asset" >&2
    exit 1
  fi

  echo "==> Installing $bin to $PREFIX/$bin"
  install_executable "$found" "$PREFIX/$bin"

  if [ "$bin" = "klshield" ]; then
    install_klshield_bpf "$extract_dir"
  fi
}

ensure_iq_layout() {
  echo "==> Ensuring IQ directories"

  # Attested (IMA-measurable): binaries + BPF + config under /opt/kernloom/attested/
  mkdir -p "$ATTESTED_DIR" "$IQ_ATTESTED_DIR" "$IQ_POLICY_DIR" "$IQ_PDP_DIR"

  # Runtime state: changes frequently, not attested
  mkdir -p "$IQ_VAR_DIR"

  if [ ! -f "$IQ_ATTESTED_DIR/whitelist.txt" ]; then
    : > "$IQ_ATTESTED_DIR/whitelist.txt"
  fi

  if [ ! -f "$IQ_VAR_DIR/feedback.json" ] || [ ! -s "$IQ_VAR_DIR/feedback.json" ]; then
    printf '[]\n' > "$IQ_VAR_DIR/feedback.json"
  fi

  chmod 755 "$ATTESTED_DIR" "$IQ_ATTESTED_DIR" "$IQ_POLICY_DIR" "$IQ_PDP_DIR" "$IQ_VAR_DIR" || true
  chmod 644 "$IQ_ATTESTED_DIR/whitelist.txt" "$IQ_VAR_DIR/feedback.json" || true

  echo "    Attested root:   $ATTESTED_DIR    (IMA-measured by Keylime)"
  echo "    Attested config: $IQ_ATTESTED_DIR"
  echo "    Policy files:    $IQ_POLICY_DIR   (place LocalPolicyPack or RuntimePolicyPack YAML here)"
  echo "    PDP configs:     $IQ_PDP_DIR      (place PDPConfig YAML here)"
  echo "    Runtime state:   $IQ_VAR_DIR      (not attested)"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    all|kliq|klshield)
      COMPONENT="$1"
      shift
      ;;
    --version)
      [ "$#" -ge 2 ] || { echo "Error: --version requires a value" >&2; exit 1; }
      KERNLOOM_VERSION="$2"
      shift 2
      ;;
    --prefix)
      [ "$#" -ge 2 ] || { echo "Error: --prefix requires a value" >&2; exit 1; }
      PREFIX="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Error: unknown argument: $1" >&2
      echo >&2
      usage >&2
      exit 1
      ;;
  esac
done

need curl
need tar
need uname
need awk
need grep
need mktemp
need id
need find

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH_RAW="$(uname -m)"

case "$OS" in
  linux) ;;
  *)
    echo "Error: Kernloom releases currently target Linux only (detected: $OS)" >&2
    exit 1
    ;;
esac

case "$ARCH_RAW" in
  x86_64|amd64)           ARCH="amd64"  ;;
  aarch64|arm64)           ARCH="arm64"  ;;
  armv7l|armv7|armhf)     ARCH="arm_v7" ;;  # Synology DS218+ (Marvell ARMv7 Cortex-A9)
  *)
    echo "Error: unsupported architecture: $ARCH_RAW" >&2
    exit 1
    ;;
esac

if [ "$KERNLOOM_VERSION" = "latest" ]; then
  KERNLOOM_VERSION="$(resolve_latest_version)"
fi

pick_prefix
mkdir -p "$PREFIX"
TMPDIR="$(mktemp -d)"

echo "==> Kernloom release: $KERNLOOM_VERSION"
echo "==> Platform: $OS/$ARCH"
echo "==> Prefix:   $PREFIX"
echo "==> Share dir: $SHARE_DIR"

# SHA256SUMS is expected for release verification.
echo "==> Downloading SHA256SUMS.txt"
if ! download_release_file "SHA256SUMS.txt" "$TMPDIR/SHA256SUMS.txt"; then
  echo "Error: failed to download SHA256SUMS.txt for release '$KERNLOOM_VERSION'" >&2
  exit 1
fi

case "$COMPONENT" in
  all)
    install_binary klshield
    install_binary kliq
    ensure_iq_layout
    ;;
  kliq)
    install_binary kliq
    ensure_iq_layout
    ;;
  klshield)
    install_binary klshield
    ;;
  *)
    echo "Error: invalid component: $COMPONENT" >&2
    exit 1
    ;;
esac

echo
echo "Installed files:"
[ -x "$PREFIX/klshield" ] && echo "  - $PREFIX/klshield"
[ -x "$PREFIX/kliq" ] && echo "  - $PREFIX/kliq"
[ -f "$SHARE_DIR/xdp_kernloom_shield.bpf.o" ] && echo "  - $SHARE_DIR/xdp_kernloom_shield.bpf.o"
[ -f "$IQ_ETC_DIR/whitelist.txt" ] && echo "  - $IQ_ETC_DIR/whitelist.txt"
[ -f "$IQ_VAR_DIR/feedback.json" ] && echo "  - $IQ_VAR_DIR/feedback.json"

echo
echo "Next steps:"
echo "  1. Attach Shield to your NIC:"
echo "     sudo $PREFIX/klshield attach-xdp --iface eth0 \\"
echo "          --obj $SHARE_DIR/xdp_kernloom_shield.bpf.o"
echo ""
echo "  2. Choose a PDPConfig profile (see $IQ_PDP_DIR/):"
echo "     Place a profile at $IQ_PDP_DIR/node.yaml"
echo "     or pass runtime flags directly to kliq."
echo ""
echo "  3. Optional: place a LocalPolicyPack or RuntimePolicyPack in:"
echo "     $IQ_POLICY_DIR"
echo ""
echo "  4. Start kliq observe-only (14-day bootstrap, dry-run):"
echo "     sudo $PREFIX/kliq run \\"
echo "          --pdp-config=$IQ_PDP_DIR/node.yaml \\"
echo "          --runtime-pdp-mode=shadow \\"
echo "          --dry-run=true --whitelist-learn=true"
echo "     Shadow mode logs RuntimePDP decisions but emits no PEP actions."
echo "     For real enforcement, create a RuntimePolicyPack and use:"
echo "          --policy-file=$IQ_POLICY_DIR/runtime-policy.yaml \\"
echo "          --runtime-pdp-mode=active --dry-run=false"
echo ""
echo "  5. Full help:  $PREFIX/kliq run --help"
echo "                 $PREFIX/klshield"
