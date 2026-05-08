#!/usr/bin/env sh
# Kernloom uninstaller
#
# Mirrors the paths created by install.sh.
# Run as root:  sudo sh uninstall.sh
# Dry-run:      sudo sh uninstall.sh --dry-run
# Keep state:   sudo sh uninstall.sh --keep-state

set -eu

DRY_RUN=0
KEEP_STATE=0

# ── Same path defaults as install.sh ─────────────────────────────────────────
OPT_DIR="${OPT_DIR:-/opt/kernloom}"
ATTESTED_DIR="${ATTESTED_DIR:-$OPT_DIR/attested}"
SHARE_DIR="${SHARE_DIR:-$ATTESTED_DIR/bpf}"
IQ_ATTESTED_DIR="${IQ_ATTESTED_DIR:-$ATTESTED_DIR/etc}"
IQ_POLICY_DIR="${IQ_POLICY_DIR:-$IQ_ATTESTED_DIR/policies}"
IQ_PDP_DIR="${IQ_PDP_DIR:-$IQ_ATTESTED_DIR/pdp}"
IQ_VAR_DIR="${IQ_VAR_DIR:-/var/lib/kernloom/iq}"

# ── All pinned BPF objects created by klshield attach-xdp ────────────────────
BPF_FS="${BPF_FS:-/sys/fs/bpf}"
BPF_PINS="
  kernloom_shield_xdp_link
  kernloom_totals
  kernloom_src4_stats
  kernloom_src6_stats
  kernloom_flow4_stats
  kernloom_allow4_lpm
  kernloom_deny4_hash
  kernloom_allow6_lpm
  kernloom_deny6_hash
  kernloom_cfg
  kernloom_rl_cfg
  kernloom_rl_policy4
  kernloom_rl_policy6
  kernloom_events
"

# ─────────────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
Kernloom uninstaller

Usage: sudo sh uninstall.sh [OPTIONS]

Options:
  --dry-run      Show what would be removed without deleting anything
  --keep-state   Keep runtime state in $IQ_VAR_DIR (graph.db, feedback.json, state.json)
  -h, --help     Show this help

Environment:
  OPT_DIR        Override base directory     (default: /opt/kernloom)
  BPF_FS         Override BPF filesystem     (default: /sys/fs/bpf)
  IQ_VAR_DIR     Override runtime state dir  (default: /var/lib/kernloom/iq)
EOF
}

log()  { printf '==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

remove_file() {
  f="$1"
  if [ -e "$f" ] || [ -L "$f" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      info "[dry-run] rm $f"
    else
      rm -f "$f" && info "removed  $f" || warn "could not remove $f"
    fi
  fi
}

remove_dir() {
  d="$1"
  if [ -d "$d" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      info "[dry-run] rm -rf $d"
    else
      rm -rf "$d" && info "removed  $d" || warn "could not remove $d"
    fi
  fi
}

# ── Parse arguments ───────────────────────────────────────────────────────────
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run)    DRY_RUN=1;    shift ;;
    --keep-state) KEEP_STATE=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *) printf 'Error: unknown argument: %s\n' "$1" >&2; usage >&2; exit 1 ;;
  esac
done

# ── Root check ────────────────────────────────────────────────────────────────
if [ "$(id -u)" -ne 0 ]; then
  printf 'Error: this script must be run as root (sudo sh uninstall.sh)\n' >&2
  exit 1
fi

[ "$DRY_RUN" -eq 1 ] && printf '\n[DRY-RUN MODE — nothing will be deleted]\n\n'

# ── Step 1: Check for running processes ───────────────────────────────────────
log "Checking for running Kernloom processes"
for proc in kliq klshield; do
  if pgrep -x "$proc" >/dev/null 2>&1; then
    warn "$proc is still running — stop it before uninstalling:"
    warn "  sudo pkill $proc"
    if [ "$DRY_RUN" -eq 0 ]; then
      printf '\nAbort: stop all Kernloom processes first.\n' >&2
      exit 1
    fi
  else
    info "$proc not running"
  fi
done

# ── Step 2: Detach XDP program ────────────────────────────────────────────────
log "Detaching XDP program"
KLSHIELD="$ATTESTED_DIR/klshield"
if [ -x "$KLSHIELD" ]; then
  if [ "$DRY_RUN" -eq 1 ]; then
    info "[dry-run] $KLSHIELD detach-xdp"
  else
    "$KLSHIELD" detach-xdp || warn "detach-xdp returned non-zero (may already be detached)"
  fi
else
  # klshield binary already gone — remove the pinned link directly
  LINK_PIN="$BPF_FS/kernloom_shield_xdp_link"
  if [ -e "$LINK_PIN" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      info "[dry-run] rm $LINK_PIN  (direct, klshield not found)"
    else
      rm -f "$LINK_PIN" && info "removed pinned XDP link $LINK_PIN" \
        || warn "could not remove $LINK_PIN"
    fi
  else
    info "no pinned XDP link found — already detached or never attached"
  fi
fi

# ── Step 3: Remove pinned BPF maps ────────────────────────────────────────────
log "Removing pinned BPF maps from $BPF_FS"
if [ -d "$BPF_FS" ]; then
  for name in $BPF_PINS; do
    remove_file "$BPF_FS/$name"
  done
else
  info "$BPF_FS not mounted — skipping"
fi

# ── Step 4: Remove binaries ───────────────────────────────────────────────────
log "Removing binaries from $ATTESTED_DIR"
remove_file "$ATTESTED_DIR/klshield"
remove_file "$ATTESTED_DIR/kliq"

# ── Step 5: Remove BPF object ─────────────────────────────────────────────────
log "Removing BPF object from $SHARE_DIR"
remove_file "$SHARE_DIR/xdp_kernloom_shield.bpf.o"
remove_dir  "$SHARE_DIR"

# ── Step 6: Remove attested config ───────────────────────────────────────────
log "Removing attested config from $IQ_ATTESTED_DIR"
remove_file "$IQ_ATTESTED_DIR/whitelist.txt"
remove_dir  "$IQ_POLICY_DIR"
remove_dir  "$IQ_PDP_DIR"
remove_dir  "$IQ_ATTESTED_DIR"
remove_dir  "$ATTESTED_DIR"

# ── Step 7: Remove runtime state ─────────────────────────────────────────────
if [ "$KEEP_STATE" -eq 1 ]; then
  log "Keeping runtime state in $IQ_VAR_DIR (--keep-state)"
else
  log "Removing runtime state from $IQ_VAR_DIR"
  remove_file "$IQ_VAR_DIR/state.json"
  remove_file "$IQ_VAR_DIR/feedback.json"
  remove_file "$IQ_VAR_DIR/graph.db"
  remove_dir  "$IQ_VAR_DIR"
  # Remove /var/lib/kernloom only if now empty
  VAR_BASE="/var/lib/kernloom"
  if [ -d "$VAR_BASE" ] && [ "$DRY_RUN" -eq 0 ]; then
    rmdir "$VAR_BASE" 2>/dev/null && info "removed  $VAR_BASE" || true
  elif [ "$DRY_RUN" -eq 1 ] && [ -d "$VAR_BASE" ]; then
    info "[dry-run] rmdir $VAR_BASE (if empty)"
  fi
fi

# ── Step 8: Remove /opt/kernloom (if now empty) ───────────────────────────────
log "Removing $OPT_DIR"
if [ "$DRY_RUN" -eq 0 ]; then
  rmdir "$OPT_DIR" 2>/dev/null && info "removed  $OPT_DIR" \
    || info "$OPT_DIR not empty or already gone — left in place"
else
  info "[dry-run] rmdir $OPT_DIR (if empty)"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
printf '\n'
if [ "$DRY_RUN" -eq 1 ]; then
  printf 'Dry-run complete. Run without --dry-run to actually remove.\n'
else
  printf 'Kernloom uninstalled.\n'
  if [ "$KEEP_STATE" -eq 1 ]; then
    printf 'Runtime state kept at: %s\n' "$IQ_VAR_DIR"
  fi
fi