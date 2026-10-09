#!/usr/bin/env bash
# Portable first-run for Raven `ash` (serverless terminal).
# Detects repo from this script — never hardcodes /Users/ahmd.
#
# Usage:
#   bash scripts/ash_first_run.sh              # build + interactive ash
#   bash scripts/ash_first_run.sh --no-run     # build only
#   bash scripts/ash_first_run.sh --init-only  # build + init + whoami, then exit
#
# FA / EN — Persian + English errors when rustc/cargo missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
NODE_DIR="$REPO_ROOT/node"
# Stable profile — NEVER mktemp (new identity every run breaks iPhone Peer pub).
# Same resolution as `ash` itself and raven-core: RAVEN_DATA_DIR, then ASH_DATA_DIR,
# then a legacy ~/.raven-ash while ~/.raven does not exist, else ~/.raven. Resolved
# before `mkdir -p` below, which would otherwise create ~/.raven, orphan the legacy
# identity (contacts pinned its key) and flip plain `ash` onto an empty profile.
resolve_data_dir() {
  if [[ -n "${RAVEN_DATA_DIR:-}" ]]; then
    printf '%s' "$RAVEN_DATA_DIR"
  elif [[ -n "${ASH_DATA_DIR:-}" ]]; then
    printf '%s' "$ASH_DATA_DIR"
  elif [[ -d "$HOME/.raven-ash" && ! -e "$HOME/.raven" ]]; then
    printf '%s' "$HOME/.raven-ash"
  else
    printf '%s' "$HOME/.raven"
  fi
}
DATA_DIR="$(resolve_data_dir)"

NO_RUN=0
INIT_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --no-run) NO_RUN=1 ;;
    --init-only) INIT_ONLY=1 ;;
    -h|--help)
      cat <<'EOF'
ash_first_run.sh — portable Raven ash bootstrap

  Detects hybrid_messenger repo relative to this script (any username/home).
  Builds ash + raven-node + raven-core, then launches ash with its default
  profile: ~/.raven, or a legacy ~/.raven-ash while that is the only one
  (stable identity — re-use the same Mac whoami on iPhone).

  --no-run      build only
  --init-only   build, init identity, print whoami, exit

  Override profile: RAVEN_DATA_DIR=/path (or ASH_DATA_DIR=/path) bash scripts/ash_first_run.sh

  Identity storage: the platform backend (macOS Keychain / Windows DPAPI /
  Linux Secret Service) is used unless RAVEN_IDENTITY_BACKEND is set. The debug
  locked-file backend keeps the seed as a PLAINTEXT 0600 file, so it is opt-in:
    ASH_FIRST_RUN_LAB_PLAINTEXT=1 bash scripts/ash_first_run.sh   (lab only)
  A profile already recorded as locked-file keeps it (ash refuses it otherwise).
EOF
      exit 0
      ;;
  esac
done

export PATH="${HOME}/.cargo/bin:${PATH}"
# Identity backend for this STABLE profile (reused for iPhone pairing). The helper
# used to force the debug-only locked-file backend, i.e. a PLAINTEXT 0600 seed file,
# contrary to docs/IDENTITY_SEED_STORAGE.md (Keychain/DPAPI/Secret Service) and
# docs/INSTALL_macOS.md (do not set this override for a normal install).
#   * the caller's RAVEN_IDENTITY_BACKEND always wins;
#   * ASH_FIRST_RUN_LAB_PLAINTEXT=1 opts in to locked-file (lab / throwaway only);
#   * a profile already recorded as locked-file (created by an older version of this
#     helper) keeps it: ash refuses such a profile without the override;
#   * otherwise it stays unset = the platform backend. Unsigned debug rebuilds can
#     make macOS ask for Keychain access: answer the prompt rather than switching
#     the long-lived identity to plaintext.
if [[ -z "${RAVEN_IDENTITY_BACKEND:-}" ]]; then
  if [[ "${ASH_FIRST_RUN_LAB_PLAINTEXT:-0}" == "1" ]]; then
    export RAVEN_IDENTITY_BACKEND=locked-file
  elif [[ "$(cat "$DATA_DIR/identity.backend" 2>/dev/null || true)" == "locked-file" ]]; then
    export RAVEN_IDENTITY_BACKEND=locked-file
    echo "NOTE: $DATA_DIR is already a locked-file profile (older ash_first_run.sh); keeping it." >&2
  fi
fi
# Env prefix for the follow-up commands this script prints (empty = platform backend).
BACKEND_ENV=""
if [[ "${RAVEN_IDENTITY_BACKEND:-}" == "locked-file" ]]; then
  BACKEND_ENV="RAVEN_IDENTITY_BACKEND=locked-file "
  echo "WARNING: identity backend = locked-file. The Ed25519 identity seed is stored as a PLAINTEXT" >&2
  echo "         0600 file ($DATA_DIR/identity.seed): any process running as you, and backups, can read it." >&2
  echo "         Debug builds only; NOT the Keychain/DPAPI/Secret Service store. Lab / throwaway use only." >&2
  echo "FA: هشدار: seed هویت به‌صورت فایل متنی ساده (۰۶۰۰) ذخیره می‌شود، نه در Keychain. فقط برای آزمایش." >&2
fi

die_tooling() {
  echo "ERROR: $1" >&2
  echo "FA: Rust لازم است — https://rustup.rs" >&2
  echo "EN: Install Rust from https://rustup.rs then re-run." >&2
  exit 1
}

command -v rustc >/dev/null || die_tooling "rustc not found"
command -v cargo >/dev/null || die_tooling "cargo not found"

echo "repo:  $REPO_ROOT"
echo "node:  $NODE_DIR"
echo "data:  $DATA_DIR  (stable — keep this for iPhone Peer pub)"
echo "rustc: $(rustc --version)"
echo "cargo: $(cargo --version)"
echo

cd "$NODE_DIR"
echo "Building ash + raven-node + raven-core…"
cargo build -p ash -p raven-node -p raven-core

ASH="$NODE_DIR/target/debug/ash"
if [[ ! -x "$ASH" ]]; then
  echo "ERROR: ash binary missing at $ASH" >&2
  exit 1
fi

mkdir -p "$DATA_DIR"

if [[ "$NO_RUN" -eq 1 ]]; then
  echo "Build OK — skip launch (--no-run)."
  echo "Next: ${BACKEND_ENV}$ASH --data-dir \"$DATA_DIR\""
  echo "Or:   ${BACKEND_ENV}$ASH   (same profile by default: $DATA_DIR)"
  exit 0
fi

if [[ "$INIT_ONLY" -eq 1 ]]; then
  "$ASH" --data-dir "$DATA_DIR" init
  echo "--- whoami (share these public bits only) ---"
  "$ASH" --data-dir "$DATA_DIR" whoami
  echo
  echo "FA: فقط address / fingerprint / pub_hex را بفرستید — هرگز seed را نه."
  echo "EN: Share address / fingerprint / pub_hex only — never a seed."
  exit 0
fi

echo "Launching interactive ash…"
echo "FA: منوی ۴ Status هویت می‌سازد؛ منوی ۳ مخاطب؛ منوی ۲ ارسال."
echo "EN: Menu 4 Status creates identity; 3 Contacts; 2 Send/Chat."
echo "FA: دیگر mktemp نزنید — هویت مک ثابت می‌ماند."
echo
exec "$ASH" --data-dir "$DATA_DIR"
