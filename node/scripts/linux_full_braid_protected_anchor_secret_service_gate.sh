#!/usr/bin/env bash
# Task 0B.3 — GNU/Linux Secret Service protected-anchor lab gate (Independent FAIL remediation).
# Lab-only. No production, commit, push, or stage. Does not start 0B.4.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/node"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FAIL: must run on GNU/Linux (got $(uname -s))" >&2
  exit 1
fi

export RAVEN_EXPECT_SQLCIPHER_4_17_0="${RAVEN_EXPECT_SQLCIPHER_4_17_0:-1}"
ART="${ROOT}/artifacts/full-braid-0b3-secret-service-gate"
mkdir -p "$ART"
: >"$ART/summary.txt"

SKIPPED=0
pass() { echo "PASS: $*" | tee -a "$ART/summary.txt"; }
# A step that asserts nothing must not read as PASS in the summary an independent
# reviewer relies on: record it as SKIP with the reason.
skip() {
  SKIPPED=$((SKIPPED + 1))
  echo "SKIP: $*" | tee -a "$ART/summary.txt"
}

echo "=== Clippy -D warnings ===" | tee -a "$ART/summary.txt"
cargo clippy -p raven-core --features full-braid-durable-lab -- -D warnings \
  2>&1 | tee "$ART/clippy.log"
pass "clippy -D warnings"

echo "=== Unit + negatives (unlocked Secret Service) ===" | tee -a "$ART/summary.txt"
dbus-run-session -- bash -c '
  set -euo pipefail
  cd "'"$ROOT"'/node"
  export RAVEN_EXPECT_SQLCIPHER_4_17_0=1
  eval "$(printf "\n" | gnome-keyring-daemon --unlock 2>/dev/null || true)"
  eval "$(gnome-keyring-daemon --start --components=secrets 2>/dev/null || true)"
  echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unset}" >&2
  cargo test -p raven-core --features full-braid-durable-lab \
    protected_anchor_linux:: \
    -- --nocapture
' 2>&1 | tee "$ART/unit-tests.log"
pass "unit tests (first-install negative, race no-collapse, anchors, no-file)"

echo "=== Unavailable (no secrets daemon) ===" | tee -a "$ART/summary.txt"
dbus-run-session -- bash -c '
  set -euo pipefail
  cd "'"$ROOT"'/node"
  export RAVEN_EXPECT_SQLCIPHER_4_17_0=1
  # No gnome-keyring: connect must fail closed without Prompt.Prompt hang.
  timeout 30 cargo test -p raven-core --features full-braid-durable-lab \
    unavailable_without_secret_service -- --nocapture
' 2>&1 | tee "$ART/neg-unavailable.log"
pass "unavailable / no-daemon (typed, no prompt hang)"

echo "=== Locked/prompt typed codes ===" | tee -a "$ART/summary.txt"
dbus-run-session -- bash -c '
  set -euo pipefail
  cd "'"$ROOT"'/node"
  export RAVEN_EXPECT_SQLCIPHER_4_17_0=1
  gnome-keyring-daemon --start --components=secrets >/dev/null 2>&1 || true
  timeout 30 cargo test -p raven-core --features full-braid-durable-lab \
    typed_locked_unavailable_codes -- --nocapture
' 2>&1 | tee "$ART/neg-locked.log"
pass "locked/prompt typed codes"

echo "=== Multi-collection / CreateCollection policy (static source assertion) ===" | tee -a "$ART/summary.txt"
# The backend must only ever use the existing default collection. A real assertion
# over the backend sources (comments excluded): no create_collection /
# CreateCollection / get_any_collection call may exist. Both files must be present
# and non-empty so a rename cannot turn this into a vacuous pass.
BACKEND_DIR="$ROOT/node/crates/raven-core/src/full_braid_durable_lab"
BACKEND_SRCS=("$BACKEND_DIR/protected_anchor_linux_ss.rs" "$BACKEND_DIR/protected_anchor_linux.rs")
for f in "${BACKEND_SRCS[@]}"; do
  [[ -s "$f" ]] || { echo "FAIL: backend source missing or empty: $f" >&2; exit 1; }
done
COLLECTION_HITS="$(grep -nE 'create_collection|CreateCollection|get_any_collection' "${BACKEND_SRCS[@]}" \
  | grep -vE '^[^:]+:[0-9]+:[[:space:]]*//' || true)"
printf '%s\n' "$COLLECTION_HITS" >"$ART/neg-multicol.log"
if [[ -n "$COLLECTION_HITS" ]]; then
  echo "FAIL: backend references a collection-creating / non-default collection API:" >&2
  echo "$COLLECTION_HITS" >&2
  exit 1
fi
grep -q 'default_collection' "${BACKEND_SRCS[0]}" \
  || { echo "FAIL: backend no longer resolves the default collection" >&2; exit 1; }
echo "no create_collection / CreateCollection / get_any_collection in backend sources" | tee -a "$ART/neg-multicol.log"
pass "multi-collection policy (static: backend never creates or enumerates other collections)"

echo "=== Malformed metadata plant ===" | tee -a "$ART/summary.txt"
# Plants an item whose attributes the backend must reject on load. The plant itself
# is asserted (no `|| true`): it must be stored and visible to search. NO verifier
# runs against the planted state (no test in the crate exercises the load path's
# CORRUPT_ATTRIBUTES rejection yet), so this step is recorded as SKIP, never PASS.
# The search output is captured, not piped into `grep -q` (that would SIGPIPE
# secret-tool and trip pipefail), and never echoed: it contains the planted secret.
# No apostrophes inside the quoted script below (it is one single-quoted string).
MALFORMED_PLANT_STATUS="$(dbus-run-session -- bash -c '
  set -euo pipefail
  eval "$(printf "\n" | gnome-keyring-daemon --unlock 2>/dev/null || true)"
  eval "$(gnome-keyring-daemon --start --components=secrets 2>/dev/null || true)"
  if ! command -v secret-tool >/dev/null; then
    echo "NO_SECRET_TOOL"
    exit 0
  fi
  SCOPE="$(python3 -c "import hashlib,time,os; print(hashlib.sha256(f\"m-{time.time()}-{os.getpid()}\".encode()).hexdigest())")"
  printf "\x11%.0s" {1..32} | secret-tool store --label="bogus raven seed" \
    application app.raven.node \
    protocol atsam-full-braid-v1 \
    kind seed \
    scope "$SCOPE" \
    evil extra-key
  FOUND="$(secret-tool search scope "$SCOPE" 2>&1)"
  case "$FOUND" in
    *"evil = extra-key"*) ;;
    *) echo "planted item not returned by search" >&2; exit 1 ;;
  esac
  echo "PLANTED"
' 2>"$ART/neg-malformed.err" | tail -n 1)" || { cat "$ART/neg-malformed.err" >&2; echo "FAIL: malformed-metadata plant did not store / was not searchable" >&2; exit 1; }
echo "plant status: $MALFORMED_PLANT_STATUS" | tee "$ART/neg-malformed.log"
case "$MALFORMED_PLANT_STATUS" in
  PLANTED) skip "malformed metadata plant: item planted but NO verifier asserts CORRUPT_ATTRIBUTES on load (needs a protected_anchor_linux test)" ;;
  NO_SECRET_TOOL) skip "malformed metadata plant: secret-tool not installed, nothing planted or asserted" ;;
  *) echo "FAIL: unexpected plant status: $MALFORMED_PLANT_STATUS" >&2; exit 1 ;;
esac

echo "=== Two-thread concurrent seed (no collapse) ===" | tee -a "$ART/summary.txt"
dbus-run-session -- bash -c '
  set -euo pipefail
  cd "'"$ROOT"'/node"
  export RAVEN_EXPECT_SQLCIPHER_4_17_0=1
  eval "$(printf "\n" | gnome-keyring-daemon --unlock 2>/dev/null || true)"
  eval "$(gnome-keyring-daemon --start --components=secrets 2>/dev/null || true)"
  cargo test -p raven-core --features full-braid-durable-lab \
    seed_duplicate_race_preserves_items_no_collapse -- --nocapture
' 2>&1 | tee "$ART/neg-concurrent.log"
pass "concurrent seed (preserve duplicates, no collapse)"

if [[ "$SKIPPED" -gt 0 ]]; then
  echo "GATE CHECKS COMPLETE WITH $SKIPPED SKIPPED STEP(S) — not every claim is asserted; see SKIP lines in summary.txt. Stop for Independent re-review (no commit/push/stage; no 0B.4)" \
    | tee -a "$ART/summary.txt"
else
  echo "ALL GATE CHECKS COMPLETE — stop for Independent re-review (no commit/push/stage; no 0B.4)" \
    | tee -a "$ART/summary.txt"
fi
