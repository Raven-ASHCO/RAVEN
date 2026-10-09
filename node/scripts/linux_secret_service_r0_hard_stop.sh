#!/usr/bin/env bash
# Task 0B.3 R0 — native GNU/Linux hard-stop proofs for the pinned secret-service fork.
# R1 (owner decision 2026-10-08, docs/design/2026-10-linux-keystore.md) put the
# fork into raven-core's default GNU/Linux graph. The stop-line is now "Secret
# Service only through the approved wrapper" (secret_service_r1_boundary_check.sh)
# instead of "no live callsite". Lab-only proofs; no 0B.4, commit, push, or stage.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/node"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "FAIL: R0 hard-stop proofs require native GNU/Linux (got $(uname -s))" >&2
  exit 1
fi

ART="${ROOT}/artifacts/full-braid-0b3-r0-secret-service-fork"
mkdir -p "$ART"
FORK_TARGET="$ART/cargo-target-fork"
mkdir -p "$FORK_TARGET"
: >"$ART/summary.txt"
pass() { echo "PASS: $*" | tee -a "$ART/summary.txt"; }
fail() { echo "FAIL: $*" | tee -a "$ART/summary.txt"; exit 1; }

command -v dbus-run-session >/dev/null || fail "dbus-run-session missing"
command -v gnome-keyring-daemon >/dev/null || fail "gnome-keyring-daemon missing"
command -v rg >/dev/null || fail "ripgrep missing"

echo "=== Read-only provenance + negative mutations ===" | tee -a "$ART/summary.txt"
"$ROOT/node/scripts/verify_secret_service_2_0_2_raven_noprompt.sh" \
  2>&1 | tee "$ART/provenance.log"
"$ROOT/node/scripts/secret_service_r0_provenance_selftest.sh" \
  2>&1 | tee "$ART/provenance-selftest.log"
pass "crate pin, exact delta, immutable digest, provenance negatives"

echo "=== Default dependency graph isolation ===" | tee -a "$ART/summary.txt"
DEFAULT_TREE="$ART/default-linux-tree.txt"
cargo tree -p raven-core --target x86_64-unknown-linux-gnu -e normal \
  >"$DEFAULT_TREE"
grep -q 'secret-service v2.0.2 (.*secret-service-2.0.2-raven-noprompt)' "$DEFAULT_TREE" \
  || fail "R1: default Linux graph must use the frozen Raven no-prompt fork"
if grep 'secret-service v' "$DEFAULT_TREE" | grep -vq 'secret-service-2.0.2-raven-noprompt'; then
  fail "R1: crates.io secret-service client is back in the default Linux graph"
fi
rg -n 'create_item_no_prompt|delete_no_prompt|with_secret_zeroizing' \
  "$ROOT/node/crates" >"$ART/live-fork-callsites.txt" || true
bash "$ROOT/node/scripts/secret_service_r1_boundary_check.sh" \
  2>&1 | tee "$ART/r1-boundary.log"
bash "$ROOT/node/scripts/secret_service_r1_boundary_check.sh" --self-test \
  2>&1 | tee -a "$ART/r1-boundary.log"
cargo check -p raven-core --lib --target x86_64-unknown-linux-gnu \
  2>&1 | tee "$ART/default-linux-check.log"
pass "default Linux graph uses the fork; no-prompt APIs only in the approved wrapper"

echo "=== Raven API static no-prompt boundary ===" | tee -a "$ART/summary.txt"
python3 - \
  "$ROOT/node/third_party/secret-service-2.0.2-raven-noprompt/src/collection.rs" \
  "$ROOT/node/third_party/secret-service-2.0.2-raven-noprompt/src/item.rs" <<'PY'
import pathlib
import sys


def function_body(path: pathlib.Path, name: str) -> str:
    source = path.read_text(encoding="utf-8")
    marker = f"pub fn {name}"
    start = source.find(marker)
    if start < 0:
        raise SystemExit(f"missing Raven API: {name}")
    opening = source.find("{", start)
    if opening < 0:
        raise SystemExit(f"missing body: {name}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening : index + 1]
    raise SystemExit(f"unterminated body: {name}")


collection = pathlib.Path(sys.argv[1])
item = pathlib.Path(sys.argv[2])
checks = (
    (collection, "create_item_no_prompt"),
    (item, "delete_no_prompt"),
    (item, "with_secret_zeroizing"),
)
for path, name in checks:
    body = function_body(path, name)
    for forbidden in ("exec_prompt", "lock_or_unlock", ".unlock(", "EncryptionType::Plain"):
        if forbidden in body:
            raise SystemExit(f"{name} reaches forbidden legacy path: {forbidden}")
    if name != "with_secret_zeroizing" and "session.is_encrypted()" not in body:
        raise SystemExit(f"{name} lost its DH-session gate")
    if name == "with_secret_zeroizing" and "read_secret_zeroizing(true)" not in body:
        raise SystemExit("with_secret_zeroizing lost its encrypted-session requirement")
# R0 semantic stop-line re-freeze 2026-08: create_item_no_prompt is add-only.
# The caller-controlled replace flag must stay removed and the D-Bus flag
# must stay hard-wired to false (no destructive item overwrite).
create_body = function_body(collection, "create_item_no_prompt")
if "replace" in create_body:
    raise SystemExit("create_item_no_prompt exposes a caller-controlled replace flag")
if "create_item(properties, secret_struct.inner, false)" not in create_body:
    raise SystemExit("create_item_no_prompt does not hard-wire the D-Bus replace flag to false")
print("R0_STATIC_NO_PROMPT_BOUNDARY_OK")
PY
pass "Raven no-prompt APIs cannot dispatch to legacy prompt/unlock/Plain paths"

echo "=== Clippy -D warnings (fork crate) ===" | tee -a "$ART/summary.txt"
CARGO_TARGET_DIR="$FORK_TARGET" cargo clippy \
  --manifest-path third_party/secret-service-2.0.2-raven-noprompt/Cargo.toml \
  --all-targets --features raven-r0-test-instrumentation -- -D warnings \
  2>&1 | tee "$ART/clippy-fork.log"
CARGO_TARGET_DIR="$FORK_TARGET" cargo test \
  --manifest-path third_party/secret-service-2.0.2-raven-noprompt/Cargo.toml \
  --features raven-r0-test-instrumentation --lib raven_no_prompt_decision \
  2>&1 | tee "$ART/no-prompt-decision.log"
CARGO_TARGET_DIR="$FORK_TARGET" cargo test \
  --manifest-path third_party/secret-service-2.0.2-raven-noprompt/Cargo.toml \
  --features raven-r0-test-instrumentation --lib \
  session::test::raven_dh_math_compatibility_kat -- --exact \
  2>&1 | tee "$ART/dh-math-compatibility.log"
pass "fork clippy -D warnings"

echo "=== Release hold (primary diagnostic only) ===" | tee -a "$ART/summary.txt"
HOLD_LOG="$ART/release-hold.log"
set +e
RAVEN_EXPECT_SQLCIPHER_4_17_0=1 cargo build --release -p raven-core \
  --features full-braid-durable-lab >"$HOLD_LOG" 2>&1
HOLD_RC=$?
set -e
[[ "$HOLD_RC" -ne 0 ]] || fail "release durable-lab build unexpectedly succeeded"
python3 - "$HOLD_LOG" <<'PY'
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
expected = "FULL_BRAID_SQLCIPHER_NOT_APPROVED"
if not re.search(r"^error: failed to run custom build command for `raven-core\b", text, re.M):
    raise SystemExit("release hold is not a raven-core custom-build failure")
pattern = re.compile(
    r"panicked at [^\n]*raven-core/build\.rs:\d+:\d+:\s*\n"
    r"[ \t]*" + re.escape(expected) + r"[ \t]*(?:\n|$)"
)
if not pattern.search(text):
    raise SystemExit("release hold is not the raven-core/build.rs panic payload")
# libsqlite3-sys-raven/build.rs holds release bundled-sqlcipher builds with the
# same payload; in a warm target dir it can run alongside raven-core's hold.
# Accept that secondary failure only with the exact hold payload.
fork_payloads = [
    m.group(1).strip()
    for m in re.finditer(
        r"panicked at [^\n]*libsqlite3-sys-raven/build\.rs:\d+:\d+:\s*\n[ \t]*([^\n]+)", text
    )
]
for payload in fork_payloads:
    if payload != expected:
        raise SystemExit(f"unrelated libsqlite3-sys-raven/build.rs panic: {payload}")
fork_failures = 0
for line in text.splitlines():
    if not line.startswith("error:"):
        continue
    if "failed to run custom build command for `raven-core" in line:
        continue
    if "failed to run custom build command for `libsqlite3-sys " in line:
        fork_failures += 1
        if fork_failures <= len(fork_payloads):
            continue
    raise SystemExit(f"unrelated cargo error polluted release hold: {line}")
print(f"R0_RELEASE_HOLD_OK={expected}")
PY
pass "exact durable-lab release hold"

echo "=== Hard-stop proofs (unlocked Secret Service) ===" | tee -a "$ART/summary.txt"
dbus-run-session -- bash -c '
  set -euo pipefail
  cd "'"$ROOT"'/node"
  eval "$(printf "\n" | gnome-keyring-daemon --unlock 2>/dev/null || true)"
  eval "$(gnome-keyring-daemon --start --components=secrets 2>/dev/null || true)"
  echo "DBUS_SESSION_BUS_ADDRESS=${DBUS_SESSION_BUS_ADDRESS:-unset}" >&2
  CARGO_TARGET_DIR="'"$FORK_TARGET"'" cargo test \
    --manifest-path third_party/secret-service-2.0.2-raven-noprompt/Cargo.toml \
    --features raven-r0-test-instrumentation --test raven_r0_hard_stop -- \
    --nocapture --test-threads=1
' 2>&1 | tee "$ART/hard-stop.log"

CONTENT_TYPE_LINES="$(
  sed -n 's/.*R0_PROVIDER_CONTENT_TYPE\[[^]]*\]=//p' "$ART/hard-stop.log"
)"
CONTENT_TYPE_COUNT="$(printf '%s\n' "$CONTENT_TYPE_LINES" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$CONTENT_TYPE_COUNT" == 2 ]] \
  || fail "expected seed and RVFA1 provider content-type evidence (got $CONTENT_TYPE_COUNT)"
CONTENT_TYPES="$(printf '%s\n' "$CONTENT_TYPE_LINES" | LC_ALL=C sort -u)"
case "$CONTENT_TYPES" in
  application/octet-stream)
    pass "provider preserved application/octet-stream"
    ;;
  text/plain)
    printf '%s\n' \
      "R1_CONTENT_TYPE_PLATFORM_HOLD: GNOME Keyring normalized requested application/octet-stream to text/plain" \
      | tee -a "$ART/summary.txt"
    ;;
  *)
    fail "unexpected or inconsistent Secret Service content types: ${CONTENT_TYPES:-missing}"
    ;;
esac
pass "DH seed/RVFA1 exact-byte round-trip, Plain refusal, collection path, prompt tripwire"

echo "R0 HARD-STOP + R1 BOUNDARY COMPLETE — no plain-session fallback, no Unlock, no 0B.4 / commit" \
  | tee -a "$ART/summary.txt"
