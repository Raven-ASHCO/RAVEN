#!/usr/bin/env bash
# Task 0A.2 negatives: profile overrides via LIBSQLITE3_FLAGS / CFLAGS / CC
# (incl. response-file and -include) must fail-closed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT/node"
export PATH="${PATH:-}"

die() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*" >&2; }

command -v cargo >/dev/null || die "cargo not found"

DIAG_RE='LIBSQLITE3_FLAGS is forbidden|forbidden SQLCipher profile override|RAVEN_SQLCIPHER_PROFILE|forbidden OpenSSL provider override|DEP_OPENSSL_VENDORED'

expect_fail() {
  local label="$1"
  shift
  set +e
  out="$("$@" 2>&1)"
  rc=$?
  set -e
  [[ "$rc" -ne 0 ]] || die "$label: expected failure, got exit 0"
  echo "$out" | grep -Eq "$DIAG_RE" \
    || die "$label: missing fail-closed diagnostic; got: $out"
  pass "$label"
}

run_lab_build() {
  env "$@" cargo test -p raven-core --features full-braid-durable-lab \
    --test full_braid_sqlcipher_profile --no-run
}

# Same guard logic as libsqlite3-sys-raven/build.rs (no openssl-sys race).
run_env_guard() {
  env "$@" cargo run -q -p raven-sqlcipher-profile-guard
}

# --- Shared env-guard binary (authoritative diagnostic for all injection shapes) ---
expect_fail "guard: LIBSQLITE3_FLAGS=-DPBKDF2_ITER=1" \
  run_env_guard LIBSQLITE3_FLAGS=-DPBKDF2_ITER=1

expect_fail "guard: CFLAGS=-DPBKDF2_ITER=1" \
  run_env_guard CFLAGS='-DPBKDF2_ITER=1'

expect_fail "guard: CC=clang -DPBKDF2_ITER=1" \
  run_env_guard CC='clang -DPBKDF2_ITER=1'

RESP_FILE="$(mktemp "${TMPDIR:-/tmp}/raven-sqlcipher-resp.XXXXXX")"
INC_FILE="$(mktemp "${TMPDIR:-/tmp}/raven-sqlcipher-inc.XXXXXX")"
trap 'rm -f "$RESP_FILE" "$INC_FILE"' EXIT

printf '%s\n' '-DPBKDF2_ITER=1' >"$RESP_FILE"
expect_fail "guard: CFLAGS=@response-file" \
  run_env_guard CFLAGS="@${RESP_FILE}"

printf '%s\n' '#define PBKDF2_ITER 1' >"$INC_FILE"
expect_fail "guard: CFLAGS=-include profile_override.h" \
  run_env_guard CFLAGS="-include ${INC_FILE}"

# --- Full cargo graph (openssl-sys may race on CFLAGS=@; CC/-D cases reach build.rs) ---
cargo clean -p libsqlite3-sys >/dev/null 2>&1 || true
expect_fail "cargo: LIBSQLITE3_FLAGS=-DPBKDF2_ITER=1" \
  run_lab_build RAVEN_EXPECT_SQLCIPHER_4_17_0=1 LIBSQLITE3_FLAGS=-DPBKDF2_ITER=1

cargo clean -p libsqlite3-sys >/dev/null 2>&1 || true
expect_fail "cargo: LIBSQLITE3_FLAGS=-DSQLITE_TEMP_STORE=3" \
  run_lab_build RAVEN_EXPECT_SQLCIPHER_4_17_0=1 LIBSQLITE3_FLAGS=-DSQLITE_TEMP_STORE=3

cargo clean -p libsqlite3-sys >/dev/null 2>&1 || true
expect_fail "cargo: CFLAGS contains PBKDF2_ITER" \
  run_lab_build RAVEN_EXPECT_SQLCIPHER_4_17_0=1 CFLAGS='-DPBKDF2_ITER=1'

# Windows openssl-src/nmake consumes CC before libsqlite3-sys build.rs.
# clang then dies on MSVC flags (/Zi, /MT) with no profile-guard diagnostic.
# The env-guard case above already covers CC='clang -DPBKDF2_ITER=1'.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    pass "skip cargo: CC=clang -DPBKDF2_ITER=1 on Windows (openssl-src/nmake race)"
    ;;
  *)
    cargo clean -p libsqlite3-sys >/dev/null 2>&1 || true
    expect_fail "cargo: CC=clang -DPBKDF2_ITER=1" \
      run_lab_build RAVEN_EXPECT_SQLCIPHER_4_17_0=1 CC='clang -DPBKDF2_ITER=1'
    ;;
esac

# -include usually reaches libsqlite3-sys after openssl tolerates the flag.
cargo clean -p libsqlite3-sys >/dev/null 2>&1 || true
expect_fail "cargo: CFLAGS=-include profile_override.h" \
  run_lab_build RAVEN_EXPECT_SQLCIPHER_4_17_0=1 CFLAGS="-include ${INC_FILE}"

# Vendored OpenSSL must not be bypassable via OPENSSL_NO_VENDOR / path overrides.
expect_fail "guard: OPENSSL_NO_VENDOR=1" \
  run_env_guard OPENSSL_NO_VENDOR=1

expect_fail "guard: OPENSSL_DIR=/tmp/fake-openssl" \
  run_env_guard OPENSSL_DIR=/tmp/fake-openssl

cargo clean -p openssl-sys -p libsqlite3-sys >/dev/null 2>&1 || true
expect_fail "cargo: OPENSSL_NO_VENDOR=1" \
  run_lab_build RAVEN_EXPECT_SQLCIPHER_4_17_0=1 OPENSSL_NO_VENDOR=1

echo "PASS: SQLCipher profile override negatives" >&2
