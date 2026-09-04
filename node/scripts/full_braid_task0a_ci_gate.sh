#!/usr/bin/env bash
# Task 0A.5 — aggregate CI stop-line for Full Braid SQLCipher packaging (0A.0–0A.4).
#
# Usage:
#   ./node/scripts/full_braid_task0a_ci_gate.sh provenance
#   ./node/scripts/full_braid_task0a_ci_gate.sh linux
#   ./node/scripts/full_braid_task0a_ci_gate.sh macos
#   ./node/scripts/full_braid_task0a_ci_gate.sh windows
#
# Does not enable production, start Task 0B, or commit/push/stage.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NODE="$ROOT/node"
SCRIPTS="$NODE/scripts"
MODE="${1:-}"
HOLD_TEXT="FULL_BRAID_SQLCIPHER_NOT_APPROVED"

die() { echo "FULL_BRAID_0A5_FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*" >&2; }

# Primary-diagnostic hold gate: nonzero exit is necessary but not sufficient.
# The hold string must be the panic payload of raven-core/build.rs — not a
# later orphan line after some other build-script panic.
assert_primary_hold_log() {
  local expected="$1"
  local log="$2"
  python3 - "$expected" "$log" <<'PY'
import re, sys

expected, path = sys.argv[1], sys.argv[2]
text = open(path, "r", encoding="utf-8", errors="replace").read()

# Cargo custom-build failures surface as this error before the script stderr.
if not re.search(
    r"^error: failed to run custom build command for `raven-core\b",
    text,
    re.M,
):
    sys.stderr.write(
        "FULL_BRAID_0A5_HOLD_PRIMARY_MISSING: "
        "missing raven-core custom build failure\n"
    )
    sys.exit(1)

# Bind hold to the build.rs panic message itself.
# Real cargo shape (indented under Caused by / --- stderr):
#   thread 'main' (...) panicked at crates/raven-core/build.rs:17:9:
#   FULL_BRAID_SQLCIPHER_NOT_APPROVED
panic_hold = re.compile(
    r"panicked at [^\n]*raven-core/build\.rs:\d+:\d+:\s*\n"
    r"[ \t]*" + re.escape(expected) + r"[ \t]*(?:\n|$)"
)
if not panic_hold.search(text):
    sys.stderr.write(
        "FULL_BRAID_0A5_HOLD_PRIMARY_MISSING: "
        f"hold {expected!r} is not the raven-core/build.rs panic payload\n"
    )
    sys.exit(1)

# Reject any other build.rs panic payload in the same log.
other_panics = []
for match in re.finditer(
    r"panicked at [^\n]*raven-core/build\.rs:\d+:\d+:\s*\n[ \t]*([^\n]+)",
    text,
):
    payload = match.group(1).strip()
    if payload != expected:
        other_panics.append(payload)
if other_panics:
    sys.stderr.write(
        "FULL_BRAID_0A5_HOLD_POLLUTED: unrelated raven-core/build.rs panic:\n"
    )
    for payload in other_panics[:10]:
        sys.stderr.write(f"  {payload}\n")
    sys.exit(1)

# Reject unrelated top-level cargo errors that are not the raven-core
# build-script failure (false-pass when hold text is merely echoed).
unrelated = []
for line in text.splitlines():
    if not line.startswith("error:"):
        continue
    if "failed to run custom build command for `raven-core" in line:
        continue
    if expected in line:
        continue
    unrelated.append(line)
if unrelated:
    sys.stderr.write(
        "FULL_BRAID_0A5_HOLD_POLLUTED: unrelated cargo error(s) present:\n"
    )
    for line in unrelated[:20]:
        sys.stderr.write(f"  {line}\n")
    sys.exit(1)

print(f"primary-hold-ok {expected}", file=sys.stderr)
PY
}

expect_release_hold_failure() {
  local log
  log="$(mktemp "${TMPDIR:-/tmp}/raven-0a5-hold-XXXXXX")"
  set +e
  (
    cd "$NODE"
    env RAVEN_EXPECT_SQLCIPHER_4_17_0=1 \
      cargo build --release -p raven-core --features full-braid-durable-lab
  ) >"$log" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "FULL_BRAID_0A5_HOLD_UNEXPECTED_SUCCESS" >&2
    cat "$log" >&2
    rm -f "$log"
    exit 1
  fi
  assert_primary_hold_log "$HOLD_TEXT" "$log"
  rm -f "$log"
  pass "exact primary hold diagnostic ($HOLD_TEXT)"
}

# Negatives: hold text alone must not pass; unrelated build.rs panic +
# trailing hold line must not pass.
assert_hold_gate_rejects_pollution() {
  local log rc

  log="$(mktemp "${TMPDIR:-/tmp}/raven-0a5-hold-neg-XXXXXX")"
  cat >"$log" <<EOF
error: linking with \`cc\` failed: exit status: 1
  |
  = note: undefined reference to \`something_unrelated\`
$HOLD_TEXT
EOF
  set +e
  assert_primary_hold_log "$HOLD_TEXT" "$log" >/dev/null 2>&1
  rc=$?
  set -e
  rm -f "$log"
  [[ "$rc" -ne 0 ]] || die "hold gate false-passed unrelated failure + hold text"
  pass "hold gate rejects unrelated failure + hold text"

  log="$(mktemp "${TMPDIR:-/tmp}/raven-0a5-hold-neg2-XXXXXX")"
  cat >"$log" <<EOF
error: failed to run custom build command for \`raven-core v0.1.0 (/tmp/raven-core)\`

Caused by:
  process didn't exit successfully: \`build-script-build\` (exit status: 101)
  --- stderr

  thread 'main' panicked at crates/raven-core/build.rs:17:9:
  UNRELATED_BUILD_RS_FAILURE
  $HOLD_TEXT
EOF
  set +e
  assert_primary_hold_log "$HOLD_TEXT" "$log" >/dev/null 2>&1
  rc=$?
  set -e
  rm -f "$log"
  [[ "$rc" -ne 0 ]] || die "hold gate false-passed unrelated build.rs panic + hold text"
  pass "hold gate rejects unrelated build.rs panic + hold text"
}

scoped_paths=(
  node/crates/raven-core/build.rs
  node/crates/raven-core/src/full_braid_durable_lab
  node/crates/raven-core/tests/full_braid_sqlcipher_profile.rs
  node/scripts/full_braid_task0a_ci_gate.sh
  node/scripts/full_braid_sqlcipher_open_profile_gate.sh
  node/scripts/full_braid_sqlcipher_cross_provider_gate.sh
  node/scripts/full_braid_sqlcipher_symbol_owner_report.sh
  node/scripts/full_braid_sqlcipher_profile_override_negatives.sh
  node/scripts/ios_full_braid_sqlcipher_gate.sh
  node/scripts/ios_full_braid_sqlcipher_physical_device_checklist.md
  node/scripts/regenerate_sqlcipher_4_17.sh
  node/scripts/verify_sqlcipher_4_17.sh
  node/scripts/sqlcipher_4_17_provenance_selftest.sh
  node/scripts/sqlcipher_4_17_templates
  node/third_party/sqlcipher-4.17.0
  node/third_party/libsqlite3-sys-raven
  node/third_party/raven-sqlcipher-profile-guard
  ios-native/RAVEN/RAVEN/Core/Security/ATSAM/Durable
  ios-native/RAVEN/RAVENTests/ATSAMFullBraidSQLCipherProfileV1Tests.swift
  .github/workflows/raven-serverless.yml
  .github/workflows/raven-serverless-lab.yml
)

# Emulate `git diff --check` for a working-tree file (tracked or untracked).
check_file_diff_style() {
  local file="$1"
  [[ -f "$file" ]] || return 0
  # Vendor amalgamation / upstream SQLite trees are byte-pinned; do not
  # enforce Raven whitespace policy on those blobs. Still enumerate them
  # as untracked above.
  case "$file" in
    *.o|*.a|*.dylib|*.so|*.dll|*.zip|*.xcframework)
      return 0
      ;;
    node/third_party/sqlcipher-4.17.0/*|\
    node/third_party/libsqlite3-sys-raven/sqlcipher/*|\
    node/third_party/libsqlite3-sys-raven/sqlite3/*|\
    node/third_party/libsqlite3-sys-raven/bindgen-bindings/*)
      return 0
      ;;
  esac
  python3 - "$ROOT/$file" "$file" <<'PY'
import pathlib, re, sys
path = pathlib.Path(sys.argv[1])
label = sys.argv[2]
try:
    data = path.read_bytes()
except OSError as exc:
    print(f"FULL_BRAID_0A5_UNTRACKED_READ:{label}:{exc}", file=sys.stderr)
    sys.exit(1)
if b"\0" in data[:4096]:
    sys.exit(0)
text = data.decode("utf-8", errors="replace")
problems = []
for idx, line in enumerate(text.splitlines(), 1):
    if line.endswith(" ") or line.endswith("\t"):
        problems.append(f"{label}:{idx}: trailing whitespace.")
    if re.match(r"^(<<<<<<<|>>>>>>>|=======)($|\s)", line):
        problems.append(f"{label}:{idx}: leftover conflict marker.")
if problems:
    sys.stderr.write("\n".join(problems) + "\n")
    sys.exit(1)
PY
}

scoped_diff_check() {
  local base="${RAVEN_0A5_DIFF_BASE:-}"
  cd "$ROOT"

  # Tracked committed range.
  if [[ -n "$base" && "$base" != "0000000000000000000000000000000000000000" ]]; then
    git diff --check "${base}...HEAD" -- "${scoped_paths[@]}"
  elif git rev-parse --verify HEAD~1 >/dev/null 2>&1; then
    git diff --check HEAD~1...HEAD -- "${scoped_paths[@]}"
  fi
  # Tracked working-tree / index mutations.
  git diff --check -- "${scoped_paths[@]}"
  git diff --cached --check -- "${scoped_paths[@]}"

  # Untracked files under the scoped paths are part of the Task 0A stop-line.
  local untracked_list
  untracked_list="$(mktemp "${TMPDIR:-/tmp}/raven-0a5-untracked-XXXXXX")"
  git ls-files --others --exclude-standard -- "${scoped_paths[@]}" >"$untracked_list"
  local count=0
  local path
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    count=$((count + 1))
    if ! check_file_diff_style "$path"; then
      rm -f "$untracked_list"
      die "scoped untracked diff-check failed: $path"
    fi
    echo "checked-untracked $path" >&2
  done <"$untracked_list"
  rm -f "$untracked_list"
  echo "untracked-scoped-count=$count" >&2
  # Gate must observe the live untracked set (including Task 0A.5 scripts
  # before they are committed). A silent zero-count on a dirty Task 0A tree
  # that still has known new scripts is a bug in path scoping.
  if [[ "$count" -eq 0 ]]; then
    local probe
    probe="$(git ls-files --others --exclude-standard -- \
      node/scripts/full_braid_task0a_ci_gate.sh \
      node/scripts/full_braid_sqlcipher_cross_provider_gate.sh \
      node/scripts/ios_full_braid_sqlcipher_physical_device_checklist.md || true)"
    if [[ -n "$probe" ]]; then
      die "scoped untracked enumeration missed Task 0A.5 scripts: $probe"
    fi
  fi
  pass "scoped tracked+untracked diff check"
}

assert_physical_checklist() {
  local checklist="$SCRIPTS/ios_full_braid_sqlcipher_physical_device_checklist.md"
  [[ -f "$checklist" ]] || die "missing physical-device checklist"
  grep -Fq '## Required before claiming device durability evidence' "$checklist" \
    || die "physical checklist missing required section"
  grep -Fq '## CI contract' "$checklist" \
    || die "physical checklist missing CI contract section"
  pass "physical-device checklist present"
}

run_release_hold() {
  assert_hold_gate_rejects_pollution
  expect_release_hold_failure
}

run_rust_lab_suite() {
  cd "$NODE"
  # Headless Linux has no Secret Service. Debug locked-file is proven-absent
  # / connect-fail only — same as rust-linux. Not a production Keychain claim.
  if [[ "$(uname -s)" == "Linux" ]]; then
    export RAVEN_IDENTITY_BACKEND=locked-file
  fi
  RAVEN_EXPECT_SQLCIPHER_4_17_0=1 \
    cargo test -p raven-core --features full-braid-durable-lab \
      --test full_braid_sqlcipher_profile -- --test-threads=1
  cargo test -p raven-core --lib
  pass "Rust durable-lab + default --lib"
}

run_clippy_rustfmt() {
  cd "$NODE"
  RAVEN_EXPECT_SQLCIPHER_4_17_0=1 \
    cargo clippy -p raven-core --features full-braid-durable-lab --all-targets -- -D warnings
  rustfmt --check \
    crates/raven-core/src/full_braid_durable_lab/*.rs \
    crates/raven-core/build.rs \
    crates/raven-core/tests/full_braid_sqlcipher_profile.rs \
    third_party/raven-sqlcipher-profile-guard/src/*.rs
  pass "clippy -D warnings + focused rustfmt"
}

run_symbol_and_override() {
  bash "$SCRIPTS/full_braid_sqlcipher_symbol_owner_report.sh" default
  bash "$SCRIPTS/full_braid_sqlcipher_symbol_owner_report.sh" lab
  bash "$SCRIPTS/full_braid_sqlcipher_profile_override_negatives.sh"
}

case "$MODE" in
  provenance)
    bash -n "$SCRIPTS/regenerate_sqlcipher_4_17.sh"
    bash -n "$SCRIPTS/verify_sqlcipher_4_17.sh"
    bash -n "$SCRIPTS/sqlcipher_4_17_provenance_selftest.sh"
    bash "$SCRIPTS/verify_sqlcipher_4_17.sh"
    bash "$SCRIPTS/sqlcipher_4_17_provenance_selftest.sh"
    assert_physical_checklist
    scoped_diff_check
    pass "Task 0A.5 provenance mode"
    ;;
  linux)
    bash -n "$SCRIPTS/full_braid_task0a_ci_gate.sh"
    bash -n "$SCRIPTS/full_braid_sqlcipher_symbol_owner_report.sh"
    bash -n "$SCRIPTS/full_braid_sqlcipher_profile_override_negatives.sh"
    bash -n "$SCRIPTS/full_braid_sqlcipher_open_profile_gate.sh"
    bash -n "$SCRIPTS/full_braid_sqlcipher_cross_provider_gate.sh"
    run_symbol_and_override
    run_rust_lab_suite
    run_clippy_rustfmt
    run_release_hold
    assert_physical_checklist
    scoped_diff_check
    pass "Task 0A.5 linux mode"
    ;;
  macos)
    bash -n "$SCRIPTS/ios_full_braid_sqlcipher_gate.sh"
    command -v plutil >/dev/null || die "plutil required on macOS"
    plutil -lint "$ROOT/ios-native/RAVEN/RAVEN/RAVEN.entitlements" >/dev/null
    plutil -lint "$ROOT/ios-native/RAVEN/RAVEN.xcodeproj/project.pbxproj" >/dev/null \
      || die "project.pbxproj failed plutil lint"
    pass "plist/project plutil lint"
    bash "$SCRIPTS/ios_full_braid_sqlcipher_gate.sh"
    run_symbol_and_override
    run_rust_lab_suite
    run_clippy_rustfmt
    run_release_hold
    assert_physical_checklist
    bash "$SCRIPTS/full_braid_sqlcipher_cross_provider_gate.sh"
    scoped_diff_check
    pass "Task 0A.5 macos mode"
    ;;
  windows)
    command -v cargo >/dev/null || die "cargo missing"
    # Symbol/import tools are mandatory on Windows (llvm-nm|dumpbin +
    # dumpbin|llvm-readobj); the symbol-owner script fails closed if absent.
    run_symbol_and_override
    run_rust_lab_suite
    run_release_hold
    assert_physical_checklist
    scoped_diff_check
    pass "Task 0A.5 windows mode"
    ;;
  *)
    die "usage: $0 provenance|linux|macos|windows"
    ;;
esac

echo "PASS: Full Braid Task 0A.5 CI gate ($MODE)" >&2
