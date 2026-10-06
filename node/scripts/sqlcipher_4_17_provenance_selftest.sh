#!/usr/bin/env bash
# Task 0A.1 self-test / negative + positive gates for SQLCipher provenance scripts.
# Does not commit, push, stage, or mutate Cargo/SPM/pbxproj dependencies.
#
# Usage:
#   ./node/scripts/sqlcipher_4_17_provenance_selftest.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
REGEN="$ROOT/node/scripts/regenerate_sqlcipher_4_17.sh"
VERIFY="$ROOT/node/scripts/verify_sqlcipher_4_17.sh"
VENDOR="$ROOT/node/third_party/sqlcipher-4.17.0"

DEP_PATHS=(
  "$ROOT/node/Cargo.toml"
  "$ROOT/node/Cargo.lock"
  "$ROOT/node/crates/raven-core/Cargo.toml"
  "$ROOT/ios-native/RAVEN/RAVEN.xcodeproj/project.pbxproj"
  "$ROOT/ios-native/RAVEN/RAVEN.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved"
)

pass() { echo "PASS: $*" >&2; }
fail() { echo "FAIL: $*" >&2; exit 1; }

expect_fail_diag() {
  local diag="$1"
  shift
  local out
  set +e
  out="$("$@" 2>&1)"
  local rc=$?
  set -e
  [[ "$rc" -ne 0 ]] || fail "expected failure for: $*"
  echo "$out" | grep -Eq "$diag" || fail "expected diagnostic '$diag' in output; got: $out"
  pass "negative ($diag)"
}

snapshot_dep_hashes() {
  local out="$1"
  : >"$out"
  local p
  for p in "${DEP_PATHS[@]}"; do
    if [[ -f "$p" ]]; then
      # path<TAB>sha256
      printf '%s\t%s\n' "$p" "$(shasum -a 256 "$p" | awk '{print $1}')" >>"$out"
    else
      printf '%s\t%s\n' "$p" "MISSING" >>"$out"
    fi
  done
}

echo "=== bash -n ===" >&2
bash -n "$REGEN"
bash -n "$VERIFY"
bash -n "$0"
pass "bash -n"

echo "=== dependency hash snapshot (before) ===" >&2
DEP_BEFORE="$(mktemp /tmp/raven-sqlcipher-dep-before-XXXXXX)"
DEP_AFTER="$(mktemp /tmp/raven-sqlcipher-dep-after-XXXXXX)"
snapshot_dep_hashes "$DEP_BEFORE"
pass "dependency hash snapshot taken"

echo "=== unsafe WORK_PARENT / WORK_ROOT negatives ===" >&2
expect_fail_diag "SQLCIPHER_WORK_PARENT_REJECTED" env WORK_ROOT=/ "$REGEN"
expect_fail_diag "SQLCIPHER_WORK_PARENT_REJECTED" env WORK_PARENT=/ "$REGEN"
expect_fail_diag "SQLCIPHER_WORK_PARENT_REJECTED" env WORK_PARENT="$ROOT" "$REGEN"
expect_fail_diag "SQLCIPHER_WORK_PARENT_REJECTED" env WORK_ROOT="$ROOT" "$REGEN"

# Symlink parent that resolves into the workspace must be rejected.
SYM_TO_WORKSPACE="$(mktemp -d /tmp/raven-sqlcipher-symws-XXXXXX)"
rmdir "$SYM_TO_WORKSPACE"
ln -s "$ROOT" "$SYM_TO_WORKSPACE"
expect_fail_diag "SQLCIPHER_WORK_PARENT_REJECTED" env WORK_PARENT="$SYM_TO_WORKSPACE" "$REGEN"
rm -f "$SYM_TO_WORKSPACE"

SYM_TO_ROOT="$(mktemp -d /tmp/raven-sqlcipher-symroot-XXXXXX)"
rmdir "$SYM_TO_ROOT"
ln -s / "$SYM_TO_ROOT"
expect_fail_diag "SQLCIPHER_WORK_PARENT_REJECTED" env WORK_PARENT="$SYM_TO_ROOT" "$REGEN"
rm -f "$SYM_TO_ROOT"

UNOWNED="$(mktemp -d /tmp/raven-sqlcipher-unowned-XXXXXX)"
chmod 555 "$UNOWNED"
expect_fail_diag "SQLCIPHER_WORK_PARENT_REJECTED" env WORK_PARENT="$UNOWNED" "$REGEN"
chmod 755 "$UNOWNED"
rmdir "$UNOWNED"

# Existing path must not be treated as a wipe target: leave a canary dir that
# looks like a workdir but has no valid sentinel; regen under same parent must
# not delete it.
SAFE_PARENT="$(mktemp -d /tmp/raven-sqlcipher-safeparent-XXXXXX)"
FAKE_WORK="$SAFE_PARENT/raven-sqlcipher-4.17.0-regen-FAKECANARY"
mkdir -p "$FAKE_WORK"
echo preserved >"$FAKE_WORK/canary.txt"
OUTSIDE_SENTINEL="$SAFE_PARENT/.raven_sqlcipher_4_17_regen_owned"
echo "OUTSIDE_SENTINEL_MUST_SURVIVE" >"$OUTSIDE_SENTINEL"

EMPTY_MIRROR="$(mktemp -d /tmp/raven-sqlcipher-empty-XXXXXX)"
git init --bare --quiet "$EMPTY_MIRROR/repo.git"
set +e
OUT_TMP="$(mktemp -d /tmp/raven-sqlcipher-outneg-XXXXXX)"
OUT="$(
  WORK_PARENT="$SAFE_PARENT" \
  OUT_DIR="$OUT_TMP" \
  SQLCIPHER_GIT_URL="$EMPTY_MIRROR/repo.git" \
  KEEP_WORK=0 \
  "$REGEN" 2>&1
)"
RC=$?
set -e
[[ "$RC" -ne 0 ]] || fail "expected regen failure on empty mirror"
echo "$OUT" | grep -q "SQLCIPHER_TAG_MISSING\|FAIL:" || fail "expected tag/clone failure; got: $OUT"
[[ -f "$FAKE_WORK/canary.txt" ]] || fail "fake workdir canary was deleted"
[[ -f "$OUTSIDE_SENTINEL" ]] || fail "outside sentinel was deleted"
grep -q "OUTSIDE_SENTINEL_MUST_SURVIVE" "$OUTSIDE_SENTINEL" || fail "outside sentinel mutated"
pass "sentinel outside workdir / fake workdir not deleted"
rm -rf "$SAFE_PARENT" "$EMPTY_MIRROR" "$OUT_TMP"

echo "=== missing-tag negative (before configure) ===" >&2
TAGLESS="$(mktemp -d /tmp/raven-sqlcipher-tagless-XXXXXX)"
git clone --quiet --bare https://github.com/sqlcipher/sqlcipher.git "$TAGLESS/full.git"
git clone --quiet --bare --no-tags "file://$TAGLESS/full.git" "$TAGLESS/notags.git"
while IFS= read -r t; do
  git --git-dir="$TAGLESS/notags.git" tag -d "$t" >/dev/null 2>&1 || true
done < <(git --git-dir="$TAGLESS/notags.git" tag)
if git --git-dir="$TAGLESS/notags.git" show-ref --verify --quiet refs/tags/v4.17.0; then
  fail "tagless mirror unexpectedly still has v4.17.0"
fi
OUT_TMP="$(mktemp -d /tmp/raven-sqlcipher-outneg2-XXXXXX)"
PHYS_TMP="$(cd /tmp && pwd -P)"
# Trusted sticky temp root (typically root-owned + sticky) must be accepted as parent.
expect_fail_diag "SQLCIPHER_TAG_MISSING" \
  env WORK_PARENT="$PHYS_TMP" OUT_DIR="$OUT_TMP" SQLCIPHER_GIT_URL="$TAGLESS/notags.git" "$REGEN"
[[ ! -f "$OUT_TMP/sqlite3.c" ]] || fail "missing-tag path wrote sqlite3.c"
rm -rf "$TAGLESS" "$OUT_TMP"
pass "missing-tag failed before configure output (sticky temp parent accepted)"

echo "=== allow-list negatives (file/dir/symlink/nested) ===" >&2
EXTRA_DIR="$(mktemp -d /tmp/raven-sqlcipher-extra-XXXXXX)"
cp -R "$VENDOR"/. "$EXTRA_DIR/"
echo junk >"$EXTRA_DIR/extra.txt"
expect_fail_diag "unexpected top-level entry" \
  env SQLCIPHER_PROVENANCE_DIR="$EXTRA_DIR" "$VERIFY"
rm -rf "$EXTRA_DIR"

DIR_NEG="$(mktemp -d /tmp/raven-sqlcipher-dirneg-XXXXXX)"
cp -R "$VENDOR"/. "$DIR_NEG/"
mkdir "$DIR_NEG/unexpected_dir"
expect_fail_diag "directory not allowed" \
  env SQLCIPHER_PROVENANCE_DIR="$DIR_NEG" "$VERIFY"
rm -rf "$DIR_NEG"

SYM_NEG="$(mktemp -d /tmp/raven-sqlcipher-symneg-XXXXXX)"
cp -R "$VENDOR"/. "$SYM_NEG/"
ln -s /etc/hosts "$SYM_NEG/hosts_link"
expect_fail_diag "symlink not allowed" \
  env SQLCIPHER_PROVENANCE_DIR="$SYM_NEG" "$VERIFY"
rm -rf "$SYM_NEG"

# Symlink replacing a required artifact must fail.
SYM_REQ="$(mktemp -d /tmp/raven-sqlcipher-symreq-XXXXXX)"
cp -R "$VENDOR"/. "$SYM_REQ/"
rm -f "$SYM_REQ/LICENSE"
ln -s /etc/hosts "$SYM_REQ/LICENSE"
expect_fail_diag "symlink not allowed" \
  env SQLCIPHER_PROVENANCE_DIR="$SYM_REQ" "$VERIFY"
rm -rf "$SYM_REQ"

NEST_NEG="$(mktemp -d /tmp/raven-sqlcipher-nestneg-XXXXXX)"
cp -R "$VENDOR"/. "$NEST_NEG/"
mkdir -p "$NEST_NEG/nested"
echo x >"$NEST_NEG/nested/x.txt"
expect_fail_diag "nested entry not allowed" \
  env SQLCIPHER_PROVENANCE_DIR="$NEST_NEG" "$VERIFY"
rm -rf "$NEST_NEG"

echo "=== verify normal vendor dir (full) ===" >&2
"$VERIFY"
pass "vendor full verify"

echo "=== dual clean clones + isolated OUT_DIR verify ===" >&2
ISO_OUT="$(mktemp -d /tmp/raven-sqlcipher-iso-out-XXXXXX)"
ISO_PARENT="$(mktemp -d /tmp/raven-sqlcipher-iso-parent-XXXXXX)"
OUT_DIR="$ISO_OUT" WORK_PARENT="$ISO_PARENT" "$REGEN"
SQLCIPHER_PROVENANCE_DIR="$ISO_OUT" "$VERIFY"
SQLCIPHER_VERIFY_MODE=generated-only SQLCIPHER_PROVENANCE_DIR="$ISO_OUT" "$VERIFY"
for f in sqlite3.c sqlite3.h manifest manifest.uuid LICENSE; do
  cmp -s "$VENDOR/$f" "$ISO_OUT/$f" || fail "diff-check mismatch on $f"
done
cmp -s "$ROOT/node/scripts/sqlcipher_4_17_templates/PROVENANCE.md" "$ISO_OUT/PROVENANCE.md" \
  || fail "PROVENANCE.md not deterministic vs template"
cmp -s "$ROOT/node/scripts/sqlcipher_4_17_templates/NOTICE" "$ISO_OUT/NOTICE" \
  || fail "NOTICE not deterministic vs template"
pass "isolated OUT_DIR full + generated-only verify + diff-check"
rm -rf "$ISO_OUT" "$ISO_PARENT"

echo "=== dependency leakage audit ===" >&2
# grep (POSIX, always present), not rg: `if rg ...; then fail; fi` read a missing
# ripgrep (rc 127) as "no leak" and passed without scanning anything. Treat only
# rc 1 (no match) as clean; a match (0) or any error (2: unreadable file, 127: no grep) fails.
leak_rc=0
grep -nE 'Cargo\.(toml|lock)|Package\.resolved|project\.pbxproj' "$REGEN" "$VERIFY" || leak_rc=$?
case "$leak_rc" in
  1) ;;
  0) fail "regen/verify scripts reference Cargo/SPM/pbxproj paths" ;;
  *) fail "dependency leakage audit could not run (grep rc=$leak_rc)" ;;
esac
snapshot_dep_hashes "$DEP_AFTER"
if ! cmp -s "$DEP_BEFORE" "$DEP_AFTER"; then
  echo "FAIL: dependency content hashes changed during selftest:" >&2
  diff -u "$DEP_BEFORE" "$DEP_AFTER" >&2 || true
  fail "dependency leakage (content hash mismatch)"
fi
pass "dependency leakage audit (before/after content hashes identical)"
rm -f "$DEP_BEFORE" "$DEP_AFTER"

STRIP="$(mktemp -d /tmp/raven-sqlcipher-strip-XXXXXX)"
for f in LICENSE sqlite3.c sqlite3.h manifest manifest.uuid; do
  cp "$VENDOR/$f" "$STRIP/"
done
SQLCIPHER_VERIFY_MODE=generated-only SQLCIPHER_PROVENANCE_DIR="$STRIP" "$VERIFY"
rm -rf "$STRIP"
pass "generated-only on docs-stripped tree"

echo "PASS: sqlcipher 4.17.0 provenance selftest complete" >&2
