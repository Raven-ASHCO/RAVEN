#!/usr/bin/env bash
# Read-only provenance verifier for Task 0B.3 R0.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FORK="${RAVEN_SS_FORK_DIR:-$ROOT/node/third_party/secret-service-2.0.2-raven-noprompt}"
EXPECTED_CRATE_SHA="e1da5c423b8783185fd3fecd1c8796c267d2c089d894ce5a93c280a5d3f780a2"
EXPECTED_LICENSE_APACHE="a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2"
EXPECTED_LICENSE_MIT="0d13fdf5615ccc7e7123b58b5c88b0d2bbabe345cd70b94e094ee44034db5be6"
# SHA-256 of the fork's RAVEN_PATCH_DIGEST file. That file lives INSIDE the fork, so
# comparing the fork against it proves only self-consistency: a PR that edits a
# MODIFIED file (e.g. src/session.rs: DH / secret handling) and regenerates the digest
# would still pass. Pinning the digest file's own hash here makes every legitimate
# re-freeze an edit of THIS script, which CODEOWNERS routes to crypto/assurance review.
EXPECTED_PATCH_DIGEST_SHA256="c1381f6acc96fed642e5de9ec08c99f96fbe06246d3db6274c62d55349353bb6"
CRATE_URL="https://static.crates.io/crates/secret-service/secret-service-2.0.2.crate"

fail() {
  printf 'SECRET_SERVICE_R0_PROVENANCE_FAIL: %s\n' "$*" >&2
  exit 1
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    fail "no SHA-256 tool"
  fi
}

command -v python3 >/dev/null 2>&1 || fail "python3 missing"
command -v cmp >/dev/null 2>&1 || fail "cmp missing"

WORK_PARENT="${RAVEN_SS_VERIFY_WORK_PARENT:-${TMPDIR:-/tmp}}"
[[ -d "$WORK_PARENT" && ! -L "$WORK_PARENT" && -w "$WORK_PARENT" ]] \
  || fail "unsafe work parent"
WORK="$(mktemp -d "$WORK_PARENT/raven-secret-service-r0-verify.XXXXXX")"
SENTINEL="$WORK/.raven-secret-service-r0-owned"
: >"$SENTINEL"

cleanup() {
  [[ -n "${WORK:-}" && -d "$WORK" && ! -L "$WORK" ]] || return 0
  [[ "$(basename "$WORK")" == raven-secret-service-r0-verify.* ]] || return 0
  [[ -f "$SENTINEL" ]] || return 0
  find "$WORK" -depth -delete
}
trap cleanup EXIT

ARCHIVE="$WORK/secret-service-2.0.2.crate"
if [[ -n "${RAVEN_SS_CRATE_ARCHIVE:-}" ]]; then
  [[ -f "$RAVEN_SS_CRATE_ARCHIVE" && ! -L "$RAVEN_SS_CRATE_ARCHIVE" ]] \
    || fail "provided crate archive is not a regular file"
  cp "$RAVEN_SS_CRATE_ARCHIVE" "$ARCHIVE"
else
  command -v curl >/dev/null 2>&1 || fail "curl missing"
  curl -A 'cargo/1.97' -fsSL "$CRATE_URL" -o "$ARCHIVE"
fi

[[ "$(sha256_file "$ARCHIVE")" == "$EXPECTED_CRATE_SHA" ]] \
  || fail "crate SHA-256 mismatch"

mkdir "$WORK/unpack"
python3 - "$ARCHIVE" "$WORK/unpack" <<'PY'
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    if not members:
        raise SystemExit("empty archive")
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if (
            path.is_absolute()
            or not path.parts
            or path.parts[0] != "secret-service-2.0.2"
            or ".." in path.parts
            or not (member.isdir() or member.isreg())
        ):
            raise SystemExit(f"unsafe archive member: {member.name}")
    tf.extractall(destination, members=members, filter="data")
PY

UPSTREAM="$WORK/unpack/secret-service-2.0.2"
[[ -d "$UPSTREAM" ]] || fail "upstream root missing"

MODIFIED=(
  Cargo.lock
  Cargo.toml
  src/collection.rs
  src/error.rs
  src/item.rs
  src/proxy/mod.rs
  src/session.rs
  src/util.rs
)
ADDED=(
  NOTICE
  PROVENANCE.md
  RAVEN_DELTA.md
  RAVEN_PATCH_DIGEST
  RAVEN_PATCH_MANIFEST
  tests/raven_r0_hard_stop.rs
)
PATCH_DIGEST_FILES=(
  Cargo.lock
  Cargo.toml
  NOTICE
  PROVENANCE.md
  RAVEN_DELTA.md
  RAVEN_PATCH_MANIFEST
  src/collection.rs
  src/error.rs
  src/item.rs
  src/proxy/mod.rs
  src/session.rs
  src/util.rs
  tests/raven_r0_hard_stop.rs
)

contains() {
  local needle="$1"
  shift
  local value
  for value in "$@"; do
    [[ "$value" == "$needle" ]] && return 0
  done
  return 1
}

[[ -d "$FORK" && ! -L "$FORK" ]] || fail "fork root missing or symlinked"
[[ -z "$(find "$FORK" -type l -print -quit)" ]] || fail "fork contains symlink"
[[ -z "$(find "$FORK" ! -type f ! -type d -print -quit)" ]] \
  || fail "fork contains non-regular entry"

while IFS= read -r upstream_file; do
  relative="${upstream_file#"$UPSTREAM/"}"
  fork_file="$FORK/$relative"
  [[ -f "$fork_file" && ! -L "$fork_file" ]] || fail "missing upstream file: $relative"
  if contains "$relative" "${MODIFIED[@]}"; then
    cmp -s "$upstream_file" "$fork_file" && fail "declared modification is unchanged: $relative"
  else
    cmp -s "$upstream_file" "$fork_file" || fail "undeclared modification: $relative"
  fi
done < <(find "$UPSTREAM" -type f | LC_ALL=C sort)

while IFS= read -r fork_file; do
  relative="${fork_file#"$FORK/"}"
  if [[ -f "$UPSTREAM/$relative" ]]; then
    continue
  fi
  contains "$relative" "${ADDED[@]}" || fail "undeclared added file: $relative"
done < <(find "$FORK" -type f | LC_ALL=C sort)

for relative in "${MODIFIED[@]}"; do
  [[ -f "$FORK/$relative" && -f "$UPSTREAM/$relative" ]] \
    || fail "modified allow-list entry missing: $relative"
done
for relative in "${ADDED[@]}"; do
  [[ -f "$FORK/$relative" && ! -e "$UPSTREAM/$relative" ]] \
    || fail "added allow-list entry mismatch: $relative"
done

[[ "$(sha256_file "$FORK/LICENSE-APACHE")" == "$EXPECTED_LICENSE_APACHE" ]] \
  || fail "Apache license mismatch"
[[ "$(sha256_file "$FORK/LICENSE-MIT")" == "$EXPECTED_LICENSE_MIT" ]] \
  || fail "MIT license mismatch"

[[ "$(sha256_file "$FORK/RAVEN_PATCH_DIGEST")" == "$EXPECTED_PATCH_DIGEST_SHA256" ]] \
  || fail "RAVEN_PATCH_DIGEST is not the pinned frozen digest (a deliberate re-freeze must update EXPECTED_PATCH_DIGEST_SHA256 in this script)"

GENERATED_DIGEST="$WORK/RAVEN_PATCH_DIGEST.generated"
: >"$GENERATED_DIGEST"
for relative in "${PATCH_DIGEST_FILES[@]}"; do
  printf '%s  %s\n' "$(sha256_file "$FORK/$relative")" "$relative" \
    >>"$GENERATED_DIGEST"
done
cmp -s "$GENERATED_DIGEST" "$FORK/RAVEN_PATCH_DIGEST" \
  || fail "frozen Raven patch digest mismatch"

printf 'SECRET_SERVICE_R0_PROVENANCE_OK crate=%s patch=%s\n' \
  "$EXPECTED_CRATE_SHA" "$(sha256_file "$FORK/RAVEN_PATCH_DIGEST")"
