#!/usr/bin/env bash
# Read-only provenance verifier for the libsqlite3-sys-raven fork's *ordinary*
# SQLite path (the amalgamation every default Raven build compiles).
#
# The fork is patched in via [patch.crates-io] as a path dependency, so
# Cargo.lock carries no checksum for it. This script proves that every file the
# fork did not intentionally change is byte-identical to the checksummed
# crates.io archive libsqlite3-sys-0.38.2.crate, and that the SHA-256 pins in
# the fork's build.rs match those upstream bytes.
#
# Offline: set RAVEN_LIBSQLITE3_SYS_CRATE_ARCHIVE=/path/to/libsqlite3-sys-0.38.2.crate
# (e.g. from ~/.cargo/registry/cache/*/); the archive SHA-256 is still checked.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
FORK="${RAVEN_LIBSQLITE3_SYS_FORK_DIR:-$ROOT/node/third_party/libsqlite3-sys-raven}"
# crates.io index `cksum` for libsqlite3-sys 0.38.2.
EXPECTED_CRATE_SHA="f1d20bef17f513b9b3004532233187769cd072d790971f4e4da0e346eb6401e8"
CRATE_URL="https://static.crates.io/crates/libsqlite3-sys/libsqlite3-sys-0.38.2.crate"
# Files the fork must not change (build.rs, Cargo.toml, sqlcipher/ and the
# Raven docs are the intentional delta and are reviewed/pinned separately).
UNCHANGED=(
  sqlite3/sqlite3.c
  sqlite3/sqlite3.h
  sqlite3/sqlite3ext.h
  sqlite3/bindgen_bundled_version.rs
  sqlite3/bindgen_bundled_version_ext.rs
  sqlite3/wasm32-wasi-vfs.c
  src/lib.rs
  src/error.rs
  bindgen-bindings/bindgen_3.34.1.rs
  bindgen-bindings/bindgen_3.34.1_ext.rs
  wrapper.h
  wrapper_ext.h
  LICENSE
)

fail() {
  printf 'LIBSQLITE3_SYS_ORDINARY_PROVENANCE_FAIL: %s\n' "$*" >&2
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
[[ -d "$FORK" && ! -L "$FORK" ]] || fail "fork directory missing: $FORK"

WORK_PARENT="${RAVEN_LIBSQLITE3_SYS_VERIFY_WORK_PARENT:-${TMPDIR:-/tmp}}"
[[ -d "$WORK_PARENT" && ! -L "$WORK_PARENT" && -w "$WORK_PARENT" ]] \
  || fail "unsafe work parent"
WORK="$(mktemp -d "$WORK_PARENT/raven-libsqlite3-sys-verify.XXXXXX")"
SENTINEL="$WORK/.raven-libsqlite3-sys-verify-owned"
: >"$SENTINEL"

cleanup() {
  [[ -n "${WORK:-}" && -d "$WORK" && ! -L "$WORK" ]] || return 0
  [[ "$(basename "$WORK")" == raven-libsqlite3-sys-verify.* ]] || return 0
  [[ -f "$SENTINEL" ]] || return 0
  find "$WORK" -depth -delete
}
trap cleanup EXIT

ARCHIVE="$WORK/libsqlite3-sys-0.38.2.crate"
if [[ -n "${RAVEN_LIBSQLITE3_SYS_CRATE_ARCHIVE:-}" ]]; then
  [[ -f "$RAVEN_LIBSQLITE3_SYS_CRATE_ARCHIVE" && ! -L "$RAVEN_LIBSQLITE3_SYS_CRATE_ARCHIVE" ]] \
    || fail "provided crate archive is not a regular file"
  cp "$RAVEN_LIBSQLITE3_SYS_CRATE_ARCHIVE" "$ARCHIVE"
else
  command -v curl >/dev/null 2>&1 || fail "curl missing"
  curl -A 'cargo/1.97' -fsSL "$CRATE_URL" -o "$ARCHIVE"
fi

[[ "$(sha256_file "$ARCHIVE")" == "$EXPECTED_CRATE_SHA" ]] \
  || fail "crate SHA-256 mismatch (expected crates.io cksum $EXPECTED_CRATE_SHA)"

mkdir "$WORK/unpack"
python3 - "$ARCHIVE" "$WORK/unpack" <<'PY'
import pathlib
import sys
import tarfile

archive, dest = sys.argv[1], pathlib.Path(sys.argv[2]).resolve()
with tarfile.open(archive, "r:gz") as tar:
    for member in tar.getmembers():
        target = (dest / member.name).resolve()
        if dest not in target.parents and target != dest:
            raise SystemExit(f"unsafe archive path: {member.name}")
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"unexpected archive member type: {member.name}")
    tar.extractall(dest)
PY
UPSTREAM="$WORK/unpack/libsqlite3-sys-0.38.2"
[[ -d "$UPSTREAM" ]] || fail "archive did not contain libsqlite3-sys-0.38.2/"

for rel in "${UNCHANGED[@]}"; do
  [[ -f "$FORK/$rel" && ! -L "$FORK/$rel" ]] || fail "fork file missing or not regular: $rel"
  [[ -f "$UPSTREAM/$rel" ]] || fail "upstream file missing: $rel"
  cmp -s "$FORK/$rel" "$UPSTREAM/$rel" || fail "fork differs from upstream: $rel"
done

# No extra or missing files in the ordinary amalgamation directory.
diff -rq "$FORK/sqlite3" "$UPSTREAM/sqlite3" >/dev/null \
  || fail "sqlite3/ directory contents differ from upstream"

# build.rs pins must be exactly the upstream hashes (and cover every file).
python3 - "$FORK/build.rs" "$UPSTREAM/sqlite3" <<'PY'
import hashlib
import pathlib
import re
import sys

build_rs = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
upstream = pathlib.Path(sys.argv[2])
block = re.search(
    r"RAVEN_ORDINARY_SQLITE_PINS: \[\(&str, &str\); \d+\] = \[(.*?)\];", build_rs, re.S
)
if not block:
    raise SystemExit("LIBSQLITE3_SYS_ORDINARY_PROVENANCE_FAIL: pin table missing from build.rs")
pins = dict(re.findall(r'\(\s*"([^"]+)",\s*"([0-9a-f]{64})",?\s*\)', block.group(1)))
files = {p.name for p in upstream.iterdir() if p.is_file()}
if set(pins) != files:
    raise SystemExit(
        f"LIBSQLITE3_SYS_ORDINARY_PROVENANCE_FAIL: pins cover {sorted(pins)}, upstream has {sorted(files)}"
    )
for name, pinned in sorted(pins.items()):
    actual = hashlib.sha256((upstream / name).read_bytes()).hexdigest()
    if actual != pinned:
        raise SystemExit(
            f"LIBSQLITE3_SYS_ORDINARY_PROVENANCE_FAIL: build.rs pin for {name} is {pinned}, upstream is {actual}"
        )
    print(f"pin-ok sqlite3/{name} {pinned}")
PY

printf 'LIBSQLITE3_SYS_ORDINARY_PROVENANCE_OK=%s\n' "$EXPECTED_CRATE_SHA"
