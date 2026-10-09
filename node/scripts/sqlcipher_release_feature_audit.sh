#!/usr/bin/env bash
# Release audit: no shipped Raven binary may link the lab SQLCipher amalgamation.
#
# The durable Full Braid lab is release-held (raven-core/build.rs, the lab
# module's compile_error!, and libsqlite3-sys-raven's own PROFILE check). This
# script is the CI-side check of the resolved feature graph: for every
# release-shipped package it fails if `bundled-sqlcipher*` or
# `full-braid-durable-lab` is enabled for any target.
#
# It also asserts that the resolved libsqlite3-sys really IS the audited fork
# (see assert_patched_libsqlite3_sys): the fork is wired only through
# [patch.crates-io] while rusqlite is pinned exactly, so a rusqlite bump that
# needs a different libsqlite3-sys would silently drop it (Cargo only warns
# "Patch ... was not used" and the --locked lockfile simply changes).
#
# Usage: scripts/sqlcipher_release_feature_audit.sh
#          audit raven-core, raven-node, ash and raven-swarm, then self-test that
#          the check does fire on raven-core's lab feature graph (CI mode)
#        scripts/sqlcipher_release_feature_audit.sh <package> ...
#          audit only these packages (no self-test)
#        RAVEN_AUDIT_FEATURES=<features> scripts/sqlcipher_release_feature_audit.sh <package>
#          audit with extra features enabled (expected to FAIL for the lab)
set -euo pipefail

NODE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$NODE"

# assert_patched_libsqlite3_sys LOCKFILE... — exit 2 unless every lockfile resolves
# exactly one libsqlite3-sys, as the path fork (version carries "+raven." and no
# registry `source`), with no unused [patch] entry. Text check on Cargo.lock: needs
# no cargo run and does not depend on `cargo tree` output format.
assert_patched_libsqlite3_sys() {
  python3 - "$@" <<'PY' || exit 2
import re, sys
bad = []
for path in sys.argv[1:]:
    text = open(path, encoding="utf-8").read()
    if "[[patch.unused]]" in text:
        bad.append(f"{path}: [[patch.unused]] present: a [patch.crates-io] entry is no longer used")
    owners = [b for b in text.split("[[package]]")
              if re.search(r'^name = "libsqlite3-sys"$', b, re.M)]
    if len(owners) != 1:
        bad.append(f"{path}: expected exactly one libsqlite3-sys package, found {len(owners)}")
        continue
    block = owners[0]
    version = re.search(r'^version = "([^"]+)"', block, re.M).group(1)
    if "+raven." not in version or re.search(r"^source = ", block, re.M):
        bad.append(f"{path}: libsqlite3-sys {version} is not the audited path fork "
                   "(third_party/libsqlite3-sys-raven, version +raven.*)")
if bad:
    for line in bad:
        print("FAIL: " + line, file=sys.stderr)
    sys.exit(1)
print("PASS: libsqlite3-sys resolves to the audited path fork in " + ", ".join(sys.argv[1:]))
PY
}

assert_patched_libsqlite3_sys "$NODE/Cargo.lock" "$NODE/fuzz/Cargo.lock"

# audit_package <package> [features] — 0 when clean, 1 when the lab provider
# is in the feature graph; exits 2 when the graph cannot be resolved.
audit_package() {
  local pkg="$1"
  local features="${2:-}"
  local tree
  # Inverted on libsqlite3-sys: every enabled feature of the single
  # links="sqlite3" owner appears as a node, whoever enables it.
  tree="$(cargo tree --locked -p "$pkg" ${features:+--features "$features"} \
    -e features --target all --prefix none \
    -i libsqlite3-sys 2>&1)" || {
    echo "FAIL: cargo tree for $pkg" >&2
    echo "$tree" >&2
    exit 2
  }
  # Sanity: the ordinary bundled SQLite must be present, or the tree is not
  # the graph we think it is.
  if ! grep -q 'libsqlite3-sys feature "bundled"' <<<"$tree"; then
    echo "FAIL: $pkg: expected libsqlite3-sys feature \"bundled\" in feature graph" >&2
    exit 2
  fi
  if grep -E '(libsqlite3-sys|rusqlite) feature "(bundled-)?sqlcipher|raven-core feature "full-braid-durable-lab"' <<<"$tree" >&2; then
    echo "FAIL: $pkg${features:+ (+$features)} enables the lab SQLCipher provider in its release feature graph" >&2
    return 1
  fi
  echo "PASS: $pkg${features:+ (+$features)} release feature graph has no SQLCipher lab provider"
  return 0
}

self_test=0
if [[ "$#" -gt 0 ]]; then
  packages=("$@")
else
  packages=(raven-core raven-node ash raven-swarm)
  self_test=1
fi

status=0
for pkg in "${packages[@]}"; do
  audit_package "$pkg" "${RAVEN_AUDIT_FEATURES:-}" || status=1
done

if [[ "$self_test" -eq 1 ]]; then
  # Negative self-test: the audit must fire on the lab feature graph, or a
  # pattern/format drift in `cargo tree` would turn it into a silent pass.
  if audit_package raven-core full-braid-durable-lab 2>/dev/null; then
    echo "FAIL: self-test: audit did not detect raven-core full-braid-durable-lab" >&2
    status=1
  else
    echo "PASS: self-test: audit detects the lab SQLCipher provider"
  fi
fi
exit "$status"
