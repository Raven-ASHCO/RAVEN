# SQLCipher 4.17.0 — Official Source Provenance (RAVEN Task 0A.1)

**Status:** Frozen for Task 0A.1. This directory is the only authorized amalgamation provenance pin for Full Braid Slice 3 SQLCipher work.

**Scope (Task 0A.1, historical):** Source provenance freeze only. Task 0A.1 itself performed no Cargo/SPM/pbxproj dependency wiring; that began with Task 0A.2. The pins in this document are unchanged since the freeze. For what happened after it, see "Current wiring status" below.

## Current wiring status (as of 2026-10-05)

This section is the only part of this document that describes anything after Task 0A.1.

- **Cargo wiring exists.** `node/Cargo.toml` patches `libsqlite3-sys` to the audited fork `node/third_party/libsqlite3-sys-raven` through `[patch.crates-io]` (Task 0A.2). The fork's `sqlcipher/` amalgamation is the artifact pinned below, and its `build.rs` re-verifies the SHA-256 pins before compiling it.
- **Lab only.** The SQLCipher amalgamation is compiled only for the `full-braid-durable-lab` feature of `raven-core` (rusqlite `bundled-sqlcipher-vendored-openssl`, using the OpenSSL pin below). Default and release builds of the shipped packages compile the ordinary SQLite amalgamation; `node/scripts/sqlcipher_release_feature_audit.sh` checks the resolved feature graphs.
- **Release hold in force.** Release builds of the lab feature fail closed (`FULL_BRAID_SQLCIPHER_NOT_APPROVED`). Production and release use of SQLCipher remains held and is not approved by this document.
- **Gates exist.** Tasks 0A.2 through 0A.5 have CI gates (`node/scripts/full_braid_task0a_ci_gate.sh` and the scripts it runs). Passing them is lab evidence only.

## Upstream Git pins

| Item | Value |
|---|---|
| Repository | `https://github.com/sqlcipher/sqlcipher.git` |
| Annotated tag | `v4.17.0` |
| Required ref | `refs/tags/v4.17.0` (mandatory; missing → `SQLCIPHER_TAG_MISSING`) |
| Tag object (SHA-1) | `f9788efa8ac4dfed75c03e4756b1666a1d0845da` |
| Peeled commit (SHA-1) | `810db22f575ee7cf94ea96a3e91622b5fcece3dc` |

## Amalgamation artifact SHA-256 pins

Regenerated with `./configure --with-tempstore=yes` and:

```text
CFLAGS="-DSQLITE_HAS_CODEC -DSQLITE_EXTRA_INIT=sqlcipher_extra_init -DSQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown"
```

| File | SHA-256 |
|---|---|
| `sqlite3.c` | `8adaff6b464052a74e7adaa3cfa2725400f48eca68f47856fa806eaf30bdf2c9` |
| `sqlite3.h` | `e564d0492e7556a8ad2f30c8ec645b5a6abb89f32f7b40465a3032d937596401` |
| `manifest` | `6703f59d2307674e09b55297c7832819ef44fb590691314a4da36f8240e41473` |
| `manifest.uuid` | `3ec90494f84736dd7efd0f49a06b787d3f791e0d6b2b1e0bce66fa792d6107e4` |

## Regeneration procedure (authoritative)

Advertised commands (temp `OUT_DIR` must verify):

```bash
OUT_DIR="$(mktemp -d /tmp/raven-sqlcipher-out-XXXXXX)"
./node/scripts/regenerate_sqlcipher_4_17.sh
# or custom:
OUT_DIR="$OUT_DIR" WORK_PARENT=/tmp ./node/scripts/regenerate_sqlcipher_4_17.sh
SQLCIPHER_PROVENANCE_DIR="$OUT_DIR" ./node/scripts/verify_sqlcipher_4_17.sh
# optional generated-only gate:
SQLCIPHER_VERIFY_MODE=generated-only SQLCIPHER_PROVENANCE_DIR="$OUT_DIR" \
  ./node/scripts/verify_sqlcipher_4_17.sh
```

1. Run `node/scripts/regenerate_sqlcipher_4_17.sh`.
2. Under an allowed `WORK_PARENT` (default `/tmp`; legacy `WORK_ROOT` is interpreted as parent only), create a dedicated `mktemp` child with prefix `raven-sqlcipher-4.17.0-regen-` and an ownership sentinel. User-supplied paths are never `rm -rf`'d directly.
3. Clone the upstream repository **twice** into that owned workdir.
4. **Before configure**, require `refs/tags/v4.17.0`; verify tag object and peeled commit match the pins (no optional branch). Mirrors without the tag fail with `SQLCIPHER_TAG_MISSING`.
5. Checkout the exact peeled commit; re-verify tag object/peel.
6. Run the configure/CFLAGS path and build the amalgamation with repository tooling.
7. Compare both generated trees **byte-for-byte**; reject unexpected `sqlite3*.c` sidecars.
8. Install amalgamation + LICENSE and **deterministic** `PROVENANCE.md` / `NOTICE` templates into `OUT_DIR`.
9. Run `node/scripts/verify_sqlcipher_4_17.sh` (`full` or `generated-only`).

Locally edited amalgamation blobs are rejected. Only script-regenerated artifacts that match the SHA-256 pins are accepted.

## Workdir safety

- Reject filesystem root, workspace root/paths, symlink parents that resolve unsafely, and non-writable parents (`SQLCIPHER_WORK_PARENT_REJECTED`).
- Accept a parent only if it is owned by the current UID, or is an explicit trusted sticky temp root (`/tmp`, `/private/tmp`, `/var/tmp` with sticky bit). Writable foreign non-sticky parents are rejected.
- Cleanup deletes only a directory that has a valid ownership sentinel, is still owned by the current UID (workdir + sentinel), lives directly under the resolved parent, and whose basename matches `raven-sqlcipher-4.17.0-regen-*`.
- A sentinel file placed outside the owned workdir must never be deleted by cleanup.

## Why `make verify-source` is not the provenance authority

Upstream SQLite’s `make verify-source` target runs `tool/src-verify.c` against the Fossil `manifest` / `manifest.uuid` in a source tree. That check answers only: “do the files currently on disk match the hashes recorded in *this* Fossil manifest?”

It is **not** RAVEN’s provenance authority for SQLCipher 4.17.0 because:

1. **SQLCipher is an intentional SQLite fork.** Codec hooks, build flags, and amalgamation contents diverge from stock SQLite by design. Passing or failing a generic SQLite release `verify-source` ritual does not certify the amalgamation we vendor.
2. **`src-verify` does not pin the generated amalgamation.** Our security-relevant deliverables are the regenerated `sqlite3.c` / `sqlite3.h` (plus accompanying `manifest` / `manifest.uuid`) produced under the exact configure/CFLAGS path. Manifest integrity of the checkout is necessary background, not sufficient proof of amalgamation identity.
3. **RAVEN’s bar is dual-clone deterministic regeneration.** Two clean clones at the exact peeled commit must produce byte-identical amalgamation trees whose SHA-256 digests match the frozen pins above. That procedure is enforced by `regenerate_sqlcipher_4_17.sh` / `verify_sqlcipher_4_17.sh`, not by `make verify-source`.

Therefore `make verify-source` may remain useful upstream hygiene, but it is explicitly rejected as the reference provenance gate for this fork’s vendored amalgamation.

## Terminal OpenSSL pin (Task 0A.1 freeze; used by the lab build since Task 0A.2)

Terminal / `bundled-sqlcipher-vendored-openssl` builds must use this exact OpenSSL source pin (crate packaging of upstream OpenSSL). Task 0A.1 itself performed no Cargo dependency mutation; the lab wiring that consumes this pin is described under "Current wiring status".

| Item | Value |
|---|---|
| Crate | `openssl-src` |
| Crate version | `300.6.1+3.6.3` |
| OpenSSL version | `3.6.3` (`VERSION.dat`: MAJOR=3 MINOR=6 PATCH=3; RELEASE_DATE="9 Jun 2026") |
| crates.io crate SHA-256 | `46eb8fb9fb3b61ce1c0f8a026c4c1a0714d3a9e138e7fbde78753ce2babc3846` |
| Crate license | MIT / Apache-2.0 |
| OpenSSL license | Apache License 2.0 (see `NOTICE`) |

## Verification modes

| Mode | Env | Checks |
|---|---|---|
| `full` (default) | `SQLCIPHER_VERIFY_MODE=full` | Requires `PROVENANCE.md` + `NOTICE` + amalgamation + `LICENSE`; doc pin greps |
| `generated-only` | `SQLCIPHER_VERIFY_MODE=generated-only` | Official generated-artifact gate: requires `sqlite3.c` / `sqlite3.h` / `manifest` / `manifest.uuid` / `LICENSE`; `PROVENANCE.md`/`NOTICE` optional if present |

## Allowed files in this directory (`full` mode)

```text
PROVENANCE.md
LICENSE
NOTICE
sqlite3.c
sqlite3.h
manifest
manifest.uuid
```

Any other file is a verify failure.
