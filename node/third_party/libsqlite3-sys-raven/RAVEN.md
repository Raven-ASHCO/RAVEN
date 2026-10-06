# RAVEN libsqlite3-sys fork (Task 0A.2)

Local audited fork of **libsqlite3-sys 0.38.2** (`links = "sqlite3"`).

## What changed vs upstream

- Package version: `0.38.2+raven.sqlcipher.4.17.0`
- `sqlcipher/sqlite3.c` and `sqlcipher/sqlite3.h` replaced with Task 0A.1 frozen SQLCipher **4.17.0** amalgamation
- `sqlcipher/manifest` + `sqlcipher/manifest.uuid` copied for build-time SHA pins
- Build script fail-closed checks when `bundled-sqlcipher*` is selected:
  - `RAVEN_EXPECT_SQLCIPHER_4_17_0=1` required
  - Exact SHA-256 pins for `sqlite3.c` / `sqlite3.h` / `manifest` / `manifest.uuid`
  - Confirms SQLCipher codec defines are scheduled
- Build script refuses `bundled-sqlcipher*` in release profiles (panic payload
  exactly `FULL_BRAID_SQLCIPHER_NOT_APPROVED`), so a dependent enabling it
  directly cannot bypass raven-core's durable-lab release hold. raven-core's
  hold stays the primary diagnostic; in a warm target dir both can fail in
  one build, and the Task 0A / R0 release-hold gates accept this secondary
  failure only with that exact payload. CI also audits the resolved release
  feature graphs (`../../scripts/sqlcipher_release_feature_audit.sh`).

## What did not change (enforced)

- Ordinary `sqlite3/` amalgamation path (default bundled SQLite 3.53.2):
  byte-identical to crates.io `libsqlite3-sys-0.38.2.crate`
  (SHA-256 `f1d20bef17f513b9b3004532233187769cd072d790971f4e4da0e346eb6401e8`).
  Every build that compiles it checks the SHA-256 pins in
  `RAVEN_ORDINARY_SQLITE_PINS` (build.rs) first, because a path dependency has
  no Cargo.lock checksum. `../../scripts/verify_sqlcipher_fork_ordinary_sqlite_upstream.sh`
  re-derives the pins from the upstream archive and byte-compares `sqlite3/`,
  `src/`, `bindgen-bindings/`, `wrapper*.h` and `LICENSE`. SQLite security
  updates therefore need an explicit vendor refresh + pin update (Dependabot
  and version-based CVE tracking do not see this path dependency).
- `links = "sqlite3"`
- Upstream MIT license for the Rust/build scaffolding
- Binding API surface (no unnecessary rewrite)

## Provenance

See `../../sqlcipher-4.17.0/PROVENANCE.md` and `sqlcipher/SQLCIPHER_LICENSE`.

OpenSSL for `bundled-sqlcipher-vendored-openssl` is pinned via openssl-src as recorded in Task 0A.1 (`300.6.1+3.6.3` / OpenSSL 3.6.3).
