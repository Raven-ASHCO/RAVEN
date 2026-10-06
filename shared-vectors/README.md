# `shared-vectors/` — cross-platform RAVEN test fixtures

This directory holds **deterministic, byte-exact test vectors** for every wire-protocol layer in RAVEN: crypto primitives, signing canonicalization, envelope encode/decode, BLE chunking, mesh routing, and trust.

Consumers:

- **iOS / Mac Catalyst** — `RAVEN-iOS/MeshV1/Tests` (SPM test target: `SharedVectorsTests.swift`, `SharedVectorsSignatureTests.swift`). On this serverless `main` there is **no** `ios-native/` tree; **Raven Serverless Node** jobs that `cd` into iOS/Watch/Libp2pBridge are **blocked / N/A** until tree and workflow align. Do not treat those jobs as healthy gates here.
- **Android** — `RAVEN-Android/modules/mesh/src/test/kotlin/.../SharedVectorsTest.kt` (or via git submodule from `raven-android`)
- **Watch (read-only)** — observation-only; vectors not consumed there. `RAVEN-WatchApp/` is absent on this `main`.
- **.NET / C# `rvn1`** — **NOT YET.** No shared-vector smoke gate in `.github/workflows/raven-serverless.yml`. Do not implement a harness from this note.

If you change a vector, **every consumer breaks**. That's the point — wire-protocol changes are coordinated across the fleet.

## Layout

```
shared-vectors/
├── generate_v1.py            (regenerator — uses cryptography lib; deterministic)
├── README.md                 (this file)
├── VERSIONING.md             (rules for adding / changing vectors)
├── v1/
│   ├── identities.json       (canonical Alice / Bob / Carol / Dave keys + fingerprints)
│   ├── crypto/               (Ed25519, X25519, HKDF, AES-GCM, fingerprint, key rotation)
│   ├── canonicalization/     (5 signing rules from §D)
│   ├── envelopes/            (SignedMeshPayload, EncryptedMeshPayload, ACK, Post, Frame, Stop)
│   ├── chunking/             (§B chunk + reassembly)
│   ├── routing/              (dedup keys, spray, forward decision, pairing code)
│   └── trust/                (TOFU friend-device states)
└── rvn1/                     (serverless V1 protocol contract — see `rvn1/` section below)
    ├── identities.json
    ├── address/, identities/ (RavenAddressV1, fingerprints)
    ├── envelope/, ack/       (RavenEnvelopeV1, ACK)
    ├── alias/, device_cert/  (alias records, device certs)
    ├── capabilities/, routing/
    ├── atsam/                (known-root KATs + disabled indexed-session profile)
    └── negative/             (malformed-input / rejection cases)
```

## Determinism

- **Fixed test keys** — RFC 8032 / RFC 7748-derived seeds. See `v1/identities.json`.
- **Fixed timestamp** — every vector uses `1700000000` (= 2023-11-14T22:13:20 Z) as its base epoch.
- **Fixed nonces** — counter-prefixed or RFC-derived; never random.
- **No "now"** — every output is reproducible. If you re-run `generate_v1.py` the files must be byte-identical.

## Regenerating

```sh
pip3 install --user cryptography
python3 shared-vectors/generate_v1.py
```

Then run `git diff shared-vectors/v1/` to confirm no changes.

If `git diff` shows changes after a regenerate, **one of these is true:**

1. The spec changed (intentional — coordinate with all consumers; bump to `v2/`).
2. A bug in `generate_v1.py` (revert the diff, fix the script).
3. A cryptography library version diff (Ed25519 / AES-GCM is deterministic — if outputs change, that's a serious red flag; pin the library version).

## Source of truth

The Kotlin scaffold at `RAVEN-Android/modules/mesh/` is the reference port targeting **v1**. The iOS app's current `MeshService.swift` is **out of sync with v1** (uses a different service UUID and a much simpler envelope). Bringing iOS up to v1 is tracked under [A1](https://github.com/Raven-offline-messenger/raven-android/issues/1).

Until iOS catches up, these vectors document what the wire **should** look like — not what it **does** look like on iOS today.

## `rvn1/`

`rvn1/` is the vector tree for the **serverless V1 protocol contract** — the wire format RAVEN moves to once it no longer depends on a central server (addresses, routing tags, envelopes, ACKs, aliases, device certs, capabilities). It is a distinct contract from `v1/` above (the original server-relayed / BLE-mesh protocol); the two are generated, versioned, and frozen independently.

- **Generator**: `protocol/reference/generate_rvn1.py`. Source of truth is the `raven_protocol` reference package (`protocol/reference/raven_protocol/`) — the same Python implementation exercised by the tests under `protocol/reference/tests/` (`cd protocol/reference && python3 -m pytest`).
- **Indexed-session profile**: `atsam/indexed_session_v1_*.json` is a separately
  identified, additive byte contract under the RVN1 outer-envelope tree. It
  freezes KDF/allocator/ACK interop but remains production-disabled pending a
  signed PairInit that negotiates and transcript-binds
  `ATSAM/indexed-session/v1`.
- **Consumers**: Rust `raven-core` / `protocol/reference` via **Raven Serverless Node** job **Rust + vectors (Linux)** step **protocol vectors (python)** (present-tree intent; parent job is **not-yet-green** on live PRs — `fmt`). Swift/iOS `rvn1` jobs in that workflow are **path-missing** on this `main`. **.NET / C# `rvn1` shared-vector CI consumer is NOT YET** (no smoke gate in `raven-serverless.yml`). Kotlin remains a future port. See `protocol/PROTOCOL_VERSIONS.md`.
- **Freeze rules**: `rvn1/` is frozen under the exact same rules as `v1/` in `VERSIONING.md` — once a vector lands it never changes; new edge cases get a new `_NNN` file; breaking changes require a new tree (`rvn2/`), not an edit in place.
- **Regeneration / drift check**: CI (**Rust + vectors (Linux)** → step **protocol vectors (python)**) runs `python3 protocol/reference/generate_rvn1.py` and then `git diff --exit-code -- shared-vectors/rvn1` plus an untracked-file check, so a vector the generator no longer reproduces fails the job. Fixtures written by the other generators (`generate_hybrid_ratchet_v2.py`, `generate_full_braid.py`) and hand-authored `lan/*` fixtures are checked by their consumer tests, not regenerated. Separately, `bash scripts/freeze_protocol_hashes.sh --check` fails CI when any `protocol/` or `shared-vectors/rvn1/` file drifts from `docs/PROTOCOL_FREEZE_HASHES_V1.md`. There is no `tools/sync-vectors.sh`.
