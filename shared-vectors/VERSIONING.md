# `shared-vectors/` versioning rules

## v1 is FROZEN

`v1/` is the wire protocol described in `docs/MESH_PROTOCOL.md` v1. It is the contract iOS, Mac, Windows, Android, and Watch all conform to.

**Once a vector lands in `v1/`, it never changes.** Even if it's wrong. Every consumer's CI is asserting against these bytes; flipping a byte breaks every port at once.

If you need to fix a wire-level bug:

1. Open a `v2/` design doc (`docs/MESH_PROTOCOL_v2.md`).
2. Add new vectors under `v2/<same-relative-path>`.
3. Run both `v1/` and `v2/` consumers in parallel during the rollout.
4. Mark `v1/` files with `"deprecated_in_v2": true` once the fleet is on v2.

## Known v1 flaws (not fixed in place)

- **Pipe-joined signing inputs are ambiguous** (`docs/MESH_PROTOCOL.md` §I.13):
  the Rule 1/2/4/5 bytes in `v1/canonicalization/*_pipe_*` join fields with a
  bare `|`, so a relay can re-split signed fields (e.g. strip a DM geo-fence)
  without breaking the signature. The v1 vectors stay as they are; until v2,
  receivers reject pipe-form envelopes with `|` inside a signed field
  (MESH_PROTOCOL.md §D). Fix: `docs/MESH_PROTOCOL_v2.md` §2.
- **Rule 3 "sorted keys" JSON is not canonical across languages** (§I.14).
  Fix: RFC 8785, `docs/MESH_PROTOCOL_v2.md` §3.

The draft fix vectors are in `v2/canonicalization/` (`"protocol_version":
"v2-draft"`, written by `generate_v1.py`). They are not frozen until v2 is
adopted; from then on the rules above apply to `v2/` too.

## Adding a new vector

Acceptable: append a new `<name>_NNN.json` (next number) with a new edge case.

NOT acceptable: change an existing vector. Use `_NNN` numbering or move to `v2/`.

## File naming

```
v1/<category>/<feature>_<NNN>.json
```

Examples: `v1/crypto/aes_gcm_seal_001.json`, `v1/envelopes/post_002.json`.

`<category>` is one of: `crypto`, `canonicalization`, `envelopes`, `chunking`, `routing`, `trust`, `atsam_stack` (future).

## Schema

Every vector follows the schema documented in `docs/android/SHARED_VECTORS_REQUEST.md` §2.1:

```json
{
  "name": "...",
  "description": "...",
  "protocol_version": "v1",
  "spec_reference": "MESH_PROTOCOL.md §...",
  "created_at": "<iso>",
  "deterministic": true,
  "inputs": { ... },
  "expected": { ... },
  "notes": "..."
}
```

`name` is **immutable** once published — UI tests reference vector names; renaming breaks dashboards.
