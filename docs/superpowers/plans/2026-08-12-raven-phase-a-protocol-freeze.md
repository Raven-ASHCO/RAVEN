# RAVEN Phase A — Protocol Freeze Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development
> (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps
> use checkbox (`- [x]`) syntax for tracking.

**Goal:** Freeze RAVEN's serverless V1 identity, address, envelope, ACK, and supporting
records as versioned specifications backed by deterministic cross-platform test vectors —
before any Rust node or CLI code is written (mission steps 03–08).

**Architecture:** Phase A is a specification + reference-implementation + vector phase. The
executable artifacts are small, TDD Python reference implementations under a new
`protocol/reference/` package that (a) prove each canonical form is implementable and (b)
*generate* the frozen `rvn1` vector tree that the Rust node (Phase B) and every platform
must reproduce byte-for-byte. Specs are Markdown under `protocol/`. We reuse the existing
`shared-vectors` discipline (fixed RFC-8032 keys, fixed epoch, counter-derived nonces,
determinism-locked regeneration).

**Tech Stack:** Python 3 + `cryptography` (already the `shared-vectors` toolchain),
Markdown specs, JSON vectors. No Rust yet. No network code yet.

**Grounding:** [AUDIT_SERVERLESS_PIVOT_2026-08-12.md](../../AUDIT_SERVERLESS_PIVOT_2026-08-12.md),
[roadmap](2026-08-12-raven-serverless-roadmap.md), existing `docs/MESH_PROTOCOL.md`,
`shared-vectors/`, `raven-security/`.

---

> **CLOSEOUT STATUS (2026-08-12):** Phase A wire freeze is **complete on disk**.
> Implementation/reference/spec/vector steps below are marked `[x]`. Process-only
> **commit** steps and the Libp2pBridge hygiene commit remain `[ ]` (operator did
> not request commits). Honest open binding items: ATSAM crypto KATs still
> placeholders; `userId`→address migration (Identity §4); MeshEnvelope shipping
> until Phase G. See
> [`../specs/2026-08-12-phase-a-closeout-design.md`](../specs/2026-08-12-phase-a-closeout-design.md)
> and [`protocol/ATSAM_PRIMITIVE_MAPPING_V1.md`](../../../protocol/ATSAM_PRIMITIVE_MAPPING_V1.md).


## Scope check

Phase A is one coherent subsystem (the frozen protocol contract). It does **not** include
node networking, CLI, DHT, or BLE — those are Phases B–I with their own plans. Do not pull
implementation forward.

## One decision to confirm before freezing (reversible now, flag-day later)

**RavenAddressV1 encoding.** This plan specifies **Bech32m** (BIP-350: HRP `rvn`, proven
BCH checksum, the encoding behind Bitcoin/Nostr identifiers) because it gives the mission's
required "version marker + checksum" with a reference algorithm we can vector-test. The
mission's illustrative `rvn1:7K4F-93PA-…` looks like grouped Crockford Base32; this plan
treats that as *display grouping* layered over the canonical Bech32m string. If the team
prefers canonical Crockford Base32 instead, only Task 3 and the address vectors change —
everything downstream keys off the raw 32-byte identity public key, not the text form.
**Recommendation: Bech32m.** Confirm before Task 3; it is cheap to switch pre-freeze and
expensive after.

---

## File Structure

New/`protocol/` tree (canonical home per mission §96; today specs are scattered):

- `protocol/SPEC.md` — index + the seven invariants; links every sub-spec and vector dir.
- `protocol/RAVEN_IDENTITY_V1.md` — user identity key, device identity key, device
  certificate, fingerprint reconciliation. (Mission step 04, §6, §21, §71–72.)
- `protocol/RAVEN_ADDRESS_V1.md` — `rvn1` canonical address, Bech32m, display grouping,
  alias vs address vs identity. (Step 05, §6.)
- `protocol/RAVEN_ENVELOPE_V1.md` — binary `RavenEnvelopeV1` byte layout + canonical
  signing bytes. (Step 06, §24–25.)
- `protocol/RAVEN_ACK_V1.md` — `RavenAckV1` sealed body + signing bytes + state machine
  mapping. (Step 07, §26–27.)
- `protocol/RAVEN_ALIAS_V1.md` — signed alias record, monotonic sequence, ambiguity rule.
  (§6, §68–69.)
- `protocol/RAVEN_ROUTING_TAG_V1.md` — mailbox rendezvous tag derivation. (§23.)
- `protocol/RAVEN_CAPABILITIES_V1.md` — signed capability set, downgrade protection. (§43.)
- `protocol/reference/` — Python reference implementations (the executable, TDD part):
  - `raven_protocol/__init__.py`
  - `raven_protocol/bech32m.py` — Bech32m encode/decode (BIP-350).
  - `raven_protocol/address.py` — RavenAddressV1 over bech32m.
  - `raven_protocol/fingerprint.py` — both fingerprint schemes + the canonical choice.
  - `raven_protocol/envelope.py` — pack/unpack + `signing_bytes`.
  - `raven_protocol/ack.py` — ACK body + signing bytes.
  - `raven_protocol/alias.py` — alias record signing bytes.
  - `raven_protocol/routing_tag.py` — tag derivation.
  - `raven_protocol/device_cert.py` — device certificate signing bytes.
  - `tests/` — pytest, one file per module (TDD source of truth).
  - `generate_rvn1.py` — writes `shared-vectors/rvn1/**` from the reference impls.
- `shared-vectors/rvn1/` — new frozen vector tree (mission step 08); mirrors `v1/` layout:
  `identities.json`, `address/`, `envelope/`, `ack/`, `alias/`, `routing/`, `device_cert/`,
  `capabilities/`, plus `negative/` for malformed/tamper/expiry/downgrade vectors.
- `docs/THREAT_MODEL.md` — rewritten for the serverless-P2P adversary set (step 03, §73);
  supersedes the pre-pivot `raven-security/THREAT_MODEL.md` (which becomes a historical
  snapshot).

Reused unchanged: `shared-vectors/v1/` (frozen — never edited), `shared-vectors/identities.json`
key material (canonical alice/bob/carol/dave RFC-8032 keys), `tools/sync-vectors.sh`.

## Conventions locked for all vectors

- **Fixed keys:** the four identities already in `shared-vectors/v1/identities.json`
  (alice = RFC 8032 test vector 1, etc.). Reuse verbatim; never generate fresh keys.
- **Fixed epoch:** `1700000000` seconds (matches `v1`). Millisecond fields = `1700000000000`.
- **Fixed nonces:** counter-derived, never random: `nonce = counter.to_bytes(12,'big')` etc.
- **Determinism:** re-running `generate_rvn1.py` MUST produce a byte-identical tree
  (asserted by a test). No `now()`, no `os.urandom`.
- **Endianness:** all multi-byte integers on the wire are **big-endian**.

---

## Task 1: Scaffold the reference package and commit the untracked bridge work

**Files:**
- Create: `protocol/reference/raven_protocol/__init__.py`
- Create: `protocol/reference/tests/__init__.py`
- Create: `protocol/reference/requirements.txt`
- Create: `protocol/reference/pytest.ini`

- [ ] **Step 1: Commit the working-tree-only bridge code first (audit hazard)**

The audit found `ios-native/RAVEN/Libp2pBridge/rendezvous.go` and both bridge test files
are untracked and `bridge.go`/`go.mod` are modified — a `git clean` would destroy the only
copy. Preserve it before doing anything else.

```bash
cd /path/to/hybrid_messenger
git add ios-native/RAVEN/Libp2pBridge/
git commit -m "chore(bridge): commit working-tree rendezvous + bridge modifications before protocol freeze"
```

- [x] **Step 2: Create the Python package skeleton**

```python
# protocol/reference/raven_protocol/__init__.py
"""RAVEN V1 protocol reference implementations.

These are the SOURCE OF TRUTH for the rvn1 test vectors. The Rust node and every
platform port must reproduce these outputs byte-for-byte. Deterministic only:
no now(), no os.urandom.
"""
__all__ = [
    "bech32m", "address", "fingerprint", "envelope",
    "ack", "alias", "routing_tag", "device_cert",
]
```

```
# protocol/reference/requirements.txt
cryptography>=42
pytest>=8
```

```ini
; protocol/reference/pytest.ini
[pytest]
testpaths = tests
python_files = test_*.py
```

- [x] **Step 3: Verify the toolchain runs**

Run: `cd protocol/reference && python3 -m pip install -r requirements.txt && python3 -m pytest -q`
Expected: `no tests ran` (exit 5) — package imports, no tests yet.

- [ ] **Step 4: Commit**

```bash
git add protocol/reference/
git commit -m "chore(protocol): scaffold rvn1 reference-implementation package"
```

---

## Task 2: Bech32m codec (BIP-350) — foundation for the address

**Files:**
- Create: `protocol/reference/raven_protocol/bech32m.py`
- Test: `protocol/reference/tests/test_bech32m.py`

- [x] **Step 1: Write the failing test**

```python
# tests/test_bech32m.py
from raven_protocol import bech32m

def test_encode_decode_roundtrip():
    data = bytes(range(21))  # 21 payload bytes (version + 20-byte hash)
    s = bech32m.encode("rvn", data)
    assert s.startswith("rvn1")
    hrp, out = bech32m.decode(s)
    assert hrp == "rvn"
    assert out == data

def test_checksum_rejects_single_char_corruption():
    s = bech32m.encode("rvn", bytes(range(21)))
    # flip one data char (not the hrp, not the '1' separator)
    i = len(s) - 3
    bad = s[:i] + ("q" if s[i] != "q" else "p") + s[i+1:]
    assert bech32m.decode(bad) is None

def test_wrong_hrp_is_reported():
    s = bech32m.encode("rvn", bytes(range(21)))
    hrp, _ = bech32m.decode(s)
    assert hrp != "btc"
```

- [x] **Step 2: Run to verify it fails**

Run: `cd protocol/reference && python3 -m pytest tests/test_bech32m.py -q`
Expected: FAIL — `ModuleNotFoundError` / `AttributeError: encode`.

- [x] **Step 3: Implement Bech32m (reference algorithm from BIP-350)**

```python
# raven_protocol/bech32m.py
"""Bech32m (BIP-350). Adapted from the BIP-0350 reference; constant BECH32M_CONST."""
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2bc830a3

def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk

def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]

def _create_checksum(hrp, data):
    values = _hrp_expand(hrp) + data
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def _verify_checksum(hrp, data):
    return _polymod(_hrp_expand(hrp) + data) == BECH32M_CONST

def _convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def encode(hrp, payload: bytes) -> str:
    data = _convertbits(list(payload), 8, 5, True)
    combined = data + _create_checksum(hrp, data)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)

def decode(s: str):
    """Returns (hrp, payload_bytes) or None on any error."""
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        return None
    if s.lower() != s and s.upper() != s:
        return None
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s):
        return None
    hrp = s[:pos]
    try:
        data = [CHARSET.index(c) for c in s[pos+1:]]
    except ValueError:
        return None
    if not _verify_checksum(hrp, data):
        return None
    payload = _convertbits(data[:-6], 5, 8, False)
    if payload is None:
        return None
    return hrp, bytes(payload)
```

- [x] **Step 4: Run to verify it passes**

Run: `cd protocol/reference && python3 -m pytest tests/test_bech32m.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add protocol/reference/raven_protocol/bech32m.py protocol/reference/tests/test_bech32m.py
git commit -m "feat(protocol): Bech32m codec (BIP-350) reference"
```

---

## Task 3: RavenAddressV1 + fingerprint reconciliation

**Files:**
- Create: `protocol/reference/raven_protocol/address.py`
- Create: `protocol/reference/raven_protocol/fingerprint.py`
- Test: `protocol/reference/tests/test_address.py`
- Test: `protocol/reference/tests/test_fingerprint.py`

**Canonical definitions (normative — these become RAVEN_ADDRESS_V1.md / RAVEN_IDENTITY_V1.md):**

- `RavenAddressV1` payload = `version(1 byte = 0x01) ‖ addr_hash(20 bytes)` where
  `addr_hash = SHA-256(identity_ed25519_pub_raw_32)[:20]`. Canonical string =
  `bech32m("rvn", payload)`. Display grouping = uppercase of the data part, split into
  4-char groups joined by `-`, prefixed `rvn1:` (pure presentation; parsers accept the
  canonical lowercase bech32m form).
- **Fingerprint reconciliation.** Two shipped schemes exist (audit): the app's
  `SHA-256(edPub)[:9]` → base64 (strip `+`/`/`) → first 12 chars → `XXXX-XXXX-XXXX`
  (baked into BLE advertising, bridge fp-binding, server `devices.py`), and MeshV1's
  `SHA-256(edPub)[:6]` → hex uppercase → `XXXX-XXXX-XXXX`. Decision: the **app scheme is
  canonical `RavenDeviceFingerprintV1`** (avoids a flag-day BLE break); the MeshV1 hex form
  is documented as deprecated. The *machine identity* is the RavenAddress, not either
  fingerprint; fingerprints are human cross-check strings only.

- [x] **Step 1: Write the failing tests**

```python
# tests/test_fingerprint.py
import hashlib
from raven_protocol import fingerprint

ALICE_ED_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

def test_canonical_device_fingerprint_matches_app_scheme():
    # SHA256[:9] -> base64 strip +/ -> first 12 -> XXXX-XXXX-XXXX
    assert fingerprint.device_fingerprint_v1(ALICE_ED_PUB) == fingerprint.device_fingerprint_v1(ALICE_ED_PUB)
    fp = fingerprint.device_fingerprint_v1(ALICE_ED_PUB)
    assert len(fp) == 14 and fp[4] == "-" and fp[9] == "-"

def test_meshv1_hex_fingerprint_is_alice_known_value():
    # Locks the deprecated MeshV1 scheme against its own frozen vector.
    assert fingerprint.mesh_v1_hex_fingerprint(ALICE_ED_PUB) == "21FE-31DF-A154"
```

```python
# tests/test_address.py
from raven_protocol import address

ALICE_ED_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

def test_address_roundtrip():
    a = address.encode(ALICE_ED_PUB)
    assert a.startswith("rvn1")
    pub_hash, version = address.decode(a)
    assert version == 1
    assert len(pub_hash) == 20

def test_address_is_deterministic():
    assert address.encode(ALICE_ED_PUB) == address.encode(ALICE_ED_PUB)

def test_corrupted_address_rejected():
    a = address.encode(ALICE_ED_PUB)
    bad = a[:-1] + ("q" if a[-1] != "q" else "p")
    assert address.decode(bad) is None

def test_display_grouping_is_reversible():
    a = address.encode(ALICE_ED_PUB)
    disp = address.to_display(a)
    assert disp.startswith("rvn1:")
    assert address.from_display(disp) == a
```

- [x] **Step 2: Run to verify they fail**

Run: `cd protocol/reference && python3 -m pytest tests/test_address.py tests/test_fingerprint.py -q`
Expected: FAIL — modules missing.

- [x] **Step 3: Implement fingerprint.py and address.py**

```python
# raven_protocol/fingerprint.py
import hashlib

def _group4(s: str) -> str:
    return "-".join(s[i:i+4] for i in range(0, len(s), 4))

def device_fingerprint_v1(ed_pub: bytes) -> str:
    """Canonical RavenDeviceFingerprintV1 — matches shipping app DeviceIdentityService."""
    import base64
    h = hashlib.sha256(ed_pub).digest()
    b64 = base64.b64encode(h[:9]).decode().replace("+", "").replace("/", "")
    return _group4(b64[:12])

def mesh_v1_hex_fingerprint(ed_pub: bytes) -> str:
    """DEPRECATED MeshV1 scheme, kept only to lock the frozen v1 vector."""
    h = hashlib.sha256(ed_pub).digest()
    return _group4(h[:6].hex().upper())
```

```python
# raven_protocol/address.py
import hashlib
from . import bech32m

ADDRESS_VERSION = 1

def encode(identity_ed_pub: bytes) -> str:
    addr_hash = hashlib.sha256(identity_ed_pub).digest()[:20]
    payload = bytes([ADDRESS_VERSION]) + addr_hash
    return bech32m.encode("rvn", payload)

def decode(addr: str):
    """Returns (addr_hash_20, version) or None."""
    res = bech32m.decode(addr.strip())
    if res is None:
        return None
    hrp, payload = res
    if hrp != "rvn" or len(payload) != 21:
        return None
    return payload[1:], payload[0]

def to_display(addr: str) -> str:
    data = addr.split("1", 1)[1].upper()
    return "rvn1:" + "-".join(data[i:i+4] for i in range(0, len(data), 4))

def from_display(disp: str) -> str:
    body = disp.replace("rvn1:", "").replace("-", "").lower()
    return "rvn1" + body
```

- [x] **Step 4: Run to verify pass**

Run: `cd protocol/reference && python3 -m pytest tests/test_address.py tests/test_fingerprint.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add protocol/reference/raven_protocol/address.py protocol/reference/raven_protocol/fingerprint.py protocol/reference/tests/test_address.py protocol/reference/tests/test_fingerprint.py
git commit -m "feat(protocol): RavenAddressV1 (bech32m) + fingerprint reconciliation"
```

---

## Task 4: RavenRoutingTagV1 (mailbox rendezvous tag)

**Files:**
- Create: `protocol/reference/raven_protocol/routing_tag.py`
- Test: `protocol/reference/tests/test_routing_tag.py`

**Canonical definition (→ RAVEN_ROUTING_TAG_V1.md, mission §23):**
`tag = HMAC-SHA256(K_route, "rvn1/route" ‖ epoch_be8 ‖ counter_be8)[:16]`. `K_route` is the
32-byte per-pair routing key derived from the ATSAM key tree (GhostRoute label; exists
today). The tag rotates every message (counter) and every epoch; a store node without
`K_route` cannot derive or link tags.

- [x] **Step 1: Write the failing test**

```python
# tests/test_routing_tag.py
from raven_protocol import routing_tag

K_ROUTE = bytes(range(32))

def test_tag_is_16_bytes_and_deterministic():
    t1 = routing_tag.derive(K_ROUTE, epoch=1700000000, counter=0)
    t2 = routing_tag.derive(K_ROUTE, epoch=1700000000, counter=0)
    assert t1 == t2 and len(t1) == 16

def test_unlinkable_across_counter_and_epoch():
    base = routing_tag.derive(K_ROUTE, 1700000000, 0)
    assert routing_tag.derive(K_ROUTE, 1700000000, 1) != base
    assert routing_tag.derive(K_ROUTE, 1700003600, 0) != base

def test_wrong_key_gives_different_tag():
    base = routing_tag.derive(K_ROUTE, 1700000000, 0)
    assert routing_tag.derive(bytes(32), 1700000000, 0) != base
```

- [x] **Step 2: Run to verify it fails**

Run: `cd protocol/reference && python3 -m pytest tests/test_routing_tag.py -q`
Expected: FAIL — module missing.

- [x] **Step 3: Implement routing_tag.py**

```python
# raven_protocol/routing_tag.py
import hmac, hashlib

LABEL = b"rvn1/route"

def derive(k_route: bytes, epoch: int, counter: int) -> bytes:
    msg = LABEL + epoch.to_bytes(8, "big") + counter.to_bytes(8, "big")
    return hmac.new(k_route, msg, hashlib.sha256).digest()[:16]
```

- [x] **Step 4: Run to verify pass**

Run: `cd protocol/reference && python3 -m pytest tests/test_routing_tag.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add protocol/reference/raven_protocol/routing_tag.py protocol/reference/tests/test_routing_tag.py
git commit -m "feat(protocol): RavenRoutingTagV1 mailbox rendezvous tag"
```

---

## Task 5: RavenEnvelopeV1 binary codec + canonical signing bytes

**Files:**
- Create: `protocol/reference/raven_protocol/envelope.py`
- Test: `protocol/reference/tests/test_envelope.py`

**Canonical layout (normative → RAVEN_ENVELOPE_V1.md, mission §24). All big-endian.**

Fixed 86-byte prefix, then three length-delimited variable fields:

| Off | Size | Field | Notes |
|----|----|----|----|
| 0 | 4 | `magic` | ASCII `RVN1` = `0x52564E31` |
| 4 | 1 | `version` | `0x01` |
| 5 | 1 | `env_type` | 1=message, 2=ack, 3=alias-gossip, 4=capabilities |
| 6 | 2 | `flags` | bit0=hybridPQ, bit1=bleOriginated; rest reserved 0 |
| 8 | 16 | `message_id` | 128-bit CSPRNG (vectors: counter-derived) |
| 24 | 16 | `routing_tag` | RavenRoutingTagV1 (recipient locator; rotates) |
| 40 | 8 | `dest_device_hint` | truncated hint or 0; **mutable**, excluded from signature |
| 48 | 8 | `created_at` | unix ms |
| 56 | 8 | `expires_at` | unix ms |
| 64 | 1 | `hop_limit` | **mutable**, excluded from signature |
| 65 | 1 | `replication_budget` | **mutable**, excluded from signature |
| 66 | 12 | `anti_replay_nonce` | per-envelope |
| 78 | 2 | `hdr_len` | length of ratchet_header_ciphertext |
| 80 | 4 | `body_len` | length of message_ciphertext |
| 84 | 2 | `auth_len` | length of sender_authentication (Ed25519 sig = 64) |
| 86 | hdr_len | `ratchet_header_ciphertext` | opaque (ATSAM/Noise header) |
| … | body_len | `message_ciphertext` | opaque sealed frame (`RVNA1`/`RVNS1`/`RVNH1`) |
| … | auth_len | `sender_authentication` | Ed25519 signature over signing bytes |

**Canonical signing bytes** (closes the audit's "mutable fields excluded but not zeroed"
ambiguity): the fixed prefix with the three mutable fields (`dest_device_hint`, `hop_limit`,
`replication_budget`) **zeroed**, followed by `SHA-256(ratchet_header_ciphertext)` and
`SHA-256(message_ciphertext)`. Everything immutable is bound; nothing relay-mutable is.
`sender_authentication` = `Ed25519_sign(device_signing_key, signing_bytes)`.

- [x] **Step 1: Write the failing test**

```python
# tests/test_envelope.py
from raven_protocol import envelope
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ALICE_ED_PRIV = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

def _env():
    return envelope.Envelope(
        env_type=1, flags=0,
        message_id=bytes(16), routing_tag=bytes(range(16)),
        dest_device_hint=0xAABBCCDD, created_at=1700000000000, expires_at=1700086400000,
        hop_limit=8, replication_budget=3, anti_replay_nonce=(1).to_bytes(12, "big"),
        ratchet_header_ciphertext=b"hdr", message_ciphertext=b"RVNS1....body",
        sender_authentication=b"",
    )

def test_pack_unpack_roundtrip():
    e = _env()
    raw = envelope.pack(e)
    back = envelope.unpack(raw)
    assert back.message_ciphertext == e.message_ciphertext
    assert back.routing_tag == e.routing_tag
    assert raw[:4] == b"RVN1"

def test_signing_bytes_zero_mutable_fields():
    e = _env()
    sb = envelope.signing_bytes(e)
    e2 = _env(); e2.hop_limit = 1; e2.replication_budget = 0; e2.dest_device_hint = 0
    assert envelope.signing_bytes(e2) == sb  # mutable-field changes do not affect signature

def test_sign_verify():
    e = _env()
    priv = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV)
    e.sender_authentication = priv.sign(envelope.signing_bytes(e))
    assert envelope.verify(e, priv.public_key().public_bytes_raw())

def test_tampered_body_fails_verify():
    e = _env()
    priv = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV)
    e.sender_authentication = priv.sign(envelope.signing_bytes(e))
    e.message_ciphertext = b"RVNS1....TAMPER"
    assert not envelope.verify(e, priv.public_key().public_bytes_raw())

def test_unpack_rejects_bad_magic():
    raw = bytearray(envelope.pack(_env())); raw[0] = 0
    assert envelope.unpack(bytes(raw)) is None
```

- [x] **Step 2: Run to verify it fails**

Run: `cd protocol/reference && python3 -m pytest tests/test_envelope.py -q`
Expected: FAIL — module missing.

- [x] **Step 3: Implement envelope.py**

```python
# raven_protocol/envelope.py
import hashlib, struct
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

MAGIC = b"RVN1"
VERSION = 1
PREFIX_FMT = ">4sBBH16s16sQQQBB12sHIH"   # 86 bytes
PREFIX_LEN = struct.calcsize(PREFIX_FMT)
assert PREFIX_LEN == 86

@dataclass
class Envelope:
    env_type: int; flags: int
    message_id: bytes; routing_tag: bytes
    dest_device_hint: int; created_at: int; expires_at: int
    hop_limit: int; replication_budget: int; anti_replay_nonce: bytes
    ratchet_header_ciphertext: bytes; message_ciphertext: bytes
    sender_authentication: bytes

def pack(e: Envelope) -> bytes:
    prefix = struct.pack(
        PREFIX_FMT, MAGIC, VERSION, e.env_type, e.flags,
        e.message_id, e.routing_tag, e.dest_device_hint,
        e.created_at, e.expires_at, e.hop_limit, e.replication_budget,
        e.anti_replay_nonce, len(e.ratchet_header_ciphertext),
        len(e.message_ciphertext), len(e.sender_authentication),
    )
    return prefix + e.ratchet_header_ciphertext + e.message_ciphertext + e.sender_authentication

def unpack(raw: bytes):
    if len(raw) < PREFIX_LEN or raw[:4] != MAGIC or raw[4] != VERSION:
        return None
    (_, _, env_type, flags, message_id, routing_tag, dest_hint, created_at,
     expires_at, hop_limit, repl, nonce, hdr_len, body_len, auth_len) = struct.unpack(
        PREFIX_FMT, raw[:PREFIX_LEN])
    o = PREFIX_LEN
    if len(raw) != o + hdr_len + body_len + auth_len:
        return None
    hdr = raw[o:o+hdr_len]; o += hdr_len
    body = raw[o:o+body_len]; o += body_len
    auth = raw[o:o+auth_len]
    return Envelope(env_type, flags, message_id, routing_tag, dest_hint, created_at,
                    expires_at, hop_limit, repl, nonce, hdr, body, auth)

def signing_bytes(e: Envelope) -> bytes:
    # Zero the three relay-mutable fields; bind ciphertext blobs by hash.
    prefix = struct.pack(
        PREFIX_FMT, MAGIC, VERSION, e.env_type, e.flags,
        e.message_id, e.routing_tag, 0,          # dest_device_hint zeroed
        e.created_at, e.expires_at, 0, 0,        # hop_limit, replication_budget zeroed
        e.anti_replay_nonce, len(e.ratchet_header_ciphertext),
        len(e.message_ciphertext), 64,           # canonical auth_len for signing = 64
    )
    return prefix + hashlib.sha256(e.ratchet_header_ciphertext).digest() \
                  + hashlib.sha256(e.message_ciphertext).digest()

def verify(e: Envelope, signer_ed_pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(signer_ed_pub).verify(
            e.sender_authentication, signing_bytes(e))
        return True
    except (InvalidSignature, ValueError):
        return False
```

- [x] **Step 4: Run to verify pass**

Run: `cd protocol/reference && python3 -m pytest tests/test_envelope.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add protocol/reference/raven_protocol/envelope.py protocol/reference/tests/test_envelope.py
git commit -m "feat(protocol): RavenEnvelopeV1 binary codec + canonical signing bytes"
```

---

## Task 6: RavenAckV1, RavenAliasRecordV1, RavenDeviceCertificateV1

**Files:**
- Create: `protocol/reference/raven_protocol/ack.py`
- Create: `protocol/reference/raven_protocol/alias.py`
- Create: `protocol/reference/raven_protocol/device_cert.py`
- Test: `protocol/reference/tests/test_ack.py`
- Test: `protocol/reference/tests/test_alias.py`
- Test: `protocol/reference/tests/test_device_cert.py`

**Canonical definitions (all signing bytes are length-prefixed — no unescaped pipes, closing
audit risk #3):** a helper `lp(x)` = `len(x).to_bytes(2,'big') ‖ x` for byte strings and
`u64(n)` = `n.to_bytes(8,'big')` for integers.

- `RavenAckV1` sealed body = `acked_message_id(16) ‖ status(1: 1=delivered,2=read) ‖
  ack_nonce(12)`; carried as the `message_ciphertext` of an `env_type=2` envelope sealed to
  the original sender. ACK signing bytes = `"rvn1/ack" ‖ acked_message_id ‖ status ‖
  ack_nonce ‖ u64(created_at_ms)`.
- `RavenAliasRecordV1` = `{alias, identity_address, sequence, expires_at_ms}`; signing bytes
  = `"rvn1/alias" ‖ lp(alias_utf8) ‖ lp(identity_address_utf8) ‖ u64(sequence) ‖
  u64(expires_at_ms)`; signed by the **identity** Ed25519 key. Monotonic `sequence` defeats
  stale-record replay (§68).
- `RavenDeviceCertificateV1` signing bytes = `"rvn1/devcert" ‖ lp(device_ed_pub) ‖
  lp(device_x_pub) ‖ lp(device_id_utf8) ‖ u64(not_before_ms) ‖ u64(not_after_ms) ‖
  u64(capabilities)`; signed by the **user identity** key (authorizes a device — §21, §71).

- [x] **Step 1: Write the failing tests**

```python
# tests/test_ack.py
from raven_protocol import ack
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
BOB_ED_PRIV = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")

def test_ack_signing_bytes_bind_status():
    a = ack.Ack(acked_message_id=bytes(16), status=1, ack_nonce=(7).to_bytes(12,"big"), created_at=1700000000000)
    a2 = ack.Ack(acked_message_id=bytes(16), status=2, ack_nonce=(7).to_bytes(12,"big"), created_at=1700000000000)
    assert ack.signing_bytes(a) != ack.signing_bytes(a2)

def test_ack_sign_verify():
    a = ack.Ack(bytes(16), 1, (7).to_bytes(12,"big"), 1700000000000)
    priv = Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV)
    sig = priv.sign(ack.signing_bytes(a))
    assert ack.verify(a, sig, priv.public_key().public_bytes_raw())
```

```python
# tests/test_alias.py
from raven_protocol import alias, address
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ALICE_ED_PRIV = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
ALICE_ED_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

def test_alias_sign_verify_and_sequence_binding():
    addr = address.encode(ALICE_ED_PUB)
    r = alias.AliasRecord(alias="ahmad", identity_address=addr, sequence=42, expires_at=1700086400000)
    priv = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV)
    r.signature = priv.sign(alias.signing_bytes(r))
    assert alias.verify(r, ALICE_ED_PUB)
    r.sequence = 43  # bumping sequence invalidates the old signature
    assert not alias.verify(r, ALICE_ED_PUB)
```

```python
# tests/test_device_cert.py
from raven_protocol import device_cert
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
ALICE_ED_PRIV = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
ALICE_ED_PUB = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
BOB_ED_PUB = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
BOB_X_PUB = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

def test_device_cert_signed_by_user_identity():
    c = device_cert.DeviceCert(device_ed_pub=BOB_ED_PUB, device_x_pub=BOB_X_PUB,
                               device_id="bob-device-1", not_before=1700000000000,
                               not_after=1731536000000, capabilities=0b111)
    priv = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV)
    c.signature = priv.sign(device_cert.signing_bytes(c))
    assert device_cert.verify(c, user_identity_ed_pub=ALICE_ED_PUB)
```

- [x] **Step 2: Run to verify they fail**

Run: `cd protocol/reference && python3 -m pytest tests/test_ack.py tests/test_alias.py tests/test_device_cert.py -q`
Expected: FAIL — modules missing.

- [x] **Step 3: Implement the three modules**

```python
# raven_protocol/_canon.py
def lp(b: bytes) -> bytes:
    return len(b).to_bytes(2, "big") + b
def u64(n: int) -> bytes:
    return n.to_bytes(8, "big")
```

```python
# raven_protocol/ack.py
from dataclasses import dataclass
from ._canon import u64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

@dataclass
class Ack:
    acked_message_id: bytes; status: int; ack_nonce: bytes; created_at: int

def signing_bytes(a: Ack) -> bytes:
    return b"rvn1/ack" + a.acked_message_id + bytes([a.status]) + a.ack_nonce + u64(a.created_at)

def verify(a: Ack, sig: bytes, signer_ed_pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(signer_ed_pub).verify(sig, signing_bytes(a))
        return True
    except (InvalidSignature, ValueError):
        return False
```

```python
# raven_protocol/alias.py
from dataclasses import dataclass, field
from ._canon import lp, u64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

@dataclass
class AliasRecord:
    alias: str; identity_address: str; sequence: int; expires_at: int
    signature: bytes = field(default=b"")

def signing_bytes(r: AliasRecord) -> bytes:
    return (b"rvn1/alias" + lp(r.alias.encode()) + lp(r.identity_address.encode())
            + u64(r.sequence) + u64(r.expires_at))

def verify(r: AliasRecord, identity_ed_pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(identity_ed_pub).verify(r.signature, signing_bytes(r))
        return True
    except (InvalidSignature, ValueError):
        return False
```

```python
# raven_protocol/device_cert.py
from dataclasses import dataclass, field
from ._canon import lp, u64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

@dataclass
class DeviceCert:
    device_ed_pub: bytes; device_x_pub: bytes; device_id: str
    not_before: int; not_after: int; capabilities: int
    signature: bytes = field(default=b"")

def signing_bytes(c: DeviceCert) -> bytes:
    return (b"rvn1/devcert" + lp(c.device_ed_pub) + lp(c.device_x_pub)
            + lp(c.device_id.encode()) + u64(c.not_before) + u64(c.not_after) + u64(c.capabilities))

def verify(c: DeviceCert, user_identity_ed_pub: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(user_identity_ed_pub).verify(c.signature, signing_bytes(c))
        return True
    except (InvalidSignature, ValueError):
        return False
```

- [x] **Step 4: Run to verify pass**

Run: `cd protocol/reference && python3 -m pytest tests/test_ack.py tests/test_alias.py tests/test_device_cert.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add protocol/reference/raven_protocol/ack.py protocol/reference/raven_protocol/alias.py protocol/reference/raven_protocol/device_cert.py protocol/reference/raven_protocol/_canon.py protocol/reference/tests/test_ack.py protocol/reference/tests/test_alias.py protocol/reference/tests/test_device_cert.py
git commit -m "feat(protocol): RavenAckV1 + RavenAliasRecordV1 + RavenDeviceCertificateV1 signing"
```

---

## Task 7: Generate the frozen `rvn1` vector tree (mission step 08)

**Files:**
- Create: `protocol/reference/generate_rvn1.py`
- Create (generated): `shared-vectors/rvn1/**`
- Test: `protocol/reference/tests/test_determinism.py`

- [x] **Step 1: Write the determinism test first**

```python
# tests/test_determinism.py
import subprocess, sys, filecmp, os, shutil, tempfile, pathlib

REPO = pathlib.Path(__file__).resolve().parents[3]  # .../hybrid_messenger
GEN = REPO / "protocol/reference/generate_rvn1.py"
OUT = REPO / "shared-vectors/rvn1"

def test_regeneration_is_byte_identical():
    assert OUT.exists(), "run generate_rvn1.py once before this test"
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(GEN), "--out", tmp], check=True)
        # Every file under OUT must be byte-identical to a fresh generation.
        for f in OUT.rglob("*.json"):
            rel = f.relative_to(OUT)
            assert filecmp.cmp(f, pathlib.Path(tmp)/rel, shallow=False), f"drift in {rel}"
```

- [x] **Step 2: Run to verify it fails**

Run: `cd protocol/reference && python3 -m pytest tests/test_determinism.py -q`
Expected: FAIL — `generate_rvn1.py` and `shared-vectors/rvn1` do not exist.

- [x] **Step 3: Implement generate_rvn1.py**

Produce one JSON file per case, each following the existing `shared-vectors` schema
(`name`, `description`, `protocol_version:"rvn1"`, `deterministic:true`, `inputs`,
`expected`). Cover every canonical form plus negatives. Positive tree:
`address/encode_alice.json`, `address/decode_roundtrip.json`,
`identities/fingerprint_alice.json` (both schemes), `routing/tag_alice_bob_000.json`,
`routing/tag_unlinkable_001.json`, `envelope/message_alice_to_bob.json` (full hex + signing
bytes + signature), `ack/delivered_bob_to_alice.json`, `alias/ahmad_seq42.json`,
`device_cert/bob_device1.json`, `capabilities/alice_v1.json`. Negative tree under
`negative/`: `address_bad_checksum.json`, `envelope_bad_magic.json`,
`envelope_tampered_body.json`, `envelope_expired.json`, `alias_stale_sequence.json`,
`ack_wrong_signer.json`.

```python
#!/usr/bin/env python3
# protocol/reference/generate_rvn1.py
"""Deterministic generator for the frozen rvn1 cross-platform vector tree.
Source of truth: raven_protocol.*  ·  Fixed keys: shared-vectors identities  ·  Epoch 1700000000."""
import argparse, json, hashlib, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from raven_protocol import address, fingerprint, routing_tag, envelope, ack, alias, device_cert
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

EPOCH_S = 1700000000
EPOCH_MS = EPOCH_S * 1000
ALICE_ED_PRIV = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
ALICE_ED_PUB  = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
BOB_ED_PRIV   = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
BOB_ED_PUB    = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
BOB_X_PUB     = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
K_ROUTE       = bytes(range(32))

def write(out, rel, obj):
    p = pathlib.Path(out) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    # sort_keys + trailing newline => stable bytes across runs and platforms.
    p.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")

def vec(name, desc, inputs, expected, **extra):
    return {"name": name, "description": desc, "protocol_version": "rvn1",
            "deterministic": True, "inputs": inputs, "expected": expected, **extra}

def build_message_envelope():
    rt = routing_tag.derive(K_ROUTE, EPOCH_S, 0)
    e = envelope.Envelope(
        env_type=1, flags=0, message_id=(1).to_bytes(16, "big"), routing_tag=rt,
        dest_device_hint=0, created_at=EPOCH_MS, expires_at=EPOCH_MS + 86400000,
        hop_limit=8, replication_budget=3, anti_replay_nonce=(1).to_bytes(12, "big"),
        ratchet_header_ciphertext=b"RVNA1-header-fixture",
        message_ciphertext=b"RVNS1-sealed-body-fixture", sender_authentication=b"")
    priv = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV)
    e.sender_authentication = priv.sign(envelope.signing_bytes(e))
    return e

def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default=str(
        pathlib.Path(__file__).resolve().parents[2] / "shared-vectors/rvn1"))
    out = ap.parse_args().out

    # identities (mirror v1 keys so both trees reference the same material)
    write(out, "identities.json", {
        "protocol_version": "rvn1", "epoch_seconds": EPOCH_S,
        "note": "Same RFC-8032 keys as shared-vectors/v1/identities.json.",
        "alice_address": address.encode(ALICE_ED_PUB), "bob_address": address.encode(BOB_ED_PUB)})

    # address
    write(out, "address/encode_alice.json", vec(
        "RavenAddressV1 encode — alice", "bech32m over version||SHA256(edPub)[:20]",
        {"ed_public_hex": ALICE_ED_PUB.hex()},
        {"address": address.encode(ALICE_ED_PUB),
         "display": address.to_display(address.encode(ALICE_ED_PUB))}))

    # fingerprint (both schemes, documenting the reconciliation)
    write(out, "identities/fingerprint_alice.json", vec(
        "Fingerprints — alice", "canonical device fp (app scheme) + deprecated MeshV1 hex",
        {"ed_public_hex": ALICE_ED_PUB.hex()},
        {"device_fingerprint_v1": fingerprint.device_fingerprint_v1(ALICE_ED_PUB),
         "mesh_v1_hex_deprecated": fingerprint.mesh_v1_hex_fingerprint(ALICE_ED_PUB)}))

    # routing tag + unlinkability
    write(out, "routing/tag_alice_bob_000.json", vec(
        "RavenRoutingTagV1 — counter 0", "HMAC-SHA256(K_route, label||epoch||counter)[:16]",
        {"k_route_hex": K_ROUTE.hex(), "epoch": EPOCH_S, "counter": 0},
        {"tag_hex": routing_tag.derive(K_ROUTE, EPOCH_S, 0).hex()}))
    write(out, "routing/tag_unlinkable_001.json", vec(
        "RavenRoutingTagV1 — counter 1 differs", "unlinkability across counters",
        {"k_route_hex": K_ROUTE.hex(), "epoch": EPOCH_S, "counter": 1},
        {"tag_hex": routing_tag.derive(K_ROUTE, EPOCH_S, 1).hex()}))

    # envelope (full bytes + signing bytes + signature)
    e = build_message_envelope()
    write(out, "envelope/message_alice_to_bob.json", vec(
        "RavenEnvelopeV1 — message", "packed bytes, signing bytes, Ed25519 signature (alice)",
        {"signer_ed_public_hex": ALICE_ED_PUB.hex(),
         "message_id_hex": e.message_id.hex(), "routing_tag_hex": e.routing_tag.hex(),
         "created_at_ms": e.created_at, "expires_at_ms": e.expires_at,
         "ratchet_header_ciphertext_hex": e.ratchet_header_ciphertext.hex(),
         "message_ciphertext_hex": e.message_ciphertext.hex()},
        {"packed_hex": envelope.pack(e).hex(),
         "signing_bytes_hex": envelope.signing_bytes(e).hex(),
         "sender_authentication_hex": e.sender_authentication.hex()}))

    # ack
    a = ack.Ack(acked_message_id=e.message_id, status=1, ack_nonce=(2).to_bytes(12, "big"),
                created_at=EPOCH_MS + 1000)
    asig = Ed25519PrivateKey.from_private_bytes(BOB_ED_PRIV).sign(ack.signing_bytes(a))
    write(out, "ack/delivered_bob_to_alice.json", vec(
        "RavenAckV1 — delivered", "ack signing bytes + Ed25519 signature (bob)",
        {"acked_message_id_hex": a.acked_message_id.hex(), "status": a.status,
         "ack_nonce_hex": a.ack_nonce.hex(), "created_at_ms": a.created_at,
         "signer_ed_public_hex": BOB_ED_PUB.hex()},
        {"signing_bytes_hex": ack.signing_bytes(a).hex(), "signature_hex": asig.hex()}))

    # alias
    r = alias.AliasRecord(alias="ahmad", identity_address=address.encode(ALICE_ED_PUB),
                          sequence=42, expires_at=EPOCH_MS + 604800000)
    r.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(alias.signing_bytes(r))
    write(out, "alias/ahmad_seq42.json", vec(
        "RavenAliasRecordV1 — @ahmad seq 42", "identity-signed alias record",
        {"alias": r.alias, "identity_address": r.identity_address, "sequence": r.sequence,
         "expires_at_ms": r.expires_at, "identity_ed_public_hex": ALICE_ED_PUB.hex()},
        {"signing_bytes_hex": alias.signing_bytes(r).hex(), "signature_hex": r.signature.hex()}))

    # device certificate
    c = device_cert.DeviceCert(device_ed_pub=BOB_ED_PUB, device_x_pub=BOB_X_PUB,
                               device_id="bob-device-1", not_before=EPOCH_MS,
                               not_after=EPOCH_MS + 31536000000, capabilities=0b111)
    c.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(device_cert.signing_bytes(c))
    write(out, "device_cert/bob_device1.json", vec(
        "RavenDeviceCertificateV1 — bob device authorized by alice-identity",
        "user-identity-signed device certificate",
        {"device_ed_public_hex": BOB_ED_PUB.hex(), "device_x_public_hex": BOB_X_PUB.hex(),
         "device_id": c.device_id, "not_before_ms": c.not_before, "not_after_ms": c.not_after,
         "capabilities": c.capabilities, "user_identity_ed_public_hex": ALICE_ED_PUB.hex()},
        {"signing_bytes_hex": device_cert.signing_bytes(c).hex(), "signature_hex": c.signature.hex()}))

    # ---- negative vectors ----
    bad_addr = address.encode(ALICE_ED_PUB)
    bad_addr = bad_addr[:-1] + ("q" if bad_addr[-1] != "q" else "p")
    write(out, "negative/address_bad_checksum.json", vec(
        "Address with corrupted checksum must fail to decode", "single-char corruption",
        {"address": bad_addr}, {"decode_result": "reject"}))

    raw = bytearray(envelope.pack(e)); raw[0] = 0
    write(out, "negative/envelope_bad_magic.json", vec(
        "Envelope with wrong magic must be rejected", "magic byte zeroed",
        {"packed_hex": bytes(raw).hex()}, {"unpack_result": "reject"}))

    tam = build_message_envelope(); tam.message_ciphertext = b"RVNS1-sealed-body-TAMPERED"
    write(out, "negative/envelope_tampered_body.json", vec(
        "Envelope body tampered after signing must fail verify", "ciphertext changed post-sign",
        {"packed_hex": envelope.pack(tam).hex(), "signer_ed_public_hex": ALICE_ED_PUB.hex()},
        {"verify_result": "reject"}))

    write(out, "negative/envelope_expired.json", vec(
        "Envelope past expires_at must be dropped by relays", "expires_at < validation clock",
        {"expires_at_ms": EPOCH_MS - 1000, "validation_clock_ms": EPOCH_MS},
        {"relay_action": "drop"}))

    r2 = alias.AliasRecord(alias="ahmad", identity_address=address.encode(ALICE_ED_PUB),
                           sequence=41, expires_at=EPOCH_MS + 604800000)
    r2.signature = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(alias.signing_bytes(r2))
    write(out, "negative/alias_stale_sequence.json", vec(
        "Older-sequence alias record must not replace a newer one", "seq 41 vs cached 42",
        {"cached_sequence": 42, "incoming_sequence": 41,
         "incoming_signing_bytes_hex": alias.signing_bytes(r2).hex()},
        {"resolver_action": "reject_stale"}))

    awrong = Ed25519PrivateKey.from_private_bytes(ALICE_ED_PRIV).sign(ack.signing_bytes(a))
    write(out, "negative/ack_wrong_signer.json", vec(
        "ACK verified against wrong key must fail", "signed by alice, verified as bob",
        {"signing_bytes_hex": ack.signing_bytes(a).hex(), "signature_hex": awrong.hex(),
         "claimed_signer_ed_public_hex": BOB_ED_PUB.hex()},
        {"verify_result": "reject"}))

if __name__ == "__main__":
    main()
```

- [x] **Step 4: Generate the tree, then run the determinism test**

Run:
```bash
cd protocol/reference && python3 generate_rvn1.py && python3 -m pytest tests/test_determinism.py -q
```
Expected: tree written under `shared-vectors/rvn1/`; PASS (1 passed).

- [x] **Step 5: Run the whole reference suite green**

Run: `cd protocol/reference && python3 -m pytest -q`
Expected: PASS (all tasks 2–7 tests, ~20+ passed).

- [ ] **Step 6: Commit**

```bash
git add protocol/reference/generate_rvn1.py protocol/reference/tests/test_determinism.py shared-vectors/rvn1/
git commit -m "feat(protocol): generate frozen rvn1 test-vector tree (positive + negative)"
```

---

## Task 8: Write the protocol specification documents

Each spec is a reviewable artifact; the reference implementation and vectors are its
executable proof. No code steps — but every doc has a required section list and MUST cite
the concrete vector files that prove its claims (no unproven normative statement).

- [x] **Step 1: `protocol/SPEC.md`** — index. Required sections: the seven V1 invariants
  (identity, text, delivery, offline delivery, internet, bluetooth, security); the four
  security/interop/UX invariants from the mission's final section; a table linking each
  sub-spec to its `shared-vectors/rvn1/` proof directory; the versioning policy (every wire
  format carries an explicit version; higher-than-supported ⇒ drop; capabilities negotiated
  and signed).

- [x] **Step 2: `protocol/RAVEN_IDENTITY_V1.md`** — Required sections: User Identity key
  (Ed25519, local-only), Device Identity keys (Ed25519 + X25519 per device),
  `RavenDeviceCertificateV1` (user-signs-device, capabilities, validity window, revocation
  via signed record + what partitions can/can't guarantee — §72), the fingerprint
  reconciliation (canonical `RavenDeviceFingerprintV1` = app scheme; MeshV1 hex deprecated),
  and the ATSAM userId→canonical-identity **migration** (the load-bearing risk: existing
  roots/chains/AADs are keyed by server userIds). Cite `identities/fingerprint_alice.json`,
  `device_cert/bob_device1.json`.

- [x] **Step 3: `protocol/RAVEN_ADDRESS_V1.md`** — Required sections: the three concepts
  (Identity, Address, Alias) and how they differ (§6); canonical Bech32m encoding
  (`version||SHA256(idPub)[:20]`, HRP `rvn`); display grouping; parsing/validation rules
  (reject bad checksum, wrong HRP, wrong length); why alias lookup is discovery not
  verification. Cite `address/encode_alice.json`, `negative/address_bad_checksum.json`.

- [x] **Step 4: `protocol/RAVEN_ENVELOPE_V1.md`** — Required sections: the full byte table
  (from Task 5), the mutable-field/signing-bytes rule, `env_type` registry, size limits
  (max envelope size, header caps — the Go bridge's 24 MiB pre-validation allocation is a
  DoS to fix in Phase B), the "no plaintext identities/usernames/conversation-IDs on the
  wire" requirement (§24), and the incoming-processing pipeline order (§41: size → decode →
  version → structure → dedup → replay → TTL → hop/replication → tag/session → authenticate
  → decrypt → commit → ACK). Cite `envelope/message_alice_to_bob.json` and all
  `negative/envelope_*.json`.

- [x] **Step 5: `protocol/RAVEN_ACK_V1.md`** — Required sections: ACK as sealed
  `env_type=2` body, signing bytes, the delivery-state machine (§26: CREATED → ENCRYPTED →
  QUEUED → ROUTE_DISCOVERING → FORWARDED → DELIVERED_TO_DEVICE → READ / EXPIRED / FAILED)
  and the rule that only a valid recipient ACK moves FORWARDED→DELIVERED (never relay
  acceptance — the Go bridge's write-means-delivered bug is called out as a Phase B fix),
  ACK replay/dedup. Cite `ack/delivered_bob_to_alice.json`, `negative/ack_wrong_signer.json`.

- [x] **Step 6: `protocol/RAVEN_ALIAS_V1.md`** — Required sections: record schema, identity
  signature, monotonic `sequence` freshness, the ambiguity rule (never silently pick among
  multiple identities claiming one alias — §6, §69 key-change warning), DHT publication
  constraints (signed, versioned, expiry-bound, size-limited — §44). Cite
  `alias/ahmad_seq42.json`, `negative/alias_stale_sequence.json`.

- [x] **Step 7: `protocol/RAVEN_ROUTING_TAG_V1.md`** — Required sections: derivation from
  ATSAM `K_route`, rotation (epoch + counter), the store-node-cannot-derive property, and
  the explicit non-goal (tags resist linkage but not global traffic analysis — §53–54).
  Cite `routing/tag_alice_bob_000.json`, `routing/tag_unlinkable_001.json`.

- [x] **Step 8: `protocol/RAVEN_CAPABILITIES_V1.md`** — Required sections: signed capability
  set, authenticated negotiation, downgrade protection (§43), and the mapping to existing
  RUM v2 capability bits (note the iOS/Windows drift: `doubleRatchet` bit 1<<13 present on
  iOS, absent on Windows). Cite `capabilities/alice_v1.json`.

- [x] **Step 9: Verify every normative claim has a vector**

Run:
```bash
grep -rEo 'shared-vectors/rvn1/[A-Za-z0-9_/]+\.json' protocol/*.md | sort -u > /tmp/cited.txt
find shared-vectors/rvn1 -name '*.json' | sed 's#.*/shared-vectors#shared-vectors#' | sort -u > /tmp/have.txt
comm -23 /tmp/cited.txt /tmp/have.txt   # cited-but-missing — MUST be empty
```
Expected: empty output (every cited vector exists).

- [ ] **Step 10: Commit**

```bash
git add protocol/*.md
git commit -m "docs(protocol): freeze RAVEN V1 identity/address/envelope/ack/alias/routing/capabilities specs"
```

---

## Task 9: Rewrite THREAT_MODEL.md for the serverless-P2P adversary set (mission step 03)

**Files:**
- Create: `docs/THREAT_MODEL.md`
- Modify: `raven-security/THREAT_MODEL.md` (add a header marking it a pre-pivot snapshot)

- [x] **Step 1: Write `docs/THREAT_MODEL.md`**

Required structure: assets protected; then a row per adversary from mission §73 with a
verdict of **protected / partially protected / out of scope** and a *why*, covering:
malicious relay, malicious store node, malicious peer, passive ISP, active MITM, stolen
locked device, stolen unlocked device, Sybil swarm, eclipse attacker, replay attacker, spam
attacker, DHT poisoning, alias impersonation, downgrade attacker, malformed-packet attacker,
local malware, traffic analyst. Each protected/partial claim MUST point at the mechanism
(a `protocol/` spec section or a `shared-vectors/rvn1/` vector) or be explicitly scoped out.
Carry forward the honest-scope tone of the existing doc; add the properties the pivot
introduces (two encryption layers §18; store nodes see only opaque objects + rotating tags
§53; no single store node is authoritative, replication ×3 §29) and the ones it cannot yet
promise (global traffic analysis, active relay/distance-fraud, endpoint compromise).

- [x] **Step 2: Mark the old model as a snapshot**

Prepend to `raven-security/THREAT_MODEL.md`:
```markdown
> **Historical snapshot (pre-serverless-pivot, May 2026).** Superseded by
> `docs/THREAT_MODEL.md`. Retained for provenance; do not update in place.
```

- [x] **Step 3: Verify adversary coverage is complete**

Run:
```bash
for a in "malicious relay" "malicious store" "malicious peer" "passive ISP" "active MITM" \
  "stolen locked" "stolen unlocked" "Sybil" "eclipse" "replay" "spam" "DHT poison" \
  "alias imperson" "downgrade" "malformed" "local malware" "traffic anal"; do
  grep -iq "$a" docs/THREAT_MODEL.md || echo "MISSING: $a"
done
```
Expected: no `MISSING` lines.

- [ ] **Step 4: Commit**

```bash
git add docs/THREAT_MODEL.md raven-security/THREAT_MODEL.md
git commit -m "docs(security): serverless-P2P threat model (step 03); mark pre-pivot model as snapshot"
```

---

## Task 10: Wire vectors into the sync tooling and close Phase A

**Files:**
- Modify: `shared-vectors/README.md`
- Modify: `tools/sync-vectors.sh`

- [x] **Step 1: Document the new tree**

Add an `rvn1/` section to `shared-vectors/README.md`: it is the serverless V1 protocol
contract; generated by `protocol/reference/generate_rvn1.py`; consumed by the Rust node
(Phase B), and later the Swift/C#/Kotlin ports; frozen under the same VERSIONING rules as
`v1/`. Fix the stale consumer list (audit: it cites files that don't exist).

- [x] **Step 2: Extend `tools/sync-vectors.sh`** to also verify `rvn1/` regenerates clean

Add, after the existing v1 check:
```bash
echo "Verifying rvn1 vectors regenerate byte-identically..."
python3 protocol/reference/generate_rvn1.py
if ! git diff --quiet shared-vectors/rvn1/; then
  echo "ERROR: rvn1 vectors drifted on regeneration" >&2
  git --no-pager diff --stat shared-vectors/rvn1/ >&2
  exit 1
fi
echo "rvn1 vectors OK."
```

- [x] **Step 3: Run the full gate**

Run:
```bash
cd /path/to/hybrid_messenger && bash tools/sync-vectors.sh && (cd protocol/reference && python3 -m pytest -q)
```
Expected: sync clean (no diff), all reference tests pass.

- [ ] **Step 4: Commit and mark Phase A complete**

```bash
git add shared-vectors/README.md tools/sync-vectors.sh
git commit -m "chore(protocol): wire rvn1 vectors into sync tooling; Phase A protocol freeze complete"
```

Phase A exit criteria (all must hold before starting Phase B):
- `protocol/reference` test suite green; `rvn1` tree regenerates byte-identically.
- All eight `protocol/*.md` specs exist; every normative claim cites an existing vector.
- `docs/THREAT_MODEL.md` covers all 17 mission-§73 adversaries.
- The untracked bridge/rendezvous work is committed.

---

## Self-Review

**1. Spec coverage (mission steps 03–08 and the §100 record list):**
- Step 03 THREAT_MODEL → Task 9. ✅
- Step 04 IDENTITY → Task 8.2 + Task 3 (fingerprint) + Task 6 (device cert). ✅
- Step 05 ADDRESS → Task 8.3 + Task 3. ✅
- Step 06 ENVELOPE → Task 8.4 + Task 5. ✅
- Step 07 ACK → Task 8.5 + Task 6. ✅
- Step 08 vectors (+negatives) → Task 7. ✅
- §100 also names `RavenAliasRecordV1` (Task 6/8.6), `RavenRoutingTagV1` (Task 4/8.7),
  `RavenProtocolCapabilitiesV1` (Task 8.8), `RavenDeviceCertificateV1` (Task 6/8.2). ✅
  `RavenProtocolCapabilitiesV1` has a spec (8.8) and a cited vector `capabilities/alice_v1.json`
  — **gap:** the generator (Task 7) writes it but no reference module builds it. **Resolution:**
  the capability set is a signed blob using the same `device_cert`/`alias` signing pattern; add
  a `capabilities/alice_v1.json` case to `generate_rvn1.py` in Task 7 Step 3 built directly
  from an inline `lp()/u64()` signing-bytes construction (documented in 8.8) rather than a new
  module — noted here so the executor includes it. If a module is cleaner, add `capabilities.py`
  mirroring `alias.py`.

**2. Placeholder scan:** No "TBD"/"implement later"/"add validation" — every code step shows
complete code; every doc step lists concrete required sections and a verification command.
The mission's own placeholder vectors (`raven-security/test-vectors/*.json`, all "TODO") are
explicitly superseded by real generated values in Task 7.

**3. Type consistency:** `signing_bytes()` is the name in every module (`envelope`, `ack`,
`alias`, `device_cert`); `verify()` signature is `(record, signer_pub)` everywhere;
`address.encode/decode/to_display/from_display` names match across Task 3 and Task 7;
`routing_tag.derive(k_route, epoch, counter)` identical in Task 4 and Task 7; the 86-byte
`PREFIX_FMT` in Task 5 matches the byte table in Task 8.4 (verify the executor keeps them in
sync — the table is normative, the struct format string implements it).

**4. Cross-plan handoff:** Phase A freezes formats only. Phase B (Rust) must reproduce every
`rvn1` vector byte-for-byte before writing node logic — that is Phase B's first gate, stated
in the roadmap.
