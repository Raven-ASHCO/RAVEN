"""Generate `shared-vectors/v1/` JSON fixtures from MESH_PROTOCOL.md.

Output is deterministic: fixed keys, fixed timestamps, fixed nonces. Re-running
this script must produce byte-identical files (no `"now"`, no random).

Run from the monorepo root::

    python3 shared-vectors/generate_v1.py

It also writes the DRAFT ``shared-vectors/v2/`` signing-input vectors
(``docs/MESH_PROTOCOL_v2.md``, the fix for MESH_PROTOCOL.md §I.13). ``v1/`` is
frozen: the v1 functions below reproduce the shipped (flawed) v1 bytes on
purpose and must never be "fixed" in place.

The values here are the SOURCE OF TRUTH for every RAVEN client. iOS, Mac,
Windows, Android, Watch — all consume these JSON files as test fixtures.

Conventions (matching `docs/android/SHARED_VECTORS_REQUEST.md`):
- Hex everywhere for binary fields, lowercase, no `0x` prefix.
- Base64 alt encoding for fields that are base64 on the wire.
- Fixed test keys (RFC 8032 / RFC 7748 style — no random ops).
- Fixed timestamp: ``ts = 1700000000`` (= 2023-11-14T22:13:20Z UTC).
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

ROOT = Path(__file__).parent / "v1"
ROOT.mkdir(parents=True, exist_ok=True)

FIXED_TS_SECONDS = 1_700_000_000  # 2023-11-14T22:13:20Z
FIXED_NOW_ISO = "2026-05-15T00:00:00Z"

# ----- helpers ------------------------------------------------------------

def hx(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")

def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def write_vector(rel_path: str, body: dict) -> None:
    path = ROOT / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(body, indent=2, sort_keys=False, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")
    print(f"wrote {rel_path}")

def vector(name: str, description: str, spec_reference: str,
           inputs: dict, expected: dict, notes: str | None = None) -> dict:
    body = {
        "name": name,
        "description": description,
        "protocol_version": "v1",
        "spec_reference": spec_reference,
        "created_at": FIXED_NOW_ISO,
        "deterministic": True,
        "inputs": inputs,
        "expected": expected,
    }
    if notes is not None:
        body["notes"] = notes
    return body

# ----- canonical identities ----------------------------------------------

def ed25519_from_seed(seed_hex: str) -> tuple[bytes, bytes]:
    seed = bytes.fromhex(seed_hex)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, pub

def x25519_from_seed(seed_hex: str) -> tuple[bytes, bytes]:
    seed = bytes.fromhex(seed_hex)
    priv = X25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, pub

# §D — Fingerprint formula: take SHA-256(ed25519_pub), take first 6 bytes (12 hex chars),
# group with hyphens: XXXX-XXXX-XXXX (uppercase).
def fingerprint(ed_pub: bytes) -> str:
    digest = hashlib.sha256(ed_pub).digest()
    hexed = binascii.hexlify(digest[:6]).decode("ascii").upper()
    return f"{hexed[0:4]}-{hexed[4:8]}-{hexed[8:12]}"

IDENTITIES = {
    "alice": {
        "ed_seed": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",  # RFC 8032 test 1
        "x_seed":  "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",  # RFC 7748 alice
    },
    "bob": {
        "ed_seed": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",  # RFC 8032 test 2
        "x_seed":  "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",  # RFC 7748 bob
    },
    "carol": {
        "ed_seed": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",  # RFC 8032 test 3
        "x_seed":  "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    },
    "dave": {
        "ed_seed": "0d4a05b07352a5436e180356da0ae6efa0345ff7fb1572575772e8005ed978e9",  # RFC 8032 test
        "x_seed":  "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321",
    },
}

resolved = {}
for name, seeds in IDENTITIES.items():
    ed_seed, ed_pub = ed25519_from_seed(seeds["ed_seed"])
    x_seed, x_pub = x25519_from_seed(seeds["x_seed"])
    resolved[name] = {
        "ed_private_hex": seeds["ed_seed"],
        "ed_public_hex": hx(ed_pub),
        "ed_public_b64": b64(ed_pub),
        "x_private_hex": seeds["x_seed"],
        "x_public_hex": hx(x_pub),
        "x_public_b64": b64(x_pub),
        "fingerprint": fingerprint(ed_pub),
        "device_id": f"{name}-device-1",
    }

ROOT.parent.mkdir(parents=True, exist_ok=True)
identities_path = ROOT / "identities.json"
identities_path.write_text(
    json.dumps({
        "protocol_version": "v1",
        "spec_reference": "MESH_PROTOCOL.md §D",
        "created_at": FIXED_NOW_ISO,
        "identities": resolved,
    }, indent=2) + "\n",
    encoding="utf-8",
)
print(f"wrote v1/identities.json")

ALICE = resolved["alice"]
BOB = resolved["bob"]
CAROL = resolved["carol"]
DAVE = resolved["dave"]

# ----- crypto vectors -----------------------------------------------------

# 1. Fingerprint vector — re-deriving Alice's fingerprint from her Ed25519 pub.
write_vector("crypto/fingerprint_001.json", vector(
    name="Fingerprint from Ed25519 public key — Alice",
    description="SHA-256(edPub)[:6] hex-encoded, uppercase, formatted XXXX-XXXX-XXXX.",
    spec_reference="MESH_PROTOCOL.md §D — Fingerprint",
    inputs={"ed_public_hex": ALICE["ed_public_hex"]},
    expected={"fingerprint": ALICE["fingerprint"]},
    notes="Identity 'alice' from v1/identities.json.",
))

# 2. X25519 ECDH — Alice priv × Bob pub → 32-byte shared secret.
def ecdh(priv_seed_hex: str, peer_pub_hex: str) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_seed_hex))
    peer = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_pub_hex))
    return priv.exchange(peer)

shared_ab = ecdh(ALICE["x_private_hex"], BOB["x_public_hex"])
shared_ba = ecdh(BOB["x_private_hex"], ALICE["x_public_hex"])
assert shared_ab == shared_ba

write_vector("crypto/x25519_ecdh_001.json", vector(
    name="X25519 ECDH — Alice × Bob",
    description="X25519 shared secret between Alice and Bob using their fixed test seeds.",
    spec_reference="MESH_PROTOCOL.md §D — ECDH",
    inputs={
        "self_x_private_hex": ALICE["x_private_hex"],
        "peer_x_public_hex": BOB["x_public_hex"],
    },
    expected={"shared_secret_hex": hx(shared_ab)},
    notes="Should be symmetric: (Bob priv) × (Alice pub) yields the same bytes.",
))

# 3. HKDF-SHA256 with salt "RAVEN-MESH" → 32-byte AES key.
def hkdf_mesh(secret: bytes, info: bytes = b"") -> bytes:
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b"RAVEN-MESH",
        info=info,
    ).derive(secret)

aes_key_ab = hkdf_mesh(shared_ab)

write_vector("crypto/hkdf_raven_mesh_001.json", vector(
    name="HKDF-SHA256 with RAVEN-MESH salt — Alice×Bob AES key",
    description="Derive the 32-byte AES-GCM key from the X25519 shared secret, using salt=\"RAVEN-MESH\" and empty info.",
    spec_reference="MESH_PROTOCOL.md §D — Key derivation",
    inputs={
        "shared_secret_hex": hx(shared_ab),
        "salt_utf8": "RAVEN-MESH",
        "info_hex": "",
        "length": 32,
    },
    expected={"derived_key_hex": hx(aes_key_ab)},
))

# 4. AES-256-GCM seal — fixed key + fixed nonce → combined blob nonce(12) || ct || tag(16).
def aes_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct_and_tag  # combined-blob format

def aes_open(key: bytes, combined: bytes, aad: bytes = b"") -> bytes:
    nonce, ct = combined[:12], combined[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)

fixed_nonce = bytes.fromhex("000102030405060708090a0b")
plaintext = b"hello raven mesh"
sealed = aes_seal(aes_key_ab, fixed_nonce, plaintext)

write_vector("crypto/aes_gcm_seal_001.json", vector(
    name="AES-256-GCM seal — Alice×Bob key, fixed nonce",
    description="Combined-blob seal: output = nonce(12) || ciphertext || tag(16). Empty AAD.",
    spec_reference="MESH_PROTOCOL.md §D — AEAD",
    inputs={
        "key_hex": hx(aes_key_ab),
        "nonce_hex": hx(fixed_nonce),
        "plaintext_utf8": plaintext.decode("utf-8"),
        "aad_hex": "",
    },
    expected={
        "combined_hex": hx(sealed),
        "combined_b64": b64(sealed),
    },
))

write_vector("crypto/aes_gcm_open_001.json", vector(
    name="AES-256-GCM open — Alice×Bob key, fixed combined blob",
    description="Open the previous seal: input the combined blob, get the plaintext back.",
    spec_reference="MESH_PROTOCOL.md §D — AEAD",
    inputs={
        "key_hex": hx(aes_key_ab),
        "combined_hex": hx(sealed),
        "aad_hex": "",
    },
    expected={"plaintext_utf8": plaintext.decode("utf-8")},
))

# 5. Ed25519 sign / verify — Alice signs canonical bytes.
def ed_sign(priv_seed_hex: str, message: bytes) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_seed_hex))
    return priv.sign(message)

def ed_verify(pub_hex: str, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(signature, message)
        return True
    except Exception:
        return False

msg = b"the quick brown fox"
sig = ed_sign(ALICE["ed_private_hex"], msg)
assert ed_verify(ALICE["ed_public_hex"], msg, sig)

write_vector("crypto/ed25519_sign_001.json", vector(
    name="Ed25519 sign — Alice signs \"the quick brown fox\"",
    description="Deterministic Ed25519 signature. Output is the 64-byte signature.",
    spec_reference="MESH_PROTOCOL.md §D — Identity keypairs",
    inputs={
        "private_key_hex": ALICE["ed_private_hex"],
        "public_key_hex": ALICE["ed_public_hex"],
        "message_utf8": msg.decode("utf-8"),
    },
    expected={
        "signature_hex": hx(sig),
        "signature_b64": b64(sig),
    },
))

write_vector("crypto/ed25519_verify_001.json", vector(
    name="Ed25519 verify — Alice signature on \"the quick brown fox\"",
    description="Verify Alice's signature with her public key. Also includes a negative case (tampered message).",
    spec_reference="MESH_PROTOCOL.md §D — Identity keypairs",
    inputs={
        "public_key_hex": ALICE["ed_public_hex"],
        "message_utf8": msg.decode("utf-8"),
        "signature_hex": hx(sig),
        "tampered_message_utf8": "the quick brown FOX",
    },
    expected={
        "verifies": True,
        "tampered_verifies": False,
    },
))

# 6. Key rotation attest — old priv signs (new_pub || ts as bytes per §D).
new_seed, new_pub = ed25519_from_seed(BOB["ed_private_hex"])
rotation_ts_ms = FIXED_TS_SECONDS * 1000
rotation_message = new_pub + struct.pack(">q", rotation_ts_ms)  # ed_pub(32) || int64 BE ms
rotation_sig = ed_sign(ALICE["ed_private_hex"], rotation_message)

write_vector("crypto/key_rotation_attest_001.json", vector(
    name="Key-rotation attestation — Alice signs Bob's pub at ts",
    description="Attestation message = new_ed_public(32) || timestamp_ms(int64 BE). Signed with the old private key.",
    spec_reference="MESH_PROTOCOL.md §D — Key rotation",
    inputs={
        "old_private_key_hex": ALICE["ed_private_hex"],
        "new_public_key_hex": hx(new_pub),
        "timestamp_ms": rotation_ts_ms,
    },
    expected={
        "attestation_message_hex": hx(rotation_message),
        "signature_hex": hx(rotation_sig),
    },
))

# ----- canonicalization vectors ------------------------------------------

# §D Rule 1 — DM SecureMeshEnvelope signing data. Pipe-delimited UTF-8.
# Field order matches the Kotlin DmSigningCanonicalizer:
# clientMessageId | roomId | senderId | senderName | recipientId | type | nonceB64 |
# senderPublicKeyB64 | timestampMs | originDeviceId | text | mediaUrl | thumbnailUrl |
# fileName | mimeType | fileSize | audioDurationSec | replyToMessageId |
# replyToTextPreview | replyToSenderName | (geoFence: h3Cell | radiusInCells | deliverOnlyInside)

dm_envelope_no_geo = {
    "clientMessageId": "dm-001",
    "roomId": "room:alice-bob",
    "senderId": "alice",
    "senderName": "Alice",
    "recipientId": "bob",
    "type": 0,  # TEXT
    "nonceB64": b64(bytes.fromhex("00112233445566778899aabbccddeeff")),
    "senderPublicKeyB64": ALICE["ed_public_b64"],
    "timestampMs": FIXED_TS_SECONDS * 1000,
    "originDeviceId": ALICE["device_id"],
    "text": "hello from alice",
    "mediaUrl": None,
    "thumbnailUrl": None,
    "fileName": None,
    "mimeType": None,
    "fileSize": None,
    "audioDurationSec": None,
    "replyToMessageId": None,
    "replyToTextPreview": None,
    "replyToSenderName": None,
    "geoFence": None,
}

def dm_fields(env: dict) -> list[str]:
    fields = [
        env["clientMessageId"], env["roomId"], env["senderId"], env["senderName"],
        env["recipientId"], str(env["type"]),
        env["nonceB64"], env["senderPublicKeyB64"], str(env["timestampMs"]),
        env["originDeviceId"],
        env["text"] or "",
        env["mediaUrl"] or "", env["thumbnailUrl"] or "",
        env["fileName"] or "", env["mimeType"] or "",
        str(env["fileSize"]) if env["fileSize"] is not None else "",
        str(env["audioDurationSec"]) if env["audioDurationSec"] is not None else "",
        env["replyToMessageId"] or "", env["replyToTextPreview"] or "", env["replyToSenderName"] or "",
    ]
    if env.get("geoFence"):
        g = env["geoFence"]
        fields += [g["h3Cell"], str(g["radiusInCells"]), "true" if g["deliverOnlyInside"] else "false"]
    return fields

def dm_pipe_bytes(env: dict) -> bytes:
    # v1 (frozen): bare "|" join, no escaping or length prefixes. Not
    # injective when a field contains "|" — see MESH_PROTOCOL.md §I.13.
    return "|".join(dm_fields(env)).encode("utf-8")

dm_bytes_no_geo = dm_pipe_bytes(dm_envelope_no_geo)
dm_sig_no_geo = ed_sign(ALICE["ed_private_hex"], dm_bytes_no_geo)

dm_envelope_with_geo = dict(dm_envelope_no_geo, geoFence={
    "h3Cell": "8a283082aac7fff",
    "radiusInCells": 1,
    "deliverOnlyInside": True,
})
dm_bytes_with_geo = dm_pipe_bytes(dm_envelope_with_geo)
dm_sig_with_geo = ed_sign(ALICE["ed_private_hex"], dm_bytes_with_geo)

write_vector("canonicalization/dm_pipe_001.json", vector(
    name="DM pipe-canonical signing bytes — no geo-fence",
    description="SecureMeshEnvelope.signingData() per §D Rule 1, pipe-delimited UTF-8. Mutable DTN fields (sc, hc, hl, rp, nf, ttl, ib) excluded.",
    spec_reference="MESH_PROTOCOL.md §C.1 + §D Rule 1",
    inputs={"envelope": dm_envelope_no_geo, "signer": "alice"},
    expected={
        "signing_bytes_hex": hx(dm_bytes_no_geo),
        "signing_bytes_utf8": dm_bytes_no_geo.decode("utf-8"),
        "signature_hex": hx(dm_sig_no_geo),
        "signature_b64": b64(dm_sig_no_geo),
    },
))

write_vector("canonicalization/dm_pipe_002.json", vector(
    name="DM pipe-canonical signing bytes — with geo-fence",
    description="Same as 001 but with geoFence appended (h3Cell|radiusInCells|deliverOnlyInside).",
    spec_reference="MESH_PROTOCOL.md §C.1 + §D Rule 1",
    inputs={"envelope": dm_envelope_with_geo, "signer": "alice"},
    expected={
        "signing_bytes_hex": hx(dm_bytes_with_geo),
        "signing_bytes_utf8": dm_bytes_with_geo.decode("utf-8"),
        "signature_hex": hx(dm_sig_with_geo),
        "signature_b64": b64(dm_sig_with_geo),
    },
))

# §D Rule 2 — Post pipe-canonical: "POST|postId|authorId|authorUsername|authorAvatar|text|createdAtMs|scope|signerPublicKeyB64"
post_envelope = {
    "postId": "post-001",
    "authorId": "alice",
    "authorUsername": "alice_raven",
    "authorAvatar": "https://cdn.raven.app/u/alice.png",
    "text": "first mesh post from alice",
    "createdAtSec": float(FIXED_TS_SECONDS),
    "scope": "friends",
    "signerPublicKeyB64": ALICE["ed_public_b64"],
}

def post_fields(p: dict) -> list[str]:
    return [
        "POST",
        p["postId"], p["authorId"], p["authorUsername"], p["authorAvatar"] or "",
        p["text"],
        str(int(round(p["createdAtSec"] * 1000))),
        p["scope"],
        p["signerPublicKeyB64"] or "",
    ]

def post_pipe_bytes(p: dict) -> bytes:
    return "|".join(post_fields(p)).encode("utf-8")

post_bytes = post_pipe_bytes(post_envelope)
post_sig = ed_sign(ALICE["ed_private_hex"], post_bytes)

write_vector("canonicalization/post_pipe_001.json", vector(
    name="Post pipe-canonical signing bytes",
    description="MeshPostEnvelope pipe signing per §D Rule 2.",
    spec_reference="MESH_PROTOCOL.md §C.3 + §D Rule 2",
    inputs={"post": post_envelope, "signer": "alice"},
    expected={
        "signing_bytes_hex": hx(post_bytes),
        "signing_bytes_utf8": post_bytes.decode("utf-8"),
        "signature_hex": hx(post_sig),
        "signature_b64": b64(post_sig),
    },
))

# §D Rule 4 — ACK pipe: "originalMessageId|senderId|recipientId|status|timestampMs"
ack_envelope = {
    "originalMessageId": "dm-001",
    "senderId": "bob",
    "recipientId": "alice",
    "status": "delivered",
    "timestampSec": float(FIXED_TS_SECONDS + 60),
}

def ack_fields(a: dict) -> list[str]:
    return [
        a["originalMessageId"], a["senderId"], a["recipientId"], a["status"],
        str(int(round(a["timestampSec"] * 1000))),
    ]

def ack_pipe_bytes(a: dict) -> bytes:
    return "|".join(ack_fields(a)).encode("utf-8")

ack_bytes = ack_pipe_bytes(ack_envelope)
ack_sig = ed_sign(BOB["ed_private_hex"], ack_bytes)

write_vector("canonicalization/ack_pipe_001.json", vector(
    name="ACK pipe-canonical signing bytes — delivered",
    description="MeshACKEnvelope pipe signing per §D Rule 4. Mutable fields (path, hopCount, routePath) NOT in signed bytes.",
    spec_reference="MESH_PROTOCOL.md §C.4 + §D Rule 4",
    inputs={"ack": ack_envelope, "signer": "bob"},
    expected={
        "signing_bytes_hex": hx(ack_bytes),
        "signing_bytes_utf8": ack_bytes.decode("utf-8"),
        "signature_hex": hx(ack_sig),
        "signature_b64": b64(ack_sig),
    },
))

# §D Rule 5 — Stop pipe: "STOP|messageId|timestampMs"
stop_command = {
    "messageId": "dm-001",
    "timestampSec": float(FIXED_TS_SECONDS + 120),
}

def stop_fields(s: dict) -> list[str]:
    return [
        "STOP", s["messageId"],
        str(int(round(s["timestampSec"] * 1000))),
    ]

def stop_pipe_bytes(s: dict) -> bytes:
    return "|".join(stop_fields(s)).encode("utf-8")

stop_bytes = stop_pipe_bytes(stop_command)
stop_sig = ed_sign(ALICE["ed_private_hex"], stop_bytes)

write_vector("canonicalization/stop_pipe_001.json", vector(
    name="Stop pipe-canonical signing bytes",
    description="StopCommand pipe signing per §D Rule 5.",
    spec_reference="MESH_PROTOCOL.md §C.5 + §D Rule 5",
    inputs={"stop": stop_command, "signer": "alice"},
    expected={
        "signing_bytes_hex": hx(stop_bytes),
        "signing_bytes_utf8": stop_bytes.decode("utf-8"),
        "signature_hex": hx(stop_sig),
        "signature_b64": b64(stop_sig),
    },
))

# §D Rule 3 — Feature-frame JSON-canonical: drop `s` and `spk`, re-serialize with sorted keys.
def sorted_json_canonical(value):
    if isinstance(value, dict):
        keys = sorted(value.keys())
        inner = ",".join(f"{json.dumps(k)}:{sorted_json_canonical(value[k])}" for k in keys)
        return "{" + inner + "}"
    if isinstance(value, list):
        return "[" + ",".join(sorted_json_canonical(v) for v in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

raw_frame = {
    "mk": "raven.example.v1",
    "p": {"x": 1, "y": "hello"},
    "sid": ALICE["device_id"],
    "mid": "frame-001",
    "hc": 0,
    "hl": 10,
    "sc": 5,
    "ts": FIXED_TS_SECONDS * 1000,
    "rp": [],
    "ttl": 86400,
    "s": "PLACEHOLDER_SIG_b64",
    "spk": ALICE["ed_public_b64"],
}
frame_for_signing = {k: v for k, v in raw_frame.items() if k not in ("s", "spk")}
frame_canonical = sorted_json_canonical(frame_for_signing)
frame_sig = ed_sign(ALICE["ed_private_hex"], frame_canonical.encode("utf-8"))

write_vector("canonicalization/frame_json_001.json", vector(
    name="Feature-frame JSON-canonical signing bytes",
    description="Apple JSONSerialization.sortedKeys compatible: drop `s` and `spk`, sort all keys recursively, compact output.",
    spec_reference="MESH_PROTOCOL.md §C.6 + §D Rule 3",
    inputs={"raw_frame": raw_frame, "signer": "alice"},
    expected={
        "canonical_utf8": frame_canonical,
        "canonical_hex": hx(frame_canonical.encode("utf-8")),
        "signature_hex": hx(frame_sig),
        "signature_b64": b64(frame_sig),
    },
))

# ----- MESH_PROTOCOL.md §I.13 self-check (asserts only; writes nothing) ------
# The v1 pipe join is not injective. A relay can strip dm_pipe_002's geo-fence
# and move its h3Cell|radius|deliverOnlyInside triple into replyToSenderName
# ("" + "|8a283082aac7fff|1|true"); both envelopes share signing bytes, so
# 002's signature verifies the unrestricted copy. v1 bytes stay frozen; the
# interim v1 rule is that a receiver rejects any pipe-form envelope with a "|"
# inside a signed field, and the real fix is the v2 draft framing (below).
def v1_fields_pipe_free(fields: list[str]) -> bool:
    """MESH_PROTOCOL.md §D "`|` inside signed fields": the v1 receiver check."""
    return all("|" not in f for f in fields)

dm_envelope_geo_stripped = dict(dm_envelope_no_geo, replyToSenderName="|8a283082aac7fff|1|true")
assert dm_pipe_bytes(dm_envelope_geo_stripped) == dm_bytes_with_geo  # the v1 flaw
assert ed_verify(ALICE["ed_public_hex"], dm_pipe_bytes(dm_envelope_geo_stripped), dm_sig_with_geo)
assert not v1_fields_pipe_free(dm_fields(dm_envelope_geo_stripped))  # interim rule rejects it
for _fields in (dm_fields(dm_envelope_no_geo), dm_fields(dm_envelope_with_geo),
                post_fields(post_envelope), ack_fields(ack_envelope), stop_fields(stop_command)):
    # Honest v1 vectors pass the rule, and for pipe-free fields splitting on
    # "|" recovers the exact field list (the join is injective on them).
    assert v1_fields_pipe_free(_fields)
    assert "|".join(_fields).split("|") == _fields

# ----- envelope vectors --------------------------------------------------
# A complete signed-DM envelope: encode -> decode roundtrip + signature check.
signed_dm_envelope = {
    "e": dm_envelope_no_geo,
    "s": b64(dm_sig_no_geo),
    "spk": ALICE["ed_public_b64"],
    "os": None,
    "ospk": None,
}

write_vector("envelopes/signed_dm_001.json", vector(
    name="SignedMeshPayload — Alice → Bob, plain text",
    description="Round-trip the full §C.1 payload. Includes the signing bytes + signature so any port can validate.",
    spec_reference="MESH_PROTOCOL.md §C.1",
    inputs={"signed_dm": signed_dm_envelope, "signer": "alice"},
    expected={
        "signing_bytes_hex": hx(dm_bytes_no_geo),
        "signature_hex": hx(dm_sig_no_geo),
        "signature_b64": b64(dm_sig_no_geo),
    },
))

# Encrypted DM seal: AES key derived from ECDH (Alice→Bob), plaintext = JSON of dm envelope.
encrypted_dm_plaintext = json.dumps(dm_envelope_no_geo, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
encrypted_dm_nonce = bytes.fromhex("aabbccddeeff00112233445566778899")[:12]
sealed_dm = aes_seal(aes_key_ab, encrypted_dm_nonce, encrypted_dm_plaintext)

encrypted_dm_payload = {
    "c": b64(sealed_dm),
    "n": b64(encrypted_dm_nonce),
    "spk": ALICE["x_public_b64"],  # NOTE: §I.2 — outer spk is the ECDH agreement key, NOT Ed25519.
    "v": 1,
    "s": b64(dm_sig_no_geo),
    "ssk": ALICE["ed_public_b64"],
}

write_vector("envelopes/encrypted_dm_001.json", vector(
    name="EncryptedMeshPayload — Alice → Bob",
    description="Encrypted DM: AES-256-GCM of the DM envelope JSON. Outer spk is the X25519 agreement key per §I.2.",
    spec_reference="MESH_PROTOCOL.md §C.2 + §I.2",
    inputs={
        "payload": encrypted_dm_payload,
        "aes_key_hex": hx(aes_key_ab),
        "ecdh_self": "alice",
        "ecdh_peer": "bob",
        "expected_plaintext_utf8": encrypted_dm_plaintext.decode("utf-8"),
    },
    expected={
        "aes_key_hex": hx(aes_key_ab),
        "combined_hex": hx(sealed_dm),
        "combined_b64": b64(sealed_dm),
    },
))

# ACK + Post envelopes (use the previously computed signatures).
ack_envelope_full = dict(
    ack_envelope,
    pathUsed="mesh",
    hopCount=2,
    hopLimit=10,
    routePath=[ALICE["device_id"]],
    originDeviceId=BOB["device_id"],
    isAck=True,
    signatureB64=b64(ack_sig),
    signerPublicKeyB64=BOB["ed_public_b64"],
)
write_vector("envelopes/ack_001.json", vector(
    name="MeshACKEnvelope — Bob → Alice, status=delivered",
    description="Full ACK with mutable routing fields populated. Signature covers only the immutable pipe fields.",
    spec_reference="MESH_PROTOCOL.md §C.4",
    inputs={"ack": ack_envelope_full, "signer": "bob"},
    expected={
        "signing_bytes_hex": hx(ack_bytes),
        "signature_hex": hx(ack_sig),
    },
))

post_envelope_full = dict(
    post_envelope,
    kind="mesh_post_v1",
    ttlHops=10, ttlSeconds=86400, hopCount=0,
    routePath=[],
    originDeviceId=ALICE["device_id"],
    initialSend="mesh",
    signatureB64=b64(post_sig),
    showOnRavenShot=False,
)
write_vector("envelopes/post_001.json", vector(
    name="MeshPostEnvelope — Alice friends-scope post",
    description="Full post envelope, scope=friends.",
    spec_reference="MESH_PROTOCOL.md §C.3",
    inputs={"post": post_envelope_full, "signer": "alice"},
    expected={
        "signing_bytes_hex": hx(post_bytes),
        "signature_hex": hx(post_sig),
    },
))

stop_full = dict(
    stop_command,
    type="STOP",
    signatureB64=b64(stop_sig),
    signerPublicKeyB64=ALICE["ed_public_b64"],
)
write_vector("envelopes/stop_001.json", vector(
    name="StopCommand — Alice cancels her DM",
    description="Stop command for dm-001 issued 120s after send.",
    spec_reference="MESH_PROTOCOL.md §C.5",
    inputs={"stop": stop_full, "signer": "alice"},
    expected={
        "signing_bytes_hex": hx(stop_bytes),
        "signature_hex": hx(stop_sig),
    },
))

# Feature frame envelope.
frame_full = dict(raw_frame, s=b64(frame_sig))
write_vector("envelopes/frame_001.json", vector(
    name="MeshMessageFrame — minimal payload",
    description="Generic feature frame with payload p={x:1,y:hello}. Signature uses JSON-canonical form.",
    spec_reference="MESH_PROTOCOL.md §C.6 + §D Rule 3",
    inputs={"raw_frame": frame_full, "signer": "alice"},
    expected={
        "canonical_utf8": frame_canonical,
        "signature_hex": hx(frame_sig),
    },
))

# ----- chunking vectors --------------------------------------------------
# §B — flag(0x00) + json (unchunked).  flag(0x01) + hash(4 LE) + total(1) + idx(1) + payload.
short_json = b'{"x":1}'
write_vector("chunking/single_chunk_001.json", vector(
    name="Single-chunk encoded packet",
    description="Payload < MTU → 1-byte flag (0x00) + raw JSON.",
    spec_reference="MESH_PROTOCOL.md §B",
    inputs={"payload_utf8": short_json.decode("utf-8")},
    expected={
        "packet_hex": "00" + hx(short_json),
    },
))

# Multi-chunk with caller-chosen messageHash 0xDEADBEEF, chunk payload size 4 bytes.
long_payload = b"ABCDEFGHIJ"  # 10 bytes
chunk_size = 4
total_chunks = -(-len(long_payload) // chunk_size)
message_hash = 0xDEADBEEF
chunks = []
for i in range(total_chunks):
    start = i * chunk_size
    end = min(start + chunk_size, len(long_payload))
    payload = long_payload[start:end]
    hash_le = struct.pack("<I", message_hash)
    packet = bytes([0x01]) + hash_le + bytes([total_chunks, i]) + payload
    chunks.append(packet)

write_vector("chunking/multi_chunk_001.json", vector(
    name="Multi-chunk encoded packets — payload spans 3 chunks",
    description="10-byte payload, 4-byte chunk payload size, messageHash=0xDEADBEEF (little-endian).",
    spec_reference="MESH_PROTOCOL.md §B + §I.1 — opaque messageHash",
    inputs={
        "payload_hex": hx(long_payload),
        "payload_utf8": long_payload.decode("ascii"),
        "chunk_payload_size": chunk_size,
        "message_hash_hex": "deadbeef",
    },
    expected={
        "total_chunks": total_chunks,
        "chunks_hex": [hx(c) for c in chunks],
    },
))

# Out-of-order reassembly — pass chunks in reverse, still get original.
write_vector("chunking/multi_chunk_reassembly_001.json", vector(
    name="Multi-chunk reassembly — out-of-order arrival",
    description="Same chunks as 001 but delivered in reverse order; reassembled payload must equal the original.",
    spec_reference="MESH_PROTOCOL.md §B — ChunkReassembler",
    inputs={
        "chunks_hex_in_arrival_order": [hx(c) for c in reversed(chunks)],
        "sender_device_id": ALICE["device_id"],
    },
    expected={"reassembled_hex": hx(long_payload)},
))

# ----- routing vectors ---------------------------------------------------
write_vector("routing/dedup_keys_001.json", vector(
    name="Dedup key strings per frame kind",
    description="Exact dedup-key strings stored in MeshDedupRepository per §E.",
    spec_reference="MESH_PROTOCOL.md §E",
    inputs={
        "client_message_id": "dm-001",
        "post_id": "post-001",
        "nonce_b64": b64(encrypted_dm_nonce),
        "ack_sender_id": "bob",
        "ack_recipient_id": "alice",
        "ack_status": "delivered",
    },
    expected={
        "signed_dm_key": "dm-001",
        "encrypted_dm_key": f"enc:{b64(encrypted_dm_nonce)}",
        "post_key": "post-001",
        "ack_key": "ack:dm-001|bob|alice|delivered",
        "stop_key": "stop:dm-001",
        "frame_key": "frame:frame-001",
    },
))

# Spray-and-wait — sprayCounter=4 → forward gives 2, sender keeps 2.
write_vector("routing/spray_transition_001.json", vector(
    name="Binary Spray-and-Wait — split from 4 tokens",
    description="sprayCounter=4 → tokensToGive=2, tokensRemaining=2, inWaitPhase=false.",
    spec_reference="MESH_PROTOCOL.md §E",
    inputs={"current_tokens": 4},
    expected={"tokens_to_give": 2, "tokens_remaining": 2, "in_wait_phase": False},
))

write_vector("routing/spray_transition_002.json", vector(
    name="Binary Spray-and-Wait — wait phase at 1 token",
    description="sprayCounter=1 → at threshold; tokensToGive=1, tokensRemaining=0, inWaitPhase=true.",
    spec_reference="MESH_PROTOCOL.md §E",
    inputs={"current_tokens": 1},
    expected={"tokens_to_give": 1, "tokens_remaining": 0, "in_wait_phase": True},
))

# Forward decision — direct recipient ALWAYS gets the frame; otherwise spray + dedup.
write_vector("routing/forward_decision_001.json", vector(
    name="Forward decision — direct recipient bypasses spray budget",
    description="If the connected peer's deviceId matches the envelope's recipientId, forward regardless of spray budget.",
    spec_reference="MESH_PROTOCOL.md §E — Forwarding rules",
    inputs={
        "envelope_recipient_id": "bob",
        "peer_device_id": BOB["device_id"],
        "current_tokens": 1,
    },
    expected={"forward": True, "reason": "direct_recipient"},
))

# Pairing code (§F) — SHA-256(min(pub1,pub2) || max || nonce)[:4 BE] mod 1_000_000.
pairing_nonce = bytes.fromhex("01020304050607080910111213141516")
sorted_pubs = sorted([ALICE["ed_public_b64"], BOB["ed_public_b64"]])
pairing_input = (sorted_pubs[0] + sorted_pubs[1]).encode("utf-8") + pairing_nonce
pairing_hash = hashlib.sha256(pairing_input).digest()
pairing_first4 = struct.unpack(">I", pairing_hash[:4])[0]
pairing_code = pairing_first4 % 1_000_000

write_vector("routing/pairing_code_001.json", vector(
    name="Pairing code — Alice ↔ Bob, fixed nonce",
    description="6-digit code from §F. Pubkeys sorted as base64 strings, concatenated UTF-8, append nonce, SHA-256, first 4 BE bytes mod 1_000_000.",
    spec_reference="MESH_PROTOCOL.md §F",
    inputs={
        "pub1_b64": ALICE["ed_public_b64"],
        "pub2_b64": BOB["ed_public_b64"],
        "nonce_hex": hx(pairing_nonce),
    },
    expected={
        "code_int": pairing_code,
        "code_str": f"{pairing_code:06d}",
    },
))

# ----- trust vectors -----------------------------------------------------
write_vector("trust/tofu_first_sighting_001.json", vector(
    name="Friend-device TOFU — first sighting",
    description="Recording a new fingerprint should produce state=unverified; subsequent sightings preserve state.",
    spec_reference="PROTOCOL_BUGS_REVIEW.md §I.11 + MESH_PROTOCOL.md §F",
    inputs={
        "device_id": BOB["device_id"],
        "user_id": "bob",
        "fingerprint": BOB["fingerprint"],
        "ed25519_public_key_b64": BOB["ed_public_b64"],
        "x25519_public_key_b64": BOB["x_public_b64"],
        "is_first_sighting": True,
    },
    expected={
        "state": "unverified",
        "verified_via": None,
        "is_trusted_relay": False,
    },
))

write_vector("trust/tofu_verify_001.json", vector(
    name="Friend-device verify after pairing code match",
    description="Promote unverified → verified once user confirms the out-of-band pairing code.",
    spec_reference="PROTOCOL_BUGS_REVIEW.md §I.11 + MESH_PROTOCOL.md §F",
    inputs={
        "device_id": BOB["device_id"],
        "via": "pairing_code",
    },
    expected={
        "state": "verified",
        "verified_via": "pairing_code",
        "is_trusted_relay": True,
    },
))


# =========================================================================
# DRAFT v2 signing inputs — docs/MESH_PROTOCOL_v2.md (fixes §I.13 / §I.14)
# =========================================================================
# v1/ is frozen (VERSIONING.md), so the fixed encoding lives in its own tree,
# v2/<same-relative-path>. Each v2 vector reuses its v1 counterpart's exact
# inputs; only the byte framing of the signing input changes. Nothing ships
# v2 yet: these files may still change until v2 is adopted, then they freeze.

ROOT_V2 = Path(__file__).parent / "v2"

def write_vector_v2(rel_path: str, body: dict) -> None:
    path = ROOT_V2 / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(body, indent=2, sort_keys=False, ensure_ascii=False)
    path.write_text(text + "\n", encoding="utf-8")
    print(f"wrote v2/{rel_path}")

def vector_v2(**kw) -> dict:
    body = vector(**kw)
    body["protocol_version"] = "v2-draft"
    body.setdefault("notes", "DRAFT (docs/MESH_PROTOCOL_v2.md): no port ships v2 yet; frozen once v2 is adopted.")
    return body

# §2 — 0xFF never occurs in UTF-8, and every v1 signing input is UTF-8, so no
# v2 input can equal any v1 input (no cross-version signature reuse).
V2_MAGIC = b"\xffRVMESH2"
V2_KIND_DM, V2_KIND_POST, V2_KIND_FRAME, V2_KIND_ACK, V2_KIND_STOP = 1, 2, 3, 4, 5

def v2_lp_fields(fields: list[str]) -> bytes:
    """u16be(field count) || for each field: u32be(len(utf8)) || utf8."""
    out = bytearray(struct.pack(">H", len(fields)))
    for f in fields:
        raw = f.encode("utf-8")
        out += struct.pack(">I", len(raw)) + raw
    return bytes(out)

def v2_lp_split(raw: bytes) -> list[str]:
    """Inverse of v2_lp_fields (strict: exact length, valid UTF-8)."""
    (n,) = struct.unpack_from(">H", raw, 0)
    off, out = 2, []
    for _ in range(n):
        (ln,) = struct.unpack_from(">I", raw, off)
        off += 4
        assert off + ln <= len(raw), "truncated field"
        out.append(raw[off:off + ln].decode("utf-8"))
        off += ln
    assert off == len(raw), "trailing bytes"
    return out

def v2_pipe_input(kind: int, fields: list[str]) -> bytes:
    out = V2_MAGIC + bytes([kind]) + v2_lp_fields(fields)
    assert v2_lp_split(out[len(V2_MAGIC) + 1:]) == fields  # injective by construction
    return out

def v2_ack_relay_key(a: dict) -> str:
    return "ack2:" + hashlib.sha256(v2_lp_fields(
        [a["originalMessageId"], a["senderId"], a["recipientId"], a["status"]]
    )).hexdigest()

# §3 — Rule 3 v2: RFC 8785 JSON Canonicalization Scheme (JCS).
def jcs_number(x) -> str:
    """ECMAScript Number::toString, as RFC 8785 §3.2.2.3 requires."""
    if isinstance(x, int):
        if abs(x) > 2**53 - 1:
            raise ValueError("I-JSON: integer outside ±(2^53−1)")
        x = float(x)
    if x != x or x in (float("inf"), float("-inf")):
        raise ValueError("JCS: NaN/Infinity have no JSON form")
    if x == 0:
        return "0"  # also -0
    if x < 0:
        return "-" + jcs_number(-x)
    mant, _, exp = repr(x).partition("e")   # repr = shortest round-trip digits
    ip, _, fp = mant.partition(".")
    digits = ip + fp
    lead = len(digits) - len(digits.lstrip("0"))
    s = digits.lstrip("0").rstrip("0")
    n = len(ip) + (int(exp) if exp else 0) - lead   # value = 0.s × 10^n
    k = len(s)
    if k <= n <= 21:
        return s + "0" * (n - k)
    if 0 < n <= 21:
        return s[:n] + "." + s[n:]
    if -6 < n <= 0:
        return "0." + "0" * (-n) + s
    e = n - 1
    return (s if k == 1 else s[0] + "." + s[1:]) + ("e+" if e >= 0 else "e-") + str(abs(e))

def jcs(value) -> str:
    if value is None or isinstance(value, bool):
        return json.dumps(value)
    if isinstance(value, (int, float)):
        return jcs_number(value)
    if isinstance(value, str):
        # Minimal escaping: `"`, `\`, U+0000–U+001F (\b \t \n \f \r short forms,
        # else \u00xx lowercase); `/` and non-ASCII are emitted literally.
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))  # UTF-16 code units
        return "{" + ",".join(f"{jcs(k)}:{jcs(value[k])}" for k in keys) + "}"
    raise TypeError(f"JCS: unsupported type {type(value).__name__}")

# RFC 8785 Appendix B number samples (IEEE-754 bit pattern -> JCS text).
for _bits, _want in [
    ("0000000000000000", "0"), ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"), ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"), ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"), ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"), ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"), ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"), ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"), ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]:
    (_x,) = struct.unpack(">d", bytes.fromhex(_bits))
    assert jcs_number(_x) == _want, (_bits, jcs_number(_x), _want)
assert jcs({"\u20ac": 1, "\r": 2, "\ufb33": 3, "1": 4, "\U0001f600": 5, "\u0080": 6, "\u00f6": 7}) \
    == '{"\\r":2,"1":4,"\u0080":6,"\u00f6":7,"\u20ac":1,"\U0001f600":5,"\ufb33":3}'  # RFC 8785 §3.2.3
# For ASCII keys and safe-range integers JCS equals the v1 reference output.
assert jcs(frame_for_signing) == frame_canonical

def v2_frame_input(frame: dict) -> tuple[str, bytes]:
    canon = jcs({k: v for k, v in frame.items() if k not in ("s", "spk")})
    return canon, V2_MAGIC + bytes([V2_KIND_FRAME]) + canon.encode("utf-8")

def v2_pipe_vector(rel: str, name: str, description: str, spec: str, inputs: dict,
                   kind: int, fields: list[str], signer: dict, extra: dict | None = None):
    sb = v2_pipe_input(kind, fields)
    sig = ed_sign(signer["ed_private_hex"], sb)
    assert ed_verify(signer["ed_public_hex"], sb, sig)
    expected = {
        "fields": fields,
        "signing_bytes_hex": hx(sb),
        "signature_hex": hx(sig),
        "signature_b64": b64(sig),
    }
    expected.update(extra or {})
    write_vector_v2(rel, vector_v2(name=name, description=description, spec_reference=spec,
                                   inputs=inputs, expected=expected))
    return sb, sig

V2_SPEC = "MESH_PROTOCOL_v2.md §2"
v2_dm_no_geo, _ = v2_pipe_vector(
    "canonicalization/dm_pipe_001.json", "DM v2 signing input — no geo-fence",
    "v1 dm_pipe_001's envelope and field list, framed per v2 (magic, kind 0x01, u16 count, u32-length-prefixed UTF-8 fields).",
    V2_SPEC + " + MESH_PROTOCOL.md §D Rule 1", {"envelope": dm_envelope_no_geo, "signer": "alice"},
    V2_KIND_DM, dm_fields(dm_envelope_no_geo), ALICE)
v2_dm_geo, v2_dm_geo_sig = v2_pipe_vector(
    "canonicalization/dm_pipe_002.json", "DM v2 signing input — with geo-fence",
    "v1 dm_pipe_002's envelope: 23 fields (geo-fence triple appended), framed per v2.",
    V2_SPEC + " + MESH_PROTOCOL.md §D Rule 1", {"envelope": dm_envelope_with_geo, "signer": "alice"},
    V2_KIND_DM, dm_fields(dm_envelope_with_geo), ALICE)

dm_envelope_pipes = dict(
    dm_envelope_no_geo,
    clientMessageId="dm-003",
    senderName="Al|ce \\ admin",
    text="a|b\\|c",
    replyToMessageId="dm-000",
    replyToTextPreview="x|y",
    replyToSenderName="Bob|",
)
v2_pipe_vector(
    "canonicalization/dm_pipe_003.json", "DM v2 signing input — `|` and `\\` inside fields",
    "Free-text fields containing `|` and `\\` are carried verbatim: length prefixes, not delimiters, separate fields, so no escaping is needed and no field can spill into another. (v1 forbids `|` in signed fields — MESH_PROTOCOL.md §I.13.)",
    V2_SPEC, {"envelope": dm_envelope_pipes, "signer": "alice"},
    V2_KIND_DM, dm_fields(dm_envelope_pipes), ALICE)

# Negative: the §I.13 geo-fence strip. Under v1 the tampered envelope shares
# 002's signing bytes; under v2 it cannot, so 002's signature must not verify.
v2_dm_stripped = v2_pipe_input(V2_KIND_DM, dm_fields(dm_envelope_geo_stripped))
assert v2_dm_stripped != v2_dm_geo
assert not ed_verify(ALICE["ed_public_hex"], v2_dm_stripped, v2_dm_geo_sig)
write_vector_v2("canonicalization/dm_pipe_004.json", vector_v2(
    name="DM v2 — geo-fence strip via field re-split is rejected",
    description="Negative. `envelope` is dm_pipe_002 with its geoFence removed and the h3Cell|radius|deliverOnlyInside triple appended to replyToSenderName; `claimed_signature_hex` is dm_pipe_002's v2 signature. The v2 signing input differs (20 fields, not 23), so verification MUST fail. Under v1 both envelopes have identical signing bytes (MESH_PROTOCOL.md §I.13).",
    spec_reference=V2_SPEC + " + MESH_PROTOCOL.md §I.13",
    inputs={
        "envelope": dm_envelope_geo_stripped,
        "signer": "alice",
        "claimed_signature_hex": hx(v2_dm_geo_sig),
    },
    expected={
        "fields": dm_fields(dm_envelope_geo_stripped),
        "signing_bytes_hex": hx(v2_dm_stripped),
        "verify_result": "reject",
    },
))

v2_pipe_vector(
    "canonicalization/post_pipe_001.json", "Post v2 signing input",
    "v1 post_pipe_001's post and field list (leading \"POST\" literal kept), framed per v2 with kind 0x02.",
    V2_SPEC + " + MESH_PROTOCOL.md §C.3", {"post": post_envelope, "signer": "alice"},
    V2_KIND_POST, post_fields(post_envelope), ALICE)
post_envelope_pipes = dict(post_envelope, postId="post-002", text="pipes | and back\\slashes|friends")
v2_pipe_vector(
    "canonicalization/post_pipe_002.json", "Post v2 signing input — `|` inside text",
    "Post text ending in `|friends` cannot be confused with the scope field: the v2 input still has exactly 9 fields.",
    V2_SPEC + " + MESH_PROTOCOL.md §C.3", {"post": post_envelope_pipes, "signer": "alice"},
    V2_KIND_POST, post_fields(post_envelope_pipes), ALICE)
v2_pipe_vector(
    "canonicalization/ack_pipe_001.json", "ACK v2 signing input — delivered",
    "v1 ack_pipe_001's ACK framed per v2 with kind 0x04, plus the v2 ACK relay dedup key (§2.3).",
    V2_SPEC + " + MESH_PROTOCOL.md §C.4", {"ack": ack_envelope, "signer": "bob"},
    V2_KIND_ACK, ack_fields(ack_envelope), BOB,
    extra={"relay_key": v2_ack_relay_key(ack_envelope)})
v2_pipe_vector(
    "canonicalization/stop_pipe_001.json", "Stop v2 signing input",
    "v1 stop_pipe_001's command (leading \"STOP\" literal kept) framed per v2 with kind 0x05.",
    V2_SPEC + " + MESH_PROTOCOL.md §C.5", {"stop": stop_command, "signer": "alice"},
    V2_KIND_STOP, stop_fields(stop_command), ALICE)

def v2_frame_vector(rel: str, name: str, description: str, frame: dict):
    canon, sb = v2_frame_input(frame)
    sig = ed_sign(ALICE["ed_private_hex"], sb)
    assert ed_verify(ALICE["ed_public_hex"], sb, sig)
    write_vector_v2(rel, vector_v2(
        name=name, description=description,
        spec_reference="MESH_PROTOCOL_v2.md §3 + RFC 8785",
        inputs={"raw_frame": frame, "signer": "alice"},
        expected={
            "canonical_utf8": canon,
            "canonical_hex": hx(canon.encode("utf-8")),
            "signing_bytes_hex": hx(sb),
            "signature_hex": hx(sig),
            "signature_b64": b64(sig),
        },
    ))

v2_frame_vector(
    "canonicalization/frame_json_001.json", "Feature-frame v2 signing input (RFC 8785)",
    "v1 frame_json_001's frame: drop `s`/`spk`, canonicalize with RFC 8785 (JCS), prefix magic + kind 0x03. For this all-ASCII, integer-only frame the JCS text equals the v1 canonical text.",
    raw_frame)
raw_frame_edge = dict(
    raw_frame,
    mid="frame-002",
    p={
        "url": "https://cdn.raven.app/u/alice.png",
        "caption": "caf\u00e9 \u2615 \"q\" \\ \u001f",
        "nums": [0, -0.0, 1.0, 1.5, -2.25, 1e21, 1e-7, 0.000001, 333333333.3333333, 5e-324],
        "\ue000": "private-use key sorts after the astral one",
        "\U0001f600": "astral key (UTF-16 D83D DE00)",
        "ok": True,
        "none": None,
    },
)
v2_frame_vector(
    "canonicalization/frame_json_002.json", "Feature-frame v2 signing input — JCS edge cases",
    "Floats (ECMAScript shortest form: 1.0→1, -0→0, 1e21→1e+21, 1e-7→1e-7, 0.000001 stays decimal), `/` not escaped, non-ASCII literal, control char as \\u001f, keys sorted by UTF-16 code units (U+1F600 before U+E000). These are the cases where \"sorted keys\" JSON diverges across languages (MESH_PROTOCOL.md §I.14).",
    raw_frame_edge)

print("\nAll v1 vectors generated. Run unit tests against shared-vectors/v1/ to verify.")
print("DRAFT v2 signing-input vectors generated under shared-vectors/v2/ (docs/MESH_PROTOCOL_v2.md).")
