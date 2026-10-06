"""EC Double Ratchet DH transitions + Raven Braid chunk KATs (production-disabled).

Status: REQUIRED / NOT YET APPROVED support code — not a full Signal SPQR port.
Crash ordering remains in hybrid_ratchet_v2_state (KAT-only).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .hybrid_ratchet_v2 import MAX_SKIP, kdf_ck, kdf_hybrid, kdf_rk
from .hybrid_ratchet_v2_state import (
    _mk_key,
    scka_epoch_promote_initiator,
    scka_epoch_promote_responder,
    scka_from_init,
    scka_next_recv_mk,
    scka_next_send_mk,
)

PRODUCTION_ENABLED = False

BRAID_CHUNK_DOMAIN = b"ATSAM/v2/braid-chunk"
BRAID_MAGIC = b"RVBC1\x00\x00\x00"
# magic(8) | epoch_u64be(8) | type(1) | index_u32be(4) | plen_u16be(2)
BRAID_HEADER_LEN = 8 + 8 + 1 + 4 + 2  # 23
BRAID_DIGEST_LEN = 32
# Per-chunk semantic max MUST NOT exceed default reassembly total budget.
# Wire still carries plen as u16; encoder MUST reject above BRAID_MAX_PAYLOAD.
BRAID_MAX_TOTAL_PAYLOAD_BYTES = 8192
BRAID_MAX_PAYLOAD = BRAID_MAX_TOTAL_PAYLOAD_BYTES
BRAID_MAX_CHUNKS_PER_EPOCH = 64
# Binding digest is NOT authentication — outer signature + AEAD provide auth.
# This SHA-256 is canonical-binding / fail-closed integrity for KAT framing only.
MAX_MKSKIPPED_RETAINED = 2000  # global retained skipped-key cap across DH epochs

# ML-KEM-768 formal object sizes (Signal ML-KEM Braid) — Full Braid target.
# Header is separate from ek_vector; full FIPS EK is Header||ek_vector = 64+1152 = 1184.
BRAID_MLKEM768_HEADER_SIZE = 64
BRAID_MLKEM768_EK_VECTOR_SIZE = 1152
BRAID_MLKEM768_EK_FIPS_SIZE = 1184  # complete encapsulation key (KAT ek_len)
BRAID_MLKEM768_CT1_SIZE = 960
BRAID_MLKEM768_CT2_SIZE = 128

CHUNK_NONE = 0
CHUNK_HDR = 1
CHUNK_EK = 2
CHUNK_EK_CT1_ACK = 3
CHUNK_CT1_ACK = 4
CHUNK_CT1 = 5
CHUNK_CT2 = 6
BRAID_ALLOWED_TYPES = frozenset(range(0, 7))
# Signal: None and Ct1Ack carry no erasure payload; canonical index is 0.
BRAID_EMPTY_PAYLOAD_TYPES = frozenset({CHUNK_NONE, CHUNK_CT1_ACK})
BRAID_DATA_PAYLOAD_TYPES = BRAID_ALLOWED_TYPES - BRAID_EMPTY_PAYLOAD_TYPES


def require_session_id(session_id: bytes) -> bytes:
    if not isinstance(session_id, (bytes, bytearray)) or len(session_id) != 32:
        raise ValueError("session_id must be 32 bytes")
    return bytes(session_id)


def require_epoch_u64(epoch: int) -> int:
    if not isinstance(epoch, int) or epoch < 0 or epoch > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("braid epoch must be u64")
    return epoch


def validate_braid_payload_rules(*, typ: int, payload: bytes, chunk_index: int) -> None:
    if typ not in BRAID_ALLOWED_TYPES:
        raise ValueError("unknown braid chunk type")
    if typ in BRAID_EMPTY_PAYLOAD_TYPES:
        if len(payload) != 0:
            raise ValueError("braid empty-type payload must be empty")
        if chunk_index != 0:
            raise ValueError("braid empty-type chunk_index must be 0")
    elif typ in BRAID_DATA_PAYLOAD_TYPES:
        if len(payload) == 0:
            raise ValueError("braid data-type payload must be non-empty")


def x25519_public(priv: bytes) -> bytes:
    if len(priv) != 32 or priv == bytes(32):
        raise ValueError("all-zero X25519 rejected")
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes_raw()


def x25519_dh(priv: bytes, pub: bytes) -> bytes:
    if len(priv) != 32 or len(pub) != 32:
        raise ValueError("X25519 length")
    if priv == bytes(32) or pub == bytes(32):
        raise ValueError("all-zero X25519 rejected")
    try:
        ss = X25519PrivateKey.from_private_bytes(priv).exchange(
            X25519PublicKey.from_public_bytes(pub)
        )
    except Exception as exc:  # noqa: BLE001
        raise ValueError("invalid X25519 input") from exc
    if ss == bytes(32):
        raise ValueError("non-contributory DH rejected")
    return ss


@dataclass
class EcDrState:
    rk: bytes
    dhs_priv: bytes
    dhs_pub: bytes
    dhr_pub: bytes | None
    cks: bytes | None
    ckr: bytes | None
    ns: int = 0
    nr: int = 0
    pn: int = 0
    mkskipped: dict[bytes, bytes] = field(default_factory=dict)

    def fingerprint(self) -> bytes:
        items = b"".join(sorted(k + v for k, v in self.mkskipped.items()))
        return hashlib.sha256(
            self.rk
            + self.dhs_pub
            + (self.dhr_pub or bytes(32))
            + (self.cks or bytes(32))
            + (self.ckr or bytes(32))
            + self.ns.to_bytes(4, "big")
            + self.nr.to_bytes(4, "big")
            + self.pn.to_bytes(4, "big")
            + items
        ).digest()


def ec_dr_init_alice(rk0: bytes, alice_priv: bytes, bob_pub: bytes) -> EcDrState:
    ss = x25519_dh(alice_priv, bob_pub)
    rk1, cks = kdf_rk(rk0, ss)
    return EcDrState(
        rk=rk1,
        dhs_priv=alice_priv,
        dhs_pub=x25519_public(alice_priv),
        dhr_pub=bob_pub,
        cks=cks,
        ckr=None,
    )


def ec_dr_init_bob(rk0: bytes, bob_priv: bytes) -> EcDrState:
    return EcDrState(
        rk=rk0,
        dhs_priv=bob_priv,
        dhs_pub=x25519_public(bob_priv),
        dhr_pub=None,
        cks=None,
        ckr=None,
    )


def ec_dr_encrypt(state: EcDrState, plaintext_label: bytes) -> tuple[EcDrState, dict, bytes]:
    if state.cks is None:
        raise ValueError("no sending chain")
    ck2, mk = kdf_ck(state.cks)
    header = {"dh_pub": state.dhs_pub, "pn": state.pn, "n": state.ns}
    out = EcDrState(
        rk=state.rk,
        dhs_priv=state.dhs_priv,
        dhs_pub=state.dhs_pub,
        dhr_pub=state.dhr_pub,
        cks=ck2,
        ckr=state.ckr,
        ns=state.ns + 1,
        nr=state.nr,
        pn=state.pn,
        mkskipped=dict(state.mkskipped),
    )
    return out, header, mk


def _dh_ratchet(state: EcDrState, their_dh: bytes, new_local_priv: bytes) -> EcDrState:
    ss1 = x25519_dh(state.dhs_priv, their_dh)
    rk1, ckr = kdf_rk(state.rk, ss1)
    local_pub = x25519_public(new_local_priv)
    ss2 = x25519_dh(new_local_priv, their_dh)
    rk2, cks = kdf_rk(rk1, ss2)
    return EcDrState(
        rk=rk2,
        dhs_priv=new_local_priv,
        dhs_pub=local_pub,
        dhr_pub=their_dh,
        cks=cks,
        ckr=ckr,
        ns=0,
        nr=0,
        pn=state.ns,
        mkskipped=dict(state.mkskipped),
    )


def ec_dr_decrypt(
    state: EcDrState,
    header: dict,
    max_skip: int = MAX_SKIP,
    new_local_priv: bytes | None = None,
    max_mkskipped: int = MAX_MKSKIPPED_RETAINED,
) -> tuple[EcDrState, bytes]:
    dh = header["dh_pub"]
    n = int(header["n"])
    pn = int(header["pn"])

    key = _mk_key(dh, n)
    if key in state.mkskipped:
        skipped = dict(state.mkskipped)
        mk = skipped.pop(key)
        out = EcDrState(
            rk=state.rk,
            dhs_priv=state.dhs_priv,
            dhs_pub=state.dhs_pub,
            dhr_pub=state.dhr_pub,
            cks=state.cks,
            ckr=state.ckr,
            ns=state.ns,
            nr=state.nr,
            pn=state.pn,
            mkskipped=skipped,
        )
        return out, mk

    def _insert_skipped(skipped: dict[bytes, bytes], k: bytes, mk_i: bytes) -> dict[bytes, bytes]:
        if k in skipped:
            return skipped
        if len(skipped) >= max_mkskipped:
            raise ValueError("MAX_MKSKIPPED_RETAINED exceeded")
        out = dict(skipped)
        out[k] = mk_i
        return out

    st = state
    if st.dhr_pub is None or dh != st.dhr_pub:
        if st.dhr_pub is not None and st.ckr is not None:
            skip_until = pn
            if skip_until < st.nr:
                raise ValueError("pn behind nr")
            if skip_until - st.nr > max_skip:
                raise ValueError("MAX_SKIP exceeded")
            ck = st.ckr
            nr = st.nr
            skipped = dict(st.mkskipped)
            while nr < skip_until:
                ck, mk_i = kdf_ck(ck)
                skipped = _insert_skipped(skipped, _mk_key(st.dhr_pub, nr), mk_i)
                nr += 1
            st = EcDrState(
                rk=st.rk,
                dhs_priv=st.dhs_priv,
                dhs_pub=st.dhs_pub,
                dhr_pub=st.dhr_pub,
                cks=st.cks,
                ckr=ck,
                ns=st.ns,
                nr=nr,
                pn=st.pn,
                mkskipped=skipped,
            )
        if new_local_priv is None:
            raise ValueError("DH ratchet requires new_local_priv")
        st = _dh_ratchet(st, dh, new_local_priv)

    if st.ckr is None:
        raise ValueError("no receiving chain")
    if n < st.nr:
        raise ValueError("replay of consumed index")
    if n > st.nr:
        if n - st.nr > max_skip:
            raise ValueError("MAX_SKIP exceeded")
        ck = st.ckr
        nr = st.nr
        skipped = dict(st.mkskipped)
        while nr < n:
            ck, mk_i = kdf_ck(ck)
            skipped = _insert_skipped(skipped, _mk_key(st.dhr_pub, nr), mk_i)
            nr += 1
        st = EcDrState(
            rk=st.rk,
            dhs_priv=st.dhs_priv,
            dhs_pub=st.dhs_pub,
            dhr_pub=st.dhr_pub,
            cks=st.cks,
            ckr=ck,
            ns=st.ns,
            nr=nr,
            pn=st.pn,
            mkskipped=skipped,
        )
    ck2, mk = kdf_ck(st.ckr)
    out = EcDrState(
        rk=st.rk,
        dhs_priv=st.dhs_priv,
        dhs_pub=st.dhs_pub,
        dhr_pub=st.dhr_pub,
        cks=st.cks,
        ckr=ck2,
        ns=st.ns,
        nr=st.nr + 1,
        pn=st.pn,
        mkskipped=dict(st.mkskipped),
    )
    return out, mk


def run_ec_dh_ratchet_matrix(
    rk0: bytes,
    alice_priv0: bytes,
    bob_priv0: bytes,
    bob_priv1: bytes,
    alice_priv1: bytes,
) -> dict:
    alice = ec_dr_init_alice(rk0, alice_priv0, x25519_public(bob_priv0))
    bob = ec_dr_init_bob(rk0, bob_priv0)

    sealed = []
    for _ in range(2):
        alice, hdr, mk = ec_dr_encrypt(alice, b"")
        sealed.append({"header": {"dh_pub_hex": hdr["dh_pub"].hex(), "pn": hdr["pn"], "n": hdr["n"]}, "mk": mk})

    # OOO across DH boundary: receive n=1 first (DH ratchet), then n=0 from skipped
    bob, mk1 = ec_dr_decrypt(
        bob,
        {"dh_pub": bytes.fromhex(sealed[1]["header"]["dh_pub_hex"]), "pn": sealed[1]["header"]["pn"], "n": sealed[1]["header"]["n"]},
        new_local_priv=bob_priv1,
    )
    assert mk1 == sealed[1]["mk"]
    bob, mk0 = ec_dr_decrypt(
        bob,
        {"dh_pub": bytes.fromhex(sealed[0]["header"]["dh_pub_hex"]), "pn": sealed[0]["header"]["pn"], "n": sealed[0]["header"]["n"]},
    )
    assert mk0 == sealed[0]["mk"]

    bob, bob_hdr, bob_mk = ec_dr_encrypt(bob, b"")
    alice, amk = ec_dr_decrypt(
        alice,
        {"dh_pub": bob_hdr["dh_pub"], "pn": bob_hdr["pn"], "n": bob_hdr["n"]},
        new_local_priv=alice_priv1,
    )
    assert amk == bob_mk

    neg = {}
    try:
        x25519_dh(alice_priv0, bytes(32))
        neg["all_zero_pub"] = "accepted"
    except ValueError as e:
        neg["all_zero_pub"] = str(e)
    try:
        x25519_public(bytes(32))
        neg["all_zero_priv"] = "accepted"
    except ValueError as e:
        neg["all_zero_priv"] = str(e)

    return {
        "alice_pub0_hex": x25519_public(alice_priv0).hex(),
        "bob_pub0_hex": x25519_public(bob_priv0).hex(),
        "bob_pub1_hex": x25519_public(bob_priv1).hex(),
        "alice_pub1_hex": x25519_public(alice_priv1).hex(),
        "recv_order": [1, 0],
        "alice_mks_hex": [s["mk"].hex() for s in sealed],
        "bob_recovered_mks_hex": [mk0.hex(), mk1.hex()],
        "bob_send_mk_hex": bob_mk.hex(),
        "alice_recovered_bob_mk_hex": amk.hex(),
        "cross_boundary_ok": True,
        "headers": [s["header"] for s in sealed],
        "bob_header": {"dh_pub_hex": bob_hdr["dh_pub"].hex(), "pn": bob_hdr["pn"], "n": bob_hdr["n"]},
        "negatives": neg,
        "final_alice_fp_hex": alice.fingerprint().hex(),
        "final_bob_fp_hex": bob.fingerprint().hex(),
    }


@dataclass
class BraidChunk:
    epoch: int
    type: int
    chunk_index: int
    payload: bytes
    session_id: bytes
    binding_digest: bytes = b""


def braid_binding(chunk: BraidChunk) -> bytes:
    sid = require_session_id(chunk.session_id)
    epoch = require_epoch_u64(chunk.epoch)
    return hashlib.sha256(
        BRAID_CHUNK_DOMAIN
        + epoch.to_bytes(8, "big")
        + bytes([chunk.type & 0xFF])
        + chunk.chunk_index.to_bytes(4, "big")
        + chunk.payload
        + sid
    ).digest()


def encode_braid_chunk(chunk: BraidChunk) -> bytes:
    require_session_id(chunk.session_id)
    require_epoch_u64(chunk.epoch)
    validate_braid_payload_rules(
        typ=chunk.type, payload=chunk.payload, chunk_index=chunk.chunk_index
    )
    if len(chunk.payload) > BRAID_MAX_PAYLOAD:
        raise ValueError("braid payload exceeds max")
    dig = braid_binding(chunk)
    return b"".join(
        (
            BRAID_MAGIC,
            chunk.epoch.to_bytes(8, "big"),
            bytes([chunk.type]),
            chunk.chunk_index.to_bytes(4, "big"),
            len(chunk.payload).to_bytes(2, "big"),
            chunk.payload,
            dig,
        )
    )


def decode_braid_chunk(wire: bytes, session_id: bytes) -> BraidChunk:
    """Fail-closed: require wire.len == BRAID_HEADER_LEN + plen + BRAID_DIGEST_LEN."""
    session_id = require_session_id(session_id)
    if not isinstance(wire, (bytes, bytearray)):
        raise ValueError("braid wire must be bytes")
    if len(wire) < BRAID_HEADER_LEN + BRAID_DIGEST_LEN:
        raise ValueError("short braid chunk")
    if wire[:8] != BRAID_MAGIC:
        raise ValueError("bad braid magic")
    typ = wire[8 + 8]
    if typ not in BRAID_ALLOWED_TYPES:
        raise ValueError("unknown braid chunk type")
    plen = int.from_bytes(wire[8 + 8 + 1 + 4 : 8 + 8 + 1 + 4 + 2], "big")
    expected = BRAID_HEADER_LEN + plen + BRAID_DIGEST_LEN
    if len(wire) != expected:
        raise ValueError("braid chunk length mismatch")
    if plen > BRAID_MAX_PAYLOAD:
        raise ValueError("braid payload exceeds max")
    off = 8
    epoch = int.from_bytes(wire[off : off + 8], "big")
    off += 8
    off += 1  # type already validated
    idx = int.from_bytes(wire[off : off + 4], "big")
    off += 4
    off += 2  # plen
    payload = bytes(wire[off : off + plen])
    off += plen
    dig = bytes(wire[off : off + BRAID_DIGEST_LEN])
    validate_braid_payload_rules(typ=typ, payload=payload, chunk_index=idx)
    chunk = BraidChunk(
        epoch=epoch,
        type=typ,
        chunk_index=idx,
        payload=payload,
        session_id=session_id,
        binding_digest=dig,
    )
    if braid_binding(chunk) != dig:
        raise ValueError("braid chunk tamper")
    return chunk


@dataclass
class BraidReassembly:
    epoch: int
    expected_count: int
    parts: dict[int, bytes] = field(default_factory=dict)
    promoted: bool = False
    deleted_prev_dk: bool = False
    prev_dk: bytes | None = None
    total_payload_bytes: int = 0
    max_chunks: int = BRAID_MAX_CHUNKS_PER_EPOCH
    max_total_bytes: int = BRAID_MAX_TOTAL_PAYLOAD_BYTES

    def __post_init__(self) -> None:
        if self.expected_count <= 0 or self.expected_count > self.max_chunks:
            raise ValueError("braid expected_count out of bounds")

    def ingest(self, chunk: BraidChunk) -> str:
        if chunk.epoch != self.epoch:
            return "epoch_mismatch"
        if chunk.type not in BRAID_ALLOWED_TYPES:
            return "unknown_type"
        if chunk.chunk_index >= self.expected_count:
            return "index_out_of_range"
        if chunk.chunk_index in self.parts:
            return "duplicate_chunk"
        if len(self.parts) >= self.max_chunks:
            return "chunk_cap_exceeded"
        nxt = self.total_payload_bytes + len(chunk.payload)
        if nxt > self.max_total_bytes:
            return "byte_cap_exceeded"
        self.parts[chunk.chunk_index] = chunk.payload
        self.total_payload_bytes = nxt
        return "stored"

    def try_complete(self) -> bytes | None:
        if any(i not in self.parts for i in range(self.expected_count)):
            return None
        return b"".join(self.parts[i] for i in range(self.expected_count))

    def promote_with_ss(self, ss: bytes, prev_dk: bytearray) -> bytes:
        """Promote and erase the caller's previous-epoch dk in place.

        `deleted_prev_dk` is only set once that buffer is observably zero, so
        the KAT's `prev_dk_zeroed` asserts real deletion.
        """
        if self.promoted:
            raise ValueError("already promoted")
        if self.try_complete() is None:
            raise ValueError("incomplete")
        if not isinstance(prev_dk, bytearray):
            raise TypeError("prev_dk must be a mutable bytearray to erase")
        prev_dk[:] = bytes(len(prev_dk))
        if any(prev_dk):
            raise ValueError("previous decapsulation key not erased")
        self.prev_dk = None
        self.deleted_prev_dk = True
        self.promoted = True
        return ss


def _craft_braid_wire(
    *,
    plen_field: int,
    payload: bytes,
    typ: int = CHUNK_CT1,
    epoch: int = 1,
    index: int = 0,
    session_id: bytes,
    trailing: bytes = b"",
    digest: bytes | None = None,
) -> bytes:
    """Build a wire for negative KATs (may be malformed)."""
    body = b"".join(
        (
            BRAID_MAGIC,
            epoch.to_bytes(8, "big"),
            bytes([typ & 0xFF]),
            index.to_bytes(4, "big"),
            (plen_field & 0xFFFF).to_bytes(2, "big"),
            payload,
        )
    )
    if digest is None:
        # Valid digest for declared payload bytes actually present (may mismatch plen).
        tmp = BraidChunk(
            epoch=epoch,
            type=typ,
            chunk_index=index,
            payload=payload,
            session_id=session_id,
        )
        digest = braid_binding(tmp)
    return body + digest + trailing


def run_braid_codec_negatives(session_id: bytes) -> dict:
    """Strict length / type / reassembly / encode caps — fail-closed."""
    cases = []
    session_id = require_session_id(session_id)

    # Truncated: plen claims more than available
    good = encode_braid_chunk(
        BraidChunk(epoch=1, type=CHUNK_CT1, chunk_index=0, payload=b"abc", session_id=session_id)
    )
    trunc = good[:-5]
    try:
        decode_braid_chunk(trunc, session_id)
        cases.append({"name": "truncated_plen", "result": "accepted"})
    except ValueError as e:
        cases.append({"name": "truncated_plen", "result": "reject", "reason": str(e)})

    # Trailing bytes after exact frame
    try:
        decode_braid_chunk(good + b"\x00", session_id)
        cases.append({"name": "trailing_bytes", "result": "accepted"})
    except ValueError as e:
        cases.append({"name": "trailing_bytes", "result": "reject", "reason": str(e)})

    # plen field larger than payload+digest room
    over = _craft_braid_wire(
        plen_field=1000, payload=b"x", session_id=session_id, trailing=b""
    )
    try:
        decode_braid_chunk(over, session_id)
        cases.append({"name": "oversized_plen_field", "result": "accepted"})
    except ValueError as e:
        cases.append({"name": "oversized_plen_field", "result": "reject", "reason": str(e)})

    # Unknown type
    try:
        encode_braid_chunk(
            BraidChunk(epoch=1, type=99, chunk_index=0, payload=b"x", session_id=session_id)
        )
        cases.append({"name": "encode_unknown_type", "result": "accepted"})
    except ValueError as e:
        cases.append({"name": "encode_unknown_type", "result": "reject", "reason": str(e)})

    # Payload > semantic max (aligned with default reassembly budget)
    try:
        encode_braid_chunk(
            BraidChunk(
                epoch=1,
                type=CHUNK_CT1,
                chunk_index=0,
                payload=bytes(BRAID_MAX_PAYLOAD + 1),
                session_id=session_id,
            )
        )
        cases.append({"name": "encode_payload_gt_max", "result": "accepted"})
    except ValueError as e:
        cases.append({"name": "encode_payload_gt_max", "result": "reject", "reason": str(e)})

    # session_id length
    try:
        encode_braid_chunk(
            BraidChunk(
                epoch=1,
                type=CHUNK_CT1,
                chunk_index=0,
                payload=b"x",
                session_id=b"short",
            )
        )
        cases.append({"name": "session_id_bad_len", "result": "accepted"})
    except ValueError as e:
        cases.append({"name": "session_id_bad_len", "result": "reject", "reason": str(e)})

    # Empty-type with non-empty payload
    try:
        encode_braid_chunk(
            BraidChunk(
                epoch=1,
                type=CHUNK_CT1_ACK,
                chunk_index=0,
                payload=b"x",
                session_id=session_id,
            )
        )
        cases.append({"name": "empty_type_nonempty_payload", "result": "accepted"})
    except ValueError as e:
        cases.append(
            {"name": "empty_type_nonempty_payload", "result": "reject", "reason": str(e)}
        )

    # Data-bearing type with empty payload
    try:
        encode_braid_chunk(
            BraidChunk(
                epoch=1,
                type=CHUNK_CT1,
                chunk_index=0,
                payload=b"",
                session_id=session_id,
            )
        )
        cases.append({"name": "data_type_empty_payload", "result": "accepted"})
    except ValueError as e:
        cases.append(
            {"name": "data_type_empty_payload", "result": "reject", "reason": str(e)}
        )

    # Empty-type with non-zero index (canonical representation)
    try:
        encode_braid_chunk(
            BraidChunk(
                epoch=1,
                type=CHUNK_NONE,
                chunk_index=1,
                payload=b"",
                session_id=session_id,
            )
        )
        cases.append({"name": "empty_type_nonzero_index", "result": "accepted"})
    except ValueError as e:
        cases.append(
            {"name": "empty_type_nonzero_index", "result": "reject", "reason": str(e)}
        )

    # Reassembly: index >= expected_count
    reb = BraidReassembly(epoch=1, expected_count=2)
    ch = BraidChunk(epoch=1, type=CHUNK_CT1, chunk_index=2, payload=b"z", session_id=session_id)
    cases.append({"name": "ingest_index_oob", "result": reb.ingest(ch)})

    # Reassembly: byte cap
    reb2 = BraidReassembly(epoch=1, expected_count=2, max_total_bytes=10)
    a = BraidChunk(epoch=1, type=CHUNK_CT1, chunk_index=0, payload=bytes(8), session_id=session_id)
    b = BraidChunk(epoch=1, type=CHUNK_CT1, chunk_index=1, payload=bytes(8), session_id=session_id)
    assert reb2.ingest(a) == "stored"
    cases.append({"name": "ingest_byte_cap", "result": reb2.ingest(b)})

    # Binding digest is not authentication (document in expected)
    cases.append(
        {
            "name": "binding_digest_role",
            "result": "canonical_binding_only",
            "note": "auth via outer signature then AEAD; SHA-256 binding is not a MAC",
        }
    )

    # Epoch width policy
    cases.append(
        {
            "name": "epoch_width_policy",
            "result": "u64be_no_wrap",
            "note": "EPOCH_TYPE=u64; ToBytes=big-endian; MUST NOT wrap on increment",
        }
    )

    # Global MKSKIPPED cap
    alice_priv = hashlib.sha256(b"atsam-v2/mkskip-cap/a0").digest()
    bob_priv = hashlib.sha256(b"atsam-v2/mkskip-cap/b0").digest()
    bob_priv2 = hashlib.sha256(b"atsam-v2/mkskip-cap/b1").digest()
    rk0 = hashlib.sha256(b"atsam-v2/mkskip-cap/rk").digest()
    alice = ec_dr_init_alice(rk0, alice_priv, x25519_public(bob_priv))
    bob = ec_dr_init_bob(rk0, bob_priv)
    # Seal many messages then receive last with tiny global cap
    sealed = []
    for _ in range(5):
        alice, hdr, mk = ec_dr_encrypt(alice, b"")
        sealed.append((hdr, mk))
    try:
        bob, _ = ec_dr_decrypt(
            bob,
            sealed[-1][0],
            new_local_priv=bob_priv2,
            max_mkskipped=2,
        )
        cases.append({"name": "mkskipped_global_cap", "result": "accepted"})
    except ValueError as e:
        cases.append({"name": "mkskipped_global_cap", "result": "reject", "reason": str(e)})

    return {
        "braid_header_len": BRAID_HEADER_LEN,
        "braid_digest_len": BRAID_DIGEST_LEN,
        "braid_max_payload": BRAID_MAX_PAYLOAD,
        "braid_max_chunks": BRAID_MAX_CHUNKS_PER_EPOCH,
        "braid_max_total_bytes": BRAID_MAX_TOTAL_PAYLOAD_BYTES,
        "max_mkskipped_retained": MAX_MKSKIPPED_RETAINED,
        "epoch_type": "u64",
        "mlkem768_header_size": BRAID_MLKEM768_HEADER_SIZE,
        "mlkem768_ek_vector_size": BRAID_MLKEM768_EK_VECTOR_SIZE,
        "mlkem768_ek_fips_size": BRAID_MLKEM768_EK_FIPS_SIZE,
        "mlkem768_ct1_size": BRAID_MLKEM768_CT1_SIZE,
        "mlkem768_ct2_size": BRAID_MLKEM768_CT2_SIZE,
        "cases": cases,
    }


def load_mlkem_kat() -> dict:
    root = Path(__file__).resolve().parents[3] / "shared-vectors/rvn1/atsam/mlkem768_hybrid_kat_001.json"
    return json.loads(root.read_text())


def run_braid_kem_chunk_matrix(session_id: bytes, sk_scka: bytes) -> dict:
    kat = load_mlkem_kat()
    ek = bytes.fromhex(kat["expected"]["mlkem_ek_hex"])
    ct = bytes.fromhex(kat["expected"]["mlkem_ct_hex"])
    z_pq = bytes.fromhex(kat["expected"]["z_pq_hex"])
    chunk_size = 42
    pieces = [ct[i : i + chunk_size] for i in range(0, len(ct), chunk_size)]
    wires = []
    for i, payload in enumerate(pieces):
        ch = BraidChunk(
            epoch=1,
            type=CHUNK_CT2 if i == len(pieces) - 1 else CHUNK_CT1,
            chunk_index=i,
            payload=payload,
            session_id=session_id,
        )
        wires.append(encode_braid_chunk(ch))

    order = list(range(len(pieces)))
    order = order[2:] + order[:2]
    reb = BraidReassembly(epoch=1, expected_count=len(pieces))
    for idx in order:
        ch = decode_braid_chunk(wires[idx], session_id)
        assert reb.ingest(ch) == "stored"
    body = reb.try_complete()
    assert body == ct

    tampered = bytearray(wires[0])
    tampered[-1] ^= 0x01
    try:
        decode_braid_chunk(bytes(tampered), session_id)
        tamper_result = "accepted"
    except ValueError as e:
        tamper_result = str(e)

    prev_dk = bytearray(hashlib.sha256(b"prev-epoch-dk").digest())
    ss = reb.promote_with_ss(z_pq, prev_dk)
    if any(prev_dk):
        raise AssertionError("prev dk still live after promote")
    alice = scka_from_init(True, sk_scka)
    bob = scka_from_init(False, sk_scka)
    alice_p = scka_epoch_promote_initiator(alice, ss)
    bob_p = scka_epoch_promote_responder(bob, ss)

    return {
        "mlkem_source": "atsam/mlkem768_hybrid_kat_001.json",
        "ek_len": len(ek),
        "ct_len": len(ct),
        "z_pq_hex": z_pq.hex(),
        "chunk_count": len(pieces),
        "chunk_size": chunk_size,
        "deliver_order": order,
        "reassembled_ct_ok": body == ct,
        "tamper_result": tamper_result,
        "epoch_promoted": reb.promoted,
        "prev_dk_zeroed": reb.deleted_prev_dk,
        "scka_rk_hex": alice_p.rk.hex(),
        "alice_ck_send_hex": alice_p.ck_send.hex(),
        "bob_ck_recv_hex": bob_p.ck_recv.hex(),
        "first_chunk_wire_hex": wires[0].hex(),
        "hdr_chunk_type": CHUNK_HDR,
        "ct1_chunk_type": CHUNK_CT1,
        "ct2_chunk_type": CHUNK_CT2,
    }


def run_tr_combo_matrix(
    *,
    sk_ec: bytes,
    sk_scka: bytes,
    session_id: bytes,
    alice_priv0: bytes,
    bob_priv0: bytes,
    bob_priv1: bytes,
    alice_priv1: bytes,
    ss_scka1: bytes,
    ss_scka2: bytes,
) -> dict:
    alice = ec_dr_init_alice(sk_ec, alice_priv0, x25519_public(bob_priv0))
    bob = ec_dr_init_bob(sk_ec, bob_priv0)
    a_scka = scka_from_init(True, sk_scka)
    b_scka = scka_from_init(False, sk_scka)
    steps = []

    alice, h0, mk_a0 = ec_dr_encrypt(alice, b"")
    alice, h1, mk_a1 = ec_dr_encrypt(alice, b"")
    bob, mk1 = ec_dr_decrypt(bob, h1, new_local_priv=bob_priv1)
    bob, mk0 = ec_dr_decrypt(bob, h0)
    assert mk0 == mk_a0 and mk1 == mk_a1
    a_scka, pq0 = scka_next_send_mk(a_scka)
    b_scka, pq0b = scka_next_recv_mk(b_scka)
    hy0, _ = kdf_hybrid(mk0, pq0)
    steps.append({"phase": "ec0_ooo", "hybrid_key_hex": hy0.hex()})

    a_scka = scka_epoch_promote_initiator(a_scka, ss_scka1)
    b_scka = scka_epoch_promote_responder(b_scka, ss_scka1)
    steps.append(
        {
            "phase": "scka1",
            "rk_hex": a_scka.rk.hex(),
            "alice_send_equals_bob_recv": a_scka.ck_send == b_scka.ck_recv,
        }
    )

    bob, hb, mk_b = ec_dr_encrypt(bob, b"")
    alice, mkb = ec_dr_decrypt(alice, hb, new_local_priv=alice_priv1)
    assert mkb == mk_b
    b_scka2 = scka_epoch_promote_initiator(b_scka, ss_scka2)
    a_scka2 = scka_epoch_promote_responder(a_scka, ss_scka2)
    b_scka2, pq_b = scka_next_send_mk(b_scka2)
    a_scka2, pq_a = scka_next_recv_mk(a_scka2)
    assert pq_b == pq_a
    hy1, _ = kdf_hybrid(mkb, pq_b)
    steps.append(
        {
            "phase": "ec1_scka2",
            "hybrid_key_hex": hy1.hex(),
            "bob_send_equals_alice_recv": b_scka2.ck_send == a_scka2.ck_recv,
            "alice_dh_pub1_hex": alice.dhs_pub.hex(),
            "bob_dh_pub1_hex": bob.dhs_pub.hex(),
        }
    )

    return {
        "dh_epochs": 2,
        "scka_epochs": 2,
        "session_id_hex": session_id.hex(),
        "steps": steps,
        "final_alice_ec_fp_hex": alice.fingerprint().hex(),
        "final_bob_ec_fp_hex": bob.fingerprint().hex(),
    }
