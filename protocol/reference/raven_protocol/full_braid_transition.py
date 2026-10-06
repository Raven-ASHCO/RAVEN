"""Independent Full Braid transition_prepare for Task 11 KATs (lab-only).

Computes KeysUnsampled Send Accept and NoHeaderReceived HDR Receive Accept
paths, including candidate RVFB1, RVBO1, RVBJ1 journal, and pipeline meta.
ML-KEM keygen material is supplied as a lab oracle; Authenticator MAC and
systematic SPQR chunking are computed in Python.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
from dataclasses import dataclass
from typing import Optional

from raven_protocol import full_braid_auth as auth
from raven_protocol import full_braid_digest as dig
from raven_protocol import full_braid_state as st
from raven_protocol import full_braid_wire as wire
from raven_protocol import hybrid_ratchet_v2 as tr_base
from raven_protocol import hybrid_ratchet_v2_state as scka
from raven_protocol import hybrid_ratchet_v2_tr as ec

CW = 32
L_HDR = 96
L_CT1 = 960
L_CT2 = 160
WIRE_HDR = 1
WIRE_CT1 = 5
WIRE_CT2 = 6
BRAID_RVOR_TTL_MS = 604_800_000
RVBJ1_HEADER_LEN = 366
INTENT_NORMAL = 0
MAX_REPLAYS = 64
REPLAY_RECORD_LEN = 102
BRAID_MAX_CHUNKS_PER_EPOCH = 64
AGENT_KEYS_SAMPLED = 1
AGENT_EK_SENT_CT1_RECEIVED = 4
AGENT_NO_HEADER_RECEIVED = 5
AGENT_HEADER_RECEIVED = 6
AGENT_CT1_SAMPLED = 7
FLAG_CT1_ACK_APPLIED = 1 << 2
MAX_SCKA_CHAIN = 8


@dataclass(frozen=True)
class KeygenMaterial:
    dk: bytes
    header: bytes
    ek_vector: bytes

    def __post_init__(self) -> None:
        if len(self.dk) != 2400 or len(self.header) != 64 or len(self.ek_vector) != 1152:
            raise ValueError("keygen material lengths")


@dataclass(frozen=True)
class PromoteMaterial:
    """Lab-only material at the Python reference's incremental ML-KEM boundary."""

    shared_secret: bytes
    encaps_state: bytes = b""
    ct1: bytes = b""

    def __post_init__(self) -> None:
        if len(self.shared_secret) != 32:
            raise ValueError("promote shared secret length")
        if self.encaps_state and len(self.encaps_state) != 2080:
            raise ValueError("promote encaps state length")
        if self.ct1 and len(self.ct1) != L_CT1:
            raise ValueError("promote ct1 length")


@dataclass
class PipelineMeta:
    sending_epoch: int
    receiving_epoch: int
    output_key_epoch: int
    flags: int
    terminal_reason: int
    pending_phase: int
    transition_id: bytes

    def as_dict(self) -> dict:
        return {
            "sending_epoch": self.sending_epoch,
            "receiving_epoch": self.receiving_epoch,
            "output_key_epoch": self.output_key_epoch,
            "flags": self.flags,
            "terminal_reason": self.terminal_reason,
            "pending_phase": self.pending_phase,
            "transition_id_hex": self.transition_id.hex(),
        }


@dataclass
class PipelineResult:
    candidate_bytes: bytes
    outputs_bytes: bytes
    intent_bytes: bytes
    meta: PipelineMeta


@dataclass
class TransitionMeta:
    sending_epoch: int
    receiving_epoch: int
    output_key_epoch: Optional[int]
    flags: int = 0


@dataclass
class TransitionResult:
    disposition: str
    candidate_bytes: bytes
    frame_bytes: Optional[bytes]
    ch_out_bytes: Optional[bytes]
    sealed_ct: Optional[bytes]
    meta: TransitionMeta


def mlkem_encaps_shared_secret(header: bytes, coins: bytes) -> bytes:
    """FIPS-203 Encaps preparation: G(coins || H(ek))[0:32]."""
    if len(header) != 64:
        raise ValueError("ML-KEM header length")
    if len(coins) != 32:
        raise ValueError("ML-KEM coins length")
    return hashlib.sha3_512(coins + header[32:]).digest()[:32]


def systematic_chunk(source: bytes, index: int) -> bytes:
    if len(source) % CW != 0:
        raise ValueError("source len")
    n = len(source) // CW
    if index < 0 or index >= n:
        raise ValueError("systematic index out of range")
    return source[index * CW : (index + 1) * CW]


def encode_rvbo1_frames(
    frames: list[bytes],
    ch_out: Optional[bytes] = None,
    sealed_ct: Optional[bytes] = None,
) -> bytes:
    out = bytearray(wire.RVBO1_MAGIC)
    out += wire._u16be(wire.RVBO1_SCHEMA)
    out += wire._u16be(len(frames))
    for frame in frames:
        out += wire._u32be(len(frame))
        out += frame
    if (ch_out is None) != (sealed_ct is None):
        raise ValueError("RVBO1 ch_out/sealed_ct pair")
    if ch_out is None:
        out += wire._u8(0)
    else:
        if len(ch_out) != wire.RVCH1_LEN:
            raise ValueError("RVBO1 ch_out length")
        out += wire._u8(1)
        out += ch_out
    if sealed_ct is None:
        out += wire._u8(0)
    else:
        out += wire._u8(1)
        out += wire._u32be(len(sealed_ct))
        out += sealed_ct
    return bytes(out)


def encode_rvbj1_header(
    *,
    session_id: bytes,
    role: int,
    direction: int,
    intent_kind: int,
    generation: int,
    transition_id: bytes,
    execution: bytes,
    input_d: bytes,
    before_d: bytes,
    prepared_d: bytes,
    promoted_d: bytes,
    cleared_d: bytes,
    output_d: bytes,
    object_d: bytes,
    retention_origin_ms: int,
    retention_expiry_ms: int,
    candidate_len: int,
    outputs_len: int,
) -> bytes:
    out = bytearray(b"RVBJ1\0\0\0")
    out += wire._u16be(1)
    out += session_id
    out += wire._u8(role)
    out += wire._u8(direction)
    out += wire._u8(intent_kind)
    out += wire._u8(0)
    out += wire._u64be(generation)
    out += transition_id
    out += execution
    out += input_d
    out += before_d
    out += prepared_d
    out += promoted_d
    out += cleared_d
    out += output_d
    out += object_d
    out += wire._u64be(retention_origin_ms)
    out += wire._u64be(retention_expiry_ms)
    out += wire._u32be(candidate_len)
    out += wire._u32be(outputs_len)
    if len(out) != RVBJ1_HEADER_LEN:
        raise AssertionError(f"rvbj1 header len {len(out)}")
    return bytes(out)


def _promoted_and_cleared(prepared: st.Rvfb1State) -> tuple[bytes, bytes]:
    promoted = st.Rvfb1State(
        prefix=st.Rvfb1Prefix(**{**prepared.prefix.__dict__}),
        inbound_sets=list(prepared.inbound_sets),
        active_send=prepared.active_send,
        objects=list(prepared.objects),
        replays=list(prepared.replays),
        tlvs=list(prepared.tlvs),
        tr_bytes=prepared.tr_bytes,
    )
    promoted.prefix.pending_phase = 2
    promoted.prefix.flags |= 1  # FLAG_AWAITING_COMPLETE
    promoted_bytes = st.encode_rvfb1(promoted)

    cleared = st.Rvfb1State(
        prefix=st.Rvfb1Prefix(**{**promoted.prefix.__dict__}),
        inbound_sets=list(promoted.inbound_sets),
        active_send=promoted.active_send,
        objects=list(promoted.objects),
        replays=list(promoted.replays),
        tlvs=list(promoted.tlvs),
        tr_bytes=promoted.tr_bytes,
    )
    cleared.prefix.pending_phase = 0
    cleared.prefix.pending_transition_id = bytes(32)
    cleared.prefix.pending_before_digest = bytes(32)
    cleared.prefix.pending_output_digest = bytes(32)
    cleared.prefix.pending_execution_digest = bytes(32)
    cleared.prefix.flags &= ~1
    cleared.prefix.generation = cleared.prefix.generation + 1
    cleared_bytes = st.encode_rvfb1(cleared)
    return promoted_bytes, cleared_bytes


def _prepare_candidate(
    before: st.Rvfb1State,
    before_bytes: bytes,
    candidate: st.Rvfb1State,
    direction: int,
    execution: bytes,
    input_d: bytes,
    object_d: bytes,
    outputs: bytes,
    retention_origin_ms: int,
    meta_flags: int,
    output_key_epoch: Optional[int],
    replay_window: int = MAX_REPLAYS,
) -> PipelineResult:
    if replay_window <= 0:
        raise ValueError("replay window capacity")
    before_digest = dig.state_digest(1, before_bytes)
    output_d = dig.output_digest(outputs)
    transition_id = dig.transition_id_digest(
        before.prefix.session_id,
        before.prefix.role,
        direction,
        before.prefix.generation,
        execution,
        before_digest,
    )
    # FIFO replay window: evict the oldest committed records so the new
    # (pending) record always fits.
    candidate.replays = list(candidate.replays)
    if any(r.transition_id == transition_id for r in candidate.replays):
        raise ValueError("duplicate replay transition_id")
    excess = len(candidate.replays) + 1 - min(replay_window, MAX_REPLAYS)
    if excess > 0:
        del candidate.replays[:excess]
    candidate.replays.append(
        st.ReplayRecord(
            transition_id=transition_id,
            execution_digest=execution,
            output_digest=output_d,
            output_len=len(outputs),
            flags=meta_flags,
        )
    )
    candidate.prefix.flags &= ~1
    candidate.prefix.pending_phase = 1
    candidate.prefix.pending_transition_id = transition_id
    candidate.prefix.pending_before_digest = before_digest
    candidate.prefix.pending_output_digest = output_d
    candidate.prefix.pending_execution_digest = execution

    candidate_bytes = st.encode_rvfb1(candidate)
    promoted_bytes, cleared_bytes = _promoted_and_cleared(candidate)
    retention_expiry_ms = retention_origin_ms + BRAID_RVOR_TTL_MS
    header = encode_rvbj1_header(
        session_id=before.prefix.session_id,
        role=before.prefix.role,
        direction=direction,
        intent_kind=INTENT_NORMAL,
        generation=before.prefix.generation,
        transition_id=transition_id,
        execution=execution,
        input_d=input_d,
        before_d=before_digest,
        prepared_d=dig.state_digest(1, candidate_bytes),
        promoted_d=dig.state_digest(1, promoted_bytes),
        cleared_d=dig.state_digest(1, cleared_bytes),
        output_d=output_d,
        object_d=object_d,
        retention_origin_ms=retention_origin_ms,
        retention_expiry_ms=retention_expiry_ms,
        candidate_len=len(candidate_bytes),
        outputs_len=len(outputs),
    )
    intent_bytes = header + candidate_bytes + outputs
    meta = PipelineMeta(
        sending_epoch=candidate.prefix.braid_send_epoch,
        receiving_epoch=candidate.prefix.braid_recv_epoch,
        output_key_epoch=output_key_epoch or 0,
        flags=meta_flags,
        terminal_reason=candidate.prefix.terminal_reason,
        pending_phase=candidate.prefix.pending_phase,
        transition_id=transition_id,
    )
    return PipelineResult(candidate_bytes, outputs, intent_bytes, meta)


def _apply_keys_unsampled_send(
    state: st.Rvfb1State, material: KeygenMaterial, direction: int
) -> tuple[st.Rvfb1State, bytes]:
    if state.prefix.agent != st.AGENT_KEYS_UNSAMPLED:
        raise ValueError("expected KeysUnsampled")
    ep = state.prefix.braid_agent_epoch
    auth_state = auth.AuthState(state.prefix.auth_root, state.prefix.auth_mac_key)
    tag = auth_state.mac_hdr(ep, material.header)
    source = material.header + tag
    if len(source) != L_HDR:
        raise ValueError("hdr source len")
    payload = systematic_chunk(source, 0)
    frame = wire.Rvbc1(
        epoch=ep,
        chunk_type=WIRE_HDR,
        index=0,
        payload=payload,
        binding=dig.binding_digest(
            direction, ep, WIRE_HDR, 0, payload, state.prefix.session_id
        ),
    )
    frame_bytes = wire.encode_rvbc1(frame)

    state.tlvs = [
        st.TlvEntry(1, material.dk),
        st.TlvEntry(2, material.header[:32]),
        st.TlvEntry(3, material.header[32:]),
        st.TlvEntry(4, material.ek_vector),
        st.TlvEntry(8, material.header),
    ]
    state.active_send = st.ActiveSend(
        direction=direction,
        epoch=ep,
        wire_type=WIRE_HDR,
        source_kind=st.SOURCE_KIND_HDR,
        source_len=len(source),
        source_digest=dig.send_source_digest(source),
        source_bytes=source,
        next_spqr_index=1,
    )
    state.prefix.agent = AGENT_KEYS_SAMPLED
    state.prefix.braid_send_epoch = ep - 1
    return state, frame_bytes


def validate_role_mode(role: int, op: int, direction: int) -> None:
    """Mirror Rust `validate_role_mode` (Parse on mismatch)."""
    expected = {
        (st.ROLE_ALICE, wire.OP_SEND): st.DIR_A2B,
        (st.ROLE_ALICE, wire.OP_RECEIVE): st.DIR_B2A,
        (st.ROLE_BOB, wire.OP_SEND): st.DIR_B2A,
        (st.ROLE_BOB, wire.OP_RECEIVE): st.DIR_A2B,
    }.get((role, op))
    if expected is None or direction != expected:
        raise ValueError("role/op/direction")


def validate_chunk_contract(frame: wire.Rvbc1) -> None:
    if frame.chunk_type in (0, 4):  # WIRE_NONE | WIRE_CT1_ACK
        if frame.index != 0 or frame.payload:
            raise ValueError("rvbc1 chunk contract")
    elif frame.chunk_type in (1, 2, 3, 5, 6):  # HDR/EK/EK_CT1_ACK/CT1/CT2
        if frame.index > 63 or len(frame.payload) != CW:
            raise ValueError("rvbc1 chunk contract")
    else:
        raise ValueError("rvbc1 chunk type")


def verify_frame_binding(
    frame: wire.Rvbc1, direction: int, session_id: bytes
) -> None:
    """Recompute binding and constant-time compare (before any mutation)."""
    expected = dig.binding_digest(
        direction,
        frame.epoch,
        frame.chunk_type,
        frame.index,
        frame.payload,
        session_id,
    )
    if not hmac.compare_digest(expected, frame.binding):
        raise ValueError("binding digest mismatch")


def decode_and_validate_frame(
    state: st.Rvfb1State, inp: wire.Rvbi1
) -> wire.Rvbc1:
    if inp.frame is None:
        raise ValueError("receive frame")
    frame = wire.decode_rvbc1(inp.frame)
    verify_frame_binding(frame, inp.direction, state.prefix.session_id)
    validate_chunk_contract(frame)
    return frame


def _apply_hdr_receive(state: st.Rvfb1State, frame: wire.Rvbc1) -> st.Rvfb1State:
    if state.prefix.agent != AGENT_NO_HEADER_RECEIVED:
        raise ValueError("expected NoHeaderReceived")
    ep = state.prefix.braid_agent_epoch
    if frame.epoch != ep or frame.chunk_type != WIRE_HDR:
        raise ValueError("hdr receive frame mismatch")
    # Insert chunk 0 into existing empty HDR inbound set (no reconstruct yet).
    if len(state.inbound_sets) != 1:
        raise ValueError("bob inbound sets")
    inbound = state.inbound_sets[0]
    if inbound.source_kind != st.SOURCE_KIND_HDR or inbound.chunks:
        raise ValueError("bob inbound not empty hdr")
    bitmap = bytearray(inbound.bitmap)
    bitmap[frame.index // 8] |= 1 << (frame.index % 8)
    inbound.bitmap = bytes(bitmap)
    inbound.chunks = [st.InboundChunk(frame.index, frame.payload)]
    state.prefix.braid_recv_epoch = ep - 1
    return state


def _tlv_value(state: st.Rvfb1State, tag: int, length: int) -> bytes:
    value = next((entry.value for entry in state.tlvs if entry.tag == tag), None)
    if value is None or len(value) != length:
        raise ValueError(f"TLV {tag} length")
    return value


def _header_from_tlvs(state: st.Rvfb1State) -> bytes:
    return _tlv_value(state, 2, 32) + _tlv_value(state, 3, 32)


def _new_active_send(
    state: st.Rvfb1State,
    direction: int,
    epoch: int,
    wire_type: int,
    source_kind: int,
    source: bytes,
) -> st.ActiveSend:
    return st.ActiveSend(
        direction=direction,
        epoch=epoch,
        wire_type=wire_type,
        source_kind=source_kind,
        source_len=len(source),
        source_digest=dig.send_source_digest(source),
        source_bytes=source,
        next_spqr_index=0,
    )


def _emit_active(state: st.Rvfb1State) -> wire.Rvbc1:
    active = state.active_send
    if active is None:
        raise ValueError("active send required")
    if (
        active.epoch != state.prefix.braid_agent_epoch
        or active.next_spqr_index > BRAID_MAX_CHUNKS_PER_EPOCH
    ):
        raise ValueError("active send contract")
    # The cursor cycles through the 64-index space (64 = legacy sentinel → 0).
    index = 0 if active.next_spqr_index > 63 else active.next_spqr_index
    payload = systematic_chunk(active.source_bytes, index)
    frame = wire.Rvbc1(
        epoch=active.epoch,
        chunk_type=active.wire_type,
        index=index,
        payload=payload,
        binding=dig.binding_digest(
            active.direction,
            active.epoch,
            active.wire_type,
            index,
            payload,
            state.prefix.session_id,
        ),
    )
    active.next_spqr_index = (index + 1) % BRAID_MAX_CHUNKS_PER_EPOCH
    return frame


def _empty_inbound_set(direction: int, epoch: int, source_kind: int) -> st.InboundSet:
    expected_len = st.SOURCE_LENGTHS[source_kind]
    return st.InboundSet(
        direction=direction,
        epoch=epoch,
        source_kind=source_kind,
        expected_source_len=expected_len,
        max_index=63,
        bitmap=bytes(8),
        chunks=[],
    )


def _insert_systematic_frame(
    state: st.Rvfb1State,
    direction: int,
    frame: wire.Rvbc1,
    source_kind: int,
) -> Optional[bytes]:
    key = (direction, frame.epoch, source_kind)
    inbound = next(
        (
            item
            for item in state.inbound_sets
            if (item.direction, item.epoch, item.source_kind) == key
        ),
        None,
    )
    if inbound is None:
        inbound = _empty_inbound_set(direction, frame.epoch, source_kind)
        state.inbound_sets.append(inbound)
        state.inbound_sets.sort(
            key=lambda item: (item.direction, item.epoch, item.source_kind)
        )
    if (
        inbound.expected_source_len != st.SOURCE_LENGTHS[source_kind]
        or inbound.max_index != 63
        or len(inbound.bitmap) != 8
    ):
        raise ValueError("inbound set contract")
    existing = next(
        (chunk for chunk in inbound.chunks if chunk.index == frame.index), None
    )
    if existing is not None:
        if existing.payload != frame.payload:
            raise ValueError("conflicting inbound chunk")
    else:
        inbound.chunks.append(st.InboundChunk(frame.index, frame.payload))
        inbound.chunks.sort(key=lambda chunk: chunk.index)
        bitmap = bytearray(inbound.bitmap)
        bitmap[frame.index // 8] |= 1 << (frame.index % 8)
        inbound.bitmap = bytes(bitmap)

    needed = inbound.expected_source_len // CW
    by_index = {chunk.index: chunk.payload for chunk in inbound.chunks}
    if all(index in by_index for index in range(needed)):
        return b"".join(by_index[index] for index in range(needed))
    return None


def _rvft1_to_ec(value: st.Rvft1) -> ec.EcDrState:
    skipped = {
        entry.dh_pub + entry.n.to_bytes(4, "big"): entry.mk
        for entry in value.ec_skipped
    }
    return ec.EcDrState(
        rk=value.ec_rk,
        dhs_priv=value.ec_dhs_priv,
        dhs_pub=value.ec_dhs_pub,
        dhr_pub=value.ec_dhr_pub if value.ec_dhr_present == 1 else None,
        cks=value.ec_ck_send if value.ec_ck_send_present == 1 else None,
        ckr=value.ec_ck_recv if value.ec_ck_recv_present == 1 else None,
        ns=value.ec_ns,
        nr=value.ec_nr,
        pn=value.ec_pn,
        mkskipped=skipped,
    )


def _apply_ec_to_rvft1(value: st.Rvft1, candidate: ec.EcDrState) -> None:
    value.ec_rk = candidate.rk
    value.ec_dhs_priv = candidate.dhs_priv
    value.ec_dhs_pub = candidate.dhs_pub
    value.ec_dhr_present = int(candidate.dhr_pub is not None)
    value.ec_dhr_pub = candidate.dhr_pub or bytes(32)
    value.ec_ck_send_present = int(candidate.cks is not None)
    value.ec_ck_send = candidate.cks or bytes(32)
    value.ec_ck_recv_present = int(candidate.ckr is not None)
    value.ec_ck_recv = candidate.ckr or bytes(32)
    value.ec_ns = candidate.ns
    value.ec_nr = candidate.nr
    value.ec_pn = candidate.pn
    value.ec_skipped = [
        st.EcSkippedEntry(key[:32], int.from_bytes(key[32:], "big"), mk)
        for key, mk in sorted(candidate.mkskipped.items())
    ]


def _insert_scka_chain(
    chain: list[st.SckaChainEntry], entry: st.SckaChainEntry
) -> None:
    chain[:] = [existing for existing in chain if existing.epoch != entry.epoch]
    chain.append(entry)
    chain.sort(key=lambda existing: existing.epoch)
    if len(chain) > MAX_SCKA_CHAIN:
        del chain[0]


def _promote_scka_send(value: st.Rvft1, epoch: int, output_key: bytes) -> None:
    root, chain_key = scka.kdf_scka_rk(value.scka_rk, output_key)
    value.scka_rk = root
    value.scka_sending_epoch = epoch
    _insert_scka_chain(
        value.scka_send_chain, st.SckaChainEntry(epoch, chain_key, 0)
    )


def _promote_scka_receive(value: st.Rvft1, epoch: int, output_key: bytes) -> None:
    root, chain_key = scka.kdf_scka_rk(value.scka_rk, output_key)
    value.scka_rk = root
    value.scka_receiving_epoch = epoch
    _insert_scka_chain(
        value.scka_recv_chain, st.SckaChainEntry(epoch, chain_key, 0)
    )


def _transcript_addr_binding(
    session_id: bytes,
    party: int,
    cert_digest: bytes,
    identity_pub: bytes,
) -> bytes:
    return hashlib.sha256(
        b"ATSAM/v2/full-braid/transcript-addr"
        + session_id
        + bytes([party])
        + cert_digest
        + identity_pub
    ).digest()


def _expected_rvba1(
    session_id: bytes,
    direction: int,
    evidence: wire.AdmittedTrustEvidence,
) -> bytes:
    sender_cert = (
        evidence.initiator_cert_digest
        if direction == st.DIR_A2B
        else evidence.responder_cert_digest
    )
    out = (
        b"RVBA1\0\0\0"
        + wire._u16be(1)
        + hashlib.sha256(tr_base.PROFILE).digest()
        + session_id
        + wire._u16be(1)
        + wire._u16be(0x0004)
        + wire._u8(direction)
        + wire._u8(0)
        + _transcript_addr_binding(
            session_id,
            0,
            evidence.initiator_cert_digest,
            evidence.initiator_identity_pub,
        )
        + _transcript_addr_binding(
            session_id,
            1,
            evidence.responder_cert_digest,
            evidence.responder_identity_pub,
        )
        + sender_cert
    )
    if len(out) != wire.RVBA1_LEN:
        raise AssertionError("RVBA1 length")
    return out


def _validate_rvba1(
    state: st.Rvfb1State, inp: wire.Rvbi1, env: wire.Rvbe1
) -> None:
    evidence = env.admitted_trust
    if evidence is None:
        raise ValueError("admitted trust required")
    expected = _expected_rvba1(state.prefix.session_id, inp.direction, evidence)
    if not hmac.compare_digest(inp.mutation.aad, expected):
        raise ValueError("RVBA1 admitted trust")


def _effective_ad(rvba1: bytes, rvch1: bytes, rvbc1: bytes) -> bytes:
    return (
        wire._u32be(len(rvba1))
        + rvba1
        + wire._u32be(len(rvch1))
        + rvch1
        + wire._u32be(len(rvbc1))
        + rvbc1
    )


def _check_ec_mk_oracle(mutation: wire.Rvbm1, message_key: bytes) -> None:
    if mutation.ec_mk_oracle_len == 0:
        if mutation.ec_mk_oracle != bytes(32):
            raise ValueError("EC message-key oracle")
    elif mutation.ec_mk_oracle_len == 32:
        if not hmac.compare_digest(mutation.ec_mk_oracle, message_key):
            raise ValueError("EC message-key oracle mismatch")
    else:
        raise ValueError("EC message-key oracle length")


def _send_rvch1(value: st.Rvft1, direction: int, epoch: int) -> wire.Rvch1:
    scka_n = next(
        (
            entry.n
            for entry in value.scka_send_chain
            if entry.epoch == epoch
        ),
        0,
    )
    return wire.Rvch1(
        ec_dh_pub=value.ec_dhs_pub,
        ec_pn=value.ec_pn,
        ec_n=value.ec_ns,
        scka_epoch=epoch,
        scka_pn=value.scka_send_pn,
        scka_n=scka_n,
        direction=direction,
    )


def _confirm_send(
    state: st.Rvfb1State,
    inp: wire.Rvbi1,
    env: wire.Rvbe1,
    frame: wire.Rvbc1,
    output_key: bytes,
    epoch: int,
) -> tuple[bytes, bytes]:
    mutation = inp.mutation
    if mutation.needs_aead != 1 or mutation.mode != wire.MODE_SEAL_COMPARE:
        raise ValueError("send AEAD mutation")
    _validate_rvba1(state, inp, env)
    tr = st.decode_rvft1(state.tr_bytes)
    ch = _send_rvch1(tr, inp.direction, epoch)
    current = _rvft1_to_ec(tr)
    ec_candidate, header, ec_mk = ec.ec_dr_encrypt(current, b"")
    if (
        header["dh_pub"] != ch.ec_dh_pub
        or header["pn"] != ch.ec_pn
        or header["n"] != ch.ec_n
    ):
        raise ValueError("send RVCH1 context")
    ch_bytes = wire.encode_rvch1(ch)
    frame_bytes = wire.encode_rvbc1(frame)
    aad = _effective_ad(mutation.aad, ch_bytes, frame_bytes)
    _check_ec_mk_oracle(mutation, ec_mk)
    key, nonce = tr_base.kdf_hybrid(ec_mk, output_key)
    sealed = tr_base.aead_seal(key, nonce, mutation.body, aad)
    if mutation.expected_ct is None or not hmac.compare_digest(
        sealed, mutation.expected_ct
    ):
        raise ValueError("AEAD seal comparison")
    _apply_ec_to_rvft1(tr, ec_candidate)
    state.tr_bytes = st.encode_rvft1(tr)
    return ch_bytes, sealed


def _materialize_ec_dh_priv(
    seed: bytes, session_id: bytes, generation: int
) -> bytes:
    if len(seed) != 32:
        raise ValueError("EC DH seed length")
    value = hmac.new(
        seed,
        b"ATSAM/v2/full-braid/ec-dh-seed"
        + session_id
        + generation.to_bytes(8, "big"),
        hashlib.sha256,
    ).digest()
    ec.x25519_public(value)
    return value


def _confirm_receive(
    state: st.Rvfb1State,
    inp: wire.Rvbi1,
    env: wire.Rvbe1,
    frame: wire.Rvbc1,
    output_key: bytes,
    epoch: int,
) -> None:
    mutation = inp.mutation
    if (
        mutation.needs_aead != 1
        or mutation.mode != wire.MODE_OPEN
        or inp.ch is None
    ):
        raise ValueError("receive AEAD mutation")
    _validate_rvba1(state, inp, env)
    ch = inp.ch
    if inp.expected_ch is not None and inp.expected_ch != ch:
        raise ValueError("receive expected RVCH1")
    if ch.direction != inp.direction or ch.scka_epoch != epoch:
        raise ValueError("receive RVCH1 context")
    tr = st.decode_rvft1(state.tr_bytes)
    if (
        tr.ec_dhr_present == 1
        and ch.ec_dh_pub == tr.ec_dhr_pub
        and ch.ec_n < tr.ec_nr
    ):
        raise ValueError("receive EC counter rewind")
    new_local = (
        _materialize_ec_dh_priv(
            env.ec_dh_seed, state.prefix.session_id, state.prefix.generation
        )
        if env.ec_dh_seed
        else None
    )
    current = _rvft1_to_ec(tr)
    ec_candidate, ec_mk = ec.ec_dr_decrypt(
        current,
        {"dh_pub": ch.ec_dh_pub, "pn": ch.ec_pn, "n": ch.ec_n},
        new_local_priv=new_local,
    )
    ch_bytes = wire.encode_rvch1(ch)
    frame_bytes = wire.encode_rvbc1(frame)
    aad = _effective_ad(mutation.aad, ch_bytes, frame_bytes)
    _check_ec_mk_oracle(mutation, ec_mk)
    key, nonce = tr_base.kdf_hybrid(ec_mk, output_key)
    plaintext = tr_base.aead_open(key, nonce, mutation.body, aad)
    if len(plaintext) > wire.BRAID_MAX_AEAD_PLAINTEXT_BYTES:
        raise ValueError("AEAD plaintext length")
    _apply_ec_to_rvft1(tr, ec_candidate)
    state.tr_bytes = st.encode_rvft1(tr)


def _first_ct1_frame(
    state: st.Rvfb1State, direction: int, epoch: int, ct1: bytes
) -> wire.Rvbc1:
    """The encapsulator's first CT1 frame (index 0) for `epoch`.

    Both nested TR confirms bind this exact RVBC1 into the AEAD AD, so the
    keygen side opens the peer's one `sealed_ct` and no hybrid key seals twice.
    """
    payload = systematic_chunk(ct1, 0)
    return wire.Rvbc1(
        epoch=epoch,
        chunk_type=WIRE_CT1,
        index=0,
        payload=payload,
        binding=dig.binding_digest(
            direction, epoch, WIRE_CT1, 0, payload, state.prefix.session_id
        ),
    )


def _apply_header_received_send(
    state: st.Rvfb1State,
    inp: wire.Rvbi1,
    env: wire.Rvbe1,
    material: PromoteMaterial,
) -> tuple[wire.Rvbc1, bytes, bytes, int]:
    if state.prefix.agent != AGENT_HEADER_RECEIVED:
        raise ValueError("expected HeaderReceived")
    if not material.encaps_state or not material.ct1:
        raise ValueError("Encaps1 material required")
    header = _header_from_tlvs(state)
    derived_secret = mlkem_encaps_shared_secret(header, env.encaps_coins)
    if not hmac.compare_digest(derived_secret, material.shared_secret):
        raise ValueError("Encaps1 shared-secret oracle mismatch")
    if material.encaps_state[-32:] != env.encaps_coins:
        raise ValueError("Encaps1 state randomness mismatch")
    epoch = state.prefix.braid_agent_epoch
    output_key = auth.kdf_ok(material.shared_secret, epoch)
    auth_state = auth.AuthState(state.prefix.auth_root, state.prefix.auth_mac_key)
    auth_state.update(epoch, output_key)
    state.prefix.auth_root = auth_state.root_key
    state.prefix.auth_mac_key = auth_state.mac_key
    rho = _tlv_value(state, 2, 32)
    hek = _tlv_value(state, 3, 32)
    state.tlvs = [
        st.TlvEntry(2, rho),
        st.TlvEntry(3, hek),
        st.TlvEntry(5, material.encaps_state),
        st.TlvEntry(6, material.ct1),
    ]
    state.active_send = _new_active_send(
        state, inp.direction, epoch, WIRE_CT1, st.SOURCE_KIND_CT1, material.ct1
    )
    state.prefix.agent = AGENT_CT1_SAMPLED
    frame = _emit_active(state)
    ch_out, sealed_ct = _confirm_send(
        state, inp, env, frame, output_key, epoch
    )
    tr = st.decode_rvft1(state.tr_bytes)
    _promote_scka_send(tr, epoch, output_key)
    state.tr_bytes = st.encode_rvft1(tr)
    state.prefix.braid_send_epoch = epoch - 1
    return frame, ch_out, sealed_ct, epoch


def _apply_ek_sent_ct1_received_receive(
    state: st.Rvfb1State,
    inp: wire.Rvbi1,
    env: wire.Rvbe1,
    frame: wire.Rvbc1,
    material: PromoteMaterial,
) -> int:
    if state.prefix.agent != AGENT_EK_SENT_CT1_RECEIVED:
        raise ValueError("expected EkSentCt1Received")
    epoch = state.prefix.braid_agent_epoch
    if frame.epoch != epoch or frame.chunk_type != WIRE_CT2:
        raise ValueError("CT2 receive frame mismatch")
    source = _insert_systematic_frame(
        state, inp.direction, frame, st.SOURCE_KIND_CT2
    )
    if source is None or len(source) != L_CT2:
        raise ValueError("CT2 source incomplete")
    ct2 = source[:128]
    expected_mac = source[128:]
    _tlv_value(state, 1, 2400)  # Decapsulation key boundary is present/canonical.
    ct1 = _tlv_value(state, 6, L_CT1)
    output_key = auth.kdf_ok(material.shared_secret, epoch)
    auth_state = auth.AuthState(state.prefix.auth_root, state.prefix.auth_mac_key)
    auth_state.update(epoch, output_key)
    if not auth_state.verify_ct(epoch, ct1 + ct2, expected_mac):
        raise ValueError("CT2 authenticator")
    state.prefix.auth_root = auth_state.root_key
    state.prefix.auth_mac_key = auth_state.mac_key
    confirm_frame = _first_ct1_frame(state, inp.direction, epoch, ct1)
    _confirm_receive(state, inp, env, confirm_frame, output_key, epoch)
    tr = st.decode_rvft1(state.tr_bytes)
    _promote_scka_receive(tr, epoch, output_key)
    state.tr_bytes = st.encode_rvft1(tr)

    next_epoch = epoch + 1
    state.prefix.braid_agent_epoch = next_epoch
    state.prefix.braid_recv_epoch = epoch - 1
    state.prefix.agent = AGENT_NO_HEADER_RECEIVED
    state.prefix.flags &= ~FLAG_CT1_ACK_APPLIED
    state.tlvs.clear()
    state.active_send = None
    state.inbound_sets = [
        _empty_inbound_set(inp.direction, next_epoch, st.SOURCE_KIND_HDR)
    ]
    return epoch


def transition(
    state_bytes: bytes,
    input_bytes: bytes,
    env_bytes: bytes,
    keygen_material: Optional[KeygenMaterial] = None,
    promote_material: Optional[PromoteMaterial] = None,
) -> TransitionResult:
    before = st.decode_rvfb1(state_bytes)
    if st.encode_rvfb1(before) != state_bytes:
        raise ValueError("before state not canonical")
    if before.prefix.pending_phase != 0:
        raise ValueError("pending phase")
    inp = wire.decode_rvbi1(input_bytes)
    if wire.encode_rvbi1(inp) != input_bytes:
        raise ValueError("input not canonical")
    env = wire.decode_rvbe1(env_bytes)
    if wire.encode_rvbe1(env) != env_bytes:
        raise ValueError("env not canonical")

    validate_role_mode(before.prefix.role, inp.op, inp.direction)

    candidate = st.decode_rvfb1(state_bytes)  # deep-ish copy via roundtrip
    frame_bytes = None
    ch_out_bytes = None
    sealed_ct = None
    output_key_epoch = None

    if inp.op == wire.OP_SEND:
        if candidate.prefix.agent == st.AGENT_KEYS_UNSAMPLED:
            if keygen_material is None:
                raise ValueError("keygen material required for send")
            if len(env.keygen_seed) != 64:
                raise ValueError("keygen seed required")
            candidate, frame_bytes = _apply_keys_unsampled_send(
                candidate, keygen_material, inp.direction
            )
        elif candidate.prefix.agent == AGENT_HEADER_RECEIVED:
            if promote_material is None:
                raise ValueError("promote material required for send")
            frame, ch_out_bytes, sealed_ct, output_key_epoch = (
                _apply_header_received_send(
                    candidate, inp, env, promote_material
                )
            )
            frame_bytes = wire.encode_rvbc1(frame)
        else:
            raise ValueError("unsupported send agent")
    elif inp.op == wire.OP_RECEIVE:
        # Binding + chunk contract BEFORE any candidate mutation.
        frame = decode_and_validate_frame(before, inp)
        if candidate.prefix.agent == AGENT_NO_HEADER_RECEIVED:
            candidate = _apply_hdr_receive(candidate, frame)
        elif candidate.prefix.agent == AGENT_EK_SENT_CT1_RECEIVED:
            if promote_material is None:
                raise ValueError("promote material required for receive")
            output_key_epoch = _apply_ek_sent_ct1_received_receive(
                candidate, inp, env, frame, promote_material
            )
        else:
            raise ValueError("unsupported receive agent")
    else:
        raise ValueError("unsupported op")

    candidate_bytes = st.encode_rvfb1(candidate)
    return TransitionResult(
        disposition="accept",
        candidate_bytes=candidate_bytes,
        frame_bytes=frame_bytes,
        ch_out_bytes=ch_out_bytes,
        sealed_ct=sealed_ct,
        meta=TransitionMeta(
            sending_epoch=candidate.prefix.braid_send_epoch,
            receiving_epoch=candidate.prefix.braid_recv_epoch,
            output_key_epoch=output_key_epoch,
        ),
    )


RVFI1_MAGIC = b"RVFI1\0\0\0"
RVFI1_LEN = 176


def init_write(rvfi1: bytes) -> bytes:
    """RVFI1 → initial canonical RVFB1 (mirror of Rust `init_write`).

    `SK_ec` is only the EC root (§3.3): Alice ratchets with her ephemeral
    `role_material`, Bob with his SPK private key (`role_material`).
    """
    if len(rvfi1) != RVFI1_LEN or rvfi1[:8] != RVFI1_MAGIC:
        raise ValueError("rvfi1 framing")
    if int.from_bytes(rvfi1[8:10], "big") != 1:
        raise ValueError("rvfi1 bad schema")
    session_id = rvfi1[10:42]
    role, reserved0 = rvfi1[42], rvfi1[43]
    if role not in (st.ROLE_ALICE, st.ROLE_BOB) or reserved0 != 0:
        raise ValueError("rvfi1 role")
    sk_ec, sk_scka = rvfi1[44:76], rvfi1[76:108]
    bob_spk_pub, role_material = rvfi1[108:140], rvfi1[140:172]
    if rvfi1[172:176] != bytes(4):
        raise ValueError("rvfi1 reserved_tail")

    if role == st.ROLE_ALICE:
        ec_state = ec.ec_dr_init_alice(sk_ec, role_material, bob_spk_pub)
        scka_init = tr_base.ratchet_init_alice_scka(sk_scka)
        agent = st.AGENT_KEYS_UNSAMPLED
        inbound_sets: list[st.InboundSet] = []
    else:
        if ec.x25519_public(role_material) != bob_spk_pub:
            raise ValueError("rvfi1 bob spk mismatch")
        ec_state = ec.ec_dr_init_bob(sk_ec, role_material)
        scka_init = tr_base.ratchet_init_bob_scka(sk_scka)
        agent = st.AGENT_NO_HEADER_RECEIVED
        inbound_sets = [_empty_inbound_set(st.DIR_A2B, 1, st.SOURCE_KIND_HDR)]

    tr = st.Rvft1(
        scka_rk=scka_init.rk,
        scka_sending_epoch=0,
        scka_receiving_epoch=0,
        scka_send_chain=[st.SckaChainEntry(0, scka_init.ck_send, 0)],
        scka_recv_chain=[st.SckaChainEntry(0, scka_init.ck_recv, 0)],
        scka_send_pn=0,
        scka_skipped=[],
        ec_rk=bytes(32),
        ec_dhs_priv=bytes(32),
        ec_dhs_pub=bytes(32),
        ec_dhr_present=0,
        ec_dhr_pub=bytes(32),
        ec_ck_send_present=0,
        ec_ck_recv_present=0,
        ec_ck_send=bytes(32),
        ec_ck_recv=bytes(32),
        ec_ns=0,
        ec_nr=0,
        ec_pn=0,
        ec_skipped=[],
    )
    _apply_ec_to_rvft1(tr, ec_state)
    auth_state = auth.AuthState.init(1, sk_scka)
    state = st.Rvfb1State(
        prefix=st.Rvfb1Prefix(
            session_id=session_id,
            role=role,
            generation=0,
            agent=agent,
            terminal_reason=0,
            auth_root=auth_state.root_key,
            auth_mac_key=auth_state.mac_key,
            braid_agent_epoch=1,
            braid_send_epoch=0,
            braid_recv_epoch=0,
            flags=0,
            pending_phase=0,
            pending_transition_id=bytes(32),
            pending_before_digest=bytes(32),
            pending_output_digest=bytes(32),
            pending_execution_digest=bytes(32),
        ),
        inbound_sets=inbound_sets,
        active_send=None,
        objects=[],
        replays=[],
        tlvs=[],
        tr_bytes=st.encode_rvft1(tr),
    )
    return st.encode_rvfb1(state)


def journal_input_digest(inp: wire.Rvbi1) -> bytes:
    """RVBJ1/RVOR1 input digest with any mode-0 plaintext zeroed.

    The plaintext stays bound through `expected_ct`; the persisted digest no
    longer lets a storage dump confirm guessed plaintexts offline.
    """
    mutation = inp.mutation
    if mutation.needs_aead != 1 or mutation.mode != wire.MODE_SEAL_COMPARE:
        return dig.input_digest(wire.encode_rvbi1(inp))
    redacted = dataclasses.replace(
        inp,
        mutation=dataclasses.replace(mutation, body=bytes(len(mutation.body))),
    )
    return dig.input_digest(wire.encode_rvbi1(redacted))


def replay_window(env: wire.Rvbe1) -> int:
    return min(
        MAX_REPLAYS,
        env.cap_replay_entries,
        env.cap_replay_bytes // REPLAY_RECORD_LEN,
    )


def transition_prepare(
    state_bytes: bytes,
    input_bytes: bytes,
    env_bytes: bytes,
    keygen_material: Optional[KeygenMaterial] = None,
    promote_material: Optional[PromoteMaterial] = None,
) -> PipelineResult:
    before = st.decode_rvfb1(state_bytes)
    inp = wire.decode_rvbi1(input_bytes)
    env = wire.decode_rvbe1(env_bytes)
    transitioned = transition(
        state_bytes,
        input_bytes,
        env_bytes,
        keygen_material=keygen_material,
        promote_material=promote_material,
    )
    candidate = st.decode_rvfb1(transitioned.candidate_bytes)
    if transitioned.frame_bytes is None:
        outputs = wire.encode_empty_rvbo1()
    else:
        outputs = encode_rvbo1_frames(
            [transitioned.frame_bytes],
            transitioned.ch_out_bytes,
            transitioned.sealed_ct,
        )

    return _prepare_candidate(
        before,
        state_bytes,
        candidate,
        inp.direction,
        dig.execution_digest(input_bytes, env_bytes),
        journal_input_digest(inp),
        inp.object_digest or bytes(32),
        outputs,
        env.clock,
        transitioned.meta.flags,
        transitioned.meta.output_key_epoch,
        replay_window(env),
    )
