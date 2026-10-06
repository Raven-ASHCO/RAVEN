"""Canonical RVFB1 subset used by the independent Full Braid transition KAT."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from raven_protocol.full_braid_wire import (
    WireReader,
    expect_magic,
    reject_trailing,
)

RVFB1_MAGIC = b"RVFB1\0\0\0"
RVFB1_SCHEMA = 1
RVFB1_PREFIX_LEN = 275
RVFT1_MAGIC = b"RVFT1\0\0\0"
RVFT1_SCHEMA = 1
RVFT1_MAX_SIZE = 80_505
MAX_SCKA_CHAIN = 8
MAX_SCKA_SKIPPED = 256
MAX_EC_SKIPPED = 1000

ROLE_ALICE = 0
ROLE_BOB = 1
DIR_A2B = 0
DIR_B2A = 1

AGENT_KEYS_UNSAMPLED = 0
AGENT_KEYS_SAMPLED = 1
AGENT_NO_HEADER_RECEIVED = 5

SOURCE_KIND_HDR = 1
SOURCE_KIND_EK = 2
SOURCE_KIND_CT1 = 5
SOURCE_KIND_CT2 = 6

SOURCE_LENGTHS = {
    SOURCE_KIND_HDR: 96,
    SOURCE_KIND_EK: 1152,
    SOURCE_KIND_CT1: 960,
    SOURCE_KIND_CT2: 160,
}
TLV_LENGTHS = {1: 2400, 2: 32, 3: 32, 4: 1152, 5: 2080, 6: 960, 7: 128, 8: 64}


def _u8(value: int) -> bytes:
    return int(value).to_bytes(1, "big")


def _u16(value: int) -> bytes:
    return int(value).to_bytes(2, "big")


def _u32(value: int) -> bytes:
    return int(value).to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return int(value).to_bytes(8, "big")


def _require_len(value: bytes, length: int, field_name: str) -> None:
    if len(value) != length:
        raise ValueError(f"{field_name} must be {length} bytes")


def _strictly_sorted(values: Iterable, key, field_name: str) -> None:
    keys = [key(value) for value in values]
    if any(left >= right for left, right in zip(keys, keys[1:])):
        raise ValueError(f"{field_name} not strictly sorted")


@dataclass
class Rvfb1Prefix:
    session_id: bytes
    role: int
    generation: int
    agent: int
    terminal_reason: int
    auth_root: bytes
    auth_mac_key: bytes
    braid_agent_epoch: int
    braid_send_epoch: int
    braid_recv_epoch: int
    flags: int
    pending_phase: int
    pending_transition_id: bytes
    pending_before_digest: bytes
    pending_output_digest: bytes
    pending_execution_digest: bytes


@dataclass
class InboundChunk:
    index: int
    payload: bytes


@dataclass
class InboundSet:
    direction: int
    epoch: int
    source_kind: int
    expected_source_len: int
    max_index: int
    bitmap: bytes
    chunks: list[InboundChunk] = field(default_factory=list)


@dataclass
class ActiveSend:
    direction: int
    epoch: int
    wire_type: int
    source_kind: int
    source_len: int
    source_digest: bytes
    source_bytes: bytes
    next_spqr_index: int


@dataclass
class BraidObject:
    direction: int
    epoch: int
    source_kind: int
    object_digest: bytes


@dataclass
class ReplayRecord:
    transition_id: bytes
    execution_digest: bytes
    output_digest: bytes
    output_len: int
    flags: int


@dataclass
class TlvEntry:
    tag: int
    value: bytes


@dataclass
class SckaChainEntry:
    epoch: int
    ck: bytes
    n: int


@dataclass
class SckaSkippedEntry:
    direction: int
    epoch: int
    n: int
    mk: bytes


@dataclass
class EcSkippedEntry:
    dh_pub: bytes
    n: int
    mk: bytes


@dataclass
class Rvft1:
    scka_rk: bytes
    scka_sending_epoch: int
    scka_receiving_epoch: int
    scka_send_chain: list[SckaChainEntry]
    scka_recv_chain: list[SckaChainEntry]
    scka_send_pn: int
    scka_skipped: list[SckaSkippedEntry]
    ec_rk: bytes
    ec_dhs_priv: bytes
    ec_dhs_pub: bytes
    ec_dhr_present: int
    ec_dhr_pub: bytes
    ec_ck_send_present: int
    ec_ck_recv_present: int
    ec_ck_send: bytes
    ec_ck_recv: bytes
    ec_ns: int
    ec_nr: int
    ec_pn: int
    ec_skipped: list[EcSkippedEntry]


@dataclass
class Rvfb1State:
    prefix: Rvfb1Prefix
    inbound_sets: list[InboundSet]
    active_send: ActiveSend | None
    objects: list[BraidObject]
    replays: list[ReplayRecord]
    tlvs: list[TlvEntry]
    tr_bytes: bytes


def _validate_optional_key(present: int, key: bytes, field_name: str) -> None:
    _require_len(key, 32, field_name)
    if present == 0:
        if key != bytes(32):
            raise ValueError(f"{field_name} must be zero when absent")
    elif present != 1:
        raise ValueError(f"{field_name}_present")


def _validate_rvft1(value: Rvft1) -> None:
    for field_name in ("scka_rk", "ec_rk", "ec_dhs_priv", "ec_dhs_pub"):
        _require_len(getattr(value, field_name), 32, field_name)
    if len(value.scka_send_chain) > MAX_SCKA_CHAIN:
        raise ValueError("rvft1 scka send cap")
    if len(value.scka_recv_chain) > MAX_SCKA_CHAIN:
        raise ValueError("rvft1 scka recv cap")
    if len(value.scka_skipped) > MAX_SCKA_SKIPPED:
        raise ValueError("rvft1 scka skipped cap")
    if len(value.ec_skipped) > MAX_EC_SKIPPED:
        raise ValueError("rvft1 ec skipped cap")
    _strictly_sorted(
        value.scka_send_chain, lambda entry: entry.epoch, "rvft1 scka send chain"
    )
    _strictly_sorted(
        value.scka_recv_chain, lambda entry: entry.epoch, "rvft1 scka recv chain"
    )
    _strictly_sorted(
        value.scka_skipped,
        lambda entry: (entry.direction, entry.epoch, entry.n),
        "rvft1 scka skipped",
    )
    _strictly_sorted(
        value.ec_skipped,
        lambda entry: (entry.dh_pub, entry.n),
        "rvft1 ec skipped",
    )
    for entry in value.scka_send_chain + value.scka_recv_chain:
        _require_len(entry.ck, 32, "rvft1 scka chain ck")
    for entry in value.scka_skipped:
        if entry.direction not in (DIR_A2B, DIR_B2A):
            raise ValueError("rvft1 scka skipped direction")
        _require_len(entry.mk, 32, "rvft1 scka skipped mk")
    for entry in value.ec_skipped:
        _require_len(entry.dh_pub, 32, "rvft1 ec skipped dh_pub")
        _require_len(entry.mk, 32, "rvft1 ec skipped mk")
    _validate_optional_key(value.ec_dhr_present, value.ec_dhr_pub, "ec_dhr_pub")
    _validate_optional_key(
        value.ec_ck_send_present, value.ec_ck_send, "ec_ck_send"
    )
    _validate_optional_key(
        value.ec_ck_recv_present, value.ec_ck_recv, "ec_ck_recv"
    )


def decode_rvft1(data: bytes) -> Rvft1:
    if len(data) > RVFT1_MAX_SIZE:
        raise ValueError("rvft1 exceeds max size")
    expect_magic(data, RVFT1_MAGIC)
    reader = WireReader(data, 8)
    if reader.read_u16be() != RVFT1_SCHEMA:
        raise ValueError("rvft1 bad schema")
    scka_rk = reader.read_array32()
    scka_sending_epoch = reader.read_u64be()
    scka_receiving_epoch = reader.read_u64be()

    send_count = reader.read_u16be()
    if send_count > MAX_SCKA_CHAIN:
        raise ValueError("rvft1 scka send cap")
    scka_send_chain = [
        SckaChainEntry(reader.read_u64be(), reader.read_array32(), reader.read_u32be())
        for _ in range(send_count)
    ]

    recv_count = reader.read_u16be()
    if recv_count > MAX_SCKA_CHAIN:
        raise ValueError("rvft1 scka recv cap")
    scka_recv_chain = [
        SckaChainEntry(reader.read_u64be(), reader.read_array32(), reader.read_u32be())
        for _ in range(recv_count)
    ]

    scka_send_pn = reader.read_u32be()
    skipped_count = reader.read_u16be()
    if skipped_count > MAX_SCKA_SKIPPED:
        raise ValueError("rvft1 scka skipped cap")
    scka_skipped = [
        SckaSkippedEntry(
            reader.read_u8(),
            reader.read_u64be(),
            reader.read_u32be(),
            reader.read_array32(),
        )
        for _ in range(skipped_count)
    ]

    ec_rk = reader.read_array32()
    ec_dhs_priv = reader.read_array32()
    ec_dhs_pub = reader.read_array32()
    ec_dhr_present = reader.read_u8()
    ec_dhr_pub = reader.read_array32()
    ec_ck_send_present = reader.read_u8()
    ec_ck_recv_present = reader.read_u8()
    ec_ck_send = reader.read_array32()
    ec_ck_recv = reader.read_array32()
    ec_ns = reader.read_u32be()
    ec_nr = reader.read_u32be()
    ec_pn = reader.read_u32be()

    ec_skipped_count = reader.read_u16be()
    if ec_skipped_count > MAX_EC_SKIPPED:
        raise ValueError("rvft1 ec skipped cap")
    ec_skipped = [
        EcSkippedEntry(
            reader.read_array32(), reader.read_u32be(), reader.read_array32()
        )
        for _ in range(ec_skipped_count)
    ]
    if reader.read_u32be() != 0:
        raise ValueError("rvft1 reserved_tail")
    reject_trailing(data, reader.off)

    value = Rvft1(
        scka_rk=scka_rk,
        scka_sending_epoch=scka_sending_epoch,
        scka_receiving_epoch=scka_receiving_epoch,
        scka_send_chain=scka_send_chain,
        scka_recv_chain=scka_recv_chain,
        scka_send_pn=scka_send_pn,
        scka_skipped=scka_skipped,
        ec_rk=ec_rk,
        ec_dhs_priv=ec_dhs_priv,
        ec_dhs_pub=ec_dhs_pub,
        ec_dhr_present=ec_dhr_present,
        ec_dhr_pub=ec_dhr_pub,
        ec_ck_send_present=ec_ck_send_present,
        ec_ck_recv_present=ec_ck_recv_present,
        ec_ck_send=ec_ck_send,
        ec_ck_recv=ec_ck_recv,
        ec_ns=ec_ns,
        ec_nr=ec_nr,
        ec_pn=ec_pn,
        ec_skipped=ec_skipped,
    )
    _validate_rvft1(value)
    return value


def encode_rvft1(value: Rvft1) -> bytes:
    _validate_rvft1(value)
    out = bytearray(RVFT1_MAGIC)
    out += _u16(RVFT1_SCHEMA)
    out += value.scka_rk
    out += _u64(value.scka_sending_epoch)
    out += _u64(value.scka_receiving_epoch)

    out += _u16(len(value.scka_send_chain))
    for entry in value.scka_send_chain:
        out += _u64(entry.epoch)
        out += entry.ck
        out += _u32(entry.n)

    out += _u16(len(value.scka_recv_chain))
    for entry in value.scka_recv_chain:
        out += _u64(entry.epoch)
        out += entry.ck
        out += _u32(entry.n)

    out += _u32(value.scka_send_pn)
    out += _u16(len(value.scka_skipped))
    for entry in value.scka_skipped:
        out += _u8(entry.direction)
        out += _u64(entry.epoch)
        out += _u32(entry.n)
        out += entry.mk

    out += value.ec_rk
    out += value.ec_dhs_priv
    out += value.ec_dhs_pub
    out += _u8(value.ec_dhr_present)
    out += value.ec_dhr_pub if value.ec_dhr_present == 1 else bytes(32)
    out += _u8(value.ec_ck_send_present)
    out += _u8(value.ec_ck_recv_present)
    out += value.ec_ck_send if value.ec_ck_send_present == 1 else bytes(32)
    out += value.ec_ck_recv if value.ec_ck_recv_present == 1 else bytes(32)
    out += _u32(value.ec_ns)
    out += _u32(value.ec_nr)
    out += _u32(value.ec_pn)

    out += _u16(len(value.ec_skipped))
    for entry in value.ec_skipped:
        out += entry.dh_pub
        out += _u32(entry.n)
        out += entry.mk
    out += _u32(0)
    if len(out) > RVFT1_MAX_SIZE:
        raise ValueError("rvft1 exceeds max size")
    return bytes(out)


def _decode_prefix(data: bytes) -> Rvfb1Prefix:
    if len(data) < RVFB1_PREFIX_LEN:
        raise ValueError("rvfb1 prefix truncated")
    expect_magic(data, RVFB1_MAGIC)
    reader = WireReader(data, 8)
    if reader.read_u16be() != RVFB1_SCHEMA:
        raise ValueError("rvfb1 bad schema")
    prefix = Rvfb1Prefix(
        session_id=reader.read_array32(),
        role=reader.read_u8(),
        generation=reader.read_u64be(),
        agent=reader.read_u8(),
        terminal_reason=reader.read_u16be(),
        auth_root=reader.read_array32(),
        auth_mac_key=reader.read_array32(),
        braid_agent_epoch=reader.read_u64be(),
        braid_send_epoch=reader.read_u64be(),
        braid_recv_epoch=reader.read_u64be(),
        flags=reader.read_u32be(),
        pending_phase=reader.read_u8(),
        pending_transition_id=reader.read_array32(),
        pending_before_digest=reader.read_array32(),
        pending_output_digest=reader.read_array32(),
        pending_execution_digest=reader.read_array32(),
    )
    if reader.off != RVFB1_PREFIX_LEN:
        raise ValueError("rvfb1 prefix length")
    return prefix


def _encode_prefix(prefix: Rvfb1Prefix) -> bytes:
    for name in (
        "session_id",
        "auth_root",
        "auth_mac_key",
        "pending_transition_id",
        "pending_before_digest",
        "pending_output_digest",
        "pending_execution_digest",
    ):
        _require_len(getattr(prefix, name), 32, name)
    out = bytearray(RVFB1_MAGIC)
    out += _u16(RVFB1_SCHEMA)
    out += prefix.session_id
    out += _u8(prefix.role)
    out += _u64(prefix.generation)
    out += _u8(prefix.agent)
    out += _u16(prefix.terminal_reason)
    out += prefix.auth_root
    out += prefix.auth_mac_key
    out += _u64(prefix.braid_agent_epoch)
    out += _u64(prefix.braid_send_epoch)
    out += _u64(prefix.braid_recv_epoch)
    out += _u32(prefix.flags)
    out += _u8(prefix.pending_phase)
    out += prefix.pending_transition_id
    out += prefix.pending_before_digest
    out += prefix.pending_output_digest
    out += prefix.pending_execution_digest
    if len(out) != RVFB1_PREFIX_LEN:
        raise AssertionError("rvfb1 prefix length")
    return bytes(out)


def decode_rvfb1(data: bytes) -> Rvfb1State:
    prefix = _decode_prefix(data)
    reader = WireReader(data, RVFB1_PREFIX_LEN)

    inbound_sets = []
    for _ in range(reader.read_u16be()):
        direction = reader.read_u8()
        epoch = reader.read_u64be()
        source_kind = reader.read_u8()
        expected_source_len = reader.read_u32be()
        max_index = reader.read_u32be()
        bitmap = reader.read_bytes(reader.read_u16be())
        chunks = []
        for _ in range(reader.read_u16be()):
            index = reader.read_u32be()
            chunks.append(InboundChunk(index, reader.read_bytes(reader.read_u16be())))
        inbound_sets.append(
            InboundSet(
                direction,
                epoch,
                source_kind,
                expected_source_len,
                max_index,
                bitmap,
                chunks,
            )
        )

    present = reader.read_u8()
    if present == 0:
        active_send = None
    elif present == 1:
        direction = reader.read_u8()
        epoch = reader.read_u64be()
        wire_type = reader.read_u8()
        source_kind = reader.read_u8()
        source_len = reader.read_u32be()
        source_digest = reader.read_array32()
        source_bytes = reader.read_bytes(source_len)
        active_send = ActiveSend(
            direction,
            epoch,
            wire_type,
            source_kind,
            source_len,
            source_digest,
            source_bytes,
            reader.read_u32be(),
        )
    else:
        raise ValueError("rvfb1 active_send present")

    objects = [
        BraidObject(
            reader.read_u8(),
            reader.read_u64be(),
            reader.read_u8(),
            reader.read_array32(),
        )
        for _ in range(reader.read_u16be())
    ]
    replays = [
        ReplayRecord(
            reader.read_array32(),
            reader.read_array32(),
            reader.read_array32(),
            reader.read_u32be(),
            reader.read_u16be(),
        )
        for _ in range(reader.read_u16be())
    ]
    tlvs = [
        TlvEntry(reader.read_u16be(), reader.read_bytes(reader.read_u32be()))
        for _ in range(reader.read_u16be())
    ]
    tr_bytes = reader.read_bytes(reader.read_u32be())
    reject_trailing(data, reader.off)
    expect_magic(tr_bytes, RVFT1_MAGIC)

    state = Rvfb1State(
        prefix, inbound_sets, active_send, objects, replays, tlvs, tr_bytes
    )
    _validate_state(state)
    return state


MAX_INBOUND_SETS = 8
MAX_OBJECTS = 32
MAX_REPLAYS = 64
BRAID_MAX_CHUNKS_PER_EPOCH = 64
BRAID_MAX_CHUNK_INDEX = 63
AGENT_TERMINAL = 11

# required / optional / forbidden per agent (design §6.3 / Rust tlv_matrix)
_TLV_MATRIX: dict[int, tuple[tuple[int, ...], tuple[int, ...], tuple[int, ...]]] = {
    0: ((), (), (1, 2, 3, 4, 5, 6, 7, 8)),
    1: ((1, 2, 3, 4, 8), (), (5, 6, 7)),
    2: ((1, 4), (), (2, 3, 5, 6, 7, 8)),
    3: ((1, 4, 6), (), (2, 3, 5, 7, 8)),
    4: ((1, 6), (), (2, 3, 4, 5, 7, 8)),
    5: ((), (), (1, 2, 3, 4, 5, 6, 7, 8)),
    6: ((2, 3), (), (1, 4, 5, 6, 7, 8)),
    7: ((2, 3, 5, 6), (), (1, 4, 7, 8)),
    8: ((2, 3, 4, 5, 6), (), (1, 7, 8)),
    9: ((2, 3, 5, 6), (), (1, 4, 7, 8)),
    10: ((7,), (6,), (1, 2, 3, 4, 5, 8)),
    AGENT_TERMINAL: ((), (), (1, 2, 3, 4, 5, 6, 7, 8)),
}


def _bitmap_get(bitmap: bytes, index: int) -> bool:
    return bool(bitmap[index // 8] & (1 << (index % 8)))


def _validate_tlvs_for_agent(agent: int, tlvs: list[TlvEntry]) -> None:
    matrix = _TLV_MATRIX.get(agent)
    if matrix is None:
        raise ValueError("rvfb1 unknown agent for tlv matrix")
    required, optional, forbidden = matrix
    for entry in tlvs:
        expect = TLV_LENGTHS.get(entry.tag)
        if expect is None:
            raise ValueError("rvfb1 unknown tlv tag")
        if len(entry.value) != expect:
            raise ValueError("rvfb1 tlv length")
        if entry.tag in forbidden:
            raise ValueError("rvfb1 tlv forbidden for agent")
        if entry.tag not in required and entry.tag not in optional:
            raise ValueError("rvfb1 tlv not allowed for agent")
    for req in required:
        if not any(entry.tag == req for entry in tlvs):
            raise ValueError("rvfb1 tlv required missing")


def _validate_inbound_set(inbound: InboundSet) -> None:
    if inbound.direction not in (DIR_A2B, DIR_B2A):
        raise ValueError("rvfb1 inbound direction")
    if inbound.source_kind not in SOURCE_LENGTHS:
        raise ValueError("rvfb1 inbound source_kind")
    if inbound.expected_source_len != SOURCE_LENGTHS[inbound.source_kind]:
        raise ValueError("rvfb1 inbound expected_source_len")
    if inbound.max_index != BRAID_MAX_CHUNK_INDEX:
        raise ValueError("rvfb1 inbound max_index must be BRAID_MAX_CHUNK_INDEX")
    if len(inbound.bitmap) != 8:
        raise ValueError("rvfb1 inbound bitmap_len")
    if len(inbound.chunks) > BRAID_MAX_CHUNKS_PER_EPOCH:
        raise ValueError("rvfb1 inbound num_chunks")
    _strictly_sorted(inbound.chunks, lambda item: item.index, "rvfb1 inbound chunks")
    for chunk in inbound.chunks:
        if chunk.index > BRAID_MAX_CHUNK_INDEX or chunk.index > inbound.max_index:
            raise ValueError("rvfb1 inbound chunk index")
        _require_len(chunk.payload, 32, "rvfb1 inbound chunk")
        if not _bitmap_get(inbound.bitmap, chunk.index):
            raise ValueError("rvfb1 inbound bitmap missing chunk bit")
    # Exact consistency: every set bit must have a matching chunk (no orphans).
    bit_count = 0
    for i in range(inbound.max_index + 1):
        if _bitmap_get(inbound.bitmap, i):
            bit_count += 1
            if not any(chunk.index == i for chunk in inbound.chunks):
                raise ValueError("rvfb1 inbound bitmap orphan bit")
    if bit_count != len(inbound.chunks):
        raise ValueError("rvfb1 inbound bitmap/chunk count")


def _validate_state(state: Rvfb1State) -> None:
    if state.prefix.role not in (ROLE_ALICE, ROLE_BOB):
        raise ValueError("rvfb1 role")
    if len(state.inbound_sets) > MAX_INBOUND_SETS:
        raise ValueError("rvfb1 too many inbound sets")
    if len(state.objects) > MAX_OBJECTS:
        raise ValueError("rvfb1 too many objects")
    if len(state.replays) > MAX_REPLAYS:
        raise ValueError("rvfb1 too many replays")
    _strictly_sorted(
        state.inbound_sets,
        lambda item: (item.direction, item.epoch, item.source_kind),
        "rvfb1 inbound sets",
    )
    for inbound in state.inbound_sets:
        _validate_inbound_set(inbound)
    _strictly_sorted(
        state.objects,
        lambda item: (item.direction, item.epoch, item.source_kind),
        "rvfb1 objects",
    )
    # Replay records are a FIFO window in commit order (oldest first); the
    # canonical form is the recorded sequence, with unique transition ids.
    replay_ids = [item.transition_id for item in state.replays]
    if len(set(replay_ids)) != len(replay_ids):
        raise ValueError("rvfb1 replays duplicate transition_id")
    _strictly_sorted(state.tlvs, lambda item: item.tag, "rvfb1 tlvs")
    for replay in state.replays:
        _require_len(replay.transition_id, 32, "replay transition_id")
        _require_len(replay.execution_digest, 32, "replay execution_digest")
        _require_len(replay.output_digest, 32, "replay output_digest")
    _validate_tlvs_for_agent(state.prefix.agent, state.tlvs)
    if state.active_send is not None:
        active = state.active_send
        if active.direction not in (DIR_A2B, DIR_B2A):
            raise ValueError("rvfb1 active_send direction")
        if len(active.source_bytes) != active.source_len:
            raise ValueError("rvfb1 active source_len")
        _require_len(active.source_digest, 32, "rvfb1 active source_digest")
        if active.next_spqr_index > BRAID_MAX_CHUNKS_PER_EPOCH:
            raise ValueError("rvfb1 active_send next_spqr_index")
    expect_magic(state.tr_bytes, RVFT1_MAGIC)


def encode_rvfb1(state: Rvfb1State) -> bytes:
    _validate_state(state)
    out = bytearray(_encode_prefix(state.prefix))

    out += _u16(len(state.inbound_sets))
    for inbound in state.inbound_sets:
        out += _u8(inbound.direction)
        out += _u64(inbound.epoch)
        out += _u8(inbound.source_kind)
        out += _u32(inbound.expected_source_len)
        out += _u32(inbound.max_index)
        out += _u16(len(inbound.bitmap))
        out += inbound.bitmap
        out += _u16(len(inbound.chunks))
        for chunk in inbound.chunks:
            out += _u32(chunk.index)
            out += _u16(len(chunk.payload))
            out += chunk.payload

    if state.active_send is None:
        out += _u8(0)
    else:
        active = state.active_send
        out += _u8(1)
        out += _u8(active.direction)
        out += _u64(active.epoch)
        out += _u8(active.wire_type)
        out += _u8(active.source_kind)
        out += _u32(active.source_len)
        out += active.source_digest
        out += active.source_bytes
        out += _u32(active.next_spqr_index)

    out += _u16(len(state.objects))
    for item in state.objects:
        _require_len(item.object_digest, 32, "object_digest")
        out += _u8(item.direction)
        out += _u64(item.epoch)
        out += _u8(item.source_kind)
        out += item.object_digest

    out += _u16(len(state.replays))
    for replay in state.replays:
        out += replay.transition_id
        out += replay.execution_digest
        out += replay.output_digest
        out += _u32(replay.output_len)
        out += _u16(replay.flags)

    out += _u16(len(state.tlvs))
    for entry in state.tlvs:
        out += _u16(entry.tag)
        out += _u32(len(entry.value))
        out += entry.value

    out += _u32(len(state.tr_bytes))
    out += state.tr_bytes
    return bytes(out)
