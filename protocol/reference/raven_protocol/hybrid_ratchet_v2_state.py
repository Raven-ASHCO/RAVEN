"""Stateful Triple Ratchet KATs for ATSAM/hybrid-ratchet/v2 (production-disabled).

Models EC skip/OOO, SCKA epoch promote + CK reorder, route/mailbox tags,
replay/dedup, and crash-order machines. No live callsites.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac

from .hybrid_ratchet_v2 import (
    MAX_SKIP,
    MAILBOX_LATE_ARRIVAL_DAYS,
    PROFILE,
    SPQR_PROTOCOL_INFO,
    aead_open,
    kdf_ck,
)
from .pair_init_v2 import hkdf_sha256

PRODUCTION_ENABLED = False

SCKA_RK_INFO = SPQR_PROTOCOL_INFO  # KDF_SCKA_RK info = SPQR_PROTOCOL_INFO
ROUTE_INFO_PREFIX = PROFILE + b"\x00route\x00"
ROUTE_TAG_DOMAIN = b"ATSAM/v2/route"
MAILBOX_TAG_DOMAIN = b"ATSAM/v2/mailbox"
STORE_TAG_DOMAIN = b"raven/relay-tag/v1"
MS_PER_DAY = 86_400_000
# ATSAM §5.1: EPOCH_TYPE = u64; increments MUST NOT wrap (fail closed).
EPOCH_MAX = (1 << 64) - 1
CTR_MAX = (1 << 32) - 1
# Global retained skipped-key cap (mirrors hybrid_ratchet_v2_tr).
MAX_MKSKIPPED_RETAINED = 2000


def _next_epoch(epoch: int) -> int:
    if not 0 <= epoch < EPOCH_MAX:
        raise ValueError("SCKA epoch overflow (EPOCH_TYPE=u64 MUST NOT wrap)")
    return epoch + 1


def _next_ctr(ctr: int, what: str) -> int:
    if not 0 <= ctr < CTR_MAX:
        raise ValueError(f"{what} counter overflow")
    return ctr + 1


def kdf_scka_rk(rk: bytes, ss: bytes) -> tuple[bytes, bytes]:
    """KDF_SCKA_RK(rk, ss) -> (rk', ck). salt=rk, IKM=ss, info=SPQR, L=64."""
    if len(rk) != 32 or len(ss) != 32:
        raise ValueError("rk and ss must be 32 bytes")
    if ss == bytes(32):
        raise ValueError("non-contributory SCKA ss rejected")
    okm = hkdf_sha256(ikm=ss, salt=rk, info=SCKA_RK_INFO, length=64)
    return okm[:32], okm[32:]


def kdf_scka_ck(ck: bytes) -> tuple[bytes, bytes]:
    """KDF_SCKA_CK — same HMAC contract as KDF_CK."""
    return kdf_ck(ck)


@dataclass
class SckaEpochState:
    rk: bytes
    ck_send: bytes
    ck_recv: bytes
    sending_epoch: int = 0
    receiving_epoch: int = 0
    send_ctr: int = 0
    recv_ctr: int = 0

    def fingerprint(self) -> bytes:
        return hashlib.sha256(
            self.rk
            + self.ck_send
            + self.ck_recv
            + self.sending_epoch.to_bytes(8, "big")
            + self.receiving_epoch.to_bytes(8, "big")
            + self.send_ctr.to_bytes(4, "big")
            + self.recv_ctr.to_bytes(4, "big")
        ).digest()


def scka_from_init(alice: bool, sk_scka: bytes) -> SckaEpochState:
    from .hybrid_ratchet_v2 import ratchet_init_alice_scka, ratchet_init_bob_scka

    init = ratchet_init_alice_scka(sk_scka) if alice else ratchet_init_bob_scka(sk_scka)
    return SckaEpochState(rk=init.rk, ck_send=init.ck_send, ck_recv=init.ck_recv)


def scka_epoch_promote_initiator(state: SckaEpochState, ss: bytes) -> SckaEpochState:
    """Epoch initiator installs new send CK; receiving chain unchanged."""
    rk2, ck = kdf_scka_rk(state.rk, ss)
    return SckaEpochState(
        rk=rk2,
        ck_send=ck,
        ck_recv=state.ck_recv,
        sending_epoch=_next_epoch(state.sending_epoch),
        receiving_epoch=state.receiving_epoch,
        send_ctr=0,
        recv_ctr=state.recv_ctr,
    )


def scka_epoch_promote_responder(state: SckaEpochState, ss: bytes) -> SckaEpochState:
    """Epoch responder installs new recv CK; sending chain unchanged."""
    rk2, ck = kdf_scka_rk(state.rk, ss)
    return SckaEpochState(
        rk=rk2,
        ck_send=state.ck_send,
        ck_recv=ck,
        sending_epoch=state.sending_epoch,
        receiving_epoch=_next_epoch(state.receiving_epoch),
        send_ctr=state.send_ctr,
        recv_ctr=0,
    )


def scka_next_send_mk(state: SckaEpochState) -> tuple[SckaEpochState, bytes]:
    ck2, mk = kdf_scka_ck(state.ck_send)
    out = SckaEpochState(
        rk=state.rk,
        ck_send=ck2,
        ck_recv=state.ck_recv,
        sending_epoch=state.sending_epoch,
        receiving_epoch=state.receiving_epoch,
        send_ctr=_next_ctr(state.send_ctr, "SCKA send"),
        recv_ctr=state.recv_ctr,
    )
    return out, mk


def scka_next_recv_mk(state: SckaEpochState) -> tuple[SckaEpochState, bytes]:
    ck2, mk = kdf_scka_ck(state.ck_recv)
    out = SckaEpochState(
        rk=state.rk,
        ck_send=state.ck_send,
        ck_recv=ck2,
        sending_epoch=state.sending_epoch,
        receiving_epoch=state.receiving_epoch,
        send_ctr=state.send_ctr,
        recv_ctr=_next_ctr(state.recv_ctr, "SCKA recv"),
    )
    return out, mk


def _mk_key(dh_pub: bytes, n: int) -> bytes:
    return dh_pub + n.to_bytes(4, "big")


@dataclass
class EcRecvState:
    ck: bytes
    n: int
    dh_pub: bytes
    mkskipped: dict[bytes, bytes] = field(default_factory=dict)

    def fingerprint(self) -> bytes:
        items = b"".join(sorted(k + v for k, v in self.mkskipped.items()))
        return hashlib.sha256(
            self.ck + self.dh_pub + self.n.to_bytes(4, "big") + items
        ).digest()


@dataclass
class EcSendState:
    ck: bytes
    n: int
    dh_pub: bytes


def ec_send_mk(state: EcSendState) -> tuple[EcSendState, bytes]:
    ck2, mk = kdf_ck(state.ck)
    n = _next_ctr(state.n, "EC send")
    return EcSendState(ck=ck2, n=n, dh_pub=state.dh_pub), mk


def ec_skip_keys(state: EcRecvState, until_n: int, max_skip: int = MAX_SKIP) -> EcRecvState:
    """Advance recv chain to until_n, storing skipped mks. No partial mutate on fail."""
    if until_n < state.n:
        raise ValueError("until_n behind current n")
    skip_count = until_n - state.n
    if skip_count > max_skip:
        raise ValueError("MAX_SKIP exceeded")
    if len(state.mkskipped) + skip_count > MAX_MKSKIPPED_RETAINED:
        raise ValueError("MAX_MKSKIPPED_RETAINED exceeded")
    ck = state.ck
    n = state.n
    skipped = dict(state.mkskipped)
    while n < until_n:
        ck, mk = kdf_ck(ck)
        skipped[_mk_key(state.dh_pub, n)] = mk
        n += 1
    return EcRecvState(ck=ck, n=until_n, dh_pub=state.dh_pub, mkskipped=skipped)


def ec_try_skipped(state: EcRecvState, dh_pub: bytes, n: int) -> tuple[bytes | None, EcRecvState]:
    key = _mk_key(dh_pub, n)
    if key not in state.mkskipped:
        return None, state
    skipped = dict(state.mkskipped)
    mk = skipped.pop(key)
    return mk, EcRecvState(ck=state.ck, n=state.n, dh_pub=state.dh_pub, mkskipped=skipped)


def ec_recv_in_order(state: EcRecvState) -> tuple[EcRecvState, bytes]:
    ck2, mk = kdf_ck(state.ck)
    return (
        EcRecvState(
            ck=ck2,
            n=_next_ctr(state.n, "EC recv"),
            dh_pub=state.dh_pub,
            mkskipped=dict(state.mkskipped),
        ),
        mk,
    )


def ec_recv_message(
    state: EcRecvState, dh_pub: bytes, n: int, max_skip: int = MAX_SKIP
) -> tuple[EcRecvState, bytes]:
    if dh_pub != state.dh_pub:
        raise ValueError("DH ratchet not modeled in this KAT path")
    mk, st = ec_try_skipped(state, dh_pub, n)
    if mk is not None:
        return st, mk
    if n < state.n:
        raise ValueError("replay of consumed index")
    if n > state.n:
        st = ec_skip_keys(state, n, max_skip=max_skip)
    else:
        st = state
    return ec_recv_in_order(st)


@dataclass
class AcceptKey:
    session_id: bytes
    dh_pub: bytes
    n: int
    scka_epoch: int
    scka_ctr: int

    def packed(self) -> bytes:
        return (
            self.session_id
            + self.dh_pub
            + self.n.to_bytes(4, "big")
            + self.scka_epoch.to_bytes(4, "big")
            + self.scka_ctr.to_bytes(4, "big")
        )


@dataclass
class CommitLedger:
    accepted_keys: set[bytes] = field(default_factory=set)
    digest_to_ack: dict[bytes, bytes] = field(default_factory=dict)
    mutation_count: int = 0

    def fingerprint(self) -> bytes:
        keys = b"".join(sorted(self.accepted_keys))
        digests = b"".join(sorted(k + v for k, v in self.digest_to_ack.items()))
        return hashlib.sha256(keys + digests + self.mutation_count.to_bytes(8, "big")).digest()


def commit_accept(
    ledger: CommitLedger, key: AcceptKey, object_digest: bytes, retained_ack: bytes
) -> tuple[CommitLedger, str]:
    packed = key.packed()
    if packed in ledger.accepted_keys:
        return ledger, "replay_no_mutation"
    if object_digest in ledger.digest_to_ack:
        return ledger, "duplicate_committed"
    out = CommitLedger(
        accepted_keys=set(ledger.accepted_keys) | {packed},
        digest_to_ack=dict(ledger.digest_to_ack),
        mutation_count=ledger.mutation_count + 1,
    )
    out.digest_to_ack[object_digest] = retained_ack
    return out, "accepted"


def duplicate_ack_exact(ledger: CommitLedger, object_digest: bytes) -> bytes | None:
    return ledger.digest_to_ack.get(object_digest)


def k_route(k_route_master: bytes, direction: int) -> bytes:
    if len(k_route_master) != 32:
        raise ValueError("k_route_master")
    if direction not in (0, 1):
        raise ValueError("direction")
    info = ROUTE_INFO_PREFIX + bytes([direction & 0xFF])
    return hkdf_sha256(ikm=k_route_master, salt=bytes(32), info=info, length=32)


def routing_tag(
    *,
    k_route_d: bytes,
    created_at_ms: int,
    n: int,
    app_type: int,
    direction: int,
    session_id: bytes,
) -> bytes:
    epoch = created_at_ms // 1000
    counter = ((n & 0xFFFFFFFFFFFFFFFF) << 8) | ((app_type & 0x7F) << 1) | (direction & 1)
    msg = (
        ROUTE_TAG_DOMAIN
        + epoch.to_bytes(8, "big")
        + counter.to_bytes(8, "big")
        + session_id
    )
    return hmac.new(k_route_d, msg, hashlib.sha256).digest()[:16]


def mailbox_tag(*, k_route_d: bytes, unix_ms: int, direction: int, session_id: bytes) -> bytes:
    day_epoch = unix_ms // MS_PER_DAY
    msg = (
        MAILBOX_TAG_DOMAIN
        + day_epoch.to_bytes(8, "big")
        + direction.to_bytes(8, "big")
        + session_id
    )
    return hmac.new(k_route_d, msg, hashlib.sha256).digest()[:16]


def store_tag(mailbox_tag_bytes: bytes) -> bytes:
    return hashlib.sha256(STORE_TAG_DOMAIN + mailbox_tag_bytes).digest()[:16]


@dataclass
class MailboxCatchupPlan:
    today: int
    ttl_horizon: int
    late_arrival_floor: int
    historical_days: list[int]
    always_repoll_days: list[int]


def mailbox_catchup_plan(
    *,
    now_ms: int,
    catchup_cursor_day: int,
    mailbox_ttl_days: int,
    late_arrival_days: int = MAILBOX_LATE_ARRIVAL_DAYS,
) -> MailboxCatchupPlan:
    today = now_ms // MS_PER_DAY
    ttl_horizon = today - mailbox_ttl_days
    late_arrival_floor = today - late_arrival_days
    start = max(catchup_cursor_day + 1, ttl_horizon)
    historical = list(range(start, today)) if start < today else []
    always = sorted({d for d in range(max(late_arrival_floor, ttl_horizon), today + 1)})
    return MailboxCatchupPlan(
        today=today,
        ttl_horizon=ttl_horizon,
        late_arrival_floor=late_arrival_floor,
        historical_days=historical,
        always_repoll_days=always,
    )


def candidate_decrypt(
    *,
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
    live_fp: bytes,
) -> dict:
    try:
        pt = aead_open(key, nonce, ciphertext, aad)
        return {
            "open_result": "ok",
            "plaintext_hex": pt.hex(),
            "durable_mutation": True,
            "promote_live_head": True,
            "live_fp_after_hex": hashlib.sha256(live_fp + b"\x01").digest().hex(),
        }
    except Exception:
        return {
            "open_result": "fail",
            "durable_mutation": False,
            "promote_live_head": False,
            "live_fp_after_hex": live_fp.hex(),
        }


class CrashMachineError(Exception):
    pass


@dataclass
class ReceiveCommitMachine:
    state: str = "idle"
    durable_mutation: bool = False
    skipped_persisted: bool = False
    epoch_promoted: bool = False
    epoch_on_candidate: bool = False
    generation: int = 0

    def apply(self, action: str) -> None:
        if action == "clone_candidate":
            if self.state != "idle":
                raise CrashMachineError("bad")
            self.state = "candidate"
        elif action == "derive_keys_on_candidate":
            if self.state != "candidate":
                raise CrashMachineError("bad")
            self.state = "derived"
        elif action == "aead_ok":
            if self.state not in ("derived",):
                raise CrashMachineError("bad")
            self.state = "aead_ok"
        elif action == "write_PENDING_inbound":
            if self.state != "aead_ok":
                raise CrashMachineError("bad")
            self.state = "pending"
        elif action == "sql_commit_receipt_dedup":
            if self.state != "pending":
                raise CrashMachineError("bad")
            self.state = "sql_committed"
            self.durable_mutation = True
        elif action == "persist_MKSKIPPED":
            if self.state != "sql_committed":
                raise CrashMachineError("bad")
            self.skipped_persisted = True
            self.state = "skipped_persisted"
        elif action == "FINALIZE_head":
            if self.state not in ("sql_committed", "skipped_persisted"):
                raise CrashMachineError("finalize_requires_sql")
            if self.epoch_on_candidate:
                raise CrashMachineError("use_commit_epoch_with_finalize")
            self.generation += 1
            self.state = "finalized"
        elif action == "promote_scka_epoch_on_candidate":
            if self.state not in ("derived", "aead_ok"):
                raise CrashMachineError("bad")
            self.epoch_on_candidate = True
            # stay in current state; durable epoch only at commit_epoch_with_finalize
        elif action == "commit_epoch_with_finalize":
            if self.state not in ("sql_committed", "skipped_persisted"):
                raise CrashMachineError("epoch_requires_sql")
            if not self.epoch_on_candidate:
                raise CrashMachineError("epoch_requires_pending")
            if not self.durable_mutation:
                raise CrashMachineError("epoch_requires_sql")
            self.epoch_promoted = True
            self.generation += 1
            self.state = "finalized"
        elif action == "clear_PENDING":
            if self.state != "finalized":
                raise CrashMachineError("bad")
            self.state = "cleared"
        elif action == "FINALIZE_before_sql":
            raise CrashMachineError("finalize_before_sql_forbidden")
        elif action == "promote_epoch_before_sql":
            raise CrashMachineError("epoch_before_sql_forbidden")
        else:
            raise CrashMachineError(f"unknown:{action}")


def run_braid_epoch_matrix(sk_scka: bytes, ss1: bytes, ss2: bytes) -> dict:
    alice = scka_from_init(True, sk_scka)
    bob = scka_from_init(False, sk_scka)
    assert alice.ck_send == bob.ck_recv

    alice1i = scka_epoch_promote_initiator(alice, ss1)
    bob1r = scka_epoch_promote_responder(bob, ss1)
    assert alice1i.rk == bob1r.rk
    assert alice1i.ck_send == bob1r.ck_recv

    alice1, a_mk = scka_next_send_mk(alice1i)
    bob1, b_mk = scka_next_recv_mk(bob1r)
    assert a_mk == b_mk

    bob2i = scka_epoch_promote_initiator(bob1, ss2)
    alice2r = scka_epoch_promote_responder(alice1, ss2)
    assert bob2i.rk == alice2r.rk
    assert bob2i.ck_send == alice2r.ck_recv

    bob2, b_mk2 = scka_next_send_mk(bob2i)
    alice2, a_mk2 = scka_next_recv_mk(alice2r)
    assert b_mk2 == a_mk2

    return {
        "epoch1": {
            "rk_hex": alice1i.rk.hex(),
            "alice_ck_send_hex": alice1i.ck_send.hex(),
            "bob_ck_recv_hex": bob1r.ck_recv.hex(),
            "alice_send_equals_bob_recv": alice1i.ck_send == bob1r.ck_recv,
            "mk_hex": a_mk.hex(),
            "alice_sending_epoch": alice1i.sending_epoch,
            "bob_receiving_epoch": bob1r.receiving_epoch,
        },
        "epoch2": {
            "rk_hex": bob2i.rk.hex(),
            "bob_ck_send_hex": bob2i.ck_send.hex(),
            "alice_ck_recv_hex": alice2r.ck_recv.hex(),
            "bob_send_equals_alice_recv": bob2i.ck_send == alice2r.ck_recv,
            "mk_hex": b_mk2.hex(),
            "bob_sending_epoch": bob2i.sending_epoch,
            "alice_receiving_epoch": alice2r.receiving_epoch,
        },
        "directions_reordered": True,
    }


def run_ec_ooo_matrix(ck0: bytes, dh_pub: bytes) -> dict:
    send = EcSendState(ck=ck0, n=0, dh_pub=dh_pub)
    mks = []
    for _ in range(4):
        send, mk = ec_send_mk(send)
        mks.append(mk)

    recv = EcRecvState(ck=ck0, n=0, dh_pub=dh_pub)
    order = [0, 3, 1, 2]
    recovered = []
    for idx in order:
        recv, mk = ec_recv_message(recv, dh_pub, idx)
        recovered.append(mk.hex())
        assert mk == mks[idx]

    return {
        "send_mks_hex": [m.hex() for m in mks],
        "receive_order": order,
        "recovered_mks_hex": recovered,
        "final_skipped_count": len(recv.mkskipped),
        "final_n": recv.n,
        "ooo_ok": True,
    }


def run_skip_boundary(ck0: bytes, dh_pub: bytes) -> dict:
    cases = []
    for count in (0, 1, 999, 1000, 1001):
        base = EcRecvState(ck=ck0, n=0, dh_pub=dh_pub)
        fp_before = base.fingerprint()
        try:
            advanced = ec_skip_keys(base, until_n=count, max_skip=MAX_SKIP)
            first_mk = None
            last_mk = None
            if count > 0:
                first_mk = advanced.mkskipped[_mk_key(dh_pub, 0)].hex()
                last_mk = advanced.mkskipped[_mk_key(dh_pub, count - 1)].hex()
            cases.append(
                {
                    "skip_count": count,
                    "result": "ok",
                    "skipped_stored": count,
                    "first_mk_hex": first_mk,
                    "last_mk_hex": last_mk,
                    "final_ck_hex": advanced.ck.hex(),
                    "final_n": advanced.n,
                    "fp_before_hex": fp_before.hex(),
                    "fp_after_hex": advanced.fingerprint().hex(),
                }
            )
        except ValueError as exc:
            cases.append(
                {
                    "skip_count": count,
                    "result": "reject",
                    "reason": str(exc),
                    "fp_before_hex": fp_before.hex(),
                    "fp_after_hex": base.fingerprint().hex(),
                    "state_unchanged": base.fingerprint() == fp_before,
                    "allocation": False,
                    "state_advance": False,
                }
            )
    return {"max_skip": MAX_SKIP, "cases": cases}
