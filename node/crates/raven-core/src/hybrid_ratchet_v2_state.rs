//! Stateful Triple Ratchet KATs (production-disabled). No live callsites.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::Zeroize;

use crate::hybrid_ratchet_v2::{
    hkdf_sha256, kdf_ck, ratchet_init_alice_scka, ratchet_init_bob_scka, MAX_SKIP, PROFILE,
    SPQR_PROTOCOL_INFO,
};
use crate::hybrid_ratchet_v2_tr::MAX_MKSKIPPED_RETAINED;

type HmacSha256 = Hmac<Sha256>;

pub const MAILBOX_LATE_ARRIVAL_DAYS: i64 = 7;
pub const MS_PER_DAY: i64 = 86_400_000;
pub const ROUTE_TAG_DOMAIN: &[u8] = b"ATSAM/v2/route";
pub const MAILBOX_TAG_DOMAIN: &[u8] = b"ATSAM/v2/mailbox";
pub const STORE_TAG_DOMAIN: &[u8] = b"raven/relay-tag/v1";

pub fn kdf_scka_rk(rk: &[u8; 32], ss: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), String> {
    if *ss == [0u8; 32] {
        return Err("non-contributory SCKA ss".into());
    }
    let okm = hkdf_sha256(ss, rk, SPQR_PROTOCOL_INFO, 64);
    let mut rk2 = [0u8; 32];
    let mut ck = [0u8; 32];
    rk2.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    Ok((rk2, ck))
}

/// SCKA epoch/chain KAT state. Epochs are `EPOCH_TYPE = u64` (ATSAM §5.1) and
/// every increment fails closed instead of wrapping; root/chain keys are wiped
/// on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct SckaEpochState {
    pub rk: [u8; 32],
    pub ck_send: [u8; 32],
    pub ck_recv: [u8; 32],
    pub sending_epoch: u64,
    pub receiving_epoch: u64,
    pub send_ctr: u32,
    pub recv_ctr: u32,
}

impl fmt::Debug for SckaEpochState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SckaEpochState")
            .field("sending_epoch", &self.sending_epoch)
            .field("receiving_epoch", &self.receiving_epoch)
            .field("send_ctr", &self.send_ctr)
            .field("recv_ctr", &self.recv_ctr)
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl Drop for SckaEpochState {
    fn drop(&mut self) {
        self.rk.zeroize();
        self.ck_send.zeroize();
        self.ck_recv.zeroize();
    }
}

fn next_epoch(epoch: u64) -> Result<u64, String> {
    epoch
        .checked_add(1)
        .ok_or_else(|| "SCKA epoch overflow (EPOCH_TYPE=u64 MUST NOT wrap)".to_string())
}

fn next_ctr(ctr: u32, what: &str) -> Result<u32, String> {
    ctr.checked_add(1)
        .ok_or_else(|| format!("{what} counter overflow"))
}

pub fn scka_from_init(alice: bool, sk: &[u8; 32]) -> SckaEpochState {
    let init = if alice {
        ratchet_init_alice_scka(sk)
    } else {
        ratchet_init_bob_scka(sk)
    };
    SckaEpochState {
        rk: init.rk,
        ck_send: init.ck_send,
        ck_recv: init.ck_recv,
        sending_epoch: 0,
        receiving_epoch: 0,
        send_ctr: 0,
        recv_ctr: 0,
    }
}

pub fn scka_epoch_promote_initiator(
    state: &SckaEpochState,
    ss: &[u8; 32],
) -> Result<SckaEpochState, String> {
    let (rk2, ck) = kdf_scka_rk(&state.rk, ss)?;
    Ok(SckaEpochState {
        rk: rk2,
        ck_send: ck,
        ck_recv: state.ck_recv,
        sending_epoch: next_epoch(state.sending_epoch)?,
        receiving_epoch: state.receiving_epoch,
        send_ctr: 0,
        recv_ctr: state.recv_ctr,
    })
}

pub fn scka_epoch_promote_responder(
    state: &SckaEpochState,
    ss: &[u8; 32],
) -> Result<SckaEpochState, String> {
    let (rk2, ck) = kdf_scka_rk(&state.rk, ss)?;
    Ok(SckaEpochState {
        rk: rk2,
        ck_send: state.ck_send,
        ck_recv: ck,
        sending_epoch: state.sending_epoch,
        receiving_epoch: next_epoch(state.receiving_epoch)?,
        send_ctr: state.send_ctr,
        recv_ctr: 0,
    })
}

pub fn scka_next_send_mk(state: &SckaEpochState) -> Result<(SckaEpochState, [u8; 32]), String> {
    let send_ctr = next_ctr(state.send_ctr, "SCKA send")?;
    let (ck2, mk) = kdf_ck(&state.ck_send);
    Ok((
        SckaEpochState {
            rk: state.rk,
            ck_send: ck2,
            ck_recv: state.ck_recv,
            sending_epoch: state.sending_epoch,
            receiving_epoch: state.receiving_epoch,
            send_ctr,
            recv_ctr: state.recv_ctr,
        },
        mk,
    ))
}

pub fn scka_next_recv_mk(state: &SckaEpochState) -> Result<(SckaEpochState, [u8; 32]), String> {
    let recv_ctr = next_ctr(state.recv_ctr, "SCKA recv")?;
    let (ck2, mk) = kdf_ck(&state.ck_recv);
    Ok((
        SckaEpochState {
            rk: state.rk,
            ck_send: state.ck_send,
            ck_recv: ck2,
            sending_epoch: state.sending_epoch,
            receiving_epoch: state.receiving_epoch,
            send_ctr: state.send_ctr,
            recv_ctr,
        },
        mk,
    ))
}

fn mk_key(dh_pub: &[u8; 32], n: u32) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(dh_pub);
    k[32..].copy_from_slice(&n.to_be_bytes());
    k
}

/// EC receive chain KAT state: chain and skipped message keys are wiped on drop
/// and redacted from Debug.
#[derive(Clone, Default)]
pub struct EcRecvState {
    pub ck: [u8; 32],
    pub n: u32,
    pub dh_pub: [u8; 32],
    pub mkskipped: BTreeMap<[u8; 36], [u8; 32]>,
}

impl fmt::Debug for EcRecvState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcRecvState")
            .field("n", &self.n)
            .field("dh_pub", &self.dh_pub)
            .field("mkskipped_len", &self.mkskipped.len())
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl Drop for EcRecvState {
    fn drop(&mut self) {
        self.ck.zeroize();
        for mk in self.mkskipped.values_mut() {
            mk.zeroize();
        }
    }
}

impl EcRecvState {
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.ck);
        h.update(self.dh_pub);
        h.update(self.n.to_be_bytes());
        for (k, v) in &self.mkskipped {
            h.update(k);
            h.update(v);
        }
        h.finalize().into()
    }
}

#[derive(Clone)]
pub struct EcSendState {
    pub ck: [u8; 32],
    pub n: u32,
    pub dh_pub: [u8; 32],
}

impl fmt::Debug for EcSendState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcSendState")
            .field("n", &self.n)
            .field("dh_pub", &self.dh_pub)
            .field("ck", &"<redacted>")
            .finish()
    }
}

impl Drop for EcSendState {
    fn drop(&mut self) {
        self.ck.zeroize();
    }
}

pub fn ec_send_mk(state: &EcSendState) -> Result<(EcSendState, [u8; 32]), String> {
    let n = next_ctr(state.n, "EC send")?;
    let (ck2, mk) = kdf_ck(&state.ck);
    Ok((
        EcSendState {
            ck: ck2,
            n,
            dh_pub: state.dh_pub,
        },
        mk,
    ))
}

pub fn ec_skip_keys(
    state: &EcRecvState,
    until_n: u32,
    max_skip: u32,
) -> Result<EcRecvState, String> {
    if until_n < state.n {
        return Err("until_n behind current n".into());
    }
    let skip_count = until_n - state.n;
    if skip_count > max_skip {
        return Err("MAX_SKIP exceeded".into());
    }
    // Global bound across chains, matching the DR retention cap.
    if state.mkskipped.len() + skip_count as usize > MAX_MKSKIPPED_RETAINED {
        return Err("MAX_MKSKIPPED_RETAINED exceeded".into());
    }
    let mut ck = state.ck;
    let mut n = state.n;
    let mut skipped = state.mkskipped.clone();
    while n < until_n {
        let (ck2, mk) = kdf_ck(&ck);
        skipped.insert(mk_key(&state.dh_pub, n), mk);
        ck = ck2;
        n += 1;
    }
    Ok(EcRecvState {
        ck,
        n: until_n,
        dh_pub: state.dh_pub,
        mkskipped: skipped,
    })
}

pub fn ec_try_skipped(
    state: &EcRecvState,
    dh_pub: &[u8; 32],
    n: u32,
) -> (Option<[u8; 32]>, EcRecvState) {
    let key = mk_key(dh_pub, n);
    let mut out = state.clone();
    if let Some(mk) = out.mkskipped.remove(&key) {
        (Some(mk), out)
    } else {
        (None, out)
    }
}

pub fn ec_recv_in_order(state: &EcRecvState) -> Result<(EcRecvState, [u8; 32]), String> {
    let n = next_ctr(state.n, "EC recv")?;
    let (ck2, mk) = kdf_ck(&state.ck);
    Ok((
        EcRecvState {
            ck: ck2,
            n,
            dh_pub: state.dh_pub,
            mkskipped: state.mkskipped.clone(),
        },
        mk,
    ))
}

pub fn ec_recv_message(
    state: &EcRecvState,
    dh_pub: &[u8; 32],
    n: u32,
    max_skip: u32,
) -> Result<(EcRecvState, [u8; 32]), String> {
    if dh_pub != &state.dh_pub {
        return Err("DH ratchet not modeled".into());
    }
    let (maybe, st) = ec_try_skipped(state, dh_pub, n);
    if let Some(mk) = maybe {
        return Ok((st, mk));
    }
    if n < st.n {
        return Err("replay of consumed index".into());
    }
    let st = if n > st.n {
        ec_skip_keys(&st, n, max_skip)?
    } else {
        st
    };
    ec_recv_in_order(&st)
}

#[derive(Clone, Debug)]
pub struct AcceptKey {
    pub session_id: [u8; 32],
    pub dh_pub: [u8; 32],
    pub n: u32,
    pub scka_epoch: u32,
    pub scka_ctr: u32,
}

impl AcceptKey {
    pub fn packed(&self) -> [u8; 76] {
        let mut out = [0u8; 76];
        out[..32].copy_from_slice(&self.session_id);
        out[32..64].copy_from_slice(&self.dh_pub);
        out[64..68].copy_from_slice(&self.n.to_be_bytes());
        out[68..72].copy_from_slice(&self.scka_epoch.to_be_bytes());
        out[72..76].copy_from_slice(&self.scka_ctr.to_be_bytes());
        out
    }
}

#[derive(Clone, Debug, Default)]
pub struct CommitLedger {
    pub accepted_keys: BTreeSet<[u8; 76]>,
    pub digest_to_ack: BTreeMap<[u8; 32], Vec<u8>>,
    pub mutation_count: u64,
}

impl CommitLedger {
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        for k in &self.accepted_keys {
            h.update(k);
        }
        for (k, v) in &self.digest_to_ack {
            h.update(k);
            h.update(v);
        }
        h.update(self.mutation_count.to_be_bytes());
        h.finalize().into()
    }
}

pub fn commit_accept(
    ledger: &CommitLedger,
    key: &AcceptKey,
    object_digest: &[u8; 32],
    retained_ack: &[u8],
) -> (CommitLedger, &'static str) {
    let packed = key.packed();
    if ledger.accepted_keys.contains(&packed) {
        return (ledger.clone(), "replay_no_mutation");
    }
    if ledger.digest_to_ack.contains_key(object_digest) {
        return (ledger.clone(), "duplicate_committed");
    }
    let mut out = ledger.clone();
    out.accepted_keys.insert(packed);
    out.digest_to_ack
        .insert(*object_digest, retained_ack.to_vec());
    out.mutation_count += 1;
    (out, "accepted")
}

pub fn duplicate_ack_exact(ledger: &CommitLedger, object_digest: &[u8; 32]) -> Option<Vec<u8>> {
    ledger.digest_to_ack.get(object_digest).cloned()
}

pub fn k_route(k_route_master: &[u8; 32], direction: u8) -> Result<[u8; 32], String> {
    if direction > 1 {
        return Err("direction".into());
    }
    let mut info = PROFILE.to_vec();
    info.extend_from_slice(b"\x00route\x00");
    info.push(direction);
    let okm = hkdf_sha256(k_route_master, &[0u8; 32], &info, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    Ok(out)
}

pub fn routing_tag(
    k_route_d: &[u8; 32],
    created_at_ms: u64,
    n: u64,
    app_type: u8,
    direction: u8,
    session_id: &[u8; 32],
) -> [u8; 16] {
    let epoch = created_at_ms / 1000;
    let counter = (n << 8) | (((app_type as u64) & 0x7f) << 1) | ((direction as u64) & 1);
    let mut msg = Vec::new();
    msg.extend_from_slice(ROUTE_TAG_DOMAIN);
    msg.extend_from_slice(&epoch.to_be_bytes());
    msg.extend_from_slice(&counter.to_be_bytes());
    msg.extend_from_slice(session_id);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k_route_d).expect("hmac");
    mac.update(&msg);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

pub fn mailbox_tag(
    k_route_d: &[u8; 32],
    unix_ms: u64,
    direction: u64,
    session_id: &[u8; 32],
) -> [u8; 16] {
    let day_epoch = unix_ms / (MS_PER_DAY as u64);
    let mut msg = Vec::new();
    msg.extend_from_slice(MAILBOX_TAG_DOMAIN);
    msg.extend_from_slice(&day_epoch.to_be_bytes());
    msg.extend_from_slice(&direction.to_be_bytes());
    msg.extend_from_slice(session_id);
    let mut mac = <HmacSha256 as Mac>::new_from_slice(k_route_d).expect("hmac");
    mac.update(&msg);
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

pub fn store_tag(mailbox: &[u8; 16]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(STORE_TAG_DOMAIN);
    h.update(mailbox);
    let full = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

pub fn candidate_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
    live_fp: &[u8; 32],
) -> serde_json::Value {
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("key");
    let n = Nonce::from_slice(nonce);
    match cipher.decrypt(
        n,
        Payload {
            msg: ciphertext,
            aad,
        },
    ) {
        Ok(pt) => {
            let mut h = Sha256::new();
            h.update(live_fp);
            h.update([0x01]);
            let after: [u8; 32] = h.finalize().into();
            serde_json::json!({
                "open_result": "ok",
                "plaintext_hex": hex::encode(pt),
                "durable_mutation": true,
                "promote_live_head": true,
                "live_fp_after_hex": hex::encode(after),
            })
        }
        Err(_) => serde_json::json!({
            "open_result": "fail",
            "durable_mutation": false,
            "promote_live_head": false,
            "live_fp_after_hex": hex::encode(live_fp),
        }),
    }
}

#[derive(Clone, Debug)]
pub struct MailboxCatchupPlan {
    pub today: i64,
    pub ttl_horizon: i64,
    pub late_arrival_floor: i64,
    pub historical_days: Vec<i64>,
    pub always_repoll_days: Vec<i64>,
}

pub fn mailbox_catchup_plan(
    now_ms: i64,
    catchup_cursor_day: i64,
    mailbox_ttl_days: i64,
    late_arrival_days: i64,
) -> MailboxCatchupPlan {
    let today = now_ms / MS_PER_DAY;
    let ttl_horizon = today - mailbox_ttl_days;
    let late_arrival_floor = today - late_arrival_days;
    let start = catchup_cursor_day + 1;
    let start = if start > ttl_horizon {
        start
    } else {
        ttl_horizon
    };
    let mut historical = Vec::new();
    if start < today {
        let mut e = start;
        while e < today {
            historical.push(e);
            e += 1;
        }
    }
    let mut always = BTreeSet::new();
    let mut d = late_arrival_floor.max(ttl_horizon);
    while d <= today {
        always.insert(d);
        d += 1;
    }
    MailboxCatchupPlan {
        today,
        ttl_horizon,
        late_arrival_floor,
        historical_days: historical,
        always_repoll_days: always.into_iter().collect(),
    }
}

#[derive(Clone, Debug, Default)]
pub struct ReceiveCommitMachine {
    pub state: String,
    pub durable_mutation: bool,
    pub skipped_persisted: bool,
    pub epoch_promoted: bool,
    pub epoch_on_candidate: bool,
    pub generation: u64,
}

impl ReceiveCommitMachine {
    pub fn new() -> Self {
        Self {
            state: "idle".into(),
            ..Default::default()
        }
    }

    pub fn apply(&mut self, action: &str) -> Result<(), String> {
        match action {
            "clone_candidate" => {
                if self.state != "idle" {
                    return Err("bad".into());
                }
                self.state = "candidate".into();
            }
            "derive_keys_on_candidate" => {
                if self.state != "candidate" {
                    return Err("bad".into());
                }
                self.state = "derived".into();
            }
            "aead_ok" => {
                if self.state != "derived" {
                    return Err("bad".into());
                }
                self.state = "aead_ok".into();
            }
            "write_PENDING_inbound" => {
                if self.state != "aead_ok" {
                    return Err("bad".into());
                }
                self.state = "pending".into();
            }
            "sql_commit_receipt_dedup" => {
                if self.state != "pending" {
                    return Err("bad".into());
                }
                self.state = "sql_committed".into();
                self.durable_mutation = true;
            }
            "persist_MKSKIPPED" => {
                if self.state != "sql_committed" {
                    return Err("bad".into());
                }
                self.skipped_persisted = true;
                self.state = "skipped_persisted".into();
            }
            "FINALIZE_head" => {
                if self.state != "sql_committed" && self.state != "skipped_persisted" {
                    return Err("finalize_requires_sql".into());
                }
                if self.epoch_on_candidate {
                    return Err("use_commit_epoch_with_finalize".into());
                }
                self.generation += 1;
                self.state = "finalized".into();
            }
            "promote_scka_epoch_on_candidate" => {
                if self.state != "derived" && self.state != "aead_ok" {
                    return Err("bad".into());
                }
                self.epoch_on_candidate = true;
            }
            "commit_epoch_with_finalize" => {
                if self.state != "sql_committed" && self.state != "skipped_persisted" {
                    return Err("epoch_requires_sql".into());
                }
                if !self.epoch_on_candidate {
                    return Err("epoch_requires_pending".into());
                }
                if !self.durable_mutation {
                    return Err("epoch_requires_sql".into());
                }
                self.epoch_promoted = true;
                self.generation += 1;
                self.state = "finalized".into();
            }
            "clear_PENDING" => {
                if self.state != "finalized" {
                    return Err("bad".into());
                }
                self.state = "cleared".into();
            }
            "FINALIZE_before_sql" => return Err("finalize_before_sql_forbidden".into()),
            "promote_epoch_before_sql" => return Err("epoch_before_sql_forbidden".into()),
            _ => return Err(format!("unknown:{action}")),
        }
        Ok(())
    }
}

pub fn run_braid_epoch_matrix(
    sk: &[u8; 32],
    ss1: &[u8; 32],
    ss2: &[u8; 32],
) -> Result<serde_json::Value, String> {
    let alice = scka_from_init(true, sk);
    let bob = scka_from_init(false, sk);
    let alice1i = scka_epoch_promote_initiator(&alice, ss1)?;
    let bob1r = scka_epoch_promote_responder(&bob, ss1)?;
    assert_eq!(alice1i.rk, bob1r.rk);
    assert_eq!(alice1i.ck_send, bob1r.ck_recv);
    let (alice1, a_mk) = scka_next_send_mk(&alice1i)?;
    let (bob1, b_mk) = scka_next_recv_mk(&bob1r)?;
    assert_eq!(a_mk, b_mk);
    let bob2i = scka_epoch_promote_initiator(&bob1, ss2)?;
    let alice2r = scka_epoch_promote_responder(&alice1, ss2)?;
    assert_eq!(bob2i.rk, alice2r.rk);
    assert_eq!(bob2i.ck_send, alice2r.ck_recv);
    let (_bob2, b_mk2) = scka_next_send_mk(&bob2i)?;
    let (_alice2, a_mk2) = scka_next_recv_mk(&alice2r)?;
    assert_eq!(b_mk2, a_mk2);
    Ok(serde_json::json!({
        "directions_reordered": true,
        "epoch1": {
            "rk_hex": hex::encode(alice1i.rk),
            "alice_ck_send_hex": hex::encode(alice1i.ck_send),
            "bob_ck_recv_hex": hex::encode(bob1r.ck_recv),
            "alice_send_equals_bob_recv": alice1i.ck_send == bob1r.ck_recv,
            "mk_hex": hex::encode(a_mk),
            "alice_sending_epoch": alice1i.sending_epoch,
            "bob_receiving_epoch": bob1r.receiving_epoch,
        },
        "epoch2": {
            "rk_hex": hex::encode(bob2i.rk),
            "bob_ck_send_hex": hex::encode(bob2i.ck_send),
            "alice_ck_recv_hex": hex::encode(alice2r.ck_recv),
            "bob_send_equals_alice_recv": bob2i.ck_send == alice2r.ck_recv,
            "mk_hex": hex::encode(b_mk2),
            "bob_sending_epoch": bob2i.sending_epoch,
            "alice_receiving_epoch": alice2r.receiving_epoch,
        },
    }))
}

pub fn run_ec_ooo_matrix(ck0: &[u8; 32], dh_pub: &[u8; 32]) -> Result<serde_json::Value, String> {
    let mut send = EcSendState {
        ck: *ck0,
        n: 0,
        dh_pub: *dh_pub,
    };
    let mut mks = Vec::new();
    for _ in 0..4 {
        let (s, mk) = ec_send_mk(&send)?;
        send = s;
        mks.push(mk);
    }
    let mut recv = EcRecvState {
        ck: *ck0,
        n: 0,
        dh_pub: *dh_pub,
        mkskipped: BTreeMap::new(),
    };
    let order = [0u32, 3, 1, 2];
    let mut recovered = Vec::new();
    for idx in order {
        let (st, mk) = ec_recv_message(&recv, dh_pub, idx, MAX_SKIP)?;
        recv = st;
        assert_eq!(mk, mks[idx as usize]);
        recovered.push(hex::encode(mk));
    }
    Ok(serde_json::json!({
        "send_mks_hex": mks.iter().map(hex::encode).collect::<Vec<_>>(),
        "receive_order": order,
        "recovered_mks_hex": recovered,
        "final_skipped_count": recv.mkskipped.len(),
        "final_n": recv.n,
        "ooo_ok": true,
    }))
}

pub fn run_skip_boundary(ck0: &[u8; 32], dh_pub: &[u8; 32]) -> serde_json::Value {
    let mut cases = Vec::new();
    for count in [0u32, 1, 999, 1000, 1001] {
        let base = EcRecvState {
            ck: *ck0,
            n: 0,
            dh_pub: *dh_pub,
            mkskipped: BTreeMap::new(),
        };
        let fp_before = base.fingerprint();
        match ec_skip_keys(&base, count, MAX_SKIP) {
            Ok(advanced) => {
                let first = if count > 0 {
                    Some(hex::encode(
                        advanced.mkskipped.get(&mk_key(dh_pub, 0)).unwrap(),
                    ))
                } else {
                    None
                };
                let last = if count > 0 {
                    Some(hex::encode(
                        advanced.mkskipped.get(&mk_key(dh_pub, count - 1)).unwrap(),
                    ))
                } else {
                    None
                };
                cases.push(serde_json::json!({
                    "skip_count": count,
                    "result": "ok",
                    "skipped_stored": count,
                    "first_mk_hex": first,
                    "last_mk_hex": last,
                    "final_ck_hex": hex::encode(advanced.ck),
                    "final_n": advanced.n,
                    "fp_before_hex": hex::encode(fp_before),
                    "fp_after_hex": hex::encode(advanced.fingerprint()),
                }));
            }
            Err(reason) => {
                cases.push(serde_json::json!({
                    "skip_count": count,
                    "result": "reject",
                    "reason": reason,
                    "fp_before_hex": hex::encode(fp_before),
                    "fp_after_hex": hex::encode(base.fingerprint()),
                    "state_unchanged": base.fingerprint() == fp_before,
                    "allocation": false,
                    "state_advance": false,
                }));
            }
        }
    }
    serde_json::json!({ "max_skip": MAX_SKIP, "cases": cases })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors/rvn1/atsam")
    }

    fn load(name: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(root().join(name)).unwrap()).unwrap()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn scka_epochs_are_u64_and_fail_closed_instead_of_wrapping() {
        let mut state = scka_from_init(true, &[0x42; 32]);
        state.sending_epoch = u64::from(u32::MAX);
        state.receiving_epoch = u64::from(u32::MAX);
        let ss = [0x07; 32];
        // Past the old u32 range: no wrap to 0.
        assert_eq!(
            scka_epoch_promote_initiator(&state, &ss)
                .unwrap()
                .sending_epoch,
            u64::from(u32::MAX) + 1
        );
        assert_eq!(
            scka_epoch_promote_responder(&state, &ss)
                .unwrap()
                .receiving_epoch,
            u64::from(u32::MAX) + 1
        );
        state.sending_epoch = u64::MAX;
        state.receiving_epoch = u64::MAX;
        assert!(scka_epoch_promote_initiator(&state, &ss).is_err());
        assert!(scka_epoch_promote_responder(&state, &ss).is_err());
        state.send_ctr = u32::MAX;
        state.recv_ctr = u32::MAX;
        assert!(scka_next_send_mk(&state).is_err());
        assert!(scka_next_recv_mk(&state).is_err());
        let send = EcSendState {
            ck: [0x01; 32],
            n: u32::MAX,
            dh_pub: [0x02; 32],
        };
        assert!(ec_send_mk(&send).is_err());
        // Secrets never reach Debug output.
        let printed = format!("{state:?}{send:?}");
        assert!(printed.contains("<redacted>"));
        assert!(!printed.contains("rk:") && !printed.contains("[1, 1, 1"));
    }

    #[test]
    fn ec_skip_keys_enforces_global_retention_cap() {
        let mut state = EcRecvState {
            ck: [0x03; 32],
            n: 0,
            dh_pub: [0x04; 32],
            mkskipped: BTreeMap::new(),
        };
        for n in 0..1500u32 {
            state.mkskipped.insert(mk_key(&[0x05; 32], n), [0x06; 32]);
        }
        // Within MAX_SKIP for this chain, but past the total retention cap.
        assert_eq!(
            ec_skip_keys(&state, 600, MAX_SKIP).unwrap_err(),
            "MAX_MKSKIPPED_RETAINED exceeded"
        );
        assert_eq!(
            ec_skip_keys(&state, 500, MAX_SKIP).unwrap().mkskipped.len(),
            MAX_MKSKIPPED_RETAINED
        );
    }

    #[test]
    fn braid_epoch_001() {
        let v = load("tr_braid_epoch_001.json");
        let out = run_braid_epoch_matrix(
            &hex32(v["inputs"]["sk_scka_hex"].as_str().unwrap()),
            &hex32(v["inputs"]["ss_epoch1_hex"].as_str().unwrap()),
            &hex32(v["inputs"]["ss_epoch2_hex"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(out, v["expected"]);
    }

    #[test]
    fn ec_ooo_001() {
        let v = load("tr_ec_ooo_001.json");
        let out = run_ec_ooo_matrix(
            &hex32(v["inputs"]["ck_hex"].as_str().unwrap()),
            &hex32(v["inputs"]["dh_pub_hex"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(out, v["expected"]);
    }

    #[test]
    fn skip_boundary_001() {
        let v = load("tr_skip_boundary_001.json");
        let out = run_skip_boundary(
            &hex32(v["inputs"]["ck_hex"].as_str().unwrap()),
            &hex32(v["inputs"]["dh_pub_hex"].as_str().unwrap()),
        );
        assert_eq!(out, v["expected"]);
    }

    #[test]
    fn replay_duplicate_001() {
        let v = load("tr_replay_duplicate_001.json");
        let inp = &v["inputs"];
        let ledger = CommitLedger::default();
        let key = AcceptKey {
            session_id: hex32(inp["session_id_hex"].as_str().unwrap()),
            dh_pub: hex32(inp["dh_pub_hex"].as_str().unwrap()),
            n: inp["accept_key"]["n"].as_u64().unwrap() as u32,
            scka_epoch: inp["accept_key"]["scka_epoch"].as_u64().unwrap() as u32,
            scka_ctr: inp["accept_key"]["scka_ctr"].as_u64().unwrap() as u32,
        };
        let digest = hex32(inp["object_digest_hex"].as_str().unwrap());
        let ack = hex::decode(inp["retained_ack_hex"].as_str().unwrap()).unwrap();
        let (ledger, r1) = commit_accept(&ledger, &key, &digest, &ack);
        let fp1 = ledger.fingerprint();
        let (ledger2, r2) = commit_accept(&ledger, &key, &digest, &ack);
        let fp2 = ledger2.fingerprint();
        let dup = duplicate_ack_exact(&ledger2, &digest).unwrap();
        assert_eq!(r1, v["expected"]["first_result"].as_str().unwrap());
        assert_eq!(r2, v["expected"]["replay_result"].as_str().unwrap());
        assert_eq!(
            hex::encode(fp1),
            v["expected"]["fp_after_accept_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(fp2),
            v["expected"]["fp_after_replay_hex"].as_str().unwrap()
        );
        assert_eq!(fp1, fp2);
        assert_eq!(dup, ack);
        assert_eq!(ledger2.mutation_count, 1);
    }

    #[test]
    fn route_mailbox_001() {
        let v = load("tr_route_mailbox_001.json");
        let inp = &v["inputs"];
        let master = hex32(inp["k_route_master_hex"].as_str().unwrap());
        let sid = hex32(inp["session_id_hex"].as_str().unwrap());
        let kr0 = k_route(&master, 0).unwrap();
        let kr1 = k_route(&master, 1).unwrap();
        let r0 = routing_tag(
            &kr0,
            inp["created_at_ms"].as_u64().unwrap(),
            inp["n"].as_u64().unwrap(),
            inp["app_type"].as_u64().unwrap() as u8,
            0,
            &sid,
        );
        let r1 = routing_tag(
            &kr1,
            inp["created_at_ms"].as_u64().unwrap(),
            inp["n"].as_u64().unwrap(),
            inp["app_type"].as_u64().unwrap() as u8,
            1,
            &sid,
        );
        let m0 = mailbox_tag(&kr0, inp["now_ms"].as_u64().unwrap(), 0, &sid);
        let s0 = store_tag(&m0);
        let plan = mailbox_catchup_plan(
            inp["now_ms"].as_i64().unwrap(),
            inp["catchup_cursor_day"].as_i64().unwrap(),
            inp["mailbox_ttl_days"].as_i64().unwrap(),
            MAILBOX_LATE_ARRIVAL_DAYS,
        );
        assert_eq!(
            hex::encode(kr0),
            v["expected"]["k_route_0_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(kr1),
            v["expected"]["k_route_1_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(r0),
            v["expected"]["routing_tag_d0_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(r1),
            v["expected"]["routing_tag_d1_hex"].as_str().unwrap()
        );
        assert_ne!(r0, r1);
        assert_eq!(
            hex::encode(m0),
            v["expected"]["mailbox_tag_d0_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(s0),
            v["expected"]["store_tag_d0_hex"].as_str().unwrap()
        );
        assert_eq!(
            plan.today,
            v["expected"]["catchup"]["today"].as_i64().unwrap()
        );
        assert_eq!(
            plan.ttl_horizon,
            v["expected"]["catchup"]["ttl_horizon"].as_i64().unwrap()
        );
        assert_eq!(
            plan.late_arrival_floor,
            v["expected"]["catchup"]["late_arrival_floor"]
                .as_i64()
                .unwrap()
        );
        assert_eq!(
            plan.historical_days,
            v["expected"]["catchup"]["historical_days"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_i64().unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            plan.always_repoll_days,
            v["expected"]["catchup"]["always_repoll_days"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_i64().unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            plan.historical_days.len() as i64,
            v["expected"]["catchup"]["historical_span"]
                .as_i64()
                .unwrap()
        );
    }

    #[test]
    fn tamper_candidate_001() {
        let v = load("tr_tamper_candidate_001.json");
        let inp = &v["inputs"];
        let key = hex32(inp["aead_key_hex"].as_str().unwrap());
        let nonce_v = hex::decode(inp["nonce_hex"].as_str().unwrap()).unwrap();
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_v);
        let ct = hex::decode(inp["ciphertext_hex"].as_str().unwrap()).unwrap();
        let aad = hex::decode(inp["aad_hex"].as_str().unwrap()).unwrap();
        let live = hex32(inp["live_fp_hex"].as_str().unwrap());

        let good = candidate_decrypt(&key, &nonce, &ct, &aad, &live);
        assert_eq!(good, v["expected"]["good"]);

        let mut bad_ct = ct.clone();
        let last = bad_ct.len() - 1;
        bad_ct[last] ^= 0x01;
        assert_eq!(
            candidate_decrypt(&key, &nonce, &bad_ct, &aad, &live),
            v["expected"]["bad_ciphertext"]
        );

        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 0x01;
        assert_eq!(
            candidate_decrypt(&key, &bad_nonce, &ct, &aad, &live),
            v["expected"]["bad_nonce"]
        );

        let mut bad_aad = aad.clone();
        let last = bad_aad.len() - 1;
        bad_aad[last] ^= 0x01;
        assert_eq!(
            candidate_decrypt(&key, &nonce, &ct, &bad_aad, &live),
            v["expected"]["bad_aad_header"]
        );

        let mut h = Sha256::new();
        h.update(key);
        let wrong: [u8; 32] = h.finalize().into();
        assert_eq!(
            candidate_decrypt(&wrong, &nonce, &ct, &aad, &live),
            v["expected"]["wrong_root_key"]
        );
    }

    #[test]
    fn crash_machines() {
        for name in [
            "tr_crash_receive_commit_001.json",
            "tr_crash_skipped_persist_001.json",
            "tr_crash_epoch_promote_001.json",
        ] {
            let v = load(name);
            let mut m = ReceiveCommitMachine::new();
            for step in v["steps"].as_array().unwrap() {
                m.apply(step["action"].as_str().unwrap()).unwrap();
            }
            assert_eq!(m.state, "cleared");
            for neg in v["negatives"].as_array().unwrap() {
                let mut bad = ReceiveCommitMachine::new();
                assert!(bad.apply(neg.as_str().unwrap()).is_err());
            }
        }
    }
}
