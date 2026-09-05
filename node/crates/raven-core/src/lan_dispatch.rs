//! Inbound LAN-direct dispatch after Noise XX.
//!
//! Handles RLB1 offers, PairInit responder, indexed messages, and sealed ACKs.

#[cfg(test)]
use std::cell::Cell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::address::encode_address;
use crate::atsam_mlkem::{begin_hybrid_initiation, HybridKeypair};
use crate::chat_history::{
    clear_staged_outbound_body, list_staged_outbound_bodies, load_staged_outbound_body,
    stage_outbound_body, BlockList, ChatHistory, ChatHistoryEntry, StagedOutboundBody,
};
use crate::device_cert::{ensure_local_device_certificate, DeviceCertificate, DeviceRegistry};
use crate::device_sync::RevocationStore;
use crate::envelope::{EnvType, Envelope};
use crate::identity::Identity;
use crate::indexed_session_store::{
    AuthorizedEndpointDevice, EndpointAcceptance, EndpointDeliveryState, IndexedSessionRecordKey,
    IndexedSessionStore, IndexedSessionStoreError, LocalRole,
};
use crate::lan_rlb1::{decode_offer, encode_offer, is_rlb1, LanBundle};
use crate::pair_init::{
    confirmation_tag, decode_init, decode_response, device_certificate_hash, encode_init,
    encode_response, init_hash, init_signing_bytes, prekey_bundle_hash, response_signing_bytes,
    session_id, transcript_hash, PairInit, PairInitTrust, PairResponse,
};
use crate::pair_init_lan_oob::{
    classify_packed_envelope, wrap_oob_wire, PairInitOobClassify, PairInitOobKind,
};
use crate::paths::{DataDirLock, PRIMARY_DEVICE_ID};
use crate::prekey_bundle::{PrekeyBundle, PrekeyStore};
use crate::prekey_lifecycle::{PrekeyClaimOutcome, PrekeyGenerationPrivate, PrekeyLifecycleActor};
use zeroize::Zeroize;

const PEER_CERT_CACHE: &str = "peer_device_certs.json";
const PEER_CACHE_STAGE: &str = "peer_cache.stage.json";
const PEER_CACHE_LOCK: &str = ".lan_peer_cache.lock.sqlite";
/// Soft cap for durable contact-trusted peer keys (device_ed + user_ed).
const MAX_TRUSTED_PEER_CERT_KEYS: usize = 256;
const EPHEMERAL_PEER_TTL: Duration = Duration::from_secs(15 * 60);
const EPHEMERAL_PEER_MAX: usize = 16;

#[derive(Clone)]
struct EphemeralPeer {
    bundle: LanBundle,
    expires_at: Instant,
}

type EphemeralDirMap = HashMap<String, HashMap<[u8; 32], EphemeralPeer>>;

/// Per data-dir ephemeral peers, keyed only by device_ed (one slot per peer).
static EPHEMERAL_PEERS: Mutex<Option<EphemeralDirMap>> = Mutex::new(None);

#[cfg(test)]
thread_local! {
    static FAIL_AFTER_PEER_CACHE_STAGE: Cell<bool> = const { Cell::new(false) };
}

fn ephemeral_dir_key(data_dir: &Path) -> String {
    std::fs::canonicalize(data_dir)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| data_dir.to_string_lossy().into_owned())
}

/// Keep an unverified/unknown LAN peer in process memory only (TTL + LRU).
/// Never writes `peer_device_certs.json` / `prekey_store.json`.
pub fn remember_ephemeral_peer(data_dir: &Path, bundle: &LanBundle) -> Result<(), String> {
    let now = Instant::now();
    let dir_key = ephemeral_dir_key(data_dir);
    let mut guard = EPHEMERAL_PEERS
        .lock()
        .map_err(|_| "ephemeral peer lock poisoned".to_string())?;
    let root = guard.get_or_insert_with(HashMap::new);
    let map = root.entry(dir_key).or_insert_with(HashMap::new);
    map.retain(|_, e| e.expires_at > now);
    while map.len() >= EPHEMERAL_PEER_MAX {
        let victim = map
            .iter()
            .min_by_key(|(_, e)| e.expires_at)
            .map(|(k, _)| *k);
        let Some(k) = victim else {
            break;
        };
        map.remove(&k);
    }
    map.insert(
        bundle.cert.device_ed_pub,
        EphemeralPeer {
            bundle: bundle.clone(),
            expires_at: now + EPHEMERAL_PEER_TTL,
        },
    );
    Ok(())
}

fn load_ephemeral_peer(data_dir: &Path, peer_pub: &[u8; 32]) -> Option<LanBundle> {
    let now = Instant::now();
    let dir_key = ephemeral_dir_key(data_dir);
    let mut guard = EPHEMERAL_PEERS.lock().ok()?;
    let root = guard.as_mut()?;
    let map = root.get_mut(&dir_key)?;
    map.retain(|_, e| e.expires_at > now);
    if let Some(e) = map.get(peer_pub) {
        return Some(e.bundle.clone());
    }
    map.values()
        .find(|e| e.bundle.cert.user_ed_pub == *peer_pub)
        .map(|e| e.bundle.clone())
}

#[derive(Debug, Deserialize)]
struct ContactPubRow {
    #[serde(default)]
    pub_hex: String,
    #[serde(default)]
    petname: String,
    #[serde(default)]
    public_tag: String,
    #[serde(default)]
    alias: String,
}

fn contact_rows(data_dir: &Path) -> Result<Vec<ContactPubRow>, String> {
    let path = data_dir.join("contacts.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("contacts.json: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("contacts.json corrupt: {e}"))
}

fn contact_pub_set(data_dir: &Path) -> Result<std::collections::HashSet<String>, String> {
    Ok(contact_rows(data_dir)?
        .into_iter()
        .map(|r| r.pub_hex.trim().to_lowercase())
        .filter(|h| !h.is_empty())
        .collect())
}

fn contact_label_for_pub(data_dir: &Path, pub_hex: &str) -> (String, String) {
    let want = pub_hex.trim().to_lowercase();
    let Ok(rows) = contact_rows(data_dir) else {
        return (String::new(), String::new());
    };
    for r in rows {
        if r.pub_hex.trim().eq_ignore_ascii_case(&want) {
            let tag = if !r.public_tag.is_empty() {
                r.public_tag
            } else {
                r.alias
            };
            return (r.petname, tag);
        }
    }
    (String::new(), String::new())
}

/// Persist a LAN message into durable ChatHistory (full body + short preview).
/// Deduped/upserted by (peer_pub, direction, message_id). Failures must be propagated.
pub fn persist_lan_chat_history(
    data_dir: &Path,
    direction: &str,
    peer_pub: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    delivery: &str,
    plaintext: &[u8],
) -> Result<(), String> {
    let peer_pub_hex = hex::encode(peer_pub);
    let (peer_petname, peer_tag) = contact_label_for_pub(data_dir, &peer_pub_hex);
    let text = String::from_utf8_lossy(plaintext);
    let body = text.as_ref().to_string();
    let preview: String = body.chars().take(120).collect();
    let entry = ChatHistoryEntry {
        message_id_hex: hex::encode(message_id),
        direction: direction.into(),
        peer_petname,
        peer_tag,
        peer_pub_hex,
        created_at_ms,
        delivery: delivery.into(),
        preview,
        body,
    };
    ChatHistory::append_persisted(data_dir, entry).map_err(|e| e.to_string())
}

/// Upgrade an existing history row's delivery (e.g. `queued` → `delivered`).
/// Fails if no matching row exists — callers must not treat missing as success
/// when committing Delivered / Failed.
pub fn mark_lan_chat_history_delivery(
    data_dir: &Path,
    direction: &str,
    peer_pub: &[u8; 32],
    message_id: &[u8; 16],
    delivery: &str,
) -> Result<(), String> {
    let updated = ChatHistory::set_delivery_persisted(
        data_dir,
        &hex::encode(peer_pub),
        direction,
        &hex::encode(message_id),
        delivery,
    )
    .map_err(|e| e.to_string())?;
    if !updated {
        return Err(format!(
            "chat history row missing for delivery={delivery} mid={}",
            hex::encode(message_id)
        ));
    }
    Ok(())
}

fn parse_stage_hex32(hex_s: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_s).map_err(|e| e.to_string())?;
    if bytes.len() != 32 {
        return Err("staged binding hex must be 32 bytes".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn parse_stage_hex16(hex_s: &str) -> Result<[u8; 16], String> {
    let bytes = hex::decode(hex_s).map_err(|e| e.to_string())?;
    if bytes.len() != 16 {
        return Err("staged message_id hex must be 16 bytes".into());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn map_stage_persist_err(err: crate::chat_history::ChatHistoryError) -> String {
    match err {
        crate::chat_history::ChatHistoryError::TooLarge => {
            "outbound stage capacity exceeded".into()
        }
        other => other.to_string(),
    }
}

fn staged_binding_matches(
    staged: &StagedOutboundBody,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
) -> bool {
    staged
        .peer_pub_hex
        .eq_ignore_ascii_case(&hex::encode(peer_pub))
        && staged
            .session_id_hex
            .eq_ignore_ascii_case(&hex::encode(session_id))
        && staged
            .object_digest_hex
            .eq_ignore_ascii_case(&hex::encode(object_digest))
        && staged
            .message_id_hex
            .eq_ignore_ascii_case(&hex::encode(message_id))
}

/// Ensure outbound history has the exact body (from stage and/or compose text)
/// before dialing. Writes durable protected stage first, then ChatHistory `queued`.
/// Uses the staged `created_at_ms` on retry (never the caller's "now").
pub fn ensure_outbound_queued_history(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    compose_text: Option<&str>,
) -> Result<(), String> {
    ensure_outbound_queued_history_inner(
        data_dir,
        None,
        peer_pub,
        session_id,
        object_digest,
        message_id,
        created_at_ms,
        compose_text,
    )
}

/// Same as [`ensure_outbound_queued_history`], but stages under an already-held
/// [`OutboundStageSendGuard`] so capacity preflight cannot race the write.
pub fn ensure_outbound_queued_history_under_send_guard(
    guard: &crate::chat_history::OutboundStageSendGuard,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    compose_text: Option<&str>,
) -> Result<(), String> {
    ensure_outbound_queued_history_inner(
        guard.data_dir(),
        Some(guard),
        peer_pub,
        session_id,
        object_digest,
        message_id,
        created_at_ms,
        compose_text,
    )
}

#[allow(clippy::too_many_arguments)]
fn ensure_outbound_queued_history_inner(
    data_dir: &Path,
    stage_guard: Option<&crate::chat_history::OutboundStageSendGuard>,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    created_at_ms: u64,
    compose_text: Option<&str>,
) -> Result<(), String> {
    let (body, stamped_at) = if let Some(text) = compose_text {
        if let Some(guard) = stage_guard {
            guard
                .stage_outbound_body(
                    peer_pub,
                    session_id,
                    object_digest,
                    message_id,
                    created_at_ms,
                    text,
                )
                .map_err(map_stage_persist_err)?;
        } else {
            stage_outbound_body(
                data_dir,
                peer_pub,
                session_id,
                object_digest,
                message_id,
                created_at_ms,
                text,
            )
            .map_err(map_stage_persist_err)?;
        }
        let staged = if let Some(guard) = stage_guard {
            guard
                .load_staged_outbound_body(message_id)
                .map_err(map_stage_persist_err)?
        } else {
            load_staged_outbound_body(data_dir, message_id).map_err(map_stage_persist_err)?
        }
        .ok_or_else(|| "staged outbound missing after write".to_string())?;
        if !staged_binding_matches(&staged, peer_pub, session_id, object_digest, message_id) {
            return Err("staged outbound binding mismatch after write".into());
        }
        (staged.body, staged.created_at_ms)
    } else if let Some(staged) = {
        if let Some(guard) = stage_guard {
            guard
                .load_staged_outbound_body(message_id)
                .map_err(map_stage_persist_err)?
        } else {
            load_staged_outbound_body(data_dir, message_id).map_err(map_stage_persist_err)?
        }
    } {
        if !staged_binding_matches(&staged, peer_pub, session_id, object_digest, message_id) {
            return Err(format!(
                "staged outbound binding mismatch for mid={}",
                hex::encode(message_id)
            ));
        }
        (staged.body, staged.created_at_ms)
    } else if ChatHistory::has_body_persisted(
        data_dir,
        &hex::encode(peer_pub),
        "out",
        &hex::encode(message_id),
    )
    .map_err(|e| e.to_string())?
    {
        return Ok(());
    } else {
        return Err(format!(
            "outbound body unavailable for mid={}",
            hex::encode(message_id)
        ));
    };
    persist_lan_chat_history(
        data_dir,
        "out",
        peer_pub,
        message_id,
        stamped_at,
        "queued",
        body.as_bytes(),
    )
}

/// Reconcile protected stage after crash between accept_ack and mark/clear.
/// - `Delivered`/`Read` outstanding → history `delivered`, clear stage
/// - `Sent` outstanding → re-ensure `queued` history from stage
/// - no outstanding row → treat as abandoned → history `failed`, clear stage
pub fn reconcile_outbound_stage_history(data_dir: &Path) -> Result<(), String> {
    let staged = list_staged_outbound_bodies(data_dir).map_err(|e| e.to_string())?;
    if staged.is_empty() {
        return Ok(());
    }
    let store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    for entry in staged {
        let peer = parse_stage_hex32(&entry.peer_pub_hex)?;
        let session_id = parse_stage_hex32(&entry.session_id_hex)?;
        let object_digest = parse_stage_hex32(&entry.object_digest_hex)?;
        let message_id = parse_stage_hex16(&entry.message_id_hex)?;
        let delivery = store
            .outstanding_delivery_state(&session_id, &message_id, &peer)
            .map_err(|e| e.redacted_display())?;
        match delivery {
            Some(EndpointDeliveryState::Delivered) | Some(EndpointDeliveryState::Read) => {
                ensure_outbound_queued_history(
                    data_dir,
                    &peer,
                    &session_id,
                    &object_digest,
                    &message_id,
                    entry.created_at_ms,
                    None,
                )?;
                mark_lan_chat_history_delivery(data_dir, "out", &peer, &message_id, "delivered")?;
                clear_staged_outbound_body(data_dir, &message_id).map_err(|e| e.to_string())?;
            }
            Some(EndpointDeliveryState::Sent) => {
                ensure_outbound_queued_history(
                    data_dir,
                    &peer,
                    &session_id,
                    &object_digest,
                    &message_id,
                    entry.created_at_ms,
                    None,
                )?;
            }
            None => {
                persist_lan_chat_history(
                    data_dir,
                    "out",
                    &peer,
                    &message_id,
                    entry.created_at_ms,
                    "failed",
                    entry.body.as_bytes(),
                )?;
                clear_staged_outbound_body(data_dir, &message_id).map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

fn archive_expired_inbox_to_history(data_dir: &Path, now: u64) -> Result<(), String> {
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    for key in sessions
        .list_record_keys()
        .map_err(|e| e.redacted_display())?
    {
        // Metadata-only expiry — must not load protected state (secret may already be gone).
        let expires = sessions
            .head_expires_at_ms(&key)
            .map_err(|e| e.redacted_display())?;
        if expires > now {
            continue;
        }
        match sessions.list_endpoint_inbox_for_record(&key) {
            Ok(rows) => {
                for row in rows {
                    persist_lan_chat_history(
                        data_dir,
                        "in",
                        &row.sender_device,
                        &row.message_id,
                        row.created_at_ms,
                        "received",
                        &row.plaintext,
                    )?;
                }
            }
            // Secret already deleted after a prior crash — history must have been
            // written on accept; continue so SQLite metadata can be pruned.
            Err(IndexedSessionStoreError::ProtectedStateMissing) => {}
            Err(e) => return Err(e.redacted_display()),
        }
    }
    Ok(())
}

/// Durable peer cache requires **user trust** (local contact book), not merely a
/// cryptographically confirmed PairInit session (attackers can self-PairInit).
pub fn peer_is_trusted(data_dir: &Path, bundle: &LanBundle) -> Result<bool, String> {
    let contacts = contact_pub_set(data_dir)?;
    let device = hex::encode(bundle.cert.device_ed_pub);
    let user = hex::encode(bundle.cert.user_ed_pub);
    Ok(contacts.contains(&device) || contacts.contains(&user))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Envelope expiry must stay inside the PairInit session window (typically 24h).
fn envelope_expires(now: u64, session_expires: u64) -> Result<u64, String> {
    let expires = now.saturating_add(60 * 60 * 1000).min(session_expires);
    if expires <= now {
        return Err("session expired".into());
    }
    Ok(expires)
}

/// Publish a local hybrid prekey if none is currently fetchable.
pub fn ensure_local_prekey(data_dir: &Path, id: &Identity) -> Result<(), String> {
    let now = now_ms();
    let _ = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID)?;
    let store = PrekeyStore::load_checked(data_dir)?;
    if store.fetch(&id.public_key_bytes(), now)?.is_some() {
        return Ok(());
    }
    let mut rng = rand::thread_rng();
    let mut kp = HybridKeypair::generate(&mut rng);
    let actor = PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    let next_id = actor
        .status()
        .map_err(|e| e.to_string())?
        .highest_signed_prekey_id
        .saturating_add(1)
        .max(1);
    let bundle = PrekeyBundle::from_hybrid_public(
        PRIMARY_DEVICE_ID,
        kp.x25519_public,
        kp.mlkem_ek_bytes.clone(),
        next_id,
        now,
        now.saturating_add(30 * 24 * 3600 * 1000),
    )?
    .sign(id)?;
    actor
        .install_generation(
            std::slice::from_ref(&bundle),
            PrekeyGenerationPrivate::new(kp.x25519_secret, kp.mlkem_seed, vec![]),
            now,
        )
        .map_err(|e| e.to_string())?;
    kp.x25519_secret.zeroize();
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    let mut store = PrekeyStore::load_checked(data_dir)?;
    store.publish(&bundle, now)?;
    store.save(data_dir)?;
    Ok(())
}

pub fn local_bundle(data_dir: &Path, id: &Identity) -> Result<LanBundle, String> {
    ensure_local_prekey(data_dir, id)?;
    let (cert, _) = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID)?;
    let now = now_ms();
    let store = PrekeyStore::load_checked(data_dir)?;
    let prekey = store
        .fetch(&id.public_key_bytes(), now)?
        .ok_or_else(|| "local prekey missing after ensure".to_string())?;
    Ok(LanBundle { cert, prekey })
}

pub fn rlb1_matches_noise_identity(peer: &LanBundle, noise_ed: &[u8; 32]) -> bool {
    peer.cert.device_ed_pub == *noise_ed || peer.cert.user_ed_pub == *noise_ed
}

pub fn lan_peer_blocked(
    data_dir: &Path,
    peer: &LanBundle,
    noise_ed: &[u8; 32],
) -> Result<bool, String> {
    let blocks = BlockList::load_checked(data_dir)?;
    Ok(blocks.is_blocked(&hex::encode(noise_ed))
        || blocks.is_blocked(&hex::encode(peer.cert.user_ed_pub))
        || blocks.is_blocked(&hex::encode(peer.cert.device_ed_pub)))
}

fn pair_revocation(
    data_dir: &Path,
    local_registry: &DeviceRegistry,
    local_role: LocalRole,
    initiator_user_ed: &[u8; 32],
    initiator_device_id: &str,
    responder_user_ed: &[u8; 32],
    responder_device_id: &str,
) -> Result<(bool, bool), String> {
    let rev = RevocationStore::load_checked(data_dir)?;
    // DeviceRegistry is local-identity-scoped. Apply it only to the local role's
    // side — never by comparing device_id strings (both peers are often ash-primary).
    let initiator_revoked = rev.is_revoked(&hex::encode(initiator_user_ed), initiator_device_id)
        || (local_role == LocalRole::Initiator && local_registry.is_revoked(initiator_device_id));
    let responder_revoked = rev.is_revoked(&hex::encode(responder_user_ed), responder_device_id)
        || (local_role == LocalRole::Responder && local_registry.is_revoked(responder_device_id));
    Ok((initiator_revoked, responder_revoked))
}

fn cached_pair_response_path(data_dir: &Path, init_id: &[u8; 16]) -> std::path::PathBuf {
    data_dir
        .join("lan_pair_response")
        .join(hex::encode(init_id))
}

fn verify_cached_pair_response_bytes(
    packed: &[u8],
    init: &PairInit,
    local_device_ed: &[u8; 32],
) -> Result<Vec<u8>, String> {
    if packed.is_empty() {
        return Err("pair response cache empty".into());
    }
    let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(packed) else {
        return Err("pair response cache is not PairResponse OOB".into());
    };
    let response =
        decode_response(&wire).map_err(|e| format!("pair response cache decode: {e}"))?;
    let digest = init_hash(init).map_err(|e| format!("{e}"))?;
    if response.init_id != init.init_id {
        return Err("pair response cache init_id mismatch".into());
    }
    if response.init_hash != digest {
        return Err("pair response cache init_hash mismatch".into());
    }
    if &response.responder_device_ed_pub != local_device_ed {
        return Err("pair response cache responder mismatch".into());
    }
    let signing = response_signing_bytes(&response).map_err(|e| format!("{e}"))?;
    if !Identity::verify(
        &response.responder_device_ed_pub,
        &signing,
        &response.signature,
    ) {
        return Err("pair response cache bad signature".into());
    }
    Ok(packed.to_vec())
}

fn load_verified_cached_pair_response(
    data_dir: &Path,
    init: &PairInit,
    local_device_ed: &[u8; 32],
) -> Result<Vec<u8>, String> {
    let path = cached_pair_response_path(data_dir, &init.init_id);
    let bytes =
        std::fs::read(&path).map_err(|_| "pair response unavailable for retry".to_string())?;
    match verify_cached_pair_response_bytes(&bytes, init, local_device_ed) {
        Ok(v) => Ok(v),
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            Err(e)
        }
    }
}

fn store_cached_pair_response(
    data_dir: &Path,
    init_id: &[u8; 16],
    packed: &[u8],
) -> Result<(), String> {
    crate::paths::atomic_write_private(&cached_pair_response_path(data_dir, init_id), packed)
}

fn replay_cached_pair_response(
    data_dir: &Path,
    init: &PairInit,
    local_device_ed: &[u8; 32],
) -> Result<Vec<Vec<u8>>, String> {
    Ok(vec![load_verified_cached_pair_response(
        data_dir,
        init,
        local_device_ed,
    )?])
}

pub fn encode_local_offer(data_dir: &Path, id: &Identity) -> Result<Vec<u8>, String> {
    encode_offer(&local_bundle(data_dir, id)?)
}

fn load_peer_cert_map_checked(path: &Path) -> Result<HashMap<String, DeviceCertificate>, String> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| format!("peer cert cache read: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("peer cert cache corrupt: {e}"))
}

#[derive(Debug, Serialize, Deserialize)]
struct PeerCacheStage {
    generation: u64,
    certs_json: String,
    prekey_json: String,
}

fn peer_cache_stage_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join(PEER_CACHE_STAGE)
}

fn peer_cache_gen_path(data_dir: &Path) -> std::path::PathBuf {
    data_dir.join("peer_cache.generation")
}

fn read_committed_peer_cache_generation(data_dir: &Path) -> Result<u64, String> {
    let path = peer_cache_gen_path(data_dir);
    if !path.exists() {
        return Ok(0);
    }
    let raw =
        std::fs::read_to_string(&path).map_err(|e| format!("peer_cache.generation read: {e}"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("peer_cache.generation empty".into());
    }
    trimmed
        .parse::<u64>()
        .map_err(|_| "peer_cache.generation corrupt".to_string())
}

fn write_committed_peer_cache_generation(data_dir: &Path, generation: u64) -> Result<(), String> {
    if generation == 0 {
        return Err("peer_cache.generation refuse zero".into());
    }
    crate::paths::atomic_write_private(
        &peer_cache_gen_path(data_dir),
        format!("{generation}\n").as_bytes(),
    )
}

/// Verify stage payloads, drop expired entries, return sanitized cert/prekey JSON.
fn sanitize_peer_cache_stage_payloads(
    stage: &PeerCacheStage,
    now: u64,
) -> Result<(String, String), String> {
    if stage.generation == 0 {
        return Err("peer cache stage generation missing".into());
    }
    let mut map: HashMap<String, DeviceCertificate> = serde_json::from_str(&stage.certs_json)
        .map_err(|e| format!("peer cache stage certs corrupt: {e}"))?;
    map.retain(|key, cert| {
        if cert.verify(now).is_err() {
            return false;
        }
        let device = hex::encode(cert.device_ed_pub);
        let user = hex::encode(cert.user_ed_pub);
        key == &device || key == &user
    });
    if map.is_empty() {
        return Err("peer cache stage certs empty after expiry prune".into());
    }
    for (key, cert) in &map {
        let device = hex::encode(cert.device_ed_pub);
        let user = hex::encode(cert.user_ed_pub);
        if key != &device && key != &user {
            return Err("peer cache stage cert key mismatch".into());
        }
    }
    let mut store: PrekeyStore = serde_json::from_str(&stage.prekey_json)
        .map_err(|e| format!("peer cache stage prekey corrupt: {e}"))?;
    let _ = store.retain_valid(now);
    if store.is_empty() {
        return Err("peer cache stage prekey empty after expiry prune".into());
    }
    let raw: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&store).map_err(|e| e.to_string())?)
            .map_err(|e| format!("peer cache stage prekey json: {e}"))?;
    let Some(bundles) = raw.get("bundles").and_then(|b| b.as_object()) else {
        return Err("peer cache stage prekey missing bundles".into());
    };
    for (key, value) in bundles {
        let j: crate::prekey_bundle::PrekeyBundleJson = serde_json::from_value(value.clone())
            .map_err(|e| format!("peer cache stage bundle {key}: {e}"))?;
        let b = PrekeyBundle::from_json(&j)
            .map_err(|e| format!("peer cache stage bundle {key}: {e}"))?;
        b.verify(now)
            .map_err(|e| format!("peer cache stage bundle {key}: {e}"))?;
        // Peer certs must bind matching prekeys; local/other identities may coexist
        // in the shared prekey_store.json without a peer cert entry.
        if let Some(cert) = map
            .values()
            .find(|cert| cert.user_ed_pub == b.identity_ed25519_pub)
        {
            if b.device_id != cert.device_id {
                return Err(format!("peer cache stage bundle {key}: device_id mismatch"));
            }
        }
    }
    // Every peer cert must have a currently valid matching prekey in the store.
    for cert in map.values() {
        let has = bundles.values().any(|value| {
            let Ok(j) =
                serde_json::from_value::<crate::prekey_bundle::PrekeyBundleJson>(value.clone())
            else {
                return false;
            };
            let Ok(b) = PrekeyBundle::from_json(&j) else {
                return false;
            };
            b.identity_ed25519_pub == cert.user_ed_pub && b.device_id == cert.device_id
        });
        if !has {
            return Err("peer cache stage cert missing bound prekey".into());
        }
    }
    let certs_json = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
    let prekey_json = serde_json::to_string_pretty(&store).map_err(|e| e.to_string())?;
    Ok((certs_json, prekey_json))
}

/// Finish or discard an interrupted cert+prekey dual write.
fn recover_peer_cache_stage(data_dir: &Path) -> Result<(), String> {
    let stage_path = peer_cache_stage_path(data_dir);
    if !stage_path.exists() {
        return Ok(());
    }
    let raw =
        std::fs::read_to_string(&stage_path).map_err(|e| format!("peer cache stage read: {e}"))?;
    let stage: PeerCacheStage =
        serde_json::from_str(&raw).map_err(|e| format!("peer cache stage corrupt: {e}"))?;
    let committed = read_committed_peer_cache_generation(data_dir)?;
    if stage.generation < committed {
        // Stale stage from an older writer — discard.
        std::fs::remove_file(&stage_path)
            .map_err(|e| format!("peer cache stale stage remove: {e}"))?;
        return Ok(());
    }
    let now = now_ms();
    let (certs_json, prekey_json) = match sanitize_peer_cache_stage_payloads(&stage, now) {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&stage_path);
            return Err(e);
        }
    };
    crate::paths::atomic_write_private(&data_dir.join(PEER_CERT_CACHE), certs_json.as_bytes())?;
    crate::paths::atomic_write_private(&PrekeyStore::path(data_dir), prekey_json.as_bytes())?;
    write_committed_peer_cache_generation(data_dir, stage.generation)?;
    std::fs::remove_file(&stage_path).map_err(|e| format!("peer cache stage remove: {e}"))?;
    Ok(())
}

fn commit_peer_cache_pair(
    data_dir: &Path,
    certs_bytes: &[u8],
    prekey_bytes: &[u8],
) -> Result<(), String> {
    recover_peer_cache_stage(data_dir)?;
    let committed = read_committed_peer_cache_generation(data_dir)?;
    let generation = now_ms().max(committed.saturating_add(1)).max(1);
    let stage = PeerCacheStage {
        generation,
        certs_json: String::from_utf8(certs_bytes.to_vec())
            .map_err(|_| "peer cache certs utf8".to_string())?,
        prekey_json: String::from_utf8(prekey_bytes.to_vec())
            .map_err(|_| "peer cache prekey utf8".to_string())?,
    };
    let (certs_json, prekey_json) = sanitize_peer_cache_stage_payloads(&stage, now_ms())?;
    let stage = PeerCacheStage {
        generation,
        certs_json,
        prekey_json,
    };
    let stage_bytes = serde_json::to_vec_pretty(&stage).map_err(|e| e.to_string())?;
    crate::paths::atomic_write_private(&peer_cache_stage_path(data_dir), &stage_bytes)?;
    #[cfg(test)]
    if FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.get()) {
        return Err("injected peer cache stage failure".into());
    }
    recover_peer_cache_stage(data_dir)?;
    Ok(())
}

/// Shared lock for prekey_store.json / peer cache mutations (ash + node).
pub fn with_prekey_store_lock<F, T>(data_dir: &Path, f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    f()
}

/// Fail-closed load + publish + atomic save under the shared prekey lock.
pub fn publish_prekey_bundle_checked(
    data_dir: &Path,
    bundle: &PrekeyBundle,
    now: u64,
) -> Result<(), String> {
    with_prekey_store_lock(data_dir, || {
        let mut store = PrekeyStore::load_checked(data_dir)?;
        store.publish(bundle, now)?;
        store.save(data_dir)
    })
}

/// Persist cert+prekey for a **contact-trusted** peer via a crash-recoverable stage.
pub fn persist_trusted_peer_bundle(data_dir: &Path, bundle: &LanBundle) -> Result<(), String> {
    let now = now_ms();
    bundle.verify_bound(now)?;
    if !peer_is_trusted(data_dir, bundle)? {
        return Err("refusing durable peer cache for untrusted peer".into());
    }
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let path = data_dir.join(PEER_CERT_CACHE);
    let mut map = load_peer_cert_map_checked(&path)?;
    map.retain(|key, cert| {
        cert.verify(now).is_ok()
            && (key == &hex::encode(cert.device_ed_pub) || key == &hex::encode(cert.user_ed_pub))
    });
    let device_key = hex::encode(bundle.cert.device_ed_pub);
    let user_key = hex::encode(bundle.cert.user_ed_pub);
    map.insert(device_key, bundle.cert.clone());
    map.insert(user_key, bundle.cert.clone());
    if map.len() > MAX_TRUSTED_PEER_CERT_KEYS {
        return Err("trusted peer cert cache full".into());
    }
    let mut store = PrekeyStore::load_checked(data_dir)?;
    let _ = store.retain_valid(now);
    store.publish(&bundle.prekey, now)?;
    if store.len() > MAX_TRUSTED_PEER_CERT_KEYS {
        return Err("trusted prekey store full".into());
    }
    let certs_bytes = serde_json::to_string_pretty(&map)
        .map_err(|e| e.to_string())?
        .into_bytes();
    let prekey_bytes = serde_json::to_string_pretty(&store)
        .map_err(|e| e.to_string())?
        .into_bytes();
    commit_peer_cache_pair(data_dir, &certs_bytes, &prekey_bytes)?;
    remember_ephemeral_peer(data_dir, bundle)?;
    Ok(())
}

/// Remember peer for this process; durable write only when in the local contact book.
pub fn cache_peer_bundle(data_dir: &Path, bundle: &LanBundle) -> Result<(), String> {
    bundle.require_identity_bound()?;
    remember_ephemeral_peer(data_dir, bundle)?;
    if peer_is_trusted(data_dir, bundle)? {
        persist_trusted_peer_bundle(data_dir, bundle)?;
    }
    Ok(())
}

pub fn parse_peer_offer(bytes: &[u8]) -> Result<LanBundle, String> {
    decode_offer(bytes)
}

fn prune_lan_pair_response_files(
    data_dir: &Path,
    live_init_ids: &std::collections::HashSet<[u8; 16]>,
) -> Result<usize, String> {
    let dir = data_dir.join("lan_pair_response");
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("lan_pair_response read: {e}"))? {
        let entry = entry.map_err(|e| format!("lan_pair_response entry: {e}"))?;
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            std::fs::remove_file(&path).map_err(|e| format!("lan_pair_response remove: {e}"))?;
            removed += 1;
            continue;
        };
        let Ok(bytes) = hex::decode(name) else {
            std::fs::remove_file(&path).map_err(|e| format!("lan_pair_response remove: {e}"))?;
            removed += 1;
            continue;
        };
        if bytes.len() != 16 {
            std::fs::remove_file(&path).map_err(|e| format!("lan_pair_response remove: {e}"))?;
            removed += 1;
            continue;
        }
        let mut init_id = [0u8; 16];
        init_id.copy_from_slice(&bytes);
        if !live_init_ids.contains(&init_id) {
            std::fs::remove_file(&path).map_err(|e| format!("lan_pair_response remove: {e}"))?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Drop expired lifecycle claims, expired SQLite sessions, and orphan pair-response files.
fn prune_lan_durable_state(data_dir: &Path, now: u64) -> Result<(), String> {
    let actor = PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    let _ = actor.prune_expired(now).map_err(|e| e.to_string())?;
    // Archive sealed inbox plaintext into ChatHistory before session roots are destroyed.
    archive_expired_inbox_to_history(data_dir, now)?;
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let _ = sessions
        .prune_expired_sessions(now)
        .map_err(|e| e.redacted_display())?;
    let live = sessions
        .live_init_ids(now)
        .map_err(|e| e.redacted_display())?;
    let _ = prune_lan_pair_response_files(data_dir, &live)?;
    Ok(())
}

/// Operational maintenance for LAN durable state (listener preflight / PairInit).
pub fn maintain_lan_durable_state(data_dir: &Path) -> Result<(), String> {
    reconcile_outbound_stage_history(data_dir)?;
    prune_lan_durable_state(data_dir, now_ms())
}

fn build_pair_response(
    init: &PairInit,
    root: &[u8; 32],
    identity: &Identity,
    now: u64,
) -> Result<PairResponse, String> {
    let digest = init_hash(init).map_err(|e| format!("{e}"))?;
    let expires = init.expires_at_ms.min(now.saturating_add(24 * 3600 * 1000));
    if expires <= now {
        return Err("pair response expired".into());
    }
    let mut response = PairResponse {
        init_id: init.init_id,
        init_hash: digest,
        responder_device_ed_pub: identity.public_key_bytes(),
        created_at_ms: now,
        expires_at_ms: expires,
        confirmation_tag: confirmation_tag(root, &digest),
        signature: [0u8; 64],
    };
    let signing = response_signing_bytes(&response).map_err(|e| format!("{e}"))?;
    response.signature = identity.sign(&signing);
    Ok(response)
}

fn handle_pair_init(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    wire: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    // Contact book is the durable trust root: strangers must not create sessions,
    // lifecycle claims, or lan_pair_response/* (claim cap is finite).
    if !peer_is_trusted(data_dir, peer)? {
        return Err("pair init refused: peer is not a local contact".into());
    }
    let init = decode_init(wire).map_err(|e| format!("pair init: {e}"))?;
    let now = now_ms();
    prune_lan_durable_state(data_dir, now)?;
    let (local_cert, registry) =
        ensure_local_device_certificate(data_dir, identity, PRIMARY_DEVICE_ID)?;
    let store = PrekeyStore::load_checked(data_dir)?;
    let local_prekey = store
        .fetch(&identity.public_key_bytes(), now)?
        .ok_or_else(|| "local prekey missing for PairInit".to_string())?;
    let (initiator_revoked, responder_revoked) = pair_revocation(
        data_dir,
        &registry,
        LocalRole::Responder,
        &peer.cert.user_ed_pub,
        &peer.cert.device_id,
        &local_cert.user_ed_pub,
        &local_cert.device_id,
    )?;
    let trust = PairInitTrust {
        initiator_certificate: &peer.cert,
        responder_certificate: &local_cert,
        responder_prekey: &local_prekey,
        initiator_revoked,
        responder_revoked,
    };

    let actor = PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    if let Some(existing) = sessions
        .find_confirmed_session_for_peer(&peer.cert.device_ed_pub)
        .map_err(|e| e.redacted_display())?
    {
        if existing.init_id == init.init_id {
            let packed =
                replay_cached_pair_response(data_dir, &init, &identity.public_key_bytes())?;
            // Crash between confirm and complete_claim leaves the claim pending;
            // exact replay must finish handoff so rotation is not wedged.
            match actor.claim_pair_init(&init, &trust, now) {
                Ok(PrekeyClaimOutcome::Accepted(claim))
                | Ok(PrekeyClaimOutcome::DuplicatePending(claim)) => {
                    let claim_id = claim.claim_id();
                    let sid = claim.session_id();
                    actor
                        .complete_claim(&claim_id, &sid)
                        .map_err(|e| e.to_string())?;
                }
                Ok(PrekeyClaimOutcome::DuplicateCompleted { .. }) => {}
                Ok(PrekeyClaimOutcome::DuplicateAbandoned { .. }) => {
                    return Err("pair init claim abandoned".into());
                }
                Err(e) => return Err(e.to_string()),
            }
            return Ok(packed);
        }
        // Different init_id: allow replacement so a lost PairResponse does not
        // lock pairing. find_confirmed already skipped expired sessions.
    }

    let mut outcome = actor
        .claim_pair_init(&init, &trust, now)
        .map_err(|e| e.to_string())?;
    let (claim_id, sid, root) = match &mut outcome {
        PrekeyClaimOutcome::Accepted(claim) | PrekeyClaimOutcome::DuplicatePending(claim) => {
            let root = claim
                .take_provisional_root()
                .ok_or_else(|| "pair init claim missing root".to_string())?;
            (claim.claim_id(), claim.session_id(), *root)
        }
        PrekeyClaimOutcome::DuplicateCompleted { .. } => {
            return replay_cached_pair_response(data_dir, &init, &identity.public_key_bytes());
        }
        PrekeyClaimOutcome::DuplicateAbandoned { .. } => {
            return Err("pair init claim abandoned".into());
        }
    };

    let key = sessions
        .create_verified_pair_init_session(&init, &trust, now, LocalRole::Responder, root)
        .map_err(|e| e.redacted_display())?;
    let response = build_pair_response(&init, &root, identity, now)?;
    let mut rng = OsRng;
    let mut tag = [0u8; 16];
    rng.fill_bytes(&mut tag);
    let packed = wrap_oob_wire(
        &encode_response(&response).map_err(|e| format!("{e}"))?,
        PairInitOobKind::PairResponse,
        identity,
        tag,
        now,
        &mut rng,
    )?;
    // Cache before confirm/complete so a crash cannot leave a Confirmed session
    // without a replayable PairResponse.
    store_cached_pair_response(data_dir, &init.init_id, &packed)?;
    sessions
        .confirm_verified_pair_response(&key, &init, &response, now)
        .map_err(|e| e.redacted_display())?;
    actor
        .complete_claim(&claim_id, &sid)
        .map_err(|e| e.to_string())?;
    // Keep peer ephemeral only — PairInit Confirm ≠ user contact trust.
    remember_ephemeral_peer(data_dir, peer)?;
    let _ = session_id(&init);
    Ok(vec![packed])
}

fn handle_indexed_message(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    packed: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if !peer_is_trusted(data_dir, peer)? {
        return Err("message refused: peer is not a local contact".into());
    }
    let now = now_ms();
    let (local_cert, registry) =
        ensure_local_device_certificate(data_dir, identity, PRIMARY_DEVICE_ID)?;
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let key = sessions
        .find_confirmed_session_for_peer(&peer.cert.device_ed_pub)
        .map_err(|e| e.redacted_display())?
        .ok_or_else(|| "no confirmed LAN session for peer".to_string())?;
    let session_expires = sessions
        .session_expires_at(&key)
        .map_err(|e| e.redacted_display())?;
    let ack_expires = envelope_expires(now, session_expires)?;
    let sender_revoked = RevocationStore::load_checked(data_dir)?
        .is_revoked(&hex::encode(peer.cert.user_ed_pub), &peer.cert.device_id);
    let accepted = sessions
        .accept_message_envelope(&key, packed, &peer.cert, sender_revoked, now)
        .map_err(|e| e.redacted_display())?;
    let digest = match &accepted {
        EndpointAcceptance::Committed {
            object_digest,
            message_id,
            plaintext,
            ..
        } => {
            // Fail-closed: never ACK if durable history cannot retain the body.
            persist_lan_chat_history(
                data_dir,
                "in",
                &peer.cert.device_ed_pub,
                message_id,
                now,
                "received",
                plaintext,
            )?;
            *object_digest
        }
        EndpointAcceptance::Duplicate {
            object_digest,
            message_id,
            ..
        } => {
            // Retry path after a prior history failure — load sealed inbox and persist.
            if let Some(row) = sessions
                .load_endpoint_inbox(&key, object_digest)
                .map_err(|e| e.redacted_display())?
            {
                persist_lan_chat_history(
                    data_dir,
                    "in",
                    &peer.cert.device_ed_pub,
                    message_id,
                    row.created_at_ms,
                    "received",
                    &row.plaintext,
                )?;
            } else {
                return Err("duplicate message missing local inbox row for history".into());
            }
            *object_digest
        }
    };
    let local_device = AuthorizedEndpointDevice::authorize(&local_cert, identity, &registry, now)
        .map_err(|e| e.redacted_display())?;
    let mut rng = OsRng;
    let outbound = sessions
        .enqueue_committed_ack(
            &key,
            &digest,
            &local_device,
            now,
            ack_expires,
            now,
            &mut rng,
            &mut |digest: &[u8; 32], _bytes: &[u8]| Ok(*digest),
        )
        .map_err(|e| e.redacted_display())?;
    if outbound.immutable_envelope_bytes.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![outbound.immutable_envelope_bytes])
}

fn handle_ack(data_dir: &Path, peer: &LanBundle, packed: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if !peer_is_trusted(data_dir, peer)? {
        return Err("ack refused: peer is not a local contact".into());
    }
    let now = now_ms();
    // Remote peer revocation is composite RevocationStore only — never the local registry.
    let sender_revoked = RevocationStore::load_checked(data_dir)?
        .is_revoked(&hex::encode(peer.cert.user_ed_pub), &peer.cert.device_id);
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let key = sessions
        .find_confirmed_session_for_peer(&peer.cert.device_ed_pub)
        .map_err(|e| e.redacted_display())?
        .ok_or_else(|| "no confirmed LAN session for ACK".to_string())?;
    sessions
        .accept_ack_envelope(&key, packed, &peer.cert, sender_revoked, now)
        .map_err(|e| e.redacted_display())?;
    Ok(Vec::new())
}

/// Dispatch one plaintext (already Noise-decrypted) LAN frame.
///
/// `noise_ed` is the peer Ed25519 bound by the Noise/bind handshake for this
/// connection. Mid-session RLB1 offers must match that identity and the
/// established peer device; they cannot introduce a new cache identity.
pub fn dispatch_frame(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    noise_ed: &[u8; 32],
    frame: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if is_rlb1(frame) {
        let offer = decode_offer(frame)?;
        if !rlb1_matches_noise_identity(&offer, noise_ed) {
            return Err("rlb1/noise identity mismatch".into());
        }
        if offer.cert.device_ed_pub != peer.cert.device_ed_pub {
            return Err("rlb1 device identity drift".into());
        }
        cache_peer_bundle(data_dir, &offer)?;
        return Ok(Vec::new());
    }
    match classify_packed_envelope(frame) {
        PairInitOobClassify::PairInit(wire) => {
            return handle_pair_init(data_dir, identity, peer, &wire);
        }
        PairInitOobClassify::PairResponse(_) => {
            return Ok(Vec::new());
        }
        PairInitOobClassify::NotPairInitOob => {}
    }
    let Some(env) = Envelope::unpack(frame) else {
        return Err("lan frame is not RavenEnvelopeV1".into());
    };
    if env.env_type == EnvType::Ack as u8 {
        return handle_ack(data_dir, peer, frame);
    }
    if env.env_type == EnvType::Message as u8 {
        return handle_indexed_message(data_dir, identity, peer, frame);
    }
    Ok(Vec::new())
}

pub fn load_cached_peer_bundle(
    data_dir: &Path,
    peer_pub: &[u8; 32],
) -> Result<Option<LanBundle>, String> {
    if let Some(ephemeral) = load_ephemeral_peer(data_dir, peer_pub) {
        return Ok(Some(ephemeral));
    }
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let now = now_ms();
    let path = data_dir.join(PEER_CERT_CACHE);
    let map = load_peer_cert_map_checked(&path)?;
    let key = hex::encode(peer_pub);
    let Some(cert) = map.get(&key).cloned() else {
        return Ok(None);
    };
    let store = PrekeyStore::load_checked(data_dir)?;
    let Some(prekey) = store.fetch(peer_pub, now)? else {
        return Ok(None);
    };
    Ok(Some(LanBundle { cert, prekey }))
}

pub fn find_confirmed_peer_session(
    data_dir: &Path,
    peer_device: &[u8; 32],
) -> Result<Option<IndexedSessionRecordKey>, String> {
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    store
        .find_confirmed_session_for_peer(peer_device)
        .map_err(|e| e.redacted_display())
}

/// Build a signed PairInit and persist the initiator provisional session.
pub fn create_initiator_pair_init(
    data_dir: &Path,
    id: &Identity,
    peer: &LanBundle,
) -> Result<(PairInit, IndexedSessionRecordKey), String> {
    if !peer_is_trusted(data_dir, peer)? {
        return Err("pair init refused: peer is not a local contact".into());
    }
    let now = now_ms();
    prune_lan_durable_state(data_dir, now)?;
    let (local_cert, registry) = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID)?;
    let (initiator_revoked, responder_revoked) = pair_revocation(
        data_dir,
        &registry,
        LocalRole::Initiator,
        &local_cert.user_ed_pub,
        &local_cert.device_id,
        &peer.cert.user_ed_pub,
        &peer.cert.device_id,
    )?;
    let trust = PairInitTrust {
        initiator_certificate: &local_cert,
        responder_certificate: &peer.cert,
        responder_prekey: &peer.prekey,
        initiator_revoked,
        responder_revoked,
    };
    let mut rng = OsRng;
    let mut eph = HybridKeypair::generate(&mut rng);
    let selected_x = if peer.prekey.one_time_prekey_id != 0 {
        peer.prekey.one_time_x25519_pub.ok_or("peer OTP missing")?
    } else {
        peer.prekey.x25519_pub
    };
    let pending = begin_hybrid_initiation(
        &mut rng,
        &eph.x25519_secret,
        &selected_x,
        &peer.prekey.mlkem768_ek,
    )
    .map_err(|e| format!("hybrid begin: {e}"))?;
    let ciphertext = pending.ciphertext().to_vec();
    let mut init_id = [0u8; 16];
    rng.fill_bytes(&mut init_id);
    let mut pairing_nonce = [0u8; 32];
    rng.fill_bytes(&mut pairing_nonce);
    let otp_pub = peer.prekey.one_time_x25519_pub.unwrap_or([0u8; 32]);
    let mut init = PairInit {
        initiator_address: id.address(),
        responder_address: encode_address(&peer.cert.user_ed_pub),
        init_id,
        pairing_nonce,
        initiator_device_ed_pub: id.public_key_bytes(),
        responder_device_ed_pub: peer.cert.device_ed_pub,
        initiator_ephemeral_x25519_pub: eph.x25519_public,
        responder_signed_x25519_pub: peer.prekey.x25519_pub,
        responder_one_time_x25519_pub: otp_pub,
        initiator_device_cert_hash: device_certificate_hash(&local_cert)
            .map_err(|e| format!("{e:?}"))?,
        responder_device_cert_hash: device_certificate_hash(&peer.cert)
            .map_err(|e| format!("{e:?}"))?,
        responder_prekey_bundle_hash: prekey_bundle_hash(&peer.prekey)
            .map_err(|e| format!("{e:?}"))?,
        signed_prekey_id: peer.prekey.signed_prekey_id,
        one_time_prekey_id: peer.prekey.one_time_prekey_id,
        responder_mlkem768_ek: peer.prekey.mlkem768_ek.clone(),
        mlkem768_ciphertext: ciphertext,
        created_at_ms: now,
        expires_at_ms: now.saturating_add(7 * 24 * 3600 * 1000),
        signature: [0u8; 64],
    };
    let signing = init_signing_bytes(&init).map_err(|e| format!("{e:?}"))?;
    init.signature = id.sign(&signing);
    eph.x25519_secret = [0u8; 32];
    let digest = transcript_hash(&init).map_err(|e| format!("{e:?}"))?;
    let (_ct, root) = pending.finalize(&digest);
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let record_key = store
        .create_verified_pair_init_session(&init, &trust, now, LocalRole::Initiator, root)
        .map_err(|e| e.redacted_display())?;
    Ok((init, record_key))
}

pub fn wrap_pair_init(id: &Identity, init: &PairInit) -> Result<Vec<u8>, String> {
    let wire = encode_init(init).map_err(|e| format!("{e:?}"))?;
    let mut tag = [0u8; 16];
    OsRng.fill_bytes(&mut tag);
    wrap_oob_wire(
        &wire,
        PairInitOobKind::PairInit,
        id,
        tag,
        now_ms(),
        &mut OsRng,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prekey_lifecycle::PrekeyGenerationPrivate;
    use zeroize::Zeroize;

    fn now() -> u64 {
        now_ms()
    }

    fn publish_and_install(data_dir: &Path, id: &Identity) {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let mut rng = rand::thread_rng();
        let mut kp = HybridKeypair::generate(&mut rng);
        let t = now();
        let bundle = crate::prekey_bundle::PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            1,
            t,
            t.saturating_add(30 * 24 * 3600 * 1000),
        )
        .unwrap()
        .sign(id)
        .unwrap();
        let actor = PrekeyLifecycleActor::open(data_dir).unwrap();
        actor
            .install_generation(
                std::slice::from_ref(&bundle),
                PrekeyGenerationPrivate::new(kp.x25519_secret, kp.mlkem_seed, vec![]),
                t,
            )
            .unwrap();
        kp.x25519_secret.zeroize();
        let mut store = PrekeyStore::load_checked(data_dir).unwrap();
        store.publish(&bundle, t).unwrap();
        store.save(data_dir).unwrap();
        let _ = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID).unwrap();
    }

    fn write_contact(data_dir: &Path, peer_device_ed: &[u8; 32], petname: &str) {
        let contacts = serde_json::json!([{
            "petname": petname,
            "pub_hex": hex::encode(peer_device_ed),
            "address": "",
        }]);
        std::fs::write(
            data_dir.join("contacts.json"),
            serde_json::to_string_pretty(&contacts).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn pair_init_message_ack_dispatch() {
        let alice = Identity::from_seed(&[0xa1; 32]);
        let bob = Identity::from_seed(&[0xb2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let pair_replies =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        assert_eq!(pair_replies.len(), 1);
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();

        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let local_device =
            AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let t = now();
        let expires =
            envelope_expires(t, a_store.session_expires_at(&record_key).unwrap()).unwrap();
        let mut queued = None;
        a_store
            .send_message_envelope(
                &record_key,
                "hello lan",
                &local_device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    queued = Some((*digest, bytes.to_vec()));
                    Ok(*digest)
                },
            )
            .unwrap();
        let packed = queued.unwrap().1;
        let replies = dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &packed).unwrap();
        assert_eq!(replies.len(), 1);

        let mut b_store = IndexedSessionStore::open(b_dir.path()).unwrap();
        let inbox = b_store.list_endpoint_inbox().unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].plaintext, b"hello lan");
        let history = ChatHistory::load(b_dir.path()).unwrap();
        let rows = history.for_peer(&hex::encode(a_bundle.cert.device_ed_pub));
        assert!(
            rows.iter()
                .any(|e| e.preview.contains("hello lan") && e.direction == "in"),
            "inbound must be in durable ChatHistory"
        );

        a_store
            .accept_ack_envelope(&record_key, &replies[0], &b_bundle.cert, false, now())
            .unwrap();

        let replay_pair =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        assert_eq!(replay_pair.len(), 1);
        assert!(matches!(
            classify_packed_envelope(&replay_pair[0]),
            PairInitOobClassify::PairResponse(_)
        ));

        let replay_ack =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &packed).unwrap();
        assert_eq!(replay_ack.len(), 1);
        assert_eq!(replay_ack[0], replies[0]);
    }

    #[test]
    fn mid_session_rlb1_must_match_noise_and_peer_device() {
        let alice = Identity::from_seed(&[0xa3; 32]);
        let bob = Identity::from_seed(&[0xb4; 32]);
        let mallory = Identity::from_seed(&[0xc5; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let m_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        publish_and_install(m_dir.path(), &mallory);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let m_bundle = local_bundle(m_dir.path(), &mallory).unwrap();
        let alice_noise = alice.public_key_bytes();
        let foreign = encode_offer(&m_bundle).unwrap();
        let err =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &foreign).unwrap_err();
        assert!(
            err.contains("mismatch") || err.contains("drift"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn peer_cache_rejects_corrupt_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PEER_CERT_CACHE);
        std::fs::write(&path, b"{not-json").unwrap();
        let err = load_peer_cert_map_checked(&path).unwrap_err();
        assert!(err.contains("corrupt"));
    }

    #[test]
    fn unknown_peer_stays_ephemeral_not_durable() {
        let alice = Identity::from_seed(&[0xd1; 32]);
        let dir = tempfile::tempdir().unwrap();
        publish_and_install(dir.path(), &alice);
        let bundle = local_bundle(dir.path(), &alice).unwrap();
        cache_peer_bundle(dir.path(), &bundle).unwrap();
        assert!(load_ephemeral_peer(dir.path(), &bundle.cert.device_ed_pub).is_some());
        assert!(!dir.path().join(PEER_CERT_CACHE).exists());
        assert!(
            !peer_is_trusted(dir.path(), &bundle).unwrap(),
            "no contact yet"
        );
    }

    #[test]
    fn pair_init_refuses_stranger_without_durable_state() {
        let alice = Identity::from_seed(&[0xa1; 32]);
        let bob = Identity::from_seed(&[0xb2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        // A treats B as a contact so initiator can build PairInit; B has no contact for A.
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        remember_ephemeral_peer(b_dir.path(), &a_bundle).unwrap();
        let claims_before = PrekeyLifecycleActor::open(b_dir.path())
            .unwrap()
            .status()
            .unwrap()
            .accepted_claims;
        let (init, _) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let err =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap_err();
        assert!(err.contains("not a local contact"), "unexpected: {err}");
        assert!(
            !b_dir.path().join(PEER_CERT_CACHE).exists(),
            "stranger PairInit must not durable-poison peer cache"
        );
        assert!(!b_dir.path().join("lan_pair_response").exists());
        let mut sessions = IndexedSessionStore::open(b_dir.path()).unwrap();
        assert!(sessions
            .find_confirmed_session_for_peer(&a_bundle.cert.device_ed_pub)
            .unwrap()
            .is_none());
        assert!(sessions.list_record_keys().unwrap().is_empty());
        let claims_after = PrekeyLifecycleActor::open(b_dir.path())
            .unwrap()
            .status()
            .unwrap()
            .accepted_claims;
        assert_eq!(claims_before, claims_after);
        assert!(!peer_is_trusted(b_dir.path(), &a_bundle).unwrap());
    }

    #[test]
    fn create_initiator_refuses_stranger() {
        let alice = Identity::from_seed(&[0xa8; 32]);
        let bob = Identity::from_seed(&[0xb9; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let err = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap_err();
        assert!(err.contains("not a local contact"), "unexpected: {err}");
    }

    #[test]
    fn contact_makes_peer_trusted_for_durable_cache() {
        let alice = Identity::from_seed(&[0xd2; 32]);
        let bob = Identity::from_seed(&[0xd3; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let contacts = serde_json::json!([{
            "petname": "Bob",
            "pub_hex": hex::encode(b_bundle.cert.device_ed_pub),
            "address": "",
        }]);
        std::fs::write(
            a_dir.path().join("contacts.json"),
            serde_json::to_string_pretty(&contacts).unwrap(),
        )
        .unwrap();
        assert!(peer_is_trusted(a_dir.path(), &b_bundle).unwrap());
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        assert!(a_dir.path().join(PEER_CERT_CACHE).exists());
        let loaded = load_cached_peer_bundle(a_dir.path(), &b_bundle.cert.device_ed_pub)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.cert.device_ed_pub, b_bundle.cert.device_ed_pub);
    }

    #[test]
    fn persist_trusted_refuses_unknown() {
        let alice = Identity::from_seed(&[0xd4; 32]);
        let dir = tempfile::tempdir().unwrap();
        publish_and_install(dir.path(), &alice);
        let bundle = local_bundle(dir.path(), &alice).unwrap();
        let err = persist_trusted_peer_bundle(dir.path(), &bundle).unwrap_err();
        assert!(err.contains("untrusted"));
    }

    #[test]
    fn durable_cache_stage_failure_leaves_no_partial_finals() {
        let alice = Identity::from_seed(&[0xd5; 32]);
        let bob = Identity::from_seed(&[0xd6; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let contacts = serde_json::json!([{
            "petname": "Bob",
            "pub_hex": hex::encode(b_bundle.cert.device_ed_pub),
            "address": "",
        }]);
        std::fs::write(
            a_dir.path().join("contacts.json"),
            serde_json::to_string_pretty(&contacts).unwrap(),
        )
        .unwrap();
        FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(true));
        let err = persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap_err();
        FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(false));
        assert!(err.contains("injected"));
        // Stage may remain for recovery; finals must not appear without successful apply.
        // Recovery should finish the apply on next persist/load.
        assert!(a_dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(!a_dir.path().join(PEER_CERT_CACHE).exists());
        // Next successful path recovers from stage.
        recover_peer_cache_stage(a_dir.path()).unwrap();
        assert!(a_dir.path().join(PEER_CERT_CACHE).exists());
        assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(a_dir.path().join("peer_cache.generation").exists());
    }

    #[test]
    fn recover_discards_invalid_stage_payload() {
        let dir = tempfile::tempdir().unwrap();
        let stage = PeerCacheStage {
            generation: 1,
            certs_json: r#"{"bad":"not-a-cert"}"#.into(),
            prekey_json: r#"{"bundles":{}}"#.into(),
        };
        std::fs::write(
            dir.path().join(PEER_CACHE_STAGE),
            serde_json::to_string_pretty(&stage).unwrap(),
        )
        .unwrap();
        let err = recover_peer_cache_stage(dir.path()).unwrap_err();
        assert!(
            err.contains("stage") || err.contains("corrupt") || err.contains("empty"),
            "unexpected: {err}"
        );
        assert!(!dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(!dir.path().join(PEER_CERT_CACHE).exists());
    }

    #[test]
    fn recover_discards_stale_generation_stage() {
        let alice = Identity::from_seed(&[0xd7; 32]);
        let bob = Identity::from_seed(&[0xd8; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let committed = read_committed_peer_cache_generation(a_dir.path()).unwrap();
        assert!(committed > 0);
        let stale = PeerCacheStage {
            generation: committed.saturating_sub(1),
            certs_json: r#"{}"#.into(),
            prekey_json: r#"{"bundles":{}}"#.into(),
        };
        std::fs::write(
            a_dir.path().join(PEER_CACHE_STAGE),
            serde_json::to_string_pretty(&stale).unwrap(),
        )
        .unwrap();
        recover_peer_cache_stage(a_dir.path()).unwrap();
        assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(a_dir.path().join(PEER_CERT_CACHE).exists());
    }

    #[test]
    fn corrupt_generation_file_is_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("peer_cache.generation"), b"not-a-number\n").unwrap();
        let err = read_committed_peer_cache_generation(dir.path()).unwrap_err();
        assert!(err.contains("corrupt"), "unexpected: {err}");
    }

    #[test]
    fn lan_bundle_rejects_identity_mismatch() {
        let alice = Identity::from_seed(&[0xe1; 32]);
        let bob = Identity::from_seed(&[0xe2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let mixed = LanBundle {
            cert: a_bundle.cert.clone(),
            prekey: b_bundle.prekey.clone(),
        };
        let err = mixed.require_identity_bound().unwrap_err();
        assert!(err.contains("mismatch"), "unexpected: {err}");
        write_contact(a_dir.path(), &a_bundle.cert.device_ed_pub, "Self");
        let err = persist_trusted_peer_bundle(a_dir.path(), &mixed).unwrap_err();
        assert!(
            err.contains("mismatch") || err.contains("identity"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn message_path_refuses_removed_contact() {
        let alice = Identity::from_seed(&[0xf1; 32]);
        let bob = Identity::from_seed(&[0xf2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let pair_replies =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let local_device =
            AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let t = now();
        let expires =
            envelope_expires(t, a_store.session_expires_at(&record_key).unwrap()).unwrap();
        let mut queued = None;
        a_store
            .send_message_envelope(
                &record_key,
                "after revoke contact",
                &local_device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    queued = Some((*digest, bytes.to_vec()));
                    Ok(*digest)
                },
            )
            .unwrap();
        let packed = queued.unwrap().1;
        // Remove Alice from Bob's contacts — message/ACK must fail closed.
        std::fs::write(b_dir.path().join("contacts.json"), "[]").unwrap();
        let err = dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &packed).unwrap_err();
        assert!(err.contains("not a local contact"), "unexpected: {err}");
    }

    #[test]
    fn reconcile_outbound_stage_marks_delivered_after_ack_crash_window() {
        use crate::indexed_session_store::EndpointDeliveryState;

        let alice = Identity::from_seed(&[0xa7; 32]);
        let bob = Identity::from_seed(&[0xb8; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let pair_replies =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        assert_eq!(pair_replies.len(), 1);
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();

        let (a_cert, a_reg) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        let local_device =
            AuthorizedEndpointDevice::authorize(&a_cert, &alice, &a_reg, now()).unwrap();
        let t = now();
        let expires =
            envelope_expires(t, a_store.session_expires_at(&record_key).unwrap()).unwrap();
        let mut queued = None;
        let outbound = a_store
            .send_message_envelope(
                &record_key,
                "reconcile-body",
                &local_device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    queued = Some((*digest, bytes.to_vec()));
                    Ok(*digest)
                },
            )
            .unwrap();
        let packed = queued.unwrap().1;
        let replies = dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &packed).unwrap();
        assert_eq!(replies.len(), 1);
        a_store
            .accept_ack_envelope(&record_key, &replies[0], &b_bundle.cert, false, now())
            .unwrap();
        assert_eq!(
            a_store
                .outstanding_delivery_state(
                    &outbound.session_id,
                    &outbound.message_id,
                    &b_bundle.cert.device_ed_pub
                )
                .unwrap(),
            Some(EndpointDeliveryState::Delivered)
        );

        // Crash window: ACK committed, history mark/stage clear not done — stage remains.
        stage_outbound_body(
            a_dir.path(),
            &b_bundle.cert.device_ed_pub,
            &outbound.session_id,
            &outbound.object_digest,
            &outbound.message_id,
            t,
            "reconcile-body",
        )
        .unwrap();
        reconcile_outbound_stage_history(a_dir.path()).unwrap();
        let history = ChatHistory::load(a_dir.path()).unwrap();
        let row = history
            .entries
            .iter()
            .find(|e| e.message_id_hex == hex::encode(outbound.message_id))
            .expect("history row");
        assert_eq!(row.delivery, "delivered");
        assert_eq!(row.body, "reconcile-body");
        assert!(
            load_staged_outbound_body(a_dir.path(), &outbound.message_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn stage_capacity_preflight_blocks_before_outbox_reservation() {
        let alice = Identity::from_seed(&[0xa9; 32]);
        let bob = Identity::from_seed(&[0xba; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(&alice, &init).unwrap();
        let alice_noise = alice.public_key_bytes();
        let pair_replies =
            dispatch_frame(b_dir.path(), &bob, &a_bundle, &alice_noise, &init_frame).unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        let session_id = a_store.session_id_for_record_key(&record_key).unwrap();

        // Fill stage to entry cap so one more body is refused.
        for i in 0..256u16 {
            let mut mid = [0u8; 16];
            mid[14..].copy_from_slice(&i.to_be_bytes());
            let mut digest = [0u8; 32];
            digest[30..].copy_from_slice(&i.to_be_bytes());
            stage_outbound_body(
                a_dir.path(),
                &b_bundle.cert.device_ed_pub,
                &session_id,
                &digest,
                &mid,
                i as u64,
                "pad",
            )
            .unwrap();
        }
        assert!(matches!(
            crate::OutboundStageSendGuard::acquire(a_dir.path(), "another", now()),
            Err(crate::ChatHistoryError::TooLarge)
        ));
        assert!(
            a_store.pending_endpoint_outbound().unwrap().is_empty(),
            "preflight must run before any outbox reservation"
        );
        // Guarded send path: capacity failure means we never call send_message_envelope.
        let before = a_store.pending_endpoint_outbound().unwrap().len();
        assert!(crate::OutboundStageSendGuard::acquire(a_dir.path(), "x", now()).is_err());
        assert_eq!(
            a_store.pending_endpoint_outbound().unwrap().len(),
            before,
            "no new Prepared/Queued outbox after capacity refusal"
        );
    }
}
