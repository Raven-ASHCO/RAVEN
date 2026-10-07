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
use crate::device_cert::{
    ensure_local_device_certificate, load_device_registry_checked, DeviceCertificate,
    DeviceRegistry,
};
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
    session_id, transcript_hash, verify_init, PairInit, PairInitTrust, PairResponse,
};
use crate::pair_init_lan_oob::{
    classify_packed_envelope, wrap_oob_wire, PairInitOobClassify, PairInitOobKind,
};
use crate::paths::{DataDirLock, PRIMARY_DEVICE_ID};
use crate::prekey_bundle::{PrekeyBundle, PrekeyStore};
use crate::prekey_lifecycle::{
    local_prekey_rotation_due, PrekeyClaimOutcome, PrekeyGenerationPrivate, PrekeyLifecycleActor,
};
use zeroize::Zeroize;

const PEER_CERT_CACHE: &str = "peer_device_certs.json";
const PEER_CACHE_STAGE: &str = "peer_cache.stage.json";
const PEER_CACHE_LOCK: &str = ".lan_peer_cache.lock.sqlite";
// Durable peer caches are capped per contact, not globally: one cert slot keyed
// by the verified signer (`user_ed_pub`) and one prekey slot per identity, for
// current contacts only. Strangers cannot consume capacity.
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

/// A LAN bundle binds exactly one identity. The certificate must be
/// self-certified (`device_ed_pub == user_ed_pub`): the certificate signature
/// is then the device key's proof of possession, and every field the caches
/// key on is covered by that signature. Cert + prekey signatures and validity
/// windows must verify. Every cache write and trust decision runs this first.
///
/// Certificates for a separate device key carry no device proof of possession
/// in RLB1, and the LAN caches hold one device per identity, so they are
/// refused here rather than trusted on the signer's word.
pub fn verify_lan_bundle(bundle: &LanBundle, now_ms: u64) -> Result<(), String> {
    if bundle.cert.device_ed_pub != bundle.cert.user_ed_pub {
        return Err("lan bundle device key is not the certificate signer".into());
    }
    bundle.verify_bound(now_ms)
}

/// Keep a LAN peer in process memory only (TTL + LRU). Never writes
/// `peer_device_certs.json` / `prekey_store.json`. The bundle is verified
/// first, so a slot keyed by `device_ed_pub` can only be filled by the holder
/// of that key.
pub fn remember_ephemeral_peer(data_dir: &Path, bundle: &LanBundle) -> Result<(), String> {
    verify_lan_bundle(bundle, now_ms())?;
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
    // Exact key only: no lookup by any other (unverified) certificate field.
    let bundle = map.get(peer_pub)?.bundle.clone();
    if bundle.cert.device_ed_pub != *peer_pub || verify_lan_bundle(&bundle, now_ms()).is_err() {
        map.remove(peer_pub);
        return None;
    }
    Some(bundle)
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
///
/// Trust is computed only from the verified signer (`user_ed_pub`) of a bundle
/// that passes [`verify_lan_bundle`]; an unverified or foreign-keyed bundle is
/// an error, never "trusted".
pub fn peer_is_trusted(data_dir: &Path, bundle: &LanBundle) -> Result<bool, String> {
    verify_lan_bundle(bundle, now_ms())?;
    let contacts = contact_pub_set(data_dir)?;
    Ok(contacts.contains(&hex::encode(bundle.cert.user_ed_pub)))
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

/// Publish a local hybrid prekey if none is valid or the current one is due
/// for rotation (see `PREKEY_ROTATION_LEAD_MS`).
pub fn ensure_local_prekey(data_dir: &Path, id: &Identity) -> Result<(), String> {
    let _ = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID)?;
    let identity_pub = id.public_key_bytes();
    // Common case: nothing to do, and no lock is taken.
    let store = PrekeyStore::load_checked(data_dir)?;
    if !local_prekey_rotation_due(&store, &identity_pub, now_ms()) {
        return Ok(());
    }
    // Every inbound connection (and ash) can arrive the moment rotation becomes
    // due. Serialize on the shared prekey-store lock, recover an interrupted
    // cache stage like every other writer of prekey_store.json (a pending stage
    // would otherwise be replayed over the store saved below), and re-check:
    // the winner of the race has already published.
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let now = now_ms();
    let mut store = PrekeyStore::load_checked(data_dir)?;
    if !local_prekey_rotation_due(&store, &identity_pub, now) {
        return Ok(());
    }
    let mut rng = rand::thread_rng();
    let mut kp = HybridKeypair::generate(&mut rng);
    let actor = PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    // Never reuse an id already published for us: after lifecycle state loss
    // the actor's counter restarts below the id our store still pins, and a
    // lower or equal id is refused as rollback/equivocation on every retry.
    let published_id = store
        .fetch_valid(&identity_pub, now)
        .map_or(0, |bundle| bundle.signed_prekey_id);
    let next_id = actor
        .status()
        .map_err(|e| e.to_string())?
        .highest_signed_prekey_id
        .max(published_id)
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
    // Installing the generation is durable and irreversible, and the actor
    // retains at most `MAX_PREKEY_GENERATIONS`. Refuse a bundle the store would
    // reject (rollback/equivocation against a desynced store) *before*
    // installing, so retries cannot burn the cap on a generation that can never
    // be published. The private key must stay durable before the bundle is
    // public, so publishing first is not an option.
    store.clone().publish(&bundle, now)?;
    actor
        .rotate_generation(
            std::slice::from_ref(&bundle),
            PrekeyGenerationPrivate::new(kp.x25519_secret, kp.mlkem_seed, vec![]),
            now,
        )
        .map_err(|e| e.to_string())?;
    kp.x25519_secret.zeroize();
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

/// Exactly one identity per connection: the Noise-bound key must be both the
/// certificate's device key and its signer (see [`verify_lan_bundle`]).
pub fn rlb1_matches_noise_identity(peer: &LanBundle, noise_ed: &[u8; 32]) -> bool {
    peer.cert.device_ed_pub == *noise_ed && peer.cert.user_ed_pub == *noise_ed
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
    initiator_cert: &DeviceCertificate,
    responder_cert: &DeviceCertificate,
) -> Result<(bool, bool), String> {
    let rev = RevocationStore::load_checked(data_dir)?;
    // DeviceRegistry is local-identity-scoped. Apply it only to the local role's
    // side — never by comparing device_id strings (both peers are often ash-primary).
    let initiator_revoked = identity_denies_device_lineage(
        &rev,
        local_registry,
        initiator_cert,
        local_role == LocalRole::Initiator,
    )?;
    let responder_revoked = identity_denies_device_lineage(
        &rev,
        local_registry,
        responder_cert,
        local_role == LocalRole::Responder,
    )?;
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

/// A durable peer-cert entry is usable only when it is keyed by its verified
/// signer, self-certified, and inside its validity window.
fn durable_peer_cert_entry_valid(key: &str, cert: &DeviceCertificate, now: u64) -> bool {
    cert.device_ed_pub == cert.user_ed_pub
        && *key == hex::encode(cert.user_ed_pub)
        && cert.verify(now).is_ok()
}

/// Verify stage payloads, drop expired/unbound entries, return sanitized
/// cert/prekey JSON. Entries are pruned individually so one stale contact
/// cannot block persistence for every other contact.
fn sanitize_peer_cache_stage_payloads(
    stage: &PeerCacheStage,
    now: u64,
) -> Result<(String, String), String> {
    if stage.generation == 0 {
        return Err("peer cache stage generation missing".into());
    }
    let mut map: HashMap<String, DeviceCertificate> = serde_json::from_str(&stage.certs_json)
        .map_err(|e| format!("peer cache stage certs corrupt: {e}"))?;
    let mut store: PrekeyStore = serde_json::from_str(&stage.prekey_json)
        .map_err(|e| format!("peer cache stage prekey corrupt: {e}"))?;
    let _ = store.retain_valid(now);
    if store.is_empty() {
        return Err("peer cache stage prekey empty after expiry prune".into());
    }
    // Every peer cert must have a currently valid prekey bound to the same
    // identity and device_id; local/other identities may coexist in the shared
    // prekey_store.json without a peer cert entry.
    map.retain(|key, cert| {
        durable_peer_cert_entry_valid(key, cert, now)
            && matches!(
                store.fetch(&cert.user_ed_pub, now),
                Ok(Some(prekey)) if prekey.device_id == cert.device_id
            )
    });
    if map.is_empty() {
        return Err("peer cache stage certs empty after expiry prune".into());
    }
    let certs_json = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
    let prekey_json = serde_json::to_string_pretty(&store).map_err(|e| e.to_string())?;
    Ok((certs_json, prekey_json))
}

/// Move an unusable cache file aside (kept for inspection, one copy) so it
/// stops failing every cache operation; falls back to removal.
fn quarantine_peer_cache_file(path: &Path) -> Result<(), String> {
    let mut aside = path.as_os_str().to_owned();
    aside.push(".corrupt");
    let aside = std::path::PathBuf::from(aside);
    // Windows refuses to rename over a leftover from an earlier quarantine.
    let _ = std::fs::remove_file(&aside);
    if std::fs::rename(path, &aside).is_ok() {
        return Ok(());
    }
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("peer cache quarantine {}: {e}", path.display())),
    }
}

/// An empty or non-numeric `peer_cache.generation` cannot order a stage against
/// the committed files, and would fail every cache operation until deleted by
/// hand. The committed cert/prekey files are the source of truth and the stage
/// is only a replayable snapshot of them, so quarantine the counter together
/// with any stage; the next commit restarts it from `now_ms()`.
fn heal_corrupt_peer_cache_generation(data_dir: &Path) -> Result<(), String> {
    let path = peer_cache_gen_path(data_dir);
    let raw = match std::fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        // Not UTF-8: corrupt, not an I/O fault.
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => String::new(),
        Err(e) => return Err(format!("peer_cache.generation read: {e}")),
    };
    if raw.trim().parse::<u64>().is_ok() {
        return Ok(());
    }
    quarantine_peer_cache_file(&path)?;
    let stage_path = peer_cache_stage_path(data_dir);
    if stage_path.exists() {
        quarantine_peer_cache_file(&stage_path)?;
    }
    Ok(())
}

/// Finish or discard an interrupted cert+prekey dual write.
///
/// An unreadable or unparseable stage, or a corrupt generation counter, is
/// quarantined and treated as "nothing to replay" instead of failing every
/// caller until someone deletes the file by hand.
fn recover_peer_cache_stage(data_dir: &Path) -> Result<(), String> {
    heal_corrupt_peer_cache_generation(data_dir)?;
    let stage_path = peer_cache_stage_path(data_dir);
    if !stage_path.exists() {
        return Ok(());
    }
    let raw = match std::fs::read_to_string(&stage_path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => String::new(),
        Err(e) => return Err(format!("peer cache stage read: {e}")),
    };
    let Ok(stage) = serde_json::from_str::<PeerCacheStage>(&raw) else {
        return quarantine_peer_cache_file(&stage_path);
    };
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

/// Status prefix of the error [`persist_trusted_peer_bundle`] returns when the
/// durable prekey pin refuses a verified bundle of a contact as a rollback or
/// equivocation (lower or equal `signed_prekey_id`): the contact reinstalled or
/// reset its prekey counter while this node still pins its old bundle.
pub const PEER_PREKEY_RESET: &str = "PEER_PREKEY_RESET";

fn peer_prekey_policy_error(peer_user_pub: &[u8; 32], err: String) -> String {
    if err == "PREKEY_ROLLBACK" || err == "PREKEY_EQUIVOCATION" {
        format!(
            "{PEER_PREKEY_RESET}: contact {} offered a prekey the pinned bundle refuses ({err}); \
             it reinstalled or reset. No new session is started on it. To accept it now, \
             verify the contact's fingerprint out of band, then `ash contact remove` it and \
             add it again; otherwise this clears when the old pinned prekey expires",
            hex::encode(&peer_user_pub[..4])
        )
    } else {
        err
    }
}

/// Forget the durable prekey pin of a contact: the explicit re-pin behind
/// `ash contact remove`. A contact that reinstalled (counter reset) is refused by
/// the pin ([`PEER_PREKEY_RESET`]) until the old pinned bundle expires; the user
/// can deliberately drop the pin, after verifying the contact's fingerprint out
/// of band, and the next offer is pinned afresh. Never reachable from the network.
/// `Ok(true)` when a pin was removed.
pub fn forget_peer_prekey_pin(data_dir: &Path, peer_user_pub: &[u8; 32]) -> Result<bool, String> {
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let mut store = PrekeyStore::load_checked(data_dir)?;
    if !store.remove(peer_user_pub) {
        return Ok(false);
    }
    // One atomic file write. A cert cache entry left without its prekey is
    // already treated as absent by every reader and pruned at the next commit.
    store.save(data_dir)?;
    Ok(true)
}

/// A new session may only start on a prekey bundle the durable pin would accept.
///
/// [`cache_peer_bundle`] keeps a *connection* to a contact that reinstalled
/// working (the offer is verified, bound to the peer's identity, and a refused
/// durable pin is only reported), and existing sessions never needed the prekey.
/// But PairInit encapsulates to the offered prekey, so a rolled-back or
/// equivocating bundle (lower id, or same id with other keys) must not seed a
/// new session unless the user explicitly re-pinned (see
/// [`forget_peer_prekey_pin`]) or the pinned bundle expired. Dry run on a copy of
/// the store: nothing is written here.
fn require_prekey_acceptable_to_pin(
    data_dir: &Path,
    peer: &LanBundle,
    now: u64,
) -> Result<(), String> {
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let mut store = PrekeyStore::load_checked(data_dir)?;
    let _ = store.retain_valid(now);
    store
        .publish(&peer.prekey, now)
        .map_err(|e| peer_prekey_policy_error(&peer.cert.user_ed_pub, e))
}

/// Persist cert+prekey for a **contact-trusted** peer via a crash-recoverable stage.
///
/// The bundle is verified before anything is cached. The durable entry is keyed
/// only by the verified signer (`user_ed_pub`, equal to `device_ed_pub`), so a
/// contact owns exactly one cert slot and one prekey slot; entries for peers
/// that are no longer contacts are pruned instead of counting against a
/// global cap.
pub fn persist_trusted_peer_bundle(data_dir: &Path, bundle: &LanBundle) -> Result<(), String> {
    let now = now_ms();
    verify_lan_bundle(bundle, now)?;
    let contacts = contact_pub_set(data_dir)?;
    let user_key = hex::encode(bundle.cert.user_ed_pub);
    if !contacts.contains(&user_key) {
        return Err("refusing durable peer cache for untrusted peer".into());
    }
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let path = data_dir.join(PEER_CERT_CACHE);
    let mut map = load_peer_cert_map_checked(&path)?;
    map.retain(|key, cert| durable_peer_cert_entry_valid(key, cert, now) && contacts.contains(key));
    map.insert(user_key, bundle.cert.clone());
    let mut store = PrekeyStore::load_checked(data_dir)?;
    let _ = store.retain_valid(now);
    store
        .publish(&bundle.prekey, now)
        .map_err(|e| peer_prekey_policy_error(&bundle.cert.user_ed_pub, e))?;
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
/// Signatures and validity are verified before either cache is touched.
///
/// A contact that reset its prekey counter (reinstall, data wipe) is refused by
/// the durable pin ([`PEER_PREKEY_RESET`]). That must not drop the *connection*
/// (existing sessions never needed the prekey), so it is reported on stderr and
/// this still returns `Ok`. But the refused bundle is **not** remembered, and
/// [`create_initiator_pair_init`] re-checks the pin: it is never used to start a
/// new session unless the user explicitly re-pins ([`forget_peer_prekey_pin`]) or
/// the pinned bundle expires.
pub fn cache_peer_bundle(data_dir: &Path, bundle: &LanBundle) -> Result<(), String> {
    verify_lan_bundle(bundle, now_ms())?;
    if peer_is_trusted(data_dir, bundle)? {
        // The durable pin decides first: only an accepted bundle is remembered
        // (`persist_trusted_peer_bundle` does that itself once it committed).
        return match persist_trusted_peer_bundle(data_dir, bundle) {
            Ok(()) => Ok(()),
            Err(e) if e.starts_with(PEER_PREKEY_RESET) => {
                eprintln!("raven: {e}");
                Ok(())
            }
            Err(e) => Err(e),
        };
    }
    remember_ephemeral_peer(data_dir, bundle)
}

pub fn parse_peer_offer(bytes: &[u8]) -> Result<LanBundle, String> {
    decode_offer(bytes)
}

/// Entries of `lan_pair_response/` younger than this are never pruned. The
/// daemon and ash both prune, unlocked: an atomic-write temp file
/// (`.<hex>.tmp.<rand>`) of a response being cached, or a final file whose
/// session this pruner's `live` snapshot predates, may still be in flight in
/// another thread or process.
const PAIR_RESPONSE_PRUNE_GRACE: Duration = Duration::from_secs(60);

/// `Some(init_id)` only for a canonical response file name (32 lowercase hex).
fn pair_response_file_init_id(name: &str) -> Option<[u8; 16]> {
    if name.len() != 32 || !name.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(name).ok()?.try_into().ok()
}

fn prune_lan_pair_response_files(
    data_dir: &Path,
    live_init_ids: &std::collections::HashSet<[u8; 16]>,
) -> Result<usize, String> {
    prune_lan_pair_response_files_at(data_dir, live_init_ids, std::time::SystemTime::now())
}

fn prune_lan_pair_response_files_at(
    data_dir: &Path,
    live_init_ids: &std::collections::HashSet<[u8; 16]>,
    now: std::time::SystemTime,
) -> Result<usize, String> {
    let dir = data_dir.join("lan_pair_response");
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("lan_pair_response read: {e}"))? {
        // A concurrent pruner may have removed the entry already.
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let live = name
            .to_str()
            .and_then(pair_response_file_init_id)
            .is_some_and(|init_id| live_init_ids.contains(&init_id));
        if live {
            continue;
        }
        // Orphaned responses, leftover temp files and stray names are garbage,
        // but only once nobody can still be writing them. An unreadable or
        // future mtime counts as young.
        let aged = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= PAIR_RESPONSE_PRUNE_GRACE);
        if !aged {
            continue;
        }
        // Best effort: pruning is housekeeping and must not fail PairInit or
        // maintenance (NotFound is a lost race; Windows refuses open files).
        if std::fs::remove_file(entry.path()).is_ok() {
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

/// Expiry-only pass for raven-node's periodic service prune: destroys expired
/// sessions (protected `K_root`, outbox envelopes and inbox rows, after the
/// inbox is archived to ChatHistory), expired prekey claims and orphan
/// pair-response files. Unlike [`maintain_lan_durable_state`] it leaves the
/// outbound stage alone, so it is safe while `ash` sends are in flight.
pub fn prune_expired_lan_durable_state(data_dir: &Path) -> Result<(), String> {
    prune_lan_durable_state(data_dir, now_ms())
}

fn build_pair_response(
    init: &PairInit,
    root: &[u8; 32],
    identity: &Identity,
    now: u64,
) -> Result<PairResponse, String> {
    let digest = init_hash(init).map_err(|e| format!("{e}"))?;
    // The initiator's clock may run ahead of ours (verification tolerates a
    // bounded skew). A response stamped before the init it confirms is refused
    // by `verify_response`, so never go below `init.created_at_ms`.
    let created = now.max(init.created_at_ms);
    let expires = init
        .expires_at_ms
        .min(created.saturating_add(24 * 3600 * 1000));
    if expires <= created {
        return Err("pair response expired".into());
    }
    let mut response = PairResponse {
        init_id: init.init_id,
        init_hash: digest,
        responder_device_ed_pub: identity.public_key_bytes(),
        created_at_ms: created,
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
        &peer.cert,
        &local_cert,
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

    // Run the exact check the session store will apply below *before* the
    // claim is journaled, so a root is never durably claimed for an init the
    // session store then refuses (that would leak a claim slot per attempt).
    verify_init(&init, &trust, now).map_err(|e| format!("PairInit validation failed: {e}"))?;
    let mut outcome = actor
        .claim_pair_init(&init, &trust, now)
        .map_err(|e| e.to_string())?;
    let (claim_id, sid, root) = match &mut outcome {
        PrekeyClaimOutcome::Accepted(claim) | PrekeyClaimOutcome::DuplicatePending(claim) => {
            // Stays `Zeroizing`: wiped on every return path below.
            let root = claim
                .take_provisional_root()
                .ok_or_else(|| "pair init claim missing root".to_string())?;
            (claim.claim_id(), claim.session_id(), root)
        }
        PrekeyClaimOutcome::DuplicateCompleted { .. } => {
            return replay_cached_pair_response(data_dir, &init, &identity.public_key_bytes());
        }
        PrekeyClaimOutcome::DuplicateAbandoned { .. } => {
            return Err("pair init claim abandoned".into());
        }
    };

    let key = sessions
        .create_verified_pair_init_session(&init, &trust, now, LocalRole::Responder, *root)
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
    let candidates = sessions
        .find_confirmed_sessions_for_peer_at(&peer.cert.device_ed_pub, now)
        .map_err(|e| e.redacted_display())?;
    if candidates.is_empty() {
        return Err("no confirmed LAN session for peer".to_string());
    }
    // Full lineage check on the sender cert; accept_message_envelope then binds
    // that exact cert to the session's PairInit certificate digest.
    let sender_revoked = identity_denies_device_lineage(
        &RevocationStore::load_checked(data_dir)?,
        &registry,
        &peer.cert,
        false,
    )?;
    // The route tag identifies the session (ATSAM_ENDPOINT_TRANSACTION_V1 §1
    // step 4), so try every Confirmed session with this peer, newest first.
    // Peers that paired at the same moment hold two of them and each sealed its
    // first message under the session its *own* pairing produced; trying only
    // the newest refused the other direction for good. A mismatch is decided
    // before any state is touched, so the next candidate starts clean.
    let mut chosen = None;
    for key in candidates {
        let session_expires = sessions
            .session_expires_at(&key)
            .map_err(|e| e.redacted_display())?;
        let ack_expires = envelope_expires(now, session_expires)?;
        match sessions.accept_message_envelope(&key, packed, &peer.cert, sender_revoked, now) {
            Err(IndexedSessionStoreError::RouteTagMismatch) => continue,
            result => {
                chosen = Some((key, ack_expires, result));
                break;
            }
        }
    }
    let Some((key, ack_expires, accepted)) = chosen else {
        return Err(IndexedSessionStoreError::RouteTagMismatch.redacted_display());
    };
    let accepted = accepted.map_err(|e| e.redacted_display())?;
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
    let sender_revoked = identity_denies_device_lineage(
        &RevocationStore::load_checked(data_dir)?,
        &DeviceRegistry::default(),
        &peer.cert,
        false,
    )?;
    let mut sessions = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let candidates = sessions
        .find_confirmed_sessions_for_peer_at(&peer.cert.device_ed_pub, now)
        .map_err(|e| e.redacted_display())?;
    if candidates.is_empty() {
        return Err("no confirmed LAN session for ACK".to_string());
    }
    // Resolve the session by route tag over every Confirmed session with this
    // peer, newest first (see `handle_indexed_message`).
    for key in candidates {
        match sessions.accept_ack_envelope(&key, packed, &peer.cert, sender_revoked, now) {
            Err(IndexedSessionStoreError::RouteTagMismatch) => continue,
            result => {
                result.map_err(|e| e.redacted_display())?;
                return Ok(Vec::new());
            }
        }
    }
    Err(IndexedSessionStoreError::RouteTagMismatch.redacted_display())
}

/// Dispatch one plaintext (already Noise-decrypted) LAN frame.
///
/// `noise_ed` is the peer Ed25519 bound by the Noise/bind handshake for this
/// connection. The connection's `peer` bundle and any mid-session RLB1 offer
/// must bind exactly that identity and verify; they cannot introduce a new
/// cache identity.
pub fn dispatch_frame(
    data_dir: &Path,
    identity: &Identity,
    peer: &LanBundle,
    noise_ed: &[u8; 32],
    frame: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if !rlb1_matches_noise_identity(peer, noise_ed) {
        return Err("rlb1/noise identity mismatch".into());
    }
    verify_lan_bundle(peer, now_ms())?;
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

/// Cached peer material for `peer_pub` (ephemeral first, then durable).
///
/// Only entries that re-verify under [`verify_lan_bundle`] and are keyed by
/// their own signer are returned; anything else (including entries written by
/// older builds under an unverified key) is treated as absent.
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
    if !durable_peer_cert_entry_valid(&key, &cert, now) {
        return Ok(None);
    }
    let store = PrekeyStore::load_checked(data_dir)?;
    let Some(prekey) = store.fetch(peer_pub, now)? else {
        return Ok(None);
    };
    let bundle = LanBundle { cert, prekey };
    if verify_lan_bundle(&bundle, now).is_err() {
        return Ok(None);
    }
    Ok(Some(bundle))
}

/// Durable peer cert stored under `peer_pub`, without validity-window checks.
/// Callers must bind it to something already verified (e.g. a session digest).
fn load_durable_peer_cert_raw(
    data_dir: &Path,
    peer_pub: &[u8; 32],
) -> Result<Option<DeviceCertificate>, String> {
    let _lock = DataDirLock::acquire(data_dir, PEER_CACHE_LOCK)?;
    recover_peer_cache_stage(data_dir)?;
    let map = load_peer_cert_map_checked(&data_dir.join(PEER_CERT_CACHE))?;
    Ok(map.get(&hex::encode(peer_pub)).cloned())
}

/// The peer certificate bound into `record_key` at PairInit: the candidate from
/// the ephemeral or durable cache whose `device_certificate_hash` equals the
/// session's remote certificate digest. Cache contents never feed security
/// decisions unless they hash to that digest.
fn load_session_bound_peer_cert(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_device: &[u8; 32],
) -> Result<Option<DeviceCertificate>, String> {
    let bound = store
        .remote_certificate_digest(record_key)
        .map_err(map_seal_store_error)?;
    let mut candidates = Vec::new();
    if let Some(ephemeral) = load_ephemeral_peer(data_dir, peer_device) {
        candidates.push(ephemeral.cert);
    }
    if let Some(durable) = load_durable_peer_cert_raw(data_dir, peer_device)? {
        candidates.push(durable);
    }
    for cert in candidates {
        if cert.device_ed_pub != *peer_device {
            continue;
        }
        if device_certificate_hash(&cert).map_err(|e| format!("{e:?}"))? == bound {
            return Ok(Some(cert));
        }
    }
    Ok(None)
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

/// Frozen IPC refuse: no persisted authenticated ATSAM session is usable.
/// Distinct from [`ATSAM_LINEAGE_REVOKED`].
pub const ATSAM_SESSION_REQUIRED: &str = "ATSAM_SESSION_REQUIRED";

/// Frozen IPC refuse: session lineage is covered by Identity RVDR1 / denylist.
/// Do not collapse this to [`ATSAM_SESSION_REQUIRED`] (no re-PairInit same lineage).
pub const ATSAM_LINEAGE_REVOKED: &str = "ATSAM_LINEAGE_REVOKED";

fn parse_peer_device_hint(peer_hint: &str) -> Result<[u8; 32], String> {
    let h = peer_hint.trim().to_lowercase();
    if h.len() != 64 {
        return Err("SEAL_PEER_HINT: peer_hint must be 64 hex chars (device Ed25519)".into());
    }
    let v = hex::decode(&h).map_err(|_| {
        "SEAL_PEER_HINT: peer_hint must be 64 hex chars (device Ed25519)".to_string()
    })?;
    if v.len() != 32 {
        return Err("SEAL_PEER_HINT: peer_hint must be 64 hex chars (device Ed25519)".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

/// Identity denylist / RVDR1 sticky deny for one device lineage.
///
/// Every G5 covering identifier of `cert` is checked: `device_id` (exact
/// bytes), `device_ed_pub`, `device_x_pub` and `device_cert_hash`, against the
/// signed revocation store (legacy records + verified RVDR1 claims, scoped to
/// the cert's identity) and — for the local identity only — the lineages the
/// local registry retired. A cert that reuses any retired identifier under a
/// new `device_id` is denied (RAVEN_DEVICE_REVOCATION_V1 §2.2).
///
/// Uses existing Identity loaders only (`RevocationStore::load_checked`,
/// `load_device_registry_checked`). Soft `unwrap_or_default` empty-denylist
/// loaders are forbidden on this path.
fn identity_denies_device_lineage(
    rev: &RevocationStore,
    local_reg: &DeviceRegistry,
    cert: &DeviceCertificate,
    apply_local_registry: bool,
) -> Result<bool, String> {
    if rev.denies_certificate(cert)? {
        return Ok(true);
    }
    if apply_local_registry && local_reg.denies_lineage(cert)? {
        return Ok(true);
    }
    Ok(false)
}

/// Fail-closed Identity lineage check for the peer (and local) lineages used
/// by a persisted session. Must run **before** any ATSAM seal crypto.
pub fn refuse_if_session_lineage_revoked(
    data_dir: &Path,
    local_cert: &DeviceCertificate,
    peer_cert: &DeviceCertificate,
) -> Result<(), String> {
    let rev = RevocationStore::load_checked(data_dir)?;
    let local_reg = load_device_registry_checked(data_dir)?;
    if identity_denies_device_lineage(&rev, &local_reg, peer_cert, false)?
        || identity_denies_device_lineage(&rev, &local_reg, local_cert, true)?
    {
        return Err(ATSAM_LINEAGE_REVOKED.into());
    }
    Ok(())
}

fn map_seal_store_error(err: IndexedSessionStoreError) -> String {
    match err {
        IndexedSessionStoreError::RevokedDevice
        | IndexedSessionStoreError::LocalDeviceUnauthorized => ATSAM_LINEAGE_REVOKED.into(),
        IndexedSessionStoreError::SessionNotConfirmed
        | IndexedSessionStoreError::NotFound
        | IndexedSessionStoreError::EndpointNotCurrentlyValid
        | IndexedSessionStoreError::ProtectedStateMissing => {
            format!("{ATSAM_SESSION_REQUIRED}: {}", err.redacted_display())
        }
        other => other.redacted_display(),
    }
}

/// Seal application payload bytes under the persisted confirmed ATSAM session.
///
/// NON-RELEASE. Reuses `IndexedSessionStore::send_message_envelope` (same
/// indexed seal as LAN / pair_init_lab). Does not flip production tripwires.
/// Identity lineage/deny runs before seal crypto.
pub fn seal_app_payload_under_session(
    data_dir: &Path,
    identity: &Identity,
    peer_hint: &str,
    app_payload: &[u8],
) -> Result<Vec<u8>, String> {
    // Same cap `ash send` enforces before sealing: a larger payload would seal
    // (burning a ratchet index and committing an outbox row) into an envelope
    // no LAN/Internet carrier can ever send, wedging later resends.
    if app_payload.len() > crate::lan_noise::MAX_LAN_ENDPOINT_TEXT {
        return Err(format!(
            "SEAL_PAYLOAD: app payload exceeds {} bytes (LAN/Internet transport limit)",
            crate::lan_noise::MAX_LAN_ENDPOINT_TEXT
        ));
    }
    let peer_device = parse_peer_device_hint(peer_hint)?;
    let (local_cert, local_reg) =
        ensure_local_device_certificate(data_dir, identity, PRIMARY_DEVICE_ID)?;

    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let record_key = store
        .find_confirmed_session_for_peer(&peer_device)
        .map_err(|e| e.redacted_display())?
        .ok_or_else(|| {
            format!(
                "{ATSAM_SESSION_REQUIRED}: no authenticated persisted ATSAM session is available"
            )
        })?;
    // Revocation is evaluated against the certificate bound into this session
    // at PairInit — never an unbound cached/ephemeral cert for the same key.
    let peer_cert = load_session_bound_peer_cert(data_dir, &mut store, &record_key, &peer_device)?
        .ok_or_else(|| {
            format!("{ATSAM_SESSION_REQUIRED}: no persisted peer certificate bound to the session")
        })?;

    // BEFORE any seal crypto: Identity lineage/deny for lineages used by this session.
    refuse_if_session_lineage_revoked(data_dir, &local_cert, &peer_cert)?;

    let text = std::str::from_utf8(app_payload).map_err(|_| {
        "SEAL_PAYLOAD: app payload must be UTF-8 under indexed-session policy".to_string()
    })?;
    let now = now_ms();
    let session_expires = store
        .session_expires_at(&record_key)
        .map_err(|e| e.redacted_display())?;
    let expires = envelope_expires(now, session_expires).map_err(|_| {
        format!("{ATSAM_SESSION_REQUIRED}: persisted ATSAM session is not currently usable")
    })?;
    if local_reg.is_revoked(&local_cert.device_id) {
        return Err(ATSAM_LINEAGE_REVOKED.into());
    }
    let local_device = AuthorizedEndpointDevice::authorize(&local_cert, identity, &local_reg, now)
        .map_err(map_seal_store_error)?;
    let mut captured = None;
    let mut rng = OsRng;
    match store.send_message_envelope(
        &record_key,
        text,
        &local_device,
        now,
        expires,
        now,
        &mut rng,
        &mut |digest, bytes| {
            captured = Some(bytes.to_vec());
            Ok(*digest)
        },
    ) {
        Ok(_) => captured.ok_or_else(|| "SEAL: missing sealed envelope after handoff".into()),
        Err(err) => Err(map_seal_store_error(err)),
    }
}

/// Lifetime of the sessions this node initiates. The indexed-session profile
/// has no forward secrecy inside a session (ATSAM_INDEXED_SESSION_PROFILE_V1
/// §2.4): whoever obtains a session's state reads all of it, in both
/// directions. A session is therefore kept short and replaced by a fresh
/// PairInit once it expires (owner decision 2026-10-07,
/// docs/WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md). Responders still
/// accept up to `prekey_lifecycle::MAX_PAIR_INIT_LIFETIME_MS` from older peers.
pub const LAN_SESSION_LIFETIME_MS: u64 = 24 * 60 * 60 * 1_000;
// A responder refuses PairInits longer than this; never initiate one it would refuse.
const _: () =
    assert!(LAN_SESSION_LIFETIME_MS <= crate::prekey_lifecycle::MAX_PAIR_INIT_LIFETIME_MS);

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
    // Before anything is created: a prekey the durable pin refuses (rollback /
    // equivocation) never seeds a new session.
    require_prekey_acceptable_to_pin(data_dir, peer, now)?;
    prune_lan_durable_state(data_dir, now)?;
    let (local_cert, registry) = ensure_local_device_certificate(data_dir, id, PRIMARY_DEVICE_ID)?;
    let (initiator_revoked, responder_revoked) = pair_revocation(
        data_dir,
        &registry,
        LocalRole::Initiator,
        &local_cert,
        &peer.cert,
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
    // Stamp the init with our own clock and never later. The session binding
    // takes `created_at_ms` from it and the session store refuses traffic
    // dated before that instant, so future-dating it (for instance up to the
    // peer prekey's `created_at_ms`, which comes from the peer's clock) would
    // lock our own session out of sealing. A prekey or cert created slightly
    // after this instant is covered by the verifiers' bounded skew
    // (`MAX_PREKEY_FUTURE_SKEW_MS`) instead.
    let created_at_ms = now;
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
        created_at_ms,
        expires_at_ms: created_at_ms.saturating_add(LAN_SESSION_LIFETIME_MS),
        signature: [0u8; 64],
    };
    let signing = init_signing_bytes(&init).map_err(|e| format!("{e:?}"))?;
    init.signature = id.sign(&signing);
    eph.x25519_secret = [0u8; 32];
    let digest = transcript_hash(&init).map_err(|e| format!("{e:?}"))?;
    // `root` is `Zeroizing`: wiped on every return path below.
    let (_ct, root) = pending.finalize(&digest);
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let record_key = store
        .create_verified_pair_init_session(&init, &trust, now, LocalRole::Initiator, *root)
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
    use crate::device_sync::RevocationRecord;
    use crate::prekey_lifecycle::PrekeyGenerationPrivate;
    use zeroize::Zeroize;

    fn now() -> u64 {
        now_ms()
    }

    fn publish_and_install(data_dir: &Path, id: &Identity) {
        publish_and_install_with(data_dir, id, 1, now());
    }

    /// Install and publish a local prekey with an explicit id and creation
    /// instant (a peer whose clock or counter differs from ours).
    fn publish_and_install_with(data_dir: &Path, id: &Identity, prekey_id: u32, t: u64) {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let mut rng = rand::thread_rng();
        let mut kp = HybridKeypair::generate(&mut rng);
        let bundle = crate::prekey_bundle::PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            prekey_id,
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

    /// Far-future bundle signed by `signer` that names `device_ed` as its device key.
    fn signed_bundle(signer: &Identity, device_ed: [u8; 32], device_id: &str) -> LanBundle {
        let t = now();
        let far = t.saturating_add(10 * 365 * 24 * 3600 * 1000);
        let cert = DeviceCertificate::issue(
            signer,
            device_ed,
            [0x42; 32],
            device_id,
            t.saturating_sub(60_000),
            far,
            0,
        )
        .unwrap();
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        let prekey = PrekeyBundle::from_hybrid_public(
            device_id,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            1,
            t,
            far,
        )
        .unwrap()
        .sign(signer)
        .unwrap();
        LanBundle { cert, prekey }
    }

    /// Simulates cache state written before offers were verified.
    fn inject_ephemeral_unchecked(data_dir: &Path, key: [u8; 32], bundle: &LanBundle) {
        let mut guard = EPHEMERAL_PEERS.lock().unwrap();
        let root = guard.get_or_insert_with(HashMap::new);
        root.entry(ephemeral_dir_key(data_dir)).or_default().insert(
            key,
            EphemeralPeer {
                bundle: bundle.clone(),
                expires_at: Instant::now() + EPHEMERAL_PEER_TTL,
            },
        );
    }

    fn clear_ephemeral(data_dir: &Path) {
        let mut guard = EPHEMERAL_PEERS.lock().unwrap();
        if let Some(root) = guard.as_mut() {
            root.remove(&ephemeral_dir_key(data_dir));
        }
    }

    /// Seal `text` under `key` on `dir`'s store (what `ash send` does right
    /// after its own pairing) and return the packed message envelope.
    fn seal_under(dir: &Path, id: &Identity, key: &IndexedSessionRecordKey, text: &str) -> Vec<u8> {
        let mut store = IndexedSessionStore::open(dir).unwrap();
        let (cert, reg) = ensure_local_device_certificate(dir, id, PRIMARY_DEVICE_ID).unwrap();
        let device = AuthorizedEndpointDevice::authorize(&cert, id, &reg, now()).unwrap();
        let t = now();
        let expires = envelope_expires(t, store.session_expires_at(key).unwrap()).unwrap();
        let mut queued = None;
        store
            .send_message_envelope(
                key,
                text,
                &device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    queued = Some(bytes.to_vec());
                    Ok(*digest)
                },
            )
            .unwrap();
        queued.unwrap()
    }

    /// Sessions this node initiates last `LAN_SESSION_LIFETIME_MS` (24 h), not
    /// the 7-day maximum a responder accepts: the profile has no forward secrecy
    /// inside a session, so a short session bounds what a stolen state reveals.
    #[test]
    fn initiated_sessions_last_one_day() {
        let alice = Identity::from_seed(&[0xd5; 32]);
        let bob = Identity::from_seed(&[0xd6; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, key) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        assert_eq!(LAN_SESSION_LIFETIME_MS, 24 * 60 * 60 * 1_000);
        assert_eq!(
            init.expires_at_ms - init.created_at_ms,
            LAN_SESSION_LIFETIME_MS
        );
        let mut store = IndexedSessionStore::open(a_dir.path()).unwrap();
        assert_eq!(store.session_expires_at(&key).unwrap(), init.expires_at_ms);
    }

    /// One prune pass (what raven-node's periodic `durable_prune` runs) destroys
    /// an expired session's protected root, not only its metadata, and keeps
    /// a session that has not expired yet.
    #[test]
    fn one_prune_pass_destroys_an_expired_sessions_protected_root() {
        let alice = Identity::from_seed(&[0xd1; 32]);
        let bob = Identity::from_seed(&[0xd2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, key) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();

        let record_keys = || {
            IndexedSessionStore::open(a_dir.path())
                .unwrap()
                .list_record_keys()
                .unwrap()
        };
        // Under the lab locked-file backend each protected root is one file.
        let locked_file = ["RAVEN_SESSION_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var_os(k).is_some_and(|v| v == "locked-file"));
        let secrets = a_dir.path().join("indexed-session-secrets");
        let protected_roots = || {
            std::fs::read_dir(&secrets)
                .map(|dir| {
                    dir.flatten()
                        .filter(|e| e.path().extension().is_some_and(|x| x == "bin"))
                        .count()
                })
                .unwrap_or(0)
        };
        assert_eq!(record_keys(), vec![key]);
        if locked_file {
            assert_eq!(protected_roots(), 1);
        }

        prune_lan_durable_state(a_dir.path(), init.expires_at_ms - 1).unwrap();
        assert_eq!(record_keys().len(), 1, "a live session must be kept");
        if locked_file {
            assert_eq!(protected_roots(), 1);
        }

        prune_lan_durable_state(a_dir.path(), init.expires_at_ms).unwrap();
        assert!(record_keys().is_empty());
        if locked_file {
            assert_eq!(protected_roots(), 0, "expired K_root left in the store");
        }
    }

    /// Two peers that say hello at the same moment each run a PairInit and so
    /// each hold two confirmed sessions with the other. Each sealed its first
    /// message under the session its *own* pairing produced; the receiver used to
    /// try only its newest session, so the direction whose session was not the
    /// newest was refused with a route-tag mismatch, and the pair stayed wedged.
    /// The receiver now resolves the session by route tag, so both directions
    /// deliver (and the ACKs come back).
    #[test]
    fn crossed_first_contact_delivers_in_both_directions() {
        let alice = Identity::from_seed(&[0xe1; 32]);
        let bob = Identity::from_seed(&[0xe2; 32]);
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
        let (a_pub, b_pub) = (alice.public_key_bytes(), bob.public_key_bytes());

        // Both start pairing before either has heard from the other.
        let (init_a, key_a) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        let (init_b, key_b) = create_initiator_pair_init(b_dir.path(), &bob, &a_bundle).unwrap();
        // Each answers the other's init as responder...
        let to_b = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &a_pub,
            &wrap_pair_init(&alice, &init_a).unwrap(),
        )
        .unwrap();
        let to_a = dispatch_frame(
            a_dir.path(),
            &alice,
            &b_bundle,
            &b_pub,
            &wrap_pair_init(&bob, &init_b).unwrap(),
        )
        .unwrap();
        // ...and each confirms its own init from the PairResponse it gets back.
        let response = |frames: &[Vec<u8>]| {
            let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&frames[0])
            else {
                panic!("expected PairResponse");
            };
            crate::pair_init::decode_response(&wire).unwrap()
        };
        IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .confirm_verified_pair_response(&key_a, &init_a, &response(&to_b), now())
            .unwrap();
        IndexedSessionStore::open(b_dir.path())
            .unwrap()
            .confirm_verified_pair_response(&key_b, &init_b, &response(&to_a), now())
            .unwrap();

        // Both nodes hold both sessions, and agree which one is newest.
        let sessions = |dir: &Path, peer: &[u8; 32]| {
            IndexedSessionStore::open(dir)
                .unwrap()
                .find_confirmed_sessions_for_peer_at(peer, now())
                .unwrap()
        };
        let at_alice = sessions(a_dir.path(), &b_pub);
        let at_bob = sessions(b_dir.path(), &a_pub);
        assert_eq!(at_alice.len(), 2);
        assert_eq!(
            at_alice, at_bob,
            "both nodes order the sessions identically"
        );
        // One direction is therefore sealed under a session the receiver does not
        // consider newest: the case that used to be refused.
        let newest = at_alice[0].clone();
        assert!(key_a != newest || key_b != newest);

        for (
            label,
            sender_dir,
            sender,
            sender_bundle,
            key,
            receiver_dir,
            receiver,
            receiver_bundle,
        ) in [
            (
                "alice->bob",
                a_dir.path(),
                &alice,
                &a_bundle,
                &key_a,
                b_dir.path(),
                &bob,
                &b_bundle,
            ),
            (
                "bob->alice",
                b_dir.path(),
                &bob,
                &b_bundle,
                &key_b,
                a_dir.path(),
                &alice,
                &a_bundle,
            ),
        ] {
            let packed = seal_under(sender_dir, sender, key, label);
            let replies = dispatch_frame(
                receiver_dir,
                receiver,
                sender_bundle,
                &sender.public_key_bytes(),
                &packed,
            )
            .unwrap_or_else(|e| panic!("{label}: refused: {e}"));
            assert_eq!(replies.len(), 1, "{label}: one sealed ACK");
            // The receiver committed it...
            let inbox = IndexedSessionStore::open(receiver_dir)
                .unwrap()
                .list_endpoint_inbox()
                .unwrap();
            assert!(
                inbox.iter().any(|row| row.plaintext == label.as_bytes()),
                "{label}: not in the receiver's inbox"
            );
            // ...and its ACK is accepted by the sender under the session it used.
            IndexedSessionStore::open(sender_dir)
                .unwrap()
                .accept_ack_envelope(key, &replies[0], &receiver_bundle.cert, false, now())
                .unwrap_or_else(|e| panic!("{label}: ACK refused: {e:?}"));
            // An ACK frame that arrives unsolicited is resolved by route tag too.
            dispatch_frame(
                sender_dir,
                sender,
                receiver_bundle,
                &receiver.public_key_bytes(),
                &replies[0],
            )
            .unwrap_or_else(|e| panic!("{label}: unsolicited ACK refused: {e}"));
        }
    }

    /// The route-tag search is not a way around the session binding: a message
    /// no confirmed session of the peer recognises is refused (with the usual
    /// text), and so is one from a peer the receiver holds no session with.
    #[test]
    fn message_no_session_recognises_is_still_refused() {
        let alice = Identity::from_seed(&[0xe3; 32]);
        let bob = Identity::from_seed(&[0xe4; 32]);
        let carol = Identity::from_seed(&[0xe5; 32]);
        let (a_dir, b_dir, c_dir) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        for (d, id) in [(&a_dir, &alice), (&b_dir, &bob), (&c_dir, &carol)] {
            publish_and_install(d.path(), id);
        }
        let (a_bundle, _b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let key = IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .find_confirmed_session_for_peer_at(&bob.public_key_bytes(), now())
            .unwrap()
            .unwrap();
        let packed = seal_under(a_dir.path(), &alice, &key, "to bob");

        // A routing tag no session derives: every candidate mismatches.
        let mut env = Envelope::unpack(&packed).unwrap();
        env.routing_tag[0] ^= 0xff;
        let err = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &env.pack(),
        )
        .unwrap_err();
        assert!(err.contains("route tag does not match"), "{err}");

        // The untouched message is accepted by the session it was sealed under.
        let replies = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &packed,
        )
        .expect("the genuine message is accepted");
        assert_eq!(replies.len(), 1);

        // A contact Bob holds no session with: no candidate at all.
        let c_bundle = local_bundle(c_dir.path(), &carol).unwrap();
        write_contact(b_dir.path(), &c_bundle.cert.device_ed_pub, "Carol");
        let err = dispatch_frame(
            b_dir.path(),
            &bob,
            &c_bundle,
            &carol.public_key_bytes(),
            &packed,
        )
        .unwrap_err();
        assert!(err.contains("no confirmed LAN session"), "{err}");
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

    fn confirm_alice_to_bob(
        a_dir: &Path,
        b_dir: &Path,
        alice: &Identity,
        bob: &Identity,
    ) -> (LanBundle, LanBundle) {
        let a_bundle = local_bundle(a_dir, alice).unwrap();
        let b_bundle = local_bundle(b_dir, bob).unwrap();
        write_contact(a_dir, &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir, &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir, &a_bundle).unwrap();
        cache_peer_bundle(a_dir, &b_bundle).unwrap();
        let (init, record_key) = create_initiator_pair_init(a_dir, alice, &b_bundle).unwrap();
        let init_frame = wrap_pair_init(alice, &init).unwrap();
        let pair_replies = dispatch_frame(
            b_dir,
            bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &init_frame,
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&pair_replies[0])
        else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        let mut a_store = IndexedSessionStore::open(a_dir).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        (a_bundle, b_bundle)
    }

    #[test]
    fn seal_under_session_roundtrip_with_lab_session() {
        let alice = Identity::from_seed(&[0xc1; 32]);
        let bob = Identity::from_seed(&[0xc2; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let (_a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let peer_hint = hex::encode(b_bundle.cert.device_ed_pub);
        let packed =
            seal_app_payload_under_session(a_dir.path(), &alice, &peer_hint, b"m2-daemon-seal")
                .expect("lab session should seal under persisted ATSAM session");
        let env = Envelope::unpack(&packed).expect("RavenEnvelopeV1");
        assert_eq!(env.env_type, EnvType::Message as u8);
        assert!(!env.message_ciphertext.is_empty());
    }

    #[test]
    fn seal_under_session_refuses_without_session() {
        let alice = Identity::from_seed(&[0xc3; 32]);
        let bob = Identity::from_seed(&[0xc4; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let err = seal_app_payload_under_session(
            a_dir.path(),
            &alice,
            &hex::encode(b_bundle.cert.device_ed_pub),
            b"no-session",
        )
        .unwrap_err();
        assert!(
            err.starts_with(ATSAM_SESSION_REQUIRED),
            "expected {ATSAM_SESSION_REQUIRED}, got {err}"
        );
        assert!(
            !err.contains(ATSAM_LINEAGE_REVOKED),
            "missing session must not collapse into revoke: {err}"
        );
    }

    #[test]
    fn seal_under_session_revoked_lineage_is_hard_deny_before_seal() {
        let alice = Identity::from_seed(&[0xc5; 32]);
        let bob = Identity::from_seed(&[0xc6; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let (_a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);

        let rec =
            RevocationRecord::issue(&bob, &b_bundle.cert.device_id, 1, now(), "lost").unwrap();
        let mut rev = RevocationStore::load_checked(a_dir.path()).unwrap();
        assert!(rev.apply(rec).unwrap());
        rev.save(a_dir.path()).unwrap();

        let before = {
            let store = IndexedSessionStore::open(a_dir.path()).unwrap();
            store.pending_endpoint_outbound().unwrap().len()
        };
        let err = seal_app_payload_under_session(
            a_dir.path(),
            &alice,
            &hex::encode(b_bundle.cert.device_ed_pub),
            b"must-not-seal",
        )
        .unwrap_err();
        assert_eq!(
            err, ATSAM_LINEAGE_REVOKED,
            "revoked lineage must freeze ATSAM_LINEAGE_REVOKED, got {err}"
        );
        assert!(
            !err.contains(ATSAM_SESSION_REQUIRED),
            "do not collapse revoke to session-required: {err}"
        );
        let after = {
            let store = IndexedSessionStore::open(a_dir.path()).unwrap();
            store.pending_endpoint_outbound().unwrap().len()
        };
        assert_eq!(
            after, before,
            "lineage deny must run before seal crypto (no outbox reservation)"
        );
    }

    /// networking-core#0: a stranger's cert that names a contact's key as its
    /// device key (signed by the stranger) must not pass the identity bind or
    /// contact trust, and must not reach either cache.
    #[test]
    fn stranger_cannot_poison_contact_cache_via_foreign_device_key() {
        let alice = Identity::from_seed(&[0x31; 32]);
        let bob = Identity::from_seed(&[0x32; 32]);
        let mallory = Identity::from_seed(&[0x33; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let bob_pub = bob.public_key_bytes();
        let m_noise = mallory.public_key_bytes();
        write_contact(a_dir.path(), &bob_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let forged = signed_bundle(&mallory, bob_pub, "x");
        assert!(
            forged.verify_bound(now()).is_ok(),
            "signatures alone verify"
        );
        assert!(!rlb1_matches_noise_identity(&forged, &m_noise));
        assert!(!rlb1_matches_noise_identity(&forged, &bob_pub));
        assert!(peer_is_trusted(a_dir.path(), &forged).is_err());
        assert!(remember_ephemeral_peer(a_dir.path(), &forged).is_err());
        assert!(cache_peer_bundle(a_dir.path(), &forged).is_err());
        assert!(persist_trusted_peer_bundle(a_dir.path(), &forged).is_err());

        // Mid-session RLB1 on Mallory's own (self-certified) connection.
        let m_self = signed_bundle(&mallory, m_noise, "ash-primary");
        let frame = encode_offer(&forged).unwrap();
        let err = dispatch_frame(a_dir.path(), &alice, &m_self, &m_noise, &frame).unwrap_err();
        assert!(err.contains("mismatch"), "unexpected: {err}");
        // The forged bundle as the connection peer is refused before any handler.
        assert!(dispatch_frame(a_dir.path(), &alice, &forged, &m_noise, &frame).is_err());

        let map = load_peer_cert_map_checked(&a_dir.path().join(PEER_CERT_CACHE)).unwrap();
        assert_eq!(map.len(), 1, "one slot for the one contact");
        assert_eq!(map[&hex::encode(bob_pub)], b_bundle.cert);
        let loaded = load_cached_peer_bundle(a_dir.path(), &bob_pub)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.cert, b_bundle.cert);
        assert!(PrekeyStore::load_checked(a_dir.path())
            .unwrap()
            .fetch(&m_noise, now())
            .unwrap()
            .is_none());
    }

    /// networking-core#0: unverified offers never enter the in-memory map, and
    /// throwaway identities cannot consume durable capacity or break later
    /// persistence for real contacts.
    #[test]
    fn stranger_flood_cannot_fill_caches_or_break_contact_persist() {
        let alice = Identity::from_seed(&[0x34; 32]);
        let bob = Identity::from_seed(&[0x35; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &bob.public_key_bytes(), "Bob");
        let store_before = PrekeyStore::load_checked(a_dir.path()).unwrap().len();

        for i in 0..24u8 {
            let m = Identity::from_seed(&[0x90u8.wrapping_add(i); 32]);
            let own = signed_bundle(&m, m.public_key_bytes(), "ash-primary");
            // Self-certified strangers stay ephemeral and never become durable.
            cache_peer_bundle(a_dir.path(), &own).unwrap();
            assert!(persist_trusted_peer_bundle(a_dir.path(), &own).is_err());
            // Cross-keyed certs naming the contact are refused outright.
            let cross = signed_bundle(&m, bob.public_key_bytes(), "ash-primary");
            assert!(cache_peer_bundle(a_dir.path(), &cross).is_err());
            // Tampered signatures never reach (or replace) the ephemeral entry.
            let mut bad_sig = own.clone();
            bad_sig.cert.not_after_ms += 1;
            assert!(remember_ephemeral_peer(a_dir.path(), &bad_sig).is_err());
            let kept = load_ephemeral_peer(a_dir.path(), &m.public_key_bytes()).unwrap();
            assert_eq!(kept.cert, own.cert);
        }
        assert!(load_ephemeral_peer(a_dir.path(), &bob.public_key_bytes()).is_none());
        assert!(!a_dir.path().join(PEER_CERT_CACHE).exists());
        assert_eq!(
            PrekeyStore::load_checked(a_dir.path()).unwrap().len(),
            store_before
        );
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let map = load_peer_cert_map_checked(&a_dir.path().join(PEER_CERT_CACHE)).unwrap();
        assert_eq!(map.len(), 1);
    }

    /// Per-contact slots: entries for peers no longer in contacts are pruned
    /// and a poisoned legacy entry (unverified key) is never served.
    #[test]
    fn durable_cache_is_per_contact_and_drops_unbound_entries() {
        let alice = Identity::from_seed(&[0x36; 32]);
        let bob = Identity::from_seed(&[0x37; 32]);
        let carol = Identity::from_seed(&[0x38; 32]);
        let mallory = Identity::from_seed(&[0x39; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        let c_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        publish_and_install(c_dir.path(), &carol);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let c_bundle = local_bundle(c_dir.path(), &carol).unwrap();
        let contacts = serde_json::json!([
            {"petname": "Bob", "pub_hex": hex::encode(bob.public_key_bytes())},
            {"petname": "Carol", "pub_hex": hex::encode(carol.public_key_bytes())},
        ]);
        std::fs::write(
            a_dir.path().join("contacts.json"),
            serde_json::to_string(&contacts).unwrap(),
        )
        .unwrap();
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        persist_trusted_peer_bundle(a_dir.path(), &c_bundle).unwrap();
        let path = a_dir.path().join(PEER_CERT_CACHE);
        assert_eq!(load_peer_cert_map_checked(&path).unwrap().len(), 2);

        // Older builds could leave a foreign cert under a contact's key.
        let forged = signed_bundle(&mallory, carol.public_key_bytes(), "x");
        let mut map = load_peer_cert_map_checked(&path).unwrap();
        map.insert(hex::encode(carol.public_key_bytes()), forged.cert.clone());
        std::fs::write(&path, serde_json::to_string(&map).unwrap()).unwrap();
        clear_ephemeral(a_dir.path());
        assert!(
            load_cached_peer_bundle(a_dir.path(), &carol.public_key_bytes())
                .unwrap()
                .is_none()
        );

        // Carol leaves contacts: the next persist keeps only live contact slots.
        write_contact(a_dir.path(), &bob.public_key_bytes(), "Bob");
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let map = load_peer_cert_map_checked(&path).unwrap();
        assert_eq!(map.len(), 1);
        assert!(map.contains_key(&hex::encode(bob.public_key_bytes())));
    }

    /// networking-core#1: the pre-seal revocation check uses the certificate
    /// bound into the session at PairInit, so a poisoned cache entry for the
    /// revoked peer's key can neither bypass the deny nor be sealed to.
    #[test]
    fn seal_revocation_uses_session_bound_cert_not_cached_offer() {
        let alice = Identity::from_seed(&[0x3a; 32]);
        let bob = Identity::from_seed(&[0x3b; 32]);
        let mallory = Identity::from_seed(&[0x3c; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let (_a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let bob_pub = bob.public_key_bytes();
        let hint = hex::encode(bob_pub);

        // After a restart only the durable cache is left: still sealable.
        clear_ephemeral(a_dir.path());
        seal_app_payload_under_session(a_dir.path(), &alice, &hint, b"durable-bound").unwrap();

        let rec =
            RevocationRecord::issue(&bob, &b_bundle.cert.device_id, 1, now(), "lost").unwrap();
        let mut rev = RevocationStore::load_checked(a_dir.path()).unwrap();
        assert!(rev.apply(rec).unwrap());
        rev.save(a_dir.path()).unwrap();

        let forged = signed_bundle(&mallory, bob_pub, "x");
        assert!(remember_ephemeral_peer(a_dir.path(), &forged).is_err());
        // Even an injected (pre-fix) ephemeral entry cannot redirect the check.
        inject_ephemeral_unchecked(a_dir.path(), bob_pub, &forged);
        let before = IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .pending_endpoint_outbound()
            .unwrap()
            .len();
        let err = seal_app_payload_under_session(a_dir.path(), &alice, &hint, b"must-not-seal")
            .unwrap_err();
        assert_eq!(err, ATSAM_LINEAGE_REVOKED);

        // A poisoned durable entry with no bound cert anywhere fails closed.
        clear_ephemeral(a_dir.path());
        let path = a_dir.path().join(PEER_CERT_CACHE);
        let mut map = load_peer_cert_map_checked(&path).unwrap();
        map.insert(hex::encode(bob_pub), forged.cert.clone());
        std::fs::write(&path, serde_json::to_string(&map).unwrap()).unwrap();
        let err = seal_app_payload_under_session(a_dir.path(), &alice, &hint, b"must-not-seal")
            .unwrap_err();
        assert!(err.starts_with(ATSAM_SESSION_REQUIRED), "unexpected: {err}");
        let after = IndexedSessionStore::open(a_dir.path())
            .unwrap()
            .pending_endpoint_outbound()
            .unwrap()
            .len();
        assert_eq!(after, before, "nothing may be sealed to the revoked peer");
    }

    fn rvdr1_for(owner: &Identity, cert: &DeviceCertificate) -> Vec<u8> {
        crate::device_revocation::DeviceRevocationV1 {
            identity_address: owner.address(),
            device_id: cert.device_id.as_bytes().to_vec(),
            device_ed_pub: cert.device_ed_pub,
            device_x_pub: cert.device_x_pub,
            device_cert_hash: device_certificate_hash(cert).unwrap(),
            issuer_device_id: b"ash-primary".to_vec(),
            issuer_seq: 1,
            revocation_id: [7u8; 16],
            reason_code: 1,
            created_at_ms: now(),
            signature: [0u8; 64],
        }
        .sign(owner)
        .unwrap()
        .encode()
        .unwrap()
    }

    /// identity-devices#1 / protocol-reference#0: a revoked lineage that is
    /// re-certified under a new device_id with the same keys stays denied.
    #[test]
    fn pair_init_refuses_recertified_revoked_lineage() {
        let alice = Identity::from_seed(&[0x3d; 32]);
        let bob = Identity::from_seed(&[0x3e; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        let bob_pub = bob.public_key_bytes();
        write_contact(a_dir.path(), &bob_pub, "Bob");

        let mut rev = RevocationStore::load_checked(a_dir.path()).unwrap();
        assert!(rev
            .apply_rvdr1(&bob_pub, &rvdr1_for(&bob, &b_bundle.cert))
            .unwrap());
        rev.save(a_dir.path()).unwrap();

        let t = now();
        let cert = DeviceCertificate::issue(
            &bob,
            bob_pub,
            b_bundle.cert.device_x_pub,
            "fresh-id",
            t.saturating_sub(60_000),
            t + 86_400_000,
            0,
        )
        .unwrap();
        let prekey = PrekeyBundle::from_hybrid_public(
            "fresh-id",
            b_bundle.prekey.x25519_pub,
            b_bundle.prekey.mlkem768_ek.clone(),
            2,
            t,
            t + 86_400_000,
        )
        .unwrap()
        .sign(&bob)
        .unwrap();
        let recert = LanBundle { cert, prekey };
        assert!(peer_is_trusted(a_dir.path(), &recert).unwrap());
        let rev = RevocationStore::load_checked(a_dir.path()).unwrap();
        assert!(!rev.is_revoked(&hex::encode(bob_pub), "fresh-id"));
        assert!(rev.denies_certificate(&recert.cert).unwrap());
        let err = create_initiator_pair_init(a_dir.path(), &alice, &recert).unwrap_err();
        assert!(err.to_lowercase().contains("revoked"), "unexpected: {err}");
        let (local_cert, _) =
            ensure_local_device_certificate(a_dir.path(), &alice, PRIMARY_DEVICE_ID).unwrap();
        assert_eq!(
            refuse_if_session_lineage_revoked(a_dir.path(), &local_cert, &recert.cert).unwrap_err(),
            ATSAM_LINEAGE_REVOKED
        );
    }

    /// connection-reliability: the two peers' wall clocks differ. Bob's prekey
    /// is "created" two minutes after Alice's `now` (his clock runs ahead), so
    /// Alice's init predates the trust window she verifies against. Neither
    /// verifier may refuse the other's timestamps, and the session that comes
    /// out of it must carry traffic both ways straight away: the init must not
    /// be future-dated, because the session binding takes its instant from it.
    #[test]
    fn pair_init_completes_across_bounded_peer_clock_skew() {
        let alice = Identity::from_seed(&[0xa7; 32]);
        let bob = Identity::from_seed(&[0xb7; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install_with(b_dir.path(), &bob, 1, now() + 120_000);
        let a_bundle = local_bundle(a_dir.path(), &alice).unwrap();
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        assert!(b_bundle.prekey.created_at_ms > now());
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        write_contact(b_dir.path(), &a_bundle.cert.device_ed_pub, "Alice");
        cache_peer_bundle(b_dir.path(), &a_bundle).unwrap();
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();

        let (init, record_key) =
            create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();
        assert!(
            init.created_at_ms <= now(),
            "init must carry the initiator's own clock, never a later instant"
        );
        assert!(init.created_at_ms < b_bundle.prekey.created_at_ms);
        let frame = wrap_pair_init(&alice, &init).unwrap();
        let replies = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &frame,
        )
        .unwrap();
        let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(&replies[0]) else {
            panic!("expected PairResponse");
        };
        let response = crate::pair_init::decode_response(&wire).unwrap();
        assert!(response.created_at_ms >= init.created_at_ms);
        let mut a_store = IndexedSessionStore::open(a_dir.path()).unwrap();
        a_store
            .confirm_verified_pair_response(&record_key, &init, &response, now())
            .unwrap();
        assert!(
            find_confirmed_peer_session(b_dir.path(), &alice.public_key_bytes())
                .unwrap()
                .is_some()
        );
        let status = PrekeyLifecycleActor::open(b_dir.path())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.pending_handoffs, 0, "claim completed, not leaked");

        // The first message right after PairResponse (what ash sends next):
        // Alice seals, Bob accepts and ACKs, Alice accepts the ACK.
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
                "hello skew",
                &local_device,
                t,
                expires,
                t,
                &mut OsRng,
                &mut |digest, bytes| {
                    queued = Some(bytes.to_vec());
                    Ok(*digest)
                },
            )
            .expect("the initiator's own session must be usable at once");
        let packed = queued.unwrap();
        let acks = dispatch_frame(
            b_dir.path(),
            &bob,
            &a_bundle,
            &alice.public_key_bytes(),
            &packed,
        )
        .unwrap();
        assert_eq!(acks.len(), 1);
        let mut b_store = IndexedSessionStore::open(b_dir.path()).unwrap();
        let inbox = b_store.list_endpoint_inbox().unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].plaintext, b"hello skew");
        a_store
            .accept_ack_envelope(&record_key, &acks[0], &b_bundle.cert, false, now())
            .unwrap();
    }

    /// The responder stamps its PairResponse no earlier than the init it
    /// confirms, even when the initiator's clock runs ahead of its own: a
    /// response dated before its init is refused by `verify_response`.
    #[test]
    fn pair_response_is_never_stamped_before_its_init() {
        let alice = Identity::from_seed(&[0xa9; 32]);
        let bob = Identity::from_seed(&[0xb9; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        let (init, _) = create_initiator_pair_init(a_dir.path(), &alice, &b_bundle).unwrap();

        let root = [0x5a; 32];
        // Responder clock behind the init by a minute (initiator ahead).
        let behind = init.created_at_ms.saturating_sub(60_000);
        let response = build_pair_response(&init, &root, &bob, behind).unwrap();
        assert_eq!(response.created_at_ms, init.created_at_ms);
        assert!(response.expires_at_ms > response.created_at_ms);
        // Responder clock ahead: the response carries the responder's clock.
        let ahead = init.created_at_ms + 60_000;
        let response = build_pair_response(&init, &root, &bob, ahead).unwrap();
        assert_eq!(response.created_at_ms, ahead);
    }

    /// connection-core-0 + security-regression: a contact that reinstalled
    /// (counter restarted below, or equal to with different keys, the id we
    /// pinned) must stay *reachable* (the connection and existing sessions keep
    /// working), but a prekey the durable pin refuses must never seed a NEW
    /// session unless the user explicitly re-pins (`ash contact remove`) or the
    /// pinned bundle has expired.
    #[test]
    fn contact_that_reset_its_prekey_counter_stays_reachable_but_gets_no_new_session() {
        for (pinned_id, reset_id, expect) in [
            (3u32, 1u32, "PREKEY_ROLLBACK"),
            (1u32, 1u32, "PREKEY_EQUIVOCATION"),
        ] {
            let alice = Identity::from_seed(&[0xa8; 32]);
            let bob = Identity::from_seed(&[0xb8; 32]);
            let a_dir = tempfile::tempdir().unwrap();
            let b_dir = tempfile::tempdir().unwrap();
            let b2_dir = tempfile::tempdir().unwrap();
            publish_and_install(a_dir.path(), &alice);
            publish_and_install_with(b_dir.path(), &bob, pinned_id, now());
            let b_old = local_bundle(b_dir.path(), &bob).unwrap();
            write_contact(a_dir.path(), &b_old.cert.device_ed_pub, "Bob");
            cache_peer_bundle(a_dir.path(), &b_old).unwrap();

            // Bob reinstalls: same identity seed, fresh data dir, counter reset.
            publish_and_install_with(b2_dir.path(), &bob, reset_id, now() + 1);
            let b_new = local_bundle(b2_dir.path(), &bob).unwrap();
            assert_ne!(b_new.prekey, b_old.prekey);

            // The durable pin refuses it, with a distinct typed status that says
            // how to proceed...
            let err = persist_trusted_peer_bundle(a_dir.path(), &b_new).unwrap_err();
            assert!(err.starts_with(PEER_PREKEY_RESET), "{err}");
            assert!(err.contains(expect), "{err}");
            assert!(err.contains("ash contact remove"), "{err}");
            // ...but the dial / mid-session offer path no longer fails on it,
            cache_peer_bundle(a_dir.path(), &b_new).unwrap();
            // ...and the refused bundle is NOT remembered: the cache still serves
            // the pinned one.
            let live = load_cached_peer_bundle(a_dir.path(), &bob.public_key_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(
                live.prekey, b_old.prekey,
                "refused bundle must not be cached"
            );
            // A NEW session is refused outright, and nothing was created.
            let err = create_initiator_pair_init(a_dir.path(), &alice, &b_new).unwrap_err();
            assert!(err.starts_with(PEER_PREKEY_RESET), "{err}");
            assert!(IndexedSessionStore::open(a_dir.path())
                .unwrap()
                .find_confirmed_sessions_for_peer_at(&bob.public_key_bytes(), now())
                .unwrap()
                .is_empty());

            // Offline use stays fail-closed: the pin is untouched.
            clear_ephemeral(a_dir.path());
            let pinned = load_cached_peer_bundle(a_dir.path(), &bob.public_key_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(pinned.prekey, b_old.prekey);

            // Explicit re-pin (what `ash contact remove` does): the next offer is
            // pinned afresh and a session can start on it.
            assert!(forget_peer_prekey_pin(a_dir.path(), &bob.public_key_bytes()).unwrap());
            assert!(
                !forget_peer_prekey_pin(a_dir.path(), &bob.public_key_bytes()).unwrap(),
                "nothing left to forget"
            );
            cache_peer_bundle(a_dir.path(), &b_new).unwrap();
            let repinned = load_cached_peer_bundle(a_dir.path(), &bob.public_key_bytes())
                .unwrap()
                .unwrap();
            assert_eq!(repinned.prekey, b_new.prekey);
            create_initiator_pair_init(a_dir.path(), &alice, &b_new).unwrap();
        }
    }

    /// The pin protects a bundle only while it is usable: once the pinned
    /// bundle has expired, the contact's reset counter is accepted and a new
    /// session can start (no user action needed).
    #[test]
    fn expired_pin_no_longer_blocks_a_reset_contact() {
        let alice = Identity::from_seed(&[0xa7; 32]);
        let bob = Identity::from_seed(&[0xb7; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b2_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        let month = 30 * 24 * 3600 * 1000u64;
        let long_ago = now() - 2 * month;
        // Bob's old bundle, pinned while it was valid; it has since expired.
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        let old = crate::prekey_bundle::PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            9,
            long_ago,
            long_ago + month,
        )
        .unwrap()
        .sign(&bob)
        .unwrap();
        let mut store = PrekeyStore::load_checked(a_dir.path()).unwrap();
        store.publish(&old, long_ago + 1_000).unwrap();
        store.save(a_dir.path()).unwrap();

        // Bob reinstalled: counter restarted at 1.
        publish_and_install_with(b2_dir.path(), &bob, 1, now());
        let b_new = local_bundle(b2_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_new.cert.device_ed_pub, "Bob");
        cache_peer_bundle(a_dir.path(), &b_new).unwrap();
        create_initiator_pair_init(a_dir.path(), &alice, &b_new)
            .expect("an expired pin must not block the reset contact");
    }

    /// connection-core-6: concurrent callers at the moment rotation becomes
    /// due must rotate once (the loser used to fail its connection).
    #[test]
    fn concurrent_ensure_local_prekey_rotates_exactly_once() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xc7; 32]);
        let dir = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(6);
        std::thread::scope(|scope| {
            for _ in 0..6 {
                scope.spawn(|| {
                    barrier.wait();
                    ensure_local_prekey(dir.path(), &id).unwrap();
                });
            }
        });
        let status = PrekeyLifecycleActor::open(dir.path())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.highest_signed_prekey_id, 1);
        assert_eq!(status.retained_generations, 1);
        ensure_local_prekey(dir.path(), &id).unwrap();
    }

    /// ratchet-v2-5: a publish the store would refuse must not burn one of the
    /// actor's few retained generations per attempt. Local clock stepped back
    /// behind the pinned bundle's `created_at_ms`: the new bundle is refused
    /// until the clock catches up.
    #[test]
    fn ensure_local_prekey_does_not_burn_generations_on_publish_rollback() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xc8; 32]);
        let dir = tempfile::tempdir().unwrap();
        let t = now();
        let day = 24 * 3600 * 1000;
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        // Pinned local bundle created "in the future" (within the verify skew)
        // and inside the rotation lead, so a bundle stamped `now` is stale.
        let pinned = PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            1,
            t + 60_000,
            t + 2 * day,
        )
        .unwrap()
        .sign(&id)
        .unwrap();
        let mut store = PrekeyStore::default();
        store.publish(&pinned, t).unwrap();
        store.save(dir.path()).unwrap();
        assert!(local_prekey_rotation_due(&store, &id.public_key_bytes(), t));

        for _ in 0..(crate::prekey_lifecycle::MAX_PREKEY_GENERATIONS + 2) {
            assert_eq!(
                ensure_local_prekey(dir.path(), &id).unwrap_err(),
                "PREKEY_ROLLBACK"
            );
        }
        let status = PrekeyLifecycleActor::open(dir.path())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.retained_generations, 0);
        assert_eq!(status.highest_signed_prekey_id, 0);
    }

    /// Lifecycle state lost while prekey_store.json survives: the new bundle
    /// must take an id above the pinned one instead of failing as a rollback
    /// on every connection.
    #[test]
    fn ensure_local_prekey_never_reuses_a_published_id() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xcd; 32]);
        let dir = tempfile::tempdir().unwrap();
        let t = now();
        let day = 24 * 3600 * 1000;
        let kp = HybridKeypair::generate(&mut rand::thread_rng());
        let pinned = PrekeyBundle::from_hybrid_public(
            PRIMARY_DEVICE_ID,
            kp.x25519_public,
            kp.mlkem_ek_bytes.clone(),
            5,
            t - 28 * day,
            t + 2 * day,
        )
        .unwrap()
        .sign(&id)
        .unwrap();
        let mut store = PrekeyStore::default();
        store.publish(&pinned, t).unwrap();
        store.save(dir.path()).unwrap();
        assert!(local_prekey_rotation_due(&store, &id.public_key_bytes(), t));

        ensure_local_prekey(dir.path(), &id).unwrap();
        let store = PrekeyStore::load_checked(dir.path()).unwrap();
        let fresh = store.fetch_valid(&id.public_key_bytes(), now()).unwrap();
        assert_eq!(fresh.signed_prekey_id, 6);
        let status = PrekeyLifecycleActor::open(dir.path())
            .unwrap()
            .status()
            .unwrap();
        assert_eq!(status.highest_signed_prekey_id, 6);
        assert_eq!(status.retained_generations, 1);
    }

    /// connection-core-6 (a): a pending stage must be recovered before the new
    /// local bundle is saved, not replayed over it later.
    #[test]
    fn ensure_local_prekey_recovers_pending_stage_before_saving() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let alice = Identity::from_seed(&[0xc9; 32]);
        let bob = Identity::from_seed(&[0xca; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        // A crash leaves a stage holding a snapshot of Bob's cache only.
        FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(true));
        let err = persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap_err();
        FAIL_AFTER_PEER_CACHE_STAGE.with(|f| f.set(false));
        assert!(err.contains("injected"));
        assert!(a_dir.path().join(PEER_CACHE_STAGE).exists());

        // Our own first prekey is published afterwards; it must survive.
        ensure_local_prekey(a_dir.path(), &alice).unwrap();
        assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
        let store = PrekeyStore::load_checked(a_dir.path()).unwrap();
        assert!(store
            .fetch_valid(&alice.public_key_bytes(), now())
            .is_some());
        assert!(store.fetch_valid(&bob.public_key_bytes(), now()).is_some());
        recover_peer_cache_stage(a_dir.path()).unwrap();
        let store = PrekeyStore::load_checked(a_dir.path()).unwrap();
        assert!(
            store
                .fetch_valid(&alice.public_key_bytes(), now())
                .is_some(),
            "a later recovery must not replay a stale snapshot over our bundle"
        );
    }

    fn contact_cache_fixture() -> (tempfile::TempDir, LanBundle) {
        let alice = Identity::from_seed(&[0xd9; 32]);
        let bob = Identity::from_seed(&[0xda; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let b_bundle = local_bundle(b_dir.path(), &bob).unwrap();
        write_contact(a_dir.path(), &b_bundle.cert.device_ed_pub, "Bob");
        (a_dir, b_bundle)
    }

    /// connection-core-7: an unparseable stage used to fail every cache
    /// operation until someone deleted it by hand.
    #[test]
    fn truncated_peer_cache_stage_is_quarantined_and_cache_recovers() {
        let (a_dir, b_bundle) = contact_cache_fixture();
        std::fs::write(
            a_dir.path().join(PEER_CACHE_STAGE),
            br#"{"generation":12,"certs_json":"{"#,
        )
        .unwrap();
        persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
        assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
        assert!(a_dir.path().join("peer_cache.stage.json.corrupt").exists());
        clear_ephemeral(a_dir.path());
        let loaded = load_cached_peer_bundle(a_dir.path(), &b_bundle.cert.device_ed_pub)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.prekey, b_bundle.prekey);
    }

    /// connection-core-7: same for an empty / non-numeric generation counter;
    /// a stage that cannot be ordered against it is dropped with it.
    #[test]
    fn corrupt_generation_file_is_quarantined_and_cache_recovers() {
        for junk in [&b"not-a-number\n"[..], &b""[..], &[0xff, 0xfe][..]] {
            let (a_dir, b_bundle) = contact_cache_fixture();
            persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
            std::fs::write(a_dir.path().join("peer_cache.generation"), junk).unwrap();
            let stage = PeerCacheStage {
                generation: 7,
                certs_json: "{}".into(),
                prekey_json: r#"{"bundles":{}}"#.into(),
            };
            std::fs::write(
                a_dir.path().join(PEER_CACHE_STAGE),
                serde_json::to_vec(&stage).unwrap(),
            )
            .unwrap();
            persist_trusted_peer_bundle(a_dir.path(), &b_bundle).unwrap();
            assert!(a_dir.path().join("peer_cache.generation.corrupt").exists());
            assert!(!a_dir.path().join(PEER_CACHE_STAGE).exists());
            assert!(read_committed_peer_cache_generation(a_dir.path()).unwrap() > 0);
            clear_ephemeral(a_dir.path());
            assert!(
                load_cached_peer_bundle(a_dir.path(), &b_bundle.cert.device_ed_pub)
                    .unwrap()
                    .is_some()
            );
        }
    }

    /// connection-core-5: the daemon and ash prune unlocked, so nothing young
    /// (in-flight temp file, just-written response) may be deleted, and losing
    /// a race with another pruner is not an error.
    #[test]
    fn pair_response_prune_spares_young_files() {
        let dir = tempfile::tempdir().unwrap();
        let rdir = dir.path().join("lan_pair_response");
        std::fs::create_dir_all(&rdir).unwrap();
        let live_id = [1u8; 16];
        let names = [
            hex::encode(live_id),
            hex::encode([2u8; 16]),
            format!(".{}.tmp.0000000000000001", hex::encode([3u8; 16])),
            "stray.txt".to_string(),
            hex::encode([4u8; 16]).to_uppercase(),
        ];
        for name in &names {
            std::fs::write(rdir.join(name), b"x").unwrap();
        }
        let live = std::collections::HashSet::from([live_id]);
        // Everything was written just now: nothing is old enough to prune.
        assert_eq!(prune_lan_pair_response_files(dir.path(), &live).unwrap(), 0);
        assert!(names.iter().all(|n| rdir.join(n).exists()));

        let later = std::time::SystemTime::now() + PAIR_RESPONSE_PRUNE_GRACE * 2;
        assert_eq!(
            prune_lan_pair_response_files_at(dir.path(), &live, later).unwrap(),
            names.len() - 1
        );
        assert!(rdir.join(&names[0]).exists(), "live response is kept");
        assert_eq!(std::fs::read_dir(&rdir).unwrap().count(), 1);
        // A second pruner finds nothing left and is not an error.
        assert_eq!(
            prune_lan_pair_response_files_at(dir.path(), &live, later).unwrap(),
            0
        );
    }

    /// connection-core-4: a payload no LAN/Internet carrier can send must be
    /// refused before it burns a ratchet index or an outbox row.
    #[test]
    fn seal_under_session_refuses_oversize_payload_before_any_state_change() {
        let alice = Identity::from_seed(&[0xcb; 32]);
        let bob = Identity::from_seed(&[0xcc; 32]);
        let a_dir = tempfile::tempdir().unwrap();
        let b_dir = tempfile::tempdir().unwrap();
        publish_and_install(a_dir.path(), &alice);
        publish_and_install(b_dir.path(), &bob);
        let (_a_bundle, b_bundle) = confirm_alice_to_bob(a_dir.path(), b_dir.path(), &alice, &bob);
        let peer_hint = hex::encode(b_bundle.cert.device_ed_pub);
        let outbox = |dir: &Path| {
            IndexedSessionStore::open(dir)
                .unwrap()
                .pending_endpoint_outbound()
                .unwrap()
                .len()
        };
        let before = outbox(a_dir.path());

        let too_big = vec![b'x'; crate::lan_noise::MAX_LAN_ENDPOINT_TEXT + 1];
        let err =
            seal_app_payload_under_session(a_dir.path(), &alice, &peer_hint, &too_big).unwrap_err();
        assert!(err.starts_with("SEAL_PAYLOAD"), "{err}");
        assert_eq!(outbox(a_dir.path()), before, "no outbox row for a refusal");

        // The cap itself seals into an envelope that fits one transport frame.
        let at_cap = vec![b'x'; crate::lan_noise::MAX_LAN_ENDPOINT_TEXT];
        let packed =
            seal_app_payload_under_session(a_dir.path(), &alice, &peer_hint, &at_cap).unwrap();
        assert!(packed.len() <= crate::lan_noise::MAX_TRANSPORT_PLAINTEXT);
    }
}
