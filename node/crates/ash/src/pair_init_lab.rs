//! Indexed send: LanDial (Noise XX) or InternetDial (RIH1) + PairInit + ACK.
//!
//! Never uses `unsafe-demo-crypto` / public-key-derived `seal_message`.
//! Lab import files are optional leftovers; the live path uses RLB1 on the socket.
//! InternetDial is lab-gated and is not a WAN claim.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use raven_core::device_cert::{ensure_local_device_certificate, DeviceCertificate, DeviceRegistry};
use raven_core::device_sync::RevocationStore;
use raven_core::envelope::{EnvType, Envelope};
use raven_core::identity::Identity;
use raven_core::indexed_session_store::{
    AuthorizedEndpointDevice, EndpointOutboundKind, IndexedSessionRecordKey, IndexedSessionStore,
};
use raven_core::ipc::{ipc_endpoint, IpcRequest, IpcResponse, IPC_VERSION};
use raven_core::lan_dispatch::{
    cache_peer_bundle, create_initiator_pair_init, find_confirmed_peer_session, parse_peer_offer,
    wrap_pair_init,
};
use raven_core::pair_init::PairInit;
use raven_core::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};
use raven_core::paths::PRIMARY_DEVICE_ID;
use raven_core::sanitize::sanitize_terminal_text;

use super::trace_delivery;

const C_DIM: &str = "\x1b[38;2;160;160;170m";
const C_GREEN: &str = "\x1b[38;2;34;197;94m";
const C_RESET: &str = "\x1b[0m";
const C_BOLD: &str = "\x1b[1m";

const DEVICE_ID: &str = PRIMARY_DEVICE_ID;
const PEER_CERT_CACHE: &str = "peer_device_certs.json";

/// Carrier for one indexed send. `Internet` is lab-only (not WAN Proven).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialCarrier {
    Lan,
    Internet,
}

impl DialCarrier {
    fn label(self) -> &'static str {
        match self {
            Self::Lan => "lan_dial",
            Self::Internet => "internet_dial",
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_pub_hex(s: &str) -> Result<[u8; 32], String> {
    let h = s.trim().to_lowercase();
    if h.len() != 64 {
        return Err("pub_hex must be 64 hex chars".into());
    }
    let v = hex::decode(&h).map_err(|_| "pub_hex invalid hex".to_string())?;
    if v.len() != 32 {
        return Err("pub_hex must decode to 32 bytes".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

struct PendingLabInit {
    init: PairInit,
    record_key: IndexedSessionRecordKey,
}

fn pending_inits() -> &'static Mutex<HashMap<[u8; 16], PendingLabInit>> {
    static MAP: OnceLock<Mutex<HashMap<[u8; 16], PendingLabInit>>> = OnceLock::new();
    MAP.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ensure_local_device_cert(
    data_dir: &Path,
    id: &Identity,
) -> Result<(DeviceCertificate, DeviceRegistry), String> {
    ensure_local_device_certificate(data_dir, id, DEVICE_ID)
}

fn cache_peer_cert(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    cert: &DeviceCertificate,
) -> Result<(), String> {
    let path = data_dir.join(PEER_CERT_CACHE);
    let mut map: HashMap<String, DeviceCertificate> = if path.exists() {
        serde_json::from_str(&std::fs::read_to_string(&path).map_err(|e| e.to_string())?)
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    map.insert(hex::encode(peer_pub), cert.clone());
    let out = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
    raven_core::atomic_write_private(&path, out.as_bytes())
}

fn ipc_carrier_dial(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    use base64::Engine;
    let ep = ipc_endpoint(data_dir);
    if !ep.transport_available() {
        return Err("ipc_transport_missing".into());
    }
    if dial.trim().is_empty()
        || dial.eq_ignore_ascii_case("local-listen")
        || dial.eq_ignore_ascii_case("local")
    {
        return Err(format!(
            "valid {} host:port required (LocalListenQueue is disabled)",
            carrier.label()
        ));
    }
    let frames_b64 = frames
        .iter()
        .map(|f| base64::engine::general_purpose::STANDARD.encode(f))
        .collect();
    let req = match carrier {
        DialCarrier::Lan => IpcRequest::LanDial {
            v: IPC_VERSION,
            lan_dial: dial.to_string(),
            expected_pub_hex: expected_pub_hex.to_string(),
            frames_b64,
        },
        DialCarrier::Internet => IpcRequest::InternetDial {
            v: IPC_VERSION,
            internet_dial: dial.to_string(),
            expected_pub_hex: expected_pub_hex.to_string(),
            frames_b64,
        },
    };
    match super::ipc_client::ipc_request_timeout(data_dir, &req, Duration::from_secs(50)) {
        Ok(IpcResponse::LanDialResult { frames_b64, .. }) if carrier == DialCarrier::Lan => {
            frames_b64
                .iter()
                .map(|s| {
                    base64::engine::general_purpose::STANDARD
                        .decode(s.trim())
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim())
                        })
                        .map_err(|e| e.to_string())
                })
                .collect()
        }
        Ok(IpcResponse::InternetDialResult { frames_b64, .. })
            if carrier == DialCarrier::Internet =>
        {
            frames_b64
                .iter()
                .map(|s| {
                    base64::engine::general_purpose::STANDARD
                        .decode(s.trim())
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim())
                        })
                        .map_err(|e| e.to_string())
                })
                .collect()
        }
        Ok(IpcResponse::Error { code, message, .. }) => Err(format!("ipc {code}: {message}")),
        Ok(other) => Err(format!("unexpected ipc: {other:?}")),
        Err(e) => Err(e),
    }
}

fn first_pair_response(frames: &[Vec<u8>]) -> Option<raven_core::PairResponse> {
    for packed in frames {
        if let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(packed) {
            if let Ok(response) = raven_core::pair_init::decode_response(&wire) {
                return Some(response);
            }
        }
    }
    None
}

fn peer_ack_revoked(data_dir: &Path, peer_cert: &DeviceCertificate) -> Result<bool, String> {
    Ok(RevocationStore::load_checked(data_dir)?
        .is_revoked(&hex::encode(peer_cert.user_ed_pub), &peer_cert.device_id))
}

fn first_ack_frame(frames: &[Vec<u8>]) -> Option<&[u8]> {
    for packed in frames {
        if let Some(env) = Envelope::unpack(packed) {
            if env.env_type == EnvType::Ack as u8 {
                return Some(packed.as_slice());
            }
        }
    }
    None
}

pub fn ensure_lab_local_material(data_dir: &Path, id: &Identity) -> Result<(), String> {
    let (_cert, _reg) = ensure_local_device_cert(data_dir, id)?;
    raven_core::ensure_local_prekey(data_dir, id)
}

/// PairInit + indexed send over one-connection LanDial or InternetDial.
pub fn run_pair_init_and_send(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    text: &str,
) -> Result<(), String> {
    run_pair_init_and_send_on(data_dir, id, peer, peer_pub_hex, text, DialCarrier::Lan)
}

/// PairInit + indexed send on a named carrier. Internet is lab-only (not WAN).
pub fn run_pair_init_and_send_on(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    text: &str,
    carrier: DialCarrier,
) -> Result<(), String> {
    if !trace_delivery::live_pair_init_outbound_ready() {
        return Err(trace_delivery::production_gate_status().into());
    }
    if carrier == DialCarrier::Internet && !raven_core::internet_direct_live_enabled() {
        return Err(
            "INTERNET_DIRECT_HOLD: indexed InternetTransport is lab-only \
             (debug RAVEN_LAB_TEST_A=1); INTERNET_DIRECT_PRODUCTION_ENABLED=false; \
             localhost ≠ WAN Proven"
                .into(),
        );
    }
    if !peer.contains(':')
        || peer.eq_ignore_ascii_case("local-listen")
        || peer.eq_ignore_ascii_case("local")
    {
        return Err(format!(
            "valid {} host:port required — refusing LocalListenQueue fallback",
            carrier.label()
        ));
    }
    ensure_lab_local_material(data_dir, id)?;
    let peer_pub = parse_pub_hex(peer_pub_hex)?;
    let (local_cert, registry) = ensure_local_device_cert(data_dir, id)?;

    let rlb1_replies = ipc_carrier_dial(data_dir, carrier, peer, peer_pub_hex, &[])?;
    let peer_bundle = rlb1_replies
        .iter()
        .find_map(|f| parse_peer_offer(f).ok())
        .ok_or_else(|| "peer did not return an RLB1 bundle".to_string())?;
    if peer_bundle.cert.user_ed_pub != peer_pub && peer_bundle.cert.device_ed_pub != peer_pub {
        return Err("RLB1 identity does not match --peer-pub-hex / contact".into());
    }
    cache_peer_bundle(data_dir, &peer_bundle)?;

    let record_key = if let Some(existing) =
        find_confirmed_peer_session(data_dir, &peer_bundle.cert.device_ed_pub)?
    {
        existing
    } else {
        let (init, key) = create_initiator_pair_init(data_dir, id, &peer_bundle)?;
        let init_frame = wrap_pair_init(id, &init)?;
        let replies = ipc_carrier_dial(data_dir, carrier, peer, peer_pub_hex, &[init_frame])?;
        let response = first_pair_response(&replies).ok_or_else(|| {
            let kinds: Vec<String> = replies
                .iter()
                .map(|f| {
                    if parse_peer_offer(f).is_ok() {
                        "rlb1".into()
                    } else {
                        format!("{:?}", classify_packed_envelope(f))
                    }
                })
                .collect();
            format!(
                "WAITING_FOR_PAIR_RESPONSE: no PairResponse on LanDial ({} frames: {})",
                replies.len(),
                kinds.join(",")
            )
        })?;
        let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
        store
            .confirm_verified_pair_response(&key, &init, &response, now_ms())
            .map_err(|e| e.redacted_display())?;
        trace_delivery::trace_event(
            "ash/pair_init_lab.rs:run_pair_init_and_send",
            "TRACE_PAIR_RESPONSE_CONFIRMED",
            "SESSION_CONFIRMED",
            Some(&hex::encode(&init.init_id[..4])),
            Some(carrier.label()),
        );
        println!("{C_GREEN}PairResponse confirmed{C_RESET} — sending indexed message");
        key
    };

    send_indexed_text(
        data_dir,
        id,
        &registry,
        &local_cert,
        &record_key,
        text,
        peer,
        peer_pub_hex,
        &peer_bundle.cert,
        carrier,
    )
}

#[allow(clippy::too_many_arguments)]
fn send_indexed_text(
    data_dir: &Path,
    id: &Identity,
    registry: &DeviceRegistry,
    local_cert: &DeviceCertificate,
    record_key: &IndexedSessionRecordKey,
    text: &str,
    lan_dial: &str,
    peer_pub_hex: &str,
    peer_cert: &DeviceCertificate,
    carrier: DialCarrier,
) -> Result<(), String> {
    let max_text = match carrier {
        DialCarrier::Lan => raven_core::lan_noise::MAX_LAN_ENDPOINT_TEXT,
        DialCarrier::Internet => raven_core::MAX_ENDPOINT_TEXT_BYTES.min(64 * 1024),
    };
    if text.len() > max_text {
        return Err(format!(
            "message too large for {} (max {} bytes)",
            carrier.label(),
            max_text
        ));
    }
    let now = now_ms();
    let local_device = AuthorizedEndpointDevice::authorize(local_cert, id, registry, now)
        .map_err(|e| e.redacted_display())?;
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let session_expires = store
        .session_expires_at(record_key)
        .map_err(|e| e.redacted_display())?;
    let expires = now.saturating_add(60 * 60 * 1000).min(session_expires);
    if expires <= now {
        return Err("session expired".into());
    }
    let mut rng = rand::rngs::OsRng;
    let replies = std::cell::RefCell::new(Vec::<Vec<u8>>::new());
    let dial_err = std::cell::RefCell::new(None::<String>);
    let recipient = &peer_cert.device_ed_pub;
    raven_core::reconcile_outbound_stage_history(data_dir)?;
    let session_id = store
        .session_id_for_record_key(record_key)
        .map_err(|e| e.redacted_display())?;
    // Compose text is only set for the *new* send. Retries reload body from the
    // protected outbound stage written before ChatHistory on the first dial attempt.
    let history_queue_text = std::cell::RefCell::new(None::<String>);
    let dial_session = std::cell::RefCell::new(session_id);
    let dial_expected_digest = std::cell::RefCell::new(None::<[u8; 32]>);
    // Held from capacity preflight until stage write succeeds; dropped before network.
    let stage_guard = std::cell::RefCell::new(None::<raven_core::OutboundStageSendGuard>);
    // Exact binding observed in the dial callback when handoff fails.
    let failed_binding = std::cell::RefCell::new(None::<([u8; 32], [u8; 32], [u8; 16])>);
    let mut dial = |digest: &[u8; 32], bytes: &[u8]| {
        let oversize = match carrier {
            DialCarrier::Lan => bytes.len() > raven_core::lan_noise::MAX_TRANSPORT_PLAINTEXT,
            DialCarrier::Internet => bytes.len() > raven_core::MAX_FRAME_BYTES,
        };
        if oversize {
            *dial_err.borrow_mut() = Some(format!(
                "packed envelope exceeds {} transport limit",
                carrier.label()
            ));
            return Err(());
        }
        if let Some(expected) = *dial_expected_digest.borrow() {
            if expected != *digest {
                *dial_err.borrow_mut() = Some("outbound object digest mismatch".into());
                return Err(());
            }
        }
        if let Some(env) = raven_core::Envelope::unpack(bytes) {
            if env.env_type == raven_core::EnvType::Message as u8 {
                let compose = history_queue_text.borrow();
                let session = *dial_session.borrow();
                *failed_binding.borrow_mut() = Some((session, *digest, env.message_id));
                let stage_result = match stage_guard.borrow().as_ref() {
                    Some(guard) => raven_core::ensure_outbound_queued_history_under_send_guard(
                        guard,
                        &peer_cert.device_ed_pub,
                        &session,
                        digest,
                        &env.message_id,
                        now,
                        compose.as_deref(),
                    ),
                    None => raven_core::ensure_outbound_queued_history(
                        data_dir,
                        &peer_cert.device_ed_pub,
                        &session,
                        digest,
                        &env.message_id,
                        now,
                        compose.as_deref(),
                    ),
                };
                if let Err(e) = stage_result {
                    *dial_err.borrow_mut() = Some(e);
                    return Err(());
                }
                // Never hold BEGIN EXCLUSIVE across carrier dial (up to ~45s).
                let _ = stage_guard.borrow_mut().take();
            }
        }
        match ipc_carrier_dial(data_dir, carrier, lan_dial, peer_pub_hex, &[bytes.to_vec()]) {
            Ok(frames) => {
                *replies.borrow_mut() = frames;
                Ok(*digest)
            }
            Err(e) => {
                *dial_err.borrow_mut() = Some(e);
                Err(())
            }
        }
    };
    for pending in store
        .pending_endpoint_outbound_for_recipient(Some(recipient))
        .map_err(|e| e.redacted_display())?
    {
        if pending.kind != EndpointOutboundKind::Message {
            continue;
        }
        let Some(pending_key) = store
            .record_key_for_session_id(&pending.session_id)
            .map_err(|e| e.redacted_display())?
        else {
            continue;
        };
        *dial_session.borrow_mut() = pending.session_id;
        *dial_expected_digest.borrow_mut() = Some(pending.object_digest);
        match store.retry_endpoint_outbound(
            &pending_key,
            &pending.object_digest,
            &local_device,
            now,
            &mut dial,
        ) {
            Ok(row) => {
                let mid = hex::encode(&row.message_id[..4]);
                let frames = replies.borrow();
                if let Some(ack) = first_ack_frame(&frames) {
                    let ack = ack.to_vec();
                    drop(frames);
                    finish_outbound_delivered(
                        data_dir,
                        &mut store,
                        &pending_key,
                        peer_cert,
                        &pending.session_id,
                        &pending.object_digest,
                        &row.message_id,
                        &ack,
                        now,
                    )?;
                    println!("{C_GREEN}status{C_RESET} delivered (retried) mid={mid}…");
                } else {
                    return Err("WAITING_FOR_ENDPOINT_ACK: prior send has no ACK".into());
                }
            }
            Err(raven_core::IndexedSessionStoreError::NotFound)
            | Err(raven_core::IndexedSessionStoreError::BindingConflict) => continue,
            Err(raven_core::IndexedSessionStoreError::EndpointNotCurrentlyValid) => {
                store
                    .abandon_undelivered_outbound(&pending_key, &pending.object_digest)
                    .map_err(|e| e.redacted_display())?;
                mark_outbound_failed(
                    data_dir,
                    &peer_cert.device_ed_pub,
                    &pending.session_id,
                    &pending.object_digest,
                    &pending.message_id,
                )?;
                continue;
            }
            Err(e) => {
                let detail = dial_err
                    .borrow()
                    .clone()
                    .unwrap_or_else(|| e.redacted_display());
                if stage_or_body_handoff_failure(&detail) {
                    store
                        .abandon_undelivered_outbound(&pending_key, &pending.object_digest)
                        .map_err(|e| e.redacted_display())?;
                    mark_outbound_failed(
                        data_dir,
                        &peer_cert.device_ed_pub,
                        &pending.session_id,
                        &pending.object_digest,
                        &pending.message_id,
                    )?;
                }
                return Err(detail);
            }
        }
    }
    for awaiting in store
        .awaiting_ack_endpoint_outbound_for_recipient(Some(recipient))
        .map_err(|e| e.redacted_display())?
    {
        if awaiting.kind != EndpointOutboundKind::Message {
            continue;
        }
        let Some(await_key) = store
            .record_key_for_session_id(&awaiting.session_id)
            .map_err(|e| e.redacted_display())?
        else {
            continue;
        };
        *dial_session.borrow_mut() = awaiting.session_id;
        *dial_expected_digest.borrow_mut() = Some(awaiting.object_digest);
        match store.resend_queued_endpoint_outbound(
            &await_key,
            &awaiting.object_digest,
            &local_device,
            now,
            &mut dial,
        ) {
            Ok(row) => {
                let mid = hex::encode(&row.message_id[..4]);
                let frames = replies.borrow();
                if let Some(ack) = first_ack_frame(&frames) {
                    let ack = ack.to_vec();
                    drop(frames);
                    finish_outbound_delivered(
                        data_dir,
                        &mut store,
                        &await_key,
                        peer_cert,
                        &awaiting.session_id,
                        &awaiting.object_digest,
                        &row.message_id,
                        &ack,
                        now,
                    )?;
                    println!("{C_GREEN}status{C_RESET} delivered (ack-resend) mid={mid}…");
                } else {
                    return Err("WAITING_FOR_ENDPOINT_ACK: queued send still has no ACK".into());
                }
            }
            Err(raven_core::IndexedSessionStoreError::NotFound)
            | Err(raven_core::IndexedSessionStoreError::BindingConflict) => continue,
            Err(raven_core::IndexedSessionStoreError::EndpointNotCurrentlyValid) => {
                store
                    .abandon_undelivered_outbound(&await_key, &awaiting.object_digest)
                    .map_err(|e| e.redacted_display())?;
                mark_outbound_failed(
                    data_dir,
                    &peer_cert.device_ed_pub,
                    &awaiting.session_id,
                    &awaiting.object_digest,
                    &awaiting.message_id,
                )?;
                continue;
            }
            Err(e) => {
                let detail = dial_err
                    .borrow()
                    .clone()
                    .unwrap_or_else(|| e.redacted_display());
                if stage_or_body_handoff_failure(&detail) {
                    store
                        .abandon_undelivered_outbound(&await_key, &awaiting.object_digest)
                        .map_err(|e| e.redacted_display())?;
                    mark_outbound_failed(
                        data_dir,
                        &peer_cert.device_ed_pub,
                        &awaiting.session_id,
                        &awaiting.object_digest,
                        &awaiting.message_id,
                    )?;
                }
                return Err(detail);
            }
        }
    }
    *history_queue_text.borrow_mut() = Some(text.to_string());
    *dial_session.borrow_mut() = session_id;
    *dial_expected_digest.borrow_mut() = None;
    // Lock+capacity held until stage write inside dial (or send fails).
    *stage_guard.borrow_mut() = Some(
        raven_core::OutboundStageSendGuard::acquire(data_dir, text, now).map_err(|e| match e {
            raven_core::ChatHistoryError::TooLarge => {
                "outbound stage capacity exceeded".to_string()
            }
            other => other.to_string(),
        })?,
    );
    let outbound = match store.send_message_envelope(
        record_key,
        text,
        &local_device,
        now,
        expires,
        now,
        &mut rng,
        &mut dial,
    ) {
        Ok(row) => {
            let _ = stage_guard.borrow_mut().take();
            row
        }
        Err(e) => {
            let detail = dial_err
                .borrow()
                .clone()
                .unwrap_or_else(|| e.redacted_display());
            let binding = failed_binding.borrow_mut().take();
            let _ = stage_guard.borrow_mut().take();
            if stage_or_body_handoff_failure(&detail) {
                if let Some((sid, digest, mid)) = binding {
                    abandon_prepared_binding(
                        data_dir,
                        &mut store,
                        &peer_cert.device_ed_pub,
                        &sid,
                        &digest,
                        &mid,
                    )?;
                }
            }
            return Err(detail);
        }
    };

    let mid = hex::encode(&outbound.message_id[..4]);
    trace_delivery::trace_event(
        "ash/pair_init_lab.rs:send_indexed_text",
        "TRACE_INDEXED_MESSAGE_DIALED",
        "WAITING_FOR_ENDPOINT_ACK",
        Some(&mid),
        Some(carrier.label()),
    );
    println!(
        "{C_GREEN}indexed message queued after dial{C_RESET} mid={mid}… peer={} carrier={}",
        sanitize_terminal_text(lan_dial),
        carrier.label()
    );
    if let Some(ack) = first_ack_frame(&replies.borrow()) {
        finish_outbound_delivered(
            data_dir,
            &mut store,
            record_key,
            peer_cert,
            &session_id,
            &outbound.object_digest,
            &outbound.message_id,
            ack,
            now,
        )?;
        println!("{C_GREEN}status{C_RESET} delivered");
        trace_delivery::trace_event(
            "ash/pair_init_lab.rs:send_indexed_text",
            "TRACE_ENDPOINT_ACK_ACCEPTED",
            "DELIVERED",
            Some(&mid),
            Some("accept_ack_envelope"),
        );
    } else {
        return Err("WAITING_FOR_ENDPOINT_ACK: dial succeeded but no sealed ACK".into());
    }
    Ok(())
}

fn stage_or_body_handoff_failure(detail: &str) -> bool {
    detail.contains("outbound body unavailable")
        || detail.contains("binding mismatch")
        || detail.contains("outbound stage capacity exceeded")
}

fn abandon_prepared_binding(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<(), String> {
    let Some(pending_key) = store
        .record_key_for_session_id(session_id)
        .map_err(|e| e.redacted_display())?
    else {
        return Ok(());
    };
    let pending = store
        .pending_endpoint_outbound_for_recipient(Some(peer_pub))
        .map_err(|e| e.redacted_display())?
        .into_iter()
        .find(|row| {
            row.kind == EndpointOutboundKind::Message
                && row.session_id == *session_id
                && row.object_digest == *object_digest
                && row.message_id == *message_id
        });
    let Some(pending) = pending else {
        return Ok(());
    };
    store
        .abandon_undelivered_outbound(&pending_key, &pending.object_digest)
        .map_err(|e| e.redacted_display())?;
    mark_outbound_failed(
        data_dir,
        peer_pub,
        &pending.session_id,
        &pending.object_digest,
        &pending.message_id,
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn finish_outbound_delivered(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    record_key: &IndexedSessionRecordKey,
    peer_cert: &DeviceCertificate,
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
    ack: &[u8],
    now: u64,
) -> Result<(), String> {
    // History body must exist before Delivered is committed.
    raven_core::ensure_outbound_queued_history(
        data_dir,
        &peer_cert.device_ed_pub,
        session_id,
        object_digest,
        message_id,
        now,
        None,
    )?;
    store
        .accept_ack_envelope(
            record_key,
            ack,
            peer_cert,
            peer_ack_revoked(data_dir, peer_cert)?,
            now_ms(),
        )
        .map_err(|e| e.redacted_display())?;
    raven_core::mark_lan_chat_history_delivery(
        data_dir,
        "out",
        &peer_cert.device_ed_pub,
        message_id,
        "delivered",
    )?;
    raven_core::clear_staged_outbound_body(data_dir, message_id).map_err(|e| e.to_string())?;
    Ok(())
}

fn mark_outbound_failed(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    session_id: &[u8; 32],
    object_digest: &[u8; 32],
    message_id: &[u8; 16],
) -> Result<(), String> {
    if let Some(staged) =
        raven_core::load_staged_outbound_body(data_dir, message_id).map_err(|e| e.to_string())?
    {
        if !staged
            .peer_pub_hex
            .eq_ignore_ascii_case(&hex::encode(peer_pub))
            || !staged
                .session_id_hex
                .eq_ignore_ascii_case(&hex::encode(session_id))
            || !staged
                .object_digest_hex
                .eq_ignore_ascii_case(&hex::encode(object_digest))
            || !staged
                .message_id_hex
                .eq_ignore_ascii_case(&hex::encode(message_id))
        {
            return Err(format!(
                "staged outbound binding mismatch on fail mid={}",
                hex::encode(message_id)
            ));
        }
        raven_core::persist_lan_chat_history(
            data_dir,
            "out",
            peer_pub,
            message_id,
            staged.created_at_ms,
            "failed",
            staged.body.as_bytes(),
        )?;
    } else {
        raven_core::mark_lan_chat_history_delivery(
            data_dir, "out", peer_pub, message_id, "failed",
        )?;
    }
    raven_core::clear_staged_outbound_body(data_dir, message_id).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn export_lab_device_cert(data_dir: &Path, id: &Identity) -> Result<(), String> {
    let (cert, _) = ensure_local_device_cert(data_dir, id)?;
    let path = data_dir.join("lab_device_cert.json");
    let json = serde_json::to_string_pretty(&cert).map_err(|e| e.to_string())?;
    raven_core::atomic_write_private(&path, json.as_bytes())?;
    println!(
        "{C_BOLD}lab device cert{C_RESET} → {} (give peer; map key = your pub_hex)",
        path.display()
    );
    println!(
        "{C_DIM}peer_device_certs.json entry key{C_RESET} {}",
        hex::encode(id.public_key_bytes())
    );
    Ok(())
}

pub fn import_peer_device_cert(
    data_dir: &Path,
    peer_pub_hex: &str,
    cert_json_path: &Path,
) -> Result<(), String> {
    let peer = parse_pub_hex(peer_pub_hex)?;
    let raw = std::fs::read_to_string(cert_json_path).map_err(|e| e.to_string())?;
    let cert: DeviceCertificate =
        serde_json::from_str(&raw).map_err(|e| format!("cert json: {e}"))?;
    if cert.user_ed_pub != peer && cert.device_ed_pub != peer {
        return Err("cert does not match peer_pub_hex".into());
    }
    cache_peer_cert(data_dir, &peer, &cert)?;
    println!("{C_GREEN}peer cert cached{C_RESET} for {peer_pub_hex}");
    Ok(())
}

#[allow(dead_code)]
pub fn ingest_pair_response_packed(data_dir: &Path, packed: &[u8]) -> Result<(), String> {
    let PairInitOobClassify::PairResponse(wire) = classify_packed_envelope(packed) else {
        return Err("not PairResponse OOB".into());
    };
    let response = raven_core::pair_init::decode_response(&wire).map_err(|e| format!("{e:?}"))?;
    let mut map = pending_inits().lock().map_err(|_| "pending lock")?;
    let Some(pending) = map.remove(&response.init_id) else {
        return Err("no pending PairInit for this response".into());
    };
    let mut store = IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    store
        .confirm_verified_pair_response(&pending.record_key, &pending.init, &response, now_ms())
        .map_err(|e| e.redacted_display())?;
    let path = data_dir.join("lab_pair_response.rvpr1");
    raven_core::atomic_write_private(&path, &wire)
}

#[allow(dead_code)]
fn _path_marker() -> PathBuf {
    PathBuf::from(".")
}
