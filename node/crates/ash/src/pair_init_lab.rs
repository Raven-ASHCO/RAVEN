//! Indexed send: LanDial (Noise XX) or InternetDial (RIH1) + PairInit + ACK.
//!
//! Never uses `unsafe-demo-crypto` / public-key-derived `seal_message`.
//! Lab import files are optional leftovers; the live path uses RLB1 on the socket.
//! InternetDial is lab-gated and is not a WAN claim.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use raven_core::device_cert::{ensure_local_device_certificate, DeviceCertificate, DeviceRegistry};
use raven_core::envelope::Envelope;
use raven_core::identity::Identity;
use raven_core::indexed_session_store::{
    AuthorizedEndpointDevice, EndpointOutboundKind, IndexedSessionRecordKey, IndexedSessionStore,
};
use raven_core::ipc::{ipc_endpoint, IpcRequest, IpcResponse, IPC_VERSION};
use raven_core::lan_dispatch::{
    cache_peer_bundle, create_initiator_pair_init, find_confirmed_peer_session,
    load_cached_peer_bundle, parse_peer_offer, wrap_pair_init,
};
use raven_core::outbox::{
    abandon_undelivered_to_peer, clear_object_routes, envelope_expires_at,
    finish_outbound_delivered, first_ack_frame, give_up_outbound, outbound_already_delivered,
    peer_lineage_denied, record_object_routes, record_outbound_delivered, send_lock_busy,
    CarrierChoice, GiveUp, OutboxCarrier, OutboxRoute, PeerSendLock, ACK_FOR_ANOTHER_MESSAGE,
    CONTACT_NOT_VERIFIED, HISTORY_EXPIRED, HISTORY_FAILED,
};
use raven_core::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};
use raven_core::paths::PRIMARY_DEVICE_ID;
use raven_core::sanitize::sanitize_terminal_line;

use super::ext::{
    earlier_unconfirmed_text, earlier_undelivered_text, friendly_send_error, not_sent_text,
    queued_text, quoted_preview, recorded_locally_failed_text, unconfirmed_text, RetryNote,
    SendCtx,
};
use super::trace_delivery;

// Shared palette (NO_COLOR / non-TTY aware), clock and strict pub_hex parser.
use super::{now_ms, parse_pub_hex_strict as parse_pub_hex, C_BOLD, C_DIM, C_GREEN, C_RESET};

const DEVICE_ID: &str = PRIMARY_DEVICE_ID;
const PEER_CERT_CACHE: &str = "peer_device_certs.json";
/// Mirrors raven-core `lan_dispatch::MAX_TRUSTED_PEER_CERT_KEYS`: the lab
/// import must not grow the shared peer cert cache past the production cap.
const MAX_PEER_CERT_CACHE_KEYS: usize = 256;
/// Longest one `ash send` waits for another send from this profile to the same
/// peer (another `ash send`, or raven-node's outbox retrying it; see
/// [`acquire_send_lock`]).
const PEER_SEND_LOCK_WAIT: Duration = Duration::from_secs(120);

/// The per-peer send lock shared with raven-node's outbox worker
/// ([`raven_core::outbox::PeerSendLock`]): pairing (first contact), the retry
/// of an earlier queued message, staging the new one and its dial run under it.
/// Without it, concurrent senders interleave in ways the store can only refuse
/// (two first-contact sends each ran PairInit; a burst lost texts to the single
/// outstanding-message slot). Under the lock the second sender finds the first
/// one's confirmed session and reuses it, and a burst goes out one by one.
///
/// It is taken *after* the RLB1 probe, so waiting on an unreachable peer is not
/// serialised, and an offline send (stage only, no dial) holds it just briefly.
/// Held per peer, so sends to different peers never wait on each other.
pub(crate) fn acquire_send_lock(
    data_dir: &Path,
    peer_device: &[u8; 32],
) -> Result<PeerSendLock, String> {
    acquire_send_lock_within(data_dir, peer_device, PEER_SEND_LOCK_WAIT)
}

/// [`acquire_send_lock`] for a send to `who`: when the lock is not free at
/// once, say so on stderr (one plain line) before the bounded wait, so a send
/// that waits behind raven-node's background retry (or another terminal) does
/// not look frozen.
fn acquire_send_lock_noting(
    data_dir: &Path,
    peer_device: &[u8; 32],
    who: &str,
) -> Result<PeerSendLock, String> {
    acquire_send_lock_noting_within(data_dir, peer_device, who, PEER_SEND_LOCK_WAIT, &mut |l| {
        eprintln!("{C_DIM}{l}{C_RESET}")
    })
}

fn acquire_send_lock_noting_within(
    data_dir: &Path,
    peer_device: &[u8; 32],
    who: &str,
    wait: Duration,
    note: &mut dyn FnMut(&str),
) -> Result<PeerSendLock, String> {
    match PeerSendLock::acquire_within(data_dir, peer_device, Duration::ZERO) {
        Ok(lock) => return Ok(lock),
        Err(e) if !send_lock_busy(&e) => {
            return Err(format!("NOT SENT, nothing queued: send lock: {e}"));
        }
        Err(_) => {}
    }
    note(&send_lock_waiting_text(who, wait));
    acquire_send_lock_within(data_dir, peer_device, wait)
}

/// The one line a send prints while it waits for the per-peer send lock.
fn send_lock_waiting_text(who: &str, wait: Duration) -> String {
    format!(
        "waiting: another send to {who} is in progress (raven-node retrying an earlier \
         message, or another terminal); this waits at most {}s",
        wait.as_secs()
    )
}

fn acquire_send_lock_within(
    data_dir: &Path,
    peer_device: &[u8; 32],
    wait: Duration,
) -> Result<PeerSendLock, String> {
    PeerSendLock::acquire_within(data_dir, peer_device, wait).map_err(|e| {
        if send_lock_busy(&e) {
            format!(
                "NOT SENT, nothing queued: another `ash send` to this peer from this \
                 profile (or raven-node's outbox retrying an earlier message) was still \
                 running after {}s; try again shortly",
                wait.as_secs()
            )
        } else {
            format!("NOT SENT, nothing queued: send lock: {e}")
        }
    })
}

/// How long the RLB1 probe may take when the message can be queued anyway (a
/// confirmed session exists): `raven send` then ends within about 10 s and
/// raven-node's outbox keeps trying. A first message still waits for the
/// full dial, since it cannot be queued.
const QUEUEABLE_PROBE_TIMEOUT: Duration = Duration::from_secs(7);
/// The IPC wait of every other dial (just above the daemon's 45 s dial cap).
const DIAL_IPC_TIMEOUT: Duration = Duration::from_secs(50);
/// How long `raven send` waits for raven-node to accept an `OutboxKick`.
const OUTBOX_KICK_TIMEOUT: Duration = Duration::from_secs(2);

/// Refusal for the lab-only Internet carrier. Shared with ext.rs, which refuses
/// with it before it would start a daemon.
pub const INTERNET_DIRECT_HOLD: &str =
    "INTERNET_DIRECT_HOLD: indexed InternetTransport is lab-only \
     (debug RAVEN_LAB_TEST_A=1); INTERNET_DIRECT_PRODUCTION_ENABLED=false; \
     localhost ≠ WAN Proven";

/// Carrier for one indexed send. `Internet` is lab-only (not WAN Proven).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DialCarrier {
    Lan,
    Internet,
}

impl DialCarrier {
    pub(crate) fn label(self) -> &'static str {
        self.outbox().label()
    }

    /// The same carrier in the shared outbox / route policy.
    pub(crate) fn outbox(self) -> OutboxCarrier {
        match self {
            Self::Lan => OutboxCarrier::Lan,
            Self::Internet => OutboxCarrier::Internet,
        }
    }
}

/// Refusal for an Internet send to a contact that is not verified (owner
/// decision 2026-10-08: Internet delivery only for pinned contacts). Nothing
/// was dialled.
pub(crate) fn unverified_internet_text(who: &str, verify_cmd: &str, pin_cmd: &str) -> String {
    format!(
        "NOT SENT: {who} is not verified: Internet delivery needs the fingerprint checked \
         first. Compare it with {who} by phone or in person (run: {verify_cmd}), then pin it: \
         {pin_cmd}. Nothing was dialled. ({CONTACT_NOT_VERIFIED})"
    )
}

fn ensure_local_device_cert(
    data_dir: &Path,
    id: &Identity,
) -> Result<(DeviceCertificate, DeviceRegistry), String> {
    ensure_local_device_certificate(data_dir, id, DEVICE_ID)
}

/// Lab-only cert import write. Runs under raven-core's shared peer-cache lock
/// (which also recovers any staged cert+prekey commit first) and refuses to
/// rewrite a cache it cannot parse instead of silently dropping trusted certs.
fn cache_peer_cert(
    data_dir: &Path,
    peer_pub: &[u8; 32],
    cert: &DeviceCertificate,
) -> Result<(), String> {
    raven_core::with_prekey_store_lock(data_dir, || {
        let path = data_dir.join(PEER_CERT_CACHE);
        let mut map: HashMap<String, DeviceCertificate> = if path.exists() {
            let raw =
                std::fs::read_to_string(&path).map_err(|e| format!("peer cert cache read: {e}"))?;
            serde_json::from_str(&raw)
                .map_err(|e| format!("peer cert cache corrupt — refusing overwrite: {e}"))?
        } else {
            HashMap::new()
        };
        map.insert(hex::encode(peer_pub), cert.clone());
        if map.len() > MAX_PEER_CERT_CACHE_KEYS {
            return Err(format!(
                "peer cert cache full ({MAX_PEER_CERT_CACHE_KEYS} keys) — refusing lab import"
            ));
        }
        let out = serde_json::to_string_pretty(&map).map_err(|e| e.to_string())?;
        raven_core::atomic_write_private(&path, out.as_bytes())
    })
}

fn ipc_carrier_dial(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    ipc_carrier_dial_within(
        data_dir,
        carrier,
        dial,
        expected_pub_hex,
        frames,
        DIAL_IPC_TIMEOUT,
    )
}

/// [`ipc_carrier_dial`] that waits at most `timeout` for the daemon's answer.
/// Only for frame-less probes when shorter than the daemon's own dial cap: the
/// daemon may still finish such a dial, which sends nothing.
fn ipc_carrier_dial_within(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    timeout: Duration,
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
    // Retry only the connect (daemon just auto-started / restarting); a request
    // that was written is never replayed.
    let answer = super::ipc_client::ipc_request_retrying_connect(data_dir, &req, timeout);
    if timeout < DIAL_IPC_TIMEOUT && frames.is_empty() {
        if let Err(e) = &answer {
            if super::ipc_client::error_means_no_answer(e) {
                return Err(format!(
                    "{} {}: no answer within {}s (the probe was cut short; nothing was sent)",
                    carrier.label(),
                    dial,
                    timeout.as_secs()
                ));
            }
        }
    }
    match answer {
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

/// [`ipc_carrier_dial`], repeated while the peer's listener sheds load. A refusal
/// *during the handshake* means none of our frames reached the peer, so the dial
/// is safe to repeat; a burst of concurrent sends from one profile otherwise
/// overflowed the listener's small per-source handshake cap and read as an
/// unreachable peer or a failed dial.
fn ipc_carrier_dial_patient(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    ipc_carrier_dial_patient_within(
        data_dir,
        carrier,
        dial,
        expected_pub_hex,
        frames,
        DIAL_IPC_TIMEOUT,
    )
}

fn ipc_carrier_dial_patient_within(
    data_dir: &Path,
    carrier: DialCarrier,
    dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
    timeout: Duration,
) -> Result<Vec<Vec<u8>>, String> {
    retry_while_peer_sheds_load(PROBE_ATTEMPTS, PROBE_BACKOFF, std::thread::sleep, || {
        ipc_carrier_dial_within(data_dir, carrier, dial, expected_pub_hex, frames, timeout)
    })
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

pub fn ensure_lab_local_material(data_dir: &Path, id: &Identity) -> Result<(), String> {
    let (_cert, _reg) = ensure_local_device_cert(data_dir, id)?;
    raven_core::ensure_local_prekey(data_dir, id)
}

/// One way to dial a peer for one send: a carrier and its `host:port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialRoute {
    pub carrier: DialCarrier,
    pub dial: String,
}

/// PairInit + indexed send over one-connection LanDial or InternetDial, on a
/// named carrier. `ctx` names the recipient for every line this prints (see
/// `ext::SendCtx`): success lines go to stdout, and every `Err` is already the
/// user's sentence (queued / not sent / unconfirmed). Production sends go
/// through [`run_pair_init_and_send_routes`]; this single-route form is kept
/// for the tests (Unix-only ones).
#[cfg(test)]
#[cfg_attr(not(unix), allow(dead_code))]
pub fn run_pair_init_and_send_on(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    text: &str,
    carrier: DialCarrier,
    ctx: &SendCtx,
) -> Result<(), String> {
    let route = DialRoute {
        carrier,
        dial: peer.to_string(),
    };
    run_pair_init_and_send_routes(data_dir, id, &[route], peer_pub_hex, text, ctx).map(|_| ())
}

/// [`run_pair_init_and_send_on`] over the first of `routes` (in order: LAN,
/// then Internet) whose RLB1 probe answers, and returns the route it used.
///
/// Only the probe moves on to the next route. It carries no message frame and
/// stages nothing, so trying another route can never send or queue a second
/// copy. Everything stateful (pairing, the retry of an earlier queued message,
/// staging and dialing this one) runs once, on the chosen route. When no route
/// answers, the send behaves exactly like a single-route send on the first
/// route (queued for retry if a confirmed session exists, else NOT SENT).
pub fn run_pair_init_and_send_routes(
    data_dir: &Path,
    id: &Identity,
    routes: &[DialRoute],
    peer_pub_hex: &str,
    text: &str,
    ctx: &SendCtx,
) -> Result<DialRoute, String> {
    if !trace_delivery::live_pair_init_outbound_ready() {
        return Err(trace_delivery::production_gate_status().into());
    }
    let first = routes
        .first()
        .ok_or_else(|| "no host:port to dial — refusing LocalListenQueue fallback".to_string())?;
    for route in routes {
        if route.carrier == DialCarrier::Internet && !raven_core::internet_direct_live_enabled() {
            return Err(INTERNET_DIRECT_HOLD.into());
        }
        let peer = route.dial.as_str();
        if !peer.contains(':')
            || peer.eq_ignore_ascii_case("local-listen")
            || peer.eq_ignore_ascii_case("local")
        {
            return Err(format!(
                "valid {} host:port required — refusing LocalListenQueue fallback",
                route.carrier.label()
            ));
        }
    }
    let peer_pub = parse_pub_hex(peer_pub_hex)?;
    // Internet delivery only for a verified (pinned) contact: refuse before
    // anything is dialled (`--peer … --carrier internet` included).
    if routes.iter().any(|r| r.carrier == DialCarrier::Internet)
        && !raven_core::carrier_allowed_for_contact(
            OutboxCarrier::Internet,
            raven_core::contact_is_pinned(data_dir, &peer_pub)?,
        )
    {
        return Err(unverified_internet_text(
            &ctx.display_name(),
            &format!(
                "raven contact verify --address {}",
                raven_core::encode_address(&peer_pub)
            ),
            &pin_command_hint(&peer_pub),
        ));
    }
    ensure_lab_local_material(data_dir, id)?;
    let (local_cert, registry) = ensure_local_device_cert(data_dir, id)?;
    let handoff = OutboxHandoff::new(data_dir, routes, peer_pub, ctx.choice);
    // With a confirmed session the message can be queued for raven-node's
    // outbox whatever the probe says, so an unreachable peer costs ~10 s here,
    // not a full dial timeout. A first message needs the probe's answer.
    let probe_timeout = match offline_send_target(data_dir, &peer_pub) {
        Ok(Some(_)) => QUEUEABLE_PROBE_TIMEOUT,
        _ => DIAL_IPC_TIMEOUT,
    };

    let mut probe_errors: Vec<String> = Vec::new();
    let mut answered: Option<(DialRoute, raven_core::LanBundle)> = None;
    for (i, route) in routes.iter().enumerate() {
        let probe = ipc_carrier_dial_patient_within(
            data_dir,
            route.carrier,
            &route.dial,
            peer_pub_hex,
            &[],
            probe_timeout,
        )
        .and_then(|replies| {
            replies
                .iter()
                .find_map(|f| parse_peer_offer(f).ok())
                .ok_or_else(|| "peer did not return an RLB1 bundle".to_string())
        });
        match probe {
            Ok(bundle) => {
                answered = Some((route.clone(), bundle));
                break;
            }
            Err(e) => {
                if let Some(next) = routes.get(i + 1).filter(|_| super::ext::verbose()) {
                    eprintln!(
                        "{C_DIM}{} {} did not answer; trying {} {}{C_RESET}",
                        route.carrier.label(),
                        sanitize_terminal_line(&route.dial),
                        next.carrier.label(),
                        sanitize_terminal_line(&next.dial)
                    );
                }
                probe_errors.push(if routes.len() > 1 {
                    format!("{} {}: {e}", route.carrier.label(), route.dial)
                } else {
                    e
                });
            }
        }
    }
    // From here on the send reads and writes per-peer session state: serialise it
    // with every other `ash send` to this peer (see `PeerSendLock`). After the
    // probe, so an unreachable peer's timeouts are not serialised.
    let _send_lock = acquire_send_lock_noting(data_dir, &peer_pub, &ctx.display_name())?;
    let (route, peer_bundle) = match answered {
        Some(hit) => hit,
        // Peer asleep / unreachable on every route: the RLB1 probe is not needed
        // to stage a message into an already-confirmed session, so do that (on
        // the first route) instead of dropping the text.
        None => {
            let ctx = SendCtx {
                dial: first.dial.trim().to_string(),
                ..ctx.clone()
            };
            return send_when_peer_unreachable(
                data_dir,
                id,
                &registry,
                &local_cert,
                &first.dial,
                peer_pub_hex,
                &peer_pub,
                text,
                first.carrier,
                probe_errors.join("; "),
                &ctx,
                &handoff,
            )
            .map(|()| first.clone());
        }
    };
    let ctx = &SendCtx {
        dial: route.dial.trim().to_string(),
        ..ctx.clone()
    };
    let (peer, carrier) = (route.dial.as_str(), route.carrier);
    if peer_bundle.cert.user_ed_pub != peer_pub && peer_bundle.cert.device_ed_pub != peer_pub {
        return Err("RLB1 identity does not match --peer-pub-hex / contact".into());
    }
    cache_peer_bundle(data_dir, &peer_bundle)?;

    let record_key = if let Some(existing) =
        find_confirmed_peer_session(data_dir, &peer_bundle.cert.device_ed_pub)?
    {
        existing
    } else {
        // PairInit (addresses and trust material in clear, PairInit V1 §7) only
        // rides a carrier whose Raven Noise session ends at the contact.
        if !carrier.outbox().confidential_to_endpoint() {
            return Err(not_sent_text(
                ctx,
                &format!(
                    "{} is not confidential to the endpoint; no PairInit on it",
                    carrier.label()
                ),
                true,
            ));
        }
        let (init, key) = create_initiator_pair_init(data_dir, id, &peer_bundle)?;
        let init_frame = wrap_pair_init(id, &init)?;
        // A responder that does not list us as a contact already closed the RLB1
        // probe above after our hello (`LINK_NOT_ACCEPTED`). Should it refuse the
        // PairInit itself ("pair init refused: peer is not a local contact"), it
        // says nothing on the wire, so the dial ends in a silent close;
        // `not_sent_text` names the likely cause (and nothing was queued).
        let replies =
            ipc_carrier_dial_patient(data_dir, carrier, peer, peer_pub_hex, &[init_frame])
                .map_err(|e| not_sent_text(ctx, &e, true))?;
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
            not_sent_text(
                ctx,
                &format!(
                    "WAITING_FOR_PAIR_RESPONSE: no PairResponse on {} ({} frames: {})",
                    carrier.label(),
                    replies.len(),
                    kinds.join(",")
                ),
                true,
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
        ctx.say_first_contact();
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
        None,
        ctx,
        &handoff,
    )
    .map(|()| route.clone())
}

/// Refusal for a LAN send to an unverified contact at an address that is not
/// on the local network (owner decision 2026-10-08: unverified contacts are
/// LAN only). Nothing was dialled.
pub(crate) fn unverified_remote_lan_text(
    who: &str,
    reason: &str,
    verify_cmd: &str,
    pin_cmd: &str,
) -> String {
    format!(
        "NOT SENT: {who} is not verified, and {reason}: an unverified contact is reached only \
         at addresses on your local network. Compare the fingerprint with {who} by phone or in \
         person (run: {verify_cmd}), then pin it: {pin_cmd}. Nothing was dialled. \
         ({CONTACT_NOT_VERIFIED})"
    )
}

/// `raven contact add …` that pins the contact whose key is `peer`, for the
/// verified-contact refusal (the existing verify command only shows the
/// fingerprint; adding again with `--verify-fp` pins it).
pub(crate) fn pin_command_hint(peer: &[u8; 32]) -> String {
    format!(
        "raven contact add --address {} --pub-hex {} --verify-fp <the fingerprint they read out>",
        raven_core::encode_address(peer),
        hex::encode(peer)
    )
}

/// Hands a message this send left undelivered to raven-node's background
/// outbox: records, for that object, the carrier choice and the routes this
/// send planned (so the worker never widens them; the record expires with the
/// envelope) and kicks the worker once per send.
pub(crate) struct OutboxHandoff<'a> {
    data_dir: &'a Path,
    routes: &'a [DialRoute],
    peer: [u8; 32],
    choice: CarrierChoice,
    taken: std::cell::Cell<Option<bool>>,
}

impl<'a> OutboxHandoff<'a> {
    /// `choice`: what `--carrier` asked for; `None` derives it from the routes
    /// (both carriers: auto; one: that one).
    pub(crate) fn new(
        data_dir: &'a Path,
        routes: &'a [DialRoute],
        peer: [u8; 32],
        choice: Option<CarrierChoice>,
    ) -> Self {
        let has = |c: DialCarrier| routes.iter().any(|r| r.carrier == c);
        let derived = match (has(DialCarrier::Lan), has(DialCarrier::Internet)) {
            (true, true) => CarrierChoice::Auto,
            (false, true) => CarrierChoice::Internet,
            _ => CarrierChoice::Lan,
        };
        Self {
            data_dir,
            routes,
            peer,
            choice: choice.unwrap_or(derived),
            taken: std::cell::Cell::new(None),
        }
    }

    /// Did raven-node's outbox take it (its `OutboxKick` was accepted)? An
    /// older service answers with an error: nothing retries it then.
    fn kicked(&self) -> bool {
        if let Some(taken) = self.taken.get() {
            return taken;
        }
        let taken = outbox_kick(self.data_dir, Some(&self.peer));
        self.taken.set(Some(taken));
        taken
    }

    /// Record `message_id` for the worker and return the retry promise for its
    /// envelope, which expires at `expires_at_ms`.
    pub(crate) fn note(&self, message_id: &[u8; 16], expires_at_ms: u64) -> RetryNote {
        let routes: Vec<OutboxRoute> = self
            .routes
            .iter()
            .map(|r| OutboxRoute {
                carrier: r.carrier.outbox(),
                dial: r.dial.clone(),
            })
            .collect();
        // Best effort: without the record the worker plans LAN from the book.
        let _ = record_object_routes(
            self.data_dir,
            message_id,
            &self.peer,
            self.choice,
            &routes,
            expires_at_ms,
            now_ms(),
        );
        RetryNote {
            expires_at_ms,
            background: self.kicked(),
        }
    }
}

/// Ask raven-node's outbox to retry the objects to `peer` (or all) now.
/// `true` only when a worker accepted it.
pub(crate) fn outbox_kick(data_dir: &Path, peer: Option<&[u8; 32]>) -> bool {
    let req = IpcRequest::OutboxKick {
        v: IPC_VERSION,
        peer_pub_hex: peer.map(hex::encode),
    };
    matches!(
        super::ipc_client::ipc_request_timeout(data_dir, &req, OUTBOX_KICK_TIMEOUT),
        Ok(IpcResponse::Accepted { .. })
    )
}

/// When the sealed envelope `bytes` stops being valid (0 if unreadable).
fn envelope_expiry(bytes: &[u8]) -> u64 {
    Envelope::unpack(bytes).map(|e| e.expires_at).unwrap_or(0)
}

/// Attempts at a dial the peer shed at the handshake, and the first back-off
/// between them (doubling).
const PROBE_ATTEMPTS: u32 = 5;
const PROBE_BACKOFF: Duration = Duration::from_millis(150);

/// The daemon's text when the peer's listener closed the connection *during the
/// handshake*: it is at its connection limit (or not a RAVEN node), and nothing
/// of ours was sent.
fn peer_shed_the_connection(err: &str) -> bool {
    err.contains("closed the connection during the handshake")
}

/// Run `attempt`, retrying (with doubling back-off plus a little jitter) while the
/// peer's listener sheds load. Only for dials, whose refusal *during the
/// handshake* proves no frame reached the peer, so repeating them cannot
/// duplicate anything: a burst of concurrent `ash send`s all dial at once, and the
/// listener's small per-source handshake cap used to turn the overflow into "peer
/// unreachable" or a queued message. Any other error, and the last attempt's, is
/// returned as is.
fn retry_while_peer_sheds_load<T>(
    attempts: u32,
    first_backoff: Duration,
    mut sleep: impl FnMut(Duration),
    mut attempt: impl FnMut() -> Result<T, String>,
) -> Result<T, String> {
    use rand::Rng;
    let mut backoff = first_backoff;
    let mut n = 1;
    loop {
        match attempt() {
            Err(e) if peer_shed_the_connection(&e) && n < attempts => {
                let jitter = rand::thread_rng().gen_range(0..=backoff.as_millis() as u64 / 2);
                sleep(backoff + Duration::from_millis(jitter));
                backoff *= 2;
                n += 1;
            }
            other => return other,
        }
    }
}

/// The peer's cached (re-verified) certificate and the confirmed session with
/// it, if both exist. First contact has neither: the peer's RLB1 bundle is
/// needed to seal the PairInit, so it cannot be staged offline.
fn offline_send_target(
    data_dir: &Path,
    peer_pub: &[u8; 32],
) -> Result<Option<(DeviceCertificate, IndexedSessionRecordKey)>, String> {
    let Some(bundle) = load_cached_peer_bundle(data_dir, peer_pub)? else {
        return Ok(None);
    };
    if bundle.cert.user_ed_pub != *peer_pub && bundle.cert.device_ed_pub != *peer_pub {
        return Ok(None);
    }
    let Some(record_key) = find_confirmed_peer_session(data_dir, &bundle.cert.device_ed_pub)?
    else {
        return Ok(None);
    };
    Ok(Some((bundle.cert, record_key)))
}

/// The RLB1 probe could not reach the peer. With a confirmed session the send
/// path stages the message durably before dialing, so run it: the message is
/// then queued and retried on the next send. Without one, say plainly that
/// nothing was queued (a first message cannot wait for the peer to come online).
#[allow(clippy::too_many_arguments)]
fn send_when_peer_unreachable(
    data_dir: &Path,
    id: &Identity,
    registry: &DeviceRegistry,
    local_cert: &DeviceCertificate,
    peer: &str,
    peer_pub_hex: &str,
    peer_pub: &[u8; 32],
    text: &str,
    carrier: DialCarrier,
    probe_err: String,
    ctx: &SendCtx,
    handoff: &OutboxHandoff<'_>,
) -> Result<(), String> {
    let (peer_cert, record_key) = match offline_send_target(data_dir, peer_pub) {
        Ok(Some(target)) => target,
        Ok(None) => return Err(not_sent_text(ctx, &probe_err, true)),
        Err(e) => {
            return Err(not_sent_text(
                ctx,
                &format!("{probe_err}; cached peer state is unavailable: {e}"),
                false,
            ));
        }
    };
    // The probe just failed: stage (and keep ordering behind any earlier queued
    // message) without dialing a second time, so an asleep peer costs one
    // timeout, not two.
    send_indexed_text(
        data_dir,
        id,
        registry,
        local_cert,
        &record_key,
        text,
        peer,
        peer_pub_hex,
        &peer_cert,
        carrier,
        Some(&probe_err),
        ctx,
        handoff,
    )
}

/// One line for a failed `ash send`. The outcomes differ, and one blanket
/// "send refused:" prefix misreported two of them:
/// - the text is **queued** locally (the carrier dial failed after staging):
///   `not delivered yet: ... queued locally ...`;
/// - the frames were **sent** and only the ACK is missing: `sent, delivery
///   unconfirmed ...` (the peer may already hold the message, so a script must not
///   read it as "not sent" and blindly send the text again);
/// - nothing of the message was queued: `NOT SENT: ...`, or the old
///   `send refused: ...` for text no sentence covers.
///
/// The send path already returns these sentences; this only turns text from
/// elsewhere into one (see `ext::friendly_send_error`, which takes the contact's
/// name for a more personal sentence).
pub(crate) fn send_failure_line(error: &str) -> String {
    friendly_send_error(error, "")
}

/// Why an earlier queued message was given up: it outlived its envelope validity
/// before it could be (re)delivered; the retry paths abandon it, and this says so.
const EXPIRED_BEFORE_DELIVERY: &str = "it expired before delivery was confirmed and was marked \
     expired (not delivered); send it again if you still need it";

/// Why a queued message was abandoned: it was sealed under a session the peer no
/// longer accepts while a newer confirmed session exists, so it can never be
/// delivered.
const SUPERSEDED_SESSION: &str = "it was sealed under an older connection that the other side \
     no longer accepts (a newer one exists) and was marked failed; send it again if you still \
     need it";

/// The daemon's error code for "the peer completed the handshake, took the
/// frames, and closed the connection without answering": a refusal it gave no
/// reason for (not a contact, no session with us, a session it no longer holds).
const PEER_REFUSED_CODE: &str = "_DIAL_PEER_CLOSED";

fn is_peer_refusal(detail: &str) -> bool {
    detail.contains(PEER_REFUSED_CODE)
}

/// The new message was refused before anything of it was staged.
fn not_sent_nothing_queued(ctx: &SendCtx, detail: &str) -> String {
    if detail.starts_with("NOT SENT") {
        detail.to_string()
    } else {
        not_sent_text(ctx, detail, false)
    }
}

/// `"first words..."` of a message that is still staged for retry, so a line about
/// an earlier message shows the user's own words instead of a hex id. Empty once
/// the staged body is gone (or cannot be read).
fn staged_preview(data_dir: &Path, message_id: &[u8; 16]) -> String {
    raven_core::load_staged_outbound_body(data_dir, message_id)
        .ok()
        .flatten()
        .map(|staged| quoted_preview(&staged.body))
        .unwrap_or_default()
}

/// Whether a failed retry of a queued row proves the row can never be delivered:
/// the peer is reachable (the RLB1 probe worked), it refused the frames, and the
/// row is sealed under a session other than the one this send uses, i.e. one a
/// newer confirmed session has superseded. A row on the *current* session is
/// kept (the refusal may be transient, and a duplicate must stay deduplicated).
fn superseded_row_was_refused(
    peer_unreachable: Option<&str>,
    row_key: &IndexedSessionRecordKey,
    selected: &IndexedSessionRecordKey,
    detail: &str,
) -> bool {
    peer_unreachable.is_none() && row_key != selected && is_peer_refusal(detail)
}

/// Daemon parity (`load_session_bound_peer_cert`): revocation is decided
/// against the certificate bound into the confirmed session at PairInit, never
/// against whatever certificate the peer presents now (RLB1 reply or cache). A
/// holder of a revoked device key can re-certify the same key under a new
/// `device_id`, which a legacy `(user, device_id)` revocation record does not
/// match. Such a certificate never hashes to the session's remote digest, so it
/// is refused here, before any seal or dial, instead of the message being
/// delivered and only the ACK acceptance failing.
fn require_session_bound_peer_cert(
    peer_cert: &DeviceCertificate,
    bound_digest: &[u8; 32],
) -> Result<(), String> {
    let presented = raven_core::device_certificate_hash(peer_cert)
        .map_err(|e| format!("peer device cert hash: {e}"))?;
    if presented != *bound_digest {
        return Err(format!(
            "{}: the peer's certificate is not the one bound into the confirmed session \
             (renewed or re-certified); nothing was sent",
            raven_core::ATSAM_SESSION_REQUIRED
        ));
    }
    Ok(())
}

/// Daemon parity (`seal_app_payload_under_session`): never seal to, retry
/// toward or resend to a revoked peer lineage, and refuse a retired local one.
/// Only the session-bound peer certificate is evaluated
/// (`require_session_bound_peer_cert`). Undelivered messages for a revoked peer
/// are abandoned (marked failed) so they are not retried on every later send.
fn refuse_revoked_peer(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    local_cert: &DeviceCertificate,
    peer_cert: &DeviceCertificate,
    bound_digest: &[u8; 32],
) -> Result<(), String> {
    require_session_bound_peer_cert(peer_cert, bound_digest)?;
    let peer_revoked = peer_lineage_denied(data_dir, peer_cert)?;
    if peer_revoked {
        abandon_undelivered_to_peer(data_dir, store, &peer_cert.device_ed_pub)?;
    }
    raven_core::refuse_if_session_lineage_revoked(data_dir, local_cert, peer_cert).map_err(|e| {
        if peer_revoked {
            format!("{e}: peer device lineage is revoked; nothing was sent; any queued messages for it were abandoned")
        } else {
            e
        }
    })
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
    // `Some(reason)`: the peer is already known unreachable (failed RLB1 probe).
    // Stage and queue as usual but skip the network, failing with `reason`.
    peer_unreachable: Option<&str>,
    ctx: &SendCtx,
    // Where a message this send leaves undelivered goes: raven-node's outbox.
    handoff: &OutboxHandoff<'_>,
) -> Result<(), String> {
    // LAN and Internet both carry each envelope as one Noise transport message.
    let max_text = raven_core::lan_noise::MAX_LAN_ENDPOINT_TEXT;
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
    // Before any retry, resend or seal: an existing confirmed session skips the
    // PairInit-time revocation check, so enforce it here, on the cert the
    // session is bound to.
    let bound_digest = store
        .remote_certificate_digest(record_key)
        .map_err(|e| e.redacted_display())?;
    refuse_revoked_peer(data_dir, &mut store, local_cert, peer_cert, &bound_digest)?;
    let session_expires = store
        .session_expires_at(record_key)
        .map_err(|e| e.redacted_display())?;
    // The shared validity policy (min(session end, now + 24 h)).
    let expires = envelope_expires_at(now, session_expires)?;
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
    // True once the new message body is durably staged, i.e. a failed dial left
    // it queued for retry (a staging failure did not).
    let staged_for_retry = std::cell::Cell::new(false);
    let mut dial = |digest: &[u8; 32], bytes: &[u8]| {
        let oversize = bytes.len() > raven_core::lan_noise::MAX_TRANSPORT_PLAINTEXT;
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
                staged_for_retry.set(true);
                // Never hold BEGIN EXCLUSIVE across carrier dial (up to ~45s).
                let _ = stage_guard.borrow_mut().take();
            }
        }
        if let Some(reason) = peer_unreachable {
            *dial_err.borrow_mut() = Some(reason.to_string());
            return Err(());
        }
        match ipc_carrier_dial_patient(data_dir, carrier, lan_dial, peer_pub_hex, &[bytes.to_vec()])
        {
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
    // Earlier messages to this peer first (queued, then sent without an ACK):
    // one outstanding message per peer, in order.
    let mut earlier: Vec<(raven_core::EndpointOutbound, bool)> = store
        .pending_endpoint_outbound_for_recipient(Some(recipient))
        .map_err(|e| e.redacted_display())?
        .into_iter()
        .map(|row| (row, false))
        .collect();
    earlier.extend(
        store
            .awaiting_ack_endpoint_outbound_for_recipient(Some(recipient))
            .map_err(|e| e.redacted_display())?
            .into_iter()
            .map(|row| (row, true)),
    );
    for (earlier_row, resend) in earlier {
        if earlier_row.kind != EndpointOutboundKind::Message {
            continue;
        }
        let Some(row_key) = store
            .record_key_for_session_id(&earlier_row.session_id)
            .map_err(|e| e.redacted_display())?
        else {
            continue;
        };
        let preview = staged_preview(data_dir, &earlier_row.message_id);
        let note = || {
            handoff.note(
                &earlier_row.message_id,
                envelope_expiry(&earlier_row.immutable_envelope_bytes),
            )
        };
        // An ACK that came back another way (pushed by the peer's outbox, or
        // seen by raven-node) already delivered it: record that, never dial it.
        if outbound_already_delivered(
            &store,
            &earlier_row.session_id,
            &earlier_row.message_id,
            recipient,
        )? {
            record_outbound_delivered(
                data_dir,
                &mut store,
                recipient,
                &earlier_row.session_id,
                &earlier_row.message_id,
            )?;
            let _ = clear_object_routes(data_dir, &[earlier_row.message_id]);
            ctx.say_earlier_delivered(&preview);
            continue;
        }
        *dial_session.borrow_mut() = earlier_row.session_id;
        *dial_expected_digest.borrow_mut() = Some(earlier_row.object_digest);
        replies.borrow_mut().clear();
        let result = if resend {
            store.resend_queued_endpoint_outbound(
                &row_key,
                &earlier_row.object_digest,
                &local_device,
                now,
                &mut dial,
            )
        } else {
            store.retry_endpoint_outbound(
                &row_key,
                &earlier_row.object_digest,
                &local_device,
                now,
                &mut dial,
            )
        };
        match result {
            Ok(row) => {
                let frames = replies.borrow();
                if let Some(ack) = first_ack_frame(&frames) {
                    let ack = ack.to_vec();
                    drop(frames);
                    finish_outbound_delivered(
                        data_dir,
                        &mut store,
                        &row_key,
                        peer_cert,
                        &earlier_row.session_id,
                        &earlier_row.object_digest,
                        &row.message_id,
                        &ack,
                        now,
                    )
                    .map_err(|e| finish_failure_text(ctx, &e, &preview, &note()))?;
                    let _ = clear_object_routes(data_dir, &[row.message_id]);
                    ctx.say_earlier_delivered(&preview);
                } else {
                    // Sent again, no ACK yet: the outbox keeps resending it.
                    let _ = note();
                    return Err(earlier_unconfirmed_text(ctx, &preview));
                }
            }
            Err(raven_core::IndexedSessionStoreError::NotFound)
            | Err(raven_core::IndexedSessionStoreError::BindingConflict) => continue,
            Err(raven_core::IndexedSessionStoreError::EndpointNotCurrentlyValid) => {
                // Expired by its own clock: give it up. Otherwise the clock
                // moved (a step backwards): keep it, raven-node retries it.
                if envelope_expiry(&earlier_row.immutable_envelope_bytes) <= now {
                    match give_up_row(
                        data_dir,
                        &mut store,
                        &row_key,
                        recipient,
                        &earlier_row,
                        HISTORY_EXPIRED,
                    )? {
                        GiveUp::Abandoned => {
                            ctx.say_earlier_failed(&preview, EXPIRED_BEFORE_DELIVERY)
                        }
                        GiveUp::Delivered => ctx.say_earlier_delivered(&preview),
                    }
                    continue;
                }
                if resend {
                    continue;
                }
                return Err(earlier_undelivered_text(
                    ctx,
                    CLOCK_MOVED,
                    &preview,
                    &note(),
                ));
            }
            Err(e) => {
                let detail = dial_err
                    .borrow()
                    .clone()
                    .unwrap_or_else(|| e.redacted_display());
                if stage_or_body_handoff_failure(&detail) {
                    give_up_row(
                        data_dir,
                        &mut store,
                        &row_key,
                        recipient,
                        &earlier_row,
                        HISTORY_FAILED,
                    )?;
                    return Err(detail);
                }
                if superseded_row_was_refused(peer_unreachable, &row_key, record_key, &detail) {
                    // Sealed under a session the (reachable) peer refuses while a
                    // newer one exists: it can never be accepted, and left alone it
                    // would block every later send until its envelope expires.
                    match give_up_row(
                        data_dir,
                        &mut store,
                        &row_key,
                        recipient,
                        &earlier_row,
                        HISTORY_FAILED,
                    )? {
                        GiveUp::Abandoned => ctx.say_earlier_failed(&preview, SUPERSEDED_SESSION),
                        GiveUp::Delivered => ctx.say_earlier_delivered(&preview),
                    }
                    continue;
                }
                return Err(earlier_undelivered_text(ctx, &detail, &preview, &note()));
            }
        }
    }
    // The loops above ran the shared `dial` for *earlier* messages and left their
    // binding and staged flag behind. They describe someone else's message: reset
    // them so the new send's own dial is the only thing that can say "queued".
    // (A stale binding made a send that failed at key reservation report that its
    // text was queued under the *earlier* message's id; it was never staged.)
    *failed_binding.borrow_mut() = None;
    staged_for_retry.set(false);
    *dial_err.borrow_mut() = None;
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
            // A binding that was prepared but never staged means the staging step
            // itself failed (chat history unreadable, Keychain denied, history locked,
            // ...). The body and the reserved outbound row may be half-written, and a
            // row left pending would be delivered silently by the NEXT send, so a user
            // who retypes the text as advised would send it twice. Abandon it, so that
            // "nothing was queued" is true.
            if stage_or_body_handoff_failure(&detail)
                || (binding.is_some() && !staged_for_retry.get())
            {
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
                return Err(detail);
            }
            return Err(match binding {
                // Only this call's own dial can have staged this message.
                Some((_, _, mid)) if staged_for_retry.get() => queued_text(
                    ctx,
                    &format!("{detail}; mid={}…", hex::encode(&mid[..4])),
                    &quoted_preview(text),
                    &handoff.note(&mid, expires),
                ),
                _ => not_sent_nothing_queued(ctx, &detail),
            });
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
        )
        .map_err(|e| {
            finish_failure_text(
                ctx,
                &e,
                &quoted_preview(text),
                &handoff.note(&outbound.message_id, expires),
            )
        })?;
        // Only a verified ACK gets here: "delivered" means the receiver confirmed.
        ctx.say_delivered(carrier.label(), &outbound.message_id);
        trace_delivery::trace_event(
            "ash/pair_init_lab.rs:send_indexed_text",
            "TRACE_ENDPOINT_ACK_ACCEPTED",
            "DELIVERED",
            Some(&mid),
            Some("accept_ack_envelope"),
        );
    } else {
        return Err(unconfirmed_text(
            ctx,
            &format!("WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid={mid}…"),
            &quoted_preview(text),
            &handoff.note(&outbound.message_id, expires),
        ));
    }
    Ok(())
}

/// The detail of an earlier message the store refuses although its envelope
/// has not expired: the computer's clock moved back past its creation time.
const CLOCK_MOVED: &str = "ENDPOINT_NOT_CURRENTLY_VALID: the earlier message is dated ahead of \
     this computer's clock (did the clock change?); it is kept, not given up, and raven-node \
     tries it again";

/// [`give_up_outbound`] for one outbox row; its route record goes too.
fn give_up_row(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    key: &IndexedSessionRecordKey,
    peer: &[u8; 32],
    row: &raven_core::EndpointOutbound,
    delivery: &str,
) -> Result<GiveUp, String> {
    let outcome = give_up_outbound(
        data_dir,
        store,
        key,
        peer,
        &row.session_id,
        &row.object_digest,
        &row.message_id,
        delivery,
    )?;
    let _ = clear_object_routes(data_dir, &[row.message_id]);
    Ok(outcome)
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
    give_up_row(
        data_dir,
        store,
        &pending_key,
        peer_pub,
        &pending,
        HISTORY_FAILED,
    )?;
    Ok(())
}

/// How a failure of [`finish_outbound_delivered`] is told: an ACK for another
/// message leaves this one unconfirmed; anything else happened after the peer
/// acknowledged this message, so it must not be retyped.
fn finish_failure_text(ctx: &SendCtx, raw: &str, preview: &str, retry: &RetryNote) -> String {
    if raw.starts_with(ACK_FOR_ANOTHER_MESSAGE) {
        unconfirmed_text(ctx, raw, preview, retry)
    } else {
        recorded_locally_failed_text(ctx, raw, preview, retry)
    }
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

/// Decode an already-sealed RavenEnvelopeV1. Does not seal (O6 M3 lab).
pub fn decode_already_sealed_envelope_b64(envelope_b64: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let raw = envelope_b64.trim();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw))
        .map_err(|e| format!("envelope_b64: {e}"))?;
    if Envelope::unpack(&bytes).is_none() {
        return Err("not a packed RavenEnvelopeV1 (already-sealed LanDial only)".into());
    }
    if bytes.len() < 4 || &bytes[..4] != b"RVN1" {
        return Err("envelope magic is not RVN1 (already-sealed LanDial only)".into());
    }
    Ok(bytes)
}

/// Forward an already-sealed RavenEnvelopeV1 over LanDial. Lab-only. Not WAN.
pub fn lan_dial_already_sealed(
    data_dir: &Path,
    lan_dial: &str,
    expected_pub_hex: &str,
    envelope: &[u8],
) -> Result<Vec<Vec<u8>>, String> {
    if Envelope::unpack(envelope).is_none() || envelope.len() < 4 || &envelope[..4] != b"RVN1" {
        return Err("not a packed RavenEnvelopeV1 (already-sealed LanDial only)".into());
    }
    ipc_carrier_dial(
        data_dir,
        DialCarrier::Lan,
        lan_dial,
        expected_pub_hex,
        &[envelope.to_vec()],
    )
}

/// `ash lab import-peer-cert`: Test A lab only (debug + `RAVEN_LAB_TEST_A=1`).
/// The live LAN path learns certs from RLB1 on the socket instead.
pub fn import_peer_device_cert(
    data_dir: &Path,
    peer_pub_hex: &str,
    cert_json_path: &Path,
) -> Result<(), String> {
    if !raven_core::pair_init::lab_test_a_enabled() {
        return Err(
            "lab import-peer-cert requires a debug build with RAVEN_LAB_TEST_A=1 \
             (live LAN pairing learns the peer cert from RLB1)"
                .into(),
        );
    }
    let peer = parse_pub_hex(peer_pub_hex)?;
    let raw = std::fs::read_to_string(cert_json_path).map_err(|e| e.to_string())?;
    let cert: DeviceCertificate =
        serde_json::from_str(&raw).map_err(|e| format!("cert json: {e}"))?;
    verify_imported_peer_cert(&cert, &peer, now_ms())?;
    cache_peer_cert(data_dir, &peer, &cert)?;
    println!(
        "{C_GREEN}peer cert cached{C_RESET} for {}",
        hex::encode(peer)
    );
    Ok(())
}

/// Signature + validity window + key binding for a hand-imported device cert.
fn verify_imported_peer_cert(
    cert: &DeviceCertificate,
    peer: &[u8; 32],
    now: u64,
) -> Result<(), String> {
    if cert.user_ed_pub != *peer && cert.device_ed_pub != *peer {
        return Err("cert does not match peer_pub_hex".into());
    }
    cert.verify(now)?;
    if cert.device_id.trim().is_empty() || cert.device_id != sanitize_terminal_line(&cert.device_id)
    {
        return Err("cert device_id is empty or contains control characters".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn already_sealed_decode_refuses_raw_payload() {
        use base64::Engine;
        let raw = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let err = decode_already_sealed_envelope_b64(&raw).unwrap_err();
        assert!(
            err.contains("already-sealed") || err.contains("RavenEnvelopeV1"),
            "{err}"
        );
    }

    fn lab_cert(user: &Identity, device_id: &str, not_after_ms: u64) -> DeviceCertificate {
        DeviceCertificate::issue(
            user,
            user.public_key_bytes(),
            [7u8; 32],
            device_id,
            0,
            not_after_ms,
            0,
        )
        .unwrap()
    }

    #[test]
    fn imported_peer_cert_must_verify_and_bind() {
        let peer = Identity::from_seed(&[0x31; 32]);
        let other = Identity::from_seed(&[0x32; 32]);
        let pk = peer.public_key_bytes();
        let now = now_ms();
        let good = lab_cert(&peer, PRIMARY_DEVICE_ID, now + 60_000);
        verify_imported_peer_cert(&good, &pk, now).unwrap();

        // Wrong key binding.
        assert!(verify_imported_peer_cert(&good, &other.public_key_bytes(), now).is_err());
        // Tampered device_id breaks the signature (previously accepted unverified).
        let mut forged = good.clone();
        forged.device_id = "ash-other".into();
        assert_eq!(
            verify_imported_peer_cert(&forged, &pk, now).unwrap_err(),
            "DEVICE_CERT_BAD_SIG"
        );
        // Expired.
        let expired = lab_cert(&peer, PRIMARY_DEVICE_ID, 1);
        assert_eq!(
            verify_imported_peer_cert(&expired, &pk, now).unwrap_err(),
            "DEVICE_CERT_EXPIRED"
        );
        // Control characters in a (validly signed) device_id.
        let ctl = lab_cert(&peer, "ash\nprimary", now + 60_000);
        assert!(verify_imported_peer_cert(&ctl, &pk, now).is_err());
    }

    #[test]
    fn peer_cert_cache_refuses_to_overwrite_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let peer = Identity::from_seed(&[0x33; 32]);
        let path = dir.path().join(PEER_CERT_CACHE);
        std::fs::write(&path, b"{not json").unwrap();
        let cert = lab_cert(&peer, PRIMARY_DEVICE_ID, now_ms() + 60_000);
        let err = cache_peer_cert(dir.path(), &peer.public_key_bytes(), &cert).unwrap_err();
        assert!(err.contains("corrupt"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"{not json");
    }

    #[test]
    fn peer_cert_cache_merges_existing_entries() {
        let dir = tempfile::tempdir().unwrap();
        let a = Identity::from_seed(&[0x34; 32]);
        let b = Identity::from_seed(&[0x35; 32]);
        let now = now_ms();
        cache_peer_cert(
            dir.path(),
            &a.public_key_bytes(),
            &lab_cert(&a, "d", now + 60_000),
        )
        .unwrap();
        cache_peer_cert(
            dir.path(),
            &b.public_key_bytes(),
            &lab_cert(&b, "d", now + 60_000),
        )
        .unwrap();
        let raw = std::fs::read_to_string(dir.path().join(PEER_CERT_CACHE)).unwrap();
        let map: HashMap<String, DeviceCertificate> = serde_json::from_str(&raw).unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn peer_cert_cache_import_respects_shared_cap() {
        let dir = tempfile::tempdir().unwrap();
        let a = Identity::from_seed(&[0x37; 32]);
        let now = now_ms();
        let cert = lab_cert(&a, "d", now + 60_000);
        let full: HashMap<String, DeviceCertificate> = (0..MAX_PEER_CERT_CACHE_KEYS)
            .map(|i| (format!("{i:064x}"), cert.clone()))
            .collect();
        let path = dir.path().join(PEER_CERT_CACHE);
        std::fs::write(&path, serde_json::to_string(&full).unwrap()).unwrap();
        let before = std::fs::read(&path).unwrap();
        let err = cache_peer_cert(dir.path(), &a.public_key_bytes(), &cert).unwrap_err();
        assert!(err.contains("full"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
        // Replacing an existing key does not grow the cache and is allowed.
        let mut existing = [0u8; 32];
        existing[31] = 1;
        cache_peer_cert(dir.path(), &existing, &cert).unwrap();
    }

    #[test]
    fn import_peer_cert_is_lab_gated() {
        if raven_core::pair_init::lab_test_a_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let peer = Identity::from_seed(&[0x36; 32]);
        let file = dir.path().join("cert.json");
        let cert = lab_cert(&peer, PRIMARY_DEVICE_ID, now_ms() + 60_000);
        std::fs::write(&file, serde_json::to_string(&cert).unwrap()).unwrap();
        let err = import_peer_device_cert(dir.path(), &hex::encode(peer.public_key_bytes()), &file)
            .unwrap_err();
        assert!(err.contains("RAVEN_LAB_TEST_A"), "{err}");
        assert!(!dir.path().join(PEER_CERT_CACHE).exists());
    }

    #[test]
    fn already_sealed_dial_refuses_unpacked_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let err = lan_dial_already_sealed(dir.path(), "127.0.0.1:9", &"ab".repeat(32), b"hello")
            .unwrap_err();
        assert!(
            err.contains("already-sealed") || err.contains("RavenEnvelopeV1"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod revocation_and_offline_tests {
    use super::*;
    use raven_core::device_revocation::DeviceRevocationV1;
    use raven_core::device_sync::RevocationRecord;
    use raven_core::device_sync::RevocationStore;

    const FAR_FUTURE: u64 = u64::MAX / 2;

    /// The lab file-backed stores. These tests must never reach the OS keychain,
    /// whatever environment `cargo test` runs in; set once and left set (a restore
    /// would race with the other tests, which use the same backends).
    fn lab_backends() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            for key in [
                "RAVEN_SESSION_BACKEND",
                "RAVEN_PREKEY_BACKEND",
                "RAVEN_CHAT_HISTORY_BACKEND",
            ] {
                unsafe { std::env::set_var(key, "locked-file") };
            }
        });
    }

    fn cert(user: &Identity, ed: [u8; 32], x: [u8; 32], device_id: &str) -> DeviceCertificate {
        DeviceCertificate::issue(user, ed, x, device_id, 0, FAR_FUTURE, 0).unwrap()
    }

    fn revoke_legacy(owner: &Identity, dir: &Path, device_id: &str) {
        let mut store = RevocationStore::load_checked(dir).unwrap();
        let rec = RevocationRecord::issue(owner, device_id, 1, 10, "test").unwrap();
        assert!(store.apply(rec).unwrap());
        store.save(dir).unwrap();
    }

    fn revoke_rvdr1(owner: &Identity, dir: &Path, victim: &DeviceCertificate) {
        let wire = DeviceRevocationV1 {
            identity_address: owner.address(),
            device_id: victim.device_id.as_bytes().to_vec(),
            device_ed_pub: victim.device_ed_pub,
            device_x_pub: victim.device_x_pub,
            device_cert_hash: raven_core::device_certificate_hash(victim).unwrap(),
            issuer_device_id: b"desk".to_vec(),
            issuer_seq: 1,
            revocation_id: [9u8; 16],
            reason_code: 1,
            created_at_ms: 10,
            signature: [0u8; 64],
        }
        .sign(owner)
        .unwrap()
        .encode()
        .unwrap();
        let mut store = RevocationStore::load_checked(dir).unwrap();
        assert!(store.apply_rvdr1(&owner.public_key_bytes(), &wire).unwrap());
        store.save(dir).unwrap();
    }

    #[test]
    fn peer_denial_is_lineage_aware_not_just_legacy_device_id() {
        let owner = Identity::from_seed(&[0x61; 32]);
        let dev = Identity::from_seed(&[0x62; 32]);
        let phone = cert(&owner, dev.public_key_bytes(), [3u8; 32], "phone");
        // Same keys re-certified under a new device_id (the RVDR1 §2.2 evasion).
        let recert = cert(&owner, dev.public_key_bytes(), [3u8; 32], "phone-2");
        let fresh = cert(
            &owner,
            Identity::from_seed(&[0x63; 32]).public_key_bytes(),
            [5u8; 32],
            "tablet",
        );

        let clean = tempfile::tempdir().unwrap();
        assert!(!peer_lineage_denied(clean.path(), &phone).unwrap());

        let legacy = tempfile::tempdir().unwrap();
        revoke_legacy(&owner, legacy.path(), "phone");
        assert!(peer_lineage_denied(legacy.path(), &phone).unwrap());
        assert!(!peer_lineage_denied(legacy.path(), &fresh).unwrap());

        let rvdr1 = tempfile::tempdir().unwrap();
        revoke_rvdr1(&owner, rvdr1.path(), &phone);
        assert!(peer_lineage_denied(rvdr1.path(), &phone).unwrap());
        assert!(
            peer_lineage_denied(rvdr1.path(), &recert).unwrap(),
            "reused keys under a new device_id stay denied"
        );
        assert!(!peer_lineage_denied(rvdr1.path(), &fresh).unwrap());
        // The old predicate (what ACK acceptance used) missed exactly this case.
        let store = RevocationStore::load_checked(rvdr1.path()).unwrap();
        assert!(!store.is_revoked(&hex::encode(recert.user_ed_pub), &recert.device_id));
    }

    #[test]
    fn peer_denial_refuses_a_corrupt_revocation_store() {
        let owner = Identity::from_seed(&[0x64; 32]);
        let phone = cert(&owner, [1u8; 32], [2u8; 32], "phone");
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("revocations.json"), b"{not json").unwrap();
        assert!(peer_lineage_denied(dir.path(), &phone).is_err());
    }

    /// An existing confirmed session skips the PairInit-time check, so the send
    /// path itself must refuse a revoked peer lineage (daemon parity), judged on
    /// the certificate the session is bound to.
    #[test]
    fn send_path_refuses_revoked_peer_lineage() {
        // Lab backend: this test must never touch the OS keychain.
        lab_backends();
        let local = Identity::from_seed(&[0x65; 32]);
        let peer = Identity::from_seed(&[0x66; 32]);
        let dev = Identity::from_seed(&[0x67; 32]);
        let peer_cert = cert(&peer, dev.public_key_bytes(), [7u8; 32], "phone");
        let recert = cert(&peer, dev.public_key_bytes(), [7u8; 32], "phone-2");
        let digest = |c: &DeviceCertificate| raven_core::device_certificate_hash(c).unwrap();

        let check = |dir: &Path, victim: &DeviceCertificate, bound: &DeviceCertificate| {
            let (local_cert, _registry) = ensure_local_device_cert(dir, &local).unwrap();
            let mut store = IndexedSessionStore::open(dir).unwrap();
            refuse_revoked_peer(dir, &mut store, &local_cert, victim, &digest(bound))
        };

        let clean = tempfile::tempdir().unwrap();
        check(clean.path(), &peer_cert, &peer_cert).expect("unrevoked peer is allowed");

        let legacy = tempfile::tempdir().unwrap();
        revoke_legacy(&peer, legacy.path(), "phone");
        let err = check(legacy.path(), &peer_cert, &peer_cert).unwrap_err();
        assert!(err.contains(raven_core::ATSAM_LINEAGE_REVOKED), "{err}");
        assert!(err.contains("peer device lineage is revoked"), "{err}");

        // A session established under `recert` is lineage-checked on `recert`.
        let rvdr1 = tempfile::tempdir().unwrap();
        revoke_rvdr1(&peer, rvdr1.path(), &peer_cert);
        let err = check(rvdr1.path(), &recert, &recert).unwrap_err();
        assert!(err.contains(raven_core::ATSAM_LINEAGE_REVOKED), "{err}");
    }

    /// The holder of a legacy-revoked device key re-certifies it under a new
    /// `device_id`: the legacy `(user, device_id)` record no longer matches, so
    /// only the session binding stops the send.
    #[test]
    fn send_path_refuses_recertified_cert_that_evades_a_legacy_revocation() {
        lab_backends();
        let local = Identity::from_seed(&[0x6a; 32]);
        let peer = Identity::from_seed(&[0x6b; 32]);
        let dev = Identity::from_seed(&[0x6c; 32]);
        let bound = cert(&peer, dev.public_key_bytes(), [7u8; 32], "phone");
        let recert = cert(&peer, dev.public_key_bytes(), [7u8; 32], "phone-2");
        let bound_digest = raven_core::device_certificate_hash(&bound).unwrap();

        let dir = tempfile::tempdir().unwrap();
        revoke_legacy(&peer, dir.path(), "phone");
        // The lineage check alone is evaded by the new device_id.
        assert!(peer_lineage_denied(dir.path(), &bound).unwrap());
        assert!(!peer_lineage_denied(dir.path(), &recert).unwrap());

        let (local_cert, _registry) = ensure_local_device_cert(dir.path(), &local).unwrap();
        let mut store = IndexedSessionStore::open(dir.path()).unwrap();
        let err = refuse_revoked_peer(dir.path(), &mut store, &local_cert, &recert, &bound_digest)
            .unwrap_err();
        assert!(err.starts_with(raven_core::ATSAM_SESSION_REQUIRED), "{err}");
        assert!(err.contains("not the one bound"), "{err}");
        assert!(err.contains("nothing was sent"), "{err}");
        // The cert the session is bound to is still refused as revoked.
        let err = refuse_revoked_peer(dir.path(), &mut store, &local_cert, &bound, &bound_digest)
            .unwrap_err();
        assert!(err.contains(raven_core::ATSAM_LINEAGE_REVOKED), "{err}");
    }

    #[test]
    fn session_bound_cert_check_is_exact_on_the_cert_hash() {
        let owner = Identity::from_seed(&[0x6d; 32]);
        let dev = Identity::from_seed(&[0x6e; 32]);
        let bound = cert(&owner, dev.public_key_bytes(), [3u8; 32], "phone");
        let digest = raven_core::device_certificate_hash(&bound).unwrap();
        require_session_bound_peer_cert(&bound, &digest).unwrap();
        // Same keys, new device_id: a different certificate.
        let recert = cert(&owner, dev.public_key_bytes(), [3u8; 32], "phone-2");
        assert!(require_session_bound_peer_cert(&recert, &digest).is_err());
        // An all-zero digest binds nothing.
        assert!(require_session_bound_peer_cert(&bound, &[0u8; 32]).is_err());
    }

    /// The recipient the outcome sentences name in these tests.
    fn bob_ctx(dir: &Path) -> SendCtx {
        SendCtx {
            name: "Bob".into(),
            selector: "--petname Bob".into(),
            dial: "127.0.0.1:9".into(),
            data_dir: Some(dir.to_path_buf()),
            ..SendCtx::default()
        }
    }

    #[test]
    fn unreachable_peer_without_a_session_says_nothing_was_queued() {
        lab_backends();
        let dir = tempfile::tempdir().unwrap();
        let local = Identity::from_seed(&[0x68; 32]);
        let peer = Identity::from_seed(&[0x69; 32]);
        let peer_pub = peer.public_key_bytes();
        assert!(offline_send_target(dir.path(), &peer_pub)
            .unwrap()
            .is_none());

        let (local_cert, registry) = ensure_local_device_cert(dir.path(), &local).unwrap();
        let routes = [DialRoute {
            carrier: DialCarrier::Lan,
            dial: "127.0.0.1:9".into(),
        }];
        let handoff = OutboxHandoff::new(dir.path(), &routes, peer_pub, None);
        let err = send_when_peer_unreachable(
            dir.path(),
            &local,
            &registry,
            &local_cert,
            "127.0.0.1:9",
            &hex::encode(peer_pub),
            &peer_pub,
            "hello",
            DialCarrier::Lan,
            "ipc LAN_DIAL: lan connect: cannot connect to 127.0.0.1:9 (127.0.0.1:9: Connection \
             refused (os error 61))"
                .into(),
            &bob_ctx(dir.path()),
            &handoff,
        )
        .unwrap_err();
        assert!(err.starts_with("NOT SENT: "), "{err}");
        assert!(err.contains("Bob"), "names the person: {err}");
        assert!(
            !dir.path()
                .join(raven_core::outbox::OUTBOX_ROUTES_FILE)
                .exists(),
            "nothing was queued, so nothing was handed to the outbox"
        );
        assert!(err.contains("Nothing was queued"), "{err}");
        assert!(
            err.contains("a first message needs Bob to be online"),
            "{err}"
        );
        assert!(err.contains("ash listen"), "gives the next step: {err}");
        assert!(
            err.contains("(technical: ipc LAN_DIAL: lan connect")
                && err.contains("Connection refused"),
            "the raw text stays at the end: {err}"
        );
        assert!(!err.contains("status delivered"), "{err}");
    }

    #[test]
    fn delivery_status_wording_distinguishes_queued_from_not_sent() {
        let ctx = bob_ctx(Path::new("/p"));
        let day = RetryNote {
            expires_at_ms: now_ms() + raven_core::ENVELOPE_VALIDITY_MS,
            background: false,
        };
        let queued = queued_text(
            &ctx,
            "ipc LAN_DIAL: lan dial timeout; mid=abababab…",
            "\"see you at 5\"",
            &day,
        );
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        assert!(queued.contains("queued locally"), "{queued}");
        assert!(queued.contains("\"see you at 5\""), "{queued}");
        assert!(queued.contains("abababab"), "{queued}");
        assert!(queued.contains("timeout"), "{queued}");
        // The retry promise carries the real window (the envelope validity, a
        // day), and says when nothing retries in the background.
        assert!(queued.contains("UTC (in about 24 h)"), "{queued}");
        assert!(queued.contains("expires"), "{queued}");
        assert!(queued.contains("NOT retried automatically"), "{queued}");
        let kept = queued_text(
            &ctx,
            "ipc LAN_DIAL: lan dial timeout; mid=abababab…",
            "\"see you at 5\"",
            &RetryNote {
                background: true,
                ..day
            },
        );
        assert!(kept.contains("raven-node keeps trying"), "{kept}");
        assert!(!kept.contains("NOT retried"), "{kept}");
        assert!(SUPERSEDED_SESSION.contains("marked failed"));
        assert!(EXPIRED_BEFORE_DELIVERY.contains("marked expired (not delivered)"));
        for why in [EXPIRED_BEFORE_DELIVERY, SUPERSEDED_SESSION] {
            assert!(why.contains("send it again"), "{why}");
        }
        let held = earlier_undelivered_text(
            &ctx,
            "ipc LAN_DIAL: lan dial timeout",
            "\"see you at 5\"",
            &day,
        );
        assert!(held.starts_with("NOT SENT"), "{held}");
        assert!(held.contains("not queued"), "{held}");
        assert!(!held.contains("queued locally"), "{held}");
        let unconfirmed = unconfirmed_text(
            &ctx,
            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid=abababab…",
            "",
            &day,
        );
        assert!(
            unconfirmed.starts_with("sent, delivery unconfirmed"),
            "{unconfirmed}"
        );
        assert!(unconfirmed.contains("Do not retype it"), "{unconfirmed}");
    }

    #[test]
    fn internet_hold_message_is_the_shared_gate_text() {
        assert!(INTERNET_DIRECT_HOLD.starts_with("INTERNET_DIRECT_HOLD:"));
        assert!(INTERNET_DIRECT_HOLD.contains("RAVEN_LAB_TEST_A=1"));
        assert!(INTERNET_DIRECT_HOLD.contains("localhost ≠ WAN Proven"));
    }
}

/// The whole `ash send` path against an in-process stand-in for the local daemon
/// and the peer (a UDS server that answers `LanDial` by driving the peer's real
/// `dispatch_frame`), with the lab file backends so nothing touches an OS
/// keystore. Black-box for the send logic: only the daemon boundary is faked.
#[cfg(all(test, unix))]
mod send_path_tests {
    use super::super::ipc_client::test_support::short_tempdir;
    use super::*;
    use base64::Engine;
    use raven_core::envelope::EnvType;
    use raven_core::ipc::{decode_request, encode_response};
    use raven_core::lan_dispatch::{dispatch_frame, encode_local_offer, local_bundle};
    use std::io::{Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
    use std::sync::Arc;

    const DOWN: u8 = 0;
    const UP: u8 = 1;
    const REFUSE_ALL: u8 = 2;

    const PEER_CLOSED_TEXT: &str = "LAN_DIAL_PEER_CLOSED: the peer closed the connection without \
        replying; the frames were sent, delivery is unconfirmed and a retry is safe";

    fn lab_backends() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            for key in [
                "RAVEN_SESSION_BACKEND",
                "RAVEN_PREKEY_BACKEND",
                "RAVEN_CHAT_HISTORY_BACKEND",
            ] {
                unsafe { std::env::set_var(key, "locked-file") };
            }
        });
    }

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    fn contacts_json(peer: &[u8; 32]) -> String {
        format!(
            r#"[{{"petname":"Peer","public_tag":"","alias":"","address":"","pub_hex":"{}","pinned":false,"lan_dial":""}}]"#,
            hex::encode(peer)
        )
    }

    /// Faults the fake daemon injects; each counts down as it fires.
    #[derive(Default)]
    struct Faults {
        /// Message frames the peer refuses (closes on) before it behaves again.
        refuse_messages: AtomicUsize,
        /// Dials that carry frames and that the peer's listener sheds at the
        /// handshake (none of the frames reaches it), before it accepts again.
        shed_frame_dials: AtomicUsize,
    }

    struct Rig {
        a: tempfile::TempDir,
        b: tempfile::TempDir,
        alice: Identity,
        bob: Identity,
        mode: Arc<AtomicU8>,
        faults: Arc<Faults>,
    }

    impl Rig {
        fn new(seed: u8) -> Self {
            lab_backends();
            let a = short_tempdir();
            let b = short_tempdir();
            let alice = Identity::from_seed(&[seed; 32]);
            let bob = Identity::from_seed(&[seed.wrapping_add(1); 32]);
            ensure_lab_local_material(a.path(), &alice).unwrap();
            ensure_lab_local_material(b.path(), &bob).unwrap();
            let a_bundle = local_bundle(a.path(), &alice).unwrap();
            let bob_pub = bob.public_key_bytes();
            let alice_pub = alice.public_key_bytes();
            std::fs::write(a.path().join("contacts.json"), contacts_json(&bob_pub)).unwrap();
            std::fs::write(b.path().join("contacts.json"), contacts_json(&alice_pub)).unwrap();
            let mode = Arc::new(AtomicU8::new(UP));
            let faults = Arc::new(Faults::default());

            let listener = UnixListener::bind(raven_core::default_socket_path(a.path())).unwrap();
            let (b_dir, bob2, m, f) = (
                b.path().to_path_buf(),
                Identity::from_seed(&[seed.wrapping_add(1); 32]),
                mode.clone(),
                faults.clone(),
            );
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { return };
                    serve_one(&mut stream, &b_dir, &bob2, &a_bundle, &alice_pub, &m, &f);
                }
            });
            Self {
                a,
                b,
                alice,
                bob,
                mode,
                faults,
            }
        }

        fn send(&self, text: &str) -> Result<(), String> {
            run_pair_init_and_send_on(
                self.a.path(),
                &self.alice,
                "127.0.0.1:9",
                &hex::encode(self.bob.public_key_bytes()),
                text,
                DialCarrier::Lan,
                &SendCtx {
                    name: "Peer".into(),
                    selector: "--petname Peer".into(),
                    dial: "127.0.0.1:9".into(),
                    data_dir: Some(self.a.path().to_path_buf()),
                    ..SendCtx::default()
                },
            )
        }

        fn set_mode(&self, mode: u8) {
            self.mode.store(mode, Ordering::SeqCst);
        }

        fn bob_inbox(&self) -> Vec<String> {
            let mut store = IndexedSessionStore::open(self.b.path()).unwrap();
            let mut texts: Vec<String> = store
                .list_endpoint_inbox()
                .unwrap()
                .into_iter()
                .map(|row| String::from_utf8_lossy(&row.plaintext).into_owned())
                .collect();
            texts.sort();
            texts
        }

        fn alice_sessions(&self) -> usize {
            IndexedSessionStore::open(self.a.path())
                .unwrap()
                .find_confirmed_sessions_for_peer_at(&self.bob.public_key_bytes(), now_ms())
                .unwrap()
                .len()
        }

        fn alice_pending(&self) -> usize {
            let store = IndexedSessionStore::open(self.a.path()).unwrap();
            store
                .pending_endpoint_outbound_for_recipient(Some(&self.bob.public_key_bytes()))
                .unwrap()
                .len()
        }

        fn alice_history(&self) -> Vec<(String, String)> {
            raven_core::ChatHistory::load(self.a.path())
                .unwrap()
                .entries
                .into_iter()
                .filter(|e| e.direction == "out")
                .map(|e| (e.body, e.delivery))
                .collect()
        }
    }

    /// One framed `IpcRequest` in, one framed `IpcResponse` out.
    fn serve_one(
        stream: &mut UnixStream,
        b_dir: &Path,
        bob: &Identity,
        a_bundle: &raven_core::LanBundle,
        alice_pub: &[u8; 32],
        mode: &AtomicU8,
        faults: &Faults,
    ) {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return;
        }
        let mut frame = len.to_vec();
        frame.resize(4 + u32::from_be_bytes(len) as usize, 0);
        if stream.read_exact(&mut frame[4..]).is_err() {
            return;
        }
        let error = |message: &str| IpcResponse::Error {
            v: IPC_VERSION,
            code: "LAN_DIAL".into(),
            message: message.into(),
        };
        let response = match decode_request(&frame) {
            Ok(IpcRequest::Ping { .. }) => IpcResponse::Pong { v: IPC_VERSION },
            Ok(IpcRequest::LanDial { frames_b64, .. }) => {
                let frames: Vec<Vec<u8>> = frames_b64
                    .iter()
                    .map(|s| base64::engine::general_purpose::STANDARD.decode(s).unwrap())
                    .collect();
                let mode = mode.load(Ordering::SeqCst);
                let shed = !frames.is_empty()
                    && faults
                        .shed_frame_dials
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                        .is_ok();
                if mode == DOWN {
                    error("lan connect: cannot connect to 127.0.0.1:9 (connection refused)")
                } else if shed {
                    // The listener hung up in the middle of the handshake: nothing
                    // of ours was processed.
                    error(
                        "peer closed the connection during the handshake (3 attempts); the \
                         peer may be at its connection limit or may not be a RAVEN node",
                    )
                } else {
                    let offer = encode_local_offer(b_dir, bob).unwrap();
                    let mut replies = vec![b64(&offer)];
                    let mut failure = None;
                    for f in &frames {
                        let is_message = Envelope::unpack(f)
                            .is_some_and(|e| e.env_type == EnvType::Message as u8);
                        let refused = mode == REFUSE_ALL
                            || (is_message
                                && faults
                                    .refuse_messages
                                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                                        n.checked_sub(1)
                                    })
                                    .is_ok());
                        if refused {
                            failure = Some(PEER_CLOSED_TEXT.to_string());
                            break;
                        }
                        match dispatch_frame(b_dir, bob, a_bundle, alice_pub, f) {
                            Ok(more) => replies.extend(more.iter().map(|r| b64(r))),
                            Err(_) => {
                                // The daemon closes on a dispatch error: the dialer
                                // sees a silent peer.
                                failure = Some(PEER_CLOSED_TEXT.to_string());
                                break;
                            }
                        }
                    }
                    match failure {
                        Some(text) => error(&text),
                        None => IpcResponse::LanDialResult {
                            v: IPC_VERSION,
                            frames_b64: replies,
                        },
                    }
                }
            }
            _ => error("unsupported request"),
        };
        let _ = stream.write_all(&encode_response(&response).unwrap());
    }

    fn mid_of(queued_text: &str) -> String {
        let after = queued_text.split("mid=").nth(1).expect("mid= in text");
        after
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect()
    }

    /// The headline regression. A queued message M1 is retried (and delivered) at
    /// the start of the next send; a *new* message that then fails before its own
    /// dial (here: a control character) reported "not delivered yet: message
    /// mid=<M1> is queued locally" because the retry had left its binding and
    /// staged flag behind. The new text was never staged: it must say so.
    #[test]
    fn a_new_message_that_fails_early_is_not_reported_as_queued_under_the_earlier_one() {
        let rig = Rig::new(0x80);
        rig.send("hello").expect("first contact delivers");
        rig.set_mode(DOWN);
        let queued = rig.send("queued one").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        let m1 = mid_of(&queued);
        rig.set_mode(UP);

        let err = rig.send("bad\u{1b}[31mtext").unwrap_err();
        assert!(err.starts_with("NOT SENT: "), "{err}");
        assert!(err.contains("Nothing was queued"), "{err}");
        assert!(!err.contains("queued locally"), "{err}");
        assert!(
            !err.contains(&m1),
            "must not name the earlier message: {err}"
        );
        assert_eq!(
            send_failure_line(&err),
            err,
            "and the CLI prints it as it is: no queued prefix, no second refusal prefix"
        );
        // The retry of M1 inside that send did deliver it, and nothing of the new
        // text was staged anywhere.
        assert_eq!(rig.bob_inbox(), vec!["hello", "queued one"]);
        assert_eq!(rig.alice_pending(), 0);
        assert!(
            rig.alice_history()
                .iter()
                .all(|(body, _)| !body.contains("bad")),
            "{:?}",
            rig.alice_history()
        );
        // The channel is healthy afterwards.
        rig.send("fine").unwrap();
        assert_eq!(rig.bob_inbox(), vec!["fine", "hello", "queued one"]);
    }

    /// A refused retry of a row on the *current* session is kept (the refusal may
    /// be transient), the error names the likely cause, and the new text is not
    /// queued.
    #[test]
    fn refused_retry_on_the_current_session_keeps_the_row_and_says_why() {
        let rig = Rig::new(0x82);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let queued = rig.send("held back").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        rig.set_mode(UP);
        rig.faults.refuse_messages.store(1, Ordering::SeqCst);

        let err = rig.send("second").unwrap_err();
        assert!(err.starts_with("NOT SENT: an earlier message"), "{err}");
        assert!(
            err.contains("\"held back\""),
            "shows the text, not an id: {err}"
        );
        assert!(err.contains("this message was not queued"), "{err}");
        assert!(err.contains("without saying why"), "{err}");
        assert!(err.contains("not have you in their contacts"), "{err}");
        assert_eq!(rig.alice_pending(), 1, "the earlier row stays queued");
        // Once the peer behaves, the next send delivers both, in order.
        rig.send("third").unwrap();
        assert_eq!(rig.bob_inbox(), vec!["held back", "hello", "third"]);
        assert_eq!(rig.alice_pending(), 0);
    }

    /// A row sealed under a session the reachable peer refuses, while a newer
    /// confirmed session exists, can never be delivered: it is abandoned (marked
    /// failed) instead of blocking every send until its envelope expires.
    #[test]
    fn row_on_a_superseded_session_that_the_peer_refuses_is_abandoned() {
        let rig = Rig::new(0x84);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let queued = rig.send("stuck on the old session").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        // A newer confirmed session with the same peer (a re-pair).
        std::thread::sleep(Duration::from_millis(20));
        let old_sessions = rig.alice_sessions();
        rig.set_mode(UP);
        {
            let bob_bundle = local_bundle(rig.b.path(), &rig.bob).unwrap();
            let (init, key) =
                create_initiator_pair_init(rig.a.path(), &rig.alice, &bob_bundle).unwrap();
            let a_bundle = local_bundle(rig.a.path(), &rig.alice).unwrap();
            let replies = dispatch_frame(
                rig.b.path(),
                &rig.bob,
                &a_bundle,
                &rig.alice.public_key_bytes(),
                &wrap_pair_init(&rig.alice, &init).unwrap(),
            )
            .unwrap();
            let response = first_pair_response(&replies).expect("PairResponse");
            IndexedSessionStore::open(rig.a.path())
                .unwrap()
                .confirm_verified_pair_response(&key, &init, &response, now_ms())
                .unwrap();
        }
        assert_eq!(rig.alice_sessions(), old_sessions + 1);
        // The peer refuses the old row's retry once (it lost that session), then
        // accepts the new message on the new session.
        rig.faults.refuse_messages.store(1, Ordering::SeqCst);
        rig.send("on the new session")
            .expect("not blocked by the stale row");
        assert_eq!(rig.alice_pending(), 0);
        let history = rig.alice_history();
        assert!(
            history
                .iter()
                .any(|(body, state)| body == "stuck on the old session" && state == "failed"),
            "{history:?}"
        );
        assert_eq!(rig.bob_inbox(), vec!["hello", "on the new session"]);
    }

    /// C (ash side): a queued message whose ACK already came back another way
    /// (raven-node's outbox, or the peer pushing it) is recorded as delivered
    /// by the next send and never dialled again, and the new message goes out
    /// behind it as usual.
    #[test]
    fn a_queued_message_already_acknowledged_is_not_dialled_again() {
        let rig = Rig::new(0x8a);
        rig.send("hello").unwrap();
        rig.set_mode(DOWN);
        let queued = rig.send("acked elsewhere").unwrap_err();
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        // Bob got the exact bytes some other way; his ACK reaches Alice's store
        // without touching the row (the F8 race).
        let row = IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .pending_endpoint_outbound()
            .unwrap()
            .remove(0);
        let a_bundle = local_bundle(rig.a.path(), &rig.alice).unwrap();
        let ack = dispatch_frame(
            rig.b.path(),
            &rig.bob,
            &a_bundle,
            &rig.alice.public_key_bytes(),
            &row.immutable_envelope_bytes,
        )
        .unwrap()
        .into_iter()
        .find(|f| Envelope::unpack(f).is_some())
        .unwrap();
        let key = IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .record_key_for_session_id(&row.session_id)
            .unwrap()
            .unwrap();
        let bob_cert = local_bundle(rig.b.path(), &rig.bob).unwrap().cert;
        IndexedSessionStore::open(rig.a.path())
            .unwrap()
            .accept_ack_envelope(&key, &ack, &bob_cert, false, now_ms())
            .unwrap();
        // Bob is still down: the next send must not dial (or wait on) the
        // delivered row, and queues its own text.
        let err = rig.send("next").unwrap_err();
        assert!(err.starts_with("not delivered yet"), "{err}");
        assert!(!err.contains("earlier message"), "{err}");
        assert!(rig
            .alice_history()
            .iter()
            .any(|(body, state)| body == "acked elsewhere" && state == "delivered"));
        assert_eq!(rig.alice_pending(), 1, "only the new message is queued");
    }

    /// D(b) (ash side): an earlier message the store refuses only because the
    /// clock stepped back (it is dated ahead of now) is kept, not given up as
    /// expired, and the next send says why.
    #[test]
    fn an_earlier_message_dated_ahead_of_the_clock_is_kept_not_expired() {
        let rig = Rig::new(0x8c);
        rig.send("hello").unwrap();
        // Stage a message sealed 10 minutes "in the future" (a fast clock that
        // was corrected since), its dial failing.
        let ahead = now_ms() + 10 * 60_000;
        let (cert, registry) = ensure_local_device_cert(rig.a.path(), &rig.alice).unwrap();
        let device =
            AuthorizedEndpointDevice::authorize(&cert, &rig.alice, &registry, ahead).unwrap();
        let bob = rig.bob.public_key_bytes();
        let mut store = IndexedSessionStore::open(rig.a.path()).unwrap();
        let key = store
            .find_confirmed_session_for_peer(&bob)
            .unwrap()
            .unwrap();
        let session = store.session_id_for_record_key(&key).unwrap();
        let end = store.session_expires_at(&key).unwrap();
        let a_dir = rig.a.path().to_path_buf();
        let _ = store.send_message_envelope(
            &key,
            "from a fast clock",
            &device,
            ahead,
            (ahead + 3_600_000).min(end),
            ahead,
            &mut rand::rngs::OsRng,
            &mut |d: &[u8; 32], bytes: &[u8]| {
                let env = Envelope::unpack(bytes).unwrap();
                raven_core::ensure_outbound_queued_history(
                    &a_dir,
                    &bob,
                    &session,
                    d,
                    &env.message_id,
                    ahead,
                    Some("from a fast clock"),
                )
                .unwrap();
                Err(())
            },
        );
        drop(store);
        assert_eq!(rig.alice_pending(), 1);
        let err = rig.send("now").unwrap_err();
        assert!(err.starts_with("NOT SENT: an earlier message"), "{err}");
        assert!(err.contains("ENDPOINT_NOT_CURRENTLY_VALID"), "{err}");
        assert!(err.contains("did the clock change"), "{err}");
        assert_eq!(rig.alice_pending(), 1, "kept, not abandoned");
        assert!(rig
            .alice_history()
            .iter()
            .any(|(body, state)| body == "from a fast clock" && state == "queued"));
    }

    /// First contact: the PairInit itself is refused silently (the stranger case,
    /// the peer logs "peer is not a local contact" and says nothing on the wire).
    /// The error must name the likely cause.
    #[test]
    fn silently_refused_pair_init_names_the_missing_contact() {
        let rig = Rig::new(0x86);
        rig.set_mode(REFUSE_ALL);
        let err = rig.send("hello").unwrap_err();
        assert!(
            err.starts_with("NOT SENT: Peer did not accept your first message"),
            "{err}"
        );
        assert!(
            err.contains("most often Peer has not added you as a contact yet"),
            "{err}"
        );
        assert!(err.contains("ask them to add you"), "{err}");
        assert!(err.contains("Nothing was queued"), "{err}");
        assert!(
            err.contains("PEER_CLOSED"),
            "the raw text stays at the end: {err}"
        );
        // The sentence itself must not repeat the daemon's "a retry is safe": a
        // retry does nothing until they add you. Only the raw tail keeps it.
        let sentence = err.split("(technical:").next().unwrap();
        assert!(!sentence.contains("retry is safe"), "{err}");
        assert!(!err.contains("status delivered"), "{err}");
        assert_eq!(rig.alice_sessions(), 0);
    }

    /// Concurrent `ash send`s from one profile used to interleave: two first
    /// contacts each ran PairInit and left two sessions (the pair then stayed
    /// wedged), and a burst fought over the single outstanding-message slot, so
    /// some of the texts were lost. Serialised per peer, every send succeeds on
    /// the one session the first of them created.
    #[test]
    fn concurrent_first_contact_sends_share_one_session_and_all_deliver() {
        let rig = Arc::new(Rig::new(0x88));
        const N: usize = 6;
        let barrier = Arc::new(std::sync::Barrier::new(N));
        let handles: Vec<_> = (0..N)
            .map(|i| {
                let (rig, barrier) = (rig.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    rig.send(&format!("burst {i}"))
                })
            })
            .collect();
        let results: Vec<Result<(), String>> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();
        for (i, r) in results.iter().enumerate() {
            assert!(r.is_ok(), "send {i}: {r:?}");
        }
        assert_eq!(rig.alice_sessions(), 1, "exactly one PairInit may have won");
        let expected: Vec<String> = {
            let mut v: Vec<String> = (0..N).map(|i| format!("burst {i}")).collect();
            v.sort();
            v
        };
        assert_eq!(rig.bob_inbox(), expected);
        assert_eq!(rig.alice_pending(), 0);
    }

    /// A burst of concurrent sends overflows the peer's per-source handshake cap
    /// and the listener hangs up *during the handshake*: none of our frames got
    /// through, so the PairInit dial and the message dial are repeated (like the
    /// RLB1 probe) instead of reporting a failed dial or leaving the text queued.
    #[test]
    fn pair_init_and_message_dials_shed_at_the_handshake_are_retried() {
        let rig = Rig::new(0x8a);
        // First contact: the PairInit dial is shed once, then goes through.
        rig.faults.shed_frame_dials.store(1, Ordering::SeqCst);
        rig.send("hello")
            .expect("a shed PairInit dial is retried, not reported");
        assert_eq!(rig.faults.shed_frame_dials.load(Ordering::SeqCst), 0);
        assert_eq!(rig.alice_sessions(), 1, "one PairInit, not one per attempt");
        // The message dial is shed twice, then goes through.
        rig.faults.shed_frame_dials.store(2, Ordering::SeqCst);
        rig.send("second")
            .expect("a shed message dial is retried, not queued");
        assert_eq!(rig.faults.shed_frame_dials.load(Ordering::SeqCst), 0);
        assert_eq!(rig.alice_pending(), 0, "delivered, not left queued");
        assert_eq!(rig.bob_inbox(), vec!["hello", "second"]);
        assert!(
            rig.alice_history()
                .iter()
                .all(|(_, state)| state != "failed"),
            "{:?}",
            rig.alice_history()
        );
    }

    #[test]
    fn rlb1_probe_retries_only_while_the_peer_sheds_load() {
        let shed = "ipc LAN_DIAL: peer closed the connection during the handshake (3 attempts); \
                    the peer may be at its connection limit";
        // Overflow of a burst: shed twice, then through.
        let mut calls = 0;
        let mut slept = Vec::new();
        let got = retry_while_peer_sheds_load(
            5,
            Duration::from_millis(100),
            |d| slept.push(d),
            || {
                calls += 1;
                if calls < 3 {
                    Err(shed.to_string())
                } else {
                    Ok(calls)
                }
            },
        );
        assert_eq!(got, Ok(3));
        assert_eq!(slept.len(), 2);
        assert!(slept[0] >= Duration::from_millis(100) && slept[0] <= Duration::from_millis(150));
        assert!(slept[1] >= Duration::from_millis(200) && slept[1] <= Duration::from_millis(300));
        // A peer that keeps shedding is given up on after the last attempt, unchanged.
        let mut calls = 0;
        let err = retry_while_peer_sheds_load(
            3,
            Duration::ZERO,
            |_| {},
            || {
                calls += 1;
                Err::<(), _>(shed.to_string())
            },
        )
        .unwrap_err();
        assert_eq!((calls, err.as_str()), (3, shed));
        // Anything else (peer down, bad bundle) is not retried: one attempt.
        for other in [
            "ipc LAN_DIAL: lan connect: cannot connect (Connection refused)",
            "peer did not return an RLB1 bundle",
        ] {
            let mut calls = 0;
            let err = retry_while_peer_sheds_load(
                5,
                Duration::ZERO,
                |_| {},
                || {
                    calls += 1;
                    Err::<(), _>(other.to_string())
                },
            )
            .unwrap_err();
            assert_eq!((calls, err.as_str()), (1, other));
        }
    }

    #[test]
    fn peer_send_lock_is_per_peer_and_times_out_with_a_clear_message() {
        let dir = tempfile::tempdir().unwrap();
        let (p1, p2) = ([1u8; 32], [2u8; 32]);
        let held = acquire_send_lock(dir.path(), &p1).unwrap();
        // Another peer is not held up.
        let other = acquire_send_lock_within(dir.path(), &p2, Duration::from_millis(50));
        assert!(other.is_ok());
        // The same peer waits, then gives up with an actionable message.
        let started = std::time::Instant::now();
        let err = match acquire_send_lock_within(dir.path(), &p1, Duration::from_millis(80)) {
            Ok(_) => panic!("lock must be held"),
            Err(e) => e,
        };
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(err.starts_with("NOT SENT, nothing queued"), "{err}");
        assert!(err.contains("another `ash send` to this peer"), "{err}");
        assert!(err.contains("raven-node's outbox"), "{err}");
        drop(held);
        // raven-node's outbox takes the very same lock (shared core type).
        let worker = PeerSendLock::acquire_within(dir.path(), &p1, Duration::ZERO).unwrap();
        assert!(acquire_send_lock_within(dir.path(), &p1, Duration::from_millis(80)).is_err());
        drop(worker);
        assert!(acquire_send_lock_within(dir.path(), &p1, Duration::from_millis(80)).is_ok());
        // The lock file is the inert `*.lock.sqlite` shape (first-install safe).
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            names
                .iter()
                .all(|n| n.starts_with(".send_") && n.contains(".lock.sqlite")),
            "{names:?}"
        );
    }

    /// K: a send that finds the per-peer lock taken (raven-node's outbox doing
    /// its store work, or another terminal) says so in one line and waits a
    /// bounded time; a free lock prints nothing.
    #[test]
    fn a_send_behind_a_held_lock_says_it_is_waiting_and_stays_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let peer = [7u8; 32];
        let mut lines = Vec::new();
        let free = acquire_send_lock_noting_within(
            dir.path(),
            &peer,
            "Bob",
            Duration::from_secs(1),
            &mut |l| lines.push(l.to_string()),
        );
        assert!(free.is_ok() && lines.is_empty(), "{lines:?}");
        drop(free);

        // Held briefly (the worker's store-only section): wait, then go on.
        let held = PeerSendLock::acquire_within(dir.path(), &peer, Duration::ZERO).unwrap();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(held);
        });
        let got = acquire_send_lock_noting_within(
            dir.path(),
            &peer,
            "Bob",
            Duration::from_secs(5),
            &mut |l| lines.push(l.to_string()),
        );
        releaser.join().unwrap();
        assert!(got.is_ok());
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].starts_with("waiting: another send to Bob"),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains("raven-node"), "{}", lines[0]);
        assert!(lines[0].contains("at most 5s"), "{}", lines[0]);
        drop(got);

        // Held throughout: the wait ends at its bound with the refusal.
        let _held = PeerSendLock::acquire_within(dir.path(), &peer, Duration::ZERO).unwrap();
        lines.clear();
        let started = std::time::Instant::now();
        let err = match acquire_send_lock_noting_within(
            dir.path(),
            &peer,
            "Bob",
            Duration::from_millis(150),
            &mut |l| lines.push(l.to_string()),
        ) {
            Ok(_) => panic!("lock must be held"),
            Err(e) => e,
        };
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(lines.len(), 1);
        assert!(err.starts_with("NOT SENT, nothing queued"), "{err}");
        // The production bound is stated in the line and is finite.
        assert!(send_lock_waiting_text("Bob", PEER_SEND_LOCK_WAIT).contains("at most 120s"));
    }

    #[test]
    fn send_failure_line_distinguishes_queued_unconfirmed_and_refused() {
        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        let day = RetryNote {
            expires_at_ms: now_ms() + raven_core::ENVELOPE_VALIDITY_MS,
            background: false,
        };
        let queued = queued_text(&ctx, "ipc: timed out; mid=07070707…", "", &day);
        assert_eq!(
            send_failure_line(&queued),
            queued,
            "queued is not a refusal"
        );
        let unconfirmed = unconfirmed_text(
            &ctx,
            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid=07070707…",
            "",
            &day,
        );
        assert_eq!(send_failure_line(&unconfirmed), unconfirmed);
        assert!(!unconfirmed.contains("send refused"), "{unconfirmed}");
        // An *earlier* message awaiting its ACK means this one was not queued.
        let earlier = earlier_unconfirmed_text(&ctx, "\"see you\"");
        assert!(earlier.starts_with("NOT SENT"), "{earlier}");
        assert!(earlier.contains("this message was not queued"), "{earlier}");
        assert_eq!(send_failure_line(&earlier), earlier);
        // Text no sentence covers keeps the old refusal form, untouched inside...
        assert_eq!(
            send_failure_line("ATSAM_SESSION_REQUIRED: not the one bound"),
            "send refused: ATSAM_SESSION_REQUIRED: not the one bound"
        );
        // ...a raw daemon error becomes a NOT SENT sentence.
        let raw = send_failure_line(
            "ipc LAN_DIAL: lan connect: cannot connect to 127.0.0.1:9 (127.0.0.1:9: Connection \
             refused (os error 61))",
        );
        assert!(raw.starts_with("NOT SENT: "), "{raw}");
        assert!(raw.contains("Connection refused"), "{raw}");
        assert_eq!(
            not_sent_nothing_queued(&ctx, "NOT SENT: earlier message"),
            "NOT SENT: earlier message"
        );
        let plain = not_sent_nothing_queued(&ctx, "bad payload");
        assert!(plain.starts_with("NOT SENT: "), "{plain}");
        assert!(plain.contains("(technical: bad payload)"), "{plain}");
    }
}
