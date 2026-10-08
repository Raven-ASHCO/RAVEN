//! Indexed send: LanDial (Noise XX) or InternetDial (RIH1) + PairInit + ACK.
//!
//! Never uses `unsafe-demo-crypto` / public-key-derived `seal_message`.
//! Lab import files are optional leftovers; the live path uses RLB1 on the socket.
//! InternetDial is lab-gated and is not a WAN claim.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use raven_core::device_cert::{ensure_local_device_certificate, DeviceCertificate, DeviceRegistry};
use raven_core::device_sync::RevocationStore;
use raven_core::envelope::{EnvType, Envelope};
use raven_core::identity::Identity;
use raven_core::indexed_session_store::{
    AuthorizedEndpointDevice, EndpointAckAcceptance, EndpointOutboundKind, IndexedSessionRecordKey,
    IndexedSessionStore,
};
use raven_core::ipc::{ipc_endpoint, IpcRequest, IpcResponse, IPC_VERSION};
use raven_core::lan_dispatch::{
    cache_peer_bundle, create_initiator_pair_init, find_confirmed_peer_session,
    load_cached_peer_bundle, parse_peer_offer, wrap_pair_init,
};
use raven_core::pair_init_lan_oob::{classify_packed_envelope, PairInitOobClassify};
use raven_core::paths::PRIMARY_DEVICE_ID;
use raven_core::sanitize::sanitize_terminal_line;

use super::ext::{
    earlier_unconfirmed_text, earlier_undelivered_text, friendly_send_error, not_sent_text,
    queued_text, quoted_preview, recorded_locally_failed_text, unconfirmed_text, SendCtx,
};
use super::trace_delivery;

// Shared palette (NO_COLOR / non-TTY aware), clock and strict pub_hex parser.
use super::{now_ms, parse_pub_hex_strict as parse_pub_hex, C_BOLD, C_DIM, C_GREEN, C_RESET};

const DEVICE_ID: &str = PRIMARY_DEVICE_ID;
const PEER_CERT_CACHE: &str = "peer_device_certs.json";
/// Mirrors raven-core `lan_dispatch::MAX_TRUSTED_PEER_CERT_KEYS`: the lab
/// import must not grow the shared peer cert cache past the production cap.
const MAX_PEER_CERT_CACHE_KEYS: usize = 256;
/// How long a sealed message envelope stays valid (same window as the daemon's
/// `envelope_expires`). A message staged for retry can only be retried inside
/// it: afterwards the store refuses the retry as `EndpointNotCurrentlyValid`
/// and the message is marked failed.
const MESSAGE_VALIDITY_MS: u64 = 60 * 60 * 1000;
/// Longest one `ash send` waits for another `ash send` from this profile to the
/// same peer (see [`PeerSendLock`]).
const PEER_SEND_LOCK_WAIT: Duration = Duration::from_secs(120);

/// Cross-process lock serialising the stateful part of every `ash send` to one
/// peer from this profile: pairing (first contact), the retry of an earlier
/// queued message, staging the new one and its dial.
///
/// Without it, concurrent invocations interleave in ways the store can only
/// refuse. Two first-contact sends each ran PairInit and left two sessions the
/// peer then refused (the pair stayed wedged until the message expired), and a
/// burst of sends fought over the single outstanding-message slot, so some of
/// them lost their text. Under the lock the second sender finds the first one's
/// confirmed session and reuses it, and a burst goes out one after the other.
///
/// It is taken *after* the RLB1 probe, so waiting on an unreachable peer is not
/// serialised, and an offline send (stage only, no dial) holds it just briefly.
/// Held per peer, so sends to different peers never wait on each other.
struct PeerSendLock {
    _lock: raven_core::DataDirLock,
}

impl PeerSendLock {
    fn acquire(data_dir: &Path, peer_device: &[u8; 32]) -> Result<Self, String> {
        Self::acquire_within(data_dir, peer_device, PEER_SEND_LOCK_WAIT)
    }

    fn acquire_within(
        data_dir: &Path,
        peer_device: &[u8; 32],
        wait: Duration,
    ) -> Result<Self, String> {
        // Dot-prefixed `*.lock.sqlite`: the same inert lock-database shape the
        // first-install check already tolerates.
        let name = format!(".send_{}.lock.sqlite", hex::encode(peer_device));
        raven_core::DataDirLock::acquire_within(data_dir, &name, wait)
            .map(|_lock| Self { _lock })
            .map_err(|e| {
                if e.contains("database is locked") || e.contains("database is busy") {
                    format!(
                        "NOT SENT, nothing queued: another `ash send` to this peer from this \
                         profile was still running after {}s; try again shortly",
                        wait.as_secs()
                    )
                } else {
                    format!("NOT SENT, nothing queued: send lock: {e}")
                }
            })
    }
}

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
        match self {
            Self::Lan => "lan_dial",
            Self::Internet => "internet_dial",
        }
    }
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
    match super::ipc_client::ipc_request_retrying_connect(data_dir, &req, Duration::from_secs(50)) {
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
    retry_while_peer_sheds_load(PROBE_ATTEMPTS, PROBE_BACKOFF, std::thread::sleep, || {
        ipc_carrier_dial(data_dir, carrier, dial, expected_pub_hex, frames)
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

/// Lineage-aware peer denial, the same predicate the receive side uses
/// (`RevocationStore::denies_certificate`): legacy `(user, device_id)` records
/// plus RVDR1 claims covering the device id, either device key or the cert
/// hash. The bare `is_revoked` misses an RVDR1 lineage re-certified under a
/// new `device_id` with reused keys.
fn peer_lineage_denied(data_dir: &Path, peer_cert: &DeviceCertificate) -> Result<bool, String> {
    RevocationStore::load_checked(data_dir)?.denies_certificate(peer_cert)
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

/// PairInit + indexed send over one-connection LanDial or InternetDial, on a
/// named carrier. Internet is lab-only (not WAN). `ctx` names the recipient for
/// every line this prints (see `ext::SendCtx`): success lines go to stdout, and
/// every `Err` is already the user's sentence (queued / not sent / unconfirmed).
pub fn run_pair_init_and_send_on(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    text: &str,
    carrier: DialCarrier,
    ctx: &SendCtx,
) -> Result<(), String> {
    if !trace_delivery::live_pair_init_outbound_ready() {
        return Err(trace_delivery::production_gate_status().into());
    }
    if carrier == DialCarrier::Internet && !raven_core::internet_direct_live_enabled() {
        return Err(INTERNET_DIRECT_HOLD.into());
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

    let probe =
        ipc_carrier_dial_patient(data_dir, carrier, peer, peer_pub_hex, &[]).and_then(|replies| {
            replies
                .iter()
                .find_map(|f| parse_peer_offer(f).ok())
                .ok_or_else(|| "peer did not return an RLB1 bundle".to_string())
        });
    // From here on the send reads and writes per-peer session state: serialise it
    // with every other `ash send` to this peer (see `PeerSendLock`). After the
    // probe, so an unreachable peer's timeouts are not serialised.
    let _send_lock = PeerSendLock::acquire(data_dir, &peer_pub)?;
    let peer_bundle = match probe {
        Ok(bundle) => bundle,
        // Peer asleep / unreachable: the RLB1 probe is not needed to stage a
        // message into an already-confirmed session, so do that instead of
        // dropping the text.
        Err(probe_err) => {
            return send_when_peer_unreachable(
                data_dir,
                id,
                &registry,
                &local_cert,
                peer,
                peer_pub_hex,
                &peer_pub,
                text,
                carrier,
                probe_err,
                ctx,
            );
        }
    };
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
    )
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
    )
}

/// Minutes a staged message stays deliverable (its sealed envelope's validity):
/// the retry promise in the queued / unconfirmed sentences.
const MESSAGE_VALIDITY_MINUTES: u64 = MESSAGE_VALIDITY_MS / 60_000;

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
     failed; send it again if you still need it";

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
        abandon_undelivered_to_peer(data_dir, store, peer_cert)?;
    }
    raven_core::refuse_if_session_lineage_revoked(data_dir, local_cert, peer_cert).map_err(|e| {
        if peer_revoked {
            format!("{e}: peer device lineage is revoked; nothing was sent; any queued messages for it were abandoned")
        } else {
            e
        }
    })
}

fn abandon_undelivered_to_peer(
    data_dir: &Path,
    store: &mut IndexedSessionStore,
    peer_cert: &DeviceCertificate,
) -> Result<(), String> {
    let recipient = &peer_cert.device_ed_pub;
    let mut rows = store
        .pending_endpoint_outbound_for_recipient(Some(recipient))
        .map_err(|e| e.redacted_display())?;
    rows.extend(
        store
            .awaiting_ack_endpoint_outbound_for_recipient(Some(recipient))
            .map_err(|e| e.redacted_display())?,
    );
    for row in rows {
        if row.kind != EndpointOutboundKind::Message {
            continue;
        }
        let Some(key) = store
            .record_key_for_session_id(&row.session_id)
            .map_err(|e| e.redacted_display())?
        else {
            continue;
        };
        store
            .abandon_undelivered_outbound(&key, &row.object_digest)
            .map_err(|e| e.redacted_display())?;
        mark_outbound_failed(
            data_dir,
            recipient,
            &row.session_id,
            &row.object_digest,
            &row.message_id,
        )?;
    }
    Ok(())
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
    let expires = now.saturating_add(MESSAGE_VALIDITY_MS).min(session_expires);
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
                let preview = staged_preview(data_dir, &row.message_id);
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
                    )
                    .map_err(|e| finish_failure_text(ctx, &e, &preview))?;
                    ctx.say_earlier_delivered(&preview);
                } else {
                    return Err(earlier_unconfirmed_text(ctx, &preview));
                }
            }
            Err(raven_core::IndexedSessionStoreError::NotFound)
            | Err(raven_core::IndexedSessionStoreError::BindingConflict) => continue,
            Err(raven_core::IndexedSessionStoreError::EndpointNotCurrentlyValid) => {
                let preview = staged_preview(data_dir, &pending.message_id);
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
                ctx.say_earlier_failed(&preview, EXPIRED_BEFORE_DELIVERY);
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
                    return Err(detail);
                }
                if superseded_row_was_refused(peer_unreachable, &pending_key, record_key, &detail) {
                    // Sealed under a session the (reachable) peer refuses while a
                    // newer one exists: it can never be accepted, and left alone it
                    // would block every later send until its envelope expires.
                    let preview = staged_preview(data_dir, &pending.message_id);
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
                    ctx.say_earlier_failed(&preview, SUPERSEDED_SESSION);
                    continue;
                }
                return Err(earlier_undelivered_text(
                    ctx,
                    &detail,
                    &staged_preview(data_dir, &pending.message_id),
                    MESSAGE_VALIDITY_MINUTES,
                ));
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
                let preview = staged_preview(data_dir, &row.message_id);
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
                    )
                    .map_err(|e| finish_failure_text(ctx, &e, &preview))?;
                    ctx.say_earlier_delivered(&preview);
                } else {
                    return Err(earlier_unconfirmed_text(ctx, &preview));
                }
            }
            Err(raven_core::IndexedSessionStoreError::NotFound)
            | Err(raven_core::IndexedSessionStoreError::BindingConflict) => continue,
            Err(raven_core::IndexedSessionStoreError::EndpointNotCurrentlyValid) => {
                let preview = staged_preview(data_dir, &awaiting.message_id);
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
                ctx.say_earlier_failed(&preview, EXPIRED_BEFORE_DELIVERY);
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
                    return Err(detail);
                }
                if superseded_row_was_refused(peer_unreachable, &await_key, record_key, &detail) {
                    // See the retry loop above: same reasoning for a resend.
                    let preview = staged_preview(data_dir, &awaiting.message_id);
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
                    ctx.say_earlier_failed(&preview, SUPERSEDED_SESSION);
                    continue;
                }
                return Err(earlier_undelivered_text(
                    ctx,
                    &detail,
                    &staged_preview(data_dir, &awaiting.message_id),
                    MESSAGE_VALIDITY_MINUTES,
                ));
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
                    MESSAGE_VALIDITY_MINUTES,
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
        .map_err(|e| finish_failure_text(ctx, &e, &quoted_preview(text)))?;
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
            MESSAGE_VALIDITY_MINUTES,
        ));
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
    let accepted = store
        .accept_ack_envelope(
            record_key,
            ack,
            peer_cert,
            peer_lineage_denied(data_dir, peer_cert)?,
            now_ms(),
        )
        .map_err(|e| e.redacted_display())?;
    let acked = match accepted {
        EndpointAckAcceptance::Committed {
            acked_message_id, ..
        }
        | EndpointAckAcceptance::Duplicate {
            acked_message_id, ..
        } => acked_message_id,
    };
    if acked != *message_id {
        // A genuine ACK (the store matched it to an outstanding message of this
        // session) but for ANOTHER message: that one is delivered, this one is
        // still unconfirmed. It must never make this message read "delivered".
        let _ = raven_core::mark_lan_chat_history_delivery(
            data_dir,
            "out",
            &peer_cert.device_ed_pub,
            &acked,
            "delivered",
        );
        return Err(format!(
            "{ACK_FOR_ANOTHER_MESSAGE}: the acknowledgement that came back is for message \
             {}…, not for this one",
            hex::encode(&acked[..4])
        ));
    }
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

/// Start of the error [`finish_outbound_delivered`] returns when the ACK that came
/// back belongs to another outstanding message of the session.
const ACK_FOR_ANOTHER_MESSAGE: &str = "ACK_FOR_ANOTHER_MESSAGE";

/// How a failure of [`finish_outbound_delivered`] is told: an ACK for another
/// message leaves this one unconfirmed; anything else happened after the peer
/// acknowledged this message, so it must not be retyped.
fn finish_failure_text(ctx: &SendCtx, raw: &str, preview: &str) -> String {
    if raw.starts_with(ACK_FOR_ANOTHER_MESSAGE) {
        unconfirmed_text(ctx, raw, preview, MESSAGE_VALIDITY_MINUTES)
    } else {
        recorded_locally_failed_text(ctx, raw, preview, MESSAGE_VALIDITY_MINUTES)
    }
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
        )
        .unwrap_err();
        assert!(err.starts_with("NOT SENT: "), "{err}");
        assert!(err.contains("Bob"), "names the person: {err}");
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
        let queued = queued_text(
            &ctx,
            "ipc LAN_DIAL: lan dial timeout; mid=abababab…",
            "\"see you at 5\"",
            MESSAGE_VALIDITY_MINUTES,
        );
        assert!(queued.starts_with("not delivered yet"), "{queued}");
        assert!(queued.contains("queued locally"), "{queued}");
        assert!(queued.contains("\"see you at 5\""), "{queued}");
        assert!(queued.contains("abababab"), "{queued}");
        assert!(queued.contains("timeout"), "{queued}");
        // The retry promise carries the real window (the envelope validity), and
        // says nothing retries in the background.
        assert!(queued.contains("within 60 minutes"), "{queued}");
        assert!(queued.contains("expires"), "{queued}");
        assert!(queued.contains("NOT retried automatically"), "{queued}");
        for why in [EXPIRED_BEFORE_DELIVERY, SUPERSEDED_SESSION] {
            assert!(why.contains("marked failed"), "{why}");
            assert!(why.contains("send it again"), "{why}");
        }
        assert!(EXPIRED_BEFORE_DELIVERY.contains("expired"));
        let held = earlier_undelivered_text(
            &ctx,
            "ipc LAN_DIAL: lan dial timeout",
            "\"see you at 5\"",
            MESSAGE_VALIDITY_MINUTES,
        );
        assert!(held.starts_with("NOT SENT"), "{held}");
        assert!(held.contains("not queued"), "{held}");
        assert!(!held.contains("queued locally"), "{held}");
        let unconfirmed = unconfirmed_text(
            &ctx,
            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid=abababab…",
            "",
            MESSAGE_VALIDITY_MINUTES,
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
        let held = PeerSendLock::acquire(dir.path(), &p1).unwrap();
        // Another peer is not held up.
        let other = PeerSendLock::acquire_within(dir.path(), &p2, Duration::from_millis(50));
        assert!(other.is_ok());
        // The same peer waits, then gives up with an actionable message.
        let started = std::time::Instant::now();
        let err = match PeerSendLock::acquire_within(dir.path(), &p1, Duration::from_millis(80)) {
            Ok(_) => panic!("lock must be held"),
            Err(e) => e,
        };
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(err.starts_with("NOT SENT, nothing queued"), "{err}");
        assert!(err.contains("another `ash send` to this peer"), "{err}");
        drop(held);
        assert!(PeerSendLock::acquire_within(dir.path(), &p1, Duration::from_millis(80)).is_ok());
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

    #[test]
    fn send_failure_line_distinguishes_queued_unconfirmed_and_refused() {
        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        let queued = queued_text(
            &ctx,
            "ipc: timed out; mid=07070707…",
            "",
            MESSAGE_VALIDITY_MINUTES,
        );
        assert_eq!(
            send_failure_line(&queued),
            queued,
            "queued is not a refusal"
        );
        let unconfirmed = unconfirmed_text(
            &ctx,
            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid=07070707…",
            "",
            MESSAGE_VALIDITY_MINUTES,
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
