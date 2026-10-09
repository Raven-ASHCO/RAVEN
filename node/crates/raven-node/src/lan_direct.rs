//! Direct LAN TCP: Noise XX + RLB1 + inbound PairInit/message/ACK dispatch.
//!
//! The dialer's signed bind comes first; the listener sends its own bind and
//! RLB1 only to a dialer whose bind names a local, unblocked contact, and
//! closes on anyone else before revealing its identity or prekey bundle.
//!
//! This path does not use `bridge_run` fanout. The listener loads the local
//! identity once at start; unauthenticated connections never touch the
//! identity lock / secret store, and all SQLite / file work for a connection
//! runs on the blocking pool. The pre-auth handshake has its own short
//! deadline, so an idle connection cannot sit on a slot for the session
//! lifetime.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use raven_core::identity::Identity;
use raven_core::lan_dispatch::{
    cache_peer_bundle, dispatch_frame, encode_local_offer, lan_peer_blocked, parse_peer_offer,
    remember_ephemeral_peer, rlb1_matches_noise_identity,
};
use raven_core::lan_noise::{
    build_initiator, build_responder, derive_noise_static, encode_bind, get_remote_static,
    handshake_read, handshake_write, into_transport, noise_static_public, transport_decrypt,
    transport_encrypt, verify_bind, NoiseTransport, MAX_TRANSPORT_PLAINTEXT,
};
use raven_core::load_identity_required;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::netutil::{
    self, AdmissionSlot, DialProgress, InboundLimits, ReplyWait, CONNECT_BUDGET, CONNECT_TIMEOUT,
    PEER_CLOSED, PRODUCTION_REPLY_WAITS,
};

/// One Noise message at most (snow rejects longer); checked before allocating.
const MAX_FRAME: usize = raven_core::lan_noise::MAX_NOISE_MSG;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// The whole dial, below the 45 s IPC cap so the caller gets this module's
/// precise error (or the replies already collected) instead of a bare timeout.
const DIAL_DEADLINE: Duration = Duration::from_secs(40);
const READ_TIMEOUT: &str = "lan read timeout";
const HANDSHAKE_TIMEOUT: &str = "lan handshake deadline exceeded";

async fn blocking<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| format!("lan_direct blocking join: {e}"))?
}

const PRODUCTION_LIMITS: InboundLimits = netutil::PRODUCTION_INBOUND;

fn frame_budget_allows(frames_seen: &mut u32, max_frames: u32) -> bool {
    *frames_seen = frames_seen.saturating_add(1);
    *frames_seen <= max_frames
}

static LISTENER_UP: AtomicBool = AtomicBool::new(false);

pub fn listener_is_up() -> bool {
    LISTENER_UP.load(Ordering::Relaxed)
}

struct ListenerGuard;
impl Drop for ListenerGuard {
    fn drop(&mut self) {
        LISTENER_UP.store(false, Ordering::Relaxed);
    }
}

fn parse_pub_hex(s: &str) -> Result<[u8; 32], String> {
    let h = s.trim().to_lowercase();
    if h.len() != 32 * 2 {
        return Err("expected_pub_hex must be 64 hex chars".into());
    }
    let v = hex::decode(&h).map_err(|_| "expected_pub_hex invalid hex".to_string())?;
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

pub fn looks_like_lan_dial(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.contains(' ') || t.starts_with("rvn1") {
        return false;
    }
    let Some((host, port)) = t.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && port.parse::<u16>().ok().is_some_and(|p| p != 0)
}

async fn write_raw<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > MAX_FRAME {
        return Err("lan frame too large".into());
    }
    // One write per frame: a separate 4-byte prefix segment would wait on the
    // peer's delayed ACK before the body goes out.
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    framed.extend_from_slice(bytes);
    let write = async {
        stream
            .write_all(&framed)
            .await
            .map_err(|e| netutil::io_error_text(&e))?;
        stream
            .flush()
            .await
            .map_err(|e| netutil::io_error_text(&e))?;
        Ok::<(), String>(())
    };
    tokio::time::timeout(IO_TIMEOUT, write)
        .await
        .map_err(|_| "lan write timeout".to_string())?
}

/// One length-prefixed frame, with no deadline of its own (callers bound it).
async fn read_raw_untimed<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| netutil::io_error_text(&e))?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err("lan frame length".into());
    }
    let mut buf = vec![0u8; n];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| netutil::io_error_text(&e))?;
    Ok(buf)
}

async fn read_raw<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    tokio::time::timeout(IO_TIMEOUT, read_raw_untimed(stream))
        .await
        .map_err(|_| READ_TIMEOUT.to_string())?
}

async fn write_cipher<S: AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut NoiseTransport,
    plain: &[u8],
) -> Result<(), String> {
    if plain.len() > MAX_TRANSPORT_PLAINTEXT {
        return Err("lan payload exceeds Noise transport limit".into());
    }
    let ct = transport_encrypt(transport, plain).map_err(|e| e.to_string())?;
    write_raw(stream, &ct).await
}

async fn read_cipher<S: AsyncRead + Unpin>(
    stream: &mut S,
    transport: &mut NoiseTransport,
) -> Result<Vec<u8>, String> {
    let ct = read_raw(stream).await?;
    transport_decrypt(transport, &ct).map_err(|e| e.to_string())
}

/// Wait up to `wait` for the next reply frame and say what happened.
async fn read_reply<S: AsyncRead + Unpin>(
    stream: &mut S,
    transport: &mut NoiseTransport,
    wait: Duration,
) -> ReplyWait {
    let read = async {
        let ct = read_raw_untimed(stream).await?;
        transport_decrypt(transport, &ct).map_err(|e| e.to_string())
    };
    match tokio::time::timeout(wait, read).await {
        Ok(Ok(frame)) => ReplyWait::Frame(frame),
        Ok(Err(why)) => ReplyWait::Closed(why),
        Err(_) => ReplyWait::Idle,
    }
}

async fn initiator_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    expected: &[u8; 32],
) -> Result<NoiseTransport, String> {
    let secret = derive_noise_static(identity).map_err(|e| e.to_string())?;
    let local_pub = noise_static_public(&secret);
    let mut hs = build_initiator(&secret).map_err(|e| e.to_string())?;
    let m1 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
    write_raw(stream, &m1).await?;
    let m2 = read_raw(stream).await?;
    handshake_read(&mut hs, &m2).map_err(|e| e.to_string())?;
    let m3 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
    write_raw(stream, &m3).await?;
    let remote_static = get_remote_static(&hs).map_err(|e| e.to_string())?;
    let mut t = into_transport(hs).map_err(|e| e.to_string())?;
    write_cipher(stream, &mut t, &encode_bind(identity, &local_pub)).await?;
    // The responder answers only a dialer whose bind names one of its contacts;
    // anyone else sees the connection close here, before any identity of the
    // responder (see `responder_handshake`).
    let bind = read_cipher(stream, &mut t)
        .await
        .map_err(netutil::closed_before_peer_identity)?;
    verify_bind(&bind, &remote_static, Some(expected)).map_err(|e| e.to_string())?;
    Ok(t)
}

/// Responder: Noise XX, then the dialer's signed bind, which always comes
/// first. Returns the dialer's bound Ed25519 key, the transport and our own
/// bind, which is **not** sent yet: the caller decides first whether the
/// dialer may learn who we are ([`raven_core::lan_dispatch::link_peer_admission`]).
async fn responder_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
) -> Result<([u8; 32], NoiseTransport, Vec<u8>), String> {
    let secret = derive_noise_static(identity).map_err(|e| e.to_string())?;
    let local_pub = noise_static_public(&secret);
    let mut hs = build_responder(&secret).map_err(|e| e.to_string())?;
    let m1 = read_raw(stream).await?;
    handshake_read(&mut hs, &m1).map_err(|e| e.to_string())?;
    let m2 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
    write_raw(stream, &m2).await?;
    let m3 = read_raw(stream).await?;
    handshake_read(&mut hs, &m3).map_err(|e| e.to_string())?;
    let remote_static = get_remote_static(&hs).map_err(|e| e.to_string())?;
    let mut t = into_transport(hs).map_err(|e| e.to_string())?;
    let bind = read_cipher(stream, &mut t).await?;
    let remote_ed = verify_bind(&bind, &remote_static, None).map_err(|e| e.to_string())?;
    Ok((remote_ed, t, encode_bind(identity, &local_pub).to_vec()))
}

/// [`responder_handshake`] that answers every dialer (scripted test peers).
#[cfg(test)]
async fn responder_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
) -> Result<([u8; 32], NoiseTransport), String> {
    let (remote_ed, mut t, ours) = responder_handshake(stream, identity).await?;
    write_cipher(stream, &mut t, &ours).await?;
    Ok((remote_ed, t))
}

async fn handle_inbound<S: AsyncRead + AsyncWrite + Unpin>(
    data_dir: PathBuf,
    identity: Arc<Identity>,
    mut stream: S,
    limits: InboundLimits,
    slot: &mut AdmissionSlot,
    // The dialer's address: an unverified contact is answered only from the
    // local network (`None` counts as remote).
    source: Option<std::net::IpAddr>,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    // Identity comes from the listener (loaded once): an unauthenticated peer
    // must not be able to trigger identity-lock / secret-store work. The
    // network half of the handshake has its own short deadline; the local
    // blocking work below deliberately does not (a slow disk is not the
    // peer's fault), so the contact check's time is added back to it.
    let mut deadline = tokio::time::Instant::now() + limits.handshake_deadline;
    let (remote_ed, mut transport, our_bind) = match tokio::time::timeout_at(
        deadline,
        responder_handshake(&mut stream, &identity),
    )
    .await
    {
        Ok(done) => done?,
        Err(_) => return Err(HANDSHAKE_TIMEOUT.into()),
    };
    // Contact gate before anything identifying leaves this node: a stranger
    // (or a blocked key) gets the connection closed and nothing else, not our
    // bind (Raven identity) and not our RLB1 (certificate + prekey bundle).
    // An unverified contact dialling from outside the local network is
    // treated exactly like a stranger (owner decision 2026-10-08).
    let gate_started = tokio::time::Instant::now();
    {
        let dd = data_dir.clone();
        blocking(move || {
            raven_core::lan_dispatch::link_admission(
                &dd,
                &remote_ed,
                raven_core::OutboxCarrier::Lan,
                source,
            )
            .map_err(String::from)
        })
        .await?;
    }
    deadline += gate_started.elapsed();
    let offer = tokio::time::timeout_at(deadline, async {
        write_cipher(&mut stream, &mut transport, &our_bind).await?;
        read_cipher(&mut stream, &mut transport).await
    })
    .await;
    let peer_offer = match offer {
        Ok(done) => done?,
        Err(_) => return Err(HANDSHAKE_TIMEOUT.into()),
    };
    let (peer, local, trusted) = {
        let dd = data_dir.clone();
        let id = identity.clone();
        blocking(move || {
            let peer = parse_peer_offer(&peer_offer)?;
            if !rlb1_matches_noise_identity(&peer, &remote_ed) {
                return Err("rlb1/noise identity mismatch".into());
            }
            if lan_peer_blocked(&dd, &peer, &remote_ed)? {
                return Err("blocked peer".into());
            }
            // Unknown inbound peers stay ephemeral until PairInit confirms trust.
            remember_ephemeral_peer(&dd, &peer)?;
            let local = encode_local_offer(&dd, &id)?;
            // Fail closed: an unreadable contact book trusts nobody.
            let trusted = raven_core::lan_dispatch::peer_is_trusted(&dd, &peer).unwrap_or(false);
            Ok((peer, local, trusted))
        })
        .await?
    };
    // A bound RLB1 offer proves only that the peer holds *a* key: anyone can
    // generate an identity and self-sign a bundle. So only a local contact (the
    // sole kind of peer this node accepts PairInit, messages and ACKs from) moves
    // out of the pre-auth caps into a slot a newcomer cannot displace. A stranger
    // keeps a displaceable pre-auth slot, so a handful of sources cannot fill the
    // listener with throw-away identities and lock real contacts out.
    if trusted {
        slot.authenticated();
        // A contact that reaches us is online now: retry what we owe it.
        crate::outbox::peer_seen(&remote_ed);
    }
    write_cipher(&mut stream, &mut transport, &local).await?;

    let mut frames_seen = 0u32;
    loop {
        if started.elapsed() > limits.lifetime {
            return Err("lan connection lifetime exceeded".into());
        }
        let frame = match read_cipher(&mut stream, &mut transport).await {
            Ok(f) => f,
            // The dialer is done (it closes as soon as it has its replies) or
            // went quiet: normal ends, not events worth a log line.
            Err(e) if e == PEER_CLOSED || e == READ_TIMEOUT => break,
            Err(e) => {
                netutil::log_inbound_failure("lan_direct inbound read", e);
                break;
            }
        };
        if !frame_budget_allows(&mut frames_seen, limits.max_frames) {
            return Err("lan frame budget exceeded".into());
        }
        let dd = data_dir.clone();
        let id = identity.clone();
        let peer_c = peer.clone();
        let noise_ed = remote_ed;
        let replies = tokio::task::spawn_blocking(move || {
            if lan_peer_blocked(&dd, &peer_c, &noise_ed)? {
                return Ok(None);
            }
            dispatch_frame(&dd, &id, &peer_c, &noise_ed, &frame).map(Some)
        })
        .await
        .map_err(|e| format!("dispatch join: {e}"))?
        .map_err(|e| format!("dispatch: {e}"))?
        .ok_or_else(|| "blocked peer".to_string())?;
        for (i, reply) in replies.iter().enumerate() {
            if let Err(e) = write_cipher(&mut stream, &mut transport, reply).await {
                // The sealed ACK of a message we just accepted never left: the
                // outbox pushes it to the sender later (transports design F8).
                crate::outbox::note_unsent_replies(&remote_ed, &replies[i..]);
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Blocking: loads the identity (the listener keeps it for its lifetime) and
/// readies durable LAN state.
fn preflight_lan_ready(data_dir: &Path) -> Result<Identity, String> {
    let identity = load_identity_required(data_dir).map_err(|e| e.to_string())?;
    raven_core::ensure_local_prekey(data_dir, &identity)?;
    let _ = raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let _ = raven_core::PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    raven_core::maintain_lan_durable_state(data_dir)?;
    Ok(identity)
}

/// Listen on `lan_listen` and dispatch inbound LAN-direct sessions.
pub async fn run_listener(data_dir: PathBuf, lan_listen: String) -> Result<(), String> {
    run_listener_with_limits(data_dir, lan_listen, PRODUCTION_LIMITS).await
}

async fn run_listener_with_limits(
    data_dir: PathBuf,
    lan_listen: String,
    limits: InboundLimits,
) -> Result<(), String> {
    // Each start-up step is retried on its own (a busy port must not re-run
    // the preflight, which takes the data-dir locks `ash` sends need), and a
    // failure never ends the listener or the daemon around it.
    let identity = Arc::new(
        netutil::retry_until_ok("lan_direct", || {
            let dd = data_dir.clone();
            async move {
                netutil::with_slow_notice(
                    "lan_direct",
                    "local state preflight (identity, sessions, outbound stage)",
                    blocking(move || preflight_lan_ready(&dd)),
                )
                .await
            }
        })
        .await,
    );
    let listener = netutil::retry_until_ok("lan_direct", || async {
        TcpListener::bind(&lan_listen)
            .await
            .map_err(|e| format!("lan_direct bind {lan_listen}: {e}"))
    })
    .await;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!("raven-node lan_direct: listen {local}");
    LISTENER_UP.store(true, Ordering::Relaxed);
    let _up = ListenerGuard;
    // Back on the network: whatever the outbox holds is worth a try now.
    crate::outbox::listener_up();
    match serve_listener(listener, data_dir, identity, limits).await {}
}

/// Accept and serve inbound sessions for as long as the task lives.
async fn serve_listener(
    listener: TcpListener,
    data_dir: PathBuf,
    identity: Arc<Identity>,
    limits: InboundLimits,
) -> Infallible {
    netutil::serve_connections(
        "lan_direct",
        || listener.accept(),
        limits,
        move |stream, mut slot| {
            let dd = data_dir.clone();
            let id = identity.clone();
            async move {
                let source = stream.peer_addr().ok().map(|a| a.ip());
                handle_inbound(dd, id, stream, limits, &mut slot, source).await
            }
        },
    )
    .await
}

/// How often the service prunes expired durable LAN state. Listener start-up
/// and each new PairInit prune too, but a node that keeps running and never
/// pairs again must still destroy an expired session's `K_root`, outbox
/// envelopes and inbox rows.
pub(crate) const DURABLE_PRUNE_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// A prune that keeps failing does so every interval: log it once an hour.
static PRUNE_LOG: netutil::LogLimiter = netutil::LogLimiter::new(Duration::from_secs(3600));

/// Run `pass` once at start and then every `interval`, for ever. Each pass
/// runs on the blocking pool and takes and releases its SQLite / keystore
/// locks itself, so nothing is held across an await. A failed or panicking
/// pass is logged (rate limited) and the next tick simply tries again.
async fn run_periodic<F>(name: &'static str, interval: Duration, pass: F) -> Infallible
where
    F: Fn() -> Result<(), String> + Send + Sync + 'static,
{
    let pass = Arc::new(pass);
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // The first tick completes at once: the pass at start.
        ticker.tick().await;
        let p = Arc::clone(&pass);
        let outcome = match tokio::task::spawn_blocking(move || p()).await {
            Ok(result) => result,
            Err(e) => Err(format!("pass ended abnormally: {e}")),
        };
        if let Err(e) = outcome {
            netutil::log_limited(&PRUNE_LOG, &format!("{name} failed"), e);
        }
    }
}

/// The service's periodic expiry prune (supervised in `main`).
pub async fn run_durable_prune(data_dir: PathBuf) -> Result<(), String> {
    match run_periodic("durable_prune", DURABLE_PRUNE_INTERVAL, move || {
        raven_core::lan_dispatch::prune_expired_lan_durable_state(&data_dir)
    })
    .await {}
}

/// Send `frames` and collect the replies into `progress`. Ends as soon as
/// every frame that gets a reply has had it; a peer that closes without
/// replying is an error rather than an empty success.
async fn exchange_frames<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut NoiseTransport,
    frames: &[Vec<u8>],
    progress: &mut DialProgress,
) -> Result<(), String> {
    progress.stage = "sending frames";
    for frame in frames {
        write_cipher(stream, transport, frame).await?;
    }
    if frames.is_empty() {
        return Ok(());
    }
    progress.frames_sent = true;
    progress.collector.mark_frames_sent();
    progress.stage = "waiting for a reply";
    let wait = progress.collector.first_wait();
    let mut more = progress
        .collector
        .first(read_reply(stream, transport, wait).await)?;
    while more {
        let wait = progress.collector.idle_wait();
        more = progress
            .collector
            .next(read_reply(stream, transport, wait).await)?;
    }
    Ok(())
}

async fn dial_session(
    data_dir: &Path,
    lan_dial: &str,
    expected: &[u8; 32],
    frames: &[Vec<u8>],
    progress: &mut DialProgress,
) -> Result<(), String> {
    progress.stage = "loading the local identity";
    let (identity, local) = {
        let dd = data_dir.to_path_buf();
        blocking(move || {
            let identity = load_identity_required(&dd).map_err(|e| e.to_string())?;
            let local = encode_local_offer(&dd, &identity)?;
            Ok((identity, local))
        })
        .await?
    };
    progress.stage = "connecting and in the Noise handshake";
    let (mut stream, mut transport) = {
        let identity = &identity;
        netutil::with_handshake_retries(move || async move {
            let (mut stream, _addr) =
                netutil::connect_dial(lan_dial, CONNECT_TIMEOUT, CONNECT_BUDGET)
                    .await
                    .map_err(|e| format!("lan connect: {e}"))?;
            let transport = initiator_session(&mut stream, identity, expected).await?;
            Ok((stream, transport))
        })
        .await?
    };
    drop(identity);
    progress.stage = "exchanging RLB1 offers";
    write_cipher(&mut stream, &mut transport, &local).await?;
    let peer_offer = read_cipher(&mut stream, &mut transport).await?;
    let peer_offer = {
        let dd = data_dir.to_path_buf();
        let expected = *expected;
        blocking(move || {
            let peer = parse_peer_offer(&peer_offer)?;
            if peer.cert.device_ed_pub != expected && peer.cert.user_ed_pub != expected {
                return Err("rlb1 offer identity mismatch".into());
            }
            if lan_peer_blocked(&dd, &peer, &expected)? {
                return Err("blocked peer".into());
            }
            cache_peer_bundle(&dd, &peer)?;
            Ok(peer_offer)
        })
        .await?
    };
    progress.collector.begin(peer_offer, frames)?;
    exchange_frames(&mut stream, &mut transport, frames, progress).await
}

/// Dial `lan_dial` (`host:port`: an IP, a DNS / mDNS name, or `[v6%if]:port`),
/// complete Noise+RLB1, send `frames`, collect replies.
pub async fn dial(
    data_dir: &Path,
    lan_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    if !looks_like_lan_dial(lan_dial) {
        return Err(
            "lan_dial must be host:port (e.g. 192.168.1.20:7420 or mac-mini.local:7420)".into(),
        );
    }
    let expected = parse_pub_hex(expected_pub_hex)?;
    let mut progress = DialProgress::new("LAN", PRODUCTION_REPLY_WAITS);
    let outcome = tokio::time::timeout(
        DIAL_DEADLINE,
        dial_session(data_dir, lan_dial, &expected, frames, &mut progress),
    )
    .await;
    match outcome {
        Ok(Ok(())) => Ok(progress.collector.into_replies()),
        Ok(Err(e)) => Err(e),
        Err(_) => progress.on_deadline("lan", lan_dial, DIAL_DEADLINE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The source address the scripted dialers of these tests connect from.
    const LOOPBACK: Option<std::net::IpAddr> =
        Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    use crate::netutil::{Admission, ReplyWaits};
    use raven_core::envelope::{EnvType, Envelope};
    use tokio::net::TcpStream;

    /// The service prunes once at start and then every interval; a pass that
    /// fails or panics is only logged and the next tick runs again.
    #[tokio::test(start_paused = true)]
    async fn periodic_prune_runs_at_start_then_every_interval_despite_failures() {
        use std::sync::atomic::AtomicUsize;
        let passes = Arc::new(AtomicUsize::new(0));
        let p = Arc::clone(&passes);
        let task = tokio::spawn(run_periodic(
            "test_prune",
            DURABLE_PRUNE_INTERVAL,
            move || match p.fetch_add(1, Ordering::SeqCst) {
                0 => Err("store busy".into()),
                1 => panic!("prune bug (test)"),
                _ => Ok(()),
            },
        ));
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert_eq!(passes.load(Ordering::SeqCst), 1, "one pass at start");
        tokio::time::sleep(DURABLE_PRUNE_INTERVAL * 3).await;
        assert_eq!(passes.load(Ordering::SeqCst), 4);
        assert!(!task.is_finished());
        task.abort();
    }

    #[test]
    fn preflight_fails_without_identity() {
        let dir = tempfile::tempdir().unwrap();
        let err = preflight_lan_ready(dir.path())
            .err()
            .expect("preflight must fail without identity");
        assert!(!err.is_empty());
        assert!(!listener_is_up());
    }

    fn test_slot() -> AdmissionSlot {
        Admission::new(PRODUCTION_LIMITS)
            .try_admit("127.0.0.1".parse().unwrap())
            .expect("slot")
    }

    /// Regression: inbound connections used to call load_identity_required
    /// (exclusive SQLite lock + secret store, blocking) before the handshake.
    /// The listener's identity is now used; the data dir here has none at all.
    #[tokio::test]
    async fn inbound_handshake_uses_listener_identity_not_store() {
        let dir = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x51; 32]));
        let expected = responder.public_key_bytes();
        let data_dir = dir.path().to_path_buf();
        let initiator = Identity::from_seed(&[0x52; 32]);
        write_contacts(dir.path(), &[&initiator]);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut slot = test_slot();
            handle_inbound(
                data_dir,
                responder,
                stream,
                PRODUCTION_LIMITS,
                &mut slot,
                LOOPBACK,
            )
            .await
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut transport = initiator_session(&mut client, &initiator, &expected)
            .await
            .expect("Noise XX + bind with the listener's in-memory identity");
        write_cipher(&mut client, &mut transport, b"not-an-rlb1-offer")
            .await
            .unwrap();
        let err = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("inbound handler finishes")
            .unwrap()
            .unwrap_err();
        assert!(!err.is_empty());
    }

    /// Real prekeys need the documented lab backend (debug builds only), which
    /// the Linux CI job exports for the whole run. Elsewhere the test is skipped
    /// rather than risk a keystore prompt.
    fn lab_backend_available() -> bool {
        let lab = ["RAVEN_PREKEY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(debug_assertions) && lab) {
            eprintln!("skipped: needs a debug build and RAVEN_IDENTITY_BACKEND=locked-file");
            return false;
        }
        true
    }

    /// Admit from `ip` until the pre-auth cap says no; returns how many more
    /// pre-auth connections that source could still open.
    fn spare_preauth_slots(admission: &Arc<netutil::Admission>, ip: std::net::IpAddr) -> usize {
        let mut held = Vec::new();
        while let Some(s) = admission.try_admit(ip) {
            held.push(s);
        }
        held.len()
    }

    fn write_contacts(dir: &Path, contacts: &[&Identity]) {
        let rows: Vec<String> = contacts
            .iter()
            .map(|c| format!(r#"{{"pub_hex":"{}"}}"#, hex::encode(c.public_key_bytes())))
            .collect();
        std::fs::write(dir.join("contacts.json"), format!("[{}]", rows.join(","))).unwrap();
    }

    /// An RLB1 offer proves the peer holds *a* key, nothing more: anyone can
    /// generate an identity and self-sign a bundle. Only a local contact (the
    /// only peer whose PairInit / messages / ACKs are accepted) may therefore
    /// leave the pre-auth caps for a slot newcomers cannot displace. (A
    /// stranger never gets that far: see `stranger_learns_nothing_but_not_accepted`.)
    #[tokio::test]
    async fn only_a_local_contact_earns_a_protected_slot() {
        if !lab_backend_available() {
            return;
        }
        let ip: std::net::IpAddr = "10.9.8.7".parse().unwrap();
        let resp_dir = tempfile::tempdir().unwrap();
        let init_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x71; 32]));
        let initiator = Identity::from_seed(&[0x72; 32]);
        write_contacts(resp_dir.path(), &[&initiator]);
        let admission = Admission::new(PRODUCTION_LIMITS);
        let mut slot = admission.try_admit(ip).expect("slot");
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
        let server = tokio::spawn(async move {
            handle_inbound(
                data_dir,
                resp,
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
                LOOPBACK,
            )
            .await
        });
        let mut t = initiator_session(&mut client, &initiator, &responder.public_key_bytes())
            .await
            .expect("Noise XX + bind");
        let offer = encode_local_offer(init_dir.path(), &initiator).unwrap();
        write_cipher(&mut client, &mut t, &offer).await.unwrap();
        // The responder's own offer is written after it decided.
        let theirs = read_cipher(&mut client, &mut t).await.unwrap();
        assert!(parse_peer_offer(&theirs).is_ok(), "a contact gets our RLB1");
        assert_eq!(
            spare_preauth_slots(&admission, ip),
            PRODUCTION_LIMITS.max_handshaking_per_ip,
            "a contact no longer counts as pre-auth"
        );
        drop(client);
        tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("handler ends when the dialer hangs up")
            .unwrap()
            .unwrap();
    }

    /// F4: a dialer that completes Noise XX with a key that is not a local
    /// contact (or is blocked) gets the connection closed right after its own
    /// bind. It never receives a single transport frame: not our bind (Raven
    /// identity), not our RLB1 (certificate + prekey bundle). Its error is the
    /// fixed `LINK_NOT_ACCEPTED`, never retried; the responder logs a fixed,
    /// key-free reason.
    #[tokio::test]
    async fn stranger_learns_nothing_but_not_accepted() {
        let responder = Arc::new(Identity::from_seed(&[0x75; 32]));
        let stranger = Identity::from_seed(&[0x76; 32]);
        let other = Identity::from_seed(&[0x77; 32]);
        for case in [
            "no contacts.json",
            "other contact",
            "blocked contact",
            "corrupt book",
        ] {
            let resp_dir = tempfile::tempdir().unwrap();
            match case {
                "other contact" => write_contacts(resp_dir.path(), &[&other]),
                "blocked contact" => {
                    write_contacts(resp_dir.path(), &[&stranger]);
                    let mut blocks = raven_core::BlockList::default();
                    blocks.block(&hex::encode(stranger.public_key_bytes()));
                    blocks.save(resp_dir.path()).unwrap();
                }
                "corrupt book" => {
                    std::fs::write(resp_dir.path().join("contacts.json"), "{not json").unwrap()
                }
                _ => {}
            }
            let (mut client, server_side) = tokio::io::duplex(1 << 18);
            let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
            let server = tokio::spawn(async move {
                let mut slot = test_slot();
                handle_inbound(
                    data_dir,
                    resp,
                    server_side,
                    PRODUCTION_LIMITS,
                    &mut slot,
                    LOOPBACK,
                )
                .await
            });
            let err = initiator_session(&mut client, &stranger, &responder.public_key_bytes())
                .await
                .err()
                .unwrap_or_else(|| panic!("{case}: stranger must not get our bind"));
            assert_eq!(err, netutil::LINK_NOT_ACCEPTED, "{case}");
            let refusal = tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("handler ends")
                .unwrap()
                .unwrap_err();
            let want = if case == "blocked contact" {
                raven_core::lan_dispatch::LINK_REFUSED_BLOCKED
            } else {
                raven_core::lan_dispatch::LINK_REFUSED_NOT_CONTACT
            };
            assert_eq!(refusal, want, "{case}");
            assert!(!refusal.contains(&hex::encode(stranger.public_key_bytes())));
            // Nothing but the close follows the handshake.
            let mut rest = Vec::new();
            let n = client.read_to_end(&mut rest).await.unwrap_or(0);
            assert_eq!(n, 0, "{case}: no byte after the stranger's bind");
        }
    }

    /// Owner decision 2026-10-08: an unverified contact is answered on LAN
    /// direct only from a local-network address. From anywhere else (or an
    /// unknown source) it gets exactly the stranger's treatment: the link
    /// closes after its bind, before any byte of ours. A verified (pinned)
    /// contact is answered from anywhere.
    #[tokio::test]
    async fn an_unverified_contact_from_outside_the_local_network_is_a_stranger() {
        let responder = Arc::new(Identity::from_seed(&[0x7c; 32]));
        let dialer = Identity::from_seed(&[0x7d; 32]);
        let public: Option<std::net::IpAddr> = Some("203.0.113.9".parse().unwrap());
        let cgnat: Option<std::net::IpAddr> = Some("100.64.3.4".parse().unwrap());
        for (source, pinned, refused) in [
            (public, false, true),
            (cgnat, false, true),
            (None, false, true),
            (public, true, false),
        ] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(
                dir.path().join("contacts.json"),
                format!(
                    r#"[{{"pub_hex":"{}","pinned":{pinned}}}]"#,
                    hex::encode(dialer.public_key_bytes())
                ),
            )
            .unwrap();
            let (mut client, server_side) = tokio::io::duplex(1 << 18);
            let (data_dir, resp) = (dir.path().to_path_buf(), responder.clone());
            let server = tokio::spawn(async move {
                let mut slot = test_slot();
                handle_inbound(
                    data_dir,
                    resp,
                    server_side,
                    PRODUCTION_LIMITS,
                    &mut slot,
                    source,
                )
                .await
            });
            let got = initiator_session(&mut client, &dialer, &responder.public_key_bytes()).await;
            let case = format!("{source:?} pinned={pinned}");
            if refused {
                assert_eq!(
                    got.err().as_deref(),
                    Some(netutil::LINK_NOT_ACCEPTED),
                    "{case}"
                );
                let refusal = tokio::time::timeout(Duration::from_secs(10), server)
                    .await
                    .expect("handler ends")
                    .unwrap()
                    .unwrap_err();
                assert_eq!(
                    refusal,
                    raven_core::lan_dispatch::LINK_REFUSED_NOT_VERIFIED,
                    "{case}"
                );
                let mut rest = Vec::new();
                assert_eq!(
                    client.read_to_end(&mut rest).await.unwrap_or(0),
                    0,
                    "{case}"
                );
            } else {
                assert!(got.is_ok(), "{case}: {:?}", got.err());
                server.abort();
            }
        }
    }

    /// The dialer authenticates first, so a contact that dials a responder
    /// which has *it* as a contact still verifies the responder's bind.
    #[tokio::test]
    async fn contact_dialer_still_authenticates_the_responder() {
        let resp_dir = tempfile::tempdir().unwrap();
        let responder = Arc::new(Identity::from_seed(&[0x78; 32]));
        let dialer = Identity::from_seed(&[0x79; 32]);
        let mallory = Identity::from_seed(&[0x7a; 32]);
        write_contacts(resp_dir.path(), &[&dialer]);
        let (mut client, server_side) = tokio::io::duplex(1 << 18);
        let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
        let _server = tokio::spawn(async move {
            let mut slot = test_slot();
            handle_inbound(
                data_dir,
                resp,
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
                LOOPBACK,
            )
            .await
        });
        // Dialing the right listener but expecting someone else still fails on
        // the responder's (now disclosed) bind.
        let Err(err) = initiator_session(&mut client, &dialer, &mallory.public_key_bytes()).await
        else {
            panic!("wrong expected identity must fail");
        };
        assert_ne!(err, netutil::LINK_NOT_ACCEPTED, "{err}");
    }

    /// Regression: the pre-auth phase shared the 120 s session lifetime, so a
    /// connection that never sent anything held one of the 32 slots for two
    /// minutes. It now ends at the handshake deadline and frees its slot.
    #[tokio::test(start_paused = true)]
    async fn silent_connection_ends_at_handshake_deadline_and_frees_slot() {
        let dir = tempfile::tempdir().unwrap();
        let admission = Admission::new(PRODUCTION_LIMITS);
        let ip = "10.1.2.3".parse().unwrap();
        let mut slots = Vec::new();
        while let Some(s) = admission.try_admit(ip) {
            slots.push(s);
        }
        assert_eq!(slots.len(), PRODUCTION_LIMITS.max_handshaking_per_ip);
        let mut slot = slots.pop().unwrap();

        let (_silent_peer, server_side) = tokio::io::duplex(1024);
        let responder = Arc::new(Identity::from_seed(&[0x53; 32]));
        let started = tokio::time::Instant::now();
        let err = handle_inbound(
            dir.path().to_path_buf(),
            responder,
            server_side,
            PRODUCTION_LIMITS,
            &mut slot,
            LOOPBACK,
        )
        .await
        .unwrap_err();
        assert_eq!(err, HANDSHAKE_TIMEOUT);
        let waited = started.elapsed();
        assert!(waited >= PRODUCTION_LIMITS.handshake_deadline, "{waited:?}");
        assert!(waited < PRODUCTION_LIMITS.lifetime, "{waited:?}");

        // Dropping the finished handler's slot makes room for the next dial.
        assert!(admission.try_admit(ip).is_none(), "still full");
        drop(slot);
        assert!(admission.try_admit(ip).is_some(), "slot freed");
    }

    fn message_frame(id: u8) -> Vec<u8> {
        envelope_frame(EnvType::Message, id)
    }

    fn ack_frame(id: u8) -> Vec<u8> {
        envelope_frame(EnvType::Ack, id)
    }

    fn envelope_frame(kind: EnvType, id: u8) -> Vec<u8> {
        Envelope {
            env_type: kind as u8,
            flags: 0,
            message_id: [id; 16],
            routing_tag: [0x44; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at: u64::MAX / 2,
            hop_limit: 4,
            replication_budget: 1,
            anti_replay_nonce: [0x55; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![id; 8],
            // Parsed only (never verified) by the reply classifier.
            sender_authentication: vec![0u8; 64],
        }
        .pack()
    }

    /// Dialer side of a duplex pipe after the Noise handshake, plus the
    /// responder's transport for the scripted peer.
    async fn noise_pair() -> (
        tokio::io::DuplexStream,
        NoiseTransport,
        tokio::task::JoinHandle<(tokio::io::DuplexStream, NoiseTransport)>,
    ) {
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
        let bob = Identity::from_seed(&[0x62; 32]);
        let expected = bob.public_key_bytes();
        let peer = tokio::spawn(async move {
            let (_, t) = responder_session(&mut listener, &bob).await.unwrap();
            (listener, t)
        });
        let alice = Identity::from_seed(&[0x61; 32]);
        let t = initiator_session(&mut dialer, &alice, &expected)
            .await
            .unwrap();
        (dialer, t, peer)
    }

    const FAST: ReplyWaits = ReplyWaits {
        first: Duration::from_secs(60),
        idle: Duration::from_secs(60),
    };

    /// A dial returns the moment its terminal reply arrives, without sitting
    /// out the idle wait (the peer keeps the connection open).
    #[tokio::test]
    async fn dial_returns_as_soon_as_the_ack_arrives() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![message_frame(1)];
        let (mut conn, mut peer_t) = peer.await.unwrap();
        let ack = ack_frame(2);
        let ack_c = ack.clone();
        let server = tokio::spawn(async move {
            let got = read_cipher(&mut conn, &mut peer_t).await.unwrap();
            write_cipher(&mut conn, &mut peer_t, &ack_c).await.unwrap();
            // Stay connected, like a real peer does after replying.
            let _keep = (conn, peer_t);
            std::future::pending::<()>().await;
            got
        });
        let mut progress = DialProgress::new("LAN", FAST);
        progress
            .collector
            .begin(b"peer-offer".to_vec(), &frames)
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(20),
            exchange_frames(&mut dialer, &mut t, &frames, &mut progress),
        )
        .await
        .expect("must not wait for the idle timeout once the ACK is in")
        .unwrap();
        let replies = progress.collector.into_replies();
        assert_eq!(replies, vec![b"peer-offer".to_vec(), ack]);
        server.abort();
    }

    /// A peer that rejects the frame and hangs up used to yield a success
    /// holding only the RLB1 offer; it is now an explicit, retry-safe error.
    #[tokio::test]
    async fn peer_closing_without_a_reply_is_an_error() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![message_frame(3)];
        let (mut conn, mut peer_t) = peer.await.unwrap();
        let server = tokio::spawn(async move {
            let _ = read_cipher(&mut conn, &mut peer_t).await;
            drop(conn);
        });
        let mut progress = DialProgress::new("LAN", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let err = exchange_frames(&mut dialer, &mut t, &frames, &mut progress)
            .await
            .unwrap_err();
        assert!(err.starts_with("LAN_DIAL_PEER_CLOSED"), "{err}");
        assert!(err.contains("frames were sent"), "{err}");
        server.await.unwrap();
    }

    /// No reply within the first-reply wait is not an error: the caller sees
    /// only the offer and maps it to "waiting for ACK".
    #[tokio::test(start_paused = true)]
    async fn silent_peer_yields_offer_only() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![message_frame(4)];
        let (conn, peer_t) = peer.await.unwrap();
        let mut progress = DialProgress::new("LAN", PRODUCTION_REPLY_WAITS);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        exchange_frames(&mut dialer, &mut t, &frames, &mut progress)
            .await
            .unwrap();
        assert_eq!(progress.collector.into_replies(), vec![b"offer".to_vec()]);
        drop((conn, peer_t));
    }

    /// Frames that get no reply (an ACK we forward, an RLB1 refresh) must not
    /// wait the patient first-reply time for nothing.
    #[tokio::test(start_paused = true)]
    async fn frames_without_replies_use_the_short_wait() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![ack_frame(5)];
        let (conn, peer_t) = peer.await.unwrap();
        let mut progress = DialProgress::new("LAN", PRODUCTION_REPLY_WAITS);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let started = tokio::time::Instant::now();
        exchange_frames(&mut dialer, &mut t, &frames, &mut progress)
            .await
            .unwrap();
        assert!(started.elapsed() < PRODUCTION_REPLY_WAITS.first);
        drop((conn, peer_t));
    }

    /// A peer that streams frames cannot grow the reply buffer past one IPC
    /// response, and the error says the frames were delivered.
    #[tokio::test]
    async fn reply_flood_hits_the_budget() {
        let (mut dialer, mut t, peer) = noise_pair().await;
        let frames = vec![message_frame(6)];
        let (mut conn, mut peer_t) = peer.await.unwrap();
        let server = tokio::spawn(async move {
            let _ = read_cipher(&mut conn, &mut peer_t).await;
            for _ in 0..200 {
                if write_cipher(&mut conn, &mut peer_t, b"not-terminal")
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let mut progress = DialProgress::new("LAN", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let err = exchange_frames(&mut dialer, &mut t, &frames, &mut progress)
            .await
            .unwrap_err();
        assert!(err.starts_with("LAN_DIAL_REPLY_OVERFLOW"), "{err}");
        assert!(err.ends_with("(frames were sent)"), "{err}");
        drop(dialer);
        server.abort();
    }

    /// The overall deadline reports what was in flight; once the frames are
    /// written the replies collected so far are the answer.
    #[test]
    fn deadline_reports_stage_or_returns_collected_replies() {
        let mut p = DialProgress::new("LAN", FAST);
        p.stage = "connecting";
        let err = p
            .on_deadline("lan", "bob.local:7420", DIAL_DEADLINE)
            .unwrap_err();
        assert!(err.contains("bob.local:7420"), "{err}");
        assert!(err.contains("while connecting"), "{err}");

        let mut p = DialProgress::new("LAN", FAST);
        p.stage = "sending frames";
        let err = p.on_deadline("lan", "x:1", DIAL_DEADLINE).unwrap_err();
        assert!(err.contains("may have been delivered"), "{err}");

        let mut p = DialProgress::new("LAN", FAST);
        p.collector.begin(b"offer".to_vec(), &[]).unwrap();
        p.frames_sent = true;
        assert_eq!(
            p.on_deadline("lan", "x:1", DIAL_DEADLINE).unwrap(),
            vec![b"offer".to_vec()]
        );
    }

    #[test]
    fn inbound_caps_are_bounded() {
        const {
            assert!(PRODUCTION_LIMITS.max_conns >= PRODUCTION_LIMITS.max_per_ip);
            assert!(PRODUCTION_LIMITS.max_per_ip >= PRODUCTION_LIMITS.max_handshaking_per_ip);
            assert!(PRODUCTION_LIMITS.max_handshaking_per_ip > 0);
            assert!(PRODUCTION_LIMITS.max_frames > 0);
        }
        assert!(PRODUCTION_LIMITS.lifetime.as_secs() >= 30);
        assert!(PRODUCTION_LIMITS.handshake_deadline < PRODUCTION_LIMITS.lifetime);
    }

    #[test]
    fn frame_budget_rejects_after_max() {
        let mut seen = 0u32;
        for _ in 0..3 {
            assert!(frame_budget_allows(&mut seen, 3));
        }
        assert!(!frame_budget_allows(&mut seen, 3));
        assert_eq!(seen, 4);
    }

    #[test]
    fn dial_string_accepts_names_and_scoped_v6() {
        assert!(looks_like_lan_dial("192.168.1.20:7420"));
        assert!(looks_like_lan_dial("mac-mini.local:7420"));
        assert!(looks_like_lan_dial("[fe80::1%en0]:7420"));
        assert!(!looks_like_lan_dial("192.168.1.20:0"));
        assert!(!looks_like_lan_dial("rvn1qabc"));
    }
}
