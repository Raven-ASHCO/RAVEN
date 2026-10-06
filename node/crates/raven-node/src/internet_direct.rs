//! InternetTransport live path: Noise XX + channel-bound RIH1 hello + frames.
//!
//! Every `u32_be`-framed message is a Noise message. After the XX handshake
//! each side sends an encrypted RIH1 hello signed over the handshake hash,
//! its role and its Noise static key (see `raven_core::internet`), so a
//! captured hello cannot authenticate another connection. The same indexed
//! PairInit / message / sealed-ACK dispatcher as LAN-direct then runs on
//! Noise transport frames (transport auth ≠ E2EE); RLB1 and PairInit never
//! travel in cleartext. Lab-gated: [`raven_core::internet_direct_live_enabled`].
//! Not WAN Proven.
//!
//! Mirrors `lan_direct`: the listener loads the identity once, unauthenticated
//! connections never touch the identity lock / secret store, the pre-auth
//! handshake has its own deadline, and all SQLite / file work runs on the
//! blocking pool.

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use raven_core::identity::Identity;
use raven_core::internet::{
    build_noise_initiator, build_noise_responder, frame as pack_inet_frame, pack_hello,
    unpack_verify_hello, HelloBinding, HelloRole, CAP_INTERNET, HELLO_WIRE_LEN, MAX_FRAME_BYTES,
    MAX_PAYLOAD_BYTES,
};
use raven_core::internet_direct_live_enabled;
use raven_core::lan_dispatch::{
    cache_peer_bundle, dispatch_frame, encode_local_offer, lan_peer_blocked, parse_peer_offer,
    remember_ephemeral_peer, rlb1_matches_noise_identity,
};
use raven_core::lan_noise::{
    derive_noise_static, get_remote_static, handshake_hash, handshake_read, handshake_write,
    into_transport, noise_static_public, transport_decrypt, transport_encrypt, NoiseTransport,
};
use raven_core::load_identity_required;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::netutil::{
    self, AdmissionSlot, DialProgress, InboundLimits, ReplyWait, CONNECT_BUDGET, CONNECT_TIMEOUT,
    PEER_CLOSED, PRODUCTION_REPLY_WAITS,
};

const IO_TIMEOUT: Duration = Duration::from_secs(30);
/// The whole dial, below the 45 s IPC cap (see `lan_direct`).
const DIAL_DEADLINE: Duration = Duration::from_secs(40);
const READ_TIMEOUT: &str = "internet frame read timeout";
const HANDSHAKE_TIMEOUT: &str = "internet handshake deadline exceeded";
const HOLD: &str = "INTERNET_DIRECT_HOLD: indexed InternetTransport is lab-only \
    (debug RAVEN_LAB_TEST_A=1); INTERNET_DIRECT_PRODUCTION_ENABLED=false; \
    localhost ≠ WAN Proven";

async fn blocking<T, F>(work: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| format!("internet_direct blocking join: {e}"))?
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

pub fn looks_like_internet_dial(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.contains(' ') || t.starts_with("rvn1") {
        return false;
    }
    let Some((host, port)) = t.rsplit_once(':') else {
        return false;
    };
    !host.is_empty() && port.parse::<u16>().ok().is_some_and(|p| p != 0)
}

fn require_live() -> Result<(), String> {
    if internet_direct_live_enabled() {
        Ok(())
    } else {
        Err(HOLD.into())
    }
}

async fn write_raw<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<(), String> {
    let framed = pack_inet_frame(bytes)?;
    tokio::time::timeout(IO_TIMEOUT, async {
        stream
            .write_all(&framed)
            .await
            .map_err(|e| netutil::io_error_text(&e))?;
        stream
            .flush()
            .await
            .map_err(|e| netutil::io_error_text(&e))?;
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "internet frame write timeout".to_string())?
}

/// One length-prefixed frame, with no deadline of its own (callers bound it).
async fn read_raw_untimed<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| netutil::io_error_text(&e))?;
    let n = u32::from_be_bytes(len_buf) as usize;
    // One Noise message at most: reject before allocating.
    if n == 0 || n > MAX_FRAME_BYTES {
        return Err("internet frame length".into());
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

async fn write_inet_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut NoiseTransport,
    payload: &[u8],
) -> Result<(), String> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err("internet payload exceeds Noise transport limit".into());
    }
    let ct = transport_encrypt(transport, payload).map_err(|e| e.to_string())?;
    write_raw(stream, &ct).await
}

async fn read_inet_frame<S: AsyncRead + Unpin>(
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

fn verify_peer_hello(raw: &[u8], peer: &HelloBinding) -> Result<[u8; 32], String> {
    let (caps, pk) = unpack_verify_hello(raw, peer)?;
    if caps & CAP_INTERNET == 0 {
        return Err("internet hello missing CAP_INTERNET".into());
    }
    Ok(pk)
}

/// Dialer side: XX, then exchange hellos bound to this handshake. Returns the
/// peer's authenticated Ed25519 key (must equal `expected`) and the transport.
async fn initiator_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
    expected: &[u8; 32],
) -> Result<([u8; 32], NoiseTransport), String> {
    let secret = derive_noise_static(identity).map_err(|e| e.to_string())?;
    let local_static = noise_static_public(&secret);
    let mut hs = build_noise_initiator(&secret).map_err(|e| e.to_string())?;
    drop(secret);
    let m1 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
    write_raw(stream, &m1).await?;
    let m2 = read_raw(stream).await?;
    handshake_read(&mut hs, &m2).map_err(|e| e.to_string())?;
    let m3 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
    write_raw(stream, &m3).await?;
    let remote_static = get_remote_static(&hs).map_err(|e| e.to_string())?;
    let hash = handshake_hash(&hs);
    let mut t = into_transport(hs).map_err(|e| e.to_string())?;
    let ours = HelloBinding {
        role: HelloRole::Initiator,
        handshake_hash: hash,
        noise_static_pub: local_static,
    };
    let hello = pack_hello(identity, CAP_INTERNET, &ours);
    if hello.len() != HELLO_WIRE_LEN {
        return Err("hello pack length".into());
    }
    write_inet_frame(stream, &mut t, &hello).await?;
    let theirs = HelloBinding {
        role: HelloRole::Responder,
        handshake_hash: hash,
        noise_static_pub: remote_static,
    };
    let pk = verify_peer_hello(&read_inet_frame(stream, &mut t).await?, &theirs)?;
    if pk != *expected {
        return Err("internet hello identity mismatch".into());
    }
    Ok((pk, t))
}

/// Listener side: XX, verify the dialer's hello against this handshake, then
/// answer with ours. Returns the dialer's authenticated Ed25519 key.
async fn responder_session<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    identity: &Identity,
) -> Result<([u8; 32], NoiseTransport), String> {
    let secret = derive_noise_static(identity).map_err(|e| e.to_string())?;
    let local_static = noise_static_public(&secret);
    let mut hs = build_noise_responder(&secret).map_err(|e| e.to_string())?;
    drop(secret);
    let m1 = read_raw(stream).await?;
    handshake_read(&mut hs, &m1).map_err(|e| e.to_string())?;
    let m2 = handshake_write(&mut hs, &[]).map_err(|e| e.to_string())?;
    write_raw(stream, &m2).await?;
    let m3 = read_raw(stream).await?;
    handshake_read(&mut hs, &m3).map_err(|e| e.to_string())?;
    let remote_static = get_remote_static(&hs).map_err(|e| e.to_string())?;
    let hash = handshake_hash(&hs);
    let mut t = into_transport(hs).map_err(|e| e.to_string())?;
    let theirs = HelloBinding {
        role: HelloRole::Initiator,
        handshake_hash: hash,
        noise_static_pub: remote_static,
    };
    let pk = verify_peer_hello(&read_inet_frame(stream, &mut t).await?, &theirs)?;
    let ours = HelloBinding {
        role: HelloRole::Responder,
        handshake_hash: hash,
        noise_static_pub: local_static,
    };
    write_inet_frame(stream, &mut t, &pack_hello(identity, CAP_INTERNET, &ours)).await?;
    Ok((pk, t))
}

/// Gate, then serve one inbound session.
async fn handle_inbound<S: AsyncRead + AsyncWrite + Unpin>(
    data_dir: PathBuf,
    identity: Arc<Identity>,
    stream: S,
    limits: InboundLimits,
    slot: &mut AdmissionSlot,
) -> Result<(), String> {
    require_live()?;
    serve_inbound(data_dir, identity, stream, limits, slot).await
}

async fn serve_inbound<S: AsyncRead + AsyncWrite + Unpin>(
    data_dir: PathBuf,
    identity: Arc<Identity>,
    mut stream: S,
    limits: InboundLimits,
    slot: &mut AdmissionSlot,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    // Identity comes from the listener (loaded once): an unauthenticated peer
    // must not be able to trigger identity-lock / secret-store work. The
    // network half of the handshake has its own short deadline; the local
    // blocking work below deliberately does not.
    let handshake = tokio::time::timeout(limits.handshake_deadline, async {
        let (remote_ed, mut transport) = responder_session(&mut stream, &identity).await?;
        let peer_offer = read_inet_frame(&mut stream, &mut transport).await?;
        Ok::<_, String>((remote_ed, transport, peer_offer))
    })
    .await;
    let (remote_ed, mut transport, peer_offer) = match handshake {
        Ok(done) => done?,
        Err(_) => return Err(HANDSHAKE_TIMEOUT.into()),
    };
    let (peer, local, trusted) = {
        let dd = data_dir.clone();
        let id = identity.clone();
        blocking(move || {
            let peer = parse_peer_offer(&peer_offer)?;
            if !rlb1_matches_noise_identity(&peer, &remote_ed) {
                return Err("rlb1/internet hello identity mismatch".into());
            }
            if lan_peer_blocked(&dd, &peer, &remote_ed)? {
                return Err("blocked peer".into());
            }
            remember_ephemeral_peer(&dd, &peer)?;
            let local = encode_local_offer(&dd, &id)?;
            // Fail closed: an unreadable contact book trusts nobody.
            let trusted = raven_core::lan_dispatch::peer_is_trusted(&dd, &peer).unwrap_or(false);
            Ok((peer, local, trusted))
        })
        .await?
    };
    // Only a local contact leaves the pre-auth caps for a slot a newcomer cannot
    // displace: a bound RLB1 offer proves possession of *a* key, and anyone can
    // self-sign a bundle (see `lan_direct::handle_inbound`).
    if trusted {
        slot.authenticated();
    }
    write_inet_frame(&mut stream, &mut transport, &local).await?;

    let mut frames_seen = 0u32;
    loop {
        if started.elapsed() > limits.lifetime {
            return Err("internet connection lifetime exceeded".into());
        }
        let frame = match read_inet_frame(&mut stream, &mut transport).await {
            Ok(f) => f,
            // The dialer is done (it closes as soon as it has its replies) or
            // went quiet: normal ends, not events worth a log line.
            Err(e) if e == PEER_CLOSED || e == READ_TIMEOUT => break,
            Err(e) => {
                netutil::log_inbound_failure("internet_direct inbound read", e);
                break;
            }
        };
        if !frame_budget_allows(&mut frames_seen, limits.max_frames) {
            return Err("internet frame budget exceeded".into());
        }
        let dd = data_dir.clone();
        let id = identity.clone();
        let peer_c = peer.clone();
        let hello_ed = remote_ed;
        let replies = tokio::task::spawn_blocking(move || {
            if lan_peer_blocked(&dd, &peer_c, &hello_ed)? {
                return Ok(None);
            }
            dispatch_frame(&dd, &id, &peer_c, &hello_ed, &frame).map(Some)
        })
        .await
        .map_err(|e| format!("dispatch join: {e}"))?
        .map_err(|e| format!("dispatch: {e}"))?
        .ok_or_else(|| "blocked peer".to_string())?;
        for reply in replies {
            write_inet_frame(&mut stream, &mut transport, &reply).await?;
        }
    }
    Ok(())
}

/// Blocking: loads the identity (the listener keeps it for its lifetime) and
/// readies durable state.
fn preflight_internet_ready(data_dir: &Path) -> Result<Identity, String> {
    require_live()?;
    let identity = load_identity_required(data_dir).map_err(|e| e.to_string())?;
    raven_core::ensure_local_prekey(data_dir, &identity)?;
    let _ = raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let _ = raven_core::PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    raven_core::maintain_lan_durable_state(data_dir)?;
    Ok(identity)
}

/// Listen on `internet_listen` and dispatch inbound InternetTransport sessions.
pub async fn run_listener(data_dir: PathBuf, internet_listen: String) -> Result<(), String> {
    run_listener_with_limits(data_dir, internet_listen, PRODUCTION_LIMITS).await
}

async fn run_listener_with_limits(
    data_dir: PathBuf,
    internet_listen: String,
    limits: InboundLimits,
) -> Result<(), String> {
    // Each start-up step is retried on its own (see `lan_direct`).
    let identity = Arc::new(
        netutil::retry_until_ok("internet_direct", || {
            let dd = data_dir.clone();
            async move {
                netutil::with_slow_notice(
                    "internet_direct",
                    "local state preflight (identity, sessions, outbound stage)",
                    blocking(move || preflight_internet_ready(&dd)),
                )
                .await
            }
        })
        .await,
    );
    let listener = netutil::retry_until_ok("internet_direct", || async {
        TcpListener::bind(&internet_listen)
            .await
            .map_err(|e| format!("internet_direct bind {internet_listen}: {e}"))
    })
    .await;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!("raven-node internet_direct: listen {local}");
    eprintln!("CLAIM: InternetTransport localhost/lab listen — dial≠WAN");
    LISTENER_UP.store(true, Ordering::Relaxed);
    let _up = ListenerGuard;
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
        "internet_direct",
        || listener.accept(),
        limits,
        move |stream, mut slot| {
            let dd = data_dir.clone();
            let id = identity.clone();
            async move { handle_inbound(dd, id, stream, limits, &mut slot).await }
        },
    )
    .await
}

/// Send `frames` and collect the replies into `progress` (see
/// `lan_direct::exchange_frames`).
async fn exchange_frames<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    transport: &mut NoiseTransport,
    frames: &[Vec<u8>],
    progress: &mut DialProgress,
) -> Result<(), String> {
    progress.stage = "sending frames";
    for frame in frames {
        write_inet_frame(stream, transport, frame).await?;
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
    internet_dial: &str,
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
    let (mut stream, (remote_ed, mut transport)) = {
        let identity = &identity;
        netutil::with_handshake_retries(move || async move {
            let (mut stream, _addr) =
                netutil::connect_dial(internet_dial, CONNECT_TIMEOUT, CONNECT_BUDGET)
                    .await
                    .map_err(|e| format!("internet connect: {e}"))?;
            let session = initiator_session(&mut stream, identity, expected).await?;
            Ok((stream, session))
        })
        .await?
    };
    drop(identity);
    progress.stage = "exchanging RLB1 offers";
    write_inet_frame(&mut stream, &mut transport, &local).await?;
    let peer_offer = read_inet_frame(&mut stream, &mut transport).await?;
    let peer_offer = {
        let dd = data_dir.to_path_buf();
        let expected = *expected;
        blocking(move || {
            let peer = parse_peer_offer(&peer_offer)?;
            if peer.cert.device_ed_pub != expected && peer.cert.user_ed_pub != expected {
                return Err("rlb1 offer identity mismatch".into());
            }
            if !rlb1_matches_noise_identity(&peer, &remote_ed) {
                return Err("rlb1/internet hello identity mismatch".into());
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

/// Dial `internet_dial` (`host:port`: an IP or a DNS name), complete
/// Noise+RIH1+RLB1, send `frames`, collect replies.
pub async fn dial(
    data_dir: &Path,
    internet_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    require_live()?;
    dial_unchecked(data_dir, internet_dial, expected_pub_hex, frames).await
}

async fn dial_unchecked(
    data_dir: &Path,
    internet_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    if !looks_like_internet_dial(internet_dial) {
        return Err(
            "internet_dial must be host:port (e.g. 127.0.0.1:7421 or relay.example.com:7421)"
                .into(),
        );
    }
    let expected = parse_pub_hex(expected_pub_hex)?;
    let mut progress = DialProgress::new("INTERNET", PRODUCTION_REPLY_WAITS);
    let outcome = tokio::time::timeout(
        DIAL_DEADLINE,
        dial_session(data_dir, internet_dial, &expected, frames, &mut progress),
    )
    .await;
    match outcome {
        Ok(Ok(())) => Ok(progress.collector.into_replies()),
        Ok(Err(e)) => Err(e),
        Err(_) => progress.on_deadline("internet", internet_dial, DIAL_DEADLINE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netutil::{Admission, ReplyWaits};
    use raven_core::envelope::{EnvType, Envelope};

    #[test]
    fn hold_without_lab_when_flag_false() {
        if raven_core::pair_init::lab_test_a_enabled() {
            return;
        }
        assert!(!internet_direct_live_enabled());
        assert_eq!(require_live().unwrap_err(), HOLD);
        assert!(!listener_is_up());
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
    fn dial_string_rejects_non_host_port() {
        assert!(looks_like_internet_dial("127.0.0.1:7421"));
        assert!(!looks_like_internet_dial("127.0.0.1:0"));
        assert!(!looks_like_internet_dial("rvn1qabc"));
        assert!(!looks_like_internet_dial(""));
    }

    fn alice() -> Identity {
        Identity::from_seed(&[0x11; 32])
    }
    fn bob() -> Identity {
        Identity::from_seed(&[0x22; 32])
    }
    fn mallory() -> Identity {
        Identity::from_seed(&[0x33; 32])
    }

    #[tokio::test]
    async fn noise_session_authenticates_both_sides_and_encrypts_frames() {
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
        let responder = tokio::spawn(async move {
            let (peer, mut t) = responder_session(&mut listener, &bob()).await.unwrap();
            let got = read_inet_frame(&mut listener, &mut t).await.unwrap();
            write_inet_frame(&mut listener, &mut t, b"pong")
                .await
                .unwrap();
            (peer, got)
        });
        let expected = bob().public_key_bytes();
        let (peer, mut t) = initiator_session(&mut dialer, &alice(), &expected)
            .await
            .unwrap();
        assert_eq!(peer, expected);
        write_inet_frame(&mut dialer, &mut t, b"RLB1 offer")
            .await
            .unwrap();
        assert_eq!(read_inet_frame(&mut dialer, &mut t).await.unwrap(), b"pong");
        let (responder_saw, got) = responder.await.unwrap();
        assert_eq!(responder_saw, alice().public_key_bytes());
        assert_eq!(got, b"RLB1 offer");
    }

    #[tokio::test]
    async fn dialer_rejects_unexpected_responder_identity() {
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 17);
        let responder = tokio::spawn(async move {
            let _ = responder_session(&mut listener, &mallory()).await;
        });
        let err = initiator_session(&mut dialer, &alice(), &bob().public_key_bytes())
            .await
            .unwrap_err();
        assert_eq!(err, "internet hello identity mismatch");
        drop(dialer);
        responder.await.unwrap();
    }

    /// Mallory completes XX with her own static key, then presents a hello
    /// signed by Alice for a different connection. Before the fix the hello
    /// only covered a self-chosen nonce, so the listener accepted it as Alice.
    #[tokio::test]
    async fn listener_rejects_hello_replayed_from_another_connection() {
        let (mut attacker, mut listener) = tokio::io::duplex(1 << 17);
        let responder =
            tokio::spawn(
                async move { responder_session(&mut listener, &bob()).await.map(|r| r.0) },
            );

        let m_secret = derive_noise_static(&mallory()).unwrap();
        let mut hs = build_noise_initiator(&m_secret).unwrap();
        write_raw(&mut attacker, &handshake_write(&mut hs, &[]).unwrap())
            .await
            .unwrap();
        let m2 = read_raw(&mut attacker).await.unwrap();
        handshake_read(&mut hs, &m2).unwrap();
        write_raw(&mut attacker, &handshake_write(&mut hs, &[]).unwrap())
            .await
            .unwrap();
        let mut t = into_transport(hs).unwrap();
        // Alice's genuine hello from some earlier Alice→Bob connection.
        let captured = pack_hello(
            &alice(),
            CAP_INTERNET,
            &HelloBinding {
                role: HelloRole::Initiator,
                handshake_hash: [0x5a; 32],
                noise_static_pub: noise_static_public(&derive_noise_static(&alice()).unwrap()),
            },
        );
        write_inet_frame(&mut attacker, &mut t, &captured)
            .await
            .unwrap();
        assert_eq!(responder.await.unwrap().unwrap_err(), "hello sig");
    }

    #[tokio::test]
    async fn legacy_cleartext_hello_fails_closed() {
        let (mut old_peer, mut listener) = tokio::io::duplex(1 << 12);
        let mut legacy = b"RIH1".to_vec();
        legacy.resize(116, 0);
        old_peer.write_all(&legacy).await.unwrap();
        let err = responder_session(&mut listener, &bob()).await.unwrap_err();
        assert_eq!(err, "internet frame length");
    }

    #[tokio::test]
    async fn oversized_frame_rejected_before_allocation() {
        let (mut peer, mut listener) = tokio::io::duplex(64);
        peer.write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_raw(&mut listener).await.unwrap_err(),
            "internet frame length"
        );
        let (mut a, _b, _, _) = raven_core::lan_noise::handshake_pair(&alice(), &bob()).unwrap();
        let (mut sink, _keep) = tokio::io::duplex(64);
        assert_eq!(
            write_inet_frame(&mut sink, &mut a, &vec![0u8; MAX_PAYLOAD_BYTES + 1])
                .await
                .unwrap_err(),
            "internet payload exceeds Noise transport limit"
        );
    }

    fn test_slot() -> AdmissionSlot {
        Admission::new(PRODUCTION_LIMITS)
            .try_admit("127.0.0.1".parse().unwrap())
            .expect("slot")
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

    const FAST: ReplyWaits = ReplyWaits {
        first: Duration::from_secs(60),
        idle: Duration::from_secs(60),
    };

    /// Dialer side of a duplex pipe after the full RIH1 session, plus the
    /// listener's side for a scripted peer.
    async fn session_pair() -> (
        tokio::io::DuplexStream,
        NoiseTransport,
        tokio::io::DuplexStream,
        NoiseTransport,
    ) {
        let (mut dialer, mut listener) = tokio::io::duplex(1 << 18);
        let expected = bob().public_key_bytes();
        let peer = tokio::spawn(async move {
            let (_, t) = responder_session(&mut listener, &bob()).await.unwrap();
            (listener, t)
        });
        let (_, t) = initiator_session(&mut dialer, &alice(), &expected)
            .await
            .unwrap();
        let (listener, peer_t) = peer.await.unwrap();
        (dialer, t, listener, peer_t)
    }

    /// Regression: a peer that kept streaming frames made `dial` buffer them
    /// without bound until the 45 s IPC timeout; it now stops at the shared
    /// one-IPC-response budget and says the frames were delivered.
    #[tokio::test]
    async fn dial_reply_flood_hits_the_budget() {
        let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
        let frames = vec![envelope_frame(EnvType::Message, 1)];
        let server = tokio::spawn(async move {
            let _ = read_inet_frame(&mut conn, &mut peer_t).await;
            for _ in 0..200 {
                if write_inet_frame(&mut conn, &mut peer_t, b"not-terminal")
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let mut progress = DialProgress::new("INTERNET", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let err = exchange_frames(&mut dialer, &mut t, &frames, &mut progress)
            .await
            .unwrap_err();
        assert!(err.starts_with("INTERNET_DIAL_REPLY_OVERFLOW"), "{err}");
        assert!(err.ends_with("(frames were sent)"), "{err}");
        drop(dialer);
        server.abort();
    }

    /// The oversized RLB1 offer itself is also bounded (no frames sent yet).
    #[test]
    fn oversized_peer_offer_is_refused_before_any_frame_is_sent() {
        let mut progress = DialProgress::new("INTERNET", FAST);
        let err = progress
            .collector
            .begin(
                vec![0u8; 400 * 1024],
                &[envelope_frame(EnvType::Message, 1)],
            )
            .unwrap_err();
        assert!(err.starts_with("INTERNET_DIAL_REPLY_OVERFLOW"), "{err}");
        assert!(err.ends_with("(no frames were sent)"), "{err}");
    }

    /// Terminal reply ends the dial at once; the peer stays connected.
    #[tokio::test]
    async fn dial_returns_as_soon_as_the_ack_arrives() {
        let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
        let frames = vec![envelope_frame(EnvType::Message, 2)];
        let ack = envelope_frame(EnvType::Ack, 3);
        let ack_c = ack.clone();
        let server = tokio::spawn(async move {
            let _ = read_inet_frame(&mut conn, &mut peer_t).await.unwrap();
            write_inet_frame(&mut conn, &mut peer_t, &ack_c)
                .await
                .unwrap();
            let _keep = (conn, peer_t);
            std::future::pending::<()>().await;
        });
        let mut progress = DialProgress::new("INTERNET", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(20),
            exchange_frames(&mut dialer, &mut t, &frames, &mut progress),
        )
        .await
        .expect("must not wait for the idle timeout once the ACK is in")
        .unwrap();
        assert_eq!(
            progress.collector.into_replies(),
            vec![b"offer".to_vec(), ack]
        );
        server.abort();
    }

    #[tokio::test]
    async fn peer_closing_without_a_reply_is_an_error() {
        let (mut dialer, mut t, mut conn, mut peer_t) = session_pair().await;
        let frames = vec![envelope_frame(EnvType::Message, 4)];
        let server = tokio::spawn(async move {
            let _ = read_inet_frame(&mut conn, &mut peer_t).await;
            drop(conn);
        });
        let mut progress = DialProgress::new("INTERNET", FAST);
        progress
            .collector
            .begin(b"offer".to_vec(), &frames)
            .unwrap();
        let err = exchange_frames(&mut dialer, &mut t, &frames, &mut progress)
            .await
            .unwrap_err();
        assert!(err.starts_with("INTERNET_DIAL_PEER_CLOSED"), "{err}");
        server.await.unwrap();
    }

    /// Regression: `handle_inbound` loaded the identity from the secret store
    /// for every unauthenticated connection and ran SQLite work on the async
    /// workers. The session now takes the listener's identity (the data dir
    /// here has none at all) and a silent peer ends at the handshake deadline.
    #[tokio::test(start_paused = true)]
    async fn silent_connection_ends_at_handshake_deadline_and_frees_slot() {
        let dir = tempfile::tempdir().unwrap();
        let admission = Admission::new(PRODUCTION_LIMITS);
        let ip = "10.1.2.3".parse().unwrap();
        let mut slot = admission.try_admit(ip).unwrap();
        let (_silent_peer, server_side) = tokio::io::duplex(1024);
        let started = tokio::time::Instant::now();
        let err = serve_inbound(
            dir.path().to_path_buf(),
            Arc::new(bob()),
            server_side,
            PRODUCTION_LIMITS,
            &mut slot,
        )
        .await
        .unwrap_err();
        assert_eq!(err, HANDSHAKE_TIMEOUT);
        assert!(started.elapsed() >= PRODUCTION_LIMITS.handshake_deadline);
        assert!(started.elapsed() < PRODUCTION_LIMITS.lifetime);
    }

    /// Mirrors `lan_direct::only_a_local_contact_earns_a_protected_slot`: an
    /// RLB1 offer proves possession of *a* key only, so just a local contact
    /// leaves the pre-auth caps for a non-displaceable slot.
    #[tokio::test]
    async fn only_a_local_contact_earns_a_protected_slot() {
        let lab = ["RAVEN_PREKEY_BACKEND", "RAVEN_IDENTITY_BACKEND"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "locked-file"));
        if !(cfg!(debug_assertions) && lab) {
            eprintln!("skipped: needs a debug build and RAVEN_IDENTITY_BACKEND=locked-file");
            return;
        }
        let ip: std::net::IpAddr = "10.9.8.8".parse().unwrap();
        for contact in [false, true] {
            let resp_dir = tempfile::tempdir().unwrap();
            let init_dir = tempfile::tempdir().unwrap();
            let responder = Arc::new(Identity::from_seed(&[0x73; 32]));
            let initiator = Identity::from_seed(&[0x74; 32]);
            if contact {
                std::fs::write(
                    resp_dir.path().join("contacts.json"),
                    format!(
                        r#"[{{"pub_hex":"{}"}}]"#,
                        hex::encode(initiator.public_key_bytes())
                    ),
                )
                .unwrap();
            }
            let admission = Admission::new(PRODUCTION_LIMITS);
            let mut slot = admission.try_admit(ip).expect("slot");
            let (mut client, server_side) = tokio::io::duplex(1 << 18);
            let (data_dir, resp) = (resp_dir.path().to_path_buf(), responder.clone());
            let server = tokio::spawn(async move {
                serve_inbound(data_dir, resp, server_side, PRODUCTION_LIMITS, &mut slot).await
            });
            let (_, mut t) =
                initiator_session(&mut client, &initiator, &responder.public_key_bytes())
                    .await
                    .expect("RIH1 session");
            let offer = encode_local_offer(init_dir.path(), &initiator).unwrap();
            write_inet_frame(&mut client, &mut t, &offer).await.unwrap();
            let _theirs = read_inet_frame(&mut client, &mut t).await.unwrap();

            let mut held = Vec::new();
            while let Some(s) = admission.try_admit(ip) {
                held.push(s);
            }
            let cap = PRODUCTION_LIMITS.max_handshaking_per_ip;
            if contact {
                assert_eq!(held.len(), cap, "a contact no longer counts as pre-auth");
            } else {
                assert_eq!(held.len(), cap - 1, "a stranger must stay a pre-auth slot");
            }
            drop(held);
            drop(client);
            tokio::time::timeout(Duration::from_secs(10), server)
                .await
                .expect("handler ends when the dialer hangs up")
                .unwrap()
                .unwrap();
        }
    }

    /// A full RIH1 session with the listener identity but no local state: a
    /// garbage RLB1 offer is refused after the handshake (and the slot stays
    /// a pre-auth slot until then).
    #[tokio::test]
    async fn inbound_session_uses_listener_identity_not_store() {
        let dir = tempfile::tempdir().unwrap();
        let (mut dialer, server_side) = tokio::io::duplex(1 << 17);
        let responder = Arc::new(bob());
        let expected = responder.public_key_bytes();
        let data_dir = dir.path().to_path_buf();
        let server = tokio::spawn(async move {
            let mut slot = test_slot();
            serve_inbound(
                data_dir,
                responder,
                server_side,
                PRODUCTION_LIMITS,
                &mut slot,
            )
            .await
        });
        let (_, mut t) = initiator_session(&mut dialer, &alice(), &expected)
            .await
            .expect("RIH1 session with the listener's in-memory identity");
        write_inet_frame(&mut dialer, &mut t, b"not-an-rlb1-offer")
            .await
            .unwrap();
        let err = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .expect("inbound session finishes")
            .unwrap()
            .unwrap_err();
        assert!(!err.is_empty());
    }
}
