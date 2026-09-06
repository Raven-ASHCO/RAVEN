//! InternetTransport live path: RIH1 hello + length-prefixed frames.
//!
//! After mutual Ed25519 hello, the same indexed PairInit / message / sealed-ACK
//! dispatcher as LAN-direct runs on plaintext frames (transport auth ≠ E2EE).
//! Lab-gated: [`raven_core::internet_direct_live_enabled`]. Not WAN Proven.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;
use raven_core::identity::Identity;
use raven_core::internet::{
    frame as pack_inet_frame, pack_hello, unpack_verify_hello, CAP_INTERNET, HELLO_WIRE_LEN,
    MAX_FRAME_BYTES,
};
use raven_core::internet_direct_live_enabled;
use raven_core::lan_dispatch::{
    cache_peer_bundle, dispatch_frame, encode_local_offer, lan_peer_blocked, parse_peer_offer,
    remember_ephemeral_peer, rlb1_matches_noise_identity,
};
use raven_core::load_identity_required;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Semaphore};

const IO_TIMEOUT: Duration = Duration::from_secs(30);
const REPLY_IDLE: Duration = Duration::from_secs(2);
const HOLD: &str = "INTERNET_DIRECT_HOLD: indexed InternetTransport is lab-only \
    (debug RAVEN_LAB_TEST_A=1); INTERNET_DIRECT_PRODUCTION_ENABLED=false; \
    localhost ≠ WAN Proven";

#[derive(Debug, Clone, Copy)]
struct InboundLimits {
    max_conns: usize,
    max_per_ip: usize,
    max_frames: u32,
    lifetime: Duration,
}

const PRODUCTION_LIMITS: InboundLimits = InboundLimits {
    max_conns: 32,
    max_per_ip: 4,
    max_frames: 64,
    lifetime: Duration::from_secs(120),
};

fn try_admit_connection(
    slots: &Arc<Semaphore>,
    per_ip: &mut HashMap<IpAddr, usize>,
    ip: IpAddr,
    max_per_ip: usize,
) -> Option<tokio::sync::OwnedSemaphorePermit> {
    let permit = Arc::clone(slots).try_acquire_owned().ok()?;
    let n = per_ip.entry(ip).or_insert(0);
    if *n >= max_per_ip {
        return None;
    }
    *n += 1;
    Some(permit)
}

fn release_ip_slot(per_ip: &mut HashMap<IpAddr, usize>, ip: IpAddr) {
    if let Some(n) = per_ip.get_mut(&ip) {
        *n = n.saturating_sub(1);
        if *n == 0 {
            per_ip.remove(&ip);
        }
    }
}

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

async fn write_hello(stream: &mut TcpStream, identity: &Identity) -> Result<(), String> {
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let packed = pack_hello(identity, CAP_INTERNET, nonce);
    if packed.len() != HELLO_WIRE_LEN {
        return Err("hello pack length".into());
    }
    tokio::time::timeout(IO_TIMEOUT, stream.write_all(&packed))
        .await
        .map_err(|_| "internet hello write timeout".to_string())?
        .map_err(|e| e.to_string())?;
    tokio::time::timeout(IO_TIMEOUT, stream.flush())
        .await
        .map_err(|_| "internet hello flush timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(())
}

async fn read_hello(stream: &mut TcpStream) -> Result<(u32, [u8; 32]), String> {
    let mut buf = [0u8; HELLO_WIRE_LEN];
    tokio::time::timeout(IO_TIMEOUT, stream.read_exact(&mut buf))
        .await
        .map_err(|_| "internet hello read timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let (caps, pk) = unpack_verify_hello(&buf)?;
    if caps & CAP_INTERNET == 0 {
        return Err("internet hello missing CAP_INTERNET".into());
    }
    Ok((caps, pk))
}

async fn write_inet_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), String> {
    let framed = pack_inet_frame(payload)?;
    tokio::time::timeout(IO_TIMEOUT, async {
        stream.write_all(&framed).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "internet frame write timeout".to_string())?
}

async fn read_inet_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    tokio::time::timeout(IO_TIMEOUT, async {
        let mut len_buf = [0u8; 4];
        stream
            .read_exact(&mut len_buf)
            .await
            .map_err(|e| e.to_string())?;
        let n = u32::from_be_bytes(len_buf) as usize;
        if n == 0 || n > MAX_FRAME_BYTES {
            return Err("internet frame length".into());
        }
        let mut buf = vec![0u8; n];
        stream
            .read_exact(&mut buf)
            .await
            .map_err(|e| e.to_string())?;
        Ok(buf)
    })
    .await
    .map_err(|_| "internet frame read timeout".to_string())?
}

async fn initiator_hello(
    stream: &mut TcpStream,
    identity: &Identity,
    expected: &[u8; 32],
) -> Result<[u8; 32], String> {
    write_hello(stream, identity).await?;
    let (_caps, pk) = read_hello(stream).await?;
    if pk != *expected {
        return Err("internet hello identity mismatch".into());
    }
    Ok(pk)
}

async fn responder_hello(stream: &mut TcpStream, identity: &Identity) -> Result<[u8; 32], String> {
    let (_caps, pk) = read_hello(stream).await?;
    write_hello(stream, identity).await?;
    Ok(pk)
}

async fn handle_inbound(
    data_dir: PathBuf,
    mut stream: TcpStream,
    limits: InboundLimits,
) -> Result<(), String> {
    require_live()?;
    let started = std::time::Instant::now();
    let identity = load_identity_required(&data_dir).map_err(|e| e.to_string())?;
    let remote_ed = responder_hello(&mut stream, &identity).await?;
    let peer_offer = read_inet_frame(&mut stream).await?;
    let peer = parse_peer_offer(&peer_offer)?;
    if !rlb1_matches_noise_identity(&peer, &remote_ed) {
        return Err("rlb1/internet hello identity mismatch".into());
    }
    if lan_peer_blocked(&data_dir, &peer, &remote_ed)? {
        return Err("blocked peer".into());
    }
    remember_ephemeral_peer(&data_dir, &peer)?;
    let local = encode_local_offer(&data_dir, &identity)?;
    write_inet_frame(&mut stream, &local).await?;

    let mut frames_seen = 0u32;
    loop {
        if started.elapsed() > limits.lifetime {
            return Err("internet connection lifetime exceeded".into());
        }
        let frame = match tokio::time::timeout(IO_TIMEOUT, read_inet_frame(&mut stream)).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => {
                eprintln!("internet_direct inbound read: {e}");
                break;
            }
            Err(_) => break,
        };
        if !frame_budget_allows(&mut frames_seen, limits.max_frames) {
            return Err("internet frame budget exceeded".into());
        }
        if lan_peer_blocked(&data_dir, &peer, &remote_ed)? {
            return Err("blocked peer".into());
        }
        let dd = data_dir.clone();
        let peer_c = peer.clone();
        let frame_c = frame.clone();
        let hello_ed = remote_ed;
        let replies = tokio::task::spawn_blocking(move || {
            let identity = load_identity_required(&dd).map_err(|e| e.to_string())?;
            dispatch_frame(&dd, &identity, &peer_c, &hello_ed, &frame_c)
        })
        .await
        .map_err(|e| format!("dispatch join: {e}"))?
        .map_err(|e| {
            eprintln!("internet_direct dispatch: {e}");
            e
        })?;
        for reply in replies {
            write_inet_frame(&mut stream, &reply).await?;
        }
    }
    Ok(())
}

fn preflight_internet_ready(data_dir: &Path) -> Result<(), String> {
    require_live()?;
    let identity = load_identity_required(data_dir).map_err(|e| e.to_string())?;
    raven_core::ensure_local_prekey(data_dir, &identity)?;
    let _ = raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let _ = raven_core::PrekeyLifecycleActor::open(data_dir).map_err(|e| e.to_string())?;
    raven_core::maintain_lan_durable_state(data_dir)?;
    Ok(())
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
    preflight_internet_ready(&data_dir)?;
    let listener = TcpListener::bind(&internet_listen)
        .await
        .map_err(|e| format!("internet_direct bind {internet_listen}: {e}"))?;
    let local = listener.local_addr().map_err(|e| e.to_string())?;
    eprintln!("raven-node internet_direct: listen {local}");
    eprintln!("CLAIM: InternetTransport localhost/lab listen — dial≠WAN");
    LISTENER_UP.store(true, Ordering::Relaxed);
    let _up = ListenerGuard;
    let slots = Arc::new(Semaphore::new(limits.max_conns));
    let per_ip = Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                let ip = addr.ip();
                let permit = {
                    let mut map = per_ip.lock().await;
                    try_admit_connection(&slots, &mut map, ip, limits.max_per_ip)
                };
                let Some(permit) = permit else {
                    eprintln!("internet_direct: connection cap");
                    continue;
                };
                let dd = data_dir.clone();
                let per_ip_c = per_ip.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let result =
                        tokio::time::timeout(limits.lifetime, handle_inbound(dd, stream, limits))
                            .await;
                    {
                        let mut map = per_ip_c.lock().await;
                        release_ip_slot(&mut map, ip);
                    }
                    match result {
                        Ok(Err(e)) => eprintln!("internet_direct inbound: {e}"),
                        Err(_) => {
                            eprintln!("internet_direct inbound: connection lifetime exceeded")
                        }
                        Ok(Ok(())) => {}
                    }
                });
            }
            Err(e) => return Err(format!("internet_direct accept: {e}")),
        }
    }
}

/// Dial `internet_dial`, complete RIH1+RLB1, send `frames`, collect replies.
pub async fn dial(
    data_dir: &Path,
    internet_dial: &str,
    expected_pub_hex: &str,
    frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, String> {
    require_live()?;
    if !looks_like_internet_dial(internet_dial) {
        return Err("internet_dial must be host:port (e.g. 127.0.0.1:7421)".into());
    }
    let expected = parse_pub_hex(expected_pub_hex)?;
    let addr: SocketAddr = internet_dial
        .parse()
        .map_err(|e| format!("internet_dial parse: {e}"))?;
    let identity = load_identity_required(data_dir).map_err(|e| e.to_string())?;
    let connect = TcpStream::connect(addr);
    let mut stream = tokio::time::timeout(IO_TIMEOUT, connect)
        .await
        .map_err(|_| "internet dial timeout".to_string())?
        .map_err(|e| format!("internet connect: {e}"))?;

    let remote_ed = initiator_hello(&mut stream, &identity, &expected).await?;
    let local = encode_local_offer(data_dir, &identity)?;
    write_inet_frame(&mut stream, &local).await?;
    let peer_offer = read_inet_frame(&mut stream).await?;
    let peer = parse_peer_offer(&peer_offer)?;
    if peer.cert.device_ed_pub != expected && peer.cert.user_ed_pub != expected {
        return Err("rlb1 offer identity mismatch".into());
    }
    if !rlb1_matches_noise_identity(&peer, &remote_ed) {
        return Err("rlb1/internet hello identity mismatch".into());
    }
    if lan_peer_blocked(data_dir, &peer, &expected)? {
        return Err("blocked peer".into());
    }
    cache_peer_bundle(data_dir, &peer)?;

    let mut replies = vec![peer_offer];
    for frame in frames {
        write_inet_frame(&mut stream, frame).await?;
    }
    if frames.is_empty() {
        return Ok(replies);
    }
    match tokio::time::timeout(IO_TIMEOUT, read_inet_frame(&mut stream)).await {
        Ok(Ok(frame)) => replies.push(frame),
        _ => return Ok(replies),
    }
    while let Ok(Ok(frame)) = tokio::time::timeout(REPLY_IDLE, read_inet_frame(&mut stream)).await {
        replies.push(frame);
    }
    Ok(replies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
            assert!(PRODUCTION_LIMITS.max_frames > 0);
        }
        assert!(PRODUCTION_LIMITS.lifetime.as_secs() >= 30);
    }

    #[test]
    fn admission_enforces_global_and_per_ip_caps() {
        let slots = Arc::new(Semaphore::new(2));
        let mut per_ip = HashMap::new();
        let ip_a = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ip_b = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
        let p1 = try_admit_connection(&slots, &mut per_ip, ip_a, 1).expect("first");
        assert!(try_admit_connection(&slots, &mut per_ip, ip_a, 1).is_none());
        let p2 = try_admit_connection(&slots, &mut per_ip, ip_b, 1).expect("second ip");
        assert!(try_admit_connection(&slots, &mut per_ip, ip_b, 1).is_none());
        drop(p1);
        release_ip_slot(&mut per_ip, ip_a);
        let _p3 = try_admit_connection(&slots, &mut per_ip, ip_a, 1).expect("reuse after release");
        drop(p2);
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
}
