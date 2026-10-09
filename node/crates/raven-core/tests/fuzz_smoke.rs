//! Parser fuzz smoke + ANSI/bidi sanitization + opt-in scale hook.
//!
//! `fuzz_targets` is the cargo-fuzz target library (`node/fuzz/src/lib.rs`),
//! compiled here as a module so every libFuzzer target body type-checks against
//! the current decoder APIs and runs on stable in CI over seeded pseudo-random
//! inputs (`fuzz_smoke_all_targets_random`). Long campaigns: see node/fuzz/.

#[path = "../../../fuzz/src/lib.rs"]
mod fuzz_targets;

use raven_core::envelope::Envelope;
use raven_core::internet::{deframe_prefix, frame, unpack_verify_hello, HelloBinding, HelloRole};
use raven_core::sanitize::{had_dangerous_controls, sanitize_terminal_text};
use raven_core::store_object::StoreObject;
use std::path::{Path, PathBuf};

/// Deterministic byte mutations — CI-safe fuzz smoke (not a long campaign).
#[test]
fn fuzz_smoke_envelope_and_frames() {
    let seeds: &[&[u8]] = &[
        &[],
        b"RVN1",
        b"RVN1\x01",
        b"RSO1",
        b"RIH1",
        &[0xff; 8],
        &[0x00; 200],
        b"\x1b[31mRVN1",
    ];
    let mut corpus = Vec::new();
    for s in seeds {
        corpus.push(s.to_vec());
        // Mutations
        let mut m = s.to_vec();
        if !m.is_empty() {
            m[0] ^= 0x5a;
            corpus.push(m.clone());
            m.push(0xaa);
            corpus.push(m);
        }
        let mut big = s.to_vec();
        big.extend(std::iter::repeat_n(0x41, 4096));
        corpus.push(big);
    }
    // Also mutate a well-formed framed payload.
    if let Ok(f) = frame(b"RVN1demo") {
        corpus.push(f.clone());
        let mut t = f;
        if t.len() > 5 {
            t[5] ^= 0xff;
        }
        corpus.push(t);
    }

    let hello_binding = HelloBinding {
        role: HelloRole::Initiator,
        handshake_hash: [0u8; 32],
        noise_static_pub: [0u8; 32],
    };
    for c in &corpus {
        let _ = Envelope::unpack(c);
        let _ = StoreObject::unpack(c);
        let _ = unpack_verify_hello(c, &hello_binding);
        let _ = deframe_prefix(c);
    }
}

/// Deterministic xorshift64* — reproducible "random" inputs without a
/// dev-dependency. Override with RAVEN_FUZZ_SMOKE_SEED / RAVEN_FUZZ_SMOKE_ROUNDS.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn rvn1_vectors_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../shared-vectors/rvn1")
}

/// Collect structured seeds from the committed vectors: every hex string
/// (decoded) and every JSON object (re-serialised), so mutations start from
/// well-formed envelopes, PairInit, RLB1 offers, revocations, certs, bundles.
fn collect_vector_seeds(dir: &Path, out: &mut Vec<Vec<u8>>) {
    fn walk(v: &serde_json::Value, out: &mut Vec<Vec<u8>>) {
        match v {
            serde_json::Value::String(s) => {
                if s.len() >= 8 && s.len() % 2 == 0 {
                    if let Ok(b) = hex::decode(s) {
                        out.push(b);
                    }
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|x| walk(x, out)),
            serde_json::Value::Object(m) => {
                out.push(serde_json::to_vec(v).expect("re-serialise"));
                m.values().for_each(|x| walk(x, out));
            }
            _ => {}
        }
    }
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .map(|e| e.expect("dir entry").path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_vector_seeds(&p, out);
        } else if p.extension().is_some_and(|x| x == "json") {
            let raw = std::fs::read(&p).expect("read vector");
            let v: serde_json::Value = serde_json::from_slice(&raw).expect("vector json");
            walk(&v, out);
        }
    }
}

fn mutate(rng: &mut XorShift, seed: &[u8]) -> Vec<u8> {
    let mut m = seed.to_vec();
    match rng.below(7) {
        0 if !m.is_empty() => {
            let i = rng.below(m.len());
            m[i] ^= 1 << rng.below(8);
        }
        1 if !m.is_empty() => {
            let i = rng.below(m.len());
            m[i] = rng.next() as u8;
        }
        2 => m.truncate(rng.below(m.len() + 1)),
        3 => {
            let at = rng.below(m.len() + 1);
            let n = 1 + rng.below(16);
            let extra = rng.bytes(n);
            m.splice(at..at, extra);
        }
        4 if m.len() >= 4 => {
            // Hit length fields with boundary values.
            let at = rng.below(m.len() - 3);
            let vals = [0u32, 1, 0x7fff_ffff, u32::MAX, m.len() as u32];
            let v = vals[rng.below(vals.len())];
            m[at..at + 4].copy_from_slice(&v.to_be_bytes());
        }
        5 => m.push(rng.next() as u8),
        _ => {
            let n = 1 + rng.below(4);
            for _ in 0..n {
                if m.is_empty() {
                    break;
                }
                let i = rng.below(m.len());
                m[i] = rng.next() as u8;
            }
        }
    }
    m
}

#[test]
fn fuzz_smoke_all_targets_random() {
    use raven_core::ipc::{encode_request, IpcRequest, IPC_VERSION};

    let mut seeds = Vec::new();
    collect_vector_seeds(&rvn1_vectors_root(), &mut seeds);
    for req in [
        IpcRequest::Ping { v: IPC_VERSION },
        IpcRequest::Status { v: IPC_VERSION },
        IpcRequest::SetPolicy {
            v: IPC_VERSION,
            bridge: Some(true),
            store: None,
            relay: Some(false),
        },
    ] {
        seeds.push(encode_request(&req).expect("encode ipc"));
    }
    let framed: Vec<Vec<u8>> = seeds.iter().filter_map(|s| frame(s).ok()).collect();
    seeds.extend(framed);
    assert!(seeds.len() > 100, "vector seed corpus unexpectedly small");

    // The round-trip assertions inside the targets only fire on accepted
    // inputs; make sure the seed corpus actually reaches them.
    let accepted = |f: &dyn Fn(&[u8]) -> bool| seeds.iter().filter(|s| f(s)).count();
    assert!(
        accepted(&|s| Envelope::unpack(s).is_some()) > 0,
        "no valid RVN1 seed"
    );
    assert!(
        accepted(&|s| raven_core::pair_init::decode_init(s).is_ok()) > 0,
        "no PairInit seed"
    );
    assert!(
        accepted(&|s| raven_core::lan_rlb1::decode_offer(s).is_ok()) > 0,
        "no RLB1 seed"
    );
    assert!(
        accepted(&|s| raven_core::device_revocation::DeviceRevocationV1::decode(s).is_ok()) > 0,
        "no device revocation seed"
    );
    assert!(
        accepted(&|s| raven_core::ipc::decode_request(s).is_ok()) > 0,
        "no IPC seed"
    );
    assert!(
        accepted(&|s| deframe_prefix(s).is_some()) > 0,
        "no framed seed"
    );

    let mut rng = XorShift(env_u64("RAVEN_FUZZ_SMOKE_SEED", 0x5241_5645_4e5f_4655) | 1);
    let rounds = env_u64("RAVEN_FUZZ_SMOKE_ROUNDS", 6) as usize;
    let mut inputs = 0usize;
    for seed in &seeds {
        for (_, target) in fuzz_targets::ALL_TARGETS {
            target(seed);
        }
        inputs += 1;
        for _ in 0..rounds {
            let m = mutate(&mut rng, seed);
            for (_, target) in fuzz_targets::ALL_TARGETS {
                target(&m);
            }
            inputs += 1;
        }
    }
    // Unstructured noise of assorted lengths.
    for _ in 0..(rounds * 200) {
        let len = rng.below(2048);
        let noise = rng.bytes(len);
        for (_, target) in fuzz_targets::ALL_TARGETS {
            target(&noise);
        }
        inputs += 1;
    }
    assert!(inputs > seeds.len() * rounds);
}

#[test]
fn ansi_and_bidi_sanitization() {
    let nasty = "\u{1b}[32malice\u{202E}bob\u{1b}[0m";
    assert!(had_dangerous_controls(nasty));
    let clean = sanitize_terminal_text(nasty);
    assert_eq!(clean, "alicebob");
    assert!(!clean.contains('\u{1b}'));
    assert!(!clean.contains('\u{202E}'));
}

#[test]
fn scale_1k_queue_enqueue_dedup_ack() {
    // Strengthened 1k subset of the 10k reliability script — always runs in CI.
    use raven_core::queue::{DeliveryState, OutgoingQueue, QueueItem};
    let dir = tempfile::tempdir().unwrap();
    let q = OutgoingQueue::open(&dir.path().join("q.sqlite")).unwrap();
    const N: u32 = 1_000;
    for i in 0..N {
        let mut mid = [0u8; 16];
        mid[..4].copy_from_slice(&i.to_be_bytes());
        q.enqueue(&QueueItem {
            message_id: mid,
            packed_envelope: {
                let mut v = vec![0x52, 0x56, 0x4E, 0x31, 1];
                v.extend_from_slice(&i.to_be_bytes());
                v
            },
            peer_addr: format!("peer-{}", i % 17),
            state: DeliveryState::Queued,
            created_at_ms: i as u64,
        })
        .unwrap();
        if i % 2 == 0 {
            q.mark_state(&mid, DeliveryState::Sent).unwrap();
        }
        assert!(!q.dedup_check_and_insert(&mid, i as u64).unwrap());
        assert!(q.dedup_check_and_insert(&mid, i as u64 + 1).unwrap());
    }
    assert_eq!(q.pending().unwrap().len(), N as usize);
    for i in 0..N {
        let mut mid = [0u8; 16];
        mid[..4].copy_from_slice(&i.to_be_bytes());
        q.mark_state(&mid, DeliveryState::Delivered).unwrap();
    }
    assert!(q.pending().unwrap().is_empty());
}
