//! Reliability: dedup, queue restart, malformed frames, OOO message_ids.

use raven_core::envelope::Envelope;
use raven_core::queue::{DeliveryState, OutgoingQueue, QueueItem};
use tempfile::tempdir;

#[test]
fn restart_mid_queue_then_ack() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("q.sqlite");
    let mid = [3u8; 16];
    {
        let q = OutgoingQueue::open(&path).unwrap();
        q.enqueue(&QueueItem {
            message_id: mid,
            packed_envelope: vec![0x52, 0x56, 0x4E, 0x31],
            peer_addr: "rvn1examplepeer000000000000000000000".into(),
            state: DeliveryState::Queued,
            created_at_ms: 10,
        })
        .unwrap();
        q.mark_state(&mid, DeliveryState::Sent).unwrap();
    }
    // Crash window: Sent but not Delivered
    let q = OutgoingQueue::open(&path).unwrap();
    let pending = q.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].state, DeliveryState::Sent);
    q.mark_state(&mid, DeliveryState::Delivered).unwrap();
    assert!(q.pending().unwrap().is_empty());
}

#[test]
fn duplicate_inbound_dedup() {
    let dir = tempdir().unwrap();
    let q = OutgoingQueue::open(&dir.path().join("q.sqlite")).unwrap();
    let mid = [9u8; 16];
    assert!(!q.dedup_check_and_insert(&mid, 1).unwrap());
    assert!(q.dedup_check_and_insert(&mid, 2).unwrap());
    assert!(q.dedup_check_and_insert(&mid, 3).unwrap());
}

#[test]
fn malformed_and_truncated_do_not_panic() {
    let cases: &[&[u8]] = &[
        &[],
        &[0xff, 0xff],
        b"RVN1",
        &[0x52, 0x56, 0x4E, 0x31, 0x01],
        &[0u8; 86],
    ];
    for c in cases {
        let _ = Envelope::unpack(c);
    }
    let mut almost = vec![0u8; 120];
    almost[0..4].copy_from_slice(b"RVN1");
    almost[4] = 1;
    almost[78] = 0x00;
    almost[79] = 0x10; // hdr 16
    almost[80] = 0;
    almost[81] = 0;
    almost[82] = 0;
    almost[83] = 0x10; // body 16 — total claim exceeds buffer
    let _ = Envelope::unpack(&almost);
}

#[test]
fn out_of_order_message_ids_still_dedup_independently() {
    let dir = tempdir().unwrap();
    let q = OutgoingQueue::open(&dir.path().join("q.sqlite")).unwrap();
    let a = [1u8; 16];
    let b = [2u8; 16];
    // Arrive B before A
    assert!(!q.dedup_check_and_insert(&b, 1).unwrap());
    assert!(!q.dedup_check_and_insert(&a, 2).unwrap());
    assert!(q.dedup_check_and_insert(&b, 3).unwrap());
}

// ── Adversarial storage coverage ─────────────────────────────────────────

use raven_core::chat_history::{BlockList, ChatHistory, ChatHistoryEntry};

fn inbound(peer: u8, index: usize, body: &str) -> ChatHistoryEntry {
    ChatHistoryEntry {
        message_id_hex: format!("{index:032x}"),
        direction: "in".into(),
        peer_petname: String::new(),
        peer_tag: String::new(),
        peer_pub_hex: hex::encode([peer; 32]),
        created_at_ms: index as u64,
        delivery: "received".into(),
        preview: String::new(),
        body: body.into(),
    }
}

#[test]
fn history_flood_from_one_contact_keeps_other_conversations() {
    let mut history = ChatHistory::default();
    for i in 0..3 {
        history.append(inbound(0xb0, i, "keep me"));
    }
    // ~4.8 MiB of maximum-size bodies from one trusted-but-hostile contact.
    let big = "m".repeat(40 * 1024);
    for i in 3..123 {
        history.append(inbound(0xe0, i, &big));
    }
    assert_eq!(history.for_peer(&hex::encode([0xb0; 32])).len(), 3);
    assert!(!history.for_peer(&hex::encode([0xe0; 32])).is_empty());
    assert!(serde_json::to_vec(&history).unwrap().len() < 4 * 1024 * 1024);
}

#[test]
fn corrupt_block_list_fails_closed_and_is_never_replaced() {
    let dir = tempdir().unwrap();
    let path = raven_core::blocked_path(dir.path());
    std::fs::write(&path, b"[\"truncated").unwrap();
    assert!(BlockList::load_checked(dir.path()).is_err());
    let mut replacement = BlockList::default();
    replacement.block("aa");
    assert!(replacement.save(dir.path()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"[\"truncated");
}

#[test]
fn interrupted_atomic_writes_never_tear_the_target() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("contacts.json");
    raven_core::atomic_write_private(&target, b"v1").unwrap();
    // Debris from a crash between temp write and rename must not matter.
    let stale = dir.path().join(".contacts.json.tmp.00000000deadbeef");
    std::fs::write(&stale, b"half-written").unwrap();
    raven_core::atomic_write_private(&target, b"v2").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"v2");
    assert_eq!(std::fs::read(&stale).unwrap(), b"half-written");

    // A replace that cannot complete leaves the old target and no new debris.
    let blocked = dir.path().join("occupied");
    std::fs::create_dir(&blocked).unwrap();
    std::fs::write(blocked.join("keep"), b"x").unwrap();
    assert!(raven_core::atomic_write_private(&blocked, b"new").is_err());
    assert!(blocked.join("keep").exists());
    let debris: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".occupied.tmp."))
        .collect();
    assert!(debris.is_empty(), "{debris:?}");
}

#[cfg(unix)]
#[test]
fn queues_holding_peer_addresses_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempdir().unwrap();
    let data_dir = root.path().join("raven");
    std::fs::create_dir(&data_dir).unwrap();
    std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

    let _outgoing = OutgoingQueue::open(&data_dir.join("queue.sqlite")).unwrap();
    let _forward =
        raven_core::forward_queue::ForwardQueue::open(&data_dir.join("forward_queue.sqlite"))
            .unwrap();
    assert_eq!(mode(&data_dir), 0o700);
    for name in ["queue.sqlite", "forward_queue.sqlite"] {
        for suffix in ["", "-wal", "-shm"] {
            let file = data_dir.join(format!("{name}{suffix}"));
            if file.exists() {
                assert_eq!(mode(&file), 0o600, "{name}{suffix}");
            }
        }
    }
}
