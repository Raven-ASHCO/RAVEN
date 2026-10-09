//! Persistent outgoing queue (SQLite). Delivery advances only on signed ACK.

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeliveryState {
    Queued = 0,
    Sent = 1,
    Delivered = 2,
    Failed = 3,
}

impl DeliveryState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Sent,
            2 => Self::Delivered,
            3 => Self::Failed,
            _ => Self::Queued,
        }
    }
}

#[derive(Debug, Clone)]
pub struct QueueItem {
    pub message_id: [u8; 16],
    pub packed_envelope: Vec<u8>,
    pub peer_addr: String,
    pub state: DeliveryState,
    pub created_at_ms: u64,
}

#[derive(Error, Debug)]
pub enum QueueError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("bad message_id length")]
    BadId,
    #[error("message_id collision with a different immutable outbound object")]
    MessageIdCollision,
}

pub struct OutgoingQueue {
    conn: Connection,
}

/// Delivered / Failed rows (recipient address + timestamp) are local
/// metadata only; keep them for status display, then drop them.
pub const TERMINAL_ROW_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

impl OutgoingQueue {
    /// Open (or create) the queue, which always lives directly in the Raven
    /// data dir. The database and its WAL/SHM sidecars are owner-only (0600)
    /// and the data dir is locked to its owner (0700): rows name recipients.
    pub fn open(path: &Path) -> Result<Self, QueueError> {
        let conn = crate::paths::open_private_data_dir_sqlite(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS outgoing (
               message_id BLOB PRIMARY KEY NOT NULL,
               packed BLOB NOT NULL,
               peer_addr TEXT NOT NULL,
               state INTEGER NOT NULL,
               created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS seen_inbound (
               message_id BLOB PRIMARY KEY NOT NULL,
               seen_at_ms INTEGER NOT NULL
             );",
        )?;
        let queue = Self { conn };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        queue.prune_terminal_before(now_ms.saturating_sub(TERMINAL_ROW_RETENTION_MS))?;
        Ok(queue)
    }

    /// Delete Delivered / Failed rows created before `cutoff_ms`. Queued and
    /// Sent rows are never pruned: they still need (re)delivery.
    pub fn prune_terminal_before(&self, cutoff_ms: u64) -> Result<usize, QueueError> {
        let cutoff = i64::try_from(cutoff_ms).unwrap_or(i64::MAX);
        Ok(self.conn.execute(
            "DELETE FROM outgoing WHERE state IN (2, 3) AND created_at_ms < ?1",
            params![cutoff],
        )?)
    }

    pub fn enqueue(&self, item: &QueueItem) -> Result<(), QueueError> {
        if item.message_id.len() != 16 {
            return Err(QueueError::BadId);
        }
        // Retries of the exact same immutable object are idempotent and must
        // not reset delivery state. Reusing an ID for different ciphertext or
        // a different recipient is a hard local integrity failure.
        let existing: Option<(Vec<u8>, String)> = self
            .conn
            .query_row(
                "SELECT packed, peer_addr FROM outgoing WHERE message_id = ?1",
                params![item.message_id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((packed, peer_addr)) = existing {
            if packed == item.packed_envelope && peer_addr == item.peer_addr {
                return Ok(());
            }
            return Err(QueueError::MessageIdCollision);
        }
        self.conn.execute(
            "INSERT INTO outgoing (message_id, packed, peer_addr, state, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                item.message_id.as_slice(),
                item.packed_envelope,
                item.peer_addr,
                item.state as u8,
                item.created_at_ms as i64
            ],
        )?;
        Ok(())
    }

    pub fn mark_state(
        &self,
        message_id: &[u8; 16],
        state: DeliveryState,
    ) -> Result<(), QueueError> {
        // Delivery is monotonic. In particular, a concurrent transport-write
        // completion must never regress Delivered back to Sent.
        let predicate = match state {
            DeliveryState::Queued => "state = 0",
            DeliveryState::Sent => "state = 0",
            DeliveryState::Delivered | DeliveryState::Failed => "state IN (0, 1)",
        };
        let sql = format!("UPDATE outgoing SET state = ?1 WHERE message_id = ?2 AND ({predicate})");
        self.conn
            .execute(&sql, params![state as u8, message_id.as_slice()])?;
        Ok(())
    }

    /// Compare-and-set used by authenticated receipt handling. Returns true
    /// exactly once for a live Queued/Sent row; duplicates and terminal rows
    /// are no-ops, which prevents duplicate UI delivery events.
    pub fn mark_delivered_once(&self, message_id: &[u8; 16]) -> Result<bool, QueueError> {
        let changed = self.conn.execute(
            "UPDATE outgoing SET state = ?1
             WHERE message_id = ?2 AND state IN (0, 1)",
            params![DeliveryState::Delivered as u8, message_id.as_slice()],
        )?;
        Ok(changed == 1)
    }

    pub fn get(&self, message_id: &[u8; 16]) -> Result<Option<QueueItem>, QueueError> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, packed, peer_addr, state, created_at_ms FROM outgoing WHERE message_id = ?1",
        )?;
        let row = stmt
            .query_row(params![message_id.as_slice()], |r| {
                let id: Vec<u8> = r.get(0)?;
                let mut mid = [0u8; 16];
                if id.len() == 16 {
                    mid.copy_from_slice(&id);
                }
                Ok(QueueItem {
                    message_id: mid,
                    packed_envelope: r.get(1)?,
                    peer_addr: r.get(2)?,
                    state: DeliveryState::from_u8(r.get::<_, u8>(3)?),
                    created_at_ms: r.get::<_, i64>(4)? as u64,
                })
            })
            .optional()?;
        Ok(row)
    }

    /// Items still needing send or re-send after crash (Queued or Sent, not Delivered).
    pub fn pending(&self) -> Result<Vec<QueueItem>, QueueError> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, packed, peer_addr, state, created_at_ms FROM outgoing
             WHERE state IN (0, 1) ORDER BY created_at_ms ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            let id: Vec<u8> = r.get(0)?;
            let mut mid = [0u8; 16];
            if id.len() == 16 {
                mid.copy_from_slice(&id);
            }
            Ok(QueueItem {
                message_id: mid,
                packed_envelope: r.get(1)?,
                peer_addr: r.get(2)?,
                state: DeliveryState::from_u8(r.get::<_, u8>(3)?),
                created_at_ms: r.get::<_, i64>(4)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// All outgoing rows' metadata (for CLI status), oldest first.
    ///
    /// `packed_envelope` is left **empty**: a status listing needs ids, state
    /// and recipient, and loading every ciphertext blob (up to 1 MiB each,
    /// Delivered rows included for 30 days) into memory just to print them is
    /// pure waste. Use [`Self::get`] or [`Self::pending`] when the ciphertext
    /// is needed.
    pub fn list_all(&self) -> Result<Vec<QueueItem>, QueueError> {
        let mut stmt = self.conn.prepare(
            "SELECT message_id, peer_addr, state, created_at_ms FROM outgoing
             ORDER BY created_at_ms ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            let id: Vec<u8> = r.get(0)?;
            let mut mid = [0u8; 16];
            if id.len() == 16 {
                mid.copy_from_slice(&id);
            }
            Ok(QueueItem {
                message_id: mid,
                packed_envelope: Vec::new(),
                peer_addr: r.get(1)?,
                state: DeliveryState::from_u8(r.get::<_, u8>(2)?),
                created_at_ms: r.get::<_, i64>(3)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Returns true if this inbound message_id was already seen (duplicate).
    ///
    /// `seen_inbound` is deliberately never pruned: it is replay protection,
    /// not a cache. A receiver does not bound an envelope's `expires_at`, so
    /// forgetting an id after any fixed age would let a recorded, validly
    /// signed message be accepted (and re-ACKed) again. Bounding it safely
    /// needs the envelope's expiry recorded with the row.
    pub fn dedup_check_and_insert(
        &self,
        message_id: &[u8; 16],
        now_ms: u64,
    ) -> Result<bool, QueueError> {
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM seen_inbound WHERE message_id = ?1",
                params![message_id.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if existing.is_some() {
            return Ok(true);
        }
        self.conn.execute(
            "INSERT INTO seen_inbound (message_id, seen_at_ms) VALUES (?1, ?2)",
            params![message_id.as_slice(), now_ms as i64],
        )?;
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn persist_across_reopen() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("q.sqlite");
        let mid = [7u8; 16];
        {
            let q = OutgoingQueue::open(&path).unwrap();
            q.enqueue(&QueueItem {
                message_id: mid,
                packed_envelope: vec![1, 2, 3],
                peer_addr: "rvn1example".into(),
                state: DeliveryState::Queued,
                created_at_ms: 1,
            })
            .unwrap();
            q.mark_state(&mid, DeliveryState::Sent).unwrap();
        }
        let q = OutgoingQueue::open(&path).unwrap();
        let item = q.get(&mid).unwrap().unwrap();
        assert_eq!(item.state, DeliveryState::Sent);
        assert_eq!(q.pending().unwrap().len(), 1);
        q.mark_state(&mid, DeliveryState::Delivered).unwrap();
        assert!(q.pending().unwrap().is_empty());
    }

    #[test]
    fn dedup() {
        let dir = tempdir().unwrap();
        let q = OutgoingQueue::open(&dir.path().join("q.sqlite")).unwrap();
        let mid = [1u8; 16];
        assert!(!q.dedup_check_and_insert(&mid, 1).unwrap());
        assert!(q.dedup_check_and_insert(&mid, 2).unwrap());
    }

    /// `list_all` is a status listing: metadata only, no ciphertext blobs.
    #[test]
    fn list_all_returns_metadata_without_loading_ciphertext() {
        let dir = tempdir().unwrap();
        let q = OutgoingQueue::open(&dir.path().join("q.sqlite")).unwrap();
        for (byte, created_at_ms) in [(2u8, 20u64), (1, 10), (3, 30)] {
            q.enqueue(&QueueItem {
                message_id: [byte; 16],
                packed_envelope: vec![byte; 1024],
                peer_addr: format!("rvn1peer{byte}"),
                state: DeliveryState::Queued,
                created_at_ms,
            })
            .unwrap();
        }
        q.mark_state(&[2; 16], DeliveryState::Delivered).unwrap();
        let all = q.list_all().unwrap();
        let ids: Vec<u8> = all.iter().map(|i| i.message_id[0]).collect();
        assert_eq!(ids, vec![1, 2, 3], "oldest first");
        assert_eq!(all[1].state, DeliveryState::Delivered);
        assert_eq!(all[1].peer_addr, "rvn1peer2");
        assert_eq!(all[1].created_at_ms, 20);
        assert!(all.iter().all(|i| i.packed_envelope.is_empty()));
        // The ciphertext is still there for the callers that need it.
        assert_eq!(
            q.get(&[2; 16]).unwrap().unwrap().packed_envelope.len(),
            1024
        );
        assert_eq!(q.pending().unwrap().len(), 2);
        assert!(q
            .pending()
            .unwrap()
            .iter()
            .all(|i| i.packed_envelope.len() == 1024));
    }

    #[test]
    fn immutable_enqueue_is_idempotent_and_rejects_id_collision() {
        let dir = tempdir().unwrap();
        let q = OutgoingQueue::open(&dir.path().join("q.sqlite")).unwrap();
        let item = QueueItem {
            message_id: [9u8; 16],
            packed_envelope: vec![1, 2, 3],
            peer_addr: "rvn1peer".into(),
            state: DeliveryState::Queued,
            created_at_ms: 1,
        };
        q.enqueue(&item).unwrap();
        q.mark_state(&item.message_id, DeliveryState::Sent).unwrap();
        q.enqueue(&item).unwrap();
        assert_eq!(
            q.get(&item.message_id).unwrap().unwrap().state,
            DeliveryState::Sent
        );

        let mut collision = item.clone();
        collision.packed_envelope.push(4);
        assert!(matches!(
            q.enqueue(&collision),
            Err(QueueError::MessageIdCollision)
        ));
    }

    #[test]
    fn retention_prunes_only_old_terminal_rows_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("q.sqlite");
        let item = |byte: u8, created_at_ms: u64| QueueItem {
            message_id: [byte; 16],
            packed_envelope: vec![byte],
            peer_addr: format!("rvn1peer{byte}"),
            state: DeliveryState::Queued,
            created_at_ms,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        {
            let q = OutgoingQueue::open(&path).unwrap();
            // Old delivered + old failed: pruned. Old pending: kept. Recent delivered: kept.
            q.enqueue(&item(1, 1)).unwrap();
            q.mark_state(&[1; 16], DeliveryState::Delivered).unwrap();
            q.enqueue(&item(2, 1)).unwrap();
            q.mark_state(&[2; 16], DeliveryState::Failed).unwrap();
            q.enqueue(&item(3, 1)).unwrap();
            q.mark_state(&[3; 16], DeliveryState::Sent).unwrap();
            q.enqueue(&item(4, now)).unwrap();
            q.mark_state(&[4; 16], DeliveryState::Delivered).unwrap();
        }
        let q = OutgoingQueue::open(&path).unwrap();
        assert!(q.get(&[1; 16]).unwrap().is_none());
        assert!(q.get(&[2; 16]).unwrap().is_none());
        assert_eq!(q.get(&[3; 16]).unwrap().unwrap().state, DeliveryState::Sent);
        assert_eq!(
            q.get(&[4; 16]).unwrap().unwrap().state,
            DeliveryState::Delivered
        );
    }

    #[cfg(unix)]
    #[test]
    fn queue_database_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("raven");
        let path = data_dir.join("queue.sqlite");
        let q = OutgoingQueue::open(&path).unwrap();
        q.enqueue(&QueueItem {
            message_id: [5u8; 16],
            packed_envelope: vec![1],
            peer_addr: "rvn1recipient".into(),
            state: DeliveryState::Queued,
            created_at_ms: 1,
        })
        .unwrap();
        let mode =
            |p: std::path::PathBuf| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(data_dir.clone()), 0o700);
        assert_eq!(mode(path.clone()), 0o600);
        for suffix in ["-wal", "-shm"] {
            let sidecar = data_dir.join(format!("queue.sqlite{suffix}"));
            if sidecar.exists() {
                assert_eq!(mode(sidecar), 0o600, "{suffix}");
            }
        }
    }

    /// The outgoing queue is data-dir state: opening it locks down a data dir
    /// left group/other-readable by an older build.
    #[cfg(unix)]
    #[test]
    fn opening_the_queue_tightens_an_existing_data_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let data_dir = dir.path().join("raven");
        std::fs::create_dir(&data_dir).unwrap();
        std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        drop(OutgoingQueue::open(&data_dir.join("queue.sqlite")).unwrap());
        let mode = std::fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn delivered_state_never_regresses_and_cas_fires_once() {
        let dir = tempdir().unwrap();
        let q = OutgoingQueue::open(&dir.path().join("q.sqlite")).unwrap();
        let mid = [8u8; 16];
        q.enqueue(&QueueItem {
            message_id: mid,
            packed_envelope: vec![7],
            peer_addr: "rvn1peer".into(),
            state: DeliveryState::Queued,
            created_at_ms: 1,
        })
        .unwrap();
        assert!(q.mark_delivered_once(&mid).unwrap());
        assert!(!q.mark_delivered_once(&mid).unwrap());
        q.mark_state(&mid, DeliveryState::Sent).unwrap();
        assert_eq!(
            q.get(&mid).unwrap().unwrap().state,
            DeliveryState::Delivered
        );
    }
}
