//! Persistent opaque forward queue (Bridge V1 store-carry-bridge).
//!
//! Holds packed RavenEnvelopeV1 bytes only — never plaintext / ratchet keys.
//! Survives raven-node restart; expires by envelope TTL / row expires_at_ms.
//!
//! Custody is bounded: row lifetime is clamped to [`MAX_FORWARD_TTL_MS`],
//! pending rows are capped by count and bytes, and rows that leave custody
//! (Forwarded / Expired / Failed) drop their payload immediately and remain
//! only as small dedup tombstones until expiry or the tombstone cap.

use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::path::Path;
use thiserror::Error;

use crate::bridge::authenticated_object_digest;
use crate::envelope::Envelope;
use crate::transport::TransportKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ForwardState {
    Queued = 0,
    InFlight = 1,
    Forwarded = 2,
    Expired = 3,
    Failed = 4,
}

impl ForwardState {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::InFlight,
            2 => Self::Forwarded,
            3 => Self::Expired,
            4 => Self::Failed,
            _ => Self::Queued,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ForwardItem {
    /// Immutable relay-object identity persisted as the V2 primary key.
    pub object_digest: [u8; 32],
    pub message_id: [u8; 16],
    pub packed_envelope: Vec<u8>,
    pub ingress: TransportKind,
    pub egress: TransportKind,
    pub state: ForwardState,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub previous_hop: String,
}

#[derive(Error, Debug)]
pub enum ForwardQueueError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("bad message_id")]
    BadId,
    #[error("object_digest does not match packed envelope")]
    BadObjectDigest,
    #[error("queue full (limit {0})")]
    QueueFull(usize),
    #[error("envelope too large ({0} bytes)")]
    TooLarge(usize),
}

/// Default V1 limits (never flood).
pub const MAX_FORWARD_QUEUE: usize = 512;
pub const MAX_ENVELOPE_BYTES: usize = 1_048_576;
/// Cap pending custody per previous_hop: an opaque per-source quota key from
/// the transport (raven-node bridge: source IP, IPv6 /64 — never the source
/// port, and never a Raven identity).
pub const MAX_PER_PEER_PENDING: usize = 64;
/// Max new enqueues accepted from one peer inside `PEER_RATE_WINDOW_MS`.
pub const MAX_PER_PEER_ENQUEUES_PER_WINDOW: usize = 30;
pub const PEER_RATE_WINDOW_MS: u64 = 60_000;
/// Soft per-peer byte budget inside the same window (text envelopes ≪ this).
pub const MAX_PER_PEER_BYTES_PER_WINDOW: u64 = 256_000;
/// Relay replay cache is deliberately bounded; unauthenticated peers must not
/// be able to grow a durable table without limit.
pub const MAX_RELAY_SEEN_OBJECTS: usize = 4_096;
pub const RELAY_SEEN_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
/// Longest custody a relay grants one object, whatever the envelope claims
/// (matches the offline-mailbox 7-day cap). Row expiry is clamped to
/// `created_at_ms + MAX_FORWARD_TTL_MS`.
pub const MAX_FORWARD_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
/// Total packed bytes held in pending (Queued/InFlight) rows.
pub const MAX_FORWARD_QUEUE_BYTES: u64 = 64 * 1024 * 1024;
/// Payload-free terminal rows kept for replay dedup (oldest evicted first).
pub const MAX_FORWARD_TOMBSTONES: usize = 16_384;
/// Rows kept in the per-source rate table (older windows are dropped first);
/// bounds the table when sources are keyed per connection (loopback).
pub const MAX_PEER_RATE_ROWS: usize = 4_096;

/// Result of an idempotent [`ForwardQueue::enqueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Inserted,
    /// The exact immutable object already has a row (pending or tombstone);
    /// nothing was changed. Callers on the relay path treat this as a replay.
    AlreadyPresent(ForwardState),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerRateDecision {
    Allow,
    PeerQueueFull,
    RateLimited,
}

pub struct ForwardQueue {
    conn: Connection,
    max_items: usize,
    max_bytes: usize,
    max_pending_bytes: u64,
    max_per_peer_pending: usize,
    max_per_peer_enqueues: usize,
    max_per_peer_bytes: u64,
    peer_rate_window_ms: u64,
}

impl ForwardQueue {
    pub fn open(path: &Path) -> Result<Self, ForwardQueueError> {
        Self::open_with_limits(path, MAX_FORWARD_QUEUE, MAX_ENVELOPE_BYTES)
    }

    pub fn open_with_limits(
        path: &Path,
        max_items: usize,
        max_bytes: usize,
    ) -> Result<Self, ForwardQueueError> {
        Self::open_with_peer_limits(
            path,
            max_items,
            max_bytes,
            MAX_PER_PEER_PENDING,
            MAX_PER_PEER_ENQUEUES_PER_WINDOW,
            MAX_PER_PEER_BYTES_PER_WINDOW,
            PEER_RATE_WINDOW_MS,
        )
    }

    pub fn open_with_peer_limits(
        path: &Path,
        max_items: usize,
        max_bytes: usize,
        max_per_peer_pending: usize,
        max_per_peer_enqueues: usize,
        max_per_peer_bytes: u64,
        peer_rate_window_ms: u64,
    ) -> Result<Self, ForwardQueueError> {
        // Owner-only db + WAL/SHM: rows hold previous-hop peer addresses. The
        // path may be caller-chosen (`raven-node ipc --forward-db`), so missing
        // parents are created 0700 but an existing parent keeps its mode.
        let conn = crate::paths::open_private_sqlite(path)?;
        conn.busy_timeout(std::time::Duration::from_secs(10))?;
        conn.execute_batch(
            "PRAGMA auto_vacuum=INCREMENTAL;
             PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=10000;
             CREATE TABLE IF NOT EXISTS forward_queue (
               message_id BLOB PRIMARY KEY NOT NULL,
               packed BLOB NOT NULL,
               ingress TEXT NOT NULL,
               egress TEXT NOT NULL,
               state INTEGER NOT NULL,
               created_at_ms INTEGER NOT NULL,
               expires_at_ms INTEGER NOT NULL,
               previous_hop TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS bridge_seen (
               message_id BLOB PRIMARY KEY NOT NULL,
               seen_at_ms INTEGER NOT NULL,
               ingress TEXT NOT NULL,
               previous_hop TEXT NOT NULL DEFAULT ''
             );
             CREATE TABLE IF NOT EXISTS forward_objects_v2 (
               object_digest BLOB PRIMARY KEY NOT NULL,
               message_id BLOB NOT NULL,
               packed BLOB NOT NULL,
               ingress TEXT NOT NULL,
               egress TEXT NOT NULL,
               state INTEGER NOT NULL,
               created_at_ms INTEGER NOT NULL,
               expires_at_ms INTEGER NOT NULL,
               previous_hop TEXT NOT NULL DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS idx_forward_objects_v2_message_id
               ON forward_objects_v2(message_id);
             CREATE INDEX IF NOT EXISTS idx_forward_objects_v2_state
               ON forward_objects_v2(state, expires_at_ms);
             CREATE INDEX IF NOT EXISTS idx_forward_objects_v2_peer
               ON forward_objects_v2(previous_hop, state);
             CREATE TABLE IF NOT EXISTS bridge_seen_objects_v2 (
               object_digest BLOB PRIMARY KEY NOT NULL,
               seen_at_ms INTEGER NOT NULL,
               ingress TEXT NOT NULL,
               previous_hop TEXT NOT NULL DEFAULT ''
             );
             CREATE INDEX IF NOT EXISTS idx_bridge_seen_objects_v2_time
               ON bridge_seen_objects_v2(seen_at_ms);
             CREATE TABLE IF NOT EXISTS bridge_peer_rate (
               peer_key TEXT NOT NULL,
               window_start_ms INTEGER NOT NULL,
               enqueue_count INTEGER NOT NULL,
               byte_count INTEGER NOT NULL,
               PRIMARY KEY (peer_key, window_start_ms)
             );
             CREATE INDEX IF NOT EXISTS idx_bridge_peer_rate_window
               ON bridge_peer_rate(window_start_ms);",
        )?;
        migrate_legacy_forward_rows(&conn)?;
        clamp_legacy_custody(&conn)?;
        purge_terminal_payloads(&conn)?;
        Ok(Self {
            conn,
            max_items,
            max_bytes,
            max_pending_bytes: MAX_FORWARD_QUEUE_BYTES,
            max_per_peer_pending,
            max_per_peer_enqueues,
            max_per_peer_bytes,
            peer_rate_window_ms,
        })
    }

    pub fn count_pending_for_peer(&self, previous_hop: &str) -> Result<usize, ForwardQueueError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM forward_objects_v2
             WHERE state IN (0, 1) AND previous_hop = ?1",
            params![previous_hop],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    /// Sliding-window per-peer abuse check. Records the attempt only when Allow.
    pub fn check_peer_rate(
        &self,
        previous_hop: &str,
        now_ms: u64,
        envelope_bytes: usize,
    ) -> Result<PeerRateDecision, ForwardQueueError> {
        let peer = previous_hop;
        if self.count_pending_for_peer(peer)? >= self.max_per_peer_pending {
            return Ok(PeerRateDecision::PeerQueueFull);
        }
        let window = self.peer_rate_window_ms.max(1);
        let window_start = (now_ms / window) * window;
        // Drop older windows (keep DB small).
        self.conn.execute(
            "DELETE FROM bridge_peer_rate WHERE window_start_ms < ?1",
            params![window_start.saturating_sub(window * 2) as i64],
        )?;
        let row: Option<(i64, i64)> = self
            .conn
            .query_row(
                "SELECT enqueue_count, byte_count FROM bridge_peer_rate
                 WHERE peer_key = ?1 AND window_start_ms = ?2",
                params![peer, window_start as i64],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let (count, bytes) = row.unwrap_or((0, 0));
        if count as usize >= self.max_per_peer_enqueues
            || (bytes as u64).saturating_add(envelope_bytes as u64) > self.max_per_peer_bytes
        {
            return Ok(PeerRateDecision::RateLimited);
        }
        self.conn.execute(
            "INSERT INTO bridge_peer_rate (peer_key, window_start_ms, enqueue_count, byte_count)
             VALUES (?1, ?2, 1, ?3)
             ON CONFLICT(peer_key, window_start_ms) DO UPDATE SET
               enqueue_count = enqueue_count + 1,
               byte_count = byte_count + excluded.byte_count",
            params![peer, window_start as i64, envelope_bytes as i64],
        )?;
        if row.is_none() {
            // A new key: bound the table (per-connection keys churn).
            self.conn.execute(
                "DELETE FROM bridge_peer_rate WHERE rowid IN (
                   SELECT rowid FROM bridge_peer_rate
                   ORDER BY window_start_ms DESC
                   LIMIT -1 OFFSET ?1
                 )",
                params![MAX_PEER_RATE_ROWS as i64],
            )?;
        }
        Ok(PeerRateDecision::Allow)
    }

    pub fn count_pending(&self) -> Result<usize, ForwardQueueError> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM forward_objects_v2 WHERE state IN (0, 1)",
            [],
            |r| r.get(0),
        )?;
        Ok(n as usize)
    }

    pub fn count_all(&self) -> Result<usize, ForwardQueueError> {
        let n: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM forward_objects_v2", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// Packed bytes currently held in custody (Queued/InFlight rows).
    pub fn pending_bytes(&self) -> Result<u64, ForwardQueueError> {
        let n: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(length(packed)), 0) FROM forward_objects_v2
             WHERE state IN (0, 1)",
            [],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as u64)
    }

    /// Idempotent admission of one immutable object.
    ///
    /// An existing row for the same `object_digest` (pending *or* terminal
    /// tombstone) is never overwritten: a replay can neither resurrect a
    /// Forwarded/Expired object nor bypass the capacity checks. Row lifetime
    /// is clamped to [`MAX_FORWARD_TTL_MS`] after `created_at_ms`.
    pub fn enqueue(&self, item: &ForwardItem) -> Result<EnqueueOutcome, ForwardQueueError> {
        if item.message_id.len() != 16 {
            return Err(ForwardQueueError::BadId);
        }
        if item.packed_envelope.len() > self.max_bytes {
            return Err(ForwardQueueError::TooLarge(item.packed_envelope.len()));
        }
        let env = Envelope::unpack(&item.packed_envelope).ok_or(ForwardQueueError::BadId)?;
        if env.message_id != item.message_id {
            return Err(ForwardQueueError::BadId);
        }
        let object_digest = authenticated_object_digest(&env);
        if item.object_digest != object_digest {
            return Err(ForwardQueueError::BadObjectDigest);
        }
        // One write transaction: existence, capacity and insert are atomic
        // against the IPC connection sharing this file.
        let tx = Transaction::new_unchecked(&self.conn, TransactionBehavior::Immediate)?;
        self.prune_terminal(item.created_at_ms)?;
        // Exact immutable objects are idempotent. Different objects carrying
        // the same public message_id occupy separate bounded rows, preventing
        // a forged first arrival from poisoning a later valid object.
        let existing: Option<u8> = self
            .conn
            .query_row(
                "SELECT state FROM forward_objects_v2 WHERE object_digest = ?1",
                params![object_digest.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(state) = existing {
            tx.commit()?;
            return Ok(EnqueueOutcome::AlreadyPresent(ForwardState::from_u8(state)));
        }
        if self.count_pending()? >= self.max_items
            || self
                .pending_bytes()?
                .saturating_add(item.packed_envelope.len() as u64)
                > self.max_pending_bytes
        {
            tx.commit()?; // keep the tombstone prune
            return Err(ForwardQueueError::QueueFull(self.max_items));
        }
        // SQLite INTEGER is signed; clamp so u64::MAX does not store as -1.
        let expires = item
            .expires_at_ms
            .min(item.created_at_ms.saturating_add(MAX_FORWARD_TTL_MS));
        let expires_i64 = expires.min(i64::MAX as u64) as i64;
        let created_i64 = item.created_at_ms.min(i64::MAX as u64) as i64;
        // Enqueue always creates custody; a terminal state has no meaning here.
        let state = if is_terminal(item.state) {
            ForwardState::Queued
        } else {
            item.state
        };
        self.conn.execute(
            "INSERT INTO forward_objects_v2
             (object_digest, message_id, packed, ingress, egress, state, created_at_ms, expires_at_ms, previous_hop)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                object_digest.as_slice(),
                item.message_id.as_slice(),
                item.packed_envelope,
                item.ingress.as_str(),
                item.egress.as_str(),
                state as u8,
                created_i64,
                expires_i64,
                item.previous_hop,
            ],
        )?;
        tx.commit()?;
        Ok(EnqueueOutcome::Inserted)
    }

    /// Set a row's state. Leaving custody (Forwarded / Expired / Failed)
    /// drops the payload at once; the row stays only as a dedup tombstone.
    ///
    /// A Forwarded tombstone lives until the envelope's own `expires_at`
    /// (not just the clamped custody expiry), so an envelope claiming a
    /// lifetime beyond [`MAX_FORWARD_TTL_MS`] cannot be replayed and
    /// re-forwarded once per custody period. The tombstone cap still bounds
    /// the table.
    pub fn mark_object_state(
        &self,
        object_digest: &[u8; 32],
        state: ForwardState,
    ) -> Result<(), ForwardQueueError> {
        if is_terminal(state) {
            let dedup_until = if state == ForwardState::Forwarded {
                self.pending_envelope_expiry(object_digest)?
            } else {
                None
            };
            self.conn.execute(
                "UPDATE forward_objects_v2
                 SET state = ?1, packed = X'',
                     expires_at_ms = MAX(expires_at_ms, COALESCE(?3, expires_at_ms))
                 WHERE object_digest = ?2",
                params![state as u8, object_digest.as_slice(), dedup_until],
            )?;
        } else {
            // A tombstone has no payload left to carry; never reopen it.
            self.conn.execute(
                "UPDATE forward_objects_v2 SET state = ?1
                 WHERE object_digest = ?2 AND state IN (0, 1)",
                params![state as u8, object_digest.as_slice()],
            )?;
        }
        Ok(())
    }

    /// `expires_at` of a row still holding its payload (i64-clamped).
    fn pending_envelope_expiry(
        &self,
        object_digest: &[u8; 32],
    ) -> Result<Option<i64>, ForwardQueueError> {
        let packed: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT packed FROM forward_objects_v2
                 WHERE object_digest = ?1 AND state IN (0, 1)",
                params![object_digest.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(packed
            .as_deref()
            .and_then(Envelope::unpack)
            .map(|env| env.expires_at.min(i64::MAX as u64) as i64))
    }

    /// Daemon startup only: a file created before auto_vacuum=INCREMENTAL is
    /// rewritten once (VACUUM) so tombstone pruning can return pages. Kept out
    /// of [`ForwardQueue::open`] so `status` / IPC opens never hold the write
    /// lock for a full rewrite. Best effort; returns whether it ran.
    pub fn compact_legacy_file(&self) -> Result<bool, ForwardQueueError> {
        let mode: i64 = self
            .conn
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
        if mode == 2 {
            return Ok(false);
        }
        self.conn
            .execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM;")?;
        Ok(true)
    }

    /// Return one handed-off (InFlight) object to Queued after every carrier
    /// attempt failed. Rows already settled are left alone.
    pub fn requeue_object(&self, object_digest: &[u8; 32]) -> Result<bool, ForwardQueueError> {
        let n = self.conn.execute(
            "UPDATE forward_objects_v2 SET state = ?1
             WHERE object_digest = ?2 AND state = ?3",
            params![
                ForwardState::Queued as u8,
                object_digest.as_slice(),
                ForwardState::InFlight as u8
            ],
        )?;
        Ok(n > 0)
    }

    /// Crash recovery: nothing is in flight when the dispatcher starts.
    pub fn requeue_all_in_flight(&self) -> Result<usize, ForwardQueueError> {
        let n = self.conn.execute(
            "UPDATE forward_objects_v2 SET state = ?1 WHERE state = ?2",
            params![ForwardState::Queued as u8, ForwardState::InFlight as u8],
        )?;
        Ok(n)
    }

    /// Delete terminal tombstones that have expired, then enforce the
    /// tombstone row cap (oldest first). Pending custody is never touched.
    pub fn prune_terminal(&self, now_ms: u64) -> Result<usize, ForwardQueueError> {
        let now_i64 = now_ms.min(i64::MAX as u64) as i64;
        let mut n = self.conn.execute(
            "DELETE FROM forward_objects_v2
             WHERE state IN (2, 3, 4) AND expires_at_ms < ?1",
            params![now_i64],
        )?;
        n += self.conn.execute(
            "DELETE FROM forward_objects_v2
             WHERE object_digest IN (
               SELECT object_digest FROM forward_objects_v2
               WHERE state IN (2, 3, 4)
               ORDER BY created_at_ms DESC, object_digest DESC
               LIMIT -1 OFFSET ?1
             )",
            params![MAX_FORWARD_TOMBSTONES as i64],
        )?;
        Ok(n)
    }

    /// Periodic maintenance: expire, prune tombstones, return freed pages.
    pub fn maintain(&self, now_ms: u64) -> Result<(), ForwardQueueError> {
        self.expire_stale(now_ms)?;
        if self.prune_terminal(now_ms)? > 0 {
            // No-op unless the file was created (or vacuumed) with
            // auto_vacuum=INCREMENTAL; failure only delays file shrinking.
            let _ = self.conn.execute_batch("PRAGMA incremental_vacuum(1024);");
        }
        Ok(())
    }

    /// Pending (Queued/InFlight) that are not expired.
    pub fn pending_ready(&self, now_ms: u64) -> Result<Vec<ForwardItem>, ForwardQueueError> {
        self.expire_stale(now_ms)?;
        let mut stmt = self.conn.prepare(
            "SELECT object_digest, message_id, packed, ingress, egress, state, created_at_ms, expires_at_ms, previous_hop
             FROM forward_objects_v2
             WHERE state IN (0, 1) AND expires_at_ms >= ?1
             ORDER BY created_at_ms ASC",
        )?;
        let rows = stmt.query_map(params![now_ms as i64], row_to_v2_item)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    pub fn expire_stale(&self, now_ms: u64) -> Result<usize, ForwardQueueError> {
        let n = self.conn.execute(
            "UPDATE forward_objects_v2 SET state = ?1, packed = X''
             WHERE state IN (0, 1) AND expires_at_ms < ?2",
            params![ForwardState::Expired as u8, now_ms as i64],
        )?;
        Ok(n)
    }

    pub fn get(&self, message_id: &[u8; 16]) -> Result<Option<ForwardItem>, ForwardQueueError> {
        let mut stmt = self.conn.prepare(
            "SELECT object_digest, message_id, packed, ingress, egress, state, created_at_ms, expires_at_ms, previous_hop
             FROM forward_objects_v2 WHERE message_id = ?1
             ORDER BY created_at_ms ASC, object_digest ASC LIMIT 1",
        )?;
        let row = stmt
            .query_row(params![message_id.as_slice()], row_to_v2_item)
            .optional()?;
        Ok(row)
    }

    pub fn get_object(
        &self,
        object_digest: &[u8; 32],
    ) -> Result<Option<ForwardItem>, ForwardQueueError> {
        let mut stmt = self.conn.prepare(
            "SELECT object_digest, message_id, packed, ingress, egress, state, created_at_ms, expires_at_ms, previous_hop
             FROM forward_objects_v2 WHERE object_digest = ?1",
        )?;
        let row = stmt
            .query_row(params![object_digest.as_slice()], row_to_v2_item)
            .optional()?;
        Ok(row)
    }

    /// Read-only relay dedup lookup. Callers MUST perform this before resource
    /// admission but insert only after the object was successfully admitted.
    pub fn object_was_seen(&self, object_digest: &[u8; 32]) -> Result<bool, ForwardQueueError> {
        let existing: Option<i64> = self
            .conn
            .query_row(
                "SELECT 1 FROM bridge_seen_objects_v2 WHERE object_digest = ?1",
                params![object_digest.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(existing.is_some())
    }

    /// Record an already-admitted immutable relay object. The table is pruned
    /// by age and a hard row cap before every insert.
    pub fn mark_object_seen(
        &self,
        object_digest: &[u8; 32],
        now_ms: u64,
        ingress: TransportKind,
        previous_hop: &str,
    ) -> Result<(), ForwardQueueError> {
        self.prune_seen_objects(now_ms)?;
        self.conn.execute(
            "INSERT OR IGNORE INTO bridge_seen_objects_v2
             (object_digest, seen_at_ms, ingress, previous_hop)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                object_digest.as_slice(),
                now_ms as i64,
                ingress.as_str(),
                previous_hop
            ],
        )?;
        Ok(())
    }

    pub fn prune_seen_objects(&self, now_ms: u64) -> Result<(), ForwardQueueError> {
        let cutoff = now_ms
            .saturating_sub(RELAY_SEEN_TTL_MS)
            .min(i64::MAX as u64) as i64;
        self.conn.execute(
            "DELETE FROM bridge_seen_objects_v2 WHERE seen_at_ms < ?1",
            params![cutoff],
        )?;
        self.conn.execute(
            "DELETE FROM bridge_seen_objects_v2
             WHERE object_digest IN (
               SELECT object_digest FROM bridge_seen_objects_v2
               ORDER BY seen_at_ms DESC, object_digest DESC
               LIMIT -1 OFFSET ?1
             )",
            params![MAX_RELAY_SEEN_OBJECTS as i64],
        )?;
        Ok(())
    }
}

fn is_terminal(state: ForwardState) -> bool {
    matches!(
        state,
        ForwardState::Forwarded | ForwardState::Expired | ForwardState::Failed
    )
}

/// Earlier builds kept full payloads in terminal rows forever. Drop them on
/// open (a cheap indexed UPDATE); the one-time file rewrite that returns the
/// space is [`ForwardQueue::compact_legacy_file`], run by the bridge daemon.
fn purge_terminal_payloads(conn: &Connection) -> Result<(), ForwardQueueError> {
    conn.execute(
        "UPDATE forward_objects_v2 SET packed = X''
         WHERE state IN (2, 3, 4) AND length(packed) > 0",
        [],
    )?;
    Ok(())
}

/// Earlier builds stored pending rows with the envelope's own expiry. Apply
/// the custody cap to them too (`created_at_ms` is the relay's admission
/// clock), so an upgrade does not keep a far-future row in custody. Uses no
/// wall clock: a device booting with a wrong clock must not expire custody.
fn clamp_legacy_custody(conn: &Connection) -> Result<(), ForwardQueueError> {
    let ttl = MAX_FORWARD_TTL_MS as i64;
    conn.execute(
        "UPDATE forward_objects_v2 SET expires_at_ms = created_at_ms + ?1
         WHERE state IN (0, 1) AND created_at_ms <= ?2
           AND expires_at_ms > created_at_ms + ?1",
        params![ttl, i64::MAX - ttl],
    )?;
    Ok(())
}

/// One-time migration from the original message-id-keyed queue.
/// Keeping every distinct immutable object in V2 removes the attacker-chosen
/// message-ID overwrite/poisoning primitive while preserving queued custody.
///
/// Migrated legacy rows are deleted in the same transaction. Otherwise a V2
/// row that was later forwarded and garbage-collected would be re-inserted
/// from the legacy table on the next open (custody resurrection).
fn migrate_legacy_forward_rows(conn: &Connection) -> Result<(), ForwardQueueError> {
    let any: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM forward_queue)", [], |r| {
        r.get(0)
    })?;
    if !any {
        return Ok(());
    }
    let tx = Transaction::new_unchecked(conn, TransactionBehavior::Immediate)?;
    loop {
        // Bounded batches: a legacy table may hold large terminal payloads.
        let batch = {
            let mut stmt = conn.prepare(
                "SELECT message_id, packed, ingress, egress, state, created_at_ms, expires_at_ms, previous_hop, rowid
                 FROM forward_queue ORDER BY rowid LIMIT 256",
            )?;
            let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(8)?, row_to_legacy_item(r)?)))?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            out
        };
        if batch.is_empty() {
            break;
        }
        for (rowid, item) in batch {
            conn.execute("DELETE FROM forward_queue WHERE rowid = ?1", params![rowid])?;
            let Some(env) = Envelope::unpack(&item.packed_envelope) else {
                continue;
            };
            if env.message_id != item.message_id {
                continue;
            }
            let digest = authenticated_object_digest(&env);
            let terminal = is_terminal(item.state);
            conn.execute(
                "INSERT OR IGNORE INTO forward_objects_v2
                 (object_digest, message_id, packed, ingress, egress, state, created_at_ms, expires_at_ms, previous_hop)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    digest.as_slice(),
                    item.message_id.as_slice(),
                    if terminal { &[][..] } else { &item.packed_envelope[..] },
                    item.ingress.as_str(),
                    item.egress.as_str(),
                    item.state as u8,
                    item.created_at_ms.min(i64::MAX as u64) as i64,
                    item.expires_at_ms.min(i64::MAX as u64) as i64,
                    item.previous_hop,
                ],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

fn parse_transport(s: &str) -> TransportKind {
    match s {
        "ble" => TransportKind::Ble,
        "lan" => TransportKind::Lan,
        "internet" => TransportKind::Internet,
        _ => TransportKind::MockBle,
    }
}

fn row_to_legacy_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<ForwardItem> {
    let id: Vec<u8> = r.get(0)?;
    let mut mid = [0u8; 16];
    if id.len() == 16 {
        mid.copy_from_slice(&id);
    }
    let packed_envelope: Vec<u8> = r.get(1)?;
    let object_digest = Envelope::unpack(&packed_envelope)
        .map(|env| authenticated_object_digest(&env))
        .unwrap_or([0u8; 32]);
    let ingress_s: String = r.get(2)?;
    let egress_s: String = r.get(3)?;
    Ok(ForwardItem {
        object_digest,
        message_id: mid,
        packed_envelope,
        ingress: parse_transport(&ingress_s),
        egress: parse_transport(&egress_s),
        state: ForwardState::from_u8(r.get::<_, u8>(4)?),
        created_at_ms: r.get::<_, i64>(5)? as u64,
        expires_at_ms: r.get::<_, i64>(6)? as u64,
        previous_hop: r.get(7)?,
    })
}

fn row_to_v2_item(r: &rusqlite::Row<'_>) -> rusqlite::Result<ForwardItem> {
    let digest: Vec<u8> = r.get(0)?;
    let mut object_digest = [0u8; 32];
    if digest.len() == object_digest.len() {
        object_digest.copy_from_slice(&digest);
    }
    let id: Vec<u8> = r.get(1)?;
    let mut message_id = [0u8; 16];
    if id.len() == message_id.len() {
        message_id.copy_from_slice(&id);
    }
    let ingress_s: String = r.get(3)?;
    let egress_s: String = r.get(4)?;
    Ok(ForwardItem {
        object_digest,
        message_id,
        packed_envelope: r.get(2)?,
        ingress: parse_transport(&ingress_s),
        egress: parse_transport(&egress_s),
        state: ForwardState::from_u8(r.get::<_, u8>(5)?),
        created_at_ms: r.get::<_, i64>(6)? as u64,
        expires_at_ms: r.get::<_, i64>(7)? as u64,
        previous_hop: r.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{EnvType, Envelope};
    use crate::identity::Identity;
    use sha2::Digest;
    use tempfile::tempdir;

    fn packed_with_body(mid: [u8; 16], body: &[u8]) -> Vec<u8> {
        let identity = Identity::from_seed(&[mid[0].wrapping_add(1); 32]);
        let mut env = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id: mid,
            routing_tag: [1u8; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at: 10_000,
            hop_limit: 4,
            replication_budget: 2,
            anti_replay_nonce: [2u8; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: body.to_vec(),
            sender_authentication: vec![],
        };
        env.sign_with(&identity);
        env.pack()
    }

    fn packed(mid: [u8; 16]) -> Vec<u8> {
        packed_with_body(mid, &[mid[0], 3, 4])
    }

    fn item(mid: [u8; 16], packed_envelope: Vec<u8>) -> ForwardItem {
        let env = Envelope::unpack(&packed_envelope).unwrap();
        ForwardItem {
            object_digest: authenticated_object_digest(&env),
            message_id: mid,
            packed_envelope,
            ingress: TransportKind::MockBle,
            egress: TransportKind::Lan,
            state: ForwardState::Queued,
            created_at_ms: 1,
            expires_at_ms: 100,
            previous_hop: "peer-a".into(),
        }
    }

    /// `--forward-db ~/Documents/fwd.sqlite` must not silently chmod ~/Documents
    /// to 0700; the database files stay owner-only and new parents are private.
    #[cfg(unix)]
    #[test]
    fn open_never_chmods_an_existing_parent_but_keeps_files_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let root = tempdir().unwrap();
        let docs = root.path().join("Documents");
        std::fs::create_dir(&docs).unwrap();
        std::fs::set_permissions(&docs, std::fs::Permissions::from_mode(0o755)).unwrap();
        {
            let q = ForwardQueue::open(&docs.join("fwd.sqlite")).unwrap();
            q.enqueue(&item([7u8; 16], packed([7u8; 16]))).unwrap();
        }
        assert_eq!(mode(&docs), 0o755, "existing parent keeps its mode");
        for suffix in ["", "-wal", "-shm"] {
            let file = docs.join(format!("fwd.sqlite{suffix}"));
            if file.exists() {
                assert_eq!(mode(&file), 0o600, "fwd.sqlite{suffix}");
            }
        }

        let fresh = root.path().join("a").join("b");
        drop(ForwardQueue::open(&fresh.join("fwd.sqlite")).unwrap());
        assert_eq!(mode(&fresh), 0o700, "missing parents are created private");
    }

    #[test]
    fn persist_and_expire() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fwd.sqlite");
        let mid = [3u8; 16];
        {
            let q = ForwardQueue::open(&path).unwrap();
            q.enqueue(&item(mid, packed(mid))).unwrap();
            assert_eq!(q.count_pending().unwrap(), 1);
        }
        let q = ForwardQueue::open(&path).unwrap();
        assert_eq!(q.pending_ready(50).unwrap().len(), 1);
        assert!(q.pending_ready(200).unwrap().is_empty());
        let item = q.get(&mid).unwrap().unwrap();
        assert_eq!(item.state, ForwardState::Expired);
    }

    #[test]
    fn dedup_seen() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        let mid = [9u8; 16];
        let env = Envelope::unpack(&packed(mid)).unwrap();
        let digest = authenticated_object_digest(&env);
        assert!(!q.object_was_seen(&digest).unwrap());
        q.mark_object_seen(&digest, 1, TransportKind::Lan, "h1")
            .unwrap();
        assert!(q.object_was_seen(&digest).unwrap());
    }

    #[test]
    fn per_peer_rate_and_pending_caps() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open_with_peer_limits(
            &dir.path().join("fwd.sqlite"),
            512,
            MAX_ENVELOPE_BYTES,
            2, // max pending per peer
            3, // max enqueues / window
            10_000,
            60_000,
        )
        .unwrap();
        let now = 1_700_000_000_000u64;
        assert_eq!(
            q.check_peer_rate("peer-a", now, 100).unwrap(),
            PeerRateDecision::Allow
        );
        assert_eq!(
            q.check_peer_rate("peer-a", now + 1, 100).unwrap(),
            PeerRateDecision::Allow
        );
        assert_eq!(
            q.check_peer_rate("peer-a", now + 2, 100).unwrap(),
            PeerRateDecision::Allow
        );
        assert_eq!(
            q.check_peer_rate("peer-a", now + 3, 100).unwrap(),
            PeerRateDecision::RateLimited
        );
        // Other peer unaffected.
        assert_eq!(
            q.check_peer_rate("peer-b", now, 100).unwrap(),
            PeerRateDecision::Allow
        );

        for i in 0u8..2 {
            let mid = [i; 16];
            let packed_envelope = packed(mid);
            let env = Envelope::unpack(&packed_envelope).unwrap();
            q.enqueue(&ForwardItem {
                object_digest: authenticated_object_digest(&env),
                message_id: mid,
                packed_envelope,
                ingress: TransportKind::Lan,
                egress: TransportKind::MockBle,
                state: ForwardState::Queued,
                created_at_ms: now,
                expires_at_ms: now + 60_000,
                previous_hop: "peer-c".into(),
            })
            .unwrap();
        }
        assert_eq!(q.count_pending_for_peer("peer-c").unwrap(), 2);
        // Fresh queue with pending-only check path via check_peer_rate.
        let q2 = ForwardQueue::open_with_peer_limits(
            &dir.path().join("fwd2.sqlite"),
            512,
            MAX_ENVELOPE_BYTES,
            1,
            100,
            1_000_000,
            60_000,
        )
        .unwrap();
        let mid = [7u8; 16];
        let packed_envelope = packed(mid);
        let env = Envelope::unpack(&packed_envelope).unwrap();
        q2.enqueue(&ForwardItem {
            object_digest: authenticated_object_digest(&env),
            message_id: mid,
            packed_envelope,
            ingress: TransportKind::Lan,
            egress: TransportKind::MockBle,
            state: ForwardState::Queued,
            created_at_ms: now,
            expires_at_ms: now + 60_000,
            previous_hop: "full".into(),
        })
        .unwrap();
        assert_eq!(
            q2.check_peer_rate("full", now, 10).unwrap(),
            PeerRateDecision::PeerQueueFull
        );
    }

    #[test]
    fn same_message_id_objects_transition_independently() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        let mid = [0x44; 16];
        let first = item(mid, packed_with_body(mid, b"first object"));
        let mut second = item(mid, packed_with_body(mid, b"second object"));
        second.created_at_ms = 2;
        let first_digest = first.object_digest;
        let second_digest = second.object_digest;
        assert_ne!(first_digest, second_digest);

        q.enqueue(&first).unwrap();
        q.enqueue(&second).unwrap();
        q.mark_object_state(&first_digest, ForwardState::Forwarded)
            .unwrap();

        assert_eq!(
            q.get_object(&first_digest).unwrap().unwrap().state,
            ForwardState::Forwarded
        );
        assert_eq!(
            q.get_object(&second_digest).unwrap().unwrap().state,
            ForwardState::Queued
        );

        q.mark_object_state(&second_digest, ForwardState::Failed)
            .unwrap();
        assert_eq!(
            q.get_object(&first_digest).unwrap().unwrap().state,
            ForwardState::Forwarded
        );
        assert_eq!(
            q.get_object(&second_digest).unwrap().unwrap().state,
            ForwardState::Failed
        );
    }

    fn payload_len(q: &ForwardQueue, digest: &[u8; 32]) -> i64 {
        q.conn
            .query_row(
                "SELECT length(packed) FROM forward_objects_v2 WHERE object_digest = ?1",
                params![digest.as_slice()],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// storage-durable#0: rows leaving custody drop their payload at once and
    /// are deleted after expiry; the table does not grow without bound.
    #[test]
    fn terminal_rows_drop_payload_and_are_garbage_collected() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        let items: Vec<ForwardItem> = (0u8..3)
            .map(|i| item([0x50 + i; 16], packed([0x50 + i; 16])))
            .collect();
        for it in &items {
            assert_eq!(q.enqueue(it).unwrap(), EnqueueOutcome::Inserted);
        }
        q.mark_object_state(&items[0].object_digest, ForwardState::Forwarded)
            .unwrap();
        q.mark_object_state(&items[1].object_digest, ForwardState::Failed)
            .unwrap();
        assert_eq!(payload_len(&q, &items[0].object_digest), 0);
        assert_eq!(payload_len(&q, &items[1].object_digest), 0);
        assert_eq!(
            q.pending_bytes().unwrap(),
            items[2].packed_envelope.len() as u64
        );
        // Tombstones still answer dedup lookups while unexpired.
        assert_eq!(
            q.get_object(&items[0].object_digest)
                .unwrap()
                .unwrap()
                .state,
            ForwardState::Forwarded
        );

        // After custody expiry the Failed and Expired rows are deleted; the
        // Forwarded tombstone dedups until the envelope's own expiry.
        q.maintain(200).unwrap();
        assert_eq!(q.count_all().unwrap(), 1);
        q.maintain(10_001).unwrap();
        assert_eq!(q.count_all().unwrap(), 0);
        // New files can return freed pages (auto_vacuum=INCREMENTAL).
        let auto_vacuum: i64 = q
            .conn
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .unwrap();
        assert_eq!(auto_vacuum, 2);
    }

    #[test]
    fn tombstone_rows_are_hard_capped() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        let live = item([0x61; 16], packed([0x61; 16]));
        q.enqueue(&live).unwrap();
        q.conn.execute_batch("BEGIN").unwrap();
        for i in 0..(MAX_FORWARD_TOMBSTONES + 50) {
            let d = sha2::Sha256::digest(i.to_be_bytes());
            q.conn
                .execute(
                    "INSERT INTO forward_objects_v2
                     (object_digest, message_id, packed, ingress, egress, state, created_at_ms, expires_at_ms, previous_hop)
                     VALUES (?1, ?2, X'', 'lan', 'mock_ble', 2, ?3, ?4, 'peer')",
                    params![d.as_slice(), [0u8; 16].as_slice(), i as i64, i64::MAX],
                )
                .unwrap();
        }
        q.conn.execute_batch("COMMIT").unwrap();
        q.prune_terminal(1).unwrap();
        assert_eq!(q.count_all().unwrap(), MAX_FORWARD_TOMBSTONES + 1);
        // Pending custody is never evicted by the tombstone cap.
        assert_eq!(
            q.get_object(&live.object_digest).unwrap().unwrap().state,
            ForwardState::Queued
        );
    }

    /// node-swarm#12 / storage-durable#12: a replayed object is idempotent;
    /// it can neither resurrect a tombstone nor bypass the capacity check.
    #[test]
    fn replayed_object_never_resurrects_or_bypasses_capacity() {
        let dir = tempdir().unwrap();
        let q =
            ForwardQueue::open_with_limits(&dir.path().join("fwd.sqlite"), 1, MAX_ENVELOPE_BYTES)
                .unwrap();
        let first = item([0x71; 16], packed([0x71; 16]));
        q.enqueue(&first).unwrap();
        q.mark_object_state(&first.object_digest, ForwardState::Forwarded)
            .unwrap();
        let mut replay = first.clone();
        replay.previous_hop = "attacker".into();
        assert_eq!(
            q.enqueue(&replay).unwrap(),
            EnqueueOutcome::AlreadyPresent(ForwardState::Forwarded)
        );
        let row = q.get_object(&first.object_digest).unwrap().unwrap();
        assert_eq!(row.state, ForwardState::Forwarded);
        assert_eq!(row.previous_hop, "peer-a");
        assert_eq!(q.count_pending().unwrap(), 0);

        // Queue full: an existing pending object stays idempotent, a new one
        // is refused.
        let second = item([0x72; 16], packed([0x72; 16]));
        q.enqueue(&second).unwrap();
        assert_eq!(
            q.enqueue(&second).unwrap(),
            EnqueueOutcome::AlreadyPresent(ForwardState::Queued)
        );
        let third = item([0x73; 16], packed([0x73; 16]));
        assert!(matches!(
            q.enqueue(&third),
            Err(ForwardQueueError::QueueFull(1))
        ));
        // Reopening a tombstone is refused too.
        q.mark_object_state(&first.object_digest, ForwardState::Queued)
            .unwrap();
        assert_eq!(
            q.get_object(&first.object_digest).unwrap().unwrap().state,
            ForwardState::Forwarded
        );
    }

    #[test]
    fn pending_byte_cap_refuses_new_custody() {
        let dir = tempdir().unwrap();
        let mut q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        let a = item([0x74; 16], packed([0x74; 16]));
        q.max_pending_bytes = a.packed_envelope.len() as u64 + 10;
        q.enqueue(&a).unwrap();
        let b = item([0x75; 16], packed([0x75; 16]));
        assert!(matches!(
            q.enqueue(&b),
            Err(ForwardQueueError::QueueFull(_))
        ));
        q.mark_object_state(&a.object_digest, ForwardState::Forwarded)
            .unwrap();
        assert_eq!(q.enqueue(&b).unwrap(), EnqueueOutcome::Inserted);
    }

    /// storage-durable#2: custody lifetime is capped whatever the envelope says.
    #[test]
    fn custody_ttl_is_clamped() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        let mut it = item([0x76; 16], packed([0x76; 16]));
        it.created_at_ms = 1_000;
        it.expires_at_ms = u64::MAX;
        q.enqueue(&it).unwrap();
        let row = q.get_object(&it.object_digest).unwrap().unwrap();
        assert_eq!(row.expires_at_ms, 1_000 + MAX_FORWARD_TTL_MS);
        assert!(q
            .pending_ready(1_000 + MAX_FORWARD_TTL_MS + 1)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn requeue_only_returns_in_flight_rows() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        let a = item([0x77; 16], packed([0x77; 16]));
        let b = item([0x78; 16], packed([0x78; 16]));
        q.enqueue(&a).unwrap();
        q.enqueue(&b).unwrap();
        q.mark_object_state(&a.object_digest, ForwardState::InFlight)
            .unwrap();
        q.mark_object_state(&b.object_digest, ForwardState::Forwarded)
            .unwrap();
        assert!(q.requeue_object(&a.object_digest).unwrap());
        assert!(!q.requeue_object(&b.object_digest).unwrap());
        assert_eq!(
            q.get_object(&b.object_digest).unwrap().unwrap().state,
            ForwardState::Forwarded
        );
        q.mark_object_state(&a.object_digest, ForwardState::InFlight)
            .unwrap();
        assert_eq!(q.requeue_all_in_flight().unwrap(), 1);
        assert_eq!(
            q.get_object(&a.object_digest).unwrap().unwrap().state,
            ForwardState::Queued
        );
    }

    #[test]
    fn legacy_terminal_payloads_are_purged_on_open() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fwd.sqlite");
        let it = item([0x79; 16], packed([0x79; 16]));
        {
            let q = ForwardQueue::open(&path).unwrap();
            q.enqueue(&it).unwrap();
            // What earlier builds left behind: terminal state, full payload.
            q.conn
                .execute(
                    "UPDATE forward_objects_v2 SET state = 2 WHERE object_digest = ?1",
                    params![it.object_digest.as_slice()],
                )
                .unwrap();
            assert!(payload_len(&q, &it.object_digest) > 0);
        }
        let q = ForwardQueue::open(&path).unwrap();
        assert_eq!(payload_len(&q, &it.object_digest), 0);
    }

    /// node-swarm#12: a Forwarded tombstone outlives the clamped custody
    /// period, so a far-future envelope cannot be re-forwarded every 7 days.
    /// Expired custody is not extended (a sender may retry it).
    #[test]
    fn forwarded_tombstone_dedups_for_envelope_lifetime() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        // Envelope expires_at = 10_000; custody expiry (row) = 100.
        let fwd = item([0x7a; 16], packed([0x7a; 16]));
        let exp = item([0x7b; 16], packed([0x7b; 16]));
        q.enqueue(&fwd).unwrap();
        q.enqueue(&exp).unwrap();
        q.mark_object_state(&fwd.object_digest, ForwardState::Forwarded)
            .unwrap();
        let row = q.get_object(&fwd.object_digest).unwrap().unwrap();
        assert_eq!(row.expires_at_ms, 10_000);
        assert!(row.packed_envelope.is_empty());
        // A second terminal report (payload gone) keeps the dedup expiry.
        q.mark_object_state(&fwd.object_digest, ForwardState::Forwarded)
            .unwrap();
        assert_eq!(
            q.get_object(&fwd.object_digest)
                .unwrap()
                .unwrap()
                .expires_at_ms,
            10_000
        );

        q.maintain(5_000).unwrap();
        assert!(q.get_object(&exp.object_digest).unwrap().is_none());
        let mut replay = fwd.clone();
        replay.created_at_ms = 5_000;
        replay.expires_at_ms = 5_100;
        assert_eq!(
            q.enqueue(&replay).unwrap(),
            EnqueueOutcome::AlreadyPresent(ForwardState::Forwarded)
        );
        q.maintain(10_001).unwrap();
        assert_eq!(q.count_all().unwrap(), 0);
    }

    fn insert_legacy_row(path: &Path, it: &ForwardItem) {
        let conn = Connection::open(path).unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS forward_queue (
               message_id BLOB PRIMARY KEY NOT NULL,
               packed BLOB NOT NULL,
               ingress TEXT NOT NULL,
               egress TEXT NOT NULL,
               state INTEGER NOT NULL,
               created_at_ms INTEGER NOT NULL,
               expires_at_ms INTEGER NOT NULL,
               previous_hop TEXT NOT NULL DEFAULT ''
             );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO forward_queue VALUES (?1, ?2, 'lan', 'mock_ble', ?3, ?4, ?5, ?6)",
            params![
                it.message_id.as_slice(),
                it.packed_envelope,
                it.state as u8,
                it.created_at_ms as i64,
                it.expires_at_ms.min(i64::MAX as u64) as i64,
                it.previous_hop
            ],
        )
        .unwrap();
    }

    /// Legacy (pre-V2) rows migrate once: custody is clamped, and after the
    /// migrated row is forwarded and garbage-collected a reopen does not
    /// resurrect it from the legacy table.
    #[test]
    fn legacy_rows_migrate_once_with_clamped_custody() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fwd.sqlite");
        let mut it = item([0x7c; 16], packed([0x7c; 16]));
        it.created_at_ms = 1;
        it.expires_at_ms = u64::MAX;
        insert_legacy_row(&path, &it);

        let q = ForwardQueue::open(&path).unwrap();
        let row = q.get_object(&it.object_digest).unwrap().unwrap();
        assert_eq!(row.state, ForwardState::Queued);
        assert_eq!(row.expires_at_ms, 1 + MAX_FORWARD_TTL_MS);
        let legacy: i64 = q
            .conn
            .query_row("SELECT COUNT(*) FROM forward_queue", [], |r| r.get(0))
            .unwrap();
        assert_eq!(legacy, 0);

        q.mark_object_state(&it.object_digest, ForwardState::Forwarded)
            .unwrap();
        q.maintain(u64::MAX / 2).unwrap();
        assert_eq!(q.count_all().unwrap(), 0);
        drop(q);
        let q = ForwardQueue::open(&path).unwrap();
        assert_eq!(q.count_all().unwrap(), 0);
        assert!(q.pending_ready(2).unwrap().is_empty());
    }

    /// storage-durable#0: `open` (status, IPC) never runs a full VACUUM; the
    /// bridge daemon converts a pre-GC file once.
    #[test]
    fn legacy_file_is_compacted_only_on_request() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("fwd.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE unrelated (x INTEGER);")
                .unwrap();
        }
        let mode = |q: &ForwardQueue| -> i64 {
            q.conn
                .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
                .unwrap()
        };
        let q = ForwardQueue::open(&path).unwrap();
        assert_eq!(mode(&q), 0);
        assert!(q.compact_legacy_file().unwrap());
        assert_eq!(mode(&q), 2);
        assert!(!q.compact_legacy_file().unwrap());
    }

    #[test]
    fn peer_rate_table_is_bounded() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        let now = 1_700_000_000_000u64;
        q.conn.execute_batch("BEGIN").unwrap();
        for i in 0..(MAX_PEER_RATE_ROWS + 25) {
            assert_eq!(
                q.check_peer_rate(&format!("loopback/conn.{i}"), now, 10)
                    .unwrap(),
                PeerRateDecision::Allow
            );
        }
        q.conn.execute_batch("COMMIT").unwrap();
        let rows: i64 = q
            .conn
            .query_row("SELECT COUNT(*) FROM bridge_peer_rate", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows as usize, MAX_PEER_RATE_ROWS);
    }

    #[test]
    fn relay_seen_cache_is_hard_bounded() {
        let dir = tempdir().unwrap();
        let q = ForwardQueue::open(&dir.path().join("fwd.sqlite")).unwrap();
        for i in 0..(MAX_RELAY_SEEN_OBJECTS + 32) {
            let digest = sha2::Sha256::digest(i.to_be_bytes());
            let mut d = [0u8; 32];
            d.copy_from_slice(&digest);
            q.mark_object_seen(&d, i as u64 + 1, TransportKind::Lan, "peer")
                .unwrap();
        }
        q.prune_seen_objects((MAX_RELAY_SEEN_OBJECTS + 33) as u64)
            .unwrap();
        let count: i64 = q
            .conn
            .query_row("SELECT COUNT(*) FROM bridge_seen_objects_v2", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert!(count as usize <= MAX_RELAY_SEEN_OBJECTS);
    }
}
