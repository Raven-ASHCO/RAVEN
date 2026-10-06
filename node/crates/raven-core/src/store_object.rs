//! RavenStoreObjectV1 — opaque custody + rotating mailbox tags.
//!
//! Spec: `protocol/RAVEN_STORE_OBJECT_V1.md`

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::bridge::authenticated_object_digest;
use crate::envelope::Envelope;
use crate::identity::Identity;
use crate::internet::opaque_store_tag;

type HmacSha256 = Hmac<Sha256>;

pub const STORE_MAGIC: &[u8; 4] = b"RSO1";
pub const MAILBOX_LABEL: &[u8] = b"rvn1/mailbox";
pub const CUSTODY_DOMAIN: &[u8] = b"rvn1/store-custody";
pub const MAX_ENVELOPE_LEN: usize = 1_048_576;
pub const MAX_STORE_OBJECTS: usize = 4_096;
pub const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_MAILBOX_DISK_BYTES: u64 = (MAX_STORE_BYTES as u64 * 2) + (16 * 1024 * 1024);
pub const FLAG_CUSTODY_SIG: u16 = 1 << 0;

/// mailbox_tag = HMAC-SHA256(K_route, "rvn1/mailbox" || epoch || slot)[:16]
pub fn mailbox_tag(k_route: &[u8], epoch: u64, slot: u64) -> [u8; 16] {
    let mut mac = HmacSha256::new_from_slice(k_route).expect("HMAC key");
    mac.update(MAILBOX_LABEL);
    mac.update(&epoch.to_be_bytes());
    mac.update(&slot.to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// Accept current and previous epoch (clock-skew overlap).
pub fn mailbox_tags_with_overlap(k_route: &[u8], epoch: u64, slot: u64) -> [[u8; 16]; 2] {
    let cur = mailbox_tag(k_route, epoch, slot);
    let prev = if epoch == 0 {
        cur
    } else {
        mailbox_tag(k_route, epoch - 1, slot)
    };
    [cur, prev]
}

/// Public store index key from mailbox tag (never a username).
pub fn store_tag_from_mailbox(mailbox: &[u8; 16]) -> [u8; 16] {
    opaque_store_tag(mailbox)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreObject {
    pub store_tag: [u8; 16],
    pub message_id: [u8; 16],
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub flags: u16,
    pub packed_envelope: Vec<u8>,
    pub custody_sig: Option<[u8; 64]>,
}

impl StoreObject {
    fn validated_envelope(&self) -> Result<Envelope, String> {
        if self.flags & !FLAG_CUSTODY_SIG != 0 {
            return Err("unknown store flags".into());
        }
        if (self.flags & FLAG_CUSTODY_SIG != 0) != self.custody_sig.is_some() {
            return Err("custody flag/signature mismatch".into());
        }
        if self.expires_at_ms <= self.created_at_ms {
            return Err("invalid store lifetime".into());
        }
        let env = Envelope::unpack(&self.packed_envelope)
            .ok_or_else(|| "invalid RavenEnvelopeV1".to_string())?;
        if env.message_id != self.message_id {
            return Err("store/envelope message_id mismatch".into());
        }
        if self.created_at_ms < env.created_at || self.expires_at_ms > env.expires_at {
            return Err("store lifetime exceeds envelope lifetime".into());
        }
        Ok(env)
    }

    pub fn pack_unsigned(&self) -> Result<Vec<u8>, String> {
        if self.packed_envelope.len() > MAX_ENVELOPE_LEN {
            return Err("envelope too large".into());
        }
        self.validated_envelope()?;
        let mut out =
            Vec::with_capacity(4 + 1 + 16 + 16 + 8 + 8 + 2 + 4 + self.packed_envelope.len());
        out.extend_from_slice(STORE_MAGIC);
        out.push(1);
        out.extend_from_slice(&self.store_tag);
        out.extend_from_slice(&self.message_id);
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        // Pack without custody bit for signing base.
        let flags_nosig = self.flags & !FLAG_CUSTODY_SIG;
        out.extend_from_slice(&flags_nosig.to_be_bytes());
        out.extend_from_slice(&(self.packed_envelope.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.packed_envelope);
        Ok(out)
    }

    pub fn sign_custody(&mut self, store_id: &Identity) -> Result<(), String> {
        let base = self.pack_unsigned()?;
        let mut msg = CUSTODY_DOMAIN.to_vec();
        msg.extend_from_slice(&base);
        let sig = store_id.sign(&msg);
        self.custody_sig = Some(sig);
        self.flags |= FLAG_CUSTODY_SIG;
        Ok(())
    }

    pub fn pack(&self) -> Result<Vec<u8>, String> {
        let mut out = self.pack_unsigned()?;
        if let Some(sig) = self.custody_sig {
            // Rewrite flags with custody bit.
            let flag_off = 4 + 1 + 16 + 16 + 8 + 8;
            out[flag_off..flag_off + 2].copy_from_slice(&self.flags.to_be_bytes());
            out.extend_from_slice(&sig);
        }
        Ok(out)
    }

    pub fn unpack(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 4 + 1 + 16 + 16 + 8 + 8 + 2 + 4 {
            return Err("short store object".into());
        }
        if &raw[0..4] != STORE_MAGIC {
            return Err("bad magic".into());
        }
        if raw[4] != 1 {
            return Err("version".into());
        }
        let mut store_tag = [0u8; 16];
        store_tag.copy_from_slice(&raw[5..21]);
        let mut message_id = [0u8; 16];
        message_id.copy_from_slice(&raw[21..37]);
        let created_at_ms = u64::from_be_bytes(raw[37..45].try_into().unwrap());
        let expires_at_ms = u64::from_be_bytes(raw[45..53].try_into().unwrap());
        let flags = u16::from_be_bytes([raw[53], raw[54]]);
        if flags & !FLAG_CUSTODY_SIG != 0 {
            return Err("unknown store flags".into());
        }
        let elen = u32::from_be_bytes([raw[55], raw[56], raw[57], raw[58]]) as usize;
        if elen > MAX_ENVELOPE_LEN {
            return Err("envelope too large".into());
        }
        let start = 59;
        let end = start + elen;
        if raw.len() < end {
            return Err("truncated envelope".into());
        }
        let packed_envelope = raw[start..end].to_vec();
        let custody_sig = if flags & FLAG_CUSTODY_SIG != 0 {
            if raw.len() != end + 64 {
                return Err("missing custody sig".into());
            }
            let mut s = [0u8; 64];
            s.copy_from_slice(&raw[end..end + 64]);
            Some(s)
        } else {
            if raw.len() != end {
                return Err("trailing store bytes".into());
            }
            None
        };
        let value = Self {
            store_tag,
            message_id,
            created_at_ms,
            expires_at_ms,
            flags,
            packed_envelope,
            custody_sig,
        };
        value.validated_envelope()?;
        Ok(value)
    }

    pub fn verify_custody(&self, store_pub: &[u8; 32]) -> bool {
        let Some(sig) = self.custody_sig else {
            return false;
        };
        let Ok(base) = self.pack_unsigned() else {
            return false;
        };
        let mut msg = CUSTODY_DOMAIN.to_vec();
        msg.extend_from_slice(&base);
        Identity::verify(store_pub, &msg, &sig)
    }

    pub fn expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_at_ms
    }
}

/// A stored object plus its authenticated digest, computed once on insert so
/// dedup never re-unpacks and re-hashes every stored envelope.
struct StoredObject {
    object: StoreObject,
    digest: [u8; 32],
}

/// In-memory mailbox indexed by store_tag (software substitute for multi-node store).
pub struct StoreMailbox {
    items: Vec<StoredObject>,
    max_per_tag: usize,
    max_total: usize,
    max_total_bytes: usize,
    /// Set when contents differ from the last snapshot written/read, so
    /// idempotent re-puts (a peer resending one object) never force a full
    /// snapshot rewrite.
    dirty: std::sync::atomic::AtomicBool,
}

impl Default for StoreMailbox {
    fn default() -> Self {
        Self::new(64)
    }
}

impl StoreMailbox {
    pub fn new(max_per_tag: usize) -> Self {
        Self::new_with_resource_limits(max_per_tag, MAX_STORE_OBJECTS, MAX_STORE_BYTES)
    }

    pub fn new_with_limits(max_per_tag: usize, max_total: usize) -> Self {
        Self::new_with_resource_limits(max_per_tag, max_total, MAX_STORE_BYTES)
    }

    pub fn new_with_resource_limits(
        max_per_tag: usize,
        max_total: usize,
        max_total_bytes: usize,
    ) -> Self {
        Self {
            items: Vec::new(),
            max_per_tag: max_per_tag.max(1),
            max_total: max_total.max(1),
            max_total_bytes: max_total_bytes.max(1),
            // Never persisted yet: the first save must write a snapshot.
            dirty: std::sync::atomic::AtomicBool::new(true),
        }
    }

    fn mark_dirty(&self) {
        self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Idempotent for an exact duplicate (same tag + authenticated digest).
    pub fn put(&mut self, obj: StoreObject) -> Result<(), String> {
        self.insert(obj).map(|_| ())
    }

    /// Like [`Self::put`], but reports whether a new row was stored
    /// (`Ok(false)` for an exact duplicate, which changes nothing).
    pub fn insert(&mut self, obj: StoreObject) -> Result<bool, String> {
        let env = obj.validated_envelope()?;
        if obj.expired(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        ) {
            return Err("STORE_EXPIRED".into());
        }
        let digest = authenticated_object_digest(&env);
        if self
            .items
            .iter()
            .any(|item| item.object.store_tag == obj.store_tag && item.digest == digest)
        {
            return Ok(false);
        }
        if self.items.len() >= self.max_total {
            return Err("STORE_FULL".into());
        }
        let used_bytes = self.items.iter().try_fold(0usize, |used, item| {
            used.checked_add(item.object.packed_envelope.len())
        });
        if used_bytes
            .and_then(|used| used.checked_add(obj.packed_envelope.len()))
            .map(|next| next > self.max_total_bytes)
            .unwrap_or(true)
        {
            return Err("STORE_FULL".into());
        }
        let count = self
            .items
            .iter()
            .filter(|i| i.object.store_tag == obj.store_tag)
            .count();
        if count >= self.max_per_tag {
            return Err("STORE_FULL".into());
        }
        // Different authenticated objects with the same public message_id are
        // independent bounded rows. An attacker cannot pre-poison a genuine
        // object by racing an ID collision.
        self.items.push(StoredObject {
            object: obj,
            digest,
        });
        self.mark_dirty();
        Ok(true)
    }

    pub fn get(&self, store_tag: &[u8; 16], now_ms: u64) -> Vec<&StoreObject> {
        self.items
            .iter()
            .map(|i| &i.object)
            .filter(|o| o.store_tag == *store_tag && !o.expired(now_ms))
            .collect()
    }

    pub fn purge_expired(&mut self, now_ms: u64) -> usize {
        let before = self.items.len();
        self.items.retain(|i| !i.object.expired(now_ms));
        let removed = before - self.items.len();
        if removed > 0 {
            self.mark_dirty();
        }
        removed
    }

    /// Persist mailbox as opaque JSON (store_tag hex → objects). Never indexes usernames.
    ///
    /// A no-op when nothing changed since the last successful save or load,
    /// so duplicate puts cannot be used to force full-snapshot rewrites.
    pub fn save_disk(&self, path: &std::path::Path) -> Result<(), String> {
        if !self.dirty.load(std::sync::atomic::Ordering::SeqCst) && path.exists() {
            return Ok(());
        }
        self.write_snapshot(path)?;
        self.dirty.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    /// Stream the snapshot as compact JSON, one row at a time: each envelope is
    /// hex-encoded only while its own row is serialized, so peak memory is a
    /// row, not a second and third copy of the whole (up to 64 MiB) store.
    /// `load_disk` reads whitespace-agnostic JSON, so the stored format is
    /// unchanged apart from being compact.
    fn write_rows<W: std::io::Write>(&self, out: W) -> Result<(), String> {
        use serde::Serializer as _;
        #[derive(Serialize)]
        struct Row {
            store_tag_hex: String,
            message_id_hex: String,
            created_at_ms: u64,
            expires_at_ms: u64,
            flags: u16,
            packed_envelope_hex: String,
            custody_sig_hex: Option<String>,
        }
        let rows = self.items.iter().map(|i| &i.object).map(|o| Row {
            store_tag_hex: hex::encode(o.store_tag),
            message_id_hex: hex::encode(o.message_id),
            created_at_ms: o.created_at_ms,
            expires_at_ms: o.expires_at_ms,
            flags: o.flags,
            packed_envelope_hex: hex::encode(&o.packed_envelope),
            custody_sig_hex: o.custody_sig.map(hex::encode),
        });
        let mut serializer = serde_json::Serializer::new(out);
        (&mut serializer)
            .collect_seq(rows)
            .map_err(|e| e.to_string())
    }

    fn write_snapshot(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let parent = path
                .parent()
                .ok_or_else(|| "mailbox path has no parent".to_string())?;
            let tmp = parent.join(format!(
                ".mailbox.tmp.{}.{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            let result = (|| -> Result<(), String> {
                let file = std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&tmp)
                    .map_err(|e| e.to_string())?;
                let mut writer = std::io::BufWriter::new(file);
                self.write_rows(&mut writer)?;
                writer.flush().map_err(|e| e.to_string())?;
                writer.get_ref().sync_all().map_err(|e| e.to_string())?;
                std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
                Ok(())
            })();
            if result.is_err() {
                let _ = std::fs::remove_file(&tmp);
                return result;
            }
            // The rename has committed: a directory fsync problem must not be
            // reported as a failed write (see `sync_dir_best_effort`).
            crate::paths::sync_dir_best_effort(parent);
            Ok(())
        }
        #[cfg(not(unix))]
        {
            // Temp + fsync + replace, never a truncate-and-write: a torn
            // snapshot makes the whole mailbox unloadable (fail-closed).
            let mut raw = Vec::new();
            self.write_rows(&mut raw)?;
            crate::paths::atomic_write_private(path, &raw)
        }
    }

    pub fn load_disk(path: &std::path::Path, max_per_tag: usize) -> Result<Self, String> {
        #[derive(Deserialize)]
        struct Row {
            store_tag_hex: String,
            message_id_hex: String,
            created_at_ms: u64,
            expires_at_ms: u64,
            flags: u16,
            packed_envelope_hex: String,
            custody_sig_hex: Option<String>,
        }
        fn row_object(r: Row) -> Result<StoreObject, String> {
            let st = hex::decode(&r.store_tag_hex).map_err(|e| e.to_string())?;
            let mid = hex::decode(&r.message_id_hex).map_err(|e| e.to_string())?;
            if st.len() != 16 || mid.len() != 16 {
                return Err("invalid mailbox row identifier".into());
            }
            let mut store_tag = [0u8; 16];
            store_tag.copy_from_slice(&st);
            let mut message_id = [0u8; 16];
            message_id.copy_from_slice(&mid);
            let packed_envelope = hex::decode(&r.packed_envelope_hex).map_err(|e| e.to_string())?;
            let custody_sig = match r.custody_sig_hex {
                Some(h) => {
                    let v = hex::decode(h).map_err(|e| e.to_string())?;
                    if v.len() != 64 {
                        return Err("invalid custody signature length".into());
                    }
                    let mut s = [0u8; 64];
                    s.copy_from_slice(&v);
                    Some(s)
                }
                None => None,
            };
            Ok(StoreObject {
                store_tag,
                message_id,
                created_at_ms: r.created_at_ms,
                expires_at_ms: r.expires_at_ms,
                flags: r.flags,
                packed_envelope,
                custody_sig,
            })
        }
        let mut mb = Self::new(max_per_tag);
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return Ok(mb);
        };
        if !metadata.is_file() || metadata.len() > MAX_MAILBOX_DISK_BYTES {
            return Err("mailbox file exceeds resource limit".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.file_type().is_symlink()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o077 != 0
            {
                return Err("mailbox file is not a private regular file".into());
            }
        }
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        // An unparseable snapshot is corrupt as a whole: fail closed.
        let rows: Vec<Row> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let mut dropped = false;
        for r in rows {
            // A single row that no longer passes current rules (expired,
            // malformed, over a tightened limit) is skipped rather than making
            // the whole mailbox unloadable; the next save drops it for good.
            match row_object(r) {
                Ok(obj) if !obj.expired(now_ms) => {
                    if mb.insert(obj).is_err() {
                        dropped = true;
                    }
                }
                _ => dropped = true,
            }
        }
        mb.dirty.store(dropped, std::sync::atomic::Ordering::SeqCst);
        Ok(mb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{EnvType, Envelope};

    fn packed_envelope(message_id: [u8; 16], expires_at: u64, body: u8) -> Vec<u8> {
        let id = Identity::generate();
        let mut env = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id,
            routing_tag: [3u8; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at,
            hop_limit: 4,
            replication_budget: 2,
            anti_replay_nonce: [4u8; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![body],
            sender_authentication: vec![],
        };
        env.sign_with(&id);
        env.pack()
    }

    #[test]
    fn mailbox_rotates_and_unlinks() {
        let k: Vec<u8> = (0u8..32).collect();
        let a = mailbox_tag(&k, 100, 0);
        let b = mailbox_tag(&k, 100, 1);
        let c = mailbox_tag(&k, 101, 0);
        assert_ne!(a, b);
        assert_ne!(a, c);
        let st = store_tag_from_mailbox(&a);
        assert_ne!(st, a);
    }

    #[test]
    fn mailbox_tag_matches_shared_vector() {
        let k: Vec<u8> = (0u8..32).collect();
        let tag = mailbox_tag(&k, 1_700_000_000, 0);
        assert_eq!(hex::encode(tag), "cb693b77e3f986fe8394872d73f35428");
        assert_eq!(
            hex::encode(store_tag_from_mailbox(&tag)),
            "648ba67cde1b71c8257b0c7e3c8315b3"
        );
    }

    #[test]
    fn overlap_includes_prev_epoch() {
        let k = [9u8; 32];
        let [cur, prev] = mailbox_tags_with_overlap(&k, 5, 0);
        assert_eq!(cur, mailbox_tag(&k, 5, 0));
        assert_eq!(prev, mailbox_tag(&k, 4, 0));
    }

    #[test]
    fn store_object_roundtrip_with_custody() {
        let id = Identity::generate();
        let mut obj = StoreObject {
            store_tag: [1u8; 16],
            message_id: [2u8; 16],
            created_at_ms: 1,
            expires_at_ms: u64::MAX,
            flags: 0,
            packed_envelope: packed_envelope([2u8; 16], u64::MAX, 7),
            custody_sig: None,
        };
        obj.sign_custody(&id).unwrap();
        let packed = obj.pack().unwrap();
        let got = StoreObject::unpack(&packed).unwrap();
        assert_eq!(got.packed_envelope, obj.packed_envelope);
        assert!(got.verify_custody(&id.public_key_bytes()));

        let mut trailing = packed;
        trailing.push(0);
        assert!(StoreObject::unpack(&trailing).is_err());
    }

    #[test]
    fn mailbox_put_get_purge() {
        let mut mb = StoreMailbox::new(2);
        let obj = StoreObject {
            store_tag: [3u8; 16],
            message_id: [4u8; 16],
            created_at_ms: 1,
            expires_at_ms: 9_000_000_000_000,
            flags: 0,
            packed_envelope: packed_envelope([4u8; 16], 9_000_000_000_000, 1),
            custody_sig: None,
        };
        mb.put(obj).unwrap();
        assert_eq!(mb.get(&[3u8; 16], 50).len(), 1);
        // Force-expire through the private test fixture; production deletion is
        // TTL-only and intentionally exposes no message-ID deletion API.
        let mut expired_mb = StoreMailbox::new(2);
        let expired = StoreObject {
            store_tag: [3u8; 16],
            message_id: [5u8; 16],
            created_at_ms: 1,
            expires_at_ms: 100,
            flags: 0,
            packed_envelope: packed_envelope([5u8; 16], 100, 2),
            custody_sig: None,
        };
        let digest =
            authenticated_object_digest(&Envelope::unpack(&expired.packed_envelope).unwrap());
        expired_mb.items.push(StoredObject {
            object: expired,
            digest,
        });
        assert!(expired_mb.get(&[3u8; 16], 100).is_empty());
        assert_eq!(expired_mb.purge_expired(100), 1);
    }

    #[test]
    fn same_public_id_different_objects_do_not_poison_each_other() {
        let mid = [0x44u8; 16];
        let expires = 9_000_000_000_000;
        let mut mailbox = StoreMailbox::new_with_limits(4, 4);
        for body in [1u8, 2u8] {
            mailbox
                .put(StoreObject {
                    store_tag: [8u8; 16],
                    message_id: mid,
                    created_at_ms: 1,
                    expires_at_ms: expires,
                    flags: 0,
                    packed_envelope: packed_envelope(mid, expires, body),
                    custody_sig: None,
                })
                .unwrap();
        }
        assert_eq!(mailbox.get(&[8u8; 16], 2).len(), 2);
    }

    #[test]
    fn identical_object_can_be_published_under_overlapping_mailbox_tags() {
        let mid = [0x55u8; 16];
        let expires = 9_000_000_000_000;
        let packed = packed_envelope(mid, expires, 3);
        let mut mailbox = StoreMailbox::new_with_limits(4, 4);
        for tag in [[1u8; 16], [2u8; 16]] {
            mailbox
                .put(StoreObject {
                    store_tag: tag,
                    message_id: mid,
                    created_at_ms: 1,
                    expires_at_ms: expires,
                    flags: 0,
                    packed_envelope: packed.clone(),
                    custody_sig: None,
                })
                .unwrap();
        }
        assert_eq!(mailbox.get(&[1u8; 16], 2).len(), 1);
        assert_eq!(mailbox.get(&[2u8; 16], 2).len(), 1);
    }

    #[test]
    fn aggregate_byte_limit_is_hard() {
        let expires = 9_000_000_000_000;
        let first = packed_envelope([1u8; 16], expires, 1);
        let limit = first.len();
        let mut mailbox = StoreMailbox::new_with_resource_limits(4, 4, limit);
        mailbox
            .put(StoreObject {
                store_tag: [1u8; 16],
                message_id: [1u8; 16],
                created_at_ms: 1,
                expires_at_ms: expires,
                flags: 0,
                packed_envelope: first,
                custody_sig: None,
            })
            .unwrap();
        assert_eq!(
            mailbox
                .put(StoreObject {
                    store_tag: [2u8; 16],
                    message_id: [2u8; 16],
                    created_at_ms: 1,
                    expires_at_ms: expires,
                    flags: 0,
                    packed_envelope: packed_envelope([2u8; 16], expires, 2),
                    custody_sig: None,
                })
                .unwrap_err(),
            "STORE_FULL"
        );
    }

    #[cfg(unix)]
    #[test]
    fn disk_snapshot_is_private_atomic_and_reloadable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox.json");
        let expires = 9_000_000_000_000;
        let mut mailbox = StoreMailbox::new(4);
        mailbox
            .put(StoreObject {
                store_tag: [7u8; 16],
                message_id: [8u8; 16],
                created_at_ms: 1,
                expires_at_ms: expires,
                flags: 0,
                packed_envelope: packed_envelope([8u8; 16], expires, 9),
                custody_sig: None,
            })
            .unwrap();
        mailbox.save_disk(&path).unwrap();

        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(std::fs::read_dir(dir.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".mailbox.tmp")));
        let loaded = StoreMailbox::load_disk(&path, 4).unwrap();
        assert_eq!(loaded.get(&[7u8; 16], 2).len(), 1);
    }

    fn sample_object(tag: u8, mid: u8, body: u8) -> StoreObject {
        let expires = 9_000_000_000_000;
        StoreObject {
            store_tag: [tag; 16],
            message_id: [mid; 16],
            created_at_ms: 1,
            expires_at_ms: expires,
            flags: 0,
            packed_envelope: packed_envelope([mid; 16], expires, body),
            custody_sig: None,
        }
    }

    #[test]
    fn duplicate_put_does_not_rewrite_the_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox.json");
        let mut mailbox = StoreMailbox::new(4);
        let object = sample_object(1, 2, 3);
        assert!(mailbox.insert(object.clone()).unwrap());
        mailbox.save_disk(&path).unwrap();
        // Sentinel content (mode preserved) proves whether a rewrite happens.
        std::fs::write(&path, b"[]").unwrap();
        for _ in 0..3 {
            assert!(!mailbox.insert(object.clone()).unwrap(), "exact duplicate");
            mailbox.put(object.clone()).unwrap();
            mailbox.save_disk(&path).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), b"[]");
        assert!(mailbox.insert(sample_object(1, 5, 6)).unwrap());
        mailbox.save_disk(&path).unwrap();
        assert_eq!(
            StoreMailbox::load_disk(&path, 4)
                .unwrap()
                .get(&[1; 16], 2)
                .len(),
            2
        );
    }

    /// The snapshot is streamed row by row as compact JSON (no whole-store
    /// pretty-printed string, no full-store hex copy) and stays loadable, with
    /// custody signatures intact, and leaves no temp file behind.
    #[test]
    fn snapshot_is_compact_streamed_json_that_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox.json");
        let store_id = Identity::generate();
        let mut mailbox = StoreMailbox::new(4);
        let mut signed = sample_object(1, 2, 3);
        signed.sign_custody(&store_id).unwrap();
        mailbox.put(signed.clone()).unwrap();
        mailbox.put(sample_object(1, 4, 5)).unwrap();
        mailbox.put(sample_object(2, 6, 7)).unwrap();
        mailbox.save_disk(&path).unwrap();
        // A second save of changed contents replaces the file atomically.
        mailbox.put(sample_object(2, 8, 9)).unwrap();
        mailbox.save_disk(&path).unwrap();

        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.contains(&b'\n'), "snapshot must be compact JSON");
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&raw).unwrap();
        assert_eq!(rows.len(), 4);
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("mailbox.json")]);

        let loaded = StoreMailbox::load_disk(&path, 4).unwrap();
        assert_eq!(loaded.get(&[1; 16], 2).len(), 2);
        assert_eq!(loaded.get(&[2; 16], 2).len(), 2);
        let back = loaded
            .get(&[1; 16], 2)
            .into_iter()
            .find(|o| o.message_id == [2; 16])
            .unwrap();
        assert!(back.verify_custody(&store_id.public_key_bytes()));
        assert_eq!(*back, signed);
    }

    #[test]
    fn one_invalid_row_does_not_make_the_mailbox_unloadable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mailbox.json");
        let mut mailbox = StoreMailbox::new(4);
        mailbox.put(sample_object(1, 2, 3)).unwrap();
        mailbox.put(sample_object(1, 4, 5)).unwrap();
        mailbox.save_disk(&path).unwrap();
        let mut rows: Vec<serde_json::Value> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        rows[0]["packed_envelope_hex"] = serde_json::Value::String("zz".into());
        std::fs::write(&path, serde_json::to_vec(&rows).unwrap()).unwrap();

        let loaded = StoreMailbox::load_disk(&path, 4).unwrap();
        assert_eq!(loaded.get(&[1; 16], 2).len(), 1);
        // A tightened per-tag limit also drops excess rows instead of failing.
        let mut full = StoreMailbox::new(4);
        full.put(sample_object(7, 1, 1)).unwrap();
        full.put(sample_object(7, 2, 2)).unwrap();
        full.save_disk(&path).unwrap();
        assert_eq!(
            StoreMailbox::load_disk(&path, 1)
                .unwrap()
                .get(&[7; 16], 2)
                .len(),
            1
        );
        // A snapshot that is not JSON at all still fails closed.
        std::fs::write(&path, b"{not json").unwrap();
        assert!(StoreMailbox::load_disk(&path, 4).is_err());
    }

    #[test]
    fn total_and_per_tag_limits_are_hard() {
        let expires = 9_000_000_000_000;
        let mut mailbox = StoreMailbox::new_with_limits(1, 2);
        for i in 0..2u8 {
            let mid = [i; 16];
            mailbox
                .put(StoreObject {
                    store_tag: [i; 16],
                    message_id: mid,
                    created_at_ms: 1,
                    expires_at_ms: expires,
                    flags: 0,
                    packed_envelope: packed_envelope(mid, expires, i),
                    custody_sig: None,
                })
                .unwrap();
        }
        let mid = [9u8; 16];
        assert_eq!(
            mailbox
                .put(StoreObject {
                    store_tag: [9u8; 16],
                    message_id: mid,
                    created_at_ms: 1,
                    expires_at_ms: expires,
                    flags: 0,
                    packed_envelope: packed_envelope(mid, expires, 9),
                    custody_sig: None,
                })
                .unwrap_err(),
            "STORE_FULL"
        );
    }
}
