//! Multi-device contact sync + signed revocation propagation (§39).
//!
//! Software-feasible subset:
//! - Encrypt device-to-device contact sync with a user-identity-derived key
//!   (no central plaintext store).
//! - Signed `RevocationRecord` with monotonic epoch; merge is denylist-sticky.
//! - Partition tests: revoked device cannot re-add; partitioned peer may lag
//!   until it observes a higher-epoch revocation (documented limitation).
//!
//! Not in V1 wire gossip: live network push of revocation (no dedicated DHT
//! record type frozen yet). Callers exchange sealed blobs / records OOB or
//! via opaque store-carry.

use crate::device_cert::{DeviceCertificate, DeviceRegistry, RevokedDeviceLineage};
use crate::device_revocation::{claim_digest, DeviceRevocationV1};
use crate::identity::Identity;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};

const SYNC_MAGIC: &[u8; 8] = b"RDCS1\0\0\0"; // Raven Device Contact Sync v1
const SYNC_INFO: &[u8] = b"raven/rvn1/device-sync/contacts/v1";
const REVOKE_DOMAIN: &[u8] = b"rvn1/devrevoke/v1";
/// Verified RVDR1 claims (exact record bytes), kept beside `revocations.json`.
const RVDR1_CLAIMS_FILE: &str = "device_revocations_rvdr1.json";

/// Public contact fields only — never private keys.
/// Raven Tag V1: petname (Layer C) + public_tag (Layer B) + pin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncContact {
    /// Layer C — device-local petname (primary UI label).
    #[serde(default)]
    pub petname: String,
    /// Layer B — public Raven Tag / Alias V1 (NOT globally unique).
    #[serde(default)]
    pub public_tag: String,
    /// Legacy alias field (migrated into public_tag when empty).
    #[serde(default)]
    pub alias: String,
    pub address: String,
    pub pub_hex: String,
    /// Soft-unique pin: Tag+key locked after QR/verify.
    #[serde(default)]
    pub pinned: bool,
}

impl SyncContact {
    /// Normalize legacy rows that only had `alias`.
    pub fn migrate(mut self) -> Self {
        if self.public_tag.is_empty() && !self.alias.is_empty() {
            self.public_tag = self.alias.clone();
        }
        if self.petname.is_empty() {
            if !self.public_tag.is_empty() {
                self.petname = self.public_tag.clone();
            } else if !self.alias.is_empty() {
                self.petname = self.alias.clone();
            }
        }
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactSyncPlaintext {
    pub schema: u32,
    pub from_device_id: String,
    pub contacts: Vec<SyncContact>,
    pub issued_at_ms: u64,
}

/// User-identity-signed device revocation (local + exchangeable).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationRecord {
    pub schema: u32,
    pub user_ed_pub_hex: String,
    pub device_id: String,
    /// Monotonic per-user epoch; higher wins on merge.
    pub epoch: u64,
    pub issued_at_ms: u64,
    pub reason: String,
    pub signature_hex: String,
}

impl RevocationRecord {
    pub fn issue(
        user: &Identity,
        device_id: impl Into<String>,
        epoch: u64,
        issued_at_ms: u64,
        reason: impl Into<String>,
    ) -> Result<Self, String> {
        let device_id = device_id.into();
        let reason = reason.into();
        let user_ed = user.public_key_bytes();
        let sb = revocation_signing_bytes(&user_ed, &device_id, epoch, issued_at_ms, &reason);
        let signature = user.sign(&sb);
        Ok(Self {
            schema: 1,
            user_ed_pub_hex: hex::encode(user_ed),
            device_id,
            epoch,
            issued_at_ms,
            reason,
            signature_hex: hex::encode(signature),
        })
    }

    pub fn verify(&self) -> Result<(), String> {
        if self.schema != 1 {
            return Err("REVOKE_SCHEMA".into());
        }
        let user_ed = decode_32_hex(&self.user_ed_pub_hex)?;
        let sig = decode_64_hex(&self.signature_hex)?;
        let sb = revocation_signing_bytes(
            &user_ed,
            &self.device_id,
            self.epoch,
            self.issued_at_ms,
            &self.reason,
        );
        if !Identity::verify(&user_ed, &sb, &sig) {
            return Err("REVOKE_BAD_SIG".into());
        }
        Ok(())
    }
}

fn revocation_signing_bytes(
    user_ed: &[u8; 32],
    device_id: &str,
    epoch: u64,
    issued_at_ms: u64,
    reason: &str,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(REVOKE_DOMAIN);
    v.extend_from_slice(user_ed);
    v.extend_from_slice(&(device_id.len() as u32).to_be_bytes());
    v.extend_from_slice(device_id.as_bytes());
    v.extend_from_slice(&epoch.to_be_bytes());
    v.extend_from_slice(&issued_at_ms.to_be_bytes());
    v.extend_from_slice(&(reason.len() as u32).to_be_bytes());
    v.extend_from_slice(reason.as_bytes());
    v
}

fn decode_32_hex(s: &str) -> Result<[u8; 32], String> {
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    if v.len() != 32 {
        return Err("expected 32 bytes".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

fn decode_64_hex(s: &str) -> Result<[u8; 64], String> {
    let v = hex::decode(s).map_err(|e| e.to_string())?;
    if v.len() != 64 {
        return Err("expected 64 bytes".into());
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(&v);
    Ok(a)
}

/// Derive contact-sync AEAD key from user identity seed (never printed).
pub fn derive_device_sync_key(user: &Identity) -> [u8; 32] {
    let seed = user.seed_bytes();
    let hk = Hkdf::<Sha256>::new(Some(b"raven-device-sync"), &seed);
    let mut okm = [0u8; 32];
    hk.expand(SYNC_INFO, &mut okm).expect("hkdf");
    okm
}

/// Seal contact sync for another authorized device of the same user.
pub fn seal_contact_sync(user: &Identity, plain: &ContactSyncPlaintext) -> Result<Vec<u8>, String> {
    let key = derive_device_sync_key(user);
    let pt = serde_json::to_vec(plain).map_err(|e| e.to_string())?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let aad = user.public_key_bytes();
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &pt,
                aad: &aad,
            },
        )
        .map_err(|_| "device sync seal failed".to_string())?;
    let mut wire = Vec::with_capacity(8 + 12 + ct.len());
    wire.extend_from_slice(SYNC_MAGIC);
    wire.extend_from_slice(&nonce_bytes);
    wire.extend_from_slice(&ct);
    Ok(wire)
}

/// Unseal contact sync. Caller must ensure `from_device_id` is authorized.
pub fn unseal_contact_sync(user: &Identity, wire: &[u8]) -> Result<ContactSyncPlaintext, String> {
    if wire.len() < 8 + 12 + 16 {
        return Err("truncated device sync".into());
    }
    if &wire[..8] != SYNC_MAGIC {
        return Err("bad device sync magic".into());
    }
    let key = derive_device_sync_key(user);
    let nonce = Nonce::from_slice(&wire[8..20]);
    let ct = &wire[20..];
    let aad = user.public_key_bytes();
    let cipher = ChaCha20Poly1305::new((&key).into());
    let pt = cipher
        .decrypt(nonce, Payload { msg: ct, aad: &aad })
        .map_err(|_| "device sync unseal failed".to_string())?;
    serde_json::from_slice(&pt).map_err(|e| e.to_string())
}

/// Allowed clock skew for a sync blob's `issued_at_ms` (sender ahead of us).
const SYNC_FUTURE_SKEW_MS: u64 = 5 * 60 * 1000;
/// Per-sender high-water marks of imported sync blobs (`from_device_id` → ms).
const SYNC_SEEN_FILE: &str = "device_sync_seen.json";
const SYNC_SEEN_LOCK: &str = ".device_sync_seen.lock.sqlite";

fn unseal_contact_sync_checked(
    user: &Identity,
    wire: &[u8],
    now_ms: u64,
) -> Result<ContactSyncPlaintext, String> {
    let plain = unseal_contact_sync(user, wire)?;
    if plain.schema != 1 {
        return Err("SYNC_SCHEMA".into());
    }
    // A far-future stamp would otherwise pin every later blob as "stale".
    if plain.issued_at_ms > now_ms.saturating_add(SYNC_FUTURE_SKEW_MS) {
        return Err("SYNC_FROM_FUTURE".into());
    }
    Ok(plain)
}

/// Apply sealed sync only if source device is authorized in the local registry.
///
/// NOTE: the sync key derives from the identity seed and `from_device_id` is
/// self-asserted inside the ciphertext, so this is a policy check, not device
/// authentication. Callers that persist contacts should use
/// [`import_contact_sync_checked`], which also refuses replayed/stale blobs.
pub fn import_contact_sync(
    user: &Identity,
    registry: &DeviceRegistry,
    wire: &[u8],
    now_ms: u64,
) -> Result<Vec<SyncContact>, String> {
    let plain = unseal_contact_sync_checked(user, wire, now_ms)?;
    if !registry.is_authorized(&plain.from_device_id, now_ms) {
        return Err("SYNC_FROM_UNAUTHORIZED_OR_REVOKED".into());
    }
    Ok(plain
        .contacts
        .into_iter()
        .map(SyncContact::migrate)
        .collect())
}

/// Fail-closed import for a data dir: the device registry is loaded with the
/// checked loader (a corrupt registry is an error, never "no devices"), the
/// sender must be authorized — except on a data dir with no registry file yet
/// (first import before any device cert), where only the seal key is checked —
/// and `issued_at_ms` must be strictly newer than the last blob imported from
/// the same `from_device_id`, so replaying an old export cannot resurrect
/// deleted contacts. The high-water mark is recorded before returning, so a
/// caller whose own save can still fail after this returns should use
/// [`import_contact_sync_checked_then`] instead.
pub fn import_contact_sync_checked(
    data_dir: &std::path::Path,
    user: &Identity,
    wire: &[u8],
    now_ms: u64,
) -> Result<Vec<SyncContact>, String> {
    import_contact_sync_checked_then(data_dir, user, wire, now_ms, Ok)
}

/// [`import_contact_sync_checked`] with a commit step. `apply` receives the
/// verified contacts and persists them; the replay high-water mark is recorded
/// only after `apply` returns `Ok`, and its value is returned.
///
/// If `apply` fails (an unreadable or unwritable contacts store), the mark is
/// untouched, so the same blob is accepted again once the user has fixed the
/// problem instead of being refused forever as `SYNC_REPLAY_OR_STALE`. The
/// data-dir lock that guards the mark is held while `apply` runs, so imports
/// are serialized; `apply` must not take that lock itself.
pub fn import_contact_sync_checked_then<T>(
    data_dir: &std::path::Path,
    user: &Identity,
    wire: &[u8],
    now_ms: u64,
    apply: impl FnOnce(Vec<SyncContact>) -> Result<T, String>,
) -> Result<T, String> {
    let registry = crate::device_cert::load_device_registry_checked(data_dir)?;
    let plain = unseal_contact_sync_checked(user, wire, now_ms)?;
    let first_import = !crate::device_cert::device_registry_path(data_dir).exists();
    if !first_import && !registry.is_authorized(&plain.from_device_id, now_ms) {
        return Err("SYNC_FROM_UNAUTHORIZED_OR_REVOKED".into());
    }
    let _lock = crate::paths::DataDirLock::acquire(data_dir, SYNC_SEEN_LOCK)?;
    let seen_path = data_dir.join(SYNC_SEEN_FILE);
    let mut seen: BTreeMap<String, u64> = if seen_path.exists() {
        let raw = std::fs::read_to_string(&seen_path)
            .map_err(|e| format!("device sync seen read: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("device sync seen corrupt: {e}"))?
    } else {
        BTreeMap::new()
    };
    if let Some(last) = seen.get(&plain.from_device_id) {
        if plain.issued_at_ms <= *last {
            return Err("SYNC_REPLAY_OR_STALE".into());
        }
    }
    let applied = apply(
        plain
            .contacts
            .into_iter()
            .map(SyncContact::migrate)
            .collect(),
    )?;
    seen.insert(plain.from_device_id.clone(), plain.issued_at_ms);
    let raw = serde_json::to_string_pretty(&seen).map_err(|e| e.to_string())?;
    crate::paths::atomic_write_private(&seen_path, raw.as_bytes())?;
    Ok(applied)
}

/// Persist revocation store as JSON under data dir (OOB exchangeable).
pub fn revocation_store_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("revocations.json")
}

/// Merge revocation records: sticky denylist; higher epoch wins per
/// `(user_ed_pub, device_id)` so shared labels like `ash-primary` do not collide.
///
/// Legacy `rvn1/devrevoke/v1` records name only `(user_ed_pub, device_id)`.
/// Verified `RavenDeviceRevocationV1` (RVDR1) claims name the full lineage and
/// are union-applied (append-only, keyed by `claim_digest`); see
/// [`RevocationStore::denies_certificate`].
#[derive(Debug, Default, Clone)]
pub struct RevocationStore {
    /// composite key → best (highest epoch) verified record
    by_device: HashMap<String, RevocationRecord>,
    /// claim_digest → verified RVDR1 claim (never removed)
    rvdr1: BTreeMap<[u8; 32], Rvdr1Claim>,
}

/// One accepted RVDR1 claim and the identity key that signed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rvdr1Claim {
    pub identity_ed_pub: [u8; 32],
    pub claim_digest: [u8; 32],
    pub record: DeviceRevocationV1,
    pub exact_record_bytes: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Rvdr1ClaimRow {
    identity_ed_pub_hex: String,
    record_hex: String,
}

/// `device_id` is compared as exact bytes (RAVEN_DEVICE_REVOCATION_V1 §2.3, no
/// normalization); only the hex spelling of the user key is canonicalized.
fn revocation_store_key(user_ed_pub_hex: &str, device_id: &str) -> String {
    format!("{}:{}", user_ed_pub_hex.trim().to_lowercase(), device_id)
}

pub fn rvdr1_claims_path(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join(RVDR1_CLAIMS_FILE)
}

impl RevocationStore {
    pub fn load(data_dir: &std::path::Path) -> Self {
        Self::load_checked(data_dir).unwrap_or_default()
    }

    /// Missing file → empty store. Corrupt JSON / bad signature / epoch conflict
    /// → error (fail-closed for policy). RVDR1 claims are re-verified on load.
    pub fn load_checked(data_dir: &std::path::Path) -> Result<Self, String> {
        let mut store = Self::default();
        let path = revocation_store_path(data_dir);
        if path.exists() {
            let raw = std::fs::read_to_string(&path)
                .map_err(|e| format!("revocation store read: {e}"))?;
            let recs: Vec<RevocationRecord> =
                serde_json::from_str(&raw).map_err(|e| format!("revocation store corrupt: {e}"))?;
            for r in recs {
                store.apply(r)?;
            }
        }
        let rvdr1_path = rvdr1_claims_path(data_dir);
        if rvdr1_path.exists() {
            let raw = std::fs::read_to_string(&rvdr1_path)
                .map_err(|e| format!("rvdr1 claim store read: {e}"))?;
            let rows: Vec<Rvdr1ClaimRow> = serde_json::from_str(&raw)
                .map_err(|e| format!("rvdr1 claim store corrupt: {e}"))?;
            for row in rows {
                let identity = decode_32_hex(&row.identity_ed_pub_hex)
                    .map_err(|e| format!("rvdr1 claim store corrupt: {e}"))?;
                let wire = hex::decode(&row.record_hex)
                    .map_err(|e| format!("rvdr1 claim store corrupt: {e}"))?;
                store
                    .apply_rvdr1(&identity, &wire)
                    .map_err(|e| format!("rvdr1 claim store corrupt: {e}"))?;
            }
        }
        Ok(store)
    }

    pub fn save(&self, data_dir: &std::path::Path) -> Result<(), String> {
        std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
        let path = revocation_store_path(data_dir);
        let recs: Vec<&RevocationRecord> = self.records().collect();
        let raw = serde_json::to_string_pretty(&recs).map_err(|e| e.to_string())?;
        crate::paths::atomic_write_private(&path, raw.as_bytes())?;
        // Append-only: an empty in-memory claim set never truncates the file.
        if !self.rvdr1.is_empty() {
            let rows: Vec<Rvdr1ClaimRow> = self
                .rvdr1
                .values()
                .map(|c| Rvdr1ClaimRow {
                    identity_ed_pub_hex: hex::encode(c.identity_ed_pub),
                    record_hex: hex::encode(&c.exact_record_bytes),
                })
                .collect();
            let raw = serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?;
            crate::paths::atomic_write_private(&rvdr1_claims_path(data_dir), raw.as_bytes())?;
        }
        Ok(())
    }

    pub fn apply(&mut self, rec: RevocationRecord) -> Result<bool, String> {
        rec.verify()?;
        let key = revocation_store_key(&rec.user_ed_pub_hex, &rec.device_id);
        match self.by_device.get(&key) {
            Some(prev) if prev.epoch > rec.epoch => Ok(false),
            Some(prev) if prev.epoch == rec.epoch => {
                // Same epoch: accept if identical; reject conflicting payloads.
                if prev == &rec {
                    Ok(false)
                } else {
                    Err("REVOKE_EPOCH_CONFLICT".into())
                }
            }
            _ => {
                self.by_device.insert(key, rec);
                Ok(true)
            }
        }
    }

    /// Authenticated ingest of one exact RVDR1 record signed by
    /// `identity_ed_pub` (strict parse + address binding + signature).
    /// Union semantics: a new `claim_digest` only ever adds deny coverage.
    /// Returns `Ok(false)` for an already-applied claim.
    pub fn apply_rvdr1(&mut self, identity_ed_pub: &[u8; 32], wire: &[u8]) -> Result<bool, String> {
        let record = DeviceRevocationV1::decode(wire)?;
        record.verify(identity_ed_pub)?;
        let digest = claim_digest(wire);
        if self.rvdr1.contains_key(&digest) {
            return Ok(false);
        }
        self.rvdr1.insert(
            digest,
            Rvdr1Claim {
                identity_ed_pub: *identity_ed_pub,
                claim_digest: digest,
                record,
                exact_record_bytes: wire.to_vec(),
            },
        );
        Ok(true)
    }

    pub fn is_revoked(&self, user_ed_pub_hex: &str, device_id: &str) -> bool {
        self.by_device
            .contains_key(&revocation_store_key(user_ed_pub_hex, device_id))
    }

    /// Lineage deny (RAVEN_DEVICE_REVOCATION_V1 §2, §5.6 item 3) for `cert`
    /// under its own identity: a legacy record for its exact `device_id`, or an
    /// RVDR1 claim covering any of `device_id`, `device_ed_pub`, `device_x_pub`
    /// or `device_cert_hash` — so a lineage re-certified under a new
    /// `device_id` with reused keys stays denied.
    pub fn denies_certificate(&self, cert: &DeviceCertificate) -> Result<bool, String> {
        if self.is_revoked(&hex::encode(cert.user_ed_pub), &cert.device_id) {
            return Ok(true);
        }
        let mut cert_hash = None;
        for claim in self.rvdr1.values() {
            if claim.identity_ed_pub != cert.user_ed_pub {
                continue;
            }
            let r = &claim.record;
            if r.device_id.as_slice() == cert.device_id.as_bytes()
                || r.device_ed_pub == cert.device_ed_pub
                || r.device_x_pub == cert.device_x_pub
            {
                return Ok(true);
            }
            let hash = match cert_hash {
                Some(h) => h,
                None => {
                    let h = crate::pair_init::device_certificate_hash(cert)
                        .map_err(|e| format!("device cert hash: {e}"))?;
                    cert_hash = Some(h);
                    h
                }
            };
            if r.device_cert_hash == hash {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn epoch_of(&self, user_ed_pub_hex: &str, device_id: &str) -> Option<u64> {
        self.by_device
            .get(&revocation_store_key(user_ed_pub_hex, device_id))
            .map(|r| r.epoch)
    }

    /// Apply into a DeviceRegistry (local denylist for this identity's devices).
    pub fn push_into_registry(&self, user_ed_pub_hex: &str, reg: &mut DeviceRegistry) {
        let want = user_ed_pub_hex.trim().to_lowercase();
        for rec in self.by_device.values() {
            if rec.user_ed_pub_hex.eq_ignore_ascii_case(&want) {
                reg.revoke(&rec.device_id);
            }
        }
        for claim in self.rvdr1.values() {
            if hex::encode(claim.identity_ed_pub) != want {
                continue;
            }
            let r = &claim.record;
            // Non-UTF-8 ids cannot name a DeviceCertificate; keys/hash still retire.
            let device_id = String::from_utf8(r.device_id.clone()).unwrap_or_default();
            if !device_id.is_empty() {
                reg.revoke(&device_id);
            }
            let lineage = RevokedDeviceLineage {
                device_id,
                device_ed_pub: r.device_ed_pub,
                device_x_pub: r.device_x_pub,
                device_cert_hash: r.device_cert_hash,
            };
            if !reg.revoked_lineage.contains(&lineage) {
                reg.revoked_lineage.push(lineage);
            }
        }
    }

    pub fn records(&self) -> impl Iterator<Item = &RevocationRecord> {
        self.by_device.values()
    }

    pub fn rvdr1_claims(&self) -> impl Iterator<Item = &Rvdr1Claim> {
        self.rvdr1.values()
    }
}

/// Partition limitation: without observing a revocation, a peer may still
/// treat a device as authorized. Software test models lagging replica B.
pub fn partition_lag_allows_stale_auth(
    fresh: &DeviceRegistry,
    lagging: &DeviceRegistry,
    device_id: &str,
    now_ms: u64,
) -> bool {
    !fresh.is_authorized(device_id, now_ms) && lagging.is_authorized(device_id, now_ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_cert::DeviceCertificate;

    fn issue_phone(user: &Identity, id: &str) -> DeviceCertificate {
        let device = Identity::generate();
        DeviceCertificate::issue(
            user,
            device.public_key_bytes(),
            [3u8; 32],
            id,
            1,
            u64::MAX / 2,
            1,
        )
        .unwrap()
    }

    #[test]
    fn encrypted_contact_sync_roundtrip() {
        let user = Identity::generate();
        let mut reg = DeviceRegistry::default();
        reg.add(issue_phone(&user, "phone-a"), 100).unwrap();
        let plain = ContactSyncPlaintext {
            schema: 1,
            from_device_id: "phone-a".into(),
            contacts: vec![SyncContact {
                petname: "Bob Desk".into(),
                public_tag: "bob".into(),
                alias: "bob".into(),
                address: "rvn1qqqq".into(),
                pub_hex: "aa".into(),
                pinned: true,
            }],
            issued_at_ms: 100,
        };
        let wire = seal_contact_sync(&user, &plain).unwrap();
        assert!(wire.starts_with(SYNC_MAGIC));
        let got = import_contact_sync(&user, &reg, &wire, 100).unwrap();
        assert_eq!(got[0].petname, "Bob Desk");
        assert_eq!(got[0].public_tag, "bob");
        assert!(got[0].pinned);
    }

    #[test]
    fn revoked_device_cannot_push_sync() {
        let user = Identity::generate();
        let mut reg = DeviceRegistry::default();
        reg.add(issue_phone(&user, "phone-lost"), 100).unwrap();
        let plain = ContactSyncPlaintext {
            schema: 1,
            from_device_id: "phone-lost".into(),
            contacts: vec![],
            issued_at_ms: 100,
        };
        let wire = seal_contact_sync(&user, &plain).unwrap();
        reg.revoke("phone-lost");
        assert_eq!(
            import_contact_sync(&user, &reg, &wire, 100).unwrap_err(),
            "SYNC_FROM_UNAUTHORIZED_OR_REVOKED"
        );
    }

    #[test]
    fn revoked_cannot_add_another_device() {
        let user = Identity::generate();
        let mut reg = DeviceRegistry::default();
        reg.add(issue_phone(&user, "term-1"), 100).unwrap();
        reg.revoke("term-1");
        // After revoke, registry refuses re-add of same id (sticky denylist).
        assert!(reg.add(issue_phone(&user, "term-1"), 100).is_err());
        // A separate "issuer" check: revoked devices are not authorized, so
        // policy layer must refuse using them as co-signers — modeled here as
        // is_authorized == false before any add-device UX.
        assert!(!reg.is_authorized("term-1", 100));
    }

    #[test]
    fn revocation_record_merge_and_partition_lag() {
        let user = Identity::generate();
        let mut fresh = DeviceRegistry::default();
        let mut lagging = DeviceRegistry::default();
        let cert = issue_phone(&user, "stolen");
        fresh.add(cert.clone(), 50).unwrap();
        lagging.add(cert, 50).unwrap();

        let rec = RevocationRecord::issue(&user, "stolen", 2, 60, "lost").unwrap();
        let mut store = RevocationStore::default();
        assert!(store.apply(rec.clone()).unwrap());
        store.push_into_registry(&hex::encode(user.public_key_bytes()), &mut fresh);

        assert!(partition_lag_allows_stale_auth(
            &fresh, &lagging, "stolen", 70
        ));

        // Lagging eventually observes the record.
        let mut store_b = RevocationStore::default();
        assert!(store_b.apply(rec).unwrap());
        // Older epoch ignored
        let older = RevocationRecord::issue(&user, "stolen", 1, 55, "old").unwrap();
        assert!(!store_b.apply(older).unwrap());
        store_b.push_into_registry(&hex::encode(user.public_key_bytes()), &mut lagging);
        assert!(!partition_lag_allows_stale_auth(
            &fresh, &lagging, "stolen", 70
        ));
        assert!(!lagging.is_authorized("stolen", 70));
        assert!(store_b.is_revoked(&hex::encode(user.public_key_bytes()), "stolen"));
        let other = Identity::generate();
        assert!(!store_b.is_revoked(&hex::encode(other.public_key_bytes()), "stolen"));
    }

    #[test]
    fn load_checked_rejects_bad_signature() {
        let user = Identity::generate();
        let mut rec = RevocationRecord::issue(&user, "ash-primary", 1, 10, "lost").unwrap();
        rec.signature_hex = "00".repeat(64);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            revocation_store_path(dir.path()),
            serde_json::to_string(&[rec]).unwrap(),
        )
        .unwrap();
        assert!(RevocationStore::load_checked(dir.path()).is_err());
    }

    fn rvdr1_wire(owner: &Identity, cert: &DeviceCertificate) -> Vec<u8> {
        DeviceRevocationV1 {
            identity_address: owner.address(),
            device_id: cert.device_id.as_bytes().to_vec(),
            device_ed_pub: cert.device_ed_pub,
            device_x_pub: cert.device_x_pub,
            device_cert_hash: crate::pair_init::device_certificate_hash(cert).unwrap(),
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
        .unwrap()
    }

    fn cert_for(user: &Identity, ed: [u8; 32], x: [u8; 32], id: &str) -> DeviceCertificate {
        DeviceCertificate::issue(user, ed, x, id, 1, u64::MAX / 2, 1).unwrap()
    }

    /// Every lineage identifier is enforced, not just device_id (§2.1-§2.2).
    #[test]
    fn rvdr1_lineage_denies_reused_keys_under_new_device_id() {
        let user = Identity::generate();
        let dev = Identity::generate();
        let user_pub = user.public_key_bytes();
        let cert = cert_for(&user, dev.public_key_bytes(), [3u8; 32], "phone");
        let wire = rvdr1_wire(&user, &cert);
        let mut store = RevocationStore::default();
        assert!(store.apply_rvdr1(&user_pub, &wire).unwrap());
        assert!(!store.apply_rvdr1(&user_pub, &wire).unwrap(), "idempotent");
        assert!(store.denies_certificate(&cert).unwrap());
        let same_ed = cert_for(&user, dev.public_key_bytes(), [4u8; 32], "phone-2");
        let same_x = cert_for(
            &user,
            Identity::generate().public_key_bytes(),
            [3u8; 32],
            "phone-3",
        );
        let fresh = cert_for(
            &user,
            Identity::generate().public_key_bytes(),
            [5u8; 32],
            "phone-4",
        );
        assert!(store.denies_certificate(&same_ed).unwrap());
        assert!(store.denies_certificate(&same_x).unwrap());
        assert!(!store.denies_certificate(&fresh).unwrap());
        // Scoped to the identity that signed the claim.
        let stranger = Identity::generate();
        let other = cert_for(&stranger, dev.public_key_bytes(), [3u8; 32], "phone");
        assert!(!store.denies_certificate(&other).unwrap());
        // Only the owning identity key may mint; tampered bytes are refused.
        assert!(store
            .apply_rvdr1(&stranger.public_key_bytes(), &wire)
            .is_err());
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(store.apply_rvdr1(&user_pub, &bad).is_err());

        // Persisted beside revocations.json, re-verified on load, never truncated.
        let dir = tempfile::tempdir().unwrap();
        store.save(dir.path()).unwrap();
        RevocationStore::default().save(dir.path()).unwrap();
        let loaded = RevocationStore::load_checked(dir.path()).unwrap();
        assert!(loaded.denies_certificate(&same_x).unwrap());
        let mut reg = DeviceRegistry::default();
        loaded.push_into_registry(&hex::encode(user_pub), &mut reg);
        assert!(reg.denies_lineage(&same_ed).unwrap());
        assert!(!reg.denies_lineage(&fresh).unwrap());
        let rows = serde_json::json!([{
            "identity_ed_pub_hex": hex::encode(user_pub),
            "record_hex": hex::encode(&bad),
        }]);
        std::fs::write(rvdr1_claims_path(dir.path()), rows.to_string()).unwrap();
        assert!(RevocationStore::load_checked(dir.path()).is_err());
    }

    /// RAVEN_DEVICE_REVOCATION_V1 §2.3: device_id equality is exact bytes.
    #[test]
    fn legacy_revocation_device_id_is_exact_bytes() {
        let user = Identity::generate();
        let hex_user = hex::encode(user.public_key_bytes());
        let mut store = RevocationStore::default();
        store
            .apply(RevocationRecord::issue(&user, "ash-primary ", 1, 10, "x").unwrap())
            .unwrap();
        assert!(store.is_revoked(&hex_user, "ash-primary "));
        assert!(!store.is_revoked(&hex_user, "ash-primary"));
        // Distinct ids never collide into one epoch slot.
        store
            .apply(RevocationRecord::issue(&user, "ash-primary", 1, 11, "y").unwrap())
            .unwrap();
        assert!(store.is_revoked(&hex_user, "ash-primary"));
    }

    fn sync_blob(user: &Identity, from: &str, issued_at_ms: u64) -> Vec<u8> {
        let plain = ContactSyncPlaintext {
            schema: 1,
            from_device_id: from.into(),
            contacts: vec![SyncContact {
                petname: "Bob".into(),
                public_tag: String::new(),
                alias: String::new(),
                address: "rvn1qqqq".into(),
                pub_hex: "bb".into(),
                pinned: false,
            }],
            issued_at_ms,
        };
        seal_contact_sync(user, &plain).unwrap()
    }

    /// identity-devices#2: replayed/stale blobs and corrupt registries fail closed.
    #[test]
    fn checked_import_refuses_replay_future_and_corrupt_registry() {
        let user = Identity::generate();
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000u64;
        // First import on a data dir with no registry file: seal key only.
        let old = sync_blob(&user, "ash-device", now - 10);
        assert_eq!(
            import_contact_sync_checked(dir.path(), &user, &old, now)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            import_contact_sync_checked(dir.path(), &user, &old, now).unwrap_err(),
            "SYNC_REPLAY_OR_STALE"
        );
        let older = sync_blob(&user, "ash-device", now - 20);
        assert_eq!(
            import_contact_sync_checked(dir.path(), &user, &older, now).unwrap_err(),
            "SYNC_REPLAY_OR_STALE"
        );
        let future = sync_blob(&user, "ash-device", now + SYNC_FUTURE_SKEW_MS + 1);
        assert_eq!(
            import_contact_sync_checked(dir.path(), &user, &future, now).unwrap_err(),
            "SYNC_FROM_FUTURE"
        );
        assert!(import_contact_sync(&user, &DeviceRegistry::default(), &future, now).is_err());
        let newer = sync_blob(&user, "ash-device", now - 5);
        import_contact_sync_checked(dir.path(), &user, &newer, now).unwrap();

        // A corrupt registry is an error, never an empty "first import" registry.
        std::fs::write(
            crate::device_cert::device_registry_path(dir.path()),
            b"{bad",
        )
        .unwrap();
        let next = sync_blob(&user, "ash-device", now - 1);
        assert!(import_contact_sync_checked(dir.path(), &user, &next, now)
            .unwrap_err()
            .contains("corrupt"));
        // An existing registry requires an authorized, unrevoked sender.
        let mut reg = DeviceRegistry::default();
        reg.add(issue_phone(&user, "phone-a"), 100).unwrap();
        crate::device_cert::save_device_registry(dir.path(), &reg).unwrap();
        assert_eq!(
            import_contact_sync_checked(dir.path(), &user, &next, now).unwrap_err(),
            "SYNC_FROM_UNAUTHORIZED_OR_REVOKED"
        );
        let from_phone = sync_blob(&user, "phone-a", now - 1);
        import_contact_sync_checked(dir.path(), &user, &from_phone, now).unwrap();
    }

    /// A failed contacts save after the replay check must not burn the blob:
    /// the user fixes `contacts.json` and re-runs the same import.
    #[test]
    fn failed_apply_does_not_burn_the_replay_high_water_mark() {
        let user = Identity::generate();
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000_000u64;
        let blob = sync_blob(&user, "ash-device", now - 10);
        let seen_path = dir.path().join(SYNC_SEEN_FILE);

        let err = import_contact_sync_checked_then(dir.path(), &user, &blob, now, |contacts| {
            assert_eq!(contacts.len(), 1);
            Err::<(), _>("contacts.json unwritable".to_string())
        })
        .unwrap_err();
        assert_eq!(err, "contacts.json unwritable");
        assert!(!seen_path.exists(), "nothing recorded when apply fails");

        // Same blob, problem fixed: accepted, and only now recorded.
        let n = import_contact_sync_checked_then(dir.path(), &user, &blob, now, |contacts| {
            Ok(contacts.len())
        })
        .unwrap();
        assert_eq!(n, 1);
        assert!(seen_path.exists());
        assert_eq!(
            import_contact_sync_checked_then(dir.path(), &user, &blob, now, |_| Ok(()))
                .unwrap_err(),
            "SYNC_REPLAY_OR_STALE"
        );
        // Replay protection is unchanged for the plain entry point.
        assert_eq!(
            import_contact_sync_checked(dir.path(), &user, &blob, now).unwrap_err(),
            "SYNC_REPLAY_OR_STALE"
        );
        // A replayed blob never reaches `apply`.
        let mut reached = false;
        let _ = import_contact_sync_checked_then(dir.path(), &user, &blob, now, |_| {
            reached = true;
            Ok(())
        });
        assert!(!reached);
    }

    #[test]
    fn wrong_user_key_fails_unseal() {
        let a = Identity::generate();
        let b = Identity::generate();
        let plain = ContactSyncPlaintext {
            schema: 1,
            from_device_id: "x".into(),
            contacts: vec![],
            issued_at_ms: 1,
        };
        let wire = seal_contact_sync(&a, &plain).unwrap();
        assert!(unseal_contact_sync(&b, &wire).is_err());
    }
}
