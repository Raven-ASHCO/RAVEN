//! Multi-device certificates (§39) — user-identity-signed device auth + local revoke.
//!
//! Spec: `protocol/RAVEN_IDENTITY_V1.md`. V1 has no network push-revocation
//! channel; this module implements issuance, local store, expiry checks, and a
//! local revocation denylist (software substitute until a dedicated revocation
//! record type is frozen).
//!
//! Device tier (current, collapsed): the local certificate certifies the
//! identity key itself (`device_ed_pub == user_ed_pub`) with one X25519 device
//! key per data dir, so every local `device_id` shares one lineage. Revoking any
//! local lineage retires the identity key's device role
//! (RAVEN_DEVICE_REVOCATION_V1 §2.2, §9.1); per-install device keys are not
//! implemented.

use crate::identity::Identity;
use crate::paths::PRIMARY_DEVICE_ID;
use crate::prekey_lifecycle::MAX_PREKEY_FUTURE_SKEW_MS;
use crate::records::device_cert_signing_bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

fn ser_32<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v))
}
fn de_32<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let s = String::deserialize(d)?;
    let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
    if v.len() != 32 {
        return Err(serde::de::Error::custom("expected 32 bytes"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}
fn ser_64<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex::encode(v))
}
fn de_64<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
    let s = String::deserialize(d)?;
    let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
    if v.len() != 64 {
        return Err(serde::de::Error::custom("expected 64 bytes"));
    }
    let mut a = [0u8; 64];
    a.copy_from_slice(&v);
    Ok(a)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCertificate {
    #[serde(serialize_with = "ser_32", deserialize_with = "de_32")]
    pub device_ed_pub: [u8; 32],
    #[serde(serialize_with = "ser_32", deserialize_with = "de_32")]
    pub device_x_pub: [u8; 32],
    pub device_id: String,
    pub not_before_ms: u64,
    pub not_after_ms: u64,
    pub capabilities: u64,
    #[serde(serialize_with = "ser_64", deserialize_with = "de_64")]
    pub signature: [u8; 64],
    /// Signer (user identity) public key — recovered at verify time by caller.
    #[serde(serialize_with = "ser_32", deserialize_with = "de_32")]
    pub user_ed_pub: [u8; 32],
}

impl DeviceCertificate {
    pub fn issue(
        user: &Identity,
        device_ed_pub: [u8; 32],
        device_x_pub: [u8; 32],
        device_id: impl Into<String>,
        not_before_ms: u64,
        not_after_ms: u64,
        capabilities: u64,
    ) -> Result<Self, String> {
        let device_id = device_id.into();
        if not_after_ms < not_before_ms {
            return Err("not_after before not_before".into());
        }
        let sb = device_cert_signing_bytes(
            &device_ed_pub,
            &device_x_pub,
            &device_id,
            not_before_ms,
            not_after_ms,
            capabilities,
        )?;
        let signature = user.sign(&sb);
        Ok(Self {
            device_ed_pub,
            device_x_pub,
            device_id,
            not_before_ms,
            not_after_ms,
            capabilities,
            signature,
            user_ed_pub: user.public_key_bytes(),
        })
    }

    pub fn verify(&self, now_ms: u64) -> Result<(), String> {
        if now_ms < self.not_before_ms {
            return Err("DEVICE_CERT_NOT_YET_VALID".into());
        }
        if now_ms > self.not_after_ms {
            return Err("DEVICE_CERT_EXPIRED".into());
        }
        let sb = device_cert_signing_bytes(
            &self.device_ed_pub,
            &self.device_x_pub,
            &self.device_id,
            self.not_before_ms,
            self.not_after_ms,
            self.capabilities,
        )?;
        if !Identity::verify(&self.user_ed_pub, &sb, &self.signature) {
            return Err("DEVICE_CERT_BAD_SIG".into());
        }
        Ok(())
    }
}

/// Lineage identifiers of a certificate retired by the local registry
/// (RAVEN_DEVICE_REVOCATION_V1 §2.1). Retained after the cert itself is
/// dropped so a re-issued certificate that reuses any retired identifier under
/// a new `device_id` is still denied (§2.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevokedDeviceLineage {
    pub device_id: String,
    #[serde(serialize_with = "ser_32", deserialize_with = "de_32")]
    pub device_ed_pub: [u8; 32],
    #[serde(serialize_with = "ser_32", deserialize_with = "de_32")]
    pub device_x_pub: [u8; 32],
    #[serde(serialize_with = "ser_32", deserialize_with = "de_32")]
    pub device_cert_hash: [u8; 32],
}

impl RevokedDeviceLineage {
    pub fn of(cert: &DeviceCertificate) -> Result<Self, String> {
        Ok(Self {
            device_id: cert.device_id.clone(),
            device_ed_pub: cert.device_ed_pub,
            device_x_pub: cert.device_x_pub,
            device_cert_hash: crate::pair_init::device_certificate_hash(cert)
                .map_err(|e| format!("device cert hash: {e}"))?,
        })
    }

    /// True if `cert` reuses any identifier of this retired lineage.
    pub fn covers(&self, cert: &DeviceCertificate) -> Result<bool, String> {
        if self.device_id.as_bytes() == cert.device_id.as_bytes()
            || self.device_ed_pub == cert.device_ed_pub
            || self.device_x_pub == cert.device_x_pub
        {
            return Ok(true);
        }
        let hash = crate::pair_init::device_certificate_hash(cert)
            .map_err(|e| format!("device cert hash: {e}"))?;
        Ok(self.device_cert_hash == hash)
    }
}

/// Local multi-device registry for one user identity.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DeviceRegistry {
    /// device_id → certificate
    pub certs: HashMap<String, DeviceCertificate>,
    /// Locally revoked device_ids (no network push in V1).
    pub revoked: HashSet<String>,
    /// Full lineage of every revoked cert the registry held (append-only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_lineage: Vec<RevokedDeviceLineage>,
}

impl DeviceRegistry {
    pub fn add(&mut self, cert: DeviceCertificate, now_ms: u64) -> Result<(), String> {
        cert.verify(now_ms)?;
        if self.denies_lineage(&cert)? {
            return Err("DEVICE_REVOKED".into());
        }
        self.certs.insert(cert.device_id.clone(), cert);
        Ok(())
    }

    pub fn revoke(&mut self, device_id: &str) -> bool {
        self.revoked.insert(device_id.to_string());
        if let Some(cert) = self.certs.remove(device_id) {
            // Keep the retired lineage; a hash failure still retires the keys.
            let lineage = RevokedDeviceLineage::of(&cert).unwrap_or(RevokedDeviceLineage {
                device_id: cert.device_id.clone(),
                device_ed_pub: cert.device_ed_pub,
                device_x_pub: cert.device_x_pub,
                device_cert_hash: [0u8; 32],
            });
            if !self.revoked_lineage.contains(&lineage) {
                self.revoked_lineage.push(lineage);
            }
        }
        true
    }

    pub fn is_revoked(&self, device_id: &str) -> bool {
        self.revoked.contains(device_id)
    }

    /// True if `cert` is revoked by `device_id` or reuses any identifier
    /// (`device_ed_pub`, `device_x_pub`, `device_cert_hash`) of a retired lineage.
    pub fn denies_lineage(&self, cert: &DeviceCertificate) -> Result<bool, String> {
        if self.revoked.contains(&cert.device_id) {
            return Ok(true);
        }
        for lineage in &self.revoked_lineage {
            if lineage.covers(cert)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn is_authorized(&self, device_id: &str, now_ms: u64) -> bool {
        if self.revoked.contains(device_id) {
            return false;
        }
        match self.certs.get(device_id) {
            Some(c) => c.verify(now_ms).is_ok() && matches!(self.denies_lineage(c), Ok(false)),
            None => false,
        }
    }

    pub fn lookup_by_ed_pub(&self, ed: &[u8; 32], now_ms: u64) -> Option<&DeviceCertificate> {
        self.certs.values().find(|c| {
            &c.device_ed_pub == ed
                && matches!(self.denies_lineage(c), Ok(false))
                && c.verify(now_ms).is_ok()
        })
    }
}

pub fn device_registry_path(data_dir: &Path) -> PathBuf {
    data_dir.join("device_registry.json")
}

/// Soft load for display helpers. Prefer [`load_device_registry_checked`].
pub fn load_device_registry(data_dir: &Path) -> DeviceRegistry {
    load_device_registry_checked(data_dir).unwrap_or_default()
}

/// Missing file → empty. Corrupt JSON → error (fail-closed; never wipe revocation).
pub fn load_device_registry_checked(data_dir: &Path) -> Result<DeviceRegistry, String> {
    let path = device_registry_path(data_dir);
    if !path.exists() {
        return Ok(DeviceRegistry::default());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("device registry read: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("device registry corrupt: {e}"))
}

const DEVICE_X_SECRET: &str = "device_x25519.secret";
const DEVICE_X_PUBLIC: &str = "device_x25519.pub";
const LEGACY_X_SECRET: &str = "lab_device_x25519.secret";
const LEGACY_X_PUBLIC: &str = "lab_device_x25519.pub";
pub const DEVICE_REGISTRY_LOCK: &str = ".device_registry.lock.sqlite";

/// Serialize all device-registry readers/writers (ensure, revoke, …).
pub fn with_device_registry_lock<F, T>(data_dir: &Path, f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, String>,
{
    let _lock = crate::paths::DataDirLock::acquire(data_dir, DEVICE_REGISTRY_LOCK)?;
    f()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn load_or_create_device_x25519(data_dir: &Path) -> Result<[u8; 32], String> {
    for (secret_name, public_name) in [
        (DEVICE_X_SECRET, DEVICE_X_PUBLIC),
        (LEGACY_X_SECRET, LEGACY_X_PUBLIC),
    ] {
        let secret_path = data_dir.join(secret_name);
        let public_path = data_dir.join(public_name);
        if secret_path.exists() && public_path.exists() {
            let secret_raw = std::fs::read(&secret_path).map_err(|e| e.to_string())?;
            let pub_raw = std::fs::read(&public_path).map_err(|e| e.to_string())?;
            if secret_raw.len() != 32 || pub_raw.len() != 32 {
                return Err(format!(
                    "{secret_name}/{public_name}: expected 32-byte secret and public"
                ));
            }
            let mut secret_bytes = [0u8; 32];
            secret_bytes.copy_from_slice(&secret_raw);
            let mut claimed_pub = [0u8; 32];
            claimed_pub.copy_from_slice(&pub_raw);
            let secret = StaticSecret::from(secret_bytes);
            let derived = X25519PublicKey::from(&secret).to_bytes();
            if derived != claimed_pub {
                return Err(format!(
                    "{secret_name}/{public_name}: public key does not match secret"
                ));
            }
            return Ok(derived);
        }
    }
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = X25519PublicKey::from(&secret).to_bytes();
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let secret_path = data_dir.join(DEVICE_X_SECRET);
    let public_path = data_dir.join(DEVICE_X_PUBLIC);
    crate::paths::atomic_write_private(&secret_path, &secret.to_bytes())?;
    crate::paths::atomic_write_private(&public_path, &public)?;
    Ok(public)
}

/// How far before "now" a locally issued device certificate starts
/// (`not_before`). [`DeviceCertificate::verify`] is strict: a peer whose clock is
/// behind the issuer's rejects a young certificate as `DEVICE_CERT_NOT_YET_VALID`.
/// PairInit tolerates peer clocks up to [`MAX_PREKEY_FUTURE_SKEW_MS`] ahead (prekey
/// and init stamps), and that tolerance is only worth anything if the certificate
/// the same peer presents is already valid for such a peer, right after `ash init`
/// too. So the start is backdated by that skew plus a margin (a 60 s backdate made
/// every certificate younger than `skew - 60 s` unusable for a peer 2-5 minutes
/// behind).
pub const LOCAL_CERT_BACKDATE_MS: u64 = MAX_PREKEY_FUTURE_SKEW_MS + 5 * 60 * 1_000;

/// Issue or reuse the local primary device certificate for this identity.
pub fn ensure_local_device_certificate(
    data_dir: &Path,
    id: &Identity,
    device_id: &str,
) -> Result<(DeviceCertificate, DeviceRegistry), String> {
    with_device_registry_lock(data_dir, || {
        let device_id = if device_id.is_empty() {
            PRIMARY_DEVICE_ID
        } else {
            device_id
        };
        // RAVEN_DEVICE_REVOCATION_V1 §2.3: every lineage must stay revocable.
        if device_id.len() > 64 {
            return Err("DEVICE_ID_LENGTH: device_id must be 1..64 bytes".into());
        }
        let mut reg = load_device_registry_checked(data_dir)?;
        let now = now_ms();
        if let Some(existing) = reg.certs.get(device_id).cloned() {
            // A cert whose lineage was retired (even under another device_id)
            // is never reused; re-issuance below then fails with DEVICE_REVOKED.
            if existing.device_ed_pub == id.public_key_bytes()
                && existing.user_ed_pub == id.public_key_bytes()
                && existing.verify(now).is_ok()
                && !reg.denies_lineage(&existing)?
            {
                return Ok((existing, reg));
            }
        }
        let x_pub = load_or_create_device_x25519(data_dir)?;
        let cert = DeviceCertificate::issue(
            id,
            id.public_key_bytes(),
            x_pub,
            device_id,
            now.saturating_sub(LOCAL_CERT_BACKDATE_MS),
            now.saturating_add(365 * 24 * 3600 * 1000),
            0,
        )?;
        reg.add(cert.clone(), now)?;
        save_device_registry(data_dir, &reg)?;
        Ok((cert, reg))
    })
}

pub fn save_device_registry(data_dir: &Path, reg: &DeviceRegistry) -> Result<(), String> {
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let raw = serde_json::to_string_pretty(reg).map_err(|e| e.to_string())?;
    crate::paths::atomic_write_private(&device_registry_path(data_dir), raw.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A peer whose clock is behind ours by up to the PairInit skew tolerance
    /// must still accept a *freshly issued* local certificate (the same time
    /// error `verify_init` / `verify_response` already forgive for prekeys).
    #[test]
    fn fresh_local_certificate_is_valid_for_a_peer_clock_within_the_skew() {
        crate::identity_store::test_enable_locked_file_identity_backend();
        let id = Identity::from_seed(&[0xd1; 32]);
        let dir = tempdir().unwrap();
        let before = super::now_ms();
        let (cert, _) = ensure_local_device_certificate(dir.path(), &id, "ash-primary").unwrap();
        const { assert!(LOCAL_CERT_BACKDATE_MS > MAX_PREKEY_FUTURE_SKEW_MS) };
        // A peer 4 minutes behind (inside the tolerance) accepts it at once...
        let behind = before.saturating_sub(4 * 60 * 1_000);
        cert.verify(behind)
            .expect("fresh cert, peer clock 4 min behind");
        // ...and so does one exactly at the tolerance.
        cert.verify(before.saturating_sub(MAX_PREKEY_FUTURE_SKEW_MS))
            .expect("fresh cert, peer clock at the skew tolerance");
        // Strictness is intact: a peer far behind still refuses it.
        assert_eq!(
            cert.verify(before.saturating_sub(LOCAL_CERT_BACKDATE_MS + 60_000))
                .unwrap_err(),
            "DEVICE_CERT_NOT_YET_VALID"
        );
        // The 60 s backdate it replaces would have failed the 4-minute case.
        let old_style = DeviceCertificate::issue(
            &id,
            id.public_key_bytes(),
            [3u8; 32],
            "ash-primary",
            before.saturating_sub(60_000),
            before + 3_600_000,
            0,
        )
        .unwrap();
        assert_eq!(
            old_style.verify(behind).unwrap_err(),
            "DEVICE_CERT_NOT_YET_VALID"
        );
    }

    #[test]
    fn add_and_revoke_device() {
        let user = Identity::generate();
        let device = Identity::generate();
        let x = [9u8; 32];
        let cert = DeviceCertificate::issue(
            &user,
            device.public_key_bytes(),
            x,
            "phone-1",
            1,
            u64::MAX / 2,
            7,
        )
        .unwrap();
        let mut reg = DeviceRegistry::default();
        reg.add(cert, 100).unwrap();
        assert!(reg.is_authorized("phone-1", 100));
        assert!(reg
            .lookup_by_ed_pub(&device.public_key_bytes(), 100)
            .is_some());
        reg.revoke("phone-1");
        assert!(!reg.is_authorized("phone-1", 100));
        // Re-add after revoke must fail
        let cert2 = DeviceCertificate::issue(
            &user,
            device.public_key_bytes(),
            x,
            "phone-1",
            1,
            u64::MAX / 2,
            7,
        )
        .unwrap();
        assert!(reg.add(cert2, 100).is_err());
    }

    fn issue_for(user: &Identity, ed: [u8; 32], x: [u8; 32], id: &str) -> DeviceCertificate {
        DeviceCertificate::issue(user, ed, x, id, 1, u64::MAX / 2, 0).unwrap()
    }

    /// RAVEN_DEVICE_REVOCATION_V1 §2.2: a retired lineage stays denied when the
    /// same keys are re-certified under a new device_id.
    #[test]
    fn revoked_lineage_blocks_recertification_under_new_device_id() {
        let user = Identity::generate();
        let device = Identity::generate();
        let mut reg = DeviceRegistry::default();
        reg.add(
            issue_for(&user, device.public_key_bytes(), [5; 32], "old"),
            100,
        )
        .unwrap();
        reg.revoke("old");

        let same_ed = issue_for(&user, device.public_key_bytes(), [6; 32], "new-1");
        assert!(reg.denies_lineage(&same_ed).unwrap());
        assert_eq!(reg.add(same_ed.clone(), 100).unwrap_err(), "DEVICE_REVOKED");
        let same_x = issue_for(
            &user,
            Identity::generate().public_key_bytes(),
            [5; 32],
            "new-2",
        );
        assert_eq!(reg.add(same_x, 100).unwrap_err(), "DEVICE_REVOKED");
        let fresh = issue_for(
            &user,
            Identity::generate().public_key_bytes(),
            [7; 32],
            "new-3",
        );
        reg.add(fresh, 100).unwrap();
        assert!(reg.is_authorized("new-3", 100));

        let dir = tempdir().unwrap();
        save_device_registry(dir.path(), &reg).unwrap();
        let loaded = load_device_registry_checked(dir.path()).unwrap();
        assert!(loaded.denies_lineage(&same_ed).unwrap());
    }

    /// Collapsed tier: every local cert is the identity key + the one device
    /// X25519 key, so retiring any local lineage retires them all; the primary
    /// must not be silently re-issued over the retired keys.
    #[test]
    fn ensure_local_refuses_reissue_over_revoked_collapsed_lineage() {
        let dir = tempdir().unwrap();
        let id = Identity::generate();
        let (second, _) = ensure_local_device_certificate(dir.path(), &id, "second").unwrap();
        assert_eq!(second.device_ed_pub, id.public_key_bytes());
        let (primary, _) =
            ensure_local_device_certificate(dir.path(), &id, PRIMARY_DEVICE_ID).unwrap();
        with_device_registry_lock(dir.path(), || {
            let mut reg = load_device_registry_checked(dir.path())?;
            reg.revoke("second");
            save_device_registry(dir.path(), &reg)
        })
        .unwrap();
        let reg = load_device_registry_checked(dir.path()).unwrap();
        assert!(reg.denies_lineage(&primary).unwrap());
        assert_eq!(
            ensure_local_device_certificate(dir.path(), &id, PRIMARY_DEVICE_ID).unwrap_err(),
            "DEVICE_REVOKED"
        );
    }

    #[test]
    fn expired_rejected() {
        let user = Identity::generate();
        let device = Identity::generate();
        let cert =
            DeviceCertificate::issue(&user, device.public_key_bytes(), [1u8; 32], "old", 1, 50, 0)
                .unwrap();
        assert!(cert.verify(100).is_err());
    }

    #[test]
    fn registry_file_roundtrip() {
        let dir = tempdir().unwrap();
        let user = Identity::generate();
        let device = Identity::generate();
        let cert = DeviceCertificate::issue(
            &user,
            device.public_key_bytes(),
            [2u8; 32],
            "term-a",
            1,
            u64::MAX / 2,
            1,
        )
        .unwrap();
        let mut reg = DeviceRegistry::default();
        reg.add(cert, 10).unwrap();
        save_device_registry(dir.path(), &reg).unwrap();
        let loaded = load_device_registry(dir.path());
        assert!(loaded.is_authorized("term-a", 10));
    }

    #[test]
    fn shared_vector_bob_device1_signing_bytes() {
        // Parity with shared-vectors/rvn1/device_cert/bob_device1.json via records API.
        let sb = device_cert_signing_bytes(
            &hex::decode("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .unwrap(),
            &hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap(),
            "bob-device-1",
            1700000000000,
            1731536000000,
            7,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&sb),
            "72766e312f6465766365727400203d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c0020de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f000c626f622d6465766963652d310000018bcfe5680000000193279694000000000000000007"
        );
    }

    #[test]
    fn device_registry_checked_rejects_corrupt() {
        let dir = tempdir().unwrap();
        std::fs::write(device_registry_path(dir.path()), b"{bad").unwrap();
        let err = load_device_registry_checked(dir.path()).unwrap_err();
        assert!(err.contains("corrupt"));
        // Soft load still defaults — ensure_local must not use that path.
        assert!(load_device_registry(dir.path()).certs.is_empty());
    }

    #[test]
    fn device_x25519_rejects_mismatched_public() {
        let dir = tempdir().unwrap();
        let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let good_pub = X25519PublicKey::from(&secret).to_bytes();
        crate::paths::atomic_write_private(&dir.path().join(DEVICE_X_SECRET), &secret.to_bytes())
            .unwrap();
        crate::paths::atomic_write_private(&dir.path().join(DEVICE_X_PUBLIC), &good_pub).unwrap();
        assert_eq!(load_or_create_device_x25519(dir.path()).unwrap(), good_pub);

        let tampered = [0xAAu8; 32];
        crate::paths::atomic_write_private(&dir.path().join(DEVICE_X_PUBLIC), &tampered).unwrap();
        let err = load_or_create_device_x25519(dir.path()).unwrap_err();
        assert!(err.contains("does not match"));
    }
}
