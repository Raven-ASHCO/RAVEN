//! RavenProfileRecordV1 — signed, expiring public profile (exact Raven ID lookup).
//!
//! DHT key: H("raven/profile/v1" || raven_id). No phone/email/friendship graph.

use crate::address::encode_address;
use crate::canon::{lp, u64_be};
use crate::identity::Identity;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub const PROFILE_DOMAIN: &[u8] = b"rvn1/profile";
pub const PROFILE_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RavenProfileRecordV1 {
    pub version: u8,
    pub raven_id: String,
    pub display_name: String,
    pub public_aliases: Vec<String>,
    pub profile_image_digest: [u8; 32],
    pub device_set_commitment: [u8; 32],
    pub prekey_bundle_reference: [u8; 32],
    pub sequence: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    /// 0 = public signed profile (V1).
    pub visibility: u8,
    pub signature: [u8; 64],
    pub ed25519_pub: [u8; 32],
}

impl RavenProfileRecordV1 {
    pub fn dht_key(raven_id: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"raven/profile/v1");
        h.update(raven_id.as_bytes());
        h.finalize().into()
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = PROFILE_DOMAIN.to_vec();
        out.push(self.version);
        out.extend(lp(self.raven_id.as_bytes())?);
        out.extend(lp(self.display_name.as_bytes())?);
        let alias_count = u16::try_from(self.public_aliases.len())
            .map_err(|_| "too many profile aliases".to_string())?;
        out.extend_from_slice(&alias_count.to_be_bytes());
        for a in &self.public_aliases {
            out.extend(lp(a.as_bytes())?);
        }
        out.extend_from_slice(&self.profile_image_digest);
        out.extend_from_slice(&self.device_set_commitment);
        out.extend_from_slice(&self.prekey_bundle_reference);
        out.extend_from_slice(&u64_be(self.sequence));
        out.extend_from_slice(&u64_be(self.issued_at));
        out.extend_from_slice(&u64_be(self.expires_at));
        out.push(self.visibility);
        Ok(out)
    }

    pub fn sign(mut self, id: &Identity) -> Result<Self, String> {
        self.ed25519_pub = id.public_key_bytes();
        self.raven_id = id.address();
        let sb = self.signing_bytes()?;
        self.signature = id.sign(&sb);
        Ok(self)
    }

    pub fn verify(&self, now_ms: u64) -> Result<(), String> {
        if self.version != PROFILE_VERSION {
            return Err("PROFILE_BAD_VERSION".into());
        }
        if now_ms > self.expires_at {
            return Err("PROFILE_EXPIRED".into());
        }
        if encode_address(&self.ed25519_pub) != self.raven_id {
            return Err("PROFILE_ADDR_MISMATCH".into());
        }
        let sb = self.signing_bytes()?;
        if !Identity::verify(&self.ed25519_pub, &sb, &self.signature) {
            return Err("PROFILE_BAD_SIG".into());
        }
        Ok(())
    }

    pub fn profile_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        if let Ok(sb) = self.signing_bytes() {
            h.update(&sb);
        }
        h.update(self.signature);
        h.finalize().into()
    }
}

#[derive(Default)]
pub struct ProfileStore {
    by_id: HashMap<String, RavenProfileRecordV1>,
}

impl ProfileStore {
    pub fn put(&mut self, rec: RavenProfileRecordV1, now_ms: u64) -> Result<(), String> {
        rec.verify(now_ms)?;
        if let Some(prev) = self.by_id.get(&rec.raven_id) {
            if rec.sequence <= prev.sequence {
                return Err("PROFILE_STALE_SEQUENCE".into());
            }
        }
        self.by_id.insert(rec.raven_id.clone(), rec);
        Ok(())
    }

    pub fn get(&self, raven_id: &str, now_ms: u64) -> Option<&RavenProfileRecordV1> {
        let r = self.by_id.get(raven_id)?;
        r.verify(now_ms).ok()?;
        Some(r)
    }

    pub fn get_raw(&self, raven_id: &str) -> Option<&RavenProfileRecordV1> {
        self.by_id.get(raven_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_expired_not_current() {
        let id = Identity::generate();
        let rec = RavenProfileRecordV1 {
            version: 1,
            raven_id: String::new(),
            display_name: "Poline".into(),
            public_aliases: vec!["poline".into()],
            profile_image_digest: [0u8; 32],
            device_set_commitment: [1u8; 32],
            prekey_bundle_reference: [2u8; 32],
            sequence: 1,
            issued_at: 1,
            expires_at: 100,
            visibility: 0,
            signature: [0u8; 64],
            ed25519_pub: [0u8; 32],
        }
        .sign(&id)
        .unwrap();
        let mut store = ProfileStore::default();
        store.put(rec, 50).unwrap();
        assert!(store.get(&id.address(), 50).is_some());
        assert!(store.get(&id.address(), 101).is_none());
    }

    #[test]
    fn oversized_alias_count_fails_closed() {
        let id = Identity::from_seed(&[0x33; 32]);
        let rec = RavenProfileRecordV1 {
            version: 1,
            raven_id: id.address(),
            display_name: String::new(),
            public_aliases: vec![String::new(); usize::from(u16::MAX) + 1],
            profile_image_digest: [0u8; 32],
            device_set_commitment: [0u8; 32],
            prekey_bundle_reference: [0u8; 32],
            sequence: 1,
            issued_at: 1,
            expires_at: 100,
            visibility: 0,
            signature: [0u8; 64],
            ed25519_pub: id.public_key_bytes(),
        };
        assert!(rec.signing_bytes().is_err());
        assert!(rec.sign(&id).is_err());
    }
}
