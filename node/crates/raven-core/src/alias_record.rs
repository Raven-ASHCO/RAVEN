//! RavenAliasRecordV1 — signed, expiring, non-unique alias claims.
//!
//! Spec: `protocol/RAVEN_ALIAS_V1.md`. Alias ≠ identity; conflicts must surface.

use crate::address::{decode_address, encode_address};
use crate::canon::{lp, u64_be};
use crate::identity::Identity;
use crate::records::alias_signing_bytes;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// V1 alias charset: lowercase a-z, digits, underscore, hyphen only.
pub fn normalize_alias(raw: &str) -> Result<String, String> {
    let s = raw.trim().trim_start_matches('@').to_lowercase();
    if s.is_empty() {
        return Err("ALIAS_EMPTY".into());
    }
    if s.len() > 64 {
        return Err("ALIAS_TOO_LONG".into());
    }
    if !s
        .chars()
        .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'))
    {
        return Err("ALIAS_CHARSET".into());
    }
    Ok(s)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasRecord {
    pub alias: String,
    pub identity_address: String,
    pub sequence: u64,
    pub expires_at: u64,
    pub signature: [u8; 64],
    /// Claiming Ed25519 public key (must encode to `identity_address`).
    pub ed25519_pub: [u8; 32],
}

impl AliasRecord {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        alias_signing_bytes(
            &self.alias,
            &self.identity_address,
            self.sequence,
            self.expires_at,
        )
    }

    pub fn sign(mut self, id: &Identity) -> Result<Self, String> {
        self.ed25519_pub = id.public_key_bytes();
        self.identity_address = id.address();
        let sb = self.signing_bytes()?;
        self.signature = id.sign(&sb);
        Ok(self)
    }

    /// Verify signature, address binding, and expiry.
    pub fn verify(&self, now_ms: u64) -> Result<(), String> {
        if now_ms > self.expires_at {
            return Err("ALIAS_EXPIRED".into());
        }
        let derived = encode_address(&self.ed25519_pub);
        if derived != self.identity_address {
            return Err("ALIAS_ADDR_MISMATCH".into());
        }
        if decode_address(&self.identity_address).is_none() {
            return Err("ALIAS_BAD_ADDR".into());
        }
        let sb = self.signing_bytes()?;
        if !Identity::verify(&self.ed25519_pub, &sb, &self.signature) {
            return Err("ALIAS_BAD_SIG".into());
        }
        Ok(())
    }

    /// Opaque DHT key for exact-alias index (hashed alias — not plaintext required on wire).
    pub fn dht_key(alias_normalized: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"raven/alias/v1");
        h.update(alias_normalized.as_bytes());
        h.finalize().into()
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        out.extend(lp(self.alias.as_bytes())?);
        out.extend(lp(self.identity_address.as_bytes())?);
        out.extend_from_slice(&u64_be(self.sequence));
        out.extend_from_slice(&u64_be(self.expires_at));
        out.extend_from_slice(&self.ed25519_pub);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 2 + 2 + 8 + 8 + 32 + 64 {
            return Err("alias record short".into());
        }
        let a_len = u16::from_be_bytes([raw[0], raw[1]]) as usize;
        let mut off = 2;
        if raw.len() < off + a_len + 2 {
            return Err("alias truncated".into());
        }
        let alias = String::from_utf8(raw[off..off + a_len].to_vec())
            .map_err(|_| "alias utf8".to_string())?;
        off += a_len;
        let i_len = u16::from_be_bytes([raw[off], raw[off + 1]]) as usize;
        off += 2;
        if raw.len() < off + i_len + 8 + 8 + 32 + 64 {
            return Err("alias truncated2".into());
        }
        let identity_address = String::from_utf8(raw[off..off + i_len].to_vec())
            .map_err(|_| "addr utf8".to_string())?;
        off += i_len;
        let sequence = u64::from_be_bytes(raw[off..off + 8].try_into().unwrap());
        off += 8;
        let expires_at = u64::from_be_bytes(raw[off..off + 8].try_into().unwrap());
        off += 8;
        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(&raw[off..off + 32]);
        off += 32;
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&raw[off..off + 64]);
        off += 64;
        if off != raw.len() {
            return Err("alias trailing bytes".into());
        }
        Ok(Self {
            alias,
            identity_address,
            sequence,
            expires_at,
            signature,
            ed25519_pub,
        })
    }
}

/// Per-publisher Sybil / rate limits for public alias publication.
#[derive(Debug, Clone)]
pub struct AliasPublishQuota {
    pub max_live_claims_per_pub: usize,
    pub max_publishes_per_window: usize,
    pub window_ms: u64,
}

impl Default for AliasPublishQuota {
    fn default() -> Self {
        Self {
            max_live_claims_per_pub: 8,
            max_publishes_per_window: 16,
            window_ms: 3_600_000,
        }
    }
}

#[derive(Default)]
struct PubStats {
    window_start_ms: u64,
    publishes_in_window: usize,
}

/// Default global cap on stored claims across all publishers.
pub const ALIAS_STORE_MAX_CLAIMS: usize = 4096;

/// In-process alias claim store (community/manual peer DHT stand-in).
///
/// Keyed by `(alias, identity_address)` with LWW by `sequence`. Multiple live
/// claims for the same alias are retained and surfaced as conflicts. Expired
/// claims stay as sequence high-water marks (anti-rollback) but never count
/// toward a publisher's live quota; they are evicted only when the store is at
/// its global cap.
pub struct AliasClaimStore {
    /// (normalized_alias, identity_address) → record
    claims: HashMap<(String, String), AliasRecord>,
    stats: HashMap<[u8; 32], PubStats>,
    pub quota: AliasPublishQuota,
    /// Global cap across all publishers; admission fails closed beyond it.
    pub max_total_claims: usize,
}

impl Default for AliasClaimStore {
    fn default() -> Self {
        Self {
            claims: HashMap::new(),
            stats: HashMap::new(),
            quota: AliasPublishQuota::default(),
            max_total_claims: ALIAS_STORE_MAX_CLAIMS,
        }
    }
}

impl AliasClaimStore {
    pub fn with_quota(quota: AliasPublishQuota) -> Self {
        Self {
            quota,
            ..Default::default()
        }
    }

    /// Admit a claim from an untrusted (network / DHT) source: full
    /// verification plus the per-publisher rate limit and Sybil quota.
    pub fn put(&mut self, rec: AliasRecord, now_ms: u64) -> Result<(), String> {
        let (key, rec) = self.admit(rec, now_ms)?;

        let pubk = rec.ed25519_pub;
        let window_ms = self.quota.window_ms;
        self.stats
            .retain(|_, s| now_ms.saturating_sub(s.window_start_ms) <= window_ms);
        let is_new_live = !self
            .claims
            .get(&key)
            .is_some_and(|p| now_ms <= p.expires_at);
        let live = self
            .claims
            .values()
            .filter(|r| r.ed25519_pub == pubk && now_ms <= r.expires_at)
            .count();
        let stats = self.stats.entry(pubk).or_insert(PubStats {
            window_start_ms: now_ms,
            publishes_in_window: 0,
        });
        if stats.publishes_in_window >= self.quota.max_publishes_per_window {
            return Err("ALIAS_RATE_LIMIT".into());
        }
        if is_new_live && live >= self.quota.max_live_claims_per_pub {
            return Err("ALIAS_SYBIL_QUOTA".into());
        }
        stats.publishes_in_window += 1;
        self.claims.insert(key, rec);
        Ok(())
    }

    /// Insert a claim from a trusted local source (e.g. reloading the user's
    /// own persisted publications) without the network rate limit or Sybil
    /// quota, so a reload never silently drops rows. Signature, address
    /// binding, expiry, sequence LWW and the global cap still apply.
    pub fn put_trusted(&mut self, rec: AliasRecord, now_ms: u64) -> Result<(), String> {
        let (key, rec) = self.admit(rec, now_ms)?;
        self.claims.insert(key, rec);
        Ok(())
    }

    /// Checks shared by every insert path. Returns the store key and the
    /// record; does not insert.
    ///
    /// The signature is verified over the alias exactly as received, and the
    /// received alias must already be the canonical (normalized) form. The
    /// record is never rewritten before verification: that would let one valid
    /// signature admit `kevin`, `KEVIN`, `@kevin` and `\u{212A}evin` as
    /// distinct wire objects, and a Python verifier of the raw bytes would
    /// disagree with the Rust store.
    fn admit(
        &mut self,
        rec: AliasRecord,
        now_ms: u64,
    ) -> Result<((String, String), AliasRecord), String> {
        let alias = normalize_alias(&rec.alias)?;
        rec.verify(now_ms)?;
        if rec.alias != alias {
            return Err("ALIAS_CHARSET".into());
        }

        let key = (alias, rec.identity_address.clone());
        if let Some(prev) = self.claims.get(&key) {
            if rec.sequence <= prev.sequence {
                return Err("ALIAS_STALE_SEQUENCE".into());
            }
        } else if self.claims.len() >= self.max_total_claims {
            // Under pressure, drop expired high-water marks before refusing.
            self.claims.retain(|_, r| now_ms <= r.expires_at);
            if self.claims.len() >= self.max_total_claims {
                return Err("ALIAS_STORE_FULL".into());
            }
        }
        Ok((key, rec))
    }

    /// All live, verified claims for an exact alias (conflict set).
    pub fn lookup_exact(&self, alias_raw: &str, now_ms: u64) -> Result<Vec<AliasRecord>, String> {
        let alias = normalize_alias(alias_raw)?;
        let mut out = Vec::new();
        for ((a, _), rec) in &self.claims {
            if a == &alias && rec.verify(now_ms).is_ok() {
                out.push(rec.clone());
            }
        }
        out.sort_by(|x, y| x.identity_address.cmp(&y.identity_address));
        Ok(out)
    }

    pub fn len(&self) -> usize {
        self.claims.len()
    }

    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Fixture scan helper: reject if any stored claim embeds phone/email markers.
    pub fn contains_phone_or_email_marker(&self) -> bool {
        for rec in self.claims.values() {
            let a = rec.alias.to_lowercase();
            if a.contains('@') && a.contains('.') {
                return true;
            }
            if a.chars().filter(|c| c.is_ascii_digit()).count() >= 10 {
                return true;
            }
            if a.contains("phone") || a.contains("email") || a.contains("tel:") {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_rejects_bad_charset() {
        assert!(normalize_alias("Poline!").is_err());
        assert_eq!(normalize_alias("@Poline").unwrap(), "poline");
        assert_eq!(normalize_alias("a_b-1").unwrap(), "a_b-1");
    }

    /// The signature covers the alias bytes as transmitted. A record is not
    /// admitted under a normalized spelling it was never signed over, so the
    /// same signature cannot appear as several distinct wire objects.
    #[test]
    fn non_canonical_wire_alias_is_rejected_not_rewritten() {
        let id = Identity::from_seed(&[0x49; 32]);
        let canonical = AliasRecord {
            alias: "kevin".into(),
            identity_address: String::new(),
            sequence: 1,
            expires_at: u64::MAX,
            signature: [0u8; 64],
            ed25519_pub: [0u8; 32],
        }
        .sign(&id)
        .unwrap();
        let mut store = AliasClaimStore::default();

        // Variants carrying the signature made over `kevin`: the signature does
        // not cover the transmitted bytes.
        for variant in ["KEVIN", "@kevin", " kevin ", "\u{212A}evin"] {
            let mut rec = canonical.clone();
            rec.alias = variant.into();
            assert_eq!(
                store.put(rec.clone(), 1).unwrap_err(),
                "ALIAS_BAD_SIG",
                "{variant:?}"
            );
            assert_eq!(
                store.put_trusted(rec, 1).unwrap_err(),
                "ALIAS_BAD_SIG",
                "{variant:?}"
            );
        }
        assert!(store.is_empty());

        // Validly signed over a non-canonical spelling: refused as non-canonical
        // (previously ALIAS_BAD_SIG, because admission re-derived the signed
        // bytes from the normalized alias).
        for variant in ["Kevin", "@kevin", " kevin ", "\u{212A}evin"] {
            let rec = AliasRecord {
                alias: variant.into(),
                identity_address: String::new(),
                sequence: 1,
                expires_at: u64::MAX,
                signature: [0u8; 64],
                ed25519_pub: [0u8; 32],
            }
            .sign(&id)
            .unwrap();
            assert_eq!(
                store.put(rec, 1).unwrap_err(),
                "ALIAS_CHARSET",
                "{variant:?}"
            );
        }
        assert!(store.is_empty());

        // The canonical record is admitted and found through any query spelling.
        store.put(canonical, 1).unwrap();
        for query in ["kevin", "@KEVIN", " @Kevin "] {
            assert_eq!(store.lookup_exact(query, 1).unwrap().len(), 1, "{query:?}");
        }
    }

    #[test]
    fn conflict_set_both_claims() {
        let a = Identity::generate();
        let b = Identity::generate();
        let mut store = AliasClaimStore::default();
        let r1 = AliasRecord {
            alias: "poline".into(),
            identity_address: String::new(),
            sequence: 1,
            expires_at: u64::MAX,
            signature: [0u8; 64],
            ed25519_pub: [0u8; 32],
        }
        .sign(&a)
        .unwrap();
        let r2 = AliasRecord {
            alias: "poline".into(),
            identity_address: String::new(),
            sequence: 1,
            expires_at: u64::MAX,
            signature: [0u8; 64],
            ed25519_pub: [0u8; 32],
        }
        .sign(&b)
        .unwrap();
        store.put(r1, 1).unwrap();
        store.put(r2, 1).unwrap();
        let hits = store.lookup_exact("@poline", 1).unwrap();
        assert_eq!(hits.len(), 2);
    }

    fn claim(id: &Identity, alias: &str, sequence: u64, expires_at: u64) -> AliasRecord {
        AliasRecord {
            alias: alias.into(),
            identity_address: String::new(),
            sequence,
            expires_at,
            signature: [0u8; 64],
            ed25519_pub: [0u8; 32],
        }
        .sign(id)
        .unwrap()
    }

    #[test]
    fn expired_claims_do_not_consume_live_quota() {
        let id = Identity::from_seed(&[0x41; 32]);
        let mut store = AliasClaimStore::with_quota(AliasPublishQuota {
            max_live_claims_per_pub: 2,
            max_publishes_per_window: 100,
            window_ms: 3_600_000,
        });
        store.put(claim(&id, "a1", 1, 100), 1).unwrap();
        store.put(claim(&id, "a2", 1, 100), 1).unwrap();
        assert_eq!(
            store.put(claim(&id, "a3", 1, 1_000), 1).unwrap_err(),
            "ALIAS_SYBIL_QUOTA"
        );
        // Both earlier claims have expired: the key may publish again.
        store.put(claim(&id, "a3", 1, 1_000), 101).unwrap();
        // Renewing an expired claim is a new live claim and is counted.
        store.put(claim(&id, "a1", 2, 1_000), 101).unwrap();
        assert_eq!(
            store.put(claim(&id, "a2", 2, 1_000), 101).unwrap_err(),
            "ALIAS_SYBIL_QUOTA"
        );
    }

    #[test]
    fn stale_sequence_rejected_after_prior_claim_expired() {
        let id = Identity::from_seed(&[0x42; 32]);
        let mut store = AliasClaimStore::default();
        store.put(claim(&id, "poline", 5, 10), 1).unwrap();
        assert_eq!(
            store.put(claim(&id, "poline", 3, 1_000), 20).unwrap_err(),
            "ALIAS_STALE_SEQUENCE"
        );
    }

    #[test]
    fn trusted_reload_keeps_every_row() {
        let id = Identity::from_seed(&[0x43; 32]);
        let rows: Vec<_> = (0..20)
            .map(|i| claim(&id, &format!("alias{i}"), 1, u64::MAX))
            .collect();
        let mut network = AliasClaimStore::default();
        let admitted = rows
            .iter()
            .filter(|r| network.put((*r).clone(), 1).is_ok())
            .count();
        assert_eq!(
            admitted,
            AliasPublishQuota::default().max_live_claims_per_pub
        );
        let mut local = AliasClaimStore::default();
        for r in rows {
            local.put_trusted(r, 1).unwrap();
        }
        assert_eq!(local.len(), 20);
        // Trusted rows still go through signature / sequence checks.
        let mut forged = claim(&id, "alias0", 2, u64::MAX);
        forged.signature[0] ^= 1;
        assert!(local.put_trusted(forged, 1).is_err());
        assert_eq!(
            local
                .put_trusted(claim(&id, "alias0", 1, u64::MAX), 1)
                .unwrap_err(),
            "ALIAS_STALE_SEQUENCE"
        );
    }

    #[test]
    fn publish_rate_limit_resets_after_window() {
        let id = Identity::from_seed(&[0x44; 32]);
        let mut store = AliasClaimStore::with_quota(AliasPublishQuota {
            max_live_claims_per_pub: 100,
            max_publishes_per_window: 2,
            window_ms: 1_000,
        });
        store.put(claim(&id, "a1", 1, u64::MAX), 1).unwrap();
        store.put(claim(&id, "a2", 1, u64::MAX), 1).unwrap();
        assert_eq!(
            store.put(claim(&id, "a3", 1, u64::MAX), 2).unwrap_err(),
            "ALIAS_RATE_LIMIT"
        );
        store.put(claim(&id, "a3", 1, u64::MAX), 1_002).unwrap();
    }

    #[test]
    fn global_cap_fails_closed_then_evicts_expired() {
        let mut store = AliasClaimStore {
            max_total_claims: 2,
            ..Default::default()
        };
        let a = Identity::from_seed(&[0x45; 32]);
        let b = Identity::from_seed(&[0x46; 32]);
        let c = Identity::from_seed(&[0x47; 32]);
        store.put(claim(&a, "x", 1, 50), 1).unwrap();
        store.put(claim(&b, "x", 1, u64::MAX), 1).unwrap();
        assert_eq!(
            store.put(claim(&c, "x", 1, u64::MAX), 1).unwrap_err(),
            "ALIAS_STORE_FULL"
        );
        // Updating an existing key never needs a new slot.
        store.put(claim(&b, "x", 2, u64::MAX), 1).unwrap();
        store.put(claim(&c, "x", 1, u64::MAX), 51).unwrap();
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn decode_is_exact() {
        let id = Identity::from_seed(&[0x48; 32]);
        let rec = claim(&id, "poline", 1, u64::MAX);
        let mut wire = rec.encode().unwrap();
        assert_eq!(AliasRecord::decode(&wire).unwrap(), rec);
        wire.push(0);
        assert_eq!(
            AliasRecord::decode(&wire).unwrap_err(),
            "alias trailing bytes"
        );
    }
}
