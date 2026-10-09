//! RavenDeviceRevocationV1 — exact wire + store snapshot hash.
//! Spec: `protocol/RAVEN_DEVICE_REVOCATION_V1.md` (vector freeze).

use crate::address::{decode_address, encode_address};
use crate::canon::{lp, u64_be};
use crate::identity::Identity;
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 8] = b"RVDR1\0\0\0";
pub const VERSION: u8 = 0x01;
pub const SUITE: u8 = 0x01;
pub const SIGNING_DOMAIN: &[u8] = b"rvn1/device-revocation";
pub const STORE_SNAPSHOT_DOMAIN: &[u8] = b"rvn1/device-revocation/store-v1";
const ADDRESS_LEN: usize = 44;
const ID_MIN: usize = 1;
const ID_MAX: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRevocationV1 {
    pub identity_address: String,
    pub device_id: Vec<u8>,
    pub device_ed_pub: [u8; 32],
    pub device_x_pub: [u8; 32],
    pub device_cert_hash: [u8; 32],
    pub issuer_device_id: Vec<u8>,
    pub issuer_seq: u64,
    pub revocation_id: [u8; 16],
    pub reason_code: u8,
    pub created_at_ms: u64,
    pub signature: [u8; 64],
}

fn require_id(label: &str, raw: &[u8]) -> Result<(), String> {
    if raw.len() < ID_MIN || raw.len() > ID_MAX {
        return Err(format!("{label} length must be 1..64"));
    }
    Ok(())
}

fn require_address(addr: &str) -> Result<(), String> {
    if addr.len() != ADDRESS_LEN {
        return Err("identity_address must be 44 chars".into());
    }
    if decode_address(addr).is_none() {
        return Err("identity_address invalid".into());
    }
    if addr != addr.to_lowercase() || !addr.starts_with("rvn1") {
        return Err("identity_address not canonical".into());
    }
    Ok(())
}

impl DeviceRevocationV1 {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, String> {
        require_address(&self.identity_address)?;
        require_id("device_id", &self.device_id)?;
        require_id("issuer_device_id", &self.issuer_device_id)?;
        if self.revocation_id == [0u8; 16] {
            return Err("revocation_id all-zero".into());
        }
        let mut out = Vec::new();
        out.extend_from_slice(SIGNING_DOMAIN);
        out.push(VERSION);
        out.push(SUITE);
        out.extend_from_slice(self.identity_address.as_bytes());
        out.extend(lp(&self.device_id)?);
        out.extend_from_slice(&self.device_ed_pub);
        out.extend_from_slice(&self.device_x_pub);
        out.extend_from_slice(&self.device_cert_hash);
        out.extend(lp(&self.issuer_device_id)?);
        out.extend_from_slice(&u64_be(self.issuer_seq));
        out.extend_from_slice(&self.revocation_id);
        out.push(self.reason_code);
        out.extend_from_slice(&u64_be(self.created_at_ms));
        Ok(out)
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let sb = self.signing_bytes()?;
        let mut out = Vec::with_capacity(8 + sb.len() - SIGNING_DOMAIN.len() + 64);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&sb[SIGNING_DOMAIN.len()..]);
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn decode(wire: &[u8]) -> Result<Self, String> {
        if wire.len()
            < 8 + 2 + ADDRESS_LEN + 2 + ID_MIN + 32 + 32 + 32 + 2 + ID_MIN + 8 + 16 + 1 + 8 + 64
        {
            return Err("wire too short".into());
        }
        if &wire[..8] != MAGIC {
            return Err("bad magic".into());
        }
        if wire[8] != VERSION || wire[9] != SUITE {
            return Err("bad version/suite".into());
        }
        let mut off = 10;
        let addr = std::str::from_utf8(take(wire, &mut off, ADDRESS_LEN)?)
            .map_err(|_| "identity_address not utf8")?;
        let identity_address = addr.to_string();
        require_address(&identity_address)?;
        let (device_id, noff) = read_lp(wire, off)?;
        off = noff;
        // Every fixed-size field is bounds-checked: the length floor above
        // assumes 1-byte ids, so a long id with a short tail must be an error.
        let device_ed_pub = take_array::<32>(wire, &mut off)?;
        let device_x_pub = take_array::<32>(wire, &mut off)?;
        let device_cert_hash = take_array::<32>(wire, &mut off)?;
        let (issuer_device_id, noff) = read_lp(wire, off)?;
        off = noff;
        let issuer_seq = u64::from_be_bytes(take_array::<8>(wire, &mut off)?);
        let revocation_id = take_array::<16>(wire, &mut off)?;
        if revocation_id == [0u8; 16] {
            return Err("revocation_id all-zero".into());
        }
        let reason_code = take_array::<1>(wire, &mut off)?[0];
        let created_at_ms = u64::from_be_bytes(take_array::<8>(wire, &mut off)?);
        let signature = take_array::<64>(wire, &mut off)?;
        if off != wire.len() {
            return Err("trailing bytes".into());
        }
        Ok(Self {
            identity_address,
            device_id,
            device_ed_pub,
            device_x_pub,
            device_cert_hash,
            issuer_device_id,
            issuer_seq,
            revocation_id,
            reason_code,
            created_at_ms,
            signature,
        })
    }

    pub fn sign(mut self, id: &Identity) -> Result<Self, String> {
        self.identity_address = id.address();
        let sb = self.signing_bytes()?;
        self.signature = id.sign(&sb);
        Ok(self)
    }

    pub fn verify(&self, identity_ed_pub: &[u8; 32]) -> Result<(), String> {
        if encode_address(identity_ed_pub) != self.identity_address {
            return Err("ADDR_MISMATCH".into());
        }
        let sb = self.signing_bytes()?;
        if !Identity::verify(identity_ed_pub, &sb, &self.signature) {
            return Err("BAD_SIG".into());
        }
        Ok(())
    }
}

fn take<'a>(buf: &'a [u8], off: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = off
        .checked_add(n)
        .filter(|end| *end <= buf.len())
        .ok_or_else(|| "truncated field".to_string())?;
    let out = &buf[*off..end];
    *off = end;
    Ok(out)
}

fn take_array<const N: usize>(buf: &[u8], off: &mut usize) -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    out.copy_from_slice(take(buf, off, N)?);
    Ok(out)
}

fn read_lp(buf: &[u8], off: usize) -> Result<(Vec<u8>, usize), String> {
    if off + 2 > buf.len() {
        return Err("truncated lp".into());
    }
    let n = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    if !(ID_MIN..=ID_MAX).contains(&n) {
        return Err("lp length out of 1..64".into());
    }
    let end = off + 2 + n;
    if end > buf.len() {
        return Err("truncated lp body".into());
    }
    Ok((buf[off + 2..end].to_vec(), end))
}

pub fn claim_digest(wire: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(wire);
    h.finalize().into()
}

#[derive(Debug, Clone)]
pub struct StoreClaim {
    pub exact_record_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ExhaustedMarker {
    pub identity_address: String,
    pub claim_digest: [u8; 32],
    pub exact_record_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CorruptMarker {
    pub scope: String,
    pub reason_code: u8,
}

pub fn canonical_store_snapshot(
    generation: u64,
    claims: &[StoreClaim],
    exhausted: &[ExhaustedMarker],
    corrupt: &[CorruptMarker],
) -> Result<Vec<u8>, String> {
    let mut claims_sorted = claims.to_vec();
    claims_sorted.sort_by_key(|a| claim_digest(&a.exact_record_bytes));
    let mut exh = exhausted.to_vec();
    exh.sort_by(|a, b| {
        (a.identity_address.as_bytes(), a.claim_digest.as_slice())
            .cmp(&(b.identity_address.as_bytes(), b.claim_digest.as_slice()))
    });
    let mut cor = corrupt.to_vec();
    cor.sort_by_key(|a| a.scope.clone());

    let mut out = Vec::new();
    out.extend_from_slice(STORE_SNAPSHOT_DOMAIN);
    out.push(0);
    out.extend_from_slice(&u64_be(generation));
    out.extend_from_slice(&(claims_sorted.len() as u32).to_be_bytes());
    for c in &claims_sorted {
        let d = claim_digest(&c.exact_record_bytes);
        out.extend_from_slice(&d);
        out.extend_from_slice(&(c.exact_record_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&c.exact_record_bytes);
    }
    out.extend_from_slice(&(exh.len() as u32).to_be_bytes());
    for e in &exh {
        if claim_digest(&e.exact_record_bytes) != e.claim_digest {
            return Err("exhausted digest mismatch".into());
        }
        out.extend(lp(e.identity_address.as_bytes())?);
        out.extend_from_slice(&e.claim_digest);
        out.extend_from_slice(&(e.exact_record_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&e.exact_record_bytes);
    }
    out.extend_from_slice(&(cor.len() as u32).to_be_bytes());
    for c in &cor {
        out.extend(lp(c.scope.as_bytes())?);
        out.push(c.reason_code);
    }
    Ok(out)
}

pub fn revocation_store_hash(
    generation: u64,
    claims: &[StoreClaim],
    exhausted: &[ExhaustedMarker],
    corrupt: &[CorruptMarker],
) -> Result<[u8; 32], String> {
    let snap = canonical_store_snapshot(generation, claims, exhausted, corrupt)?;
    let mut h = Sha256::new();
    h.update(&snap);
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;

    fn vectors_root() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors").join("rvn1")
    }

    fn load(rel: &str) -> Value {
        let raw = std::fs::read_to_string(vectors_root().join(rel)).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn valid_001_roundtrip() {
        let v = load("device_revocation/valid_001.json");
        let wire = hex(v["expected"]["wire_hex"].as_str().unwrap());
        let rec = DeviceRevocationV1::decode(&wire).unwrap();
        assert_eq!(rec.encode().unwrap(), wire);
        let mut pubk = [0u8; 32];
        pubk.copy_from_slice(&hex(v["inputs"]["identity_ed_pub_hex"].as_str().unwrap()));
        rec.verify(&pubk).unwrap();
        assert_eq!(
            hex::encode(claim_digest(&wire)),
            v["expected"]["claim_digest_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn wrong_signer_rejects() {
        let v = load("negative/device_revocation_wrong_signer.json");
        let wire = hex(v["inputs"]["wire_hex"].as_str().unwrap());
        let rec = DeviceRevocationV1::decode(&wire).unwrap();
        let mut pubk = [0u8; 32];
        pubk.copy_from_slice(&hex(v["inputs"]["claimed_identity_ed_pub_hex"]
            .as_str()
            .unwrap()));
        assert!(rec.verify(&pubk).is_err());
    }

    #[test]
    fn long_id_short_tail_is_error_not_panic() {
        let v = load("negative/device_revocation_long_id_short_tail.json");
        let wire = hex(v["inputs"]["wire_hex"].as_str().unwrap());
        assert_eq!(
            wire.len() as u64,
            v["expected"]["wire_len"].as_u64().unwrap()
        );
        assert!(DeviceRevocationV1::decode(&wire).is_err());
    }

    #[test]
    fn decode_rejects_every_truncation_and_id_length_without_panic() {
        let v = load("device_revocation/valid_001.json");
        let wire = hex(v["expected"]["wire_hex"].as_str().unwrap());
        for n in 0..wire.len() {
            assert!(DeviceRevocationV1::decode(&wire[..n]).is_err());
        }
        for n in 0u16..70 {
            let mut w = wire.clone();
            w[54..56].copy_from_slice(&n.to_be_bytes());
            let full = DeviceRevocationV1::decode(&w);
            assert_eq!(full.is_ok(), w == wire);
            assert!(DeviceRevocationV1::decode(&w[..253]).is_err());
        }
    }

    #[test]
    fn store_hash_parity() {
        for name in [
            "device_revocation/store_hash_001.json",
            "device_revocation/store_hash_exhausted_001.json",
        ] {
            let v = load(name);
            let claims: Vec<StoreClaim> = v["inputs"]["claims_wire_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| StoreClaim {
                    exact_record_bytes: hex(h.as_str().unwrap()),
                })
                .collect();
            let exhausted: Vec<ExhaustedMarker> = v["inputs"]["exhausted"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| {
                    let mut d = [0u8; 32];
                    d.copy_from_slice(&hex(e["claim_digest_hex"].as_str().unwrap()));
                    ExhaustedMarker {
                        identity_address: e["identity_address"].as_str().unwrap().to_string(),
                        claim_digest: d,
                        exact_record_bytes: hex(e["exact_record_bytes_hex"].as_str().unwrap()),
                    }
                })
                .collect();
            let gen = v["inputs"]["generation"].as_u64().unwrap();
            let h = revocation_store_hash(gen, &claims, &exhausted, &[]).unwrap();
            assert_eq!(
                hex::encode(h),
                v["expected"]["revocation_store_hash_hex"].as_str().unwrap()
            );
            let snap = canonical_store_snapshot(gen, &claims, &exhausted, &[]).unwrap();
            assert_eq!(
                hex::encode(snap),
                v["expected"]["canonical_snapshot_hex"].as_str().unwrap()
            );
        }
    }
}
