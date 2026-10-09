//! ATSAM/hybrid-ratchet/v2 KDF + expand KATs (vector freeze).
//! Production disabled. PairInit V1 MUST NOT be reinterpreted as V2.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

pub const PROFILE: &[u8] = b"ATSAM/hybrid-ratchet/v2";
pub const TR_PROTOCOL_INFO: &[u8] = b"ATSAM/hybrid-ratchet/v2\x00TR";
pub const SPQR_PROTOCOL_INFO: &[u8] = b"ATSAM/hybrid-ratchet/v2\x00SPQR";
pub const EC_RK_INFO: &[u8] = b"ATSAM/hybrid-ratchet/v2\x00EC-KDF-RK";
pub const SCKA_INIT_INFO: &[u8] = b"ATSAM/hybrid-ratchet/v2\x00SPQR\x00SCKA-INIT";
pub const PAIR_INIT_LABEL: &[u8] = b"ATSAM/v2/pair-init";
pub const TRANSCRIPT_DOMAIN: &[u8] = b"ATSAM/v2/transcript";
pub const PAIR_EXPAND_INFO_PREFIX: &[u8] = b"ATSAM/hybrid-ratchet/v2\x00pair-expand";
pub const SESSION_ID_DOMAIN: &[u8] = b"ATSAM/v2/pair-session";
pub const INIT_MAGIC_V2: &[u8; 8] = b"RVPI2\0\0\0";
pub const INIT_MAGIC_V1: &[u8; 8] = b"RVPI1\0\0\0";
pub const SEALED_PROTO: u8 = 0x04;
pub const MAX_SKIP: u32 = 1000;
/// Fixed canonical PairInit V2 wire length (spec §3.2.1; `offsets.total_len` in
/// `shared-vectors/rvn1/atsam/pair_init_v2_001.json`; Python `INIT_WIRE_LEN`).
pub const INIT_WIRE_LEN: usize = 2787;

/// HKDF-SHA256. The returned OKM is key material: it is wiped on drop, and the
/// intermediate PRK / `T(i)` blocks are wiped here. The buffer is sized up front
/// so it never reallocates (which would leave an unwiped copy behind).
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Zeroizing<Vec<u8>> {
    let salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    let mut mac = HmacSha256::new_from_slice(salt).expect("hmac");
    mac.update(ikm);
    let mut prk: [u8; 32] = mac.finalize().into_bytes().into();
    let mut okm = Zeroizing::new(Vec::with_capacity(length.div_ceil(32) * 32));
    let mut t = [0u8; 32];
    let mut t_len = 0usize;
    let mut counter = 1u8;
    while okm.len() < length {
        let mut m = HmacSha256::new_from_slice(&prk).expect("hmac");
        m.update(&t[..t_len]);
        m.update(info);
        m.update(&[counter]);
        t = m.finalize().into_bytes().into();
        t_len = t.len();
        okm.extend_from_slice(&t);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(length);
    prk.zeroize();
    t.zeroize();
    okm
}

pub fn reject_if_pair_init_v1(wire: &[u8]) -> Result<(), String> {
    if wire.len() >= 8 && &wire[..8] == INIT_MAGIC_V1 {
        return Err("PairInit V1 must not be reinterpreted as V2".into());
    }
    Ok(())
}

pub fn transcript_hash(wire: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_DOMAIN);
    h.update(PAIR_INIT_LABEL);
    h.update(wire);
    h.finalize().into()
}

pub fn init_hash_v2(wire: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PAIR_INIT_LABEL);
    h.update(wire);
    h.finalize().into()
}

/// Session secrets from pair-expand: wiped on drop, redacted from Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct PairExpandV2 {
    pub sk_ec: [u8; 32],
    pub sk_scka: [u8; 32],
    pub k_route_master: [u8; 32],
    pub k_confirm: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub init_hash_v2: [u8; 32],
    pub session_id: [u8; 32],
}

impl fmt::Debug for PairExpandV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairExpandV2")
            .field("transcript_hash", &self.transcript_hash)
            .field("init_hash_v2", &self.init_hash_v2)
            .field("session_id", &self.session_id)
            .field("keys", &"<redacted>")
            .finish()
    }
}

impl Drop for PairExpandV2 {
    fn drop(&mut self) {
        self.sk_ec.zeroize();
        self.sk_scka.zeroize();
        self.k_route_master.zeroize();
        self.k_confirm.zeroize();
    }
}

pub fn pair_expand(z_x: &[u8; 32], z_pq: &[u8; 32], wire: &[u8]) -> Result<PairExpandV2, String> {
    reject_if_pair_init_v1(wire)?;
    // Python `pair_expand`/`transcript_hash`/`init_hash_v2` require exactly this
    // length; never derive session keys from a truncated or extended transcript.
    if wire.len() != INIT_WIRE_LEN {
        return Err("PairInit V2 wire length".into());
    }
    if &wire[..8] != INIT_MAGIC_V2 {
        return Err("bad PairInit V2 magic".into());
    }
    let th = transcript_hash(wire);
    let ih = init_hash_v2(wire);
    let mut info = PAIR_EXPAND_INFO_PREFIX.to_vec();
    info.extend_from_slice(&th);
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(z_x);
    ikm[32..].copy_from_slice(z_pq);
    let okm = hkdf_sha256(&ikm[..], &th, &info, 128);
    let mut sid_h = Sha256::new();
    sid_h.update(SESSION_ID_DOMAIN);
    sid_h.update(ih);
    // Fill the (Drop-wiped) result in place rather than via local key copies.
    let mut out = PairExpandV2 {
        sk_ec: [0u8; 32],
        sk_scka: [0u8; 32],
        k_route_master: [0u8; 32],
        k_confirm: [0u8; 32],
        transcript_hash: th,
        init_hash_v2: ih,
        session_id: sid_h.finalize().into(),
    };
    out.sk_ec.copy_from_slice(&okm[0..32]);
    out.sk_scka.copy_from_slice(&okm[32..64]);
    out.k_route_master.copy_from_slice(&okm[64..96]);
    out.k_confirm.copy_from_slice(&okm[96..128]);
    Ok(out)
}

pub fn kdf_rk(rk: &[u8; 32], dh_out: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), String> {
    if *dh_out == [0u8; 32] {
        return Err("non-contributory DH".into());
    }
    let okm = hkdf_sha256(dh_out, rk, EC_RK_INFO, 64);
    let mut rk2 = [0u8; 32];
    let mut ck = [0u8; 32];
    rk2.copy_from_slice(&okm[..32]);
    ck.copy_from_slice(&okm[32..]);
    Ok((rk2, ck))
}

pub fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut m1 = HmacSha256::new_from_slice(ck).expect("hmac");
    m1.update(&[0x01]);
    let mk: [u8; 32] = m1.finalize().into_bytes().into();
    let mut m2 = HmacSha256::new_from_slice(ck).expect("hmac");
    m2.update(&[0x02]);
    let ck2: [u8; 32] = m2.finalize().into_bytes().into();
    (ck2, mk)
}

pub fn kdf_hybrid(ec_mk: &[u8; 32], scka_mk: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let okm = hkdf_sha256(ec_mk, scka_mk, TR_PROTOCOL_INFO, 44);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..44]);
    (key, nonce)
}

/// SCKA-INIT root/chain keys: wiped on drop, redacted from Debug.
#[derive(Clone, PartialEq, Eq)]
pub struct SckaInitOut {
    pub rk: [u8; 32],
    pub ck_send: [u8; 32],
    pub ck_recv: [u8; 32],
}

impl fmt::Debug for SckaInitOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SckaInitOut { <redacted> }")
    }
}

impl Drop for SckaInitOut {
    fn drop(&mut self) {
        self.rk.zeroize();
        self.ck_send.zeroize();
        self.ck_recv.zeroize();
    }
}

pub fn ratchet_init_alice_scka(sk: &[u8; 32]) -> SckaInitOut {
    let okm = hkdf_sha256(sk, &[0u8; 32], SCKA_INIT_INFO, 96);
    let mut out = SckaInitOut {
        rk: [0; 32],
        ck_send: [0; 32],
        ck_recv: [0; 32],
    };
    out.rk.copy_from_slice(&okm[0..32]);
    out.ck_send.copy_from_slice(&okm[32..64]);
    out.ck_recv.copy_from_slice(&okm[64..96]);
    out
}

pub fn ratchet_init_bob_scka(sk: &[u8; 32]) -> SckaInitOut {
    let okm = hkdf_sha256(sk, &[0u8; 32], SCKA_INIT_INFO, 96);
    let mut out = SckaInitOut {
        rk: [0; 32],
        ck_send: [0; 32],
        ck_recv: [0; 32],
    };
    out.rk.copy_from_slice(&okm[0..32]);
    out.ck_send.copy_from_slice(&okm[64..96]);
    out.ck_recv.copy_from_slice(&okm[32..64]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.pop();
        p.join("shared-vectors/rvn1/atsam")
    }

    fn load(name: &str) -> Value {
        serde_json::from_str(&std::fs::read_to_string(root().join(name)).unwrap()).unwrap()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    #[test]
    fn pair_expand_001() {
        let v = load("pair_init_v2_001.json");
        let wire = hex::decode(v["expected"]["pair_init_wire_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            wire.len(),
            v["expected"]["pair_init_wire_len"].as_u64().unwrap() as usize
        );
        let zx = hex32(v["inputs"]["z_x_hex"].as_str().unwrap());
        let zp = hex32(v["inputs"]["z_pq_hex"].as_str().unwrap());
        let e = pair_expand(&zx, &zp, &wire).unwrap();
        assert_eq!(
            hex::encode(e.sk_ec),
            v["expected"]["sk_ec_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(e.sk_scka),
            v["expected"]["sk_scka_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(e.k_route_master),
            v["expected"]["k_route_master_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(e.session_id),
            v["expected"]["session_id_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn pair_expand_002_z_x_derives_from_wire_keys() {
        use crate::hybrid_ratchet_v2_tr::{x25519_dh, x25519_public};

        let v = load("pair_init_v2_002.json");
        let wire = hex::decode(v["expected"]["pair_init_wire_hex"].as_str().unwrap()).unwrap();
        let offsets = &v["expected"]["offsets"];
        let at = |field: &str| {
            let off = offsets[field].as_u64().unwrap() as usize;
            let mut out = [0u8; 32];
            out.copy_from_slice(&wire[off..off + 32]);
            out
        };
        let eph_priv = hex32(
            v["inputs"]["initiator_ephemeral_x25519_priv_hex"]
                .as_str()
                .unwrap(),
        );
        let otp_priv = hex32(
            v["inputs"]["responder_otp_x25519_priv_hex"]
                .as_str()
                .unwrap(),
        );
        let eph_pub = at("initiator_ephemeral_x25519_pub");
        let otp_pub = at("responder_one_time_x25519_pub");
        assert_eq!(x25519_public(&eph_priv).unwrap(), eph_pub);
        assert_eq!(x25519_public(&otp_priv).unwrap(), otp_pub);
        // Z_X is the DH of exactly the keys the transcript carries.
        let z_x = x25519_dh(&eph_priv, &otp_pub).unwrap();
        assert_eq!(z_x, x25519_dh(&otp_priv, &eph_pub).unwrap());
        assert_eq!(hex::encode(z_x), v["expected"]["z_x_hex"].as_str().unwrap());
        assert_eq!(
            hex::encode(at("responder_prekey_bundle_hash")),
            v["expected"]["responder_prekey_bundle_hash_hex"]
                .as_str()
                .unwrap()
        );

        let zp = hex32(v["inputs"]["z_pq_hex"].as_str().unwrap());
        let e = pair_expand(&z_x, &zp, &wire).unwrap();
        for (field, value) in [
            ("sk_ec_hex", e.sk_ec),
            ("sk_scka_hex", e.sk_scka),
            ("k_route_master_hex", e.k_route_master),
            ("k_confirm_hex", e.k_confirm),
            ("session_id_hex", e.session_id),
        ] {
            assert_eq!(
                hex::encode(value),
                v["expected"][field].as_str().unwrap(),
                "{field}"
            );
        }
    }

    #[test]
    fn pair_expand_rejects_non_canonical_wire_length() {
        let v = load("pair_init_v2_001.json");
        let wire = hex::decode(v["expected"]["pair_init_wire_hex"].as_str().unwrap()).unwrap();
        assert_eq!(wire.len(), INIT_WIRE_LEN);
        let zx = hex32(v["inputs"]["z_x_hex"].as_str().unwrap());
        let zp = hex32(v["inputs"]["z_pq_hex"].as_str().unwrap());
        assert!(pair_expand(&zx, &zp, &wire).is_ok());
        // Truncated (still carries the RVPI2 magic) and extended wires.
        assert!(pair_expand(&zx, &zp, &wire[..100]).is_err());
        assert!(pair_expand(&zx, &zp, &wire[..INIT_WIRE_LEN - 1]).is_err());
        let mut longer = wire.clone();
        longer.push(0);
        assert!(pair_expand(&zx, &zp, &longer).is_err());
        assert!(pair_expand(&zx, &zp, &[]).is_err());
        // The PairInit V1 magic keeps its specific diagnostic.
        let mut v1 = wire.clone();
        v1[..8].copy_from_slice(INIT_MAGIC_V1);
        assert_eq!(
            pair_expand(&zx, &zp, &v1).unwrap_err(),
            "PairInit V1 must not be reinterpreted as V2"
        );
    }

    #[test]
    fn hkdf_sha256_matches_rfc5869_case_1_and_multi_block() {
        // RFC 5869 A.1 (SHA-256).
        let ikm = [0x0bu8; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42);
        assert_eq!(
            hex::encode(&okm[..]),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
        // Truncation and block counts agree with the reference implementation
        // for lengths that straddle the 32-byte block boundary.
        for len in [0usize, 1, 31, 32, 33, 64, 95, 96, 128] {
            let full = hkdf_sha256(&ikm, &salt, &info, 128);
            let part = hkdf_sha256(&ikm, &salt, &info, len);
            assert_eq!(part.len(), len);
            assert_eq!(&part[..], &full[..len]);
        }
    }

    #[test]
    fn v1_rejected() {
        let v = load("negative/pair_init_v1_as_v2_001.json");
        let wire = hex::decode(v["inputs"]["wire_hex"].as_str().unwrap()).unwrap();
        assert!(reject_if_pair_init_v1(&wire).is_err());
    }

    #[test]
    fn ec_kdf_001() {
        let v = load("tr_ec_kdf_001.json");
        let rk = hex32(v["inputs"]["rk_hex"].as_str().unwrap());
        let dh = hex32(v["inputs"]["dh_out_hex"].as_str().unwrap());
        let (rk1, ck) = kdf_rk(&rk, &dh).unwrap();
        let (ck2, mk) = kdf_ck(&ck);
        assert_eq!(
            hex::encode(rk1),
            v["expected"]["rk_next_hex"].as_str().unwrap()
        );
        assert_eq!(hex::encode(ck), v["expected"]["ck_hex"].as_str().unwrap());
        assert_eq!(
            hex::encode(ck2),
            v["expected"]["ck_next_hex"].as_str().unwrap()
        );
        assert_eq!(hex::encode(mk), v["expected"]["mk_hex"].as_str().unwrap());
    }

    #[test]
    fn scka_init_001() {
        let v = load("tr_scka_init_001.json");
        let sk = hex32(v["inputs"]["sk_scka_hex"].as_str().unwrap());
        let a = ratchet_init_alice_scka(&sk);
        let b = ratchet_init_bob_scka(&sk);
        assert_eq!(
            hex::encode(a.ck_send),
            v["expected"]["alice"]["ck_send_hex"].as_str().unwrap()
        );
        assert_eq!(a.ck_send, b.ck_recv);
        assert_ne!(a.ck_send, b.ck_send);
    }

    #[test]
    fn hybrid_001() {
        let v = load("tr_hybrid_aead_001.json");
        let ec = hex32(v["inputs"]["ec_mk_hex"].as_str().unwrap());
        let pq = hex32(v["inputs"]["scka_mk_hex"].as_str().unwrap());
        let (key, nonce) = kdf_hybrid(&ec, &pq);
        assert_eq!(
            hex::encode(key),
            v["expected"]["aead_key_hex"].as_str().unwrap()
        );
        assert_eq!(
            hex::encode(nonce),
            v["expected"]["nonce_hex"].as_str().unwrap()
        );
    }

    #[test]
    fn sealed_proto_constant() {
        let v = load("tr_domain_labels_001.json");
        assert_eq!(v["expected"]["SEALED_PROTO"].as_str().unwrap(), "04");
        assert_eq!(SEALED_PROTO, 0x04);
        assert_eq!(MAX_SKIP, 1000);
    }
}
