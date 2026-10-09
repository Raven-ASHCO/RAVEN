//! Revocation store conformance (union / quota / corrupt / auth gates).
//! Spec: `protocol/RAVEN_DEVICE_REVOCATION_V1.md` — KAT only, not production SQL.

use crate::device_revocation::{
    claim_digest, revocation_store_hash, CorruptMarker, DeviceRevocationV1, ExhaustedMarker,
    StoreClaim,
};
use std::collections::BTreeMap;

/// Frozen corrupt-marker reason codes (RAVEN_DEVICE_REVOCATION_V1 §6.0). They
/// are hashed into `revocation_store_hash`, so every implementation must agree.
/// Journal bytes that are not one complete canonical RVDR1 record (short, or
/// failing strict parse).
pub const CORRUPT_TRUNCATED: u8 = 1;
/// Journal `claim_digest` differs from SHA-256 of the exact bytes.
pub const CORRUPT_DIGEST_MISMATCH: u8 = 2;
/// Record parses but the identity signature / address binding fails.
pub const CORRUPT_BAD_SIGNATURE: u8 = 3;

pub const SURFACES: &[&str] = &[
    "pair_init_v1",
    "pair_init_v2",
    "session",
    "message",
    "ack",
    "noise_bind",
];

#[derive(Debug, Clone)]
pub struct RevokedTarget {
    pub kind: String,
    pub value_hex: String,
    pub claim_digest_hex: String,
    pub revocation_id_hex: String,
}

#[derive(Debug, Clone)]
pub struct Journal {
    pub kind: String,
    pub claim_digest_hex: String,
    pub exact_record_bytes: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ConformanceStore {
    pub identity_address: String,
    pub generation: u64,
    pub claims: BTreeMap<String, Vec<u8>>,
    pub revoked: Vec<RevokedTarget>,
    pub exhausted: Vec<ExhaustedMarker>,
    pub corrupt: Vec<CorruptMarker>,
    pub seen_revocation_ids: BTreeMap<String, String>,
    pub collisions: Vec<(String, String, String)>, // id, first, second
    pub max_claims: usize,
    pub journal: Option<Journal>,
}

impl ConformanceStore {
    pub fn new(identity_address: String, max_claims: usize) -> Self {
        Self {
            identity_address,
            generation: 0,
            claims: BTreeMap::new(),
            revoked: Vec::new(),
            exhausted: Vec::new(),
            corrupt: Vec::new(),
            seen_revocation_ids: BTreeMap::new(),
            collisions: Vec::new(),
            max_claims,
            journal: None,
        }
    }

    pub fn store_hash(&self) -> Result<[u8; 32], String> {
        let claims: Vec<StoreClaim> = self
            .claims
            .values()
            .map(|b| StoreClaim {
                exact_record_bytes: b.clone(),
            })
            .collect();
        revocation_store_hash(self.generation, &claims, &self.exhausted, &self.corrupt)
    }
}

fn append_targets(store: &mut ConformanceStore, rec: &DeviceRevocationV1, cd: &[u8; 32]) {
    let cd_h = hex::encode(cd);
    let rid = hex::encode(rec.revocation_id);
    let entries = [
        ("device_id", hex::encode(&rec.device_id)),
        ("device_ed_pub", hex::encode(rec.device_ed_pub)),
        ("device_x_pub", hex::encode(rec.device_x_pub)),
        ("device_cert_hash", hex::encode(rec.device_cert_hash)),
    ];
    for (kind, value_hex) in entries {
        if !store
            .revoked
            .iter()
            .any(|t| t.kind == kind && t.value_hex == value_hex)
        {
            store.revoked.push(RevokedTarget {
                kind: kind.to_string(),
                value_hex,
                claim_digest_hex: cd_h.clone(),
                revocation_id_hex: rid.clone(),
            });
        }
    }
}

pub fn apply_verified_claim(
    store: &mut ConformanceStore,
    wire: &[u8],
    identity_ed_pub: &[u8; 32],
    pending_already_written: bool,
) -> Result<&'static str, String> {
    let rec = DeviceRevocationV1::decode(wire)?;
    if rec.identity_address != store.identity_address {
        return Err("identity_address mismatch".into());
    }
    rec.verify(identity_ed_pub)?;
    let cd = claim_digest(wire);
    let cd_h = hex::encode(cd);

    if pending_already_written {
        let j = store.journal.as_ref().ok_or("missing_pending")?;
        if j.kind == "PENDING_REVOKE_EXHAUSTED" {
            return Err("direct_exhausted_consumption".into());
        }
        if j.kind != "PENDING_REVOKE" {
            return Err("missing_pending".into());
        }
        if j.exact_record_bytes != wire {
            return Err("pending_bytes_mismatch".into());
        }
        if j.claim_digest_hex != cd_h {
            return Err("pending_digest_mismatch".into());
        }
    } else if store
        .journal
        .as_ref()
        .map(|j| j.kind == "PENDING_REVOKE_EXHAUSTED")
        .unwrap_or(false)
    {
        return Err("direct_exhausted_consumption".into());
    }

    if store.claims.contains_key(&cd_h) {
        return Ok("idempotent");
    }
    if !store.corrupt.is_empty() {
        return Err("REVOCATION_STORE_CORRUPT".into());
    }
    if store.claims.len() >= store.max_claims {
        let exh = ExhaustedMarker {
            identity_address: store.identity_address.clone(),
            claim_digest: cd,
            exact_record_bytes: wire.to_vec(),
        };
        store.exhausted.retain(|e| e.claim_digest != cd);
        store.exhausted.push(exh);
        store.journal = Some(Journal {
            kind: "PENDING_REVOKE_EXHAUSTED".into(),
            claim_digest_hex: cd_h,
            exact_record_bytes: wire.to_vec(),
        });
        store.generation += 1;
        return Ok("exhausted");
    }
    let rid = hex::encode(rec.revocation_id);
    if let Some(first) = store.seen_revocation_ids.get(&rid) {
        if first != &cd_h {
            store
                .collisions
                .push((rid.clone(), first.clone(), cd_h.clone()));
        }
    } else {
        store.seen_revocation_ids.insert(rid, cd_h.clone());
    }
    store.claims.insert(cd_h, wire.to_vec());
    append_targets(store, &rec, &cd);
    store.exhausted.retain(|e| e.claim_digest != cd);
    if pending_already_written
        || store
            .journal
            .as_ref()
            .map(|j| j.kind == "PENDING_REVOKE")
            .unwrap_or(false)
    {
        store.journal = None;
    }
    store.generation += 1;
    Ok("applied")
}

pub fn expand_quota(store: &mut ConformanceStore, new_max: usize) -> Result<(), String> {
    if new_max < store.max_claims {
        return Err("quota may only expand".into());
    }
    store.max_claims = new_max;
    Ok(())
}

pub fn convert_exhausted_journal_to_pending(store: &mut ConformanceStore) -> Result<(), String> {
    let j = store.journal.as_ref().ok_or("no journal")?;
    if j.kind != "PENDING_REVOKE_EXHAUSTED" {
        return Err("not exhausted journal".into());
    }
    store.journal = Some(Journal {
        kind: "PENDING_REVOKE".into(),
        claim_digest_hex: j.claim_digest_hex.clone(),
        exact_record_bytes: j.exact_record_bytes.clone(),
    });
    Ok(())
}

pub fn reverify_journal(
    store: &mut ConformanceStore,
    identity_ed_pub: &[u8; 32],
) -> Result<(&'static str, Option<u8>), String> {
    let j = store.journal.as_ref().ok_or("no journal")?.clone();
    let wire = j.exact_record_bytes;
    let fail = |store: &mut ConformanceStore, code: u8| {
        store.corrupt.push(CorruptMarker {
            scope: store.identity_address.clone(),
            reason_code: code,
        });
        store.journal = None;
        store.generation += 1;
        Ok(("corrupt", Some(code)))
    };
    if wire.len() < 54 {
        return fail(store, CORRUPT_TRUNCATED);
    }
    // Any strict-parse failure is "not a complete record" (code 1), for every
    // length; Python and Rust must hash the same marker.
    let rec = match DeviceRevocationV1::decode(&wire) {
        Ok(r) => r,
        Err(_) => {
            return fail(store, CORRUPT_TRUNCATED);
        }
    };
    let cd = claim_digest(&wire);
    let cd_h = hex::encode(cd);
    if cd_h != j.claim_digest_hex {
        return fail(store, CORRUPT_DIGEST_MISMATCH);
    }
    if rec.verify(identity_ed_pub).is_err() {
        return fail(store, CORRUPT_BAD_SIGNATURE);
    }
    Ok(("ok", None))
}

pub struct AuthResult {
    pub authorized: bool,
    pub reason: &'static str,
    pub surface: String,
    pub matched_kind: Option<&'static str>,
}

pub fn authorize_device(
    store: &ConformanceStore,
    device_id: Option<&[u8]>,
    device_ed_pub: Option<&[u8]>,
    device_x_pub: Option<&[u8]>,
    device_cert_hash: Option<&[u8]>,
    surface: &str,
) -> AuthResult {
    if !store.corrupt.is_empty() {
        return AuthResult {
            authorized: false,
            reason: "REVOCATION_STORE_CORRUPT",
            surface: surface.into(),
            matched_kind: None,
        };
    }
    if store
        .exhausted
        .iter()
        .any(|e| e.identity_address == store.identity_address)
    {
        return AuthResult {
            authorized: false,
            reason: "IDENTITY_REVOKE_EXHAUSTED",
            surface: surface.into(),
            matched_kind: None,
        };
    }
    let checks: [(&str, Option<String>); 4] = [
        ("device_id", device_id.map(hex::encode)),
        ("device_ed_pub", device_ed_pub.map(hex::encode)),
        ("device_x_pub", device_x_pub.map(hex::encode)),
        ("device_cert_hash", device_cert_hash.map(hex::encode)),
    ];
    for (kind, val) in checks {
        let Some(val) = val else { continue };
        if store
            .revoked
            .iter()
            .any(|t| t.kind == kind && t.value_hex == val)
        {
            return AuthResult {
                authorized: false,
                reason: "revoked_target",
                surface: surface.into(),
                matched_kind: Some(kind),
            };
        }
    }
    AuthResult {
        authorized: true,
        reason: "ok",
        surface: surface.into(),
        matched_kind: None,
    }
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
        p.join("shared-vectors/rvn1/device_revocation")
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

    fn assert_revoked_targets(store: &ConformanceStore, expected: &Value) {
        let arr = expected.as_array().unwrap();
        let mut got = store.revoked.clone();
        got.sort_by(|a, b| {
            (
                a.claim_digest_hex.as_str(),
                a.kind.as_str(),
                a.value_hex.as_str(),
            )
                .cmp(&(
                    b.claim_digest_hex.as_str(),
                    b.kind.as_str(),
                    b.value_hex.as_str(),
                ))
        });
        assert_eq!(got.len(), arr.len());
        for (g, exp) in got.iter().zip(arr.iter()) {
            assert_eq!(g.kind, exp["kind"].as_str().unwrap());
            assert_eq!(g.value_hex, exp["value_hex"].as_str().unwrap());
            assert_eq!(
                g.claim_digest_hex,
                exp["claim_digest_hex"].as_str().unwrap()
            );
            assert_eq!(
                g.revocation_id_hex,
                exp["revocation_id_hex"].as_str().unwrap()
            );
        }
    }

    fn assert_collisions(store: &ConformanceStore, expected: &Value) {
        let arr = expected.as_array().unwrap();
        assert_eq!(store.collisions.len(), arr.len());
        for (got, exp) in store.collisions.iter().zip(arr.iter()) {
            assert_eq!(got.0, exp["revocation_id_hex"].as_str().unwrap());
            assert_eq!(got.1, exp["first_claim_digest_hex"].as_str().unwrap());
            assert_eq!(got.2, exp["second_claim_digest_hex"].as_str().unwrap());
        }
    }

    fn peer_bytes(peer: &Value) -> (Vec<u8>, [u8; 32], [u8; 32], [u8; 32]) {
        (
            peer["device_id_utf8"].as_str().unwrap().as_bytes().to_vec(),
            hex32(peer["device_ed_pub_hex"].as_str().unwrap()),
            hex32(peer["device_x_pub_hex"].as_str().unwrap()),
            hex32(peer["device_cert_hash_hex"].as_str().unwrap()),
        )
    }

    #[test]
    fn union_001() {
        let v = load("union_001.json");
        let addr = v["inputs"]["identity_address"]
            .as_str()
            .unwrap()
            .to_string();
        let pubk = hex32(v["inputs"]["identity_ed_pub_hex"].as_str().unwrap());
        let mut store = ConformanceStore::new(addr, 10_000);
        let mut results = Vec::new();
        for h in v["inputs"]["claims_wire_hex"].as_array().unwrap() {
            let wire = hex::decode(h.as_str().unwrap()).unwrap();
            results.push(apply_verified_claim(&mut store, &wire, &pubk, false).unwrap());
        }
        assert_eq!(results, vec!["applied", "applied"]);
        assert_eq!(
            hex::encode(store.store_hash().unwrap()),
            v["expected"]["store"]["revocation_store_hash_hex"]
                .as_str()
                .unwrap()
        );
        assert_revoked_targets(&store, &v["expected"]["store"]["revoked_targets"]);
        assert_collisions(&store, &v["expected"]["store"]["revocation_id_collisions"]);
    }

    #[test]
    fn collision_revocation_id_001() {
        let v = load("collision_revocation_id_001.json");
        let addr = v["inputs"]["identity_address"]
            .as_str()
            .unwrap()
            .to_string();
        let pubk = hex32(v["inputs"]["identity_ed_pub_hex"].as_str().unwrap());
        let mut store = ConformanceStore::new(addr, 10_000);
        for h in v["inputs"]["claims_wire_hex"].as_array().unwrap() {
            let wire = hex::decode(h.as_str().unwrap()).unwrap();
            apply_verified_claim(&mut store, &wire, &pubk, false).unwrap();
        }
        assert_eq!(
            hex::encode(store.store_hash().unwrap()),
            v["expected"]["store"]["revocation_store_hash_hex"]
                .as_str()
                .unwrap()
        );
        assert_revoked_targets(&store, &v["expected"]["store"]["revoked_targets"]);
        assert_collisions(&store, &v["expected"]["store"]["revocation_id_collisions"]);
    }

    #[test]
    fn quota_machine_001() {
        let v = load("quota_machine_001.json");
        let gates = load("apply_gates_001.json");
        let addr = v["inputs"]["identity_address"]
            .as_str()
            .unwrap()
            .to_string();
        let pubk = hex32(v["inputs"]["identity_ed_pub_hex"].as_str().unwrap());
        let mut store = ConformanceStore::new(
            addr,
            v["inputs"]["max_claims_initial"].as_u64().unwrap() as usize,
        );
        let bob = hex::decode(v["inputs"]["wire_bob_hex"].as_str().unwrap()).unwrap();
        let carol = hex::decode(v["inputs"]["wire_carol_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            apply_verified_claim(&mut store, &bob, &pubk, false).unwrap(),
            "applied"
        );
        assert_eq!(
            apply_verified_claim(&mut store, &carol, &pubk, false).unwrap(),
            "exhausted"
        );
        let step3 = v["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == 3)
            .unwrap();
        assert_eq!(
            hex::encode(store.store_hash().unwrap()),
            step3["store_hash_hex"].as_str().unwrap()
        );
        assert_eq!(
            apply_verified_claim(&mut store, &carol, &pubk, true).unwrap_err(),
            "direct_exhausted_consumption"
        );
        let (cid, ced, cx, cch) = peer_bytes(&gates["inputs"]["carol_peer"]);
        for s in SURFACES {
            let r = authorize_device(&store, Some(&cid), Some(&ced), Some(&cx), Some(&cch), s);
            assert!(!r.authorized);
            assert_eq!(r.reason, "IDENTITY_REVOKE_EXHAUSTED");
        }
        expand_quota(
            &mut store,
            v["inputs"]["max_claims_after_expand"].as_u64().unwrap() as usize,
        )
        .unwrap();
        assert_eq!(reverify_journal(&mut store, &pubk).unwrap().0, "ok");
        convert_exhausted_journal_to_pending(&mut store).unwrap();
        assert_eq!(
            apply_verified_claim(&mut store, &carol, &pubk, true).unwrap(),
            "applied"
        );
        assert_eq!(
            hex::encode(store.store_hash().unwrap()),
            v["expected_after"]["revocation_store_hash_hex"]
                .as_str()
                .unwrap()
        );
        assert_revoked_targets(&store, &v["expected_after"]["revoked_targets"]);
    }

    #[test]
    fn corrupt_journal_matrix() {
        for (name, reason_code) in [
            ("corrupt_journal_truncated_001.json", CORRUPT_TRUNCATED),
            ("corrupt_journal_malformed_001.json", CORRUPT_TRUNCATED),
            (
                "corrupt_journal_digest_mismatch_001.json",
                CORRUPT_DIGEST_MISMATCH,
            ),
            (
                "corrupt_journal_bad_signature_001.json",
                CORRUPT_BAD_SIGNATURE,
            ),
        ] {
            let v = load(name);
            let addr = v["inputs"]["identity_address"]
                .as_str()
                .unwrap()
                .to_string();
            let pubk = hex32(v["inputs"]["identity_ed_pub_hex"].as_str().unwrap());
            let mut store = ConformanceStore::new(addr, 10_000);
            let jb = &v["inputs"]["journal_before"];
            store.journal = Some(Journal {
                kind: jb["kind"].as_str().unwrap().into(),
                claim_digest_hex: jb["claim_digest_hex"].as_str().unwrap().into(),
                exact_record_bytes: hex::decode(jb["exact_record_bytes_hex"].as_str().unwrap())
                    .unwrap(),
            });
            let (res, code) = reverify_journal(&mut store, &pubk).unwrap();
            assert_eq!(res, "corrupt");
            assert_eq!(code, Some(reason_code));
            assert!(store.journal.is_none());
            assert_eq!(
                hex::encode(store.store_hash().unwrap()),
                v["expected"]["store"]["revocation_store_hash_hex"]
                    .as_str()
                    .unwrap()
            );
        }
    }

    #[test]
    fn corrupt_recovery_authorize() {
        let v = load("corrupt_journal_recovery_001.json");
        let mut store = ConformanceStore::new(
            v["inputs"]["identity_address"].as_str().unwrap().into(),
            10_000,
        );
        for c in v["inputs"]["corrupt"].as_array().unwrap() {
            store.corrupt.push(CorruptMarker {
                scope: c["scope"].as_str().unwrap().into(),
                reason_code: c["reason_code"].as_u64().unwrap() as u8,
            });
        }
        let (id, ed, x, ch) = peer_bytes(&v["inputs"]["peer"]);
        for (i, s) in SURFACES.iter().enumerate() {
            let r = authorize_device(&store, Some(&id), Some(&ed), Some(&x), Some(&ch), s);
            let exp = &v["expected"]["gates"][i];
            assert_eq!(r.authorized, exp["authorized"].as_bool().unwrap());
            assert_eq!(r.reason, exp["reason"].as_str().unwrap());
            assert_eq!(r.surface, exp["surface"].as_str().unwrap());
        }
    }

    #[test]
    fn apply_gates_001() {
        let v = load("apply_gates_001.json");
        let addr = v["inputs"]["identity_address"]
            .as_str()
            .unwrap()
            .to_string();
        let pubk = hex32(v["inputs"]["identity_ed_pub_hex"].as_str().unwrap());
        let mut store = ConformanceStore::new(addr.clone(), 10_000);
        let wire = hex::decode(v["inputs"]["revoked_wire_hex"].as_str().unwrap()).unwrap();
        apply_verified_claim(&mut store, &wire, &pubk, false).unwrap();
        let (bid, bed, bx, bch) = peer_bytes(&v["inputs"]["bob_peer"]);
        let (cid, ced, cx, cch) = peer_bytes(&v["inputs"]["carol_peer"]);
        for (i, s) in SURFACES.iter().enumerate() {
            let r = authorize_device(&store, Some(&bid), Some(&bed), Some(&bx), Some(&bch), s);
            let exp = &v["expected"]["bob_revoked_gates"][i];
            assert_eq!(r.authorized, exp["authorized"].as_bool().unwrap());
            assert_eq!(r.reason, exp["reason"].as_str().unwrap());
        }
        for (i, s) in SURFACES.iter().enumerate() {
            let r = authorize_device(&store, Some(&cid), Some(&ced), Some(&cx), Some(&cch), s);
            let exp = &v["expected"]["carol_unrevoked_gates"][i];
            assert_eq!(r.authorized, exp["authorized"].as_bool().unwrap());
        }
        let carol_wire = hex::decode(v["inputs"]["carol_wire_hex"].as_str().unwrap()).unwrap();
        let mut ex = ConformanceStore::new(addr, 1);
        apply_verified_claim(&mut ex, &wire, &pubk, false).unwrap();
        apply_verified_claim(&mut ex, &carol_wire, &pubk, false).unwrap();
        for (i, s) in SURFACES.iter().enumerate() {
            let r = authorize_device(&ex, Some(&cid), Some(&ced), Some(&cx), Some(&cch), s);
            let exp = &v["expected"]["carol_under_exhausted_gates"][i];
            assert_eq!(r.authorized, exp["authorized"].as_bool().unwrap());
            assert_eq!(r.reason, exp["reason"].as_str().unwrap());
        }
    }

    #[test]
    fn pending_binding_negatives() {
        let v = load("pending_binding_negatives_001.json");
        let addr = v["inputs"]["identity_address"]
            .as_str()
            .unwrap()
            .to_string();
        let pubk = hex32(v["inputs"]["identity_ed_pub_hex"].as_str().unwrap());
        for case in v["cases"].as_array().unwrap() {
            let mut store = ConformanceStore::new(addr.clone(), 10_000);
            if !case["journal_before"].is_null() {
                let jb = &case["journal_before"];
                store.journal = Some(Journal {
                    kind: jb["kind"].as_str().unwrap().into(),
                    claim_digest_hex: jb["claim_digest_hex"].as_str().unwrap().into(),
                    exact_record_bytes: hex::decode(jb["exact_record_bytes_hex"].as_str().unwrap())
                        .unwrap(),
                });
            }
            let wire = hex::decode(case["apply_wire_hex"].as_str().unwrap()).unwrap();
            let err = apply_verified_claim(&mut store, &wire, &pubk, true).unwrap_err();
            assert_eq!(err, case["expected_error"].as_str().unwrap());
        }
    }
}
