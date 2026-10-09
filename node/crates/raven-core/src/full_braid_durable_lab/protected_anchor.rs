//! Task 0B.1 — protected installation seed scope/KDF and RVFA1 codec (lab-only).
//!
//! No OS credential backends. Production remains disabled.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

/// RFC 5869 HKDF-SHA256 extract+expand (all-zero salt when empty).
/// Temporary PRK/T/OKM buffers are zeroized before return.
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Zeroizing<Vec<u8>> {
    let salt = if salt.is_empty() {
        &[0u8; 32][..]
    } else {
        salt
    };
    let mut mac = HmacSha256::new_from_slice(salt).expect("hmac");
    mac.update(ikm);
    let mut prk = Zeroizing::new(mac.finalize().into_bytes().to_vec());
    let mut okm = Zeroizing::new(Vec::with_capacity(length.saturating_add(32)));
    let mut t = Zeroizing::new(Vec::<u8>::new());
    let mut counter = 1u8;
    while okm.len() < length {
        let mut m = HmacSha256::new_from_slice(&prk).expect("hmac");
        m.update(&t);
        m.update(info);
        m.update(&[counter]);
        let mut next = Zeroizing::new(m.finalize().into_bytes().to_vec());
        t.clear();
        t.extend_from_slice(&next);
        okm.extend_from_slice(&next);
        next.zeroize();
        counter = counter.wrapping_add(1);
    }
    okm.truncate(length);
    // Zeroizing Drop wipes prk/t/okm; explicit wipe keeps temporaries clear on early paths too.
    prk.zeroize();
    t.zeroize();
    okm
}

pub const RVFA1_LEN: usize = 204;
pub const RVFA1_PREFIX_LEN: usize = 172;
pub const SEED_LEN: usize = 32;
pub const INITIAL_ANCHOR_SEQ: u64 = 1;
pub const RVFA1_MAGIC: &[u8; 8] = b"RVFA1\0\0\0";
pub const RVFA1_SCHEMA: u16 = 1;

pub const APPLE_SEED_SERVICE: &str = "app.raven.atsam.full-braid.store.v1";
pub const APPLE_ANCHOR_SERVICE: &str = "app.raven.atsam.full-braid.anchor.v1";
pub const LINUX_APPLICATION: &str = "app.raven.node";
pub const LINUX_PROTOCOL: &str = "atsam-full-braid-v1";
pub const WINDOWS_TARGET_PREFIX: &str = "Raven/ATSAM/FullBraid/v1";
pub const WINDOWS_CRED_MAX_BLOB: usize = 2560;
pub const MAX_FULL_BRAID_SESSIONS: usize = 4096;
pub const RELEASE_HOLD: &str = "FULL_BRAID_PROTECTED_ANCHOR_NOT_APPROVED";

pub const ERROR_CODES: &[&str] = &[
    "UNAVAILABLE",
    "LOCKED_OR_PROMPT_REQUIRED",
    "MISSING",
    "DUPLICATE",
    "CONFLICT",
    "CORRUPT_LENGTH",
    "CORRUPT_ATTRIBUTES",
    "WRONG_ACCESSIBILITY_OR_PERSISTENCE",
    "CAPACITY",
    "READBACK_MISMATCH",
    "IO_OR_PLATFORM",
];

pub const SCOPE_DOMAIN: &[u8] = b"ATSAM/v2/full-braid/durable/platform-scope";
pub const RECORD_DOMAIN: &[u8] = b"ATSAM/v2/full-braid/durable/record";
pub const APPLE_APP_ID: &[u8] = b"app.raven.ios";
pub const APPLE_LOGICAL_ROOT: &[u8] = b"group.app.raven.fullbraid";
pub const TERMINAL_APP_ID: &[u8] = b"app.raven.node";

const INFO_STATE: &[u8] = b"ATSAM/v2/full-braid/durable/state-aead";
const INFO_INDEX: &[u8] = b"ATSAM/v2/full-braid/durable/index";
const INFO_SQL: &[u8] = b"ATSAM/v2/full-braid/durable/sqlcipher";
const INFO_LOCAL: &[u8] = b"ATSAM/v2/full-braid/durable/domain-local";
const INFO_ANCHOR: &[u8] = b"ATSAM/v2/full-braid/durable/anchor";
const INFO_SQL_SALT: &[u8] = b"ATSAM/v2/full-braid/durable/sqlcipher-salt";
const INFO_STATE_RECORD: &[u8] = b"ATSAM/v2/full-braid/durable/state-record";
const INFO_STAGE: &[u8] = b"ATSAM/v2/full-braid/durable/domain-stage";
const ZERO_SALT: [u8; 32] = [0u8; 32];
const ZERO32: [u8; 32] = [0u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rvfa1Status {
    Head = 1,
    Deleting = 2,
    Tombstone = 3,
}

impl Rvfa1Status {
    fn from_u8(value: u8) -> Result<Self, ProtectedAnchorError> {
        match value {
            1 => Ok(Self::Head),
            2 => Ok(Self::Deleting),
            3 => Ok(Self::Tombstone),
            _ => Err(ProtectedAnchorError::Codec("bad status")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendDecision {
    Appended,
    ExactReplay,
    Corrupt,
}

impl AppendDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Appended => "Appended",
            Self::ExactReplay => "ExactReplay",
            Self::Corrupt => "Corrupt",
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtectedAnchorError {
    #[error("PROTECTED_ANCHOR_CODEC:{0}")]
    Codec(&'static str),
}

pub struct DerivedKeys {
    pub k_state: [u8; 32],
    pub k_index: [u8; 32],
    pub k_sql: [u8; 32],
    pub k_local: [u8; 32],
    pub k_anchor: [u8; 32],
    pub k_sql_salt: [u8; 16],
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.k_state.zeroize();
        self.k_index.zeroize();
        self.k_sql.zeroize();
        self.k_local.zeroize();
        self.k_anchor.zeroize();
        self.k_sql_salt.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rvfa1 {
    pub status: Rvfa1Status,
    pub role: u8,
    pub record_key: [u8; 32],
    pub session_id: [u8; 32],
    pub anchor_seq: u64,
    pub generation: u64,
    pub cleared_state_digest: [u8; 32],
    pub cleared_store_revision: u64,
    pub transition_id: [u8; 32],
    pub horizon_ms: u64,
    /// Empty/all-zero means "compute on encode"; any other value must match.
    pub hmac: [u8; 32],
}

fn u32be(n: u32) -> [u8; 4] {
    n.to_be_bytes()
}

fn require_nonempty(bytes: &[u8]) -> Result<(), ProtectedAnchorError> {
    if bytes.is_empty() {
        return Err(ProtectedAnchorError::Codec("empty scope component"));
    }
    Ok(())
}

pub fn scope_id(
    platform_app_id: &[u8],
    logical_root_id: &[u8],
) -> Result<[u8; 32], ProtectedAnchorError> {
    require_nonempty(platform_app_id)?;
    require_nonempty(logical_root_id)?;
    if logical_root_id == b"group.app.raven.shared" || logical_root_id == b"group.app.raven.ios" {
        return Err(ProtectedAnchorError::Codec(
            "forbidden Raven App Group fallback",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(SCOPE_DOMAIN);
    hasher.update(u32be(platform_app_id.len() as u32));
    hasher.update(platform_app_id);
    hasher.update(u32be(logical_root_id.len() as u32));
    hasher.update(logical_root_id);
    Ok(hasher.finalize().into())
}

pub fn apple_scope_id() -> [u8; 32] {
    scope_id(APPLE_APP_ID, APPLE_LOGICAL_ROOT).expect("apple scope")
}

pub fn terminal_scope_id(canonical_root_bytes: &[u8]) -> Result<[u8; 32], ProtectedAnchorError> {
    scope_id(TERMINAL_APP_ID, canonical_root_bytes)
}

/// Derive straight into the (wipe-on-drop) destination: no loose stack copy.
fn hkdf32_into(out: &mut [u8; 32], ikm: &[u8], info: &[u8]) {
    let okm = hkdf_sha256(ikm, &ZERO_SALT, info, 32);
    out.copy_from_slice(&okm);
}

pub fn derive_store_keys(seed32: &[u8; SEED_LEN]) -> DerivedKeys {
    let mut keys = DerivedKeys {
        k_state: [0u8; 32],
        k_index: [0u8; 32],
        k_sql: [0u8; 32],
        k_local: [0u8; 32],
        k_anchor: [0u8; 32],
        k_sql_salt: [0u8; 16],
    };
    hkdf32_into(&mut keys.k_state, seed32, INFO_STATE);
    hkdf32_into(&mut keys.k_index, seed32, INFO_INDEX);
    hkdf32_into(&mut keys.k_sql, seed32, INFO_SQL);
    hkdf32_into(&mut keys.k_local, seed32, INFO_LOCAL);
    hkdf32_into(&mut keys.k_anchor, seed32, INFO_ANCHOR);
    let salt16 = hkdf_sha256(seed32, &ZERO_SALT, INFO_SQL_SALT, 16);
    keys.k_sql_salt.copy_from_slice(&salt16);
    keys
}

pub fn record_key(k_index: &[u8; 32], session_id: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(k_index).expect("hmac");
    mac.update(RECORD_DOMAIN);
    mac.update(session_id);
    mac.finalize().into_bytes().into()
}

/// Per-record state key; wiped when the returned value is dropped.
pub fn k_state_record(k_state: &[u8; 32], record_key32: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let okm = hkdf_sha256(k_state, record_key32, INFO_STATE_RECORD, 32);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&okm);
    out
}

/// Per-transition stage key; wiped when the returned value is dropped.
pub fn k_stage_transition(k_local: &[u8; 32], transition_id: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let okm = hkdf_sha256(k_local, transition_id, INFO_STAGE, 32);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&okm);
    out
}

fn prefix_bytes(fields: &Rvfa1) -> Result<[u8; RVFA1_PREFIX_LEN], ProtectedAnchorError> {
    if fields.role > 1 {
        return Err(ProtectedAnchorError::Codec("role must be 0 or 1"));
    }
    let mut out = [0u8; RVFA1_PREFIX_LEN];
    out[..8].copy_from_slice(RVFA1_MAGIC);
    out[8..10].copy_from_slice(&RVFA1_SCHEMA.to_be_bytes());
    out[10] = fields.status as u8;
    out[11] = fields.role;
    out[12..44].copy_from_slice(&fields.record_key);
    out[44..76].copy_from_slice(&fields.session_id);
    out[76..84].copy_from_slice(&fields.anchor_seq.to_be_bytes());
    out[84..92].copy_from_slice(&fields.generation.to_be_bytes());
    out[92..124].copy_from_slice(&fields.cleared_state_digest);
    out[124..132].copy_from_slice(&fields.cleared_store_revision.to_be_bytes());
    out[132..164].copy_from_slice(&fields.transition_id);
    out[164..172].copy_from_slice(&fields.horizon_ms.to_be_bytes());
    Ok(out)
}

pub fn encode_rvfa1(
    fields: &Rvfa1,
    k_anchor: &[u8; 32],
) -> Result<[u8; RVFA1_LEN], ProtectedAnchorError> {
    let prefix = prefix_bytes(fields)?;
    let mut mac = HmacSha256::new_from_slice(k_anchor).expect("hmac");
    mac.update(&prefix);
    let tag: [u8; 32] = mac.finalize().into_bytes().into();
    if fields.hmac != ZERO32 && fields.hmac != tag {
        return Err(ProtectedAnchorError::Codec(
            "provided hmac does not match K_anchor",
        ));
    }
    let mut out = [0u8; RVFA1_LEN];
    out[..RVFA1_PREFIX_LEN].copy_from_slice(&prefix);
    out[RVFA1_PREFIX_LEN..].copy_from_slice(&tag);
    Ok(out)
}

pub fn decode_rvfa1(raw: &[u8], k_anchor: &[u8; 32]) -> Result<Rvfa1, ProtectedAnchorError> {
    if raw.len() != RVFA1_LEN {
        return Err(ProtectedAnchorError::Codec("rvfa1 length"));
    }
    if &raw[..8] != RVFA1_MAGIC {
        return Err(ProtectedAnchorError::Codec("bad magic"));
    }
    let schema = u16::from_be_bytes([raw[8], raw[9]]);
    if schema != RVFA1_SCHEMA {
        return Err(ProtectedAnchorError::Codec("bad schema"));
    }
    let status = Rvfa1Status::from_u8(raw[10])?;
    let role = raw[11];
    if role > 1 {
        return Err(ProtectedAnchorError::Codec("bad role"));
    }
    let prefix = &raw[..RVFA1_PREFIX_LEN];
    let tag = &raw[RVFA1_PREFIX_LEN..];
    let mut mac = HmacSha256::new_from_slice(k_anchor).expect("hmac");
    mac.update(prefix);
    mac.verify_slice(tag)
        .map_err(|_| ProtectedAnchorError::Codec("bad hmac"))?;
    let mut record_key = [0u8; 32];
    let mut session_id = [0u8; 32];
    let mut cleared_state_digest = [0u8; 32];
    let mut transition_id = [0u8; 32];
    let mut hmac = [0u8; 32];
    record_key.copy_from_slice(&raw[12..44]);
    session_id.copy_from_slice(&raw[44..76]);
    cleared_state_digest.copy_from_slice(&raw[92..124]);
    transition_id.copy_from_slice(&raw[132..164]);
    hmac.copy_from_slice(tag);
    Ok(Rvfa1 {
        status,
        role,
        record_key,
        session_id,
        anchor_seq: u64::from_be_bytes(raw[76..84].try_into().unwrap()),
        generation: u64::from_be_bytes(raw[84..92].try_into().unwrap()),
        cleared_state_digest,
        cleared_store_revision: u64::from_be_bytes(raw[124..132].try_into().unwrap()),
        transition_id,
        horizon_ms: u64::from_be_bytes(raw[164..172].try_into().unwrap()),
        hmac,
    })
}

fn record_invariants_ok(item: &Rvfa1, k_index: &[u8; 32]) -> bool {
    if record_key(k_index, &item.session_id) != item.record_key {
        return false;
    }
    let is_initial = item.anchor_seq == INITIAL_ANCHOR_SEQ;
    match item.status {
        Rvfa1Status::Head => {
            if item.horizon_ms != 0 {
                return false;
            }
            if is_initial {
                item.transition_id == ZERO32
            } else {
                item.transition_id != ZERO32
            }
        }
        Rvfa1Status::Deleting => {
            if is_initial || item.horizon_ms == 0 || item.transition_id == ZERO32 {
                return false;
            }
            true
        }
        Rvfa1Status::Tombstone => {
            if is_initial || item.horizon_ms == 0 || item.transition_id != ZERO32 {
                return false;
            }
            true
        }
    }
}

fn status_transition_ok(prev: Option<Rvfa1Status>, nxt: Rvfa1Status) -> bool {
    match prev {
        None => nxt == Rvfa1Status::Head,
        Some(Rvfa1Status::Head) => matches!(nxt, Rvfa1Status::Head | Rvfa1Status::Deleting),
        Some(Rvfa1Status::Deleting) => nxt == Rvfa1Status::Tombstone,
        Some(Rvfa1Status::Tombstone) => false,
    }
}

/// Existing same-record anchors must form a complete seq=1..N chain with valid status edges.
fn established_chain_ok(same_record: &[([u8; RVFA1_LEN], Rvfa1)]) -> bool {
    if same_record.is_empty() {
        return true;
    }
    let mut ordered: Vec<&Rvfa1> = same_record.iter().map(|(_, item)| item).collect();
    ordered.sort_by_key(|item| item.anchor_seq);
    if ordered[0].anchor_seq != INITIAL_ANCHOR_SEQ {
        return false;
    }
    if !status_transition_ok(None, ordered[0].status) {
        return false;
    }
    for (idx, item) in ordered.iter().enumerate() {
        let expected_seq = INITIAL_ANCHOR_SEQ + idx as u64;
        if item.anchor_seq != expected_seq {
            return false;
        }
        if idx > 0 && !status_transition_ok(Some(ordered[idx - 1].status), item.status) {
            return false;
        }
    }
    true
}

pub fn classify_append(
    existing_raw: &[&[u8]],
    candidate_raw: &[u8],
    k_anchor: &[u8; 32],
    k_index: &[u8; 32],
) -> AppendDecision {
    let candidate = match decode_rvfa1(candidate_raw, k_anchor) {
        Ok(value) if record_invariants_ok(&value, k_index) => value,
        _ => return AppendDecision::Corrupt,
    };

    let mut same_record: Vec<([u8; RVFA1_LEN], Rvfa1)> = Vec::new();
    let mut seen = std::collections::BTreeMap::<([u8; 32], u64), [u8; RVFA1_LEN]>::new();
    for raw in existing_raw {
        let item = match decode_rvfa1(raw, k_anchor) {
            Ok(value) if record_invariants_ok(&value, k_index) => value,
            _ => return AppendDecision::Corrupt,
        };
        if raw.len() != RVFA1_LEN {
            return AppendDecision::Corrupt;
        }
        let mut owned = [0u8; RVFA1_LEN];
        owned.copy_from_slice(raw);
        let key = (item.record_key, item.anchor_seq);
        if seen.insert(key, owned).is_some() {
            return AppendDecision::Corrupt;
        }
        if item.record_key != candidate.record_key {
            continue;
        }
        if item.session_id != candidate.session_id || item.role != candidate.role {
            return AppendDecision::Corrupt;
        }
        same_record.push((owned, item));
    }

    // Validate the established chain before ExactReplay or append.
    if !established_chain_ok(&same_record) {
        return AppendDecision::Corrupt;
    }

    if let Some(existing) = seen.get(&(candidate.record_key, candidate.anchor_seq)) {
        return if existing.as_slice() == candidate_raw {
            AppendDecision::ExactReplay
        } else {
            AppendDecision::Corrupt
        };
    }

    if same_record.is_empty() {
        if candidate.anchor_seq != INITIAL_ANCHOR_SEQ {
            return AppendDecision::Corrupt;
        }
        if !status_transition_ok(None, candidate.status) {
            return AppendDecision::Corrupt;
        }
        return AppendDecision::Appended;
    }

    let highest_item = same_record
        .iter()
        .max_by_key(|(_, item)| item.anchor_seq)
        .map(|(_, item)| item)
        .unwrap();
    let highest = highest_item.anchor_seq;
    if highest == u64::MAX {
        return AppendDecision::Corrupt;
    }
    if candidate.anchor_seq != highest + 1 {
        return AppendDecision::Corrupt;
    }
    if !status_transition_ok(Some(highest_item.status), candidate.status) {
        return AppendDecision::Corrupt;
    }
    AppendDecision::Appended
}

pub fn open_rollback_class(
    anchor_generation: u64,
    anchor_digest: &[u8; 32],
    anchor_revision: u64,
    file_generation: u64,
    file_digest: &[u8; 32],
    file_revision: u64,
) -> &'static str {
    if anchor_generation > file_generation {
        return "container_behind_anchor";
    }
    if anchor_generation < file_generation {
        return "anchor_behind_container";
    }
    // Equal generation: digest mismatch is corruption (digest is not ordered).
    if anchor_digest != file_digest {
        return "digest_mismatch";
    }
    if anchor_revision > file_revision {
        return "container_behind_anchor";
    }
    if anchor_revision < file_revision {
        return "anchor_behind_container";
    }
    "aligned"
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::path::PathBuf;

    fn vector() -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../shared-vectors/rvn1/atsam/full_braid_protected_anchor_001.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("vector")).expect("json")
    }

    fn hex32(value: &str) -> [u8; 32] {
        let bytes = hex::decode(value).expect("hex");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    #[test]
    fn shared_vector_scope_kdf_rvfa1_append() {
        let v = vector();
        assert_eq!(v["production_enabled"], false);
        let seed = hex32(v["inputs"]["seed_hex"].as_str().unwrap());
        let session = hex32(v["inputs"]["session_id_hex"].as_str().unwrap());
        let keys = derive_store_keys(&seed);
        let exp = &v["expected"];

        assert_eq!(INITIAL_ANCHOR_SEQ, 1);
        assert_eq!(hex::encode(apple_scope_id()), exp["apple_scope_id_hex"]);
        assert_eq!(
            hex::encode(
                terminal_scope_id(
                    v["inputs"]["terminal_root_utf8"]
                        .as_str()
                        .unwrap()
                        .as_bytes()
                )
                .unwrap()
            ),
            exp["terminal_scope_id_hex"]
        );
        assert_eq!(hex::encode(keys.k_state), exp["k_state_hex"]);
        assert_eq!(hex::encode(keys.k_index), exp["k_index_hex"]);
        assert_eq!(hex::encode(keys.k_sql), exp["k_sql_hex"]);
        assert_eq!(hex::encode(keys.k_local), exp["k_local_hex"]);
        assert_eq!(hex::encode(keys.k_anchor), exp["k_anchor_hex"]);
        assert_eq!(hex::encode(keys.k_sql_salt), exp["k_sql_salt_hex"]);

        let rk = record_key(&keys.k_index, &session);
        assert_eq!(hex::encode(rk), exp["record_key_hex"]);

        let raw1 = hex::decode(exp["rvfa1_seq1_hex"].as_str().unwrap()).unwrap();
        let raw2 = hex::decode(exp["rvfa1_seq2_hex"].as_str().unwrap()).unwrap();
        let raw3 = hex::decode(exp["rvfa1_seq3_hex"].as_str().unwrap()).unwrap();
        let raw4 = hex::decode(exp["rvfa1_seq4_hex"].as_str().unwrap()).unwrap();
        let conflict = hex::decode(exp["rvfa1_seq2_conflict_hex"].as_str().unwrap()).unwrap();
        let deleting = hex::decode(exp["rvfa1_deleting_seq2_hex"].as_str().unwrap()).unwrap();
        assert_eq!(raw1.len(), RVFA1_LEN);
        let decoded = decode_rvfa1(&raw1, &keys.k_anchor).unwrap();
        assert_eq!(decoded.anchor_seq, 1);
        assert_eq!(decoded.record_key, rk);
        assert_eq!(decoded.transition_id, ZERO32);

        assert_eq!(
            classify_append(&[], &raw1, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_empty_seq1"]
        );
        assert_eq!(
            classify_append(&[&raw1], &raw1, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_replay_seq1"]
        );
        assert_eq!(
            classify_append(&[&raw1], &raw2, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_seq2_after_seq1"]
        );
        assert_eq!(
            classify_append(&[&raw1, &raw2], &conflict, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_conflict_same_seq"]
        );
        assert_eq!(
            classify_append(&[], &raw2, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_first_nonzero_not_one"]
        );

        let mut gap_fields = decode_rvfa1(&raw2, &keys.k_anchor).unwrap();
        gap_fields.anchor_seq = 4;
        gap_fields.generation = 4;
        gap_fields.cleared_state_digest = hex32(&"66".repeat(32));
        gap_fields.cleared_store_revision = 9;
        gap_fields.transition_id = hex32(&"77".repeat(32));
        gap_fields.horizon_ms = 0;
        gap_fields.hmac = ZERO32;
        let gap = encode_rvfa1(&gap_fields, &keys.k_anchor).unwrap();
        assert_eq!(
            classify_append(&[&raw1, &raw2], &gap, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_gap_seq4"]
        );
        assert_eq!(
            classify_append(&[&raw1, &raw3], &raw4, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_gapped_chain_seq4"]
        );
        assert_eq!(
            classify_append(&[&raw1, &raw3], &raw3, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_replay_on_gapped_chain"]
        );

        let bad_rk = hex::decode(v["negatives"]["bad_record_key_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            classify_append(&[], &bad_rk, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_bad_record_key"]
        );
        let bad_horizon =
            hex::decode(v["negatives"]["head_nonzero_horizon_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            classify_append(&[], &bad_horizon, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_head_nonzero_horizon"]
        );
        let bad_status =
            hex::decode(v["negatives"]["tombstone_after_head_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            classify_append(&[&raw1], &bad_status, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_bad_status_transition"]
        );
        assert_eq!(
            classify_append(&[&raw1, &bad_status], &raw1, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_bad_status_in_chain"]
        );
        assert_eq!(
            classify_append(
                &[&raw1],
                &hex::decode(
                    v["negatives"]["tombstone_zero_horizon_hex"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
                &keys.k_anchor,
                &keys.k_index
            )
            .as_str(),
            exp["append_tombstone_zero_horizon"]
        );
        assert_eq!(
            classify_append(
                &[&raw1],
                &hex::decode(
                    v["negatives"]["tombstone_nonzero_transition_hex"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
                &keys.k_anchor,
                &keys.k_index
            )
            .as_str(),
            exp["append_tombstone_nonzero_transition"]
        );
        assert_eq!(
            classify_append(
                &[&raw1],
                &hex::decode(
                    v["negatives"]["noninitial_head_zero_transition_hex"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
                &keys.k_anchor,
                &keys.k_index
            )
            .as_str(),
            exp["append_noninitial_head_zero_transition"]
        );
        assert_eq!(
            classify_append(
                &[&raw1],
                &hex::decode(
                    v["negatives"]["deleting_zero_transition_hex"]
                        .as_str()
                        .unwrap()
                )
                .unwrap(),
                &keys.k_anchor,
                &keys.k_index
            )
            .as_str(),
            exp["append_deleting_zero_transition"]
        );
        assert_eq!(
            classify_append(&[&raw1], &deleting, &keys.k_anchor, &keys.k_index).as_str(),
            exp["append_deleting_after_seq1"]
        );

        let d44 = hex32(&"44".repeat(32));
        let d33 = hex32(&"33".repeat(32));
        assert_eq!(
            open_rollback_class(2, &d44, 8, 2, &d44, 8),
            exp["open_aligned"]
        );
        assert_eq!(
            open_rollback_class(2, &d44, 8, 1, &d33, 7),
            exp["open_container_behind"]
        );
        assert_eq!(
            open_rollback_class(1, &d33, 7, 2, &d44, 8),
            exp["open_anchor_behind"]
        );
        assert_eq!(
            open_rollback_class(2, &d44, 8, 2, &d33, 8),
            exp["open_digest_mismatch"]
        );
        assert_eq!(RELEASE_HOLD, "FULL_BRAID_PROTECTED_ANCHOR_NOT_APPROVED");
        assert_eq!(MAX_FULL_BRAID_SESSIONS, 4096);
        assert_eq!(WINDOWS_CRED_MAX_BLOB, 2560);
        assert_eq!(ERROR_CODES.len(), 11);
    }

    #[test]
    fn negatives_forbidden_group_bad_hmac_and_encode_parity() {
        let v = vector();
        assert!(scope_id(
            APPLE_APP_ID,
            v["negatives"]["forbidden_shared_group"]
                .as_str()
                .unwrap()
                .as_bytes()
        )
        .is_err());
        let seed = hex32(v["inputs"]["seed_hex"].as_str().unwrap());
        let session = hex32(v["inputs"]["session_id_hex"].as_str().unwrap());
        let keys = derive_store_keys(&seed);
        let bad = hex::decode(v["negatives"]["bad_hmac_hex"].as_str().unwrap()).unwrap();
        assert!(decode_rvfa1(&bad, &keys.k_anchor).is_err());

        let rk = record_key(&keys.k_index, &session);
        let mut fields = Rvfa1 {
            status: Rvfa1Status::Head,
            role: 0,
            record_key: rk,
            session_id: session,
            anchor_seq: 1,
            generation: 1,
            cleared_state_digest: hex32(&"33".repeat(32)),
            cleared_store_revision: 7,
            transition_id: ZERO32,
            horizon_ms: 0,
            hmac: hex32(&"ff".repeat(32)),
        };
        assert!(encode_rvfa1(&fields, &keys.k_anchor).is_err());
        fields.hmac = ZERO32;
        assert!(encode_rvfa1(&fields, &keys.k_anchor).is_ok());
        assert_eq!(
            v["negatives"]["encode_provided_hmac_mismatch"],
            "CodecError"
        );
    }
}
