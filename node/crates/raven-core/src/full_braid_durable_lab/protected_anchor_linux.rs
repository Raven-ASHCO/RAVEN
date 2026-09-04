//! Task 0B.3 — GNU/Linux Secret Service protected seed + append-only RVFA1 (lab-only).
//!
//! Binding: Task 0B protected-anchor design Rev2 §4.3 / §5.
//! Fail-closed: no file fallback, no Prompt.Prompt, production disabled.
//! Duplicate collapse / loser deletion is deferred to Task 0C / 0B.5 mutation lease.

#![cfg(all(target_os = "linux", target_env = "gnu"))]

use super::protected_anchor::{
    classify_append, decode_rvfa1, AppendDecision, LINUX_APPLICATION, LINUX_PROTOCOL,
    MAX_FULL_BRAID_SESSIONS, RELEASE_HOLD, RVFA1_LEN, SEED_LEN,
};
use super::protected_anchor_linux_ss::{NopromptError, NopromptSs};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use zeroize::Zeroize;
use zvariant::OwnedObjectPath;

pub const PRODUCTION_ENABLED: bool = false;
pub const SEED_LABEL: &str = "RAVEN Full Braid installation seed";
pub const CONTENT_TYPE: &str = "text/plain";
const ATTR_APPLICATION: &str = "application";
const ATTR_PROTOCOL: &str = "protocol";
const ATTR_KIND: &str = "kind";
const ATTR_SCOPE: &str = "scope";
const ATTR_RECORD: &str = "record";
const ATTR_SEQUENCE: &str = "sequence";
const ATTR_XDG_SCHEMA: &str = "xdg:schema";
const XDG_SCHEMA_GENERIC: &str = "org.freedesktop.Secret.Generic";
const KIND_SEED: &str = "seed";
const KIND_ANCHOR: &str = "anchor";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("FULL_BRAID_PROTECTED_ANCHOR_NOT_APPROVED")]
    ProductionDisabled,
    #[error("UNAVAILABLE")]
    Unavailable,
    #[error("LOCKED_OR_PROMPT_REQUIRED")]
    LockedOrPromptRequired,
    #[error("MISSING")]
    Missing,
    #[error("DUPLICATE")]
    Duplicate,
    #[error("CONFLICT")]
    Conflict,
    #[error("CORRUPT_LENGTH")]
    CorruptLength,
    #[error("CORRUPT_ATTRIBUTES")]
    CorruptAttributes,
    #[error("WRONG_ACCESSIBILITY_OR_PERSISTENCE")]
    WrongAccessibilityOrPersistence,
    #[error("CAPACITY")]
    Capacity,
    #[error("READBACK_MISMATCH")]
    ReadbackMismatch,
    #[error("IO_OR_PLATFORM")]
    IoOrPlatform,
}

impl StoreError {
    pub fn as_code(&self) -> &'static str {
        match self {
            Self::ProductionDisabled => RELEASE_HOLD,
            Self::Unavailable => "UNAVAILABLE",
            Self::LockedOrPromptRequired => "LOCKED_OR_PROMPT_REQUIRED",
            Self::Missing => "MISSING",
            Self::Duplicate => "DUPLICATE",
            Self::Conflict => "CONFLICT",
            Self::CorruptLength => "CORRUPT_LENGTH",
            Self::CorruptAttributes => "CORRUPT_ATTRIBUTES",
            Self::WrongAccessibilityOrPersistence => "WRONG_ACCESSIBILITY_OR_PERSISTENCE",
            Self::Capacity => "CAPACITY",
            Self::ReadbackMismatch => "READBACK_MISMATCH",
            Self::IoOrPlatform => "IO_OR_PLATFORM",
        }
    }
}

/// Explicit first-install attestation required before minting a new seed.
#[derive(Debug, Clone, Copy)]
pub struct FirstInstallProof {
    attested_empty_durable_scope: bool,
}

impl FirstInstallProof {
    pub const fn attest_empty_durable_scope() -> Self {
        Self {
            attested_empty_durable_scope: true,
        }
    }

    fn is_valid(self) -> bool {
        self.attested_empty_durable_scope
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedCreateResult {
    Created([u8; SEED_LEN]),
    Existing([u8; SEED_LEN]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedLoadResult {
    Missing,
    Exact([u8; SEED_LEN]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorAppendResult {
    Appended,
    ExactReplay,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceProbe {
    pub backend: &'static str,
    pub application: &'static str,
    pub protocol: &'static str,
    pub content_type: &'static str,
    pub scope_id_hex: String,
    pub seed_collection_path: Option<String>,
}

pub struct Namespace {
    scope_id: [u8; 32],
    scope_id_hex: String,
    seed_collection_path: Option<String>,
}

impl Namespace {
    pub fn scope_id(&self) -> &[u8; 32] {
        &self.scope_id
    }

    pub fn scope_id_hex(&self) -> &str {
        &self.scope_id_hex
    }

    pub fn namespace_probe(&self) -> NamespaceProbe {
        NamespaceProbe {
            backend: "secret-service",
            application: LINUX_APPLICATION,
            protocol: LINUX_PROTOCOL,
            content_type: CONTENT_TYPE,
            scope_id_hex: self.scope_id_hex.clone(),
            seed_collection_path: self.seed_collection_path.clone(),
        }
    }

    /// Create-if-absent. Create path requires explicit first-install proof.
    /// Never replaces; never deletes duplicate losers (0C / 0B.5 lease only).
    pub fn seed_create_if_absent(
        &mut self,
        candidate32: &mut [u8; SEED_LEN],
        first_install: Option<FirstInstallProof>,
    ) -> Result<SeedCreateResult, StoreError> {
        require_lab()?;
        let mut guard = CandidateGuard(candidate32);
        match self.seed_load_exact()? {
            SeedLoadResult::Exact(existing) => {
                guard.zeroize();
                return Ok(SeedCreateResult::Existing(existing));
            }
            SeedLoadResult::Missing => {}
        }

        let proof = first_install.ok_or(StoreError::Missing)?;
        if !proof.is_valid() {
            return Err(StoreError::Missing);
        }

        let ss = connect()?;
        let anchors = search_anchor_paths(&ss, &self.scope_id_hex, None, None)?;
        if !anchors.is_empty() {
            return Err(StoreError::CorruptAttributes);
        }

        let secret = *guard.0;
        let attrs = seed_attrs_owned(&self.scope_id_hex);
        match ss.create_item_noprompt(SEED_LABEL, attrs, &secret, CONTENT_TYPE) {
            Ok(_) => {}
            Err(NopromptError::LockedOrPromptRequired) => {
                return Err(StoreError::LockedOrPromptRequired);
            }
            Err(NopromptError::Capacity) => return Err(StoreError::Capacity),
            Err(NopromptError::Unavailable) => return Err(StoreError::Unavailable),
            Err(NopromptError::Io) => {}
        }

        let paths = search_seed_paths(&ss, &self.scope_id_hex)?;
        if paths.is_empty() {
            return Err(StoreError::IoOrPlatform);
        }
        if paths.len() > 1 {
            return Err(StoreError::Duplicate);
        }
        let path = paths[0].as_str();
        let (seed, _) = read_seed_verified(&ss, path, &self.scope_id_hex)?;
        let coll = collection_path_of(path)?;
        if coll != ss.default_collection_path() {
            return Err(StoreError::Duplicate);
        }
        self.seed_collection_path = Some(coll);
        let outcome = if seed == secret {
            SeedCreateResult::Created(seed)
        } else {
            SeedCreateResult::Existing(seed)
        };
        guard.zeroize();
        Ok(outcome)
    }

    pub fn seed_load_exact(&mut self) -> Result<SeedLoadResult, StoreError> {
        require_lab()?;
        let ss = connect()?;
        let paths = search_seed_paths(&ss, &self.scope_id_hex)?;
        if paths.is_empty() {
            return Ok(SeedLoadResult::Missing);
        }
        if paths.len() > 1 {
            return Err(StoreError::Duplicate);
        }
        let path = paths[0].as_str();
        let (seed, coll) = read_seed_verified(&ss, path, &self.scope_id_hex)?;
        if coll != ss.default_collection_path() {
            return Err(StoreError::Duplicate);
        }
        self.seed_collection_path = Some(coll);
        Ok(SeedLoadResult::Exact(seed))
    }

    pub fn anchor_list(
        &mut self,
        record_key32: &[u8; 32],
        k_index: &[u8; 32],
        k_anchor: &[u8; 32],
    ) -> Result<Vec<[u8; RVFA1_LEN]>, StoreError> {
        require_lab()?;
        let _ = self.require_seed_collection()?;
        let ss = connect()?;
        let record_hex = hex32(record_key32);
        let paths = search_anchor_paths(&ss, &self.scope_id_hex, Some(record_hex.as_str()), None)?;
        let mut out = Vec::with_capacity(paths.len());
        for path in &paths {
            let raw = read_anchor_verified(
                &ss,
                path.as_str(),
                &self.scope_id_hex,
                Some(record_hex.as_str()),
                None,
            )?;
            let mut owned = [0u8; RVFA1_LEN];
            owned.copy_from_slice(&raw);
            let decoded =
                decode_rvfa1(&owned, k_anchor).map_err(|_| StoreError::CorruptAttributes)?;
            if decoded.record_key != *record_key32 {
                return Err(StoreError::CorruptAttributes);
            }
            if super::protected_anchor::record_key(k_index, &decoded.session_id)
                != decoded.record_key
            {
                return Err(StoreError::CorruptAttributes);
            }
            out.push((decoded.anchor_seq, owned));
        }
        out.sort_by_key(|(seq, _)| *seq);
        for w in out.windows(2) {
            if w[0].0 == w[1].0 {
                return Err(StoreError::Duplicate);
            }
        }
        Ok(out.into_iter().map(|(_, b)| b).collect())
    }

    pub fn anchor_append(
        &mut self,
        exact_rvfa1: &[u8],
        k_index: &[u8; 32],
        k_anchor: &[u8; 32],
    ) -> Result<AnchorAppendResult, StoreError> {
        require_lab()?;
        if exact_rvfa1.len() != RVFA1_LEN {
            return Err(StoreError::CorruptLength);
        }
        let _ = self.require_seed_collection()?;
        let decoded =
            decode_rvfa1(exact_rvfa1, k_anchor).map_err(|_| StoreError::CorruptAttributes)?;
        let record_hex = hex32(&decoded.record_key);
        let seq_hex = format!("{:016x}", decoded.anchor_seq);

        let existing = self.anchor_list(&decoded.record_key, k_index, k_anchor)?;
        let refs: Vec<&[u8]> = existing.iter().map(|b| b.as_slice()).collect();
        match classify_append(&refs, exact_rvfa1, k_anchor, k_index) {
            AppendDecision::ExactReplay => return Ok(AnchorAppendResult::ExactReplay),
            AppendDecision::Corrupt => return Err(StoreError::CorruptAttributes),
            AppendDecision::Appended => {}
        }

        let ss = connect()?;
        let unique_records = count_unique_records_in_scope(&ss, &self.scope_id_hex)?;
        let already = unique_records.contains(&record_hex);
        if !already && unique_records.len() >= MAX_FULL_BRAID_SESSIONS {
            return Err(StoreError::Capacity);
        }

        let label = format!(
            "RAVEN Full Braid RVFA1 {}/{}/{}",
            &self.scope_id_hex[..8],
            &record_hex[..8],
            seq_hex
        );
        let attrs = anchor_attrs_owned(&self.scope_id_hex, &record_hex, &seq_hex);
        match ss.create_item_noprompt(&label, attrs, exact_rvfa1, CONTENT_TYPE) {
            Ok(path) => {
                let read = read_anchor_verified(
                    &ss,
                    path.as_str(),
                    &self.scope_id_hex,
                    Some(record_hex.as_str()),
                    Some(seq_hex.as_str()),
                )?;
                if read.as_slice() != exact_rvfa1 {
                    return Err(StoreError::ReadbackMismatch);
                }
                let got_label = ss.item_label(path.as_str()).map_err(map_np)?;
                if got_label != label {
                    return Err(StoreError::CorruptAttributes);
                }
            }
            Err(NopromptError::LockedOrPromptRequired) => {
                return Err(StoreError::LockedOrPromptRequired);
            }
            Err(NopromptError::Capacity) => return Err(StoreError::Capacity),
            Err(NopromptError::Unavailable) => return Err(StoreError::Unavailable),
            Err(NopromptError::Io) => {
                let after = self.anchor_list(&decoded.record_key, k_index, k_anchor)?;
                let matches: Vec<_> = after
                    .iter()
                    .filter(|b| b.as_slice() == exact_rvfa1)
                    .collect();
                if matches.len() != 1 {
                    return Err(StoreError::Conflict);
                }
                let refs: Vec<&[u8]> = after.iter().map(|b| b.as_slice()).collect();
                return match classify_append(&refs, exact_rvfa1, k_anchor, k_index) {
                    AppendDecision::ExactReplay => Ok(AnchorAppendResult::ExactReplay),
                    _ => Err(StoreError::CorruptAttributes),
                };
            }
        }

        let after = self.anchor_list(&decoded.record_key, k_index, k_anchor)?;
        let without_new: Vec<&[u8]> = after
            .iter()
            .map(|b| b.as_slice())
            .filter(|b| *b != exact_rvfa1)
            .collect();
        match classify_append(&without_new, exact_rvfa1, k_anchor, k_index) {
            AppendDecision::Appended | AppendDecision::ExactReplay => {}
            AppendDecision::Corrupt => return Err(StoreError::CorruptAttributes),
        }
        let with_new: Vec<&[u8]> = after.iter().map(|b| b.as_slice()).collect();
        match classify_append(&with_new, exact_rvfa1, k_anchor, k_index) {
            AppendDecision::ExactReplay => Ok(AnchorAppendResult::Appended),
            _ => Err(StoreError::CorruptAttributes),
        }
    }

    pub fn anchor_delete_exact(
        &mut self,
        record_key32: &[u8; 32],
        seq: u64,
        expected_digest32: &[u8; 32],
    ) -> Result<(), StoreError> {
        require_lab()?;
        let _ = self.require_seed_collection()?;
        let ss = connect()?;
        let record_hex = hex32(record_key32);
        let seq_hex = format!("{:016x}", seq);
        let paths = search_anchor_paths(
            &ss,
            &self.scope_id_hex,
            Some(record_hex.as_str()),
            Some(seq_hex.as_str()),
        )?;
        if paths.is_empty() {
            return Err(StoreError::Missing);
        }
        if paths.len() != 1 {
            return Err(StoreError::Duplicate);
        }
        let path = paths[0].as_str();
        let raw = read_anchor_verified(
            &ss,
            path,
            &self.scope_id_hex,
            Some(record_hex.as_str()),
            Some(seq_hex.as_str()),
        )?;
        let digest = sha256_32(&raw);
        if &digest != expected_digest32 {
            return Err(StoreError::Conflict);
        }
        ss.delete_item_noprompt(path).map_err(map_np)?;
        Ok(())
    }

    /// Lab/test cleanup for this scope only. Never a production path.
    pub fn lab_delete_all_scoped_items(&mut self) -> Result<(), StoreError> {
        require_lab()?;
        let ss = connect()?;
        let seed_paths = search_seed_paths(&ss, &self.scope_id_hex).unwrap_or_default();
        for path in &seed_paths {
            let _ = ss.delete_item_noprompt(path.as_str());
        }
        let anchor_paths =
            search_anchor_paths(&ss, &self.scope_id_hex, None, None).unwrap_or_default();
        for path in &anchor_paths {
            let _ = ss.delete_item_noprompt(path.as_str());
        }
        self.seed_collection_path = None;
        if !search_seed_paths(&ss, &self.scope_id_hex)?.is_empty() {
            return Err(StoreError::IoOrPlatform);
        }
        if !search_anchor_paths(&ss, &self.scope_id_hex, None, None)?.is_empty() {
            return Err(StoreError::IoOrPlatform);
        }
        Ok(())
    }

    fn require_seed_collection(&mut self) -> Result<&str, StoreError> {
        if self.seed_collection_path.is_none() {
            match self.seed_load_exact()? {
                SeedLoadResult::Exact(_) => {}
                SeedLoadResult::Missing => return Err(StoreError::Missing),
            }
        }
        self.seed_collection_path
            .as_deref()
            .ok_or(StoreError::CorruptAttributes)
    }
}

pub fn open(scope_id: [u8; 32]) -> Result<Namespace, StoreError> {
    require_lab()?;
    Ok(Namespace {
        scope_id_hex: hex32(&scope_id),
        scope_id,
        seed_collection_path: None,
    })
}

pub fn open_terminal(canonical_root_bytes: &[u8]) -> Result<Namespace, StoreError> {
    let scope = super::protected_anchor::terminal_scope_id(canonical_root_bytes)
        .map_err(|_| StoreError::CorruptAttributes)?;
    open(scope)
}

fn require_lab() -> Result<(), StoreError> {
    if PRODUCTION_ENABLED {
        return Err(StoreError::ProductionDisabled);
    }
    Ok(())
}

fn connect() -> Result<NopromptSs, StoreError> {
    NopromptSs::connect().map_err(map_np)
}

fn map_np(err: NopromptError) -> StoreError {
    match err {
        NopromptError::Unavailable => StoreError::Unavailable,
        NopromptError::LockedOrPromptRequired => StoreError::LockedOrPromptRequired,
        NopromptError::Capacity => StoreError::Capacity,
        NopromptError::Io => StoreError::IoOrPlatform,
    }
}

fn seed_attrs_owned(scope_hex: &str) -> HashMap<&str, &str> {
    HashMap::from([
        (ATTR_APPLICATION, LINUX_APPLICATION),
        (ATTR_PROTOCOL, LINUX_PROTOCOL),
        (ATTR_KIND, KIND_SEED),
        (ATTR_SCOPE, scope_hex),
        (ATTR_XDG_SCHEMA, XDG_SCHEMA_GENERIC),
    ])
}

fn anchor_attrs_owned<'a>(
    scope_hex: &'a str,
    record_hex: &'a str,
    seq_hex: &'a str,
) -> HashMap<&'a str, &'a str> {
    HashMap::from([
        (ATTR_APPLICATION, LINUX_APPLICATION),
        (ATTR_PROTOCOL, LINUX_PROTOCOL),
        (ATTR_KIND, KIND_ANCHOR),
        (ATTR_SCOPE, scope_hex),
        (ATTR_RECORD, record_hex),
        (ATTR_SEQUENCE, seq_hex),
        (ATTR_XDG_SCHEMA, XDG_SCHEMA_GENERIC),
    ])
}

fn search_seed_paths(ss: &NopromptSs, scope_hex: &str) -> Result<Vec<OwnedObjectPath>, StoreError> {
    ss.search(seed_attrs_owned(scope_hex)).map_err(map_np)
}

fn search_anchor_paths(
    ss: &NopromptSs,
    scope_hex: &str,
    record_hex: Option<&str>,
    seq_hex: Option<&str>,
) -> Result<Vec<OwnedObjectPath>, StoreError> {
    let mut attrs = HashMap::from([
        (ATTR_APPLICATION, LINUX_APPLICATION),
        (ATTR_PROTOCOL, LINUX_PROTOCOL),
        (ATTR_KIND, KIND_ANCHOR),
        (ATTR_SCOPE, scope_hex),
    ]);
    if let Some(r) = record_hex {
        attrs.insert(ATTR_RECORD, r);
    }
    if let Some(s) = seq_hex {
        attrs.insert(ATTR_SEQUENCE, s);
    }
    ss.search(attrs).map_err(map_np)
}

fn count_unique_records_in_scope(
    ss: &NopromptSs,
    scope_hex: &str,
) -> Result<HashSet<String>, StoreError> {
    let paths = search_anchor_paths(ss, scope_hex, None, None)?;
    let mut records = HashSet::new();
    for path in &paths {
        let attrs = ss.item_attributes(path.as_str()).map_err(map_np)?;
        verify_exact_attrs(
            &attrs,
            &[
                (ATTR_APPLICATION, LINUX_APPLICATION),
                (ATTR_PROTOCOL, LINUX_PROTOCOL),
                (ATTR_KIND, KIND_ANCHOR),
                (ATTR_SCOPE, scope_hex),
                (ATTR_XDG_SCHEMA, XDG_SCHEMA_GENERIC),
            ],
            &["record", "sequence"],
        )?;
        let Some(record) = attrs.get(ATTR_RECORD) else {
            return Err(StoreError::CorruptAttributes);
        };
        if !attrs.contains_key(ATTR_SEQUENCE) {
            return Err(StoreError::CorruptAttributes);
        }
        if attrs.len() != 7 {
            return Err(StoreError::CorruptAttributes);
        }
        records.insert(record.clone());
    }
    Ok(records)
}

fn read_seed_verified(
    ss: &NopromptSs,
    path: &str,
    scope_hex: &str,
) -> Result<([u8; SEED_LEN], String), StoreError> {
    if ss.item_locked(path).map_err(map_np)? {
        return Err(StoreError::LockedOrPromptRequired);
    }
    let label = ss.item_label(path).map_err(map_np)?;
    if label != SEED_LABEL {
        return Err(StoreError::CorruptAttributes);
    }
    let attrs = ss.item_attributes(path).map_err(map_np)?;
    verify_exact_attrs(
        &attrs,
        &[
            (ATTR_APPLICATION, LINUX_APPLICATION),
            (ATTR_PROTOCOL, LINUX_PROTOCOL),
            (ATTR_KIND, KIND_SEED),
            (ATTR_SCOPE, scope_hex),
            (ATTR_XDG_SCHEMA, XDG_SCHEMA_GENERIC),
        ],
        &[],
    )?;
    let (secret, ctype) = ss.item_secret(path).map_err(map_np)?;
    if ctype != CONTENT_TYPE {
        return Err(StoreError::CorruptAttributes);
    }
    if secret.len() != SEED_LEN {
        return Err(StoreError::CorruptLength);
    }
    let mut owned = [0u8; SEED_LEN];
    owned.copy_from_slice(&secret);
    let coll = collection_path_of(path)?;
    Ok((owned, coll))
}

fn read_anchor_verified(
    ss: &NopromptSs,
    path: &str,
    scope_hex: &str,
    record_hex: Option<&str>,
    seq_hex: Option<&str>,
) -> Result<Vec<u8>, StoreError> {
    if ss.item_locked(path).map_err(map_np)? {
        return Err(StoreError::LockedOrPromptRequired);
    }
    let attrs = ss.item_attributes(path).map_err(map_np)?;
    let mut expected = vec![
        (ATTR_APPLICATION, LINUX_APPLICATION),
        (ATTR_PROTOCOL, LINUX_PROTOCOL),
        (ATTR_KIND, KIND_ANCHOR),
        (ATTR_SCOPE, scope_hex),
        (ATTR_XDG_SCHEMA, XDG_SCHEMA_GENERIC),
    ];
    if let Some(r) = record_hex {
        expected.push((ATTR_RECORD, r));
    }
    if let Some(s) = seq_hex {
        expected.push((ATTR_SEQUENCE, s));
    }
    if record_hex.is_some() && seq_hex.is_some() {
        verify_exact_attrs(&attrs, &expected, &[])?;
    } else {
        if attrs.len() != 7 {
            return Err(StoreError::CorruptAttributes);
        }
        for (k, v) in &expected {
            require_attr(&attrs, k, v)?;
        }
        if !attrs.contains_key(ATTR_RECORD) || !attrs.contains_key(ATTR_SEQUENCE) {
            return Err(StoreError::CorruptAttributes);
        }
    }
    let label = ss.item_label(path).map_err(map_np)?;
    let record = attrs
        .get(ATTR_RECORD)
        .ok_or(StoreError::CorruptAttributes)?;
    let seq = attrs
        .get(ATTR_SEQUENCE)
        .ok_or(StoreError::CorruptAttributes)?;
    let expect_label = format!(
        "RAVEN Full Braid RVFA1 {}/{}/{}",
        &scope_hex[..8.min(scope_hex.len())],
        &record[..8.min(record.len())],
        seq
    );
    if label != expect_label {
        return Err(StoreError::CorruptAttributes);
    }
    let (secret, ctype) = ss.item_secret(path).map_err(map_np)?;
    if ctype != CONTENT_TYPE {
        return Err(StoreError::CorruptAttributes);
    }
    if secret.len() != RVFA1_LEN {
        return Err(StoreError::CorruptLength);
    }
    Ok(secret)
}

fn verify_exact_attrs(
    attrs: &HashMap<String, String>,
    expected: &[(&str, &str)],
    allow_extra: &[&str],
) -> Result<(), StoreError> {
    for (k, v) in expected {
        require_attr(attrs, k, v)?;
    }
    for key in attrs.keys() {
        let allowed =
            expected.iter().any(|(k, _)| *k == key.as_str()) || allow_extra.contains(&key.as_str());
        if !allowed {
            return Err(StoreError::CorruptAttributes);
        }
    }
    if allow_extra.is_empty() && attrs.len() != expected.len() {
        return Err(StoreError::CorruptAttributes);
    }
    Ok(())
}

fn require_attr(
    attrs: &HashMap<String, String>,
    key: &str,
    expect: &str,
) -> Result<(), StoreError> {
    match attrs.get(key).map(String::as_str) {
        Some(v) if v == expect => Ok(()),
        _ => Err(StoreError::CorruptAttributes),
    }
}

fn collection_path_of(item_path: &str) -> Result<String, StoreError> {
    let Some((parent, _)) = item_path.rsplit_once('/') else {
        return Err(StoreError::CorruptAttributes);
    };
    if parent == "/org/freedesktop/secrets/collection"
        || !parent.starts_with("/org/freedesktop/secrets/collection/")
    {
        return Err(StoreError::CorruptAttributes);
    }
    Ok(parent.to_string())
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

struct CandidateGuard<'a>(&'a mut [u8; SEED_LEN]);

impl Drop for CandidateGuard<'_> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl CandidateGuard<'_> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::full_braid_durable_lab::protected_anchor::{
        derive_store_keys, encode_rvfa1, record_key, Rvfa1, Rvfa1Status, INITIAL_ANCHOR_SEQ,
    };
    use std::sync::{Arc, Barrier, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_root(tag: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        format!("raven-0b3-{tag}-{nanos}-{}", std::process::id())
    }

    fn open_isolated(tag: &str) -> Namespace {
        let root = unique_root(tag);
        let mut ns = open_terminal(root.as_bytes()).expect("open");
        let _ = ns.lab_delete_all_scoped_items();
        ns
    }

    fn proof() -> FirstInstallProof {
        FirstInstallProof::attest_empty_durable_scope()
    }

    fn make_head(
        keys: &super::super::protected_anchor::DerivedKeys,
        session: &[u8; 32],
        seq: u64,
        generation: u64,
        digest_byte: u8,
        transition: [u8; 32],
    ) -> [u8; RVFA1_LEN] {
        let rk = record_key(&keys.k_index, session);
        encode_rvfa1(
            &Rvfa1 {
                status: Rvfa1Status::Head,
                role: 0,
                record_key: rk,
                session_id: *session,
                anchor_seq: seq,
                generation,
                cleared_state_digest: [digest_byte; 32],
                cleared_store_revision: 7 + seq,
                transition_id: transition,
                horizon_ms: 0,
                hmac: [0u8; 32],
            },
            &keys.k_anchor,
        )
        .expect("encode")
    }

    #[test]
    fn production_flag_stays_off() {
        const { assert!(!PRODUCTION_ENABLED) };
        assert_eq!(RELEASE_HOLD, "FULL_BRAID_PROTECTED_ANCHOR_NOT_APPROVED");
    }

    #[test]
    fn seed_create_requires_first_install_proof() {
        let mut ns = open_isolated("noproof");
        let mut candidate = [0x11u8; 32];
        let err = ns
            .seed_create_if_absent(&mut candidate, None)
            .expect_err("must refuse without proof");
        assert_eq!(err, StoreError::Missing);
        assert!(candidate.iter().all(|&b| b == 0));
        match ns.seed_load_exact().expect("load") {
            SeedLoadResult::Missing => {}
            SeedLoadResult::Exact(_) => panic!("must not create without proof"),
        }
    }

    #[test]
    fn seed_create_reload_and_existing() {
        let mut ns = open_isolated("seed");
        let mut candidate = [0x11u8; 32];
        let created = ns
            .seed_create_if_absent(&mut candidate, Some(proof()))
            .expect("create");
        assert!(candidate.iter().all(|&b| b == 0), "candidate must zeroize");
        let SeedCreateResult::Created(seed) = created else {
            panic!("expected Created");
        };
        match ns.seed_load_exact().expect("load") {
            SeedLoadResult::Exact(loaded) => assert_eq!(loaded, seed),
            SeedLoadResult::Missing => panic!("missing"),
        }
        let mut other = [0xABu8; 32];
        let second = ns
            .seed_create_if_absent(&mut other, None)
            .expect("second without proof ok for Existing");
        let SeedCreateResult::Existing(existing) = second else {
            panic!("expected Existing");
        };
        assert_eq!(existing, seed);
        assert!(other.iter().all(|&b| b == 0));
        let probe = ns.namespace_probe();
        assert_eq!(probe.backend, "secret-service");
        assert_eq!(probe.application, LINUX_APPLICATION);
        assert_eq!(probe.content_type, CONTENT_TYPE);
        assert!(probe.seed_collection_path.is_some());
        ns.lab_delete_all_scoped_items().expect("cleanup");
    }

    #[test]
    fn seed_duplicate_race_preserves_items_no_collapse() {
        let root = unique_root("race");
        let scope = super::super::protected_anchor::terminal_scope_id(root.as_bytes()).unwrap();
        {
            let mut ns = open(scope).unwrap();
            let _ = ns.lab_delete_all_scoped_items();
        }

        let barrier = Arc::new(Barrier::new(2));
        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for byte in [0x11u8, 0x22u8] {
            let barrier = Arc::clone(&barrier);
            let results = Arc::clone(&results);
            handles.push(std::thread::spawn(move || {
                let mut ns = open(scope).unwrap();
                let mut candidate = [byte; 32];
                barrier.wait();
                let outcome = ns.seed_create_if_absent(&mut candidate, Some(proof()));
                assert!(candidate.iter().all(|&b| b == 0));
                results.lock().unwrap().push(outcome);
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let outcomes = results.lock().unwrap();
        assert_eq!(outcomes.len(), 2);
        let mut ns = open(scope).unwrap();
        let ss = connect().expect("ss");
        let paths = search_seed_paths(&ss, ns.scope_id_hex()).expect("search");
        assert!(!paths.is_empty(), "at least one seed must remain");
        if paths.len() > 1 {
            assert!(
                outcomes
                    .iter()
                    .any(|o| matches!(o, Err(StoreError::Duplicate))),
                "duplicates must surface as DUPLICATE"
            );
            assert!(matches!(ns.seed_load_exact(), Err(StoreError::Duplicate)));
        }
        let _ = ns.lab_delete_all_scoped_items();
    }

    #[test]
    fn anchor_append_replay_conflict_and_gap() {
        let mut ns = open_isolated("anchor");
        let mut candidate = [0x11u8; 32];
        let SeedCreateResult::Created(seed) = ns
            .seed_create_if_absent(&mut candidate, Some(proof()))
            .unwrap()
        else {
            panic!("created");
        };
        let keys = derive_store_keys(&seed);
        let session = [0x22u8; 32];
        let rk = record_key(&keys.k_index, &session);

        let seq1 = make_head(&keys, &session, INITIAL_ANCHOR_SEQ, 1, 0x33, [0u8; 32]);
        assert_eq!(
            ns.anchor_append(&seq1, &keys.k_index, &keys.k_anchor)
                .unwrap(),
            AnchorAppendResult::Appended
        );
        assert_eq!(
            ns.anchor_append(&seq1, &keys.k_index, &keys.k_anchor)
                .unwrap(),
            AnchorAppendResult::ExactReplay
        );

        let seq2 = make_head(&keys, &session, 2, 2, 0x44, [0x55u8; 32]);
        assert_eq!(
            ns.anchor_append(&seq2, &keys.k_index, &keys.k_anchor)
                .unwrap(),
            AnchorAppendResult::Appended
        );

        let conflict = make_head(&keys, &session, 2, 2, 0xAA, [0x55u8; 32]);
        assert_eq!(
            ns.anchor_append(&conflict, &keys.k_index, &keys.k_anchor),
            Err(StoreError::CorruptAttributes)
        );

        let gap = make_head(&keys, &session, 4, 4, 0x66, [0x77u8; 32]);
        assert_eq!(
            ns.anchor_append(&gap, &keys.k_index, &keys.k_anchor),
            Err(StoreError::CorruptAttributes)
        );

        let listed = ns.anchor_list(&rk, &keys.k_index, &keys.k_anchor).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], seq1);
        assert_eq!(listed[1], seq2);

        ns.lab_delete_all_scoped_items().expect("cleanup");
    }

    #[test]
    fn unavailable_without_secret_service() {
        assert_eq!(StoreError::Unavailable.as_code(), "UNAVAILABLE");
        assert_eq!(
            StoreError::LockedOrPromptRequired.as_code(),
            "LOCKED_OR_PROMPT_REQUIRED"
        );
        let prev = std::env::var_os("DBUS_SESSION_BUS_ADDRESS");
        std::env::set_var(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/tmp/raven-0b3-missing-bus",
        );
        let err = NopromptSs::connect().err();
        match prev {
            Some(v) => std::env::set_var("DBUS_SESSION_BUS_ADDRESS", v),
            None => std::env::remove_var("DBUS_SESSION_BUS_ADDRESS"),
        }
        assert!(
            matches!(
                err,
                Some(NopromptError::Unavailable) | Some(NopromptError::LockedOrPromptRequired)
            ),
            "expected Unavailable/Locked, got {err:?}"
        );
    }

    #[test]
    fn typed_locked_unavailable_codes() {
        assert_eq!(StoreError::Unavailable.as_code(), "UNAVAILABLE");
        assert_eq!(
            StoreError::LockedOrPromptRequired.as_code(),
            "LOCKED_OR_PROMPT_REQUIRED"
        );
        assert_eq!(StoreError::Capacity.as_code(), "CAPACITY");
        assert_eq!(StoreError::Duplicate.as_code(), "DUPLICATE");
        assert_eq!(
            StoreError::CorruptAttributes.as_code(),
            "CORRUPT_ATTRIBUTES"
        );
    }

    #[test]
    fn no_file_fallback_symbols() {
        let ns = open_isolated("nofile");
        let probe = ns.namespace_probe();
        assert_eq!(probe.backend, "secret-service");
        assert!(!probe.backend.contains("file"));
    }
}
