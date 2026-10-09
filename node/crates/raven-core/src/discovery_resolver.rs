//! Multi-lane DiscoveryResolver — search without a central Raven DB.
//!
//! Finding a name ≠ verifying a person. `@alias` is NOT identity; `rvn1…` is.
//! Spec: `docs/RAVEN_DISCOVERY_V1.md`.

use crate::address::{decode_address, encode_address, from_display, ADDRESS_VERSION};
use crate::alias_record::{normalize_alias, AliasClaimStore, AliasRecord};
use crate::chat_history::BlockList;
use crate::introduction::IntroductionInbox;
use crate::nearby::NearbyRegistry;
use crate::profile_record::{ProfileStore, RavenProfileRecordV1};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoveryScope {
    Local,
    ExactId,
    ExactAlias,
    MyNetwork,
    Nearby,
    Public,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationState {
    DirectlyVerified,
    TrustedContact,
    Introduced,
    ScopedVerified,
    NearbyVerified,
    PublicSignedProfile,
    AliasConflict,
    ExpiredOrStale,
    Blocked,
    /// Well-formed Raven ID with no signed profile, contact or introduction
    /// behind it. Exact-ID search can still offer it; nothing is verified.
    Unverified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiscoverySource {
    LocalContacts,
    ExactRavenId,
    AliasDht,
    NearbyBle,
    SocialIntroduction,
    PublicProfileIndex,
    /// Present only when serverless flag is OFF — never required for V1 serverless.
    LegacyServer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryIntroduction {
    pub introducer_raven_id: String,
    pub subject_raven_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryResult {
    pub raven_id: String,
    pub display_name: String,
    pub aliases: Vec<String>,
    pub profile_digest: String,
    pub source_set: Vec<DiscoverySource>,
    pub verification_state: VerificationState,
    pub introductions: Vec<DiscoveryIntroduction>,
    pub conflict_count: u32,
    pub sequence: u64,
    pub expires_at: u64,
}

/// Local contact row for LocalContactsProvider (bound to raven_id, not alias).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalContactRow {
    pub raven_id: String,
    pub pub_hex: String,
    pub petname: String,
    pub public_tag: String,
    pub display_name: String,
    pub pinned: bool,
    pub directly_verified: bool,
}

/// Shared discovery context (in-process / community peer stand-in).
pub struct DiscoveryContext {
    pub contacts: Vec<LocalContactRow>,
    pub aliases: AliasClaimStore,
    pub profiles: ProfileStore,
    pub intros: IntroductionInbox,
    pub nearby: NearbyRegistry,
    pub blocked: BlockList,
    /// When true, LegacyServerProvider is disabled (serverless V1).
    pub serverless: bool,
    /// PublicProfileIndexProvider is STUB/OFF for V1.
    pub public_profile_index_enabled: bool,
    pub now_ms: u64,
}

impl Default for DiscoveryContext {
    fn default() -> Self {
        Self {
            contacts: Vec::new(),
            aliases: AliasClaimStore::default(),
            profiles: ProfileStore::default(),
            intros: IntroductionInbox::default(),
            nearby: NearbyRegistry::default(),
            blocked: BlockList::default(),
            serverless: true,
            public_profile_index_enabled: false,
            now_ms: 0,
        }
    }
}

pub trait DiscoveryProvider {
    fn name(&self) -> DiscoverySource;
    fn search(&self, ctx: &DiscoveryContext, query: &str) -> Vec<DiscoveryResult>;
}

pub struct LocalContactsProvider;
pub struct ExactRavenIdProvider;
pub struct AliasDhtProvider;
pub struct NearbyBleProvider;
pub struct SocialIntroductionProvider;
/// STUB/OFF for V1 — exact search first per research.
pub struct PublicProfileIndexProvider;
/// Must NOT be required when serverless flag is on.
pub struct LegacyServerProvider;

impl DiscoveryProvider for LocalContactsProvider {
    fn name(&self) -> DiscoverySource {
        DiscoverySource::LocalContacts
    }
    fn search(&self, ctx: &DiscoveryContext, query: &str) -> Vec<DiscoveryResult> {
        let q = query.trim().trim_start_matches('@').to_lowercase();
        let mut out = Vec::new();
        for c in &ctx.contacts {
            let pet = c.petname.to_lowercase();
            let tag = c.public_tag.to_lowercase();
            let disp = c.display_name.to_lowercase();
            let id_match = c.raven_id.eq_ignore_ascii_case(query.trim());
            let local_match = !q.is_empty()
                && (pet.contains(&q)
                    || tag == q
                    || disp.contains(&q)
                    || c.raven_id.to_lowercase().contains(&q));
            if !(id_match || local_match) {
                continue;
            }
            // Only a blocked contact that matches the query is reported.
            if ctx.blocked.is_blocked(&c.pub_hex) {
                out.push(blocked_result(&c.raven_id));
                continue;
            }
            let state = if c.directly_verified || c.pinned {
                VerificationState::DirectlyVerified
            } else {
                VerificationState::TrustedContact
            };
            out.push(DiscoveryResult {
                raven_id: c.raven_id.clone(),
                display_name: if !c.petname.is_empty() {
                    c.petname.clone()
                } else if !c.display_name.is_empty() {
                    c.display_name.clone()
                } else {
                    c.public_tag.clone()
                },
                aliases: if c.public_tag.is_empty() {
                    vec![]
                } else {
                    vec![c.public_tag.clone()]
                },
                profile_digest: String::new(),
                source_set: vec![DiscoverySource::LocalContacts],
                verification_state: state,
                introductions: vec![],
                conflict_count: 0,
                sequence: 0,
                expires_at: u64::MAX,
            });
        }
        out
    }
}

impl DiscoveryProvider for ExactRavenIdProvider {
    fn name(&self) -> DiscoverySource {
        DiscoverySource::ExactRavenId
    }
    fn search(&self, ctx: &DiscoveryContext, query: &str) -> Vec<DiscoveryResult> {
        let Some(id) = canonical_raven_id(query) else {
            return vec![];
        };
        if blocked_raven_ids(ctx).contains(&id) {
            return vec![blocked_result(&id)];
        }
        let mut r = if let Some(prof) = ctx.profiles.get(&id, ctx.now_ms) {
            profile_to_result(prof, DiscoverySource::ExactRavenId, 0)
        } else {
            // Checksum-valid ID with no profile: offer it, but never as verified.
            DiscoveryResult {
                raven_id: id,
                display_name: String::new(),
                aliases: vec![],
                profile_digest: String::new(),
                source_set: vec![DiscoverySource::ExactRavenId],
                verification_state: VerificationState::Unverified,
                introductions: vec![],
                conflict_count: 0,
                sequence: 0,
                expires_at: 0,
            }
        };
        // A local (unblocked) contact row is stronger than either state above.
        if let Some(c) = ctx
            .contacts
            .iter()
            .find(|c| c.raven_id.eq_ignore_ascii_case(&r.raven_id))
        {
            r.verification_state = if c.directly_verified || c.pinned {
                VerificationState::DirectlyVerified
            } else {
                VerificationState::TrustedContact
            };
            r.source_set.push(DiscoverySource::LocalContacts);
        }
        vec![r]
    }
}

impl DiscoveryProvider for AliasDhtProvider {
    fn name(&self) -> DiscoverySource {
        DiscoverySource::AliasDht
    }
    fn search(&self, ctx: &DiscoveryContext, query: &str) -> Vec<DiscoveryResult> {
        let raw = query.trim();
        // Exact alias lane: @name or normalized exact token (not fuzzy).
        let is_alias_query =
            raw.starts_with('@') || (normalize_alias(raw).is_ok() && !raw.starts_with("rvn1"));
        if !is_alias_query {
            return vec![];
        }
        let Ok(claims) = ctx.aliases.lookup_exact(raw, ctx.now_ms) else {
            return vec![];
        };
        if claims.is_empty() {
            return vec![];
        }
        let conflict_count = if claims.len() > 1 {
            claims.len() as u32
        } else {
            0
        };
        let mut out = Vec::new();
        for claim in claims {
            let mut r = claim_to_result(&claim, conflict_count, ctx);
            if conflict_count > 0 {
                r.verification_state = VerificationState::AliasConflict;
            }
            out.push(r);
        }
        out
    }
}

impl DiscoveryProvider for NearbyBleProvider {
    fn name(&self) -> DiscoverySource {
        DiscoverySource::NearbyBle
    }
    fn search(&self, ctx: &DiscoveryContext, _query: &str) -> Vec<DiscoveryResult> {
        let mut out = Vec::new();
        for b in &ctx.nearby.confirmed {
            out.push(DiscoveryResult {
                raven_id: b.peer_raven_id.clone(),
                display_name: String::new(),
                aliases: vec![],
                profile_digest: String::new(),
                source_set: vec![DiscoverySource::NearbyBle],
                verification_state: VerificationState::NearbyVerified,
                introductions: vec![],
                conflict_count: 0,
                sequence: 0,
                expires_at: u64::MAX,
            });
        }
        out
    }
}

impl DiscoveryProvider for SocialIntroductionProvider {
    fn name(&self) -> DiscoverySource {
        DiscoverySource::SocialIntroduction
    }
    fn search(&self, ctx: &DiscoveryContext, query: &str) -> Vec<DiscoveryResult> {
        let intros = ctx.intros.for_subject_alias(query, ctx.now_ms);
        // Admission only proved the introducer was a trusted contact *then*.
        // INTRODUCED results are ranked above signed public profiles, so trust
        // is re-checked at query time: an introducer who has since been
        // blocked, or is no longer a (non-blocked) contact, vouches for no one.
        let blocked = blocked_raven_ids(ctx);
        let introducer_trusted = |introducer: &str| {
            !blocked.contains(&introducer.to_lowercase())
                && ctx.contacts.iter().any(|c| {
                    c.raven_id.eq_ignore_ascii_case(introducer)
                        && !ctx.blocked.is_blocked(&c.pub_hex)
                })
        };
        let mut by_subject: HashMap<String, DiscoveryResult> = HashMap::new();
        for i in intros {
            if !introducer_trusted(&i.introducer_raven_id) {
                continue;
            }
            let entry = by_subject
                .entry(i.subject_raven_id.clone())
                .or_insert_with(|| DiscoveryResult {
                    raven_id: i.subject_raven_id.clone(),
                    display_name: i.subject_display_name.clone(),
                    aliases: i.subject_aliases.clone(),
                    profile_digest: String::new(),
                    source_set: vec![DiscoverySource::SocialIntroduction],
                    verification_state: VerificationState::Introduced,
                    introductions: vec![],
                    conflict_count: 0,
                    sequence: 0,
                    expires_at: i.expires_at,
                });
            entry.introductions.push(DiscoveryIntroduction {
                introducer_raven_id: i.introducer_raven_id.clone(),
                subject_raven_id: i.subject_raven_id.clone(),
            });
        }
        by_subject.into_values().collect()
    }
}

impl DiscoveryProvider for PublicProfileIndexProvider {
    fn name(&self) -> DiscoverySource {
        DiscoverySource::PublicProfileIndex
    }
    fn search(&self, ctx: &DiscoveryContext, _query: &str) -> Vec<DiscoveryResult> {
        // STUB/OFF for V1 — no fuzzy / trigram index.
        if !ctx.public_profile_index_enabled {
            return vec![];
        }
        vec![]
    }
}

impl DiscoveryProvider for LegacyServerProvider {
    fn name(&self) -> DiscoverySource {
        DiscoverySource::LegacyServer
    }
    fn search(&self, ctx: &DiscoveryContext, _query: &str) -> Vec<DiscoveryResult> {
        if ctx.serverless {
            return vec![];
        }
        // Intentionally empty stub — FastAPI search must not be required.
        vec![]
    }
}

/// Canonical `rvn1…` address when `query` is a well-formed RavenAddressV1
/// (bech32m checksum, `rvn` HRP, version 1). Display form is accepted.
fn canonical_raven_id(query: &str) -> Option<String> {
    let q = query.trim();
    if !q.to_ascii_lowercase().starts_with("rvn1") {
        return None;
    }
    let canon = from_display(q);
    match decode_address(&canon)? {
        (_, ADDRESS_VERSION) => Some(canon),
        _ => None,
    }
}

/// Raven IDs the local block list covers: blocked contacts plus the address of
/// every blocked key, so a blocked identity is caught whichever lane (exact
/// ID, alias, nearby, introduction) surfaces it — contact row or not.
fn blocked_raven_ids(ctx: &DiscoveryContext) -> HashSet<String> {
    let mut out: HashSet<String> = ctx
        .contacts
        .iter()
        .filter(|c| ctx.blocked.is_blocked(&c.pub_hex))
        .map(|c| c.raven_id.to_lowercase())
        .collect();
    for h in &ctx.blocked.pub_hex {
        let Ok(raw) = hex::decode(h.trim()) else {
            continue;
        };
        if let Ok(ed) = <[u8; 32]>::try_from(raw.as_slice()) {
            out.insert(encode_address(&ed));
        }
    }
    out
}

fn blocked_result(raven_id: &str) -> DiscoveryResult {
    DiscoveryResult {
        raven_id: raven_id.to_string(),
        display_name: String::new(),
        aliases: vec![],
        profile_digest: String::new(),
        source_set: vec![DiscoverySource::LocalContacts],
        verification_state: VerificationState::Blocked,
        introductions: vec![],
        conflict_count: 0,
        sequence: 0,
        expires_at: 0,
    }
}

fn profile_to_result(
    prof: &RavenProfileRecordV1,
    source: DiscoverySource,
    conflict_count: u32,
) -> DiscoveryResult {
    let state = if conflict_count > 0 {
        VerificationState::AliasConflict
    } else {
        VerificationState::PublicSignedProfile
    };
    DiscoveryResult {
        raven_id: prof.raven_id.clone(),
        display_name: prof.display_name.clone(),
        aliases: prof.public_aliases.clone(),
        profile_digest: hex::encode(prof.profile_digest()),
        source_set: vec![source],
        verification_state: state,
        introductions: vec![],
        conflict_count,
        sequence: prof.sequence,
        expires_at: prof.expires_at,
    }
}

fn claim_to_result(
    claim: &AliasRecord,
    conflict_count: u32,
    ctx: &DiscoveryContext,
) -> DiscoveryResult {
    let mut r = if let Some(prof) = ctx.profiles.get(&claim.identity_address, ctx.now_ms) {
        profile_to_result(prof, DiscoverySource::AliasDht, conflict_count)
    } else {
        DiscoveryResult {
            raven_id: claim.identity_address.clone(),
            display_name: String::new(),
            aliases: vec![claim.alias.clone()],
            profile_digest: String::new(),
            source_set: vec![DiscoverySource::AliasDht],
            verification_state: if conflict_count > 0 {
                VerificationState::AliasConflict
            } else {
                VerificationState::PublicSignedProfile
            },
            introductions: vec![],
            conflict_count,
            sequence: claim.sequence,
            expires_at: claim.expires_at,
        }
    };
    if !r.aliases.contains(&claim.alias) {
        r.aliases.push(claim.alias.clone());
    }
    r.sequence = claim.sequence;
    r.expires_at = claim.expires_at;
    if !r.source_set.contains(&DiscoverySource::AliasDht) {
        r.source_set.push(DiscoverySource::AliasDht);
    }
    // Local trusted contact upgrades verification (unless conflict/blocked).
    if let Some(c) = ctx
        .contacts
        .iter()
        .find(|c| c.raven_id == claim.identity_address)
    {
        if ctx.blocked.is_blocked(&c.pub_hex) {
            r.verification_state = VerificationState::Blocked;
        } else if conflict_count == 0 {
            r.verification_state = if c.directly_verified || c.pinned {
                VerificationState::DirectlyVerified
            } else {
                VerificationState::TrustedContact
            };
            if !r.source_set.contains(&DiscoverySource::LocalContacts) {
                r.source_set.push(DiscoverySource::LocalContacts);
            }
        }
    }
    r
}

/// Canonical multi-lane resolver.
pub struct DiscoveryResolver {
    providers: Vec<Box<dyn DiscoveryProvider + Send + Sync>>,
}

impl Default for DiscoveryResolver {
    fn default() -> Self {
        Self::v1()
    }
}

impl DiscoveryResolver {
    pub fn v1() -> Self {
        Self {
            providers: vec![
                Box::new(LocalContactsProvider),
                Box::new(ExactRavenIdProvider),
                Box::new(AliasDhtProvider),
                Box::new(NearbyBleProvider),
                Box::new(SocialIntroductionProvider),
                Box::new(PublicProfileIndexProvider),
                Box::new(LegacyServerProvider),
            ],
        }
    }

    pub fn search(
        &self,
        query: &str,
        scope: DiscoveryScope,
        ctx: &DiscoveryContext,
    ) -> Vec<DiscoveryResult> {
        let active: BTreeSet<DiscoverySource> = match scope {
            DiscoveryScope::Local => [DiscoverySource::LocalContacts].into_iter().collect(),
            DiscoveryScope::ExactId => [DiscoverySource::ExactRavenId].into_iter().collect(),
            DiscoveryScope::ExactAlias => [DiscoverySource::AliasDht].into_iter().collect(),
            DiscoveryScope::MyNetwork => [
                DiscoverySource::LocalContacts,
                DiscoverySource::SocialIntroduction,
            ]
            .into_iter()
            .collect(),
            DiscoveryScope::Nearby => [DiscoverySource::NearbyBle].into_iter().collect(),
            DiscoveryScope::Public => [
                DiscoverySource::ExactRavenId,
                DiscoverySource::AliasDht,
                DiscoverySource::PublicProfileIndex,
            ]
            .into_iter()
            .collect(),
            DiscoveryScope::All => self.providers.iter().map(|p| p.name()).collect(),
        };

        let mut merged: HashMap<String, DiscoveryResult> = HashMap::new();
        let mut conflict_bucket: HashMap<String, Vec<DiscoveryResult>> = HashMap::new();

        for p in &self.providers {
            if !active.contains(&p.name()) {
                continue;
            }
            // PublicProfileIndex stays OFF unless explicitly enabled.
            if p.name() == DiscoverySource::PublicProfileIndex && !ctx.public_profile_index_enabled
            {
                continue;
            }
            if p.name() == DiscoverySource::LegacyServer && ctx.serverless {
                continue;
            }
            for r in p.search(ctx, query) {
                if r.verification_state == VerificationState::AliasConflict {
                    conflict_bucket
                        .entry(query.trim().trim_start_matches('@').to_lowercase())
                        .or_default()
                        .push(r);
                    continue;
                }
                merge_result(&mut merged, r);
            }
        }

        // Surface all conflict candidates (never silent pick).
        let mut out: Vec<DiscoveryResult> = merged.into_values().collect();
        for (_alias, claims) in conflict_bucket {
            for r in claims {
                // Keep distinct raven_ids even under conflict.
                if let Some(existing) = out.iter_mut().find(|e| e.raven_id == r.raven_id) {
                    existing.verification_state = VerificationState::AliasConflict;
                    existing.conflict_count = existing.conflict_count.max(r.conflict_count);
                    for s in r.source_set {
                        if !existing.source_set.contains(&s) {
                            existing.source_set.push(s);
                        }
                    }
                } else {
                    out.push(r);
                }
            }
        }

        // Block list wins over every lane's own verdict.
        let blocked = blocked_raven_ids(ctx);
        for r in &mut out {
            if r.verification_state != VerificationState::Blocked
                && blocked.contains(&r.raven_id.to_lowercase())
            {
                let sources = std::mem::take(&mut r.source_set);
                *r = blocked_result(&r.raven_id);
                r.source_set = sources;
            }
        }

        out.sort_by(|a, b| {
            rank(a.verification_state)
                .cmp(&rank(b.verification_state))
                .then(a.raven_id.cmp(&b.raven_id))
        });
        out
    }
}

fn merge_result(merged: &mut HashMap<String, DiscoveryResult>, r: DiscoveryResult) {
    merged
        .entry(r.raven_id.clone())
        .and_modify(|e| {
            for s in &r.source_set {
                if !e.source_set.contains(s) {
                    e.source_set.push(*s);
                }
            }
            if e.display_name.is_empty() && !r.display_name.is_empty() {
                e.display_name = r.display_name.clone();
            }
            for a in &r.aliases {
                if !e.aliases.contains(a) {
                    e.aliases.push(a.clone());
                }
            }
            if e.profile_digest.is_empty() {
                e.profile_digest = r.profile_digest.clone();
            }
            if rank(r.verification_state) < rank(e.verification_state) {
                e.verification_state = r.verification_state;
            }
            e.conflict_count = e.conflict_count.max(r.conflict_count);
            e.introductions.extend(r.introductions.iter().cloned());
            e.sequence = e.sequence.max(r.sequence);
            if r.expires_at > 0 {
                e.expires_at = if e.expires_at == 0 {
                    r.expires_at
                } else {
                    e.expires_at.min(r.expires_at)
                };
            }
        })
        .or_insert(r);
}

fn rank(s: VerificationState) -> u8 {
    match s {
        VerificationState::Blocked => 0,
        VerificationState::DirectlyVerified => 1,
        VerificationState::TrustedContact => 2,
        VerificationState::ScopedVerified => 3,
        VerificationState::Introduced => 4,
        VerificationState::NearbyVerified => 5,
        VerificationState::PublicSignedProfile => 6,
        VerificationState::AliasConflict => 7,
        VerificationState::ExpiredOrStale => 8,
        VerificationState::Unverified => 9,
    }
}

/// Stable JSON shape for terminal/mobile parity (acceptance #19).
pub fn result_model_schema_keys() -> &'static [&'static str] {
    &[
        "raven_id",
        "display_name",
        "aliases",
        "profile_digest",
        "source_set",
        "verification_state",
        "introductions",
        "conflict_count",
        "sequence",
        "expires_at",
    ]
}
