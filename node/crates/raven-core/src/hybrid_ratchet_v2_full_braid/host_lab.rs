//! In-memory Full Braid host harness (design §§2.2, 2.4, 4.12).

use crate::hybrid_ratchet_v2_full_braid::constants::{
    BRAID_MAX_RVOR_BYTES, BRAID_MAX_RVOR_ENTRIES, BRAID_MAX_RVQI_ENTRIES,
};
use crate::hybrid_ratchet_v2_full_braid::pipeline::{self, BRAID_RVOR_TTL_MS, RECOVER_PREPARED};
use crate::hybrid_ratchet_v2_full_braid::state_codec::decode_rvfb1;
use crate::hybrid_ratchet_v2_full_braid::wire_rvbj1::{decode_rvbj1, INTENT_NORMAL};
use crate::hybrid_ratchet_v2_full_braid::wire_rvor1::{decode_rvor1, encode_rvor1};
use crate::hybrid_ratchet_v2_full_braid::wire_rvqi1::{
    decode_rvqi1, encode_rvqi1, Rvqi1, RVQI1_STATUS_QUARANTINED,
};
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::{Zeroize, Zeroizing};

pub type ObjectDigest = [u8; 32];
pub type TransitionId = [u8; 32];
pub type OwnerToken = u64;
pub type HostLabResult<T> = Result<T, HostLabError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DedupState {
    Reserved,
    Pending,
    Active,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupRecord {
    pub object_digest: ObjectDigest,
    pub state: DedupState,
    pub owner_token: Option<OwnerToken>,
    pub transition_id: Option<TransitionId>,
    pub authenticated_endpoint_expires_at_ms: u64,
    pub horizon_ms: Option<u64>,
    pub cas_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostLabError {
    DedupConflict(DedupState),
    MissingDedup,
    MissingJournal,
    MissingLiveState,
    MissingRvor,
    MissingRvqi,
    NotActive,
    Quarantined,
    WrongState,
    WrongOwner,
    TransitionMismatch,
    PhaseNotPromoted,
    StoreConflict,
    StoreCapacity,
    InvalidWire,
    Pipeline(i32),
    TimeOverflow,
    CasOverflow,
    HorizonNotReached,
    CasTagMismatch,
    RvorStillRetained,
    PendingReference,
    RepairNotReady,
}

#[derive(Debug, Clone)]
struct StoredRvor {
    bytes: Vec<u8>,
    retention_expiry_ms: u64,
}

/// The journaled RVBJ1 embeds the complete candidate session state: wiped on
/// drop, redacted from `Debug`.
#[derive(Clone)]
struct JournalRecord {
    object_digest: ObjectDigest,
    intent_bytes: Vec<u8>,
}

impl fmt::Debug for JournalRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JournalRecord")
            .field("object_digest", &self.object_digest)
            .field("intent_len", &self.intent_bytes.len())
            .finish()
    }
}

impl Drop for JournalRecord {
    fn drop(&mut self) {
        self.intent_bytes.zeroize();
    }
}

#[derive(Clone)]
struct RepairSuccessor {
    transition_id: TransitionId,
    /// Exact repair RVBJ1 retained as A–F evidence (not caller IDs alone).
    intent_bytes: Vec<u8>,
}

impl fmt::Debug for RepairSuccessor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepairSuccessor")
            .field("transition_id", &self.transition_id)
            .field("intent_len", &self.intent_bytes.len())
            .finish()
    }
}

#[derive(Default)]
struct HostLabState {
    dedup: HashMap<ObjectDigest, DedupRecord>,
    rvors: HashMap<TransitionId, StoredRvor>,
    rvqis: HashMap<TransitionId, Vec<u8>>,
    journals: HashMap<TransitionId, JournalRecord>,
    live_states: HashMap<ObjectDigest, Vec<u8>>,
    repair_successors: HashMap<TransitionId, RepairSuccessor>,
    clear_call_count: u64,
}

/// Counts only: `live_states` holds every session's ratchet secrets.
impl fmt::Debug for HostLabState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostLabState")
            .field("dedup", &self.dedup.len())
            .field("rvors", &self.rvors.len())
            .field("rvqis", &self.rvqis.len())
            .field("journals", &self.journals.len())
            .field("live_states", &self.live_states.len())
            .field("repair_successors", &self.repair_successors.len())
            .field("clear_call_count", &self.clear_call_count)
            .finish()
    }
}

impl HostLabState {
    /// Store a live session state, wiping the one it replaces.
    fn put_live_state(&mut self, object_digest: ObjectDigest, state_bytes: Vec<u8>) {
        if let Some(mut old) = self.live_states.insert(object_digest, state_bytes) {
            old.zeroize();
        }
    }

    /// Drop a live session state, wiping it.
    fn remove_live_state(&mut self, object_digest: &ObjectDigest) {
        if let Some(mut old) = self.live_states.remove(object_digest) {
            old.zeroize();
        }
    }
}

impl Drop for HostLabState {
    fn drop(&mut self) {
        for live in self.live_states.values_mut() {
            live.zeroize();
        }
    }
}

/// Cloneable handle whose mutation methods execute under one exclusive mutex lease.
#[derive(Debug, Clone, Default)]
pub struct HostLab {
    inner: Arc<Mutex<HostLabState>>,
}

impl HostLab {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock_state(&self) -> MutexGuard<'_, HostLabState> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub fn with_lease<R>(
        &self,
        operation: impl FnOnce(&mut MutationLease<'_>) -> HostLabResult<R>,
    ) -> HostLabResult<R> {
        let mut state = self.lock_state();
        let mut lease = MutationLease { state: &mut state };
        operation(&mut lease)
    }

    pub fn dedup_record(&self, object_digest: ObjectDigest) -> Option<DedupRecord> {
        self.lock_state().dedup.get(&object_digest).cloned()
    }

    pub fn live_state(&self, object_digest: ObjectDigest) -> Option<Vec<u8>> {
        self.lock_state().live_states.get(&object_digest).cloned()
    }

    pub fn has_rvor(&self, transition_id: TransitionId) -> bool {
        self.lock_state().rvors.contains_key(&transition_id)
    }

    pub fn has_rvqi(&self, transition_id: TransitionId) -> bool {
        self.lock_state().rvqis.contains_key(&transition_id)
    }

    pub fn clear_call_count(&self) -> u64 {
        self.lock_state().clear_call_count
    }

    /// Slice 2 restart rule: no canonical mutation exists for volatile RESERVED rows.
    pub fn drop_all_reserved(&self) -> usize {
        let mut state = self.lock_state();
        let before = state.dedup.len();
        state
            .dedup
            .retain(|_, record| record.state != DedupState::Reserved);
        before - state.dedup.len()
    }
}

/// Exclusive view over all host-side state that participates in Task 9 CAS decisions.
pub struct MutationLease<'a> {
    state: &'a mut HostLabState,
}

impl MutationLease<'_> {
    pub fn dedup_record(&self, object_digest: ObjectDigest) -> Option<DedupRecord> {
        self.state.dedup.get(&object_digest).cloned()
    }

    pub fn try_reserve(
        &mut self,
        object_digest: ObjectDigest,
        owner_token: OwnerToken,
        authenticated_endpoint_expires_at_ms: u64,
    ) -> HostLabResult<ReservationGuard<'_>> {
        if let Some(existing) = self.state.dedup.get(&object_digest) {
            return Err(HostLabError::DedupConflict(existing.state));
        }
        self.state.dedup.insert(
            object_digest,
            DedupRecord {
                object_digest,
                state: DedupState::Reserved,
                owner_token: Some(owner_token),
                transition_id: None,
                authenticated_endpoint_expires_at_ms,
                horizon_ms: None,
                cas_generation: 1,
            },
        );
        Ok(ReservationGuard {
            state: self.state,
            object_digest,
            owner_token,
            armed: true,
        })
    }

    pub fn promote_pending(&mut self, object_digest: ObjectDigest) -> HostLabResult<Vec<u8>> {
        let record = self
            .state
            .dedup
            .get(&object_digest)
            .cloned()
            .ok_or(HostLabError::MissingDedup)?;
        if record.state != DedupState::Pending {
            return Err(HostLabError::WrongState);
        }
        let transition_id = record
            .transition_id
            .ok_or(HostLabError::TransitionMismatch)?;
        let journal = self
            .state
            .journals
            .get(&transition_id)
            .cloned()
            .ok_or(HostLabError::MissingJournal)?;
        if journal.object_digest != object_digest {
            return Err(HostLabError::TransitionMismatch);
        }
        let live = Zeroizing::new(
            self.state
                .live_states
                .get(&object_digest)
                .cloned()
                .ok_or(HostLabError::MissingLiveState)?,
        );
        let promoted = pipeline::promote_state(&live, &journal.intent_bytes)
            .map_err(HostLabError::Pipeline)?;
        if promoted.meta.transition_id != transition_id || promoted.meta.pending_phase != 2 {
            return Err(HostLabError::TransitionMismatch);
        }
        self.state
            .put_live_state(object_digest, promoted.state_bytes.clone());
        Ok(promoted.state_bytes)
    }

    pub fn insert_rvor(
        &mut self,
        transition_id: TransitionId,
        rvor_bytes: Vec<u8>,
    ) -> HostLabResult<()> {
        let decoded = decode_rvor1(&rvor_bytes).map_err(|_| HostLabError::InvalidWire)?;
        if decoded.transition_id != transition_id
            || encode_rvor1(&decoded).map_err(|_| HostLabError::InvalidWire)? != rvor_bytes
        {
            return Err(HostLabError::TransitionMismatch);
        }
        if let Some(successor) = self
            .state
            .repair_successors
            .values()
            .find(|successor| successor.transition_id == transition_id)
        {
            pipeline::verify_repair_rvor_evidence(&successor.intent_bytes, &rvor_bytes)
                .map_err(HostLabError::Pipeline)?;
        }
        if let Some(existing) = self.state.rvors.get(&transition_id) {
            return if existing.bytes == rvor_bytes {
                Ok(())
            } else {
                Err(HostLabError::StoreConflict)
            };
        }
        if self.state.rvors.len() >= BRAID_MAX_RVOR_ENTRIES {
            return Err(HostLabError::StoreCapacity);
        }
        let used_bytes = self
            .state
            .rvors
            .values()
            .try_fold(0usize, |used, record| used.checked_add(record.bytes.len()))
            .ok_or(HostLabError::StoreCapacity)?;
        if used_bytes
            .checked_add(rvor_bytes.len())
            .filter(|total| *total <= BRAID_MAX_RVOR_BYTES)
            .is_none()
        {
            return Err(HostLabError::StoreCapacity);
        }
        self.state.rvors.insert(
            transition_id,
            StoredRvor {
                bytes: rvor_bytes,
                retention_expiry_ms: decoded.retention_expiry_ms,
            },
        );
        Ok(())
    }

    /// Apply the §4.12 RVOR eviction predicates before removing immutable output evidence.
    pub fn evict_rvor(&mut self, transition_id: TransitionId, now_ms: u64) -> HostLabResult<()> {
        let stored = self
            .state
            .rvors
            .get(&transition_id)
            .cloned()
            .ok_or(HostLabError::MissingRvor)?;
        if now_ms < stored.retention_expiry_ms {
            return Err(HostLabError::HorizonNotReached);
        }
        let decoded = decode_rvor1(&stored.bytes).map_err(|_| HostLabError::InvalidWire)?;
        if decoded.transition_id != transition_id {
            return Err(HostLabError::TransitionMismatch);
        }

        let has_canonical_replay = self.state.live_states.values().any(|live| {
            decode_rvfb1(live).map_or(true, |state| {
                state
                    .replays
                    .iter()
                    .any(|replay| replay.transition_id == transition_id)
            })
        });
        if !self.state.rvqis.contains_key(&transition_id) && has_canonical_replay {
            return Err(HostLabError::PendingReference);
        }
        if decoded.object_digest != [0; 32] {
            let mapping = self
                .state
                .dedup
                .get(&decoded.object_digest)
                .ok_or(HostLabError::MissingDedup)?;
            if mapping.state != DedupState::Blocked || mapping.transition_id != Some(transition_id)
            {
                return Err(HostLabError::WrongState);
            }
        }

        self.state.rvors.remove(&transition_id);
        Ok(())
    }

    pub fn insert_rvqi(
        &mut self,
        transition_id: TransitionId,
        rvqi_bytes: Vec<u8>,
    ) -> HostLabResult<()> {
        let decoded = decode_rvqi1(&rvqi_bytes).map_err(|_| HostLabError::InvalidWire)?;
        if decoded.transition_id != transition_id
            || encode_rvqi1(&decoded).map_err(|_| HostLabError::InvalidWire)? != rvqi_bytes
        {
            return Err(HostLabError::TransitionMismatch);
        }
        let mapping = self
            .state
            .dedup
            .get(&decoded.object_digest)
            .ok_or(HostLabError::MissingDedup)?;
        // RVQI may only exist for Blocked mappings produced by the atomic
        // quarantine barrier. Standalone PENDING+RVQI is forbidden.
        if mapping.state != DedupState::Blocked {
            return Err(HostLabError::WrongState);
        }
        if mapping.transition_id != Some(transition_id) {
            return Err(HostLabError::TransitionMismatch);
        }
        if decoded.cas_tag != mapping.cas_generation {
            return Err(HostLabError::CasTagMismatch);
        }
        if let Some(existing) = self.state.rvqis.get(&transition_id) {
            return if existing == &rvqi_bytes {
                Ok(())
            } else {
                Err(HostLabError::StoreConflict)
            };
        }
        if self.state.rvqis.len() >= BRAID_MAX_RVQI_ENTRIES {
            return Err(HostLabError::StoreCapacity);
        }
        self.state.rvqis.insert(transition_id, rvqi_bytes);
        Ok(())
    }

    pub fn record_repair_successor(
        &mut self,
        quarantined_transition_id: TransitionId,
        repair_intent_bytes: Vec<u8>,
    ) -> HostLabResult<()> {
        let repair_transition_id = pipeline::repair_intent_binds_original(
            &quarantined_transition_id,
            &repair_intent_bytes,
        )
        .map_err(HostLabError::Pipeline)?;
        if quarantined_transition_id == repair_transition_id {
            return Err(HostLabError::TransitionMismatch);
        }
        if !self.state.dedup.values().any(|record| {
            record.transition_id == Some(quarantined_transition_id)
                && record.state != DedupState::Reserved
        }) {
            return Err(HostLabError::MissingDedup);
        }
        if let Some(stored) = self.state.rvors.get(&repair_transition_id) {
            pipeline::verify_repair_rvor_evidence(&repair_intent_bytes, &stored.bytes)
                .map_err(HostLabError::Pipeline)?;
        }
        if let Some(existing) = self.state.repair_successors.get(&quarantined_transition_id) {
            return if existing.transition_id == repair_transition_id
                && existing.intent_bytes == repair_intent_bytes
            {
                Ok(())
            } else {
                Err(HostLabError::StoreConflict)
            };
        }
        self.state.repair_successors.insert(
            quarantined_transition_id,
            RepairSuccessor {
                transition_id: repair_transition_id,
                intent_bytes: repair_intent_bytes,
            },
        );
        Ok(())
    }

    pub fn releasable(&self, transition_id: TransitionId) -> bool {
        self.state.rvors.contains_key(&transition_id)
            && !self.state.rvqis.contains_key(&transition_id)
    }

    pub fn clear_barrier(
        &mut self,
        object_digest: ObjectDigest,
        now_ms: u64,
    ) -> HostLabResult<Vec<u8>> {
        let mapping = self
            .state
            .dedup
            .get(&object_digest)
            .cloned()
            .ok_or(HostLabError::MissingDedup)?;
        if mapping.state != DedupState::Pending {
            return Err(HostLabError::WrongState);
        }
        let transition_id = mapping
            .transition_id
            .ok_or(HostLabError::TransitionMismatch)?;
        let live = Zeroizing::new(
            self.state
                .live_states
                .get(&object_digest)
                .cloned()
                .ok_or(HostLabError::MissingLiveState)?,
        );
        let live_state = decode_rvfb1(&live).map_err(|_| HostLabError::InvalidWire)?;
        if live_state.prefix.pending_phase != 2
            || live_state.prefix.pending_transition_id != transition_id
        {
            return Err(HostLabError::PhaseNotPromoted);
        }
        if self.state.rvqis.contains_key(&transition_id) {
            return Err(HostLabError::Quarantined);
        }
        let rvor = self
            .state
            .rvors
            .get(&transition_id)
            .cloned()
            .ok_or(HostLabError::MissingRvor)?;
        let journal = self
            .state
            .journals
            .get(&transition_id)
            .cloned()
            .ok_or(HostLabError::MissingJournal)?;
        if journal.object_digest != object_digest {
            return Err(HostLabError::TransitionMismatch);
        }
        let next_generation = mapping
            .cas_generation
            .checked_add(1)
            .ok_or(HostLabError::CasOverflow)?;

        self.state.clear_call_count = self.state.clear_call_count.saturating_add(1);
        let cleared = pipeline::clear_pending(&live, &journal.intent_bytes, &rvor.bytes, now_ms)
            .map_err(HostLabError::Pipeline)?;
        if cleared.meta.transition_id != transition_id || cleared.meta.pending_phase != 0 {
            return Err(HostLabError::TransitionMismatch);
        }

        self.state
            .put_live_state(object_digest, cleared.state_bytes.clone());
        let record = self
            .state
            .dedup
            .get_mut(&object_digest)
            .ok_or(HostLabError::MissingDedup)?;
        record.state = DedupState::Active;
        record.cas_generation = next_generation;
        self.state.journals.remove(&transition_id);
        Ok(cleared.state_bytes)
    }

    pub fn try_release(&self, object_digest: ObjectDigest) -> HostLabResult<Vec<u8>> {
        let mapping = self
            .state
            .dedup
            .get(&object_digest)
            .ok_or(HostLabError::MissingDedup)?;
        if mapping.state != DedupState::Active {
            return Err(HostLabError::NotActive);
        }
        let transition_id = mapping
            .transition_id
            .ok_or(HostLabError::TransitionMismatch)?;
        if self.state.rvqis.contains_key(&transition_id) {
            return Err(HostLabError::Quarantined);
        }
        let rvor = self
            .state
            .rvors
            .get(&transition_id)
            .ok_or(HostLabError::MissingRvor)?;
        let decoded = decode_rvor1(&rvor.bytes).map_err(|_| HostLabError::InvalidWire)?;
        if decoded.transition_id != transition_id {
            return Err(HostLabError::TransitionMismatch);
        }
        Ok(decoded.outputs_bytes)
    }

    pub fn quarantine_or_repair_block(
        &mut self,
        object_digest: ObjectDigest,
        transition_id: TransitionId,
        now_ms: u64,
    ) -> HostLabResult<DedupRecord> {
        let mapping = self
            .state
            .dedup
            .get(&object_digest)
            .cloned()
            .ok_or(HostLabError::MissingDedup)?;
        if !matches!(mapping.state, DedupState::Pending | DedupState::Active) {
            return Err(HostLabError::WrongState);
        }
        if mapping.transition_id != Some(transition_id) {
            return Err(HostLabError::TransitionMismatch);
        }
        let ttl_horizon = now_ms
            .checked_add(BRAID_RVOR_TTL_MS)
            .ok_or(HostLabError::TimeOverflow)?;
        let rvor_expiry = self
            .state
            .rvors
            .get(&transition_id)
            .map(|record| record.retention_expiry_ms)
            .unwrap_or(0);
        let horizon_ms = mapping
            .authenticated_endpoint_expires_at_ms
            .max(rvor_expiry)
            .max(ttl_horizon);
        let next_generation = mapping
            .cas_generation
            .checked_add(1)
            .ok_or(HostLabError::CasOverflow)?;
        let rvqi_bytes = encode_rvqi1(&Rvqi1 {
            transition_id,
            object_digest,
            status: RVQI1_STATUS_QUARANTINED,
            cas_tag: next_generation,
        })
        .map_err(|_| HostLabError::InvalidWire)?;
        match self.state.rvqis.get(&transition_id) {
            Some(existing) if existing != &rvqi_bytes => {
                return Err(HostLabError::StoreConflict);
            }
            None if self.state.rvqis.len() >= BRAID_MAX_RVQI_ENTRIES => {
                return Err(HostLabError::StoreCapacity);
            }
            _ => {}
        }

        let mut blocked = mapping;
        blocked.state = DedupState::Blocked;
        blocked.owner_token = None;
        blocked.horizon_ms = Some(horizon_ms);
        blocked.cas_generation = next_generation;
        self.state.dedup.insert(object_digest, blocked.clone());
        self.state.rvqis.insert(transition_id, rvqi_bytes);
        Ok(blocked)
    }

    pub fn joint_gc(
        &mut self,
        object_digest: ObjectDigest,
        now_ms: u64,
        cas_tag: u64,
    ) -> HostLabResult<()> {
        let mapping = self
            .state
            .dedup
            .get(&object_digest)
            .cloned()
            .ok_or(HostLabError::MissingDedup)?;
        if mapping.state != DedupState::Blocked {
            return Err(HostLabError::WrongState);
        }
        let transition_id = mapping
            .transition_id
            .ok_or(HostLabError::TransitionMismatch)?;
        let horizon_ms = mapping.horizon_ms.ok_or(HostLabError::WrongState)?;
        if now_ms < horizon_ms {
            return Err(HostLabError::HorizonNotReached);
        }
        let rvqi_bytes = self
            .state
            .rvqis
            .get(&transition_id)
            .cloned()
            .ok_or(HostLabError::MissingRvqi)?;
        let rvqi = decode_rvqi1(&rvqi_bytes).map_err(|_| HostLabError::InvalidWire)?;
        if rvqi.transition_id != transition_id
            || rvqi.object_digest != object_digest
            || rvqi.status != RVQI1_STATUS_QUARANTINED
        {
            return Err(HostLabError::TransitionMismatch);
        }
        if rvqi.cas_tag != cas_tag || mapping.cas_generation != cas_tag {
            return Err(HostLabError::CasTagMismatch);
        }
        if self.state.rvors.contains_key(&transition_id) {
            return Err(HostLabError::RvorStillRetained);
        }
        if self.state.journals.contains_key(&transition_id)
            || self.state.live_states.values().any(|live| {
                decode_rvfb1(live).map_or(true, |state| {
                    matches!(state.prefix.pending_phase, 1 | 2)
                        && state.prefix.pending_transition_id == transition_id
                })
            })
        {
            return Err(HostLabError::PendingReference);
        }
        if let Some(successor) = self.state.repair_successors.get(&transition_id).cloned() {
            // Durable A–F evidence: exact retained repair RVBJ1 whose materialize
            // equals the stored successor RVOR, and successor remains Releasable.
            let Some(stored) = self.state.rvors.get(&successor.transition_id) else {
                return Err(HostLabError::RepairNotReady);
            };
            if pipeline::verify_repair_rvor_evidence(&successor.intent_bytes, &stored.bytes)
                .map_err(HostLabError::Pipeline)?
                != successor.transition_id
            {
                return Err(HostLabError::TransitionMismatch);
            }
            if self.state.rvqis.contains_key(&successor.transition_id) {
                return Err(HostLabError::RepairNotReady);
            }
        }

        self.state.dedup.remove(&object_digest);
        self.state.rvqis.remove(&transition_id);
        self.state.repair_successors.remove(&transition_id);
        // The GC'd digest can be reserved again, and `mark_pending_inner` refuses
        // an object whose live state still exists (`StoreConflict`). Every
        // pending reference was ruled out above, so the stale state is garbage.
        self.state.remove_live_state(&object_digest);
        Ok(())
    }
}

/// Scoped RESERVED ownership. Any uncommitted drop removes only the matching token's row.
pub struct ReservationGuard<'a> {
    state: &'a mut HostLabState,
    object_digest: ObjectDigest,
    owner_token: OwnerToken,
    armed: bool,
}

impl ReservationGuard<'_> {
    fn mark_pending_inner(
        mut self,
        transition_id: TransitionId,
        material: Option<(Vec<u8>, Vec<u8>)>,
    ) -> HostLabResult<()> {
        let next_generation = {
            let record = self
                .state
                .dedup
                .get(&self.object_digest)
                .ok_or(HostLabError::MissingDedup)?;
            if record.state != DedupState::Reserved {
                return Err(HostLabError::WrongState);
            }
            if record.owner_token != Some(self.owner_token) {
                return Err(HostLabError::WrongOwner);
            }
            record
                .cas_generation
                .checked_add(1)
                .ok_or(HostLabError::CasOverflow)?
        };

        if let Some((intent_bytes, live_state_bytes)) = &material {
            let recovered = pipeline::recover_state(live_state_bytes, intent_bytes)
                .map_err(HostLabError::Pipeline)?;
            let intent = decode_rvbj1(intent_bytes).map_err(|_| HostLabError::InvalidWire)?;
            if recovered.meta.flags != RECOVER_PREPARED
                || recovered.meta.transition_id != transition_id
                || intent.header.transition_id != transition_id
            {
                return Err(HostLabError::TransitionMismatch);
            }
            // Normal inbound journals must bind exactly to the reserved object.
            if intent.header.intent_kind != INTENT_NORMAL
                || intent.header.object_digest != self.object_digest
            {
                return Err(HostLabError::TransitionMismatch);
            }
            if self.state.journals.contains_key(&transition_id)
                || self.state.live_states.contains_key(&self.object_digest)
            {
                return Err(HostLabError::StoreConflict);
            }
        }

        if let Some((intent_bytes, live_state_bytes)) = material {
            self.state.journals.insert(
                transition_id,
                JournalRecord {
                    object_digest: self.object_digest,
                    intent_bytes,
                },
            );
            self.state
                .put_live_state(self.object_digest, live_state_bytes);
        }
        let record = self
            .state
            .dedup
            .get_mut(&self.object_digest)
            .ok_or(HostLabError::MissingDedup)?;
        record.state = DedupState::Pending;
        record.owner_token = None;
        record.transition_id = Some(transition_id);
        record.horizon_ms = None;
        record.cas_generation = next_generation;
        self.armed = false;
        Ok(())
    }

    pub fn mark_pending(self, transition_id: TransitionId) -> HostLabResult<()> {
        self.mark_pending_inner(transition_id, None)
    }

    pub fn mark_pending_with_session(
        self,
        transition_id: TransitionId,
        intent_bytes: Vec<u8>,
        live_state_bytes: Vec<u8>,
    ) -> HostLabResult<()> {
        self.mark_pending_inner(transition_id, Some((intent_bytes, live_state_bytes)))
    }

    pub fn cancel_with_token(&mut self, owner_token: OwnerToken) -> bool {
        if !self.armed || owner_token != self.owner_token {
            return false;
        }
        let matches_owner = self
            .state
            .dedup
            .get(&self.object_digest)
            .is_some_and(|record| {
                record.state == DedupState::Reserved && record.owner_token == Some(self.owner_token)
            });
        if matches_owner {
            self.state.dedup.remove(&self.object_digest);
            self.armed = false;
        }
        matches_owner
    }

    pub fn cancel(mut self) -> bool {
        self.cancel_with_token(self.owner_token)
    }
}

impl Drop for ReservationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.cancel_with_token(self.owner_token);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_ratchet_v2_full_braid::constants::FLAG_AWAITING_COMPLETE;
    use crate::hybrid_ratchet_v2_full_braid::init::{
        init_write, ROLE_ALICE, RVFI1_MAGIC, RVFI1_SCHEMA,
    };
    use crate::hybrid_ratchet_v2_full_braid::pipeline::{
        materialize_rvor, terminalize_conflict, transition_prepare, PipelineResult,
        BRAID_RVOR_TTL_MS,
    };
    use crate::hybrid_ratchet_v2_full_braid::state_codec::{decode_rvfb1, encode_rvfb1};
    use crate::hybrid_ratchet_v2_full_braid::transition::LabCrypto;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{encode_rvbe1, Rvbe1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{encode_rvbi1, Rvbi1, OP_SEND};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::Rvbm1;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbo1::encode_empty_rvbo1;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvor1::{
        decode_rvor1, encode_rvor1, Rvor1, RVOR1_FLAG_REPAIR,
    };
    use crate::hybrid_ratchet_v2_full_braid::wire_rvqi1::{
        encode_rvqi1, Rvqi1, RVQI1_STATUS_QUARANTINED,
    };
    use crate::hybrid_ratchet_v2_full_braid::wire_util::{
        write_array32, write_bytes, write_u16be, write_u32be, write_u8,
    };
    use crate::hybrid_ratchet_v2_tr::x25519_public;
    use crate::mlkem768_incremental as mlkem;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};
    use std::thread;

    // Send journals bind object_digest = 0; reservation must match.
    const OBJECT: [u8; 32] = [0; 32];
    const OWNER: u64 = 0x1122_3344_5566_7788;

    fn before_bytes() -> Vec<u8> {
        let bob_spk_pub = x25519_public(&[0x33; 32]).unwrap();
        let mut init = Vec::new();
        write_bytes(&mut init, RVFI1_MAGIC);
        write_u16be(&mut init, RVFI1_SCHEMA);
        write_array32(&mut init, &[0x53; 32]);
        write_u8(&mut init, ROLE_ALICE);
        write_u8(&mut init, 0);
        write_array32(&mut init, &[0x11; 32]);
        write_array32(&mut init, &[0x22; 32]);
        write_array32(&mut init, &bob_spk_pub);
        write_array32(&mut init, &[0x44; 32]);
        write_u32be(&mut init, 0);
        init_write(&init).unwrap()
    }

    fn send_input_bytes() -> Vec<u8> {
        encode_rvbi1(&Rvbi1 {
            op: OP_SEND,
            direction: 0,
            ch: None,
            expected_ch: None,
            object_digest: None,
            frame: None,
            mutation: Rvbm1::no_aead(),
        })
        .unwrap()
    }

    fn env_bytes(clock: u64) -> Vec<u8> {
        let mut env = Rvbe1::default_caps(clock);
        env.keygen_seed = vec![0x5A; mlkem::SEED_LEN];
        encode_rvbe1(&env).unwrap()
    }

    fn prepare_after_reservation(
        host: &HostLab,
        object_digest: [u8; 32],
        owner_token: u64,
        endpoint_expiry: u64,
        clock: u64,
    ) -> PipelineResult {
        host.with_lease(|lease| {
            let reservation = lease.try_reserve(object_digest, owner_token, endpoint_expiry)?;
            let mut crypto = LabCrypto::default();
            let prepared = transition_prepare(
                &before_bytes(),
                &send_input_bytes(),
                &env_bytes(clock),
                &mut crypto,
            )
            .unwrap();
            reservation.mark_pending_with_session(
                prepared.meta.transition_id,
                prepared.intent_bytes.clone(),
                prepared.candidate_bytes.clone(),
            )?;
            Ok(prepared)
        })
        .unwrap()
    }

    fn promote_and_insert_rvor(
        host: &HostLab,
        object_digest: [u8; 32],
        prepared: &PipelineResult,
    ) -> Vec<u8> {
        host.with_lease(|lease| lease.promote_pending(object_digest))
            .unwrap();
        let rvor = materialize_rvor(&prepared.intent_bytes).unwrap().rvor_bytes;
        host.with_lease(|lease| lease.insert_rvor(prepared.meta.transition_id, rvor.clone()))
            .unwrap();
        rvor
    }

    fn conflict_repair_intent(original_intent: &[u8], now_ms: u64) -> PipelineResult {
        // A different state at the intent's own generation is a real conflict.
        let mut conflict = decode_rvfb1(&before_bytes()).unwrap();
        conflict.prefix.auth_root[0] ^= 1;
        let conflict_live = encode_rvfb1(&conflict).unwrap();
        terminalize_conflict(&conflict_live, original_intent, now_ms).unwrap()
    }

    #[test]
    fn happy_path_activates_only_after_clear_then_releases() {
        let host = HostLab::new();
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, 900_000_000, 1_000);
        let pending = host.dedup_record(OBJECT).unwrap();
        assert_eq!(pending.state, DedupState::Pending);
        assert_eq!(pending.transition_id, Some(prepared.meta.transition_id));

        let promoted = host
            .with_lease(|lease| lease.promote_pending(OBJECT))
            .unwrap();
        let promoted_state = decode_rvfb1(&promoted).unwrap();
        assert_eq!(promoted_state.prefix.pending_phase, 2);
        assert_ne!(promoted_state.prefix.flags & FLAG_AWAITING_COMPLETE, 0);

        let rvor = materialize_rvor(&prepared.intent_bytes).unwrap().rvor_bytes;
        host.with_lease(|lease| lease.insert_rvor(prepared.meta.transition_id, rvor.clone()))
            .unwrap();
        assert_eq!(
            host.dedup_record(OBJECT).unwrap().state,
            DedupState::Pending
        );

        let cleared = host
            .with_lease(|lease| lease.clear_barrier(OBJECT, 1_001))
            .unwrap();
        assert_eq!(decode_rvfb1(&cleared).unwrap().prefix.pending_phase, 0);
        assert_eq!(host.dedup_record(OBJECT).unwrap().state, DedupState::Active);

        let released = host.with_lease(|lease| lease.try_release(OBJECT)).unwrap();
        assert_eq!(released, decode_rvor1(&rvor).unwrap().outputs_bytes);
    }

    #[test]
    fn pending_with_rvor_refuses_release_until_clear() {
        let host = HostLab::new();
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, 900_000_000, 2_000);
        let rvor = promote_and_insert_rvor(&host, OBJECT, &prepared);

        assert_eq!(
            host.with_lease(|lease| lease.try_release(OBJECT))
                .unwrap_err(),
            HostLabError::NotActive
        );
        assert_eq!(
            host.dedup_record(OBJECT).unwrap().state,
            DedupState::Pending
        );

        host.with_lease(|lease| lease.clear_barrier(OBJECT, 2_001))
            .unwrap();
        assert_eq!(
            host.with_lease(|lease| lease.try_release(OBJECT)).unwrap(),
            decode_rvor1(&rvor).unwrap().outputs_bytes
        );
    }

    #[test]
    fn reservation_guard_drop_cancel_and_owner_cas_are_safe() {
        let host = HostLab::new();
        host.with_lease(|lease| {
            let reservation = lease.try_reserve(OBJECT, OWNER, 10_000)?;
            drop(reservation);
            Ok(())
        })
        .unwrap();
        assert!(host.dedup_record(OBJECT).is_none());

        host.with_lease(|lease| {
            let mut reservation = lease.try_reserve(OBJECT, OWNER, 10_000)?;
            assert!(!reservation.cancel_with_token(OWNER + 1));
            assert!(reservation.cancel());
            Ok(())
        })
        .unwrap();
        assert!(host.dedup_record(OBJECT).is_none());

        host.with_lease(|lease| {
            let reservation = lease.try_reserve(OBJECT, OWNER, 10_000)?;
            std::mem::forget(reservation);
            Ok(())
        })
        .unwrap();
        assert_eq!(host.drop_all_reserved(), 1);
        assert!(host.dedup_record(OBJECT).is_none());
    }

    #[test]
    fn concurrent_dual_miss_allows_exactly_one_transition() {
        let host = HostLab::new();
        let start = Arc::new(Barrier::new(3));
        let transition_calls = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();

        for owner in [11_u64, 22_u64] {
            let host = host.clone();
            let start = Arc::clone(&start);
            let transition_calls = Arc::clone(&transition_calls);
            threads.push(thread::spawn(move || {
                start.wait();
                host.with_lease(|lease| {
                    let reservation = match lease.try_reserve(OBJECT, owner, 90_000) {
                        Ok(reservation) => reservation,
                        Err(HostLabError::DedupConflict(_)) => return Ok(false),
                        Err(error) => return Err(error),
                    };
                    transition_calls.fetch_add(1, Ordering::SeqCst);
                    let mut crypto = LabCrypto::default();
                    let prepared = transition_prepare(
                        &before_bytes(),
                        &send_input_bytes(),
                        &env_bytes(3_000),
                        &mut crypto,
                    )
                    .unwrap();
                    reservation.mark_pending_with_session(
                        prepared.meta.transition_id,
                        prepared.intent_bytes,
                        prepared.candidate_bytes,
                    )?;
                    Ok(true)
                })
                .unwrap()
            }));
        }

        start.wait();
        let wins = threads
            .into_iter()
            .map(|handle| handle.join().unwrap() as usize)
            .sum::<usize>();
        assert_eq!(wins, 1);
        assert_eq!(transition_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            host.dedup_record(OBJECT).unwrap().state,
            DedupState::Pending
        );
    }

    #[test]
    fn joint_gc_waits_for_endpoint_inclusive_horizon_then_deletes_both() {
        let host = HostLab::new();
        let now_ms = 1_000;
        let endpoint_expiry = now_ms + BRAID_RVOR_TTL_MS + 10_000;
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, endpoint_expiry, now_ms);
        let transition_id = prepared.meta.transition_id;
        promote_and_insert_rvor(&host, OBJECT, &prepared);
        host.with_lease(|lease| lease.clear_barrier(OBJECT, now_ms + 1))
            .unwrap();
        let blocked = host
            .with_lease(|lease| lease.quarantine_or_repair_block(OBJECT, transition_id, now_ms))
            .unwrap();
        assert_eq!(blocked.horizon_ms, Some(endpoint_expiry));
        assert!(host.has_rvqi(transition_id));
        let same_rvqi = encode_rvqi1(&Rvqi1 {
            transition_id,
            object_digest: OBJECT,
            status: RVQI1_STATUS_QUARANTINED,
            cas_tag: blocked.cas_generation,
        })
        .unwrap();
        host.with_lease(|lease| lease.insert_rvqi(transition_id, same_rvqi))
            .unwrap();
        let different_rvqi = encode_rvqi1(&Rvqi1 {
            transition_id,
            object_digest: OBJECT,
            status: RVQI1_STATUS_QUARANTINED,
            cas_tag: blocked.cas_generation + 1,
        })
        .unwrap();
        assert!(host
            .with_lease(|lease| lease.insert_rvqi(transition_id, different_rvqi))
            .is_err());

        let repair = conflict_repair_intent(&prepared.intent_bytes, now_ms + 2);
        let repair_tid = repair.meta.transition_id;
        host.with_lease(|lease| {
            lease.record_repair_successor(transition_id, repair.intent_bytes.clone())
        })
        .unwrap();

        assert_eq!(
            host.with_lease(|lease| {
                lease.joint_gc(OBJECT, endpoint_expiry - 1, blocked.cas_generation)
            })
            .unwrap_err(),
            HostLabError::HorizonNotReached
        );
        assert_eq!(
            host.dedup_record(OBJECT).unwrap().state,
            DedupState::Blocked
        );
        assert!(host.has_rvqi(transition_id));

        assert_eq!(
            host.with_lease(|lease| {
                lease.joint_gc(OBJECT, endpoint_expiry, blocked.cas_generation)
            })
            .unwrap_err(),
            HostLabError::RvorStillRetained
        );
        host.with_lease(|lease| lease.evict_rvor(transition_id, endpoint_expiry))
            .unwrap();

        assert_eq!(
            host.with_lease(|lease| {
                lease.joint_gc(OBJECT, endpoint_expiry, blocked.cas_generation)
            })
            .unwrap_err(),
            HostLabError::RepairNotReady
        );

        let repair_rvor = materialize_rvor(&repair.intent_bytes).unwrap().rvor_bytes;
        host.with_lease(|lease| lease.insert_rvor(repair_tid, repair_rvor))
            .unwrap();
        host.with_lease(|lease| lease.joint_gc(OBJECT, endpoint_expiry, blocked.cas_generation))
            .unwrap();
        assert!(host.dedup_record(OBJECT).is_none());
        assert!(!host.has_rvqi(transition_id));
    }

    #[test]
    fn joint_gc_rejects_forged_repair_rvor_and_wrong_predecessor() {
        let host = HostLab::new();
        let now_ms = 2_000;
        let endpoint_expiry = now_ms + BRAID_RVOR_TTL_MS + 10_000;
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, endpoint_expiry, now_ms);
        let transition_id = prepared.meta.transition_id;
        promote_and_insert_rvor(&host, OBJECT, &prepared);
        host.with_lease(|lease| lease.clear_barrier(OBJECT, now_ms + 1))
            .unwrap();
        let blocked = host
            .with_lease(|lease| lease.quarantine_or_repair_block(OBJECT, transition_id, now_ms))
            .unwrap();
        host.with_lease(|lease| lease.evict_rvor(transition_id, endpoint_expiry))
            .unwrap();

        let repair = conflict_repair_intent(&prepared.intent_bytes, now_ms + 2);
        let repair_tid = repair.meta.transition_id;
        let repair_rvor = materialize_rvor(&repair.intent_bytes).unwrap().rvor_bytes;

        // Wrong predecessor: repair input digest binds only to the original transition.
        let other_object = [0xB1; 32];
        let other_tid = [0xCD; 32];
        host.with_lease(|lease| {
            lease
                .try_reserve(other_object, OWNER + 1, endpoint_expiry)?
                .mark_pending(other_tid)
        })
        .unwrap();
        host.with_lease(|lease| lease.quarantine_or_repair_block(other_object, other_tid, now_ms))
            .unwrap();
        assert!(matches!(
            host.with_lease(|lease| {
                lease.record_repair_successor(other_tid, repair.intent_bytes.clone())
            }),
            Err(HostLabError::Pipeline(_))
        ));

        host.with_lease(|lease| {
            lease.record_repair_successor(transition_id, repair.intent_bytes.clone())
        })
        .unwrap();

        // Forged output digest: REPAIR-shaped RVOR that does not materialize from intent.
        let mut forged = decode_rvor1(&repair_rvor).unwrap();
        forged.output_digest[0] ^= 0xFF;
        let forged_bytes = encode_rvor1(&forged).unwrap();
        assert!(matches!(
            host.with_lease(|lease| lease.insert_rvor(repair_tid, forged_bytes)),
            Err(HostLabError::Pipeline(_))
        ));

        // Caller-built REPAIR blob (no retained repair intent for this successor) leaves GC blocked.
        let orphan = encode_rvor1(&Rvor1 {
            transition_id: [0x67; 32],
            object_digest: [0; 32],
            execution_digest: [0x71; 32],
            input_digest: [0x72; 32],
            output_digest: [0x73; 32],
            retention_origin_ms: now_ms,
            retention_expiry_ms: endpoint_expiry + 1,
            flags: RVOR1_FLAG_REPAIR,
            outputs_bytes: encode_empty_rvbo1(),
        })
        .unwrap();
        host.with_lease(|lease| lease.insert_rvor([0x67; 32], orphan))
            .unwrap();
        assert_eq!(
            host.with_lease(|lease| {
                lease.joint_gc(OBJECT, endpoint_expiry, blocked.cas_generation)
            })
            .unwrap_err(),
            HostLabError::RepairNotReady
        );

        // Exact materialized RVOR from the retained repair intent authorizes GC.
        host.with_lease(|lease| lease.insert_rvor(repair_tid, repair_rvor))
            .unwrap();
        host.with_lease(|lease| lease.joint_gc(OBJECT, endpoint_expiry, blocked.cas_generation))
            .unwrap();
        assert!(host.dedup_record(OBJECT).is_none());
    }

    #[test]
    fn reservation_rejects_intent_object_digest_mismatch() {
        let host = HostLab::new();
        let reserved = [0xA5; 32];
        host.with_lease(|lease| {
            let reservation = lease.try_reserve(reserved, OWNER, 10_000)?;
            let mut crypto = LabCrypto::default();
            let prepared = transition_prepare(
                &before_bytes(),
                &send_input_bytes(),
                &env_bytes(4_200),
                &mut crypto,
            )
            .unwrap();
            let intent = decode_rvbj1(&prepared.intent_bytes).unwrap();
            assert_eq!(intent.header.object_digest, [0; 32]);
            assert_ne!(intent.header.object_digest, reserved);
            assert_eq!(
                reservation
                    .mark_pending_with_session(
                        prepared.meta.transition_id,
                        prepared.intent_bytes,
                        prepared.candidate_bytes,
                    )
                    .unwrap_err(),
                HostLabError::TransitionMismatch
            );
            Ok(())
        })
        .unwrap();
        assert!(host.dedup_record(reserved).is_none());
    }

    #[test]
    fn pending_rejects_standalone_rvqi_insert() {
        let host = HostLab::new();
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, 900_000_000, 4_000);
        promote_and_insert_rvor(&host, OBJECT, &prepared);
        let rvqi = encode_rvqi1(&Rvqi1 {
            transition_id: prepared.meta.transition_id,
            object_digest: OBJECT,
            status: RVQI1_STATUS_QUARANTINED,
            cas_tag: 77,
        })
        .unwrap();

        assert_eq!(
            host.with_lease(|lease| lease.insert_rvqi(prepared.meta.transition_id, rvqi))
                .unwrap_err(),
            HostLabError::WrongState
        );
        assert_eq!(
            host.dedup_record(OBJECT).unwrap().state,
            DedupState::Pending
        );
        assert!(!host.has_rvqi(prepared.meta.transition_id));
    }

    #[test]
    fn clear_barrier_after_quarantine_barrier_refuses_clear() {
        let host = HostLab::new();
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, 900_000_000, 4_100);
        promote_and_insert_rvor(&host, OBJECT, &prepared);
        let blocked = host
            .with_lease(|lease| {
                lease.quarantine_or_repair_block(OBJECT, prepared.meta.transition_id, 4_100)
            })
            .unwrap();
        assert_eq!(blocked.state, DedupState::Blocked);
        assert!(host.has_rvqi(prepared.meta.transition_id));
        let calls_before = host.clear_call_count();

        assert_eq!(
            host.with_lease(|lease| lease.clear_barrier(OBJECT, 4_101))
                .unwrap_err(),
            HostLabError::WrongState
        );
        assert_eq!(host.clear_call_count(), calls_before);
        assert_eq!(
            host.dedup_record(OBJECT).unwrap().state,
            DedupState::Blocked
        );
        assert_eq!(
            decode_rvfb1(&host.live_state(OBJECT).unwrap())
                .unwrap()
                .prefix
                .pending_phase,
            2
        );
    }

    #[test]
    fn active_mapping_rejects_standalone_rvqi_insert() {
        let host = HostLab::new();
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, 900_000_000, 4_500);
        promote_and_insert_rvor(&host, OBJECT, &prepared);
        host.with_lease(|lease| lease.clear_barrier(OBJECT, 4_501))
            .unwrap();
        let rvqi = encode_rvqi1(&Rvqi1 {
            transition_id: prepared.meta.transition_id,
            object_digest: OBJECT,
            status: RVQI1_STATUS_QUARANTINED,
            cas_tag: 88,
        })
        .unwrap();

        assert_eq!(
            host.with_lease(|lease| lease.insert_rvqi(prepared.meta.transition_id, rvqi))
                .unwrap_err(),
            HostLabError::WrongState
        );
        assert_eq!(host.dedup_record(OBJECT).unwrap().state, DedupState::Active);
        assert!(host
            .with_lease(|lease| Ok(lease.releasable(prepared.meta.transition_id)))
            .unwrap());
    }

    #[test]
    fn blocked_rvor_is_evicted_legally_before_joint_gc() {
        let host = HostLab::new();
        let endpoint_expiry = 900_000_000;
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, endpoint_expiry, 5_500);
        promote_and_insert_rvor(&host, OBJECT, &prepared);
        host.with_lease(|lease| lease.clear_barrier(OBJECT, 5_501))
            .unwrap();
        let blocked = host
            .with_lease(|lease| {
                lease.quarantine_or_repair_block(OBJECT, prepared.meta.transition_id, 6_000)
            })
            .unwrap();
        let horizon_ms = blocked.horizon_ms.unwrap();

        assert_eq!(
            host.with_lease(|lease| { lease.joint_gc(OBJECT, horizon_ms, blocked.cas_generation) })
                .unwrap_err(),
            HostLabError::RvorStillRetained
        );
        host.with_lease(|lease| lease.evict_rvor(prepared.meta.transition_id, horizon_ms))
            .unwrap();
        assert!(!host.has_rvor(prepared.meta.transition_id));

        host.with_lease(|lease| lease.joint_gc(OBJECT, horizon_ms, blocked.cas_generation))
            .unwrap();
        assert!(host.dedup_record(OBJECT).is_none());
        assert!(!host.has_rvqi(prepared.meta.transition_id));
    }

    #[test]
    fn gc_reclaims_live_state_so_the_digest_can_be_readmitted() {
        let host = HostLab::new();
        let endpoint_expiry = 900_000_000;
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, endpoint_expiry, 5_500);
        promote_and_insert_rvor(&host, OBJECT, &prepared);
        host.with_lease(|lease| lease.clear_barrier(OBJECT, 5_501))
            .unwrap();
        let blocked = host
            .with_lease(|lease| {
                lease.quarantine_or_repair_block(OBJECT, prepared.meta.transition_id, 6_000)
            })
            .unwrap();
        let horizon_ms = blocked.horizon_ms.unwrap();
        host.with_lease(|lease| lease.evict_rvor(prepared.meta.transition_id, horizon_ms))
            .unwrap();
        assert!(host.live_state(OBJECT).is_some());
        host.with_lease(|lease| lease.joint_gc(OBJECT, horizon_ms, blocked.cas_generation))
            .unwrap();
        assert!(host.dedup_record(OBJECT).is_none());
        // The stale per-object session state is gone with the mapping ...
        assert!(host.live_state(OBJECT).is_none());

        // ... so the same digest is admitted again instead of `StoreConflict`.
        let again = prepare_after_reservation(&host, OBJECT, OWNER + 1, endpoint_expiry, 9_000);
        assert_ne!(again.meta.transition_id, prepared.meta.transition_id);
        assert_eq!(
            host.dedup_record(OBJECT).unwrap().transition_id,
            Some(again.meta.transition_id)
        );
        assert!(host.live_state(OBJECT).is_some());
    }

    #[test]
    fn debug_output_never_prints_session_state() {
        let host = HostLab::new();
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, 900_000_000, 1_000);
        let live = host.live_state(OBJECT).unwrap();
        let shown = format!("{host:?}");
        assert!(shown.contains("live_states: 1"), "{shown}");
        assert!(shown.contains("journals: 1"), "{shown}");
        // Raw byte lists (`[82, 86, ...]`) of the state / journal never appear.
        let state_prefix = format!("{:?}", &live[..16]);
        let intent_prefix = format!("{:?}", &prepared.intent_bytes[..16]);
        let shown_state = state_prefix.trim_matches(|c| c == '[' || c == ']');
        let shown_intent = intent_prefix.trim_matches(|c| c == '[' || c == ']');
        assert!(!shown.contains(shown_state), "{shown}");
        assert!(!shown.contains(shown_intent), "{shown}");
        let journal = host
            .lock_state()
            .journals
            .get(&prepared.meta.transition_id)
            .cloned()
            .unwrap();
        let shown = format!("{journal:?}");
        assert!(shown.contains("intent_len"), "{shown}");
        assert!(!shown.contains(shown_intent), "{shown}");
    }

    #[test]
    fn active_re_release_returns_identical_rvor_outputs() {
        let host = HostLab::new();
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, 900_000_000, 5_000);
        let rvor = promote_and_insert_rvor(&host, OBJECT, &prepared);
        host.with_lease(|lease| lease.clear_barrier(OBJECT, 5_001))
            .unwrap();

        let first = host.with_lease(|lease| lease.try_release(OBJECT)).unwrap();
        let second = host.with_lease(|lease| lease.try_release(OBJECT)).unwrap();
        assert_eq!(first, decode_rvor1(&rvor).unwrap().outputs_bytes);
        assert_eq!(second, first);
    }

    #[test]
    fn duplicate_during_pending_plus_rvor_resumes_clear_not_release() {
        // Exit §9: duplicate while PENDING+RVOR must resume clear/recover only —
        // never release outputs and never start a second transition.
        let host = HostLab::new();
        let prepared = prepare_after_reservation(&host, OBJECT, OWNER, 900_000_000, 7_000);
        let rvor = promote_and_insert_rvor(&host, OBJECT, &prepared);
        let clear_before = host.clear_call_count();

        let reserve_err = host
            .with_lease(|lease| match lease.try_reserve(OBJECT, OWNER + 9, 90_000) {
                Ok(reservation) => {
                    drop(reservation);
                    Err(HostLabError::WrongState)
                }
                Err(error) => Ok(error),
            })
            .unwrap();
        assert_eq!(
            reserve_err,
            HostLabError::DedupConflict(DedupState::Pending)
        );
        assert_eq!(
            host.with_lease(|lease| lease.try_release(OBJECT))
                .unwrap_err(),
            HostLabError::NotActive
        );
        assert_eq!(host.clear_call_count(), clear_before);
        assert_eq!(
            host.dedup_record(OBJECT).unwrap().state,
            DedupState::Pending
        );

        let cleared = host
            .with_lease(|lease| lease.clear_barrier(OBJECT, 7_001))
            .unwrap();
        assert_eq!(decode_rvfb1(&cleared).unwrap().prefix.pending_phase, 0);
        assert_eq!(host.dedup_record(OBJECT).unwrap().state, DedupState::Active);
        assert_eq!(host.clear_call_count(), clear_before + 1);
        assert_eq!(
            host.with_lease(|lease| lease.try_release(OBJECT)).unwrap(),
            decode_rvor1(&rvor).unwrap().outputs_bytes
        );
    }
}
