//! Full Braid Slice 2 — lab-only module (`full-braid-lab`).
//!
//! The `design §x` comments in this module cite the Slice 2 design document
//! (`2026-08-16-full-braid-slice2-design.md`, Rev20). That file is NOT tracked
//! in this repository (`docs/superpowers/specs/` only holds the iOS redesign
//! spec), so those section numbers cannot be checked here. The in-repo
//! normative sources are `protocol/ATSAM_HYBRID_RATCHET_V2.md` (Revision 10,
//! §5.2 Full Braid lab rules and §6.3 SCKA KDF tables), the Python reference in
//! `protocol/reference/raven_protocol/full_braid_*.py`, and the frozen
//! `shared-vectors/rvn1/atsam/full_braid_*.json` / `tr_braid_*.json` vectors.
//! Task 0 pin audit MUST pass before state-machine work.

#![cfg(feature = "full-braid-lab")]

pub mod agent;
pub mod authenticator;
pub mod constants;
pub mod digest;
#[cfg(test)]
mod exit_matrix;
pub mod ffi;
#[cfg(test)]
mod full_braid_vectors;
pub mod host_lab;
pub mod init;
pub mod pipeline;
#[cfg(test)]
mod pipeline_soak;
pub mod spqr_codec;
pub mod spqr_pin_audit;
pub mod state_codec;
pub mod tr_confirm;
pub mod transition;
pub mod wire_rvbc1;
pub mod wire_rvbe1;
pub mod wire_rvbi1;
pub mod wire_rvbj1;
pub mod wire_rvbm1;
pub mod wire_rvbo1;
pub mod wire_rvch1;
pub mod wire_rvft1;
pub mod wire_rvor1;
pub mod wire_rvqi1;
pub mod wire_util;

pub use agent::BraidAgent;
pub use constants::*;
pub use spqr_codec::{
    wire_needs_decoder, BraidDecoder, BraidEncoder, SpqrCodecError, WIRE_CT1, WIRE_CT1_ACK,
    WIRE_CT2, WIRE_EK, WIRE_EK_CT1_ACK, WIRE_HDR, WIRE_NONE,
};
pub use spqr_pin_audit::{
    CW, FIXED_BASE, INBOUND_BUDGET, N_CT1, N_CT2, N_EK, N_HDR, SPQR_GIT_REV, SPQR_VERSION,
};
pub use state_codec::{
    ActiveSend, BraidObject, InboundChunk, InboundSet, ReplayRecord, Rvfb1Prefix, Rvfb1State,
    TlvEntry,
};
pub use transition::{
    transition, BraidCrypto, Disposition, LabCrypto, RejectReason, TransitionMeta, TransitionResult,
};
pub use wire_rvft1::{EcSkippedEntry, Rvft1, SckaChainEntry, SckaSkippedEntry};
