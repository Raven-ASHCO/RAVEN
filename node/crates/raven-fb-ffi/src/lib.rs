//! Lab-only staticlib binder for Hybrid Ratchet V2 Full Braid (`raven_fb_*`).
//!
//! The durable C ABI lives in `raven-core` (`hybrid_ratchet_v2_full_braid::ffi`).
//! This crate archives those symbols into a linkable Debug-only static library
//! and exports size helpers for the Swift XCTest binder.
//!
//! **Release and App Store builds must not link this crate.**

#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(not(debug_assertions))]
compile_error!("raven-fb-ffi is lab-only and must not be linked in Release/App Store builds");

#[cfg(all(debug_assertions, feature = "lab"))]
mod lab {
    use raven_core::hybrid_ratchet_v2_full_braid::constants::{
        BRAID_MAX_CANONICAL_STATE_BYTES, BRAID_MAX_RVOR_RECORD_BYTES, MAX_RVBO1, RVBJ1_HEADER_LEN,
    };
    use raven_core::hybrid_ratchet_v2_full_braid::ffi::{
        raven_fb_clear_pending_measure, raven_fb_clear_pending_write, raven_fb_init_measure,
        raven_fb_init_write, raven_fb_promote_measure, raven_fb_promote_write,
        raven_fb_recover_measure, raven_fb_recover_write, raven_fb_rvor_materialize_measure,
        raven_fb_rvor_materialize_write, raven_fb_terminalize_conflict_measure,
        raven_fb_terminalize_conflict_write, raven_fb_terminalize_expired_measure,
        raven_fb_terminalize_expired_write, raven_fb_transition_measure, raven_fb_transition_write,
    };
    use raven_core::hybrid_ratchet_v2_full_braid::pipeline::MAX_RVBJ1;

    pub use raven_core::hybrid_ratchet_v2_full_braid::ffi::{RavenFbResultMeta, RavenFbSizes};

    pub const RAVEN_FB_OK: i32 = 0;
    pub const RAVEN_FB_ERR_NEED_CAPACITY: i32 = 1;
    pub const RAVEN_FB_ERR_PARSE: i32 = 2;
    pub const RAVEN_FB_ERR_EPOCH: i32 = 3;
    pub const RAVEN_FB_ERR_CAS: i32 = 8;
    pub const RAVEN_FB_ERR_TERMINAL_STATE_OP: i32 = 9;
    pub const RAVEN_FB_ERR_INTERNAL: i32 = 10;

    const _: [(); 16] = [(); core::mem::size_of::<RavenFbSizes>()];
    const _: [(); 64] = [(); core::mem::size_of::<RavenFbResultMeta>()];
    const _: [(); 279_055] = [(); RVBJ1_HEADER_LEN + BRAID_MAX_CANONICAL_STATE_BYTES + MAX_RVBO1];
    const _: [(); 279_055] = [(); MAX_RVBJ1];

    #[inline(never)]
    #[no_mangle]
    pub extern "C" fn raven_fb_ffi_keep_alive() -> usize {
        let mut acc = 0usize;
        acc ^= raven_fb_init_measure as *const () as usize;
        acc ^= raven_fb_init_write as *const () as usize;
        acc ^= raven_fb_transition_measure as *const () as usize;
        acc ^= raven_fb_transition_write as *const () as usize;
        acc ^= raven_fb_promote_measure as *const () as usize;
        acc ^= raven_fb_promote_write as *const () as usize;
        acc ^= raven_fb_rvor_materialize_measure as *const () as usize;
        acc ^= raven_fb_rvor_materialize_write as *const () as usize;
        acc ^= raven_fb_clear_pending_measure as *const () as usize;
        acc ^= raven_fb_clear_pending_write as *const () as usize;
        acc ^= raven_fb_recover_measure as *const () as usize;
        acc ^= raven_fb_recover_write as *const () as usize;
        acc ^= raven_fb_terminalize_conflict_measure as *const () as usize;
        acc ^= raven_fb_terminalize_conflict_write as *const () as usize;
        acc ^= raven_fb_terminalize_expired_measure as *const () as usize;
        acc ^= raven_fb_terminalize_expired_write as *const () as usize;
        acc
    }

    #[no_mangle]
    pub extern "C" fn raven_fb_len_sizes() -> usize {
        core::mem::size_of::<RavenFbSizes>()
    }

    #[no_mangle]
    pub extern "C" fn raven_fb_len_meta() -> usize {
        core::mem::size_of::<RavenFbResultMeta>()
    }

    #[no_mangle]
    pub extern "C" fn raven_fb_max_state() -> usize {
        BRAID_MAX_CANONICAL_STATE_BYTES
    }

    #[no_mangle]
    pub extern "C" fn raven_fb_max_rvbo1() -> usize {
        MAX_RVBO1
    }

    #[no_mangle]
    pub extern "C" fn raven_fb_max_rvbj1() -> usize {
        MAX_RVBJ1
    }

    #[no_mangle]
    pub extern "C" fn raven_fb_max_rvor_record() -> usize {
        BRAID_MAX_RVOR_RECORD_BYTES
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use raven_core::hybrid_ratchet_v2_full_braid::constants::{
            ERR_CAS, ERR_EPOCH, ERR_INTERNAL, ERR_NEED_CAPACITY, ERR_OK, ERR_PARSE,
            ERR_TERMINAL_STATE_OP,
        };

        #[test]
        fn keep_alive_is_nonzero() {
            assert_ne!(raven_fb_ffi_keep_alive(), 0);
        }

        #[test]
        fn exported_layout_constants() {
            assert_eq!(raven_fb_len_sizes(), 16);
            assert_eq!(raven_fb_len_meta(), 64);
            assert_eq!(raven_fb_max_state(), 262_144);
            assert_eq!(raven_fb_max_rvbo1(), 16_545);
            assert_eq!(raven_fb_max_rvbj1(), 279_055);
            assert_eq!(raven_fb_max_rvor_record(), 16_741);
        }

        /// The Swift binder sizes its caller-owned buffers from the header
        /// macros, so they must track the raven-core constants (expected values
        /// come from raven-core, not literals).
        #[test]
        fn c_header_matches_rust_constants() {
            let header = include_str!("../include/raven_fb.h");
            for (name, value) in [
                ("RAVEN_FB_SIZES_LEN", core::mem::size_of::<RavenFbSizes>()),
                (
                    "RAVEN_FB_META_LEN",
                    core::mem::size_of::<RavenFbResultMeta>(),
                ),
                ("RAVEN_FB_MAX_STATE", BRAID_MAX_CANONICAL_STATE_BYTES),
                ("RAVEN_FB_MAX_RVBO1", MAX_RVBO1),
                ("RAVEN_FB_MAX_RVBJ1", MAX_RVBJ1),
                ("RAVEN_FB_MAX_RVOR_RECORD", BRAID_MAX_RVOR_RECORD_BYTES),
            ] {
                let needle = format!("#define {name} {value}\n");
                assert!(header.contains(&needle), "C header missing `{needle}`");
                // No second, stale definition of the same macro.
                assert_eq!(
                    header.matches(&format!("#define {name} ")).count(),
                    1,
                    "{name} defined more than once"
                );
            }
            for (name, value) in [
                ("RAVEN_FB_OK", RAVEN_FB_OK),
                ("RAVEN_FB_ERR_NEED_CAPACITY", RAVEN_FB_ERR_NEED_CAPACITY),
                ("RAVEN_FB_ERR_PARSE", RAVEN_FB_ERR_PARSE),
                ("RAVEN_FB_ERR_EPOCH", RAVEN_FB_ERR_EPOCH),
                ("RAVEN_FB_ERR_CAS", RAVEN_FB_ERR_CAS),
                (
                    "RAVEN_FB_ERR_TERMINAL_STATE_OP",
                    RAVEN_FB_ERR_TERMINAL_STATE_OP,
                ),
                ("RAVEN_FB_ERR_INTERNAL", RAVEN_FB_ERR_INTERNAL),
            ] {
                let needle = format!("    {name} = {value}");
                assert!(header.contains(&needle), "C header missing `{needle}`");
            }
            // The header error enum is the raven-core ABI code set.
            for (header_value, core_value) in [
                (RAVEN_FB_OK, ERR_OK),
                (RAVEN_FB_ERR_NEED_CAPACITY, ERR_NEED_CAPACITY),
                (RAVEN_FB_ERR_PARSE, ERR_PARSE),
                (RAVEN_FB_ERR_EPOCH, ERR_EPOCH),
                (RAVEN_FB_ERR_CAS, ERR_CAS),
                (RAVEN_FB_ERR_TERMINAL_STATE_OP, ERR_TERMINAL_STATE_OP),
                (RAVEN_FB_ERR_INTERNAL, ERR_INTERNAL),
            ] {
                assert_eq!(header_value, core_value);
            }
        }

        /// Field order and offsets of the two `#[repr(C)]` out-structs match
        /// the C declarations in the header.
        #[test]
        fn c_header_struct_layout_matches_rust() {
            use core::mem::offset_of;
            let header = include_str!("../include/raven_fb.h");
            let in_order = |fields: &[&str]| {
                let mut at = 0;
                for field in fields {
                    let found = header[at..]
                        .find(field)
                        .unwrap_or_else(|| panic!("C header lacks `{field}` in order"));
                    at += found + field.len();
                }
            };
            in_order(&[
                "typedef struct RavenFbSizes {",
                "uint32_t candidate_len;",
                "uint32_t outputs_len;",
                "uint32_t intent_len;",
                "uint32_t reserved0;",
                "} RavenFbSizes;",
            ]);
            assert_eq!(offset_of!(RavenFbSizes, candidate_len), 0);
            assert_eq!(offset_of!(RavenFbSizes, outputs_len), 4);
            assert_eq!(offset_of!(RavenFbSizes, intent_len), 8);
            assert_eq!(offset_of!(RavenFbSizes, reserved0), 12);
            in_order(&[
                "typedef struct RavenFbResultMeta {",
                "uint64_t sending_epoch;",
                "uint64_t receiving_epoch;",
                "uint64_t output_key_epoch;",
                "uint32_t flags;",
                "uint16_t terminal_reason;",
                "uint16_t pending_phase;",
                "uint8_t transition_id[32];",
                "} RavenFbResultMeta;",
            ]);
            assert_eq!(offset_of!(RavenFbResultMeta, sending_epoch), 0);
            assert_eq!(offset_of!(RavenFbResultMeta, receiving_epoch), 8);
            assert_eq!(offset_of!(RavenFbResultMeta, output_key_epoch), 16);
            assert_eq!(offset_of!(RavenFbResultMeta, flags), 24);
            assert_eq!(offset_of!(RavenFbResultMeta, terminal_reason), 28);
            assert_eq!(offset_of!(RavenFbResultMeta, pending_phase), 30);
            assert_eq!(offset_of!(RavenFbResultMeta, transition_id), 32);
        }

        /// Every exported `raven_fb_*` entry point is declared in the header.
        #[test]
        fn c_header_declares_every_exported_symbol() {
            let header = include_str!("../include/raven_fb.h");
            for name in [
                "raven_fb_ffi_keep_alive",
                "raven_fb_len_sizes",
                "raven_fb_len_meta",
                "raven_fb_max_state",
                "raven_fb_max_rvbo1",
                "raven_fb_max_rvbj1",
                "raven_fb_max_rvor_record",
                "raven_fb_init_measure",
                "raven_fb_init_write",
                "raven_fb_transition_measure",
                "raven_fb_transition_write",
                "raven_fb_promote_measure",
                "raven_fb_promote_write",
                "raven_fb_rvor_materialize_measure",
                "raven_fb_rvor_materialize_write",
                "raven_fb_clear_pending_measure",
                "raven_fb_clear_pending_write",
                "raven_fb_recover_measure",
                "raven_fb_recover_write",
                "raven_fb_terminalize_conflict_measure",
                "raven_fb_terminalize_conflict_write",
                "raven_fb_terminalize_expired_measure",
                "raven_fb_terminalize_expired_write",
            ] {
                assert!(
                    header.contains(&format!(" {name}(")),
                    "C header does not declare `{name}`"
                );
            }
        }
    }
}

#[cfg(all(debug_assertions, feature = "lab"))]
pub use lab::*;
