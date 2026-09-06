//! InternetTransport indexed-delivery lab gate.
//!
//! Independent of the four global `PRODUCTION_ENABLED` tripwires and of
//! [`crate::LAN_DIRECT_PRODUCTION_ENABLED`]. Stays false until a founder GO
//! after the localhost indexed smoke is green. Not a WAN / multi-NAT claim.

/// Hard enable for indexed InternetTransport (RIH1 + PairInit + sealed ACK).
/// Lab smoke uses debug `RAVEN_LAB_TEST_A=1` instead of flipping this.
pub const INTERNET_DIRECT_PRODUCTION_ENABLED: bool = false;

/// Live InternetTransport indexed path: compile-time slice gate or debug lab.
pub fn internet_direct_live_enabled() -> bool {
    INTERNET_DIRECT_PRODUCTION_ENABLED || crate::pair_init::lab_test_a_enabled()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_flag_stays_false() {
        const {
            assert!(!INTERNET_DIRECT_PRODUCTION_ENABLED);
            assert!(!crate::pair_init::PRODUCTION_ENABLED);
            assert!(!crate::INDEXED_SESSION_STORE_PRODUCTION_ENABLED);
            assert!(!crate::PREKEY_LIFECYCLE_PRODUCTION_ENABLED);
            assert!(!crate::atsam_indexed_session::PRODUCTION_ENABLED);
        }
    }

    #[test]
    fn gate_does_not_open_generic_live_enabled() {
        if crate::pair_init::lab_test_a_enabled() {
            return;
        }
        assert!(!internet_direct_live_enabled());
        assert!(!crate::pair_init::live_enabled());
        assert!(!crate::indexed_session_store::live_enabled());
        assert!(!crate::prekey_lifecycle::live_enabled());
        assert!(!crate::atsam_indexed_session::live_enabled());
    }
}
