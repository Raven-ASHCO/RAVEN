//! libp2p carrier (P3: direct TCP/QUIC, Circuit Relay v2, DCUtR) lab gate.
//!
//! Independent of the four global `PRODUCTION_ENABLED` tripwires, of
//! [`crate::LAN_DIRECT_PRODUCTION_ENABLED`], of
//! [`crate::INTERNET_DIRECT_PRODUCTION_ENABLED`] and of the separate
//! `raven-swarm` NAT experiment (`PRODUCTION_NAT_CONNECTIVITY_ENABLED`). Stays
//! false until a founder GO after the relay and DCUtR physical rows (R7b, R8)
//! and the waiver (docs/WAIVER_P2P_RELAY_DRAFT.md). With it off a release
//! build never listens, dials, reserves or advertises libp2p. Not a WAN /
//! multi-NAT claim.

/// Hard enable for the libp2p carrier and the relay role.
/// Lab smoke uses debug `RAVEN_LAB_TEST_A=1` instead of flipping this.
pub const P2P_PRODUCTION_ENABLED: bool = false;

/// The one refusal every p2p entry point (service host, relay, dial, IPC,
/// `raven send --carrier p2p`) prints while the gate is closed.
pub const P2P_HOLD: &str = "P2P_HOLD: the libp2p carrier (relay + hole punching) is lab-only \
    (debug RAVEN_LAB_TEST_A=1); P2P_PRODUCTION_ENABLED=false; localhost ≠ WAN Proven";

/// Live libp2p carrier: compile-time slice gate or debug lab.
pub fn p2p_live_enabled() -> bool {
    P2P_PRODUCTION_ENABLED || crate::pair_init::lab_test_a_enabled()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_flag_stays_false() {
        const {
            assert!(!P2P_PRODUCTION_ENABLED);
            assert!(!crate::INTERNET_DIRECT_PRODUCTION_ENABLED);
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
        assert!(!p2p_live_enabled());
        assert!(!crate::internet_direct_live_enabled());
        assert!(!crate::pair_init::live_enabled());
        assert!(!crate::indexed_session_store::live_enabled());
        assert!(!crate::prekey_lifecycle::live_enabled());
        assert!(!crate::atsam_indexed_session::live_enabled());
    }

    #[test]
    fn hold_text_names_the_flag_and_the_lab_unlock() {
        assert!(P2P_HOLD.starts_with("P2P_HOLD:"));
        assert!(P2P_HOLD.contains("P2P_PRODUCTION_ENABLED=false"));
        assert!(P2P_HOLD.contains("RAVEN_LAB_TEST_A=1"));
    }
}
