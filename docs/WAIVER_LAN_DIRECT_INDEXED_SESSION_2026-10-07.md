# Owner waiver: live LAN-direct slice on the indexed-session profile

| | |
|---|---|
| **Waiver ID** | `WAIVER-LAN-DIRECT-2026-10-07` |
| **Approver** | Ahmadreza, protocol owner |
| **Date** | 2026-10-07 |
| **Decision** | Keep the LAN-direct slice enabled in default and release builds under this waiver, instead of disabling it until an external review |
| **Review by** | 2027-01-07 (proposed; renew, narrow or withdraw on or before this date) |
| **Withdrawal** | Set `LAN_DIRECT_PRODUCTION_ENABLED = false` in `node/crates/raven-core/src/lan_gate.rs` |

## 1. Why a waiver is needed

[`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](../protocol/RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md)
§9.1 forbids a Release/production flag for the "LAN secure path" until **all**
of its holds pass. [`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](../protocol/ATSAM_INDEXED_SESSION_PROFILE_V1.md)
§7, [`RAVEN_PAIR_INIT_V1.md`](../protocol/RAVEN_PAIR_INIT_V1.md) §7-§8 and
[`ATSAM_PRIMITIVE_MAPPING_V1.md`](../protocol/ATSAM_PRIMITIVE_MAPPING_V1.md) §3
describe the profile and PairInit as production-disabled.

The code nevertheless ships the slice live:
`node/crates/raven-core/src/lan_gate.rs` sets
`LAN_DIRECT_PRODUCTION_ENABLED = true`, `raven-node service` always runs the
LAN listener, and `ash send` delivers over it without any lab flag. The October
2026 review found that the specs and the shipped behaviour contradicted each
other. This record resolves the contradiction explicitly instead of leaving it
implicit.

## 2. Scope (exactly what is covered)

Covered, and only in this combination:

- carrier: LAN direct TCP between two `raven-node` services, Noise XX with the
  Noise static key bound to the Raven identity, RLB1 offer;
- session establishment: PairInit V1 / PairResponse (suite 1: X25519 +
  ML-KEM-768 + HKDF-SHA256 + Ed25519), accepted only from local contacts;
- session profile: `ATSAM/indexed-session/v1`, RVNA1 `0x03` messages and sealed
  ACKs.

Not covered (all remain held under §9.1): Internet dial, relay, DCUtR, mailbox,
BLE mesh forwarding, store-and-forward bridge delivery, the Hybrid Ratchet v2 /
Full Braid lab, PairInit V2, and any rebranding of this slice as "Session V2".

## 3. Holds of umbrella §9.1 waived for this scope

| Hold | Status | Waived? |
|---|---|---|
| 1. Automated gates | Pass on macOS (CI matrix, smoke scripts, `final_serverless_proof.sh` 16/16) | Not waived |
| 2. All companions APPROVED | Not all approved | **Waived for this slice** |
| 3. Independent security review | Not done. An internal multi-reviewer review (2026-10) found no critical or high issue on this path; it is not an independent review | **Waived** |
| 4. Physical rows / failure matrix | Not run on physical multi-device setups | **Waived for LAN direct only** |
| 5. Indexed-session paths stay lab-gated | Indexed-session v1 is live on this slice | **Waived for this slice**; it MUST NOT be described as Session V2 |

## 4. Residual risks accepted

1. **No forward secrecy and no post-compromise security inside a session**
   (profile §2.4). Whoever obtains a device's session state can read every
   message of its live sessions in both directions. From this waiver on, this
   implementation initiates sessions that last **24 hours** (it still accepts
   up to 7 days from older peers). A real ratchet is planned in
   [`design/2026-10-ratchet-fs-pcs.md`](design/2026-10-ratchet-fs-pcs.md).
2. **No independent cryptographic review and no formal model** of PairInit and
   the session state machine.
3. **Device key equals identity key** (the device tier is collapsed, contrary to
   `RAVEN_IDENTITY_V1.md` §1). One compromised install compromises the
   identity; revocation cannot contain it. Planned in
   [`design/2026-10-per-device-keys.md`](design/2026-10-per-device-keys.md).
4. **No deniability.** PairInit, PairResponse, every envelope and every ACK are
   signed with the long-term key.
5. **Revocation is local only.** A peer that has not received a revocation keeps
   accepting the revoked device.
6. **Metadata.** PairInit is not encrypted by itself (it travels inside Noise on
   LAN); the outer signature identifies the sender to anyone holding candidate
   public keys.
7. **macOS Keychain behaviour.** ash and raven-node are separate code identities;
   the first use of each Keychain item by the other binary, and every rebuild of
   an unsigned binary, shows a permission dialog. Mitigated by a 3-second hint;
   planned in [`design/2026-10-daemon-owned-secrets.md`](design/2026-10-daemon-owned-secrets.md).
8. **Platform coverage.** Swift parity is not verified in this repository;
   Windows and Linux are compile- and lint-checked, not run.

## 5. Compensating controls in place

- Only contacts are accepted (`peer_is_trusted`), over a mutually authenticated
  Noise XX channel bound to the identity.
- Strict, fixed-length codecs; hybrid PQ root bound to the full signed
  transcript; strict Ed25519; X25519 small-order rejection; constant-time
  confirmation tag.
- Only RVNA1 `0x03` / suite 1 reaches the session path; the `0x7F` demo cipher
  cannot be built in release; there is no plaintext fallback.
- Random 96-bit AEAD nonces from the OS CSPRNG, unique per session (enforced in
  storage), and index reservation journaled before network handoff.
- ACKs require the session-bound device's inner and outer signatures, an
  outstanding row and replay checks, and must name the message being confirmed.
- Expired sessions and their roots are pruned.

## 6. Conditions

This waiver lapses, and the flag MUST be set back to `false`, if any of these
happens before it is renewed:

- a critical or high finding on the covered path is confirmed and not fixed;
- the slice is extended beyond the scope in §2 without a new waiver or review;
- the review-by date passes without renewal.
