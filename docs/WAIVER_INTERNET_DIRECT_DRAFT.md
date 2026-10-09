# DRAFT owner waiver: Internet direct with explicit addresses (transports P1)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file. `INTERNET_DIRECT_PRODUCTION_ENABLED` stays `false` until the owner signs
> a final copy (renamed to `docs/WAIVER_INTERNET_DIRECT_<date>.md`), the exit
> conditions in §7 are met, and the gate-flip change is applied as its own
> reviewed commit.

| | |
|---|---|
| **Waiver ID** | `WAIVER-INTERNET-DIRECT-<date>` (to be assigned on signature) |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md), whose §6 makes any scope extension without a new record a lapse condition |
| **Approver** | Ahmadreza, protocol owner (signature pending) |
| **Date** | pending |
| **Decision** | Enable Internet direct (explicit `host:port` routes, contacts only) in default and release builds under this waiver, instead of waiting for an independent review |
| **Review by** | 3 months after signature at the latest |
| **Withdrawal** | Set `INTERNET_DIRECT_PRODUCTION_ENABLED = false` in `node/crates/raven-core/src/internet_gate.rs` |
| **Design** | [`design/2026-10-transports-internet-mesh-bridge.md`](design/2026-10-transports-internet-mesh-bridge.md) §3.1-§3.4, §3.6-§3.7, §5 (row P1), §7.2 |

## 1. Why a waiver is needed

Umbrella §9.1 ([`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](../protocol/RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md))
holds every carrier until all of its holds pass. The LAN waiver covers LAN
direct only and lists "Internet dial" as not covered (its §2). The Internet
direct carrier (`raven/internet/v1` Noise XX + RIH1 hello) has run as a lab
path behind `INTERNET_DIRECT_PRODUCTION_ENABLED = false` and the debug
`RAVEN_LAB_TEST_A=1` unlock since its introduction; P1 adds explicit contact
routes, cards, `raven send --carrier auto|lan|internet`, an opt-in service
listener (`--internet-listen`, `RAVEN_INTERNET_LISTEN`, `raven node internet
on`, installer flags) and the C2 CI scenario on three operating systems.
Turning it on for users is a scope extension of a waived slice and needs this
record.

## 2. Scope (exactly what is covered)

Covered, and only in this combination:

- **carrier:** Internet direct TCP between two `raven-node` services, Noise XX
  with prologue `raven/internet/v1`, the channel-bound RIH1 hello (signed over
  role, caps, handshake hash, Noise static and Ed25519 key, `verify_strict`),
  and the RLB1 offer exchanged inside Noise;
- **link class:** `ENDPOINT_AUTHENTICATED` (Carrier Conformance §3.2): the link
  terminates at the intended contact; no hop, relay or store holds any byte;
- **objects:** the same as the LAN waiver: PairInit V1 / PairResponse (accepted
  only from local contacts), `ATSAM/indexed-session/v1` RVNA1 `0x03` messages
  and sealed ACKs, through the same dispatcher as LAN direct;
- **peers:** contacts only, in both directions: the dialer requires the
  responder's hello to name the expected (pinned) key, and the responder sends
  its hello and RLB1 only to a dialer whose hello names a local, unblocked
  contact (P0 contact-gated responder, finding F4);
- **addresses:** explicit `host:port` routes from the contact record or a
  contact card (IPv4, bracketed IPv6, DNS name), never discovered, never
  published; the listener is off unless the user opts in.

Not covered (all remain held): libp2p direct, Circuit Relay v2, DCUtR, AutoNAT,
UPnP / NAT-PMP, any DHT or public peer record, mesh / bridge / mailbox custody,
the background outbox worker (P2a), PairInit over any non-confidential carrier,
the Hybrid Ratchet v2 / Full Braid lab, and any Session V2 claim. Live chat
(`raven send --chat`) stays LAN-only in this slice.

## 3. Holds of umbrella §9.1 for this scope

| Hold | Status at signature (to fill) | Waived? |
|---|---|---|
| 1. Automated gates | C2 green on ubuntu, macOS and Windows (`carrier_matrix`), `internet_indexed_two_node.sh`, `internet_dial_smoke.sh`, `final_serverless_proof.sh` 16/16 | Not waived |
| 2. All companions APPROVED | Not all approved | **Waived for this slice** |
| 3. Independent security review | Not done | **Waived** |
| 4. Physical rows / failure matrix | Row R7a (Linux VPS ↔ macOS at home, port-forward or global IPv6) and the stage-12 Internet slice: **must be recorded before signature** (row 7 also names DCUtR; this waiver covers only its direct part) | **Not waived** for the direct part |
| 5. Indexed-session paths stay lab-gated | Live on this slice, as for LAN | **Waived for this slice**; never described as Session V2 |

## 4. Residual risks accepted

Everything in LAN waiver §4 (no FS/PCS inside a 24 h session, no independent
review or formal model, device key = identity key, no deniability, local-only
revocation, Keychain prompts, platform coverage) applies unchanged, plus:

1. **Public listener exposure.** An opted-in node accepts TCP from the whole
   Internet. A stranger completes Noise message 2 and so learns the node's
   stable Noise static public key, which links the node across IP addresses
   (it does not name the Raven ID). A port scanner learns that something
   listens on 7422.
2. **Denial of service.** Handshakes cost CPU (X25519, Ed25519 verify) and
   pre-auth slots. The listener shares `PRODUCTION_INBOUND` limits with LAN (32
   connections, 8 per IP, 4 handshaking per IP, 10 s handshake deadline,
   120 s session, 64 frames) with contacts in non-displaceable slots; the
   per-/24 (IPv4) and per-/48 (IPv6) pre-auth cap proposed in design §3.4 is
   **not** implemented yet. A distributed flood can still keep contacts out.
3. **Metadata.** Every network observer sees both IPs, timing and frame sizes.
   A contact card or a contact record maps an IP or DNS name to a Raven ID for
   whoever holds it; a stable IPv6 address or DNS name in a card is a stable
   location identifier. The outer Ed25519 signature names the sender to anyone
   holding candidate keys (LAN waiver risk 6) — here only the two endpoints see
   envelopes, as on LAN. The **dialer's** signed RIH1 hello goes first, so
   whoever answers at a saved address (a reassigned IP, a hijacked DNS name)
   learns the dialer's Raven identity and whom it tried to reach; it cannot
   impersonate the contact (the responder's hello must name the pinned key).
   With `--carrier auto`, a LAN miss makes the send dial the saved Internet
   address automatically, so this applies to every contact that has one.
4. **No forward secrecy and no post-compromise security** inside a session
   (profile §2.4), now for traffic that crosses the Internet: a recorded
   Internet transcript plus later theft of session state reveals that
   session's messages. Noise XX itself is forward secret for the link, which
   limits this to session-state compromise, not long-term key compromise alone.
5. **Unverified contacts.** Owner decision 2026-10-08: **narrowed, not
   waived.** The Internet carrier (and later p2p, mesh, mailbox) is refused
   for contacts that are not pinned (fingerprint not verified): `raven send`
   skips or refuses the route, the outbox worker never plans it, and the
   Internet listener treats an unpinned contact like a stranger. LAN direct
   for unpinned contacts is unchanged. Implementation lands with P2a; this
   risk is closed when that change is committed with its tests.
6. **Windows reachability.** The logon task runs only while the user is signed
   in, and Defender Firewall may silently block the port after a dismissed
   prompt.
7. **Clock skew** between Internet hosts against `expires_at` and PairInit
   windows (normative ±5 min); no NTP check yet (design Q14).

## 5. Compensating controls in place

- Contact-gated responder (F4): a stranger never receives the responder's
  hello, Raven identity or RLB1 bundle; the refusal is logged key-free.
- Dialer pins the expected key: hello identity == contact key, and RLB1 must
  bind exactly the hello's key (`rlb1_matches_noise_identity`).
- Addresses are hints only: identity is always the pinned key, checked by the
  Noise bind on every connection; cards are parsed strictly (known fields only,
  address must encode the key, fingerprint must match).
- Opt-in exposure: no listener unless `--internet-listen`,
  `RAVEN_INTERNET_LISTEN` or `raven node internet on` asks for one; a corrupt
  `node_policy.json` fails closed (no listener); installers print firewall
  rules and never apply them (Windows: Private profile only).
- Shared inbound limits and the separate pre-auth handshake deadline; frames
  are size-bounded (`MAX_FRAME_BYTES`) and strictly decoded.
- `raven status` shows whether the Internet listener is really up (from the
  running service's own Status), so exposure is visible.
- Same dispatcher, admission and session checks as the LAN waiver §5.

## 6. Conditions

This waiver lapses, and the flag MUST be set back to `false`, if any of these
happens before it is renewed:

- a critical or high finding on the covered path is confirmed and not fixed;
- the slice is extended beyond §2 (relay, DCUtR, discovery, custody, …)
  without a new waiver or review;
- the C2 CI scenario is disabled or fails on any of the three runners for more
  than one release;
- the review-by date passes without renewal.

## 7. Exit conditions before signature

- CI green on ubuntu, Windows and macOS with C2 (`carrier_matrix`): **met**
  2026-10-08 on `8e7bf26` (C1 + C2 ran and passed on all three runners).
- R7a physical row recorded under `node/proof_artifacts/` (two hosts on
  different networks), plus the stage-12 Internet failure slice. **Open:** the
  owner has no publicly reachable host yet (no VPS, port-forward or global
  IPv6), so R7a waits; P3 (relay + hole punching) may provide the first
  reachable path.
- Owner decision on risk 5 (unverified contacts on the Internet carrier):
  **decided** 2026-10-08, verified contacts only (§4 item 5); the code change
  and its tests are still to land.
- The gate-flip change applied as one reviewed commit: the flag, the
  `internet_gate.rs` tests, the umbrella §9.1 "Recorded owner exception",
  PairInit §7, indexed profile §7, Transport Interface §3, ADR 0002,
  `core/discovery.rs` `NAT_STATUS`, and a regenerated
  `docs/PROTOCOL_FREEZE_HASHES_V1.md` (design §5 row P1).
