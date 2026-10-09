# Forward secrecy and post-compromise security for the live session path

| | |
|---|---|
| **Status** | Design proposal for owner decision. Not normative: it changes no flag, wire format, frozen spec or vector. |
| **Date** | 2026-10-07 |
| **Scope** | The live LAN-direct session path (PairInit V1 + RVNA1 `0x03`) and every carrier that will reuse its session layer |
| **Baseline** | `file:line` citations refer to commit `a1d3e1d` (`fix/code-review-2026-09-29`). *(uncommitted)* marks working-tree changes another engineer was making while this was written; re-check them before acting. |
| **Sibling designs** | [`2026-10-per-device-keys.md`](2026-10-per-device-keys.md) (device keys, PrekeyBundleV2, RLB2), [`2026-10-daemon-owned-secrets.md`](2026-10-daemon-owned-secrets.md) (who holds secrets, vault, rollback guard) |
| **Retires when done** | Residual risk 1 of [`WAIVER-LAN-DIRECT-2026-10-07`](../WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) §4 (untracked draft at the time of writing) |

"(verify)" marks a statement about external work that was not re-checked against the primary source while
writing. Check it against the published paper or spec before relying on it. Byte layouts in §5 are proposals;
they freeze only together with vectors.

## 0. Summary

- The live profile has no forward secrecy (FS) and no post-compromise security (PCS) inside a session: every key
  is a function of a `K_root` that the store keeps for the session's life (profile §2.4). A copy of one device's
  state reads every message and ACK of every live session, in both directions, for the whole session: 7 days at
  `a1d3e1d`, 24 h after the in-flight change for sessions the node starts. The responder's retained prekeys
  extend that to about 37 days back for any PairInit the thief also captured.
- Shorter sessions (in flight) and not storing `K_root` (proposed here, no wire change) should ship now. Neither
  gives PCS, and short sessions also cap how late an offline peer can receive.
- **Recommendation:** a new profile `ATSAM/hybrid-ratchet/v3` ("HR3"). It is Signal's Double Ratchet in which
  every DH ratchet step also carries one ML-KEM-768 encapsulation to the peer's latest ratchet key, seeded by a
  PairInit V3 hybrid root. Around it: hedged, rollback-safe nonces; skipped keys that expire and evict; ACKs as
  ratchet messages; a stable route/header/mailbox lane; the existing protected journal. It gives per-message FS,
  classical and PQ PCS after one round trip, and keeps harvest-now-decrypt-later (HNDL) resistance. The price is
  about 2.4 KB per frame and a composition that Raven must model and have reviewed itself.
- Freeze the Full Braid lab; do not finish it. If the owner values inheriting Signal's SPQR analysis above
  native Swift, one-round-trip PQ healing and a smaller state machine, put SPQR in the KEM slot instead; the rest
  of §5 carries over.
- Effort: 1.5–2.5 engineer-weeks for the interim; 3.5–5 months to first Rust-only ratcheted LAN traffic; 6–9
  months to a modelled, externally reviewed claim with Swift parity.

## 1. Problem statement and current exposure

### 1.1 The live path

- LAN-direct runs in default builds: `LAN_DIRECT_PRODUCTION_ENABLED = true` (`lan_gate.rs:8`). Internet-direct is
  off (`internet_gate.rs:9`), and the generic tripwires stay `false` (`docs/crypto/ATSAM_THREAT_ASSUMPTIONS_V1.md`
  §3 item 4; `docs/THREAT_MODEL.md` line 32).
- The layers are Noise XX `Noise_XX_25519_ChaChaPoly_BLAKE2s`, whose static key is derived from the identity
  seed (`lan_noise.rs:17`, `:48-60`), then an RLB1 bundle offer (`lan_rlb1.rs:1-5`), then PairInit V1 with a
  signed hybrid X25519 + ML-KEM-768 root (`RAVEN_PAIR_INIT_V1.md` §4). After that come RVNA1 `0x03` messages and
  sealed ACKs, whose keys form a fixed tree under `K_root` (`ATSAM_INDEXED_SESSION_PROFILE_V1.md` §2.1-§2.3).
- The initiator signs PairInits valid for 7 days (`lan_dispatch.rs:1886`), and the session inherits that expiry
  (`indexed_session_store.rs:1771`). `ash send` reuses any confirmed session and pairs only when none exists
  (`ash/src/pair_init_lab.rs:356-360`), so a session lives its full lifetime however much it is used.
  *(uncommitted)* `LAN_SESSION_LIFETIME_MS` = 24 h for sessions this node initiates. Acceptance stays up to 7
  days (`prekey_lifecycle.rs:52`), as the waiver states (§4 item 1).
- On this slice the device key is the identity key (`lan_dispatch.rs:89-94`; waiver §4 item 3), and only
  contacts may pair (`lan_dispatch.rs:538-542`).

### 1.2 Secrets and their lifetimes

| Secret | Where | Lifetime |
|---|---|---|
| `K_root`, one per session | `SecretRatchets.root` in the protected blob (`indexed_session_store.rs:696-697`, written at `:6191`): a macOS Keychain generic password (`:1140`), Secret Service, or a DPAPI file in the data dir on Windows (`:1302-1343`) | Until the session is pruned after expiry (`:3352-3432`). At `a1d3e1d` prune runs only at listener start/maintenance and on PairInit (`lan_dispatch.rs:1207-1210`, `:1256`, `:1821`), so an idle node can keep an expired root indefinitely. *(uncommitted)* a 10-minute periodic prune (`DURABLE_PRUNE_INTERVAL`, `raven-node/src/lan_direct.rs`) |
| Keys re-derived from `K_root` | message/ACK chains and route/mailbox keys (profile §2.1-§2.3, §6), local inbox key (`:5545-5556`), store-integrity key (`:6160-6171`) | Recomputable whenever `K_root` is present |
| Skipped receive keys | Same blob, ≤ 256 per lane, oldest evicted (`:83-84`, `:5764-5800`) | Until used or evicted |
| Responder signed prekey: X25519 private + ML-KEM-768 seed | Prekey-lifecycle protected store (`prekey_lifecycle.rs:601-603` on macOS) | Bundle validity 30 d (`lan_dispatch.rs:604`) + 7 d grace (`prekey_lifecycle.rs:58`). At most 4 generations (`:43`). Rotation when ≤ 8 d remain (`:57`), about every 22 d. No one-time prekeys are installed (`lan_dispatch.rs:617`) |
| Initiator ephemeral X25519 | Memory | Zeroized after signing (`lan_dispatch.rs:1891`) |
| Plaintext history | ChatHistory: ciphertext under a Keychain, Secret Service or DPAPI key (`chat_history.rs:1-27`). Inbox rows are archived into it before prune (`lan_dispatch.rs:1193-1194`) | No retention limit found |

### 1.3 What a thief of device state at time t can decrypt

Assume the thief copies the protected stores, SQLite and the identity seed at instant t (on macOS all of them are
Keychain items: `identity_store.rs:726`, `indexed_session_store.rs:1140`, `prekey_lifecycle.rs:601-603`). Assume
also that the thief separately holds ciphertext captured from some carrier.

| Exposed | Window at `a1d3e1d` | Window after the in-flight change |
|---|---|---|
| Every `0x03` message and ACK of every live session, both directions (profile §2.4) | The whole session, `created_at` to `expires_at`, wherever t falls. Up to 7 d per session, plus any expired session not yet pruned | 24 h for sessions this node initiated, plus ≤ 10 min until prune. Up to 7 d for sessions that older peers initiated |
| Route and mailbox tags of those sessions (linkability, not content) | Same | Same |
| Past sessions where this node was the responder, even after their root was pruned, provided the thief captured the PairInit wire | Any PairInit to a retained generation: up to ~37 d before t | Unchanged |
| Future sessions where this node is the responder | Until the next prekey rotation, ≤ ~22 d. Carriers that serve cached bundles extend this to bundle expiry, ≤ 30 d | Unchanged |
| Future sessions this node initiates | None passively: each PairInit has a fresh ephemeral and encapsulation | Same |
| Plaintext the device keeps | All of ChatHistory, whatever the protocol does | Same |

On today's LAN carrier these frames travel inside a Noise XX session with ephemeral keys, so a classical passive
recorder cannot capture the PairInits and frames that rows 1, 3 and 4 need. The rows apply in full to an HNDL
recorder (Noise XX is classical X25519 only), to anyone who reads the peer's stored outbox or inbox, and to every
carrier now on hold (internet direct, relay, mailbox, store-and-forward), where ciphertext sits with third parties
for up to the 7-day envelope lifetime (`indexed_session_store.rs:87`) and Noise protects at most one hop. The
property must be fixed before those carriers ship. The errata already says that recomputing historic message
keys from a retained root "is not forward secrecy" (`SECURITY_ERRATA_RVN1_2026-08-13.md` line 97). The same
compromise of either peer exposes the same sessions.

### 1.4 No post-compromise security

Nothing heals inside a session (profile §2.4). A new session heals only if the compromised node initiates it. When
that node is the responder, the new PairInit is encapsulated to a prekey the thief already holds, so healing waits
for the next rotation (row 4). Because the device key is the identity key on this slice, a thief who stays active
can also impersonate the device, and no ratchet can fix that (N4).

## 2. Goals and non-goals

Goals:

- **G1 Per-message FS.** A compromise at t reveals no frame whose keys were deleted before t. The exceptions are
  bounded and stated: unexpired skipped keys (§5.7), and the initiator's first flight, which is only as
  forward-secure as the responder's prekey retention (§5.15).
- **G2 PCS after one round trip, classical and PQ,** against an adversary that is passive once its access ends.
  After each side has sent one frame following the compromise, later frames are secret again.
- **G3 Keep HNDL resistance.** A recorder that later breaks X25519 learns nothing without also breaking ML-KEM-768.
  This holds for the PairInit root and for every ratchet step (the both-halves rule of
  `ATSAM_THREAT_ASSUMPTIONS_V1.md` §1).
- **G4 Offline and asynchronous delivery.** No handshake beyond the one-flight PairInit. Delay up to the envelope
  lifetime, loss and reordering are tolerated. Key lifetime no longer depends on session lifetime.
- **G5 Crash and rollback safety.** No key/nonce reuse after a crash, after a detected rollback of one store, or
  after an undetected restore of both. The worst case is a desynchronized session that re-pairs.
- **G6 No silent downgrade** to `0x03` once both ends have advertised the ratchet.
- **G7 Reuse the endpoint transaction** (`ATSAM_ENDPOINT_TRANSACTION_V1.md` §2, §4): protected journal, dedup,
  ACK intents, exact-byte retries.

Non-goals:

- **N1 Multi-device.** Sessions stay per device pair (HR v2 §9). Device keys, per-device bundles and fan-out
  belong to the per-device-keys design (its §5.4-§5.8; fan-out is its P5).
- **N2 Deniability.** Every PairInit, envelope and ACK stays signed (waiver §4 item 4).
- **N3 PQ authentication.** Ed25519 stays classical (HR v2 §1.2 item 1).
- **N4 PCS against ongoing or active compromise,** including pairing or MITM with a stolen key. That needs
  revocation and per-device keys.
- **N5 Traffic analysis** beyond today's routing-tag unlinkability (`docs/THREAT_MODEL.md` §3.17).
- **N6 Plaintext the device keeps.** FS protects ciphertext held elsewhere, not ChatHistory. That is a retention
  decision (D6).
- **N7 Guaranteed erasure** on Keychain databases, Secret Service, DPAPI or sealed files, SSDs, snapshots or
  backups (see §5.9 and the sibling design's R6).
- **N8 Groups, and any change to the RVN1 envelope** (`RAVEN_ENVELOPE_V1.md` §1 is reused unchanged).

## 3. Threat model

| ID | Adversary | Can | Claim of the recommended design |
|---|---|---|---|
| A1 | Passive recorder | Record every RVN1 byte on any carrier, including relays and stores | Content confidentiality; tags unlinkable without the route key |
| A2 | HNDL | A1, then later break X25519 (and therefore Noise XX) | Content stays secret unless ML-KEM-768 also breaks (G3) |
| A3 | Active network | Drop, delay, reorder, replay, inject; cannot forge device signatures | Integrity and replay rejection; bounded work; delivery only if frames eventually arrive |
| A4 | One-time state theft | Copy the protected stores, SQLite and identity seed at t | G1 for the past; G2 if it stays passive afterwards |
| A5 | Ongoing or active compromise | Persistent malware; pairing or MITM with the stolen key | Out of scope (N4) |
| A6 | Environment rollback | Backup restore, VM snapshot, disk image; not necessarily hostile | No key/nonce reuse; worst case desync and re-pair (G5) |
| A7 | Malicious contact | Send any well-signed frame on its own sessions | Cannot touch other sessions; bounded CPU and state per frame |
| A8 | Downgrade | Serve stale bundles, replay PairInit V1, strip unsigned capability claims | No new `0x03` session once v3 has been advertised and seen (G6); the residual window is in §5.13 |

Assumptions: standard security of X25519, ML-KEM-768 (FIPS 203), HKDF/HMAC-SHA256, ChaCha20-Poly1305 and Ed25519;
the concatenation combiner of `ATSAM_THREAT_ASSUMPTIONS_V1.md` §1; an OS CSPRNG that works except under A6;
at-rest protection as in `docs/THREAT_MODEL.md` §3.6; endpoints honest during the windows the claims need
(threat model §3.7 and §3.16 stay out of scope).

## 4. Options

### 4.a Classical Double Ratchet on the PairInit root, with hybrid re-keying

Run Signal's Double Ratchet (DR) from a PairInit hybrid root. HNDL resistance without compromise comes from the
root, because every later root key is keyed by the previous one. There are two ways to add PQ PCS:

- **(a1) Periodic re-key,** in the style of Apple's PQ3 (verify its schedule and its analyses). The sender adds an
  ML-KEM exchange every N frames or T hours. This uses less bandwidth, but it adds sender policy state and heals
  only at the next re-key.
- **(a2) Dense KEM step.** Every DH ratchet step also carries an ML-KEM-768 ciphertext to the peer's latest ratchet
  encapsulation key, plus a fresh key of the sender's own, and both secrets enter the root KDF. This is a KEM-based
  continuous key agreement running beside the DH one, in the sense of Alwen, Coretti and Dodis (verify). It gives
  PQ PCS after one round trip with no extra state machine, at about 2.3 KB per frame.

**For.** DR is the most analysed messaging ratchet (Cohn-Gordon et al.; Alwen–Coretti–Dodis). The repo already has
`KDF_RK`, `KDF_CK` and DR transition code with KATs (`hybrid_ratchet_v2.rs:152-172`,
`hybrid_ratchet_v2_tr.rs:170-358`); the code can be reused, though not the vectors. Every primitive is native on all
three stacks. Classical security does not depend on the KEM half, because both secrets are concatenated into one
HKDF input.

**Against.** The composition is Raven's own, so it needs its own model and review. HR v2 currently forbids a
"Raven-only `Encaps(peer_pq_ek)` into `HKDF(ss_PQ || RK)`" as the PQ story (`ATSAM_HYBRID_RATCHET_V2.md` line 309;
§1.2 item 3), and that decision must be revisited. The umbrella does allow the "PQ3/SPQR-class principle"
(`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md` §4, line 172). Option (a2) makes every frame larger.

### 4.b A published PQ ratchet: Signal's Triple Ratchet with SPQR

Signal's Triple Ratchet combines DR with the Sparse Post-Quantum Ratchet over the ML-KEM Braid, and derives each
message key as `KDF_HYBRID(ec_mk, pq_mk)` (HR v2 header and §4.1). To adopt it, use Signal's `spqr` crate as the PQ
component, with Raven's own DR and composition. The crate is already an optional, git-pinned dependency
(`raven-core/Cargo.toml:26`; rev `fd320484`, v1.5.3, `spqr_pin_audit.rs:22-25`).

**For.** It is a published construction with Signal's analysis and verification work behind it (verify what is
proven, in which model, and whether that covers the Rust code). Per-frame overhead is small, since chunks are 32
bytes (`spqr_pin_audit.rs:28`). Upstream maintains it, and both projects are AGPL-3.0 (`LICENSE`; verify `spqr`'s
licence).

**Against.** PQ healing is sparse: an epoch needs its header, key and ciphertext chunks to flow (3 + 36 + 30 + 5
chunks, `spqr_pin_audit.rs:31-34`), i.e. tens of frames per direction (verify the per-frame chunk rate), which misses
"PQ PCS after one round trip". The state is complex, there is no native Swift (FFI only, as with libsignal's Swift
binding; verify), and Python cannot run it. A git-pinned revision used with `test-utils` (`spqr_pin_audit.rs:18-19`)
is not a stable API. Raven still has to model its own composition (PairInit V2, AckV2, routes, journal), and the
analysis carries over only if the algorithms are used unchanged (HR v2 §14 item 2).

### 4.c Finish the in-repo Hybrid Ratchet v2 / Full Braid

The lab engine reimplements the Braid with ten lab wire formats (`mod.rs:34-43`). It lives in
`hybrid_ratchet_v2_full_braid/`, about 16.9k lines including tests, and builds only with `full-braid-lab`
(`mod.rs:13`). Live code does not use it: only module declarations, the build script, one test and a lab FFI crate
reference it. The earlier review's findings hold:

1. **No message-level Triple Ratchet.** Nothing encrypts application frames or AckV2 per message. The EC ratchet
   advances only inside the per-epoch nested confirm (`tr_confirm.rs:705-792`). The stateful KAT module answers a
   DH change with "DH ratchet not modeled" (`hybrid_ratchet_v2_state.rs:315-323`).
2. **Skipped keys never expire, and the cap rejects instead of evicting.** Entries carry no age or epoch
   (`wire_rvft1.rs:38-42`); `insert_skipped` returns an error at the cap (`hybrid_ratchet_v2_tr.rs:257-271`), and
   Python mirrors it (`hybrid_ratchet_v2_tr.py:237-238`). The old chain is skipped before the DH step
   (`hybrid_ratchet_v2_tr.rs:296-322`), so once the table is full — 1000 entries (`wire_rvft1.rs:18`; one gap of
   `MAX_SKIP` = 1000 suffices) or 2000 (`hybrid_ratchet_v2_tr.rs:26`) — the next lost frame wedges the session: every
   later frame of that chain, and the peer's next DH step (whose PN then exceeds Nr), needs an insertion and is
   rejected without commit, forever. An attacker withholding ~1000 frames causes it, and so does long-run honest
   loss; the stale keys are also an unbounded FS hole.
3. **The AEAD nonce comes from the message keys.** `KDF_HYBRID` outputs key and nonce (L=44;
   `hybrid_ratchet_v2.rs:174-181`; spec §6.4), and the confirm seal uses it (`tr_confirm.rs:649`). The DR spec allows
   this for single-use keys (verify the wording), but Raven cannot guarantee single use: restoring both stores — easy
   on Windows, where both are files in the data dir (`indexed_session_store.rs:1302-1343`), and under the sibling
   vault (its §3.6) — or a VM snapshot replays the state, and the next seal reuses key and nonce on a new plaintext:
   ChaCha20 keystream reuse and a reused Poly1305 key. HR v2's "never reseal" rules (§11) cover crashes, not restores.
4. **The nested confirm is optional.** It runs only when the host sets `needs_aead == 1` (`transition.rs:592`,
   `:728`; "(optional TR AEAD)" at `:568`, `:714`), but the SCKA epoch is promoted either way (`:608`, `:763`), and
   the spec sends Bob's first encapsulating Send "without the confirm" (§5.2). One property has two code paths; an
   epoch can be promoted with no binding to the EC state, and without a confirm the EC ratchet never advances.

Fixing these means building the message-level engine and its store integration (the bulk of (b)); adding age fields
to RVFT1; changing eviction (`tr_skip_boundary_001`) and the nonce (`tr_hybrid_aead_001`, marked frozen); removing or
mandating the confirm (`full_braid_full_exchange_2pq_2dh_001`); reviewing the reimplemented Braid for equivalence
with `spqr`; and porting ~17k lines to Swift or exposing FFI. That costs more than (b), which deletes the
reimplementation. Freeze it as a lab reference.

### 4.d Shorter sessions only (interim)

The 24-hour sessions and 10-minute prune *(uncommitted)* cut the live-root window from 7 days to 24 h for sessions
this node initiates. One more step needs no wire or KDF change: **stop storing `K_root`.** After setup it serves only
route tags (`indexed_session_store.rs:2744`, `:3884`, `:4527`, `:4838`, `:5004`), the local inbox key (`:5545`), the
integrity key (`:6160`), PairResponse checking (`:4211`) and the idempotent-replay comparison (`:1805`). Store the
two route keys, the two derived local keys, the expected confirmation tag and a hash commitment of the root instead
(store version 4; today 3, `:94-97`). The frozen chain is one-way (`atsam_kdf.rs:40-56`), so consumed keys then
have per-message FS inside a session, apart from ≤ 256 skipped keys per lane. Profile §2.4's sentence that the
reference store keeps `K_root` describes the store, not the KDF, and would need updating.

Still missing: PCS; any fix for the responder-side prekey window (rows 3-4 of §1.3); and asynchronous reach — a
frame is accepted only before its session expires (`indexed_session_store.rs:2755-2760`) and an envelope never
outlives it (`lan_dispatch.rs:551-557`), so a 24-hour session is a 24-hour delivery horizon. More PairInits are not
a quota problem: claims are retained only until PairInit expiry (`prekey_lifecycle.rs:1631`), although
`RAVEN_PREKEY_LIFECYCLE_V1.md` §5 still says bundle expiry plus 7 days (a small spec/code drift).

### 4.e Comparison

| | (a2) HR3, recommended | (b) Triple Ratchet + `spqr` | (c) finish Full Braid | (d) interim |
|---|---|---|---|---|
| Per-message FS | Yes | Yes | Yes, after fix 1 | Consumed keys only, with root erasure |
| Classical PCS | 1 round trip | 1 round trip | 1 round trip | At session end, conditionally |
| PQ PCS | 1 round trip | After an epoch: tens of frames (verify) | As (b) | As classical |
| HNDL | Kept | Kept | Kept | Kept |
| Published analysis | DR yes; the composition needs a Raven model | Signal's (verify scope); the composition still needs a Raven model | Only after an equivalence review | n/a |
| Extra bytes per frame | ~2.4 KB | Small | Small | 0 |
| Swift | Native CryptoKit, 26+ (verify) | FFI | Port or FFI | Trivial |
| Python reference | All but ML-KEM (injected) | KDF/codec only | Partial today | n/a |
| First Rust-only LAN traffic | 3.5–5 months | 4.5–6 months | 6+ months | 1–2 weeks |

**Recommendation.** Ship (d) with root erasure now, build (a2) as HR3, and freeze (c). Choose (b) only if inheriting
Signal's analysis outweighs native Swift, one-round-trip PQ healing and the smaller state machine. Everything in §5
except the KEM step carries over.

## 5. Recommended design: `ATSAM/hybrid-ratchet/v3` (HR3)

### 5.1 Overview and wire versioning

| Item | Value |
|---|---|
| Profile | `ATSAM/hybrid-ratchet/v3` (23 bytes); written `P` below |
| Suite | `0x01`: X25519 + ML-KEM-768 + HKDF-SHA256/HMAC-SHA256 + ChaCha20-Poly1305 + Ed25519 |
| Envelope | RVN1 v1 unchanged; `env_type` 1 = text, 2 = ACK (`RAVEN_ENVELOPE_V1.md` §3) |
| Ratchet header | Encrypted, carried in `ratchet_header_ciphertext` (`hdr_len` u16, envelope §1; covered by the outer signature, §2) |
| Sealed body | `RVNA1\0\0\0` + proto **`0x05`** + suite. `0x05` is unassigned: `0x01`/`0x02` are legacy (`seal.rs:42-43`), `0x03` indexed, `0x04` the HR v2 lab, `0x7F` the stub |
| Establishment | PairInit / PairResponse **V3** (`RVPI3` / `RVPR3`, version `0x03`) |
| Prekey bundle | The per-device-keys design's PrekeyBundleV2 (its §5.4), plus one signed `u16 profile_set` |
| ACK record | **AckV3**: the 197-byte AckV2 layout (HR v2 §7.4) with signature domain `ATSAM/v3/ack` |

An unknown proto, suite, header layout or inner type is a hard reject. There is no "closest value" negotiation
(`RAVEN_PAIR_INIT_V1.md` §3). `0x03` stays accepted only for existing `0x03` sessions, and `0x04` is never live.

### 5.2 Establishment, and how the PairInit roots relate

PairInit V3 keeps the field order of `RAVEN_PAIR_INIT_V1.md` §3 with a 23-byte profile, so its layout is PairInit
V2's (2787 bytes; response 227). It differs from V2 only in magic `RVPI3\0\0\0` / `RVPR3\0\0\0`, version `0x03`,
signing domains `rvn1/pair-init-v3` / `rvn1/pair-response-v3`, and a `responder_prekey_bundle_hash` over
PrekeyBundleV2 (domain `rvn1/pair-prekey/v2`, as per-device-keys §5.4).

PairInit V3 adopts the trust-record rules of per-device-keys §5.7: device-key signatures, versioned certificate
digests and admissibility flags. That settles that design's R11 and Q6, which it filed against "PairInit V2". The
verification order, small-order rejection, claim idempotency, provisional rule and prekey lifecycle keep V1's
semantics (V1 §1-§6; lifecycle §4-§5); the lifecycle actor has to accept V3 transcripts. A responder sends nothing
on the ratchet before it has received the initiator's chain 0 (it has no sending chain until then).

```text
th         = SHA-256("ATSAM/v3/transcript" || "ATSAM/v3/pair-init" || PairInitV3)
ih         = SHA-256("ATSAM/v3/pair-init" || PairInitV3)
RK0 || K_route_master || K_hdr_master || K_confirm
           = HKDF(IKM = Z_X || Z_PQ, salt = th, info = P || 0x00 || "pair-expand" || th, L = 128)
session_id = SHA-256("ATSAM/v3/pair-session" || ih)
confirm    = HMAC-SHA256(K_confirm, "ATSAM/v3/pair-init/confirm" || 0x00 || ih)
```

- **V1 roots never seed HR3.** A V1 `K_root` is transcript-bound to `ATSAM/indexed-session/v1` (V1 §3 offset 12,
  §4). Reusing it would be the silent upgrade HR v2 forbids (§0, §15), and it would add no FS for traffic already
  sent under a retained root.
- **V2 roots stay with HR v2.** Its expand feeds `SK_ec` and `SK_scka` (HR v2 §0.3). Under option (b), PairInit V2
  is the right establishment, unchanged.
- **No prekey becomes a ratchet key.** Unlike HR v2 §3.3, Bob's signed prekey is not his first ratchet key. The
  initiator's first chain comes from `RK0` alone (§5.6), so no prekey private key is ever copied into session state.

### 5.3 State: one protected blob per session

```text
SessionStateV3                                    # replaced whole on every mutation, as today
  magic "RVNHR3S\0", version, generation u64        # reconciled with SQLite as today (:6010-6030)
  binding        PairInit V3 digests, both cert digests, roles, created_at, send_until, accept_until, lifecycle
  stable         K_route[0..1], K_hdr[0..1], K_hnonce[0..1], K_local, K_integrity   # last two random
  rk             32
  dhs            X25519 private 32 + public 32        # current sending ratchet key
  kem_self       ML-KEM-768 dk seed 64 (ek 1184 re-derivable from the seed)
  dhr, peer_ek   peer ratchet public 32 and peer ratchet ek 1184 (absent until known)
  kem_ct_out     1088, repeated in every header of the current sending chain (absent in chain 0)
  cks, ckr       optional 32 each; ns, nr, pn u32; expect_chain0 and step_pending flags
  g_send, g_recv_next u64; g_missing ≤ 512 entries
  skipped        ≤ 512 × {chain_dh 32, n u32, mk 32, expires_at_ms u64}
  time_floor_ms  u64, highest wall clock ever committed
  desync_strikes u8
  journal        at most one pending acceptance, ACK acceptance or outbound record (as :704-711)
  mac            HMAC-SHA256(K_integrity, all of the above)   # corruption check, not a boundary
```

Typical size is about 6 KB. A full skipped table adds about 39 KB, and a journaled envelope adds its own size, as
it does today. The current blob already holds up to 512 skipped entries (2 lanes × 256) and is rewritten for every
message.

### 5.4 Frame format

```text
H (header plaintext, 2321 B; 1233 B in the initiator's chain 0)
  u64 g | dh_pub[32] | u32 pn | u32 n | u8 kem_flags (bit0 = kem_ct present) | ek_send[1184] | kem_ct[1088] if bit0

ratchet_header_ciphertext = 0x01 (layout) || hnonce[12] || ChaCha20-Poly1305(K_hdr[d], hnonce, AD_h, H)
AD_h = "ATSAM/v3/hdr-aad" || 0x00 || 0x01 || session_id || u8(d) || routing_tag || message_id
       || u8(env_type) || u64(created_at_ms) || u64(expires_at_ms)

message_ciphertext = "RVNA1\0\0\0" || 0x05 || 0x01 || mnonce[12] || ChaCha20-Poly1305(K_aead, mnonce, AD_m, I)
AD_m = "ATSAM/v3/msg-aad" || 0x00 || 0x05 || 0x01 || session_id || u8(d) || sender_cert_hash
       || recipient_cert_hash || message_id || u8(env_type) || u64(created_at_ms) || SHA-256(H)
I    = u8 inner_type || u16 body_len || body || zero padding
       # 0x01 text (env_type 1); 0x02 AckV3 (env_type 2); 0x03 session-start (env_type 1, empty, never ACKed)
```

`d` is the transcript direction, with 0 for initiator to responder. `kem_flags` bit 0 is 0 exactly on the initiator's
chain 0 and 1 everywhere else. The inner type must match `env_type`, and padding must be zero.

The header is encrypted because a clear `dh_pub`, `ek_send` or `kem_ct` would let relays link every frame of a
chain. That would undo per-frame tag rotation (`RAVEN_ROUTING_TAG_V1.md` §1; `docs/THREAT_MODEL.md` §3.1).

### 5.5 KDF chain and domain-separated labels

All HKDF is HKDF-SHA256, `0^32` is 32 zero bytes, `‖` is concatenation and `00` is a zero byte.

| Name | Definition | Output |
|---|---|---|
| Chain 0 | `HKDF(IKM=RK0, salt=0^32, info=P‖00‖"chain0", L=64)` | `RK1 ‖ CK` of the initiator's chain 0 |
| `KDF_RK` | `HKDF(IKM=dh_out‖kem_ss, salt=rk, info=P‖00‖"rk", L=64)` | `rk' ‖ ck` |
| `KDF_CK` | `mk = HMAC(ck, 0x01)`, `ck' = HMAC(ck, 0x02)` | As the DR spec and HR v2 §6.2 |
| Message keys | `HKDF(IKM=mk, salt=0^32, info=P‖00‖"msg-keys", L=64)` | `K_aead ‖ K_nonce` |
| Route key | `HKDF(IKM=K_route_master, salt=0^32, info=P‖00‖"route"‖00‖u8(d), L=32)` | `K_route[d]` |
| Header keys | `HKDF(IKM=K_hdr_master, salt=0^32, info=P‖00‖"header"‖00‖u8(d), L=64)` | `K_hdr[d] ‖ K_hnonce[d]` |
| Routing tag | `HMAC(K_route[d], "ATSAM/v3/route"‖session_id‖u64(g))[0:16]` | 16 B |
| Mailbox tag | `HMAC(K_route[d], "ATSAM/v3/mailbox"‖session_id‖u64(day)‖u8(d))[0:16]` | 16 B; `store_tag = SHA-256("raven/relay-tag/v1"‖tag)[0:16]`, as today |

Rules: an all-zero X25519 output and a small-order `dh_pub` are hard rejects, as in PairInit V1 §3-§4; the FIPS 203
encapsulation-key check runs before `Encaps` and an exact 1088-byte length check before `Decaps` (verify what the
`ml-kem` crate already enforces); every counter increment is checked, and overflow ends the session.

### 5.6 Ratchet algorithm

```text
InitAlice: RK, CKs := Chain0(RK0); dhs := X25519.Gen(); (dk, ek) := MLKEM.Gen(); dhr, peer_ek, kem_ct_out := none
InitBob:   RK, CKr := Chain0(RK0); expect_chain0 := true            # no sending chain yet

Send(frame):                                  # draws only ids and nonce randomness
  CKs, mk := KDF_CK(CKs); H := {g_send, dhs.pub, pn, ns, ek, kem_ct_out}; ns += 1; g_send += 1

Receive(frame), on a candidate copy C, after the outer signature has been verified:
  H := open header with K_hdr[d_in]; require H.g == the g whose routing tag matched
  if (H.dh_pub, H.n) in C.skipped: mk := take it
  else
    if C.expect_chain0:                       # Bob receiving Alice's chain 0
      require kem_flags == 0 and pn == 0; C.dhr := H.dh_pub; C.peer_ek := H.ek_send; C.step_pending := true
      C.expect_chain0 := false
    elif H.dh_pub != C.dhr:                   # new peer chain: hybrid receiving step
      require kem_flags == 1; skip(C, C.ckr, H.pn)   # skip() is a no-op while ckr is absent
      ss := MLKEM.Decaps(C.dk, H.kem_ct)
      C.RK, C.CKr := KDF_RK(C.RK, X25519(C.dhs, H.dh_pub) || ss); C.nr := 0
      C.dhr := H.dh_pub; C.peer_ek := H.ek_send; C.step_pending := true
    skip(C, C.ckr, H.n); C.CKr, mk := KDF_CK(C.CKr); C.nr := H.n + 1
  I := open body with mk                      # any failure: discard C; no write, no journal, no ACK
  if C.step_pending:                          # sending step, only after authentication
    C.pn := C.ns; C.ns := 0; C.dhs := X25519.Gen(); (C.dk, C.ek) := MLKEM.Gen()
    (C.kem_ct_out, ss2) := MLKEM.Encaps(C.peer_ek)
    C.RK, C.CKs := KDF_RK(C.RK, X25519(C.dhs, C.dhr) || ss2); wipe the old dhs and dk; C.step_pending := false
  commit C (§5.9)
```

This is DR's `RatchetDecrypt`/`DHRatchet` (verify against the spec's pseudocode) with a KEM secret appended to every
DH output. **Work bound:** the expensive sending step runs only after the AEAD succeeds; before that, an
authenticated peer can force at most one `Decaps`, one X25519 and `MAX_SKIP` HMACs per frame. **Healing:** after a
compromise of Alice, her next chain uses a fresh DH key and an encapsulation to Bob's key (secret even from a
quantum attacker), and Bob's next chain encapsulates to Alice's fresh key — one round trip. **First flight:** Bob's
first ACK already starts his first chain, and the initiator may send only `n = 0` while provisional
(`ATSAM_ENDPOINT_TRANSACTION_V1.md` §4.1), so Alice's first flight is normally one frame.

### 5.7 Skipped-key policy

- **Work bound:** `MAX_SKIP = 1024` per `skip()` call. Skips run only after outer authentication, so only the
  authenticated peer can trigger them.
- **Storage bound:** `MAX_SKIPPED = 512` entries in total. Inserting past the cap **evicts** the oldest entries
  (FIFO); it never rejects the frame, so no DH step can wedge. The current store already evicts (`:5788-5795`).
- **Expiry:** `expires_at = created_at(trigger frame) + 7 d + 5 min`, from `MAX_ENDPOINT_ENVELOPE_LIFETIME_MS` and
  `MAX_ENDPOINT_FUTURE_SKEW_MS` (`:86-87`). The trigger's signed `created_at` is at most now + 5 min (`:149`); a
  skipped frame was sealed earlier on the sender's clock and cannot be accepted after its own envelope expires, so
  expiry loses no deliverable frame (a sender clock jumping backwards could lose one). Expired entries are swept on
  every mutation and by the periodic prune, against `time_floor_ms`, so a clock set back cannot extend retention.
- **Deletion:** zeroize in memory and replace the protected state; storage remanence is out of scope (N7, §5.9).
  `g_missing`, which serves tag lookup, follows the same cap and expiry.

### 5.8 Nonce policy that stays safe under rollback

```text
mnonce = HMAC-SHA256(K_nonce,     "ATSAM/v3/nonce"  || r  || u32(len AD_m) || AD_m || I)[0:12]
hnonce = HMAC-SHA256(K_hnonce[d], "ATSAM/v3/hnonce" || r' || u32(len AD_h) || AD_h || H)[0:12]
r, r'  = 32 fresh bytes each from the OS CSPRNG; never stored; KATs fix them
```

Receivers take the transmitted nonce and never recompute it, so this is a sender rule that vectors pin. With a
working RNG the nonce is uniformly random, like today's random `0x03` nonces (`:2051-2053`). If a restore replays the
state and the same `mk` seals a different frame, the nonce still differs except with probability about 2^-96, even
when the RNG output was replayed too (a VM snapshot): the synthetic-IV argument (Rogaway–Shrimpton; verify), resting
only on HMAC as a PRF. Identical inputs give identical ciphertext, which leaks only equality. AES-GCM-SIV (RFC 8452)
has the same property but is not in CryptoKit, and XChaCha20-Poly1305 does not help when the RNG output is replayed
(verify both). Message keys stay single-use in normal operation; under the long-lived header key the 96-bit
collision bound is about 2^48 frames.

### 5.9 Crash and rollback consistency with the protected journal

HR3 keeps the store's ordering: protected head first, SQLite second (`indexed_session_store.rs:18-27`). It keeps its
journal and fault points too (`:2104-2146`, `:6081-6103`).

1. **Outbound, text or ACK.** Take the lease and an IMMEDIATE transaction, recover any journal, reconcile the
   generation (`:6010-6030`), and draw the message id, anti-replay nonce, `r` and `r'`. On a candidate, advance the
   chain, seal, sign and re-verify the envelope; journal the exact bytes and stage the outbox and outstanding rows.
   Replace the protected head, commit, clear the journal, and hand off outside the lease. Retries resend exact bytes
   only (`ATSAM_ENDPOINT_TRANSACTION_V1.md` §4.1).
2. **Inbound.** Run §5.6 on a candidate, then the acceptance transaction of `ATSAM_ENDPOINT_TRANSACTION_V1.md` §2.
   What is new: the sending step's randomness (DH key, KEM seed, encapsulation coins) is drawn before the protected
   write and travels in the journaled candidate. Recovery replays SQL rows; it never re-derives or regenerates keys.
3. **ACK acceptance** follows HR v2 §11.2: signature, outstanding row, nonce uniqueness, monotone lattice.
4. **Skipped-key sweep and close** are journal-free protected mutations that bump the generation. Close follows
   `prune_expired_sessions` (`:3352-3432`) after the inbox has been archived.
5. **Rollback.** A protected head older than SQLite fails closed, as today, and leads to a fresh PairInit V3. A
   restore of both stores is undetectable locally: a full-system restore or VM snapshot today, and a plain data-dir
   restore under the sibling vault design unless its `store_epoch` guard ships (daemon-owned-secrets §3.6, §4.5
   step 5); HR3 requires that guard wherever state lives in files. When a restore goes undetected, (i) §5.8 still
   prevents key/nonce reuse, (ii) the peer rejects reused indices as replays, and (iii) after 3 consecutive
   peer-signed frames that fail header or body AEAD, the session is marked desynchronized, stops sending and
   re-pairs. Keys deleted after the snapshot are back on disk; that is inherent to the restore.
6. **Erasure at rest (the sibling design's R6).** "Deleted" means wiped in memory and overwritten in the store. If
   state moves into sealed files under a static vault key, old copies in APFS snapshots or backups stay decryptable.
   That holds today for the Keychain database too. Erasure therefore holds only against copies that lack the
   wrapping key. Excluding session state from backups is D10.

### 5.10 ACK lane

ACKs are ordinary ratchet frames (`inner_type` 0x02, outer `env_type` 2). They get FS and PCS, consume `g` and `n`,
and turn the ratchet in one-way conversations; there is no separate symmetric ACK chain from a frozen root (HR v2
§7.1). Materialization comes only from a committed intent, one ACK per intent, with exact bytes retained and
re-queued on duplicate source frames; there is no ACK-of-ACK, and the delivery lattice is unchanged
(`ATSAM_ENDPOINT_TRANSACTION_V1.md` §4.2; HR v2 §11.2-§11.4). AckV3 keeps the inner device signature, so stolen
session state alone cannot forge a delivery.

### 5.11 Route, mailbox and header keys

`K_route[d]` and `K_hdr[d]` stay fixed for the session's life, so choosing a candidate session never needs the
current ratchet head (HR v2 §10.1). The receiver precomputes tags for `g` in `[g_recv_next, g_recv_next + 1024)` and
for `g_missing`, for at most 8 sessions per peer device (HR v2 §10.4), so an arriving tag is an O(1) lookup; the
decrypted `H.g` must equal the matched `g`. Crossed pairings still give two sessions per peer
(`lan_dispatch.rs:1389-1394`): senders use the newest confirmed one, receivers try all. Daily mailbox tags and
catch-up polling follow HR v2 §10.5. Compromise of these keys reveals, for the session's life, which envelopes belong
to it and their headers (public ratchet values), never content; session lifetime bounds that.

### 5.12 Session lifetime

PairInit V3 `expires_at` (≤ 7 d) bounds only acceptance of the PairInit itself. Proposed (D4): a session seals for
7 d (`send_until = created_at + 7 d`) and accepts for one envelope lifetime more (`accept_until = send_until + 7 d +
5 min`); from day 6 the node pre-pairs a successor, so rollover never blocks sending; it closes early on revocation
(`RAVEN_DEVICE_REVOCATION_V1.md`), block or delete, certificate expiry, or desync.

The bound matters for two reasons: the per-device-keys design contains a device revoked under partition only "plus
at most one session lifetime" (its §0), and the stable lane of §5.11 is linkable for the session's life. Longer
sessions, for example 30 d, would work cryptographically but extend both bounds.

### 5.13 Migration from `0x03` and downgrade prevention

1. **No in-place conversion.** Existing `0x03` sessions run to expiry, with root erasure from P0: ≤ 24 h, or ≤ 7 d
   for sessions older peers initiated. Nothing is derived from a V1 root (§5.2).
2. **Advertise.** An HR3 node sets `profile_set = {v1, v3}` in its PrekeyBundleV2 (bit 0 indexed-session/v1, bit 2
   hybrid-ratchet/v3, bit 1 reserved for the HR v2 lab and 0 in production, other bits 0) and sends it in RLB2
   (per-device-keys §5.5). V2 bundles have their own per-device cache key (per-device-keys §5.4), so V1's same-id
   equivocation rule (`RAVEN_PREKEY_BUNDLE_V1.md` §4) never sees two layouts of one generation. Old peers keep
   getting RLB1 and V1 bundles until the sunset.
3. **Choose deterministically.** The initiator uses the highest profile in the intersection of its own support and
   the verified bundle's set; there is no negotiation message for an attacker to strip.
4. **Sticky floor**, like per-device-keys' `transport_min` pin (its §5.6). Once a node has verified a v3-capable
   bundle from a peer device, or confirmed an HR3 session with it, it durably records `profile_floor[peer lineage] =
   v3`: it never initiates V1 to that device again and rejects inbound PairInit V1 from it. Only an explicit user
   reset clears the floor, like `forget_peer_prekey_pin` (`lan_dispatch.rs:1012-1029`). The existing
   `signed_prekey_id` rollback pin already refuses an older bundle once a newer one was seen
   (`lan_dispatch.rs:993-1010`).
5. **Sunset.** After the owner's date (D5), reject all PairInit V1 and stop publishing V1 bundles.
6. **Not used: identity capability records.** They have no bit registry (`RAVEN_CAPABILITIES_V1.md` §1) and no
   sequence number (§3).

Residual window: first contact between two HR3 nodes over an unauthenticated bundle channel before the sunset,
where an attacker replays a still-valid V1-only bundle (≤ 30 d). On LAN the bundle comes from the peer itself over
Noise XX (`lan_rlb1.rs:1-5`), so the attack needs the peer's key. A consistent rollback (A6) can also roll back the
floor.

### 5.14 Size and cost budget

| Item | Size or cost |
|---|---|
| Encrypted header | 1 + 12 + 2321 + 16 = 2350 B (1262 B in the initiator's chain 0) |
| Body overhead | 8 + 1 + 1 + 12 + 16 + 3 = 41 B, plus payload and padding |
| Text frame | 86 + 2350 + 41 + 64 ≈ 2.5 KB plus text. Fits the 48 KiB LAN text cap inside one Noise frame (`lan_noise.rs:22-28`) |
| ACK frame | ≈ 2.7 KB, against 293 B for a `0x03` ACK (profile §5) |
| CPU per new chain | 1 ML-KEM keygen + 1 Encaps + 1 Decaps + 2 X25519 + a few HKDF. Expected sub-millisecond on desktop CPUs; to be measured |
| Protected write per frame | ~6 KB typical, ≤ ~45 KB plus a journaled envelope; one write per message, as today |

One optimization would omit the KEM fields once the peer has acknowledged the chain, bringing steady-state headers
down to about 0.1 KB. It creates dependencies between frames, so it belongs in a later versioned revision.

### 5.15 What HR3 would claim, once §7 has passed

| Property | Bound | Depends on |
|---|---|---|
| Per-message FS | Every frame whose keys are deleted, except unexpired skipped keys (≤ 512, ≤ 7 d + 5 min) and the initiator's chain 0. Chain 0 is only as forward-secure as the responder's prekey retention, ≤ ~37 d (D12) | Deletion actually happening (N7) |
| Classical PCS | Heals one round trip after access ends | A passive adversary afterwards; a working RNG |
| PQ PCS | The same round trip | ML-KEM-768 |
| HNDL | The root and every step need ML-KEM-768 broken | The combiner (§3 assumptions) |
| Metadata | Tags and headers linkable for the session's life after a compromise | Session lifetime (§5.12) |
| Rollback | No key/nonce reuse; worst case desync and re-pair | HMAC as a PRF (§5.8) |

Nothing here is claimed until the model, vectors and external review of §7 have passed. Until then HR3 is
"production-disabled, unreviewed", like the slice it replaces.

## 6. Phased implementation plan

The estimates assume one senior Rust/crypto engineer full-time and part-time review, plus a separate Swift engineer
for P5. "Weeks" means engineer-weeks.

| Phase | Work | Effort | Ships |
|---|---|---|---|
| P0 | Finish the 24 h sessions and periodic prune *(uncommitted)*. `K_root` erasure: store v4, migration on open, crash matrix. Coordinate with the engineer now editing `indexed_session_store.rs`. Update profile §2.4, the threat-model LAN row and the waiver; protocol docs go through the freeze manifest (`PROTOCOL_VERSIONS.md` line 98) | 1.5–2.5 | Yes, now; no wire change |
| P1 | Decision record for D1/D2. HR3 spec, PairInit V3, AckV3 and the `profile_set` field, frozen once together with per-device-keys' PrekeyBundleV2/RLB2. Python reference (X25519 native, ML-KEM injected as today). Vector generator; about 25 KATs and 25 negatives | 4–6 | Spec and vectors |
| P2 | Rust core: pure state machine, codecs, hedged nonces, skipped policy, KAT parity with Python, fuzz targets | 4–6 | No |
| P3 | Rust store and LAN integration: protected state v3; send, receive, ACK and sweep transactions; tag index; floor; bundle publication; migration; fault injection and two-daemon kill tests. Depends on per-device-keys P1–P2 for PrekeyBundleV2 and RLB2 | 6–9 | Rust↔Rust LAN behind a new gate, under an amended waiver |
| P4 | Tamarin model, in parallel from P1 and shared with per-device-keys §7.3 | 4–8 (specialist) | Gates the claims |
| P5 | Native Swift implementation (OFF-MAIN), vectors, adapters | 6–10 | Apple clients |
| P6 | External review and fixes | 4–8 calendar weeks + 2–4 | Release claim |
| P7 | `0x03` sunset: stop V1 initiation, reject PairInit V1 after the date, delete the code after the last session ends | 1–2 | — |

The total is about 28–48 engineer-weeks. Rust-only ratcheted LAN traffic arrives about 3.5–5 months after P1
starts (P1–P3 in sequence). A modelled, reviewed claim with Swift parity takes about 6–9 months. P0 is independent
and should not wait.

## 7. Verification plan

**Shared KATs** in `shared-vectors/rvn1/atsam/` (Python and Rust run all of them; Swift runs those CryptoKit
allows): the label catalog; PairInit V3 wire, expand and confirm; the PrekeyBundleV2 `profile_set` signing bytes;
`KDF_RK` with given DH and KEM inputs, `KDF_CK` and message keys; hedged nonces with fixed `r`; header and body codecs
and their AEAD; route and mailbox tags; AckV3. Plus a scripted exchange from fixed seeds, using FIPS 203
deterministic keygen and encapsulation (`atsam_mlkem.rs:23-27`, `:191`), that covers three hybrid steps, reordering
across chains, skips, expiry, eviction and ACKs, and records the state fingerprint after every step.

**Negative vectors:** PairInit V1 or V2 presented as V3; V3 against a bundle without the v3 bit; V1 after the floor
is set; header or body tampering; a header moved to another envelope, session or direction; a `g` mismatch;
`kem_flags` 0 outside chain 0; a ciphertext for the wrong key; small-order or all-zero DH; wrong lengths; trailing
bytes; an unknown layout or inner type; an inner type that does not match `env_type`; `MAX_SKIP + 1`; replay of a
consumed key and of an expired one; ACK-of-ACK; an ACK without an outstanding row; a delivery downgrade.

**Crash and rollback.** Reuse the existing fault points (before and after protected replacement, database commit,
journal clear and queue handoff) for sends, in-chain receives, receives with a hybrid step, skipped-key use, sweep,
eviction, ACK materialization and ACK acceptance. Add process-kill tests with two `raven-node` daemons
(`node/scripts/lan_direct_two_node.sh`). Rollback tests: restoring only the blob must fail closed; restoring both
stores must never reuse a nonce under one key, also with a replayed RNG; desync must end in re-pairing.

**Fuzzing.** Add HR3 header, body, PairInit V3, PrekeyBundleV2 and AckV3 decoders beside the existing targets
(`node/fuzz/fuzz_targets/`), and a stateful two-party harness that drops, duplicates, reorders, tampers, crashes and
restores. It checks that no frame is accepted twice, no ACK appears without an inbox row, state stays bounded, the
generation is monotone, nothing panics, and the session converges after two clean round trips. Replay its
transcripts in Python for a differential check.

**Formal model.** Use Tamarin, which handles mutable state and PCS. The repo has no model today (waiver §4 item 2);
put it beside the per-device-keys model in `protocol/reference/formal/`. Scope: PairInit V3 (signed hybrid KEM and
DH, the transcript, the bundle's profile set), the ratchet with both key agreements, state, long-term and prekey
reveals, and a "DH broken" rule for a quantum adversary. Lemmas: (1) message secrecy; (2) FS; (3) passive PCS
after one round trip; (4) lemmas 1–3 again under "DH broken", i.e. HNDL, PQ FS and PQ PCS; (5) injective agreement on
session, direction, `g` and plaintext; (6) profile agreement, and no V1 session after the floor is set; (7) key
confirmation; (8) executability lemmas.

Bound the number of ratchet steps if needed; published Tamarin and ProVerif models of PQ3, PQXDH and Signal are
possible starting points (verify availability). Symbolic models cannot capture nonce reuse, rollback or the
combiner, so cover those with a short computational argument for the external reviewer: the DR modular proof with a
hybrid key agreement, plus the synthetic-IV nonce.

**External review** of the spec, model, Rust core and store transactions before any claim. Physical-device rows
as the umbrella requires (§9.1).

## 8. Risks and open questions

Decisions requested from the owner:

- **D1** Approve HR3's dense KEM step, which revises HR v2 line 309 and §1.2 item 3 for a successor profile in line
  with umbrella §4. Or choose SPQR, option (b).
- **D2** Freeze the Full Braid lab as a reference and stop investing in it.
- **D3** Swift: native CryptoKit or FFI to the Rust core. CryptoKit has `MLKEM768` only on iOS/macOS 26+
  (`ATSAM_THREAT_ASSUMPTIONS_V1.md` §2, unverified on `main`), so older OS versions would stay on `0x03` or be
  refused.
- **D4** HR3 session lifetime: 7 d to send plus 7 d to accept, as proposed, or longer, which widens the revocation
  and linkability bounds.
- **D5** Migration: a flag day for the small LAN population (recommended) or a dual stack. Also the PairInit V1
  sunset date and a waiver amendment covering HR3.
- **D6** Message retention. Without a retention limit or disappearing messages, FS cannot protect what a device
  thief finds in ChatHistory.
- **D7** Accept about 2.4 KB per frame, which makes ACKs about 9 times larger. Revisit for BLE and mailbox quotas.
- **D8** Header encryption under a stable per-session key, as proposed, or DR's ratcheted header keys (verify the
  spec's header-encryption variant), at the cost of trial decryption.
- **D9** Downgrade anchor: the bundle's profile set plus a sticky floor (recommended), or a device-certificate
  capability bit in RVDC2.
- **D10** Exclude session state from backups where the platform allows, accept best-effort erasure, and require the
  vault's `store_epoch` guard if sealed files are adopted.
- **D11** Keep "only `n = 0` while provisional", or relax it for store-and-forward first contact, which lengthens the
  first flight.
- **D12** One-time prekeys destroyed after their first claim, to shrink the first-flight window below ~37 d. This
  needs the versioned change to the "accept both" race rule (`RAVEN_PREKEY_LIFECYCLE_V1.md` §6).
- **D13** Staffing for the model and budget for the external review.

Risks:

- **R1** A flaw in Raven's own composition. Mitigation: the model and the review; classical security does not rest
  on the KEM half.
- **R2** Store integration is where the bugs will be: receive now draws randomness and replaces more state.
  Mitigation: the fault matrix and kill tests.
- **R3** Desync and re-pair loops after rollbacks or bugs. Rate-limit re-pairing and tell the user.
- **R4** One protected write per frame on Keychain and Secret Service, including the prompts of waiver §4 item 7,
  until the daemon-owned-secrets design lands.
- **R5** Mixed fleets keep `0x03` exposure alive until the sunset, and Swift lag lengthens it.
- **R6** While the device key equals the identity key, PCS holds only against passive adversaries (N4).
- **R7** Python cannot check ML-KEM steps today, so some vectors stay Rust-generated
  (`docs/crypto/ATSAM_KAT_CONSUMER_MATRIX_V1.md`).
- **R8** HR3 depends on per-device-keys P1–P2 for the bundle and the offer. If that design slips, HR3 needs an
  interim profile field. Freeze PrekeyBundleV2 once for both.

To verify before the spec freezes: what Signal's Triple Ratchet/SPQR analysis covers and its per-frame chunk rate;
Apple PQ3's re-key schedule and analyses; the Alwen–Coretti–Dodis KEM-based key agreement; the DR spec's wording on
derived nonces, its header-encryption variant and its pseudocode; `spqr`'s licence and public API; CryptoKit support
for ML-KEM seeds, deterministic encapsulation, AES-GCM-SIV and XChaCha20; whether the pinned `cryptography` exposes
ML-KEM; which key and ciphertext checks the `ml-kem` crate performs; and which backups and snapshots capture the
login keychain and the data dir.

## 9. References

**In repo, at `a1d3e1d`:** in `protocol/`, `ATSAM_INDEXED_SESSION_PROFILE_V1.md`, `RAVEN_PAIR_INIT_V1.md`,
`ATSAM_ENDPOINT_TRANSACTION_V1.md`, `ATSAM_HYBRID_RATCHET_V2.md`, `RAVEN_PREKEY_BUNDLE_V1.md`,
`RAVEN_PREKEY_LIFECYCLE_V1.md`, `RAVEN_ENVELOPE_V1.md`, `RAVEN_ROUTING_TAG_V1.md`, `RAVEN_CAPABILITIES_V1.md`,
`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md` and `SECURITY_ERRATA_RVN1_2026-08-13.md`; `docs/THREAT_MODEL.md` and
`docs/crypto/ATSAM_THREAT_ASSUMPTIONS_V1.md`; the sibling designs in the header; and the code cited inline.

**External** (all to verify): Signal, *The Double Ratchet Algorithm*, revision 4, and *The ML-KEM Braid Protocol*,
at the URLs HR v2 cites; `signalapp/SparsePostQuantumRatchet` at `fd320484`; Alwen, Coretti, Dodis, *The Double
Ratchet: Security Notions, Proofs, and Modularization for the Signal Protocol*, EUROCRYPT 2019; Cohn-Gordon,
Cremers, Dowling, Garratt, Stebila, *A Formal Security Analysis of the Signal Messaging Protocol*, EuroS&P 2017;
Cohn-Gordon, Cremers, Garratt, *On Post-Compromise Security*, CSF 2016; Apple Security Research, *iMessage with PQ3*
(2024) and its published analyses; Bhargavan, Jacomme, Kiefer, Schmidt, formal verification of PQXDH (2024);
Rogaway, Shrimpton, deterministic authenticated encryption and SIV, EUROCRYPT 2006; FIPS 203; RFC 5869, RFC 7748,
RFC 8439, RFC 8452.
