# RAVEN Threat Model — Serverless P2P (Phase A)

> **2026-08-13 security correction:** RVN1 is under a production hold. The
> audit found a publicly derivable interim cipher, plaintext/unverified ACK
> paths, ACK-before-decrypt/commit, pre-authentication dedup poisoning, and
> unauthenticated mutable hop ceilings. Until the gates in
> [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md)
> pass, every older “Protected” verdict that depends on endpoint E2EE, ACK
> authentication, replay/dedup ordering, ratchet durability, or bounded
> multi-hop forwarding is superseded by **Not protected in the audited
> implementation / fail-closed containment in progress**. The adversary
> descriptions remain useful; they are not release evidence.

**Status:** Audited design record under the RVN1 production hold. The detailed
verdicts below describe the intended/frozen design and are **not release
claims**. The executable posture in the table immediately below is normative;
it supersedes every older `Protected` label until the corresponding gate is
closed. `raven-security/THREAT_MODEL.md` is retained only as a pre-pivot
historical snapshot.

### Current executable posture (2026-08-13)

| Area | Current verdict | Evidence / remaining gate |
|---|---|---|
| Content confidentiality | **Fail-closed, not production-enabled** (except the LAN-direct slice, see its row below) | Public-material demo sealers are disabled and plaintext carrier admission is rejected. Outside the LAN-direct slice, a transcript-bound, persisted ATSAM session is not yet active. |
| Message/ACK endpoint acceptance | **Fail-closed, production-disabled** | Rust and Swift (**OFF-MAIN**, unverified from this tree) reference actors now verify PairInit-bound device certificates, route/AAD/AEAD, exact inbox/outstanding rows, sealed ACKs, replay state, and recoverable message/ACK journals. Swift concrete Keychain/SQLCipher/queue adapters, a bound ACK sender, live wiring, and external review remain gates; the Rust actors are wired live only for the LAN-direct slice below. |
| Relay/store opacity | **Partially implemented** | Queues store immutable opaque envelopes and deduplicate by authenticated-object digest. Production route/mailbox keys still require the authenticated session actor. |
| Replay/dedup | **Implemented in disabled reference actors** | Relay cache poisoning by attacker-chosen IDs is contained. Rust and Swift (**OFF-MAIN**) reference actors commit authenticated object/logical-ID/ACK-nonce replay state with their ratchets; live paths remain disabled (except the LAN-direct slice below) until concrete adapters and integration pass review. |
| Resource exhaustion | **Bounded at audited wire boundaries** | Go bridge and raw Rust TCP handlers cap streams/handlers, declared bytes, frame size, and deadlines before allocation. The gated NAT profile also caps pending/established/per-peer connections and AutoNAT candidates. Peer scoring/Sybil resistance remains future work. |
| Hop/replication ceilings | **Cooperative-policy only** | RVN1 does not authenticate mutable hop fields. No Byzantine forwarding bound is claimed until a versioned custody wrapper exists. |
| Revocation freshness | **Partition-limited** | Local deny lists and certificate expiry work; V1 has no globally fresh signed revocation distribution guarantee. |
| LAN-direct slice (terminal to terminal) | **Live in default builds; unreviewed; not a release claim** | `raven_core::lan_gate::LAN_DIRECT_PRODUCTION_ENABLED = true` runs Noise XX, RLB1 identity binding, PairInit V1, indexed-session v1 and sealed ACKs between `raven-node service` daemons on a LAN; the four global `PRODUCTION_ENABLED` flags (PairInit, session store, prekey lifecycle, ATSAM indexed session) stay `false`. **Trust model:** the local contact book only (`peer_is_trusted`: any `contacts.json` key, pinned or not; fingerprint pinning is not enforced) plus the Noise-to-RLB1 identity binding. **Known limits:** no one-time prekeys are installed, so first-contact forward secrecy is bounded by signed-prekey rotation alone ([`RAVEN_PREKEY_LIFECYCLE_V1.md`](../protocol/RAVEN_PREKEY_LIFECYCLE_V1.md) §6); IP addresses, timing and sizes are visible on the wire (§3.4, §3.17); the in-tree CI proof is Linux-only and uses the debug `locked-file` identity override (`scripts/lan_direct_two_node.sh`). **Errata gates still open for it:** monotonic one-time-prekey consumption, Rust/Swift fixture exchange (Swift is off-main), the real-device matrix and the external review; the other release-gate items have not been assessed for this slice here, so their omission is not a pass. |
| Release status | **HOLD** | iOS Release hard-disables RVN1, default Rust origination requires an authenticated session, and the external security review/real-device matrix has not happened. |

This document explains, in plain language, what RAVEN is designed to protect
and what it explicitly does not protect, for the serverless peer-to-peer
architecture: no trusted central server, delivery via mesh relays and
untrusted store-and-forward nodes, addressing via a DHT-backed alias layer,
and a single frozen wire object (`RavenEnvelopeV1`) carried unchanged across
every transport.

Honest scope statements are part of the security boundary, not a marketing
afterthought. A verdict of **partially protected** or **out of scope** next
to an adversary is not an admission of failure — it is the document doing
its job. Overclaiming is the actual defect.

Every citation below points at a committed, frozen spec in `protocol/` or a
byte-exact test vector in `shared-vectors/rvn1/`, or at a specific shipped
source file — except citations tagged **OFF-MAIN** (the `ios-native/…`
Swift/Go paths), which refer to a tree that is not in this repository and are
unverified-from-main: they are not evidence for this checkout (same convention
as [`crypto/ATSAM_KAT_CONSUMER_MATRIX_V1.md`](crypto/ATSAM_KAT_CONSUMER_MATRIX_V1.md)).
If a citation and the shipped code ever disagree, the code is
wrong until proven otherwise — see §4.

---

## 1. Assets we protect

RAVEN's serverless design exists to protect:

1. **Message content.** What people say to each other, end-to-end, at rest
   in transit through every relay and store node, no exceptions.
2. **Recipient identity at the relay/store layer.** A relay or store node
   handling an envelope should not learn who it is addressed to.
3. **Nearby-peer discovery privacy.** Who is in radio/network range of whom,
   in the eyes of someone who is not the user's contact.
4. **Long-term content secrecy for opted-in (Vault Mode) messages.** A
   message a user marks Vault Mode should remain confidential against
   future computational advances (including large-scale quantum
   computation), provided the pad conditions are met.

RAVEN does **not** primarily exist to protect:

- The fact that some traffic exists, or its timing/volume/shape.
- A user's identity or data on a device the user has already lost physical
  control over while unlocked.
- Uniqueness of human-readable names (the alias namespace is deliberately
  not globally unique — see §3.13).

---

## 2. How to read the table

Every row below is one of the 17 adversary classes in scope for this
document. **Verdict** is one of:

- **Protected** — a concrete, cited mechanism defeats this adversary for the
  stated goal.
- **Partially protected** — some sub-case is defended with a cited
  mechanism; another sub-case is explicitly out of scope, stated with a
  reason.
- **Out of scope** — RAVEN does not defend against this today. The reason is
  stated, and, where one exists, the future-work item that would change the
  verdict.

| # | Adversary | Verdict | Mechanism / reason |
|---|---|---|---|
| 3.1 | Malicious relay | Design target; production held | Opaque envelope/object queue exists; authenticated session-derived encryption and routing are not live |
| 3.2 | Malicious store node | Design target; production held | Opaque TTL store exists; mailbox derivation is vector-only and ACK deletion is forbidden |
| 3.3 | Malicious peer (direct connection) | Partially protected | Strict parser plus bounded Go/Rust connection, byte, deadline, and gated NAT admission; endpoint reference transaction exists but is not live |
| 3.4 | Passive ISP | Partially protected | Transport Noise hides envelope bytes; connection metadata still visible |
| 3.5 | Active MITM | Partially protected | QR pairing + safety number; wrong-person pairing is user's responsibility |
| 3.6 | Stolen locked device | Partially protected | iOS roots use device-only Keychain; terminal backend strength is platform-dependent |
| 3.7 | Stolen unlocked device | Out of scope | Endpoint sets the floor |
| 3.8 | Sybil swarm | Partially protected | Peer/store diversity + replication budget; Peer ID ≠ identity; full defense is future work |
| 3.9 | Eclipse attacker | Partially protected | Same mitigations as Sybil; full defense is future work |
| 3.10 | Replay attacker | Design implemented; production held | Relay object-digest cache and disabled Rust/Swift authenticated endpoint replay journals are bounded; concrete live integration remains |
| 3.11 | Spam attacker | Partially protected | Contact-first + message requests + blocking; no central moderation (by design) |
| 3.12 | DHT poisoning | Partially protected | Signed/versioned/expiry-bound/size-limited records |
| 3.13 | Alias impersonation | Design target | Identity-signed aliases exist; live discovery acceptance still needs the final session/device binding audit |
| 3.14 | Downgrade attacker | Incomplete; production held | Capabilities are signed, but the exact indexed-session profile must be transcript-bound by PairInit |
| 3.15 | Malformed-packet attacker | Partially protected | Strict cross-language envelope parsing and bounded framing are implemented; endpoint state-machine fuzzing remains |
| 3.16 | Local malware | Out of scope | Endpoint sets the floor |
| 3.17 | Traffic analyst | Out of scope | Explicit non-goal of the routing-tag design; future work |

---

## 3. Adversary detail

### 3.1 Malicious relay

**Can do:** Run a mesh (BLE) or bridge (libp2p) relay node and forward
`RavenEnvelopeV1` traffic between strangers, with no trust relationship to
either party.

**Verdict: Design target; production held.**

**Intended mechanism:** RAVEN uses two independent encryption layers. Message content is
to be sealed by the recipient's session key before it ever reaches a relay
(`protocol/RAVEN_ENVELOPE_V1.md` §5, "No plaintext identities on the wire");
the recipient locator carried alongside it is not a stable identifier but a
rotating HMAC tag (`protocol/RAVEN_ROUTING_TAG_V1.md` §1–2) that changes
every message. A relay sees only `message_id` (meaningless CSPRNG),
`routing_tag` (rotates, unlinkable without `K_route`), and two opaque
ciphertext blobs. It cannot decrypt, cannot determine whether two envelopes
it has forwarded belong to the same conversation, and cannot forge
authorship: every immutable field is bound into the Ed25519 signature over
`signing_bytes` (`protocol/RAVEN_ENVELOPE_V1.md` §2), so a relay tampering
with `message_ciphertext` produces a signature that fails verification
(vector: `shared-vectors/rvn1/negative/envelope_tampered_body.json`,
`verify_result: reject`). A malicious relay also cannot forge a delivery
receipt on the recipient's behalf: `RavenAckV1` carries its own signature
under the acknowledging device's key, checked independently of the outer
envelope (`protocol/RAVEN_ACK_V1.md` §2; vector:
`shared-vectors/rvn1/negative/ack_wrong_signer.json`,
`verify_result: reject`).

**Current executable boundary:** the publicly derivable interim sealer and
unverified delivery transitions are disabled. Production-disabled Rust and
Swift actors implement the transcript-bound indexed session and recoverable
inbox/ACK transaction, but they have no approved live transport/UI wiring, so
the statements above remain design/test evidence rather than production claims.

**What still leaks:** Envelope size and forwarding timestamp at that relay.
That is a traffic-analysis question, addressed (and scoped out) at §3.17.

### 3.2 Malicious store node

**Can do:** Operate an offline-store relay that holds envelopes for
recipients who are not currently reachable, and inspect or tamper with
whatever it stores.

**Verdict: Design target; production held.**

**Intended mechanism:** A store node is architecturally the same untrusted party as a
relay (§3.1) — it never receives `K_route`, which lives only in the two
endpoints' key trees. A recipient explicitly presents a separately derived,
daily rotating `store_tag`; the store can link every access and object using
that same tag during its day window, as well as the source libp2p Peer ID, but
cannot derive another day's tag or map the capability to a Raven address. Vector
`shared-vectors/rvn1/routing/tag_unlinkable_001.json` demonstrates that two
tags derived from the same `K_route` at adjacent counters are structurally
unrelated byte strings. Content and authentication protections are
identical to §3.1.

**Current executable boundary:** the store validates strict opaque envelopes,
uses separately derived mailbox tags, enforces count/byte/stream/time limits,
persists atomically, and deletes only by TTL. A production-disabled libp2p
PUT/GET service proves sender-disconnect/store-restart/recipient retrieval.
Session-derived live mailbox keys, multi-store discovery/replication, and
authenticated endpoint retrieval are still held.

**What still leaks:** Size/timing, same-day tag reuse, source Peer ID, and how
long an envelope sat there before being claimed (queue-depth side channel).
These are not separately defended in V1.

### 3.3 Malicious peer (direct connection)

**Can do:** Open a direct libp2p stream or BLE GATT connection to a node
without being an authorized contact, and send it arbitrary bytes.

**Verdict: Partially protected.**

**Intended endpoint gate:** Once a frame reaches the envelope pipeline, the
required order is size → strict decode → TTL → local route/session → outer
authentication → AEAD open → transactional commit. Current release
containment rejects unknown or undecryptable bodies and emits no ACK. Disabled
Rust and Swift reference actors exercise this complete order and its crash
matrix, but the transaction is not active in the app/node, so this is not a
production claim.

**Current boundary:** the earlier pre-validation allocation gap is closed at
the audited transport layer. The Go bridge reserves nonblocking per-peer and
global stream/declared-byte budgets before allocation, bounds idempotency
keys, resets malformed or stalled streams, and releases reservations on every
exit. The raw Rust TCP listener independently enforces a 1 MiB frame ceiling,
64-handler global cap, idle/frame/write/lifetime deadlines, and exact reads.
These controls bound one peer's pre-parser resource footprint; they do not
replace authenticated endpoint admission, peer scoring, or Sybil resistance.

### 3.4 Passive ISP

**Can do:** Observe all traffic between a device and the internet — e.g. a
network operator, an ISP, or a Wi-Fi hotspot operator — for internet-bridge
(libp2p) traffic.

**Verdict: Partially protected.**

**Why (protected sub-case):** On the Rust side, the libp2p smoke host
(`node/crates/raven-swarm`) secures TCP with Noise and QUIC with libp2p's own
TLS-based transport security (not Noise), and the LAN-direct carrier is Noise
XX (`raven_core::lan_noise`). An on-path ISP therefore sees an encrypted
transport stream, not `RavenEnvelopeV1` bytes in the clear: it cannot read the
routing tag, the ciphertext, or the magic bytes without breaking the
transport-layer handshake. The original claim that the iOS/Go libp2p bridge
host uses `libp2p.DefaultSecurity` (Noise + TLS) cites
`ios-native/RAVEN/Libp2pBridge/bridge.go:135` (**OFF-MAIN**, unverified from
this tree). This is on top of, and independent from, the message-level E2EE
described in §3.1 — two layers, as stated in §1's asset list.

**Why (out-of-scope sub-case):** Transport encryption hides *content*, not
*shape*. An ISP still observes which IP addresses a device connects to, at
what times, for how long, and how many bytes flow. `protocol/
RAVEN_ROUTING_TAG_V1.md` §4 states this explicitly as a non-goal: routing
tags resist linkage at the tag-value layer, not global traffic analysis.
Defeating this requires cover traffic / padding / timing obfuscation, which
is future work (the `coverTraffic` capability bit referenced in
`protocol/RAVEN_CAPABILITIES_V1.md` is a placeholder for this, not a shipped
defense). See §3.17.

### 3.5 Active MITM

**Can do:** Sit on the network path during pairing or session setup and
attempt to substitute their own key material for a legitimate contact's.

**Verdict: Partially protected.**

**Protected sub-case:** a correctly scanned in-person QR code and a manually
compared safety number provide an out-of-band identity check. Signed device
certificates, prekey bundles, envelopes, and capability records prevent an
on-path party from altering those exact authenticated records unnoticed.

**Current boundary:** PairInit V1 now byte-binds the two device certificates,
responder prekey, hybrid contributions, roles, profile, and suite. It is
byte-for-byte verified by Python, Rust, and Swift (Swift is **OFF-MAIN**, unverified from this tree) but remains
production-disabled pending a confidential carrier, protected durable endpoint
state, one-time-prekey lifecycle, and external review. Older ad-hoc
pairing code is not evidence that every live message path has this binding.

**Why (user-responsibility sub-case):** Cryptographic pairing verifies "the
key I now hold matches the key the other device holds" — it cannot verify
"the human on the other end is who I think they are." An attacker who
successfully impersonates a contact during the in-person QR exchange itself
(e.g. a fake QR code, a compromised video-call impersonation) defeats
pairing at the human layer, not the cryptographic layer. This is explicitly
the user's responsibility, matching the pre-pivot model's §3.4. We also note
`SafetyNumberView.swift`'s (**OFF-MAIN**) own comment marks automated QR-based safety
number re-verification as a TODO; today the safety-number check is a manual
compare-in-person-or-by-call flow, not an automated re-scan.

### 3.6 Stolen locked device

**Can do:** Gain physical possession of a device that is powered on but
locked (passcode/biometric not entered).

**Verdict: Partially protected; platform-dependent.**

**Why:** iOS roots are Keychain-backed, device-only, and excluded from
backup. Rust identity/session storage uses Keychain on macOS and DPAPI on
Windows. On Linux, existing glibc Secret Service identities load, but identity
**creation is disabled in Release builds pending R1** (musl and other Unix
targets have no protected identity backend), so a Release Linux install cannot
create an identity today. The `0600` `locked-file` seed
(`RAVEN_IDENTITY_BACKEND=locked-file`) is a debug/lab/CI-only override that
Release builds refuse; it is not an approved fallback. The protected session
store is refused when no supported backend exists.

**Limit:** the current iOS root accessibility is
`AfterFirstUnlockThisDeviceOnly`. After the first unlock following boot, that
class can remain available while the screen is locked. It prevents simple
file-copy extraction but is not a claim that keys are cryptographically
unavailable throughout every locked interval. Notification previews, OS
compromise, memory capture, backup policy, and each desktop keyring's lock
state remain platform concerns.

### 3.7 Stolen unlocked device

**Can do:** Gain physical possession of a device that is unlocked, or
compel the owner to unlock it.

**Verdict: Out of scope.**

**Why:** Once an attacker holds an unlocked device, they can read anything
the legitimate user's UI can display, and any key material Keychain
protection classes release for an unlocked device. No protocol-level
mechanism can distinguish "the legitimate user is looking at this screen"
from "an attacker is looking at this screen." This mirrors the pre-pivot
model's §3.6 (coercion/lawful access) — the floor is set by the endpoint's
OS-level unlock security, not by RAVEN.

### 3.8 Sybil swarm

**Can do:** Create a large number of cheap, independently-addressed peer
identities and use them to dominate a target's connection slots, routing
table, or store-node selection.

**Verdict: Partially protected.**

**Protected sub-case:** audited Go and Rust ingress paths enforce hard
connection/handler, stream, frame-byte, deadline, and aggregate-store limits.
These constrain resource use by each admitted transport identity.

**Cooperative-only fields:** `replication_budget` and `hop_limit` help honest
routers but are excluded from the RVN1 sender signature. A Byzantine relay can
reset them, and they therefore provide no Sybil security bound.

**Why (out-of-scope sub-case, stated honestly):** RAVEN does not yet
implement peer scoring, per-remote connection-count limits, or diverse
peer/store selection policy that would make a Sybil swarm's cost outweigh
its benefit — no such mechanism exists in the codebase as of this document.
A libp2p Peer ID is a hash of a locally-generated keypair, not an
authenticated identity; nothing prevents an adversary from generating many
Peer IDs cheaply. Full Sybil resistance (peer reputation, resource-bound
identity issuance, or a trusted bootstrap set) is future work, tracked
alongside the DHT hardening in §3.12.

### 3.9 Eclipse attacker

**Can do:** Surround a target node with adversary-controlled peers so that
all of the target's DHT/mesh connections go through the attacker, enabling
selective censorship or feeding the target a manipulated view of the
network (e.g. poisoned alias records, withheld envelopes).

**Verdict: Partially protected.**

**Why:** Signed DHT records prevent a surrounding attacker from forging the
record owner, but do not force that attacker to return or forward records.
RAVEN does not yet implement diverse/independent peer selection,
connection-count limits per subnet, or any other structural defense
specifically against eclipse positioning — this is the same gap as §3.8,
under a different attack goal (isolate rather than merely flood). We are
not claiming a censorship defense that does not exist. The unauthenticated
RVN1 hop fields do not change this result.

### 3.10 Replay attacker

**Can do:** Capture a valid, signed envelope and resend it later, hoping to
cause duplicate delivery or reuse of stale state.

**Verdict: Incomplete; production held.**

**Current protection:** strict TTL validation, immutable-object relay caches,
monotonic queue transitions, and bounded ratchet prototypes have negative
tests. Relays no longer durably deduplicate on an attacker-chosen public
message ID alone.

**Remaining gate:** endpoint replay acceptance must be committed atomically
with authenticated AEAD open, receive-ratchet/skipped-key state, inbox dedup,
and ACK-outbox intent. The indexed protected Rust store advances ratchets
without rollback, but it is deliberately not yet coupled to an inbox
transaction. Until that actor exists on both Rust and Swift, replay defense is
not production-complete.

### 3.11 Spam attacker

**Can do:** Send unsolicited messages or connection/pairing attempts to
users who have not established a relationship with the sender.

**Verdict: Partially protected.**

**Why:** RAVEN's serverless design is contact-first: an unknown sender's
first message surfaces as a message request rather than landing directly in
an established conversation, and a recipient can block a contact or remove
them (removing per-pair key material — see the "swipe-to-remove a contact"
serverless key cleanup shipped in this branch). This raises the cost of
unsolicited contact relative to an open, discoverable inbox.

**Why not fully protected, stated plainly:** There is no central,
cross-user moderation layer, no shared spam-reputation service, and no
network-wide rate limiter — because there is no central operator to run
one. This is not an oversight; it is the direct, honest cost of removing
the central server. A traditional centralized messenger's server is
simultaneously its metadata-collection risk *and* an implicit anti-spam/
anti-abuse chokepoint (it can globally rate-limit an account, ban a
fingerprint, or throttle a sender across all recipients at once).
Decentralizing removes both at the same time. Per-identity local rate
limiting and per-contact blocking are local, per-recipient defenses, not a
network-wide one — a spammer blocked by one recipient is not thereby
blocked anywhere else.

### 3.12 DHT poisoning

**Can do:** Inject false, stale, or oversized records into the DHT used for
alias resolution, attempting to redirect lookups, exhaust store capacity, or
squat abandoned names.

**Verdict: Partially protected.**

**Why:** `protocol/RAVEN_ALIAS_V1.md` §4 requires every published alias
record to satisfy four constraints simultaneously: **signed** (unsigned
records are discarded on receipt — nothing else binds the claim to an
identity); **versioned** (`sequence` is the version; replacement in the
store is keyed by `(alias, identity_address)` with last-write-wins by
`sequence`, never by receipt order, because receipt order is not
trustworthy in a store with multiple untrusted writers); **expiry-bound**
(a resolver treats a record as absent past `expires_at`, preventing
indefinite squatting of an abandoned name); and **size-limited** (both
variable-length fields are length-prefixed, and a store SHOULD impose a
practical cap well below the 65,535-byte theoretical ceiling, since nothing
resembling a human-typed alias needs to approach it). A stale-record replay
specifically is covered by the same monotonic-sequence rule as §3.13 (vector
`shared-vectors/rvn1/negative/alias_stale_sequence.json`).

**What is not yet covered:** Broader DHT-level resistance — e.g. an
adversary who controls enough of the DHT's keyspace neighborhood to
withhold or selectively serve records regardless of their validity (a
Kademlia-style routing attack, closely related to §3.8/§3.9) — is future
work, not addressed by record-level signing alone.

### 3.13 Alias impersonation

**Can do:** Attempt to claim, hijack, or roll back a human-readable alias
that legitimately belongs to someone else.

**Verdict: Partially protected; alias is discovery, not trust.**

**Why:** Every accepted alias record is self-signed by the identity it claims to
belong to — signed by `identity_address`'s own Ed25519 identity key over
domain-separated bytes (`protocol/RAVEN_ALIAS_V1.md` §1) — so an attacker
without that private key cannot forge a claim for someone else's address. A
captured, validly-signed *older* record cannot be replayed to roll an alias
back: a verifier holding a record at `sequence=N` for an alias must reject
any incoming record for the same alias/identity with `sequence <= N`, even
if validly signed (`protocol/RAVEN_ALIAS_V1.md` §2; vector:
`shared-vectors/rvn1/negative/alias_stale_sequence.json`,
`resolver_action: reject_stale`). When a lookup for a previously-resolved
alias returns a *different* address than last seen and pinned, the spec
requires surfacing a key-change warning before delivering to or trusting
the new identity — treated with the same severity as a contact's
fingerprint changing (`protocol/RAVEN_ALIAS_V1.md` §3, cross-referencing
`protocol/RAVEN_IDENTITY_V1.md` §3). Conflicting live claims for the same
alias string (a namespace-ambiguity case, not impersonation of a specific
identity — the namespace has no registrar and is not unique by design) MUST
be surfaced as ambiguous, never silently resolved by a predictable
tie-break, since a predictable tie-break is itself attacker-exploitable.
This proves control of that Raven identity, not the human's real-world name.
Only a pinned address/fingerprint or out-of-band verification establishes a
trusted contact; live alias discovery cannot silently replace that binding.

### 3.14 Downgrade attacker

**Can do:** Sit on-path or control a relay and attempt to force two peers
into negotiating a weaker capability set than both actually support (e.g.
stripping a post-quantum-hybrid or delivery-authentication bit).

**Verdict: Incomplete; production held.**

**Current protection:** `protocol/RAVEN_CAPABILITIES_V1.md` replaces the legacy unsigned
BLE `Capabilities` advertisement — which any on-path relay could read or
alter without either side detecting it (§2, citing
`ios-native/RAVEN/RAVEN/Core/Mesh/RUMProtocolV2.swift:155-218`, **OFF-MAIN**) — with a
self-signed, identity-bound, time-bound record. A verifier caches the
freshest signed capability set seen for a given identity and refuses to
silently accept a lower-capability claim unless that claim is itself
freshly signed and unexpired (§3): an attacker cannot replay an old,
validly-signed, lower-capability record once its `expires_at_ms` has
passed, and cannot forge a new one without the identity's private key.

**Remaining gate:** a signed record by itself does not bind the suite actually
used by a session. PairInit V1 now transcript-binds the exact suite, roles,
profile, certificates, and prekey contribution, but is production-disabled.
V1's capability record also has no
monotonic sequence field (unlike alias records) — freshness relies on
`expires_at_ms` alone. Two differently-signed records with *overlapping*
validity windows have no defined tie-break in V1; the spec recommends
negotiating to the intersection of claimed bits until a future version adds
a sequence field. This is a stated scope gap, not a vector-backed guarantee.

### 3.15 Malformed-packet attacker

**Can do:** Send a structurally invalid, truncated, oversized, or
field-tampered `RavenEnvelopeV1` frame to a peer, relay, or store node.

**Verdict: Partially protected.**

**Implemented boundary:** Rust and Swift envelope decoders reject oversized,
unknown-type, unknown-flag, invalid-time, non-64-byte-auth, length-overflow,
trailing, and truncated objects before endpoint logic. Go and Rust transport
admission bounds declared sizes and stalled reads before allocation. Existing
negative vectors cover bad magic, tampering, expiry, and framing.

**Remaining gate:** the production-disabled PairInit, indexed session state,
ACK codec, store request protocol, and complete endpoint state machine still
need sustained fuzz campaigns and cross-platform stateful fuzzing. Therefore
strict envelope parsing is implemented, but malformed-input protection for
the whole future endpoint is not yet a complete claim.

The corrected endpoint order in
`protocol/ATSAM_ENDPOINT_TRANSACTION_V1.md` is size → strict decode/type/time →
bounded session/tag candidate → outer device authentication → read-only
object duplicate check → AEAD open → recoverable ratchet/inbox/dedup/ACK-intent
commit → ACK worker. Attacker-chosen IDs are not durably inserted before
authentication. A zeroed magic byte is
rejected at decode (vector:
`shared-vectors/rvn1/negative/envelope_bad_magic.json`,
`unpack_result: reject`); a body altered after signing fails at the
authenticate stage because the appended `SHA-256(message_ciphertext)` no
longer matches what was signed (vector:
`shared-vectors/rvn1/negative/envelope_tampered_body.json`,
`verify_result: reject`); an expired envelope is dropped at the TTL stage
before authentication is even attempted (vector:
`shared-vectors/rvn1/negative/envelope_expired.json`,
`relay_action: drop`).

The earlier allocate-before-validate bridge issue is closed by preallocation
budgets and exact length limits; it remains covered by regression tests.

### 3.16 Local malware

**Can do:** Run arbitrary code with the legitimate user's OS-level
privileges on the user's own device — a jailbreak, a malicious app with
excessive permissions, or a supply-chain-compromised dependency.

**Verdict: Out of scope.**

**Why:** Once an attacker can execute code as the user, they can read
whatever the app can read, including decrypted plaintext and any key
material the OS releases to a running, authorized process. No
application-layer protocol can defend against a fully compromised endpoint
— this is the same floor as §3.7, restated for a software rather than
physical attack vector. Endpoint integrity (OS sandboxing, code signing,
jailbreak detection) is the user's and the OS vendor's responsibility, not
a RAVEN protocol guarantee.

### 3.17 Traffic analyst

**Can do:** Observe connection metadata — who connects to whom, when, how
often, and how much data flows — across relays, store nodes, or the
internet bridge, without necessarily controlling any of them, and correlate
that shape over time.

**Verdict: Out of scope for V1.**

**Why:** `protocol/RAVEN_ROUTING_TAG_V1.md` §4 states this as an explicit
non-goal: routing tags resist linkage *at the tag-value layer* — an
observer cannot tell from tag bytes alone that two envelopes share a
recipient — but they do not resist *global traffic analysis*. An adversary
watching timing, volume, envelope size, and network position across the
system can still correlate flows through side channels the tag design does
not touch (e.g. "an envelope of size X leaves peer A one hop before an
envelope of similar size arrives at peer B"). This is the same underlying
gap named in §3.4 (passive ISP) and §3.8/§3.9 (Sybil/eclipse positioning
enabling better vantage points for exactly this kind of correlation).
Closing it requires cover traffic, batching, or timing obfuscation; the
`coverTraffic` capability bit referenced in
`protocol/RAVEN_CAPABILITIES_V1.md` exists as a negotiation placeholder for
this future work, not a shipped defense today.

---

## 4. How we treat this document

This file is part of the security boundary, not marketing copy, carrying
forward the same posture as its pre-pivot predecessor.

If a finding shows that a claim in this document does not match the
behavior of the shipped protocol or app, we will:

1. Fix the document to match reality first.
2. Then fix the implementation.
3. Acknowledge the gap publicly.

In that order. An outdated "protected" claim that no longer matches shipped
behavior is a more serious defect than an honestly-stated gap — fix the
claim before anyone relies on it.

Every **protected** or **partially protected** verdict above cites either a
frozen `protocol/*.md` section, a specific `shared-vectors/rvn1/` vector
file, or a specific shipped source file and line. Every **out of scope**
verdict states its reason. If a future change to `protocol/` or the shipped
apps invalidates a citation here, update this document in the same change —
do not let the citations drift from what is actually running.
