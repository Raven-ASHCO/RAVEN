# Terminal transports: Internet (direct, relay, hole punching), bridge and mesh on Windows, Linux and macOS

| | |
|---|---|
| **Status** | Design proposal for owner decision. Not normative: it changes no flag, wire format, frozen spec or vector by itself. |
| **Date** | 2026-10-08 |
| **Owner decisions applied** | 2026-10-08: terminals first (Windows, Linux, macOS); Swift/iOS out of scope for now; "every node can be a relay" (anyone with a public IP or VPS runs `raven-node` in relay mode; others use libp2p Circuit Relay v2 plus DCUtR); no central server; Linux keys in Secret Service or an Argon2id passphrase vault (in progress) |
| **Scope** | The terminal send and receive path over LAN direct, Internet direct, libp2p (direct, relayed, hole-punched), opaque bridge store-and-forward and multi-hop terminal mesh, plus an offline mailbox |
| **Baseline** | `file:line` citations refer to commit `dd296bd` (`fix/code-review-2026-09-29`). Another engineer was editing the working tree while this was written: the Linux keystore work in `raven-core` (`Cargo.toml`, `identity_store.rs`, `chat_history.rs`, `indexed_session_store.rs`, `ipc.rs`, `lib.rs`, `prekey_lifecycle.rs`, new `keystore_*.rs`) and `node/scripts/install/macos_launchd.sh`. Citations into those files were re-checked against `dd296bd`; re-check them before acting. |
| **Sibling designs** | [`2026-10-ratchet-fs-pcs.md`](2026-10-ratchet-fs-pcs.md) (session ratchet), [`2026-10-per-device-keys.md`](2026-10-per-device-keys.md) (device keys, RLB2), [`2026-10-daemon-owned-secrets.md`](2026-10-daemon-owned-secrets.md) (IPC v2, daemon-side send), [`2026-10-linux-keystore.md`](2026-10-linux-keystore.md) (Secret Service / Argon2id vault; untracked draft at the time of writing) |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](../WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md); each phase below needs its own recorded waiver or review (§5) |

Path shorthand: `core/` = `node/crates/raven-core/src/`, `rn/` = `node/crates/raven-node/src/`, `ash/` = `node/crates/ash/src/`, `swarm/` = `node/crates/raven-swarm/src/`, `inst/` = `node/scripts/install/`, `proto/` = `protocol/`, `wf/` = `.github/workflows/`.
Markers: **(guess)** is an estimate or a judgement with no measurement behind it. **(verify)** is a claim about an external library or OS that I did not check against the primary source while writing.

## 0. Summary

- **Today only LAN direct carries real traffic** (`core/lan_gate.rs:8`). Internet direct is a complete lab path behind one flag (`core/internet_gate.rs:9`). The libp2p host has no relay server, keeps relay client, DCUtR and AutoNAT behind a feature and a runtime flag, and carries no Raven payload. The bridge forwards raw unauthenticated TCP frames between a LAN listener and a mock BLE listener, both bound to loopback in `raven-node service`. CI has never moved a real `0x03` envelope through it: the A-B-C demo builds with `unsafe-demo-crypto`.
- **Proposed architecture:** one endpoint session layer (PairInit V1 + RVNA1 `0x03` today, the ratchet profile later) over five carriers chosen per contact. A **durable outbox worker inside `raven-node`** retries the exact staged bytes on every carrier until the first verified ACK or expiry. It replaces "retry on the next `ash send`".
- **Internet:** libp2p is only a connectivity substrate (TCP/QUIC, Circuit Relay v2, DCUtR, AutoNAT). The Raven link always runs the existing Raven Noise XX plus a channel-bound RIH1 hello **inside** a libp2p stream, so the libp2p PeerId never has to be trusted and a relay sees only ciphertext. PairInit travels only inside such an end-to-end link. That makes it a confidential carrier in the sense of `proto/RAVEN_PAIR_INIT_V1.md` §7. It is never placed in a relay-readable or store-readable body.
- **Bridge and mesh:** mesh hops are authenticated Raven links between mutual contacts. Hop budgets move into a new hop wrapper (`RHW1`), so the endpoint bytes are never mutated. Admission allows only sealed `0x03` messages and ACKs, never PairInit. Routing is blind, budgeted spray with dedup by object digest.
- **Six problems found while verifying (§1.7)** that the plan must fix first:
  1. The public `dest_device_hint` names the recipient to every relay.
  2. Envelopes are valid for only 1 hour.
  3. The bridge would forward a PairInit today.
  4. The Internet responder sends its identity and prekey bundle to any stranger who completes Noise.
  5. Public Kademlia peer records let anyone locate a Raven ID.
  6. **Sessions last 24 h and PairInit needs a confidential carrier.** A contact pair that can only reach each other through a store-and-forward bridge therefore loses its session within a day and cannot re-pair.
- **Recommended order** (it deviates from the suggested P1-P4, see §7.7):
  - P0: hardening and a portable carrier test harness.
  - P1: Internet direct with explicit addresses, in parallel with P2a, the background outbox.
  - P3: libp2p relay plus hole punching. This is the first phase that helps most NAT'd users, and it is also the confidential pairing path for them.
  - P2b: bridge carrier.
  - P4: multi-hop mesh plus mailbox.
- **Total effort:** about 100-145 engineer-days **(guess)**. P1 can ship in about 3 weeks (P0 + P1). Every phase needs a recorded waiver extension or an independent review, plus its physical row, before its flag flips (§5).

## 1. Current state (verified)

### 1.1 The live slice: LAN direct

| Element | Where | Note |
|---|---|---|
| Gate | `core/lan_gate.rs:8` `LAN_DIRECT_PRODUCTION_ENABLED = true`; generic tripwires stay false (`:20-27`) | Covered by the waiver, which excludes every other carrier (waiver §2) |
| Link | `rn/lan_direct.rs:1-8`, responder `:209-223`, inbound `:225-300`, `run_listener` `:331`, `dial` `:520` | Noise XX; static key = HKDF of the identity seed (`core/lan_noise.rs:52-60`); signed bind (`encode_bind`/`verify_bind`, `rn/lan_direct.rs:199-221`) |
| RLB1 offer | `core/lan_rlb1.rs:10-24` (max `65519` B, `:16`) | Cert + prekey bundle, exchanged both ways inside Noise |
| Dispatch | `core/lan_dispatch.rs:1527-1568` `dispatch_frame`: RLB1, PairInit (magic sniff `core/pair_init_lan_oob.rs:59-67`), message `:1372-1486`, ACK `:1488-1519` | Messages and ACKs only from local contacts (`:1378`, `:1489`) |
| Session | PairInit V1 `core/pair_init.rs:73` (2788 B); RVNA1 proto `0x03` `core/atsam_indexed_session.rs:35`; lifetime 24 h `core/lan_dispatch.rs:1825` | No FS or PCS inside a session (`proto/ATSAM_INDEXED_SESSION_PROFILE_V1.md` §2.4) |
| Sealed ACK | Enqueued after commit `core/lan_dispatch.rs:1470-1481`; returned as a reply frame on the same connection | The queue callback is a no-op (`:1479`): nothing carries an ACK if that connection drops |
| Inbound limits | `rn/main.rs:737-744` (32 conns, 8/IP, 4 handshaking/IP, 64 frames, 120 s, 10 s handshake) | Shared by LAN and Internet direct |

### 1.2 Internet direct (lab only)

- Gate `core/internet_gate.rs:9` `INTERNET_DIRECT_PRODUCTION_ENABLED = false`. Its tests assert the flag *and* `!internet_direct_live_enabled()` (`:21-41`), so flipping the flag requires rewriting them.
- Codec `core/internet.rs`:
  - Prologue `raven/internet/v1` (`:24-28`).
  - RIH1 hello signed over role, caps, the handshake hash, the Noise static and the Ed25519 key (`:124-135`). Verified with `verify_strict` (`:157-174`).
  - Replay, reflection and wrong-static tests at `:327-367`.
- Live path `rn/internet_direct.rs`:
  - The dialer requires hello identity == expected (`:239-242`) and RLB1 == hello identity (`:520-526`).
  - The responder verifies *any* initiator, then sends its own hello (`:270-276`) and its RLB1 offer (`:339`) whether or not the initiator is a contact; `trusted` only changes the admission slot (`:336-338`).
  - The same dispatcher as LAN (`:367`). Gate `HOLD` `:52-54`.
- Service flag `--internet-listen` (empty means off), `rn/main.rs:1822-1825`, `:3413-3420`. The installers never pass it (`inst/linux_systemd_user.sh:79`, `inst/windows_service.ps1:82`, `inst/macos_launchd.sh:66-78` at `dd296bd`; `:69-81` in the working tree).
- IPC op `InternetDial` exists (`core/ipc.rs:52-59`, `rn/ipc_server.rs:504-545`). ash already has `DialCarrier::Internet` (`ash/pair_init_lab.rs:105-119`) behind a hidden `--carrier internet` flag (`ash/cli.rs:351-354`). The gate refusal is at `ash/ext.rs:2154-2156`.
- Evidence: `node/scripts/internet_indexed_two_node.sh` runs in the Linux and macOS jobs, on loopback only (`wf/raven-serverless.yml:332-333`, `:410-411`). Specs: `proto/RAVEN_TRANSPORT_INTERFACE_V1.md` §3, §5-6; `docs/adr/0002-internet-transport.md`.

### 1.3 libp2p host (`raven-swarm`)

- Default build: TCP + Noise + Yamux, QUIC, Kademlia (`/raven/kad/1.0.0`), Identify, Ping (`node/crates/raven-swarm/Cargo.toml`, libp2p 0.56; `swarm/main.rs:154-207`).
- The libp2p key is derived from the Raven seed with domain separation (`swarm/main.rs:141-152`), so the PeerId is stable per profile and is not the Raven address.
- Kademlia inbound PUTs are filtered (`swarm/main.rs:176-181`) and validated: size, signature, expiry ≤ 24 h, key = signer's DHT key, no write to our own key, no older record (`:220-252`). The record key is `SHA-256("rvn1/peer-key" || raven_pub)` (`:209-216`; `core/discovery.rs:54-60`).
- `swarm/connectivity.rs:30` `PRODUCTION_NAT_CONNECTIVITY_ENABLED = false`. The behaviour has **relay client**, DCUtR, **AutoNAT v2 client**, Identify, Ping and limits (`:490-498`, `:504-562`). **The only relay server in the tree is a unit-test fixture** (`:580-614`). Activation needs a feature and a runtime flag (`proto/RAVEN_NAT_CONNECTIVITY_V1.md` §1); NAT spec §6 lists the production holds.
- `swarm/mailbox.rs`: an opaque StoreObject store over `/raven/offline-mailbox/1.0.0`, behind a feature and `--allow-experimental-mailbox`.
  - Per-peer and per-network quotas (`:47-93`).
  - TTL-only deletion and no sybil-proof deposits (`:1-25`).

### 1.4 Bridge and store-and-forward

- `rn/bridge_run.rs`:
  - Unauthenticated listeners on raw `u32 || RVN1` TCP (`:1-24`). Limits are 64 conns and 32/IP (`:184-191`).
  - Policy is re-read from disk on *every* frame (`:704`).
  - The full `message_id` is logged per forward (`:733-746`).
  - In `service` mode the LAN side binds `127.0.0.1:0` and mock BLE binds `127.0.0.1:7421` (`rn/main.rs:3428-3441`), so the bridge is effectively local-only in production.
- `core/message_router.rs:73-90` picks egress by ingress kind only (BLE↔LAN); there is no destination-aware routing.
- `core/bridge.rs:150-160` decrements `hop_limit`/`replication_budget` in the envelope. Carrier Conformance §18 lists this as non-conformant to V2.
- `core/forward_queue.rs`: Queued → InFlight → Forwarded/Expired/Failed (`:21-27`); caps 512 rows / 64 MiB, 7-day custody, tombstones (`:70-95`).
- `proto/RAVEN_BRIDGE_V1.md` "Known limit": unauthenticated pulls let a silent subscriber receive relayed ciphertext.
- `node/scripts/bridge_abc_demo.sh:5-7`, `:36-37`: A-B-C with mock BLE, **built with `unsafe-demo-crypto`**, so the demo cipher is used, not `0x03`.
- `core/ble_adapter.rs`: the BLE "radio" is a TCP mock (`:57-72`). For terminals, *mesh* here means multi-hop over TCP/IP (and later libp2p), not radio.

### 1.5 Send path today

- ash does all session work in-process and uses the daemon only as a dialer. `ash/pair_init_lab.rs`:
  - `run_pair_init_and_send_on` `:290`, `send_indexed_text` `:695`.
  - IPC `LanDial`/`InternetDial` `:157-231`. Only the connect is retried; a written request is never replayed (`:196-198`).
  - Cross-process per-peer lock `.send_<peer>.lock.sqlite` (`:65-95`).
- The contact row stores only `lan_dial` (`ash/ext.rs:890-901`; `ash contact set-dial`, `ash/cli.rs:590-599`). The LAN carrier is the default (`ash/ext.rs:2048-2069`).
- Retry happens only at the next `ash send` or chat. There is no background worker.
- Message validity is **1 hour**: `MESSAGE_VALIDITY_MS` (`ash/pair_init_lab.rs:41-46`) and `envelope_expires` (`core/lan_dispatch.rs:552-558`), both capped by the session.
- The session store already has what a worker needs:
  - A durable `endpoint_outbox` with exact immutable bytes.
  - `retry_endpoint_outbound` (no RNG and no signing; `core/indexed_session_store.rs:2364-2420`).
  - `pending_endpoint_outbound` (`:2424-2464`), `awaiting_ack_endpoint_outbound` (`:2468-2513`) and `resend_queued_endpoint_outbound` (`:2518`).
- Three queues coexist:
  - `endpoint_outbox` (session store; the truth for own objects).
  - `forward_queue.sqlite` (bridge custody).
  - The legacy `queue.sqlite` (`OutgoingQueue`). `EnqueueSealed` writes to both of the last two (`rn/ipc_server.rs:238-323`).

### 1.6 Platform

- Windows:
  - Per-user named pipe with a current-user DACL (`rn/ipc_server_windows.rs:1-40`); the client verifies the server owner.
  - DPAPI for the identity (`core/identity_store.rs:809-891`) and for history (`core/chat_history.rs:1398-1421`).
  - Per-user logon task, not a Windows service (`inst/windows_service.ps1:90-98`).
  - CI on `windows-latest` runs unit tests, `bridge_v1`, the 10k-queue test, a doctor/menu smoke (`node/scripts/ash_doctor_send_smoke.ps1`) and the installer exercise (`wf/raven-serverless.yml:418-568`). **No two-process message delivery runs on Windows.**
- Linux: Secret Service (glibc only); `systemd --user` unit with a lingering note (`inst/linux_systemd_user.sh:74-112`).
- macOS: launchd agent and legacy-Keychain ACL prompts per binary and per rebuild (waiver risk 7; daemon-owned secrets §1).
- Installers default to `127.0.0.1:7420` (LAN exposure is opt-in) even though `core/paths.rs:7` says `0.0.0.0:7420`. Mock BLE uses `7421` (`core/paths.rs:9`).

### 1.7 Problems found while verifying

| # | Finding | Evidence | Consequence | Fix (phase) |
|---|---|---|---|---|
| F1 | `dest_device_hint = SHA-256("rvn1/device-hint/v1" ‖ device_pub)[:8]`, set on every outbound envelope | `core/indexed_session_store.rs:4298-4304`, `:4555`; validated `:4862`, `:5034` | Anyone who holds the recipient's public key (it is their address) can recognise the recipient of every relayed envelope. Invisible today only because LAN frames are inside Noise | Materialize `0`; receivers already accept `0` (`:2745`, `:3885`) (P0) |
| F2 | Envelope validity is 1 h | §1.5 | Store-and-forward and background retry stop after 1 h | Validity = min(session end, now + 24 h) (P2a, owner decision) |
| F3 | Bridge admission is any strict RVN1 (`core/ble_adapter.rs:47-55`); PairInit is wrapped as an ordinary message with `flags: 0` (`core/pair_init_lan_oob.rs:96`) | `rn/bridge_run.rs:696-778` | A PairInit (addresses and trust material in clear, PairInit §7) would be stored and forwarded if anything handed it to the bridge | Allow-list admission (P0) |
| F4 | The Internet responder reveals its hello (Raven identity) and its RLB1 (cert + prekey bundle) to any party that completes XX | `rn/internet_direct.rs:270-276`, `:326-339`; same on LAN `rn/lan_direct.rs:221`, `:254-276` | A public listener lets an Internet scanner map IP → Raven ID and prekeys | Gate on the contact check before the responder hello (P0) |
| F5 | The Kad record key is publicly derivable from the Raven pub key; records have no sequence number | `swarm/main.rs:209-216`, `:242-249` | Anyone can look up any contact's current IP (presence and location); this conflicts with `proto/RAVEN_PRIVATE_RENDEZVOUS_V1.md` PR1 | No public PeerRecords in production; pairwise records later (P4) |
| F6 | Sessions last 24 h (`core/lan_dispatch.rs:1825`) and PairInit may travel only on a confidential carrier (PairInit §7) | waiver §4.1 | A contact pair reachable only through store-and-forward loses its session within a day and cannot re-pair. Bridge-only reachability is a dead end | Order P3 before P2b; proactive re-pair; ratchet later (§4.8) |
| F7 | The A-B-C bridge demo uses the demo cipher | `node/scripts/bridge_abc_demo.sh:36-37` | No evidence that a real `0x03` message or ACK survives the bridge | New `0x03` E2E test (P2b) |
| F8 | The ACK queue callback is a no-op; the ACK only rides the inbound connection | `core/lan_dispatch.rs:1479` | An ACK for a relayed or asynchronous message has no way back | ACK outbox worker (P2a) |
| F9 | The Internet error text suggests port 7421, which is mock BLE's default | `rn/internet_direct.rs:559`; `core/paths.rs:9` | Port collision | New default port 7422 (P1) |

## 2. Carrier architecture for the send path

### 2.1 Layers

```text
 raven (CLI) ── IPC (pipe/UDS) ──► raven-node service
                                   ├─ Endpoint layer: IndexedSessionStore (0x03 now, HR3 later)
                                   │    PairInit, seal, accept, sealed ACK, endpoint_outbox (exact bytes)
                                   ├─ Outbox worker (new, rn/outbox.rs): plans, retries, cancels on first ACK
                                   ├─ Carrier registry (new, rn/carrier/*.rs)
                                   │    lan_direct      ENDPOINT_AUTHENTICATED   Raven Noise XX (no prologue)
                                   │    internet_direct ENDPOINT_AUTHENTICATED   Raven Noise XX "raven/internet/v1"
                                   │    p2p             ENDPOINT_AUTHENTICATED / OPAQUE_CIRCUIT
                                   │                    Raven Noise XX "raven/p2p-link/v1" inside a libp2p stream
                                   │                    (direct TCP/QUIC, Circuit Relay v2, DCUtR upgrade)
                                   │    mesh            ADJACENT_HOP_AUTHENTICATED  RHW1 frames on any of the links above
                                   │    mailbox         MAILBOX_CAPABILITY       /raven/offline-mailbox/1.0.0
                                   └─ Relay role (optional): forward_queue custody, Circuit Relay v2 server
```

Link classes are those of `proto/RAVEN_CARRIER_CONFORMANCE_V1.md` §3.2. The endpoint layer is the only component that decrypts, accepts PairInit or mints and verifies ACKs (umbrella §1.1). Carriers move `endpoint_object_bytes` unchanged (umbrella §2.1).

### 2.2 Carrier interface (Rust, in `rn/carrier/mod.rs`)

```rust
pub enum LinkClass { EndpointAuthenticated, OpaqueCircuit, AdjacentHop, MailboxCapability }

pub struct Route {                 // one untrusted hint from the contact record, a card or RLB2 route hints
    pub kind: RouteKind,           // Lan(host:port) | Internet(host:port) | P2p(Multiaddr) | Mesh(hop_pub) | Mailbox(Multiaddr)
    pub learned_from: RouteSource, // ContactRecord | Card | Rlb2Hint | Observed
    pub expires_at_ms: Option<u64>,
}

pub enum AttemptOutcome {
    Delivered { ack_frames: Vec<Vec<u8>> },  // live link: the peer answered with ACK frame(s)
    Transmitted,                             // written, no ACK yet (keep awaiting)
    Custody { hop: [u8; 32] },               // a hop or store durably accepted the exact bytes (not delivery)
    Refused(CarrierError),                   // the peer said no (blocked, not a contact): do not retry this route
    Unreachable(CarrierError),               // connect or handshake failed: back off
}

#[async_trait::async_trait]
pub trait Carrier: Send + Sync {
    fn kind(&self) -> CarrierKind;
    fn class(&self) -> LinkClass;
    /// May this carrier carry PairInit? Only `EndpointAuthenticated` / `OpaqueCircuit` links say yes.
    fn confidential_to_endpoint(&self) -> bool;
    async fn attempt(&self, route: &Route, expected_peer: &[u8; 32],
                     frames: &[Vec<u8>], deadline: Instant) -> AttemptOutcome;
}
```

`lan_direct::dial` (`rn/lan_direct.rs:520`) and `internet_direct::dial` (`rn/internet_direct.rs:541`) already have the right shape: frames in, reply frames out. They become the first two `Carrier` impls without protocol changes.

### 2.3 Per-contact carrier choice

- The contact row (`ash/ext.rs:890-901`) gains `routes: Vec<Route>`. `lan_dial` is migrated into it.
- Plan order (umbrella §6; Carrier Conformance §10.1):
  1. `lan`
  2. `internet` (explicit address)
  3. `p2p` direct
  4. `p2p` via relay, with DCUtR attempted by libp2p on that connection
  5. `mesh` (only if a confirmed session exists)
  6. `mailbox` (same condition)
- `core/transport.rs:84-105` `plan_paths` stays the policy function. It gets a `PathContext` built from the contact's routes and the local carrier state.
- PairInit may be planned only on carriers with `confidential_to_endpoint() == true` (§3.3). The worker enforces this, not the caller.
- Hedging: at most 2 concurrent live attempts per object. Mesh and mailbox start only after live carriers failed for ≥ 60 s **(guess)**, so a reachable peer does not get a second, store-held copy.

### 2.4 Outbox worker (`rn/outbox.rs`)

- **Owner:** a supervised task in `Commands::Service` next to the LAN, Internet, prune and bridge tasks (`rn/main.rs:3398-3458`). The service gains a sixth `JoinHandle` in `wait_service_end`.
- **Work source:** `IndexedSessionStore::pending_endpoint_outbound()` (state Queued) and `awaiting_ack_endpoint_outbound()` (handed off, no ACK yet), for both kinds (messages and ACKs). There is no second queue. The exact bytes come from the outbox row (umbrella §2.1.2).
- **Per object, in memory and rebuilt at start-up:** `{object_digest, kind, recipient_device, attempts[carrier] (u32, monotonic per Carrier Conformance §4.2), next_attempt_at, last_error}`.
- **Locking:** the worker takes the same `.send_<peer>.lock.sqlite` lock as ash (`ash/pair_init_lab.rs:65-95`; move `PeerSendLock` into `core/`). No network I/O runs inside session-store transactions (umbrella §1.1).
- **Triggers:**
  - IPC `OutboxKick` right after ash stages a message.
  - Any authenticated inbound link from that contact. The worker pushes our pending objects on the *same* link before it closes, which is what a NAT'd peer that dials out needs.
  - Listener up or network change.
  - A timer: backoff 5 s × 2, capped at 10 min, ±50 % jitter **(guess)**. The swarm `liveness::reconnect_delay` (`swarm/lib.rs`) can be reused.
- **Stop conditions:**
  - First verified ACK: delivered; cancel the other local attempts (umbrella §2.4).
  - `expires_at` passed: abandon via `abandon_undelivered_outbound` (`core/indexed_session_store.rs:3055`); history shows "expired, not delivered".
  - Contact deleted, blocked or revoked: fail closed (umbrella §9.2 E4).
- **ACK objects** (receiver side): the worker sends our own pending ACKs to the original sender over that contact's plan. This fixes F8.
- **Proactive re-pair (P2a, optional):** if the newest confirmed session with a contact has < 6 h left **(guess)** and a confidential carrier is up, run `create_initiator_pair_init` (`core/lan_dispatch.rs:1831`) inside the daemon. This needs only the identity, which the daemon already loads, and no plaintext.
- **What stays in ash until IPC v2:** sealing new plaintext (`SealUnderSession` exists, `rn/ipc_server.rs:324`). Daemon-side `SubmitMessage` is Phase 3 of the daemon-owned-secrets design. The worker never needs plaintext.

### 2.5 Delivery state and ACKs per carrier

| Carrier | Attempt result the worker records | How the ACK returns | Becomes Delivered when |
|---|---|---|---|
| LAN / Internet / p2p direct / p2p relayed | `Delivered` if an ACK frame is in the replies, else `Transmitted` | Reply frame on the same Raven link (`core/lan_dispatch.rs:1470-1485`) | The sender verifies the sealed ACK (`core/lan_dispatch.rs:1488-1519` logic, moved to a core fn shared by ash and the worker) |
| Lost ACK on a live link | `Transmitted` | The worker resends the exact bytes; the receiver sees a Duplicate and resends the existing ACK (errata rule 5) | Same |
| Mesh | `Custody{hop}` after the hop's authenticated `STORED` result (§4.2) | A separate sealed ACK object, sent by the *receiver's* worker over any carrier back to the sender | Same; custody never counts (Carrier Conformance §8.2) |
| Mailbox | `Custody` on `STORED` (`proto/RAVEN_MAILBOX_TRANSPORT_V1.md` §2) | The receiver polls, accepts, and its worker returns the ACK by any carrier, the sender's mailbox included | Same; `STORED`/`GET` never count |

The history status uses the existing `mark_lan_chat_history_delivery` (`core/lan_dispatch.rs:226`), renamed in P2a.

### 2.6 Inbound: sender-agnostic endpoint entry

`handle_indexed_message` requires the authenticated link peer (`core/lan_dispatch.rs:1372-1390`). A relayed object arrives from a hop or a store, not from its sender. New function, `core/relayed_dispatch.rs`:

```rust
pub fn dispatch_relayed_object(data_dir: &Path, identity: &Identity, packed: &[u8], now_ms: u64)
    -> Result<RelayedOutcome, String>   // NotForUs | Accepted{ack_queued} | Duplicate | Refused(code)
```

1. Run the admission allow-list (§4.1) and the strict decode.
2. Find the session by route tag across all Confirmed sessions. The new store query `find_confirmed_session_for_route(routing_tag, created_at, header_index, env_type, now)` costs one HMAC per live session per object (`proto/ATSAM_INDEXED_SESSION_PROFILE_V1.md` §2.3). No state changes until a session matches.
3. Contact, block and revocation checks use the **session's bound peer certificate**, not the hop.
4. Call `accept_message_envelope` or `accept_ack_envelope` unchanged.
5. The ACK goes to `endpoint_outbox` for the worker.

## 3. Internet

### 3.1 How peers learn reachability

Ordered by privacy cost, lowest first. Every source is an untrusted hint (umbrella §2.5; Private Rendezvous §0).

1. **Contact record and card (P1).**
   - `raven whoami --card` prints a public card: `address`, `pub_hex`, fingerprint, optional `inet=host:port`; later `p2p=<PeerId>` and `via=<relay multiaddr>` (P3) and `mbx=<provider>` (P4).
   - `raven contact add --card …` imports it. Fingerprint verification stays mandatory for trust.
   - Exposure: whoever holds the card learns the addresses.
2. **Route hints inside authenticated links (P3).**
   - The RLB2 bundle of the per-device-keys design is extended with a signed, bounded `route_hints[]`: ≤ 8 entries, ≤ 512 B each, `expires_at`.
   - It is exchanged only inside Noise between contacts, so every successful contact refreshes both sides' routes. This needs that design's RLB2 freeze. Without RLB2, a separate signed `RRH1` control frame on the link works too.
3. **Relay reservations (P3).**
   - B keeps reservations on ≤ 2 relays named in its card or hints.
   - A dials `/<relay addr>/p2p/<R>/p2p-circuit/p2p/<B>`.
   - The libp2p rendezvous protocol is **not** used: it registers namespaces at a third party.
4. **DHT (P4, optional).**
   - Today's public `PeerRecord` (`core/discovery.rs:17-60`) must not be published in production (F5).
   - The replacement is a pairwise record: `key = HMAC(K_pair, "raven/rdv/v1" ‖ epoch_day)`, `value = AEAD(K_pair, signed descriptor)`, per Private Rendezvous §5.4 (`R3_PAIRWISE_DIRECTORY`).
   - **Proposal (needs review):** `K_pair = HKDF(X25519(noise_static_a, noise_static_b), "raven/rendezvous/v1" ‖ sorted(ed_a, ed_b))`. It needs both Noise static publics, learned on the first authenticated link. It is long-term (no FS), and is used for lookup only.
   - The validation rules of `swarm/main.rs:220-252` stay, plus a `generation` counter and a required terminal `/p2p/<PeerId>`.

### 3.2 Identity binding (no TOFU gap)

- **libp2p is a substrate only.** A PeerId authenticates a libp2p key, never a Raven identity (Carrier Conformance §11.4.2).
- Every Raven link over libp2p opens a stream `/raven/link/1.0.0` and runs, *inside* it, exactly `initiator_session` / `responder_session` from `rn/internet_direct.rs:206-278`. Those functions are already generic over `AsyncRead + AsyncWrite`; the libp2p stream is adapted with `tokio_util::compat` (tokio-util 0.7.19 is already in `node/Cargo.lock`).
- Use a new prologue `raven/p2p-link/v1` so that neither a raw-TCP transcript nor a libp2p transcript can complete against the other (same reasoning as `core/internet.rs:26-28`). The RIH1 layout is unchanged.
- The dialer always knows the expected Raven key from the contact record, and fails unless hello == expected (`rn/internet_direct.rs:239-242`). The RLB1/RLB2 identity must equal the hello (`:520-526`).
- Over a circuit, this Raven session is end to end between A and B. The relay sees the A↔B libp2p Noise ciphertext, and inside it the Raven Noise ciphertext. This is `OPAQUE_CIRCUIT` (Carrier Conformance §3.2, §7.4).
- After a DCUtR upgrade, a *new* stream runs a *new* Raven handshake on the direct connection (Carrier Conformance §7.4). Pending objects are retried byte-identically.
- The only trust input is the contact record, added out of band with `--verify-fp` (`ash/cli.rs:466-480`). Product rule: `raven contact add` without fingerprint verification may use LAN, but the worker refuses Internet, p2p, mesh and mailbox routes for that contact until it is verified **(owner decision)**.
- Library check: the libp2p crate `libp2p-stream` (`Control::open_stream`/`accept`) is **not** in `node/Cargo.lock` today; add the `stream` feature of libp2p 0.56 **(verify)**. Relayed connections are "limited" in rust-libp2p; a protocol must explicitly allow streams on them **(verify the 0.56 API)**.

### 3.3 PairInit only over a confidential carrier

- Allowed: LAN direct, Internet direct and p2p (direct or circuit), because PairInit rides inside a Raven Noise session that terminates at the intended contact.
- Forbidden: mesh, bridge and mailbox, where a hop or store would hold the bytes in clear (PairInit §7; F3).
- Enforcement in three places:
  1. Admission (§4.1) refuses PairInit and PairResponse on every custody path.
  2. The worker never plans PairInit on a non-confidential carrier.
  3. A test asserts that a captured relay or mailbox store contains no `RVPI1`/`RVPR1` magic.
- The async bootstrap carrier PairInit §7 asks for (offline first contact through a store) is **not** solved here; it is open question Q3.

### 3.4 Public-listener hardening (P0, before any Internet exposure)

1. **Contact-gated responder (fixes F4).**
   - The responder verifies the initiator hello, then checks `contacts.json` for that Ed25519 key, then sends its hello.
   - A stranger receives only Noise message 2 and is disconnected. Message 2 does expose the stable Noise static public key, which links the node across IP addresses but does not name the Raven ID.
   - Applied to `internet_direct` and `p2p` always, and to `lan_direct` behind a policy flag. Check first whether contact-request flows need stranger offers **(verify)**.
2. **Admission:** keep `PRODUCTION_INBOUND` (`rn/main.rs:737-744`); contacts move to non-displaceable slots (already, `rn/internet_direct.rs:336-338`). Add a per-/24 (IPv4) and per-/48 (IPv6) pre-auth cap of 8, as the mailbox does (`swarm/mailbox.rs:1-15`).
3. **Logs:** no peer key, address or message ID at info level. Truncate `rn/bridge_run.rs:733-746` to 4 bytes like `DROP_LOG`.

### 3.5 Relay mode: `raven-node relay`

**Process model:**

- A VPS runs `raven-node relay --data-dir <dir>` **without a Raven identity**. It holds only a libp2p key file (`relay_key.ed25519`, 0600) and therefore no messaging secret, no Secret Service and no vault.
- A home machine with a public IP may instead run `raven-node service --relay`, which shares the service's libp2p host. Its relay PeerId is then the user's PeerId, which is disclosed.
- No relay address is compiled in (NAT spec §1). Relays come only from cards, hints and user config.

**Behaviour:** `relay::Behaviour` (server), `autonat::v2::server` (optional, `--autonat-server`), Identify, Ping, `connection_limits`, `swarm::ip_limits`. No Raven link protocol, no Kademlia server until P4, no mailbox until P4 (`--mailbox`).

**Limits (proposed defaults; libp2p defaults in brackets, all (verify)):**

| Knob | Default | Hard max | Why |
|---|---:|---:|---|
| Reservations total | 128 [128] | 1024 | One per friend device |
| Reservations per peer / per IP | 1 / 4 [4 / -] | 2 / 16 | PeerIds are free; cap by IP (`swarm/connectivity.rs` IP limits) |
| Reservation duration | 30 min [1 h] | 2 h | Clients renew; stale ones expire |
| Circuits total / per peer | 64 / 4 [16 / 4] | 256 / 8 | |
| Circuit duration | 5 min [2 min] | 30 min | DCUtR usually upgrades within seconds; the stream closes when idle |
| Circuit bytes | 2 MiB [128 KiB] | 16 MiB | PairInit (2788 B) + RLB1 offers (≤ 64 KiB each) + 48 KiB messages exceed 128 KiB (guess) |
| Reservation / circuit rate per IP | 4/min / 30/min | - | `relay::Config` rate limiters (verify names) |
| Established conns total / per IP | 256 / 8 | 1024 / 32 | `connection_limits` + `ip_limits` |
| Aggregate bandwidth | `--max-mbps` | - | Not native to libp2p: account `CircuitClosed` bytes, or document `tc`/cloud QoS (verify) |

**Abuse controls:**

- **Allow-list by default.** Reservations are accepted only from PeerIds in `relay_allow.json`, filled by `raven relay allow --tag bob`, which reads Bob's card PeerId. `--open` serves anyone and switches to stricter defaults (reservations 32, circuit bytes 512 KiB).
- Circuit Relay v2 connects only to peers holding a reservation, so a relay cannot be used as an open proxy or for SSRF (verify against the spec).
- Fail closed on an unreadable allow-list. Logs and metrics are counts only (NAT spec §5).

**What a relay learns, and what it cannot:**

| Learns | Does not learn |
|---|---|
| Both PeerIds and IPs of every circuit, its timing, duration and byte count; who reserves; AutoNAT probe targets | Raven IDs (unless it holds cards, which map PeerId → Raven ID), plaintext, PairInit, RLB1, route tags, message IDs: all are inside two layers of Noise |

**Correlation:** a relay that also holds friends' cards learns the friend graph at the PeerId level. That is stated in the disclosure table (Carrier Conformance §13).

### 3.6 DCUtR, AutoNAT, IPv6, ports, UPnP

- **AutoNAT v2 client:** a reachability hint only, never trust (umbrella §6). If the result is public, skip reservations; if private or unknown, reserve on the relays in the card.
- **DCUtR:** coordinated over an existing relayed connection. On failure keep the circuit (Carrier Conformance §11.5.5). Expected success on cone NATs; fails on symmetric or CGNAT-to-CGNAT pairs. The published libp2p measurement is roughly 70 % **(verify)**.
- **IPv6:** listen on `/ip6/::/tcp/7423` and `/ip6/::/udp/7423/quic-v1`. A home with global IPv6 behind a stateful CPE firewall usually hole-punches without NAT **(guess)**.
  - Admission keys already fold to /64 (`rn/main.rs:746-759`).
  - A stable listening IPv6 address in a card is a stable location identifier; say so in the UX.
- **Ports:**
  - LAN direct TCP 7420 (unchanged).
  - Mock BLE 7421 (loopback, tests only).
  - Internet direct TCP **7422**.
  - libp2p TCP+UDP **7423**, used by both service and relay.
  - No mesh port: mesh rides the existing links (§4.2).
- **UPnP/NAT-PMP:** `libp2p-upnp` resolves in the lockfile, but off by default, because opening router ports silently is a policy decision (Q8).

### 3.7 Firewall prompts per OS

| OS | What happens on first non-loopback listen | Installer behaviour |
|---|---|---|
| Windows | Defender Firewall shows "Windows Security Alert" (Private/Public). Allowing needs admin; dismissing creates a block rule. Unclear whether a background logon task's prompt appears in the session (verify) | `windows_service.ps1 -InternetListen 0.0.0.0:7422 [-P2pListen 7423]` prints, and does not run, the elevated commands: `New-NetFirewallRule -DisplayName "Raven node" -Direction Inbound -Program <raven-node.exe> -Protocol TCP -LocalPort 7422,7423 -Profile Private` plus the same with `-Protocol UDP -LocalPort 7423`. Default profile Private, never Public. Outbound needs no rule |
| macOS | The Application Firewall is off by default. When on, it prompts per code identity, so an unsigned rebuild prompts again; "Block all incoming" drops connections silently. Separately, macOS 15+ Local Network privacy can block LAN (not Internet) traffic for background processes (verify) | `macos_launchd.sh` gains `RAVEN_INTERNET_LISTEN` / `RAVEN_P2P_LISTEN` and prints the `socketfilterfw --add/--unblockapp` hint. Stable signing (daemon-owned secrets Phase 0/(e)) makes the rule stick |
| Linux | No prompt. ufw/firewalld/nftables and cloud security groups decide | `linux_systemd_user.sh` gains the same variables and prints `ufw allow 7422/tcp; ufw allow 7423/tcp; ufw allow 7423/udp`. Relay on a VPS: a system unit (§6.2) |

## 4. Bridge and mesh

### 4.1 What custody paths may carry (`core/carrier_admission.rs`, P0)

`admit_relayable(packed, now_ms) -> Result<RelayableObject, DropReason>`. It is called by `message_router::handle_inbound`, `EnqueueSealed`, mesh RHW1 ingress and mailbox PUT. It admits only:

- a strict `RavenEnvelopeV1` with `env_type ∈ {1, 2}` and `flags == 0` (as `OUTBOUND_FLAGS`, `core/indexed_session_store.rs:104`);
- a body that starts with `RVNA1\0\0\0 ‖ 0x03 ‖ 0x01` (later also the ratchet profile's byte); an empty header;
- a body that `classify_packed_envelope` (`core/pair_init_lan_oob.rs:59`) classifies as `NotPairInitOob`;
- packed size ≤ 64 KiB (one Noise frame), `created_at ≤ now + 5 min` (normative skew, commit `dd296bd`) and `expires_at ≤ now + 24 h`.

Everything else is dropped before custody: PairInit/PairResponse, `0x7F`, alias, capabilities and RVOS control. `0x03` stays absent from relay *interpretation*: the allow-list reads only the magic and proto bytes, never the ciphertext (umbrella §7.2).

### 4.2 Mesh-hop link

- **Mesh frames ride the existing authenticated links (LAN, Internet, p2p).** There is no new port and no new handshake.
- After the RIH1 hello (whose caps are signed, `core/internet.rs:126-135`), a frame starting with magic `RHW1` is a hop-wrapped object for custody. A bare `RVN1` frame is still an endpoint object for the link peer.
- Both sides must be mutual contacts with the flag `mesh_neighbor` and advertise `CAP_BRIDGE` (`core/internet.rs:48`). Otherwise `RHW1` frames are refused. This closes the Bridge V1 "unauthenticated pull" known limit for remote hops.
- Frames inside the link (all `carrier_control_bytes` except the wrapped object):

```text
RHW1  = "RHW1" || ver=1 || hop_budget_u8 || copy_budget_u8 || flags_u8(0)
        || hop_expires_at_ms_be64 || object_len_be32 || endpoint_object_bytes
RHR1  = "RHR1" || ver=1 || object_digest32 || code_u8      # 0 STORED, 1 DUPLICATE, 2 REFUSED, 3 FULL, 4 EXPIRED
```

- `object_digest = SHA-256(endpoint_object_bytes)`. `RHR1 STORED` is link-authenticated custody evidence for one attempt (Carrier Conformance §8.3), never delivery.
- New wire, so: `proto/RAVEN_TERMINAL_MESH_V1.md` (new companion), vectors under `shared-vectors/rvn1/mesh/`, and a `PROTOCOL_VERSIONS.md` row.

### 4.3 Hop-local budgets, the errata, and exact bytes

- The sender's envelope keeps `hop_limit = 8`, `replication_budget = 2` (`core/indexed_session_store.rs:105-106`), and **no hop rewrites them** (umbrella §1.2). `core/bridge.rs:150-160` is retired for mesh paths and kept only for the legacy mock-BLE test path.
- **Budgets live in RHW1:**
  - The sender sets `hop_budget ≤ 3` and `copy_budget ≤ 4`.
  - Every hop clamps the received values to its local maxima (3/4), decrements `hop_budget`, and splits `copy_budget` binary (spray-and-wait, `core/bridge.rs:165`).
  - It refuses zero.
- **Errata rule 8 still applies:** these budgets are unauthenticated against a Byzantine hop. Claims are limited to "cooperative bound + local quotas + dedup".
- `dest_device_hint`: materialized as `0` after P0 (F1). The field stays mutable and unsigned (`proto/RAVEN_ENVELOPE_V1.md` §2). Admission does not reject a non-zero hint from old senders, but a hop rewrites nothing.

### 4.4 Dedup, TTL, quotas

- **Dedup:** the existing `bridge_seen_objects_v2` and forward-queue row checks (`core/forward_queue.rs:83-92`), keyed by the inner digest. Today's key is `authenticated_object_digest` (`core/bridge.rs:67`), which equals the raw digest once nothing mutates; store both during migration. Same digest with different bytes is quarantined (Carrier Conformance §10.4).
- **TTL:** custody = min(envelope `expires_at`, RHW1 `hop_expires_at`, admitted + 24 h) **(guess; today 7 d, `core/forward_queue.rs:88`)**. Tombstones last until `expires_at`, as today.
- **Quotas:**
  - Per hop identity, not per IP: 64 pending objects, 30 enqueues and 256 KB per minute (`core/forward_queue.rs:75-80`).
  - Node-wide: 512 rows / 64 MiB (`:70`, `:90`).
  - The "own objects" class (from our outbox) is never evicted by relayed ones.

### 4.5 Metadata exposure

| Observer | Sees |
|---|---|
| Adjacent hop (a contact) | Ingress link identity, exact ciphertext, size and time. **Outer Ed25519 signature:** anyone holding candidate public keys can verify `sender_authentication` and so name the sender (waiver risk 6). `routing_tag` is opaque but correlates the copies of one object. Until F1 is fixed, `dest_device_hint` names the recipient |
| Every later hop | Same object, same digest: all hops can correlate one message across the mesh (Carrier Conformance §13) |
| Network observer | IPs, timing, sizes of Noise frames |

Removing sender identification from the outer layer needs a sealed-sender profile with a new envelope version and an umbrella revision (Q5). This design does not claim it.

### 4.6 Multi-hop A-B-C-D routing

- **Blind spray within the friend mesh.** No hop knows the destination; no routing table is published.
- Step by step:
  1. A's worker pushes RHW1 to its mesh neighbours (B), at most `copy_budget` copies.
  2. B runs `dispatch_relayed_object`. If it returns `NotForUs`, B takes custody and forwards to its other neighbours except ingress, with decremented budgets.
  3. When C connects, or is connected, B pushes. C does the same towards D.
  4. D's route-tag match makes it the endpoint.
  5. D's ACK object returns along any of D's carriers to A: direct if possible, else the same spray.
- **Inventory on connect** (instead of Object Sync, which is not approved):
  - When a mesh link comes up, each side pushes at most 64 pending custody objects, oldest first. `DUPLICATE` answers stop re-sends.
  - This is push-only. Wasteful on duplicates, but bounded by quotas and 64 KiB objects. Move to Object Sync once it is APPROVED.
- **Loop prevention:** seen set, never back to ingress, hop budget.
- **Expected reach:** 3 hops among always-on terminals **(guess)**. Mesh is not anonymity.

### 4.7 Mailbox for offline peers (P4)

- **Store:** `swarm/mailbox.rs` served by `raven-node relay --mailbox`, or a friend's service. PUT/GET as `proto/RAVEN_MAILBOX_TRANSPORT_V1.md`.
- **Index:** `store_tag[d]` from the session's `K_route[d]` and the day epoch (`proto/ATSAM_INDEXED_SESSION_PROFILE_V1.md` §6). The recipient polls today and yesterday every 5 min while online, and at start-up **(guess)**.
- **Deposit:** the mailbox carrier deposits only admitted objects (§4.1). The store depositor allow-list holds the PeerIds of the operator's friends (sybil gap, `swarm/mailbox.rs:9-14`). Deletion is TTL-only; an ACK never deletes (errata rule 9).
- **Limit:** the tag lives only as long as the session (24 h) and the envelope validity (F2). The mailbox helps short offline gaps, not week-long ones, until the ratchet profile gives long-lived sessions.

### 4.8 The 24 h session constraint (F6)

Store-and-forward only carries messages inside an existing session, and a new session needs a confidential carrier. The options are below, and they are not exclusive:

- (a) The P3 circuit relay is the confidential carrier for NAT'd pairs, so P3 should come before P2b.
- (b) Proactive re-pair whenever any confidential link is up (§2.4).
- (c) The ratchet profile (`2026-10-ratchet-fs-pcs.md`) gives long sessions with FS/PCS, which removes the 24 h cliff.
- (d) A sealed asynchronous PairInit carrier (Q3).

Raising the session lifetime back to 7 d is the cheapest fix and the worst for exposure (waiver §4.1).

## 5. Security holds per step

Umbrella §9.1 holds:

1. Automated gates.
2. All companions APPROVED.
3. Independent review or a recorded owner waiver.
4. Physical rows plus the stage-12 failure matrix for that carrier.
5. Indexed-session paths stay lab-gated.

None of the §8 companions is APPROVED except Revocation, so hold 2 needs a waiver for every phase.

| Phase / flag | Holds to satisfy | Waived (new record) | Physical rows (umbrella §10.2) | Code and doc changes at flip |
|---|---|---|---|---|
| P1 `INTERNET_DIRECT_PRODUCTION_ENABLED` (`core/internet_gate.rs:9`) | 1 (CI matrix §6.4 on all 3 OS), 4 | 2, 3, 5 for "Internet direct TCP between two `raven-node` services, Noise XX `raven/internet/v1` + RIH1, contacts only, explicit `host:port` from the contact record" | Stage 7 *direct part only*: two hosts on different networks (VPS ↔ home with port-forward, or global IPv6); stage 12 for Internet. Row 7 also names DCUtR, so the waiver must split it | Rewrite tests `core/internet_gate.rs:21-41`; `HOLD` `rn/internet_direct.rs:52-54`; `ash/pair_init_lab.rs:100-103`; amend umbrella §9.1 "Recorded owner exception", PairInit §7, indexed profile §7, Transport Interface §3, ADR 0002, `core/discovery.rs:157` `NAT_STATUS`; regenerate `docs/PROTOCOL_FREEZE_HASHES_V1.md` |
| P2a outbox worker | 1 | No new carrier, but it changes retry timing and validity (F2): record in the LAN waiver as a narrowing amendment | Stage 12 rows: kill/relaunch, loss, duplicate, expiry on LAN and Internet | Validity constants; history states |
| P2b mesh (`MESH_PRODUCTION_ENABLED`, new `core/mesh_gate.rs`) | 1, 4 | 2, 3, 5 for "opaque custody of RVNA1 `0x03` messages and ACKs over authenticated mesh-hop links between mutual-contact `raven-node` services; no PairInit". Carrier Conformance is NOT APPROVED and `RAVEN_TERMINAL_MESH_V1` is new: waive or have it reviewed | Row 10 is BLE→gateway→Internet, which does not apply to terminals. The waiver must define a substitute "Terminal A → B → C across two networks" row, and a later umbrella revision should add it. Stage 12 for mesh | Bridge V1 §Relay limits and "Known limit" amended; Carrier Conformance §18 audit row updated |
| P3 `P2P_PRODUCTION_ENABLED` (new `core/p2p_gate.rs`) + `PRODUCTION_NAT_CONNECTIVITY_ENABLED` (`swarm/connectivity.rs:30`) | 1, 4; NAT spec §6 also requires Rust **and iOS** session integration, explicit relay policy (§3.5), abuse tests, soak | 2, 3, 5 **and the iOS-parity requirement of NAT spec §6** (owner decision: terminals only) | Stages 7 (DCUtR) and 8 (relay-only), stage 12 for both. Two NAT'd homes + one VPS relay | NAT spec §1/§6 rewritten for the relay mode; feature graph change; recommend an **independent review** here, not only a waiver: first public-facing libp2p surface (Q1) |
| P4 mailbox (`MAILBOX_PRODUCTION_ENABLED`) | 1, 4; Carrier Conformance §11.6.9 (V2 store wrapper) | 2, 3, 5, plus the V1 wrapper limitation | Stage 9, stage 12 | Mailbox spec status line |
| Windows path (any carrier) | Stage 11 "Windows Terminal ↔ Unix" + stage 12; Carrier Conformance §19.2 Windows row | Waiver risk 8 is retired only by evidence | Stage 11 | - |

**Waiver record template** (copy of the LAN waiver's shape). Each phase adds one file `docs/WAIVER_<CARRIER>_<date>.md` with:

- ID, approver, date, scope (exact carrier, link class, objects, peers);
- holds table;
- residual risks: everything in waiver §4 plus that carrier's metadata table from §3.5 and §4.5;
- compensating controls (the allow-list, contact gating, limits);
- review-by date (≤ 3 months);
- withdrawal: the exact flag;
- lapse conditions as in waiver §6.

A waiver never covers "any carrier": the LAN waiver §6 makes extending scope without a new record a lapse condition.

## 6. Cross-platform specifics and CI

### 6.1 Windows

- **IPC:** the named pipe stays (`rn/ipc_server_windows.rs`). New IPC ops (§7) need no transport change.
- **Keys:** DPAPI file backend unchanged; the libp2p key derives from the seed (`swarm/main.rs:141-152`, moved to `core/`), so it adds no new secret. Relay mode stores `relay_key.ed25519` protected by DPAPI.
- **Service:**
  - The per-user logon task (`inst/windows_service.ps1:90-98`) runs only while the user is logged in, so a Windows PC is a poor always-on relay or mesh hop. Say so in `raven doctor`.
  - Relay on Windows Server needs a real service (`New-Service`/SCM) with a virtual account. Not planned (Q9).
- **Firewall:** §3.7.
- **Tests:** two-process LAN and Internet E2E on `windows-latest`, through the Rust harness of §6.4, not bash.

### 6.2 Linux

- **Endpoint keys:** Secret Service on desktops. On headless hosts, the Argon2id passphrase vault (in progress). Unattended restart needs the passphrase: use `systemd-ask-password` or `LoadCredentialEncrypted=` **(verify the vault design)**. Otherwise a headless endpoint cannot restart after a reboot without a human.
- **Relay:** needs no vault (it holds no Raven identity).
- **Units:**
  - Endpoint: `systemd --user` + `loginctl enable-linger` (already hinted, `inst/linux_systemd_user.sh:105-112`).
  - Relay: a new system unit `inst/linux_systemd_relay.sh` with `DynamicUser=yes`, `StateDirectory=raven-relay`, `ProtectSystem=strict`, `ProtectHome=yes`, `NoNewPrivileges=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `MemoryMax=512M`, `LimitNOFILE=4096` **(guess on sizes)**.
- **musl static builds have no Secret Service** (`core/Cargo.toml` comment). They are fine for relays, and use the vault for endpoints.

### 6.3 macOS

- **launchd:** the agent gets the new listen variables. The relay is better on Linux; a Mac relay is a LaunchAgent with the same flags.
- **Keychain:** the outbox worker reads session state inside `raven-node`, which already reads it on receive, so it adds no new code identity. P2a adds no prompts beyond today's.
- **Firewall and signing:** §3.7; daemon-owned secrets Phase 0/(e).

### 6.4 CI test matrix

A new Rust integration harness, `node/crates/raven-node/tests/carrier_matrix.rs` (`#[ignore]`, run explicitly in CI):

- It spawns `raven-node service` and `raven` processes in temp data dirs, with debug `locked-file` backends as the existing smokes do. On Windows it uses the real DPAPI backend.
- It drives IPC directly. It is portable across all three OSes, which bash plus `kill`/`mktemp` is not on Windows.
- Each scenario asserts message 1 → ACK → message 2, a restart, an exact-byte retry, contact delete, and block (umbrella §10.2 row contents).

| Scenario | Processes (all on one runner) | ubuntu | windows | macos | Proves |
|---|---|:-:|:-:|:-:|---|
| C1 LAN direct | A, B on 127.0.0.1 | ✓ | ✓ | ✓ | Today's slice on 3 OS (retires waiver risk 8 in CI) |
| C2 Internet direct | A, B with `--internet-listen 127.0.0.1:0`, no LAN route | ✓ | ✓ | ✓ | P1 |
| C3 Contact gating | Stranger S dials B | ✓ | ✓ | ✓ | F4: S gets no hello, no RLB1 |
| C4 Outbox restart | Kill A after stage; B down 60 s; restart both | ✓ | ✓ | ✓ | P2a delivery without a new `send` |
| C5 Lost ACK | Fault hook drops B's reply once | ✓ | ✓ | ✓ | Exact resend → Duplicate → ACK |
| C6 Forced relay | R relay; A, B listen only on circuit addrs; direct dial disabled by test flag | ✓ | ✓ | ✓ | P3 OPAQUE_CIRCUIT; PairInit through R; capture at R has no `RVPI1`/`RLB1`/plaintext |
| C7 DCUtR | netns NAT (below) | ✓ | - | - | Direct upgrade on cone NAT; stays on relay on symmetric NAT |
| C8 Mesh A-B-C-D | 4 nodes; sessions pre-made on LAN, then LAN routes removed; mesh links A-B, B-C, C-D only | ✓ | ✓ | ✓ | P2b/P4: delivery, ACK back, budgets, dedup, PairInit refused at B, no envelope mutation |
| C9 Mailbox | A, store S, D offline then online | ✓ | ✓ | ✓ | P4 |
| C10 Abuse | Flood handshakes, reservations, RHW1 junk | ✓ | - | ✓ | Limits hold; contacts keep slots |

**netns NAT simulation (ubuntu-latest; hosted runners have passwordless sudo; kernel netfilter support (verify)):**

- Namespaces: `pub` (relay R at 10.0.0.1), `rA` and `rB` routers each doing `nft masquerade`, `hA` behind `rA` (192.168.1.2) and `hB` behind `rB` (192.168.2.2).
- "Cone" run: default masquerade, which is endpoint-independent mapping with port preservation where possible (verify) → expect `dcutr` success.
- "Symmetric" run: `masquerade random,fully-random` → expect relay-only delivery, which is the stage-8 substitute.
- Script `node/scripts/netns_nat_dcutr.sh`, CI job `nat-sim-linux`. It is a software substitute and does **not** replace physical rows 7-8 (`docs/NAT_SOFTWARE_SIM.md` "Honest claim").

### 6.5 Physical rows (owner-run, recorded under `node/proof_artifacts/`)

| Row | Setup |
|---|---|
| R7a Internet direct | Linux VPS ↔ macOS at home (port-forward or IPv6) |
| R7b DCUtR | Two homes behind consumer NAT + VPS relay |
| R8 Relay-only | One side on a phone hotspot (CGNAT) |
| R11 Windows | Windows ↔ Linux on LAN and over Internet |
| Mesh substitute row | A (home 1) → B (VPS, mesh hop) → C (home 2) |
| R9 Mailbox | D offline 30 min |

Each row runs the umbrella §10.2 row contents and the stage-12 slice.

## 7. Phased plan

Effort is in engineer-days for one engineer who knows this code, including tests and docs. **All estimates are guesses.**

### 7.1 P0: preconditions (6-9 d)

| Item | Files | Effort |
|---|---|---:|
| Portable carrier harness, C1 + C3 | `rn/../tests/carrier_matrix.rs`, `wf/raven-serverless.yml` jobs on 3 OS | 3-5 |
| Contact-gated responder (F4) | `rn/internet_direct.rs:248-339`; flag-gated in `rn/lan_direct.rs:209-276` | 1-2 |
| `dest_device_hint = 0` (F1) | `core/indexed_session_store.rs:4555`, `:4862`, `:5034` + tests and fixtures | 1-2 |
| Custody admission allow-list (F3) | new `core/carrier_admission.rs`; calls in `core/message_router.rs`, `rn/ipc_server.rs:238`, `swarm/mailbox.rs` PUT | 1-2 |
| Log hygiene, port text (F9) | `rn/bridge_run.rs:733-746`, `rn/internet_direct.rs:559` | 0.5 |

### 7.2 P1: Internet direct production with explicit addresses (10-15 d + owner physical)

| Item | Files / surface | Effort |
|---|---|---:|
| Contact routes (`internet` route) + migration of `lan_dial` | `ash/ext.rs:890-901`; contacts.json schema; read side in `core/lan_dispatch.rs:538` (`peer_is_trusted`) unchanged | 2 |
| CLI `raven contact set-addr --tag T [--lan H:P] [--internet H:P] [--clear KIND]` (`set-dial` kept as alias) | `ash/cli.rs:466-600` | 1 |
| Cards: `raven whoami --card`, `raven contact add --card <text\|file>` | `ash/cli.rs:317-322`, contact add | 2 |
| `raven send --carrier auto\|lan\|internet` (auto default: LAN, then Internet) | `ash/ext.rs:2048-2205`, `ash/cli.rs:351-354` (unhide) | 2 |
| Service and installers: `--internet-listen` default port 7422; `RAVEN_INTERNET_LISTEN`, `-InternetListen`; firewall hints; `raven node internet on --listen 0.0.0.0:7422 \| off` | `rn/main.rs:1815-1828`; `inst/*.sh`, `inst/windows_service.ps1`; `ash/cli.rs:637-669` | 2-3 |
| Gate flip + spec/waiver edits (§5 row P1) | `core/internet_gate.rs`, docs, freeze hashes | 2 |
| CI C2 on 3 OS + Internet stage-12 slice | harness | 2-3 |

Exit: CI green on 3 OS, R7a recorded, waiver signed. Benefit: friends with a VPS, a port-forward or open IPv6 message over the Internet.

### 7.3 P2a: background outbox worker (10-14 d)

| Item | Files / surface | Effort |
|---|---|---:|
| Worker task, scheduler, backoff, triggers, expiry, cancel-on-ACK | new `rn/outbox.rs`; `rn/main.rs:3398-3458` | 4-5 |
| Shared ACK acceptance + `PeerSendLock` into core | `ash/pair_init_lab.rs:65-95`, `:270-279` → `core/` | 2 |
| Push pending objects on authenticated inbound links | `rn/lan_direct.rs`, `rn/internet_direct.rs` serve loops; dialer side dispatches extra frames instead of only collecting replies | 2-3 |
| IPC `OutboxKick{v, peer_pub_hex?}`, `OutboxStatus{v, message_id_hex}` → `{state, carrier, attempts, next_attempt_ms, last_error_code}`, `OutboxList{v, peer_pub_hex?, limit≤200}`; no plaintext fields (`core/ipc.rs:112`) | `core/ipc.rs`, `rn/ipc_server.rs` | 1-2 |
| CLI `raven outbox [list\|status <mid>\|retry <mid>\|cancel <mid>]`; `send` returns "queued, raven-node keeps trying until HH:MM" after ≤ 10 s | `ash/cli.rs`, `ash/ext.rs` | 1-2 |
| Validity policy (F2) + optional proactive re-pair | `ash/pair_init_lab.rs:46`, `core/lan_dispatch.rs:552-558`, `:1831` | 1 |

Runs in parallel with P1 (independent files apart from `ash/ext.rs`).

### 7.4 P3: libp2p relay + hole punching (28-38 d + owner physical)

| Item | Files / surface | Effort |
|---|---|---:|
| Move swarm building blocks into the lib (`build_swarm`, Kad validation, key derivation) | `swarm/main.rs:137-252` → `swarm/lib.rs`; key fn into `core/` | 3 |
| `raven_swarm::host`: relay client, DCUtR, AutoNAT v2 client, Identify `/raven/identify/1.0.0`, Ping, limits, ip_limits, `libp2p-stream` | `swarm/host.rs` (from `swarm/connectivity.rs:490-562`); `Cargo.toml` features | 4-5 |
| `rn/p2p.rs`: supervised host in Service, listens 7423 TCP/QUIC v4/v6, reservation manager (≤ 2 relays, renew), `/raven/link/1.0.0` running Raven Noise `raven/p2p-link/v1` + RIH1 via `tokio_util::compat`, then `dispatch_frame` | new; reuse `rn/internet_direct.rs:206-378` with a prologue parameter | 6-8 |
| Dial strategy and carrier impl (direct → circuit → DCUtR; new link per upgrade) | `rn/carrier/p2p.rs` | 3-4 |
| `raven-node relay` (relay server, AutoNAT server, allow-list, limits §3.5, counts-only metrics) + `raven relay allow\|deny\|status\|card` | `rn/main.rs` Commands; new `rn/relay.rs`; `swarm/relay_server.rs` | 5-7 |
| Cards and route hints (`p2p=`, `via=`); RLB2 hints if that design freezes in time | `ash/`, `core/lan_rlb1.rs` successor | 2-3 |
| IPC `P2pDial{v, multiaddr, expected_pub_hex, frames_b64}`; `Status` adds `nat`, `reservations`, `listen_addrs` | `core/ipc.rs`, `rn/ipc_server.rs` | 1 |
| CI C6, C7 (netns), C10 relay abuse; installer flags `RAVEN_P2P_LISTEN`, `linux_systemd_relay.sh` | harness, `node/scripts/netns_nat_dcutr.sh`, `inst/` | 4-6 |

Exit: R7b and R8 recorded; an independent review of the public libp2p surface is recommended (§5).

### 7.5 P2b: bridge carrier over authenticated mesh links (20-28 d)

| Item | Files / surface | Effort |
|---|---|---:|
| `RHW1`/`RHR1` codec + vectors + `proto/RAVEN_TERMINAL_MESH_V1.md` | new `core/hop_wrapper.rs`; `shared-vectors/rvn1/mesh/` | 4-5 |
| `dispatch_relayed_object` + `find_confirmed_session_for_route` | new `core/relayed_dispatch.rs`; `core/indexed_session_store.rs` near `:3266` | 5-7 |
| RHW1 frame handling on all links; mesh-neighbour flag; quotas keyed by hop identity | `core/lan_dispatch.rs:1527` (new magic branch); `core/forward_queue.rs` peer key | 4-5 |
| `bridge_run` refactor: custody queue feeds mesh links; stop envelope mutation; drop remote raw-TCP listeners | `rn/bridge_run.rs`, `core/message_router.rs:73-90`, `core/bridge.rs:150-160` | 4-6 |
| Worker: mesh as a carrier attempt; custody evidence | `rn/outbox.rs` | 1-2 |
| CLI `raven node mesh add\|remove\|list --tag T`; doctor shows mesh links | `ash/cli.rs:637-669` | 1 |
| CI C8 (`0x03`, not the demo cipher; retire F7) | harness | 2 |

### 7.6 P4: multi-hop spray + mailbox (25-40 d)

| Item | Files / surface | Effort |
|---|---|---:|
| Multi-hop spray, inventory-on-connect, loop tests (A-B-C-D, rings, partitions) | `rn/bridge_run.rs`, `rn/outbox.rs`; `core/` sim extension of `RAVEN_NETWORK_SIMULATION_1000_V1` | 6-8 |
| Mailbox in relay mode (`--mailbox`), depositor allow-list, endpoint PUT/poll, `mbx=` card hint | `swarm/mailbox.rs`, `rn/relay.rs`, `rn/carrier/mailbox.rs` | 8-10 |
| Pairwise rendezvous records in Raven Kad (only after a spec + review) | `swarm/`, new companion | 10-15 (optional) |
| CI C9; R9 | harness | 3-5 |

### 7.7 Order and why it differs from P1 → P2 → P3 → P4

1. **P0** first: F1, F3 and F4 are cheap. F4 must precede any public listener; F1 and F3 must precede any custody path.
2. **P1 ∥ P2a.** P1 is the cheapest real Internet benefit. P2a improves *every* carrier (LAN included) and is a prerequisite for anything asynchronous. Together about 4-5 weeks with two engineers **(guess)**.
3. **P3 before P2b.** Most residential, mobile-hotspot and CGNAT users cannot accept inbound connections. For them, P1 does nothing and P2b alone is a dead end within 24 h (F6). P3 gives them both live delivery *and* the confidential pairing path that P2b depends on. It also matches the owner's model directly ("every node can be a relay").
4. **P2b, then P4.** The mesh is most useful once P3 provides pairing and re-pairing; the mailbox is least valuable while sessions last 24 h.

If the owner prefers the original order, P2b still works for contacts who re-pair over LAN or P1 at least daily. State that limit in the UX.

## 8. Risks and open questions for the owner

| # | Risk or question | My recommendation |
|---|---|---|
| Q1 | Each phase extends a waived slice without independent review. P3 adds the first public-facing libp2p surface (relay server, AutoNAT server, Identify, Kad later) | Waivers for P1/P2a/P2b; a focused external review before the P3 flag flips |
| Q2 | 24 h sessions + PairInit confidentiality (F6) | Ship proactive re-pair in P2a; prioritise the ratchet design; do not go back to 7 d |
| Q3 | Offline first contact and re-pair through a store need a sealed async PairInit carrier, for example PairInit sealed to the recipient's prekey with no outer sender signature | Specify as a companion after P3; until then, first contact needs a live confidential link |
| Q4 | Envelope validity: 1 h today (F2). Longer validity lets hops and stores hold copies longer; re-sealing after expiry risks a visible duplicate if the old copy did arrive | min(session end, 24 h); no automatic re-seal; the user chooses "resend" with a "may duplicate" note |
| Q5 | The outer Ed25519 signature names the sender to every hop, store and relay that holds the sender's public key | Disclose now; a sealed-sender envelope version later (umbrella revision) |
| Q6 | Stable PeerId (`swarm/main.rs:141-152`) links a user across relays and networks for ever; cards map it to the Raven ID | Accept for P3 (reservations need stability); consider per-epoch rotation announced through route hints later |
| Q7 | Open relays attract abuse; operators relay encrypted traffic for people they do not know (legal and abuse exposure) | Allow-list (friends) by default; `--open` explicit, with stricter limits and a printed notice |
| Q8 | UPnP/NAT-PMP would reduce relay load but opens router ports silently | Off by default; `raven node upnp on` opt-in |
| Q9 | Windows runs as a logon task, not always on; no Windows relay | Document; relay = Linux VPS; revisit an SCM service later |
| Q10 | Headless Linux endpoint with a passphrase vault cannot restart unattended | Decide between systemd credentials and a manual unlock (`raven keystore unlock`); relays need neither |
| Q11 | Two Internet stacks (raw RIH1 on 7422, libp2p on 7423) double the audit surface | Keep raw RIH1 for P1 speed; after P3, make libp2p direct the default and deprecate 7422 after one release (decision at P3 exit) |
| Q12 | NAT spec §6 requires iOS parity; the owner deferred iOS | Record an explicit waiver line; do not let it lapse silently |
| Q13 | Kademlia: public PeerRecords leak presence (F5) | No DHT in P1-P3; pairwise records only after a spec |
| Q14 | Clock skew between Internet hosts against `expires_at` and PairInit windows | Keep the normative ±5 min; `raven doctor` warns when the system clock is not NTP-synced (verify per OS) |
| Q15 | Fingerprint-unverified contacts on non-LAN carriers (§3.2) | Refuse non-LAN carriers until verified; owner to confirm the UX cost |
| Q16 | Mesh spray amplifies traffic in dense friend graphs | Budgets 3 hops / 4 copies, per-hop quotas; measure in the 1000-node simulation before P4 |
| Q17 | Effort estimates are unmeasured guesses; P3 depends on rust-libp2p APIs I marked (verify) | Spike `libp2p-stream` over a limited (relayed) connection in the first 2 days of P3 |
