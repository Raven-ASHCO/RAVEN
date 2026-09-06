# Trust Boundaries — Architect Draft (Sprint 0)

**Status:** Architect draft — **not Security Board approved**  
**Primary owner:** #1 Principal Architect  
**Mandatory reviewers (checklist):** #17 Security Assurance Lead (Security Board chair), #6 Identity Lead  
**Also consult:** #5 Crypto Lead (ATSAM/keys), #4 Raven↔RDAP Interop, #14 RDAP Protocol Lead  
**Date:** 2026-09-04  
**Risk class of *changing* a boundary in code:** R3 (`risk-classes.md`, `approval-matrix.md` row “Trust boundary change”). This markdown is R0 documentation of the current model.

> **Coordination note.** Sprint 0 checklist assigns Trust boundaries to **#1, #17, #6**. This file is the Architect (#1) draft. Security Board (#17) and Identity (#6) are invited to mark gaps, reclassify residual risk, and reject undocumented assumptions before this row is treated as an assurance artifact. #1 will not self-merge any follow-up R3 change that *implements* a boundary.

Cross-links: [`architecture-dependency-map.md`](architecture-dependency-map.md), [`risk-classes.md`](risk-classes.md), [`approval-matrix.md`](approval-matrix.md), [`org-structure.md`](org-structure.md), [`docs/THREAT_MODEL.md`](../../THREAT_MODEL.md), [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../../../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md). Identity SoT on `main` (landed [PR#5](https://github.com/Raven-ASHCO/RAVEN/pull/5)): [`SPRINT0_IDENTITY_THREAT_MODEL.md`](../../SPRINT0_IDENTITY_THREAT_MODEL.md), [`G5_CROSS_STACK_REVOKE_POLICY.md`](../../G5_CROSS_STACK_REVOKE_POLICY.md). Raven↔RDAP confidential path + Appendix G5: ADR 0004 ([PR#3](https://github.com/Raven-ASHCO/RAVEN/pull/3); not yet on `main`).

---

## How to read this draft

For each boundary:

- **Trusted** — components allowed to see or decide the protected asset.
- **Untrusted** — anything on the other side of the cut; authenticate and bound it.
- **Must validate** — concrete checks that already exist or are **required but not live**.
- **Owner role(s)** — primary + board, matching `approval-matrix.md`.
- **Threat-model rows** — `THREAT_MODEL.md` adversary classes.
- **Gaps** — undocumented assumptions or missing enforcement.

**Global posture (2026-08-13):** RVN1 is under a **production hold**. Older “Protected” verdicts that depend on live ATSAM E2EE, authenticated ACKs, or bounded multi-hop forwarding are superseded (`THREAT_MODEL.md` executable-posture table). Boundaries below describe the *intended* cut plus what the audited code actually does.

---

## TB1 — Process / IPC boundary (client ↔ raven-node)

**Cut:** A user-facing process (`ash` / `raven`, future RDAP helper, **UNKNOWN** iOS/Windows hosts) talks to the `raven-node` daemon. Unix: UDS `data_dir/raven-node.sock`. Windows: documented named pipe `\\.\pipe\raven-node` — **client not landed** (`node/scripts/install/WINDOWS_SERVICE.md`).

| | |
|--|--|
| **Trusted** | `raven-node` process (same euid as the connecting client). OS peer-cred. Data-dir owner. |
| **Untrusted** | Any other local process, other UIDs, stale sockets, malicious `IpcRequest` bytes, argv/`ps` observers. |
| **Must validate** | `IPC_VERSION == 1`; frame ≤ `MAX_IPC_FRAME` (256 KiB); JSON tag `op`; **refuse** substrings `seed` / `private_key` / `plaintext` / `recovery`; envelope decode on `EnqueueSealed`; `expected_pub_hex` on `LanDial`; UID match via `SO_PEERCRED` / `getpeereid`. Socket mode `0600`, unlink/rebind on start. |
| **Evidence** | `node/crates/raven-core/src/ipc.rs`; `node/crates/raven-node/src/ipc_server.rs`; ADR 0003; `protocol/RAVEN_ERROR_CODES_V1.md` (`IPC_*`). |
| **Owners** | #7 Core Runtime (IPC/daemon), #1 (boundary shape), #17 if authz/peer-cred changes. Identity #6 if IPC ever carried credentials (it must not). |
| **THREAT_MODEL** | §3.7 stolen unlocked device (out of scope once attacker is the user); §3.16 local malware (out of scope); MASTER checklist “Local IPC Security” in `node/MASTER_ENGINEERING_CHECKLIST.md` §19. |
| **Risk class** | Changing IPC auth or allowing secrets on the wire: **R3**. Adding a non-secret op: **R2**. |

**Allowed ops today:** `Ping`, `Status`, `SetPolicy`, `EnqueueSealed` (already-sealed envelope only), `LanDial`. Daemon “never seals from plaintext here.”

### Gaps / assumptions (TB1)

| ID | Gap | Assumption if unreviewed |
|----|-----|--------------------------|
| G1 | Same-UID is the entire local authz model | Any code running as the user is the user (`THREAT_MODEL` §3.16). No macOS/Windows code-signing check of the client binary. |
| G2 | Windows named-pipe client missing | Windows path is `--send-stdin` spawn (plaintext on a pipe to a child — still local, but **not** the UDS auth story). |
| G3 | `ash` also opens `queue.sqlite`, `contacts.json`, `forward_queue.sqlite` **directly** | IPC is not the only client↔node coupling. A compromised `ash` is a compromised data-dir. See undocumented deps D8. |
| G4 | No RDAP IPC client | RDAP does not cross this boundary at all (integration gap). |
| G5 | iOS/Watch/Windows app IPC | **UNKNOWN** — trees absent from this checkout. |

---

## TB2 — Network boundary (swarm / BLE / bridge)

**Cut:** Bytes arriving from LAN TCP, InternetTransport (`RIH1` + length-prefixed frames), libp2p (`raven-swarm`), BLE GATT / mock-BLE, or a Bridge hop. Relays and stores are **untrusted** (`SERVERLESS_FRIEND_MESH_BRIDGE_DESIGN.md` plane 2–3). Founder priority (2026-09-04): terminal Win/macOS/Linux first; keep the three delivery pathways (mesh relay / bridge / direct internet) uncollapsed — [`architecture-dependency-map.md` §2.1](architecture-dependency-map.md). Architecture lock ≠ proof: try-phase **executed evidence** required before a pathway is “proven.” On `main`, terminal mesh “proven” = **`mock_ble` only** until B8 + RBF1 (`architecture-dependency-map.md` §2.1). iOS/Watch trees **UNKNOWN** / deferred.

| | |
|--|--|
| **Trusted** | Local envelope parser + (intended) ATSAM endpoint. Path selection in `raven_core::transport`. |
| **Untrusted** | Every peer, relay, store, DHT participant, BLE neighbor, ISP, Bridge operator. FastAPI **must not** be on this path. |
| **Must validate** | Size → strict `RVN1` decode → TTL → route/session → outer auth → AEAD open → transactional commit (`THREAT_MODEL` §3.3 intended order). Caps are generic (`ble`/`internet`/`relay`/`store`/`bridge`) — never contact graphs (ADR 0002). BLE: `validate_opaque_rvn1` before TX (`RAVEN_BLE_FRAMING_V1.md`). Swarm mailbox: endpoint-supplied 16-byte `store_tag`, no derive-from-routing-tag (`mailbox.rs`). |
| **Evidence** | ADR 0002; `RAVEN_TRANSPORT_INTERFACE_V1.md`; `RAVEN_BRIDGE_V1.md`; `RAVEN_BLE_FRAMING_V1.md`; `docs/MESH_PROTOCOL.md` (legacy GATT JSON); `raven-node/src/main.rs` frame limits; `raven-swarm`. |
| **Owners** | **Role #6** P2P / libp2p Network (`raven-swarm`; Sprint 0 assignment — freeze org-structure numbers this **#9**); #10 Transport (BLE/framing); #2 Protocol (wire); #12 Apple (GATT); #17 for hold/errata. Identity Lead remains freeze-org **#6** on TB3 — not the swarm owner. |
| **THREAT_MODEL** | §3.1 malicious relay; §3.2 store; §3.3 malicious peer; §3.4 passive ISP; §3.8/3.9 Sybil/eclipse; §3.15 malformed packet; §3.17 traffic analysis (out of scope). |

**Two encryption layers (design):** transport Noise/TLS ≠ Raven E2EE. Relays never decrypt sealed content (ADR 0002).

**Mesh relay ≠ Circuit Relay v2.** TB2 “mesh / BLE” is the founder delivery pathway (nearby/`mock_ble` opaque forward). libp2p Circuit Relay v2 is a different, production-disabled NAT mechanism — see [`architecture-dependency-map.md` §2.1](architecture-dependency-map.md) and [`docs/network/raven-swarm-connectivity-matrix.md`](https://github.com/Raven-ASHCO/RAVEN/blob/main/docs/network/raven-swarm-connectivity-matrix.md) §0 (on `main`).

**Legacy vs RVN1:** `docs/MESH_PROTOCOL.md` is SoT for **shipped iOS GATT JSON** (including `Data.hashValue` chunk-key quirk). `RAVEN_BLE_FRAMING_V1.md` is SoT for **RVN1** (`RBF1` chunks). Do not mix parsers.

### Gaps / assumptions (TB2)

| ID | Gap | Assumption if unreviewed |
|----|-----|--------------------------|
| G6 | Hop / `replication_budget` **not** in sender signature | Cooperative policy only; Byzantine relay can raise them (`SPEC.md` invariant 7, errata). |
| G7 | Peer scoring / Sybil resistance “future work” | Connection caps bound resources, not identity (`THREAT_MODEL` §3.8). |
| G8 | Public Internet Kad / multi-NAT | `NAT_STATUS` / `RAVEN_NAT_CONNECTIVITY_V1.md` **BLOCKED_HARDWARE**; experimental bin only. |
| G9 | Go `Libp2pBridge` cited at `ios-native/RAVEN/Libp2pBridge/bridge.go` | **UNKNOWN** in this snapshot; ADR 0001 allows it as a mobile helper until Rust parity. |
| G10 | RDAP HTTP `:9001` and Git relay are **additional** network cuts, not Raven transports | Signed A2A ≠ envelope path. See TB4. |
| G11 | Mock-BLE is TCP on loopback | CI stand-in; not a radio security claim (`SERVERLESS_MODEL.md`). |

---

## TB3 — Crypto / identity boundary (ATSAM, keys, peer pinning)

**Cut:** Long-term Ed25519 user identity, device certificates, PairInit / prekeys, ATSAM session roots, and the **pin** that makes a network peer “this person.” Transport PeerId is a different namespace (ADR 0003; swarm derives libp2p key from `SHA-256("raven/libp2p-peer-key/v1" ‖ seed)`).

| | |
|--|--|
| **Trusted** | Platform keystore for the 32-byte seed (`identity_store.rs`, `docs/IDENTITY_SEED_STORAGE.md`). Intended ATSAM indexed-session actor (production-disabled). Human OOB check (QR / fingerprint / safety number). |
| **Untrusted** | Relays, DHT, anyone presenting an address without a local pin, RDAP’s **separate** `.team/keys` principal, `unsafe-demo-crypto` / proto `0x7F` interim sealer, lab Full Braid FFI. |
| **Must validate** | Address checksum (`RAVEN_ADDRESS_V1`); device cert + registry; contact add with `--verify-fp`; `LanDial.expected_pub_hex`; PairInit transcript bind (disabled); refuse logging seeds; RDAP `validate_address_public_key` + pin on trust/invite. |
| **Evidence** | ADR 0003; `RAVEN_IDENTITY_V1.md`; `RAVEN_PAIR_INIT_V1.md`; `ATSAM_*`; `docs/IDENTITY_SEED_STORAGE.md`; ash `contact add`; RDAP `raven_identity.py` + README trust model. |
| **Owners** | #6 Identity (pins, certs, authz), #5 Crypto (ATSAM/primitives/RNG), #3 Spec (versioned identity records), #17 Security Board second on R3. **#1 must not self-merge.** |
| **THREAT_MODEL** | §3.5 active MITM; §3.6 stolen locked device; §3.13 alias impersonation; §3.14 downgrade; errata on publicly derivable interim cipher. |
| **Risk class** | Any key-handling / ATSAM / pin-rule change: **R3**. |

**Pinning today (terminal):** local `contacts.json` maps petname/tag → `rvn1…` + pub hex + optional fingerprint (`SERVERLESS_FRIEND_MESH_BRIDGE_DESIGN.md`). Friendship never uses FastAPI.

**Pinning today (RDAP):** invite line `RDAP1 <name> <rvn1> <ed25519> <url>`; `trust` live-checks signed Agent Card against that pin. The RDAP pin Ed25519 is an **address-level** pin (`rvn1…` / user-identity key material). **Pin ≢ `device_ed_pub`.** RVDR1 covers **device lineage** only and does not revoke the address; a pin match is not a device-cert match ([`G5_CROSS_STACK_REVOKE_POLICY.md`](../../G5_CROSS_STACK_REVOKE_POLICY.md), ADR 0004 Appendix G5 on [PR#3](https://github.com/Raven-ASHCO/RAVEN/pull/3)). Today’s RDAP key under `.team/keys` is still a **separate store** from `raven-node` unless M1 binds the same RVN1 (ADR 0004 D3; not implemented here).

### Gaps / assumptions (TB3)

| ID | Gap | Assumption if unreviewed |
|----|-----|--------------------------|
| G12 | ATSAM session / PairInit / prekey lifecycle **production-disabled** | Default `raven-node` origination requires authenticated session; demo sealer is feature-gated. No production E2EE claim. |
| G13 | Two identity stores (raven-node vs RDAP `.team/keys`); pin ≢ `device_ed_pub` | Address format may match; **principal / lineage is not**. An ash `contacts.json` pin does not authorize an RDAP peer and vice versa. Applied RVDR1 ⇒ **lineage-scoped data-plane fail-closed** (session/task refuse for that device lineage) — not an automatic RDAP address-deny, and not a pin-string equals `device_ed_pub` predicate. See Identity G5 + ADR 0004 Appendix G5. |
| G14 | Linux Secret Service vs locked-file fallback | `IDENTITY_SEED_STORAGE.md` vs `identity_store.rs` comments disagree on whether locked-file is “approved fallback” or “lab/CI override only”. **Needs #6+#5 resolution.** |
| G15 | `AfterFirstUnlockThisDeviceOnly` on iOS | Keys may be available while locked after first unlock (`THREAT_MODEL` §3.6). |
| G16 | Windows RDAP key files lack tested DACL-equivalent to POSIX `0600` | RDAP README Windows security hold. |
| G17 | Human QR/safety-number check is user responsibility | Crypto cannot prove the human (`THREAT_MODEL` §3.5). |
| G18 | Full Braid / ML-KEM incremental FFI | Lab/DEBUG only; Release `compile_error!`. Still an identity-adjacent binary interface if linked. |
| G29 | Soft-load fail-open on corrupt **denylist** | See **OPEN-ID-P0** below. Not an Architect approval of the behavior. |

### OPEN-ID-P0 — Soft-load fail-open if denylist is corrupt

**Status:** draft / **OPEN** — Identity docs on `main` via [PR#5](https://github.com/Raven-ASHCO/RAVEN/pull/5) ([`SPRINT0_IDENTITY_THREAT_MODEL.md`](../../SPRINT0_IDENTITY_THREAT_MODEL.md) §3.2 P0 + G5, [`G5_CROSS_STACK_REVOKE_POLICY.md`](../../G5_CROSS_STACK_REVOKE_POLICY.md)); Architect ack on §2.4 + P0 note; **code held** (Manager Sprint 1 batch with Architect + Crypto). Architecture does **not** approve or implement denylist load behavior in this PR.

| | |
|--|--|
| **Behavior (named)** | Soft-load **fail-open** when a local denylist / block / revocation store is **corrupt**: `load()` returns an empty default instead of refusing the operation. Empty denylist ⇒ nobody is blocked or revoked. |
| **Where observed (cite only)** | `BlockList::load` → `load_checked(...).unwrap_or_default()` (`node/crates/raven-core/src/chat_history.rs`); test `block_list_corrupt_is_fail_closed` documents that legacy `load()` still returns empty `pub_hex` for non-LAN callers. Same soft-load shape: `RevocationStore::load` (`device_sync.rs`); `load_device_registry` (`device_cert.rs`). `load_checked` variants are the fail-closed pair. Callers that still use `load()` (e.g. `ash` `cli.rs` discovery `BlockList::load`) take the fail-open path. |
| **Risk** | **Availability vs security.** Fail-open keeps the node usable after disk/JSON damage (availability). It **widens trust**: a corrupt or attacker-truncated denylist is treated as “no denials,” so previously blocked peers or revoked devices may be admitted until an operator notices. That is a persistence-integrity hole on TB3 (identity/authz) and TB5 (on-disk policy). Fail-closed (`load_checked`) is the opposite tradeoff (safer deny, possible denial-of-service if the file is unreadable). |
| **THREAT_MODEL** | Identity SoT on `main` ([PR#5](https://github.com/Raven-ASHCO/RAVEN/pull/5)): [`SPRINT0_IDENTITY_THREAT_MODEL.md`](../../SPRINT0_IDENTITY_THREAT_MODEL.md) §3.2 P0 + G5; [`G5_CROSS_STACK_REVOKE_POLICY.md`](../../G5_CROSS_STACK_REVOKE_POLICY.md). Adjacent Raven TM: §3.6, §3.11, revocation freshness (partition-limited). |
| **Owners** | **Identity (#6) primary.** **Security Board (#17) review** still requested. **Architect (#1) ACK’d** Identity §2.4 trust boundaries and this soft-load P0 as a **documented trust-boundary defect**. That ack is **not** code approval or an R3 merge. |
| **Architecture action now** | Status updated to PR#5 + §2.4/P0 ack. No denylist implementation, no load-path change, no R3 self-merge. |
| **Code** | **Held** for Manager Sprint 1 batch with Architect + Crypto. Status stays OPEN until #6+#17 close the assurance item and the held fix lands. |

---

## TB4 — RDAP agent / runtime boundary (signed tasks, reply, replay)

**Cut:** Untrusted natural-language / tool context vs delegated authority. RDAP today is an **experimental A2A companion**, not the approved `RAVEN_USER_OWNED_AGENT_RUNTIME_V1` executor.

| | |
|--|--|
| **Trusted** | Operator-pinned peer (address+key); verified HTTP signature (`raven.a2a.http-request.v1`); verified delegation (`raven.a2a.delegation.v2`); local revocation file (fail-closed); replay caches (transport and delegation, durable SQLite). |
| **Untrusted** | Task text, LLM output, tool results, Git history outside the `.team` allowlist, mDNS discover (TOFU), `--open` unsigned mode, `--allow-shell` (full OS user), remote model providers (plaintext leaves E2EE). |
| **Must validate** | Default reject unsigned RPC/tasks; pin match on card and reply; nonce+expiry+skew; replay `first_time`; owner-scoped task store; cancel requires owner’s fresh Raven HTTP signature; body/in-flight limits (`TEAM_MAX_*`). Mailbox path: operator flag `--experimental-plaintext-mailbox` — **must not** be sold as confidential. |
| **Evidence** | RDAP `README.md`; `team_agents/server.py`, `client.py`, `raven_identity.py`, `task_store.py`, `mesh.py`, `tools.py`. Runtime *intent*: `protocol/RAVEN_USER_OWNED_AGENT_RUNTIME_V1.md` (not approved; does not name RDAP). O6 confidential path (ATSAM via `raven-node` `LanDial`; signed HTTP = control plane only): ADR 0004 ([PR#3](https://github.com/Raven-ASHCO/RAVEN/pull/3)) + Appendix G5. |
| **Owners** | #14 RDAP Protocol, #15 RDAP Runtime, #4 Interop, #16 UX/tooling, #6 if identity merge, #17 if security interop. |
| **THREAT_MODEL** | Raven TM does **not** enumerate A2A/LLM/tool threats. Runtime spec §2 does (prompt injection, capability replay, confused deputy). Joint revoke mapping: Identity G5 + ADR 0004 Appendix G5 (lineage-scoped data-plane fail-closed; pin ≢ `device_ed_pub`). |
| **Risk class** | Carrier onto ATSAM / identity merge / unsigned-default change: **R3**. Tool policy / LLM endpoint: **R2–R3**. |

**Honest output modes** (runtime spec §3.2): recommendation vs user-confirmed draft vs delegated agent action. RDAP `ask` is mode-3-shaped (distinct key, signed task) but **without** the Raven capability verifier / human-approval executor in that spec.

### Gaps / assumptions (TB4)

| ID | Gap | Assumption if unreviewed |
|----|-----|--------------------------|
| G19 | RDAP has no production ATSAM data plane yet | Tasks never enter `EnqueueSealed` / `LanDial`. Production Raven confidentiality **does not apply**. Intended O6 path: ADR 0004 ([PR#3](https://github.com/Raven-ASHCO/RAVEN/pull/3)) — ATSAM-sealed frames via `raven-node` only; signed HTTP stays control plane. |
| G20 | `env_type=4` + zeroed `sender_authentication` on mailbox envelopes | Outer RVN1 auth is vacant; “E2E auth lives INSIDE body sig” (`mesh.py`). A Raven node that later accepts these as capabilities or as signed envelopes will mis-handle them. |
| G21 | `store_tag = SHA-256("rdap-task:" ‖ address)[:16]` | Stable, address-derived, not `K_route` rotating mailbox (`RAVEN_STORE_OBJECT_V1.md`). Linkable and not a Raven polling capability. |
| G22 | Runtime spec vs RDAP implementation | Spec forbids treating model output as authority; RDAP still sends task text to an LLM/tools. Enforcement is signature+pin+path policy, not the AR1–AR12 capability machine. |
| G23 | `--allow-shell` / `--open` | Documented foot-guns; default off. Any default-on change is R3. |
| G24 | Joint Raven↔RDAP revoke / confidential-path docs vs live code | O6 **inventory** landed 2026-09-06: [`o6-raven-rdap-try-phase-gap-board.md`](o6-raven-rdap-try-phase-gap-board.md) (Sprint 0 row IN PROGRESS). ADR 0004 + Appendix G5 and Identity G5 remain the docs SoT (PR#3 / PR#5); **code held**. Applied device-lineage revoke ⇒ lineage-scoped data-plane fail-closed, not automatic address-deny. Harness / interop CI still RED. |

---

## TB5 — Persistence boundary (SQLite / SQLCipher)

**Cut:** On-disk state vs process memory vs platform secret stores.

| Store | Encryption | Contents | Who opens it |
|-------|------------|----------|--------------|
| `identity.seed` / Keychain / DPAPI / Secret Service | Platform | 32-byte Ed25519 seed | `identity_store.rs` (ash, node, swarm if same data-dir) |
| `queue.sqlite` | **rusqlite bundled SQLite — not SQLCipher in default features** | Outgoing envelopes + inbound seen IDs | `raven-core::queue`; ash **and** node |
| `forward_queue.sqlite` | Same (unencrypted SQLite) | Bridge custody | node `bridge_run`, ash status paths |
| Chat history / stage locks | SQLite | History, staged outbound | `chat_history.rs` |
| Indexed session / prekey lifecycle files | Intended protected store; **production-disabled** | Session/prekey actors | core modules with `PRODUCTION_ENABLED` flags |
| SQLCipher 4.17.0 | Lab feature `full-braid-durable-lab` only | Full Braid durable lab | `full_braid_durable_lab/*`; release must fail closed (`build.rs` comment in core) |
| RDAP replay `*.sqlite` | SQLite, mode `0600` on POSIX | Signature hashes + expiry | `raven_identity.py` `ReplayCache` |
| RDAP `.team/keys` | File; POSIX `0600`; Windows DACL **untested** | Agent Ed25519 | `RavenIdentity.load_or_create` |

| | |
|--|--|
| **Trusted** | OS user + disk encryption + platform keystore. Lab SQLCipher profile guard (when that feature is on). |
| **Untrusted** | Stolen disk without platform unlock; copied `data_dir`; other users if mode bits slip; RDAP Git relay (must not stage keys — allowlist in README). |
| **Must validate** | `0600` / DACL; no seed in logs; WAL schema race handling (`raven-node` comments); SQLCipher profile overrides rejected (`raven-sqlcipher-profile-guard`); RDAP relay exclude `.team/keys` and replay DBs. |
| **Evidence** | `queue.rs`, `IDENTITY_SEED_STORAGE.md`, `node/third_party/sqlcipher-4.17.0/PROVENANCE.md`, RDAP README. |
| **Owners** | #7 / #8 (default SQLite), #5 / #6 (keystore + SQLCipher lab), #17 (hold on calling default queues “encrypted at rest”), #15 (RDAP stores). |
| **THREAT_MODEL** | §3.6 locked device (partial); §3.7 unlocked (out of scope). No dedicated “DBA on the same UID” row. |

### Gaps / assumptions (TB5)

| ID | Gap | Assumption if unreviewed |
|----|-----|--------------------------|
| G25 | Default message queues are **not** SQLCipher | “Persistence boundary (sqlite/sqlcipher)” in the Sprint 0 prompt must not be read as “production uses SQLCipher.” SQLCipher is lab-gated. |
| G26 | Same files opened by ash and raven-node | Multi-process SQLite (WAL) is an implicit concurrency contract — not an ADR. |
| G27 | Swarm mailbox default persist `offline_mailbox_v1.json` | Feature-gated; JSON not SQLCipher (`mailbox.rs` `MAILBOX_DB_FILENAME`). |
| G28 | RDAP replay uses `journal_mode=DELETE` + `secure_delete=ON`, not Raven WAL queues | Two persistence dialects; no shared backup/migration story. |
| G29 | Soft-load fail-open on corrupt denylist / block / revocation files | Same OPEN-ID-P0 as TB3. Identity on `main` ([PR#5](https://github.com/Raven-ASHCO/RAVEN/pull/5)); #1 ACK’d §2.4 + P0 note; **code held.** **#17 review still requested.** |

---

## Role ownership summary

| Boundary | Primary role(s) | Board / second |
|----------|-----------------|----------------|
| TB1 IPC | #7, #1 | #17 if authz |
| TB2 Network | **Role #6** P2P (`raven-swarm`); #10 framing; #2 | #12 BLE; #17 errata |
| TB3 Crypto/identity | #5, #6 | Security Board #17; #3 if spec version |
| TB3/TB5 OPEN-ID-P0 denylist fail-open | **#6** | **#17** review still requested; **#1** ACK’d PR#5 §2.4 + P0 (no code approval; code held) |
| TB4 RDAP runtime | #14, #15, #4 | #17 if interop security; #6 if identity merge |
| TB5 Persistence | #7, #8, #5 | #17 (encryption claims) |

Architecture Board (#1 chair, #2, #4, #7) owns the *shape* of these cuts. Security Board (#17 chair, #5, #6) owns *whether the cut is adequate*. Eng Management cannot waive R3 no-self-merge (`risk-classes.md`).

---

## Residual risk the Architect is **not** asserting as closed

1. Production E2EE / ACK / replay journals are **held** (`THREAT_MODEL.md` posture table).
2. RDAP confidentiality is **not** Raven E2EE on any current carrier (ADR 0004 O6 path not implemented; HOLD).
3. Local same-UID malware is **out of scope**.
4. Traffic analysis is **out of scope**.
5. Client trees (iOS/Windows) were **not inspectable** in this RAVEN snapshot.
6. **OPEN-ID-P0** — soft-load fail-open on corrupt denylist is **not closed**. Identity docs on `main` (PR#5); Architect ack on §2.4 + P0 note; **code held.**
7. Pin ≢ `device_ed_pub`. Device-lineage revoke is **lineage-scoped data-plane fail-closed**, not an automatic RDAP address-deny (Identity G5 + ADR 0004 Appendix G5).

#17 / #6: please confirm or rewrite G1, G13–G16, G19–G21, G25, and **OPEN-ID-P0** before this document is cited as an assurance baseline. This remains an Architect draft — Raven↔RDAP countersign polish is **not** a new gate and **not** Security Board approval.
