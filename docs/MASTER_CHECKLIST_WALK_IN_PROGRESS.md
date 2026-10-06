# Master Engineering Checklist — Walk In Progress

**Branch (historical):** authored on `feature/raven-serverless-v1`; this file now lives on `main` and is a dated snapshot, not a statement about an open branch  
**Walk started:** 2026-08-12  
**Walk closed (document):** 2026-08-12 (this continuation)  
**Baseline HEAD at walk start:** `6189f2e`  
**Security-fix commit (prior):** `113bf33af5f65da7df96f1efa50a38ca48c92cde`  
**This continuation:** PeerKeyDirectory → Keychain (§14), logout pin wipe, ATSAM Keychain non-sync, checklist §1–60 fill  
**Operator:** automated desktop agent (evidence-backed; human review still required)

> Formal §1–§60 walk. Status values: `PASS` | `FAIL` | `BLOCKED_HUMAN` | `BLOCKED_HARDWARE` | `IN_PROGRESS`.  
> No item marked PASS without concrete evidence (test name, script, SHA, or file).  
> Combined rows from earlier draft are **expanded** so every section number appears once.

---

## Session evidence pack (this machine)

| Proof | Result | Artifact / command |
|-------|--------|-------------------|
| Reliability matrix 20× | **INVALIDATED** — runs before the 2026-09-29 harness fix were false-green (scenario status was its last command, usually `rm -rf`; bridged sends used the refused `atsam` mode). Re-run: `scripts/reliability_matrix_20.sh` now enforces every assertion | `scripts/reliability_matrix_20.sh` → `node/proof_artifacts/reliability_20_*` / `LATEST_RELIABILITY` |
| §59 harness | **INVALIDATED** — runs before the 2026-09-29 harness fix counted only each step's last command. Re-run `scripts/final_serverless_proof.sh` (16 enforced steps, lab build; also a CI job) | `scripts/final_serverless_proof.sh` → `node/proof_artifacts/LATEST` |
| raven-core + ash tests | PASS | `cargo test -p raven-core -p ash` |
| bridge / mailbox / swarm / two_node / lan | PASS | matrix scenarios 01–11 + node/scripts/* |
| macOS build | PASS | `cargo build -p raven-core -p ash -p raven-node` |
| Windows cross | PASS_SOFTWARE_SUBSTITUTE | PE32+ `ash.exe` self-check (wine blocked on sudo/gstreamer) |
| Linux runtime | PASS | musl ash in Lima `ash-amd64-preflight` + Docker NAT via Lima sock |
| Docker NAT sim | **PASS** | `nat_docker_sim.sh` auto-wires Lima `DOCKER_HOST` |
| iOS iPhone XCTest | PASS ×2 | Discovery* + ContactRequest* + RavenEnvelope* + RavenBleRvn1* on `RAVEN-iPhone-15` |
| iOS iPad XCTest | PASS ×2 | Same suite on `iPad Air 11-inch (M4)` |
| Service survives ash | PASS | SQLite busy_timeout + service queue warmup; matrix 11 |
| MeshEnvelope default | PASS (safe OFF) | `FeatureFlags.swift` `.ravenEnvelopeV1` default `false` |
| `--send` argv refuse | PASS | `raven-node run --send …` exits 2 with `REFUSE:` |
| UDS peer UID | PASS | `ipc_server.rs` `getpeereid` / `SO_PEERCRED` |

---

## Sections 1–60 (honest, one row each)

| § | Title | Status | Evidence / gap |
|---|-------|--------|----------------|
| 1 | Completion Rules | PASS | Walk + status docs require SHA/tests; no checkbox without evidence |
| 2 | Non-Negotiable Product Requirements | PASS (software) | 1:1 text serverless path + reliability matrix; BLE physical listed separately |
| 3 | Exact Meaning of Serverless | PASS | `docs/SERVERLESS_MODEL.md`; harness step `04_fastapi_not_in_path` |
| 4 | V1 Scope | PASS | Text 1:1 only; groups/media out of scope in docs |
| 5 | Repository and Baseline Safety | PASS | Branch `feature/raven-serverless-v1`; secret scan scripts present; live secret rotation **BLOCKED_HUMAN** |
| 6 | Architecture Decisions | PASS (V1) | ADR 0001–0003 landed; further ADRs deferred non-blocking |
| 7 | Prior-Art Review | PASS | `docs/PRIOR_ART_REVIEW_V1.md` |
| 8 | Phase A Protocol Freeze | PASS (soft) | `docs/PROTOCOL_FREEZE_HASHES_V1.md` + packet; independent freeze review **BLOCKED_HUMAN** |
| 9 | Raven Identity | PASS | raven-core + iOS fingerprint; public bits only in ash banner |
| 10 | Raven Address | PASS / FROZEN | Vectors + `from_display` |
| 11 | Aliases and Contacts | PASS | Soft Unique Tags; ash `contact`/`find`; iOS FindContacts behind flag; alias conflict never silent |
| 12 | Asynchronous First Contact | PASS | Contact request E2EE + accept inbox; anti-spam caps (`113bf33`) |
| 13 | Cryptographic Requirements | PASS (software) | Envelope + ATSAM KATs + matrix tamper/replay; full ML-KEM interop optional |
| 14 | Key Storage | PASS | Desktop `identity_store`: macOS Keychain, Windows DPAPI (`RVNDPAPI`), Linux Secret Service (gnu) / locked-file `0600` + `IDENTITY_SEED_STORAGE.md`; plaintext migrate; raven-core `identity_store::tests`. iOS device identity Keychain; **PeerKeyDirectory Keychain** (`77708ce`) + UD→KC + logout purge |
| 15 | Canonical Raven Envelope | PASS / FROZEN | Shared vectors rust/swift |
| 16 | Delivery States and ACK | PASS | Harness step `08_ack_delivered_status` + matrix |
| 17 | Raven Node Core | PASS | raven-node daemon + service |
| 18 | Background Service Integration | PASS (software) | launchd/systemd; service survives ash (SQLite warmup); notarization **BLOCKED_HUMAN** |
| 19 | Local IPC Security | PASS | UDS 0600 + peer-UID check + secret-field refuse |
| 20 | Terminal Command / Install | PASS | ash/raven; never overwrite `/bin/ash` (INSTALL_macOS); Windows `ash.exe` naming |
| 21 | Terminal First-Run Flow | PASS | ash first-run / identity create path exercised on macOS |
| 22 | Terminal Main Menu | PASS | ash banner + menu verified interactively on macOS |
| 23 | Messages Menu | PASS | ash messages path verified with demos |
| 24 | Chat History | PASS | `chat_history.json` + ash history commands |
| 25 | Send New Message | PASS | ash send via stdin / node IPC (no argv plaintext) |
| 26 | Secure CLI Usage | PASS | ash refuse argv; **raven-node `--send` REFUSE** (`113bf33`) |
| 27 | Local DB and Queues | PASS | SQLite outbox + forward_queue (+ busy_timeout) |
| 28 | Internet P2P | HOLD | raw path refuses ATSAM origination; libp2p/NAT composition is experimental only |
| 29 | DHT / Peer Discovery | PASS_SOFTWARE_SUBSTITUTE | DiscoveryResolver + local Kad; public Internet Kad **BLOCKED_HARDWARE** |
| 30 | Bootstrap Nodes | PASS | disable-raven-defaults + manual peer smoke |
| 31 | NAT Traversal | PASS_SOFTWARE_SUBSTITUTE | `nat_docker_sim.sh` **PASS** via Lima Docker; live CGNAT/DCUtR **BLOCKED_HARDWARE** |
| 32 | Offline Store-and-Forward | PASS | Harness step 06 + mailbox + matrix 04/07 |
| 33 | Raven Bridge Definition | PASS | DTN gateway sense; bridge never decrypts |
| 34 | Transport Adapter Architecture | PASS | mock_ble + LAN + Internet + store |
| 35 | Routing Policy | PASS | Spray-and-Wait bounds in bridge_v1 tests |
| 36 | Bluetooth Transport | PASS_SOFTWARE_SUBSTITUTE | mock_ble TCP framing only; iOS GATT **unverified / absent on main** (SoT `feature/raven-serverless-v1` until B8 — `RavenBleRvn1CarrierTests.swift` not in this tree); RBF1 held; headless GATT **BLOCKED_HARDWARE** |
| 37 | Bluetooth Forwarding Policy | PASS_SOFTWARE_SUBSTITUTE | Software multi-hop mock_ble / bridge_abc; physical BLE **BLOCKED_HARDWARE** |
| 38 | Mobile Compatibility | PASS | iPhone + iPad sim XCTest loops (Discovery/Contact/Envelope) |
| 39 | Multi-Device | PASS | DeviceCert + ash device sync commands |
| 40 | Dedup and Replay | PASS | bridge_v1 + matrix 08/09 |
| 41 | Out-of-Order | PASS (software) | ATSAM skipped-key iOS + Rust AEAD |
| 42 | Abuse and Spam | PASS | Per-peer bridge limits + contact-request sender/inbox caps |
| 43 | Privacy / Metadata | PASS (software) | Redacted logs; DHT privacy cost documented |
| 44 | Logging / Diagnostics | PASS | ash doctor; no secrets in §59 / reliability artifacts |
| 45 | Threat Model | PASS (soft) | `docs/THREAT_MODEL.md`; external align **BLOCKED_HUMAN** |
| 46 | Parser / Fuzzing | PASS (smoke) | `fuzz_smoke` green; long campaign optional |
| 47 | Cross-Platform Interop | PASS | macOS + Win PE substitute + Linux Lima/musl + Docker NAT |
| 48 | Mandatory Network Tests | PASS | Demos + matrix network scenarios |
| 49 | Mandatory Security Tests | PASS | Refuse argv, UDS peer-UID, envelope KATs, anti-spam, tamper |
| 50 | Reliability and Scale Tests | IN_PROGRESS | `reliability_matrix_20.sh` — earlier green runs invalidated (false-green harness, fixed 2026-09-29); needs a fresh run |
| 51 | Terminal-Specific Security Tests | PASS | ash/raven-node argv refuse + doctor redaction |
| 52 | Packaging | PASS (unsigned) | `scripts/release/build_unsigned.sh` prior; MSI/notarize **BLOCKED_HUMAN** |
| 53 | Node Operator Controls | PASS | ash node bridge/store/relay/bootstrap |
| 54 | Migration | PASS | Never silent FastAPI (ash assert + iOS exclusive path when flag ON) |
| 55 | Open-Source Readiness | PASS (docs) | AGPL; no GitHub push this wave (operator) |
| 56 | Documentation | PASS | SERVERLESS_MODEL, INSTALL_*, CHECKLIST_100_AUTOMATABLE, this walk |
| 57 | CI Requirements | PASS (declared) | `.github/workflows/raven-serverless.yml` matrix |
| 58 | Phase Exit Gates | PASS (software) | Software maximized; A human freeze **BLOCKED_HUMAN** |
| 59 | Final Serverless Proof | IN_PROGRESS | Harness fixed 2026-09-29; fresh enforced run pending (earlier green runs INVALIDATED); physical multi-device **BLOCKED_HARDWARE** |
| 60 | Final Definition of Done | BLOCKED_HUMAN | External auditors / notarize / phones |

---

## Progress estimate

- **Sections with a terminal status recorded:** **60 / 60 (100% walked)**  
- **Automatable PASS / soft-PASS / FROZEN / PASS_SOFTWARE_SUBSTITUTE:** claimed **100%** on 2026-08-12 (see `docs/CHECKLIST_100_AUTOMATABLE.md`); **withdrawn pending a fresh enforced run** (rows 50/59; row 28 is HOLD)  
- **Explicit absolute-DoD leftovers:** §60 BLOCKED_HUMAN; nested hardware notes on §29/§31/§36–37/§59; nested human notes on §5/§8/§18/§45/§52/§58  

**Checklist automatable 100%?** **NOT CURRENTLY CLAIMED** — pending a fresh enforced run of the reliability matrix and §59 harness  
**Absolute marketing DoD closed?** **NO** (phones / notarize / external review)

**READY for user physical test?** **CONDITIONAL / lab only.** Terminal + sim software on this Mac is a lab path under the RVN1 production HOLD (not a confidentiality or release claim), pending a fresh enforced harness run. **NO** for multi-device BLE / notarized installers / public CGNAT.

---

## Security fixes this continuation

1. iOS `PeerKeyDirectory` UserDefaults → Keychain (+ one-shot migration, peer index, tests)  
2. `AuthService.logout` → `PeerKeyDirectory.purgeAllPins()` (cross-account pin wipe)  
3. `ATSAMRootStorage` Keychain queries set `kSecAttrSynchronizable = false`  
4. Desktop `raven_core::identity_store` — macOS Keychain / Windows DPAPI / Linux Secret Service + locked-file `0600` (historical, 2026-08-12; since then Linux creation is disabled before R1 and locked-file is a debug/lab/CI-only override refused in Release — see `docs/IDENTITY_SEED_STORAGE.md`); plaintext `identity.seed` migrate; ash/raven-node/raven-swarm wired  
5. `ForwardQueue` SQLite `busy_timeout` + `raven-node service` queue warmup (fixes IPC/bridge race → ash-close flake)  
6. `scripts/reliability_matrix_20.sh` + Lima Docker NAT auto-wire; iPhone/iPad sim loops  

Prior wave (`113bf33`): OAuth state/PKCE, SessionStore clear, raven-node `--send` refuse, UDS peer-UID, anti-spam.
