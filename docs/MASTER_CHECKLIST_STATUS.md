# MASTER_CHECKLIST_STATUS — Raven Serverless Terminal Messaging

**Branch (historical):** authored on `feature/raven-serverless-v1`; this file now lives on `main` and is a dated snapshot, not a statement about an open branch  
**Baseline start commit:** `18fa01e2a32ef014387ae2857ca272f34555cddd`  
**Updated:** 2026-08-12 (reliability 20× + automatable 100%); headline and rows 28/59 re-qualified 2026-10-05 (see below)  
**Checklist source:** `docs/MASTER_ENGINEERING_CHECKLIST.md`  
**Walk log:** `docs/MASTER_CHECKLIST_WALK_IN_PROGRESS.md`  
**Automatable 100% ledger:** `docs/CHECKLIST_100_AUTOMATABLE.md`

> **Automatable coverage "100% PASS" (2026-08-12) is withdrawn pending a fresh enforced run** of
> `scripts/reliability_matrix_20.sh` and `scripts/final_serverless_proof.sh`: the earlier green
> runs it rested on are INVALIDATED (see *Last green proofs*), and §50 is IN_PROGRESS.  
> RVN1 messaging is under a **production HOLD** with no external review — see
> [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md),
> [`docs/THREAT_MODEL.md`](THREAT_MODEL.md) and connectivity matrix §0
> ([`docs/network/raven-swarm-connectivity-matrix.md`](network/raven-swarm-connectivity-matrix.md)).  
> Absolute marketing DoD (§60) is **not** claimed — physical BLE / CGNAT / notarize / external review remain BLOCKED_*.

Status legend: `NOT_STARTED` | `IN_PROGRESS` | `IMPLEMENTED` | `REVIEWED` | `FROZEN` | `BLOCKED_HUMAN` | `BLOCKED_HARDWARE` | `PASS_SOFTWARE_SUBSTITUTE` | `HOLD`

Reviewer for all IMPLEMENTED rows: **pending human** unless noted.

**Last green proofs (this machine):**
- `scripts/reliability_matrix_20.sh` → **INVALIDATED** — runs before the 2026-09-29 harness fix were false-green (scenario status was its last command, usually `rm -rf`; bridged sends used the refused `atsam` mode). Re-run: `scripts/reliability_matrix_20.sh` now enforces every assertion.
- `scripts/nat_docker_sim.sh` → **PASS** via Lima Docker (`DOCKER_HOST=unix://…/lima/ash-amd64-preflight/sock/docker.sock`)
- Linux: musl `ash --help` inside Lima `ash-amd64-preflight`
- Windows: `ash.exe` PE32+ self-check (`PASS_SOFTWARE_SUBSTITUTE`; wine blocked on sudo/gstreamer)
- iOS: iPhone + iPad sim XCTest loops (Discovery / ContactRequest / RavenEnvelope*) **TEST SUCCEEDED** — **OFF-MAIN**: the `ios-native` tree is not in this repository, so this is not reproducible from this checkout
- Desktop: `cargo test -p raven-core -p ash`; service SQLite race fixed (WAL busy_timeout + warmup)

| § | Section | Status | Evidence / notes |
|---|---------|--------|------------------|
| 1 | Completion Rules | IMPLEMENTED | Walk + SHA/test evidence required |
| 2 | Non-Negotiable Product Requirements | IMPLEMENTED | 1:1 text path proven; physical BLE listed separately |
| 3 | Exact Meaning of Serverless | IMPLEMENTED | `SERVERLESS_MODEL.md` + Tag V1 |
| 4 | V1 Scope | IMPLEMENTED | Text 1:1 only |
| 5 | Repository and Baseline Safety | IMPLEMENTED | Branch + secret scan; live rotation **BLOCKED_HUMAN** |
| 6 | Required Architecture Decisions | IMPLEMENTED | ADR 0001–0003; remaining deferred as non-blocking for V1 text path |
| 7 | Prior-Art Review | IMPLEMENTED | `PRIOR_ART_REVIEW_V1.md` |
| 8 | Phase A Protocol Freeze | IMPLEMENTED | Specs + freeze hashes; independent review **BLOCKED_HUMAN** |
| 9 | Raven Identity | IMPLEMENTED | raven-core + iOS fingerprint |
| 10 | Raven Address | FROZEN | Vectors |
| 11 | Aliases and Contacts | IMPLEMENTED | Soft Unique Tags; ash find/contact; matrix scenario 06 |
| 12 | Asynchronous First Contact | IMPLEMENTED | request/accept/block; matrix 06 |
| 13 | Cryptographic Requirements | IMPLEMENTED | Envelope + ATSAM KATs + tamper/replay matrix 09 (full ML-KEM interop optional debt) |
| 14 | Key Storage | IMPLEMENTED | identity_store Keychain/DPAPI; Linux: Secret Service (add-only no-prompt create, R1 2026-10-08) else passphrase vault (`keystore_vault`, Argon2id); first Linux Release proof is the CI `linux-release-keystore` job; iOS PeerKeyDirectory is OFF-MAIN |
| 15 | Canonical Raven Envelope | FROZEN | rust/swift/python vectors |
| 16 | Delivery States and ACK | IMPLEMENTED | matrix + §59 |
| 17 | Raven Node Core | IMPLEMENTED | raven-node daemon + service |
| 18 | Background Service Integration | IMPLEMENTED | launchd/systemd + service survives ash; notarization **BLOCKED_HUMAN** |
| 19 | Local IPC Security | IMPLEMENTED | UDS 0600 + peer-UID |
| 20 | Terminal Command and Installation | IMPLEMENTED | ash/raven; Win `ash.exe` |
| 21 | Terminal First-Run Flow | IMPLEMENTED | ash identity create |
| 22 | Terminal Main Menu | IMPLEMENTED | banner verified |
| 23 | Messages Menu | IMPLEMENTED | demos |
| 24 | Chat History | IMPLEMENTED | chat_history.json |
| 25 | Send New Message | IMPLEMENTED | stdin / IPC |
| 26 | Secure CLI Usage | IMPLEMENTED | argv refuse |
| 27 | Local DB and Queues | IMPLEMENTED | SQLite outbox + forward_queue (busy_timeout) |
| 28 | Internet P2P Networking | HOLD | direct Internet not proven; raw path refuses ATSAM origination (fail-closed); libp2p/NAT is experimental only — connectivity matrix §0. (Earlier “IMPLEMENTED / matrix 01” withdrawn; matches the walk log.) |
| 29 | DHT and Peer Discovery | PASS_SOFTWARE_SUBSTITUTE | Local Kad/libp2p swarm; public Internet Kad **BLOCKED_HARDWARE** |
| 30 | Bootstrap Nodes | IMPLEMENTED | matrix 10 |
| 31 | NAT Traversal | PASS_SOFTWARE_SUBSTITUTE | Docker dual-net NAT sim **PASS** (Lima); live CGNAT **BLOCKED_HARDWARE** |
| 32 | Offline Store-and-Forward | IMPLEMENTED | matrix 04/07 |
| 33 | Raven Bridge Definition | IMPLEMENTED | bridge never decrypts |
| 34 | Transport Adapter Architecture | IMPLEMENTED | mock_ble + LAN + Internet + store |
| 35 | Routing Policy | IMPLEMENTED | Spray-and-Wait / bridge_v1 |
| 36 | Bluetooth Transport | PASS_SOFTWARE_SUBSTITUTE | mock_ble TCP framing only; iOS GATT **unverified / absent on main** (SoT `feature/raven-serverless-v1` until B8; no export PR); RBF1 held; physical GATT **BLOCKED_HARDWARE** |
| 37 | Bluetooth Forwarding Policy | PASS_SOFTWARE_SUBSTITUTE | Software multi-hop mock_ble; physical **BLOCKED_HARDWARE** |
| 38 | Mobile Compatibility | IMPLEMENTED | iPhone + iPad sim loops |
| 39 | Multi-Device User Support | IMPLEMENTED | DeviceCert + ash device |
| 40 | Dedup and Replay | IMPLEMENTED | matrix 08/09 |
| 41 | Out-of-Order | IMPLEMENTED | ATSAM skipped-key + Rust AEAD path exercised |
| 42 | Abuse and Spam Controls | IMPLEMENTED | rate limits + contact caps |
| 43 | Privacy and Metadata | IMPLEMENTED | redacted logs; DHT cost documented |
| 44 | Logging and Diagnostics | IMPLEMENTED | ash doctor; no secrets in artifacts |
| 45 | Security Threat Model | IMPLEMENTED | threat model + review packet; align **BLOCKED_HUMAN** |
| 46 | Parser and Fuzzing | IMPLEMENTED | fuzz_smoke CI green (long campaign optional) |
| 47 | Cross-Platform Interop | IMPLEMENTED | macOS runtime + Win PE + Linux Lima/musl + Docker NAT |
| 48 | Mandatory Network Tests | IMPLEMENTED | matrix 01–05, 15 |
| 49 | Mandatory Security Tests | IMPLEMENTED | refuse argv, UDS, KATs, tamper |
| 50 | Reliability and Scale Tests | IN_PROGRESS | `reliability_matrix_20.sh` — earlier green runs invalidated (false-green harness, fixed 2026-09-29); needs a fresh run. `reliability_10k` is a single-threaded queue test without fault injection. |
| 51 | Terminal-Specific Security Tests | IMPLEMENTED | ash/raven-node refuse + doctor |
| 52 | Packaging | IMPLEMENTED | unsigned release; MSI/notarize **BLOCKED_HUMAN** |
| 53 | Node Operator Controls | IMPLEMENTED | ash node bridge/store/relay/bootstrap |
| 54 | Migration | IMPLEMENTED | never silent FastAPI |
| 55 | Open-Source Readiness | IMPLEMENTED | AGPL + docs; publish not pushed (operator) |
| 56 | Documentation | IMPLEMENTED | INSTALL_*, CHECKLIST_100, walk |
| 57 | CI Requirements | IMPLEMENTED | raven-serverless.yml declared |
| 58 | Phase Exit Gates | IMPLEMENTED | Software gates maximized; human freeze **BLOCKED_HUMAN** |
| 59 | Final Serverless Proof | IN_PROGRESS | Harness fixed 2026-09-29; fresh enforced run of `final_serverless_proof.sh` + `reliability_matrix_20.sh` pending (earlier green runs INVALIDATED); physical multi-device **BLOCKED_HARDWARE** |
| 60 | Final Definition of Done | BLOCKED_HUMAN | External review / notarize / phones |

## Honest leftovers (absolute DoD only)

### BLOCKED_HUMAN
- External crypto/protocol freeze review
- Apple notarized signing / Windows Authenticode
- External DoD review (§60)
- Live secret rotation decisions

### BLOCKED_HARDWARE
- Physical 3-phone BLE mesh
- Live CGNAT / DCUtR hole-punch
- Headless CoreBluetooth desktop radio
- Public Internet Kad soak

**READY FOR FULL TEST (marketing) = NO** — the automatable-coverage claim is pending a fresh enforced run (rows 50/59), RVN1 is under production HOLD, and absolute DoD needs human+hardware.
