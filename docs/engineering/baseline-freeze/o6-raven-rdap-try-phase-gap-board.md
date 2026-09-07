# O6 try-phase gap board — Raven↔RDAP encrypted two-device path

**As of:** 2026-09-07 · board snapshot after O6 M3 lab harness (parent `e69411c` / #55); G-M3 = localhost two-process lab only — **not** O6 E2E Proven  
**Owner:** Eng Program (#2) · consult Raven↔RDAP Integration Lead (`@Raven-ASHCO/architecture`, `@Raven-ASHCO/rdap`), Protocol Spec (#4), Adversarial QA (#18), Python Runtime (#14)  
**Risk class:** **R0** (docs + fail-closed checklist). **Not** M1–M3 production code.  
**Label:** **non-release** / **fail-closed containment**. This board does **not** claim confidential Raven messaging, production ATSAM, or a HOLD lift.

**Companion check (try-phase RED, expected):** [`scripts/o6_try_phase_gap_check.sh`](../../../scripts/o6_try_phase_gap_check.sh)

---

## Hard gate (do not regress)

Citations: [`docs/THREAT_MODEL.md`](../../THREAT_MODEL.md) (executable posture; Release status **HOLD**) and [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../../../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md) (RVN1 messaging **not approved for production**).

1. O6 claims of “**production ATSAM**” / **confidential delivery**, and M1–M3 **production enablement / Release**, remain **subordinate** to that HOLD.
2. Harness / lab / interop work against held paths MUST stay labeled **non-release**, run under **fail-closed containment**, and MUST NOT be described as confidential Raven messaging or production-approved.
3. **Harness green ≠ HOLD lifted.** This board is inventory + next-PR sequencing. **Docs-only ≠ Proven.**
4. Python / RDAP MUST NOT construct ATSAM / RVNA1 ciphertext ([ADR 0004](../../adr/0004-raven-rdap-atsam-transport.md) D4).

---

## Verdict (2026-09-06)

| Question | Honest answer |
|----------|---------------|
| Is O6 **inventory** closer to green? | **Yes (docs).** ADR 0004 + Appendix G5 are ACK’d on `main`. This board + the fail-closed check close the Sprint 0 “Known security / interop / Raven↔RDAP gaps” row as **inventory landed**. |
| Is O6 **two-device encrypted E2E harness** green? | **No.** Still **RED / not Proven.** M3 lab (two `raven-node` processes on localhost + RDAP `SealUnderSession` + already-sealed LanDial) is **lab-only**. Still blocked on (1) Founder Priority #1 terminal board green, (2) RVN1 HOLD / no production enablement, (3) M1 identity bridge **in progress** (RDAP still mints `.team/keys` seed if `load_or_create` is used), (4) no RDAP `ask` over `atsam_rvn1`, (5) physical two-device WAN = `BLOCKED_HARDWARE`. |
| May M1–M3 **production** code land now? | **No.** ADR 0004 header: no M1–M3 production code until terminal-path board green + HOLD lift process. CEO override only for scheduling M1 eng before the terminal board is green. |
| May a **non-release** harness scaffold land? | **Yes — lab only.** M2 IPC seal + M3 two-process localhost path exist. That is **not** O6 E2E Proven, **not** confidential RDAP delivery, **not** a HOLD lift, **not** WAN. |

**O6 KPI is not one number.** Do not collapse:

| Definition | Source | Status at `7ccf180` |
|------------|--------|---------------------|
| Gaps inventoried with owners; interop tests in CI | [`ninety-day-outcomes.md`](ninety-day-outcomes.md) O6 | **Inventory: IN PROGRESS → this board.** Interop tests in CI: **not started** (blocked on M1–M3). |
| Two-device encrypted E2E harness (`LanDial` primary, ATSAM-sealed payloads, carrier `atsam_rvn1`) | [ADR 0004](../../adr/0004-raven-rdap-atsam-transport.md) D1 / D5 / M3 | **RED / not Proven.** Lab substitute: [`o6-m3-two-node-rdap-lab-evidence.md`](o6-m3-two-node-rdap-lab-evidence.md) (localhost two-process; `BLOCKED_HARDWARE` for WAN) |

---

## What’s green (do not over-read)

These are **green as stated**. None of them is the O6 encrypted harness.

| Item | Evidence | What it is not |
|------|----------|----------------|
| **M0 spec freeze** | [RAVEN#3](https://github.com/Raven-ASHCO/RAVEN/pull/3) merged `ce087c7d9cfb`. ADR 0004 + [`0004-appendix-g5-raven-rdap-revoke.md`](../../adr/0004-appendix-g5-raven-rdap-revoke.md) on `main`. Architect + Crypto + Identity **full ACK** (body + G5). | Not M1. Not HOLD lift. Not a Python IPC client. |
| **Identity G5 SoT** | [`G5_CROSS_STACK_REVOKE_POLICY.md`](../G5_CROSS_STACK_REVOKE_POLICY.md); pin ≢ `device_ed_pub`; R → lineage-scoped data-plane fail-closed; R ↛ auto address-deny. | Code held. No joint revoke harness. |
| **RAVEN B1 names main-green verified** | [RAVEN#47](https://github.com/Raven-ASHCO/RAVEN/pull/47) on tip `e0a317aa` / this SHA. Six Serverless Node check names SUCCESS. | Pin / branch-protection **not enabled** (pending founder GO). Not O6 interop CI. |
| **RDAP B1 live pins** | [RAVEN#44](https://github.com/Raven-ASHCO/RAVEN/pull/44); RDAP `main` six A2A selftest contexts. | Signed HTTP / selftest only. **Not** confidential. **Not** Raven↔RDAP encrypted E2E. |
| **Windows named-pipe IPC landed** | [RAVEN#43](https://github.com/Raven-ASHCO/RAVEN/pull/43): `ipc_server_windows.rs`, `ash` named-pipe client, `WINDOWS_NAMED_PIPE`. | **Not** terminal Proven. **Not** WAN. **Not** RDAP. Living Sprint 0 boards dated 2026-09-04 still say “pipe = #1 blocker” — that sentence is **stale vs this tip**. |
| **Linux/macOS UDS + `ash` IPC client** | `node/crates/ash/src/ipc_client.rs`; ops `Ping` / `Status` / `SetPolicy` / `EnqueueSealed` / `LanDial`. | Rust `ash` only. **No** Python / RDAP client in this repo. |
| **Raven-only two-node LAN precursor** | [`node/scripts/lan_direct_two_node.sh`](../../../node/scripts/lan_direct_two_node.sh) (contact → send → inbox → sealed ACK; no `unsafe-demo-crypto`). | **Not RDAP.** Not two-device RDAP `ask`. Not a confidentiality / Release claim. |
| **Internet dial fail-closed** | [`node/scripts/internet_dial_smoke.sh`](../../../node/scripts/internet_dial_smoke.sh) | Negative gate only. **NOT** a WAN reliability claim. |
| **Crypto O6 boundary docs** | [`docs/crypto/ATSAM_THREAT_ASSUMPTIONS_V1.md`](../../crypto/ATSAM_THREAT_ASSUMPTIONS_V1.md) §6: confidentiality is **not** an RDAP property. Open sibling [RAVEN#25](https://github.com/Raven-ASHCO/RAVEN/pull/25) (`RDAP_ATSAM_BOUNDARY_V1.md`) is complementary Crypto wording, not this board. | Not a harness. |
| **M2 lab IPC seal (NON-RELEASE)** | RAVEN #54 `116eb021` + RDAP #11 `3207e8ea`. Execute: [`o6-m2-seal-under-session-lab-evidence.md`](o6-m2-seal-under-session-lab-evidence.md). | **Not** O6 E2E Proven. **Not** HOLD lift. **Not** WAN. **Not** confidential RDAP delivery. |
| **M3 lab two-process path (NON-RELEASE)** | [`o6-m3-two-node-rdap-lab-evidence.md`](o6-m3-two-node-rdap-lab-evidence.md) / [`node/scripts/o6_m3_two_node_rdap_lab.sh`](../../../node/scripts/o6_m3_two_node_rdap_lab.sh). Two `raven-node` processes + RDAP `SealUnderSession` + `ash lab lan-dial-sealed`. | **Not** O6 E2E Proven. **Not** HOLD lift. **Not** WAN (`BLOCKED_HARDWARE`). **Not** confidential RDAP delivery. **Not** RDAP `ask` over `atsam_rvn1`. |

---

## What’s blocked (O6 encrypted path)

| ID | Gap | Why it blocks O6 harness | Owners after gate |
|----|-----|--------------------------|-------------------|
| **G-HOLD** | RVN1 production HOLD | Even a perfect lab harness is **non-release**. Cannot claim confidential production delivery. | Security / Crypto process — **not** this PR |
| **G-TERM** | Terminal L/M/W board not Proven | Founder Priority #1 sits **above** O6 M1+. Named-pipe **code** landed (#43); Proven still needs executed green/red (linked CI or agent smoke) per [`terminal-path-reliability.md`](terminal-path-reliability.md). Living boards at [`blockers-ownership-board.md`](blockers-ownership-board.md) / [`three-path-verification-board.md`](three-path-verification-board.md) are **stale (2026-09-04)** and still narrate pipe-as-blocker. | SRE Perf (#19), Windows (#11), Node IPC (#8), CLI DX (#12) |
| **G-M1** | Same-RVN1 identity bridge **M1-in-progress (NON-RELEASE)** | RAVEN-side public export: `ash whoami --json` (no new IPC op). Pin-file bind stub + executed green/red: [`scripts/o6_m1_same_rvn1_bind_check.sh`](../../../scripts/o6_m1_same_rvn1_bind_check.sh). Contract: [`o6-m1-same-rvn1-bind-contract.md`](o6-m1-same-rvn1-bind-contract.md). **No workflow wire in this PR** (avoids #51 / OAuth collision; DevSecOps CI follow-up after #51). Companion RDAP may grow a pin-import path; that still is **not** O6 encrypt / M2. IPC-mediated signing remains follow-up. Default `load_or_create` seed mint is still a parallel-identity hazard if used. **Not** O6 E2E. **Not** HOLD lift. Harness green ≠ HOLD lift. Encrypted M1–M3 code gate remains **CLOSED**. Private keys MUST NOT appear in IPC JSON. | Identity (#15) + Node IPC (#8) + Python Runtime (#14) |
| **G-M2-IPC** | Daemon-seal IPC **landed** (#54, `116eb021`); **not** O6 E2E | `IpcRequest::SealUnderSession` seals app bytes inside `raven-node` under a persisted ATSAM session. `EnqueueSealed` / `LanDial` / `InternetDial` stay sealed-frame-only. Lab execute: [`o6-m2-seal-under-session-lab-evidence.md`](o6-m2-seal-under-session-lab-evidence.md) / [`node/scripts/o6_m2_seal_under_session_lab.sh`](../../../node/scripts/o6_m2_seal_under_session_lab.sh). **NON-RELEASE.** HOLD unchanged. | Node IPC + Crypto (#3) + RDAP Protocol (#13) + Python Runtime |
| **G-M2-PY** | RDAP plaintext-to-daemon client **landed** (companion #11, `3207e8ea`); **not** confidential delivery | `./rdap seal-under-session` / `team_agents.raven_ipc` submit `app_payload_b64` only. Fail-closed `ATSAM_SESSION_REQUIRED` / `ATSAM_LINEAGE_REVOKED`. This repo still has **zero** `team_agents/`. Not O6 E2E. Not HOLD lift. | Python Runtime (#14) + Raven↔RDAP Integration Lead |
| **G-M3** | Two-device RDAP harness **lab-only** | Localhost two-process execute: [`o6-m3-two-node-rdap-lab-evidence.md`](o6-m3-two-node-rdap-lab-evidence.md). D5 full acceptance remains **RED**: no RDAP `ask` over `atsam_rvn1`, no carrier enum, physical WAN = `BLOCKED_HARDWARE`. **Not** O6 E2E Proven. **Not** HOLD lift. | Adversarial QA (#18) + SRE + Eng Program + CLI DX |
| **G-M4** | RDAP “Important integration gap” still live | Honest today. D5.5 says replace it with a pointer to ADR 0004 **when** the encrypted path exists — **not before**. | RDAP Protocol + Assurance |
| **G-CI** | No Raven↔RDAP interop job | O6 KPI “interop tests in CI” is empty. Do **not** pin a greenwashed job that talks HTTP A2A or experimental mailbox and calls it `atsam_rvn1`. | DevSecOps (#20) after M3 |

**RDAP live gap (companion repo, not cloned here):** [`Raven-ASHCO/raven-distributed-agent-protocol`](https://github.com/Raven-ASHCO/raven-distributed-agent-protocol) README (fetched 2026-09-06):

> RDAP currently creates its own key under `.team/keys` and does not submit or receive application payloads through the production `raven-node` ATSAM session actor.

Carriers on that README: signed HTTP (not Raven E2EE), Git relay (not Raven E2EE), experimental plaintext swarm mailbox (**never** confidential).

---

## Discarded hypotheses (do not implement)

| Hypothesis | Why discarded |
|------------|---------------|
| Implement Python ATSAM / stuff task JSON into `message_ciphertext` and call it sealed | Forbidden by ADR 0004 D4 / F11. |
| Treat `LanDial` Noise XX as O6 confidentiality | D1 / D2: Noise authenticates the transport peer only. |
| Force M1 same-RVN1 into production Release paths | HOLD + errata. Same-RVN1 reuse still must not bypass the hold. |
| Treat the M3 localhost two-process lab as O6 E2E / confidential Proven | Lab ≠ WAN. Marker-in-inbox ≠ RDAP `ask`. HOLD still active. |
| Use `two_node_demo.sh` / `unsafe-demo-crypto` as O6 evidence | Lab/demo crypto. Not ATSAM production-shaped. Not RDAP. |
| Use experimental mailbox / signed HTTP A2A selftest as O6 green | Explicitly non-confidential. RDAP B1 ≠ O6 harness. |
| Rewrite living A/B/C boards in this PR | Out of scope. This board records that they are stale vs #43 / #47; a later Eng Program refresh should retcon B10. |
| Claim this checklist / script Proven | Founder rule: docs-only ≠ Proven. The script is **expected RED**. |

---

## Exact next PRs (ordered; do not skip)

**Now (authorized, this class of work):**

1. **Landed (#49)** — inventory + fail-closed RED check + Sprint 0 row flip. R0. No HOLD lift.
2. **Optional sibling (already open):** [RAVEN#25](https://github.com/Raven-ASHCO/RAVEN/pull/25) Crypto `RDAP_ATSAM_BOUNDARY_V1.md` — do not duplicate; do not merge as if it were M1.
3. **Optional RDAP docs-only:** pointer-only README sentence (“see RAVEN ADR 0004; gap still open; HOLD”) — **keep** “Important integration gap” until M3. Must not claim the carrier exists.
4. **M1 (in progress, NON-RELEASE):** read-only public whoami + pin-file bind of the local `raven-node` RVN1 (D3). `ash whoami --json` / [`o6-m1-same-rvn1-bind-contract.md`](o6-m1-same-rvn1-bind-contract.md). **No** private keys on IPC. **No** seal. **No** `atsam_rvn1` send claim. RDAP companion still needs to consume the pin (do not `load_or_create` a parallel seed). RDAP remains HTTP control plane. **Not** O6 E2E. Harness green ≠ HOLD lift.

**After terminal board is honestly green** (executed green/red on the named terminal path) — still **non-release / HOLD-labeled**:
5. **M2 landed (#54 / RDAP #11):** Crypto-owned `SealUnderSession` + RDAP plaintext-to-daemon client. Lab execute: [`o6-m2-seal-under-session-lab-evidence.md`](o6-m2-seal-under-session-lab-evidence.md). **Not** O6 E2E Proven. **Not** HOLD lift.
6. **M3 lab landed (this pack):** two-process localhost harness. Execute: [`o6-m3-two-node-rdap-lab-evidence.md`](o6-m3-two-node-rdap-lab-evidence.md). **Not** O6 E2E Proven. **Not** HOLD lift. Physical WAN = `BLOCKED_HARDWARE`. RDAP `ask` over `atsam_rvn1` still **BLOCKED** at companion tip `3207e8ea`.
7. **Next (still NON-RELEASE / HOLD):** RDAP `ask` → echo over `atsam_rvn1` (companion PR) and/or physical two-device WAN when hardware exists. Do not replace the RDAP gap paragraph until that `ask` path exists.
8. **M4** stays parallel: RDAP README replaces “Important integration gap” **only then**; plaintext carriers stay explicitly non-confidential.

**After HOLD lift (separate security process — not a coding PR in this series):** Release/production enablement may be discussed. Harness green still does not, by itself, lift HOLD.

---

## D5 harness acceptance (copy/reminder — O6 E2E still RED)

Two devices (physical or VM), each with `raven-node` + RDAP:

1. Mutual pin of the same RVN1 / device bindings used by each node (D3).
2. Alice `ask` → Bob completes (echo provider fine); markers e.g. `RAVEN_A2A_OK_*`.
3. Data-plane frames are ATSAM-sealed (harness assert + negative: drop session → refuse).
4. Carrier enum reports `atsam_rvn1`; docs state HOLD / non-Release while errata is active.
5. RDAP README points at this ADR / O6 path (replacing the gap paragraph **only then**).
6. Experimental mailbox remains opt-in, labeled non-production / non-confidential.

Lab substitute (not a D5 close): two-process localhost execute exists. Items 2, 4, 5 and physical WAN remain **Not Proven**. `BLOCKED_HARDWARE` for two-device WAN.

---

## Try-phase evidence

| Kind | Allowed as O6 evidence? |
|------|-------------------------|
| This board / ADR 0004 / G5 | Inventory only |
| `scripts/o6_try_phase_gap_check.sh` exit ≠ 0 | **Executed RED** (honest). Not a pass. |
| `scripts/o6_m1_same_rvn1_bind_check.sh` | **Executed green+red for G-M1 public bind only.** Still **NON-RELEASE**. Not O6 E2E. Not HOLD lift. |
| `node/scripts/o6_m2_seal_under_session_lab.sh` | **Lab localhost IPC seal under HOLD** (unit + RED no-session + GREEN daemon envelope + revoke or honest BLOCKED). Still **NON-RELEASE**. **Not** O6 E2E Proven. **Not** HOLD lift. **Not** WAN. **Not** confidential RDAP delivery. |
| `node/scripts/o6_m3_two_node_rdap_lab.sh` | **Lab localhost two-process encrypted path under HOLD** (unit + pin + RED no-session + GREEN seal/dial/inbox + RED missing-session + `BLOCKED_HARDWARE`). Still **NON-RELEASE**. **Not** O6 E2E Proven. **Not** HOLD lift. **Not** WAN. **Not** confidential RDAP delivery. **Not** RDAP `ask` over `atsam_rvn1`. |
| `lan_direct_two_node.sh` | Raven-only precursor. Cite as precursor, never as O6 green. |
| RDAP A2A selftest | Control-plane only. |
| Future M3 job labeled `atsam_rvn1` with HOLD banner | Harness claim only; still not Release. |

**FOUNDER RULE:** consolidate **executed green/red only** (linked CI or agent smoke). Do not estimate a soak/pass rate. Do not flip this board to Proven from a docs edit.
