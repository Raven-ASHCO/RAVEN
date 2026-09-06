# Living blockers / ownership status — Sprint 0

**As of:** 2026-09-04 ~13:45 Europe/Madrid (Eng Program refresh after rebase onto latest `main`, incl. #24 / #26 / #30 / #29)  
**Owner:** Eng Program (#2)  
**Audience:** Manager (CEO)  
**Scope:** Ownership freeze only — no feature velocity metrics  
**Repos:** `Raven-ASHCO/RAVEN`, `Raven-ASHCO/raven-distributed-agent-protocol`

---

## Manager M0 scoreboard (do not regress)

**M0 docs done.** [RAVEN#3](https://github.com/Raven-ASHCO/RAVEN/pull/3) **MERGED** on `main` at `ce087c7d9cfb`.

| Party | ACK |
|-------|-----|
| Architect | **full ACK** ADR body + Appendix G5 |
| Identity | **full ACK** ADR body + G5 pin `5d39099907ea` (= `main`) |
| Crypto | **ACK** |

**Only** M1–M3 **production** code remains gated (terminal + HOLD). No M0 ACK is open. Do not list Architect or Identity as pending on M0.

## Manager SoT (accepted 2026-09-04)

1. SRE honesty map + bar: Delivered+ACK+dedup+opaque; ≥2 OS or WAIVE; no CI≠hardware conflation.
2. DTN Bridge claim: opaque custody + cooperative hop/repl/TTL + sealed-ACK-only — Forwarded≠Delivered.
3. Direct internet: localhost/LAN + fail-closed ≠ WAN claim (P2P).
4. Terminal #1: Win named-pipe/MSVC + CLI DX doctor/install/send evidence.
5. Try-phase: consolidate executed green/red only (linked CI or agent smoke). Docs-only ≠ Proven.

## Manager Path A lock (2026-09-04)

**Path A (mesh / NAT / relay) is locked.** Localhost reservation **only**. Two-client circuit / WAN / auto-fallback / DCUtR **NOT proven**. Hop server **missing**. Multi-NAT **BLOCKED_HARDWARE**. NAT hold **intact**.

**Do not call mesh relay reliable.** Path B and Path C are locked below. **A+B+C board fills now present.** Continue **terminal**. See [`three-path-verification-board.md`](three-path-verification-board.md).

## Manager Path B lock (2026-09-04)

**Path B (DTN / bridge) claim language is locked.** Opaque custody + `ENDPOINT_ACK_ONLY` **proven (software)** — prefer executed green/red citations (linked CI or agent smoke). Hop/repl **cooperative-only**. Prod mailbox **held**. iOS **blocked on B8**. **Not flood-proof / not Byzantine-safe.** Path C is locked below. Continue **terminal**.

## Manager Path C lock (2026-09-04)

**Path C (direct Internet) claim language is locked.** LAN/localhost **proven**. WAN **blocked/untested**. Internet dial **fail-closed proven** — **NOT** a WAN reliability claim. `ash_menu_smoke` → CLI DX [RAVEN#16](https://github.com/Raven-ASHCO/RAVEN/pull/16). Windows **honest fail-closed** until named-pipe. **A+B+C board fills now present.** Continue **terminal**.

## Node IPC (terminal input)

**Windows named-pipe gap = #1 blocker.** `ipc_server` is **UDS-only**; `ash --send-stdin` spawn has no Win pipe path.

**B10 Manager decision A:** named-pipe **implement AUTHORIZED NOW** — **not** Sprint-1-deferred. Sprint 1 terminal slice is **OPEN for pipe only**. Owners: **Windows + Node IPC**. Doctor/client keyed on `WINDOWS_NAMED_PIPE`. Still **does not unblock WAN Path C**.

| OS / item | Honest status |
|-----------|----------------|
| Linux / macOS UDS | **Mostly green** (not WAN Proven; try-phase still wants executed green/red citations) |
| Windows named-pipe | **#1 blocker** — **decision A AUTHORIZED NOW** (pipe-only Sprint 1 slice) |
| `WINDOWS_NAMED_PIPE` | Doctor/client **keyed on this** |
| `ash --send-stdin` spawn | Honest fail-closed on Win until pipe lands |
| SCM + LAN parity | **P1 after pipe** |
| WAN Path C | **Not unblocked** by this work |

## Manager macOS slice (2026-09-04)

**CI unit/smoke proven.** Menu smokes are **not GHA-gated yet** — **decision:** wire `ash_menu_smoke` / `ash doctor` into CI (**not** operator-only). Track [RAVEN#16](https://github.com/Raven-ASHCO/RAVEN/pull/16) + [RAVEN#22](https://github.com/Raven-ASHCO/RAVEN/pull/22). Notarize remains **BLOCKED_HUMAN** residual.

## Founder rules (try phase = execute)

**Try-phase = execute:** consolidate **executed green/red only** (linked CI or agent smoke). **Docs-only ≠ Proven.** Applies to **terminal reliability** and the **three paths** (`mesh` | `bridge` | `direct`). See [`three-path-verification-board.md`](three-path-verification-board.md).

**Founder Priority #1:** Terminal Win / macOS / Linux reliability **and** the three-path matrices sit **above O6 M1+**. **Do not schedule M1 eng until the terminal board is green** (CEO override only).

---

## Executive snapshot

| Area | State |
|------|--------|
| Org + teams + CODEOWNERS + `main` protection | **DONE** (Raven-ASHCO live) |
| Required CI checks on `main` | **OPEN (B1)** — contexts still empty; RAVEN#19 CI-align is draft; **do not enable** until green + Manager GO |
| Specialist path coverage | **PARTIAL** — B3 **CLEARED** (RAVEN#7); B4 FlatBuffer FFI still `*` |
| Team bus factor | **Accepted (bot-only)** — founder sole GitHub member; escalate only if human reviewers added |
| Founder Priority #1 | Terminal L/M/W + three-path matrices **above** O6 M1+ |
| Path A (mesh/NAT/relay) | **LOCKED** — localhost reservation only; circuit/WAN/auto-fallback/DCUtR **NOT proven**; hop server missing; multi-NAT **BLOCKED_HARDWARE**; NAT hold intact. **Not reliable.** |
| Path B (DTN/bridge) | **LOCKED** — opaque custody + `ENDPOINT_ACK_ONLY` **proven (software)**; hop/repl cooperative-only; prod mailbox held; iOS blocked on B8. **Not flood-proof / not Byzantine-safe.** Prefer executed green/red citations. |
| Path C (direct Internet) | **LOCKED** — LAN/localhost **proven**; WAN **blocked/untested**; internet dial **fail-closed proven** — **NOT** a WAN reliability claim. `ash_menu_smoke` → CLI DX #16. Windows honest fail-closed until named-pipe. **A+B+C fills present.** Continue **terminal**. |
| Node IPC / B10 #1 | **Decision A AUTHORIZED NOW** — named-pipe implement **not** Sprint-1-deferred. Sprint 1 terminal slice **OPEN for pipe only**. Windows + Node IPC. Doctor/client keyed on `WINDOWS_NAMED_PIPE`. **Does not unblock WAN Path C.** |
| Critical path / O6 gate | **M0 docs done ✅ CLOSED / MERGED** — [RAVEN#3](https://github.com/Raven-ASHCO/RAVEN/pull/3) ADR 0004 on `main` `ce087c7d9cfb`. Architect **full ACK** body+G5; Identity **full ACK** body+G5 pin `5d39099907ea` (= `main`); Crypto **ACK**. **Only** M1–M3 **production** code remains gated (terminal + HOLD). |
| Performance baseline | **#19 SRE Perf** — harvest landed [RAVEN#26](https://github.com/Raven-ASHCO/RAVEN/pull/26); soft budgets draft; docs-only ≠ Proven |
| Menu-smoke | Sole CI via RAVEN#16 (Apple APPROVE + Core ACK); converge DONE with SRE; **Proven flip only after executed green** (linked CI or agent smoke) |
| macOS slice | **CI unit/smoke proven.** Menu smokes **not GHA-gated yet** — wire `ash_menu_smoke`/`doctor` into CI (not operator-only). Track #16/#22. Notarize **BLOCKED_HUMAN**. |

Org-create / personal-account CODEOWNERS blockers from morning audit are **cleared**. **B3 cleared** via merged RAVEN#7.

---

## Manager / Eng Program actions (current)

1. **B1:** RAVEN#19 CI-align **open (draft)**. Provisional pin set **after** next green `main` / PR runs. **Do not enable** required checks until names verified green **and** Manager GO.
2. **B3 CLEARED:** merged RAVEN#7 — `node/crates/raven-mlkem768-incremental-ffi/` → `@Raven-ASHCO/crypto` + `@Raven-ASHCO/core`.
3. **B2:** Accepted for bot-only org; escalate only if human reviewers added.
4. **Terminal first:** do not schedule M1 eng until terminal board green (CEO override only). Flag premature Raven↔RDAP / M1–M3 production PRs.
5. **Menu-smoke merge order:** #20 **done** → land #16 when green → #19 rebases **preserving** menu-smoke.
6. Keep this board under `docs/engineering/baseline-freeze/` (this PR). **M0 docs done ✅ CLOSED / MERGED** on `main` `ce087c7d9cfb` (RAVEN#3). Architect **full ACK** body+G5; Identity **full ACK** body+G5 pin `5d39099907ea` (= `main`); Crypto **ACK**. **Only** M1–M3 production code remains gated (terminal + HOLD).
7. **Path A locked** — do not claim mesh relay reliable.
8. **Path B locked** — opaque custody + `ENDPOINT_ACK_ONLY` proven (software); hop/repl cooperative-only; prod mailbox held; iOS blocked on B8. **Not flood-proof / not Byzantine-safe.** Prefer executed green/red citations.
9. **Path C locked** — LAN/localhost proven; WAN blocked/untested; internet dial fail-closed proven — **NOT** a WAN reliability claim. `ash_menu_smoke` → CLI DX #16. Windows honest fail-closed until named-pipe. **A+B+C board fills now present.** Continue **terminal**.
10. **B10 decision A:** named-pipe **implement AUTHORIZED NOW** (not Sprint-1-deferred). Sprint 1 terminal slice **OPEN for pipe only**. Windows + Node IPC. Doctor/client keyed on `WINDOWS_NAMED_PIPE`. **Does not unblock WAN Path C.**
11. **macOS slice:** CI unit/smoke proven. Menu smokes not GHA-gated yet — wire `ash_menu_smoke`/`doctor` into CI (not operator-only). Track #16/#22. Notarize **BLOCKED_HUMAN**.

---

## CLI DX in-flight

| Track | Status | PR / next | Notes |
|-------|--------|-----------|-------|
| Windows MSVC `ash` `Command` ungate (compile P0-1) | **DONE / MERGED** via [RAVEN#20](https://github.com/Raven-ASHCO/RAVEN/pull/20) + [RAVEN#21](https://github.com/Raven-ASHCO/RAVEN/pull/21) | #20 + #21 on `main` | **Do not greenlight duplicate compile fixes.** Compile ungate only — docs/helpers **not** e2e-proven. |
| `ash_menu_smoke` / doctor CI | In flight → CLI DX [RAVEN#16](https://github.com/Raven-ASHCO/RAVEN/pull/16) + [RAVEN#22](https://github.com/Raven-ASHCO/RAVEN/pull/22) | #16 / #22 | **Decision:** wire into CI (**not** operator-only). Menu smokes **not GHA-gated yet**. macOS CI unit/smoke **proven**. Notarize **BLOCKED_HUMAN**. Windows honest fail-closed until named-pipe. |
| `install.sh` fail-close (B11) | In flight (draft) | [RAVEN#17](https://github.com/Raven-ASHCO/RAVEN/pull/17) | Hazard retire / fail-close. **Not** install Proven. |
| Core doctor axes (presence / ready / send_path) | In flight | [RAVEN#22](https://github.com/Raven-ASHCO/RAVEN/pull/22) | `ash doctor` exit 0 ≠ send Proven. |
| Doctor identity-backend mismatch | In flight | [RAVEN#23](https://github.com/Raven-ASHCO/RAVEN/pull/23) | Identity usable / `daemon_ready` honesty. |
| Windows named-pipe IPC (`WINDOWS_NAMED_PIPE`) | **Decision A AUTHORIZED NOW** | B10 · Windows (#11) + Node IPC (#8) | Sprint 1 terminal slice **OPEN for pipe only** — **not** Sprint-1-deferred. Doctor/client keyed on `WINDOWS_NAMED_PIPE`. **Does not unblock WAN Path C.** |
| install→doctor→send CI (Win) | Open P0 (after pipe) | B10 · CLI DX (#12) | Still remaining B10; not Proven until executed green/red. |
| Win loopback `127.0.0.1:7420` | Excluded (B12) | — | Loopback ≠ WAN / named-pipe / terminal Proven. |

---

## Open blockers board

| ID | Blocker | Age | Owner (bot / role) | Severity | Notes |
|----|---------|-----|--------------------|----------|-------|
| B1 | Required status checks empty on `main` | 0d (since protection landed) | DevSecOps (#20) + Architect (#1) | High | Protection exists; `checks`/`contexts` = `[]` on RAVEN + RDAP. RAVEN#19 CI-align **open (draft)**. Provisional pin after green; **not enabling** until green + Manager GO. |
| B2 | Bus factor = 1 on all 12 GitHub teams | 0d | Manager + Eng Program | **Accepted (bot-only org)** | Escalate **only** if human reviewers are added. |
| B3 | Crypto FFI crate not specialist-owned | — | Crypto ATSAM (#3) + Rust Core (#5) | **CLEARED** | **CLEARED** via merged [RAVEN#7](https://github.com/Raven-ASHCO/RAVEN/pull/7) — `raven-mlkem768-incremental-ffi` → `crypto` + `core`. |
| B4 | FlatBuffer FFI crate not specialist-owned | 0d | Rust Core (#5) + Protocol Spec (#4) | Med | `node/crates/raven-fb-ffi/` → `*` only. |
| B5 | Platform trees missing vs CODEOWNERS | 0d | Apple (#10), Windows (#11) | Med | `/ios-native/`, `/RAVEN-Windows/` **absent** on `main` (gap notes #8 / #10). |
| B6 | No GitHub team for SRE/Perf | 0d | SRE Perf (#19) + Manager | Med | No `@Raven-ASHCO/perf` (or similar). |
| B7 | Review-latency baseline under-sampled | 0d | Eng Program (#2) | Low | Early sample was RAVEN#1 self-merge. More PRs merged today; **SLA still undefined** — exclude self-merges. Do not invent latency numbers here. |
| B8 | iOS / Apple tree landing (Phase 1+) | — | Apple (#10) + Eng Program | **PARKED** | **Phase 1+ PARKED** — Windows terminal **>** iOS landing this phase. See `apple-tree-gap.md`. |
| B10 | Windows named-pipe — Manager **decision A** | 0d | Windows (#11) + Node IPC (#8) | High (Priority #1) | **Decision A: implement AUTHORIZED NOW** (not Sprint-1-deferred). Sprint 1 terminal slice **OPEN for pipe only**. Doctor/client keyed on `WINDOWS_NAMED_PIPE`. Compile P0-1 DONE (#20+#21). Linux/macOS UDS mostly green. **Does not unblock WAN Path C.** Docs/helpers **not** e2e-proven. **Do not greenlight duplicate compile fixes.** |
| B11 | `install.sh` hazard | 0d | CLI DX (#12) + DevSecOps (#20) | High | [RAVEN#17](https://github.com/Raven-ASHCO/RAVEN/pull/17) (draft) — fail-close install path. **Not** install evidence; docs/PR ≠ Proven. |
| B12 | Win loopback `127.0.0.1:7420` | 0d | Windows (#11) + Node IPC (#8) | Med | Loopback bind/listen is **not** WAN / named-pipe Proven. Docs-only ≠ Proven. |

**Cleared:** GitHub Org missing · repos on personal account · no CODEOWNERS · unprotected `main` · no teams · **B3** (RAVEN#7) · **M0 docs done ✅ CLOSED / MERGED** (RAVEN#3 ADR 0004 @ `ce087c7d9cfb`; Architect **full ACK** body+G5; Identity **full ACK** body+G5 pin `5d39099907ea` (= `main`); Crypto **ACK**) · **B10 compile P0-1** (RAVEN#20 + #21 MERGED).

---

## Ownership matrix (bot → GitHub team → primary paths)

| # | Bot | GitHub team(s) | Primary ownership |
|---|-----|----------------|-------------------|
| 1 | Architect | `architecture` | ADR/docs, default `*`, architecture board |
| 2 | Eng Program | _(none — process)_ | Blockers board, dependency age, review latency, critical path |
| 3 | Crypto ATSAM | `crypto` | ATSAM protocol/*, atsam*/hybrid*, shared-vectors atsam, **mlkem incremental FFI (B3 cleared)** |
| 4 | Protocol Spec | `protocol` | `/protocol/`, wire meaning, SPEC |
| 5 | Rust Core | `core` | `raven-core` (non-crypto slices), `ash`, mlkem FFI (with crypto) |
| 6 | P2P Network | `network` | `raven-swarm`, bridge/forward_queue |
| 7 | DTN Forward | `network` (+ assurance on queue) | forward_queue / mailbox / store-and-forward semantics |
| 8 | Node IPC | `core` + `identity` | `raven-node` (incl. `ipc_server.rs`), IPC stability |
| 9 | BLE Transport | `transport` (+ apple on BLE) | `ble*` framing/adapters |
| 10 | Apple Platform | `apple` | `/ios-native/` **(path missing; B8 Phase 1+ PARKED)** |
| 11 | Windows Platform | `windows` | `/RAVEN-Windows/` **(path missing)**; terminal path is Priority #1 (B10) |
| 12 | CLI DX | `core` / `release` | `node/crates/ash` |
| 13 | RDAP Protocol | `rdap` + `protocol` | RDAP repo protocol + task lifecycle |
| 14 | Python Runtime | `rdap` | `team_agents` server/client/executor/task_store |
| 15 | Identity AuthZ | `identity` | RAVEN_IDENTITY*, device_*/prekey*, `raven_identity.py` |
| 16 | LLM Runtime | `rdap` | `team_agents/llm.py` |
| 17 | Raven↔RDAP | `architecture` + `rdap` + `assurance` | Interop contract; **gates critical path** |
| 18 | Adversarial QA | `assurance` | Fuzz/property/fault; shared-vectors assurance |
| 19 | SRE Perf | **NO TEAM** | Delivery latency / queue depth / **Performance baseline** / reliability evidence bar — **unowned as a GitHub team** |
| 20 | DevSecOps | `release` + `assurance` | `.github/`, branch protection, SBOM/CI |

Default catch-all on both repos: `@Raven-ASHCO/architecture` + `@Raven-ASHCO/release` (RDAP also `@rdap`).

---

## Unowned / weakly owned paths

| Path | Repo | Effective owners today | Gap |
|------|------|------------------------|-----|
| `node/crates/raven-mlkem768-incremental-ffi/**` | RAVEN | `crypto` + `core` | **B3 CLEARED** (RAVEN#7) |
| `node/crates/raven-fb-ffi/**` | RAVEN | `*` only | Should be `core` / `protocol` (B4) |
| `node/third_party/**` | RAVEN | `*` only | Vendored crypto/sqlite — need `crypto`/`release` eyes |
| `node/adr/**` | RAVEN | `*` (docs ADR is under `/docs/adr/` only) | Align or extend CODEOWNERS |
| `/ios-native/**`, `/RAVEN-Windows/**` | RAVEN | Named but **trees missing** | B8 Phase 1+ **PARKED**; B5 / B9 landing later |
| Perf / SLO docs & gates | both | none (no `perf` team) | No GitHub team for #19 |

---

## O6 try-phase gap board (2026-09-06)

**Non-release inventory** at tip `7ccf180`: [`o6-raven-rdap-try-phase-gap-board.md`](o6-raven-rdap-try-phase-gap-board.md). Fail-closed check [`scripts/o6_try_phase_gap_check.sh`](../../../scripts/o6_try_phase_gap_check.sh) is **expected RED**. M0 remains closed; **M1–M3 production code still gated** (terminal + HOLD). This 2026-09-04 board’s B10 “named-pipe = #1 blocker” sentence is **stale vs [RAVEN#43](https://github.com/Raven-ASHCO/RAVEN/pull/43)** (pipe **code** landed; **not** terminal Proven). Do not treat a docs refresh as O6 harness green.

## O6 milestone gate (M0 / RAVEN#3)

**M0 docs done ✅ CLOSED / MERGED.** [RAVEN#3](https://github.com/Raven-ASHCO/RAVEN/pull/3) ADR 0004 is on `main` at `ce087c7d9cfb`.

| Party | ACK |
|-------|-----|
| Architect | **full ACK** ADR body + Appendix G5 |
| Identity | **full ACK** ADR body + G5 pin `5d39099907ea` (= `main`) |
| Crypto | **ACK** |

**Only** M1–M3 **production** code remains gated (terminal-path board green **and** RVN1 **HOLD**). M0 MERGED ≠ terminal Proven ≠ HOLD lift ≠ license to land M1–M3 production code. No M0 ACK is open.

| ID | Name | Window | Owners | Status |
|----|------|--------|--------|--------|
| **M0** | Spec freeze (ADR 0004) | W0–1 | Raven↔RDAP + Architect + Crypto + Identity | **✅ CLOSED / MERGED** — `main` `ce087c7d9cfb`; Architect **full ACK** body+G5; Identity **full ACK** body+G5 pin `5d39099907ea` (= `main`); Crypto **ACK**. **Only** M1–M3 code remains gated. |
| **M1** | Identity bridge (same RVN1) | W1–3 | Identity + Node IPC + Python Runtime | **No M1–M3 production code** — closed on terminal + HOLD |
| **M2** | Sealed carrier via IPC/LanDial | W3–6 | Node IPC + Crypto + RDAP Protocol + Python Runtime | Blocked on M1 |
| **M3** | Two-device encrypted harness | W6–8 | Adversarial QA + SRE + **Eng Program** + CLI DX | Blocked on M2 |
| **M4** | Deprecate confidential claims for plaintext carriers | ∥ M3 | RDAP Protocol + Assurance | Parallel w/ M3; not separately greenlit |

**Stretch:** production mailbox offline leg **after** M3 green.

**Eng Program watch:** flag M1–M3 production / feature work; escalate blocked-dependency age; M3 harness coordination stays after terminal Priority #1.

---

## Critical path — terminal board → RDAP integration → identity → ATSAM → IPC

**Order is hard dependency.** Terminal Win/macOS/Linux reliability + three-path matrices **before** O6 M1+.

**Do not claim production Raven↔RDAP integration until lower layers are owned + CI-gated + Proven** (try-phase: executed green/red only — linked CI or agent smoke). Docs-only ≠ Proven.

Fake-integration watch: any PR that wires RDAP tasks to production raven-node ATSAM sessions, or lands M1–M3 **production** code, while B1 remains open **or** terminal board is not green → Eng Program flags as premature.

---

## Menu-smoke / terminal CI sequence

| Item | State |
|------|--------|
| Sole menu-smoke CI | [RAVEN#16](https://github.com/Raven-ASHCO/RAVEN/pull/16) — Apple **APPROVE** + Core **ACK**; converge **DONE** with SRE |
| Proven flip | **Only** after executed green/red recorded (linked CI or agent smoke). Docs-only ≠ Proven. |
| Merge order | #20 + #21 **MERGED** (compile P0-1 **DONE**) → land #16 **when green** → #19 rebases **preserving** menu-smoke |
| B10 remaining | **Decision A AUTHORIZED NOW** — named-pipe implement (Windows + Node IPC). Sprint 1 slice **OPEN for pipe only**. Doctor/client keyed on `WINDOWS_NAMED_PIPE`. **Does not unblock WAN Path C.** |
| #21 | **MERGED** with #20 — **not** CI-held. Compile P0-1 closed. |

---

## Review-latency baseline (Sprint 0)

| Metric | Value | Sample |
|--------|-------|--------|
| Early merged-PR sample | 1 | RAVEN#1 docs baseline freeze (author==merger, 0 reviews) |
| Approving reviews on that sample | **0** | author merged |
| Later `main` merges | several Sprint 0 docs/governance PRs | **Do not invent** new time-to-merge numbers here |

**Baseline declaration:** review latency **undefined / insufficient sample**. Exclude self-merges from SLA.

---

## Protection / governance checklist (live)

| Control | RAVEN | RDAP |
|---------|-------|------|
| Under `Raven-ASHCO` | Yes | Yes |
| `.github/CODEOWNERS` | Yes (B3 line live) | Yes |
| Required CI contexts | **None** (B1; #19 draft — do not enable) | **None** |
| Code owner reviews required | Yes | Yes |
| `enforce_admins` | Yes | Yes |

---

## Next actions

1. **DevSecOps (#20) + Eng Program:** RAVEN#19 draft CI-align; provisional pin **after green**; **do not enable** required checks until verified + Manager GO (B1).
2. **B3:** **CLEARED** (RAVEN#7). No further CODEOWNERS action on mlkem FFI.
3. **B2:** accepted for bot-only org; escalate only if human reviewers added.
4. **Founder Priority #1:** terminal L/M/W + three-path matrices; **no M1 eng** until terminal board green (CEO override only).
5. **Menu-smoke / macOS:** wire `ash_menu_smoke`/`doctor` into CI (not operator-only) via [RAVEN#16](https://github.com/Raven-ASHCO/RAVEN/pull/16) + [RAVEN#22](https://github.com/Raven-ASHCO/RAVEN/pull/22). Menu smokes not GHA-gated yet. macOS CI unit/smoke proven. Notarize **BLOCKED_HUMAN**. Windows honest fail-closed until named-pipe.
6. **B10 decision A:** named-pipe **implement AUTHORIZED NOW** (not Sprint-1-deferred). Sprint 1 terminal slice **OPEN for pipe only**. Windows + Node IPC. Doctor/client keyed on `WINDOWS_NAMED_PIPE`. **Does not unblock WAN Path C.** No duplicate compile fixes.
7. **B11 / B12:** track #17 fail-close; do not treat `install.sh` or Win loopback `127.0.0.1:7420` as Proven.
8. **B8 Phase 1+ PARKED** (Windows terminal > iOS landing).
9. **SRE Perf (#19):** Performance baseline remains #19; harvest landed [RAVEN#26](https://github.com/Raven-ASHCO/RAVEN/pull/26). Soft budgets draft. Docs-only ≠ Proven.
10. **Apple/Windows trees:** B5 remains; B8 parked. **Manager + SRE:** `perf` team or fold #19 (B6).
11. **Path A locked:** localhost reservation only; do **not** call mesh relay reliable.
12. **Path B locked:** opaque custody + `ENDPOINT_ACK_ONLY` proven (software); not flood-proof / not Byzantine-safe. Prefer executed green/red citations.
13. **Path C locked:** LAN/localhost proven; WAN blocked/untested; internet dial fail-closed proven — **NOT** a WAN reliability claim. `ash_menu_smoke` → CLI DX #16. Windows honest fail-closed until named-pipe. **A+B+C board fills now present.** Continue **terminal**.
14. **macOS slice:** CI unit/smoke proven. Menu smokes not GHA-gated yet — wire `ash_menu_smoke`/`doctor` into CI (not operator-only). Track #16/#22. Notarize **BLOCKED_HUMAN**.
