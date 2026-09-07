# RAVEN + RDAP — Ownership & Baseline Freeze (Sprint 0)

**بستهٔ فریز مالکیت و خط پایه | Ownership & Baseline Freeze Package**  
Date: 2026-09-04 · Org: RAVEN + RDAP engineering

## Purpose

This package freezes **who owns what**, **how risk is classified**, and **what must be true** before feature work starts. Without a baseline freeze, PRs merge without required review, trust boundaries stay implicit, and Raven↔RDAP gaps accumulate silently.

هدف: قبل از شروع فیچر، مالکیت، مرز اعتماد، و قوانین مرژ مشخص و قابل اجرا باشند.

## What must be true before feature work

| Gate | Required state |
|------|----------------|
| Ownership | Every critical path has a primary owner (role #) + team handle |
| Risk | R0–R3 classes published; R3 cannot be self-merged by anyone |
| Reviews | Approval matrix enforced via branch protection / rulesets |
| CODEOWNERS | Active on GitHub Org repos (not personal-account repos) |
| CI | Required status checks on `main` for RAVEN and RDAP |
| Baseline | Protocol versions, experimental flags, perf numbers, known gaps recorded |
| Security | Trust boundaries + known security/interop gaps documented |

Feature PRs that touch R2/R3 surfaces **must not** land until the Sprint 0 checklist ([`sprint0-checklist.md`](sprint0-checklist.md)) is complete or explicitly waived by Architecture Board + Security Board.

## Document map

| File | Contents |
|------|----------|
| [`risk-classes.md`](risk-classes.md) | R0–R3 definitions + no-self-merge-R3 rule |
| [`org-structure.md`](org-structure.md) | 5 domains, roles #1–#20, boards, text org chart |
| `03-role-charters.md` | **UNKNOWN** in this snapshot — checklist still cites it |
| [`approval-matrix.md`](approval-matrix.md) | Change type → owner → mandatory second approval |
| [`CODEOWNERS.proposed.md`](CODEOWNERS.proposed.md) | Pointer to live [`.github/CODEOWNERS`](../../../.github/CODEOWNERS) |
| [`github-org-plan.md`](github-org-plan.md) | Org, repos, teams |
| [`ninety-day-outcomes.md`](ninety-day-outcomes.md) | Outcomes O1–O7 |
| [`sprint0-checklist.md`](sprint0-checklist.md) | Deliverables checklist with status columns |
| `09-audit-snapshot-2026-09-04.md` | **UNKNOWN** in this snapshot |
| [`apple-tree-gap.md`](apple-tree-gap.md) | iOS/watchOS tree gap (exists on `main`) |
| [`windows-tree-gap.md`](windows-tree-gap.md) | Windows tree gap (exists on `main`) |
| [`docs/network/raven-swarm-connectivity-matrix.md`](../../network/raven-swarm-connectivity-matrix.md) | Sprint 0 raven-swarm connectivity / relay / NAT inventory; §0 founder direct-Internet honesty |
| [`perf-baseline-2026-09-04.md`](perf-baseline-2026-09-04.md) | Sprint 0 perf harvest (Role #19 SRE Perf); soft budgets draft |
| [`reliability-evidence-bar.md`](reliability-evidence-bar.md) | Sprint 0 terminal reliability tiers (Proven / substitute / Blocked); Role #19 SRE Perf; CLI DX operator appendix. **`reliability_10k` on macOS/Windows = queue durability only, not a path proof.** Path-claim sibling: [`terminal-path-reliability.md`](terminal-path-reliability.md). |
| [`terminal-path-reliability.md`](terminal-path-reliability.md) | Path-claim governance (honest bar); recorded Bridge / mesh / Internet / cross-OS claims as of 2026-09-04; Role #19 SRE Perf |
| [`tickets/cross-os-bridge-matrix.md`](tickets/cross-os-bridge-matrix.md) | Design-only ticket: minimal cross-OS Bridge CI matrix (`bridge_v1` + `bridge_abc`/smoke) — no implementation in that file |
| [`blockers-ownership-board.md`](blockers-ownership-board.md) | Living Sprint 0 blockers / ownership board (Eng Program) |
| [`three-path-verification-board.md`](three-path-verification-board.md) | Manager SoT A/B/C + founder Proven rule; mesh \| bridge \| direct |
| [`o6-raven-rdap-try-phase-gap-board.md`](o6-raven-rdap-try-phase-gap-board.md) | O6 try-phase honesty: what’s green vs gated toward the two-device encrypted harness; **non-release**; inventory ≠ Proven |
| [`o6-m1-same-rvn1-bind-contract.md`](o6-m1-same-rvn1-bind-contract.md) | O6 M1 D3 public whoami → RDAP pin-file bind (NON-RELEASE; not O6 E2E; not HOLD lift) |
| [`o6-m3-two-node-rdap-lab-evidence.md`](o6-m3-two-node-rdap-lab-evidence.md) | O6 M3 localhost two-process Raven↔RDAP lab (NON-RELEASE; not O6 E2E; `BLOCKED_HARDWARE` for WAN) |
| Live CODEOWNERS | [`.github/CODEOWNERS`](../../../.github/CODEOWNERS) (RAVEN); RDAP repo `.github/CODEOWNERS` |

### Sprint 0 architecture drafts (#1)

| File | Contents |
|------|----------|
| [`architecture-dependency-map.md`](architecture-dependency-map.md) | Layer boundaries, allowed/forbidden deps, crate inventory, RDAP→node path |
| [`trust-boundaries.md`](trust-boundaries.md) | TB1–TB5 Architect draft; #17 + #6 review requested |
| [`adr-framework.md`](adr-framework.md) | When/how to write ADRs; template; R3 no-self-merge; ADR-0004 (O6 / Appendix G5 — pin ≢ `device_ed_pub`) |
| [`undocumented-cross-layer-deps.md`](undocumented-cross-layer-deps.md) | Implicit couplings found in code/doc review (D1–D45) |

These four files are **R0 documentation**. They do **not** authorize R3 crypto, CODEOWNERS, or feature code.

**Try-phase (normative, this PR):** docs, the architecture map, and ADRs are **not** pass evidence. A pathway is **pass** only when **Delivered + ACK + dedup + opaque** is shown on a **named** path, on **≥2 OS** or with Architecture **and** Security **WAIVE**, with labels **per OS × path**. Do not collapse the three planes (mesh / bridge / direct). **Do not conflate software vs hardware.** Cross-link: [`terminal-path-reliability.md`](terminal-path-reliability.md), [`reliability-evidence-bar.md`](reliability-evidence-bar.md). **Bridge** is **sealed-ACK-only / opaque**: forward envelopes only — **must not decrypt or mint endpoint ACKs**.

**Identity (merged on `main` via PR #5):** [`docs/engineering/SPRINT0_IDENTITY_THREAT_MODEL.md`](../SPRINT0_IDENTITY_THREAT_MODEL.md), [`docs/engineering/G5_CROSS_STACK_REVOKE_POLICY.md`](../G5_CROSS_STACK_REVOKE_POLICY.md). Architect ACK: §2.4 + OPEN-ID-P0 is a **documented defect**, not a code approval. Soft-load fail-open stays **held**.

Living Eng Program boards (this PR): [`blockers-ownership-board.md`](blockers-ownership-board.md) · [`three-path-verification-board.md`](three-path-verification-board.md) — FOUNDER try-phase; Manager SoT A/B/C; **M0 docs done** `ce087c7d9cfb` (Architect **full ACK** body+G5; Identity **full ACK** body+G5 pin `5d39099907ea` (= `main`); Crypto **ACK**; **only** M1–M3 code remains gated).

## Non-goals

- Assigning named humans to roles (use role numbers / `@Raven-ASHCO/*` teams only until staffing is confirmed).
- Cloning or modifying live repos from this package (docs + paste-ready artifacts only).
- Inventing current CODEOWNERS or branch protection that do not exist (see audit).

## Next step

Complete [`sprint0-checklist.md`](sprint0-checklist.md). Org and teams are live (`github-org-plan.md`); remaining work is checklist rows and required CI pins.

1. Confirm Architecture + Trust rows (Architect **DONE** draft; Trust still requests **#17 + #6**).
2. Do **not** treat this PR as merge-ready until **#17** countersigns.
3. Further work is **#17 / #6 / #3 / #8 / #9 / #11** per checklist — not a second Architecture rewrite.
