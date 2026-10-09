# Terminal path reliability — governance (Sprint 0)

**Date:** 2026-09-04  
**Owner:** Role #19 SRE Perf  
**Risk class:** R0 (docs / governance only)  
**Repo:** [Raven-ASHCO/RAVEN](https://github.com/Raven-ASHCO/RAVEN)

> **Status-wording note (2026-10-05):** this document is a dated 2026-09-04
> snapshot. Its "in flight" / "pending" labels for PR #16, #17 and #26 predate
> their landing: `.github/workflows/raven-serverless.yml` on `main` already runs
> `ash_menu_smoke.sh` in the Linux, macOS and Windows jobs and named `bridge_v1`
> on macOS and Windows. Treat those labels as historical and re-check the
> workflow before relying on any "in-flight" row; this note does not upgrade any
> row to Proven.

This one-pager freezes **how a path may be claimed**. It does not add CI, does not change product behavior, and **does not invent metrics**. Tiers live in [`reliability-evidence-bar.md`](reliability-evidence-bar.md) (**Proven** / **PASS_SOFTWARE_SUBSTITUTE** / **Blocked**). Harvest numbers and draft soft budgets live in [`perf-baseline-2026-09-04.md`](perf-baseline-2026-09-04.md) / [PR #14](https://github.com/Raven-ASHCO/RAVEN/pull/14).

Org chart [`org-structure.md`](org-structure.md) still uses freeze titles (#19 Release Engineering Lead). This file follows the Sprint 0 assignment (**Role #19 SRE Perf**).

---

## Honest bar (policy)

A **named path** (Bridge / Mesh relay / Direct Internet — or a later named carrier) may be labeled Proven for terminal/node **only** when all of the following hold:

1. **Delivered + ACK + dedup + opaque** on that **named** path, via a **named** CI job or test on that OS (see evidence-bar Proven). Opaque means the carrier/bridge forwards `RavenEnvelope` / `RVN1` bytes and does not decrypt or mint endpoint ACKs.
2. **The same proof on ≥2 of {Linux, macOS, Windows}** for terminal/node — **or** Architecture Board **AND** Security Board **WAIVE** with **written notes from both boards** (same waiver form as [`sprint0-checklist.md`](sprint0-checklist.md)). **Eng Management alone cannot waive.** One green Linux job does not make macOS or Windows Proven.
3. **Soft soak fail-rate bound only after the first real snapshot.** Harvest maxima and Queue10kWall times in the perf baseline / PR #14 are **not** caps. Soft latency / soak-rate numbers stay **draft** until a later designated snapshot from a triggered run (or a cited Actions run ID). See founder rule below.
4. **Never conflate CI/software proof with physical/hardware proof.** `bridge_v1` / mock_ble / `network_sim_1000` / localhost swarm ≠ physical BLE radio, public CGNAT, DCUtR, or WAN.

Labels apply **per OS** and **per path**.

---

## Founder harvest rule

**FOUNDER RULE — Try phase = execute.** Numbers come only from runs this repo actually triggered, or from **cited GitHub Actions run IDs**. Do not estimate, placeholder-fake, or infer a soak/pass rate from missing `proof_artifacts/`. Precedent: [PR #14](https://github.com/Raven-ASHCO/RAVEN/pull/14) / [`perf-baseline-2026-09-04.md`](perf-baseline-2026-09-04.md). Soft budgets only after a real snapshot lands.

---

## Recorded claims (as of 2026-09-04)

No new numbers. Status is copied from the evidence bar Path × OS map, CI tables on current `main`, and in-tree harness docs. In-flight PRs are **not** green until merged to `main`.

| Path | Honest status (2026-09-04) | What exists | What it is not |
|------|----------------------------|-------------|----------------|
| **Bridge** | **Strongest software evidence.** Linux on current `main`: named `bridge_v1` + `lan_direct_two_node.sh` = **Proven (software)** in the evidence bar. Operator / harness: [`node/scripts/bridge_abc_demo.sh`](../../../node/scripts/bridge_abc_demo.sh) (mock_ble over TCP) and [`scripts/final_serverless_proof.sh`](../../../scripts/final_serverless_proof.sh) / [`docs/FINAL_SERVERLESS_PROOF.md`](../../FINAL_SERVERLESS_PROOF.md). | Software A–B–C Delivered+ACK+dedup+opaque (B does not decrypt). | Physical BLE. Not cross-OS terminal Proven on `main` (mac/Win: umbrella `cargo test` includes `bridge_v1`; **no** dedicated named step on current `main`). |
| **Mesh relay** | **Policy / sim strong; live weak.** Named `network_sim_1000` on Linux CI; sim also runs inside umbrella `cargo test` on mac/Win. Operator `reliability_matrix_20` `02_mesh_relay` is `bridge_v1` cargo — **not** CI live mesh. | Deterministic 1_000-node virtual-time model (harvest in perf baseline). Manual radio script: [`MESH_TEST_SCENARIOS.md`](../../../MESH_TEST_SCENARIOS.md). Physical three-device: [`docs/PHYSICAL_BLE_THREE_DEVICE.md`](../../PHYSICAL_BLE_THREE_DEVICE.md) (`BLOCKED_HARDWARE`). | Architecture map try-phase lock ([`architecture-dependency-map.md`](architecture-dependency-map.md) §2.1, [PR #4](https://github.com/Raven-ASHCO/RAVEN/pull/4); BLE framing SoT [`protocol/RAVEN_BLE_FRAMING_V1.md`](../../../protocol/RAVEN_BLE_FRAMING_V1.md)): on `main`, terminal mesh “proven” = **`mock_ble` only** until **B8 + RBF1**. `mock_ble` green ≠ live mesh DoD. Live radio remains `BLOCKED_HARDWARE`. **`network_sim_1000` ≠ `mock_ble` try-phase evidence.** Not CI live-proven. **Manager Path A libp2p mesh lock:** default [`raven-swarm`](../../../node/crates/raven-swarm) / [`libp2p_swarm_smoke.sh`](../../../node/scripts/libp2p_swarm_smoke.sh) is **localhost only** — must **not** be labeled “reliable” or mesh-relay Proven. `libp2p` swarm smoke ≠ reliable path claim. |
| **Direct Internet** | **Localhost / LAN + fail-closed legacy smoke only.** Linux CI: [`node/scripts/internet_dial_smoke.sh`](../../../node/scripts/internet_dial_smoke.sh) proves legacy `InternetTransport` origination stays **fail-closed** on `127.0.0.1`. Swarm / bootstrap smokes are localhost Kad/Noise. Transport note: [`protocol/RAVEN_TRANSPORT_INTERFACE_V1.md`](../../../protocol/RAVEN_TRANSPORT_INTERFACE_V1.md) (NAT/CGNAT/DCUtR **BLOCKED_HARDWARE**). | Fail-closed legacy path; LAN-direct two-node on Linux. Default `raven-swarm` smoke: [`node/scripts/libp2p_swarm_smoke.sh`](../../../node/scripts/libp2p_swarm_smoke.sh) (localhost TCP+Noise / Kad). | **NOT a WAN reliability claim.** Not public IP / CGNAT / DCUtR Proven. No `internet_dial_smoke` on `rust-macos` / `rust-windows`. **Manager Path A libp2p mesh lock:** default/`raven-swarm` localhost mesh/smoke is **localhost only** — must **not** be labeled “reliable” or WAN Proven. `libp2p` swarm smoke ≠ reliable path claim. |
| **Cross-OS terminal gap** | Messaging-path **named** gates on current `main` are **mostly Linux-only** (`reliability_10k --ignored`, dedicated `bridge_v1`, mailbox / `internet_dial_smoke`, `lan_direct_two_node.sh`). macOS/Windows umbrella `cargo test` is **not** a substitute for those named steps (evidence bar). | Expanding **in-flight** — do **not** claim green until merged to `main`: [PR #16](https://github.com/Raven-ASHCO/RAVEN/pull/16) `ash_menu_smoke` on linux+macos; [PR #26](https://github.com/Raven-ASHCO/RAVEN/pull/26) named `reliability_10k` + named `bridge_v1` on mac/Win and `ash_doctor_send_smoke.ps1` on Windows. | Not terminal-path Proven on mac/Win today. Design follow-up: [`tickets/cross-os-bridge-matrix.md`](tickets/cross-os-bridge-matrix.md) (**DESIGN ONLY**). |

---

## Non-evidence (do not relabel)

| ID / item | Rule |
|-----------|------|
| **B11** | [`node/scripts/install.sh`](../../../node/scripts/install.sh) is **Blocked / non-evidence**. [PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17) fatal-exit + README one-liner removal is operator relabel / fail-closed, **not** Proven install. |
| **B12** | Windows `127.0.0.1:7420` loopback in `windows_service.ps1` is **not** WAN, **not** LAN-direct Proven, **not** `terminal-path Proven (Windows)`. |
| Doctor-alone | `ash doctor` exit 0 ≠ send Proven. Presence / ready / send_path stay distinct (evidence bar). |
| Wine / lima / PE check | `reliability_matrix_20` `PASS_SOFTWARE_SUBSTITUTE` ≠ Windows Proven. |
| Parse-only install helpers | `windows_service.ps1` `Parser::ParseFile` is syntax, not install→doctor→send. |

---

## Related

| Doc | Role |
|-----|------|
| [`reliability-evidence-bar.md`](reliability-evidence-bar.md) | Per-OS / per-path tiers; named CI jobs; B11/B12 lock |
| [`perf-baseline-2026-09-04.md`](perf-baseline-2026-09-04.md) / [PR #14](https://github.com/Raven-ASHCO/RAVEN/pull/14) | First harvest; soft budgets **draft**; no soak rate |
| [`tickets/cross-os-bridge-matrix.md`](tickets/cross-os-bridge-matrix.md) | Design-only ticket for ≥2-OS Bridge CI |
| [`architecture-dependency-map.md`](architecture-dependency-map.md) §2.1 ([PR #4](https://github.com/Raven-ASHCO/RAVEN/pull/4); not on this topic branch) | Try-phase lock: terminal mesh “proven” on `main` = **`mock_ble` only** until **B8 + RBF1**; live radio `BLOCKED_HARDWARE` |
| [`protocol/RAVEN_BLE_FRAMING_V1.md`](../../../protocol/RAVEN_BLE_FRAMING_V1.md) | BLE Transport / framing SoT (`mock_ble` vs `ble_gatt`; desktop radio `BLOCKED_HARDWARE`) |
| [`docs/network/raven-swarm-connectivity-matrix.md`](../../network/raven-swarm-connectivity-matrix.md) | Swarm / NAT / relay honesty (on `main` as of PR #2). **Manager Path A:** default `raven-swarm` / `libp2p_swarm_smoke` = localhost only; not “reliable”; not WAN / mesh-relay Proven |
| [`node/scripts/libp2p_swarm_smoke.sh`](../../../node/scripts/libp2p_swarm_smoke.sh) | Two-node localhost rust-libp2p TCP (+QUIC listen) + Kad put/get — **not** a reliable-path or WAN claim |
| [`docs/NAT_SOFTWARE_SIM.md`](../../NAT_SOFTWARE_SIM.md) | Software NAT substitutes; not WAN |

---

## Addendum — Eng Program (Manager Path A)

**Manager Path A libp2p mesh lock:** default / `raven-swarm` localhost mesh and [`libp2p_swarm_smoke.sh`](../../../node/scripts/libp2p_swarm_smoke.sh) are **localhost only**. They must **not** be labeled “reliable” or WAN / mesh-relay Proven. `libp2p` swarm smoke ≠ a reliable path claim. Honesty inventory: [`docs/network/raven-swarm-connectivity-matrix.md`](../../network/raven-swarm-connectivity-matrix.md) (on `main` as of PR #2). No new numbers.

---

## Countersign

This policy is **R0**. Path-claim bar countersigns:

- [x] **Eng Program** countersign — COMPLETE 2026-09-04 (Path A libp2p localhost lock)
- [x] **Architect** countersign — ACK 2026-09-04 conditional→complete after `mock_ble` line

Waiver of clause 2 (≥2 OS) requires **Architecture Board AND Security Board written notes** (both boards; not Eng Management alone), not this checkbox.
