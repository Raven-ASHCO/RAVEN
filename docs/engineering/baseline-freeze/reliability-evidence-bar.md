# Terminal reliability evidence bar (Sprint 0)

**Date:** 2026-09-04  
**Owner (semantics / CI bar):** Role #19 SRE Perf  
**Co-owner (operator surface / appendix):** CLI DX  
**Repo:** [Raven-ASHCO/RAVEN](https://github.com/Raven-ASHCO/RAVEN)  
**Workflow cited:** [`.github/workflows/raven-serverless.yml`](../../../.github/workflows/raven-serverless.yml) (`name: Raven Serverless Node`)

> **Status-wording note (2026-10-05):** this document is a dated 2026-09-04
> snapshot. Its "in flight" / "pending" labels for PR #16, #17 and #26 predate
> their landing: `.github/workflows/raven-serverless.yml` on `main` already runs
> `ash_menu_smoke.sh` in the Linux, macOS and Windows jobs and named `bridge_v1`
> on macOS and Windows. Treat those labels as historical and re-check the
> workflow before relying on any "in-flight" row; this note does not upgrade any
> row to Proven.

This file defines **Proven** vs **PASS_SOFTWARE_SUBSTITUTE** vs **Blocked** for terminal Win / macOS / Linux reliability. It does **not** invent run counts, soak rates, or `reliability_matrix_20` pass totals.

**FOUNDER RULE — Try phase = execute.** Harvest numbers only from runs we actually trigger, **or** cite exact GitHub Actions run IDs. Soft budgets only after real snapshots land. **Never invent or estimate metrics.** Precedent: [PR #14](https://github.com/Raven-ASHCO/RAVEN/pull/14) / [`perf-baseline-2026-09-04.md`](perf-baseline-2026-09-04.md) (triggered `cargo test` harvest on a recorded host). Soft latency budgets stay **draft**.

Swarm / NAT / relay honesty: [`docs/network/raven-swarm-connectivity-matrix.md`](../../network/raven-swarm-connectivity-matrix.md) (on `main` as of PR #2; not required to exist on every topic branch).

Org chart [`org-structure.md`](org-structure.md) still titles #19 as Release Engineering Lead. This bar follows the Sprint 0 assignment (**Role #19 SRE Perf**), same as the perf harvest.

---

## Purpose and owners

| Surface | Owner | Owns |
|---------|-------|------|
| Evidence tiers, named CI jobs, what may be labeled Proven | **#19 SRE Perf** | This document; workflow steps that are reliability *evidence* (queue 10k, `bridge_v1`, path-row labels) |
| **B11** evidence exclusion | **#19 SRE Perf** (co-own) | `install.sh` stays off Proven (CI exclusion). CLI DX [PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17) is fail-closed relabel, not Proven |
| **B12** evidence exclusion | **#19 SRE Perf** | Windows `127.0.0.1:7420` loopback ≠ path Proven. **Not B11.** |
| Operator retire / relabel of `install.sh` (**B11** only) | **CLI DX** (co-own) | [PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17) fatal-exit / README one-liner removal — **in flight**, not Proven |
| Operator how-to, `ash doctor` / install exit codes, how to run `reliability_matrix_20.sh` | **CLI DX** | Operator how-to + exit-code appendix at the bottom of this file; `ash` menu UX; install-script operator docs |

**Menu-smoke CI (linux + macOS):** owned by **CLI DX PR #16** (`cursor/ash-menu-smoke-linux-ci-a976`, agent `bc-097f7c8d`). That PR wires `node/scripts/ash_menu_smoke.sh` into `rust-linux` **and** `rust-macos`. This PR adds **zero** `ash_menu_smoke` CI steps. Until #16 is merged to `main`, menu-smoke is **pending / in-flight** — do not claim green.

**`reliability_10k` on macOS / Windows = queue durability only, not a path proof.** Path proof stays the already-tiered named **`bridge_v1`** / **`ash_menu_smoke`** / **`ash_doctor_send_smoke.ps1`** gates.

**One-pager** `terminal-path-reliability.md` lives in [PR #29](https://github.com/Raven-ASHCO/RAVEN/pull/29). It is **not** folded into this PR.

### Board IDs (exact — do not swap)

| ID | Meaning | Not this ID |
|----|---------|-------------|
| **B11** | `node/scripts/install.sh` **non-evidence** (wrong remote / `unsafe-demo-crypto` / ad-hoc sign). CLI DX [PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17) fail-closed + this bar’s CI exclusion. Still **not Proven**. | Windows loopback |
| **B12** | Windows `127.0.0.1:7420` loopback ≠ Proven path evidence | `install.sh` |

**Also exclude as Proven (no new board ID):** doctor-alone (`ash doctor` exit 0 ≠ send), `install.sh` (**B11**), Win loopback (**B12**).

Related:

- Perf numbers and draft soft budgets: [`perf-baseline-2026-09-04.md`](perf-baseline-2026-09-04.md)
- Localhost swarm vs public NAT: [`docs/network/raven-swarm-connectivity-matrix.md`](../../network/raven-swarm-connectivity-matrix.md)
- NAT substitutes (not WAN): [`docs/NAT_SOFTWARE_SIM.md`](../../NAT_SOFTWARE_SIM.md)

---

## Tier definitions (strict)

Labels apply **per OS** and **per path**. A green Linux job does not make Windows Proven.

### Proven

Automated **green on that OS** for **Delivered + ACK** (or **queue Delivered** for `reliability_10k`) **and** dedup **and** no panic on malformed input, via a **named** CI job / test on that OS.

Examples that can become Proven when the named step is green on that OS’s job:

- `cargo test -p raven-core --test reliability` (`reliability.rs`: restart→Delivered, inbound dedup, malformed/truncated do not panic)
- `cargo test -p raven-core --test reliability_10k -- --ignored` (queue enqueue / dedup / Delivered × 10_000)
- `cargo test -p raven-core --test bridge_v1` (software bridge Delivered + ACK + dedup)

**`reliability_10k` on macOS / Windows is queue durability only — not a path proof.** The named `rust-macos` / `rust-windows` `10,000-message queue reliability gate` proves enqueue / dedup / queue Delivered × 10_000 on that OS. It does **not** prove a messaging path, CLI/terminal-path, install→doctor→send, or WAN. **Path proof** (already tiered) requires the named **`bridge_v1`** step (software bridge Delivered+ACK+dedup) **and/or** **`ash_menu_smoke`** (Unix; CLI DX [PR #16](https://github.com/Raven-ASHCO/RAVEN/pull/16)) **and/or** **`ash_doctor_send_smoke.ps1`** (Windows; this PR). Do not promote a green `reliability_10k` row to path / terminal-path Proven.

**CLI / terminal-path Proven** is a *distinct* claim (see below). It is **not** implied by queue or `bridge_v1` Proven.

**One-pager** `terminal-path-reliability.md` is **not** in this PR. It lives in [PR #29](https://github.com/Raven-ASHCO/RAVEN/pull/29). Do not fold it here.

### PASS_SOFTWARE_SUBSTITUTE

Substitute results that **may** count toward a `reliability_matrix_20` budget and **MUST NOT** be labeled cross-OS terminal Proven:

- `reliability_matrix_20.sh` `sc_windows_wine`: wine64 `ash --help` or PE32+ self-check when wine is absent (`PASS_SOFTWARE_SUBSTITUTE`)
- lima `ash --help` / lima uname-only (`sc_linux_container`)
- Docker NAT topology **without** `raven-swarm` (`scripts/nat_docker_sim.sh`; `not_claimed=public_CGNAT,DCUtR,AutoNAT`)
- Cross-built `ash.exe` PE header check on a non-Windows host

**`reliability_matrix_20` wine / lima `ash --help` ≠ Windows Proven.** Never promote those rows to `terminal-path Proven (Windows)`.

### Blocked

No evidence on that OS’s CI job, or the path is hardware / portal / public-Internet by existing docs:

- Physical BLE (mock_ble / software bridge is not a radio claim)
- Public CGNAT / DCUtR / live multi-NAT
- Apple notarization / Windows Authenticode
- **B11** — `node/scripts/install.sh` ([PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17) fatal-exit is relabel, not Proven; see exclusion below)
- **B12** — Windows `127.0.0.1:7420` loopback (not WAN / not terminal-path Proven)
- Any path with **no** named job/test on that OS

### Core doctor gate (locked with Eng Program / CLI DX)

`ash doctor` reports **three distinct axes**. They must not be collapsed into one “healthy” bit.

| Axis | Meaning (SRE evidence) | Must not be read as |
|------|------------------------|---------------------|
| **presence** | Local daemon answered an IPC ping (transport-agnostic). | send Proven; identity ready; WAN path |
| **ready** | Presence plus usable identity / messaging_path / store-or-status as CLI DX implements. | send Proven; public Internet / BLE |
| **send_path** | Whether a send path was actually exercised or probed. Default in the Core gate is **not** green from presence or ready. | CLI / terminal-path Proven by itself |

**`ash doctor` exit code 0 must never be interpreted as “send proven.”** Exit 0 means the diagnostic *report completed*. It is not Delivered+ACK, not a send smoke, and not CLI ready.

**Presence or IPC-up alone ≠ Proven for send.** `daemon_state: up`, a socket/pipe existing, or `daemon_presence: present` does not make the terminal path Proven.

**CLI / terminal ready** still requires **install → doctor → send** (or green `ash_menu_smoke` on that OS, or green `ash_doctor_send_smoke.ps1` on Windows). Doctor output used as *inputs* to that chain must show the axes separately; a single green exit is not enough.

**False-green / false-red (honesty, locked):** treating exit 0 or IPC-up as send-ready is a **false-green**. Treating “doctor printed a warning / daemon absent” as a hard reliability FAIL when the report completed and send was never claimed is a **false-red** if someone then blocks a queue/`bridge_v1` Proven row. Keep the axes separate so neither happens. Windows `127.0.0.1:7420` (B12) is loopback-only — citing it as WAN/path Proven is also a **false-green**.

Detailed exit-code tables and operator wording live in the CLI DX appendix below (source: [PR #22](https://github.com/Raven-ASHCO/RAVEN/pull/22)). This section only locks the evidence rule.

**Also exclude as Proven (do not relabel):**

- doctor-alone (`ash doctor` exit 0 ≠ send)
- **B11** — `install.sh` + CLI DX [PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17) fail-closed (see below)
- **B12** — Windows `127.0.0.1:7420` loopback (see below; **not B11**)

---

## CLI / terminal-ready gate (SRE Perf)

| Claim | Required evidence on that OS | Not enough |
|-------|------------------------------|------------|
| Queue durability (`reliability_10k`) | Named `reliability_10k --ignored` green | **Not a path proof.** Doctor, `ash --help`, wine PE, `bridge_v1` |
| Software path / protocol (`bridge_v1`) | Named `bridge_v1` green | `reliability_10k` (queue only); doctor; wine PE |
| **CLI / terminal-path Proven** | Named CI step: `ash_menu_smoke.sh` (Unix; CLI DX #16) **or** `ash_doctor_send_smoke.ps1` (Windows; this PR) exercising **init → doctor (presence/ready/send_path distinct) → send teach or fail-closed send** | Doctor exit 0; presence / IPC-up; `ash --help`; matrix_20 wine/lima; **`reliability_10k`** |
| `terminal-path Proven (Windows)` | Green `rust-windows` step running `node/scripts/ash_doctor_send_smoke.ps1` on MSVC `ash.exe` | matrix_20 `14_windows_ash` wine / PE substitute; **B12** loopback listen |

Until the named step is green **on `main`**, label the row **proposed / in-flight**, not Proven.

---

## B11 — `node/scripts/install.sh` is non-evidence (Blocked)

**Eng Program B11 High — locked 2026-09-04.**

**Board ID B11** = `install.sh` is **NOT install evidence**. Status: **Blocked / non-evidence**. Our CI exclusion stays correct.

Do not cite [`node/scripts/install.sh`](../../../node/scripts/install.sh) as Proven or as an install path for reliability claims.

Reasons the path was never evidence (this branch’s copy still shows the old body until #17 merges):

- Wrong remote: curl header / `REPO=` clone **Ahmadreza-Arezehgar/RAVEN**
- `cargo build … --features raven-node/unsafe-demo-crypto` (debug lab crypto)
- Ad-hoc Darwin `codesign -s -` on those debug binaries

**CLI DX P0 [PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17):** `node/scripts/install.sh` now **fatal-exits** (fail-closed for leftover `curl | bash`). README one-liner removed. That is **operator relabel + fail-closed, not Proven install evidence.** Cite #17 next to B11 in every non-evidence list.

**Ownership (locked):** SRE Perf **co-owns evidence exclusion** (this bar + CI). CLI DX **co-owns operator retire / relabel** (already in flight via #17). Fatal-exit is progress on the hazard, **still not Proven**.

Prefer [`node/scripts/install/`](../../../node/scripts/install/) (`linux_systemd_user.sh`, `macos_launchd.sh`, `windows_service.ps1`) **only when separately proven** by a named job — do not invent Proven:

| Script | What CI does today (current `main` / this branch before merge) |
|--------|----------------------------------------------------------------|
| `linux_systemd_user.sh` | **Not** a `rust-linux` step |
| `macos_launchd.sh` | **Not** a `rust-macos` step |
| `windows_service.ps1` | `rust-windows` **parse-only** (`Parser::ParseFile`) — syntax, not install→doctor→send |

Parse-only or an unchecked helper is **not** terminal-path Proven.

## B12 — Windows `127.0.0.1:7420` loopback is not path Proven

**Board ID B12** (not B11). [`node/scripts/install/windows_service.ps1`](../../../node/scripts/install/windows_service.ps1) and [`WINDOWS_SERVICE.md`](../../../node/scripts/install/WINDOWS_SERVICE.md) bind `--lan-listen 127.0.0.1:7420`. That is **loopback-only**. It is **not** WAN Proven, **not** LAN-direct Proven, **not** `terminal-path Proven (Windows)`, and **not** a substitute for `ash_doctor_send_smoke.ps1`.

Do not file Windows loopback under B11.

---

## Per-OS CI evidence

Two columns: **current `main`** (workflow as investigated; `origin/main` at write time still matches the job bodies below) vs **this PR’s intended bar**. “Proposed” becomes Proven only after the named step is green on `main`.

`cargo test -p raven-core` (no `--ignored`) **does** run `reliability.rs`, `bridge_v1`, and `network_sim_1000` because those tests are not `#[ignore]`. `reliability_10k` is `#[ignore]` and runs **only** when a step passes `--ignored`.

### Linux — job `rust-linux` / **Rust + vectors (Linux)**

| Gate | Current `main` | This PR |
|------|----------------|---------|
| `reliability.rs` (via `cargo test -p raven-core`) | Yes | Unchanged |
| Named `reliability_10k --ignored` | Yes — step `10,000-message queue reliability gate` | Unchanged |
| Named `bridge_v1` (+ `fuzz_smoke`) | Yes — step `bridge + fuzz smoke` | Unchanged |
| Named `network_sim_1000` debug + release | Yes | Unchanged |
| `lan_` KATs | Yes | Unchanged |
| `lan_direct_two_node.sh` | Yes | Unchanged |
| `libp2p_swarm_smoke.sh` / `bootstrap_manual_peer_smoke.sh` | Yes | Unchanged |
| Mailbox smokes (`mailbox_opaque_smoke.sh`, `swarm_mailbox_smoke.sh`) | Yes | Unchanged |
| `internet_dial_smoke.sh` (legacy path **fail-closed**) | Yes | Unchanged |
| Experimental mailbox/NAT binaries + security-hold | Yes | Unchanged |
| `ash_menu_smoke.sh` | **No** | **No** — CLI DX PR #16 / follow-up |
| `reliability_matrix_20.sh` | **Not in CI** | **Not in CI** |

### macOS — job `rust-macos` / **Rust (macOS)**

| Gate | Current `main` | This PR |
|------|----------------|---------|
| `cargo test -p raven-core -p ash -p raven-node` (includes `reliability.rs`, `bridge_v1`, `network_sim_1000`) | Yes | Unchanged |
| `lan_` KATs | Yes | Unchanged |
| Named `reliability_10k --ignored` | **No** | **Proposed** — new step; **queue durability only, not a path proof** |
| Named `bridge_v1` | **No** dedicated step (covered only inside the umbrella `cargo test`) | **Proposed** — new named step (path / software-bridge proof) |
| Named `network_sim_1000` debug+release | **No** dedicated step (debug sim already inside umbrella `cargo test`) | Not added (already in `cargo test`; Linux keeps the extra release pass) |
| `lan_direct_two_node.sh` | **No** | **No** |
| Mailbox / `internet_dial_smoke.sh` | **No** | **No** |
| Swarm + bootstrap bash smokes | Yes | Unchanged |
| `ash_menu_smoke.sh` | **No** | **No** — CLI DX PR #16 / follow-up |

`network_sim_1000` is a deterministic virtual-time model (harvest wall ~0.5 s debug on Linux). It is **not** skipped here for heaviness; a second named macOS/Windows invocation is omitted because the umbrella `cargo test -p raven-core` already executes it. That umbrella is **not** a substitute for naming `reliability_10k` (ignored) or a dedicated `bridge_v1` step.

### Windows — job `rust-windows` / **Rust (Windows)**

| Gate | Current `main` | This PR |
|------|----------------|---------|
| `cargo test -p raven-core -p ash -p raven-node` (includes `reliability.rs`, `bridge_v1`, `network_sim_1000`) | Yes | Unchanged |
| Named `reliability_10k --ignored` | **No** | **Proposed** — new step (cargo, not bash); **queue durability only, not a path proof** |
| Named `bridge_v1` | **No** dedicated step | **Proposed** — new named cargo step (path / software-bridge proof) |
| Bash smokes (swarm / bootstrap / mailbox / internet / lan_direct / `ash_menu_smoke`) | **No** | **No** — do not add |
| `windows_service.ps1` | Parse-only | Unchanged (not terminal-path Proven) |
| `ash_doctor_send_smoke.ps1` | **No** | **Proposed** — new pwsh step; fail loud if `ash.exe` missing |
| matrix_20 wine `ash --help` | Not CI | Never Windows Proven |

Windows cargo steps use the job default shell (not bash). No `|| true` on the new smoke.

---

## Artifact map

| Artifact | Role | CI |
|----------|------|----|
| [`node/crates/raven-core/tests/reliability.rs`](../../../node/crates/raven-core/tests/reliability.rs) | Restart mid-queue → Delivered; inbound dedup; malformed/truncated `Envelope::unpack` must not panic; OOO message_ids dedup independently | Via `cargo test -p raven-core` on `rust-linux`, `rust-macos`, `rust-windows` |
| [`node/crates/raven-core/tests/reliability_10k.rs`](../../../node/crates/raven-core/tests/reliability_10k.rs) | Ignored 10k enqueue / dedup / Delivered — **queue durability only, not a path proof** | Named on `rust-linux` today; **this PR** adds the same named command on `rust-macos` and `rust-windows` |
| [`node/scripts/reliability_10k.sh`](../../../node/scripts/reliability_10k.sh) | Operator wrapper; without `RAVEN_RELIABILITY_10K=1` runs a 1k `fuzz_smoke` subset instead of 10k | **Not** a workflow step (CI calls `cargo test … --ignored` directly) |
| [`scripts/reliability_matrix_20.sh`](../../../scripts/reliability_matrix_20.sh) | Looped operator matrix; allows `PASS` / `PASS_SOFTWARE_SUBSTITUTE` / `SKIP` | **NOT in CI.** No pass counts recorded here. |
| [`node/scripts/ash_menu_smoke.sh`](../../../node/scripts/ash_menu_smoke.sh) | Unix install→doctor→menu/send (ephemeral dir, `RAVEN_IDENTITY_BACKEND=locked-file`) | **pending / in-flight** — CLI DX PR #16 / follow-up. Not on current `main`. Not added in this PR. |
| [`node/scripts/ash_doctor_send_smoke.ps1`](../../../node/scripts/ash_doctor_send_smoke.ps1) | Windows init→doctor→send teach / fail-closed (MSVC `ash.exe`) | **This PR** wires `rust-windows`. Intended `terminal-path Proven (Windows)` **after** green on `main`. |
| [`node/scripts/install.sh`](../../../node/scripts/install.sh) + [PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17) | Wrong remote + `unsafe-demo-crypto` + ad-hoc sign. #17 **fatal-exit** / README one-liner removed = relabel + fail-closed, **not** Proven | **Blocked / non-evidence (B11)** |
| `127.0.0.1:7420` in `windows_service.ps1` | Loopback listen only | **Blocked as path evidence (B12)** |

No `RELIABILITY_20_GREEN` rate or soak percentage is claimed. `proof_artifacts/` is gitignored; absence is not a pass rate.

---

## Path × OS (honest map)

Software bridge is the strongest automated story. Mesh is sim + (optional) manual. Direct Internet in CI is localhost **fail-closed**, not WAN Proven.

| Path | Linux | macOS | Windows |
|------|-------|-------|---------|
| **Mesh relay** | **Partial** — `network_sim_1000` (named) + `reliability.rs`; `reliability_matrix_20` `02_mesh_relay` is `bridge_v1` cargo (operator, not CI). Not a live multi-hop radio mesh. | **Partial** — sim inside umbrella `cargo test`; no named extra sim step. | **Partial** — same umbrella `cargo test`. No bash mesh smoke. |
| **Bridge** | **Proven (software)** on current `main` via named `bridge_v1` + `lan_direct_two_node.sh`. Not physical BLE. | **Partial** on current `main` (umbrella `cargo test` includes `bridge_v1`). **This PR:** named `bridge_v1` → **proposed Proven (software)** once green on `main`. No `lan_direct` / `bridge_abc` on this job. | **Partial** on current `main`. **This PR:** named `bridge_v1` → **proposed Proven (software)** once green on `main`. No bash bridge demo. |
| **Direct Internet** | **Not WAN Proven.** `internet_dial_smoke.sh` proves legacy `InternetTransport` origination stays **fail-closed** on localhost. Public IP / CGNAT / DCUtR **Blocked**. | **Blocked** for WAN. No `internet_dial_smoke` on `rust-macos`. Swarm smoke is localhost Kad/Noise, not public Internet. | **Blocked** for WAN. No internet smoke. Wine `ash --help` is **Substitute**, not this row. |

**Always Blocked (all OS):** physical BLE, public CGNAT/DCUtR, notarization / Authenticode, **B11** `install.sh` ([#17](https://github.com/Raven-ASHCO/RAVEN/pull/17) fatal-exit ≠ Proven), **B12** Win loopback-as-WAN, doctor-alone (exit 0), any path with no named evidence on that OS.

---

## Windows real path vs wine substitute

| Tier | What it is | What it is not |
|------|------------|----------------|
| **`terminal-path Proven (Windows)`** | Future/this-PR pwsh: `ash.exe init` → `doctor` (presence / ready / send_path distinct; **exit 0 ≠ send**) → send teach or fail-closed send, on an MSVC runner via [`node/scripts/ash_doctor_send_smoke.ps1`](../../../node/scripts/ash_doctor_send_smoke.ps1) | matrix_20 wine, PE self-check, lima, Docker NAT, **B12** `127.0.0.1:7420` |
| **PASS_SOFTWARE_SUBSTITUTE (Windows)** | `sc_windows_wine` in `reliability_matrix_20.sh` | Never upgrade to terminal-path Proven |

If `target/debug/ash.exe` is missing after `cargo build -p ash`, the smoke **exits 1** with `MSVC ash binary missing — blocked on Windows Platform PR1`. There is **no** silent skip and **no** green path when the binary is absent. `RAVEN_ALLOW_ASH_SMOKE_SKIP` is **not** honored by this script (fail-on-silent-skip).

Do **not** conflate `windows_service.ps1` parse-only with this tier.

---

## Soft budgets

**FOUNDER RULE — Try phase = execute** applies here: harvest maxima and Queue10kWall times in [`perf-baseline-2026-09-04.md`](perf-baseline-2026-09-04.md) / [PR #14](https://github.com/Raven-ASHCO/RAVEN/pull/14) are **not** caps. Soft budgets only after a real designated snapshot from a triggered run (or a cited Actions run ID). Never invent or estimate numbers. Soft budgets remain **draft**.

---

## Operator how-to (CLI DX)

These commands are for **operators**. They do **not** change the SRE tiers above. Matrix wine / lima rows stay **PASS_SOFTWARE_SUBSTITUTE** (never Windows Proven). Real install (release builds) is the `docs/INSTALL_*.md` path, not `node/scripts/install.sh`.

### `scripts/reliability_matrix_20.sh` (operator matrix; **not in CI**)

Path is repo-root [`scripts/reliability_matrix_20.sh`](../../../scripts/reliability_matrix_20.sh). From the repository root:

```bash
bash scripts/reliability_matrix_20.sh
# optional:
ITERS=3 bash scripts/reliability_matrix_20.sh
SKIP_IOS=1 SKIP_DOCKER=1 SKIP_WINE=1 bash scripts/reliability_matrix_20.sh
```

The script builds debug `raven-node` / `ash` / `raven-swarm`, loops the scenario list, and writes `node/proof_artifacts/reliability_20_<run-id>/` (`SUMMARY.md`, `RESULTS_TABLE.md`, `results.csv`). Exit 0 only when the pass budget is met and no hard `FAIL` remains. Platform `SKIP` is allowed. **This file records no pass counts.**

**wine / lima = PASS_SOFTWARE_SUBSTITUTE only — never Windows Proven.**

| Matrix row | What it actually runs | Evidence label |
|------------|----------------------|----------------|
| `14_windows_ash` (`sc_windows_wine`) | Cross-built `ash.exe` PE32+ self-check; optional `wine64 ash --help` | **PASS_SOFTWARE_SUBSTITUTE** — even if the script prints `PASS` for wine `--help` |
| `15_linux_container` lima fallback | lima `uname` and/or lima `ash --help` (or musl ELF self-check) | **PASS_SOFTWARE_SUBSTITUTE** |

Do **not** promote those rows to `terminal-path Proven (Windows)`. Wine / lima `ash --help` is a help-text substitute, not Delivered+ACK, not install→doctor→send.

### `node/scripts/ash_menu_smoke.sh` (Unix terminal-path smoke)

Local (from `node/`; script builds `target/debug/ash` if missing):

```bash
cd node
./scripts/ash_menu_smoke.sh
```

Uses an ephemeral `--data-dir` and `RAVEN_IDENTITY_BACKEND=locked-file`. Success prints `ASH MENU SMOKE PASSED`. That backend is a debug/CI identity, **not** a Keychain or production-install claim. Operators must **not** set `RAVEN_IDENTITY_BACKEND=locked-file` for a normal Keychain / Secret Service install.

**CI landing (linux + macOS):** [PR #16](https://github.com/Raven-ASHCO/RAVEN/pull/16) wires this script into `rust-linux` **and** `rust-macos`. Until #16 is merged to `main`, menu-smoke is **pending / in-flight** — do not claim green. This reliability-bar PR does **not** add those steps.

### Real install (release builds)

Operator install is **release**, not the matrix / menu-smoke debug binaries:

- [`docs/INSTALL_Linux.md`](../../INSTALL_Linux.md) → `node/scripts/install/linux_systemd_user.sh`
- [`docs/INSTALL_macOS.md`](../../INSTALL_macOS.md) → `node/scripts/install/macos_launchd.sh`
- [`docs/INSTALL_Windows.md`](../../INSTALL_Windows.md) → native MSVC `ash.exe` / `windows_service.ps1`

Those endorsed helpers stay **unproven** until a named CI job covers them (see B11 table above). `node/scripts/install.sh` is **not** an install path — see Explicit notes / B11.

Local first-run bootstrap (debug, stable `~/.raven`, **not** evidence): `bash scripts/ash_first_run.sh` (`--init-only` / `--no-run` supported). Prefer the INSTALL docs for a real machine.

### Windows path smoke — `node/scripts/ash_doctor_send_smoke.ps1`

Scaffolded on this PR. Sibling of `ash_menu_smoke.sh` (Unix CI: [PR #16](https://github.com/Raven-ASHCO/RAVEN/pull/16)). **Fail-loud if `ash.exe` is missing** — no silent skip, no `RAVEN_ALLOW_ASH_SMOKE_SKIP`. Do **not** call `node/scripts/install.sh` ([PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17) B11). Doctor axes from [PR #22](https://github.com/Raven-ASHCO/RAVEN/pull/22): `daemon_presence` / `daemon_ready` / `send_path` stay distinct; doctor exit 0 ≠ send Proven. Operator/CI usage is also in the script header. **Do not invent Proven** — proposed until the named `rust-windows` step is green on `main`.

**Operators (from `node/` on a Windows / pwsh host):**

```powershell
cd node
pwsh -File scripts/ash_doctor_send_smoke.ps1
```

The script `cargo build`s `-p ash -p raven-node` if needed, then `init` → `whoami` → `doctor` (requires identity + `serverless_rvn1`; IPC-up / `daemon_presence: present` alone is not enough) → menu send teach / fail-closed. Exit 0 only when every required string is present.

**Windows Platform co-review (PR #26):** workflow glue LGTM. The smoke does **not** require `daemon_presence: present` (that would greenwash Windows `blocked (reason=ipc_transport_missing)`). Once [PR #22](https://github.com/Raven-ASHCO/RAVEN/pull/22) labels appear on this tree, the script requires `daemon_presence:`, `daemon_ready:`, and `send_path: not_ready|unchecked`; on Windows until the Sprint 1 named-pipe client it expects `daemon_presence: blocked (reason=ipc_transport_missing)`. Pre-#22 trees (labels not printed today) keep identity + `serverless_rvn1` only. Requiring `present` remains a false-green.

If `target\debug\ash.exe` is still missing after cargo: **exit 1** with `MSVC ash binary missing — blocked on Windows Platform PR1`. Same fail-closed if the `.ps1` itself is missing.

**Debug binary is intentional.** Same as `ash_menu_smoke.sh` / [PR #16](https://github.com/Raven-ASHCO/RAVEN/pull/16): `RAVEN_IDENTITY_BACKEND=locked-file` is `debug_assertions` only and **refused in Release**. Do not point this smoke at `target\release\ash.exe`. No step-order change requested — keep the named `rust-windows` step after the job’s cargo test/build.

**Split A ownership (no duplicate glue PR):** script content = **CLI DX**; `rust-windows` job glue (fail-loud if the `.ps1` is missing, then invoke it) = **Windows Platform**.

**CI (`rust-windows`, working-directory `node`, `shell: pwsh`):**

```powershell
$ErrorActionPreference = 'Stop'
$script = 'scripts/ash_doctor_send_smoke.ps1'
if (-not (Test-Path -LiteralPath $script)) {
  Write-Error "$script missing — refusing silent skip"
  exit 1
}
& $script
if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
```

`terminal-path Proven (Windows)` is only claimed after this smoke is green on `main`. Until then the row is **proposed / in-flight**.

---

## Doctor / install exit codes (CLI DX)

**Source of truth:** Core gate + [PR #22](https://github.com/Raven-ASHCO/RAVEN/pull/22) (`cmd_doctor` on `presence` / `ready` / `send_path`). Labels below are pasted from that gate — not invented here.

SRE binding rule (locked above): **`ash doctor` exit 0 ≠ send Proven**; `daemon_presence` / `daemon_ready` / `send_path` stay distinct.

### Axes (`ash doctor`)

| Label | Meaning (Core / #22) | Default / honesty |
|-------|----------------------|-------------------|
| `daemon_presence` | Local IPC **Ping** answered. **Not** “file exists.” **Not** send. Replaces Ping-only `daemon_state: up`. | `present` / `absent (reason=…)` / `blocked (reason=…)` |
| `daemon_ready` | Presence **plus** `IpcResponse::Status`, identity usable via `store_status`/`load`, queue/DB open **or** Status `forward_pending`, and `serverless_rvn1`. File existence is `file_present` only. | `ready` or `not_ready (reason=…)` (`status_unchecked`, `no_presence`, `ipc_transport_blocked`, …) |
| `send_path` | Whether a send path was actually exercised or probed. | Default **`not_ready (reason=not_probed)`** or **`unchecked`**. Never green from presence or ready. |

`ash doctor --require-ready` still does **not** claim send. It only exits 1 when `daemon_ready` is false.

### Exit codes

| Code | Meaning | Must not be read as |
|------|---------|---------------------|
| **0** | Report **completed**. Diagnostic printed. | **≠ send Proven.** Not Delivered+ACK. Not CLI / terminal-path Proven. |
| **1** | Hard diagnostic failure, or `--require-ready` when `daemon_ready` is false. | Soft-skip / “daemon absent” as a queue/`bridge_v1` reliability FAIL (that would be a **false-red** if send was never claimed) |
| **2** | Security hold / production gate (`legacy_fastapi`, identity continuity). | Install Proven; send Proven |

### Soft-skips never ✓

Doctor prints these as skips / unknown. They are **never** a checkmark and **never** “up”:

- `bluetooth: skipped (headless)`
- `nat_class: unknown (BLOCKED_HARDWARE)`

### Doctor IPC-up alone ≠ CLI ready

`daemon_presence: present`, `daemon_state: up`, or a socket/pipe existing is **not** CLI ready and **not** send Proven.

**CLI / terminal ready** still requires **install → doctor → send** on that OS, **or** green [`ash_menu_smoke.sh`](../../../node/scripts/ash_menu_smoke.sh) (Unix; [PR #16](https://github.com/Raven-ASHCO/RAVEN/pull/16)), **or** green [`ash_doctor_send_smoke.ps1`](../../../node/scripts/ash_doctor_send_smoke.ps1) (Windows; this PR). Doctor output is an *input* to that chain; a single green exit is not enough.

### Windows presence (named-pipe Ping)

Canonical pipe: `raven_core::ipc::WINDOWS_NAMED_PIPE` = `\\.\pipe\raven-node` is the prefix; the daemon binds the per-user pipe `\\.\pipe\raven-node-<user SID>` (`raven_core::ipc::windows_user_pipe_name`).

The `ash` named-pipe **client** has landed (PR #43; `node/crates/ash/src/ipc_client.rs`: `connect_named_pipe` / `open_named_pipe`, which refuses a pipe served by another user). On Windows `ash doctor` never looks for `raven-node.sock`: it prints `file_present: raven-node.sock not_probed` and pings the pipe, so presence is the same Ping classification as on Unix:

- `daemon_presence: present` — a Ping answered on the pipe (still **not** CLI ready, **not** send Proven)
- `daemon_presence: down` — the pipe could not be opened or did not answer
- `daemon_presence: blocked (reason=ipc_transport_missing)` — only when there is no IPC transport at all: an unsupported OS, or a Windows process whose user SID cannot be read (`ipc_endpoint` is then `Unsupported`). Never a checkmark; it also makes `daemon_ready: not_ready (reason=ipc_transport_blocked)` and `send_path: not_ready (reason=not_probed)`.

The pipe is per user, not per profile: `ipc_endpoint` ignores the data dir on Windows (see `node/scripts/install/WINDOWS_SERVICE.md`).

Do not treat a loopback listen on `127.0.0.1:7420` as presence or path Proven (**B12**).

---

## Explicit notes (CLI DX)

- **wine / lima `ash --help` ≠ Win Proven.** Matrix `14_windows_ash` (wine or PE self-check) and lima `ash --help` / uname-only are **PASS_SOFTWARE_SUBSTITUTE** only. Never `terminal-path Proven (Windows)`.
- **B11 — `node/scripts/install.sh`.** CLI DX [PR #17](https://github.com/Raven-ASHCO/RAVEN/pull/17) fail-closes leftover `curl | bash` (fatal-exit; README one-liner removed). That is operator **relabel**, **not** install Proven. The path stays **Blocked / non-evidence**: wrong remote (`Ahmadreza-Arezehgar/RAVEN`) + `unsafe-demo-crypto` neutralized by the fatal-exit. SRE Perf co-owns the exclusion; CLI DX co-owns the relabel. Use `docs/INSTALL_*.md` for real (release) install.
