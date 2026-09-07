# O6 M3 — two-process localhost Raven↔RDAP lab (NON-RELEASE)

**Status:** lab execute / evidence only. **Not** O6 E2E Proven. **Not** a HOLD lift.  
**ADR:** [0004 D5](../../adr/0004-raven-rdap-atsam-transport.md) — harness acceptance (M3). This pack is the **smallest honest lab substitute** (two logical devices on `127.0.0.1`).  
**Label:** **NON-RELEASE**. Harness green ≠ HOLD lift. HOLD still active.  
**Topology:** localhost two-process (`raven-node` Alice + Bob). **dial≠WAN.**  
**Hardware:** `TWO_DEVICE_WAN=BLOCKED_HARDWARE` (no second physical device / WAN peer on this runner).  
**Owners:** Raven↔RDAP Integration Lead (#17) + SRE Perf (#19). **Sole M3 vehicle:** [RAVEN#57](https://github.com/Raven-ASHCO/RAVEN/pull/57) — no duplicate harness PRs.

Companion client invocation against RDAP tip `3207e8ea56002ff0efe0909ec9b6ec233b920c05` (`./rdap seal-under-session` / `team_agents.raven_ipc`). **No RDAP code change** in this pack — the tip still has no `EnqueueSealed` / `LanDial` in `raven_ipc.py` and no `ask` over `atsam_rvn1`. Dial uses existing Raven IPC (`ash lab lan-dial-sealed`). Python ATSAM is forbidden.

### Raven↔RDAP tip (do not invert)

| Surface | At RDAP `3207e8ea` / Raven this pack |
|---------|--------------------------------------|
| Seal | `./rdap seal-under-session` (plaintext-to-daemon) — on RDAP main |
| Python `EnqueueSealed` / `LanDial` | **Missing** in `raven_ipc.py` |
| `./rdap ask` | Still **HTTP A2A** — not `atsam_rvn1` |
| Dial | Prefer **`ash lab lan-dial-sealed`** (already-sealed Raven IPC; lab-only) |
| Ask carrier not wired | `BLOCKED_ASK_ATSAM` — do **not** fake |

---

## Claim language (normative for this pack)

| Claim | Status |
|-------|--------|
| Proven (lab under HOLD) | **Only markers that PASS with artifacts** (see table below) |
| Not Proven | **O6 E2E** · **HOLD lift** · **WAN** · **confidential production** · **PRODUCTION_ENABLED** · **HTTP A2A as O6 green** · **RDAP ask-over-atsam_rvn1** · **physical two-device** |
| HOLD | **ACTIVE** |
| Harness green ≠ HOLD lift | **true** |

Do **not** flip `PRODUCTION_ENABLED` tripwires. Do **not** describe this as confidential Raven messaging or production ATSAM. `mock_ble` remains the mesh claim on `main` (this pack does not touch BLE). Docs-only ≠ Proven. Harness green ≠ HOLD lift.

Stderr banner (harness):

```
NON-RELEASE / HOLD active. two-process localhost Raven↔RDAP lab only. Not O6 E2E Proven. No HOLD lift. dial≠WAN. Soft-load P0 held. PRODUCTION_ENABLED unchanged. mock_ble untouched.
```

---

## Reliability (Role #19 SRE Perf)

Cross-link: [`reliability-evidence-bar.md`](reliability-evidence-bar.md) · [`perf-baseline-2026-09-04.md`](perf-baseline-2026-09-04.md). Harvest numbers only from runs we actually trigger. **Never invent or estimate metrics.**

| Rule | This pack |
|------|-----------|
| Soft p50 / p95 | **Not recorded.** Soft latency budgets only after a **real snapshot**. Do not invent. |
| Wall-clock | **OK now.** Harness records `WALL_CLOCK_SEC` (host wall time for the execute pack). Not a budget. |
| Bring-up / listen race | **One retry max.** If `raven-node` bind/listen fails, restart that node once. If still red → hard `O6_M3_TWO_NODE_LAB=FAIL`. |
| Silent skip | **Forbidden.** Missing surfaces are `BLOCKED` (honest cite) or `FAIL`. Do not skip a required marker. |
| Artifacts | Public logs only under [`artifacts/o6-m3-two-node-rdap/`](artifacts/o6-m3-two-node-rdap/). No identity / session secrets. |

---

## Honesty matrix (D5 vs this lab)

| D5 acceptance item | This pack |
|--------------------|-----------|
| Two devices (physical or VM), each with `raven-node` + RDAP | **Lab substitute:** two `raven-node` processes + RDAP seal CLI on Alice. Physical / WAN = `BLOCKED_HARDWARE`. |
| Mutual pin of the same RVN1 / device bindings (D3) | **PASS (lab):** mutual `ash contact add` + M1 public pin files via `scripts/o6_m1_same_rvn1_bind.sh`. |
| Alice `ask` → Bob completes (`RAVEN_A2A_OK_*`) | **Lab substitute / not Proven:** marker `RAVEN_A2A_OK_M3_LAB` is sealed by RDAP and opened in Bob's ash inbox (`GREEN_DIAL_OR_INBOX`). `BLOCKED_ASK_ATSAM` — `./rdap ask` at this tip remains **signed HTTP**. Do not treat HTTP A2A as O6 green. |
| Data-plane frames ATSAM-sealed + drop-session refuse | **PASS (lab) for seal/no-session:** daemon `RavenEnvelopeV1` + `RED_NO_SESSION` / `RED_MISSING_SESSION` (`ATSAM_SESSION_REQUIRED`; RDAP reports no task success). `RED_DROP_SESSION=BLOCKED` — no public session-drop IPC; Soft-load P0 held; do not invent revoke plumbing. |
| Carrier enum `atsam_rvn1` | **BLOCKED** — RDAP status at this tip does not report `atsam_rvn1`. |
| Replace RDAP “Important integration gap” | **Not done.** Gap paragraph stays (honest). D5.5 is for when the encrypted `ask` path exists. |
| Experimental mailbox opt-in / non-confidential | Unchanged. This pack does not enable it. |

---

## Pins

| Repo | Tip SHA | Note |
|------|---------|------|
| `Raven-ASHCO/RAVEN` | this branch (parent `e69411c8e8ef` / #55) | M3 lab harness + `ash lab lan-dial-sealed` |
| `Raven-ASHCO/raven-distributed-agent-protocol` | `3207e8ea56002ff0efe0909ec9b6ec233b920c05` | M2 plaintext-to-daemon client (#11); **no companion PR** |

Execute against those tips (or a later main that still contains them). Record the actual `git rev-parse HEAD` from the run in the captured `SUMMARY.txt`.

---

## Automated pack

```bash
# from repo root; debug ash + raven-node; no unsafe-demo-crypto
EVIDENCE_OUT=docs/engineering/baseline-freeze/artifacts/o6-m3-two-node-rdap \
  RDAP_HOME=/path/to/raven-distributed-agent-protocol \
  bash node/scripts/o6_m3_two_node_rdap_lab.sh
```

`RDAP_HOME` is optional: the script clones the pinned RDAP SHA when unset.

**Not wired** into `.github/workflows/raven-serverless.yml` here (same OAuth / required-check collision as M1/M2). Agent / local executable only.

Expected codes (Role #17 / #19 marker names; GREEN/RED/BLOCKED only — no invent):

| Marker | Expect |
|--------|--------|
| `UNIT_OR_PIN` | `PASS` — unit selftest + M1 same-RVN1 public pin |
| `RED_NO_SESSION` | nonzero RDAP CLI + `ATSAM_SESSION_REQUIRED`; RDAP must **not** report task success |
| `GREEN_SEAL` | `PASS` — `./rdap seal-under-session` → daemon `envelope_b64` |
| `GREEN_DIAL_OR_INBOX` | `PASS` — `ash lab lan-dial-sealed` + Bob inbox `RAVEN_A2A_OK_M3_LAB` (**lab substitute**, not full `ask`) |
| `BLOCKED_ASK_ATSAM` | `BLOCKED` — `./rdap ask` over `atsam_rvn1` missing at tip `3207e8ea` |
| `RED_DROP_SESSION` | `BLOCKED` this execute (no session-drop IPC; Soft-load P0 held). Negative refuse covered by `RED_MISSING_SESSION`. |
| `HOLD` | `ACTIVE` |
| `O6_M3_TWO_NODE_LAB` | `PASS` (lab only) and process exit **0** |
| `WALL_CLOCK_SEC` | recorded (host wall time; not a budget) |
| `P50_MS` / `P95_MS` | `not_recorded` until a real snapshot |
| Fail / regression | `O6_M3_TWO_NODE_LAB=FAIL` and exit **1** |

---

## Exact CLI (authoritative M3 smoke)

1. Two `raven-node service` processes on `127.0.0.1` (Alice + Bob).
2. Mutual `ash contact add` + M1 pin files.
3. Session-ensure is Raven, not RDAP: `RAVEN_LAB_TEST_A=1` + `ash send --contact`.
4. Alice:

```bash
./rdap seal-under-session \
  --peer-hint <64-hex-device-Ed25519> \
  --payload-b64 "$(printf '%s' 'RAVEN_A2A_OK_M3_LAB' | base64)" \
  --data-dir "$ALICE_DATA_DIR"
```

5. Forward the daemon envelope (already-sealed; ash does not seal):

```bash
ash --data-dir "$ALICE_DATA_DIR" lab lan-dial-sealed \
  --dial 127.0.0.1:<bob-lan-port> \
  --expected-pub-hex <bob-user-pub-hex> \
  --envelope-b64 "$ENVELOPE_B64"
```

6. Bob: `ash --data-dir "$BOB_DATA_DIR" inbox` contains `RAVEN_A2A_OK_M3_LAB`.

RDAP submits `app_payload_b64` only. It does **not** construct ATSAM / RVNA1 ciphertext.

---

## Captured run

Executed 2026-09-07 on this branch via:

```bash
EVIDENCE_OUT=docs/engineering/baseline-freeze/artifacts/o6-m3-two-node-rdap \
  RDAP_HOME=/tmp/rdap-inspect/rdap \
  bash node/scripts/o6_m3_two_node_rdap_lab.sh
```

Toolchain: rustc/cargo **1.98.1** (1.83.0 cannot parse current `Cargo.lock` / `edition2024` crates). RDAP venv: `python3 -m virtualenv` fallback because this image has no `ensurepip` / `python3-venv`.

Public logs only (no `identity.seed` / session secrets): [`artifacts/o6-m3-two-node-rdap/`](artifacts/o6-m3-two-node-rdap/).

SRE bar markers first (GREEN / RED / BLOCKED only — no invent). Proven = **only** these lab markers that PASS with artifacts under HOLD.

| Marker | Result |
|--------|--------|
| `UNIT_OR_PIN` | **PASS** — unit selftest (`162 passed` + `RDAP_TRY_OK`) + M1 same-RVN1 public pin (`bind=same_rvn1`; no seed copy) + mutual `ash contact add` |
| `RED_NO_SESSION` | **PASS** — `rc=1` + `ATSAM_SESSION_REQUIRED` (not `ATSAM_LINEAGE_REVOKED`); RDAP task success = **none** |
| `GREEN_SEAL` | **PASS** — `./rdap seal-under-session` → `envelope_b64` unpacks `RVN1` v1 `Message` `ct_len=61` `packed_len=211` |
| `GREEN_DIAL_OR_INBOX` | **PASS** — `ash lab lan-dial-sealed` + Bob inbox `RAVEN_A2A_OK_M3_LAB` (**lab substitute**, not full `ask`) |
| `BLOCKED_ASK_ATSAM` | **BLOCKED** — `./rdap ask` over `atsam_rvn1` missing at tip `3207e8ea`; do not fake |
| `RED_DROP_SESSION` | **BLOCKED** — no public drop of the established Alice↔Bob session; Soft-load P0 held |
| `HOLD` | **ACTIVE** |
| `O6_M3_TWO_NODE_LAB` | **PASS** (lab localhost two-process path under HOLD) |
| `WALL_CLOCK_SEC` | **20** (host wall time; not a budget). Soft p50/p95 = **not recorded** (no real snapshot). |
| `BRING_UP_RETRY_COUNT` | **0** (one listen/bind retry max; still-red → FAIL) |

Detail aliases (same execute; not extra claims):

| Alias | Result |
|-------|--------|
| `UNIT_BASELINE` / `PIN_M1` / `PIN_CONTACT` | **PASS** — folded into `UNIT_OR_PIN` |
| `GREEN_LAB_SEAL` / `GREEN_LAN_DIAL` / `GREEN_INBOX` | **PASS** — folded into `GREEN_SEAL` / `GREEN_DIAL_OR_INBOX` |
| `RED_MISSING_SESSION` | **PASS** — never-paired hint → `rc=1` + `ATSAM_SESSION_REQUIRED`; RDAP task success = none |
| `RDAP_NO_LOCAL_ATSAM` | **PASS** — request keys `{op, v, peer_hint, app_payload_b64}` only |
| `RDAP_ASK_ATSAM` / `CARRIER_ENUM_ATSAM_RVN1` | **BLOCKED** |
| `TWO_DEVICE_WAN` | **BLOCKED_HARDWARE** |
| HOLD `PRODUCTION_ENABLED` tripwires | **false** (unchanged). `LAN_DIRECT_PRODUCTION_ENABLED=true` is pre-existing on `main`. |

### Pins actually executed

| Repo | `git rev-parse HEAD` |
|------|----------------------|
| RAVEN (this branch, execute tip) | `bc2fa6c4b63fd8f0019e7256b19bc85eee694269` |
| RDAP | `3207e8ea56002ff0efe0909ec9b6ec233b920c05` |

### UNIT excerpt

From [`artifacts/o6-m3-two-node-rdap/unit/selftest.stdout`](artifacts/o6-m3-two-node-rdap/unit/selftest.stdout):

```
162 passed, 0 failed
RDAP_TRY_OK
```

### RED no-session excerpt

Env: `RAVEN_IDENTITY_BACKEND=locked-file`; `ash init`; `raven-node service` (IPC UDS up); **no** PairInit / no indexed session.

stderr ([`red/cli.stderr`](artifacts/o6-m3-two-node-rdap/red/cli.stderr)):

```
NON-RELEASE / HOLD active. plaintext-to-daemon SealUnderSession only. Not O6 E2E Proven. No HOLD lift. Soft-load P0 held. Seal still requires a raven-node ATSAM session.
ATSAM_SESSION_REQUIRED: no persisted peer material for hint
```

IPC refuse token: `ATSAM_SESSION_REQUIRED`. `rc=1`. stdout empty. No `ATSAM_LINEAGE_REVOKED`.

### GREEN excerpt

Session-ensure is Raven, not RDAP: `RAVEN_LAB_TEST_A=1` + two-node `ash send --contact @bob` → `status delivered` / `carrier=lan_dial` ([`green/a.send.out`](artifacts/o6-m3-two-node-rdap/green/a.send.out)).

Topology: `localhost_two_process` Alice `127.0.0.1:18070` / Bob `127.0.0.1:18570`.

RDAP Alice sealed marker `RAVEN_A2A_OK_M3_LAB`. Decode assert: `ENVELOPE=RVN1 v1 Message ct_len=61 packed_len=211`.

Then `ash lab lan-dial-sealed` ([`green/dial.stdout`](artifacts/o6-m3-two-node-rdap/green/dial.stdout)):

```
O6_M3_LAN_DIAL_SEALED=OK replies=2
HOLD=ACTIVE
LABEL=NON-RELEASE
CLAIM=lab localhost already-sealed LanDial under HOLD
NOT_PROVEN=O6 E2E; HOLD lift; WAN; confidential RDAP delivery
```

Bob inbox ([`green/b.inbox.out`](artifacts/o6-m3-two-node-rdap/green/b.inbox.out)):

```
inbox (2)
  dcfeaaed hello from a (lab pair_init / session-ensure)
  37a71f66 RAVEN_A2A_OK_M3_LAB
```

### RED missing-session excerpt

Same Alice node, never-paired dummy hint → `rc=1` + `ATSAM_SESSION_REQUIRED` (not `ATSAM_LINEAGE_REVOKED`) ([`green/red-hint.stderr`](artifacts/o6-m3-two-node-rdap/green/red-hint.stderr)).

### `SUMMARY.txt`

SRE bar keys from this execute ([`SUMMARY.txt`](artifacts/o6-m3-two-node-rdap/SUMMARY.txt)). `scripts/o6_try_phase_gap_check.sh` stayed **RED** (`O6_TRY_PHASE=RED`, exit 1) — expected.

```
O6_M3_TWO_NODE_LAB=PASS
HOLD=ACTIVE
UNIT_OR_PIN=PASS
RED_NO_SESSION=PASS rc=1 ATSAM_SESSION_REQUIRED
GREEN_SEAL=PASS rc=0
GREEN_DIAL_OR_INBOX=PASS rc=0 marker=RAVEN_A2A_OK_M3_LAB
BLOCKED_ASK_ATSAM=BLOCKED
RED_DROP_SESSION=BLOCKED
RDAP_TASK_SUCCESS=none
WALL_CLOCK_SEC=20
BRING_UP_RETRY_COUNT=0
P50_MS=not_recorded
P95_MS=not_recorded
TWO_DEVICE_WAN=BLOCKED_HARDWARE
CLAIM=lab localhost two-process encrypted Raven↔RDAP path under HOLD
NOT_PROVEN=O6 E2E; HOLD lift; WAN; confidential production; PRODUCTION_ENABLED; HTTP A2A as O6; RDAP ask-over-atsam_rvn1; physical two-device
HARNESS_GREEN_NE_HOLD_LIFT=true
```

---

## What this does **not** do

- No O6 E2E Proven / no HOLD lift / no Release / no production enablement.
- No WAN / physical two-device claim (`BLOCKED_HARDWARE`).
- No confidential RDAP delivery Proven.
- No RDAP `ask` over `atsam_rvn1` (companion tip has no such path).
- No carrier-enum `atsam_rvn1` from RDAP status.
- No Python ATSAM / no `PRODUCTION_ENABLED` flip.
- No Python `EnqueueSealed` / `LanDial` client (RDAP `raven_ipc.py` at this tip is seal-only; dial is `ash lab lan-dial-sealed`).
- No treating Noise XX as confidentiality.
- No HTTP A2A selftest as O6 green.
- No live BLE mesh DoD / no `mock_ble` change.
- No iOS-native work.
- No duplicate M3 harness PR.
