# O6 M3 — two-process localhost Raven↔RDAP lab (NON-RELEASE)

**Status:** lab execute / evidence only. **Not** O6 E2E Proven. **Not** a HOLD lift.  
**ADR:** [0004 D5](../../adr/0004-raven-rdap-atsam-transport.md) — harness acceptance (M3). This pack is the **smallest honest lab substitute** (two logical devices on `127.0.0.1`).  
**Label:** **NON-RELEASE**. Harness green ≠ HOLD lift. HOLD still active.  
**Topology:** localhost two-process (`raven-node` Alice + Bob). **dial≠WAN.**  
**Hardware:** `TWO_DEVICE_WAN=BLOCKED_HARDWARE` (no second physical device / WAN peer on this runner).

Companion client invocation against RDAP tip `3207e8ea56002ff0efe0909ec9b6ec233b920c05` (`./rdap seal-under-session` / `team_agents.raven_ipc`). **No RDAP code change** in this pack — the tip still has no `ask` over `atsam_rvn1`.

---

## Claim language (normative for this pack)

| Claim | Status |
|-------|--------|
| Proven | **lab localhost two-process encrypted Raven↔RDAP path under HOLD** |
| Not Proven | **O6 E2E**, **HOLD lift**, **WAN**, **confidential RDAP delivery**, **RDAP ask-over-atsam_rvn1**, **physical two-device** |

Do **not** flip `PRODUCTION_ENABLED` tripwires. Do **not** describe this as confidential Raven messaging or production ATSAM. `mock_ble` remains the mesh claim on `main` (this pack does not touch BLE).

Stderr banner (harness):

```
NON-RELEASE / HOLD active. two-process localhost Raven↔RDAP lab only. Not O6 E2E Proven. No HOLD lift. dial≠WAN. Soft-load P0 held. PRODUCTION_ENABLED unchanged. mock_ble untouched.
```

---

## Honesty matrix (D5 vs this lab)

| D5 acceptance item | This pack |
|--------------------|-----------|
| Two devices (physical or VM), each with `raven-node` + RDAP | **Lab substitute:** two `raven-node` processes + RDAP seal CLI on Alice. Physical / WAN = `BLOCKED_HARDWARE`. |
| Mutual pin of the same RVN1 / device bindings (D3) | **PASS (lab):** mutual `ash contact add` + M1 public pin files via `scripts/o6_m1_same_rvn1_bind.sh`. |
| Alice `ask` → Bob completes (`RAVEN_A2A_OK_*`) | **Partial / not Proven:** marker `RAVEN_A2A_OK_M3_LAB` is sealed by RDAP and opened in Bob's ash inbox. RDAP `ask` at this tip remains **signed HTTP** (`http_signed`). `RDAP_ASK_ATSAM=BLOCKED`. |
| Data-plane frames ATSAM-sealed + drop-session refuse | **PASS (lab):** daemon `RavenEnvelopeV1` + RED `ATSAM_SESSION_REQUIRED` on missing session / never-paired hint. |
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

Expected codes:

| Marker | Expect |
|--------|--------|
| `O6_M3_TWO_NODE_LAB` | `PASS` (lab only) and process exit **0** |
| `RED_NO_SESSION` | nonzero RDAP CLI + `ATSAM_SESSION_REQUIRED` |
| `GREEN_LAB_SEAL` / `GREEN_LAN_DIAL` / `GREEN_INBOX` | `PASS` |
| `TWO_DEVICE_WAN` | `BLOCKED_HARDWARE` |
| `RDAP_ASK_ATSAM` | `BLOCKED` |
| `HOLD` | `ACTIVE` |
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

See [`artifacts/o6-m3-two-node-rdap/`](artifacts/o6-m3-two-node-rdap/) after execute. Public logs only (no `identity.seed` / session secrets).

Until that directory is filled, treat the pack as **code + contract only** — docs-only ≠ Proven.

---

## What this does **not** do

- No O6 E2E Proven / no HOLD lift / no Release / no production enablement.
- No WAN / physical two-device claim (`BLOCKED_HARDWARE`).
- No confidential RDAP delivery Proven.
- No RDAP `ask` over `atsam_rvn1` (companion tip has no such path).
- No carrier-enum `atsam_rvn1` from RDAP status.
- No Python ATSAM / no `PRODUCTION_ENABLED` flip.
- No live BLE mesh DoD / no `mock_ble` change.
- No iOS-native work.
