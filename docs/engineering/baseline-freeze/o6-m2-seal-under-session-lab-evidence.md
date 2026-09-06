# O6 M2 — lab SealUnderSession execute evidence (NON-RELEASE)

**Status:** lab execute / evidence only. **Not** O6 E2E Proven. **Not** a HOLD lift.  
**ADR:** [0004 D4](../../adr/0004-raven-rdap-atsam-transport.md) — sealing ownership (M2).  
**Label:** **NON-RELEASE**. Harness green ≠ HOLD lift. HOLD still active.  
**Soft-load P0:** held. This pack does not invent revoke / soft-load plumbing.

Companion client: `Raven-ASHCO/raven-distributed-agent-protocol` `./rdap seal-under-session` / `team_agents.raven_ipc` (plaintext-to-daemon only).

---

## Claim language (normative for this pack)

| Claim | Status |
|-------|--------|
| Proven | **lab localhost IPC seal under HOLD** |
| Not Proven | **O6 E2E**, **HOLD lift**, **WAN**, **confidential RDAP delivery** |

Do **not** flip `PRODUCTION_ENABLED` tripwires. Do **not** describe this as confidential Raven messaging or production ATSAM.

Stderr footer (always, RDAP CLI):

```
NON-RELEASE / HOLD active. plaintext-to-daemon SealUnderSession only. Not O6 E2E Proven. No HOLD lift. Soft-load P0 held. Seal still requires a raven-node ATSAM session.
```

GREEN extra stderr:

```
NON-RELEASE / HOLD. Not O6 Proven. envelope_b64 is daemon-sealed; RDAP did not construct ATSAM/RVNA1 ciphertext.
```

---

## Pins

| Repo | Tip SHA | Note |
|------|---------|------|
| `Raven-ASHCO/RAVEN` | `116eb0218d0ec2a0309a2284194728ed4cf9dd6a` | `SealUnderSession` IPC (#54) |
| `Raven-ASHCO/raven-distributed-agent-protocol` | `3207e8ea56002ff0efe0909ec9b6ec233b920c05` | plaintext-to-daemon client (#11) |

Execute against those tips (or a later main that still contains them). Record the actual `git rev-parse HEAD` from the run in the captured `SUMMARY.txt`.

---

## Automated pack

```bash
# from repo root; debug ash + raven-node; no unsafe-demo-crypto
EVIDENCE_OUT=docs/engineering/baseline-freeze/artifacts/o6-m2-seal-under-session \
  RDAP_HOME=/path/to/raven-distributed-agent-protocol \
  bash node/scripts/o6_m2_seal_under_session_lab.sh
```

`RDAP_HOME` is optional: the script clones the pinned RDAP SHA when unset.

**Not wired** into `.github/workflows/raven-serverless.yml` here (same OAuth / required-check collision as M1). Agent / local executable only.

---

## Exact CLI (authoritative M2 smoke)

```bash
./rdap seal-under-session \
  --peer-hint <64-hex-device-Ed25519> \
  --payload-b64 aGVsbG8= \
  --data-dir "$RAVEN_DATA_DIR"
```

`peer_hint` = 64 hex **device** Ed25519 (ash LanDial / `lab export-cert` `device_ed_pub` plane).  
IPC: `<data-dir>/raven-node.sock` or `\\.\pipe\raven-node`.

RDAP submits `app_payload_b64` only. It does **not** construct ATSAM / RVNA1 ciphertext.

---

## Matrix

### 0) UNIT (caller-only, mocked — baseline)

```bash
.venv/bin/python -m team_agents.selftest --unit
# expect 162 passed + RDAP_TRY_OK
```

### 1) RED — no session (ready today)

raven-node up, identity present, **no** persisted ATSAM session:

```bash
./rdap seal-under-session \
  --peer-hint "$(printf 'ab%.0s' {1..32})" \
  --payload-b64 aGVsbG8= \
  --data-dir "$RAVEN_DATA_DIR"
```

Expect: nonzero + `ATSAM_SESSION_REQUIRED`. Must **not** collapse with `ATSAM_LINEAGE_REVOKED`.

### 2) GREEN — lab session present

Crypto / Node establishes the persisted indexed ATSAM session the same way LAN/lab already does:

- debug build
- `RAVEN_LAB_TEST_A=1`
- `ash init` + `prekey publish` + two `raven-node service` + mutual `contact add` + `ash send --contact`

RDAP has **no** session-ensure. Then the seal CLI with `peer_hint` from that session (`ash lab export-cert` → `device_ed_pub`).

Expect: stdout `{"envelope_b64": "…"}` that decodes to packed `RavenEnvelopeV1` (`RVN1` magic, `EnvType::Message`, nonempty `message_ciphertext`).

### 3) RED — revoked lineage

If feasible with **existing** Identity loaders (`ash device revoke --device-id ash-primary`, `RevocationStore::load_checked`) without inventing soft-load fixes: expect `ATSAM_LINEAGE_REVOKED` distinct from `ATSAM_SESSION_REQUIRED`.

Else: honest **BLOCKED** (Soft-load P0 / missing fixtures). Do not invent revoke plumbing.

---

## Captured run

Executed 2026-09-06 on this branch via:

```bash
EVIDENCE_OUT=docs/engineering/baseline-freeze/artifacts/o6-m2-seal-under-session \
  RDAP_HOME=/tmp/rdap \
  bash node/scripts/o6_m2_seal_under_session_lab.sh
```

Public logs only (no `identity.seed` / session secrets): [`artifacts/o6-m2-seal-under-session/`](artifacts/o6-m2-seal-under-session/).

| Marker | Result |
|--------|--------|
| `UNIT_BASELINE` | **PASS** — `162 passed, 0 failed` + `RDAP_TRY_OK` (`rc=0`) |
| `RED_NO_SESSION` | **PASS** — `rc=1` + `ATSAM_SESSION_REQUIRED` (not `ATSAM_LINEAGE_REVOKED`) |
| `GREEN_LAB_SEAL` | **PASS** — `rc=0` + `envelope_b64` unpacks `RVN1` v1 `Message` `ct_len=47` `packed_len=197` |
| `RED_REVOKE` | **BLOCKED** — `ash device revoke` applied (`ok revoked ash-primary`); live IPC returned `DEVICE_REVOKED` (nonzero, distinct from `ATSAM_SESSION_REQUIRED`) but **not** frozen `ATSAM_LINEAGE_REVOKED`. No invented mapping. Soft-load P0 held. |
| `RDAP_NO_LOCAL_ATSAM` | **PASS** — request keys `{op, v, peer_hint, app_payload_b64}` only |
| `O6_M2_SEAL_LAB` | **PASS** (lab localhost IPC seal under HOLD) |
| `HOLD` | **ACTIVE** (unchanged) |
| HOLD `PRODUCTION_ENABLED` tripwires | **false** (unchanged). `LAN_DIRECT_PRODUCTION_ENABLED=true` is pre-existing on `main` (`lan_gate.rs`); this pack did not flip it. |

### Pins actually executed

| Repo | `git rev-parse HEAD` |
|------|----------------------|
| RAVEN (this branch, based on #54) | `1b662b4d0c6a59a8c73c36409ad769f652b73f4e` (parent `116eb021`) |
| RDAP | `3207e8ea56002ff0efe0909ec9b6ec233b920c05` |

### UNIT excerpt

From [`artifacts/o6-m2-seal-under-session/unit/selftest.stdout`](artifacts/o6-m2-seal-under-session/unit/selftest.stdout):

```
162 passed, 0 failed
RDAP_TRY_OK
```

### RED no-session excerpt

Env: `RAVEN_IDENTITY_BACKEND=locked-file`; `ash init`; `raven-node service` (IPC UDS up); **no** PairInit / no indexed session.

```
CMD: ./rdap seal-under-session --peer-hint "$(printf 'ab%.0s' {1..32})" --payload-b64 aGVsbG8= --data-dir $RAVEN_DATA_DIR
```

stderr ([`red/cli.stderr`](artifacts/o6-m2-seal-under-session/red/cli.stderr)):

```
NON-RELEASE / HOLD active. plaintext-to-daemon SealUnderSession only. Not O6 E2E Proven. No HOLD lift. Soft-load P0 held. Seal still requires a raven-node ATSAM session.
ATSAM_SESSION_REQUIRED: no persisted peer material for hint
```

IPC refuse token: `ATSAM_SESSION_REQUIRED`. `rc=1`. stdout empty. No `ATSAM_LINEAGE_REVOKED`.

Daemon ([`red/node.log`](artifacts/o6-m2-seal-under-session/red/node.log)): `raven-node ipc: listening …/raven-node.sock` + `lan_direct: listen`.

### GREEN excerpt

Session-ensure is Raven, not RDAP: `RAVEN_LAB_TEST_A=1` + two-node `ash send --contact @bob` → `status delivered` / `carrier=lan_dial` / `PairResponse confirmed` ([`green/a.send.out`](artifacts/o6-m2-seal-under-session/green/a.send.out)).

`peer_hint` from `ash lab export-cert` on B: `8703511b1d03279a3d98c6f94cd9df1b541b2815a620fc1a0dc0e5752c471dfb` (device Ed25519).

```
CMD: ./rdap seal-under-session --peer-hint $PEER_HINT --payload-b64 aGVsbG8= --data-dir $A
```

stdout ([`green/cli.stdout`](artifacts/o6-m2-seal-under-session/green/cli.stdout)): `{"envelope_b64": "UlZOMQEB…"}` (base64 prefix `UlZOMQ` = `RVN1`). Decode assert: `ENVELOPE=RVN1 v1 Message ct_len=47 packed_len=197`.

stderr ([`green/cli.stderr`](artifacts/o6-m2-seal-under-session/green/cli.stderr)):

```
NON-RELEASE / HOLD active. plaintext-to-daemon SealUnderSession only. Not O6 E2E Proven. No HOLD lift. Soft-load P0 held. Seal still requires a raven-node ATSAM session.
NON-RELEASE / HOLD. Not O6 Proven. envelope_b64 is daemon-sealed; RDAP did not construct ATSAM/RVNA1 ciphertext.
```

### RED revoke excerpt (BLOCKED)

Existing Identity loader only:

```
ash --data-dir $A device revoke --device-id ash-primary --epoch 1
```

→ `ok revoked ash-primary` ([`green/revoke.out`](artifacts/o6-m2-seal-under-session/green/revoke.out)).

Then the same GREEN seal CLI returned `rc=1`:

```
NON-RELEASE / HOLD active. plaintext-to-daemon SealUnderSession only. Not O6 E2E Proven. No HOLD lift. Soft-load P0 held. Seal still requires a raven-node ATSAM session.
DEVICE_REVOKED
```

Distinct from `ATSAM_SESSION_REQUIRED`. **Not** the frozen `ATSAM_LINEAGE_REVOKED` token required by this matrix. Honest **BLOCKED** (Soft-load P0 / G5 IPC-string freeze vs operator-revoke `DEVICE_REVOKED`). No invented mapping or extra revoke plumbing.

### `SUMMARY.txt`

```
O6_M2_SEAL_LAB=PASS
HOLD=ACTIVE
LABEL=NON-RELEASE
UNIT_BASELINE=PASS rc=0 162 passed RDAP_TRY_OK
RED_NO_SESSION=PASS rc=1 ATSAM_SESSION_REQUIRED
GREEN_LAB_SEAL=PASS rc=0
RED_REVOKE=BLOCKED
RDAP_NO_LOCAL_ATSAM=PASS
CLAIM=lab localhost IPC seal under HOLD
NOT_PROVEN=O6 E2E; HOLD lift; WAN; confidential RDAP delivery
```

---

## What this does **not** do

- No O6 E2E / two-device RDAP `ask` harness (M3).
- No HOLD lift / Release / production enablement.
- No WAN / confidential RDAP delivery claim.
- No Python ATSAM.
- No `PRODUCTION_ENABLED` flip.
- No new crypto.
