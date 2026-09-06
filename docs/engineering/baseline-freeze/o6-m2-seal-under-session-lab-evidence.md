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

Filled after `node/scripts/o6_m2_seal_under_session_lab.sh` exits 0. Logs live under [`artifacts/o6-m2-seal-under-session/`](artifacts/o6-m2-seal-under-session/) when `EVIDENCE_OUT` is set.

| Marker | Result |
|--------|--------|
| `UNIT_BASELINE` | *(pending execute)* |
| `RED_NO_SESSION` | *(pending execute)* |
| `GREEN_LAB_SEAL` | *(pending execute)* |
| `RED_REVOKE` | *(pending execute)* |
| `RDAP_NO_LOCAL_ATSAM` | *(pending execute)* |
| `HOLD` | **ACTIVE** (must stay) |
| `PRODUCTION_ENABLED` | **false** (must stay) |

---

## What this does **not** do

- No O6 E2E / two-device RDAP `ask` harness (M3).
- No HOLD lift / Release / production enablement.
- No WAN / confidential RDAP delivery claim.
- No Python ATSAM.
- No `PRODUCTION_ENABLED` flip.
- No new crypto.
