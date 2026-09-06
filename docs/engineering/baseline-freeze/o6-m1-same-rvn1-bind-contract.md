# O6 M1 — same-RVN1 public bind contract (NON-RELEASE)

**Status:** M1-in-progress lab/harness only. **Not** O6 Proven. **Not** a HOLD lift.  
**ADR:** [0004 D3](../../adr/0004-raven-rdap-atsam-transport.md) — Identity binding for M1 (no soft parallel identity).  
**Label:** **NON-RELEASE**. Harness green ≠ HOLD lift. HOLD still active.

This is the RAVEN-side bind contract for RDAP `.team/keys` to consume the **same RVN1** already owned by the local `raven-node` data dir (`~/.raven` or `--data-dir`). It does **not** claim confidential delivery, `atsam_rvn1` send, daemon-seal, or two-device E2E.

---

## Source of truth

| Side | Store | What M1 may export |
|------|--------|--------------------|
| `raven-node` / `ash` | data dir identity (Identity V1: user identity → `rvn1…`) | **Public** whoami only: address + `pub_hex` + ash-style fingerprint |
| RDAP (companion) | today: `.team/keys/device_ed25519.seed` via `RavenIdentity.load_or_create` | **Must not** mint a second keypair that merely prints a similar address |

Private keys stay in the node identity store (ADR 0003 / `ipc.rs`). **Private keys MUST NOT appear in IPC JSON.**

Status IPC remains policy/capabilities only. Public whoami is the existing `ash whoami` surface (optional `--json`). No new `IpcRequest::Whoami`. No seal IPC.

---

## Export (this repo)

```bash
ash --data-dir "$DATA" init          # creates the node identity if missing
ash --data-dir "$DATA" whoami --json # public card only
```

`--json` shape (exactly these three keys):

```json
{"address":"rvn1…","fingerprint":"XXXX-XXXX-XXXX","pub_hex":"<64 hex>"}
```

`address` MUST equal Identity V1 encode of `pub_hex` (`SHA-256(ed_pub)[:20]` + bech32m `rvn`). That `ed_pub` is the **user identity** key that derives the RVN1 — **not** a device-only key and **not** `device_ed_pub`. Fingerprint MUST equal `device_fingerprint_v1` of that same identity pub (ash-style contact pin). **Pin ≢ `device_ed_pub`** (G5 SoT / ADR 0004 Appendix G5).

---

## Bind path for RDAP `.team/keys`

RDAP MUST consume that **public** card as an ash-style **pin of the same RVN1** — not a newly invented RDAP-only keypair under `.team/keys`.

This repo ships a stub that proves the contract without cloning RDAP / adding `team_agents/`:

```bash
scripts/o6_m1_same_rvn1_bind.sh --rdap-home "$RDAP_HOME" --whoami-json "$CARD"
```

Writes (public pin only; mode `0644` on the pin, directory `0700`):

| File | Role |
|------|------|
| `$RDAP_HOME/.team/keys/o6_m1_same_rvn1.pin` | `address=` / `pub_hex=` / `fingerprint=` + NON-RELEASE labels |
| `$RDAP_HOME/.team/keys/o6_m1_same_rvn1.json` | Same card + `schema=o6_m1_same_rvn1_pin_v1` |

**Must refuse (fail-closed):**

1. Missing / unusable node identity (`ash whoami --json` → `no_identity`).
2. Address / `pub_hex` mismatch (derived RVN1 ≠ exported address).
3. Parallel private key: existing `$RDAP_HOME/.team/keys/device_ed25519.seed` (RDAP `load_or_create` seed). M1 must not treat that seed as “the same RVN1.”
4. Existing pin file whose `address` differs from the node whoami (second pin namespace).
5. Any whoami / pin / IPC JSON containing `seed` / `private_key` / `plaintext` / `recovery`.

The helper **never** writes `device_ed25519.seed` or copies `identity.seed`.

---

## What this does **not** do

- No IPC-mediated signing (follow-up if RDAP HTTP control plane must sign *as* the node identity without holding the seed).
- No daemon-seal / `EnqueueSealed` / `LanDial` as O6 confidentiality.
- No Python ATSAM / no `atsam_rvn1` send claim.
- No distinct `USER_AGENT_DEVICE` (documented follow-on after M2).
- No second pin namespace / soft parallel trust root beside the node contact plane.
- No soft-load P0 (OPEN-ID-P0 stays held; out of this PR).
- No HOLD lift / Release / production enablement.

---

## RDAP companion follow-up (not this repo)

`team_agents/` is forbidden here. Checklist for `Raven-ASHCO/raven-distributed-agent-protocol`:

1. Do **not** call `RavenIdentity.load_or_create` for the O6 harness when a same-RVN1 pin is present — that mints `device_ed25519.seed` and is a parallel identity.
2. Import `$RDAP_HOME/.team/keys/o6_m1_same_rvn1.json` (or `ash whoami --json`) via existing `validate_address_public_key` + `fingerprint_for_public_key`.
3. Trust / invite MUST pin that exact `rvn1…` (ash contact plane). No second `trusted_peers` root.
4. Keep “Important integration gap” until M3. Pointer to RAVEN ADR 0004 is OK; do not claim the encrypted carrier exists.
5. If HTTP signed control plane must speak *as* the node RVN1, that is IPC-mediated signing (Identity + Node IPC) — **not** seed export. Out of this M1 slice.
6. M2 daemon-seal + M3 two-device harness remain gated. HOLD remains active.
