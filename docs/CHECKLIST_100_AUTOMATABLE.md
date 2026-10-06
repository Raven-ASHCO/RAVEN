# Checklist — 100% of automatable rows (2026-08-12)

> **Status note (2026-10-05):** the "100%" below is the 2026-08-12 claim and is **withdrawn pending a
> fresh enforced run** of `scripts/reliability_matrix_20.sh` and `scripts/final_serverless_proof.sh`
> (the runs it rested on are INVALIDATED, see the evidence pack). RVN1 messaging is under a production
> **HOLD** with no external review: see [`THREAT_MODEL.md`](THREAT_MODEL.md),
> [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md) and
> connectivity matrix §0 ([`network/raven-swarm-connectivity-matrix.md`](network/raven-swarm-connectivity-matrix.md)).

**Branch (historical):** authored on `feature/raven-serverless-v1`; this file now lives on `main` and is a dated snapshot, not a statement about an open branch  
**Definition:** Every row that can be proven without hired auditors, Apple notarization, Windows Authenticode, or physical BLE/CGNAT radios is **PASS** or **PASS_SOFTWARE_SUBSTITUTE**.  
**Absolute marketing DoD (§60)** remains **not** claimed — see physical-only table.

## Automatable coverage: **100%** *(claimed 2026-08-12; withdrawn pending a fresh enforced run — see status note)*

| Bucket | Count | Status |
|--------|------:|--------|
| Automatable software rows (§1–59 software claims) | 100% (claimed 2026-08-12) | **Pending fresh enforced run** (reliability matrix and §59 harness evidence below are INVALIDATED) |
| Absolute DoD including human + hardware | <100% | Physical/human leftovers listed |

### Primary evidence pack

| Proof | Result | Artifact |
|-------|--------|----------|
| Reliability matrix 20× | **INVALIDATED** — runs before the 2026-09-29 harness fix were false-green (scenario status was its last command, usually `rm -rf`; bridged sends used the refused `atsam` mode). Re-run: `scripts/reliability_matrix_20.sh` now enforces every assertion | `node/proof_artifacts/LATEST_RELIABILITY` (local, gitignored) |
| §59 harness | **INVALIDATED** — runs before the 2026-09-29 harness fix counted only each step's last command. Re-run `scripts/final_serverless_proof.sh` (16 enforced steps, lab build; also a CI job) | `node/proof_artifacts/LATEST` |
| Docker NAT substitute | **PASS** via Lima dockerd | `scripts/nat_docker_sim.sh` → `nat_docker_*` |
| Linux runtime | musl `ash --help` in Lima VM | `limactl shell ash-amd64-preflight` |
| Windows | PE32+ self-check (`ash.exe`) | `PASS_SOFTWARE_SUBSTITUTE` (wine needs sudo/gstreamer) |
| iOS iPhone sim | Discovery + ContactRequest + RavenEnvelope* | `RAVEN-iPhone-15` ×2 **TEST SUCCEEDED** — **OFF-MAIN** (`ios-native` is not in this repository; not reproducible from this tree) |
| iOS iPad sim | Same suite | `iPad Air 11-inch (M4)` ×2 **TEST SUCCEEDED** — **OFF-MAIN** (same caveat) |
| macOS native | ash/raven-node demos + Keychain identity_store | primary desktop |

### Status doc mapping

See `docs/MASTER_CHECKLIST_STATUS.md` and `docs/MASTER_CHECKLIST_WALK_IN_PROGRESS.md`.  
Automatable IN_PROGRESS debt was marked closed to **PASS / PASS (software)** where a software substitute exists (2026-08-12); §28 is HOLD and §50/§59 are IN_PROGRESS pending a fresh enforced run. Remaining **BLOCKED_*** are physical/human only.

## Physical-only / human-only (absolute DoD leftovers)

| Item | Why not automatable | Runbook |
|------|---------------------|---------|
| Physical 3-phone BLE mesh | Real radios | `docs/PHYSICAL_BLE_THREE_DEVICE.md` |
| Live CGNAT / DCUtR | Public multi-NAT | `docs/NAT_SOFTWARE_SIM.md` (Docker = substitute only) |
| Headless CoreBluetooth GATT on desktop | Hardware radio | mock_ble software path used in CI |
| Apple notarization / Developer ID | Human + Apple account | `docs/SIGNING_NOTARIZATION_CHECKLIST.md` |
| Windows Authenticode / MSI | Human + cert | `docs/INSTALL_Windows.md` |
| External crypto/protocol freeze review | Hired auditor | `docs/EXTERNAL_REVIEW_PACKET.md` |
| Live secret rotation decisions | Operator | `scripts/secret_history_scan.sh` |
| Public Internet Kad DHT soak | Long-lived network | DiscoveryResolver + local Kad smoke only |

## How to re-verify

```bash
# Reliability matrix (≥20 successful cycles)
DOCKER_HOST=unix://$HOME/.lima/ash-amd64-preflight/sock/docker.sock \
  bash scripts/reliability_matrix_20.sh

# NAT substitute (start lima first: limactl start ash-amd64-preflight)
bash scripts/nat_docker_sim.sh

# §59 harness
bash scripts/final_serverless_proof.sh
```
