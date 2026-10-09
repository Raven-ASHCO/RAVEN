# Final Serverless Proof (§59) — automated harness

> **Status banner (2026-10-05):** RVN1 messaging is under a production **HOLD** with no external
> review — see [`THREAT_MODEL.md`](THREAT_MODEL.md),
> [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md)
> and connectivity matrix §0 ([`network/raven-swarm-connectivity-matrix.md`](network/raven-swarm-connectivity-matrix.md)).
> Harness results are lab evidence only (`unsafe-demo-crypto` interim cipher) and never lift the HOLD.
> The harness was fixed on 2026-09-29; earlier green runs are INVALIDATED and **a fresh enforced run
> is pending**.

## What this is

`scripts/final_serverless_proof.sh` exercises every **software-automatable** step of the Master Checklist §59 Final Serverless Proof on a developer machine:

| §59 intent | How the harness covers it |
|---|---|
| Fresh install / identity | Ephemeral data-dirs + `ash init` / `whoami` |
| Contact add + verify | `ash contact add --verify-fp` + `contact verify` |
| Offline recipient | Bridge store-carry while mobile offline, then join |
| Encrypted locally / queue | Sealed send; bridge logs **and** bridge data-dir state must not contain the plaintext marker (lab `unsafe-interim` cipher — shows the bridge does not record plaintext, not that it cannot derive the key) |
| No central API | `doctor` messaging_path + grep refuse FastAPI |
| Store-forward | Bridge B queues until C appears |
| Close Terminal; node continues | `raven-node service` + `ash ipc-ping` after ash exit |
| ACK / Delivered | Direct + bridged ACK logs |
| Bridge A↔B↔C both ways | `bridge_abc_demo.sh` (happy + reverse + store-carry) |
| No duplicates | `cargo test -p raven-core --test bridge_v1` |
| Shut Raven bootstrap; manual peers | `disable-raven-defaults` + `bootstrap_manual_peer_smoke` + swarm |
| Same message identity | mid logged across A/B/C in bridge demo |

## Run

```bash
bash scripts/final_serverless_proof.sh              # exits 0 only when every step passes
bash scripts/final_serverless_proof.sh --self-test  # harness self-test only (no build)
# artifacts → node/proof_artifacts/<run-id>/  (steps/<step>.log holds each step's full output)
cat node/proof_artifacts/LATEST/SUMMARY.md
```

Every command and assertion inside a step is enforced: step bodies run through
`run_isolated` (`scripts/lib/proof_assert.sh`) with errexit really in effect, and
negative checks exit explicitly. Runs before 2026-09-29 used
`( ... ) && step_ok || step_fail`, which only counted each step's **last**
command — their `AUTOMATED_PROOF_GREEN` results are not evidence. The harness
also runs in CI (job **Final serverless proof (lab harness)**).

It is a **lab** harness: it builds `--features raven-node/unsafe-demo-crypto`
and bridged sends use `--body-mode unsafe-interim`.

## Claim language (honest)

Harness fixed 2026-09-29; a fresh enforced run is pending (no such run is recorded in this tree).
When a fresh run is green, the script prints:

> **IMPLEMENTATION + PROOF HARNESS COMPLETE** for automatable §59 software steps.

That is a statement about a **lab** harness, not a security or release claim, and it does not lift
the RVN1 production HOLD. Still **not** marketing READY / full §59 DoD. See each run’s `BLOCKED.md`.

## Related

- Physical 3-device BLE: `docs/PHYSICAL_BLE_THREE_DEVICE.md`
- NAT substitutes: `docs/NAT_SOFTWARE_SIM.md` + `scripts/nat_docker_sim.sh`
- External review handoff: `docs/EXTERNAL_REVIEW_PACKET.md`
