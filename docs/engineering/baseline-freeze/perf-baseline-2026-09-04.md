# Performance baseline harvest — 2026-09-04

**Date:** 2026-09-04  
**Owner:** Role #19 SRE Perf  
**Repo:** [Raven-ASHCO/RAVEN](https://github.com/Raven-ASHCO/RAVEN)  
**Status:** first harvest of existing gates/sims. Soft latency budgets remain **DRAFT** (no numeric soft caps). This file does not enforce soft budgets.

**FOUNDER RULE — Try phase = execute.** Harvest numbers only from runs we actually trigger, **or** cite exact GitHub Actions run IDs. Soft budgets only after real snapshots land. **Never invent or estimate metrics.** This file is the precedent ([PR #14](https://github.com/Raven-ASHCO/RAVEN/pull/14)): numbers below come from a triggered `./scripts/harvest_perf_baseline.sh` / `cargo test` run on a recorded host, plus cited in-tree constants. Soft budgets stay **draft**.

Numbers below are copied from real `--nocapture` stdout or from cited source constants. Missing values are **NOT MEASURED**. Nothing here is estimated or placeholder-faked.

Eng Program: update [`sprint0-checklist.md`](sprint0-checklist.md) so the **Performance baseline** row lists owner **#19** and records this harvest as evidence. That checklist still shows `#11` / `NOT STARTED` as of this write. [`org-structure.md`](org-structure.md) currently titles #19 as Release Engineering Lead and #11 as Performance Owner — reconcile titles there; this harvest follows the Sprint 0 assignment (Role #19 SRE Perf).

---

## How harvested

Helper: [`node/scripts/harvest_perf_baseline.sh`](../../../node/scripts/harvest_perf_baseline.sh).

From `node/`:

```sh
RAVEN_PERF_RELEASE=1 RAVEN_RELIABILITY_10K=1 RAVEN_RELIABILITY_10K_RUNS=3 \
  ./scripts/harvest_perf_baseline.sh
```

Equivalent cargo commands (also what the script runs):

```sh
cargo test -p raven-core --test network_sim_1000 -- --nocapture
cargo test --release -p raven-core --test network_sim_1000 -- --nocapture
cargo test -p raven-core --test reliability_10k -- --nocapture --ignored
```

The last command was repeated three times on this host.

| Item | Value |
|------|--------|
| Host | Linux 6.12.94+ x86_64, hostname `cursor`, `nproc=4` |
| Successful toolchain | rustc 1.98.1 (48a229cea 2026-09-01), cargo 1.98.1 (797e8a9bc 2026-08-05) |
| First attempt | rustc/cargo **1.83.0** — all five requested gates failed before compile: crates.io `kem v0.3.0` requires `edition2024` |
| Successful artifact | [`artifacts/20260904T111355Z-2345/`](artifacts/20260904T111355Z-2345/) (`verdict=HARVEST_OK`, 5/5) |
| Failed artifact | [`artifacts/20260904T111245Z-2038/`](artifacts/20260904T111245Z-2038/) (`verdict=HARVEST_FAILED`, rustc 1.83.0) |
| Debug vs release sim | Both **passed**. Printed `network_sim_1000 scenario=...` fields were **identical** across profiles (deterministic virtual-time model). Cargo harness wall times differed (`finished in 0.50s` debug, `0.02s` release) and are **not** a baseline metric — see gaps. |

The harvest script streams cargo stdout and writes timestamped files under `docs/engineering/baseline-freeze/artifacts/`. It exits non-zero if any requested test fails and never prints `HARVEST_OK` in that case.

---

## Proposed metric set

| Metric | Harvest source | This date |
|--------|----------------|-----------|
| **DeliverySuccess** | `network_sim_1000` printed `ui=` / `ack_materialized=` / `ack_transition=` | **Measured.** Every scheduled-path scenario printed `ui=1 ack_materialized=1 ack_transition=1`. `ttl_expiry` printed `ui=0 ack_materialized=0 ack_transition=0` (no valid recipient path; asserted). |
| **PeakQueueDepth** | printed `peak_event=`, `peak_node_queue=`, `peak_total_queue=` | **Measured.** Observed maxima across printed lines: `peak_event=640` (`half_node_loss`), `peak_node_queue=8` (`bounded_queue_pressure`), `peak_total_queue=42` (`half_node_loss`). Per-scenario values in the report dump below. |
| **RelayAmplification** | printed `transfers=`, `accepted=`, `duplicates=` | **Measured as those three fields only.** No amplification ratio is printed; none is computed here. |
| **AdmissionPressure** | printed `peak_node_queue=` / `mutations_rejected=` on `bounded_queue_pressure`; `local_admission_rejections` is **not** in `print_report` | **Partial.** Printed: `peak_node_queue=8 peak_node_seen=8 mutations_rejected=3`. Rejection **count** = **NOT MEASURED** (not printed). Code asserts `local_admission_rejections >= 57` — **INVARIANT-ONLY**. |
| **LogicalMemory** | printed `peak_queue_bytes=`, `peak_inflight_bytes=` | **Measured.** Observed maxima across printed lines: `peak_queue_bytes=21084` (`half_node_loss`), `peak_inflight_bytes=5680` (`bounded_queue_pressure`). |
| **Queue10kWall** | `reliability_10k ok in ...` (debug test profile) | **Measured** (three host wall times): `20.753959149s`, `20.150360064s`, `21.344168403s`. |
| **LanPathSuccess** | live LAN smokes (`lan_path_smoke.sh`, `lan_direct_two_node.sh`) | **NOT MEASURED** on this harvest. Those scripts were not run. No in-repo numeric snapshot found. |
| **Recovery** | `restart_reconstruction`, `partition_then_heal` report lines | **Measured.** `restart_reconstruction`: `restarts=2 ui=1 ack_transition=1`. `partition_then_heal`: `ui=1 ack_transition=1`. `reconstructed_replicas` is asserted (`>= 2`) but **not printed** — **INVARIANT-ONLY** for that field. |
| **Reconnect/Churn** | `half_node_loss` printed `peak_offline=`; availability-change count | **Partial.** Printed `peak_offline=500`. `availability_changes == 600` is asserted in the test and **not printed** — **INVARIANT-ONLY**. |

---

## `network_sim_1000 scenario=...` report lines

Copied from the successful **debug** harvest (`artifacts/20260904T111355Z-2345/network_sim_1000.debug.stdout.txt`). The **release** harvest printed the same field values. Cargo ran 13 tests; `loss_latency_reordering` prints once per seed (the reproducibility test prints seed `268435458` twice with identical fields).

```
network_sim_1000 scenario=two_transport_bridge seed=268435474 events=15/15 contacts=6 attempts=9 transfers=9 accepted=6 duplicates=3 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=6 peak_node_queue=2 peak_node_seen=2 peak_total_queue=8 peak_queue_bytes=4016 peak_inflight_bytes=1004 peak_offline=0
network_sim_1000 scenario=connected_baseline seed=268435457 events=44/44 contacts=20 attempts=24 transfers=24 accepted=20 duplicates=4 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=20 peak_node_queue=2 peak_node_seen=2 peak_total_queue=22 peak_queue_bytes=11044 peak_inflight_bytes=1004 peak_offline=0
network_sim_1000 scenario=bounded_queue_pressure seed=268435473 events=29/29 contacts=5 attempts=24 transfers=24 accepted=12 duplicates=10 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=3 restarts=0 peak_event=9 peak_node_queue=8 peak_node_seen=8 peak_total_queue=21 peak_queue_bytes=14078 peak_inflight_bytes=5680 peak_offline=0
network_sim_1000 scenario=malicious_relays seed=268435465 events=71/71 contacts=17 attempts=54 transfers=54 accepted=29 duplicates=25 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=2 restarts=0 peak_event=20 peak_node_queue=5 peak_node_seen=5 peak_total_queue=32 peak_queue_bytes=15232 peak_inflight_bytes=5020 peak_offline=0
network_sim_1000 scenario=duplicate_multipath_storm seed=268435462 events=60/60 contacts=28 attempts=32 transfers=32 accepted=10 duplicates=22 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=30 peak_node_queue=2 peak_node_seen=2 peak_total_queue=12 peak_queue_bytes=6024 peak_inflight_bytes=4016 peak_offline=0
network_sim_1000 scenario=partition_then_heal seed=268435460 events=25/25 contacts=12 attempts=11 transfers=11 accepted=8 duplicates=3 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=14 peak_node_queue=2 peak_node_seen=2 peak_total_queue=10 peak_queue_bytes=5020 peak_inflight_bytes=1004 peak_offline=0
network_sim_1000 scenario=half_node_loss seed=268435459 events=684/684 contacts=40 attempts=44 transfers=44 accepted=40 duplicates=4 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=640 peak_node_queue=2 peak_node_seen=2 peak_total_queue=42 peak_queue_bytes=21084 peak_inflight_bytes=1004 peak_offline=500
network_sim_1000 scenario=out_of_order seed=268435463 events=14/14 contacts=3 attempts=11 transfers=11 accepted=2 duplicates=9 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=7 peak_node_queue=2 peak_node_seen=2 peak_total_queue=4 peak_queue_bytes=2008 peak_inflight_bytes=4260 peak_offline=0
network_sim_1000 scenario=restart_reconstruction seed=268435464 events=12/12 contacts=4 attempts=6 transfers=6 accepted=4 duplicates=2 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=2 peak_event=6 peak_node_queue=2 peak_node_seen=2 peak_total_queue=6 peak_queue_bytes=3012 peak_inflight_bytes=1004 peak_offline=0
network_sim_1000 scenario=non_simultaneous_online seed=268435461 events=14/14 contacts=4 attempts=6 transfers=6 accepted=4 duplicates=2 packet_loss=0 contact_loss=0 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=8 peak_node_queue=2 peak_node_seen=2 peak_total_queue=6 peak_queue_bytes=3012 peak_inflight_bytes=1004 peak_offline=2
network_sim_1000 scenario=ttl_expiry seed=268435472 events=19/19 contacts=9 attempts=9 transfers=9 accepted=9 duplicates=0 packet_loss=0 contact_loss=0 ui=0 ack_materialized=0 ack_transition=0 mutations_rejected=0 restarts=0 peak_event=10 peak_node_queue=1 peak_node_seen=1 peak_total_queue=10 peak_queue_bytes=7100 peak_inflight_bytes=710 peak_offline=1
network_sim_1000 scenario=loss_latency_reordering seed=268435458 events=94/94 contacts=66 attempts=45 transfers=28 accepted=2 duplicates=26 packet_loss=17 contact_loss=21 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=68 peak_node_queue=2 peak_node_seen=2 peak_total_queue=4 peak_queue_bytes=2008 peak_inflight_bytes=4554 peak_offline=0
network_sim_1000 scenario=loss_latency_reordering seed=1592590337 events=93/93 contacts=66 attempts=49 transfers=27 accepted=2 duplicates=25 packet_loss=22 contact_loss=22 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=68 peak_node_queue=2 peak_node_seen=2 peak_total_queue=4 peak_queue_bytes=2008 peak_inflight_bytes=4260 peak_offline=0
network_sim_1000 scenario=loss_latency_reordering seed=268435458 events=94/94 contacts=66 attempts=45 transfers=28 accepted=2 duplicates=26 packet_loss=17 contact_loss=21 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=68 peak_node_queue=2 peak_node_seen=2 peak_total_queue=4 peak_queue_bytes=2008 peak_inflight_bytes=4554 peak_offline=0
network_sim_1000 scenario=loss_latency_reordering seed=1592590338 events=94/94 contacts=66 attempts=47 transfers=28 accepted=2 duplicates=26 packet_loss=19 contact_loss=23 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=68 peak_node_queue=2 peak_node_seen=2 peak_total_queue=4 peak_queue_bytes=2008 peak_inflight_bytes=4260 peak_offline=0
network_sim_1000 scenario=loss_latency_reordering seed=1592590339 events=92/92 contacts=66 attempts=44 transfers=26 accepted=2 duplicates=24 packet_loss=18 contact_loss=29 ui=1 ack_materialized=1 ack_transition=1 mutations_rejected=0 restarts=0 peak_event=69 peak_node_queue=2 peak_node_seen=2 peak_total_queue=4 peak_queue_bytes=2008 peak_inflight_bytes=5264 peak_offline=0
```

Cargo summary (debug): `test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.50s`  
Cargo summary (release): `test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s`

---

## Queue10kWall — `reliability_10k`

Ignored test `reliability_10k_enqueue_dedup_ack` in `node/crates/raven-core/tests/reliability_10k.rs` (debug profile). Elapsed line is `eprintln!("reliability_10k ok in {:?}", t0.elapsed())`.

| Run | Printed line | Cargo summary |
|-----|----------------|---------------|
| 1 | `reliability_10k ok in 20.753959149s` | `ok. 1 passed; ... finished in 20.77s` |
| 2 | `reliability_10k ok in 20.150360064s` | `ok. 1 passed; ... finished in 20.17s` |
| 3 | `reliability_10k ok in 21.344168403s` | `ok. 1 passed; ... finished in 21.36s` |

These are host wall times for enqueue/dedup/ack of 10_000 queue items. They are not a sim-tick figure and are not a soft budget.

---

## Hard regression budgets (existing caps / invariants only)

These are compiled or asserted limits already in tree. They are **not** soft latency SLOs.

### `network_sim_1000.rs` constants

Source: `node/crates/raven-core/tests/network_sim_1000.rs` lines 18–24.

| Symbol | Line | Value |
|--------|------|-------|
| `NODE_COUNT` | 18 | `1_000` |
| `NODE_QUEUE_CAP` | 19 | `8` |
| `NODE_SEEN_CAP` | 20 | `32` |
| `MAX_EVENT_QUEUE` | 22 | `10_000` |
| `MAX_EVENTS_PROCESSED` | 23 | `50_000` |
| `MAX_SIM_OBJECT_BYTES` | 24 | `4_096` |

`assert_hard_bounds` (same file, lines 1091–1102) requires:

- `nodes.len() == NODE_COUNT`
- `events.len() <= MAX_EVENT_QUEUE`
- `peak_event_queue <= MAX_EVENT_QUEUE`
- `peak_node_queue <= NODE_QUEUE_CAP`
- `peak_node_seen <= NODE_SEEN_CAP`
- `peak_total_queued <= NODE_COUNT * NODE_QUEUE_CAP`
- `peak_logical_buffered_bytes <= NODE_COUNT * NODE_QUEUE_CAP * MAX_SIM_OBJECT_BYTES`
- `peak_in_flight_bytes <= MAX_EVENT_QUEUE * MAX_SIM_OBJECT_BYTES`

`finish_success` (lines 1217–1236) additionally requires `ui_deliveries == 1`, `endpoint_commits == 1`, `ack_materializations == 1`, `ack_transitions == 1`, `incorrect_ack_transitions == 0` for every scheduled valid temporal path.

### `forward_queue.rs` constants

Source: `node/crates/raven-core/src/forward_queue.rs` lines 65–77.

| Symbol | Line | Value |
|--------|------|-------|
| `MAX_FORWARD_QUEUE` | 65 | `512` |
| `MAX_PER_PEER_PENDING` | 68 | `64` |
| `MAX_PER_PEER_ENQUEUES_PER_WINDOW` | 70 | `30` |
| `PEER_RATE_WINDOW_MS` | 71 | `60_000` |
| `MAX_PER_PEER_BYTES_PER_WINDOW` | 73 | `256_000` |
| `MAX_RELAY_SEEN_OBJECTS` | 76 | `4_096` |
| `RELAY_SEEN_TTL_MS` | 77 | `7 * 24 * 60 * 60 * 1_000` |

`MAX_ENVELOPE_BYTES` (`1_048_576`, line 66) sits next to these limits and is used by `ForwardQueue` open paths; it was not in the requested harvest list.

---

## Soft budgets — DRAFT

**No numeric soft caps on 2026-09-04.**

Do not treat harvest maxima, Queue10kWall elapsed times, or “2× / 3×” multipliers as enforced budgets. A later snapshot designation (same commands, recorded host, compared harvest) is required before any soft latency/SLO number is written. Until then this section stays draft and empty of caps.

---

## CI wiring (status facts only)

Workflow: [`.github/workflows/raven-serverless.yml`](../../../.github/workflows/raven-serverless.yml) (`name: Raven Serverless Node`).

| Job (`name`) | Step `name` | Command in tree |
|--------------|-------------|-----------------|
| `rust-linux` / **Rust + vectors (Linux)** | `10,000-message queue reliability gate` | `cargo test -p raven-core --test reliability_10k -- --ignored` |
| `rust-linux` / **Rust + vectors (Linux)** | `Deterministic 1,000-node adversarial DTN simulation` | `cargo test -p raven-core --test network_sim_1000` and `cargo test --release -p raven-core --test network_sim_1000` |
| `rust-macos` / **Rust (macOS)** | `test raven-core + ash + swarm build` | `cargo test -p raven-core ...` (includes `network_sim_1000`; does **not** pass `--ignored`, so `reliability_10k` is not run) |
| `rust-windows` / **Rust (Windows)** | `test raven-core + ash (no bash smoke scripts)` | same as macOS: `network_sim_1000` via `cargo test -p raven-core`; no `--ignored` |

Linux CI does **not** pass `--nocapture`, so scenario report lines are not in default passing logs. This harvest used `--nocapture` locally.

`lan_path_smoke.sh` is **not** a step in this workflow. Linux CI does run `./scripts/lan_direct_two_node.sh` as **LAN direct two-node smoke** — that output was not harvested here.

This document does not claim current GitHub Actions run status.

---

## Soak / proof artifacts (paths only)

No soak pass-rate numbers are recorded here. In-repo **scripts and docs** that define PASS / SKIP / BLOCKED language:

| Path | What it states (not a measured rate) |
|------|--------------------------------------|
| [`scripts/final_serverless_proof.sh`](../../../scripts/final_serverless_proof.sh) | Increments `PASS` / `FAIL` / `SKIP`; writes `node/proof_artifacts/<run-id>/`; exit 0 only if `FAIL==0`. Hardware leftovers go to `BLOCKED.md` (`BLOCKED_HARDWARE` includes real CGNAT / multi-NAT / DCUtR). |
| [`docs/FINAL_SERVERLESS_PROOF.md`](../../FINAL_SERVERLESS_PROOF.md) | Documents `AUTOMATED_PROOF_GREEN` vs not full §59 DoD. Points at `node/proof_artifacts/LATEST/SUMMARY.md`. |
| [`scripts/reliability_matrix_20.sh`](../../../scripts/reliability_matrix_20.sh) | Allows `PASS`, `PASS_SOFTWARE_SUBSTITUTE`, `SKIP` with notes. |
| [`scripts/nat_docker_sim.sh`](../../../scripts/nat_docker_sim.sh) | Prints `RESULT=SKIP` when Docker is missing/down; `not_claimed=public_CGNAT,DCUtR,AutoNAT`. |
| [`scripts/soak_mac_lan_pull.sh`](../../../scripts/soak_mac_lan_pull.sh) | Long-running Mac LAN soak; logs `RESULT=PASS` / `RESULT=FAIL` under `.cursor/` (operator machine). **No committed soak log or pass rate in this repo.** |
| `node/proof_artifacts/` (untracked, gitignored; not a link) | Destination for proof-harness runs. **No `proof_artifacts/` tree is committed** (root `.gitignore` has `proof_artifacts/`). |

Do not invent a soak pass rate from the absence of those artifacts.

---

## Honest gaps

- **No live p50 / p95 / p99 delivery latency.** `node/MASTER_ENGINEERING_CHECKLIST.md` still has unchecked “Measure p50/p95/p99 delivery latency” items. This harvest has no live latency histogram.
- **Sim wall-clock is excluded by design.** [`protocol/RAVEN_NETWORK_SIMULATION_1000_V1.md`](../../../protocol/RAVEN_NETWORK_SIMULATION_1000_V1.md): the model uses virtual ticks; “Runtime itself is intentionally not part of the report because it depends on the CI host.” Cargo `finished in …` times above are harness noise, not a budget.
- **DCUtR / multi-NAT hardware is blocked** where docs already say so: `node/NAT_TRAVERSAL.md` (`BLOCKED_HARDWARE`), `protocol/RAVEN_TRANSPORT_INTERFACE_V1.md` § NAT/CGNAT/DCUtR, `raven_core::discovery::NAT_STATUS`. Software substitutes exist; they were not re-run for this baseline.
- **`print_report` omits several asserted counters** (`local_admission_rejections`, `availability_changes`, `reconstructed_replicas`, `partition_blocked_contacts`, …). Those stay **INVARIANT-ONLY** until a harvest prints them.
- **LanPathSuccess** and any public-Internet / BLE / radio path: **NOT MEASURED**.
- **First toolchain on this VM (1.83.0) could not build** current `Cargo.lock`; numbers come only from rustc 1.98.1.

---

## Re-harvest

```sh
cd node
./scripts/harvest_perf_baseline.sh
# optional:
RAVEN_PERF_RELEASE=1 RAVEN_RELIABILITY_10K=1 RAVEN_RELIABILITY_10K_RUNS=3 \
  ./scripts/harvest_perf_baseline.sh
```

Compare new `network_sim_1000 scenario=` lines to this file. Deterministic fields should match for the same source. `Queue10kWall` will move with disk and host. Soft budgets stay draft until Eng Program marks a snapshot.
