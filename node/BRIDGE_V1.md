# Raven Bridge V1 (local)

Opaque **cross-transport** forward of the same `RavenEnvelopeV1` between LAN/Internet and BLE (mock BLE = TCP length-prefix in CI).  
Bridge ≠ trusted server: never decrypts, never re-origins, never changes `message_id`.

> Security status: bridge mechanics are testable, but production messaging is
> blocked by [`../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md).
> The bridge never parses sealed ACK content or declares recipient delivery.

Conceptual credit: MIT DTN store-carry-forward, Spray-and-Wait replication budgets, RFC 9171 lifetime/hop-safety lessons — **not** BPv7 wire format.

## Topology (A–B–C)

| Node | Radios | Role |
|------|--------|------|
| **A** | Internet/LAN ON, BLE OFF | Sender — seals A↔C E2EE, dials B LAN |
| **B** | LAN + BLE (mock) | **Bridge** — opaque forward + store-carry |
| **C** | Internet OFF, BLE ON (mock) | Recipient — decrypts, emits **only** Delivered ACK |

## Automated tests (no phones)

```bash
cd /path/to/hybrid_messenger/node
cargo build -p raven-core -p raven-node -p ash
cargo test -p raven-core --test bridge_v1          # case01–case15, case10b, e2ee_survives_bridge_hop
./scripts/two_node_demo.sh
./scripts/lan_path_smoke.sh
./scripts/bridge_abc_demo.sh                       # A–B–C + store-carry + ash status
```

### Cases covered by `bridge_v1`

1. BLE→Internet forward  
2. Internet→BLE reverse  
3. Store-carry when Internet down, flush later
4. Dup BLE+Internet → one delivery
5. Tampered ciphertext → auth fail
6. Replay → dedup drop
7. Crash after queue → recover
8. Expired offline → never forward
9. Per-peer rate limit (noisy hop dropped; quiet hop still forwards)
10. Recipient ACK reverse (BLE→LAN sealed and opaque, with no acknowledged-ID peek); destination dispatch remains separate from authenticated endpoint acceptance
    - `case10b`: destination ingest. When the local node is an endpoint (not a forced bridge), the envelope is dispatched for endpoint delivery with its ciphertext untouched
11. Replay after the bounded seen-cache evicts the object is still a duplicate (the forward tombstone outlives the cache)
12. Full relay custody is reported as `STORE_FULL`, not as malformed input
13. Relay custody is clamped to `MAX_FORWARD_TTL_MS`: a far-future envelope expiry cannot squat a pending slot
14. Forwarded rows keep no ciphertext and are garbage-collected
15. Far-future replay after the custody period is still a duplicate (the tombstone lasts until the envelope's own expiry)

`e2ee_survives_bridge_hop`: the endpoint can still unseal the A↔C body after a bridge hop.

## Abuse limits (V1 defaults)

| Limit | Default |
|-------|---------|
| Global pending queue | 512 |
| Max envelope bytes | 1 MiB |
| Per-peer pending | 64 |
| Per-peer enqueues / 60s | 30 |
| Per-peer bytes / 60s | 256 KiB |

`previous_hop` is an opaque peer key (never BLE MAC / IP as Raven identity).

## BLE adapters

| Adapter | Where | Notes |
|---------|--------|-------|
| `mock_ble` | `raven-node bridge` (TCP) | CI / demos — keep forever |
| `ble_gatt` | iOS `BLEMeshEngine` + `RavenBleRvn1Carrier` | Flagged; MeshEnvelope default when flag OFF |

## Hardware BLE note

Software path is proven with **mock_ble** (TCP). Real GATT on device uses existing iOS `BLEMeshEngine` characteristic path for raw `RVN1` behind `FeatureFlag.ravenEnvelopeV1`.

**raven-node on macOS:** keep `mock_ble` for CI/demos. A CoreBluetooth / BlueZ GATT adapter is **not** wired into `raven-node` (would break headless CI and needs interactive Bluetooth entitlements). Use iOS hardware for GATT; use `bridge_abc_demo` for cross-transport ACK proof.

iOS phone-as-B:
- Optional LAN listen port → opaque BLE forward (`RavenEnvelopeBridgeService.forwardLanToBle`)
- Recipient ACK reverse: BLE ACK is routed as an opaque envelope toward active LAN paths; the bridge does not read `acked_message_id`. Only the originating endpoint can decrypt and apply it.
- Phone-as-C: destination classification must come from a recognized local routing tag/session, never a user-forced unconditional boolean. Unknown routes remain relay-only or are dropped.
- `RavenEnvelopeChatWire` may emit a sealed Delivered ACK only after authenticated decrypt and durable inbox/ratchet commit; sender delivery requires full outer + AEAD + inner ACK verification and exact pending-recipient binding.

### Hardware GATT smoke (iOS device, flag ON)

1. Two phones (or phone + Mac with iOS Simulator BLE limited): enable **RavenEnvelopeV1**
2. Phone B: Serverless LAN listen port > 0; BLE peers nearby; `localIsDestination = false`
3. Phone C: BLE only; install an authenticated session whose routing tag matches the test envelope
4. A (Mac test harness or phone): send a real session-sealed envelope to B LAN; expect C authenticated commit followed by a sealed ACK back to A
5. Confirm MeshEnvelope path still works with flag OFF

## ash terminal controls (does **not** stop bridging)

Policy file: `<data-dir>/node_policy.json` (no secrets).  
`raven-node bridge` hot-reloads it; closing ash leaves the node running.

```bash
DATA=$(mktemp -d)
./target/debug/ash --data-dir "$DATA" init
./target/debug/ash --data-dir "$DATA" node bridge on
./target/debug/ash --data-dir "$DATA" node store on
./target/debug/ash --data-dir "$DATA" node relay off
./target/debug/ash --data-dir "$DATA" status
./target/debug/ash --data-dir "$DATA" banner
```

Interactive menu → **3 Status** shows the same Bridge / transports / forward_q lines.

## Run bridge daemon (B)

```bash
./target/debug/raven-node bridge \
  --data-dir "$DATA_B" \
  --lan-listen 127.0.0.1:0 \
  --ble-listen 127.0.0.1:0 \
  --write-lan-addr /tmp/b.lan \
  --write-ble-addr /tmp/b.ble \
  --timeout-secs 0          # 0 = until killed; ash exit does not stop this
```

## Safety

- Never print seeds / private keys / plaintext
- Logs: aggregate state and bounded error classes only; do not write peer addresses, message identifiers, plaintext, ciphertext, keys, or absolute developer paths
- Capability ads: `ble` / `internet` / `relay` / `store` / `bridge` — never “I know Bob”
- No GitHub push of demo data dirs
