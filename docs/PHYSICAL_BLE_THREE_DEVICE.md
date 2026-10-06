# Physical BLE three-device proof (operator)

**Status:** `BLOCKED_HARDWARE` until three physical devices are operated by a human.  
Software stand-in: `node/scripts/bridge_abc_demo.sh` (mock_ble over TCP).

> **LAB / NON-RELEASE.** RVN1 messaging is under a production HOLD
> ([`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md),
> [`THREAT_MODEL.md`](THREAT_MODEL.md)). A passing run of this runbook would show opaque forwarding and
> delivery mechanics only: the in-repo bridge evidence uses the lab interim cipher (key derivable from
> public keys), and bridging under authenticated ATSAM sessions is not yet exercised. It is **not** a
> confidentiality claim. The iOS steps below drive `ios-native`, which is **not in this repository**
> (OFF-MAIN) and whose Release builds hard-disable RVN1.

## Topology

```
Phone A (Internet/LAN capable) ──LAN/TCP──► Bridge B (Mac/Linux raven-node) ──BLE──► Phone C (BLE-only / airplane+BT)
```

- **A** = terminal `ash` + `raven-node` *or* iOS with `FeatureFlag.ravenEnvelopeV1` ON  
- **B** = always-on bridge (`raven-node service` / launchd) — **must never decrypt**  
- **C** = iOS/Android mesh client receiving opaque `RVN1` over GATT

## Exact commands (desktop B)

```bash
cd node
cargo build -p raven-node -p ash --release
DATA="$HOME/.raven-bridge-b"
./target/release/raven-node init --data-dir "$DATA"
./target/release/ash --data-dir "$DATA" node bridge on
./target/release/ash --data-dir "$DATA" node store on

# Foreground proof (or use scripts/install/macos_launchd.sh for service).
# The bridge must be reachable from phone A, so --lan-listen is non-loopback;
# prefer this host's specific LAN IP over 0.0.0.0 (all interfaces) where practical.
./target/release/raven-node service \
  --data-dir "$DATA" \
  --lan-listen "0.0.0.0:7420" \
  --ble-listen "127.0.0.1:7421"   # mock_ble until CoreBluetooth feature enabled
```

## iOS A / C (when you have phones)

1. Build `ios-native/RAVEN` with `FeatureFlag.ravenEnvelopeV1 = true`.
2. Pair A↔C via QR / Soft Unique Tag verify (friendship plane — not FastAPI).
3. On C: enable Airplane Mode, leave Bluetooth ON.
4. On A: send text 1:1; confirm Outbox → then Delivered after B carries.
5. Reverse: C sends over BLE → B → A Internet path.
6. Confirm: identical `message_id` in diagnostics; no duplicate UI rows; B logs show forward only (no plaintext).

## Pass criteria (human checklist)

- [ ] No FastAPI / central inbox involved (`ash doctor` → `serverless_rvn1`)
- [ ] B cannot show plaintext of either direction
- [ ] ACK → Delivered on sender after C decrypts
- [ ] Duplicate suppression if A retries same mid
- [ ] Record screen + `ash status` / bridge status JSON (redact pubs if sharing publicly)

## Software substitute already green

```bash
bash node/scripts/bridge_abc_demo.sh
# → ALL BRIDGE A-B-C CHECKS PASSED
```
