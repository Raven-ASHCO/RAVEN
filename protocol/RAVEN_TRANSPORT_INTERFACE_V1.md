# RAVEN Transport Interface V1

**Version:** 1 (`rvn1`)  
**Status:** Binding adapter contract  
**Companions:** ADR-0002, [`RAVEN_BRIDGE_V1.md`](RAVEN_BRIDGE_V1.md), [`RAVEN_BLE_FRAMING_V1.md`](RAVEN_BLE_FRAMING_V1.md)

## 1. Goal

All transports expose the same logical operations so Bridge / router code stays transport-agnostic.

## 2. Logical interface

```
Transport {
  kind: Ble | MockBle | Lan | Internet | Store
  listen(addr) -> LocalEndpoint
  dial(peer) -> Session
  send(session, opaque_bytes)   // RavenEnvelopeV1 or framed control
  recv(session) -> opaque_bytes
  advertise_caps(bits)          // generic only
  close(session)
}
```

| Requirement | Rule |
|-------------|------|
| Object | Packed `RavenEnvelopeV1` (or hello/control clearly typed) |
| Auth layers | Transport auth ≠ E2EE; both may exist |
| Caps | `ble`/`internet`/`relay`/`store`/`bridge` only — never contacts |
| Errors | Map to [`RAVEN_ERROR_CODES_V1.md`](RAVEN_ERROR_CODES_V1.md) |

## 3. Internet framing (shipping)

```
Hello: RIH1 || caps_u32_be || nonce12 || ed25519_pub32 || sig64
Frame: u32_be(len) || payload
```

Proto id string in signing bytes: `raven/internet/v1`. Implemented in `raven_core::internet`.

## 4. Path selection

`raven_core::transport::select_path` / `prefer_transport` — prefer direct LAN/Internet, else BLE, else store-carry. Bridge when ingress≠egress radios.

## 5. Discovery (DHT-ready)

Signed peer record (`raven_core::discovery`):

```
"rvn1/peer" || lp(multiaddr_utf8) || ed25519_pub32 || caps_u32 || u64(expires_ms)
```

Ed25519-signed. MAY be published into a Kademlia DHT when `rust-libp2p` integration is enabled. V1 shipping path dials explicit `host:port` / multiaddr without requiring live DHT.

**NAT / CGNAT / DCUtR:** multi-NAT live matrix is **BLOCKED_HARDWARE**. Software substitutes: localhost + LAN dial smokes (`internet_dial_smoke` fail-closed; `internet_indexed_two_node` localhost/lab indexed delivery — **dial≠WAN**; `lan_path_smoke`); AutoNAT/DCUtR not claimed complete.

## 6. Target libp2p (ADR-0002)

| Feature | V1 status |
|---------|-----------|
| TCP length-prefix + hello | **IMPLEMENTED** |
| QUIC / Noise / Yamux stack | **IMPLEMENTED** local swarm (`raven-swarm`: TCP+Noise+Yamux; QUIC listen attempted) |
| DHT signed discovery | Record format **IMPLEMENTED**; local Kad put/get **IMPLEMENTED**; public Internet Kad **BLOCKED_HARDWARE** |
| Circuit relay / DCUtR | Not complete — see BLOCKED_HARDWARE |

## 7. Tests

`internet` unit tests, `internet_dial_smoke.sh` (fail-closed), `internet_indexed_two_node.sh` (localhost lab; **dial≠WAN**), `lan_path_smoke.sh`, `libp2p_swarm_smoke.sh`, `bootstrap_manual_peer_smoke.sh`, bridge demos.
