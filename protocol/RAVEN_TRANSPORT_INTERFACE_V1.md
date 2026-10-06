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

## 3. Internet framing (lab-gated)

InternetTransport is compiled into default builds but runs only in debug
builds with `RAVEN_LAB_TEST_A=1` (`INTERNET_DIRECT_PRODUCTION_ENABLED=false`).
Implemented in `raven_core::internet` (codec) and `raven-node`
`internet_direct` (sockets).

```
Frame:     u32_be(len) || noise_msg        1 <= len <= 65535, checked before allocating
Handshake: Noise_XX_25519_ChaChaPoly_BLAKE2s, prologue "raven/internet/v1",
           static = the LAN Noise static (HKDF of the identity seed), empty payloads
Hello:     Noise transport plaintext, initiator first, then responder:
           RIH1 || caps_u32_be || ed25519_pub32 || sig64                  (104 bytes)
sig input: "rvn1/internet-hello/v1" || role_u8 || caps_u32_be
           || noise_handshake_hash32 || signer_noise_static_pub32 || ed25519_pub32
           role_u8: 1 = initiator, 2 = responder
Then:      RLB1 offer each way, then PairInit / envelopes / ACKs,
           each one Noise transport message (plaintext <= 65519 bytes)
```

Verification rules:

- The receiver verifies the peer hello against the peer's role, its own final
  Noise handshake hash, and the peer static key authenticated by XX. Any
  mismatch closes the connection. Both sides require `CAP_INTERNET`; the dialer
  also requires `ed25519_pub` to equal the identity it dialed.
- The handshake hash covers both ephemeral keys, so a hello is valid for exactly
  one connection and one direction. A captured hello cannot be replayed on
  another connection, and a reflected hello fails on `role_u8`.
- The prologue gives domain separation: a LAN Noise transcript (no prologue)
  cannot complete against an Internet endpoint, or the reverse.
- Only Noise handshake messages are sent in the clear. XX encrypts the static
  keys. RLB1 offers and PairInit expose addresses and trust material
  ([`RAVEN_PAIR_INIT_V1.md`](RAVEN_PAIR_INIT_V1.md) §7), so they are sent only
  as Noise ciphertext. An on-path observer still sees IP/port, timing and frame
  sizes. Transport authentication is not E2EE.

**Retired:** the earlier cleartext hello (`RIH1 || caps || nonce12 || pub ||
sig` over a nonce the signer chose, followed by plaintext frames) has been
removed. It was replayable, had no channel binding, and exposed RLB1 and
PairInit to any observer. Pre-revision lab builds do not interoperate with this
version and fail closed at the first length prefix.

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
| TCP length-prefix + Noise XX + channel-bound hello | **IMPLEMENTED** (lab-gated, §3) |
| QUIC / Noise / Yamux stack | **IMPLEMENTED** local swarm (`raven-swarm`: TCP+Noise+Yamux; QUIC listen attempted) |
| DHT signed discovery | Record format **IMPLEMENTED**; local Kad put/get **IMPLEMENTED**; public Internet Kad **BLOCKED_HARDWARE** |
| Circuit relay / DCUtR | Not complete — see BLOCKED_HARDWARE |

## 7. Tests

`internet` unit tests, `internet_dial_smoke.sh` (fail-closed), `internet_indexed_two_node.sh` (localhost lab; **dial≠WAN**), `lan_path_smoke.sh`, `libp2p_swarm_smoke.sh`, `bootstrap_manual_peer_smoke.sh`, bridge demos.
