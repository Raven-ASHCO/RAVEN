# Security Policy

This policy covers **this repository**: the Rust serverless node workspace under
`node/`, the protocol specifications under `protocol/`, the Python reference
implementation under `protocol/reference/`, the shared test vectors under
`shared-vectors/`, and the scripts / CI under `scripts/`, `node/scripts/` and
`.github/`. Mobile apps and any legacy server live in other trees and are out of
scope here (report issues in them the same way; we will route them).

## Reporting a vulnerability

- **Email:** info@raven-messenger.com
- **Subject:** `[SECURITY] <short description>`
- **Do NOT** open a public GitHub issue, pull request or discussion for a
  vulnerability.

Please include the affected component (crate / binary / spec / script), the
commit you tested, build features used (for example whether
`unsafe-demo-crypto` or a lab feature was enabled), reproduction steps or a
proof-of-concept input, and the impact you believe it has.

### Response timeline

| Action | Target |
|--------|--------|
| Acknowledgment | within 48 hours |
| Initial assessment | within 5 business days |
| Fix and coordinated disclosure | within 30 days, or an agreed date for complex issues |

## Scope

In scope — default builds and anything reachable by a remote peer or another
local user:

- **Wire decoders and protocol logic in `raven-core`:** RVN1 envelope
  (`RAVEN_ENVELOPE_V1`), ACK, store objects (RSO1), PairInit / pair response,
  ATSAM indexed sessions and RVNA1 bodies, prekey bundles and lifecycle, device
  certificates and revocation, routing / store tags, alias and profile
  records, contact-request / introduction codecs, RLB1 LAN offers, the LAN
  Noise binding (`Noise_XX_25519_ChaChaPoly_BLAKE2s`), bridge frames and
  store-and-forward queues.
- **`raven-node` daemon:** LAN / bridge / mock-BLE listeners, the Internet
  carrier, the local IPC endpoint (Unix socket / Windows named pipe) and its
  request parser, on-disk state (queues, session stores, chat history).
- **`raven-swarm`:** the libp2p host (Noise, TCP/QUIC, Kademlia
  `/raven/kad/1.0.0`, relay, DCUtR), signed PeerRecords and bootstrap config.
- **`ash` CLI:** identity creation and key storage (macOS Keychain, Windows
  DPAPI, Linux Secret Service), contact pinning, import/export paths.
- **FFI crates** (`raven-fb-ffi`, `raven-mlkem768-incremental-ffi`) and other
  `unsafe` code.
- **Denial of service and resource exhaustion** of peers, relays, bridges and
  store-and-forward nodes (unbounded allocation, queue or disk growth,
  amplification, CPU exhaustion from crafted input). Forwarding for others is a
  core function of a mesh node, so remote DoS is in scope.
- **Specifications, reference code and vectors** that are wrong in a way that
  would lead a conforming implementation to be insecure.
- **Build, release and CI:** anything that lets `unsafe-demo-crypto` or a lab
  feature reach a release artifact, or that compromises the supply chain.

Out of scope:

- Lab-only paths used **as documented**: the `unsafe-demo-crypto` feature and
  `--body-mode unsafe-interim` (a public-key-derived demo cipher that is *known*
  to be readable by any observer), `RAVEN_LAB_TEST_A`, the `locked-file`
  debug key backend, and features marked experimental / lab. A way to reach
  them from a release build *is* in scope.
- Social engineering, and physical attacks on an unlocked device.
- Volumetric network flooding that no protocol change can mitigate.
- Vulnerabilities in third-party dependencies with no Raven-specific impact
  (please report upstream; tell us if Raven is affected).

## Current security status

Read these before assessing an issue — several limitations are already known
and documented:

- [`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](protocol/SECURITY_ERRATA_RVN1_2026-08-13.md)
  — normative errata and production hold for RVN1.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and
  [`docs/crypto/ATSAM_THREAT_ASSUMPTIONS_V1.md`](docs/crypto/ATSAM_THREAT_ASSUMPTIONS_V1.md).
- [`protocol/SPEC.md`](protocol/SPEC.md) — which wire formats are frozen and
  which are implementation-defined.
- [`docs/EXTERNAL_REVIEW_PACKET.md`](docs/EXTERNAL_REVIEW_PACKET.md) — review
  scope and known gaps.

## Cryptography actually used

| Purpose | Primitive |
|---|---|
| Identity and record signatures | Ed25519 (`ed25519-dalek`) |
| Session key agreement (ATSAM hybrid root) | X25519 **and** ML-KEM-768, bound to a transcript hash |
| Key derivation | HKDF-SHA-256, HMAC-SHA-256 |
| Message / ACK / at-rest AEAD | ChaCha20-Poly1305 |
| LAN link binding | Noise `XX_25519_ChaChaPoly_BLAKE2s` (`snow`) |
| libp2p transport | libp2p Noise over TCP / QUIC |
| Local key storage | macOS Keychain, Windows DPAPI, Linux Secret Service |

There is no central message server and no TLS server endpoint in this
repository. Message routing is store-carry-forward over LAN, bridge, mock-BLE,
mailbox and libp2p carriers.

## Acknowledgments

We credit researchers who report valid vulnerabilities, with their permission.
