# Multi-Device Sync + Partition Revocation (V1 software subset)

**Checklist:** §39  
**Branch (historical):** authored on `feature/raven-serverless-v1`; this file now lives on `main` and is a dated snapshot, not a statement about an open branch  
**Code:** `raven-core::device_cert`, `raven-core::device_sync`

## What V1 implements (software)

| Capability | Status |
|------------|--------|
| One user identity, many device certs | `DeviceCertificate` + `DeviceRegistry` |
| Local revoke denylist | Sticky; re-add of same `device_id` fails |
| Encrypted device-to-device contact sync | `seal_contact_sync` / `import_contact_sync` (ChaCha20-Poly1305, HKDF from user seed) |
| Signed revocation records + epoch merge | `RevocationRecord` + `RevocationStore` |
| Revoked device cannot push sync | Import checks `is_authorized` |
| Partition lag model + tests | `partition_lag_allows_stale_auth` |

## What V1 does **not** claim

- Live DHT / gossip push of revocation to all contacts. (A frozen wire record, `RavenDeviceRevocationV1` / RVDR1, now exists: [`protocol/RAVEN_DEVICE_REVOCATION_V1.md`](../protocol/RAVEN_DEVICE_REVOCATION_V1.md) is APPROVED but **production-disabled**, with a Rust implementation in `raven_core::device_revocation`.)
- Automatic contact warning UX on every material device change (stub: operator must exchange records).
- Physical phone + terminal under one identity (needs **BLOCKED_HARDWARE** / human devices).

## Partition limitations (honest)

During a network partition:

1. Device **A** (online) issues `RevocationRecord(epoch=N)` for stolen device **S** and applies it locally.
2. Device **B** (partitioned) still has **S** authorized until it observes a record with epoch ≥ N.
3. **S** cannot mint new device certs that **A** will accept (sticky denylist + signature by user identity required for certs).
4. **S** cannot push encrypted contact sync into a registry that already revoked it.
5. After partition heals, **B** merges records; higher epoch wins; denylist remains sticky.

Operators should exchange revocation blobs via any opaque channel (QR, store-carry, manual file). Software tests cover merge + lag; they do **not** replace a multi-NAT hardware proof (§59).

## Contact sync threat notes

- Plaintext contacts are **public fields only** (alias, address, pub hex).
- Sealed blob is bound to the user identity public key as AEAD AAD.
- Wrong user seed fails unseal.
- Never store plaintext sync on a central server.
