# Migration: Legacy Raven Messaging → Serverless V1 (§54)

**Branch (historical):** authored on `feature/raven-serverless-v1`; this file now lives on `main` and is a dated snapshot, not a statement about an open branch  
**Binding model:** `docs/SERVERLESS_MODEL.md` / `node/SERVERLESS_MODEL.md`

## Non-negotiable rule

> The serverless (`RavenEnvelopeV1` / `raven-node` / `ash`) path **never silently uses FastAPI** (or any central message inbox) for 1:1 text delivery.

If FastAPI appears in a process that also carries serverless code, it must be a **separately labeled** legacy route — never an implicit fallback when a peer dial / BLE / store path fails.

## Feature flags

| Surface | Flag | Default | Effect |
|---------|------|---------|--------|
| iOS | `FeatureFlag.ravenEnvelopeV1` (`raven_envelope_v1`) | **OFF; forced OFF in Release** | Debug-only integration switch. Release ignores stale persisted values until the indexed ATSAM session and endpoint transaction gates pass. |
| Terminal (`ash` / `raven-node`) | always serverless | n/a | Binaries speak RVN1 only; no FastAPI client for DMs. |
| Env (diagnostics) | `RAVEN_SERVERLESS_RVN1` | implied ON for node | Documented for dual-stack hosts. |
| Env (diagnostics only) | `RAVEN_DIAG_FORCE_LEGACY_LABEL=1` | unset | Forces `legacy_mesh_envelope` **label** in doctor/status — does **not** enable FastAPI. |

Rust helper: `raven_core::messaging_path` (`MessagingPath::{ServerlessRvn1, LegacyMeshEnvelope, LegacyFastApi}`).

## Diagnostic labels

| Label | Meaning |
|-------|---------|
| `serverless_rvn1` | Active serverless envelope path (terminal default). |
| `legacy_mesh_envelope` | MeshEnvelope / flag-OFF mobile mesh. |
| `legacy_fastapi` | Central inbox — **must not** be selected by serverless send. |

`ash status` / `ash doctor` print `messaging_path=<label>` and a one-line human string.

`ash doctor` Core gate — never one green `up` that implies send:

| Label | Meaning |
|-------|---------|
| `daemon_presence` | `ipc_client::ipc_ping` over `ipc_endpoint`. Success: `present` (not `up`). Connect fail: `down`. `IpcEndpoint::Unsupported`: `blocked (reason=ipc_transport_missing)` — never a ✓. Windows: the per-user pipe `\\.\pipe\raven-node-<user SID>` only (never UDS); a pipe whose server runs as another user is refused. |
| `daemon_ready` | Presence plus Status, `raven_core::identity_usable` (mismatch ⇒ ready FAIL), queue/DB or `forward_pending`, `serverless_rvn1`. |
| `send_path` | Default `not_ready (reason=not_probed)`. Never green from presence or ready. |

## Identity / contacts / history

| Artifact | Migration stance (V1) |
|----------|----------------------|
| Identity | New `identity.seed` (Ed25519) for ash; do **not** treat old usernames as crypto identities. |
| Contacts | ash `contacts.json` (public fields); optional encrypted device sync (`device_sync`). |
| History | No automatic import from FastAPI DB into RVN1 outbox. |
| Device keys | Device certificates under user identity (§39); separate from transport PeerId. |
| Rollback | Turn iOS flag OFF → MeshEnvelope resumes; ash remains RVN1-only. User data in `data_dir` preserved. |

## Mixing envelopes

- Relays/bridges forward **opaque** `RVN1` bytes only.
- MeshEnvelope JSON and RavenEnvelopeV1 must not be rewritten into each other by a “compatibility adapter” that decrypts centrally.
- Minimum compatible clients: ash/raven-node on this branch + iOS builds with `ravenEnvelopeV1` support when the flag is ON.

## Release gate

Do **not** make serverless the product default (iOS flag ON, website claims) until §59/§60 gates pass or the user explicitly waives hardware/human review.

Security gates cannot be waived by a feature toggle. In particular, the
public-key-derived interim sealer, plaintext/ID-only ACK handling, and
synthetic ATSAM bodies are forbidden in every production artifact. Current
normative status is in
[`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md).
