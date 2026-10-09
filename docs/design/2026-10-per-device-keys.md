# Per-device keys and containable device compromise

| | |
|---|---|
| **Status** | Design proposal for protocol-owner decision. Not a spec: it authorizes no code, wire freeze, vector, or Release flag. Companion names below are proposals. |
| **Date** | 2026-10-07 |
| **Baseline** | `fix/code-review-2026-09-29` at `a1d3e1d`. All `file:line` citations refer to that commit. `node/crates/` is being edited concurrently (for example the 24 h `LAN_SESSION_LIFETIME_MS` change), so re-check lines before acting on them. |
| **Retires when done** | Residual risks 3 and 5, and part of 4, of [`WAIVER-LAN-DIRECT-2026-10-07`](../WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) §4 |
| **Specs touched** | [`RAVEN_IDENTITY_V1`](../../protocol/RAVEN_IDENTITY_V1.md), [`RAVEN_DEVICE_REVOCATION_V1`](../../protocol/RAVEN_DEVICE_REVOCATION_V1.md), [`RAVEN_PAIR_INIT_V1`](../../protocol/RAVEN_PAIR_INIT_V1.md), [`RAVEN_PREKEY_BUNDLE_V1`](../../protocol/RAVEN_PREKEY_BUNDLE_V1.md), [`RAVEN_ID_RESOLUTION_V1`](../../protocol/RAVEN_ID_RESOLUTION_V1.md) §3.1/§10, [`RAVEN_IDENTITY_CONTINUITY_V2`](../../protocol/RAVEN_IDENTITY_CONTINUITY_V2.md), [`THREAT_MODEL`](../THREAT_MODEL.md) |
| **Sibling designs** | `2026-10-ratchet-fs-pcs.md` (FS/PCS, PairInit V2) and `2026-10-daemon-owned-secrets.md` (who holds secrets), both named by the waiver |

## 0. Summary

- The spec requires two key tiers that "MUST NOT" be collapsed. The node collapses them. Every install holds the identity seed and uses it online for every routine signature and for several key derivations (Appendix A). One compromised install, including a parser RCE in the network-facing daemon, compromises the identity permanently. Revocation cannot contain this: there is only one lineage, and the attacker can mint new ones.
- **Recommendation:** an identity-signed device certificate that the device key co-signs (`RavenDeviceCertificateV2`, proof of possession). It comes with an identity-signed, monotonic **DeviceSet** whose generation is the freshness epoch and whose membership is positive. Prekeys are signed by the device. The Noise static key is the certified device X25519 key, with no per-connection identity signature. An `RLB2` offer carries the certificate, DeviceSet and revocations. The PairInit wire is unchanged; its trust-record digests are versioned.
- **The identity root leaves the daemon.** It stays either in a keystore item that only `ash` reads and uses only in confirmed ceremonies (custody **K**), or in an offline recovery phrase (custody **O**). It is used only to enroll, renew (batched, about every 6 weeks), revoke, sign the DeviceSet, and sign alias and capability records.
- **Revocation** is an RVDR1 record plus a DeviceSet generation bump. It is pushed to contacts and piggy-backed on every RLB2. Pre-signed revocations let a surviving device revoke without the root. A contact that the attacker isolates accepts the revoked device until the certificate or DeviceSet expires (60 days by default, 180 days at most), plus at most one session lifetime. Today the bound is effectively forever.
- **Migration:** each install re-certifies once. A compat mode serves v1 contacts, which keeps the root in the primary's daemon until sunset. Sunset retires the collapsed lineage. **Migration cannot heal earlier compromise**, because every existing install has held the seed.
- **Not covered:** deniability is unchanged (there is none). Multi-device fan-out is deferred to P5; until then a message is delivered to the one device the carrier reaches.
- **Effort:** P0 to P4 is about 17 to 18 engineer-weeks plus 2 to 3 weeks of formal modelling. Fan-out (P5) is 5 to 6 more.

## 1. Problem statement and evidence

### 1.1 What the protocol requires

- `RAVEN_IDENTITY_V1` §1 (lines 9-13) defines two tiers, which "MUST NOT collapse". §1.2 (lines 30-41) requires distinct per-device Ed25519 and X25519 keys, with the device key signing `sender_authentication`. §2 (lines 61-66, 85-89) makes the identity-signed certificate the **only** binding between a `device_ed_pub` and an identity.
- The umbrella spec ([`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2`](../../protocol/RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md) line 154) says Noise expected-bind keys and dial targets use **device** keys when user ≠ device.
- The locked roadmap decision ([`2026-08-12-raven-serverless-roadmap.md`](../superpowers/plans/2026-08-12-raven-serverless-roadmap.md) line 58) is to "keep per-device Ed25519+X25519; add a user-identity Ed25519 key above it". Checklist §39 ([`MASTER_ENGINEERING_CHECKLIST.md`](../MASTER_ENGINEERING_CHECKLIST.md) lines 1326-1346) is entirely open.

### 1.2 What the code does

| # | Fact | Evidence (`a1d3e1d`) |
|---|---|---|
| E1 | The local certificate certifies the identity key itself, for 365 days. It is reissued automatically with the identity key whenever it is invalid. | `raven-core/src/device_cert.rs:8-13`, `:350-370` (`:368`) |
| E2 | LAN accepts only collapsed certificates. The stated reason is that RLB1 has no device proof of possession and the caches hold one device per identity. | `lan_dispatch.rs:80-94`, `:638-642`, `:810-816`, `:52-54`, `:1055-1062` |
| E3 | The identity key signs PairInit, PairResponse, and both OOB wrapper envelopes. | `lan_dispatch.rs:1865-1890`, `:1229-1239`, `:1339-1346`, `:1901-1913` |
| E4 | The identity key is the endpoint signer for every message envelope and ACK. | `lan_dispatch.rs:1457`, `:1786` into `indexed_session_store.rs:292-349` |
| E5 | The identity key signs every prekey bundle (30-day validity, rotated about every 22 days). The store keeps one bundle per identity. | `lan_dispatch.rs:598-606`; `RAVEN_PREKEY_BUNDLE_V1` §4 (lines 56-63) |
| E6 | The Noise static key is HKDF(identity seed). The LAN bind is an identity signature over the static key only, not channel-bound. The Internet RIH1 hello is an identity signature over the handshake hash. | `lan_noise.rs:3-5`, `:48-60`, `:74-80`; `raven-node/src/lan_direct.rs:183-224`; `internet.rs:124-152` |
| E7 | Other secrets are derived from the identity seed: the contact-sync AEAD key ("a policy check, not device authentication") and the libp2p peer key. | `device_sync.rs:172-179`, `:246-251`; `raven-swarm/src/main.rs:140-151` |
| E8 | The network-facing daemon holds the identity for the listener's whole lifetime. | `raven-node/src/lan_direct.rs:234-236` |
| E9 | The seed is a Keychain generic password per data directory, a DPAPI file, or a Secret Service item. No command exports or backs up the seed. | `identity_store.rs:1-8`, `:177-184`, `:726-735`; [`IDENTITY_SEED_STORAGE.md`](../IDENTITY_SEED_STORAGE.md) |
| E10 | The device X25519 secret is a plaintext 0600 file. Nothing uses it except the certificate and lineage fields. | `device_cert.rs:260-319` |
| E11 | `ash device revoke` mints a legacy `rvn1/devrevoke/v1` record and stores it locally, with no confirmation and no distribution. Nothing ingests a peer's revocation: there is no command and no network path. | `ash/src/ext.rs:1088-1136`; `ash/src/cli.rs:687-693`; REVOCATION §9.1 (line 537); `device_sync.rs:10-12` |
| E12 | Revoking any local lineage retires the identity key's device role, so the node "must move to a new identity". | REVOCATION §9.1 (line 538); `device_cert.rs:509-532` |
| E13 | PairInit and the indexed session refuse equal addresses, so two devices of one identity cannot hold a session. | `pair_init.rs:175-186`; `atsam_indexed_session.rs:196-204` |

### 1.3 Consequences

1. **Compromising one install compromises the identity permanently.** The address *is* the key, and V1 cannot rotate it (IDENTITY_V1 §1.1; Continuity V2 §0, §13.3). Because of E8, a memory-disclosure or RCE bug in any daemon parser (RLB1 JSON, PairInit, envelope) is enough; local malware is not required.
2. **The attacker gets full minting power:** device certificates (E1), prekeys (E5), PairResponses (E3), RVDR1 records (REVOCATION §1.3, line 43), and alias, capability and peer records.
3. **Revocation cannot contain it.** There is one lineage, so revoking it is identity suicide (E12). RVDR1 §2.2 only forbids *reusing* identifiers, and the seed holder can mint a fresh lineage at will. G5 playbook A ("stolen device, seed safe", [`G5_CROSS_STACK_REVOKE_POLICY.md`](../engineering/G5_CROSS_STACK_REVOKE_POLICY.md) §2.3) can never actually occur.
4. **Revocation is local only** (E11). Peers that are connected keep accepting a revoked device, not only partitioned ones (waiver §4.5). `partition_lag_allows_stale_auth` encodes this as a known allow (`device_sync.rs:571-580`).
5. **The 365-day expiry is no backstop**, because whoever holds the seed reissues (E1).
6. **Multi-device is blocked** by E2, E5 and E13.
7. **There is no deniability** (waiver §4.4).

What already works: the lower layers are device-ready. `verify_init` takes the address from `cert.user_ed_pub` and the signer from `cert.device_ed_pub` (`pair_init.rs:432-443`, `:487`). `AuthorizedEndpointDevice` requires signer == `cert.device_ed_pub` (`indexed_session_store.rs:317`). Sessions are keyed per device pair (`indexed_session_store.rs:1752-1759`, `:3262-3277`). RVDR1 already denies whole lineages. The collapse lives in issuance, RLB1, transport binding, the caches, and the call sites.

## 2. Goals and non-goals

**Goals**

- **G1 Identity root offline or rarely used.** No routine operation uses the root: connecting, PairInit, messages, ACKs and prekey rotation all run without it. `raven-node` never holds it.
- **G2 Per-install device keys.** Each install generates its own Ed25519 and X25519 keys in the protected store and never exports them. Every certificate carries the device's proof-of-possession co-signature.
- **G3 Revocation that reaches contacts** within explicit freshness bounds (§5.9).
- **G4 A recovery story** for device loss, device compromise, root loss and total loss (§5.10).
- **G5 Backwards compatibility.** Contacts stay pinned by identity key and keep working. Collapsed certificates from identities that have not migrated stay valid. Each install re-certifies once.
- **G6 No regression in authentication** (§5.13).
- **G7 A testable containment property.** An attacker who fully controls install D gets D's keys, sessions and local history. They can act as D toward contact V only until V learns that D is excluded, or until D's certificate or the DeviceSet expires. They cannot enroll, renew or re-include devices, sign a DeviceSet, or impersonate another device. They can revoke another device only if D holds a pre-signed revocation for it (§5.9).

**Non-goals.** Forward secrecy and post-compromise security inside a session (ratchet design; waiver §4.1). Deniability (§4.4). Recovery after root compromise (Continuity V2). Instant global revocation (REVOCATION line 16). MLS (§4.1). Preventing malware on an install ([`THREAT_MODEL`](../THREAT_MODEL.md) §3.16): this design contains compromise, it does not prevent it. Hiding the device count from contacts. Swift parity, which is off-main and still required before any Apple claim.

## 3. Threat model

Assumptions: Ed25519 is EUF-CMA with strict verification (IDENTITY_V1 §1.3); X25519 is sound, and Noise XX authenticates statics with KCI resistance; verifier clocks are within `MAX_PREKEY_FUTURE_SKEW_MS`; ceremonies run on an uncompromised custody install; users compare the short authentication string (SAS) at enrollment.

| ID | Adversary or event | Today (collapsed) | With this design | Residual |
|---|---|---|---|---|
| T1 | Stolen locked non-custody device | Keystore strength only (THREAT_MODEL §3.6). If the seed is extracted, the identity is lost for good. | Only the device key is at risk. The owner revokes; contacts drop it at the next contact or push, or at expiry. | History stored on the device; isolated contacts per §5.9 |
| T2 | Stolen unlocked or coerced device | Out of scope (§3.7); the identity is lost | Same as T3 | — |
| T3 | Malware or daemon RCE on a non-custody install | Seed in daemon memory (E8): permanent identity compromise, attacker can mint everything | Device key, its sessions and its history only. Cannot mint certificates, DeviceSets or revocations, or renew. | No PCS within a session (waiver §4.1) |
| T3b | Malware on the custody install (K) | — | Root compromised at the next ceremony. On DPAPI or Secret Service it is compromised immediately unless passphrase-wrapped. | Same as today for that install. Custody O avoids it. |
| T4 | Partitioned or attacker-isolated contact | Never learns of the revocation (no ingest) and trusts the device indefinitely | Accepts until it first talks to any honest device of X, receives a push, or expiry is reached (default 60 days) | Inherent (REVOCATION line 16) |
| T5 | Lost identity root | Equals identity loss (IDENTITY_V1 §1.1) | Devices keep working until expiry, but nothing can be enrolled, renewed or revoked | Migrate before expiry |
| T6 | Cloned data directory or restored backup | Seed not in the data directory on Keychain or DPAPI. With locked-file storage the clone is complete. | Device secrets are in the protected store, bound to the canonical path (`device.binding`), so a clone at another path cannot load them | A perfect clone (same path plus a restored keychain) is undetectable; session state forks (P6) |
| T7 | Downgrade to v1 or collapsed | n/a | Contacts pinned to v2 refuse v1. After sunset, the collapsed lineage is denied. | Before the first v2 contact, an attacker can force v1, which is today's level |
| T8 | Malicious contact: certifies someone else's device key, poisons caches, floods revocations | Avoided only by banning separate device keys (`lan_dispatch.rs:80-88`) | Proof of possession; caches keyed by (identity, device); RVDR1 scoped per identity with quotas (REVOCATION §5.2.1) | Deny-DoS limited to that identity |

## 4. Options and trade-offs

### 4.1 How devices are authorized

| Option | Containment of one install | Root use | Complexity | Verdict |
|---|---|---|---|---|
| **A.** Identity-signed certificate plus device co-signature (two tiers) | Yes, except the custody install | Enroll, renew, revoke | Low: extends the V1 certificate and RVDR1 | **Recommended** |
| **B1.** Signal-style linked devices, which by Signal's public design share the account identity key | None; this is today's collapse with more copies | None | Low | Rejected (fails G1, G2, G7) |
| **B2.** WhatsApp-style: the primary holds the identity key and signs the companion list, as in its published multi-device paper | Companions yes; the primary no, and it must stay online | Frequent | Medium | Subsumed: it is A with custody K on the primary |
| **C.** Matrix-style intermediate key: an offline master signs an online self-signing key, which certifies devices | Self-signing key holder not contained, but recoverable through the master | Rare | Medium-high: a new record, chain validation and revocation | Deferred. It duplicates the Continuity V2 operational key (§3.2), which V1 cannot express without inventing a mini-V2. |
| **D.** An MLS group per identity or conversation | Gives PCS and O(log n) fan-out | — | High: needs ordered commits (a delivery service), which a partitioned serverless network lacks; credentials still need certificates | Not justified for 1:1 chats with up to 16 devices. Revisit with communities, which already plan MLS leaves (Continuity V2 §8.4). |

**Why proof of possession is load-bearing.** Without the device's co-signature, identity M can certify Alice's device key under M. Everything keyed by a device key could then be poisoned or misattributed: the ephemeral cache (`lan_dispatch.rs:66-67`, `:120-126`), the durable caches, sessions found by remote device, and blocks. Today's code avoids this only by refusing separate device keys (`lan_dispatch.rs:80-88`; test `stranger_cannot_poison_contact_cache_via_foreign_device_key`, `:2962`). With the co-signature, a device consents to exactly one identity and one exact certificate core.

### 4.2 Identity-root custody

| Custody | Protects the root from malware on that install? | UX | Verdict |
|---|---|---|---|
| Keystore readable by the daemon (today) | No: the root is in daemon memory | Invisible | Rejected |
| **K** Keystore item that only `ash` reads, used only in ceremonies, with a recovery phrase | macOS: the Keychain trusts only the creating program (`macos_keychain.rs:3-6`), so other binaries get a prompt. Windows DPAPI: the blob is protected without optional entropy (`identity_store.rs:825-831`), so any process of the same user can decrypt it, and K **requires** a passphrase wrap (Argon2id). Linux Secret Service: in practice any session client can read an unlocked collection, so a passphrase wrap is required there too. | One confirm prompt per ceremony | Default |
| **O** Offline recovery phrase only (24-word BIP39 encoding of the 32-byte seed) | Yes, except while it is typed on the install performing the ceremony | Type the phrase per ceremony | Recommended for high-risk users |
| H Hardware Ed25519 token | Yes (non-exportable) | Plug in per ceremony | P6 |
| Guardians or threshold | — | — | Continuity V2 §4-§5, not V1 |

### 4.3 Revocation distribution

| Mechanism | For | Against | Decision |
|---|---|---|---|
| Owner pushes to every contact (a dial carrying only RLB2; mailbox later) | Fast for contacts that can be reached | Shows contacts when a device is lost; unreachable contacts wait | Yes, in P3 (Q9) |
| Piggy-back on every RLB2: the sender identity's DeviceSet and RVDR1 records, plus the receiver's own identity set if the sender holds a newer one | Free; no new message type; works through any honest device | Reaches only peers that talk to an honest device | Yes, in P2 |
| Third-party gossip (Y forwards X's revocations to Z) | Reaches isolated peers | Leaks the social graph: Y must know that Z knows X | No, by default |
| Public publication (DHT or mailbox keyed by identity) | Reaches anyone who looks | Lookup privacy; those carriers are disabled | Later, as an umbrella public record class |
| Freshness epoch = DeviceSet generation with positive membership | Exclusion works even if the RVDR1 is withheld; supports suspend and resume; staleness bounded by set expiry | Needs an amendment to ID Resolution §3.1 rule 6 (line 150); each generation needs the root | Yes (Q3) |
| Minimum epoch inside the signed PairInit | Auditable "I had seen generation g" | RVPI1 is a fixed 2788 bytes; the value is advisory, since acceptance uses the verifier's own pin; cleartext PairInit would leak device-change timing (PairInit §7) | Not in V1. Offer for PairInit V2 before it is approved (Q6). |
| Short certificate lifetime | A hard bound for isolated verifiers | Each renewal needs the root | Yes: 60 days by default |
| Pre-signed revocations | Revoke from any surviving device without the root | Whoever holds one can deny service to that device | Yes, with opt-out (Q8) |

### 4.4 Deniability

Today there is none. PairInit, PairResponse, every envelope, every ACK and the transport bind are Ed25519 signatures by the long-term identity key (waiver §4.4).

This design does **not** add message deniability. Device signatures on PairInit, envelopes and ACKs remain transferable proofs and chain to the identity through public certificates; proof of possession makes that chain stronger evidence, not weaker. There is one small improvement. The v2 transport authenticates the device by Noise static Diffie-Hellman only (§5.6). The RIH1 hello it replaces signs the handshake hash, which is transferable proof of a live connection at a given time (`internet.rs:124-152`).

Real deniability would need two changes: session MACs instead of envelope and ACK signatures, and DH-based (PQXDH-like) authentication instead of the PairInit signature. Both conflict with `RAVEN_ENVELOPE_V1` §6.2 step 8 (authenticate the device before AEAD) and PairInit §3. That work belongs with the ratchet design. Adding a channel-bound device signature to LAN v2 (Q11) would make the transport less deniable.

## 5. Recommended design

### 5.1 Keys, custody, and type separation

| Key | Location | Uses | Frequency |
|---|---|---|---|
| Identity root (Ed25519 seed; RavenAddressV1) | Custody K or O; never in `raven-node` | RVDC2 identity signature, DeviceSet, RVDR1, pre-signed revocations, alias, capability records | Ceremonies only |
| Device signing key (Ed25519) | Protected-store item `app.raven.node.device`, account = H(canonical data dir), plus a `device.binding` file modelled on `identity_store.rs:200-252` | PairInit, PairResponse, OOB wrappers, envelopes, ACKs, PrekeyBundleV2, proof of possession, PeerRecord | Online |
| Device agreement key (X25519) | Same item; replaces `device_x25519.secret` (E10) | Noise static (v2), per-device sync sealing | Online |
| Derived keys | From the device seed only (libp2p key under `raven/libp2p-peer-key/v2`) | Transport identifiers | — |

Two new newtypes enforce the split: `IdentityRoot` and `DeviceKey`. Only `IdentityRoot` exposes certify, DeviceSet, revoke, alias and capability signing. Only `DeviceKey` is accepted by `AuthorizedEndpointDevice`, `wrap_oob_wire`, `PrekeyBundle::sign`, PairInit and PairResponse construction, and the transport. A clippy `disallowed-methods` rule bans `Identity::seed_bytes` outside `identity_store`.

Ownership of the device item follows `2026-10-daemon-owned-secrets.md` (`ash` requests signatures over IPC) if that design lands. Otherwise both binaries read the item, as both read the seed today (waiver §4.7).

### 5.2 `RavenDeviceCertificateV2` (RVDC2)

A strict binary record with fixed order, like RVDR1 §3:

```text
magic "RVDC2\0\0\0" | version 0x02 | suite 0x01
identity_address (44 ASCII) | identity_ed_pub (32)
lp(device_id)            u16be length, 1..64 bytes (RVDR1 §2.3)
device_ed_pub (32) | device_x_pub (32)
cert_serial u64 | issued_at_ms u64 | not_before_ms u64 | not_after_ms u64
capabilities u64         device-scoped namespace of IDENTITY_V1 §2
device_pop_sig (64) = Sig_device  (lp("rvn1/devcert-pop/v2") || core)
identity_sig  (64)  = Sig_identity(lp("rvn1/devcert/v2")     || core || device_pop_sig)
core      = every byte from version through capabilities
cert_hash = SHA-256(lp("rvn1/pair-devcert/v2") || exact RVDC2 bytes)
total length = 320 + |device_id| bytes
```

Rules:

- **Domain hygiene, for every record in this design.** Each new signing or hash input begins with `lp(domain)`. Every existing input begins with an ASCII domain or magic, never `0x00`, while every new input begins with the length high byte `0x00`; the two can never be equal. This is needed because `rvn1/pair-devcert/v2` extends the V1 domain `rvn1/pair-devcert`, and in V1 the bytes after that domain are an attacker-choosable identity key. Vectors include cross-version negatives.
- Both signatures use strict verification, and the address must equal encode(identity).
- `device_ed_pub ≠ identity_ed_pub`; collapsed certificates exist in V1 only.
- `not_after − not_before` is at most 180 days. The default is 60 days, with `not_before` backdated by `LOCAL_CERT_BACKDATE_MS` (`device_cert.rs:330`).
- `device_id` is `ash-` plus 10 random base32 characters and is never reused. Today every install is `ash-primary` (`lan_dispatch.rs:663-664`).
- Renewal is a new RVDC2 with the same lineage, a new serial and a fresh proof of possession. `cert_serial = max(previous + 1, issued_at_ms)`, so it strictly increases per identity even when the root is used from different places (custody O).
- RVDR1 §2.1 needs a one-line amendment: an RVDR1 targeting an RVDC2 carries the `cert_hash` above. Lineage denial by id and keys works unchanged (`device_sync.rs:494-524`).

### 5.3 `RavenDeviceSetV1`: freezing the core of ID Resolution §3.1

```text
magic "RVDS1\0\0\0" | version 0x01 | suite 0x01 | identity_address | identity_ed_pub
generation u64 | issued_at_ms u64 | expires_at_ms u64
flags u8   bit0 AUTHORITATIVE (positive membership), bit1 LEGACY_COLLAPSED_RETIRED
n_certs u8 (1..16), then that many [u16 len || RVDC2]
n_revoked u8 (0..64), then that many RVDR1 claim_digest (32)
prev_set_digest (32, zero for the first set)
identity_sig (64) over lp("rvn1/device-set/v1") || all of the above
```

Rules:

- `generation = max(prev + 1, issued_at_ms / 1000)`. A root that has lost track of the previous set (recovery, custody O) still lands above it.
- Verifiers pin the greatest (generation, digest) per identity. The same generation with different bytes is equivocation and fails closed (ID Resolution rule 7, line 151). A lower generation is stale and ignored.
- `expires_at` is at most `issued_at` + 180 days; the default is 60 days.
- Under AUTHORITATIVE, a device is **admissible** for new PairInits, messages and ACKs only if three things hold: it is listed in the greatest pinned set, the set and its certificate are unexpired, and no RVDR1 covers it. Leaving a device out excludes it, which is reversible ("suspend"). RVDR1 remains the sticky, irreversible part. This amends ID Resolution rule 6 for authoritative sets only (Q3).
- Prekey and introduction references stay outside this core until ID Resolution freezes them; a trailing extension block is reserved.

### 5.4 `RavenPrekeyBundleV2`

V1's fields, except that `identity_ed25519_pub` is replaced by `identity_ed_pub || device_ed_pub || device_cert_hash`. The domain is `rvn1/prekey/v2`, length-prefixed per §5.2, and the bundle is **signed by the device key**. The store key is `SHA-256(lp("rvn1/prekey-key/v2") || identity || device_ed_pub)`, which removes the one-bundle-per-identity limit (PREKEY_BUNDLE §4).

Rollback pins become per device, so a reinstall becomes a new device instead of a `PEER_PREKEY_RESET` (`lan_dispatch.rs:1095-1101`). The PairInit digest is `SHA-256(lp("rvn1/pair-prekey/v2") || signing_bytes || sig)`.

### 5.5 RLB2 offer, replacing RLB1's embedded JSON (`lan_rlb1.rs:24-43`)

```text
"RLB2" | 0x02 | kind 0x02
u16 len || RVDC2                    sending device
u16 len || PrekeyBundleV2           sending device
u32 len || RavenDeviceSetV1         sender identity, greatest known; trusted peers only,
                                    strangers receive (generation, digest)
u8  n   || n × [u16 len || RVDR1]   sender identity, at most 16, newest first
u32 len || peer_identity_devset     optional: the receiver identity's set, only if newer
u64 seen_generation_of_receiver_identity
```

The receiver accepts in this order:

1. Bounded strict decode.
2. Transport binding (§5.6).
3. RVDC2 verification.
4. Contact gate on the identity (`peer_is_trusted` semantics; umbrella line 144). Nothing from a non-contact is persisted; strangers stay ephemeral, as today (`lan_dispatch.rs:96-128`).
5. For contacts only: DeviceSet verification and pin.
6. For contacts only: RVDR1 union-apply under the REVOCATION §5.2.1 quotas.
7. Admissibility and lineage check.
8. The prekey binds to the certificate.

A mid-session RLB2 must name the Noise-bound device, keeping the rule at `lan_dispatch.rs:1528-1535`. Sending the full DeviceSet only to trusted peers matters because the responder answers strangers with its offer today (`raven-node/src/lan_direct.rs:262`, `:278`); a full set would reveal the device list to anyone on the LAN. The side that speaks first sends only the head. Full sets are exchanged mid-session, once both offers are verified and each side knows the other is a contact.

### 5.6 Transport binding: the Noise static key

- **LAN v2.** `Noise_XX_25519_ChaChaPoly_BLAKE2s` with prologue `raven/lan/v2`; LAN v1 has no prologue (`lan_noise.rs:113-114`). The local static is the device X25519 key, and the first transport message in each direction is RLB2.
  - **Binding:** `remote_static == offer.cert.device_x_pub`. The initiator also checks that `offer.cert.identity` is the dialled contact; the responder applies the contact gate.
  - **No bind signature.** XX proves possession of the static key on every connection. The certificate binds the static to the device and the identity, and the proof of possession binds the device to the identity.
- **Internet v2.** The same with prologue `raven/internet/v2`. RIH1 is replaced by RLB2.
- **Downgrade.** Try v2 first. Fall back to v1 only for contacts that are not pinned `transport_min = v2`. The pin is set after the first v2 success with any device of that identity. v1 is refused outright for identities whose pinned set has `LEGACY_COLLAPSED_RETIRED`. `rlb1_matches_noise_identity` (`lan_dispatch.rs:640-642`) is kept for v1 only.

### 5.7 PairInit and PairResponse

The wires are unchanged: RVPI1 is 2788 bytes and RVPR1 is 228 bytes. RVPI2 should adopt the same rules; its `pair_init_v2_002` KAT already assumes "dedicated device X keys" (`ATSAM_HYBRID_RATCHET_V2` line 780). The changes go into a new companion, not an edit of the frozen document (`scripts/freeze_protocol_hashes.sh`):

1. Offsets 332 and 364 may carry RVDC2 `cert_hash` values, and offset 396 may carry a PrekeyBundleV2 hash. A responder with an RVDC2 certificate must present a V2 prekey bound to that certificate. Mixing V1 and V2 records on one side is rejected.
2. Offsets 172 and 204 must equal `cert.device_ed_pub`, which `pair_init.rs:437-443` already enforces. With an RVDC2 certificate they must also differ from the identity key.
3. The PairInit, PairResponse and OOB-wrapper signatures move to the device key (E3).
4. `PairInitTrust` (`pair_init.rs:117`) gains `initiator_admissible` and `responder_admissible` next to the revoked flags, and `verify_init` refuses when either is false.
5. The PairInit validity window must still lie within both certificate windows (`pair_init.rs:457-480`). Renewal opens 21 days before expiry, so even a 7-day PairInit fits.

The DeviceSet generation is not bound into the signed transcript, for three reasons. RVPI1 has no slot for it. Acceptance always uses the verifier's own greatest pin, a fresher set authenticates itself, and stripping a hint only delays learning. And PairInit travels in cleartext on async carriers. The hints ride in RLB2, inside Noise.

### 5.8 How devices and sessions are selected

- **Inbound.** Session lookup by remote device is unchanged (`indexed_session_store.rs:3262-3277`), and trust is decided by identity.
  - Chat history must be keyed by the **identity**. `lan_dispatch.rs:1421-1429` and `:1442-1450` currently pass `device_ed_pub`.
  - Old rows are already identity-keyed, because device equals identity today. A new `peer_device_hex` field records which device a row came from.
- **Outbound (P2).** Resolve the contact's identity, dial its target, and accept the device that answers with an admissible RLB2. Then reuse or create the session with that device, applying the logic of `ash/src/pair_init_lab.rs:350-361` by identity.
  - Offline staging (`pair_init_lab.rs:465-476`) uses the admissible device with the most recently confirmed session.
  - The UI says "delivered to Bob (device 'laptop')". `DELIVERED_TO_DEVICE` is tracked per device (umbrella line 134).
  - The IPC `SealUnderSession` `peer_hint` (`lan_dispatch.rs:1656-1670`) accepts an identity or a device; an identity resolves by the same rule.
- **Fan-out (P5, deferred).** Seal once per admissible recipient device under a shared logical message id. This needs content framing, because the indexed-session payload is UTF-8 text only (`lan_dispatch.rs:1773-1775`). Copies to the sender's own devices need a new own-device session profile (E13).
  - **Why defer:** contacts have one dial target each (`lan_dial`); Private Rendezvous is production-disabled; and O(n·m) PairInits is acceptable for up to 16 devices.

### 5.9 Revocation, end to end

1. `ash device revoke <label|device_id>` runs on the custody install, or on any device that holds a pre-signed RVDR1 for the target.
2. The user confirms (§5.12).
3. **Ceremony.** Mint an RVDR1 for the full lineage, plus DeviceSet g+1 without the device. Then follow REVOCATION §8: journal, local apply, cleanup work items (§6.3: close sessions, cancel the outbox), and only then touch the network.
4. **Fan-out.** Push-dial every known target of every contact (RLB2 only, with persisted backoff). Include the update in every later RLB2.
5. **Contacts.** Union-apply the RVDR1 and pin g+1. Close sessions bound to the revoked certificate, judged by the session-bound certificate (REVOCATION line 535; `lan_dispatch.rs:1607-1636`). Refuse its PairInits, messages and ACKs. Show "Alice removed a device", which closes SPRINT0 gap G3.
6. **The revoked device.** If it is honest (lost, not stolen), it learns from any peer's `peer_identity_devset` and wipes its keys.
7. **Status.** Show progress per contact. Never say "revoked everywhere" (REVOCATION §7.3 #3).

**Pre-signed revocations.** At enrollment the root also signs an RVDR1 for the new device. It is stored on the owner's *other* devices and in the recovery kit, never on the target device. Publishing one needs no root and contacts apply it as usual (RVDR1 is sticky on its own); the matching DeviceSet exclusion follows at the next root ceremony. Stop minting legacy `rvn1/devrevoke/v1` records, but keep reading them (`device_sync.rs:76-131`).

| Verifier V | Accepts the revoked device S until |
|---|---|
| Talks to any honest device of X after the revocation | That RLB2 exchange |
| Reachable for a push | The push is delivered |
| Isolated by S | min(S.not_after, pinned set's expires_at): 60 days by default, 180 at most. After that new PairInits are refused, and existing sessions end within 24 h (up to 7 days for older peers). |
| Has learned g+1 or the RVDR1 | Never again: pins are monotonic and RVDR1 is sticky |
| Today | Forever; and the attacker reissues with the seed |

### 5.10 Recovery

| Event | Root | What the user does | Residual |
|---|---|---|---|
| Device lost or stolen | Safe | Revoke (pre-signed or by root), then enroll a replacement on a new lineage | Its stored history; isolated contacts per §5.9 |
| Malware on a non-custody install | Safe | Same as above; a reinstall is a new device | Traffic until contacts learn of the revocation |
| Custody install compromised or phrase stolen | Compromised | V1: a new identity, and contacts re-verify (G5 playbook B). A V2 bridge works only if it was created beforehand (Continuity V2 §13). | Permanent for that address |
| Root lost | Lost | Devices keep working until expiry; `ash` warns 21 days ahead; migrate to a new identity | Unrecoverable (IDENTITY_V1 §1.1) |
| All devices lost, phrase kept | Safe | `ash init --restore` on a fresh data dir. The generation uses the time floor, the latest set is learned from contacts (`peer_identity_devset`), and unknown lineages are revoked. | — |

The recovery phrase is the 24-word BIP39 encoding of the existing 32-byte seed (the raw entropy, not a PBKDF2 output). It is shown once at init or migration and confirmed by re-entering 3 words. It never appears in argv, environment variables or logs (IDENTITY_SEED_STORAGE).

### 5.11 Migration from the collapsed model

Each install moves from **C** (collapsed, today) to **M** (migrated, compat on) to **S** (sunset).

1. **Migrate.** Upgrading offers `ash identity migrate` (and `ash doctor` points to it). It generates fresh device keys in the protected store with a new `device_id`. The X25519 key is never the old `device_x25519.secret`, because sunset revokes that key. It then issues an RVDC2 with proof of possession signed by the existing seed, and creates DeviceSet g (time floor, AUTHORITATIVE). It also produces pre-signed RVDR1 records, displays the phrase, and sets the custody choice.
2. **Compat mode.** The collapsed V1 certificate stays valid but is not renewed past sunset. `raven-node` can still reach the seed, but only to answer v1 peers. **No containment while compat is on**, and `ash` must say so.
3. **Contacts and state.** Contact pins are unchanged: they are identity keys, and the whoami card already omits `device_ed_pub` (`cli.rs:6996`). v2 contacts pin transport v2; v1 contacts notice nothing. Collapsed sessions expire within 24 h to 7 days. History needs no rewrite. A secondary install cannot talk to v1 peers at all, because they reject any non-collapsed certificate (E2).
4. **Sunset.** Triggered when `ash` reports no v1 contacts left, or on the owner's chosen date (Q5). Issue DeviceSet g+1 with `LEGACY_COLLAPSED_RETIRED`, plus an RVDR1 for the collapsed lineage (`device_ed_pub` = the identity key, `ash-primary`, the old X25519 key, the certificate hash). v2 verifiers then deny collapsed certificates for that identity forever. Compat goes off and the daemon loses access to the root.
5. **Honesty about the past.** Every install that existed before migration has held the seed (E8, E9). Migration contains only *future* compromise. If an install may already have been compromised, the only remedy is a new identity, or Continuity V2.
6. **Two installs, one identity.** This happens only through a manual seed copy; there is no supported path. If both migrate independently, the higher generation wins and the other device is excluded (fail closed) and flagged. `ash device reconcile` then issues a combined set.

### 5.12 UX in `ash`

```text
$ ash device list
Identity rvn1q…x7  fingerprint If4x-36FU-omFi   device list gen 1791331200, expires in 41 days
  * this device  "work-mac"   ash-7k2mq9xv4c   device fp 3F9a-QwK2   cert expires in 41 days
  * active       "phone"      ash-p4e8w0tnz2                          cert expires in 41 days
  - suspended    "old-mac"    ash-q19d7g2m4b   not in the current list
  x revoked      "stolen-pc"  ash-v0a1zr3k8e   revoked 2026-10-02 · 9 of 12 contacts have the new list
Identity key: on this Mac, asked before every use · recovery phrase confirmed 2026-09-30
```

- **`ash device add`** (new install) and **`ash device approve`** (custody install). The join code is the identity address plus a one-time secret. Enrollment runs Noise `XXpsk3` with prologue `raven/enroll/v1`, and both screens show 6 SAS words from the handshake hash. The approve screen says: "'phone' will be able to read and send messages as you to all your contacts. Approve only a device you are holding." The user types the label to confirm.
- **`ash device revoke`.** It warns: "Revoking 'stolen-pc' (device fp …). Contacts that receive this stop accepting it. Contacts that are offline, or reachable only through that device, keep trusting it until they hear from another of your devices, or at the latest until 2026-11-30. It keeps any messages it already received. This cannot be undone."
  - The user must type the label.
  - It refuses the current device unless `--this-device` is given.
  - In the collapsed state it refuses with the E12 explanation. This is a quick win, independent of the rest.
- **`ash device suspend|resume`** changes only the DeviceSet and is reversible.
- **`ash identity status|renew|move-offline|export-phrase|restore`.** Starting 21 days before expiry, a banner asks the user to run `ash identity renew`. One ceremony renews every device, the DeviceSet, and the alias and capability records.
- **Contact side.** `ash contact show bob` lists Bob's devices. A one-line notice reads "Bob added a device 'laptop'". Device keys are never offered as safety numbers: users compare only the identity fingerprint (IDENTITY_V1 §3).

### 5.13 Authentication invariants that must not regress

1. The contact book, keyed by identity key, stays the only trust root (umbrella line 144). Device keys are never pins.
2. Every signature is verified strictly, including the proof of possession.
3. The transport peer equals the certificate's device (static equality), and the certificate's identity equals the contact.
4. A mid-session offer cannot switch device (`lan_dispatch.rs:1528-1535`).
5. PairInit keeps its bindings: address from the certificate identity, signer equal to the certificate's device key, and certificate and prekey digests (`pair_init.rs:432-456`).
6. Revocation and admissibility are judged on the session-bound certificate, never a cache entry (`lan_dispatch.rs:1607-1636`).
7. Only `*_checked` loaders are used, and corruption fails closed (SPRINT0 G2).
8. Collapsed V1 certificates are accepted only from identities with no pinned v2 set, or before `LEGACY_COLLAPSED_RETIRED`.

## 6. Phased plan

| Phase | Scope | Effort (eng-weeks) | Exit criteria |
|---|---|---|---|
| **P0 Spec and vectors** | Companion `RAVEN_DEVICE_KEYS_V1` (RVDC2, RVDS1 core, PrekeyBundleV2, RLB2, v2 transport binding, PairInit trust amendment); amendments to RVDR1 §2.1 and ID Resolution rule 6; Python reference with positive and negative vectors. Quick wins: the revoke guard (§5.12), the `seed_bytes` lint, and moving `device_x25519.secret` into the protected store. | 3 | Owner approval; vectors reproduced in Python and Rust |
| **P0′ Formal model** | Tamarin model of §7.3, in parallel with P0 | 2-3 | Lemmas proven, or counterexamples fixed in the spec |
| **P1 Core** | `DeviceKey` and `IdentityRoot`, the device store and its binding, codecs, a per-device PrekeyStore and caches, history keyed by identity | 3 | Unit tests and vector parity; nothing changes on the wire |
| **P2 Transport and sessions** | LAN and Internet v2, RLB2, PairInit trust v2, admissibility, downgrade pins, compat dual stack, migration for single-install users | 4 | Two-process LAN tests pass for v2↔v2, v2↔v1 and compat, plus every §7.2 negative |
| **P3 Revocation** | `ash` mints RVDR1 instead of legacy records; RLB2 ingest; the REVOCATION §6 journal and anchor subset; cleanup items; push fan-out with persisted retries; pre-signed revocations; contact notices | 4 | PT1 to PT9 green |
| **P4 Multi-install and custody** | Enrollment (XXpsk3 with SAS); approve, revoke and suspend UX; custody K and O; the phrase; the renewal ceremony; per-device sealing for contact sync (replacing E7); sunset tooling | 3-4 | Two installs of one identity work on a LAN; a sunset rehearsal |
| P5 Fan-out (deferred) | Per-device fan-out, logical message ids, an own-device sync profile | 5-6 | Checklist §39 delivery items closed |
| P6 Hardening | Device keys wrapped by Secure Enclave or TPM; clone heuristics; Swift parity; external review | Open | External review passed |

P0 to P4 add up to about 17 to 18 engineer-weeks plus the modelling: roughly four months for one engineer with a reviewer. Waiver risk 5 retires after P3, and risk 3 retires per identity at its sunset.

## 7. Verification plan

### 7.1 Positive vectors

The Python reference generates these, as `generate_rvn1.py` does today; Rust must match byte for byte, and Swift follows off-main.

- `device_cert_v2/valid_001` (core, proof of possession, identity signature, `cert_hash`).
- `device_set/valid_001` and `renewal_002` (generation floor, flags, digest).
- `prekey/bundle_v2_001`.
- `lan/rlb2_offer_001` and `lan/noise_xx_v2_001` (fixed ephemerals, following `noise_xx_handshake_001`).
- `atsam/pair_init_v1_trust_v2_001` (RVPI1 with RVDC2 and PrekeyBundleV2 digests, signed by the device key).
- `device_revocation/rvdc2_target_001`.
- `enroll/xxpsk3_sas_001`.

### 7.2 Negative vectors

Each expects an exact error code.

- **N1** An RVDC2 where `device_ed_pub == identity_ed_pub`.
- **N2** The proof of possession is missing or zero.
- **N3** The proof of possession was made by a key other than `device_ed_pub`.
- **N4** A proof of possession made for a different identity is reused (unknown key-share).
- **N5** The identity signature omits or swaps the proof of possession.
- **N6** The lifetime exceeds 180 days, or `not_before` exceeds `issued_at` plus the skew.
- **N7** `device_id` is empty, 65 bytes long, or not UTF-8.
- **N8** The V1 hash domain is applied to RVDC2 bytes inside a PairInit.
- **N9** A PairInit that references an RVDC2 is signed by the identity key.
- **N10** A PrekeyBundleV2 is signed by the identity key, or bound to another device's certificate.
- **N11** A DeviceSet has the same generation with different bytes, a lower generation, a device signature, more than 16 certificates, or a certificate of a different identity.
- **N12** A device absent from an AUTHORITATIVE set sends a PairInit, envelope or ACK.
- **N13** v2 Noise where the remote static ≠ `cert.device_x_pub`.
- **N14** v1 is used toward a v2-pinned contact, or a collapsed certificate arrives after `LEGACY_COLLAPSED_RETIRED`.
- **N15** A mid-session RLB2 names a different device.
- **N16** An RLB2 is truncated, oversized, has trailing bytes, or declares hostile lengths (following `lan_rlb1.rs:153-172`).
- **N17** A renewed certificate reuses a revoked lineage identifier.

### 7.3 Formal model

Today there is none (waiver §4.2). Proposed: Tamarin, with ProVerif as an alternative, stored in `protocol/reference/formal/`.

**Roles:** custody, device, peer. **Rules:** enroll (with proof of possession), renew, suspend, revoke (RVDR1 plus g+1), connect (XX with static = `cert.x`), PairInit (device signature over the certificate hashes), accept. **Compromise rules:** `RevealDevice(D)` and `RevealRoot(X)`.

| Lemma | Property |
|---|---|
| L1 Device authentication | Injective agreement on `init_hash`. If V accepts a PairInit from (X, D), then D signed it and X certified D, unless D or X's root was revealed beforehand. |
| L2 Containment | `RevealDevice(D)` never leads to acceptance attributed to any D′ ≠ D, nor to any new certificate or set. |
| L3 Enrollment authority | Every accepted certificate and set was signed by the root. |
| L4 Monotonic exclusion | After V pins a generation that excludes D, or applies an RVDR1 covering D, V accepts nothing more from D. |
| L5 No unknown key-share | An accepted device maps to exactly one identity. |
| L6 Transport binding | An XX-authenticated static corresponds to exactly one admissible certificate of the dialled identity. |

The model abstracts ATSAM to a root derived from the transcript. Its stated limit is that per-session device separation rests on distinct roots, because the session context binds only addresses (`ATSAM_INDEXED_SESSION_PROFILE_V1` §1).

### 7.4 Partition, propagation and interop tests

**PT1 to PT9** run in process with a simulated clock (following `device_sync.rs:660-692`), and at scale by extending `raven-core/tests/network_sim_1000.rs` with identities of 1 to 4 devices.

| Test | Scenario | Expected |
|---|---|---|
| PT1 | A1 revokes A2 while B is online | B refuses A2 after one push |
| PT2 | B is reachable only through A2 | B accepts A2 until exactly min(cert, set expiry), then refuses |
| PT3 | B talks to C, a contact of A | No third-party gossip, so B still accepts A2 (documented) |
| PT4 | A2 replays generation g after B pinned g+1 | Refused |
| PT5 | A2 forges a g+1 that includes itself | Signature failure |
| PT6 | A2 publishes a pre-signed revocation of A1 | A1 is denied (DoS); A1 recovers only by enrolling a new lineage |
| PT7 | Two different sets with the same generation | Equivocation; fails closed |
| PT8 | Crash at each REVOCATION §6 step | Recovers per `crash_replay_order_001.json` |
| PT9 | Mixed versions: v1 peer with compat primary, v1 peer with secondary, and the post-sunset path | Compat works, the secondary is refused, and sunset refuses collapsed certificates |

Also:

- Two-process localhost runs following the O6 M3 harness (`docs/engineering/baseline-freeze/artifacts/o6-m3-two-node-rdap/`).
- Fuzzing of the RVDC2, RVDS1 and RLB2 decoders (`tests/fuzz_smoke.rs` pattern).
- A trybuild compile-fail test that signing a PairInit with `IdentityRoot` does not compile.
- Platform checks: on macOS, `raven-node` cannot read the root item without a prompt. On Windows and Linux, custody K without a passphrase wrap is refused.

## 8. Risks and open questions for the owner

**Risks**

- **R1 Compat mode.** It puts the root back in the primary's daemon, so there is no containment until sunset, and a single lagging contact can stall sunset indefinitely. A date is needed (Q5).
- **R2 Past compromise.** Migration does not heal it. The wording must never suggest "your identity is now protected" for an identity that existed before migration.
- **R3 Renewal fatigue.** Prompts every few weeks may push users toward long certificates, or toward custody K over O. Mitigations: one batched prompt, and owner-set defaults.
- **R4 Availability.** If the root is unavailable at renewal time (for example, custody O while travelling), the identity becomes unreachable for new sessions. Fail closed by design.
- **R5 Metadata.** DeviceSets reveal device count and enrollment and revocation timing to contacts, and pushes reveal losses. RVDR1 is public by design (REVOCATION §4.2).
- **R6 Clocks.** Expiry relies on verifier clocks; a wrong clock extends the §5.9 bounds.
- **R7 Perfect clones** are undetectable (T6); hardware wrapping in P6 helps.
- **R8 Pre-signed revocations** let any holder deny service to that device.
- **R9 Scope and parity.** Three new records, a v2 transport and three spec amendments, with Swift parity off-main. Doc changes go through the freeze-hash process.
- **R10 Single-device delivery in P2 to P4.** Messages land on one device, which will confuse users until P5.
- **R11 Sibling designs.** RVPI2 (ratchet) must adopt the same trust-record rules, and device-key ownership depends on the daemon-owned-secrets design.

**Open questions**

- **Q1 Default custody:** K (recommended) or O? Should a passphrase wrap be mandatory on Windows and Linux?
- **Q2 Lifetimes:** accept 60 days default, 180 days cap, renewal opening at 21 days, and 16 devices per identity?
- **Q3 Positive membership:** amend ID Resolution rule 6 so that authoritative sets exclude devices they omit?
- **Q4 Intermediate signing key (§4.1 C):** confirm deferring it to Continuity V2?
- **Q5 Compat sunset rule:** a fixed date (for example 90 days after the P2 release), "all contacts on v2", or a per-user choice?
- **Q6 Minimum epoch:** bind it into PairInit V2 before that is approved, or keep it as an advisory RLB2 field only?
- **Q7 Phrase format:** BIP39 English, 24 words of the raw seed? How should localization work?
- **Q8 Pre-signed revocations:** on by default (DoS risk versus speed)?
- **Q9 Proactive push:** push revocations to all contacts by default (privacy versus speed)?
- **Q10 Delivery:** accept single-device delivery until P5?
- **Q11 v2 transport:** keep it deniable with no per-connection device signature, or add a channel-bound one for defense in depth?
- **Q12 Vectors:** keep them additive under `shared-vectors/rvn1/` (as `pair_init_v2` is) or start `rvn2/`?
- **Q13 Alias and capability records:** keep them identity-signed and batched into renewal (alias records currently expire after 30 days: `cli.rs:2495`), or move them to device-signed records with a certificate chain (Alias V2)?

## Appendix A: Uses of the identity key, and where each goes

| Use | Today (`a1d3e1d`) | After |
|---|---|---|
| Device certificate issuance | Identity, automatic (`device_cert.rs:362-370`) | `IdentityRoot`, ceremony only, with the device's proof of possession |
| PairInit, PairResponse, OOB wrappers | Identity (`lan_dispatch.rs:1890`, `:1239`, `:1339-1346`, `:1901-1913`) | `DeviceKey` |
| Message and ACK envelopes | Identity as the endpoint signer (`lan_dispatch.rs:1457`, `:1786`) | `DeviceKey` (the store already checks signer == `cert.device_ed_pub`) |
| Prekey bundles | Identity (`lan_dispatch.rs:598-606`) | `DeviceKey` (PrekeyBundleV2) |
| Noise static | HKDF(identity seed) (`lan_noise.rs:48-60`) | Device X25519 key |
| LAN bind and RIH1 hello | Identity (`lan_noise.rs:74-80`; `internet.rs:142-152`) | Removed (static equality) |
| Contact-sync key | HKDF(identity seed) (`device_sync.rs:172-179`) | Sealed per recipient device |
| libp2p peer key | SHA-256(identity seed) (`raven-swarm/src/main.rs:140-151`) | Derived from the device seed |
| PeerRecord (DHT) | Identity (`discovery.rs:36-41`) | `DeviceKey`, with the certificate attached |
| Alias and capability records | Identity (`cli.rs:2494-2504`) | `IdentityRoot`, batched into renewal (Q13) |
| Revocation | Legacy record (`ext.rs:1103`) | RVDR1 plus DeviceSet, by `IdentityRoot`, or pre-signed |
