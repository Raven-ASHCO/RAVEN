# Daemon-owned secrets: one code identity for every protected secret

| | |
|---|---|
| **Status** | Design proposal for owner decision. It authorizes no code, storage-format or IPC change by itself. |
| **Date** | 2026-10-07 |
| **Baseline** | `fix/code-review-2026-09-29` at `a1d3e1d`. Every `file:line` is at that commit. Another engineer had uncommitted edits in `indexed_session_store.rs`, `lan_dispatch.rs`, `prekey_lifecycle.rs`, `raven-node/src/lan_direct.rs` and `raven-node/src/main.rs` while this was written; re-check lines there before acting. |
| **Retires** | Residual risk 7 of [`WAIVER-LAN-DIRECT-2026-10-07`](../WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md) §4 |
| **Sibling designs** | [`2026-10-per-device-keys.md`](2026-10-per-device-keys.md) (custody of the identity root, §4.2 there), `2026-10-ratchet-fs-pcs.md` (session ratchet) |
| **Proposed risk class** | Phase 1 is packaging. Phases 2 and 3 change secret storage and the confidential IPC path: treat them as R3 under ADR 0004 (Crypto ATSAM + Identity AuthZ acks, no self-merge). |

Path shorthand: `core/` = `node/crates/raven-core/src/`, `ash/` = `node/crates/ash/src/`, `rn/` = `node/crates/raven-node/src/`, `inst/` = `node/scripts/install/`, `sf/` = crate `security-framework` 2.11.1 and `sfs/` = `security-framework-sys` 2.17.0 (the versions in `node/Cargo.lock`), `libc/` = `libc` 0.2.189.

## 0. Summary

- On macOS every Raven secret is a legacy login-Keychain item whose ACL trusts only the program that created it. Raven runs two to four executables (`ash`, `raven`, `raven-node`, `raven-swarm`), all unsigned or ad-hoc signed, so each one meets each item as a stranger, and every rebuild is a stranger again. The read then blocks inside `SecItemCopyMatching` behind a dialog that has no timeout.
- That is the root cause of the owner's "not sent / not stored / not shown" reports: whichever process touched an item it did not create (ash on send, inbox and chat; raven-node on start-up and receive) stopped, and so did everything waiting on its locks.
- Today's Tier 0 watchdog explains the wait after 3 s. It does not shorten or remove it.
- **Recommendation**, in order: (1) one multi-call executable (`raven`; `ash` and `raven-node` become names of the same file), so a single code identity creates and reads every item; (2) one versioned vault item per profile instead of 3 + N items, so a new code identity costs one approval, not one per conversation; (3) the daemon becomes the only process that touches secrets, and the CLI a thin IPC v2 client with typed operations, pagination and a code-identity peer check on macOS; (4) stable code signing (Developer ID; a self-signed certificate for development, with caveats) to bring rebuild prompts to zero.
- Reject SecAccess dual-trust ACLs. Defer the data-protection keychain until Raven ships a signed app bundle.
- **Ships first:** Phase 0 (signing guidance and owner verification, about 1 day) and Phase 1 (single executable, IPC before the identity preflight, keystore state in `Status`, forward-compatible fences; 8 to 11 engineer-days).

## 1. Problem statement

### 1.1 Where the secrets live on macOS

| Service | Holds | Account (one per data dir) | Written by | Read by |
|---|---|---|---|---|
| `app.raven.node.identity` (`core/identity_store.rs:53`) | 32-byte Ed25519 seed | SHA-256 of a domain plus the canonical data dir (`core/identity_store.rs:177-184`) | `SecKeychain::default().add_generic_password`, add-only (`core/identity_store.rs:725-738`) | ash on nearly every command: `init` (`ash/cli.rs:5843-5855`), whoami (`:5856`), status (`:4405`), listen (`:2109`), doctor (`:6346-6347`), send; raven-node start-up (`rn/main.rs:3373-3383`) and every `SealUnderSession` (`rn/ipc_server.rs:349`); raven-swarm (`node/crates/raven-swarm/src/main.rs:137-138`) |
| `app.raven.node.chat-history.v1` (`core/chat_history.rs:218`) | key of the history file and the outbound stage | `history_account` (`core/chat_history.rs:1012-1014`) | add-only (`core/chat_history.rs:1100-1120`) | ash chat, send and inbox poll (`ash/ext.rs:2936`, `:2469-2477`; `ash/pair_init_lab.rs:742-797`); raven-node for every received message (`core/lan_dispatch.rs:195-221`) |
| `app.raven.node.atsam-indexed-session` (`core/indexed_session_store.rs:110`) | per-session roots, chain keys, journals | `<namespace>:<hex record_key>`, **one item per conversation** (`core/indexed_session_store.rs:1036-1043`, `:1091-1093`, `:1787`) | `set_generic_password`, i.e. `SecItemAdd` then `SecItemUpdate` (`core/indexed_session_store.rs:1135-1145`; `sf/src/passwords.rs:133-149`) | ash send, inbox, chat (`ash/pair_init_lab.rs:390`, `:723`; `ash/cli.rs:5114`; `ash/ext.rs:2450-2451`); raven-node receive, ACK, preflight (`rn/lan_direct.rs:324`) |
| `app.raven.node.prekey-lifecycle` (`core/prekey_lifecycle.rs:67`) | prekey private material and claim journal | hash of the canonical data dir (`core/prekey_lifecycle.rs:882-885`) | `set_generic_password` (`core/prekey_lifecycle.rs:596-606`) | raven-node preflight and PairInit responder (`rn/lan_direct.rs:325`); ash on `init`, prekey publish and rotation (`ash/cli.rs:5851`; `ash/ext.rs:3222-3300`; `core/lan_dispatch.rs:562-584`) |

None of these writes sets `kSecAttrAccess`, `kSecUseDataProtectionKeychain` or `kSecAttrAccessGroup`, so all four land in the legacy login keychain with the default ACL: the creating program is the only trusted application.

### 1.2 Why the sibling binary, or a rebuild, blocks

- The ACL names code by its designated requirement (DR). Unsigned or ad-hoc (linker-)signed code has no certificate, so its identity is effectively its cdhash, and every build changes it.
- Raven has several executables. `ash` and `raven` are two `[[bin]]` targets that each compile the same `cli.rs` (`node/crates/ash/Cargo.toml:7-13`; `ash/bin/ash.rs:2-3`; `ash/bin/raven.rs:2-3`), so straight from `target/` they are two identities. `raven-node` is a third (`node/crates/raven-node/Cargo.toml:9-11`) and `raven-swarm` reads the seed too. The installers copy `ash` to `raven` and link `ash -> raven` (`inst/macos_launchd.sh:50-55`; `scripts/release/build_unsigned.sh:19-23`), which leaves two identities in an installed layout.
- The code says so itself (`core/macos_keychain.rs:3-8`), and the debug locked-file override exists precisely to avoid "per-binary ACL prompts" (`core/identity_store.rs:1108-1110`).
- **Every fresh install starts with dialogs today.** The installer runs `raven init` (`inst/macos_launchd.sh:88`), which creates the identity and the prekey state as `raven` (`ash/cli.rs:5843-5855`). The LaunchAgent then starts `raven-node`, whose first act is to read both (`rn/main.rs:3373-3383`; `rn/lan_direct.rs:321-325`). The identity read happens before IPC is bound (`rn/main.rs:3380` runs before `:3393-3397`), so until someone answers a dialog raised by a background process, ash sees a dead service.
- Amplifiers. `load_identity` holds the cross-process identity lock across the Keychain round trip and caches nothing (`core/identity_store.rs:1492-1506`), so a second process waits up to 60 s and fails (`:425-440`). ash's readiness wait is 20 s, stretched 8x when it finds the daemon's `BLOCKED_ON_KEYCHAIN` line by scraping the service log (`ash/ext.rs:85-108`, `:249-263`, `:304-368`). Over SSH there is no dialog to answer at all (`core/macos_keychain.rs:293-299`; `docs/INSTALL_macOS.md:143`).

### 1.3 Prompt arithmetic

Dialogs per new code identity, worst case = (executables that read the item) x (3 + N), with N conversations. For N = 5:

| Layout | Executables reading secrets | Worst-case dialogs |
|---|---|---|
| `node/target/release` today | ash, raven, raven-node (+ raven-swarm for the seed) | 3 x 8 = 24 |
| Installed today (launchd or tarball) | raven (= ash), raven-node | 2 x 8 = 16 |
| Phase 1 (single executable) | raven | 8 |
| Phase 2 (vault) | raven | 1 |
| Stable signing, any phase | raven | 0 after the first approval of each pre-existing item |

Each program only asks for items it touches (ash rarely opens the prekey item), so real counts are lower, but they grow with every conversation and every rebuild.

### 1.4 User impact

- **Not sent:** `ash send` blocks reading the identity, a session or the history key in-process; or `require_local_daemon` (`ash/ext.rs:2215-2223`) gives up because raven-node is stuck in its preflight dialog.
- **Not stored:** raven-node accepts a message, then blocks persisting it (history key, `core/lan_dispatch.rs:195-221`) or loading the session item; the sender sees "queued" or "unconfirmed".
- **Not shown:** `ash inbox` (`ash/cli.rs:5107-5165`) and the chat poller, which runs every 500 ms (`ash/ext.rs:3019-3024`), open the session store and history in-process and freeze.
- Every other raven command queues behind the blocked one (`core/macos_keychain.rs:164-184`).
- **Prompt fatigue is a security cost.** The hint tells the user to choose "Always Allow" (`core/macos_keychain.rs:121-127`, `:293-299`). A dialog after every rebuild trains users to approve any program that claims to be Raven, which is the opposite of what the ACL is for.

### 1.5 Today's mitigation and its limits

- `guarded()` (`core/macos_keychain.rs:186-199`) prints a hint after 3 s and a reminder every 30 s (`:45-49`); the daemon also logs a machine-readable marker (`:119-127`) that ash looks for (`ash/ext.rs:249-263`).
- `scripts/keychain_guard_check.sh` keeps every Keychain call inside `guarded` (allow-list `:27-37`) and runs in CI (`.github/workflows/raven-serverless.yml:114-121`).
- `docs/INSTALL_macOS.md:98-145` explains the dialogs and a self-signed signing recipe.
- Lab and CI avoid the Keychain with debug-only overrides, refused in Release (`core/identity_store.rs:1108-1115`; `core/chat_history.rs:1236-1257`; `core/indexed_session_store.rs:944-961`; `core/prekey_lifecycle.rs:464-475`).
- Limits: a blocked call still cannot be cancelled, the lock waits still cascade, the count still grows with N, and nothing has been tested against a real Keychain (the `a1d3e1d` commit message says the macOS verification used lab backends only).

### 1.6 Windows and Linux

- **Windows:** DPAPI user scope with `CRYPTPROTECT_UI_FORBIDDEN` (`core/identity_store.rs:809-888`), per-account `.dpapi` files for sessions (`core/indexed_session_store.rs:1302-1350`) and prekeys (`core/prekey_lifecycle.rs:684-730`). No dialog and no per-program ACL: any process of the user can decrypt. No sibling problem; the boundary is the user SID.
- **Linux (glibc):** Secret Service (`core/identity_store.rs:992-1095`; `core/chat_history.rs:1122-1224`; `core/indexed_session_store.rs:1164-1299`). The code never calls `Unlock`, so a locked collection fails fast instead of prompting. Common providers (gnome-keyring) do not gate per application inside an unlocked collection, so the boundary is the user's session bus. Identity creation stays disabled until R1 (`core/identity_store.rs:994-1008`).
- So the hang is macOS-only. On Windows and Linux, daemon-owned secrets are a structural and reliability change, not a security change.

## 2. Goals and non-goals

**Goals** (each has a check in §6):

- **G1 No silent hangs.** No command waits on an OS keystore for more than 3 s without saying why; in steady state the CLI never sits inside a keystore call at all; every wait is bounded or interruptible, and `raven status` reports its cause without log scraping.
- **G2 One approval per install.** A new code identity (fresh install, unsigned rebuild, first run after migration) costs at most one dialog per profile, whatever the number of conversations or executables. Migration from today's items is a one-time exception (§4.5).
- **G3 Survive rebuilds and upgrades when signed.** With a stable signing identity: zero dialogs after installation.
- **G4 No secret ever crosses IPC in plaintext.** "Secret" means key material: the identity seed, the history key, session roots and chain and message keys, prekey private material, and the vault key. None of these appears in an IPC frame, encrypted or not. Message bodies are user content: they already cross the socket in `SealUnderSession` (`core/ipc.rs:33-44`) and will cross it in history and inbox reads, protected by the 0600 socket, the owner-only data dir and the peer check (§4.4). The forbidden-key rule (`core/ipc.rs:110-140`) stays and is extended to responses.
- **G5 No weaker same-user boundary than today** unless the owner accepts a named exception (§3.0 defines today's boundary).
- **G6 The CLI keeps working when the daemon is down where it must:** first-run `init`, `whoami`, `status`, `doctor`, contacts, and the keystore migrate/retry/forget commands. Other commands start the daemon, as `send` does today (`ash/ext.rs:2215-2223`).
- **G7 Never lose an identity.** No delete-then-add, add-only creation, readback verification, and the existing continuity checks (binding and marker, `core/identity_store.rs:223-252`, `:396-423`) are preserved or strengthened.

**Non-goals:** defending against arbitrary same-user malware (`docs/THREAT_MODEL.md:114`, `:529-545`; we keep what the Keychain incidentally gives today, no more); Secure Enclave or biometric policies; wire, ATSAM or RVN1 HOLD changes; Linux R1 and iOS; building the notarization pipeline (owner-blocked, `docs/INSTALL_macOS.md:153`).

## 3. Options

### 3.0 Today's same-user boundary (the bar for G5)

| A same-user process that is not Raven's code can... | macOS today | Windows / Linux today |
|---|---|---|
| read the seed, history key, session or prekey state | only after a Keychain dialog (login password, then Allow) | yes, silently |
| read stored messages | ciphertext only; the key costs a dialog | yes |
| seal and send as the user through the daemon | **yes, silently**: `SealUnderSession`, `LanDial`, `InternetDial`, `EnqueueSealed` check only the UID (`rn/ipc_server.rs:59-120`, `:863-866`) | yes |
| run Raven's own CLI (`ash inbox`) and read its output | yes, once the user chose "Always Allow" for it | yes |

Two consequences. Any new IPC operation that returns message content or uses identity keys must check more than the UID on macOS, or it is weaker than today. And the existing UID-only seal and dial operations already fall short of ADR 0004, which says unsigned or unattributed local callers must not reach them (`docs/adr/0004-raven-rdap-atsam-transport.md:61`, `:105`).

### 3.1 (a) The daemon owns all secrets; the CLI is a thin IPC client

- **Mechanism.** raven-node is the only process that opens `identity_store`, `chat_history`, `IndexedSessionStore` and `PrekeyLifecycleActor`. ash keeps contacts, rendering and its plain-words outcomes (`ash/ext.rs:1696-1840`). ADR 0003 already says ash and raven are clients and raven-node is the daemon (`docs/adr/0003-wire-crypto-identity-bridge-ipc.md:29`), but today the CLI does the send crypto itself: it opens the session store, confirms the PairResponse, stages the body, writes history, seals, and uses the daemon only to carry already-sealed frames (`ash/pair_init_lab.rs:290-419`, `:695-811`; `core/ipc.rs:45-59`).
- **New operations:** submit a message (PairInit when needed, stage, history, seal, dial: one op instead of a six-step client orchestration), message state, inbox page, history page and clear, and typed identity operations (prekey and alias publish, device revoke, device sync, contact requests). **No generic sign or decrypt op:** `Identity::sign` signs arbitrary bytes (`core/identity.rs:35-37`) and each object's domain is a prefix the caller builds (`core/device_revocation.rs:12`, `core/prekey_bundle.rs:14`), so a signing oracle would let any authorised caller mint revocations. The list is in §4.4.
- **Framing and pagination.** Today a frame is a 4-byte length plus JSON, at most 256 KiB in both directions (`core/ipc.rs:9`, `:99-108`, `:185-205`), one request per connection (`rn/ipc_server.rs:599-618`), with a 10 s server I/O timeout (`:31`) and a 3 s client default (`ash/ipc_client.rs:22`). That cannot carry what a thin client needs. A single inbox row may legally hold 256 KiB of text (`core/indexed_session_store.rs:85`, `:156-157`), which fits no encoding in a 256 KiB frame, and history holds up to 2,000 entries and 4 MiB with bodies up to 48 KiB (`core/chat_history.rs:193-199`, `:229`). v2 therefore needs a larger response limit, cursor pagination with a byte budget, and a long-poll to replace the 500 ms chat poll.
- **Authorising the local peer.** UID peer credentials (`getpeereid` / `SO_PEERCRED`, `rn/ipc_server.rs:59-120`) are the only check today. On Windows and Linux that equals the platform boundary (§1.6). On macOS it is weaker than the Keychain for anything that returns message content or uses identity keys: a UID-only history read would hand any same-user process what today costs it a password dialog. macOS therefore needs a code-identity check: read the peer's audit token (`LOCAL_PEERTOKEN`, `libc/src/unix/bsd/apple/mod.rs:2948`), resolve it with `SecCodeCopyGuestWithAttributes` and require a code requirement (`sf/src/os/macos/code_signing.rs:138`, `:201-247`). Use the audit token, never the PID, which can be reused. With separate binaries the requirement must name the other binary's cdhash, which changes on every unsigned build; with (b) it is the daemon's own DR. One binding is missing: `SecCodeCopyDesignatedRequirement` is not in `sfs/src/code_signing.rs:52-89`.
- **Security.** For: one process holds secrets; the CLI can never block in a keystore call; one writer replaces the cross-process waits that make a hang contagious (identity lock 60 s; per-peer send lock 120 s, `ash/pair_init_lab.rs:47-96`; history locks 10 s, `core/chat_history.rs:258-299`); SSH clients work through an already-unlocked agent. Against: a larger IPC surface for confused-deputy use; the daemon becomes a single point of failure for messaging; secrets stay resident in the network-facing process. That is already true for the identity (`rn/lan_direct.rs:319-328`), and the sibling design rejects it for the identity root (`2026-10-per-device-keys.md` §4.2). The bridge, which ADR 0003 forbids to hold conversation keys (`docs/adr/0003-wire-crypto-identity-bridge-ipc.md:24`), must get no handle to them. On its own, (a) does not meet G2: the daemon still asks once per item per new code identity.
- **Cost:** large. The orchestration in `ash/pair_init_lab.rs` (2,474 lines) and the send and chat parts of `ash/ext.rs` move into the daemon, and ADR 0004 D4 must be amended for a new plaintext-taking op. **Verdict:** the long-term boundary, third in order.

### 3.2 (b) Single executable with argv0 dispatch

- **Mechanism.** One `[[bin]]` named `raven` replaces the three binaries. `main` dispatches on the basename of `argv[0]` (`raven-node` selects the daemon personality; `raven` and `ash` the CLI) and on an explicit `raven daemon <raven-node arguments>`. (`raven node` is taken by the policy command, `ash/cli.rs:372-373`.) Installers create `ash` and `raven-node` as symlinks on Unix and as byte-identical copies on Windows. ash starts the service as `current_exe() daemon service ...` instead of looking for a sibling file (`ash/ext.rs:75-80`, `:223-232`).
- **Fixes:** the sibling-binary class completely, including the fresh-install dialogs of §1.2; and it makes (a)'s peer check trivial ("the peer runs my code"). **Does not fix:** rebuild prompts (still one per item per build), or hangs inside the CLI.
- **Security:** no change against foreign code; the trusted code is "Raven's binary" before and after. The CLI personality can now silently read items only raven-node created, and vice versa; both are the same code base. One real interaction: the sibling design's custody **K** keeps the identity root in an item "only ash reads" and relies on the per-program ACL to make the daemon prompt (`2026-10-per-device-keys.md` §4.2). A single code identity removes that distinction, so on macOS custody K needs the same passphrase wrap K already requires on Windows and Linux (Q3).
- **Costs and risks:** raven-node's `#[tokio::main]` (`rn/main.rs:2966-2975`) becomes a library entry that builds its own runtime; two clap trees; one feature set for both personalities (`unsafe-demo-crypto`, `debug-trace-delivery`, `corebluetooth`); a running daemon pins its `.exe` on Windows (already handled by stopping it, `inst/windows_service.ps1:55-79`); 18 lab scripts, 3 installers, the tarball and CI change; `raven-swarm` is a separate crate that also reads the seed (Q5). **Verdict:** first.

### 3.3 (c) SecAccess dual-trust ACL at item creation

- **Mechanism.** `SecAccessCreate` with `SecTrustedApplicationCreateFromPath` for both binaries, passed as `kSecAttrAccess` to `SecItemAdd`.
- **Needs hand-written FFI** to APIs deprecated since macOS 10.10: `sfs` binds only `SecAccessGetTypeID` (`sfs/src/access.rs:3-4`) and has no `kSecAttrAccess` constant (`sfs/src/item.rs:81-96` has only the access-group and access-control keys).
- **Pins cdhashes.** A trusted-application entry records the DR of the file at that path when the item is created. For ad-hoc builds that is the cdhash, so both entries go stale at the next rebuild, and both binaries must exist before the item is created.
- **Existing items** need `SecKeychainItemSetAccess`, which is expected to ask for the keychain password per item, on top of the partition list macOS keeps on legacy items since 10.12.
- **Verdict:** reject. With (b) there is nothing to dual-trust, and with (e) a shared DR covers both programs without new FFI.

### 3.4 (d) Data-protection keychain plus an access group

- **Mechanism.** `kSecUseDataProtectionKeychain` with `kSecAttrAccessGroup` `TEAMID.app.raven.node`. The constants exist (`sfs/src/item.rs:51`, `:81`) and `sf` has `ItemAddOptions::set_access_group` and `Location::DataProtectionKeychain` (`sf/src/item.rs:575-675`, `:736-749`) behind its `OSX_10_15` feature, which `node/crates/raven-core/Cargo.toml:31-33` does not enable.
- **Requirements.** The crate itself documents that this keychain needs a binary signed with access-group entitlements (`sf/src/item.rs:745-747`). That entitlement is restricted, so it needs a provisioning profile, which a bare command-line tool cannot carry: the binary must live in an app-like bundle, signed by a paid Developer Program team. Ad-hoc development builds cannot use it at all (`errSecMissingEntitlement`, -34018), so development needs a second backend.
- **Fixes:** no dialogs ever for signed builds (G1, G2, G3), and a **stronger** boundary than today: entitlement-based, with no "Always Allow" to talk a user into. **Does not fix:** development builds; migration still reads every legacy item once; availability follows the user's login session (fine for a LaunchAgent; SSH-only sessions untested).
- **Verdict:** the target for a signed `.app` release channel; not now (signing is `BLOCKED_HUMAN`, `docs/INSTALL_macOS.md:153`).

### 3.5 (e) Stable code signing (a complement to every option)

- **Developer ID.** The DR is identifier plus team, stable across rebuilds, and the legacy keychain's partition list identifies team-signed code by its team ID. Sign the single executable once (it is one file), with `--options runtime` as notarization requires anyway (`docs/SIGNING_NOTARIZATION_CHECKLIST.md:17`); the hardened runtime also blocks `DYLD_*` injection and debugger attach.
- **Self-signed development certificate** (`docs/INSTALL_macOS.md:119-141`). The recipe already signs `raven` and `raven-node` with the same identifier (`-i app.raven.node`, `:134`), so both get the same DR; if the Keychain matches ACL entries by DR, as Apple documents, that alone merges the two programs. Two caveats. (1) Whether the partition list accepts a re-signed build that has no team ID is **unverified**; the repo has never been tested against a real Keychain (M1 settles it). (2) The recipe says to choose "Always Allow" when `codesign` asks for the signing key (`:140`). From then on any same-user process can sign its own code as "Raven Dev" and read every Raven item silently, which is a G5 regression. Keep the signing identity in a separate keychain with its own password and answer "Allow" per signing, or accept the exception explicitly (Q2).
- **Verdict:** always; it is the only route to G3. It neither removes hangs nor the x N multiplication for unsigned builds.

### 3.6 (f) One vault item per profile (added: G2 is unreachable for unsigned builds without it)

- **Mechanism.** One add-only item `app.raven.node.vault.v2` per data dir holds `{version, vault root key (VRK, 32 bytes), identity seed}`. Everything else (history key, session states, prekey state, and the device key of the sibling design) becomes AEAD-sealed files under HKDF(VRK, purpose and account), which is the layout Windows already uses with DPAPI (`core/indexed_session_store.rs:1302-1350`; `core/prekey_lifecycle.rs:684-730`), written with temp, fsync and rename (`core/paths.rs:373`).
- **Fixes G2:** one item means one dialog per new code identity, whatever N is; it also ends the Keychain clutter and the hand-deletion hazard (`docs/INSTALL_macOS.md:145`).
- **Security analysis.** *Granularity:* one approval releases everything, where today each item is its own approval; but "Always Allow" for one program already releases everything that program reads. *Seed resilience:* the seed stays in the item, not in a file, so deleting the data dir cannot destroy it (today's Keychain copy survives that too). *Rollback:* today a restored data dir (Time Machine, a copied backup) is safe, because the protected head stays in the Keychain and the store only fast-forwards metadata (`core/indexed_session_store.rs:18-22`, `:6010-6020`). With sealed files in the data dir, a consistent old copy rolls both back and reuses send keys. A rollback guard outside the data dir is therefore **required** (§4.5); without it, macOS drops to Windows' current level. *Forward secrecy at rest:* with a static VRK, an old sealed file recovered from a disk snapshot stays decryptable; the ratchet design must agree on key erasure (R6).
- **Verdict:** do it after (b), macOS only; Windows and Linux keep their backends behind the same trait. The owner must accept the granularity trade-off (Q1).

### 3.7 Comparison

| | (a) daemon owns | (b) single exe | (c) SecAccess | (d) DP keychain | (e) signing | (f) vault |
|---|---|---|---|---|---|---|
| G1 no silent hangs | yes | partial | partial | yes | partial | partial |
| G2 one approval | only with (b)+(f) or (e) | no (per item) | no | yes | yes, if signed from first use | yes |
| G3 signed rebuilds | needs (e) | needs (e) | no if ad-hoc | yes | yes | needs (e) for zero |
| G4 no key over IPC | by design | n/a | n/a | n/a | n/a | n/a |
| G5 boundary | needs code-identity check | equal | equal | stronger | equal, with the codesign caveat | slightly coarser |
| G6 CLI without daemon | needs in-process fallback | yes | yes | yes | yes | yes |
| Effort | 5-8 weeks | 2 weeks | 2 weeks, deprecated FFI | 2-3 weeks plus Apple account and bundle | 1-3 days plus owner | 2-3 weeks |

## 4. Recommended architecture

### 4.1 Decision

(b) now, (f) next, (a) as the long-term boundary, (e) throughout; reject (c); keep (d) for a signed app-bundle channel. In the target state there is one file, `raven`. Its daemon personality is the only owner of online secrets, the login Keychain holds one item per profile, and the CLI personality reaches secrets only through IPC v2 except in the G6 commands, where it runs the same code under the same identity.

```
 terminal --> raven (CLI personality)          raven (daemon personality, LaunchAgent)
              contacts, rendering, outcomes     KeystoreOwner: unlock vault once, hold keys
              no keystore call in steady state  stores: identity, history, sessions, prekeys
              in-process only for G6 commands   transports and bridge (bridge gets no key handle)
                        |                                   ^
                        +-- IPC v2: 0600 UDS / per-user pipe, typed ops, paged, peer = my code
                                                            |
                                    login Keychain: app.raven.node.vault.v2 (one item per profile)
```

Scope with the sibling design: "all secrets" means all **online** secrets. Until per-device keys land, the identity seed is one of them (it signs online in nine ways, `2026-10-per-device-keys.md` Appendix A). Once they land, the device key is daemon-owned and the identity root moves to that design's ceremony custody, which on macOS then needs a passphrase wrap (Q3).

### 4.2 Keystore owner inside the daemon

- A new `raven_core::vault` with a `SecretVault` trait and five implementations: macOS legacy keychain (one item), Windows DPAPI (an adapter over today's files), Linux Secret Service (an adapter), `lab` (derived key, debug only, replacing the four environment overrides), and `fake` for tests. Stores take keys from a `VaultHandle` instead of calling the platform directly; the existing seams make that mechanical (`core/chat_history.rs:114-147`, `:1276-1300`; `core/indexed_session_store.rs:933-937`; `core/prekey_lifecycle.rs:443-446`).
- Start-up order: bind IPC first, then unlock on a dedicated thread inside `guarded()`. The first-install proof already tolerates the socket, its lock and the service log in a fresh profile (`core/identity_store.rs:327-356`). State machine: `Locked -> Waiting{what, since} -> Unlocked | Denied | Unavailable`.
- `Status` gains `keystore {state, what, waited_secs}` and `build {version, git}`, field names that pass the forbidden-key rule and keep Status free of the address (`core/ipc.rs:929-932`). ash then stops scraping the log (`ash/ext.rs:249-263`, `:339-349`).
- Operations that need secrets while the state is not `Unlocked` return `KEYSTORE_WAITING` or `KEYSTORE_DENIED` at once; `Ping` stays inline (`rn/ipc_server.rs:563-564`); `KeystoreRetry` re-runs the unlock after a Deny instead of a restart (`docs/INSTALL_macOS.md:113`).
- No per-request keystore round trip and no identity lock on the hot path (today every `SealUnderSession` reloads the identity, `rn/ipc_server.rs:349`).
- Hardening: zeroize on drop; `RLIMIT_CORE` 0 for the daemon personality; the bridge and forward-queue tasks never receive the handle.

### 4.3 What changes for the user

- Fresh install, signed or not: no dialog (the code that creates the vault is the code that reads it).
- Unsigned rebuild: one dialog, raised by the daemon, reported by `raven status` and by every command that needs it, with the same 3 s hint.
- Signed rebuild or upgrade: none. SSH: works against the running agent, with no dialog to answer.

### 4.4 IPC v2

**Framing.** Same 4-byte big-endian length plus UTF-8 JSON.

- Requests stay at 256 KiB (`MAX_IPC_FRAME`). The largest request carries one body of at most 48 KiB (`core/lan_noise.rs:28`), at most twice that once JSON-escaped.
- v2 responses may be up to 1 MiB, because one inbox row may hold 256 KiB. The client checks the limit of the version it asked for (today `ash/ipc_client.rs:291-308` checks 256 KiB).
- Pages are row-limited (at most 200) and byte-budgeted (512 KiB), and always contain the first row, so one large row cannot wedge pagination.
- Still one request per connection. `InboxPage.wait_ms` (at most 25 s) long-polls on an in-daemon notify, which replaces the 500 ms chat poll.
- New error codes: `KEYSTORE_WAITING`, `KEYSTORE_DENIED`, `KEYSTORE_UNAVAILABLE`, `PEER_NOT_AUTHORIZED`, `CURSOR_STALE`, `BUSY`.
- v2 decode errors carry fixed text: today serde's message is echoed back (`core/ipc.rs:156-157`, `:174-175`; `rn/ipc_server.rs:578-582`). Neither side logs v2 bodies.
- Versioning. v1 ops accept `v` of 1 or 2; new ops require 2. An older daemon answers `IPC_VERSION` (`core/ipc.rs:158-170`), and the CLI then says "the running raven-node is older than this raven; restart it", which is the normal state after an upgrade while launchd's `KeepAlive` (`inst/macos_launchd.sh:80`) keeps the old process alive.

**Operations** (tier U = UID match as today; tier C = U plus, on macOS, "peer satisfies the daemon's own DR"):

| Op | Tier | Replaces today | Notes |
|---|---|---|---|
| `Ping`, `Status` | U | - | Status adds `keystore`, `build` |
| `KeystoreRetry` | U | daemon restart after Deny | |
| `SubmitMessage {peer_pub_hex, dial, carrier, body, client_ref}` | C | the client orchestration in `ash/pair_init_lab.rs:290-419`, `:695-811` | answers after durable stage and history; idempotent on `client_ref`; the per-peer lock becomes an in-process mutex |
| `MessageStatus {client_ref}` | C | in-process outcome | the CLI polls up to 50 s, the dial budget of `ash/pair_init_lab.rs:198` |
| `InboxPage {sender_pub_hex?, after?, limit, wait_ms?}` | C | `ash/cli.rs:5107-5165`, `ash/ext.rs:2444-2491` | cursor `(received_at_ms, message_id)` as today (`ash/ext.rs:2227-2234`) |
| `HistoryPage {peer_pub_hex?, before?, limit}` / `HistoryClearPeer` | C | `ChatHistory::load` in ash (`ash/ext.rs:2936`; `ash/cli.rs:1757`), `ash/ext.rs:2434-2441` | newest first; tombstone semantics unchanged |
| `PrekeyPublish`, `AliasPublish`, `DeviceRevoke`, `DeviceSyncExport`, `DeviceSyncImport`, `ContactRequest{Create,List,Accept,Decline}` | C | `ash/ext.rs:3222-3300`; `ash/cli.rs:2472-2510`; `ash/ext.rs:918-1160`; `ash/cli.rs:2800`, `:3089` | the daemon builds and signs the typed object |
| `SealUnderSession`, `LanDial`, `InternetDial`, `EnqueueSealed`, `SetPolicy` | C on macOS (U today) | - | closes the ADR 0004 gap of §3.0 |

**Not added:** any generic sign, decrypt or key-export op (§3.1); and no `Whoami`, which the O6 guard forbids (`scripts/lib/o6_ipc_guard.sh:31`; `scripts/o6_try_phase_gap_check.sh:58`). `SubmitMessage` takes plaintext, so it needs the same ADR 0004 D4 review that `SealUnderSession` had, and the guard's deny-list (`scripts/lib/o6_ipc_guard.sh:28`) should name the reviewed ops explicitly rather than be passed by choosing a harmless-looking name. Field names avoid every token of `core/ipc.rs:112`; the body field is `body`. `decode_response` gains the forbidden-key scan that today only requests have (`core/ipc.rs:196-205`).

**Peer authorisation.**

- *macOS tier C:* `getsockopt(SOL_LOCAL, LOCAL_PEERTOKEN)`, then `GuestAttributes::set_audit_token`, `SecCode::copy_guest_with_attribues`, `check_validity(own DR)`. Own DR = `SecCodeCopyDesignatedRequirement(SecCodeCopySelf)`, one small non-deprecated extern. Because CLI and daemon are one file, this means exactly "Raven's code", for ad-hoc (cdhash) and signed (identifier and team) builds alike, with no requirement strings to maintain.
- *Linux and Windows:* tier C equals tier U, optionally plus "same executable" (`/proc/<pid>/exe` device and inode; `GetNamedPipeClientProcessId` plus image path), which equals today's platform boundary.
- *The client verifies the server too:* on Unix, `getpeereid` on the connected socket must equal the client's own euid (today Unix clients do not check, `rn/ipc_server.rs:657-662`; Windows does, `core/ipc.rs:390-402`), and on macOS the server must also satisfy the client's own DR.
- *Residual, equal to today:* a same-user attacker can run the genuine `raven` and read its output (§3.0, last row).

### 4.5 The vault and the migration of existing items (Phase 2, macOS)

**Invariants:** add-only; never delete-then-add; read back and compare every copy; legacy items are never modified by migration; every step can be resumed; anything unexpected fails closed.

**Steps,** run by the daemon personality or by `raven keystore migrate`, under the identity lock, the history key-init lock, an IMMEDIATE session-store transaction and the prekey writer lock, keeping the existing order stage, history, key-init (`core/chat_history.rs:258-260`):

1. If `identity.backend` already reads `macos-vault-v2`, stop.
2. Read the legacy seed (dialog 1 for a new code identity). Add the vault item add-only with `{VRK, seed, store_epoch}`, as identity and history do today (`core/identity_store.rs:732-736`); on `errSecDuplicateItem`, read it back and resume. Compare the seeds byte for byte.
3. Copy the history key (dialog 2), the prekey state (dialog 3) and each session state (dialogs 4 to 3 + N) into sealed files, then decrypt each copy and compare. The session set comes from the SQLite heads, because nothing enumerates the keystore (`core/indexed_session_store.rs:1844-1847`).
4. Flip fences that old binaries already reject: identity marker `macos-vault-v2` and a binding with a new backend code (old parsers return Continuity, `core/identity_store.rs:239`, `:517-522`); session metadata `PRAGMA user_version = 2` (old binaries refuse versions above 1, `core/indexed_session_store.rs:89-93`, `:1590-1595`); history magic `RVNHIST2` (`core/chat_history.rs:202`). The prekey store has no version an old binary checks: Phase 1 adds a "vault-v2 present: refuse legacy" check to all four stores, so Phase 1 binaries are safe downgrade targets. Older binaries remain a gap for prekey state only (Q8).
5. Rollback guard: every sealed file carries the `store_epoch` it was written under; the daemon bumps the epoch in the Keychain after each protected write; on open, a data dir whose newest sealed epoch is older than the Keychain epoch is a restored copy and fails with `RollbackDetected`. Where the epoch lives is open. Inside the vault payload means one item, but every bump rewrites the item that holds the seed. A non-secret attribute is the alternative: attribute reads do not need the decrypt right, but whether an update by a not-yet-trusted build prompts must be measured (M7).
6. Leave the legacy items in place. A later, explicit `raven keystore forget-legacy` deletes them by exact service and account, never by service alone (`docs/INSTALL_macOS.md:145`). It may cost one approval per item and is optional.

**Approval accounting.** Migration reads each legacy item exactly once, so "Allow" is enough (not "Always Allow"), and the profile never asks for those items again. Unsigned: 3 + N dialogs once in the profile's life, then one per new code identity. Signed, with the same DR as the items' creator: zero. Announce it on one screen first (what, how many dialogs, "Allow" is enough). A migration cannot be rehearsed on a copy of a real profile: the accounts hash the canonical path (`core/identity_store.rs:177-184`), so a copy finds no items. Rehearse on throwaway profiles made by the old build.

### 4.6 When the daemon is not running

| Class | Commands | Behaviour |
|---|---|---|
| No secrets | contacts, find, banner, bootstrap, `lab status`, help | unchanged |
| Public identity | whoami, status, listen | Phases 1-2: in-process load, same code identity, no extra dialog. Phase 3: either keep that, or read the public key and address from `identity.binding` (`core/identity_store.rs:200-221`), whose checksum is not authenticated (Q4) |
| Must work offline (G6) | `init`, `doctor`, `keystore migrate`/`retry`/`forget-legacy`, device sync export for recovery | in-process under the same locks; if the daemon holds its instance lock (`core/ipc.rs:267-276`, probed by `ash/ext.rs:517`), use IPC instead |
| Daemon-backed | send, chat, inbox, history, prekey and alias publish, device revoke, contact requests | start the daemon as send does (`ash/ext.rs:735`), with `launchctl kickstart` when the agent is installed instead of spawning an unmanaged second daemon (`ash/ext.rs:387-477`); on `KEYSTORE_WAITING`, a visible bounded countdown; never an in-process fallback |

`doctor` reports the keystore state from `Status` when the daemon is up. When it is down, `doctor` reads only markers and offers `--probe-keystore` (bounded, guarded) instead of loading the seed by default, as it does today (`ash/cli.rs:6346-6347`).

### 4.7 Service integration

- **macOS launchd** (`gui/<uid>` agent, `inst/macos_launchd.sh:91`): `ProgramArguments` become `raven daemon service ...` (`:66-78`). Keep the order `raven init` then `bootstrap` (`:87-91`): `init` creates the vault and the identity under the daemon's code identity, so a fresh install shows no dialog. A gui-domain agent can present the dialog. Upgrades keep `install` then `bootout`/`bootstrap`: zero dialogs when signed, one when unsigned.
- **Linux systemd --user:** `ExecStart` becomes `raven daemon service ...` (`inst/linux_systemd_user.sh:79`). Secret Service needs the session bus in the unit's environment. There is no vault on Linux in Phase 2. The unit deliberately sets no `PrivateTmp` (`:82-86`), so the `/tmp/raven-<uid>` socket fallback (`core/ipc.rs:311-347`) keeps working.
- **Windows:** the per-user logon task (`inst/windows_service.ps1:92-98`) runs `raven-node.exe`, a copy of `raven.exe`; DPAPI is unchanged, and the existing stop-before-replace logic (`:55-79`) handles the locked executable.

### 4.8 Tests and scripts

- **Lab scripts.** 18 scripts under `node/scripts/` reference `raven-node`, typically `ASH="$BIN/ash"` and `NODE="$BIN/raven-node"` after `cargo build -p raven-node -p ash` (for example `node/scripts/lan_direct_two_node.sh:18-20`, `:54-55`; `o6_m2_seal_under_session_lab.sh:42-44`; `o6_m3_two_node_rdap_lab.sh:46-47`; `internet_indexed_two_node.sh:29-30`; `two_node_demo.sh:14`; `ash_menu_smoke.sh:11-12`). Phase 1 adds one helper (in a later PR) that builds `-p raven` and creates `ash` and `raven-node` links in a temporary bin dir. argv0 dispatch keeps every `"$NODE" service ...` line working, so each script changes by 2 to 4 lines.
- **Lab overrides** keep working in Phase 1. Phase 2 maps them onto the `lab` vault backend (one debug-only switch) and keeps the old variable names as aliases for one release.
- **Rust tests.** Today's macOS identity tests create real login-Keychain items on CI runners (`core/identity_store.rs:2045-2114`, run by `.github/workflows/raven-serverless.yml:383-385`). The vault refactor turns them into fake-vault tests; the real-Keychain variants become `#[ignore]` and run only on the owner's Mac.
- **Guards.** The `keychain_guard_check.sh` allow-list shrinks to the vault backend plus a migration-only legacy reader. Phase 3 adds a client-boundary check: CLI modules may not open stores outside the G6 commands. `o6_ipc_guard.sh` gets the reviewed op list.

## 5. Phased plan

Estimates are engineer-days for one engineer who knows this code, including tests and docs.

| Phase | Contents | Effort | Exit criteria |
|---|---|---|---|
| **0** | Fix the signing guidance: one identifier for all binaries, the codesign "Always Allow" warning, a DR check in `doctor`. The owner runs M1. | 1 day plus owner time | M1 recorded: does a re-signed self-signed build ask again? |
| **1 (ships first)** | Single executable and `raven daemon`; IPC bound before the identity preflight; `Status.keystore` and `build`; "vault-v2 present" fences in all four stores; installers, tarball, 18 scripts, CI, `INSTALL_macOS.md` | 8-11 days | Dialogs per new code identity = items touched, not x executables; fresh install has none; M2, M3 pass |
| **2** | `SecretVault` (macOS item plus adapters), sealed-file store backends, rollback guard, migration and fences, fake-vault suite, `raven keystore` commands | 12-15 days | G2 met; M4, M7, M8, M9 pass; no real Keychain touched in CI |
| **3** | IPC v2 with tier C, daemon-side send, history, inbox and identity ops, thin CLI, long-poll chat, ADR 0003/0004 amendments | 25-40 days | G1 (no CLI keystore call in steady state), the §3.0 table holds, M5, M6, M10 pass |
| **(e)** | Developer ID, hardened runtime, notarization | 2-3 days once the owner has credentials | G3 for releases |
| **(d)** | Data-protection keychain inside an app bundle | later, 10-15 days | - |

Why this order: Phase 1 removes the largest multiplier with no storage-format change, and it carries the fences Phase 2 relies on. Phase 2 makes G2 true for unsigned builds. Phase 3 is the largest and most review-heavy change, and it is much simpler once the daemon holds one unlocked vault and shares its code identity with its clients.

## 6. Verification plan

**Automated (CI; the real Keychain is never touched):**

1. A conformance suite for every `SecretVault` backend (fake and lab everywhere, DPAPI on `rust-windows`): add-only creation, duplicate handling, readback, `Denied`/`Unavailable` mapping.
2. Migration fault injection at every step of §4.5 (after the vault add, after each sealed copy, before and after each fence). Each run must resume to the same end state, never lose a secret, and never delete or modify a legacy item.
3. Fences: today's parsers (copies of the `a1d3e1d` readers kept as test fixtures) refuse `macos-vault-v2`, binding code 5, `user_version = 2` and `RVNHIST2`, and never mint a new identity.
4. Rollback: restore an older copy of a data dir while the fake vault's epoch is ahead; expect `RollbackDetected` and no send.
5. Keystore waiting: a fake vault that blocks until released (channels as the clock, like `core/macos_keychain.rs:592-611`). `Ping` and `Status` answer within 100 ms; secret ops return `KEYSTORE_WAITING` within the client timeout; the CLI prints the hint and exits non-zero instead of hanging.
6. IPC v2 codec: forbidden keys refused in requests **and** responses for every variant (extending `core/ipc.rs:937-1008`); a 256 KiB row; budget boundaries; empty pages; cursors stable across concurrent inserts and deletes; v2 request to a v1 server.
7. Authorisation on the macOS runner (no Keychain involved): the test binary connecting to its own server passes tier C; `/usr/bin/python3` or `nc` on the same socket gets `PEER_NOT_AUTHORIZED` for C ops and an answer for `Ping`.
8. Dispatch: `raven`, `ash`, `raven-node` and `raven daemon` select the right personality; every script smoke runs through symlinks.
9. Tripwire: CI sets an environment variable that makes `guarded()` panic in test builds, proving that no test reaches the real Keychain; plus the self-tests of both guard scripts.

**Manual, by the owner on a real Mac** (record the macOS version, the signing state and the number and wording of dialogs; never use `security delete-generic-password` by hand):

- **M1** Build twice, sign both builds with the same self-signed certificate and identifier, check `codesign -d -r-`, run them: is the second build asked again? Repeat ad-hoc (it should be asked). This settles the partition-list question of §3.5.
- **M2** Phase 1 fresh install on a new data dir: no dialog; send, receive, inbox and chat work; Keychain Access shows one application, `raven`, on each item.
- **M3** Phase 1 upgrade of an existing profile: one dialog per item at most, once; then an unsigned rebuild asks again and a signed one does not.
- **M4** Phase 2 migration on a throwaway profile made by the old build (two local profiles, a few conversations): 3 + N dialogs answered with "Allow", then none after a daemon restart; messages, history and inbox intact.
- **M5** Deny: `raven status` shows `KEYSTORE_DENIED`, commands say so, and `raven keystore retry` recovers without a restart.
- **M6** SSH: with the agent running in the GUI session, `ssh localhost raven inbox` works with no dialog (Phase 3).
- **M7** Hidden dialog behind other windows: every command reports the wait within 3 s and nothing hangs silently. Also measure whether a not-yet-trusted build updating a vault-item attribute prompts (§4.5 step 5).
- **M8** Downgrade: the previous release against a migrated profile fails closed and never mints a new identity.
- **M9** Restore: put an older copy of the data dir in place: `RollbackDetected`, no send.
- **M10** A non-Raven process asking for `InboxPage` or `SubmitMessage` on the socket is refused.
- **M11** Count application-firewall and Local Network prompts before and after Phase 1 (they are also per code identity).

## 7. Risks and open questions

**Risks:**

- **R1 Self-signed stability is unverified** (M1). If the partition list re-asks after every re-signing, development builds still get one dialog per build after Phase 2; only Developer ID gets to zero.
- **R2 Migration bugs could cost an identity.** Mitigated by add-only creation, readback, legacy items left intact, fences, fault-injection tests, rehearsal on throwaway profiles, and an explicit one-screen announcement.
- **R3 Version skew** between a new CLI and an old running daemon after upgrades: v1/v2 negotiation, `Status.build`, and installers that restart the agent.
- **R4 The daemon becomes a single point of failure** for messaging. Supervised tasks, inline `Ping`, `KeepAlive` and the G6 in-process commands limit the damage; it is still a change from "ash works partly while the daemon is down".
- **R5 Concentration.** Long-lived keys in the network-facing process, a larger confused-deputy IPC surface, and a coarser approval with the vault. Mitigated by tier C, typed ops only, fixed-text errors, fuzzing the v2 decoder (`node/fuzz/`), and keeping the bridge away from key handles.
- **R6 Forward secrecy at rest.** With a static VRK, sealed session files recovered from APFS snapshots or backups stay decryptable; the Keychain's own database has the same property today. The ratchet design must define key erasure for whatever store holds session state.
- **R7 Phase 3 effort** is the least certain number. The send orchestration in `ash/pair_init_lab.rs` (2,474 lines) and the send, chat and outcome logic inside `ash/ext.rs` (5,837 lines in all) assume in-process errors and must map onto typed reason codes without losing the "truthful delivery" sentences.

**Open questions for the owner:**

- **Q1** Accept the vault (one item, sealed files, rollback guard) for macOS, or stay with per-item Keychain storage and make signing mandatory for every build, including development?
- **Q2** Get a Developer ID team (robust G3 now, (d) later)? Until then, is the self-signed recipe acceptable with its codesign "Always Allow" exception, or must the signing key live in a separate keychain?
- **Q3** With one code identity, the sibling design's custody K cannot rely on the per-program ACL on macOS. Adopt its passphrase wrap on macOS too, or keep a separate ceremony helper binary with its own identity?
- **Q4** In Phase 3, should `whoami` keep loading the identity in-process, read the unauthenticated `identity.binding`, or should the O6 rule against a `Whoami` IPC op be revisited?
- **Q5** `raven-swarm`: fold it into the single executable (a much larger binary), make it an IPC client, or accept that it asks for the identity on its own?
- **Q6** Code-identity authorisation excludes the planned Python RDAP client of ADR 0004 D4 on macOS. Should RDAP drive the `raven` CLI, use a separate reduced socket, or should the owner accept UID-only for it?
- **Q7** Should `SealUnderSession`, `LanDial`, `InternetDial` and `EnqueueSealed` move to tier C as soon as Phase 1 lands, ahead of Phase 3, to meet ADR 0004 now?
- **Q8** Downgrade from a migrated profile to pre-Phase-1 binaries leaves stale prekey state readable. Declare such downgrades unsupported, or also write a tombstone into the legacy prekey item, which may cost one more dialog?
- **Q9** When, if ever, should legacy items be deleted (`forget-legacy`), knowing that deletion may itself ask per item?
- **Q10** Linux after R1: adopt the vault on Secret Service as well, or keep per-item storage there?
