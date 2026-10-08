# RAVEN — Serverless Mesh Core

**Messaging Beyond Connectivity.** A peer-to-peer communication core with **no
central message server**: identity, discovery, relay, store-and-forward and
bridges are all meant to be performed by the peers themselves (design goal; see
the status box for what is actually wired today).

> **Status: pre-release, not independently reviewed.** RVN1 messaging is under a
> production **HOLD** and no independent security review has happened — see the
> [security errata](protocol/SECURITY_ERRATA_RVN1_2026-08-13.md) and the
> [threat model](docs/THREAT_MODEL.md). Treat this as a research prototype and
> do not rely on it for sensitive communication.
>
> * **Lab / NON-RELEASE:** the proof harness and every *Lab demos* walkthrough
>   (debug builds with `unsafe-demo-crypto`, whose cipher is derivable from the
>   two public keys).
> * **Local mocks only:** `ash nearby` (no BLE radio) and `ash mailbox` (a local
>   file) do not use any radio or network.
> * **Experimental, feature-gated, absent from default builds:** relay / DCUtR /
>   AutoNAT client, and the networked offline mailbox. Internet (WAN) delivery
>   and NAT traversal are not proven
>   ([connectivity matrix](docs/network/raven-swarm-connectivity-matrix.md)).
> * **Direct LAN `ash send`** is the one live terminal-to-terminal slice in
>   default builds. It is exercised by lab/CI scripts and is not a
>   confidentiality or release claim.

```
 Terminal A ─── direct LAN/TCP ───► Terminal B
     │                                 ▲
     └── Bridge (opaque) ──────────────┘        FastAPI: NEVER in the path
         + store-and-forward while a peer       (fail-closed by design)
           is offline · mailbox · mock-BLE
```

**Proof harness:** `bash scripts/final_serverless_proof.sh` exits 0 and writes
`AUTOMATED_PROOF_GREEN` only when all 16 automated steps pass. It is a **lab**
harness (debug build with `unsafe-demo-crypto`); see [Verify everything](#verify-everything)
for what it does and does not show.

---

## What is inside

| path | contents |
|---|---|
| `node/crates/raven-core` | RVN1 binary envelope · ATSAM hybrid crypto (X25519+ML-KEM-768) · chain KDF/AEAD · pairing |
| `node/crates/raven-swarm` | libp2p smoke host: Noise over TCP, optional QUIC (libp2p's own transport security, not Noise), Kademlia `/raven/kad/1.0.0`, Identify, Ping. Relay / DCUtR / AutoNAT client exist **only** in the feature-gated, production-disabled `experimental-nat-connectivity` binary; the offline mailbox only behind `experimental-offline-mailbox`. Neither is in default builds and WAN traversal is not proven ([connectivity matrix](docs/network/raven-swarm-connectivity-matrix.md)) |
| `node/crates/raven-node` | daemon: direct send/recv, bridge + store-and-forward, IPC service |
| `node/crates/ash` | the user CLI — interactive menu, contacts, mailbox, tutorial |
| `protocol/` | versioned wire specs (`RAVEN_*_V1`, `ATSAM_*`) |
| `shared-vectors/` | cross-language test vectors — checked against Rust + the Python reference in CI; Swift/Dart clients consume them from their own trees (not exercised by this repo's CI) |
| `scripts/` | proof & smoke harnesses |

---

## Build

**Toolchain:** install Rust with [rustup](https://rustup.rs) (a current stable
compiler). Distro-packaged compilers are usually too old: the locked dependency
graph includes edition-2024 crates (`kem 0.3.0`, `ml-kem 0.3`, both declaring
`rust-version = "1.85"`) and its highest declared `rust-version` is 1.88
(`time 0.3.55`), so e.g. rustc/cargo 1.83.0 fails at dependency resolution (see
[`perf-baseline-2026-09-04.md`](docs/engineering/baseline-freeze/perf-baseline-2026-09-04.md)).
CI is validated on rustc 1.98.0 only; the workspace does not yet set a
`rust-version`, so the exact minimum has not been verified.

```bash
cd node
cargo build --release --locked -p ash -p raven-node -p raven-swarm
export BIN=$PWD/target/release
```

Two binaries matter:

* **`ash`** — everything you do as a person (menu, identity, contacts…)
* **`raven-node`** — the engine that actually carries messages (also runs as a bridge/service)

---

## Install

Do **not** `curl | bash` `node/scripts/install.sh`. That path is retired and
fail-closed: it used to clone a personal fork and install debug
`unsafe-demo-crypto` binaries onto `~/.local/bin`.

Operator install is **release / secure build only**:

* [Linux](docs/INSTALL_Linux.md) — `node/scripts/install/linux_systemd_user.sh`
  (keys in Secret Service when a desktop keyring is unlocked, else a passphrase vault — see that guide)
* [macOS](docs/INSTALL_macOS.md) — `node/scripts/install/macos_launchd.sh`
* [Windows](docs/INSTALL_Windows.md)

Manual build: see [Build](#build). After `ash` / `raven` is on `PATH`, first
run offers to create your identity; menu **8** is a guided tutorial; menu
**4** is Listen (receive). Node forwarding policy is `ash node …`.

### The interactive menu

```
◆ MESSAGES   1 Chat/Send (guided)      2 Inbox
◆ NETWORK    3 Status                  4 Listen
◆ PEOPLE     5 Contacts (paste-add)
◆ TOOLS      6 Mailbox   7 Nearby scan   8 Tutorial
raven ❯
```

---

## Pairing two terminals / two machines

Raven has **no account system**. Two people "add each other" by exchanging
their three public lines (`ash whoami`) over *any* channel, then adding (and
ideally pinning) them.

**Step 1 — both sides create an identity** (once):
```bash
ash init
```

**Step 2 — exchange `whoami` blocks** (Telegram/QR/paper — anything). The
block has this shape (placeholders — *not* a real identity; never pin values
copied from documentation):
```
address      rvn1<address printed by your own `ash whoami`>
fingerprint  XXXX-XXXX-XXXX
pub_hex      <64 hex characters: your Ed25519 public key>
```

**Step 3 — each side adds the other** (paste the whole block in the menu, or):

```bash
# Alice adds and pins Bob:
ash contact add --address <BOB address> --pub-hex <BOB pub_hex> \
                --petname Bob --verify-fp <BOB fingerprint>
# Bob adds Alice symmetrically.
```

`--verify-fp` (menu: **[V]erify & pin**) records that you compared fingerprints
out-of-band; the **fingerprint check is your only protection against a spoofed
`whoami` block**. Adding a contact is what makes the daemon trust that key, and
a contact added without `--verify-fp` (menu: **[C]ontinue unpinned**) is trusted
for sessions exactly like a pinned one — pinning is not enforced by the daemon.
Check the state any time:

```bash
ash contact list          # shows "✓ pinned" or "○ unpinned" for each contact
```

---

## Direct chat (LAN) — contacts + `ash send`

This is the path the default (non-demo) build supports: a contact with a LAN
dial address, a local `raven-node service`, and `ash send --contact`. The
scripted version is `node/scripts/lan_direct_two_node.sh` (run in CI). It is a
lab- and CI-verified slice, **not** a confidentiality or release claim: the
RVN1 production hold and the missing external review (see the status box above)
apply to it, and it installs no one-time prekeys, so first-contact forward
secrecy is bounded by signed-prekey rotation alone (see
[`protocol/RAVEN_PREKEY_LIFECYCLE_V1.md`](protocol/RAVEN_PREKEY_LIFECYCLE_V1.md)).
Platform key-storage notes: [Linux](docs/INSTALL_Linux.md) ·
[macOS](docs/INSTALL_macOS.md) · [Windows](docs/INSTALL_Windows.md).

**Both sides** (once): `ash init` and `ash prekey publish`, then run the node:
```bash
$BIN/raven-node service --data-dir ~/.raven --lan-listen <LAN_IP>:7420 --ble-listen 127.0.0.1:0
```

**Each side pins the other with its dial address:**
```bash
ash contact add --address <BOB address> --pub-hex <BOB pub_hex> \
                --petname Bob --tag bob --verify-fp <BOB fingerprint> \
                --lan-dial <BOB_LAN_IP>:7420
```

**Alice sends; Bob reads:**
```bash
printf 'hello raven\n' | ash send --contact @bob     # → status … delivered
ash inbox                                            # on Bob's machine
```

The receiving daemon only accepts PairInit from peers whose key is in the local
contact book (pinned **or** unpinned — see the pairing section); a stranger's
PairInit is refused (asserted by `lan_direct_two_node.sh`).

---

## Lab demos (debug build + `unsafe-demo-crypto` only)

The raw `raven-node run` walkthroughs below use `--body-mode unsafe-interim`, a
**lab transport demo cipher** whose key is derived from the two *public* keys:
anyone who knows both public keys — including a bridge — can decrypt it. It is
compiled out of release builds (`cargo build --release --features
unsafe-demo-crypto` is refused), and a default debug build refuses it too. Build
the lab binaries explicitly. These demos are **lab / NON-RELEASE only**; they
bind `0.0.0.0` for convenience, so on an untrusted network substitute a specific
loopback or LAN address, and never exchange anything you want kept private over
them:

```bash
cd node
cargo build -p raven-node -p ash --features raven-node/unsafe-demo-crypto
export BIN=$PWD/target/debug
```

### Direct `raven-node run` (LAN)

**Receiver:**
```bash
$BIN/raven-node run --data-dir ~/.raven-lab-a \
  --listen 0.0.0.0:0 --write-addr /tmp/a.addr --write-pub /tmp/a.pub \
  --exit-after-recv 1 --timeout-secs 120 \
  --peer-pub-hex <SENDER pub_hex>
```

**Sender:**
```bash
printf 'hello raven\n' | $BIN/raven-node run --data-dir ~/.raven-lab-b \
  --listen 0.0.0.0:0 \
  --peer "$(cat /tmp/a.addr)" \
  --peer-pub-hex <RECEIVER pub_hex> \
  --send-stdin --body-mode unsafe-interim --exit-after-ack --timeout-secs 30
```

Receiver prints `DELIVERED bytes=N`; sender prints `ACK delivered`. Without
`--body-mode unsafe-interim` (the default is `atsam`) the sender refuses with
`ATSAM_SESSION_REQUIRED` in every build — `node/scripts/lan_path_smoke.sh` and
`node/scripts/internet_dial_smoke.sh` assert that refusal.

For real Wi-Fi between two Macs, use the receiver's LAN IP printed via
`--write-addr` (e.g. `192.168.x.x:port`) instead of loopback.

### Bridge + store-and-forward (receiver offline)

```bash
# 1. Bridge node — forwards the sealed envelope without opening it
$BIN/raven-node bridge --data-dir ~/.raven-lab-bridge \
  --lan-listen 0.0.0.0:0 --ble-listen 0.0.0.0:0 \
  --write-lan-addr /tmp/b.lan --write-ble-addr /tmp/b.ble

# 2. Sender → bridge, sealed to the offline recipient
printf 'offline msg\n' | $BIN/raven-node run --data-dir ~/.raven-lab-a \
  --peer "$(cat /tmp/b.lan)" --peer-pub-hex <BRIDGE pub_hex> \
  --seal-to-pub-hex <OFFLINE pub> --ack-pub-hex <OFFLINE pub> \
  --send-stdin --body-mode unsafe-interim --exit-after-ack

# 3. Offline peer joins later on the BLE leg → receives + end-to-end ACK
$BIN/raven-node run --data-dir ~/.raven-lab-c \
  --peer "$(cat /tmp/b.ble)" --peer-pub-hex <SENDER pub> \
  --origin-pub-hex <SENDER pub> --exit-after-recv 1
```

Full scripted demo incl. reverse direction: `node/scripts/bridge_abc_demo.sh`
(prints `ALL BRIDGE A-B-C CHECKS PASSED`).

---

## Tool reference

| command | purpose |
|---|---|
| `ash init` / `whoami` | local keypair identity; print public bits only |
| `ash contact add/list/verify/remove` | local contact book with optional fingerprint pinning (never FastAPI). Needs an identity first (`ash init`): a contact file created before it would block the first `ash init`. `remove` is also the deliberate re-pin: it forgets the prekey pinned for that contact (see `PEER_PREKEY_RESET` below) |
| `ash send` | forward to running raven-node; plaintext only via stdin. Delivery: first contact needs the peer online. With a confirmed session and the peer offline the message is **queued locally**; nothing retries it in the background, only your **next `ash send` to that peer** does, within 60 minutes (then it is marked failed). One message per peer may be outstanding, and concurrent sends to one peer are serialised. The result line says which case you are in: `status delivered` (the peer confirmed), `not delivered yet … queued locally` (do not retype it), `sent, delivery unconfirmed` (the peer may already have it, do not retype it), or `NOT SENT … Nothing was queued` (safe to send again). Unclassified errors keep the older `send refused: …` form |
| `ash inbox` | the messages you received (the committed endpoint inbox: PairInit/LAN arrivals), newest last, each with how long ago and from whom; an empty inbox says why and names the profile; empty until the identity exists |
| `ash status` / `doctor` | live policy/diagnosis; `messaging_path` must read `serverless_rvn1` (FastAPI refuse is fail-closed, exit 1). Doctor splits `daemon_presence` (Ping via `ipc_client` / `ipc_endpoint`; success is `present` not `up`), `daemon_ready` (`identity_usable` + Status + queue + serverless), and `send_path` (default `not_ready`). Unsupported OS: `blocked (reason=ipc_transport_missing)`. Presence or ready never means send works. |
| `ash node bridge\|store\|relay on/off` | local forwarding policy |
| `ash find` | multi-lane discovery resolver (no central DB) |
| `ash nearby` | **local software mock** — mints and lists only this device's own ephemeral tokens; no BLE radio, no receive side, never finds another peer |
| `ash alias` | signed Alias V1 claims (community DHT stand-in) |
| `ash prekey` | signed prekey publish/fetch (untrusted store) |
| `ash device` | multi-device encrypted contact sync + revocation |
| `ash mailbox put/get` | **local-only** opaque store keyed by `store_tag`, kept in `mailbox_store.json` in the data dir; contacts no peer or store node, so nothing is delivered to an offline contact |
| `ash lab …` | Test-A PairInit experiments (debug + env-gated) |

`ash send` / `ash listen` start a background `raven-node service` for the profile when none answers (it keeps running after `ash` exits; the start notice prints its process id: stop only this profile's service with `kill <pid>`, and avoid a blanket `pkill raven-node`, which would also stop the services of other profiles). Its output goes to `<data-dir>/raven-node-service.log` (mode `0600`, kept to about 1 MiB: `ash` trims it at each start and the running service truncates it in place; remote peer addresses are not logged). A service that holds the profile's instance lock but does not answer (stopped, wedged, or waiting on a keystore prompt) is reported as such after a few seconds; `ash` never unlinks its socket or starts a second one.

---

## Verify everything

```bash
bash scripts/final_serverless_proof.sh
# 16 steps: build · identity · whoami · contacts · no-FastAPI · manual bootstrap ·
# offline store-forward · service survives CLI exit · ACK states ·
# bridge ABC both directions · dedup · opaque mailbox · manual-peer smoke ·
# swarm smoke · LAN/Internet incl. fail-closed origination · secret scrub
# → AUTOMATED_PROOF_GREEN only if every step passes
bash scripts/final_serverless_proof.sh --self-test   # harness self-test only
```

Every assertion in a step is enforced (a harness self-test proves a failing
assertion turns the run red). What it does **not** show: the transport steps
run on the lab `unsafe-interim` cipher, so the bridge "no plaintext" checks
prove only that bridges do not log or store plaintext — not that they cannot
read it. Hardware, human and production-crypto gaps are listed in each run's
`BLOCKED.md`.

Single-path smokes: `node/scripts/{lan_path_smoke,two_node_demo,internet_dial_smoke,internet_indexed_two_node,bootstrap_manual_peer_smoke,bridge_abc_demo}.sh`

---

## Security posture

* **Envelope:** RVN1 binary wire format — Ed25519-signed, anti-replay nonce,
  strict size ceiling. The hop budget and replication budget are **not**
  covered by the sender signature: they are cooperative limits only, and a
  malicious relay can reset them (no Byzantine forwarding bound; errata rule 8).
* **Sessions:** ATSAM hybrid root = X25519 **and** ML-KEM-768 shares bound to a
  transcript hash. This is a design goal (aimed at harvest-now-decrypt-later
  resistance) of an implementation that has **not** been independently
  reviewed, and production use is disabled under the HOLD.
* **Relays forward sealed bytes:** bridges forward the envelope without
  opening it. The only automated bridge evidence today uses the lab
  `unsafe-interim` cipher (key derivable from public keys by any observer,
  bridge included); it shows bridges do not log or store plaintext, not that
  they cannot read it. Bridging under authenticated ATSAM sessions is not yet
  exercised by the harness.
* **Fail-closed defaults:** production origination refuses without an
  authenticated session; unknown proto/suite/index are rejected at decode.
* Docs: `docs/SERVERLESS_MODEL.md`, `docs/AUDIT_SERVERLESS_PIVOT_2026-08-12.md`,
  `docs/network/raven-swarm-connectivity-matrix.md`,
  `protocol/SECURITY_ERRATA_*`.

## Troubleshooting

| symptom | meaning |
|---|---|
| `ATSAM_SESSION_REQUIRED` | expected from `raven-node run` in every build unless a lab (`unsafe-demo-crypto`) build is given `--body-mode unsafe-interim`; use contacts + `ash send` |
| `note: --data-dir looks ephemeral (mktemp) …` | not an error and **not** a remap: a mktemp-style `--data-dir` is used exactly as given (never moved onto `~/.raven`), and its identity is throwaway, so peers must re-pin it every run. For a stable identity omit `--data-dir` (default `~/.raven`); `RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1` silences the note for lab runs |
| `PEER_PREKEY_RESET` | a contact reinstalled (its prekey counter restarted) and your node still pins its old prekey, so no *new* session is started on the new one (connections and existing sessions keep working). Verify the contact's fingerprint out of band, then `ash contact remove` it and add it again; otherwise it clears when the old pinned prekey expires |
| `NOT SENT … accepted the connection but refused it without saying why` | the peer closed the connection silently: usually it does not have you in its contacts, or lost its session with you (reinstall), or its own RAVEN could not save the message (chat history or Keychain), in which case it may already be in their inbox. Ask them to check their contacts, `ash listen` and any macOS Keychain window (`ash doctor` shows more), and add each other as contacts; do not retype the message until they confirm it did not arrive |
| receiver times out | sender's `--peer-pub-hex` must be the *receiver's* pub, and vice-versa for `--origin-pub-hex` |
| `messaging_path ≠ serverless_rvn1` | run `ash doctor`; never bypass the fail-closed path |

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE). Vendored third-party code keeps its
own headers under `node/third_party/`.
