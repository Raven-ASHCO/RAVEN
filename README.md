# RAVEN — Serverless Mesh Core

**Messaging Beyond Connectivity.** A peer-to-peer communication core with **no
central message server**: identity, discovery, relay, store-and-forward and
bridges are all performed by the peers themselves.

```
 Terminal A ─── direct LAN/TCP ───► Terminal B
     │                                 ▲
     └── Bridge (opaque) ──────────────┘        FastAPI: NEVER in the path
         + store-and-forward while a peer       (fail-closed by design)
           is offline · mailbox · mock-BLE
```

**Proof status:** `bash scripts/final_serverless_proof.sh` → **AUTOMATED_PROOF_GREEN (16/16)**

---

## What is inside

| path | contents |
|---|---|
| `node/crates/raven-core` | RVN1 binary envelope · ATSAM hybrid crypto (X25519+ML-KEM-768) · chain KDF/AEAD · pairing |
| `node/crates/raven-swarm` | libp2p host: Noise, TCP, Kademlia `/raven/kad/1.0.0`, relay, DCUtR |
| `node/crates/raven-node` | daemon: direct send/recv, bridge + store-and-forward, IPC service |
| `node/crates/ash` | the user CLI — interactive menu, contacts, mailbox, tutorial |
| `protocol/` | versioned wire specs (`RAVEN_*_V1`, `ATSAM_*`) |
| `shared-vectors/` | cross-language test vectors (Rust ⇄ Swift ⇄ Dart) |
| `scripts/` | proof & smoke harnesses |

---

## Build

```bash
cd node
cargo build --release -p ash -p raven-node -p raven-swarm
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
* [macOS](docs/INSTALL_macOS.md) — `node/scripts/install/macos_launchd.sh`
* [Windows](docs/INSTALL_Windows.md)

Manual build: see [Build](#build). After `ash` / `raven` is on `PATH`, first
run offers to create your identity; menu **8** is a guided tutorial; menu
**4** is node policy / listen.

### The interactive menu

```
◆ MESSAGES   1 Chat/Send (guided)      2 Inbox
◆ NETWORK    3 Status                  4 Node policy
◆ PEOPLE     5 Contacts (paste-add)
◆ TOOLS      6 Mailbox   7 Nearby scan   8 Tutorial
raven ❯
```

---

## Pairing two terminals / two machines

Raven has **no account system**. Two people "add each other" by exchanging
their three public lines (`ash whoami`) over *any* channel, then pinning them.

**Step 1 — both sides create an identity** (once):
```bash
ash init
```

**Step 2 — exchange `whoami` blocks** (Telegram/QR/paper — anything):
```
address      rvn1q9rm6xamxjrl897g6r6juev2cahfzm4045vh6dz0
fingerprint  R70b-uzSH-85fI
pub_hex      4de0c6f92486459fb3dd74db379438f4aec59a532f15d1d08d43319bf5f85de7
```

**Step 3 — each side pins the other** (paste the whole block in the menu, or):

```bash
# Alice pins Bob:
ash contact add --address rvn1q9rm6… --pub-hex 4de0c6f9… \
                --petname Bob --verify-fp R70b-uzSH-85fI
# Bob pins Alice symmetrically.
```

`--verify-fp` means you compared fingerprints out-of-band; that mutual pin is
the entire trust model. Verify any time:

```bash
ash contact list          # → 1  Bob [pinned]  fp=R70b-uzSH-85fI
```

---

## Direct chat (LAN)

**Receiver:**
```bash
$BIN/raven-node run --data-dir ~/.raven \
  --listen 0.0.0.0:0 --write-addr /tmp/a.addr --write-pub /tmp/a.pub \
  --exit-after-recv 1 --timeout-secs 120 \
  --peer-pub-hex <SENDER pub_hex>
```

**Sender:**
```bash
printf 'hello raven\n' | $BIN/raven-node run --data-dir ~/.raven-b \
  --listen 0.0.0.0:0 \
  --peer "$(cat /tmp/a.addr)" \
  --peer-pub-hex <RECEIVER pub_hex> \
  --send-stdin --body-mode unsafe-interim --exit-after-ack --timeout-secs 30
```

Receiver prints `DELIVERED bytes=N`; sender prints `ACK delivered`.

> **Crypto note.** `unsafe-interim` is a **lab transport demo mode**
> (debug builds only). Production origination is fail-closed: without a
> persisted authenticated ATSAM session the daemon refuses with
> `ATSAM_SESSION_REQUIRED`. That refusal is itself tested by the harness.

For real Wi-Fi between two Macs, use the receiver's LAN IP printed via
`--write-addr` (e.g. `192.168.x.x:port`) instead of loopback.

---

## Bridge + store-and-forward (receiver offline)

```bash
# 1. Bridge node — forwards opaque ciphertext it cannot read
$BIN/raven-node bridge --data-dir ~/.raven-bridge \
  --lan-listen 0.0.0.0:0 --ble-listen 0.0.0.0:0 \
  --write-lan-addr /tmp/b.lan --write-ble-addr /tmp/b.ble

# 2. Sender → bridge, sealed to the offline recipient
printf 'offline msg\n' | $BIN/raven-node run --data-dir ~/.raven \
  --peer "$(cat /tmp/b.lan)" --peer-pub-hex <BRIDGE pub_hex> \
  --seal-to-pub-hex <OFFLINE pub> --ack-pub-hex <OFFLINE pub> \
  --send-stdin --exit-after-ack

# 3. Offline peer joins later on the BLE leg → receives + end-to-end ACK
$BIN/raven-node run --data-dir ~/.raven-c \
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
| `ash contact add/list/verify` | fingerprint-pinned friendship plane (never FastAPI) |
| `ash send` | forward to running raven-node; plaintext only via stdin |
| `ash inbox` | committed endpoint inbox (PairInit/LAN arrivals) |
| `ash status` / `doctor` | live policy/diagnosis; `messaging_path` must read `serverless_rvn1` (FastAPI refuse is fail-closed, exit 1). Doctor splits `daemon_presence` (Ping via `ipc_client` / `ipc_endpoint`; success is `present` not `up`), `daemon_ready` (`identity_usable` + Status + queue + serverless), and `send_path` (default `not_ready`). Unsupported OS: `blocked (reason=ipc_transport_missing)`. Presence or ready never means send works. |
| `ash node bridge\|store\|relay on/off` | local forwarding policy |
| `ash find` | multi-lane discovery resolver (no central DB) |
| `ash nearby` | ephemeral BLE scan — no permanent IDs advertised |
| `ash alias` | signed Alias V1 claims (community DHT stand-in) |
| `ash prekey` | signed prekey publish/fetch (untrusted store) |
| `ash device` | multi-device encrypted contact sync + revocation |
| `ash mailbox put/get` | opaque offline mailbox by store_tag only |
| `ash lab …` | Test-A PairInit experiments (debug + env-gated) |

---

## Verify everything

```bash
bash scripts/final_serverless_proof.sh
# 16 checks: build · identity · contacts · no-FastAPI · manual bootstrap ·
# offline store-forward · service survives CLI exit · ACK states ·
# bridge ABC both directions · dedup · opaque mailbox · swarm smoke ·
# fail-closed origination · secret scrub → AUTOMATED_PROOF_GREEN
```

Single-path smokes: `node/scripts/{lan_path_smoke,two_node_demo,internet_dial_smoke,internet_indexed_two_node,bootstrap_manual_peer_smoke,bridge_abc_demo}.sh`

---

## Security posture

* **Envelope:** RVN1 binary wire format — Ed25519-signed, anti-replay nonce,
  hop budget + replication budget, strict size ceiling.
* **Sessions:** ATSAM hybrid root = X25519 **and** ML-KEM-768 shares bound to a
  transcript hash; harvest-now-decrypt-later resistant by construction.
* **Relays are blind:** bridges forward sealed bytes they cannot open; the
  harness greps their logs to prove plaintext never appears.
* **Fail-closed defaults:** production origination refuses without an
  authenticated session; unknown proto/suite/index are rejected at decode.
* Docs: `docs/SERVERLESS_MODEL.md`, `docs/AUDIT_SERVERLESS_PIVOT_2026-08-12.md`,
  `docs/network/raven-swarm-connectivity-matrix.md`,
  `protocol/SECURITY_ERRATA_*`.

## Troubleshooting

| symptom | meaning |
|---|---|
| `ATSAM_SESSION_REQUIRED` | expected in release builds — origination needs a paired session (lab builds may opt into `unsafe-interim`) |
| `ephemeral data-dir detected` | you used mktemp; Raven switches to stable `~/.raven` so identities persist |
| receiver times out | sender's `--peer-pub-hex` must be the *receiver's* pub, and vice-versa for `--origin-pub-hex` |
| `messaging_path ≠ serverless_rvn1` | run `ash doctor`; never bypass the fail-closed path |

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE). Vendored third-party code keeps its
own headers under `node/third_party/`.
