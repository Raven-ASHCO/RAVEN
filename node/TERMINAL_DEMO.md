# RAVEN terminal demo (safe — no secrets)

Local-only walkthrough for the serverless **`ash`** product CLI and `raven-node`.
Uses **ephemeral identities** (`mktemp -d` / Windows TEMP). Never paste real production keys,
tokens, APNs/JWT material, or recovery secrets into this file or shell history demos.

**Brand:** [raven-messager.com](https://raven-messager.com/) · public logo  
`https://raven-messager.com/raven_logo.png` (also `/raven_logo_64.png`, `/raven_logo_192.png`)  
Terminal welcome uses **black & white** (monochrome bold/dim ANSI — or plain text with `NO_COLOR=1` / `TERM=dumb`). Site CSS palette is separate from the CLI.

## Persian quick start / شروع سریع (FA + EN)

| Step | EN | FA |
|---|---|---|
| 1 | Clone/copy the **whole** repo on **this** Mac (your home path) | کل ریپو را روی **همین** مک کپی/کلون کنید (مسیر خانهٔ خودتان) |
| 2 | `bash scripts/ash_first_run.sh` | اسکریپت پرتابل — مسیر `/Users/ahmd` لازم نیست |
| 3 | Menu **4 Status** → creates identity | منوی **۴** هویت می‌سازد |
| 4 | Share `ash whoami` (address + pub_hex only) | فقط address و pub_hex را بفرستید — **هرگز seed** |
| 5 | Menu **3** add contact → Menu **2** send | مخاطب → ارسال (شماره مخاطب، نه host:port) |

```bash
# From repo root — works on any Mac username:
bash scripts/ash_first_run.sh
# build only:
bash scripts/ash_first_run.sh --no-run
# init + print whoami then exit:
bash scripts/ash_first_run.sh --init-only
```

اگر `rustc`/`cargo` نباشد، اسکریپت پیام دو زبانه می‌دهد → [rustup.rs](https://rustup.rs).

## Two Macs on the same LAN

**Why Mac2 often fails:** docs/commands with `/Users/ahmd/...` are **someone else’s home**. On Mac2 use *their* clone path (or the portable script above).

```bash
# Mac2 — after copying/cloning the repo to YOUR home:
cd ~/hybrid_messenger          # or wherever YOU put it
export PATH="$HOME/.cargo/bin:$PATH"
bash scripts/ash_first_run.sh --init-only
# copy address + fingerprint + pub_hex to Mac1 (Messages / AirDrop / …)

# Mac1 — add Mac2 as contact (menu 3), then:
# Mac2 starts a listener, e.g.:
DATA=$(mktemp -d)
./node/target/debug/raven-node run --data-dir "$DATA" --listen 0.0.0.0:7420 \
  --peer-pub-hex <MAC1_PUB_HEX> --timeout-secs 300
# Mac1: menu 2 → pick contact # → enter Mac2_LAN_IP:7420 once (saved on contact)
```

Automated loopback proof (same machine):

```bash
cd node
./scripts/ash_contacts_lan_demo.sh
./scripts/ash_menu_smoke.sh
```

CI (`rust-linux` / `rust-macos` / `rust-windows`) runs `ash_menu_smoke.sh` against **debug** `target/debug/ash` with `RAVEN_IDENTITY_BACKEND=locked-file`. That is **menu/CLI smoke only** — not Keychain, launchd, or Gatekeeper/notarize. Operators must not set `locked-file` for a normal Keychain install (Option A default). See [`docs/INSTALL_macOS.md`](../docs/INSTALL_macOS.md).

## Prerequisites

```bash
# Prefer portable script, or:
cd /path/to/hybrid_messenger/node   # ← your path, not /Users/ahmd
cargo build -p raven-core -p raven-node -p ash
cargo test -p raven-core -p ash
cargo test -p raven-core --test reliability
```

Python oracle (repo venv has `cryptography`):

```bash
cd /path/to/hybrid_messenger/protocol/reference
../.venv/bin/python -m pytest -q
```

**Windows:** see [`WINDOWS.md`](./WINDOWS.md) (native MSVC build → `ash.exe` / `raven-node.exe`, or cross-compile notes). No installer yet.

## First time

```bash
cd /path/to/hybrid_messenger/node
DATA=$(mktemp -d)
./target/debug/ash --data-dir "$DATA"          # interactive — menu 4 creates identity
./target/debug/ash --data-dir "$DATA" init     # or create identity up front (public bits only)
./target/debug/ash --data-dir "$DATA" banner   # welcome only
```

1. Run `ash` with a fresh `--data-dir` — the banner explains first-run steps.
2. Create identity via menu **4 Status** (auto-creates if missing) or `ash init`.
3. **Add a contact** (menu **3**) before Send / Chat — paste their `ash whoami` or rvn1… + pub_hex.
4. Then menu **2** → pick contact **#** or `@tag`. Enter LAN `host:port` **once**; it is saved on the contact (`lan_dial`). Beginners should not re-type host:port every send.

## Add a contact

### Interactive (recommended)

```text
raven> 3
Contacts menu
  a  Add contact
contacts> a
Enter Raven address (rvn1…) / @alias / paste whoami:   # paste full whoami OK
…
Optional LAN dial host:port (Enter to skip — set later on Send): 192.168.1.20:7420
[V]erify & pin  /  [C]ontinue unpinned  /  [A]bort: V
```

Soft Unique Tags (brief):

| Layer | What | Notes |
|---|---|---|
| A | `rvn1…` address | Durable identity |
| B | `@alias` / public tag | Soft Unique — conflicts show a picker |
| C | petname (e.g. Poline) | Local-only primary label |
| — | fingerprint verify | Pins Tag+key locally (`V` or `--verify-fp`) |
| — | `lan_dial` | Optional saved `host:port` for Send |

### CLI

```bash
# Peer runs: ash --data-dir "$PEER" whoami   → copy address + pub_hex (+ fingerprint)
./target/debug/ash --data-dir "$DATA" contact add \
  --address rvn1q… \
  --pub-hex <64 hex> \
  --petname "Poline" \
  --tag poline \
  --lan-dial 192.168.1.20:7420 \
  --verify-fp XXXX-XXXX-XXXX

./target/debug/ash contact add --help   # Soft Unique Tag examples
```

## Primary entry: `ash` interactive welcome

`ash` with **no subcommand** opens the Raven Node shell (not Cursor/ash-autonomous).

```bash
cd /path/to/hybrid_messenger/node
DATA=$(mktemp -d)
./target/debug/ash --data-dir "$DATA" init     # public bits only
./target/debug/ash --data-dir "$DATA" banner   # non-interactive welcome
./target/debug/ash --data-dir "$DATA"          # interactive menu
NO_COLOR=1 ./target/debug/ash --data-dir "$DATA" banner   # plain text
```

**Welcome (B&W stand-in; bold/dim ANSI in a real TTY):**

```
      ┌──────────────────────────────────────────────────┐
      │                                                  │
      │      .--.     ≺═══◈═══≻                         │
      │     /  ◉\      NODE                            │
      │    /  /\ \                                       │
      │   /__/  \_\   Welcome to Raven Node            │
      │              Messaging Beyond Connectivity     │
      │                                                  │
      │  serverless · ATSAM · peer-to-peer               │
      └──────────────────────────────────────────────────┘

Brand logo (PNG): https://raven-messager.com/raven_logo.png
Site:             https://raven-messager.com/

● identity ready (public bits only — never a seed)
address     rvn1q…          # placeholder — yours will differ
fingerprint XXXX-XXXX-XXXX
pub_hex     <64 hex chars>  # public Ed25519 only — never a seed

  Menu
  1  Messages      outgoing queue + local chat history (ids only)
  2  Send / Chat   message a contact — add contacts first if empty
  3  Contacts      add by rvn1… / @alias / petname + fingerprint
  4  Status        identity, bridge, transports (public fields)
  q  Quit

raven>
```

### Banner / CLI security checklist

| Check | Status |
|---|---|
| No private keys / seeds / session keys / tokens in banner or menu | **Yes** |
| After identity: only `address` / `fingerprint` / `pub_hex` | **Yes** |
| Messages view: msg id prefix + delivery state + peer address — no plaintext, no packed envelopes logged | **Yes** |
| Contacts store public `address` + `pub_hex` (+ optional alias) only | **Yes** |
| No unauthenticated localhost admin HTTP | **Yes** — ash/raven-node local files only; no daemon HTTP |
| Demo data dirs ephemeral (`mktemp -d`) | **Yes** |
| E2EE / ATSAM path unchanged; node logs lengths / opaque status only | **Yes** |

## One-shot reliability demo

```bash
cd /path/to/hybrid_messenger/node
./scripts/two_node_demo.sh
./scripts/lan_path_smoke.sh
./scripts/bridge_abc_demo.sh
./scripts/ash_menu_smoke.sh
./scripts/ash_contacts_lan_demo.sh
cargo test -p raven-core --test bridge_v1
```

**Expected:** four `round N OK` + `ALL DEMO CHECKS PASSED`; `mode=interim OK`, `mode=opaque-atsam OK`;  
`bridge_abc_demo` → three A–B–C rounds + store-carry + `ALL BRIDGE A-B-C CHECKS PASSED`;  
`ash_menu_smoke` / `ash_contacts_lan_demo` → menu + contact LAN deliver green.

## Bridge A–B–C (local, mock BLE)

See **[`BRIDGE_V1.md`](./BRIDGE_V1.md)** for the full Bridge V1 spec walkthrough.

Topology: **A** LAN-only → **B** bridge (LAN + mock BLE) → **C** BLE-only. Same opaque `RavenEnvelopeV1`; B never decrypts; Delivered ACK only from C.

```bash
cd /path/to/hybrid_messenger/node
cargo build -p raven-node -p ash
./scripts/bridge_abc_demo.sh
```

### ash Bridge controls (config only — does not stop `raven-node`)

```bash
DATA_B=$(mktemp -d)
./target/debug/ash --data-dir "$DATA_B" init
./target/debug/ash --data-dir "$DATA_B" node bridge on
./target/debug/ash --data-dir "$DATA_B" node store on
./target/debug/ash --data-dir "$DATA_B" node relay off
./target/debug/ash --data-dir "$DATA_B" status
```

Sample status (safe fields only):

```
Bridge
  bridge     on
  store      on
  relay      off
  transports lan, mock_ble
  caps       ble, internet, store, bridge
  forward_q  0 pending / N total
note      ash configures only — raven-node bridge keeps running after ash exits
```

Start B daemon separately (survives ash quit):

```bash
./target/debug/raven-node bridge \
  --data-dir "$DATA_B" \
  --lan-listen 127.0.0.1:0 \
  --ble-listen 127.0.0.1:0 \
  --write-lan-addr /tmp/raven-b.lan \
  --write-ble-addr /tmp/raven-b.ble \
  --timeout-secs 0
```

## Manual two-node DM (`raven-node`)

Terminal A (receiver):

```bash
cd /path/to/hybrid_messenger/node
DATA_A=$(mktemp -d) DATA_B=$(mktemp -d)
./target/debug/raven-node init --data-dir "$DATA_A"
./target/debug/raven-node init --data-dir "$DATA_B"
# Note pub_hex from each init (public only).
./target/debug/raven-node run \
  --data-dir "$DATA_B" \
  --listen 127.0.0.1:0 \
  --peer-pub-hex <A_PUB_HEX> \
  --write-addr /tmp/raven-b.listen \
  --exit-after-recv 1 \
  --timeout-secs 30
```

Terminal B (sender) — after `/tmp/raven-b.listen` exists:

```bash
./target/debug/raven-node run \
  --data-dir "$DATA_A" \
  --listen 127.0.0.1:0 \
  --peer "$(cat /tmp/raven-b.listen)" \
  --peer-pub-hex <B_PUB_HEX> \
  --send "hello from terminal" \
  --exit-after-ack \
  --timeout-secs 30
```

**Expected:** `ACK delivered` / `DELIVERED bytes=…` (length only).

## Phone ↔ Mac terminal (flagged LAN)

**Goal:** iOS packs sealed chat bytes into `RavenEnvelopeV1` and TCP to `raven-node`. MeshEnvelope stays active.

### A. Mac listener

```bash
cd /path/to/hybrid_messenger/node
DATA=$(mktemp -d)
./target/debug/raven-node init --data-dir "$DATA"
./target/debug/raven-node run \
  --data-dir "$DATA" \
  --listen 0.0.0.0:7420 \
  --peer-pub-hex <IOS_PUB_HEX> \
  --timeout-secs 300
```

### B. Phone — Account → Serverless LAN

1. Enable **RavenEnvelopeV1 (serverless)** (Account → **Serverless LAN**)
2. Copy device **pub hex** into Mac `--peer-pub-hex`
3. Host = Mac LAN IP (or `127.0.0.1` for Simulator + loopback listen)
4. Port `7420`; Peer pub = node `pub_hex`
5. Save — UI shows fingerprint only (no seeds)

### C. Add Mac from iPhone (Discover)

1. Flag **ON** (same Serverless LAN screen)
2. Account → **Discover** → **Paste ash whoami** (or toolbar menu)
3. Paste `rvn1…` + `pub_hex` from Mac `ash whoami` (+ optional petname)
4. Save — local contact only (public bits)

### D. Send a chat message

Mac: `DELIVERED opaque_atsam …` or `DELIVERED bytes=N`. Never screenshot seeds/plaintext.

```bash
./scripts/lan_path_smoke.sh   # automated stand-in
```

## BLE raw RavenEnvelopeV1 (Phase G — flagged)

Behind `FeatureFlag.ravenEnvelopeV1` (default **OFF**):

- `RavenBleRvn1Carrier` packs/unpacks signed `RVN1` for BLE (Message + ACK)
- `MessageRouter` may enqueue parallel BLE RVN1 when preference is `bleMesh`
- `BLEMeshEngine` peeks `RVN1` magic before Mesh JSON; posts `.ravenEnvelopeV1BleReceived` (opaque — no decrypt)
- `RavenEnvelopeBridgeService`: BLE↔LAN forward; **ACK relay** (waiter on LAN socket); destination vs bridge role
- `RavenEnvelopeEndpointIngest`: when this device is destination, posts `.ravenEnvelopeV1EndpointIngest` with sealed body for chat sealer (BridgeSubsystem stays key-free)
- `RavenEnvelopeChatWire`: observes that notification → `MessageContentSealer` decrypt/display + opaque Delivered ACK emit; sender LAN/BLE ACK → UI **Delivered** ticks (`MeshACKReceived`) without bridge keys
- MeshEnvelope default path **unchanged** when flag is off

Unit tests: `RavenBleRvn1CarrierTests`, `RavenEnvelopeBridgeServiceTests`, `RavenEnvelopeEndpointIngestTests`, `RavenEnvelopeChatWireTests`.  
Rust: `cargo test -p raven-core --test bridge_v1` (cases 1–10).

### Verify locally (run twice)

```bash
cd /path/to/hybrid_messenger/node
cargo test -p raven-core --test bridge_v1
./scripts/bridge_abc_demo.sh
./scripts/two_node_demo.sh
./scripts/lan_path_smoke.sh
./scripts/ash_menu_smoke.sh
./scripts/ash_contacts_lan_demo.sh
# repeat:
cargo test -p raven-core --test bridge_v1 && ./scripts/bridge_abc_demo.sh
```

## Portable ATSAM KATs (Rust)

| Vector | Meaning |
|---|---|
| `shared-vectors/rvn1/atsam/chain_kdf_001.json` | Chain HKDF labels |
| `shared-vectors/rvn1/atsam/rvna1_header_layouts_001.json` | Header classify |
| `shared-vectors/rvn1/atsam/rvna1_v2_aead_known_root_001.json` | RVNA1 v2 AEAD + AAD with **known** `K_root` (no ML-KEM) |

Network path for shipping ATSAM without a known root remains **opaque ACK**.

## What is NOT ready yet

- Full ATSAM ML-KEM pairing in Rust (needs known root or ML-KEM port)
- libp2p DHT / NAT in Rust (InternetTransport stubbed behind path selection)
- Windows MSI/MSIX installer / WinUI LAN UI
- raven-node CoreBluetooth/BlueZ GATT (mock_ble stays for CI; iOS GATT via BLEMeshEngine)
- ash-autonomous (out of scope)

## Safety rules for public/GitHub demos

- Show only `address=` / `pub_hex=` / fingerprints / delivery status
- Credit logo URL from raven-messager.com (public asset)
- Use `mktemp -d`; do not commit `identity.seed`, queue DBs, or `.env`
- Do not dump message plaintext
- Prefer local demos; do not push secrets or demo data dirs
