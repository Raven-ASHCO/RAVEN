# RAVEN terminal demo (safe — no secrets)

Local-only walkthrough for the serverless **`ash`** product CLI and `raven-node`.
Demos below use **throwaway identities** (`mktemp -d` / Windows TEMP). An explicit
`--data-dir` is always used as given — ash never remaps it onto your real `~/.raven`
profile; a mktemp-looking path only prints a note (silence it with
`RAVEN_ALLOW_EPHEMERAL_DATA_DIR=1`). For a stable Mac identity that a phone keeps
pinned, run `ash` **without** `--data-dir` (default `~/.raven`).
Never paste real production keys, tokens, APNs/JWT material, or recovery secrets into
this file or shell history demos.

**Brand:** [raven-messager.com](https://raven-messager.com/) · public logo  
`https://raven-messager.com/raven_logo.png` (also `/raven_logo_64.png`, `/raven_logo_192.png`)  
Terminal welcome uses **black & white** (monochrome bold/dim ANSI — or plain text with `NO_COLOR=1` / `TERM=dumb`). Site CSS palette is separate from the CLI.

## Persian quick start / شروع سریع (FA + EN)

| Step | EN | FA |
|---|---|---|
| 1 | Clone/copy the **whole** repo on **this** Mac (your home path) | کل ریپو را روی **همین** مک کپی/کلون کنید (مسیر خانهٔ خودتان) |
| 2 | `bash scripts/ash_first_run.sh` | اسکریپت پرتابل — مسیر `/Users/ahmd` لازم نیست |
| 3 | First run: answer **Y** → creates identity (menu **3 Status** shows it) | اجرای اول: **Y** هویت می‌سازد (منوی **۳** وضعیت) |
| 4 | Share `ash whoami` (address + pub_hex, or the one-line `invite`) | فقط address و pub_hex (یا خط invite) را بفرستید — **هرگز seed** |
| 5 | Menu **5** add contact → Menu **1** send · Menu **4** listen · Menu **2** inbox | مخاطب (۵) → ارسال (۱) · دریافت (۴) · صندوق (۲) |

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

# Both Macs add each other as contacts (menu 5 — paste the other's whoami / invite).
# Mac2 listens (LAN-direct receiver on port 7420, trusts contacts only):
./node/target/debug/ash listen          # or menu 4
# Mac1: menu 1 → pick contact # → enter Mac2_LAN_IP:7420 once (saved after delivery)
# Mac2: menu 2 Inbox shows the message, attributed to Mac1's petname + fingerprint
```

Automated loopback proof (same machine):

```bash
cd node
./scripts/ash_contacts_lan_demo.sh
./scripts/ash_menu_smoke.sh
```

Both use the same secure default-build send as `ash send`: LAN-direct (Noise XX) +
PairInit + indexed session + sealed ACK — never `--body-mode unsafe-interim`.
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
DATA=$(mktemp -d)                              # throwaway demo identity
./target/debug/ash --data-dir "$DATA"          # interactive — first-run prompt creates identity
./target/debug/ash --data-dir "$DATA" init     # or create identity up front (public bits only)
./target/debug/ash --data-dir "$DATA" banner   # welcome only
```

1. Run `ash` with a fresh `--data-dir` — the banner explains first-run steps.
2. Answer **Y** at "Create your Raven identity now?" (or run `ash init`); menu **3 Status** shows it.
3. **Add a contact** (menu **5** → `a`) before Send / Chat — paste their `ash whoami` block, their one-line `invite raven:…`, or rvn1… + pub_hex. The contact is **merged** into your book (existing contacts, pins and dials are kept); a key that does not encode to the pasted address is refused.
4. Then menu **1** → pick contact **#**, `@tag` or petname (several matches → a fingerprint picker, never a silent pick). Enter LAN `host:port` **once**; it is saved on the contact (`lan_dial`) after the first delivery.

## Add a contact

### Interactive (recommended)

```text
raven> 5
 ── Contacts ──
  a  Add contact
contacts> a
Enter Raven address (rvn1…) / @alias / paste whoami:   # whoami block or invite line OK
…
Optional LAN dial host:port (Enter to skip — Send auto-resolves / Mac-listens): 192.168.1.20:7420
[V]erify & pin  /  [C]ontinue unpinned  /  [A]bort: V      # anything else = cancel, nothing saved
```

`V` records that you compared the fingerprint out-of-band. `C` still adds the contact, and the
receiving daemon admits PairInit from **any** key in the contact book — pinned or not — and refuses a
key that is not in it. Pinning is therefore your own record of an out-of-band check, not something the
daemon enforces; skip it and a spoofed `whoami` block is accepted like a genuine one.

Soft Unique Tags (brief):

| Layer | What | Notes |
|---|---|---|
| A | `rvn1…` address | Durable identity |
| B | `@alias` / public tag | Soft Unique — conflicts show a picker; charset `a-z 0-9 _ -` |
| C | petname (e.g. Poline) | Local-only primary label; unique on this device |
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

**Welcome (B&W; bold/dim ANSI only when stdout is a TTY and `NO_COLOR` is unset):**

```
  ╭──────────────────────────────────────────────────╮
  │                                                  │
  │  R A V E N                                       │
  │  N O D E                                         │
  │                                                  │
  │  Messaging Beyond Connectivity                   │
  │                                                  │
  │  ◆ serverless · P2P · private                    │
  │                                                  │
  │  "The Raven bears witness as the Phoenix         │
  │   rises from the ASH"                            │
  │                                                  │
  ╰──────────────────────────────────────────────────╯

   https://raven-messager.com
   profile: /path/to/profile

● identity ready
  address       rvn1q…          # placeholder — yours will differ
  fingerprint   XXXX-XXXX-XXXX
  pub_hex       <64 hex chars>  # public Ed25519 only — never a seed

◆ MESSAGES
    1  Chat / Send              send one message to a contact
    2  Inbox                    messages you received
◆ NETWORK
    3  Status                   your invite, contacts, is the node running
    4  Listen                   stay online to receive (keep this window open)
◆ PEOPLE
    5  Contacts                 add a friend (paste their invite) · list · verify
◆ TOOLS
    6  Mailbox                  advanced tool, this computer only (not your inbox)
    7  Nearby scan              demo, this computer only (no Bluetooth yet)
    8  Tutorial                 new here? start here

    q  quit

raven ❯
```

Note: **6 Mailbox** is a local-only store (`mailbox_store.json` in the data dir; it contacts no peer or
store node) and **7 Nearby scan** is a local software mock (it lists only this device's own ephemeral
tokens; there is no BLE radio or receive side). Neither reaches another device.

### Banner / CLI security checklist

| Check | Status |
|---|---|
| No private keys / seeds / session keys / tokens in banner or menu | **Yes** |
| After identity: only `address` / `fingerprint` / `pub_hex` | **Yes** |
| Inbox / chat: one sanitized line per message (CR/LF → `⏎`; ANSI, C0/C1, bidi and invisible code points dropped), attributed to the sender's petname + pin state + fingerprint (`unknown device [fp=…]` otherwise) | **Yes** |
| Contacts store public `address` + `pub_hex` (+ optional alias) only | **Yes** |
| No unauthenticated localhost admin HTTP | **Yes** — ash/raven-node local files only; no daemon HTTP |
| Explicit `--data-dir` used as given (never remapped onto `~/.raven`); `mktemp -d` demo dirs are throwaway identities | **Yes** |
| Colour escapes only on a TTY; `NO_COLOR` / `TERM=dumb` / pipes get plain text | **Yes** |
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

**Expected:** four `round N OK` + `ALL DEMO CHECKS PASSED`; `mode=unsafe-interim OK`, `mode=failclosed OK (ATSAM_SESSION_REQUIRED enforced, …)` (from `lan_path_smoke.sh`);  
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

## Manual two-node DM (`raven-node service` + `ash send`)

`raven-node run` cannot originate messages in default builds (it answers
`ATSAM_SESSION_REQUIRED`), and `--send "<text>"` is refused because it puts
plaintext on argv. The secure path is two `raven-node service` receivers plus
`ash send` (message on stdin), exactly what `scripts/lan_direct_two_node.sh` runs:

```bash
cd /path/to/hybrid_messenger/node
export RAVEN_IDENTITY_BACKEND=locked-file RAVEN_CHAT_HISTORY_BACKEND=locked-file  # debug demo only
DATA_A=$(mktemp -d) DATA_B=$(mktemp -d)
./target/debug/ash --data-dir "$DATA_A" init     # note address / pub_hex / fingerprint
./target/debug/ash --data-dir "$DATA_B" init
./target/debug/raven-node service --data-dir "$DATA_A" --lan-listen 127.0.0.1:18001 --ble-listen 127.0.0.1:0 &
./target/debug/raven-node service --data-dir "$DATA_B" --lan-listen 127.0.0.1:18002 --ble-listen 127.0.0.1:0 &
# Each side trusts only its contact book:
./target/debug/ash --data-dir "$DATA_A" contact add --address <B_ADDR> --pub-hex <B_PUB_HEX> \
  --petname Bob --tag bob --lan-dial 127.0.0.1:18002 --verify-fp <B_FP>
./target/debug/ash --data-dir "$DATA_B" contact add --address <A_ADDR> --pub-hex <A_PUB_HEX> \
  --petname Alice --tag alice --verify-fp <A_FP>
printf 'hello from terminal\n' | ./target/debug/ash --data-dir "$DATA_A" send --contact @bob
./target/debug/ash --data-dir "$DATA_B" inbox
```

**Expected:** sender `status delivered`; receiver inbox row
`← Alice [pinned fp=…]: hello from terminal`.

## Phone ↔ Mac terminal (flagged LAN)

> **LAB / NON-RELEASE only.** RVN1 messaging is under a production HOLD
> ([`SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md),
> [`THREAT_MODEL.md`](../docs/THREAT_MODEL.md)). This walkthrough needs a **lab build**
> (`cargo build -p raven-node --features raven-node/unsafe-demo-crypto`) and a Debug/lab iOS build
> (`ios-native` is **not in this repository**, OFF-MAIN). It uses the interim cipher, whose key is
> derivable from the two **public** keys by any observer (a LAN sniffer or bridge included), over plain
> TCP framing — send nothing private. A default build answers `UNSAFE_INTERIM_DISABLED` /
> `ATSAM_SESSION_REQUIRED` and never delivers. For the default-build path use "Manual two-node DM"
> above (`ash send` + `raven-node service`). See also the README "Lab demos".

**Goal:** iOS packs interim-sealed chat bytes into `RavenEnvelopeV1` and TCP to `raven-node` (lab). MeshEnvelope stays active.

### A. Mac listener

```bash
cd /path/to/hybrid_messenger/node
DATA=$(mktemp -d)
./target/debug/raven-node init --data-dir "$DATA"
# Use the Mac's LAN IP rather than 0.0.0.0 (all interfaces) where practical.
./target/debug/raven-node run \
  --data-dir "$DATA" \
  --listen <MAC_LAN_IP>:7420 \
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

Mac (lab build): `DELIVERED bytes=N`, preceded by an `INCOMING` block that prints the received plaintext on stderr. Never screenshot seeds/plaintext or share that log. (There is no `opaque_atsam` delivery line: synthetic opaque ATSAM bodies are refused with `ATSAM_SESSION_REQUIRED` and get no ACK.)

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
Rust: `cargo test -p raven-core --test bridge_v1` (case01–case13 + `e2ee_survives_bridge_hop`).

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

Production body-mode fails closed: without a persisted authenticated ATSAM session, origination returns `ATSAM_SESSION_REQUIRED` and emits no envelope (errata rule 2; synthetic opaque ATSAM bytes are not ciphertext). There is no "opaque ACK" shipping path.

## What is NOT ready yet

- Full PQ ratchet and iOS parity: the ML-KEM-768 + X25519 hybrid is implemented in `raven-core` (`atsam_mlkem`, `pair_init`) but PairInit is production-disabled (live only on the unreviewed LAN-direct slice); not a shipping claim
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
