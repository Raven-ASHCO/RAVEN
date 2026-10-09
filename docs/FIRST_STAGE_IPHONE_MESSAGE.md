# First-stage iPhone message / مرحلهٔ اول پیام آیفون

Crystal-clear steps for **today’s** test: add a contact → send a message over **Wi‑Fi** and/or **Bluetooth** using the latest Raven iOS app (`ios-native`).

> **LAB / NON-RELEASE only — read before running anything below.**
> RVN1 messaging is under a production HOLD ([`protocol/SECURITY_ERRATA_RVN1_2026-08-13.md`](../protocol/SECURITY_ERRATA_RVN1_2026-08-13.md), [`THREAT_MODEL.md`](THREAT_MODEL.md)).
> - The Mac side of this walkthrough (`raven-node run`) needs a **lab build**: `cd node && cargo build -p raven-node --features raven-node/unsafe-demo-crypto`, and the iOS side must be a Debug/lab build.
> - That path uses the interim body cipher, whose key is derivable from the two **public** keys: anyone who sees both public keys — a LAN sniffer or a bridge included — can decrypt it. Do **not** send anything private.
> - A default (release or plain debug) `raven-node` answers `UNSAFE_INTERIM_DISABLED` / `ATSAM_SESSION_REQUIRED` and never delivers, so this flow cannot work against it.
> - The iOS tree (`ios-native`) is **not in this repository** (OFF-MAIN); the app-side steps cannot be verified from this checkout, and iOS Release builds hard-disable RVN1.
> - The default-build, authenticated-session terminal path is `ash send` + `raven-node service` (see `node/TERMINAL_DEMO.md`, "Manual two-node DM") and the README "Direct chat (LAN)" section — itself an unreviewed lab/CI slice, not a release claim.

---

## FA — خلاصه

1. Xcode → Run اپ Raven روی آیفون  
2. **Account → Serverless LAN · enable flag** → فلگ **Serverless · RavenEnvelopeV1** را روشن کنید  
3. مخاطب: **Discover** → Paste whoami / اسکن QR  
4. **Wi‑Fi:** در همان صفحه Serverless LAN، Host/Port/Peer pub را ذخیره کنید → New Chat → پیام  
5. **Bluetooth:** هر دو گوشی نزدیک + بلوتوث روشن → New Chat → پیام (مسیر RavenEnvelope وقتی فلگ ON است)

---

## EN — Flag to enable

| Where | What |
|---|---|
| **Account → Serverless LAN · enable flag** | Toggle **Serverless · RavenEnvelopeV1** **ON** |
| Default | **OFF** — without it, Discover paste/whoami is limited; chat uses legacy MeshEnvelope for BLE |

---

## Exact steps — Wi‑Fi / LAN

### A. Peer is another iPhone (same Wi‑Fi)

1. On **both** phones: enable the flag (above).  
2. **Phone B** — Account → Serverless LAN → copy **Ed25519 pub (hex)**.  
3. **Phone A** — Discover → **Paste ash whoami** *or* paste B’s `rvn1…` + `pub_hex` (from B’s whoami-equivalent / QR fields) → Save.  
4. Optional LAN TCP between phones is advanced; for same-LAN phone↔phone, **Bluetooth mesh / BLE RVN1** is the usual carrier. For **Mac `raven-node`**, use section below.

### B. Peer is Mac `ash` / `raven-node` (recommended LAN test)

**Mac:**

```bash
cd /path/to/hybrid_messenger   # YOUR home path — not /Users/ahmd
export PATH="$HOME/.cargo/bin:$PATH"
bash scripts/ash_first_run.sh --init-only
# Note address + pub_hex + fingerprint (public only)

DATA=$(mktemp -d)
# Lab build only (see banner): cd node && cargo build -p raven-node --features raven-node/unsafe-demo-crypto
# Listen on the Mac's LAN IP (not 0.0.0.0, which exposes the port on every interface);
# `run` carries the lab interim cipher over a plain TCP framing — trusted LAN only.
./node/target/debug/raven-node run \
  --data-dir "$DATA" \
  --listen <MAC_LAN_IP>:7420 \
  --peer-pub-hex <IPHONE_PUB_HEX> \
  --timeout-secs 600
```

**iPhone:**

1. Flag **ON** (Serverless LAN screen).  
2. Copy **This device pub hex** → paste into Mac `--peer-pub-hex`.  
3. Fields on phone:
   - **Host** = Mac LAN IP (Settings → Wi‑Fi → ⓘ on Mac, or `ipconfig getifaddr en0`)  
   - **Port** = `7420`  
   - **Peer pub hex** = Mac `pub_hex` from `ash whoami` / init  
4. **Save LAN config**.  
5. Discover → Paste Mac `ash whoami` (rvn1 + pub_hex) → petname → Save.  
6. Inbox → **Start a chat** / New Chat → select contact → send text.  
7. Mac log should show `DELIVERED bytes=N`. Note: the **lab** build also prints the received message as an `INCOMING` plaintext block on stderr, so do not share or screenshot that log.

---

## Exact steps — Bluetooth

1. Flag **ON** on **both** devices.  
2. Bluetooth **ON**; phones within a few meters; keep Raven in foreground once.  
3. Add contact: **Discover** → Scan QR **or** Paste whoami (second phone / Mac public bits).  
4. Wait until mesh shows a nearby/connected peer (status / mesh indicators).  
5. New Chat → send.  
6. With flag ON, chat send also enqueues **raw RavenEnvelopeV1 on BLE** when peers are connected (parallel with LAN if configured).  
7. If flag **OFF**, BLE still uses shipping **MeshEnvelope** JSON path — honest fallback.

---

## If other side is Mac ash (checklist)

| Step | Mac | iPhone |
|---|---|---|
| Identity | `ash init` / `ash_first_run.sh --init-only` | Auto on first launch |
| Share | `ash whoami` → address + pub_hex | Paste in Discover |
| LAN listen | `raven-node run --listen <MAC_LAN_IP>:7420` (lab build) | Host=Mac IP, Port=7420, Peer pub=Mac |
| Send | Wait for DELIVERED | Chat compose → Send |

Never share seeds / private keys.

---

## Rebuild / open Xcode

```bash
# OFF-MAIN: ios-native is not in this repository
cd /path/to/hybrid_messenger/ios-native/RAVEN
open RAVEN.xcodeproj
# Scheme: RAVEN · Run on device or Simulator
```

Simulator LAN to Mac: Host `127.0.0.1` only if `raven-node` listens on loopback; physical phone needs Mac’s LAN IP.

---

## Honest capability note

| Path | Flag OFF | Flag ON |
|---|---|---|
| Discover + paste whoami | QR mainly | Discover + paste + contact requests |
| Wi‑Fi to raven-node | idle | TCP RavenEnvelopeV1 (Serverless LAN config) |
| Bluetooth | MeshEnvelope (shipping) | + parallel BLE RavenEnvelopeV1 when peers connected |
