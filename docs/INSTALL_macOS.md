# Install Raven Serverless (macOS)

`node/scripts/install.sh` is **not** a production installer. It fails closed
and does not put binaries on `PATH`. Use the release-build steps below
(`scripts/install/macos_launchd.sh`). Do not `curl | bash` a convenience
script.

**Unsigned developer layout.** Notarization requires your Apple Developer ID — see [`SIGNING_NOTARIZATION_CHECKLIST.md`](SIGNING_NOTARIZATION_CHECKLIST.md).

**Toolchain:** install Rust with [rustup](https://rustup.rs) (current stable);
older or externally packaged compilers may be too old (rustc 1.83.0 fails at
dependency resolution because the locked graph needs edition 2024; its highest
declared `rust-version` is 1.88). CI is validated on rustc 1.98.0 only; the exact
minimum is not yet verified.

## Option A — from source

```bash
cd node
cargo build --locked -p raven-node -p ash --release
bash scripts/install/macos_launchd.sh
# ash/raven → ~/.local/bin ; raven-node launchd agent
export PATH="$HOME/.local/bin:$PATH"
ash init
ash doctor
```

Never overwrite `/bin/ash`. The installer links `~/.local/bin/ash` → `raven` only in the user prefix.
The data directory (`~/.raven`) is created mode `0700`. The installer picks the
same profile `raven` / `ash` use without `--data-dir` (`RAVEN_DATA_DIR`, then
`ASH_DATA_DIR`, then a legacy `~/.raven-ash` while `~/.raven` does not exist, else
`~/.raven`), and registers *absolute* paths in the launchd agent (launchd starts
it with the working directory `/`, so a relative `RAVEN_DATA_DIR` /
`RAVEN_BIN_DIR` is resolved by the installer first).

**IPC socket location.** The daemon listens on `<data-dir>/raven-node.sock`. When
that path would be too long for a Unix socket (about 100 bytes on macOS, e.g. a
deep checkout or sandbox temp dir) it serves `/tmp/raven-<uid>/raven-<hash>.sock`
instead (a private, owner-only directory). The choice depends on the resolved
data dir, never on how the path was spelled. Do not hard-code the socket path:
`raven doctor` (and the installer's last lines) print the real `ipc_endpoint=`.

**LAN exposure is opt-in with the installer scripts (same default on every
OS):** `scripts/install/macos_launchd.sh` starts the agent listening on
`127.0.0.1:7420`, so LAN peers cannot reach it. (A bare `raven-node service`
without `--lan-listen` binds `0.0.0.0:7420` — always pass an explicit address
when you start it by hand, as in Option B.) To accept LAN peers:

```bash
RAVEN_LAN_LISTEN=<this-Mac-LAN-IP>:7420 bash scripts/install/macos_launchd.sh
```

and allow `raven-node` in the macOS firewall for the local network only.

**Internet direct is opt-in too (off by default).** It lets contacts who have
your Internet address (`raven whoami --card --inet <public-ip-or-name>:7422`)
reach this computer over TCP port **7422** (7421 is mock BLE's, 7423 is
reserved for libp2p). Only your contacts get an answer: anyone else completes
the Noise handshake and is disconnected before this node names itself, but a
scanner still learns that something listens on that port. A build with
Internet direct off (`INTERNET_DIRECT_PRODUCTION_ENABLED = false`, the state
until its waiver is signed) keeps the port closed and logs `internet_direct
failed: INTERNET_DIRECT_HOLD ...`; the debug lab unlock is `RAVEN_LAB_TEST_A=1`.
`raven status` shows an `internet` row: `YES` only while the running service
really has the listener up.

```bash
# at install time
RAVEN_INTERNET_LISTEN=0.0.0.0:7422 bash scripts/install/macos_launchd.sh
# or later (saved in node_policy.json, applied when the agent restarts)
raven node internet on --listen 0.0.0.0:7422
launchctl kickstart -k "gui/$(id -u)/com.raven.raven-node"
raven node internet off          # closes it again at the next restart
```

Firewall: the macOS Application Firewall is off by default. When it is on it
prompts per code identity (an unsigned rebuild prompts again), and "Block all
incoming connections" drops the connections silently. Allow the agent yourself:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add ~/.local/bin/raven-node
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp ~/.local/bin/raven-node
```

Forward TCP 7422 on your router if the Mac is behind NAT. Contacts:
`raven contact add --card '<their card line>'`, `raven contact set-addr <name>
--internet HOST:PORT`, then `raven send --contact <name>` (LAN address first,
then Internet; `--carrier lan|internet` forces one). An address is only a hint:
every connection still has to prove the contact's pinned key. Internet delivery
is for verified contacts only. A contact whose fingerprint you have not
confirmed (`--verify-fp` when adding) is reached over the LAN carrier only, and
only when every address its LAN route resolves to is on your local network:
loopback, private (10/8, 172.16/12, 192.168/16), link-local (169.254/16,
fe80::/10) or unique-local IPv6 (fc00::/7); a public or CGNAT (100.64/10)
address is refused and nothing is dialled. Your Internet listener treats an
unverified contact like a stranger, and so does your LAN listener when it
connects from outside those ranges.

## libp2p: relay and hole punching (not enabled yet)

**libp2p is opt-in too, and release builds do not run it yet.** It is phase P3
of the transports plan
([`design/2026-10-transports-internet-mesh-bridge.md`](design/2026-10-transports-internet-mesh-bridge.md)
§3.5-§3.7). It is meant for two contacts who are both behind a home router
(NAT), with no public IP, port forward or IPv6 between them, so Internet direct
cannot connect them. Each keeps a reservation on a relay that both can reach;
one dials the other through the relay, and libp2p then tries to turn the
relayed connection into a direct one by hole punching (DCUtR). The relay can be
a friend's home node (`raven-node service --relay`) or a dedicated always-on
box (`raven-node relay`). It only passes encrypted bytes along: the Raven link
inside runs end to end between the two contacts.

The gate is `P2P_PRODUCTION_ENABLED = false` in
`node/crates/raven-core/src/p2p_gate.rs`, the state until its waiver is signed
([`WAIVER_P2P_RELAY_DRAFT.md`](WAIVER_P2P_RELAY_DRAFT.md) is an unsigned
draft). While it is off, `raven-node` never listens, dials, reserves or
advertises libp2p, whatever you configure below, and logs one line starting
`P2P_HOLD:`; the debug lab unlock is `RAVEN_LAB_TEST_A=1`, as for Internet
direct. Nothing here has been tested between real homes yet: the physical rows
R7b (two NAT'd homes plus a relay) and R8 (relay only, one side behind CGNAT or
a phone hotspot) are run by the owner and are still pending.

libp2p uses TCP **and** UDP (QUIC) port **7423**, for the endpoint service and
the relay alike (LAN direct stays on TCP 7420, mock BLE on 7421, loopback only,
and Internet direct on TCP 7422).

### Turn p2p on

```bash
# at install time
RAVEN_P2P_LISTEN=7423 bash scripts/install/macos_launchd.sh
# or later (saved in node_policy.json, applied when the agent restarts)
raven node p2p on --listen 7423
launchctl kickstart -k "gui/$(id -u)/com.raven.raven-node"
raven node p2p off               # stops it again at the next restart
```

The service reads `--p2p-listen`, then `RAVEN_P2P_LISTEN`, then
`node_policy.json` (`p2p_listen`). `7423` or `on` listens on every interface,
IPv4 and IPv6, TCP and QUIC; `IP:PORT` listens on that address only; empty or
`off` is off, the default; `relay` opens no port at all (reachable only through
your relays, no hole punching). `raven status` shows a `p2p` row: `YES` only
while the libp2p host is really up, with its NAT reachability (it follows every
new AutoNAT result) and active relay reservations, then `p2p_peer` (this node's
PeerId) and `p2p_listen` (its listen and relay addresses). While the service
runs, the row shows the service's own setting and where it came from
(`--p2p-listen`, `RAVEN_P2P_LISTEN` or `node_policy.json`), so a setting the
installer passed as a flag shows up too; the installer also saves what
`RAVEN_P2P_LISTEN` sets with `raven node p2p on`, so `raven status` and `raven
whoami --card` agree with the service while it is stopped. If another program
already holds the port, the service does not share it: it logs `p2p failed:
listen port 7423/tcp is already in use by another program (another raven-node?);
it is not opened and is retried`, keeps the rest of the host running,
`p2p_listen` says `(none open yet: the port is busy, retrying)`, and once the
port is free it logs `raven-node p2p: listen port 7423/tcp is open now`. The
agent's log (`raven-node.err` in the data dir) holds categories and counts only,
never a PeerId or an address: `raven-node p2p: host up (listeners=<n>)`,
`raven-node p2p: reservation accepted (active=<k>)`, `raven-node p2p:
reservation lost (active=<k>)` and `raven-node p2p: direct connection upgraded
(dcutr)`, and `raven-node p2p: link via a direct connection` / `raven-node p2p:
link via the relay` whenever the kind of a contact's link changes. Stopping or
restarting the agent (`launchctl kickstart -k`, SIGTERM) closes its libp2p
connections first, so a relay frees its reservation at once and the restarted
node reserves again within seconds.

Firewall: the macOS Application Firewall is off by default. When it is on, the
two `socketfilterfw` lines above (`--add` and `--unblockapp` for
`~/.local/bin/raven-node`) allow the program, so they cover TCP and UDP 7423 as
well; RAVEN prints them and never runs them. Add them on a relay and on any
node that should accept direct connections.

A node that only reaches its contacts through a relay needs no port forward. A
relay, or a node that should accept direct connections, has to be reachable on
TCP and UDP 7423 from the Internet: a public IP, global IPv6, a port forward on
the router, or UPnP (below).

### Reach a contact through a relay

Both contacts do this, with the relay's address (its operator prints it with
`raven relay card`, below):

```bash
raven node p2p on --listen 7423 --relay /ip4/203.0.113.7/tcp/7423/p2p/12D3KooW...
# or, when the relay is a contact's home node (raven-node service --relay):
raven node p2p on --listen 7423 --relay @carol
launchctl kickstart -k "gui/$(id -u)/com.raven.raven-node"
# a card that names the relay: give it to your contact, and add theirs
raven whoami --card --via /ip4/203.0.113.7/tcp/7423/p2p/12D3KooW...
raven contact add --card '<their raven-card/2 line>'
raven send --contact bob                  # auto: LAN, Internet direct, then p2p
raven send --contact bob --carrier p2p    # p2p only
```

- `--relay` on `raven node p2p on` names a relay this node keeps a reservation
  on and renews before it expires (repeatable, at most 2; saved as
  `p2p_relays`; the service flag is `--p2p-relay <MULTIADDR>`, the environment
  variable `RAVEN_P2P_RELAYS`, comma separated). A relay address ends in
  `/p2p/<relay PeerId>`. `@carol` takes it from Carol's card: the `via=` entry
  that ends in Carol's own PeerId. No relay address is compiled into RAVEN.
  This is not `raven-node service --relay`, which makes your node serve as a
  relay (next section).
- A relay address may use a name (`/dns/relay.example.org/tcp/7423/p2p/...`,
  also `/dns4` and `/dns6`): it stays a name, is resolved again before every
  reservation attempt, and every address it resolves to is tried in turn; a
  name that does not resolve yet is retried. The `p2p` row counts every
  configured relay (`reservations <active>/<configured>`).
- Cards: once p2p is configured, `raven whoami --card` prints a `raven-card/2`
  line with `p2p=<your PeerId>` and one `via=<relay multiaddr>` per `--via` (at
  most 2); `--inet` and `--lan` work as before. Without p2p it prints the old
  `raven-card/1` line. `raven contact add --card` reads both. Without `--via`,
  the card names the relays the running service uses (while it is stopped, those
  in `node_policy.json`). The card size limit fits the longest valid card (two
  relays, the longest addresses); `raven whoami --card` refuses to print a
  longer one. `raven contact set-addr <name> --p2p <PeerId> --via <MULTIADDR>`
  edits the p2p route (repeat `--via` for a second relay) and `--clear p2p`
  removes it.
- Order: `--carrier auto` tries LAN, then Internet direct, then p2p: a direct
  libp2p connection first, then through the relay, and on a relayed connection
  libp2p then tries the hole-punching upgrade (DCUtR). Hole punching usually
  fails when either side is behind a symmetric NAT or carrier-grade NAT (CGNAT,
  common on mobile networks and phone hotspots); the messages then keep going
  through the relay.
- Trust: a PeerId is only a hint and is never trusted. Every p2p link runs the
  Raven Noise handshake (prologue `raven/p2p-link/v1`) inside the libp2p stream
  and has to prove the contact's pinned key. p2p is for verified (pinned)
  contacts only, like Internet direct: a contact whose fingerprint you have not
  confirmed is never dialled over p2p, and your node answers it like a
  stranger.

### Be the relay for your friends

**Your home node.** Install the agent with the relay role:

```bash
RAVEN_P2P_LISTEN=7423 RAVEN_P2P_RELAY=1 bash scripts/install/macos_launchd.sh
```

The installer rewrites the agent, so pass again every other variable you
installed with, such as `RAVEN_LAN_LISTEN`. `raven-node service --relay`
(`RAVEN_P2P_RELAY=1`) then also serves as a Circuit Relay v2 relay for the
PeerIds in `relay_allow.json` in its data dir, while p2p listen is on. Its relay
PeerId is your own libp2p PeerId, the `p2p=` in your card. Everyone who uses
your relay learns it and can link it to your card, and so to your Raven ID; and
every card that names your relay in a `via=` carries your PeerId and your home
address to whoever receives that card. A dedicated relay (below) has its own
key and avoids this. A Mac that sleeps, or whose user logs out, stops relaying
for that time.

**A dedicated relay** on an always-on box (an always-on Mac or, better, a Linux
box; see [`INSTALL_Linux.md`](INSTALL_Linux.md)):

```bash
raven-node relay --data-dir ~/.raven-relay      # TCP + QUIC 7423 on every interface
```

It holds no Raven identity and touches no keystore, so it never asks for
Keychain access. Its folder holds only `relay_key.ed25519` (its own libp2p key,
mode `0600`), `relay_allow.json`, `relay_status.json` and a lock file (one relay per folder: a second `raven-node relay` on the same folder exits); give it a folder of its own, not your profile. `--listen <PORT|IP:PORT>` changes the address,
`--autonat-server` answers reachability probes from its clients, and the limits
below can be tuned. Keep it running with a service manager of your choice (for
example a launchd agent that runs this command).

If another program already holds its port, the relay exits with `relay
listen: port 7423/tcp is already in use by another program (another relay or
raven-node?); stop it or pick another --listen port`. In reservations it names
only its public (globally routable) listen addresses, an address you listen on
explicitly (`--listen 192.168.1.5:7423`), and each `--external <MULTIADDR>`
you pass (repeatable: `--external /ip4/203.0.113.7/tcp/7423`, `--external
/dns4/relay.example.org/tcp/7423`). Listening on every interface never
discloses its LAN or loopback addresses; behind a router, with no public
address on the box itself, forward the port and pass `--external` with the
router's public address, or it logs `raven-node relay: no public address known
...`. `raven relay status --data-dir <folder>` shows a `state` row: `not
running` while no relay holds the folder, `running`, or `running but its
status is <N>s old (stuck?)` (a running relay rewrites `relay_status.json` at
least every 10 s).

**Who may use it.** The allow-list is on by default: only PeerIds in
`relay_allow.json` may reserve. A missing allow-list means nobody may, and so
does an unreadable or corrupt one (it fails closed).

```bash
raven relay allow @alice          # the PeerId (p2p=) from Alice's card
raven relay allow 12D3KooW...     # or the PeerId itself
raven relay deny @alice
raven relay status                # counts: reservations, circuits, refusals
raven relay card --host 203.0.113.7   # via=/ip4/203.0.113.7/tcp/7423/p2p/<relay PeerId>
# a dedicated relay: name its folder (it has no contacts, so allow PeerIds)
raven relay allow --data-dir ~/.raven-relay 12D3KooW...
raven relay card --data-dir ~/.raven-relay --host 203.0.113.7
```

Without `--data-dir`, `raven relay` works on your profile's own
`relay_allow.json` (`service --relay`); `raven relay allow` also takes `--card
CARD`. Give your friends the `via=` lines from `raven relay card` (`--host` is
the relay's public address, `--port` only if it is not 7423); they pass them to
`raven node p2p on --relay` and `raven whoami --card --via`.

**`--open`** (`raven-node relay --open`, or `--relay-open` on `raven-node
service`) serves anyone instead of the allow-list, with stricter limits (32
reservations, 512 KiB per circuit) and a printed notice. You would then relay
encrypted traffic for people you do not know; keep the allow-list unless you
mean that.

**Limits** (default / hard max): reservations 128 / 1024 in total, 2 / 2 per
peer and 4 / 16 per IP, each lasting 30 min / 2 h; circuits 64 / 256 in total
and 4 / 8 per peer, each lasting 5 min / 30 min and carrying 2 MiB / 16 MiB; 4
reservations and 30 circuits per minute per IP; established connections 256 /
1024 in total and 8 / 32 per IP. A dedicated relay tunes them with
`--max-reservations`, `--max-circuits`, `--circuit-bytes`, `--circuit-secs` and
`--reservation-secs`. "Per IP" means one IPv4 address or one IPv6 /64, and every
node and relay keeps 16 connection slots for its own dials that inbound
connections cannot take. Its log and `relay_status.json` hold counts only
(reservations, circuits, refusals); `relay_status.json` also keeps the relay's
own PeerId and listen addresses for `raven relay card`. `raven status` shows a
`p2p_relay` row when this node relays.

### Router port mapping (UPnP / NAT-PMP, optional)

A home relay is reachable from the Internet only if the router lets TCP and UDP
7423 in. RAVEN can ask the router to do that with UPnP / NAT-PMP, but never on
its own. The first `raven node p2p on` you run in a terminal, while the setting
is still unset, asks once:

```text
Open TCP/UDP 7423 on your router automatically (UPnP/NAT-PMP) so friends can reach this node and it can relay for them? [y/N]
```

Enter or end of input means no. The answer is saved in `node_policy.json`
(`upnp`) and never asked again. A run without a terminal (a script) never asks
and leaves it unset, which behaves as off. `--upnp` or `--no-upnp` on `raven
node p2p on` answers up front, `raven node upnp on` / `raven node upnp off`
changes it at any time (applied when the agent restarts), and the installer
takes `RAVEN_UPNP=1` or `RAVEN_UPNP=0` (unset: an interactive install that turns
p2p on may ask the same question once; a non-interactive one never asks). When
it is on, the log shows only the mapped external port and whether it worked,
never an IP address: `raven-node p2p: upnp mapped port <port>` or `raven-node
p2p: upnp mapping failed`; `raven status` shows an `upnp` row (the setting and
the mapping result). A mapping opens the port to the whole Internet. It cannot
help when your ISP puts the router itself behind CGNAT (its WAN address is in
100.64/10 or another private range).

### What a relay learns

| A relay learns | A relay does not learn |
|---|---|
| Both PeerIds and IP addresses of every circuit, when it opens, how long it lasts and how many bytes pass; who keeps a reservation on it; with `--autonat-server`, the addresses it is asked to probe | Raven IDs (unless it also holds cards, which map a PeerId to a Raven ID), message text, PairInit, RLB1 offers, route tags, message IDs: all are inside libp2p Noise and, inside that, the Raven Noise link `raven/p2p-link/v1` |

A relay that also holds your friends' cards learns who talks to whom, at the
PeerId level. Your PeerId is stable, so it links you across relays and
networks; a stable public IPv6 listen address in a card is a stable location
identifier. Anyone who connects to an open port 7423 learns that node's PeerId
(libp2p names itself in its handshake), but no Raven identity: the Raven link
answers your verified contacts only. libp2p's Identify exchange sends only
addresses confirmed as public (relay circuits, an address AutoNAT found
reachable, a UPnP mapping), never a node's LAN or loopback listen addresses.

## Option B — unsigned release tarball

```bash
bash scripts/release/build_unsigned.sh
# → dist/raven-serverless-*-darwin-*.tar.gz
tar xzf dist/raven-serverless-*.tar.gz
cd raven-serverless-*/
./bin/ash --data-dir ./raven-data init
./bin/raven-node service --data-dir ./raven-data --lan-listen 127.0.0.1:7420
```

Without `--lan-listen` the service binds `0.0.0.0:7420` and accepts connections
from every host on the network.

Verify (**integrity only, not authenticity**):

```bash
shasum -a 256 -c SHA256SUMS.txt
```

`SHA256SUMS.txt` ships *inside* the tarball, so a tampered archive can carry a
matching file: this check only detects accidental corruption after extraction.
For authenticity, compare the separate `<archive>.tar.gz.sha256` written next to
the tarball against a hash you obtained out-of-band from the builder over a
trusted channel (or use a signature).

## Gatekeeper note

Unsigned binaries will be quarantined if downloaded from the Internet. Either:
- build from source locally, or
- complete Developer ID + notarization (checklist), or
- (dev only, archives you built yourself) remove quarantine: `xattr -dr com.apple.quarantine ./bin`. Do not strip quarantine from an archive you downloaded and have not verified out-of-band.

## Proof

```bash
bash scripts/final_serverless_proof.sh
```

## Identity seed

macOS stores the node seed in the **login Keychain** (service `app.raven.node.identity`). Legacy plaintext `identity.seed` files are migrated and removed on first load. See [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md). If a command seems frozen the first time you run it, read the next section.

## Keychain prompts

Raven keeps four kinds of secrets in the login Keychain. The service name is what the macOS dialog shows:

| Service | Holds | Raven's hint calls it |
| --- | --- | --- |
| `app.raven.node.identity` | the identity of one data dir | your Raven identity |
| `app.raven.node.chat-history.v1` | the key that encrypts local chat history | your chat history |
| `app.raven.node.atsam-indexed-session` | one item per conversation | a conversation key |
| `app.raven.node.prekey-lifecycle` | key-exchange state | key-exchange data |

**What happens and why.** A Keychain item trusts only the program that created it, identified by its code signature. The command line (`ash` / `raven`) and the background service (`raven-node`) are separate programs, so when a different one reads an item for the first time (or the same one after you rebuilt or upgraded it) macOS opens a dialog, something like "… wants to use your confidential information stored in "app.raven.node.…" in your keychain", and the program **waits for your answer**. There is no timeout and macOS prints nothing in the terminal, so `ash send`, `ash inbox` or a chat can look frozen. After 3 seconds Raven prints `raven: still waiting for macOS Keychain access (<what>) after 3s.` and the next step on stderr, then a short reminder every 30 seconds. The background service writes the same hint plus a `BLOCKED_ON_KEYCHAIN` line to its log: `raven-node-service.log` in the data dir (`~/.raven` by default) when `ash` started the service, `raven-node.err` there when the launchd agent from Option A runs it.

**A second command waits behind the first.** While the dialog for your identity is open, another `ash` or `raven` command has to wait for the one that is blocked (identity access is one at a time). After 3 seconds it prints `raven: waiting for another raven program that is using your identity (3s).` and carries on by itself once you have answered; it gives up after about a minute, so answer the dialog and run it again.

**What to click.** Find the dialog; it can sit behind other windows (try Mission Control), and if `SecurityAgent` is listed in Activity Monitor a dialog is waiting. Enter your macOS login password and choose **Always Allow**. *Allow* covers this one access only and you will be asked again; *Deny* makes the command fail with a Keychain error (the background service may ask again after it restarts). Ctrl-C stops a command you started in the terminal; the background service has no terminal and simply waits until you answer.

**Why the command line and the service each ask.** Each program is asked once per item. In an installed layout (Option A, or the Option B tarball) `ash` and `raven` are one file, one a link to the other, so there are two programs: `ash` / `raven` and `raven-node`. Straight from a build directory (`node/target/release`) `ash`, `raven` and `raven-node` are three separate executables, and each is asked. Conversations have one item each, so several conversations can mean several dialogs the first time the other program touches them.

**Rebuilt or upgraded binaries ask again.** An unsigned (ad-hoc signed) binary gets a new identity with every build, so macOS no longer recognises it as the program that was allowed. Binaries from `cargo build` and from `scripts/release/build_unsigned.sh` are unsigned in this sense.

**A stable identity for developer builds.** Sign the binaries with a certificate of your own and macOS keeps recognising them:

1. In Keychain Access choose Certificate Assistant, Create a Certificate…, name it (for example `Raven Dev`), set *Identity Type* to Self Signed Root and *Certificate Type* to Code Signing. It stays in your login Keychain on this Mac.
2. Sign the files that actually run, with the same certificate and identifier, then check that the requirement names the certificate and not a `cdhash`. Which files those are depends on how you installed:

   | Layout | Sign |
   | --- | --- |
   | Option A (installer) | `~/.local/bin/raven` and `~/.local/bin/raven-node` (`ash` there is a link to `raven`), then restart the agent |
   | Option B (tarball) | `bin/ash` and `bin/raven-node` (`bin/raven` is a link to `bin/ash`) |
   | Straight from a build | `node/target/release/ash`, `raven` and `raven-node` (`target/debug` for debug builds) |

   Option A with the installer's default location (use `RAVEN_BIN_DIR` if you set it); for the other layouts run the same `codesign` line on the files in the table:

   ```bash
   for bin in raven raven-node; do
     codesign -f -s "Raven Dev" -i app.raven.node "$HOME/.local/bin/$bin"
   done
   codesign -d -r- "$HOME/.local/bin/raven-node"   # designated => identifier "app.raven.node" and certificate leaf = H"…"
   launchctl kickstart -k "gui/$(id -u)/com.raven.raven-node"   # restart the agent so it runs the signed file
   ```

   (`codesign` asks to use the certificate's private key: choose **Allow**, not *Always Allow*. If `codesign` may use that key without asking, any program running as you can sign itself as Raven and then read Raven's Keychain items without a dialog; with *Allow* you confirm each signing run.) Signing sticks to the file, so repeat it whenever the files that run are replaced: the installer copies freshly built, unsigned files over the installed ones every time it runs, and a rebuild replaces the ones in `target`.
3. Run `ash` once, let the service start (or restart it as above) and answer the dialogs with **Always Allow**. Items that already exist keep trusting the old identity, so each one asks once more; after that, rebuilds you sign again should stop asking. If a dialog keeps coming back, the `codesign -d -r-` line above shows whether the file that runs really carries the certificate.

**SSH sessions have no dialog.** Over SSH macOS cannot show the window, so a command that needs an answer waits or fails. Run it once on the Mac itself (Terminal app or Screen Sharing), answer the dialog there, then use SSH.

**Never delete these items by hand to "fix" a prompt.** In particular do not run `security delete-generic-password -s app.raven.node.identity` without `-a <account>`: it removes whichever matching item macOS finds first, possibly the identity of another data dir. A deleted identity cannot be recovered; Raven refuses to start with "recorded Keychain identity is missing" rather than invent a new address.

## CI menu smoke is not an install proof

GitHub Actions `rust-linux`, `rust-macos`, and `rust-windows` run `node/scripts/ash_menu_smoke.sh` against **debug** `target/debug/ash` only. That is **menu/CLI smoke** (init → doctor → contacts → send). It does **not** prove:

- Keychain identity (Option A default above remains the login Keychain)
- launchd service install (`scripts/install/macos_launchd.sh`)
- Gatekeeper-clean or notarized install (still unsigned; notarization remains `BLOCKED_HUMAN`)

CI and lab scripts force `RAVEN_IDENTITY_BACKEND=locked-file` so ash and raven-node share an ephemeral `0600` seed file under `mktemp` `--data-dir` (avoids Keychain ACL hangs). `locked-file` is refused in Release. Operators must **not** set that override for a normal Keychain install.

The chat-history / outbound-stage key is a separate Keychain item (service `app.raven.node.chat-history.v1`, one per data dir). In **debug** builds `RAVEN_CHAT_HISTORY_BACKEND=locked-file` (or `RAVEN_IDENTITY_BACKEND=locked-file`) makes ash and raven-node derive a per-data-dir lab key instead and never touch the Keychain for it; Release builds ignore the variable. Without it, the first history read of each binary (service, `ash`) waits on a Keychain access prompt until someone answers it (see [Keychain prompts](#keychain-prompts)); no cross-process lock is held meanwhile, and the service logs `… is taking longer than 15s … answer its prompt` when its start-up is stuck there.
