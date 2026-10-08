# Install Raven Serverless (Windows)

Also see [`node/WINDOWS.md`](../node/WINDOWS.md) and [`node/scripts/install/WINDOWS_SERVICE.md`](../node/scripts/install/WINDOWS_SERVICE.md).

Unix `node/scripts/install.sh` is **not** an installer (fail-closed). It never
was a Windows path. Use the release-build steps below.

## Native build

```powershell
cd node
cargo build -p raven-core -p raven-node -p ash --release
.\target\release\ash.exe --data-dir $env:TEMP\raven-data init
.\target\release\ash.exe --data-dir $env:TEMP\raven-data doctor
```

Task Scheduler / service helper: `scripts/install/windows_service.ps1`
(builds with `--locked`). Its default `-DataDir` is the profile `raven.exe` /
`ash.exe` use without `--data-dir` (`RAVEN_DATA_DIR`, then `ASH_DATA_DIR`, then
`%USERPROFILE%\.raven`); binaries go to `%LOCALAPPDATA%\RavenNode` (`-BinDir`).
The named pipe is per user, not per profile, so a daemon installed with any other
`-DataDir` must be addressed with `--data-dir <that dir>` on every CLI command, or
the CLI would ping a daemon that serves a different profile. **LAN exposure is
opt-in with this helper (same default on every OS):** the task listens on `127.0.0.1:7420`; pass `-LanListen <LAN-IP>:7420`
and allow TCP 7420 for the local subnet in Windows Firewall to accept LAN peers.
A bare `raven-node.exe service` without `--lan-listen` binds `0.0.0.0:7420`, so
always pass an explicit address when you start it by hand.

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

```powershell
# at install time
.\node\scripts\install\windows_service.ps1 -InternetListen 0.0.0.0:7422
# or later (saved in node_policy.json, applied when the task restarts)
raven.exe node internet on --listen 0.0.0.0:7422
Stop-ScheduledTask -TaskName RavenNodeBridge; Start-ScheduledTask -TaskName RavenNodeBridge
raven.exe node internet off      # closes it again at the next restart
```

Firewall: on the first non-loopback listen Defender Firewall may show "Windows
Security Alert"; allowing needs an administrator and dismissing it creates a
block rule. The installer prints, and never runs, the rule to add in an
elevated PowerShell (Private profile only, never Public; outbound needs no rule):

```powershell
New-NetFirewallRule -DisplayName "Raven node" -Direction Inbound `
  -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol TCP -LocalPort 7422 -Profile Private
```

Forward TCP 7422 on your router if the PC is behind NAT. The logon task runs only
while you are signed in, so a Windows PC is reachable only then. Contacts:
`raven contact add --card "<their card line>"`, `raven contact set-addr <name>
--internet HOST:PORT`, then `raven send --contact <name>` (LAN address first,
then Internet; `--carrier lan|internet` forces one). Internet delivery is for
verified contacts only. A contact whose fingerprint you have not confirmed
(`--verify-fp` when adding) is reached over the LAN carrier only, and only when
every address its LAN route resolves to is on your local network: loopback,
private (10/8, 172.16/12, 192.168/16), link-local (169.254/16, fe80::/10) or
unique-local IPv6 (fc00::/7); a public or CGNAT (100.64/10) address is refused
and nothing is dialled. Your Internet listener treats an unverified contact like
a stranger, and so does your LAN listener when it connects from outside those
ranges.

**Toolchain:** install Rust with [rustup](https://rustup.rs) (current stable);
older compilers fail at dependency resolution (rustc 1.83.0: the locked graph
needs edition 2024; its highest declared `rust-version` is 1.88). CI is validated
on rustc 1.98.0 only; the exact minimum is not yet verified.

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

In PowerShell a bare `@name` means splatting, so quote contact names that start
with `@` (`'@carol'`), as below.

### Turn p2p on

```powershell
# at install time (-P2pListen, like -InternetListen; -P2pRelays a,b and -Upnp 1|0 too)
.\node\scripts\install\windows_service.ps1 -P2pListen 7423
# or later (saved in node_policy.json, applied when the task restarts)
raven.exe node p2p on --listen 7423
Stop-ScheduledTask -TaskName RavenNodeBridge; Start-ScheduledTask -TaskName RavenNodeBridge
raven.exe node p2p off           # stops it again at the next restart
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
`-P2pListen` sets with `raven node p2p on`, so `raven status` and `raven whoami
--card` agree with the service while it is stopped. If another program already
holds the port, the service does not share it: it logs `p2p failed: listen port
7423/tcp is already in use by another program (another raven-node?); it is not
opened and is retried`, keeps the rest of the host running, `p2p_listen` says
`(none open yet: the port is busy, retrying)`, and once the port is free it logs
`raven-node p2p: listen port 7423/tcp is open now`. (A program that starts later
and binds 7423 with `SO_REUSEADDR` can still share the port on Windows, since
libp2p does not bind it exclusively.) Its log lines hold categories and counts
only, never a PeerId or an address: `raven-node p2p: host up (listeners=<n>)`,
`raven-node p2p: reservation accepted (active=<k>)`, `raven-node p2p:
reservation lost (active=<k>)` and `raven-node p2p: direct connection upgraded
(dcutr)`, and `raven-node p2p: link via a direct connection` / `raven-node p2p:
link via the relay` whenever the kind of a contact's link changes. Ctrl-C in a
console that runs `raven-node.exe service` closes its libp2p connections first,
so a relay frees the reservation at once. `Stop-ScheduledTask` ends the process
at once instead; the restarted node still reserves again within seconds (a relay
keeps up to two reservations per peer while the old one times out).

Firewall: on the first non-loopback listen Defender Firewall may show "Windows
Security Alert"; allowing needs an administrator and dismissing it creates a
block rule. RAVEN prints, and never runs, the two rules to add in an elevated
PowerShell (Private profile only, never Public; outbound needs no rule). Add
them on a relay and on any node that should accept direct connections:

```powershell
New-NetFirewallRule -DisplayName "Raven node p2p" -Direction Inbound `
  -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol TCP -LocalPort 7423 -Profile Private
New-NetFirewallRule -DisplayName "Raven node p2p" -Direction Inbound `
  -Program "$env:LOCALAPPDATA\RavenNode\raven-node.exe" -Protocol UDP -LocalPort 7423 -Profile Private
```

While Windows treats the current network as Public, these rules do not apply
and nothing gets in. A node that only reaches its contacts through a relay
needs no port forward. A relay, or a node that should accept direct
connections, has to be reachable on TCP and UDP 7423 from the Internet: a
public IP, global IPv6, a port forward on the router, or UPnP (below).

### Reach a contact through a relay

Both contacts do this, with the relay's address (its operator prints it with
`raven relay card`, below):

```powershell
raven.exe node p2p on --listen 7423 --relay /ip4/203.0.113.7/tcp/7423/p2p/12D3KooW...
# or, when the relay is a contact's home node (raven-node service --relay):
raven.exe node p2p on --listen 7423 --relay '@carol'
Stop-ScheduledTask -TaskName RavenNodeBridge; Start-ScheduledTask -TaskName RavenNodeBridge
# a card that names the relay: give it to your contact, and add theirs
raven.exe whoami --card --via /ip4/203.0.113.7/tcp/7423/p2p/12D3KooW...
raven.exe contact add --card "<their raven-card/2 line>"
raven.exe send --contact bob                  # auto: LAN, Internet direct, then p2p
raven.exe send --contact bob --carrier p2p    # p2p only
```

- `--relay` on `raven node p2p on` names a relay this node keeps a reservation
  on and renews before it expires (repeatable, at most 2; saved as
  `p2p_relays`; the service flag is `--p2p-relay <MULTIADDR>`, the environment
  variable `RAVEN_P2P_RELAYS`, comma separated). A relay address ends in
  `/p2p/<relay PeerId>`. `'@carol'` takes it from Carol's card: the `via=`
  entry that ends in Carol's own PeerId. No relay address is compiled into
  RAVEN. This is not `raven-node service --relay`, which makes your node serve
  as a relay (next section).
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

**A Windows PC is a poor always-on relay.** The logon task runs only while you
are signed in, so a relay on this PC serves your friends only then, and RAVEN
sets up no Windows service or task for a dedicated relay. For a relay your
friends rely on, prefer an always-on Linux box (see
[`INSTALL_Linux.md`](INSTALL_Linux.md)).

**Your home node.** Install the task with the relay role:

```powershell
.\node\scripts\install\windows_service.ps1 -P2pListen 7423 -P2pRelay
```

The helper registers the task again, so pass again every parameter you
installed with, such as `-LanListen`. `raven-node service --relay`
(`-P2pRelay` here, `RAVEN_P2P_RELAY=1` elsewhere) then also serves as a Circuit Relay v2 relay for the
PeerIds in `relay_allow.json` in its data dir, while p2p listen is on. Its relay
PeerId is your own libp2p PeerId, the `p2p=` in your card. Everyone who uses
your relay learns it and can link it to your card, and so to your Raven ID; and
every card that names your relay in a `via=` carries your PeerId and your home
address to whoever receives that card. A dedicated relay (below) has its own
key and avoids this.

**A dedicated relay:**

```powershell
raven-node.exe relay --data-dir "$env:LOCALAPPDATA\RavenRelay"   # TCP + QUIC 7423 on every interface
```

It holds no Raven identity and touches no keystore (no DPAPI identity). Its
folder holds only `relay_key.ed25519` (its own libp2p key; like every private Raven file and folder it gets a protected ACL that allows only your Windows account), `relay_allow.json`, `relay_status.json` and a lock file (one relay per folder: a second `raven-node relay` on the same folder exits); give it a folder of its own,
not your profile. `--listen <PORT|IP:PORT>` changes the address,
`--autonat-server` answers reachability probes from its clients, and the limits
below can be tuned. It runs only while its window or a task of your own keeps it running.

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

```powershell
raven.exe relay allow '@alice'        # the PeerId (p2p=) from Alice's card
raven.exe relay allow 12D3KooW...     # or the PeerId itself
raven.exe relay deny '@alice'
raven.exe relay status                # counts: reservations, circuits, refusals
raven.exe relay card --host 203.0.113.7   # via=/ip4/203.0.113.7/tcp/7423/p2p/<relay PeerId>
# a dedicated relay: name its folder (it has no contacts, so allow PeerIds)
raven.exe relay allow --data-dir "$env:LOCALAPPDATA\RavenRelay" 12D3KooW...
raven.exe relay card --data-dir "$env:LOCALAPPDATA\RavenRelay" --host 203.0.113.7
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
changes it at any time (applied when the task restarts), and the installer
takes `-Upnp 1` or `-Upnp 0` (unset: an interactive install that turns p2p on
may ask the same question once; a non-interactive one never asks). When
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

## Unsigned layout from macOS/Linux host

Cross-compile notes in `node/WINDOWS.md`. Prefer native Windows CI for release binaries you will Authenticode-sign.

## Signing

MSI / Authenticode steps: [`SIGNING_NOTARIZATION_CHECKLIST.md`](SIGNING_NOTARIZATION_CHECKLIST.md). This repo ships **unsigned** artifacts only.

## Identity seed

Windows stores the node seed as a **DPAPI**-protected `identity.seed` blob (user-bound). Legacy plaintext 32-byte files are migrated automatically. See [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md).

The profile folder and every private file Raven writes there (and in a relay's
folder) get a protected ACL with a single entry: full access for your Windows
account. Nothing is inherited from the parent folder, and SYSTEM and
Administrators get no entry (an administrator can still take ownership, as
root can on Unix). Files that other programs create in the folder inherit the
same entry. The ACL is set before a file's contents are written and read back
afterwards; when that fails (for example a profile on a FAT32 or exFAT drive,
which has no ACLs) Raven refuses to use the folder instead of keeping private
state readable by others. Check it with `icacls "$env:USERPROFILE\.raven"`.
