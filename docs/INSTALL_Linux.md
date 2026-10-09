# Install Raven Serverless (Linux)

`node/scripts/install.sh` is **not** a production installer. It fails closed
and does not put binaries on `PATH`. Use the release-build steps below
(`scripts/install/linux_systemd_user.sh`). Do not `curl | bash` a convenience
script.

> **Where your keys live.** With an unlocked desktop keyring (GNOME Keyring /
> KWallet, i.e. Secret Service) RAVEN stores its keys there. Without one (servers,
> SSH sessions, a Raspberry Pi bridge, musl builds) it keeps them in an encrypted
> file, `<data-dir>/keystore.vault`, protected by a **passphrase** you choose
> (Argon2id + XChaCha20-Poly1305). The choice is made once per profile and recorded
> in `<data-dir>/keystore.backend`; RAVEN never moves keys between the two on its
> own. Details: [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md) and
> [`design/2026-10-linux-keystore.md`](design/2026-10-linux-keystore.md).

### Passphrase vault in practice

- `raven init` / `ash init` on a terminal explains this and asks for the
  passphrase twice (nothing is echoed; at least 8 characters). Later runs ask once.
  There is no recovery without it.
- Non-interactive use (scripts, CI, the service) needs a passphrase **file**:

  ```bash
  mkdir -p ~/.config/raven && chmod 700 ~/.config/raven
  ( umask 077; printf '%s\n' 'your long passphrase' > ~/.config/raven/keystore-passphrase )
  export RAVEN_KEYSTORE_PASSPHRASE_FILE=~/.config/raven/keystore-passphrase
  ```

  The file must be a regular file owned by you with mode `0600` or `0400`. The
  passphrase itself is never accepted in an environment variable or on the command
  line (`RAVEN_KEYSTORE_PASSPHRASE` is refused). A file next to the data dir
  protects only against copies of the data dir *without* it: keep it out of
  backups that contain `keystore.vault`.
- `raven-node service` never prompts. Give it the file through the installer
  (below), or with systemd `LoadCredential=raven-keystore-passphrase:<file>`.
- Force the vault on a desktop with `RAVEN_KEYSTORE_BACKEND=vault` before the
  first `raven init` of a profile.

**Toolchain:** install Rust with [rustup](https://rustup.rs) (current stable);
distro-packaged compilers are usually too old (rustc 1.83.0 fails at dependency
resolution because the locked graph needs edition 2024; its highest declared
`rust-version` is 1.88). CI is validated on rustc 1.98.0 only; the exact minimum
is not yet verified.

## From source

```bash
cd node
cargo build --locked -p raven-node -p ash --release
bash scripts/install/linux_systemd_user.sh
export PATH="$HOME/.local/bin:$PATH"
raven init        # `ash` is only aliased when no system ash shell exists
raven doctor
```

Headless host (no desktop keyring): pass the passphrase file so the unit can
unlock the vault. The unit gets `Environment=RAVEN_KEYSTORE_PASSPHRASE_FILE=<path>`
(the path only); `RAVEN_SYSTEMD_LOAD_CREDENTIAL=1` uses `LoadCredential=` instead:

```bash
RAVEN_KEYSTORE_PASSPHRASE_FILE=$HOME/.config/raven/keystore-passphrase \
  bash scripts/install/linux_systemd_user.sh
```

User systemd unit runs `raven-node service` (bridge + IPC). Does not require root.
The data directory (`~/.raven`) is created mode `0700`. The installer picks the
same profile `raven` / `ash` use without `--data-dir` (`RAVEN_DATA_DIR`, then
`ASH_DATA_DIR`, then a legacy `~/.raven-ash` while `~/.raven` does not exist, else
`~/.raven`), and writes *absolute*, quoted paths into the unit (`systemd --user`
starts it from your home directory, so a relative `RAVEN_DATA_DIR` /
`RAVEN_BIN_DIR` is resolved by the installer first).

**IPC socket location.** The daemon listens on `<data-dir>/raven-node.sock`. When
that path would be too long for a Unix socket (about 107 bytes on Linux) it serves
`/tmp/raven-<uid>/raven-<hash>.sock` instead (a private, owner-only directory).
The choice depends on the resolved data dir, never on how the path was spelled.
Do not hard-code the socket path: `raven doctor` (and the installer's last lines)
print the real `ipc_endpoint=`.

**LAN exposure is opt-in with the installer scripts (same default on every
OS):** `scripts/install/linux_systemd_user.sh` starts the service listening on
`127.0.0.1:7420`, so LAN peers cannot reach it. (A bare `raven-node service`
without `--lan-listen` binds `0.0.0.0:7420` — always pass an explicit address
when you start it by hand.) To accept LAN peers, install with an explicit
address and open the port to your LAN only:

```bash
RAVEN_LAN_LISTEN=<this-host-LAN-IP>:7420 bash scripts/install/linux_systemd_user.sh
sudo ufw allow from 192.168.0.0/16 to any port 7420 proto tcp
```

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
RAVEN_INTERNET_LISTEN=0.0.0.0:7422 bash scripts/install/linux_systemd_user.sh
# or later (saved in node_policy.json, applied when the service restarts)
raven node internet on --listen 0.0.0.0:7422
systemctl --user restart raven-node
raven node internet off          # closes it again at the next restart
```

The service reads `--internet-listen`, then `RAVEN_INTERNET_LISTEN`, then
`node_policy.json`; a bare IP gets port 7422 and an empty value is off.
Firewall: Linux shows no prompt, ufw / firewalld / nftables and cloud security
groups decide. Open the port yourself, e.g. `sudo ufw allow 7422/tcp`
(`firewall-cmd --add-port=7422/tcp --permanent` on firewalld), and forward TCP
7422 on your router if the host is behind NAT. A VPS with a public IP or a home
with global IPv6 (`[::]:7422`) needs no forwarding.

Contacts: `raven contact add --card '<their card line>'` saves their routes,
`raven contact set-addr <name> --internet HOST:PORT` (or `--lan`, `--clear
internet`) edits them, and `raven send --contact <name>` tries their LAN
address first, then their Internet address (`--carrier lan|internet` forces
one). An address is only a hint: every connection still has to prove the
contact's pinned key. Internet delivery is for verified contacts only. A contact
whose fingerprint you have not confirmed (`--verify-fp` when adding) is reached
over the LAN carrier only, and only when every address its LAN route resolves to
is on your local network: loopback, private (10/8, 172.16/12, 192.168/16),
link-local (169.254/16, fe80::/10) or unique-local IPv6 (fc00::/7); a public or
CGNAT (100.64/10) address is refused and nothing is dialled. Your Internet
listener treats an unverified contact like a stranger, and so does your LAN
listener when it connects from outside those ranges.

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
RAVEN_P2P_LISTEN=7423 bash scripts/install/linux_systemd_user.sh
# or later (saved in node_policy.json, applied when the service restarts)
raven node p2p on --listen 7423
systemctl --user restart raven-node
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
port is free it logs `raven-node p2p: listen port 7423/tcp is open now`. The log
(`journalctl --user -u raven-node`) holds categories and counts only, never a
PeerId or an address: `raven-node p2p: host up (listeners=<n>)`, `raven-node
p2p: reservation accepted (active=<k>)`, `raven-node p2p: reservation lost
(active=<k>)` and `raven-node p2p: direct connection upgraded (dcutr)`, and
`raven-node p2p: link via a direct connection` / `raven-node p2p: link via the
relay` whenever the kind of a contact's link changes. Stopping or restarting the
service (`systemctl --user stop|restart raven-node`, SIGTERM) closes its libp2p
connections first, so a relay frees its reservation at once and the restarted
node reserves again within seconds.

Firewall: Linux shows no prompt. RAVEN prints these rules and never runs them;
add them on a relay and on any node that should accept direct connections (or
the equivalent in firewalld, nftables or your cloud security group):

```bash
sudo ufw allow 7423/tcp
sudo ufw allow 7423/udp
```

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
systemctl --user restart raven-node
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

**Your home node.** Install the service with the relay role:

```bash
RAVEN_P2P_LISTEN=7423 RAVEN_P2P_RELAY=1 bash scripts/install/linux_systemd_user.sh
```

The installer rewrites the unit, so pass again every other variable you
installed with, such as `RAVEN_LAN_LISTEN`. `raven-node service --relay`
(`RAVEN_P2P_RELAY=1`) then also serves as a Circuit Relay v2 relay for the
PeerIds in `relay_allow.json` in its data dir, while p2p listen is on. Its relay
PeerId is your own libp2p PeerId, the `p2p=` in your card. Everyone who uses
your relay learns it and can link it to your card, and so to your Raven ID; and
every card that names your relay in a `via=` carries your PeerId and your home
address to whoever receives that card. A dedicated relay (below) has its own
key and avoids this.

**A dedicated relay** on an always-on box (a home server, a Raspberry Pi):

```bash
raven-node relay --data-dir ~/.raven-relay      # TCP + QUIC 7423 on every interface
```

It holds no Raven identity and touches no keystore (no Secret Service, no
passphrase vault), so it restarts without anyone typing a passphrase. Its
folder holds only `relay_key.ed25519` (its own libp2p key, mode `0600`), `relay_allow.json`, `relay_status.json` and a lock file (one relay per folder: a second `raven-node relay` on the same folder exits); give it a folder of its own, not
your profile. `--listen <PORT|IP:PORT>` changes the address, `--autonat-server`
answers reachability probes from its clients, and the limits below can be
tuned. Keep it running with a service manager of your choice (for example a
systemd unit that runs this command).

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
changes it at any time (applied when the service restarts), and the installer
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

## Unsigned tarball

```bash
bash scripts/release/build_unsigned.sh
tar xzf dist/raven-serverless-*-linux-*.tar.gz
cd raven-serverless-*/
./bin/ash --data-dir ./raven-data init
```

If you then start the daemon by hand, bind it explicitly, e.g.
`./bin/raven-node service --data-dir ./raven-data --lan-listen 127.0.0.1:7420`
(the bare default is `0.0.0.0:7420`).

**Checksums are integrity-only.** `SHA256SUMS.txt` ships *inside* the tarball, so
a tampered archive can carry a matching file; checking it only detects accidental
corruption after extraction. For authenticity, compare the separate
`<archive>.tar.gz.sha256` written next to the tarball against a hash you obtained
out-of-band from the builder over a trusted channel (or use a signature). Signing/
packages (deb/rpm) are operator-owned — not produced unsigned.

## Notes

- `ash` is also the BusyBox / Alpine shell. The installer only links `~/.local/bin/ash` → `raven` when no other `ash` is on the system; otherwise use `raven`.
- No central message server is configured; see `SERVERLESS_MODEL.md`.
- Identity seed storage: Secret Service when an unlocked keyring answers, else the passphrase vault (above). The mode `0600` `locked-file` seed is a debug/lab/CI-only override that Release builds refuse — see [`IDENTITY_SEED_STORAGE.md`](IDENTITY_SEED_STORAGE.md).
