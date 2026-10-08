# DRAFT owner waiver: libp2p relay and hole punching (transports P3)

> **DRAFT. NOT SIGNED, NOT IN FORCE.** Nothing in the tree depends on this
> file (the doc comment of `p2p_gate.rs` only points here).
> `P2P_PRODUCTION_ENABLED` stays `false` until the owner signs a final copy
> (renamed to `docs/WAIVER_P2P_RELAY_<date>.md`), the exit conditions in §7 are
> met, and the gate-flip change (§8) is applied as its own reviewed commit. For
> this phase the design recommends an independent review, not only a waiver
> (design §8 Q1; §3 hold 3 below).

| | |
|---|---|
| **Waiver ID** | `WAIVER-P2P-RELAY-<date>` (to be assigned on signature) |
| **Extends** | [`WAIVER-LAN-DIRECT-2026-10-07`](WAIVER_LAN_DIRECT_INDEXED_SESSION_2026-10-07.md), whose §6 makes any scope extension without a new record a lapse condition. Independent of the Internet direct draft ([`WAIVER_INTERNET_DIRECT_DRAFT.md`](WAIVER_INTERNET_DIRECT_DRAFT.md)): either may be signed first, and neither covers the other's carrier |
| **Approver** | Ahmadreza, protocol owner (signature pending) |
| **Date** | pending |
| **Decision** | Enable the libp2p carrier (direct TCP/QUIC, Circuit Relay v2, DCUtR; verified contacts only) and the relay role in default and release builds under this waiver, instead of waiting for an independent review |
| **Review by** | `<YYYY-MM-DD>`: at most 3 months after signature |
| **Withdrawal** | Set `P2P_PRODUCTION_ENABLED = false` in `node/crates/raven-core/src/p2p_gate.rs`. `PRODUCTION_NAT_CONNECTIVITY_ENABLED` (`node/crates/raven-swarm/src/connectivity.rs`) is not this gate: it belongs to the separate `raven-swarm-connectivity-experimental` binary, stays `false` whether or not this waiver is in force, and needs its own record to change |
| **Design** | [`design/2026-10-transports-internet-mesh-bridge.md`](design/2026-10-transports-internet-mesh-bridge.md) §2.1, §3.1-§3.3, §3.5-§3.7, §5 (row P3), §6.4-§6.5, §7.4, §8 (Q1, Q6-Q9, Q11, Q12) |
| **User docs** | `INSTALL_Linux.md`, `INSTALL_macOS.md`, `INSTALL_Windows.md`, section "libp2p: relay and hole punching" |

## 1. Why a waiver is needed

Umbrella §9.1 ([`RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md`](../protocol/RAVEN_UNIFIED_SERVERLESS_ARCHITECTURE_V2.md))
holds every relay and DCUtR flag until all of its holds pass, and its recorded
owner exception covers LAN direct only. The LAN waiver lists relay and DCUtR as
not covered (its §2). [`RAVEN_NAT_CONNECTIVITY_V1.md`](../protocol/RAVEN_NAT_CONNECTIVITY_V1.md)
§6 adds its own production hold: ATSAM endpoint/session integration on Rust
**and iOS**, signed-ACK recovery, abuse testing across relay and AutoNAT
failures, explicit relay policy, mobile lifecycle handling and interop soak
tests.

P3 adds to `raven-node`: a supervised libp2p host in `raven-node service`
(opt-in `--p2p-listen`, TCP and QUIC on 7423), the Raven link protocol
`/raven/link/1.0.0`, reservations on up to two relays, DCUtR, an AutoNAT v2
client, the relay role (`raven-node relay`, `raven-node service --relay`), an
opt-in UPnP / NAT-PMP mapping, `raven-card/2` cards, `raven send --carrier p2p`
and `raven relay allow|deny|status|card`. It is the first public-facing libp2p
surface in Raven (Q1), and for contacts who are both behind NAT it is the only
confidential carrier, so also their only pairing path (design F6, §4.8).
Turning it on for users is a scope extension of a waived slice and needs this
record.

## 2. Scope (exactly what is covered)

Covered, and only in this combination:

- **carrier:** the libp2p carrier of `raven-node`: libp2p TCP (Noise + Yamux)
  or QUIC-v1 connections, direct or through a Circuit Relay v2 circuit, with
  the DCUtR upgrade. Inside each connection one libp2p stream of protocol
  `/raven/link/1.0.0` runs Raven Noise XX with prologue `raven/p2p-link/v1`,
  the channel-bound RIH1 identity bind (same layout and verification as
  Internet direct, Transport Interface §3) and the RLB1 offer, then the same
  dispatcher as LAN and Internet direct;
- **link classes** (Carrier Conformance §3.2): `ENDPOINT_AUTHENTICATED` for a
  direct or DCUtR-upgraded connection, `OPAQUE_CIRCUIT` through a relay. A
  DCUtR upgrade runs a new stream and a new Raven handshake on the direct
  connection, and pending objects are retried byte-identically (Carrier
  Conformance §7.4);
- **objects:** as in the LAN waiver: PairInit V1 / PairResponse (accepted only
  from local contacts), `ATSAM/indexed-session/v1` RVNA1 `0x03` messages and
  sealed ACKs. The Raven link ends at the contact, relayed or not, so p2p is a
  confidential carrier in the sense of PairInit §7; PairInit is never placed in
  a relay-readable body;
- **peers:** verified (pinned) contacts only, in both directions. The dialer
  requires the responder's hello to name the pinned key. The responder answers
  only an initiator whose hello names a local, unblocked, pinned contact, and
  closes the stream for anyone else at the same point and with the same timing
  as for a stranger (stranger timing parity). The libp2p PeerId is never
  trusted for identity (Carrier Conformance §11.4 item 2, §11.5 item 7);
- **addresses:** a PeerId and up to two relay multiaddrs (each ending in
  `/p2p/<relay PeerId>`) from the contact record or a `raven-card/2` (`p2p=`,
  `via=`), and relays the user names (`--p2p-relay`, `RAVEN_P2P_RELAYS`,
  `p2p_relays`, at most 2). None is compiled in, none is discovered through a
  DHT or rendezvous. The listener is off unless the user opts in;
- **reachability helpers:** AutoNAT v2 client (a hint only, never trust),
  Identify `/raven/identify/1.0.0`, Ping; UPnP / NAT-PMP only after the user
  says yes (owner decision Q8, "ask once at setup"; unset behaves as off);
- **relay role:** a Circuit Relay v2 server in `raven-node relay --data-dir
  <dir>` (no Raven identity, no keystore; optional AutoNAT v2 server with
  `--autonat-server`) and in `raven-node service --relay` (shares the service's
  host, so its relay PeerId is the user's own PeerId). The allow-list
  (`relay_allow.json`) is on by default. `--open` (dedicated relay) and
  `--relay-open` (service) serve anyone, with stricter limits and a printed
  notice. **Owner choice at signature:** keep open relays in scope, or exclude
  them, in which case release builds must refuse both flags.

Not covered (all remain held): Kademlia, any DHT or public peer record
(design F5), the libp2p rendezvous protocol, route hints inside links (RLB2 /
`RRH1`, design §3.1 item 2), the offline mailbox (`--mailbox`, P4), mesh and
bridge custody and `RHW1` (P2b), PairInit over any non-confidential carrier and
the asynchronous PairInit carrier (Q3), the separate
`raven-swarm-connectivity-experimental` binary and its flag, Swift / iOS, a
Windows SCM service for the relay (Q9), an aggregate relay bandwidth cap (the
`--max-mbps` idea of design §3.5 is not implemented), Object Sync over p2p, the
Hybrid Ratchet v2 / Full Braid lab, and any Session V2 claim. Raw Internet
direct on TCP 7422 is covered only by its own record.

## 3. Holds for this scope

### 3.1 Umbrella §9.1

| Hold | Status at signature (to fill) | Waived? |
|---|---|---|
| 1. Automated gates | Design §6.4 scenarios: C6 forced relay (`OPAQUE_CIRCUIT`, PairInit through the relay; A and B reach the relay through a recording TCP proxy, and everything it relayed holds no `RVPI1`, `RVPR1`, `RLB1` or `RIH1` magic, no message text and no Raven identity key or address) on ubuntu, macOS and Windows; C7 DCUtR in the netns NAT simulation (cone: upgrade, then the next message logs `link via a direct connection`; symmetric: stays on the relay; ubuntu only, advisory job `nat-sim-linux` in `raven-serverless-lab.yml` until it has run green); C10 relay abuse (handshake, reservation and junk floods; contacts keep their slots) on ubuntu and macOS; C3 contact gating over p2p; C1 / C2 unchanged | Not waived |
| 2. All companions APPROVED | Not all approved. Carrier Conformance V1 is not APPROVED, and the link uses the RIH1 bind, which its §18 calls a legacy adapter (§4 item 10) | **Waived for this slice** |
| 3. Independent security review | Not done. The design recommends a focused external review of the public libp2p surface (relay server, AutoNAT server, Identify, the `/raven/link/1.0.0` responder, UPnP) before this flag flips (Q1). **Owner decision at signature:** commission that review, or waive it here with the reason written down | **Waived only if the owner records that decision** |
| 4. Physical rows / failure matrix | Umbrella §10.2 stage 7 (its DCUtR part) as row R7b, stage 8 as row R8, and the stage-12 slice for p2p (design §6.5): **must be recorded before signature**. Pending, owner-run | **Not waived** |
| 5. Indexed-session paths stay lab-gated | Live on this slice, as for LAN | **Waived for this slice**; never described as Session V2 |

### 3.2 NAT spec §6 production hold

| Requirement | Status at signature (to fill) | Waived? |
|---|---|---|
| ATSAM endpoint/session integration on Rust | The p2p link feeds the LAN / Internet dispatcher; C6 shows message 1, ACK, message 2 through a relay | Not waived |
| The same on iOS | Not done. Swift / iOS is out of scope (owner decision 2026-10-08, "terminals only") | **Waived**, recorded here so that it does not lapse silently (design Q12) |
| Signed-ACK recovery | The sealed ACK rides the same link; a lost ACK gives exact resend, Duplicate, ACK (C5); the P2a outbox worker returns ACKs later | Not waived |
| Abuse testing across relay and AutoNAT failures | C10, plus relay down, reservation lost and AutoNAT "unknown" cases | Not waived |
| Explicit relay policy | Allow-list by default and fail closed, the limits of §5, no compiled-in relay, `--open` explicit with a notice | Not waived |
| Mobile lifecycle handling | No mobile client in scope | **Waived** together with iOS parity |
| Interop soak tests | Setup and duration to be defined by the owner (for example the R7b setup left running for several days) | Not waived |

Carrier Conformance §19.2 adds for "Circuit Relay/DCUtR": explicit relay policy
(above), an opaque-stream proof (the C6 capture), new-context behaviour (a new
Raven handshake after DCUtR, C7) and physical rows 7-8 (R7b, R8).

## 4. Residual risks accepted

Everything in LAN waiver §4 applies unchanged: no forward secrecy and no
post-compromise security inside a 24 h session (profile §2.4), now for traffic
that a relay can record; no independent review or formal model; device key
equals identity key; no deniability; local-only revocation; Keychain prompts;
platform coverage. So do items 3 (metadata, the dialer's hello goes first), 4
(no FS / PCS for traffic that crosses the Internet), 5 (verified contacts only:
narrowed, not waived), 6 (Windows reachability) and 7 (clock skew) of the
Internet direct draft, now for p2p. In addition:

1. **Relay metadata** (design §3.5; the disclosure table Carrier Conformance
   §13 asks for):

   | Observer | Learns | Does not learn |
   |---|---|---|
   | A relay | Both PeerIds and IPs of every circuit, its timing, duration and byte count; who reserves; with `--autonat-server`, the probe targets | Raven IDs (unless it holds cards mapping PeerId to Raven ID), plaintext, PairInit, RLB1, route tags, message IDs: all inside libp2p Noise and, inside that, the Raven Noise link `raven/p2p-link/v1` |
   | A relay that also holds friends' cards | The friend graph at PeerId level | Message contents |
   | Anyone who connects to an open 7423 | The node's PeerId (libp2p identifies itself in its handshake), what Identify sends: its protocols, the agent `raven`, the address it observed for the peer, and only the node's **confirmed external** addresses (relay circuits, addresses AutoNAT v2 found reachable, a UPnP mapping; for a relay, the addresses of §5 "relay addresses"); that a node listens | The Raven ID: the Raven link answers pinned contacts only. Its listen addresses: Identify runs with `with_hide_listen_addrs(true)` and no listen-address push (checked against libp2p-identify 0.47: only the external set is sent), so LAN, link-local and loopback listen addresses are never published |
   | A holder of a `raven-card/2` | The mapping PeerId to Raven ID, and the relays named in `via=` (their IPs and PeerIds) | - |
   | Peers and relay during DCUtR | The address candidates exchanged for hole punching | - |
   | ISP / network observer | IPs, ports, timing, volume, that libp2p is in use | Contents |

   A relay can also refuse service, delay, drop or selectively degrade
   circuits (NAT spec §4); it cannot read or forge Raven traffic.
2. **Stable PeerId (Q6).** The libp2p key is derived from the Raven seed, so
   the PeerId is stable per profile. It links a user across relays and
   networks, and every card maps it to the Raven ID. Accepted for P3
   (reservations need a stable PeerId); per-epoch rotation announced through
   route hints may come later. A stable public IPv6 listen address in a card is
   a stable location identifier.
3. **PeerId disclosure of `service --relay`.** The relay PeerId is the user's
   own PeerId. It is disclosed to every friend who uses the relay, and every
   friend's card whose `via=` names the relay carries the user's PeerId and
   home IP to all of that friend's contacts. Anyone who also holds the user's
   card can then map that home IP to the user's Raven ID. The dedicated relay
   (`raven-node relay`, its own key) avoids this; the user docs and the
   installer output say so.
4. **Public listener exposure.** An opted-in node, and every relay, accepts
   libp2p connections from the whole Internet: anyone who connects learns the
   PeerId (item 1), and with the card the current IP of a Raven ID. Handshakes
   cost CPU and pre-auth slots; the limits of §5 and the existing per-IP caps
   bound it, but a distributed flood can still keep friends out. The per-/24
   (IPv4) and per-/48 (IPv6) pre-auth cap of design §3.4 is **not** what the
   libp2p listener applies: it caps pending (4) and established (8)
   connections per IPv4 address or IPv6 /64, and inbound connections in total
   leave 16 slots for the node's own dials (its relays and contacts), so a
   flood cannot lock a node out of its relay. Whether that is enough: **owner
   decision at signature**.
5. **Open relays (Q7).** With `--open` / `--relay-open` the operator relays
   encrypted traffic for strangers: bandwidth, abuse complaints and possible
   legal exposure land on the operator. Limits are stricter (32 reservations,
   512 KiB per circuit), but PeerIds are free, so per-peer limits are weak and
   the per-IP limits are the real bound. There is no aggregate bandwidth cap.
6. **UPnP / NAT-PMP (Q8).** Owner decision "ask once at setup": the first
   interactive `raven node p2p on` (or an interactive install that turns p2p
   on) asks once, Enter or EOF means no, the answer is saved; non-interactive
   runs never ask; unset behaves as off; `raven node upnp on|off`, `--upnp` /
   `--no-upnp` and `RAVEN_UPNP=1|0` change it. When on, it changes router state
   and exposes 7423 to the whole Internet. Mapping lifetime and clean-up after
   the node stops depend on the router **(verify)**; consumer UPnP stacks have a
   weak security record; behind CGNAT a mapping does not make the node
   reachable. Logs show only the mapped external port and success or failure.
7. **DCUtR limits.** Hole punching fails on symmetric NAT and CGNAT-to-CGNAT
   pairs (the published libp2p success rate of roughly 70 % is unverified,
   design §3.6). Such pairs stay relay-only, so the relay sees the metadata of
   their whole conversation. Each circuit is capped (5 min and 2 MiB by
   default), so longer exchanges open new circuits. Delivery then depends on a
   friend's relay staying up: a laptop, a Mac that sleeps or a Windows logon
   task is a poor relay (Q9).
8. **Two Internet stacks (Q11).** Raw RIH1 on TCP 7422 and libp2p on 7423
   double the audit surface. The design proposes to make libp2p direct the
   default after P3 and deprecate 7422 after one release. **Decision at P3 exit:
   to fill.**
9. **Third-party code on a public port.** rust-libp2p 0.56 (relay server and
   client, DCUtR, AutoNAT v2, Identify, QUIC, UPnP) has not been reviewed by
   us. Several API behaviours the design relies on are marked (verify), for
   example streams on limited (relayed) connections (design §3.2, Q17).
10. **Carrier Conformance gap.** The link binds identity with RIH1 (Transport
    Interface §3), which Carrier Conformance §18 lists as a legacy adapter. It
    has no `RVCM1` / `RVLN1` / `RVLB1` / `RVLC1` negotiation (§6) and no exporter
    (§7). Accepted by waiving hold 2; no Object Sync runs over p2p.
11. **AutoNAT server (optional, dedicated relay only).** It dials back
    addresses that clients ask it to probe, and so learns them. libp2p-autonat
    0.15 itself dials any address it is asked to (checked: no address filter);
    it only makes a client that asks for an address other than the one it
    connects from first send it 30-100 kB (the protocol's amplification check).
    `raven-node relay` adds a dial-back guard that refuses every outbound
    connection of the relay host to an address that is not globally routable
    (loopback, private, link-local, CGNAT `100.64/10`, ULA, documentation and
    benchmark ranges, multicast, broadcast, reserved), so it cannot be used to
    reach the relay's own LAN; a client can still have it send one connection
    attempt to any global address per request. Off unless `--autonat-server`
    is given.
12. **Port sharing on Windows.** libp2p-tcp binds with `SO_REUSEADDR` (and
    `SO_REUSEPORT` on Unix) and no `SO_EXCLUSIVEADDRUSE`. Before it binds,
    `raven-node` probe-binds every listen port with a plain socket and refuses
    a port another program already holds (one clear log line, retried with
    backoff; the dedicated relay exits). On Windows a program that starts
    *later* with `SO_REUSEADDR` can still bind the same port and take some of
    its connections; the Raven link still authenticates the contact, so this
    costs availability, not confidentiality.

## 5. Compensating controls in place

- **Allow-list by default** on both relay forms: only PeerIds in
  `relay_allow.json` may reserve. A missing allow-list means nobody, an
  unreadable or corrupt one means nobody (fail closed). `raven relay
  allow|deny|status|card` manage and show it.
- **Contact-gated, pinned-only responder** on `/raven/link/1.0.0`, with
  stranger timing parity: a stranger or an unpinned contact never receives the
  responder's hello, Raven identity or RLB1 offer. The dialer requires hello
  identity == pinned key, and RLB1 must bind exactly the hello's key.
- **Domain separation:** the prologue `raven/p2p-link/v1` keeps a LAN (no
  prologue) or raw Internet (`raven/internet/v1`) transcript from completing
  against a p2p endpoint, and the reverse.
- **PeerIds and relay data are hints only:** PeerIds, relay addresses and
  AutoNAT observations never feed identity or contact decisions (Carrier
  Conformance §11.5 item 7); AutoNAT is a reachability signal, not an
  authorization oracle (NAT spec §2.1).
- **Relay limits** (default / hard max; a dedicated relay tunes them with
  `--max-reservations`, `--max-circuits`, `--circuit-bytes`, `--circuit-secs`,
  `--reservation-secs`):

  | Knob | Default | Hard max |
  |---|---:|---:|
  | Reservations total | 128 | 1024 |
  | Reservations per peer | 2 (a friend's new connection after a restart reserves at once while the relay still holds the old one) | 2 |
  | Reservations per IP | 4 | 16 |
  | Reservation duration | 30 min | 2 h |
  | Circuits total | 64 | 256 |
  | Circuits per peer | 4 | 8 |
  | Circuit duration | 5 min | 30 min |
  | Circuit bytes | 2 MiB | 16 MiB |
  | Reservation rate per IP | 4/min | - |
  | Circuit rate per IP | 30/min | - |
  | Established connections total | 256 | 1024 |
  | Established inbound connections | total - 16 (16 kept for the host's own dials) | - |
  | Established connections per IP | 8 | 32 |
  | Sources tracked per rate table | 4096 (oldest evicted; pruned every tick) | - |
  | `--open` / `--relay-open` | 32 reservations, 512 KiB per circuit | - |

  Every per-IP knob (reservations, both rates, pending and established
  connections) keys on an IPv4 address or an IPv6 /64; libp2p's own per-IP
  rate limiters, which key on the exact address (a /128 for IPv6), are not
  used. The endpoint host (no relay role) allows 64 established connections,
  48 of them inbound, 16 pending, and 4 pending and 8 established per source.
  The connection
  limits are the first behaviours asked for every connection, so a denied
  connection never reaches DCUtR, AutoNAT or the relay.
- **Relay addresses:** a relay names (in reservations and to Identify) only its
  globally routable listen addresses, a specific address the operator listens
  on, and `--external` addresses; with an unspecified listen address
  (`0.0.0.0`, `::`) it never names its LAN, link-local or loopback addresses.
  With nothing it may name, it uses a loopback placeholder (libp2p rejects a
  reservation without addresses) and logs once that `--external` is needed.
  Expired listen addresses are withdrawn.
- **Busy ports and clean restarts:** every listen port is probe-bound before
  libp2p binds it (§4 item 12); a busy one is retried on its own (the rest of
  the host keeps running) and `raven status` says so. On SIGTERM / SIGINT
  (Ctrl-C on Windows) the service closes its libp2p connections and waits at
  most 1.5 s for them to close, so a relay frees the reservation at once and
  the restarted node reserves again within seconds.
- **One relay per folder:** `raven-node relay` holds a lock in its folder for
  its whole life (a second one exits), rewrites `relay_status.json` at least
  every 10 s, and `raven relay status` says `not running`, `running` or
  `running but its status is Ns old (stuck?)`.
- **Counts-only logs** (NAT spec §5): no PeerIds, addresses, message IDs,
  route tags or payloads. The log lines are `raven-node p2p: host up
  (listeners=<n>, relays=<n>)`, `reservation accepted (active=<k>)`,
  `reservation lost (active=<k>)`, `direct connection upgraded (dcutr)`, `link
  via a direct connection` / `link via the relay` (when the kind of a peer's
  link changes), `upnp mapped port <port>` / `upnp mapping failed (...)`,
  `listen port <port>/tcp is already in use by another program ...` / `listen
  port <port>/tcp is open now`, `a configured relay name does not resolve
  (yet); retrying`, and `P2P_HOLD: ...`. The node's own PeerId and listen
  addresses appear only in `raven status` (IPC) and, for a relay, in
  `relay_status.json` for `raven relay card`.
- **No compiled-in relay**, no DHT, no rendezvous: relays come only from cards
  and user configuration, at most two.
- **Relay names in cards and settings:** a `/dns*` relay address is kept as a
  name and resolved again before every reservation attempt, and the attempts
  rotate through every address it resolves to; a name that does not resolve
  is retried with backoff.
- **Opt-in exposure:** no libp2p listener unless `--p2p-listen`,
  `RAVEN_P2P_LISTEN` or `raven node p2p on` asks for one; a corrupt
  `node_policy.json` fails closed (no listener, no relays, no mapping); UPnP
  unset behaves as off; installers print firewall rules and never apply them
  (Windows: Private profile only).
- **The dedicated relay holds no Raven identity** and touches no keystore: only
  `relay_key.ed25519` (mode `0600`; on Windows a protected DACL that allows
  only the current user, as for every private Raven file and folder),
  `relay_allow.json`, `relay_status.json` and its lock file.
- **Visible state:** `raven status` shows `p2p` (`YES` only while the host is
  really up; otherwise the running service's own setting and where it came
  from, a flag, an environment variable or `node_policy.json`), `p2p_peer`,
  `p2p_listen`, `upnp` (setting and mapping result) and `p2p_relay` rows.
  `raven whoami --card` takes its `p2p=` / `via=` from the running service
  too, and refuses to print a card longer than the longest valid card.
- **The gate itself:** with the flag off, a release build never listens, dials,
  reserves or advertises libp2p and logs one `P2P_HOLD:` line.
- Same dispatcher, admission and session checks as LAN waiver §5.

## 6. Conditions

This waiver lapses, and the flag MUST be set back to `false`, if any of these
happens before it is renewed:

- a critical or high finding on the covered path, including the rust-libp2p
  components it uses, is confirmed and not fixed;
- the slice is extended beyond §2 (DHT, rendezvous, mailbox, mesh custody,
  route hints, a compiled-in or default relay, a Windows relay service, ...)
  without a new waiver or review;
- the relay allow-list stops being the default, or a log line starts carrying
  PeerIds, addresses or message IDs;
- `PRODUCTION_NAT_CONNECTIVITY_ENABLED` is set to `true` without its own
  record;
- C6, C7 or C10 is disabled or fails on any of its runners for more than one
  release;
- the LAN waiver it extends lapses or is withdrawn;
- the review-by date passes without renewal.

## 7. Exit conditions before signature

- CI green with C6, C7 (ubuntu, netns; advisory in the lab workflow until it
  has run green, required green for signature), C10 and C3 over p2p:
  **open**.
- R7b (two homes behind consumer NAT plus a relay) and R8 (relay only, one
  side on a phone hotspot or CGNAT) recorded under `node/proof_artifacts/`,
  plus the stage-12 p2p slice: **open**. The owner has no publicly reachable
  host (no VPS, port forward or global IPv6), so R7b needs a relay both homes
  can reach, for example a friend's home node made reachable with UPnP or a
  port forward. Loopback and netns results do not replace these rows
  ([`NAT_SOFTWARE_SIM.md`](NAT_SOFTWARE_SIM.md), "Honest claim").
- Owner decision on hold 3 (independent review or a written waiver, Q1):
  **open**.
- Owner decisions recorded: iOS parity and mobile lifecycle waived ("terminals
  only", 2026-10-08): **decided**; UPnP "ask once at setup" (Q8): **decided**;
  stable PeerId accepted (Q6): **to record**; allow-list default and whether
  open relays stay in scope (Q7, §2): **to record**; two Internet stacks (Q11):
  **open**; soak setup and duration: **open**.
- The disclosure text (§4 item 1, and the `service --relay` PeerId note)
  shipped with the feature in the user docs and command output (Carrier
  Conformance §19.1 item 9).
- The gate-flip change applied as one reviewed commit: the flag; the
  `p2p_gate.rs` tests that assert it stays off (`production_flag_stays_false`,
  `gate_does_not_open_generic_live_enabled`); the spec amendments of §8; and a
  regenerated `docs/PROTOCOL_FREEZE_HASHES_V1.md`.

## 8. Frozen specs that would need amending at the flip

Section numbers and titles checked against the files on 2026-10-08. This draft
edits none of them, and the freeze manifest is not regenerated here.

1. [`protocol/RAVEN_NAT_CONNECTIVITY_V1.md`](../protocol/RAVEN_NAT_CONNECTIVITY_V1.md)
   (its status line, "production disabled", "the isolated Rust experiment
   only", changes too):
   - **§1 Activation boundary.** Today: the `experimental-nat-connectivity`
     feature of `raven-swarm`, the separate
     `raven-swarm-connectivity-experimental` binary and
     `--enable-experimental-nat-connectivity`. Amend: `raven-node` now
     compiles these protocols behind the `p2p-host` Cargo feature and the
     runtime gate `P2P_PRODUCTION_ENABLED` (plus the user's opt-in listener);
     the experimental binary keeps its own rules. "No relay ... address is
     compiled in" stays; "accepted only from the operator for that invocation"
     becomes "from contact cards and the saved policy as well".
   - **§2 Behaviour and transport composition.** Add the Circuit Relay v2
     **server** role, the optional AutoNAT v2 server (today "client only
     (there is no AutoNAT server behaviour)"), Identify
     `/raven/identify/1.0.0` (today `/raven/connectivity/1.0.0`) and the
     payload protocol `/raven/link/1.0.0`. §2.1 (realtime-media boundary) is
     unchanged.
   - **§3 Fixed resource ceilings.** Add the relay-server ceilings of §5. They
     exceed the experiment's budget (established total 32, hard maximum 128;
     `MAX_ESTABLISHED_CONNECTIONS = 128` in `connectivity.rs`) against 256 /
     1024 for the relay, so they need their own table, and the section must
     say which budget the endpoint host uses. "At most eight explicit dial
     addresses and runs for at most one hour per invocation" does not fit a
     long-running service and needs a replacement rule.
   - **§4 Relay selection and address rules.** "One relay multiaddr" becomes
     up to two (`--p2p-relay`, `p2p_relays`, card `via=`), from cards or user
     configuration. The `/p2p-circuit` and terminal-peer rules stay.
   - **§5 Privacy and failure policy.** The logging rule stays (no PeerIds,
     relay / dial / listen addresses, message identifiers, routing tags or
     payloads in logs); add that `raven status` and `raven relay card` show the
     node's own PeerId and addresses on request and `relay_status.json` stores
     them. The sentence "No payload protocol is attached by this profile" sits
     in this section, not in §2: replace it with `/raven/link/1.0.0` carrying
     the Raven Noise link; the authenticate-before-durable-write rule stays.
   - **§6 Production hold.** Add a recorded owner exception naming this
     waiver, the waived iOS-parity and mobile-lifecycle requirements, and what
     stays held.
2. [`protocol/RAVEN_PAIR_INIT_V1.md`](../protocol/RAVEN_PAIR_INIT_V1.md) **§7
   Privacy/carrier and activation gaps.** Its recorded owner exception names
   LAN direct only and says "Every other carrier ... remains disabled". Add p2p
   (direct or circuit) as a confidential carrier under this waiver: PairInit
   rides inside the end-to-end Raven Noise link, never in a relay-readable
   body.
3. [`protocol/RAVEN_TRANSPORT_INTERFACE_V1.md`](../protocol/RAVEN_TRANSPORT_INTERFACE_V1.md)
   **§3 Internet framing (lab-gated).** Add the libp2p variant: stream
   `/raven/link/1.0.0`, prologue `raven/p2p-link/v1`, the same frame, RIH1,
   RLB1 and contact-gate rules, its gate and lab unlock. Two more places in
   the same file go stale: §5 "Discovery (DHT-ready)" (the "NAT / CGNAT /
   DCUtR ... BLOCKED_HARDWARE" note) and §6 "Target libp2p (ADR-0002)" (row
   "Circuit relay / DCUtR: Not complete").
4. [`protocol/RAVEN_CARRIER_CONFORMANCE_V1.md`](../protocol/RAVEN_CARRIER_CONFORMANCE_V1.md):
   - §3.2 "Link classes" and §7.4 "Circuit Relay and DCUtR" need no text
     change; the flip commit records how the carrier maps onto them (§2
     above).
   - §11.4 "Internet direct profile" and §11.5 "Circuit Relay and DCUtR
     profile" are requirement lists to check item by item; §11.4 item 2 is met
     by RIH1, not by the §6 negotiation (§4 item 10). §11.1 "Summary matrix"
     rows stay as they are.
   - The audit rows are in **§18 "Migration and current implementation audit"**,
     not in §11.4-§11.5: "NAT connectivity experiment" (today "currently has
     no endpoint payload/conformance binding") and "`RAVEN_TRANSPORT_INTERFACE_V1`
     `RIH1` and raw framing" (now also used inside libp2p). The per-profile
     blockers of the §19.2 row "Circuit Relay/DCUtR" are answered in §3.2 of
     this record.
5. Also needed, as in the Internet direct record: the umbrella's §9.1
   "Recorded owner exception (2026-10-07)" (it names relay and DCUtR as still
   held) and [`ATSAM_INDEXED_SESSION_PROFILE_V1.md`](../protocol/ATSAM_INDEXED_SESSION_PROFILE_V1.md)
   §7 "Activation and vectors" ("every other carrier, relay, mailbox, and store
   path for this profile stays disabled").
6. [`docs/PROTOCOL_FREEZE_HASHES_V1.md`](PROTOCOL_FREEZE_HASHES_V1.md):
   regenerate with `scripts/freeze_protocol_hashes.sh` in the same commit (CI
   runs it with `--check`); version new identifiers in
   `protocol/PROTOCOL_VERSIONS.md` if the amended specs register them there.
