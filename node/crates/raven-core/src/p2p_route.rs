//! Text rules for libp2p routes (P3, transports design 2026-10 §3.1-§3.2):
//! PeerIds and `via=` multiaddrs in contact cards, the contact book, the
//! outbox and node policy.
//!
//! No libp2p dependency: `raven` parses and prints cards with these functions
//! alone, and raven-node re-parses with the real `Multiaddr` before it dials.
//! The grammar is deliberately narrow (one host part, one transport, one
//! terminal `/p2p/<PeerId>`), so a card cannot smuggle a circuit, a second
//! peer or an unexpected protocol into a route.
//!
//! A PeerId names a libp2p key only, never a Raven identity: every p2p link
//! runs the Raven Noise link with the RIH1 identity bind inside the libp2p
//! stream, and the dialer accepts only the contact's pinned key. A card's
//! `p2p=` value is therefore a reachability hint, never trusted.

use crate::identity::Identity;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// libp2p TCP and UDP (QUIC) port of the endpoint service and the relay.
pub const DEFAULT_P2P_PORT: u16 = 7423;
/// Relays one node reserves on, and `via=` entries one card carries.
pub const MAX_VIA: usize = 2;
/// Longest multiaddr text accepted anywhere (real ones are far shorter).
pub const MAX_MULTIADDR_CHARS: usize = 300;
/// Domain of the libp2p key derived from a Raven seed: the PeerId is stable
/// per profile but is not the Raven address.
pub const LIBP2P_KEY_DOMAIN: &[u8] = b"raven/libp2p-peer-key/v1";

/// Multihash prefix of an Ed25519 PeerId: identity hash (0x00) of 36 bytes,
/// holding the protobuf `PublicKey { Type: Ed25519 (1), Data: 32 bytes }`.
const ED25519_PEER_ID_PREFIX: [u8; 6] = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
const PEER_ID_BYTES: usize = ED25519_PEER_ID_PREFIX.len() + 32;

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|b| **b == 0).count();
    // Base-58 digits, least significant first.
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 138 / 100 + 1);
    for &byte in &bytes[zeros..] {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            carry += (*d as u32) << 8;
            *d = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(digits.iter().rev().map(|d| B58[*d as usize] as char));
    out
}

fn base58_decode(text: &str) -> Option<Vec<u8>> {
    let zeros = text.bytes().take_while(|b| *b == b'1').count();
    // Base-256 digits, least significant first.
    let mut bytes: Vec<u8> = Vec::with_capacity(text.len());
    for c in text.bytes().skip(zeros) {
        let mut carry = B58.iter().position(|a| *a == c)? as u32;
        for b in bytes.iter_mut() {
            carry += (*b as u32) * 58;
            *b = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Some(out)
}

/// The libp2p Ed25519 secret key seed of this Raven profile:
/// `SHA-256(LIBP2P_KEY_DOMAIN || raven seed)`. Same derivation `raven-swarm`
/// has always used, so PeerIds do not change.
pub fn libp2p_ed25519_seed(id: &Identity) -> Zeroizing<[u8; 32]> {
    let seed = id.seed_zeroizing();
    let mut h = Sha256::new();
    h.update(LIBP2P_KEY_DOMAIN);
    h.update(seed.as_slice());
    Zeroizing::new(h.finalize().into())
}

/// Public half of [`libp2p_ed25519_seed`].
pub fn libp2p_ed25519_public(id: &Identity) -> [u8; 32] {
    let seed = libp2p_ed25519_seed(id);
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
}

/// The text form (`12D3KooW…`) of the PeerId of an Ed25519 libp2p key.
pub fn peer_id_from_ed25519_public(public: &[u8; 32]) -> String {
    let mut bytes = Vec::with_capacity(PEER_ID_BYTES);
    bytes.extend_from_slice(&ED25519_PEER_ID_PREFIX);
    bytes.extend_from_slice(public);
    base58_encode(&bytes)
}

/// This profile's own PeerId (what `raven whoami --card` prints as `p2p=`).
pub fn local_peer_id(id: &Identity) -> String {
    peer_id_from_ed25519_public(&libp2p_ed25519_public(id))
}

/// Strict PeerId parse: only the Ed25519 identity-multihash form Raven nodes
/// and relays use (`12D3KooW…`, 52 characters). Returns the libp2p public key.
pub fn parse_peer_id(text: &str) -> Result<[u8; 32], String> {
    let t = text.trim();
    if t.len() != 52 || !t.starts_with("12D3KooW") {
        return Err("a PeerId looks like 12D3KooW… (52 characters, an Ed25519 libp2p key)".into());
    }
    let bytes = base58_decode(t).ok_or("PeerId is not base58")?;
    if bytes.len() != PEER_ID_BYTES
        || bytes[..ED25519_PEER_ID_PREFIX.len()] != ED25519_PEER_ID_PREFIX
    {
        return Err("PeerId is not an Ed25519 libp2p key".into());
    }
    let mut public = [0u8; 32];
    public.copy_from_slice(&bytes[ED25519_PEER_ID_PREFIX.len()..]);
    // Canonical form only: re-encoding must give the same text.
    if peer_id_from_ed25519_public(&public) != t {
        return Err("PeerId is not in canonical form".into());
    }
    Ok(public)
}

/// [`parse_peer_id`], returning the canonical text.
pub fn normalize_peer_id(text: &str) -> Result<String, String> {
    parse_peer_id(text).map(|public| peer_id_from_ed25519_public(&public))
}

fn plausible_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with(['-', '.'])
        && !name.ends_with('-')
        && !name.contains("..")
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn parse_port(text: &str) -> Result<u16, String> {
    match text.parse::<u16>() {
        Ok(p) if p != 0 && text == p.to_string() => Ok(p),
        _ => Err(format!(
            "port \"{}\" must be 1-65535",
            crate::sanitize::sanitize_terminal_line(text)
        )),
    }
}

/// One parsed `via=` address: `/<ip4|ip6|dns|dns4|dns6>/<host>/<tcp/PORT |
/// udp/PORT/quic-v1>/p2p/<PeerId>`. A relay's address, or (when the PeerId is
/// the contact's own) a direct address of the contact. Never a circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViaAddr {
    /// Canonical text (normalised IP and PeerId).
    pub text: String,
    /// The terminal PeerId (the relay, or the contact itself).
    pub peer_id: String,
}

/// Strict parse of a `via=` / `--via` / `--p2p-relay` multiaddr.
pub fn parse_via(text: &str) -> Result<ViaAddr, String> {
    let t = text.trim();
    let shown = crate::sanitize::sanitize_terminal_line(t);
    if t.len() > MAX_MULTIADDR_CHARS || !t.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(format!(
            "address \"{shown}\" is not a multiaddr (at most {MAX_MULTIADDR_CHARS} plain characters)"
        ));
    }
    let usage = || {
        format!(
            "address \"{shown}\" must look like /ip4/203.0.113.7/tcp/{DEFAULT_P2P_PORT}/p2p/12D3KooW… \
             (or /ip6/…, /dns4/name/…, …/udp/{DEFAULT_P2P_PORT}/quic-v1/p2p/…)"
        )
    };
    let Some(rest) = t.strip_prefix('/') else {
        return Err(usage());
    };
    let parts: Vec<&str> = rest.split('/').collect();
    let mut out = String::new();
    let mut i = 0;
    // Host.
    match (parts.first(), parts.get(1)) {
        (Some(&"ip4"), Some(ip)) => {
            let ip: std::net::Ipv4Addr = ip.parse().map_err(|_| usage())?;
            if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
                return Err(format!("address \"{shown}\" names no single host"));
            }
            out.push_str(&format!("/ip4/{ip}"));
        }
        (Some(&"ip6"), Some(ip)) => {
            let ip: std::net::Ipv6Addr = ip.parse().map_err(|_| usage())?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err(format!("address \"{shown}\" names no single host"));
            }
            out.push_str(&format!("/ip6/{ip}"));
        }
        (Some(kind @ (&"dns" | &"dns4" | &"dns6")), Some(name)) if plausible_dns_name(name) => {
            out.push_str(&format!("/{kind}/{}", name.to_ascii_lowercase()));
        }
        _ => return Err(usage()),
    }
    i += 2;
    // Transport.
    match (parts.get(i), parts.get(i + 1), parts.get(i + 2)) {
        (Some(&"tcp"), Some(port), _) => {
            out.push_str(&format!("/tcp/{}", parse_port(port)?));
            i += 2;
        }
        (Some(&"udp"), Some(port), Some(&"quic-v1")) => {
            out.push_str(&format!("/udp/{}/quic-v1", parse_port(port)?));
            i += 3;
        }
        _ => return Err(usage()),
    }
    // Terminal peer, and nothing after it.
    match (parts.get(i), parts.get(i + 1), parts.len()) {
        (Some(&"p2p"), Some(peer), n) if n == i + 2 => {
            let peer_id = normalize_peer_id(peer).map_err(|e| format!("address \"{shown}\": {e}"))?;
            out.push_str(&format!("/p2p/{peer_id}"));
            Ok(ViaAddr { text: out, peer_id })
        }
        _ if parts.contains(&"p2p-circuit") => Err(format!(
            "address \"{shown}\" is a circuit: give the relay's own address (it ends in /p2p/<relay PeerId>)"
        )),
        _ => Err(usage()),
    }
}

/// The circuit address that reaches `target` through the relay `via`:
/// `<via>/p2p-circuit/p2p/<target>` (transports design §3.1).
pub fn circuit_addr(via: &ViaAddr, target_peer_id: &str) -> String {
    format!("{}/p2p-circuit/p2p/{target_peer_id}", via.text)
}

/// The outbox / IPC route for "reach this PeerId any way we know":
/// `/p2p/<PeerId>`. raven-node then dials the contact's direct `via=`
/// addresses first, then circuits through its relays.
pub fn peer_route(peer_id: &str) -> String {
    format!("/p2p/{peer_id}")
}

/// What a p2p dial string (`OutboxRoute::dial`, IPC `P2pDial.multiaddr`)
/// asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum P2pDialTarget {
    /// `/p2p/<PeerId>`: every way the contact book knows.
    Peer { peer_id: String },
    /// One direct address of the target (`<via>` naming the target itself).
    Direct { peer_id: String, addr: ViaAddr },
    /// One circuit `<relay via>/p2p-circuit/p2p/<target>`.
    Circuit { peer_id: String, relay: ViaAddr },
}

impl P2pDialTarget {
    pub fn peer_id(&self) -> &str {
        match self {
            Self::Peer { peer_id }
            | Self::Direct { peer_id, .. }
            | Self::Circuit { peer_id, .. } => peer_id,
        }
    }
}

/// Strict parse of a p2p dial string; every form ends in the target's PeerId.
pub fn parse_p2p_dial(text: &str) -> Result<P2pDialTarget, String> {
    let t = text.trim();
    if let Some(peer) = t.strip_prefix("/p2p/") {
        if !peer.contains('/') {
            return Ok(P2pDialTarget::Peer {
                peer_id: normalize_peer_id(peer)?,
            });
        }
    }
    if let Some((relay, target)) = t.split_once("/p2p-circuit/p2p/") {
        let relay = parse_via(relay)?;
        let peer_id = normalize_peer_id(target)?;
        if relay.peer_id == peer_id {
            return Err("a circuit through the target itself is not a circuit".into());
        }
        return Ok(P2pDialTarget::Circuit { peer_id, relay });
    }
    let addr = parse_via(t)?;
    Ok(P2pDialTarget::Direct {
        peer_id: addr.peer_id.clone(),
        addr,
    })
}

/// A contact's p2p routes as the contact book stores them: its PeerId and at
/// most [`MAX_VIA`] `via=` addresses. Junk is dropped, never dialled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContactP2p {
    pub peer_id: String,
    pub via: Vec<ViaAddr>,
}

impl ContactP2p {
    /// From the stored fields; `None` when there is no usable PeerId.
    pub fn from_fields(peer_id: &str, via: &[String]) -> Option<Self> {
        let peer_id = normalize_peer_id(peer_id).ok()?;
        let mut out = Self {
            peer_id,
            via: Vec::new(),
        };
        for v in via {
            if out.via.len() >= MAX_VIA {
                break;
            }
            if let Ok(v) = parse_via(v) {
                if !out.via.contains(&v) {
                    out.via.push(v);
                }
            }
        }
        Some(out)
    }

    /// The addresses to dial, in plan order (transports design §2.3): direct
    /// ones (a `via` that names the contact itself) first, then circuits
    /// through the relays.
    pub fn dial_addrs(&self) -> Vec<String> {
        let direct = self
            .via
            .iter()
            .filter(|v| v.peer_id == self.peer_id)
            .map(|v| v.text.clone());
        let circuits = self
            .via
            .iter()
            .filter(|v| v.peer_id != self.peer_id)
            .map(|v| circuit_addr(v, &self.peer_id));
        direct.chain(circuits).collect()
    }
}

/// Normalise a p2p listen setting (`--p2p-listen`, `RAVEN_P2P_LISTEN`,
/// node_policy.json `p2p_listen`). Empty or `off`: `Ok(None)` (no libp2p
/// host). `on` or a bare port: every interface, IPv4 and IPv6, on that port
/// ([`DEFAULT_P2P_PORT`] for `on`). `IP:PORT` / `[IPv6]:PORT`: that address
/// only (port 0 is kept for tests). `relay`: no listening port at all, reached
/// only through the relays this node reserves on (no hole punching).
pub fn normalize_p2p_listen(raw: &str) -> Result<Option<P2pListen>, String> {
    let s = raw.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("off") {
        return Ok(None);
    }
    if s.eq_ignore_ascii_case("on") {
        return Ok(Some(P2pListen::All(DEFAULT_P2P_PORT)));
    }
    if s.eq_ignore_ascii_case("relay") {
        return Ok(Some(P2pListen::RelayOnly));
    }
    if let Ok(port) = s.parse::<u16>() {
        if s == port.to_string() {
            return Ok(Some(P2pListen::All(port)));
        }
    }
    if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
        return Ok(Some(P2pListen::One(addr)));
    }
    Err(format!(
        "p2p listen must be a port (e.g. {DEFAULT_P2P_PORT}: every interface, IPv4 and IPv6), \
         IP:PORT (e.g. 127.0.0.1:{DEFAULT_P2P_PORT}), \"relay\" (no listening port: only \
         through your relays), \"on\" or \"off\"; got \"{}\"",
        crate::sanitize::sanitize_terminal_line(s)
    ))
}

/// Where the libp2p host listens (TCP and QUIC on each).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P2pListen {
    /// `0.0.0.0` and `::` on this port.
    All(u16),
    /// One address.
    One(std::net::SocketAddr),
    /// No listener: reachable only through relay reservations.
    RelayOnly,
}

impl P2pListen {
    /// The listen multiaddrs, TCP then QUIC per address.
    pub fn multiaddrs(&self) -> Vec<String> {
        let ips: Vec<std::net::IpAddr> = match self {
            Self::All(_) => vec![
                std::net::Ipv4Addr::UNSPECIFIED.into(),
                std::net::Ipv6Addr::UNSPECIFIED.into(),
            ],
            Self::One(addr) => vec![addr.ip()],
            Self::RelayOnly => Vec::new(),
        };
        let port = match self {
            Self::All(p) => *p,
            Self::One(addr) => addr.port(),
            Self::RelayOnly => 0,
        };
        let mut out = Vec::new();
        for ip in ips {
            let host = match ip {
                std::net::IpAddr::V4(v4) => format!("/ip4/{v4}"),
                std::net::IpAddr::V6(v6) => format!("/ip6/{v6}"),
            };
            out.push(format!("{host}/tcp/{port}"));
            out.push(format!("{host}/udp/{port}/quic-v1"));
        }
        out
    }

    /// The canonical text saved in node_policy.json.
    pub fn policy_text(&self) -> String {
        match self {
            Self::All(p) => p.to_string(),
            Self::One(addr) => addr.to_string(),
            Self::RelayOnly => "relay".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> String {
        local_peer_id(&Identity::from_seed(&[seed; 32]))
    }

    #[test]
    fn base58_round_trips_and_keeps_leading_zeros() {
        for bytes in [
            vec![],
            vec![0],
            vec![0, 0, 1],
            vec![0xff; 40],
            (0u8..=255).collect::<Vec<_>>(),
        ] {
            assert_eq!(base58_decode(&base58_encode(&bytes)).unwrap(), bytes);
        }
        assert_eq!(base58_encode(&[0, 0, 0x01]), "112");
        assert!(base58_decode("0OIl").is_none());
    }

    #[test]
    fn peer_ids_are_canonical_ed25519_only() {
        let id = Identity::from_seed(&[7; 32]);
        let p = local_peer_id(&id);
        assert!(p.starts_with("12D3KooW") && p.len() == 52, "{p}");
        assert_eq!(parse_peer_id(&p).unwrap(), libp2p_ed25519_public(&id));
        assert_eq!(normalize_peer_id(&format!("  {p} ")).unwrap(), p);
        // Domain separated from the Raven key, stable per seed.
        assert_ne!(libp2p_ed25519_public(&id), id.public_key_bytes());
        assert_eq!(p, peer(7));
        assert_ne!(p, peer(8));
        for bad in [
            "",
            "12D3KooW",
            "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N", // RSA/sha256 form
            &p[..51],
            &format!("{p}x"),
            &p.replace('W', "0"),
        ] {
            assert!(parse_peer_id(bad).is_err(), "{bad}");
        }
        // A one-character change that is still base58 is a different key or
        // not an Ed25519 PeerId at all; never the same one.
        let mut tweaked = p.clone().into_bytes();
        let last = tweaked.len() - 1;
        tweaked[last] = if tweaked[last] == b'z' { b'y' } else { b'z' };
        let tweaked = String::from_utf8(tweaked).unwrap();
        assert_ne!(parse_peer_id(&tweaked).ok(), parse_peer_id(&p).ok());
    }

    #[test]
    fn via_grammar_is_narrow() {
        let r = peer(1);
        let ok = |s: &str| parse_via(s).unwrap();
        let v = ok(&format!("/ip4/203.0.113.7/tcp/7423/p2p/{r}"));
        assert_eq!(v.peer_id, r);
        assert_eq!(v.text, format!("/ip4/203.0.113.7/tcp/7423/p2p/{r}"));
        assert_eq!(
            ok(&format!("/ip6/2001:DB8:0::1/udp/7423/quic-v1/p2p/{r}")).text,
            format!("/ip6/2001:db8::1/udp/7423/quic-v1/p2p/{r}")
        );
        assert_eq!(
            ok(&format!("/dns4/Relay.Example.com/tcp/7423/p2p/{r}")).text,
            format!("/dns4/relay.example.com/tcp/7423/p2p/{r}")
        );
        ok(&format!("/ip4/127.0.0.1/tcp/1/p2p/{r}"));
        for bad in [
            format!("ip4/203.0.113.7/tcp/7423/p2p/{r}"),
            "/ip4/203.0.113.7/tcp/7423".to_string(),
            format!("/ip4/203.0.113.7/tcp/0/p2p/{r}"),
            format!("/ip4/203.0.113.7/tcp/07423/p2p/{r}"),
            format!("/ip4/0.0.0.0/tcp/7423/p2p/{r}"),
            format!("/ip6/::/tcp/7423/p2p/{r}"),
            format!("/ip4/203.0.113.7/udp/7423/p2p/{r}"),
            format!("/ip4/203.0.113.7/tcp/7423/p2p/{r}/p2p-circuit"),
            format!(
                "/ip4/203.0.113.7/tcp/7423/p2p/{r}/p2p-circuit/p2p/{}",
                peer(2)
            ),
            format!("/ip4/203.0.113.7/tcp/7423/ws/p2p/{r}"),
            format!("/dns4/-bad/tcp/7423/p2p/{r}"),
            format!("/dns4/a..b/tcp/7423/p2p/{r}"),
            format!("/unix/x/tcp/7423/p2p/{r}"),
            "/ip4/203.0.113.7/tcp/7423/p2p/not-a-peer".to_string(),
            format!("/ip4/203.0.113.7/tcp/7423/p2p/{r} extra"),
            format!("/ip4/203.0.113.7/tcp/7423/p2p/{r}/"),
            "/".repeat(400),
        ] {
            assert!(parse_via(&bad).is_err(), "{bad}");
        }
        let circuit = parse_via(&format!(
            "/ip4/203.0.113.7/tcp/7423/p2p/{r}/p2p-circuit/p2p/{}",
            peer(2)
        ))
        .unwrap_err();
        assert!(circuit.contains("circuit"), "{circuit}");
    }

    #[test]
    fn dial_targets_and_plan_order() {
        let (relay, bob) = (peer(1), peer(2));
        let relay_via = parse_via(&format!("/ip4/198.51.100.1/tcp/7423/p2p/{relay}")).unwrap();
        let direct_via = parse_via(&format!("/ip4/203.0.113.9/tcp/7423/p2p/{bob}")).unwrap();
        assert_eq!(
            parse_p2p_dial(&peer_route(&bob)).unwrap(),
            P2pDialTarget::Peer {
                peer_id: bob.clone()
            }
        );
        let circuit = circuit_addr(&relay_via, &bob);
        assert_eq!(
            parse_p2p_dial(&circuit).unwrap(),
            P2pDialTarget::Circuit {
                peer_id: bob.clone(),
                relay: relay_via.clone()
            }
        );
        assert_eq!(
            parse_p2p_dial(&direct_via.text).unwrap().peer_id(),
            bob.as_str()
        );
        assert!(parse_p2p_dial(&circuit_addr(&relay_via, &relay)).is_err());
        assert!(parse_p2p_dial("/p2p/").is_err());
        assert!(parse_p2p_dial("203.0.113.9:7423").is_err());

        // Direct addresses first, then circuits; at most MAX_VIA, junk dropped.
        let c = ContactP2p::from_fields(
            &bob,
            &[
                relay_via.text.clone(),
                "junk".into(),
                direct_via.text.clone(),
                relay_via.text.clone(),
                format!("/ip4/198.51.100.2/tcp/7423/p2p/{}", peer(3)),
            ],
        )
        .unwrap();
        assert_eq!(c.via.len(), MAX_VIA);
        assert_eq!(c.dial_addrs(), vec![direct_via.text.clone(), circuit]);
        assert!(ContactP2p::from_fields("nope", &[]).is_none());
    }

    #[test]
    fn listen_setting_is_opt_in_and_covers_both_families() {
        assert_eq!(normalize_p2p_listen("").unwrap(), None);
        assert_eq!(normalize_p2p_listen(" off ").unwrap(), None);
        assert_eq!(
            normalize_p2p_listen("on").unwrap(),
            Some(P2pListen::All(DEFAULT_P2P_PORT))
        );
        let all = normalize_p2p_listen("7423").unwrap().unwrap();
        assert_eq!(
            all.multiaddrs(),
            vec![
                "/ip4/0.0.0.0/tcp/7423",
                "/ip4/0.0.0.0/udp/7423/quic-v1",
                "/ip6/::/tcp/7423",
                "/ip6/::/udp/7423/quic-v1"
            ]
        );
        assert_eq!(all.policy_text(), "7423");
        let one = normalize_p2p_listen("127.0.0.1:0").unwrap().unwrap();
        assert_eq!(
            one.multiaddrs(),
            vec!["/ip4/127.0.0.1/tcp/0", "/ip4/127.0.0.1/udp/0/quic-v1"]
        );
        assert_eq!(
            normalize_p2p_listen("[::1]:7423")
                .unwrap()
                .unwrap()
                .multiaddrs()[0],
            "/ip6/::1/tcp/7423"
        );
        let relay_only = normalize_p2p_listen("relay").unwrap().unwrap();
        assert!(relay_only.multiaddrs().is_empty());
        assert_eq!(relay_only.policy_text(), "relay");
        for bad in ["07423", "99999", "host:7423", "yes", "1.2.3.4"] {
            assert!(normalize_p2p_listen(bad).is_err(), "{bad}");
        }
    }
}
