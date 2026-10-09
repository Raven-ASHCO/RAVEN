//! `raven-node relay` (transports design 2026-10 §3.5): a dedicated Circuit
//! Relay v2 relay for friends, e.g. on an always-on box at home.
//!
//! It holds **no Raven identity** and touches no keystore: its only key is
//! the libp2p key `relay_key.ed25519` (32-byte Ed25519 seed, owner-only), and
//! it refuses a folder that holds a Raven profile. It runs the relay server,
//! an optional AutoNAT v2 server, Identify and Ping with the limits of
//! [`RelayLimits`]; no Raven link protocol, no Kademlia, no mailbox.
//!
//! Only the PeerIds in `relay_allow.json` may reserve (on by default; `raven
//! relay allow|deny`), re-read every few seconds; a peer taken off the list
//! loses its reservation. No list admits nobody, an unreadable one admits
//! nobody (fail closed). `--open` serves anyone with the stricter limits.
//! Logs and `relay_status.json` carry counts only (NAT spec §5) besides the
//! relay's own PeerId and listen addresses in the status file, which `raven
//! relay card` turns into `via=` lines for friends. No relay address is
//! compiled in anywhere.
//!
//! What a relay learns: both PeerIds and IPs of every circuit, its timing,
//! duration and bytes, who reserves (and, with `--autonat-server`, the
//! addresses it is asked to probe). It never learns Raven IDs (unless it holds
//! cards that map PeerIds to them), plaintext, PairInit, RLB1, route tags or
//! message ids: they are inside libp2p Noise and, inside that, the Raven link.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use futures::StreamExt;
use raven_core::ipc::RelayCounts;
use raven_core::p2p_route::P2pListen;
use raven_core::relay_allow::{
    load_relay_allow, write_relay_status, RelayStatusFile, RELAY_ALLOW_FILE, RELAY_KEY_FILE,
    RELAY_LOCK_FILE, RELAY_STATUS_HEARTBEAT,
};
use raven_swarm::host::{
    build_relay_swarm, is_circuit, listen_port_label, probe_listen_addr, AllowPolicy, HostGate,
    ListenProbe, RelayAdvertiser, RelayBehaviourEvent, RelayGuard, RelayLimits,
};
use raven_swarm::libp2p::identity::Keypair;
use raven_swarm::libp2p::swarm::SwarmEvent;
use raven_swarm::libp2p::{relay, Multiaddr, PeerId};
use raven_swarm::liveness::close_if_dead;

/// How often the allow-list is re-read and the status file refreshed (it is
/// rewritten when something changed, and at least every
/// [`RELAY_STATUS_HEARTBEAT`] as a heartbeat for `raven relay status`).
const RELOAD: Duration = Duration::from_secs(2);
/// A counts line at most this often (only when the counts changed).
const COUNTS_LOG: Duration = Duration::from_secs(30);

/// Who may reserve, from `relay_allow.json` in `dir`: `--open` admits anyone;
/// no file admits nobody; an unusable file admits nobody (fail closed).
pub(crate) fn allow_policy(dir: &Path, open: bool) -> AllowPolicy {
    if open {
        return AllowPolicy::Open;
    }
    match load_relay_allow(dir) {
        Ok(None) => AllowPolicy::Peers(HashSet::new()),
        Ok(Some(list)) => {
            let mut peers = HashSet::new();
            for entry in &list.peers {
                match entry.peer_id.parse::<PeerId>() {
                    Ok(p) => {
                        peers.insert(p);
                    }
                    Err(_) => return AllowPolicy::Unreadable,
                }
            }
            AllowPolicy::Peers(peers)
        }
        Err(_) => AllowPolicy::Unreadable,
    }
}

/// Files whose presence means `dir` is a Raven profile, not a relay folder.
/// Only names are checked: nothing is opened, no keystore is asked.
const PROFILE_MARKERS: [&str; 4] = [
    raven_core::BACKEND_MARKER_NAME,
    raven_core::SEED_FILE_NAME,
    "contacts.json",
    raven_core::INDEXED_SESSION_METADATA_FILE,
];

fn refuse_profile_dir(dir: &Path) -> Result<(), String> {
    if PROFILE_MARKERS.iter().any(|m| dir.join(m).exists()) {
        return Err(format!(
            "{} holds a Raven profile: a relay needs a folder of its own (it holds no Raven \
             identity). Use `raven-node service --relay` to relay from this profile instead.",
            dir.display()
        ));
    }
    Ok(())
}

/// The relay's libp2p key: read `relay_key.ed25519`, or create it (32 random
/// bytes, owner-only, never overwritten).
pub(crate) fn load_or_create_relay_key(dir: &Path) -> Result<Keypair, String> {
    use rand::RngCore;
    let path = dir.join(RELAY_KEY_FILE);
    if !path.exists() {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        match raven_core::paths::create_new_private(&path, &seed) {
            Ok(()) => {}
            // Another start won the race: use its key.
            Err(_) if path.exists() => {}
            Err(e) => return Err(format!("{RELAY_KEY_FILE}: {e}")),
        }
        seed.fill(0);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta =
            std::fs::symlink_metadata(&path).map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))?;
        if !meta.is_file() {
            return Err(format!("{RELAY_KEY_FILE} is not a regular file"));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("{RELAY_KEY_FILE}: cannot restrict to owner-only: {e}"))?;
        }
    }
    let mut bytes = std::fs::read(&path).map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))?;
    if bytes.len() != 32 {
        bytes.fill(0);
        return Err(format!(
            "{RELAY_KEY_FILE} must hold exactly 32 bytes; move it aside to make a new relay \
             identity (friends must then update their via= addresses)"
        ));
    }
    // `ed25519_from_bytes` zeroizes its input.
    Keypair::ed25519_from_bytes(&mut bytes).map_err(|e| format!("{RELAY_KEY_FILE}: {e}"))
}

/// `raven-node relay` settings.
#[derive(Clone, Debug)]
pub(crate) struct RelayCmd {
    pub data_dir: PathBuf,
    pub listen: P2pListen,
    pub open: bool,
    pub autonat_server: bool,
    pub limits: RelayLimits,
    /// Public addresses to name in reservations besides the listeners.
    pub external: Vec<Multiaddr>,
}

fn counts(guard: &RelayGuard, open: bool, circuits: u32, refused: (u64, u64)) -> RelayCounts {
    let c = guard.counts();
    RelayCounts {
        open,
        allowed_peers: c.allowed_peers,
        allow_list_unreadable: c.unreadable,
        reservations: c.active_reservations,
        circuits,
        reservations_refused: refused.0,
        circuits_refused: refused.1,
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn policy_line(policy: &AllowPolicy) -> String {
    match policy {
        AllowPolicy::Open => "open: anyone may reserve (stricter limits)".into(),
        AllowPolicy::Peers(p) if p.is_empty() => format!(
            "allow-list empty: nobody may reserve yet (add friends with `raven --data-dir <this \
             folder> relay allow`; {RELAY_ALLOW_FILE})"
        ),
        AllowPolicy::Peers(p) => format!("allow-list: {} peer(s)", p.len()),
        AllowPolicy::Unreadable => {
            format!("{RELAY_ALLOW_FILE} is unreadable: nobody may reserve until it is fixed")
        }
    }
}

/// Run the relay until the process is stopped.
pub(crate) async fn run_relay(cmd: RelayCmd) -> Result<(), String> {
    let gate = HostGate::open(raven_core::p2p_live_enabled())
        .map_err(|_| raven_core::P2P_HOLD.to_string())?;
    cmd.limits.validate().map_err(|e| e.to_string())?;
    raven_core::paths::ensure_private_dir(&cmd.data_dir)?;
    refuse_profile_dir(&cmd.data_dir)?;
    // One relay per folder, for its whole life (`raven relay status` probes
    // this lock to tell a stopped relay from a running one).
    let _instance = raven_core::paths::DataDirLock::acquire_within(
        &cmd.data_dir,
        RELAY_LOCK_FILE,
        Duration::from_secs(2),
    )
    .map_err(|_| {
        format!(
            "another raven-node relay already runs in {} (one relay per folder)",
            cmd.data_dir.display()
        )
    })?;
    let key = load_or_create_relay_key(&cmd.data_dir)?;
    let mut policy = allow_policy(&cmd.data_dir, cmd.open);
    let guard = RelayGuard::new(policy.clone(), &cmd.limits);
    let mut swarm = build_relay_swarm(&gate, key, cmd.limits, &guard, cmd.autonat_server)
        .map_err(|e| format!("relay: {e}"))?;
    let peer_id = *swarm.local_peer_id();
    let addrs = cmd
        .listen
        .multiaddrs()
        .iter()
        .map(|t| {
            t.parse::<Multiaddr>()
                .map_err(|e| format!("relay listen: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if addrs.is_empty() {
        return Err("relay --listen needs a port or IP:PORT (not \"relay\")".into());
    }
    // Probe every address before opening any: libp2p-tcp would share a port
    // another program holds (SO_REUSEADDR / SO_REUSEPORT) and silently lose
    // connections to it.
    let mut usable = Vec::new();
    for addr in addrs {
        match probe_listen_addr(&addr) {
            Ok(()) => usable.push(addr),
            Err(ListenProbe::Busy) => {
                return Err(format!(
                    "relay listen: port {} is already in use by another program (another \
                     relay or raven-node?); stop it or pick another --listen port",
                    listen_port_label(&addr)
                ))
            }
            Err(ListenProbe::Unavailable) => eprintln!(
                "raven-node relay: listen port {} cannot be opened on this host (no such \
                 address family or interface); skipped",
                listen_port_label(&addr)
            ),
        }
    }
    let mut listeners = 0usize;
    for addr in usable {
        let label = listen_port_label(&addr);
        match swarm.listen_on(addr) {
            Ok(_) => listeners += 1,
            Err(_) => eprintln!("relay failed: listen port {label} could not be opened"),
        }
    }
    if listeners == 0 {
        return Err("relay listen: no listener could be opened".into());
    }
    let listen_is_specific = matches!(cmd.listen, P2pListen::One(a) if !a.ip().is_unspecified());
    let mut advertiser = RelayAdvertiser::new(&mut swarm, listen_is_specific, &cmd.external);
    eprintln!(
        "raven-node relay: up (listeners={listeners}; {})",
        policy_line(&policy)
    );
    if cmd.open {
        eprintln!(
            "raven-node relay: OPEN relay: anyone may reserve and relay through this host; they \
             all learn its PeerId and address (stricter limits apply)"
        );
    }
    let mut listen_addrs: Vec<Multiaddr> = Vec::new();
    let (mut circuits, mut res_refused, mut circ_refused) = (0u32, 0u64, 0u64);
    let mut published: Option<RelayStatusFile> = None;
    let mut last_write = tokio::time::Instant::now();
    let mut ticks = 0u32;
    let mut logged: Option<RelayCounts> = None;
    let mut last_log = tokio::time::Instant::now() - COUNTS_LOG;
    let mut tick = tokio::time::interval(RELOAD);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    if !is_circuit(&address) {
                        // A reservation must name at least one address, but
                        // never a LAN / loopback one nobody chose.
                        advertiser.on_new_listen_addr(&mut swarm, &address);
                        listen_addrs.push(address);
                    }
                }
                SwarmEvent::ExpiredListenAddr { address, .. } => {
                    advertiser.on_expired_listen_addr(&mut swarm, &address);
                    listen_addrs.retain(|a| *a != address);
                }
                SwarmEvent::ListenerError { .. } => {
                    eprintln!("relay failed: a listener reported an error");
                }
                SwarmEvent::Behaviour(RelayBehaviourEvent::Relay(event)) => {
                    guard.on_relay_event(&event);
                    match event {
                        relay::Event::CircuitReqAccepted { .. } => circuits += 1,
                        relay::Event::CircuitClosed { .. } => circuits = circuits.saturating_sub(1),
                        relay::Event::CircuitReqDenied { .. } => circ_refused += 1,
                        relay::Event::ReservationReqDenied { .. } => res_refused += 1,
                        _ => {}
                    }
                }
                SwarmEvent::Behaviour(RelayBehaviourEvent::Ping(event)) => {
                    close_if_dead(&mut swarm, &event);
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => {
                    guard.on_peer_disconnected(&peer_id);
                }
                _ => {}
            },
            _ = tick.tick() => {
                ticks = ticks.saturating_add(1);
                if ticks == 2 && advertiser.placeholder_only() {
                    eprintln!(
                        "raven-node relay: no public address known (only private / loopback \
                         listen addresses): reservations name a loopback placeholder. Pass \
                         --external /ip4/<public IP>/tcp/<port> (the address in `raven relay \
                         card --host`)"
                    );
                }
                guard.prune();
                let next = allow_policy(&cmd.data_dir, cmd.open);
                if next != policy {
                    eprintln!("raven-node relay: {}", policy_line(&next));
                    policy = next.clone();
                }
                for peer in guard.set_policy(next) {
                    let _ = swarm.disconnect_peer_id(peer);
                }
                let now = counts(&guard, cmd.open, circuits, (res_refused, circ_refused));
                if logged.as_ref() != Some(&now) && last_log.elapsed() >= COUNTS_LOG {
                    eprintln!(
                        "raven-node relay: reservations={} circuits={} refused_reservations={} \
                         refused_circuits={}",
                        now.reservations, now.circuits, now.reservations_refused,
                        now.circuits_refused
                    );
                    logged = Some(now.clone());
                    last_log = tokio::time::Instant::now();
                }
                let status = RelayStatusFile {
                    version: 1,
                    peer_id: peer_id.to_string(),
                    listen_addrs: listen_addrs.iter().map(|a| a.to_string()).collect(),
                    counts: now,
                    updated_at_ms: 0,
                    pid: std::process::id(),
                };
                // Rewritten on a change, and as a heartbeat.
                if published.as_ref() != Some(&status)
                    || last_write.elapsed() >= RELAY_STATUS_HEARTBEAT
                {
                    let stamped = RelayStatusFile {
                        updated_at_ms: now_ms(),
                        ..status.clone()
                    };
                    match write_relay_status(&cmd.data_dir, &stamped) {
                        Ok(()) => {
                            published = Some(status);
                            last_write = tokio::time::Instant::now();
                        }
                        Err(e) => eprintln!("raven-node relay: status file: {e}"),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> String {
        raven_core::p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[seed; 32]))
    }

    #[test]
    fn allow_policy_is_on_by_default_and_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            allow_policy(dir.path(), false),
            AllowPolicy::Peers(HashSet::new()),
            "no list: nobody"
        );
        assert_eq!(allow_policy(dir.path(), true), AllowPolicy::Open);
        raven_core::relay_allow::relay_allow(dir.path(), &peer(1), "bob").unwrap();
        match allow_policy(dir.path(), false) {
            AllowPolicy::Peers(p) => {
                assert_eq!(p.len(), 1);
                assert!(p.contains(&peer(1).parse().unwrap()));
            }
            other => panic!("{other:?}"),
        }
        std::fs::write(dir.path().join(RELAY_ALLOW_FILE), b"{broken").unwrap();
        assert_eq!(allow_policy(dir.path(), false), AllowPolicy::Unreadable);
        // `--open` does not depend on the file at all.
        assert_eq!(allow_policy(dir.path(), true), AllowPolicy::Open);
    }

    #[test]
    fn the_relay_key_is_created_once_owner_only_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let first = load_or_create_relay_key(dir.path()).unwrap();
        let again = load_or_create_relay_key(dir.path()).unwrap();
        assert_eq!(first.public().to_peer_id(), again.public().to_peer_id());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = dir.path().join(RELAY_KEY_FILE);
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            load_or_create_relay_key(dir.path()).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "tightened again");
        }
        std::fs::write(dir.path().join(RELAY_KEY_FILE), [1u8; 31]).unwrap();
        assert!(load_or_create_relay_key(dir.path()).is_err());
    }

    #[test]
    fn a_profile_folder_is_never_used_as_a_relay_folder() {
        let dir = tempfile::tempdir().unwrap();
        refuse_profile_dir(dir.path()).unwrap();
        std::fs::write(dir.path().join("contacts.json"), b"[]").unwrap();
        let err = refuse_profile_dir(dir.path()).unwrap_err();
        assert!(err.contains("needs a folder of its own"), "{err}");
    }

    #[tokio::test]
    async fn the_relay_is_held_while_the_gate_is_closed() {
        if raven_core::p2p_live_enabled() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let err = run_relay(RelayCmd {
            data_dir: dir.path().to_path_buf(),
            listen: P2pListen::One("127.0.0.1:0".parse().unwrap()),
            open: false,
            autonat_server: false,
            limits: RelayLimits::friends(),
            external: Vec::new(),
        })
        .await
        .unwrap_err();
        assert_eq!(err, raven_core::P2P_HOLD);
        // Held before anything is created: no key, no status file.
        assert!(!dir.path().join(RELAY_KEY_FILE).exists());
    }
}
