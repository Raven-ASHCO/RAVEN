//! `raven node p2p|upnp` and `raven relay …` (transports design 2026-10 P3),
//! and the p2p rows of `raven status`.
//!
//! Everything here edits local files only (node_policy.json,
//! relay_allow.json) or reads what the running raven-node reports over IPC.
//! raven-node applies the p2p settings when it (re)starts; the relay
//! allow-list is re-read live. Nothing here opens a port, maps one on the
//! router or dials anybody.

use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use raven_core::ipc::{IpcRequest, IpcResponse, P2pStatusInfo, RelayCounts, IPC_VERSION};
use raven_core::node_policy::{save_policy, try_load_policy, NodePolicy};
use raven_core::p2p_route::{self, P2pListen, DEFAULT_P2P_PORT, MAX_VIA};
use raven_core::relay_allow::{self, RELAY_ALLOW_FILE};
use raven_core::sanitize::sanitize_terminal_line;

use super::{
    c, ipc_client, kv, load_contacts, no_contact_message, read_line_opt, resolve_contact_arg,
    service_restart_hint, stdin_is_tty, try_load_identity, Contact, C_DIM, C_GREEN, C_PURPLE,
    C_RESET,
};

/// The p2p settings of `raven node p2p on`.
#[derive(Debug, Clone, Default)]
pub(super) struct P2pOnArgs {
    pub listen: String,
    pub relay: Vec<String>,
    /// `--upnp` / `--no-upnp` (they skip the question).
    pub upnp: Option<bool>,
}

/// Inbound firewall rule for the libp2p port (TCP and UDP), as text to run
/// yourself: RAVEN never changes firewall settings.
pub(super) fn p2p_firewall_hint(port: u16) -> String {
    if cfg!(windows) {
        format!(
            "New-NetFirewallRule -DisplayName \"Raven node p2p\" -Direction Inbound -Program \
             <path to raven-node.exe> -Protocol TCP -LocalPort {port} -Profile Private, and the \
             same with -Protocol UDP (elevated PowerShell; never the Public profile)"
        )
    } else if cfg!(target_os = "macos") {
        "if the macOS firewall is on: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add \
         <path to raven-node> && sudo /usr/libexec/ApplicationFirewall/socketfilterfw \
         --unblockapp <path to raven-node>"
            .to_string()
    } else {
        format!(
            "e.g. sudo ufw allow {port}/tcp && sudo ufw allow {port}/udp (or your firewalld / \
             nftables / cloud rule)"
        )
    }
}

/// The one UPnP question (owner decision Q8, "ask once at setup").
pub(super) fn upnp_question(port: u16) -> String {
    format!(
        "Open TCP/UDP {port} on your router automatically (UPnP/NAT-PMP) so friends can reach \
         this node and it can relay for them? [y/N] "
    )
}

/// What `raven node p2p on` saves for UPnP, and whether it asked. A flag
/// (`--upnp` / `--no-upnp`) decides without asking; an answer saved before is
/// kept and never asked again; a run that is not on a terminal (scripts, CI,
/// installers) asks nothing and leaves it unset (behaves as off); otherwise
/// the question is asked exactly once: `y`/`yes` is on, Enter, EOF or anything
/// else is off. No port to open (`--listen relay`): nothing is asked either.
pub(super) fn upnp_decision(
    saved: Option<bool>,
    flag: Option<bool>,
    port: Option<u16>,
    tty: bool,
    ask: impl FnOnce(u16) -> Option<String>,
) -> (Option<bool>, bool) {
    if flag.is_some() {
        return (flag, false);
    }
    if saved.is_some() {
        return (saved, false);
    }
    let Some(port) = port else {
        return (None, false);
    };
    if !tty {
        return (None, false);
    }
    let yes = ask(port).is_some_and(|a| {
        let a = a.trim();
        a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes")
    });
    (Some(yes), true)
}

fn ask_on_terminal(port: u16) -> Option<String> {
    print!("{}", upnp_question(port));
    let _ = io::stdout().flush();
    read_line_opt()
}

/// The direct libp2p address in `contact`'s card (a `via=` naming the
/// contact's own PeerId): what `--relay @friend` uses.
fn contact_direct_address(contact: &Contact) -> Result<String, String> {
    let label = contact.primary_label();
    let peer = p2p_route::normalize_peer_id(&contact.p2p).map_err(|_| {
        format!(
            "{label} has no p2p PeerId saved: add their card again (`raven contact add --card …`) \
             or ask them for `raven relay card`"
        )
    })?;
    contact
        .p2p_via
        .iter()
        .filter_map(|v| p2p_route::parse_via(v).ok())
        .find(|v| v.peer_id == peer)
        .map(|v| v.text)
        .ok_or_else(|| {
            format!(
                "{label}'s card has no direct address of their own (a via= that ends in their own \
                 PeerId): ask them to run `raven relay card --host <their public address>` and \
                 give you that line"
            )
        })
}

/// `--relay` values: multiaddrs, or `@contact` / a contact name (their own
/// direct address).
fn resolve_relays(data_dir: &Path, relays: &[String]) -> Result<Vec<String>, String> {
    if relays.len() > MAX_VIA {
        return Err(format!("at most {MAX_VIA} relays (got {})", relays.len()));
    }
    let mut out = Vec::new();
    for r in relays {
        let text = if r.trim().starts_with('/') {
            p2p_route::parse_via(r)
                .map_err(|e| format!("--relay: {e}"))?
                .text
        } else {
            let contacts = load_contacts(data_dir)?;
            let hits = resolve_contact_arg(&contacts, r);
            match hits.as_slice() {
                [] => return Err(no_contact_message(&contacts, r)),
                [one] => contact_direct_address(one)?,
                many => {
                    return Err(format!(
                        "contact {} is ambiguous ({} matches): use the @tag",
                        sanitize_terminal_line(r),
                        many.len()
                    ))
                }
            }
        };
        if !out.contains(&text) {
            out.push(text);
        }
    }
    Ok(out)
}

/// The policy, or a refusal that names the problem: saving over an
/// unreadable file would silently turn the user's other flags off.
fn policy_for_edit(data_dir: &Path) -> Result<NodePolicy, String> {
    try_load_policy(data_dir).map_err(|e| {
        format!(
            "node_policy.json is unreadable ({}); fix or move it aside first (nothing changed)",
            sanitize_terminal_line(&e.to_string())
        )
    })
}

fn listen_port(listen: &P2pListen) -> Option<u16> {
    match listen {
        P2pListen::All(p) => Some(*p),
        P2pListen::One(a) => Some(a.port()),
        P2pListen::RelayOnly => None,
    }
}

/// `raven node p2p on …` (`Some`) / `off` (`None`).
pub(super) fn cmd_node_p2p(data_dir: &Path, on: Option<P2pOnArgs>) -> Result<(), String> {
    cmd_node_p2p_with(data_dir, on, stdin_is_tty(), ask_on_terminal)
}

pub(super) fn cmd_node_p2p_with(
    data_dir: &Path,
    on: Option<P2pOnArgs>,
    tty: bool,
    ask: impl FnOnce(u16) -> Option<String>,
) -> Result<(), String> {
    let mut policy = policy_for_edit(data_dir)?;
    let path = data_dir.join("node_policy.json");
    let Some(args) = on else {
        policy.p2p_listen.clear();
        save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
        println!(
            "{C_GREEN}ok{C_RESET} p2p=off saved in {} (relays and UPnP choice kept)",
            path.display()
        );
        println!(
            "{C_DIM}a running raven-node stops its libp2p host when it restarts: {}{C_RESET}",
            service_restart_hint()
        );
        return Ok(());
    };
    let listen = p2p_route::normalize_p2p_listen(&args.listen)
        .map_err(|e| format!("--listen: {e}"))?
        .ok_or("--listen needs a port, IP:PORT or relay (or use `raven node p2p off`)")?;
    let relays = if args.relay.is_empty() {
        policy.p2p_relays.clone()
    } else {
        resolve_relays(data_dir, &args.relay)?
    };
    let port = listen_port(&listen);
    let (upnp, asked) = upnp_decision(policy.upnp, args.upnp, port, tty, ask);
    policy.p2p_listen = listen.policy_text();
    policy.p2p_relays = relays;
    policy.upnp = upnp;
    save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
    println!(
        "{C_GREEN}ok{C_RESET} p2p listen={} relays={} upnp={} saved in {}",
        policy.p2p_listen,
        policy.p2p_relays.len(),
        upnp_policy_word(policy.upnp),
        path.display()
    );
    if asked {
        println!("{C_DIM}(asked once; change it any time with `raven node upnp on|off`){C_RESET}");
    }
    println!(
        "{C_DIM}raven-node starts its libp2p host when it (re)starts: {}{C_RESET}",
        service_restart_hint()
    );
    if let Some(port) = port {
        println!(
            "{C_DIM}only your verified contacts get a Raven link, but anyone who scans the port can \
             see that a libp2p node listens there. Allow inbound TCP and UDP {port}: {}{C_RESET}",
            p2p_firewall_hint(port)
        );
    }
    if policy.p2p_relays.is_empty() {
        println!(
            "{C_DIM}no relay: friends behind other NATs reach you only directly. Add one with \
             --relay MULTIADDR (a friend's `raven relay card` line) or --relay @friend.{C_RESET}"
        );
    }
    println!(
        "{C_DIM}your card now carries p2p=<your PeerId> and a via= per relay: `raven whoami \
         --card`{C_RESET}"
    );
    if !raven_core::p2p_live_enabled() {
        println!(
            "{C_PURPLE}note{C_RESET}: the p2p carrier is not enabled in this build \
             (P2P_PRODUCTION_ENABLED=false): raven-node keeps it off until it is."
        );
    }
    Ok(())
}

fn upnp_policy_word(upnp: Option<bool>) -> &'static str {
    match upnp {
        None => "unset",
        Some(true) => "on",
        Some(false) => "off",
    }
}

/// `raven node upnp on|off`: change the saved UPnP / NAT-PMP choice.
pub(super) fn cmd_node_upnp(data_dir: &Path, on: bool) -> Result<(), String> {
    let mut policy = policy_for_edit(data_dir)?;
    policy.upnp = Some(on);
    save_policy(data_dir, &policy).map_err(|e| format!("save policy failed: {e}"))?;
    println!(
        "{C_GREEN}ok{C_RESET} upnp={} saved in {}",
        upnp_policy_word(policy.upnp),
        data_dir.join("node_policy.json").display()
    );
    println!(
        "{C_DIM}raven-node applies it when it (re)starts: {}{C_RESET}",
        service_restart_hint()
    );
    if on {
        println!(
            "{C_DIM}when p2p is on, raven-node asks your router to forward its p2p port; it logs \
             only the mapped port and whether it worked. Your router may not support it.{C_RESET}"
        );
    }
    Ok(())
}

// ── raven status rows ────────────────────────────────────────────────────────

/// The running service's libp2p host, while it is up.
fn p2p_info(status: &Result<IpcResponse, String>) -> Option<&P2pStatusInfo> {
    service_p2p(status).filter(|i| i.up)
}

/// What the running service reports about p2p, up or not: its effective
/// setting and where it came from (a flag or env var beats node_policy.json).
/// `None`: no service answers, or an older one that does not say.
pub(super) fn service_p2p(status: &Result<IpcResponse, String>) -> Option<&P2pStatusInfo> {
    match status {
        Ok(IpcResponse::Status {
            p2p: Some(info), ..
        }) => Some(info),
        _ => None,
    }
}

/// The `p2p` row: YES only while the running service reports its host up.
/// While a service answers, its own effective setting is shown (an installer
/// flag included); otherwise what node_policy.json (`configured`) asks.
pub(super) fn p2p_reach_row(
    status: &Result<IpcResponse, String>,
    configured: &str,
    p2p_live: bool,
) -> String {
    if let Some(info) = p2p_info(status) {
        let retrying = if info.listen_retrying > 0 {
            format!(
                "; {} listen address(es) busy, retrying: see raven-node-service.log",
                info.listen_retrying
            )
        } else {
            String::new()
        };
        return format!(
            "YES \u{2014} the libp2p host is up (reachability: {}; reservations {}/{}{retrying})",
            sanitize_terminal_line(&info.nat),
            info.reservations.len(),
            info.relays_configured
        );
    }
    if let Some(info) = service_p2p(status) {
        let setting = sanitize_terminal_line(&info.listen_setting);
        let source = sanitize_terminal_line(&info.source);
        return if !info.config_error.is_empty() {
            format!(
                "NO \u{2014} the p2p settings could not be used ({}); see \
                 raven-node-service.log in your Raven folder",
                sanitize_terminal_line(&info.config_error)
            )
        } else if setting.is_empty() {
            if source.is_empty() || source == "node_policy.json" {
                format!("off (opt-in: raven node p2p on --listen {DEFAULT_P2P_PORT})")
            } else {
                format!("off ({source} turns it off for the running raven-node)")
            }
        } else if info.held {
            format!(
                "NO \u{2014} configured ({setting}, from {source}) but the p2p carrier is not \
                 enabled in this build (P2P_PRODUCTION_ENABLED=false)"
            )
        } else {
            format!(
                "NO \u{2014} configured ({setting}, from {source}) but the libp2p host is not up \
                 yet (starting, or failing: see raven-node-service.log in your Raven folder)"
            )
        };
    }
    let configured = sanitize_terminal_line(configured);
    match status {
        Ok(IpcResponse::Status { .. }) if configured.is_empty() => {
            format!("off (opt-in: raven node p2p on --listen {DEFAULT_P2P_PORT})")
        }
        Ok(IpcResponse::Status { .. }) if !p2p_live => format!(
            "NO \u{2014} configured ({configured}) but the p2p carrier is not enabled in this \
             build (P2P_PRODUCTION_ENABLED=false)"
        ),
        Ok(IpcResponse::Status { .. }) => format!(
            "NO \u{2014} configured ({configured}) but the libp2p host is not up (busy port, or \
             raven-node started before it was configured: restart it); see \
             raven-node-service.log in your Raven folder"
        ),
        Err(e) if ipc_client::error_means_not_running(e) && configured.is_empty() => {
            "off (raven-node is not running)".into()
        }
        Err(e) if ipc_client::error_means_not_running(e) => {
            format!("off \u{2014} configured ({configured}), raven-node is not running")
        }
        _ => "unknown \u{2014} raven-node does not answer; run `ash doctor`".into(),
    }
}

fn upnp_row(status: &Result<IpcResponse, String>, policy: Option<bool>) -> String {
    let live = p2p_info(status).map(|i| i.upnp.as_str());
    match (policy, live) {
        (None, _) => "unset (never asked: no router mapping; raven node upnp on|off)".into(),
        (Some(false), _) => "off".into(),
        (Some(true), Some(state)) if state.starts_with("mapped") => format!(
            "on \u{2014} the router forwards port {}",
            sanitize_terminal_line(state.trim_start_matches("mapped").trim())
        ),
        (Some(true), Some("failed")) => {
            "on \u{2014} the router mapping failed (no UPnP/NAT-PMP router, or it refused); \
             friends then reach you through a relay"
                .into()
        }
        (Some(true), Some(_)) => "on \u{2014} asking the router".into(),
        (Some(true), None) => "on (applied while the libp2p host runs)".into(),
    }
}

fn relay_row(counts: &RelayCounts) -> String {
    let who = if counts.open {
        "anyone (open)".to_string()
    } else if counts.allow_list_unreadable {
        format!("nobody: {RELAY_ALLOW_FILE} is unreadable")
    } else {
        format!("{} allow-listed peer(s)", counts.allowed_peers)
    };
    format!(
        "YES \u{2014} relaying for {who}; reservations={} circuits={} refused={} (its PeerId is \
         YOUR PeerId: everyone who uses it learns it)",
        counts.reservations,
        counts.circuits,
        counts.reservations_refused + counts.circuits_refused
    )
}

/// The `p2p_listen` row of a running host: its listen and circuit addresses.
fn p2p_listen_row(info: &P2pStatusInfo) -> String {
    let listen: Vec<String> = info
        .listen_addrs
        .iter()
        .map(|a| sanitize_terminal_line(a))
        .collect();
    if listen.is_empty() && info.listen_retrying > 0 {
        "(none open yet: the port is busy, retrying)".to_string()
    } else if listen.is_empty() {
        "(none: reachable through relays only)".to_string()
    } else {
        listen.join(", ")
    }
}

/// The p2p rows of `raven status` (after the `internet` row).
pub(super) fn print_status_rows(status: &Result<IpcResponse, String>, policy: &NodePolicy) {
    kv(
        "p2p",
        &p2p_reach_row(status, &policy.p2p_listen, raven_core::p2p_live_enabled()),
    );
    if let Some(info) = p2p_info(status) {
        kv("p2p_peer", &sanitize_terminal_line(&info.peer_id));
        kv("p2p_listen", &p2p_listen_row(info));
    }
    let service_on = service_p2p(status).is_some_and(|i| !i.listen_setting.is_empty());
    if !policy.p2p_listen.is_empty() || policy.upnp.is_some() || service_on {
        kv("upnp", &upnp_row(status, policy.upnp));
    }
    if let Some(counts) = p2p_info(status).and_then(|i| i.relay.as_ref()) {
        kv("p2p_relay", &relay_row(counts));
    }
}

// ── raven relay … ────────────────────────────────────────────────────────────

/// `raven relay allow|deny` target: a PeerId, or a contact (its p2p PeerId).
fn resolve_peer_id(data_dir: &Path, who: &str) -> Result<(String, String), String> {
    if let Ok(peer) = p2p_route::normalize_peer_id(who) {
        return Ok((peer, String::new()));
    }
    let contacts = load_contacts(data_dir)?;
    let hits = resolve_contact_arg(&contacts, who);
    let contact = match hits.as_slice() {
        [] => {
            return Err(format!(
                "{} is neither a PeerId (12D3KooW…) nor one of your contacts{}",
                sanitize_terminal_line(who),
                if contacts.is_empty() {
                    " (this folder has no contacts: pass the PeerId or --card)".to_string()
                } else {
                    format!(": {}", no_contact_message(&contacts, who))
                }
            ))
        }
        [one] => *one,
        many => {
            return Err(format!(
                "contact {} is ambiguous ({} matches): use the @tag",
                sanitize_terminal_line(who),
                many.len()
            ))
        }
    };
    let peer = p2p_route::normalize_peer_id(&contact.p2p).map_err(|_| {
        format!(
            "{} has no p2p PeerId saved: add their raven-card/2 (`raven contact add --card …`) \
             or pass the PeerId",
            contact.primary_label()
        )
    })?;
    Ok((peer, contact.primary_label()))
}

/// `raven relay allow`: who (a PeerId or a contact) or `--card`.
pub(super) fn cmd_relay_allow(
    data_dir: &Path,
    who: Option<&str>,
    card: Option<&str>,
    label: &str,
) -> Result<(), String> {
    let (peer, name) = match (who, card) {
        (Some(_), Some(_)) => return Err("give a contact / PeerId or --card, not both".into()),
        (None, None) => {
            return Err("who may reserve? give a contact (@tag), a PeerId or --card CARD".into())
        }
        (Some(w), None) => resolve_peer_id(data_dir, w)?,
        (None, Some(text)) => {
            let card = super::read_card_arg(text)?;
            let route = card.p2p.ok_or(
                "that card has no p2p= PeerId (a raven-card/2): ask for `raven whoami --card` \
                 after `raven node p2p on`",
            )?;
            (route.peer_id, String::new())
        }
    };
    let label = if label.trim().is_empty() {
        name
    } else {
        label.to_string()
    };
    let added = relay_allow::relay_allow(data_dir, &peer, &label)?;
    println!(
        "{C_GREEN}{}{C_RESET} {peer}{} may reserve on this relay ({})",
        if added { "allowed" } else { "already allowed" },
        if label.is_empty() {
            String::new()
        } else {
            format!(" ({})", sanitize_terminal_line(&label))
        },
        relay_allow::relay_allow_path(data_dir).display()
    );
    println!(
        "{C_DIM}a running relay picks this up within seconds. They learn this relay's PeerId and \
         address; it learns their PeerId, IP, timing and byte counts, never their messages.{C_RESET}"
    );
    Ok(())
}

pub(super) fn cmd_relay_deny(data_dir: &Path, who: &str) -> Result<(), String> {
    let (peer, _) = resolve_peer_id(data_dir, who)?;
    let removed = relay_allow::relay_deny(data_dir, &peer)?;
    if removed {
        println!(
            "{C_GREEN}denied{C_RESET} {peer}: a running relay ends its reservation within seconds"
        );
    } else {
        println!("{C_DIM}{peer} was not on the allow-list (nothing changed){C_RESET}");
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn status_age(updated_at_ms: u64) -> String {
    let secs = now_ms().saturating_sub(updated_at_ms) / 1000;
    format!("{secs}s ago")
}

/// Whether a dedicated relay runs: it holds its folder's lock for its whole
/// life, and rewrites its status at least every 10 s (a heartbeat).
pub(super) fn relay_state_line(running: bool, updated_at_ms: u64, now: u64) -> String {
    let age = now.saturating_sub(updated_at_ms) / 1000;
    match (
        running,
        now.saturating_sub(updated_at_ms) > relay_allow::RELAY_STATUS_STALE_MS,
    ) {
        (false, _) => format!(
            "not running (last status {age}s ago; start it: raven-node relay --data-dir <this \
             folder>)"
        ),
        (true, false) => "running".into(),
        (true, true) => {
            format!("running but its status is {age}s old (stuck?): check its log, or restart it")
        }
    }
}

fn counts_line(c: &RelayCounts) -> String {
    format!(
        "reservations={} circuits={} refused_reservations={} refused_circuits={}",
        c.reservations, c.circuits, c.reservations_refused, c.circuits_refused
    )
}

/// `raven relay status`: who may reserve, and what the relay does (counts).
pub(super) fn cmd_relay_status(data_dir: &Path) -> Result<(), String> {
    let col = c();
    println!();
    println!(
        "{}RELAY \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}",
        col.bold, col.reset
    );
    let dedicated = relay_allow::is_relay_dir(data_dir);
    kv(
        "folder",
        &format!(
            "{} ({})",
            data_dir.display(),
            if dedicated {
                "dedicated relay: raven-node relay"
            } else {
                "profile: raven-node service --relay"
            }
        ),
    );
    let allow = relay_allow::load_relay_allow(data_dir);
    match &allow {
        Ok(None) => kv(
            "allow_list",
            "none yet: nobody may reserve (raven relay allow …)",
        ),
        Ok(Some(list)) => {
            kv("allow_list", &format!("{} peer(s)", list.peers.len()));
            for e in &list.peers {
                kv(
                    "",
                    &format!(
                        "{}{}",
                        e.peer_id,
                        if e.label.is_empty() {
                            String::new()
                        } else {
                            format!("  ({})", sanitize_terminal_line(&e.label))
                        }
                    ),
                );
            }
        }
        Err(e) => kv(
            "allow_list",
            &format!(
                "UNREADABLE: nobody may reserve until it is fixed ({})",
                sanitize_terminal_line(e)
            ),
        ),
    }
    if dedicated {
        let running = relay_allow::relay_is_running(data_dir);
        match relay_allow::load_relay_status(data_dir)? {
            Some(st) => {
                kv(
                    "state",
                    &relay_state_line(running, st.updated_at_ms, now_ms()),
                );
                kv("peer_id", &sanitize_terminal_line(&st.peer_id));
                kv(
                    "listen",
                    &st.listen_addrs
                        .iter()
                        .map(|a| sanitize_terminal_line(a))
                        .collect::<Vec<_>>()
                        .join(", "),
                );
                kv(
                    "counts",
                    &format!(
                        "{} (updated {})",
                        counts_line(&st.counts),
                        status_age(st.updated_at_ms)
                    ),
                );
            }
            None => kv(
                "state",
                "the relay has not run here yet: raven-node relay --data-dir <this folder>",
            ),
        }
    } else {
        let daemon = ipc_client::ipc_request_timeout(
            data_dir,
            &IpcRequest::Status { v: IPC_VERSION },
            Duration::from_secs(2),
        );
        match p2p_info(&daemon).and_then(|i| i.relay.as_ref()) {
            Some(counts) => kv("state", &relay_row(counts)),
            None => kv(
                "state",
                "not relaying (start raven-node service with --relay, or RAVEN_P2P_RELAY=1)",
            ),
        }
    }
    Ok(())
}

/// The multiaddr host part for `--host`: an IPv4 / IPv6 literal or a DNS name.
fn host_part(host: &str) -> Result<String, String> {
    let h = host.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(v4) = h.parse::<std::net::Ipv4Addr>() {
        return Ok(format!("/ip4/{v4}"));
    }
    if let Ok(v6) = h.parse::<std::net::Ipv6Addr>() {
        return Ok(format!("/ip6/{v6}"));
    }
    Ok(format!("/dns/{}", h.to_ascii_lowercase()))
}

/// `raven relay card`: the `via=` line(s) friends put in their contact book
/// (or `raven node p2p on --relay …`) to use this relay.
pub(super) fn cmd_relay_card(
    data_dir: &Path,
    host: Option<&str>,
    port: u16,
    quic: bool,
) -> Result<(), String> {
    let (peer_id, listen) = if relay_allow::is_relay_dir(data_dir) {
        let st = relay_allow::load_relay_status(data_dir)?.ok_or(
            "start the relay once first (raven-node relay --data-dir <this folder>): its PeerId \
             is in relay_status.json",
        )?;
        (st.peer_id, st.listen_addrs)
    } else {
        let id = try_load_identity(data_dir)?
            .ok_or("no identity here: this is neither a relay folder nor a profile")?;
        let daemon = ipc_client::ipc_request_timeout(
            data_dir,
            &IpcRequest::Status { v: IPC_VERSION },
            Duration::from_secs(2),
        );
        let listen = p2p_info(&daemon)
            .map(|i| i.listen_addrs.clone())
            .unwrap_or_default();
        (p2p_route::local_peer_id(&id), listen)
    };
    let mut lines: Vec<String> = Vec::new();
    match host {
        Some(h) => {
            let base = host_part(h)?;
            lines.push(format!("{base}/tcp/{port}/p2p/{peer_id}"));
            if quic {
                lines.push(format!("{base}/udp/{port}/quic-v1/p2p/{peer_id}"));
            }
        }
        None => {
            for a in &listen {
                let a = a.trim();
                let tcp = a.contains("/tcp/") && !a.contains("/p2p-circuit");
                let q = quic && a.contains("/quic-v1") && !a.contains("/p2p-circuit");
                if (tcp || q)
                    && !a.starts_with("/ip4/0.0.0.0")
                    && !a.starts_with("/ip6/::/")
                    && !a.contains("/p2p/")
                {
                    lines.push(format!("{a}/p2p/{peer_id}"));
                }
            }
        }
    }
    let mut valid = Vec::new();
    for l in lines {
        if let Ok(v) = p2p_route::parse_via(&l) {
            if !valid.contains(&v.text) {
                valid.push(v.text);
            }
        }
    }
    if valid.is_empty() {
        return Err(format!(
            "no address to give out yet: pass the address friends reach this relay at, e.g. \
             `raven relay card --host 203.0.113.7` (your public IP, a DNS name, or a forwarded \
             port's address; port {port})"
        ));
    }
    for v in &valid {
        println!("via={v}");
    }
    eprintln!(
        "{C_DIM}Give a line to each friend you allowed (raven relay allow …); they use it as \
         `raven node p2p on --relay <the part after via=>`. A loopback or LAN address works only \
         for friends on this computer or network.{C_RESET}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    /// Owner decision Q8: asked once, only on a terminal; Enter or EOF is off;
    /// the flags skip the question; an answer saved before is never asked
    /// again; non-interactive runs stay unset.
    #[test]
    fn upnp_is_asked_once_only_on_a_terminal() {
        let never = |_: u16| -> Option<String> { panic!("must not ask") };
        // Flags decide without asking, on a terminal or not.
        assert_eq!(
            upnp_decision(None, Some(true), Some(7423), true, never),
            (Some(true), false)
        );
        assert_eq!(
            upnp_decision(None, Some(false), Some(7423), true, never),
            (Some(false), false)
        );
        assert_eq!(
            upnp_decision(Some(false), Some(true), Some(7423), false, never),
            (Some(true), false)
        );
        // Saved answers are kept: never asked again.
        assert_eq!(
            upnp_decision(Some(true), None, Some(7423), true, never),
            (Some(true), false)
        );
        assert_eq!(
            upnp_decision(Some(false), None, Some(7423), true, never),
            (Some(false), false)
        );
        // Not a terminal: no prompt, stays unset.
        assert_eq!(
            upnp_decision(None, None, Some(7423), false, never),
            (None, false)
        );
        // No port to open: nothing to ask.
        assert_eq!(upnp_decision(None, None, None, true, never), (None, false));
        // On a terminal: y / yes is on; Enter, EOF and anything else are off.
        for (answer, want) in [
            (Some("y"), true),
            (Some(" YES "), true),
            (Some(""), false),
            (None, false),
            (Some("n"), false),
            (Some("maybe"), false),
        ] {
            let mut asked_port = 0;
            let got = upnp_decision(None, None, Some(7999), true, |p| {
                asked_port = p;
                answer.map(String::from)
            });
            assert_eq!(got, (Some(want), true), "{answer:?}");
            assert_eq!(asked_port, 7999);
        }
        assert!(upnp_question(7423).starts_with("Open TCP/UDP 7423 on your router automatically"));
        assert!(upnp_question(7423).ends_with("[y/N] "));
    }

    #[test]
    fn node_p2p_on_asks_once_saves_the_answer_and_round_trips() {
        let dir = tmp();
        let asked = std::cell::Cell::new(0);
        let ask = |_: u16| {
            asked.set(asked.get() + 1);
            None // EOF
        };
        let on = || P2pOnArgs {
            listen: "7423".into(),
            ..P2pOnArgs::default()
        };
        cmd_node_p2p_with(dir.path(), Some(on()), true, ask).unwrap();
        assert_eq!(asked.get(), 1);
        let p = try_load_policy(dir.path()).unwrap();
        assert_eq!(p.p2p_listen, "7423");
        assert_eq!(p.upnp, Some(false), "EOF saves off");
        // Never asked again.
        cmd_node_p2p_with(dir.path(), Some(on()), true, |_| -> Option<String> {
            panic!("asked twice")
        })
        .unwrap();
        // `raven node upnp on` changes it at any time; off keeps it.
        cmd_node_upnp(dir.path(), true).unwrap();
        cmd_node_p2p_with(dir.path(), None, true, |_| -> Option<String> {
            panic!("no")
        })
        .unwrap();
        let p = try_load_policy(dir.path()).unwrap();
        assert!(p.p2p_listen.is_empty());
        assert_eq!(p.upnp, Some(true));
        // A non-interactive first run leaves it unset (no prompt at all).
        let fresh = tmp();
        cmd_node_p2p_with(fresh.path(), Some(on()), false, |_| -> Option<String> {
            panic!("no prompt off a terminal")
        })
        .unwrap();
        assert_eq!(try_load_policy(fresh.path()).unwrap().upnp, None);
        // --no-upnp / --upnp skip the question.
        let flagged = tmp();
        cmd_node_p2p_with(
            flagged.path(),
            Some(P2pOnArgs {
                upnp: Some(true),
                ..on()
            }),
            true,
            |_| -> Option<String> { panic!("the flag skips the question") },
        )
        .unwrap();
        assert_eq!(try_load_policy(flagged.path()).unwrap().upnp, Some(true));
    }

    #[test]
    fn node_p2p_on_validates_relays_and_refuses_an_unreadable_policy() {
        let dir = tmp();
        let relay = p2p_route::local_peer_id(&raven_core::Identity::from_seed(&[4; 32]));
        let good = format!("/ip4/198.51.100.7/tcp/7423/p2p/{relay}");
        cmd_node_p2p_with(
            dir.path(),
            Some(P2pOnArgs {
                listen: "relay".into(),
                relay: vec![good.clone()],
                upnp: None,
            }),
            true,
            |_| -> Option<String> { panic!("no port: nothing to ask") },
        )
        .unwrap();
        let p = try_load_policy(dir.path()).unwrap();
        assert_eq!(p.p2p_listen, "relay");
        assert_eq!(p.p2p_relays, vec![good.clone()]);
        assert_eq!(p.upnp, None);
        for bad in [
            vec!["/ip4/198.51.100.7/tcp/7423".to_string()],
            vec![good.clone(), good.clone(), good.clone()],
        ] {
            assert!(cmd_node_p2p_with(
                dir.path(),
                Some(P2pOnArgs {
                    listen: "7423".into(),
                    relay: bad,
                    upnp: Some(false),
                }),
                false,
                |_| None,
            )
            .is_err());
        }
        std::fs::write(dir.path().join("node_policy.json"), b"{broken").unwrap();
        let err = cmd_node_upnp(dir.path(), true).unwrap_err();
        assert!(err.contains("nothing changed"), "{err}");
        assert_eq!(
            std::fs::read(dir.path().join("node_policy.json")).unwrap(),
            b"{broken"
        );
    }

    fn status(p2p: Option<P2pStatusInfo>) -> Result<IpcResponse, String> {
        Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: true,
            store: true,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
            p2p,
        })
    }

    #[test]
    fn status_p2p_row_says_yes_only_while_the_host_is_up() {
        let up = P2pStatusInfo {
            up: true,
            nat: "private".into(),
            reservations: vec!["x".into()],
            relays_configured: 2,
            upnp: "mapped 7423".into(),
            ..P2pStatusInfo::default()
        };
        assert!(p2p_reach_row(&status(Some(up.clone())), "7423", true).starts_with("YES"));
        assert!(p2p_reach_row(&status(Some(up.clone())), "7423", true).contains("reservations 1/2"));
        let down = P2pStatusInfo {
            up: false,
            listen_setting: "7423".into(),
            source: "node_policy.json".into(),
            ..up.clone()
        };
        assert!(p2p_reach_row(&status(Some(down)), "7423", true).starts_with("NO"));
        assert!(p2p_reach_row(&status(None), "", true).starts_with("off"));
        assert!(
            p2p_reach_row(&status(None), "7423", false).contains("P2P_PRODUCTION_ENABLED=false")
        );
        assert!(p2p_reach_row(&status(None), "7423", true).contains("not up"));
        assert_eq!(
            upnp_row(&status(Some(up.clone())), Some(true)),
            "on \u{2014} the router forwards port 7423"
        );
        assert!(upnp_row(&status(None), None).starts_with("unset"));
        assert_eq!(upnp_row(&status(None), Some(false)), "off");
        let failed = P2pStatusInfo {
            upnp: "failed".into(),
            ..up
        };
        assert!(upnp_row(&status(Some(failed)), Some(true)).contains("failed"));
        let row = relay_row(&RelayCounts {
            allowed_peers: 2,
            reservations: 1,
            ..RelayCounts::default()
        });
        assert!(
            row.contains("2 allow-listed") && row.contains("YOUR PeerId"),
            "{row}"
        );
    }

    /// Review item 8: while a service answers, its own effective setting (an
    /// installer flag included) decides the row, not node_policy.json.
    #[test]
    fn status_p2p_row_follows_the_running_service_not_the_policy_file() {
        let service = |f: fn(&mut P2pStatusInfo)| {
            let mut info = P2pStatusInfo::default();
            f(&mut info);
            status(Some(info))
        };
        // A flag turned it on although node_policy.json says nothing.
        let held = service(|i| {
            i.listen_setting = "7423".into();
            i.source = "--p2p-listen".into();
            i.held = true;
        });
        let row = p2p_reach_row(&held, "", true);
        assert!(
            row.starts_with("NO")
                && row.contains("from --p2p-listen")
                && row.contains("P2P_PRODUCTION"),
            "{row}"
        );
        let starting = service(|i| {
            i.listen_setting = "relay".into();
            i.source = "RAVEN_P2P_LISTEN".into();
        });
        let row = p2p_reach_row(&starting, "", true);
        assert!(
            row.contains("(relay, from RAVEN_P2P_LISTEN)") && row.contains("not up"),
            "{row}"
        );
        // An env var turned it off although node_policy.json turns it on.
        let off = service(|i| i.source = "RAVEN_P2P_LISTEN".into());
        let row = p2p_reach_row(&off, "7423", true);
        assert_eq!(
            row,
            "off (RAVEN_P2P_LISTEN turns it off for the running raven-node)"
        );
        let plain_off = service(|i| i.source = "node_policy.json".into());
        assert!(p2p_reach_row(&plain_off, "", true).starts_with("off (opt-in"));
        let broken = service(|i| {
            i.listen_setting = "7423".into();
            i.config_error = "bad relay".into();
        });
        let row = p2p_reach_row(&broken, "7423", true);
        assert!(row.starts_with("NO") && row.contains("bad relay"), "{row}");
        // Up, but every listen port busy: said so in both rows.
        let busy = P2pStatusInfo {
            up: true,
            nat: "unknown".into(),
            listen_setting: "7423".into(),
            listen_retrying: 2,
            ..P2pStatusInfo::default()
        };
        let row = p2p_reach_row(&status(Some(busy.clone())), "7423", true);
        assert!(
            row.starts_with("YES") && row.contains("2 listen address(es) busy"),
            "{row}"
        );
        assert_eq!(
            p2p_listen_row(&busy),
            "(none open yet: the port is busy, retrying)"
        );
        let relayed = P2pStatusInfo {
            listen_retrying: 0,
            ..busy.clone()
        };
        assert_eq!(
            p2p_listen_row(&relayed),
            "(none: reachable through relays only)"
        );
        let open = P2pStatusInfo {
            listen_addrs: vec![
                "/ip4/127.0.0.1/tcp/7423".into(),
                "/ip4/127.0.0.1/udp/7423/quic-v1".into(),
            ],
            ..relayed
        };
        assert_eq!(
            p2p_listen_row(&open),
            "/ip4/127.0.0.1/tcp/7423, /ip4/127.0.0.1/udp/7423/quic-v1"
        );
    }

    /// Review item 13: a stopped relay is told apart by its lock, a stuck one
    /// by its heartbeat.
    #[test]
    fn relay_status_says_not_running_running_or_stuck() {
        let now = 1_000_000_000;
        assert!(relay_state_line(false, now - 5_000, now)
            .starts_with("not running (last status 5s ago"));
        assert_eq!(relay_state_line(true, now - 5_000, now), "running");
        let stuck = relay_state_line(true, now - relay_allow::RELAY_STATUS_STALE_MS - 1_000, now);
        assert!(
            stuck.starts_with("running but its status is 36s old"),
            "{stuck}"
        );
        // A relay that never wrote a status (0) and is not running.
        assert!(relay_state_line(false, 0, now).starts_with("not running"));
    }

    #[test]
    fn relay_allow_reads_peer_ids_cards_and_contacts() {
        let dir = tmp();
        let friend = raven_core::Identity::from_seed(&[9; 32]);
        let peer = p2p_route::local_peer_id(&friend);
        cmd_relay_allow(dir.path(), Some(&peer), None, "").unwrap();
        assert!(relay_allow::load_relay_allow(dir.path())
            .unwrap()
            .unwrap()
            .contains(&peer));
        let card = super::super::format_card_with(
            &friend,
            "",
            "",
            Some(&super::super::P2pRoute {
                peer_id: peer.clone(),
                via: Vec::new(),
            }),
        );
        cmd_relay_allow(dir.path(), None, Some(&card), "bob").unwrap();
        let v1 = super::super::format_card_with(&friend, "", "", None);
        assert!(cmd_relay_allow(dir.path(), None, Some(&v1), "").is_err());
        assert!(cmd_relay_allow(dir.path(), None, None, "").is_err());
        assert!(cmd_relay_allow(dir.path(), Some("nobody"), None, "").is_err());
        cmd_relay_deny(dir.path(), &peer).unwrap();
        assert!(!relay_allow::load_relay_allow(dir.path())
            .unwrap()
            .unwrap()
            .contains(&peer));
    }

    #[test]
    fn relay_card_host_parts_cover_v4_v6_and_names() {
        assert_eq!(host_part("203.0.113.7").unwrap(), "/ip4/203.0.113.7");
        assert_eq!(host_part("[2001:db8::7]").unwrap(), "/ip6/2001:db8::7");
        assert_eq!(
            host_part("Relay.Example.com").unwrap(),
            "/dns/relay.example.com"
        );
    }
}
