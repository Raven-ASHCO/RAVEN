//! Extended ash commands: bootstrap, device sync, chat, secure send, mailbox.
//! Kept separate from main.rs to keep the interactive shell readable.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use rand::RngCore;
use raven_core::address::encode_address;
use raven_core::atsam_mlkem::HybridKeypair;
use raven_core::bootstrap::{load_bootstrap, save_bootstrap, try_load_bootstrap, BootstrapConfig};
use raven_core::chat_history::{BlockList, ChatHistory};
use raven_core::device_cert::{
    ensure_local_device_certificate, load_device_registry_checked, save_device_registry,
    with_device_registry_lock,
};
use raven_core::device_sync::{
    import_contact_sync_checked, seal_contact_sync, ContactSyncPlaintext, RevocationRecord,
    RevocationStore, SyncContact,
};
use raven_core::envelope::Envelope;
use raven_core::fingerprint::device_fingerprint_v1;
use raven_core::identity::Identity;
#[cfg(unix)]
use raven_core::ipc::default_socket_path;
use raven_core::ipc::{IpcRequest, IpcResponse, IPC_VERSION};
use raven_core::messaging_path::{assert_no_silent_fastapi, resolve_terminal_messaging_path};
use raven_core::paths::PRIMARY_DEVICE_ID;
use raven_core::prekey_bundle::{PrekeyBundle, PrekeyBundleJson, PrekeyStore};
use raven_core::prekey_lifecycle::{PrekeyGenerationPrivate, PrekeyLifecycleActor};
use raven_core::sanitize::{sanitize_terminal_line, sanitize_terminal_text};
use raven_core::store_object::{
    mailbox_tag, mailbox_tags_with_overlap, store_tag_from_mailbox, StoreMailbox, StoreObject,
};
use std::process::Command;
use std::time::Duration;
use zeroize::Zeroize;

// Shared with cli.rs: one palette (honours NO_COLOR / non-TTY), one strict
// pub_hex parser, one clock, one host:port validator.
use super::{
    looks_like_lan_dial as looks_like_host_port, now_ms, parse_pub_hex_strict as parse_pub_hex,
    C_BOLD, C_CYAN, C_DIM, C_GREEN, C_PURPLE, C_RESET, DEFAULT_LAN_PORT,
};

#[derive(Debug, PartialEq, Eq)]
pub enum LineResult {
    Line(String),
    Eof,
    /// The line was not valid UTF-8 (a terminal or paste in a legacy encoding).
    /// It was read and dropped; the input is still open, so the caller says so
    /// and carries on instead of ending the session as if the user had quit.
    BadInput,
    Err,
}

pub fn read_line_result() -> LineResult {
    read_line_from(&mut io::stdin().lock())
}

fn read_line_from(input: &mut impl io::BufRead) -> LineResult {
    let mut s = String::new();
    match input.read_line(&mut s) {
        Ok(0) => LineResult::Eof,
        Ok(_) => LineResult::Line(s.trim().to_string()),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => LineResult::BadInput,
        Err(_) => LineResult::Err,
    }
}

pub fn raven_node_bin_public() -> PathBuf {
    raven_node_bin()
}

fn raven_node_bin() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("raven-node")))
        .unwrap_or_else(|| PathBuf::from("raven-node"))
}

/// Per-profile log the auto-started service writes stdout/stderr to (0600, in
/// the private data dir). It is the only place a failed start can explain itself.
const DAEMON_LOG_NAME: &str = raven_core::paths::SERVICE_LOG_NAME;
/// A fresh service must answer IPC within this window. It runs identity init
/// (Keychain / SQLCipher) before it binds the socket, which can take many
/// seconds on a cold profile.
const DAEMON_READY_DEADLINE: Duration = Duration::from_secs(20);
/// IPC timeout of one readiness probe, so a wedged daemon cannot eat the whole
/// window in a single probe.
const DAEMON_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a service that holds the instance lock but does not answer is given
/// before it is reported as unresponsive (the lock is taken right before the
/// socket is bound, so a healthy service answers within moments).
const DAEMON_LOCK_HOLDER_GRACE: Duration = Duration::from_secs(5);
const DAEMON_LOG_TAIL_BYTES: u64 = 2048;
/// Cap on the service log. `open_daemon_log` enforces it when ash starts a
/// service; the running service enforces it itself (it truncates its own log in
/// place) when ash passes the cap in [`DAEMON_LOG_MAX_ENV`], which it does only
/// for a log it opened, so a service started any other way is never touched.
const DAEMON_LOG_MAX_BYTES: u64 = 1 << 20;
const DAEMON_LOG_MAX_ENV: &str = "RAVEN_SERVICE_LOG_MAX_BYTES";
const DAEMON_LOG_MARKER: &str = "--- ash: starting raven-node service ---";
/// A service whose log says it is blocked on a macOS Keychain dialog is waiting
/// for a person, not slow: it gets this many times the usual readiness window
/// (160 s for the default 20 s), long enough to find the dialog and answer it
/// and still bounded, so a dialog nobody answers cannot hang ash for good.
const DAEMON_KEYCHAIN_WAIT_FACTOR: u32 = 8;
/// A service that has not answered after this long gets a "still starting" note
/// (terminals only: pipes keep their output).
const DAEMON_SLOW_START_NOTICE_AFTER: Duration = Duration::from_secs(3);
/// How often the service log is re-read while waiting, for the Keychain marker.
const DAEMON_LOG_POLL: Duration = Duration::from_millis(500);
/// After the service answers IPC, how long ash waits for it to report its LAN
/// listener (`lan_direct` in Status capabilities) before it says the computer is
/// not receiving. The listener starts right after IPC, so this is only slack.
const DAEMON_LISTENER_WAIT: Duration = Duration::from_secs(3);
/// What to do when the service waited on macOS for Keychain access. Appended to
/// the "did not answer" error: on a Mac that is by far the most likely cause.
const KEYCHAIN_APPROVE_HINT: &str =
    "If macOS asked for Keychain access for raven-node, approve it (Always Allow) and retry";

/// The service this process last auto-started, with the log offset where its
/// output begins. A slow start is awaited rather than duplicated (a second
/// spawn would only fail to bind the LAN port), and an exited child is reaped.
type StartedDaemon = std::sync::Mutex<Option<(std::process::Child, u64)>>;
static STARTED_DAEMON: StartedDaemon = std::sync::Mutex::new(None);

fn daemon_log_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DAEMON_LOG_NAME)
}

/// Open (append, 0600) the service log; returns the file and the offset where
/// this attempt's output starts. A log grown past the cap is dropped first.
fn open_daemon_log(path: &Path) -> io::Result<(std::fs::File, u64)> {
    if std::fs::metadata(path).is_ok_and(|m| m.len() > DAEMON_LOG_MAX_BYTES) {
        let _ = std::fs::remove_file(path);
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `mode` only applies on creation; tighten a pre-existing file too.
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    let start = file.metadata()?.len();
    writeln!(file, "{DAEMON_LOG_MARKER}")?;
    Ok((file, start))
}

/// Last bytes of this attempt's output (sanitized for the terminal).
fn daemon_log_tail(path: &Path, from: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    let begin = from.max(len.saturating_sub(DAEMON_LOG_TAIL_BYTES));
    if file.seek(SeekFrom::Start(begin)).is_err() {
        return String::new();
    }
    let mut raw = Vec::new();
    let _ = file.take(DAEMON_LOG_TAIL_BYTES).read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw);
    let kept: Vec<&str> = text
        .lines()
        .filter(|l| *l != DAEMON_LOG_MARKER && !l.trim().is_empty())
        .collect();
    sanitize_terminal_text(&kept.join("\n"))
}

/// Failure text: what happened, the service's own last words, the full log.
fn daemon_failure(what: &str, log: &Path, tail: &str) -> String {
    let mut msg = what.to_string();
    if !tail.is_empty() {
        msg.push_str("\n  service output:");
        let lines: Vec<&str> = tail.lines().collect();
        for line in &lines[lines.len().saturating_sub(8)..] {
            msg.push_str("\n    ");
            msg.push_str(line);
        }
        let lower = tail.to_lowercase();
        if lower.contains("failed to bind") || lower.contains("in use") {
            msg.push_str(
                "\n  hint: another process holds the LAN port; set \
                 RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0 for an outbound-only service",
            );
        }
    }
    msg.push_str(&format!("\n  full log: {}", log.display()));
    msg
}

/// Keep the service alive after ash exits or its terminal closes: own process
/// group on Unix (a tty Ctrl-C / hangup targets the foreground group only),
/// detached console and new group on Windows.
fn detach_from_terminal(cmd: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = cmd;
    }
}

fn node_service_command(node: &Path, data_dir: &Path, listen: &str) -> Command {
    let mut cmd = Command::new(node);
    cmd.arg("service").arg("--data-dir").arg(data_dir).args([
        "--lan-listen",
        listen,
        "--ble-listen",
        "127.0.0.1:0",
    ]);
    cmd
}

/// How to stop the one service this ash started, by its process id: never a
/// pattern that would also match the service of another profile.
fn stop_advice(pid: u32) -> String {
    if cfg!(windows) {
        // The service runs detached (no window), so plain `taskkill` only asks it
        // to close and Windows refuses; it has to be forced.
        format!("taskkill /F /PID {pid}")
    } else {
        format!("kill {pid}")
    }
}

/// What the service log says the service is blocked on: the Keychain marker line
/// the daemon writes while a macOS dialog holds its Keychain call
/// (`raven_core::macos_keychain`), in the plain words of the hint ash itself shows.
fn keychain_block_in(log_tail: &str) -> Option<&'static str> {
    use raven_core::macos_keychain::{last_daemon_marker, KeychainWhat};
    const ALL: [KeychainWhat; 4] = [
        KeychainWhat::IdentitySeed,
        KeychainWhat::ChatHistoryKey,
        KeychainWhat::SessionSecret,
        KeychainWhat::PrekeyState,
    ];
    let marker = last_daemon_marker(log_tail)?;
    Some(
        ALL.iter()
            .find(|what| what.token() == marker.what)
            .map_or("a saved secret", |what| what.label()),
    )
}

/// Said once, when the service log first shows it is waiting for a Keychain answer.
fn keychain_wait_notice(what: &str, wait_more: Duration) -> String {
    format!(
        "{C_PURPLE}note{C_RESET}: raven-node (the background service) is waiting for macOS \
         Keychain access to {what}.\n  \
         If a macOS window asks whether raven-node may use it, approve it (choose \"Always \
         Allow\"); the window can be hidden behind other windows.\n  \
         ash keeps waiting for up to {} more seconds, then gives up. Ctrl-C stops waiting now.",
        wait_more.as_secs()
    )
}

/// The service did not answer IPC in time, though it is still running.
fn slow_start_error(pid: u32, waited: Duration, keychain: Option<&str>) -> String {
    let mut msg = format!(
        "raven-node service did not answer IPC within {}s (it is still running as process \
         {pid}; retry shortly, or stop only this one with: {})",
        waited.as_secs(),
        stop_advice(pid)
    );
    if let Some(what) = keychain {
        msg.push_str(&format!(
            "\n  its log says it is waiting for macOS Keychain access to {what}"
        ));
    }
    if keychain.is_some() || cfg!(target_os = "macos") {
        msg.push_str(&format!("\n  {KEYCHAIN_APPROVE_HINT}"));
    }
    msg
}

/// Poll until the service answers IPC, exits (reported at once with its log
/// tail), or `deadline` passes. The IPC probe comes first, so another daemon
/// that came up meanwhile (a concurrent start) also counts as success.
///
/// A service can also be *waiting for a person*: on macOS it blocks inside a
/// Keychain call until a dialog is answered and says so in its log. ash notices,
/// tells the user once what to do, and gives it [`DAEMON_KEYCHAIN_WAIT_FACTOR`]
/// times the window instead of giving up on it after 20 s.
fn wait_for_daemon(
    data_dir: &Path,
    child: &mut std::process::Child,
    log_start: u64,
    deadline: Duration,
) -> Result<(), String> {
    let log = daemon_log_path(data_dir);
    let started = std::time::Instant::now();
    let mut deadline = deadline;
    let log_poll = DAEMON_LOG_POLL.min(deadline / 5);
    let mut keychain: Option<&'static str> = None;
    let mut next_log_look = Duration::ZERO;
    let mut said_still_starting = false;
    let mut delay = Duration::from_millis(40);
    loop {
        if super::ipc_client::ipc_daemon_up_within(data_dir, DAEMON_PROBE_TIMEOUT) {
            return Ok(());
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if super::ipc_client::ipc_daemon_up_within(data_dir, DAEMON_PROBE_TIMEOUT) {
                    return Ok(());
                }
                return Err(daemon_failure(
                    &format!("raven-node service exited during startup ({status})"),
                    &log,
                    &daemon_log_tail(&log, log_start),
                ));
            }
            Ok(None) => {}
            Err(e) => return Err(format!("could not poll the raven-node service: {e}")),
        }
        let elapsed = started.elapsed();
        // Always look once more at the deadline: a marker written a moment ago
        // must not be missed by the poll interval.
        if keychain.is_none() && (elapsed >= next_log_look || elapsed >= deadline) {
            next_log_look = elapsed + log_poll;
            if let Some(what) = keychain_block_in(&daemon_log_tail(&log, log_start)) {
                deadline = deadline.saturating_mul(DAEMON_KEYCHAIN_WAIT_FACTOR);
                eprintln!(
                    "{}",
                    keychain_wait_notice(what, deadline.saturating_sub(elapsed))
                );
                keychain = Some(what);
            }
        }
        if keychain.is_none()
            && !said_still_starting
            && elapsed >= DAEMON_SLOW_START_NOTICE_AFTER
            && io::stderr().is_terminal()
        {
            said_still_starting = true;
            eprintln!("{C_DIM}waiting for the raven-node service to start ...{C_RESET}");
        }
        if elapsed >= deadline {
            return Err(daemon_failure(
                &slow_start_error(child.id(), deadline, keychain),
                &log,
                &daemon_log_tail(&log, log_start),
            ));
        }
        std::thread::sleep(delay.min(deadline - elapsed));
        delay = (delay * 3 / 2).min(Duration::from_millis(250));
    }
}

/// Printed right after the service is spawned: what it is, that it outlives ash,
/// and how to stop only this one (its process id, never a name pattern that would
/// also stop another profile's service).
fn started_notice(pid: u32, log: &Path) -> String {
    format!(
        "{C_PURPLE}notice{C_RESET}: started raven-node (process {pid}), RAVEN's background service \
         for this profile. It keeps running after ash exits.\n\
         {C_DIM}stop only this one with: {} · log: {}{C_RESET}",
        stop_advice(pid),
        log.display()
    )
}

/// Spawn `cmd` detached with stdout/stderr in the 0600 service log, say what was
/// started ([`started_notice`]), then wait for it to serve IPC. Reuses a
/// still-running service this process started earlier instead of spawning a
/// competing one.
fn start_daemon(
    data_dir: &Path,
    mut cmd: Command,
    deadline: Duration,
    slot: &StartedDaemon,
) -> Result<(), String> {
    let mut slot = slot.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((child, _)) = slot.as_mut() {
        if !matches!(child.try_wait(), Ok(None)) {
            *slot = None; // exited (now reaped) or unpollable: start afresh
        }
    }
    if slot.is_none() {
        let log = daemon_log_path(data_dir);
        let (stdout, stderr, log_start, log_captured) = match open_daemon_log(&log) {
            Ok((file, start)) => match file.try_clone() {
                Ok(dup) => (
                    std::process::Stdio::from(dup),
                    std::process::Stdio::from(file),
                    start,
                    true,
                ),
                Err(_) => (
                    std::process::Stdio::null(),
                    std::process::Stdio::null(),
                    0,
                    false,
                ),
            },
            Err(e) => {
                eprintln!(
                    "{C_DIM}note: cannot write {} ({e}); service output will not be captured{C_RESET}",
                    log.display()
                );
                (
                    std::process::Stdio::null(),
                    std::process::Stdio::null(),
                    0,
                    false,
                )
            }
        };
        if log_captured {
            // The daemon outlives this process and appends for weeks: let it
            // bound the log it was handed (see DAEMON_LOG_MAX_BYTES).
            cmd.env(DAEMON_LOG_MAX_ENV, DAEMON_LOG_MAX_BYTES.to_string());
        }
        cmd.stdin(std::process::Stdio::null())
            .stdout(stdout)
            .stderr(stderr);
        detach_from_terminal(&mut cmd);
        let child = cmd.spawn().map_err(|e| {
            format!(
                "could not start {} ({e}); build or install raven-node next to ash",
                cmd.get_program().to_string_lossy()
            )
        })?;
        // Said before the wait, so a process that was left running (Ctrl-C while
        // waiting) is never a surprise.
        eprintln!("{}", started_notice(child.id(), &log));
        *slot = Some((child, log_start));
    }
    let (child, log_start) = slot.as_mut().expect("daemon slot filled above");
    wait_for_daemon(data_dir, child, *log_start, deadline)
}

/// What the IPC endpoint of a profile says about the service that owns it.
#[derive(Debug, PartialEq, Eq)]
enum ExistingService {
    /// It answered a Ping.
    Up,
    /// A live service holds the instance lock (the contained path) but does not
    /// answer: wedged (stopped, deadlocked) or blocked on an OS keystore prompt.
    /// (Detected through the Unix instance lock only; Windows has no such lock.)
    #[cfg_attr(not(unix), allow(dead_code))]
    Unresponsive(PathBuf),
    /// No service for this profile (no one answers, no one holds the lock).
    Absent,
}

/// Probe the service for `data_dir`: up to three short pings (a busy daemon can
/// miss one), then, on Unix, whether a live service still *owns* the profile.
///
/// A pinged-out service that holds the instance lock is `Unresponsive`: its
/// socket must never be unlinked and no competing service started, which would
/// only die on that lock with a misleading "exited during startup". The lock is
/// taken only after the service's identity preflight, right before it binds, so a
/// holder that stays silent past a short `grace` (the gap between taking the lock
/// and listening) is not "still starting". Worst case is a few probes plus
/// `grace` instead of three full 10 s IPC timeouts. `still_starting`: the lock
/// belongs to a service this process started itself, which `start_daemon` waits for.
fn probe_existing_service(
    data_dir: &Path,
    probe: Duration,
    grace: Duration,
    still_starting: bool,
) -> ExistingService {
    for attempt in 0..3 {
        if super::ipc_client::ipc_daemon_up_within(data_dir, probe) {
            return ExistingService::Up;
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(150));
        }
    }
    #[cfg(unix)]
    if !still_starting {
        let lock = raven_core::ipc::instance_lock_path(&default_socket_path(data_dir));
        if instance_lock_is_held(&lock) {
            let deadline = std::time::Instant::now() + grace;
            loop {
                if super::ipc_client::ipc_daemon_up_within(data_dir, probe) {
                    return ExistingService::Up;
                }
                if std::time::Instant::now() >= deadline {
                    return ExistingService::Unresponsive(lock);
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (grace, still_starting);
    ExistingService::Absent
}

/// True when another process holds the (exclusive `flock`) instance lock at
/// `lock`. Probing takes the lock for an instant when it is free and releases it
/// at once. A missing or unopenable lock file has no holder.
#[cfg(unix)]
fn instance_lock_is_held(lock: &Path) -> bool {
    let Ok(file) = std::fs::OpenOptions::new().read(true).open(lock) else {
        return false;
    };
    matches!(file.try_lock(), Err(std::fs::TryLockError::WouldBlock))
}

/// Start of [`unresponsive_service_error`]; the send path reports this error as
/// is instead of wrapping it in "not running and could not be started", which
/// would be the opposite of the truth.
const SERVICE_UNRESPONSIVE_PREFIX: &str =
    "local raven-node service is running but is not answering IPC";

/// Single-quote `s` for a POSIX shell (the stop advice below is pasted into one).
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Escape `s` for a POSIX extended regular expression (`pkill -f` takes one).
fn ere_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(
            c,
            '.' | '[' | ']' | '{' | '}' | '(' | ')' | '*' | '+' | '?' | '^' | '$' | '|' | '\\'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A Keychain marker in the service log describes what the service is doing now
/// only while the log is still being written: the guard repeats the marker every
/// 30 s while a dialog is open and writes nothing when it is answered, so an old
/// marker is just history.
const KEYCHAIN_MARKER_FRESH: Duration = Duration::from_secs(90);

fn log_written_within(path: &Path, window: Duration) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|written| written.elapsed().ok())
        .is_some_and(|age| age <= window)
}

fn unresponsive_service_error(data_dir: &Path, lock: &Path) -> String {
    // A service blocked on a Keychain dialog says so in its log: name it, so the
    // user answers the dialog instead of killing a healthy service. Only a log
    // that is still being written can say what the service waits for now.
    let log = daemon_log_path(data_dir);
    let waiting = if log_written_within(&log, KEYCHAIN_MARKER_FRESH) {
        keychain_block_in(&daemon_log_tail(&log, 0))
    } else {
        None
    }
    .map(|what| format!(" Its log says it is waiting for macOS Keychain access to {what}."))
    .unwrap_or_default();
    // `pkill -f` matches an unanchored regex against the whole command line: end
    // the pattern at the argument so `--data-dir /a/b` cannot also stop `/a/b2`.
    format!(
        "{SERVICE_UNRESPONSIVE_PREFIX} (profile {}; it holds {}): it may be wedged or waiting \
         on an OS keystore prompt.{waiting} Not starting a second one. Answer any prompt and \
         retry, or stop only this profile's service with: pkill -f {}",
        data_dir.display(),
        lock.display(),
        shell_quote(&format!(
            "raven-node service --data-dir {}( |$)",
            ere_escape(&data_dir.display().to_string())
        ))
    )
}

/// What the service reports about its LAN listener: `Some(true)` it is up,
/// `Some(false)` Status came back without `lan_direct` (port busy or unusable),
/// `None` Status could not be asked.
fn listener_reported(status: &Result<IpcResponse, String>) -> Option<bool> {
    match status {
        Ok(IpcResponse::Status { capabilities, .. }) => {
            Some(capabilities.iter().any(|c| c == "lan_direct"))
        }
        _ => None,
    }
}

/// Poll the service's Status for up to `wait` until it lists `lan_direct`. The
/// capability is listed only while the listener is really bound, and the service
/// answers IPC before its listener is up, so the first answers can still say no.
fn wait_for_lan_listener(data_dir: &Path, wait: Duration) -> Option<bool> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let probe = DAEMON_PROBE_TIMEOUT.min(left.max(Duration::from_millis(200)));
        let state = listener_reported(&super::ipc_client::ipc_request_timeout(
            data_dir,
            &IpcRequest::Status { v: IPC_VERSION },
            probe,
        ));
        if state != Some(false) || std::time::Instant::now() >= deadline {
            return state;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn listen_port_is_ephemeral(listen: &str) -> bool {
    listen
        .parse::<std::net::SocketAddr>()
        .is_ok_and(|a| a.port() == 0)
}

fn listen_is_loopback(listen: &str) -> bool {
    listen
        .parse::<std::net::SocketAddr>()
        .map(|a| a.ip().is_loopback())
        .unwrap_or_else(|_| listen.starts_with("localhost"))
}

/// The next port after `port` that is not one RAVEN itself uses (mock BLE
/// 7421, Internet direct 7422, libp2p 7423): suggesting 7421 for a second
/// profile's LAN listener collided with the service's own mock BLE listener.
fn next_free_lan_port(port: u16) -> Option<u16> {
    let mut next = port.checked_add(1)?;
    while raven_core::paths::RESERVED_RAVEN_PORTS.contains(&next) {
        next = next.checked_add(1)?;
    }
    Some(next)
}

/// A listen address for a second profile on this computer: the same host, the
/// next port RAVEN does not use itself.
fn alternative_listen(listen: &str) -> String {
    let fallback = || {
        format!(
            "0.0.0.0:{}",
            next_free_lan_port(DEFAULT_LAN_PORT).unwrap_or(DEFAULT_LAN_PORT)
        )
    };
    match listen.parse::<std::net::SocketAddr>() {
        Ok(mut addr) if addr.port() != 0 => match next_free_lan_port(addr.port()) {
            Some(port) => {
                addr.set_port(port);
                addr.to_string()
            }
            None => fallback(),
        },
        _ => fallback(),
    }
}

/// What to tell the user about the LAN listener of a service ash just started.
/// "It receives on ..." only once the service says its listener is up; when it is
/// not, the computer would otherwise be silently deaf (a second profile on the
/// same machine always loses the default port), so say so once per process.
fn listener_message(
    listen: &str,
    state: Option<bool>,
    log: &Path,
    warned: &AtomicBool,
    pid: Option<u32>,
) -> Option<String> {
    let listen = sanitize_terminal_line(listen);
    match state {
        Some(true) => Some(format!(
            "{C_DIM}it is receiving messages{}{}{C_RESET}",
            // Port 0 asks the OS for a free one: the configured text says nothing.
            if listen_port_is_ephemeral(&listen) {
                String::new()
            } else {
                format!(" on {listen}")
            },
            if listen_is_loopback(&listen) {
                " (this computer only)"
            } else {
                " (other computers on your network can reach it)"
            }
        )),
        Some(false) if !warned.swap(true, Ordering::SeqCst) => Some(format!(
            "{C_PURPLE}warning{C_RESET}: this computer is NOT receiving messages: LAN port \
             {listen} is busy or unavailable (log: {}). Sending still works.\n  To receive: \
             free that port (the service keeps retrying by itself), or stop this service ({}) \
             and run ash again with RAVEN_SERVICE_LAN_LISTEN={} (and tell your contacts the \
             new port). Setting the variable while this service keeps running changes nothing.",
            log.display(),
            match pid {
                Some(pid) => stop_advice(pid),
                None => "stop this profile's service".to_string(),
            },
            alternative_listen(&listen)
        )),
        _ => None,
    }
}

/// Set once the "not receiving" warning was printed (once per ash process).
static LISTENER_WARNED: AtomicBool = AtomicBool::new(false);

/// Start the service with `cmd`, wait until it answers IPC, then say whether it
/// is receiving. The part of [`ensure_mac_lan_daemon`] that follows the probes.
fn start_and_report(
    data_dir: &Path,
    cmd: Command,
    listen: &str,
    deadline: Duration,
    listener_wait: Duration,
    slot: &StartedDaemon,
    warned: &AtomicBool,
) -> Result<(), String> {
    start_daemon(data_dir, cmd, deadline, slot)?;
    let pid = slot
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|(child, _)| child.id());
    if let Some(message) = listener_message(
        listen,
        wait_for_lan_listener(data_dir, listener_wait),
        &daemon_log_path(data_dir),
        warned,
        pid,
    ) {
        eprintln!("{message}");
    }
    Ok(())
}

/// Start / revive the LAN + IPC daemon the secure send path dials through.
///
/// The service it starts is persistent (it outlives ash: own process group, its
/// output kept in `raven-node-service.log`) and receives on
/// `RAVEN_SERVICE_LAN_LISTEN` (default `0.0.0.0:7420`, the Mac-listens port),
/// so the user is told what was started, how to stop that one process, and
/// whether it is really receiving (the listener can be down while IPC works).
///
/// `Err` carries why it is not up (exit status, the service's own last output,
/// the log path) so callers refuse the send with a real reason instead of a
/// bare "No such file or directory" from the next IPC connect.
pub fn ensure_mac_lan_daemon(data_dir: &Path) -> Result<(), String> {
    // A service this process started earlier may still be coming up: its socket
    // is not stale, and it must not be replaced.
    let still_starting = STARTED_DAEMON
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .is_some_and(|(child, _)| matches!(child.try_wait(), Ok(None)));
    match probe_existing_service(
        data_dir,
        DAEMON_PROBE_TIMEOUT,
        DAEMON_LOCK_HOLDER_GRACE,
        still_starting,
    ) {
        ExistingService::Up => return Ok(()),
        ExistingService::Unresponsive(lock) => {
            return Err(unresponsive_service_error(data_dir, &lock));
        }
        ExistingService::Absent => {}
    }
    #[cfg(unix)]
    {
        let sock = default_socket_path(data_dir);
        if !still_starting && sock.exists() {
            // Stale UDS after crash → remove so a fresh service can bind.
            let _ = std::fs::remove_file(&sock);
        }
    }
    let node = raven_node_bin();
    // Outbound-IPC-only deployments (or same-host tests) may need a different
    // or ephemeral LAN bind than the default receive port.
    let listen = std::env::var("RAVEN_SERVICE_LAN_LISTEN")
        .unwrap_or_else(|_| format!("0.0.0.0:{DEFAULT_LAN_PORT}"));
    start_and_report(
        data_dir,
        node_service_command(&node, data_dir, &listen),
        &listen,
        DAEMON_READY_DEADLINE,
        DAEMON_LISTENER_WAIT,
        &STARTED_DAEMON,
        &LISTENER_WARNED,
    )
}

// ── Bootstrap UX ──────────────────────────────────────────────────────────

pub fn cmd_bootstrap_show(data_dir: &Path) {
    let cfg = load_bootstrap(data_dir);
    println!("{C_BOLD}bootstrap{C_RESET}");
    println!(
        "{C_DIM}use_raven_defaults{C_RESET} {}",
        cfg.use_raven_defaults
    );
    println!(
        "{C_DIM}raven_defaults{C_RESET}     {}",
        cfg.raven_defaults.len()
    );
    for p in &cfg.raven_defaults {
        println!("  {C_DIM}raven{C_RESET} {}", sanitize_terminal_line(p));
    }
    println!("{C_DIM}custom{C_RESET}            {}", cfg.custom.len());
    for p in &cfg.custom {
        println!("  {C_CYAN}+{C_RESET} {}", sanitize_terminal_line(p));
    }
    println!(
        "{C_DIM}manual_peers{C_RESET}      {}",
        cfg.manual_peers.len()
    );
    for p in &cfg.manual_peers {
        println!("  {C_GREEN}*{C_RESET} {}", sanitize_terminal_line(p));
    }
    println!(
        "{C_DIM}effective{C_RESET}         {} peers",
        cfg.effective_peers().len()
    );
    println!(
        "{C_DIM}manual_only_ok{C_RESET}    {}",
        cfg.manual_peer_only_ok()
    );
}

/// Load `bootstrap.json` for a read-modify-write. A file that exists but cannot
/// be read or parsed is an error, never the fail-closed empty default (which
/// would then be saved over the user's real peer lists). A missing file is the
/// default config, so a first `add` still works.
fn load_bootstrap_for_edit(data_dir: &Path) -> Result<BootstrapConfig, String> {
    try_load_bootstrap(data_dir).map_err(|e| {
        format!(
            "bootstrap.json is unreadable ({e}); refusing to overwrite it. Fix or move it \
             aside, or reset it explicitly with `ash node init-bootstrap`"
        )
    })
}

fn bootstrap_add_apply(data_dir: &Path, multiaddr: &str, manual: bool) -> Result<String, String> {
    let s = sanitize_terminal_text(multiaddr.trim());
    if s.is_empty() {
        return Err("empty multiaddr".into());
    }
    let mut cfg = load_bootstrap_for_edit(data_dir)?;
    if manual {
        if !cfg.manual_peers.iter().any(|x| x == &s) {
            cfg.manual_peers.push(s.clone());
        }
    } else {
        cfg.add_custom(s.clone());
    }
    save_bootstrap(data_dir, &cfg).map_err(|e| format!("save failed: {e}"))?;
    Ok(s)
}

pub fn cmd_bootstrap_add(data_dir: &Path, multiaddr: &str, manual: bool) {
    match bootstrap_add_apply(data_dir, multiaddr, manual) {
        Ok(s) => println!("{C_GREEN}ok{C_RESET} added {}", s),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
    cmd_bootstrap_show(data_dir);
}

fn bootstrap_disable_raven_apply(data_dir: &Path) -> Result<(), String> {
    let mut cfg = load_bootstrap_for_edit(data_dir)?;
    cfg.remove_raven_defaults();
    save_bootstrap(data_dir, &cfg).map_err(|e| format!("save failed: {e}"))
}

pub fn cmd_bootstrap_disable_raven(data_dir: &Path) {
    if let Err(e) = bootstrap_disable_raven_apply(data_dir) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    println!("{C_GREEN}ok{C_RESET} raven defaults disabled/cleared");
    cmd_bootstrap_show(data_dir);
}

pub fn cmd_bootstrap_init(data_dir: &Path, no_raven_defaults: bool) {
    let mut cfg = BootstrapConfig::default();
    if no_raven_defaults {
        cfg.remove_raven_defaults();
    }
    if let Err(e) = save_bootstrap(data_dir, &cfg) {
        eprintln!("save failed: {e}");
        std::process::exit(1);
    }
    println!("{C_GREEN}ok{C_RESET} wrote bootstrap.json");
    cmd_bootstrap_show(data_dir);
}

// ── Device sync ───────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize)]
struct LocalContactRow {
    #[serde(default)]
    petname: String,
    #[serde(default)]
    public_tag: String,
    #[serde(default)]
    alias: String,
    address: String,
    pub_hex: String,
    #[serde(default)]
    pinned: bool,
    #[serde(default)]
    lan_dial: String,
}

fn load_local_contacts(data_dir: &Path) -> Result<Vec<LocalContactRow>, String> {
    let path = data_dir.join("contacts.json");
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("contacts.json: {e}"))?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("contacts.json corrupt — refusing empty book: {e}"))
}

fn save_local_contacts(data_dir: &Path, rows: &[LocalContactRow]) -> Result<(), String> {
    let raw = serde_json::to_string_pretty(rows).map_err(|e| e.to_string())?;
    raven_core::atomic_write_private(&data_dir.join("contacts.json"), raw.as_bytes())
}

pub fn cmd_device_sync_export(data_dir: &Path, id: &Identity, device_id: &str, out: &Path) {
    let contacts = match load_local_contacts(data_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let sync: Vec<SyncContact> = contacts
        .into_iter()
        .map(|c| {
            SyncContact {
                petname: c.petname,
                public_tag: if c.public_tag.is_empty() {
                    c.alias.clone()
                } else {
                    c.public_tag
                },
                alias: c.alias,
                address: c.address,
                pub_hex: c.pub_hex,
                pinned: c.pinned,
            }
            .migrate()
        })
        .collect();
    let plain = ContactSyncPlaintext {
        schema: 1,
        from_device_id: sanitize_terminal_text(device_id),
        contacts: sync,
        issued_at_ms: now_ms(),
    };
    match seal_contact_sync(id, &plain) {
        Ok(wire) => {
            if let Err(e) = std::fs::write(out, hex::encode(&wire)) {
                eprintln!("write failed: {e}");
                std::process::exit(1);
            }
            println!(
                "{C_GREEN}ok{C_RESET} sealed {} contacts → {}",
                plain.contacts.len(),
                out.display()
            );
            println!("{C_DIM}note{C_RESET} hex blob — exchange OOB / opaque store only");
        }
        Err(e) => {
            eprintln!("seal failed: {e}");
            std::process::exit(1);
        }
    }
}

pub fn cmd_device_sync_import(data_dir: &Path, id: &Identity, file: &Path) {
    let raw = match std::fs::read_to_string(file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("read: {e}");
            std::process::exit(1);
        }
    };
    let wire = match hex::decode(raw.trim()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("hex: {e}");
            std::process::exit(1);
        }
    };
    match device_sync_import_apply(data_dir, id, &wire) {
        Ok(added) => println!("{C_GREEN}ok{C_RESET} imported {added} new contact(s)"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// Serialises the contacts.json load → merge → save of a sync import.
const CONTACTS_LOCK: &str = ".contacts.lock.sqlite";

fn device_sync_import_apply(data_dir: &Path, id: &Identity, wire: &[u8]) -> Result<usize, String> {
    let _contacts_lock = raven_core::DataDirLock::acquire(data_dir, CONTACTS_LOCK)
        .map_err(|e| format!("contacts lock: {e}"))?;
    // Load the local book BEFORE importing: the import records the per-sender
    // replay watermark, so a corrupt or unreadable contacts.json must fail
    // first, while the same sync file can still be imported once it is fixed.
    let mut local = load_local_contacts(data_dir)?;
    // Fail-closed: checked registry (corrupt ≠ empty), sender auth unless no
    // registry exists yet, and replayed/stale blobs refused per sender.
    let imported = import_contact_sync_checked(data_dir, id, wire, now_ms())
        .map_err(|e| format!("import failed: {e}"))?;
    let mut added = 0usize;
    for sc in imported {
        // Same validation as `contact add`: strict key, canonical address that
        // the key actually encodes to. Rows here become trusted peers.
        let (pub_hex, address) = match validate_sync_row(&sc.address, &sc.pub_hex) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "{C_PURPLE}skip{C_RESET} invalid synced contact ({})",
                    sanitize_terminal_line(&e)
                );
                continue;
            }
        };
        if local
            .iter()
            .any(|c| c.pub_hex.eq_ignore_ascii_case(&pub_hex) || c.address == address)
        {
            continue;
        }
        // Pin conflict: refuse overwrite of pinned different key for same tag.
        let tag = if sc.public_tag.is_empty() {
            sc.alias.clone()
        } else {
            sc.public_tag.clone()
        };
        if !tag.is_empty()
            && local.iter().any(|c| {
                c.pinned
                    && c.public_tag.eq_ignore_ascii_case(&tag)
                    && !c.pub_hex.eq_ignore_ascii_case(&pub_hex)
            })
        {
            eprintln!(
                "{C_PURPLE}skip{C_RESET} @{} — pinned local key differs",
                sanitize_terminal_line(&tag)
            );
            continue;
        }
        local.push(LocalContactRow {
            petname: sanitize_terminal_line(sc.petname.trim()),
            public_tag: sanitize_terminal_line(&tag),
            alias: sanitize_terminal_line(&sc.alias),
            address,
            pub_hex,
            pinned: sc.pinned,
            lan_dial: String::new(),
        });
        added += 1;
    }
    save_local_contacts(data_dir, &local).map_err(|e| format!("save contacts: {e}"))?;
    Ok(added)
}

/// Strict key + canonical address bound to that key → `(pub_hex, address)`.
fn validate_sync_row(address: &str, pub_hex: &str) -> Result<(String, String), String> {
    let ed = parse_pub_hex(pub_hex)?;
    let address = raven_core::address::from_display(address);
    if raven_core::address::decode_address(&address).is_none() {
        return Err("address is not valid rvn1 bech32m".into());
    }
    if encode_address(&ed) != address {
        return Err("address/pub mismatch".into());
    }
    Ok((hex::encode(ed), address))
}

#[derive(Debug, PartialEq, Eq)]
enum RevokeOutcome {
    /// A new record was issued and saved.
    Revoked,
    /// The store already revoked this device at this or a newer epoch.
    AlreadyRevoked,
}

/// Revoke `device_id` in the revocation store and keep the device registry in
/// step. The registry push is idempotent and runs on every outcome, so a rerun
/// repairs a data dir where an earlier run saved `revocations.json` but failed
/// before the registry (that rerun must not be turned away as "already
/// applied" or as a same-epoch conflict with its own earlier record).
fn device_revoke_apply(
    data_dir: &Path,
    id: &Identity,
    device_id: &str,
    epoch: u64,
) -> Result<RevokeOutcome, String> {
    let user_hex = hex::encode(id.public_key_bytes());
    let mut store =
        RevocationStore::load_checked(data_dir).map_err(|e| format!("revocation store: {e}"))?;
    let outcome = if store
        .epoch_of(&user_hex, device_id)
        .is_some_and(|existing| existing >= epoch)
    {
        RevokeOutcome::AlreadyRevoked
    } else {
        let rec = RevocationRecord::issue(id, device_id, epoch, now_ms(), "operator-revoke")?;
        if store.apply(rec)? {
            store
                .save(data_dir)
                .map_err(|e| format!("revocation save failed: {e}"))?;
            RevokeOutcome::Revoked
        } else {
            RevokeOutcome::AlreadyRevoked
        }
    };
    with_device_registry_lock(data_dir, || {
        let mut reg = load_device_registry_checked(data_dir)?;
        store.push_into_registry(&user_hex, &mut reg);
        save_device_registry(data_dir, &reg)
    })
    .map_err(|e| format!("device registry: {e}"))?;
    Ok(outcome)
}

pub fn cmd_device_revoke(data_dir: &Path, id: &Identity, device_id: &str, epoch: u64) {
    match device_revoke_apply(data_dir, id, device_id, epoch) {
        Ok(RevokeOutcome::Revoked) => println!(
            "{C_GREEN}ok{C_RESET} revoked {}",
            sanitize_terminal_line(device_id)
        ),
        Ok(RevokeOutcome::AlreadyRevoked) => println!(
            "{C_DIM}already revoked at epoch >= {epoch}; device registry reconciled{C_RESET}"
        ),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

// ── Send outcomes in plain words ──────────────────────────────────────────
//
// Every way a send can end is said in the user's terms: what happened to their
// text (delivered / queued locally / NOT SENT, nothing queued), who it concerns
// (the contact's name, never a key) and the next step. The raw daemon or OS text
// stays at the end as "(technical: ...)" so logs and bug reports still carry it.
// The text goes to stderr (see `send_failure_line`); only success is on stdout.

/// Who a send goes to, where, and how its outcome is shown.
#[derive(Clone, Debug, Default)]
pub(crate) struct SendCtx {
    /// Petname, else `@tag`; empty when the peer is not a saved contact.
    pub(crate) name: String,
    /// Flags that select this contact in `ash contact ...` hints.
    pub(crate) selector: String,
    /// The peer's key (64 hex): `ash contact unblock` takes nothing else.
    pub(crate) pub_hex: String,
    /// The `host:port` being dialled (may be empty).
    pub(crate) dial: String,
    /// The profile, to name files in recovery steps.
    pub(crate) data_dir: Option<PathBuf>,
    /// Chat transcript lines instead of `status ...` lines.
    pub(crate) chat: bool,
}

/// `s` as one shell word in a hint: bare when plain, else quoted.
fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '@' | '-' | ':'));
    if plain {
        s.to_string()
    } else if s.chars().any(|c| matches!(c, '"' | '$' | '`' | '\\' | '!')) {
        shell_quote(s)
    } else {
        format!("\"{s}\"")
    }
}

/// The `ash contact ...` selector flags for a contact known by `name`
/// (petname, or `@tag`) or else by `address`.
fn selector_for(name: &str, address: &str) -> String {
    if let Some(tag) = name.strip_prefix('@') {
        format!("--tag {}", shell_word(tag))
    } else if !name.is_empty() {
        format!("--petname {}", shell_word(name))
    } else if !address.is_empty() {
        format!("--address {address}")
    } else {
        String::new()
    }
}

impl SendCtx {
    /// Only a display name is known (see [`friendly_send_error`]).
    pub(crate) fn named(who: &str) -> Self {
        let name = sanitize_terminal_line(who.trim());
        Self {
            selector: selector_for(&name, ""),
            name,
            ..Self::default()
        }
    }

    fn who(&self) -> String {
        if self.name.is_empty() {
            "the other person".into()
        } else {
            self.name.clone()
        }
    }

    fn whose(&self) -> String {
        format!("{}'s", self.who())
    }

    fn sel(&self) -> String {
        if self.selector.is_empty() {
            "--petname NAME".into()
        } else {
            self.selector.clone()
        }
    }
}

/// The saved contact whose key is `pub_hex` (read-only; an unreadable book is
/// "no contact", the send itself reports a corrupt book where it matters).
fn contact_for_key(data_dir: &Path, pub_hex: &str) -> Option<LocalContactRow> {
    load_local_contacts(data_dir)
        .ok()?
        .into_iter()
        .find(|c| c.pub_hex.trim().eq_ignore_ascii_case(pub_hex.trim()))
}

/// Who `peer_pub_hex` is to the user: the contact's petname, else its `@tag`.
/// `petname` / `tag` are what the caller already knows (the chat does); the CLI
/// send paths pass "" and the saved contact is looked up here.
pub(crate) fn send_ctx(data_dir: &Path, petname: &str, tag: &str, peer_pub_hex: &str) -> SendCtx {
    let clean_tag = |t: &str| sanitize_terminal_line(t.trim().trim_start_matches('@'));
    let mut petname = sanitize_terminal_line(petname.trim());
    let mut tag = clean_tag(tag);
    if petname.is_empty() && tag.is_empty() {
        if let Some(c) = contact_for_key(data_dir, peer_pub_hex) {
            petname = sanitize_terminal_line(c.petname.trim());
            tag = clean_tag(&c.public_tag);
        }
    }
    let name = if !petname.is_empty() {
        petname
    } else if !tag.is_empty() {
        format!("@{tag}")
    } else {
        String::new()
    };
    let key = parse_pub_hex(peer_pub_hex).ok();
    SendCtx {
        selector: selector_for(&name, &key.map(|k| encode_address(&k)).unwrap_or_default()),
        name,
        pub_hex: key.map(hex::encode).unwrap_or_default(),
        dial: String::new(),
        data_dir: Some(data_dir.to_path_buf()),
        chat: false,
    }
}

/// How a failed send is explained. The raw text decides ([`classify_cause`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    /// The computer answered but nothing listens on that port.
    NotListening,
    /// No answer at all (off, asleep, other network, new IP).
    NotReachable,
    /// Something answered, then hung up or went silent.
    ClosedEarly,
    /// The peer took the connection and closed it without a word.
    PeerRefused,
    /// The address belongs to another key than the saved contact's.
    WrongIdentity,
    BadAddress,
    NoAddress,
    /// RAVEN's own background service on this computer.
    ServiceDown,
    ServiceStart,
    /// The service was started and is still running but has not answered yet: a
    /// slow start, often a macOS Keychain window nobody has answered.
    ServiceSlow,
    HistoryUnreadable,
    KeychainDenied,
    HistoryLocked,
    TooLarge,
    BadCharacters,
    Blocked,
    SendInProgress,
    /// Nothing but whitespace was typed.
    EmptyMessage,
    /// Not one of the above: the raw text is all there is.
    Other,
}

fn classify_cause(raw: &str) -> Cause {
    let l = raw.to_ascii_lowercase();
    let has = |needles: &[&str]| needles.iter().any(|n| l.contains(n));
    // Most specific first: several texts embed the words of another. A service
    // that is still running but slow to answer is wrapped in the same "not
    // running and could not be started" prefix as one that failed to start.
    if has(&["did not answer ipc within", "is still running as process"]) {
        Cause::ServiceSlow
    } else if has(&["service is not running and could not be started"]) {
        Cause::ServiceStart
    } else if has(&[
        "identity bind does not match",
        "rlb1 identity does not match",
        "rlb1 offer identity mismatch",
    ]) {
        Cause::WrongIdentity
    } else if has(&[
        "_dial_peer_closed",
        "link_not_accepted",
        "closed the connection without",
        "waiting_for_pair_response",
        "not a local contact",
    ]) {
        Cause::PeerRefused
    } else if has(&["on the local block list", "blocked peer"]) {
        Cause::Blocked
    } else if has(&["still held by another raven process"]) {
        Cause::HistoryLocked
    } else if has(&[
        "chat history is corrupt",
        "chat history authentication failed",
        "protected chat-history key is corrupt",
        "chat history file has unsafe metadata",
        "plaintext chat history",
    ]) {
        Cause::HistoryUnreadable
    } else if has(&[
        "protected chat-history key is missing",
        "keychain read failed",
        "keychain default failed",
        "keychain add failed",
        "chat-history backend unavailable",
    ]) {
        Cause::KeychainDenied
    } else if has(&["message too large for"]) {
        Cause::TooLarge
    } else if has(&["violates the bounded application policy"]) {
        Cause::BadCharacters
    } else if has(&["earlier outbound object must be retried"]) {
        Cause::SendInProgress
    } else if has(&["message is empty"]) {
        Cause::EmptyMessage
    } else if has(&["host:port required", "localistenqueue"]) {
        Cause::NoAddress
    } else if has(&[
        "invalid socket address",
        "must be host:port",
        "lan_dial parse",
        "internet_dial parse",
    ]) {
        Cause::BadAddress
    } else if has(&[
        "raven-node is not running",
        "service stopped during the request",
        "raven-node did not answer in time",
        "ipc_transport_missing",
        "is running but is not answering ipc",
        "ipc worker exited",
        "ipc_frame",
        "unexpected ipc",
    ]) {
        Cause::ServiceDown
    } else if has(&["connection refused", "actively refused"]) {
        Cause::NotListening
    } else if has(&[
        "closed the connection during the handshake",
        "early eof",
        "failed to fill whole buffer",
        "connection reset",
        "broken pipe",
        "read timeout",
        "handshake deadline exceeded",
        "did not return an rlb1 bundle",
    ]) {
        Cause::ClosedEarly
    } else if has(&[
        "no answer within",
        "timed out",
        "timeout",
        "cannot connect",
        "connect budget exhausted",
        "no route to host",
        "network is unreachable",
        "host is down",
        "unknown network interface",
        "dial exceeded",
    ]) {
        Cause::NotReachable
    } else {
        Cause::Other
    }
}

/// The address being dialled: the caller's, else the one the daemon names
/// ("cannot connect to 10.0.0.5:7420 (...)"), as ` at <address>` (or nothing).
fn at_dial(ctx: &SendCtx, raw: &str) -> String {
    let named = raw
        .split("cannot connect to ")
        .nth(1)
        .and_then(|rest| rest.split([' ', '(']).next())
        .unwrap_or_default();
    let dial = if ctx.dial.trim().is_empty() {
        named
    } else {
        ctx.dial.trim()
    };
    if dial.is_empty() {
        String::new()
    } else {
        format!(" at {}", sanitize_terminal_line(dial))
    }
}

/// The `(max N bytes)` of the size refusal, in words a reader can use.
fn too_large_sentence(raw: &str) -> String {
    let limit = raw
        .split("(max ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|n| n.parse::<usize>().ok());
    match limit {
        Some(n) => format!(
            "this message is too big to send in one piece (the limit is {n} bytes: about {} \
             Persian or {n} English letters)",
            n / 2
        ),
        None => "this message is too big to send in one piece".into(),
    }
}

fn history_file(ctx: &SendCtx) -> String {
    match &ctx.data_dir {
        Some(dir) => dir.join("chat_history.json").display().to_string(),
        None => "chat_history.json (in your RAVEN data folder)".into(),
    }
}

/// What happened, without a closing period: the caller adds the sentence end.
fn cause_sentence(cause: Cause, ctx: &SendCtx, raw: &str, first_contact: bool) -> String {
    let (who, whose, at) = (ctx.who(), ctx.whose(), at_dial(ctx, raw));
    match cause {
        Cause::NotListening => format!("{whose} computer is there, but RAVEN is not listening{at}"),
        Cause::NotReachable => format!(
            "{who} did not answer{at}: their computer may be off or asleep, on another \
             network, or have a new IP address"
        ),
        Cause::ClosedEarly => format!(
            "something answered{at} but stopped talking or hung up: it may not be RAVEN, or \
             {whose} RAVEN is busy or stuck"
        ),
        Cause::PeerRefused if first_contact => format!(
            "{who} did not accept your first message: most often {who} has not added you as a \
             contact yet (both of you must add each other)"
        ),
        Cause::PeerRefused => format!(
            "{who} accepted the connection but refused it without saying why: {who} may not \
             have you in their contacts, may have lost their connection with you (for \
             example after a reinstall), or {whose} RAVEN could not save the message (their \
             chat history or Keychain), in which case it may already be in their inbox"
        ),
        Cause::WrongIdentity => format!(
            "the computer{at} answered, but it is not {who}: its key is not the one you saved \
             for {who}"
        ),
        Cause::BadAddress if ctx.dial.trim().is_empty() => {
            "the saved address is not a valid IP:PORT".into()
        }
        Cause::BadAddress => format!(
            "the saved address \"{}\" is not a valid IP:PORT",
            sanitize_terminal_line(ctx.dial.trim())
        ),
        Cause::NoAddress => format!("{who} has no network address saved yet"),
        Cause::ServiceDown => {
            "RAVEN's background service (raven-node) on this computer is not answering".into()
        }
        Cause::ServiceStart => {
            "RAVEN's background service (raven-node) could not be started on this computer".into()
        }
        Cause::ServiceSlow if waits_on_keychain(raw) => {
            "RAVEN's background service (raven-node) was started but is still waiting for macOS \
             Keychain access"
                .into()
        }
        Cause::ServiceSlow => {
            "RAVEN's background service (raven-node) was started but has not answered yet".into()
        }
        Cause::HistoryUnreadable => {
            "your local chat history cannot be opened (the file is damaged or its key changed)"
                .into()
        }
        Cause::KeychainDenied => "RAVEN could not open its saved chat key (the system keychain \
             refused access, or the key is missing)"
            .into(),
        Cause::HistoryLocked => "another RAVEN program on this computer is holding your chat \
             history (usually raven-node, waiting for a Keychain answer)"
            .into(),
        Cause::TooLarge => too_large_sentence(raw),
        Cause::BadCharacters => "your message contains characters that cannot be sent (control \
             characters, for example from arrow, Home or End keys)"
            .into(),
        Cause::Blocked => format!("{who} is blocked on this computer"),
        Cause::SendInProgress => {
            format!("another send to {who} is still running (another terminal?)")
        }
        Cause::EmptyMessage => "the message is empty (it has no visible text)".into(),
        Cause::Other => "the send could not be completed".into(),
    }
}

/// True when the service's own words say it waits for a macOS Keychain answer.
fn waits_on_keychain(raw: &str) -> bool {
    raw.to_ascii_lowercase()
        .contains("waiting for macos keychain access")
}

/// The number after `marker` in `raw` (the process id in "... still running as
/// process 123; ...").
fn number_after(raw: &str, marker: &str) -> Option<u32> {
    let rest = raw.split(marker).nth(1)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// What to do about it; empty when there is nothing to add. `raw` is the text the
/// cause was read from (a few causes carry facts in it, such as a process id).
fn next_step(cause: Cause, ctx: &SendCtx, first_contact: bool, raw: &str) -> String {
    let (who, sel) = (ctx.who(), ctx.sel());
    match cause {
        Cause::NotListening => format!(
            "Ask {who} to run `ash listen` and keep it open, then send again. If the address is \
             wrong: ash contact set-dial {sel} --lan-dial IP:PORT."
        ),
        Cause::NotReachable => format!(
            "Check that you are on the same network as {who}. If their IP changed: ash contact \
             set-dial {sel} --lan-dial IP:PORT."
        ),
        Cause::ClosedEarly => format!(
            "Try again in a moment. If it keeps happening, check the address: ash contact \
             set-dial {sel} --lan-dial IP:PORT."
        ),
        Cause::PeerRefused if first_contact => format!(
            "Send {who} your invite line (`ash whoami`) and ask them to add you and to keep \
             `ash listen` running, then send again."
        ),
        Cause::PeerRefused => format!(
            "Send {who} your invite line (`ash whoami`) and ask them to check that you are in \
             their contacts, that `ash listen` is running and that no macOS Keychain window \
             is waiting for them (`ash doctor` shows more). If they already see your message, \
             do not send it again."
        ),
        Cause::WrongIdentity => format!(
            "If {who} reinstalled RAVEN, get their new invite, compare the fingerprint with \
             them by phone or in person, then `ash contact remove {sel}` and add them again. \
             If only their address changed: ash contact set-dial {sel} --lan-dial IP:PORT."
        ),
        Cause::BadAddress => {
            format!("Save a valid one: ash contact set-dial {sel} --lan-dial 192.168.1.20:7420.")
        }
        Cause::NoAddress => format!(
            "Ask {who} to run `ash listen` and tell you the IP:PORT it shows, then save it: ash \
             contact set-dial {sel} --lan-dial IP:PORT."
        ),
        Cause::ServiceDown => {
            "Try again in a moment; if it keeps happening, run `ash doctor`.".into()
        }
        Cause::ServiceStart => {
            "The technical details below say why; fix that and send again.".into()
        }
        Cause::ServiceSlow => {
            let stop = number_after(raw, "is still running as process ")
                .map(|pid| format!(" Or stop it with: {}.", stop_advice(pid)))
                .unwrap_or_default();
            if waits_on_keychain(raw) {
                format!(
                    "If a macOS window asks whether raven-node may use a saved secret, approve \
                     it (choose \"Always Allow\"; the window can be hidden behind other \
                     windows), then send again.{stop}"
                )
            } else {
                format!(
                    "Wait a moment and send again; if it keeps happening, run `ash \
                     doctor`.{stop}"
                )
            }
        }
        Cause::HistoryUnreadable => format!(
            "Your keys and contacts are not affected. Quit ash, move {} aside (keep it if you \
             may want to recover it), then try again: the history starts empty.",
            history_file(ctx)
        ),
        Cause::KeychainDenied => {
            "On a Mac, approve the Keychain window when it asks (Always Allow), then send again."
                .into()
        }
        Cause::HistoryLocked => "Answer any macOS Keychain window (Always Allow), then send \
             again. The service log (raven-node-service.log in your RAVEN data folder) says \
             what it is waiting for."
            .into(),
        Cause::TooLarge => "Shorten it or split it into several messages.".into(),
        Cause::BadCharacters => "Retype it with plain text only; arrow keys do not edit inside \
             this prompt, use Backspace."
            .into(),
        Cause::Blocked => unblock_hint(ctx),
        Cause::SendInProgress => "Wait a moment, then send again.".into(),
        Cause::EmptyMessage => "Type some text and send again.".into(),
        Cause::Other => String::new(),
    }
}

/// The undo for a block. `ash contact unblock` takes the key itself.
fn unblock_hint(ctx: &SendCtx) -> String {
    if ctx.pub_hex.is_empty() {
        "To undo: ash contact unblock --pub-hex <their key>".into()
    } else {
        format!("To undo: ash contact unblock --pub-hex {}", ctx.pub_hex)
    }
}

/// `"the first 30 characters…"` of a message for outcome lines, or nothing.
pub(crate) fn quoted_preview(text: &str) -> String {
    let line = sanitize_terminal_line(text.trim());
    if line.is_empty() {
        return String::new();
    }
    let mut shown: String = line.chars().take(30).collect();
    if line.chars().count() > 30 {
        shown.push('…');
    }
    format!("\"{shown}\"")
}

/// ` "preview"` (with a leading space), or nothing.
fn spaced(preview: &str) -> String {
    if preview.is_empty() {
        String::new()
    } else {
        format!(" {preview}")
    }
}

fn join_sentences(parts: &[String]) -> String {
    parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Start of the "queued locally" outcome (see [`queued_text`]).
pub(crate) const QUEUED_PREFIX: &str = "not delivered yet";
/// Start of the "sent but unconfirmed" outcome (see [`unconfirmed_text`]).
pub(crate) const UNCONFIRMED_PREFIX: &str = "sent, delivery unconfirmed";

/// True for text that already is a finished outcome line.
fn is_outcome_text(text: &str) -> bool {
    text.starts_with("NOT SENT")
        || text.starts_with(QUEUED_PREFIX)
        || text.starts_with(UNCONFIRMED_PREFIX)
        || text.starts_with("send refused: ")
}

/// NOT SENT: the message was refused before anything of it was queued.
/// `first_contact`: no session with the peer exists yet, so it could not wait
/// for the peer to come online either.
fn not_sent_for(cause: Cause, ctx: &SendCtx, raw: &str, first_contact: bool) -> String {
    let nothing_queued = if first_contact
        && matches!(
            cause,
            Cause::NotListening | Cause::NotReachable | Cause::ClosedEarly
        ) {
        format!(
            "Nothing was queued: a first message needs {} to be online.",
            ctx.who()
        )
    } else {
        "Nothing was queued.".into()
    };
    join_sentences(&[
        format!(
            "NOT SENT: {}.",
            cause_sentence(cause, ctx, raw, first_contact)
        ),
        nothing_queued,
        next_step(cause, ctx, first_contact, raw),
        format!("(technical: {raw})"),
    ])
}

/// [`not_sent_for`] with the cause read from the raw text.
pub(crate) fn not_sent_text(ctx: &SendCtx, raw: &str, first_contact: bool) -> String {
    not_sent_for(classify_cause(raw), ctx, raw, first_contact)
}

/// [`next_step`] for a message that is already queued: advice that ends in "then
/// send again" must not invite retyping it (the retry would deliver both copies).
fn next_step_queued(cause: Cause, ctx: &SendCtx, raw: &str) -> String {
    let step = next_step(cause, ctx, false, raw)
        .replace(", then send again.", ".")
        .replace("Try again in a moment. ", "");
    join_sentences(&[
        step,
        format!(
            "Do not retype this message: it goes out with your next send to {}.",
            ctx.who()
        ),
    ])
}

/// The message is durably queued here but its dial failed. The retry only works
/// while the sealed envelope is valid, so say for how long, and that nothing
/// retries it in the background.
pub(crate) fn queued_text(ctx: &SendCtx, raw: &str, preview: &str, minutes: u64) -> String {
    let cause = classify_cause(raw);
    let who = ctx.who();
    join_sentences(&[
        format!(
            "{QUEUED_PREFIX}: your message{} to {who} is queued locally because {}.",
            spaced(preview),
            cause_sentence(cause, ctx, raw, false)
        ),
        format!(
            "It is NOT retried automatically: it is sent when you next send {who} a message, \
             within {minutes} minutes; after that it expires and is marked failed."
        ),
        next_step_queued(cause, ctx, raw),
        format!("(technical: {raw})"),
    ])
}

/// The peer's acknowledgement came back (it holds the message) but this computer
/// could not finish recording that, so the text must not be retyped.
pub(crate) fn recorded_locally_failed_text(
    ctx: &SendCtx,
    raw: &str,
    preview: &str,
    minutes: u64,
) -> String {
    let (who, whose) = (ctx.who(), ctx.whose());
    let cause = classify_cause(raw);
    let local = matches!(
        cause,
        Cause::HistoryUnreadable | Cause::KeychainDenied | Cause::HistoryLocked
    );
    join_sentences(&[
        format!(
            "{UNCONFIRMED_PREFIX}: your message{} reached {whose} computer and an \
             acknowledgement came back, but {}.",
            spaced(preview),
            if local {
                cause_sentence(cause, ctx, raw, false)
            } else {
                "this computer could not finish recording it".to_string()
            }
        ),
        format!(
            "Do not retype it: fix the problem below, and your next send to {who} finishes the \
             record (within {minutes} minutes)."
        ),
        if local {
            next_step(cause, ctx, false, raw)
        } else {
            String::new()
        },
        format!("(technical: {raw})"),
    ])
}

/// The new message's frames were written and only its ACK is missing: the peer
/// may already hold it, so it must not be retyped.
pub(crate) fn unconfirmed_text(ctx: &SendCtx, raw: &str, preview: &str, minutes: u64) -> String {
    let (who, whose) = (ctx.who(), ctx.whose());
    join_sentences(&[
        format!(
            "{UNCONFIRMED_PREFIX}: your message{} was sent to {whose} computer, but {who} has \
             not confirmed it yet ({who}'s RAVEN may be unable to save it, or {who} may have \
             removed or blocked you).",
            spaced(preview)
        ),
        format!(
            "Do not retype it: it stays queued, and your next send to {who} tries again, \
             within {minutes} minutes."
        ),
        format!("(technical: {raw})"),
    ])
}

/// An earlier message to the peer is still undelivered, so this one was not
/// queued behind it (the store keeps one outstanding message per peer).
pub(crate) fn earlier_undelivered_text(
    ctx: &SendCtx,
    raw: &str,
    preview: &str,
    minutes: u64,
) -> String {
    let cause = classify_cause(raw);
    let who = ctx.who();
    join_sentences(&[
        format!(
            "NOT SENT: an earlier message{} to {who} is still undelivered ({}), so this message \
             was not queued behind it.",
            spaced(preview),
            cause_sentence(cause, ctx, raw, false)
        ),
        next_step(cause, ctx, false, raw),
        format!(
            "Then send this message again: the earlier one goes first, within its {minutes} \
             minutes."
        ),
        format!("(technical: {raw})"),
    ])
}

/// An earlier message was sent again but its ACK has not come, so this one was
/// not queued. Unlike a refusal its frames *were* written.
pub(crate) fn earlier_unconfirmed_text(ctx: &SendCtx, preview: &str) -> String {
    let who = ctx.who();
    format!(
        "NOT SENT: an earlier message{} to {who} was sent again, but {who} has not confirmed \
         it yet (it may already have arrived), so this message was not queued. Wait a moment, \
         then send again.",
        spaced(preview)
    )
}

/// Plain-words text for a failed send. `raw` is whatever the send path
/// returned (a daemon or OS error, or one of the outcome texts below, which pass
/// through unchanged); `who` is the contact's name, empty when unknown.
///
/// The result starts with the outcome (`NOT SENT: ...`, `not delivered yet: ...
/// queued locally ...`, `sent, delivery unconfirmed: ...`; anything it does not
/// understand keeps the old `send refused: ...` form), names the person, gives the
/// next step, and keeps the raw text at the end as `(technical: ...)`. One line,
/// no newline of its own: callers that sanitize to a single line stay readable.
pub(crate) fn friendly_send_error(raw: &str, who: &str) -> String {
    let raw = raw.trim();
    translate_known(raw, &SendCtx::named(who)).unwrap_or_else(|| {
        if is_outcome_text(raw) {
            raw.to_string()
        } else {
            format!("send refused: {raw}")
        }
    })
}

/// [`friendly_send_error`] for text the send path itself returns: `None` for text
/// that is already an outcome line, or that no sentence covers (a gate text such
/// as `INTERNET_DIRECT_HOLD` or an `ATSAM_*` code must reach callers untouched).
fn translate_known(raw: &str, ctx: &SendCtx) -> Option<String> {
    let raw = raw.trim();
    if is_outcome_text(raw) {
        return None;
    }
    match classify_cause(raw) {
        Cause::Other => None,
        cause => Some(not_sent_for(cause, ctx, raw, false)),
    }
}

/// Technical delivery lines (message id, carrier) in the default output:
/// `RAVEN_VERBOSE=1` (or `ASH_VERBOSE=1`).
pub(crate) fn verbose() -> bool {
    verbose_with(|name| std::env::var_os(name))
}

fn verbose_with(get: impl Fn(&str) -> Option<std::ffi::OsString>) -> bool {
    ["RAVEN_VERBOSE", "ASH_VERBOSE"]
        .iter()
        .any(|name| get(name).is_some_and(|v| !v.is_empty() && v != "0"))
}

impl SendCtx {
    fn first_contact_line(&self) -> String {
        if self.chat {
            format!(
                "  {C_DIM}(secure connection with {} set up){C_RESET}",
                self.who()
            )
        } else {
            format!(
                "{C_DIM}First time talking to {}: secure connection set up.{C_RESET}",
                self.who()
            )
        }
    }

    /// `status delivered` stays the first words of the line: scripts and the iOS
    /// gate look for exactly that, and only a verified ACK may print it. The chat
    /// shows its own transcript line instead.
    fn delivered_line(&self) -> Option<String> {
        (!self.chat).then(|| {
            format!(
                "{C_GREEN}status{C_RESET} delivered — {} confirmed receipt",
                self.who()
            )
        })
    }

    /// The lab Internet carrier is evidence-driven (`carrier=internet_dial` is
    /// asserted by its smoke script); everyone else sees this on request.
    fn delivery_detail_line(&self, carrier: &str, mid: &[u8; 16], verbose: bool) -> Option<String> {
        (verbose || carrier == "internet_dial").then(|| {
            format!(
                "{C_DIM}message {}… via carrier={carrier} peer={}{C_RESET}",
                hex::encode(&mid[..4]),
                sanitize_terminal_line(&self.dial)
            )
        })
    }

    fn earlier_delivered_line(&self, preview: &str) -> String {
        if self.chat {
            format!(
                "  {C_GREEN}✓{C_RESET} your earlier message{} to {} has now arrived",
                spaced(preview),
                self.who()
            )
        } else {
            format!(
                "{C_GREEN}status{C_RESET} delivered — your earlier message{} to {} has now \
                 arrived and {} confirmed it",
                spaced(preview),
                self.who(),
                self.who()
            )
        }
    }

    fn earlier_failed_line(&self, preview: &str, why: &str) -> String {
        format!(
            "{C_BOLD}status{C_RESET} failed: your earlier message{} to {}: {why}",
            spaced(preview),
            self.who()
        )
    }

    /// First message to this peer: a session had to be set up first.
    pub(crate) fn say_first_contact(&self) {
        println!("{}", self.first_contact_line());
    }

    /// The new message was acknowledged by the receiver (its sealed ACK verified).
    pub(crate) fn say_delivered(&self, carrier: &str, mid: &[u8; 16]) {
        if let Some(line) = self.delivered_line() {
            println!("{line}");
        }
        if let Some(line) = self.delivery_detail_line(carrier, mid, verbose()) {
            println!("{line}");
        }
    }

    /// An earlier, queued message was delivered by this send's retry.
    pub(crate) fn say_earlier_delivered(&self, preview: &str) {
        println!("{}", self.earlier_delivered_line(preview));
    }

    /// An earlier, queued message was given up on. A failure: stderr.
    pub(crate) fn say_earlier_failed(&self, preview: &str, why: &str) {
        eprintln!("{}", self.earlier_failed_line(preview, why));
    }
}

/// Prints one stderr line when the work it guards runs longer than `after`, and
/// only when stderr is a terminal: a pipe or a log keeps exactly the output it
/// had. Dropping it ends the wait (and joins the helper thread).
pub(crate) struct SlowNote {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// How long a send runs before it says it is working.
const SLOW_NOTE_AFTER: Duration = Duration::from_secs(1);

impl SlowNote {
    pub(crate) fn start(message: String) -> Self {
        Self::start_with(
            message,
            SLOW_NOTE_AFTER,
            io::stderr().is_terminal(),
            Box::new(|m| eprintln!("{C_DIM}{m}{C_RESET}")),
        )
    }

    fn start_with(
        message: String,
        after: Duration,
        enabled: bool,
        emit: Box<dyn Fn(&str) + Send>,
    ) -> Self {
        if !enabled {
            return Self {
                stop: None,
                thread: None,
            };
        }
        let (stop, rx) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("ash-slow-note".into())
            .spawn(move || {
                // A sender that is dropped wakes this at once (`Disconnected`):
                // only a full timeout means the work is still running.
                if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = rx.recv_timeout(after) {
                    emit(&message);
                }
            })
            .ok();
        Self {
            stop: Some(stop),
            thread,
        }
    }
}

impl Drop for SlowNote {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ── Secure send (seal in ash → IPC enqueue; never argv plaintext) ─────────

pub fn refuse_argv_plaintext() {
    eprintln!("{C_PURPLE}REFUSE{C_RESET}: plaintext on argv is forbidden (visible via ps).");
    eprintln!(
        "{C_DIM}use:{C_RESET} echo \"hello\" | ash send --contact @alice   # the message goes on stdin"
    );
    eprintln!("{C_DIM} or:{C_RESET} ash send --contact @alice < message.txt");
    eprintln!(
        "{C_DIM} or:{C_RESET} ash send --peer … --peer-pub-hex …   # then type message on stdin"
    );
    std::process::exit(2);
}

/// Lab Test A send: PairInit LAN OOB → PairResponse → IndexedSessionStore envelope.
/// Never uses public-key-derived seal_message / unsafe-demo-crypto.
///
/// The `Err` text is already the user's sentence (see [`friendly_send_error`]): the
/// contact is named by `petname` / `tag`, or looked up from `peer_pub_hex`.
#[allow(clippy::too_many_arguments)]
pub fn run_send_secure(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    text: &str,
    petname: &str,
    tag: &str,
) -> Result<(), String> {
    let ctx = send_ctx(data_dir, petname, tag, peer_pub_hex);
    send_with(
        data_dir,
        id,
        peer,
        peer_pub_hex,
        listen,
        text,
        &ctx,
        super::pair_init_lab::DialCarrier::Lan,
    )
}

/// Same as [`run_send_secure`] on a named carrier (`lan` or lab `internet`).
#[allow(clippy::too_many_arguments)]
pub fn run_send_secure_on(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    text: &str,
    petname: &str,
    tag: &str,
    carrier: super::pair_init_lab::DialCarrier,
) -> Result<(), String> {
    let ctx = send_ctx(data_dir, petname, tag, peer_pub_hex);
    send_with(
        data_dir,
        id,
        peer,
        peer_pub_hex,
        listen,
        text,
        &ctx,
        carrier,
    )
}

/// One send, whatever the carrier: every error that leaves it is the user's
/// sentence where one exists. Text no sentence covers (the `INTERNET_DIRECT_HOLD`
/// gate, `ATSAM_*` codes, the FastAPI refusal) is returned untouched.
#[allow(clippy::too_many_arguments)]
fn send_with(
    data_dir: &Path,
    id: &Identity,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    text: &str,
    ctx: &SendCtx,
    carrier: super::pair_init_lab::DialCarrier,
) -> Result<(), String> {
    use super::pair_init_lab::DialCarrier;
    // LAN may fall back to the listen address; the lab Internet carrier dials
    // `peer` only.
    let dial = match carrier {
        DialCarrier::Lan if !looks_like_host_port(peer) && looks_like_host_port(listen) => listen,
        _ => peer,
    };
    let ctx = SendCtx {
        dial: dial.trim().to_string(),
        ..ctx.clone()
    };
    deliver(data_dir, id, dial, peer_pub_hex, text, &ctx, carrier)
        .map_err(|e| translate_known(&e, &ctx).unwrap_or(e))
}

fn deliver(
    data_dir: &Path,
    id: &Identity,
    dial: &str,
    peer_pub_hex: &str,
    text: &str,
    ctx: &SendCtx,
    carrier: super::pair_init_lab::DialCarrier,
) -> Result<(), String> {
    use super::pair_init_lab::DialCarrier;
    let path = resolve_terminal_messaging_path();
    assert_no_silent_fastapi(path)?;
    let blocks = BlockList::load_checked(data_dir)?;
    if blocks.is_blocked(peer_pub_hex) {
        return Err("peer is on the local block list".into());
    }
    let _peer_pub = parse_pub_hex(peer_pub_hex)?;
    if text.trim().is_empty() {
        return Err("message is empty".into());
    }
    if !looks_like_host_port(dial) {
        return Err(format!(
            "valid {} host:port required — refusing LocalListenQueue / 127.0.0.1:0 fallback",
            carrier.label()
        ));
    }
    // The Internet carrier has its own (stricter) gate than LAN: refuse here,
    // before ensure_mac_lan_daemon changes this machine's listening state.
    if carrier == DialCarrier::Internet && !raven_core::internet_direct_live_enabled() {
        return Err(super::pair_init_lab::INTERNET_DIRECT_HOLD.into());
    }

    let mut message_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut message_id);
    let mid_prefix = hex::encode(&message_id[..4]);

    if !super::trace_delivery::live_pair_init_outbound_ready() {
        let status = super::trace_delivery::production_gate_status();
        if carrier == DialCarrier::Lan {
            super::trace_delivery::trace_event(
                "ash/ext.rs:run_send_secure",
                "TRACE_SEND_BLOCKED",
                status,
                Some(&mid_prefix),
                Some("no_live_pair_init_or_indexed_session_callsite"),
            );
            eprintln!("{C_PURPLE}status{C_RESET} {status}");
            eprintln!(
                "{C_DIM}EN:{C_RESET} Message not sent — set RAVEN_LAB_TEST_A=1 (debug) after wiring, or wait for production gates."
            );
            eprintln!(
                "{C_DIM}FA:{C_RESET} پیام ارسال نشد؛ تا PairInit و session واقعی فعال نشوند صف ساختگی باز نمی‌شود."
            );
        }
        return Err(status.into());
    }

    require_local_daemon(data_dir)?;
    if carrier == DialCarrier::Lan {
        super::trace_delivery::trace_event(
            "ash/ext.rs:run_send_secure",
            "TRACE_SEND_LAB_PAIR_INIT",
            super::trace_delivery::production_gate_status(),
            Some(&mid_prefix),
            Some("pair_init_lab"),
        );
    }
    // The network part: on a terminal, say so when it takes more than a second.
    let _working = SlowNote::start(format!(
        "sending to {} at {} ...",
        ctx.who(),
        sanitize_terminal_line(dial)
    ));
    super::pair_init_lab::run_pair_init_and_send_on(
        data_dir,
        id,
        dial,
        peer_pub_hex,
        text,
        carrier,
        ctx,
    )
}

/// The send path dials through the local raven-node service: refuse with the
/// reason when it is not running and cannot be started. A service that runs but
/// does not answer is reported as that, in its own words (they already say what to
/// do), not wrapped in "could not be started": that would be the opposite of the
/// truth.
fn require_local_daemon(data_dir: &Path) -> Result<(), String> {
    ensure_mac_lan_daemon(data_dir).map_err(|e| {
        if e.starts_with(SERVICE_UNRESPONSIVE_PREFIX) {
            format!("NOT SENT, nothing queued: {e}")
        } else {
            format!("local raven-node service is not running and could not be started: {e}")
        }
    })
}

// ── Chat session with slash commands ──────────────────────────────────────

/// Position in a peer's endpoint inbox. The derived order is the SQL order of
/// `list_endpoint_inbox_for_sender_after`: `(received_at_ms, message_id)`, with
/// "no message id" below every id.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
struct InboxCursor {
    received_at_ms: u64,
    message_id: Option<[u8; 16]>,
}

const CHAT_INBOX_POLL_LIMIT: usize = 8;
const CHAT_PENDING_MAX: usize = 64;

/// One inbox row ready to print, with its id so a row the chat already showed
/// (as part of the history dump) is not shown a second time.
#[derive(Clone)]
struct InboxLine {
    message_id: [u8; 16],
    text: String,
}

#[derive(Clone)]
struct PendingInboxBatch {
    lines: Vec<InboxLine>,
    cursor_after: InboxCursor,
}

#[derive(Default)]
struct ChatPendingQueue {
    batches: Vec<PendingInboxBatch>,
    /// Latest inbox error only — never competes with message slots.
    last_error: Option<String>,
    /// At most one batch waiting while the display queue is full.
    deferred: Option<PendingInboxBatch>,
    /// "New message" notice already shown for what is queued; cleared when the
    /// queue is drained, so one burst of messages gives one notice.
    notified: bool,
}

/// Print the rows of `batch` the chat has not shown yet and remember them. A
/// row is skipped only if it was *actually printed* (history dump or an earlier
/// batch): existence in the history is not enough, because the poller persists a
/// row to history before it is displayed.
fn print_unseen_lines(batch: &PendingInboxBatch, shown: &mut std::collections::HashSet<[u8; 16]>) {
    for line in unseen_lines(batch, shown) {
        println!("{}", line.text);
    }
}

/// The rows of `batch` not in `shown`, which are added to it.
fn unseen_lines<'a>(
    batch: &'a PendingInboxBatch,
    shown: &mut std::collections::HashSet<[u8; 16]>,
) -> Vec<&'a InboxLine> {
    batch
        .lines
        .iter()
        .filter(|line| shown.insert(line.message_id))
        .collect()
}

fn chat_inbox_cursors_path(data_dir: &Path) -> PathBuf {
    data_dir.join("chat_inbox_cursors.json")
}

#[derive(Debug)]
enum CursorMapError {
    Missing,
    Io(String),
    Corrupt(String),
}

fn load_cursor_map(
    data_dir: &Path,
) -> Result<serde_json::Map<String, serde_json::Value>, CursorMapError> {
    let path = chat_inbox_cursors_path(data_dir);
    match std::fs::read_to_string(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(CursorMapError::Missing),
        Err(e) => Err(CursorMapError::Io(e.to_string())),
        Ok(raw) => {
            let value: serde_json::Value =
                serde_json::from_str(&raw).map_err(|e| CursorMapError::Corrupt(e.to_string()))?;
            let serde_json::Value::Object(map) = value else {
                return Err(CursorMapError::Corrupt(
                    "chat_inbox_cursors.json root must be an object".into(),
                ));
            };
            Ok(map)
        }
    }
}

fn parse_cursor_entry(entry: &serde_json::Value) -> Result<InboxCursor, String> {
    let obj = entry
        .as_object()
        .ok_or_else(|| "cursor entry must be an object".to_string())?;
    let received_at_ms = obj
        .get("received_at_ms")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "cursor entry missing received_at_ms".to_string())?;
    let message_id = match obj.get("message_id_hex") {
        None => None,
        Some(serde_json::Value::Null) => None,
        Some(v) => {
            let hex_s = v
                .as_str()
                .ok_or_else(|| "cursor message_id_hex must be a string".to_string())?;
            let bytes = hex::decode(hex_s).map_err(|e| format!("cursor message_id_hex: {e}"))?;
            if bytes.len() != 16 {
                return Err("cursor message_id_hex must be 16 bytes".into());
            }
            let mut id = [0u8; 16];
            id.copy_from_slice(&bytes);
            Some(id)
        }
    };
    Ok(InboxCursor {
        received_at_ms,
        message_id,
    })
}

fn load_durable_inbox_cursor(data_dir: &Path, contact_pub: &str) -> Result<InboxCursor, String> {
    match load_cursor_map(data_dir) {
        Err(CursorMapError::Missing) => Ok(InboxCursor::default()),
        Err(CursorMapError::Io(e)) => Err(format!("inbox cursor read failed: {e}")),
        Err(CursorMapError::Corrupt(e)) => Err(format!("inbox cursor corrupt: {e}")),
        Ok(map) => {
            let want = contact_pub.trim().to_lowercase();
            match map.get(&want) {
                None => Ok(InboxCursor::default()),
                Some(entry) => parse_cursor_entry(entry),
            }
        }
    }
}

fn save_durable_inbox_cursor(
    data_dir: &Path,
    contact_pub: &str,
    cursor: &InboxCursor,
) -> Result<(), String> {
    let path = chat_inbox_cursors_path(data_dir);
    let _lock = raven_core::DataDirLock::acquire(data_dir, ".chat_inbox_cursors.lock.sqlite")?;
    let mut map = match load_cursor_map(data_dir) {
        Ok(map) => map,
        Err(CursorMapError::Missing) => serde_json::Map::new(),
        Err(CursorMapError::Io(e)) => return Err(format!("inbox cursor read failed: {e}")),
        Err(CursorMapError::Corrupt(e)) => {
            return Err(format!("inbox cursor corrupt (refusing overwrite): {e}"));
        }
    };
    let mut entry = serde_json::Map::new();
    entry.insert(
        "received_at_ms".into(),
        serde_json::Value::from(cursor.received_at_ms),
    );
    if let Some(id) = cursor.message_id {
        entry.insert(
            "message_id_hex".into(),
            serde_json::Value::String(hex::encode(id)),
        );
    }
    map.insert(
        contact_pub.trim().to_lowercase(),
        serde_json::Value::Object(entry),
    );
    let json =
        serde_json::to_vec_pretty(&serde_json::Value::Object(map)).map_err(|e| e.to_string())?;
    raven_core::atomic_write_private(&path, &json)
}

fn compute_inbox_tombstone(data_dir: &Path, contact_pub: &str) -> Result<InboxCursor, String> {
    let peer = parse_pub_hex(contact_pub)?;
    let mut store =
        raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let mut cursor = InboxCursor::default();
    loop {
        let rows = store
            .list_endpoint_inbox_for_sender_after(
                &peer,
                cursor.received_at_ms,
                cursor.message_id.as_ref(),
                CHAT_INBOX_POLL_LIMIT,
            )
            .map_err(|e| e.redacted_display())?;
        if rows.is_empty() {
            break;
        }
        for row in rows {
            cursor.received_at_ms = row.received_at_ms;
            cursor.message_id = Some(row.message_id);
        }
    }
    Ok(cursor)
}

fn advance_inbox_cursor_past_peer(
    data_dir: &Path,
    contact_pub: &str,
) -> Result<InboxCursor, String> {
    let cursor = compute_inbox_tombstone(data_dir, contact_pub)?;
    save_durable_inbox_cursor(data_dir, contact_pub, &cursor)?;
    Ok(cursor)
}

/// Tombstone inbox first, then clear history — crash between leaves history
/// intact under an advanced cursor (no inbox rebuild). Never clear-then-tombstone.
fn clear_peer_history_with_tombstone(
    data_dir: &Path,
    contact_pub: &str,
) -> Result<InboxCursor, String> {
    let cursor = compute_inbox_tombstone(data_dir, contact_pub)?;
    save_durable_inbox_cursor(data_dir, contact_pub, &cursor)?;
    ChatHistory::clear_peer_persisted(data_dir, contact_pub).map_err(|e| e.to_string())?;
    Ok(cursor)
}

fn peek_endpoint_inbox_for_contact(
    data_dir: &Path,
    contact_pub: &str,
    cursor: &InboxCursor,
) -> Result<Option<PendingInboxBatch>, String> {
    let peer = parse_pub_hex(contact_pub)?;
    let mut store =
        raven_core::IndexedSessionStore::open(data_dir).map_err(|e| e.redacted_display())?;
    let rows = store
        .list_endpoint_inbox_for_sender_after(
            &peer,
            cursor.received_at_ms,
            cursor.message_id.as_ref(),
            CHAT_INBOX_POLL_LIMIT,
        )
        .map_err(|e| e.redacted_display())?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut lines = Vec::new();
    let mut cursor_after = *cursor;
    for row in rows {
        cursor_after.received_at_ms = row.received_at_ms;
        cursor_after.message_id = Some(row.message_id);
        let preview = String::from_utf8_lossy(&row.plaintext);
        raven_core::persist_lan_chat_history(
            data_dir,
            "in",
            &peer,
            &row.message_id,
            row.created_at_ms,
            "received",
            &row.plaintext,
        )?;
        lines.push(InboxLine {
            message_id: row.message_id,
            text: format!(
                "  ← {C_DIM}{}{C_RESET} {}",
                hex::encode(&row.message_id[..4]),
                sanitize_terminal_line(&preview)
            ),
        });
    }
    Ok(Some(PendingInboxBatch {
        lines,
        cursor_after,
    }))
}

fn chat_queue_blocks_poll(pending: &std::sync::Mutex<ChatPendingQueue>) -> bool {
    let Ok(q) = pending.lock() else {
        return true;
    };
    q.batches.len() >= CHAT_PENDING_MAX || q.deferred.is_some()
}

/// Queue a batch for the main thread. `true` when the caller should show the
/// "new message" notice: the first batch since the queue was last drained.
fn push_chat_batch(pending: &std::sync::Mutex<ChatPendingQueue>, batch: PendingInboxBatch) -> bool {
    let Ok(mut q) = pending.lock() else {
        return false;
    };
    if q.batches.len() >= CHAT_PENDING_MAX {
        // Keep exactly one deferred batch; do not re-peek/re-persist in a hot loop.
        if q.deferred.is_none() {
            q.deferred = Some(batch);
        }
    } else {
        q.batches.push(batch);
    }
    !std::mem::replace(&mut q.notified, true)
}

fn set_chat_pending_error(pending: &std::sync::Mutex<ChatPendingQueue>, err: String) {
    if let Ok(mut q) = pending.lock() {
        q.last_error = Some(err);
    }
}

fn poll_cursor_with_pending(
    pending: &std::sync::Mutex<ChatPendingQueue>,
    shared: InboxCursor,
) -> InboxCursor {
    let Ok(q) = pending.lock() else {
        return shared;
    };
    q.batches.last().map(|b| b.cursor_after).unwrap_or(shared)
}

/// Drop everything queued but not yet printed. After `/clear-local-history`
/// those rows are older than the tombstone and must never be shown.
fn discard_chat_pending(pending: &std::sync::Mutex<ChatPendingQueue>) {
    if let Ok(mut q) = pending.lock() {
        q.batches.clear();
        q.deferred = None;
        q.last_error = None;
        q.notified = false;
    }
}

/// Print queued batches in order and advance the durable cursor. Forward-only:
/// a batch at or behind the cursor was already shown (or cleared), so it is
/// skipped rather than printed twice or moving the cursor backwards.
fn drain_chat_pending(
    data_dir: &Path,
    contact_pub: &str,
    pending: &std::sync::Mutex<ChatPendingQueue>,
    cursor: &mut InboxCursor,
    shown: &mut std::collections::HashSet<[u8; 16]>,
) {
    let Ok(mut q) = pending.lock() else {
        return;
    };
    if let Some(err) = q.last_error.take() {
        eprintln!("{}", inbox_problem_text(&err, data_dir));
    }
    let mut batches = std::mem::take(&mut q.batches);
    if let Some(deferred) = q.deferred.take() {
        batches.push(deferred);
    }
    q.notified = false;
    drop(q);
    let before = *cursor;
    for batch in batches {
        if batch.cursor_after <= *cursor {
            continue;
        }
        print_unseen_lines(&batch, shown);
        *cursor = batch.cursor_after;
    }
    if *cursor != before {
        if let Err(e) = save_durable_inbox_cursor(data_dir, contact_pub, cursor) {
            eprintln!("inbox cursor save failed: {e}");
        }
    }
}

/// How long the chat's "is my receiver running?" check may take: it is read-only
/// (it never starts the service) and must not delay a chat that ends at once.
const CHAT_RECEIVER_PROBE: Duration = Duration::from_millis(500);

/// Whether this computer can receive messages right now, as the local service
/// itself reports it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ReceiverState {
    /// The service runs and its LAN listener is up.
    Receiving,
    /// The service runs but its LAN listener is not up (busy port, or started
    /// outbound-only): sending works, nothing can arrive.
    NotReceiving,
    /// No service for this profile.
    NotRunning,
    /// Something owns the endpoint but does not answer in time (stuck or busy).
    NotAnswering,
}

fn classify_receiver(status: &Result<IpcResponse, String>) -> ReceiverState {
    match (listener_reported(status), status) {
        (Some(true), _) => ReceiverState::Receiving,
        (Some(false), _) => ReceiverState::NotReceiving,
        (None, Err(e)) if super::ipc_client::error_means_not_running(e) => {
            ReceiverState::NotRunning
        }
        (None, _) => ReceiverState::NotAnswering,
    }
}

/// Ask the local service (one Status, bounded by `wait`) whether this computer is
/// receiving. Read-only: it never starts the service, so it is safe for the inbox,
/// the status screen and the menu as well as the chat.
pub(crate) fn receiver_state(data_dir: &Path, wait: Duration) -> ReceiverState {
    classify_receiver(&super::ipc_client::ipc_request_timeout(
        data_dir,
        &IpcRequest::Status { v: IPC_VERSION },
        wait,
    ))
}

/// The chat's one-time heads-up (stderr) when replies cannot arrive.
fn chat_receiver_note(state: ReceiverState, name: &str) -> Option<String> {
    match state {
        ReceiverState::Receiving => None,
        ReceiverState::NotRunning => Some(format!(
            "{C_PURPLE}note{C_RESET}: raven-node is not running, so replies from {name} cannot \
             arrive yet. It starts when you send a message here, or run `ash listen` in another \
             terminal."
        )),
        ReceiverState::NotReceiving => Some(format!(
            "{C_PURPLE}warning{C_RESET}: this computer is NOT receiving messages: raven-node runs, \
             but its LAN listener is down (a busy port, or started outbound-only), so replies \
             from {name} cannot arrive. See raven-node-service.log in your RAVEN data folder, or \
             run `ash doctor`."
        )),
        ReceiverState::NotAnswering => Some(format!(
            "{C_PURPLE}note{C_RESET}: raven-node is running but not answering, so replies from \
             {name} may not arrive. Run `ash doctor` for details."
        )),
    }
}

/// What the chat calls the other person: petname, else `@tag`, else a short
/// fingerprint (never 64 hex digits).
fn chat_name(petname: &str, tag: &str, contact_pub: &str) -> String {
    let petname = sanitize_terminal_line(petname.trim());
    if !petname.is_empty() {
        return petname;
    }
    let tag = sanitize_terminal_line(tag.trim().trim_start_matches('@'));
    if !tag.is_empty() {
        return format!("@{tag}");
    }
    match parse_pub_hex(contact_pub) {
        Ok(key) => format!("device {}", device_fingerprint_v1(&key)),
        Err(_) => "this contact".into(),
    }
}

fn chat_header(name: &str, tag: &str) -> String {
    let tag = sanitize_terminal_line(tag.trim().trim_start_matches('@'));
    let tag = if tag.is_empty() || name == format!("@{tag}") {
        String::new()
    } else {
        format!(" @{tag}")
    };
    format!("{C_BOLD}chat with{C_RESET} {name}{tag}")
}

/// What one line typed in the chat means.
#[derive(Debug, PartialEq, Eq)]
enum ChatInput<'a> {
    Empty,
    /// Text for the other person.
    Send(&'a str),
    /// `/help`, or the bare word `help` / `?` (`bare`).
    Help {
        bare: bool,
    },
    /// `/back`, `/quit`, `/q`, `/exit`, or the bare words `exit` / `quit` (`bare`).
    Leave {
        bare: bool,
    },
    /// Any other `/command`.
    Command(&'a str),
}

/// `help`, `?`, `exit` and `quit` typed on their own are the chat's commands, not
/// a message: nobody opens a chat to send their friend the word "quit", and
/// sending it by mistake cannot be taken back. Add a character to send the word.
fn classify_chat_input(line: &str) -> ChatInput<'_> {
    let line = line.trim();
    if line.is_empty() {
        return ChatInput::Empty;
    }
    if line.starts_with('/') {
        return match line.split_whitespace().next().unwrap_or("") {
            "/help" | "/?" => ChatInput::Help { bare: false },
            "/back" | "/quit" | "/q" | "/exit" => ChatInput::Leave { bare: false },
            other => ChatInput::Command(other),
        };
    }
    match line.to_lowercase().as_str() {
        "help" | "?" => ChatInput::Help { bare: true },
        "exit" | "quit" => ChatInput::Leave { bare: true },
        _ => ChatInput::Send(line),
    }
}

fn chat_help_lines(name: &str, tag: &str) -> Vec<String> {
    let tag = sanitize_terminal_line(tag.trim().trim_start_matches('@'));
    let file_send = if tag.is_empty() {
        "ash send --contact @tag < message.txt".to_string()
    } else {
        format!("ash send --contact @{tag} < message.txt")
    };
    vec![
        format!("  Type a message and press Enter to send it to {name}."),
        "  /help      this list".into(),
        "  /back      leave the chat (also /quit, exit, quit, or Ctrl-D)".into(),
        format!("  /info      who {name} is (name, tag, key, address)"),
        format!("  /verify    the fingerprint to compare with {name} by phone or in person"),
        format!("  /block     stop all messages to and from {name} (asks first)"),
        "  /clear-local-history   delete this conversation from this computer only".into(),
        format!(
            "  New messages from {name} show up after you press Enter. A line that starts with \
             / is read as a command."
        ),
        // A terminal in canonical mode drops what is typed past about 1000 bytes
        // (macOS: 1023), including the Enter: the message looks frozen or is cut.
        format!(
            "  A message is one line: keep it under about 1000 bytes (roughly 500 Persian or \
             1000 English letters), a terminal may cut a longer one. For longer or multi-line \
             text: {file_send}"
        ),
    ]
}

/// The transcript line for a message just sent (stdout) and, when it did not go
/// through, the sentence that says why (stderr). The failure marker never says
/// "delivered": only a verified ACK does, and that is the `Ok` case.
fn chat_echo(text: &str, result: &Result<(), String>, name: &str) -> (String, Option<String>) {
    let shown = sanitize_terminal_line(text);
    match result {
        Ok(()) => (
            format!(
                "  {C_DIM}→{C_RESET} {shown}  {C_GREEN}✓{C_RESET} {C_DIM}{name} confirmed receipt{C_RESET}"
            ),
            None,
        ),
        Err(error) => {
            let line = friendly_send_error(error, name);
            let marker = if line.starts_with(QUEUED_PREFIX) {
                "[queued: goes out with your next message]"
            } else if line.starts_with(UNCONFIRMED_PREFIX) {
                "[sent, not confirmed]"
            } else {
                "[NOT SENT]"
            };
            (format!("  {C_DIM}→{C_RESET} {shown}  {C_DIM}{marker}{C_RESET}"), Some(line))
        }
    }
}

/// `/verify`: what the fingerprint is for, what this command does not do, and the
/// one command that marks the contact verified (there is no shorter one yet).
fn verify_lines(name: &str, fp: &str, pinned: Option<bool>, pin_command: &str) -> Vec<String> {
    let mut lines = vec![
        format!("{C_BOLD}fingerprint{C_RESET} {fp}"),
        format!(
            "{C_DIM}Ask {name} to read you the fingerprint of THEIR identity (`ash whoami` on \
             their computer) by phone or in person, not in this chat. If it is identical, \
             {name} is who you think. This only shows it; nothing is changed.{C_RESET}"
        ),
    ];
    match pinned {
        Some(true) => lines.push(format!(
            "{C_DIM}{name} is already marked verified (pinned) on this computer.{C_RESET}"
        )),
        Some(false) => lines.push(format!(
            "{C_DIM}{name} is not marked verified yet. Once the fingerprints match, mark them \
             verified: {pin_command}{C_RESET}"
        )),
        None => {}
    }
    lines
}

fn chat_verify_lines(data_dir: &Path, contact_pub: &str, name: &str) -> Vec<String> {
    let Ok(key) = parse_pub_hex(contact_pub) else {
        return Vec::new();
    };
    let fp = device_fingerprint_v1(&key);
    // The command takes what the OTHER person read out, not the fingerprint shown
    // here: pasting this one back would "verify" a key against itself.
    let pin_command = format!(
        "ash contact add --address {} --pub-hex {} --verify-fp <the fingerprint {name} read out \
         to you>",
        encode_address(&key),
        hex::encode(key)
    );
    let pinned = contact_for_key(data_dir, contact_pub).map(|c| c.pinned);
    verify_lines(name, &fp, pinned, &pin_command)
}

/// `/block`: ask first (an empty answer, anything but yes, or end of input
/// cancels), then block and say how to undo it. `true` when the chat should end.
fn chat_block(data_dir: &Path, contact_pub: &str, name: &str) -> bool {
    println!(
        "{C_BOLD}Block {name}?{C_RESET} You will not receive messages from {name}, and you \
         cannot send to {name}, until you unblock."
    );
    print!("Type yes to block; anything else cancels: ");
    let _ = io::stdout().flush();
    let answer = read_line_result();
    let confirmed = matches!(
        &answer,
        LineResult::Line(l) if l.eq_ignore_ascii_case("yes") || l.eq_ignore_ascii_case("y")
    );
    if !confirmed {
        if !matches!(answer, LineResult::Line(_)) {
            println!();
        }
        println!("{C_DIM}not blocked{C_RESET}");
        return false;
    }
    let mut blocks = match BlockList::load_checked(data_dir) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("block list: {e}");
            return false;
        }
    };
    blocks.block(contact_pub);
    if let Err(e) = blocks.save(data_dir) {
        eprintln!("block save failed: {e}");
        return false;
    }
    println!(
        "{C_GREEN}blocked{C_RESET} {name}. Messages from {name} are ignored from now on, and \
         you cannot send to {name}."
    );
    let hint = SendCtx {
        pub_hex: parse_pub_hex(contact_pub)
            .map(hex::encode)
            .unwrap_or_default(),
        ..SendCtx::default()
    };
    println!("{C_DIM}{}{C_RESET}", unblock_hint(&hint));
    true
}

/// The file that remembers which messages the chat has already shown cannot be
/// read, so the chat cannot open. It holds no messages, but it also remembers
/// which conversations were cleared (`/clear-local-history`): moving it aside
/// makes the old messages of those show up again, so say so.
fn cursor_unavailable_text(raw: &str, data_dir: &Path) -> String {
    format!(
        "chat not opened: the file that remembers which messages you have already seen ({}) \
         cannot be used. Your messages and contacts are not affected. If you move that file \
         aside (keep it if you want to look at it), the chat opens again, but conversations \
         you cleared with /clear-local-history show their old messages again. \
         (technical: {raw})",
        chat_inbox_cursors_path(data_dir).display()
    )
}

/// Why the chat history cannot be used, in the user's words, and what to do (the
/// raw reason stays at the end). `None` for a reason no sentence covers.
fn history_problem_text(raw: &str, data_dir: &Path) -> Option<String> {
    let ctx = SendCtx {
        data_dir: Some(data_dir.to_path_buf()),
        ..SendCtx::default()
    };
    match classify_cause(raw) {
        cause @ (Cause::HistoryUnreadable | Cause::KeychainDenied | Cause::HistoryLocked) => {
            Some(format!(
                "{}. {} (technical: {raw})",
                cause_sentence(cause, &ctx, raw, false),
                next_step(cause, &ctx, false, raw)
            ))
        }
        _ => None,
    }
}

/// The history could not be opened when the chat started.
fn history_unavailable_text(raw: &str, data_dir: &Path) -> String {
    format!(
        "local protected history unavailable: {}",
        history_problem_text(raw, data_dir).unwrap_or_else(|| raw.to_string())
    )
}

/// The background reader could not list or save new messages. The same history
/// problems end here, and a bare "chat history is corrupt" has no way out.
fn inbox_problem_text(raw: &str, data_dir: &Path) -> String {
    format!(
        "inbox: {}",
        history_problem_text(raw, data_dir).unwrap_or_else(|| raw.to_string())
    )
}

pub fn cmd_chat_session(
    data_dir: &Path,
    id: &Identity,
    contact_petname: &str,
    contact_tag: &str,
    contact_pub: &str,
    peer_listen: &str,
) {
    let name = chat_name(contact_petname, contact_tag, contact_pub);
    println!("{}", chat_header(&name, contact_tag));
    println!(
        "{C_DIM}  type a message and press Enter · /help lists the commands · /back leaves{C_RESET}"
    );
    if let Some(note) = chat_receiver_note(receiver_state(data_dir, CHAT_RECEIVER_PROBE), &name) {
        eprintln!("{note}");
    }
    let mut starting_cursor = match load_durable_inbox_cursor(data_dir, contact_pub) {
        Ok(c) => c,
        Err(e) => {
            // Nothing else can open this chat, and ending quietly with exit 0 hid
            // that: say what file it is and that nothing was lost.
            eprintln!("{}", cursor_unavailable_text(&e, data_dir));
            std::process::exit(1);
        }
    };
    let mut peer_history_nonempty = false;
    // Ids of the inbound rows the history dump below actually prints. The daemon
    // persists every received message to the history when it arrives, so a
    // message that came in while the chat was closed is in the dump *and* still
    // after the saved inbox cursor: without this it was shown twice.
    let mut shown: std::collections::HashSet<[u8; 16]> = std::collections::HashSet::new();
    match ChatHistory::load(data_dir) {
        Ok(history) => {
            let rows = history.for_peer(contact_pub);
            peer_history_nonempty = !rows.is_empty();
            if rows.is_empty() {
                println!("{C_DIM}(no local history){C_RESET}");
            } else {
                for e in rows.iter().rev().take(20).rev() {
                    if e.direction == "in" {
                        if let Some(id) = hex::decode(&e.message_id_hex)
                            .ok()
                            .and_then(|b| <[u8; 16]>::try_from(b).ok())
                        {
                            shown.insert(id);
                        }
                    }
                    let dir = if e.direction == "out" { "→" } else { "←" };
                    let text = if e.body.is_empty() {
                        e.preview.as_str()
                    } else {
                        e.body.as_str()
                    };
                    let mid: String = e.message_id_hex.chars().take(8).collect();
                    println!(
                        "  {C_DIM}{}{C_RESET} {} {}{}",
                        sanitize_terminal_line(&mid),
                        dir,
                        sanitize_terminal_line(text),
                        super::delivery_suffix(e)
                    );
                }
            }
        }
        Err(error) => {
            eprintln!("{}", history_unavailable_text(&error.to_string(), data_dir));
        }
    }
    // History already covers prior inbox traffic; avoid replaying it under the
    // history dump when this peer has never had a durable cursor saved.
    if starting_cursor == InboxCursor::default() && peer_history_nonempty {
        match advance_inbox_cursor_past_peer(data_dir, contact_pub) {
            Ok(c) => starting_cursor = c,
            Err(e) => eprintln!("inbox cursor catch-up failed: {e}"),
        }
    }
    let inbox_cursor = std::sync::Arc::new(std::sync::Mutex::new(starting_cursor));
    let pending_lines = std::sync::Arc::new(std::sync::Mutex::new(ChatPendingQueue::default()));
    if let Ok(mut cursor) = inbox_cursor.lock() {
        loop {
            match peek_endpoint_inbox_for_contact(data_dir, contact_pub, &cursor) {
                Ok(None) => break,
                Ok(Some(batch)) => {
                    print_unseen_lines(&batch, &mut shown);
                    *cursor = batch.cursor_after;
                    if let Err(e) = save_durable_inbox_cursor(data_dir, contact_pub, &cursor) {
                        eprintln!("inbox cursor save failed: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("{}", inbox_problem_text(&e, data_dir));
                    break;
                }
            }
        }
    }

    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_c = std::sync::Arc::clone(&stop);
    let cursor_c = std::sync::Arc::clone(&inbox_cursor);
    let pending_c = std::sync::Arc::clone(&pending_lines);
    let data_dir_c = data_dir.to_path_buf();
    let contact_c = contact_pub.to_string();
    // `peek_gate` serialises one whole peek with `/clear-local-history`; `epoch`
    // counts the clears. Neither is the cursor lock, which the prompt needs: a
    // peek persists to the protected history (keystore, SQLite) and can stall, and
    // while it held the cursor lock the chat could not even redraw its prompt.
    let peek_gate = std::sync::Arc::new(std::sync::Mutex::new(()));
    let epoch = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let (gate_c, epoch_c) = (
        std::sync::Arc::clone(&peek_gate),
        std::sync::Arc::clone(&epoch),
    );
    let notice_prompt = format!("{C_PURPLE}{name}>{C_RESET} ");
    let poller = std::thread::spawn(move || {
        use std::sync::atomic::Ordering::SeqCst;
        while !stop_c.load(SeqCst) {
            std::thread::sleep(Duration::from_millis(500));
            if stop_c.load(SeqCst) {
                break;
            }
            if chat_queue_blocks_poll(&pending_c) {
                continue;
            }
            // Only `/clear-local-history` waits on this gate. Within it, the
            // cursor lock is held just to read the start position and again to
            // publish; the slow peek in between holds neither.
            let Ok(_gate) = gate_c.lock() else {
                break;
            };
            let (start, seen_epoch) = {
                let Ok(shared) = cursor_c.lock() else {
                    break;
                };
                (
                    poll_cursor_with_pending(&pending_c, *shared),
                    epoch_c.load(SeqCst),
                )
            };
            let peeked = peek_endpoint_inbox_for_contact(&data_dir_c, &contact_c, &start);
            let Ok(shared) = cursor_c.lock() else {
                break;
            };
            // A clear while this ran moved the tombstone past these rows (the
            // gate keeps that from happening mid-peek, this is the cheap recheck):
            // drop the batch, the next tick starts from the new cursor.
            if epoch_c.load(SeqCst) != seen_epoch
                || poll_cursor_with_pending(&pending_c, *shared) != start
            {
                continue;
            }
            match peeked {
                Ok(None) => {}
                Ok(Some(batch)) => {
                    if push_chat_batch(&pending_c, batch) {
                        // The chat sits in a blocking read until Enter, so say a
                        // message is waiting; the lines themselves are only ever
                        // printed between prompts (never over a half-typed line).
                        println!(
                            "\n{C_DIM}  (new message — press Enter to show){C_RESET}\n{notice_prompt}"
                        );
                        let _ = io::stdout().flush();
                    }
                }
                Err(e) => set_chat_pending_error(&pending_c, e),
            }
            drop(shared);
        }
    });

    loop {
        // Never clear the half-typed line: print queued inbox only between prompts.
        if let Ok(mut cursor) = inbox_cursor.lock() {
            drain_chat_pending(
                data_dir,
                contact_pub,
                &pending_lines,
                &mut cursor,
                &mut shown,
            );
        }
        print!("{C_PURPLE}{name}>{C_RESET} ");
        let _ = io::stdout().flush();
        let line = match read_line_result() {
            LineResult::Eof | LineResult::Err => {
                println!("{C_DIM}left chat{C_RESET}");
                break;
            }
            LineResult::BadInput => {
                eprintln!(
                    "input was not valid UTF-8, line skipped (nothing was sent; is your \
                     terminal set to UTF-8?)"
                );
                continue;
            }
            LineResult::Line(line) => line,
        };
        match classify_chat_input(&line) {
            ChatInput::Empty => continue,
            ChatInput::Help { bare } => {
                if bare {
                    println!(
                        "{C_DIM}\"{}\" is not sent to {name}; here are the chat commands:{C_RESET}",
                        sanitize_terminal_line(&line)
                    );
                }
                for help_line in chat_help_lines(&name, contact_tag) {
                    println!("{C_DIM}{help_line}{C_RESET}");
                }
            }
            ChatInput::Leave { bare } => {
                if bare {
                    println!(
                        "{C_DIM}\"{}\" leaves the chat; it is not sent to {name}.{C_RESET}",
                        sanitize_terminal_line(&line)
                    );
                }
                println!("{C_DIM}left chat{C_RESET}");
                break;
            }
            ChatInput::Command("/info") => {
                println!(
                    "{C_DIM}petname{C_RESET} {}",
                    sanitize_terminal_line(contact_petname)
                );
                if !contact_tag.is_empty() {
                    println!(
                        "{C_DIM}tag{C_RESET}     @{}",
                        sanitize_terminal_line(contact_tag)
                    );
                }
                println!(
                    "{C_DIM}pub{C_RESET}     {}",
                    sanitize_terminal_line(contact_pub)
                );
                if let Ok(p) = parse_pub_hex(contact_pub) {
                    println!("{C_DIM}fp{C_RESET}      {}", device_fingerprint_v1(&p));
                    println!("{C_DIM}address{C_RESET} {}", encode_address(&p));
                }
            }
            ChatInput::Command("/verify") => {
                for verify_line in chat_verify_lines(data_dir, contact_pub, &name) {
                    println!("{verify_line}");
                }
            }
            ChatInput::Command("/block") => {
                if chat_block(data_dir, contact_pub, &name) {
                    // Nothing can be sent to them now: the chat ends here.
                    println!("{C_DIM}left chat{C_RESET}");
                    break;
                }
            }
            ChatInput::Command("/clear-local-history") => {
                // Behind the peek gate (no peek is in flight) and under the
                // cursor lock, so the poller cannot re-persist or queue rows
                // from before the tombstone while it runs; the epoch bump
                // makes any peek that did start before it discard its batch.
                let _gate = peek_gate.lock().unwrap_or_else(|e| e.into_inner());
                if let Ok(mut cursor) = inbox_cursor.lock() {
                    match clear_peer_history_with_tombstone(data_dir, contact_pub) {
                        Ok(c) => {
                            *cursor = c;
                            epoch.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            discard_chat_pending(&pending_lines);
                            println!("{C_GREEN}cleared{C_RESET} local history for peer");
                        }
                        Err(error) => {
                            eprintln!("local history clear failed: {error}");
                        }
                    }
                }
            }
            ChatInput::Command(other) => println!(
                "{C_DIM}unknown command:{C_RESET} {} {C_DIM}— type /help{C_RESET}",
                sanitize_terminal_line(other)
            ),
            ChatInput::Send(text) => {
                let mut ctx = send_ctx(data_dir, contact_petname, contact_tag, contact_pub);
                ctx.chat = true;
                let sent = send_with(
                    data_dir,
                    id,
                    peer_listen,
                    contact_pub,
                    "127.0.0.1:0",
                    text,
                    &ctx,
                    super::pair_init_lab::DialCarrier::Lan,
                );
                let (echo, failure) = chat_echo(text, &sent, &name);
                println!("{echo}");
                if let Some(failure) = failure {
                    eprintln!("{failure}");
                }
                // No second inbox reader here: the poller is the only producer and
                // the drain at the top of the loop the only consumer. A peek from
                // the shared cursor ignored queued batches, printed their rows
                // now and again at the next drain, and could save the cursor
                // behind what was already shown.
            }
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = poller.join();
    if let Ok(mut cursor) = inbox_cursor.lock() {
        drain_chat_pending(
            data_dir,
            contact_pub,
            &pending_lines,
            &mut cursor,
            &mut shown,
        );
    };
}

// ── Real prekey publish ───────────────────────────────────────────────────

pub fn cmd_prekey_publish_real(
    data_dir: &Path,
    id: &Identity,
    device_id: &str,
    out: Option<&Path>,
) -> Result<(), String> {
    let device_id = if device_id.trim().is_empty() {
        PRIMARY_DEVICE_ID
    } else {
        device_id
    };
    ensure_local_device_certificate(data_dir, id, device_id)
        .map_err(|e| format!("device cert: {e}"))?;

    let mut rng = rand::thread_rng();
    let mut kp = HybridKeypair::generate(&mut rng);

    let now = now_ms();
    let actor = match PrekeyLifecycleActor::open(data_dir) {
        Ok(a) => a,
        Err(e) => {
            kp.x25519_secret.zeroize();
            kp.mlkem_seed.zeroize();
            return Err(format!("prekey actor: {e}"));
        }
    };
    let next_id = match actor.status() {
        Ok(status) => status.highest_signed_prekey_id.saturating_add(1).max(1),
        Err(e) => {
            kp.x25519_secret.zeroize();
            kp.mlkem_seed.zeroize();
            return Err(format!("prekey status: {e}"));
        }
    };
    let bundle = match PrekeyBundle::from_hybrid_public(
        sanitize_terminal_text(device_id),
        kp.x25519_public,
        kp.mlkem_ek_bytes.clone(),
        next_id,
        now,
        now.saturating_add(30 * 24 * 3600 * 1000),
    ) {
        Ok(b) => b,
        Err(e) => {
            kp.x25519_secret.zeroize();
            kp.mlkem_seed.zeroize();
            return Err(e);
        }
    };
    let bundle = match bundle.sign(id) {
        Ok(b) => b,
        Err(e) => {
            kp.x25519_secret.zeroize();
            kp.mlkem_seed.zeroize();
            return Err(format!("sign: {e}"));
        }
    };

    // Private material is durable only via PrekeyLifecycleActor's protected
    // backend. Do not also write a plaintext `prekey_hybrid.secret` duplicate.
    // Delete any legacy plaintext first so a failed remove cannot leave a
    // consumed generation while the command still fails (retry would burn gens).
    let legacy = data_dir.join("prekey_hybrid.secret");
    if legacy.exists() {
        std::fs::remove_file(&legacy).map_err(|e| {
            format!("legacy prekey_hybrid.secret still present and could not be removed: {e}")
        })?;
    }
    // Build the private half straight from `kp` (no named stack copies that
    // would outlive this call), then wipe `kp`; `private` wipes itself on drop,
    // including when install_generation fails.
    let private = PrekeyGenerationPrivate::new(kp.x25519_secret, kp.mlkem_seed, vec![]);
    kp.x25519_secret.zeroize();
    kp.mlkem_seed.zeroize();
    actor
        .install_generation(std::slice::from_ref(&bundle), private, now)
        .map_err(|e| format!("prekey install_generation: {e}"))?;

    raven_core::publish_prekey_bundle_checked(data_dir, &bundle, now)
        .map_err(|e| format!("publish: {e}"))?;
    println!("{C_GREEN}prekey published{C_RESET} (real X25519 + ML-KEM-768 EK)");
    println!(
        "{C_DIM}store_key{C_RESET} {}",
        hex::encode(PrekeyBundle::store_key(&id.public_key_bytes()))
    );
    println!("{C_DIM}note{C_RESET}      never FastAPI — OOB/file/DHT only");
    if let Some(path) = out {
        let j = bundle.to_json();
        let raw =
            serde_json::to_string_pretty(&j).map_err(|e| format!("prekey export encode: {e}"))?;
        raven_core::atomic_write_private(path, raw.as_bytes())
            .map_err(|e| format!("prekey export write: {e}"))?;
        println!("{C_DIM}oob_file{C_RESET} {}", path.display());
    }
    Ok(())
}

/// The text of a styled line: the palette is live whenever the test run has a
/// terminal, and assertions are about words.
#[cfg(test)]
fn plain(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            for d in chars.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod sync_row_tests {
    use super::*;

    #[test]
    fn sync_rows_must_bind_address_to_key() {
        let alice = Identity::from_seed(&[0x41; 32]);
        let mallory = Identity::from_seed(&[0x4d; 32]);
        let a_hex = hex::encode(alice.public_key_bytes());
        let (pub_hex, address) =
            validate_sync_row(&alice.address(), &a_hex.to_uppercase()).unwrap();
        assert_eq!(pub_hex, a_hex);
        assert_eq!(address, alice.address());
        // Alice's address with Mallory's key is refused (was imported verbatim).
        assert!(
            validate_sync_row(&alice.address(), &hex::encode(mallory.public_key_bytes())).is_err()
        );
        assert!(validate_sync_row(&alice.address(), "zz").is_err());
        assert!(validate_sync_row("not-an-address", &a_hex).is_err());
    }
}

#[cfg(test)]
mod chat_cursor_tests {
    use super::*;
    use std::sync::Mutex;

    const PEER: &str = "AB00000000000000000000000000000000000000000000000000000000000001";

    fn cur(ms: u64, id: u8) -> InboxCursor {
        InboxCursor {
            received_at_ms: ms,
            message_id: Some([id; 16]),
        }
    }

    fn batch(ms: u64, id: u8) -> PendingInboxBatch {
        PendingInboxBatch {
            lines: vec![InboxLine {
                message_id: [id; 16],
                text: format!("line {ms}"),
            }],
            cursor_after: cur(ms, id),
        }
    }

    #[test]
    fn durable_cursor_round_trips_per_peer_and_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        let load = |peer: &str| load_durable_inbox_cursor(dir.path(), peer).unwrap();
        assert_eq!(load(PEER), InboxCursor::default());
        save_durable_inbox_cursor(dir.path(), PEER, &cur(42, 7)).unwrap();
        let other = "cd00000000000000000000000000000000000000000000000000000000000002";
        save_durable_inbox_cursor(dir.path(), other, &cur(9, 1)).unwrap();
        assert_eq!(load(&PEER.to_lowercase()), cur(42, 7));
        assert_eq!(load(PEER), cur(42, 7));
        assert_eq!(load(other), cur(9, 1));
        // A cursor without message id (legacy) still parses.
        let entry = serde_json::json!({ "received_at_ms": 5 });
        let c = parse_cursor_entry(&entry).unwrap();
        assert_eq!(c.received_at_ms, 5);
        assert!(c.message_id.is_none());
    }

    #[test]
    fn corrupt_cursor_file_is_reported_and_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = chat_inbox_cursors_path(dir.path());
        for bad in [&b"{not json"[..], b"[1,2]"] {
            std::fs::write(&path, bad).unwrap();
            let err = load_durable_inbox_cursor(dir.path(), PEER).unwrap_err();
            assert!(err.contains("corrupt"), "{err}");
            let err = save_durable_inbox_cursor(dir.path(), PEER, &cur(1, 1)).unwrap_err();
            assert!(err.contains("refusing overwrite"), "{err}");
            assert_eq!(std::fs::read(&path).unwrap(), bad);
        }
        for entry in [
            serde_json::json!("x"),
            serde_json::json!({}),
            serde_json::json!({ "received_at_ms": 1, "message_id_hex": "00" }),
            serde_json::json!({ "received_at_ms": 1, "message_id_hex": 3 }),
        ] {
            assert!(parse_cursor_entry(&entry).is_err(), "{entry}");
        }
    }

    #[test]
    fn pending_queue_defers_one_batch_when_full_and_polls_from_newest() {
        let q = Mutex::new(ChatPendingQueue::default());
        let shared = cur(1, 1);
        assert_eq!(poll_cursor_with_pending(&q, shared), shared);
        assert!(!chat_queue_blocks_poll(&q));
        for i in 0..CHAT_PENDING_MAX as u64 {
            push_chat_batch(&q, batch(10 + i, 2));
        }
        // Next poll continues after the newest queued batch, not the shared one.
        let newest = cur(10 + CHAT_PENDING_MAX as u64 - 1, 2);
        assert_eq!(poll_cursor_with_pending(&q, shared), newest);
        assert!(chat_queue_blocks_poll(&q));
        // Full: exactly one deferred batch is kept; later pushes are dropped
        // (the poller is blocked, so they are re-peeked from the cursor).
        push_chat_batch(&q, batch(500, 3));
        push_chat_batch(&q, batch(600, 4));
        let g = q.lock().unwrap();
        assert_eq!(g.batches.len(), CHAT_PENDING_MAX);
        assert_eq!(g.deferred.as_ref().unwrap().cursor_after, cur(500, 3));
    }

    #[test]
    fn drain_advances_and_persists_cursor_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let q = Mutex::new(ChatPendingQueue::default());
        push_chat_batch(&q, batch(10, 1));
        push_chat_batch(&q, batch(20, 2));
        q.lock().unwrap().deferred = Some(batch(30, 3));
        set_chat_pending_error(&q, "boom".into());
        let mut cursor = cur(5, 0);
        drain_chat_pending(
            dir.path(),
            PEER,
            &q,
            &mut cursor,
            &mut std::collections::HashSet::new(),
        );
        assert_eq!(cursor, cur(30, 3), "deferred batch is drained last");
        assert_eq!(
            load_durable_inbox_cursor(dir.path(), PEER).unwrap(),
            cur(30, 3)
        );
        let g = q.lock().unwrap();
        assert!(g.batches.is_empty() && g.deferred.is_none() && g.last_error.is_none());
        drop(g);
        // Nothing queued → cursor unchanged, file untouched.
        let path = chat_inbox_cursors_path(dir.path());
        let before = std::fs::read(&path).unwrap();
        drain_chat_pending(
            dir.path(),
            PEER,
            &q,
            &mut cursor,
            &mut std::collections::HashSet::new(),
        );
        assert_eq!(cursor, cur(30, 3));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn cursor_order_matches_the_sql_order() {
        // (received_at_ms, message_id), "no id" below any id.
        let none = |ms| InboxCursor {
            received_at_ms: ms,
            message_id: None,
        };
        assert!(none(5) < cur(5, 0));
        assert!(cur(5, 0) < cur(5, 1));
        assert!(cur(5, 255) < cur(6, 0));
        assert!(none(6) > cur(5, 255));
        assert_eq!(cur(5, 1).max(cur(5, 2)), cur(5, 2));
    }

    /// A batch queued before the cursor moved on (the same rows shown by another
    /// path, or cleared by `/clear-local-history`) must neither print again nor
    /// drag the durable cursor backwards.
    #[test]
    fn drain_skips_stale_batches_and_never_moves_the_cursor_back() {
        let dir = tempfile::tempdir().unwrap();
        let q = Mutex::new(ChatPendingQueue::default());
        let mut cursor = cur(50, 5);
        save_durable_inbox_cursor(dir.path(), PEER, &cursor).unwrap();
        push_chat_batch(&q, batch(30, 3)); // behind the cursor
        push_chat_batch(&q, batch(50, 5)); // exactly at the cursor
        push_chat_batch(&q, batch(60, 6)); // genuinely new
        drain_chat_pending(
            dir.path(),
            PEER,
            &q,
            &mut cursor,
            &mut std::collections::HashSet::new(),
        );
        assert_eq!(cursor, cur(60, 6));
        assert_eq!(
            load_durable_inbox_cursor(dir.path(), PEER).unwrap(),
            cur(60, 6)
        );

        // Only stale batches queued: cursor and file stay exactly as they were.
        let path = chat_inbox_cursors_path(dir.path());
        let before = std::fs::read(&path).unwrap();
        push_chat_batch(&q, batch(10, 1));
        q.lock().unwrap().deferred = Some(batch(60, 6));
        drain_chat_pending(
            dir.path(),
            PEER,
            &q,
            &mut cursor,
            &mut std::collections::HashSet::new(),
        );
        assert_eq!(cursor, cur(60, 6));
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn discard_drops_queued_batches_deferred_and_error() {
        let q = Mutex::new(ChatPendingQueue::default());
        push_chat_batch(&q, batch(10, 1));
        q.lock().unwrap().deferred = Some(batch(20, 2));
        set_chat_pending_error(&q, "boom".into());
        discard_chat_pending(&q);
        let g = q.lock().unwrap();
        assert!(g.batches.is_empty() && g.deferred.is_none() && g.last_error.is_none());
    }
}

#[cfg(all(test, unix))]
mod prekey_private_store_tests {
    use super::*;
    use tempfile::tempdir;

    /// The lab file-backed prekey store. These tests must never reach the OS
    /// keychain, whatever environment `cargo test` runs in (on a Mac the real
    /// backend is the login Keychain: a dialog, or an item left behind). Set once
    /// and left set, never restored: the other tests of this binary use the same
    /// backend and a restore would race with them.
    fn lab_prekey_backend() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| unsafe { std::env::set_var("RAVEN_PREKEY_BACKEND", "locked-file") });
    }

    #[test]
    fn persistence_failure_prevents_publication_and_export() {
        lab_prekey_backend();
        let dir = tempdir().expect("tempdir");
        let unusable_data_dir = dir.path().join("not-a-directory");
        std::fs::write(&unusable_data_dir, b"blocker").expect("blocker");
        let export = dir.path().join("public-prekey.json");
        let identity = Identity::from_seed(&[0x55; 32]);

        let err =
            cmd_prekey_publish_real(&unusable_data_dir, &identity, "test-device", Some(&export));
        assert!(err.is_err());

        assert!(!export.exists());
        assert!(!unusable_data_dir.join("prekey_store.json").exists());
        assert!(!unusable_data_dir.join("prekey_hybrid.secret").exists());
    }

    #[test]
    fn publish_does_not_write_plaintext_hybrid_secret() {
        let dir = tempdir().expect("tempdir");
        let identity = Identity::from_seed(&[0x77; 32]);
        // rust-linux has no Secret Service. The explicit lab locked-file
        // backend lets publish succeed so we can assert it still never writes
        // a plaintext hybrid secret.
        lab_prekey_backend();
        cmd_prekey_publish_real(dir.path(), &identity, PRIMARY_DEVICE_ID, None).expect("publish");
        assert!(!dir.path().join("prekey_hybrid.secret").exists());
        assert!(dir.path().join("prekey_store.json").exists());
    }
}

/// `contact add --prekey-file`: verify the OOB bundle against the contact key
/// and store it in the local prekey store (same path as `ash prekey fetch`).
pub fn contact_add_fetch_prekey(
    data_dir: &Path,
    pub_hex: &str,
    prekey_file: Option<&Path>,
) -> Result<(), String> {
    // Same (whoami-line tolerant) parser `contact add` just accepted.
    let ed = super::parse_pub_hex(pub_hex)?;
    let now = now_ms();
    let bundle = if let Some(path) = prekey_file {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        let j: PrekeyBundleJson = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        PrekeyBundle::from_json(&j)?
    } else {
        PrekeyStore::load_checked(data_dir)?
            .fetch(&ed, now)?
            .ok_or_else(|| "no prekey in local store (pass --prekey-file)".to_string())?
    };
    bundle.verify(now)?;
    if bundle.identity_ed25519_pub != ed {
        return Err("PREKEY_IDENTITY_MISMATCH".into());
    }
    raven_core::publish_prekey_bundle_checked(data_dir, &bundle, now)
        .map_err(|e| format!("store publish: {e}"))?;
    println!(
        "{C_GREEN}prekey ok{C_RESET} (verified, cached in prekey_store.json; fp={})",
        device_fingerprint_v1(&ed)
    );
    Ok(())
}

// ── Mailbox put/get (opaque tags) ─────────────────────────────────────────

pub fn mailbox_db_path(data_dir: &Path) -> PathBuf {
    data_dir.join("mailbox_store.json")
}

/// Serialises `mailbox put`'s load → put → save of `mailbox_store.json` (each
/// save atomically replaces the whole snapshot, so unlocked concurrent puts
/// would drop each other's objects while both reporting "stored").
const MAILBOX_LOCK: &str = ".mailbox_store.lock.sqlite";

fn mailbox_store_put(data_dir: &Path, obj: StoreObject) -> Result<(), String> {
    let _lock = raven_core::DataDirLock::acquire(data_dir, MAILBOX_LOCK)
        .map_err(|e| format!("mailbox lock: {e}"))?;
    let path = mailbox_db_path(data_dir);
    let mut mb =
        StoreMailbox::load_disk(&path, 64).map_err(|e| format!("mailbox database: {e}"))?;
    mb.put(obj).map_err(|e| format!("put: {e}"))?;
    mb.save_disk(&path)
        .map_err(|e| format!("mailbox persistence: {e}"))
}

pub fn cmd_mailbox_put(
    data_dir: &Path,
    k_route_hex: &str,
    epoch: u64,
    slot: u64,
    envelope_hex: &str,
) {
    let k = match hex::decode(k_route_hex.trim()) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("k_route_hex required");
            std::process::exit(1);
        }
    };
    let packed = match hex::decode(envelope_hex.trim()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("envelope hex: {e}");
            std::process::exit(1);
        }
    };
    let envelope = match Envelope::unpack(&packed) {
        Some(value) => value,
        None => {
            eprintln!("envelope must be a strict RavenEnvelopeV1 object");
            std::process::exit(1);
        }
    };
    let mtag = mailbox_tag(&k, epoch, slot);
    let store_tag = store_tag_from_mailbox(&mtag);
    let now = now_ms();
    if now < envelope.created_at || now >= envelope.expires_at {
        eprintln!("envelope is not within its validity window");
        std::process::exit(1);
    }
    let obj = StoreObject {
        store_tag,
        message_id: envelope.message_id,
        created_at_ms: now,
        expires_at_ms: envelope.expires_at,
        flags: 0,
        packed_envelope: packed,
        custody_sig: None,
    };
    if let Err(e) = mailbox_store_put(data_dir, obj) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    println!("{C_GREEN}stored{C_RESET}");
    println!("{C_DIM}mailbox_tag{C_RESET} {}", hex::encode(mtag));
    println!(
        "{C_DIM}store_tag{C_RESET}   {} (opaque index — no username)",
        hex::encode(store_tag)
    );
}

pub fn cmd_mailbox_get(data_dir: &Path, k_route_hex: &str, epoch: u64, slot: u64) {
    let k = match hex::decode(k_route_hex.trim()) {
        Ok(v) if !v.is_empty() => v,
        _ => {
            eprintln!("k_route_hex required");
            std::process::exit(1);
        }
    };
    let tags = mailbox_tags_with_overlap(&k, epoch, slot);
    let mb = match StoreMailbox::load_disk(&mailbox_db_path(data_dir), 64) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("mailbox database: {error}");
            std::process::exit(1);
        }
    };
    let now = now_ms();
    let mut found = 0usize;
    for mtag in &tags {
        let st = store_tag_from_mailbox(mtag);
        for obj in mb.get(&st, now) {
            found += 1;
            println!(
                "{C_GREEN}hit{C_RESET} store_tag={} msg={}… env_len={}",
                hex::encode(st),
                &hex::encode(obj.message_id)[..8],
                obj.packed_envelope.len()
            );
        }
    }
    if found == 0 {
        println!("{C_DIM}no objects for rotating mailbox tags{C_RESET}");
    } else {
        println!("{C_DIM}retrieved {found} (opaque tags only){C_RESET}");
    }
}

#[cfg(test)]
mod bootstrap_edit_tests {
    use super::*;

    fn seed_peers(dir: &Path) {
        bootstrap_add_apply(dir, "/ip4/10.0.0.1/tcp/4001", false).unwrap();
        bootstrap_add_apply(dir, "/ip4/10.0.0.2/tcp/4001", true).unwrap();
    }

    #[test]
    fn add_on_a_missing_file_starts_from_the_default_config() {
        let dir = tempfile::tempdir().unwrap();
        let added = bootstrap_add_apply(dir.path(), " /ip4/1.2.3.4/tcp/4001 ", false).unwrap();
        assert_eq!(added, "/ip4/1.2.3.4/tcp/4001");
        let cfg = try_load_bootstrap(dir.path()).unwrap();
        assert!(cfg.custom.iter().any(|p| p == "/ip4/1.2.3.4/tcp/4001"));
    }

    #[test]
    fn add_and_disable_never_overwrite_a_corrupt_bootstrap_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = raven_core::bootstrap::bootstrap_path(dir.path());
        for bad in [&b"{not json"[..], b"", b"[1,2,3]"] {
            std::fs::write(&path, bad).unwrap();
            let err = bootstrap_add_apply(dir.path(), "/ip4/1.2.3.4/tcp/4001", false).unwrap_err();
            assert!(err.contains("refusing to overwrite"), "{err}");
            assert!(err.contains("init-bootstrap"), "{err}");
            assert!(bootstrap_add_apply(dir.path(), "/ip4/1.2.3.4/tcp/1", true).is_err());
            assert!(bootstrap_disable_raven_apply(dir.path()).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bad, "file must be untouched");
        }
    }

    #[test]
    fn add_on_a_valid_file_keeps_existing_entries() {
        let dir = tempfile::tempdir().unwrap();
        seed_peers(dir.path());
        bootstrap_add_apply(dir.path(), "/ip4/10.0.0.3/tcp/4001", false).unwrap();
        let cfg = try_load_bootstrap(dir.path()).unwrap();
        assert!(cfg.custom.iter().any(|p| p == "/ip4/10.0.0.1/tcp/4001"));
        assert!(cfg.custom.iter().any(|p| p == "/ip4/10.0.0.3/tcp/4001"));
        assert!(cfg
            .manual_peers
            .iter()
            .any(|p| p == "/ip4/10.0.0.2/tcp/4001"));
        bootstrap_disable_raven_apply(dir.path()).unwrap();
        let cfg = try_load_bootstrap(dir.path()).unwrap();
        assert!(cfg.custom.iter().any(|p| p == "/ip4/10.0.0.1/tcp/4001"));
    }

    #[test]
    fn empty_multiaddr_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            bootstrap_add_apply(dir.path(), "   ", false).unwrap_err(),
            "empty multiaddr"
        );
    }
}

#[cfg(test)]
mod device_sync_import_tests {
    use super::*;

    fn sync_blob(owner: &Identity, contact: &Identity, issued_at_ms: u64) -> Vec<u8> {
        let plain = ContactSyncPlaintext {
            schema: 1,
            from_device_id: "ash-primary".into(),
            contacts: vec![SyncContact {
                petname: "bob".into(),
                public_tag: "bob".into(),
                alias: String::new(),
                address: contact.address(),
                pub_hex: hex::encode(contact.public_key_bytes()),
                pinned: false,
            }],
            issued_at_ms,
        };
        seal_contact_sync(owner, &plain).unwrap()
    }

    /// The import burns the per-sender replay watermark, so a contacts.json
    /// that cannot be loaded must fail BEFORE it: re-running the same sync file
    /// after fixing the file must work (it used to fail SYNC_REPLAY_OR_STALE).
    #[test]
    fn corrupt_contacts_fail_before_the_replay_watermark_is_consumed() {
        let owner = Identity::from_seed(&[0x71; 32]);
        let bob = Identity::from_seed(&[0x72; 32]);
        let dir = tempfile::tempdir().unwrap();
        let wire = sync_blob(&owner, &bob, now_ms());

        let contacts = dir.path().join("contacts.json");
        std::fs::write(&contacts, b"{not json").unwrap();
        let err = device_sync_import_apply(dir.path(), &owner, &wire).unwrap_err();
        assert!(err.contains("contacts.json corrupt"), "{err}");
        assert_eq!(std::fs::read(&contacts).unwrap(), b"{not json");

        std::fs::remove_file(&contacts).unwrap();
        assert_eq!(
            device_sync_import_apply(dir.path(), &owner, &wire).unwrap(),
            1,
            "same sync file imports once the book is readable"
        );
        let rows = load_local_contacts(dir.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].pub_hex, hex::encode(bob.public_key_bytes()));

        // Replay protection is intact after a successful import.
        let err = device_sync_import_apply(dir.path(), &owner, &wire).unwrap_err();
        assert!(err.contains("SYNC_REPLAY_OR_STALE"), "{err}");
    }
}

#[cfg(test)]
mod device_revoke_tests {
    use super::*;

    fn device_revoked_in_registry(dir: &Path, device_id: &str) -> bool {
        load_device_registry_checked(dir)
            .unwrap()
            .is_revoked(device_id)
    }

    #[test]
    fn revoke_updates_store_and_registry_and_is_idempotent() {
        let owner = Identity::from_seed(&[0x73; 32]);
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "phone", 1).unwrap(),
            RevokeOutcome::Revoked
        );
        assert!(device_revoked_in_registry(dir.path(), "phone"));
        // Same epoch again: no new record, no REVOKE_EPOCH_CONFLICT.
        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "phone", 1).unwrap(),
            RevokeOutcome::AlreadyRevoked
        );
        // Older epoch is also "already revoked"; a newer one is a new record.
        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "phone", 0).unwrap(),
            RevokeOutcome::AlreadyRevoked
        );
        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "phone", 2).unwrap(),
            RevokeOutcome::Revoked
        );
    }

    /// An earlier run saved revocations.json and then failed before the device
    /// registry. The rerun (same epoch, fresh signature) used to be refused as
    /// REVOKE_EPOCH_CONFLICT / "already applied" and never reached the registry.
    #[test]
    fn rerun_repairs_a_registry_left_behind_by_a_partial_revoke() {
        let owner = Identity::from_seed(&[0x74; 32]);
        let dir = tempfile::tempdir().unwrap();
        let mut store = RevocationStore::load_checked(dir.path()).unwrap();
        let rec = RevocationRecord::issue(&owner, "stolen", 1, 111, "operator-revoke").unwrap();
        assert!(store.apply(rec).unwrap());
        store.save(dir.path()).unwrap();
        assert!(
            !device_revoked_in_registry(dir.path(), "stolen"),
            "precondition: registry step never ran"
        );

        assert_eq!(
            device_revoke_apply(dir.path(), &owner, "stolen", 1).unwrap(),
            RevokeOutcome::AlreadyRevoked
        );
        assert!(device_revoked_in_registry(dir.path(), "stolen"));
    }

    #[test]
    fn corrupt_revocation_store_is_an_error_not_an_empty_store() {
        let owner = Identity::from_seed(&[0x75; 32]);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("revocations.json"), b"{not json").unwrap();
        let err = device_revoke_apply(dir.path(), &owner, "phone", 1).unwrap_err();
        assert!(err.contains("revocation store"), "{err}");
    }
}

#[cfg(test)]
mod mailbox_put_tests {
    use super::*;

    fn object(mid: u8) -> StoreObject {
        let expires = 9_000_000_000_000u64;
        let mut env = Envelope {
            env_type: raven_core::envelope::EnvType::Message as u8,
            flags: 0,
            message_id: [mid; 16],
            routing_tag: [3u8; 16],
            dest_device_hint: 0,
            created_at: 1,
            expires_at: expires,
            hop_limit: 4,
            replication_budget: 2,
            anti_replay_nonce: [4u8; 12],
            ratchet_header_ciphertext: vec![],
            message_ciphertext: vec![mid],
            sender_authentication: vec![],
        };
        env.sign_with(&Identity::from_seed(&[0x76; 32]));
        StoreObject {
            store_tag: [9u8; 16],
            message_id: [mid; 16],
            created_at_ms: 1,
            expires_at_ms: expires,
            flags: 0,
            packed_envelope: env.pack(),
            custody_sig: None,
        }
    }

    /// Each put atomically replaces the whole snapshot, so without the lock two
    /// racing puts start from the same snapshot and one object is lost.
    #[test]
    fn concurrent_puts_do_not_lose_objects() {
        const PUTS: u8 = 8;
        let dir = tempfile::tempdir().unwrap();
        std::thread::scope(|scope| {
            for mid in 1..=PUTS {
                let data_dir = dir.path();
                scope.spawn(move || mailbox_store_put(data_dir, object(mid)).unwrap());
            }
        });
        let mb = StoreMailbox::load_disk(&mailbox_db_path(dir.path()), 64).unwrap();
        assert_eq!(mb.get(&[9u8; 16], 2).len(), usize::from(PUTS));
    }

    #[test]
    fn put_into_a_corrupt_mailbox_is_refused_and_leaves_it_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = mailbox_db_path(dir.path());
        std::fs::write(&path, b"{not json").unwrap();
        let err = mailbox_store_put(dir.path(), object(1)).unwrap_err();
        assert!(err.contains("mailbox database"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"{not json");
    }
}

#[cfg(test)]
mod internet_gate_tests {
    use super::*;

    /// A refused lab-only Internet send must not change this machine's
    /// listening state: the gate fires before any daemon is started.
    #[test]
    fn internet_carrier_is_refused_before_a_daemon_is_started() {
        if raven_core::internet_direct_live_enabled() {
            return; // lab (debug + RAVEN_LAB_TEST_A=1): the gate is open by design
        }
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::from_seed(&[0x77; 32]);
        let peer_pub = hex::encode(Identity::from_seed(&[0x78; 32]).public_key_bytes());
        let err = run_send_secure_on(
            dir.path(),
            &id,
            "127.0.0.1:9",
            &peer_pub,
            "127.0.0.1:0",
            "hello",
            "",
            "",
            super::super::pair_init_lab::DialCarrier::Internet,
        )
        .unwrap_err();
        assert!(err.starts_with("INTERNET_DIRECT_HOLD"), "{err}");
        assert!(
            !daemon_log_path(dir.path()).exists(),
            "no daemon start was attempted"
        );
    }
}

#[cfg(all(test, unix))]
mod daemon_start_tests {
    use super::super::ipc_client::test_support::{
        short_tempdir, spawn_pong_server, spawn_status_server,
    };
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    fn shell(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", script]);
        cmd
    }

    fn sleeper() -> Command {
        let mut cmd = Command::new("/bin/sleep");
        cmd.arg("30");
        cmd
    }

    fn empty_slot() -> StartedDaemon {
        Mutex::new(None)
    }

    fn kill_started(slot: &StartedDaemon) {
        if let Some((mut child, _)) = slot.lock().unwrap().take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn early_exit_is_reported_at_once_with_status_and_log_tail() {
        let dir = short_tempdir();
        let slot = empty_slot();
        let err = start_daemon(
            dir.path(),
            shell("echo 'service: boom' >&2; echo 'lan_direct failed to bind' >&2; exit 3"),
            Duration::from_secs(30),
            &slot,
        )
        .unwrap_err();
        assert!(err.contains("exited during startup"), "{err}");
        assert!(err.contains("exit status: 3"), "{err}");
        assert!(err.contains("service: boom"), "{err}");
        assert!(
            err.contains("RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0"),
            "{err}"
        );
        assert!(err.contains(DAEMON_LOG_NAME), "{err}");
        // The exited child was reaped (status cached), not left as a zombie.
        let mut held = slot.lock().unwrap();
        let (child, _) = held.as_mut().unwrap();
        assert!(child.try_wait().unwrap().is_some());
    }

    /// The detached daemon appends for weeks, so it is handed the cap for the log
    /// it was given (and only for a log ash opened): the running service
    /// truncates its own file in place, ash only enforces the cap at the next start.
    #[test]
    fn daemon_is_told_the_log_cap_for_the_log_it_was_given() {
        let dir = short_tempdir();
        let err = start_daemon(
            dir.path(),
            shell("echo \"cap=${RAVEN_SERVICE_LOG_MAX_BYTES:-unset}\" >&2; exit 1"),
            Duration::from_secs(30),
            &empty_slot(),
        )
        .unwrap_err();
        assert!(
            err.contains(&format!("cap={DAEMON_LOG_MAX_BYTES}")),
            "daemon must be told the cap: {err}"
        );
        // The variable name is the contract with raven-node.
        assert_eq!(DAEMON_LOG_MAX_ENV, "RAVEN_SERVICE_LOG_MAX_BYTES");
    }

    /// Holds the daemon's instance lock the way `raven-node` does (an exclusive
    /// `flock` on `<sock>.lock`) and, optionally, never answers on its socket.
    struct FakeService {
        _lock: std::fs::File,
        sock: PathBuf,
    }

    impl FakeService {
        fn wedged(data_dir: &Path) -> Self {
            let sock = raven_core::default_socket_path(data_dir);
            let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
            std::thread::spawn(move || {
                // Accept and sit on every connection: a stopped / deadlocked daemon.
                let mut held = Vec::new();
                for stream in listener.incoming() {
                    match stream {
                        Ok(s) => held.push(s),
                        Err(_) => return,
                    }
                }
            });
            Self::hold_lock(sock)
        }

        fn hold_lock(sock: PathBuf) -> Self {
            let lock_path = raven_core::ipc::instance_lock_path(&sock);
            let lock = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(lock_path)
                .unwrap();
            lock.lock().unwrap();
            Self { _lock: lock, sock }
        }
    }

    const FAST_PROBE: Duration = Duration::from_millis(150);
    const FAST_GRACE: Duration = Duration::from_millis(400);

    /// A SIGSTOPped / deadlocked service keeps its instance lock but never
    /// answers. It used to cost three full 10 s IPC timeouts, after which ash
    /// unlinked the live socket and started a second service that died on the
    /// lock ("exited during startup"). It is now reported as what it is, quickly,
    /// and left alone.
    #[test]
    fn wedged_service_holding_the_lock_is_reported_not_replaced() {
        let dir = short_tempdir();
        let svc = FakeService::wedged(dir.path());
        let started = std::time::Instant::now();
        let verdict = probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, false);
        let lock = raven_core::ipc::instance_lock_path(&svc.sock);
        assert_eq!(verdict, ExistingService::Unresponsive(lock.clone()));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "bounded: {:?}",
            started.elapsed()
        );
        assert!(
            svc.sock.exists(),
            "a live service's socket must not be unlinked"
        );
        let msg = unresponsive_service_error(dir.path(), &lock);
        assert!(msg.starts_with(SERVICE_UNRESPONSIVE_PREFIX), "{msg}");
        assert!(msg.contains("is running"), "{msg}");
        assert!(msg.contains("not answering IPC"), "{msg}");
        assert!(msg.contains("Not starting a second one"), "{msg}");
        // Stops only this profile's service, never every raven-node on the machine:
        // the pattern ends at the argument, so a profile whose directory merely
        // starts with this one's (`/a/b` vs `/a/b2`) is not matched.
        assert!(
            msg.contains(&format!(
                "pkill -f 'raven-node service --data-dir {}( |$)'",
                ere_escape(&dir.path().display().to_string())
            )),
            "{msg}"
        );
        assert!(!msg.contains("pkill -f 'raven-node service'"), "{msg}");
        assert!(!msg.contains("exited during startup"), "{msg}");
    }

    #[test]
    fn answering_service_is_up_even_while_it_holds_the_lock() {
        let dir = short_tempdir();
        let sock = raven_core::default_socket_path(dir.path());
        spawn_pong_server(&sock);
        let _svc = FakeService::hold_lock(sock);
        assert_eq!(
            probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, false),
            ExistingService::Up
        );
    }

    #[test]
    fn no_service_and_a_stale_lock_file_are_absent() {
        let dir = short_tempdir();
        assert_eq!(
            probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, false),
            ExistingService::Absent
        );
        // A lock file nobody holds (the daemon exited; the kernel dropped its
        // flock) is not a service.
        let sock = raven_core::default_socket_path(dir.path());
        std::fs::write(raven_core::ipc::instance_lock_path(&sock), b"").unwrap();
        assert_eq!(
            probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, false),
            ExistingService::Absent
        );
    }

    /// A lock held by the service this very process just spawned belongs to
    /// `start_daemon`, which waits for it: not "unresponsive".
    #[test]
    fn a_lock_held_by_our_own_starting_service_is_not_reported() {
        let dir = short_tempdir();
        let sock = raven_core::default_socket_path(dir.path());
        let _svc = FakeService::hold_lock(sock);
        assert_eq!(
            probe_existing_service(dir.path(), FAST_PROBE, FAST_GRACE, true),
            ExistingService::Absent
        );
    }

    #[test]
    fn unspawnable_binary_is_reported_by_name() {
        let dir = short_tempdir();
        let err = start_daemon(
            dir.path(),
            Command::new("/nonexistent/raven-node"),
            Duration::from_secs(5),
            &empty_slot(),
        )
        .unwrap_err();
        assert!(
            err.contains("could not start /nonexistent/raven-node"),
            "{err}"
        );
    }

    #[test]
    fn service_is_ready_as_soon_as_ipc_answers() {
        let dir = short_tempdir();
        spawn_pong_server(&raven_core::default_socket_path(dir.path()));
        let slot = empty_slot();
        start_daemon(dir.path(), sleeper(), Duration::from_secs(30), &slot).unwrap();
        kill_started(&slot);
    }

    #[test]
    fn slow_start_times_out_without_killing_and_is_reused_not_respawned() {
        let dir = short_tempdir();
        let slot = empty_slot();
        let err =
            start_daemon(dir.path(), sleeper(), Duration::from_millis(300), &slot).unwrap_err();
        assert!(err.contains("did not answer IPC"), "{err}");
        assert!(err.contains("still running"), "{err}");
        let first_pid = slot.lock().unwrap().as_ref().map(|(c, _)| c.id()).unwrap();

        // A second attempt waits for the same child; spawning the (broken)
        // command it is handed would give "could not start" instead.
        let err = start_daemon(
            dir.path(),
            Command::new("/nonexistent/raven-node"),
            Duration::from_millis(300),
            &slot,
        )
        .unwrap_err();
        assert!(err.contains("did not answer IPC"), "{err}");
        assert_eq!(
            slot.lock().unwrap().as_ref().map(|(c, _)| c.id()),
            Some(first_pid)
        );
        kill_started(&slot);
    }

    #[test]
    fn another_daemon_answering_counts_even_if_our_child_exited() {
        // e.g. a concurrent ash started the real service; ours lost the port race.
        let dir = short_tempdir();
        spawn_pong_server(&raven_core::default_socket_path(dir.path()));
        start_daemon(
            dir.path(),
            shell("echo 'lan_direct failed to bind' >&2; exit 1"),
            Duration::from_secs(30),
            &empty_slot(),
        )
        .unwrap();
    }

    #[test]
    fn child_is_detached_into_its_own_process_group() {
        let pgid = |pid: u32| -> Option<String> {
            let out = Command::new("ps")
                .args(["-o", "pgid=", "-p", &pid.to_string()])
                .output()
                .ok()?;
            out.status
                .success()
                .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
        };
        let dir = short_tempdir();
        spawn_pong_server(&raven_core::default_socket_path(dir.path()));
        let slot = empty_slot();
        start_daemon(dir.path(), sleeper(), Duration::from_secs(30), &slot).unwrap();
        let child_pid = slot.lock().unwrap().as_ref().map(|(c, _)| c.id()).unwrap();
        if let (Some(ours), Some(theirs)) = (pgid(std::process::id()), pgid(child_pid)) {
            // A tty Ctrl-C / hangup goes to the foreground process group only.
            assert_ne!(ours, theirs, "daemon must not share ash's process group");
            assert_eq!(theirs, child_pid.to_string(), "child leads its own group");
        }
        kill_started(&slot);
    }

    #[test]
    fn log_is_private_appended_and_capped() {
        let dir = tempfile::tempdir().unwrap();
        let log = daemon_log_path(dir.path());

        // A pre-existing world-readable log is tightened, and appended to.
        std::fs::write(&log, b"older run\n").unwrap();
        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (_file, start) = open_daemon_log(&log).unwrap();
        assert_eq!(start, "older run\n".len() as u64);
        assert_eq!(
            std::fs::metadata(&log).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let raw = std::fs::read_to_string(&log).unwrap();
        assert!(raw.starts_with("older run\n") && raw.contains(DAEMON_LOG_MARKER));

        // Created fresh: 0600 from the start.
        let fresh = dir.path().join("fresh.log");
        open_daemon_log(&fresh).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );

        // Past the cap the old content is dropped instead of growing forever.
        std::fs::File::options()
            .write(true)
            .open(&log)
            .unwrap()
            .set_len(DAEMON_LOG_MAX_BYTES + 1)
            .unwrap();
        let (_file, start) = open_daemon_log(&log).unwrap();
        assert_eq!(start, 0);
    }

    #[test]
    fn log_tail_covers_only_this_attempt_and_is_sanitized() {
        let dir = tempfile::tempdir().unwrap();
        let log = daemon_log_path(dir.path());
        std::fs::write(&log, b"previous attempt: stale error\n").unwrap();
        let (mut file, start) = open_daemon_log(&log).unwrap();
        writeln!(file, "fresh line\r\n\x1b[31mred\x1b[0m").unwrap();
        let tail = daemon_log_tail(&log, start);
        assert!(tail.contains("fresh line"), "{tail:?}");
        assert!(tail.contains("red"), "{tail:?}");
        assert!(!tail.contains("stale error"), "{tail:?}");
        assert!(!tail.contains(DAEMON_LOG_MARKER), "{tail:?}");
        assert!(!tail.contains('\u{1b}'), "{tail:?}");
        // Bounded: a huge burst keeps only the last DAEMON_LOG_TAIL_BYTES.
        let big = "x".repeat(10_000);
        writeln!(file, "{big}\nlast words").unwrap();
        let tail = daemon_log_tail(&log, start);
        assert!(tail.len() as u64 <= DAEMON_LOG_TAIL_BYTES, "{}", tail.len());
        assert!(tail.ends_with("last words"), "{tail:?}");
    }

    #[test]
    fn failure_text_hints_only_for_a_port_conflict() {
        let log = Path::new("/p/raven-node-service.log");
        let busy = daemon_failure("exited", log, "Error: Address already in use");
        assert!(
            busy.contains("RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:0"),
            "{busy}"
        );
        let other = daemon_failure("exited", log, "identity locked");
        assert!(!other.contains("RAVEN_SERVICE_LAN_LISTEN"), "{other}");
        assert!(
            other.contains("identity locked") && other.contains("full log: /p/"),
            "{other}"
        );
        let silent = daemon_failure("exited", log, "");
        assert!(!silent.contains("service output"), "{silent}");
    }

    /// What the daemon writes while a macOS dialog holds its Keychain call.
    const MARKER: &str = "raven-node: BLOCKED_ON_KEYCHAIN what=identity waited=3s \
                          hint=\"approve the macOS dialog for this program (Always Allow)\"";

    fn blocked_on_keychain() -> Command {
        shell(&format!("echo '{MARKER}' >&2; sleep 30"))
    }

    fn started_pid(slot: &StartedDaemon) -> u32 {
        slot.lock().unwrap().as_ref().map(|(c, _)| c.id()).unwrap()
    }

    /// The service is not slow, it is waiting for a person to answer a dialog: it
    /// gets a longer (bounded) window instead of the 20 s timeout that made ash
    /// give up on a healthy service. Here it "answers" after about 0.9 s, far past
    /// the 250 ms window and inside the extended one.
    #[test]
    fn a_service_waiting_for_a_keychain_answer_gets_more_time_not_a_timeout() {
        let dir = short_tempdir();
        let sock = raven_core::default_socket_path(dir.path());
        let answer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(900));
            spawn_pong_server(&sock);
        });
        let slot = empty_slot();
        let started = std::time::Instant::now();
        start_daemon(
            dir.path(),
            blocked_on_keychain(),
            Duration::from_millis(250),
            &slot,
        )
        .expect("a service blocked on the Keychain is waited for");
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        answer.join().unwrap();
        kill_started(&slot);
    }

    /// The extension is bounded, and the timeout then says what to do about it.
    #[test]
    fn the_keychain_wait_is_bounded_and_the_timeout_error_names_it() {
        let dir = short_tempdir();
        let slot = empty_slot();
        let started = std::time::Instant::now();
        let err = start_daemon(
            dir.path(),
            blocked_on_keychain(),
            Duration::from_millis(250),
            &slot,
        )
        .unwrap_err();
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(1500) && waited < Duration::from_secs(20),
            "250 ms x {DAEMON_KEYCHAIN_WAIT_FACTOR}, not forever: {waited:?}"
        );
        assert!(err.contains("did not answer IPC within 2s"), "{err}");
        assert!(
            err.contains("waiting for macOS Keychain access to your Raven identity"),
            "{err}"
        );
        assert!(err.contains(KEYCHAIN_APPROVE_HINT), "{err}");
        assert!(err.contains("still running"), "{err}");
        let pid = started_pid(&slot);
        assert!(err.contains(&format!("kill {pid}")), "{err}");
        assert!(!err.contains("pkill"), "{err}");
        kill_started(&slot);
    }

    /// A marker from an earlier attempt (before this start's log offset) is not
    /// this service's: no extension, no claim.
    #[test]
    fn a_stale_keychain_marker_from_an_earlier_attempt_is_not_counted() {
        let dir = short_tempdir();
        std::fs::write(
            daemon_log_path(dir.path()),
            format!("{DAEMON_LOG_MARKER}\n{MARKER}\n"),
        )
        .unwrap();
        let slot = empty_slot();
        let started = std::time::Instant::now();
        let err =
            start_daemon(dir.path(), sleeper(), Duration::from_millis(250), &slot).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "{:?}",
            started.elapsed()
        );
        assert!(!err.contains("Keychain access to"), "{err}");
        assert!(!err.contains("its log says"), "{err}");
        kill_started(&slot);
    }

    /// The ordinary timeout names the one process to stop (never `pkill -f
    /// 'raven-node service'`, which stops every profile's service); the Keychain
    /// advice is for the platform that has a Keychain.
    #[test]
    fn an_ordinary_timeout_names_the_process_to_stop() {
        let dir = short_tempdir();
        let slot = empty_slot();
        let err =
            start_daemon(dir.path(), sleeper(), Duration::from_millis(300), &slot).unwrap_err();
        let pid = started_pid(&slot);
        assert!(err.contains(&format!("process {pid}")), "{err}");
        assert!(err.contains(&format!("kill {pid}")), "{err}");
        assert!(!err.contains("pkill"), "{err}");
        assert_eq!(
            err.contains(KEYCHAIN_APPROVE_HINT),
            cfg!(target_os = "macos"),
            "{err}"
        );
        assert!(!err.contains("its log says"), "no marker, no claim: {err}");
        kill_started(&slot);
    }

    #[test]
    fn the_start_notice_names_the_process_to_stop_and_the_log() {
        let log = Path::new("/p/raven-node-service.log");
        let text = plain(&started_notice(4242, log));
        assert!(text.contains("raven-node (process 4242)"), "{text}");
        assert!(text.contains("keeps running after ash exits"), "{text}");
        assert!(
            text.contains("stop only this one with: kill 4242"),
            "{text}"
        );
        assert!(text.contains("log: /p/raven-node-service.log"), "{text}");
        assert!(!text.contains("pkill"), "{text}");
        assert_eq!(
            stop_advice(7),
            if cfg!(windows) {
                "taskkill /F /PID 7"
            } else {
                "kill 7"
            }
        );
    }

    /// An unresponsive service whose own log says it waits for the Keychain is
    /// named as such, so the user answers the dialog instead of killing it.
    #[test]
    fn an_unresponsive_service_blocked_on_the_keychain_is_named() {
        let dir = short_tempdir();
        std::fs::write(
            daemon_log_path(dir.path()),
            format!("{DAEMON_LOG_MARKER}\n{MARKER}\n"),
        )
        .unwrap();
        let msg = unresponsive_service_error(dir.path(), Path::new("/x.lock"));
        assert!(
            msg.contains("waiting for macOS Keychain access to your Raven identity"),
            "{msg}"
        );
        assert!(msg.starts_with(SERVICE_UNRESPONSIVE_PREFIX), "{msg}");
        let quiet = short_tempdir();
        let msg = unresponsive_service_error(quiet.path(), Path::new("/x.lock"));
        assert!(!msg.contains("Keychain access to"), "{msg}");
    }

    /// A marker in a log nobody has written for a long time is history (the dialog
    /// was answered long ago), not the reason the service is unresponsive now.
    #[test]
    fn a_stale_keychain_marker_is_not_blamed_for_a_wedged_service() {
        let dir = short_tempdir();
        let log = daemon_log_path(dir.path());
        std::fs::write(&log, format!("{DAEMON_LOG_MARKER}\n{MARKER}\n")).unwrap();
        let long_ago = std::time::SystemTime::now() - Duration::from_secs(24 * 3600);
        std::fs::File::options()
            .write(true)
            .open(&log)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        let msg = unresponsive_service_error(dir.path(), Path::new("/x.lock"));
        assert!(!msg.contains("Keychain access to"), "{msg}");
        assert!(msg.starts_with(SERVICE_UNRESPONSIVE_PREFIX), "{msg}");
    }

    #[test]
    fn the_stop_pattern_escapes_regex_characters_in_the_path() {
        assert_eq!(ere_escape("/a/b.c+(d)"), "/a/b\\.c\\+\\(d\\)");
        assert_eq!(ere_escape("/plain/dir-1"), "/plain/dir-1");
    }

    #[test]
    fn keychain_marker_is_read_back_in_plain_words() {
        let line = |what: &str| {
            format!("raven-node: BLOCKED_ON_KEYCHAIN what={what} waited=3s hint=\"x\"")
        };
        assert_eq!(
            keychain_block_in(&line("identity")),
            Some("your Raven identity")
        );
        assert_eq!(
            keychain_block_in(&line("chat_history")),
            Some("your chat history")
        );
        assert_eq!(
            keychain_block_in(&line("session")),
            Some("a conversation key")
        );
        assert_eq!(
            keychain_block_in(&line("prekey")),
            Some("key-exchange data")
        );
        assert_eq!(
            keychain_block_in(&line("something_new")),
            Some("a saved secret")
        );
        // The newest complete marker wins; text that merely mentions the tag does not count.
        let log = format!(
            "{}\n{}\nunrelated line\n",
            line("identity"),
            line("session")
        );
        assert_eq!(keychain_block_in(&log), Some("a conversation key"));
        assert_eq!(
            keychain_block_in("note: BLOCKED_ON_KEYCHAIN is a marker"),
            None
        );
        assert_eq!(keychain_block_in(""), None);
    }

    /// After IPC answers, the LAN listener may still be coming up: wait for
    /// `lan_direct`, but only so long, and say "unknown" when nothing answers.
    #[test]
    fn the_listener_poll_waits_for_lan_direct_and_reports_each_outcome() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        let listing =
            |caps: &[&str]| -> Vec<String> { caps.iter().map(|c| c.to_string()).collect() };

        let dir = short_tempdir();
        spawn_status_server(&raven_core::default_socket_path(dir.path()), {
            let up = listing(&["ipc", "lan_direct"]);
            move || up.clone()
        });
        assert_eq!(
            wait_for_lan_listener(dir.path(), Duration::from_secs(5)),
            Some(true)
        );

        // The listener comes up shortly after IPC does.
        let dir = short_tempdir();
        let up = Arc::new(AtomicBool::new(false));
        spawn_status_server(&raven_core::default_socket_path(dir.path()), {
            let up = up.clone();
            move || {
                if up.load(Ordering::SeqCst) {
                    vec!["ipc".into(), "lan_direct".into()]
                } else {
                    vec!["ipc".into()]
                }
            }
        });
        let flip = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            up.store(true, Ordering::SeqCst);
        });
        assert_eq!(
            wait_for_lan_listener(dir.path(), Duration::from_secs(10)),
            Some(true)
        );
        flip.join().unwrap();

        // Never: IPC only. Reported after the wait, not before and not forever.
        let dir = short_tempdir();
        spawn_status_server(&raven_core::default_socket_path(dir.path()), || {
            vec!["ipc".into()]
        });
        let started = std::time::Instant::now();
        assert_eq!(
            wait_for_lan_listener(dir.path(), Duration::from_millis(400)),
            Some(false)
        );
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "{:?}",
            started.elapsed()
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );

        // Nothing answers: unknown, at once.
        let dir = short_tempdir();
        let started = std::time::Instant::now();
        assert_eq!(
            wait_for_lan_listener(dir.path(), Duration::from_secs(3)),
            None
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    /// A started service that never lists `lan_direct` is reported (the warning
    /// flag is the once-per-process guard); one that does is not.
    #[test]
    fn a_started_service_without_a_listener_is_reported_once() {
        use std::sync::atomic::AtomicBool;
        let run = |caps: &'static [&'static str]| -> bool {
            let dir = short_tempdir();
            spawn_status_server(&raven_core::default_socket_path(dir.path()), move || {
                caps.iter().map(|c| c.to_string()).collect()
            });
            let slot = empty_slot();
            let warned = AtomicBool::new(false);
            start_and_report(
                dir.path(),
                sleeper(),
                "0.0.0.0:7420",
                Duration::from_secs(30),
                Duration::from_millis(300),
                &slot,
                &warned,
            )
            .unwrap();
            kill_started(&slot);
            warned.load(Ordering::SeqCst)
        };
        assert!(run(&["ipc", "bridge"]), "no lan_direct: warned");
        assert!(
            !run(&["ipc", "lan_direct"]),
            "listener up: nothing to warn about"
        );
    }
}

#[cfg(test)]
mod chat_queue_tests {
    use super::*;

    fn batch(ids: &[u8], cursor_ms: u64) -> PendingInboxBatch {
        PendingInboxBatch {
            lines: ids
                .iter()
                .map(|&b| InboxLine {
                    message_id: [b; 16],
                    text: format!("line {b}"),
                })
                .collect(),
            cursor_after: InboxCursor {
                received_at_ms: cursor_ms,
                message_id: ids.last().map(|&b| [b; 16]),
            },
        }
    }

    /// A message that arrived while the chat was closed is in the history dump
    /// *and* after the saved inbox cursor: it must be shown once, not twice, while
    /// a row the dump did not print is still shown.
    #[test]
    fn rows_the_history_dump_printed_are_not_shown_again() {
        let mut shown: std::collections::HashSet<[u8; 16]> = [[2u8; 16]].into_iter().collect();
        let b = batch(&[1, 2, 3], 10);
        let fresh: Vec<&str> = unseen_lines(&b, &mut shown)
            .into_iter()
            .map(|l| l.text.as_str())
            .collect();
        assert_eq!(fresh, vec!["line 1", "line 3"]);
        // The same batch again (a re-peek after a crash between peek and cursor
        // save) shows nothing new.
        assert!(unseen_lines(&b, &mut shown).is_empty());
        // A row that merely exists in the history but was never printed is new.
        let later = batch(&[4], 11);
        assert_eq!(unseen_lines(&later, &mut shown).len(), 1);
    }

    /// One burst of messages gives one "new message" notice; draining the queue
    /// (or discarding it) re-arms it.
    #[test]
    fn a_burst_gives_one_notice_until_the_queue_is_drained() {
        let dir = tempfile::tempdir().unwrap();
        let pending = std::sync::Mutex::new(ChatPendingQueue::default());
        assert!(
            push_chat_batch(&pending, batch(&[1], 1)),
            "first batch notifies"
        );
        assert!(
            !push_chat_batch(&pending, batch(&[2], 2)),
            "same burst: silent"
        );
        assert!(!push_chat_batch(&pending, batch(&[3], 3)));

        let mut cursor = InboxCursor::default();
        let mut shown = std::collections::HashSet::new();
        drain_chat_pending(
            dir.path(),
            &"ab".repeat(32),
            &pending,
            &mut cursor,
            &mut shown,
        );
        assert_eq!(shown.len(), 3, "all rows were printed once");
        assert_eq!(cursor.received_at_ms, 3, "cursor advanced past the burst");
        assert!(
            push_chat_batch(&pending, batch(&[4], 4)),
            "drained: notifies again"
        );

        discard_chat_pending(&pending);
        assert!(
            push_chat_batch(&pending, batch(&[5], 5)),
            "discarded: notifies again"
        );
    }

    /// A full display queue defers one batch but still counts as one burst.
    #[test]
    fn a_full_queue_defers_a_batch_without_a_second_notice() {
        let pending = std::sync::Mutex::new(ChatPendingQueue::default());
        for i in 0..CHAT_PENDING_MAX {
            push_chat_batch(&pending, batch(&[1], i as u64 + 1));
        }
        assert!(chat_queue_blocks_poll(&pending));
        assert!(!push_chat_batch(&pending, batch(&[9], 999)));
        assert!(pending.lock().unwrap().deferred.is_some());
    }
}

#[cfg(test)]
mod send_outcome_tests {
    use super::*;

    fn bob() -> SendCtx {
        SendCtx {
            name: "Bob".into(),
            selector: "--petname Bob".into(),
            pub_hex: "ab".repeat(32),
            dial: "192.168.0.14:7420".into(),
            data_dir: Some(PathBuf::from("/data")),
            chat: false,
        }
    }

    /// (a text the send path can see, how it must be read, words its sentence
    /// must carry): the table behind every "NOT SENT: ..." line.
    #[test]
    fn raw_errors_become_sentences_with_a_next_step_and_keep_the_raw_text() {
        let table: &[(&str, Cause, &[&str])] = &[
            (
                "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.14:7420 (192.168.0.14:7420: Connection refused (os error 61))",
                Cause::NotListening,
                &[
                    "Bob's computer is there, but RAVEN is not listening at 192.168.0.14:7420",
                    "ash listen",
                    "ash contact set-dial --petname Bob --lan-dial IP:PORT",
                ],
            ),
            (
                "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.14:7420 (192.168.0.14:7420: no answer within 5.0s)",
                Cause::NotReachable,
                &["Bob did not answer at 192.168.0.14:7420", "same network", "new IP address"],
            ),
            (
                "ipc LAN_DIAL: lan dial to 192.168.0.14:7420 timed out after 45s while connecting and in the Noise handshake",
                Cause::NotReachable,
                &["Bob did not answer"],
            ),
            (
                "ipc LAN_DIAL: lan read timeout",
                Cause::ClosedEarly,
                &["something answered at 192.168.0.14:7420 but stopped talking or hung up", "may not be RAVEN"],
            ),
            ("ipc LAN_DIAL: early eof", Cause::ClosedEarly, &["hung up"]),
            (
                "ipc LAN_DIAL: peer closed the connection during the handshake (3 attempts); the peer may be at its connection limit or may not be a RAVEN node",
                Cause::ClosedEarly,
                &["hung up"],
            ),
            (
                "peer did not return an RLB1 bundle",
                Cause::ClosedEarly,
                &["may not be RAVEN"],
            ),
            (
                "ipc LAN_DIAL: identity bind does not match expected pub",
                Cause::WrongIdentity,
                &[
                    "it is not Bob",
                    "its key is not the one you saved",
                    "compare the fingerprint",
                    "ash contact remove --petname Bob",
                ],
            ),
            (
                "ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying; the frames were sent, delivery is unconfirmed and a retry is safe",
                Cause::PeerRefused,
                &["accepted the connection but refused it without saying why", "ash whoami"],
            ),
            (
                "WAITING_FOR_PAIR_RESPONSE: no PairResponse on LanDial (1 frames: rlb1)",
                Cause::PeerRefused,
                &["ash whoami"],
            ),
            (
                "ipc LAN_DIAL: lan_dial parse: invalid socket address syntax",
                Cause::BadAddress,
                &["the saved address \"192.168.0.14:7420\" is not a valid IP:PORT", "192.168.1.20:7420"],
            ),
            (
                "valid lan_dial host:port required — refusing LocalListenQueue / 127.0.0.1:0 fallback",
                Cause::NoAddress,
                &["Bob has no network address saved yet", "ash contact set-dial --petname Bob"],
            ),
            (
                "the local raven-node service stopped during the request (the connection closed before it answered)",
                Cause::ServiceDown,
                &["RAVEN's background service (raven-node) on this computer is not answering", "ash doctor"],
            ),
            (
                "raven-node is not running; start it with `ash listen`, or send a message (that starts it too) (nothing is listening at /x/raven-node.sock: No such file or directory (os error 2))",
                Cause::ServiceDown,
                &["not answering"],
            ),
            (
                "local raven-node service is not running and could not be started: raven-node service exited during startup (exit status: 3)\n  full log: /data/raven-node-service.log",
                Cause::ServiceStart,
                &["could not be started on this computer", "technical details below say why"],
            ),
            (
                "chat history is corrupt",
                Cause::HistoryUnreadable,
                &["/data/chat_history.json", "Your keys and contacts are not affected", "the history starts empty"],
            ),
            (
                "chat history authentication failed (wrong key or tampered file)",
                Cause::HistoryUnreadable,
                &["cannot be opened"],
            ),
            (
                "protected chat-history backend unavailable: keychain read failed: User interaction is not allowed.",
                Cause::KeychainDenied,
                &["could not open its saved chat key", "approve the Keychain window"],
            ),
            (
                "chat history I/O failed: history lock: still held by another raven process after 10s (database is locked); if the raven-node service is waiting on an OS keystore prompt, answer it, or see raven-node-service.log in the data dir",
                Cause::HistoryLocked,
                &["another RAVEN program on this computer is holding your chat history", "raven-node-service.log"],
            ),
            (
                "message too large for lan_dial (max 49152 bytes)",
                Cause::TooLarge,
                &["49152 bytes", "24576 Persian", "49152 English", "split"],
            ),
            (
                "endpoint text payload violates the bounded application policy",
                Cause::BadCharacters,
                &["control characters", "Backspace"],
            ),
            (
                "an earlier outbound object must be retried before reserving another key",
                Cause::SendInProgress,
                &["another send to Bob is still running"],
            ),
            (
                "peer is on the local block list",
                Cause::Blocked,
                &["Bob is blocked on this computer", "ash contact unblock --pub-hex abababab"],
            ),
            ("message is empty", Cause::EmptyMessage, &["empty", "Type some text"]),
        ];
        for (raw, cause, words) in table {
            assert_eq!(classify_cause(raw), *cause, "{raw}");
            let text = not_sent_for(*cause, &bob(), raw, false);
            assert!(text.starts_with("NOT SENT: "), "{text}");
            assert!(text.contains("Nothing was queued"), "{text}");
            assert!(
                text.ends_with(&format!("(technical: {raw})")),
                "the raw text stays at the end: {text}"
            );
            assert!(
                !text.to_lowercase().contains("delivered"),
                "a refusal never claims delivery: {text}"
            );
            assert_eq!(
                text.lines().count(),
                raw.lines().count(),
                "one line, no newline of its own: {text}"
            );
            for word in *words {
                assert!(text.contains(word), "{word:?} missing from: {text}");
            }
        }
    }

    /// A service that is still running but slow to answer (often a macOS Keychain
    /// window nobody has answered) is not "could not be started": say what it is
    /// waiting for and what to do, and keep "could not be started" for real
    /// start failures.
    #[test]
    fn a_service_that_is_still_starting_is_not_reported_as_unable_to_start() {
        let slow = "local raven-node service is not running and could not be started: raven-node service did not answer IPC within 160s (it is still running as process 4321; retry shortly, or stop only this one with: kill 4321)\n  its log says it is waiting for macOS Keychain access to your Raven identity";
        assert_eq!(classify_cause(slow), Cause::ServiceSlow);
        let text = not_sent_for(Cause::ServiceSlow, &bob(), slow, false);
        assert!(
            text.contains("was started but is still waiting for macOS Keychain access"),
            "{text}"
        );
        assert!(text.contains("Always Allow"), "{text}");
        assert!(
            text.contains(&format!("Or stop it with: {}.", stop_advice(4321))),
            "{text}"
        );
        assert!(
            !text.contains("could not be started on this computer"),
            "{text}"
        );
        assert!(text.starts_with("NOT SENT: "), "{text}");

        let quiet = "local raven-node service is not running and could not be started: raven-node service did not answer IPC within 20s (it is still running as process 77; retry shortly, or stop only this one with: kill 77)";
        assert_eq!(classify_cause(quiet), Cause::ServiceSlow);
        let text = not_sent_for(Cause::ServiceSlow, &bob(), quiet, false);
        assert!(text.contains("has not answered yet"), "{text}");
        assert!(text.contains("ash doctor"), "{text}");
        assert!(
            !text.contains("Keychain"),
            "no Keychain claim without evidence: {text}"
        );

        let failed = "local raven-node service is not running and could not be started: raven-node service exited during startup (exit status: 3)";
        assert_eq!(classify_cause(failed), Cause::ServiceStart);
    }

    /// After the first contact a refusal without a reason can also mean the peer
    /// could not save the message (it may already be in their inbox): never tell the
    /// sender to just send it again.
    #[test]
    fn a_later_refusal_may_mean_the_peer_could_not_save_it_and_never_invites_a_duplicate() {
        let raw =
            "ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying";
        let text = not_sent_for(Cause::PeerRefused, &bob(), raw, false);
        assert!(text.contains("could not save the message"), "{text}");
        assert!(text.contains("may already be in their inbox"), "{text}");
        assert!(text.contains("do not send it again"), "{text}");
        assert!(!text.contains("then send again"), "{text}");
    }

    /// A message that IS queued is delivered by the next send: the advice must say
    /// not to retype it (the retry would deliver both copies).
    #[test]
    fn queued_advice_never_invites_retyping_the_queued_message() {
        let raw = "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.14:7420 (192.168.0.14:7420: Connection refused (os error 61)); mid=abcdef01…";
        let text = queued_text(&bob(), raw, "\"hello\"", 60);
        assert!(text.starts_with(QUEUED_PREFIX), "{text}");
        assert!(text.contains("Do not retype this message"), "{text}");
        assert!(!text.contains(", then send again"), "{text}");
        assert!(text.contains("ash listen"), "the next step stays: {text}");
    }

    /// The peer's acknowledgement came back but this computer could not record it:
    /// the message was delivered, so it is neither "NOT SENT" nor "nothing queued".
    #[test]
    fn an_acknowledged_message_that_could_not_be_recorded_is_never_called_not_sent() {
        let raw = "chat history I/O failed: history lock: still held by another raven process after 10s (database is locked)";
        let text = recorded_locally_failed_text(&bob(), raw, "\"hello\"", 60);
        assert!(text.starts_with(UNCONFIRMED_PREFIX), "{text}");
        assert!(
            !text.contains("NOT SENT") && !text.contains("Nothing was queued"),
            "{text}"
        );
        assert!(text.contains("reached Bob's computer"), "{text}");
        assert!(text.contains("Do not retype it"), "{text}");
        assert!(
            text.contains("another RAVEN program on this computer is holding your chat history"),
            "{text}"
        );
        assert!(text.ends_with(&format!("(technical: {raw})")), "{text}");
        assert_eq!(
            translate_known(&text, &bob()),
            None,
            "an outcome line passes through unchanged"
        );
        let other = recorded_locally_failed_text(&bob(), "disk full", "", 60);
        assert!(
            other.contains("this computer could not finish recording it"),
            "{other}"
        );
    }

    #[test]
    fn a_first_message_that_cannot_wait_says_so() {
        let refused =
            "ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying";
        let text = not_sent_for(Cause::PeerRefused, &bob(), refused, true);
        assert!(
            text.contains("Bob did not accept your first message"),
            "{text}"
        );
        assert!(
            text.contains("has not added you as a contact yet"),
            "{text}"
        );
        assert!(text.contains("ask them to add you"), "{text}");
        let sentence = text.split("(technical:").next().unwrap();
        assert!(!sentence.contains("retry is safe"), "{text}");
        let down = "ipc LAN_DIAL: lan connect: cannot connect to 192.168.0.14:7420 (192.168.0.14:7420: Connection refused (os error 61))";
        let text = not_sent_text(&bob(), down, true);
        assert!(
            text.contains("Nothing was queued: a first message needs Bob to be online"),
            "{text}"
        );
        let later = not_sent_text(&bob(), down, false);
        assert!(!later.contains("first message"), "{later}");
    }

    #[test]
    fn queued_unconfirmed_and_earlier_texts_say_what_happened_to_the_text() {
        let ctx = bob();
        let raw = "ipc LAN_DIAL: lan read timeout; mid=01020304…";
        let queued = queued_text(&ctx, raw, "\"see you at 5\"", 60);
        for word in [
            "not delivered yet: your message \"see you at 5\" to Bob is queued locally because",
            "NOT retried automatically",
            "within 60 minutes",
            "expires and is marked failed",
            "(technical: ipc LAN_DIAL: lan read timeout; mid=01020304…)",
        ] {
            assert!(queued.contains(word), "{word:?} missing from: {queued}");
        }
        let unconfirmed = unconfirmed_text(
            &ctx,
            "WAITING_FOR_ENDPOINT_ACK: no sealed ACK came back; mid=01020304…",
            "\"hi\"",
            60,
        );
        for word in [
            "sent, delivery unconfirmed: your message \"hi\" was sent to Bob's computer",
            "Bob has not confirmed it yet",
            "Do not retype it",
            "within 60 minutes",
        ] {
            assert!(
                unconfirmed.contains(word),
                "{word:?} missing from: {unconfirmed}"
            );
        }
        let earlier = earlier_undelivered_text(&ctx, raw, "\"see you at 5\"", 60);
        for word in [
            "NOT SENT: an earlier message \"see you at 5\" to Bob is still undelivered",
            "this message was not queued behind it",
            "send this message again",
            "the earlier one goes first, within its 60 minutes",
        ] {
            assert!(earlier.contains(word), "{word:?} missing from: {earlier}");
        }
        let awaiting = earlier_unconfirmed_text(&ctx, "");
        assert!(
            awaiting.starts_with("NOT SENT: an earlier message to Bob was sent again"),
            "{awaiting}"
        );
        assert!(
            awaiting.contains("this message was not queued"),
            "{awaiting}"
        );
        // Only a verified ACK may say "delivered" (and it says it elsewhere).
        for text in [&queued, &unconfirmed, &earlier, &awaiting] {
            assert!(!text.contains("status delivered"), "{text}");
        }
    }

    #[test]
    fn outcome_texts_pass_through_and_unknown_text_keeps_the_old_refusal_form() {
        let ctx = bob();
        let outcomes = [
            queued_text(&ctx, "ipc LAN_DIAL: lan read timeout", "", 60),
            unconfirmed_text(&ctx, "no sealed ACK", "", 60),
            earlier_undelivered_text(&ctx, "ipc LAN_DIAL: early eof", "", 60),
            earlier_unconfirmed_text(&ctx, ""),
            not_sent_text(&ctx, "ipc LAN_DIAL: early eof", false),
            "NOT SENT, nothing queued: another `ash send` to this peer from this profile was still running after 120s; try again shortly".to_string(),
            "send refused: x".to_string(),
        ];
        for text in &outcomes {
            assert_eq!(&friendly_send_error(text, "Bob"), text, "idempotent");
            assert_eq!(translate_known(text, &ctx), None);
        }
        // Gate texts and codes no sentence covers reach callers untouched (a unit
        // test and scripts match their exact words), and print as before.
        for gate in [
            super::super::pair_init_lab::INTERNET_DIRECT_HOLD,
            "ATSAM_SESSION_REQUIRED: the peer's certificate is not the one bound into the confirmed session (renewed or re-certified); nothing was sent",
            "ATSAM_LINEAGE_REVOKED: peer device lineage is revoked; nothing was sent",
            "REFUSE: serverless path must never silently use FastAPI for message delivery",
            "pub_hex must be 64 hex characters",
            "block list corrupt: refusing to continue",
        ] {
            assert_eq!(classify_cause(gate), Cause::Other, "{gate}");
            assert_eq!(translate_known(gate, &ctx), None, "{gate}");
            assert_eq!(friendly_send_error(gate, "Bob"), format!("send refused: {gate}"));
        }
    }

    #[test]
    fn the_person_is_named_never_a_key_and_hostile_names_are_neutralised() {
        let raw = "ipc LAN_DIAL: lan connect: cannot connect to 10.0.0.5:7420 (10.0.0.5:7420: Connection refused (os error 61))";
        let named = friendly_send_error(raw, "Bob");
        assert!(named.contains("Bob's computer is there"), "{named}");
        assert!(
            named.contains("at 10.0.0.5:7420"),
            "the daemon's own text names the address: {named}"
        );
        assert!(named.contains("--petname Bob"), "{named}");
        let anonymous = friendly_send_error(raw, "");
        assert!(
            anonymous.contains("the other person's computer is there"),
            "{anonymous}"
        );
        assert!(anonymous.contains("--petname NAME"), "{anonymous}");
        assert!(friendly_send_error(raw, "@bob").contains("--tag bob"));
        assert!(friendly_send_error(raw, "Offline Mobile").contains("--petname \"Offline Mobile\""));
        assert!(friendly_send_error(raw, "علی رضا").contains("--petname \"علی رضا\""));
        let hostile = friendly_send_error(raw, "Bob\u{1b}[2J\nsecond line");
        assert!(
            !hostile.contains('\u{1b}') && !hostile.contains('\n'),
            "{hostile:?}"
        );
        // No 64-hex key anywhere unless it is the block undo (which needs the key).
        assert!(!named
            .chars()
            .collect::<Vec<_>>()
            .windows(64)
            .any(|w| w.iter().all(char::is_ascii_hexdigit)));
    }

    #[test]
    fn shell_words_and_selectors_are_safe_to_paste() {
        assert_eq!(shell_word("Bob"), "Bob");
        assert_eq!(shell_word("Offline Mobile"), "\"Offline Mobile\"");
        assert_eq!(shell_word("a$b"), "'a$b'");
        assert_eq!(shell_word("it's"), "\"it's\"");
        assert_eq!(selector_for("Bob", ""), "--petname Bob");
        assert_eq!(selector_for("@bob", ""), "--tag bob");
        assert_eq!(selector_for("", "rvn1qabc"), "--address rvn1qabc");
        assert_eq!(selector_for("", ""), "");
    }

    #[test]
    fn previews_show_the_users_own_words_cut_short_and_safe() {
        assert_eq!(quoted_preview("see you at 5"), "\"see you at 5\"");
        assert_eq!(quoted_preview("   \n "), "");
        let long = "x".repeat(45);
        assert_eq!(quoted_preview(&long), format!("\"{}…\"", "x".repeat(30)));
        // Persian text and its ZWNJ come through intact.
        let persian = "می\u{200c}خواهم کتاب\u{200c}ها رو ببینم";
        assert_eq!(quoted_preview(persian), format!("\"{persian}\""));
        let nasty = quoted_preview("a\u{1b}[31mb\nc");
        assert!(
            !nasty.contains('\u{1b}') && !nasty.contains('\n'),
            "{nasty:?}"
        );
    }

    #[test]
    fn the_contact_is_named_from_the_book_by_key() {
        let dir = tempfile::tempdir().unwrap();
        let (bob_id, carol_id, nobody) = (
            Identity::from_seed(&[0x41; 32]),
            Identity::from_seed(&[0x42; 32]),
            Identity::from_seed(&[0x43; 32]),
        );
        let hex_of = |id: &Identity| hex::encode(id.public_key_bytes());
        let row = |id: &Identity, petname: &str, tag: &str| {
            serde_json::json!({
                "petname": petname, "public_tag": tag, "alias": tag,
                "address": id.address(), "pub_hex": hex_of(id), "pinned": false, "lan_dial": ""
            })
        };
        std::fs::write(
            dir.path().join("contacts.json"),
            serde_json::to_vec(&vec![
                row(&bob_id, "Bob", "bob"),
                row(&carol_id, "", "carol"),
            ])
            .unwrap(),
        )
        .unwrap();

        let ctx = send_ctx(dir.path(), "", "", &hex_of(&bob_id).to_uppercase());
        assert_eq!(
            (ctx.name.as_str(), ctx.selector.as_str()),
            ("Bob", "--petname Bob")
        );
        assert_eq!(
            ctx.pub_hex,
            hex_of(&bob_id),
            "normalised for `contact unblock`"
        );
        let ctx = send_ctx(dir.path(), "", "", &hex_of(&carol_id));
        assert_eq!(
            (ctx.name.as_str(), ctx.selector.as_str()),
            ("@carol", "--tag carol")
        );
        // Not a contact: no name, and the hint selects by address.
        let ctx = send_ctx(dir.path(), "", "", &hex_of(&nobody));
        assert_eq!(ctx.name, "");
        assert_eq!(ctx.selector, format!("--address {}", nobody.address()));
        // What the caller already knows wins (the chat passes it).
        let ctx = send_ctx(dir.path(), "Zed", "", &hex_of(&bob_id));
        assert_eq!(ctx.name, "Zed");
        // An unreadable book or key is "unknown", never a panic.
        std::fs::write(dir.path().join("contacts.json"), b"{not json").unwrap();
        assert_eq!(send_ctx(dir.path(), "", "", &hex_of(&bob_id)).name, "");
        let ctx = send_ctx(dir.path(), "", "", "zz");
        assert_eq!(
            (
                ctx.name.as_str(),
                ctx.selector.as_str(),
                ctx.pub_hex.as_str()
            ),
            ("", "", "")
        );
    }

    /// Success is on stdout and says who confirmed it; `status delivered` stays
    /// the literal start (scripts and the iOS gate match it) and the technical
    /// line (message id, carrier) shows only on request or for the lab carrier.
    #[test]
    fn success_lines_name_the_person_and_keep_the_status_literal() {
        let ctx = bob();
        let line = plain(&ctx.delivered_line().unwrap());
        assert_eq!(line, "status delivered — Bob confirmed receipt");
        assert!(line.starts_with("status delivered"));
        assert!(
            !line.contains("mid=") && !line.contains("carrier") && !line.contains("PairResponse")
        );
        // Chat shows its own transcript line instead.
        assert_eq!(
            SendCtx {
                chat: true,
                ..bob()
            }
            .delivered_line(),
            None
        );

        let mid = [0xab; 16];
        assert_eq!(ctx.delivery_detail_line("lan_dial", &mid, false), None);
        let verbose = plain(&ctx.delivery_detail_line("lan_dial", &mid, true).unwrap());
        assert!(
            verbose.contains("abababab") && verbose.contains("carrier=lan_dial"),
            "{verbose}"
        );
        let lab = plain(
            &ctx.delivery_detail_line("internet_dial", &mid, false)
                .unwrap(),
        );
        assert!(
            lab.contains("carrier=internet_dial") && lab.contains("peer=192.168.0.14:7420"),
            "{lab}"
        );

        let first = plain(&ctx.first_contact_line());
        assert_eq!(
            first,
            "First time talking to Bob: secure connection set up."
        );
        assert!(!first.contains("PairResponse"));
        let earlier = plain(&ctx.earlier_delivered_line("\"see you at 5\""));
        assert!(
            earlier.starts_with("status delivered — your earlier message \"see you at 5\" to Bob"),
            "{earlier}"
        );
        let failed = plain(&ctx.earlier_failed_line("\"x\"", "it expired"));
        assert_eq!(
            failed,
            "status failed: your earlier message \"x\" to Bob: it expired"
        );
        // Nothing here ever prints for someone unnamed as an empty string.
        let anon = SendCtx::default();
        assert!(
            plain(&anon.delivered_line().unwrap()).contains("the other person confirmed receipt")
        );
    }

    #[test]
    fn verbose_is_an_explicit_opt_in() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| std::ffi::OsString::from(*v))
            }
        };
        assert!(!verbose_with(env(&[])));
        assert!(!verbose_with(env(&[("RAVEN_VERBOSE", "")])));
        assert!(!verbose_with(env(&[("RAVEN_VERBOSE", "0")])));
        assert!(verbose_with(env(&[("RAVEN_VERBOSE", "1")])));
        assert!(verbose_with(env(&[("ASH_VERBOSE", "1")])));
    }

    #[test]
    fn the_listener_messages_say_receiving_only_when_it_is_and_warn_once_otherwise() {
        let log = Path::new("/p/raven-node-service.log");
        let warned = AtomicBool::new(false);
        let up =
            plain(&listener_message("0.0.0.0:7420", Some(true), log, &warned, Some(4242)).unwrap());
        assert!(up.contains("receiving messages on 0.0.0.0:7420"), "{up}");
        assert!(
            up.contains("other computers on your network can reach it"),
            "{up}"
        );
        assert!(!warned.load(Ordering::SeqCst));
        let local =
            plain(&listener_message("127.0.0.1:0", Some(true), log, &warned, Some(4242)).unwrap());
        assert!(
            local.contains("this computer only") && !local.contains(":0"),
            "{local}"
        );
        assert_eq!(
            listener_message("0.0.0.0:7420", None, log, &warned, Some(4242)),
            None,
            "unknown: say nothing"
        );

        let down = plain(
            &listener_message("0.0.0.0:7420", Some(false), log, &warned, Some(4242)).unwrap(),
        );
        for word in [
            "warning: this computer is NOT receiving messages",
            "LAN port 0.0.0.0:7420 is busy or unavailable",
            "(log: /p/raven-node-service.log)",
            "Sending still works",
            "free that port (the service keeps retrying by itself)",
            "stop this service (kill 4242)",
            "run ash again with RAVEN_SERVICE_LAN_LISTEN=0.0.0.0:7424",
            "Setting the variable while this service keeps running changes nothing",
        ] {
            assert!(down.contains(word), "{word:?} missing from: {down}");
        }
        assert!(!down.contains("IPC + LAN receive on"), "{down}");
        assert_eq!(
            listener_message("0.0.0.0:7420", Some(false), log, &warned, Some(4242)),
            None,
            "once per process"
        );
    }

    #[test]
    fn a_second_profile_is_offered_the_next_port() {
        // 7421-7423 are RAVEN's own ports (mock BLE, Internet, libp2p).
        assert_eq!(alternative_listen("0.0.0.0:7420"), "0.0.0.0:7424");
        assert_eq!(alternative_listen("[::]:7420"), "[::]:7424");
        assert_eq!(alternative_listen("0.0.0.0:7424"), "0.0.0.0:7425");
        assert_eq!(alternative_listen("192.168.1.9:9000"), "192.168.1.9:9001");
        for odd in ["127.0.0.1:0", "0.0.0.0:65535", "not-an-address", ""] {
            assert_eq!(alternative_listen(odd), "0.0.0.0:7424", "{odd}");
        }
        assert!(listen_is_loopback("127.0.0.1:7420") && listen_is_loopback("localhost:7420"));
        assert!(!listen_is_loopback("0.0.0.0:7420") && !listen_is_loopback("192.168.1.9:7420"));
    }
}

#[cfg(test)]
mod slow_note_tests {
    use super::*;
    use std::sync::mpsc;

    type Sink = Box<dyn Fn(&str) + Send>;

    fn channel_sink() -> (mpsc::Receiver<String>, Sink) {
        let (tx, rx) = mpsc::channel();
        (rx, Box::new(move |m: &str| tx.send(m.to_string()).unwrap()))
    }

    #[test]
    fn it_speaks_when_the_work_outlasts_the_delay() {
        let (rx, emit) = channel_sink();
        let note = SlowNote::start_with(
            "sending to Bob ...".into(),
            Duration::from_millis(20),
            true,
            emit,
        );
        assert_eq!(
            rx.recv_timeout(Duration::from_secs(10)).unwrap(),
            "sending to Bob ..."
        );
        drop(note);
    }

    #[test]
    fn it_stays_quiet_when_the_work_finishes_first() {
        let (rx, emit) = channel_sink();
        let note = SlowNote::start_with("sending ...".into(), Duration::from_secs(600), true, emit);
        let started = std::time::Instant::now();
        drop(note); // joins the helper thread: nothing can be printed afterwards
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert!(rx.try_recv().is_err());
    }

    /// A pipe or a log keeps exactly the output it had.
    #[test]
    fn it_never_speaks_when_stderr_is_not_a_terminal() {
        let (rx, emit) = channel_sink();
        let note = SlowNote::start_with("sending ...".into(), Duration::ZERO, false, emit);
        drop(note);
        assert!(rx.try_recv().is_err());
    }
}

#[cfg(test)]
mod chat_ux_tests {
    use super::*;

    #[test]
    fn bare_help_exit_and_quit_are_commands_not_messages() {
        use ChatInput::*;
        for (line, want) in [
            ("help", Help { bare: true }),
            ("?", Help { bare: true }),
            ("  HELP  ", Help { bare: true }),
            ("Exit", Leave { bare: true }),
            ("quit", Leave { bare: true }),
            ("/help", Help { bare: false }),
            ("/?", Help { bare: false }),
            ("/back", Leave { bare: false }),
            ("/quit", Leave { bare: false }),
            ("/q", Leave { bare: false }),
            ("/exit", Leave { bare: false }),
            ("/info", Command("/info")),
            ("/block now", Command("/block")),
            ("/nope", Command("/nope")),
            ("", Empty),
            ("   ", Empty),
        ] {
            assert_eq!(classify_chat_input(line), want, "{line:?}");
        }
        // Anything else is a message, including lines that merely contain those words.
        for line in [
            "help me",
            "hello",
            "quit smoking?",
            "exit 3",
            "?? what",
            "helpful",
            "سلام",
            "کمک",
        ] {
            assert_eq!(classify_chat_input(line), Send(line), "{line:?}");
        }
        assert_eq!(classify_chat_input("  padded  "), Send("padded"));
    }

    #[test]
    fn help_lists_every_command_and_names_the_person() {
        let help = chat_help_lines("Bob", "bob").join("\n");
        for command in [
            "/help",
            "/back",
            "/info",
            "/verify",
            "/block",
            "/clear-local-history",
        ] {
            assert!(help.contains(command), "{command} missing: {help}");
        }
        for word in [
            "quit",
            "Ctrl-D",
            "Bob",
            "press Enter",
            "starts with /",
            "under about 1000 bytes",
            "ash send --contact @bob < message.txt",
        ] {
            assert!(help.contains(word), "{word} missing: {help}");
        }
        assert!(!help.contains("pub_hex"));
        // A contact without a tag still gets the pattern.
        assert!(chat_help_lines("Bob", "")
            .join("\n")
            .contains("ash send --contact @tag < message.txt"));
    }

    #[test]
    fn the_chat_names_the_person_never_64_hex_digits() {
        let key = "ab".repeat(32);
        assert_eq!(chat_name("Bob", "bob", &key), "Bob");
        assert_eq!(chat_name("", "@bob", &key), "@bob");
        let by_fp = chat_name("", "", &key);
        assert!(
            by_fp.starts_with("device ") && !by_fp.contains(&key),
            "{by_fp}"
        );
        assert_eq!(chat_name("", "", "zz"), "this contact");
        let hostile = chat_name("Bob\u{1b}[2J\nx", "", &key);
        assert!(
            hostile.starts_with("Bob") && !hostile.contains('\u{1b}') && !hostile.contains('\n'),
            "{hostile:?}"
        );
        assert_eq!(plain(&chat_header("Bob", "bob")), "chat with Bob @bob");
        assert_eq!(plain(&chat_header("@bob", "bob")), "chat with @bob");
        assert_eq!(plain(&chat_header("Bob", "")), "chat with Bob");
    }

    #[test]
    fn a_sent_line_is_echoed_with_what_happened_to_it() {
        let (echo, failure) = chat_echo("hello bob", &Ok(()), "Bob");
        let echo = plain(&echo);
        assert_eq!(echo, "  → hello bob  ✓ Bob confirmed receipt");
        assert_eq!(failure, None);

        let ctx = SendCtx {
            name: "Bob".into(),
            ..SendCtx::default()
        };
        let queued = queued_text(&ctx, "ipc LAN_DIAL: lan read timeout", "\"hi\"", 60);
        let unconfirmed = unconfirmed_text(&ctx, "no sealed ACK", "\"hi\"", 60);
        let refused = not_sent_text(&ctx, "ipc LAN_DIAL: early eof", false);
        for (text, marker, sentence) in [
            (
                queued,
                "[queued: goes out with your next message]",
                "not delivered yet",
            ),
            (
                unconfirmed,
                "[sent, not confirmed]",
                "sent, delivery unconfirmed",
            ),
            (refused, "[NOT SENT]", "NOT SENT"),
        ] {
            let (echo, failure) = chat_echo("hi there", &Err(text.clone()), "Bob");
            let echo = plain(&echo);
            assert_eq!(echo, format!("  → hi there  {marker}"));
            assert!(
                !echo.to_lowercase().contains("delivered"),
                "stdout never claims delivery for a message that was not confirmed: {echo}"
            );
            let failure = failure.expect("the sentence goes to stderr");
            assert_eq!(failure, text);
            assert!(failure.starts_with(sentence), "{failure}");
        }
        // A raw error from outside the send path is made friendly, not echoed raw.
        let (echo, failure) = chat_echo("hi", &Err("ipc LAN_DIAL: early eof".into()), "Bob");
        assert!(plain(&echo).ends_with("[NOT SENT]"));
        assert!(failure.unwrap().starts_with("NOT SENT: "));
        // The echoed text is neutralised like every peer- or user-supplied line.
        let (echo, _) = chat_echo("a\u{1b}[31mb\nc", &Ok(()), "Bob");
        assert!(!echo.contains('\u{1b}') && !echo.contains('\n'), "{echo:?}");
    }

    #[test]
    fn verify_says_what_it_does_and_what_it_does_not() {
        let fp = "H3si-4Bmu-hqJl";
        let cmd = "ash contact add --address rvn1x --pub-hex ab --verify-fp <what Bob read out>";
        let unpinned = verify_lines("Bob", fp, Some(false), cmd);
        let text = plain(&unpinned.join("\n"));
        assert_eq!(text.lines().next().unwrap(), "fingerprint H3si-4Bmu-hqJl");
        for word in [
            "THEIR identity",
            "by phone or in person, not in this chat",
            "This only shows it; nothing is changed",
            "Bob is not marked verified yet",
            cmd,
        ] {
            assert!(text.contains(word), "{word:?} missing from: {text}");
        }
        assert!(
            !text.contains("ash contact verify"),
            "the old, misleading pointer: {text}"
        );
        let pinned = plain(&verify_lines("Bob", fp, Some(true), cmd).join("\n"));
        assert!(
            pinned.contains("already marked verified (pinned)"),
            "{pinned}"
        );
        assert!(!pinned.contains(cmd));
        let unknown = plain(&verify_lines("Bob", fp, None, cmd).join("\n"));
        assert!(
            !unknown.contains("verified") || unknown.contains("is who you think"),
            "{unknown}"
        );
        assert!(!unknown.contains(cmd));
    }

    #[test]
    fn the_receiver_note_explains_why_replies_cannot_arrive() {
        let status = |caps: &[&str]| -> Result<IpcResponse, String> {
            Ok(IpcResponse::Status {
                v: IPC_VERSION,
                bridge: false,
                store: false,
                relay: false,
                forward_pending: 0,
                capabilities: caps.iter().map(|c| c.to_string()).collect(),
            })
        };
        assert_eq!(
            classify_receiver(&status(&["ipc", "lan_direct"])),
            ReceiverState::Receiving
        );
        assert_eq!(
            classify_receiver(&status(&["ipc"])),
            ReceiverState::NotReceiving
        );
        assert_eq!(
            classify_receiver(&Err("raven-node is not running; start it with `ash listen` (nothing is listening at /x)".into())),
            ReceiverState::NotRunning
        );
        assert_eq!(
            classify_receiver(&Err(
                "raven-node did not answer in time: it is busy or stuck".into()
            )),
            ReceiverState::NotAnswering
        );
        assert_eq!(
            classify_receiver(&Ok(IpcResponse::Pong { v: IPC_VERSION })),
            ReceiverState::NotAnswering
        );
        assert_eq!(chat_receiver_note(ReceiverState::Receiving, "Bob"), None);
        let off = plain(&chat_receiver_note(ReceiverState::NotRunning, "Bob").unwrap());
        assert!(off.contains("replies from Bob cannot arrive yet"), "{off}");
        assert!(off.contains("ash listen"), "{off}");
        assert!(
            off.contains("when you send a message here"),
            "starts by itself on the first send: {off}"
        );
        let deaf = plain(&chat_receiver_note(ReceiverState::NotReceiving, "Bob").unwrap());
        assert!(deaf.contains("NOT receiving messages"), "{deaf}");
        assert!(deaf.contains("raven-node-service.log"), "{deaf}");
        let stuck = plain(&chat_receiver_note(ReceiverState::NotAnswering, "Bob").unwrap());
        assert!(stuck.contains("not answering"), "{stuck}");
    }

    /// The probe is read-only and bounded: a profile with no service answers at
    /// once and nothing is started.
    #[cfg(unix)]
    #[test]
    fn the_receiver_probe_never_starts_anything() {
        let dir = super::super::ipc_client::test_support::short_tempdir();
        let started = std::time::Instant::now();
        assert_eq!(
            receiver_state(dir.path(), Duration::from_millis(500)),
            ReceiverState::NotRunning
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert!(
            !daemon_log_path(dir.path()).exists(),
            "no service log: nothing was started"
        );
    }

    /// A line in the wrong encoding is dropped with a message; it does not end the
    /// session as if the user had quit, and the next line still reads.
    #[test]
    fn a_line_that_is_not_utf8_is_skipped_not_taken_for_quitting() {
        let mut input =
            io::Cursor::new(b"hello  \n\xed\xa1\xe4\xe3 \n  second line \nlast".to_vec());
        assert_eq!(read_line_from(&mut input), LineResult::Line("hello".into()));
        assert_eq!(read_line_from(&mut input), LineResult::BadInput);
        assert_eq!(
            read_line_from(&mut input),
            LineResult::Line("second line".into())
        );
        assert_eq!(read_line_from(&mut input), LineResult::Line("last".into()));
        assert_eq!(read_line_from(&mut input), LineResult::Eof);
        let mut persian = io::Cursor::new("سلام دنیا\n".as_bytes().to_vec());
        assert_eq!(
            read_line_from(&mut persian),
            LineResult::Line("سلام دنیا".into())
        );
    }

    #[test]
    fn an_unreadable_history_comes_with_a_way_out() {
        let dir = Path::new("/data");
        let corrupt = history_unavailable_text("chat history is corrupt", dir);
        for word in [
            "local protected history unavailable:",
            "/data/chat_history.json",
            "Your keys and contacts are not affected",
            "(technical: chat history is corrupt)",
        ] {
            assert!(corrupt.contains(word), "{word:?} missing from: {corrupt}");
        }
        let key = history_unavailable_text("protected chat-history key is missing", dir);
        assert!(key.contains("approve the Keychain window"), "{key}");
        assert_eq!(
            history_unavailable_text("chat history I/O failed: disk full", dir),
            "local protected history unavailable: chat history I/O failed: disk full"
        );
    }

    #[test]
    fn an_unusable_cursor_file_is_named_and_the_cost_of_moving_it_is_stated() {
        let text =
            cursor_unavailable_text("inbox cursor corrupt: expected value", Path::new("/data"));
        for word in [
            "chat not opened",
            "/data/chat_inbox_cursors.json",
            "Your messages and contacts are not affected",
            "If you move that file aside",
            // The file also remembers cleared conversations: moving it brings
            // their old messages back, so that must be said, not hidden.
            "you cleared with /clear-local-history show their old messages again",
            "(technical: inbox cursor corrupt: expected value)",
        ] {
            assert!(text.contains(word), "{word:?} missing from: {text}");
        }
        assert!(!text.contains("safe to move"), "{text}");
    }

    #[test]
    fn the_background_reader_explains_a_history_problem_too() {
        let dir = Path::new("/data");
        let corrupt = inbox_problem_text("chat history is corrupt", dir);
        assert!(
            corrupt.starts_with("inbox: your local chat history cannot be opened"),
            "{corrupt}"
        );
        assert!(corrupt.contains("/data/chat_history.json"), "{corrupt}");
        assert!(
            corrupt.contains("(technical: chat history is corrupt)"),
            "{corrupt}"
        );
        // Anything else is shown as it was.
        assert_eq!(inbox_problem_text("boom", dir), "inbox: boom");
    }

    #[test]
    fn blocking_asks_first_and_names_the_undo() {
        // The confirm itself reads the process stdin; the pieces around it are pure.
        let ctx = SendCtx {
            pub_hex: "cd".repeat(32),
            ..SendCtx::default()
        };
        assert_eq!(
            unblock_hint(&ctx),
            format!("To undo: ash contact unblock --pub-hex {}", "cd".repeat(32))
        );
        assert!(unblock_hint(&SendCtx::default()).contains("--pub-hex <their key>"));
    }
}
