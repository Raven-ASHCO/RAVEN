//! Black-box checks of what `ash` tells the user: how a send ends (delivered /
//! queued / NOT SENT), what the chat does with `help` / `exit` / `/block` /
//! `/verify` and with a line in the wrong encoding, and how a dead or hung local
//! service is reported.
//!
//! Every run uses throwaway profiles and the file-backed (`locked-file`) secret
//! stores, so nothing here can reach the OS keychain or the network. The local
//! daemon is faked by a UDS server in the test process (it answers Ping, Status
//! and LanDial, the last by driving a second profile's real `dispatch_frame`),
//! so the real `ash` binary sees an "already running" service and starts none.
//!
//! Unix only: the planted 0600 identity seed and the UDS are the unix layout.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use raven_core::chat_history::BlockList;
use raven_core::device_cert::ensure_local_device_certificate;
use raven_core::fingerprint::device_fingerprint_v1;
use raven_core::identity::Identity;
use raven_core::ipc::{decode_request, encode_response, IpcRequest, IpcResponse, IPC_VERSION};
use raven_core::lan_dispatch::{dispatch_frame, encode_local_offer, local_bundle};
use raven_core::paths::PRIMARY_DEVICE_ID;

/// The identity `plant_identity` writes (a 0600 locked-file seed).
const SEED: u8 = 0x5a;

fn ash(dir: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_ash"));
    c.arg("--data-dir")
        .arg(dir)
        .env("RAVEN_IDENTITY_BACKEND", "locked-file")
        .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
        .env("RAVEN_PREKEY_BACKEND", "locked-file")
        .env("RAVEN_SESSION_BACKEND", "locked-file")
        .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
        .env("NO_COLOR", "1")
        .env_remove("RAVEN_PEER")
        .env_remove("ASH_LAN_DIAL")
        .env_remove("RAVEN_VERBOSE")
        .env_remove("ASH_VERBOSE")
        .env_remove("RAVEN_SERVICE_LAN_LISTEN");
    c
}

fn run(mut c: Command, stdin: &[u8]) -> Output {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ash");
    // The child may exit without reading its stdin: a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().expect("wait ash")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

/// A private profile directory whose socket path fits `sun_path`.
fn short_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    if dir.path().as_os_str().len() <= 60 {
        return dir;
    }
    tempfile::Builder::new()
        .prefix("ux")
        .tempdir_in("/tmp")
        .unwrap()
}

fn plant_identity(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let seed = dir.join("identity.seed");
    std::fs::write(&seed, [SEED; 32]).unwrap();
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn pub_hex(id: &Identity) -> String {
    hex::encode(id.public_key_bytes())
}

/// If a bug ever made one of these runs start a real service, do not leave it
/// behind: stop the one for this profile (and only that one).
struct StopService(PathBuf);

impl Drop for StopService {
    fn drop(&mut self) {
        let _ = Command::new("pkill")
            .args([
                "-f",
                &format!("raven-node service --data-dir {}", self.0.display()),
            ])
            .status();
    }
}

fn add_bob(dir: &Path, bob: &Identity, dial: &str) {
    let mut c = ash(dir);
    c.args(["contact", "add", "--address", &bob.address()])
        .args(["--pub-hex", &pub_hex(bob)])
        .args(["--petname", "Bob", "--tag", "bob", "--lan-dial", dial]);
    let o = run(c, b"");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
}

// ── the chat ────────────────────────────────────────────────────────────────

fn chat_profile() -> (tempfile::TempDir, Identity, StopService) {
    let dir = short_dir();
    plant_identity(dir.path());
    let bob = Identity::from_seed(&[0x42; 32]);
    add_bob(dir.path(), &bob, "127.0.0.1:9");
    let guard = StopService(dir.path().to_path_buf());
    (dir, bob, guard)
}

fn chat(dir: &Path, stdin: &[u8]) -> Output {
    let mut c = ash(dir);
    c.args(["send", "--contact", "@bob", "--chat"]);
    run(c, stdin)
}

#[test]
fn chat_commands_typed_as_words_are_not_sent_to_the_friend() {
    let (dir, _bob, _guard) = chat_profile();
    let o = chat(dir.path(), b"help\n/help\nexit\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{err}");
    assert!(
        out.contains("\"help\" is not sent to Bob; here are the chat commands:"),
        "{out}"
    );
    for command in [
        "/help",
        "/back",
        "/info",
        "/verify",
        "/block",
        "/clear-local-history",
    ] {
        assert!(out.contains(command), "{command} missing: {out}");
    }
    assert!(
        out.contains("\"exit\" leaves the chat; it is not sent to Bob."),
        "{out}"
    );
    assert!(out.contains("left chat"), "{out}");
    // Nothing reached the send path: no refusal text, no service was started.
    assert!(
        !out.contains("NOT SENT") && !err.contains("NOT SENT"),
        "{out}\n{err}"
    );
    assert!(
        !dir.path().join("raven-node-service.log").exists(),
        "a send would have started the service"
    );
    // The receiver is not running here: the chat says so up front, once.
    assert!(
        err.contains("raven-node is not running, so replies from Bob cannot arrive yet"),
        "{err}"
    );
    assert_eq!(err.matches("replies from Bob").count(), 1, "{err}");
    assert!(err.contains("ash listen"), "{err}");
}

/// A damaged cursor file used to end the chat with a bare line and exit status 0.
#[test]
fn a_chat_that_cannot_open_says_why_and_fails() {
    let (dir, _bob, _guard) = chat_profile();
    let cursors = dir.path().join("chat_inbox_cursors.json");
    std::fs::write(&cursors, b"{not json").unwrap();
    let o = chat(dir.path(), b"hello\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(err.contains("chat not opened"), "{err}");
    assert!(err.contains(&cursors.display().to_string()), "{err}");
    assert!(
        err.contains("Your messages and contacts are not affected"),
        "{err}"
    );
    assert!(err.contains("(technical: inbox cursor corrupt"), "{err}");
    assert!(!out.contains("left chat"), "it never opened: {out}");
    assert_eq!(
        std::fs::read(&cursors).unwrap(),
        b"{not json",
        "the file is left alone"
    );
    assert!(
        !dir.path().join("raven-node-service.log").exists(),
        "nothing was sent or started"
    );
}

#[test]
fn chat_quit_leaves_and_the_header_points_to_help() {
    let (dir, _bob, _guard) = chat_profile();
    let o = chat(dir.path(), b"quit\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("chat with Bob @bob"), "{out}");
    assert!(out.contains("/help lists the commands"), "{out}");
    assert_eq!(out.matches("left chat").count(), 1, "{out}");
}

/// A line in a legacy encoding is dropped with a message, and the chat goes on:
/// the `/help` after it still runs, and only the `/back` ends the session.
#[test]
fn chat_survives_a_line_that_is_not_utf8() {
    let (dir, _bob, _guard) = chat_profile();
    let o = chat(dir.path(), b"\xed\xa1\xe4\xe3\n/help\n/back\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{err}");
    assert!(
        err.contains("input was not valid UTF-8, line skipped"),
        "{err}"
    );
    assert!(
        out.contains("/clear-local-history"),
        "the chat went on: {out}"
    );
    assert_eq!(out.matches("left chat").count(), 1, "{out}");
    assert!(
        !dir.path().join("raven-node-service.log").exists(),
        "the dropped line was not sent"
    );
}

#[test]
fn chat_block_asks_first_and_names_the_undo() {
    // End of input, or anything but yes, cancels.
    for (input, left_by_command) in [
        (&b"/block\n"[..], false),
        (&b"/block\nno\n/back\n"[..], true),
    ] {
        let (dir, bob, _guard) = chat_profile();
        let o = chat(dir.path(), input);
        let out = text(&o.stdout);
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        assert!(out.contains("Block Bob?"), "{out}");
        assert!(
            out.contains("Type yes to block; anything else cancels"),
            "{out}"
        );
        assert!(out.contains("not blocked"), "{out}");
        assert!(
            out.contains("left chat"),
            "the chat went on ({left_by_command}): {out}"
        );
        assert!(
            !BlockList::load_checked(dir.path())
                .unwrap()
                .is_blocked(&pub_hex(&bob)),
            "nobody is blocked without a yes"
        );
    }

    // A yes blocks, says who, names the undo, and ends the chat.
    let (dir, bob, _guard) = chat_profile();
    let o = chat(dir.path(), b"/block\nyes\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("blocked Bob."), "{out}");
    assert!(
        out.contains(&format!(
            "To undo: ash contact unblock --pub-hex {}",
            pub_hex(&bob)
        )),
        "{out}"
    );
    assert_eq!(
        out.matches(&pub_hex(&bob)).count(),
        1,
        "the key appears once, inside the undo command, never as the confirmation: {out}"
    );
    assert!(out.contains("left chat"), "blocking ends the chat: {out}");
    assert!(BlockList::load_checked(dir.path())
        .unwrap()
        .is_blocked(&pub_hex(&bob)));

    // Afterwards a send says so, names the undo, and starts nothing.
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@bob"]);
    let o = run(c, b"hi\n");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(
        err.contains("NOT SENT: Bob is blocked on this computer."),
        "{err}"
    );
    assert!(err.contains("ash contact unblock --pub-hex"), "{err}");
    assert!(
        !dir.path().join("raven-node-service.log").exists(),
        "a blocked send must not start the service"
    );
}

#[test]
fn chat_verify_says_what_it_does_and_how_to_mark_the_contact_verified() {
    let (dir, bob, _guard) = chat_profile();
    let fp = device_fingerprint_v1(&bob.public_key_bytes());
    let o = chat(dir.path(), b"/verify\n/back\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let words = [
        format!("fingerprint {fp}"),
        "THEIR identity".to_string(),
        "by phone or in person, not in this chat".to_string(),
        "This only shows it; nothing is changed".to_string(),
        "Bob is not marked verified yet".to_string(),
        // The pin command takes what Bob READ OUT, never the fingerprint shown
        // here (pasting that back would verify the key against itself).
        format!(
            "ash contact add --address {} --pub-hex {} --verify-fp <the fingerprint Bob read out to you>",
            bob.address(),
            pub_hex(&bob)
        ),
    ];
    for word in &words {
        assert!(out.contains(word.as_str()), "{word:?} missing from: {out}");
    }
    assert!(!out.contains("ash contact verify"), "{out}");
    assert!(
        !out.contains(&format!("--verify-fp {fp}")),
        "the command must not embed the fingerprint it is meant to check: {out}"
    );
}

#[test]
fn a_whitespace_only_message_is_refused_before_anything_starts() {
    let (dir, _bob, _guard) = chat_profile();
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@bob"]);
    let o = run(c, b"   \n\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.contains("NOT SENT: the message is empty"), "{err}");
    assert!(err.contains("Nothing was queued"), "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "{out}");
    assert!(!dir.path().join("raven-node-service.log").exists());
}

// ── the local service, dead or hung ─────────────────────────────────────────

#[test]
fn ipc_ping_without_a_service_says_so_and_how_to_start_it() {
    let dir = short_dir();
    let mut c = ash(dir.path());
    c.arg("ipc-ping");
    let o = run(c, b"");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(!out.contains("ipc pong"), "{out}");
    assert!(
        err.contains("ipc ping failed: raven-node is not running"),
        "{err}"
    );
    assert!(err.contains("ash listen"), "{err}");
    assert!(
        err.contains("No such file"),
        "the OS text stays at the end for a log search: {err}"
    );
}

/// A service that accepts the connection and never answers (stopped, deadlocked,
/// or blocked on a Keychain dialog) is reported within seconds, not 10 s of
/// silence, and as "not answering", not as an OS error.
#[test]
fn a_hung_service_is_reported_in_seconds_as_not_answering() {
    let dir = short_dir();
    let listener = UnixListener::bind(raven_core::default_socket_path(dir.path())).unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = stop.clone();
    let server = std::thread::spawn(move || {
        let mut held: Vec<UnixStream> = Vec::new();
        while !stop_c.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => held.push(stream),
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    let mut c = ash(dir.path());
    c.arg("ipc-ping");
    let started = Instant::now();
    let o = run(c, b"");
    let waited = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    server.join().unwrap();
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(waited < Duration::from_secs(8), "bounded: {waited:?}");
    assert!(
        err.contains("ipc ping failed: raven-node did not answer in time"),
        "{err}"
    );
    assert!(err.contains("ash doctor"), "{err}");
    assert!(!err.contains("not running"), "stuck is not absent: {err}");
}

#[test]
fn status_names_a_service_that_is_not_running_in_plain_words() {
    let dir = short_dir();
    plant_identity(dir.path());
    let mut c = ash(dir.path());
    c.arg("status");
    let o = run(c, b"");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("raven-node is not running"), "{out}");
    assert!(out.contains("ash listen"), "{out}");
}

// ── the service a send starts (the real raven-node, when it is built) ───────

/// The `raven-node` that sits next to `ash` (what `ash` itself would start), or
/// `None` when this test run did not build it (`cargo test -p ash` alone).
fn raven_node_next_to_ash() -> Option<PathBuf> {
    let node = Path::new(env!("CARGO_BIN_EXE_ash")).with_file_name("raven-node");
    node.exists().then_some(node)
}

/// The number after `marker` in `text` (a process id the notice printed).
fn number_after(text: &str, marker: &str) -> Option<u32> {
    let rest = text.split(marker).nth(1)?;
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

fn process_command(pid: u32) -> String {
    let out = Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    text(&out.stdout).trim().to_string()
}

/// A send into a profile with no service starts one. The notice says what was
/// started, that it outlives ash, and how to stop only that one process: its id
/// (and the profile's own command line proves the id is the right one).
#[test]
fn starting_the_service_says_what_it_is_and_how_to_stop_only_it() {
    if raven_node_next_to_ash().is_none() {
        eprintln!("skipped: raven-node is not built next to ash");
        return;
    }
    let (dir, _bob, guard) = chat_profile();
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@bob"])
        .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0");
    let o = run(c, b"hello\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    let pid = number_after(&err, "started raven-node (process ").expect(&err);
    let alive = Command::new("kill")
        .args(["-0", &pid.to_string()])
        .status()
        .unwrap()
        .success();
    let command = process_command(pid);
    let _ = Command::new("kill").arg(pid.to_string()).status();
    drop(guard);

    assert!(alive, "the service keeps running after ash exits: {err}");
    assert!(
        command.contains(&format!(
            "raven-node service --data-dir {}",
            dir.path().display()
        )),
        "the id belongs to THIS profile's service: {command}"
    );
    for word in [
        "notice: started raven-node (process",
        "RAVEN's background service for this profile. It keeps running after ash exits.",
        &format!("stop only this one with: kill {pid}"),
        &format!(
            "log: {}",
            dir.path().join("raven-node-service.log").display()
        ),
        "it is receiving messages (this computer only)",
    ] {
        assert!(err.contains(word), "{word:?} missing from: {err}");
    }
    assert!(!err.contains("pkill"), "no blanket stop advice: {err}");
    assert!(!err.contains("IPC + LAN receive on"), "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "{out}");
    // The peer is unreachable (nothing listens on port 9): the send says so.
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.contains("NOT SENT: Bob's computer is there"), "{err}");
}

/// The port this profile would receive on is taken (a second profile on the same
/// computer always meets this): the service runs and sending works, but the
/// computer is deaf, and the user is told so, with the way out.
#[test]
fn a_busy_lan_port_is_reported_as_not_receiving_with_the_way_out() {
    if raven_node_next_to_ash().is_none() {
        eprintln!("skipped: raven-node is not built next to ash");
        return;
    }
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let (dir, _bob, guard) = chat_profile();
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@bob"])
        .env("RAVEN_SERVICE_LAN_LISTEN", format!("127.0.0.1:{port}"));
    let o = run(c, b"hello\n");
    let err = text(&o.stderr);
    let pid = number_after(&err, "started raven-node (process ");
    if let Some(pid) = pid {
        let _ = Command::new("kill").arg(pid.to_string()).status();
    }
    drop(guard);
    drop(taken);

    for word in [
        "warning: this computer is NOT receiving messages".to_string(),
        format!("LAN port 127.0.0.1:{port} is busy or unavailable"),
        format!(
            "(log: {})",
            dir.path().join("raven-node-service.log").display()
        ),
        "Sending still works.".to_string(),
        // The way out must work: the running service keeps its busy port, so the
        // variable only helps after it is stopped (and it names how, by pid).
        "free that port (the service keeps retrying by itself)".to_string(),
        format!(
            "run ash again with RAVEN_SERVICE_LAN_LISTEN=127.0.0.1:{}",
            port + 1
        ),
        "Setting the variable while this service keeps running changes nothing".to_string(),
    ] {
        assert!(err.contains(&word), "{word:?} missing from: {err}");
    }
    let pid = pid.expect("the started notice names the service process");
    let stop = if cfg!(windows) {
        format!("taskkill /F /PID {pid}")
    } else {
        format!("kill {pid}")
    };
    assert!(
        err.contains(&format!("stop this service ({stop})")),
        "{stop:?} missing from: {err}"
    );
    assert!(!err.contains("it is receiving messages"), "{err}");
    assert!(!err.contains("IPC + LAN receive on"), "{err}");
    assert_eq!(err.matches("is NOT receiving").count(), 1, "once: {err}");
    // Sending still got as far as the peer (nothing listens on port 9).
    assert!(err.contains("NOT SENT: Bob's computer is there"), "{err}");
}

// ── how a send ends, against a faked local service and a real peer ──────────

const UP: u8 = 0;
const DOWN: u8 = 1;
const WRONG_KEY: u8 = 2;
/// Bob answers every message with the FIRST ACK he ever sent (a stale or
/// replayed receipt for an earlier message).
const STALE_ACK: u8 = 3;

const REFUSED: &str =
    "lan connect: cannot connect to 127.0.0.1:9 (127.0.0.1:9: Connection refused (os error 61))";
const PEER_CLOSED: &str = "LAN_DIAL_PEER_CLOSED: the peer closed the connection without replying; \
     the frames were sent, delivery is unconfirmed and a retry is safe";

fn lab_backends() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        for key in [
            "RAVEN_SESSION_BACKEND",
            "RAVEN_PREKEY_BACKEND",
            "RAVEN_CHAT_HISTORY_BACKEND",
            "RAVEN_IDENTITY_BACKEND",
        ] {
            unsafe { std::env::set_var(key, "locked-file") };
        }
    });
}

/// Alice (the profile under test, run by the real `ash`) and Bob (a second
/// profile the faked service drives), joined by a UDS server on Alice's socket.
struct Net {
    a: tempfile::TempDir,
    b: tempfile::TempDir,
    mode: Arc<AtomicU8>,
    /// The faked service runs raven-node's background outbox (it accepts
    /// `OutboxKick`); off, it answers like an older service.
    outbox: Arc<AtomicBool>,
}

impl Net {
    /// `bob_trusts_alice`: Bob has Alice in his contacts (otherwise he refuses
    /// her first message, as a stranger's).
    fn new(bob_trusts_alice: bool) -> Self {
        lab_backends();
        let (a, b) = (short_dir(), short_dir());
        let alice = Identity::from_seed(&[SEED; 32]);
        let bob = Identity::from_seed(&[0x42; 32]);
        plant_identity(a.path());
        for (dir, id) in [(a.path(), &alice), (b.path(), &bob)] {
            ensure_local_device_certificate(dir, id, PRIMARY_DEVICE_ID).unwrap();
            raven_core::ensure_local_prekey(dir, id).unwrap();
        }
        add_bob(a.path(), &bob, "127.0.0.1:9");
        if bob_trusts_alice {
            let row = serde_json::json!([{
                "petname": "Alice", "public_tag": "", "alias": "",
                "address": alice.address(), "pub_hex": pub_hex(&alice),
                "pinned": false, "lan_dial": ""
            }]);
            std::fs::write(b.path().join("contacts.json"), row.to_string()).unwrap();
        }
        let a_bundle = local_bundle(a.path(), &alice).unwrap();
        let mode = Arc::new(AtomicU8::new(UP));
        let outbox = Arc::new(AtomicBool::new(false));
        let listener = UnixListener::bind(raven_core::default_socket_path(a.path())).unwrap();
        let (b_dir, bob_c, mode_c, outbox_c) = (
            b.path().to_path_buf(),
            Identity::from_seed(&[0x42; 32]),
            mode.clone(),
            outbox.clone(),
        );
        let alice_pub = alice.public_key_bytes();
        std::thread::spawn(move || {
            let first_ack = std::sync::Mutex::new(None::<Vec<u8>>);
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                serve_one(
                    &mut stream,
                    &b_dir,
                    &bob_c,
                    &a_bundle,
                    &alice_pub,
                    &mode_c,
                    &first_ack,
                    &outbox_c,
                );
            }
        });
        Self { a, b, mode, outbox }
    }

    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }

    fn set_outbox(&self, running: bool) {
        self.outbox.store(running, Ordering::SeqCst);
    }

    fn send(&self, message: &str) -> Output {
        let mut c = ash(self.a.path());
        c.args(["send", "--contact", "@bob"]);
        run(c, format!("{message}\n").as_bytes())
    }

    fn bob_inbox(&self) -> Vec<String> {
        let mut store = raven_core::IndexedSessionStore::open(self.b.path()).unwrap();
        let mut texts: Vec<String> = store
            .list_endpoint_inbox()
            .unwrap()
            .into_iter()
            .map(|row| String::from_utf8_lossy(&row.plaintext).into_owned())
            .collect();
        texts.sort();
        texts
    }
}

/// One framed `IpcRequest` in, one framed `IpcResponse` out.
#[allow(clippy::too_many_arguments)]
fn serve_one(
    stream: &mut UnixStream,
    b_dir: &Path,
    bob: &Identity,
    a_bundle: &raven_core::LanBundle,
    alice_pub: &[u8; 32],
    mode: &AtomicU8,
    first_ack: &std::sync::Mutex<Option<Vec<u8>>>,
    outbox: &AtomicBool,
) {
    let mut len = [0u8; 4];
    if stream.read_exact(&mut len).is_err() {
        return;
    }
    let mut frame = len.to_vec();
    frame.resize(4 + u32::from_be_bytes(len) as usize, 0);
    if stream.read_exact(&mut frame[4..]).is_err() {
        return;
    }
    let error = |message: &str| IpcResponse::Error {
        v: IPC_VERSION,
        code: "LAN_DIAL".into(),
        message: message.into(),
    };
    let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);
    let response = match decode_request(&frame) {
        Ok(IpcRequest::Ping { .. }) => IpcResponse::Pong { v: IPC_VERSION },
        Ok(IpcRequest::Status { .. }) => IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into(), "lan_direct".into()],
            p2p: None,
        },
        Ok(IpcRequest::LanDial { frames_b64, .. }) => match mode.load(Ordering::SeqCst) {
            DOWN => error(REFUSED),
            WRONG_KEY => error("identity bind does not match expected pub"),
            _ => {
                let offer = encode_local_offer(b_dir, bob).unwrap();
                let mut replies = vec![b64(&offer)];
                let mut failure = None;
                for b64_frame in &frames_b64 {
                    let f = base64::engine::general_purpose::STANDARD
                        .decode(b64_frame)
                        .unwrap();
                    match dispatch_frame(b_dir, bob, a_bundle, alice_pub, &f) {
                        Ok(more) => {
                            for reply in more {
                                let is_ack = raven_core::Envelope::unpack(&reply)
                                    .is_some_and(|e| e.env_type == raven_core::EnvType::Ack as u8);
                                let mut kept = first_ack.lock().unwrap();
                                let reply = match (is_ack, kept.as_ref()) {
                                    (true, None) => {
                                        *kept = Some(reply.clone());
                                        reply
                                    }
                                    (true, Some(old))
                                        if mode.load(Ordering::SeqCst) == STALE_ACK =>
                                    {
                                        old.clone()
                                    }
                                    _ => reply,
                                };
                                replies.push(b64(&reply));
                            }
                        }
                        // The daemon closes on a dispatch error: the dialer sees a
                        // silent peer (the stranger case).
                        Err(_) => {
                            failure = Some(PEER_CLOSED.to_string());
                            break;
                        }
                    }
                }
                match failure {
                    Some(text) => error(&text),
                    None => IpcResponse::LanDialResult {
                        v: IPC_VERSION,
                        frames_b64: replies,
                    },
                }
            }
        },
        Ok(IpcRequest::OutboxKick { .. }) if outbox.load(Ordering::SeqCst) => {
            IpcResponse::Accepted { v: IPC_VERSION }
        }
        _ => error("unsupported request"),
    };
    let _ = stream.write_all(&encode_response(&response).unwrap());
}

#[test]
fn a_delivered_send_names_the_person_keeps_the_status_line_and_drops_the_jargon() {
    let net = Net::new(true);
    let o = net.send("hello Bob");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.lines()
            .any(|l| l == "First time talking to Bob: secure connection set up."),
        "{out}"
    );
    // The literal scripts and the iOS gate match, on stdout, with the person.
    assert!(
        out.lines()
            .any(|l| l == "status delivered — Bob confirmed receipt"),
        "{out}"
    );
    for jargon in [
        "PairResponse",
        "mid=",
        "carrier=",
        "indexed message",
        "queued after dial",
    ] {
        assert!(!out.contains(jargon), "{jargon} in default output: {out}");
    }
    assert_eq!(
        err, "",
        "the service was already running: nothing to announce"
    );
    assert_eq!(net.bob_inbox(), vec!["hello Bob"]);

    // The second message needs no first-contact line.
    let o = net.send("second");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{out}");
    assert!(!out.contains("First time"), "{out}");
    assert!(
        out.contains("status delivered — Bob confirmed receipt"),
        "{out}"
    );
    assert_eq!(net.bob_inbox(), vec!["hello Bob", "second"]);
}

#[test]
fn a_stranger_is_told_to_ask_to_be_added_and_nothing_says_delivered() {
    let net = Net::new(false);
    let o = net.send("stranger probe");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(!out.to_lowercase().contains("delivered"), "stdout: {out}");
    assert!(
        err.starts_with("NOT SENT: Bob did not accept your first message"),
        "{err}"
    );
    assert!(err.contains("has not added you as a contact yet"), "{err}");
    assert!(err.contains("Nothing was queued"), "{err}");
    assert!(err.contains("ash whoami"), "{err}");
    let sentence = err.split("(technical:").next().unwrap();
    assert!(!sentence.contains("retry is safe"), "{err}");
    assert!(
        err.contains("(technical: ipc LAN_DIAL: LAN_DIAL_PEER_CLOSED"),
        "{err}"
    );
    assert!(net.bob_inbox().is_empty());
}

#[test]
fn an_unreachable_first_contact_says_nothing_was_queued_and_why() {
    let net = Net::new(true);
    net.set_mode(DOWN);
    let o = net.send("anyone there");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "{out}");
    assert!(
        err.starts_with(
            "NOT SENT: Bob's computer is there, but RAVEN is not listening at 127.0.0.1:9."
        ),
        "{err}"
    );
    assert!(
        err.contains("Nothing was queued: a first message needs Bob to be online."),
        "{err}"
    );
    assert!(
        err.contains("ash contact set-dial --petname Bob --lan-dial IP:PORT"),
        "{err}"
    );
    assert!(
        err.contains("Connection refused"),
        "the raw text stays at the end: {err}"
    );
}

#[test]
fn a_changed_address_is_flagged_as_a_different_computer() {
    let net = Net::new(true);
    net.set_mode(WRONG_KEY);
    let o = net.send("hi");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(err.contains("answered, but it is not Bob"), "{err}");
    assert!(err.contains("compare the fingerprint"), "{err}");
    assert!(err.contains("ash contact remove --petname Bob"), "{err}");
    assert!(err.starts_with("NOT SENT: "), "{err}");
}

/// The whole life of a queued message: sent while the peer is down (queued, with
/// the real retry rule), refused behind it, then delivered by the next send, and
/// every line says which text it is about.
#[test]
fn a_queued_message_is_named_by_its_text_and_delivered_by_the_next_send() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    net.set_mode(DOWN);

    let o = net.send("are you there");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "stdout: {out}");
    assert!(
        err.starts_with(
            "not delivered yet: your message \"are you there\" to Bob is queued locally because"
        ),
        "{err}"
    );
    // This faked service has no background outbox (an older raven-node): the
    // next send retries it, until the envelope's expiry a day from now.
    assert!(err.contains("It is NOT retried automatically"), "{err}");
    assert!(err.contains("UTC (in about 24 h)"), "{err}");

    let o = net.send("second one");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1, "{err}");
    assert!(
        err.starts_with(
            "NOT SENT: an earlier message \"are you there\" to Bob is still undelivered"
        ),
        "{err}"
    );
    assert!(
        err.contains("this message was not queued behind it"),
        "{err}"
    );

    net.set_mode(UP);
    let o = net.send("third");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.lines().any(|l| l
            == "status delivered — your earlier message \"are you there\" to Bob has now arrived and Bob confirmed it"),
        "{out}"
    );
    assert!(
        out.lines()
            .any(|l| l == "status delivered — Bob confirmed receipt"),
        "{out}"
    );
    assert_eq!(net.bob_inbox(), vec!["are you there", "first", "third"]);
}

/// With raven-node's background outbox the queued sentence says so: nothing to
/// do, no retyping, and until when it keeps trying (a day, the envelope's
/// validity). The send itself returns at once instead of waiting it out.
#[test]
fn a_queued_message_is_handed_to_the_background_outbox() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    net.set_mode(DOWN);
    net.set_outbox(true);
    let started = std::time::Instant::now();
    let o = net.send("are you there");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "a queued send ends within 10 s"
    );
    assert_eq!(code(&o), 1, "not delivered yet: {err}");
    assert!(!out.to_lowercase().contains("delivered"), "stdout: {out}");
    assert!(
        err.starts_with(
            "not delivered yet: your message \"are you there\" to Bob is queued locally because"
        ),
        "{err}"
    );
    for words in [
        "Queued: raven-node keeps trying in the background until ",
        "UTC (in about 24 h)",
        "you do not need to send it again",
        "Do not retype this message: it goes out as soon as Bob can be reached.",
    ] {
        assert!(err.contains(words), "{words:?} missing: {err}");
    }
    assert!(!err.contains("NOT retried"), "{err}");
    // The routes this send used are recorded for the worker (hints only).
    let routes = std::fs::read_to_string(net.a.path().join("outbox_routes.json")).unwrap();
    assert!(routes.contains("127.0.0.1:9"), "{routes}");
}

/// A local chat-history failure while the message is being staged leaves nothing
/// pending: "nothing was queued" is true, and a later send does not silently
/// deliver the text the user was told was NOT sent (retyping it, as advised,
/// would then have sent it twice).
#[test]
fn a_history_failure_while_staging_leaves_nothing_behind_to_deliver_later() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);
    let history = net.a.path().join("chat_history.json");
    let good = std::fs::read(&history).expect("a delivered send wrote the chat history");
    let mut bad = good.clone();
    for byte in bad.iter_mut().skip(8).take(80) {
        *byte ^= 0xA5;
    }
    std::fs::write(&history, &bad).unwrap();

    let o = net.send("lost text");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 1, "{out}\n{err}");
    assert!(err.starts_with("NOT SENT: "), "{err}");
    assert!(err.contains("Nothing was queued"), "{err}");
    assert!(!out.to_lowercase().contains("delivered"), "{out}");

    std::fs::write(&history, &good).unwrap();
    let o = net.send("next");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        !out.contains("earlier message"),
        "the text that was reported as not sent must not come back: {out}"
    );
    assert_eq!(net.bob_inbox(), vec!["first", "next"]);
}

/// An ACK that belongs to an EARLIER message (a stale or replayed receipt) must
/// never make the new message read "delivered": the new message stays
/// unconfirmed and is confirmed by a later send, once its own ACK comes back.
#[test]
fn an_ack_for_an_earlier_message_never_marks_the_new_one_delivered() {
    let net = Net::new(true);
    assert_eq!(code(&net.send("first")), 0);

    net.set_mode(STALE_ACK);
    let o = net.send("second");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_ne!(code(&o), 0, "{out}\n{err}");
    assert!(
        !out.contains("status delivered"),
        "a receipt for \"first\" must not confirm \"second\": {out}"
    );
    assert!(err.starts_with("sent, delivery unconfirmed"), "{err}");
    assert_eq!(net.bob_inbox(), vec!["first", "second"], "Bob did get it");

    net.set_mode(UP);
    let o = net.send("third");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{out}\n{err}");
    assert!(
        out.contains("your earlier message \"second\""),
        "its own ACK confirms it on the next send: {out}"
    );
    assert_eq!(net.bob_inbox(), vec!["first", "second", "third"]);
}

/// The chat shows what it sent and what happened to it, in plain words.
#[test]
fn the_chat_echoes_what_it_sent_with_the_outcome() {
    let net = Net::new(true);
    let mut c = ash(net.a.path());
    c.args(["send", "--contact", "@bob", "--chat"]);
    let o = run(c, b"hello bob\n/back\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{err}");
    assert!(out.contains("(secure connection with Bob set up)"), "{out}");
    assert!(
        out.contains("→ hello bob  ✓ Bob confirmed receipt"),
        "{out}"
    );
    assert!(
        !out.contains("status delivered"),
        "the chat has its own transcript line: {out}"
    );
    assert_eq!(err, "", "service up and receiving: no warning: {err}");
    assert_eq!(net.bob_inbox(), vec!["hello bob"]);

    net.set_mode(DOWN);
    let mut c = ash(net.a.path());
    c.args(["send", "--contact", "@bob", "--chat"]);
    let o = run(c, b"are you there\n/back\n");
    let (out, err) = (text(&o.stdout), text(&o.stderr));
    assert_eq!(code(&o), 0, "{err}");
    assert!(
        out.contains("→ are you there  [queued: goes out with your next message]"),
        "{out}"
    );
    assert!(
        !out.to_lowercase().contains("delivered"),
        "stdout never claims delivery: {out}"
    );
    assert!(
        err.contains("not delivered yet: your message \"are you there\" to Bob is queued locally"),
        "{err}"
    );
}
