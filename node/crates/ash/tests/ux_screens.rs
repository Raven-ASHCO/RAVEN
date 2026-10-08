//! Black-box checks of the plain-language screens of `ash`: help and version,
//! the first-run offer, the menu text, `status` / `doctor` / `inbox` saying what
//! is going on, how a contact is named and saved, and `--contact <petname>`.
//!
//! Every run uses a throwaway profile and the file-backed (`locked-file`)
//! secret stores, so nothing here can reach the OS keychain or the network. The
//! local node is either absent or faked by a UDS server inside the test (it only
//! answers Ping and Status), so no run starts a real `raven-node`.
//!
//! Unix only: the planted 0600 identity seed and the UDS are the unix layout.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use raven_core::identity::Identity;
use raven_core::ipc::{decode_request, encode_response, IpcRequest, IpcResponse, IPC_VERSION};

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
        .env_remove("RAVEN_SERVICE_LAN_LISTEN");
    c
}

fn run(mut c: Command, stdin: &str) -> Output {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ash");
    // The child may exit without reading its stdin: a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin.as_bytes());
    child.wait_with_output().expect("wait ash")
}

/// `ash --data-dir <dir> <args>` run to completion with `stdin`.
fn ash_out(dir: &Path, args: &[&str], stdin: &str) -> Output {
    let mut c = ash(dir);
    c.args(args);
    run(c, stdin)
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
    std::fs::write(&seed, [0x5au8; 32]).unwrap();
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn pub_hex(id: &Identity) -> String {
    hex::encode(id.public_key_bytes())
}

fn add_bob(dir: &Path, petname: &str) -> Identity {
    let bob = Identity::from_seed(&[0x42; 32]);
    let mut c = ash(dir);
    c.args(["contact", "add", "--address", &bob.address()])
        .args(["--pub-hex", &pub_hex(&bob), "--petname", petname]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    bob
}

/// A local node that answers Ping and Status (with `caps`) and nothing else.
struct FakeNode {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl FakeNode {
    fn start(dir: &Path, caps: &[&str]) -> Self {
        let listener = UnixListener::bind(raven_core::default_socket_path(dir)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_c = stop.clone();
        let caps: Vec<String> = caps.iter().map(|c| c.to_string()).collect();
        let thread = std::thread::spawn(move || {
            while !stop_c.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut frame = len.to_vec();
                frame.resize(4 + u32::from_be_bytes(len) as usize, 0);
                if stream.read_exact(&mut frame[4..]).is_err() {
                    continue;
                }
                let response = match decode_request(&frame) {
                    Ok(IpcRequest::Ping { .. }) => IpcResponse::Pong { v: IPC_VERSION },
                    Ok(IpcRequest::Status { .. }) => IpcResponse::Status {
                        v: IPC_VERSION,
                        bridge: true,
                        store: true,
                        relay: false,
                        forward_pending: 0,
                        capabilities: caps.clone(),
                    },
                    _ => IpcResponse::Error {
                        v: IPC_VERSION,
                        code: "UNSUPPORTED".into(),
                        message: "not faked".into(),
                    },
                };
                let _ = stream.write_all(&encode_response(&response).unwrap());
            }
        });
        FakeNode {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for FakeNode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ── help and version ────────────────────────────────────────────────────────

#[test]
fn version_and_help_are_plain_and_the_example_starts_with_adding_each_other() {
    let dir = tempfile::tempdir().unwrap();
    let o = ash_out(dir.path(), &["--version"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout).starts_with("ash "), "{}", text(&o.stdout));

    let o = ash_out(dir.path(), &["--help"], "");
    let help = text(&o.stdout);
    assert_eq!(code(&o), 0);
    assert!(help.to_lowercase().contains("raven"), "{help}");
    // The worked example: both add each other first, the receiver listens.
    assert!(help.contains("FIRST CHAT"), "{help}");
    assert!(
        help.contains("ash whoami") && help.contains("invite"),
        "{help}"
    );
    assert!(help.contains("ash listen"), "{help}");
    assert!(
        help.contains("echo \"hello\" | ash send --contact Bob"),
        "{help}"
    );
    assert!(help.contains("added each other"), "{help}");
    // Nothing a repository checkout is needed for, no developer vocabulary.
    for dev in [
        "final_serverless_proof",
        "AUTOMATED_PROOF_GREEN",
        "PairInit",
        "--peer-pub-hex <receiver",
    ] {
        assert!(!help.contains(dev), "{dev:?} in {help}");
    }

    // `--data-dir` is explained for a person, with no `[default: ""]`.
    let o = ash_out(dir.path(), &["-h"], "");
    let short = text(&o.stdout);
    assert!(
        short.contains("Folder where Raven keeps your identity"),
        "{short}"
    );
    assert!(
        !short.contains("mktemp") && !short.contains("[default: \"\"]"),
        "{short}"
    );
}

#[test]
fn send_help_says_the_text_comes_from_stdin_and_shows_the_example() {
    let dir = tempfile::tempdir().unwrap();
    let o = ash_out(dir.path(), &["send", "--help"], "");
    let help = text(&o.stdout);
    assert_eq!(code(&o), 0);
    assert!(help.contains("stdin"), "{help}");
    assert!(
        help.contains("echo \"hello\" | ash send --contact @alice"),
        "{help}"
    );
    assert!(help.contains("--contact <CONTACT>"), "{help}");
    // How to reach the contact is a user choice now (transports P1): shown.
    assert!(help.contains("--carrier <auto|lan|internet>"), "{help}");
    // The old developer-only wording and the unusable options are gone from view.
    for old in ["Forward send to raven-node", "--listen", "--stdin-text"] {
        assert!(!help.contains(old), "{old:?} in {help}");
    }
    // ... but they are still accepted (scripts pass them).
    let o = ash_out(
        dir.path(),
        &[
            "send",
            "--stdin-text",
            "--carrier",
            "lan",
            "--contact",
            "@x",
        ],
        "hi\n",
    );
    assert!(
        !text(&o.stderr).contains("unexpected argument"),
        "{}",
        text(&o.stderr)
    );
}

// ── first run and the menu ──────────────────────────────────────────────────

#[test]
fn the_first_run_prompt_explains_what_an_identity_is_and_a_typo_creates_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let o = ash_out(dir.path(), &[], "ok\nq\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("Your identity is a private key that stays on this computer"),
        "{out}"
    );
    assert!(
        out.contains("no account, no phone number, no server"),
        "{out}"
    );
    assert!(
        out.contains("Create your Raven identity now? [Y/n]"),
        "{out}"
    );
    // An answer that is neither yes nor no is not a yes (and a pipe is never
    // asked twice: the next line belongs to the menu).
    assert!(
        out.contains("Not a yes or a no — identity not created"),
        "{out}"
    );
    assert!(!dir.path().join("identity.seed").exists());
    assert!(out.contains("fly safe"), "{out}");
}

#[test]
fn the_menu_is_one_copy_of_plain_words_with_one_quit_line() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let o = ash_out(dir.path(), &[], "5\n\n6\n7\nh\nzzz\nQ\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    // Hints in plain words, Mailbox / Nearby honest about being local.
    assert!(out.contains("messages you received"), "{out}");
    assert!(out.contains("stay online to receive"), "{out}");
    assert!(out.contains("add a friend (paste their invite)"), "{out}");
    for jargon in [
        "committed endpoint inbox",
        "ephemeral BLE discovery",
        "opaque offline put/get",
    ] {
        assert!(!out.contains(jargon), "{jargon:?} in {out}");
    }
    assert!(
        out.contains("advanced tool, this computer only (not your inbox)"),
        "{out}"
    );
    assert!(
        out.contains("demo, this computer only (no Bluetooth yet)"),
        "{out}"
    );
    assert!(
        out.contains("Nearby scan is a demo on this computer only"),
        "{out}"
    );
    assert!(
        out.contains("Mailbox is an advanced tool for this computer only"),
        "{out}"
    );
    // `h` helps, a wrong key says what to pick, a capital Q quits.
    assert!(out.contains("Pick a number from 1 to 8"), "{out}");
    assert!(
        out.contains("unknown: zzz — pick 1-8 or q (h = help)"),
        "{out}"
    );
    assert!(out.contains("fly safe"), "{out}");
    // The quit key is listed once per screen, not twice.
    assert_eq!(out.matches("q  quit   q  quit").count(), 0, "{out}");
    let screens = out
        .matches("R A V E N")
        .count()
        .max(out.matches("◆ MESSAGES").count());
    assert_eq!(out.matches("    q  quit").count(), screens, "{out}");
    // The scripted keys still land on the same screens.
    assert!(out.contains("Send / Chat"), "{out}");
}

#[test]
fn the_tutorial_says_both_people_add_each_other_and_the_receiver_listens() {
    let dir = tempfile::tempdir().unwrap();
    let o = ash_out(dir.path(), &[], "y\n8\n\nq\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("[1/4] Your identity"), "{out}");
    assert!(out.contains("the `invite` line"), "{out}");
    assert!(out.contains("They must add YOU the same way"), "{out}");
    assert!(out.contains("keep menu 4 (Listen) open"), "{out}");
    assert!(out.contains("run `ash doctor`"), "{out}");
    // The old advice (address + fingerprint is not enough to be added) and the
    // false green tick for the path rule are gone.
    assert!(!out.contains("address+fingerprint"), "{out}");
    assert!(!out.contains("messaging_path must read"), "{out}");
    assert!(!out.contains("bridge relays"), "{out}");
    // The status it runs ends with the verdict.
    assert!(
        out.contains("raven-node is not running: start it with `ash listen`"),
        "{out}"
    );
    assert!(
        out.contains("Full diagnostics anytime: ash doctor"),
        "{out}"
    );
}

// ── status, doctor, inbox ───────────────────────────────────────────────────

#[test]
fn status_gives_a_plain_receiving_row_and_a_verdict_for_every_node_state() {
    // No node at all.
    let dir = short_dir();
    plant_identity(dir.path());
    let o = ash_out(dir.path(), &["status"], "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("receiving     NO — raven-node is not running"),
        "{out}"
    );
    assert!(
        out.trim_end()
            .ends_with("raven-node is not running: start it with `ash listen` (it also starts by itself when you send a message)."),
        "{out}"
    );
    // What the scripts parse is still there, and the raw OS error is not.
    assert!(out.contains("bridge") && out.contains("forward_q"), "{out}");
    assert!(!out.contains("os error"), "{out}");
    assert!(
        !out.contains("mock_ble") && !out.contains("transports"),
        "{out}"
    );

    // A node whose LAN listener is up receives.
    let dir = short_dir();
    plant_identity(dir.path());
    let node = FakeNode::start(dir.path(), &["ipc", "lan_direct", "bridge", "store"]);
    let o = ash_out(dir.path(), &["status"], "");
    drop(node);
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("receiving     YES"), "{out}");
    assert!(
        out.trim_end().ends_with("You can send and receive."),
        "{out}"
    );
    assert!(out.contains("daemon        running (answers IPC)"), "{out}");

    // A node without its LAN listener (busy port, outbound-only) cannot receive.
    let dir = short_dir();
    plant_identity(dir.path());
    let node = FakeNode::start(dir.path(), &["ipc", "bridge"]);
    let o = ash_out(dir.path(), &["status"], "");
    drop(node);
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("receiving     NO — raven-node runs but its LAN listener is down"),
        "{out}"
    );
    assert!(out.contains("You can send but NOT receive"), "{out}");
    assert!(!out.contains("You can send and receive"), "{out}");
}

#[test]
fn doctor_opens_with_a_summary_and_a_next_step_and_keeps_its_technical_lines() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");
    let o = ash_out(dir.path(), &["doctor"], "");
    let out = text(&o.stdout);
    // Identity is fine and the node being down is not a failure of the report.
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let top: Vec<&str> = out.lines().take(8).collect();
    let top = top.join("\n");
    assert!(top.starts_with("raven doctor\nSUMMARY"), "{top}");
    assert!(top.contains("identity      OK"), "{top}");
    assert!(top.contains("raven-node    NOT running"), "{top}");
    assert!(top.contains("contacts      1"), "{top}");
    assert!(
        top.contains("next step     to receive messages run `ash listen`"),
        "{top}"
    );
    // Also the last line, so `| tail` shows it.
    assert!(
        out.trim_end()
            .lines()
            .last()
            .unwrap()
            .starts_with("Next step: to receive messages run `ash listen`"),
        "{out}"
    );
    // Every token line the scripts and installers read is still there.
    for token in [
        "serverless_rvn1",
        "never silently uses FastAPI",
        "daemon_presence: down",
        "daemon_ready: not_ready",
        "send_path:",
        "identity: present",
        "ipc_endpoint=",
    ] {
        assert!(out.contains(token), "{token:?} missing from {out}");
    }
    // The node being down is a plain row, not a raw error code.
    assert!(!top.contains("os error"), "{top}");

    // With no identity the one step is `ash init`.
    let empty = short_dir();
    let o = ash_out(empty.path(), &["doctor"], "");
    let out = text(&o.stdout);
    assert!(
        out.contains("identity      MISSING (run: ash init)"),
        "{out}"
    );
    assert!(out.contains("next step     run `ash init`"), "{out}");
}

#[test]
fn an_empty_inbox_says_why_and_names_the_profile_and_touches_nothing() {
    let dir = short_dir();
    plant_identity(dir.path());
    let o = ash_out(dir.path(), &["inbox"], "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains(&format!("No messages yet in {}.", dir.path().display())),
        "{out}"
    );
    assert!(out.contains("nobody has written to you yet"), "{out}");
    assert!(
        out.contains("they have not added you as a contact"),
        "{out}"
    );
    assert!(
        out.contains("this computer is not receiving (check: `ash status`)"),
        "{out}"
    );
    assert!(out.contains("keep `ash listen` running"), "{out}");
    // A stopped node is named on stderr (stdout stays the message list).
    assert!(
        text(&o.stderr).contains("raven-node is not running, so nothing can arrive right now"),
        "{}",
        text(&o.stderr)
    );
    assert!(!out.contains("endpoint inbox empty"), "{out}");

    // With a node that receives there is no such warning.
    let dir = short_dir();
    plant_identity(dir.path());
    let node = FakeNode::start(dir.path(), &["ipc", "lan_direct"]);
    let o = ash_out(dir.path(), &["inbox"], "");
    drop(node);
    assert_eq!(code(&o), 0);
    assert!(
        !text(&o.stderr).contains("nothing can arrive"),
        "{}",
        text(&o.stderr)
    );
    // And one that runs without its listener says so.
    let dir = short_dir();
    plant_identity(dir.path());
    let node = FakeNode::start(dir.path(), &["ipc"]);
    let o = ash_out(dir.path(), &["inbox"], "");
    drop(node);
    assert!(
        text(&o.stderr).contains("this computer is NOT receiving"),
        "{}",
        text(&o.stderr)
    );

    // Before the identity the read-only command creates nothing.
    let bare = short_dir();
    let o = ash_out(bare.path(), &["inbox"], "");
    assert_eq!(code(&o), 0);
    assert!(
        text(&o.stdout).contains("no identity yet"),
        "{}",
        text(&o.stdout)
    );
    // (only the empty identity lock that every identity check leaves, which the
    // first-install check treats as inert: `ash init` still works afterwards)
    let left: Vec<String> = std::fs::read_dir(bare.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        left.iter().all(|n| n == ".identity_store.lock.sqlite"),
        "{left:?}"
    );
    let o = ash_out(bare.path(), &["init"], "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
}

// ── contacts ────────────────────────────────────────────────────────────────

#[test]
fn contact_saved_says_the_other_person_must_add_you_back() {
    let dir = short_dir();
    plant_identity(dir.path());
    let bob = Identity::from_seed(&[0x42; 32]);
    let mut c = ash(dir.path());
    c.args(["contact", "add", "--address", &bob.address()])
        .args(["--pub-hex", &pub_hex(&bob), "--petname", "Bob"]);
    let o = run(c, "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    // The substrings scripts grep for ...
    assert!(out.contains("contact saved"), "{out}");
    assert!(out.to_lowercase().contains("no fastapi"), "{out}");
    assert!(
        out.contains("fingerprint") && out.contains("pinned"),
        "{out}"
    );
    // ... the name, and the one thing to do next.
    assert!(out.contains("contact saved: Bob"), "{out}");
    assert!(out.contains("ask Bob to add YOU too"), "{out}");
    assert!(out.contains("`ash whoami`"), "{out}");
    assert!(out.contains("BOTH of you have added each other"), "{out}");
    assert!(out.contains("not verified yet"), "{out}");
    // The phone note belongs to the guided flow, not to the command line.
    assert!(!out.contains("iPhone") && !out.contains("آیفون"), "{out}");

    // A contact with no name does not show an address as its "petname".
    let carol = Identity::from_seed(&[0x43; 32]);
    let mut c = ash(dir.path());
    c.args(["contact", "add", "--address", &carol.address()])
        .args(["--pub-hex", &pub_hex(&carol)]);
    let o = run(c, "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(out.contains("contact saved (no name given"), "{out}");
    assert!(out.contains("petname     (none yet)"), "{out}");
    assert!(out.contains("ask them to add YOU too"), "{out}");
}

#[test]
fn your_own_identity_is_refused_in_the_guided_add_and_flagged_on_the_command_line() {
    let dir = short_dir();
    plant_identity(dir.path());
    let me = Identity::from_seed(&[0x5a; 32]);

    // Command line: scripts add the profile's own key on purpose, so it is saved,
    // but the person is told.
    let mut c = ash(dir.path());
    c.args(["contact", "add", "--address", &me.address()])
        .args(["--pub-hex", &pub_hex(&me), "--petname", "Me"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).contains("contact saved"),
        "{}",
        text(&o.stdout)
    );
    assert!(
        text(&o.stderr).contains("YOUR OWN identity"),
        "{}",
        text(&o.stderr)
    );

    // Guided add (menu 5, a, paste): refused, nothing saved.
    let fresh = short_dir();
    plant_identity(fresh.path());
    let invite = format!("raven:{}:{}", me.address(), pub_hex(&me));
    let o = ash_out(
        fresh.path(),
        &[],
        &format!("5\na\n{invite}\nFriend\nc\n\nq\n"),
    );
    let both = format!("{}{}", text(&o.stdout), text(&o.stderr));
    assert!(both.contains("That is YOUR OWN invite"), "{both}");
    assert!(!both.contains("contact saved"), "{both}");
    assert!(!fresh.path().join("contacts.json").exists());

    // Another key through the same menu still saves.
    let bob = Identity::from_seed(&[0x42; 32]);
    let invite = format!("raven:{}:{}", bob.address(), pub_hex(&bob));
    let o = ash_out(
        fresh.path(),
        &[],
        &format!("5\na\n{invite}\nFriend\nc\n\nq\n"),
    );
    let both = format!("{}{}", text(&o.stdout), text(&o.stderr));
    assert!(both.contains("contact saved"), "{both}");
    assert!(fresh.path().join("contacts.json").exists());
}

#[test]
fn send_contact_finds_a_person_by_petname_like_the_picker_does() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");

    // Petname in any case: the contact is FOUND (it has no address yet, which is
    // a different, later error) — before this, only an @tag worked.
    for name in ["Bob", "bob", "BOB"] {
        let o = ash_out(dir.path(), &["send", "--contact", name], "hello\n");
        let err = text(&o.stderr);
        assert_eq!(code(&o), 1, "{err}");
        assert!(!err.contains("no contact for"), "{name}: {err}");
        assert!(
            err.contains("contact Bob has no reachable lan_dial"),
            "{name}: {err}"
        );
        assert!(
            !text(&o.stdout).contains("delivered"),
            "{}",
            text(&o.stdout)
        );
    }
    // The chat finds the same person.
    let o = ash_out(dir.path(), &["send", "--chat", "--contact", "bob"], "");
    let err = text(&o.stderr);
    assert!(!err.contains("no contact for"), "{err}");
    assert!(
        err.contains("contact Bob has no reachable lan_dial"),
        "{err}"
    );

    // Nobody by that name: say who exists and how to name them.
    let o = ash_out(dir.path(), &["send", "--contact", "Zed"], "hello\n");
    let err = text(&o.stderr);
    assert_eq!(code(&o), 1);
    assert!(
        err.contains("no contact for Zed. Your contacts: Bob."),
        "{err}"
    );
    assert!(err.contains("--contact NAME or --contact @tag"), "{err}");
    // A lone @ still reaches nobody, not the untagged contact.
    let o = ash_out(dir.path(), &["send", "--contact", "@"], "hello\n");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("no contact for @"),
        "{}",
        text(&o.stderr)
    );
}

#[test]
fn the_send_picker_says_it_sends_one_message_and_where_a_live_chat_is() {
    let dir = short_dir();
    plant_identity(dir.path());
    add_bob(dir.path(), "Bob");
    // Menu 1, a blank pick (back to the menu), quit.
    let o = ash_out(dir.path(), &[], "1\n\nq\n");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        out.contains("Pick a contact by number, @tag or petname"),
        "{out}"
    );
    assert!(
        out.contains("This sends one message. For a live chat: ash send --contact NAME --chat"),
        "{out}"
    );
    assert!(out.contains("fly safe"), "{out}");
}
