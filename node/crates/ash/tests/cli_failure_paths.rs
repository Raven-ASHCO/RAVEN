//! Black-box checks of `ash` failure paths: commands must exit non-zero and
//! explain on stderr, trust prompts must not decide on EOF / blank answers, and
//! first-run identity creation needs a real "yes".
//!
//! Every run uses a throwaway data dir and the file-backed (`locked-file`)
//! secret stores, so nothing here can reach the OS keychain or the network.
//!
//! Unix only: the planted 0600 identity seed is the unix locked-file layout
//! (the Windows ACL-hardened store is not exercised here).
#![cfg(unix)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use raven_core::address::encode_address;
use raven_core::fingerprint::device_fingerprint_v1;
use raven_core::identity::Identity;

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

/// Run to completion with `stdin_text` on a (non-terminal) stdin.
fn run(mut c: Command, stdin_text: &str) -> Output {
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ash");
    // The child may exit without reading its stdin: a broken pipe is fine.
    let _ = child.stdin.take().unwrap().write_all(stdin_text.as_bytes());
    child.wait_with_output().expect("wait ash")
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// A usable locked-file identity without running `ash init` (32-byte 0600 seed).
fn plant_identity(dir: &Path) {
    let seed = dir.join("identity.seed");
    std::fs::write(&seed, [0x5au8; 32]).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn ident(seed: u8) -> Identity {
    Identity::from_seed(&[seed; 32])
}

fn pub_hex(id: &Identity) -> String {
    hex::encode(id.public_key_bytes())
}

fn add_contact_args(c: &mut Command, id: &Identity, petname: &str, tag: Option<&str>, dial: &str) {
    c.args(["contact", "add", "--address", &id.address()])
        .args(["--pub-hex", &pub_hex(id), "--petname", petname]);
    if let Some(t) = tag {
        c.args(["--tag", t]);
    }
    if !dial.is_empty() {
        c.args(["--lan-dial", dial]);
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap_or(-1)
}

#[test]
fn listen_exits_nonzero_when_it_cannot_start() {
    // No identity.
    let dir = tempfile::tempdir().unwrap();
    let mut c = ash(dir.path());
    c.arg("listen");
    let o = run(c, "");
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    assert!(!text(&o.stderr).trim().is_empty());
    assert!(!text(&o.stdout).contains("LISTENING"));

    // Identity but no contacts to accept.
    plant_identity(dir.path());
    let mut c = ash(dir.path());
    c.arg("listen");
    let o = run(c, "");
    assert_eq!(code(&o), 1, "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("No pinned contacts"),
        "{}",
        text(&o.stderr)
    );
    assert!(!text(&o.stdout).contains("LISTENING"));

    // Corrupt contact book.
    std::fs::write(dir.path().join("contacts.json"), "{not-json").unwrap();
    let mut c = ash(dir.path());
    c.arg("listen");
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(text(&o.stderr).contains("corrupt"), "{}", text(&o.stderr));
    assert!(!text(&o.stdout).contains("LISTENING"));
}

#[test]
fn inbox_on_an_unopenable_store_is_a_failure_not_an_empty_inbox() {
    let dir = tempfile::tempdir().unwrap();
    // A regular file where the profile directory should be: the store cannot open.
    let not_a_dir = dir.path().join("profile-is-a-file");
    std::fs::write(&not_a_dir, b"x").unwrap();
    let mut c = ash(&not_a_dir);
    c.arg("inbox");
    let o = run(c, "");
    assert_eq!(
        code(&o),
        1,
        "stdout={} stderr={}",
        text(&o.stdout),
        text(&o.stderr)
    );
    assert!(text(&o.stderr).contains("inbox:"), "{}", text(&o.stderr));
    assert!(!text(&o.stdout).contains("endpoint inbox empty"));
}

#[test]
fn prekey_fetch_and_import_peer_prekey_fail_loudly() {
    let dir = tempfile::tempdir().unwrap();
    let peer = pub_hex(&ident(0x31));

    let mut c = ash(dir.path());
    c.args(["prekey", "fetch", "--pub-hex", "zz"]);
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(text(&o.stderr).contains("pub_hex"), "{}", text(&o.stderr));
    assert!(!text(&o.stdout).contains("prekey ok"));

    // `import-peer-prekey … && ash send …` must stop at an unreadable bundle.
    let mut c = ash(dir.path());
    c.args([
        "lab",
        "import-peer-prekey",
        "--peer-pub-hex",
        &peer,
        "--file",
    ])
    .arg(dir.path().join("missing.json"));
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(text(&o.stderr).contains("read:"), "{}", text(&o.stderr));

    let garbage = dir.path().join("bundle.json");
    std::fs::write(&garbage, "{not json").unwrap();
    let mut c = ash(dir.path());
    c.args(["prekey", "fetch", "--pub-hex", &peer, "--file"])
        .arg(&garbage);
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(text(&o.stderr).contains("json:"), "{}", text(&o.stderr));
}

#[test]
fn contact_lookups_that_match_nothing_exit_nonzero() {
    let dir = tempfile::tempdir().unwrap();
    for args in [
        &["contact", "verify", "--tag", "nobody"][..],
        &["contact", "verify"][..],
        &["contact", "verify", "--petname", "Zed"][..],
        &["contact", "resolve", "--tag", "nobody"][..],
        // A lone "@" names nobody (it used to match every untagged contact).
        &["contact", "resolve", "--tag", "@"][..],
    ] {
        let mut c = ash(dir.path());
        c.args(args);
        let o = run(c, "");
        assert_eq!(code(&o), 1, "{args:?}: {}", text(&o.stderr));
        assert!(!text(&o.stderr).trim().is_empty(), "{args:?}");
    }
}

#[test]
fn alias_publish_defaults_to_the_next_sequence_and_refuses_regressions() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let publish = |extra: &[&str]| {
        let mut c = ash(dir.path());
        c.args(["alias", "publish", "--alias", "alice"]).args(extra);
        run(c, "")
    };
    let o = publish(&["--sequence", "5"]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    // The old default (sequence 1) would silently overwrite seq 5 locally and
    // be rejected as stale by every peer that already holds it.
    let o = publish(&["--sequence", "1"]);
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("ALIAS_STALE_SEQUENCE"),
        "{}",
        text(&o.stderr)
    );
    // No --sequence: stored + 1.
    let o = publish(&[]);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).contains("sequence    6"),
        "{}",
        text(&o.stdout)
    );
    // A first claim for another alias starts at 1.
    let mut c = ash(dir.path());
    c.args(["alias", "publish", "--alias", "bob"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stdout).contains("sequence    1"),
        "{}",
        text(&o.stdout)
    );
}

#[test]
fn contact_set_dial_remove_and_unblock_are_explicit_and_local() {
    let dir = tempfile::tempdir().unwrap();
    // Contacts are profile state: they need the identity to exist first.
    plant_identity(dir.path());
    let poline = ident(0x41);
    let fp = device_fingerprint_v1(&poline.public_key_bytes());
    let mut c = ash(dir.path());
    add_contact_args(
        &mut c,
        &poline,
        "Poline",
        Some("poline"),
        "192.168.1.20:7420",
    );
    c.args(["--verify-fp", &fp]);
    assert_eq!(code(&run(c, "")), 0);

    // Refresh the dial without losing petname / tag / pin.
    let mut c = ash(dir.path());
    c.args([
        "contact",
        "set-dial",
        "--petname",
        "Poline",
        "--lan-dial",
        "192.168.1.31:7420",
    ]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let book = std::fs::read_to_string(dir.path().join("contacts.json")).unwrap();
    assert!(book.contains("192.168.1.31:7420") && !book.contains("192.168.1.20:7420"));
    assert!(
        book.contains("\"petname\": \"Poline\"") && book.contains("\"public_tag\": \"poline\"")
    );
    assert!(book.contains("\"pinned\": true"));

    let mut c = ash(dir.path());
    c.args([
        "contact",
        "set-dial",
        "--petname",
        "Nobody",
        "--lan-dial",
        "10.0.0.1:7420",
    ]);
    assert_eq!(code(&run(c, "")), 1);

    // Removing needs a real confirmation: piped stdin cannot give one.
    let mut c = ash(dir.path());
    c.args(["contact", "remove", "--petname", "Poline"]);
    let o = run(c, "remove\n");
    assert_eq!(code(&o), 1);
    assert!(std::fs::read_to_string(dir.path().join("contacts.json"))
        .unwrap()
        .contains("Poline"));
    let mut c = ash(dir.path());
    c.args(["contact", "remove", "--petname", "Poline", "--yes"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(!std::fs::read_to_string(dir.path().join("contacts.json"))
        .unwrap()
        .contains("Poline"));

    // Unblock: not blocked → error, unknown key format → error.
    let mut c = ash(dir.path());
    c.args(["contact", "unblock", "--pub-hex", &pub_hex(&poline)]);
    let o = run(c, "");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("not on the block list"),
        "{}",
        text(&o.stderr)
    );
    let mut c = ash(dir.path());
    c.args(["contact", "unblock", "--pub-hex", "zz"]);
    assert_eq!(code(&run(c, "")), 1);
}

#[test]
fn send_to_a_lone_at_sign_reaches_nobody() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let bob = ident(0x42);
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &bob, "Bob", None, "192.168.1.9:7420");
    assert_eq!(code(&run(c, "")), 0);
    // `--contact "@$TAG"` with $TAG unset must not fall onto the petname-only contact.
    let mut c = ash(dir.path());
    c.args(["send", "--contact", "@"]);
    let o = run(c, "secret\n");
    assert_eq!(code(&o), 1);
    assert!(
        text(&o.stderr).contains("no contact for"),
        "{}",
        text(&o.stderr)
    );
}

#[test]
fn status_reports_a_broken_book_and_does_not_present_policy_as_live_state() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    std::fs::write(dir.path().join("contacts.json"), "{not-json").unwrap();
    let mut c = ash(dir.path());
    c.arg("status");
    let o = run(c, "");
    let out = text(&o.stdout);
    assert_eq!(code(&o), 1, "{out}");
    assert!(text(&o.stderr).contains("corrupt"), "{}", text(&o.stderr));
    // The rest of the screen still renders, with the failure shown in place.
    assert!(
        out.contains("CONTACTS") && out.contains("unavailable"),
        "{out}"
    );
    assert!(out.contains("BRIDGE") && out.contains("forward_q"), "{out}");
    // No daemon is running: say so instead of claiming transports / capabilities.
    assert!(out.contains("not running"), "{out}");
    assert!(
        !out.contains("mock_ble") && !out.contains("transports"),
        "{out}"
    );
}

#[test]
fn node_flag_on_an_unreadable_policy_warns_about_the_reset_flags() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("node_policy.json"), "{broken").unwrap();
    let mut c = ash(dir.path());
    c.args(["node", "bridge", "on"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("unreadable"),
        "{}",
        text(&o.stderr)
    );
    let out = text(&o.stdout);
    assert!(
        out.contains("bridge=on") && out.contains("store=off"),
        "{out}"
    );
}

#[test]
fn first_run_identity_needs_a_real_yes() {
    // stdin closed (EOF): no human decided, nothing is created.
    let dir = tempfile::tempdir().unwrap();
    let o = run(ash(dir.path()), "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(!dir.path().join("identity.seed").exists());
    assert!(
        text(&o.stdout).contains("identity not created"),
        "{}",
        text(&o.stdout)
    );
    // A blank line on a pipe is not a decision either.
    let o = run(ash(dir.path()), "\n");
    assert_eq!(code(&o), 0);
    assert!(!dir.path().join("identity.seed").exists());
    // An explicit yes still works (the menu smoke script relies on it).
    let o = run(ash(dir.path()), "y\nq\n");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(dir.path().join("identity.seed").exists());
    assert!(
        text(&o.stdout).contains("identity created"),
        "{}",
        text(&o.stdout)
    );
}

/// Drive menu 5 → a (guided add) with `answers` and return the output.
fn guided_add(dir: &Path, answers: &str) -> Output {
    run(ash(dir), &format!("5\na\n{answers}"))
}

#[test]
fn guided_add_never_trusts_a_contact_on_eof_or_a_blank_answer() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let friend = ident(0x51);
    let invite = format!("raven:{}:{}", friend.address(), pub_hex(&friend));
    let fp = device_fingerprint_v1(&friend.public_key_bytes());
    let book = dir.path().join("contacts.json");

    // EOF at the fingerprint prompt.
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\n"));
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(!book.exists(), "EOF must not add a contact");
    assert!(
        text(&o.stdout).contains("nothing saved"),
        "{}",
        text(&o.stdout)
    );
    // A blank answer (stray Enter / pasted empty line) aborts too.
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\n\nq\n"));
    assert!(!book.exists(), "{}", text(&o.stdout));
    // `v` alone never pins: it asks for the fingerprint, and EOF there aborts.
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\nv\n"));
    assert!(!book.exists(), "{}", text(&o.stdout));
    // ... and a wrong fingerprint aborts.
    let o = guided_add(
        dir.path(),
        &format!("{invite}\nFriend\nv\nAAAA-BBBB-CCCC\n"),
    );
    assert!(!book.exists(), "{}", text(&o.stdout));
    assert!(
        text(&o.stdout).contains("did not match"),
        "{}",
        text(&o.stdout)
    );
    // `c` saves unpinned (what the menu smoke script drives).
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\nc\n\nq\n"));
    assert!(
        text(&o.stdout).contains("contact saved"),
        "{}",
        text(&o.stdout)
    );
    let saved = std::fs::read_to_string(&book).unwrap();
    assert!(saved.contains("\"pinned\": false"), "{saved}");
    std::fs::remove_file(&book).unwrap();
    // v + the typed fingerprint pins.
    let o = guided_add(dir.path(), &format!("{invite}\nFriend\nv\n{fp}\nq\n"));
    assert!(
        text(&o.stdout).contains("contact saved"),
        "{}",
        text(&o.stdout)
    );
    let saved = std::fs::read_to_string(&book).unwrap();
    assert!(saved.contains("\"pinned\": true"), "{saved}");
}

#[test]
fn pasted_contact_card_cannot_answer_the_fingerprint_prompt_by_itself() {
    // The reported scenario: a "contact card" whose later lines line up with
    // the tag / petname / dial / choice prompts and end in `v`.
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let attacker = ident(0x66);
    let card = format!(
        "address {}\npub_hex {}\n\nMom\n\nv\n",
        encode_address(&attacker.public_key_bytes()),
        pub_hex(&attacker)
    );
    let o = guided_add(dir.path(), &card);
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(
        !dir.path().join("contacts.json").exists(),
        "pasted `v` must not pin: {}",
        text(&o.stdout)
    );
}

#[test]
fn menu_survives_a_corrupt_contact_book() {
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    std::fs::write(dir.path().join("contacts.json"), "{not-json").unwrap();
    // 3 Status, 5 Contacts (Enter = back), q: neither screen may end the session.
    let o = run(ash(dir.path()), "3\n5\n\nq\n");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout).contains("fly safe"), "{}", text(&o.stdout));
    assert!(text(&o.stderr).contains("corrupt"), "{}", text(&o.stderr));
}

/// First-install wedge: whatever a command creates in a profile with no identity
/// makes the first `ash init` fail the continuity check ("profile contains
/// state but has no identity continuity record") and point at identity theft.
/// Commands that create state must therefore refuse (or do nothing) until the
/// identity exists, and the profile must stay initialisable afterwards.
mod first_install {
    use super::*;

    /// Names inert for the first-install check (see raven-core identity_store).
    fn entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    fn assert_still_initialisable(dir: &Path) {
        let mut c = ash(dir);
        c.arg("init");
        let o = run(c, "");
        assert_eq!(
            code(&o),
            0,
            "init refused after a pre-identity command: stdout={} stderr={}",
            text(&o.stdout),
            text(&o.stderr)
        );
        assert!(text(&o.stdout).contains("pub_hex="), "{}", text(&o.stdout));
    }

    #[test]
    fn inbox_before_the_identity_creates_nothing_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ash(dir.path());
        c.arg("inbox");
        let o = run(c, "");
        assert_eq!(code(&o), 0, "{}", text(&o.stderr));
        let out = text(&o.stdout);
        assert!(out.contains("no identity yet"), "{out}");
        assert!(out.contains("ash init"), "{out}");
        assert!(!out.contains("endpoint inbox empty"), "{out}");
        for name in entries(dir.path()) {
            assert!(
                !name.starts_with("indexed_sessions") && name != "indexed-session-secrets",
                "inbox created the session store: {name}"
            );
        }
        assert_still_initialisable(dir.path());
    }

    #[test]
    fn nearby_before_the_identity_is_refused_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = ash(dir.path());
        c.arg("nearby");
        let o = run(c, "");
        assert_eq!(code(&o), 1, "{}", text(&o.stdout));
        assert!(text(&o.stderr).contains("ash init"), "{}", text(&o.stderr));
        assert!(!dir.path().join("nearby_registry.json").exists());
        assert_still_initialisable(dir.path());
    }

    #[test]
    fn contact_add_before_the_identity_is_refused_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let bob = ident(0x43);
        let mut c = ash(dir.path());
        add_contact_args(&mut c, &bob, "Bob", None, "");
        let o = run(c, "");
        assert_eq!(code(&o), 1, "{}", text(&o.stdout));
        assert!(text(&o.stderr).contains("ash init"), "{}", text(&o.stderr));
        assert!(!dir.path().join("contacts.json").exists());
        assert_still_initialisable(dir.path());
    }

    /// Menu 5 -> a(dd) on the first-run menu: piped input, no identity.
    #[test]
    fn menu_add_contact_before_the_identity_is_refused_and_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let bob = ident(0x44);
        let c = ash(dir.path());
        // n: decline identity creation; 5 a: add a contact; paste an invite.
        let script = format!(
            "n\n5\na\nraven:{}:{}\n\n\n\nq\n",
            bob.address(),
            pub_hex(&bob)
        );
        let o = run(c, &script);
        let all = format!("{}{}", text(&o.stdout), text(&o.stderr));
        assert!(all.contains("needs an identity first"), "{all}");
        assert!(!dir.path().join("contacts.json").exists(), "{all}");
        assert_still_initialisable(dir.path());
    }

    /// Menu 2 (Inbox) is the second entry of the first-run menu.
    #[test]
    fn menu_inbox_before_the_identity_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let o = run(ash(dir.path()), "n\n2\nq\n");
        let all = format!("{}{}", text(&o.stdout), text(&o.stderr));
        assert!(all.contains("no identity yet"), "{all}");
        for name in entries(dir.path()) {
            assert!(!name.starts_with("indexed_sessions"), "{name}");
        }
        assert_still_initialisable(dir.path());
    }

    /// An unreadable identity store must not be answered with "run `ash init`"
    /// (that is what is failing): the first-run tip says what to do instead.
    #[test]
    fn unreadable_identity_store_is_not_answered_with_ash_init_tip() {
        let dir = tempfile::tempdir().unwrap();
        // Leftover state without an identity record: a continuity violation.
        std::fs::write(dir.path().join("contacts.json"), "[]").unwrap();
        let c = ash(dir.path());
        let o = run(c, "q\n");
        let out = text(&o.stdout);
        assert!(out.contains("identity unavailable"), "{out}");
        assert!(!out.contains("run `ash init` anytime"), "{out}");
        assert!(out.contains("recovery steps"), "{out}");
    }
}

/// Rust ignores SIGPIPE, so a closed stdout pipe (`ash ... | head -1`,
/// `... | grep -q x`) made std's `println!` panic: exit 101 and "failed printing
/// to stdout: Broken pipe". The reader is gone from the start here (the read
/// end is closed before the process exists), so the very first write hits EPIPE.
#[test]
fn a_closed_stdout_pipe_is_not_a_panic() {
    let dir = tempfile::tempdir().unwrap();
    for args in [&["banner"][..], &["whoami"], &["doctor"], &["inbox"]] {
        let (reader, writer) = std::io::pipe().unwrap();
        drop(reader);
        let mut c = ash(dir.path());
        c.args(args)
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(Stdio::piped());
        let o = c.spawn().unwrap().wait_with_output().unwrap();
        let err = text(&o.stderr);
        assert!(!err.contains("panicked"), "{args:?}: {err}");
        assert!(!err.contains("Broken pipe"), "{args:?}: {err}");
        assert_ne!(code(&o), 101, "{args:?}: {err}");
    }
    // Output that is not broken still arrives (the shadowed macros print).
    let mut c = ash(dir.path());
    c.arg("banner");
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    assert!(text(&o.stdout).contains("R A V E N"), "{}", text(&o.stdout));
}

/// `ash contact remove` is the deliberate re-pin: it also forgets the prekey
/// pinned for that contact. A contact that reinstalled is refused
/// (PEER_PREKEY_RESET) for new sessions until its old pinned prekey expires;
/// removing and re-adding it is the way to accept it sooner.
#[test]
fn contact_remove_forgets_the_pinned_prekey() {
    use raven_core::atsam_mlkem::HybridKeypair;
    use raven_core::prekey_bundle::{PrekeyBundle, PrekeyStore};
    let dir = tempfile::tempdir().unwrap();
    plant_identity(dir.path());
    let poline = ident(0x45);
    let mut c = ash(dir.path());
    add_contact_args(&mut c, &poline, "Poline", None, "");
    assert_eq!(code(&run(c, "")), 0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let kp = HybridKeypair::generate(&mut rand::thread_rng());
    let bundle = PrekeyBundle::from_hybrid_public(
        "ash-primary",
        kp.x25519_public,
        kp.mlkem_ek_bytes.clone(),
        5,
        now,
        now + 3_600_000,
    )
    .unwrap()
    .sign(&poline)
    .unwrap();
    let mut store = PrekeyStore::load_checked(dir.path()).unwrap();
    store.publish(&bundle, now).unwrap();
    store.save(dir.path()).unwrap();
    let pinned = |dir: &Path| {
        PrekeyStore::load_checked(dir)
            .unwrap()
            .fetch(&poline.public_key_bytes(), now)
            .unwrap()
            .is_some()
    };
    assert!(pinned(dir.path()), "precondition: a prekey is pinned");

    let mut c = ash(dir.path());
    c.args(["contact", "remove", "--petname", "Poline", "--yes"]);
    let o = run(c, "");
    assert_eq!(code(&o), 0, "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains("removed"), "{out}");
    assert!(out.contains("forgot the prekey pinned"), "{out}");
    assert!(!pinned(dir.path()), "the pin must be gone with the contact");
    // Idempotent: nothing pinned, nothing said, still a clean removal of the next one.
    assert!(
        !dir.path().join("contacts.json").exists() || {
            let raw = std::fs::read_to_string(dir.path().join("contacts.json")).unwrap();
            !raw.contains("Poline")
        }
    );
}
