//! Two real processes, one identity-store lock.
//!
//! A raven process blocked in a macOS Keychain dialog keeps the identity-store
//! lock until the dialog is answered, so a second raven command used to wait
//! behind it in silence for up to a minute. Here one process (this test) holds
//! the lock and a child process calls `load_identity`: it must say why it waits
//! (on its real stderr, after the production 3 s) and carry on by itself once
//! the lock is free.
//!
//! No Keychain is touched: the profile carries a marker naming no known
//! backend, so `load_identity` fails with a continuity error right after the
//! lock, before any secure store is asked.

use raven_core::identity_store::{load_identity, IdentityStoreError};
use raven_core::macos_keychain::FIRST_HINT_AFTER;
use raven_core::paths::DataDirLock;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const DIR_ENV: &str = "RAVEN_IDENTITY_LOCK_TEST_DIR";
/// The identity-store lock file in the data dir (a stable on-disk name).
const LOCK_FILE: &str = ".identity_store.lock.sqlite";
const NOTICE: &str = "raven: waiting for another raven program that is using your identity";
/// Upper bound for waiting on something that must happen; never the thing a
/// test measures.
const PATIENCE: Duration = Duration::from_secs(45);

/// A profile whose first read stops at the backend marker.
fn profile_that_never_reaches_a_secure_store() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("identity.backend"), "not-a-backend\n").expect("marker");
    dir
}

/// Child half. In a normal test run the variable is unset and this does
/// nothing; the parent tests below re-run this binary with it set.
#[test]
fn child_load_identity() {
    let Ok(dir) = std::env::var(DIR_ENV) else {
        return;
    };
    // The continuity error is expected (see the module docs); what the parent
    // watches is the wait for the lock that comes first.
    assert!(
        matches!(
            load_identity(Path::new(&dir)),
            Err(IdentityStoreError::Continuity(_))
        ),
        "the backend marker must stop the load before any secure store"
    );
}

fn spawn_child(dir: &Path) -> Child {
    Command::new(std::env::current_exe().expect("path of the running test binary"))
        .args([
            "--exact",
            "child_load_identity",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(DIR_ENV, dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the child test")
}

/// The child's stderr, line by line; the channel closes when the child exits.
fn stderr_lines(child: &mut Child) -> mpsc::Receiver<String> {
    let stderr = child.stderr.take().expect("piped stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    rx
}

/// Every remaining line until the child has exited (its stderr closes).
fn drain(child: &mut Child, rx: &mpsc::Receiver<String>) -> Vec<String> {
    let mut lines = Vec::new();
    loop {
        match rx.recv_timeout(PATIENCE) {
            Ok(line) => lines.push(line),
            Err(mpsc::RecvTimeoutError::Disconnected) => return lines,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = child.kill();
                panic!("the child did not finish after the lock was released: {lines:?}");
            }
        }
    }
}

#[test]
fn a_second_process_says_why_it_waits_and_carries_on_when_the_lock_is_free() {
    let dir = profile_that_never_reaches_a_secure_store();
    let holder = DataDirLock::acquire(dir.path(), LOCK_FILE).expect("take the lock");
    let started = Instant::now();
    let mut child = spawn_child(dir.path());
    let rx = stderr_lines(&mut child);

    // The child is stuck behind us; its notice is the signal to let go.
    let mut seen = Vec::new();
    loop {
        match rx.recv_timeout(PATIENCE) {
            Ok(line) => {
                let is_notice = line.starts_with(NOTICE);
                seen.push(line);
                if is_notice {
                    break;
                }
            }
            Err(_) => {
                let _ = child.kill();
                panic!("no notice from a process waiting for the identity lock: {seen:?}");
            }
        }
    }
    let waited = started.elapsed();
    drop(holder);

    // Never early; and not late either (the first attempt waits the hint
    // delay, not the 10 s a plain lock wait would).
    assert!(
        waited >= FIRST_HINT_AFTER - Duration::from_secs(1),
        "notice after {waited:?}"
    );
    assert!(
        waited < FIRST_HINT_AFTER + Duration::from_secs(6),
        "notice after {waited:?}"
    );
    let rest = drain(&mut child, &rx);
    let status = child.wait().expect("child status");
    assert!(
        status.success(),
        "child failed: {status:?} {seen:?} {rest:?}"
    );
    let all: Vec<&String> = seen.iter().chain(rest.iter()).collect();
    assert_eq!(
        all.iter().filter(|l| l.starts_with(NOTICE)).count(),
        1,
        "one notice per wait: {all:?}"
    );
    let notice = all.iter().find(|l| l.starts_with(NOTICE)).expect("notice");
    assert!(notice.ends_with("s)."), "{notice}");
    assert!(
        !all.iter()
            .any(|l| l.contains("seed") || l.contains("app.raven")),
        "no secrets or service ids in the notice: {all:?}"
    );
}

#[test]
fn a_free_lock_is_taken_without_a_word() {
    let dir = profile_that_never_reaches_a_secure_store();
    let mut child = spawn_child(dir.path());
    let rx = stderr_lines(&mut child);
    let lines = drain(&mut child, &rx);
    let status = child.wait().expect("child status");
    assert!(status.success(), "child failed: {status:?} {lines:?}");
    assert!(
        !lines.iter().any(|l| l.starts_with(NOTICE)),
        "nothing to announce when the lock is free: {lines:?}"
    );
}
