//! Public contract of the Keychain wait guard (`raven_core::macos_keychain`).
//!
//! No test here touches a Keychain: every "Keychain call" is a plain closure.
//! The watchdog's timing and stop rules are unit-tested next to the code with
//! injected thresholds and writers; this file pins what other crates see: the
//! pass-through behaviour of `guarded`, the one-line daemon marker, the
//! set-once process mode and (macOS only) the real production timing on a real
//! stderr, measured in a child process.

use raven_core::macos_keychain::{
    daemon_marker_line, guarded, hint_mode, last_daemon_marker, lock_wait_notice, set_hint_mode,
    DaemonMarker, HintMode, KeychainWhat, DAEMON_MARKER_TAG, FIRST_HINT_AFTER, REPEAT_HINT_EVERY,
};
use std::time::Duration;

const ALL: [KeychainWhat; 4] = [
    KeychainWhat::IdentitySeed,
    KeychainWhat::ChatHistoryKey,
    KeychainWhat::SessionSecret,
    KeychainWhat::PrekeyState,
];

#[test]
fn guarded_runs_the_call_on_the_calling_thread_and_returns_its_value() {
    let caller = std::thread::current().id();
    for what in ALL {
        let (id, value) = guarded(what, || (std::thread::current().id(), 0xC0FFEE_u32));
        assert_eq!(id, caller, "{what}");
        assert_eq!(value, 0xC0FFEE);
    }
}

#[test]
fn guarded_leaves_error_results_alone() {
    let denied: Result<Vec<u8>, String> = guarded(KeychainWhat::SessionSecret, || {
        Err("keychain read status -128".to_string())
    });
    assert_eq!(denied, Err("keychain read status -128".to_string()));
    let missing: Result<Option<[u8; 32]>, String> =
        guarded(KeychainWhat::IdentitySeed, || Ok(None));
    assert_eq!(missing, Ok(None));
}

#[test]
fn guarded_propagates_a_panic_and_stays_usable() {
    let caught = std::panic::catch_unwind(|| {
        guarded(KeychainWhat::PrekeyState, || -> u8 {
            panic!("the call itself failed")
        })
    });
    assert!(caught.is_err(), "the panic must reach the caller");
    // Nothing global was poisoned.
    assert_eq!(guarded(KeychainWhat::PrekeyState, || 9), 9);
}

#[test]
fn guarded_calls_may_nest() {
    let v = guarded(KeychainWhat::IdentitySeed, || {
        guarded(KeychainWhat::ChatHistoryKey, || 20) + 1
    });
    assert_eq!(v, 21);
}

#[test]
fn the_hint_schedule_is_three_seconds_then_every_thirty() {
    assert_eq!(FIRST_HINT_AFTER, Duration::from_secs(3));
    assert_eq!(REPEAT_HINT_EVERY, Duration::from_secs(30));
}

#[test]
fn the_daemon_marker_is_one_greppable_line() {
    assert_eq!(
        daemon_marker_line(KeychainWhat::IdentitySeed, 3),
        "raven-node: BLOCKED_ON_KEYCHAIN what=identity waited=3s \
         hint=\"approve the macOS dialog for this program (Always Allow)\""
    );
    // The words other crates and scripts read: pinned, not just self-consistent.
    for (what, label, token) in [
        (
            KeychainWhat::IdentitySeed,
            "your Raven identity",
            "identity",
        ),
        (
            KeychainWhat::ChatHistoryKey,
            "your chat history",
            "chat_history",
        ),
        (KeychainWhat::SessionSecret, "a conversation key", "session"),
        (KeychainWhat::PrekeyState, "key-exchange data", "prekey"),
    ] {
        assert_eq!(what.label(), label);
        assert_eq!(what.token(), token);
    }
    for what in ALL {
        let line = daemon_marker_line(what, 123);
        assert!(!line.contains('\n'), "{line}");
        assert!(line.contains(DAEMON_MARKER_TAG));
        // Machine tokens: one lowercase word, no spaces, never the words a
        // reader could mistake for key material.
        let token = what.token();
        assert!(token.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        assert!(!token.contains("seed") && !token.contains("private"));
        // A reader (ash) recovers exactly what was written.
        assert_eq!(
            last_daemon_marker(&format!("noise\n{line}\nmore noise\n")),
            Some(DaemonMarker {
                what: token.to_string(),
                waited_secs: 123
            })
        );
    }
}

#[test]
fn the_lock_wait_notice_is_plain_text_about_waiting_for_another_program() {
    // What a second raven process prints while another one holds the identity
    // lock (possibly across its own Keychain dialog).
    let notice = lock_wait_notice(3);
    assert!(
        notice.starts_with(
            "raven: waiting for another raven program that is using your identity (3s).\n"
        ),
        "{notice}"
    );
    assert!(notice.is_ascii() && notice.ends_with('\n'), "{notice}");
    assert!(notice.lines().all(|line| line.len() <= 80), "{notice}");
    for secret_like in ["app.raven", "seed", "/"] {
        assert!(!notice.contains(secret_like), "{notice}");
    }
}

#[test]
fn the_newest_marker_in_a_log_tail_wins() {
    let log = [
        "--- ash: starting raven-node service ---".to_string(),
        daemon_marker_line(KeychainWhat::IdentitySeed, 3),
        daemon_marker_line(KeychainWhat::IdentitySeed, 33),
        "raven-node ipc: listening /tmp/raven-501/raven-x.sock".to_string(),
    ]
    .join("\n");
    assert_eq!(
        last_daemon_marker(&log),
        Some(DaemonMarker {
            what: "identity".into(),
            waited_secs: 33
        })
    );
    assert_eq!(last_daemon_marker("raven-node ipc: listening"), None);
}

/// Process-wide state: this is the only test in this binary that sets it (the
/// child processes of the macOS test below have their own).
#[test]
fn the_hint_mode_is_set_once_and_the_first_call_wins() {
    assert_eq!(
        hint_mode(),
        HintMode::Interactive,
        "default is the human text"
    );
    assert!(set_hint_mode(HintMode::Daemon), "first call sets the mode");
    assert_eq!(hint_mode(), HintMode::Daemon);
    assert!(
        !set_hint_mode(HintMode::Interactive),
        "second call is ignored"
    );
    assert_eq!(hint_mode(), HintMode::Daemon);
}

/// Production timing on a real stderr: a child process runs one slow "Keychain
/// call" through `guarded` and the parent reads what it printed.
#[cfg(target_os = "macos")]
mod end_to_end {
    use super::*;
    use std::process::Command;

    const ROLE_ENV: &str = "RAVEN_KEYCHAIN_GUARD_TEST_CHILD";

    /// Child half. In a normal test run the variable is unset and this does
    /// nothing; the parent tests below re-run this binary with it set.
    #[test]
    fn child_slow_call() {
        let Ok(role) = std::env::var(ROLE_ENV) else {
            return;
        };
        if role == "daemon" {
            assert!(set_hint_mode(HintMode::Daemon));
        }
        // Long enough for the first hint (3 s), far too short for the
        // reminder (33 s). The sleep is the slow call under test.
        let value = guarded(KeychainWhat::IdentitySeed, || {
            std::thread::sleep(FIRST_HINT_AFTER + Duration::from_millis(700));
            7
        });
        assert_eq!(value, 7);
    }

    fn stderr_of_slow_child(role: &str) -> String {
        let exe = std::env::current_exe().expect("path of the running test binary");
        let out = Command::new(exe)
            .args([
                "--exact",
                "end_to_end::child_slow_call",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ROLE_ENV, role)
            .output()
            .expect("run the child test");
        assert!(out.status.success(), "child failed: {out:?}");
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    /// The whole seconds the first hint reports, from "... after <n>s.".
    fn reported_seconds(stderr: &str) -> u64 {
        let tail = stderr
            .split("(your Raven identity) after ")
            .nth(1)
            .unwrap_or_else(|| panic!("no hint in child stderr: {stderr}"));
        let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().expect("elapsed seconds")
    }

    #[test]
    fn a_slow_call_prints_one_human_hint_after_three_seconds() {
        let stderr = stderr_of_slow_child("human");
        assert_eq!(
            stderr
                .matches("still waiting for macOS Keychain access")
                .count(),
            1,
            "{stderr}"
        );
        assert!(
            stderr.contains("raven: still waiting for macOS Keychain access (your Raven identity)"),
            "{stderr}"
        );
        assert!(stderr.contains("\"Always Allow\""), "{stderr}");
        // A command in a terminal can be given up with Ctrl-C.
        assert!(stderr.contains("Ctrl-C gives up."), "{stderr}");
        // The thread that prints it can be late on a busy machine, never early.
        assert!((3..30).contains(&reported_seconds(&stderr)), "{stderr}");
        assert!(
            !stderr.contains(DAEMON_MARKER_TAG),
            "the human mode never logs the marker: {stderr}"
        );
    }

    #[test]
    fn the_daemon_mode_adds_the_marker_line_once() {
        let stderr = stderr_of_slow_child("daemon");
        assert_eq!(stderr.matches(DAEMON_MARKER_TAG).count(), 1, "{stderr}");
        assert!(
            stderr.contains("raven: still waiting for macOS Keychain access (your Raven identity)"),
            "the human text stays: {stderr}"
        );
        // Nothing can press Ctrl-C in a detached service: the text says what applies.
        assert!(!stderr.contains("Ctrl-C"), "{stderr}");
        assert!(stderr.contains("The service keeps waiting"), "{stderr}");
        let marker = last_daemon_marker(&stderr).expect("marker in child stderr");
        assert_eq!(marker.what, "identity");
        assert!((3..30).contains(&marker.waited_secs), "{stderr}");
        assert!(
            stderr.contains("hint=\"approve the macOS dialog for this program (Always Allow)\""),
            "{stderr}"
        );
    }
}
