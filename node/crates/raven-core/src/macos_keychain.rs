//! macOS Keychain wait guard ("Tier 0").
//!
//! Every Keychain item Raven creates trusts only the program that created it.
//! `ash` and `raven-node` are different programs (and an unsigned binary is a
//! different program again after every rebuild), so the first read by the
//! other one makes macOS ask the user through a dialog **inside** the
//! `SecItem*` call. That call has no timeout and prints nothing: from a
//! terminal the send, inbox or chat command just hangs.
//!
//! [`guarded`] runs the Keychain call unchanged on the **calling** thread and
//! starts a watchdog thread beside it. When the call is still running after
//! [`FIRST_HINT_AFTER`] the watchdog prints one human hint to stderr, then a
//! short reminder every [`REPEAT_HINT_EVERY`]; a drop guard stops it when the
//! call returns or panics. The guard only explains the wait. It never changes
//! the call's result, error mapping, locking or cancellation (a blocked call
//! cannot be cancelled; Ctrl-C ends the process as before). It takes no lock of
//! its own and the watchdog needs none from the call site.
//!
//! The hint comes from the process that is inside the Keychain call. A second
//! raven process that waits for a lock the first one holds across that call
//! (the identity-store lock does) hears nothing from this module: it prints
//! [`lock_wait_notice`] itself. The other cross-process waits (chat history, key
//! set-up, sessions, prekeys) are limited to about 10 s per step and then fail.
//!
//! The hint names WHAT is being read ([`KeychainWhat`], in plain words), never
//! an account name, hash, path or secret.
//!
//! The daemon calls [`set_hint_mode`]`(`[`HintMode::Daemon`]`)` once at start-up.
//! Its text then drops the Ctrl-C advice (a background service has no terminal
//! to press it in) and each hint is followed by one machine-greppable line
//! ([`daemon_marker_line`]) on the daemon's stderr, so `ash` can tell "the
//! service is blocked on a Keychain dialog" from a service that is merely slow
//! ([`last_daemon_marker`]). That stderr is `raven-node-service.log` when `ash`
//! started the service, and `raven-node.err` (next to `raven-node.log`) when the
//! launchd agent from `scripts/install/macos_launchd.sh` runs it.
//!
//! Other platforms have no such dialog: [`guarded`] is a plain call there. The
//! watchdog is still compiled into test builds of every platform so its timing
//! and stop rules are exercised everywhere.

use std::fmt;
use std::sync::OnceLock;
use std::time::Duration;

/// How long a Keychain call may run before the first hint is printed.
pub const FIRST_HINT_AFTER: Duration = Duration::from_secs(3);

/// Spacing of the short reminders printed after the first hint.
pub const REPEAT_HINT_EVERY: Duration = Duration::from_secs(30);

/// Marker word of the daemon log line (see [`daemon_marker_line`]).
pub const DAEMON_MARKER_TAG: &str = "BLOCKED_ON_KEYCHAIN";

/// What a Keychain call is for. Deliberately a closed list: the hint must
/// never carry account names, hashes or secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainWhat {
    IdentitySeed,
    ChatHistoryKey,
    SessionSecret,
    PrekeyState,
}

impl KeychainWhat {
    /// Plain words for the human hint: the reader is not an engineer, and
    /// "seed" next to a password dialog reads like a recovery phrase.
    pub const fn label(self) -> &'static str {
        match self {
            Self::IdentitySeed => "your Raven identity",
            Self::ChatHistoryKey => "your chat history",
            Self::SessionSecret => "a conversation key",
            Self::PrekeyState => "key-exchange data",
        }
    }

    /// Single lowercase token for the daemon log line (`what=<token>`).
    pub const fn token(self) -> &'static str {
        match self {
            Self::IdentitySeed => "identity",
            Self::ChatHistoryKey => "chat_history",
            Self::SessionSecret => "session",
            Self::PrekeyState => "prekey",
        }
    }
}

impl fmt::Display for KeychainWhat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Who reads the hints. `ash` (and tests) keep the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HintMode {
    /// Human text on stderr only, for a command run in a terminal (it can be
    /// given up with Ctrl-C).
    #[default]
    Interactive,
    /// Human text for a background service (no Ctrl-C advice) plus the
    /// [`daemon_marker_line`] for the service log.
    Daemon,
}

static HINT_MODE: OnceLock<HintMode> = OnceLock::new();

/// Choose the hint mode for the whole process. Meant to be called once, by
/// `raven-node`, before the first Keychain access. The first call wins:
/// `true` when this call set the mode, `false` when one was already set.
pub fn set_hint_mode(mode: HintMode) -> bool {
    HINT_MODE.set(mode).is_ok()
}

/// The mode in effect ([`HintMode::Interactive`] until one is set).
pub fn hint_mode() -> HintMode {
    HINT_MODE.get().copied().unwrap_or_default()
}

/// The one line the daemon logs next to the human hint. Fixed shape, no paths,
/// account names or hashes; `ash` greps for it (see [`last_daemon_marker`]).
pub fn daemon_marker_line(what: KeychainWhat, waited_secs: u64) -> String {
    format!(
        "raven-node: {DAEMON_MARKER_TAG} what={} waited={waited_secs}s \
         hint=\"approve the macOS dialog for this program (Always Allow)\"",
        what.token()
    )
}

/// A [`daemon_marker_line`] read back from a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonMarker {
    /// The [`KeychainWhat::token`] text.
    pub what: String,
    pub waited_secs: u64,
}

/// The newest complete marker line in `log` (for example the tail of the
/// service log), or `None`. Lines that merely mention the tag, or that were
/// cut short by the tail, are skipped.
pub fn last_daemon_marker(log: &str) -> Option<DaemonMarker> {
    log.lines().rev().find_map(parse_marker_line)
}

fn parse_marker_line(line: &str) -> Option<DaemonMarker> {
    let (_, fields) = line.split_once(DAEMON_MARKER_TAG)?;
    let mut what = None;
    let mut waited_secs = None;
    for field in fields.split_whitespace() {
        if let Some(value) = field.strip_prefix("what=") {
            let plain = !value.is_empty()
                && value.len() <= 24
                && value.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
            what = plain.then(|| value.to_string());
        } else if let Some(value) = field.strip_prefix("waited=") {
            waited_secs = value.strip_suffix('s').and_then(|n| n.parse().ok());
        }
    }
    Some(DaemonMarker {
        what: what?,
        waited_secs: waited_secs?,
    })
}

/// What a raven process prints once it has waited [`FIRST_HINT_AFTER`] for the
/// identity-store lock because another raven process holds it. That process may
/// itself be blocked in a Keychain dialog and keeps the lock until the dialog is
/// answered, so from outside the wait looks like a freeze, and [`guarded`] only
/// speaks inside the process that makes the call. The Keychain advice is
/// macOS-only. Plain words: no account names, paths or secrets.
pub fn lock_wait_notice(waited_secs: u64) -> String {
    lock_wait_text(waited_secs, cfg!(target_os = "macos"))
}

fn lock_wait_text(waited_secs: u64, keychain: bool) -> String {
    let mut text = format!(
        "raven: waiting for another raven program that is using your identity \
         ({waited_secs}s).\n"
    );
    if keychain {
        text.push_str("  If macOS is asking that program for Keychain access, answer the dialog\n");
        text.push_str("  (\"Always Allow\"). This command then continues by itself.\n");
    }
    text
}

/// Run one Keychain call. See the module docs: `f` runs unchanged on this
/// thread; a watchdog explains a long wait on stderr.
#[cfg(target_os = "macos")]
pub fn guarded<T>(what: KeychainWhat, f: impl FnOnce() -> T) -> T {
    watch::guarded_stderr(what, f)
}

/// Run one Keychain call. No other platform has a Keychain dialog, so this is
/// just `f()`.
#[cfg(not(target_os = "macos"))]
#[inline(always)]
pub fn guarded<T>(_what: KeychainWhat, f: impl FnOnce() -> T) -> T {
    f()
}

// The watchdog is only reachable from `guarded` on macOS; other platforms
// compile it for their unit tests alone.
#[cfg(any(target_os = "macos", test))]
mod watch {
    use super::{
        daemon_marker_line, hint_mode, HintMode, KeychainWhat, FIRST_HINT_AFTER, REPEAT_HINT_EVERY,
    };
    use std::io::Write;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::time::{Duration, Instant};

    /// How long a returning guard waits for its watchdog thread to wind down.
    /// That takes microseconds; the bound only matters when the watchdog is
    /// stuck writing to a stderr nobody drains, which must never hold up the
    /// Keychain caller.
    const QUIESCE_WAIT: Duration = Duration::from_millis(500);

    #[derive(Clone, Copy)]
    pub(super) struct Timing {
        pub(super) first_after: Duration,
        pub(super) repeat_every: Duration,
    }

    const PRODUCTION: Timing = Timing {
        first_after: FIRST_HINT_AFTER,
        repeat_every: REPEAT_HINT_EVERY,
    };

    pub(super) fn guarded_stderr<T>(what: KeychainWhat, f: impl FnOnce() -> T) -> T {
        guarded_to(std::io::stderr(), PRODUCTION, hint_mode(), what, f)
    }

    /// `guarded` with the writer, timing and mode injected.
    pub(super) fn guarded_to<W, T>(
        mut out: W,
        timing: Timing,
        mode: HintMode,
        what: KeychainWhat,
        f: impl FnOnce() -> T,
    ) -> T
    where
        W: Write + Send + 'static,
    {
        let _watchdog = Watchdog::start(timing, move |elapsed, first| {
            // One write per hint keeps its lines together. A closed or full
            // stderr must not take the Keychain call down with it.
            let _ = out.write_all(render(what, mode, elapsed.as_secs(), first).as_bytes());
        });
        f()
    }

    /// Text for one watchdog wake-up: the full hint the first time, a one-line
    /// reminder afterwards, plus the daemon marker in [`HintMode::Daemon`].
    /// A background service is detached from the terminal (or run by launchd),
    /// so Ctrl-C cannot reach it: its text never offers that way out.
    pub(super) fn render(
        what: KeychainWhat,
        mode: HintMode,
        elapsed_secs: u64,
        first: bool,
    ) -> String {
        let service = mode == HintMode::Daemon;
        let mut text = if first {
            let way_out = if service {
                SERVICE_WAITS
            } else {
                TERMINAL_GIVE_UP
            };
            format!(
                "raven: still waiting for macOS Keychain access ({what}) after {elapsed_secs}s.\n\
                 {}\n  the Mac itself. {way_out}\n",
                FIRST_HINT_DETAIL.join("\n")
            )
        } else {
            let way_out = if service {
                "; the service keeps waiting."
            } else {
                ", or press Ctrl-C to give up."
            };
            format!(
                "raven: still waiting for macOS Keychain access ({what}) after {elapsed_secs}s - \
                 answer the macOS dialog (\"Always Allow\"){way_out}\n"
            )
        };
        if service {
            text.push_str(&daemon_marker_line(what, elapsed_secs));
            text.push('\n');
        }
        text
    }

    /// The first hint, up to the sentence that depends on who is waiting.
    const FIRST_HINT_DETAIL: [&str; 5] = [
        "  macOS is probably asking whether this program may use the item - the",
        "  window can be hidden behind other windows. Enter your login password",
        "  there and choose \"Always Allow\" (not \"Deny\"). ash and raven-node are",
        "  separate programs, so each is asked once per item; a rebuilt or upgraded",
        "  unsigned binary is asked again. Over SSH there is no dialog: run this on",
    ];
    /// How a command in a terminal gives up.
    const TERMINAL_GIVE_UP: &str = "Ctrl-C gives up.";
    /// What a background service does instead: there is nothing to press.
    const SERVICE_WAITS: &str = "The service keeps waiting until you answer.";

    /// Watchdog thread of one guarded call. Dropping it (the call returned or
    /// panicked) stops the thread and waits, bounded, for it to be gone.
    struct Watchdog {
        /// Dropping the sender is the stop signal; nothing is ever sent.
        stop: Option<mpsc::Sender<()>>,
        /// Disconnects when the watchdog thread has finished.
        gone: Option<mpsc::Receiver<()>>,
    }

    impl Watchdog {
        /// `report(elapsed, first)` runs on the watchdog thread after
        /// `timing.first_after` and then every `timing.repeat_every` until the
        /// guard is dropped. `None` when the thread cannot be started: the
        /// Keychain call then simply runs unwatched.
        fn start(
            timing: Timing,
            report: impl FnMut(Duration, bool) + Send + 'static,
        ) -> Option<Self> {
            let (stop_tx, stop_rx) = mpsc::channel::<()>();
            let (gone_tx, gone_rx) = mpsc::channel::<()>();
            let started = Instant::now();
            std::thread::Builder::new()
                .name("raven-keychain-wait".into())
                .stack_size(256 * 1024)
                .spawn(move || {
                    wait_and_report(timing, started, stop_rx, report);
                    drop(gone_tx);
                })
                .ok()?;
            Some(Self {
                stop: Some(stop_tx),
                gone: Some(gone_rx),
            })
        }
    }

    impl Drop for Watchdog {
        fn drop(&mut self) {
            drop(self.stop.take());
            if let Some(gone) = self.gone.take() {
                let _ = gone.recv_timeout(QUIESCE_WAIT);
            }
        }
    }

    fn wait_and_report(
        timing: Timing,
        started: Instant,
        stop: mpsc::Receiver<()>,
        mut report: impl FnMut(Duration, bool),
    ) {
        let mut wait = timing.first_after;
        let mut first = true;
        loop {
            match stop.recv_timeout(wait) {
                Err(RecvTimeoutError::Timeout) => {
                    report(started.elapsed(), first);
                    first = false;
                    wait = timing.repeat_every;
                }
                // The only sender is the guard; it never sends, it hangs up.
                Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::macos_keychain::DAEMON_MARKER_TAG;
        use std::sync::Arc;

        /// `Write` that forwards every hint to a channel, and holds a probe
        /// `Arc` so a test can see when the watchdog thread (the only other
        /// owner) is gone.
        struct ChannelWriter {
            lines: mpsc::Sender<String>,
            _probe: Arc<()>,
        }

        impl Write for ChannelWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let text = String::from_utf8_lossy(buf).into_owned();
                let _ = self.lines.send(text);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn writer() -> (ChannelWriter, mpsc::Receiver<String>, Arc<()>) {
            let (tx, rx) = mpsc::channel();
            let probe = Arc::new(());
            let w = ChannelWriter {
                lines: tx,
                _probe: Arc::clone(&probe),
            };
            (w, rx, probe)
        }

        const ALL: [KeychainWhat; 4] = [
            KeychainWhat::IdentitySeed,
            KeychainWhat::ChatHistoryKey,
            KeychainWhat::SessionSecret,
            KeychainWhat::PrekeyState,
        ];

        /// Far longer than any test runs: the watchdog can only be heard from
        /// when a test wants it to.
        const NEVER: Duration = Duration::from_secs(3600);
        const SOON: Duration = Duration::from_millis(5);
        /// Upper bound for waiting on something that must happen; never the
        /// thing a test measures.
        const PATIENCE: Duration = Duration::from_secs(30);

        fn timing(first_after: Duration, repeat_every: Duration) -> Timing {
            Timing {
                first_after,
                repeat_every,
            }
        }

        #[test]
        fn first_hint_names_what_and_the_next_step() {
            let text = render(KeychainWhat::IdentitySeed, HintMode::Interactive, 3, true);
            assert!(text.starts_with(
                "raven: still waiting for macOS Keychain access (your Raven identity) after 3s.\n"
            ));
            for needle in [
                "macOS is probably asking whether this program may use the item",
                "hidden behind other windows",
                "\"Always Allow\" (not \"Deny\")",
                "ash and raven-node are",
                "rebuilt or upgraded",
                "Over SSH there is no dialog",
                "Ctrl-C gives up.",
            ] {
                assert!(text.contains(needle), "missing {needle:?} in {text}");
            }
            assert!(text.ends_with('\n'));
            assert!(!text.contains(DAEMON_MARKER_TAG));
            assert!(
                !text.contains("keeps waiting"),
                "service wording in a terminal hint"
            );
            assert!(!text.contains('\u{1b}'), "no ANSI on stderr");
            assert!(text.is_ascii());
            // Lines stay terminal-sized.
            assert!(text.lines().all(|line| line.len() <= 80), "{text}");
        }

        #[test]
        fn hint_labels_follow_what_is_read() {
            for (what, label) in [
                (KeychainWhat::IdentitySeed, "your Raven identity"),
                (KeychainWhat::ChatHistoryKey, "your chat history"),
                (KeychainWhat::SessionSecret, "a conversation key"),
                (KeychainWhat::PrekeyState, "key-exchange data"),
            ] {
                let text = render(what, HintMode::Interactive, 7, true);
                assert!(
                    text.contains(&format!("access ({label}) after 7s.")),
                    "{text}"
                );
                assert_eq!(what.to_string(), label);
            }
        }

        #[test]
        fn later_hints_are_a_single_reminder_line_with_the_elapsed_time() {
            let text = render(
                KeychainWhat::ChatHistoryKey,
                HintMode::Interactive,
                33,
                false,
            );
            assert_eq!(text.lines().count(), 1, "{text}");
            assert!(text.starts_with(
                "raven: still waiting for macOS Keychain access (your chat history) after 33s"
            ));
            assert!(text.contains("\"Always Allow\""));
            assert!(text.contains("Ctrl-C"));
            assert!(
                !text.contains("keeps waiting"),
                "service wording in a terminal hint"
            );
        }

        /// The labels are read by people who never heard of seeds or prekeys.
        #[test]
        fn hint_labels_are_plain_words() {
            for what in ALL {
                let label = what.label();
                assert!(label.is_ascii() && label.len() <= 24, "{label}");
                let lower = label.to_lowercase();
                for jargon in [
                    "seed", "prekey", "secret", "session", "rvn", "atsam", "pairinit", "oob", "dht",
                ] {
                    assert!(!lower.contains(jargon), "{label:?} contains {jargon:?}");
                }
                // They still have to read as part of the sentence.
                assert!(
                    render(what, HintMode::Interactive, 3, true)
                        .contains(&format!("access ({label}) after 3s.")),
                    "{label}"
                );
            }
        }

        /// A background service is detached from the terminal (ash starts it in
        /// its own process group; launchd owns it), so Ctrl-C cannot reach it:
        /// its text must not offer that, only what actually applies.
        #[test]
        fn the_service_text_never_offers_ctrl_c() {
            for what in ALL {
                for first in [true, false] {
                    let text = render(what, HintMode::Daemon, 33, first);
                    assert!(!text.contains("Ctrl-C"), "{text}");
                    assert!(!text.to_lowercase().contains("give up"), "{text}");
                    assert!(text.contains("keeps waiting"), "{text}");
                    // The rest of the advice is the same as in a terminal.
                    assert!(text.contains("\"Always Allow\""), "{text}");
                    assert!(
                        text.starts_with("raven: still waiting for macOS Keychain access ("),
                        "{text}"
                    );
                }
            }
            // `ash` quotes the last 8 lines of the service log when the service
            // does not come up (daemon_failure in ash's ext.rs): the whole first
            // hint, marker included, has to fit so its first line is not cut off.
            let first = render(KeychainWhat::IdentitySeed, HintMode::Daemon, 3, true);
            assert!(first.lines().count() <= 8, "{first}");
            assert!(first
                .lines()
                .filter(|l| !l.starts_with("raven-node:"))
                .all(|l| l.len() <= 80));
        }

        #[test]
        fn daemon_mode_adds_the_marker_after_the_human_text() {
            for first in [true, false] {
                let text = render(KeychainWhat::SessionSecret, HintMode::Daemon, 33, first);
                let mut lines: Vec<&str> = text.lines().collect();
                assert_eq!(
                    lines.pop(),
                    Some(
                        "raven-node: BLOCKED_ON_KEYCHAIN what=session waited=33s \
                         hint=\"approve the macOS dialog for this program (Always Allow)\""
                    )
                );
                assert!(lines[0].starts_with("raven: still waiting for macOS Keychain access"));
                assert_eq!(text.matches(DAEMON_MARKER_TAG).count(), 1);
            }
        }

        #[test]
        fn interactive_mode_never_prints_the_marker() {
            for first in [true, false] {
                let text = render(KeychainWhat::PrekeyState, HintMode::Interactive, 3, first);
                assert!(!text.contains(DAEMON_MARKER_TAG), "{text}");
            }
        }

        #[test]
        fn hint_never_carries_account_names_or_service_ids() {
            for what in [
                KeychainWhat::IdentitySeed,
                KeychainWhat::ChatHistoryKey,
                KeychainWhat::SessionSecret,
                KeychainWhat::PrekeyState,
            ] {
                for first in [true, false] {
                    let text = render(what, HintMode::Daemon, 3, first);
                    assert!(!text.contains("app.raven"), "{text}");
                    assert!(!text.contains('/'), "no paths in {text}");
                    assert!(
                        !text
                            .split(|c: char| !c.is_ascii_hexdigit())
                            .any(|run| run.len() >= 16),
                        "no hash-like runs in {text}"
                    );
                }
            }
        }

        #[test]
        fn a_slow_call_gets_exactly_one_hint_and_the_guard_then_stands_down() {
            let (out, rx, probe) = writer();
            let seen = guarded_to(
                out,
                timing(SOON, NEVER),
                HintMode::Interactive,
                KeychainWhat::IdentitySeed,
                || {
                    // The call "blocks" until the hint arrives; the channel is
                    // the clock, nothing sleeps.
                    rx.recv_timeout(PATIENCE)
                        .expect("a hint while the call is still running")
                },
            );
            assert!(seen.starts_with("raven: still waiting for macOS Keychain access"));
            // Returned: the watchdog is gone and can never print again.
            assert_eq!(Arc::strong_count(&probe), 1, "watchdog thread still alive");
            assert!(rx.try_recv().is_err(), "a second hint appeared");
        }

        #[test]
        fn a_long_call_keeps_reminding_with_the_elapsed_time() {
            let (out, rx, _probe) = writer();
            let all = guarded_to(
                out,
                timing(SOON, SOON),
                HintMode::Interactive,
                KeychainWhat::PrekeyState,
                || {
                    (0..3)
                        .map(|_| rx.recv_timeout(PATIENCE).expect("reminder"))
                        .collect::<Vec<_>>()
                },
            );
            assert!(all[0].lines().count() > 1, "first hint is the full text");
            for later in &all[1..] {
                assert_eq!(later.lines().count(), 1, "later hints are one line");
                assert!(later.contains("(key-exchange data) after "));
            }
        }

        #[test]
        fn a_fast_call_prints_nothing() {
            let (out, rx, probe) = writer();
            let value = guarded_to(
                out,
                timing(NEVER, NEVER),
                HintMode::Daemon,
                KeychainWhat::IdentitySeed,
                || {
                    // A short but real call: a watchdog that ignored its
                    // threshold would have time to speak. The sleep is how long
                    // the call takes, not something the test waits for.
                    std::thread::sleep(Duration::from_millis(100));
                    41 + 1
                },
            );
            assert_eq!(value, 42);
            assert_eq!(Arc::strong_count(&probe), 1, "watchdog thread still alive");
            assert!(rx.try_recv().is_err(), "a fast call must stay silent");
        }

        #[test]
        fn the_watchdog_stops_when_the_call_panics() {
            let (out, rx, probe) = writer();
            let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                guarded_to(
                    out,
                    timing(NEVER, NEVER),
                    HintMode::Interactive,
                    KeychainWhat::SessionSecret,
                    || -> u8 { panic!("keychain call exploded") },
                )
            }));
            let payload = caught.expect_err("the panic must propagate to the caller");
            assert_eq!(
                payload.downcast_ref::<&str>().copied(),
                Some("keychain call exploded")
            );
            assert_eq!(Arc::strong_count(&probe), 1, "watchdog thread still alive");
            assert!(rx.try_recv().is_err());
        }

        #[test]
        fn the_call_runs_on_the_calling_thread_and_its_result_is_untouched() {
            let (out, _rx, _probe) = writer();
            let caller = std::thread::current().id();
            let (id, result) = guarded_to(
                out,
                timing(NEVER, NEVER),
                HintMode::Interactive,
                KeychainWhat::ChatHistoryKey,
                || {
                    (
                        std::thread::current().id(),
                        Err::<u8, String>("denied".into()),
                    )
                },
            );
            assert_eq!(id, caller);
            assert_eq!(result, Err("denied".to_string()));
        }

        #[test]
        fn a_stuck_writer_cannot_hold_the_call_up_for_long() {
            // A watchdog that is blocked inside `write` (a stderr nobody
            // drains) is waited for only up to QUIESCE_WAIT.
            struct StuckWriter {
                entered: mpsc::Sender<()>,
                release: mpsc::Receiver<()>,
            }
            impl Write for StuckWriter {
                fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                    let _ = self.entered.send(());
                    let _ = self.release.recv_timeout(PATIENCE);
                    Ok(buf.len())
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let (entered_tx, entered_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let out = StuckWriter {
                entered: entered_tx,
                release: release_rx,
            };
            let started = Instant::now();
            guarded_to(
                out,
                timing(SOON, NEVER),
                HintMode::Interactive,
                KeychainWhat::IdentitySeed,
                || {
                    entered_rx
                        .recv_timeout(PATIENCE)
                        .expect("watchdog reached the writer")
                },
            );
            assert!(
                started.elapsed() < QUIESCE_WAIT + Duration::from_secs(10),
                "the guard waited for a stuck writer"
            );
            drop(release_tx);
        }

        #[test]
        fn stderr_flavour_passes_values_through() {
            // Fast call through the production entry point: no hint can be
            // due, the value and the panic behave exactly like a plain call.
            assert_eq!(guarded_stderr(KeychainWhat::IdentitySeed, || 7), 7);
            assert_eq!(PRODUCTION.first_after, Duration::from_secs(3));
            assert_eq!(PRODUCTION.repeat_every, Duration::from_secs(30));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_line_has_the_documented_shape() {
        assert_eq!(
            daemon_marker_line(KeychainWhat::IdentitySeed, 3),
            "raven-node: BLOCKED_ON_KEYCHAIN what=identity waited=3s \
             hint=\"approve the macOS dialog for this program (Always Allow)\""
        );
        assert_eq!(KeychainWhat::ChatHistoryKey.token(), "chat_history");
        assert_eq!(KeychainWhat::SessionSecret.token(), "session");
        assert_eq!(KeychainWhat::PrekeyState.token(), "prekey");
    }

    #[test]
    fn marker_round_trips_for_every_what() {
        for what in [
            KeychainWhat::IdentitySeed,
            KeychainWhat::ChatHistoryKey,
            KeychainWhat::SessionSecret,
            KeychainWhat::PrekeyState,
        ] {
            let line = daemon_marker_line(what, 63);
            assert_eq!(
                last_daemon_marker(&line),
                Some(DaemonMarker {
                    what: what.token().to_string(),
                    waited_secs: 63
                })
            );
            assert!(!line.contains('\n'), "one line");
        }
    }

    #[test]
    fn last_marker_is_the_newest_complete_one() {
        let log = format!(
            "--- ash: starting raven-node service ---\n{}\nraven-node ipc: listening x\n{}\n\
             raven-node: BLOCKED_ON_KEYCHAIN what=ident",
            daemon_marker_line(KeychainWhat::IdentitySeed, 3),
            daemon_marker_line(KeychainWhat::ChatHistoryKey, 33),
        );
        // The last line was cut by the log tail, so the one before it wins.
        let marker = last_daemon_marker(&log).expect("marker");
        assert_eq!(marker.what, "chat_history");
        assert_eq!(marker.waited_secs, 33);
    }

    #[test]
    fn unrelated_or_malformed_lines_are_not_markers() {
        assert_eq!(last_daemon_marker(""), None);
        assert_eq!(
            last_daemon_marker("raven-node ipc: listening /tmp/x.sock"),
            None
        );
        for bad in [
            "raven-node: BLOCKED_ON_KEYCHAIN",
            "raven-node: BLOCKED_ON_KEYCHAIN what=identity",
            "raven-node: BLOCKED_ON_KEYCHAIN waited=3s",
            "raven-node: BLOCKED_ON_KEYCHAIN what=identity waited=soon",
            "raven-node: BLOCKED_ON_KEYCHAIN what=Identity-Seed waited=3s",
            "raven-node: BLOCKED_ON_KEYCHAIN what= waited=3s",
        ] {
            assert_eq!(last_daemon_marker(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_lock_wait_notice_says_who_is_waited_for_and_what_to_do() {
        let mac = lock_wait_text(3, true);
        assert!(mac.starts_with(
            "raven: waiting for another raven program that is using your identity (3s).\n"
        ));
        assert!(mac.contains("macOS is asking that program for Keychain access"));
        assert!(mac.contains("\"Always Allow\""));
        assert!(mac.contains("continues by itself"));
        // Elsewhere there is no Keychain dialog to talk about.
        let other = lock_wait_text(3, false);
        assert_eq!(other.lines().count(), 1, "{other}");
        assert!(!other.contains("Keychain"));
        for text in [&mac, &other] {
            assert!(text.is_ascii() && text.ends_with('\n'));
            assert!(text.lines().all(|line| line.len() <= 80), "{text}");
            assert!(!text.contains("app.raven") && !text.contains('/'), "{text}");
        }
        assert_eq!(
            lock_wait_notice(61),
            lock_wait_text(61, cfg!(target_os = "macos"))
        );
        assert!(lock_wait_notice(61).contains("(61s)"));
    }

    #[test]
    fn hint_mode_defaults_to_the_human_text() {
        // `set_hint_mode` itself is process-wide state: it is covered by the
        // dedicated integration test, which owns its own process.
        assert_eq!(HintMode::default(), HintMode::Interactive);
    }

    #[test]
    fn guarded_is_a_plain_call_for_fast_work() {
        let caller = std::thread::current().id();
        let (id, value) = guarded(KeychainWhat::PrekeyState, || {
            (std::thread::current().id(), 5)
        });
        assert_eq!(id, caller);
        assert_eq!(value, 5);
    }
}
