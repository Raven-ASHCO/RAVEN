//! Portable multi-process carrier harness (transports design 2026-10 §6.4).
//!
//! Real `raven-node service` daemons and the `raven` CLI on loopback, each
//! profile in its own temp data dir with the documented debug lab backends
//! (`locked-file` identity / session / prekey; chat history uses the lab key
//! on Unix and real DPAPI on Windows). Rust instead of bash so the same test
//! runs on ubuntu, macOS and Windows (named-pipe IPC there).
//!
//! - **C1 LAN direct:** A and B on 127.0.0.1, mutual contacts, one `raven
//!   send` each way, each delivered (sealed ACK back) and in the other inbox.
//! - **C3 contact gating (F4):** stranger S, who has B as a contact but is not
//!   B's contact, dials B. B closes before it identifies itself: S's send fails
//!   with `LINK_NOT_ACCEPTED`, B logs only the key-free reason, and S never
//!   received B's RLB1 (S would have cached B's certificate, since B is S's
//!   contact).
//!
//! - **C2 Internet direct (P1):** A and B with Internet direct listeners (A on
//!   127.0.0.1, B on [::1] when the runner has IPv6 loopback) and contacts that
//!   hold only Internet routes (one imported from a `raven whoami --card`, one
//!   set with `raven contact set-addr`). `raven send --carrier auto` (the
//!   default) reaches each other over Internet direct, names the carrier only in
//!   verbose mode, and a stranger holding B's card is refused before B
//!   identifies itself. Runs under the debug lab unlock (`RAVEN_LAB_TEST_A=1`)
//!   while `INTERNET_DIRECT_PRODUCTION_ENABLED` is false, and without it once
//!   the flag is flipped.
//!
//! - **C4 outbox restart (P2a):** A and B on loopback with a confirmed session.
//!   B goes down, A sends (queued: `raven send` ends at once and says raven-node
//!   keeps trying), A's service is killed, B stays down a few seconds, then
//!   both restart (A first, B on its old port). A's rebuilt outbox delivers the
//!   exact staged bytes with no new `raven send`: `raven outbox status` and the
//!   history say delivered, and B's inbox holds the message exactly once.
//!
//! Internet direct is for verified (pinned) contacts only (owner decision
//! 2026-10-08): C2 also checks that an unverified contact is refused on send
//! (nothing dialled) and by the listener (treated like a stranger).
//!
//! Synchronisation is event driven: the harness reads each daemon's stderr and
//! waits for its own "ipc: listening" / "lan_direct: listen <addr>" lines. Every
//! wait and every child process has a bounded deadline; nothing sleeps to
//! "give it time".
//!
//! `#[ignore]` (spawns processes, needs the `raven` binary):
//!
//! ```text
//! cargo build --locked -p ash -p raven-node
//! cargo test --locked -p raven-node --test carrier_matrix -- --ignored --nocapture
//! ```

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const NODE: &str = env!("CARGO_BIN_EXE_raven-node");
const READY_TIMEOUT: Duration = Duration::from_secs(120);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const LOG_TIMEOUT: Duration = Duration::from_secs(30);

/// The `raven` CLI: `RAVEN_HARNESS_RAVEN_BIN`, else next to `raven-node`
/// (`cargo build -p ash` puts both in the same target directory).
fn raven_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("RAVEN_HARNESS_RAVEN_BIN") {
        return PathBuf::from(p);
    }
    let node = Path::new(NODE);
    let name = if cfg!(windows) { "raven.exe" } else { "raven" };
    let path = node.with_file_name(name);
    assert!(
        path.is_file(),
        "{} is missing: run `cargo build --locked -p ash -p raven-node` first (or set \
         RAVEN_HARNESS_RAVEN_BIN)",
        path.display()
    );
    path
}

/// Lines of one process's stderr, appended by a reader thread; waiters block
/// on the condition variable until a matching line arrives or time runs out.
#[derive(Default)]
struct Log {
    lines: Mutex<(Vec<String>, bool)>,
    changed: Condvar,
}

impl Log {
    fn follow(self: &Arc<Self>, stream: impl Read + Send + 'static) {
        let log = Arc::clone(self);
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines() {
                let Ok(line) = line else { break };
                log.lines.lock().unwrap().0.push(line);
                log.changed.notify_all();
            }
            log.lines.lock().unwrap().1 = true;
            log.changed.notify_all();
        });
    }

    /// The first line matching `pred` (already seen or arriving within
    /// `timeout`). `None` on timeout or when the stream ended without one.
    fn wait_for(&self, timeout: Duration, pred: impl Fn(&str) -> bool) -> Option<String> {
        let deadline = Instant::now() + timeout;
        let mut guard = self.lines.lock().unwrap();
        loop {
            if let Some(hit) = guard.0.iter().find(|l| pred(l)) {
                return Some(hit.clone());
            }
            let now = Instant::now();
            if guard.1 || now >= deadline {
                return None;
            }
            guard = self.changed.wait_timeout(guard, deadline - now).unwrap().0;
        }
    }

    fn text(&self) -> String {
        self.lines.lock().unwrap().0.join("\n")
    }
}

/// One running `raven-node service`; killed when dropped.
struct Service {
    child: Child,
    log: Arc<Log>,
    lan_dial: String,
    /// The bound Internet direct address (empty without `--internet-listen`).
    internet_dial: String,
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

struct Output {
    ok: bool,
    stdout: String,
    stderr: String,
}

impl Output {
    fn all(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

struct Profile {
    name: &'static str,
    dir: PathBuf,
    address: String,
    pub_hex: String,
    fingerprint: String,
    /// Debug lab unlock for Internet direct (`RAVEN_LAB_TEST_A=1`) on every
    /// process of this profile; the C1 profiles run without it.
    lab_internet: bool,
}

impl Profile {
    /// Every process of this profile gets the same lab environment, including
    /// its own Windows pipe name (debug builds; ignored on Unix, where the IPC
    /// socket already lives in the data dir).
    fn env(&self, cmd: &mut Command) {
        for k in [
            "RAVEN_PREKEY_BACKEND",
            "RAVEN_SESSION_BACKEND",
            "RAVEN_KEYSTORE_PASSPHRASE",
            "RAVEN_LAB_TEST_A",
            "RAVEN_DATA_DIR",
            "ASH_DATA_DIR",
            "RAVEN_INTERNET_LISTEN",
            "RAVEN_PEER",
            "ASH_LAN_DIAL",
            "RAVEN_VERBOSE",
            "ASH_VERBOSE",
        ] {
            cmd.env_remove(k);
        }
        if self.lab_internet {
            cmd.env("RAVEN_LAB_TEST_A", "1");
        }
        cmd.env("RAVEN_IDENTITY_BACKEND", "locked-file")
            .env("RAVEN_CHAT_HISTORY_BACKEND", "locked-file")
            .env("RAVEN_ALLOW_EPHEMERAL_DATA_DIR", "1")
            .env("RAVEN_SERVICE_LAN_LISTEN", "127.0.0.1:0")
            .env(
                "RAVEN_LAB_IPC_PIPE_SUFFIX",
                format!("cm-{}-{}", std::process::id(), self.name),
            )
            .env("NO_COLOR", "1");
    }

    fn raven(&self, args: &[&str], stdin: Option<&str>) -> Output {
        self.raven_with(args, stdin, &[])
    }

    fn raven_with(&self, args: &[&str], stdin: Option<&str>, env: &[(&str, &str)]) -> Output {
        let mut cmd = Command::new(raven_bin());
        self.env(&mut cmd);
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.arg("--data-dir").arg(&self.dir).args(args);
        run_bounded(
            cmd,
            stdin,
            COMMAND_TIMEOUT,
            &format!("{} {:?}", self.name, args),
        )
    }

    fn create(root: &Path, name: &'static str) -> Self {
        Self::create_with(root, name, false)
    }

    fn create_with(root: &Path, name: &'static str, lab_internet: bool) -> Self {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let mut p = Profile {
            name,
            dir,
            address: String::new(),
            pub_hex: String::new(),
            fingerprint: String::new(),
            lab_internet,
        };
        let init = p.raven(&["init"], None);
        assert!(init.ok, "{name} init failed:\n{}", init.all());
        let field = |key: &str| {
            init.stdout
                .lines()
                .find_map(|l| l.trim().strip_prefix(key).map(str::to_string))
                .unwrap_or_else(|| panic!("{name} init printed no {key}:\n{}", init.all()))
        };
        p.address = field("address=");
        p.pub_hex = field("pub_hex=");
        p.fingerprint = field("fingerprint=");
        let publish = p.raven(&["prekey", "publish"], None);
        assert!(publish.ok, "{name} prekey publish:\n{}", publish.all());
        p
    }

    /// Start the daemon and wait until its IPC endpoint and LAN listener are up.
    fn start_service(&self) -> Service {
        self.start_service_with(None)
    }

    /// [`Self::start_service`], plus an Internet direct listener on `internet`
    /// (waited for too) when given.
    fn start_service_with(&self, internet: Option<&str>) -> Service {
        self.start_service_on("127.0.0.1:0", internet)
    }

    /// [`Self::start_service_with`] on a chosen LAN listen address (a restart
    /// that must come back on the same port).
    fn start_service_on(&self, lan_listen: &str, internet: Option<&str>) -> Service {
        let mut cmd = Command::new(NODE);
        self.env(&mut cmd);
        cmd.arg("service").arg("--data-dir").arg(&self.dir).args([
            "--lan-listen",
            lan_listen,
            "--ble-listen",
            "127.0.0.1:0",
        ]);
        if let Some(addr) = internet {
            cmd.args(["--internet-listen", addr]);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn raven-node service");
        let log = Arc::new(Log::default());
        log.follow(child.stderr.take().unwrap());
        let mut service = Service {
            child,
            log,
            lan_dial: String::new(),
            internet_dial: String::new(),
        };
        let ipc = service
            .log
            .wait_for(READY_TIMEOUT, |l| l.contains("raven-node ipc: listening"));
        let lan = service.log.wait_for(READY_TIMEOUT, |l| {
            l.contains("raven-node lan_direct: listen ")
        });
        let (Some(_), Some(lan)) = (ipc, lan) else {
            panic!(
                "{} service did not come up within {READY_TIMEOUT:?}:\n{}",
                self.name,
                service.log.text()
            );
        };
        service.lan_dial = lan.rsplit(' ').next().unwrap().trim().to_string();
        if internet.is_some() {
            let inet = service.log.wait_for(READY_TIMEOUT, |l| {
                l.contains("raven-node internet_direct: listen ")
            });
            let Some(inet) = inet else {
                panic!(
                    "{} internet listener did not come up within {READY_TIMEOUT:?}:\n{}",
                    self.name,
                    service.log.text()
                );
            };
            service.internet_dial = inet.rsplit(' ').next().unwrap().trim().to_string();
        }
        // The listener line is printed after bind; one positive ping proves the
        // CLI reaches this daemon (on Windows: this profile's own pipe).
        let ping = self.raven(&["ipc-ping"], None);
        assert!(
            ping.ok,
            "{} ipc-ping failed:\n{}\n{}",
            self.name,
            ping.all(),
            service.log.text()
        );
        service
    }

    fn add_contact(&self, other: &Profile, tag: &str, lan_dial: &str) {
        let out = self.raven(
            &[
                "contact",
                "add",
                "--address",
                &other.address,
                "--pub-hex",
                &other.pub_hex,
                "--petname",
                tag,
                "--tag",
                tag,
                "--lan-dial",
                lan_dial,
            ],
            None,
        );
        assert!(out.ok, "{} contact add {tag}:\n{}", self.name, out.all());
    }

    fn send(&self, tag: &str, text: &str) -> Output {
        self.raven(
            &["send", "--contact", &format!("@{tag}")],
            Some(&format!("{text}\n")),
        )
    }

    fn inbox(&self) -> String {
        let out = self.raven(&["inbox"], None);
        assert!(out.ok, "{} inbox:\n{}", self.name, out.all());
        out.stdout
    }
}

/// Run `cmd` with a hard deadline (killed on expiry; the test then fails).
fn run_bounded(mut cmd: Command, stdin: Option<&str>, timeout: Duration, what: &str) -> Output {
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap_or_else(|e| panic!("spawn {what}: {e}"));
    if let Some(text) = stdin {
        let mut pipe = child.stdin.take().unwrap();
        let _ = pipe.write_all(text.as_bytes());
        // Dropping the pipe closes stdin (EOF ends the message).
    }
    let collect = |stream: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = String::new();
            if let Some(mut s) = stream {
                let _ = s.read_to_string(&mut buf);
            }
            buf
        })
    };
    let out = collect(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = collect(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let child = Arc::new(Mutex::new(child));
    let waiter = Arc::clone(&child);
    // `try_wait` behind the lock lets the timeout path still kill the child.
    std::thread::spawn(move || loop {
        let done = waiter.lock().unwrap().try_wait();
        match done {
            Ok(Some(status)) => {
                let _ = tx.send(status.success());
                return;
            }
            Ok(None) => std::thread::park_timeout(Duration::from_millis(20)),
            Err(_) => {
                let _ = tx.send(false);
                return;
            }
        }
    });
    let ok = match rx.recv_timeout(timeout) {
        Ok(ok) => ok,
        Err(_) => {
            let _ = child.lock().unwrap().kill();
            panic!(
                "{what} did not finish within {timeout:?}:\n{}\n{}",
                out.join().unwrap_or_default(),
                err.join().unwrap_or_default()
            );
        }
    };
    Output {
        ok,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    }
}

/// `[::1]` when this runner has IPv6 loopback, else `127.0.0.1`.
fn second_loopback() -> &'static str {
    if std::net::TcpListener::bind("[::1]:0").is_ok() {
        "[::1]:0"
    } else {
        eprintln!("note: no IPv6 loopback on this runner; C2 uses 127.0.0.1 for both nodes");
        "127.0.0.1:0"
    }
}

/// The Internet direct lab unlock is needed only while the P1 flag is off;
/// after the flip C2 runs the production path unchanged.
fn internet_lab_unlock() -> bool {
    !raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED
}

fn lab_ready() -> bool {
    if !cfg!(debug_assertions) {
        eprintln!("skipped: the lab locked-file backends need a debug build");
        return false;
    }
    true
}

fn assert_delivered(from: &str, out: &Output) {
    let all = out.all().to_lowercase();
    assert!(
        out.ok && all.contains("status") && all.contains("delivered"),
        "{from} send was not delivered:\n{}",
        out.all()
    );
}

/// C1 + C3 on one runner. One test so the daemons are started once.
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c1_lan_direct_both_ways_and_c3_stranger_is_not_accepted() {
    if !lab_ready() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create(root.path(), "a");
    let b = Profile::create(root.path(), "b");
    let a_svc = a.start_service();
    let b_svc = b.start_service();

    // ── C1: LAN direct, one send each way ────────────────────────────────
    a.add_contact(&b, "bob", &b_svc.lan_dial);
    b.add_contact(&a, "alice", &a_svc.lan_dial);

    let sent = a.send("bob", "c1 hello from a");
    assert_delivered("a→b", &sent);
    // Positive control for C3 below: a contact's RLB1 lands in the durable
    // peer cache of the dialer.
    let a_cache = std::fs::read_to_string(a.dir.join("peer_device_certs.json")).unwrap_or_default();
    assert!(
        a_cache.contains(&b.pub_hex),
        "a did not cache b's certificate after a delivered send"
    );
    assert!(
        b.inbox().contains("c1 hello from a"),
        "b inbox misses a's message"
    );

    let sent = b.send("alice", "c1 hello from b");
    assert_delivered("b→a", &sent);
    assert!(
        a.inbox().contains("c1 hello from b"),
        "a inbox misses b's message"
    );

    // ── C3: a stranger learns nothing but "not accepted" ─────────────────
    let s = Profile::create(root.path(), "s");
    let _s_svc = s.start_service();
    s.add_contact(&b, "bob", &b_svc.lan_dial);
    let refused = s.send("bob", "c3 stranger probe");
    assert!(!refused.ok, "stranger send succeeded:\n{}", refused.all());
    assert!(
        !refused.all().to_lowercase().contains("status: delivered"),
        "{}",
        refused.all()
    );
    assert!(
        refused.all().contains("LINK_NOT_ACCEPTED"),
        "the stranger must see only the fixed refusal:\n{}",
        refused.all()
    );
    let reason = b_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| {
            l.contains("lan_direct inbound") && l.contains("not a local contact")
        })
        .unwrap_or_else(|| panic!("b did not log the refusal:\n{}", b_svc.log.text()));
    assert!(
        !reason.contains(&s.pub_hex) && !reason.contains(&s.address),
        "the refusal log names the stranger: {reason}"
    );
    // B is S's contact, so an RLB1 offer from B would have been persisted in
    // S's durable peer cache. It must not be there: S got no bundle.
    let cache = std::fs::read_to_string(s.dir.join("peer_device_certs.json")).unwrap_or_default();
    assert!(
        !cache.contains(&b.pub_hex),
        "the stranger received b's certificate:\n{cache}"
    );
    assert!(
        !b.inbox().contains("c3 stranger probe"),
        "b accepted the stranger's message"
    );
    // B's contacts still get through after the refusal.
    let again = a.send("bob", "c1 after the stranger");
    assert_delivered("a→b after c3", &again);
    assert!(b.inbox().contains("c1 after the stranger"));
}

/// C2: Internet direct between two services whose contacts hold only Internet
/// routes, both ways, plus a stranger refused (lab gate; transports design
/// §6.4 C2, §7.2).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c2_internet_direct_routes_both_ways_and_stranger_is_refused() {
    if !lab_ready() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create_with(root.path(), "ia", internet_lab_unlock());
    let b = Profile::create_with(root.path(), "ib", internet_lab_unlock());
    let a_svc = a.start_service_with(Some("127.0.0.1:0"));
    let b_svc = b.start_service_with(Some(second_loopback()));
    eprintln!(
        "C2: a internet={} b internet={} (lab unlock: {})",
        a_svc.internet_dial,
        b_svc.internet_dial,
        internet_lab_unlock()
    );
    assert!(
        a_svc.log.text().contains("dial≠WAN"),
        "missing the lab listen claim:\n{}",
        a_svc.log.text()
    );

    // A imports B from B's card (Internet route only, fingerprint pinned).
    let card = b.raven(&["whoami", "--card", "--inet", &b_svc.internet_dial], None);
    assert!(card.ok, "b whoami --card:\n{}", card.all());
    let card_line = card.stdout.trim();
    assert_eq!(card.stdout.trim_end().lines().count(), 1, "{}", card.stdout);
    assert!(card_line.starts_with("raven-card/1 "), "{card_line}");
    let added = a.raven(
        &[
            "contact",
            "add",
            "--card",
            card_line,
            "--petname",
            "bob",
            "--tag",
            "bob",
            "--verify-fp",
            &b.fingerprint,
        ],
        None,
    );
    assert!(added.ok, "a contact add --card:\n{}", added.all());
    assert!(added.stdout.contains("contact saved"), "{}", added.all());
    // B adds A the classic way, then saves A's Internet route with set-addr.
    let added = b.raven(
        &[
            "contact",
            "add",
            "--address",
            &a.address,
            "--pub-hex",
            &a.pub_hex,
            "--petname",
            "alice",
            "--tag",
            "alice",
        ],
        None,
    );
    assert!(added.ok, "b contact add:\n{}", added.all());
    let set = b.raven(
        &[
            "contact",
            "set-addr",
            "@alice",
            "--internet",
            &a_svc.internet_dial,
        ],
        None,
    );
    assert!(set.ok, "b contact set-addr:\n{}", set.all());
    let a_book = std::fs::read_to_string(a.dir.join("contacts.json")).unwrap();
    assert!(
        a_book.contains(&format!("\"internet_dial\": \"{}\"", b_svc.internet_dial))
            && a_book.contains("\"lan_dial\": \"\""),
        "a's contact for b must hold only the Internet route:\n{a_book}"
    );

    // B has not verified A (no --verify-fp): Internet delivery needs a pinned
    // contact, so B's send is refused at once and nothing is dialled.
    let a_inbox_before = a.inbox();
    let unverified = b.send("alice", "c2 must wait for verification");
    assert!(!unverified.ok, "{}", unverified.all());
    assert!(
        unverified.all().contains(
            "@alice is not verified: Internet delivery needs the fingerprint checked first"
        ),
        "{}",
        unverified.all()
    );
    assert!(
        unverified.all().contains("CONTACT_NOT_VERIFIED")
            && unverified.all().contains("Nothing was dialled")
            && unverified.all().contains("--verify-fp"),
        "{}",
        unverified.all()
    );
    assert_eq!(a.inbox(), a_inbox_before, "nothing reached a");
    assert!(
        !a_svc.log.text().contains("internet_direct inbound"),
        "a saw no Internet dial at all:\n{}",
        a_svc.log.text()
    );
    // B verifies A's fingerprint and pins it (adding again with --verify-fp
    // keeps the petname, tag and routes).
    let pinned = b.raven(
        &[
            "contact",
            "add",
            "--address",
            &a.address,
            "--pub-hex",
            &a.pub_hex,
            "--verify-fp",
            &a.fingerprint,
        ],
        None,
    );
    assert!(pinned.ok, "b pins a:\n{}", pinned.all());
    assert!(
        pinned.stdout.contains("pinned      yes"),
        "{}",
        pinned.all()
    );

    // No LAN route: `--carrier lan` refuses at once, nothing is dialled.
    let lan_only = a.raven(
        &["send", "--contact", "@bob", "--carrier", "lan"],
        Some("c2 must not go out\n"),
    );
    assert!(!lan_only.ok, "{}", lan_only.all());
    assert!(
        lan_only.all().contains("no reachable lan_dial"),
        "{}",
        lan_only.all()
    );

    // Default carrier (auto) → Internet direct; the carrier is not named.
    let sent = a.send("bob", "c2 hello over internet from a");
    assert_delivered("a→b (internet)", &sent);
    assert!(
        !sent.stdout.contains("carrier="),
        "auto must name the carrier only in verbose mode:\n{}",
        sent.all()
    );
    assert!(
        b.inbox().contains("c2 hello over internet from a"),
        "b inbox misses a's Internet message"
    );
    // The other way, verbose: the carrier is named.
    let sent = b.raven_with(
        &["send", "--contact", "@alice"],
        Some("c2 hello over internet from b\n"),
        &[("RAVEN_VERBOSE", "1")],
    );
    assert_delivered("b→a (internet)", &sent);
    assert!(
        sent.stdout.contains("carrier=internet_dial"),
        "verbose send must name the carrier:\n{}",
        sent.all()
    );
    assert!(
        a.inbox().contains("c2 hello over internet from b"),
        "a inbox misses b's Internet message"
    );
    let status = b.raven(&["status"], None);
    assert!(status.ok, "b status:\n{}", status.all());
    let row = status
        .stdout
        .lines()
        .find(|l| l.trim_start().starts_with("internet "))
        .unwrap_or_else(|| panic!("no internet row in status:\n{}", status.stdout));
    assert!(row.contains("YES"), "{row}");

    // ── Stranger: S holds B's card (verified), B does not know S ─────────
    let s = Profile::create_with(root.path(), "is", internet_lab_unlock());
    let _s_svc = s.start_service();
    let added = s.raven(
        &[
            "contact",
            "add",
            "--card",
            card_line,
            "--petname",
            "bob",
            "--tag",
            "bob",
            "--verify-fp",
            &b.fingerprint,
        ],
        None,
    );
    assert!(added.ok, "s contact add --card:\n{}", added.all());
    let refused = s.send("bob", "c2 stranger probe");
    assert!(!refused.ok, "stranger send succeeded:\n{}", refused.all());
    assert!(
        !refused.stdout.to_lowercase().contains("delivered"),
        "{}",
        refused.all()
    );
    assert!(
        refused.all().contains("LINK_NOT_ACCEPTED"),
        "the stranger must see only the fixed refusal:\n{}",
        refused.all()
    );
    let reason = b_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| {
            l.contains("internet_direct inbound") && l.contains("not a local contact")
        })
        .unwrap_or_else(|| panic!("b did not log the refusal:\n{}", b_svc.log.text()));
    let stranger_logged = Instant::now();
    assert!(
        !reason.contains(&s.pub_hex) && !reason.contains(&s.address),
        "the refusal log names the stranger: {reason}"
    );
    let cache = std::fs::read_to_string(s.dir.join("peer_device_certs.json")).unwrap_or_default();
    assert!(
        !cache.contains(&b.pub_hex),
        "the stranger received b's certificate:\n{cache}"
    );
    assert!(
        !b.inbox().contains("c2 stranger probe"),
        "b accepted the stranger's message"
    );
    // ── Unverified contact: B adds S but never pins it ───────────────────
    // On the Internet listener such a contact is a stranger: S learns nothing
    // but "not accepted" (no hello, no RLB1), and B logs a key-free reason.
    let added = b.raven(
        &[
            "contact",
            "add",
            "--address",
            &s.address,
            "--pub-hex",
            &s.pub_hex,
            "--petname",
            "sam",
            "--tag",
            "sam",
        ],
        None,
    );
    assert!(added.ok, "b contact add s:\n{}", added.all());
    // Peer-caused refusals are logged once per 10 s window: let the stranger's
    // window close so this refusal gets its own line.
    std::thread::sleep(Duration::from_secs(11).saturating_sub(stranger_logged.elapsed()));
    let refused = s.send("bob", "c2 unverified contact probe");
    assert!(!refused.ok, "unverified send succeeded:\n{}", refused.all());
    assert!(
        !refused.stdout.to_lowercase().contains("delivered"),
        "{}",
        refused.all()
    );
    assert!(
        refused.all().contains("LINK_NOT_ACCEPTED"),
        "an unverified contact must see only the fixed refusal:\n{}",
        refused.all()
    );
    let reason = b_svc
        .log
        .wait_for(LOG_TIMEOUT, |l| {
            l.contains("internet_direct inbound") && l.contains("not verified")
        })
        .unwrap_or_else(|| panic!("b did not log the refusal:\n{}", b_svc.log.text()));
    assert!(
        !reason.contains(&s.pub_hex) && !reason.contains(&s.address),
        "the refusal log names the contact: {reason}"
    );
    let cache = std::fs::read_to_string(s.dir.join("peer_device_certs.json")).unwrap_or_default();
    assert!(
        !cache.contains(&b.pub_hex),
        "the unverified contact received b's certificate:\n{cache}"
    );
    assert!(
        !b.inbox().contains("c2 unverified contact probe"),
        "b accepted the unverified contact's Internet message"
    );
    // A still gets through after the refusals.
    let again = a.send("bob", "c2 after the stranger");
    assert_delivered("a→b after the stranger", &again);
    assert!(b.inbox().contains("c2 after the stranger"));
}

/// A free loopback port for a service that must restart on the same address.
fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// The 8-hex message id a queued send prints (`mid=1a2b3c4d…`).
fn queued_mid(out: &Output) -> String {
    let all = out.all();
    let at = all
        .find("mid=")
        .unwrap_or_else(|| panic!("no mid= in the queued line:\n{all}"));
    all[at + 4..]
        .chars()
        .take_while(char::is_ascii_hexdigit)
        .collect()
}

/// C4: a message staged while B is down is delivered by A's background outbox
/// after both services restart, with no new `raven send` (transports design
/// §6.4 C4, P2a).
#[test]
#[ignore = "multi-process harness: cargo build -p ash first, then run with --ignored"]
fn c4_outbox_delivers_after_a_restart_without_a_new_send() {
    if !lab_ready() {
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let a = Profile::create(root.path(), "oa");
    let b = Profile::create(root.path(), "ob");
    let b_listen = format!("127.0.0.1:{}", free_loopback_port());
    let a_svc = a.start_service();
    let b_svc = b.start_service_on(&b_listen, None);
    assert_eq!(b_svc.lan_dial, b_listen);
    a.add_contact(&b, "bob", &b_svc.lan_dial);
    b.add_contact(&a, "alice", &a_svc.lan_dial);
    assert_delivered("a→b (session)", &a.send("bob", "c4 first"));

    // B goes down; A's send is queued and handed to raven-node's outbox, and
    // `raven send` ends right away instead of waiting the peer out.
    drop(b_svc);
    let text = "c4 sent while bob was down";
    let started = Instant::now();
    let queued = a.send("bob", text);
    let took = started.elapsed();
    assert!(!queued.ok, "nothing confirmed it yet:\n{}", queued.all());
    assert!(
        queued
            .all()
            .contains("raven-node keeps trying in the background until"),
        "{}",
        queued.all()
    );
    assert!(took < Duration::from_secs(10), "raven send took {took:?}");
    let mid = queued_mid(&queued);
    assert_eq!(mid.len(), 8, "{mid}");
    let status = a.raven(&["outbox", "status", &mid], None);
    assert!(status.ok, "{}", status.all());
    assert!(
        ["state       queued", "state       sent", "state       held"]
            .iter()
            .any(|s| status.stdout.contains(s)),
        "{}",
        status.all()
    );

    // Kill A after staging: the schedule is in memory only, the staged bytes
    // are in A's session store. B stays down for a few seconds (the scenario,
    // not a synchronisation), then A comes back first (its rebuilt outbox
    // tries, finds B down and backs off), then B on its old port.
    drop(a_svc);
    std::thread::sleep(Duration::from_secs(3));
    let a_svc = a.start_service();
    assert!(
        a_svc
            .log
            .wait_for(READY_TIMEOUT, |l| l.contains("raven-node outbox: running"))
            .is_some(),
        "a's outbox did not start:\n{}",
        a_svc.log.text()
    );
    std::thread::sleep(Duration::from_secs(2));
    let b_svc = b.start_service_on(&b_listen, None);

    // No new send: A's outbox delivers on its next retry (5 s doubling).
    let deadline = Instant::now() + Duration::from_secs(90);
    let delivered = loop {
        let st = a.raven(&["outbox", "status", &mid], None);
        if st.ok && st.stdout.contains("state       delivered") {
            break st;
        }
        assert!(
            Instant::now() < deadline,
            "not delivered within 90 s:\n{}\n{}\n{}",
            st.all(),
            a_svc.log.text(),
            b_svc.log.text()
        );
        std::thread::sleep(Duration::from_millis(500));
    };
    assert!(
        delivered.stdout.contains("history     delivered"),
        "{}",
        delivered.all()
    );
    assert!(
        delivered.stdout.contains("carrier     lan_dial"),
        "{}",
        delivered.all()
    );
    let inbox = b.inbox();
    assert_eq!(
        inbox.matches(text).count(),
        1,
        "exactly once on b:\n{inbox}"
    );
    let list = a.raven(&["outbox", "list"], None);
    assert!(list.ok, "{}", list.all());
    assert!(
        list.stdout.contains("Nothing waiting"),
        "nothing left to retry:\n{}",
        list.all()
    );
    // The next send needs nothing from the outbox and is delivered as usual.
    assert_delivered("a→b after c4", &a.send("bob", "c4 after the restart"));
    assert_eq!(b.inbox().matches(text).count(), 1, "still exactly once");
}
