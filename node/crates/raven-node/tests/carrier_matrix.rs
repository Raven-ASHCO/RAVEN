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
        ] {
            cmd.env_remove(k);
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
        let mut cmd = Command::new(raven_bin());
        self.env(&mut cmd);
        cmd.arg("--data-dir").arg(&self.dir).args(args);
        run_bounded(
            cmd,
            stdin,
            COMMAND_TIMEOUT,
            &format!("{} {:?}", self.name, args),
        )
    }

    fn create(root: &Path, name: &'static str) -> Self {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let mut p = Profile {
            name,
            dir,
            address: String::new(),
            pub_hex: String::new(),
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
        let publish = p.raven(&["prekey", "publish"], None);
        assert!(publish.ok, "{name} prekey publish:\n{}", publish.all());
        p
    }

    /// Start the daemon and wait until its IPC endpoint and LAN listener are up.
    fn start_service(&self) -> Service {
        let mut cmd = Command::new(NODE);
        self.env(&mut cmd);
        cmd.arg("service")
            .arg("--data-dir")
            .arg(&self.dir)
            .args(["--lan-listen", "127.0.0.1:0", "--ble-listen", "127.0.0.1:0"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("spawn raven-node service");
        let log = Arc::new(Log::default());
        log.follow(child.stderr.take().unwrap());
        let mut service = Service {
            child,
            log,
            lan_dial: String::new(),
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
