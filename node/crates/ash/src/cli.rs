//! RAVEN terminal CLI (`ash` product name). Local-only Raven Node control.
//!
//! This is the **product** CLI in `node/` — not Cursor/ash-autonomous automation.
//! Never prints private keys, seeds, session keys, recovery secrets, or plaintext.

// ── stdout that survives a closed pipe ───────────────────────────────────────
// Rust sets SIGPIPE to "ignore", so a write to a pipe whose reader has gone
// (`ash inbox | head -1`, `ash inbox | grep -q x`) returns EPIPE, and std's
// `println!` answers with a panic: exit 101 and "failed printing to stdout:
// Broken pipe". These shadow std's `print!` / `println!` for this file and the
// child modules declared below it (textual macro scope). A broken pipe is the
// reader saying it has seen enough: the rest of the output is dropped and the
// command still runs to completion, so an operation is never abandoned half-way
// (a send after its PairInit, say). Any other write error panics as before.
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::ash_cli::print_stdout(format_args!($($arg)*))
    };
}
macro_rules! println {
    () => {
        $crate::ash_cli::print_stdout(format_args!("\n"))
    };
    ($($arg:tt)*) => {
        $crate::ash_cli::print_stdout(format_args!("{}\n", format_args!($($arg)*)))
    };
}

mod ext;
mod ipc_client;
mod pair_init_lab;
mod trace_delivery;

use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use clap::{Parser, Subcommand};
use raven_core::address::{decode_address, encode_address};
use raven_core::alias_record::{normalize_alias, AliasClaimStore, AliasRecord};
use raven_core::chat_history::BlockList;
use raven_core::contact_request::{
    ContactAcceptOutcome, ContactRequestInbox, ContactRequestInner, RavenContactRequestV1,
};
use raven_core::discovery_resolver::{
    DiscoveryContext, DiscoveryResolver, DiscoveryResult, DiscoveryScope, LocalContactRow,
    VerificationState,
};
use raven_core::fingerprint::device_fingerprint_v1;
use raven_core::forward_queue::ForwardQueue;
use raven_core::identity::Identity;
use raven_core::ipc::{ipc_endpoint, IpcEndpoint, IpcRequest, IpcResponse, IPC_VERSION};
use raven_core::messaging_path::{
    assert_no_silent_fastapi, resolve_terminal_messaging_path, MessagingPath,
};
use raven_core::nearby::{NearbyAdvertisement, NearbyRegistry};
use raven_core::node_policy::{load_policy, save_policy, try_load_policy, NodePolicy};
use raven_core::prekey_bundle::{PrekeyBundle, PrekeyBundleJson, PrekeyStore};
use raven_core::profile_record::ProfileStore;
use raven_core::queue::{DeliveryState, OutgoingQueue};
use raven_core::sanitize::{sanitize_terminal_line, sanitize_terminal_text};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use std::sync::OnceLock;

/// Set once stdout reported a broken pipe: later output is dropped quietly.
#[cfg(not(test))]
static STDOUT_CLOSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Backend of the shadowed `print!` / `println!` (see the top of this file).
/// Unit tests keep std's macros so libtest still captures their output; the
/// broken-pipe behaviour is exercised against the real binary (tests/).
#[cfg(test)]
pub(crate) fn print_stdout(args: std::fmt::Arguments<'_>) {
    std::print!("{args}");
}

/// Backend of the shadowed `print!` / `println!` (see the top of this file).
#[cfg(not(test))]
pub(crate) fn print_stdout(args: std::fmt::Arguments<'_>) {
    use std::sync::atomic::Ordering;
    if STDOUT_CLOSED.load(Ordering::Relaxed) {
        return;
    }
    if let Err(e) = io::stdout().lock().write_fmt(args) {
        if e.kind() == io::ErrorKind::BrokenPipe {
            STDOUT_CLOSED.store(true, Ordering::Relaxed);
            return;
        }
        panic!("failed printing to stdout: {e}");
    }
}

/// Monochrome terminal style (bold / dim only — no cyan/purple/green).
/// Empty strings when NO_COLOR is set, TERM=dumb, or stdout is not a terminal.
#[derive(Clone, Copy)]
struct Style {
    bold: &'static str,
    dim: &'static str,
    reset: &'static str,
}

/// Pure colour decision (NO_COLOR spec: set and non-empty disables colour).
fn color_enabled_for(no_color_set: bool, term_dumb: bool, stdout_is_tty: bool) -> bool {
    !no_color_set && !term_dumb && stdout_is_tty
}

fn color_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        color_enabled_for(
            std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty()),
            std::env::var_os("TERM").is_some_and(|t| t == "dumb"),
            io::stdout().is_terminal(),
        )
    })
}

/// One SGR escape that renders only when [`color_enabled`] (checked at format
/// time), so `{C_DIM}` in a format string honours NO_COLOR / pipes everywhere.
#[derive(Clone, Copy)]
struct Sgr(&'static str);

impl std::fmt::Display for Sgr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if color_enabled() {
            f.write_str(self.0)
        } else {
            Ok(())
        }
    }
}

fn style() -> Style {
    if color_enabled() {
        Style {
            bold: "\x1b[1m",
            dim: "\x1b[2m",
            reset: "\x1b[0m",
        }
    } else {
        Style {
            bold: "",
            dim: "",
            reset: "",
        }
    }
}

// Palette shared by cli / ext / pair_init_lab. Honors NO_COLOR / TERM=dumb /
// non-TTY stdout through `Sgr`'s Display impl.
const C_BOLD: Sgr = Sgr("\x1b[1m");
const C_DIM: Sgr = Sgr("\x1b[2m");
const C_RESET: Sgr = Sgr("\x1b[0m");
const C_CYAN: Sgr = Sgr("\x1b[1;36m");
const C_PURPLE: Sgr = Sgr("\x1b[1;35m");
const C_GREEN: Sgr = Sgr("\x1b[1;32m");

fn c() -> Colors {
    if color_enabled() {
        // Black & white design: emphasis via bold/dim only.
        Colors {
            bold: "\x1b[1m",
            dim: "\x1b[2m",
            reset: "\x1b[0m",
            cyan: "\x1b[1m",
            purple: "\x1b[1m",
            green: "\x1b[1m",
            yellow: "\x1b[2m",
            red: "\x1b[1m",
        }
    } else {
        Colors {
            bold: "",
            dim: "",
            reset: "",
            cyan: "",
            purple: "",
            green: "",
            yellow: "",
            red: "",
        }
    }
}

struct Colors {
    bold: &'static str,
    dim: &'static str,
    reset: &'static str,
    cyan: &'static str,
    purple: &'static str,
    green: &'static str,
    yellow: &'static str,
    red: &'static str,
}

/// The default profile, or why there is none (no override and no usable HOME).
fn default_ash_data_dir() -> Result<PathBuf, String> {
    raven_core::paths::try_default_raven_data_dir()
}

fn is_ephemeral_data_dir(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/T/tmp.")
        || s.contains("/tmp/raven-ash-")
        || (s.contains("/var/folders/") && s.contains("/T/tmp"))
}

/// An explicit `--data-dir` is always honoured (never silently remapped onto
/// the real ~/.raven profile). A mktemp-looking path only earns a warning —
/// its identity changes every run, so a phone must re-pin each time.
fn resolve_data_dir(raw: &str) -> Result<PathBuf, String> {
    resolve_data_dir_with(raw, default_ash_data_dir)
}

/// [`resolve_data_dir`] with the default profile injected, so the "no profile
/// can be determined" path is testable without touching the process environment.
fn resolve_data_dir_with(
    raw: &str,
    default: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    let t = raw.trim();
    if t.is_empty() {
        return default();
    }
    let p = PathBuf::from(t);
    let quiet = std::env::var_os("RAVEN_ALLOW_EPHEMERAL_DATA_DIR").is_some_and(|v| v == "1");
    if is_ephemeral_data_dir(&p) && !quiet {
        eprintln!(
            "{C_PURPLE}note{C_RESET}: --data-dir looks ephemeral (mktemp) — this is a throwaway identity; peers must re-pin it every run."
        );
        eprintln!(
            "{C_DIM}FA:{C_RESET} پوشهٔ mktemp هویت موقت است؛ برای هویت ثابت مک از ~/.raven (بدون --data-dir) استفاده کنید."
        );
    }
    Ok(p)
}

/// Create the profile directory owner-only (0700) when it does not exist yet.
/// Existing directories are left alone: `--data-dir` may point anywhere.
fn create_private_data_dir(dir: &Path) -> std::io::Result<()> {
    // The "no profile could be determined" placeholder must never be created
    // (a root process on a minimal system could otherwise build its tree).
    raven_core::paths::require_resolved_data_dir(dir)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Public logo assets (no secrets) — credit raven-messager.com.
#[allow(dead_code)]
pub const LOGO_URL: &str = "https://raven-messager.com/raven_logo.png";
#[allow(dead_code)]
pub const LOGO_64_URL: &str = "https://raven-messager.com/raven_logo_64.png";

#[derive(Parser, Debug)]
#[command(
    name = "ash",
    version,
    about = "RAVEN Node — Messaging Beyond Connectivity",
    long_about = "RAVEN — serverless mesh messaging, from your terminal.\n\
                  \n\
                  Run `ash` with no arguments for the interactive menu (recommended;\n\
                  menu 8 is a guided tutorial). There is no central server: your\n\
                  identity is a key kept on this computer, and you talk directly to\n\
                  the people who added you.\n\
                  \n\
                  FIRST CHAT  (both people do steps 1-3)\n\
                  \x20 1. ash init                  create your identity (once)\n\
                  \x20 2. ash whoami                send your friend the `invite` line it prints\n\
                  \x20 3. ash                       menu 5 Contacts, then a: paste your friend's\n\
                  \x20                              invite line (they paste yours the same way)\n\
                  \x20 4. ash listen                the receiving side keeps this window open\n\
                  \x20 5. echo \"hello\" | ash send --contact Bob   (Bob = the name you gave them)\n\
                  \n\
                  Messages only arrive between people who added each other, and the\n\
                  computer that receives must be listening (step 4; a first `ash send`\n\
                  on it also leaves a background receiver running).\n\
                  The text of a message always comes from stdin, never from the command\n\
                  line. Live chat: ash send --contact Bob --chat\n\
                  \n\
                  Problems?  ash doctor    (says what is wrong and what to do next)\n\
                  \n\
                  Never prints private keys. https://raven-messager.com/"
)]
struct Cli {
    /// Folder where Raven keeps your identity and contacts (default: ~/.raven).
    /// Use the same folder every time.
    ///
    /// Do not use a throwaway folder (mktemp): the identity inside it is new
    /// every time, so friends would have to add you again.
    #[arg(long, global = true, default_value = "", hide_default_value = true)]
    data_dir: String,
    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create local identity (prints address + pub hex + fingerprint only).
    Init,
    /// Show public identity bits for data dir (never a seed).
    Whoami {
        /// Machine-readable public card only (`address` / `fingerprint` / `pub_hex`).
        /// NON-RELEASE O6 M1 bind helper. No private key fields.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Send one message to a contact (the text comes from stdin).
    ///
    /// Pipe the message in, or type it and finish with Ctrl-D:
    ///
    ///   echo "hello" | ash send --contact @alice
    ///
    /// The text is never taken from the command line. With no options on a
    /// terminal you get the guided contact picker; add --chat for a live chat.
    Send {
        /// Advanced: send straight to host:port instead of a saved contact
        /// (needs --peer-pub-hex).
        #[arg(long, default_value = "", hide_default_value = true)]
        peer: String,
        /// Advanced: the receiver's public key (64 hex characters, `ash whoami`).
        #[arg(long, default_value = "", hide_default_value = true)]
        peer_pub_hex: String,
        #[arg(long, default_value = "127.0.0.1:0", hide = true)]
        listen: String,
        /// Who to send to: a contact name or @tag, as shown by `ash contact list`.
        #[arg(long, default_value = "", hide_default_value = true)]
        contact: String,
        /// The message is read from stdin (this is always the case).
        #[arg(long, default_value_t = true, hide = true)]
        stdin_text: bool,
        /// Open a live chat with --contact instead of sending one message
        /// (inside: /help, /back).
        #[arg(long, default_value_t = false)]
        chat: bool,
        /// `lan` (default, Noise XX) or `internet` (RIH1 lab path).
        /// `internet` is localhost/indexed lab only — not WAN Proven.
        #[arg(long, default_value = "lan", hide = true)]
        carrier: String,
    },
    /// Show the messages you received.
    Inbox,
    /// Print welcome banner only (safe — no secrets).
    Banner,
    /// Stay online to receive messages from your contacts (keep this window open).
    Listen,
    /// Show your identity, contacts, and whether this computer can send and receive.
    Status,
    /// Check your setup and say what to do next (details follow the summary).
    Doctor {
        /// Exit 1 if `daemon_ready` is false. Does not claim send works.
        #[arg(long, default_value_t = false)]
        require_ready: bool,
    },
    /// Advanced: check that the local raven-node answers (it must be running).
    IpcPing,
    /// Advanced: change what this computer's raven-node does (bridge/store/relay/peers).
    Node {
        #[command(subcommand)]
        cmd: NodeCommands,
    },
    /// Manage your contacts: add, list, verify, remove (stored on this computer only).
    Contact {
        #[command(subcommand)]
        cmd: ContactCommands,
    },
    /// Advanced: look a person up among your contacts (there is no central directory).
    Find {
        /// Query: `rvn1…`, `@alias`, or local petname/tag text.
        query: String,
        /// Local-only (no public fuzzy in V1).
        #[arg(long, default_value_t = false)]
        local: bool,
        /// Exact Raven ID lane only.
        #[arg(long, default_value_t = false)]
        exact_id: bool,
        /// Exact alias lane only.
        #[arg(long, default_value_t = false)]
        exact_alias: bool,
        /// Non-interactive: print all conflict candidates (never silent pick).
        #[arg(long, default_value_t = false)]
        all: bool,
    },
    /// Demo only: a software mock of Bluetooth discovery (this computer only).
    Nearby,
    /// Advanced: sign a short @alias claim for your address (kept on this computer).
    Alias {
        #[command(subcommand)]
        cmd: AliasCommands,
    },
    /// Advanced: manage the signed key bundle a friend needs to start a chat with you.
    Prekey {
        #[command(subcommand)]
        cmd: PrekeyCommands,
    },
    /// Advanced: copy contacts to another device of yours, or revoke a device.
    Device {
        #[command(subcommand)]
        cmd: DeviceCommands,
    },
    /// Advanced: a mailbox store on this computer only (it is not your inbox).
    Mailbox {
        #[command(subcommand)]
        cmd: MailboxCommands,
    },
    /// Test A lab helpers (requires debug + RAVEN_LAB_TEST_A=1 for live PairInit).
    #[command(hide = true)]
    Lab {
        #[command(subcommand)]
        cmd: LabCommands,
    },
}

#[derive(Subcommand, Debug)]
enum LabCommands {
    /// Export local device certificate JSON for the peer's peer_device_certs.json.
    ExportCert,
    /// Import peer device certificate JSON into peer_device_certs.json.
    ImportPeerCert {
        #[arg(long)]
        peer_pub_hex: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Import peer prekey JSON into local prekey_store.json (OOB paste file).
    ImportPeerPrekey {
        #[arg(long)]
        peer_pub_hex: String,
        #[arg(long)]
        file: PathBuf,
    },
    /// Print lab unlock status.
    Status,
    /// Forward an already-sealed RavenEnvelopeV1 over LanDial (O6 M3 lab).
    ///
    /// Does **not** seal. Requires debug + `RAVEN_LAB_TEST_A=1`.
    /// NON-RELEASE: not O6 E2E Proven, not a HOLD lift, dial≠WAN.
    LanDialSealed {
        /// Peer LAN listen host:port (localhost lab).
        #[arg(long)]
        dial: String,
        /// Peer identity or device Ed25519 (64 hex) — same plane as ash send.
        #[arg(long)]
        expected_pub_hex: String,
        /// Daemon-sealed envelope from SealUnderSession / RDAP (standard or URL-safe b64).
        #[arg(long)]
        envelope_b64: String,
    },
}

#[derive(Subcommand, Debug)]
enum ContactCommands {
    /// Add a contact from QR/OOB public bits (never a private key).
    ///
    /// Soft Unique Tags: `@alias` is public and NOT globally unique — always
    /// confirm fingerprint. Petname is your private label on this device.
    ///
    /// Examples:
    ///
    ///   ash contact add --address rvn1q… --pub-hex <64 hex> --petname "Poline"
    ///
    ///   ash contact add --address rvn1q… --pub-hex <64 hex> --petname "Poline" --tag poline --verify-fp XXXX-XXXX-XXXX
    ///
    ///   ash contact add --address rvn1q… --pub-hex <64 hex> --petname "Ahmad (Berlin)" --tag ahmad
    #[command(after_help = "\
Soft Unique Tags (Raven Tag V1):
  • Layer A — Raven address (rvn1…) is the durable identity
  • Layer B — @alias / public tag is Soft Unique (conflicts show a picker)
  • Layer C — petname is local-only (e.g. \"Poline\") and primary in the UI
  • --verify-fp pins Tag+key locally after you confirm fingerprint OOB
  Never pass seeds or private keys. Public hex + address only.

Interactive (recommended for first-timers):
  ash                  # menu → 5 Contacts → guided add
")]
    Add {
        #[arg(long, help = "Raven address (rvn1… bech32m) from QR/OOB")]
        address: String,
        #[arg(long, help = "Ed25519 public key hex (64 chars) — never a seed")]
        pub_hex: String,
        /// Layer C — unique on this device only (primary label).
        #[arg(long, default_value = "", help = "Local petname, e.g. Poline")]
        petname: String,
        /// Layer B — public Alias V1 tag (NOT globally unique), e.g. ahmad.
        #[arg(long, default_value = "", help = "Optional public @tag (Soft Unique)")]
        tag: String,
        /// Legacy alias of --tag (deprecated).
        #[arg(long, default_value = "")]
        alias: String,
        /// Expected fingerprint. On match: pin Tag+key (DHT cannot overwrite).
        #[arg(long, help = "Confirm fingerprint to pin Tag+key locally")]
        verify_fp: Option<String>,
        /// Optional OOB prekey JSON: verified against --pub-hex and stored in
        /// the local prekey store (like `ash prekey fetch --file`).
        #[arg(long)]
        prekey_file: Option<PathBuf>,
        /// Optional LAN listen host:port (saved for Send / Chat — beginners pick #, not dial).
        #[arg(
            long,
            default_value = "",
            help = "Peer LAN listen host:port, e.g. 192.168.1.20:7420"
        )]
        lan_dial: String,
    },
    /// List contacts: petname first, @tag subtitle (never address-primary).
    List,
    /// Fingerprint / pin check by --tag, --petname, or --address.
    Verify {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        alias: Option<String>,
        #[arg(long)]
        petname: Option<String>,
        #[arg(long)]
        address: Option<String>,
    },
    /// Resolve @tag with ambiguity picker (never silent winner).
    Resolve {
        #[arg(long)]
        tag: String,
    },
    /// Send encrypted contact request (E2EE; delivered via MessageRouter / store).
    Request {
        /// Target `@alias` or `rvn1…` address.
        target: String,
        /// Optional short message (sealed inside ciphertext).
        #[arg(long, default_value = "")]
        message: String,
        /// When multiple alias claims: pick 1-based index (interactive if omitted).
        #[arg(long)]
        pick: Option<usize>,
    },
    /// List pending inbound contact requests (opened locally).
    Pending,
    /// Ingest a received RavenContactRequestV1 wire blob into the local inbox.
    Ingest {
        #[arg(long)]
        file: PathBuf,
    },
    /// Accept a pending request: emit ContactAcceptV1 + bind petname locally.
    Accept {
        /// request_id hex (32 chars).
        request_id: String,
        #[arg(long)]
        petname: String,
    },
    /// Decline a pending request (local only — no central moderation).
    Decline { request_id: String },
    /// Block sender of a pending request (local block list).
    Block { request_id: String },
    /// Undo a block: remove a sender's public key from the local block list.
    Unblock {
        /// Ed25519 public key hex (64 chars) of the blocked sender.
        #[arg(long)]
        pub_hex: String,
    },
    /// Remove a contact (and its pin) from this device's book — local only.
    ///
    /// The way to deliberately replace a pinned key (see KEY-CHANGE WARNING):
    /// verify the new fingerprint out-of-band, remove the old row, then
    /// `ash contact add … --verify-fp <new fingerprint>`.
    Remove {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        petname: Option<String>,
        #[arg(long)]
        address: Option<String>,
        /// Skip the typed confirmation (scripts).
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
    /// Change the saved LAN dial (host:port) of one contact; keeps petname, tag and pin.
    SetDial {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        petname: Option<String>,
        #[arg(long)]
        address: Option<String>,
        #[arg(long, help = "Peer LAN listen host:port, e.g. 192.168.1.31:7420")]
        lan_dial: String,
    },
}

#[derive(Subcommand, Debug)]
enum AliasCommands {
    /// Publish a signed Alias V1 claim into the local community store.
    Publish {
        #[arg(long)]
        alias: String,
        /// Claim sequence (default: stored sequence + 1, or 1 for a first claim).
        /// Peers reject a claim whose sequence is not higher than the one they hold.
        #[arg(long)]
        sequence: Option<u64>,
        /// Expiry unix ms (default: now + 30d).
        #[arg(long)]
        expires_at: Option<u64>,
    },
}

#[derive(Subcommand, Debug)]
enum PrekeyCommands {
    /// Publish a signed prekey bundle (real X25519 + ML-KEM) into local store.
    Publish {
        #[arg(long, default_value = raven_core::PRIMARY_DEVICE_ID)]
        device_id: String,
        /// Optional path to write OOB JSON export (public fields only).
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Fetch+verify a bundle for a contact pub hex from local store or --file.
    Fetch {
        #[arg(long)]
        pub_hex: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum NodeCommands {
    /// Bridge cross-transport forward (opaque RavenEnvelope).
    Bridge {
        #[command(subcommand)]
        state: OnOff,
    },
    /// Persistent store-carry-forward queue.
    Store {
        #[command(subcommand)]
        state: OnOff,
    },
    /// Same-transport relay (optional V1).
    Relay {
        #[command(subcommand)]
        state: OnOff,
    },
    /// Add a custom bootstrap multiaddr (or --manual peer).
    AddBootstrap {
        multiaddr: String,
        #[arg(long, default_value_t = false)]
        manual: bool,
    },
    /// Disable and clear Raven-shipped bootstrap defaults.
    DisableRavenDefaults,
    /// Show effective bootstrap peers.
    ShowBootstrap,
    /// Write empty/default bootstrap.json (--no-raven-defaults clears Raven list).
    InitBootstrap {
        #[arg(long, default_value_t = false)]
        no_raven_defaults: bool,
    },
}

#[derive(Subcommand, Debug)]
enum DeviceCommands {
    /// Export sealed contact/petname sync blob (hex) for another authorized device.
    SyncExport {
        /// Must be a device the importing registry authorizes (default: this
        /// profile's primary device certificate).
        #[arg(long, default_value = raven_core::PRIMARY_DEVICE_ID)]
        device_id: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Import sealed sync blob; merges petname/tag/pin with key-change rules.
    SyncImport {
        #[arg(long)]
        file: PathBuf,
    },
    /// Issue + persist a signed device revocation record.
    Revoke {
        #[arg(long)]
        device_id: String,
        #[arg(long, default_value_t = 1)]
        epoch: u64,
    },
}

/// The mailbox routing key (k_route) derives every rotating mailbox_tag /
/// store_tag, so it is read from `RAVEN_K_ROUTE_HEX` or stdin — never argv.
#[derive(Subcommand, Debug)]
enum MailboxCommands {
    /// Deposit opaque envelope under rotating mailbox → store_tag index.
    /// k_route: `RAVEN_K_ROUTE_HEX=<hex>` or `--k-route-stdin`.
    Put {
        /// REFUSED (argv is visible via ps / shell history).
        #[arg(long, hide = true)]
        k_route_hex: Option<String>,
        /// Read k_route hex from the first line of stdin.
        #[arg(long, default_value_t = false)]
        k_route_stdin: bool,
        #[arg(long, default_value_t = 1)]
        epoch: u64,
        #[arg(long, default_value_t = 0)]
        slot: u64,
        #[arg(long)]
        envelope_hex: String,
    },
    /// Retrieve by opaque rotating tags (current + previous epoch).
    /// k_route: `RAVEN_K_ROUTE_HEX=<hex>` or `--k-route-stdin`.
    Get {
        /// REFUSED (argv is visible via ps / shell history).
        #[arg(long, hide = true)]
        k_route_hex: Option<String>,
        /// Read k_route hex from the first line of stdin.
        #[arg(long, default_value_t = false)]
        k_route_stdin: bool,
        #[arg(long, default_value_t = 1)]
        epoch: u64,
        #[arg(long, default_value_t = 0)]
        slot: u64,
    },
}

/// Resolve k_route without ever taking it from argv.
fn resolve_k_route_hex(
    argv: Option<&str>,
    from_stdin: bool,
    env: Option<String>,
    read_stdin_line: impl FnOnce() -> String,
) -> Result<String, String> {
    if argv.is_some() {
        return Err(
            "REFUSE: --k-route-hex puts the mailbox routing key on argv (visible via ps / \
             shell history). Use RAVEN_K_ROUTE_HEX=<hex> or --k-route-stdin."
                .into(),
        );
    }
    let raw = if from_stdin {
        read_stdin_line()
    } else {
        env.ok_or_else(|| {
            "k_route required: set RAVEN_K_ROUTE_HEX or pass --k-route-stdin".to_string()
        })?
    };
    let raw = raw.trim().to_string();
    if raw.is_empty() {
        return Err("k_route required: set RAVEN_K_ROUTE_HEX or pass --k-route-stdin".into());
    }
    Ok(raw)
}

fn k_route_or_exit(argv: Option<&str>, from_stdin: bool) -> String {
    match resolve_k_route_hex(
        argv,
        from_stdin,
        std::env::var("RAVEN_K_ROUTE_HEX").ok(),
        read_line,
    ) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    }
}

#[derive(Subcommand, Debug, Clone, Copy)]
enum OnOff {
    On,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Contact {
    /// Layer C — device-local petname (primary UI label). Unique on MY device.
    #[serde(default)]
    petname: String,
    /// Layer B — public Raven Tag / Alias V1 self-claim (NOT globally unique).
    #[serde(default)]
    public_tag: String,
    /// Legacy field — migrated into public_tag on load when public_tag empty.
    #[serde(default)]
    alias: String,
    /// Layer A — Raven address (rvn1…).
    address: String,
    /// Ed25519 public key hex only.
    pub_hex: String,
    /// Soft-unique pin: first-meet / QR verify locked Tag+key locally.
    #[serde(default)]
    pinned: bool,
    /// Optional LAN listen `host:port` for this peer (saved after first send).
    /// Beginners pick a contact # — they should not re-type host:port every time.
    #[serde(default)]
    lan_dial: String,
}

impl Contact {
    fn migrate(mut self) -> Self {
        if self.public_tag.is_empty() && !self.alias.is_empty() {
            self.public_tag = self.alias.clone();
        }
        if self.petname.is_empty() {
            if !self.public_tag.is_empty() {
                self.petname = self.public_tag.clone();
            } else if !self.alias.is_empty() {
                self.petname = self.alias.clone();
            }
        }
        self
    }

    fn primary_label(&self) -> String {
        let p = sanitize_terminal_line(&self.petname);
        if !p.is_empty() {
            return p;
        }
        let t = normalize_tag(&self.public_tag);
        if !t.is_empty() {
            return format!("@{t}");
        }
        // Address only as last resort — never preferred.
        sanitize_terminal_line(&self.address)
    }

    fn tag_subtitle(&self) -> Option<String> {
        let t = normalize_tag(&self.public_tag);
        if t.is_empty() {
            None
        } else {
            Some(format!("@{t}"))
        }
    }
}

fn contacts_path(data_dir: &Path) -> PathBuf {
    data_dir.join("contacts.json")
}

fn load_contacts(data_dir: &Path) -> Result<Vec<Contact>, String> {
    let path = contacts_path(data_dir);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("contacts.json: {e}"))?;
    let list: Vec<Contact> = serde_json::from_str(&raw)
        .map_err(|e| format!("contacts.json corrupt — refusing empty book: {e}"))?;
    Ok(list.into_iter().map(Contact::migrate).collect())
}

fn contacts_or_die(data_dir: &Path) -> Vec<Contact> {
    match load_contacts(data_dir) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn save_contacts(data_dir: &Path, contacts: &[Contact]) -> Result<(), String> {
    create_private_data_dir(data_dir).map_err(|e| e.to_string())?;
    let path = contacts_path(data_dir);
    let raw = serde_json::to_string_pretty(contacts).map_err(|e| e.to_string())?;
    raven_core::atomic_write_private(&path, raw.as_bytes())
}

fn ensure_identity(data_dir: &Path) -> Identity {
    match raven_core::load_or_create_identity(data_dir) {
        Ok((id, _)) => id,
        Err(e) => {
            let raw = e.redacted_display();
            eprintln!("secure identity store: {raw}");
            if raw.contains("continuity violation") {
                let c = c();
                eprintln!();
                eprintln!(
                    "{0}This profile has leftover state but no identity record.{1}",
                    c.yellow, c.reset
                );
                eprintln!(
                    "{0}Raven refuses to bind a NEW key over old state silently\n\
                     (that would look like identity theft to your contacts).{1}",
                    c.dim, c.reset
                );
                eprintln!();
                eprintln!(
                    "{0}Recovery — pick one:{1}\n  \
                     1) Fresh start: move the old profile aside, then re-run init.\n       \
                     e.g.  mv ~/.raven ~/.raven.backup-20260101\n  \
                     2) Restore:     if you have a backup of this profile's \
                     identity files, put them back and retry.",
                    c.bold, c.reset
                );
            }
            std::process::exit(1);
        }
    }
}

fn require_identity(data_dir: &Path) -> Identity {
    match raven_core::load_identity(data_dir) {
        Ok(Some(id)) => id,
        Ok(None) => {
            eprintln!("identity missing — run: ash --data-dir <dir> init");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("secure identity store: {}", e.redacted_display());
            std::process::exit(1);
        }
    }
}

fn try_load_identity(data_dir: &Path) -> Result<Option<Identity>, String> {
    raven_core::load_identity(data_dir).map_err(|e| e.redacted_display())
}

/// Gate for commands that create profile state (contacts, the session store, the
/// nearby registry): they must not run before the first identity exists. Whatever
/// they leave behind makes the first `ash init` fail the first-install continuity
/// check, whose recovery text then talks about identity theft. The check only
/// reads (`load_identity` takes just the allow-listed identity lock), so asking
/// creates nothing. `Ok(false)`: no identity yet; `Err`: the store is unreadable.
fn identity_exists_before_state(data_dir: &Path, what: &str) -> Result<bool, String> {
    match try_load_identity(data_dir) {
        Ok(found) => Ok(found.is_some()),
        Err(e) => Err(format!(
            "{what}: identity store unavailable: {}",
            sanitize_terminal_line(&e)
        )),
    }
}

/// [`identity_exists_before_state`] as one refusal text.
fn require_identity_before_state(data_dir: &Path, what: &str) -> Result<(), String> {
    match identity_exists_before_state(data_dir, what)? {
        true => Ok(()),
        false => Err(format!("{what} needs an identity first — run `ash init`")),
    }
}

fn print_public_identity(id: &Identity) {
    kv("address", &id.address());
    kv(
        "fingerprint",
        &device_fingerprint_v1(&id.public_key_bytes()),
    );
    kv("pub_hex", &hex::encode(id.public_key_bytes()));
    println!(
        "{0}invite{1}        {2}raven:{3}:{4}{5}",
        c().dim,
        c().reset,
        c().bold,
        id.address(),
        hex::encode(id.public_key_bytes()),
        c().reset
    );
}

/// Public whoami card for O6 M1 same-RVN1 bind (ADR 0004 D3).
/// Public material only — MUST NOT include seed / private_key / plaintext.
fn public_whoami_card(id: &Identity) -> serde_json::Value {
    serde_json::json!({
        "address": id.address(),
        "fingerprint": device_fingerprint_v1(&id.public_key_bytes()),
        "pub_hex": hex::encode(id.public_key_bytes()),
    })
}

/// Static part of the welcome banner: public branding only, never identity
/// or key material (unit-tested). Monochrome, NO_COLOR aware. Every framed
/// row is padded to the same width so the right border lines up.
fn welcome_banner_text() -> String {
    const INNER: usize = 50;
    const ROWS: [&str; 11] = [
        "",
        "  R A V E N",
        "  N O D E",
        "",
        "  Messaging Beyond Connectivity",
        "",
        "  \u{25c6} serverless \u{00b7} P2P \u{00b7} private",
        "",
        "  \"The Raven bears witness as the Phoenix",
        "   rises from the ASH\"",
        "",
    ];
    let c = c();
    let (d, r) = (c.dim, c.reset);
    let rule = "\u{2500}".repeat(INNER);
    let mut s = format!("\n  \u{256d}{rule}\u{256e}\n");
    for row in ROWS {
        s.push_str(&format!("  \u{2502}{row:<INNER$}\u{2502}\n"));
    }
    s.push_str(&format!("  \u{2570}{rule}\u{256f}\n\n"));
    s.push_str(&format!("{d}   https://raven-messager.com{r}\n"));
    s
}

/// What the identity store said when the banner asked, so the interactive shell
/// does not read it (identity lock + secure-store round trip) a second time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdentityState {
    Ready,
    Missing,
    /// Unreadable store (continuity violation, locked, I/O error): not the
    /// same as "no identity yet", and never an invitation to mint one.
    Unavailable,
}

/// Raven Node welcome banner — monochrome.
fn print_welcome(data_dir: &Path) {
    if print_welcome_state(data_dir) == IdentityState::Missing {
        println!("{C_DIM}Create one with: ash init{C_RESET}");
    }
}

fn print_welcome_state(data_dir: &Path) -> IdentityState {
    let c = c();
    let (b, d, r) = (c.bold, c.dim, c.reset);
    print!("{}", welcome_banner_text());
    println!(
        "{d}   profile: {path}{r}",
        d = d,
        path = data_dir.display(),
        r = r
    );
    println!();

    match try_load_identity(data_dir) {
        Ok(Some(id)) => {
            println!("{b}\u{25cf} identity ready{r}", b = b, r = r);
            kv("address", &id.address());
            kv(
                "fingerprint",
                &device_fingerprint_v1(&id.public_key_bytes()),
            );
            kv("pub_hex", &hex::encode(id.public_key_bytes()));
            println!();
            println!(
                "{d}Tip: menu 8 = Tutorial \u{00b7} menu 4 = Listen{r}",
                d = d,
                r = r
            );
            println!();
            IdentityState::Ready
        }
        Ok(None) => {
            println!("{b}First run \u{2014} no identity yet.{r}\n", b = b, r = r);
            IdentityState::Missing
        }
        Err(e) => {
            println!("identity unavailable: {}", sanitize_terminal_line(&e));
            IdentityState::Unavailable
        }
    }
}
/// First-run "create identity?" answer. EOF / a read error never creates one
/// (no human decided). On a terminal Enter takes the `[Y]` default; piped input
/// must say yes explicitly, since an empty line there is not a decision.
fn first_run_answer_accepts(answer: Option<&str>, interactive: bool) -> bool {
    match answer {
        None => false,
        Some("") => interactive,
        Some(a) => a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes"),
    }
}

/// An answer that is neither yes nor no ("ok", the letters a Persian keyboard
/// layout produces, ...). On a terminal that is worth asking again; EOF and an
/// empty line are not "unclear" (EOF is no answer, Enter takes the default).
fn first_run_answer_is_unclear(answer: Option<&str>) -> bool {
    match answer {
        None | Some("") => false,
        Some(a) => !["y", "yes", "n", "no"]
            .iter()
            .any(|w| a.eq_ignore_ascii_case(w)),
    }
}

/// How often a terminal user is asked again after an answer that is neither
/// yes nor no. Piped input is never asked again (it would eat the next line of
/// someone's script); it simply does not create an identity.
const FIRST_RUN_REASKS: usize = 2;

/// What an identity is, in two plain sentences (EN + FA), shown before the
/// question: the person has to decide something they have not been told about.
fn print_identity_explainer() {
    let c = c();
    println!(
        "{0}Your identity is a private key that stays on this computer. It gives you a public\n\
         address (rvn1\u{2026}) that friends use to add you: no account, no phone number, no server.{1}",
        c.dim, c.reset
    );
    println!(
        "{0}FA:{1} \u{200f}هویت شما یک کلید خصوصی است که فقط روی همین کامپیوتر می\u{200c}ماند؛ دوستانتان با آدرس عمومی شما (rvn1\u{2026}) شما را اضافه می\u{200c}کنند.",
        c.dim, c.reset
    );
    if cfg!(target_os = "macos") {
        println!(
            "{0}macOS may ask whether ash may use the Keychain for your key: choose \"Always Allow\" (plain \"Allow\" asks again every time).{1}\n",
            c.dim, c.reset
        );
    } else {
        println!();
    }
}

/// How the first-run identity offer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstRun {
    /// An identity already existed (nothing was asked).
    Present,
    Created,
    /// The user said no, or there was no one to ask (stdin closed).
    Declined,
    /// The identity store is unreadable, so nothing was offered: `ash init`
    /// fails the same way until that is fixed.
    Unavailable,
}

/// Offer inline identity creation on first run. Used by the interactive shell
/// so newcomers don't need to know the `init` subcommand at all.
fn offer_first_run_identity(data_dir: &Path) -> FirstRun {
    let state = match try_load_identity(data_dir) {
        Ok(Some(_)) => IdentityState::Ready,
        Ok(None) => IdentityState::Missing,
        Err(_) => IdentityState::Unavailable,
    };
    offer_first_run_identity_given(data_dir, state)
}

/// [`offer_first_run_identity`] for a caller that already asked the identity
/// store (the welcome banner), so it is not asked twice.
fn offer_first_run_identity_given(data_dir: &Path, state: IdentityState) -> FirstRun {
    match state {
        IdentityState::Ready => return FirstRun::Present,
        // An unreadable identity store is not "no identity": never offer to
        // create (and bind) a new key over it. `print_welcome` already said why.
        IdentityState::Unavailable => return FirstRun::Unavailable,
        IdentityState::Missing => {}
    }
    let c = c();
    let (green, reset, red, dim) = (c.green, c.reset, c.red, c.dim);
    print_identity_explainer();
    let mut asked_again = 0;
    let ans = loop {
        print!(
            "{}?{} Create your Raven identity now? [{}Y/n{}] ",
            c.yellow, reset, green, reset
        );
        let _ = io::stdout().flush();
        let ans = read_line_opt();
        if first_run_answer_is_unclear(ans.as_deref())
            && stdin_is_tty()
            && asked_again < FIRST_RUN_REASKS
        {
            asked_again += 1;
            println!("{dim}Please answer y (yes) or n (no), using English letters.{reset}");
            continue;
        }
        break ans;
    };
    if !first_run_answer_accepts(ans.as_deref(), stdin_is_tty()) {
        if ans.is_none() {
            println!("\n{dim}no answer (stdin closed) — identity not created.{reset}");
        } else if first_run_answer_is_unclear(ans.as_deref()) {
            println!("{dim}Not a yes or a no — identity not created.{reset}");
        }
        return FirstRun::Declined;
    }
    let id = ensure_identity(data_dir);
    if let Err(e) = raven_core::ensure_local_prekey(data_dir, &id) {
        eprintln!("{red}prekey: {}{reset}", sanitize_terminal_line(&e));
    }
    println!("{green}✔ identity created{reset}");
    print_public_identity(&id);
    println!(
        "\n{dim}Private key stays on this machine. Share only the public lines above (or just the invite line).{reset}"
    );
    println!(
        "{dim}Next: send your friend the invite line (`ash whoami` shows it again any time), then paste theirs under menu 5 Contacts.{reset}"
    );
    FirstRun::Created
}

fn section(label: &str) {
    let c = c();
    let (purple, bold, reset) = (c.purple, c.bold, c.reset);
    println!(
        "\n{purple}◆{reset} {bold}{}{reset}",
        label.to_ascii_uppercase()
    );
}

fn item(num: &str, title: &str, hint: &str) {
    let c = c();
    let (cyan, bold, dim, reset) = (c.cyan, c.bold, c.dim, c.reset);
    println!(
        "    {cyan}{}{reset}  {bold}{:<24}{reset} {dim}{}{reset}",
        num, title, hint
    );
}

fn print_menu() {
    let menu_item = |idx: usize| {
        let (num, title, hint) = MENU_ITEMS[idx];
        item(num, title, hint);
    };
    section("messages");
    menu_item(0);
    menu_item(1);
    section("network");
    menu_item(2);
    menu_item(3);
    section("people");
    menu_item(4);
    section("tools");
    menu_item(5);
    menu_item(6);
    menu_item(7);
    let c = c();
    println!();
    println!("    {c_dim}q  quit{reset}", c_dim = c.dim, reset = c.reset);
    print!("\n{}raven{} {}❯{} ", c.bold, c.reset, c.cyan, c.reset);
    let _ = io::stdout().flush();
}

/// One trimmed line from stdin. `None` = EOF or a read error, which is NOT the
/// same as an empty answer: trust decisions must never treat it as one.
fn read_line_opt() -> Option<String> {
    let mut s = String::new();
    match io::stdin().read_line(&mut s) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(s.trim().to_string()),
    }
}

fn read_line() -> String {
    read_line_opt().unwrap_or_default()
}

/// Throw away whatever is already queued on a terminal's stdin (lines of a
/// multi-line paste that earlier prompts did not consume). Terminals only:
/// piped input is the caller's explicit script and is left alone.
///
/// Best effort, NOT a barrier: a paste larger than the tty input queue (about
/// 1 KiB) or delivered line by line keeps arriving after this drain, and on
/// Windows there is no drain at all. What makes a trust decision unforgeable
/// by pasted input is the random code of [`new_confirm_code`].
fn discard_pending_tty_input() {
    let _ = drain_tty_input("0");
}

/// [`discard_pending_tty_input`] that says how many bytes it threw away.
/// `wait_tenths` is the VTIME wait ("0" = none, "1" = up to 100 ms for the tail
/// of a paste that is still arriving). Terminals only; 0 elsewhere.
fn drain_tty_input(wait_tenths: &str) -> usize {
    if !cfg!(unix) || !stdin_is_tty() {
        return 0;
    }
    // Non-canonical: read(2) returns 0 once the queue is empty (after the wait).
    // The user's own tty settings come back via `restore_tty`.
    let _ = saved_tty_state();
    stty(&["-icanon", "min", "0", "time", wait_tenths]);
    let mut buf = [0u8; 512];
    let mut drained = 0usize;
    for _ in 0..128 {
        match io::stdin().read(&mut buf) {
            Ok(n) if n > 0 => drained += n,
            _ => break,
        }
    }
    restore_tty();
    drained
}

/// A line typed or pasted at a terminal prompt is read in cooked mode, so cursor
/// keys arrive as escape bytes and other control bytes arrive as they are.
/// The core refuses such text ("violates the bounded application policy") after
/// the whole message was typed: say it here, before anything is sent.
/// (Same rule as the core: tab / CR / LF are fine, every other control byte and
/// DEL are not.)
fn tty_message_problem(text: &str) -> Option<&'static str> {
    if text.contains('\u{1b}') {
        return Some("cursor keys are not supported in this prompt, retype the message");
    }
    if text
        .chars()
        .any(|ch| (ch < ' ' && !matches!(ch, '\t' | '\n' | '\r')) || ch == '\u{7f}')
    {
        return Some("control characters are not supported in this prompt, retype the message");
    }
    None
}

/// A cooked terminal line holds about 1023 bytes: the rest of a longer paste is
/// dropped, silently. At or past this size the line is probably cut.
const TTY_LINE_WARN_BYTES: usize = 1000;

/// Read ONE message line at a terminal prompt (`"> "`), or `None` (nothing to
/// send: a reason was printed). Piped input is taken as is, as before. On a
/// terminal: cursor keys / control bytes are refused with a re-prompt, extra
/// pasted lines refuse the send (they would otherwise run as menu commands and
/// the message would go out cut), and a line near the terminal limit asks first.
fn read_tty_message(prompt: &str) -> Option<String> {
    let mut attempts = 0;
    loop {
        print!("{prompt}");
        let _ = io::stdout().flush();
        let text = read_line();
        if text.is_empty() {
            eprintln!("empty message");
            return None;
        }
        if !stdin_is_tty() {
            return Some(text);
        }
        let extra = drain_tty_input("1");
        if extra > 0 {
            eprintln!(
                "{C_BOLD}NOT SENT:{C_RESET} you pasted more than one line (about {extra} more bytes). This prompt sends ONE line. For several lines: ash send --contact NAME < message.txt"
            );
            return None;
        }
        if let Some(problem) = tty_message_problem(&text) {
            attempts += 1;
            eprintln!("{problem}");
            if attempts >= 3 {
                return None;
            }
            continue;
        }
        if text.len() >= TTY_LINE_WARN_BYTES {
            eprintln!(
                "{C_BOLD}Careful:{C_RESET} this line is {} bytes; a terminal prompt may have cut it at about 1000 characters.",
                text.len()
            );
            print!("Send it anyway? [y/N] ");
            let _ = io::stdout().flush();
            let yes = read_line_opt()
                .is_some_and(|a| a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes"));
            if !yes {
                println!("{C_DIM}cancelled — nothing sent.{C_RESET}");
                return None;
            }
        }
        return Some(text);
    }
}

/// Read one field, or drain a pasted multi-line `ash whoami` block from stdin.
fn read_paste_blob() -> String {
    let first = read_line();
    if first.is_empty() {
        return first;
    }
    let lower = first.to_ascii_lowercase();
    let looks_like_whoami_header = lower.trim_start().starts_with("address")
        || lower.trim_start().starts_with("pub_hex")
        || lower.trim_start().starts_with("fingerprint");
    if !looks_like_whoami_header {
        return first;
    }
    let mut lines = vec![first];
    for _ in 0..8 {
        let joined = lines.join("\n");
        if extract_address_field(&joined).is_some() && extract_pub_hex_field(&joined).is_some() {
            break;
        }
        let next = read_line();
        if next.is_empty() {
            break;
        }
        lines.push(next);
    }
    lines.join("\n")
}

/// True for a line of a pasted `ash whoami` block (address / fingerprint /
/// pub_hex / invite). `read_paste_blob` stops once address + pub_hex are
/// known, so the trailing `invite …` line must not be eaten by the next prompt.
fn is_whoami_paste_line(line: &str) -> bool {
    let t = line.trim();
    if t.is_empty() {
        return false;
    }
    if parse_raven_invite(t).is_some() {
        return true;
    }
    let lower = t.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("fingerprint") {
        let r = rest.trim_start_matches(['=', ':', ' ', '\t']);
        return r.len() >= 12 && r.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    }
    (lower.starts_with("address") && extract_address_field(t).is_some())
        || (lower.starts_with("pub_hex") && extract_pub_hex_field(t).is_some())
}

/// What a prompt that may follow a pasted `ash whoami` block is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnswerKind {
    /// Tag / petname / dial / verify choice: every whoami line is a leftover.
    Free,
    /// The explicit pub_hex prompt: a `pub_hex <hex>` line (or bare 64 hex,
    /// or an `invite` line, reduced to its pub) IS the answer; other whoami
    /// lines (address / fingerprint) are skipped.
    PubHex,
}

/// First line from `lines` that answers a prompt of `kind`, skipping at most
/// 8 leftover whoami lines (then an empty answer). `None` = `lines` ended
/// (EOF) before any answer arrived. Pure so the prompt logic is unit-testable.
fn pick_answer_line_checked<I: IntoIterator<Item = String>>(
    lines: I,
    kind: AnswerKind,
) -> Option<String> {
    let mut lines = lines.into_iter();
    for _ in 0..8 {
        let line = lines.next()?;
        if kind == AnswerKind::PubHex {
            match parse_raven_invite(&line) {
                Some(Ok(invite)) => return Some(invite.pub_hex),
                // Invalid invite typed at the pub_hex prompt: hand it back so
                // the add fails loudly instead of the prompt silently hanging.
                Some(Err(_)) => return Some(line),
                None => {}
            }
            if !looks_like_shell_input(&line) {
                if let Some(hex) = extract_pub_hex_field(&line) {
                    return Some(hex);
                }
            }
        }
        if !is_whoami_paste_line(&line) {
            return Some(line);
        }
    }
    Some(String::new())
}

/// [`pick_answer_line_checked`] with EOF folded into an empty answer, for
/// prompts whose empty answer is harmless (optional tag / petname / dial).
fn pick_answer_line<I: IntoIterator<Item = String>>(lines: I, kind: AnswerKind) -> String {
    pick_answer_line_checked(lines, kind).unwrap_or_default()
}

/// Answer to a prompt that follows a paste: skips leftover whoami lines.
fn read_answer_line() -> String {
    pick_answer_line(std::iter::from_fn(read_line_opt), AnswerKind::Free)
}

/// Answer to a trust decision: queued terminal input is dropped first and EOF
/// is `None` (never an answer), so nothing is decided on the user's behalf.
fn read_decision_line() -> Option<String> {
    discard_pending_tty_input();
    pick_answer_line_checked(std::iter::from_fn(read_line_opt), AnswerKind::Free)
}

/// Answer to the explicit pub_hex prompt: accepts the labelled whoami
/// `pub_hex  <hex>` line (reduced to the hex), skips address/fingerprint lines.
fn read_pub_hex_answer() -> String {
    pick_answer_line(std::iter::from_fn(read_line_opt), AnswerKind::PubHex)
}

/// Parsed one-text invite (`raven:<rvn1 address>:<64 hex pub>`), as printed by
/// `ash whoami` on its `invite` line.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedInvite {
    address: String,
    pub_hex: String,
    fingerprint: String,
}

/// `None` when `text` is not an invite at all; `Some(Err)` when it is one but
/// the address/key binding or hex is invalid. Accepts the whoami `invite` label.
fn parse_raven_invite(text: &str) -> Option<Result<ParsedInvite, String>> {
    let t = text.trim();
    let t = if t.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("invite")) {
        t[6..].trim_start_matches(['=', ':', ' ', '\t'])
    } else {
        t
    };
    let body = t.strip_prefix("raven:")?;
    Some((|| {
        let (addr_raw, pub_raw) = body
            .rsplit_once(':')
            .ok_or_else(|| "invite must be raven:<rvn1 address>:<64 hex pub>".to_string())?;
        let ed = parse_pub_hex_strict(pub_raw)?;
        let address = raven_core::address::from_display(addr_raw);
        if decode_address(&address).is_none() {
            return Err("invite address must be valid rvn1 bech32m".into());
        }
        if encode_address(&ed) != address {
            return Err(
                "invite address/pub mismatch — refusing (possible key substitution)".into(),
            );
        }
        Ok(ParsedInvite {
            address,
            pub_hex: hex::encode(ed),
            fingerprint: device_fingerprint_v1(&ed),
        })
    })())
}

/// What the fingerprint prompt decided. Only an explicit answer saves anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VerifyChoice {
    /// A / abort / q / Enter / anything unrecognised: nothing is saved.
    Abort,
    /// C / continue: save without a pin.
    Unpinned,
    /// V / verify / pin: pinning still needs the fingerprint typed back.
    ConfirmFingerprint,
    /// The fingerprint itself was entered: pin.
    Pin,
}

/// Typed fingerprint vs the displayed one (case and separators ignored).
fn fingerprint_matches(typed: &str, fp: &str) -> bool {
    let norm = |s: &str| {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_ascii_lowercase()
    };
    let typed = norm(typed);
    !typed.is_empty() && typed == norm(fp)
}

/// First answer at the `[V]erify & pin / [C]ontinue unpinned / [A]bort`
/// prompt. An empty answer aborts: a stray Enter (or a pasted blank line)
/// never adds a trusted contact, and `v` alone never pins.
fn parse_verify_choice(choice: &str, fp: &str) -> VerifyChoice {
    let c = choice.trim();
    match c.to_ascii_lowercase().as_str() {
        "v" | "verify" | "pin" => VerifyChoice::ConfirmFingerprint,
        "c" | "continue" => VerifyChoice::Unpinned,
        _ if fingerprint_matches(c, fp) => VerifyChoice::Pin,
        _ => VerifyChoice::Abort,
    }
}

/// Characters of a [`new_confirm_code`]: digits and capitals without the
/// look-alikes 0/O and 1/I/L, so the code can be read off the screen and typed.
const CONFIRM_CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";
const CONFIRM_CODE_LEN: usize = 5;

/// A fresh random code for one save confirmation (~25 bits). It is drawn when
/// the prompt appears and deliberately not derived from the contact: whoever
/// composed a pasted contact card knows its keys and fingerprint, but cannot
/// know a code that did not exist when the card was written.
fn new_confirm_code<R: rand::Rng>(rng: &mut R) -> String {
    (0..CONFIRM_CODE_LEN)
        .map(|_| CONFIRM_CODE_ALPHABET[rng.gen_range(0..CONFIRM_CODE_ALPHABET.len())] as char)
        .collect()
}

/// Typed code vs the displayed one (case, spaces and dashes ignored).
fn confirm_code_matches(typed: &str, code: &str) -> bool {
    fingerprint_matches(typed, code)
}

/// The fingerprint decision as a pure state machine over `next` (one answer per
/// call, `None` = EOF). `code` is `Some` at a terminal: whatever the choice, a
/// save then also needs that code typed back. Pasted input can carry `c`, `v`
/// and the (attacker's own) fingerprint, so those prove nothing; the code is
/// what keeps a paste that outlives the one-shot tty flush from saving a key.
/// `None` = piped stdin, the caller's explicit script (menu smoke, tests):
/// nobody is there to read a code.
fn verify_prompt_flow(
    fp: &str,
    code: Option<&str>,
    next: &mut dyn FnMut() -> Option<String>,
) -> Option<bool> {
    print!("[V]erify & pin  /  [C]ontinue unpinned  /  [A]bort (Enter aborts): ");
    let _ = io::stdout().flush();
    let pin = match parse_verify_choice(&next()?, fp) {
        VerifyChoice::Abort => return None,
        VerifyChoice::Unpinned => false,
        VerifyChoice::Pin => true,
        VerifyChoice::ConfirmFingerprint => {
            print!("Type the fingerprint shown above to pin it: ");
            let _ = io::stdout().flush();
            if !fingerprint_matches(&next()?, fp) {
                println!("fingerprint did not match");
                return None;
            }
            true
        }
    };
    if let Some(code) = code {
        print!("Type {code} to confirm saving this contact (anything else cancels): ");
        let _ = io::stdout().flush();
        if !confirm_code_matches(&next()?, code) {
            println!("confirmation code did not match");
            return None;
        }
    }
    Some(pin)
}

/// Interactive fingerprint decision for a new contact: `Some(pin)` = save
/// (pinned or not), `None` = abort, nothing saved. EOF, Enter and unknown
/// answers abort; pinning needs the fingerprint typed back; at a terminal every
/// save also needs the random confirmation code (see [`verify_prompt_flow`]).
fn prompt_verify_choice(fp: &str) -> Option<bool> {
    let code = stdin_is_tty().then(|| new_confirm_code(&mut rand::thread_rng()));
    verify_prompt_flow(fp, code.as_deref(), &mut read_decision_line)
}

/// Save an invite through [`add_contact`] (load + merge + binding / key-change /
/// tag checks). `pin` is only true after the fingerprint was confirmed.
fn commit_invite_contact(
    data_dir: &Path,
    invite: &ParsedInvite,
    petname: &str,
    pin: bool,
) -> Result<(), String> {
    add_contact(
        data_dir,
        &invite.address,
        &invite.pub_hex,
        petname,
        "",
        pin.then_some(invite.fingerprint.as_str()),
        "",
    )
}

/// Delivery marker for an outbound history row: ` [queued]` / ` [failed]` (or any
/// other state the row carries) for a message that is not known to be delivered;
/// nothing for inbound rows and delivered ones. Without it a queued or failed
/// message looked exactly like a delivered one in the chat dump and `ash messages`,
/// and the only notice of a failure was a one-off line at the next send. Shared by
/// both views so they cannot diverge.
pub(crate) fn delivery_suffix(e: &raven_core::ChatHistoryEntry) -> String {
    if e.direction != "out" {
        return String::new();
    }
    match e.delivery.as_str() {
        "" | "delivered" => String::new(),
        other => format!(" {C_DIM}[{}]{C_RESET}", sanitize_terminal_line(other)),
    }
}

/// How long ago, in words: "just now", "5 min ago", "2 h ago", "3 d ago". An age
/// needs no time zone (std has none), so it reads the same on every machine.
/// `then_ms == 0` (unknown) gives "".
fn short_age(now_ms: u64, then_ms: u64) -> String {
    if then_ms == 0 {
        return String::new();
    }
    let secs = now_ms.saturating_sub(then_ms) / 1000;
    match secs {
        0..=59 => "just now".into(),
        60..=3_599 => format!("{} min ago", secs / 60),
        3_600..=86_399 => format!("{} h ago", secs / 3_600),
        _ => format!("{} d ago", secs / 86_400),
    }
}

/// On a terminal one huge message must not push everything else off the screen
/// (piped output is never clipped).
const TTY_BODY_MAX_CHARS: usize = 2000;
/// Rows of the inbox shown on a terminal (the newest ones).
const TTY_INBOX_ROWS: usize = 20;

fn clip_body(text: String, max_chars: Option<usize>) -> String {
    match max_chars {
        Some(max) if text.chars().count() > max => {
            let more = text.chars().count() - max;
            let kept: String = text.chars().take(max).collect();
            format!("{kept}\u{2026} (+{more} more characters)")
        }
        _ => text,
    }
}

/// One stored message (`ash messages`) on ONE line: age, who to whom, the text,
/// a ` [queued]` / ` [failed]` marker when it is not known to be delivered, and
/// the short message id (the sender's `mid=`) last.
fn format_history_row(
    e: &raven_core::ChatHistoryEntry,
    now_ms: u64,
    max_chars: Option<usize>,
) -> String {
    let label = if !e.peer_petname.is_empty() {
        sanitize_terminal_line(&e.peer_petname)
    } else if !e.peer_tag.is_empty() {
        format!("@{}", sanitize_terminal_line(&e.peer_tag))
    } else {
        sanitize_terminal_line(&e.peer_pub_hex.chars().take(12).collect::<String>())
    };
    let (from, to) = if e.direction == "out" {
        ("you".to_string(), label)
    } else {
        (label, "you".to_string())
    };
    let age = short_age(now_ms, e.created_at_ms);
    let when = if age.is_empty() {
        String::new()
    } else {
        format!("{C_DIM}{age}{C_RESET}  ")
    };
    let text = if e.body.is_empty() {
        &e.preview
    } else {
        &e.body
    };
    let mid: String = e.message_id_hex.chars().take(8).collect();
    format!(
        "  {when}{from} \u{2192} {to}: {}{}  {C_DIM}[{}]{C_RESET}",
        clip_body(sanitize_terminal_line(text), max_chars),
        delivery_suffix(e),
        sanitize_terminal_line(&mid)
    )
}

fn cmd_messages(data_dir: &Path) {
    let qpath = data_dir.join("queue.db");
    let qpath2 = data_dir.join("queue.sqlite");
    let path = if qpath.exists() { qpath } else { qpath2 };
    // The old outgoing queue is only worth a line when something is waiting in it.
    if path.exists() {
        match OutgoingQueue::open(&path) {
            Ok(q) => match q.list_all() {
                Ok(items) => {
                    if !items.is_empty() {
                        println!("{C_DIM}{:<12} {:<12} peer{C_RESET}", "msg_id", "state");
                        for it in items {
                            let id = hex::encode(it.message_id);
                            let st = match it.state {
                                DeliveryState::Queued => "queued",
                                DeliveryState::Sent => "sent",
                                DeliveryState::Delivered => "delivered",
                                DeliveryState::Failed => "failed",
                            };
                            println!("{}… {:<12} {}", &id[..8.min(id.len())], st, it.peer_addr);
                        }
                    }
                }
                Err(e) => eprintln!("queue list error: {e}"),
            },
            Err(e) => eprintln!("queue open error: {e}"),
        }
    }
    match raven_core::ChatHistory::load(data_dir) {
        Ok(hist) if hist.entries.is_empty() => {
            println!("{C_DIM}No messages stored on this computer yet.{C_RESET}");
        }
        Ok(hist) => {
            println!("{C_BOLD}Recent messages{C_RESET} (stored encrypted on this computer)");
            let now = now_ms();
            let max_chars = io::stdout().is_terminal().then_some(TTY_BODY_MAX_CHARS);
            let mut marked = false;
            for e in hist.entries.iter().rev().take(15).rev() {
                marked |= !delivery_suffix(e).is_empty();
                println!("{}", format_history_row(e, now, max_chars));
            }
            if marked {
                println!(
                    "{C_DIM}[queued] = not delivered yet; [failed] = could not be delivered.{C_RESET}"
                );
            }
        }
        Err(error) => {
            eprintln!("local protected history unavailable: {error}");
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Detect pasted zsh/bash setup lines (export PATH, cargo build, mktemp, $DATA…).
fn looks_like_shell_input(s: &str) -> bool {
    for line in s.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("export ")
            || lower.starts_with("cargo ")
            || lower.contains("mktemp")
            || lower.contains("$data")
        {
            return true;
        }
    }
    false
}

fn shell_paste_rejection() -> &'static str {
    "That looks like a Terminal shell command. Exit ash (q), run those in zsh. Here paste only rvn1… or 64-char pub_hex from the other person's: ash whoami"
}

/// Lenient user-input parser: rejects pasted shell text and accepts a
/// whoami `pub_hex  <hex>` line. Wire / IPC callers use [`parse_pub_hex_strict`].
fn parse_pub_hex(s: &str) -> Result<[u8; 32], String> {
    if looks_like_shell_input(s) {
        return Err(shell_paste_rejection().into());
    }
    let h = extract_pub_hex_field(s).unwrap_or_else(|| s.trim().to_lowercase());
    parse_pub_hex_strict(&h)
}

/// Exactly 64 hex chars (surrounding whitespace / case ignored) → 32 bytes.
/// The single strict parser shared by cli, ext and pair_init_lab.
fn parse_pub_hex_strict(s: &str) -> Result<[u8; 32], String> {
    let h = s.trim().to_lowercase();
    if h.len() != 64 {
        return Err("pub_hex must be 64 hex chars (32 bytes)".into());
    }
    let v = hex::decode(&h).map_err(|_| "pub_hex invalid hex".to_string())?;
    if v.len() != 32 {
        return Err("pub_hex must decode to 32 bytes".into());
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    Ok(a)
}

/// Pull `pub_hex` / `address` from a pasted `ash whoami` block (or bare values).
fn extract_pub_hex_field(blob: &str) -> Option<String> {
    for line in blob.lines() {
        let t = line.trim();
        let lower = t.to_ascii_lowercase();
        if let Some(rest) = lower
            .strip_prefix("pub_hex")
            .or_else(|| lower.strip_prefix("pubhex"))
        {
            let rest = rest.trim_start_matches(['=', ':', ' ', '\t']);
            let hex: String = rest
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>()
                .to_lowercase();
            if hex.len() == 64 {
                return Some(hex);
            }
        }
        // Bare 64-hex line inside a multi-line paste.
        let only_hex: String = t
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .collect::<String>()
            .to_lowercase();
        if only_hex.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(only_hex);
        }
    }
    let t = blob.trim();
    if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(t.to_lowercase());
    }
    None
}

fn extract_address_field(blob: &str) -> Option<String> {
    for line in blob.lines() {
        let t = line.trim();
        let lower = t.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("address") {
            let rest = rest.trim_start_matches(['=', ':', ' ', '\t']);
            // Recover original casing from the line after the key.
            if let Some(idx) = t.to_ascii_lowercase().find("address") {
                let after = t[idx + "address".len()..].trim_start_matches(['=', ':', ' ', '\t']);
                if after.starts_with("rvn1") {
                    return Some(after.split_whitespace().next()?.to_string());
                }
            }
            let _ = rest;
        }
        if t.starts_with("rvn1") {
            return Some(t.split_whitespace().next()?.to_string());
        }
    }
    None
}

/// iPhone "Copy pub hex" (and accidental `@` + 64 hex) — not an Soft Unique @alias.
fn looks_like_bare_pub_hex(s: &str) -> Option<String> {
    let t = s.trim().trim_start_matches('@').trim();
    if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(t.to_ascii_lowercase())
    } else {
        None
    }
}

/// Default Raven LAN listen port (Mac listens / iPhone Serverless LAN).
const DEFAULT_LAN_PORT: u16 = 7420;

/// Env overrides for peer LAN dial (checked in order). Matches RAVEN_* convention.
const ENV_PEER_LAN_DIAL: &[&str] = &["RAVEN_PEER", "ASH_LAN_DIAL"];

fn looks_like_lan_dial(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.contains(' ') {
        return false;
    }
    // host:port — avoid treating rvn1… as dial
    if t.starts_with("rvn1") {
        return false;
    }
    if let Some((host, port)) = t.rsplit_once(':') {
        // Hostname / IPv4 / bracketed IPv6 characters only — never control or
        // escape bytes (the dial is stored, printed and handed to the daemon).
        if host.is_empty()
            || !host.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '[' | ']' | ':' | '%')
            })
        {
            return false;
        }
        return port.parse::<u16>().ok().is_some_and(|p| p != 0);
    }
    false
}

fn update_contact_lan_dial(data_dir: &Path, pub_hex: &str, dial: &str) -> Result<(), String> {
    let dial = dial.trim();
    if !looks_like_lan_dial(dial) {
        return Err("lan_dial must look like host:port (e.g. 192.168.1.20:7420)".into());
    }
    let want = pub_hex.trim().to_lowercase();
    let mut contacts = load_contacts(data_dir)?;
    let mut found = false;
    for c in contacts.iter_mut() {
        if c.pub_hex.eq_ignore_ascii_case(&want) {
            c.lan_dial = dial.to_string();
            found = true;
            break;
        }
    }
    if !found {
        return Err("contact not found for lan_dial update".into());
    }
    save_contacts(data_dir, &contacts)
}

/// How Send / Chat reaches a contact on LAN without an interactive host:port prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResolvedLanPeer {
    /// Dial this `host:port` (saved, env, or discovered).
    Dial(String),
}

fn env_peer_lan_dial() -> Option<String> {
    for key in ENV_PEER_LAN_DIAL {
        if let Ok(v) = std::env::var(key) {
            let t = v.trim();
            if looks_like_lan_dial(t) {
                return Some(t.to_string());
            }
        }
    }
    None
}

/// Is a raven-node IPC server for this profile answering? A bounded probe: a
/// wedged daemon must not stall `ash listen` for the full IPC I/O timeout.
fn ipc_daemon_up(data_dir: &Path) -> bool {
    ipc_client::ipc_daemon_up_within(data_dir, LISTEN_PREFLIGHT_PROBE)
}

/// An address worth telling a friend: IPv4, and not loopback / link-local /
/// unspecified (a Thunderbolt-bridge 169.254.x.x is no use to anyone else).
#[cfg(any(target_os = "macos", test))]
fn usable_lan_ipv4(s: &str) -> bool {
    s.parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified())
}

/// Best-effort primary LAN IPv4 for tips (macOS `ipconfig getifaddr enN`, else none).
fn local_lan_ipv4_tip() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        // Wi-Fi is usually en0/en1; USB / dock Ethernet adapters come later.
        for iface in ["en0", "en1", "en2", "en3", "en4", "en5"] {
            if let Ok(out) = Command::new("ipconfig").args(["getifaddr", iface]).output() {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if usable_lan_ipv4(&s) {
                        return Some(s);
                    }
                }
            }
        }
    }
    None
}

/// Exit code + message of a failed `ash listen`. `ash listen` exits with the
/// code (a supervisor must see the failure); the menu prints the message and
/// carries on.
type ListenError = (i32, String);

/// How long `ash listen` waits for the spawned service to prove its LAN
/// listener is up before it says so: identity unlock (Keychain prompt) and the
/// SQLCipher open can take a while. After this it warns and keeps waiting.
const LISTEN_READY_DEADLINE: Duration = Duration::from_secs(20);
const LISTEN_READY_POLL: Duration = Duration::from_millis(100);
/// The service binds the LAN port in parallel with its IPC task, which can
/// still fail on the instance lock: re-check the child after a short grace.
const LISTEN_READY_GRACE: Duration = Duration::from_millis(300);
/// Pre-flight IPC probe: a wedged daemon must not stall `ash listen` for the
/// full IPC I/O timeout.
const LISTEN_PREFLIGHT_PROBE: Duration = Duration::from_secs(2);

#[derive(Debug)]
enum ListenWait {
    Ready,
    Exited(std::process::ExitStatus),
    TimedOut,
    WaitFailed(io::Error),
}

/// Poll until `ready()` says the listener is up, `child` exits, or `deadline`
/// passes. Readiness is re-confirmed against the child after `grace`.
fn wait_for_listener(
    child: &mut std::process::Child,
    deadline: Duration,
    poll: Duration,
    grace: Duration,
    mut ready: impl FnMut() -> bool,
) -> ListenWait {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return ListenWait::Exited(st),
            Ok(None) => {}
            Err(e) => return ListenWait::WaitFailed(e),
        }
        if ready() {
            std::thread::sleep(grace);
            return match child.try_wait() {
                Ok(Some(st)) => ListenWait::Exited(st),
                Ok(None) => ListenWait::Ready,
                Err(e) => ListenWait::WaitFailed(e),
            };
        }
        if start.elapsed() >= deadline {
            return ListenWait::TimedOut;
        }
        std::thread::sleep(poll);
    }
}

/// The daemon's own word that its LAN listener is bound: IPC `Status` lists
/// `lan_direct` only once `lan_direct::listener_is_up()`. A bare IPC pong or a
/// TCP connect would also be satisfied by a different process.
fn status_reports_lan_listener(status: &Result<IpcResponse, String>) -> bool {
    matches!(
        status,
        Ok(IpcResponse::Status { capabilities, .. }) if capabilities.iter().any(|c| c == "lan_direct")
    )
}

/// Is the spawned service's LAN listener up right now?
fn lan_listener_up(data_dir: &Path) -> bool {
    if ipc_endpoint(data_dir).transport_available() {
        status_reports_lan_listener(&ipc_client::ipc_request_timeout(
            data_dir,
            &IpcRequest::Status { v: IPC_VERSION },
            Duration::from_millis(500),
        ))
    } else {
        // No IPC transport on this OS: fall back to the port itself.
        std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], DEFAULT_LAN_PORT)),
            Duration::from_millis(200),
        )
        .is_ok()
    }
}

fn report_listen_error(msg: &str) {
    let c = c();
    eprintln!("{0}{msg}{1}", c.red, c.reset);
}

/// `ash listen` / menu 4 — receive messages with ONE command.
///
/// Runs the same `raven-node service` receiver the secure send path dials
/// (LAN-direct Noise XX + PairInit + indexed session), in the foreground on
/// the fixed LAN port. Only peers in the contact book are trusted, so there is
/// nothing to pick; received messages land in the endpoint inbox (menu 2).
///
/// `Ok` = clean stop (or the profile's service already receives); every
/// startup failure and a non-zero listener exit is an `Err((exit code, why))`.
fn cmd_listen(data_dir: &Path) -> Result<(), ListenError> {
    let c = c();
    let id = match try_load_identity(data_dir) {
        Ok(Some(id)) => id,
        Ok(None) => {
            return Err((
                1,
                "identity missing — run: ash --data-dir <dir> init".into(),
            ))
        }
        Err(e) => {
            return Err((
                1,
                format!("secure identity store: {}", sanitize_terminal_line(&e)),
            ))
        }
    };
    let contacts = load_contacts(data_dir).map_err(|e| (1, sanitize_terminal_line(&e)))?;
    if contacts.is_empty() {
        return Err((
            1,
            "No pinned contacts yet.\nAdd one first (menu 5), so I know whose keys to accept."
                .into(),
        ));
    }

    // Local IP(s) to share with the friend.
    let ip = local_lan_ipv4_tip().unwrap_or_else(|| "<your-LAN-IP>".into());

    let node = ext::raven_node_bin_public();

    // Pre-flight: make sure the port is actually free before spawning.
    {
        use std::net::TcpListener;
        match TcpListener::bind(("0.0.0.0", DEFAULT_LAN_PORT)) {
            Ok(l) => {
                drop(l);
                // Port free but this profile's service answers IPC: it is an
                // outbound-only one (e.g. `RAVEN_SERVICE_LAN_LISTEN` was set).
                // A second service would die on the IPC instance lock after
                // already having bound the port, so refuse up front.
                if ipc_daemon_up(data_dir) {
                    return Err((
                        1,
                        format!(
                            "a raven-node service for this profile is already running but is NOT \
                             listening on port {DEFAULT_LAN_PORT} (outbound-only, started by an \
                             earlier send).\n\
                             Stop it:   pkill -f 'raven-node service'\n\
                             then run `ash listen` again (or unset RAVEN_SERVICE_LAN_LISTEN)."
                        ),
                    ));
                }
            }
            Err(_) if ipc_daemon_up(data_dir) => {
                // The raven-node service for this profile (auto-started by a
                // send) already listens on the LAN port and fills the inbox.
                println!(
                    "{0}port {DEFAULT_LAN_PORT} is busy and a raven-node service for this profile is running{1}",
                    c.yellow, c.reset
                );
                println!(
                    "{0}(started by an earlier send). It already receives — see menu 2 Inbox.{1}",
                    c.dim, c.reset
                );
                println!(
                    "   {0}Tell your friend: {ip}:{DEFAULT_LAN_PORT}{1}",
                    c.cyan, c.reset
                );
                println!("   your pub_hex: {}", hex::encode(id.public_key_bytes()));
                return Ok(());
            }
            Err(_) => {
                return Err((
                    1,
                    format!(
                        "port {DEFAULT_LAN_PORT} is already taken by another process.\n\
                         Find it:   lsof -i :{DEFAULT_LAN_PORT}\n\
                         Stop it:   pkill -f raven-node"
                    ),
                ));
            }
        }
    }

    let mut child = Command::new(node)
        .stdin(std::process::Stdio::null())
        .arg("service")
        .arg("--data-dir")
        .arg(data_dir)
        .args(["--lan-listen", &format!("0.0.0.0:{DEFAULT_LAN_PORT}")])
        .args(["--ble-listen", "127.0.0.1:0"])
        .spawn()
        .map_err(|e| {
            (
                1,
                format!(
                    "could not start raven-node: {}",
                    sanitize_terminal_line(&e.to_string())
                ),
            )
        })?;

    // Announce nothing until the service itself reports its LAN listener up
    // (or it died): a fixed sleep used to print LISTENING for a node that was
    // still unlocking its identity, or about to fail on the IPC instance lock.
    let probe = || lan_listener_up(data_dir);
    let mut waited = wait_for_listener(
        &mut child,
        LISTEN_READY_DEADLINE,
        LISTEN_READY_POLL,
        LISTEN_READY_GRACE,
        probe,
    );
    if matches!(waited, ListenWait::TimedOut) {
        eprintln!(
            "{0}still starting — the LAN listener is not up yet (identity unlock / Keychain prompt?). \
             I will announce it once it is. (Ctrl+C to give up){1}",
            c.yellow, c.reset
        );
        waited = wait_for_listener(
            &mut child,
            Duration::MAX,
            LISTEN_READY_POLL,
            LISTEN_READY_GRACE,
            probe,
        );
    }
    match waited {
        ListenWait::Ready => {}
        ListenWait::Exited(st) => {
            let _ = child.wait();
            return Err((
                st.code().filter(|code| *code != 0).unwrap_or(1),
                format!("listener exited during startup ({st}) — see raven-node's message above."),
            ));
        }
        ListenWait::TimedOut => {
            let _ = child.kill();
            let _ = child.wait();
            return Err((1, "the LAN listener never came up".into()));
        }
        ListenWait::WaitFailed(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err((
                1,
                format!(
                    "failed waiting for raven-node: {}",
                    sanitize_terminal_line(&e.to_string())
                ),
            ));
        }
    }

    println!();
    println!("{0}═══ LISTENING ═══{1}", c.purple, c.reset);
    println!("{0}Tell your friend to send to:{1}", c.dim, c.reset);
    println!("   {0}{ip}:{DEFAULT_LAN_PORT}{1}", c.cyan, c.reset);
    println!("{0}{LISTEN_INVITE_HINT}{1}", c.dim, c.reset);
    println!(
        "   raven:{}:{}",
        id.address(),
        hex::encode(id.public_key_bytes())
    );
    println!(
        "{0}Accepting your {1} contact(s) only. {LISTEN_STAYS_BUSY}{2}",
        c.dim,
        contacts.len(),
        c.reset
    );
    println!();

    match child.wait() {
        Ok(s) if s.success() => {
            println!("{0}listener stopped.{1}", c.dim, c.reset);
            Ok(())
        }
        Ok(s) => Err((s.code().unwrap_or(1), format!("listener exited ({s})."))),
        Err(e) => Err((
            1,
            format!(
                "failed waiting for raven-node: {}",
                sanitize_terminal_line(&e.to_string())
            ),
        )),
    }
}

/// What a friend does with the address shown above: they have to add YOU too.
const LISTEN_INVITE_HINT: &str =
    "…and they add you under menu 5 Contacts, a, pasting this invite line (it is also in `ash whoami`):";

/// This terminal is occupied by the receiver, so say where messages are read.
const LISTEN_STAYS_BUSY: &str = "This terminal stays busy while listening: open a second terminal and run `ash inbox` (or `ash`, menu 2) to read messages. Ctrl+C stops receiving.";

fn print_lan_unresolved_hint(contact_label: &str) {
    let s = style();
    let bold = s.bold;
    let dim = s.dim;
    let reset = s.reset;
    println!(
        "{bold}LAN peer not resolved{reset} for {} — identity ≠ IP.",
        sanitize_terminal_line(contact_label)
    );
    println!(
        "{dim}EN:{reset} Peer must reach this Mac (iPhone Serverless LAN → Host=Mac IP, Port={DEFAULT_LAN_PORT}),"
    );
    println!(
        "{dim}   {reset} or set listen on the phone / export RAVEN_PEER=host:port. No host:port prompt."
    );
    println!(
        "{dim}   {reset} Save it once: ash contact set-dial --petname <name> --lan-dial host:port"
    );
    println!(
        "{dim}FA:{reset} مخاطب باید به این مک برسد (آیفون Serverless LAN → Host=آی‌پی مک، Port={DEFAULT_LAN_PORT})؛"
    );
    println!(
        "{dim}   {reset} یا روی گوشی listen بگذارید / RAVEN_PEER=host:port. از شما port نمی‌پرسیم."
    );
    if let Some(ip) = local_lan_ipv4_tip() {
        println!(
            "{dim}Tip / نکته:{reset} Mac LAN IP ≈ {bold}{ip}{reset}  → phone Host={ip} Port={DEFAULT_LAN_PORT}"
        );
    } else {
        println!(
            "{dim}Tip:{reset} `ipconfig getifaddr en0` → put that IP + port {DEFAULT_LAN_PORT} on the phone."
        );
    }
    println!(
        "{dim}Also:{reset} `raven-node run --listen 0.0.0.0:{DEFAULT_LAN_PORT}` (Mac listens; phone dials)."
    );
}

/// Pure resolution used by tests: saved dial → env. No dial → `None`
/// (LocalListenQueue is disabled; the caller explains Mac-listens instead).
fn resolve_lan_peer_parts(saved_lan_dial: &str, env_dial: Option<&str>) -> Option<ResolvedLanPeer> {
    let saved = saved_lan_dial.trim();
    if looks_like_lan_dial(saved) {
        return Some(ResolvedLanPeer::Dial(saved.to_string()));
    }
    if let Some(e) = env_dial.map(str::trim).filter(|t| looks_like_lan_dial(t)) {
        return Some(ResolvedLanPeer::Dial(e.to_string()));
    }
    None
}

fn contact_fingerprint(c: &Contact) -> String {
    match parse_pub_hex(&c.pub_hex) {
        Ok(a) => device_fingerprint_v1(&a),
        Err(_) => "—".into(),
    }
}

fn normalize_tag(tag: &str) -> String {
    sanitize_terminal_line(tag.trim().trim_start_matches('@')).to_lowercase()
}

fn alias_store_path(data_dir: &Path) -> PathBuf {
    data_dir.join("alias_claims.json")
}

fn nearby_store_path(data_dir: &Path) -> PathBuf {
    data_dir.join("nearby_registry.json")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AliasClaimJson {
    alias: String,
    identity_address: String,
    sequence: u64,
    expires_at: u64,
    signature_hex: String,
    ed25519_pub_hex: String,
}

fn load_alias_store(data_dir: &Path, now: u64) -> AliasClaimStore {
    let mut store = AliasClaimStore::default();
    let Ok(raw) = std::fs::read_to_string(alias_store_path(data_dir)) else {
        return store;
    };
    let Ok(rows) = serde_json::from_str::<Vec<AliasClaimJson>>(&raw) else {
        return store;
    };
    for row in rows {
        let Ok(sig_v) = hex::decode(&row.signature_hex) else {
            continue;
        };
        let Ok(pub_v) = hex::decode(&row.ed25519_pub_hex) else {
            continue;
        };
        if sig_v.len() != 64 || pub_v.len() != 32 {
            continue;
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&sig_v);
        let mut ed25519_pub = [0u8; 32];
        ed25519_pub.copy_from_slice(&pub_v);
        let rec = AliasRecord {
            alias: row.alias,
            identity_address: row.identity_address,
            sequence: row.sequence,
            expires_at: row.expires_at,
            signature,
            ed25519_pub,
        };
        // Local file of the user's own publications: no network quota, so a
        // reload never silently drops rows beyond the Sybil / rate limits.
        let _ = store.put_trusted(rec, now);
    }
    store
}

/// Rows of `alias_claims.json`. Same policy as contacts.json: a corrupt store
/// is an error, never an empty list that a rewrite would silently persist.
fn read_alias_rows(data_dir: &Path) -> Result<Vec<AliasClaimJson>, String> {
    match std::fs::read_to_string(alias_store_path(data_dir)) {
        Ok(raw) => serde_json::from_str(&raw)
            .map_err(|e| format!("alias_claims.json corrupt — refusing overwrite: {e}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("alias_claims.json: {e}")),
    }
}

/// Highest stored sequence for this (alias, identity), expired or not: peers
/// keep that high-water mark after expiry too.
fn stored_alias_sequence(
    rows: &[AliasClaimJson],
    alias: &str,
    identity_address: &str,
) -> Option<u64> {
    rows.iter()
        .filter(|r| r.alias == alias && r.identity_address == identity_address)
        .map(|r| r.sequence)
        .max()
}

fn save_alias_claim(data_dir: &Path, rec: &AliasRecord) -> Result<(), String> {
    let path = alias_store_path(data_dir);
    let mut rows = read_alias_rows(data_dir)?;
    // Mirror `AliasClaimStore::admit`: peers refuse a claim whose sequence is
    // not above the one they already hold, so never regress local state.
    if let Some(prev) = stored_alias_sequence(&rows, &rec.alias, &rec.identity_address) {
        if rec.sequence <= prev {
            return Err(format!(
                "ALIAS_STALE_SEQUENCE: @{} is already stored at sequence {prev}; \
                 publish with a higher --sequence (got {})",
                rec.alias, rec.sequence
            ));
        }
    }
    rows.retain(|r| !(r.alias == rec.alias && r.identity_address == rec.identity_address));
    rows.push(AliasClaimJson {
        alias: rec.alias.clone(),
        identity_address: rec.identity_address.clone(),
        sequence: rec.sequence,
        expires_at: rec.expires_at,
        signature_hex: hex::encode(rec.signature),
        ed25519_pub_hex: hex::encode(rec.ed25519_pub),
    });
    create_private_data_dir(data_dir).map_err(|e| e.to_string())?;
    let raw = serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?;
    raven_core::atomic_write_private(&path, raw.as_bytes())
}

fn cmd_alias_publish(data_dir: &Path, alias: &str, sequence: Option<u64>, expires_at: Option<u64>) {
    let id = require_identity(data_dir);
    let alias = match normalize_alias(alias) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    // Default: one above what is stored, so a refresh (new expiry) is accepted
    // by peers that already hold the earlier claim.
    let sequence = match sequence {
        Some(s) => s,
        None => match read_alias_rows(data_dir) {
            Ok(rows) => stored_alias_sequence(&rows, &alias, &id.address())
                .map_or(1, |prev| prev.saturating_add(1)),
            Err(e) => {
                eprintln!("alias store: {e}");
                std::process::exit(1);
            }
        },
    };
    let now = now_ms();
    let expires_at = expires_at.unwrap_or(now.saturating_add(30 * 24 * 60 * 60 * 1000));
    let rec = AliasRecord {
        alias: alias.clone(),
        identity_address: id.address(),
        sequence,
        expires_at,
        signature: [0u8; 64],
        ed25519_pub: id.public_key_bytes(),
    };
    let signed = match rec.sign(&id) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("alias sign: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = signed.verify(now) {
        eprintln!("alias verify: {e}");
        std::process::exit(1);
    }
    if let Err(e) = save_alias_claim(data_dir, &signed) {
        eprintln!("alias store: {e}");
        std::process::exit(1);
    }
    println!("{C_GREEN}alias published{C_RESET} @{alias}");
    println!("{C_DIM}sequence{C_RESET}    {sequence}");
    println!("{C_DIM}expires_ms{C_RESET}  {expires_at}");
    println!("{C_DIM}address{C_RESET}     {}", signed.identity_address);
}

fn build_discovery_ctx(data_dir: &Path) -> DiscoveryContext {
    let now = now_ms();
    let contacts: Vec<LocalContactRow> = contacts_or_die(data_dir)
        .into_iter()
        .map(|c| LocalContactRow {
            raven_id: c.address.clone(),
            pub_hex: c.pub_hex.clone(),
            petname: c.petname.clone(),
            public_tag: if c.public_tag.is_empty() {
                c.alias.clone()
            } else {
                c.public_tag.clone()
            },
            display_name: c.petname.clone(),
            pinned: c.pinned,
            directly_verified: c.pinned,
        })
        .collect();
    DiscoveryContext {
        contacts,
        aliases: load_alias_store(data_dir, now),
        // No public profile index in V1 (serverless): nothing to load.
        profiles: ProfileStore::default(),
        blocked: BlockList::load_checked(data_dir).unwrap_or_else(|e| {
            eprintln!("block list: {e}");
            std::process::exit(1);
        }),
        serverless: true,
        public_profile_index_enabled: false,
        now_ms: now,
        ..Default::default()
    }
}

fn print_discovery_hit(i: usize, h: &DiscoveryResult) {
    println!(
        "  {C_CYAN}{}{C_RESET}  {}  {}",
        i + 1,
        if h.display_name.is_empty() {
            "(no display name)".into()
        } else {
            sanitize_terminal_line(&h.display_name)
        },
        match h.verification_state {
            VerificationState::AliasConflict => format!("{C_PURPLE}ALIAS_CONFLICT{C_RESET}"),
            VerificationState::DirectlyVerified => format!("{C_GREEN}DIRECTLY_VERIFIED{C_RESET}"),
            VerificationState::TrustedContact => format!("{C_GREEN}TRUSTED_CONTACT{C_RESET}"),
            VerificationState::Blocked => format!("{C_PURPLE}BLOCKED{C_RESET}"),
            VerificationState::Introduced => "INTRODUCED".into(),
            VerificationState::NearbyVerified => "NEARBY_VERIFIED".into(),
            VerificationState::PublicSignedProfile => "PUBLIC_SIGNED_PROFILE".into(),
            VerificationState::ScopedVerified => "SCOPED_VERIFIED".into(),
            VerificationState::ExpiredOrStale => "EXPIRED_OR_STALE".into(),
            VerificationState::Unverified => format!("{C_PURPLE}UNVERIFIED{C_RESET}"),
        }
    );
    println!(
        "      {C_DIM}raven_id{C_RESET}  {}",
        sanitize_terminal_line(&h.raven_id)
    );
    if !h.aliases.is_empty() {
        println!(
            "      {C_DIM}aliases{C_RESET}   {}",
            h.aliases
                .iter()
                .map(|a| format!("@{}", sanitize_terminal_line(a)))
                .collect::<Vec<_>>()
                .join(" ")
        );
    }
    println!(
        "      {C_DIM}sources{C_RESET}   {:?}  conflict={}",
        h.source_set, h.conflict_count
    );
}

fn cmd_find(
    data_dir: &Path,
    query: &str,
    local: bool,
    exact_id: bool,
    exact_alias: bool,
    all: bool,
) {
    let ctx = build_discovery_ctx(data_dir);
    let scope = if local {
        DiscoveryScope::Local
    } else if exact_id {
        DiscoveryScope::ExactId
    } else if exact_alias || query.trim().starts_with('@') {
        DiscoveryScope::ExactAlias
    } else if query.trim().starts_with("rvn1") {
        DiscoveryScope::ExactId
    } else {
        // Bare text → local only in V1 (no public fuzzy).
        DiscoveryScope::Local
    };
    let hits = DiscoveryResolver::v1().search(query, scope, &ctx);
    println!(
        "{C_BOLD}Discovery{C_RESET} query={} scope={:?} hits={}",
        sanitize_terminal_line(query),
        scope,
        hits.len()
    );
    if hits.is_empty() {
        println!("{C_DIM}No results. Try ash find @alias / rvn1… / --local{C_RESET}");
        return;
    }
    let conflicts = hits
        .iter()
        .any(|h| h.verification_state == VerificationState::AliasConflict);
    for (i, h) in hits.iter().enumerate() {
        print_discovery_hit(i, h);
    }
    if conflicts && !all && hits.len() > 1 {
        println!(
            "{C_PURPLE}alias conflict{C_RESET}: {} candidates — pick one (never silent)",
            hits.len()
        );
        print!("pick [1-{}] or Enter to abort: ", hits.len());
        let _ = io::stdout().flush();
        let line = read_line();
        if let Ok(n) = line.trim().parse::<usize>() {
            if n >= 1 && n <= hits.len() {
                let h = &hits[n - 1];
                println!(
                    "{C_GREEN}selected{C_RESET} {} — use: ash contact request {}",
                    sanitize_terminal_line(&h.raven_id),
                    sanitize_terminal_line(&h.raven_id)
                );
            }
        }
    }
}

/// Persisted nearby advertisement (local mock). The full advertisement is
/// stored so a reload shows the original token/commitment with its original
/// expiry — tokens are never re-minted with a fresh TTL.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NearbyTokenJson {
    token_hex: String,
    commitment_hex: String,
    issued_at_ms: u64,
    ttl_ms: u64,
}

impl NearbyTokenJson {
    fn from_adv(a: &NearbyAdvertisement) -> Self {
        Self {
            token_hex: hex::encode(a.ephemeral_token),
            commitment_hex: hex::encode(a.session_commitment),
            issued_at_ms: a.issued_at_ms,
            ttl_ms: a.ttl_ms,
        }
    }

    fn to_adv(&self) -> Option<NearbyAdvertisement> {
        let token: [u8; 16] = hex::decode(&self.token_hex).ok()?.try_into().ok()?;
        let commitment: [u8; 32] = hex::decode(&self.commitment_hex).ok()?.try_into().ok()?;
        Some(NearbyAdvertisement {
            ephemeral_token: token,
            session_commitment: commitment,
            issued_at_ms: self.issued_at_ms,
            ttl_ms: self.ttl_ms,
        })
    }
}

/// Still-live stored advertisements. Expired rows, malformed rows and the
/// legacy bare-token list (no mint time → cannot prove liveness) are dropped.
fn load_live_nearby_ads(raw: &str, now: u64) -> Vec<NearbyAdvertisement> {
    let Ok(rows) = serde_json::from_str::<Vec<serde_json::Value>>(raw) else {
        return Vec::new();
    };
    rows.into_iter()
        .filter_map(|v| serde_json::from_value::<NearbyTokenJson>(v).ok())
        .filter_map(|row| row.to_adv())
        .filter(|a| a.is_live(now))
        .collect()
}

fn cmd_nearby(data_dir: &Path) {
    // The registry file is profile state: not before the first identity.
    if let Err(e) = require_identity_before_state(data_dir, "nearby") {
        eprintln!("{}", sanitize_terminal_line(&e));
        std::process::exit(1);
    }
    let path = nearby_store_path(data_dir);
    let now = now_ms();
    let mut reg = NearbyRegistry::default();
    if let Ok(raw) = std::fs::read_to_string(&path) {
        for adv in load_live_nearby_ads(&raw, now) {
            let _ = reg.publish_ephemeral(adv);
        }
    }
    let adv = NearbyAdvertisement::mint(now, 60_000, b"ash-nearby");
    if adv.contains_permanent_raven_id() {
        eprintln!("refused: permanent Raven ID in nearby advertisement");
        std::process::exit(1);
    }
    if let Err(e) = reg.publish_ephemeral(adv) {
        eprintln!("nearby: {e}");
        std::process::exit(1);
    }
    let rows: Vec<NearbyTokenJson> = reg
        .scan_live(now)
        .into_iter()
        .map(NearbyTokenJson::from_adv)
        .collect();
    if let Err(e) = create_private_data_dir(data_dir)
        .map_err(|e| e.to_string())
        .and_then(|_| {
            let raw = serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?;
            raven_core::atomic_write_private(&path, raw.as_bytes())
        })
    {
        eprintln!("nearby store: {e}");
    }
    println!(
        "{C_BOLD}Nearby{C_RESET} (local software mock — lists only THIS device's own ephemeral tokens; no BLE receive side)"
    );
    for a in reg.scan_live(now) {
        let phrase = raven_core::nearby_safety_phrase(&a.ephemeral_token, &a.session_commitment);
        let left_ms = a.issued_at_ms.saturating_add(a.ttl_ms).saturating_sub(now);
        println!(
            "  token={} ttl_left_ms={} commitment={}",
            hex::encode(a.ephemeral_token),
            left_ms,
            hex::encode(a.session_commitment)
        );
        println!(
            "  {C_PURPLE}safety phrase{C_RESET} {phrase}  {C_DIM}(confirm OOB before pin){C_RESET}"
        );
    }
    println!("{C_DIM}Confirm pairing locally before binding to rvn1 identity.{C_RESET}");
}

/// Product contact-request transport stays off until ash owns an authenticated
/// ATSAM root plus crash-safe send/receive chain state. The low-level codec is
/// available for vectors, but CLI commands never synthesize that session.
///
/// Legacy RavenContactRequestV1 entry points remain fail-closed. Live friendship
/// bootstrap is PairInit (see `pair_init::PRODUCTION_ENABLED`), not rootless
/// contact ciphertext.
fn contact_session_transport_ready() -> bool {
    // Legacy RavenContactRequestV1 stays fail-closed until the four generic
    // production tripwires flip. LAN-direct must not open this path.
    raven_core::pair_init::live_enabled()
        && raven_core::indexed_session_store::live_enabled()
        && raven_core::prekey_lifecycle::live_enabled()
        && raven_core::atsam_indexed_session::live_enabled()
}

fn refuse_unready_contact_session() -> ! {
    let status = "PRODUCTION_GATE_DISABLED:WAITING_FOR_PAIR_INIT_SESSION";
    trace_delivery::trace_event(
        "ash/cli.rs:refuse_unready_contact_session",
        "TRACE_FRIEND_REQUEST_BLOCKED",
        status,
        None,
        Some("legacy_contact_request_entry_fail_closed"),
    );
    eprintln!("{C_PURPLE}status{C_RESET} {status}");
    eprintln!(
        "{C_PURPLE}security hold{C_RESET}: authenticated PairInit/ATSAM session required; no request or accept wire was created/opened"
    );
    std::process::exit(2)
}

/// 1-based user pick → 0-based index. 0 and anything past the end are out of
/// range (a saturating `n - 1` used to turn `--pick 0` into candidate 1).
fn pick_index(n: usize, len: usize) -> Option<usize> {
    n.checked_sub(1).filter(|i| *i < len)
}

fn cmd_contact_request(data_dir: &Path, target: &str, message: &str, pick: Option<usize>) {
    if !contact_session_transport_ready() {
        refuse_unready_contact_session();
    }
    let id = require_identity(data_dir);
    let ctx = build_discovery_ctx(data_dir);
    let q = target.trim();
    let mut hits = if q.starts_with("rvn1") {
        DiscoveryResolver::v1().search(q, DiscoveryScope::ExactId, &ctx)
    } else {
        DiscoveryResolver::v1().search(q, DiscoveryScope::ExactAlias, &ctx)
    };
    // Fall back to local contacts for @tag
    if hits.is_empty() {
        hits = DiscoveryResolver::v1().search(q, DiscoveryScope::Local, &ctx);
    }
    if hits.is_empty() {
        eprintln!("no discovery hit for {q}");
        std::process::exit(1);
    }
    let chosen = if hits.len() == 1 {
        &hits[0]
    } else if let Some(n) = pick {
        // --pick is 1-based: 0 is out of range, never "the first candidate".
        pick_index(n, hits.len())
            .map(|i| &hits[i])
            .unwrap_or_else(|| {
                eprintln!("pick out of range (1-{})", hits.len());
                std::process::exit(1);
            })
    } else {
        println!("{C_PURPLE}multiple candidates{C_RESET} — pick one:");
        for (i, h) in hits.iter().enumerate() {
            print_discovery_hit(i, h);
        }
        print!("pick [1-{}]: ", hits.len());
        let _ = io::stdout().flush();
        let line = read_line();
        let n: usize = line.trim().parse().unwrap_or(0);
        if n < 1 || n > hits.len() {
            eprintln!("aborted");
            std::process::exit(1);
        }
        &hits[n - 1]
    };
    if chosen.verification_state == VerificationState::Blocked {
        eprintln!("refused: target is blocked locally");
        std::process::exit(1);
    }
    let peer_pub = if let Some(c) = ctx.contacts.iter().find(|c| c.raven_id == chosen.raven_id) {
        parse_pub_hex(&c.pub_hex).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(1);
        })
    } else if let Ok(claims) = ctx.aliases.lookup_exact(
        chosen.aliases.first().map(|s| s.as_str()).unwrap_or(q),
        now_ms(),
    ) {
        // Only a claim for exactly the chosen identity may supply the key —
        // never "the only claim", which could belong to someone else.
        if let Some(claim) = claims
            .iter()
            .find(|c| c.identity_address == chosen.raven_id)
        {
            claim.ed25519_pub
        } else {
            eprintln!("need contact pub_hex or signed alias claim with matching raven_id");
            std::process::exit(1);
        }
    } else {
        eprintln!("need local contact or signed alias claim to seal request (address alone is not a pubkey)");
        std::process::exit(1);
    };
    let mut request_id = [0u8; 16];
    {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut request_id);
    }
    let req = RavenContactRequestV1::create(
        &id,
        &peer_pub,
        &chosen.raven_id,
        ContactRequestInner {
            request_id,
            sender_raven_id: id.address(),
            sender_display_name: String::new(),
            sender_aliases: vec![],
            sender_profile_digest: [0u8; 32],
            optional_message: sanitize_terminal_text(message),
            created_at: now_ms(),
            expires_at: now_ms() + 7 * 24 * 3600 * 1000,
        },
    )
    .unwrap_or_else(|e| {
        eprintln!("seal failed: {e}");
        std::process::exit(1);
    });
    if !req.is_ciphertext_only() {
        eprintln!("refused: contact request is not ciphertext-only");
        std::process::exit(1);
    }
    let wire = req.encode_wire().unwrap_or_else(|e| {
        eprintln!("wire encode failed: {e}");
        std::process::exit(1);
    });
    // Ciphertext-only file (opaque to store/bridge) + full wire for endpoint delivery.
    let out_ct = data_dir.join(format!("contact_request_{}.bin", hex::encode(request_id)));
    let out_wire = data_dir.join(format!("contact_request_{}.wire", hex::encode(request_id)));
    for (path, bytes) in [(&out_ct, &req.ciphertext), (&out_wire, &wire)] {
        if let Err(e) = raven_core::atomic_write_private(path, bytes) {
            eprintln!("write {}: {e}", path.display());
            std::process::exit(1);
        }
    }
    println!("{C_GREEN}contact request sealed{C_RESET} (ciphertext-only for store/bridge)");
    println!("{C_DIM}request_id{C_RESET} {}", hex::encode(request_id));
    println!(
        "{C_DIM}recipient{C_RESET}  {}",
        sanitize_terminal_line(&chosen.raven_id)
    );
    println!("{C_DIM}ciphertext{C_RESET} {}", out_ct.display());
    println!("{C_DIM}wire{C_RESET}       {}", out_wire.display());
    println!(
        "{C_DIM}deliver wire via MessageRouter (direct/relay/store/BLE/Bridge) — same message_id{C_RESET}"
    );
}

fn contact_inbox_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("contact_inbox")
}

fn parse_request_id_hex(s: &str) -> [u8; 16] {
    let v = hex::decode(s.trim()).unwrap_or_else(|_| {
        eprintln!("bad request_id hex");
        std::process::exit(1);
    });
    if v.len() != 16 {
        eprintln!("request_id must be 16 bytes (32 hex chars)");
        std::process::exit(1);
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&v);
    id
}

fn load_contact_inbox(data_dir: &Path) -> ContactRequestInbox {
    let id = require_identity(data_dir);
    let mut inbox = ContactRequestInbox::default();
    let dir = contact_inbox_dir(data_dir);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return inbox;
    };
    for ent in entries.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("wire") {
            continue;
        }
        let Ok(raw) = std::fs::read(&path) else {
            continue;
        };
        let Ok(outer) = RavenContactRequestV1::decode_wire(&raw) else {
            continue;
        };
        let _ = inbox.ingest(outer, &id, now_ms());
    }
    inbox
}

fn persist_inbox_wire(data_dir: &Path, outer: &RavenContactRequestV1) -> Result<(), String> {
    let dir = contact_inbox_dir(data_dir);
    create_private_data_dir(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.wire", hex::encode(outer.request_id)));
    let wire = outer.encode_wire()?;
    raven_core::atomic_write_private(&path, &wire)
}

/// Drop a handled request from the pending inbox. A failed delete is only a
/// warning (the request would merely show up as pending again), but never silent.
fn remove_inbox_wire(data_dir: &Path, request_id: &[u8; 16]) {
    let path = contact_inbox_dir(data_dir).join(format!("{}.wire", hex::encode(request_id)));
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => eprintln!(
            "warning: could not remove pending request {}: {e}",
            path.display()
        ),
    }
}

fn cmd_contact_pending(data_dir: &Path) {
    if !contact_session_transport_ready() {
        refuse_unready_contact_session();
    }
    let inbox = load_contact_inbox(data_dir);
    println!(
        "{C_BOLD}Pending contact requests{C_RESET} ({})",
        inbox.pending().len()
    );
    if inbox.pending().is_empty() {
        println!(
            "{C_DIM}None. Ingest with: ash contact ingest --file contact_request_….wire{C_RESET}"
        );
        return;
    }
    for (i, p) in inbox.pending().iter().enumerate() {
        println!(
            "  {C_CYAN}{}{C_RESET}  id={}  from={}  name=\"{}\"  msg=\"{}\"",
            i + 1,
            hex::encode(p.outer.request_id),
            sanitize_terminal_line(&p.inner.sender_raven_id),
            sanitize_terminal_line(&p.inner.sender_display_name),
            sanitize_terminal_line(&p.inner.optional_message)
        );
    }
    println!("{C_DIM}ash contact accept <id> --petname \"…\" | decline <id> | block <id>{C_RESET}");
}

fn cmd_contact_ingest(data_dir: &Path, file: &Path) {
    if !contact_session_transport_ready() {
        refuse_unready_contact_session();
    }
    let id = require_identity(data_dir);
    let raw = std::fs::read(file).unwrap_or_else(|e| {
        eprintln!("read failed: {e}");
        std::process::exit(1);
    });
    let outer = RavenContactRequestV1::decode_wire(&raw).unwrap_or_else(|e| {
        eprintln!("bad wire: {e}");
        std::process::exit(1);
    });
    // Bridge/store opacity: wire encodes outer metadata + opaque ciphertext.
    // The wire comes from a user-supplied file: refuse, never panic.
    if !outer.is_ciphertext_only() {
        eprintln!("bad wire: not ciphertext-only");
        std::process::exit(1);
    }
    let mut inbox = ContactRequestInbox::default();
    let inner = inbox
        .ingest(outer.clone(), &id, now_ms())
        .unwrap_or_else(|e| {
            eprintln!("ingest refused: {e}");
            std::process::exit(1);
        });
    if let Err(e) = persist_inbox_wire(data_dir, &outer) {
        eprintln!("persist failed: {e}");
        std::process::exit(1);
    }
    println!(
        "{C_GREEN}ingested{C_RESET} request {}",
        hex::encode(inner.request_id)
    );
    println!(
        "{C_DIM}from{C_RESET} {} — {}",
        sanitize_terminal_line(&inner.sender_raven_id),
        sanitize_terminal_line(&inner.sender_display_name)
    );
}

/// Make an accepted request durable: bind the contact, write the accept wire,
/// and only then drop the pending request. A failure before the last step
/// leaves the request pending, so accept can be re-run (`add_contact` replaces
/// the same key's row, so a retry is idempotent). Returns the accept wire path.
fn finish_contact_accept(
    data_dir: &Path,
    rid: &[u8; 16],
    outcome: &ContactAcceptOutcome,
) -> Result<PathBuf, String> {
    // Bind local contact (raven_id + petname); verification = trusted contact.
    add_contact(
        data_dir,
        &outcome.binding.raven_id,
        &outcome.binding.pub_hex,
        &outcome.binding.petname,
        "",
        None,
        "",
    )
    .map_err(|e| format!("bind failed: {}", sanitize_terminal_line(&e)))?;
    let wire = outcome
        .accept
        .encode_wire()
        .map_err(|e| format!("accept wire: {e}"))?;
    let out = data_dir.join(format!("contact_accept_{}.wire", hex::encode(rid)));
    raven_core::atomic_write_private(&out, &wire).map_err(|e| format!("accept wire write: {e}"))?;
    remove_inbox_wire(data_dir, rid);
    Ok(out)
}

fn cmd_contact_accept(data_dir: &Path, request_id_hex: &str, petname: &str) {
    if !contact_session_transport_ready() {
        refuse_unready_contact_session();
    }
    let id = require_identity(data_dir);
    let rid = parse_request_id_hex(request_id_hex);
    let mut inbox = load_contact_inbox(data_dir);
    let outcome = inbox
        .accept(&rid, &id, petname, now_ms())
        .unwrap_or_else(|e| {
            eprintln!("accept failed: {e}");
            std::process::exit(1);
        });
    let out = finish_contact_accept(data_dir, &rid, &outcome).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(1);
    });
    println!(
        "{C_GREEN}accepted{C_RESET} + bound petname \"{}\"",
        sanitize_terminal_line(&outcome.binding.petname)
    );
    println!(
        "{C_DIM}raven_id{C_RESET} {}",
        sanitize_terminal_line(&outcome.binding.raven_id)
    );
    println!(
        "{C_DIM}verify{C_RESET}   {:?}",
        outcome.binding.verification_state
    );
    println!(
        "{C_DIM}accept wire{C_RESET} {} (deliver opaque via MessageRouter)",
        out.display()
    );
}

fn cmd_contact_decline(data_dir: &Path, request_id_hex: &str) {
    if !contact_session_transport_ready() {
        refuse_unready_contact_session();
    }
    let rid = parse_request_id_hex(request_id_hex);
    let mut inbox = load_contact_inbox(data_dir);
    if let Err(e) = inbox.decline(&rid) {
        eprintln!("decline failed: {e}");
        std::process::exit(1);
    }
    remove_inbox_wire(data_dir, &rid);
    println!("{C_GREEN}declined{C_RESET} {}", hex::encode(rid));
}

fn cmd_contact_block(data_dir: &Path, request_id_hex: &str) {
    if !contact_session_transport_ready() {
        refuse_unready_contact_session();
    }
    let rid = parse_request_id_hex(request_id_hex);
    let mut inbox = load_contact_inbox(data_dir);
    let mut blocks = match BlockList::load_checked(data_dir) {
        Ok(blocks) => blocks,
        Err(e) => {
            eprintln!("block list: {e}");
            std::process::exit(1);
        }
    };
    if let Err(e) = inbox.block(&rid, &mut blocks) {
        eprintln!("block failed: {e}");
        std::process::exit(1);
    }
    if let Err(e) = blocks.save(data_dir) {
        eprintln!("block save failed: {e}");
        std::process::exit(1);
    }
    remove_inbox_wire(data_dir, &rid);
    println!("{C_GREEN}blocked{C_RESET} sender of {}", hex::encode(rid));
}

/// Resolve @public_tag — never silent pick when multiple match.
fn resolve_tag_contacts<'a>(contacts: &'a [Contact], tag: &str) -> Vec<&'a Contact> {
    let want = normalize_tag(tag);
    // A lone "@" normalises to "", and so does every untagged contact: that is
    // "no tag given", not a tag to match (it used to select petname-only contacts).
    if want.is_empty() {
        return Vec::new();
    }
    contacts
        .iter()
        .filter(|c| normalize_tag(&c.public_tag) == want || normalize_tag(&c.alias) == want)
        .collect()
}

/// Back-compat alias used by interactive send.
fn resolve_alias_contacts<'a>(contacts: &'a [Contact], alias: &str) -> Vec<&'a Contact> {
    resolve_tag_contacts(contacts, alias)
}

/// `--contact <value>` exactly like the guided picker: `@tag` is a tag (a lone
/// `@` names nobody); anything else is a petname (case-insensitive), and a bare
/// word that is no petname still works as a tag (`--contact b` for `@b`).
fn resolve_contact_arg<'a>(contacts: &'a [Contact], arg: &str) -> Vec<&'a Contact> {
    let t = arg.trim();
    if t.starts_with('@') {
        return resolve_alias_contacts(contacts, t);
    }
    let want = sanitize_terminal_line(t).to_lowercase();
    if want.is_empty() {
        return Vec::new();
    }
    let by_name: Vec<&Contact> = contacts
        .iter()
        .filter(|c| sanitize_terminal_line(&c.petname).to_lowercase() == want)
        .collect();
    if by_name.is_empty() {
        resolve_alias_contacts(contacts, t)
    } else {
        by_name
    }
}

/// "no contact for X" with the names that do exist, so a typo is one look away
/// from the fix (keeps the `no contact for` prefix scripts and tests look for).
fn no_contact_message(contacts: &[Contact], arg: &str) -> String {
    let asked = sanitize_terminal_line(arg);
    if contacts.is_empty() {
        return format!(
            "no contact for {asked} — you have no contacts yet. Add one: ash contact add --address rvn1… --pub-hex … --petname NAME (or run `ash`, menu 5)"
        );
    }
    let names: Vec<String> = contacts
        .iter()
        .take(8)
        .map(|c| match c.tag_subtitle() {
            Some(tag) => format!("{} ({tag})", c.primary_label()),
            None => c.primary_label(),
        })
        .collect();
    let more = if contacts.len() > names.len() {
        format!(
            ", … (+{} more: `ash contact list`)",
            contacts.len() - names.len()
        )
    } else {
        String::new()
    };
    format!(
        "no contact for {asked}. Your contacts: {}{more}. Use --contact NAME or --contact @tag.",
        names.join(", ")
    )
}

fn add_contact(
    data_dir: &Path,
    address: &str,
    pub_hex: &str,
    petname: &str,
    public_tag: &str,
    verify_fp: Option<&str>,
    lan_dial: &str,
) -> Result<(), String> {
    let ed = parse_pub_hex(pub_hex)?;
    let address_raw = extract_address_field(address).unwrap_or_else(|| address.trim().to_string());
    if address_raw.is_empty() {
        return Err("address required".into());
    }
    let address = raven_core::address::from_display(&address_raw);
    if decode_address(&address).is_none() {
        return Err("address must be valid rvn1 bech32m".into());
    }
    let derived = encode_address(&ed);
    if derived != address {
        return Err(format!(
            "address/pub mismatch: pub encodes to {derived}, got {address}"
        ));
    }
    let fp = device_fingerprint_v1(&ed);
    let pin = if let Some(expected) = verify_fp {
        let exp = expected.trim();
        if !exp.eq_ignore_ascii_case(&fp) {
            return Err(format!(
                "fingerprint mismatch: got {fp}, expected {}",
                sanitize_terminal_line(exp)
            ));
        }
        true
    } else {
        false
    };

    // Layer B tags follow the Alias V1 charset (a-z 0-9 _ -); never free text.
    let tag_clean = if public_tag.trim().trim_start_matches('@').trim().is_empty() {
        String::new()
    } else {
        normalize_alias(public_tag)
            .map_err(|e| format!("public @tag rejected ({e}): use a-z 0-9 _ - (max 64)"))?
    };
    let mut pet = sanitize_terminal_line(petname.trim());
    let ed_hex = hex::encode(ed);

    let mut contacts = load_contacts(data_dir)?;

    // Re-adding a known key (refreshing its `--lan-dial`, accepting a request
    // from an existing contact, …) must not blank its labels: an omitted
    // petname / tag keeps the stored one. An explicit value still overrides.
    // The tag clash / key-change checks below look at the EXPLICIT tag only.
    let prior = contacts
        .iter()
        .find(|c| c.pub_hex.eq_ignore_ascii_case(&ed_hex))
        .cloned();
    if pet.is_empty() {
        pet = match prior.as_ref() {
            Some(p) if !sanitize_terminal_line(&p.petname).is_empty() => {
                sanitize_terminal_line(&p.petname)
            }
            _ => tag_clean.clone(),
        };
    }
    let tag_store = if tag_clean.is_empty() {
        prior
            .as_ref()
            .map(|p| normalize_tag(&p.public_tag))
            .unwrap_or_default()
    } else {
        tag_clean.clone()
    };

    // Key-change warning: pinned row for the same identity (address) or the
    // same public_tag, but bound to a different key.
    for c in contacts.iter() {
        let same_identity = c.address == address;
        let same_tag = !tag_clean.is_empty() && normalize_tag(&c.public_tag) == tag_clean;
        if c.pinned
            && (same_identity || same_tag)
            && (!c.pub_hex.eq_ignore_ascii_case(&ed_hex) || c.address != address)
        {
            if same_tag {
                eprintln!("{C_PURPLE}KEY-CHANGE WARNING{C_RESET}: pinned @{tag_clean} was");
            } else {
                eprintln!(
                    "{C_PURPLE}KEY-CHANGE WARNING{C_RESET}: pinned {} was",
                    c.primary_label()
                );
            }
            eprintln!(
                "  old fp={}  {}",
                contact_fingerprint(c),
                sanitize_terminal_line(&c.address)
            );
            eprintln!("  new fp={fp}  {}", sanitize_terminal_line(&address));
            eprintln!(
                "{C_DIM}DHT/gossip cannot overwrite a pin. To replace it deliberately: verify the new fingerprint out-of-band, run{C_RESET}"
            );
            eprintln!(
                "  ash contact remove --address {}",
                sanitize_terminal_line(&c.address)
            );
            eprintln!(
                "{C_DIM}then add the new key again with --verify-fp <new fingerprint>.{C_RESET}"
            );
            return Err("KEY_CHANGE_REFUSED_WITHOUT_REPIN".into());
        }
    }

    // Soft-unique: competing same @tag → ambiguity notice; require distinct petnames.
    if !tag_clean.is_empty() {
        let clashes: Vec<&Contact> = contacts
            .iter()
            .filter(|c| {
                normalize_tag(&c.public_tag) == tag_clean
                    && !c.pub_hex.eq_ignore_ascii_case(&ed_hex)
            })
            .collect();
        if !clashes.is_empty() {
            eprintln!(
                "{C_PURPLE}tag ambiguity{C_RESET}: {} other contact(s) claim '@{tag_clean}'",
                clashes.len()
            );
            for (i, c) in clashes.iter().enumerate() {
                eprintln!(
                    "  {}  {}  @{}  fp={}{}",
                    i + 1,
                    c.primary_label(),
                    normalize_tag(&c.public_tag),
                    contact_fingerprint(c),
                    if c.pinned { " [pinned]" } else { "" }
                );
            }
            if pet.is_empty() || clashes.iter().any(|c| c.petname == pet) {
                return Err(
                    "choose a distinct --petname (e.g. \"Ahmad (Berlin)\") — never silent pick"
                        .into(),
                );
            }
            eprintln!(
                "{C_DIM}saving with distinct petname — pinned rows stay authoritative{C_RESET}"
            );
        }
    }

    // Petnames are the primary local label and the Send picker key: unique
    // on this device (case-insensitive), so a later add can never shadow one.
    if !pet.is_empty() {
        let want = pet.to_lowercase();
        if let Some(other) = contacts
            .iter()
            .find(|c| !c.pub_hex.eq_ignore_ascii_case(&ed_hex) && c.petname.to_lowercase() == want)
        {
            return Err(format!(
                "petname \"{pet}\" is already used by another contact (fp={}) — choose a distinct petname",
                contact_fingerprint(other)
            ));
        }
    }

    // Replace same pub_hex if present (preserve pin / dial if already set).
    let prior_pinned = prior.as_ref().map(|c| c.pinned).unwrap_or(false);
    let prior_dial = prior
        .as_ref()
        .map(|c| c.lan_dial.clone())
        .unwrap_or_default();
    let dial = if !lan_dial.trim().is_empty() {
        let d = lan_dial.trim();
        if !looks_like_lan_dial(d) {
            return Err("lan_dial must look like host:port (e.g. 192.168.1.20:7420)".into());
        }
        d.to_string()
    } else {
        prior_dial
    };
    // Also drop unpinned rows claiming this address under another key: the
    // address is derived from the key, so such a row is an invalid binding.
    contacts.retain(|c| !c.pub_hex.eq_ignore_ascii_case(&ed_hex) && c.address != address);
    contacts.push(Contact {
        petname: pet,
        public_tag: tag_store.clone(),
        alias: tag_store,
        address,
        pub_hex: ed_hex,
        pinned: pin || prior_pinned,
        lan_dial: dial,
    });
    save_contacts(data_dir, &contacts)?;
    let saved = contacts.last().unwrap();
    let label = saved.primary_label();
    let named = !saved.petname.trim().is_empty();
    if named || saved.tag_subtitle().is_some() {
        println!("{C_GREEN}contact saved{C_RESET}: {label}");
    } else {
        println!(
            "{C_GREEN}contact saved{C_RESET} (no name given: add --petname NAME next time so you can pick them easily)"
        );
    }
    println!(
        "{C_DIM}petname{C_RESET}     {}",
        if named { label.as_str() } else { "(none yet)" }
    );
    if let Some(t) = saved.tag_subtitle() {
        println!("{C_DIM}public_tag{C_RESET}  {t}");
    }
    if !saved.lan_dial.is_empty() {
        println!(
            "{C_DIM}lan_dial{C_RESET}    {}",
            sanitize_terminal_line(&saved.lan_dial)
        );
    }
    println!("{C_DIM}fingerprint{C_RESET} {fp}");
    println!(
        "{C_DIM}pinned{C_RESET}      {}",
        if pin || prior_pinned {
            "yes (Tag+key locked locally)"
        } else {
            "no — not verified yet (compare the fingerprint with them by phone or in person, then add them again with --verify-fp)"
        }
    );
    let who = if named { label.as_str() } else { "them" };
    println!(
        "{C_BOLD}Next:{C_RESET} ask {who} to add YOU too: send them your invite (`ash whoami`). Messages only work once BOTH of you have added each other."
    );
    println!("{C_DIM}(stored on this computer only — no FastAPI / no registrar){C_RESET}");
    Ok(())
}

/// Only the guided add shows this: the flag path is scripts and experts.
fn print_iphone_note() {
    println!(
        "{C_DIM}iPhone:{C_RESET} this did NOT sync to the phone. On iPhone: Discover → Paste ash whoami → paste THIS Mac `ash whoami` (address + pub_hex)."
    );
    println!(
        "{C_DIM}آیفون:{C_RESET} مخاطب فقط روی مک ذخیره شد. روی گوشی: Discover → Paste ash whoami → whoami همین مک را بچسبانید."
    );
}

/// Is this key the profile's own? (Pasting your own whoami instead of the
/// friend's is a common slip.)
fn is_own_pub_hex(data_dir: &Path, pub_hex: &str) -> bool {
    matches!(
        try_load_identity(data_dir),
        Ok(Some(id)) if hex::encode(id.public_key_bytes()).eq_ignore_ascii_case(pub_hex.trim())
    )
}

const OWN_INVITE_REFUSAL: &str =
    "That is YOUR OWN invite. Paste your friend's `ash whoami` (or their invite line), not yours.";

/// A name makes the contact easy to pick later. Terminal only: a piped script's
/// next line is its answer to the NEXT prompt, so nothing is asked there.
fn ask_petname_again(petname: String) -> String {
    if !petname.trim().is_empty() || !stdin_is_tty() {
        return petname;
    }
    println!(
        "{C_DIM}A name helps you find them later, e.g. Alice. Press Enter again to skip.{C_RESET}"
    );
    print!("Petname: ");
    let _ = io::stdout().flush();
    read_answer_line()
}

fn cmd_contact_list(data_dir: &Path) -> Result<(), String> {
    let c = c();
    let contacts = load_contacts(data_dir)?;
    println!();
    println!("{}CONTACTS \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}", c.bold, c.reset);
    println!(
        "  {d}{count} saved{r}",
        d = c.dim,
        count = contacts.len(),
        r = c.reset
    );

    if contacts.is_empty() {
        println!();
        println!("{0}No contacts yet.{1}", c.dim, c.reset);
        println!(
            "  {0}rvn1… address  = durable identity (from QR / whoami){1}",
            c.dim, c.reset
        );
        println!(
            "  {0}@alias         = public Soft Unique tag{1}",
            c.dim, c.reset
        );
        println!(
            "  {0}petname        = your private label (e.g. \"Poline\"){1}",
            c.dim, c.reset
        );
        println!(
            "  {0}verify the fingerprint out-of-band before pinning{1}",
            c.dim, c.reset
        );
        return Ok(());
    }

    // Dynamic column widths from data (alignment is readability).
    let w_name = contacts
        .iter()
        .map(|x| x.primary_label().chars().count())
        .max()
        .unwrap_or(4)
        .max(7);
    let w_tag = contacts
        .iter()
        .map(|x| x.tag_subtitle().map(|t| t.chars().count()).unwrap_or(2))
        .max()
        .unwrap_or(5)
        .max(5);

    println!();
    for (i, ct) in contacts.iter().enumerate() {
        let name = ct.primary_label();
        let tag = ct.tag_subtitle().unwrap_or_else(|| "—".into());
        let pin = if ct.pinned {
            format!("{0}✓ pinned{1}", c.bold, c.reset)
        } else {
            format!("{0}○ unpinned{1}", c.dim, c.reset)
        };
        let fp = contact_fingerprint(ct);
        let dial = if ct.lan_dial.is_empty() {
            String::new()
        } else {
            format!(
                "  {0}→ {1}{2}",
                c.dim,
                sanitize_terminal_line(&ct.lan_dial),
                c.reset
            )
        };

        println!(
            "  {i}. {name:<nw$}  {tag:<tw$}  {pin}{dial}",
            i = i + 1,
            name = name,
            nw = w_name,
            tag = tag,
            tw = w_tag
        );
        println!("     {d}fp {fp}{r}", d = c.dim, r = c.reset, fp = fp);
    }
    Ok(())
}

/// Menu callers: show why a command failed and stay in the menu.
fn show_menu_error(result: Result<(), String>) {
    if let Err(e) = result {
        eprintln!("{}", sanitize_terminal_line(&e));
    }
}

/// CLI callers: the reason goes to stderr and the process exits 1.
fn exit_on_err(result: Result<(), String>) {
    if let Err(e) = result {
        eprintln!("{}", sanitize_terminal_line(&e));
        std::process::exit(1);
    }
}

fn resolve_alias_claims_for_add(data_dir: &Path, alias: &str) -> Vec<AliasRecord> {
    let now = now_ms();
    let store = load_alias_store(data_dir, now);
    store.lookup_exact(alias, now).unwrap_or_default()
}

/// Interactive contact add — teaches Soft Unique Tags; never prints private keys.
fn cmd_contacts(data_dir: &Path) {
    let s = style();
    let bold = s.bold;
    let dim = s.dim;
    let reset = s.reset;

    show_menu_error(cmd_contact_list(data_dir));
    println!();
    screen_header("Contacts");
    println!(
        "  {bold}a{reset}  Add contact     {dim}rvn1… or @alias + petname + fingerprint{reset}"
    );
    println!("  {bold}l{reset}  List again");
    println!("  {bold}2{reset}  Send / Chat     {dim}jump to message a contact{reset}");
    println!("  {bold}1{reset}  Messages       {dim}outgoing queue / history{reset}");
    println!("  {bold}Enter{reset}  Back to main menu");
    print!("\n{bold}contacts>{reset} ");
    let _ = io::stdout().flush();
    let choice = read_line();
    match choice.to_ascii_lowercase().as_str() {
        "a" | "add" | "y" | "yes" => cmd_contact_add_interactive(data_dir),
        "l" | "list" => show_menu_error(cmd_contact_list(data_dir)),
        "2" | "s" | "send" => {
            println!("{dim}→ Send / Chat{reset}");
            cmd_send_interactive(data_dir);
        }
        "1" | "m" | "messages" => {
            println!("{dim}→ Messages (queue/history — to compose a new DM use 2){reset}");
            cmd_messages(data_dir);
        }
        "4" | "status" => show_menu_error(cmd_status(data_dir)),
        "q" | "quit" | "exit" => {
            println!("{dim}Press Enter to leave Contacts, then type q at raven> to quit.{reset}");
        }
        "" => {}
        other => println!(
            "{dim}unknown:{reset} {} — try a / l / 2 (Send) / Enter (back)",
            sanitize_terminal_line(other)
        ),
    }
}

fn cmd_contact_add_interactive(data_dir: &Path) {
    let s = style();
    let bold = s.bold;
    let dim = s.dim;
    let reset = s.reset;

    // `contacts.json` is exactly the state the first-install check treats as an
    // established profile: no contact before the identity.
    if let Err(e) = require_identity_before_state(data_dir, "adding a contact") {
        eprintln!("{}", sanitize_terminal_line(&e));
        return;
    }

    println!();
    println!("{bold}Add contact{reset} {dim}(public bits only — never paste a seed){reset}");
    println!(
        "{dim}Soft Unique Tags: @alias is NOT globally unique. Always check fingerprint.{reset}"
    );
    println!(
        "{dim}Tip: paste their whole `ash whoami` block, or just the rvn1… line + pub_hex.{reset}"
    );
    println!(
        "{bold}iPhone:{reset} {dim}Account → Serverless LAN → copy address + pub hex (NOT Terminal cargo / cd).{reset}"
    );
    println!();
    print!("Enter Raven address (rvn1…) / @alias / paste whoami: ");
    let _ = io::stdout().flush();
    let who = read_paste_blob();
    if who.trim().is_empty() {
        println!("{dim}cancelled.{reset}");
        return;
    }
    if looks_like_shell_input(&who) {
        eprintln!("{}", shell_paste_rejection());
        eprintln!(
            "{dim}To add an iPhone: on the phone open Account → Serverless LAN, copy rvn1… + pub hex, paste HERE — not `cargo` / `cd`.{reset}"
        );
        return;
    }

    let address;
    let pub_hex;
    let tag;

    let trimmed = who.trim();

    // One-text invite: paste `raven:addr:pubhex` to skip manual entry. Goes
    // through add_contact (merge into the book, address/key binding, key-change
    // and tag checks) — never a separate write path.
    if let Some(parsed) = parse_raven_invite(trimmed) {
        let invite = match parsed {
            Ok(invite) => invite,
            Err(e) => {
                eprintln!("rejected: {}", sanitize_terminal_line(&e));
                return;
            }
        };
        if is_own_pub_hex(data_dir, &invite.pub_hex) {
            eprintln!("{OWN_INVITE_REFUSAL}");
            return;
        }
        println!(
            "{C_GREEN}\u{2713} invite parsed{C_RESET} \u{2014} {}",
            sanitize_terminal_line(&invite.address)
        );
        print!("Optional petname (e.g. \"Alice\" — local label): ");
        let _ = io::stdout().flush();
        let petname = ask_petname_again(read_answer_line());
        println!("{bold}Fingerprint{reset}  {}", invite.fingerprint);
        println!(
            "{dim}Compare this with your peer out-of-band (Signal call, in person, etc.).{reset}"
        );
        match prompt_verify_choice(&invite.fingerprint) {
            None => println!("{dim}cancelled — nothing saved.{reset}"),
            Some(pin) => match commit_invite_contact(data_dir, &invite, &petname, pin) {
                Ok(()) => {
                    println!(
                        "{dim}Tip: menu 1 Send / Chat → pick this contact by # or @tag (not host:port).{reset}"
                    );
                    print_iphone_note();
                }
                Err(e) => eprintln!("rejected: {}", sanitize_terminal_line(&e)),
            },
        }
        return;
    }
    // Full whoami paste: has both address + pub_hex lines.
    if let (Some(addr), Some(ph)) = (
        extract_address_field(trimmed),
        extract_pub_hex_field(trimmed),
    ) {
        address = addr;
        pub_hex = ph;
        println!(
            "{dim}Parsed whoami → {}{reset}",
            sanitize_terminal_line(&address)
        );
        print!("optional public @tag (Soft Unique, e.g. poline): ");
        let _ = io::stdout().flush();
        tag = read_answer_line();
    } else if let Some(ph) = looks_like_bare_pub_hex(trimmed) {
        // iPhone Serverless LAN "Copy pub hex" — derive rvn1; do NOT treat as @alias.
        let ed = match parse_pub_hex(&ph) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("rejected: {e}");
                return;
            }
        };
        address = encode_address(&ed);
        pub_hex = ph;
        println!(
            "{dim}Detected pub_hex → derived {}{reset}",
            sanitize_terminal_line(&address)
        );
        print!("optional public @tag (Soft Unique, e.g. poline): ");
        let _ = io::stdout().flush();
        tag = read_answer_line();
    } else if trimmed.starts_with('@') || (!trimmed.starts_with("rvn1") && !trimmed.contains(':')) {
        // Treat as @alias (Soft Unique) — look up local alias claims.
        let alias = trimmed.trim_start_matches('@');
        tag = normalize_tag(alias);
        let claims = resolve_alias_claims_for_add(data_dir, &tag);
        if claims.is_empty() {
            println!("{dim}No local alias claim for @{tag}.{reset}");
            println!(
                "{dim}Serverless: there is no global @alias directory. You need their rvn1… + pub_hex from their{reset} {bold}ash whoami{reset}{dim},{reset}"
            );
            println!(
                "{dim}or they must publish the alias first and that claim must reach you (local/peers).{reset}"
            );
            println!(
                "{dim}ash find @{tag} only helps when a claim is already available — it does not work as offline lookup.{reset}"
            );
            println!(
                "{dim}Tip: iPhone Account → Serverless LAN → Copy whoami for ash (or paste 64-char pub hex alone).{reset}"
            );
            print!("Paste rvn1… / whoami / pub_hex instead (or Enter to cancel): ");
            let _ = io::stdout().flush();
            let pasted = read_paste_blob();
            if pasted.trim().is_empty() {
                return;
            }
            if looks_like_shell_input(&pasted) {
                eprintln!("{}", shell_paste_rejection());
                return;
            }
            if let Some(ph) = looks_like_bare_pub_hex(pasted.trim()) {
                let ed = match parse_pub_hex(&ph) {
                    Ok(a) => a,
                    Err(e) => {
                        eprintln!("rejected: {e}");
                        return;
                    }
                };
                address = encode_address(&ed);
                pub_hex = ph;
                println!(
                    "{dim}Detected pub_hex → derived {}{reset}",
                    sanitize_terminal_line(&address)
                );
            } else {
                address =
                    extract_address_field(&pasted).unwrap_or_else(|| pasted.trim().to_string());
                if let Some(ph) = extract_pub_hex_field(&pasted) {
                    pub_hex = ph;
                } else {
                    print!("pub_hex (64 chars, public only): ");
                    let _ = io::stdout().flush();
                    pub_hex = read_pub_hex_answer();
                }
            }
        } else if claims.len() == 1 {
            let c = &claims[0];
            address = c.identity_address.clone();
            pub_hex = hex::encode(c.ed25519_pub);
            println!(
                "{dim}Resolved @{tag} → {}{reset}",
                sanitize_terminal_line(&address)
            );
        } else {
            println!(
                "{bold}alias conflict{reset}: {} candidates — pick one (never silent)",
                claims.len()
            );
            for (i, c) in claims.iter().enumerate() {
                let fp = device_fingerprint_v1(&c.ed25519_pub);
                println!(
                    "  {bold}{}{reset}  {}  fp={}",
                    i + 1,
                    sanitize_terminal_line(&c.identity_address),
                    fp
                );
            }
            print!("pick [1-{}]: ", claims.len());
            let _ = io::stdout().flush();
            let line = read_line();
            let Ok(n) = line.trim().parse::<usize>() else {
                println!("{dim}cancelled.{reset}");
                return;
            };
            if n < 1 || n > claims.len() {
                println!("{dim}invalid pick.{reset}");
                return;
            }
            let c = &claims[n - 1];
            address = c.identity_address.clone();
            pub_hex = hex::encode(c.ed25519_pub);
        }
    } else {
        address = extract_address_field(trimmed).unwrap_or_else(|| trimmed.to_string());
        if let Some(ph) = extract_pub_hex_field(trimmed) {
            pub_hex = ph;
            println!("{dim}Parsed pub_hex from paste.{reset}");
        } else {
            print!("pub_hex (64 chars from their `ash whoami` — public only): ");
            let _ = io::stdout().flush();
            pub_hex = read_pub_hex_answer();
        }
        print!("optional public @tag (Soft Unique, e.g. poline): ");
        let _ = io::stdout().flush();
        tag = read_answer_line();
    }

    if looks_like_shell_input(&address) || looks_like_shell_input(&pub_hex) {
        eprintln!("{}", shell_paste_rejection());
        return;
    }

    print!("Optional petname (e.g. \"Poline\" — local label): ");
    let _ = io::stdout().flush();
    let petname = ask_petname_again(read_answer_line());

    print!("Optional LAN dial host:port (Enter to skip — Send auto-resolves / Mac-listens): ");
    let _ = io::stdout().flush();
    let lan_dial = read_answer_line();

    let ed = match parse_pub_hex(&pub_hex) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("rejected: {e}");
            return;
        }
    };
    if is_own_pub_hex(data_dir, &pub_hex) {
        eprintln!("{OWN_INVITE_REFUSAL}");
        return;
    }
    let fp = device_fingerprint_v1(&ed);
    println!();
    println!("{bold}Fingerprint{reset}  {fp}");
    println!("{dim}Compare this with your peer out-of-band (Signal call, in person, etc.).{reset}");
    let Some(pin) = prompt_verify_choice(&fp) else {
        println!("{dim}cancelled — nothing saved.{reset}");
        return;
    };

    if let Err(e) = add_contact(
        data_dir,
        &address,
        &pub_hex,
        &petname,
        &tag,
        pin.then_some(fp.as_str()),
        &lan_dial,
    ) {
        eprintln!("rejected: {}", sanitize_terminal_line(&e));
    } else {
        println!(
            "{dim}Tip: menu 1 Send / Chat → pick this contact by # or @tag (not host:port).{reset}"
        );
        print_iphone_note();
    }
}

fn cmd_contact_resolve(data_dir: &Path, tag: &str) -> Result<(), String> {
    let contacts = load_contacts(data_dir)?;
    let hits = resolve_tag_contacts(&contacts, tag);
    if hits.is_empty() {
        eprintln!("{C_DIM}no \"is tag taken?\" API — add via QR/OOB only{C_RESET}");
        return Err(format!("no local contacts for @{}", normalize_tag(tag)));
    }
    if hits.len() == 1 {
        let c = hits[0];
        println!("{C_GREEN}resolved{C_RESET} {}", c.primary_label());
        if let Some(t) = c.tag_subtitle() {
            println!("{C_DIM}public_tag{C_RESET}  {t}");
        }
        println!("{C_DIM}fingerprint{C_RESET} {}", contact_fingerprint(c));
        println!(
            "{C_DIM}pinned{C_RESET}      {}",
            if c.pinned { "yes" } else { "no" }
        );
        return Ok(());
    }
    println!(
        "{C_PURPLE}ambiguity picker{C_RESET}: {} claims for @{} — never silent pick",
        hits.len(),
        normalize_tag(tag)
    );
    for (i, c) in hits.iter().enumerate() {
        println!(
            "  {C_CYAN}{}{C_RESET}  {}  {}  fp={}{}",
            i + 1,
            c.primary_label(),
            c.tag_subtitle().unwrap_or_default(),
            contact_fingerprint(c),
            if c.pinned { " [pinned]" } else { "" }
        );
    }
    println!("{C_DIM}Pick a # and use that petname in send — or re-add with a distinct petname.{C_RESET}");
    Ok(())
}

/// Contacts picked by `--tag`, `--petname` or `--address` (first one given
/// wins). `None` = no selector at all. An empty selector matches nothing.
fn find_contacts<'a>(
    contacts: &'a [Contact],
    tag: Option<&str>,
    petname: Option<&str>,
    address: Option<&str>,
) -> Option<Vec<&'a Contact>> {
    if let Some(t) = tag {
        Some(resolve_tag_contacts(contacts, t))
    } else if let Some(p) = petname {
        let want = sanitize_terminal_line(p.trim());
        Some(if want.is_empty() {
            Vec::new()
        } else {
            contacts
                .iter()
                .filter(|c| c.petname.eq_ignore_ascii_case(&want))
                .collect()
        })
    } else {
        address.map(|addr| {
            let addr = raven_core::address::from_display(addr.trim());
            contacts.iter().filter(|c| c.address == addr).collect()
        })
    }
}

fn cmd_contact_verify(
    data_dir: &Path,
    tag: Option<&str>,
    alias: Option<&str>,
    petname: Option<&str>,
    address: Option<&str>,
) -> Result<(), String> {
    let contacts = load_contacts(data_dir)?;
    let matches = find_contacts(&contacts, tag.or(alias), petname, address)
        .ok_or("need --tag, --petname, or --address")?;
    if matches.is_empty() {
        return Err("no contact matched".into());
    }
    if matches.len() > 1 {
        println!(
            "{C_PURPLE}ambiguity{C_RESET}: {} matches — compare fingerprints",
            matches.len()
        );
    }
    for c in matches {
        println!("{C_DIM}petname{C_RESET}     {}", c.primary_label());
        if let Some(t) = c.tag_subtitle() {
            println!("{C_DIM}public_tag{C_RESET}  {t}");
        }
        println!(
            "{C_DIM}address{C_RESET}     {}",
            sanitize_terminal_line(&c.address)
        );
        println!("{C_DIM}fingerprint{C_RESET} {}", contact_fingerprint(c));
        println!(
            "{C_DIM}pinned{C_RESET}      {}",
            if c.pinned { "yes" } else { "no" }
        );
    }
    Ok(())
}

/// The one contact a `--tag/--petname/--address` selector names; several or
/// none is an error (never a silent pick).
fn select_one_contact(
    contacts: &[Contact],
    tag: Option<&str>,
    petname: Option<&str>,
    address: Option<&str>,
) -> Result<Contact, String> {
    let matches = find_contacts(contacts, tag, petname, address)
        .ok_or("need --tag, --petname, or --address")?;
    match matches.as_slice() {
        [] => Err("no contact matched".into()),
        [one] => Ok((*one).clone()),
        many => Err(format!(
            "{} contacts match — narrow it with --address (see `ash contact list`)",
            many.len()
        )),
    }
}

/// Typed confirmation for a removal: Enter, EOF and anything else cancel, and
/// a non-terminal stdin cannot confirm at all (scripts pass `--yes`).
fn confirm_contact_removal() -> bool {
    if !stdin_is_tty() {
        eprintln!("stdin is not a terminal: pass --yes to remove without the prompt");
        return false;
    }
    print!("Type \"remove\" to delete this contact and its pin (Enter cancels): ");
    let _ = io::stdout().flush();
    matches!(read_decision_line(), Some(t) if t.eq_ignore_ascii_case("remove"))
}

/// `ash contact remove`: the deliberate, local-only way to drop a contact or a
/// pin (e.g. before re-pinning a peer's new key). Never reachable from the
/// network, discovery or invite paths.
fn cmd_contact_remove(
    data_dir: &Path,
    tag: Option<&str>,
    petname: Option<&str>,
    address: Option<&str>,
    yes: bool,
) -> Result<(), String> {
    let mut contacts = load_contacts(data_dir)?;
    let target = select_one_contact(&contacts, tag, petname, address)?;
    println!("{C_DIM}contact{C_RESET}     {}", target.primary_label());
    println!(
        "{C_DIM}address{C_RESET}     {}",
        sanitize_terminal_line(&target.address)
    );
    println!(
        "{C_DIM}fingerprint{C_RESET} {}",
        contact_fingerprint(&target)
    );
    println!(
        "{C_DIM}pinned{C_RESET}      {}",
        if target.pinned { "yes" } else { "no" }
    );
    if !yes && !confirm_contact_removal() {
        return Err("cancelled — nothing removed".into());
    }
    contacts.retain(|c| !c.pub_hex.eq_ignore_ascii_case(&target.pub_hex));
    save_contacts(data_dir, &contacts)?;
    println!("{C_GREEN}removed{C_RESET} {}", target.primary_label());
    // Removing a contact is the explicit re-pin: also forget the prekey pinned
    // for it, so a contact that reinstalled (and is refused as PEER_PREKEY_RESET
    // until its old pinned prekey expires) is pinned afresh when added again. A
    // failure here never undoes the removal.
    if let Ok(ed) = parse_pub_hex(&target.pub_hex) {
        match raven_core::lan_dispatch::forget_peer_prekey_pin(data_dir, &ed) {
            Ok(true) => println!(
                "{C_DIM}also forgot the prekey pinned for this contact; the next offer it makes is pinned afresh{C_RESET}"
            ),
            Ok(false) => {}
            Err(e) => eprintln!(
                "{C_DIM}note: could not clear the pinned prekey ({}){C_RESET}",
                sanitize_terminal_line(&e)
            ),
        }
    }
    Ok(())
}

/// `ash contact unblock`: undo a block (contact-request or chat `/block`).
fn cmd_contact_unblock(data_dir: &Path, pub_hex: &str) -> Result<(), String> {
    let ed = parse_pub_hex(pub_hex)?;
    let ed_hex = hex::encode(ed);
    let mut blocks = BlockList::load_checked(data_dir).map_err(|e| format!("block list: {e}"))?;
    if !blocks.is_blocked(&ed_hex) {
        return Err(format!(
            "that key is not on the block list (fingerprint {})",
            device_fingerprint_v1(&ed)
        ));
    }
    blocks.unblock(&ed_hex);
    blocks.save(data_dir)?;
    println!(
        "{C_GREEN}unblocked{C_RESET} fingerprint {}",
        device_fingerprint_v1(&ed)
    );
    Ok(())
}

/// `ash contact set-dial`: refresh one contact's saved LAN dial in place
/// (petname, tag and pin are untouched).
fn cmd_contact_set_dial(
    data_dir: &Path,
    tag: Option<&str>,
    petname: Option<&str>,
    address: Option<&str>,
    lan_dial: &str,
) -> Result<(), String> {
    let contacts = load_contacts(data_dir)?;
    let target = select_one_contact(&contacts, tag, petname, address)?;
    update_contact_lan_dial(data_dir, &target.pub_hex, lan_dial)?;
    println!(
        "{C_GREEN}lan_dial updated{C_RESET} {} → {}",
        target.primary_label(),
        sanitize_terminal_line(lan_dial.trim())
    );
    Ok(())
}

fn cmd_prekey_publish(data_dir: &Path, device_id: &str, out: Option<&Path>) {
    let id = require_identity(data_dir);
    if let Err(e) = ext::cmd_prekey_publish_real(data_dir, &id, device_id, out) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

/// Every failure is an `Err` (the caller exits 1): `ash lab import-peer-prekey
/// … && ash send …` must not carry on after an expired or mismatched bundle.
fn cmd_prekey_fetch(data_dir: &Path, pub_hex: &str, file: Option<&Path>) -> Result<(), String> {
    let ed = parse_pub_hex(pub_hex)?;
    let now = now_ms();
    let bundle = if let Some(path) = file {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read: {e}"))?;
        let j = serde_json::from_str::<PrekeyBundleJson>(&raw).map_err(|e| format!("json: {e}"))?;
        PrekeyBundle::from_json(&j).map_err(|e| format!("bundle parse: {e}"))?
    } else {
        match PrekeyStore::load_checked(data_dir).and_then(|s| s.fetch(&ed, now)) {
            Ok(Some(b)) => b,
            Ok(None) => {
                return Err("no bundle in local store for that pub (try --file OOB json)".into())
            }
            Err(e) => return Err(format!("fetch/verify failed: {e}")),
        }
    };
    bundle
        .verify(now)
        .map_err(|e| format!("verify failed: {e}"))?;
    if bundle.identity_ed25519_pub != ed {
        return Err("PREKEY_IDENTITY_MISMATCH".into());
    }
    // Persist into local untrusted store so PairInit / lab send can fetch.
    raven_core::publish_prekey_bundle_checked(data_dir, &bundle, now)
        .map_err(|e| format!("store publish: {e}"))?;
    println!("{C_GREEN}prekey ok{C_RESET} (cached in prekey_store.json)");
    println!(
        "{C_DIM}fingerprint{C_RESET} {}",
        device_fingerprint_v1(&bundle.identity_ed25519_pub)
    );
    println!(
        "{C_DIM}device_id{C_RESET}   {}",
        sanitize_terminal_line(&bundle.device_id)
    );
    println!("{C_DIM}prekey_id{C_RESET}   {}", bundle.signed_prekey_id);
    println!("{C_DIM}expires_ms{C_RESET}  {}", bundle.expires_at_ms);
    Ok(())
}

fn print_messaging_path_diag() -> Result<(), String> {
    let path = resolve_terminal_messaging_path();
    match assert_no_silent_fastapi(path) {
        Ok(()) => {
            kv(
                "messaging",
                &format!("{} ({})", path.as_diag_label(), path.human()),
            );
            kv(
                "path_rule",
                &format!(
                    "never silently uses FastAPI ({})",
                    MessagingPath::LegacyFastApi.as_diag_label()
                ),
            );
            Ok(())
        }
        Err(e) => {
            println!("  FAIL: messaging_path {}", sanitize_terminal_line(&e));
            Err(e)
        }
    }
}

const M3_LAN_DIAL_SEALED_BANNER: &str = "NON-RELEASE / HOLD active. already-sealed LanDial only. Not O6 E2E Proven. No HOLD lift. dial≠WAN. Soft-load P0 held.";

fn cmd_lab_lan_dial_sealed(
    data_dir: &Path,
    dial: &str,
    expected_pub_hex: &str,
    envelope_b64: &str,
) {
    eprintln!("{M3_LAN_DIAL_SEALED_BANNER}");
    if !raven_core::pair_init::lab_test_a_enabled() {
        eprintln!("O6_M3_LAN_DIAL_SEALED=RED");
        eprintln!("reason=RAVEN_LAB_TEST_A required (debug lab only; not a production path)");
        eprintln!("HOLD=ACTIVE");
        std::process::exit(1);
    }
    let envelope = match pair_init_lab::decode_already_sealed_envelope_b64(envelope_b64) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("O6_M3_LAN_DIAL_SEALED=RED");
            eprintln!("{}", sanitize_terminal_line(&e));
            eprintln!("HOLD=ACTIVE");
            std::process::exit(1);
        }
    };
    match pair_init_lab::lan_dial_already_sealed(data_dir, dial, expected_pub_hex, &envelope) {
        Ok(replies) => {
            println!("O6_M3_LAN_DIAL_SEALED=OK replies={}", replies.len());
            println!("HOLD=ACTIVE");
            println!("LABEL=NON-RELEASE");
            println!("CLAIM=lab localhost already-sealed LanDial under HOLD");
            println!("NOT_PROVEN=O6 E2E; HOLD lift; WAN; confidential RDAP delivery");
        }
        Err(e) => {
            eprintln!("O6_M3_LAN_DIAL_SEALED=RED");
            eprintln!("{}", sanitize_terminal_line(&e));
            eprintln!("HOLD=ACTIVE");
            std::process::exit(1);
        }
    }
}

fn print_production_gate_matrix() {
    let on = |b: bool| {
        if b {
            format!("{C_GREEN}true{C_RESET}")
        } else {
            format!("{C_DIM}false{C_RESET}")
        }
    };
    println!("{C_BOLD}production gates (Test A PairInit path){C_RESET}");
    println!(
        "  {C_DIM}pair_init::PRODUCTION_ENABLED{C_RESET}              {}",
        on(raven_core::pair_init::PRODUCTION_ENABLED)
    );
    println!(
        "  {C_DIM}pair_init::live_enabled{C_RESET}                   {}",
        on(raven_core::pair_init::live_enabled())
    );
    println!(
        "  {C_DIM}RAVEN_LAB_TEST_A{C_RESET}                           {}",
        on(raven_core::pair_init::lab_test_a_enabled())
    );
    println!(
        "  {C_DIM}atsam_indexed_session::PRODUCTION_ENABLED{C_RESET}  {}",
        on(raven_core::atsam_indexed_session::PRODUCTION_ENABLED)
    );
    println!(
        "  {C_DIM}INDEXED_SESSION_STORE_PRODUCTION_ENABLED{C_RESET}   {}",
        on(raven_core::INDEXED_SESSION_STORE_PRODUCTION_ENABLED)
    );
    println!(
        "  {C_DIM}PREKEY_LIFECYCLE_PRODUCTION_ENABLED{C_RESET}        {}",
        on(raven_core::PREKEY_LIFECYCLE_PRODUCTION_ENABLED)
    );
    println!(
        "  {C_DIM}LAN_DIRECT_PRODUCTION_ENABLED{C_RESET}             {}",
        on(raven_core::LAN_DIRECT_PRODUCTION_ENABLED)
    );
    println!(
        "  {C_DIM}lan_direct_live_enabled{C_RESET}                   {}",
        on(raven_core::lan_direct_live_enabled())
    );
    println!(
        "  {C_DIM}INTERNET_DIRECT_PRODUCTION_ENABLED{C_RESET}        {}",
        on(raven_core::INTERNET_DIRECT_PRODUCTION_ENABLED)
    );
    println!(
        "  {C_DIM}internet_direct_live_enabled{C_RESET}              {}",
        on(raven_core::internet_direct_live_enabled())
    );
    println!(
        "  {C_DIM}unsafe-demo-crypto feature{C_RESET}                {}",
        on(cfg!(feature = "unsafe-demo-crypto"))
    );
    println!(
        "  {C_DIM}contact_session_transport_ready{C_RESET}           {}",
        on(contact_session_transport_ready())
    );
    println!(
        "  {C_DIM}live_outbound_status{C_RESET}                      {}",
        trace_delivery::production_gate_status()
    );
    println!(
        "{C_DIM}note{C_RESET}: Lab unlock = debug build + RAVEN_LAB_TEST_A=1 (Release stays fail-closed)."
    );
    println!(
        "{C_DIM}note{C_RESET}: LAN PairInit rides RVN1 OOB wrap (RVPI1/RVPR1 as message ciphertext)."
    );
}

/// Whether this computer can send and receive, as the local raven-node itself
/// says it (its IPC `Status` lists `lan_direct` only while the LAN listener is
/// really bound). Policy files say what the node WOULD do; this is what it does.
#[derive(Debug, Clone, PartialEq, Eq)]
enum NodeReach {
    /// Running, LAN listener up.
    SendAndReceive,
    /// Running, LAN listener down (busy port, or started outbound-only).
    SendOnly,
    /// No node for this profile.
    NotRunning,
    /// Something owns the endpoint but does not answer sensibly.
    NotAnswering,
}

fn classify_node_reach(status: &Result<IpcResponse, String>) -> NodeReach {
    match status {
        Ok(IpcResponse::Status { capabilities, .. }) => {
            if capabilities.iter().any(|c| c == "lan_direct") {
                NodeReach::SendAndReceive
            } else {
                NodeReach::SendOnly
            }
        }
        Err(e) if ipc_client::error_means_not_running(e) => NodeReach::NotRunning,
        _ => NodeReach::NotAnswering,
    }
}

/// Value of the `receiving` row of `ash status`.
fn node_reach_row(reach: &NodeReach) -> String {
    match reach {
        NodeReach::SendAndReceive => {
            "YES \u{2014} the LAN listener is up (friends on your network can send to you)".into()
        }
        NodeReach::SendOnly => "NO \u{2014} raven-node runs but its LAN listener is down (busy port, or started \
             outbound-only); see raven-node-service.log in your Raven folder"
            .into(),
        NodeReach::NotRunning => {
            "NO \u{2014} raven-node is not running (it starts when you send; to receive run `ash listen`)"
                .into()
        }
        NodeReach::NotAnswering => {
            "NO \u{2014} raven-node is running but does not answer; run `ash doctor`".into()
        }
    }
}

/// The one-line verdict `ash status` ends with.
fn node_reach_verdict(reach: &NodeReach) -> String {
    match reach {
        NodeReach::SendAndReceive => "You can send and receive.".into(),
        NodeReach::SendOnly => "You can send but NOT receive: this computer's LAN listener is \
             down (busy port?). See raven-node-service.log in your Raven folder, or run `ash doctor`."
            .into(),
        NodeReach::NotRunning => "raven-node is not running: start it with `ash listen` (it also \
             starts by itself when you send a message)."
            .into(),
        NodeReach::NotAnswering => {
            "raven-node is running but does not answer: run `ash doctor` for details.".into()
        }
    }
}

fn cmd_status(data_dir: &Path) -> Result<(), String> {
    let c = c();
    println!();
    println!("{}STATUS \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}", c.bold, c.reset);

    kv("profile", &data_dir.display().to_string());
    print_messaging_path_diag()?;

    match try_load_identity(data_dir) {
        Ok(Some(id)) => {
            println!();
            println!("{}IDENTITY \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}", c.bold, c.reset);
            println!(
                "  {0}\u{25cf}{1} ready {2}(public bits only \u{2014} never a seed){3}",
                c.green, c.reset, c.dim, c.reset
            );
            print_public_identity(&id);
        }
        Ok(None) => println!(
            "\n{0}\u{25cb} identity missing{1} \u{2014} run {2}ash init{3}",
            c.dim, c.reset, c.bold, c.reset
        ),
        Err(e) => {
            return Err(format!(
                "identity store unavailable: {}",
                sanitize_terminal_line(&e)
            ));
        }
    }

    // A corrupt book must not abort the whole session (the menu calls this):
    // report it in place, keep rendering, and fail the command at the end.
    let contacts_err = match load_contacts(data_dir) {
        Ok(contacts) => {
            println!();
            println!("{}CONTACTS \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}", c.bold, c.reset);
            kv("count", &contacts.len().to_string());
            None
        }
        Err(e) => {
            println!();
            println!("{}CONTACTS \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}", c.bold, c.reset);
            kv("count", "unavailable (see error below)");
            Some(sanitize_terminal_line(&e))
        }
    };

    let policy = load_policy(data_dir);
    let queue = forward_queue_view(&data_dir.join("forward_queue.sqlite"));
    // What the node would do (node_policy.json) vs what is actually running:
    // only the daemon's own IPC Status says the latter.
    let daemon = ipc_client::ipc_request_timeout(
        data_dir,
        &IpcRequest::Status { v: IPC_VERSION },
        Duration::from_secs(2),
    );

    println!();
    println!("{}BRIDGE \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}", c.bold, c.reset);
    kv(
        "configured",
        "node_policy.json (what raven-node will do when running)",
    );
    kv("bridge", ok(policy.bridge));
    kv("store", ok(policy.store));
    kv("relay", ok(policy.relay));
    kv("endpoint", ok(policy.endpoint));
    kv("policy", if policy.auto_policy { "AUTO" } else { "manual" });
    match &daemon {
        Ok(IpcResponse::Status {
            capabilities,
            forward_pending,
            ..
        }) => {
            kv("daemon", "running (answers IPC)");
            kv("caps", &capabilities.join(", "));
            kv("fwd_pending", &forward_pending.to_string());
        }
        Ok(_) => kv("daemon", "unexpected IPC response"),
        Err(e) if ipc_client::error_means_not_running(e) => kv(
            "daemon",
            "not running — policy only, nothing is relaying (it starts when you send; or run `ash listen`)",
        ),
        Err(e) => kv(
            "daemon",
            &format!(
                "not running or not answering — policy only, nothing is relaying ({})",
                sanitize_terminal_line(e)
            ),
        ),
    }
    let reach = classify_node_reach(&daemon);
    kv("receiving", &node_reach_row(&reach));
    kv("forward_q", &forward_queue_line(&queue));

    let qpath = data_dir.join("queue.db");
    let qpath2 = data_dir.join("queue.sqlite");
    let out_q = if qpath.exists() {
        Some(qpath)
    } else if qpath2.exists() {
        Some(qpath2)
    } else {
        None
    };
    if let Some(qp) = out_q {
        println!("outbox file: {}", qp.display());
    }

    println!();
    println!("{}{}{}", c.bold, node_reach_verdict(&reach), c.reset);

    contacts_err.map_or(Ok(()), Err)
}

/// What `ash status` can say about the store-and-forward queue file. A queue
/// that exists but cannot be opened or counted is NOT "0 pending".
#[derive(Debug, PartialEq, Eq)]
enum ForwardQueueView {
    Absent,
    Counts { pending: usize, total: usize },
    Unavailable(String),
}

fn forward_queue_view(path: &Path) -> ForwardQueueView {
    match path.try_exists() {
        Ok(false) => return ForwardQueueView::Absent,
        Ok(true) => {}
        Err(e) => return ForwardQueueView::Unavailable(format!("stat failed: {e}")),
    }
    let q = match ForwardQueue::open(path) {
        Ok(q) => q,
        Err(e) => return ForwardQueueView::Unavailable(format!("open failed: {e}")),
    };
    match (q.count_pending(), q.count_all()) {
        (Ok(pending), Ok(total)) => ForwardQueueView::Counts { pending, total },
        (Err(e), _) | (_, Err(e)) => ForwardQueueView::Unavailable(format!("count failed: {e}")),
    }
}

fn forward_queue_line(view: &ForwardQueueView) -> String {
    match view {
        ForwardQueueView::Absent => "no queue file yet (0 pending / 0 total)".into(),
        ForwardQueueView::Counts { pending, total } => {
            format!("{pending} pending / {total} total")
        }
        ForwardQueueView::Unavailable(why) => {
            format!(
                "unavailable ({}) — pending items unknown",
                sanitize_terminal_line(why)
            )
        }
    }
}

fn set_node_flag(data_dir: &Path, which: &str, on: bool) {
    // An unreadable node_policy.json falls back to the fail-closed policy.
    // Saving it would silently turn every flag the user did NOT name OFF, so
    // that case is reported loudly (the save still repairs the file).
    let (mut policy, unreadable) = match try_load_policy(data_dir) {
        Ok(policy) => (policy, None),
        Err(e) => (NodePolicy::fail_closed(), Some(e.to_string())),
    };
    policy.auto_policy = false;
    match which {
        "bridge" => policy.bridge = on,
        "store" => policy.store = on,
        "relay" => policy.relay = on,
        _ => {
            eprintln!("unknown flag {which}");
            return;
        }
    }
    if let Err(e) = save_policy(data_dir, &policy) {
        eprintln!("save policy failed: {e}");
        std::process::exit(1);
    }
    if let Some(why) = unreadable {
        eprintln!(
            "warning: node_policy.json was unreadable ({}); rewrote it from the fail-closed \
             policy, so the flags you did not set are now OFF",
            sanitize_terminal_line(&why)
        );
    }
    println!(
        "{C_GREEN}ok{C_RESET} {which}={} (raven-node reloads from {})",
        if on { "on" } else { "off" },
        data_dir.join("node_policy.json").display()
    );
    println!(
        "{C_DIM}policy{C_RESET}  bridge={} store={} relay={}",
        ok(policy.bridge),
        ok(policy.store),
        ok(policy.relay)
    );
}

/// Guided Send / Chat. Every lane — picked contact or advanced host:port —
/// goes through the same authenticated PairInit + indexed-session LAN-direct
/// path as `ash send --contact/--peer` ([`menu_send_secure`]).
fn cmd_send_interactive(data_dir: &Path) {
    let c = c();
    let id = match try_load_identity(data_dir) {
        Ok(Some(id)) => id,
        Ok(None) => {
            println!("{0}No identity yet.{1}", c.bold, c.reset);
            println!(
                "{0}Run {1}ash init{0} first (or restart the menu and accept the offer).{2}",
                c.dim, c.bold, c.reset
            );
            return;
        }
        Err(e) => {
            eprintln!("identity store unavailable: {}", sanitize_terminal_line(&e));
            return;
        }
    };
    let contacts = match load_contacts(data_dir) {
        Ok(contacts) => contacts,
        Err(e) => {
            eprintln!("{}", sanitize_terminal_line(&e));
            return;
        }
    };

    if contacts.is_empty() {
        screen_header("Send");
        println!(
            "{0}no pinned contacts — add one to get started{1}",
            c.dim, c.reset
        );
        println!();
        println!(
            "  {0}1.{1} Add someone first: menu {0}5 Contacts{2}",
            c.bold, c.reset, c.reset
        );
        println!("     (rvn1… address + pub_hex from their `ash whoami`, or @alias)");
        println!(
            "  {0}2.{1} Advanced: direct peer host:port (LAN demo / power users)",
            c.bold, c.reset
        );
        println!();
        print!("Add a contact now? [Y/n/advanced]: ");
        let _ = io::stdout().flush();
        let ans = read_line();
        let a = ans.trim().to_ascii_lowercase();
        if a.is_empty() || a == "y" || a == "yes" {
            cmd_contact_add_interactive(data_dir);
            return;
        }
        if a != "advanced" && a != "a" && a != "n" && a != "no" {
            println!(
                "{0}cancelled — use menu 5 to add a contact.{1}",
                c.dim, c.reset
            );
            return;
        }
        if a == "n" || a == "no" {
            println!(
                "{0}Add a contact first (menu 5), then try Send / Chat again.{1}",
                c.dim, c.reset
            );
            return;
        }
        if let Some((peer, pub_hex, text)) = direct_peer_prompts() {
            report_menu_send(menu_send_secure(data_dir, &id, &peer, &pub_hex, &text));
        }
        return;
    }

    // ── Contact picker ──
    screen_header("Send");
    println!(
        "{0}Pick a contact by number, @tag or petname. Direct host:port is advanced only.{1}",
        c.dim, c.reset
    );
    println!(
        "{0}This sends one message. For a live chat: ash send --contact NAME --chat{1}",
        c.dim, c.reset
    );
    for (i, ct) in contacts.iter().enumerate() {
        let sub = ct
            .tag_subtitle()
            .map(|t| format!("  {0}{t}{1}", c.dim, c.reset))
            .unwrap_or_default();
        let dial = if ct.lan_dial.is_empty() {
            format!("  {0}(no LAN dial yet){1}", c.dim, c.reset)
        } else {
            format!(
                "  {0}→ {1}{2}",
                c.dim,
                sanitize_terminal_line(&ct.lan_dial),
                c.reset
            )
        };
        println!(
            "  {n}  {label}{sub}  {d}fp={fp}{r}{dial}{pinned}",
            n = i + 1,
            label = ct.primary_label(),
            d = c.dim,
            fp = contact_fingerprint(ct),
            r = c.reset,
            pinned = if ct.pinned { " [pinned]" } else { "" }
        );
    }
    print!("contact # | @tag | petname | advanced: ");
    let _ = io::stdout().flush();
    let choice = read_line();
    let trimmed = choice.trim();

    if trimmed.eq_ignore_ascii_case("advanced") || looks_like_lan_dial(trimmed) {
        if let Some((peer, pub_hex, text)) = direct_peer_prompts() {
            report_menu_send(menu_send_secure(data_dir, &id, &peer, &pub_hex, &text));
        }
        return;
    }

    // Resolve the picked contact — never a silent first match.
    let ct = match pick_send_contact(&contacts, trimmed) {
        SendPick::One(i) => &contacts[i],
        SendPick::Ambiguous(hits) => {
            println!(
                "{0}ambiguity picker{1}: {2} contacts match — never silent pick",
                c.bold,
                c.reset,
                hits.len()
            );
            for &i in &hits {
                let ct = &contacts[i];
                println!(
                    "  {0}  {1}  {2}  fp={3}{4}",
                    i + 1,
                    ct.primary_label(),
                    ct.tag_subtitle().unwrap_or_default(),
                    contact_fingerprint(ct),
                    if ct.pinned { " [pinned]" } else { "" }
                );
            }
            print!("contact # (compare fingerprints; Enter cancels): ");
            let _ = io::stdout().flush();
            let n = read_line().trim().parse::<usize>().unwrap_or(0);
            match n.checked_sub(1).filter(|i| hits.contains(i)) {
                Some(i) => &contacts[i],
                None => {
                    println!("{0}cancelled.{1}", c.dim, c.reset);
                    return;
                }
            }
        }
        SendPick::NoMatch => {
            println!(
                "{0}unknown choice — pick a number, @tag, petname, or type advanced.{1}",
                c.dim, c.reset
            );
            return;
        }
    };

    let env = env_peer_lan_dial();
    let (peer, prompted) = match resolve_lan_peer_parts(&ct.lan_dial, env.as_deref()) {
        Some(ResolvedLanPeer::Dial(dial)) => (dial, false),
        None => {
            print_lan_unresolved_hint(&ct.primary_label());
            if !stdin_is_tty() {
                println!(
                    "{0}no LAN dial saved and stdin is not a terminal \u{2014} \
                     re-add this contact with --lan-dial host:port{1}",
                    c.yellow, c.reset
                );
                return;
            }
            let mut tries: u8 = 0;
            let hp = loop {
                tries += 1;
                if tries > 3 {
                    println!(
                        "{0}too many invalid entries \u{2014} cancelled.{1}",
                        c.dim, c.reset
                    );
                    return;
                }
                print!(
                    "{0}?{1} Type the IP:PORT shown on their Listen screen (e.g. 192.168.1.20:7420): ",
                    c.yellow, c.reset
                );
                let _ = io::stdout().flush();
                let hp = read_line();
                let t = hp.trim();
                if t.is_empty() {
                    return;
                }
                if looks_like_lan_dial(t) {
                    break t.to_string();
                }
                println!(
                    "{0}not an IP:PORT — copy the line from their Listen screen (like 192.168.1.20:7420){1}",
                    c.red,
                    c.reset
                );
            };
            (hp, true)
        }
    };

    println!(
        "{0}message for {1}:{2} ",
        c.dim,
        ct.primary_label(),
        c.reset
    );
    if stdin_is_tty() {
        println!(
            "{0}One line, up to about 1000 characters; arrow keys do not edit here (use Backspace). Longer or multi-line text: ash send --contact NAME < message.txt{1}",
            c.dim, c.reset
        );
    }
    let Some(text) = read_tty_message("> ") else {
        return;
    };
    let result = menu_send_secure(data_dir, &id, &peer, &ct.pub_hex, &text);
    if result.is_err() && !prompted {
        // A saved dial that no longer reaches the peer (new DHCP address) can
        // only be replaced explicitly: it always wins over RAVEN_PEER.
        println!(
            "{0}If {1}'s address changed: ash contact set-dial --address {2} --lan-dial host:port{3}",
            c.dim,
            ct.primary_label(),
            sanitize_terminal_line(&ct.address),
            c.reset
        );
    }
    if result.is_ok() && prompted {
        // Beginners type host:port once; it is remembered after a real delivery.
        match update_contact_lan_dial(data_dir, &ct.pub_hex, &peer) {
            Ok(()) => println!(
                "{0}Saved lan_dial on contact for next Send.{1}",
                c.dim, c.reset
            ),
            Err(e) => eprintln!("could not save dial: {}", sanitize_terminal_line(&e)),
        }
    }
    report_menu_send(result);
}

/// Send-picker resolution. Several matches are never resolved silently.
#[derive(Debug, PartialEq, Eq)]
enum SendPick {
    One(usize),
    Ambiguous(Vec<usize>),
    NoMatch,
}

/// `#` (1-based), `@tag` (Soft Unique — may match several) or petname
/// (case-insensitive; unique for new adds, legacy books may still repeat).
fn pick_send_contact(contacts: &[Contact], input: &str) -> SendPick {
    let t = input.trim();
    if t.is_empty() {
        return SendPick::NoMatch;
    }
    if let Ok(n) = t.parse::<usize>() {
        return match n.checked_sub(1).filter(|i| *i < contacts.len()) {
            Some(i) => SendPick::One(i),
            None => SendPick::NoMatch,
        };
    }
    let hits: Vec<usize> = if t.starts_with('@') {
        let want = normalize_tag(t);
        // A lone "@" normalises to "" — the tag of every untagged contact. It
        // names nobody, so it must not select one.
        if want.is_empty() {
            return SendPick::NoMatch;
        }
        contacts
            .iter()
            .enumerate()
            .filter(|(_, c)| {
                normalize_tag(&c.public_tag) == want || normalize_tag(&c.alias) == want
            })
            .map(|(i, _)| i)
            .collect()
    } else {
        let want = sanitize_terminal_line(t).to_lowercase();
        contacts
            .iter()
            .enumerate()
            .filter(|(_, c)| sanitize_terminal_line(&c.petname).to_lowercase() == want)
            .map(|(i, _)| i)
            .collect()
    };
    match hits.as_slice() {
        [] => SendPick::NoMatch,
        [one] => SendPick::One(*one),
        _ => SendPick::Ambiguous(hits),
    }
}

/// Advanced lane: host:port + pub_hex + message, validated before any dial.
fn direct_peer_prompts() -> Option<(String, String, String)> {
    let c = c();
    if !stdin_is_tty() {
        println!(
            "{0}direct peer needs interactive input \u{2014} \
             use a contact with --lan-dial, or run inside a terminal.{1}",
            c.yellow, c.reset
        );
        return None;
    }
    println!();
    println!("{0}Advanced — direct peer{1}", c.bold, c.reset);
    println!(
        "{0}Use when you already know the peer's LAN listen address + public key.{1}",
        c.dim, c.reset
    );
    print!("peer host:port: ");
    let _ = io::stdout().flush();
    let peer = read_line();
    if !looks_like_lan_dial(&peer) {
        println!("{0}not a host:port \u{2014} cancelled.{1}", c.dim, c.reset);
        return None;
    }
    print!("peer pub_hex (64 chars, public only): ");
    let _ = io::stdout().flush();
    let pub_hex = match parse_pub_hex(&read_line()) {
        Ok(k) => hex::encode(k),
        Err(e) => {
            println!(
                "{0}rejected: {1}{2}",
                c.dim,
                sanitize_terminal_line(&e),
                c.reset
            );
            return None;
        }
    };
    let text = read_tty_message("message (stdin — never argv): ")?;
    Some((peer.trim().to_string(), pub_hex, text))
}

/// Menu / bare-TTY send. Same authenticated default-build path as
/// `ash send --contact/--peer`: PairInit (RLB1 over LanDial) + indexed session
/// + sealed ACK via [`ext::run_send_secure`]. Never `--body-mode unsafe-interim`.
fn menu_send_secure(
    data_dir: &Path,
    id: &Identity,
    dial: &str,
    pub_hex: &str,
    text: &str,
) -> Result<(), String> {
    ext::run_send_secure(data_dir, id, dial, pub_hex, "127.0.0.1:0", text, "", "")
}

/// Menu sends report and return to the menu (never exit the process).
fn report_menu_send(result: Result<(), String>) {
    if let Err(e) = result {
        let c = c();
        eprintln!(
            "{0}{1}{2}",
            c.yellow,
            sanitize_terminal_line(&pair_init_lab::send_failure_line(&e)),
            c.reset
        );
    }
}

/// Dial for `c`, and whether it is NOT the saved one (it came from
/// `RAVEN_PEER` / `ASH_LAN_DIAL`). An env dial is never written into the
/// contact here: the variable is process-global, not per contact, so a stale or
/// wrong value would be stamped onto whoever was picked and then beat the right
/// one forever. Callers may save it after a delivery actually succeeded.
fn resolve_or_reuse_lan_dial(c: &Contact) -> Option<(ResolvedLanPeer, bool)> {
    resolve_or_reuse_lan_dial_with(c, env_peer_lan_dial())
}

/// [`resolve_or_reuse_lan_dial`] with the environment dial passed in (tests).
fn resolve_or_reuse_lan_dial_with(
    c: &Contact,
    env: Option<String>,
) -> Option<(ResolvedLanPeer, bool)> {
    let s = style();
    let bold = s.bold;
    let dim = s.dim;
    let reset = s.reset;

    // No service auto-start here: an unresolved dial fails below anyway, and
    // the secure send path starts the service itself (with a notice) when it
    // actually dials.
    let resolved = resolve_lan_peer_parts(&c.lan_dial, env.as_deref());

    match resolved {
        Some(ResolvedLanPeer::Dial(dial)) => {
            let saved = looks_like_lan_dial(&c.lan_dial) && c.lan_dial.trim() == dial.as_str();
            if saved {
                println!(
                    "{dim}LAN dial{reset} {bold}{}{reset} {dim}(saved · {}){reset}",
                    sanitize_terminal_line(&dial),
                    c.primary_label()
                );
                if let Some(e) = env.as_deref().filter(|e| *e != dial) {
                    println!(
                        "{dim}note: RAVEN_PEER={} is ignored — the saved dial wins. Replace it: \
                         ash contact set-dial --address {} --lan-dial host:port{reset}",
                        sanitize_terminal_line(e),
                        sanitize_terminal_line(&c.address)
                    );
                }
            } else {
                println!(
                    "{dim}LAN dial{reset} {bold}{}{reset} {dim}(env · {} · saved only after a delivery succeeds){reset}",
                    sanitize_terminal_line(&dial),
                    c.primary_label()
                );
            }
            Some((ResolvedLanPeer::Dial(dial), !saved))
        }
        None => {
            print_lan_unresolved_hint(&c.primary_label());
            None
        }
    }
}

/// Where `ash send` dials. `save_dial_after_success`: the dial came from the
/// environment, so it is written to the contact only once a delivery worked.
#[derive(Debug, PartialEq, Eq)]
struct SendTarget {
    peer: String,
    pub_hex: String,
    listen: String,
    save_dial_after_success: bool,
}

fn resolve_send_target(
    data_dir: &Path,
    contact: &str,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
) -> Result<SendTarget, String> {
    if !contact.trim().is_empty() {
        let contacts = load_contacts(data_dir)?;
        let hits = resolve_contact_arg(&contacts, contact);
        if hits.is_empty() {
            return Err(no_contact_message(&contacts, contact));
        }
        if hits.len() > 1 {
            return Err(format!(
                "contact {} is ambiguous ({} matches): use the @tag, or see `ash contact list`",
                sanitize_terminal_line(contact),
                hits.len()
            ));
        }
        let c = hits[0];
        return match resolve_or_reuse_lan_dial(c) {
            Some((ResolvedLanPeer::Dial(dial), from_env)) => Ok(SendTarget {
                peer: dial,
                pub_hex: c.pub_hex.clone(),
                listen: listen.to_string(),
                save_dial_after_success: from_env,
            }),
            None => Err(format!(
                "contact {} has no reachable lan_dial — set host:port (not LocalListenQueue)",
                c.primary_label()
            )),
        };
    }
    if peer_pub_hex.trim().is_empty() || !looks_like_lan_dial(peer) {
        return Err("send requires --contact @tag or --peer host:port plus --peer-pub-hex".into());
    }
    Ok(SendTarget {
        peer: peer.to_string(),
        pub_hex: peer_pub_hex.to_string(),
        listen: listen.to_string(),
        save_dial_after_success: false,
    })
}

/// Said when the inbox has nothing in it: the likely reasons and the profile
/// (a wrong `--data-dir` looks exactly like "nobody wrote to me").
fn inbox_empty_text(data_dir: &Path) -> String {
    format!(
        "No messages yet in {}.\n  Either nobody has written to you yet, or they have not added you as a contact, or this computer is not receiving (check: `ash status`).\n  To receive: add your friend as a contact (menu 5), then keep `ash listen` running.",
        sanitize_terminal_line(&data_dir.display().to_string())
    )
}

/// One line (stderr) when messages cannot arrive right now; `None` when they can.
fn inbox_receiver_note(state: &ext::ReceiverState) -> Option<&'static str> {
    match state {
        ext::ReceiverState::Receiving => None,
        ext::ReceiverState::NotRunning => Some(
            "Note: raven-node is not running, so nothing can arrive right now. Start it with menu 4 Listen (`ash listen`); it also starts when you send.",
        ),
        ext::ReceiverState::NotReceiving => Some(
            "Note: this computer is NOT receiving: raven-node runs but its LAN listener is down. Run `ash status`.",
        ),
        ext::ReceiverState::NotAnswering => {
            Some("Note: raven-node is running but not answering. Run `ash doctor`.")
        }
    }
}

fn print_inbox_receiver_note(data_dir: &Path) {
    // Read-only and bounded: it never starts the service.
    let state = ext::receiver_state(data_dir, Duration::from_millis(500));
    if let Some(note) = inbox_receiver_note(&state) {
        eprintln!("{C_DIM}{note}{C_RESET}");
    }
}

/// An unreadable / locked / wrong-key store is an `Err` (exit 1), never
/// confused with an empty inbox (`Ok`).
fn cmd_endpoint_inbox(data_dir: &Path) -> Result<(), String> {
    // Opening the session store creates it. Before the first identity the inbox
    // is empty by definition, and creating the store would wedge `ash init`.
    if !identity_exists_before_state(data_dir, "inbox")? {
        println!("{C_DIM}no identity yet — the inbox is empty; run `ash init` first{C_RESET}");
        return Ok(());
    }
    let mut store = raven_core::IndexedSessionStore::open(data_dir)
        .map_err(|e| format!("inbox: {}", e.redacted_display()))?;
    match store.list_endpoint_inbox() {
        Ok(rows) if rows.is_empty() => {
            println!("{C_DIM}{}{C_RESET}", inbox_empty_text(data_dir));
            println!("{C_DIM}FA: \u{200f}هنوز پیامی دریافت نشده است.{C_RESET}");
            print_inbox_receiver_note(data_dir);
            Ok(())
        }
        Ok(rows) => {
            // Attribution needs the book; a corrupt book still shows fingerprints.
            let contacts = match load_contacts(data_dir) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{}", sanitize_terminal_line(&e));
                    Vec::new()
                }
            };
            // On a terminal only the newest rows (and clipped bodies) are shown;
            // piped output (`| grep`, `| less`) always gets everything.
            let tty = io::stdout().is_terminal();
            let hidden = if tty {
                rows.len().saturating_sub(TTY_INBOX_ROWS)
            } else {
                0
            };
            let max_chars = tty.then_some(TTY_BODY_MAX_CHARS);
            let now = now_ms();
            println!("{C_BOLD}inbox{C_RESET} ({})", rows.len());
            if hidden > 0 {
                println!(
                    "{C_DIM}  \u{2026} {hidden} older message(s) not shown (`ash inbox | less` shows them all){C_RESET}"
                );
            }
            for row in rows.into_iter().skip(hidden) {
                println!(
                    "{}",
                    format_inbox_row(
                        &contacts,
                        &row.sender_device,
                        &row.message_id,
                        &row.plaintext,
                        &short_age(now, row.received_at_ms),
                        max_chars,
                    )
                );
            }
            print_inbox_receiver_note(data_dir);
            Ok(())
        }
        Err(e) => Err(format!("inbox: {}", e.redacted_display())),
    }
}

/// One inbox row on ONE terminal line: how long ago, who from (petname, with
/// "pinned" + fingerprint for a verified contact, or "unknown device" + its
/// fingerprint), then the body with line breaks / controls neutralised, then the
/// short message id (the sender's `mid=`) last.
fn format_inbox_row(
    contacts: &[Contact],
    sender_device: &[u8; 32],
    message_id: &[u8; 16],
    plaintext: &[u8],
    age: &str,
    max_chars: Option<usize>,
) -> String {
    let sender_hex = hex::encode(sender_device);
    let fp = device_fingerprint_v1(sender_device);
    let who = match contacts
        .iter()
        .find(|c| c.pub_hex.trim().eq_ignore_ascii_case(&sender_hex))
    {
        Some(ct) if ct.pinned => format!(
            "{C_BOLD}{}{C_RESET} {C_DIM}[pinned fp={fp}]{C_RESET}",
            ct.primary_label()
        ),
        Some(ct) => format!(
            "{C_BOLD}{}{C_RESET} {C_DIM}(not verified){C_RESET}",
            ct.primary_label()
        ),
        None => format!("{C_PURPLE}unknown device{C_RESET} {C_DIM}[fp={fp}]{C_RESET}"),
    };
    let when = if age.is_empty() {
        String::new()
    } else {
        format!("{C_DIM}{age}{C_RESET}  ")
    };
    format!(
        "  {when}from {who}: {}  {C_DIM}[{}]{C_RESET}",
        clip_body(
            sanitize_terminal_line(&String::from_utf8_lossy(plaintext)),
            max_chars
        ),
        hex::encode(&message_id[..4])
    )
}

fn parse_send_carrier(s: &str) -> Result<pair_init_lab::DialCarrier, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "lan" | "" => Ok(pair_init_lab::DialCarrier::Lan),
        "internet" => Ok(pair_init_lab::DialCarrier::Internet),
        other => Err(format!(
            "unknown --carrier {other} (lan | internet). internet is localhost/indexed lab only — not WAN Proven"
        )),
    }
}

fn run_send(
    data_dir: &Path,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    text: &str,
    carrier: pair_init_lab::DialCarrier,
) -> Result<(), String> {
    let id = require_identity(data_dir);
    match carrier {
        pair_init_lab::DialCarrier::Lan => {
            ext::run_send_secure(data_dir, &id, peer, peer_pub_hex, listen, text, "", "")
        }
        pair_init_lab::DialCarrier::Internet => ext::run_send_secure_on(
            data_dir,
            &id,
            peer,
            peer_pub_hex,
            listen,
            text,
            "",
            "",
            carrier,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn cmd_send_cli(
    data_dir: &Path,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    contact: &str,
    stdin_text: bool,
    chat: bool,
    carrier: &str,
) {
    let carrier = match parse_send_carrier(carrier) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{}", sanitize_terminal_line(&e));
            std::process::exit(1);
        }
    };
    let no_target = contact.trim().is_empty() && peer.trim().is_empty();
    if chat {
        if carrier == pair_init_lab::DialCarrier::Internet {
            eprintln!(
                "ash send --chat --carrier internet is not in this slice \
                 (localhost indexed send-only; not WAN Proven)"
            );
            std::process::exit(1);
        }
        if no_target {
            eprintln!(
                "ash send --chat requires --contact @tag or --peer host:port plus --peer-pub-hex"
            );
            std::process::exit(1);
        }
        let id = require_identity(data_dir);
        if !contact.trim().is_empty() {
            let contacts = match load_contacts(data_dir) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            };
            let hits = resolve_contact_arg(&contacts, contact);
            if hits.is_empty() {
                eprintln!("{}", no_contact_message(&contacts, contact));
                std::process::exit(1);
            }
            if hits.len() > 1 {
                eprintln!(
                    "contact {} is ambiguous ({} matches): use the @tag, or see `ash contact list`",
                    sanitize_terminal_line(contact),
                    hits.len()
                );
                std::process::exit(1);
            }
            let c = hits[0];
            // Chat never persists an env dial (no delivery signal to save after).
            let Some((ResolvedLanPeer::Dial(dial), _)) = resolve_or_reuse_lan_dial(c) else {
                eprintln!(
                    "contact {} has no reachable lan_dial — set host:port",
                    c.primary_label()
                );
                std::process::exit(1);
            };
            ext::cmd_chat_session(
                data_dir,
                &id,
                &c.petname,
                &normalize_tag(&c.public_tag),
                &c.pub_hex,
                &dial,
            );
            return;
        }
        if peer_pub_hex.trim().is_empty() || !looks_like_lan_dial(peer) {
            eprintln!(
                "ash send --chat requires --contact @tag or --peer host:port plus --peer-pub-hex"
            );
            std::process::exit(1);
        }
        ext::cmd_chat_session(data_dir, &id, "", "", peer_pub_hex, peer);
        return;
    }
    if no_target && stdin_is_tty() {
        // The guided picker only speaks LAN: an explicit `--carrier internet`
        // must not silently end up there (lab evidence on the wrong carrier).
        if carrier != pair_init_lab::DialCarrier::Lan {
            eprintln!(
                "ash send --carrier internet requires --contact @tag or --peer host:port plus --peer-pub-hex"
            );
            std::process::exit(1);
        }
        cmd_send_interactive(data_dir);
        return;
    }
    if !stdin_text {
        ext::refuse_argv_plaintext();
    }
    if stdin_is_tty() {
        // A target was given, so no picker follows: say what is being waited for.
        eprintln!("type your message, then press Ctrl-D on an empty line to send");
    }
    let text = match read_message_text(
        io::stdin().lock(),
        raven_core::lan_noise::MAX_LAN_ENDPOINT_TEXT,
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    if text.is_empty() {
        eprintln!("empty message");
        std::process::exit(1);
    }
    if stdin_is_tty() {
        if let Some(problem) = tty_message_problem(&text) {
            eprintln!("{problem}");
            std::process::exit(1);
        }
    }
    match resolve_send_target(data_dir, contact, peer, peer_pub_hex, listen) {
        Ok(target) => {
            if let Err(error) = run_send(
                data_dir,
                &target.peer,
                &target.pub_hex,
                &target.listen,
                &text,
                carrier,
            ) {
                eprintln!("{}", pair_init_lab::send_failure_line(&error));
                std::process::exit(1);
            }
            if target.save_dial_after_success {
                // The dial came from RAVEN_PEER and just reached (and
                // authenticated) this contact: only now is it worth keeping.
                match update_contact_lan_dial(data_dir, &target.pub_hex, &target.peer) {
                    Ok(()) => println!("{C_DIM}Saved lan_dial on contact for next Send.{C_RESET}"),
                    Err(e) => eprintln!("could not save dial: {}", sanitize_terminal_line(&e)),
                }
            }
        }
        Err(e) => {
            eprintln!("{}", sanitize_terminal_line(&e));
            std::process::exit(1);
        }
    }
}

/// Slack so trailing CR/LF past the limit are not mistaken for an oversized body.
const STDIN_TRAILING_SLACK: usize = 4096;

/// Read the message body for `ash send` from `input`, never buffering much
/// more than `max_bytes`: a runaway pipe (`cat /dev/zero | ash send …`) must hit
/// the size error, not exhaust memory first. Trailing CR/LF are dropped.
fn read_message_text(input: impl Read, max_bytes: usize) -> Result<String, String> {
    let too_large = || format!("message too large (max {max_bytes} bytes)");
    let limit = (max_bytes + STDIN_TRAILING_SLACK + 1) as u64;
    let mut buf = Vec::new();
    input
        .take(limit)
        .read_to_end(&mut buf)
        .map_err(|_| "failed to read message from stdin".to_string())?;
    if buf.len() as u64 >= limit {
        return Err(too_large());
    }
    let text =
        String::from_utf8(buf).map_err(|_| "failed to read message from stdin".to_string())?;
    let text = text.trim_end_matches(['\r', '\n']);
    if text.len() > max_bytes {
        return Err(too_large());
    }
    Ok(text.to_string())
}

/// Flat menu model shared by both navigation modes.
const MENU_ITEMS: [(&str, &str, &str); 8] = [
    ("1", "Chat / Send", "send one message to a contact"),
    ("2", "Inbox", "messages you received"),
    ("3", "Status", "your invite, contacts, is the node running"),
    (
        "4",
        "Listen",
        "stay online to receive (keep this window open)",
    ),
    (
        "5",
        "Contacts",
        "add a friend (paste their invite) · list · verify",
    ),
    (
        "6",
        "Mailbox",
        "advanced tool, this computer only (not your inbox)",
    ),
    (
        "7",
        "Nearby scan",
        "demo, this computer only (no Bluetooth yet)",
    ),
    ("8", "Tutorial", "new here? start here"),
];

/// Execute a menu choice; returns false when the user asked to quit.
fn run_menu_choice(data_dir: &Path, choice: &str) -> bool {
    let c = c();
    match choice.to_ascii_lowercase().as_str() {
        "1" | "s" | "send" | "chat" => cmd_send_interactive(data_dir),
        "2" | "i" | "inbox" => show_menu_error(cmd_endpoint_inbox(data_dir)),
        "3" | "st" | "status" => show_menu_error(cmd_status(data_dir)),
        "4" | "l" | "listen" => {
            if let Err((_, msg)) = cmd_listen(data_dir) {
                report_listen_error(&msg);
            }
        }
        "5" | "c" | "contacts" => cmd_contacts(data_dir),
        "6" | "mailbox" => println!(
            "{0}Mailbox is an advanced tool for this computer only; it is not where your messages arrive (that is menu 2 Inbox). Details: `ash mailbox --help`.{1}",
            c.dim, c.reset
        ),
        "7" | "nearby" => println!(
            "{0}Nearby scan is a demo on this computer only (no Bluetooth yet): it cannot find friends. To add a friend use menu 5 Contacts. Run the demo anyway: `ash nearby`.{1}",
            c.dim, c.reset
        ),
        "h" | "?" | "help" => println!(
            "{0}Pick a number from 1 to 8 (8 = Tutorial, a guided start), or q to quit.{1}",
            c.dim, c.reset
        ),
        "8" | "t" | "tutorial" => cmd_tutorial(data_dir),
        "q" | "quit" | "exit" => {
            println!("{0}fly safe.{1}", c.purple, c.reset);
            return false;
        }
        "" => {}
        _ => println!(
            "{0}unknown:{1} {2} {0}— pick 1-8 or q (h = help){1}",
            c.dim,
            c.reset,
            sanitize_terminal_line(choice)
        ),
    }
    true
}

fn interactive(data_dir: &Path) {
    let state = print_welcome_state(data_dir);
    let first = offer_first_run_identity_given(data_dir, state);
    match first {
        FirstRun::Present | FirstRun::Created => {}
        FirstRun::Declined => {
            println!("{C_DIM}tip: run `ash init` anytime to create an identity.{C_RESET}");
        }
        // `ash init` is exactly what the store is refusing: do not send the user
        // there to create one; it prints the recovery steps instead.
        FirstRun::Unavailable => {
            println!(
                "{C_DIM}no identity was offered: the identity store above must be fixed \
                 first. `ash init` shows the same error and, for leftover profile state, \
                 the recovery steps.{C_RESET}"
            );
        }
    }
    if io::stdin().is_terminal() && !cfg!(windows) {
        // The arrow menu clears the screen: without a pause the identity and
        // invite just printed (or the reason there is none) vanish at once.
        if first != FirstRun::Present {
            pause_before_menu();
        }
        arrow_menu_loop(data_dir);
    } else {
        line_menu_loop(data_dir);
    }
}

/// Terminal only: wait for Enter so what the first-run offer printed can be read
/// and copied before the menu redraws the screen. EOF just carries on.
fn pause_before_menu() {
    println!(
        "\n{C_DIM}Press Enter to open the menu (`ash whoami` shows your invite again).{C_RESET}"
    );
    let _ = io::stdout().flush();
    let _ = read_line_opt();
}

/// Classic numbered input — used when stdin is piped (tests) or on Windows.
fn line_menu_loop(data_dir: &Path) {
    loop {
        print_menu();
        let mut choice = String::new();
        if let Ok(0) = io::stdin().read_line(&mut choice) {
            break; // stdin closed — stop instead of spinning
        }
        let choice = choice.trim().to_string();
        if !run_menu_choice(data_dir, &choice) {
            break;
        }
        println!();
    }
}

// ── Arrow-key navigation (interactive terminals only) ─────────────────────

#[derive(PartialEq)]
enum MenuKey {
    Up,
    Down,
    Enter,
    Escape,
    Digit(usize),
    Quit,
    Other,
}

/// Interactive prompts require a human terminal. Automated callers (scripts,
/// rdap-style tools) must supply values up-front; we never spin on EOF.
fn stdin_is_tty() -> bool {
    use std::io::IsTerminal;
    io::stdin().is_terminal()
}

// ── Terminal design system v1 (monochrome) ─────────────────────────────
// Symbols: ◆ section · ▸ selected · ✓ ok · ✗ fail · ● ready · → action
// Type:    bold = emphasis/values, dim = hints/secondary
// Layout:  2-space base indent inside sections, blank line between groups.

const W_KEY: usize = 14; // column width for key/value rows

/// Aligned key-value row: dim padded label, plain value.
/// Sub-screen header for consistent inner views.
fn screen_header(title: &str) {
    let c = c();
    let label = format!(" ── {} ", title);
    let fill_len = 56usize.saturating_sub(label.chars().count());
    let fill = "─".repeat(fill_len);
    println!("\n{}{}{}{}", c.dim, label, fill, c.reset);
}

fn kv(label: &str, value: &str) {
    let c = c();
    println!(
        "  {d}{l:<w$}{r}{v}",
        d = c.dim,
        l = label,
        w = W_KEY,
        r = c.reset,
        v = value
    );
}

fn ok(v: bool) -> &'static str {
    if v {
        "on"
    } else {
        "off"
    }
}

fn clear_screen() {
    print!("\u{1b}[2J\u{1b}[H");
    let _ = io::stdout().flush();
}

fn wait_back() -> bool {
    // Returns false = quit app. True = go back to menu.
    println!("\n  {d}[Esc] back{r}", d = c().dim, r = c().reset);
    let _ = io::stdout().flush();
    loop {
        match read_key_raw() {
            MenuKey::Escape | MenuKey::Enter => return true,
            MenuKey::Quit => return false,
            _ => {}
        }
    }
}

fn stty(args: &[&str]) {
    #[cfg(unix)]
    let _ = Command::new("stty").args(args).status();
    #[cfg(not(unix))]
    let _ = args;
}

/// The user's own tty settings (`stty -g`), captured once before the first
/// raw read so every restore puts back exactly what they had — not `sane`.
fn saved_tty_state() -> Option<&'static str> {
    static SAVED: OnceLock<Option<String>> = OnceLock::new();
    SAVED
        .get_or_init(|| {
            #[cfg(unix)]
            {
                let out = Command::new("stty")
                    .arg("-g")
                    .stdin(std::process::Stdio::inherit())
                    .stderr(std::process::Stdio::null())
                    .output()
                    .ok()?;
                let state = String::from_utf8(out.stdout).ok()?.trim().to_string();
                (out.status.success() && !state.is_empty()).then_some(state)
            }
            #[cfg(not(unix))]
            {
                None
            }
        })
        .as_deref()
}

fn restore_tty() {
    match saved_tty_state() {
        Some(state) => stty(&[state]),
        None => stty(&["sane"]),
    }
}

fn read_key_raw() -> MenuKey {
    // Capture the user's settings before the first switch into raw mode.
    let _ = saved_tty_state();
    // Brief raw window: keystrokes arrive unbuffered (no Enter needed).
    stty(&["raw", "-echo"]);
    let key = read_key_raw_inner();
    restore_tty();
    key
}

fn read_key_raw_inner() -> MenuKey {
    use io::Read;
    let mut b = [0u8; 1];
    if io::stdin().read(&mut b).unwrap_or(0) == 0 {
        return MenuKey::Quit;
    }
    match b[0] {
        b'\r' | b'\n' => MenuKey::Enter,
        0x1b => {
            // `stty raw` is VMIN=1/VTIME=0, so a plain read would block until
            // the NEXT key (and swallow it). Arrow keys send their bytes
            // together; switch to a 100 ms timed read to tell them apart from
            // a bare Esc press.
            stty(&["min", "0", "time", "1"]);
            let tail = read_escape_tail(|buf| io::stdin().read(buf).unwrap_or(0));
            stty(&["min", "1", "time", "0"]);
            classify_escape(&tail)
        }
        b'q' | b'Q' => MenuKey::Quit,
        b'\x03' => MenuKey::Quit, // Ctrl+C
        d @ b'1'..=b'8' => MenuKey::Digit((d - b'0') as usize),
        _ => MenuKey::Other,
    }
}

/// Drain the rest of one escape sequence after ESC: a whole CSI (`[`,
/// parameter bytes 0x20..=0x3F, one final byte) or SS3 (`O` + one byte), so
/// modifier keys such as Ctrl+Up (`ESC [ 1 ; 5 A`) leave no stray bytes for
/// the next key read. `read1` returns 0 on timeout / EOF. Bounded at 16 bytes.
fn read_escape_tail(mut read1: impl FnMut(&mut [u8]) -> usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = [0u8; 1];
    if read1(&mut b) == 0 {
        return out;
    }
    let first = b[0];
    out.push(first);
    match first {
        b'[' => {
            while out.len() < 16 {
                if read1(&mut b) == 0 {
                    break;
                }
                out.push(b[0]);
                if !(0x20..=0x3f).contains(&b[0]) {
                    break; // final byte (or anything that cannot continue a CSI)
                }
            }
        }
        b'O' if read1(&mut b) == 1 => out.push(b[0]),
        _ => {}
    }
    out
}

/// Bytes read after ESC (within the timed window) → key. Accepts CSI and SS3
/// (application cursor mode) arrows, with or without modifier parameters.
fn classify_escape(after_esc: &[u8]) -> MenuKey {
    match after_esc {
        [] => MenuKey::Escape,
        [b'[' | b'O', .., b'A'] => MenuKey::Up,
        [b'[' | b'O', .., b'B'] => MenuKey::Down,
        [b'[' | b'O', ..] => MenuKey::Other,
        _ => MenuKey::Escape,
    }
}

/// The `raven ❯` prompt row. Its style is closed again: an unreset bold here
/// used to leak into the next command's first unstyled output.
fn arrow_menu_prompt(cc: &Colors) -> String {
    format!("raven {}❯ {}", cc.cyan, cc.reset)
}

/// The line under the arrow menu: ONE quit key, how to move, where to start.
fn arrow_menu_footer(dim: &str, reset: &str) -> String {
    format!("q  quit   {dim}(up/down + Enter, or press a number)  ·  new here? press 8{reset}")
}

fn render_arrow_menu(sel: usize, first: bool) {
    let items = MENU_ITEMS;
    let cc = c();
    let (purple, _bold, dim, reset, marker) = (cc.purple, cc.bold, cc.dim, cc.reset, "\u{25b8}");

    let mut lines: Vec<String> = Vec::new();
    let section = |v: &mut Vec<String>, label: &str| {
        v.push(format!(
            "{p}◆ {l}{r}",
            p = purple,
            l = label.to_ascii_uppercase(),
            r = reset
        ));
    };
    let row = |v: &mut Vec<String>, idx: usize| {
        let (num, title, hint) = items[idx];
        if idx == sel {
            v.push(format!(
                "  {m} {n}  {t}{r}  {d}{h}{r}",
                m = marker,
                n = num,
                t = title,
                d = dim,
                h = hint,
                r = reset
            ));
        } else {
            v.push(format!("    {n}  {t}", n = num, t = title));
        }
    };

    section(&mut lines, "messages");
    row(&mut lines, 0);
    row(&mut lines, 1);
    section(&mut lines, "network");
    row(&mut lines, 2);
    row(&mut lines, 3);
    section(&mut lines, "people");
    row(&mut lines, 4);
    section(&mut lines, "tools");
    row(&mut lines, 5);
    row(&mut lines, 6);
    row(&mut lines, 7);
    lines.push(String::new());
    lines.push(arrow_menu_footer(dim, reset));
    lines.push(arrow_menu_prompt(&cc));

    let n = lines.len();
    // Clear-to-end-of-line on every row so highlights never leave residue,
    // then join with plain newlines (we always draw in cooked mode).
    for l in lines.iter_mut() {
        l.push_str("\x1b[K");
    }
    let body = lines.join("\n");
    if first {
        println!();
        print!("{}", body);
    } else {
        // From the prompt row back to the first row of the block = n-1 up.
        print!("\r\x1b[{}A{}", n.saturating_sub(1), body);
    }
    let _ = io::stdout().flush();
}

pub fn run() {
    let path = resolve_terminal_messaging_path();
    if let Err(e) = assert_no_silent_fastapi(path) {
        eprintln!("{e}");
        std::process::exit(1);
    }
    let cli = Cli::parse();
    // Linux passphrase vault (no reachable Secret Service): the CLI may ask
    // for the keystore passphrase on its terminal (no echo; twice on first
    // creation). Non-TTY runs still need RAVEN_KEYSTORE_PASSPHRASE_FILE, and
    // raven-node never prompts. No effect on macOS / Windows backends.
    raven_core::keystore_vault::enable_terminal_prompt();
    // Say up front when there is no profile to use (no --data-dir, no
    // RAVEN_DATA_DIR / ASH_DATA_DIR and no usable HOME), instead of letting
    // whichever store is touched first fail with "Not a directory".
    let data_dir = match resolve_data_dir(&cli.data_dir) {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let _ = create_private_data_dir(&data_dir);
    match cli.cmd {
        None => interactive(&data_dir),
        Some(Commands::Banner) => print_welcome(&data_dir),
        Some(Commands::Listen) => {
            if let Err((code, msg)) = cmd_listen(&data_dir) {
                report_listen_error(&msg);
                std::process::exit(code);
            }
        }
        Some(Commands::Init) => {
            let id = ensure_identity(&data_dir);
            println!("address={}", id.address());
            println!(
                "fingerprint={}",
                device_fingerprint_v1(&id.public_key_bytes())
            );
            println!("pub_hex={}", hex::encode(id.public_key_bytes()));
            if let Err(e) = raven_core::ensure_local_prekey(&data_dir, &id) {
                eprintln!("prekey: {e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Whoami { json }) => match try_load_identity(&data_dir) {
            Ok(Some(id)) => {
                if json {
                    println!("{}", public_whoami_card(&id));
                } else {
                    print_public_identity(&id);
                }
            }
            Ok(None) => {
                if json {
                    eprintln!("{{\"error\":\"no_identity\"}}");
                    std::process::exit(1);
                }
                println!("no identity — run init");
            }
            Err(e) => {
                // A hard failure (not just "no identity yet"): never exit 0.
                eprintln!("identity store: {}", sanitize_terminal_line(&e));
                std::process::exit(1);
            }
        },
        Some(Commands::Status) => {
            if let Err(e) = cmd_status(&data_dir) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Doctor { require_ready }) => cmd_doctor(&data_dir, require_ready),
        Some(Commands::IpcPing) => cmd_ipc_ping(&data_dir),
        Some(Commands::Inbox) => exit_on_err(cmd_endpoint_inbox(&data_dir)),
        Some(Commands::Send {
            peer,
            peer_pub_hex,
            listen,
            contact,
            stdin_text,
            chat,
            carrier,
        }) => cmd_send_cli(
            &data_dir,
            &peer,
            &peer_pub_hex,
            &listen,
            &contact,
            stdin_text,
            chat,
            &carrier,
        ),
        Some(Commands::Find {
            query,
            local,
            exact_id,
            exact_alias,
            all,
        }) => cmd_find(&data_dir, &query, local, exact_id, exact_alias, all),
        Some(Commands::Nearby) => cmd_nearby(&data_dir),
        Some(Commands::Node { cmd }) => match cmd {
            NodeCommands::Bridge { state } => {
                set_node_flag(&data_dir, "bridge", matches!(state, OnOff::On))
            }
            NodeCommands::Store { state } => {
                set_node_flag(&data_dir, "store", matches!(state, OnOff::On))
            }
            NodeCommands::Relay { state } => {
                set_node_flag(&data_dir, "relay", matches!(state, OnOff::On))
            }
            NodeCommands::AddBootstrap { multiaddr, manual } => {
                ext::cmd_bootstrap_add(&data_dir, &multiaddr, manual)
            }
            NodeCommands::DisableRavenDefaults => ext::cmd_bootstrap_disable_raven(&data_dir),
            NodeCommands::ShowBootstrap => ext::cmd_bootstrap_show(&data_dir),
            NodeCommands::InitBootstrap { no_raven_defaults } => {
                ext::cmd_bootstrap_init(&data_dir, no_raven_defaults)
            }
        },
        Some(Commands::Alias { cmd }) => match cmd {
            AliasCommands::Publish {
                alias,
                sequence,
                expires_at,
            } => cmd_alias_publish(&data_dir, &alias, sequence, expires_at),
        },
        Some(Commands::Prekey { cmd }) => match cmd {
            PrekeyCommands::Publish { device_id, out } => {
                cmd_prekey_publish(&data_dir, &device_id, out.as_deref())
            }
            PrekeyCommands::Fetch { pub_hex, file } => {
                exit_on_err(cmd_prekey_fetch(&data_dir, &pub_hex, file.as_deref()))
            }
        },
        Some(Commands::Device { cmd }) => {
            let id = require_identity(&data_dir);
            match cmd {
                DeviceCommands::SyncExport { device_id, out } => {
                    ext::cmd_device_sync_export(&data_dir, &id, &device_id, &out)
                }
                DeviceCommands::SyncImport { file } => {
                    ext::cmd_device_sync_import(&data_dir, &id, &file)
                }
                DeviceCommands::Revoke { device_id, epoch } => {
                    ext::cmd_device_revoke(&data_dir, &id, &device_id, epoch)
                }
            }
        }
        Some(Commands::Mailbox { cmd }) => match cmd {
            MailboxCommands::Put {
                k_route_hex,
                k_route_stdin,
                epoch,
                slot,
                envelope_hex,
            } => {
                let k_route = k_route_or_exit(k_route_hex.as_deref(), k_route_stdin);
                ext::cmd_mailbox_put(&data_dir, &k_route, epoch, slot, &envelope_hex)
            }
            MailboxCommands::Get {
                k_route_hex,
                k_route_stdin,
                epoch,
                slot,
            } => {
                let k_route = k_route_or_exit(k_route_hex.as_deref(), k_route_stdin);
                ext::cmd_mailbox_get(&data_dir, &k_route, epoch, slot)
            }
        },
        Some(Commands::Lab { cmd }) => match cmd {
            LabCommands::ExportCert => {
                let id = require_identity(&data_dir);
                if let Err(e) = pair_init_lab::export_lab_device_cert(&data_dir, &id) {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
            LabCommands::ImportPeerCert { peer_pub_hex, file } => {
                if let Err(e) =
                    pair_init_lab::import_peer_device_cert(&data_dir, &peer_pub_hex, &file)
                {
                    eprintln!("{e}");
                    std::process::exit(1);
                }
            }
            LabCommands::ImportPeerPrekey { peer_pub_hex, file } => {
                exit_on_err(cmd_prekey_fetch(&data_dir, &peer_pub_hex, Some(&file)))
            }
            LabCommands::Status => print_production_gate_matrix(),
            LabCommands::LanDialSealed {
                dial,
                expected_pub_hex,
                envelope_b64,
            } => cmd_lab_lan_dial_sealed(&data_dir, &dial, &expected_pub_hex, &envelope_b64),
        },
        Some(Commands::Contact { cmd }) => match cmd {
            ContactCommands::Add {
                address,
                pub_hex,
                petname,
                tag,
                alias,
                verify_fp,
                prekey_file,
                lan_dial,
            } => {
                let public_tag = if !tag.trim().is_empty() { tag } else { alias };
                exit_on_err(require_identity_before_state(&data_dir, "contact add"));
                if is_own_pub_hex(&data_dir, &pub_hex) {
                    eprintln!(
                        "warning: this is YOUR OWN identity, not a friend's. Nobody else can be reached with it; ask your friend for THEIR invite (`ash whoami`)."
                    );
                }
                if let Err(e) = add_contact(
                    &data_dir,
                    &address,
                    &pub_hex,
                    &petname,
                    &public_tag,
                    verify_fp.as_deref(),
                    &lan_dial,
                ) {
                    eprintln!("{}", sanitize_terminal_line(&e));
                    std::process::exit(1);
                }
                if let Some(path) = prekey_file {
                    if let Err(e) = ext::contact_add_fetch_prekey(&data_dir, &pub_hex, Some(&path))
                    {
                        eprintln!("{}", sanitize_terminal_line(&e));
                        std::process::exit(1);
                    }
                }
            }
            ContactCommands::List => exit_on_err(cmd_contact_list(&data_dir)),
            ContactCommands::Verify {
                tag,
                alias,
                petname,
                address,
            } => exit_on_err(cmd_contact_verify(
                &data_dir,
                tag.as_deref(),
                alias.as_deref(),
                petname.as_deref(),
                address.as_deref(),
            )),
            ContactCommands::Resolve { tag } => exit_on_err(cmd_contact_resolve(&data_dir, &tag)),
            ContactCommands::Request {
                target,
                message,
                pick,
            } => cmd_contact_request(&data_dir, &target, &message, pick),
            ContactCommands::Pending => cmd_contact_pending(&data_dir),
            ContactCommands::Ingest { file } => cmd_contact_ingest(&data_dir, &file),
            ContactCommands::Accept {
                request_id,
                petname,
            } => cmd_contact_accept(&data_dir, &request_id, &petname),
            ContactCommands::Decline { request_id } => cmd_contact_decline(&data_dir, &request_id),
            ContactCommands::Block { request_id } => cmd_contact_block(&data_dir, &request_id),
            ContactCommands::Unblock { pub_hex } => {
                exit_on_err(cmd_contact_unblock(&data_dir, &pub_hex))
            }
            ContactCommands::Remove {
                tag,
                petname,
                address,
                yes,
            } => exit_on_err(cmd_contact_remove(
                &data_dir,
                tag.as_deref(),
                petname.as_deref(),
                address.as_deref(),
                yes,
            )),
            ContactCommands::SetDial {
                tag,
                petname,
                address,
                lan_dial,
            } => exit_on_err(cmd_contact_set_dial(
                &data_dir,
                tag.as_deref(),
                petname.as_deref(),
                address.as_deref(),
                &lan_dial,
            )),
        },
    }
}

/// Guided walkthrough for newcomers. Every step prints what it does and why,
/// then runs the safe ones inline. No private material is ever displayed.
fn cmd_tutorial(data_dir: &Path) {
    let c = c();
    let first = offer_first_run_identity(data_dir);

    println!(
        "\n{0}\u{2550}\u{2550}\u{2550} RAVEN TUTORIAL \u{2550}\u{2550}\u{2550}{1}",
        c.purple, c.reset
    );
    println!(
        "{0}Raven has no central server: you and your friends ARE the network.{1}",
        c.dim, c.reset
    );
    println!(
        "{0}No phone number, no account. Messages go straight between people who added each other.{1}\n",
        c.dim, c.reset
    );

    println!("{0}[1/4] Your identity{1}", c.bold, c.reset);
    match try_load_identity(data_dir) {
        Ok(Some(id)) => {
            let word = if first == FirstRun::Created {
                "created"
            } else {
                "ready"
            };
            println!(
                "  {0}\u{2714}{1} {word}. These lines are public and safe to share. The one to send your friend is the `invite` line:",
                c.green, c.reset
            );
            print_public_identity(&id);
            println!();
        }
        Ok(None) => {
            println!(
                "  {0}skipped (declined). Re-enter via menu 8 anytime.{1}\n",
                c.dim, c.reset
            );
            return;
        }
        Err(e) => {
            println!("  {0}\u{00d7} {1}\n", c.red, sanitize_terminal_line(&e));
            return;
        }
    }

    println!("{0}[2/4] Add your friend{1}", c.bold, c.reset);
    println!(
        "  {0}Paste your friend's invite line (or their whole {1}ash whoami{0} block).\n  They must add YOU the same way: messages only flow between people who added each other.{2}",
        c.dim, c.bold, c.reset
    );
    print!("  {}Add now? [y/N] {}", c.yellow, c.reset);
    let _ = io::stdout().flush();
    let ans = read_line();
    if ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes") {
        cmd_contacts(data_dir);
    } else {
        println!("  {0}later: menu 5 \u{2192} Contacts{1}", c.dim, c.reset);
    }
    println!();

    println!("{0}[3/4] Check this computer{1}", c.bold, c.reset);
    match cmd_status(data_dir) {
        Ok(_) => println!(
            "  {0}The last line above says whether this computer can send and receive.\n  Sending starts what it needs by itself; to RECEIVE keep menu 4 (Listen) open.{1}\n",
            c.dim, c.reset
        ),
        Err(e) => println!("  {0}\u{00d7}{1} status: {2}\n", c.red, c.reset, e),
    }

    println!("{0}[4/4] Send and receive{1}", c.bold, c.reset);
    println!(
        "  {0}Send: menu 1, pick your friend, type the message.\n  Receive: your friend keeps menu 4 (Listen) open on their computer; you read replies in menu 2 (Inbox).\n  If a send fails, run `ash doctor`: it says what to do next.{1}\n",
        c.dim, c.reset
    );

    println!("{0}Done!{1}", c.purple, c.reset);
    println!("{}", tutorial_footer(&c));
}

/// Tutorial last line: dim label, bold command, then one reset. (The arguments
/// were swapped before, which dimmed the command and left everything printed
/// afterwards dim.)
fn tutorial_footer(c: &Colors) -> String {
    format!(
        "  {0}Full diagnostics anytime: {1}ash doctor{2}",
        c.dim, c.bold, c.reset
    )
}

fn arrow_menu_loop(data_dir: &Path) {
    let mut sel: usize = 0;

    loop {
        clear_screen();
        print_welcome_minimal(data_dir);
        render_arrow_menu(sel, true);

        let key = read_key_raw();

        match key {
            MenuKey::Up => {
                if sel > 0 {
                    sel -= 1;
                    render_arrow_menu(sel, false);
                }
            }
            MenuKey::Down => {
                if sel + 1 < MENU_ITEMS.len() {
                    sel += 1;
                    render_arrow_menu(sel, false);
                }
            }
            MenuKey::Enter => {
                clear_screen();
                let choice = MENU_ITEMS[sel].0.to_string();
                run_menu_choice(data_dir, &choice);

                if !wait_back() {
                    break;
                }
            }
            MenuKey::Digit(d) => {
                sel = d.saturating_sub(1);
                clear_screen();
                let choice = MENU_ITEMS[sel].0.to_string();
                run_menu_choice(data_dir, &choice);

                if !wait_back() {
                    break;
                }
            }
            MenuKey::Escape => {}
            MenuKey::Quit => {
                clear_screen();
                let cc = c();
                println!("{0}R A V E N{1}", cc.bold, cc.reset);
                println!("{0}fly safe.{1}", cc.dim, cc.reset);
                break;
            }
            MenuKey::Other => {}
        }
    }

    clear_screen();
}

/// Minimal header shown on every screen refresh (not the full banner).
fn print_welcome_minimal(_data_dir: &Path) {
    let c = c();
    let (b, d, r) = (c.bold, c.dim, c.reset);
    println!("{b}R A V E N{r}  {d}\u{00b7}  serverless \u{00b7} P2P{r}");
    println!("{d}your invite: `ash whoami`  \u{00b7}  new here? press 8{r}");
    println!();
}

fn cmd_ipc_ping(data_dir: &Path) {
    let ep = ipc_endpoint(data_dir);
    if !ep.transport_available() {
        eprintln!("ipc_transport_missing");
        eprintln!("start: raven-node ipc --data-dir {}", data_dir.display());
        std::process::exit(1);
    }
    match ipc_client::ipc_ping(data_dir) {
        Ok(IpcResponse::Pong { v }) => {
            println!("{C_GREEN}ipc pong{C_RESET} v={v} endpoint={ep}");
        }
        Ok(other) => {
            eprintln!("unexpected response: {other:?}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("ipc ping failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Core doctor gate: Ping answers. Not file exists. Not send.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DaemonPresence {
    Present {
        ipc_version: u16,
    },
    /// Transport exists but Ping failed — fail-closed connect, not a skip.
    Down {
        reason: String,
    },
    /// No IPC transport on this OS (`IpcEndpoint::Unsupported`).
    Blocked {
        reason: &'static str,
    },
}

/// Presence + Status + usable identity + queue/DB or `forward_pending` + serverless.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DaemonReady {
    Ready,
    NotReady { reason: String },
}

/// Default not_ready / unchecked. Never green from presence or ready.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SendPathLabel {
    NotReady {
        reason: String,
    },
    #[allow(dead_code)]
    Unchecked,
}

const DOCTOR_EXIT_OK: i32 = 0;
const DOCTOR_EXIT_HARD: i32 = 1;
const DOCTOR_EXIT_SECURITY: i32 = 2;

fn classify_presence_from_ping(ping: Result<IpcResponse, String>) -> DaemonPresence {
    match ping {
        Ok(IpcResponse::Pong { v }) => DaemonPresence::Present { ipc_version: v },
        Ok(_) => DaemonPresence::Down {
            reason: "unexpected_ipc_response".into(),
        },
        Err(e) => DaemonPresence::Down { reason: e },
    }
}

fn probe_daemon_presence(data_dir: &Path) -> DaemonPresence {
    let ep = ipc_endpoint(data_dir);
    if !ep.transport_available() {
        return DaemonPresence::Blocked {
            reason: "ipc_transport_missing",
        };
    }
    classify_presence_from_ping(ipc_client::ipc_ping(data_dir))
}

fn probe_ipc_status(data_dir: &Path) -> Result<IpcResponse, String> {
    ipc_client::ipc_request(data_dir, &IpcRequest::Status { v: IPC_VERSION })
}

/// Thin wrapper used by doctor unit tests. Production doctor uses
/// `probe_doctor_identity` (same `raven_core::identity_usable` backend).
#[cfg_attr(not(test), allow(dead_code))]
fn identity_usable(data_dir: &Path) -> bool {
    match raven_core::identity_usable(data_dir) {
        Ok(u) => u.usable,
        Err(_) => false,
    }
}

fn identity_not_usable_fail_line(issue: &str) -> String {
    format!(
        "  FAIL: identity not usable ({})",
        sanitize_terminal_line(issue)
    )
}

struct DoctorIdentityProbe {
    usable: bool,
    hard_fail: bool,
    identity_err: Option<String>,
}

fn probe_doctor_identity(data_dir: &Path) -> DoctorIdentityProbe {
    match raven_core::identity_usable(data_dir) {
        Ok(report) => {
            let backend = report
                .consistency
                .recorded
                .map(|b| b.as_str())
                .unwrap_or("none");
            println!(
                "  secure_keystore: backend={backend} identity={}",
                if report.has_identity {
                    "present"
                } else {
                    "absent"
                }
            );
            if report.consistency.blocks_identity_use() {
                let issue = report
                    .reason
                    .as_deref()
                    .or(report.consistency.issue.as_deref())
                    .unwrap_or("identity backend mismatch");
                println!("{}", identity_not_usable_fail_line(issue));
                return DoctorIdentityProbe {
                    usable: false,
                    hard_fail: true,
                    identity_err: Some(issue.to_string()),
                };
            }
            if let Ok(ks) = raven_core::store_status(data_dir) {
                if ks.legacy_plaintext_present {
                    println!(
                        "  {C_PURPLE}secure_keystore{C_RESET}: legacy plaintext seed file still present — reopen once to migrate"
                    );
                }
            }
            DoctorIdentityProbe {
                usable: report.usable,
                hard_fail: false,
                identity_err: report.reason,
            }
        }
        Err(e) => {
            let raw = e.redacted_display();
            match e {
                raven_core::IdentityStoreError::Continuity(_)
                | raven_core::IdentityStoreError::Corrupt => {
                    println!("{}", identity_not_usable_fail_line(&raw));
                    DoctorIdentityProbe {
                        usable: false,
                        hard_fail: true,
                        identity_err: Some(raw),
                    }
                }
                _ => {
                    println!(
                        "  {C_PURPLE}secure_keystore{C_RESET}: unavailable ({})",
                        sanitize_terminal_line(&raw)
                    );
                    DoctorIdentityProbe {
                        usable: false,
                        hard_fail: false,
                        identity_err: Some(raw),
                    }
                }
            }
        }
    }
}

fn queue_db_openable(data_dir: &Path) -> bool {
    let fwd = data_dir.join("forward_queue.sqlite");
    if fwd.exists() && ForwardQueue::open(&fwd).is_ok() {
        return true;
    }
    for name in ["queue.sqlite", "queue.db"] {
        let p = data_dir.join(name);
        if p.exists() && OutgoingQueue::open(&p).is_ok() {
            return true;
        }
    }
    false
}

fn status_forward_pending_ok(status: &Result<IpcResponse, String>) -> bool {
    matches!(status, Ok(IpcResponse::Status { .. }))
}

fn classify_daemon_ready(
    presence: &DaemonPresence,
    status: Option<&Result<IpcResponse, String>>,
    identity_ok: bool,
    queue_or_forward_ok: bool,
    messaging: MessagingPath,
) -> DaemonReady {
    if matches!(presence, DaemonPresence::Blocked { .. }) {
        return DaemonReady::NotReady {
            reason: "ipc_transport_blocked".into(),
        };
    }
    if !matches!(presence, DaemonPresence::Present { .. }) {
        return DaemonReady::NotReady {
            reason: "no_presence".into(),
        };
    }
    match status {
        Some(Ok(IpcResponse::Status { .. })) => {}
        Some(Ok(_)) => {
            return DaemonReady::NotReady {
                reason: "status_unexpected_response".into(),
            };
        }
        Some(Err(_)) => {
            return DaemonReady::NotReady {
                reason: "status_failed".into(),
            };
        }
        None => {
            return DaemonReady::NotReady {
                reason: "status_unchecked".into(),
            };
        }
    }
    if !identity_ok {
        return DaemonReady::NotReady {
            reason: "identity_unusable".into(),
        };
    }
    if !queue_or_forward_ok {
        return DaemonReady::NotReady {
            reason: "queue_unopened".into(),
        };
    }
    if messaging != MessagingPath::ServerlessRvn1 {
        return DaemonReady::NotReady {
            reason: format!("messaging_path={}", messaging.as_diag_label()),
        };
    }
    DaemonReady::Ready
}

fn classify_send_path() -> SendPathLabel {
    SendPathLabel::NotReady {
        reason: "not_probed".into(),
    }
}

fn doctor_security_hold(messaging: MessagingPath, identity_err: Option<&str>) -> Option<String> {
    let _ = messaging;
    if let Some(err) = identity_err {
        if err.contains("continuity") {
            return Some("identity_continuity".into());
        }
    }
    None
}

fn doctor_exit_code(
    ready: &DaemonReady,
    require_ready: bool,
    security_hold: Option<&str>,
    hard_failure: bool,
) -> i32 {
    if security_hold.is_some() {
        return DOCTOR_EXIT_SECURITY;
    }
    if hard_failure {
        return DOCTOR_EXIT_HARD;
    }
    if require_ready && !matches!(ready, DaemonReady::Ready) {
        return DOCTOR_EXIT_HARD;
    }
    DOCTOR_EXIT_OK
}

fn print_presence(presence: &DaemonPresence) {
    match presence {
        DaemonPresence::Present { ipc_version } => {
            println!("  daemon_presence: present (ipc_ping ok v={ipc_version})");
        }
        DaemonPresence::Down { reason } => {
            println!(
                "  daemon_presence: down ({})",
                sanitize_terminal_line(reason)
            );
        }
        DaemonPresence::Blocked { reason } => {
            println!("  daemon_presence: blocked (reason={reason})");
        }
    }
}

fn print_ready(ready: &DaemonReady) {
    match ready {
        DaemonReady::Ready => println!("  daemon_ready: ready"),
        DaemonReady::NotReady { reason } => {
            println!("  daemon_ready: not_ready (reason={reason})");
        }
    }
}

fn print_send_path(send: &SendPathLabel) {
    match send {
        SendPathLabel::NotReady { reason } => {
            println!("  send_path: not_ready (reason={reason})");
        }
        SendPathLabel::Unchecked => println!("  send_path: unchecked"),
    }
}

/// The one thing to do next, in plain words, from what `ash doctor` found. The
/// first problem wins (no identity before no contacts before the node).
fn doctor_next_step(identity: IdentityState, contacts: Option<usize>, reach: &NodeReach) -> String {
    match (identity, contacts, reach) {
        (IdentityState::Missing, _, _) => "run `ash init` to create your identity.".into(),
        (IdentityState::Unavailable, _, _) => {
            "fix the identity store problem shown in the details below; nothing can be sent until then."
                .into()
        }
        (IdentityState::Ready, Some(0), _) => {
            "add your first friend: run `ash`, open menu 5 Contacts and paste their invite line (they add yours the same way)."
                .into()
        }
        (IdentityState::Ready, None, _) => {
            "your contacts file cannot be read; see the message below.".into()
        }
        (IdentityState::Ready, Some(_), NodeReach::NotRunning) => {
            "to receive messages run `ash listen` and keep it open (the node also starts by itself when you send).".into()
        }
        (IdentityState::Ready, Some(_), NodeReach::SendOnly) => {
            "this computer is NOT receiving: the LAN listener is down. See raven-node-service.log in your Raven folder; sending still works.".into()
        }
        (IdentityState::Ready, Some(_), NodeReach::NotAnswering) => {
            "raven-node is running but does not answer; see the details below.".into()
        }
        (IdentityState::Ready, Some(_), NodeReach::SendAndReceive) => {
            "all set. Send a test message: echo \"hello\" | ash send --contact NAME".into()
        }
    }
}

/// Plain-language block at the top of `ash doctor` (the technical lines it keeps
/// printing follow). Read-only: never starts the node. Returns the next step so
/// the report can end with it too (`| tail` shows it).
fn print_doctor_summary(data_dir: &Path) -> String {
    let c = c();
    let identity = match try_load_identity(data_dir) {
        Ok(Some(_)) => IdentityState::Ready,
        Ok(None) => IdentityState::Missing,
        Err(_) => IdentityState::Unavailable,
    };
    let contacts = load_contacts(data_dir).ok().map(|v| v.len());
    let reach = classify_node_reach(&ipc_client::ipc_request_timeout(
        data_dir,
        &IpcRequest::Status { v: IPC_VERSION },
        Duration::from_secs(2),
    ));
    let identity_text = match identity {
        IdentityState::Ready => "OK",
        IdentityState::Missing => "MISSING (run: ash init)",
        IdentityState::Unavailable => "UNAVAILABLE (see the details below)",
    };
    let node_text = match reach {
        NodeReach::SendAndReceive => "running; you can send and receive",
        NodeReach::SendOnly => "running, but NOT receiving (LAN listener is down)",
        NodeReach::NotRunning => {
            "NOT running (it starts when you send; to receive run: ash listen)"
        }
        NodeReach::NotAnswering => "running but not answering",
    };
    let contacts_text = match contacts {
        Some(n) => n.to_string(),
        None => "unreadable (see the message below)".into(),
    };
    let next = doctor_next_step(identity, contacts, &reach);
    println!("{}SUMMARY{}", c.bold, c.reset);
    kv("identity", identity_text);
    kv("raven-node", node_text);
    kv("contacts", &contacts_text);
    kv("next step", &next);
    println!("{}(technical details follow){}\n", c.dim, c.reset);
    next
}

fn cmd_doctor(data_dir: &Path, require_ready: bool) {
    println!("{C_BOLD}raven doctor{C_RESET}");
    let next_step = print_doctor_summary(data_dir);
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".into());
    let exe_clean = sanitize_terminal_line(&exe);
    println!("  this_binary={exe_clean}");
    println!("  argv0_hint: `raven` and `ash` are the same program (`ash` is the short name)");
    println!(
        "  data_dir={}",
        sanitize_terminal_line(&data_dir.display().to_string())
    );
    let messaging_path_fail = print_messaging_path_diag().is_err();
    print_production_gate_matrix();
    {
        let cfg = raven_core::load_bootstrap(data_dir);
        println!(
            "  bootstrap: use_raven_defaults={} effective_peers={} manual_only_ok={}",
            cfg.use_raven_defaults,
            cfg.effective_peers().len(),
            cfg.manual_peer_only_ok()
        );
    }

    let ep = ipc_endpoint(data_dir);
    println!(
        "  ipc_transport: {}",
        match &ep {
            IpcEndpoint::NamedPipe(_) => "named_pipe",
            IpcEndpoint::UnixSocket(_) => "uds",
            IpcEndpoint::Unsupported => "missing",
        }
    );
    println!("  ipc_endpoint={}", sanitize_terminal_line(&ep.to_string()));
    match &ep {
        IpcEndpoint::UnixSocket(sock) => {
            println!(
                "  file_present: ipc_endpoint={} {}",
                sanitize_terminal_line(&sock.display().to_string()),
                if sock.exists() { "yes" } else { "no" }
            );
        }
        IpcEndpoint::NamedPipe(_) => {
            println!("  file_present: raven-node.sock not_probed");
        }
        IpcEndpoint::Unsupported => {
            println!("  file_present: ipc_endpoint not_probed");
        }
    }

    let presence = probe_daemon_presence(data_dir);
    print_presence(&presence);

    let status = if matches!(presence, DaemonPresence::Present { .. }) {
        Some(probe_ipc_status(data_dir))
    } else {
        None
    };
    if let Some(st) = status.as_ref() {
        match st {
            Ok(IpcResponse::Status {
                v,
                bridge,
                store,
                relay,
                forward_pending,
                capabilities,
            }) => {
                println!(
                    "  ipc_status: ok v={v} bridge={bridge} store={store} relay={relay} forward_pending={forward_pending} caps={}",
                    capabilities.join(",")
                );
            }
            Ok(_) => println!("  ipc_status: unexpected ipc response"),
            Err(e) => {
                println!("  ipc_status: fail ({})", sanitize_terminal_line(e));
            }
        }
    }

    let identity = probe_doctor_identity(data_dir);
    let identity_ok = identity.usable;
    let mut identity_err = identity.identity_err;

    let queue_open = queue_db_openable(data_dir);
    let forward_ok = status
        .as_ref()
        .map(status_forward_pending_ok)
        .unwrap_or(false);
    let queue_or_forward_ok = queue_open || forward_ok;

    for name in [
        "queue.sqlite",
        "queue.db",
        "forward_queue.sqlite",
        "contacts.json",
        "device_registry.json",
        "node_policy.json",
        "bootstrap.json",
    ] {
        let p = data_dir.join(name);
        println!(
            "  file_present: {} {}",
            name,
            if p.exists() { "yes" } else { "no" }
        );
    }
    println!(
        "  queue_db: {}",
        if queue_open { "open" } else { "unopened" }
    );

    let messaging = resolve_terminal_messaging_path();
    let ready = classify_daemon_ready(
        &presence,
        status.as_ref(),
        identity_ok,
        queue_or_forward_ok,
        messaging,
    );
    print_ready(&ready);

    let send = classify_send_path();
    print_send_path(&send);
    println!(
        "  send_path note: doctor never sends a test message; to try sending: echo \"hello\" | ash send --contact NAME"
    );

    println!("  bluetooth: skipped (headless)");
    println!("  nat_class: unknown (BLOCKED_HARDWARE)");
    println!("  relay_hint: policy.relay + bootstrap peers (no Raven-mandatory relay)");

    #[cfg(unix)]
    {
        let bin_ash = Path::new("/bin/ash");
        if bin_ash.exists() {
            println!("  {C_GREEN}note{C_RESET}: /bin/ash exists — Raven must NOT overwrite it");
            println!(
                "  conflict_detection: system ash present; use `raven` or ~/.local/bin/ash → raven"
            );
            if let (Ok(cur), Ok(sys)) =
                (std::fs::canonicalize(&exe), std::fs::canonicalize(bin_ash))
            {
                if cur == sys {
                    println!(
                        "  {C_PURPLE}WARNING{C_RESET}: running binary IS /bin/ash — unexpected"
                    );
                } else {
                    println!("  conflict_ok: this binary ≠ /bin/ash");
                }
            }
        } else {
            println!("  /bin/ash: absent on this host");
        }
        if let Ok(out) = Command::new("sh")
            .args(["-c", "command -v ash; command -v raven"])
            .output()
        {
            let s = String::from_utf8_lossy(&out.stdout);
            for line in s.lines() {
                let clean = sanitize_terminal_line(line);
                println!("  path_which: {clean}");
            }
        }
    }
    match try_load_identity(data_dir) {
        Ok(Some(id)) => {
            println!("  identity: present");
            print_public_identity(&id);
        }
        Ok(None) => println!("  identity: missing (run: ash init)"),
        Err(e) => {
            if identity_err.is_none() {
                identity_err = Some(e.clone());
            }
            println!("  identity: unavailable ({})", sanitize_terminal_line(&e));
        }
    }
    let pol = load_policy(data_dir);
    println!(
        "  policy bridge={} store={} relay={}",
        pol.bridge, pol.store, pol.relay
    );
    println!(
        "{C_DIM}Closing this CLI does not stop raven-node if installed as a service.{C_RESET}"
    );
    println!("{C_DIM}Diagnostics never print private keys, seeds, or plaintext bodies.{C_RESET}");
    println!(
        "{C_DIM}doctor report complete — send_path is not implied by daemon_presence or daemon_ready.{C_RESET}"
    );
    println!("{C_BOLD}Next step:{C_RESET} {next_step}");

    let security = doctor_security_hold(messaging, identity_err.as_deref());
    let hard_failure = messaging_path_fail || identity.hard_fail;
    let code = doctor_exit_code(&ready, require_ready, security.as_deref(), hard_failure);
    if code != DOCTOR_EXIT_OK {
        if let Some(reason) = security {
            eprintln!("doctor: security hold / production gate (reason={reason})");
        } else if messaging_path_fail {
            eprintln!("doctor: messaging_path refused (FastAPI fail-closed)");
        } else if identity.hard_fail {
            eprintln!("doctor: identity not usable");
        } else if require_ready {
            eprintln!("doctor: --require-ready and daemon_ready is false");
        }
        std::process::exit(code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_constants_are_public_https() {
        assert!(LOGO_URL.starts_with("https://raven-messager.com/"));
        assert!(LOGO_64_URL.starts_with("https://raven-messager.com/"));
        assert!(!LOGO_URL.contains("seed"));
        assert!(!LOGO_URL.contains("private"));
    }

    #[test]
    fn contact_session_transport_is_fail_closed() {
        assert!(!contact_session_transport_ready());
    }

    #[test]
    fn welcome_art_has_branding_not_secrets() {
        // The real banner text printed by print_welcome (not a stand-in).
        let art = welcome_banner_text();
        assert!(art.contains("R A V E N"));
        assert!(art.contains("Messaging Beyond Connectivity"));
        assert!(art.contains("https://raven-messager.com"));
        for secret in ["seed", "private_key", "secret", "rvn1", "pub_hex"] {
            assert!(!art.contains(secret), "banner must not show {secret}");
        }
        // Monochrome: no 24-bit brand RGB, and only plain SGR (bold/dim/reset)
        // when colour is on at all.
        assert!(!art.contains("38;2;"));
        if !color_enabled() {
            assert!(!art.contains('\u{1b}'));
        }
        // Every framed line, borders included, has the same width (the old
        // hand-padded box was ragged: 39..54 columns).
        let widths: Vec<usize> = art
            .lines()
            .filter(|l| l.contains(['\u{2502}', '\u{256d}', '\u{2570}']))
            .map(|l| l.chars().count())
            .collect();
        assert_eq!(widths.len(), 13, "{art}");
        assert!(widths.iter().all(|w| *w == widths[0]), "{widths:?}");
    }

    #[test]
    fn no_color_style_is_empty() {
        // Palette consts are plain SGR codes (no 24-bit brand RGB).
        assert!(!C_CYAN.0.contains("38;2"));
        assert!(!C_PURPLE.0.contains("38;2"));
        assert!(!C_GREEN.0.contains("38;2"));
        // color_enabled() is cached per-process (OnceLock), so we can only
        // assert consistency with the current environment, not both branches.
        let colors = c();
        if color_enabled() {
            // Black & white design: accent fields collapse to bold/dim.
            assert_eq!(colors.cyan, colors.bold);
            assert_eq!(colors.purple, colors.bold);
            assert_ne!(colors.yellow, colors.bold);
        } else {
            assert_eq!(colors.cyan, "");
            assert_eq!(colors.bold, "");
            // The C_* palette used by ~100 format strings follows the same switch.
            assert_eq!(format!("{C_BOLD}x{C_RESET}{C_DIM}{C_PURPLE}"), "x");
        }
    }

    #[test]
    fn color_decision_honours_no_color_dumb_term_and_pipes() {
        assert!(color_enabled_for(false, false, true));
        assert!(!color_enabled_for(true, false, true));
        assert!(!color_enabled_for(false, true, true));
        // Output piped / redirected: no escapes.
        assert!(!color_enabled_for(false, false, false));
    }

    #[test]
    fn shell_looking_paste_is_detected() {
        assert!(looks_like_shell_input(
            "export PATH=\"$HOME/.cargo/bin:$PATH\""
        ));
        assert!(looks_like_shell_input("cargo build -p ash"));
        assert!(looks_like_shell_input("DATA=$(mktemp -d)"));
        assert!(looks_like_shell_input("ash --data-dir \"$DATA\" whoami"));
        assert!(!looks_like_shell_input("rvn1qexampleaddressonly"));
        assert!(!looks_like_shell_input(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        ));
        assert!(!looks_like_shell_input("@poline"));
    }

    #[test]
    fn parse_pub_hex_rejects_shell_paste_clearly() {
        let err = parse_pub_hex("export PATH=/usr/bin:$PATH").unwrap_err();
        assert!(err.contains("Terminal shell command"));
        assert!(err.contains("ash whoami"));
        assert!(!err.contains("64 hex"));
    }

    #[test]
    fn bare_pub_hex_is_not_treated_as_alias_token() {
        let hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        assert_eq!(looks_like_bare_pub_hex(hex).as_deref(), Some(hex));
        assert_eq!(
            looks_like_bare_pub_hex(&format!("@{hex}")).as_deref(),
            Some(hex)
        );
        assert!(looks_like_bare_pub_hex("@poline").is_none());
        assert!(looks_like_bare_pub_hex("rvn1qabc").is_none());
        let ed = parse_pub_hex(hex).unwrap();
        let addr = encode_address(&ed);
        assert!(addr.starts_with("rvn1"));
    }

    #[test]
    fn public_whoami_card_has_no_private_key_material() {
        let id = Identity::from_seed(&[0x11; 32]);
        let card = public_whoami_card(&id);
        let raw = card.to_string();
        let lower = raw.to_ascii_lowercase();
        for bad in ["seed", "private_key", "plaintext", "recovery"] {
            assert!(!lower.contains(bad), "{bad} leaked into whoami JSON");
        }
        assert_eq!(card["address"].as_str().unwrap(), id.address());
        assert_eq!(
            card["pub_hex"].as_str().unwrap(),
            hex::encode(id.public_key_bytes())
        );
        assert_eq!(
            card["fingerprint"].as_str().unwrap(),
            device_fingerprint_v1(&id.public_key_bytes())
        );
        assert!(id.address().starts_with("rvn1"));
        assert_eq!(card.as_object().map(|o| o.len()), Some(3));
    }

    #[test]
    fn public_whoami_card_is_user_identity_pin_not_device_ed_pub() {
        let user = Identity::from_seed(&[0x11; 32]);
        let device = Identity::from_seed(&[0x22; 32]);
        let card = public_whoami_card(&user);
        let obj = card.as_object().expect("object");
        assert_eq!(card["address"].as_str().unwrap(), user.address());
        assert_eq!(
            card["address"].as_str().unwrap(),
            encode_address(&user.public_key_bytes())
        );
        assert_ne!(
            card["address"].as_str().unwrap(),
            encode_address(&device.public_key_bytes()),
            "pin RVN1 must be user identity, not a parallel device key"
        );
        assert_ne!(
            card["pub_hex"].as_str().unwrap(),
            hex::encode(device.public_key_bytes())
        );
        assert_eq!(
            card["fingerprint"].as_str().unwrap(),
            device_fingerprint_v1(&user.public_key_bytes())
        );
        assert_ne!(
            card["fingerprint"].as_str().unwrap(),
            device_fingerprint_v1(&device.public_key_bytes())
        );
        assert!(
            !obj.contains_key("device_ed_pub"),
            "G5: pin ≢ device_ed_pub — field must not appear"
        );
        assert!(!obj.contains_key("seed"));
        assert!(!obj.contains_key("private_key"));
    }

    #[test]
    fn whoami_blob_extracts_address_and_pub_hex() {
        let blob = "\
address     rvn1qexampleaddressonlyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
fingerprint ABCD-EFGH-IJKL
pub_hex     d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
";
        // address may fail bech32 decode later — extractor still finds the token
        assert!(extract_address_field(blob).unwrap().starts_with("rvn1"));
        assert_eq!(
            extract_pub_hex_field(blob).unwrap(),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let eq_blob = "address=rvn1qabc\npub_hex=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a\n";
        assert_eq!(extract_address_field(eq_blob).unwrap(), "rvn1qabc");
        assert!(looks_like_lan_dial("127.0.0.1:7420"));
        assert!(looks_like_lan_dial("192.168.1.20:9000"));
        assert!(!looks_like_lan_dial("rvn1qabc"));
        assert!(!looks_like_lan_dial("not-a-dial"));
    }

    #[test]
    fn send_carrier_parses_lan_and_internet_refuses_wan() {
        assert_eq!(
            parse_send_carrier("lan").unwrap(),
            pair_init_lab::DialCarrier::Lan
        );
        assert_eq!(
            parse_send_carrier("internet").unwrap(),
            pair_init_lab::DialCarrier::Internet
        );
        assert!(parse_send_carrier("wan").is_err());
    }

    #[test]
    fn resolve_reuses_saved_lan_dial_without_prompt() {
        let got = resolve_lan_peer_parts("192.168.1.20:7420", None);
        assert_eq!(got, Some(ResolvedLanPeer::Dial("192.168.1.20:7420".into())));
        // Saved wins over env — no stdin involved.
        let got = resolve_lan_peer_parts("10.0.0.2:7420", Some("10.0.0.9:7420"));
        assert_eq!(got, Some(ResolvedLanPeer::Dial("10.0.0.2:7420".into())));
    }

    #[test]
    fn resolve_empty_dial_uses_env_then_errors_without_local_queue() {
        let got = resolve_lan_peer_parts("", Some("192.168.1.50:7420"));
        assert_eq!(got, Some(ResolvedLanPeer::Dial("192.168.1.50:7420".into())));
        assert_eq!(resolve_lan_peer_parts("", None), None);
        assert_eq!(resolve_lan_peer_parts("not-a-dial", None), None);
        assert_eq!(resolve_lan_peer_parts("", Some("rvn1notadial")), None);
    }

    #[test]
    fn corrupt_contacts_json_errors_instead_of_empty_book() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("contacts.json"), "{not-json").unwrap();
        let err = load_contacts(dir.path()).unwrap_err();
        assert!(err.contains("corrupt"), "{err}");
    }

    #[test]
    fn parse_pub_hex_accepts_whoami_line() {
        let line = "pub_hex     d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let got = parse_pub_hex(line).unwrap();
        assert_eq!(
            hex::encode(got),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }

    fn present() -> DaemonPresence {
        DaemonPresence::Present {
            ipc_version: IPC_VERSION,
        }
    }

    fn status_ok() -> Result<IpcResponse, String> {
        Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: vec!["ipc".into()],
        })
    }

    #[test]
    fn doctor_presence_ping_is_present_not_up() {
        assert_eq!(
            classify_presence_from_ping(Ok(IpcResponse::Pong { v: IPC_VERSION })),
            DaemonPresence::Present {
                ipc_version: IPC_VERSION
            }
        );
        assert_eq!(
            classify_presence_from_ping(Ok(IpcResponse::Accepted { v: IPC_VERSION })),
            DaemonPresence::Down {
                reason: "unexpected_ipc_response".into()
            }
        );
        assert_eq!(
            classify_presence_from_ping(Err("dial failed".into())),
            DaemonPresence::Down {
                reason: "dial failed".into()
            }
        );
        let blocked = DaemonPresence::Blocked {
            reason: "ipc_transport_missing",
        };
        assert_eq!(
            format!(
                "  daemon_presence: blocked (reason={})",
                match &blocked {
                    DaemonPresence::Blocked { reason } => *reason,
                    _ => unreachable!(),
                }
            ),
            "  daemon_presence: blocked (reason=ipc_transport_missing)"
        );
        assert_eq!(
            classify_daemon_ready(&blocked, None, true, true, MessagingPath::ServerlessRvn1,),
            DaemonReady::NotReady {
                reason: "ipc_transport_blocked".into()
            }
        );
        let ep = ipc_endpoint(std::path::Path::new("/tmp/raven-data"));
        if cfg!(windows) {
            // Per-user pipe: `{WINDOWS_NAMED_PIPE}-{user SID}`.
            assert!(matches!(ep, IpcEndpoint::NamedPipe(_)));
            assert!(ep
                .to_string()
                .starts_with(&format!("{}-S-1-", raven_core::WINDOWS_NAMED_PIPE)));
            assert!(!ep.to_string().contains("raven-node.sock"));
            assert!(ep.transport_available());
        } else if cfg!(unix) {
            assert!(matches!(ep, IpcEndpoint::UnixSocket(_)));
            assert!(ep.to_string().ends_with("raven-node.sock"));
            assert!(ep.transport_available());
        } else {
            assert_eq!(ep, IpcEndpoint::Unsupported);
            assert!(!ep.transport_available());
        }
    }

    #[test]
    fn doctor_presence_is_not_ready_or_send() {
        let ready =
            classify_daemon_ready(&present(), None, true, true, MessagingPath::ServerlessRvn1);
        assert_eq!(
            ready,
            DaemonReady::NotReady {
                reason: "status_unchecked".into()
            }
        );
        assert_eq!(
            classify_send_path(),
            SendPathLabel::NotReady {
                reason: "not_probed".into()
            }
        );
    }

    #[test]
    fn doctor_ready_requires_status_identity_queue_and_serverless() {
        let st = status_ok();
        assert!(status_forward_pending_ok(&st));
        assert_eq!(
            classify_daemon_ready(
                &present(),
                Some(&st),
                true,
                true,
                MessagingPath::ServerlessRvn1,
            ),
            DaemonReady::Ready
        );
        assert_eq!(
            classify_daemon_ready(
                &DaemonPresence::Down {
                    reason: "dial failed".into()
                },
                Some(&st),
                true,
                true,
                MessagingPath::ServerlessRvn1,
            ),
            DaemonReady::NotReady {
                reason: "no_presence".into()
            }
        );
        assert_eq!(
            classify_daemon_ready(
                &present(),
                Some(&st),
                false,
                true,
                MessagingPath::ServerlessRvn1,
            ),
            DaemonReady::NotReady {
                reason: "identity_unusable".into()
            }
        );
    }

    #[test]
    fn doctor_send_path_never_green_from_ready() {
        match classify_send_path() {
            SendPathLabel::NotReady { reason } => assert_eq!(reason, "not_probed"),
            SendPathLabel::Unchecked => {}
        }
    }

    #[test]
    fn doctor_exit_codes_follow_core_gate() {
        let ready = DaemonReady::Ready;
        let not_ready = DaemonReady::NotReady {
            reason: "no_presence".into(),
        };
        assert_eq!(doctor_exit_code(&ready, false, None, false), DOCTOR_EXIT_OK);
        assert_eq!(
            doctor_exit_code(&not_ready, false, None, false),
            DOCTOR_EXIT_OK
        );
        assert_eq!(
            doctor_exit_code(&not_ready, true, None, false),
            DOCTOR_EXIT_HARD
        );
        assert_eq!(doctor_exit_code(&ready, true, None, false), DOCTOR_EXIT_OK);
        assert_eq!(
            doctor_exit_code(&ready, false, None, true),
            DOCTOR_EXIT_HARD
        );
        assert_eq!(
            doctor_exit_code(&ready, false, Some("identity_continuity"), false),
            DOCTOR_EXIT_SECURITY
        );
    }

    #[test]
    fn doctor_security_hold_is_continuity_not_fastapi() {
        assert_eq!(
            doctor_security_hold(MessagingPath::LegacyFastApi, None),
            None
        );
        assert_eq!(
            doctor_security_hold(
                MessagingPath::ServerlessRvn1,
                Some("identity continuity violation")
            )
            .as_deref(),
            Some("identity_continuity")
        );
    }

    #[test]
    fn doctor_identity_usable_is_not_file_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("identity.seed"), b"not-a-usable-seed").unwrap();
        assert!(!identity_usable(dir.path()));
    }

    #[test]
    fn doctor_identity_usable_false_on_locked_file_without_env() {
        if std::env::var_os("RAVEN_IDENTITY_BACKEND").is_some_and(|v| v == "locked-file") {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("identity.backend"), b"locked-file\n").unwrap();
        let report = raven_core::identity_usable(dir.path()).unwrap();
        assert!(!report.usable);
        assert!(report.consistency.blocks_identity_use());
        assert!(!identity_usable(dir.path()));
        assert_eq!(
            classify_daemon_ready(
                &present(),
                Some(&status_ok()),
                identity_usable(dir.path()),
                true,
                MessagingPath::ServerlessRvn1,
            ),
            DaemonReady::NotReady {
                reason: "identity_unusable".into()
            }
        );
    }

    #[test]
    fn m3_lan_dial_sealed_banner_is_honest() {
        let b = M3_LAN_DIAL_SEALED_BANNER;
        assert!(b.contains("NON-RELEASE"));
        assert!(b.contains("HOLD"));
        assert!(b.contains("already-sealed"));
        assert!(b.contains("Not O6 E2E Proven"));
        assert!(b.contains("dial≠WAN") || b.contains("dial!=WAN"));
        assert!(!b.contains("confidential Proven"));
    }

    #[test]
    fn doctor_messaging_path_refuses_legacy_fastapi() {
        let err = assert_no_silent_fastapi(MessagingPath::LegacyFastApi).unwrap_err();
        assert!(err.contains("FastAPI"));
        let ready = DaemonReady::NotReady {
            reason: "messaging_path=legacy_fastapi".into(),
        };
        assert_eq!(
            doctor_exit_code(&ready, false, None, true),
            DOCTOR_EXIT_HARD
        );
    }

    // ── g9 regression tests: invite / add_contact / send picker / display ──

    fn ident(seed: u8) -> Identity {
        Identity::from_seed(&[seed; 32])
    }

    fn invite_for(id: &Identity) -> String {
        format!(
            "raven:{}:{}",
            id.address(),
            hex::encode(id.public_key_bytes())
        )
    }

    fn seed_book(dir: &Path) -> Vec<Contact> {
        let a = ident(0x0a);
        let b = ident(0x0b);
        add_contact(
            dir,
            &a.address(),
            &hex::encode(a.public_key_bytes()),
            "Alice",
            "alice",
            Some(&device_fingerprint_v1(&a.public_key_bytes())),
            "192.168.1.20:7420",
        )
        .unwrap();
        add_contact(
            dir,
            &b.address(),
            &hex::encode(b.public_key_bytes()),
            "Bob",
            "",
            None,
            "",
        )
        .unwrap();
        load_contacts(dir).unwrap()
    }

    #[test]
    fn invite_add_keeps_existing_contacts_pins_and_dials() {
        let dir = tempfile::tempdir().unwrap();
        let before = seed_book(dir.path());
        let carol = ident(0x0c);
        let invite = parse_raven_invite(&invite_for(&carol)).unwrap().unwrap();
        commit_invite_contact(dir.path(), &invite, "Carol", false).unwrap();
        let after = load_contacts(dir.path()).unwrap();
        assert_eq!(after.len(), 3, "invite must merge, not replace the book");
        for old in &before {
            let kept = after.iter().find(|c| c.pub_hex == old.pub_hex).unwrap();
            assert_eq!(kept.pinned, old.pinned);
            assert_eq!(kept.lan_dial, old.lan_dial);
            assert_eq!(kept.petname, old.petname);
        }
        let c = after.iter().find(|c| c.petname == "Carol").unwrap();
        assert_eq!(c.address, carol.address());
        assert!(!c.pinned);
    }

    #[test]
    fn invite_abort_or_unknown_answer_saves_nothing() {
        // The interactive layer only calls `commit_invite_contact` for an
        // explicit save decision: every other answer must classify as Abort
        // (or the V → type-the-fingerprint step), never as a save.
        let invite = parse_raven_invite(&invite_for(&ident(0x0c)))
            .unwrap()
            .unwrap();
        for answer in ["a", "A", "abort", "q", "x", "yes please", "", "   "] {
            assert_eq!(
                parse_verify_choice(answer, &invite.fingerprint),
                VerifyChoice::Abort,
                "{answer:?}"
            );
        }
        // Pinning: only with the confirmed fingerprint, exactly like the long add path.
        let dir = tempfile::tempdir().unwrap();
        commit_invite_contact(dir.path(), &invite, "Carol", true).unwrap();
        assert!(load_contacts(dir.path()).unwrap()[0].pinned);
    }

    #[test]
    fn invite_rejects_address_key_mismatch_and_bad_hex() {
        let victim = ident(0x0a);
        let attacker = ident(0x0e);
        let forged = format!(
            "raven:{}:{}",
            victim.address(),
            hex::encode(attacker.public_key_bytes())
        );
        let err = parse_raven_invite(&forged).unwrap().unwrap_err();
        assert!(err.contains("mismatch"), "{err}");
        let not_hex = format!("raven:{}:{}", victim.address(), "zz".repeat(32));
        assert!(parse_raven_invite(&not_hex).unwrap().is_err());
        let esc = format!(
            "raven:rvn1\u{1b}]52;c;AAAA\u{7}:{}",
            hex::encode(victim.public_key_bytes())
        );
        assert!(parse_raven_invite(&esc).unwrap().is_err());
        assert!(parse_raven_invite("rvn1qabc").is_none());
        // whoami `invite` label and upper-case hex are accepted and normalised.
        let labelled = format!(
            "invite        raven:{}:{}",
            victim.address(),
            hex::encode_upper(victim.public_key_bytes())
        );
        let ok = parse_raven_invite(&labelled).unwrap().unwrap();
        assert_eq!(ok.pub_hex, hex::encode(victim.public_key_bytes()));
        assert_eq!(
            ok.fingerprint,
            device_fingerprint_v1(&victim.public_key_bytes())
        );
    }

    #[test]
    fn invite_save_errors_propagate_and_keep_corrupt_book() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("contacts.json"), "{not-json").unwrap();
        let invite = parse_raven_invite(&invite_for(&ident(0x0c)))
            .unwrap()
            .unwrap();
        let err = commit_invite_contact(dir.path(), &invite, "Carol", false).unwrap_err();
        assert!(err.contains("corrupt"), "{err}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("contacts.json")).unwrap(),
            "{not-json"
        );
    }

    #[test]
    fn invite_cannot_rebind_pinned_identity_to_new_key() {
        let dir = tempfile::tempdir().unwrap();
        seed_book(dir.path());
        // A pinned @alice stays authoritative: same tag, different key refused.
        let mallory = ident(0x0e);
        let err = add_contact(
            dir.path(),
            &mallory.address(),
            &hex::encode(mallory.public_key_bytes()),
            "Alice (new phone)",
            "alice",
            None,
            "",
        )
        .unwrap_err();
        assert_eq!(err, "KEY_CHANGE_REFUSED_WITHOUT_REPIN");
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 2);
    }

    #[test]
    fn verify_choice_is_strict() {
        let fp = "If4x-36FU-omFi";
        // `v` alone never pins: the fingerprint has to be typed back.
        assert_eq!(
            parse_verify_choice("v", fp),
            VerifyChoice::ConfirmFingerprint
        );
        assert_eq!(
            parse_verify_choice(" Verify ", fp),
            VerifyChoice::ConfirmFingerprint
        );
        assert_eq!(
            parse_verify_choice("pin", fp),
            VerifyChoice::ConfirmFingerprint
        );
        assert_eq!(parse_verify_choice(fp, fp), VerifyChoice::Pin);
        assert_eq!(parse_verify_choice("if4x36fuomfi", fp), VerifyChoice::Pin);
        assert_eq!(parse_verify_choice("C", fp), VerifyChoice::Unpinned);
        assert_eq!(parse_verify_choice("continue", fp), VerifyChoice::Unpinned);
        // An empty answer (stray Enter / pasted blank line) is NOT a decision.
        assert_eq!(parse_verify_choice("", fp), VerifyChoice::Abort);
        assert_eq!(parse_verify_choice("a", fp), VerifyChoice::Abort);
        assert_eq!(parse_verify_choice("vv", fp), VerifyChoice::Abort);
        assert_eq!(parse_verify_choice("If4x-36FU", fp), VerifyChoice::Abort);
    }

    const VERIFY_FP: &str = "If4x-36FU-omFi";

    /// `verify_prompt_flow` fed like `read_decision_line`: leftover whoami
    /// lines are skipped, a stream that ends before an answer is `None`.
    fn run_verify_flow(code: Option<&str>, answers: &[&str]) -> Option<bool> {
        let mut it = lines(answers).into_iter();
        verify_prompt_flow(VERIFY_FP, code, &mut || {
            pick_answer_line_checked(&mut it, AnswerKind::Free)
        })
    }

    #[test]
    fn confirm_code_is_typeable_and_not_derived_from_the_contact() {
        use rand::rngs::mock::StepRng;
        let a = new_confirm_code(&mut StepRng::new(
            0x1234_5678_9abc_def0,
            0x9e37_79b9_7f4a_7c15,
        ));
        let b = new_confirm_code(&mut StepRng::new(
            0x8765_4321_0fed_cba9,
            0x9e37_79b9_7f4a_7c15,
        ));
        assert_ne!(a, b, "the code follows the rng, nothing else");
        for code in [&a, &b] {
            assert_eq!(code.len(), CONFIRM_CODE_LEN);
            assert!(
                code.bytes().all(|c| CONFIRM_CODE_ALPHABET.contains(&c)),
                "{code}"
            );
        }
        // Nothing to mistake for something else when reading it off a screen.
        assert!(CONFIRM_CODE_ALPHABET
            .iter()
            .all(|c| !b"01OIL".contains(c) && !c.is_ascii_lowercase()));
        assert_eq!(
            CONFIRM_CODE_ALPHABET.len(),
            CONFIRM_CODE_ALPHABET
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        );
    }

    #[test]
    fn confirm_code_match_forgives_form_not_content() {
        assert!(confirm_code_matches("K7Q4M", "K7Q4M"));
        assert!(confirm_code_matches("  k7q-4m ", "K7Q4M"));
        assert!(!confirm_code_matches("", "K7Q4M"));
        assert!(!confirm_code_matches("---", "K7Q4M"));
        assert!(!confirm_code_matches("K7Q4", "K7Q4M"));
        assert!(!confirm_code_matches("K7Q4MM", "K7Q4M"));
        assert!(!confirm_code_matches("K7Q4N", "K7Q4M"));
    }

    #[test]
    fn pasted_card_cannot_answer_the_confirmation_code() {
        // Everything the author of a pasted contact card knows or can type.
        let id = ident(0x66);
        let pasted = [
            "c".to_string(),
            "v".to_string(),
            "y".to_string(),
            "yes".to_string(),
            "continue".to_string(),
            "confirm".to_string(),
            String::new(),
            VERIFY_FP.to_string(),
            VERIFY_FP.to_ascii_lowercase(),
            hex::encode(id.public_key_bytes()),
            id.address(),
        ];
        let code = Some("K7Q4M");
        for guess in &pasted {
            for choice in [&["c"][..], &["v", VERIFY_FP], &[VERIFY_FP]] {
                let mut answers = choice.to_vec();
                answers.push(guess);
                assert_eq!(run_verify_flow(code, &answers), None, "{answers:?}");
            }
        }
        // Padding with whoami lines (they are skipped as leftovers) buys the
        // paste nothing: the next real line still has to be the code.
        let pad = "fingerprint AAAA-BBBB-CCCC-DDDD";
        for n in 0..8 {
            let mut answers = vec!["c"];
            answers.extend(std::iter::repeat_n(pad, n));
            answers.extend(["v", VERIFY_FP, "c"]);
            assert_eq!(run_verify_flow(code, &answers), None, "pad {n}");
        }
        // The stream ending at the code prompt is not an answer either.
        assert_eq!(run_verify_flow(code, &["c"]), None);
        assert_eq!(run_verify_flow(code, &["v", VERIFY_FP]), None);
        // A wrong fingerprint aborts before the code is even asked.
        assert_eq!(
            run_verify_flow(code, &["v", "AAAA-BBBB-CCCC", "K7Q4M"]),
            None
        );
    }

    #[test]
    fn typed_confirmation_code_completes_every_save() {
        let code = Some("K7Q4M");
        assert_eq!(run_verify_flow(code, &["c", "k7q4m"]), Some(false));
        assert_eq!(
            run_verify_flow(code, &["v", VERIFY_FP, "K7Q-4M"]),
            Some(true)
        );
        assert_eq!(run_verify_flow(code, &[VERIFY_FP, "K7Q4M"]), Some(true));
        // Aborting at the choice never reaches the code.
        assert_eq!(run_verify_flow(code, &["a", "K7Q4M"]), None);
        assert_eq!(run_verify_flow(code, &["", "K7Q4M"]), None);
    }

    #[test]
    fn piped_stdin_script_keeps_the_choice_only_flow() {
        // No terminal, no code: scripts (menu smoke, tests) drive c / v + fp.
        assert_eq!(run_verify_flow(None, &["c"]), Some(false));
        assert_eq!(run_verify_flow(None, &["v", VERIFY_FP]), Some(true));
        assert_eq!(run_verify_flow(None, &[""]), None);
        assert_eq!(run_verify_flow(None, &[]), None);
        assert_eq!(run_verify_flow(None, &["v"]), None);
    }

    #[test]
    fn typed_fingerprint_must_match_the_whole_thing() {
        let fp = "If4x-36FU-omFi";
        assert!(fingerprint_matches("If4x-36FU-omFi", fp));
        assert!(fingerprint_matches("  if4x 36fu omfi ", fp));
        assert!(!fingerprint_matches("", fp));
        assert!(!fingerprint_matches("---", fp));
        assert!(!fingerprint_matches("If4x-36FU", fp));
        assert!(!fingerprint_matches("If4x-36FU-omFj", fp));
    }

    #[test]
    fn eof_is_not_an_answer_but_an_empty_line_is() {
        // Trust decisions use the checked picker: a stream that ends before any
        // answer arrives is None, never "" (which parse_verify_choice aborts
        // and the optional prompts treat as "skip").
        assert_eq!(
            pick_answer_line_checked(Vec::<String>::new(), AnswerKind::Free),
            None
        );
        assert_eq!(
            pick_answer_line_checked(lines(&[""]), AnswerKind::Free),
            Some(String::new())
        );
        let id = ident(0x0a);
        // Only leftover whoami lines, then EOF: still no answer.
        assert_eq!(
            pick_answer_line_checked(lines(&[&invite_for(&id)]), AnswerKind::Free),
            None
        );
        assert_eq!(
            pick_answer_line_checked(lines(&[&invite_for(&id), "c"]), AnswerKind::Free),
            Some("c".to_string())
        );
        // The lenient wrapper folds EOF into an empty answer (optional prompts).
        assert_eq!(pick_answer_line(Vec::<String>::new(), AnswerKind::Free), "");
    }

    #[test]
    fn first_run_identity_needs_a_real_yes() {
        // EOF / closed stdin never creates an identity.
        assert!(!first_run_answer_accepts(None, true));
        assert!(!first_run_answer_accepts(None, false));
        // On a terminal Enter takes the [Y] default; piped input must be explicit.
        assert!(first_run_answer_accepts(Some(""), true));
        assert!(!first_run_answer_accepts(Some(""), false));
        for yes in ["y", "Y", "yes", "YES"] {
            assert!(first_run_answer_accepts(Some(yes), false), "{yes}");
            assert!(first_run_answer_accepts(Some(yes), true), "{yes}");
        }
        for no in ["n", "no", "yep", "sure", "1"] {
            assert!(!first_run_answer_accepts(Some(no), true), "{no}");
            assert!(!first_run_answer_accepts(Some(no), false), "{no}");
        }
    }

    #[test]
    fn leftover_whoami_lines_are_not_answers() {
        let id = ident(0x0a);
        assert!(is_whoami_paste_line(&format!(
            "invite        {}",
            invite_for(&id)
        )));
        assert!(is_whoami_paste_line(&invite_for(&id)));
        assert!(is_whoami_paste_line("fingerprint If4x-36FU-omFi"));
        assert!(is_whoami_paste_line(&format!(
            "pub_hex     {}",
            hex::encode(id.public_key_bytes())
        )));
        assert!(is_whoami_paste_line(&format!(
            "address     {}",
            id.address()
        )));
        for answer in [
            "",
            "poline",
            "Address Book Guy",
            "c",
            "V",
            "192.168.1.20:7420",
        ] {
            assert!(!is_whoami_paste_line(answer), "{answer}");
        }
    }

    fn lines(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn pub_hex_prompt_accepts_labelled_whoami_line() {
        // Regression: the pub_hex prompt must not swallow `pub_hex  <hex>`
        // (that hung the TTY and shifted every later answer by one prompt).
        let id = ident(0x0a);
        let hex_pub = hex::encode(id.public_key_bytes());
        let labelled = format!("pub_hex       {}", hex_pub.to_uppercase());
        assert_eq!(
            pick_answer_line(lines(&[&labelled, "poline"]), AnswerKind::PubHex),
            hex_pub
        );
        // A whole whoami block pasted at the pub_hex prompt: address and
        // fingerprint are skipped, the pub_hex line is the answer.
        let addr = format!("address       {}", id.address());
        let fp = format!(
            "fingerprint   {}",
            device_fingerprint_v1(&id.public_key_bytes())
        );
        assert_eq!(
            pick_answer_line(lines(&[&addr, &fp, &labelled]), AnswerKind::PubHex),
            hex_pub
        );
        // Bare hex and the invite line both reduce to the pub.
        assert_eq!(
            pick_answer_line(lines(&[&hex_pub]), AnswerKind::PubHex),
            hex_pub
        );
        let inv = format!("invite        {}", invite_for(&id));
        assert_eq!(
            pick_answer_line(lines(&[&inv]), AnswerKind::PubHex),
            hex_pub
        );
        // A broken invite is handed back (add then fails) instead of skipped.
        let other = ident(0x0b);
        let bad = format!(
            "raven:{}:{}",
            id.address(),
            hex::encode(other.public_key_bytes())
        );
        let got = pick_answer_line(lines(&[&bad, "later"]), AnswerKind::PubHex);
        assert_eq!(got, bad);
        assert!(parse_pub_hex(&got).is_err());
        // Garbage / shell text is returned verbatim so the caller rejects it.
        assert_eq!(
            pick_answer_line(lines(&["nope", &hex_pub]), AnswerKind::PubHex),
            "nope"
        );
        let shell = format!("export X={hex_pub}");
        assert_eq!(
            pick_answer_line(lines(&[&shell]), AnswerKind::PubHex),
            shell
        );

        // Free prompts (tag / petname / dial / choice) still skip every
        // leftover whoami line, including the labelled pub_hex one.
        assert_eq!(
            pick_answer_line(lines(&[&labelled, &inv, "poline"]), AnswerKind::Free),
            "poline"
        );
        assert_eq!(pick_answer_line(lines(&[""]), AnswerKind::Free), "");
        // Bounded: never loops forever on a stream of leftovers.
        let many: Vec<String> = std::iter::repeat_n(labelled.clone(), 20).collect();
        assert_eq!(pick_answer_line(many, AnswerKind::Free), "");
    }

    #[test]
    fn add_contact_validates_tag_charset_and_unique_petname() {
        let dir = tempfile::tempdir().unwrap();
        seed_book(dir.path());
        let carol = ident(0x0c);
        let c_hex = hex::encode(carol.public_key_bytes());
        let err = add_contact(
            dir.path(),
            &carol.address(),
            &c_hex,
            "Carol",
            "invite raven:x",
            None,
            "",
        )
        .unwrap_err();
        assert!(err.contains("@tag rejected"), "{err}");
        let err =
            add_contact(dir.path(), &carol.address(), &c_hex, "bob", "", None, "").unwrap_err();
        assert!(err.contains("already used"), "{err}");
        let err = add_contact(
            dir.path(),
            &carol.address(),
            &c_hex,
            "Carol",
            "",
            None,
            "evil\u{1b}[2J:7420",
        )
        .unwrap_err();
        assert!(err.contains("lan_dial"), "{err}");
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 2);
        add_contact(
            dir.path(),
            &carol.address(),
            &c_hex,
            "Carol",
            "@Carol",
            None,
            "",
        )
        .unwrap();
        let book = load_contacts(dir.path()).unwrap();
        assert_eq!(book.len(), 3);
        assert_eq!(book[2].public_tag, "carol");
        // Re-adding the same key under its own petname is an update, not a clash.
        add_contact(dir.path(), &carol.address(), &c_hex, "carol", "", None, "").unwrap();
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 3);
    }

    #[test]
    fn send_picker_never_silently_picks_among_duplicates() {
        let a = ident(0x0a);
        let b = ident(0x0b);
        let row = |id: &Identity, pet: &str, tag: &str| Contact {
            petname: pet.into(),
            public_tag: tag.into(),
            alias: tag.into(),
            address: id.address(),
            pub_hex: hex::encode(id.public_key_bytes()),
            pinned: false,
            lan_dial: String::new(),
        };
        let book = vec![
            row(&a, "Ahmad (Berlin)", "ahmad"),
            row(&b, "Ahmad (Tehran)", "ahmad"),
        ];
        assert_eq!(
            pick_send_contact(&book, "@ahmad"),
            SendPick::Ambiguous(vec![0, 1])
        );
        assert_eq!(
            pick_send_contact(&book, "@AHMAD"),
            SendPick::Ambiguous(vec![0, 1])
        );
        assert_eq!(pick_send_contact(&book, "2"), SendPick::One(1));
        assert_eq!(pick_send_contact(&book, "ahmad (tehran)"), SendPick::One(1));
        assert_eq!(pick_send_contact(&book, "3"), SendPick::NoMatch);
        assert_eq!(pick_send_contact(&book, "0"), SendPick::NoMatch);
        assert_eq!(pick_send_contact(&book, "@nobody"), SendPick::NoMatch);
        let legacy_dupes = vec![row(&a, "Ahmad", ""), row(&b, "ahmad", "")];
        assert_eq!(
            pick_send_contact(&legacy_dupes, "Ahmad"),
            SendPick::Ambiguous(vec![0, 1])
        );
    }

    #[test]
    fn menu_send_uses_secure_pair_init_path() {
        // Menu send is ext::run_send_secure (PairInit / indexed session), never
        // a raven-node `--body-mode unsafe-interim` child: its own validation
        // answers before any process is spawned or dial attempted.
        let dir = tempfile::tempdir().unwrap();
        let me = ident(0x01);
        let peer = ident(0x02);
        let peer_hex = hex::encode(peer.public_key_bytes());
        let err = menu_send_secure(dir.path(), &me, "not-a-dial", &peer_hex, "hi").unwrap_err();
        assert!(err.contains("lan_dial host:port required"), "{err}");
        let err = menu_send_secure(dir.path(), &me, "127.0.0.1:9", "zz", "hi").unwrap_err();
        assert!(err.contains("pub_hex"), "{err}");
        let mut blocks = BlockList::load_checked(dir.path()).unwrap();
        blocks.block(&peer_hex);
        blocks.save(dir.path()).unwrap();
        let err = menu_send_secure(dir.path(), &me, "127.0.0.1:9", &peer_hex, "hi").unwrap_err();
        assert!(err.contains("block list"), "{err}");
    }

    #[test]
    fn inbox_rows_are_attributed_and_single_line() {
        let a = ident(0x0a);
        let stranger = ident(0x0f);
        let book = vec![Contact {
            petname: "Alice".into(),
            public_tag: String::new(),
            alias: String::new(),
            address: a.address(),
            pub_hex: hex::encode(a.public_key_bytes()),
            pinned: true,
            lan_dial: String::new(),
        }];
        let mid = [0xabu8; 16];
        let forged =
            b"ok\r  \xe2\x86\x92 1a2b3c4d I agree to pay\n  \xe2\x86\x90 99999999 Alice: hi";
        let line = format_inbox_row(
            &book,
            &a.public_key_bytes(),
            &mid,
            forged,
            "5 min ago",
            None,
        );
        assert!(!line.contains('\r') && !line.contains('\n'), "{line:?}");
        assert!(line.contains("Alice"));
        assert!(line.contains("pinned"));
        assert!(line.contains(&device_fingerprint_v1(&a.public_key_bytes())));
        let line = format_inbox_row(
            &book,
            &stranger.public_key_bytes(),
            &mid,
            b"This is Alice: pay",
            "",
            None,
        );
        assert!(line.contains("unknown device"), "{line}");
        assert!(line.contains(&device_fingerprint_v1(&stranger.public_key_bytes())));
        assert!(!line.contains("Alice ["), "{line}");
    }

    fn history_row(direction: &str, delivery: &str) -> raven_core::ChatHistoryEntry {
        raven_core::ChatHistoryEntry {
            message_id_hex: "aa".repeat(16),
            direction: direction.into(),
            peer_petname: "Bob".into(),
            peer_tag: String::new(),
            peer_pub_hex: "bb".repeat(32),
            created_at_ms: 1,
            delivery: delivery.into(),
            preview: "hi".into(),
            body: "hi".into(),
        }
    }

    /// A queued or failed message must not look like a delivered one in the chat
    /// dump or `ash messages` (both render through `delivery_suffix`).
    #[test]
    fn outbound_rows_show_their_delivery_state_unless_delivered() {
        assert_eq!(delivery_suffix(&history_row("out", "queued")), " [queued]");
        assert_eq!(delivery_suffix(&history_row("out", "failed")), " [failed]");
        assert_eq!(delivery_suffix(&history_row("out", "delivered")), "");
        assert_eq!(delivery_suffix(&history_row("out", "")), "");
        // Inbound rows carry "received": never annotated.
        assert_eq!(delivery_suffix(&history_row("in", "received")), "");
        // The state is sanitised like any other terminal text.
        let hostile = delivery_suffix(&history_row("out", "failed\x1b[2J\nfake"));
        assert!(
            !hostile.contains('\x1b') && !hostile.contains('\n'),
            "{hostile:?}"
        );
    }

    #[test]
    fn explicit_ephemeral_data_dir_is_never_remapped() {
        for p in [
            "/var/folders/xy/abc/T/tmp.XXXX123",
            "/tmp/raven-ash-menu-abc",
            "/private/var/folders/q/T/tmp.1",
        ] {
            assert_eq!(resolve_data_dir(p), Ok(PathBuf::from(p)));
        }
        assert_eq!(resolve_data_dir("  "), default_ash_data_dir());
    }

    /// No `--data-dir`, no override and no usable HOME: an error that says what
    /// to set, not a placeholder path whose first use fails with ENOTDIR.
    #[test]
    fn unresolvable_default_profile_is_an_up_front_error() {
        let err = resolve_data_dir_with("", || {
            raven_core::paths::try_resolve_raven_data_dir(None, None, None)
        })
        .unwrap_err();
        assert!(
            err.contains("cannot determine the Raven data directory"),
            "{err}"
        );
        assert!(
            err.contains("RAVEN_DATA_DIR") && err.contains("--data-dir"),
            "{err}"
        );
        assert!(err.contains("HOME"), "{err}");
        // An explicit directory never consults the default.
        assert_eq!(
            resolve_data_dir_with("/some/profile", || -> Result<PathBuf, String> {
                panic!("default must not be consulted")
            }),
            Ok(PathBuf::from("/some/profile"))
        );
    }

    /// Defence in depth: even a caller that kept the infallible placeholder
    /// can never make ash create a profile tree under it.
    #[test]
    fn the_unresolved_profile_placeholder_is_never_created() {
        let placeholder = raven_core::resolve_raven_data_dir(None, None, None);
        assert!(raven_core::paths::is_unresolved_data_dir(&placeholder));
        let err = create_private_data_dir(&placeholder).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("cannot determine"), "{err}");
    }

    #[test]
    fn private_data_dir_is_created_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a/b/profile");
        create_private_data_dir(&nested).unwrap();
        assert!(nested.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700);
        }
    }

    #[test]
    fn k_route_is_never_taken_from_argv() {
        let err =
            resolve_k_route_hex(Some("00ff"), false, Some("aa".into()), String::new).unwrap_err();
        assert!(err.contains("REFUSE"), "{err}");
        assert_eq!(
            resolve_k_route_hex(None, false, Some(" 00ff \n".into()), String::new).unwrap(),
            "00ff"
        );
        assert_eq!(
            resolve_k_route_hex(None, true, None, || "abcd".to_string()).unwrap(),
            "abcd"
        );
        assert!(resolve_k_route_hex(None, false, None, String::new).is_err());
    }

    #[test]
    fn nearby_store_drops_expired_and_legacy_tokens() {
        let now = 1_000_000u64;
        let live = NearbyAdvertisement::mint(now - 10_000, 60_000, b"t");
        let dead = NearbyAdvertisement::mint(now - 120_000, 60_000, b"t");
        let raw = serde_json::to_string(&vec![
            serde_json::to_value(NearbyTokenJson::from_adv(&live)).unwrap(),
            serde_json::to_value(NearbyTokenJson::from_adv(&dead)).unwrap(),
            serde_json::Value::String("00112233445566778899aabbccddeeff".into()),
        ])
        .unwrap();
        let got = load_live_nearby_ads(&raw, now);
        assert_eq!(got, vec![live.clone()]);
        // Original expiry is kept (no fresh TTL on reload).
        assert!(load_live_nearby_ads(&raw, now + 60_000).is_empty());
        assert!(load_live_nearby_ads("[\"00112233445566778899aabbccddeeff\"]", now).is_empty());
    }

    #[test]
    fn alias_claim_store_refuses_to_overwrite_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = alias_store_path(dir.path());
        std::fs::write(&path, "[{broken").unwrap();
        let id = ident(0x0a);
        let rec = AliasRecord {
            alias: "alice".into(),
            identity_address: id.address(),
            sequence: 1,
            expires_at: now_ms() + 60_000,
            signature: [0u8; 64],
            ed25519_pub: id.public_key_bytes(),
        }
        .sign(&id)
        .unwrap();
        let err = save_alias_claim(dir.path(), &rec).unwrap_err();
        assert!(err.contains("corrupt"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[{broken");
    }

    #[test]
    fn escape_bytes_classify_without_blocking_on_next_key() {
        assert!(classify_escape(&[]) == MenuKey::Escape);
        assert!(classify_escape(b"[A") == MenuKey::Up);
        assert!(classify_escape(b"[B") == MenuKey::Down);
        assert!(classify_escape(b"OA") == MenuKey::Up);
        assert!(classify_escape(b"[1;5A") == MenuKey::Up);
        assert!(classify_escape(b"[1;2B") == MenuKey::Down);
        assert!(classify_escape(b"[5~") == MenuKey::Other);
        assert!(classify_escape(b"[") == MenuKey::Other);
        assert!(classify_escape(b"q") == MenuKey::Escape);
    }

    /// Feed `bytes` one read at a time; 0 once exhausted (= timeout).
    fn drain(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut rest = bytes.to_vec();
        let tail = read_escape_tail(|buf| {
            if rest.is_empty() {
                0
            } else {
                buf[0] = rest.remove(0);
                1
            }
        });
        (tail, rest)
    }

    #[test]
    fn escape_tail_consumes_whole_sequence_only() {
        // Ctrl+Up: the whole CSI is consumed, the next key ('2') is not.
        assert_eq!(drain(b"[1;5A2"), (b"[1;5A".to_vec(), b"2".to_vec()));
        assert_eq!(drain(b"[B"), (b"[B".to_vec(), vec![]));
        assert_eq!(drain(b"OAq"), (b"OA".to_vec(), b"q".to_vec()));
        // Bare Esc (timeout) consumes nothing; Alt+x consumes just 'x'.
        assert_eq!(drain(b""), (vec![], vec![]));
        assert_eq!(drain(b"x1"), (b"x".to_vec(), b"1".to_vec()));
        // Bounded even for a hostile never-ending parameter run.
        let long = [b"[".as_slice(), &[b'1'; 40]].concat();
        assert_eq!(drain(&long).0.len(), 16);
    }

    #[test]
    fn lan_dial_rejects_control_bytes() {
        assert!(looks_like_lan_dial("192.168.1.20:7420"));
        assert!(looks_like_lan_dial("mac-mini.local:7420"));
        assert!(looks_like_lan_dial("[fe80::1%en0]:7420"));
        assert!(!looks_like_lan_dial("evil\u{1b}[2J:7420"));
        assert!(!looks_like_lan_dial("host\u{202e}:7420"));
        assert!(!looks_like_lan_dial("host:0"));
    }

    #[test]
    fn strict_and_lenient_pub_hex_share_one_decoder() {
        let hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
        let want = parse_pub_hex_strict(hex).unwrap();
        assert_eq!(parse_pub_hex_strict(&hex.to_uppercase()).unwrap(), want);
        assert_eq!(parse_pub_hex(&format!("pub_hex     {hex}")).unwrap(), want);
        // Strict (wire / IPC) never accepts the whoami label form.
        assert!(parse_pub_hex_strict(&format!("pub_hex {hex}")).is_err());
    }

    // ── fixer D regression tests: exit codes, trust prompts, contact book ──

    fn book_row(id: &Identity, pet: &str, tag: &str) -> Contact {
        Contact {
            petname: pet.into(),
            public_tag: tag.into(),
            alias: tag.into(),
            address: id.address(),
            pub_hex: hex::encode(id.public_key_bytes()),
            pinned: false,
            lan_dial: String::new(),
        }
    }

    fn status_with_caps(caps: &[&str]) -> Result<IpcResponse, String> {
        Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: false,
            store: false,
            relay: false,
            forward_pending: 0,
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
        })
    }

    #[test]
    fn listener_ready_needs_lan_direct_in_ipc_status() {
        // IPC answering is not enough: the IPC task can be up (or about to
        // fail on the instance lock) before the LAN port is bound.
        assert!(!status_reports_lan_listener(&status_with_caps(&["ipc"])));
        assert!(status_reports_lan_listener(&status_with_caps(&[
            "ipc",
            "lan_direct",
            "store"
        ])));
        assert!(!status_reports_lan_listener(&Ok(IpcResponse::Pong {
            v: IPC_VERSION
        })));
        assert!(!status_reports_lan_listener(&Err("dial failed".into())));
    }

    #[cfg(unix)]
    fn spawn_sh(script: &str) -> std::process::Child {
        Command::new("sh")
            .args(["-c", script])
            .stdin(std::process::Stdio::null())
            .spawn()
            .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn listen_wait_reports_an_early_exit_never_ready() {
        // A service that dies on startup is an exit (with its status), not LISTENING.
        let mut child = spawn_sh("exit 3");
        let got = wait_for_listener(
            &mut child,
            Duration::from_secs(60),
            Duration::from_millis(2),
            Duration::ZERO,
            || false,
        );
        match got {
            ListenWait::Exited(st) => assert_eq!(st.code(), Some(3)),
            other => panic!("{other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn listen_wait_is_ready_while_the_child_lives_and_times_out_otherwise() {
        let mut child = spawn_sh("sleep 60");
        let got = wait_for_listener(
            &mut child,
            Duration::from_secs(60),
            Duration::from_millis(2),
            Duration::ZERO,
            || true,
        );
        assert!(matches!(got, ListenWait::Ready), "{got:?}");
        // The listener never reports up: a bounded wait ends in TimedOut
        // (the caller warns instead of announcing LISTENING).
        let got = wait_for_listener(
            &mut child,
            Duration::from_millis(30),
            Duration::from_millis(2),
            Duration::ZERO,
            || false,
        );
        assert!(matches!(got, ListenWait::TimedOut), "{got:?}");
        child.kill().unwrap();
        child.wait().unwrap();
    }

    fn signed_claim(id: &Identity, alias: &str, sequence: u64) -> AliasRecord {
        AliasRecord {
            alias: alias.into(),
            identity_address: id.address(),
            sequence,
            expires_at: now_ms() + 60_000,
            signature: [0u8; 64],
            ed25519_pub: id.public_key_bytes(),
        }
        .sign(id)
        .unwrap()
    }

    #[test]
    fn alias_publish_never_regresses_the_stored_sequence() {
        let dir = tempfile::tempdir().unwrap();
        let id = ident(0x0a);
        let addr = id.address();
        save_alias_claim(dir.path(), &signed_claim(&id, "alice", 5)).unwrap();
        // A refresh published with the old default (1), or a replay (5), is
        // refused: peers holding seq 5 would reject it as ALIAS_STALE_SEQUENCE.
        for seq in [1, 4, 5] {
            let err = save_alias_claim(dir.path(), &signed_claim(&id, "alice", seq)).unwrap_err();
            assert!(err.contains("ALIAS_STALE_SEQUENCE"), "{err}");
        }
        let rows = read_alias_rows(dir.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(stored_alias_sequence(&rows, "alice", &addr), Some(5));
        // Higher sequences replace the row; other aliases / identities are independent.
        save_alias_claim(dir.path(), &signed_claim(&id, "alice", 6)).unwrap();
        save_alias_claim(dir.path(), &signed_claim(&id, "bob", 1)).unwrap();
        save_alias_claim(dir.path(), &signed_claim(&ident(0x0b), "alice", 1)).unwrap();
        let rows = read_alias_rows(dir.path()).unwrap();
        assert_eq!(stored_alias_sequence(&rows, "alice", &addr), Some(6));
        assert_eq!(stored_alias_sequence(&rows, "bob", &addr), Some(1));
        assert_eq!(stored_alias_sequence(&rows, "carol", &addr), None);
        assert_eq!(rows.len(), 3);
    }

    #[test]
    fn lan_tip_skips_unusable_addresses() {
        assert!(usable_lan_ipv4("192.168.1.20"));
        assert!(usable_lan_ipv4("10.0.0.5"));
        for bad in [
            "",
            "127.0.0.1",
            "169.254.3.4",
            "0.0.0.0",
            "fe80::1",
            "not-an-ip",
        ] {
            assert!(!usable_lan_ipv4(bad), "{bad:?}");
        }
    }

    #[test]
    fn pick_is_one_based_and_never_clamps_to_the_first_candidate() {
        assert_eq!(pick_index(1, 3), Some(0));
        assert_eq!(pick_index(3, 3), Some(2));
        assert_eq!(pick_index(0, 3), None);
        assert_eq!(pick_index(4, 3), None);
        assert_eq!(pick_index(1, 0), None);
    }

    #[test]
    fn re_adding_a_contact_keeps_its_labels_and_pin() {
        let dir = tempfile::tempdir().unwrap();
        seed_book(dir.path());
        let a = ident(0x0a);
        let a_hex = hex::encode(a.public_key_bytes());
        let find = |dir: &Path| {
            load_contacts(dir)
                .unwrap()
                .into_iter()
                .find(|c| c.pub_hex == a_hex)
                .unwrap()
        };
        // The documented dial-refresh workflow: only address + key + dial given.
        add_contact(
            dir.path(),
            &a.address(),
            &a_hex,
            "",
            "",
            None,
            "192.168.1.31:7420",
        )
        .unwrap();
        let alice = find(dir.path());
        assert_eq!(alice.petname, "Alice");
        assert_eq!(alice.public_tag, "alice");
        assert_eq!(alice.alias, "alice");
        assert!(alice.pinned);
        assert_eq!(alice.lan_dial, "192.168.1.31:7420");
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 2);
        // An explicit petname still overrides; the omitted tag is kept.
        add_contact(dir.path(), &a.address(), &a_hex, "Alice B", "", None, "").unwrap();
        let alice = find(dir.path());
        assert_eq!(alice.petname, "Alice B");
        assert_eq!(alice.public_tag, "alice");
        assert_eq!(alice.lan_dial, "192.168.1.31:7420");
        // A petname-only contact stays petname-only.
        let b = ident(0x0b);
        add_contact(
            dir.path(),
            &b.address(),
            &hex::encode(b.public_key_bytes()),
            "",
            "",
            None,
            "",
        )
        .unwrap();
        let book = load_contacts(dir.path()).unwrap();
        let bob = book.iter().find(|c| c.petname == "Bob").unwrap();
        assert_eq!(bob.public_tag, "");
        assert!(!bob.pinned);
    }

    #[test]
    fn lone_at_sign_selects_nobody() {
        let a = ident(0x0a);
        let b = ident(0x0b);
        let book = vec![book_row(&a, "Alice", "alice"), book_row(&b, "Bob", "")];
        for q in ["@", "@@", " @ "] {
            assert!(resolve_tag_contacts(&book, q).is_empty(), "{q:?}");
            assert!(resolve_alias_contacts(&book, q).is_empty(), "{q:?}");
            assert_eq!(pick_send_contact(&book, q), SendPick::NoMatch, "{q:?}");
        }
        // Real tags still resolve.
        assert_eq!(resolve_tag_contacts(&book, "@alice").len(), 1);
        assert_eq!(pick_send_contact(&book, "@Alice"), SendPick::One(0));
        // `ash send --contact @` must not reach the petname-only contact.
        let dir = tempfile::tempdir().unwrap();
        save_contacts(dir.path(), &book).unwrap();
        let err = resolve_send_target(dir.path(), "@", "", "", "127.0.0.1:0").unwrap_err();
        assert!(err.contains("no contact for"), "{err}");
    }

    #[test]
    fn env_dial_is_resolved_but_never_written_to_the_contact() {
        let dir = tempfile::tempdir().unwrap();
        seed_book(dir.path());
        let book = load_contacts(dir.path()).unwrap();
        let alice = book.iter().find(|c| c.petname == "Alice").unwrap();
        let bob = book.iter().find(|c| c.petname == "Bob").unwrap();
        let before = std::fs::read(dir.path().join("contacts.json")).unwrap();
        // No saved dial: the env dial is used, flagged "not saved", and the
        // book is untouched (it used to be stamped onto whoever was picked).
        assert_eq!(
            resolve_or_reuse_lan_dial_with(bob, Some("10.9.9.9:7420".into())),
            Some((ResolvedLanPeer::Dial("10.9.9.9:7420".into()), true))
        );
        assert_eq!(
            std::fs::read(dir.path().join("contacts.json")).unwrap(),
            before
        );
        // A saved dial wins (documented) and is not flagged for saving.
        assert_eq!(
            resolve_or_reuse_lan_dial_with(alice, Some("10.9.9.9:7420".into())),
            Some((ResolvedLanPeer::Dial("192.168.1.20:7420".into()), false))
        );
        assert_eq!(resolve_or_reuse_lan_dial_with(bob, None), None);
    }

    #[test]
    fn forward_queue_status_does_not_hide_failures() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("forward_queue.sqlite");
        assert_eq!(forward_queue_view(&path), ForwardQueueView::Absent);
        assert!(forward_queue_line(&ForwardQueueView::Absent).contains("no queue file"));
        ForwardQueue::open(&path).unwrap();
        assert_eq!(
            forward_queue_view(&path),
            ForwardQueueView::Counts {
                pending: 0,
                total: 0
            }
        );
        assert_eq!(
            forward_queue_line(&ForwardQueueView::Counts {
                pending: 2,
                total: 5
            }),
            "2 pending / 5 total"
        );
        // A queue that exists but cannot be opened is NOT "0 pending / 0 total".
        std::fs::write(&path, b"this is not a sqlite database, just text padding").unwrap();
        let view = forward_queue_view(&path);
        assert!(matches!(view, ForwardQueueView::Unavailable(_)), "{view:?}");
        let line = forward_queue_line(&view);
        assert!(line.contains("unavailable"), "{line}");
        assert!(!line.contains("0 pending"), "{line}");
    }

    #[test]
    fn stdin_message_is_bounded_and_trimmed() {
        assert_eq!(
            read_message_text(&b"hello\r\n\n"[..], 100).unwrap(),
            "hello"
        );
        assert_eq!(
            read_message_text(&b"hi\nthere\n"[..], 100).unwrap(),
            "hi\nthere"
        );
        assert_eq!(read_message_text(&b""[..], 100).unwrap(), "");
        // Exactly the limit (plus the trailing newline) fits; one byte more does not.
        let exact = format!("{}\n", "a".repeat(100));
        assert_eq!(read_message_text(exact.as_bytes(), 100).unwrap().len(), 100);
        let over = "a".repeat(101);
        let err = read_message_text(over.as_bytes(), 100).unwrap_err();
        assert!(err.contains("too large"), "{err}");
        // An endless pipe stops at the cap instead of being buffered forever.
        let err = read_message_text(std::io::repeat(b'a'), 100).unwrap_err();
        assert!(err.contains("too large"), "{err}");
        assert_eq!(
            read_message_text(&[0xff, 0xfe][..], 100).unwrap_err(),
            "failed to read message from stdin"
        );
    }

    #[test]
    fn node_flag_keeps_unnamed_flags_and_repairs_an_unreadable_policy() {
        let dir = tempfile::tempdir().unwrap();
        // A readable policy: only the named flag changes.
        let p = NodePolicy {
            bridge: false,
            store: true,
            relay: true,
            endpoint: true,
            auto_policy: true,
        };
        save_policy(dir.path(), &p).unwrap();
        set_node_flag(dir.path(), "bridge", true);
        let got = try_load_policy(dir.path()).unwrap();
        assert!(got.bridge && got.store && got.relay);
        assert!(!got.auto_policy);
        // Unreadable policy: the command still repairs the file (fail-closed
        // base, only the named flag on) — and warns about the reset flags.
        std::fs::write(raven_core::node_policy::policy_path(dir.path()), "{broken").unwrap();
        set_node_flag(dir.path(), "bridge", true);
        let got = try_load_policy(dir.path()).unwrap();
        assert!(got.bridge && !got.store && !got.relay && !got.auto_policy);
    }

    #[test]
    fn styled_terminal_rows_close_their_styles() {
        let cc = Colors {
            bold: "\x1b[1m",
            dim: "\x1b[2m",
            reset: "\x1b[0m",
            cyan: "\x1b[1m",
            purple: "\x1b[1m",
            green: "\x1b[1m",
            yellow: "\x1b[2m",
            red: "\x1b[1m",
        };
        // Tutorial footer: dim label, bold command, one trailing reset (the
        // arguments were swapped, leaving everything after it dim).
        assert_eq!(
            tutorial_footer(&cc),
            "  \x1b[2mFull diagnostics anytime: \x1b[1mash doctor\x1b[0m"
        );
        // Menu prompt row: its bold is closed again.
        assert_eq!(arrow_menu_prompt(&cc), "raven \x1b[1m❯ \x1b[0m");
    }

    #[test]
    fn accept_keeps_the_request_until_bind_and_wire_are_durable() {
        use raven_core::contact_request::{ContactAcceptV1, ContactBinding};
        let dir = tempfile::tempdir().unwrap();
        let me = ident(0x0b);
        let sender = ident(0x0a);
        let other = ident(0x0c);
        // "Alice" is already a different contact: the bind must fail.
        add_contact(
            dir.path(),
            &other.address(),
            &hex::encode(other.public_key_bytes()),
            "Alice",
            "",
            None,
            "",
        )
        .unwrap();
        let rid = [0x42u8; 16];
        let pending = contact_inbox_dir(dir.path()).join(format!("{}.wire", hex::encode(rid)));
        std::fs::create_dir_all(pending.parent().unwrap()).unwrap();
        std::fs::write(&pending, b"pending request").unwrap();
        let accept = ContactAcceptV1 {
            request_id: rid,
            accepter_raven_id: String::new(),
            requester_raven_id: sender.address(),
            accepted_at: 1,
            signature: [0u8; 64],
            accepter_pub: [0u8; 32],
        }
        .sign(&me)
        .unwrap();
        let mut outcome = ContactAcceptOutcome {
            accept,
            binding: ContactBinding {
                raven_id: sender.address(),
                pub_hex: hex::encode(sender.public_key_bytes()),
                petname: "Alice".into(),
                verification_state: VerificationState::TrustedContact,
            },
        };
        let accept_wire = dir
            .path()
            .join(format!("contact_accept_{}.wire", hex::encode(rid)));
        let err = finish_contact_accept(dir.path(), &rid, &outcome).unwrap_err();
        assert!(
            err.contains("bind failed") && err.contains("already used"),
            "{err}"
        );
        assert!(
            pending.exists(),
            "request must stay pending after a failed bind"
        );
        assert!(!accept_wire.exists());
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 1);
        // Retry with a free petname: bound, accept wire written, request gone.
        outcome.binding.petname = "Alice 2".into();
        let out = finish_contact_accept(dir.path(), &rid, &outcome).unwrap();
        assert_eq!(out, accept_wire);
        assert!(accept_wire.exists());
        assert!(!pending.exists());
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 2);
        // Re-running after the request is gone is harmless (same key row replaced).
        finish_contact_accept(dir.path(), &rid, &outcome).unwrap();
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 2);
    }

    #[test]
    fn contact_remove_is_the_explicit_path_to_re_pin_a_changed_key() {
        let dir = tempfile::tempdir().unwrap();
        seed_book(dir.path());
        let mallory = ident(0x0e);
        let m_hex = hex::encode(mallory.public_key_bytes());
        let m_fp = device_fingerprint_v1(&mallory.public_key_bytes());
        let add_new = |fp: Option<&str>| {
            add_contact(
                dir.path(),
                &mallory.address(),
                &m_hex,
                "Alice (new phone)",
                "alice",
                fp,
                "",
            )
        };
        assert_eq!(
            add_new(Some(&m_fp)).unwrap_err(),
            "KEY_CHANGE_REFUSED_WITHOUT_REPIN"
        );
        // Selectors that name nobody (or everybody) remove nothing.
        assert!(cmd_contact_remove(dir.path(), None, None, None, true).is_err());
        assert!(cmd_contact_remove(dir.path(), None, Some("nobody"), None, true).is_err());
        assert!(cmd_contact_remove(dir.path(), Some("@"), None, None, true).is_err());
        assert!(cmd_contact_remove(dir.path(), None, Some(""), None, true).is_err());
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 2);
        // Remove the old pinned row by petname, then re-pin the new key.
        cmd_contact_remove(dir.path(), None, Some("alice"), None, true).unwrap();
        let book = load_contacts(dir.path()).unwrap();
        assert_eq!(book.len(), 1);
        assert_eq!(book[0].petname, "Bob");
        add_new(Some(&m_fp)).unwrap();
        let book = load_contacts(dir.path()).unwrap();
        assert!(book
            .iter()
            .any(|c| c.pinned && c.public_tag == "alice" && c.pub_hex == m_hex));
    }

    #[test]
    fn contact_remove_never_guesses_among_several_matches() {
        let dir = tempfile::tempdir().unwrap();
        let a = ident(0x0a);
        let b = ident(0x0b);
        save_contacts(
            dir.path(),
            &[
                book_row(&a, "Ahmad (Berlin)", "ahmad"),
                book_row(&b, "Ahmad (Tehran)", "ahmad"),
            ],
        )
        .unwrap();
        let err = cmd_contact_remove(dir.path(), Some("ahmad"), None, None, true).unwrap_err();
        assert!(err.contains("2 contacts match"), "{err}");
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 2);
        // A unique selector works (address form).
        cmd_contact_remove(dir.path(), None, None, Some(&a.address()), true).unwrap();
        assert_eq!(load_contacts(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn contact_unblock_reverses_a_block_and_refuses_unknown_keys() {
        let dir = tempfile::tempdir().unwrap();
        let peer = ident(0x0d);
        let peer_hex = hex::encode(peer.public_key_bytes());
        let mut blocks = BlockList::load_checked(dir.path()).unwrap();
        blocks.block(&peer_hex);
        blocks.save(dir.path()).unwrap();
        cmd_contact_unblock(dir.path(), &peer_hex).unwrap();
        assert!(!BlockList::load_checked(dir.path())
            .unwrap()
            .is_blocked(&peer_hex));
        let err = cmd_contact_unblock(dir.path(), &peer_hex).unwrap_err();
        assert!(err.contains("not on the block list"), "{err}");
        assert!(cmd_contact_unblock(dir.path(), "zz").is_err());
        // A corrupt list is never overwritten.
        let path = raven_core::chat_history::blocked_path(dir.path());
        std::fs::write(&path, "{broken").unwrap();
        let err = cmd_contact_unblock(dir.path(), &peer_hex).unwrap_err();
        assert!(err.contains("block list"), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{broken");
    }

    #[test]
    fn set_dial_refreshes_only_the_dial() {
        let dir = tempfile::tempdir().unwrap();
        seed_book(dir.path());
        let a = ident(0x0a);
        cmd_contact_set_dial(
            dir.path(),
            None,
            None,
            Some(&a.address()),
            "192.168.1.31:7420",
        )
        .unwrap();
        let book = load_contacts(dir.path()).unwrap();
        let alice = book.iter().find(|c| c.petname == "Alice").unwrap();
        assert_eq!(alice.lan_dial, "192.168.1.31:7420");
        assert_eq!(alice.public_tag, "alice");
        assert!(alice.pinned);
        // Bad dials and unknown contacts change nothing.
        let before = std::fs::read(dir.path().join("contacts.json")).unwrap();
        assert!(
            cmd_contact_set_dial(dir.path(), Some("@alice"), None, None, "evil\u{1b}[2J:7420")
                .is_err()
        );
        assert!(
            cmd_contact_set_dial(dir.path(), None, Some("Zed"), None, "10.0.0.1:7420").is_err()
        );
        assert!(cmd_contact_set_dial(dir.path(), Some("@"), None, None, "10.0.0.1:7420").is_err());
        assert_eq!(
            std::fs::read(dir.path().join("contacts.json")).unwrap(),
            before
        );
    }
    // ── plain-language screens ──────────────────────────────────────────────

    #[test]
    fn a_first_run_answer_that_is_neither_yes_nor_no_is_asked_again() {
        for unclear in ["ok", "yea", "da", "بله", "غ", "yes please", " "] {
            assert!(first_run_answer_is_unclear(Some(unclear)), "{unclear:?}");
            assert!(
                !first_run_answer_accepts(Some(unclear), true),
                "{unclear:?}"
            );
            assert!(
                !first_run_answer_accepts(Some(unclear), false),
                "{unclear:?}"
            );
        }
        for clear in ["y", "Y", "yes", "YES", "n", "N", "no", "No"] {
            assert!(!first_run_answer_is_unclear(Some(clear)), "{clear:?}");
        }
        // EOF is no answer and Enter is the default: neither is "unclear".
        assert!(!first_run_answer_is_unclear(None));
        assert!(!first_run_answer_is_unclear(Some("")));
        // Whatever it is, an empty answer on a pipe and EOF never create one.
        assert!(!first_run_answer_accepts(None, true));
        assert!(!first_run_answer_accepts(Some(""), false));
    }

    #[test]
    fn short_age_reads_in_plain_words() {
        let now = 10_000_000_000u64;
        assert_eq!(short_age(now, now), "just now");
        assert_eq!(short_age(now, now - 59_999), "just now");
        assert_eq!(short_age(now, now - 60_000), "1 min ago");
        assert_eq!(short_age(now, now - 5 * 60_000), "5 min ago");
        assert_eq!(short_age(now, now - 3_600_000), "1 h ago");
        assert_eq!(short_age(now, now - 23 * 3_600_000), "23 h ago");
        assert_eq!(short_age(now, now - 3 * 86_400_000), "3 d ago");
        // A clock that ran backwards is not a time in the future.
        assert_eq!(short_age(now, now + 5_000_000), "just now");
        // No timestamp, no age.
        assert_eq!(short_age(now, 0), "");
    }

    #[test]
    fn inbox_rows_lead_with_age_and_name_not_with_ids_and_pin_jargon() {
        let a = ident(0x0a);
        let b = ident(0x0b);
        let mk = |petname: &str, who: &Identity, pinned: bool| Contact {
            petname: petname.into(),
            public_tag: String::new(),
            alias: String::new(),
            address: who.address(),
            pub_hex: hex::encode(who.public_key_bytes()),
            pinned,
            lan_dial: String::new(),
        };
        let book = vec![mk("Alice", &a, false), mk("Bobby", &b, true)];
        let mid = [0xabu8; 16];
        let line = format_inbox_row(
            &book,
            &a.public_key_bytes(),
            &mid,
            "سلام، می\u{200c}خواهم بیایم".as_bytes(),
            "5 min ago",
            None,
        );
        // Who and when come first; the id is last; no "unpinned fp=" on the row.
        assert!(line.starts_with("  5 min ago  from Alice"), "{line}");
        assert!(line.ends_with("[abababab]"), "{line}");
        assert!(
            !line.contains("unpinned") && !line.contains("fp="),
            "{line}"
        );
        assert!(line.contains("(not verified)"), "{line}");
        // Persian text and the ZWNJ come through byte-exact.
        assert!(line.contains("سلام، می\u{200c}خواهم بیایم"), "{line}");
        // A verified contact still reads `Name [pinned ...` (scripts grep it).
        let pinned = format_inbox_row(&book, &b.public_key_bytes(), &mid, b"hi", "", None);
        assert!(pinned.contains("Bobby [pinned fp="), "{pinned}");
        assert!(pinned.starts_with("  from Bobby"), "{pinned}");
        // Never wrapped or split across lines.
        assert!(!line.contains('\n') && !pinned.contains('\n'));
    }

    #[test]
    fn long_bodies_are_clipped_only_on_request() {
        let long = "x".repeat(50);
        assert_eq!(clip_body(long.clone(), None), long);
        assert_eq!(clip_body(long.clone(), Some(50)), long);
        let clipped = clip_body(long.clone(), Some(10));
        assert!(clipped.starts_with(&"x".repeat(10)), "{clipped}");
        assert!(clipped.ends_with("(+40 more characters)"), "{clipped}");
        // Clipping counts characters, never splits one.
        let persian = "س".repeat(30);
        let clipped = clip_body(persian, Some(5));
        assert!(clipped.starts_with(&"س".repeat(5)) && clipped.contains("(+25 more"));
    }

    #[test]
    fn history_rows_say_who_to_whom_and_whether_it_arrived() {
        let now = 5_000_000_000u64;
        let mut e = history_row("out", "queued");
        e.created_at_ms = now - 120_000;
        e.body = "see you at five".into();
        let row = format_history_row(&e, now, None);
        assert!(
            row.starts_with("  2 min ago  you \u{2192} Bob: see you at five"),
            "{row}"
        );
        assert!(row.contains(" [queued]"), "{row}");
        assert!(row.ends_with("[aaaaaaaa]"), "{row}");
        let delivered = format_history_row(&history_row("out", "delivered"), now, None);
        assert!(!delivered.contains("[queued]") && !delivered.contains("[failed]"));
        let incoming = format_history_row(&history_row("in", "received"), now, None);
        assert!(incoming.contains("Bob \u{2192} you"), "{incoming}");
        let failed = format_history_row(&history_row("out", "failed"), now, None);
        assert!(failed.contains(" [failed]"), "{failed}");
        // The body is shown when there is one; the 120-char preview only for old rows.
        assert!(format_history_row(&history_row("out", "queued"), now, None).contains(": hi"));
    }

    fn book_with(names: &[(&str, &str)]) -> Vec<Contact> {
        names
            .iter()
            .enumerate()
            .map(|(i, (petname, tag))| {
                let id = ident(0x20 + i as u8);
                Contact {
                    petname: (*petname).into(),
                    public_tag: (*tag).into(),
                    alias: (*tag).into(),
                    address: id.address(),
                    pub_hex: hex::encode(id.public_key_bytes()),
                    pinned: false,
                    lan_dial: String::new(),
                }
            })
            .collect()
    }

    #[test]
    fn contact_argument_resolves_a_petname_like_the_picker() {
        let book = book_with(&[("Alice", "alice"), ("Bob", ""), ("Carol", "cc")]);
        let name_of = |arg: &str| -> Vec<String> {
            resolve_contact_arg(&book, arg)
                .iter()
                .map(|c| c.petname.clone())
                .collect()
        };
        // Petname, any case, with or without the picker's whitespace.
        assert_eq!(name_of("Bob"), ["Bob"]);
        assert_eq!(name_of("bob"), ["Bob"]);
        assert_eq!(name_of(" BOB "), ["Bob"]);
        // @tag keeps tag semantics (and a petname after @ is not a tag).
        assert_eq!(name_of("@alice"), ["Alice"]);
        assert_eq!(name_of("@ALICE"), ["Alice"]);
        assert!(name_of("@bob").is_empty());
        // A bare word that is no petname still works as a tag.
        assert_eq!(name_of("cc"), ["Carol"]);
        // Nobody: nothing, a lone @ and empty never select an untagged contact.
        for none in ["", " ", "@", "@@", "Zed", "@zed"] {
            assert!(name_of(none).is_empty(), "{none:?}");
        }
        // The petname wins over a tag with the same word.
        let tricky = book_with(&[("alice", "zed"), ("Zed", "alice")]);
        let pet: Vec<_> = resolve_contact_arg(&tricky, "alice")
            .iter()
            .map(|c| c.petname.clone())
            .collect();
        assert_eq!(pet, ["alice"]);
    }

    #[test]
    fn no_contact_message_names_who_exists_and_keeps_its_prefix() {
        let book = book_with(&[("Alice", "alice"), ("Bob", "")]);
        let msg = no_contact_message(&book, "Zed");
        assert!(msg.starts_with("no contact for Zed"), "{msg}");
        assert!(
            msg.contains("Alice (@alice)") && msg.contains("Bob"),
            "{msg}"
        );
        assert!(
            msg.contains("--contact NAME") && msg.contains("--contact @tag"),
            "{msg}"
        );
        let none = no_contact_message(&[], "Zed");
        assert!(none.starts_with("no contact for Zed"), "{none}");
        assert!(
            none.contains("no contacts yet") && none.contains("ash contact add"),
            "{none}"
        );
        // A hostile name cannot smuggle escapes into the line.
        assert!(!no_contact_message(&book, "x\u{1b}[2J").contains('\u{1b}'));
        // Many contacts are capped, with a way to see the rest.
        let many: Vec<(String, String)> =
            (0..12).map(|i| (format!("P{i}"), String::new())).collect();
        let refs: Vec<(&str, &str)> = many.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
        let msg = no_contact_message(&book_with(&refs), "nobody");
        assert!(
            msg.contains("+4 more") && msg.contains("ash contact list"),
            "{msg}"
        );
    }

    fn status_with(caps: &[&str]) -> Result<IpcResponse, String> {
        Ok(IpcResponse::Status {
            v: IPC_VERSION,
            bridge: true,
            store: true,
            relay: false,
            forward_pending: 0,
            capabilities: caps.iter().map(|c| c.to_string()).collect(),
        })
    }

    #[test]
    fn status_says_in_plain_words_whether_this_computer_can_receive() {
        let up = classify_node_reach(&status_with(&["ipc", "lan_direct", "bridge"]));
        assert_eq!(up, NodeReach::SendAndReceive);
        assert!(node_reach_row(&up).starts_with("YES"));
        assert_eq!(node_reach_verdict(&up), "You can send and receive.");

        let deaf = classify_node_reach(&status_with(&["ipc", "bridge"]));
        assert_eq!(deaf, NodeReach::SendOnly);
        assert!(node_reach_row(&deaf).starts_with("NO"));
        assert!(node_reach_verdict(&deaf).starts_with("You can send but NOT receive"));

        let down = classify_node_reach(&Err(
            "raven-node is not running; start it with `ash listen`".into(),
        ));
        assert_eq!(down, NodeReach::NotRunning);
        assert!(node_reach_row(&down).starts_with("NO"));
        let verdict = node_reach_verdict(&down);
        assert!(verdict.starts_with("raven-node is not running: start it with `ash listen`"));

        // A node that answers badly, or not at all, is not "not running".
        for other in [
            Err("raven-node did not answer in time: it is busy or stuck".to_string()),
            Ok(IpcResponse::Pong { v: IPC_VERSION }),
        ] {
            let reach = classify_node_reach(&other);
            assert_eq!(reach, NodeReach::NotAnswering, "{other:?}");
            assert!(node_reach_verdict(&reach).contains("ash doctor"));
        }
        // No row or verdict may use the words `ash status` must not show without
        // a daemon (bridge_abc_demo / cli_failure_paths) or any secret word.
        for reach in [up, deaf, down] {
            for line in [node_reach_row(&reach), node_reach_verdict(&reach)] {
                let low = line.to_lowercase();
                for banned in ["mock_ble", "transports", "seed", "private key", "plaintext"] {
                    assert!(!low.contains(banned), "{line}");
                }
            }
        }
    }

    #[test]
    fn doctor_names_one_next_step_and_the_first_problem_wins() {
        use IdentityState::*;
        let all_up = NodeReach::SendAndReceive;
        assert!(doctor_next_step(Missing, Some(0), &all_up).contains("ash init"));
        assert!(doctor_next_step(Missing, None, &NodeReach::NotRunning).contains("ash init"));
        assert!(doctor_next_step(Unavailable, Some(2), &all_up).contains("identity store"));
        assert!(
            doctor_next_step(Ready, Some(0), &NodeReach::NotRunning).contains("menu 5 Contacts")
        );
        assert!(doctor_next_step(Ready, None, &all_up).contains("contacts file"));
        assert!(doctor_next_step(Ready, Some(2), &NodeReach::NotRunning).contains("ash listen"));
        assert!(doctor_next_step(Ready, Some(2), &NodeReach::SendOnly).contains("NOT receiving"));
        assert!(doctor_next_step(Ready, Some(2), &NodeReach::NotAnswering).contains("not answer"));
        assert!(doctor_next_step(Ready, Some(2), &all_up).contains("ash send --contact NAME"));
    }

    #[test]
    fn a_message_typed_at_a_prompt_is_checked_before_anything_is_sent() {
        // Cursor keys arrive as escape sequences in a cooked terminal line.
        for arrow in [
            "see you at 5 \u{1b}[D\u{1b}[D pm",
            "\u{1b}[H",
            "\u{1b}OA hi",
        ] {
            let problem = tty_message_problem(arrow).expect(arrow);
            assert_eq!(
                problem,
                "cursor keys are not supported in this prompt, retype the message"
            );
        }
        // Other control bytes (NUL, BEL, DEL, backspace) are refused too.
        for ctrl in ["a\u{0}b", "a\u{7}b", "a\u{7f}b", "a\u{8}b"] {
            assert!(tty_message_problem(ctrl).is_some(), "{ctrl:?}");
        }
        // Everything the core accepts passes: Persian, ZWNJ, RLM/LRM, emoji, tab.
        for fine in [
            "hello",
            "سلام، حالت چطوره؟",
            "می\u{200c}خواهم",
            "a\u{200f}b\u{200e}c",
            "👨\u{200d}👩\u{200d}👧 ok",
            "tab\there",
        ] {
            assert_eq!(tty_message_problem(fine), None, "{fine:?}");
        }
    }

    #[test]
    fn menu_hints_are_plain_and_say_when_a_tool_is_local_only() {
        let hints: Vec<&str> = MENU_ITEMS.iter().map(|(_, _, h)| *h).collect();
        for jargon in [
            "committed endpoint",
            "transports",
            "opaque",
            "ephemeral BLE",
            "one command, no flags",
        ] {
            assert!(
                !hints.iter().any(|h| h.contains(jargon)),
                "{jargon:?} in {hints:?}"
            );
        }
        assert!(
            MENU_ITEMS[5].2.contains("this computer only"),
            "{:?}",
            MENU_ITEMS[5]
        );
        assert!(
            MENU_ITEMS[6].2.contains("this computer only"),
            "{:?}",
            MENU_ITEMS[6]
        );
        assert!(
            MENU_ITEMS[6].2.contains("no Bluetooth"),
            "{:?}",
            MENU_ITEMS[6]
        );
        // The numbers scripts and muscle memory use do not move.
        let titles: Vec<&str> = MENU_ITEMS.iter().map(|(_, t, _)| *t).collect();
        assert_eq!(
            titles,
            [
                "Chat / Send",
                "Inbox",
                "Status",
                "Listen",
                "Contacts",
                "Mailbox",
                "Nearby scan",
                "Tutorial"
            ]
        );
    }
    #[test]
    fn the_arrow_menu_footer_lists_quit_once_and_points_new_users_to_the_tutorial() {
        let footer = arrow_menu_footer("", "");
        assert_eq!(footer.matches("quit").count(), 1, "{footer}");
        assert!(footer.starts_with("q  quit"), "{footer}");
        assert!(
            footer.contains("press a number") && footer.contains("press 8"),
            "{footer}"
        );
        // Styles are opened and closed around the hint only.
        assert_eq!(arrow_menu_footer("<d>", "</d>").matches("<d>").count(), 1);
    }
    #[test]
    fn the_listen_screen_says_this_terminal_is_busy_and_how_a_friend_adds_you() {
        // It used to promise "Messages land in menu 2 Inbox" in the one terminal
        // that cannot reach any menu while it listens.
        assert!(
            LISTEN_STAYS_BUSY.contains("second terminal"),
            "{LISTEN_STAYS_BUSY}"
        );
        assert!(
            LISTEN_STAYS_BUSY.contains("`ash inbox`"),
            "{LISTEN_STAYS_BUSY}"
        );
        assert!(
            !LISTEN_STAYS_BUSY.contains("land in menu 2"),
            "{LISTEN_STAYS_BUSY}"
        );
        assert!(LISTEN_INVITE_HINT.contains("add you") && LISTEN_INVITE_HINT.contains("menu 5"));
        assert!(
            LISTEN_INVITE_HINT.contains("`ash whoami`"),
            "{LISTEN_INVITE_HINT}"
        );
    }
}
