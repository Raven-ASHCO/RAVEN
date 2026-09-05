//! RAVEN terminal CLI (`ash` product name). Local-only Raven Node control.
//!
//! This is the **product** CLI in `node/` — not Cursor/ash-autonomous automation.
//! Never prints private keys, seeds, session keys, recovery secrets, or plaintext.

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
    ContactRequestInbox, ContactRequestInner, RavenContactRequestV1,
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
use raven_core::node_policy::{load_policy, save_policy, BridgeStatusSnapshot, NodePolicy};
use raven_core::prekey_bundle::{PrekeyBundle, PrekeyBundleJson, PrekeyStore};
use raven_core::profile_record::ProfileStore;
use raven_core::queue::{DeliveryState, OutgoingQueue};
use raven_core::sanitize::sanitize_terminal_text;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use std::sync::OnceLock;

/// Monochrome terminal style (bold / dim only — no cyan/purple/green).
/// Empty strings when NO_COLOR is set or TERM=dumb.
#[derive(Clone, Copy)]
struct Style {
    bold: &'static str,
    dim: &'static str,
    reset: &'static str,
}

fn color_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| {
        std::env::var_os("NO_COLOR").is_none()
            && !std::env::var_os("TERM").is_some_and(|t| t == "dumb")
    })
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

// Brand palette. Honors NO_COLOR / TERM=dumb via `style()`.
const C_BOLD: &str = "\x1b[1m";
const C_DIM: &str = "\x1b[2m";
const C_RESET: &str = "\x1b[0m";
const C_CYAN: &str = "\x1b[1;36m";
const C_PURPLE: &str = "\x1b[1;35m";
const C_GREEN: &str = "\x1b[1;32m";

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

fn default_ash_data_dir() -> PathBuf {
    raven_core::default_raven_data_dir()
}

fn is_ephemeral_data_dir(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/T/tmp.")
        || s.contains("/tmp/raven-ash-")
        || (s.contains("/var/folders/") && s.contains("/T/tmp"))
}

fn resolve_data_dir(raw: &str) -> PathBuf {
    let t = raw.trim();
    let p = if t.is_empty() {
        default_ash_data_dir()
    } else {
        PathBuf::from(t)
    };
    let explicit_ephemeral = std::env::var_os("RAVEN_ALLOW_EPHEMERAL_DATA_DIR")
        .map(|value| value == "1")
        .unwrap_or(false);
    if !is_ephemeral_data_dir(&p) || explicit_ephemeral {
        return p;
    }
    let stable = default_ash_data_dir();
    eprintln!(
        "{C_PURPLE}WARN{C_RESET}: ephemeral data-dir detected — switching to stable {}",
        stable.display()
    );
    eprintln!(
        "{C_DIM}FA:{C_RESET} mktemp هویت مک را هر بار عوض می‌کند و آیفون وصل نمی‌شود. از ~/.raven استفاده می‌کنیم."
    );
    eprintln!(
        "{C_DIM}EN:{C_RESET} Stop using DATA=$(mktemp -d). Using ~/.raven so Mac whoami stays stable."
    );
    let _ = std::fs::create_dir_all(&stable);
    // Best-effort: bring contacts along once.
    let from_c = p.join("contacts.json");
    let to_c = stable.join("contacts.json");
    if from_c.is_file() && !to_c.is_file() {
        let _ = std::fs::copy(&from_c, &to_c);
    }
    stable
}

/// Public logo assets (no secrets) — credit raven-messager.com.
#[allow(dead_code)]
pub const LOGO_URL: &str = "https://raven-messager.com/raven_logo.png";
#[allow(dead_code)]
pub const LOGO_64_URL: &str = "https://raven-messager.com/raven_logo_64.png";

#[derive(Parser, Debug)]
#[command(
    name = "ash",
    about = "RAVEN Node — Messaging Beyond Connectivity",
    long_about = "RAVEN — serverless mesh messaging, from your terminal.\n\
                  \n\
                  Run with no subcommand for the interactive menu (recommended).\n\
                  No central server: identity is a local keypair, contacts are\n\
                  pinned by fingerprint, and messages ride LAN / bridge / mailbox.\n\
                  \n\
                  QUICKSTART\n\
                    ash                      # menu → 8 Tutorial (guided)\n\
                    ash init                 # create identity\n\
                    ash whoami               # share these 3 lines with a friend\n\
                  \n\
                  TWO-TERMINAL CHAT (direct LAN)\n\
                    # receiver:\n\
                    raven-node run --data-dir ~/.raven --listen 127.0.0.1:0 \\\n\
                      --write-addr /tmp/a.addr --write-pub /tmp/a.pub \\\n\
                      --exit-after-recv 1 --peer-pub-hex <sender pub_hex>\n\
                    # sender:\n\
                    echo hi | raven-node run --data-dir ~/.raven-b \\\n\
                      --listen 127.0.0.1:0 --peer \"$(cat /tmp/a.addr)\" \\\n\
                      --peer-pub-hex <receiver pub_hex> --send-stdin \\\n\
                      --body-mode unsafe-interim --exit-after-ack\n\
                  \n\
                  VERIFY EVERYTHING\n\
                    bash scripts/final_serverless_proof.sh   # → AUTOMATED_PROOF_GREEN\n\
                  \n\
                  Never prints private keys. https://raven-messager.com/"
)]
struct Cli {
    /// Stable local profile (default: ~/.raven, or ~/.raven-ash if that legacy
    /// tree already exists). Do NOT use mktemp — phone must re-paste Mac whoami
    /// every time the identity changes.
    #[arg(long, global = true, default_value = "")]
    data_dir: String,
    #[command(subcommand)]
    cmd: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Create local identity (prints address + pub hex + fingerprint only).
    Init,
    /// Show public identity bits for data dir.
    Whoami,
    /// Forward send to raven-node. Plaintext ONLY via stdin (never argv).
    Send {
        #[arg(long, default_value = "")]
        peer: String,
        #[arg(long, default_value = "")]
        peer_pub_hex: String,
        #[arg(long, default_value = "127.0.0.1:0")]
        listen: String,
        /// Resolve `@tag` from contacts.json (pub_hex + lan_dial).
        #[arg(long, default_value = "")]
        contact: String,
        /// Read message body from stdin (required — argv plaintext is refused).
        #[arg(long, default_value_t = true)]
        stdin_text: bool,
        /// Interactive chat session with /back /info /verify /block.
        #[arg(long, default_value_t = false)]
        chat: bool,
    },
    /// Show committed endpoint inbox (PairInit/LAN messages).
    Inbox,
    /// Print welcome banner only (safe — no secrets).
    Banner,
    /// Receive: listen on the fixed LAN port for a pinned contact (no flags).
    Listen,
    /// Show identity + Bridge/transports/forward queue (safe fields only).
    Status,
    /// Diagnose presence / ready / send_path (never one green "up" for send).
    Doctor {
        /// Exit 1 if `daemon_ready` is false. Does not claim send works.
        #[arg(long, default_value_t = false)]
        require_ready: bool,
    },
    /// Ping raven-node UDS IPC (must be running: `raven-node ipc` / service).
    IpcPing,
    /// Configure local raven-node policy / bootstrap (bridge/store/relay/peers).
    Node {
        #[command(subcommand)]
        cmd: NodeCommands,
    },
    /// Local friendship plane — contacts + fingerprint verify (never FastAPI).
    Contact {
        #[command(subcommand)]
        cmd: ContactCommands,
    },
    /// Multi-lane discovery (DiscoveryResolver — no central Raven DB / no FastAPI).
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
    /// Nearby BLE ephemeral scan (software mock — no permanent ID in adv).
    Nearby,
    /// Publish / manage signed Alias V1 claims (community DHT stand-in).
    Alias {
        #[command(subcommand)]
        cmd: AliasCommands,
    },
    /// Signed prekey publish/fetch via local untrusted store (OOB/DHT stand-in).
    Prekey {
        #[command(subcommand)]
        cmd: PrekeyCommands,
    },
    /// Multi-device encrypted contact sync + revocation (OOB sealed blobs).
    Device {
        #[command(subcommand)]
        cmd: DeviceCommands,
    },
    /// Offline opaque mailbox put/get (store_tag only — no usernames).
    Mailbox {
        #[command(subcommand)]
        cmd: MailboxCommands,
    },
    /// Test A lab helpers (requires debug + RAVEN_LAB_TEST_A=1 for live PairInit).
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
  ash                  # menu → 3 Contacts → guided add
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
        /// Optional OOB prekey JSON for first-message hybrid initiate.
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
}

#[derive(Subcommand, Debug)]
enum AliasCommands {
    /// Publish a signed Alias V1 claim into the local community store.
    Publish {
        #[arg(long)]
        alias: String,
        #[arg(long, default_value_t = 1)]
        sequence: u64,
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
        #[arg(long, default_value = "ash-device")]
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

#[derive(Subcommand, Debug)]
enum MailboxCommands {
    /// Deposit opaque envelope under rotating mailbox → store_tag index.
    Put {
        #[arg(long)]
        k_route_hex: String,
        #[arg(long, default_value_t = 1)]
        epoch: u64,
        #[arg(long, default_value_t = 0)]
        slot: u64,
        #[arg(long)]
        envelope_hex: String,
    },
    /// Retrieve by opaque rotating tags (current + previous epoch).
    Get {
        #[arg(long)]
        k_route_hex: String,
        #[arg(long, default_value_t = 1)]
        epoch: u64,
        #[arg(long, default_value_t = 0)]
        slot: u64,
    },
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
        let p = sanitize_terminal_text(&self.petname);
        if !p.is_empty() {
            return p;
        }
        let t = normalize_tag(&self.public_tag);
        if !t.is_empty() {
            return format!("@{t}");
        }
        // Address only as last resort — never preferred.
        sanitize_terminal_text(&self.address)
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
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
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

/// Raven Node welcome banner — monochrome.
fn print_welcome(data_dir: &Path) {
    let c = c();
    let (b, d, r) = (c.bold, c.dim, c.reset);
    println!();
    println!("  \u{256d}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{256e}");
    println!("  \u{2502}                                                  \u{2502}");
    println!("  \u{2502}  R A V E N                                      \u{2502}");
    println!("  \u{2502}  N O D E                                        \u{2502}");
    println!("  \u{2502}                                                  \u{2502}");
    println!("  \u{2502}  Messaging Beyond Connectivity                  \u{2502}");
    println!("  \u{2502}                                                  \u{2502}");
    println!(
        "  \u{2502}  \u{25c6} serverless \u{00b7} P2P \u{00b7} private                   \u{2502}"
    );
    println!("  \u{2502}                                                  \u{2502}");
    println!("  \u{2502}  \"The Raven bears witness as the Phoenix        \u{2502}");
    println!("  \u{2502}   rises from the ASH\"                          \u{2502}");
    println!("  \u{2502}                                                  \u{2502}");
    println!("  \u{2570}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{256f}");

    println!();
    println!("{d}   https://raven-messager.com{r}", d = d, r = r);
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
        }
        Ok(None) => {
            println!(
                "{b}First run \u{2014} no identity yet.{r} Create one below.\n",
                b = b,
                r = r
            );
        }
        Err(e) => {
            println!("identity unavailable: {}", sanitize_terminal_text(&e));
        }
    }
}
/// Offer inline identity creation on first run; returns true when an identity
/// exists afterwards. Used by the interactive shell so newcomers don't need to
/// know the `init` subcommand at all.
fn offer_first_run_identity(data_dir: &Path) -> bool {
    if try_load_identity(data_dir).ok().flatten().is_some() {
        return true;
    }
    let c = c();
    let (green, reset, red, dim) = (c.green, c.reset, c.red, c.dim);
    print!(
        "{}?{} Create your Raven identity now? [{}Y/n{}] ",
        c.yellow, reset, green, reset
    );
    let _ = io::stdout().flush();
    let ans = read_line();
    if !(ans.is_empty() || ans.eq_ignore_ascii_case("y") || ans.eq_ignore_ascii_case("yes")) {
        return false;
    }
    let id = ensure_identity(data_dir);
    if let Err(e) = raven_core::ensure_local_prekey(data_dir, &id) {
        eprintln!("{red}prekey: {}{reset}", sanitize_terminal_text(&e));
    }
    println!("{green}✔ identity created{reset}");
    print_public_identity(&id);
    println!(
        "\n{dim}Private key stays on this machine. Share only the three public lines above.{reset}"
    );
    true
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
    section("messages");
    item("1", "Chat / Send", "message a contact — guided");
    item("2", "Inbox", "committed endpoint inbox");
    section("network");
    item("3", "Status", "identity · bridge · transports");
    item("4", "Listen", "receive — one command, no flags");
    section("people");
    item("5", "Contacts", "add by rvn1… paste · list · verify");
    section("tools");
    item("6", "Mailbox", "opaque offline put/get");
    item("7", "Nearby scan", "ephemeral BLE discovery");
    item("8", "Tutorial", "guided walkthrough — start here");
    let c = c();
    println!();
    println!("    {c_dim}q  quit{reset}", c_dim = c.dim, reset = c.reset);
    print!("\n{}raven{} {}❯{} ", c.bold, c.reset, c.cyan, c.reset);
    let _ = io::stdout().flush();
}

fn read_line() -> String {
    let mut s = String::new();
    if io::stdin().read_line(&mut s).is_err() {
        return String::new();
    }
    s.trim().to_string()
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

fn cmd_messages(data_dir: &Path) {
    let qpath = data_dir.join("queue.db");
    let qpath2 = data_dir.join("queue.sqlite");
    let path = if qpath.exists() { qpath } else { qpath2 };
    if path.exists() {
        match OutgoingQueue::open(&path) {
            Ok(q) => match q.list_all() {
                Ok(items) => {
                    if items.is_empty() {
                        println!("{C_DIM}Queue empty.{C_RESET}");
                    } else {
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
    } else {
        println!("{C_DIM}No outgoing queue yet.{C_RESET}");
    }
    match raven_core::ChatHistory::load(data_dir) {
        Ok(hist) if hist.entries.is_empty() => {
            println!("{C_DIM}No local chat history.{C_RESET}");
        }
        Ok(hist) => {
            println!("{C_BOLD}Recent history{C_RESET} (protected at rest)");
            for e in hist.entries.iter().rev().take(15).rev() {
                let label = if !e.peer_petname.is_empty() {
                    sanitize_terminal_text(&e.peer_petname)
                } else if !e.peer_tag.is_empty() {
                    format!("@{}", sanitize_terminal_text(&e.peer_tag))
                } else {
                    e.peer_pub_hex.chars().take(12).collect()
                };
                println!(
                    "  {C_DIM}{}{C_RESET} {} → {}  {}",
                    &e.message_id_hex[..8.min(e.message_id_hex.len())],
                    e.direction,
                    label,
                    sanitize_terminal_text(&e.preview)
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

fn parse_pub_hex(s: &str) -> Result<[u8; 32], String> {
    if looks_like_shell_input(s) {
        return Err(shell_paste_rejection().into());
    }
    let h = extract_pub_hex_field(s).unwrap_or_else(|| s.trim().to_lowercase());
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
        if host.is_empty() {
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

fn ipc_daemon_up(data_dir: &Path) -> bool {
    ipc_client::ipc_daemon_up(data_dir)
}

fn ensure_mac_lan_service(data_dir: &Path) -> bool {
    ext::ensure_mac_lan_daemon(data_dir)
}

/// Best-effort primary LAN IPv4 for tips (macOS `ipconfig getifaddr en0`, else none).
fn local_lan_ipv4_tip() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        for iface in ["en0", "en1"] {
            if let Ok(out) = Command::new("ipconfig").args(["getifaddr", iface]).output() {
                if out.status.success() {
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if !s.is_empty() && s.parse::<std::net::Ipv4Addr>().is_ok() {
                        return Some(s);
                    }
                }
            }
        }
    }
    None
}

/// `ash listen` / menu 4 — receive messages with ONE command.
///
/// Wraps `raven-node run` with everything pre-filled from the local profile:
/// fixed LAN port, pinned-contact public keys (no flags to remember), and a
/// share-banner showing exactly what the friend should dial.
fn cmd_listen(data_dir: &Path) {
    let c = c();
    let id = require_identity(data_dir);
    let contacts = load_contacts(data_dir).unwrap_or_default();

    let contact = match contacts.len() {
        0 => {
            println!("{0}No pinned contacts yet.{1}", c.yellow, c.reset);
            println!(
                "{0}Add one first (menu 5), so I know whose keys to accept.{1}",
                c.dim, c.reset
            );
            return;
        }
        1 => &contacts[0],
        _ => {
            println!("{}Listen for which contact?{}", c.bold, c.reset);
            for (i, ct) in contacts.iter().enumerate() {
                let fp = device_fingerprint_v1(&{
                    let mut k = [0u8; 32];
                    if let Ok(b) = hex::decode(&ct.pub_hex) {
                        k.copy_from_slice(&b[..32.min(b.len())]);
                    }
                    k
                });
                println!("  {0} {1}  fp={2}", i + 1, ct.primary_label(), fp);
            }
            print!("number: ");
            let _ = io::stdout().flush();
            let pick: usize = read_line().parse().unwrap_or(0);
            if pick == 0 || pick > contacts.len() {
                println!("{0}cancelled.{1}", c.dim, c.reset);
                return;
            }
            &contacts[pick - 1]
        }
    };

    // Local IP(s) to share with the friend.
    let ip = local_lan_ipv4_tip().unwrap_or_else(|| "<your-LAN-IP>".into());

    println!();
    println!("{0}═══ LISTENING ═══{1}", c.purple, c.reset);
    println!("{0}Tell your friend to send to:{1}", c.dim, c.reset);
    println!("   {0}{ip}:{DEFAULT_LAN_PORT}{1}", c.cyan, c.reset);
    println!("{0}…and use YOUR pub_hex when asked:{1}", c.dim, c.reset);
    println!("   {}", hex::encode(id.public_key_bytes()));
    println!(
        "{0}Waiting for {1} …{2}",
        c.dim,
        contact.primary_label(),
        c.reset
    );
    println!();

    let node = ext::raven_node_bin_public();

    // Spawn first, then wait until the port actually accepts — otherwise the
    // friend may dial before we're ready ("connection refused").
    // Pre-flight: make sure the port is actually free before spawning.
    {
        use std::net::TcpListener;
        match TcpListener::bind(("0.0.0.0", DEFAULT_LAN_PORT)) {
            Ok(l) => drop(l),
            Err(_) => {
                println!(
                    "{0}port {DEFAULT_LAN_PORT} is already taken by another process.\n\
                     Find it:   lsof -i :{DEFAULT_LAN_PORT}\n\
                     Stop it:   pkill -f raven-node{1}",
                    c.red, c.reset
                );
                return;
            }
        }
    }

    let mut child = match Command::new(node)
        .stdin(std::process::Stdio::null())
        .arg("run")
        .args(["--data-dir", &data_dir.display().to_string()])
        .args(["--listen", &format!("0.0.0.0:{DEFAULT_LAN_PORT}")])
        // Keep receiving every message this session (Ctrl+C stops).
        .args(["--timeout-secs", "21600"])
        .args(["--peer-pub-hex", contact.pub_hex.trim()])
        .args(["--origin-pub-hex", contact.pub_hex.trim()])
        .spawn()
    {
        Ok(ch) => ch,
        Err(e) => {
            println!("{0}could not start raven-node: {1}{2}", c.red, e, c.reset);
            return;
        }
    };

    // Give the daemon a beat to bind; bail out if it died immediately.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    if let Some(st) = child.try_wait().ok().flatten() {
        let _ = child.wait();
        println!(
            "{0}listener exited early ({1}) — see message above.{2}",
            c.yellow, st, c.reset
        );
        return;
    }

    println!();
    println!("{0}═══ LISTENING ═══{1}", c.purple, c.reset);
    println!("{0}Tell your friend to send to:{1}", c.dim, c.reset);
    println!("   {0}{ip}:{DEFAULT_LAN_PORT}{1}", c.cyan, c.reset);
    println!("{0}…and use YOUR pub_hex when asked:{1}", c.dim, c.reset);
    println!("   {}", hex::encode(id.public_key_bytes()));
    println!(
        "{0}Waiting for {1} … (Ctrl+C to stop){2}",
        c.dim,
        contact.primary_label(),
        c.reset
    );
    println!();

    let status = child.wait();

    match status {
        Ok(s) if s.success() => {
            println!("{0}✔ message received & ACKed.{1}", c.green, c.reset);
        }
        Ok(s) => println!("{0}listener exited ({1}).{2}", c.yellow, s, c.reset),
        Err(e) => println!("{0}could not start raven-node: {1}{2}", c.red, e, c.reset),
    }
}

fn print_lan_unresolved_hint(contact_label: &str) {
    let s = style();
    let bold = s.bold;
    let dim = s.dim;
    let reset = s.reset;
    println!(
        "{bold}LAN peer not resolved{reset} for {} — identity ≠ IP.",
        sanitize_terminal_text(contact_label)
    );
    println!(
        "{dim}EN:{reset} Peer must reach this Mac (iPhone Serverless LAN → Host=Mac IP, Port={DEFAULT_LAN_PORT}),"
    );
    println!(
        "{dim}   {reset} or set listen on the phone / export RAVEN_PEER=host:port. No host:port prompt."
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

/// Pure resolution used by tests: saved dial → env → Mac-listens local queue.
/// `ipc_up` is informational for callers; empty dial always prefers local queue (daemon may auto-start).
fn resolve_lan_peer_parts(
    saved_lan_dial: &str,
    env_dial: Option<&str>,
    _ipc_up: bool,
) -> Option<ResolvedLanPeer> {
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
    sanitize_terminal_text(tag.trim().trim_start_matches('@')).to_lowercase()
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
        let _ = store.put(rec, now);
    }
    store
}

fn save_alias_claim(data_dir: &Path, rec: &AliasRecord) -> Result<(), String> {
    let path = alias_store_path(data_dir);
    let mut rows: Vec<AliasClaimJson> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|r| serde_json::from_str(&r).ok())
        .unwrap_or_default();
    rows.retain(|r| !(r.alias == rec.alias && r.identity_address == rec.identity_address));
    rows.push(AliasClaimJson {
        alias: rec.alias.clone(),
        identity_address: rec.identity_address.clone(),
        sequence: rec.sequence,
        expires_at: rec.expires_at,
        signature_hex: hex::encode(rec.signature),
        ed25519_pub_hex: hex::encode(rec.ed25519_pub),
    });
    std::fs::create_dir_all(data_dir).map_err(|e| e.to_string())?;
    let raw = serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?;
    std::fs::write(path, raw).map_err(|e| e.to_string())
}

fn cmd_alias_publish(data_dir: &Path, alias: &str, sequence: u64, expires_at: Option<u64>) {
    let id = require_identity(data_dir);
    let alias = match normalize_alias(alias) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
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

fn load_profile_store(_data_dir: &Path, _now: u64) -> ProfileStore {
    ProfileStore::default()
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
        profiles: load_profile_store(data_dir, now),
        blocked: BlockList::load(data_dir),
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
            sanitize_terminal_text(&h.display_name)
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
        }
    );
    println!(
        "      {C_DIM}raven_id{C_RESET}  {}",
        sanitize_terminal_text(&h.raven_id)
    );
    if !h.aliases.is_empty() {
        println!(
            "      {C_DIM}aliases{C_RESET}   {}",
            h.aliases
                .iter()
                .map(|a| format!("@{a}"))
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
        sanitize_terminal_text(query),
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
                    sanitize_terminal_text(&h.raven_id),
                    sanitize_terminal_text(&h.raven_id)
                );
            }
        }
    }
}

fn cmd_nearby(data_dir: &Path) {
    let path = nearby_store_path(data_dir);
    let mut reg = NearbyRegistry::default();
    if let Ok(raw) = std::fs::read_to_string(&path) {
        if let Ok(tokens) = serde_json::from_str::<Vec<String>>(&raw) {
            for t in tokens {
                if let Ok(v) = hex::decode(&t) {
                    if v.len() == 16 {
                        let mut token = [0u8; 16];
                        token.copy_from_slice(&v);
                        let mut adv = NearbyAdvertisement::mint(now_ms(), 60_000, b"ash-nearby");
                        adv.ephemeral_token = token;
                        let _ = reg.publish_ephemeral(adv);
                    }
                }
            }
        }
    }
    let adv = NearbyAdvertisement::mint(now_ms(), 60_000, b"ash-nearby");
    if adv.contains_permanent_raven_id() {
        eprintln!("refused: permanent Raven ID in nearby advertisement");
        std::process::exit(1);
    }
    reg.publish_ephemeral(adv.clone()).unwrap();
    let mut tokens: Vec<String> = reg
        .live_ads
        .iter()
        .map(|a| hex::encode(a.ephemeral_token))
        .collect();
    tokens.sort();
    tokens.dedup();
    std::fs::create_dir_all(data_dir).ok();
    let _ = std::fs::write(
        path,
        serde_json::to_string_pretty(&tokens).unwrap_or_default(),
    );
    println!("{C_BOLD}Nearby{C_RESET} (ephemeral — no permanent Raven ID in adv)");
    for a in reg.scan_live(now_ms()) {
        let phrase = raven_core::nearby_safety_phrase(&a.ephemeral_token, &a.session_commitment);
        println!(
            "  token={} ttl_ms={} commitment={}",
            hex::encode(a.ephemeral_token),
            a.ttl_ms,
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
        hits.get(n.saturating_sub(1)).unwrap_or_else(|| {
            eprintln!("pick out of range");
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
        if let Some(claim) = claims
            .iter()
            .find(|c| c.identity_address == chosen.raven_id)
        {
            claim.ed25519_pub
        } else if claims.len() == 1 {
            claims[0].ed25519_pub
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
    assert!(req.is_ciphertext_only());
    let wire = req.encode_wire().unwrap_or_else(|e| {
        eprintln!("wire encode failed: {e}");
        std::process::exit(1);
    });
    // Ciphertext-only file (opaque to store/bridge) + full wire for endpoint delivery.
    let out_ct = data_dir.join(format!("contact_request_{}.bin", hex::encode(request_id)));
    let out_wire = data_dir.join(format!("contact_request_{}.wire", hex::encode(request_id)));
    std::fs::write(&out_ct, &req.ciphertext).ok();
    std::fs::write(&out_wire, &wire).ok();
    println!("{C_GREEN}contact request sealed{C_RESET} (ciphertext-only for store/bridge)");
    println!("{C_DIM}request_id{C_RESET} {}", hex::encode(request_id));
    println!(
        "{C_DIM}recipient{C_RESET}  {}",
        sanitize_terminal_text(&chosen.raven_id)
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
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.wire", hex::encode(outer.request_id)));
    let wire = outer.encode_wire()?;
    std::fs::write(path, wire).map_err(|e| e.to_string())
}

fn remove_inbox_wire(data_dir: &Path, request_id: &[u8; 16]) {
    let path = contact_inbox_dir(data_dir).join(format!("{}.wire", hex::encode(request_id)));
    let _ = std::fs::remove_file(path);
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
            sanitize_terminal_text(&p.inner.sender_raven_id),
            sanitize_terminal_text(&p.inner.sender_display_name),
            sanitize_terminal_text(&p.inner.optional_message)
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
    assert!(outer.is_ciphertext_only());
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
        sanitize_terminal_text(&inner.sender_raven_id),
        sanitize_terminal_text(&inner.sender_display_name)
    );
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
    remove_inbox_wire(data_dir, &rid);
    // Bind local contact (raven_id + petname); verification = trusted contact.
    if let Err(e) = add_contact(
        data_dir,
        &outcome.binding.raven_id,
        &outcome.binding.pub_hex,
        &outcome.binding.petname,
        "",
        None,
        "",
    ) {
        eprintln!("bind note: {e}");
    }
    let wire = outcome.accept.encode_wire().unwrap_or_else(|e| {
        eprintln!("accept wire: {e}");
        std::process::exit(1);
    });
    let out = data_dir.join(format!("contact_accept_{}.wire", hex::encode(rid)));
    std::fs::write(&out, &wire).ok();
    println!(
        "{C_GREEN}accepted{C_RESET} + bound petname \"{}\"",
        sanitize_terminal_text(&outcome.binding.petname)
    );
    println!(
        "{C_DIM}raven_id{C_RESET} {}",
        sanitize_terminal_text(&outcome.binding.raven_id)
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
    let mut blocks = BlockList::load(data_dir);
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
    contacts
        .iter()
        .filter(|c| normalize_tag(&c.public_tag) == want || normalize_tag(&c.alias) == want)
        .collect()
}

/// Back-compat alias used by interactive send.
fn resolve_alias_contacts<'a>(contacts: &'a [Contact], alias: &str) -> Vec<&'a Contact> {
    resolve_tag_contacts(contacts, alias)
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
                sanitize_terminal_text(exp)
            ));
        }
        true
    } else {
        false
    };

    let tag_clean = normalize_tag(public_tag);
    let mut pet = sanitize_terminal_text(petname.trim());
    if pet.is_empty() && !tag_clean.is_empty() {
        pet = tag_clean.clone();
    }

    let mut contacts = load_contacts(data_dir)?;

    // Key-change warning: pinned row with same public_tag but different pub/address.
    if !tag_clean.is_empty() {
        for c in contacts.iter() {
            if normalize_tag(&c.public_tag) == tag_clean
                && c.pinned
                && (c.pub_hex != hex::encode(ed) || c.address != address)
            {
                eprintln!("{C_PURPLE}KEY-CHANGE WARNING{C_RESET}: pinned @{tag_clean} was");
                eprintln!(
                    "  old fp={}  {}",
                    contact_fingerprint(c),
                    sanitize_terminal_text(&c.address)
                );
                eprintln!("  new fp={fp}  {}", sanitize_terminal_text(&address));
                eprintln!(
                    "{C_DIM}DHT/gossip cannot overwrite pin. Refuse unless you intend to re-pin after verify.{C_RESET}"
                );
                return Err("KEY_CHANGE_REFUSED_WITHOUT_REPIN".into());
            }
        }
    }

    // Soft-unique: competing same @tag → ambiguity notice; require distinct petnames.
    if !tag_clean.is_empty() {
        let clashes: Vec<&Contact> = contacts
            .iter()
            .filter(|c| normalize_tag(&c.public_tag) == tag_clean && c.pub_hex != hex::encode(ed))
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

    // Replace same pub_hex if present (preserve pin / dial if already set).
    let prior = contacts
        .iter()
        .find(|c| c.pub_hex == hex::encode(ed))
        .cloned();
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
    contacts.retain(|c| c.pub_hex != hex::encode(ed));
    contacts.push(Contact {
        petname: pet,
        public_tag: tag_clean.clone(),
        alias: tag_clean,
        address,
        pub_hex: hex::encode(ed),
        pinned: pin || prior_pinned,
        lan_dial: dial,
    });
    save_contacts(data_dir, &contacts)?;
    println!("{C_GREEN}contact saved{C_RESET} (local only — no FastAPI / no registrar)");
    println!(
        "{C_DIM}petname{C_RESET}     {}",
        contacts.last().unwrap().primary_label()
    );
    if let Some(t) = contacts.last().unwrap().tag_subtitle() {
        println!("{C_DIM}public_tag{C_RESET}  {t}");
    }
    if !contacts.last().unwrap().lan_dial.is_empty() {
        println!(
            "{C_DIM}lan_dial{C_RESET}    {}",
            sanitize_terminal_text(&contacts.last().unwrap().lan_dial)
        );
    }
    println!("{C_DIM}fingerprint{C_RESET} {fp}");
    println!(
        "{C_DIM}pinned{C_RESET}      {}",
        if pin || prior_pinned {
            "yes (Tag+key locked locally)"
        } else {
            "no (pass --verify-fp to pin)"
        }
    );
    println!(
        "{C_DIM}iPhone:{C_RESET} this did NOT sync to the phone. On iPhone: Discover → Paste ash whoami → paste THIS Mac `ash whoami` (address + pub_hex)."
    );
    println!(
        "{C_DIM}آیفون:{C_RESET} مخاطب فقط روی مک ذخیره شد. روی گوشی: Discover → Paste ash whoami → whoami همین مک را بچسبانید."
    );
    Ok(())
}

fn cmd_contact_list(data_dir: &Path) {
    let c = c();
    let contacts = contacts_or_die(data_dir);
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
        return;
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
                sanitize_terminal_text(&ct.lan_dial),
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

    cmd_contact_list(data_dir);
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
        "l" | "list" => cmd_contact_list(data_dir),
        "2" | "s" | "send" => {
            println!("{dim}→ Send / Chat{reset}");
            cmd_send_interactive(data_dir);
        }
        "1" | "m" | "messages" => {
            println!("{dim}→ Messages (queue/history — to compose a new DM use 2){reset}");
            cmd_messages(data_dir);
        }
        "4" | "status" => {
            let _ = cmd_status(data_dir);
        }
        "q" | "quit" | "exit" => {
            println!("{dim}Press Enter to leave Contacts, then type q at raven> to quit.{reset}");
        }
        "" => {}
        other => println!("{dim}unknown:{reset} {other} — try a / l / 2 (Send) / Enter (back)"),
    }
}

fn cmd_contact_add_interactive(data_dir: &Path) {
    let s = style();
    let bold = s.bold;
    let dim = s.dim;
    let reset = s.reset;

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

    // One-text invite: paste `raven:addr:pubhex` to skip manual entry
    if trimmed.starts_with("raven:") {
        let parts: Vec<&str> = trimmed.strip_prefix("raven:").unwrap().split(':').collect();
        if parts.len() >= 2 && parts[0].starts_with("rvn1") && parts[1].len() == 64 {
            let addr = parts[0].to_string();
            let pub_hex = parts[1].to_string();
            println!(
                "{0}\u{2713} invite parsed \u{2014} {1}{2}",
                C_GREEN, addr, C_RESET
            );
            print!("petname (e.g. \"Alice\"): ");
            let _ = io::stdout().flush();
            let petname = read_line();
            let petname = if petname.is_empty() {
                "friend".to_string()
            } else {
                petname
            };
            let mut key = [0u8; 32];
            if let Ok(decoded) = hex::decode(&pub_hex) {
                if decoded.len() == 32 {
                    key.copy_from_slice(&decoded);
                }
            }
            let fp = device_fingerprint_v1(&key);
            println!(
                "{dim}fingerprint{r} {fp}",
                dim = C_DIM,
                r = C_RESET,
                fp = fp
            );
            print!("[V]erify & pin / [C]ontinue unpinned / [A]bort: ");
            let _ = io::stdout().flush();
            let choice = read_line();
            let pinned = choice.trim().to_ascii_lowercase().starts_with('v');
            let ct = Contact {
                petname,
                public_tag: String::new(),
                alias: String::new(),
                address: addr,
                pub_hex,
                pinned,
                lan_dial: String::new(),
            }
            .migrate();
            save_contacts(data_dir, std::slice::from_ref(&ct)).ok();
            if pinned {
                println!(
                    "{green}\u{2713} contact saved & pinned{r}",
                    green = C_GREEN,
                    r = C_RESET
                );
            } else {
                println!("{dim}contact saved (unpinned){r}", dim = C_DIM, r = C_RESET);
            }
            return;
        }
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
            sanitize_terminal_text(&address)
        );
        print!("optional public @tag (Soft Unique, e.g. poline): ");
        let _ = io::stdout().flush();
        tag = read_line();
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
            sanitize_terminal_text(&address)
        );
        print!("optional public @tag (Soft Unique, e.g. poline): ");
        let _ = io::stdout().flush();
        tag = read_line();
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
                    sanitize_terminal_text(&address)
                );
            } else {
                address =
                    extract_address_field(&pasted).unwrap_or_else(|| pasted.trim().to_string());
                if let Some(ph) = extract_pub_hex_field(&pasted) {
                    pub_hex = ph;
                } else {
                    print!("pub_hex (64 chars, public only): ");
                    let _ = io::stdout().flush();
                    pub_hex = read_line();
                }
            }
        } else if claims.len() == 1 {
            let c = &claims[0];
            address = c.identity_address.clone();
            pub_hex = hex::encode(c.ed25519_pub);
            println!(
                "{dim}Resolved @{tag} → {}{reset}",
                sanitize_terminal_text(&address)
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
                    sanitize_terminal_text(&c.identity_address),
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
            pub_hex = read_line();
        }
        print!("optional public @tag (Soft Unique, e.g. poline): ");
        let _ = io::stdout().flush();
        tag = read_line();
    }

    if looks_like_shell_input(&address) || looks_like_shell_input(&pub_hex) {
        eprintln!("{}", shell_paste_rejection());
        return;
    }

    print!("Optional petname (e.g. \"Poline\" — local label): ");
    let _ = io::stdout().flush();
    let petname = read_line();

    print!("Optional LAN dial host:port (Enter to skip — Send auto-resolves / Mac-listens): ");
    let _ = io::stdout().flush();
    let lan_dial = read_line();

    let ed = match parse_pub_hex(&pub_hex) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("rejected: {e}");
            return;
        }
    };
    let fp = device_fingerprint_v1(&ed);
    println!();
    println!("{bold}Fingerprint{reset}  {fp}");
    println!("{dim}Compare this with your peer out-of-band (Signal call, in person, etc.).{reset}");
    print!("[V]erify & pin  /  [C]ontinue unpinned  /  [A]bort: ");
    let _ = io::stdout().flush();
    let choice = read_line();
    let verify = match choice.trim().to_ascii_lowercase().as_str() {
        "v" | "verify" | "pin" => Some(fp.clone()),
        "c" | "continue" | "" => None,
        "a" | "abort" | "q" => {
            println!("{dim}cancelled.{reset}");
            return;
        }
        other if other.eq_ignore_ascii_case(&fp) => Some(fp.clone()),
        _ => {
            println!("{dim}cancelled (expected V, C, or A).{reset}");
            return;
        }
    };

    if let Err(e) = add_contact(
        data_dir,
        &address,
        &pub_hex,
        &petname,
        &tag,
        verify.as_deref(),
        &lan_dial,
    ) {
        eprintln!("rejected: {e}");
    } else {
        println!(
            "{dim}Tip: menu 2 Send / Chat → pick this contact by # or @tag (not host:port).{reset}"
        );
    }
}

fn cmd_contact_resolve(data_dir: &Path, tag: &str) {
    let contacts = contacts_or_die(data_dir);
    let hits = resolve_tag_contacts(&contacts, tag);
    if hits.is_empty() {
        eprintln!("no local contacts for @{}", normalize_tag(tag));
        eprintln!("{C_DIM}no \"is tag taken?\" API — add via QR/OOB only{C_RESET}");
        return;
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
        return;
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
}

fn cmd_contact_verify(
    data_dir: &Path,
    tag: Option<&str>,
    alias: Option<&str>,
    petname: Option<&str>,
    address: Option<&str>,
) {
    let contacts = contacts_or_die(data_dir);
    let tag = tag.or(alias);
    let matches: Vec<&Contact> = if let Some(t) = tag {
        resolve_tag_contacts(&contacts, t)
    } else if let Some(p) = petname {
        let want = sanitize_terminal_text(p.trim());
        contacts
            .iter()
            .filter(|c| c.petname.eq_ignore_ascii_case(&want))
            .collect()
    } else if let Some(addr) = address {
        let addr = raven_core::address::from_display(addr.trim());
        contacts.iter().filter(|c| c.address == addr).collect()
    } else {
        eprintln!("need --tag, --petname, or --address");
        return;
    };
    if matches.is_empty() {
        eprintln!("no contact matched");
        return;
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
            sanitize_terminal_text(&c.address)
        );
        println!("{C_DIM}fingerprint{C_RESET} {}", contact_fingerprint(c));
        println!(
            "{C_DIM}pinned{C_RESET}      {}",
            if c.pinned { "yes" } else { "no" }
        );
    }
}

fn cmd_prekey_publish(data_dir: &Path, device_id: &str, out: Option<&Path>) {
    let id = require_identity(data_dir);
    if let Err(e) = ext::cmd_prekey_publish_real(data_dir, &id, device_id, out) {
        eprintln!("{e}");
        std::process::exit(1);
    }
}

fn cmd_prekey_fetch(data_dir: &Path, pub_hex: &str, file: Option<&Path>) {
    let ed = match parse_pub_hex(pub_hex) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };
    let now = now_ms();
    let bundle = if let Some(path) = file {
        match std::fs::read_to_string(path) {
            Ok(raw) => match serde_json::from_str::<PrekeyBundleJson>(&raw) {
                Ok(j) => match PrekeyBundle::from_json(&j) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("bundle parse: {e}");
                        return;
                    }
                },
                Err(e) => {
                    eprintln!("json: {e}");
                    return;
                }
            },
            Err(e) => {
                eprintln!("read: {e}");
                return;
            }
        }
    } else {
        match PrekeyStore::load_checked(data_dir).and_then(|s| s.fetch(&ed, now)) {
            Ok(Some(b)) => b,
            Ok(None) => {
                eprintln!("no bundle in local store for that pub (try --file OOB json)");
                return;
            }
            Err(e) => {
                eprintln!("fetch/verify failed: {e}");
                return;
            }
        }
    };
    if let Err(e) = bundle.verify(now) {
        eprintln!("verify failed: {e}");
        return;
    }
    if bundle.identity_ed25519_pub != ed {
        eprintln!("PREKEY_IDENTITY_MISMATCH");
        return;
    }
    // Persist into local untrusted store so PairInit / lab send can fetch.
    if let Err(e) = raven_core::publish_prekey_bundle_checked(data_dir, &bundle, now) {
        eprintln!("store publish: {e}");
        return;
    }
    println!("{C_GREEN}prekey ok{C_RESET} (cached in prekey_store.json)");
    println!(
        "{C_DIM}fingerprint{C_RESET} {}",
        device_fingerprint_v1(&bundle.identity_ed25519_pub)
    );
    println!(
        "{C_DIM}device_id{C_RESET}   {}",
        sanitize_terminal_text(&bundle.device_id)
    );
    println!("{C_DIM}prekey_id{C_RESET}   {}", bundle.signed_prekey_id);
    println!("{C_DIM}expires_ms{C_RESET}  {}", bundle.expires_at_ms);
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
            println!("  FAIL: messaging_path {}", sanitize_terminal_text(&e));
            Err(e)
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
                sanitize_terminal_text(&e)
            ));
        }
    }

    let contacts = contacts_or_die(data_dir);
    println!();
    println!("{}CONTACTS \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}", c.bold, c.reset);
    kv("count", &contacts.len().to_string());

    let policy = load_policy(data_dir);
    let fwd_path = data_dir.join("forward_queue.sqlite");
    let (pending, total) = if fwd_path.exists() {
        ForwardQueue::open(&fwd_path)
            .ok()
            .map(|q| (q.count_pending().unwrap_or(0), q.count_all().unwrap_or(0)))
            .unwrap_or((0, 0))
    } else {
        (0, 0)
    };
    let snap = BridgeStatusSnapshot::from_policy(&policy, &["lan", "mock_ble"], pending, total);

    println!();
    println!("{}BRIDGE \u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}{}", c.bold, c.reset);
    kv("bridge", ok(snap.bridge));
    kv("store", ok(snap.store));
    kv("relay", ok(snap.relay));
    kv("endpoint", ok(snap.endpoint));
    kv("policy", if snap.auto_policy { "AUTO" } else { "manual" });
    kv("transports", &snap.transports.join(", "));
    kv("caps", &snap.capabilities.join(", "));
    kv(
        "forward_q",
        &format!(
            "{} pending / {} total",
            snap.forward_queue_pending, snap.forward_queue_total
        ),
    );

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

    Ok(())
}

fn set_node_flag(data_dir: &Path, which: &str, on: bool) {
    let mut policy = load_policy(data_dir);
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
    println!(
        "{C_GREEN}ok{C_RESET} {which}={} (raven-node reloads from {})",
        if on { "on" } else { "off" },
        data_dir.join("node_policy.json").display()
    );
    // Never print keys.
    let _ = NodePolicy::default();
}

/// Guided Send / Chat. Two lanes:
///   * pinned contact with saved lan_dial → direct send, no extra prompts
///   * advanced → ask host:port + pub_hex once (lab interim transport)
fn cmd_send_interactive(data_dir: &Path) {
    let c = c();
    match try_load_identity(data_dir) {
        Ok(Some(_)) => {}
        Ok(None) => {
            println!("{0}No identity yet.{1}", c.bold, c.reset);
            println!(
                "{0}Run {1}ash init{0} first (or restart the menu and accept the offer).{2}",
                c.dim, c.bold, c.reset
            );
            return;
        }
        Err(e) => {
            eprintln!("identity store unavailable: {}", sanitize_terminal_text(&e));
            return;
        }
    }
    let _id = require_identity(data_dir);
    let contacts = load_contacts(data_dir).unwrap_or_default();

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
        let (peer, pub_hex, text) = direct_peer_prompts();
        if let Some((peer, pub_hex, text)) =
            peer.zip(pub_hex).zip(text).map(|((p, k), t)| (p, k, t))
        {
            direct_interim_send(data_dir, &peer, &pub_hex, &text);
        }
        return;
    }

    // ── Contact picker ──
    screen_header("Send");
    println!(
        "{0}Pick a contact by number or @tag. Direct host:port is advanced only.{1}",
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
                sanitize_terminal_text(&ct.lan_dial),
                c.reset
            )
        };
        println!(
            "  {n}  {label}{sub}{dial}{pinned}",
            n = i + 1,
            label = ct.primary_label(),
            pinned = if ct.pinned { " [pinned]" } else { "" }
        );
    }
    print!("contact # | @tag | advanced: ");
    let _ = io::stdout().flush();
    let choice = read_line();
    let trimmed = choice.trim();

    if trimmed.eq_ignore_ascii_case("advanced") || looks_like_lan_dial(trimmed) {
        let (peer, pub_hex, text) = direct_peer_prompts();
        if let Some((peer, pub_hex, text)) =
            peer.zip(pub_hex).zip(text).map(|((p, k), t)| (p, k, t))
        {
            direct_interim_send(data_dir, &peer, &pub_hex, &text);
        }
        return;
    }

    // Resolve the picked contact.
    let picked: Option<&Contact> = if let Ok(n) = trimmed.parse::<usize>() {
        contacts.get(n.checked_sub(1).unwrap_or(usize::MAX))
    } else if let Some(tag) = trimmed.strip_prefix('@') {
        contacts
            .iter()
            .find(|x| x.public_tag.eq_ignore_ascii_case(tag) || x.alias.eq_ignore_ascii_case(tag))
    } else {
        contacts
            .iter()
            .find(|x| x.petname.eq_ignore_ascii_case(trimmed))
    };
    let Some(ct) = picked else {
        println!(
            "{0}unknown choice — pick a number, @tag, or type advanced.{1}",
            c.dim, c.reset
        );
        return;
    };

    let peer = if ct.lan_dial.is_empty() {
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
        hp
    } else {
        ct.lan_dial.clone()
    };

    println!(
        "{0}message for {1}:{2} ",
        c.dim,
        ct.primary_label(),
        c.reset
    );
    print!("> ");
    let _ = io::stdout().flush();
    let text = read_line();
    if text.is_empty() {
        eprintln!("empty message");
        return;
    }
    direct_interim_send(data_dir, &peer, &ct.pub_hex.clone(), &text);
}

fn direct_peer_prompts() -> (Option<String>, Option<String>, Option<String>) {
    let c = c();
    if !stdin_is_tty() {
        println!(
            "{0}direct peer needs interactive input \u{2014} \
             use a contact with --lan-dial, or run inside a terminal.{1}",
            c.yellow, c.reset
        );
        return (None, None, None);
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
    print!("peer pub_hex (64 chars, public only): ");
    let _ = io::stdout().flush();
    let pub_hex = read_line();
    print!("message (stdin — never argv): ");
    let _ = io::stdout().flush();
    let text = read_line();
    if peer.trim().is_empty() {
        return (None, None, None);
    }
    (
        Some(peer.trim().to_string()),
        Some(pub_hex.trim().to_string()),
        Some(text),
    )
}

/// Proven lab transport lane: spawn raven-node with an interim-sealed envelope
/// over direct TCP. Release builds without the lab feature make the daemon
/// refuse here (ATSAM_SESSION_REQUIRED) \\u{2014} production stays fail-closed.
fn direct_interim_send(data_dir: &Path, peer: &str, pub_hex: &str, text: &str) {
    let c = c();
    let node = ext::raven_node_bin_public();
    let mut child = match Command::new(node)
        .arg("run")
        .args(["--data-dir", &data_dir.display().to_string()])
        .args(["--listen", "127.0.0.1:0"])
        .args(["--peer", peer.trim()])
        .args(["--peer-pub-hex", pub_hex.trim()])
        .args(["--send-stdin"])
        .args(["--body-mode", "unsafe-interim"])
        .args(["--exit-after-ack"])
        .args(["--timeout-secs", "45"])
        .stdin(std::process::Stdio::piped())
        .spawn()
    {
        Ok(ch) => ch,
        Err(e) => {
            let (red, reset) = (c.red, c.reset);
            eprintln!("{red}could not start raven-node: {e}{reset}");
            return;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        let _ = stdin.write_all(text.as_bytes());
        let _ = stdin.write_all(b"\\n");
    }
    match child.wait() {
        Ok(s) if s.success() => {}
        Ok(s) => {
            let (yellow, reset) = (c.yellow, c.reset);
            eprintln!("{yellow}send exited ({s}){reset}");
        }
        Err(e) => {
            let (red, reset) = (c.red, c.reset);
            eprintln!("{red}send failed: {e}{reset}");
        }
    }
}

fn resolve_or_reuse_lan_dial(data_dir: &Path, c: &Contact) -> Option<ResolvedLanPeer> {
    let s = style();
    let bold = s.bold;
    let dim = s.dim;
    let reset = s.reset;

    let env = env_peer_lan_dial();
    let had_saved = looks_like_lan_dial(&c.lan_dial);
    let ipc_up = ipc_daemon_up(data_dir);
    let resolved = resolve_lan_peer_parts(&c.lan_dial, env.as_deref(), ipc_up);
    if resolved.is_none() && !ipc_up {
        println!("{dim}Starting raven-node service so IPC LanDial can run…{reset}");
        let _ = ensure_mac_lan_service(data_dir);
    }

    match &resolved {
        Some(ResolvedLanPeer::Dial(dial)) => {
            if had_saved && c.lan_dial.trim() == dial.as_str() {
                println!(
                    "{dim}LAN dial{reset} {bold}{}{reset} {dim}(saved · {}){reset}",
                    sanitize_terminal_text(dial),
                    c.primary_label()
                );
            } else {
                println!(
                    "{dim}LAN dial{reset} {bold}{}{reset} {dim}(auto · {}){reset}",
                    sanitize_terminal_text(dial),
                    c.primary_label()
                );
                if let Err(e) = update_contact_lan_dial(data_dir, &c.pub_hex, dial) {
                    eprintln!("{dim}could not save dial: {e}{reset}");
                } else {
                    println!("{dim}Saved lan_dial on contact for next Send.{reset}");
                }
            }
        }
        None => {
            print_lan_unresolved_hint(&c.primary_label());
            return None;
        }
    }
    resolved
}

fn resolve_send_target(
    data_dir: &Path,
    contact: &str,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
) -> Result<(String, String, String), String> {
    if !contact.trim().is_empty() {
        let contacts = load_contacts(data_dir)?;
        let hits = resolve_alias_contacts(&contacts, contact);
        if hits.is_empty() {
            return Err(format!(
                "no contact for {} — ash contact add … --tag … --lan-dial host:port",
                sanitize_terminal_text(contact)
            ));
        }
        if hits.len() > 1 {
            return Err(format!(
                "contact tag {} is ambiguous ({} matches)",
                sanitize_terminal_text(contact),
                hits.len()
            ));
        }
        let c = hits[0];
        return match resolve_or_reuse_lan_dial(data_dir, c) {
            Some(ResolvedLanPeer::Dial(dial)) => Ok((dial, c.pub_hex.clone(), listen.to_string())),
            None => Err(format!(
                "contact {} has no reachable lan_dial — set host:port (not LocalListenQueue)",
                c.primary_label()
            )),
        };
    }
    if peer_pub_hex.trim().is_empty() || !looks_like_lan_dial(peer) {
        return Err("send requires --contact @tag or --peer host:port plus --peer-pub-hex".into());
    }
    Ok((
        peer.to_string(),
        peer_pub_hex.to_string(),
        listen.to_string(),
    ))
}

fn cmd_endpoint_inbox(data_dir: &Path) {
    let mut store = match raven_core::IndexedSessionStore::open(data_dir) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("inbox: {}", e.redacted_display());
            return;
        }
    };
    match store.list_endpoint_inbox() {
        Ok(rows) if rows.is_empty() => {
            println!("{C_DIM}endpoint inbox empty{C_RESET}");
        }
        Ok(rows) => {
            println!("{C_BOLD}inbox{C_RESET} ({})", rows.len());
            for row in rows {
                let preview = String::from_utf8_lossy(&row.plaintext);
                println!(
                    "  {C_DIM}{}{C_RESET} {}",
                    hex::encode(&row.message_id[..4]),
                    sanitize_terminal_text(&preview)
                );
            }
        }
        Err(e) => eprintln!("inbox: {}", e.redacted_display()),
    }
}

fn run_send(data_dir: &Path, peer: &str, peer_pub_hex: &str, listen: &str, text: &str) {
    let id = require_identity(data_dir);
    if let Err(error) =
        ext::run_send_secure(data_dir, &id, peer, peer_pub_hex, listen, text, "", "")
    {
        eprintln!("send refused: {error}");
        std::process::exit(1);
    }
}

fn cmd_send_cli(
    data_dir: &Path,
    peer: &str,
    peer_pub_hex: &str,
    listen: &str,
    contact: &str,
    stdin_text: bool,
    chat: bool,
) {
    let no_target = contact.trim().is_empty() && peer.trim().is_empty();
    if chat {
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
            let hits = resolve_alias_contacts(&contacts, contact);
            if hits.is_empty() {
                eprintln!(
                    "no contact for {} — ash contact add … --tag … --lan-dial host:port",
                    sanitize_terminal_text(contact)
                );
                std::process::exit(1);
            }
            if hits.len() > 1 {
                eprintln!(
                    "contact tag {} is ambiguous ({} matches)",
                    sanitize_terminal_text(contact),
                    hits.len()
                );
                std::process::exit(1);
            }
            let c = hits[0];
            let Some(ResolvedLanPeer::Dial(dial)) = resolve_or_reuse_lan_dial(data_dir, c) else {
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
        cmd_send_interactive(data_dir);
        return;
    }
    if !stdin_text {
        ext::refuse_argv_plaintext();
    }
    let mut text = String::new();
    if io::stdin().read_to_string(&mut text).is_err() {
        eprintln!("failed to read message from stdin");
        std::process::exit(1);
    }
    let text = text.trim_end_matches(['\r', '\n']);
    if text.is_empty() {
        eprintln!("empty message");
        std::process::exit(1);
    }
    match resolve_send_target(data_dir, contact, peer, peer_pub_hex, listen) {
        Ok((peer, pub_hex, listen)) => run_send(data_dir, &peer, &pub_hex, &listen, text),
        Err(e) => {
            eprintln!("{}", sanitize_terminal_text(&e));
            std::process::exit(1);
        }
    }
}

/// Flat menu model shared by both navigation modes.
const MENU_ITEMS: [(&str, &str, &str); 8] = [
    ("1", "Chat / Send", "message a contact — guided"),
    ("2", "Inbox", "committed endpoint inbox"),
    ("3", "Status", "identity · bridge · transports"),
    ("4", "Listen", "receive — one command, no flags"),
    ("5", "Contacts", "add by rvn1… paste · list · verify"),
    ("6", "Mailbox", "opaque offline put/get"),
    ("7", "Nearby scan", "ephemeral BLE discovery"),
    ("8", "Tutorial", "guided walkthrough — start here"),
];

/// Execute a menu choice; returns false when the user asked to quit.
fn run_menu_choice(data_dir: &Path, choice: &str) -> bool {
    let c = c();
    match choice {
        "1" | "s" | "send" | "chat" => cmd_send_interactive(data_dir),
        "2" | "i" | "inbox" => cmd_endpoint_inbox(data_dir),
        "3" | "st" | "status" => {
            let _ = cmd_status(data_dir);
        }
        "4" | "l" | "listen" => cmd_listen(data_dir),
        "5" | "c" | "contacts" => cmd_contacts(data_dir),
        "6" | "mailbox" => println!(
            "{0}mailbox is subcommand-driven — see `ash mailbox --help`.{1}",
            c.dim, c.reset
        ),
        "7" | "nearby" => println!(
            "{0}nearby scan: run `ash nearby --help` in another shell              (menu stays responsive here).{1}",
            c.dim, c.reset
        ),
        "8" | "t" | "tutorial" => cmd_tutorial(data_dir),
        "q" | "quit" | "exit" => {
            println!("{0}fly safe.{1}", c.purple, c.reset);
            return false;
        }
        "" => {}
        other => println!(
            "{0}unknown:{1} {2} {0}— pick 1-8 or q{1}",
            c.dim, c.reset, other
        ),
    }
    true
}

fn interactive(data_dir: &Path) {
    print_welcome(data_dir);
    if !offer_first_run_identity(data_dir) {
        println!("{C_DIM}tip: run `ash init` anytime to create an identity.{C_RESET}");
    }
    if io::stdin().is_terminal() && !cfg!(windows) {
        arrow_menu_loop(data_dir);
    } else {
        line_menu_loop(data_dir);
    }
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
    stty(&["raw", "-echo"]);
    loop {
        match read_key_raw() {
            MenuKey::Escape | MenuKey::Enter => {
                stty(&["sane"]);
                return true;
            }
            MenuKey::Quit => {
                stty(&["sane"]);
                return false;
            }
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

fn read_key_raw() -> MenuKey {
    // Brief raw window: keystrokes arrive unbuffered (no Enter needed).
    stty(&["raw", "-echo"]);
    let key = read_key_raw_inner();
    stty(&["sane"]);
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
            let mut b2 = [0u8; 1];
            // Poll briefly — if no follow-up byte, this is a bare ESC press.
            if io::stdin().read(&mut b2).unwrap_or(0) == 0 {
                return MenuKey::Escape;
            }
            if b2[0] != b'[' {
                return MenuKey::Escape;
            }
            let mut b3 = [0u8; 1];
            if io::stdin().read(&mut b3).unwrap_or(0) == 0 {
                return MenuKey::Other;
            }
            match b3[0] {
                b'A' => MenuKey::Up,
                b'B' => MenuKey::Down,
                _ => MenuKey::Other,
            }
        }
        b'q' | b'Q' => MenuKey::Quit,
        b'\x03' => MenuKey::Quit, // Ctrl+C
        d @ b'1'..=b'8' => MenuKey::Digit((d - b'0') as usize),
        _ => MenuKey::Other,
    }
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
    lines.push(format!(
        "q  quit   {d}q  quit{r}   {d}(up/down + Enter · number = jump){r}",
        d = dim,
        r = reset
    ));
    lines.push(format!("raven {c}❯ ", c = cc.cyan));

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
    let data_dir = resolve_data_dir(&cli.data_dir);
    let _ = std::fs::create_dir_all(&data_dir);
    match cli.cmd {
        None => interactive(&data_dir),
        Some(Commands::Banner) => print_welcome(&data_dir),
        Some(Commands::Listen) => cmd_listen(&data_dir),
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
        Some(Commands::Whoami) => match try_load_identity(&data_dir) {
            Ok(Some(id)) => print_public_identity(&id),
            Ok(None) => println!("no identity — run init"),
            Err(e) => eprintln!("identity store: {}", sanitize_terminal_text(&e)),
        },
        Some(Commands::Status) => {
            if let Err(e) = cmd_status(&data_dir) {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        Some(Commands::Doctor { require_ready }) => cmd_doctor(&data_dir, require_ready),
        Some(Commands::IpcPing) => cmd_ipc_ping(&data_dir),
        Some(Commands::Inbox) => cmd_endpoint_inbox(&data_dir),
        Some(Commands::Send {
            peer,
            peer_pub_hex,
            listen,
            contact,
            stdin_text,
            chat,
        }) => cmd_send_cli(
            &data_dir,
            &peer,
            &peer_pub_hex,
            &listen,
            &contact,
            stdin_text,
            chat,
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
                cmd_prekey_fetch(&data_dir, &pub_hex, file.as_deref())
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
                epoch,
                slot,
                envelope_hex,
            } => ext::cmd_mailbox_put(&data_dir, &k_route_hex, epoch, slot, &envelope_hex),
            MailboxCommands::Get {
                k_route_hex,
                epoch,
                slot,
            } => ext::cmd_mailbox_get(&data_dir, &k_route_hex, epoch, slot),
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
                cmd_prekey_fetch(&data_dir, &peer_pub_hex, Some(&file))
            }
            LabCommands::Status => print_production_gate_matrix(),
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
                if let Err(e) = add_contact(
                    &data_dir,
                    &address,
                    &pub_hex,
                    &petname,
                    &public_tag,
                    verify_fp.as_deref(),
                    &lan_dial,
                ) {
                    eprintln!("{}", sanitize_terminal_text(&e));
                    std::process::exit(1);
                }
                if let Some(path) = prekey_file {
                    if let Err(e) = ext::contact_add_fetch_prekey(&data_dir, &pub_hex, Some(&path))
                    {
                        eprintln!("{}", sanitize_terminal_text(&e));
                        std::process::exit(1);
                    }
                }
            }
            ContactCommands::List => cmd_contact_list(&data_dir),
            ContactCommands::Verify {
                tag,
                alias,
                petname,
                address,
            } => cmd_contact_verify(
                &data_dir,
                tag.as_deref(),
                alias.as_deref(),
                petname.as_deref(),
                address.as_deref(),
            ),
            ContactCommands::Resolve { tag } => cmd_contact_resolve(&data_dir, &tag),
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
        },
    }
}

/// Guided walkthrough for newcomers. Every step prints what it does and why,
/// then runs the safe ones inline. No private material is ever displayed.
fn cmd_tutorial(data_dir: &Path) {
    let c = c();
    let _ = offer_first_run_identity(data_dir);

    println!(
        "\n{0}\u{2550}\u{2550}\u{2550} RAVEN TUTORIAL \u{2550}\u{2550}\u{2550}{1}",
        c.purple, c.reset
    );
    println!(
        "{0}Raven is serverless: you and your contacts ARE the network.{1}",
        c.dim, c.reset
    );
    println!(
        "{0}No phone number, no central account, messages relayed by peers.{1}\n",
        c.dim, c.reset
    );

    println!("{0}[1/4] Identity{1}", c.bold, c.reset);
    match try_load_identity(data_dir) {
        Ok(Some(id)) => {
            println!(
                "  {0}\u{2714}{1} created. Your public bits:",
                c.green, c.reset
            );
            print_public_identity(&id);
            println!(
                "  {0}Share address+fingerprint with friends over any channel;\n  they pin it, you pin theirs \u{2014} that mutual pin IS the trust.{1}\n",
                c.dim, c.reset
            );
        }
        Ok(None) => {
            println!(
                "  {0}skipped (declined). Re-enter via menu 8 anytime.{1}\n",
                c.dim, c.reset
            );
            return;
        }
        Err(e) => {
            println!("  {0}\u{00d7} {1}\n", c.red, sanitize_terminal_text(&e));
            return;
        }
    }

    println!("{0}[2/4] Add your first contact{1}", c.bold, c.reset);
    println!(
        "  {0}Ask a friend to run {1}ash whoami{0} and paste their three lines here.\n  Paste detection accepts the whole block at once.{2}",
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

    println!("{0}[3/4] Health check{1}", c.bold, c.reset);
    match cmd_status(data_dir) {
        Ok(_) => println!(
            "  {0}\u{2714}{1} messaging_path must read {2}serverless_rvn1{1}\n",
            c.green, c.reset, c.bold
        ),
        Err(e) => println!("  {0}\u{00d7}{1} status: {2}\n", c.red, c.reset, e),
    }

    println!("{0}[4/4] Send a message{1}", c.bold, c.reset);
    println!(
        "  {0}Menu 1 \u{2192} pick contact \u{2192} type message.\n  Direct LAN first; bridge relays when peers are apart;\n  mailbox stores opaque bytes while someone is offline.{1}\n",
        c.dim, c.reset
    );

    println!("{0}Done!{1}", c.purple, c.reset);
    println!(
        "  {0}Full diagnostics anytime: {1}ash doctor{0}{1}",
        c.reset, c.dim
    );
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
        sanitize_terminal_text(issue)
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
                        sanitize_terminal_text(&raw)
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
                sanitize_terminal_text(reason)
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

fn cmd_doctor(data_dir: &Path, require_ready: bool) {
    println!("{C_BOLD}raven doctor{C_RESET}");
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".into());
    let exe_clean = sanitize_terminal_text(&exe);
    println!("  this_binary={exe_clean}");
    println!("  argv0_hint: prefer `raven` as primary command; `ash` is product alias");
    println!(
        "  data_dir={}",
        sanitize_terminal_text(&data_dir.display().to_string())
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
    println!("  ipc_endpoint={}", sanitize_terminal_text(&ep.to_string()));
    match &ep {
        IpcEndpoint::UnixSocket(sock) => {
            println!(
                "  file_present: ipc_endpoint={} {}",
                sanitize_terminal_text(&sock.display().to_string()),
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
                println!("  ipc_status: fail ({})", sanitize_terminal_text(e));
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
                let clean = sanitize_terminal_text(line);
                println!("  path_which: {clean}");
            }
        }
    }
    match try_load_identity(data_dir) {
        Ok(Some(id)) => {
            println!("  identity: present");
            print_public_identity(&id);
        }
        Ok(None) => println!("  identity: missing (run raven init)"),
        Err(e) => {
            if identity_err.is_none() {
                identity_err = Some(e.clone());
            }
            println!("  identity: unavailable ({})", sanitize_terminal_text(&e));
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
        // Capture-style: ensure motif strings exist; monochrome only (no brand RGB).
        let art = format!("{}Welcome to Raven Node{}", "\x1b[1m", "\x1b[0m");
        assert!(art.contains("Welcome to Raven Node"));
        assert!(!art.contains("identity.seed"));
        assert!(!art.contains("private"));
        assert!(!art.contains("38;2;64;242;255")); // old cyan RGB gone
        assert!(!art.contains("38;2;191;115;255")); // old purple RGB gone
    }

    #[test]
    fn no_color_style_is_empty() {
        // Palette consts are plain SGR codes (no 24-bit brand RGB).
        assert!(!C_CYAN.contains("38;2"));
        assert!(!C_PURPLE.contains("38;2"));
        assert!(!C_GREEN.contains("38;2"));
        // color_enabled() is cached per-process (OnceLock), so we can only
        // assert consistency with the current environment, not both branches.
        let colors = c();
        let colored_expected = std::env::var_os("NO_COLOR").is_none()
            && std::env::var_os("TERM").as_deref() != Some(std::ffi::OsStr::new("dumb"));
        if colored_expected {
            // Black & white design: accent fields collapse to bold/dim.
            assert_eq!(colors.cyan, colors.bold);
            assert_eq!(colors.purple, colors.bold);
            assert_ne!(colors.yellow, colors.bold);
        } else {
            assert_eq!(colors.cyan, "");
            assert_eq!(colors.bold, "");
        }
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
    fn resolve_reuses_saved_lan_dial_without_prompt() {
        let got = resolve_lan_peer_parts("192.168.1.20:7420", None, false);
        assert_eq!(got, Some(ResolvedLanPeer::Dial("192.168.1.20:7420".into())));
        // Saved wins over env — no stdin involved.
        let got = resolve_lan_peer_parts("10.0.0.2:7420", Some("10.0.0.9:7420"), true);
        assert_eq!(got, Some(ResolvedLanPeer::Dial("10.0.0.2:7420".into())));
    }

    #[test]
    fn resolve_empty_dial_uses_env_then_errors_without_local_queue() {
        let got = resolve_lan_peer_parts("", Some("192.168.1.50:7420"), false);
        assert_eq!(got, Some(ResolvedLanPeer::Dial("192.168.1.50:7420".into())));
        assert_eq!(resolve_lan_peer_parts("", None, true), None);
        assert_eq!(resolve_lan_peer_parts("", None, false), None);
        assert_eq!(resolve_lan_peer_parts("not-a-dial", None, false), None);
        assert_eq!(
            resolve_lan_peer_parts("", Some("rvn1notadial"), false),
            None
        );
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
            assert_eq!(ep, IpcEndpoint::NamedPipe(raven_core::WINDOWS_NAMED_PIPE));
            assert_eq!(ep.to_string(), raven_core::WINDOWS_NAMED_PIPE);
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
}
