//! Versioned, bounded libp2p transport for opaque Raven Store Object V1 rows.
//!
//! This module is compiled only with `experimental-offline-mailbox`. It has no
//! delete operation and accepts only endpoint-supplied 16-byte `store_tag`
//! capabilities; it never derives an index from an envelope routing tag.
//! Network deposits go through [`MailboxService::handle_from`], which charges
//! every PUT to the depositing `PeerId` *and* to its source network (IPv4 /24,
//! IPv6 /48): rate plus outstanding rows/bytes. One peer, or any number of
//! freshly generated PeerIds behind one host or subnet, therefore cannot fill
//! the global store for everyone else. This is not sybil-proof: depositors
//! spread over at least `MAX_STORE_OBJECTS / MAX_OBJECTS_PER_NETWORK` distinct
//! networks can still reach the global cap. Closing that needs an authorized
//! deposit (a recipient-issued capability or payment), which is a protocol
//! change; the mailbox stays lab-only until then.
//!
//! Reads are bounded too: GETs draw on their own per-peer and per-network
//! token buckets, and the page tokens of a tag are cached until its rows
//! change, so a poll does not re-pack and re-hash every stored object. At most
//! `MAX_INFLIGHT_PER_PEER` requests per peer are in flight (see
//! [`InflightLimiter`]).
//!
//! The service never serves or acknowledges a row that is not in the last
//! committed snapshot. If a snapshot write fails and the last snapshot cannot
//! be reloaded either, the service answers `Persistence` until a reload
//! succeeds (retried with backoff); it recovers by itself once the transient
//! condition clears instead of staying wedged until restart.

use std::collections::HashMap;
use std::hash::Hash;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::{Multiaddr, PeerId, StreamProtocol};
use raven_core::store_object::{
    StoreMailbox, StoreObject, MAX_ENVELOPE_LEN, MAX_STORE_BYTES, MAX_STORE_OBJECTS,
};
use sha2::{Digest, Sha256};

/// Multistream-select identifier. Any incompatible wire change gets a new path.
pub const MAILBOX_PROTOCOL_V1: StreamProtocol = StreamProtocol::new("/raven/offline-mailbox/1.0.0");
pub const MAILBOX_DB_FILENAME: &str = "offline_mailbox_v1.json";

pub const MAX_OBJECTS_PER_TAG: usize = 64;
pub const MAX_PAGE_OBJECTS: u16 = 16;
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_REQUEST_SECONDS: u64 = 8;
pub const MAX_CONCURRENT_STREAMS: usize = 32;
pub const MAX_MAILBOX_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
pub const MAX_FUTURE_SKEW_MS: u64 = 5 * 60 * 1_000;

/// Outstanding (unexpired) rows one peer may have deposited (of 4096 total).
pub const MAX_OBJECTS_PER_PEER: usize = 256;
/// Outstanding envelope bytes one peer may have deposited (of 64 MiB total).
pub const MAX_BYTES_PER_PEER: usize = 8 * 1024 * 1024;
/// PUT token bucket per peer: burst size, then one PUT per refill interval.
/// Each accepted PUT rewrites and fsyncs the snapshot, so this also bounds
/// the persistence work a single peer can cause.
pub const PEER_PUT_BURST: u32 = 32;
pub const PEER_PUT_REFILL_MS: u64 = 1_000;
/// Source-network quota (IPv4 /24, IPv6 /48; connections without an IP
/// address share one bucket). PeerIds cost nothing to generate, so this is
/// the bound that actually applies to a sybil flood from one host or subnet.
pub const MAX_OBJECTS_PER_NETWORK: usize = MAX_STORE_OBJECTS / 4;
pub const MAX_BYTES_PER_NETWORK: usize = MAX_STORE_BYTES / 4;
pub const NETWORK_PUT_BURST: u32 = 64;
pub const NETWORK_PUT_REFILL_MS: u64 = 250;
/// Accounting entries kept per table (peers, networks). A full table never
/// refuses a new depositor: idle entries are dropped first, then the entry
/// with the fewest outstanding rows is forgotten. Forgetting only loses that
/// depositor's accounting (the global store caps still hold), so the table
/// cannot be used to lock anyone out.
pub const MAX_TRACKED_DEPOSITORS: usize = MAX_STORE_OBJECTS;
/// How often expired rows are swept from every accounting entry, so tracked
/// rows stay close to the live rows in the store (at most 4096 per table).
const QUOTA_SWEEP_MS: u64 = 60_000;
/// GET token buckets. Reads store nothing, so only their rate is bounded:
/// a page costs at most one tag index build plus a few MiB of copying. Generous
/// enough that polling and paging never notice; refusals use `StoreFull`, the
/// code this module already uses for "over quota".
pub const PEER_GET_BURST: u32 = 64;
pub const PEER_GET_REFILL_MS: u64 = 100;
pub const NETWORK_GET_BURST: u32 = 128;
pub const NETWORK_GET_REFILL_MS: u64 = 50;
/// Requests handled at once by a server, over all peers and for one peer.
pub const MAX_INFLIGHT_REQUESTS: usize = 64;
pub const MAX_INFLIGHT_PER_PEER: usize = 8;
/// While the snapshot cannot be reloaded, the first retry waits this long and
/// each failed retry doubles the wait up to the cap.
const RECOVERY_BACKOFF_INITIAL_MS: u64 = 1_000;
const RECOVERY_BACKOFF_MAX_MS: u64 = 30_000;

// RSO1 fixed prefix (59 B) plus the optional 64-byte custody signature.
pub const MAX_STORE_OBJECT_WIRE_BYTES: usize = MAX_ENVELOPE_LEN + 59 + 64;
// PUT opcode + u32 object length + the largest StoreObjectV1.
pub const MAX_REQUEST_BYTES: usize = MAX_STORE_OBJECT_WIRE_BYTES + 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxRequest {
    Put(Vec<u8>),
    Get {
        store_tag: [u8; 16],
        after: Option<[u8; 32]>,
        limit: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MailboxReject {
    Malformed = 1,
    StoreFull = 2,
    Expired = 3,
    Ttl = 4,
    Persistence = 5,
}

impl MailboxReject {
    fn from_u8(value: u8) -> io::Result<Self> {
        match value {
            1 => Ok(Self::Malformed),
            2 => Ok(Self::StoreFull),
            3 => Ok(Self::Expired),
            4 => Ok(Self::Ttl),
            5 => Ok(Self::Persistence),
            _ => Err(invalid_data("unknown mailbox rejection code")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxResponse {
    Stored,
    Objects {
        /// Stable digest token for the next bounded page. It remains valid if
        /// an earlier row expires between requests.
        next_cursor: Option<[u8; 32]>,
        objects: Vec<Vec<u8>>,
    },
    Rejected(MailboxReject),
}

#[derive(Clone, Default)]
pub struct MailboxCodec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxRole {
    Server,
    Client,
    Full,
}

pub type MailboxBehaviour = request_response::Behaviour<MailboxCodec>;

pub fn mailbox_behaviour(role: MailboxRole) -> MailboxBehaviour {
    let support = match role {
        MailboxRole::Server => ProtocolSupport::Inbound,
        MailboxRole::Client => ProtocolSupport::Outbound,
        MailboxRole::Full => ProtocolSupport::Full,
    };
    let config = request_response::Config::default()
        .with_request_timeout(Duration::from_secs(MAX_REQUEST_SECONDS))
        .with_max_concurrent_streams(MAX_CONCURRENT_STREAMS);
    MailboxBehaviour::with_codec(MailboxCodec, [(MAILBOX_PROTOCOL_V1, support)], config)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn take_u16(raw: &[u8], offset: &mut usize) -> io::Result<u16> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| invalid_data("mailbox integer overflow"))?;
    let bytes: [u8; 2] = raw
        .get(*offset..end)
        .ok_or_else(|| invalid_data("truncated mailbox frame"))?
        .try_into()
        .expect("checked fixed length");
    *offset = end;
    Ok(u16::from_be_bytes(bytes))
}

fn take_u32(raw: &[u8], offset: &mut usize) -> io::Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid_data("mailbox integer overflow"))?;
    let bytes: [u8; 4] = raw
        .get(*offset..end)
        .ok_or_else(|| invalid_data("truncated mailbox frame"))?
        .try_into()
        .expect("checked fixed length");
    *offset = end;
    Ok(u32::from_be_bytes(bytes))
}

async fn read_bounded<T>(io: &mut T, maximum: usize) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let read_maximum = maximum
        .checked_add(1)
        .ok_or_else(|| invalid_input("mailbox frame limit overflow"))?;
    let mut raw = Vec::with_capacity(read_maximum.min(16 * 1024));
    io.take(read_maximum as u64).read_to_end(&mut raw).await?;
    if raw.len() > maximum {
        return Err(invalid_data("mailbox frame exceeds hard limit"));
    }
    Ok(raw)
}

fn encode_request(request: MailboxRequest) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    match request {
        MailboxRequest::Put(object) => {
            if object.len() > MAX_STORE_OBJECT_WIRE_BYTES {
                return Err(invalid_input("store object exceeds hard limit"));
            }
            let len = u32::try_from(object.len())
                .map_err(|_| invalid_input("store object length overflow"))?;
            raw.push(1);
            raw.extend_from_slice(&len.to_be_bytes());
            raw.extend_from_slice(&object);
        }
        MailboxRequest::Get {
            store_tag,
            after,
            limit,
        } => {
            if limit == 0 || limit > MAX_PAGE_OBJECTS {
                return Err(invalid_input("invalid mailbox page limit"));
            }
            raw.push(2);
            raw.extend_from_slice(&store_tag);
            match after {
                Some(token) => {
                    raw.push(1);
                    raw.extend_from_slice(&token);
                }
                None => {
                    raw.push(0);
                    raw.extend_from_slice(&[0u8; 32]);
                }
            }
            raw.extend_from_slice(&limit.to_be_bytes());
        }
    }
    if raw.len() > MAX_REQUEST_BYTES {
        return Err(invalid_input("mailbox request exceeds hard limit"));
    }
    Ok(raw)
}

fn decode_request(raw: &[u8]) -> io::Result<MailboxRequest> {
    let Some(opcode) = raw.first().copied() else {
        return Err(invalid_data("empty mailbox request"));
    };
    match opcode {
        1 => {
            let mut offset = 1;
            let length = take_u32(raw, &mut offset)? as usize;
            if length > MAX_STORE_OBJECT_WIRE_BYTES {
                return Err(invalid_data("store object exceeds hard limit"));
            }
            let end = offset
                .checked_add(length)
                .ok_or_else(|| invalid_data("store object length overflow"))?;
            if end != raw.len() {
                return Err(invalid_data("store object length mismatch"));
            }
            Ok(MailboxRequest::Put(raw[offset..end].to_vec()))
        }
        2 => {
            if raw.len() != 1 + 16 + 1 + 32 + 2 {
                return Err(invalid_data("invalid mailbox get length"));
            }
            let mut store_tag = [0u8; 16];
            store_tag.copy_from_slice(&raw[1..17]);
            let has_after = raw[17];
            if has_after > 1 {
                return Err(invalid_data("invalid mailbox continuation flag"));
            }
            let mut token = [0u8; 32];
            token.copy_from_slice(&raw[18..50]);
            if has_after == 0 && token != [0u8; 32] {
                return Err(invalid_data("noncanonical empty continuation"));
            }
            let mut offset = 50;
            let limit = take_u16(raw, &mut offset)?;
            if limit == 0 || limit > MAX_PAGE_OBJECTS {
                return Err(invalid_data("invalid mailbox page limit"));
            }
            Ok(MailboxRequest::Get {
                store_tag,
                after: (has_after == 1).then_some(token),
                limit,
            })
        }
        _ => Err(invalid_data("unknown mailbox request opcode")),
    }
}

fn encode_response(response: MailboxResponse) -> io::Result<Vec<u8>> {
    let mut raw = Vec::new();
    match response {
        MailboxResponse::Stored => raw.push(0),
        MailboxResponse::Objects {
            next_cursor,
            objects,
        } => {
            if objects.len() > MAX_PAGE_OBJECTS as usize {
                return Err(invalid_input("too many mailbox response objects"));
            }
            canonical_page(next_cursor, &objects).map_err(invalid_input)?;
            raw.push(1);
            match next_cursor {
                Some(token) => {
                    raw.push(1);
                    raw.extend_from_slice(&token);
                }
                None => {
                    raw.push(0);
                    raw.extend_from_slice(&[0u8; 32]);
                }
            }
            raw.extend_from_slice(&(objects.len() as u16).to_be_bytes());
            for object in objects {
                if object.len() > MAX_STORE_OBJECT_WIRE_BYTES {
                    return Err(invalid_input("response store object exceeds hard limit"));
                }
                let length = u32::try_from(object.len())
                    .map_err(|_| invalid_input("response object length overflow"))?;
                raw.extend_from_slice(&length.to_be_bytes());
                raw.extend_from_slice(&object);
            }
        }
        MailboxResponse::Rejected(code) => {
            raw.push(2);
            raw.push(code as u8);
        }
    }
    if raw.len() > MAX_RESPONSE_BYTES {
        return Err(invalid_input("mailbox response exceeds hard limit"));
    }
    Ok(raw)
}

fn decode_response(raw: &[u8]) -> io::Result<MailboxResponse> {
    let Some(opcode) = raw.first().copied() else {
        return Err(invalid_data("empty mailbox response"));
    };
    match opcode {
        0 if raw.len() == 1 => Ok(MailboxResponse::Stored),
        1 => {
            if raw.len() < 1 + 1 + 32 + 2 {
                return Err(invalid_data("truncated mailbox objects response"));
            }
            let has_cursor = raw[1];
            if has_cursor > 1 {
                return Err(invalid_data("invalid mailbox cursor flag"));
            }
            let mut cursor = [0u8; 32];
            cursor.copy_from_slice(&raw[2..34]);
            if has_cursor == 0 && cursor != [0u8; 32] {
                return Err(invalid_data("noncanonical empty cursor"));
            }
            let mut offset = 34;
            let count = take_u16(raw, &mut offset)?;
            if count > MAX_PAGE_OBJECTS {
                return Err(invalid_data("too many mailbox response objects"));
            }
            let mut objects = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let length = take_u32(raw, &mut offset)? as usize;
                if length > MAX_STORE_OBJECT_WIRE_BYTES {
                    return Err(invalid_data("response store object exceeds hard limit"));
                }
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| invalid_data("response object length overflow"))?;
                let object = raw
                    .get(offset..end)
                    .ok_or_else(|| invalid_data("truncated response object"))?;
                objects.push(object.to_vec());
                offset = end;
            }
            if offset != raw.len() {
                return Err(invalid_data("trailing mailbox response bytes"));
            }
            let next_cursor = (has_cursor == 1).then_some(cursor);
            canonical_page(next_cursor, &objects).map_err(invalid_data)?;
            Ok(MailboxResponse::Objects {
                next_cursor,
                objects,
            })
        }
        2 if raw.len() == 2 => Ok(MailboxResponse::Rejected(MailboxReject::from_u8(raw[1])?)),
        _ => Err(invalid_data("invalid mailbox response opcode")),
    }
}

fn canonical_page(next_cursor: Option<[u8; 32]>, objects: &[Vec<u8>]) -> Result<(), &'static str> {
    let mut previous = None;
    for object in objects {
        StoreObject::unpack(object).map_err(|_| "invalid response StoreObjectV1")?;
        let token = page_token(object);
        if previous.is_some_and(|value| value >= token) {
            return Err("noncanonical mailbox object order");
        }
        previous = Some(token);
    }
    if let Some(cursor) = next_cursor {
        if previous != Some(cursor) {
            return Err("mailbox cursor is not bound to the last object");
        }
    }
    Ok(())
}

#[async_trait]
impl request_response::Codec for MailboxCodec {
    type Protocol = StreamProtocol;
    type Request = MailboxRequest;
    type Response = MailboxResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        decode_request(&read_bounded(io, MAX_REQUEST_BYTES).await?)
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        decode_response(&read_bounded(io, MAX_RESPONSE_BYTES).await?)
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode_request(request)?).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        io.write_all(&encode_response(response)?).await
    }
}

#[derive(Clone, Copy, Debug)]
struct QuotaLimits {
    max_rows: usize,
    max_bytes: usize,
    burst: u32,
    refill_ms: u64,
}

const PEER_LIMITS: QuotaLimits = QuotaLimits {
    max_rows: MAX_OBJECTS_PER_PEER,
    max_bytes: MAX_BYTES_PER_PEER,
    burst: PEER_PUT_BURST,
    refill_ms: PEER_PUT_REFILL_MS,
};

const NETWORK_LIMITS: QuotaLimits = QuotaLimits {
    max_rows: MAX_OBJECTS_PER_NETWORK,
    max_bytes: MAX_BYTES_PER_NETWORK,
    burst: NETWORK_PUT_BURST,
    refill_ms: NETWORK_PUT_REFILL_MS,
};

/// Reads are limited by rate only (no outstanding rows or bytes).
const PEER_GET_LIMITS: QuotaLimits = QuotaLimits {
    max_rows: usize::MAX,
    max_bytes: usize::MAX,
    burst: PEER_GET_BURST,
    refill_ms: PEER_GET_REFILL_MS,
};

const NETWORK_GET_LIMITS: QuotaLimits = QuotaLimits {
    max_rows: usize::MAX,
    max_bytes: usize::MAX,
    burst: NETWORK_GET_BURST,
    refill_ms: NETWORK_GET_REFILL_MS,
};

/// Source network a deposit is charged to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetworkKey {
    V4([u8; 3]),
    V6([u8; 6]),
    /// No IP address known (e.g. a non-IP transport): one shared bucket.
    Unknown,
}

impl NetworkKey {
    /// IPv4 /24 or IPv6 /48 (IPv4-mapped IPv6 counts as IPv4).
    pub fn from_ip(origin: Option<IpAddr>) -> Self {
        let ip = match origin {
            None => return Self::Unknown,
            Some(IpAddr::V6(v6)) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            Some(ip) => ip,
        };
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                Self::V4([o[0], o[1], o[2]])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                Self::V6([o[0], o[1], o[2], o[3], o[4], o[5]])
            }
        }
    }
}

/// First IP address in a connection's remote multiaddr, if any.
pub fn multiaddr_ip(address: &Multiaddr) -> Option<IpAddr> {
    address.iter().find_map(|protocol| match protocol {
        Protocol::Ip4(ip) => Some(IpAddr::V4(ip)),
        Protocol::Ip6(ip) => Some(IpAddr::V6(ip)),
        _ => None,
    })
}

/// In-memory accounting for one depositor (process lifetime).
struct Deposits {
    tokens: u32,
    last_refill_ms: u64,
    /// (expires_at_ms, envelope bytes) of rows this depositor stored.
    rows: Vec<(u64, usize)>,
}

impl Deposits {
    fn new(limits: QuotaLimits, now_ms: u64) -> Self {
        Self {
            tokens: limits.burst,
            last_refill_ms: now_ms,
            rows: Vec::new(),
        }
    }

    fn refresh(&mut self, limits: QuotaLimits, now_ms: u64) {
        self.rows.retain(|(expires, _)| *expires > now_ms);
        let steps = now_ms.saturating_sub(self.last_refill_ms) / limits.refill_ms.max(1);
        if steps > 0 {
            let added = u32::try_from(steps).unwrap_or(u32::MAX);
            self.tokens = self.tokens.saturating_add(added).min(limits.burst);
            self.last_refill_ms = self
                .last_refill_ms
                .saturating_add(steps.saturating_mul(limits.refill_ms.max(1)));
        }
    }

    fn admits(&self, limits: QuotaLimits, bytes: usize) -> bool {
        let outstanding: usize = self.rows.iter().map(|(_, bytes)| *bytes).sum();
        self.tokens > 0
            && self.rows.len() < limits.max_rows
            && outstanding.saturating_add(bytes) <= limits.max_bytes
    }

    fn idle(&self, limits: QuotaLimits) -> bool {
        self.rows.is_empty() && self.tokens >= limits.burst
    }
}

/// Bounded depositor -> accounting table. Never refuses a new key.
struct QuotaTable<K> {
    limits: QuotaLimits,
    capacity: usize,
    entries: HashMap<K, Deposits>,
}

impl<K: Copy + Eq + Hash> QuotaTable<K> {
    fn new(limits: QuotaLimits, capacity: usize) -> Self {
        Self {
            limits,
            capacity: capacity.max(1),
            entries: HashMap::new(),
        }
    }

    /// Refreshed accounting for `key`, making room if the table is full.
    fn slot(&mut self, key: K, now_ms: u64) -> &mut Deposits {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            self.make_room(now_ms);
        }
        let limits = self.limits;
        let entry = self
            .entries
            .entry(key)
            .or_insert_with(|| Deposits::new(limits, now_ms));
        entry.refresh(limits, now_ms);
        entry
    }

    /// Drop expired rows everywhere and forget idle depositors.
    fn sweep(&mut self, now_ms: u64) {
        let limits = self.limits;
        for entry in self.entries.values_mut() {
            entry.refresh(limits, now_ms);
        }
        self.entries.retain(|_, entry| !entry.idle(limits));
    }

    fn make_room(&mut self, now_ms: u64) {
        self.sweep(now_ms);
        while self.entries.len() >= self.capacity {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.rows.len())
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.entries.remove(&victim);
        }
    }

    fn record(&mut self, key: &K, row: Option<(u64, usize)>) {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.tokens = entry.tokens.saturating_sub(1);
            if let Some(row) = row {
                entry.rows.push(row);
            }
        }
    }
}

type SaveSnapshot = fn(&StoreMailbox, &Path) -> Result<(), String>;
type LoadSnapshot = fn(&Path, usize) -> Result<StoreMailbox, String>;

/// One live row of a tag, as the page cursor sees it.
struct IndexedRow {
    /// `page_token` of the packed object (the wire cursor value).
    token: [u8; 32],
    /// Packed size, for the response byte budget.
    packed_len: usize,
    /// Index into `StoreMailbox::get` order for this tag.
    position: usize,
}

pub struct MailboxService {
    mailbox: StoreMailbox,
    path: PathBuf,
    available: bool,
    /// Whether a snapshot file is known to exist (it did at open, or a save
    /// has succeeded since). `StoreMailbox::load_disk` reads *any* stat error
    /// as "no snapshot yet" and returns an empty mailbox; once a snapshot has
    /// existed that answer must not be trusted, or a transient error would
    /// silently drop every stored row.
    snapshot_seen: bool,
    /// Earliest time an unavailable service may retry its reload, and the wait
    /// that follows the next failed retry.
    recover_at_ms: u64,
    recover_backoff_ms: u64,
    persist_failures: u64,
    recoveries: u64,
    peers: QuotaTable<PeerId>,
    networks: QuotaTable<NetworkKey>,
    get_peers: QuotaTable<PeerId>,
    get_networks: QuotaTable<NetworkKey>,
    last_sweep_ms: u64,
    /// Rows of each tag ordered by page token, valid until the tag's rows
    /// change. Page tokens depend only on the immutable packed bytes, so a GET
    /// hashes a tag once per change instead of once per page and poll.
    token_cache: HashMap<[u8; 16], Vec<IndexedRow>>,
    /// Persistence primitives; replaced only by tests to inject failures.
    save: SaveSnapshot,
    load: LoadSnapshot,
}

impl MailboxService {
    pub fn open(data_dir: &Path) -> Result<Self, String> {
        let path = data_dir.join(MAILBOX_DB_FILENAME);
        let mailbox = StoreMailbox::load_disk(&path, MAX_OBJECTS_PER_TAG)?;
        let snapshot_seen = std::fs::symlink_metadata(&path).is_ok();
        Ok(Self {
            mailbox,
            path,
            available: true,
            snapshot_seen,
            recover_at_ms: 0,
            recover_backoff_ms: RECOVERY_BACKOFF_INITIAL_MS,
            persist_failures: 0,
            recoveries: 0,
            peers: QuotaTable::new(PEER_LIMITS, MAX_TRACKED_DEPOSITORS),
            networks: QuotaTable::new(NETWORK_LIMITS, MAX_TRACKED_DEPOSITORS),
            get_peers: QuotaTable::new(PEER_GET_LIMITS, MAX_TRACKED_DEPOSITORS),
            get_networks: QuotaTable::new(NETWORK_GET_LIMITS, MAX_TRACKED_DEPOSITORS),
            last_sweep_ms: 0,
            token_cache: HashMap::new(),
            save: StoreMailbox::save_disk,
            load: StoreMailbox::load_disk,
        })
    }

    /// `false` while the service is refusing everything with `Persistence`
    /// because its snapshot could not be reloaded after a failed write.
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Snapshot writes that failed since open (each one was rolled back).
    pub fn persistence_failures(&self) -> u64 {
        self.persist_failures
    }

    /// Times the service came back from unavailable by reloading its snapshot.
    pub fn recoveries(&self) -> u64 {
        self.recoveries
    }

    /// Network entry point: like [`Self::handle`], but requests are charged to
    /// `peer` and to its source network `origin`. A PUT draws on a rate limit
    /// plus an outstanding row/byte quota for each; a GET on a rate limit for
    /// each. Over-quota requests are refused with `StoreFull` before any
    /// parsing, persistence or page work. A new depositor is never refused
    /// because of how many depositors are already tracked.
    pub fn handle_from(
        &mut self,
        peer: PeerId,
        origin: Option<IpAddr>,
        request: MailboxRequest,
        now_ms: u64,
    ) -> MailboxResponse {
        self.sweep_quotas_if_due(now_ms);
        let network = NetworkKey::from_ip(origin);
        let raw = match request {
            MailboxRequest::Put(raw) => raw,
            get => {
                if !self.admit_get(peer, network, now_ms) {
                    return MailboxResponse::Rejected(MailboxReject::StoreFull);
                }
                return self.handle(get, now_ms);
            }
        };
        if !self.ensure_available(now_ms) {
            return MailboxResponse::Rejected(MailboxReject::Persistence);
        }
        let bytes = raw.len();
        let peer_ok = {
            let limits = self.peers.limits;
            self.peers.slot(peer, now_ms).admits(limits, bytes)
        };
        let network_ok = {
            let limits = self.networks.limits;
            self.networks.slot(network, now_ms).admits(limits, bytes)
        };
        if !peer_ok || !network_ok {
            return MailboxResponse::Rejected(MailboxReject::StoreFull);
        }
        let result = self.put_object(raw, now_ms);
        // Every attempt past the quota check spends a token; only a newly
        // stored row (not a duplicate or a refusal) counts as outstanding.
        let row = match result {
            Ok(Some(expires_at_ms)) => Some((expires_at_ms, bytes)),
            _ => None,
        };
        self.peers.record(&peer, row);
        self.networks.record(&network, row);
        match result {
            Ok(_) => MailboxResponse::Stored,
            Err(code) => MailboxResponse::Rejected(code),
        }
    }

    fn sweep_quotas_if_due(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_sweep_ms) >= QUOTA_SWEEP_MS {
            self.peers.sweep(now_ms);
            self.networks.sweep(now_ms);
            self.get_peers.sweep(now_ms);
            self.get_networks.sweep(now_ms);
            self.last_sweep_ms = now_ms;
        }
    }

    /// Spend one GET token from the peer's and the network's bucket, or spend
    /// nothing and report `false` when either is empty.
    fn admit_get(&mut self, peer: PeerId, network: NetworkKey, now_ms: u64) -> bool {
        let peer_ok = {
            let limits = self.get_peers.limits;
            self.get_peers.slot(peer, now_ms).admits(limits, 0)
        };
        let network_ok = {
            let limits = self.get_networks.limits;
            self.get_networks.slot(network, now_ms).admits(limits, 0)
        };
        if !peer_ok || !network_ok {
            return false;
        }
        self.get_peers.record(&peer, None);
        self.get_networks.record(&network, None);
        true
    }

    pub fn handle(&mut self, request: MailboxRequest, now_ms: u64) -> MailboxResponse {
        if !self.ensure_available(now_ms) {
            return MailboxResponse::Rejected(MailboxReject::Persistence);
        }
        match request {
            MailboxRequest::Put(raw) => self.put(raw, now_ms),
            MailboxRequest::Get {
                store_tag,
                after,
                limit,
            } => self.get(store_tag, after, limit, now_ms),
        }
    }

    /// The last committed snapshot, never an empty store in its place.
    fn reload(&self) -> Result<StoreMailbox, String> {
        if self.snapshot_seen {
            std::fs::symlink_metadata(&self.path).map_err(|e| e.to_string())?;
        }
        (self.load)(&self.path, MAX_OBJECTS_PER_TAG)
    }

    /// Replace the in-memory rows with a freshly loaded snapshot.
    fn adopt(&mut self, mailbox: StoreMailbox) {
        self.mailbox = mailbox;
        self.token_cache.clear();
    }

    /// `true` when the service can take a request. While unavailable, retry
    /// the snapshot reload (rate-limited with backoff): a transient failure
    /// (fd exhaustion, a backup tool touching the file) must not wedge the
    /// mailbox until restart. Reloading drops any uncommitted in-memory row,
    /// so nothing unacknowledged is ever served, and the private-file checks in
    /// `load_disk` keep failing closed on a real security problem.
    fn ensure_available(&mut self, now_ms: u64) -> bool {
        if self.available {
            return true;
        }
        if now_ms < self.recover_at_ms {
            return false;
        }
        match self.reload() {
            Ok(mailbox) => {
                self.adopt(mailbox);
                self.available = true;
                self.recoveries += 1;
                self.recover_backoff_ms = RECOVERY_BACKOFF_INITIAL_MS;
                true
            }
            Err(_) => {
                self.recover_backoff_ms =
                    (self.recover_backoff_ms.saturating_mul(2)).min(RECOVERY_BACKOFF_MAX_MS);
                self.recover_at_ms = now_ms.saturating_add(self.recover_backoff_ms);
                false
            }
        }
    }

    fn persist(&mut self, now_ms: u64) -> Result<(), MailboxReject> {
        if (self.save)(&self.mailbox, &self.path).is_ok() {
            self.snapshot_seen = true;
            return Ok(());
        }
        self.persist_failures += 1;
        // Never acknowledge a row that was not durably committed. Reloading
        // the last atomic snapshot also removes the uncommitted in-memory row.
        match self.reload() {
            Ok(previous) => self.adopt(previous),
            Err(_) => {
                self.available = false;
                self.recover_backoff_ms = RECOVERY_BACKOFF_INITIAL_MS;
                self.recover_at_ms = now_ms.saturating_add(self.recover_backoff_ms);
            }
        }
        Err(MailboxReject::Persistence)
    }

    /// Drop expired rows; the cached page tokens go with them.
    fn purge_expired(&mut self, now_ms: u64) -> usize {
        let removed = self.mailbox.purge_expired(now_ms);
        if removed > 0 {
            self.token_cache.clear();
        }
        removed
    }

    fn put(&mut self, raw: Vec<u8>, now_ms: u64) -> MailboxResponse {
        match self.put_object(raw, now_ms) {
            Ok(_) => MailboxResponse::Stored,
            Err(code) => MailboxResponse::Rejected(code),
        }
    }

    /// Store one object. `Ok(Some(expires_at_ms))` when a new row was
    /// stored, `Ok(None)` when an identical row was already present.
    fn put_object(&mut self, raw: Vec<u8>, now_ms: u64) -> Result<Option<u64>, MailboxReject> {
        if raw.len() > MAX_STORE_OBJECT_WIRE_BYTES {
            return Err(MailboxReject::Malformed);
        }
        let object = StoreObject::unpack(&raw).map_err(|_| MailboxReject::Malformed)?;
        if object.expired(now_ms) {
            return Err(MailboxReject::Expired);
        }
        let latest_allowed = now_ms
            .checked_add(MAX_MAILBOX_TTL_MS)
            .ok_or(MailboxReject::Ttl)?;
        let future_creation = now_ms
            .checked_add(MAX_FUTURE_SKEW_MS)
            .ok_or(MailboxReject::Ttl)?;
        if object.expires_at_ms > latest_allowed || object.created_at_ms > future_creation {
            return Err(MailboxReject::Ttl);
        }
        let expires_at_ms = object.expires_at_ms;
        let store_tag = object.store_tag;
        self.purge_expired(now_ms);
        let before = self.mailbox.get(&store_tag, now_ms).len();
        match self.mailbox.put(object) {
            Ok(()) => {
                let stored_new = self.mailbox.get(&store_tag, now_ms).len() > before;
                if stored_new {
                    // The tag's rows changed; an unchanged tag keeps its tokens.
                    self.token_cache.remove(&store_tag);
                }
                self.persist(now_ms)
                    .map(|()| stored_new.then_some(expires_at_ms))
            }
            Err(error) if error == "STORE_FULL" => Err(MailboxReject::StoreFull),
            Err(error) if error == "STORE_EXPIRED" => Err(MailboxReject::Expired),
            Err(_) => Err(MailboxReject::Malformed),
        }
    }

    fn get(
        &mut self,
        store_tag: [u8; 16],
        after: Option<[u8; 32]>,
        limit: u16,
        now_ms: u64,
    ) -> MailboxResponse {
        if limit == 0 || limit > MAX_PAGE_OBJECTS {
            return MailboxResponse::Rejected(MailboxReject::Malformed);
        }
        if self.purge_expired(now_ms) > 0 && self.persist(now_ms).is_err() {
            return MailboxResponse::Rejected(MailboxReject::Persistence);
        }
        let live = self.mailbox.get(&store_tag, now_ms);
        if live.is_empty() {
            return MailboxResponse::Objects {
                next_cursor: None,
                objects: Vec::new(),
            };
        }
        // Tokens are computed once per change of the tag, not per page: pack
        // and hash one object at a time, keeping only the digest and size.
        let rows = match self.token_cache.get(&store_tag) {
            Some(rows) if rows.len() == live.len() => rows,
            _ => {
                let mut rows = Vec::with_capacity(live.len());
                for (position, object) in live.iter().enumerate() {
                    let packed = match object.pack() {
                        Ok(packed) => packed,
                        Err(_) => return MailboxResponse::Rejected(MailboxReject::Persistence),
                    };
                    rows.push(IndexedRow {
                        token: page_token(&packed),
                        packed_len: packed.len(),
                        position,
                    });
                }
                rows.sort_unstable_by_key(|row| row.token);
                self.token_cache.entry(store_tag).or_insert(rows)
            }
        };
        let first = after.map_or(0, |after| rows.partition_point(|row| row.token <= after));
        let remaining = &rows[first..];
        if remaining.is_empty() {
            return MailboxResponse::Objects {
                next_cursor: None,
                objects: Vec::new(),
            };
        }

        // Only the rows that fit the page are packed (a second time) and sent.
        let mut page = Vec::new();
        let mut encoded_bytes: usize = 1 + 1 + 32 + 2;
        for row in remaining.iter().take(limit as usize) {
            let next_size = match encoded_bytes.checked_add(4 + row.packed_len) {
                Some(value) => value,
                None => break,
            };
            if next_size > MAX_RESPONSE_BYTES {
                break;
            }
            encoded_bytes = next_size;
            page.push(row);
        }
        let mut objects = Vec::with_capacity(page.len());
        for row in &page {
            match live[row.position].pack() {
                Ok(packed) => objects.push(packed),
                Err(_) => return MailboxResponse::Rejected(MailboxReject::Persistence),
            }
        }
        let next_cursor = if page.len() < remaining.len() {
            page.last().map(|row| row.token)
        } else {
            None
        };
        MailboxResponse::Objects {
            next_cursor,
            objects,
        }
    }

    pub fn resource_limits() -> (usize, usize, usize) {
        (MAX_OBJECTS_PER_TAG, MAX_STORE_OBJECTS, MAX_STORE_BYTES)
    }
}

#[derive(Default)]
struct InflightState {
    total: usize,
    per_peer: HashMap<PeerId, usize>,
}

/// Bounds the requests a server handles at once: `total` over all peers and
/// `per_peer` for any one PeerId, so a single peer (2 connections x 32 streams
/// is already 64 requests) cannot take the whole budget and starve everyone
/// else. Excess requests are refused, not queued.
#[derive(Clone)]
pub struct InflightLimiter {
    total: usize,
    per_peer: usize,
    state: Arc<Mutex<InflightState>>,
}

/// Holds one in-flight slot until dropped.
pub struct InflightPermit {
    peer: PeerId,
    state: Arc<Mutex<InflightState>>,
}

impl InflightLimiter {
    pub fn new(total: usize, per_peer: usize) -> Self {
        Self {
            total,
            per_peer,
            state: Arc::new(Mutex::new(InflightState::default())),
        }
    }

    /// A slot for one more request from `peer`, or `None` when the global or
    /// the per-peer budget is used up.
    pub fn try_acquire(&self, peer: PeerId) -> Option<InflightPermit> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let used = state.per_peer.get(&peer).copied().unwrap_or(0);
        if state.total >= self.total || used >= self.per_peer {
            return None;
        }
        state.total += 1;
        state.per_peer.insert(peer, used + 1);
        Some(InflightPermit {
            peer,
            state: self.state.clone(),
        })
    }
}

impl Drop for InflightPermit {
    fn drop(&mut self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.total = state.total.saturating_sub(1);
        if let Some(used) = state.per_peer.get_mut(&self.peer) {
            *used = used.saturating_sub(1);
            if *used == 0 {
                state.per_peer.remove(&self.peer);
            }
        }
    }
}

fn page_token(packed_object: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"raven/offline-mailbox/page-token/v1");
    hash.update(packed_object);
    hash.finalize().into()
}

pub fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use futures::{io::Cursor, StreamExt};
    use libp2p::identity::Keypair;
    use libp2p::multiaddr::Protocol;
    use libp2p::request_response::{Event, Message};
    use libp2p::swarm::SwarmEvent;
    use libp2p::{noise, tcp, yamux, Multiaddr, Swarm, SwarmBuilder};
    use raven_core::envelope::{EnvType, Envelope};
    use raven_core::identity::Identity;

    use super::*;

    fn valid_store_object(now: u64, body: &[u8]) -> Vec<u8> {
        let signer = Identity::from_seed(&[0x31; 32]);
        let mut envelope = Envelope {
            env_type: EnvType::Message as u8,
            flags: 0,
            message_id: [0x42; 16],
            routing_tag: [0x99; 16],
            dest_device_hint: 7,
            created_at: now,
            expires_at: now + 60_000,
            hop_limit: 4,
            replication_budget: 2,
            anti_replay_nonce: [0x18; 12],
            ratchet_header_ciphertext: Vec::new(),
            message_ciphertext: body.to_vec(),
            sender_authentication: Vec::new(),
        };
        envelope.sign_with(&signer);
        StoreObject {
            store_tag: [0x77; 16],
            message_id: envelope.message_id,
            created_at_ms: now,
            expires_at_ms: now + 60_000,
            flags: 0,
            packed_envelope: envelope.pack(),
            custody_sig: None,
        }
        .pack()
        .unwrap()
    }

    fn test_swarm(role: MailboxRole, seed: [u8; 32]) -> Swarm<MailboxBehaviour> {
        let keypair = Keypair::ed25519_from_bytes(seed).unwrap();
        SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .unwrap()
            .with_behaviour(|_| mailbox_behaviour(role))
            .unwrap()
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(10))
            })
            .build()
    }

    async fn listen_address(server: &mut Swarm<MailboxBehaviour>) -> Multiaddr {
        server
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = server.select_next_some().await {
                    return address;
                }
            }
        })
        .await
        .expect("server listen timeout")
    }

    async fn network_round_trip(
        server: &mut Swarm<MailboxBehaviour>,
        client: &mut Swarm<MailboxBehaviour>,
        service: &mut MailboxService,
        request: MailboxRequest,
    ) -> MailboxResponse {
        let server_peer = *server.local_peer_id();
        if !client.is_connected(&server_peer) {
            let existing_address = server.listeners().next().cloned();
            let address = match existing_address {
                Some(address) => address,
                None => listen_address(server).await,
            };
            client
                .dial(address.with(Protocol::P2p(server_peer)))
                .unwrap();
        }
        let request_id = client.behaviour_mut().send_request(&server_peer, request);

        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                tokio::select! {
                    event = server.select_next_some() => {
                        if let SwarmEvent::Behaviour(Event::Message {
                            message: Message::Request { request, channel, .. },
                            ..
                        }) = event {
                            let response = service.handle(request, unix_time_ms());
                            server.behaviour_mut().send_response(channel, response).unwrap();
                        }
                    }
                    event = client.select_next_some() => {
                        match event {
                            SwarmEvent::Behaviour(Event::Message {
                                message: Message::Response {
                                    request_id: got_id,
                                    response,
                                },
                                ..
                            }) if got_id == request_id => return response,
                            SwarmEvent::Behaviour(Event::OutboundFailure {
                                request_id: got_id,
                                error,
                                ..
                            }) if got_id == request_id => panic!("mailbox request failed: {error}"),
                            _ => {}
                        }
                    }
                }
            }
        })
        .await
        .expect("mailbox round trip timeout")
    }

    #[tokio::test]
    async fn codec_rejects_oversize_and_noncanonical_frames() {
        use libp2p::request_response::Codec as _;

        let mut codec = MailboxCodec;
        let mut output = Cursor::new(Vec::new());
        let error = codec
            .write_request(
                &MAILBOX_PROTOCOL_V1,
                &mut output,
                MailboxRequest::Put(vec![0; MAX_STORE_OBJECT_WIRE_BYTES + 1]),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);

        let mut oversized_wire = Cursor::new(vec![0; MAX_REQUEST_BYTES + 1]);
        let error = codec
            .read_request(&MAILBOX_PROTOCOL_V1, &mut oversized_wire)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);

        assert!(decode_request(&[2; 24]).is_err());
        assert!(decode_response(&[0, 0]).is_err());
    }

    #[test]
    fn request_and_response_wire_roundtrip_is_canonical() {
        let request = MailboxRequest::Get {
            store_tag: [7; 16],
            after: Some([8; 32]),
            limit: 3,
        };
        assert_eq!(
            decode_request(&encode_request(request.clone()).unwrap()).unwrap(),
            request
        );

        let object = valid_store_object(unix_time_ms(), b"wire-roundtrip");
        let response = MailboxResponse::Objects {
            next_cursor: Some(page_token(&object)),
            objects: vec![object],
        };
        assert_eq!(
            decode_response(&encode_response(response.clone()).unwrap()).unwrap(),
            response
        );

        assert!(encode_response(MailboxResponse::Objects {
            next_cursor: Some([0; 32]),
            objects: Vec::new(),
        })
        .is_err());
        assert!(encode_response(MailboxResponse::Objects {
            next_cursor: None,
            objects: vec![b"not-rso1".to_vec()],
        })
        .is_err());
    }

    #[tokio::test]
    async fn localhost_put_survives_sender_disconnect_and_store_restart() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let opaque_object = valid_store_object(now, b"opaque-network-ciphertext");

        let mut first_server = test_swarm(MailboxRole::Server, [1; 32]);
        let mut sender = test_swarm(MailboxRole::Client, [2; 32]);
        let mut first_service = MailboxService::open(directory.path()).unwrap();

        let malformed = network_round_trip(
            &mut first_server,
            &mut sender,
            &mut first_service,
            MailboxRequest::Put(b"not-rso1".to_vec()),
        )
        .await;
        assert_eq!(
            malformed,
            MailboxResponse::Rejected(MailboxReject::Malformed)
        );

        // The request crosses the libp2p stream, but strict StoreObject parsing
        // rejects its attacker-controlled envelope length before allocation.
        let mut declared_oversize = vec![0u8; 59];
        declared_oversize[..4].copy_from_slice(b"RSO1");
        declared_oversize[4] = 1;
        declared_oversize[55..59].copy_from_slice(&((MAX_ENVELOPE_LEN as u32) + 1).to_be_bytes());
        let oversize = network_round_trip(
            &mut first_server,
            &mut sender,
            &mut first_service,
            MailboxRequest::Put(declared_oversize),
        )
        .await;
        assert_eq!(
            oversize,
            MailboxResponse::Rejected(MailboxReject::Malformed)
        );

        let stored = network_round_trip(
            &mut first_server,
            &mut sender,
            &mut first_service,
            MailboxRequest::Put(opaque_object.clone()),
        )
        .await;
        assert_eq!(stored, MailboxResponse::Stored);

        // Sender is gone before retrieval. Reopening both the service and its
        // libp2p listener proves retrieval comes from the crash-safe snapshot.
        drop(sender);
        drop(first_server);
        drop(first_service);

        let mut restarted_server = test_swarm(MailboxRole::Server, [1; 32]);
        let mut recipient = test_swarm(MailboxRole::Client, [3; 32]);
        let mut restarted_service = MailboxService::open(directory.path()).unwrap();
        let response = network_round_trip(
            &mut restarted_server,
            &mut recipient,
            &mut restarted_service,
            MailboxRequest::Get {
                store_tag: [0x77; 16],
                after: None,
                limit: MAX_PAGE_OBJECTS,
            },
        )
        .await;
        assert_eq!(
            response,
            MailboxResponse::Objects {
                next_cursor: None,
                objects: vec![opaque_object],
            }
        );
    }

    #[test]
    fn service_rejects_declared_oversize_and_excess_ttl() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();

        let mut declared_oversize = vec![0u8; 59];
        declared_oversize[..4].copy_from_slice(b"RSO1");
        declared_oversize[4] = 1;
        declared_oversize[55..59].copy_from_slice(&((MAX_ENVELOPE_LEN as u32) + 1).to_be_bytes());
        assert_eq!(
            service.handle(MailboxRequest::Put(declared_oversize), now),
            MailboxResponse::Rejected(MailboxReject::Malformed)
        );

        let object = StoreObject::unpack(&valid_store_object(now, b"ttl")).unwrap();
        let mut long_lived = StoreObject {
            expires_at_ms: now + MAX_MAILBOX_TTL_MS + 1,
            ..object
        };
        let mut envelope =
            raven_core::envelope::Envelope::unpack(&long_lived.packed_envelope).unwrap();
        envelope.expires_at = long_lived.expires_at_ms;
        envelope.sign_with(&Identity::from_seed(&[0x31; 32]));
        long_lived.packed_envelope = envelope.pack();
        assert_eq!(
            service.handle(MailboxRequest::Put(long_lived.pack().unwrap()), now),
            MailboxResponse::Rejected(MailboxReject::Ttl)
        );
    }

    /// Hour-long object under `store_tag = [tag; 16]` (outlives the test clock).
    fn tagged_store_object(now: u64, tag: u8, body: &[u8]) -> Vec<u8> {
        let mut object = StoreObject::unpack(&valid_store_object(now, body)).unwrap();
        let mut envelope = Envelope::unpack(&object.packed_envelope).unwrap();
        envelope.expires_at = now + 3_600_000;
        envelope.sign_with(&Identity::from_seed(&[0x31; 32]));
        object.packed_envelope = envelope.pack();
        object.expires_at_ms = now + 3_600_000;
        object.store_tag = [tag; 16];
        object.pack().unwrap()
    }

    fn ip(text: &str) -> Option<IpAddr> {
        Some(text.parse().unwrap())
    }

    /// Regression: PUT quotas were only global/per-tag, so one peer spraying
    /// random tags could fill the store for every other depositor.
    #[test]
    fn one_peer_cannot_exhaust_the_store_for_others() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();
        let flooder = PeerId::random();
        let flooder_ip = ip("198.51.100.7");
        let honest = PeerId::random();
        let honest_ip = ip("203.0.113.9");

        // Burst limit: the flooder is cut off long before the global cap.
        let mut stored = 0usize;
        for i in 0..(PEER_PUT_BURST as usize + 8) {
            let object = tagged_store_object(now, (i % 250) as u8, &[i as u8, 1]);
            if service.handle_from(flooder, flooder_ip, MailboxRequest::Put(object), now)
                == MailboxResponse::Stored
            {
                stored += 1;
            }
        }
        assert_eq!(stored, PEER_PUT_BURST as usize);
        assert_eq!(
            service.handle_from(
                flooder,
                flooder_ip,
                MailboxRequest::Put(tagged_store_object(now, 251, b"late")),
                now
            ),
            MailboxResponse::Rejected(MailboxReject::StoreFull)
        );
        // Other peers are unaffected.
        assert_eq!(
            service.handle_from(
                honest,
                honest_ip,
                MailboxRequest::Put(tagged_store_object(now, 252, b"mine")),
                now
            ),
            MailboxResponse::Stored
        );

        // Tokens refill over time, but the outstanding-row quota still binds.
        let mut later = now;
        let mut total = stored;
        while total < MAX_OBJECTS_PER_PEER + 4 {
            later += PEER_PUT_REFILL_MS;
            let object =
                tagged_store_object(now, (total % 200) as u8, &(total as u32).to_be_bytes());
            if service.handle_from(flooder, flooder_ip, MailboxRequest::Put(object), later)
                == MailboxResponse::Stored
            {
                total += 1;
            } else {
                break;
            }
        }
        assert_eq!(total, MAX_OBJECTS_PER_PEER);

        // A duplicate of a stored row is acknowledged but not charged as a
        // second outstanding row (and cannot be used to inflate accounting).
        let honest_rows = service.peers.entries[&honest].rows.len();
        assert_eq!(
            service.handle_from(
                honest,
                honest_ip,
                MailboxRequest::Put(tagged_store_object(now, 252, b"mine")),
                later
            ),
            MailboxResponse::Stored
        );
        assert_eq!(service.peers.entries[&honest].rows.len(), honest_rows);

        // Reads are not charged to the PUT quota (they have their own bucket).
        assert!(matches!(
            service.handle_from(
                flooder,
                flooder_ip,
                MailboxRequest::Get {
                    store_tag: [252; 16],
                    after: None,
                    limit: 1,
                },
                later
            ),
            MailboxResponse::Objects { .. }
        ));
    }

    /// Regression (review of node-swarm#16): PeerIds are free, so a per-PeerId
    /// quota alone lets one host rotate identities. Fresh PeerIds from the
    /// same /24 (or /48) share the network bucket; other networks are not
    /// affected.
    #[test]
    fn sybil_peer_ids_from_one_network_share_its_quota() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();

        let mut stored = 0usize;
        for i in 0..(NETWORK_PUT_BURST as usize + 16) {
            // A brand-new PeerId (full personal burst) for every PUT.
            let origin = ip(&format!("198.51.100.{}", i % 250));
            let object = tagged_store_object(now, (i % 250) as u8, &(i as u32).to_be_bytes());
            if service.handle_from(PeerId::random(), origin, MailboxRequest::Put(object), now)
                == MailboxResponse::Stored
            {
                stored += 1;
            }
        }
        assert_eq!(stored, NETWORK_PUT_BURST as usize);
        assert_eq!(
            service.handle_from(
                PeerId::random(),
                ip("::ffff:198.51.100.77"),
                MailboxRequest::Put(tagged_store_object(now, 1, b"mapped")),
                now
            ),
            MailboxResponse::Rejected(MailboxReject::StoreFull),
            "IPv4-mapped IPv6 must share the IPv4 bucket"
        );
        assert_eq!(
            service.handle_from(
                PeerId::random(),
                ip("198.51.101.1"),
                MailboxRequest::Put(tagged_store_object(now, 2, b"neighbour /24")),
                now
            ),
            MailboxResponse::Stored
        );

        for (a, b, same) in [
            ("10.1.2.3", "10.1.2.200", true),
            ("10.1.2.3", "10.1.3.3", false),
            ("2001:db8:1:2::1", "2001:db8:1:ffff::9", true),
            ("2001:db8:1:2::1", "2001:db8:2:2::1", false),
            ("::ffff:10.1.2.3", "10.1.2.9", true),
        ] {
            assert_eq!(
                NetworkKey::from_ip(ip(a)) == NetworkKey::from_ip(ip(b)),
                same,
                "{a} vs {b}"
            );
        }
        assert_eq!(NetworkKey::from_ip(None), NetworkKey::Unknown);
        let quic: Multiaddr = "/ip6/2001:db8::1/udp/4001/quic-v1".parse().unwrap();
        assert_eq!(multiaddr_ip(&quic), ip("2001:db8::1"));
        let tcp: Multiaddr = "/ip4/192.0.2.1/tcp/4001".parse().unwrap();
        assert_eq!(multiaddr_ip(&tcp), ip("192.0.2.1"));
        let dns: Multiaddr = "/dns4/example.org/tcp/4001".parse().unwrap();
        assert_eq!(multiaddr_ip(&dns), None);
    }

    /// Regression (review of node-swarm#16): a table of 1024 tracked peers
    /// that each held one long-lived row refused every new depositor with
    /// StoreFull for up to 7 days. A full table must make room instead, and
    /// must forget light entries before heavy ones.
    #[test]
    fn full_depositor_table_never_locks_out_new_depositors() {
        let now = 1_000_000u64;
        let week = now + MAX_MAILBOX_TTL_MS;
        let mut table: QuotaTable<u32> = QuotaTable::new(PEER_LIMITS, MAX_TRACKED_DEPOSITORS);

        // One heavy depositor, then enough one-row sybils to fill the table.
        let heavy = u32::MAX;
        for _ in 0..16 {
            assert!(table.slot(heavy, now).admits(PEER_LIMITS, 1));
            table.record(&heavy, Some((week, 1)));
        }
        for key in 0..(MAX_TRACKED_DEPOSITORS as u32 - 1) {
            assert!(table.slot(key, now).admits(PEER_LIMITS, 1));
            table.record(&key, Some((week, 1)));
        }
        assert_eq!(table.entries.len(), MAX_TRACKED_DEPOSITORS);

        // Newcomers are always admitted, the table stays bounded, and the
        // heavy depositor's accounting is never the one dropped.
        for newcomer in 0..64u32 {
            let key = 10_000_000 + newcomer;
            assert!(table.slot(key, now + 1).admits(PEER_LIMITS, 1));
            table.record(&key, Some((week, 1)));
            assert!(table.entries.len() <= MAX_TRACKED_DEPOSITORS);
        }
        assert_eq!(table.entries[&heavy].rows.len(), 16);

        // The same holds for the service: with both tables saturated by
        // one-row depositors, a new peer from a new network is still served.
        let directory = tempfile::tempdir().unwrap();
        let wall = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();
        for key in 0..MAX_TRACKED_DEPOSITORS {
            let peer = PeerId::random();
            service.peers.slot(peer, wall);
            service
                .peers
                .record(&peer, Some((wall + MAX_MAILBOX_TTL_MS, 1)));
            let network = NetworkKey::V6([0x20, 0x01, 0x0d, 0xb8, (key >> 8) as u8, key as u8]);
            service.networks.slot(network, wall);
            service
                .networks
                .record(&network, Some((wall + MAX_MAILBOX_TTL_MS, 1)));
        }
        assert_eq!(
            service.handle_from(
                PeerId::random(),
                ip("192.0.2.44"),
                MailboxRequest::Put(tagged_store_object(wall, 9, b"newcomer")),
                wall
            ),
            MailboxResponse::Stored
        );
        assert!(service.peers.entries.len() <= MAX_TRACKED_DEPOSITORS);
        assert!(service.networks.entries.len() <= MAX_TRACKED_DEPOSITORS);

        // Once those rows have expired, the periodic sweep forgets every idle
        // entry, so accounting memory tracks live rows, not history.
        let after = wall + MAX_MAILBOX_TTL_MS + QUOTA_SWEEP_MS + 1;
        assert_eq!(
            service.handle_from(
                PeerId::random(),
                ip("192.0.2.45"),
                MailboxRequest::Put(vec![0]),
                after
            ),
            MailboxResponse::Rejected(MailboxReject::Malformed)
        );
        assert_eq!(service.peers.entries.len(), 1);
        assert_eq!(service.networks.entries.len(), 1);
    }

    #[test]
    fn bounded_pages_resume_with_stable_digest_token() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();
        let mut expected = Vec::new();
        for value in 0..17u8 {
            let object = valid_store_object(now, &[value]);
            assert_eq!(
                service.handle(MailboxRequest::Put(object.clone()), now),
                MailboxResponse::Stored
            );
            expected.push(object);
        }

        let (cursor, mut received) = match service.handle(
            MailboxRequest::Get {
                store_tag: [0x77; 16],
                after: None,
                limit: MAX_PAGE_OBJECTS,
            },
            now,
        ) {
            MailboxResponse::Objects {
                next_cursor: Some(cursor),
                objects,
            } => (cursor, objects),
            other => panic!("unexpected first page: {other:?}"),
        };
        match service.handle(
            MailboxRequest::Get {
                store_tag: [0x77; 16],
                after: Some(cursor),
                limit: MAX_PAGE_OBJECTS,
            },
            now,
        ) {
            MailboxResponse::Objects {
                next_cursor: None,
                mut objects,
            } => received.append(&mut objects),
            other => panic!("unexpected second page: {other:?}"),
        }

        expected.sort();
        received.sort();
        assert_eq!(received, expected);
    }

    fn failing_save(_: &StoreMailbox, _: &Path) -> Result<(), String> {
        Err("injected save failure".into())
    }

    fn get_all(service: &mut MailboxService, tag: u8, now: u64) -> Vec<Vec<u8>> {
        match service.handle(
            MailboxRequest::Get {
                store_tag: [tag; 16],
                after: None,
                limit: MAX_PAGE_OBJECTS,
            },
            now,
        ) {
            MailboxResponse::Objects { objects, .. } => objects,
            other => panic!("unexpected GET response: {other:?}"),
        }
    }

    fn put_from(
        service: &mut MailboxService,
        peer: PeerId,
        object: Vec<u8>,
        now: u64,
    ) -> MailboxResponse {
        service.handle_from(peer, ip("198.51.100.7"), MailboxRequest::Put(object), now)
    }

    /// Regression test for the rollback contract: a PUT whose snapshot cannot
    /// be written is not acknowledged, leaves no trace in memory, on disk or in
    /// the depositor's quota, and does not wedge the service.
    #[test]
    fn failed_snapshot_write_is_rolled_back_and_not_acknowledged() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();
        let depositor = PeerId::random();
        let first = tagged_store_object(now, 1, b"committed");
        let second = tagged_store_object(now, 1, b"never committed");

        assert_eq!(
            put_from(&mut service, depositor, first.clone(), now),
            MailboxResponse::Stored
        );
        assert_eq!(service.peers.entries[&depositor].rows.len(), 1);

        service.save = failing_save;
        assert_eq!(
            put_from(&mut service, depositor, second.clone(), now),
            MailboxResponse::Rejected(MailboxReject::Persistence)
        );
        assert!(service.is_available(), "a rolled-back write is not a latch");
        assert_eq!(service.persistence_failures(), 1);
        assert_eq!(get_all(&mut service, 1, now), vec![first.clone()]);
        // A refused PUT is not an outstanding row for the depositor.
        assert_eq!(service.peers.entries[&depositor].rows.len(), 1);

        // Nothing leaked to disk either: a restart sees only the first row.
        drop(service);
        let mut restarted = MailboxService::open(directory.path()).unwrap();
        assert_eq!(get_all(&mut restarted, 1, now), vec![first.clone()]);

        // Once writes work again the same PUT is accepted.
        assert_eq!(
            put_from(&mut restarted, depositor, second.clone(), now),
            MailboxResponse::Stored
        );
        let mut both = get_all(&mut restarted, 1, now);
        both.sort();
        let mut expected = vec![first, second];
        expected.sort();
        assert_eq!(both, expected);
    }

    /// Regression: when the write failed and the reload failed too, the
    /// service stayed unavailable until restart. It must retry (rate-limited),
    /// come back with only committed rows, and keep serving.
    #[test]
    fn unavailable_service_recovers_when_the_snapshot_can_be_reloaded() {
        static LOAD_CALLS: AtomicUsize = AtomicUsize::new(0);
        fn counting_failure(_: &Path, _: usize) -> Result<StoreMailbox, String> {
            LOAD_CALLS.fetch_add(1, Ordering::SeqCst);
            Err("injected load failure".into())
        }

        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();
        let committed = tagged_store_object(now, 2, b"committed");
        assert_eq!(
            service.handle(MailboxRequest::Put(committed.clone()), now),
            MailboxResponse::Stored
        );

        // Disk full and fd exhaustion at once: write fails, reload fails.
        service.save = failing_save;
        service.load = counting_failure;
        let doomed = tagged_store_object(now, 2, b"uncommitted");
        assert_eq!(
            service.handle(MailboxRequest::Put(doomed), now),
            MailboxResponse::Rejected(MailboxReject::Persistence)
        );
        assert!(!service.is_available());
        assert_eq!(LOAD_CALLS.load(Ordering::SeqCst), 1);

        // Everything is refused while unavailable, without hammering the disk:
        // no reload before the backoff has elapsed.
        let get = || MailboxRequest::Get {
            store_tag: [2; 16],
            after: None,
            limit: MAX_PAGE_OBJECTS,
        };
        let refused = MailboxResponse::Rejected(MailboxReject::Persistence);
        assert_eq!(service.handle(get(), now + 1), refused);
        assert_eq!(
            service.handle(MailboxRequest::Put(committed.clone()), now + 2),
            refused
        );
        assert_eq!(
            service.handle(get(), now + RECOVERY_BACKOFF_INITIAL_MS - 1),
            refused
        );
        assert_eq!(LOAD_CALLS.load(Ordering::SeqCst), 1);

        // A retry that fails doubles the wait.
        let first_retry = now + RECOVERY_BACKOFF_INITIAL_MS;
        assert_eq!(service.handle(get(), first_retry), refused);
        assert_eq!(LOAD_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(
            service.recover_at_ms,
            first_retry + 2 * RECOVERY_BACKOFF_INITIAL_MS
        );
        assert_eq!(service.handle(get(), first_retry + 1), refused);
        assert_eq!(LOAD_CALLS.load(Ordering::SeqCst), 2);

        // The pressure clears: the next retry reloads the snapshot and the
        // service is back, holding exactly what was committed.
        service.load = StoreMailbox::load_disk;
        let healed = service.recover_at_ms;
        match service.handle(get(), healed) {
            MailboxResponse::Objects { objects, .. } => assert_eq!(objects, vec![committed]),
            other => panic!("service did not recover: {other:?}"),
        }
        assert!(service.is_available());
        assert_eq!(service.recoveries(), 1);

        // A write that still fails now rolls back instead of latching again.
        let again = tagged_store_object(now, 2, b"again");
        assert_eq!(
            service.handle(MailboxRequest::Put(again), healed),
            MailboxResponse::Rejected(MailboxReject::Persistence)
        );
        assert!(service.is_available());
        assert_eq!(get_all(&mut service, 2, healed).len(), 1);
    }

    /// Regression: `StoreMailbox::load_disk` returns an *empty* mailbox when
    /// the snapshot cannot even be stat'ed. After a failed write that reload
    /// replaced the rows in memory with nothing, and the next save made the
    /// loss permanent. A snapshot that existed must come back, not an empty store.
    #[test]
    fn vanished_snapshot_is_never_mistaken_for_an_empty_mailbox() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();
        let kept = tagged_store_object(now, 3, b"must survive");
        assert_eq!(
            service.handle(MailboxRequest::Put(kept.clone()), now),
            MailboxResponse::Stored
        );
        let snapshot = directory.path().join(MAILBOX_DB_FILENAME);
        let parked = directory.path().join("parked");
        std::fs::rename(&snapshot, &parked).unwrap();

        service.save = failing_save;
        assert_eq!(
            service.handle(
                MailboxRequest::Put(tagged_store_object(now, 3, b"doomed")),
                now
            ),
            MailboxResponse::Rejected(MailboxReject::Persistence)
        );
        assert!(
            !service.is_available(),
            "fail closed, do not serve an empty store"
        );

        // The file comes back; so does the service, with the committed row.
        std::fs::rename(&parked, &snapshot).unwrap();
        service.save = StoreMailbox::save_disk;
        let retry = now + RECOVERY_BACKOFF_INITIAL_MS;
        assert_eq!(get_all(&mut service, 3, retry), vec![kept]);
        assert!(service.is_available());
    }

    /// Before any snapshot exists, an empty reload really is the right answer.
    #[test]
    fn first_ever_write_failure_rolls_back_to_empty_without_latching() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();
        service.save = failing_save;
        assert_eq!(
            service.handle(
                MailboxRequest::Put(tagged_store_object(now, 4, b"first")),
                now
            ),
            MailboxResponse::Rejected(MailboxReject::Persistence)
        );
        assert!(service.is_available());
        assert!(get_all(&mut service, 4, now).is_empty());
    }

    fn page(
        service: &mut MailboxService,
        after: Option<[u8; 32]>,
        limit: u16,
        now: u64,
    ) -> MailboxResponse {
        service.handle(
            MailboxRequest::Get {
                store_tag: [0x77; 16],
                after,
                limit,
            },
            now,
        )
    }

    /// Page tokens are computed once per change of a tag and must never be
    /// stale: a PUT, an expiry and a reload each have to be visible.
    #[test]
    fn cached_page_tokens_follow_every_change_to_the_tag() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();
        let objects: Vec<Vec<u8>> = (0..5u8)
            .map(|value| tagged_store_object(now, 0x77, &[value]))
            .collect();
        let sorted_tokens = |rows: &[&Vec<u8>]| {
            let mut tokens: Vec<[u8; 32]> = rows.iter().map(|row| page_token(row)).collect();
            tokens.sort_unstable();
            tokens
        };
        let tokens_of = |response: &MailboxResponse| match response {
            MailboxResponse::Objects { objects, .. } => objects
                .iter()
                .map(|object| page_token(object))
                .collect::<Vec<_>>(),
            other => panic!("unexpected response: {other:?}"),
        };
        for object in &objects[..3] {
            assert_eq!(
                service.handle(MailboxRequest::Put(object.clone()), now),
                MailboxResponse::Stored
            );
        }

        // First page of two, then the cache holds the tag.
        let first = page(&mut service, None, 2, now);
        assert!(service.token_cache.contains_key(&[0x77; 16]));
        let expected_three = sorted_tokens(&objects[..3].iter().collect::<Vec<_>>());
        assert_eq!(tokens_of(&first), expected_three[..2]);
        let cursor = match first {
            MailboxResponse::Objects { next_cursor, .. } => next_cursor.unwrap(),
            _ => unreachable!(),
        };

        // A PUT to another tag leaves this tag's tokens alone; a PUT to this
        // tag drops them, and the next page already includes the new row.
        let other_tag = tagged_store_object(now, 0x78, b"elsewhere");
        service.handle(MailboxRequest::Put(other_tag), now);
        assert!(service.token_cache.contains_key(&[0x77; 16]));
        service.handle(MailboxRequest::Put(objects[3].clone()), now);
        service.handle(MailboxRequest::Put(objects[4].clone()), now);
        assert!(!service.token_cache.contains_key(&[0x77; 16]));
        let rest = page(&mut service, Some(cursor), MAX_PAGE_OBJECTS, now);
        let expected_five = sorted_tokens(&objects.iter().collect::<Vec<_>>());
        let expected_rest: Vec<_> = expected_five.into_iter().filter(|t| *t > cursor).collect();
        assert_eq!(tokens_of(&rest), expected_rest);
        assert!(service.token_cache.contains_key(&[0x77; 16]));

        // An unchanged tag answers from the cache: repeated polls agree.
        assert_eq!(
            page(&mut service, None, MAX_PAGE_OBJECTS, now),
            page(&mut service, None, MAX_PAGE_OBJECTS, now)
        );

        // Expiry drops the rows and the cached tokens with them.
        let after_expiry = now + 3_600_001;
        assert_eq!(
            page(&mut service, None, MAX_PAGE_OBJECTS, after_expiry),
            MailboxResponse::Objects {
                next_cursor: None,
                objects: Vec::new(),
            }
        );
        assert!(service.token_cache.is_empty());
    }

    /// Regression: GETs were never metered, so one caller could keep the
    /// service busy (and the global mutex held) with a tight GET loop.
    #[test]
    fn get_floods_are_rate_limited_per_peer_and_per_network() {
        let directory = tempfile::tempdir().unwrap();
        let now = unix_time_ms();
        let mut service = MailboxService::open(directory.path()).unwrap();
        let get = || MailboxRequest::Get {
            store_tag: [9; 16],
            after: None,
            limit: 1,
        };
        let served =
            |response: MailboxResponse| matches!(response, MailboxResponse::Objects { .. });
        let refused = MailboxResponse::Rejected(MailboxReject::StoreFull);
        let flooder = PeerId::random();
        let home = ip("198.51.100.7");

        for _ in 0..PEER_GET_BURST {
            assert!(served(service.handle_from(flooder, home, get(), now)));
        }
        assert_eq!(service.handle_from(flooder, home, get(), now), refused);
        // The refusal spent nothing: one refill interval buys exactly one GET.
        let later = now + PEER_GET_REFILL_MS;
        assert!(served(service.handle_from(flooder, home, get(), later)));
        assert_eq!(service.handle_from(flooder, home, get(), later), refused);

        // Fresh PeerIds (each with a full personal bucket) behind the same
        // network share its larger bucket, so they run dry too.
        let mut served_from_network = 0usize;
        while served(service.handle_from(PeerId::random(), home, get(), later)) {
            served_from_network += 1;
            assert!(
                served_from_network <= 2 * NETWORK_GET_BURST as usize,
                "network bucket never ran dry"
            );
        }
        assert!(served_from_network > 0);
        // Another network is unaffected, and PUT quotas are untouched.
        assert!(served(service.handle_from(
            PeerId::random(),
            ip("203.0.113.9"),
            get(),
            later
        )));
        assert_eq!(
            service.handle_from(
                PeerId::random(),
                ip("203.0.113.9"),
                MailboxRequest::Put(tagged_store_object(now, 9, b"deposit")),
                later
            ),
            MailboxResponse::Stored
        );
    }

    #[test]
    fn one_peer_cannot_take_the_whole_inflight_budget() {
        let limiter = InflightLimiter::new(6, 2);
        let hog = PeerId::random();
        let first = limiter.try_acquire(hog).expect("first slot");
        let second = limiter.try_acquire(hog).expect("second slot");
        assert!(limiter.try_acquire(hog).is_none(), "per-peer cap");

        // Other peers still get in until the global cap.
        let others: Vec<_> = (0..4)
            .map(|_| {
                limiter
                    .try_acquire(PeerId::random())
                    .expect("slot for another peer")
            })
            .collect();
        assert!(
            limiter.try_acquire(PeerId::random()).is_none(),
            "global cap"
        );

        // Dropping a permit frees exactly its slot, for its own peer.
        drop(first);
        let refill = limiter.try_acquire(PeerId::random());
        assert!(refill.is_some());
        assert!(
            limiter.try_acquire(hog).is_none(),
            "global cap is full again"
        );
        drop(refill);
        drop(others);
        drop(second);
        let again = limiter.try_acquire(hog).expect("slot after release");
        drop(again);
        let state = limiter.state.lock().unwrap();
        assert_eq!(state.total, 0);
        assert!(state.per_peer.is_empty(), "no leaked per-peer entries");
    }
}
