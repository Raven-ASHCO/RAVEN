//! The Kad node building blocks of the `raven-swarm` smoke binary (moved
//! into the library for P3 so other Raven binaries can reuse them): the
//! domain-separated libp2p key, the TCP/QUIC + Noise/Yamux + Kad swarm, and
//! the validation of signed `PeerRecord`s.
//!
//! Kad runs with `StoreInserts::FilterBoth`: inbound PUTs are stored only after
//! [`validate_inbound_record`] (well-formed, signed, unexpired, keyed by its
//! signer, never our own key, never an older record over a newer one).
//! Public `PeerRecord`s leak presence (transports design F5): no production
//! path publishes them.

use std::error::Error;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libp2p::identity::Keypair;
use libp2p::kad::store::{MemoryStore, MemoryStoreConfig, RecordStore};
use libp2p::kad::{self, Mode, Quorum, Record, RecordKey};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    connection_limits, identify, noise, ping, tcp, yamux, StreamProtocol, Swarm, SwarmBuilder,
};
use raven_core::discovery::PeerRecord;
use raven_core::identity::Identity;
use raven_core::CAP_INTERNET;

use crate::ip_limits::{IpLimitConfig, IpLimits};

pub const RAVEN_KAD: StreamProtocol = StreamProtocol::new("/raven/kad/1.0.0");
/// Longest PeerRecord validity accepted from the network (serve signs 1 h).
pub const MAX_PEER_RECORD_TTL_MS: u64 = 24 * 60 * 60 * 1000;
/// Validity of the PeerRecord `serve` signs for itself.
pub const SERVE_RECORD_TTL_MS: u64 = 3_600_000;
/// How often `serve` re-signs and re-publishes it (half the validity).
pub const SERVE_RECORD_REFRESH: Duration = Duration::from_millis(SERVE_RECORD_TTL_MS / 2);
/// Longest dial string accepted in a foreign PeerRecord. The codec allows
/// 64 KiB; real multiaddrs, including circuit addresses, are far shorter.
pub const MAX_PEER_DIAL_BYTES: usize = 512;
/// Largest encoded foreign PeerRecord: dial plus the fixed 110 bytes
/// (2 length + 32 key + 4 caps + 8 expiry + 64 signature). Also the store's
/// per-value cap, so a full store pins under 1 MiB instead of 64 MiB.
pub const MAX_PEER_RECORD_BYTES: usize = 110 + MAX_PEER_DIAL_BYTES;
const MAX_ESTABLISHED: u32 = 64;
const MAX_PENDING_INCOMING: u32 = 16;
const MAX_ESTABLISHED_PER_PEER: u32 = 2;

/// The Kad node behaviour of the `raven-swarm` smoke binary.
#[derive(NetworkBehaviour)]
pub struct RavenBehaviour {
    limits: connection_limits::Behaviour,
    ip_limits: IpLimits,
    pub kad: kad::Behaviour<MemoryStore>,
    pub identify: identify::Behaviour,
    pub ping: ping::Behaviour,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The libp2p key of a Raven profile. Separate namespaces: it is derived from
/// a domain-separated hash of the Raven seed
/// ([`raven_core::p2p_route::libp2p_ed25519_seed`]) so the PeerId is not the
/// Raven address, but is stable per data dir.
pub fn libp2p_keypair_from_raven(id: &Identity) -> Keypair {
    let mut seed = *raven_core::p2p_route::libp2p_ed25519_seed(id);
    // `ed25519_from_bytes` zeroizes its input.
    Keypair::ed25519_from_bytes(&mut seed).expect("ed25519 key")
}

pub fn build_swarm(id: &Identity) -> Result<libp2p::Swarm<RavenBehaviour>, Box<dyn Error>> {
    let kp = libp2p_keypair_from_raven(id);
    let peer_id = kp.public().to_peer_id();
    let swarm = SwarmBuilder::with_existing_identity(kp)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            // Records are small and signed; cap the value size so a flood of
            // validly signed junk cannot pin memory (see MAX_PEER_RECORD_BYTES).
            let store = MemoryStore::with_config(
                peer_id,
                MemoryStoreConfig {
                    // The store rejects values *at or above* this size.
                    max_value_bytes: MAX_PEER_RECORD_BYTES + 1,
                    ..Default::default()
                },
            );
            let mut kad_cfg = kad::Config::new(RAVEN_KAD);
            kad_cfg.set_query_timeout(Duration::from_secs(20));
            // Never let a remote PUT reach the store unvalidated (default is
            // Unfiltered: any peer could overwrite any key, including ours).
            kad_cfg.set_record_filtering(kad::StoreInserts::FilterBoth);
            let mut kad = kad::Behaviour::with_config(peer_id, store, kad_cfg);
            kad.set_mode(Some(Mode::Server));
            let identify = identify::Behaviour::new(identify::Config::new(
                "/raven/identify/1.0.0".into(),
                key.public(),
            ));
            let ping = ping::Behaviour::default();
            let limits = connection_limits::Behaviour::new(
                connection_limits::ConnectionLimits::default()
                    .with_max_established(Some(MAX_ESTABLISHED))
                    .with_max_pending_incoming(Some(MAX_PENDING_INCOMING))
                    .with_max_established_per_peer(Some(MAX_ESTABLISHED_PER_PEER)),
            );
            // One source address cannot hold the whole pending/established budget.
            let ip_limits = IpLimits::new(IpLimitConfig::default());
            RavenBehaviour {
                limits,
                ip_limits,
                kad,
                identify,
                ping,
            }
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    Ok(swarm)
}

pub fn dht_key_for(raven_pub: &[u8; 32]) -> [u8; 32] {
    // Same derivation as PeerRecord::dht_key.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"rvn1/peer-key");
    hasher.update(raven_pub);
    hasher.finalize().into()
}

/// Validate a record another peer asked us to store. Returns the verified
/// PeerRecord; the caller stores it only on `Ok`.
pub fn validate_inbound_record(
    store: &MemoryStore,
    own_key: &RecordKey,
    record: &Record,
    now_ms: u64,
) -> Result<PeerRecord, String> {
    if &record.key == own_key {
        // We are the only authority for our own record.
        return Err("refusing remote write to own peer record".into());
    }
    // Bounds the dial string (and the verify work) before anything is decoded.
    if record.value.len() > MAX_PEER_RECORD_BYTES {
        return Err("peer record too large".into());
    }
    let rec = PeerRecord::decode(&record.value)?;
    rec.verify(now_ms)?;
    if rec.expires_at_ms > now_ms.saturating_add(MAX_PEER_RECORD_TTL_MS) {
        return Err("peer record validity exceeds maximum".into());
    }
    if record.key != RecordKey::new(&rec.dht_key()) {
        return Err("record key is not the signer's dht key".into());
    }
    if let Some(existing) = store.get(&record.key) {
        if let Ok(old) = PeerRecord::decode(&existing.value) {
            // No sequence number in PeerRecord: expiry is the only freshness
            // signal, so never replace a valid record with an older one.
            if old.verify(now_ms).is_ok() && old.expires_at_ms >= rec.expires_at_ms {
                return Err("stale peer record (not newer than stored)".into());
            }
        }
    }
    Ok(rec)
}

/// Handle inbound Kad PUTs under `StoreInserts::FilterBoth`.
pub fn on_inbound_put(
    swarm: &mut libp2p::Swarm<RavenBehaviour>,
    own_key: &RecordKey,
    record: Record,
) {
    let now = now_ms();
    let store = swarm.behaviour_mut().kad.store_mut();
    match validate_inbound_record(store, own_key, &record, now) {
        Ok(rec) => {
            let remaining = Duration::from_millis(rec.expires_at_ms.saturating_sub(now));
            let signed_expiry = std::time::Instant::now() + remaining;
            let expires = Some(
                record
                    .expires
                    .map_or(signed_expiry, |e| e.min(signed_expiry)),
            );
            match store.put(Record { expires, ..record }) {
                Ok(()) => println!("kad_inbound_put_stored"),
                Err(e) => println!("kad_inbound_put_rejected=store:{e}"),
            }
        }
        Err(e) => println!("kad_inbound_put_rejected={e}"),
    }
}

/// Sign our own PeerRecord for `dial` (valid for [`SERVE_RECORD_TTL_MS`] from
/// `now_ms`), store it locally and push it to the network. The local copy
/// expires with its signature, so a record that is no longer being refreshed
/// is purged here instead of being served (and re-replicated) as expired.
/// Calling this again replaces the stored record with a fresher one.
pub fn publish_own_record(
    swarm: &mut Swarm<RavenBehaviour>,
    raven_id: &Identity,
    dial: &str,
    now_ms: u64,
) -> Result<PeerRecord, Box<dyn Error>> {
    let local_peer = *swarm.local_peer_id();
    let rec = PeerRecord {
        dial: dial.to_owned(),
        ed25519_pub: [0u8; 32],
        // This binary speaks Raven's Internet request/response protocol. It is
        // not a Circuit Relay server.
        caps: CAP_INTERNET,
        expires_at_ms: now_ms + SERVE_RECORD_TTL_MS,
        signature: [0u8; 64],
    }
    .sign(raven_id)?;
    let record = Record {
        key: RecordKey::new(&rec.dht_key()),
        value: rec.encode()?,
        publisher: Some(local_peer),
        expires: Some(std::time::Instant::now() + Duration::from_millis(SERVE_RECORD_TTL_MS)),
    };
    // Local store first (solo-node Quorum put would fail).
    swarm
        .behaviour_mut()
        .kad
        .store_mut()
        .put(record.clone())
        .map_err(|e| format!("local kad put: {e}"))?;
    // Also start a network put (replication); it may fail until a peer dials.
    let _ = swarm.behaviour_mut().kad.put_record(record, Quorum::One);
    Ok(rec)
}

/// Check a record returned by a GET before trusting its dial string.
pub fn verify_found_record(
    record: &Record,
    dht_key: &[u8; 32],
    raven_pub: &[u8; 32],
    now_ms: u64,
) -> Result<PeerRecord, String> {
    if record.key != RecordKey::new(dht_key) {
        return Err("record key mismatch".into());
    }
    let rec = PeerRecord::decode(&record.value)?;
    rec.verify(now_ms)?;
    if rec.ed25519_pub != *raven_pub {
        return Err("peer record pub mismatch".into());
    }
    Ok(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::PeerId;

    fn signed(id: &Identity, dial: &str, expires_at_ms: u64) -> PeerRecord {
        PeerRecord {
            dial: dial.into(),
            ed25519_pub: [0u8; 32],
            caps: CAP_INTERNET,
            expires_at_ms,
            signature: [0u8; 64],
        }
        .sign(id)
        .unwrap()
    }

    fn kad_record(rec: &PeerRecord) -> Record {
        Record {
            key: RecordKey::new(&rec.dht_key()),
            value: rec.encode().unwrap(),
            publisher: None,
            expires: None,
        }
    }

    #[test]
    fn inbound_put_filter_accepts_only_valid_newer_foreign_records() {
        let now = 1_000_000;
        let own = Identity::from_seed(&[1; 32]);
        let other = Identity::from_seed(&[2; 32]);
        let own_key = RecordKey::new(&dht_key_for(&own.public_key_bytes()));
        let mut store = MemoryStore::new(PeerId::random());

        let fresh = signed(&other, "/ip4/10.0.0.2/tcp/1", now + 60_000);
        let rec = validate_inbound_record(&store, &own_key, &kad_record(&fresh), now).unwrap();
        assert_eq!(rec, fresh);
        store.put(kad_record(&fresh)).unwrap();

        // Replay of an older (still valid) record cannot roll the address back.
        let older = signed(&other, "/ip4/6.6.6.6/tcp/1", now + 30_000);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&older), now).is_err());
        let newer = signed(&other, "/ip4/10.0.0.3/tcp/1", now + 90_000);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&newer), now).is_ok());

        // Our own key is never writable remotely, even with a valid signature.
        let own_rec = signed(&own, "/ip4/6.6.6.6/tcp/1", now + 90_000);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&own_rec), now).is_err());

        // Garbage, forged, mis-keyed, expired and over-long records are refused.
        let mut garbage = kad_record(&fresh);
        garbage.value = b"not a peer record".to_vec();
        assert!(validate_inbound_record(&store, &own_key, &garbage, now).is_err());
        let mut forged = signed(&other, "/ip4/10.0.0.9/tcp/1", now + 120_000);
        forged.dial = "/ip4/6.6.6.6/tcp/1".into();
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&forged), now).is_err());
        let third = Identity::from_seed(&[3; 32]);
        let mut miskeyed = kad_record(&signed(&third, "/ip4/10.0.0.4/tcp/1", now + 60_000));
        miskeyed.key = RecordKey::new(&fresh.dht_key());
        assert!(validate_inbound_record(&store, &own_key, &miskeyed, now).is_err());
        let expired = signed(&third, "/ip4/10.0.0.4/tcp/1", now - 1);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&expired), now).is_err());
        let forever = signed(&third, "/ip4/10.0.0.4/tcp/1", u64::MAX);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&forever), now).is_err());
    }

    /// Regression: with StoreInserts::Unfiltered any peer could overwrite the
    /// serving node's own signed PeerRecord.
    #[tokio::test]
    async fn remote_put_cannot_replace_own_record() {
        let own = Identity::from_seed(&[4; 32]);
        let mut swarm = build_swarm(&own).unwrap();
        let own_key = RecordKey::new(&dht_key_for(&own.public_key_bytes()));
        let mine = signed(&own, "/ip4/127.0.0.1/tcp/4001", now_ms() + 3_600_000);
        swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .put(kad_record(&mine))
            .unwrap();

        let mut hostile = kad_record(&signed(&own, "/ip4/6.6.6.6/tcp/1", now_ms() + 7_200_000));
        hostile.key = own_key.clone();
        on_inbound_put(&mut swarm, &own_key, hostile);
        let mut garbage = kad_record(&mine);
        garbage.value = vec![0xff; 8];
        on_inbound_put(&mut swarm, &own_key, garbage);

        let stored = swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .get(&own_key)
            .unwrap()
            .into_owned();
        assert_eq!(PeerRecord::decode(&stored.value).unwrap(), mine);

        let other = Identity::from_seed(&[5; 32]);
        let theirs = signed(&other, "/ip4/10.0.0.5/tcp/1", now_ms() + 60_000);
        on_inbound_put(&mut swarm, &own_key, kad_record(&theirs));
        let key = RecordKey::new(&theirs.dht_key());
        let stored = swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .get(&key)
            .unwrap()
            .into_owned();
        assert!(
            stored.expires.is_some(),
            "stored record expires with its signature"
        );
    }

    /// Regression: the first undecodable/forged FoundRecord aborted the dial.
    #[test]
    fn found_record_check_skips_instead_of_failing() {
        let now = 1_000_000;
        let target = Identity::from_seed(&[6; 32]);
        let pub_key = target.public_key_bytes();
        let key = dht_key_for(&pub_key);
        let good = signed(&target, "/ip4/10.0.0.6/tcp/1", now + 60_000);
        assert_eq!(
            verify_found_record(&kad_record(&good), &key, &pub_key, now).unwrap(),
            good
        );
        let mut poisoned = kad_record(&good);
        poisoned.value = b"poison".to_vec();
        assert!(verify_found_record(&poisoned, &key, &pub_key, now).is_err());
        let impostor = Identity::from_seed(&[7; 32]);
        let mut wrong = kad_record(&signed(&impostor, "/ip4/6.6.6.6/tcp/1", now + 60_000));
        wrong.key = RecordKey::new(&key);
        assert!(verify_found_record(&wrong, &key, &pub_key, now).is_err());
    }

    /// Regression: a validly signed record with a 64 KiB dial string passed
    /// validation, so ~1024 throwaway identities could pin ~64 MiB in the store.
    #[test]
    fn inbound_records_are_size_bounded() {
        let now = 1_000_000;
        let own = Identity::from_seed(&[8; 32]);
        let other = Identity::from_seed(&[9; 32]);
        let own_key = RecordKey::new(&dht_key_for(&own.public_key_bytes()));
        let store = MemoryStore::new(PeerId::random());

        let longest = signed(&other, &"x".repeat(MAX_PEER_DIAL_BYTES), now + 60_000);
        assert_eq!(kad_record(&longest).value.len(), MAX_PEER_RECORD_BYTES);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&longest), now).is_ok());

        let too_long = signed(&other, &"x".repeat(MAX_PEER_DIAL_BYTES + 1), now + 60_000);
        assert_eq!(
            validate_inbound_record(&store, &own_key, &kad_record(&too_long), now),
            Err("peer record too large".to_owned())
        );
        let huge = signed(&other, &"x".repeat(60_000), now + 60_000);
        assert!(validate_inbound_record(&store, &own_key, &kad_record(&huge), now).is_err());
        // Real dial strings, including circuit addresses, are far below the cap.
        let circuit = "/ip4/203.0.113.7/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN/p2p-circuit/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN";
        assert!(circuit.len() < MAX_PEER_DIAL_BYTES / 2);
    }

    /// The store itself refuses oversized values, whatever path they take in.
    #[tokio::test]
    async fn store_refuses_values_above_the_record_cap() {
        let mut swarm = build_swarm(&Identity::from_seed(&[12; 32])).unwrap();
        let store = swarm.behaviour_mut().kad.store_mut();
        let record = |len: usize, key: &[u8]| Record {
            key: RecordKey::new(&key),
            value: vec![0; len],
            publisher: None,
            expires: None,
        };
        assert!(store.put(record(MAX_PEER_RECORD_BYTES, b"fits")).is_ok());
        assert!(store
            .put(record(MAX_PEER_RECORD_BYTES + 1, b"too big"))
            .is_err());
    }

    /// Regression: `serve` signed its record once with a 1 h validity and never
    /// refreshed it, so after an hour every GET returned an expired record.
    #[tokio::test]
    async fn own_record_is_refreshed_before_it_expires() {
        let id = Identity::from_seed(&[10; 32]);
        let mut swarm = build_swarm(&id).unwrap();
        let dial = "/ip4/127.0.0.1/tcp/4001";
        let t0 = now_ms();
        let first = publish_own_record(&mut swarm, &id, dial, t0).unwrap();

        // The refresh timer fires at half the validity at the latest.
        assert!(SERVE_RECORD_REFRESH * 2 <= Duration::from_millis(SERVE_RECORD_TTL_MS));
        let refresh_ms = SERVE_RECORD_REFRESH.as_millis() as u64;
        let second = publish_own_record(&mut swarm, &id, dial, t0 + refresh_ms).unwrap();

        // Once the first signature has run out, only the refreshed record is
        // servable; this is exactly what dialers saw before the fix.
        let late = t0 + SERVE_RECORD_TTL_MS + 1;
        assert_eq!(first.verify(late), Err("PEER_EXPIRED".to_owned()));
        assert!(second.verify(late).is_ok());

        // A remote node holding the first copy accepts the refreshed one.
        let remote_own = RecordKey::new(&dht_key_for(
            &Identity::from_seed(&[11; 32]).public_key_bytes(),
        ));
        let mut remote = MemoryStore::new(PeerId::random());
        remote.put(kad_record(&first)).unwrap();
        assert!(validate_inbound_record(
            &remote,
            &remote_own,
            &kad_record(&second),
            t0 + refresh_ms
        )
        .is_ok());

        // Locally the refreshed record replaced the old one, and it expires
        // with its signature instead of being served forever.
        let key = RecordKey::new(&second.dht_key());
        let stored = swarm
            .behaviour_mut()
            .kad
            .store_mut()
            .get(&key)
            .unwrap()
            .into_owned();
        assert_eq!(PeerRecord::decode(&stored.value).unwrap(), second);
        assert!(stored.expires.is_some());
    }

    /// raven-core computes PeerIds and parses `via=` multiaddrs without
    /// libp2p (for `raven` cards); both must agree with libp2p exactly.
    #[test]
    fn core_peer_ids_and_multiaddr_text_match_libp2p() {
        for seed in [1u8, 7, 0xfe] {
            let id = Identity::from_seed(&[seed; 32]);
            let libp2p_peer = libp2p_keypair_from_raven(&id).public().to_peer_id();
            assert_eq!(
                raven_core::p2p_route::local_peer_id(&id),
                libp2p_peer.to_string()
            );
            let parsed: PeerId = raven_core::p2p_route::local_peer_id(&id).parse().unwrap();
            assert_eq!(parsed, libp2p_peer);
            for text in [
                format!("/ip4/203.0.113.7/tcp/7423/p2p/{libp2p_peer}"),
                format!("/ip6/2001:db8::1/udp/7423/quic-v1/p2p/{libp2p_peer}"),
                format!("/dns4/relay.example.com/tcp/7423/p2p/{libp2p_peer}"),
            ] {
                let via = raven_core::p2p_route::parse_via(&text).unwrap();
                let real: libp2p::Multiaddr = via.text.parse().unwrap();
                assert_eq!(real.to_string(), via.text);
                let circuit = raven_core::p2p_route::circuit_addr(&via, &libp2p_peer.to_string());
                let real: libp2p::Multiaddr = circuit.parse().unwrap();
                assert_eq!(real.to_string(), circuit);
            }
        }
    }
}
