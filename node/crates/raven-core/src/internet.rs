//! InternetTransport codec — RIH1 hello + length-prefixed opaque frames.
//!
//! Live sockets live in `raven-node` `internet_direct` (hello, then framed
//! envelopes). This module is pack/unpack only. Localhost indexed delivery is
//! a software substitute; it is **not** public-Internet / WAN Proven.
//!
//! ADR-0002 target: rust-libp2p QUIC/TCP + DHT. Signed discovery records live
//! in `crate::discovery`. Live Kademlia / DCUtR / multi-NAT CGNAT: see
//! `discovery::NAT_STATUS` (BLOCKED_HARDWARE).

use crate::identity::Identity;
use crate::transport::NodeCapability;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Protocol id for capability negotiation (ASCII, fixed).
pub const INTERNET_PROTO_ID: &[u8] = b"raven/internet/v1";

/// Max framed payload (matches practical bridge ceilings; below DoS extremes).
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Hello magic.
pub const HELLO_MAGIC: &[u8; 4] = b"RIH1";

/// Capability bit flags (generic — never contact-identifying).
pub const CAP_BLE: u32 = 1 << 0;
pub const CAP_INTERNET: u32 = 1 << 1;
pub const CAP_RELAY: u32 = 1 << 2;
pub const CAP_STORE: u32 = 1 << 3;
pub const CAP_BRIDGE: u32 = 1 << 4;

pub fn caps_to_bits(caps: &[NodeCapability]) -> u32 {
    let mut b = 0u32;
    for c in caps {
        b |= match c {
            NodeCapability::Ble => CAP_BLE,
            NodeCapability::Internet => CAP_INTERNET,
            NodeCapability::Relay => CAP_RELAY,
            NodeCapability::Store => CAP_STORE,
            NodeCapability::Bridge => CAP_BRIDGE,
        };
    }
    b
}

pub fn bits_to_caps(bits: u32) -> Vec<NodeCapability> {
    let mut out = Vec::new();
    if bits & CAP_BLE != 0 {
        out.push(NodeCapability::Ble);
    }
    if bits & CAP_INTERNET != 0 {
        out.push(NodeCapability::Internet);
    }
    if bits & CAP_RELAY != 0 {
        out.push(NodeCapability::Relay);
    }
    if bits & CAP_STORE != 0 {
        out.push(NodeCapability::Store);
    }
    if bits & CAP_BRIDGE != 0 {
        out.push(NodeCapability::Bridge);
    }
    out
}

/// Build hello signing bytes: magic || proto || caps_be || nonce12 || pub32
pub fn hello_signing_bytes(caps: u32, nonce12: &[u8; 12], pub_key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + INTERNET_PROTO_ID.len() + 4 + 12 + 32);
    out.extend_from_slice(HELLO_MAGIC);
    out.extend_from_slice(INTERNET_PROTO_ID);
    out.extend_from_slice(&caps.to_be_bytes());
    out.extend_from_slice(nonce12);
    out.extend_from_slice(pub_key);
    out
}

/// Packed hello wire length: magic(4) || caps_u32_be || nonce(12) || pub(32) || sig(64).
pub const HELLO_WIRE_LEN: usize = 4 + 4 + 12 + 32 + 64;

/// Packed hello: magic(4) || caps_u32_be || nonce(12) || pub(32) || sig(64)
pub fn pack_hello(id: &Identity, caps: u32, nonce12: [u8; 12]) -> Vec<u8> {
    let pk = id.public_key_bytes();
    let sb = hello_signing_bytes(caps, &nonce12, &pk);
    let sig = id.sign(&sb);
    let mut out = Vec::with_capacity(4 + 4 + 12 + 32 + 64);
    out.extend_from_slice(HELLO_MAGIC);
    out.extend_from_slice(&caps.to_be_bytes());
    out.extend_from_slice(&nonce12);
    out.extend_from_slice(&pk);
    out.extend_from_slice(&sig);
    out
}

pub fn unpack_verify_hello(raw: &[u8]) -> Result<(u32, [u8; 32]), String> {
    if raw.len() != HELLO_WIRE_LEN {
        return Err("hello length".into());
    }
    if &raw[0..4] != HELLO_MAGIC {
        return Err("hello magic".into());
    }
    let caps = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&raw[8..20]);
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&raw[20..52]);
    let mut sig_b = [0u8; 64];
    sig_b.copy_from_slice(&raw[52..116]);
    let sb = hello_signing_bytes(caps, &nonce, &pk);
    let vk = VerifyingKey::from_bytes(&pk).map_err(|_| "bad pub")?;
    let sig = Signature::from_bytes(&sig_b);
    vk.verify(&sb, &sig).map_err(|_| "hello sig")?;
    Ok((caps, pk))
}

/// Frame: u32 BE length || payload (envelope or control).
pub fn frame(payload: &[u8]) -> Result<Vec<u8>, String> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err("frame too large".into());
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn deframe_prefix(buf: &[u8]) -> Option<(Vec<u8>, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let n = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if n > MAX_FRAME_BYTES {
        return None;
    }
    if buf.len() < 4 + n {
        return None;
    }
    Some((buf[4..4 + n].to_vec(), 4 + n))
}

/// Opaque store index: SHA-256("raven/relay-tag/v1" || mailbox_tag)[:16].
/// The input is the separately derived rotating mailbox capability, never an
/// envelope routing tag or username.
pub fn opaque_store_tag(mailbox_tag: &[u8; 16]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"raven/relay-tag/v1");
    h.update(mailbox_tag);
    let d = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use rand::RngCore;

    #[test]
    fn hello_roundtrip() {
        let id = Identity::generate();
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let packed = pack_hello(&id, CAP_INTERNET | CAP_RELAY, nonce);
        assert_eq!(packed.len(), HELLO_WIRE_LEN);
        let (caps, pk) = unpack_verify_hello(&packed).unwrap();
        assert_eq!(caps, CAP_INTERNET | CAP_RELAY);
        assert_eq!(pk, id.public_key_bytes());
    }

    #[test]
    fn hello_tamper_rejected() {
        let id = Identity::generate();
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let mut packed = pack_hello(&id, CAP_BRIDGE, nonce);
        packed[10] ^= 0xff;
        assert!(unpack_verify_hello(&packed).is_err());
    }

    #[test]
    fn frame_roundtrip() {
        let payload = b"RVN1demo".to_vec();
        let f = frame(&payload).unwrap();
        let (p, n) = deframe_prefix(&f).unwrap();
        assert_eq!(p, payload);
        assert_eq!(n, f.len());
    }

    #[test]
    fn store_tag_not_username() {
        let tag = [7u8; 16];
        let a = opaque_store_tag(&tag);
        let b = opaque_store_tag(&tag);
        assert_eq!(a, b);
        assert_ne!(a, tag);
    }
}
