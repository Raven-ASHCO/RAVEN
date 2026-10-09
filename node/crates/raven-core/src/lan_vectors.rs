//! Assert `shared-vectors/rvn1/lan` fixtures against `lan_noise` / `lan_rlb1`.
//!
//! CI: `.github/workflows/raven-serverless.yml` runs `cargo test -p raven-core --lib lan_`.
//! iOS KAT: `node/scripts/ios_lan_kat.sh` (Swift `RavenSecureLanNoiseTests` / `RavenSecureLanRlb1Tests`).
//! Manual lab order: `node/scripts/ios_lan_lab_checklist.md` (design §11).
//!
//! Test fixtures only: the public seeds and the fixed-ephemeral handshake KAT
//! must not ship in a default/release build, so the module compiles under
//! `cfg(test)` or the `test-helpers` feature.
#![cfg(any(test, feature = "test-helpers"))]

use serde_json::Value;
use std::path::PathBuf;

use crate::identity::Identity;
use crate::lan_noise::{
    build_initiator_with_ephemeral, build_responder_with_ephemeral, derive_noise_static,
    encode_bind, get_remote_static, handshake_hash, handshake_read, handshake_write,
    into_transport, noise_static_public, transport_decrypt, transport_encrypt, verify_bind,
    BIND_LEN, HKDF_INFO, HKDF_SALT, NOISE_PATTERN,
};
use crate::lan_rlb1::{decode_offer, encode_offer, LanBundle, MAX_OFFER_WIRE, RLB1_HEADER_LEN};
use crate::prekey_bundle::{PrekeyBundle, MLKEM768_EK_LEN};

pub const ALICE_DEVICE_SEED: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
pub const BOB_DEVICE_SEED: &str =
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
const INITIATOR_EPHEMERAL: [u8; 32] = [0x11; 32];
const RESPONDER_EPHEMERAL: [u8; 32] = [0x22; 32];
const FIRST_APP_PLAINTEXT: &[u8] = b"rvn1/lan-vector/app-001";

fn vectors_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.pop();
    p.join("shared-vectors").join("rvn1").join("lan")
}

fn load_json(name: &str) -> Value {
    let path = vectors_root().join(name);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("missing vector {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("json")
}

fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("hex")
}

fn hex_to_arr32(s: &str) -> [u8; 32] {
    let v = hex_to_vec(s);
    let mut a = [0u8; 32];
    a.copy_from_slice(&v);
    a
}

fn identity_from_hex(seed_hex: &str) -> Identity {
    Identity::from_seed(&hex_to_arr32(seed_hex))
}

pub fn fixture_offer_bundle() -> LanBundle {
    let user = identity_from_hex(ALICE_DEVICE_SEED);
    let now = 1_700_000_000_000u64;
    let device_x = [0x71; 32];
    let cert = crate::device_cert::DeviceCertificate::issue(
        &user,
        user.public_key_bytes(),
        device_x,
        "alice-lan-device-1",
        now - 60_000,
        now + 86_400_000,
        7,
    )
    .unwrap();
    let prekey = PrekeyBundle::from_hybrid_public(
        "alice-lan-device-1",
        device_x,
        vec![0x02; MLKEM768_EK_LEN],
        1,
        now,
        now + 86_400_000,
    )
    .unwrap()
    .sign(&user)
    .unwrap();
    LanBundle { cert, prekey }
}

pub struct HandshakeKat {
    pub m1: Vec<u8>,
    pub m2: Vec<u8>,
    pub m3: Vec<u8>,
    pub initiator_static_pub: [u8; 32],
    pub responder_static_pub: [u8; 32],
    pub initiator_remote_static: [u8; 32],
    pub responder_remote_static: [u8; 32],
    pub handshake_hash: [u8; 32],
    pub initiator_bind_ct: Vec<u8>,
    pub responder_bind_ct: Vec<u8>,
    pub first_app_ct: Vec<u8>,
}

pub fn compute_handshake_kat() -> HandshakeKat {
    let initiator = identity_from_hex(ALICE_DEVICE_SEED);
    let responder = identity_from_hex(BOB_DEVICE_SEED);
    let init_priv = derive_noise_static(&initiator).expect("init static");
    let resp_priv = derive_noise_static(&responder).expect("resp static");
    let init_pub = noise_static_public(&init_priv);
    let resp_pub = noise_static_public(&resp_priv);

    let mut init_hs =
        build_initiator_with_ephemeral(&init_priv, Some(&INITIATOR_EPHEMERAL)).expect("init hs");
    let mut resp_hs =
        build_responder_with_ephemeral(&resp_priv, Some(&RESPONDER_EPHEMERAL)).expect("resp hs");

    let m1 = handshake_write(&mut init_hs, &[]).expect("m1");
    handshake_read(&mut resp_hs, &m1).expect("read m1");
    let m2 = handshake_write(&mut resp_hs, &[]).expect("m2");
    handshake_read(&mut init_hs, &m2).expect("read m2");
    let m3 = handshake_write(&mut init_hs, &[]).expect("m3");
    handshake_read(&mut resp_hs, &m3).expect("read m3");

    let hash = handshake_hash(&init_hs);
    assert_eq!(hash, handshake_hash(&resp_hs));

    let init_remote = get_remote_static(&init_hs).expect("init remote static");
    let resp_remote = get_remote_static(&resp_hs).expect("resp remote static");
    assert_eq!(init_remote, resp_pub);
    assert_eq!(resp_remote, init_pub);

    let mut init_t = into_transport(init_hs).expect("init transport");
    let mut resp_t = into_transport(resp_hs).expect("resp transport");

    let init_bind = encode_bind(&initiator, &init_pub);
    let init_bind_ct = transport_encrypt(&mut init_t, &init_bind).expect("init bind ct");
    let resp_bind = encode_bind(&responder, &resp_pub);
    let resp_bind_ct = transport_encrypt(&mut resp_t, &resp_bind).expect("resp bind ct");
    let first_app_ct = transport_encrypt(&mut init_t, FIRST_APP_PLAINTEXT).expect("first app ct");

    HandshakeKat {
        m1,
        m2,
        m3,
        initiator_static_pub: init_pub,
        responder_static_pub: resp_pub,
        initiator_remote_static: init_remote,
        responder_remote_static: resp_remote,
        handshake_hash: hash,
        initiator_bind_ct: init_bind_ct,
        responder_bind_ct: resp_bind_ct,
        first_app_ct,
    }
}

pub fn assert_noise_static_vector() {
    let v = load_json("noise_static_001.json");
    assert_eq!(v["protocol_version"].as_str().unwrap(), "rvn1");
    assert_eq!(
        v["inputs"]["hkdf_salt"].as_str().unwrap(),
        "rvn1/lan-noise/v1"
    );
    assert_eq!(v["inputs"]["hkdf_info"].as_str().unwrap(), "static-x25519");
    let seed = hex_to_arr32(v["inputs"]["device_seed_hex"].as_str().unwrap());
    let id = Identity::from_seed(&seed);
    let priv_key = derive_noise_static(&id).expect("derive");
    let pub_key = noise_static_public(&priv_key);
    assert_eq!(
        hex::encode(pub_key),
        v["expected"]["noise_static_pub_hex"].as_str().unwrap()
    );
    assert_eq!(HKDF_SALT, b"rvn1/lan-noise/v1");
    assert_eq!(HKDF_INFO, b"static-x25519");
    assert_ne!(*priv_key, seed);
}

pub fn assert_noise_bind_vector() {
    let v = load_json("noise_bind_001.json");
    let seed = hex_to_arr32(v["inputs"]["device_seed_hex"].as_str().unwrap());
    let id = Identity::from_seed(&seed);
    let static_priv = derive_noise_static(&id).expect("derive");
    let static_pub = noise_static_public(&static_priv);
    assert_eq!(
        hex::encode(static_pub),
        v["inputs"]["noise_static_pub_hex"].as_str().unwrap()
    );
    let bind = encode_bind(&id, &static_pub);
    assert_eq!(bind.len(), BIND_LEN);
    assert_eq!(
        hex::encode(bind),
        v["expected"]["bind_hex"].as_str().unwrap()
    );
    verify_bind(&bind, &static_pub, Some(&id.public_key_bytes())).expect("bind ok");
}

pub fn assert_rlb1_offer_vector() {
    let v = load_json("rlb1_offer_001.json");
    assert_eq!(
        v["canonical_json_policy"].as_str().unwrap(),
        "serde_json::to_vec field order; lowercase hex; omit null otp"
    );
    let bundle = fixture_offer_bundle();
    let wire = encode_offer(&bundle).expect("encode");
    assert_eq!(
        hex::encode(&wire),
        v["expected"]["offer_wire_hex"].as_str().unwrap()
    );
    assert!(wire.len() <= MAX_OFFER_WIRE);
    let back = decode_offer(&wire).expect("decode");
    assert_eq!(back.cert, bundle.cert);
    assert_eq!(back.prekey, bundle.prekey);

    let reject = &v["reject_cases"]["combined_cap_ge_65519"];
    let mut oversize = wire.clone();
    oversize.resize(MAX_OFFER_WIRE + 1, 0);
    assert_eq!(
        oversize.len(),
        reject["offer_wire_len"].as_u64().unwrap() as usize
    );
    assert!(oversize.len() > MAX_OFFER_WIRE);
    assert_eq!(
        decode_offer(&oversize),
        Err(reject["decode_error"].as_str().unwrap().into())
    );
    let cert_len = reject["cert_json_len"].as_u64().unwrap() as usize;
    let prekey_len = reject["prekey_json_len"].as_u64().unwrap() as usize;
    assert!(RLB1_HEADER_LEN + cert_len + prekey_len > MAX_OFFER_WIRE);
    assert_eq!(
        reject["encode_error"].as_str().unwrap(),
        "rlb1 offer exceeds transport plaintext"
    );
}

pub fn assert_noise_xx_handshake_vector() {
    let v = load_json("noise_xx_handshake_001.json");
    assert_eq!(
        v["inputs"]["noise_pattern"].as_str().unwrap(),
        NOISE_PATTERN
    );
    assert_eq!(v["inputs"]["prologue"].as_str().unwrap(), "");
    assert_eq!(
        v["inputs"]["initiator_device_seed_hex"].as_str().unwrap(),
        ALICE_DEVICE_SEED
    );
    assert_eq!(
        v["inputs"]["responder_device_seed_hex"].as_str().unwrap(),
        BOB_DEVICE_SEED
    );
    assert_eq!(
        hex::encode(INITIATOR_EPHEMERAL),
        v["inputs"]["initiator_ephemeral_priv_hex"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        hex::encode(RESPONDER_EPHEMERAL),
        v["inputs"]["responder_ephemeral_priv_hex"]
            .as_str()
            .unwrap()
    );

    let kat = compute_handshake_kat();
    let exp = &v["expected"];
    assert_eq!(hex::encode(&kat.m1), exp["m1_hex"].as_str().unwrap());
    assert_eq!(hex::encode(&kat.m2), exp["m2_hex"].as_str().unwrap());
    assert_eq!(hex::encode(&kat.m3), exp["m3_hex"].as_str().unwrap());
    assert_eq!(
        hex::encode(kat.initiator_static_pub),
        exp["initiator_static_pub_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(kat.responder_static_pub),
        exp["responder_static_pub_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(kat.initiator_remote_static),
        exp["initiator_remote_static_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(kat.responder_remote_static),
        exp["responder_remote_static_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(kat.handshake_hash),
        exp["handshake_hash_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&kat.initiator_bind_ct),
        exp["initiator_bind_transport_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&kat.responder_bind_ct),
        exp["responder_bind_transport_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(&kat.first_app_ct),
        exp["first_application_ciphertext_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(FIRST_APP_PLAINTEXT),
        exp["first_application_plaintext_hex"].as_str().unwrap()
    );

    let initiator = identity_from_hex(ALICE_DEVICE_SEED);
    let responder = identity_from_hex(BOB_DEVICE_SEED);
    let init_priv = derive_noise_static(&initiator).unwrap();
    let resp_priv = derive_noise_static(&responder).unwrap();
    let mut init_hs =
        build_initiator_with_ephemeral(&init_priv, Some(&INITIATOR_EPHEMERAL)).unwrap();
    let mut resp_hs =
        build_responder_with_ephemeral(&resp_priv, Some(&RESPONDER_EPHEMERAL)).unwrap();
    let m1 = handshake_write(&mut init_hs, &[]).unwrap();
    assert_eq!(m1, kat.m1);
    handshake_read(&mut resp_hs, &m1).unwrap();
    let m2 = handshake_write(&mut resp_hs, &[]).unwrap();
    assert_eq!(m2, kat.m2);
    handshake_read(&mut init_hs, &m2).unwrap();
    let m3 = handshake_write(&mut init_hs, &[]).unwrap();
    assert_eq!(m3, kat.m3);
    handshake_read(&mut resp_hs, &m3).unwrap();
    let mut init_t = into_transport(init_hs).unwrap();
    let mut resp_t = into_transport(resp_hs).unwrap();

    let init_bind_pt = transport_decrypt(&mut resp_t, &kat.initiator_bind_ct).unwrap();
    verify_bind(
        &init_bind_pt,
        &kat.initiator_static_pub,
        Some(&initiator.public_key_bytes()),
    )
    .unwrap();
    let resp_bind_pt = transport_decrypt(&mut init_t, &kat.responder_bind_ct).unwrap();
    verify_bind(
        &resp_bind_pt,
        &kat.responder_static_pub,
        Some(&responder.public_key_bytes()),
    )
    .unwrap();
    let app_pt = transport_decrypt(&mut resp_t, &kat.first_app_ct).unwrap();
    assert_eq!(app_pt, FIRST_APP_PLAINTEXT);
}

pub fn assert_all_lan_vectors() {
    assert_noise_static_vector();
    assert_noise_bind_vector();
    assert_rlb1_offer_vector();
    assert_noise_xx_handshake_vector();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_vectors_root_exists() {
        assert!(vectors_root().is_dir());
    }

    #[test]
    fn noise_static_001_vector() {
        assert_noise_static_vector();
    }

    #[test]
    fn noise_bind_001_vector() {
        assert_noise_bind_vector();
    }

    #[test]
    fn rlb1_offer_001_vector() {
        assert_rlb1_offer_vector();
    }

    #[test]
    fn noise_xx_handshake_001_vector() {
        assert_noise_xx_handshake_vector();
    }

    #[test]
    fn all_lan_vectors() {
        assert_all_lan_vectors();
    }

    /// Regenerate JSON fixtures: `cargo test -p raven-core lan_vector_dump -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn lan_vector_dump() {
        use std::io::Write;

        let out_dir = vectors_root();
        std::fs::create_dir_all(&out_dir).expect("mkdir lan vectors");

        let alice = identity_from_hex(ALICE_DEVICE_SEED);
        let alice_static = noise_static_public(&derive_noise_static(&alice).unwrap());
        let bind = encode_bind(&alice, &alice_static);
        let offer = fixture_offer_bundle();
        let offer_wire = encode_offer(&offer).unwrap();
        let kat = compute_handshake_kat();

        let huge_id = "x".repeat(60_000);
        let user = identity_from_hex(ALICE_DEVICE_SEED);
        let now = 1_700_000_000_000u64;
        let oversize_cert = crate::device_cert::DeviceCertificate::issue(
            &user,
            user.public_key_bytes(),
            [0x71; 32],
            &huge_id,
            now - 60_000,
            now + 86_400_000,
            7,
        )
        .unwrap();
        let oversize_prekey = PrekeyBundle::from_hybrid_public(
            &huge_id,
            [0x71; 32],
            vec![0x02; MLKEM768_EK_LEN],
            1,
            now,
            now + 86_400_000,
        )
        .unwrap()
        .sign(&user)
        .unwrap();
        let oversize_cert_json = serde_json::to_vec(&oversize_cert).unwrap();
        let oversize_prekey_json = serde_json::to_vec(&oversize_prekey.to_json()).unwrap();

        let write_json = |name: &str, value: serde_json::Value| {
            let path = out_dir.join(name);
            let mut f = std::fs::File::create(&path).expect("create json");
            writeln!(f, "{}", serde_json::to_string_pretty(&value).expect("json")).expect("write");
        };

        write_json(
            "noise_static_001.json",
            serde_json::json!({
                "name": "LAN Noise static X25519 derive",
                "description": "Device signing seed HKDF-SHA256 to Noise XX static key",
                "protocol_version": "rvn1",
                "deterministic": true,
                "inputs": {
                    "device_seed_hex": ALICE_DEVICE_SEED,
                    "hkdf_salt": "rvn1/lan-noise/v1",
                    "hkdf_info": "static-x25519"
                },
                "expected": {
                    "noise_static_pub_hex": hex::encode(alice_static)
                }
            }),
        );

        write_json(
            "noise_bind_001.json",
            serde_json::json!({
                "name": "LAN Noise identity bind",
                "description": "ed25519_pub || sig(rvn1/lan-noise/v1 || noise_static_pub)",
                "protocol_version": "rvn1",
                "deterministic": true,
                "inputs": {
                    "device_seed_hex": ALICE_DEVICE_SEED,
                    "noise_static_pub_hex": hex::encode(alice_static),
                    "bind_domain": "rvn1/lan-noise/v1"
                },
                "expected": {
                    "bind_len": BIND_LEN,
                    "bind_hex": hex::encode(bind)
                }
            }),
        );

        write_json(
            "rlb1_offer_001.json",
            serde_json::json!({
                "name": "RLB1 offer wire bytes",
                "description": "Exact offer under serde_json canonical field order",
                "protocol_version": "rvn1",
                "deterministic": true,
                "canonical_json_policy": "serde_json::to_vec field order; lowercase hex; omit null otp",
                "inputs": {
                    "device_seed_hex": ALICE_DEVICE_SEED,
                    "device_id": "alice-lan-device-1",
                    "epoch_ms": now
                },
                "expected": {
                    "offer_wire_len": offer_wire.len(),
                    "offer_wire_hex": hex::encode(&offer_wire),
                    "max_offer_wire": MAX_OFFER_WIRE
                },
                "reject_cases": {
                    "combined_cap_ge_65519": {
                        "description": "Whole offer must fit in one Noise transport plaintext",
                        "cert_json_len": oversize_cert_json.len(),
                        "prekey_json_len": oversize_prekey_json.len(),
                        "combined_json_len": oversize_cert_json.len() + oversize_prekey_json.len(),
                        "encode_error": "rlb1 offer exceeds transport plaintext",
                        "offer_wire_len": MAX_OFFER_WIRE + 1,
                        "decode_error": "rlb1 offer exceeds transport plaintext"
                    }
                }
            }),
        );

        write_json(
            "noise_xx_handshake_001.json",
            serde_json::json!({
                "name": "LAN Noise XX handshake KAT",
                "description": "Fixed ephemerals via snow fixed_ephemeral_key_for_testing_only; empty prologue",
                "protocol_version": "rvn1",
                "deterministic": true,
                "kat_production": "snow-0.9.6 fixed_ephemeral_key_for_testing_only per side",
                "inputs": {
                    "noise_pattern": NOISE_PATTERN,
                    "prologue": "",
                    "initiator_device_seed_hex": ALICE_DEVICE_SEED,
                    "responder_device_seed_hex": BOB_DEVICE_SEED,
                    "initiator_ephemeral_priv_hex": hex::encode(INITIATOR_EPHEMERAL),
                    "responder_ephemeral_priv_hex": hex::encode(RESPONDER_EPHEMERAL),
                    "first_application_plaintext_utf8": "rvn1/lan-vector/app-001"
                },
                "expected": {
                    "m1_hex": hex::encode(&kat.m1),
                    "m2_hex": hex::encode(&kat.m2),
                    "m3_hex": hex::encode(&kat.m3),
                    "initiator_static_pub_hex": hex::encode(kat.initiator_static_pub),
                    "responder_static_pub_hex": hex::encode(kat.responder_static_pub),
                    "initiator_remote_static_hex": hex::encode(kat.initiator_remote_static),
                    "responder_remote_static_hex": hex::encode(kat.responder_remote_static),
                    "handshake_hash_hex": hex::encode(kat.handshake_hash),
                    "initiator_bind_transport_hex": hex::encode(&kat.initiator_bind_ct),
                    "responder_bind_transport_hex": hex::encode(&kat.responder_bind_ct),
                    "first_application_plaintext_hex": hex::encode(FIRST_APP_PLAINTEXT),
                    "first_application_ciphertext_hex": hex::encode(&kat.first_app_ct)
                }
            }),
        );

        eprintln!("wrote LAN vectors to {}", out_dir.display());
    }

    /// Used by `ios_swift_rust_lan_integration.sh` to register the Swift test client.
    #[test]
    fn integration_swift_client_pub_hex() {
        let seed = [0x21u8; 32];
        let id = identity_from_hex(&hex::encode(seed));
        eprintln!(
            "RAVEN_INTEGRATION_CLIENT_PUB={}",
            hex::encode(id.public_key_bytes())
        );
        eprintln!("RAVEN_INTEGRATION_CLIENT_ADDR={}", id.address());
    }
}
