//! Bech32m (BIP-350) encode/decode for RavenAddressV1.
//! Uses the `bech32` crate's Bech32m variant — same checksum constant as
//! `protocol/reference/raven_protocol/bech32m.py`.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};

pub fn encode(hrp: &str, payload: &[u8]) -> Result<String, String> {
    let hrp = Hrp::parse(hrp).map_err(|e| e.to_string())?;
    bech32::encode::<Bech32m>(hrp, payload).map_err(|e| e.to_string())
}

/// Strict Bech32m (BIP-350) decode. `bech32::decode` also falls back to the
/// original BIP-173 Bech32 checksum, which would give every address a second
/// accepted string form (the Python reference accepts only `BECH32M_CONST`),
/// so validate against Bech32m explicitly.
///
/// The checksum alone is not enough: `byte_iter` silently drops trailing
/// 5-to-8-bit padding bits without checking they are zero, so a 21-byte
/// payload (2 padding bits) would still have three more valid-checksum string
/// forms. The Python reference rejects those (`_convertbits(.., pad=False)`),
/// so require the input to be exactly the canonical re-encoding of what it
/// decodes to (all-uppercase input stays accepted, mixed case does not).
pub fn decode(s: &str) -> Option<(String, Vec<u8>)> {
    let checked = CheckedHrpstring::new::<Bech32m>(s).ok()?;
    let hrp = checked.hrp();
    let data: Vec<u8> = checked.byte_iter().collect();
    let canonical = bech32::encode::<Bech32m>(Hrp::parse(&hrp.to_lowercase()).ok()?, &data).ok()?;
    if canonical != s.to_ascii_lowercase() {
        return None;
    }
    Some((hrp.to_string(), data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_bytes() {
        let payload = [0x01u8].into_iter().chain([0xABu8; 20]).collect::<Vec<_>>();
        let enc = encode("rvn", &payload).unwrap();
        assert!(enc.starts_with("rvn1"));
        let (hrp, data) = decode(&enc).unwrap();
        assert_eq!(hrp, "rvn");
        assert_eq!(data, payload);
    }

    #[test]
    fn rejects_bip173_bech32_checksum() {
        // Same 21-byte payload as Alice's address, but with the original BIP-173
        // Bech32 checksum (constant 1) instead of Bech32m (0x2bc830a3).
        let canonical = "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfvecule0";
        let bech32_variant = "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfvvyvnud";
        // Sanity: the lenient library decoder still accepts the variant, so this
        // test would fail against a plain `bech32::decode` implementation.
        assert!(bech32::decode(bech32_variant).is_ok());
        assert!(decode(canonical).is_some());
        assert!(decode(bech32_variant).is_none());
        assert!(crate::address::decode_address(bech32_variant).is_none());
    }

    #[test]
    fn rejects_nonzero_or_overlong_padding_aliases() {
        let canonical = "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfvecule0";
        // Same payload, last data char's 2 padding bits set to 1/2/3, with the
        // Bech32m checksum recomputed (each rejected by the Python reference),
        // plus one extra data char (5 surplus padding bits).
        let aliases = [
            "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfdywg2ya",
            "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfw2aau2z",
            "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldf0htffhs",
            "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfvqqw96cy",
        ];
        let (_, want) = decode(canonical).unwrap();
        for alias in aliases {
            // Sanity: the checksum is valid Bech32m and the unchecked byte
            // iterator yields the very same payload, so only the padding check
            // rejects these.
            let lenient = CheckedHrpstring::new::<Bech32m>(alias).unwrap();
            assert_eq!(lenient.byte_iter().collect::<Vec<u8>>(), want, "{alias}");
            assert!(decode(alias).is_none(), "{alias}");
            assert!(decode(&alias.to_ascii_uppercase()).is_none(), "{alias}");
            assert!(crate::address::decode_address(alias).is_none(), "{alias}");
        }
    }

    #[test]
    fn empty_and_byte_aligned_payloads_still_decode() {
        // 0 bytes (no padding) and 5 bytes (40 bits = 8 chars, no padding).
        for payload in [&[][..], &[1u8, 2, 3, 4, 5][..]] {
            let enc = encode("rvn", payload).unwrap();
            assert_eq!(decode(&enc).unwrap().1, payload);
        }
    }

    #[test]
    fn mixed_case_and_uppercase_behaviour_unchanged() {
        let canonical = "rvn1qysluvwl5922yctzd0u9gpr06gn3k7ldfvecule0";
        let upper = canonical.to_ascii_uppercase();
        // BIP-350 allows an all-uppercase string; the Python reference lowercases.
        assert!(decode(&upper).is_some());
        let mut mixed = canonical.to_string();
        mixed.replace_range(0..1, "R");
        assert!(decode(&mixed).is_none());
    }
}
