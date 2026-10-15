//! The group's Orchard-protocol keys, derived as ZIP 2005 specifies for FROST.
//!
//! The spend validating key `ak` is the FROST group key. Everything else comes
//! from a value `sk` that the participants agree on (`use_qsk = true` in
//! ZIP 2005 § 4.2.3 'Orchard Key Components'):
//!
//!   nk   = ToBase(PRF^expand_sk([0x07]))
//!   qsk  = truncate_32(PRF^expand_sk([0x0C]))
//!   qk   = BLAKE3.derive_key("Zcash ZIP 2005 qk-derivation v1", qsk)
//!   rivk = ToScalar(PRF^expand_qk([0x0D] || ak || nk))
//!
//! Notes received by these keys keep the quantum recovery path of ZIP 2005, as
//! long as qsk is kept. zcash-sign instead builds the full viewing key with a
//! constructor that gives that path up.

use std::error::Error;

use ff::{FromUniformBytes, PrimeField};
use orchard::keys::{FullViewingKey, Scope};
use pasta_curves::pallas;
use zcash_address::unified::{self, Encoding};
use zcash_protocol::consensus::NetworkType;

const QK_CONTEXT: &str = "Zcash ZIP 2005 qk-derivation v1";

/// The group's viewing keys, plus the quantum spending key.
pub struct GroupKeys {
    pub fvk: FullViewingKey,
    pub qk: [u8; 32],
    /// Not used yet: the next step splits it 2-of-3 instead of keeping sk.
    #[allow(dead_code)]
    pub qsk: [u8; 32],
}

/// PRF^expand from the protocol specification: BLAKE2b-512 personalized with
/// "Zcash_ExpandSeed", over the key followed by the input.
fn prf_expand(key: &[u8], input: &[&[u8]]) -> [u8; 64] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state();
    state.update(key);
    for part in input {
        state.update(part);
    }
    *state.finalize().as_array()
}

fn to_base(bytes: &[u8; 64]) -> pallas::Base {
    pallas::Base::from_uniform_bytes(bytes)
}

fn to_scalar(bytes: &[u8; 64]) -> pallas::Scalar {
    pallas::Scalar::from_uniform_bytes(bytes)
}

/// Combines one random contribution per participant into `sk`, so that no
/// participant chooses it alone. Same idea as the contributory generation of
/// zcash/zips#895, which carries the contributions inside COCKTAIL-DKG; this
/// prototype hashes them directly and is not byte-compatible with it.
pub fn contributory_sk(contributions: &[[u8; 32]]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"FrostZec_sk_v0__")
        .to_state();
    state.update(&(contributions.len() as u64).to_le_bytes());
    for contribution in contributions {
        state.update(contribution);
    }
    state.finalize().as_bytes().try_into().expect("32-byte hash")
}

/// Derives the group's keys from `sk` and the FROST group key `ak`.
pub fn derive(sk: &[u8; 32], ak: &[u8; 32]) -> Result<GroupKeys, Box<dyn Error>> {
    let nk = to_base(&prf_expand(sk, &[&[0x07]])).to_repr();
    let qsk: [u8; 32] = prf_expand(sk, &[&[0x0c]])[..32].try_into()?;
    let qk = blake3::derive_key(QK_CONTEXT, &qsk);
    let rivk = to_scalar(&prf_expand(&qk, &[&[0x0d], ak, &nk])).to_repr();

    let mut bytes = [0u8; 96];
    bytes[..32].copy_from_slice(ak);
    bytes[32..64].copy_from_slice(&nk);
    bytes[64..].copy_from_slice(&rivk);
    let fvk = FullViewingKey::from_bytes(&bytes).ok_or("these keys do not form a valid full viewing key")?;
    Ok(GroupKeys { fvk, qk, qsk })
}

/// The unified full viewing key, with its Orchard component only (Ironwood
/// uses the same Orchard-protocol keys).
pub fn ufvk(fvk: &FullViewingKey, network: NetworkType) -> Result<String, Box<dyn Error>> {
    let ufvk = unified::Ufvk::try_from_items(vec![unified::Fvk::Orchard(fvk.to_bytes())])?;
    Ok(ufvk.encode(&network))
}

/// The group's first external address, as a unified address.
pub fn address(fvk: &FullViewingKey, network: NetworkType) -> Result<String, Box<dyn Error>> {
    encode_address(&fvk.address_at(0u32, Scope::External), network)
}

pub fn encode_address(address: &orchard::Address, network: NetworkType) -> Result<String, Box<dyn Error>> {
    let ua = unified::Address::try_from_items(vec![unified::Receiver::Orchard(address.to_raw_address_bytes())])?;
    Ok(ua.encode(&network))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test-vectors/zcash/*.json writes byte strings reversed (like txids).
    fn reversed(text: &str) -> [u8; 32] {
        let mut bytes: [u8; 32] = hex::decode(text).unwrap().try_into().unwrap();
        bytes.reverse();
        bytes
    }

    fn official_sk() -> [u8; 32] {
        reversed("482169eef62efaaf9d9364b1666e4d4c299e04a852e10c5b949e2d9a738f7a5d")
    }

    /// The first vector of zcash-test-vectors' orchard_key_components (legacy
    /// derivation). It checks PRF^expand, ToBase and ToScalar, which the
    /// use_qsk derivation reuses; there are no official use_qsk vectors yet.
    #[test]
    fn primitives_match_the_official_orchard_vector() {
        let sk = official_sk();
        let nk = to_base(&prf_expand(&sk, &[&[0x07]])).to_repr();
        let rivk = to_scalar(&prf_expand(&sk, &[&[0x08]])).to_repr();
        assert_eq!(nk, reversed("1bfdfe68a9de398c948355ff610cc246c267c3b00df7471fd05a943867822f9f"));
        assert_eq!(rivk, reversed("3de4a771cab4568b45e6fe25e3fb19b80889332db334e0c67c5f4f6089cf1c02"));
    }

    /// The same primitives against orchard's own legacy derivation.
    #[test]
    fn primitives_match_orchard() {
        let sk = official_sk();
        let fvk = FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes(sk).unwrap()).to_bytes();
        assert_eq!(fvk[32..64], to_base(&prf_expand(&sk, &[&[0x07]])).to_repr());
        assert_eq!(fvk[64..], to_scalar(&prf_expand(&sk, &[&[0x08]])).to_repr());
    }

    #[test]
    fn use_qsk_keys_form_a_valid_viewing_key() {
        let legacy = FullViewingKey::from(&orchard::keys::SpendingKey::from_bytes(official_sk()).unwrap()).to_bytes();
        let ak: [u8; 32] = legacy[..32].try_into().unwrap();
        let keys = derive(&[7; 32], &ak).unwrap();
        assert_eq!(&keys.fvk.to_bytes()[..32], &ak);
        assert_eq!(keys.qk, blake3::derive_key(QK_CONTEXT, &keys.qsk));
        // Another sk changes nk, qsk and rivk, but not ak.
        let other = derive(&[8; 32], &ak).unwrap();
        assert_ne!(keys.fvk.to_bytes()[32..], other.fvk.to_bytes()[32..]);
    }

    #[test]
    fn every_contribution_counts() {
        let a = contributory_sk(&[[1; 32], [2; 32], [3; 32]]);
        assert_ne!(a, contributory_sk(&[[1; 32], [2; 32], [4; 32]]));
        assert_ne!(a, contributory_sk(&[[1; 32], [2; 32]]));
    }
}

#[cfg(test)]
mod independent_vectors {
    use super::*;
    use serde_json::Value;

    /// use_qsk vectors generated by another, independent implementation
    /// (zafe-core, proposed in ZcashFoundation/frost-tools#610; not official).
    const VECTORS: &str = include_str!("../tests/fixtures/zip2005_use_qsk.json");

    fn field(vector: &Value, name: &str) -> String {
        vector[name].as_str().unwrap_or_else(|| panic!("missing {name}")).to_string()
    }

    #[test]
    fn matches_the_zafe_use_qsk_vectors() {
        let vectors: Value = serde_json::from_str(VECTORS).unwrap();
        let list = vectors["vectors"].as_array().unwrap();
        assert!(!list.is_empty());
        for vector in list {
            let sk: [u8; 32] = hex::decode(field(vector, "sk")).unwrap().try_into().unwrap();
            let ak: [u8; 32] = hex::decode(field(vector, "ak")).unwrap().try_into().unwrap();
            let keys = derive(&sk, &ak).unwrap();
            let fvk = keys.fvk.to_bytes();
            assert_eq!(hex::encode(keys.qsk), field(vector, "qsk"));
            assert_eq!(hex::encode(keys.qk), field(vector, "qk"));
            assert_eq!(hex::encode(&fvk[32..64]), field(vector, "nk"));
            assert_eq!(hex::encode(&fvk[64..]), field(vector, "rivk_ext"));
            assert_eq!(hex::encode(fvk), field(vector, "fvk"));
            let address = keys.fvk.address_at(0u32, Scope::External).to_raw_address_bytes();
            assert_eq!(hex::encode(address), field(vector, "default_address_raw"));
            assert_eq!(ufvk(&keys.fvk, NetworkType::Test).unwrap(), field(vector, "ufvk_testnet"));
        }
    }
}
