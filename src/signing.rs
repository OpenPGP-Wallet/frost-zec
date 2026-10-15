//! Re-randomized FROST signing (ZIP 312) for Orchard-protocol spends.
//!
//! Each spend in a PCZT carries its randomizer alpha: the spend is authorized
//! by a RedPallas signature under rk = ak + [alpha]G, where ak is the FROST
//! group key. Two signers each produce a share over the transaction's sighash
//! with that alpha, and the coordinator aggregates them. Every aggregated
//! signature is then checked with orchard's own RedPallas code, independently
//! of the FROST library, before it is used.

use std::collections::BTreeMap;
use std::error::Error;

use ff::PrimeField;
use orchard::keys::SpendValidatingKey;
use orchard::primitives::redpallas::{self, SpendAuth};
use pasta_curves::pallas;
use reddsa::frost::redpallas as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::rerandomized::{RandomizedParams, Randomizer};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, PallasBlake2b512, SigningPackage};

/// The FROST group key as an Orchard spend validating key `ak` (32 bytes, even y).
pub fn group_ak(public_key_package: &PublicKeyPackage) -> Result<[u8; 32], Box<dyn Error>> {
    let bytes: [u8; 32] = public_key_package
        .verifying_key()
        .serialize()?
        .try_into()
        .map_err(|_| "unexpected group key length")?;
    if bytes[31] & 0x80 != 0 {
        return Err("the group key has an odd y coordinate: it is not a valid ak".into());
    }
    Ok(bytes)
}

/// Round 1 for one signer: fresh single-use nonces and their public commitment.
/// The nonces never leave memory.
pub fn commit(key_package: &KeyPackage) -> (SigningNonces, SigningCommitments) {
    frost::round1::commit(key_package.signing_share(), &mut rand::thread_rng())
}

/// Round 2 for one signer: its share of the signature over `sighash`, for the
/// spend whose randomizer is `alpha`.
pub fn share(
    sighash: &[u8; 32],
    alpha: &[u8; 32],
    commitments: &BTreeMap<Identifier, SigningCommitments>,
    nonces: &SigningNonces,
    key_package: &KeyPackage,
) -> Result<SignatureShare, Box<dyn Error>> {
    let package = SigningPackage::new(commitments.clone(), sighash);
    let randomizer = Randomizer::deserialize(alpha)?;
    // The randomizer comes from the PCZT (chosen by the transaction builder),
    // which is the "external randomizer" path; frost-rerandomized marks it
    // deprecated in favour of randomizers derived from the commitments.
    #[allow(deprecated)]
    let share = frost_rerandomized::sign::<PallasBlake2b512>(&package, nonces, key_package, randomizer)?;
    Ok(share)
}

/// Aggregates the shares into one RedPallas signature and checks it.
pub fn aggregate(
    sighash: &[u8; 32],
    alpha: &[u8; 32],
    commitments: &BTreeMap<Identifier, SigningCommitments>,
    shares: &BTreeMap<Identifier, SignatureShare>,
    public_key_package: &PublicKeyPackage,
) -> Result<[u8; 64], Box<dyn Error>> {
    let package = SigningPackage::new(commitments.clone(), sighash);
    let params = RandomizedParams::from_randomizer(public_key_package.verifying_key(), Randomizer::deserialize(alpha)?);
    let signature = frost::rerandomized::aggregate(&package, shares, public_key_package, &params)?;
    let bytes: [u8; 64] = signature.serialize()?.try_into().map_err(|_| "unexpected signature length")?;
    verify(&group_ak(public_key_package)?, alpha, sighash, &bytes)?;
    Ok(bytes)
}

/// Signs in one process with the given signers (used by `sign` and `selftest`).
pub fn sign(
    sighash: &[u8; 32],
    alpha: &[u8; 32],
    signers: &BTreeMap<Identifier, KeyPackage>,
    public_key_package: &PublicKeyPackage,
) -> Result<[u8; 64], Box<dyn Error>> {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, key_package) in signers {
        let (signer_nonces, signer_commitments) = commit(key_package);
        nonces.insert(*id, signer_nonces);
        commitments.insert(*id, signer_commitments);
    }
    let mut shares = BTreeMap::new();
    for (id, key_package) in signers {
        shares.insert(*id, share(sighash, alpha, &commitments, &nonces[id], key_package)?);
    }
    aggregate(sighash, alpha, &commitments, &shares, public_key_package)
}

/// Checks a signature the way consensus does: RedPallas under rk = ak + [alpha]G.
pub fn verify(ak: &[u8; 32], alpha: &[u8; 32], sighash: &[u8; 32], signature: &[u8; 64]) -> Result<(), Box<dyn Error>> {
    let ak = SpendValidatingKey::from_bytes(ak).ok_or("invalid ak")?;
    let alpha = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(*alpha)).ok_or("invalid randomizer")?;
    let rk = ak.randomize(&alpha);
    rk.verify(sighash, &redpallas::Signature::<SpendAuth>::from(*signature))
        .map_err(|_| "the aggregated signature does not verify under rk".into())
}

/// A random valid randomizer, for the self-test.
pub fn random_alpha() -> [u8; 32] {
    let mut wide = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut wide);
    <pallas::Scalar as ff::FromUniformBytes<64>>::from_uniform_bytes(&wide).to_repr()
}
