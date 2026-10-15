//! Distributed key generation for a t-of-n FROST(Pallas, BLAKE2b-512) group,
//! with no trusted dealer.
//!
//! All participants run in this one process and their messages are passed in
//! memory. In a real deployment each participant is a separate device and the
//! round 2 packages travel over an encrypted channel.

use std::collections::BTreeMap;
use std::error::Error;

use reddsa::frost::redpallas as frost;
use frost::keys::dkg;
use frost::keys::{EvenY, KeyPackage, PublicKeyPackage};
use frost::Identifier;

/// Runs the three DKG steps for participants 1..=max_signers and returns each
/// participant's key package plus the shared public key package.
pub fn run(
    max_signers: u16,
    min_signers: u16,
) -> Result<(BTreeMap<Identifier, KeyPackage>, PublicKeyPackage), Box<dyn Error>> {
    let mut rng = rand::thread_rng();
    let ids = (1..=max_signers)
        .map(Identifier::try_from)
        .collect::<Result<Vec<_>, _>>()?;

    // Part 1: each participant commits to its secret polynomial. The package
    // is broadcast to everyone, the secret package stays with its owner.
    let mut round1_secrets = BTreeMap::new();
    let mut round1_packages = BTreeMap::new();
    for &id in &ids {
        let (secret, package) = dkg::part1(id, max_signers, min_signers, &mut rng)?;
        round1_secrets.insert(id, secret);
        round1_packages.insert(id, package);
    }

    // Part 2: each participant checks the others' commitments and computes one
    // private package per other participant.
    let mut round2_secrets = BTreeMap::new();
    let mut round2_inboxes: BTreeMap<Identifier, BTreeMap<Identifier, dkg::round2::Package>> =
        BTreeMap::new();
    for &id in &ids {
        let received = others(&round1_packages, id);
        let secret = round1_secrets.remove(&id).ok_or("missing round 1 secret")?;
        let (round2_secret, outgoing) = dkg::part2(secret, &received)?;
        round2_secrets.insert(id, round2_secret);
        for (recipient, package) in outgoing {
            round2_inboxes.entry(recipient).or_default().insert(id, package);
        }
    }

    // Part 3: each participant derives its long-lived signing share and the
    // group public key. Every participant must end up with the same group key.
    let mut key_packages = BTreeMap::new();
    let mut group: Option<PublicKeyPackage> = None;
    for &id in &ids {
        let received = others(&round1_packages, id);
        let inbox = round2_inboxes.get(&id).ok_or("missing round 2 packages")?;
        let (key_package, public_key_package) = dkg::part3(&round2_secrets[&id], &received, inbox)?;
        match &group {
            None => group = Some(public_key_package),
            Some(expected) if expected.verifying_key() != public_key_package.verifying_key() => {
                return Err("participants disagree on the group public key".into());
            }
            Some(_) => {}
        }
        key_packages.insert(id, key_package);
    }
    let group = group.ok_or("no participants")?;

    // Orchard needs ak with an even y coordinate. If the group key is odd,
    // every participant negates its share and the group key, which keeps the
    // shares consistent because Shamir sharing is linear.
    let is_even = group.has_even_y();
    let group = group.into_even_y(Some(is_even));
    let key_packages = key_packages
        .into_iter()
        .map(|(id, key_package)| (id, key_package.into_even_y(Some(is_even))))
        .collect();
    Ok((key_packages, group))
}

/// The packages of every participant except `me`, as each participant receives them.
fn others<T: Clone>(all: &BTreeMap<Identifier, T>, me: Identifier) -> BTreeMap<Identifier, T> {
    all.iter()
        .filter(|(id, _)| **id != me)
        .map(|(id, package)| (*id, package.clone()))
        .collect()
}
