//! FROST member backup strings: version 1 of the draft ZIP described in
//! docs/backup-format.md, byte-for-byte Zkool's `zkfrost` string.
//!
//! One Bech32m string, human-readable part `zkfrost`, 68 bytes of payload:
//! version (1), member identifier (1), threshold t (1), group size n (1), the
//! member's FROST signing share (32) and the group's sk (32). The restore
//! takes the string and the group's unified full viewing key: ak comes from
//! the key, and nk and rivk recomputed from sk under each derivation tell
//! which one the group uses, or that the string belongs to another group.
//!
//! Written from the draft's rules, independently of Zkool's code; both pass
//! the same test vectors (tests/fixtures/frost-member-backup-vectors.json).

use std::error::Error;

use bech32::{Bech32m, Hrp, primitives::decode::CheckedHrpstring};
use orchard::keys::{FullViewingKey, SpendingKey};
use reddsa::frost::redpallas as frost;
use frost::keys::{KeyPackage, SigningShare, VerifyingShare};
use frost::{Identifier, VerifyingKey};
use zcash_protocol::consensus::NetworkType;

use crate::keys;

pub const HRP: &str = "zkfrost";
const VERSION: u8 = 1;
const PAYLOAD_LEN: usize = 68;

/// How the group's nk and rivk come from sk and ak.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Derivation {
    /// ZIP 2005 with use_qsk: the group's notes are quantum recoverable.
    Zip2005,
    /// Zkool's groups from before ZIP 2005: their notes are not.
    Legacy,
}

/// What a version 1 string carries.
#[derive(Debug, PartialEq, Eq)]
pub struct Backup {
    pub id: u8,
    pub t: u8,
    pub n: u8,
    pub share: [u8; 32],
    pub sk: [u8; 32],
}

impl Backup {
    /// The backup of one member of an n-member group.
    pub fn new(key_package: &KeyPackage, n: u16, sk: &[u8; 32]) -> Result<Backup, Box<dyn Error>> {
        let id = small_identifier(key_package.identifier()).ok_or(
            "this member's identifier is not an integer from 1 to 255, which version 1 cannot hold \
             (see the open points in docs/backup-format.md)",
        )?;
        let share: [u8; 32] = key_package.signing_share().serialize().try_into().map_err(|_| "signing share is not 32 bytes")?;
        Ok(Backup { id, t: u8::try_from(*key_package.min_signers())?, n: u8::try_from(n)?, share, sk: *sk })
    }

    pub fn encode(&self) -> Result<String, Box<dyn Error>> {
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.extend_from_slice(&[VERSION, self.id, self.t, self.n]);
        payload.extend_from_slice(&self.share);
        payload.extend_from_slice(&self.sk);
        Ok(bech32::encode::<Bech32m>(Hrp::parse(HRP)?, &payload)?)
    }

    /// Rejects anything that is not a well-formed version 1 string: bad
    /// Bech32m (checksum, mixed case, padding), another prefix, a wrong
    /// length, an unknown version, or an identifier or threshold outside 1..=n.
    pub fn decode(text: &str) -> Result<Backup, Box<dyn Error>> {
        let checked = CheckedHrpstring::new::<Bech32m>(text.trim()).map_err(|e| format!("not a valid backup string: {e}"))?;
        if checked.hrp().to_lowercase() != HRP {
            return Err("not a FROST member backup string".into());
        }
        // ZIP 173: the bits left over by the conversion to bytes must be at
        // most 4 and all zero, so each payload has only one lowercase string.
        checked.validate_segwit_padding().map_err(|e| format!("not a valid backup string: {e}"))?;
        let payload: Vec<u8> = checked.byte_iter().collect();
        if payload.len() != PAYLOAD_LEN {
            return Err(format!("the backup string holds {} bytes instead of {PAYLOAD_LEN}", payload.len()).into());
        }
        if payload[0] != VERSION {
            return Err(format!("backup string version {} is not supported", payload[0]).into());
        }
        let (id, t, n) = (payload[1], payload[2], payload[3]);
        if n == 0 || id == 0 || id > n || t == 0 || t > n {
            return Err(format!("invalid backup string: member {id}, threshold {t} of {n}").into());
        }
        Ok(Backup { id, t, n, share: payload[4..36].try_into()?, sk: payload[36..].try_into()? })
    }
}

/// A member rebuilt from its string and the group's viewing key.
pub struct Restored {
    pub backup: Backup,
    pub derivation: Derivation,
    pub key_package: KeyPackage,
    pub fvk: FullViewingKey,
    pub network: NetworkType,
}

pub fn restore(text: &str, ufvk: &str) -> Result<Restored, Box<dyn Error>> {
    let backup = Backup::decode(text)?;
    if bool::from(SpendingKey::from_bytes(backup.sk).is_none()) {
        return Err("the backup string holds an invalid sk".into());
    }
    let signing_share =
        SigningShare::deserialize(&backup.share).map_err(|_| "the backup string holds an invalid signing share")?;
    let (network, fvk) = keys::parse_ufvk(ufvk)?;
    let ak: [u8; 32] = fvk.to_bytes()[..32].try_into()?;
    let derivation = if keys::derive(&backup.sk, &ak)?.fvk == fvk {
        Derivation::Zip2005
    } else if keys::derive_legacy(&backup.sk, &ak)? == fvk {
        Derivation::Legacy
    } else {
        return Err("this backup string belongs to another group: neither derivation of its sk matches the viewing key".into());
    };
    let key_package = KeyPackage::new(
        Identifier::try_from(u16::from(backup.id))?,
        signing_share,
        VerifyingShare::from(signing_share),
        VerifyingKey::deserialize(&ak)?,
        u16::from(backup.t),
    );
    Ok(Restored { backup, derivation, key_package, fvk, network })
}

/// The integer value of an identifier, when it is one from 1 to 255.
fn small_identifier(id: &Identifier) -> Option<u8> {
    let bytes = id.serialize();
    (bytes[0] != 0 && bytes[1..].iter().all(|&b| b == 0)).then_some(bytes[0])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use frost::keys::PublicKeyPackage;
    use serde_json::Value;

    use super::*;
    use crate::{dkg, signing};

    const VECTORS: &str = include_str!("../tests/fixtures/frost-member-backup-vectors.json");

    fn derivation(name: &str) -> Derivation {
        match name {
            "zip2005" => Derivation::Zip2005,
            "legacy" => Derivation::Legacy,
            other => panic!("unknown derivation {other}"),
        }
    }

    fn bytes32(value: &Value) -> [u8; 32] {
        hex::decode(value.as_str().unwrap()).unwrap().try_into().unwrap()
    }

    /// The draft's vectors, checked against Zkool's own code when generated
    /// (tools/zip-vectors).
    #[test]
    fn passes_the_draft_vectors() {
        let vectors: Value = serde_json::from_str(VECTORS).unwrap();
        for group in vectors["valid"].as_array().unwrap() {
            let expected = derivation(group["derivation"].as_str().unwrap());
            for member in group["members"].as_array().unwrap() {
                let text = member["string"].as_str().unwrap();
                let backup = Backup::decode(text).unwrap();
                assert_eq!(backup.id as u64, member["id"].as_u64().unwrap());
                assert_eq!(backup.t as u64, group["t"].as_u64().unwrap());
                assert_eq!(backup.n as u64, group["n"].as_u64().unwrap());
                assert_eq!(backup.share, bytes32(&member["signing_share"]));
                assert_eq!(backup.sk, bytes32(&group["sk"]));
                assert_eq!(backup.encode().unwrap(), text);

                for (key, network) in [("ufvk_mainnet", NetworkType::Main), ("ufvk_testnet", NetworkType::Test)] {
                    let restored = restore(text, group[key].as_str().unwrap()).unwrap();
                    assert_eq!(restored.derivation, expected);
                    assert_eq!(restored.network, network);
                    assert_eq!(restored.fvk.to_bytes()[..32], bytes32(&group["ak"]));
                }
            }
        }

        let upper = &vectors["valid_upper_case"]["string"];
        assert_eq!(Backup::decode(upper.as_str().unwrap()).unwrap().id, 1);

        for case in vectors["invalid"].as_array().unwrap() {
            let text = case["string"].as_str().unwrap();
            assert!(Backup::decode(text).is_err(), "accepted: {}", case["reason"]);
        }

        let wrong = &vectors["wrong_group"];
        let text = wrong["string"].as_str().unwrap();
        assert!(Backup::decode(text).is_ok());
        assert!(restore(text, wrong["ufvk_mainnet"].as_str().unwrap()).is_err());
    }

    /// Every member of a fresh group goes through its string, and every pair
    /// of restored members still signs an Orchard spend under a fresh rk.
    #[test]
    fn restored_members_sign() {
        let (key_packages, public_key_package) = dkg::run(3, 2).unwrap();
        let ak = signing::group_ak(&public_key_package).unwrap();
        let sk = keys::contributory_sk(&[rand::random(), rand::random(), rand::random()]);
        let ufvk = keys::ufvk(&keys::derive(&sk, &ak).unwrap().fvk, NetworkType::Test).unwrap();

        let mut restored = BTreeMap::new();
        for key_package in key_packages.values() {
            let text = Backup::new(key_package, 3, &sk).unwrap().encode().unwrap();
            let member = restore(&text, &ufvk).unwrap();
            assert_eq!(member.derivation, Derivation::Zip2005);
            assert_eq!(member.key_package, *key_package);
            restored.insert(*member.key_package.identifier(), member.key_package);
        }

        let verifying_shares = restored.iter().map(|(id, kp)| (*id, *kp.verifying_share())).collect();
        let rebuilt = PublicKeyPackage::new(verifying_shares, *public_key_package.verifying_key(), Some(2));
        let ids: Vec<_> = restored.keys().copied().collect();
        for (i, a) in ids.iter().enumerate() {
            for b in &ids[i + 1..] {
                let pair = [(*a, restored[a].clone()), (*b, restored[b].clone())].into_iter().collect();
                signing::sign(&rand::random(), &signing::random_alpha(), &pair, &rebuilt).unwrap();
            }
        }
    }

    #[test]
    fn derived_identifiers_do_not_fit_version_1() {
        let (key_packages, _) = dkg::run(2, 2).unwrap();
        let key_package = key_packages.values().next().unwrap();
        let derived = Identifier::derive(b"a vault member").unwrap();
        let other = KeyPackage::new(
            derived,
            *key_package.signing_share(),
            *key_package.verifying_share(),
            *key_package.verifying_key(),
            2,
        );
        assert!(Backup::new(&other, 2, &[1; 32]).is_err());
    }
}
