//! Recovery after a lost device (docs/spec.md § 7.2). An account is never
//! repaired in place: the two remaining members create a new account and sweep
//! every note of the old one to it, so that whatever the lost device held can
//! no longer spend.
//!
//! When the coordinator is lost, a new coordinator pairs with the co-signer
//! (§ 3). The co-signer sends [`GroupInfo`], the old group's public key package
//! and viewing key, sealed under the new pairing, alongside its key generation
//! messages for the new account. The new coordinator restores member 3 from
//! its backup and checks it against them with [`restore_member`] before it
//! sends anything secret of its own. When the backup is a profile 1 file, which
//! holds the viewing key too, the co-signer's viewing key must be the file's:
//! a co-signer cannot then pass another group off as the old one. The sweep is
//! signed by the restored member 3 and the co-signer's member 2, in an ordinary
//! session (§ 5).

use std::collections::BTreeMap;
use std::error::Error;

use frost::keys::PublicKeyPackage;
use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use pczt::Pczt;
use reddsa::frost::redpallas as frost;

use crate::check::{self, Report};
use crate::cosigning::Member;
use crate::setup::{BACKUP, Group};
use crate::{backup, keys, pczt_io, signing};

/// The old group, as the co-signer describes it to a new coordinator.
pub struct GroupInfo {
    /// The old group's key and every member's verifying share.
    pub public_key_package: PublicKeyPackage,
    /// The old group's unified full viewing key.
    pub ufvk: String,
}

#[derive(Encode, Decode)]
#[cbor(map)]
struct GroupInfoWire {
    #[n(1)]
    public_key_package: ByteVec,
    #[n(2)]
    ufvk: String,
}

/// The longest viewing key a reader accepts (a unified full viewing key is a
/// few hundred characters).
const MAX_UFVK_LEN: usize = 2048;

impl GroupInfo {
    /// The description of the group `member` belongs to, whose viewing key is
    /// `ufvk`.
    pub fn new(member: &Member, ufvk: &str) -> GroupInfo {
        GroupInfo {
            public_key_package: member.public_key_package.clone(),
            ufvk: ufvk.to_string(),
        }
    }

    /// The CBOR encoding, sealed under [`crate::wire::kind::GROUP_INFO`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(minicbor::to_vec(GroupInfoWire {
            public_key_package: ByteVec::from(self.public_key_package.serialize()?),
            ufvk: self.ufvk.clone(),
        })
        .expect("encoding to memory cannot fail"))
    }

    /// Reads the CBOR encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<GroupInfo, Box<dyn Error>> {
        let wire: GroupInfoWire = minicbor::decode(bytes)?;
        if wire.ufvk.len() > MAX_UFVK_LEN {
            return Err("the group's viewing key is too long".into());
        }
        Ok(GroupInfo {
            public_key_package: PublicKeyPackage::deserialize(&wire.public_key_package)?,
            ufvk: wire.ufvk,
        })
    }
}

/// Restores member 3 from its backup string against the group the co-signer
/// described, and returns it ready to sign. `kit_ufvk` is the viewing key the
/// backup kit holds, when it holds one (a profile 1 file): the co-signer's
/// must be the same.
///
/// The checks: the kit's and the co-signer's viewing keys agree; `sk` with the
/// group key gives that viewing key (so the string is this group's); the
/// member is member 3, with the share, threshold and size of the public key
/// package.
pub fn restore_member(
    backup_text: &str,
    info: &GroupInfo,
    kit_ufvk: Option<&str>,
) -> Result<Group, Box<dyn Error>> {
    if let Some(kit) = kit_ufvk
        && kit.trim() != info.ufvk
    {
        return Err(
            "the co-signer describes another group than the one in the backup kit: \
             do not go on with this co-signer"
                .into(),
        );
    }
    let restored = backup::restore(backup_text, &info.ufvk)?;
    backup::check_member(&restored, &info.public_key_package)?;
    if u16::from(restored.backup.id) != BACKUP {
        return Err(format!("the backup is member {}, not member 3", restored.backup.id).into());
    }
    let address = keys::address(&restored.fvk, restored.network)?;
    let sk = restored.backup.sk;
    Ok(Group {
        member: Member {
            key_package: restored.key_package,
            public_key_package: info.public_key_package.clone(),
            fvk: restored.fvk,
            network: restored.network,
        },
        sk,
        ufvk: info.ufvk.clone(),
        address,
    })
}

/// When the co-signer is lost (spec § 7.2): the coordinator signs the sweep
/// with its own member and the restored member 3, after the same checks as any
/// request. Both must be members of one group; the checks run against it.
/// Until the sweep is mined this one device holds two members of three, so it
/// should be done in one sitting.
pub fn sign_with_two_members(
    pczt_bytes: &[u8],
    mine: &Member,
    restored: &Member,
) -> Result<(Pczt, Report), Box<dyn Error>> {
    if mine.public_key_package != restored.public_key_package || mine.fvk != restored.fvk {
        return Err("the restored member belongs to another group".into());
    }
    if mine.id() == restored.id() {
        return Err("two different members are needed".into());
    }
    let pczt = pczt_io::parse(pczt_bytes)?;
    let report = check::analyze(&pczt, &mine.fvk, mine.network)?;
    let sighash = pczt_io::sighash(&pczt)?;
    let signers = BTreeMap::from([
        (mine.id(), mine.key_package.clone()),
        (restored.id(), restored.key_package.clone()),
    ]);
    let mut signatures = Vec::new();
    for spend in pczt_io::spends_to_sign(&pczt)? {
        let signature = signing::sign(&sighash, &spend.alpha, &signers, &mine.public_key_package)?;
        signatures.push((spend.index, signature));
    }
    Ok((pczt_io::apply(pczt, &sighash, &signatures)?, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::{CoordinatorSetup, CosignerSetup, Round1, Round2};
    use zcash_protocol::consensus::NetworkType;

    fn group() -> (Group, Group, Group) {
        let (coordinator, c1) = CoordinatorSetup::start(NetworkType::Test).unwrap();
        let (cosigner, s1, s2) = CosignerSetup::respond(NetworkType::Test, &c1).unwrap();
        let (c2, one) = coordinator.finish(&s1, &s2).unwrap();
        let (two, three) = cosigner
            .finish(&Round2::from_bytes(&c2.to_bytes()).unwrap())
            .unwrap();
        let _ = Round1::from_bytes(&s1.to_bytes()).unwrap();
        (one, two, three)
    }

    #[test]
    fn member_3_is_restored_against_the_described_group() {
        let (_, two, three) = group();
        let info =
            GroupInfo::from_bytes(&GroupInfo::new(&two.member, &two.ufvk).to_bytes().unwrap())
                .unwrap();
        let backup = three.backup_string().unwrap();
        let restored = restore_member(&backup, &info, Some(&two.ufvk)).unwrap();
        assert_eq!(restored.address, three.address);
        assert_eq!(restored.member.id(), three.member.id());
        assert_eq!(restored.sk, three.sk);
        // Without the kit's viewing key, the co-signer's is taken as given.
        restore_member(&backup, &info, None).unwrap();
    }

    #[test]
    fn a_lying_or_mismatched_description_is_refused() {
        let (_, two, three) = group();
        let (_, other, other_three) = group();
        let backup = three.backup_string().unwrap();

        // The co-signer describes another group: the kit's viewing key differs.
        let lying = GroupInfo::new(&other.member, &other.ufvk);
        let refused = restore_member(&backup, &lying, Some(&two.ufvk))
            .err()
            .unwrap()
            .to_string();
        assert!(refused.contains("another group"), "{refused}");
        // Without the kit, the string's sk does not give that viewing key.
        assert!(restore_member(&backup, &lying, None).is_err());
        // The right viewing key with another group's public keys.
        let mixed = GroupInfo {
            public_key_package: other.member.public_key_package.clone(),
            ufvk: two.ufvk.clone(),
        };
        assert!(restore_member(&backup, &mixed, None).is_err());
        // Member 2's string is not member 3.
        let info = GroupInfo::new(&two.member, &two.ufvk);
        let refused = restore_member(&two.backup_string().unwrap(), &info, None)
            .err()
            .unwrap()
            .to_string();
        assert!(refused.contains("not member 3"), "{refused}");
        drop(other_three);
    }
}
