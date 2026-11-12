//! Key generation between the coordinator (member 1) and the co-signer, which
//! plays members 2 and 3 (docs/spec.md § 4). Member 3 is the backup: the
//! co-signer exports it as a member backup string and then deletes it.
//!
//! The DKG is the three-part FROST DKG of `reddsa`. On top of it, the members
//! agree on `sk` by commit and reveal: every member commits to 32 random bytes
//! in round 1 and reveals them in round 2, and
//!
//!   sk = H("ZcashFROSTv0DkSk", T || ak || r_1 || r_2 || r_3)
//!
//! where `T` hashes the parameters and every round 1 message. Each round 2
//! carries `T` as its sender saw it, and members abort if it differs. The
//! coordinator reveals last, but committed before seeing anything revealed,
//! so nobody chooses `sk`. The keys then follow ZIP 2005 (`use_qsk`).
//!
//! With pairing, the exchange takes six QR streams: pair-init; pair-response;
//! pair-confirm with the coordinator's round 1; once the code is confirmed,
//! the co-signer's round 1 and round 2; the coordinator's round 2; and the
//! co-signer's acknowledgement, [`Done`], sent once member 3 is exported,
//! checked and deleted. The coordinator shows no address before it holds.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use frost::Identifier;
use frost::keys::dkg::{self, round1, round2};
use frost::keys::{KeyPackage, PublicKeyPackage};
use minicbor::{Decode, Encode};
use reddsa::frost::redpallas as frost;
use zcash_protocol::consensus::NetworkType;
use zeroize::{Zeroize, Zeroizing};

use crate::cosigning::Member;
use crate::{backup, keys, signing};

/// The version bound into the `sk` commitments and the transcript.
pub const VERSION: u8 = 0;
/// The threshold: any two members sign.
pub const MIN_SIGNERS: u16 = 2;
/// The group size.
pub const MAX_SIGNERS: u16 = 3;
/// Member 1, the coordinator.
pub const COORDINATOR: u16 = 1;
/// Member 2, the co-signer.
pub const COSIGNER: u16 = 2;
/// Member 3, the backup, created on the co-signer and exported.
pub const BACKUP: u16 = 3;

const PERSONAL_COMMIT: &[u8; 16] = b"ZcashFROSTv0SkCm";
const PERSONAL_TRANSCRIPT: &[u8; 16] = b"ZcashFROSTv0DkgT";
const PERSONAL_SK: &[u8; 16] = b"ZcashFROSTv0DkSk";
const PERSONAL_DONE: &[u8; 16] = b"ZcashFROSTv0Done";

fn identifier(member: u16) -> Identifier {
    Identifier::try_from(member).expect("1, 2 and 3 are valid identifiers")
}

fn network_byte(network: NetworkType) -> Result<u8, Box<dyn Error>> {
    match network {
        NetworkType::Main => Ok(0),
        NetworkType::Test => Ok(1),
        NetworkType::Regtest => Err("regtest is not supported".into()),
    }
}

fn hash(personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personal)
        .to_state();
    for part in parts {
        state.update(part);
    }
    state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("32-byte hash")
}

fn sk_commitment(member: u16, contribution: &[u8; 32]) -> [u8; 32] {
    hash(
        PERSONAL_COMMIT,
        &[&[VERSION], &member.to_le_bytes(), contribution],
    )
}

fn random32() -> [u8; 32] {
    rand::random()
}

/// The commitment to a member's contribution `r`, for test vectors.
#[doc(hidden)]
pub fn commitment_for_vectors(member: u16, contribution: &[u8; 32]) -> [u8; 32] {
    sk_commitment(member, contribution)
}

/// The transcript hash `T` over three round 1 entries, for test vectors.
#[doc(hidden)]
pub fn transcript_for_vectors(
    network: u8,
    entries: &[Round1Entry],
) -> Result<[u8; 32], Box<dyn Error>> {
    let mut transcript = Transcript::new(network);
    for entry in entries {
        transcript.add(entry)?;
    }
    transcript.hash()
}

/// `sk` from the transcript, `ak` and the contributions, for test vectors.
#[doc(hidden)]
pub fn sk_for_vectors(
    transcript: &[u8; 32],
    ak: &[u8; 32],
    contributions: &[[u8; 32]; 3],
) -> [u8; 32] {
    let contributions = BTreeMap::from([
        (COORDINATOR, contributions[0]),
        (COSIGNER, contributions[1]),
        (BACKUP, contributions[2]),
    ]);
    combine_sk(transcript, ak, &contributions)
}

/// One member's round 1: its DKG package and its commitment to `r`.
#[derive(Encode, Decode, Clone)]
#[cbor(map)]
pub struct Round1Entry {
    /// The member's identifier, 1 to 3.
    #[n(1)]
    pub member: u16,
    /// The serialized FROST DKG round 1 package.
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub package: Vec<u8>,
    /// `c_i`, the commitment to the member's contribution to `sk`.
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub sk_commitment: [u8; 32],
}

/// A device's round 1: one entry per member it plays.
#[derive(Encode, Decode, Clone)]
#[cbor(map)]
pub struct Round1 {
    /// 0 for mainnet, 1 for testnet; bound into the transcript.
    #[n(1)]
    pub network: u8,
    /// The entries of the members this device plays.
    #[n(2)]
    pub entries: Vec<Round1Entry>,
}

/// A DKG round 2 package from one member to another. It holds secrets: it
/// only ever travels sealed.
#[derive(Encode, Decode, Clone)]
#[cbor(map)]
pub struct Round2Entry {
    /// The sending member.
    #[n(1)]
    pub from: u16,
    /// The receiving member.
    #[n(2)]
    pub to: u16,
    /// The serialized FROST DKG round 2 package. Secret.
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub package: Vec<u8>,
}

impl Drop for Round2Entry {
    fn drop(&mut self) {
        self.package.zeroize();
    }
}

/// A member's contribution to `sk`, revealed in round 2. Secret until all
/// three are combined.
#[derive(Encode, Decode, Clone)]
#[cbor(map)]
pub struct Reveal {
    /// The member.
    #[n(1)]
    pub member: u16,
    /// `r_i`, which must open the member's round 1 commitment.
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub contribution: [u8; 32],
}

impl Drop for Reveal {
    fn drop(&mut self) {
        self.contribution.zeroize();
    }
}

/// A device's round 2. It holds secrets: it only ever travels sealed.
#[derive(Encode, Decode, Clone)]
#[cbor(map)]
pub struct Round2 {
    /// The round 2 packages this device sends.
    #[n(1)]
    pub packages: Vec<Round2Entry>,
    /// The contributions of the members this device plays.
    #[n(2)]
    pub reveals: Vec<Reveal>,
    /// The transcript hash `T` as the sender saw it.
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub echo: [u8; 32],
}

macro_rules! cbor_bytes {
    ($t:ty) => {
        impl $t {
            /// The CBOR encoding. Round 2 holds secrets, so the bytes are
            /// wiped when dropped.
            pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
                Zeroizing::new(minicbor::to_vec(self).expect("encoding to memory cannot fail"))
            }
            /// Reads the CBOR encoding.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
                Ok(minicbor::decode(bytes)?)
            }
        }
    };
}
cbor_bytes!(Round1);
cbor_bytes!(Round2);

/// What a member ends up with.
pub struct Group {
    /// The member, ready to sign.
    pub member: Member,
    /// `sk`, from which `nk`, `rivk` and `qsk` derive. Secret: ZIP 2005 asks
    /// to protect it like `ask`.
    pub sk: [u8; 32],
    /// The group's unified full viewing key, encoded.
    pub ufvk: String,
    /// The group's default unified address, which both devices show.
    pub address: String,
}

impl Group {
    fn new(
        key_package: KeyPackage,
        public_key_package: PublicKeyPackage,
        sk: [u8; 32],
        network: NetworkType,
    ) -> Result<Group, Box<dyn Error>> {
        let ak = signing::group_ak(&public_key_package)?;
        let fvk = keys::derive(&sk, &ak)?.fvk;
        Ok(Group {
            ufvk: keys::ufvk(&fvk, network)?,
            address: keys::address(&fvk, network)?,
            member: Member {
                key_package,
                public_key_package,
                fvk,
                network,
            },
            sk,
        })
    }

    /// The member backup string (zcash/zips#1432, version 1).
    pub fn backup_string(&self) -> Result<String, Box<dyn Error>> {
        backup::Backup::new(&self.member.key_package, MAX_SIGNERS, &self.sk)?.encode()
    }

    /// The digest of the group this member ended with: its parameters, the
    /// group key, every member's verifying share and the viewing key. Both
    /// devices compute it; the co-signer sends its own in [`Done`].
    pub fn digest(&self) -> Result<[u8; 32], Box<dyn Error>> {
        let pkp = &self.member.public_key_package;
        let mut members = Vec::new();
        for (id, share) in pkp.verifying_shares() {
            let id: [u8; 32] = id.serialize().try_into().map_err(|_| "identifier size")?;
            let share: [u8; 32] = share.serialize()?.try_into().map_err(|_| "share size")?;
            members.push((id, share));
        }
        done_digest(
            network_byte(self.member.network)?,
            *self.member.key_package.min_signers(),
            &signing::group_ak(pkp)?,
            &members,
            &self.ufvk,
        )
    }

    /// The co-signer's acknowledgement, once member 3 is exported, checked
    /// and deleted.
    pub fn done(&self) -> Result<Done, Box<dyn Error>> {
        Ok(Done {
            digest: self.digest()?,
        })
    }

    /// The coordinator's check of the co-signer's acknowledgement: until it
    /// holds, the coordinator shows no address to fund.
    pub fn check_done(&self, done: &Done) -> Result<(), Box<dyn Error>> {
        if done.digest != self.digest()? {
            return Err(
                "the co-signer ended key generation with a different group: \
                        do not use this account"
                    .into(),
            );
        }
        Ok(())
    }
}

/// `D` of spec § 4.1, from its parts: `members` holds each member's 32-byte
/// identifier and verifying share, in identifier order.
fn done_digest(
    network: u8,
    t: u16,
    ak: &[u8; 32],
    members: &[([u8; 32], [u8; 32])],
    ufvk: &str,
) -> Result<[u8; 32], Box<dyn Error>> {
    let n = u16::try_from(members.len())?;
    let shares: Vec<u8> = members
        .iter()
        .flat_map(|(id, share)| id.iter().chain(share).copied())
        .collect();
    let ufvk = ufvk.as_bytes();
    Ok(hash(
        PERSONAL_DONE,
        &[
            &[VERSION, network],
            &t.to_le_bytes(),
            &n.to_le_bytes(),
            ak,
            &shares,
            &u32::try_from(ufvk.len())?.to_le_bytes(),
            ufvk,
        ],
    ))
}

/// `D` for test vectors (spec § 4.1).
#[doc(hidden)]
pub fn done_digest_for_vectors(
    network: u8,
    t: u16,
    ak: &[u8; 32],
    members: &[([u8; 32], [u8; 32])],
    ufvk: &str,
) -> [u8; 32] {
    done_digest(network, t, ak, members, ufvk).expect("vector inputs fit")
}

/// Checks the backup string the co-signer exported for member 3 against the
/// group it ended with: the string must restore, under ZIP 2005, to member 3
/// of this very group. The co-signer runs it on what it actually wrote, then
/// deletes member 3, then acknowledges (spec § 4).
pub fn check_backup(text: &str, group: &Group) -> Result<(), Box<dyn Error>> {
    let restored = backup::restore(text.trim(), &group.ufvk)?;
    backup::check_member(&restored, &group.member.public_key_package)?;
    if *restored.key_package.identifier() != identifier(BACKUP) {
        return Err("the backup string is not member 3".into());
    }
    if restored.derivation != backup::Derivation::Zip2005 {
        return Err("the backup string does not follow ZIP 2005".into());
    }
    Ok(())
}

/// The co-signer's acknowledgement that key generation is done: the
/// [`Group::digest`] it computed, sealed under [`crate::wire::kind::DKG_DONE`].
#[derive(Encode, Decode, Clone)]
#[cbor(map)]
pub struct Done {
    /// The co-signer's digest of the group.
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pub digest: [u8; 32],
}

impl Done {
    /// The CBOR encoding.
    pub fn to_bytes(&self) -> Vec<u8> {
        minicbor::to_vec(self).expect("encoding to memory cannot fail")
    }
    /// Reads the CBOR encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        Ok(minicbor::decode(bytes)?)
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        self.sk.zeroize();
    }
}

/// Every member's round 1, in identifier order, and the hash of it all.
struct Transcript {
    network: u8,
    packages: BTreeMap<Identifier, round1::Package>,
    commitments: BTreeMap<u16, [u8; 32]>,
}

impl Transcript {
    fn new(network: u8) -> Self {
        Transcript {
            network,
            packages: BTreeMap::new(),
            commitments: BTreeMap::new(),
        }
    }

    fn add(&mut self, entry: &Round1Entry) -> Result<(), Box<dyn Error>> {
        if !(1..=MAX_SIGNERS).contains(&entry.member) {
            return Err(format!("round 1 from unknown member {}", entry.member).into());
        }
        let package = round1::Package::deserialize(&entry.package)?;
        if self
            .packages
            .insert(identifier(entry.member), package)
            .is_some()
        {
            return Err(format!("two round 1 messages from member {}", entry.member).into());
        }
        self.commitments.insert(entry.member, entry.sk_commitment);
        Ok(())
    }

    fn hash(&self) -> Result<[u8; 32], Box<dyn Error>> {
        let mut state = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(PERSONAL_TRANSCRIPT)
            .to_state();
        state.update(&[VERSION, self.network]);
        state.update(&MIN_SIGNERS.to_le_bytes());
        state.update(&MAX_SIGNERS.to_le_bytes());
        for member in 1..=MAX_SIGNERS {
            let package = self
                .packages
                .get(&identifier(member))
                .ok_or("a member's round 1 is missing")?
                .serialize()?;
            state.update(&member.to_le_bytes());
            state.update(&(package.len() as u32).to_le_bytes());
            state.update(&package);
            state.update(&self.commitments[&member]);
        }
        Ok(state
            .finalize()
            .as_bytes()
            .try_into()
            .expect("32-byte hash"))
    }

    fn others(&self, member: u16) -> BTreeMap<Identifier, round1::Package> {
        self.packages
            .iter()
            .filter(|(id, _)| **id != identifier(member))
            .map(|(id, package)| (*id, package.clone()))
            .collect()
    }

    /// Checks the revealed contributions against the commitments.
    fn check_reveals(&self, reveals: &[Reveal], expected: &[u16]) -> Result<(), Box<dyn Error>> {
        let members: BTreeSet<u16> = reveals.iter().map(|r| r.member).collect();
        if members.len() != reveals.len() || members != expected.iter().copied().collect() {
            return Err("round 2 reveals the wrong members' contributions".into());
        }
        for reveal in reveals {
            if sk_commitment(reveal.member, &reveal.contribution)
                != self.commitments[&reveal.member]
            {
                return Err(format!(
                    "member {}'s contribution to sk does not match its commitment",
                    reveal.member
                )
                .into());
            }
        }
        Ok(())
    }
}

fn combine_sk(
    transcript: &[u8; 32],
    ak: &[u8; 32],
    contributions: &BTreeMap<u16, [u8; 32]>,
) -> [u8; 32] {
    let mut parts: Vec<&[u8]> = vec![transcript, ak];
    for contribution in contributions.values() {
        parts.push(contribution);
    }
    hash(PERSONAL_SK, &parts)
}

/// Takes the round 2 packages addressed to `to` from `from` members, exactly.
fn packages_to(
    entries: &[Round2Entry],
    to: u16,
    from: &[u16],
) -> Result<BTreeMap<Identifier, round2::Package>, Box<dyn Error>> {
    let mut found = BTreeMap::new();
    for entry in entries.iter().filter(|e| e.to == to) {
        if !from.contains(&entry.from) {
            return Err(format!("unexpected round 2 package from member {}", entry.from).into());
        }
        if found
            .insert(
                identifier(entry.from),
                round2::Package::deserialize(&entry.package)?,
            )
            .is_some()
        {
            return Err("two round 2 packages from the same member".into());
        }
    }
    if found.len() != from.len() {
        return Err(format!("round 2 packages for member {to} are missing").into());
    }
    Ok(found)
}

/// The coordinator between its round 1 and the co-signer's answer.
pub struct CoordinatorSetup {
    network: NetworkType,
    secret: round1::SecretPackage,
    entry: Round1Entry,
    contribution: [u8; 32],
}

impl CoordinatorSetup {
    /// The coordinator's round 1, sent with pair-confirm.
    pub fn start(network: NetworkType) -> Result<(Self, Round1), Box<dyn Error>> {
        let network_byte = network_byte(network)?;
        let (secret, package) = dkg::part1(
            identifier(COORDINATOR),
            MAX_SIGNERS,
            MIN_SIGNERS,
            rand::thread_rng(),
        )?;
        let contribution = random32();
        let entry = Round1Entry {
            member: COORDINATOR,
            package: package.serialize()?,
            sk_commitment: sk_commitment(COORDINATOR, &contribution),
        };
        let round1 = Round1 {
            network: network_byte,
            entries: vec![entry.clone()],
        };
        Ok((
            CoordinatorSetup {
                network,
                secret,
                entry,
                contribution,
            },
            round1,
        ))
    }

    /// Takes the co-signer's round 1 and round 2; returns the coordinator's
    /// round 2 and its seat.
    pub fn finish(
        mut self,
        theirs1: &Round1,
        theirs2: &Round2,
    ) -> Result<(Round2, Group), Box<dyn Error>> {
        let network_byte = network_byte(self.network)?;
        if theirs1.network != network_byte {
            return Err("the co-signer set up the group for another network".into());
        }
        let members: BTreeSet<u16> = theirs1.entries.iter().map(|e| e.member).collect();
        if members != BTreeSet::from([COSIGNER, BACKUP]) || theirs1.entries.len() != 2 {
            return Err("the co-signer's round 1 must cover members 2 and 3, once each".into());
        }
        let mut transcript = Transcript::new(network_byte);
        transcript.add(&self.entry)?;
        for entry in &theirs1.entries {
            transcript.add(entry)?;
        }
        let t = transcript.hash()?;
        if theirs2.echo != t {
            return Err("the co-signer saw a different round 1: abort".into());
        }
        transcript.check_reveals(&theirs2.reveals, &[COSIGNER, BACKUP])?;
        let received = packages_to(&theirs2.packages, COORDINATOR, &[COSIGNER, BACKUP])?;
        if theirs2.packages.len() != 2 {
            return Err("the co-signer's round 2 must hold exactly two packages".into());
        }

        let others = transcript.others(COORDINATOR);
        let (round2_secret, outgoing) = dkg::part2(self.secret.clone(), &others)?;
        let (key_package, public_key_package) = dkg::part3(&round2_secret, &others, &received)?;

        let mut contributions: BTreeMap<u16, [u8; 32]> = theirs2
            .reveals
            .iter()
            .map(|r| (r.member, r.contribution))
            .collect();
        contributions.insert(COORDINATOR, self.contribution);
        let ak = signing::group_ak(&public_key_package)?;
        let sk = combine_sk(&t, &ak, &contributions);
        contributions.values_mut().for_each(Zeroize::zeroize);

        let mut packages = Vec::new();
        for (to, package) in outgoing {
            let to = if to == identifier(COSIGNER) {
                COSIGNER
            } else {
                BACKUP
            };
            packages.push(Round2Entry {
                from: COORDINATOR,
                to,
                package: package.serialize()?,
            });
        }
        let round2 = Round2 {
            packages,
            reveals: vec![Reveal {
                member: COORDINATOR,
                contribution: self.contribution,
            }],
            echo: t,
        };
        self.contribution.zeroize();
        let group = Group::new(key_package, public_key_package, sk, self.network)?;
        Ok((round2, group))
    }
}

struct Role {
    member: u16,
    secret: round2::SecretPackage,
    contribution: [u8; 32],
}

/// The co-signer between its answer and the coordinator's round 2.
pub struct CosignerSetup {
    network: NetworkType,
    transcript: Transcript,
    t: [u8; 32],
    roles: Vec<Role>,
    /// The packages members 2 and 3 send each other, which never leave the device.
    internal: Vec<Round2Entry>,
}

impl CosignerSetup {
    /// Takes the coordinator's round 1; returns this device's round 1 and round 2.
    /// Send them only once the user has confirmed the pairing code.
    pub fn respond(
        network: NetworkType,
        theirs1: &Round1,
    ) -> Result<(Self, Round1, Round2), Box<dyn Error>> {
        let network_byte = network_byte(network)?;
        if theirs1.network != network_byte {
            return Err("the coordinator set up the group for another network".into());
        }
        if theirs1.entries.len() != 1 || theirs1.entries[0].member != COORDINATOR {
            return Err("the coordinator's round 1 must be member 1's, alone".into());
        }
        let mut transcript = Transcript::new(network_byte);
        transcript.add(&theirs1.entries[0])?;

        let mut secrets = Vec::new();
        let mut entries = Vec::new();
        for member in [COSIGNER, BACKUP] {
            let (secret, package) = dkg::part1(
                identifier(member),
                MAX_SIGNERS,
                MIN_SIGNERS,
                rand::thread_rng(),
            )?;
            let contribution = random32();
            let entry = Round1Entry {
                member,
                package: package.serialize()?,
                sk_commitment: sk_commitment(member, &contribution),
            };
            transcript.add(&entry)?;
            entries.push(entry);
            secrets.push((member, secret, contribution));
        }
        let t = transcript.hash()?;

        let mut roles = Vec::new();
        let mut to_coordinator = Vec::new();
        let mut internal = Vec::new();
        let mut reveals = Vec::new();
        for (member, secret, contribution) in secrets {
            let (round2_secret, outgoing) = dkg::part2(secret, &transcript.others(member))?;
            for (to, package) in outgoing {
                let to = (1..=MAX_SIGNERS)
                    .find(|m| identifier(*m) == to)
                    .ok_or("unexpected recipient")?;
                let entry = Round2Entry {
                    from: member,
                    to,
                    package: package.serialize()?,
                };
                if to == COORDINATOR {
                    to_coordinator.push(entry);
                } else {
                    internal.push(entry);
                }
            }
            reveals.push(Reveal {
                member,
                contribution,
            });
            roles.push(Role {
                member,
                secret: round2_secret,
                contribution,
            });
        }
        let round1 = Round1 {
            network: network_byte,
            entries,
        };
        let round2 = Round2 {
            packages: to_coordinator,
            reveals,
            echo: t,
        };
        let setup = CosignerSetup {
            network,
            transcript,
            t,
            roles,
            internal,
        };
        Ok((setup, round1, round2))
    }

    /// Takes the coordinator's round 2; returns members 2 and 3.
    pub fn finish(self, theirs2: &Round2) -> Result<(Group, Group), Box<dyn Error>> {
        if theirs2.echo != self.t {
            return Err("the coordinator saw a different round 1: abort".into());
        }
        self.transcript
            .check_reveals(&theirs2.reveals, &[COORDINATOR])?;
        if theirs2.packages.len() != 2 || theirs2.packages.iter().any(|e| e.from != COORDINATOR) {
            return Err("the coordinator's round 2 must hold exactly its two packages".into());
        }
        let mut contributions: BTreeMap<u16, [u8; 32]> = self
            .roles
            .iter()
            .map(|r| (r.member, r.contribution))
            .collect();
        contributions.insert(COORDINATOR, theirs2.reveals[0].contribution);

        let mut all = theirs2.packages.clone();
        all.extend(self.internal.iter().cloned());
        let mut groups = Vec::new();
        let mut group_key = None;
        for role in &self.roles {
            let others_ids: Vec<u16> = (1..=MAX_SIGNERS).filter(|m| *m != role.member).collect();
            let received = packages_to(&all, role.member, &others_ids)?;
            let (key_package, public_key_package) = dkg::part3(
                &role.secret,
                &self.transcript.others(role.member),
                &received,
            )?;
            let ak = signing::group_ak(&public_key_package)?;
            if group_key.get_or_insert(ak) != &ak {
                return Err("members 2 and 3 derived different group keys".into());
            }
            let sk = combine_sk(&self.t, &ak, &contributions);
            groups.push(Group::new(
                key_package,
                public_key_package,
                sk,
                self.network,
            )?);
        }
        contributions.values_mut().for_each(Zeroize::zeroize);
        let backup = groups.pop().ok_or("member 3 missing")?;
        let cosigner = groups.pop().ok_or("member 2 missing")?;
        Ok((cosigner, backup))
    }
}

impl Drop for CosignerSetup {
    fn drop(&mut self) {
        for role in &mut self.roles {
            role.contribution.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run() -> (Group, Group, Group) {
        let (coordinator, c1) = CoordinatorSetup::start(NetworkType::Test).unwrap();
        let c1 = Round1::from_bytes(&c1.to_bytes()).unwrap();
        let (cosigner, s1, s2) = CosignerSetup::respond(NetworkType::Test, &c1).unwrap();
        let (s1, s2) = (
            Round1::from_bytes(&s1.to_bytes()).unwrap(),
            Round2::from_bytes(&s2.to_bytes()).unwrap(),
        );
        let (c2, one) = coordinator.finish(&s1, &s2).unwrap();
        let (two, three) = cosigner
            .finish(&Round2::from_bytes(&c2.to_bytes()).unwrap())
            .unwrap();
        (one, two, three)
    }

    #[test]
    fn both_devices_end_with_the_same_group_and_every_pair_signs() {
        let (one, two, three) = run();
        assert_eq!(one.address, two.address);
        assert_eq!(two.address, three.address);
        assert_eq!(one.ufvk, three.ufvk);
        assert_eq!(one.sk, two.sk);
        let members = [&one, &two, &three];
        for (a, b) in [(0, 1), (0, 2), (1, 2)] {
            let signers = BTreeMap::from([
                (
                    members[a].member.id(),
                    members[a].member.key_package.clone(),
                ),
                (
                    members[b].member.id(),
                    members[b].member.key_package.clone(),
                ),
            ]);
            signing::sign(
                &rand::random(),
                &signing::random_alpha(),
                &signers,
                &one.member.public_key_package,
            )
            .unwrap();
        }
        // The backup string restores member 3 against the group's viewing key.
        let restored = backup::restore(&three.backup_string().unwrap(), &three.ufvk).unwrap();
        drop(restored);
    }

    #[test]
    fn the_acknowledgement_and_the_backup_check() {
        let (one, two, three) = run();
        // Every member computes the same digest of the group.
        assert_eq!(one.digest().unwrap(), two.digest().unwrap());
        assert_eq!(two.digest().unwrap(), three.digest().unwrap());
        check_backup(&three.backup_string().unwrap(), &two).unwrap();
        // Surrounding whitespace, as an editor may add to a file, is fine.
        check_backup(&format!("{}\r\n", three.backup_string().unwrap()), &two).unwrap();
        let done = Done::from_bytes(&two.done().unwrap().to_bytes()).unwrap();
        one.check_done(&done).unwrap();
        let mut wrong = done.clone();
        wrong.digest[31] ^= 1;
        assert!(one.check_done(&wrong).is_err());
        // Member 2's string is not member 3's.
        let refused = check_backup(&two.backup_string().unwrap(), &two)
            .unwrap_err()
            .to_string();
        assert!(refused.contains("not member 3"), "{refused}");
        // Another group's acknowledgement and member 3 are refused.
        let (other, _, other_three) = run();
        assert!(other.check_done(&done).is_err());
        assert!(check_backup(&other_three.backup_string().unwrap(), &two).is_err());
    }

    #[test]
    fn a_different_view_of_round_1_or_a_wrong_reveal_aborts() {
        let (coordinator, c1) = CoordinatorSetup::start(NetworkType::Test).unwrap();
        let (_, s1, mut s2) = CosignerSetup::respond(NetworkType::Test, &c1).unwrap();
        s2.echo[0] ^= 1;
        let refused = coordinator.finish(&s1, &s2).err().unwrap().to_string();
        assert!(refused.contains("different round 1"), "{refused}");

        let (coordinator, c1) = CoordinatorSetup::start(NetworkType::Test).unwrap();
        let (_, s1, mut s2) = CosignerSetup::respond(NetworkType::Test, &c1).unwrap();
        s2.reveals[0].contribution[0] ^= 1;
        let refused = coordinator.finish(&s1, &s2).err().unwrap().to_string();
        assert!(
            refused.contains("does not match its commitment"),
            "{refused}"
        );

        let (coordinator, c1) = CoordinatorSetup::start(NetworkType::Test).unwrap();
        let (cosigner, s1, s2) = CosignerSetup::respond(NetworkType::Test, &c1).unwrap();
        let (mut c2, _) = coordinator.finish(&s1, &s2).unwrap();
        c2.reveals[0].contribution[0] ^= 1;
        let refused = cosigner.finish(&c2).err().unwrap().to_string();
        assert!(
            refused.contains("does not match its commitment"),
            "{refused}"
        );
    }

    #[test]
    fn wrong_networks_and_members_are_refused() {
        let (_, c1) = CoordinatorSetup::start(NetworkType::Main).unwrap();
        assert!(CosignerSetup::respond(NetworkType::Test, &c1).is_err());

        let (_, mut c1) = CoordinatorSetup::start(NetworkType::Test).unwrap();
        c1.entries[0].member = 2;
        assert!(CosignerSetup::respond(NetworkType::Test, &c1).is_err());

        let (coordinator, c1) = CoordinatorSetup::start(NetworkType::Test).unwrap();
        let (_, mut s1, s2) = CosignerSetup::respond(NetworkType::Test, &c1).unwrap();
        s1.entries.pop();
        let refused = coordinator.finish(&s1, &s2).err().unwrap().to_string();
        assert!(refused.contains("members 2 and 3"), "{refused}");
    }
}
