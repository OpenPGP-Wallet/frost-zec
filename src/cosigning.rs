//! A signing session between the coordinator and a co-signer (docs/spec.md § 5),
//! independent of how the messages travel.
//!
//! 1. The co-signer opens the session with fresh commitments, before it sees
//!    the transaction.
//! 2. The coordinator answers with the PCZT, its own commitments and its
//!    signature shares.
//! 3. The co-signer checks the PCZT on its own, computes its shares, aggregates
//!    them with the coordinator's and verifies the final signatures, and only
//!    then asks the user. Its shares leave the device only if the user
//!    approves.
//!
//! The types enforce the rules that matter: a co-signer session answers at
//! most one request, because reviewing it consumes the session and its
//! nonces; nonces never leave memory; and nothing is signed on the
//! coordinator's word, since the sighash and the randomizers come from the
//! PCZT the co-signer checked itself.

use std::collections::BTreeMap;
use std::error::Error;

use frost::Identifier;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::{SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use orchard::keys::FullViewingKey;
use pczt::Pczt;
use rand10::rand_core::CryptoRng;
use reddsa::frost::redpallas as frost;
use zcash_protocol::consensus::NetworkType;

use crate::check::{self, Report};
use crate::{pczt_io, signing};

/// One session covers at most this many spends: the co-signer commits to this
/// many nonces up front.
pub const MAX_SPENDS: usize = 4;
pub const SESSION_ID_SIZE: usize = 16;

/// What a member needs to sign: its key package, the group's public keys,
/// and the group's full viewing key for the checks.
pub struct Member {
    pub key_package: KeyPackage,
    pub public_key_package: PublicKeyPackage,
    pub fvk: FullViewingKey,
    pub network: NetworkType,
}

impl Member {
    pub fn id(&self) -> Identifier {
        *self.key_package.identifier()
    }

    /// The other signer must be another member of this group.
    fn check_other(&self, other: &Identifier) -> Result<(), Box<dyn Error>> {
        if *other == self.id() {
            return Err("the other signer claims this member's own identifier".into());
        }
        if !self
            .public_key_package
            .verifying_shares()
            .contains_key(other)
        {
            return Err("the other signer is not a member of this group".into());
        }
        Ok(())
    }
}

/// Message 1, co-signer → coordinator.
#[derive(Clone)]
pub struct Commitments {
    pub session: [u8; SESSION_ID_SIZE],
    pub member: Identifier,
    pub commitments: Vec<SigningCommitments>,
}

/// Message 2, coordinator → co-signer.
#[derive(Clone)]
pub struct Request {
    pub session: [u8; SESSION_ID_SIZE],
    pub member: Identifier,
    /// The PCZT, unproven: a v6 signature covers neither proofs nor anchors.
    pub pczt: Vec<u8>,
    /// The coordinator's commitment for each spend, in bundle order.
    pub commitments: Vec<SigningCommitments>,
    /// The coordinator's signature share for each spend.
    pub shares: Vec<SignatureShare>,
}

/// Message 3, co-signer → coordinator.
#[derive(Clone)]
pub enum Reply {
    Shares {
        session: [u8; SESSION_ID_SIZE],
        member: Identifier,
        shares: Vec<SignatureShare>,
    },
    Refused {
        session: [u8; SESSION_ID_SIZE],
        member: Identifier,
        reason: String,
    },
}

/// The co-signer between messages 1 and 2. Its nonces live only here.
pub struct CosignerSession<'a> {
    member: &'a Member,
    session: [u8; SESSION_ID_SIZE],
    nonces: Vec<SigningNonces>,
    commitments: Vec<SigningCommitments>,
}

/// A request the co-signer checked, waiting for the user. The shares are
/// computed but not released.
pub struct PendingApproval {
    session: [u8; SESSION_ID_SIZE],
    member: Identifier,
    report: Report,
    shares: Vec<SignatureShare>,
}

impl<'a> CosignerSession<'a> {
    /// Message 1: fresh nonces for up to [`MAX_SPENDS`] spends.
    pub fn open<R: CryptoRng + ?Sized>(member: &'a Member, rng: &mut R) -> (Self, Commitments) {
        let mut session = [0u8; SESSION_ID_SIZE];
        rng.fill_bytes(&mut session);
        let (nonces, commitments): (Vec<_>, Vec<_>) = (0..MAX_SPENDS)
            .map(|_| signing::commit(&member.key_package))
            .unzip();
        let message = Commitments {
            session,
            member: member.id(),
            commitments: commitments.clone(),
        };
        let cosigner = CosignerSession {
            member,
            session,
            nonces,
            commitments,
        };
        (cosigner, message)
    }

    /// Checks message 2. Consumes the session: whatever happens, its nonces
    /// are never used again. On refusal, returns the reply to send.
    pub fn review(self, request: &Request) -> Result<PendingApproval, Reply> {
        let refuse = |reason: String| Reply::Refused {
            session: self.session,
            member: self.member.id(),
            reason,
        };
        match self.review_inner(request) {
            Ok((report, shares)) => Ok(PendingApproval {
                session: self.session,
                member: self.member.id(),
                report,
                shares,
            }),
            Err(error) => Err(refuse(error.to_string())),
        }
    }

    fn review_inner(
        &self,
        request: &Request,
    ) -> Result<(Report, Vec<SignatureShare>), Box<dyn Error>> {
        if request.session != self.session {
            return Err("the request belongs to another session".into());
        }
        self.member.check_other(&request.member)?;
        let pczt = pczt_io::parse(&request.pczt)?;
        let report = check::analyze(&pczt, &self.member.fvk, self.member.network)?;
        // The sighash and the randomizers come from the PCZT checked above,
        // never from the coordinator.
        let sighash = pczt_io::sighash(&pczt)?;
        let spends = pczt_io::spends_to_sign(&pczt)?;
        if spends.len() > self.nonces.len()
            || request.commitments.len() != spends.len()
            || request.shares.len() != spends.len()
        {
            return Err("the number of spends, commitments and shares do not match".into());
        }
        let me = self.member.id();
        let mut shares = Vec::with_capacity(spends.len());
        for (i, spend) in spends.iter().enumerate() {
            let commitments = BTreeMap::from([
                (request.member, request.commitments[i]),
                (me, self.commitments[i]),
            ]);
            let share = signing::share(
                &sighash,
                &spend.alpha,
                &commitments,
                &self.nonces[i],
                &self.member.key_package,
            )?;
            // The coordinator's share, with this one, must give a signature
            // that verifies under the spend's rk. Otherwise the coordinator
            // sent a bad share, or signed something else.
            let both = BTreeMap::from([(request.member, request.shares[i]), (me, share)]);
            signing::aggregate(
                &sighash,
                &spend.alpha,
                &commitments,
                &both,
                &self.member.public_key_package,
            )
            .map_err(|_| "the coordinator's signature share does not verify")?;
            shares.push(share);
        }
        Ok((report, shares))
    }
}

impl PendingApproval {
    /// What to show the user: built only from the co-signer's own checks.
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// Message 3, once the user approved.
    pub fn approve(self) -> Reply {
        Reply::Shares {
            session: self.session,
            member: self.member,
            shares: self.shares,
        }
    }

    /// Message 3, when the user declined. The shares are dropped unsent.
    pub fn decline(self) -> Reply {
        Reply::Refused {
            session: self.session,
            member: self.member,
            reason: "declined on the co-signing device".into(),
        }
    }
}

/// The coordinator between messages 2 and 3.
pub struct CoordinatorSession<'a> {
    member: &'a Member,
    session: [u8; SESSION_ID_SIZE],
    other: Identifier,
    pczt: Pczt,
    sighash: [u8; 32],
    spends: Vec<pczt_io::SpendToSign>,
    commitments: Vec<BTreeMap<Identifier, SigningCommitments>>,
    shares: Vec<SignatureShare>,
}

impl<'a> CoordinatorSession<'a> {
    /// Message 2: checks the PCZT too (whatever built it is not trusted to
    /// have built what the user asked for), then signs its part.
    pub fn request(
        member: &'a Member,
        pczt_bytes: &[u8],
        theirs: &Commitments,
    ) -> Result<(Self, Request, Report), Box<dyn Error>> {
        member.check_other(&theirs.member)?;
        let pczt = pczt_io::parse(pczt_bytes)?;
        let report = check::analyze(&pczt, &member.fvk, member.network)?;
        let sighash = pczt_io::sighash(&pczt)?;
        let spends = pczt_io::spends_to_sign(&pczt)?;
        if spends.len() > MAX_SPENDS || spends.len() > theirs.commitments.len() {
            return Err("more spends than the co-signer has commitments for".into());
        }
        let me = member.id();
        let mut all_commitments = Vec::with_capacity(spends.len());
        let mut my_commitments = Vec::with_capacity(spends.len());
        let mut shares = Vec::with_capacity(spends.len());
        for (i, spend) in spends.iter().enumerate() {
            // Fresh nonces, used once, right away, then dropped.
            let (nonces, mine) = signing::commit(&member.key_package);
            let commitments = BTreeMap::from([(me, mine), (theirs.member, theirs.commitments[i])]);
            shares.push(signing::share(
                &sighash,
                &spend.alpha,
                &commitments,
                &nonces,
                &member.key_package,
            )?);
            my_commitments.push(mine);
            all_commitments.push(commitments);
        }
        let request = Request {
            session: theirs.session,
            member: me,
            pczt: pczt_bytes.to_vec(),
            commitments: my_commitments,
            shares: shares.clone(),
        };
        let coordinator = CoordinatorSession {
            member,
            session: theirs.session,
            other: theirs.member,
            pczt,
            sighash,
            spends,
            commitments: all_commitments,
            shares,
        };
        Ok((coordinator, request, report))
    }

    /// Message 3: aggregates, checks each signature under its rk, and returns
    /// the signed PCZT, ready to prove and broadcast.
    pub fn finish(self, reply: &Reply) -> Result<Pczt, Box<dyn Error>> {
        let their_shares = match reply {
            Reply::Refused {
                session,
                member,
                reason,
            } if *session == self.session && *member == self.other => {
                return Err(format!("the co-signer refused: {reason}").into());
            }
            Reply::Shares {
                session,
                member,
                shares,
            } if *session == self.session && *member == self.other => shares,
            _ => return Err("the reply belongs to another session or member".into()),
        };
        if their_shares.len() != self.spends.len() {
            return Err("the co-signer returned the wrong number of shares".into());
        }
        let me = self.member.id();
        let mut signatures = Vec::with_capacity(self.spends.len());
        for (i, spend) in self.spends.iter().enumerate() {
            let shares = BTreeMap::from([(me, self.shares[i]), (self.other, their_shares[i])]);
            let signature = signing::aggregate(
                &self.sighash,
                &spend.alpha,
                &self.commitments[i],
                &shares,
                &self.member.public_key_package,
            )?;
            signatures.push((spend.index, signature));
        }
        pczt_io::apply(self.pczt, &self.sighash, &signatures)
    }
}

// The three messages on the wire (CBOR maps, sealed under the pairing).

use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};

/// The longest refusal reason a co-signer may send back.
const MAX_REASON: usize = 1000;

#[derive(Encode, Decode)]
#[cbor(map)]
struct CommitmentsWire {
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    session: [u8; SESSION_ID_SIZE],
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    member: Vec<u8>,
    #[n(3)]
    commitments: Vec<ByteVec>,
}

#[derive(Encode, Decode)]
#[cbor(map)]
struct RequestWire {
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    session: [u8; SESSION_ID_SIZE],
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    member: Vec<u8>,
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pczt: Vec<u8>,
    #[n(4)]
    commitments: Vec<ByteVec>,
    #[n(5)]
    shares: Vec<ByteVec>,
}

#[derive(Encode, Decode)]
#[cbor(map)]
struct ReplyWire {
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    session: [u8; SESSION_ID_SIZE],
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    member: Vec<u8>,
    #[n(3)]
    shares: Option<Vec<ByteVec>>,
    #[n(4)]
    refused: Option<String>,
}

fn to_cbor<T: Encode<()>>(value: &T) -> Vec<u8> {
    minicbor::to_vec(value).expect("encoding to memory cannot fail")
}

fn bounded(count: usize) -> Result<(), Box<dyn Error>> {
    if count > MAX_SPENDS {
        return Err(format!("more than {MAX_SPENDS} commitments or shares").into());
    }
    Ok(())
}

fn commitments_out(list: &[SigningCommitments]) -> Result<Vec<ByteVec>, Box<dyn Error>> {
    list.iter()
        .map(|c| Ok(ByteVec::from(c.serialize()?)))
        .collect()
}

fn commitments_in(list: &[ByteVec]) -> Result<Vec<SigningCommitments>, Box<dyn Error>> {
    bounded(list.len())?;
    list.iter()
        .map(|c| Ok(SigningCommitments::deserialize(c)?))
        .collect()
}

fn shares_out(list: &[SignatureShare]) -> Vec<ByteVec> {
    list.iter().map(|s| ByteVec::from(s.serialize())).collect()
}

fn shares_in(list: &[ByteVec]) -> Result<Vec<SignatureShare>, Box<dyn Error>> {
    bounded(list.len())?;
    list.iter()
        .map(|s| Ok(SignatureShare::deserialize(s)?))
        .collect()
}

impl Commitments {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(to_cbor(&CommitmentsWire {
            session: self.session,
            member: self.member.serialize(),
            commitments: commitments_out(&self.commitments)?,
        }))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let wire: CommitmentsWire = minicbor::decode(bytes)?;
        Ok(Commitments {
            session: wire.session,
            member: Identifier::deserialize(&wire.member)?,
            commitments: commitments_in(&wire.commitments)?,
        })
    }
}

impl Request {
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(to_cbor(&RequestWire {
            session: self.session,
            member: self.member.serialize(),
            pczt: self.pczt.clone(),
            commitments: commitments_out(&self.commitments)?,
            shares: shares_out(&self.shares),
        }))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let wire: RequestWire = minicbor::decode(bytes)?;
        Ok(Request {
            session: wire.session,
            member: Identifier::deserialize(&wire.member)?,
            pczt: wire.pczt,
            commitments: commitments_in(&wire.commitments)?,
            shares: shares_in(&wire.shares)?,
        })
    }
}

impl Reply {
    pub fn session(&self) -> [u8; SESSION_ID_SIZE] {
        match self {
            Reply::Shares { session, .. } | Reply::Refused { session, .. } => *session,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let wire = match self {
            Reply::Shares {
                session,
                member,
                shares,
            } => ReplyWire {
                session: *session,
                member: member.serialize(),
                shares: Some(shares_out(shares)),
                refused: None,
            },
            Reply::Refused {
                session,
                member,
                reason,
            } => ReplyWire {
                session: *session,
                member: member.serialize(),
                shares: None,
                refused: Some(reason.chars().take(MAX_REASON).collect()),
            },
        };
        to_cbor(&wire)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let wire: ReplyWire = minicbor::decode(bytes)?;
        let member = Identifier::deserialize(&wire.member)?;
        match (wire.shares, wire.refused) {
            (Some(shares), None) => Ok(Reply::Shares {
                session: wire.session,
                member,
                shares: shares_in(&shares)?,
            }),
            (None, Some(reason)) => Ok(Reply::Refused {
                session: wire.session,
                member,
                // Shown to the user: keep it short and free of control characters.
                reason: reason
                    .chars()
                    .take(MAX_REASON)
                    .collect::<String>()
                    .escape_debug()
                    .to_string(),
            }),
            _ => Err("a reply holds either shares or a refusal".into()),
        }
    }
}
