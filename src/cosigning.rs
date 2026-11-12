//! A signing session between the coordinator and a co-signer (docs/spec.md § 5),
//! independent of how the messages travel. Two messages:
//!
//! 1. The coordinator sends the PCZT and one fresh commitment per spend, under
//!    a session id it chose. It keeps its nonces in memory.
//! 2. The co-signer checks the PCZT on its own, draws its nonces only then,
//!    builds the commitment list itself and computes its shares. Its
//!    commitments and shares leave the device only if the user approves; its
//!    nonces are erased either way.
//!
//! The coordinator then signs its part, aggregates and checks every signature
//! under its spend's `rk`.
//!
//! Why this order is safe (spec § 5): every binding factor hashes the group
//! key, the message and the whole commitment list (RFC 9591 § 4.4). The
//! co-signer commits last, after the PCZT, the randomizers and the
//! coordinator's commitments are fixed, and answers at once, so it never has a
//! commitment waiting for a dishonest coordinator to adapt to. The coordinator
//! is the side that commits first, which is the case binding factors are for.
//!
//! The types enforce the rules that matter:
//! - the co-signer builds the commitment list from its own commitment and the
//!   coordinator's, and refuses a request naming its own identifier or a
//!   stranger;
//! - nonces never leave memory, and the co-signer's are dropped (and wiped)
//!   before the user is even asked;
//! - a coordinator session accepts one reply, because finishing consumes it
//!   and its nonces: two replies with different co-signer commitments against
//!   the same coordinator nonces could give away the coordinator's share
//!   (RFC 9591 § 7.3);
//! - nothing is signed on the coordinator's word, since the sighash and the
//!   randomizers come from the PCZT the co-signer checked itself.

use std::collections::{BTreeMap, BTreeSet};
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

/// One session covers at most this many spends.
pub const MAX_SPENDS: usize = 4;
/// Size of a signing session id, chosen at random by the coordinator.
pub const SESSION_ID_SIZE: usize = 16;

/// What a member needs to sign: its key package, the group's public keys,
/// and the group's full viewing key for the checks.
#[derive(Clone)]
pub struct Member {
    /// This member's identifier, signing share and verifying share. Secret.
    pub key_package: KeyPackage,
    /// The group key and every member's verifying share.
    pub public_key_package: PublicKeyPackage,
    /// The group's full viewing key, used to check every PCZT.
    pub fvk: FullViewingKey,
    /// The network the group's addresses are on.
    pub network: NetworkType,
}

impl Member {
    /// This member's FROST identifier.
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

/// Message 1, coordinator → co-signer.
#[derive(Clone)]
pub struct Request {
    /// The session, chosen at random by the coordinator.
    pub session: [u8; SESSION_ID_SIZE],
    /// The coordinator's identifier.
    pub member: Identifier,
    /// The PCZT, unproven: a v6 signature covers neither proofs nor anchors.
    pub pczt: Vec<u8>,
    /// The coordinator's fresh commitment for each spend, in bundle order.
    pub commitments: Vec<SigningCommitments>,
}

/// Message 2, co-signer → coordinator.
#[derive(Clone)]
pub enum Reply {
    /// The user approved: the co-signer's commitment and share for each spend.
    Shares {
        /// The session of the request.
        session: [u8; SESSION_ID_SIZE],
        /// The co-signer's identifier.
        member: Identifier,
        /// One commitment per spend, in bundle order.
        commitments: Vec<SigningCommitments>,
        /// One share per spend, in bundle order.
        shares: Vec<SignatureShare>,
    },
    /// The co-signer refused, before or after showing the transaction.
    Refused {
        /// The session of the request.
        session: [u8; SESSION_ID_SIZE],
        /// The co-signer's identifier.
        member: Identifier,
        /// Why, already made safe to show (at most 1,000 characters).
        reason: String,
    },
}

/// A request the co-signer checked, waiting for the user. The commitments and
/// shares are computed but not released; the nonces behind them are already
/// gone.
pub struct PendingApproval {
    session: [u8; SESSION_ID_SIZE],
    member: Identifier,
    report: Report,
    commitments: Vec<SigningCommitments>,
    shares: Vec<SignatureShare>,
}

/// The co-signer's side of message 1: checks the request and, if it holds,
/// prepares the reply for the user to approve. On refusal, returns the reply
/// to send. The co-signer keeps no state between requests: each request gets
/// fresh nonces, used once here and dropped before this returns.
pub fn review(member: &Member, request: &Request) -> Result<PendingApproval, Reply> {
    match review_inner(member, request) {
        Ok((report, commitments, shares)) => Ok(PendingApproval {
            session: request.session,
            member: member.id(),
            report,
            commitments,
            shares,
        }),
        Err(error) => Err(Reply::Refused {
            session: request.session,
            member: member.id(),
            reason: error.to_string(),
        }),
    }
}

type Prepared = (Report, Vec<SigningCommitments>, Vec<SignatureShare>);

fn review_inner(member: &Member, request: &Request) -> Result<Prepared, Box<dyn Error>> {
    member.check_other(&request.member)?;
    let pczt = pczt_io::parse(&request.pczt)?;
    let report = check::analyze(&pczt, &member.fvk, member.network)?;
    // The sighash and the randomizers come from the PCZT checked above,
    // never from the coordinator.
    let sighash = pczt_io::sighash(&pczt)?;
    let spends = pczt_io::spends_to_sign(&pczt)?;
    if spends.len() > MAX_SPENDS || request.commitments.len() != spends.len() {
        return Err("the number of spends and commitments do not match".into());
    }
    // A coordinator that repeats a commitment reuses its nonces, which would
    // give away its own share: refuse rather than take part.
    let distinct: BTreeSet<Vec<u8>> = request
        .commitments
        .iter()
        .map(|c| c.serialize())
        .collect::<Result<_, _>>()?;
    if distinct.len() != request.commitments.len() {
        return Err("the coordinator repeats a commitment".into());
    }
    let me = member.id();
    let mut commitments = Vec::with_capacity(spends.len());
    let mut shares = Vec::with_capacity(spends.len());
    for (i, spend) in spends.iter().enumerate() {
        // Drawn only now, once everything they will sign is fixed.
        let (nonces, mine) = signing::commit(&member.key_package);
        // The co-signer builds the list itself: exactly the coordinator and
        // this member, so its own commitment is in it by construction.
        let list = BTreeMap::from([(request.member, request.commitments[i]), (me, mine)]);
        let share = signing::share(&sighash, &spend.alpha, &list, &nonces, &member.key_package)?;
        drop::<SigningNonces>(nonces);
        commitments.push(mine);
        shares.push(share);
    }
    Ok((report, commitments, shares))
}

impl PendingApproval {
    /// What to show the user: built only from the co-signer's own checks.
    pub fn report(&self) -> &Report {
        &self.report
    }

    /// Message 2, once the user approved.
    pub fn approve(self) -> Reply {
        Reply::Shares {
            session: self.session,
            member: self.member,
            commitments: self.commitments,
            shares: self.shares,
        }
    }

    /// Message 2, when the user declined. The commitments and shares are
    /// dropped unsent.
    pub fn decline(self) -> Reply {
        Reply::Refused {
            session: self.session,
            member: self.member,
            reason: "declined on the co-signing device".into(),
        }
    }
}

/// The coordinator between messages 1 and 2. It owns a copy of the member and
/// its nonces, so an app can keep the session between two scans. Finishing
/// consumes it: one reply per set of nonces.
pub struct CoordinatorSession {
    member: Member,
    session: [u8; SESSION_ID_SIZE],
    pczt: Pczt,
    sighash: [u8; 32],
    spends: Vec<pczt_io::SpendToSign>,
    nonces: Vec<SigningNonces>,
    commitments: Vec<SigningCommitments>,
}

impl CoordinatorSession {
    /// Message 1: checks the PCZT too (whatever built it is not trusted to
    /// have built what the user asked for), then commits to fresh nonces for
    /// each spend. A new request, even for the same transaction, opens a new
    /// session with new nonces.
    pub fn request<R: CryptoRng + ?Sized>(
        member: &Member,
        pczt_bytes: &[u8],
        rng: &mut R,
    ) -> Result<(Self, Request, Report), Box<dyn Error>> {
        let pczt = pczt_io::parse(pczt_bytes)?;
        let report = check::analyze(&pczt, &member.fvk, member.network)?;
        let sighash = pczt_io::sighash(&pczt)?;
        let spends = pczt_io::spends_to_sign(&pczt)?;
        if spends.len() > MAX_SPENDS {
            return Err(format!("more than {MAX_SPENDS} spends in one transaction").into());
        }
        let mut session = [0u8; SESSION_ID_SIZE];
        rng.fill_bytes(&mut session);
        let (nonces, commitments): (Vec<_>, Vec<_>) = spends
            .iter()
            .map(|_| signing::commit(&member.key_package))
            .unzip();
        let request = Request {
            session,
            member: member.id(),
            pczt: pczt_bytes.to_vec(),
            commitments: commitments.clone(),
        };
        let coordinator = CoordinatorSession {
            member: member.clone(),
            session,
            pczt,
            sighash,
            spends,
            nonces,
            commitments,
        };
        Ok((coordinator, request, report))
    }

    /// The session id this coordinator chose.
    pub fn session(&self) -> [u8; SESSION_ID_SIZE] {
        self.session
    }

    /// Message 2: signs this member's part over the co-signer's commitments,
    /// aggregates, checks each signature under its rk, and returns the signed
    /// PCZT, ready to prove and broadcast. Consumes the session and its
    /// nonces, whatever the reply.
    pub fn finish(self, reply: &Reply) -> Result<Pczt, Box<dyn Error>> {
        let (other, their_commitments, their_shares) = match reply {
            Reply::Refused {
                session, reason, ..
            } if *session == self.session => {
                return Err(format!("the co-signer refused: {reason}").into());
            }
            Reply::Shares {
                session,
                member,
                commitments,
                shares,
            } if *session == self.session => (*member, commitments, shares),
            _ => return Err("the reply belongs to another session".into()),
        };
        self.member.check_other(&other)?;
        if their_commitments.len() != self.spends.len() || their_shares.len() != self.spends.len() {
            return Err("the co-signer returned the wrong number of commitments or shares".into());
        }
        let me = self.member.id();
        let mut signatures = Vec::with_capacity(self.spends.len());
        for (i, spend) in self.spends.iter().enumerate() {
            let list = BTreeMap::from([(me, self.commitments[i]), (other, their_commitments[i])]);
            let mine = signing::share(
                &self.sighash,
                &spend.alpha,
                &list,
                &self.nonces[i],
                &self.member.key_package,
            )?;
            let shares = BTreeMap::from([(me, mine), (other, their_shares[i])]);
            let signature = signing::aggregate(
                &self.sighash,
                &spend.alpha,
                &list,
                &shares,
                &self.member.public_key_package,
            )
            .map_err(|_| "the co-signer's signature share does not verify")?;
            signatures.push((spend.index, signature));
        }
        pczt_io::apply(self.pczt, &self.sighash, &signatures)
    }
}

// The two messages on the wire (CBOR maps, sealed under the pairing).

use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};

/// The longest refusal reason a co-signer may send back.
const MAX_REASON: usize = 1000;

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
    commitments: Option<Vec<ByteVec>>,
    #[n(4)]
    shares: Option<Vec<ByteVec>>,
    #[n(5)]
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

impl Request {
    /// The CBOR encoding sealed under [`crate::wire::kind::SIGN_REQUEST`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        Ok(to_cbor(&RequestWire {
            session: self.session,
            member: self.member.serialize(),
            pczt: self.pczt.clone(),
            commitments: commitments_out(&self.commitments)?,
        }))
    }

    /// Reads a [`Request`]; at most [`MAX_SPENDS`] commitments.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let wire: RequestWire = minicbor::decode(bytes)?;
        Ok(Request {
            session: wire.session,
            member: Identifier::deserialize(&wire.member)?,
            pczt: wire.pczt,
            commitments: commitments_in(&wire.commitments)?,
        })
    }
}

impl Reply {
    /// The session this reply answers.
    pub fn session(&self) -> [u8; SESSION_ID_SIZE] {
        match self {
            Reply::Shares { session, .. } | Reply::Refused { session, .. } => *session,
        }
    }

    /// The CBOR encoding sealed under [`crate::wire::kind::SIGN_REPLY`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let wire = match self {
            Reply::Shares {
                session,
                member,
                commitments,
                shares,
            } => ReplyWire {
                session: *session,
                member: member.serialize(),
                commitments: Some(commitments_out(commitments)?),
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
                commitments: None,
                shares: None,
                refused: Some(reason.chars().take(MAX_REASON).collect()),
            },
        };
        Ok(to_cbor(&wire))
    }

    /// Reads a [`Reply`]; a refusal's reason is shortened and made safe to show.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn Error>> {
        let wire: ReplyWire = minicbor::decode(bytes)?;
        let member = Identifier::deserialize(&wire.member)?;
        match (wire.commitments, wire.shares, wire.refused) {
            (Some(commitments), Some(shares), None) => Ok(Reply::Shares {
                session: wire.session,
                member,
                commitments: commitments_in(&commitments)?,
                shares: shares_in(&shares)?,
            }),
            (None, None, Some(reason)) => Ok(Reply::Refused {
                session: wire.session,
                member,
                // Shown to the user: keep it short and free of control characters.
                reason: crate::check::printable(
                    &reason.chars().take(MAX_REASON).collect::<String>(),
                ),
            }),
            _ => Err("a reply holds either commitments and shares, or a refusal".into()),
        }
    }
}
