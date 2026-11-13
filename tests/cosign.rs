//! The signing session (src/cosigning.rs) with a real 2-of-3 FROST group:
//! the honest path, and every way a message can be wrong.

mod common;

use common::*;
use frost_zec::cosigning::{self, CoordinatorSession, Member, Reply, Request};
use frost_zec::{dkg, keys, pczt_io, signing};
use rand10::rand_core::UnwrapErr;
use rand10::rngs::SysRng;
use reddsa::frost::redpallas::Identifier;
use zcash_protocol::consensus::NetworkType;
use zcash_protocol::memo::MemoBytes;

/// Members 1 (coordinator), 2 (co-signer) and 3 (backup) of a fresh group,
/// with ZIP 2005 keys derived from a random `sk`.
fn group() -> Vec<Member> {
    let (key_packages, public_key_package) = dkg::run(3, 2).unwrap();
    let ak = signing::group_ak(&public_key_package).unwrap();
    let sk: [u8; 32] = rand::random();
    let fvk = keys::derive(&sk, &ak).unwrap().fvk;
    key_packages
        .into_values()
        .map(|key_package| Member {
            key_package,
            public_key_package: public_key_package.clone(),
            fvk: fvk.clone(),
            network: NetworkType::Main,
        })
        .collect()
}

fn payment(members: &[Member]) -> Vec<u8> {
    let pczt = build(&members[0].fvk, honest(&members[0].fvk, text_memo("rent")));
    pczt_io::serialize(pczt).unwrap()
}

fn refusal(reply: Reply) -> String {
    match reply {
        Reply::Refused { reason, .. } => reason,
        Reply::Shares { .. } => panic!("expected a refusal"),
    }
}

fn new_request(members: &[Member], pczt: &[u8]) -> (CoordinatorSession, Request) {
    let (coordinating, request, _) =
        CoordinatorSession::request(&members[0], pczt, &mut UnwrapErr(SysRng)).unwrap();
    (coordinating, request)
}

#[test]
fn any_two_members_sign_and_the_signatures_are_inserted() {
    let members = group();
    let pczt = payment(&members);
    for (coordinator, cosigner) in [(0, 1), (0, 2), (1, 2)] {
        let (coordinating, request, _) =
            CoordinatorSession::request(&members[coordinator], &pczt, &mut UnwrapErr(SysRng))
                .unwrap();
        let pending = cosigning::review(&members[cosigner], &request)
            .ok()
            .expect("an honest request");
        let shown = pending.report().lines.join("\n");
        assert!(shown.contains("PAY 0.00400000 ZEC"), "{shown}");
        assert!(shown.contains("memo: \"rent\""), "{shown}");
        let signed = coordinating.finish(&pending.approve()).unwrap();
        // Every spend now carries a signature that orchard checked under rk.
        assert!(pczt_io::spends_to_sign(&signed).is_err());
    }
}

#[test]
fn a_transaction_with_two_spends_is_signed() {
    let members = group();
    let pczt = pczt_io::serialize(build(
        &members[0].fvk,
        two_spends(&members[0].fvk, text_memo("rent")),
    ))
    .unwrap();
    let (coordinating, request) = new_request(&members, &pczt);
    assert_eq!(request.commitments.len(), 2);
    let pending = cosigning::review(&members[1], &request)
        .ok()
        .expect("an honest request");
    let signed = coordinating.finish(&pending.approve()).unwrap();
    assert!(pczt_io::spends_to_sign(&signed).is_err());
}

/// Builds a request, lets the test damage it, and returns the co-signer's
/// verdict.
fn review_damaged(damage: impl FnOnce(&mut Request)) -> Result<String, String> {
    let members = group();
    let pczt = payment(&members);
    let (_, mut request) = new_request(&members, &pczt);
    damage(&mut request);
    match cosigning::review(&members[1], &request) {
        Ok(pending) => Ok(pending.report().lines.join("\n")),
        Err(reply) => Err(refusal(reply)),
    }
}

#[test]
fn a_request_from_outside_the_group_is_refused() {
    let refused =
        review_damaged(|request| request.member = Identifier::try_from(9u16).unwrap()).unwrap_err();
    assert!(refused.contains("not a member"), "{refused}");
}

#[test]
fn a_request_claiming_the_cosigners_own_identifier_is_refused() {
    let refused =
        review_damaged(|request| request.member = Identifier::try_from(2u16).unwrap()).unwrap_err();
    assert!(refused.contains("own identifier"), "{refused}");
}

#[test]
fn a_swapped_pczt_is_checked_on_its_own_and_refused() {
    let refused = review_damaged(|request| {
        // Same session and commitments, but another transaction: value
        // leaving through an Orchard bundle.
        let members = group();
        let mut tx = honest(&members[0].fvk, MemoBytes::empty());
        tx.outputs[1].value = SPEND - PAYMENT - 3_000 - fee(4);
        tx.orchard_payment = Some((
            stranger().address_at(5u32, orchard::keys::Scope::External),
            3_000,
        ));
        request.pczt = pczt_io::serialize(build(&members[0].fvk, tx)).unwrap();
    })
    .unwrap_err();
    assert!(refused.contains("Orchard"), "{refused}");
}

#[test]
fn missing_or_extra_commitments_are_refused() {
    let refused = review_damaged(|request| request.commitments.clear()).unwrap_err();
    assert!(refused.contains("do not match"), "{refused}");
    let refused = review_damaged(|request| {
        let extra = request.commitments[0];
        request.commitments.push(extra);
    })
    .unwrap_err();
    assert!(refused.contains("do not match"), "{refused}");
}

#[test]
fn a_repeated_coordinator_commitment_is_refused() {
    // A transaction with two spends, where the coordinator reuses its first
    // commitment for the second: it would give away its own share.
    let members = group();
    let pczt = pczt_io::serialize(build(
        &members[0].fvk,
        two_spends(&members[0].fvk, MemoBytes::empty()),
    ))
    .unwrap();
    let (_, mut request) = new_request(&members, &pczt);
    assert_eq!(request.commitments.len(), 2);
    request.commitments[1] = request.commitments[0];
    let refused = refusal(cosigning::review(&members[1], &request).err().unwrap());
    assert!(refused.contains("repeats a commitment"), "{refused}");
}

#[test]
fn every_review_draws_fresh_nonces() {
    // The co-signer keeps no state: the same request reviewed twice gets two
    // sets of commitments, never the same nonces twice.
    let members = group();
    let pczt = payment(&members);
    let (_, request) = new_request(&members, &pczt);
    let commitments = |reply: Reply| match reply {
        Reply::Shares { commitments, .. } => commitments[0].serialize().unwrap(),
        Reply::Refused { .. } => panic!("expected shares"),
    };
    let first = commitments(
        cosigning::review(&members[1], &request)
            .ok()
            .unwrap()
            .approve(),
    );
    let second = commitments(
        cosigning::review(&members[1], &request)
            .ok()
            .unwrap()
            .approve(),
    );
    assert_ne!(first, second);
}

#[test]
fn declining_sends_no_commitment_and_no_share() {
    let members = group();
    let pczt = payment(&members);
    let (coordinating, request) = new_request(&members, &pczt);
    let reply = cosigning::review(&members[1], &request)
        .ok()
        .unwrap()
        .decline();
    assert!(matches!(reply, Reply::Refused { .. }));
    let error = coordinating.finish(&reply).unwrap_err().to_string();
    assert!(error.contains("declined"), "{error}");
}

#[test]
fn the_coordinator_rejects_bad_or_foreign_replies() {
    let members = group();
    let pczt = payment(&members);
    let approve = |request: &Request| match cosigning::review(&members[1], request)
        .ok()
        .unwrap()
        .approve()
    {
        Reply::Shares {
            session,
            member,
            commitments,
            shares,
        } => (session, member, commitments, shares),
        Reply::Refused { .. } => panic!("expected shares"),
    };

    // A reply for another session.
    let (coordinating, request) = new_request(&members, &pczt);
    let (_, member, commitments, shares) = approve(&request);
    let foreign = Reply::Shares {
        session: [0; 16],
        member,
        commitments: commitments.clone(),
        shares: shares.clone(),
    };
    let error = coordinating.finish(&foreign).unwrap_err().to_string();
    assert!(error.contains("another session"), "{error}");

    // A reply naming the coordinator itself, or a stranger.
    for claimed in [1u16, 9] {
        let (coordinating, request) = new_request(&members, &pczt);
        let (session, _, commitments, shares) = approve(&request);
        let wrong = Reply::Shares {
            session,
            member: Identifier::try_from(claimed).unwrap(),
            commitments,
            shares,
        };
        assert!(coordinating.finish(&wrong).is_err());
    }

    // A reply with shares made for another request: the aggregate does not
    // verify, and the coordinator says whose share is at fault.
    let (coordinating, request) = new_request(&members, &pczt);
    let (session, member, commitments, _) = approve(&request);
    let (_, other) = new_request(&members, &pczt);
    let (_, _, _, other_shares) = approve(&other);
    let wrong = Reply::Shares {
        session,
        member,
        commitments,
        shares: other_shares,
    };
    let error = coordinating.finish(&wrong).unwrap_err().to_string();
    assert!(error.contains("co-signer's signature share"), "{error}");

    // A reply with the wrong number of commitments.
    let (coordinating, request) = new_request(&members, &pczt);
    let (session, member, _, shares) = approve(&request);
    let wrong = Reply::Shares {
        session,
        member,
        commitments: Vec::new(),
        shares,
    };
    assert!(coordinating.finish(&wrong).is_err());
}
