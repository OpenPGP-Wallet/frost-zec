//! The signing session (src/cosigning.rs) with a real 2-of-3 FROST group:
//! the honest path, and every way a message can be wrong.

mod common;

use common::*;
use frost_zec::cosigning::{CoordinatorSession, CosignerSession, Member, Reply, Request};
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

#[test]
fn any_two_members_sign_and_the_signatures_are_inserted() {
    let members = group();
    let pczt = payment(&members);
    for (coordinator, cosigner) in [(0, 1), (0, 2), (1, 2)] {
        let (session, opening) = CosignerSession::open(&members[cosigner], &mut UnwrapErr(SysRng));
        let (coordinating, request, _) =
            CoordinatorSession::request(&members[coordinator], &pczt, &opening).unwrap();
        let pending = session.review(&request).ok().expect("an honest request");
        let shown = pending.report().lines.join("\n");
        assert!(shown.contains("PAY 0.00400000 ZEC"), "{shown}");
        assert!(shown.contains("memo: \"rent\""), "{shown}");
        let signed = coordinating.finish(&pending.approve()).unwrap();
        // Every spend now carries a signature that orchard checked under rk.
        assert!(pczt_io::spends_to_sign(&signed).is_err());
    }
}

/// Runs messages 1 and 2, lets the test damage the request, and returns the
/// co-signer's verdict.
fn review_damaged(damage: impl FnOnce(&mut Request)) -> Result<String, String> {
    let members = group();
    let pczt = payment(&members);
    let (session, opening) = CosignerSession::open(&members[1], &mut UnwrapErr(SysRng));
    let (_, mut request, _) = CoordinatorSession::request(&members[0], &pczt, &opening).unwrap();
    damage(&mut request);
    match session.review(&request) {
        Ok(pending) => Ok(pending.report().lines.join("\n")),
        Err(reply) => Err(refusal(reply)),
    }
}

#[test]
fn a_bad_coordinator_share_is_refused_before_the_user_is_asked() {
    let members = group();
    let pczt = payment(&members);
    let (session, opening) = CosignerSession::open(&members[1], &mut UnwrapErr(SysRng));
    let (_, mut request, _) = CoordinatorSession::request(&members[0], &pczt, &opening).unwrap();
    // A share from another run of the coordinator, made with other nonces.
    let (_, other, _) = CoordinatorSession::request(&members[0], &pczt, &opening).unwrap();
    request.shares = other.shares;
    let refused = refusal(session.review(&request).err().unwrap());
    assert!(
        refused.contains("signature share does not verify"),
        "{refused}"
    );
}

#[test]
fn a_request_for_another_session_is_refused() {
    let refused = review_damaged(|request| request.session[0] ^= 1).unwrap_err();
    assert!(refused.contains("another session"), "{refused}");
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
        // Same session and shares, but another transaction: value leaving
        // through an Orchard bundle.
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
fn missing_or_extra_shares_are_refused() {
    let refused = review_damaged(|request| request.shares.clear()).unwrap_err();
    assert!(refused.contains("do not match"), "{refused}");
    let refused = review_damaged(|request| {
        let extra = request.shares[0];
        request.shares.push(extra);
    })
    .unwrap_err();
    assert!(refused.contains("do not match"), "{refused}");
}

#[test]
fn declining_sends_no_share() {
    let members = group();
    let pczt = payment(&members);
    let (session, opening) = CosignerSession::open(&members[1], &mut UnwrapErr(SysRng));
    let (coordinating, request, _) =
        CoordinatorSession::request(&members[0], &pczt, &opening).unwrap();
    let reply = session.review(&request).ok().unwrap().decline();
    assert!(matches!(reply, Reply::Refused { .. }));
    let error = coordinating.finish(&reply).unwrap_err().to_string();
    assert!(error.contains("declined"), "{error}");
}

#[test]
fn the_coordinator_rejects_bad_or_foreign_replies() {
    let members = group();
    let pczt = payment(&members);

    // A reply for another session.
    let (session, opening) = CosignerSession::open(&members[1], &mut UnwrapErr(SysRng));
    let (coordinating, request, _) =
        CoordinatorSession::request(&members[0], &pczt, &opening).unwrap();
    let Reply::Shares { member, shares, .. } = session.review(&request).ok().unwrap().approve()
    else {
        panic!("expected shares")
    };
    let foreign = Reply::Shares {
        session: [0; 16],
        member,
        shares: shares.clone(),
    };
    assert!(coordinating.finish(&foreign).is_err());

    // A reply whose shares were made for another request.
    let (session, opening) = CosignerSession::open(&members[1], &mut UnwrapErr(SysRng));
    let (coordinating, _, _) = CoordinatorSession::request(&members[0], &pczt, &opening).unwrap();
    let wrong = Reply::Shares {
        session: opening.session,
        member,
        shares,
    };
    assert!(coordinating.finish(&wrong).is_err());
    drop(session);
}
