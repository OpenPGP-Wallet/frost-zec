//! The whole protocol, end to end, between two devices that only exchange QR
//! payloads: pairing, key generation, then a signing session over a real PCZT.
//! Every payload goes through the UR encoder and reader, with fountain parts
//! shuffled and repeated, as a camera would see them.

mod common;

use common::*;
use frost_zec::channel::{Initiator, Pairing, Responder};
use frost_zec::cosigning::{self, CoordinatorSession, Reply, Request, SESSION_ID_SIZE};
use frost_zec::pczt_io;
use frost_zec::setup::{self, CoordinatorSetup, CosignerSetup, Done, Group, Round1, Round2};
use frost_zec::wire::{self, Message, kind};
use rand10::rand_core::UnwrapErr;
use rand10::rngs::SysRng;
use zcash_protocol::consensus::NetworkType;

/// Shows `messages` as an animated QR code and scans it on the other side.
fn qr(messages: &[Message]) -> Vec<Message> {
    let payload = wire::encode_payload(messages);
    let mut encoder = wire::encoder(&payload, 250).unwrap();
    let mut parts: Vec<String> = (0..encoder.fragment_count() * 2 + 3)
        .map(|_| encoder.next_part().unwrap().to_uppercase())
        .collect();
    let third = parts.len() / 3;
    parts.rotate_left(third);
    let mut reader = wire::Reader::default();
    for part in parts {
        if let Some(payload) = reader.receive(&part).unwrap() {
            return wire::decode_payload(&payload).unwrap();
        }
    }
    panic!("the QR stream never completed");
}

struct Devices {
    coordinator: (Pairing, Group),
    cosigner: (Pairing, Group),
    backup: Group,
}

fn pair_and_generate_keys(network: NetworkType) -> Devices {
    let mut rng = UnwrapErr(SysRng);
    // 1. Coordinator: pair-init.
    let (initiator, init) = Initiator::start(&mut rng);
    let scanned = qr(&[Message::pair_init(&init)]);
    // 2. Co-signer: pair-response.
    let (responder, response) =
        Responder::respond(&scanned[0].to_pair_init().unwrap(), &mut rng).unwrap();
    let scanned = qr(&[Message::pair_response(&response)]);
    // 3. Coordinator: pair-confirm, with its round 1 sealed.
    let (pending_c, confirm) = initiator
        .finish(&scanned[0].to_pair_response().unwrap())
        .unwrap();
    let (coordinator_setup, c1) = CoordinatorSetup::start(network).unwrap();
    let scanned = qr(&[
        Message::pair_confirm(&confirm),
        Message::seal_public(
            &pending_c,
            kind::DKG_ROUND1,
            b"dkg",
            &c1.to_bytes(),
            &mut rng,
        )
        .unwrap(),
    ]);
    // The co-signer checks the code, then answers with its rounds 1 and 2.
    let pending_s = responder
        .finish(&scanned[0].to_pair_confirm().unwrap())
        .unwrap();
    assert_eq!(pending_c.code(), pending_s.code(), "the codes must match");
    let (pairing_c, pairing_s) = (pending_c.confirm(), pending_s.confirm());
    let (_, c1) = scanned[1].open(&pairing_s, kind::DKG_ROUND1).unwrap();
    let (cosigner_setup, s1, s2) =
        CosignerSetup::respond(network, &Round1::from_bytes(&c1).unwrap()).unwrap();
    let scanned = qr(&[
        Message::seal(
            &pairing_s,
            kind::DKG_ROUND1,
            b"dkg",
            &s1.to_bytes(),
            &mut rng,
        )
        .unwrap(),
        Message::seal(
            &pairing_s,
            kind::DKG_ROUND2,
            b"dkg",
            &s2.to_bytes(),
            &mut rng,
        )
        .unwrap(),
    ]);
    // 4. Coordinator: finishes and sends its round 2.
    let (_, s1) = scanned[0].open(&pairing_c, kind::DKG_ROUND1).unwrap();
    let (_, s2) = scanned[1].open(&pairing_c, kind::DKG_ROUND2).unwrap();
    let (c2, coordinator) = coordinator_setup
        .finish(
            &Round1::from_bytes(&s1).unwrap(),
            &Round2::from_bytes(&s2).unwrap(),
        )
        .unwrap();
    let scanned = qr(&[Message::seal(
        &pairing_c,
        kind::DKG_ROUND2,
        b"dkg",
        &c2.to_bytes(),
        &mut rng,
    )
    .unwrap()]);
    // 5. Co-signer: finishes, exports member 3 and checks the string it
    // exported against the group before it acknowledges.
    let (_, c2) = scanned[0].open(&pairing_s, kind::DKG_ROUND2).unwrap();
    let (cosigner, backup) = cosigner_setup
        .finish(&Round2::from_bytes(&c2).unwrap())
        .unwrap();
    setup::check_backup(&backup.backup_string().unwrap(), &cosigner).unwrap();
    let scanned = qr(&[Message::seal(
        &pairing_s,
        kind::DKG_DONE,
        b"dkg",
        &cosigner.done().unwrap().to_bytes(),
        &mut rng,
    )
    .unwrap()]);
    // 6. Coordinator: shows the address only once the acknowledgement holds.
    let (_, done) = scanned[0].open(&pairing_c, kind::DKG_DONE).unwrap();
    coordinator
        .check_done(&Done::from_bytes(&done).unwrap())
        .unwrap();
    Devices {
        coordinator: (pairing_c, coordinator),
        cosigner: (pairing_s, cosigner),
        backup,
    }
}

#[test]
fn pairing_key_generation_and_a_signature_over_qr_codes() {
    let devices = pair_and_generate_keys(NetworkType::Main);
    let (pairing_c, coordinator) = &devices.coordinator;
    let (pairing_s, cosigner) = &devices.cosigner;
    assert_eq!(coordinator.address, cosigner.address);
    assert_eq!(coordinator.address, devices.backup.address);
    assert!(
        devices
            .backup
            .backup_string()
            .unwrap()
            .starts_with("zkfrost1")
    );

    let mut rng = UnwrapErr(SysRng);
    let fvk = &coordinator.member.fvk;
    let pczt = pczt_io::serialize(build(fvk, honest(fvk, text_memo("rent")))).unwrap();

    // Message 1: the coordinator's request, a multi-part QR stream.
    let (coordinating, request, _) =
        CoordinatorSession::request(&coordinator.member, &pczt, &mut rng).unwrap();
    let scanned = qr(&[Message::seal(
        pairing_c,
        kind::SIGN_REQUEST,
        &request.session,
        &request.to_bytes().unwrap(),
        &mut rng,
    )
    .unwrap()]);
    let (bound_session, bytes) = scanned[0].open(pairing_s, kind::SIGN_REQUEST).unwrap();
    let request = Request::from_bytes(&bytes).unwrap();
    assert_eq!(bound_session, request.session.to_vec());

    // The co-signer checks it and the user approves what is shown.
    let pending = cosigning::review(&cosigner.member, &request)
        .ok()
        .expect("an honest request");
    let shown = pending.report().lines.join(
        "
",
    );
    assert!(shown.contains("PAY 0.00400000 ZEC"), "{shown}");
    assert!(shown.contains("memo: \"rent\""), "{shown}");
    let reply = pending.approve();

    // Message 2: the reply, then the coordinator finishes.
    let scanned = qr(&[Message::seal(
        pairing_s,
        kind::SIGN_REPLY,
        &reply.session(),
        &reply.to_bytes().unwrap(),
        &mut rng,
    )
    .unwrap()]);
    let (bound_session, bytes) = scanned[0].open(pairing_c, kind::SIGN_REPLY).unwrap();
    assert_eq!(bound_session, coordinating.session().to_vec());
    let signed = coordinating
        .finish(&Reply::from_bytes(&bytes).unwrap())
        .unwrap();
    assert!(
        pczt_io::spends_to_sign(&signed).is_err(),
        "every spend is signed"
    );
}

#[test]
fn a_replayed_reply_is_refused_by_a_new_session() {
    let devices = pair_and_generate_keys(NetworkType::Test);
    let (_, coordinator) = &devices.coordinator;
    let (_, cosigner) = &devices.cosigner;
    let mut rng = UnwrapErr(SysRng);
    let fvk = &coordinator.member.fvk;
    let pczt = pczt_io::serialize(build(fvk, honest(fvk, text_memo("rent")))).unwrap();

    let (first, request, _) =
        CoordinatorSession::request(&coordinator.member, &pczt, &mut rng).unwrap();
    let reply = cosigning::review(&cosigner.member, &request)
        .ok()
        .unwrap()
        .approve();
    first.finish(&reply).unwrap();

    // Someone who recorded the reply shows it to a new session for the same
    // transaction: it opened with new nonces and its own session id.
    let (second, _, _) = CoordinatorSession::request(&coordinator.member, &pczt, &mut rng).unwrap();
    let refused = second.finish(&reply).unwrap_err().to_string();
    assert!(refused.contains("another session"), "{refused}");
    assert_eq!(request.session.len(), SESSION_ID_SIZE);
}

#[test]
fn an_acknowledgement_from_another_group_is_refused() {
    let first = pair_and_generate_keys(NetworkType::Test);
    let second = pair_and_generate_keys(NetworkType::Test);
    let (_, coordinator) = &first.coordinator;
    let (_, other) = &second.cosigner;
    let refused = coordinator
        .check_done(&other.done().unwrap())
        .unwrap_err()
        .to_string();
    assert!(refused.contains("different group"), "{refused}");
    // Nor does another group's member 3 pass for this one.
    assert!(
        setup::check_backup(&second.backup.backup_string().unwrap(), &first.cosigner.1).is_err()
    );
    // And member 2's own string is not member 3.
    assert!(
        setup::check_backup(
            &first.cosigner.1.backup_string().unwrap(),
            &first.cosigner.1
        )
        .is_err()
    );
}

#[test]
fn a_refusal_reason_cannot_rewrite_the_coordinators_screen() {
    let devices = pair_and_generate_keys(NetworkType::Test);
    let (_, coordinator) = &devices.coordinator;
    let reply = Reply::Refused {
        session: [1; SESSION_ID_SIZE],
        member: coordinator.member.id(),
        reason: format!("no\u{202E}\nPAY{}", "x".repeat(5000)),
    };
    let Reply::Refused { reason, .. } = Reply::from_bytes(&reply.to_bytes().unwrap()).unwrap()
    else {
        panic!("expected a refusal")
    };
    assert!(!reason.contains('\u{202E}') && !reason.contains('\n'));
    assert!(reason.len() < 1100);
}
