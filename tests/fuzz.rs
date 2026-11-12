//! Mutation fuzzing of every decoder an attacker can reach: valid messages of
//! each kind (pairing, DKG rounds, sealed envelopes, signing session, PCZT,
//! member backup, multi-part UR) are mutated at random and fed to the code that
//! reads them, including a co-signer reviewing a request and a coordinator
//! taking a reply. A panic is a finding; so is an input that takes long.
//!
//!   FUZZ_SECS=120 FUZZ_SEED=1 cargo test --release --test fuzz -- --ignored --nocapture

mod common;

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

use common::*;
use frost_zec::channel::{Initiator, Responder};
use frost_zec::cosigning::{self, CoordinatorSession, Member, Reply, Request};
use frost_zec::setup::{CoordinatorSetup, CosignerSetup, Done, Round1, Round2};
use frost_zec::wire::{self, Message, Reader, kind};
use frost_zec::{backup, check, dkg, keys, pczt_io, signing};
use rand::{Rng, SeedableRng, rngs::StdRng, seq::SliceRandom};
use rand10::rand_core::UnwrapErr;
use rand10::rngs::SysRng;
use zcash_protocol::consensus::NetworkType;

/// Bytes that change how CBOR reads what follows: lengths of 1 to 8 bytes,
/// indefinite lengths, the first byte of each major type.
const CBOR_EDGES: [u8; 24] = [
    0x00, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1f, 0x40, 0x58, 0x59, 0x5a, 0x5b, 0x5f, 0x60, 0x7f, 0x80,
    0x98, 0x9a, 0x9b, 0x9f, 0xa0, 0xbb, 0xbf, 0xff,
];

/// The longest a single input may take, in release.
const SLOW: Duration = Duration::from_secs(1);

fn mutate(seed: &[u8], rng: &mut StdRng) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..rng.gen_range(1..=4) {
        let len = v.len();
        match rng.gen_range(0..7) {
            0 if len > 0 => {
                let i = rng.gen_range(0..len);
                v[i] ^= 1 << rng.gen_range(0..8);
            }
            1 if len > 0 => {
                let i = rng.gen_range(0..len);
                v[i] = rng.r#gen();
            }
            2 if len > 0 => v.truncate(rng.gen_range(0..len)),
            3 => {
                let i = rng.gen_range(0..=len);
                v.insert(i, rng.r#gen());
            }
            4 if len > 0 => {
                v.remove(rng.gen_range(0..len));
            }
            5 if len > 0 => {
                let i = rng.gen_range(0..len);
                v[i] = *CBOR_EDGES.choose(rng).unwrap();
            }
            6 if len > 4 => {
                let a = rng.gen_range(0..len);
                let b = rng.gen_range(a..len.min(a + 64));
                let chunk = v[a..b].to_vec();
                let at = rng.gen_range(0..=v.len());
                v.splice(at..at, chunk);
            }
            _ => {}
        }
    }
    v
}

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

fn env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

#[test]
#[ignore = "runs for FUZZ_SECS seconds; use --release"]
fn every_decoder_survives_mutated_input() {
    let budget = Duration::from_secs(env("FUZZ_SECS", 60));
    let seed: u64 = env("FUZZ_SEED", 1);
    println!("FUZZ_SEED={seed}");
    let mut rng = StdRng::seed_from_u64(seed);
    let mut sys = UnwrapErr(SysRng);

    // A whole pairing.
    let (initiator, init) = Initiator::start(&mut sys);
    let (responder, response) = Responder::respond(&init, &mut sys).unwrap();
    let (pending_i, confirm) = initiator.finish(&response).unwrap();
    let pending_r = responder.finish(&confirm).unwrap();
    let (pairing_c, pairing_s) = (pending_i.confirm(), pending_r.confirm());

    // A whole DKG.
    let (coordinator_setup, c1) = CoordinatorSetup::start(NetworkType::Test).unwrap();
    let (_cosigner_setup, s1, s2) = CosignerSetup::respond(NetworkType::Test, &c1).unwrap();
    let (c2, _) = coordinator_setup.finish(&s1, &s2).unwrap();
    let sealed_round2 = wire::encode_payload(&[Message::seal(
        &pairing_s,
        kind::DKG_ROUND2,
        b"dkg",
        &s2.to_bytes(),
        &mut sys,
    )
    .unwrap()]);

    // A whole signing session.
    let members = group();
    let pczt = pczt_io::serialize(build(
        &members[0].fvk,
        honest(&members[0].fvk, text_memo("rent")),
    ))
    .unwrap();
    let (_, request, _) = CoordinatorSession::request(&members[0], &pczt, &mut sys).unwrap();
    let Ok(pending) = cosigning::review(&members[1], &request) else {
        panic!("the honest request was refused");
    };
    let reply = pending.approve();

    let (key_packages, _) = dkg::run(3, 2).unwrap();
    let backup_text = backup::Backup::new(key_packages.values().next().unwrap(), 3, &[9; 32])
        .unwrap()
        .encode()
        .unwrap();
    let request_bytes = request.to_bytes().unwrap();
    let ur_parts: Vec<String> = {
        let mut encoder = wire::encoder(&request_bytes, 100).unwrap();
        (0..encoder.fragment_count() + 3)
            .map(|_| encoder.next_part().unwrap())
            .collect()
    };
    let seeds: Vec<(&str, Vec<u8>)> = vec![
        (
            "pair-init",
            wire::encode_payload(&[Message::pair_init(&init)]),
        ),
        (
            "pair-response",
            wire::encode_payload(&[Message::pair_response(&response)]),
        ),
        (
            "pair-confirm",
            wire::encode_payload(&[Message::pair_confirm(&confirm)]),
        ),
        ("sealed-round2", sealed_round2),
        ("round1-coordinator", c1.to_bytes().to_vec()),
        ("round1-cosigner", s1.to_bytes().to_vec()),
        ("round2-cosigner", s2.to_bytes().to_vec()),
        ("round2-coordinator", c2.to_bytes().to_vec()),
        ("done", Done { digest: [7; 32] }.to_bytes()),
        ("request", request_bytes),
        ("reply", reply.to_bytes().unwrap()),
        ("pczt", pczt.clone()),
    ];

    // Panics are counted, not printed.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let start = Instant::now();
    let mut runs = 0u64;
    let mut findings = Vec::new();
    while start.elapsed() < budget {
        runs += 1;
        let (name, seed) = seeds.choose(&mut rng).unwrap();
        let input = mutate(seed, &mut rng);
        let target = rng.gen_range(0..9);
        let mut local = StdRng::seed_from_u64(runs);
        let began = Instant::now();
        let outcome = catch_unwind(AssertUnwindSafe(|| match target {
            // Any payload: pairing messages and sealed envelopes.
            0 => {
                if let Ok(messages) = wire::decode_payload(&input) {
                    for message in &messages {
                        let _ = message.to_pair_init();
                        let _ = message.to_pair_response();
                        let _ = message.to_pair_confirm();
                        let _ = message.open(&pairing_c, kind::DKG_ROUND2);
                        let _ = message.open(&pairing_s, kind::SIGN_REQUEST);
                    }
                    if let Ok(init) = messages[0].to_pair_init() {
                        let _ = Responder::respond(&init, &mut UnwrapErr(SysRng));
                    }
                }
            }
            // A co-signer taking the coordinator's round 1.
            1 => {
                if let Ok(round1) = Round1::from_bytes(&input) {
                    let _ = CosignerSetup::respond(NetworkType::Test, &round1);
                }
            }
            // A coordinator taking the co-signer's rounds.
            2 => {
                let round1 = Round1::from_bytes(&input);
                let round2 = Round2::from_bytes(&mutate(&s2.to_bytes(), &mut local));
                let (setup, _) = CoordinatorSetup::start(NetworkType::Test).unwrap();
                match (round1, round2) {
                    (Ok(r1), Ok(r2)) => drop(setup.finish(&r1, &r2)),
                    (Ok(r1), Err(_)) => drop(setup.finish(&r1, &s2)),
                    (Err(_), Ok(r2)) => drop(setup.finish(&s1, &r2)),
                    _ => {}
                }
            }
            3 => {
                let _ = Done::from_bytes(&input);
                let _ = Request::from_bytes(&input);
                let _ = Reply::from_bytes(&input);
            }
            // A co-signer reviewing a malicious coordinator's request.
            4 => {
                let mut forged = Request::from_bytes(&input).unwrap_or_else(|_| request.clone());
                if *name == "pczt" {
                    forged.pczt = input.clone();
                }
                let _ = cosigning::review(&members[1], &forged);
            }
            // An honest coordinator taking a malicious co-signer's reply.
            5 => {
                if let Ok((coordinating, _, _)) =
                    CoordinatorSession::request(&members[0], &pczt, &mut UnwrapErr(SysRng))
                    && let Ok(mut forged) = Reply::from_bytes(&input)
                {
                    match &mut forged {
                        Reply::Shares { session, .. } | Reply::Refused { session, .. } => {
                            *session = coordinating.session();
                        }
                    }
                    let _ = coordinating.finish(&forged);
                }
            }
            6 => {
                if let Ok(pczt) = pczt_io::parse(&input) {
                    let _ = check::analyze(&pczt, &members[0].fvk, NetworkType::Main);
                    let _ = pczt_io::sighash(&pczt);
                    let _ = pczt_io::spends_to_sign(&pczt);
                }
            }
            7 => {
                let text = mutate(backup_text.as_bytes(), &mut local);
                let _ = backup::Backup::decode(&String::from_utf8_lossy(&text));
            }
            // A QR stream with some parts mutated.
            _ => {
                let mut reader = Reader::default();
                let count = local.gen_range(1..ur_parts.len());
                for part in ur_parts.iter().take(count) {
                    let bytes = if local.gen_bool(0.3) {
                        mutate(part.as_bytes(), &mut local)
                    } else {
                        part.as_bytes().to_vec()
                    };
                    let _ = reader.receive(&String::from_utf8_lossy(&bytes));
                }
            }
        }));
        let took = began.elapsed();
        if (outcome.is_err() || took > SLOW) && findings.len() < 20 {
            findings.push(format!(
                "{} on target {target} from {name} in {took:?}: {}",
                if outcome.is_err() { "panic" } else { "slow" },
                hex::encode(&input[..input.len().min(200)])
            ));
        }
    }
    std::panic::set_hook(hook);
    println!("{runs} inputs in {:?}", start.elapsed());
    assert!(findings.is_empty(), "{}", findings.join("\n"));
}
