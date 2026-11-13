//! Test vectors for docs/spec.md (tests/fixtures/spec-vectors.json).
//!
//! `vectors_match_the_spec` recomputes every output from the formulas in the
//! spec, with BLAKE2b, X-Wing and XChaCha20-Poly1305 called directly, and checks
//! that the implementation gives the same bytes. `print_vectors` (ignored)
//! regenerates the file:
//!
//!     cargo test --test vectors print_vectors -- --ignored --nocapture

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frost_zec::channel::{Initiator, Responder};
use frost_zec::setup::{self, Round1Entry};
use frost_zec::wire::{self, Message, kind};
use frost_zec::{keys, signing};
use reddsa::frost::redpallas as frost;
use serde_json::{Value, json};
use x_wing::kem::TryDecapsulate;
use x_wing::{Ciphertext, DecapsulationKeyRejectNonContrib};
use zcash_protocol::consensus::NetworkType;

const FILE: &str = "tests/fixtures/spec-vectors.json";

fn blake2b(personal: &[u8; 16], length: usize, parts: &[&[u8]]) -> Vec<u8> {
    let mut state = blake2b_simd::Params::new()
        .hash_length(length)
        .personal(personal)
        .to_state();
    for part in parts {
        state.update(part);
    }
    state.finalize().as_bytes().to_vec()
}

fn h(text: &str) -> Vec<u8> {
    hex::decode(text).unwrap()
}

fn arr<const N: usize>(value: &Value) -> [u8; N] {
    h(value.as_str().unwrap()).try_into().unwrap()
}

/// Fixed inputs. Real ones are random.
const SEED: [u8; 32] = [0x01; 32];
const R_INITIATOR: [u8; 32] = [0x02; 32];
const ENCAPSULATION_RANDOMNESS: [u8; 64] = [0x03; 64];
const R_RESPONDER: [u8; 32] = [0x04; 32];
const NONCE: [u8; 24] = [0x05; 24];
const SESSION: &[u8] = b"vector-session";
const PLAINTEXT: &[u8] = b"FROST co-signing test vector";
const CONTRIBUTIONS: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];

#[test]
#[ignore]
fn print_vectors() {
    // Pairing.
    let (initiator, init) = Initiator::from_parts(SEED, R_INITIATOR);
    let (responder, response) =
        Responder::from_parts(&init, ENCAPSULATION_RANDOMNESS, R_RESPONDER).unwrap();
    let (pending_i, confirm) = initiator.finish(&response).unwrap();
    let pending_r = responder.finish(&confirm).unwrap();
    let code = pending_i.code();
    assert_eq!(code, pending_r.code());
    let pairing = pending_i.confirm();
    let stored = pairing.to_bytes();

    // A sealed message, initiator to responder.
    let sealed = pairing.seal_with_nonce(kind::SIGN_REQUEST, SESSION, PLAINTEXT, NONCE);

    // Wire encodings.
    let init_message = Message::pair_init(&init);
    let confirm_payload = wire::encode_payload(&[Message::pair_confirm(&confirm)]);

    // Key generation: real round 1 packages and group key from a 2-of-3 DKG.
    let mut rng = rand::thread_rng();
    let ids: Vec<frost::Identifier> = (1..=3u16).map(|i| i.try_into().unwrap()).collect();
    let mut secrets = BTreeMap::new();
    let mut packages = BTreeMap::new();
    for id in &ids {
        let (secret, package) = frost::keys::dkg::part1(*id, 3, 2, &mut rng).unwrap();
        secrets.insert(*id, secret);
        packages.insert(*id, package);
    }
    let others = |me: &frost::Identifier| -> BTreeMap<_, _> {
        packages
            .iter()
            .filter(|(id, _)| *id != me)
            .map(|(id, p)| (*id, p.clone()))
            .collect()
    };
    let mut round2 = BTreeMap::new();
    let mut inboxes: BTreeMap<frost::Identifier, BTreeMap<_, _>> = BTreeMap::new();
    for id in &ids {
        let (secret2, outgoing) =
            frost::keys::dkg::part2(secrets.remove(id).unwrap(), &others(id)).unwrap();
        round2.insert(*id, secret2);
        for (to, package) in outgoing {
            inboxes.entry(to).or_default().insert(*id, package);
        }
    }
    let (_, public) =
        frost::keys::dkg::part3(&round2[&ids[0]], &others(&ids[0]), &inboxes[&ids[0]]).unwrap();
    let ak = signing::group_ak(&public).unwrap();
    let round1_packages: Vec<String> = ids
        .iter()
        .map(|id| hex::encode(packages[id].serialize().unwrap()))
        .collect();
    let entries: Vec<Round1Entry> = (0..3)
        .map(|i| Round1Entry {
            member: i as u16 + 1,
            package: h(&round1_packages[i]),
            sk_commitment: setup::commitment_for_vectors(i as u16 + 1, &CONTRIBUTIONS[i]),
        })
        .collect();
    let transcript = setup::transcript_for_vectors(0, &entries).unwrap();
    let sk = setup::sk_for_vectors(&transcript, &ak, &CONTRIBUTIONS);
    let fvk = keys::derive(&sk, &ak).unwrap().fvk;

    let vectors = json!({
        "pairing": {
            "initiator_seed": hex::encode(SEED),
            "r_initiator": hex::encode(R_INITIATOR),
            "encapsulation_randomness": hex::encode(ENCAPSULATION_RANDOMNESS),
            "r_responder": hex::encode(R_RESPONDER),
            "encapsulation_key": hex::encode(&init.encapsulation_key),
            "commitment": hex::encode(init.commitment),
            "ciphertext": hex::encode(&response.ciphertext),
            "code": code,
            "pairing_id": hex::encode(pairing.id()),
            "key_initiator_to_responder": hex::encode(&stored[18..50]),
            "key_responder_to_initiator": hex::encode(&stored[50..82]),
        },
        "sealed": {
            "direction": 0,
            "kind": kind::SIGN_REQUEST,
            "session": hex::encode(SESSION),
            "plaintext": hex::encode(PLAINTEXT),
            "nonce": hex::encode(NONCE),
            "ciphertext": hex::encode(&sealed.ciphertext),
        },
        "wire": {
            "pair_init_message": hex::encode(minicbor::to_vec(&init_message).unwrap()),
            "pair_confirm_payload": hex::encode(&confirm_payload),
            "pair_confirm_ur": ur::encode(&confirm_payload, &ur::Type::Custom(wire::UR_TYPE)),
        },
        "key_generation": {
            "network": 0,
            "round1_packages": round1_packages,
            "contributions": CONTRIBUTIONS.iter().map(hex::encode).collect::<Vec<_>>(),
            "commitments": entries.iter().map(|e| hex::encode(e.sk_commitment)).collect::<Vec<_>>(),
            "transcript": hex::encode(transcript),
            "ak": hex::encode(ak),
            "sk": hex::encode(sk),
            "ufvk": keys::ufvk(&fvk, NetworkType::Main).unwrap(),
            "address": keys::address(&fvk, NetworkType::Main).unwrap(),
        },
        "dkg_done": dkg_done_vector(ak, &keys::ufvk(&fvk, NetworkType::Main).unwrap()),
    });
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}

#[test]
fn vectors_match_the_spec() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();

    // § 3: pairing, recomputed from the formulas.
    let p = &v["pairing"];
    let (initiator, init) =
        Initiator::from_parts(arr(&p["initiator_seed"]), arr(&p["r_initiator"]));
    assert_eq!(hex::encode(&init.encapsulation_key), p["encapsulation_key"]);
    let r_i: [u8; 32] = arr(&p["r_initiator"]);
    let commitment = blake2b(b"ZcashFROSTv0Comm", 32, &[&[0], &r_i]);
    assert_eq!(hex::encode(&commitment), p["commitment"]);
    let (responder, response) = Responder::from_parts(
        &init,
        arr(&p["encapsulation_randomness"]),
        arr(&p["r_responder"]),
    )
    .unwrap();
    assert_eq!(hex::encode(&response.ciphertext), p["ciphertext"]);

    let r_r: [u8; 32] = arr(&p["r_responder"]);
    let ek = h(p["encapsulation_key"].as_str().unwrap());
    let ct = h(p["ciphertext"].as_str().unwrap());
    let transcript = blake2b(
        b"ZcashFROSTv0Trns",
        32,
        &[&[0], &ek, &commitment, &ct, &r_r],
    );
    let sas = blake2b(b"ZcashFROSTv0SAS_", 32, &[&transcript, &r_i, &r_r]);
    let code = u64::from_le_bytes(sas[..8].try_into().unwrap()) % 1_000_000;
    assert_eq!(format!("{code:06}"), p["code"]);
    assert_eq!(hex::encode(&transcript[..16]), p["pairing_id"]);

    let decapsulation_key = DecapsulationKeyRejectNonContrib::from(arr::<32>(&p["initiator_seed"]));
    let ss: [u8; 32] = decapsulation_key
        .try_decapsulate(&Ciphertext::try_from(ct.as_slice()).unwrap())
        .unwrap()
        .into();
    let keys = blake2b(b"ZcashFROSTv0Keys", 64, &[&[0], &ss, &transcript]);
    assert_eq!(hex::encode(&keys[..32]), p["key_initiator_to_responder"]);
    assert_eq!(hex::encode(&keys[32..]), p["key_responder_to_initiator"]);

    // The implementation agrees.
    let (pending_i, confirm) = initiator.finish(&response).unwrap();
    let pending_r = responder.finish(&confirm).unwrap();
    assert_eq!(pending_i.code(), p["code"]);
    assert_eq!(pending_r.code(), p["code"]);
    let pairing = pending_i.confirm();
    assert_eq!(hex::encode(pairing.id()), p["pairing_id"]);

    // § 3.4: a sealed message.
    let s = &v["sealed"];
    let session = h(s["session"].as_str().unwrap());
    let plaintext = h(s["plaintext"].as_str().unwrap());
    let nonce: [u8; 24] = arr(&s["nonce"]);
    let mut aad = b"ZcashFROSTv0".to_vec();
    aad.extend_from_slice(&transcript[..16]);
    aad.extend_from_slice(&[0, kind::SIGN_REQUEST, session.len() as u8]);
    aad.extend_from_slice(&session);
    let key: [u8; 32] = keys[..32].try_into().unwrap();
    let ciphertext = XChaCha20Poly1305::new(&key.into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .unwrap();
    assert_eq!(hex::encode(&ciphertext), s["ciphertext"]);
    let sealed = pairing.seal_with_nonce(kind::SIGN_REQUEST, &session, &plaintext, nonce);
    assert_eq!(sealed.ciphertext, ciphertext);
    let opened = pending_r
        .confirm()
        .open(kind::SIGN_REQUEST, &session, &sealed)
        .unwrap();
    assert_eq!(opened.as_slice(), plaintext.as_slice());

    // § 2: wire encodings.
    let w = &v["wire"];
    assert_eq!(
        hex::encode(minicbor::to_vec(Message::pair_init(&init)).unwrap()),
        w["pair_init_message"]
    );
    let payload = wire::encode_payload(&[Message::pair_confirm(&confirm)]);
    assert_eq!(hex::encode(&payload), w["pair_confirm_payload"]);
    let mut reader = wire::Reader::default();
    assert_eq!(
        reader
            .receive(w["pair_confirm_ur"].as_str().unwrap())
            .unwrap(),
        Some(payload)
    );

    // § 4: key generation, recomputed from the formulas.
    let k = &v["key_generation"];
    let packages: Vec<Vec<u8>> = k["round1_packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| h(p.as_str().unwrap()))
        .collect();
    let contributions: Vec<[u8; 32]> = k["contributions"]
        .as_array()
        .unwrap()
        .iter()
        .map(arr)
        .collect();
    let mut transcript_input = vec![0u8, 0u8];
    transcript_input.extend_from_slice(&2u16.to_le_bytes());
    transcript_input.extend_from_slice(&3u16.to_le_bytes());
    let mut entries = Vec::new();
    for (i, package) in packages.iter().enumerate() {
        let member = i as u16 + 1;
        let c = blake2b(
            b"ZcashFROSTv0SkCm",
            32,
            &[&[0], &member.to_le_bytes(), &contributions[i]],
        );
        assert_eq!(hex::encode(&c), k["commitments"][i]);
        transcript_input.extend_from_slice(&member.to_le_bytes());
        transcript_input.extend_from_slice(&(package.len() as u32).to_le_bytes());
        transcript_input.extend_from_slice(package);
        transcript_input.extend_from_slice(&c);
        entries.push(Round1Entry {
            member,
            package: package.clone(),
            sk_commitment: c.try_into().unwrap(),
        });
    }
    let t = blake2b(b"ZcashFROSTv0DkgT", 32, &[&transcript_input]);
    assert_eq!(hex::encode(&t), k["transcript"]);
    assert_eq!(
        setup::transcript_for_vectors(0, &entries).unwrap().to_vec(),
        t
    );
    let ak: [u8; 32] = arr(&k["ak"]);
    let sk = blake2b(
        b"ZcashFROSTv0DkSk",
        32,
        &[
            &t,
            &ak,
            &contributions[0],
            &contributions[1],
            &contributions[2],
        ],
    );
    assert_eq!(hex::encode(&sk), k["sk"]);
    let fvk = keys::derive(&sk.try_into().unwrap(), &ak).unwrap().fvk;
    assert_eq!(keys::ufvk(&fvk, NetworkType::Main).unwrap(), k["ufvk"]);
    assert_eq!(
        keys::address(&fvk, NetworkType::Main).unwrap(),
        k["address"]
    );

    // § 4.1: the acknowledgement's digest, recomputed from the formula.
    let d = &v["dkg_done"];
    let ak: [u8; 32] = arr(&d["ak"]);
    let ufvk = d["ufvk"].as_str().unwrap();
    let members: Vec<([u8; 32], [u8; 32])> = d["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| (arr(&m["id"]), arr(&m["verifying_share"])))
        .collect();
    let t = d["t"].as_u64().unwrap() as u16;
    let network = d["network"].as_u64().unwrap() as u8;
    let mut input = vec![0u8, network];
    input.extend_from_slice(&t.to_le_bytes());
    input.extend_from_slice(&(members.len() as u16).to_le_bytes());
    input.extend_from_slice(&ak);
    for (id, share) in &members {
        input.extend_from_slice(id);
        input.extend_from_slice(share);
    }
    input.extend_from_slice(&(ufvk.len() as u32).to_le_bytes());
    input.extend_from_slice(ufvk.as_bytes());
    let digest = blake2b(b"ZcashFROSTv0Done", 32, &[&input]);
    assert_eq!(hex::encode(&digest), d["digest"]);
    assert_eq!(
        setup::done_digest_for_vectors(network, t, &ak, &members, ufvk).to_vec(),
        digest
    );
}

/// The `dkg_done` vector: the group key and viewing key of `key_generation`,
/// and fixed verifying shares (the digest does not check them).
fn dkg_done_vector(ak: [u8; 32], ufvk: &str) -> Value {
    let members: Vec<([u8; 32], [u8; 32])> = (1u16..=3)
        .map(|i| {
            let id: [u8; 32] = frost::Identifier::try_from(i)
                .unwrap()
                .serialize()
                .try_into()
                .unwrap();
            (id, [0x40 + i as u8; 32])
        })
        .collect();
    json!({
        "network": 0,
        "t": 2,
        "ak": hex::encode(ak),
        "members": members.iter().map(|(id, share)| json!({
            "id": hex::encode(id),
            "verifying_share": hex::encode(share),
        })).collect::<Vec<_>>(),
        "ufvk": ufvk,
        "digest": hex::encode(setup::done_digest_for_vectors(0, 2, &ak, &members, ufvk)),
    })
}

/// Prints the `dkg_done` vector for the `key_generation` vector already in the
/// file:
///
///     cargo test --test vectors print_dkg_done_vector -- --ignored --nocapture
#[test]
#[ignore]
fn print_dkg_done_vector() {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    let k = &v["key_generation"];
    let vector = dkg_done_vector(arr(&k["ak"]), k["ufvk"].as_str().unwrap());
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

// § 7.1: the two profiles of a member backup.

const PROFILE_PASSPHRASE: &str =
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above";
const PROFILE_SALT: [u8; 16] = [0x21; 16];
const PROFILE_NONCE: [u8; 24] = [0x22; 24];

/// Member 3 of group A of the member backup vectors, with its Mainnet viewing
/// key: the string and the key the profile vectors start from.
fn profile_inputs() -> (String, String) {
    let v: Value = serde_json::from_str(
        &std::fs::read_to_string("tests/fixtures/frost-member-backup-vectors.json").unwrap(),
    )
    .unwrap();
    let group = &v["valid"][0];
    let member = group["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == 3)
        .unwrap();
    (
        member["string"].as_str().unwrap().to_string(),
        group["ufvk_mainnet"].as_str().unwrap().to_string(),
    )
}

fn profile_contents() -> frost_zec::profiles::Contents {
    let (string, ufvk) = profile_inputs();
    frost_zec::profiles::Contents {
        backup: zeroize::Zeroizing::new(string),
        ufvk,
        birthday: Some(3_543_405),
        label: Some("FROST 2-of-3".into()),
    }
}

/// Prints the `profiles` vector:
///
///     cargo test --test vectors print_profile_vectors -- --ignored --nocapture
#[test]
#[ignore]
fn print_profile_vectors() {
    use frost_zec::profiles;
    let contents = profile_contents();
    let file = profiles::encrypt_with(
        &contents,
        PROFILE_PASSPHRASE,
        profiles::DEFAULT_COST,
        &PROFILE_SALT,
        &PROFILE_NONCE,
    )
    .unwrap();
    let backup = frost_zec::backup::Backup::decode(&contents.backup).unwrap();
    let vector = json!({
        "string": *contents.backup,
        "ufvk": contents.ufvk,
        "birthday": contents.birthday,
        "label": contents.label,
        "passphrase": PROFILE_PASSPHRASE,
        "m_cost_kib": profiles::DEFAULT_COST.m_cost_kib,
        "t_cost": profiles::DEFAULT_COST.t_cost,
        "p_cost": profiles::DEFAULT_COST.p_cost,
        "salt": hex::encode(PROFILE_SALT),
        "nonce": hex::encode(PROFILE_NONCE),
        "file": hex::encode(&file),
        "words": *profiles::to_words(&backup),
    });
    println!("{}", serde_json::to_string_pretty(&vector).unwrap());
}

#[test]
fn profile_vectors_match_the_spec() {
    use argon2::{Algorithm, Argon2, Params, Version};
    use frost_zec::profiles;
    use sha2::{Digest, Sha256};

    let v: Value = serde_json::from_str(&std::fs::read_to_string(FILE).unwrap()).unwrap();
    let p = &v["profiles"];
    let file = h(p["file"].as_str().unwrap());
    let passphrase = p["passphrase"].as_str().unwrap();

    // Profile 1, recomputed: the header, then Argon2id and XChaCha20-Poly1305.
    let (m, t, l) = (
        p["m_cost_kib"].as_u64().unwrap() as u32,
        p["t_cost"].as_u64().unwrap() as u32,
        p["p_cost"].as_u64().unwrap() as u32,
    );
    let salt = h(p["salt"].as_str().unwrap());
    let nonce: [u8; 24] = arr(&p["nonce"]);
    let mut header = b"ZKFROSTB".to_vec();
    header.push(1);
    for value in [m, t, l] {
        header.extend_from_slice(&value.to_le_bytes());
    }
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);
    assert_eq!(&file[..header.len()], header.as_slice());
    let mut key = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(m, t, l, Some(32)).unwrap(),
    )
    .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
    .unwrap();
    let plaintext = XChaCha20Poly1305::new(&key.into())
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &file[header.len()..],
                aad: &header,
            },
        )
        .unwrap();
    let string = p["string"].as_str().unwrap();
    assert!(
        plaintext
            .windows(string.len())
            .any(|w| w == string.as_bytes())
    );

    // The implementation agrees, both ways.
    let opened = profiles::decrypt(&file, passphrase).unwrap();
    assert_eq!(*opened.backup, string);
    assert_eq!(opened.ufvk, p["ufvk"]);
    assert_eq!(opened.birthday.map(u64::from), p["birthday"].as_u64());
    assert_eq!(opened.label.as_deref(), p["label"].as_str());
    let again = profiles::encrypt_with(
        &profile_contents(),
        passphrase,
        profiles::DEFAULT_COST,
        &PROFILE_SALT,
        &PROFILE_NONCE,
    )
    .unwrap();
    assert_eq!(again, file);

    // Profile 2, recomputed: the payload's 544 bits and the first 17 bits of
    // its SHA-256, 11 bits a word.
    let backup = frost_zec::backup::Backup::decode(string).unwrap();
    let payload = backup.payload();
    let digest = Sha256::digest(payload.as_slice());
    let bits: Vec<u8> = payload
        .iter()
        .chain(digest.iter())
        .flat_map(|byte| (0..8).rev().map(move |i| byte >> i & 1))
        .take(68 * 8 + 17)
        .collect();
    let list = profiles::wordlist();
    let words: Vec<&str> = bits
        .chunks(11)
        .map(|chunk| list[chunk.iter().fold(0usize, |n, b| n << 1 | usize::from(*b))])
        .collect();
    assert_eq!(words.len(), 51);
    assert_eq!(words.join(" "), p["words"]);
    assert_eq!(*profiles::to_words(&backup), words.join(" "));
    assert_eq!(
        profiles::from_words(&words.join(" "))
            .unwrap()
            .encode()
            .unwrap(),
        string
    );
}
