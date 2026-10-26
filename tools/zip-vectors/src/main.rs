//! Test vectors for the FROST member backup string (draft ZIP, see
//! docs/backup-format.md). Run with `cargo run --release` in this directory:
//! it rewrites tests/fixtures/frost-member-backup-vectors.json, and the output
//! is the same on every run.
//!
//! The strings are built here, with frost-zec's ZIP 2005 derivation and an
//! independent legacy derivation, then checked three ways:
//!
//! - Zkool's own decoder and derivation matcher (vendor/zkool, copied
//!   unchanged) must accept every valid string with the same fields, match
//!   the expected derivation, and reject every invalid string;
//! - the decoder written from the draft's rules must agree with Zkool's on
//!   every case;
//! - every t-subset of members restored from their strings must produce a
//!   FROST signature that verifies under the group key `ak`.

use std::collections::BTreeMap;

use anyhow::{anyhow, bail, ensure, Context, Result};
use bech32::{primitives::decode::CheckedHrpstring, Bech32, Bech32m, Hrp};
use ff::{FromUniformBytes, PrimeField};
use orchard::keys::{FullViewingKey, SpendingKey};
use pasta_curves::pallas;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use reddsa::frost::redpallas as frost;
use frost::keys::{EvenY, IdentifierList, KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare};
use frost::{Identifier, SigningPackage, VerifyingKey};
use serde_json::{json, Value};
use zcash_address::unified::{self, Container, Encoding};
use zcash_protocol::consensus::NetworkType;

#[path = "../../../src/keys.rs"]
#[allow(dead_code)]
mod frost_zec_keys;

// Zkool's code, copied unchanged into vendor/zkool (MIT, see its LICENSE). Its
// backup code imports `super::keys`, hence the module name.
#[path = "../vendor/zkool/keys.rs"]
#[allow(dead_code)]
mod keys;
#[path = "../vendor/zkool/backup_core.rs"]
mod zkool_backup;

const HRP: &str = "zkfrost";
const PAYLOAD_LEN: usize = 68;
const MESSAGE: &[u8] = b"FROST member backup test vector";

#[derive(Clone, Copy, PartialEq, Debug)]
enum Derivation {
    Legacy,
    Zip2005,
}

impl Derivation {
    fn name(self) -> &'static str {
        match self {
            Derivation::Legacy => "legacy",
            Derivation::Zip2005 => "zip2005",
        }
    }

    /// The DKG version Zkool's matcher returns for this derivation.
    fn zkool_version(self) -> u8 {
        match self {
            Derivation::Legacy => keys::DKG_VERSION_0,
            Derivation::Zip2005 => keys::DKG_VERSION_2,
        }
    }
}

/// PRF^expand_key(t): BLAKE2b-512 personalized "Zcash_ExpandSeed".
fn prf_expand(key: &[u8], t: &[&[u8]]) -> [u8; 64] {
    let mut state = blake2b_simd::Params::new()
        .hash_length(64)
        .personal(b"Zcash_ExpandSeed")
        .to_state();
    state.update(key);
    for part in t {
        state.update(part);
    }
    *state.finalize().as_array()
}

/// The group's Orchard full viewing key under a derivation, plus qsk and qk
/// for ZIP 2005.
struct GroupFvk {
    fvk: FullViewingKey,
    qsk_qk: Option<([u8; 32], [u8; 32])>,
}

fn group_fvk(derivation: Derivation, sk: &[u8; 32], ak: &[u8; 32]) -> Result<GroupFvk> {
    match derivation {
        Derivation::Zip2005 => {
            let keys = frost_zec_keys::derive(sk, ak).map_err(|e| anyhow!("{e}"))?;
            Ok(GroupFvk { fvk: keys.fvk, qsk_qk: Some((keys.qsk, keys.qk)) })
        }
        Derivation::Legacy => {
            // nk = H^nk(sk), rivk = H^rivk(sk), with the group key as ak.
            let nk = pallas::Base::from_uniform_bytes(&prf_expand(sk, &[&[0x07]])).to_repr();
            let rivk = pallas::Scalar::from_uniform_bytes(&prf_expand(sk, &[&[0x08]])).to_repr();
            let mut bytes = [0u8; 96];
            bytes[..32].copy_from_slice(ak);
            bytes[32..64].copy_from_slice(&nk);
            bytes[64..].copy_from_slice(&rivk);
            let fvk = FullViewingKey::from_bytes(&bytes).context("legacy keys do not form a full viewing key")?;
            Ok(GroupFvk { fvk, qsk_qk: None })
        }
    }
}

fn ufvk(fvk: &FullViewingKey, network: NetworkType) -> Result<String> {
    frost_zec_keys::ufvk(fvk, network).map_err(|e| anyhow!("{e}"))
}

fn parse_ufvk(text: &str) -> Result<FullViewingKey> {
    let (_, _, ufvk) = unified::Ufvk::decode(text).map_err(|e| anyhow!("{e}"))?;
    for item in ufvk.items() {
        if let unified::Fvk::Orchard(bytes) = item {
            return FullViewingKey::from_bytes(&bytes).context("invalid Orchard full viewing key");
        }
    }
    bail!("no Orchard component")
}

fn payload(version: u8, id: u8, t: u8, n: u8, share: &[u8; 32], sk: &[u8; 32]) -> Vec<u8> {
    let mut payload = vec![version, id, t, n];
    payload.extend_from_slice(share);
    payload.extend_from_slice(sk);
    payload
}

fn encode(payload: &[u8]) -> Result<String> {
    Ok(bech32::encode::<Bech32m>(Hrp::parse(HRP)?, payload)?)
}

/// What a version 1 string carries.
#[derive(Debug, PartialEq)]
struct Decoded {
    id: u8,
    t: u8,
    n: u8,
    share: [u8; 32],
    sk: [u8; 32],
}

/// The decoding rules of the draft, written independently of Zkool's.
fn decode_draft(text: &str) -> Result<Decoded> {
    let checked = CheckedHrpstring::new::<Bech32m>(text).map_err(|e| anyhow!("not Bech32m: {e}"))?;
    ensure!(checked.hrp().to_lowercase() == HRP, "wrong human-readable part");
    let payload: Vec<u8> = checked.byte_iter().collect();
    ensure!(payload.len() == PAYLOAD_LEN, "payload is {} bytes", payload.len());
    ensure!(payload[0] == 1, "unknown version {}", payload[0]);
    let (id, t, n) = (payload[1], payload[2], payload[3]);
    ensure!(n >= 1 && (1..=n).contains(&id) && (1..=n).contains(&t), "bad id, t or n");
    let sk: [u8; 32] = payload[36..].try_into()?;
    ensure!(bool::from(SpendingKey::from_bytes(sk).is_some()), "sk is not a valid Orchard spending key");
    Ok(Decoded { id, t, n, share: payload[4..36].try_into()?, sk })
}

struct Member {
    id: u8,
    share: [u8; 32],
}

struct Group {
    name: &'static str,
    t: u8,
    n: u8,
    sk: [u8; 32],
    ak: [u8; 32],
    members: Vec<Member>,
}

/// A t-of-n group from a trusted dealer with a fixed seed, so the vectors
/// can be regenerated. Shares are normalized so that ak has an even y.
fn make_group(name: &'static str, seed: u8, t: u8, n: u8) -> Result<Group> {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(n as u16, t as u16, IdentifierList::Default, &mut rng)?;
    let is_even = pubkeys.has_even_y();
    let pubkeys = pubkeys.into_even_y(Some(is_even));
    let ak: [u8; 32] = pubkeys.verifying_key().serialize()?.try_into().map_err(|_| anyhow!("ak is not 32 bytes"))?;
    ensure!(ak[31] & 0x80 == 0, "ak must have an even y");

    let mut members = Vec::new();
    for i in 1..=n {
        let id = Identifier::try_from(i as u16)?;
        let share = shares.get(&id).context("missing share")?.clone().into_even_y(Some(is_even));
        let key_package = KeyPackage::try_from(share)?;
        ensure!(key_package.verifying_key() == pubkeys.verifying_key());
        let share: [u8; 32] = key_package.signing_share().serialize().try_into().map_err(|_| anyhow!("share is not 32 bytes"))?;
        members.push(Member { id: i, share });
    }

    let mut sk = [0u8; 32];
    loop {
        rng.fill_bytes(&mut sk);
        if bool::from(SpendingKey::from_bytes(sk).is_some()) {
            break;
        }
    }
    Ok(Group { name, t, n, sk, ak, members })
}

/// Rebuilds each member of a t-subset from its string, as a restore does, and
/// checks that together they sign under ak.
fn sign_from_strings(strings: &[&str], ak: &[u8; 32], rng: &mut ChaCha20Rng) -> Result<()> {
    let verifying_key = VerifyingKey::deserialize(ak)?;
    let mut key_packages = BTreeMap::new();
    for text in strings {
        let decoded = decode_draft(text)?;
        let identifier = Identifier::try_from(decoded.id as u16)?;
        let signing_share = SigningShare::deserialize(&decoded.share)?;
        let verifying_share = VerifyingShare::from(signing_share);
        let key_package = KeyPackage::new(identifier, signing_share, verifying_share, verifying_key, decoded.t as u16);
        key_packages.insert(identifier, key_package);
    }

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, key_package) in &key_packages {
        let (n, c) = frost::round1::commit(key_package.signing_share(), rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let signing_package = SigningPackage::new(commitments, MESSAGE);
    let mut shares = BTreeMap::new();
    for (id, key_package) in &key_packages {
        shares.insert(*id, frost::round2::sign(&signing_package, &nonces[id], key_package)?);
    }
    let verifying_shares = key_packages.iter().map(|(id, kp)| (*id, *kp.verifying_share())).collect();
    let min_signers = key_packages.values().next().context("no signer")?.min_signers();
    let pubkeys = PublicKeyPackage::new(verifying_shares, verifying_key, Some(*min_signers));
    let signature = frost::aggregate(&signing_package, &shares, &pubkeys)?;
    verifying_key.verify(MESSAGE, &signature)?;
    Ok(())
}

fn subsets(n: usize, t: usize) -> Vec<Vec<usize>> {
    if t == 0 {
        return vec![vec![]];
    }
    if n < t {
        return vec![];
    }
    let mut out = subsets(n - 1, t);
    for mut s in subsets(n - 1, t - 1) {
        s.push(n - 1);
        out.push(s);
    }
    out
}

/// One group, its viewing key under a derivation, and its member strings.
fn group_vector(group: &Group, derivation: Derivation, rng: &mut ChaCha20Rng) -> Result<(Value, Vec<String>, String)> {
    let keys = group_fvk(derivation, &group.sk, &group.ak)?;
    let fvk_bytes = keys.fvk.to_bytes();
    let ufvk_main = ufvk(&keys.fvk, NetworkType::Main)?;
    let ufvk_test = ufvk(&keys.fvk, NetworkType::Test)?;

    let mut strings = Vec::new();
    let mut members = Vec::new();
    for m in &group.members {
        let p = payload(1, m.id, group.t, group.n, &m.share, &group.sk);
        let s = encode(&p)?;
        members.push(json!({
            "id": m.id,
            "signing_share": hex::encode(m.share),
            "payload": hex::encode(&p),
            "string": s,
        }));
        strings.push(s);
    }

    let mut signed = 0;
    for subset in subsets(strings.len(), group.t as usize) {
        let chosen: Vec<&str> = subset.iter().map(|&i| strings[i].as_str()).collect();
        sign_from_strings(&chosen, &group.ak, rng).with_context(|| format!("{} {:?}", group.name, subset))?;
        signed += 1;
    }

    let (qsk, qk) = match keys.qsk_qk {
        Some((qsk, qk)) => (json!(hex::encode(qsk)), json!(hex::encode(qk))),
        None => (Value::Null, Value::Null),
    };
    let vector = json!({
        "group": group.name,
        "derivation": derivation.name(),
        "t": group.t,
        "n": group.n,
        "sk": hex::encode(group.sk),
        "ak": hex::encode(group.ak),
        "nk": hex::encode(&fvk_bytes[32..64]),
        "qsk": qsk,
        "qk": qk,
        "rivk": hex::encode(&fvk_bytes[64..]),
        "ufvk_mainnet": ufvk_main,
        "ufvk_testnet": ufvk_test,
        "members": members,
        "signing_subsets_checked": signed,
    });
    Ok((vector, strings, ufvk_main))
}

/// Checks one string with both decoders and, when a viewing key is given,
/// with Zkool's derivation matcher.
fn check_valid(text: &str, expected: &Decoded, ufvk: &str, derivation: Derivation) -> Result<()> {
    let ours = decode_draft(text)?;
    ensure!(&ours == expected, "draft decoder fields differ");
    let theirs = zkool_backup::FrostBackup::decode(text)?;
    ensure!(
        theirs.id == expected.id && theirs.t == expected.t && theirs.n == expected.n
            && theirs.share == expected.share && theirs.sk == expected.sk,
        "Zkool decoder fields differ"
    );
    ensure!(theirs.encode()? == text.to_lowercase(), "Zkool encodes these fields differently");
    let fvk = parse_ufvk(ufvk)?;
    let sk = Option::from(SpendingKey::from_bytes(theirs.sk)).context("invalid sk")?;
    let version = zkool_backup::match_derivation(&fvk, &sk)?;
    ensure!(version == derivation.zkool_version(), "Zkool matched version {version}");
    Ok(())
}

fn main() -> Result<()> {
    let mut rng = ChaCha20Rng::from_seed([0xF5; 32]);
    let a = make_group("A", 1, 2, 3)?;
    let b = make_group("B", 2, 2, 3)?;
    let c = make_group("C", 3, 3, 5)?;

    // A: a ZIP 2005 group. B: a legacy group, and the ZIP 2005 sibling Zkool
    // creates when it upgrades one (same sk, same ak, so the same strings).
    // C: a 3-of-5 ZIP 2005 group.
    let mut valid = Vec::new();
    let mut checks = 0;
    for (group, derivation) in [
        (&a, Derivation::Zip2005),
        (&b, Derivation::Legacy),
        (&b, Derivation::Zip2005),
        (&c, Derivation::Zip2005),
    ] {
        let (vector, strings, ufvk_main) = group_vector(group, derivation, &mut rng)?;
        for (m, s) in group.members.iter().zip(&strings) {
            let expected = Decoded { id: m.id, t: group.t, n: group.n, share: m.share, sk: group.sk };
            check_valid(s, &expected, &ufvk_main, derivation)
                .with_context(|| format!("group {} {} member {}", group.name, derivation.name(), m.id))?;
            checks += 1;
        }
        valid.push(vector);
    }

    // Upper case is valid Bech32m (and shorter as a QR code in alphanumeric mode).
    let a1 = &a.members[0];
    let a1_payload = payload(1, a1.id, a.t, a.n, &a1.share, &a.sk);
    let a1_string = encode(&a1_payload)?;
    let upper = a1_string.to_uppercase();
    let a_keys = group_fvk(Derivation::Zip2005, &a.sk, &a.ak)?;
    let a_ufvk = ufvk(&a_keys.fvk, NetworkType::Main)?;
    let expected_a1 = Decoded { id: a1.id, t: a.t, n: a.n, share: a1.share, sk: a.sk };
    check_valid(&upper, &expected_a1, &a_ufvk, Derivation::Zip2005).context("upper case")?;
    checks += 1;

    // Strings both decoders must reject, built from member 1 of group A.
    let with = |version: u8, id: u8, t: u8, n: u8| payload(version, id, t, n, &a1.share, &a.sk);
    let mut bad_checksum = a1_string.clone();
    let last = bad_checksum.pop().unwrap();
    bad_checksum.push(if last == 'q' { 'p' } else { 'q' });
    let mixed_case = format!("{}{}", &a1_string[..HRP.len()].to_uppercase(), &a1_string[HRP.len()..]);
    let mut long = a1_payload.clone();
    long.push(0);
    let invalid: Vec<(&str, String)> = vec![
        ("wrong human-readable part", bech32::encode::<Bech32m>(Hrp::parse("zkfros")?, &a1_payload)?),
        ("invalid checksum", bad_checksum),
        ("Bech32 checksum instead of Bech32m", bech32::encode::<Bech32>(Hrp::parse(HRP)?, &a1_payload)?),
        ("mixed case", mixed_case),
        ("payload of 67 bytes", encode(&a1_payload[..67])?),
        ("payload of 69 bytes", encode(&long)?),
        ("version 0", encode(&with(0, 1, 2, 3))?),
        ("version 2", encode(&with(2, 1, 2, 3))?),
        ("identifier 0", encode(&with(1, 0, 2, 3))?),
        ("identifier greater than n", encode(&with(1, 4, 2, 3))?),
        ("threshold 0", encode(&with(1, 1, 0, 3))?),
        ("threshold greater than n", encode(&with(1, 1, 4, 3))?),
        ("group size 0", encode(&with(1, 1, 1, 0))?),
    ];
    let mut invalid_json = Vec::new();
    for (reason, text) in &invalid {
        ensure!(decode_draft(text).is_err(), "draft decoder accepted: {reason}");
        ensure!(zkool_backup::FrostBackup::decode(text).is_err(), "Zkool accepted: {reason}");
        invalid_json.push(json!({ "reason": reason, "string": text }));
        checks += 1;
    }

    // A valid string restored against another group's viewing key.
    let c_keys = group_fvk(Derivation::Zip2005, &c.sk, &c.ak)?;
    let c_ufvk = ufvk(&c_keys.fvk, NetworkType::Main)?;
    let a_sk = Option::from(SpendingKey::from_bytes(a.sk)).context("invalid sk")?;
    ensure!(zkool_backup::match_derivation(&parse_ufvk(&c_ufvk)?, &a_sk).is_err(), "Zkool matched another group");
    checks += 1;

    let out = json!({
        "description": "FROST member backup strings, version 1 (draft ZIP). Generated by zip-backup-vectors; every valid string decodes identically with Zkool's decoder and matches the stated derivation with Zkool's matcher, every invalid string is rejected by both decoders, and every t-subset of members restored from their strings signs under ak.",
        "zkool_commit": include_str!("../vendor/zkool/COMMIT").trim(),
        "signing_message": String::from_utf8_lossy(MESSAGE),
        "valid": valid,
        "valid_upper_case": { "string": upper, "same_as": "group A, member 1" },
        "invalid": invalid_json,
        "wrong_group": { "string": a1_string, "ufvk_mainnet": c_ufvk, "expected": "decodes, but neither derivation matches the viewing key" },
    });
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/frost-member-backup-vectors.json");
    std::fs::write(path, serde_json::to_string_pretty(&out)? + "\n")?;
    println!("ok: {checks} checks passed, vectors written to tests/fixtures/frost-member-backup-vectors.json");
    Ok(())
}
