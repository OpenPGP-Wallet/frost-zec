//! FROST 2-of-3 for shielded ZEC in the Ironwood pool: distributed key
//! generation, group keys derived as ZIP 2005 specifies for FROST, and spends
//! authorized by any two of the three participants with re-randomized FROST
//! (ZIP 312). The co-signer verifies every PCZT on its own before signing.
//!
//! zcash-devtool does the wallet side: it watches the group's viewing key,
//! builds and proves the PCZT, and broadcasts it once signed here.
//!
//! Commands:
//!   selftest                                  in-memory DKG + signatures with every pair, no network
//!   keygen [--network main|test] [--force]    run the DKG and save the shares in data/
//!   info                                      the group's unified viewing key and address
//!   sign --pczt IN --out OUT [--signers 1,3]  check and sign a proven PCZT in one process
//!   coordinate [--as 1] [--cosigner 2] --pczt IN --out OUT
//!                                             device 1: check the PCZT, then run the signing session
//!   cosign [--as 2] [--yes]                   device 2: verify the PCZT on its own, then co-sign
//!                                             (--yes skips the human check: tests only)
//!
//! Run `coordinate` and `cosign` in two terminals: they talk through files in
//! session/, which stand in for the encrypted QR codes of the real app.

mod check;
mod dkg;
mod keys;
mod pczt_io;
mod session;
mod signing;
mod store;

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, Write};
use std::str::FromStr;

use orchard::keys::FullViewingKey;
use reddsa::frost::redpallas as frost;
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::Identifier;
use zcash_protocol::consensus::NetworkType;

const MAX_SIGNERS: u16 = 3;
const MIN_SIGNERS: u16 = 2;
/// How many spends one co-signing session can cover (one nonce pair each).
const MAX_SPENDS: usize = 4;

fn main() {
    if let Err(error) = run(std::env::args().skip(1).collect()) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("selftest") => selftest(),
        Some("keygen") => keygen(&args[1..]),
        Some("info") => info(),
        Some("sign") => sign(&args[1..]),
        Some("coordinate") => coordinate(&args[1..]),
        Some("cosign") => cosign(&args[1..]),
        _ => {
            eprintln!("usage: frost-zec <selftest | keygen | info | sign | coordinate | cosign> [options]\nsee the comment at the top of src/main.rs for the options");
            Ok(())
        }
    }
}

/// Every pair of participants produces a spend authorization signature that
/// orchard accepts under rk = ak + [alpha]G, and a single participant cannot.
fn selftest() -> Result<(), Box<dyn Error>> {
    let (key_packages, public_key_package) = dkg::run(MAX_SIGNERS, MIN_SIGNERS)?;
    let ak = signing::group_ak(&public_key_package)?;
    let sk = keys::contributory_sk(&[rand::random(), rand::random(), rand::random()]);
    let group = keys::derive(&sk, &ak)?;
    println!("group address (testnet): {}", keys::address(&group.fvk, NetworkType::Test)?);

    let ids: Vec<_> = key_packages.keys().copied().collect();
    let sighash: [u8; 32] = rand::random();
    for (i, a) in ids.iter().enumerate() {
        for (j, b) in ids.iter().enumerate().skip(i + 1) {
            let alpha = signing::random_alpha();
            let pair = [(*a, key_packages[a].clone()), (*b, key_packages[b].clone())].into_iter().collect();
            signing::sign(&sighash, &alpha, &pair, &public_key_package)?;
            println!("participants {} + {}: valid RedPallas spend signature under a fresh rk", i + 1, j + 1);
        }
    }
    let single = [(ids[0], key_packages[&ids[0]].clone())].into_iter().collect();
    match signing::sign(&sighash, &signing::random_alpha(), &single, &public_key_package) {
        Err(_) => println!("one participant alone: refused, as expected"),
        Ok(_) => return Err("a single participant produced a valid signature".into()),
    }
    Ok(())
}

fn keygen(args: &[String]) -> Result<(), Box<dyn Error>> {
    if store::exists() && !flag(args, "--force") {
        return Err("keys already exist in data/ (they may hold funds); use --force to replace them".into());
    }
    let network_name = option(args, "--network").unwrap_or("test");
    let network = network_type(network_name)?;

    let (key_packages, public_key_package) = dkg::run(MAX_SIGNERS, MIN_SIGNERS)?;
    let ak = signing::group_ak(&public_key_package)?;
    // Each participant contributes to sk, so none of them chooses it alone.
    let contributions: Vec<[u8; 32]> = (0..MAX_SIGNERS).map(|_| rand::random()).collect();
    let sk = keys::contributory_sk(&contributions);
    let group_keys = keys::derive(&sk, &ak)?;
    let group = store::Group {
        network: network_name.to_string(),
        sk: hex::encode(sk),
        ak: hex::encode(ak),
        qk: hex::encode(group_keys.qk),
        ufvk: keys::ufvk(&group_keys.fvk, network)?,
        address: keys::address(&group_keys.fvk, network)?,
    };
    store::save(&key_packages, &public_key_package, &group)?;
    println!("DKG done: {MAX_SIGNERS} participants, threshold {MIN_SIGNERS}. Shares saved in data/.");
    print_group(&group);
    Ok(())
}

fn info() -> Result<(), Box<dyn Error>> {
    print_group(&store::load_group()?);
    Ok(())
}

fn print_group(group: &store::Group) {
    println!("network:      {}", group.network);
    println!("ak (FROST):   {}", group.ak);
    println!("qk:           {}", group.qk);
    println!("viewing key:  {}", group.ufvk);
    println!("address:      {}", group.address);
}

/// The group's full viewing key, rebuilt from the stored sk and ak.
fn group_fvk(group: &store::Group) -> Result<FullViewingKey, Box<dyn Error>> {
    let sk: [u8; 32] = hex::decode(&group.sk)?.try_into().map_err(|_| "bad sk")?;
    let ak: [u8; 32] = hex::decode(&group.ak)?.try_into().map_err(|_| "bad ak")?;
    Ok(keys::derive(&sk, &ak)?.fvk)
}

/// Checks and signs a proven PCZT in one process with the chosen pair.
fn sign(args: &[String]) -> Result<(), Box<dyn Error>> {
    let input = option(args, "--pczt").ok_or("--pczt IN is required")?;
    let output = option(args, "--out").ok_or("--out OUT is required")?;
    let signer_indices: Vec<u16> = option(args, "--signers").unwrap_or("1,3").split(',').map(|s| s.trim().parse()).collect::<Result<_, _>>()?;
    let group = store::load_group()?;
    let fvk = group_fvk(&group)?;
    let public_key_package = store::load_public()?;

    let pczt = pczt_io::parse(&fs::read(input)?)?;
    let report = check::analyze(&pczt, &fvk, network_type(&group.network)?)?;
    print_report("this device", &report);
    let sighash = pczt_io::sighash(&pczt)?;
    let spends = pczt_io::spends_to_sign(&pczt)?;
    let signers = store::load_signers(&signer_indices)?;
    let mut signatures = Vec::new();
    for spend in &spends {
        signatures.push((spend.index, signing::sign(&sighash, &spend.alpha, &signers, &public_key_package)?));
    }
    let signed = pczt_io::apply(pczt, &sighash, &signatures)?;
    fs::write(output, pczt_io::serialize(signed)?)?;
    println!("{} spend(s) signed by participants {signer_indices:?}; each signature verified under its rk. Written to {output}.", spends.len());
    Ok(())
}

/// Device 1: checks the proven PCZT itself, collects the co-signer's
/// commitments, sends the PCZT, then aggregates both shares for each spend and
/// inserts the signatures.
fn coordinate(args: &[String]) -> Result<(), Box<dyn Error>> {
    let me = number(args, "--as")?.unwrap_or(1u16);
    let cosigner = number(args, "--cosigner")?.unwrap_or(2u16);
    if me == cosigner {
        return Err("the coordinator and the co-signer must be different participants".into());
    }
    let input = option(args, "--pczt").ok_or("--pczt IN is required")?;
    let output = option(args, "--out").ok_or("--out OUT is required")?;
    let pczt_bytes = fs::read(input)?;
    let pczt = pczt_io::parse(&pczt_bytes)?;
    // The coordinator checks the PCZT too: whatever built it (the wallet, a
    // dApp) is not trusted to have built what the user asked for.
    let group = store::load_group()?;
    let report = check::analyze(&pczt, &group_fvk(&group)?, network_type(&group.network)?)?;
    print_report(&format!("device {me}"), &report);
    let sighash = pczt_io::sighash(&pczt)?;
    let spends = pczt_io::spends_to_sign(&pczt)?;
    if spends.len() > MAX_SPENDS {
        return Err(format!("{} spends; one session covers at most {MAX_SPENDS}", spends.len()).into());
    }
    let public_key_package = store::load_public()?;
    let key_package = single_key(me)?;
    let (my_id, their_id) = (Identifier::try_from(me)?, Identifier::try_from(cosigner)?);

    session::reset()?;
    // The session files hold the PCZT (amounts, addresses, viewing-key
    // material): they are removed when this function returns, whatever happens.
    let _cleanup = session::Cleanup;
    let session_id = hex::encode(rand::random::<[u8; 8]>());
    session::send("start", &session::Start { session: session_id.clone(), coordinator: me, cosigner })?;
    println!("[device {me}] signing session open. Run `cosign --as {cosigner}` in another terminal.");

    let theirs: session::Commitments = session::receive("commitments")?;
    if theirs.session != session_id {
        return Err("commitments from another session".into());
    }
    if theirs.commitments.len() < spends.len() {
        return Err("not enough commitments from the co-signer".into());
    }

    let mut my_nonces = Vec::new();
    let mut packages = Vec::new();
    let mut my_commitments = Vec::new();
    for (spend, their_commitment) in spends.iter().zip(&theirs.commitments) {
        let (nonces, my_commitment) = signing::commit(&key_package);
        let commitments = BTreeMap::from([(my_id, my_commitment), (their_id, SigningCommitments::deserialize(&hex::decode(their_commitment)?)?)]);
        my_commitments.push(hex::encode(my_commitment.serialize()?));
        my_nonces.push(nonces);
        packages.push((spend, commitments));
    }
    session::send("request", &session::Request { session: session_id.clone(), pczt: hex::encode(&pczt_bytes), commitments: my_commitments })?;
    println!("[device {me}] PCZT sent; waiting for device {cosigner} to check it...");

    let reply: session::Reply = session::receive("reply")?;
    if reply.session != session_id {
        return Err("reply from another session".into());
    }
    if let Some(reason) = reply.refused {
        return Err(format!("device {cosigner} refused to sign: {reason}").into());
    }
    let their_shares = reply.shares.ok_or("no shares in the reply")?;
    if their_shares.len() != spends.len() {
        return Err("the co-signer returned the wrong number of shares".into());
    }

    let mut signatures = Vec::new();
    for (((spend, commitments), nonces), their_share) in packages.iter().zip(&my_nonces).zip(&their_shares) {
        let my_share = signing::share(&sighash, &spend.alpha, commitments, nonces, &key_package)?;
        let shares = BTreeMap::from([(my_id, my_share), (their_id, SignatureShare::deserialize(&hex::decode(their_share)?)?)]);
        signatures.push((spend.index, signing::aggregate(&sighash, &spend.alpha, commitments, &shares, &public_key_package)?));
    }
    drop(my_nonces);
    let signed = pczt_io::apply(pczt, &sighash, &signatures)?;
    fs::write(output, pczt_io::serialize(signed)?)?;
    println!("[device {me}] {} spend(s) signed with device {cosigner}; each signature verified under its rk. Written to {output}.", signatures.len());
    Ok(())
}

/// Device 2: commits first, then verifies the PCZT on its own and signs the
/// sighash it computed itself.
fn cosign(args: &[String]) -> Result<(), Box<dyn Error>> {
    let me = number(args, "--as")?.unwrap_or(2u16);
    let group = store::load_group()?;
    let fvk = group_fvk(&group)?;
    let key_package = single_key(me)?;
    let my_id = Identifier::try_from(me)?;

    println!("[device {me}] waiting for a signing request...");
    let start: session::Start = session::receive("start")?;
    if start.cosigner != me {
        return Err(format!("this session expects participant {} as co-signer", start.cosigner).into());
    }
    let their_id = Identifier::try_from(start.coordinator)?;
    let mut my_nonces = Vec::new();
    let mut my_commitments = Vec::new();
    for _ in 0..MAX_SPENDS {
        let (nonces, commitment) = signing::commit(&key_package);
        my_nonces.push(nonces);
        my_commitments.push(commitment);
    }
    session::send(
        "commitments",
        &session::Commitments {
            session: start.session.clone(),
            commitments: my_commitments.iter().map(|c| c.serialize().map(hex::encode)).collect::<Result<_, _>>()?,
        },
    )?;

    let request: session::Request = session::receive("request")?;
    if request.session != start.session {
        return Err("request from another session".into());
    }
    let refuse = |reason: String| -> Result<(), Box<dyn Error>> {
        session::send("reply", &session::Reply { session: start.session.clone(), shares: None, refused: Some(reason.clone()) })?;
        Err(format!("refused: {reason}").into())
    };

    let pczt = match pczt_io::parse(&hex::decode(&request.pczt)?) {
        Ok(pczt) => pczt,
        Err(e) => return refuse(e.to_string()),
    };
    let report = match check::analyze(&pczt, &fvk, network_type(&group.network)?) {
        Ok(report) => report,
        Err(e) => return refuse(e.to_string()),
    };
    // The sighash and the randomizers come from the PCZT this device checked,
    // never from the coordinator's word.
    let (sighash, spends) = match pczt_io::sighash(&pczt).and_then(|h| Ok((h, pczt_io::spends_to_sign(&pczt)?))) {
        Ok(found) => found,
        Err(e) => return refuse(e.to_string()),
    };
    if spends.len() > MAX_SPENDS || request.commitments.len() != spends.len() {
        return refuse("the number of spends and commitments do not match".into());
    }
    print_report(&format!("device {me}"), &report);

    let approved = if flag(args, "--yes") {
        // Test mode: skips the human check. Never use it for real funds.
        println!("[device {me}] --yes: approving without a human check (test mode)");
        report.warnings.is_empty()
    } else {
        print!("[device {me}] approve and sign? [y/N] ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        answer.trim().eq_ignore_ascii_case("y")
    };
    if !approved {
        return refuse("not approved on the co-signing device".into());
    }

    let mut shares = Vec::new();
    for ((spend, their_commitment), (nonces, my_commitment)) in spends.iter().zip(&request.commitments).zip(my_nonces.iter().zip(&my_commitments)) {
        let commitments = BTreeMap::from([(their_id, SigningCommitments::deserialize(&hex::decode(their_commitment)?)?), (my_id, *my_commitment)]);
        let share = signing::share(&sighash, &spend.alpha, &commitments, nonces, &key_package)?;
        shares.push(hex::encode(share.serialize()));
    }
    drop(my_nonces);
    session::send("reply", &session::Reply { session: start.session, shares: Some(shares), refused: None })?;
    println!("[device {me}] signed the sighash computed on this device; nonces discarded.");
    Ok(())
}

fn print_report(who: &str, report: &check::Report) {
    println!("[{who}] PCZT verified against its commitments:");
    for line in &report.lines {
        println!("  {line}");
    }
    for warning in &report.warnings {
        println!("  WARNING: {warning}");
    }
}

fn network_type(name: &str) -> Result<NetworkType, Box<dyn Error>> {
    match name {
        "main" => Ok(NetworkType::Main),
        "test" => Ok(NetworkType::Test),
        other => Err(format!("unknown network `{other}` (use main or test)").into()),
    }
}

fn single_key(index: u16) -> Result<frost::keys::KeyPackage, Box<dyn Error>> {
    store::load_signers(&[index])?.into_values().next().ok_or_else(|| "missing key".into())
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn number<T: FromStr>(args: &[String], name: &str) -> Result<Option<T>, Box<dyn Error>>
where
    T::Err: Error + 'static,
{
    Ok(option(args, name).map(str::parse).transpose()?)
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_pair_signs_and_a_single_share_cannot() {
        super::selftest().expect("selftest");
    }
}
