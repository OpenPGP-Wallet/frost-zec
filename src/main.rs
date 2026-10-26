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
//!   info [--vault DIR]                        the group's unified viewing key and address
//!   inspect --pczt IN [--vault DIR]           check a PCZT and show what it does, without signing
//!   sign --pczt IN --out OUT [--signers 1,3]  check and sign a proven PCZT in one process
//!   coordinate [--as 1 | --vault DIR] [--dir session] --pczt IN --out OUT
//!                                             check the PCZT, then run the signing session
//!   cosign [--as 2 | --vault DIR] [--dir session] [--yes]
//!                                             verify the PCZT on its own, then co-sign
//!                                             (--yes skips the human check: tests only)
//!   interop dkg [--network main|test] [--vault-id HEX] [--threshold 2] [--members 2]
//!               [--dir exchange] [--out vault] [--force]
//!                                             create a vault with members running other
//!                                             software, in Zafe's key profile (docs/interop.md)
//!   backup export [--as 1 | --vault DIR]      one member's backup string (docs/backup-format.md)
//!   backup restore --in FILE --ufvk KEY [--save]
//!                                             rebuild a member from its string and the group's
//!                                             viewing key; --save writes it back into data/
//!
//! Run `coordinate` and `cosign` in two terminals: they talk through files in
//! the --dir directory, which stand in for the encrypted QR codes of the real
//! app. `--as N` uses participant N of the group in data/; `--vault DIR` uses a
//! seat created with `interop dkg`.

mod backup;
mod check;
mod dkg;
mod interop;
mod keys;
mod pczt_io;
mod session;
mod signing;
mod store;

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use orchard::keys::FullViewingKey;
use reddsa::frost::redpallas as frost;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::round1::SigningCommitments;
use frost::round2::SignatureShare;
use frost::Identifier;
use zcash_protocol::consensus::NetworkType;

const MAX_SIGNERS: u16 = 3;
const MIN_SIGNERS: u16 = 2;
/// How many spends one co-signing session can cover (one nonce pair each).
const MAX_SPENDS: usize = 4;
const SESSION_DIR: &str = "session";

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
        Some("info") => info(&args[1..]),
        Some("inspect") => inspect(&args[1..]),
        Some("sign") => sign(&args[1..]),
        Some("coordinate") => coordinate(&args[1..]),
        Some("cosign") => cosign(&args[1..]),
        Some("interop") if args.get(1).map(String::as_str) == Some("dkg") => interop_dkg(&args[2..]),
        Some("backup") if args.get(1).map(String::as_str) == Some("export") => backup_export(&args[2..]),
        Some("backup") if args.get(1).map(String::as_str) == Some("restore") => backup_restore(&args[2..]),
        _ => {
            eprintln!("usage: frost-zec <selftest | keygen | info | inspect | sign | coordinate | cosign | interop dkg | backup export | backup restore> [options]\nsee the comment at the top of src/main.rs for the options");
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
    let network = interop::network_type(network_name)?;

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

fn info(args: &[String]) -> Result<(), Box<dyn Error>> {
    match option(args, "--vault") {
        Some(dir) => interop::print_vault(&interop::Vault::load(Path::new(dir))?),
        None => print_group(&store::load_group()?),
    }
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

/// What one participant brings to a signing session.
struct Seat {
    name: String,
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
    fvk: FullViewingKey,
    network: NetworkType,
}

impl Seat {
    /// The seat from `--vault DIR`, or participant `--as N` of the group in data/.
    fn load(args: &[String], default_index: u16) -> Result<Seat, Box<dyn Error>> {
        if let Some(dir) = option(args, "--vault") {
            let vault = interop::Vault::load(Path::new(dir))?;
            let key_package = vault.key_package()?;
            return Ok(Seat {
                name: format!("member {}", interop::short(key_package.identifier())),
                key_package,
                public_key_package: vault.public_key_package()?,
                fvk: vault.fvk()?,
                network: interop::network_type(&vault.network)?,
            });
        }
        let index = number(args, "--as")?.unwrap_or(default_index);
        let group = store::load_group()?;
        Ok(Seat {
            name: format!("device {index}"),
            key_package: single_key(index)?,
            public_key_package: store::load_public()?,
            fvk: group_fvk(&group)?,
            network: interop::network_type(&group.network)?,
        })
    }

    fn id(&self) -> Identifier {
        *self.key_package.identifier()
    }

    /// Sessions have exactly two signers: the coordinator and one co-signer.
    fn check_two_signers(&self) -> Result<(), Box<dyn Error>> {
        if *self.key_package.min_signers() != 2 {
            return Err("signing sessions support a threshold of 2 only".into());
        }
        Ok(())
    }

    /// The other participant named in a message: another member of this group.
    fn other_member(&self, hex_id: &str) -> Result<Identifier, Box<dyn Error>> {
        let id = Identifier::deserialize(&hex::decode(hex_id)?)?;
        if id == self.id() || !self.public_key_package.verifying_shares().contains_key(&id) {
            return Err(format!("{hex_id} is not another member of this group").into());
        }
        Ok(id)
    }
}

fn check_kind(format: &str, kind: &str, expected: &str) -> Result<(), Box<dyn Error>> {
    if format != interop::FORMAT || kind != expected {
        return Err(format!("expected a `{expected}` message ({}), got `{kind}` ({format})", interop::FORMAT).into());
    }
    Ok(())
}

/// Checks a PCZT and shows what it does, without signing anything.
fn inspect(args: &[String]) -> Result<(), Box<dyn Error>> {
    let input = option(args, "--pczt").ok_or("--pczt IN is required")?;
    let seat = Seat::load(args, 1)?;
    let pczt = pczt_io::parse(&fs::read(input)?)?;
    let report = check::analyze(&pczt, &seat.fvk, seat.network)?;
    print_report("this group", &report);
    println!("  sighash {}", hex::encode(pczt_io::sighash(&pczt)?));
    println!("  {} spend(s) waiting for a signature", pczt_io::spends_to_sign(&pczt)?.len());
    Ok(())
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
    let report = check::analyze(&pczt, &fvk, interop::network_type(&group.network)?)?;
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

/// The coordinator: checks the PCZT itself, takes the co-signer's
/// commitments, sends the PCZT, then aggregates both shares for each spend and
/// inserts the signatures.
fn coordinate(args: &[String]) -> Result<(), Box<dyn Error>> {
    let seat = Seat::load(args, 1)?;
    seat.check_two_signers()?;
    let dir = PathBuf::from(option(args, "--dir").unwrap_or(SESSION_DIR));
    let input = option(args, "--pczt").ok_or("--pczt IN is required")?;
    let output = option(args, "--out").ok_or("--out OUT is required")?;
    let pczt_bytes = fs::read(input)?;
    let pczt = pczt_io::parse(&pczt_bytes)?;
    // The coordinator checks the PCZT too: whatever built it (the wallet, a
    // dApp) is not trusted to have built what the user asked for.
    let report = check::analyze(&pczt, &seat.fvk, seat.network)?;
    print_report(&seat.name, &report);
    let sighash = pczt_io::sighash(&pczt)?;
    let spends = pczt_io::spends_to_sign(&pczt)?;
    if spends.len() > MAX_SPENDS {
        return Err(format!("{} spends; one session covers at most {MAX_SPENDS}", spends.len()).into());
    }
    let my_id = seat.id();

    // The session files hold the PCZT (amounts, addresses, viewing-key
    // material): they are removed when this function returns, whatever happens.
    let _cleanup = session::Cleanup(&dir);
    println!("[{}] waiting for the co-signer's commitments in {}...", seat.name, session::path(&dir, session::COMMITMENTS).display());
    let theirs: session::Commitments = session::receive(&dir, session::COMMITMENTS)?;
    check_kind(&theirs.format, &theirs.kind, "sign-commitments")?;
    let their_id = seat.other_member(&theirs.identifier)?;
    if theirs.commitments.len() < spends.len() {
        return Err("not enough commitments from the co-signer".into());
    }

    let mut my_nonces = Vec::new();
    let mut packages = Vec::new();
    let mut my_commitments = Vec::new();
    for (spend, their_commitment) in spends.iter().zip(&theirs.commitments) {
        let (nonces, my_commitment) = signing::commit(&seat.key_package);
        let commitments = BTreeMap::from([(my_id, my_commitment), (their_id, SigningCommitments::deserialize(&hex::decode(their_commitment)?)?)]);
        my_commitments.push(hex::encode(my_commitment.serialize()?));
        my_nonces.push(nonces);
        packages.push((spend, commitments));
    }
    session::send(
        &dir,
        session::REQUEST,
        &session::Request {
            format: interop::FORMAT.into(),
            kind: "sign-request".into(),
            session: theirs.session.clone(),
            identifier: hex::encode(my_id.serialize()),
            pczt: hex::encode(&pczt_bytes),
            commitments: my_commitments,
        },
    )?;
    println!("[{}] request written to {}: send it to the co-signer. Waiting for its reply...", seat.name, session::path(&dir, session::REQUEST).display());

    let reply: session::Reply = session::receive(&dir, session::REPLY)?;
    check_kind(&reply.format, &reply.kind, "sign-reply")?;
    if reply.session != theirs.session || seat.other_member(&reply.identifier)? != their_id {
        return Err("reply from another session or another member".into());
    }
    if let Some(reason) = reply.refused {
        return Err(format!("the co-signer refused to sign: {reason}").into());
    }
    let their_shares = reply.shares.ok_or("no shares in the reply")?;
    if their_shares.len() != spends.len() {
        return Err("the co-signer returned the wrong number of shares".into());
    }

    let mut signatures = Vec::new();
    for (((spend, commitments), nonces), their_share) in packages.iter().zip(&my_nonces).zip(&their_shares) {
        let my_share = signing::share(&sighash, &spend.alpha, commitments, nonces, &seat.key_package)?;
        let shares = BTreeMap::from([(my_id, my_share), (their_id, SignatureShare::deserialize(&hex::decode(their_share)?)?)]);
        signatures.push((spend.index, signing::aggregate(&sighash, &spend.alpha, commitments, &shares, &seat.public_key_package)?));
    }
    drop(my_nonces);
    let signed = pczt_io::apply(pczt, &sighash, &signatures)?;
    fs::write(output, pczt_io::serialize(signed)?)?;
    println!("[{}] {} spend(s) signed with member {}; each signature verified under its rk. Written to {output}.", seat.name, signatures.len(), interop::short(&their_id));
    Ok(())
}

/// The co-signer: commits first, then verifies the PCZT on its own and signs
/// the sighash it computed itself.
fn cosign(args: &[String]) -> Result<(), Box<dyn Error>> {
    let seat = Seat::load(args, 2)?;
    seat.check_two_signers()?;
    let dir = PathBuf::from(option(args, "--dir").unwrap_or(SESSION_DIR));
    let my_id = seat.id();

    session::reset(&dir)?;
    let session_id = hex::encode(rand::random::<[u8; 8]>());
    let mut my_nonces = Vec::new();
    let mut my_commitments = Vec::new();
    for _ in 0..MAX_SPENDS {
        let (nonces, commitment) = signing::commit(&seat.key_package);
        my_nonces.push(nonces);
        my_commitments.push(commitment);
    }
    session::send(
        &dir,
        session::COMMITMENTS,
        &session::Commitments {
            format: interop::FORMAT.into(),
            kind: "sign-commitments".into(),
            session: session_id.clone(),
            identifier: hex::encode(my_id.serialize()),
            commitments: my_commitments.iter().map(|c| c.serialize().map(hex::encode)).collect::<Result<_, _>>()?,
        },
    )?;
    println!("[{}] commitments written to {}: send them to the coordinator. Waiting for its request...", seat.name, session::path(&dir, session::COMMITMENTS).display());

    let request: session::Request = session::receive(&dir, session::REQUEST)?;
    // The request holds the PCZT: it does not stay on disk once read.
    let _ = fs::remove_file(session::path(&dir, session::REQUEST));
    check_kind(&request.format, &request.kind, "sign-request")?;
    if request.session != session_id {
        return Err("request from another session".into());
    }
    let their_id = seat.other_member(&request.identifier)?;
    let refuse = |reason: String| -> Result<(), Box<dyn Error>> {
        session::send(
            &dir,
            session::REPLY,
            &session::Reply {
                format: interop::FORMAT.into(),
                kind: "sign-reply".into(),
                session: session_id.clone(),
                identifier: hex::encode(my_id.serialize()),
                shares: None,
                refused: Some(reason.clone()),
            },
        )?;
        Err(format!("refused: {reason}").into())
    };

    let pczt = match hex::decode(&request.pczt).map_err(Box::<dyn Error>::from).and_then(|bytes| pczt_io::parse(&bytes)) {
        Ok(pczt) => pczt,
        Err(e) => return refuse(e.to_string()),
    };
    let report = match check::analyze(&pczt, &seat.fvk, seat.network) {
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
    print_report(&seat.name, &report);

    let approved = if flag(args, "--yes") {
        // Test mode: skips the human check. Never use it for real funds.
        println!("[{}] --yes: approving without a human check (test mode)", seat.name);
        report.warnings.iter().all(|w| w.starts_with("v6 pre-authorization"))
    } else {
        print!("[{}] approve and sign? [y/N] ", seat.name);
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
        let share = signing::share(&sighash, &spend.alpha, &commitments, nonces, &seat.key_package)?;
        shares.push(hex::encode(share.serialize()));
    }
    drop(my_nonces);
    session::send(
        &dir,
        session::REPLY,
        &session::Reply {
            format: interop::FORMAT.into(),
            kind: "sign-reply".into(),
            session: session_id,
            identifier: hex::encode(my_id.serialize()),
            shares: Some(shares),
            refused: None,
        },
    )?;
    println!("[{}] signed the sighash computed on this device; nonces discarded. Reply written to {}: send it to the coordinator.", seat.name, session::path(&dir, session::REPLY).display());
    Ok(())
}

/// `interop dkg`: this member's side of a joint DKG with other software.
fn interop_dkg(args: &[String]) -> Result<(), Box<dyn Error>> {
    let out = PathBuf::from(option(args, "--out").unwrap_or("vault"));
    if out.join("vault.json").exists() && !flag(args, "--force") {
        return Err(format!("{} already holds a vault (it may hold funds); use --force to replace it", out.display()).into());
    }
    let vault_id: [u8; 16] = match option(args, "--vault-id") {
        Some(text) => hex::decode(text)?.try_into().map_err(|_| "the vault id is 16 bytes (32 hex characters)")?,
        None => {
            let id = rand::random();
            println!("new vault id {}: give it to the other members, who pass it with --vault-id.", hex::encode(id));
            id
        }
    };
    interop::dkg(
        option(args, "--network").unwrap_or("test"),
        vault_id,
        number(args, "--threshold")?.unwrap_or(2),
        number(args, "--members")?.unwrap_or(2),
        Path::new(option(args, "--dir").unwrap_or("exchange")),
        &out,
    )
}

/// Prints one member's backup string, followed by the viewing key the restore
/// needs. The string is as secret as the share: it holds the share and sk.
fn backup_export(args: &[String]) -> Result<(), Box<dyn Error>> {
    let seat = Seat::load(args, 1)?;
    let sk = match option(args, "--vault") {
        Some(dir) => interop::Vault::load(Path::new(dir))?.sk,
        None => store::load_group()?.sk,
    };
    let sk: [u8; 32] = hex::decode(sk)?.try_into().map_err(|_| "bad sk")?;
    let n = u16::try_from(seat.public_key_package.verifying_shares().len())?;
    let text = backup::Backup::new(&seat.key_package, n, &sk)?.encode()?;
    println!("[{}] backup string (secret, keep it offline):\n{text}", seat.name);
    println!("viewing key (needed to restore): {}", keys::ufvk(&seat.fvk, seat.network)?);
    Ok(())
}

/// Rebuilds a member from its string and the group's viewing key, and says
/// which derivation the group follows. With --save, puts the member back into
/// the group in data/, after checking it is the same group.
fn backup_restore(args: &[String]) -> Result<(), Box<dyn Error>> {
    let path = option(args, "--in").ok_or("missing --in FILE (the file holding the backup string)")?;
    let ufvk = option(args, "--ufvk").ok_or("missing --ufvk KEY (the group's unified full viewing key)")?;
    let restored = backup::restore(&fs::read_to_string(path)?, ufvk)?;
    let b = &restored.backup;
    println!("member {}, threshold {} of {}, network {:?}", b.id, b.t, b.n, restored.network);
    match restored.derivation {
        backup::Derivation::Zip2005 => println!("derivation: ZIP 2005 (use_qsk), notes are quantum recoverable"),
        backup::Derivation::Legacy => println!("derivation: legacy, WARNING: this group's notes are not quantum recoverable"),
    }
    if flag(args, "--save") {
        let group = store::load_group()?;
        if group_fvk(&group)? != restored.fvk {
            return Err("this backup belongs to another group than the one in data/".into());
        }
        store::save_participant(u16::from(b.id), &restored.key_package)?;
        println!("saved as participant {} in data/", b.id);
    }
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

fn single_key(index: u16) -> Result<KeyPackage, Box<dyn Error>> {
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
