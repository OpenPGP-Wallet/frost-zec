//! Joint key generation with another FROST implementation, in Zafe's key
//! profile, so that one vault can have members running different software
//! (docs/interop.md).
//!
//! The DKG is the plain three-part FROST DKG of reddsa (redpallas); its part 3
//! already makes the group key even-y. `sk` is agreed as Zafe agrees it
//! (zafe-cash/zafe, spec.md § 7.4): in round 1 each member commits to 32 random
//! bytes `r_i`, in round 2 it reveals them, and
//!
//!   sk = BLAKE2b-256("Zafe_VaultSecret", vault_id || transcript || r_1 || … || r_n)
//!
//! with the contributions in FROST identifier order. The commitment stops the
//! last member to reveal from choosing its `r_i` after seeing the others'.
//! Identifiers are derived from each member's 32-byte identity key and the
//! vault id, as in Zafe. The keys then follow ZIP 2005 (`use_qsk`), like the
//! rest of this prototype.
//!
//! Zafe's identity key is the member's Ed25519 messaging key. This prototype
//! has no messaging layer, so 32 random bytes stand in for it.
//!
//! Messages are JSON files in an exchange directory. Round 2 files hold
//! secrets: each one goes only to its recipient, over an end-to-end encrypted
//! channel.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use orchard::keys::FullViewingKey;
use reddsa::frost::redpallas as frost;
use frost::keys::dkg;
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::Identifier;
use serde::{Deserialize, Serialize};
use zcash_protocol::consensus::NetworkType;

use crate::{keys, session, signing};

/// Written in every interop message, so a reader can refuse a format it does not know.
pub const FORMAT: &str = "frost-zec-interop-v0";
const VAULT_FILE: &str = "vault.json";

const PERSONAL_ECHO: &[u8; 16] = b"Zafe_DKG_R1Echo_";
const PERSONAL_TRANSCRIPT: &[u8; 16] = b"Zafe_DKG_Transcr";
const PERSONAL_VAULT_SK: &[u8; 16] = b"Zafe_VaultSecret";
const PERSONAL_SK_COMMIT: &[u8; 16] = b"Zafe_SkCommit___";
const PERSONAL_ECHO_COMMITS: &[u8; 16] = b"Zafe_DKG_EchoSk_";
const PERSONAL_IDENTIFIER: &[u8] = b"Zafe member identifier v1";

/// Round 1, sent to every other member.
#[derive(Serialize, Deserialize)]
struct Round1Message {
    format: String,
    kind: String,
    network: String,
    vault_id: String,
    min_signers: u16,
    max_signers: u16,
    identity: String,
    identifier: String,
    package: String,
    sk_commitment: String,
}

/// Round 2, sent to one member only: it holds that member's part of the
/// sender's polynomial and the sender's contribution to `sk`.
#[derive(Serialize, Deserialize)]
struct Round2Message {
    format: String,
    kind: String,
    vault_id: String,
    from: String,
    to: String,
    package: String,
    /// The sender's view of round 1 (every package and every `sk` commitment).
    echo: String,
    sk_contribution: String,
}

/// One member's seat in a vault made with `interop dkg`. It holds the
/// member's share and `sk`, unencrypted like the rest of this prototype.
#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub network: String,
    pub vault_id: String,
    pub min_signers: u16,
    pub max_signers: u16,
    pub identity: String,
    pub identifier: String,
    /// Every member's identifier, this one included.
    pub members: Vec<String>,
    pub key_package: String,
    pub public_key_package: String,
    pub sk: String,
    pub ak: String,
    pub ufvk: String,
    pub address: String,
}

impl Vault {
    pub fn load(dir: &Path) -> Result<Vault, Box<dyn Error>> {
        let bytes = fs::read(dir.join(VAULT_FILE)).map_err(|_| format!("no vault in {}: run `interop dkg` first", dir.display()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn key_package(&self) -> Result<KeyPackage, Box<dyn Error>> {
        Ok(KeyPackage::deserialize(&hex::decode(&self.key_package)?)?)
    }

    pub fn public_key_package(&self) -> Result<PublicKeyPackage, Box<dyn Error>> {
        Ok(PublicKeyPackage::deserialize(&hex::decode(&self.public_key_package)?)?)
    }

    pub fn fvk(&self) -> Result<FullViewingKey, Box<dyn Error>> {
        Ok(keys::derive(&bytes32(&self.sk)?, &bytes32(&self.ak)?)?.fvk)
    }
}

pub fn member_identifier(identity: &[u8; 32], vault_id: &[u8; 16]) -> Result<Identifier, Box<dyn Error>> {
    let mut input = PERSONAL_IDENTIFIER.to_vec();
    input.extend_from_slice(vault_id);
    input.extend_from_slice(identity);
    Ok(Identifier::derive(&input)?)
}

fn sk_commitment(vault_id: &[u8; 16], identity: &[u8; 32], contribution: &[u8; 32]) -> [u8; 32] {
    let mut state = blake2b_256(PERSONAL_SK_COMMIT);
    state.update(vault_id);
    state.update(identity);
    state.update(contribution);
    finalize(state)
}

/// The vault id, the parameters and every round-1 package, in identifier order.
fn hash_params_and_round1(
    state: &mut blake2b_simd::State,
    vault_id: &[u8; 16],
    min_signers: u16,
    max_signers: u16,
    round1: &BTreeMap<Identifier, dkg::round1::Package>,
) -> Result<(), Box<dyn Error>> {
    state.update(vault_id);
    state.update(&min_signers.to_le_bytes());
    state.update(&max_signers.to_le_bytes());
    for (id, package) in round1 {
        let id_bytes = id.serialize();
        let package_bytes = package.serialize()?;
        state.update(&(id_bytes.len() as u32).to_le_bytes());
        state.update(&id_bytes);
        state.update(&(package_bytes.len() as u32).to_le_bytes());
        state.update(&package_bytes);
    }
    Ok(())
}

/// Every member must see the same round 1: the same packages and the same
/// `sk` commitments. Each one sends this hash in round 2 and the others compare.
fn echo(
    vault_id: &[u8; 16],
    min_signers: u16,
    max_signers: u16,
    round1: &BTreeMap<Identifier, dkg::round1::Package>,
    commitments: &BTreeMap<Identifier, [u8; 32]>,
) -> Result<[u8; 32], Box<dyn Error>> {
    let mut state = blake2b_256(PERSONAL_ECHO);
    hash_params_and_round1(&mut state, vault_id, min_signers, max_signers, round1)?;
    let round1_echo = finalize(state);
    let mut state = blake2b_256(PERSONAL_ECHO_COMMITS);
    state.update(&round1_echo);
    for (id, commitment) in commitments {
        let id_bytes = id.serialize();
        state.update(&(id_bytes.len() as u32).to_le_bytes());
        state.update(&id_bytes);
        state.update(commitment);
    }
    Ok(finalize(state))
}

fn transcript_hash(
    vault_id: &[u8; 16],
    min_signers: u16,
    max_signers: u16,
    round1: &BTreeMap<Identifier, dkg::round1::Package>,
    ak: &[u8; 32],
) -> Result<[u8; 32], Box<dyn Error>> {
    let mut state = blake2b_256(PERSONAL_TRANSCRIPT);
    hash_params_and_round1(&mut state, vault_id, min_signers, max_signers, round1)?;
    state.update(ak);
    Ok(finalize(state))
}

fn combine_sk(vault_id: &[u8; 16], transcript: &[u8; 32], contributions: &BTreeMap<Identifier, [u8; 32]>) -> [u8; 32] {
    let mut state = blake2b_256(PERSONAL_VAULT_SK);
    state.update(vault_id);
    state.update(transcript);
    for contribution in contributions.values() {
        state.update(contribution);
    }
    finalize(state)
}

/// `interop dkg`: runs this member's side of the DKG, exchanging files in `exchange`,
/// and saves the seat in `out`.
pub fn dkg(
    network_name: &str,
    vault_id: [u8; 16],
    min_signers: u16,
    max_signers: u16,
    exchange: &Path,
    out: &Path,
) -> Result<(), Box<dyn Error>> {
    let network = network_type(network_name)?;
    if !(2..=max_signers).contains(&min_signers) || max_signers > 15 {
        return Err("need 2 <= t <= n <= 15".into());
    }
    fs::create_dir_all(exchange)?;
    fs::create_dir_all(out)?;
    let mut rng = rand::thread_rng();

    let identity: [u8; 32] = rand::random();
    let my_id = member_identifier(&identity, &vault_id)?;
    let (round1_secret, my_round1) = dkg::part1(my_id, max_signers, min_signers, &mut rng)?;
    let contribution: [u8; 32] = rand::random();
    let my_commitment = sk_commitment(&vault_id, &identity, &contribution);
    let me = short(&my_id);
    write_json(
        &exchange.join(format!("round1.{me}.json")),
        &Round1Message {
            format: FORMAT.into(),
            kind: "dkg-round1".into(),
            network: network_name.into(),
            vault_id: hex::encode(vault_id),
            min_signers,
            max_signers,
            identity: hex::encode(identity),
            identifier: hex::encode(my_id.serialize()),
            package: hex::encode(my_round1.serialize()?),
            sk_commitment: hex::encode(my_commitment),
        },
    )?;
    println!("[{me}] round 1 written: send {} to every other member.", exchange.join(format!("round1.{me}.json")).display());
    println!("[{me}] waiting for round 1 from {} other member(s) in {}...", max_signers - 1, exchange.display());

    // Round 1 from the others: each identifier must follow from its identity key.
    let mut round1_others = BTreeMap::new();
    let mut identities = BTreeMap::from([(my_id, identity)]);
    let mut commitments = BTreeMap::from([(my_id, my_commitment)]);
    let messages: Vec<Round1Message> = wait_for(exchange, "round1.", Some(&format!("round1.{me}.json")), usize::from(max_signers) - 1)?;
    for message in messages {
        if message.format != FORMAT || message.kind != "dkg-round1" {
            return Err(format!("unexpected message in round 1: {} {}", message.format, message.kind).into());
        }
        if message.vault_id != hex::encode(vault_id) || message.network != network_name || message.min_signers != min_signers || message.max_signers != max_signers {
            return Err("a member uses another vault id, network or threshold".into());
        }
        let their_identity = bytes32(&message.identity)?;
        let their_id = member_identifier(&their_identity, &vault_id)?;
        if hex::encode(their_id.serialize()) != message.identifier {
            return Err("a member's identifier does not follow from its identity key".into());
        }
        if identities.insert(their_id, their_identity).is_some() {
            return Err("two members share one identity".into());
        }
        commitments.insert(their_id, bytes32(&message.sk_commitment)?);
        round1_others.insert(their_id, dkg::round1::Package::deserialize(&hex::decode(&message.package)?)?);
    }
    let (round2_secret, outgoing) = dkg::part2(round1_secret, &round1_others)?;
    let mut round1_all = round1_others.clone();
    round1_all.insert(my_id, my_round1);
    let my_echo = echo(&vault_id, min_signers, max_signers, &round1_all, &commitments)?;

    for (recipient, package) in outgoing {
        let path = exchange.join(format!("round2.{me}-to-{}.json", short(&recipient)));
        write_json(
            &path,
            &Round2Message {
                format: FORMAT.into(),
                kind: "dkg-round2".into(),
                vault_id: hex::encode(vault_id),
                from: hex::encode(my_id.serialize()),
                to: hex::encode(recipient.serialize()),
                package: hex::encode(package.serialize()?),
                echo: hex::encode(my_echo),
                sk_contribution: hex::encode(contribution),
            },
        )?;
        println!("[{me}] round 2 written: send {} to member {} only, over an end-to-end encrypted channel (it holds secrets).", path.display(), short(&recipient));
    }

    // Round 2 to this member: the same view of round 1, and contributions that
    // match their commitments.
    println!("[{me}] waiting for round 2 from {} other member(s)...", max_signers - 1);
    let suffix = format!("-to-{me}.json");
    let paths = wait_for_paths(exchange, "round2.", |name| name.ends_with(&suffix), usize::from(max_signers) - 1)?;
    let mut round2_received = BTreeMap::new();
    let mut contributions = BTreeMap::from([(my_id, contribution)]);
    for path in &paths {
        let message: Round2Message = serde_json::from_slice(&fs::read(path)?)?;
        if message.format != FORMAT || message.kind != "dkg-round2" || message.vault_id != hex::encode(vault_id) || message.to != hex::encode(my_id.serialize()) {
            return Err(format!("unexpected round 2 message in {}", path.display()).into());
        }
        let from = Identifier::deserialize(&hex::decode(&message.from)?)?;
        let their_identity = identities.get(&from).ok_or("round 2 from a member that sent no round 1")?;
        if message.echo != hex::encode(my_echo) {
            return Err(format!("member {} saw a different round 1: abort", short(&from)).into());
        }
        let revealed = bytes32(&message.sk_contribution)?;
        if sk_commitment(&vault_id, their_identity, &revealed) != commitments[&from] {
            return Err(format!("member {}'s contribution to sk does not match its commitment", short(&from)).into());
        }
        contributions.insert(from, revealed);
        if round2_received.insert(from, dkg::round2::Package::deserialize(&hex::decode(&message.package)?)?).is_some() {
            return Err("two round 2 packages from the same member".into());
        }
    }
    let (key_package, public_key_package) = dkg::part3(&round2_secret, &round1_others, &round2_received)?;
    let ak = signing::group_ak(&public_key_package)?;
    let transcript = transcript_hash(&vault_id, min_signers, max_signers, &round1_all, &ak)?;
    let sk = combine_sk(&vault_id, &transcript, &contributions);
    let group = keys::derive(&sk, &ak)?;

    let vault = Vault {
        network: network_name.into(),
        vault_id: hex::encode(vault_id),
        min_signers,
        max_signers,
        identity: hex::encode(identity),
        identifier: hex::encode(my_id.serialize()),
        members: round1_all.keys().map(|id| hex::encode(id.serialize())).collect(),
        key_package: hex::encode(key_package.serialize()?),
        public_key_package: hex::encode(public_key_package.serialize()?),
        sk: hex::encode(sk),
        ak: hex::encode(ak),
        ufvk: keys::ufvk(&group.fvk, network)?,
        address: keys::address(&group.fvk, network)?,
    };
    write_json(&out.join(VAULT_FILE), &vault)?;
    // The round 2 files addressed to this member are consumed: remove them.
    for path in &paths {
        let _ = fs::remove_file(path);
    }
    println!("[{me}] vault saved in {}.", out.join(VAULT_FILE).display());
    print_vault(&vault);
    println!("Compare the address with every other member before funding it. Delete the round 2 files you sent once they have been received.");
    Ok(())
}

pub fn print_vault(vault: &Vault) {
    println!("network:      {}", vault.network);
    println!("vault id:     {}", vault.vault_id);
    println!("threshold:    {}-of-{}", vault.min_signers, vault.max_signers);
    for member in &vault.members {
        let marker = if *member == vault.identifier { "  (this member)" } else { "" };
        println!("member:       {}{marker}", &member[..8]);
    }
    println!("ak (FROST):   {}", vault.ak);
    println!("viewing key:  {}", vault.ufvk);
    println!("address:      {}", vault.address);
}

/// The first 4 bytes of an identifier, in hex: enough to tell members apart in file names.
pub fn short(id: &Identifier) -> String {
    hex::encode(&id.serialize()[..4])
}

fn write_json<T: Serialize>(path: &Path, message: &T) -> Result<(), Box<dyn Error>> {
    let temporary = path.with_extension("tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(message)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

/// Waits until `count` files `prefix*.json` (other than `own`) are in `dir`, then reads them.
fn wait_for<T: for<'de> Deserialize<'de>>(dir: &Path, prefix: &str, own: Option<&str>, count: usize) -> Result<Vec<T>, Box<dyn Error>> {
    let paths = wait_for_paths(dir, prefix, |name| Some(name) != own, count)?;
    paths.iter().map(|path| Ok(serde_json::from_slice(&fs::read(path)?)?)).collect()
}

fn wait_for_paths(dir: &Path, prefix: &str, keep: impl Fn(&str) -> bool, count: usize) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let deadline = Instant::now() + session::TIMEOUT;
    loop {
        let mut found = Vec::new();
        for entry in fs::read_dir(dir)? {
            let name = entry?.file_name().to_string_lossy().into_owned();
            if name.starts_with(prefix) && name.ends_with(".json") && keep(&name) {
                found.push(dir.join(name));
            }
        }
        if found.len() > count {
            return Err(format!("more `{prefix}` files than members in {}", dir.display()).into());
        }
        if found.len() == count {
            found.sort();
            return Ok(found);
        }
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for `{prefix}` files").into());
        }
        thread::sleep(session::POLL);
    }
}

pub fn network_type(name: &str) -> Result<NetworkType, Box<dyn Error>> {
    match name {
        "main" => Ok(NetworkType::Main),
        "test" => Ok(NetworkType::Test),
        other => Err(format!("unknown network `{other}` (use main or test)").into()),
    }
}

fn bytes32(text: &str) -> Result<[u8; 32], Box<dyn Error>> {
    hex::decode(text)?.try_into().map_err(|_| "expected 32 bytes".into())
}

fn blake2b_256(personal: &[u8; 16]) -> blake2b_simd::State {
    blake2b_simd::Params::new().hash_length(32).personal(personal).to_state()
}

fn finalize(state: blake2b_simd::State) -> [u8; 32] {
    state.finalize().as_bytes().try_into().expect("32-byte hash")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two members in two threads, files in a shared directory: both end up
    /// with the same vault, and their shares sign together.
    #[test]
    fn two_members_agree_on_the_vault_and_sign_together() {
        let root = std::env::temp_dir().join(format!("frost-zec-interop-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let exchange = root.join("exchange");
        let vault_id: [u8; 16] = rand::random();
        let members: Vec<_> = ["a", "b"]
            .into_iter()
            .map(|name| {
                let (exchange, out) = (exchange.clone(), root.join(name));
                thread::spawn(move || dkg("test", vault_id, 2, 2, &exchange, &out).map_err(|e| e.to_string()).map(|()| out))
            })
            .collect();
        let vaults: Vec<Vault> = members.into_iter().map(|m| Vault::load(&m.join().unwrap().unwrap()).unwrap()).collect();
        assert_eq!(vaults[0].address, vaults[1].address);
        assert_eq!(vaults[0].sk, vaults[1].sk);
        assert_ne!(vaults[0].identifier, vaults[1].identifier);

        let signers: BTreeMap<_, _> = vaults.iter().map(|v| { let k = v.key_package().unwrap(); (*k.identifier(), k) }).collect();
        let sighash: [u8; 32] = rand::random();
        signing::sign(&sighash, &signing::random_alpha(), &signers, &vaults[0].public_key_package().unwrap()).unwrap();
        let _ = fs::remove_dir_all(&root);
    }
}
