//! Prototype key storage in `data/`.
//!
//! These are test keys, stored unencrypted on purpose so the prototype stays
//! readable. A real deployment keeps each share on its own device, encrypted
//! at rest, and does not keep `sk` in one place (see the README on qsk).

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use reddsa::frost::redpallas::keys::{KeyPackage, PublicKeyPackage};
use reddsa::frost::redpallas::Identifier;
use serde::{Deserialize, Serialize};

const DIR: &str = "data";
const PUBLIC_FILE: &str = "public-key-package.hex";
const GROUP_FILE: &str = "group.json";

/// The group's key material besides the FROST shares.
#[derive(Serialize, Deserialize)]
pub struct Group {
    /// "main" or "test".
    pub network: String,
    /// The agreed value behind nk, qsk and rivk (hex). Needed to rederive qsk.
    pub sk: String,
    /// The FROST group key, used as the spend validating key (hex).
    pub ak: String,
    /// The quantum intermediate key (hex), kept for reference.
    pub qk: String,
    pub ufvk: String,
    pub address: String,
}

fn participant_file(index: u16) -> PathBuf {
    Path::new(DIR).join(format!("participant-{index}.key"))
}

pub fn exists() -> bool {
    Path::new(DIR).join(GROUP_FILE).exists()
}

pub fn save(
    key_packages: &BTreeMap<Identifier, KeyPackage>,
    public_key_package: &PublicKeyPackage,
    group: &Group,
) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(DIR)?;
    for (position, key_package) in key_packages.values().enumerate() {
        let index = u16::try_from(position + 1)?;
        fs::write(participant_file(index), hex::encode(key_package.serialize()?))?;
    }
    fs::write(Path::new(DIR).join(PUBLIC_FILE), hex::encode(public_key_package.serialize()?))?;
    fs::write(Path::new(DIR).join(GROUP_FILE), serde_json::to_vec_pretty(group)?)?;
    Ok(())
}

pub fn load_group() -> Result<Group, Box<dyn Error>> {
    let bytes = fs::read(Path::new(DIR).join(GROUP_FILE)).map_err(|_| "no keys yet: run `keygen` first")?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn load_public() -> Result<PublicKeyPackage, Box<dyn Error>> {
    let text = fs::read_to_string(Path::new(DIR).join(PUBLIC_FILE)).map_err(|_| "no keys yet: run `keygen` first")?;
    Ok(PublicKeyPackage::deserialize(&hex::decode(text.trim())?)?)
}

/// Loads the key packages of the chosen participants (1-based indices).
pub fn load_signers(indices: &[u16]) -> Result<BTreeMap<Identifier, KeyPackage>, Box<dyn Error>> {
    let mut signers = BTreeMap::new();
    for &index in indices {
        let text = fs::read_to_string(participant_file(index)).map_err(|_| format!("no key file for participant {index}"))?;
        let key_package = KeyPackage::deserialize(&hex::decode(text.trim())?)?;
        signers.insert(*key_package.identifier(), key_package);
    }
    Ok(signers)
}
