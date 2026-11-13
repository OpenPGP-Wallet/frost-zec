//! The two ways a user keeps a member backup string (docs/backup-profiles.md,
//! spec § 7.1): a passphrase-encrypted file, and 51 words on paper.
//!
//! **Profile 1, the file.** For users who keep files: on a USB stick, in a
//! password manager, in a cloud folder they do not fully trust.
//!
//! ```text
//! magic "ZKFROSTB" (8) | version u8 = 1 | m_cost_kib u32 | t_cost u32 | p_cost u32
//! | salt (16) | nonce (24) | XChaCha20-Poly1305 ciphertext of the contents
//! ```
//!
//! Integers are little-endian. The key is Argon2id(passphrase, salt) with the
//! header's parameters; the whole header is the associated data, so a changed
//! parameter or salt fails decryption. The contents are a CBOR map: 1 the
//! member backup string, 2 the group's unified full viewing key, 3 the
//! birthday height when known, 4 a label. A text form, `zkfrost-file-1:` and
//! the bytes in unpadded base64url, carries the same file.
//!
//! **Profile 2, the words.** The 68-byte payload of the string and the first
//! 17 bits of its SHA-256, as 51 words of the BIP-39 English list, 11 bits
//! each. No wallet takes 51 words as a seed, so the words cannot be mistaken
//! for one. Restoring also needs the group's viewing key, which the words do
//! not hold; with it, [`correct_one_word`] finds a single miscopied word.

use std::error::Error;
use std::sync::OnceLock;

use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use minicbor::{Decode, Encode};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::backup::{self, Backup, PAYLOAD_LEN};
use crate::keys;

// --- Profile 1: the passphrase-encrypted file --------------------------------

/// The first bytes of a backup file.
pub const FILE_MAGIC: &[u8; 8] = b"ZKFROSTB";
const FILE_VERSION: u8 = 1;
/// The text form of a file starts with this.
pub const TEXT_PREFIX: &str = "zkfrost-file-1:";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 8 + 1 + 4 + 4 + 4 + SALT_LEN + NONCE_LEN;
/// Contents are a few hundred bytes; anything far larger is not a backup file.
const MAX_FILE_LEN: usize = 16 * 1024;

/// Argon2id's cost parameters, as stored in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cost {
    /// Memory, in KiB.
    pub m_cost_kib: u32,
    /// Passes over the memory.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

/// What files are written with: 64 MiB, 3 passes, 1 lane. A reader refuses
/// less, so that a forged file cannot pass for a strong one.
pub const DEFAULT_COST: Cost = Cost {
    m_cost_kib: 64 * 1024,
    t_cost: 3,
    p_cost: 1,
};
/// The most a reader accepts, so that a file cannot exhaust the device: 1 GiB,
/// 16 passes, 16 lanes.
pub const MAX_COST: Cost = Cost {
    m_cost_kib: 1024 * 1024,
    t_cost: 16,
    p_cost: 16,
};

/// What a backup file holds.
pub struct Contents {
    /// The member backup string. Secret.
    pub backup: Zeroizing<String>,
    /// The group's unified full viewing key, so that a restore needs nothing
    /// from another device.
    pub ufvk: String,
    /// The height to start scanning from, when known.
    pub birthday: Option<u32>,
    /// The account's name in the wallet.
    pub label: Option<String>,
}

#[derive(Encode, Decode)]
#[cbor(map)]
struct ContentsWire {
    #[n(1)]
    backup: String,
    #[n(2)]
    ufvk: String,
    #[n(3)]
    birthday: Option<u32>,
    #[n(4)]
    label: Option<String>,
}

impl Drop for ContentsWire {
    fn drop(&mut self) {
        self.backup.zeroize();
    }
}

impl Contents {
    /// Checks that the contents go together: the string is a valid member
    /// backup, and its `sk` with the group key gives this viewing key.
    pub fn check(&self) -> Result<(), Box<dyn Error>> {
        backup::restore(&self.backup, &self.ufvk)
            .map_err(|e| format!("the backup file's contents do not go together: {e}"))?;
        Ok(())
    }
}

fn key(passphrase: &str, salt: &[u8], cost: Cost) -> Result<Zeroizing<[u8; 32]>, Box<dyn Error>> {
    let params = Params::new(cost.m_cost_kib, cost.t_cost, cost.p_cost, Some(32))
        .map_err(|e| format!("Argon2 parameters: {e}"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| format!("Argon2: {e}"))?;
    Ok(key)
}

fn header(cost: Cost, salt: &[u8; SALT_LEN], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(FILE_MAGIC);
    header.push(FILE_VERSION);
    header.extend_from_slice(&cost.m_cost_kib.to_le_bytes());
    header.extend_from_slice(&cost.t_cost.to_le_bytes());
    header.extend_from_slice(&cost.p_cost.to_le_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    header
}

/// Encrypts `contents` under `passphrase`, with [`DEFAULT_COST`] and a fresh
/// salt and nonce. The contents are checked first: a file that cannot be
/// restored is never written.
pub fn encrypt(contents: &Contents, passphrase: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    encrypt_with(contents, passphrase, DEFAULT_COST, &salt, &nonce)
}

/// [`encrypt`] with the cost, salt and nonce given, for test vectors.
#[doc(hidden)]
pub fn encrypt_with(
    contents: &Contents,
    passphrase: &str,
    cost: Cost,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, Box<dyn Error>> {
    if passphrase.is_empty() {
        return Err("the passphrase is empty".into());
    }
    contents.check()?;
    let wire = ContentsWire {
        backup: contents.backup.to_string(),
        ufvk: contents.ufvk.clone(),
        birthday: contents.birthday,
        label: contents.label.clone(),
    };
    let plaintext =
        Zeroizing::new(minicbor::to_vec(&wire).expect("encoding to memory cannot fail"));
    let header = header(cost, salt, nonce);
    let key = key(passphrase, salt, cost)?;
    let ciphertext = XChaCha20Poly1305::new(&(*key).into())
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: &plaintext,
                aad: &header,
            },
        )
        .map_err(|_| "encryption failed")?;
    let mut file = header;
    file.extend_from_slice(&ciphertext);
    Ok(file)
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

/// The cost a file asks for, checked against [`DEFAULT_COST`] and
/// [`MAX_COST`] before any work is done.
pub fn file_cost(file: &[u8]) -> Result<Cost, Box<dyn Error>> {
    if file.len() < HEADER_LEN + 16 || &file[..8] != FILE_MAGIC {
        return Err("not a FROST member backup file".into());
    }
    if file[8] != FILE_VERSION {
        return Err(format!("backup file version {} is not supported", file[8]).into());
    }
    if file.len() > MAX_FILE_LEN {
        return Err("the backup file is too large".into());
    }
    let cost = Cost {
        m_cost_kib: read_u32(file, 9),
        t_cost: read_u32(file, 13),
        p_cost: read_u32(file, 17),
    };
    if cost.m_cost_kib < DEFAULT_COST.m_cost_kib
        || cost.t_cost < DEFAULT_COST.t_cost
        || cost.p_cost < DEFAULT_COST.p_cost
    {
        return Err("the backup file asks for less work than a backup file must".into());
    }
    if cost.m_cost_kib > MAX_COST.m_cost_kib
        || cost.t_cost > MAX_COST.t_cost
        || cost.p_cost > MAX_COST.p_cost
    {
        return Err("the backup file asks for more work than this device allows".into());
    }
    Ok(cost)
}

/// Decrypts a backup file, then checks that its contents go together.
pub fn decrypt(file: &[u8], passphrase: &str) -> Result<Contents, Box<dyn Error>> {
    let cost = file_cost(file)?;
    let header = &file[..HEADER_LEN];
    let salt = &file[21..21 + SALT_LEN];
    let nonce: [u8; NONCE_LEN] = file[21 + SALT_LEN..HEADER_LEN].try_into()?;
    let key = key(passphrase, salt, cost)?;
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new(&(*key).into())
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &file[HEADER_LEN..],
                    aad: header,
                },
            )
            .map_err(|_| "wrong passphrase, or a damaged backup file")?,
    );
    let wire: ContentsWire = minicbor::decode(&plaintext)
        .map_err(|e| format!("the backup file's contents are not readable: {e}"))?;
    let contents = Contents {
        backup: Zeroizing::new(wire.backup.clone()),
        ufvk: wire.ufvk.clone(),
        birthday: wire.birthday,
        label: wire.label.clone(),
    };
    contents.check()?;
    Ok(contents)
}

/// The text form of a file: `zkfrost-file-1:` and unpadded base64url.
pub fn to_text(file: &[u8]) -> String {
    format!("{TEXT_PREFIX}{}", Base64UrlUnpadded::encode_string(file))
}

/// Reads the text form of a file.
pub fn from_text(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let encoded = text
        .trim()
        .strip_prefix(TEXT_PREFIX)
        .ok_or("not the text form of a FROST member backup file")?;
    if encoded.len() > MAX_FILE_LEN * 4 / 3 + 4 {
        return Err("the backup file is too large".into());
    }
    Base64UrlUnpadded::decode_vec(encoded).map_err(|_| "the backup file's text is damaged".into())
}

/// The fewest words a passphrase may have, unless the wallet's own strength
/// check rates it very strong.
pub const MIN_PASSPHRASE_WORDS: usize = 12;

/// A passphrase of 12 random words from the BIP-39 English list: 132 bits.
pub fn generate_passphrase() -> Zeroizing<String> {
    let list = wordlist();
    let mut words = Vec::with_capacity(MIN_PASSPHRASE_WORDS);
    for _ in 0..MIN_PASSPHRASE_WORDS {
        let index = rand::Rng::gen_range(&mut rand::thread_rng(), 0..list.len());
        words.push(list[index]);
    }
    Zeroizing::new(words.join(" "))
}

/// The number of words in a passphrase, as [`MIN_PASSPHRASE_WORDS`] counts
/// them.
pub fn passphrase_words(passphrase: &str) -> usize {
    passphrase.split_whitespace().count()
}

// --- Profile 2: 51 words ----------------------------------------------------------

/// The number of words of profile 2.
pub const WORD_COUNT: usize = 51;
const CHECKSUM_BITS: usize = PAYLOAD_LEN * 8 / 32;

/// The BIP-39 English word list, in order.
pub fn wordlist() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| include_str!("bip39-english.txt").lines().collect())
}

fn bit(bytes: &[u8], index: usize) -> u16 {
    u16::from(bytes[index / 8] >> (7 - index % 8) & 1)
}

/// The words of a member backup. Secret.
pub fn to_words(backup: &Backup) -> Zeroizing<String> {
    let payload = backup.payload();
    let checksum = Sha256::digest(payload.as_slice());
    let list = wordlist();
    let mut words = Vec::with_capacity(WORD_COUNT);
    for word in 0..WORD_COUNT {
        let mut index = 0u16;
        for i in word * 11..word * 11 + 11 {
            let b = if i < PAYLOAD_LEN * 8 {
                bit(payload.as_slice(), i)
            } else {
                bit(&checksum, i - PAYLOAD_LEN * 8)
            };
            index = index << 1 | b;
        }
        words.push(list[usize::from(index)]);
    }
    Zeroizing::new(words.join(" "))
}

/// The word list's indices of the words of `text`, which must be 51 words of
/// the list (case and spacing do not matter).
fn indices(text: &str) -> Result<Vec<u16>, Box<dyn Error>> {
    let list = wordlist();
    let words: Vec<String> = text.split_whitespace().map(str::to_lowercase).collect();
    if words.len() != WORD_COUNT {
        return Err(format!(
            "a member backup has {WORD_COUNT} words, not {}",
            words.len()
        )
        .into());
    }
    words
        .iter()
        .enumerate()
        .map(|(position, word)| {
            list.binary_search(&word.as_str())
                .map(|index| index as u16)
                .map_err(|_| {
                    format!("word {} (\"{word}\") is not in the list", position + 1).into()
                })
        })
        .collect()
}

fn from_indices(indices: &[u16]) -> Result<Backup, Box<dyn Error>> {
    let mut payload = Zeroizing::new([0u8; PAYLOAD_LEN]);
    let mut checksum = 0u32;
    for (word, index) in indices.iter().enumerate() {
        for k in 0..11 {
            let b = (index >> (10 - k)) & 1;
            let i = word * 11 + k;
            if i < PAYLOAD_LEN * 8 {
                payload[i / 8] |= (b as u8) << (7 - i % 8);
            } else {
                checksum = checksum << 1 | u32::from(b);
            }
        }
    }
    let digest = Sha256::digest(payload.as_slice());
    let expected =
        u32::from_be_bytes(digest[..4].try_into().expect("4 bytes")) >> (32 - CHECKSUM_BITS);
    if checksum != expected {
        return Err("the words' checksum does not match: a word is miscopied".into());
    }
    Backup::from_payload(payload.as_slice())
}

/// Reads the words of a member backup.
pub fn from_words(text: &str) -> Result<Backup, Box<dyn Error>> {
    from_indices(&indices(text)?)
}

/// For words whose checksum fails, the corrections of a single word that pass
/// the checksum and restore against the group's viewing key `ufvk`, as word
/// lists. A miscopied word in the `sk` part is found by the viewing key alone;
/// one in the signing share part only by the checksum, so more than one
/// candidate can come back: the right one is the one whose member matches the
/// group's public key package ([`backup::check_member`]).
pub fn correct_one_word(text: &str, ufvk: &str) -> Result<Vec<Zeroizing<String>>, Box<dyn Error>> {
    let original = indices(text)?;
    let list = wordlist();
    let mut found = Vec::new();
    let mut candidate = original.clone();
    for position in 0..WORD_COUNT {
        for replacement in 0..list.len() as u16 {
            if replacement == original[position] {
                continue;
            }
            candidate[position] = replacement;
            if let Ok(backup) = from_indices(&candidate)
                && backup::restore(&backup.encode()?, ufvk).is_ok()
            {
                found.push(Zeroizing::new(
                    candidate
                        .iter()
                        .map(|i| list[usize::from(*i)])
                        .collect::<Vec<_>>()
                        .join(" "),
                ));
            }
        }
        candidate[position] = original[position];
    }
    Ok(found)
}

/// Checks that the words of a member backup, with the group's viewing key,
/// restore a member (see [`backup::restore`]).
pub fn restore_words(text: &str, ufvk: &str) -> Result<backup::Restored, Box<dyn Error>> {
    let backup = from_words(text)?;
    backup::restore(&backup.encode()?, ufvk)
}

/// The network a viewing key is on, for messages that name it.
pub fn ufvk_network(ufvk: &str) -> Result<zcash_protocol::consensus::NetworkType, Box<dyn Error>> {
    Ok(keys::parse_ufvk(ufvk)?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dkg, signing};
    use zcash_protocol::consensus::NetworkType;

    /// A member of a fresh group, its string and the group's viewing key.
    fn member() -> (Backup, String, String) {
        let (key_packages, public_key_package) = dkg::run(3, 2).unwrap();
        let ak = signing::group_ak(&public_key_package).unwrap();
        let sk: [u8; 32] = rand::random();
        let fvk = keys::derive(&sk, &ak).unwrap().fvk;
        let ufvk = keys::ufvk(&fvk, NetworkType::Test).unwrap();
        let backup = Backup::new(key_packages.values().next().unwrap(), 3, &sk).unwrap();
        let text = backup.encode().unwrap();
        (backup, text, ufvk)
    }

    #[test]
    fn the_word_list_is_bip_39_english() {
        let text = wordlist().join("\n") + "\n";
        assert_eq!(wordlist().len(), 2048);
        assert_eq!(
            hex::encode(Sha256::digest(text.as_bytes())),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
        assert!(wordlist().windows(2).all(|w| w[0] < w[1]), "sorted");
    }

    #[test]
    fn a_file_round_trips_only_with_its_passphrase() {
        let (_, text, ufvk) = member();
        let contents = Contents {
            backup: Zeroizing::new(text.clone()),
            ufvk: ufvk.clone(),
            birthday: Some(4_600_000),
            label: Some("FROST 2-of-3".into()),
        };
        let passphrase = generate_passphrase();
        assert_eq!(passphrase_words(&passphrase), 12);
        let file = encrypt(&contents, &passphrase).unwrap();
        let back = decrypt(&from_text(&to_text(&file)).unwrap(), &passphrase).unwrap();
        assert_eq!(*back.backup, text);
        assert_eq!(back.ufvk, ufvk);
        assert_eq!(back.birthday, Some(4_600_000));
        assert_eq!(back.label.as_deref(), Some("FROST 2-of-3"));
        assert!(decrypt(&file, "another passphrase").is_err());

        // A changed header (here, the salt) fails, and so does any changed byte.
        let mut changed = file.clone();
        changed[30] ^= 1;
        assert!(decrypt(&changed, &passphrase).is_err());
        let mut changed = file.clone();
        *changed.last_mut().unwrap() ^= 1;
        assert!(decrypt(&changed, &passphrase).is_err());
    }

    #[test]
    fn weak_or_huge_costs_are_refused_before_any_work() {
        let (_, text, ufvk) = member();
        let contents = Contents {
            backup: Zeroizing::new(text),
            ufvk,
            birthday: None,
            label: None,
        };
        let file = encrypt(&contents, "a passphrase").unwrap();
        for (at, value) in [(9, 1024u32), (13, 1), (9, 2 * 1024 * 1024), (13, 1000)] {
            let mut changed = file.clone();
            changed[at..at + 4].copy_from_slice(&value.to_le_bytes());
            let refused = file_cost(&changed).unwrap_err().to_string();
            assert!(refused.contains("work"), "{refused}");
        }
        assert!(file_cost(b"ZKFROSTA").is_err());
    }

    #[test]
    fn contents_that_do_not_go_together_are_never_written() {
        let (_, text, _) = member();
        let (_, _, other_ufvk) = member();
        let contents = Contents {
            backup: Zeroizing::new(text),
            ufvk: other_ufvk,
            birthday: None,
            label: None,
        };
        assert!(encrypt(&contents, "a passphrase").is_err());
    }

    #[test]
    fn words_round_trip_and_catch_a_miscopied_word() {
        let (backup, text, ufvk) = member();
        let words = to_words(&backup);
        assert_eq!(words.split_whitespace().count(), WORD_COUNT);
        assert_eq!(from_words(&words).unwrap().encode().unwrap(), text);
        assert_eq!(
            from_words(&words.to_uppercase()).unwrap().encode().unwrap(),
            text
        );
        restore_words(&words, &ufvk).unwrap();

        // One word changed in the sk part: the checksum or the viewing key
        // catches it, and the correction finds the original among few.
        let mut list: Vec<&str> = words.split_whitespace().collect();
        let original = list[40];
        list[40] = if original == "zoo" { "abandon" } else { "zoo" };
        let miscopied = list.join(" ");
        assert!(restore_words(&miscopied, &ufvk).is_err());
        let corrections = correct_one_word(&miscopied, &ufvk).unwrap();
        assert!(
            corrections.iter().any(|c| **c == *words),
            "{}",
            corrections.len()
        );
        assert!(corrections.len() <= 2, "{}", corrections.len());

        assert!(from_words("abandon ability").is_err());
        list[40] = "notaword";
        let refused = from_words(&list.join(" ")).unwrap_err().to_string();
        assert!(
            refused.contains("word 41") && refused.contains("not in the list"),
            "{refused}"
        );
    }
}
