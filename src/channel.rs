//! The encrypted channel between two paired devices (docs/spec.md, Pairing).
//!
//! Pairing takes three messages, carried by QR codes:
//!
//! 1. initiator → responder: an ephemeral X-Wing encapsulation key, and a
//!    commitment to 32 random bytes `r_i`;
//! 2. responder → initiator: an X-Wing ciphertext to that key, and 32 random
//!    bytes `r_r`;
//! 3. initiator → responder: `r_i`, which must open the commitment.
//!
//! Both devices then show a six-digit code computed from the transcript and
//! both random values, and the user checks that the codes match. The
//! commitment is what makes the code meaningful: when a man in the middle has
//! to choose what it sends to the initiator in step 2, `r_i` is still hidden
//! from it, and the responder's `r_r` is drawn after the attacker committed to
//! its own value. Either way it cannot search for a message that makes the two
//! codes match, so each attempt succeeds with probability one in a million.
//!
//! X-Wing combines X25519 and ML-KEM-768. During key generation this channel
//! carries the members' contributions to `sk`, from which `qsk` is derived, and
//! ZIP 2005 asks for `qsk` to be protected like `ask`. A channel resting on
//! X25519 alone would let someone who records the QR codes today recover `sk`
//! with a quantum computer later.
//!
//! After pairing, every message is sealed with XChaCha20-Poly1305 under a key
//! for its direction, with a random nonce, and bound to the pairing, its
//! direction, its kind and its session by the associated data.

use std::error::Error;
use std::fmt;

use blake2b_simd::Params;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand10::rand_core::CryptoRng;
use x_wing::kem::{Decapsulator, KeyExport, TryDecapsulate};
use x_wing::{
    CIPHERTEXT_SIZE, Ciphertext, DecapsulationKeyRejectNonContrib, ENCAPSULATION_KEY_SIZE,
    EncapsulationKey,
};
use zeroize::Zeroize;

/// The protocol version carried in every message and bound into every hash.
pub const VERSION: u8 = 0;

const PERSONAL_COMMIT: &[u8; 16] = b"ZcashFROSTv0Comm";
const PERSONAL_TRANSCRIPT: &[u8; 16] = b"ZcashFROSTv0Trns";
const PERSONAL_KEYS: &[u8; 16] = b"ZcashFROSTv0Keys";
const PERSONAL_SAS: &[u8; 16] = b"ZcashFROSTv0SAS_";
const AAD_PREFIX: &[u8] = b"ZcashFROSTv0";

pub const PAIRING_ID_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 24;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelError {
    /// A pairing message has the wrong size or an unknown version.
    Malformed(&'static str),
    /// The X-Wing ciphertext was refused (for instance a non-contributory
    /// X25519 share).
    Decapsulation,
    /// The initiator's random value does not open its commitment.
    CommitmentMismatch,
    /// A sealed message failed authentication: wrong pairing, direction, kind
    /// or session, or it was modified.
    Authentication,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelError::Malformed(what) => write!(f, "malformed pairing message: {what}"),
            ChannelError::Decapsulation => write!(f, "the pairing ciphertext was refused"),
            ChannelError::CommitmentMismatch => {
                write!(
                    f,
                    "the initiator's random value does not open its commitment"
                )
            }
            ChannelError::Authentication => write!(
                f,
                "a sealed message failed authentication (another pairing, direction, kind or session, or modified)"
            ),
        }
    }
}

impl Error for ChannelError {}

/// Which side of the pairing a device is. The initiator shows the first QR code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    fn direction_byte(self) -> u8 {
        match self {
            Role::Initiator => 0,
            Role::Responder => 1,
        }
    }

    fn other(self) -> Role {
        match self {
            Role::Initiator => Role::Responder,
            Role::Responder => Role::Initiator,
        }
    }
}

/// Message 1, initiator → responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairInit {
    pub version: u8,
    /// X-Wing encapsulation key, 1216 bytes.
    pub encapsulation_key: Vec<u8>,
    /// `H("ZcashFROSTv0Comm", r_i)`.
    pub commitment: [u8; 32],
}

/// Message 2, responder → initiator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairResponse {
    pub version: u8,
    /// X-Wing ciphertext, 1120 bytes.
    pub ciphertext: Vec<u8>,
    pub r_responder: [u8; 32],
}

/// Message 3, initiator → responder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairConfirm {
    pub version: u8,
    pub r_initiator: [u8; 32],
}

/// The initiator between messages 1 and 2. It holds the ephemeral
/// decapsulation key, which is dropped once the pairing is derived.
pub struct Initiator {
    decapsulation_key: DecapsulationKeyRejectNonContrib,
    init: PairInit,
    r_initiator: [u8; 32],
}

/// The responder between messages 2 and 3: it has the shared secret but cannot
/// compute the code before the initiator reveals `r_i`.
pub struct Responder {
    init: PairInit,
    response: PairResponse,
    shared_secret: [u8; 32],
}

/// A pairing whose code the user has not confirmed yet. Nothing secret may be
/// sent before [`PendingPairing::confirm`].
pub struct PendingPairing {
    code: u32,
    pairing: Pairing,
}

/// A confirmed pairing: the two direction keys and an identifier.
///
/// `to_bytes` holds the keys: store it encrypted, like a key share.
pub struct Pairing {
    id: [u8; PAIRING_ID_SIZE],
    role: Role,
    send_key: [u8; 32],
    receive_key: [u8; 32],
}

/// A message sealed under a pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

fn hash(personal: &[u8; 16], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = Params::new().hash_length(32).personal(personal).to_state();
    for part in parts {
        state.update(part);
    }
    state
        .finalize()
        .as_bytes()
        .try_into()
        .expect("32-byte hash")
}

fn commitment(r_initiator: &[u8; 32]) -> [u8; 32] {
    hash(PERSONAL_COMMIT, &[&[VERSION], r_initiator])
}

/// The hash of everything both sides saw, in order. Fields have fixed sizes,
/// so plain concatenation is unambiguous.
fn transcript(init: &PairInit, response: &PairResponse) -> [u8; 32] {
    hash(
        PERSONAL_TRANSCRIPT,
        &[
            &[VERSION],
            &init.encapsulation_key,
            &init.commitment,
            &response.ciphertext,
            &response.r_responder,
        ],
    )
}

/// Six decimal digits. The modulo bias of reducing 64 bits is below 2^-44.
fn short_code(transcript: &[u8; 32], r_initiator: &[u8; 32], r_responder: &[u8; 32]) -> u32 {
    let digest = hash(PERSONAL_SAS, &[transcript, r_initiator, r_responder]);
    let value = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
    (value % 1_000_000) as u32
}

fn derive_pairing(role: Role, shared_secret: &[u8; 32], transcript: &[u8; 32]) -> Pairing {
    let keys = Params::new()
        .hash_length(64)
        .personal(PERSONAL_KEYS)
        .to_state()
        .update(&[VERSION])
        .update(shared_secret)
        .update(transcript)
        .finalize();
    let bytes = keys.as_bytes();
    let initiator_to_responder: [u8; 32] = bytes[..32].try_into().expect("32 bytes");
    let responder_to_initiator: [u8; 32] = bytes[32..].try_into().expect("32 bytes");
    let (send_key, receive_key) = match role {
        Role::Initiator => (initiator_to_responder, responder_to_initiator),
        Role::Responder => (responder_to_initiator, initiator_to_responder),
    };
    // The identifier only names the pairing; it comes from public data.
    let id = transcript[..PAIRING_ID_SIZE].try_into().expect("16 bytes");
    Pairing {
        id,
        role,
        send_key,
        receive_key,
    }
}

impl Initiator {
    /// Message 1.
    pub fn start<R: CryptoRng + ?Sized>(rng: &mut R) -> (Initiator, PairInit) {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut r_initiator = [0u8; 32];
        rng.fill_bytes(&mut r_initiator);
        let started = Initiator::from_parts(seed, r_initiator);
        seed.zeroize();
        started
    }

    /// Deterministic version of [`Initiator::start`], for test vectors.
    #[doc(hidden)]
    pub fn from_parts(seed: [u8; 32], r_initiator: [u8; 32]) -> (Initiator, PairInit) {
        let decapsulation_key = DecapsulationKeyRejectNonContrib::from(seed);
        let encapsulation_key = decapsulation_key.encapsulation_key().to_bytes().to_vec();
        let init = PairInit {
            version: VERSION,
            encapsulation_key,
            commitment: commitment(&r_initiator),
        };
        let initiator = Initiator {
            decapsulation_key,
            init: init.clone(),
            r_initiator,
        };
        (initiator, init)
    }

    /// Takes message 2, returns message 3 and the pairing to confirm.
    pub fn finish(
        mut self,
        response: &PairResponse,
    ) -> Result<(PendingPairing, PairConfirm), ChannelError> {
        if response.version != VERSION {
            return Err(ChannelError::Malformed("unknown version"));
        }
        if response.ciphertext.len() != CIPHERTEXT_SIZE {
            return Err(ChannelError::Malformed("ciphertext size"));
        }
        let ciphertext = Ciphertext::try_from(response.ciphertext.as_slice())
            .map_err(|_| ChannelError::Malformed("ciphertext"))?;
        let mut shared_secret: [u8; 32] = self
            .decapsulation_key
            .try_decapsulate(&ciphertext)
            .map_err(|_| ChannelError::Decapsulation)?
            .into();
        let transcript = transcript(&self.init, response);
        let code = short_code(&transcript, &self.r_initiator, &response.r_responder);
        let pairing = derive_pairing(Role::Initiator, &shared_secret, &transcript);
        shared_secret.zeroize();
        let confirm = PairConfirm {
            version: VERSION,
            r_initiator: self.r_initiator,
        };
        self.r_initiator.zeroize();
        Ok((PendingPairing { code, pairing }, confirm))
    }
}

impl Responder {
    /// Takes message 1, returns message 2.
    pub fn respond<R: CryptoRng + ?Sized>(
        init: &PairInit,
        rng: &mut R,
    ) -> Result<(Responder, PairResponse), ChannelError> {
        let mut randomness = [0u8; 64];
        rng.fill_bytes(&mut randomness);
        let mut r_responder = [0u8; 32];
        rng.fill_bytes(&mut r_responder);
        let result = Responder::from_parts(init, randomness, r_responder);
        randomness.zeroize();
        result
    }

    /// Deterministic version of [`Responder::respond`], for test vectors.
    #[doc(hidden)]
    pub fn from_parts(
        init: &PairInit,
        encapsulation_randomness: [u8; 64],
        r_responder: [u8; 32],
    ) -> Result<(Responder, PairResponse), ChannelError> {
        if init.version != VERSION {
            return Err(ChannelError::Malformed("unknown version"));
        }
        if init.encapsulation_key.len() != ENCAPSULATION_KEY_SIZE {
            return Err(ChannelError::Malformed("encapsulation key size"));
        }
        let encapsulation_key = EncapsulationKey::try_from(init.encapsulation_key.as_slice())
            .map_err(|_| ChannelError::Malformed("encapsulation key"))?;
        let (ciphertext, shared_secret) =
            encapsulation_key.encapsulate_deterministic(&encapsulation_randomness.into());
        let response = PairResponse {
            version: VERSION,
            ciphertext: ciphertext.to_vec(),
            r_responder,
        };
        let responder = Responder {
            init: init.clone(),
            response: response.clone(),
            shared_secret: shared_secret.into(),
        };
        Ok((responder, response))
    }

    /// Takes message 3: checks the commitment and returns the pairing to confirm.
    pub fn finish(mut self, confirm: &PairConfirm) -> Result<PendingPairing, ChannelError> {
        if confirm.version != VERSION {
            return Err(ChannelError::Malformed("unknown version"));
        }
        if commitment(&confirm.r_initiator) != self.init.commitment {
            self.shared_secret.zeroize();
            return Err(ChannelError::CommitmentMismatch);
        }
        let transcript = transcript(&self.init, &self.response);
        let code = short_code(
            &transcript,
            &confirm.r_initiator,
            &self.response.r_responder,
        );
        let pairing = derive_pairing(Role::Responder, &self.shared_secret, &transcript);
        self.shared_secret.zeroize();
        Ok(PendingPairing { code, pairing })
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

impl PendingPairing {
    /// The six-digit code to show, for the user to compare with the other device.
    pub fn code(&self) -> String {
        format!("{:06}", self.code)
    }

    /// Call only once the user has confirmed that both devices show the same code.
    pub fn confirm(self) -> Pairing {
        self.pairing
    }

    /// Seals a message before the code is confirmed. Only for messages with no
    /// secret, such as the coordinator's DKG round 1, which rides with
    /// pair-confirm: until the user confirms the code, the other end may be a
    /// man in the middle.
    pub fn seal_public<R: CryptoRng + ?Sized>(
        &self,
        kind: u8,
        session: &[u8],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Sealed {
        self.pairing.seal(kind, session, plaintext, rng)
    }

    pub fn id(&self) -> [u8; PAIRING_ID_SIZE] {
        self.pairing.id
    }
}

impl Pairing {
    pub fn id(&self) -> [u8; PAIRING_ID_SIZE] {
        self.id
    }

    pub fn role(&self) -> Role {
        self.role
    }

    fn associated_data(&self, sender: Role, kind: u8, session: &[u8]) -> Vec<u8> {
        let session_len = u8::try_from(session.len()).expect("session ids are short");
        let mut aad = Vec::with_capacity(AAD_PREFIX.len() + PAIRING_ID_SIZE + 3 + session.len());
        aad.extend_from_slice(AAD_PREFIX);
        aad.extend_from_slice(&self.id);
        aad.push(sender.direction_byte());
        aad.push(kind);
        aad.push(session_len);
        aad.extend_from_slice(session);
        aad
    }

    /// Seals a message from this device. `kind` and `session` are bound to it:
    /// the other side must open it with the same values.
    pub fn seal<R: CryptoRng + ?Sized>(
        &self,
        kind: u8,
        session: &[u8],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Sealed {
        let mut nonce = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce);
        self.seal_with_nonce(kind, session, plaintext, nonce)
    }

    /// [`Pairing::seal`] with a given nonce, for test vectors. A nonce must
    /// never be used twice under the same key.
    #[doc(hidden)]
    pub fn seal_with_nonce(
        &self,
        kind: u8,
        session: &[u8],
        plaintext: &[u8],
        nonce: [u8; NONCE_SIZE],
    ) -> Sealed {
        let aad = self.associated_data(self.role, kind, session);
        let cipher = XChaCha20Poly1305::new(&self.send_key.into());
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("encryption of an in-memory message");
        Sealed { nonce, ciphertext }
    }

    /// Opens a message from the other device.
    pub fn open(&self, kind: u8, session: &[u8], sealed: &Sealed) -> Result<Vec<u8>, ChannelError> {
        let aad = self.associated_data(self.role.other(), kind, session);
        let cipher = XChaCha20Poly1305::new(&self.receive_key.into());
        cipher
            .decrypt(
                &XNonce::from(sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| ChannelError::Authentication)
    }

    /// Secret: the two keys. Store it encrypted.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 + PAIRING_ID_SIZE + 64);
        bytes.push(VERSION);
        bytes.push(self.role.direction_byte());
        bytes.extend_from_slice(&self.id);
        bytes.extend_from_slice(&self.send_key);
        bytes.extend_from_slice(&self.receive_key);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Pairing, ChannelError> {
        if bytes.len() != 2 + PAIRING_ID_SIZE + 64 || bytes[0] != VERSION {
            return Err(ChannelError::Malformed("stored pairing"));
        }
        let role = match bytes[1] {
            0 => Role::Initiator,
            1 => Role::Responder,
            _ => return Err(ChannelError::Malformed("stored pairing role")),
        };
        let id = bytes[2..18].try_into().expect("16 bytes");
        let send_key = bytes[18..50].try_into().expect("32 bytes");
        let receive_key = bytes[50..82].try_into().expect("32 bytes");
        Ok(Pairing {
            id,
            role,
            send_key,
            receive_key,
        })
    }
}

impl Drop for Pairing {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.receive_key.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand10::rand_core::UnwrapErr;
    use rand10::rngs::SysRng;

    fn rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    fn pair() -> (Pairing, Pairing, String, String) {
        let mut rng = rng();
        let (initiator, init) = Initiator::start(&mut rng);
        let (responder, response) = Responder::respond(&init, &mut rng).unwrap();
        let (pending_i, confirm) = initiator.finish(&response).unwrap();
        let pending_r = responder.finish(&confirm).unwrap();
        let (code_i, code_r) = (pending_i.code(), pending_r.code());
        (pending_i.confirm(), pending_r.confirm(), code_i, code_r)
    }

    #[test]
    fn both_sides_agree_and_messages_go_both_ways() {
        let (initiator, responder, code_i, code_r) = pair();
        assert_eq!(code_i, code_r);
        assert_eq!(code_i.len(), 6);
        assert_eq!(initiator.id(), responder.id());

        let mut rng = rng();
        let sealed = initiator.seal(7, b"session", b"to the co-signer", &mut rng);
        assert_eq!(
            responder.open(7, b"session", &sealed).unwrap(),
            b"to the co-signer"
        );
        let sealed = responder.seal(8, b"", b"to the coordinator", &mut rng);
        assert_eq!(
            initiator.open(8, b"", &sealed).unwrap(),
            b"to the coordinator"
        );
    }

    #[test]
    fn a_sealed_message_is_bound_to_its_direction_kind_session_and_bytes() {
        let (initiator, responder, _, _) = pair();
        let mut rng = rng();
        let sealed = initiator.seal(1, b"s1", b"message", &mut rng);
        // Reflected back to its sender.
        assert_eq!(
            initiator.open(1, b"s1", &sealed),
            Err(ChannelError::Authentication)
        );
        assert_eq!(
            responder.open(2, b"s1", &sealed),
            Err(ChannelError::Authentication)
        );
        assert_eq!(
            responder.open(1, b"s2", &sealed),
            Err(ChannelError::Authentication)
        );
        let mut modified = sealed.clone();
        modified.ciphertext[0] ^= 1;
        assert_eq!(
            responder.open(1, b"s1", &modified),
            Err(ChannelError::Authentication)
        );
        // Another pairing cannot read it.
        let (_, other_responder, _, _) = pair();
        assert_eq!(
            other_responder.open(1, b"s1", &sealed),
            Err(ChannelError::Authentication)
        );
    }

    #[test]
    fn a_wrong_reveal_is_refused() {
        let mut rng = rng();
        let (initiator, init) = Initiator::start(&mut rng);
        let (responder, response) = Responder::respond(&init, &mut rng).unwrap();
        let (_, mut confirm) = initiator.finish(&response).unwrap();
        confirm.r_initiator[0] ^= 1;
        assert!(matches!(
            responder.finish(&confirm),
            Err(ChannelError::CommitmentMismatch)
        ));
    }

    /// A relay that runs its own pairing with each side ends up with two
    /// different codes (the chance of a match is one in a million).
    #[test]
    fn a_man_in_the_middle_gets_different_codes() {
        let mut rng = rng();
        let (initiator, init) = Initiator::start(&mut rng);
        // The attacker answers the initiator itself...
        let (_, to_initiator) = Responder::respond(&init, &mut rng).unwrap();
        // ...and starts its own pairing with the responder.
        let (attacker, attacker_init) = Initiator::start(&mut rng);
        let (responder, response) = Responder::respond(&attacker_init, &mut rng).unwrap();
        let (pending_i, _) = initiator.finish(&to_initiator).unwrap();
        let (_, attacker_confirm) = attacker.finish(&response).unwrap();
        let pending_r = responder.finish(&attacker_confirm).unwrap();
        assert_ne!(pending_i.code(), pending_r.code());
        assert_ne!(pending_i.confirm().id(), pending_r.confirm().id());
    }

    #[test]
    fn a_non_contributory_x25519_share_is_refused() {
        let mut rng = rng();
        let (initiator, init) = Initiator::start(&mut rng);
        let (_, mut response) = Responder::respond(&init, &mut rng).unwrap();
        // The X25519 part is the last 32 bytes of the ciphertext; the all-zero
        // point gives an all-zero shared secret whatever the key.
        let len = response.ciphertext.len();
        response.ciphertext[len - 32..].fill(0);
        assert!(matches!(
            initiator.finish(&response),
            Err(ChannelError::Decapsulation)
        ));
    }

    #[test]
    fn wrong_sizes_and_versions_are_refused() {
        let mut rng = rng();
        let (_, mut init) = Initiator::start(&mut rng);
        init.encapsulation_key.pop();
        assert!(matches!(
            Responder::respond(&init, &mut rng),
            Err(ChannelError::Malformed(_))
        ));
        let (initiator, mut init) = Initiator::start(&mut rng);
        init.version = 1;
        assert!(matches!(
            Responder::respond(&init, &mut rng),
            Err(ChannelError::Malformed(_))
        ));
        init.version = VERSION;
        let (_, mut response) = Responder::respond(&init, &mut rng).unwrap();
        response.ciphertext.push(0);
        assert!(matches!(
            initiator.finish(&response),
            Err(ChannelError::Malformed(_))
        ));
    }

    #[test]
    fn a_stored_pairing_round_trips() {
        let (initiator, responder, _, _) = pair();
        let restored = Pairing::from_bytes(&responder.to_bytes()).unwrap();
        let mut rng = rng();
        let sealed = initiator.seal(3, b"", b"after a restart", &mut rng);
        assert_eq!(restored.open(3, b"", &sealed).unwrap(), b"after a restart");
        assert!(Pairing::from_bytes(&responder.to_bytes()[1..]).is_err());
    }
}
