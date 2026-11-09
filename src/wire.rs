//! The wire format (docs/spec.md § 2): CBOR messages, carried as Uniform
//! Resources (`ur:zcash-frost/...`), animated as multi-part QR codes when large.
//!
//! A UR payload is a CBOR array of one or more messages. Each message is a map
//! `{1: version, 2: kind, 3: body}`, where `body` is the CBOR encoding of the
//! kind's own map. Pairing messages travel in clear; everything after pairing
//! is sealed, and only the sealed envelope is visible on the wire.
//!
//! UR's fountain codes check that parts belong together with a CRC-32, which a
//! forger can match. That is fine here: pairing messages are covered by the
//! pairing code, and sealed messages by their authentication tag, so a message
//! assembled from forged parts is refused one layer up.

use std::error::Error;
use std::fmt;

use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use rand10::rand_core::CryptoRng;

use crate::channel::{self, NONCE_SIZE, PAIRING_ID_SIZE, Pairing};

pub const VERSION: u8 = 0;
pub const UR_TYPE: &str = "zcash-frost";
/// The largest payload a reader accepts, after reassembly (a PCZT for a few
/// spends is well under this).
pub const MAX_PAYLOAD_SIZE: usize = 512 * 1024;
/// The most fragments a reader accepts for one payload.
pub const MAX_FRAGMENTS: usize = 4096;
/// Session identifiers are short.
pub const MAX_SESSION_SIZE: usize = 32;

/// Message kinds. Pairing kinds travel in clear; the others only inside
/// [`SEALED`], where the kind is bound to the ciphertext.
pub mod kind {
    pub const PAIR_INIT: u8 = 1;
    pub const PAIR_RESPONSE: u8 = 2;
    pub const PAIR_CONFIRM: u8 = 3;
    pub const SEALED: u8 = 16;
    pub const DKG_ROUND1: u8 = 32;
    pub const DKG_ROUND2: u8 = 33;
    pub const SIGN_COMMITMENTS: u8 = 48;
    pub const SIGN_REQUEST: u8 = 49;
    pub const SIGN_REPLY: u8 = 50;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    TooLarge,
    TooManyFragments,
    WrongUrType(String),
    UnknownVersion(u8),
    UnexpectedKind(u8),
    WrongPairing,
    Malformed(String),
    Channel(channel::ChannelError),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::TooLarge => write!(f, "the message is larger than {MAX_PAYLOAD_SIZE} bytes"),
            WireError::TooManyFragments => {
                write!(f, "the QR stream has more than {MAX_FRAGMENTS} fragments")
            }
            WireError::WrongUrType(found) => write!(f, "not a {UR_TYPE} QR code (found {found})"),
            WireError::UnknownVersion(v) => write!(f, "unknown message version {v}"),
            WireError::UnexpectedKind(k) => write!(f, "unexpected message kind {k}"),
            WireError::WrongPairing => write!(f, "the message belongs to another pairing"),
            WireError::Malformed(what) => write!(f, "malformed message: {what}"),
            WireError::Channel(e) => write!(f, "{e}"),
        }
    }
}

impl Error for WireError {}

impl From<channel::ChannelError> for WireError {
    fn from(e: channel::ChannelError) -> Self {
        WireError::Channel(e)
    }
}

fn malformed(e: impl fmt::Display) -> WireError {
    WireError::Malformed(e.to_string())
}

/// One message on the wire.
#[derive(Encode, Decode, Debug, Clone, PartialEq, Eq)]
#[cbor(map)]
pub struct Message {
    #[n(1)]
    pub version: u8,
    #[n(2)]
    pub kind: u8,
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub body: Vec<u8>,
}

#[derive(Encode, Decode)]
#[cbor(map)]
struct PairInitBody {
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    encapsulation_key: Vec<u8>,
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    commitment: [u8; 32],
}

#[derive(Encode, Decode)]
#[cbor(map)]
struct PairResponseBody {
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    ciphertext: Vec<u8>,
    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    r_responder: [u8; 32],
}

#[derive(Encode, Decode)]
#[cbor(map)]
struct PairConfirmBody {
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    r_initiator: [u8; 32],
}

#[derive(Encode, Decode)]
#[cbor(map)]
struct SealedBody {
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    pairing: [u8; PAIRING_ID_SIZE],
    #[n(2)]
    kind: u8,
    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    session: Vec<u8>,
    #[n(4)]
    #[cbor(with = "minicbor::bytes")]
    nonce: [u8; NONCE_SIZE],
    #[n(5)]
    #[cbor(with = "minicbor::bytes")]
    ciphertext: Vec<u8>,
}

fn encode<T: Encode<()>>(value: &T) -> Vec<u8> {
    minicbor::to_vec(value).expect("encoding to memory cannot fail")
}

fn decode<'b, T: Decode<'b, ()>>(bytes: &'b [u8]) -> Result<T, WireError> {
    minicbor::decode(bytes).map_err(malformed)
}

impl Message {
    fn new(kind: u8, body: Vec<u8>) -> Message {
        Message {
            version: VERSION,
            kind,
            body,
        }
    }

    fn expect(&self, kind: u8) -> Result<(), WireError> {
        if self.version != VERSION {
            return Err(WireError::UnknownVersion(self.version));
        }
        if self.kind != kind {
            return Err(WireError::UnexpectedKind(self.kind));
        }
        Ok(())
    }

    pub fn pair_init(init: &channel::PairInit) -> Message {
        Message::new(
            kind::PAIR_INIT,
            encode(&PairInitBody {
                encapsulation_key: init.encapsulation_key.clone(),
                commitment: init.commitment,
            }),
        )
    }

    pub fn to_pair_init(&self) -> Result<channel::PairInit, WireError> {
        self.expect(kind::PAIR_INIT)?;
        let body: PairInitBody = decode(&self.body)?;
        Ok(channel::PairInit {
            version: self.version,
            encapsulation_key: body.encapsulation_key,
            commitment: body.commitment,
        })
    }

    pub fn pair_response(response: &channel::PairResponse) -> Message {
        Message::new(
            kind::PAIR_RESPONSE,
            encode(&PairResponseBody {
                ciphertext: response.ciphertext.clone(),
                r_responder: response.r_responder,
            }),
        )
    }

    pub fn to_pair_response(&self) -> Result<channel::PairResponse, WireError> {
        self.expect(kind::PAIR_RESPONSE)?;
        let body: PairResponseBody = decode(&self.body)?;
        Ok(channel::PairResponse {
            version: self.version,
            ciphertext: body.ciphertext,
            r_responder: body.r_responder,
        })
    }

    pub fn pair_confirm(confirm: &channel::PairConfirm) -> Message {
        Message::new(
            kind::PAIR_CONFIRM,
            encode(&PairConfirmBody {
                r_initiator: confirm.r_initiator,
            }),
        )
    }

    pub fn to_pair_confirm(&self) -> Result<channel::PairConfirm, WireError> {
        self.expect(kind::PAIR_CONFIRM)?;
        let body: PairConfirmBody = decode(&self.body)?;
        Ok(channel::PairConfirm {
            version: self.version,
            r_initiator: body.r_initiator,
        })
    }

    /// Seals `plaintext` of the given inner kind under the pairing.
    pub fn seal<R: CryptoRng + ?Sized>(
        pairing: &Pairing,
        inner_kind: u8,
        session: &[u8],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Message, WireError> {
        if session.len() > MAX_SESSION_SIZE {
            return Err(WireError::Malformed("session id too long".into()));
        }
        let sealed = pairing.seal(inner_kind, session, plaintext, rng);
        Ok(Message::new(
            kind::SEALED,
            encode(&SealedBody {
                pairing: pairing.id(),
                kind: inner_kind,
                session: session.to_vec(),
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
            }),
        ))
    }

    /// Seals a message with no secret before the pairing code is confirmed
    /// (see [`channel::PendingPairing::seal_public`]).
    pub fn seal_public<R: CryptoRng + ?Sized>(
        pending: &channel::PendingPairing,
        inner_kind: u8,
        session: &[u8],
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<Message, WireError> {
        if session.len() > MAX_SESSION_SIZE {
            return Err(WireError::Malformed("session id too long".into()));
        }
        let sealed = pending.seal_public(inner_kind, session, plaintext, rng);
        Ok(Message::new(
            kind::SEALED,
            encode(&SealedBody {
                pairing: pending.id(),
                kind: inner_kind,
                session: session.to_vec(),
                nonce: sealed.nonce,
                ciphertext: sealed.ciphertext,
            }),
        ))
    }

    /// Opens a sealed message of the expected inner kind. Returns the session
    /// id it is bound to and the plaintext.
    pub fn open(&self, pairing: &Pairing, inner_kind: u8) -> Result<(Vec<u8>, Vec<u8>), WireError> {
        self.expect(kind::SEALED)?;
        let body: SealedBody = decode(&self.body)?;
        if body.pairing != pairing.id() {
            return Err(WireError::WrongPairing);
        }
        if body.kind != inner_kind {
            return Err(WireError::UnexpectedKind(body.kind));
        }
        if body.session.len() > MAX_SESSION_SIZE {
            return Err(WireError::Malformed("session id too long".into()));
        }
        let plaintext = pairing.open(
            inner_kind,
            &body.session,
            &channel::Sealed {
                nonce: body.nonce,
                ciphertext: body.ciphertext,
            },
        )?;
        Ok((body.session, plaintext))
    }
}

/// The CBOR payload of one QR stream: one or more messages.
pub fn encode_payload(messages: &[Message]) -> Vec<u8> {
    encode(&messages.to_vec())
}

pub fn decode_payload(bytes: &[u8]) -> Result<Vec<Message>, WireError> {
    if bytes.len() > MAX_PAYLOAD_SIZE {
        return Err(WireError::TooLarge);
    }
    let messages: Vec<Message> = decode(bytes)?;
    if messages.is_empty() {
        return Err(WireError::Malformed("no message".into()));
    }
    if let Some(m) = messages.iter().find(|m| m.version != VERSION) {
        return Err(WireError::UnknownVersion(m.version));
    }
    Ok(messages)
}

/// The QR parts for a payload: one part if it fits in `max_fragment_length`
/// bytes, otherwise an endless fountain-coded stream to show in a loop.
pub fn encoder(
    payload: &[u8],
    max_fragment_length: usize,
) -> Result<ur::Encoder<'static>, WireError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(WireError::TooLarge);
    }
    ur::Encoder::new(payload, max_fragment_length, UR_TYPE).map_err(malformed)
}

/// A payload as one UR text (`ur:zcash-frost/...`), for carriers that are not
/// QR codes: a file, a pasted text. [`Reader`] reads it back.
pub fn single_part(payload: &[u8]) -> Result<String, WireError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(WireError::TooLarge);
    }
    Ok(ur::encode(payload, &ur::Type::Custom(UR_TYPE)))
}

/// Reassembles a payload from scanned QR parts, in any order, with repeats.
#[derive(Default)]
pub struct Reader {
    decoder: ur::Decoder,
}

impl Reader {
    /// Takes one scanned part. Returns the payload once complete.
    pub fn receive(&mut self, part: &str) -> Result<Option<Vec<u8>>, WireError> {
        let part = part.trim().to_ascii_lowercase();
        let ur_type = part
            .strip_prefix("ur:")
            .and_then(|rest| rest.split('/').next())
            .unwrap_or_default();
        if ur_type != UR_TYPE {
            return Err(WireError::WrongUrType(ur_type.to_string()));
        }
        // A short payload fits in a single part.
        if let Ok((ur::ur::Kind::SinglePart, payload)) = ur::decode(&part) {
            return check_size(payload).map(Some);
        }
        self.decoder.receive(&part).map_err(malformed)?;
        if self.decoder.fragment_count() > MAX_FRAGMENTS {
            return Err(WireError::TooManyFragments);
        }
        if !self.decoder.complete() {
            return Ok(None);
        }
        match self.decoder.message().map_err(malformed)? {
            Some(payload) => check_size(payload).map(Some),
            None => Ok(None),
        }
    }

    /// How far along the stream is, for a progress bar: (resolved, total).
    pub fn progress(&self) -> (usize, usize) {
        (
            self.decoder.resolved_fragment_count().unwrap_or(0),
            self.decoder.fragment_count(),
        )
    }
}

fn check_size(payload: Vec<u8>) -> Result<Vec<u8>, WireError> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(WireError::TooLarge);
    }
    Ok(payload)
}

/// Byte strings inside CBOR bodies, for the payloads of later layers.
pub type Bytes = ByteVec;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{Initiator, Responder};
    use rand10::rand_core::UnwrapErr;
    use rand10::rngs::SysRng;

    fn rng() -> UnwrapErr<SysRng> {
        UnwrapErr(SysRng)
    }

    /// Carries a payload across "QR codes": encodes it into parts, shuffles
    /// and repeats some, and feeds a reader until it completes.
    fn through_qr(payload: &[u8], fragment: usize) -> Vec<u8> {
        let mut encoder = encoder(payload, fragment).unwrap();
        let mut reader = Reader::default();
        let mut parts: Vec<String> = (0..encoder.fragment_count() * 3)
            .map(|_| encoder.next_part().unwrap())
            .collect();
        parts.reverse();
        for part in parts {
            if let Some(done) = reader.receive(&part.to_uppercase()).unwrap() {
                return done;
            }
        }
        panic!("the stream never completed");
    }

    #[test]
    fn a_whole_pairing_and_a_sealed_message_survive_the_qr_transport() {
        let mut rng = rng();
        let (initiator, init) = Initiator::start(&mut rng);
        let qr1 = through_qr(&encode_payload(&[Message::pair_init(&init)]), 200);
        let init = decode_payload(&qr1).unwrap()[0].to_pair_init().unwrap();

        let (responder, response) = Responder::respond(&init, &mut rng).unwrap();
        let qr2 = through_qr(&encode_payload(&[Message::pair_response(&response)]), 200);
        let response = decode_payload(&qr2).unwrap()[0].to_pair_response().unwrap();

        let (pending_i, confirm) = initiator.finish(&response).unwrap();
        let qr3 = through_qr(&encode_payload(&[Message::pair_confirm(&confirm)]), 200);
        let confirm = decode_payload(&qr3).unwrap()[0].to_pair_confirm().unwrap();
        let pending_r = responder.finish(&confirm).unwrap();
        assert_eq!(pending_i.code(), pending_r.code());
        let (coordinator, cosigner) = (pending_i.confirm(), pending_r.confirm());

        let big = vec![7u8; 20_000];
        let sealed =
            Message::seal(&coordinator, kind::SIGN_REQUEST, b"s1", &big, &mut rng).unwrap();
        let carried = through_qr(&encode_payload(&[sealed]), 300);
        let message = &decode_payload(&carried).unwrap()[0];
        let (session, plaintext) = message.open(&cosigner, kind::SIGN_REQUEST).unwrap();
        assert_eq!((session.as_slice(), plaintext), (b"s1".as_slice(), big));
        // The kind is bound: the same message cannot be opened as another kind.
        assert_eq!(
            message.open(&cosigner, kind::SIGN_REPLY),
            Err(WireError::UnexpectedKind(kind::SIGN_REQUEST))
        );
    }

    #[test]
    fn parts_of_two_streams_do_not_mix() {
        let mut first = encoder(&[1u8; 3_000], 100).unwrap();
        let mut second = encoder(&[2u8; 3_000], 100).unwrap();
        let mut reader = Reader::default();
        reader.receive(&first.next_part().unwrap()).unwrap();
        assert!(reader.receive(&second.next_part().unwrap()).is_err());
    }

    #[test]
    fn other_qr_codes_and_oversized_payloads_are_refused() {
        let mut reader = Reader::default();
        let crypto_psbt = ur::encode(b"\x41\x00", &ur::Type::Custom("crypto-psbt"));
        assert!(matches!(
            reader.receive(&crypto_psbt),
            Err(WireError::WrongUrType(_))
        ));
        assert!(matches!(
            reader.receive("https://example.com"),
            Err(WireError::WrongUrType(_))
        ));
        assert_eq!(
            decode_payload(&vec![0u8; MAX_PAYLOAD_SIZE + 1]),
            Err(WireError::TooLarge)
        );
        assert!(encoder(&vec![0u8; MAX_PAYLOAD_SIZE + 1], 200).is_err());
    }

    #[test]
    fn unknown_versions_and_garbage_are_refused() {
        let mut message = Message::pair_confirm(&channel::PairConfirm {
            version: VERSION,
            r_initiator: [3; 32],
        });
        message.version = 1;
        assert_eq!(
            decode_payload(&encode_payload(&[message])),
            Err(WireError::UnknownVersion(1))
        );
        assert!(decode_payload(b"\xff\x00garbage").is_err());
        assert!(decode_payload(&encode_payload(&[])).is_err());
    }

    #[test]
    fn a_sealed_message_for_another_pairing_is_refused() {
        let mut rng = rng();
        let pair = || {
            let mut rng = UnwrapErr(SysRng);
            let (i, init) = Initiator::start(&mut rng);
            let (r, response) = Responder::respond(&init, &mut rng).unwrap();
            let (pi, confirm) = i.finish(&response).unwrap();
            (pi.confirm(), r.finish(&confirm).unwrap().confirm())
        };
        let (coordinator, _) = pair();
        let (_, stranger) = pair();
        let sealed = Message::seal(&coordinator, kind::DKG_ROUND1, b"", b"x", &mut rng).unwrap();
        assert_eq!(
            sealed.open(&stranger, kind::DKG_ROUND1),
            Err(WireError::WrongPairing)
        );
    }
}
