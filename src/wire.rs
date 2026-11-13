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

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use minicbor::bytes::ByteVec;
use minicbor::{Decode, Encode};
use rand10::rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::channel::{self, NONCE_SIZE, PAIRING_ID_SIZE, Pairing};

/// The message format version, carried in every message.
pub const VERSION: u8 = 0;
/// The Uniform Resource type: texts and QR codes start with `ur:zcash-frost/`.
pub const UR_TYPE: &str = "zcash-frost";
/// The largest payload a reader accepts, after reassembly (a PCZT for a few
/// spends is well under this).
pub const MAX_PAYLOAD_SIZE: usize = 512 * 1024;
/// The most fragments a reader accepts for one payload. The fountain decoder's
/// work grows with the cube of the fragment count when parts are crafted, so
/// this stays well above what a real message needs (a few hundred at most)
/// and well below what would let one stream stall a reader.
pub const MAX_FRAGMENTS: usize = 1024;
/// Session identifiers are short.
pub const MAX_SESSION_SIZE: usize = 32;

/// Message kinds. Pairing kinds travel in clear; the others only inside
/// [`SEALED`](crate::wire::kind::SEALED), where the kind is bound to the
/// ciphertext.
pub mod kind {
    /// Pairing message 1, in clear (spec § 3.1).
    pub const PAIR_INIT: u8 = 1;
    /// Pairing message 2, in clear.
    pub const PAIR_RESPONSE: u8 = 2;
    /// Pairing message 3, in clear.
    pub const PAIR_CONFIRM: u8 = 3;
    /// The envelope of every message after pairing (spec § 3.4).
    pub const SEALED: u8 = 16;
    /// DKG round 1 packages and `sk` commitments (spec § 4).
    pub const DKG_ROUND1: u8 = 32;
    /// DKG round 2 packages, `sk` reveals and the transcript echo.
    pub const DKG_ROUND2: u8 = 33;
    /// The co-signer's acknowledgement that key generation is done and member
    /// 3 is exported (spec § 4).
    pub const DKG_DONE: u8 = 34;
    // 48 to 50 were the three signing messages of draft v0.1: reserved, so a
    // device from that draft and one from v1.0 refuse each other's messages.
    /// The coordinator's request: the PCZT and its commitments (spec § 5).
    pub const SIGN_REQUEST: u8 = 51;
    /// The co-signer's commitments and shares, or its refusal.
    pub const SIGN_REPLY: u8 = 52;
    /// The old group's public key package and viewing key, from the co-signer
    /// to a new coordinator during recovery (spec § 7.2).
    pub const GROUP_INFO: u8 = 64;
}

/// Why a message or a QR stream was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Over [`MAX_PAYLOAD_SIZE`] bytes, or a part longer than any message.
    TooLarge,
    /// A stream announcing more than [`MAX_FRAGMENTS`] fragments.
    TooManyFragments,
    /// Not a `ur:zcash-frost` text: the type found.
    WrongUrType(String),
    /// A message version this code does not know.
    UnknownVersion(u8),
    /// A message of another kind than expected.
    UnexpectedKind(u8),
    /// A sealed message for another pairing.
    WrongPairing,
    /// Not valid CBOR, UR or fountain data, or a stream that does not complete.
    Malformed(String),
    /// Refused by the pairing layer, for instance a failed authentication.
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
    /// [`VERSION`].
    #[n(1)]
    pub version: u8,
    /// One of [`kind`].
    #[n(2)]
    pub kind: u8,
    /// The CBOR encoding of the kind's own map.
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

    /// A pair-init message.
    pub fn pair_init(init: &channel::PairInit) -> Message {
        Message::new(
            kind::PAIR_INIT,
            encode(&PairInitBody {
                encapsulation_key: init.encapsulation_key.clone(),
                commitment: init.commitment,
            }),
        )
    }

    /// Reads a pair-init message; refuses any other kind.
    pub fn to_pair_init(&self) -> Result<channel::PairInit, WireError> {
        self.expect(kind::PAIR_INIT)?;
        let body: PairInitBody = decode(&self.body)?;
        Ok(channel::PairInit {
            version: self.version,
            encapsulation_key: body.encapsulation_key,
            commitment: body.commitment,
        })
    }

    /// A pair-response message.
    pub fn pair_response(response: &channel::PairResponse) -> Message {
        Message::new(
            kind::PAIR_RESPONSE,
            encode(&PairResponseBody {
                ciphertext: response.ciphertext.clone(),
                r_responder: response.r_responder,
            }),
        )
    }

    /// Reads a pair-response message; refuses any other kind.
    pub fn to_pair_response(&self) -> Result<channel::PairResponse, WireError> {
        self.expect(kind::PAIR_RESPONSE)?;
        let body: PairResponseBody = decode(&self.body)?;
        Ok(channel::PairResponse {
            version: self.version,
            ciphertext: body.ciphertext,
            r_responder: body.r_responder,
        })
    }

    /// A pair-confirm message.
    pub fn pair_confirm(confirm: &channel::PairConfirm) -> Message {
        Message::new(
            kind::PAIR_CONFIRM,
            encode(&PairConfirmBody {
                r_initiator: confirm.r_initiator,
            }),
        )
    }

    /// Reads a pair-confirm message; refuses any other kind.
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
    /// id it is bound to and the plaintext, wiped when dropped.
    pub fn open(
        &self,
        pairing: &Pairing,
        inner_kind: u8,
    ) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), WireError> {
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

/// Reads the payload of a QR stream: at most [`MAX_PAYLOAD_SIZE`] bytes, at
/// least one message, every message in a known version.
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
    /// The sequence numbers of the parts taken so far.
    sequences: BTreeSet<u32>,
}

impl Reader {
    /// Takes one scanned part. Returns the payload once complete.
    pub fn receive(&mut self, part: &str) -> Result<Option<Vec<u8>>, WireError> {
        // Two characters per byte, plus the prefix and a checksum.
        if part.len() > 2 * MAX_PAYLOAD_SIZE + 64 {
            return Err(WireError::TooLarge);
        }
        let part = part.trim().to_ascii_lowercase();
        let ur_type = part
            .strip_prefix("ur:")
            .and_then(|rest| rest.split('/').next())
            .unwrap_or_default();
        if ur_type != UR_TYPE {
            return Err(WireError::WrongUrType(ur_type.to_string()));
        }
        let header = match ur::decode(&part).map_err(malformed)? {
            // A short payload fits in a single part.
            (ur::ur::Kind::SinglePart, payload) => return check_size(payload).map(Some),
            (ur::ur::Kind::MultiPart, cbor) => PartHeader::check(&cbor)?,
        };
        let new = !self.sequences.contains(&header.sequence);
        if new && self.sequences.len() >= max_parts(header.count) {
            return Err(WireError::Malformed(
                "the QR stream does not complete: scan it again".into(),
            ));
        }
        self.decoder.receive(&part).map_err(malformed)?;
        self.sequences.insert(header.sequence);
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

/// How many different parts a stream may take without completing. An honest
/// fountain stream completes after little more than one part per fragment;
/// every part kept costs the decoder memory and time.
fn max_parts(fragments: usize) -> usize {
    2 * fragments + 32
}

/// The header of one fountain-coded part, checked before the `ur` decoder
/// sees the part. That decoder sizes its work by the fragment count a part
/// announces: for a mixed part it builds a table with one entry per fragment
/// and shuffles it in quadratic time, so a single crafted part announcing
/// millions of fragments would stall the reader for minutes or exhaust its
/// memory before any limit could be checked on the decoder.
struct PartHeader {
    sequence: u32,
    count: usize,
}

impl PartHeader {
    fn check(cbor: &[u8]) -> Result<PartHeader, WireError> {
        let (sequence, count, message_length, fragment_length) =
            PartHeader::read(cbor).map_err(malformed)?;
        let (count, message_length) = (count as usize, message_length as usize);
        if count > MAX_FRAGMENTS {
            return Err(WireError::TooManyFragments);
        }
        if message_length > MAX_PAYLOAD_SIZE {
            return Err(WireError::TooLarge);
        }
        // An encoder cuts the message into fragments of one length and pads
        // the last one, so count = ceil(message length / fragment length).
        if fragment_length == 0
            || fragment_length > message_length
            || count != message_length.div_ceil(fragment_length)
        {
            return Err(WireError::Malformed("inconsistent QR part".into()));
        }
        Ok(PartHeader { sequence, count })
    }

    /// `[sequence, count, message length, checksum, fragment]`, as UR encodes
    /// a part (BCR-2020-005).
    fn read(cbor: &[u8]) -> Result<(u32, u32, u32, usize), minicbor::decode::Error> {
        let mut decoder = minicbor::Decoder::new(cbor);
        if decoder.array()? != Some(5) {
            return Err(minicbor::decode::Error::message("not a QR part"));
        }
        let sequence = decoder.u32()?;
        let count = decoder.u32()?;
        let message_length = decoder.u32()?;
        let _checksum = decoder.u32()?;
        let fragment_length = decoder.bytes()?.len();
        Ok((sequence, count, message_length, fragment_length))
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
        assert_eq!(
            (session.as_slice(), plaintext.as_slice()),
            (b"s1".as_slice(), big.as_slice())
        );
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

    /// A multi-part UR with the given part header and fragment.
    fn crafted_part(sequence: u32, count: u32, message_length: u32, fragment: &[u8]) -> String {
        let mut cbor = Vec::new();
        minicbor::Encoder::new(&mut cbor)
            .array(5)
            .and_then(|e| e.u32(sequence))
            .and_then(|e| e.u32(count))
            .and_then(|e| e.u32(message_length))
            .and_then(|e| e.u32(0x1234_5678))
            .and_then(|e| e.bytes(fragment))
            .unwrap();
        format!(
            "ur:{UR_TYPE}/{sequence}-{count}/{}",
            ur::bytewords::encode(&cbor, ur::bytewords::Style::Minimal)
        )
    }

    #[test]
    fn a_part_announcing_millions_of_fragments_is_refused_before_decoding() {
        // Given to the ur decoder, the first stalls it for minutes and the
        // second exhausts memory: a mixed part makes it build and shuffle a
        // table as long as the announced count.
        for count in [1_000_000, u32::MAX - 1] {
            let part = crafted_part(count + 1, count, count, &[7]);
            assert_eq!(
                Reader::default().receive(&part),
                Err(WireError::TooManyFragments)
            );
        }
    }

    #[test]
    fn a_part_with_an_inconsistent_header_is_refused() {
        let mut reader = Reader::default();
        let max = MAX_PAYLOAD_SIZE as u32;
        // A fragment longer than the message, a count that does not match
        // the message and fragment lengths, a message over the limit.
        for part in [
            crafted_part(1, 1, 1, &[1, 2]),
            crafted_part(1, 3, 10, &[1, 2]),
            crafted_part(2, 1, 10, &[]),
        ] {
            assert!(matches!(
                reader.receive(&part),
                Err(WireError::Malformed(_))
            ));
        }
        assert_eq!(
            reader.receive(&crafted_part(1, 1024, max + 1024, &[0; 513])),
            Err(WireError::TooLarge)
        );
        assert_eq!(
            reader.receive(&format!(
                "ur:{UR_TYPE}/{}",
                "a".repeat(2 * MAX_PAYLOAD_SIZE + 64)
            )),
            Err(WireError::TooLarge)
        );
        // An honest stream still goes through the same reader afterwards.
        let payload = [9u8; 3_000];
        let mut honest = encoder(&payload, 100).unwrap();
        let done = loop {
            if let Some(done) = reader.receive(&honest.next_part().unwrap()).unwrap() {
                break done;
            }
        };
        assert_eq!(done, payload);
    }

    #[test]
    fn a_stream_that_does_not_complete_is_refused() {
        // Mixed parts of degree 2 or more and no simple part: nothing ever
        // resolves, so the decoder would keep every part it is given.
        let count = 32;
        let mut parts = (count + 1..).filter_map(|sequence| {
            let part = crafted_part(sequence, count, count, &[1]);
            let (_, cbor) = ur::decode(&part).unwrap();
            let degree = minicbor::decode::<ur::fountain::Part>(&cbor)
                .unwrap()
                .indexes()
                .len();
            (degree >= 2).then_some(part)
        });
        let mut reader = Reader::default();
        let first = parts.next().unwrap();
        assert_eq!(reader.receive(&first), Ok(None));
        for _ in 1..max_parts(count as usize) {
            assert_eq!(reader.receive(&parts.next().unwrap()), Ok(None));
        }
        assert!(matches!(
            reader.receive(&parts.next().unwrap()),
            Err(WireError::Malformed(_))
        ));
        // A part seen before is not a new one.
        assert_eq!(reader.receive(&first), Ok(None));
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
