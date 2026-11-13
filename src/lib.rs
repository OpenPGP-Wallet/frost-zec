//! FROST for shielded ZEC in the Ironwood pool: distributed key generation,
//! group keys derived as ZIP 2005 specifies for FROST, re-randomized signing
//! of PCZTs (ZIP 312), the checks a co-signer runs before it signs, and member
//! backup strings.
//!
//! This crate has no dependency on any wallet. The `frost-zec` command-line
//! tool in the same package is built on it.
//!
//! Status: prototype, not audited. Use small test amounts only.
//!
//! # Example: pairing two devices
//!
//! The coordinator shows pair-init, the co-signer answers, and both devices
//! show the same six-digit code, which the user compares before confirming on
//! each one. After that, every message is sealed under the pairing.
//!
//! ```
//! use frost_zec::channel::{Initiator, Responder};
//! use frost_zec::wire::{kind, Message};
//! use rand10::rand_core::UnwrapErr;
//! use rand10::rngs::SysRng;
//!
//! let mut rng = UnwrapErr(SysRng);
//! let (initiator, init) = Initiator::start(&mut rng);
//! let (responder, response) = Responder::respond(&init, &mut rng)?;
//! let (coordinator, confirm) = initiator.finish(&response)?;
//! let cosigner = responder.finish(&confirm)?;
//! assert_eq!(coordinator.code(), cosigner.code()); // what the user compares
//! let (coordinator, cosigner) = (coordinator.confirm(), cosigner.confirm());
//!
//! let sealed = Message::seal(&coordinator, kind::SIGN_REQUEST, b"session", b"hello", &mut rng)?;
//! let (session, plaintext) = sealed.open(&cosigner, kind::SIGN_REQUEST)?;
//! assert_eq!((session.as_slice(), plaintext.as_slice()), (&b"session"[..], &b"hello"[..]));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Key generation ([`setup`]) and the signing session ([`cosigning`]) run over
//! such a pairing; `tests/protocol.rs` in the repository runs the whole
//! protocol end to end, and `docs/spec.md` specifies it.

#![warn(missing_docs)]

pub mod backup;
#[cfg(feature = "camera")]
pub mod camera;
pub mod channel;
pub mod check;
pub mod cosigning;
pub mod dkg;
pub mod interop;
pub mod keys;
pub mod pczt_io;
pub mod profiles;
pub mod session;
pub mod setup;
pub mod signing;
pub mod wire;

/// The FROST(Pallas, BLAKE2b-512) types this crate uses, so that a wallet uses
/// the very same version.
pub use reddsa::frost::redpallas;
