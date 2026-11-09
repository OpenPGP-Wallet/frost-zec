//! FROST for shielded ZEC in the Ironwood pool: distributed key generation,
//! group keys derived as ZIP 2005 specifies for FROST, re-randomized signing
//! of PCZTs (ZIP 312), the checks a co-signer runs before it signs, and member
//! backup strings.
//!
//! This crate has no dependency on any wallet. The `frost-zec` command-line
//! tool in the same package is built on it.
//!
//! Status: prototype, not audited. Use small test amounts only.

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
pub mod session;
pub mod setup;
pub mod signing;
pub mod wire;
