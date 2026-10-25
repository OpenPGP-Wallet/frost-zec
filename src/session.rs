//! Message passing between the coordinator and a co-signer.
//!
//! Each message is a JSON file in an exchange directory (`session/` by
//! default), standing in for the encrypted QR codes of the real app. Running
//! `coordinate` and `cosign` in two terminals on one directory plays the part
//! of two devices; with another implementation, each side has its own
//! directory and the files are passed by hand (docs/interop.md).
//!
//! The co-signer opens the session: it sends fresh nonce commitments before it
//! sees the transaction. Participants are named by their FROST identifier, in
//! hex.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const POLL: Duration = Duration::from_millis(300);
/// Files may be passed by hand between two people: wait up to an hour.
pub const TIMEOUT: Duration = Duration::from_secs(3600);

pub const COMMITMENTS: &str = "commitments";
pub const REQUEST: &str = "request";
pub const REPLY: &str = "reply";

/// Co-signer → coordinator: fresh nonce commitments, one per spend it is
/// ready to sign. They are sent before the co-signer sees the transaction.
#[derive(Serialize, Deserialize)]
pub struct Commitments {
    pub format: String,
    pub kind: String,
    pub session: String,
    pub identifier: String,
    pub commitments: Vec<String>,
}

/// Coordinator → co-signer: the PCZT and the coordinator's own commitment for
/// each spend (spend i uses commitment i on both sides, in the order the
/// spends appear in the Ironwood bundle).
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub format: String,
    pub kind: String,
    pub session: String,
    pub identifier: String,
    pub pczt: String,
    pub commitments: Vec<String>,
}

/// Co-signer → coordinator: one signature share per spend, or the reason it refused.
#[derive(Serialize, Deserialize)]
pub struct Reply {
    pub format: String,
    pub kind: String,
    pub session: String,
    pub identifier: String,
    pub shares: Option<Vec<String>>,
    pub refused: Option<String>,
}

pub fn path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.json"))
}

/// Removes the session's messages when dropped. The request holds the PCZT
/// (amounts, addresses, viewing-key material), so it must not stay on disk.
pub struct Cleanup<'a>(pub &'a Path);

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        for name in [COMMITMENTS, REQUEST, REPLY] {
            let _ = fs::remove_file(path(self.0, name));
        }
    }
}

/// Removes the messages of an earlier session from `dir`.
pub fn reset(dir: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    for name in [COMMITMENTS, REQUEST, REPLY] {
        let file = path(dir, name);
        if file.exists() {
            fs::remove_file(file)?;
        }
    }
    Ok(())
}

/// Writes a message atomically, so the other side never reads half a file.
pub fn send<T: Serialize>(dir: &Path, name: &str, message: &T) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    let temporary = dir.join(format!("{name}.tmp"));
    fs::write(&temporary, serde_json::to_vec_pretty(message)?)?;
    fs::rename(temporary, path(dir, name))?;
    Ok(())
}

/// Waits for a message, then reads it.
pub fn receive<T: DeserializeOwned>(dir: &Path, name: &str) -> Result<T, Box<dyn Error>> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Ok(bytes) = fs::read(path(dir, name)) {
            return Ok(serde_json::from_slice(&bytes)?);
        }
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for `{name}.json` in {}", dir.display()).into());
        }
        thread::sleep(POLL);
    }
}
