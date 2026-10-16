//! Message passing between the coordinator and a co-signer.
//!
//! Each message is a JSON file in `session/`, standing in for the encrypted QR
//! codes of the real app. Running `coordinate` and `cosign` in two terminals
//! plays the part of two devices.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const DIR: &str = "session";
const POLL: Duration = Duration::from_millis(300);
const TIMEOUT: Duration = Duration::from_secs(900);

/// Coordinator → co-signer: a signing session is open.
#[derive(Serialize, Deserialize)]
pub struct Start {
    pub session: String,
    pub coordinator: u16,
    pub cosigner: u16,
}

/// Co-signer → coordinator: fresh nonce commitments, one per spend it is
/// ready to sign. They are sent before the co-signer sees the transaction.
#[derive(Serialize, Deserialize)]
pub struct Commitments {
    pub session: String,
    pub commitments: Vec<String>,
}

/// Coordinator → co-signer: the proven PCZT and the coordinator's own
/// commitment for each spend (spend i uses commitment i on both sides).
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub session: String,
    pub pczt: String,
    pub commitments: Vec<String>,
}

/// Co-signer → coordinator: one signature share per spend, or the reason it refused.
#[derive(Serialize, Deserialize)]
pub struct Reply {
    pub session: String,
    pub shares: Option<Vec<String>>,
    pub refused: Option<String>,
}

fn path(name: &str) -> PathBuf {
    Path::new(DIR).join(format!("{name}.json"))
}

/// Removes the session files when dropped, so a finished or failed session
/// leaves nothing on disk.
pub struct Cleanup;

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(DIR);
    }
}

/// Starts a fresh session: old messages are removed.
pub fn reset() -> Result<(), Box<dyn Error>> {
    if Path::new(DIR).exists() {
        fs::remove_dir_all(DIR)?;
    }
    fs::create_dir_all(DIR)?;
    Ok(())
}

/// Writes a message atomically, so the other side never reads half a file.
pub fn send<T: Serialize>(name: &str, message: &T) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(DIR)?;
    let temporary = Path::new(DIR).join(format!("{name}.tmp"));
    fs::write(&temporary, serde_json::to_vec_pretty(message)?)?;
    fs::rename(temporary, path(name))?;
    Ok(())
}

/// Waits for a message, then reads it.
pub fn receive<T: DeserializeOwned>(name: &str) -> Result<T, Box<dyn Error>> {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if let Ok(bytes) = fs::read(path(name)) {
            return Ok(serde_json::from_slice(&bytes)?);
        }
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for `{name}`").into());
        }
        thread::sleep(POLL);
    }
}
