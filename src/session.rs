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
    wait_json(&path(dir, name), Instant::now() + TIMEOUT)
}

/// How long a file that does not parse must stay unchanged before it counts as
/// a wrong file rather than one still being copied in.
pub const SETTLE: Duration = Duration::from_secs(2);

/// Waits for `file` and reads it as JSON. A file passed by hand can show up
/// before its copy ends (cut short, or already full size with zeros at the
/// end), so one that does not parse is read again until it does. Only once it
/// has stayed the same for `SETTLE` is it refused as a wrong message.
pub fn wait_json<T: DeserializeOwned>(file: &Path, deadline: Instant) -> Result<T, Box<dyn Error>> {
    let mut unparsed: Option<(Vec<u8>, Instant)> = None;
    loop {
        if let Ok(bytes) = fs::read(file) {
            match serde_json::from_slice(&bytes) {
                Ok(message) => return Ok(message),
                Err(error) => match &unparsed {
                    Some((seen, since)) if *seen == bytes => {
                        if since.elapsed() >= SETTLE {
                            return Err(format!(
                                "{} is not a valid message: {error}",
                                file.display()
                            )
                            .into());
                        }
                    }
                    _ => unparsed = Some((bytes, Instant::now())),
                },
            }
        }
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for {}", file.display()).into());
        }
        thread::sleep(POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize, PartialEq, Debug)]
    struct Message {
        kind: String,
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("frost-zec-session-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A file read halfway through its copy (cut short, or full size with zeros
    /// at the end) is read again until the copy ends.
    #[test]
    fn a_file_still_being_copied_is_waited_for() {
        let complete = br#"{"kind": "sign-request"}"#.to_vec();
        let mut zero_filled = complete[..10].to_vec();
        zero_filled.resize(complete.len(), 0);
        for (case, partial) in [("cut", complete[..10].to_vec()), ("zeros", zero_filled)] {
            let dir = scratch(case);
            let file = dir.join("request.json");
            fs::write(&file, partial).unwrap();
            let writer = {
                let (file, complete) = (file.clone(), complete.clone());
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(800));
                    fs::write(file, complete).unwrap();
                })
            };
            let message: Message =
                wait_json(&file, Instant::now() + Duration::from_secs(10)).unwrap();
            assert_eq!(message.kind, "sign-request", "{case}");
            writer.join().unwrap();
            let _ = fs::remove_dir_all(dir);
        }
    }

    /// A file that stays wrong is refused once it has settled, not after the
    /// whole hour.
    #[test]
    fn a_wrong_file_is_refused_once_it_settles() {
        let dir = scratch("wrong");
        let file = dir.join("reply.json");
        fs::write(&file, b"{\"kind\": 3}").unwrap();
        let started = Instant::now();
        let result: Result<Message, _> = wait_json(&file, started + Duration::from_secs(30));
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = fs::remove_dir_all(dir);
    }
}
