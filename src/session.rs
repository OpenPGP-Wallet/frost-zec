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
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// How often a message file is looked for.
pub const POLL: Duration = Duration::from_millis(300);
/// Files may be passed by hand between two people: wait up to an hour.
pub const TIMEOUT: Duration = Duration::from_secs(3600);

/// The largest message file read. A message holds at most a PCZT of a few
/// hundred KiB, hex or bytewords encoded; the other side, or whatever carries
/// the files, could otherwise make a reader load a file of any size.
pub const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024;

/// Reads a message file written by the other side, refusing one larger than
/// [`MAX_FILE_SIZE`] instead of loading it whole.
pub fn read_message_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is larger than {MAX_FILE_SIZE} bytes", path.display()),
        ));
    }
    Ok(bytes)
}

/// The commitments file name, and its `kind`.
pub const COMMITMENTS: &str = "commitments";
/// The request file name, and its `kind`.
pub const REQUEST: &str = "request";
/// The reply file name, and its `kind`.
pub const REPLY: &str = "reply";

/// Co-signer → coordinator: fresh nonce commitments, one per spend it is
/// ready to sign. They are sent before the co-signer sees the transaction.
#[derive(Serialize, Deserialize)]
pub struct Commitments {
    /// The format name, [`crate::interop::FORMAT`].
    pub format: String,
    /// [`COMMITMENTS`].
    pub kind: String,
    /// The session id, in hex.
    pub session: String,
    /// The co-signer's FROST identifier, in hex.
    pub identifier: String,
    /// Serialized signing commitments, in hex, one per spend.
    pub commitments: Vec<String>,
}

/// Coordinator → co-signer: the PCZT and the coordinator's own commitment for
/// each spend (spend i uses commitment i on both sides, in the order the
/// spends appear in the Ironwood bundle).
#[derive(Serialize, Deserialize)]
pub struct Request {
    /// The format name, [`crate::interop::FORMAT`].
    pub format: String,
    /// [`REQUEST`].
    pub kind: String,
    /// The session id of the commitments it answers, in hex.
    pub session: String,
    /// The coordinator's FROST identifier, in hex.
    pub identifier: String,
    /// The PCZT, in hex.
    pub pczt: String,
    /// The coordinator's serialized commitments, in hex, one per spend.
    pub commitments: Vec<String>,
}

/// Co-signer → coordinator: one signature share per spend, or the reason it refused.
#[derive(Serialize, Deserialize)]
pub struct Reply {
    /// The format name, [`crate::interop::FORMAT`].
    pub format: String,
    /// [`REPLY`].
    pub kind: String,
    /// The session id, in hex.
    pub session: String,
    /// The co-signer's FROST identifier, in hex.
    pub identifier: String,
    /// Serialized signature shares, in hex, one per spend, if approved.
    pub shares: Option<Vec<String>>,
    /// Why the co-signer refused, if it did.
    pub refused: Option<String>,
}

/// The path of the message file `name` in the exchange directory `dir`.
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

/// How long a reply may wait for the coordinator to collect it before the
/// next session clears it.
pub const COLLECT: Duration = Duration::from_secs(120);

/// Removes the messages of an earlier session from `dir`.
///
/// A reply written within `COLLECT` may still be on its way: the coordinator
/// removes it once read. A session started straight after the last one (a
/// script running `cosign` in a loop) waits for that, up to `COLLECT`, instead
/// of deleting the reply before the coordinator has it. An older reply is
/// stale and goes at once, so a reply carried by hand never holds up a new
/// session for long.
pub fn reset(dir: &Path) -> Result<(), Box<dyn Error>> {
    reset_within(dir, COLLECT)
}

/// Whether `dir` holds a reply younger than `COLLECT` that the coordinator
/// may not have collected yet.
pub fn reply_pending(dir: &Path) -> bool {
    reply_age(dir).is_some_and(|age| age < COLLECT)
}

fn reply_age(dir: &Path) -> Option<Duration> {
    let modified = fs::metadata(path(dir, REPLY)).ok()?.modified().ok()?;
    Some(modified.elapsed().unwrap_or_default())
}

fn reset_within(dir: &Path, window: Duration) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(dir)?;
    // The deadline bounds the wait even for a reply whose timestamp is in the
    // future and so never ages.
    let deadline = Instant::now() + window;
    while let Some(age) = reply_age(dir).filter(|age| *age < window) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        thread::sleep(POLL.min(window - age).min(left));
    }
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
        let read = read_message_file(file);
        if let Err(error) = &read
            && error.kind() == io::ErrorKind::InvalidData
        {
            return Err(error.to_string().into());
        }
        if let Ok(bytes) = read {
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

    #[test]
    fn an_oversized_file_is_refused_without_being_loaded() {
        let dir = scratch("oversized");
        let file = dir.join("request.json");
        fs::write(&file, vec![b' '; MAX_FILE_SIZE as usize]).unwrap();
        assert!(read_message_file(&file).is_ok());
        fs::write(&file, vec![b' '; MAX_FILE_SIZE as usize + 1]).unwrap();
        let error = read_message_file(&file).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // Refused at once, not after waiting for the deadline.
        let started = Instant::now();
        assert!(wait_json::<Message>(&file, started + Duration::from_secs(60)).is_err());
        assert!(started.elapsed() < Duration::from_secs(10));
        let _ = fs::remove_dir_all(dir);
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

    /// A co-signer started straight after the last session (a script running
    /// `cosign` in a loop) must not delete the reply before the coordinator,
    /// which removes it once read, has collected it.
    #[test]
    fn a_fresh_reply_is_left_for_the_coordinator() {
        let dir = scratch("fresh-reply");
        let reply = path(&dir, REPLY);
        fs::write(&reply, br#"{"kind": "sign-reply"}"#).unwrap();
        let coordinator = {
            let reply = reply.clone();
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(800));
                let message: Result<Message, _> = wait_json(&reply, Instant::now());
                let _ = fs::remove_file(&reply);
                message.map_err(|e| e.to_string())
            })
        };
        let started = Instant::now();
        reset_within(&dir, Duration::from_secs(30)).unwrap();
        let collected = coordinator.join().unwrap();
        assert_eq!(collected.unwrap().kind, "sign-reply");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!reply.exists());
        let _ = fs::remove_dir_all(dir);
    }

    /// A reply stamped in the future (a clock ahead, or a file carried from a
    /// device whose clock runs fast) never ages: the wait must still end.
    #[test]
    fn a_reply_from_the_future_does_not_hold_the_session_forever() {
        let dir = scratch("future-reply");
        let reply = path(&dir, REPLY);
        fs::write(&reply, b"{}").unwrap();
        fs::File::options()
            .write(true)
            .open(&reply)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + Duration::from_secs(3600))
            .unwrap();
        let started = Instant::now();
        reset_within(&dir, Duration::from_millis(900)).unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!reply.exists());
        let _ = fs::remove_dir_all(dir);
    }

    /// A reply nobody collects (carried by hand, or the coordinator gone) is
    /// removed once the window has passed, so the next session still starts.
    #[test]
    fn an_uncollected_reply_is_removed_after_the_window() {
        let dir = scratch("uncollected-reply");
        let reply = path(&dir, REPLY);
        fs::write(&reply, b"{}").unwrap();
        let started = Instant::now();
        reset_within(&dir, Duration::from_millis(900)).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(600));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!reply.exists());
        let _ = fs::remove_dir_all(dir);
    }

    /// A reply from long ago is stale: it is removed at once, with no wait.
    #[test]
    fn a_stale_reply_is_removed_at_once() {
        let dir = scratch("stale-reply");
        let reply = path(&dir, REPLY);
        fs::write(&reply, b"{}").unwrap();
        let an_hour_ago = std::time::SystemTime::now() - Duration::from_secs(3600);
        fs::File::options()
            .write(true)
            .open(&reply)
            .unwrap()
            .set_modified(an_hour_ago)
            .unwrap();
        let started = Instant::now();
        reset_within(&dir, Duration::from_secs(120)).unwrap();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(!reply.exists());
        let _ = fs::remove_dir_all(dir);
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
