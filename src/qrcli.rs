//! `frost-zec qr ...`: the QR protocol of docs/spec.md, as a test co-signer
//! and a test coordinator.
//!
//!   qr setup --as coordinator|cosigner [--network main|test] [--state DIR] [--via DIR|qr|clipboard] [--yes]
//!            [--backup-plain]   (co-signer: member 3 as a bare string, not an encrypted file)
//!   qr sign --as cosigner [--state DIR] [--via DIR|qr|clipboard] [--yes]
//!   qr sign --as coordinator --pczt IN --out OUT [--state DIR] [--via DIR|qr|clipboard]
//!   qr done [--state DIR] [--via DIR|qr|clipboard]
//!   qr recover --as cosigner --state NEW --old-state OLD [--via DIR|qr|clipboard] [--yes]
//!   qr recover --as coordinator --state NEW --old-state OLD --backup FILE
//!              [--passphrase-file FILE] [--network main|test] [--via DIR|qr|clipboard] [--yes]
//!   qr sign-local --state DIR --backup FILE [--passphrase-file FILE] --pczt IN --out OUT [--yes]
//!              the co-signer is lost: sign the sweep with this member and member 3
//!   qr info [--state DIR]
//!
//! With `--via qr`, every message is shown as an animated QR code and the
//! answer is read with the webcam (build with `--features camera`). With
//! `--via DIR`, each message is a single-part UR (`ur:zcash-frost/...`) written
//! as a text file in DIR: one person can pass the files between two machines.
//! With `--via clipboard`, for a wallet on the same computer, each message is
//! put on the clipboard as that text, and the answer is taken from the
//! clipboard as soon as the wallet's text is copied. All carry the same
//! payloads.
//!
//! `--yes` skips the human checks (the pairing code and the approval of a
//! payment): tests only.
//!
//! The seat in `--state` holds the member's share, `sk` and the pairing keys,
//! unencrypted like the rest of this prototype. Test amounts only.

use std::error::Error;
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use frost_zec::channel::{Initiator, Pairing, Responder};
use frost_zec::cosigning::{self, CoordinatorSession, Member, Reply, Request};
use frost_zec::setup::{
    self as dkg_setup, CoordinatorSetup, CosignerSetup, Done, Group, Round1, Round2,
};
use frost_zec::wire::{self, Message, kind};
use frost_zec::{interop, keys, pczt_io, profiles, recovery, session, signing};
use rand10::rand_core::UnwrapErr;
use rand10::rngs::SysRng;
use reddsa::frost::redpallas::keys::{KeyPackage, PublicKeyPackage};
use serde::{Deserialize, Serialize};

use super::{flag, option, print_report, qrview};

const SEAT_FILE: &str = "seat.json";
/// A mismatch ends the pairing: each new attempt would be a new guess for
/// whoever sits between the devices (spec § 3.3).
const CODES_DIFFER: &str = "pairing cancelled: the codes differ. Another device may be reading or \
     changing the messages between these two: find out why before you start a new setup";
const DKG_SESSION: &[u8] = b"dkg";

const PAIR_INIT: &str = "1-pair-init.ur";
const PAIR_RESPONSE: &str = "2-pair-response.ur";
const PAIR_CONFIRM: &str = "3-pair-confirm.ur";
const COSIGNER_KEYS: &str = "4-cosigner-keys.ur";
const COORDINATOR_KEYS: &str = "5-coordinator-keys.ur";
const COSIGNER_DONE: &str = "6-cosigner-done.ur";
const SIGN_REQUEST: &str = "sign-1-request.ur";
const SIGN_REPLY: &str = "sign-2-reply.ur";

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("setup") => setup(&args[1..]),
        Some("sign") => sign(&args[1..]),
        Some("info") => info(&args[1..]),
        Some("done") => done(&args[1..]),
        Some("recover") => recover(&args[1..]),
        Some("sign-local") => sign_local(&args[1..]),
        _ => Err(
            "usage: frost-zec qr <setup | sign | done | recover | sign-local | info> [options] (see src/qrcli.rs)"
                .into(),
        ),
    }
}

/// A member's seat: everything it needs to sign later.
#[derive(Serialize, Deserialize)]
struct Seat {
    role: String,
    network: String,
    member: u16,
    pairing: String,
    key_package: String,
    public_key_package: String,
    sk: String,
    ufvk: String,
    address: String,
}

impl Seat {
    fn new(
        role: &str,
        network: &str,
        pairing: &Pairing,
        group: &Group,
    ) -> Result<Seat, Box<dyn Error>> {
        let member = (1..=3u16)
            .find(|m| {
                reddsa::frost::redpallas::Identifier::try_from(*m).ok() == Some(group.member.id())
            })
            .ok_or("unexpected member identifier")?;
        Ok(Seat {
            role: role.into(),
            network: network.into(),
            member,
            pairing: hex::encode(pairing.to_bytes()),
            key_package: hex::encode(group.member.key_package.serialize()?),
            public_key_package: hex::encode(group.member.public_key_package.serialize()?),
            sk: hex::encode(group.sk),
            ufvk: group.ufvk.clone(),
            address: group.address.clone(),
        })
    }

    fn load(dir: &Path) -> Result<Seat, Box<dyn Error>> {
        let bytes = fs::read(dir.join(SEAT_FILE))
            .map_err(|_| format!("no seat in {}: run `qr setup` first", dir.display()))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn save(&self, dir: &Path) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(dir)?;
        let path = dir.join(SEAT_FILE);
        if path.exists() {
            return Err(format!(
                "{} already holds a seat: use another --state",
                dir.display()
            )
            .into());
        }
        fs::write(path, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Writes the seat over the one in `dir`, through a temporary file.
    fn replace(&self, dir: &Path) -> Result<(), Box<dyn Error>> {
        let path = dir.join(SEAT_FILE);
        let temporary = dir.join(".seat.json.tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        fs::rename(&temporary, &path)?;
        Ok(())
    }

    fn pairing(&self) -> Result<Pairing, Box<dyn Error>> {
        Ok(Pairing::from_bytes(&hex::decode(&self.pairing)?)?)
    }

    fn member(&self) -> Result<Member, Box<dyn Error>> {
        let public_key_package =
            PublicKeyPackage::deserialize(&hex::decode(&self.public_key_package)?)?;
        let sk: [u8; 32] = hex::decode(&self.sk)?
            .try_into()
            .map_err(|_| "sk must be 32 bytes")?;
        let ak = signing::group_ak(&public_key_package)?;
        Ok(Member {
            key_package: KeyPackage::deserialize(&hex::decode(&self.key_package)?)?,
            public_key_package,
            fvk: keys::derive(&sk, &ak)?.fvk,
            network: interop::network_type(&self.network)?,
        })
    }
}

fn state_dir(args: &[String]) -> PathBuf {
    PathBuf::from(option(args, "--state").unwrap_or("qr-state"))
}

/// How messages travel: UR text files in a directory, QR codes, or the
/// clipboard.
enum Carrier {
    Files(PathBuf),
    Qr,
    Clipboard(Clipboard),
}

impl Carrier {
    fn from_args(args: &[String]) -> Result<Carrier, Box<dyn Error>> {
        match option(args, "--via") {
            Some("qr") => Ok(Carrier::Qr),
            Some("clipboard") => Ok(Carrier::Clipboard(Clipboard::open()?)),
            other => {
                let dir = PathBuf::from(other.unwrap_or("qr-exchange"));
                fs::create_dir_all(&dir)?;
                Ok(Carrier::Files(dir))
            }
        }
    }

    /// Sends a message. In QR mode the code stays on screen until Enter, and
    /// only then does the camera open for the answer: with a single camera (a
    /// phone used as a webcam for both programs), the other side needs it to
    /// read this code.
    fn send(&mut self, name: &str, messages: &[Message]) -> Result<(), Box<dyn Error>> {
        match self {
            Carrier::Files(dir) => write_file(dir, name, messages),
            Carrier::Qr => {
                let display = qrview::Display::start(
                    &wire::encode_payload(messages),
                    format!("{name}: let the other device read this code, then press Enter."),
                )?;
                let mut line = String::new();
                io::stdin().lock().read_line(&mut line)?;
                display.stop();
                Ok(())
            }
            Carrier::Clipboard(clipboard) => {
                clipboard.put(name, &wire::single_part(&wire::encode_payload(messages))?)
            }
        }
    }

    fn receive(&mut self, name: &str) -> Result<Vec<Message>, Box<dyn Error>> {
        match self {
            Carrier::Files(dir) => read_file(dir, name),
            Carrier::Qr => Ok(wire::decode_payload(&scan(name)?)?),
            Carrier::Clipboard(clipboard) => Ok(wire::decode_payload(&clipboard.take(name)?)?),
        }
    }
}

/// The clipboard as a carrier, for a wallet on the same computer: this side
/// puts its messages there, and takes the other side's as soon as they are
/// copied. Any program on the computer can read the clipboard, which shows no
/// more than a QR code on a screen: messages are public until the pairing, and
/// sealed after it.
struct Clipboard {
    board: arboard::Clipboard,
    /// The last text put or taken, so that it is not taken (again) as an answer.
    last: String,
    /// The last message this side put, with its name: copying anything else
    /// before pasting it loses it, so Enter puts it back.
    sent: Option<(String, String)>,
}

impl Clipboard {
    fn open() -> Result<Clipboard, Box<dyn Error>> {
        let mut board =
            arboard::Clipboard::new().map_err(|e| format!("cannot open the clipboard: {e}"))?;
        // A message copied before this run, from an earlier attempt, must not
        // be taken for the other side's answer.
        let _ = board.clear();
        Ok(Clipboard {
            board,
            last: String::new(),
            sent: None,
        })
    }

    fn put(&mut self, name: &str, text: &str) -> Result<(), Box<dyn Error>> {
        self.board
            .set_text(text.to_string())
            .map_err(|e| format!("cannot write to the clipboard: {e}"))?;
        self.last = text.to_string();
        self.sent = Some((name.to_string(), text.to_string()));
        // The bell tells the user the other side can paste now.
        print!("\x07");
        println!("  → {name} is on the clipboard: paste it into the other program.");
        io::stdout().flush()?;
        Ok(())
    }

    fn take(&mut self, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        println!("  … waiting for {name}: copy it as text in the other program.");
        if let Some((sent, _)) = &self.sent {
            println!(
                "    Copied something else in between? Press Enter here to copy {sent} again."
            );
        }
        let deadline = Instant::now() + session::TIMEOUT;
        let prefix = format!("ur:{}/", wire::UR_TYPE);
        loop {
            let copied = self.board.get_text().unwrap_or_default();
            let text = copied.trim();
            // Only our messages are read and remembered: anything else copied
            // meanwhile, a password for instance, is left alone.
            let ours = text
                .get(..prefix.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(&prefix));
            if ours && text != self.last {
                self.last = text.to_string();
                match wire::Reader::default().receive(text) {
                    Ok(Some(payload)) => return Ok(payload),
                    Ok(None) => eprintln!(
                        "  the clipboard holds one part of an animated QR code: copy the message as text"
                    ),
                    Err(e) => {
                        eprintln!("  the clipboard holds no valid message ({e}): copy it again")
                    }
                }
            }
            if enter_pressed()
                && let Some((sent, text)) = self.sent.clone()
            {
                self.put(&sent, &text)?;
            }
            if Instant::now() > deadline {
                return Err(format!("timed out waiting for {name}").into());
            }
            thread::sleep(session::POLL);
        }
    }
}

/// Whether Enter was pressed since the last call, without waiting: the keys
/// typed while the clipboard is watched are read here, so none of them is left
/// to answer the next question. False when there is no console to read.
fn enter_pressed() -> bool {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind};
    let mut pressed = false;
    while matches!(event::poll(std::time::Duration::ZERO), Ok(true)) {
        match event::read() {
            Ok(Event::Key(key)) => {
                pressed |= key.code == KeyCode::Enter && key.kind == KeyEventKind::Press;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    pressed
}

#[cfg(feature = "camera")]
fn scan(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    use frost_zec::camera::{self, Progress};
    let never = std::sync::atomic::AtomicBool::new(false);
    let payload = camera::scan(&never, |progress| match progress {
        Progress::Camera(camera) => eprintln!("  reading {name} with {camera} …"),
        Progress::Fragments(done, total) => eprintln!("  {done} / {total} fragments"),
    })?;
    payload.ok_or_else(|| "scan cancelled".into())
}

#[cfg(not(feature = "camera"))]
fn scan(_: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Err("this build cannot read QR codes: build with --features camera, or use --via DIR".into())
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// Writes one QR payload as a single-part UR text file, atomically.
fn write_file(dir: &Path, name: &str, messages: &[Message]) -> Result<(), Box<dyn Error>> {
    let payload = wire::encode_payload(messages);
    let text = wire::single_part(&payload)?;
    let temporary = dir.join(format!(".{name}.tmp"));
    fs::write(&temporary, text)?;
    fs::rename(&temporary, dir.join(name))?;
    println!(
        "  → wrote {}: pass it to the other device.",
        dir.join(name).display()
    );
    Ok(())
}

/// Waits for one QR payload (up to an hour), then removes its file. A file
/// still being copied in does not decode yet, so it is read again until it
/// does, and refused once it has stayed the same for a few seconds.
fn read_file(dir: &Path, name: &str) -> Result<Vec<Message>, Box<dyn Error>> {
    let path = dir.join(name);
    println!("  … waiting for {}", path.display());
    let deadline = Instant::now() + session::TIMEOUT;
    let mut bad: Option<(String, Instant)> = None;
    loop {
        let read = session::read_message_file(&path);
        if let Err(error) = &read
            && error.kind() == io::ErrorKind::InvalidData
        {
            return Err(error.to_string().into());
        }
        if let Ok(bytes) = read {
            let text = String::from_utf8_lossy(&bytes).into_owned();
            match wire::Reader::default().receive(text.trim()) {
                Ok(Some(payload)) => {
                    let _ = fs::remove_file(&path);
                    return Ok(wire::decode_payload(&payload)?);
                }
                result => match &bad {
                    Some((seen, since)) if *seen == text => {
                        if since.elapsed() >= session::SETTLE {
                            return Err(format!(
                                "{} is not a valid message: {result:?}",
                                path.display()
                            )
                            .into());
                        }
                    }
                    _ => bad = Some((text, Instant::now())),
                },
            }
        }
        if Instant::now() > deadline {
            return Err(format!("timed out waiting for {}", path.display()).into());
        }
        thread::sleep(session::POLL);
    }
}

fn ask(question: &str, yes: bool) -> Result<bool, Box<dyn Error>> {
    if yes {
        println!("{question} [y/N] y (--yes: test mode)");
        return Ok(true);
    }
    print!("{question} [y/N] ");
    io::stdout().flush()?;
    let mut answer = String::new();
    io::stdin().lock().read_line(&mut answer)?;
    Ok(answer.trim().eq_ignore_ascii_case("y"))
}

fn one(messages: &[Message], count: usize) -> Result<(), Box<dyn Error>> {
    if messages.len() != count {
        return Err(format!("expected {count} message(s), got {}", messages.len()).into());
    }
    Ok(())
}

fn setup(args: &[String]) -> Result<(), Box<dyn Error>> {
    setup_flow(args, None)
}

/// What `qr recover` adds to a setup (spec § 7.2).
enum Recovery {
    /// The co-signer: its seat of the old group, which takes the new pairing.
    Cosigner { old_state: PathBuf, old: Seat },
    /// The new coordinator: member 3's backup string, and the viewing key of
    /// the backup kit when it is a profile 1 file.
    Coordinator {
        old_state: PathBuf,
        backup: zeroize::Zeroizing<String>,
        kit_ufvk: Option<String>,
    },
}

/// The passphrase of a backup file: from --passphrase-file, or typed (it is
/// shown as it is typed).
fn read_passphrase(args: &[String]) -> Result<zeroize::Zeroizing<String>, Box<dyn Error>> {
    if let Some(file) = option(args, "--passphrase-file") {
        return Ok(zeroize::Zeroizing::new(
            fs::read_to_string(file)?.trim().to_string(),
        ));
    }
    print!("  passphrase of the backup file (shown as you type): ");
    io::stdout().flush()?;
    let mut line = zeroize::Zeroizing::new(String::new());
    io::stdin().lock().read_line(&mut line)?;
    Ok(zeroize::Zeroizing::new(line.trim().to_string()))
}

/// After a lost device: pairs anew, the co-signer describes the old group, the
/// new coordinator restores member 3 against it, and the two create a new
/// account. The old account is then swept with `qr sign`: the coordinator
/// with the restored member 3 in --old-state, the co-signer with its old seat,
/// which now holds the new pairing.
fn recover(args: &[String]) -> Result<(), Box<dyn Error>> {
    let role = option(args, "--as").ok_or("--as coordinator|cosigner is required")?;
    let old_state = PathBuf::from(
        option(args, "--old-state").ok_or("--old-state DIR is required (the old account)")?,
    );
    let recovery = match role {
        "cosigner" => {
            let old = Seat::load(&old_state)?;
            if old.role != "cosigner" {
                return Err(format!("{} is not a co-signer's seat", old_state.display()).into());
            }
            Recovery::Cosigner { old_state, old }
        }
        "coordinator" => {
            if old_state.join(SEAT_FILE).exists() {
                return Err(format!(
                    "{} already holds a seat: give --old-state a new folder for the restored member 3",
                    old_state.display()
                )
                .into());
            }
            let (backup, kit_ufvk) = read_backup(args)?;
            Recovery::Coordinator {
                old_state,
                backup,
                kit_ufvk,
            }
        }
        _ => return Err("--as must be coordinator or cosigner".into()),
    };
    setup_flow(args, Some(recovery))
}

/// Member 3's backup string from --backup: the string itself, or a backup
/// file (profile 1), whose viewing key comes with it.
fn read_backup(
    args: &[String],
) -> Result<(zeroize::Zeroizing<String>, Option<String>), Box<dyn Error>> {
    let path = option(args, "--backup")
        .ok_or("--backup FILE is required (member 3: its string, or a backup file)")?;
    let bytes = fs::read(path)?;
    if bytes.starts_with(b"zkfrost1") {
        let text = String::from_utf8(bytes)?;
        return Ok((zeroize::Zeroizing::new(text.trim().to_string()), None));
    }
    let file = if bytes.starts_with(profiles::TEXT_PREFIX.as_bytes()) {
        profiles::from_text(std::str::from_utf8(&bytes)?)?
    } else {
        bytes
    };
    profiles::file_cost(&file)?;
    let contents = profiles::decrypt(&file, &read_passphrase(args)?)?;
    let ufvk = contents.ufvk.clone();
    Ok((contents.backup.clone(), Some(ufvk)))
}

/// The co-signer is lost (spec § 7.2): this coordinator restores member 3,
/// checked against the group in its own seat, and signs the sweep with both.
fn sign_local(args: &[String]) -> Result<(), Box<dyn Error>> {
    let seat = Seat::load(&state_dir(args))?;
    let mine = seat.member()?;
    let (backup, kit_ufvk) = read_backup(args)?;
    let restored = recovery::restore_member(
        &backup,
        &recovery::GroupInfo::new(&mine, &seat.ufvk),
        kit_ufvk.as_deref(),
    )?;
    let input = option(args, "--pczt").ok_or("--pczt IN is required")?;
    let output = option(args, "--out").ok_or("--out OUT is required")?;
    let (signed, report) =
        recovery::sign_with_two_members(&fs::read(input)?, &mine, &restored.member)?;
    print_report("this device, members 1 and 3", &report);
    if !ask("  Sign this with both members?", flag(args, "--yes"))? {
        return Err("not signed".into());
    }
    fs::write(output, pczt_io::serialize(signed)?)?;
    println!("  signed, every signature verified under its rk: written to {output}");
    println!("  Once it is mined, delete member 3 from this device.");
    Ok(())
}

fn setup_flow(args: &[String], recovery: Option<Recovery>) -> Result<(), Box<dyn Error>> {
    let role = option(args, "--as").ok_or("--as coordinator|cosigner is required")?;
    // A co-signer recovering keeps the old account's network.
    let network_name = match &recovery {
        Some(Recovery::Cosigner { old, .. }) => old.network.clone(),
        _ => option(args, "--network").unwrap_or("test").to_string(),
    };
    let network_name = network_name.as_str();
    let network = interop::network_type(network_name)?;
    let state = state_dir(args);
    if state.join(SEAT_FILE).exists() {
        return Err(format!(
            "{} already holds a seat: use another --state",
            state.display()
        )
        .into());
    }
    let mut carrier = Carrier::from_args(args)?;
    let yes = flag(args, "--yes");
    let mut rng = rng();
    match role {
        "coordinator" => {
            println!("[coordinator] pairing and key generation, network {network_name}");
            let (initiator, init) = Initiator::start(&mut rng);
            carrier.send(PAIR_INIT, &[Message::pair_init(&init)])?;
            let messages = carrier.receive(PAIR_RESPONSE)?;
            one(&messages, 1)?;
            let (pending, confirm) = initiator.finish(&messages[0].to_pair_response()?)?;
            let (coordinator_setup, round1) = CoordinatorSetup::start(network)?;
            carrier.send(
                PAIR_CONFIRM,
                &[
                    Message::pair_confirm(&confirm),
                    Message::seal_public(
                        &pending,
                        kind::DKG_ROUND1,
                        DKG_SESSION,
                        &round1.to_bytes(),
                        &mut rng,
                    )?,
                ],
            )?;
            println!("  pairing code: {}", pending.code());
            if !ask("  Does the other device show the same code?", yes)? {
                return Err(CODES_DIFFER.into());
            }
            let pairing = pending.confirm();
            let messages = carrier.receive(COSIGNER_KEYS)?;
            let restored = match &recovery {
                Some(Recovery::Coordinator {
                    backup, kit_ufvk, ..
                }) => {
                    one(&messages, 3)?;
                    let (_, info) = messages[0].open(&pairing, kind::GROUP_INFO)?;
                    // Checked before this device sends anything secret.
                    let restored = recovery::restore_member(
                        backup,
                        &recovery::GroupInfo::from_bytes(&info)?,
                        kit_ufvk.as_deref(),
                    )?;
                    if restored.member.network != network {
                        return Err(
                            "the old account is on another network: use its --network".into()
                        );
                    }
                    println!(
                        "  member 3 restored and checked: old account {}",
                        restored.address
                    );
                    Some(restored)
                }
                _ => {
                    one(&messages, 2)?;
                    None
                }
            };
            let keys_at = messages.len() - 2;
            let (_, theirs1) = messages[keys_at].open(&pairing, kind::DKG_ROUND1)?;
            let (_, theirs2) = messages[keys_at + 1].open(&pairing, kind::DKG_ROUND2)?;
            let (round2, group) = coordinator_setup.finish(
                &Round1::from_bytes(&theirs1)?,
                &Round2::from_bytes(&theirs2)?,
            )?;
            carrier.send(
                COORDINATOR_KEYS,
                &[Message::seal(
                    &pairing,
                    kind::DKG_ROUND2,
                    DKG_SESSION,
                    &round2.to_bytes(),
                    &mut rng,
                )?],
            )?;
            // No address before the co-signer acknowledges: until then it may
            // not hold its share, and member 3 may not be exported.
            let messages = carrier.receive(COSIGNER_DONE)?;
            one(&messages, 1)?;
            let (_, done) = messages[0].open(&pairing, kind::DKG_DONE)?;
            group.check_done(&Done::from_bytes(&done)?)?;
            let seat = Seat::new("coordinator", network_name, &pairing, &group)?;
            seat.save(&state)?;
            print_seat(&seat);
            if let (Some(restored), Some(Recovery::Coordinator { old_state, .. })) =
                (restored, &recovery)
            {
                let old = Seat::new("coordinator", network_name, &pairing, &restored)?;
                old.save(old_state)?;
                println!(
                    "  the old account's member 3, restored, is in {}: sweep the old account to \
                     the new address with `qr sign --as coordinator --state {}`",
                    old_state.display(),
                    old_state.display()
                );
            }
        }
        "cosigner" => {
            println!("[co-signer] pairing and key generation, network {network_name}");
            let messages = carrier.receive(PAIR_INIT)?;
            one(&messages, 1)?;
            let (responder, response) = Responder::respond(&messages[0].to_pair_init()?, &mut rng)?;
            carrier.send(PAIR_RESPONSE, &[Message::pair_response(&response)])?;
            let messages = carrier.receive(PAIR_CONFIRM)?;
            one(&messages, 2)?;
            let pending = responder.finish(&messages[0].to_pair_confirm()?)?;
            println!("  pairing code: {}", pending.code());
            if !ask("  Does the other device show the same code?", yes)? {
                return Err(CODES_DIFFER.into());
            }
            let pairing = pending.confirm();
            let (_, theirs1) = messages[1].open(&pairing, kind::DKG_ROUND1)?;
            let (cosigner_setup, round1, round2) =
                CosignerSetup::respond(network, &Round1::from_bytes(&theirs1)?)?;
            let mut keys_messages = Vec::new();
            if let Some(Recovery::Cosigner { old, .. }) = &recovery {
                let info = recovery::GroupInfo::new(&old.member()?, &old.ufvk);
                keys_messages.push(Message::seal(
                    &pairing,
                    kind::GROUP_INFO,
                    DKG_SESSION,
                    &info.to_bytes()?,
                    &mut rng,
                )?);
            }
            carrier.send(
                COSIGNER_KEYS,
                &[
                    keys_messages,
                    vec![
                        Message::seal(
                            &pairing,
                            kind::DKG_ROUND1,
                            DKG_SESSION,
                            &round1.to_bytes(),
                            &mut rng,
                        )?,
                        Message::seal(
                            &pairing,
                            kind::DKG_ROUND2,
                            DKG_SESSION,
                            &round2.to_bytes(),
                            &mut rng,
                        )?,
                    ],
                ]
                .concat(),
            )?;
            let messages = carrier.receive(COORDINATOR_KEYS)?;
            one(&messages, 1)?;
            let (_, theirs2) = messages[0].open(&pairing, kind::DKG_ROUND2)?;
            let (cosigner, backup) = cosigner_setup.finish(&Round2::from_bytes(&theirs2)?)?;
            let seat = Seat::new("cosigner", network_name, &pairing, &cosigner)?;
            seat.save(&state)?;
            // Member 3 is encrypted at once (profile 1, spec § 7.1) under a
            // new passphrase, with the group's viewing key; --backup-plain
            // writes the bare string instead, for tests.
            let plain = flag(args, "--backup-plain");
            let (backup_path, passphrase) = if plain {
                let path = state.join("member3-backup.txt");
                fs::write(&path, backup.backup_string()?)?;
                (path, None)
            } else {
                let passphrase = profiles::generate_passphrase();
                let contents = profiles::Contents {
                    backup: zeroize::Zeroizing::new(backup.backup_string()?),
                    ufvk: cosigner.ufvk.clone(),
                    birthday: None,
                    label: Some("FROST 2-of-3, member 3".into()),
                };
                let path = state.join("member3-backup.zkfrost");
                fs::write(&path, profiles::encrypt(&contents, &passphrase)?)?;
                (path, Some(passphrase))
            };
            // Member 3 leaves memory here; what was written is checked, not
            // what was in memory.
            drop(backup);
            let written = match &passphrase {
                None => zeroize::Zeroizing::new(fs::read_to_string(&backup_path)?),
                Some(passphrase) => profiles::decrypt(&fs::read(&backup_path)?, passphrase)?.backup,
            };
            dkg_setup::check_backup(&written, &cosigner).map_err(|e| {
                format!(
                    "the backup written to {} does not restore: {e}",
                    backup_path.display()
                )
            })?;
            drop(written);
            carrier.send(
                COSIGNER_DONE,
                &[Message::seal(
                    &pairing,
                    kind::DKG_DONE,
                    DKG_SESSION,
                    &cosigner.done()?.to_bytes(),
                    &mut rng,
                )?],
            )?;
            print_seat(&seat);
            match &passphrase {
                None => println!(
                    "  member 3 (the backup) written to {} and checked: move it offline and \
                     delete it here. It holds a share and sk, protect it like the seat.",
                    backup_path.display()
                ),
                Some(passphrase) => println!(
                    "  member 3 (the backup) written to {}, encrypted and checked. Its \
                     passphrase, shown only now (write it down, and keep it apart from the \
                     file):\n\n    {}\n\n  Move the file offline and delete it here.",
                    backup_path.display(),
                    **passphrase
                ),
            }
            if let Some(Recovery::Cosigner { old_state, mut old }) = recovery {
                // The old account now answers the new coordinator only: the
                // lost device's pairing is forgotten.
                old.pairing = hex::encode(pairing.to_bytes());
                old.replace(&old_state)?;
                println!(
                    "  the old account ({}) now answers the new coordinator only: sign its \
                     sweep with `qr sign --as cosigner --state {}`",
                    old.address,
                    old_state.display()
                );
            }
        }
        _ => return Err("--as must be coordinator or cosigner".into()),
    }
    println!("  Both devices now show this address. Compare them before funding it.");
    Ok(())
}

fn print_seat(seat: &Seat) {
    println!("  member:      {} ({})", seat.member, seat.role);
    println!("  network:     {}", seat.network);
    println!("  viewing key: {}", seat.ufvk);
    println!("  address:     {}", seat.address);
}

/// The co-signer's acknowledgement again, from its seat, for a coordinator
/// that did not get it at the end of the setup (spec § 4.1).
fn done(args: &[String]) -> Result<(), Box<dyn Error>> {
    let seat = Seat::load(&state_dir(args))?;
    if seat.role != "cosigner" {
        return Err("only the co-signer sends the acknowledgement".into());
    }
    let pairing = seat.pairing()?;
    let member = seat.member()?;
    let done = Done::new(&member, &seat.ufvk)?;
    Carrier::from_args(args)?.send(
        COSIGNER_DONE,
        &[Message::seal(
            &pairing,
            kind::DKG_DONE,
            DKG_SESSION,
            &done.to_bytes(),
            &mut rng(),
        )?],
    )?;
    print_seat(&seat);
    Ok(())
}

fn info(args: &[String]) -> Result<(), Box<dyn Error>> {
    print_seat(&Seat::load(&state_dir(args))?);
    Ok(())
}

fn sign(args: &[String]) -> Result<(), Box<dyn Error>> {
    let role = option(args, "--as").ok_or("--as coordinator|cosigner is required")?;
    let seat = Seat::load(&state_dir(args))?;
    let pairing = seat.pairing()?;
    let member = seat.member()?;
    let mut carrier = Carrier::from_args(args)?;
    let mut rng = rng();
    match role {
        "cosigner" => {
            println!("[co-signer] signing session");
            let messages = carrier.receive(SIGN_REQUEST)?;
            one(&messages, 1)?;
            let (bound, bytes) = messages[0].open(&pairing, kind::SIGN_REQUEST)?;
            let request = Request::from_bytes(&bytes)?;
            let reply = if bound != request.session {
                Reply::Refused {
                    session: request.session,
                    member: member.id(),
                    reason: "the request's envelope and content name different sessions".into(),
                }
            } else {
                match cosigning::review(&member, &request) {
                    Ok(pending) => {
                        print_report("co-signer", pending.report());
                        if ask("  Approve and sign?", flag(args, "--yes"))? {
                            pending.approve()
                        } else {
                            pending.decline()
                        }
                    }
                    Err(refusal) => refusal,
                }
            };
            if let Reply::Refused { reason, .. } = &reply {
                println!("  refused: {reason}");
            }
            carrier.send(
                SIGN_REPLY,
                &[Message::seal(
                    &pairing,
                    kind::SIGN_REPLY,
                    &reply.session(),
                    &reply.to_bytes()?,
                    &mut rng,
                )?],
            )?;
        }
        "coordinator" => {
            let input = option(args, "--pczt").ok_or("--pczt IN is required")?;
            let output = option(args, "--out").ok_or("--out OUT is required")?;
            let pczt = fs::read(input)?;
            println!("[coordinator] signing session");
            let (coordinating, request, report) =
                CoordinatorSession::request(&member, &pczt, &mut rng)?;
            print_report("coordinator", &report);
            carrier.send(
                SIGN_REQUEST,
                &[Message::seal(
                    &pairing,
                    kind::SIGN_REQUEST,
                    &request.session,
                    &request.to_bytes()?,
                    &mut rng,
                )?],
            )?;
            let messages = carrier.receive(SIGN_REPLY)?;
            one(&messages, 1)?;
            let (bound, bytes) = messages[0].open(&pairing, kind::SIGN_REPLY)?;
            if bound != coordinating.session() {
                return Err("the reply's envelope names another session".into());
            }
            let signed = coordinating.finish(&Reply::from_bytes(&bytes)?)?;
            fs::write(output, pczt_io::serialize(signed)?)?;
            println!("  signed, every signature verified under its rk: written to {output}");
        }
        _ => return Err("--as must be coordinator or cosigner".into()),
    }
    Ok(())
}
