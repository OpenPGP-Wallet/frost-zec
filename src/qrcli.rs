//! `frost-zec qr ...`: the QR protocol of docs/spec.md, as a test co-signer
//! and a test coordinator.
//!
//!   qr setup --as coordinator|cosigner [--network main|test] [--state DIR] [--via DIR|qr|clipboard] [--yes]
//!   qr sign --as cosigner [--state DIR] [--via DIR|qr|clipboard] [--yes]
//!   qr sign --as coordinator --pczt IN --out OUT [--state DIR] [--via DIR|qr|clipboard]
//!   qr info [--state DIR]
//!   qr camera-test [--seconds N] [--save DIR]
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
use frost_zec::cosigning::{
    Commitments, CoordinatorSession, CosignerSession, Member, Reply, Request,
};
use frost_zec::setup::{CoordinatorSetup, CosignerSetup, Group, Round1, Round2};
use frost_zec::wire::{self, Message, kind};
use frost_zec::{interop, keys, pczt_io, session, signing};
use rand10::rand_core::UnwrapErr;
use rand10::rngs::SysRng;
use reddsa::frost::redpallas::keys::{KeyPackage, PublicKeyPackage};
use serde::{Deserialize, Serialize};

use super::{flag, option, print_report, qrview};

const SEAT_FILE: &str = "seat.json";
const DKG_SESSION: &[u8] = b"dkg";

const PAIR_INIT: &str = "1-pair-init.ur";
const PAIR_RESPONSE: &str = "2-pair-response.ur";
const PAIR_CONFIRM: &str = "3-pair-confirm.ur";
const COSIGNER_KEYS: &str = "4-cosigner-keys.ur";
const COORDINATOR_KEYS: &str = "5-coordinator-keys.ur";
const SIGN_COMMITMENTS: &str = "sign-1-commitments.ur";
const SIGN_REQUEST: &str = "sign-2-request.ur";
const SIGN_REPLY: &str = "sign-3-reply.ur";

pub fn run(args: &[String]) -> Result<(), Box<dyn Error>> {
    match args.first().map(String::as_str) {
        Some("setup") => setup(&args[1..]),
        Some("sign") => sign(&args[1..]),
        Some("info") => info(&args[1..]),
        Some("camera-test") => camera_test(&args[1..]),
        _ => Err(
            "usage: frost-zec qr <setup | sign | info | camera-test> [options] (see src/qrcli.rs)"
                .into(),
        ),
    }
}

/// Shows what the webcam reads, for a camera that does not seem to read the
/// codes: point it at a QR code the wallet shows (any step).
#[cfg(feature = "camera")]
fn camera_test(args: &[String]) -> Result<(), Box<dyn Error>> {
    let seconds = match option(args, "--seconds") {
        Some(text) => text.parse().map_err(|_| "--seconds takes a number")?,
        None => 20,
    };
    let save = option(args, "--save").map(PathBuf::from);
    if let Some(dir) = &save {
        fs::create_dir_all(dir)?;
    }
    println!("[camera test] {seconds} s: point the camera at a QR code shown by the wallet");
    let started = Instant::now();
    let report = frost_zec::camera::test(seconds, save.as_deref(), |text| {
        let shown: String = text.chars().take(32).collect();
        println!("  {:5.1} s  read {shown}…", started.elapsed().as_secs_f32());
    })?;
    println!(
        "  camera: {} ({}x{}), {} frames in {seconds} s ({:.0} per second), a code read in {}",
        report.camera,
        report.width,
        report.height,
        report.frames,
        report.frames as f32 / seconds as f32,
        report.decoded
    );
    if let Some(dir) = save {
        println!("  one frame per second saved in {}", dir.display());
    }
    Ok(())
}

#[cfg(not(feature = "camera"))]
fn camera_test(_: &[String]) -> Result<(), Box<dyn Error>> {
    Err("this build cannot read QR codes: build with --features camera".into())
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
    let role = option(args, "--as").ok_or("--as coordinator|cosigner is required")?;
    let network_name = option(args, "--network").unwrap_or("test");
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
                return Err("pairing cancelled: the codes differ".into());
            }
            let pairing = pending.confirm();
            let messages = carrier.receive(COSIGNER_KEYS)?;
            one(&messages, 2)?;
            let (_, theirs1) = messages[0].open(&pairing, kind::DKG_ROUND1)?;
            let (_, theirs2) = messages[1].open(&pairing, kind::DKG_ROUND2)?;
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
            let seat = Seat::new("coordinator", network_name, &pairing, &group)?;
            seat.save(&state)?;
            print_seat(&seat);
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
                return Err("pairing cancelled: the codes differ".into());
            }
            let pairing = pending.confirm();
            let (_, theirs1) = messages[1].open(&pairing, kind::DKG_ROUND1)?;
            let (cosigner_setup, round1, round2) =
                CosignerSetup::respond(network, &Round1::from_bytes(&theirs1)?)?;
            carrier.send(
                COSIGNER_KEYS,
                &[
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
            )?;
            let messages = carrier.receive(COORDINATOR_KEYS)?;
            one(&messages, 1)?;
            let (_, theirs2) = messages[0].open(&pairing, kind::DKG_ROUND2)?;
            let (cosigner, backup) = cosigner_setup.finish(&Round2::from_bytes(&theirs2)?)?;
            let seat = Seat::new("cosigner", network_name, &pairing, &cosigner)?;
            seat.save(&state)?;
            let backup_path = state.join("member3-backup.txt");
            fs::write(&backup_path, backup.backup_string()?)?;
            print_seat(&seat);
            println!(
                "  member 3 (the backup) written to {}: move it offline and delete it here. \
                 It holds a share and sk, protect it like the seat.",
                backup_path.display()
            );
        }
        _ => return Err("--as must be coordinator or cosigner".into()),
    }
    println!("  Compare the address with the other device before funding it.");
    Ok(())
}

fn print_seat(seat: &Seat) {
    println!("  member:      {} ({})", seat.member, seat.role);
    println!("  network:     {}", seat.network);
    println!("  viewing key: {}", seat.ufvk);
    println!("  address:     {}", seat.address);
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
            let (session, opening) = CosignerSession::open(&member, &mut rng);
            carrier.send(
                SIGN_COMMITMENTS,
                &[Message::seal(
                    &pairing,
                    kind::SIGN_COMMITMENTS,
                    &opening.session,
                    &opening.to_bytes()?,
                    &mut rng,
                )?],
            )?;
            let messages = carrier.receive(SIGN_REQUEST)?;
            one(&messages, 1)?;
            let (bound, bytes) = messages[0].open(&pairing, kind::SIGN_REQUEST)?;
            let request = Request::from_bytes(&bytes)?;
            let reply = if bound != request.session {
                Reply::Refused {
                    session: opening.session,
                    member: member.id(),
                    reason: "the request's envelope and content name different sessions".into(),
                }
            } else {
                match session.review(&request) {
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
                    &reply.to_bytes(),
                    &mut rng,
                )?],
            )?;
        }
        "coordinator" => {
            let input = option(args, "--pczt").ok_or("--pczt IN is required")?;
            let output = option(args, "--out").ok_or("--out OUT is required")?;
            let pczt = fs::read(input)?;
            println!("[coordinator] signing session");
            let messages = carrier.receive(SIGN_COMMITMENTS)?;
            one(&messages, 1)?;
            let (bound, bytes) = messages[0].open(&pairing, kind::SIGN_COMMITMENTS)?;
            let opening = Commitments::from_bytes(&bytes)?;
            if bound != opening.session {
                return Err("the commitments' envelope and content name different sessions".into());
            }
            let (coordinating, request, report) =
                CoordinatorSession::request(&member, &pczt, &opening)?;
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
            let (_, bytes) = messages[0].open(&pairing, kind::SIGN_REPLY)?;
            let signed = coordinating.finish(&Reply::from_bytes(&bytes)?)?;
            fs::write(output, pczt_io::serialize(signed)?)?;
            println!("  signed, every signature verified under its rk: written to {output}");
        }
        _ => return Err("--as must be coordinator or cosigner".into()),
    }
    Ok(())
}
