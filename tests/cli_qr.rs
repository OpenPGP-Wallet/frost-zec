//! The `frost-zec qr` commands as two separate processes, a coordinator and a
//! co-signer, exchanging UR text files: pairing, key generation, then a
//! signing session over a real PCZT.

mod common;

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use common::*;
use frost_zec::{keys, pczt_io};

fn frost_zec(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_frost-zec"))
        .args(args)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap()
}

/// Waits for both processes, at most a minute, and requires success.
fn wait(children: Vec<Child>) {
    let deadline = Instant::now() + Duration::from_secs(60);
    for mut child in children {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "a frost-zec process failed: {status}");
                break;
            }
            if Instant::now() > deadline {
                let _ = child.kill();
                panic!("a frost-zec process hung");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn seat_field(dir: &Path, field: &str) -> String {
    let seat: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("seat.json")).unwrap()).unwrap();
    seat[field].as_str().unwrap().to_string()
}

#[test]
fn two_processes_pair_generate_keys_and_sign() {
    let root = std::env::temp_dir().join(format!("frost-zec-cli-qr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (via, c, s) = (
        root.join("via"),
        root.join("coordinator"),
        root.join("cosigner"),
    );
    let (via, c, s) = (
        via.to_str().unwrap(),
        c.to_str().unwrap(),
        s.to_str().unwrap(),
    );

    wait(vec![
        frost_zec(&[
            "qr",
            "setup",
            "--as",
            "coordinator",
            "--network",
            "main",
            "--state",
            c,
            "--via",
            via,
            "--yes",
        ]),
        frost_zec(&[
            "qr",
            "setup",
            "--as",
            "cosigner",
            "--network",
            "main",
            "--state",
            s,
            "--via",
            via,
            "--yes",
        ]),
    ]);
    let address = seat_field(Path::new(c), "address");
    assert_eq!(address, seat_field(Path::new(s), "address"));
    // Member 3 is encrypted at once; no bare string is left.
    assert!(Path::new(s).join("member3-backup.zkfrost").exists());
    assert!(!Path::new(s).join("member3-backup.txt").exists());
    let file = std::fs::read(Path::new(s).join("member3-backup.zkfrost")).unwrap();
    assert!(file.starts_with(b"ZKFROSTB"));
    assert!(!file.windows(8).any(|w| w == b"zkfrost1"));

    // The co-signer can show its acknowledgement again; a coordinator cannot.
    let ack = Path::new(via).join("6-cosigner-done.ur");
    let _ = std::fs::remove_file(&ack);
    wait(vec![frost_zec(&["qr", "done", "--state", s, "--via", via])]);
    assert!(ack.exists());
    let status = Command::new(env!("CARGO_BIN_EXE_frost-zec"))
        .args(["qr", "done", "--state", c, "--via", via])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(!status.success());
    let _ = std::fs::remove_file(&ack);

    let (_, fvk) = keys::parse_ufvk(&seat_field(Path::new(c), "ufvk")).unwrap();
    let pczt = pczt_io::serialize(build(&fvk, honest(&fvk, text_memo("rent")))).unwrap();
    let (input, output) = (root.join("unsigned.pczt"), root.join("signed.pczt"));
    std::fs::write(&input, pczt).unwrap();
    wait(vec![
        frost_zec(&[
            "qr", "sign", "--as", "cosigner", "--state", s, "--via", via, "--yes",
        ]),
        frost_zec(&[
            "qr",
            "sign",
            "--as",
            "coordinator",
            "--state",
            c,
            "--via",
            via,
            "--pczt",
            input.to_str().unwrap(),
            "--out",
            output.to_str().unwrap(),
        ]),
    ]);
    let signed = pczt_io::parse(&std::fs::read(&output).unwrap()).unwrap();
    assert!(
        pczt_io::spends_to_sign(&signed).is_err(),
        "every spend is signed"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Runs `frost-zec` to the end and returns its standard output.
fn run(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_frost-zec"))
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// The coordinator is lost (spec § 7.2): a new one restores member 3 from a
/// backup file, pairs with the co-signer, checks the old group it describes,
/// and the two create a new account. The old account is then swept to the
/// new one, signed by the restored member 3 and the co-signer's member 2.
#[test]
fn a_lost_coordinator_is_replaced_and_the_old_account_swept() {
    let root = std::env::temp_dir().join(format!("frost-zec-cli-recover-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = |name: &str| root.join(name).to_str().unwrap().to_string();
    let (via, c, s) = (dir("via"), dir("coordinator"), dir("cosigner"));

    // The old account.
    wait(vec![
        frost_zec(&[
            "qr",
            "setup",
            "--as",
            "coordinator",
            "--network",
            "main",
            "--state",
            &c,
            "--via",
            &via,
            "--yes",
        ]),
        frost_zec(&[
            "qr",
            "setup",
            "--as",
            "cosigner",
            "--network",
            "main",
            "--state",
            &s,
            "--via",
            &via,
            "--yes",
            "--backup-plain",
        ]),
    ]);
    let old_address = seat_field(Path::new(&c), "address");
    let old_ufvk = seat_field(Path::new(&s), "ufvk");
    let old_pairing = seat_field(Path::new(&s), "pairing");

    // Member 3 kept as a profile 1 file, with the viewing key.
    let out = run(&[
        "backup",
        "protect",
        "--in",
        &format!("{s}/member3-backup.txt"),
        "--ufvk",
        &old_ufvk,
        "--out",
        &dir("member3.zkfrost"),
    ]);
    let passphrase = out
        .lines()
        .skip_while(|l| !l.starts_with("passphrase"))
        .find(|l| l.starts_with("  "))
        .unwrap()
        .trim()
        .to_string();
    std::fs::write(dir("passphrase.txt"), passphrase).unwrap();

    // The coordinator is lost: a new one recovers with the co-signer.
    let (via2, c2, c_old, s2) = (
        dir("via2"),
        dir("coordinator2"),
        dir("restored"),
        dir("cosigner2"),
    );
    wait(vec![
        frost_zec(&[
            "qr",
            "recover",
            "--as",
            "coordinator",
            "--network",
            "main",
            "--state",
            &c2,
            "--old-state",
            &c_old,
            "--backup",
            &dir("member3.zkfrost"),
            "--passphrase-file",
            &dir("passphrase.txt"),
            "--via",
            &via2,
            "--yes",
        ]),
        frost_zec(&[
            "qr",
            "recover",
            "--as",
            "cosigner",
            "--state",
            &s2,
            "--old-state",
            &s,
            "--via",
            &via2,
            "--yes",
        ]),
    ]);
    let new_address = seat_field(Path::new(&c2), "address");
    assert_eq!(new_address, seat_field(Path::new(&s2), "address"));
    assert_ne!(new_address, old_address);
    assert_eq!(seat_field(Path::new(&c_old), "address"), old_address);
    assert_ne!(
        seat_field(Path::new(&s), "pairing"),
        old_pairing,
        "the co-signer forgot the lost device's pairing"
    );

    // The sweep: the old account's note, less the fee, to the new account.
    let (_, old_fvk) = keys::parse_ufvk(&old_ufvk).unwrap();
    let (_, new_fvk) = keys::parse_ufvk(&seat_field(Path::new(&c2), "ufvk")).unwrap();
    let mut sweep = honest(&old_fvk, text_memo("sweep"));
    sweep.outputs[0].to = new_fvk.address_at(0u32, orchard::keys::Scope::External);
    sweep.outputs[0].value = SPEND - fee(2);
    sweep.outputs.truncate(1);
    let pczt = pczt_io::serialize(build(&old_fvk, sweep)).unwrap();
    let (input, output) = (root.join("sweep.pczt"), root.join("swept.pczt"));
    std::fs::write(&input, pczt).unwrap();
    wait(vec![
        frost_zec(&[
            "qr", "sign", "--as", "cosigner", "--state", &s, "--via", &via2, "--yes",
        ]),
        frost_zec(&[
            "qr",
            "sign",
            "--as",
            "coordinator",
            "--state",
            &c_old,
            "--via",
            &via2,
            "--pczt",
            input.to_str().unwrap(),
            "--out",
            output.to_str().unwrap(),
        ]),
    ]);
    let signed = pczt_io::parse(&std::fs::read(&output).unwrap()).unwrap();
    assert!(
        pczt_io::spends_to_sign(&signed).is_err(),
        "the sweep is signed"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// The co-signer is lost (spec § 7.2): the coordinator restores member 3 and
/// signs the sweep with members 1 and 3 itself, after the usual checks. A
/// backup string from another group is refused.
#[test]
fn a_lost_cosigner_is_replaced_by_member_3_on_the_coordinator() {
    let root = std::env::temp_dir().join(format!("frost-zec-cli-local-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let dir = |name: &str| root.join(name).to_str().unwrap().to_string();
    let setup = |c: &str, s: &str, via: &str| {
        wait(vec![
            frost_zec(&[
                "qr",
                "setup",
                "--as",
                "coordinator",
                "--network",
                "test",
                "--state",
                c,
                "--via",
                via,
                "--yes",
            ]),
            frost_zec(&[
                "qr",
                "setup",
                "--as",
                "cosigner",
                "--network",
                "test",
                "--state",
                s,
                "--via",
                via,
                "--yes",
                "--backup-plain",
            ]),
        ]);
    };
    let (c, s) = (dir("coordinator"), dir("cosigner"));
    setup(&c, &s, &dir("via"));

    let (_, fvk) = keys::parse_ufvk(&seat_field(Path::new(&c), "ufvk")).unwrap();
    let mut sweep = honest(&fvk, text_memo("sweep"));
    sweep.outputs[0].value = SPEND - fee(2);
    sweep.outputs.truncate(1);
    let input = root.join("sweep.pczt");
    std::fs::write(&input, pczt_io::serialize(build(&fvk, sweep)).unwrap()).unwrap();
    let output = root.join("swept.pczt");
    run(&[
        "qr",
        "sign-local",
        "--state",
        &c,
        "--backup",
        &format!("{s}/member3-backup.txt"),
        "--pczt",
        input.to_str().unwrap(),
        "--out",
        output.to_str().unwrap(),
        "--yes",
    ]);
    let signed = pczt_io::parse(&std::fs::read(&output).unwrap()).unwrap();
    assert!(
        pczt_io::spends_to_sign(&signed).is_err(),
        "the sweep is signed"
    );

    // Another group's member 3 is refused before anything is signed.
    let (c2, s2) = (dir("coordinator2"), dir("cosigner2"));
    setup(&c2, &s2, &dir("via2"));
    let refused = Command::new(env!("CARGO_BIN_EXE_frost-zec"))
        .args([
            "qr",
            "sign-local",
            "--state",
            &c,
            "--backup",
            &format!("{s2}/member3-backup.txt"),
            "--pczt",
            input.to_str().unwrap(),
            "--out",
            root.join("never.pczt").to_str().unwrap(),
            "--yes",
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert!(!root.join("never.pczt").exists());
    let _ = std::fs::remove_dir_all(&root);
}
