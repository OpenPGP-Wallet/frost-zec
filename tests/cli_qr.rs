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
    assert!(Path::new(s).join("member3-backup.txt").exists());

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
