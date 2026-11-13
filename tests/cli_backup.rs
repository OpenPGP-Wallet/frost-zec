//! `frost-zec backup protect | open | words | from-words`: a member backup
//! string through both profiles and back, as a user would run them.

use std::fs;
use std::path::Path;
use std::process::Command;

use frost_zec::{backup, dkg, keys, signing};
use zcash_protocol::consensus::NetworkType;

fn frost_zec(args: &[&str]) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_frost-zec"))
        .args(args)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&output.stdout).to_string()
        + &String::from_utf8_lossy(&output.stderr);
    (output.status.success(), text)
}

#[test]
fn a_member_through_both_profiles_and_back() {
    let root = std::env::temp_dir().join(format!("frost-zec-cli-backup-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let path = |name: &str| root.join(name).to_str().unwrap().to_string();

    let (key_packages, public_key_package) = dkg::run(3, 2).unwrap();
    let ak = signing::group_ak(&public_key_package).unwrap();
    let sk: [u8; 32] = rand::random();
    let fvk = keys::derive(&sk, &ak).unwrap().fvk;
    let ufvk = keys::ufvk(&fvk, NetworkType::Test).unwrap();
    let string = backup::Backup::new(key_packages.values().last().unwrap(), 3, &sk)
        .unwrap()
        .encode()
        .unwrap();
    fs::write(path("member3.txt"), format!("{string}\n")).unwrap();

    // Profile 1: protect, then open with the passphrase shown once.
    let (ok, out) = frost_zec(&[
        "backup",
        "protect",
        "--in",
        &path("member3.txt"),
        "--ufvk",
        &ufvk,
        "--birthday",
        "4600000",
        "--label",
        "test group",
        "--out",
        &path("member3.zkfrost"),
    ]);
    assert!(ok, "{out}");
    let passphrase = out
        .lines()
        .skip_while(|l| !l.starts_with("passphrase"))
        .find(|l| l.starts_with("  "))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(passphrase.split_whitespace().count(), 12);
    assert!(
        !fs::read(path("member3.zkfrost"))
            .unwrap()
            .windows(7)
            .any(|w| w == b"zkfrost")
    );
    fs::write(path("passphrase.txt"), &passphrase).unwrap();
    let (ok, out) = frost_zec(&[
        "backup",
        "open",
        "--in",
        &path("member3.zkfrost"),
        "--passphrase-file",
        &path("passphrase.txt"),
        "--out",
        &path("opened.txt"),
    ]);
    assert!(ok, "{out}");
    assert!(
        out.contains("member 3, threshold 2 of 3, network Test"),
        "{out}"
    );
    assert!(out.contains("birthday height: 4600000"), "{out}");
    assert_eq!(
        fs::read_to_string(path("opened.txt")).unwrap().trim(),
        string
    );
    fs::write(path("wrong.txt"), "not the passphrase").unwrap();
    let (ok, _) = frost_zec(&[
        "backup",
        "open",
        "--in",
        &path("member3.zkfrost"),
        "--passphrase-file",
        &path("wrong.txt"),
    ]);
    assert!(!ok);

    // Profile 2: the words, numbered as printed, then back to the string.
    let (ok, out) = frost_zec(&["backup", "words", "--in", &path("member3.txt")]);
    assert!(ok, "{out}");
    let numbered: Vec<&str> = out
        .lines()
        .filter(|l| {
            l.trim_start()
                .split('.')
                .next()
                .is_some_and(|n| n.trim().parse::<u32>().is_ok())
        })
        .collect();
    assert_eq!(numbered.len(), 51, "{out}");
    fs::write(path("words.txt"), numbered.join("\n")).unwrap();
    let (ok, out) = frost_zec(&[
        "backup",
        "from-words",
        "--in",
        &path("words.txt"),
        "--ufvk",
        &ufvk,
        "--out",
        &path("from-words.txt"),
    ]);
    assert!(ok, "{out}");
    assert_eq!(
        fs::read_to_string(path("from-words.txt")).unwrap().trim(),
        string
    );

    // One word miscopied in the sk part: found with the viewing key.
    let mut words: Vec<String> = numbered
        .iter()
        .map(|l| l.split_whitespace().last().unwrap().to_string())
        .collect();
    words[45] = if words[45] == "zoo" {
        "abandon".into()
    } else {
        "zoo".into()
    };
    fs::write(path("miscopied.txt"), words.join(" ")).unwrap();
    let (ok, out) = frost_zec(&[
        "backup",
        "from-words",
        "--in",
        &path("miscopied.txt"),
        "--ufvk",
        &ufvk,
        "--out",
        &path("corrected.txt"),
    ]);
    if ok {
        assert!(out.contains("miscopied"), "{out}");
        assert_eq!(
            fs::read_to_string(path("corrected.txt")).unwrap().trim(),
            string
        );
    } else {
        // Rarely, two corrections fit: the tool says so rather than guess.
        assert!(out.contains("corrections of one word fit"), "{out}");
    }
    let (ok, _) = frost_zec(&["backup", "from-words", "--in", &path("miscopied.txt")]);
    assert!(
        !ok,
        "without the viewing key, a miscopied word is only reported"
    );
    let _ = Path::new(&root).exists() && fs::remove_dir_all(&root).is_ok();
}
