//! `coordinate` and `cosign --policy` as two separate processes, talking through
//! the session folder: a standing policy the payment breaks makes the co-signer
//! refuse without asking, and a policy file naming a rule the co-signer does not
//! enforce, or written for another network, stops `cosign` before a session
//! starts.

mod common;

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use frost_zec::{keys, pczt_io};

/// Starts `frost-zec` in `dir`, where `data/` holds the keys.
fn frost_zec(dir: &Path, args: &[&str], stderr: Stdio) -> Child {
    Command::new(env!("CARGO_BIN_EXE_frost-zec"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
        .spawn()
        .unwrap()
}

/// Waits for each process, at most a minute in all, and returns whether each succeeded.
fn outcomes(children: Vec<Child>) -> Vec<bool> {
    let deadline = Instant::now() + Duration::from_secs(60);
    children
        .into_iter()
        .map(|mut child| {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status.success();
                }
                if Instant::now() > deadline {
                    let _ = child.kill();
                    panic!("a frost-zec process hung");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        })
        .collect()
}

/// A fresh folder with a mainnet group from `keygen`, and the group's viewing key.
fn group(name: &str) -> (std::path::PathBuf, orchard::keys::FullViewingKey) {
    let root = std::env::temp_dir().join(format!("frost-zec-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    assert_eq!(
        outcomes(vec![frost_zec(
            &root,
            &["keygen", "--network", "main"],
            Stdio::null()
        )]),
        vec![true]
    );
    let group: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("data/group.json")).unwrap()).unwrap();
    let (_, fvk) = keys::parse_ufvk(group["ufvk"].as_str().unwrap()).unwrap();
    (root, fvk)
}

#[test]
fn cosign_refuses_by_policy_without_asking() {
    let (root, fvk) = group("cli-cosign-policy");
    let pczt = pczt_io::serialize(build(&fvk, honest(&fvk, text_memo("rent")))).unwrap();
    std::fs::write(root.join("unsigned.pczt"), pczt).unwrap();
    std::fs::write(
        root.join("policy.json"),
        r#"{"network": "main", "per_payment_cap_zat": 1}"#,
    )
    .unwrap();

    // No --yes, and nobody at the prompt (stdin is empty): a payment the
    // policy let through would be declined there, "not approved on the
    // co-signing device". The policy's own reason shows it never got that far.
    let said = root.join("coordinator-stderr.txt");
    let finished = outcomes(vec![
        frost_zec(
            &root,
            &["cosign", "--as", "2", "--policy", "policy.json"],
            Stdio::null(),
        ),
        frost_zec(
            &root,
            &[
                "coordinate",
                "--as",
                "1",
                "--pczt",
                "unsigned.pczt",
                "--out",
                "signed.pczt",
            ],
            Stdio::from(std::fs::File::create(&said).unwrap()),
        ),
    ]);
    // Like any refusal, the co-signer sends it to the coordinator and then
    // exits with it; the coordinator fails with the reason.
    assert_eq!(finished, vec![false, false], "both end with the refusal");
    assert!(!root.join("signed.pczt").exists(), "no signed PCZT");
    let said = std::fs::read_to_string(&said).unwrap();
    assert!(said.contains("policy: a payment of"), "{said}");
    assert!(!said.contains("not approved"), "{said}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cosign_stops_on_a_policy_it_cannot_enforce() {
    let (root, _) = group("cli-cosign-bad-policy");
    std::fs::write(
        root.join("policy.json"),
        r#"{"network": "main", "daily_budget_zat": 50000000}"#,
    )
    .unwrap();
    let said = root.join("cosigner-stderr.txt");
    let finished = outcomes(vec![frost_zec(
        &root,
        &["cosign", "--as", "2", "--policy", "policy.json"],
        Stdio::from(std::fs::File::create(&said).unwrap()),
    )]);
    assert_eq!(finished, vec![false]);
    let said = std::fs::read_to_string(&said).unwrap();
    assert!(said.contains("daily_budget_zat"), "{said}");
    // It stopped before a session began: no commitments were written.
    assert!(!root.join("session").exists(), "no session folder");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn cosign_stops_on_a_policy_for_another_network() {
    let (root, _) = group("cli-cosign-net-policy");
    std::fs::write(
        root.join("policy.json"),
        r#"{"network": "test", "per_payment_cap_zat": 1}"#,
    )
    .unwrap();
    let said = root.join("cosigner-stderr.txt");
    let finished = outcomes(vec![frost_zec(
        &root,
        &["cosign", "--as", "2", "--policy", "policy.json"],
        Stdio::from(std::fs::File::create(&said).unwrap()),
    )]);
    assert_eq!(finished, vec![false]);
    let said = std::fs::read_to_string(&said).unwrap();
    assert!(said.contains("network"), "{said}");
    assert!(!root.join("session").exists(), "no session folder");
    let _ = std::fs::remove_dir_all(&root);
}
