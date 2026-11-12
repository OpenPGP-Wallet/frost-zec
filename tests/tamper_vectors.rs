//! Shared tamper cases: `vectors/tamper/`, in the format of docs/spec.md § 8.2.
//!
//! `every_case_passes` runs each case against this co-signer's checks, as any
//! signer's runner would: the accepted PCZT must be accepted and show exactly
//! the approved payments, and the refused one must be refused with one of the
//! case's classes (this co-signer's errors are mapped to classes below). A
//! payment shown that differs from the approved one counts as a `payment`
//! refusal: the user, comparing, refuses it.
//!
//! `write_cases` (ignored) builds the cases again with the PCZT factory of
//! tests/common:
//!
//!     cargo test --test tamper_vectors write_cases -- --ignored
//!
//! PCZTs are randomized, so writing them again changes every file: do it only
//! when a case changes. A new case goes to the maintainers listed in
//! frost-zec#7 first, through private vulnerability reporting.

mod common;

use std::fs;
use std::path::Path;

use common::*;
use frost_zec::{check, keys, pczt_io};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use pczt::Pczt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zcash_protocol::consensus::NetworkType;
use zcash_protocol::memo::MemoBytes;

const DIR: &str = "vectors/tamper";
/// Time of Mainnet block 3,550,000, the height the factory targets
/// (lightwalletd, GetBlock).
const CLOCK: u64 = 1_794_101_577;
/// A height after ZIP 2009's lower fee starts on Mainnet (3,590,000), and its
/// expected time: block 3,558,933 was mined at 1,794,325,164, then one block
/// every 25 seconds (ZIP 218).
const LATER_HEIGHT: u32 = 3_600_000;
const LATER_CLOCK: u64 = 1_794_325_164 + (3_600_000 - 3_558_933) * 25;
const MEMO: &str = "invoice 42";

fn group() -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap())
}

/// The receiver paid, encoded on its own as a unified address.
fn paid() -> String {
    keys::encode_address(
        &stranger().address_at(0u32, Scope::External),
        NetworkType::Main,
    )
    .unwrap()
}

struct Payment {
    address: String,
    amount: u64,
    memo: Option<&'static str>,
}

fn usual() -> Vec<Payment> {
    vec![Payment {
        address: paid(),
        amount: PAYMENT,
        memo: Some(MEMO),
    }]
}

struct Case {
    id: &'static str,
    description: &'static str,
    changed: &'static str,
    class: &'static [&'static str],
    fee_rule: Option<&'static str>,
    part: Option<&'static str>,
    height: u32,
    clock: u64,
    approved: Vec<Payment>,
    accepted: Pczt,
    refused: Option<Pczt>,
}

impl Case {
    fn new(id: &'static str, class: &'static [&'static str], accepted: Pczt) -> Case {
        Case {
            id,
            description: "",
            changed: "",
            class,
            fee_rule: None,
            part: None,
            height: HEIGHT,
            clock: CLOCK,
            approved: usual(),
            accepted,
            refused: None,
        }
    }
    fn refused(mut self, refused: Pczt, changed: &'static str) -> Case {
        self.refused = Some(refused);
        self.changed = changed;
        self
    }
    fn about(mut self, description: &'static str) -> Case {
        self.description = description;
        self
    }
}

fn honest_tx() -> Tx {
    honest(&group(), text_memo(MEMO))
}

fn built(tx: Tx) -> Pczt {
    build(&group(), tx)
}

/// A payment of the whole note less the fee: no change, so the builder pads
/// the second output itself.
fn no_change(tx: &mut Tx) {
    tx.outputs[0].value = SPEND - fee(2);
    tx.outputs.truncate(1);
}

fn cases() -> Vec<Case> {
    let honest = || built(honest_tx());
    let mut cases = Vec::new();

    cases.push(
        Case::new("payment-without-outgoing-key", &["unreadable-output"], honest())
            .refused(
                {
                    let mut tx = honest_tx();
                    tx.outputs[0].ovk = Ovk::Without;
                    built(tx)
                },
                "payment output encrypted with no outgoing viewing key",
            )
            .about("The payment is encrypted without the group's outgoing viewing key, so the co-signer cannot read back what it would sign."),
    );

    let accepted = honest();
    let garbled = garble_ciphertext(&accepted, PAYMENT);
    cases.push(
        Case::new("payment-ciphertext-garbled", &["unreadable-output"], accepted)
            .refused(garbled, "one byte of the payment's note ciphertext flipped")
            .about("The payment's note commitment still matches, but its ciphertext does not decrypt: the recipient would never find the funds."),
    );

    let accepted = {
        let mut tx = honest_tx();
        tx.outputs[1].ovk = Ovk::Without;
        built(tx)
    };
    let garbled = garble_ciphertext(&accepted, SPEND - PAYMENT - fee(2));
    cases.push(
        Case::new("change-ciphertext-garbled", &["unreadable-output"], accepted)
            .refused(garbled, "one byte of the change's note ciphertext flipped")
            .about("The change's ciphertext does not decrypt with the group's incoming viewing key: the group would never find its change."),
    );

    cases.push(
        Case::new("orchard-bundle-payout", &["foreign-pool"], honest())
            .refused(
                {
                    let mut tx = honest_tx();
                    tx.outputs[1].value = SPEND - PAYMENT - 3_000 - fee(4);
                    tx.orchard_payment =
                        Some((stranger().address_at(5u32, Scope::External), 3_000));
                    built(tx)
                },
                "3,000 zatoshis of the change paid to a stranger through an Orchard bundle",
            )
            .about("Value spent from the group's Ironwood notes leaves through an Orchard bundle. A signer that only decodes Ironwood would show it as fee."),
    );

    cases.push(
        Case::new("foreign-note", &["foreign-spend"], honest())
            .refused(
                {
                    let mut tx = honest_tx();
                    tx.owner = stranger();
                    built(tx)
                },
                "the spent note belongs to another wallet",
            )
            .about("The note spent is not the group's: its nullifier and randomized key do not follow from the group's viewing key."),
    );

    cases.push(
        Case::new("io-finalizer-skipped", &["structure"], honest())
            .refused(
                {
                    let mut tx = honest_tx();
                    tx.finalize = false;
                    built(tx)
                },
                "the IO Finalizer was not run",
            )
            .about(
                "The dummy spend is unsigned and its spending key is still in the PCZT (ZIP 374).",
            ),
    );

    let accepted = honest();
    let zeroed = zero_randomizer(&accepted, &group(), SPEND);
    cases.push(
        Case::new("zero-randomizer", &["structure"], accepted)
            .refused(zeroed, "the spend's randomizer set to zero and its rk to the group key")
            .about("A zero randomizer puts the group's key itself on chain as rk, so every such spend can be linked."),
    );

    let mut case = Case::new("fee-above-zip-317", &["fee"], honest())
        .refused(
            {
                let mut tx = honest_tx();
                tx.outputs[1].value -= 50_000;
                tx.fee = Some(fee(2) + 50_000);
                built(tx)
            },
            "change lowered by 50,000 zatoshis; fee raised by as much",
        )
        .about("The fee shown is true, but above ZIP 317 for the two actions the payment needs.");
    case.fee_rule = Some("zip317");
    cases.push(case);

    let mut case = Case::new("zero-value-padding", &["padding", "fee"], honest())
        .refused(
            {
                let mut tx = honest_tx();
                tx.outputs[1].value = SPEND - PAYMENT - fee(3);
                tx.outputs.push(zero_value_output(
                    stranger().address_at(3u32, Scope::External),
                    Ovk::Without,
                ));
                built(tx)
            },
            "a zero-value output added, its ZIP 317 fee taken from the change",
        )
        .about("The fee is ZIP 317's for three actions, but the payment needs two: only the action count shows the padding.");
    case.fee_rule = Some("zip317");
    cases.push(case);

    let accepted = {
        let mut tx = honest_tx();
        no_change(&mut tx);
        built(tx)
    };
    let mut case = Case::new("zero-value-note-to-stranger", &["hidden-output"], accepted)
        .refused(
            {
                let mut tx = honest_tx();
                tx.outputs[0].value = SPEND - fee(2);
                tx.outputs[1] = zero_value_output(
                    stranger().address_at(3u32, Scope::External),
                    Ovk::External,
                );
                built(tx)
            },
            "the builder's padding output replaced by a zero-value note to a stranger",
        )
        .about("A payment with no change leaves one output to padding. A zero-value note to a stranger there lands on chain with a memo the user never saw.");
    case.approved[0].amount = SPEND - fee(2);
    cases.push(case);

    cases.push(
        Case::new("expiry-far-ahead", &["expiry"], honest())
            .refused(
                {
                    let mut tx = honest_tx();
                    tx.expiry = Some(499_999_999);
                    built(tx)
                },
                "expiry height set to 499,999,999",
            )
            .about("A coordinator holding a signature with a far expiry could broadcast it much later, after the user approved the same payment again."),
    );

    let paid_receiver = stranger().address_at(0u32, Scope::External);
    let invoice = invoice_address(&paid_receiver, NetworkType::Main);
    let accepted = named(honest(), &invoice);
    let attacker = invoice_address(
        &stranger().address_at(5u32, Scope::External),
        NetworkType::Main,
    );
    let swapped = named(accepted.clone(), &attacker);
    let mut case = Case::new("user-address-not-the-one-paid", &["payment"], accepted)
        .refused(swapped, "user_address names another unified address")
        .about("The address the user is shown (user_address) does not hold the receiver paid: the user would approve a payment to an address they recognize while the funds go elsewhere.");
    case.approved[0].address = invoice.clone();
    case.part = Some("recipient");
    cases.push(case);

    let accepted = named(honest(), &invoice);
    let other_network = named(
        accepted.clone(),
        &invoice_address(&paid_receiver, NetworkType::Test),
    );
    let mut case = Case::new("user-address-other-network", &["payment"], accepted)
        .refused(
            other_network,
            "user_address is the same receiver encoded for testnet",
        )
        .about("The address shown is on another network than the group's.");
    case.approved[0].address = invoice;
    case.part = Some("recipient");
    cases.push(case);

    // Accepted only: a signer must not refuse these.
    let mut case = Case::new(
        "fee-at-zip-2009-rate",
        &["fee"],
        built({
            let mut tx = honest_tx();
            tx.height = Some(LATER_HEIGHT);
            tx.outputs[1].value = SPEND - PAYMENT - 2_000;
            tx.fee = Some(2_000);
            tx
        }),
    )
    .about(
        "The fee is ZIP 2009's, 1,000 zatoshis per action, at a height after it starts on Mainnet.",
    );
    case.fee_rule = Some("zip2009");
    case.height = LATER_HEIGHT;
    case.clock = LATER_CLOCK;
    cases.push(case);

    cases.push(
        Case::new(
            "change-without-outgoing-key",
            &["unreadable-output"],
            built({
                let mut tx = honest_tx();
                tx.outputs[1].ovk = Ovk::Without;
                tx
            }),
        )
        .about("zcash_client_backend encrypts change with no outgoing viewing key by default; the group reads it with its incoming viewing key."),
    );

    let mut case = Case::new(
        "zero-value-note-to-the-group",
        &["hidden-output"],
        built({
            let mut tx = honest_tx();
            tx.outputs[0].value = SPEND - fee(2);
            tx.outputs[1] =
                zero_value_output(group().address_at(0u32, Scope::Internal), Ovk::Internal);
            tx
        }),
    )
    .about("A zero-value note to the group itself moves nothing; it is shown with its memo, not refused.");
    case.approved[0].amount = SPEND - fee(2);
    cases.push(case);

    let mut case = Case::new(
        "two-spends",
        &["padding", "fee"],
        built(two_spends(&group(), text_memo(MEMO))),
    )
    .about("Two of the group's notes pay one payment and its change: two actions, the fee ZIP 317's for two.");
    case.fee_rule = Some("zip317");
    cases.push(case);

    cases
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[test]
#[ignore = "writes vectors/tamper again, with new random PCZTs"]
fn write_cases() {
    let ufvk = keys::ufvk(&group(), NetworkType::Main).unwrap();
    let own = keys::address(&group(), NetworkType::Main).unwrap();
    for case in cases() {
        let dir = Path::new(DIR).join(case.id);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let accepted = pczt_io::serialize(case.accepted.clone()).unwrap();
        fs::write(dir.join("accepted.pczt"), &accepted).unwrap();
        let mut value = json!({
            "id": case.id,
            "format": 1,
            "description": case.description,
            "class": case.class,
            "network": "main",
            "height": case.height,
            "clock": case.clock,
            "group": { "ufvk": ufvk, "own_addresses": [own] },
            "approved": {
                "payments": case.approved.iter().map(|p| {
                    let mut payment = json!({ "address": p.address, "amount": p.amount });
                    if let Some(memo) = p.memo {
                        payment["memo"] = json!(memo);
                    }
                    payment
                }).collect::<Vec<_>>(),
            },
            "accepted": {
                "sha256": sha256(&accepted),
                "sighash": hex::encode(pczt_io::sighash(&case.accepted).unwrap()),
            },
        });
        if let Some(fee_rule) = case.fee_rule {
            value["fee_rule"] = json!(fee_rule);
        }
        if let Some(part) = case.part {
            value["part"] = json!(part);
        }
        if let Some(refused) = case.refused {
            let refused = pczt_io::serialize(refused).unwrap();
            fs::write(dir.join("refused.pczt"), &refused).unwrap();
            value["changed"] = json!(case.changed);
            value["refused"] = json!({ "sha256": sha256(&refused) });
        }
        let mut text = serde_json::to_string_pretty(&value).unwrap();
        text.push('\n');
        fs::write(dir.join("case.json"), text).unwrap();
    }
}

/// This co-signer's errors, mapped to the shared refusal classes. An error
/// that maps to nothing fails the run: every refusal must have a class.
fn class_of(error: &str) -> &'static str {
    const MAP: [(&str, &str); 14] = [
        ("does not decode", "foreign-pool"),
        ("spent note", "foreign-spend"),
        ("outgoing viewing key", "unreadable-output"),
        ("cannot decrypt", "unreadable-output"),
        ("zero-value note to another address", "hidden-output"),
        ("more than ZIP 317", "fee"),
        ("extra ones move no value", "padding"),
        ("far beyond", "expiry"),
        ("never expires", "expiry"),
        ("not the one it pays", "payment"),
        ("randomizer", "structure"),
        ("dummy", "structure"),
        ("anchor", "structure"),
        ("commitment", "structure"),
    ];
    MAP.iter()
        .find(|(text, _)| error.contains(text))
        .map(|(_, class)| *class)
        .unwrap_or("unclassified")
}

/// The payments shown, as (amount line, memo line) pairs.
fn shown_payments(report: &check::Report) -> Vec<(String, String)> {
    let lines = &report.lines;
    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("PAY "))
        .map(|(i, line)| {
            let memo = lines.get(i + 1).map(|m| m.trim().to_string());
            (line.clone(), memo.unwrap_or_default())
        })
        .collect()
}

/// The approved payments as this co-signer would show them.
fn expected_payments(case: &Value, network: NetworkType) -> Vec<(String, String)> {
    case["approved"]["payments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let amount = check::amount(p["amount"].as_u64().unwrap(), network);
            let address = p["address"].as_str().unwrap();
            let memo = match p.get("memo").and_then(Value::as_str) {
                Some(text) => MemoBytes::from_bytes(text.as_bytes()).unwrap(),
                None => MemoBytes::empty(),
            };
            (
                format!("PAY {amount} to {address}"),
                check::describe_memo(memo.as_array()),
            )
        })
        .collect()
}

#[test]
fn every_case_passes() {
    let mut ids: Vec<_> = fs::read_dir(DIR)
        .unwrap()
        .filter_map(|entry| {
            let path = entry.unwrap().path();
            path.is_dir().then_some(path)
        })
        .collect();
    ids.sort();
    assert!(ids.len() >= 17, "{} cases", ids.len());
    for dir in ids {
        let case: Value =
            serde_json::from_slice(&fs::read(dir.join("case.json")).unwrap()).unwrap();
        let id = case["id"].as_str().unwrap();
        assert_eq!(case["format"], 1, "{id}");
        assert_eq!(dir.file_name().unwrap().to_str(), Some(id));
        let network = match case["network"].as_str().unwrap() {
            "main" => NetworkType::Main,
            "test" => NetworkType::Test,
            other => panic!("{id}: network {other}"),
        };
        let (ufvk_network, fvk) =
            keys::parse_ufvk(case["group"]["ufvk"].as_str().unwrap()).unwrap();
        assert_eq!(ufvk_network, network, "{id}");
        let clock = case["clock"].as_u64().unwrap();
        let classes: Vec<&str> = case["class"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        if classes.contains(&"fee") {
            assert!(
                case.get("fee_rule").is_some(),
                "{id}: a fee case names its rule"
            );
        }
        if let Some(part) = case.get("part") {
            assert!(
                classes.contains(&"payment"),
                "{id}: part only in payment cases"
            );
            assert!(
                ["recipient", "amount", "memo"].contains(&part.as_str().unwrap()),
                "{id}"
            );
        }

        let accepted = fs::read(dir.join("accepted.pczt")).unwrap();
        assert_eq!(sha256(&accepted), case["accepted"]["sha256"], "{id}");
        let pczt = pczt_io::parse(&accepted).unwrap();
        let report = check::analyze_at(&pczt, &fvk, network, clock)
            .unwrap_or_else(|e| panic!("{id}: the accepted PCZT is refused: {e}"));
        assert_eq!(
            shown_payments(&report),
            expected_payments(&case, network),
            "{id}: the accepted PCZT does not show the approved payments"
        );
        assert_eq!(
            hex::encode(pczt_io::sighash(&pczt).unwrap()),
            case["accepted"]["sighash"],
            "{id}"
        );

        let Some(refused_sha) = case.get("refused").map(|r| &r["sha256"]) else {
            assert!(!dir.join("refused.pczt").exists(), "{id}");
            continue;
        };
        let refused = fs::read(dir.join("refused.pczt")).unwrap();
        assert_eq!(&Value::from(sha256(&refused)), refused_sha, "{id}");
        let class = match pczt_io::parse(&refused)
            .map_err(|e| e.to_string())
            .and_then(|pczt| {
                check::analyze_at(&pczt, &fvk, network, clock).map_err(|e| e.to_string())
            }) {
            Err(error) => {
                let class = class_of(&error);
                assert_ne!(class, "unclassified", "{id}: no class for \"{error}\"");
                class
            }
            // Accepted, but showing another payment than the approved one:
            // the user, comparing, refuses it.
            Ok(report) if shown_payments(&report) != expected_payments(&case, network) => "payment",
            Ok(report) => panic!("{id}: the refused PCZT is accepted: {:?}", report.lines),
        };
        assert!(
            classes.contains(&class),
            "{id}: refused as {class}, expected one of {classes:?}"
        );
    }
}
