//! Tamper suite: PCZTs a dishonest coordinator could send, which the co-signer
//! must refuse, or show exactly as they will be signed.
//!
//! The PCZTs are built with zcash_primitives' builder, spending an invented
//! note through a made-up Merkle path, so no chain is needed. The co-signer's
//! checks never look at the chain: what they verify is the PCZT against itself
//! and against the group's keys.

mod common;

use common::*;
use frost_zec::{check, keys, pczt_io};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use pczt::Pczt;
use pczt::roles::redactor::Redactor;
use pczt::roles::updater::Updater;
use zcash_protocol::consensus::NetworkType;
use zcash_protocol::memo::MemoBytes;

fn group() -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap())
}

fn analyze(pczt: &Pczt) -> Result<check::Report, String> {
    check::analyze(pczt, &group(), NetworkType::Main).map_err(|e| e.to_string())
}

fn stranger_address() -> String {
    keys::encode_address(
        &stranger().address_at(0u32, Scope::External),
        NetworkType::Main,
    )
    .unwrap()
}

#[test]
fn an_honest_payment_is_shown_in_full() {
    let pczt = build(&group(), honest(&group(), text_memo("invoice 42")));
    let report = analyze(&pczt).unwrap();
    let shown = report.lines.join("\n");
    assert!(
        shown.contains("spend 0.01000000 ZEC from this group"),
        "{shown}"
    );
    assert!(
        shown.contains(&format!("PAY 0.00400000 ZEC to {}", stranger_address())),
        "{shown}"
    );
    assert!(shown.contains("memo: \"invoice 42\""), "{shown}");
    assert!(
        shown.contains("change 0.00590000 ZEC back to this group"),
        "{shown}"
    );
    assert!(shown.contains("fee 0.00010000 ZEC"), "{shown}");
    assert!(
        report
            .warnings
            .iter()
            .all(|w| w.starts_with("v6 pre-authorization")),
        "{:?}",
        report.warnings
    );
}

#[test]
fn a_payment_the_group_cannot_read_back_is_refused() {
    let mut tx = honest(&group(), text_memo("invoice 42"));
    tx.outputs[0].ovk = Ovk::Without;
    let refused = analyze(&build(&group(), tx)).unwrap_err();
    assert!(refused.contains("outgoing viewing key"), "{refused}");
}

/// zcash_client_backend encrypts change with no outgoing key by default. The
/// group decrypts its change with its incoming viewing key instead.
#[test]
fn change_without_an_outgoing_key_is_accepted() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.outputs[1].ovk = Ovk::Without;
    let shown = analyze(&build(&group(), tx)).unwrap().lines.join("\n");
    assert!(
        shown.contains("change 0.00590000 ZEC back to this group"),
        "{shown}"
    );
}

/// Flips one byte inside the note ciphertext of the output worth `value`. The
/// note commitment still matches the claimed note, so only decrypting the
/// ciphertext can notice: the recipient would never find these funds.
fn garble_ciphertext(pczt: &Pczt, value: u64) -> Pczt {
    let mut ciphertext = None;
    pczt::roles::low_level_signer::Signer::new(pczt.clone())
        .sign_ironwood_with(|_, bundle, _| -> Result<(), pczt_io::TxError> {
            for action in bundle.actions() {
                if action.output().value().map(|v| v.inner()) == Some(value) {
                    ciphertext = Some(
                        action
                            .output()
                            .encrypted_note()
                            .enc_ciphertext
                            .as_ref()
                            .to_vec(),
                    );
                }
            }
            Ok(())
        })
        .unwrap();
    let ciphertext = ciphertext.expect("an output with this value");
    let mut bytes = pczt_io::serialize(pczt.clone()).unwrap();
    let at = bytes
        .windows(ciphertext.len())
        .position(|window| window == ciphertext.as_slice())
        .expect("the ciphertext in the serialized PCZT");
    bytes[at + 100] ^= 1;
    pczt_io::parse(&bytes).unwrap()
}

#[test]
fn a_garbled_change_ciphertext_is_refused() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.outputs[1].ovk = Ovk::Without;
    let pczt = garble_ciphertext(&build(&group(), tx), SPEND - PAYMENT - fee(2));
    let refused = analyze(&pczt).unwrap_err();
    assert!(
        refused.contains("cannot decrypt its own output"),
        "{refused}"
    );
}

#[test]
fn a_garbled_payment_ciphertext_is_refused() {
    let pczt = garble_ciphertext(
        &build(&group(), honest(&group(), text_memo("invoice 42"))),
        PAYMENT,
    );
    let refused = analyze(&pczt).unwrap_err();
    assert!(refused.contains("outgoing viewing key"), "{refused}");
}

#[test]
fn a_memo_cannot_rewrite_the_screen() {
    let pczt = build(
        &group(),
        honest(&group(), text_memo("ok\u{202E}evil\nPAY 0.00000001 ZEC")),
    );
    let shown = analyze(&pczt).unwrap().lines.join("\n");
    assert!(!shown.contains('\u{202E}'), "{shown}");
    let memo_line = shown.lines().find(|l| l.contains("memo:")).unwrap();
    assert!(
        memo_line.contains("\\u{202e}") && memo_line.contains("\\n"),
        "{memo_line}"
    );
}

#[test]
fn value_paid_out_through_an_orchard_bundle_is_refused() {
    let mut tx = honest(&group(), MemoBytes::empty());
    let attacker = stranger().address_at(5u32, Scope::External);
    // The Orchard part adds two logical actions (its spend and output are padded
    // to two actions): the group's change pays for them.
    tx.outputs[1].value = SPEND - PAYMENT - 3_000 - fee(4);
    tx.orchard_payment = Some((attacker, 3_000));
    let refused = analyze(&build(&group(), tx)).unwrap_err();
    assert!(refused.contains("Orchard"), "{refused}");
}

#[test]
fn a_note_of_another_wallet_is_refused() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.owner = stranger();
    let refused = analyze(&build(&group(), tx)).unwrap_err();
    assert!(refused.contains("spent note"), "{refused}");
}

#[test]
fn a_pczt_that_skipped_the_io_finalizer_is_refused() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.finalize = false;
    assert!(analyze(&build(&group(), tx)).is_err());
}

/// A unified address with several receivers, as wallets hand them out: the
/// given Orchard receiver and a transparent one.
fn invoice_address(orchard: &orchard::Address, network: NetworkType) -> String {
    use zcash_address::unified::{self, Encoding};
    unified::Address::try_from_items(
        unified::Revision::R0,
        vec![
            unified::Uitem::Data(unified::Receiver::Orchard(orchard.to_raw_address_bytes())),
            unified::Uitem::Data(unified::Receiver::P2pkh([7; 20])),
        ],
    )
    .unwrap()
    .encode(&network)
}

/// Writes `address` as the `user_address` of every output, as
/// zcash_client_backend does for a payment's output.
fn named(pczt: Pczt, address: &str) -> Pczt {
    let count = action_count(&pczt);
    let mut labelled = pczt;
    for index in 0..count {
        labelled = Updater::new(labelled)
            .update_ironwood_with(|mut bundle| {
                bundle.update_action_with(index, |mut action| {
                    action.set_output_user_address(address.into());
                    Ok(())
                })
            })
            .unwrap()
            .finish();
    }
    labelled
}

/// The user compares the co-signer's screen with the address they were given.
/// That address usually has several receivers, so the paid receiver alone,
/// encoded on its own, is another string: the co-signer shows the given one,
/// once it has checked that it holds the receiver paid.
#[test]
fn the_address_the_user_was_given_is_shown_once_checked() {
    let pczt = build(&group(), honest(&group(), MemoBytes::empty()));
    let invoice = invoice_address(
        &stranger().address_at(0u32, Scope::External),
        NetworkType::Main,
    );
    assert_ne!(invoice, stranger_address());
    let shown = analyze(&named(pczt, &invoice)).unwrap().lines.join("\n");
    assert!(
        shown.contains(&format!("PAY 0.00400000 ZEC to {invoice}")),
        "{shown}"
    );
}

#[test]
fn a_named_address_that_is_not_the_one_paid_is_refused() {
    let pczt = build(&group(), honest(&group(), MemoBytes::empty()));
    let attacker = invoice_address(
        &stranger().address_at(5u32, Scope::External),
        NetworkType::Main,
    );
    let other_network = invoice_address(
        &stranger().address_at(0u32, Scope::External),
        NetworkType::Test,
    );
    for label in ["u1attackerlabel", "", &attacker, &other_network] {
        let refused = analyze(&named(pczt.clone(), label)).unwrap_err();
        assert!(
            refused.contains("not the one it pays"),
            "{label}: {refused}"
        );
    }
}

/// A dishonest builder sets the spend's randomizer to zero and `rk` to the
/// group key to match (it proves after the signing, so the proof follows).
/// Every such spend would show the same `rk` on chain.
#[test]
fn a_zero_randomizer_is_refused() {
    let pczt = build(&group(), honest(&group(), MemoBytes::empty()));
    let mut found = None;
    pczt::roles::low_level_signer::Signer::new(pczt.clone())
        .sign_ironwood_with(|_, bundle, _| -> Result<(), pczt_io::TxError> {
            for action in bundle.actions() {
                let spend = action.spend();
                if spend.value().map(|v| v.inner()) == Some(SPEND) {
                    let alpha = spend.alpha().unwrap();
                    found = Some((
                        ff::PrimeField::to_repr(&alpha),
                        <[u8; 32]>::from(spend.rk()),
                    ));
                }
            }
            Ok(())
        })
        .unwrap();
    let (alpha, rk) = found.expect("the group's spend");
    let ak: [u8; 32] = group().to_bytes()[..32].try_into().unwrap();
    let mut bytes = pczt_io::serialize(pczt).unwrap();
    for (old, new) in [(alpha, [0u8; 32]), (rk, ak)] {
        let at = bytes
            .windows(32)
            .position(|window| window == old)
            .expect("the field in the serialized PCZT");
        bytes[at..at + 32].copy_from_slice(&new);
    }
    let refused = analyze(&pczt_io::parse(&bytes).unwrap()).unwrap_err();
    assert!(refused.contains("randomizer is zero"), "{refused}");
}

fn action_count(pczt: &Pczt) -> usize {
    let mut count = 0;
    pczt::roles::low_level_signer::Signer::new(pczt.clone())
        .sign_ironwood_with(|_, bundle, _| -> Result<(), pczt_io::TxError> {
            count = bundle.actions().len();
            Ok(())
        })
        .unwrap();
    count
}

type Redaction = fn(&mut pczt::roles::redactor::orchard::ActionRedactor<'_>);

/// Removing any one field of any one action never makes the co-signer show
/// something other than what it signs: either it refuses, or it shows exactly
/// the honest description for exactly the honest sighash.
#[test]
fn no_single_redaction_changes_what_is_shown_and_signed() {
    let honest_pczt = build(&group(), honest(&group(), text_memo("invoice 42")));
    let honest_lines = analyze(&honest_pczt).unwrap().lines;
    let honest_sighash = pczt_io::sighash(&honest_pczt).unwrap();
    let redactions: [(&str, Redaction); 13] = [
        ("output value", |a| a.clear_output_value()),
        ("output recipient", |a| a.clear_output_recipient()),
        ("output rseed", |a| a.clear_output_rseed()),
        ("output ock", |a| a.clear_output_ock()),
        ("output user address", |a| a.clear_output_user_address()),
        ("spend value", |a| a.clear_spend_value()),
        ("spend recipient", |a| a.clear_spend_recipient()),
        ("spend rho", |a| a.clear_spend_rho()),
        ("spend rseed", |a| a.clear_spend_rseed()),
        ("spend fvk", |a| a.clear_spend_fvk()),
        ("spend alpha", |a| a.clear_spend_alpha()),
        ("spend witness", |a| a.clear_spend_witness()),
        ("rcv", |a| a.clear_rcv()),
    ];
    let count = action_count(&honest_pczt);
    for index in 0..count {
        for (name, redaction) in redactions {
            let redacted = Redactor::new(honest_pczt.clone())
                .redact_ironwood_with(|mut bundle| {
                    bundle.redact_action(index, |mut action| redaction(&mut action))
                })
                .finish();
            if let Ok(report) = analyze(&redacted) {
                assert_eq!(
                    report.lines, honest_lines,
                    "action {index}, {name} removed: accepted with a different description"
                );
                assert_eq!(
                    pczt_io::sighash(&redacted).ok(),
                    Some(honest_sighash),
                    "action {index}, {name} removed: accepted for a different sighash"
                );
            }
        }
    }
}
