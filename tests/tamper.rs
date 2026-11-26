//! Tamper suite: PCZTs a dishonest coordinator could send, which the co-signer
//! must refuse, or show exactly as they will be signed. Most of them are also
//! exported as shared tamper cases (vectors/tamper/, tests/tamper_vectors.rs)
//! for other signers; these tests keep what is specific to this co-signer,
//! such as the exact lines it shows.
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

/// The coordinator keeps the payment and lowers the change: the fee shown is
/// the true one, but more than ZIP 317 asks for the two actions it needs.
#[test]
fn a_fee_above_zip_317_is_refused() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.outputs[1].value -= 50_000;
    tx.fee = Some(fee(2) + 50_000);
    let refused = analyze(&build(&group(), tx)).unwrap_err();
    assert!(refused.contains("more than ZIP 317"), "{refused}");
}

/// A height after ZIP 2009's lower fee starts on Mainnet (3,590,000).
const AFTER_ZIP_2009: u32 = 3_600_000;
/// The time from which the co-signer refuses the earlier fee: 1 February 2027,
/// 00:00 UTC.
const EARLIER_FEE_REFUSED_FROM: u64 = 1_801_440_000;

fn analyze_at(pczt: &Pczt, clock: u64) -> Result<check::Report, String> {
    check::analyze_at(pczt, &group(), NetworkType::Main, clock).map_err(|e| e.to_string())
}

/// A payment that can be mined after ZIP 2009's fee starts, paying `fee`.
fn after_zip_2009(fee: u64) -> Pczt {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.height = Some(AFTER_ZIP_2009);
    tx.outputs[1].value = SPEND - PAYMENT - fee;
    tx.fee = Some(fee);
    build(&group(), tx)
}

fn fee_warnings(report: &check::Report) -> Vec<&String> {
    report
        .warnings
        .iter()
        .filter(|warning| warning.contains("ZIP 2009"))
        .collect()
}

/// ZIP 2009 lowers the marginal fee to 1,000 zatoshis. Its fee passes without
/// a word, before the earlier fee is refused and after.
#[test]
fn a_fee_at_the_zip_2009_rate_is_accepted() {
    let pczt = after_zip_2009(2_000);
    for clock in [EARLIER_FEE_REFUSED_FROM - 1, EARLIER_FEE_REFUSED_FROM] {
        let report = analyze_at(&pczt, clock).unwrap();
        let shown = report.lines.join("\n");
        assert!(shown.contains("fee 0.00002000 ZEC"), "{shown}");
        assert!(fee_warnings(&report).is_empty(), "{:?}", report.warnings);
    }
}

/// A coordinator that was not updated still pays 5,000 zatoshis per action.
/// The co-signer says so and names the day it stops accepting it. From that
/// day it refuses, and one zatoshi above ZIP 2009's fee is too much.
#[test]
fn the_earlier_fee_is_warned_about_then_refused() {
    let earlier = after_zip_2009(fee(2));
    let report = analyze_at(&earlier, EARLIER_FEE_REFUSED_FROM - 1).unwrap();
    let warned = fee_warnings(&report);
    assert_eq!(warned.len(), 1, "{:?}", report.warnings);
    assert!(
        warned[0].contains("0.00002000 ZEC") && warned[0].contains("1 February 2027"),
        "{}",
        warned[0]
    );
    for pczt in [earlier, after_zip_2009(2_001)] {
        let refused = analyze_at(&pczt, EARLIER_FEE_REFUSED_FROM).unwrap_err();
        assert!(
            refused.contains("more than ZIP 317") && refused.contains("since ZIP 2009"),
            "{refused}"
        );
    }
    // Above the earlier fee, the refusal does not wait for that day.
    let above = after_zip_2009(fee(2) + 1);
    let refused = analyze_at(&above, EARLIER_FEE_REFUSED_FROM - 1).unwrap_err();
    assert!(refused.contains("more than ZIP 317"), "{refused}");
}

/// A transaction that expires before ZIP 2009's fee starts can no longer be
/// mined: the fee of its time stays its bound, whatever the clock says.
#[test]
fn a_transaction_from_before_zip_2009_keeps_the_fee_of_its_time() {
    let pczt = build(&group(), honest(&group(), MemoBytes::empty()));
    assert!(*pczt.global().expiry_height() < 3_590_000);
    let report = analyze_at(&pczt, EARLIER_FEE_REFUSED_FROM).unwrap();
    assert!(fee_warnings(&report).is_empty(), "{:?}", report.warnings);
}

/// Zero-value outputs on top of a payment and its change, the fee they "cost"
/// taken from the change: the fee is ZIP 317's for the bigger transaction, so
/// only the action count shows the padding.
#[test]
fn zero_value_padding_is_refused() {
    for extra in [1, 2] {
        let mut tx = honest(&group(), text_memo("invoice 42"));
        tx.outputs[1].value = SPEND - PAYMENT - fee(2 + extra);
        for _ in 0..extra {
            tx.outputs.push(zero_value_output(
                stranger().address_at(3u32, Scope::External),
                Ovk::Without,
            ));
        }
        let refused = analyze(&build(&group(), tx)).unwrap_err();
        assert!(
            refused.contains("extra ones move no value"),
            "{extra}: {refused}"
        );
    }
}

/// Two payments whose sum and fee use up the spent note exactly.
/// zcash_client_backend still adds a change output of value zero, so that the
/// number of outputs does not reveal that the note closed exactly, and with
/// `OvkPolicy::Sender` it encrypts that change with no outgoing key (#12).
fn two_payments_closing_exactly(change_ovk: Ovk) -> Tx {
    let mut tx = honest(&group(), text_memo("invoice 42"));
    tx.outputs[1] = Output {
        to: stranger().address_at(1u32, Scope::External),
        value: SPEND - PAYMENT - fee(3),
        memo: MemoBytes::empty(),
        ovk: Ovk::External,
    };
    tx.outputs.push(zero_change(change_ovk));
    tx
}

fn zero_change(ovk: Ovk) -> Output {
    Output {
        to: group().address_at(0u32, Scope::Internal),
        value: 0,
        memo: MemoBytes::empty(),
        ovk,
    }
}

/// The group reads such a change with its incoming viewing key, so it counts
/// as an action the payments need, whichever outgoing key encrypted it.
#[test]
fn a_zero_value_change_when_the_payments_close_the_note_is_accepted() {
    for (ovk, line) in [
        (Ovk::Without, "change 0 ZEC back to this group"),
        (Ovk::Internal, "send 0 ZEC to this group's own address"),
    ] {
        let report = analyze(&build(&group(), two_payments_closing_exactly(ovk))).unwrap();
        let shown = report.lines.join("\n");
        assert_eq!(report.payments.len(), 2, "{shown}");
        assert!(shown.contains(line), "{shown}");
        assert!(shown.contains("fee 0.00015000 ZEC"), "{shown}");
    }
}

/// zcash_client_backend adds a zero-value change only in place of a change
/// with value, never next to one: there, it is padding.
#[test]
fn a_zero_value_change_next_to_a_change_with_value_is_refused() {
    let mut tx = honest(&group(), text_memo("invoice 42"));
    tx.outputs[1].value = SPEND - PAYMENT - fee(3);
    tx.outputs.push(zero_change(Ovk::Without));
    let refused = analyze(&build(&group(), tx)).unwrap_err();
    assert!(refused.contains("extra ones move no value"), "{refused}");
}

/// One zero-value change is what the wallet adds; a second one is padding.
#[test]
fn a_second_zero_value_change_is_refused() {
    let mut tx = two_payments_closing_exactly(Ovk::Without);
    tx.outputs[1].value = SPEND - PAYMENT - fee(4);
    tx.outputs.push(zero_change(Ovk::Without));
    let refused = analyze(&build(&group(), tx)).unwrap_err();
    assert!(refused.contains("extra ones move no value"), "{refused}");
}

/// The zero-value change raises the fee bound by one action, and no more.
#[test]
fn a_fee_above_zip_317_with_a_zero_value_change_is_refused() {
    let mut tx = two_payments_closing_exactly(Ovk::Without);
    tx.fee = Some(fee(4));
    tx.outputs[1].value = SPEND - PAYMENT - fee(4);
    let refused = analyze(&build(&group(), tx)).unwrap_err();
    assert!(
        refused.contains("more than ZIP 317 asks for 3 actions"),
        "{refused}"
    );
}

/// A payment with no change leaves one slot to the builder's padding. A
/// zero-value note to a stranger there, readable with the group's outgoing
/// key, would land on chain with a memo the user never saw.
#[test]
fn a_zero_value_note_to_a_stranger_is_refused() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.outputs[0].value = SPEND - fee(2);
    tx.outputs[1] = zero_value_output(stranger().address_at(3u32, Scope::External), Ovk::External);
    let refused = analyze(&build(&group(), tx)).unwrap_err();
    assert!(
        refused.contains("zero-value note to another address"),
        "{refused}"
    );
}

/// The builder's own padding cannot be read by anyone and is not shown.
#[test]
fn the_builders_padding_is_not_shown() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.outputs[0].value = SPEND - fee(2);
    tx.outputs.truncate(1);
    let shown = analyze(&build(&group(), tx)).unwrap().lines;
    // The spend, the payment and its memo line, the fee; the builder shuffles
    // the actions, so the payment is not always the second line.
    assert_eq!(shown.len(), 4, "{shown:?}");
    assert_eq!(
        shown
            .iter()
            .filter(|line| line.starts_with("PAY 0.00990000 ZEC"))
            .count(),
        1,
        "{shown:?}"
    );
}

/// A zero-value note to the group itself moves nothing, but it is signed, so
/// it is shown with its memo.
#[test]
fn a_zero_value_note_to_the_group_is_shown() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.outputs[0].value = SPEND - fee(2);
    tx.outputs[1] = zero_value_output(group().address_at(0u32, Scope::Internal), Ovk::Internal);
    let shown = analyze(&build(&group(), tx)).unwrap().lines.join("\n");
    assert!(
        shown.contains("send 0 ZEC to this group's own address\n    memo: \"not shown\""),
        "{shown}"
    );
}

/// A signature kept by the coordinator stays usable until the expiry height:
/// one set far ahead is refused, not just shown.
#[test]
fn an_expiry_far_ahead_is_refused() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.expiry = Some(499_999_999);
    let refused = analyze(&build(&group(), tx)).unwrap_err();
    assert!(refused.contains("far beyond"), "{refused}");
}

/// The user compares the co-signer's screen with the address they were given.
/// That address usually has several receivers, so the paid receiver alone,
/// encoded on its own, is another string: the co-signer shows the given one,
/// once it has checked that it holds the receiver paid.
#[test]
fn the_address_the_user_was_given_is_shown_once_checked() {
    let pczt = build(&group(), honest(&group(), MemoBytes::empty()));
    let paid = stranger().address_at(0u32, Scope::External);
    for revision in [
        zcash_address::unified::Revision::R0,
        zcash_address::unified::Revision::R2,
    ] {
        let invoice = invoice_address_in(revision, &paid, NetworkType::Main);
        assert_ne!(invoice, stranger_address());
        let shown = analyze(&named(pczt.clone(), &invoice))
            .unwrap()
            .lines
            .join("\n");
        assert!(
            shown.contains(&format!("PAY 0.00400000 ZEC to {invoice}")),
            "{shown}"
        );
    }
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
    let pczt = zero_randomizer(
        &build(&group(), honest(&group(), MemoBytes::empty())),
        &group(),
        SPEND,
    );
    let refused = analyze(&pczt).unwrap_err();
    assert!(refused.contains("randomizer is zero"), "{refused}");
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
