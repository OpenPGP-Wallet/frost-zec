//! Tamper suite: PCZTs a dishonest coordinator could send, which the co-signer
//! must refuse, or show exactly as they will be signed.
//!
//! The PCZTs are built with zcash_primitives' builder, spending an invented
//! note through a made-up Merkle path, so no chain is needed. The co-signer's
//! checks never look at the chain: what they verify is the PCZT against itself
//! and against the group's keys.

use std::convert::Infallible;

use frost_zec::{check, keys, pczt_io};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::{Address, Anchor, Note, NoteVersion};
use pczt::Pczt;
use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use pczt::roles::redactor::Redactor;
use pczt::roles::updater::Updater;
use rand10::rand_core::UnwrapErr;
use rand10::rngs::SysRng;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317;
use zcash_protocol::consensus::{MainNetwork, NetworkType};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

/// A height after NU7 activation on Mainnet, so the builder makes a v6
/// transaction with an Ironwood bundle.
const HEIGHT: u32 = 3_550_000;
/// ZIP 317 marginal fee per logical action, with a grace of two actions.
const MARGINAL_FEE: u64 = 5_000;

fn group() -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap())
}

fn stranger() -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap())
}

#[derive(Clone, Copy)]
enum Ovk {
    External,
    Internal,
    Without,
}

struct Output {
    to: Address,
    value: u64,
    memo: MemoBytes,
    ovk: Ovk,
}

struct Tx {
    /// Whose note is spent (the group's, unless testing a foreign note).
    owner: FullViewingKey,
    spend: u64,
    outputs: Vec<Output>,
    /// A payment in a separate Orchard bundle.
    orchard_payment: Option<(Address, u64)>,
    /// Run the IO Finalizer (signs and clears the dummy spends).
    finalize: bool,
}

fn fee(logical_actions: u64) -> u64 {
    MARGINAL_FEE * logical_actions.max(2)
}

fn note_for(owner: &FullViewingKey, value: u64) -> (Note, MerklePath, Anchor) {
    let rho = (0..)
        .find_map(|_| Rho::from_bytes(&rand::random()).into_option())
        .unwrap();
    let rseed = (0..)
        .find_map(|_| RandomSeed::from_bytes(rand::random(), &rho).into_option())
        .unwrap();
    let note = Note::from_parts(
        owner.address_at(0u32, Scope::External),
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap();
    let path = MerklePath::from_parts(11, [MerkleHashOrchard::from_bytes(&[0; 32]).unwrap(); 32]);
    let anchor = path.root(ExtractedNoteCommitment::from(note.commitment()));
    (note, path, anchor)
}

fn build(tx: Tx) -> Pczt {
    let group = group();
    let (note, path, anchor) = note_for(&tx.owner, tx.spend);
    let mut builder = Builder::new(
        MainNetwork,
        HEIGHT.into(),
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: tx.orchard_payment.as_ref().map(|_| Anchor::empty_tree()),
            ironwood_anchor: Some(anchor),
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );
    builder
        .add_ironwood_spend::<Infallible>(tx.owner.clone(), note, path)
        .unwrap();
    for output in tx.outputs {
        let ovk = match output.ovk {
            Ovk::External => Some(group.to_ovk(Scope::External)),
            Ovk::Internal => Some(group.to_ovk(Scope::Internal)),
            Ovk::Without => None,
        };
        builder
            .add_ironwood_output::<Infallible>(
                ovk,
                output.to,
                Zatoshis::from_u64(output.value).unwrap(),
                output.memo,
            )
            .unwrap();
    }
    if let Some((to, value)) = tx.orchard_payment {
        // Orchard bundles now forbid sending to another address: each output
        // must go to the address of the note its action spends. An attacker
        // satisfies that with a zero-value spend from its own key, paired with
        // an output to itself, and funds the output from the transaction's
        // balance, which here comes from the group's Ironwood notes.
        builder
            .add_orchard_change_output::<Infallible>(
                stranger(),
                None,
                to,
                Zatoshis::from_u64(value).unwrap(),
                MemoBytes::empty(),
            )
            .unwrap();
    }
    let result = builder
        .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
        .unwrap();
    let pczt = Creator::build_from_parts(result.pczt_parts).unwrap();
    if tx.finalize {
        IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .unwrap()
    } else {
        pczt
    }
}

fn text_memo(text: &str) -> MemoBytes {
    MemoBytes::from_bytes(text.as_bytes()).unwrap()
}

const SPEND: u64 = 1_000_000;
const PAYMENT: u64 = 400_000;

/// The ordinary case: a payment with a memo, change back to the group.
fn honest(memo: MemoBytes) -> Tx {
    let group = group();
    Tx {
        owner: group.clone(),
        spend: SPEND,
        outputs: vec![
            Output {
                to: stranger().address_at(0u32, Scope::External),
                value: PAYMENT,
                memo,
                ovk: Ovk::External,
            },
            Output {
                to: group.address_at(0u32, Scope::Internal),
                value: SPEND - PAYMENT - fee(2),
                memo: MemoBytes::empty(),
                ovk: Ovk::Internal,
            },
        ],
        orchard_payment: None,
        finalize: true,
    }
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
    let pczt = build(honest(text_memo("invoice 42")));
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
    let mut tx = honest(text_memo("invoice 42"));
    tx.outputs[0].ovk = Ovk::Without;
    let refused = analyze(&build(tx)).unwrap_err();
    assert!(refused.contains("outgoing viewing key"), "{refused}");
}

#[test]
fn change_the_group_cannot_read_back_is_refused() {
    let mut tx = honest(MemoBytes::empty());
    tx.outputs[1].ovk = Ovk::Without;
    let refused = analyze(&build(tx)).unwrap_err();
    assert!(refused.contains("outgoing viewing key"), "{refused}");
}

#[test]
fn a_memo_cannot_rewrite_the_screen() {
    let pczt = build(honest(text_memo("ok\u{202E}evil\nPAY 0.00000001 ZEC")));
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
    let mut tx = honest(MemoBytes::empty());
    let attacker = stranger().address_at(5u32, Scope::External);
    // The Orchard part adds two logical actions (its spend and output are padded
    // to two actions): the group's change pays for them.
    tx.outputs[1].value = SPEND - PAYMENT - 3_000 - fee(4);
    tx.orchard_payment = Some((attacker, 3_000));
    let refused = analyze(&build(tx)).unwrap_err();
    assert!(refused.contains("Orchard"), "{refused}");
}

#[test]
fn a_note_of_another_wallet_is_refused() {
    let mut tx = honest(MemoBytes::empty());
    tx.owner = stranger();
    let refused = analyze(&build(tx)).unwrap_err();
    assert!(refused.contains("spent note"), "{refused}");
}

#[test]
fn a_pczt_that_skipped_the_io_finalizer_is_refused() {
    let mut tx = honest(MemoBytes::empty());
    tx.finalize = false;
    assert!(analyze(&build(tx)).is_err());
}

#[test]
fn a_claimed_address_label_is_never_shown() {
    let pczt = build(honest(MemoBytes::empty()));
    let count = action_count(&pczt);
    let mut labelled = pczt;
    for index in 0..count {
        labelled = Updater::new(labelled)
            .update_ironwood_with(|mut bundle| {
                bundle.update_action_with(index, |mut action| {
                    action.set_output_user_address("u1attackerlabel".into());
                    Ok(())
                })
            })
            .unwrap()
            .finish();
    }
    let shown = analyze(&labelled).unwrap().lines.join("\n");
    assert!(!shown.contains("attackerlabel"), "{shown}");
    assert!(shown.contains(&stranger_address()), "{shown}");
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
    let honest_pczt = build(honest(text_memo("invoice 42")));
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
