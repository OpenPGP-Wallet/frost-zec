//! The report's structured facts: what an automated signer (a spending policy,
//! say) reads instead of parsing the lines shown to a person.

mod common;

use common::*;
use frost_zec::{check, keys, pczt_io};
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use pczt::Pczt;
use pczt::roles::updater::Updater;
use zcash_address::unified::{self, Encoding};
use zcash_protocol::consensus::NetworkType;
use zcash_protocol::memo::MemoBytes;

fn group() -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap())
}

fn analyze(pczt: &Pczt) -> check::Report {
    check::analyze(pczt, &group(), NetworkType::Main).unwrap()
}

fn stranger_address() -> String {
    keys::encode_address(
        &stranger().address_at(0u32, Scope::External),
        NetworkType::Main,
    )
    .unwrap()
}

/// Writes `address` as the `user_address` of every output.
fn named(pczt: Pczt, address: &str) -> Pczt {
    let mut count = 0;
    pczt::roles::low_level_signer::Signer::new(pczt.clone())
        .sign_ironwood_with(|_, bundle, _| -> Result<(), pczt_io::TxError> {
            count = bundle.actions().len();
            Ok(())
        })
        .unwrap();
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

#[test]
fn an_honest_payment_is_reported_as_facts() {
    let pczt = build(&group(), honest(&group(), text_memo("invoice 42")));
    let report = analyze(&pczt);
    assert_eq!(
        report.payments,
        vec![check::Payment {
            address: stranger_address(),
            zat: PAYMENT,
        }]
    );
    assert_eq!(report.spent_zat, SPEND);
    assert_eq!(report.change_zat, SPEND - PAYMENT - fee(2));
    assert_eq!(report.fee_zat, fee(2));
    assert_eq!(report.expiry_height, *pczt.global().expiry_height());
}

/// The lines show the address the PCZT names once it holds the paid receiver,
/// but its other receivers are not checked against anything. A signer that
/// compares addresses must get the receiver that is paid.
#[test]
fn the_paid_receiver_is_reported_not_the_named_address() {
    let paid = stranger().address_at(0u32, Scope::External);
    let items = vec![
        unified::Uitem::Data(unified::Receiver::Orchard(paid.to_raw_address_bytes())),
        unified::Uitem::Data(unified::Receiver::Sapling([9; 43])),
    ];
    let full = unified::Address::try_from_items(unified::Revision::R0, items)
        .unwrap()
        .encode(&NetworkType::Main);
    let pczt = named(build(&group(), honest(&group(), MemoBytes::empty())), &full);

    let report = analyze(&pczt);
    assert!(
        report.lines.iter().any(|line| line.contains(&full)),
        "{:?}",
        report.lines
    );
    assert_eq!(report.payments.len(), 1);
    assert_eq!(report.payments[0].address, stranger_address());
}

/// Change and zero-value notes to the group are not payments.
#[test]
fn only_value_leaving_the_group_is_a_payment() {
    let mut tx = honest(&group(), MemoBytes::empty());
    tx.outputs.truncate(1);
    tx.outputs[0].to = group().address_at(0u32, Scope::Internal);
    tx.outputs[0].value = SPEND - fee(2);
    tx.outputs[0].ovk = Ovk::Internal;
    let report = analyze(&build(&group(), tx));
    assert!(report.payments.is_empty(), "{:?}", report.payments);
    assert_eq!(report.change_zat, SPEND - fee(2));
}
