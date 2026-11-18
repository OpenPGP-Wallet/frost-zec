//! The co-signer's optional standing policy: rules checked against the
//! report's structured facts before the user is asked. A payment outside them
//! is refused without a prompt; inside them, the prompt is unchanged.

mod common;

use common::*;
use frost_zec::check::{self, Report};
use frost_zec::policy::Policy;
use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use zcash_address::unified::{self, Encoding};
use zcash_protocol::consensus::NetworkType;

fn group() -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([7; 32]).unwrap())
}

/// The honest payment: 0.004 ZEC to the stranger's address 0, fee 0.0001.
fn report() -> Report {
    let pczt = build(&group(), honest(&group(), text_memo("rent")));
    check::analyze(&pczt, &group(), NetworkType::Main).unwrap()
}

fn ua(items: Vec<unified::Receiver>, network: NetworkType) -> String {
    let items = items.into_iter().map(unified::Uitem::Data).collect();
    unified::Address::try_from_items(unified::Revision::R0, items)
        .unwrap()
        .encode(&network)
}

fn orchard(index: u32) -> unified::Receiver {
    unified::Receiver::Orchard(
        stranger()
            .address_at(index, Scope::External)
            .to_raw_address_bytes(),
    )
}

/// The stranger's full address: its Ironwood receiver and a Sapling one, as a
/// wallet gives it out.
fn stranger_full() -> String {
    ua(
        vec![orchard(0), unified::Receiver::Sapling([9; 43])],
        NetworkType::Main,
    )
}

fn policy(json: serde_json::Value) -> Policy {
    Policy::from_json(&json.to_string()).unwrap()
}

fn refusal(policy: &Policy) -> String {
    policy
        .check(&report(), NetworkType::Main)
        .expect_err("the payment should be refused")
}

#[test]
fn a_payment_within_every_rule_passes() {
    let policy = policy(serde_json::json!({
        "network": "main",
        "per_payment_cap_zat": PAYMENT,
        "max_fee_zat": fee(2),
        "allowed_recipients": [{ "label": "landlord", "address": stranger_full() }],
    }));
    assert_eq!(policy.check(&report(), NetworkType::Main), Ok(()));
}

#[test]
fn a_payment_above_the_cap_is_refused() {
    let policy =
        policy(serde_json::json!({ "network": "main", "per_payment_cap_zat": PAYMENT - 1 }));
    assert!(refusal(&policy).contains("cap"), "{}", refusal(&policy));
}

#[test]
fn a_fee_above_the_maximum_is_refused() {
    let policy = policy(serde_json::json!({ "network": "main", "max_fee_zat": fee(2) - 1 }));
    assert!(refusal(&policy).contains("fee"), "{}", refusal(&policy));
}

#[test]
fn a_recipient_off_the_list_is_refused() {
    let other = ua(vec![orchard(5)], NetworkType::Main);
    let policy = policy(serde_json::json!({
        "network": "main",
        "allowed_recipients": [{ "address": other }],
    }));
    assert!(
        refusal(&policy).contains("allow-list"),
        "{}",
        refusal(&policy)
    );
}

/// An entry passes a payment only through a receiver of the same kind: a
/// Sapling receiver whose bytes equal the paid Orchard receiver is someone
/// else, even in an entry that also holds an Orchard receiver.
#[test]
fn a_receiver_of_another_kind_with_the_same_bytes_does_not_match() {
    let paid = stranger()
        .address_at(0u32, Scope::External)
        .to_raw_address_bytes();
    let look_alike = ua(
        vec![orchard(5), unified::Receiver::Sapling(paid)],
        NetworkType::Main,
    );
    let policy = policy(serde_json::json!({
        "network": "main",
        "allowed_recipients": [{ "address": look_alike }],
    }));
    assert!(
        refusal(&policy).contains("allow-list"),
        "{}",
        refusal(&policy)
    );
}

/// Payments go to Orchard receivers only (Ironwood notes are sent to them),
/// so an entry without one could never match: the owner learns it at load.
#[test]
fn an_allow_list_entry_without_an_orchard_receiver_is_refused_when_loading() {
    let sapling_only = ua(vec![unified::Receiver::Sapling([9; 43])], NetworkType::Main);
    let error = Policy::from_json(
        &serde_json::json!({ "network": "main", "allowed_recipients": [{ "address": sapling_only }] })
            .to_string(),
    )
    .unwrap_err();
    assert!(error.contains("Orchard"), "{error}");
}

/// The honest payment split in two outputs to the same receiver, each at the
/// cap: one signature would move twice the cap.
fn split_report() -> Report {
    let mut tx = honest(&group(), text_memo("rent"));
    tx.outputs.insert(
        1,
        Output {
            to: stranger().address_at(0u32, Scope::External),
            value: PAYMENT,
            memo: text_memo("rent, part 2"),
            ovk: Ovk::External,
        },
    );
    tx.outputs[2].value = SPEND - 2 * PAYMENT - fee(3);
    let pczt = build(&group(), tx);
    check::analyze(&pczt, &group(), NetworkType::Main).unwrap()
}

/// The cap holds for the whole transaction, since one signature approves all
/// of it: outputs each under the cap cannot add up past it.
#[test]
fn the_cap_holds_for_everything_one_transaction_pays() {
    let report = split_report();
    assert_eq!(report.payments.len(), 2, "two payments leave the group");
    let at_each = policy(serde_json::json!({ "network": "main", "per_payment_cap_zat": PAYMENT }));
    let reason = at_each
        .check(&report, NetworkType::Main)
        .expect_err("twice the cap in one transaction should be refused");
    assert!(reason.contains("cap"), "{reason}");
    let at_total =
        policy(serde_json::json!({ "network": "main", "per_payment_cap_zat": 2 * PAYMENT }));
    assert_eq!(at_total.check(&report, NetworkType::Main), Ok(()));
}

/// The co-signer knows its group's network when it loads the policy, so a
/// policy for another network stops there like any other bad file.
#[test]
fn a_policy_for_another_network_is_refused_when_loading_for_a_group() {
    let dir = std::env::temp_dir().join(format!("frost-zec-policy-net-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("policy.json");
    std::fs::write(&file, r#"{"network": "test", "per_payment_cap_zat": 1}"#).unwrap();
    let error = Policy::load_for(&file, NetworkType::Main)
        .unwrap_err()
        .to_string();
    assert!(error.contains("network"), "{error}");
    assert!(Policy::load_for(&file, NetworkType::Test).is_ok());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn without_an_allow_list_any_recipient_within_the_cap_passes() {
    let policy = policy(serde_json::json!({ "network": "main", "per_payment_cap_zat": PAYMENT }));
    assert_eq!(policy.check(&report(), NetworkType::Main), Ok(()));
}

#[test]
fn a_policy_for_another_network_is_refused() {
    let policy = policy(serde_json::json!({ "network": "test", "per_payment_cap_zat": PAYMENT }));
    assert!(refusal(&policy).contains("network"), "{}", refusal(&policy));
}

/// A rule this co-signer does not enforce must not be ignored in silence: the
/// owner would believe it holds.
#[test]
fn a_rule_this_signer_does_not_enforce_is_refused_when_loading() {
    let error = Policy::from_json(
        &serde_json::json!({
            "network": "main",
            "per_payment_cap_zat": PAYMENT,
            "daily_budget_zat": PAYMENT,
        })
        .to_string(),
    )
    .unwrap_err();
    assert!(error.contains("daily_budget_zat"), "{error}");
}

#[test]
fn a_policy_without_rules_is_refused_when_loading() {
    let error =
        Policy::from_json(&serde_json::json!({ "network": "main" }).to_string()).unwrap_err();
    assert!(error.contains("no rule"), "{error}");
}

#[test]
fn an_allow_list_entry_for_another_network_is_refused_when_loading() {
    let testnet = ua(vec![orchard(0)], NetworkType::Test);
    let error = Policy::from_json(
        &serde_json::json!({ "network": "main", "allowed_recipients": [{ "address": testnet }] })
            .to_string(),
    )
    .unwrap_err();
    assert!(error.contains("network"), "{error}");
}

/// A refusal states amounts in the network's unit, as the report's lines do:
/// on testnet a cap of TAZ, never ZEC, so the reason and the lines agree.
#[test]
fn a_testnet_refusal_states_amounts_in_taz() {
    let pczt = build(&group(), honest(&group(), text_memo("rent")));
    let report = check::analyze(&pczt, &group(), NetworkType::Test).unwrap();
    for rule in [
        serde_json::json!({ "network": "test", "per_payment_cap_zat": PAYMENT - 1 }),
        serde_json::json!({ "network": "test", "max_fee_zat": fee(2) - 1 }),
    ] {
        let reason = policy(rule)
            .check(&report, NetworkType::Test)
            .expect_err("the payment should be refused");
        assert!(
            reason.contains("TAZ") && !reason.contains("ZEC"),
            "{reason}"
        );
    }
}
