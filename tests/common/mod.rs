//! A PCZT factory for the tests: v6 transactions built with zcash_primitives'
//! builder, spending an invented note through a made-up Merkle path, so no
//! chain is needed. The co-signer's checks never look at the chain: what they
//! verify is the PCZT against itself and against the group's keys.

#![allow(dead_code)]

use std::convert::Infallible;

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use orchard::note::{ExtractedNoteCommitment, RandomSeed, Rho};
use orchard::tree::{MerkleHashOrchard, MerklePath};
use orchard::value::NoteValue;
use orchard::{Address, Anchor, Note, NoteVersion};
use pczt::Pczt;
use pczt::roles::creator::Creator;
use pczt::roles::io_finalizer::IoFinalizer;
use rand10::rand_core::UnwrapErr;
use rand10::rngs::SysRng;
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::{fixed, zip317};
use zcash_protocol::consensus::MainNetwork;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

/// A height after NU7 activation on Mainnet, so the builder makes a v6
/// transaction with an Ironwood bundle.
pub const HEIGHT: u32 = 3_550_000;
/// ZIP 317 marginal fee per logical action, with a grace of two actions.
pub const MARGINAL_FEE: u64 = 5_000;
pub const SPEND: u64 = 1_000_000;
pub const PAYMENT: u64 = 400_000;

/// Someone outside the group: the payee, or the attacker.
pub fn stranger() -> FullViewingKey {
    FullViewingKey::from(&SpendingKey::from_bytes([9; 32]).unwrap())
}

#[derive(Clone, Copy)]
pub enum Ovk {
    External,
    Internal,
    Without,
}

pub struct Output {
    pub to: Address,
    pub value: u64,
    pub memo: MemoBytes,
    pub ovk: Ovk,
}

pub struct Tx {
    /// Whose note is spent (the group's, unless testing a foreign note).
    pub owner: FullViewingKey,
    pub spend: u64,
    pub outputs: Vec<Output>,
    /// A payment in a separate Orchard bundle.
    pub orchard_payment: Option<(Address, u64)>,
    /// Run the IO Finalizer (signs and clears the dummy spends).
    pub finalize: bool,
    /// A fee set by hand instead of ZIP 317's: the outputs must leave exactly
    /// this much.
    pub fee: Option<u64>,
    /// An expiry height set by hand instead of the builder's default.
    pub expiry: Option<u32>,
}

pub fn fee(logical_actions: u64) -> u64 {
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

/// Builds the PCZT; `group` is the group whose outgoing viewing keys encrypt
/// the outputs.
pub fn build(group: &FullViewingKey, tx: Tx) -> Pczt {
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
    if let Some(expiry) = tx.expiry {
        builder = builder.with_expiry_height(expiry.into());
    }
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
    let result = match tx.fee {
        None => builder
            .build_for_pczt(UnwrapErr(SysRng), &zip317::FeeRule::standard())
            .unwrap(),
        Some(fee) => builder
            .build_for_pczt(
                UnwrapErr(SysRng),
                &fixed::FeeRule::non_standard(Zatoshis::from_u64(fee).unwrap()),
            )
            .unwrap(),
    };
    let pczt = Creator::build_from_parts(result.pczt_parts).unwrap();
    if tx.finalize {
        IoFinalizer::new(pczt)
            .finalize_io(UnwrapErr(SysRng))
            .unwrap()
    } else {
        pczt
    }
}

pub fn text_memo(text: &str) -> MemoBytes {
    MemoBytes::from_bytes(text.as_bytes()).unwrap()
}

/// The ordinary case: a payment to the stranger with a memo, change back to
/// the group.
pub fn honest(group: &FullViewingKey, memo: MemoBytes) -> Tx {
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
        fee: None,
        expiry: None,
    }
}
