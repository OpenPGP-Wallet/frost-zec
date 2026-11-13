//! A PCZT factory for the tests: v6 transactions built with zcash_primitives'
//! builder, spending an invented note through a made-up Merkle path, so no
//! chain is needed. The co-signer's checks never look at the chain: what they
//! verify is the PCZT against itself and against the group's keys.

#![allow(dead_code)]

use std::convert::Infallible;

use frost_zec::pczt_io;

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
    /// The value of a second note of the owner, spent in the same bundle.
    pub second_spend: Option<u64>,
    /// The height the transaction targets, instead of [`HEIGHT`].
    pub height: Option<u32>,
}

pub fn fee(logical_actions: u64) -> u64 {
    MARGINAL_FEE * logical_actions.max(2)
}

fn new_note(owner: &FullViewingKey, value: u64) -> Note {
    let rho = (0..)
        .find_map(|_| Rho::from_bytes(&rand::random()).into_option())
        .unwrap();
    let rseed = (0..)
        .find_map(|_| RandomSeed::from_bytes(rand::random(), &rho).into_option())
        .unwrap();
    Note::from_parts(
        owner.address_at(0u32, Scope::External),
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap()
}

fn cmx(note: &Note) -> ExtractedNoteCommitment {
    ExtractedNoteCommitment::from(note.commitment())
}

fn note_for(owner: &FullViewingKey, value: u64) -> (Note, MerklePath, Anchor) {
    let note = new_note(owner, value);
    let path = MerklePath::from_parts(11, [MerkleHashOrchard::from_bytes(&[0; 32]).unwrap(); 32]);
    let anchor = path.root(cmx(&note));
    (note, path, anchor)
}

/// Two notes side by side at positions 0 and 1 of a made-up tree, so both
/// paths lead to the same anchor.
fn two_notes_for(
    owner: &FullViewingKey,
    first: u64,
    second: u64,
) -> ([(Note, MerklePath); 2], Anchor) {
    let zero = MerkleHashOrchard::from_bytes(&[0; 32]).unwrap();
    let (a, b) = (new_note(owner, first), new_note(owner, second));
    let mut siblings_a = [zero; 32];
    siblings_a[0] = MerkleHashOrchard::from_cmx(&cmx(&b));
    let mut siblings_b = [zero; 32];
    siblings_b[0] = MerkleHashOrchard::from_cmx(&cmx(&a));
    let (path_a, path_b) = (
        MerklePath::from_parts(0, siblings_a),
        MerklePath::from_parts(1, siblings_b),
    );
    let anchor = path_a.root(cmx(&a));
    assert_eq!(anchor, path_b.root(cmx(&b)));
    ([(a, path_a), (b, path_b)], anchor)
}

/// Builds the PCZT; `group` is the group whose outgoing viewing keys encrypt
/// the outputs.
pub fn build(group: &FullViewingKey, tx: Tx) -> Pczt {
    let (spends, anchor) = match tx.second_spend {
        None => {
            let (note, path, anchor) = note_for(&tx.owner, tx.spend);
            (vec![(note, path)], anchor)
        }
        Some(second) => {
            let (spends, anchor) = two_notes_for(&tx.owner, tx.spend, second);
            (spends.to_vec(), anchor)
        }
    };
    let mut builder = Builder::new(
        MainNetwork,
        tx.height.unwrap_or(HEIGHT).into(),
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
    for (note, path) in spends {
        builder
            .add_ironwood_spend::<Infallible>(tx.owner.clone(), note, path)
            .unwrap();
    }
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
        second_spend: None,
        height: None,
    }
}

/// The ordinary case paid from two of the group's notes: two spends to sign.
pub fn two_spends(group: &FullViewingKey, memo: MemoBytes) -> Tx {
    let mut tx = honest(group, memo);
    tx.second_spend = Some(SPEND);
    tx.outputs[1].value = 2 * SPEND - PAYMENT - fee(2);
    tx
}

/// An output that moves no value, with a memo the user would not see unless
/// the co-signer shows it.
pub fn zero_value_output(to: Address, ovk: Ovk) -> Output {
    Output {
        to,
        value: 0,
        memo: text_memo("not shown"),
        ovk,
    }
}

// Changes made to a built PCZT, as a dishonest coordinator would.

/// The number of Ironwood actions.
pub fn action_count(pczt: &Pczt) -> usize {
    let mut count = 0;
    pczt::roles::low_level_signer::Signer::new(pczt.clone())
        .sign_ironwood_with(|_, bundle, _| -> Result<(), pczt_io::TxError> {
            count = bundle.actions().len();
            Ok(())
        })
        .unwrap();
    count
}

/// Flips one byte inside the note ciphertext of the output worth `value`. The
/// note commitment still matches the claimed note, so only decrypting the
/// ciphertext can notice: the recipient would never find these funds.
pub fn garble_ciphertext(pczt: &Pczt, value: u64) -> Pczt {
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

/// Sets the randomizer of the spend worth `value` to zero and its `rk` to the
/// group key `ak` to match, as a dishonest builder could (it proves after the
/// signing, so the proof follows). Every such spend would show the same `rk`
/// on chain.
pub fn zero_randomizer(pczt: &Pczt, group: &FullViewingKey, value: u64) -> Pczt {
    let mut found = None;
    pczt::roles::low_level_signer::Signer::new(pczt.clone())
        .sign_ironwood_with(|_, bundle, _| -> Result<(), pczt_io::TxError> {
            for action in bundle.actions() {
                let spend = action.spend();
                if spend.value().map(|v| v.inner()) == Some(value) {
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
    let ak: [u8; 32] = group.to_bytes()[..32].try_into().unwrap();
    let mut bytes = pczt_io::serialize(pczt.clone()).unwrap();
    for (old, new) in [(alpha, [0u8; 32]), (rk, ak)] {
        let at = bytes
            .windows(32)
            .position(|window| window == old)
            .expect("the field in the serialized PCZT");
        bytes[at..at + 32].copy_from_slice(&new);
    }
    pczt_io::parse(&bytes).unwrap()
}

/// A unified address with several receivers, as wallets hand them out: the
/// given Orchard receiver and a transparent one, in the given revision of the
/// encoding (Revision 2 gives `tu1…`).
pub fn invoice_address_in(
    revision: zcash_address::unified::Revision,
    orchard: &Address,
    network: zcash_protocol::consensus::NetworkType,
) -> String {
    use zcash_address::unified::{self, Encoding};
    unified::Address::try_from_items(
        revision,
        vec![
            unified::Uitem::Data(unified::Receiver::Orchard(orchard.to_raw_address_bytes())),
            unified::Uitem::Data(unified::Receiver::P2pkh([7; 20])),
        ],
    )
    .unwrap()
    .encode(&network)
}

/// [`invoice_address_in`] in Revision 0, the one most wallets show.
pub fn invoice_address(
    orchard: &Address,
    network: zcash_protocol::consensus::NetworkType,
) -> String {
    invoice_address_in(zcash_address::unified::Revision::R0, orchard, network)
}

/// Writes `address` as the `user_address` of every output, as
/// zcash_client_backend does for a payment's output.
pub fn named(pczt: Pczt, address: &str) -> Pczt {
    let count = action_count(&pczt);
    let mut labelled = pczt;
    for index in 0..count {
        labelled = pczt::roles::updater::Updater::new(labelled)
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
