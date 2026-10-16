//! What the co-signer checks before it signs, on its own.
//!
//! It does not trust the amounts and addresses written in the PCZT: for every
//! action it recomputes the note commitments, the nullifier, the randomized
//! key and the value commitment from those fields (orchard's PCZT verifiers),
//! so a lying coordinator cannot show one payment and get a signature for
//! another. Then it sorts the outputs into payments and change, and works out
//! the fee.

use std::error::Error;

use orchard::keys::{FullViewingKey, Scope};
use orchard::note::ExtractedNoteCommitment;
use orchard::{Anchor, Note};
use pczt::roles::low_level_signer::Signer;
use pczt::Pczt;
use zcash_protocol::consensus::NetworkType;
use zcash_protocol::constants::V6_TX_VERSION;
use zcash_protocol::PoolType;

use crate::keys;
use crate::pczt_io::TxError;

/// Above this fee the co-signer warns (ZIP 317 fees are normally 0.0001 to
/// 0.0003 ZEC for a few actions).
const HIGH_FEE: u64 = 100_000;

/// The total supply of ZEC in zatoshis: no honest amount can be larger.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

pub struct Report {
    pub lines: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn zec(zatoshis: u64) -> String {
    format!("{}.{:08} ZEC", zatoshis / 100_000_000, zatoshis % 100_000_000)
}

/// Adds an amount read from the PCZT to a running total. The amounts come
/// from the coordinator, so they are bounded instead of trusted not to overflow.
fn add(total: &mut u64, value: u64) -> Result<(), TxError> {
    *total = total
        .checked_add(value)
        .filter(|sum| *sum <= MAX_MONEY)
        .ok_or_else(|| TxError::Refused("amounts larger than the total ZEC supply".into()))?;
    Ok(())
}

/// Checks on one spend that need no key.
///
/// - ZIP 374: "Signers MUST reject PCZTs that contain `dummy_sk` values". The
///   IO Finalizer signs the dummy spends with that key and then clears it, so a
///   PCZT that still holds one skipped a step, and its signer would be handed a
///   spending key.
/// - When the PCZT gives a witness for a real note, it must lead to the
///   bundle's anchor. This only catches an inconsistent PCZT: the anchor itself
///   comes from the coordinator, and a v6 signature does not commit to it (see
///   `pre_authorization`).
///
/// A zero-value spend has no place in the tree to check: the circuit skips the
/// Merkle path for it.
fn check_spend_structure(
    index: usize,
    spend: &orchard::pczt::Spend,
    anchor: &Anchor,
    anchor_deferred: bool,
) -> Result<(), TxError> {
    if spend.dummy_sk().is_some() {
        return Err(TxError::Refused(format!(
            "action {index}: the PCZT still holds a dummy spending key (ZIP 374: a signer must refuse it)"
        )));
    }
    let value = spend.value().map(|v| v.inner()).unwrap_or_default();
    let (false, Some(witness), true) = (anchor_deferred, spend.witness(), value > 0) else {
        return Ok(());
    };
    let incomplete = || TxError::Refused(format!("action {index}: incomplete spent note"));
    let note = Note::from_parts(
        spend.recipient().ok_or_else(incomplete)?,
        spend.value().ok_or_else(incomplete)?,
        spend.rho().ok_or_else(incomplete)?,
        spend.rseed().ok_or_else(incomplete)?,
        *spend.note_version(),
    )
    .into_option()
    .ok_or_else(incomplete)?;
    if witness.root(ExtractedNoteCommitment::from(note.commitment())) != *anchor {
        return Err(TxError::Refused(format!(
            "action {index}: the note's witness does not lead to the transaction's anchor"
        )));
    }
    Ok(())
}

/// The warning every v6 signature needs. A v6 sighash leaves the anchors out
/// (ZIP 374 lets them be set after signing), so signing does not prove that the
/// spent notes exist on chain: it authorizes exactly these payments for as long
/// as the transaction can be mined, whenever those notes exist. The expiry
/// height is what bounds that; a transaction that never expires is refused.
fn pre_authorization(expiry_height: u32) -> Result<String, TxError> {
    if expiry_height == 0 {
        return Err(TxError::Refused(
            "the transaction never expires: a pre-authorized v6 spend would stay valid forever".into(),
        ));
    }
    Ok(format!(
        "v6 pre-authorization: this signature does not prove the spent notes exist on chain; \
         it authorizes these exact payments if they do, until block {expiry_height}"
    ))
}

/// Verifies and describes a PCZT that spends from the group `fvk`.
pub fn analyze(pczt: &Pczt, fvk: &FullViewingKey, network: NetworkType) -> Result<Report, Box<dyn Error>> {
    if pczt.has_data_in_pool(PoolType::Transparent) || pczt.has_data_in_pool(PoolType::SAPLING) {
        return Err("the transaction has transparent or Sapling parts, which this prototype refuses".into());
    }

    let mut lines = Vec::new();
    let mut warnings = Vec::new();
    let mut spent = 0u64;
    let mut paid = 0u64;
    let mut change = 0u64;

    if *pczt.global().tx_version() == V6_TX_VERSION {
        warnings.push(pre_authorization(*pczt.global().expiry_height())?);
    }

    Signer::new(pczt.clone()).sign_ironwood_with(|_, bundle, _| -> Result<(), TxError> {
        let refuse = |what: &str, error: &dyn std::fmt::Debug| TxError::Refused(format!("{what}: {error:?}"));
        bundle.verify_cross_address_restriction().map_err(|e| refuse("cross-address check failed", &e))?;
        let anchor = *bundle.anchor();
        let anchor_deferred = *bundle.anchor_deferred();
        for (index, action) in bundle.actions().iter().enumerate() {
            let spend = action.spend();
            let output = action.output();
            check_spend_structure(index, spend, &anchor, anchor_deferred)?;
            // The value commitment ties each claimed value to what the proof
            // commits to, so the values below cannot be faked.
            action.verify_cv_net().map_err(|e| refuse(&format!("action {index}: value commitment"), &e))?;
            let spend_value = spend.value().map(|v| v.inner()).unwrap_or_default();
            let output_value = output.value().map(|v| v.inner()).unwrap_or_default();

            if spend_value == 0 {
                // A dummy spend: it pads the transaction, belongs to a throwaway
                // key and was already signed when the PCZT was built. It moves no
                // value; an unsigned zero-value spend is not expected.
                if spend.spend_auth_sig().is_none() {
                    return Err(TxError::Refused(format!("action {index}: unsigned zero-value spend")));
                }
            } else {
                spend.verify_nullifier(Some(fvk)).map_err(|e| refuse(&format!("action {index}: spent note"), &e))?;
                spend.verify_rk(Some(fvk)).map_err(|e| refuse(&format!("action {index}: randomized key"), &e))?;
            }
            output.verify_note_commitment(spend).map_err(|e| refuse(&format!("action {index}: output note"), &e))?;
            add(&mut spent, spend_value)?;
            if spend_value > 0 {
                lines.push(format!("spend {} from this group", zec(spend_value)));
            }
            if output_value > 0 {
                let recipient = output.recipient().ok_or_else(|| TxError::Refused(format!("action {index}: output without recipient")))?;
                match fvk.scope_for_address(&recipient) {
                    Some(Scope::Internal) => {
                        add(&mut change, output_value)?;
                        lines.push(format!("change {} back to this group", zec(output_value)));
                    }
                    Some(Scope::External) => {
                        add(&mut change, output_value)?;
                        lines.push(format!("send {} to this group's own address", zec(output_value)));
                    }
                    None => {
                        add(&mut paid, output_value)?;
                        let address = keys::encode_address(&recipient, network).map_err(|e| TxError::Refused(e.to_string()))?;
                        lines.push(format!("PAY {} to {address}", zec(output_value)));
                    }
                }
            }
        }
        Ok(())
    })?;

    let mut outputs = paid;
    add(&mut outputs, change)?;
    let fee = spent
        .checked_sub(outputs)
        .ok_or("the outputs are worth more than the spent notes")?;
    lines.push(format!("fee {}", zec(fee)));
    if fee > HIGH_FEE {
        warnings.push(format!("high fee: {}", zec(fee)));
    }
    if spent == 0 {
        return Err("the transaction spends nothing from this group".into());
    }
    Ok(Report { lines, warnings })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn totals_are_bounded_by_the_supply() {
        let mut total = MAX_MONEY - 1;
        assert!(add(&mut total, 1).is_ok());
        assert!(add(&mut total, 1).is_err());
        assert_eq!(total, MAX_MONEY, "a refused amount leaves the total unchanged");
        let mut total = 1;
        assert!(add(&mut total, u64::MAX).is_err());
    }

    /// A bundle straight out of the builder, before the IO Finalizer: its dummy
    /// padding spend still holds its spending key, so the co-signer refuses it.
    #[test]
    fn a_pczt_with_a_dummy_spending_key_is_refused() {
        use orchard::builder::{Builder, BundleType};
        use orchard::bundle::{BundleVersion, Flags};
        use orchard::keys::SpendingKey;
        use orchard::value::NoteValue;

        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);
        let mut builder = Builder::new(BundleType::DEFAULT, BundleVersion::ironwood_v3(), Flags::ENABLED, Anchor::empty_tree()).unwrap();
        builder.add_output(None, recipient, NoteValue::from_raw(10_000), [0; 512]).unwrap();
        let (bundle, _) = builder.build_for_pczt(rand::rngs::OsRng).unwrap();

        let refused: Vec<_> = bundle
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| action.spend().dummy_sk().is_some())
            .map(|(index, action)| check_spend_structure(index, action.spend(), bundle.anchor(), *bundle.anchor_deferred()))
            .collect();
        assert!(!refused.is_empty(), "the builder left no dummy key to test with");
        for result in refused {
            assert!(matches!(result, Err(TxError::Refused(reason)) if reason.contains("dummy spending key")));
        }
    }

    /// A real spend whose witness leads to the anchor passes; the same spend
    /// checked against another anchor is refused.
    #[test]
    fn a_witness_must_lead_to_the_anchor() {
        use orchard::builder::{Builder, BundleType};
        use orchard::bundle::{BundleVersion, Flags};
        use orchard::keys::SpendingKey;
        use orchard::note::{RandomSeed, Rho};
        use orchard::tree::{MerkleHashOrchard, MerklePath};
        use orchard::value::NoteValue;
        use orchard::NoteVersion;

        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[1; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2; 32], &rho).unwrap();
        let note = Note::from_parts(recipient, NoteValue::from_raw(50_000), rho, rseed, NoteVersion::V3).unwrap();
        let path = MerklePath::from_parts(5, [MerkleHashOrchard::from_bytes(&[0; 32]).unwrap(); 32]);
        let anchor = path.root(ExtractedNoteCommitment::from(note.commitment()));

        let mut builder = Builder::new(BundleType::DEFAULT, BundleVersion::ironwood_v3(), Flags::ENABLED, anchor).unwrap();
        builder.add_spend(fvk, note, path).unwrap();
        builder.add_output(None, recipient, NoteValue::from_raw(40_000), [0; 512]).unwrap();
        let (bundle, _) = builder.build_for_pczt(rand::rngs::OsRng).unwrap();
        let (index, action) = bundle
            .actions()
            .iter()
            .enumerate()
            .find(|(_, action)| action.spend().value().is_some_and(|v| v.inner() == 50_000))
            .unwrap();

        assert!(check_spend_structure(index, action.spend(), &anchor, false).is_ok());
        let refused = check_spend_structure(index, action.spend(), &Anchor::empty_tree(), false);
        assert!(matches!(refused, Err(TxError::Refused(reason)) if reason.contains("witness")));
        // A deferred anchor (ZIP 374): nothing to compare yet.
        assert!(check_spend_structure(index, action.spend(), &Anchor::empty_tree(), true).is_ok());
    }

    /// The real finalized PCZT (no dummy key left) passes the structural checks,
    /// and gets the pre-authorization warning with its expiry height.
    #[test]
    fn the_finalized_testnet_pczt_passes_and_is_marked_as_pre_authorization() {
        let pczt = crate::pczt_io::parse(include_bytes!("../tests/fixtures/ironwood_v6.pczt")).unwrap();
        assert_eq!(*pczt.global().tx_version(), V6_TX_VERSION);
        Signer::new(pczt.clone())
            .sign_ironwood_with(|_, bundle, _| -> Result<(), TxError> {
                for (index, action) in bundle.actions().iter().enumerate() {
                    check_spend_structure(index, action.spend(), bundle.anchor(), *bundle.anchor_deferred())?;
                }
                Ok(())
            })
            .unwrap();
        let expiry = *pczt.global().expiry_height();
        assert!(pre_authorization(expiry).unwrap().contains(&format!("until block {expiry}")));
        assert!(pre_authorization(0).is_err());
    }
}
