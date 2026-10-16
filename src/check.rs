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
use pczt::roles::low_level_signer::Signer;
use pczt::Pczt;
use zcash_protocol::consensus::NetworkType;
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

    Signer::new(pczt.clone()).sign_ironwood_with(|_, bundle, _| -> Result<(), TxError> {
        let refuse = |what: &str, error: &dyn std::fmt::Debug| TxError::Refused(format!("{what}: {error:?}"));
        bundle.verify_cross_address_restriction().map_err(|e| refuse("cross-address check failed", &e))?;
        for (index, action) in bundle.actions().iter().enumerate() {
            let spend = action.spend();
            let output = action.output();
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
}
