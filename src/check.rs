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

pub struct Report {
    pub lines: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn zec(zatoshis: u64) -> String {
    format!("{}.{:08} ZEC", zatoshis / 100_000_000, zatoshis % 100_000_000)
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
            action.verify_cv_net().map_err(|e| refuse(&format!("action {index}: value commitment"), &e))?;
            spend.verify_nullifier(Some(fvk)).map_err(|e| refuse(&format!("action {index}: spent note"), &e))?;
            spend.verify_rk(Some(fvk)).map_err(|e| refuse(&format!("action {index}: randomized key"), &e))?;
            output.verify_note_commitment(spend).map_err(|e| refuse(&format!("action {index}: output note"), &e))?;

            // verify_cv_net succeeded, so both values are present.
            let spend_value = spend.value().map(|v| v.inner()).unwrap_or_default();
            let output_value = output.value().map(|v| v.inner()).unwrap_or_default();
            spent += spend_value;
            if spend_value > 0 {
                lines.push(format!("spend {} from this group", zec(spend_value)));
            }
            if output_value > 0 {
                let recipient = output.recipient().ok_or_else(|| TxError::Refused(format!("action {index}: output without recipient")))?;
                match fvk.scope_for_address(&recipient) {
                    Some(Scope::Internal) => {
                        change += output_value;
                        lines.push(format!("change {} back to this group", zec(output_value)));
                    }
                    Some(Scope::External) => {
                        change += output_value;
                        lines.push(format!("send {} to this group's own address", zec(output_value)));
                    }
                    None => {
                        paid += output_value;
                        let address = keys::encode_address(&recipient, network).map_err(|e| TxError::Refused(e.to_string()))?;
                        lines.push(format!("PAY {} to {address}", zec(output_value)));
                    }
                }
            }
        }
        Ok(())
    })?;

    let fee = spent
        .checked_sub(paid + change)
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
