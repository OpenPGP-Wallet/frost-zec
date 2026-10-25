//! Reading a PCZT, finding the spends to authorize, and inserting signatures.
//!
//! PCZTs come from zcash-devtool (`pczt create`, then `pczt prove`) and go
//! back to it once signed (`pczt send`).

use std::error::Error;
use std::fmt;

use ff::PrimeField;
use orchard::primitives::redpallas::{self, SpendAuth};
use pczt::roles::low_level_signer::{OrchardParseError, Signer};
use pczt::Pczt;
use zcash_primitives::transaction::sighash::{PrecomputedSighashData, SignableInput};
use zcash_primitives::transaction::TxVersion;

/// Errors raised inside the low-level signer callbacks.
#[derive(Debug)]
pub enum TxError {
    Parse(OrchardParseError),
    Apply(orchard::pczt::SignerError),
    Refused(String),
}

impl From<OrchardParseError> for TxError {
    fn from(error: OrchardParseError) -> Self {
        TxError::Parse(error)
    }
}

impl fmt::Display for TxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxError::Parse(error) => write!(f, "cannot parse the shielded bundle: {error:?}"),
            TxError::Apply(error) => write!(f, "signature rejected: {error:?}"),
            TxError::Refused(reason) => write!(f, "{reason}"),
        }
    }
}

impl Error for TxError {}

/// A spend waiting for its authorization signature, in the Ironwood bundle.
pub struct SpendToSign {
    pub index: usize,
    pub alpha: [u8; 32],
}

pub fn parse(bytes: &[u8]) -> Result<Pczt, Box<dyn Error>> {
    Pczt::parse(bytes).map_err(|e| format!("not a valid PCZT: {e:?}").into())
}

pub fn serialize(pczt: Pczt) -> Result<Vec<u8>, Box<dyn Error>> {
    pczt.serialize().map_err(|e| format!("cannot serialize the PCZT: {e:?}").into())
}

/// The sighash every spend authorization signature commits to. Only v6
/// transactions are accepted: a v5 sighash over a v6 transaction would sign
/// fine here and only fail at broadcast (see zcash-sign, frost-tools#593).
pub fn sighash(pczt: &Pczt) -> Result<[u8; 32], Box<dyn Error>> {
    let tx_data = pczt
        .clone()
        .into_effects()
        .map_err(|e| format!("the PCZT does not describe a complete transaction yet: {e:?}"))?;
    if tx_data.version() != TxVersion::V6 {
        return Err("only v6 (NU6.3, Ironwood) transactions are supported".into());
    }
    let precomputed = PrecomputedSighashData::new_zip244(tx_data).map_err(|_| "cannot compute the sighash of this transaction")?;
    Ok(*precomputed.signature_hash(&SignableInput::Shielded).as_ref())
}

/// The Ironwood spends that still need a signature. Spends in the sealed
/// Orchard pool are refused: this prototype only spends Ironwood notes.
pub fn spends_to_sign(pczt: &Pczt) -> Result<Vec<SpendToSign>, Box<dyn Error>> {
    Signer::new(pczt.clone()).sign_orchard_with(|_, bundle, _| {
        let waiting = bundle.actions().iter().any(|action| action.spend().spend_auth_sig().is_none() && action.spend().alpha().is_some());
        if waiting {
            return Err(TxError::Refused("the transaction spends from the sealed Orchard pool, which this prototype does not sign".into()));
        }
        Ok(())
    })?;

    let mut found = Vec::new();
    Signer::new(pczt.clone()).sign_ironwood_with(|_, bundle, _| -> Result<(), TxError> {
        for (index, action) in bundle.actions().iter().enumerate() {
            if action.spend().spend_auth_sig().is_none()
                && let Some(alpha) = action.spend().alpha()
            {
                found.push(SpendToSign { index, alpha: alpha.to_repr() });
            }
        }
        Ok(())
    })?;
    if found.is_empty() {
        return Err("no Ironwood spend is waiting for a signature".into());
    }
    Ok(found)
}

/// Inserts one signature per spend. orchard checks each one against the
/// spend's rk before accepting it.
pub fn apply(pczt: Pczt, sighash: &[u8; 32], signatures: &[(usize, [u8; 64])]) -> Result<Pczt, Box<dyn Error>> {
    let signed = Signer::new(pczt).sign_ironwood_with(|_, bundle, _| -> Result<(), TxError> {
        let actions = bundle.actions_mut();
        for (index, signature) in signatures {
            let action = actions.get_mut(*index).ok_or_else(|| TxError::Refused(format!("no action {index}")))?;
            action
                .apply_signature(*sighash, redpallas::Signature::<SpendAuth>::from(*signature))
                .map_err(TxError::Apply)?;
        }
        Ok(())
    })?;
    Ok(signed.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The proven, unsigned v6 PCZT behind testnet transaction
    /// a5533fe75575b09d8986a05005d2c0528cf45a1a7e4cc71b304ae76a9e14487d, an
    /// Ironwood spend authorized by a 2-of-3 FROST signature (fixture from
    /// ZcashFoundation/frost-tools, zcash-sign, MIT/Apache-2.0).
    const IRONWOOD_V6: &[u8] = include_bytes!("../tests/fixtures/ironwood_v6.pczt");

    #[test]
    fn sighash_matches_the_signed_testnet_transaction() {
        let pczt = parse(IRONWOOD_V6).unwrap();
        assert_eq!(hex::encode(sighash(&pczt).unwrap()), "7d48149e6ae74a301bc74c7e1a5af48c52c0d20550a086899db07555e73f53a5");
    }

    #[test]
    fn finds_the_spend_waiting_for_a_signature() {
        let spends = spends_to_sign(&parse(IRONWOOD_V6).unwrap()).unwrap();
        assert_eq!(spends.len(), 1);
    }
}
