//! An optional standing policy for the co-signer: rules the owner sets once,
//! checked against the report's structured facts before the user is asked. A
//! payment that breaks a rule is refused without a prompt. One that keeps them
//! all still goes to the user exactly as without a policy: the policy only ever
//! narrows what can be signed.
//!
//! The rules are stateless, so they read nothing but the transaction in front
//! of them. A policy file naming a rule this co-signer does not enforce (a
//! daily budget, say) is refused when it loads, never ignored in silence.

use std::error::Error;
use std::fs;
use std::path::Path;

use serde::Deserialize;
use zcash_address::unified::{self, Container, Encoding};
use zcash_protocol::consensus::NetworkType;

use crate::check::{Report, amount};

/// A policy file is a few hundred bytes; anything far larger is not one.
const MAX_POLICY_FILE: u64 = 1024 * 1024;

/// A standing policy, read from a JSON file the owner writes. Every rule is
/// optional, but a policy must set at least one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// `main`, `test` or `regtest`: a policy signs on one network only.
    network: String,
    /// A name for the person reading the refusal; checked against nothing.
    #[serde(default)]
    name: Option<String>,
    /// The largest single payment, in zatoshis.
    #[serde(default)]
    per_payment_cap_zat: Option<u64>,
    /// The largest fee, in zatoshis.
    #[serde(default)]
    max_fee_zat: Option<u64>,
    /// When present, every payment must go to one of these. An entry matches
    /// when one of its receivers is the paid receiver, of the same kind.
    #[serde(default)]
    allowed_recipients: Option<Vec<Recipient>>,
}

/// One entry of the allow-list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    /// A name for the person reading the policy; checked against nothing.
    #[serde(default)]
    pub label: Option<String>,
    /// A unified address on the policy's network. A payment matches when its
    /// paid receiver is one of this address's receivers, of the same kind.
    pub address: String,
}

/// One receiver of a unified address: its kind and its bytes.
#[derive(PartialEq, Eq)]
enum Receiver {
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    Sapling([u8; 43]),
    Orchard([u8; 43]),
    Unknown(u32, Vec<u8>),
}

impl Policy {
    /// Reads and checks a policy file. A file over 1 MiB, unknown fields or a
    /// policy with no rule are refused.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, Box<dyn Error>> {
        let path = path.as_ref();
        if fs::metadata(path)?.len() > MAX_POLICY_FILE {
            return Err(format!("{} is too large to be a policy", path.display()).into());
        }
        let text = fs::read_to_string(path)?;
        Self::from_json(&text).map_err(|e| format!("policy {}: {e}", path.display()).into())
    }

    /// Parses and checks a policy from its JSON text.
    pub fn from_json(text: &str) -> Result<Self, String> {
        let policy: Policy = serde_json::from_str(text).map_err(|e| e.to_string())?;
        let network = policy.network()?;
        if policy.per_payment_cap_zat.is_none()
            && policy.max_fee_zat.is_none()
            && policy.allowed_recipients.is_none()
        {
            return Err("the policy sets no rule".into());
        }
        for entry in policy.allowed_recipients.iter().flatten() {
            let (entry_network, _) = receivers(&entry.address).ok_or_else(|| {
                format!(
                    "allowed recipient {} is not a unified address",
                    short(&entry.address)
                )
            })?;
            if entry_network != network {
                return Err(format!(
                    "allowed recipient {} is for another network than the policy's {}",
                    short(&entry.address),
                    policy.network
                ));
            }
        }
        Ok(policy)
    }

    fn network(&self) -> Result<NetworkType, String> {
        match self.network.as_str() {
            "main" => Ok(NetworkType::Main),
            "test" => Ok(NetworkType::Test),
            "regtest" => Ok(NetworkType::Regtest),
            other => Err(format!(
                "unknown network {other:?}: use main, test or regtest"
            )),
        }
    }

    /// The policy's name, if it has one, for messages.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Checks the report against every rule. The reason names the first rule
    /// broken.
    pub fn check(&self, report: &Report, network: NetworkType) -> Result<(), String> {
        if self.network()? != network {
            return Err(format!(
                "policy: written for network {}, but this group is on another",
                self.network
            ));
        }
        if let Some(max) = self.max_fee_zat
            && report.fee_zat > max
        {
            return Err(format!(
                "policy: the fee ({}) is above the policy's maximum ({})",
                amount(report.fee_zat, network),
                amount(max, network)
            ));
        }
        for payment in &report.payments {
            if let Some(cap) = self.per_payment_cap_zat
                && payment.zat > cap
            {
                return Err(format!(
                    "policy: a payment of {} is above the per-payment cap of {}",
                    amount(payment.zat, network),
                    amount(cap, network)
                ));
            }
            if let Some(allowed) = &self.allowed_recipients {
                let paid = receivers(&payment.address)
                    .map(|(_, paid)| paid)
                    .unwrap_or_default();
                let listed = allowed.iter().any(|entry| {
                    receivers(&entry.address)
                        .is_some_and(|(_, entry)| entry.iter().any(|r| paid.contains(r)))
                });
                if paid.is_empty() || !listed {
                    return Err(format!(
                        "policy: recipient {} is not on the allow-list",
                        short(&payment.address)
                    ));
                }
            }
        }
        Ok(())
    }
}

/// The network and receivers of a unified address, or `None` if it is not one.
fn receivers(address: &str) -> Option<(NetworkType, Vec<Receiver>)> {
    let (network, _, ua) = unified::Address::decode(address).ok()?;
    let receivers = ua
        .items()
        .into_iter()
        .map(|item| match item {
            unified::Receiver::P2pkh(bytes) => Receiver::P2pkh(bytes),
            unified::Receiver::P2sh(bytes) => Receiver::P2sh(bytes),
            unified::Receiver::Sapling(bytes) => Receiver::Sapling(bytes),
            unified::Receiver::Orchard(bytes) => Receiver::Orchard(bytes),
            unified::Receiver::Unknown { typecode, data } => Receiver::Unknown(typecode, data),
        })
        .collect();
    Some((network, receivers))
}

fn short(address: &str) -> String {
    match (
        address.get(..12),
        address.get(address.len().saturating_sub(8)..),
    ) {
        (Some(head), Some(tail)) if address.len() > 24 => format!("{head}…{tail}"),
        _ => address.to_string(),
    }
}
