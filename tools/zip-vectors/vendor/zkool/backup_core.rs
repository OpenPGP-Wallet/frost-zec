// From Zkool's rust/src/frost/backup.rs (commit in COMMIT), copied unchanged:
// lines 46-105 (the string codec) and 143-160 (match_derivation). Only these
// imports are new; export and restore need Zkool's database and are left out.
use anyhow::{anyhow, bail, Result};
use bech32::{primitives::decode::CheckedHrpstring, Bech32m, Hrp};
use orchard::keys::{FullViewingKey, SpendingKey};

use super::keys::{group_fvk, DKG_VERSION_0, DKG_VERSION_2};

pub const HRP: &str = "zkfrost";
pub const FORMAT_VERSION: u8 = 1;
const PAYLOAD_LEN: usize = 68;

/// What the string carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostBackup {
    pub id: u8,
    pub t: u8,
    pub n: u8,
    pub share: [u8; 32],
    pub sk: [u8; 32],
}

impl FrostBackup {
    pub fn encode(&self) -> Result<String> {
        let mut payload = Vec::with_capacity(PAYLOAD_LEN);
        payload.push(FORMAT_VERSION);
        payload.push(self.id);
        payload.push(self.t);
        payload.push(self.n);
        payload.extend_from_slice(&self.share);
        payload.extend_from_slice(&self.sk);
        Ok(bech32::encode::<Bech32m>(Hrp::parse(HRP)?, &payload)?)
    }

    /// Rejects a wrong prefix, a bad checksum, a wrong length and an
    /// unknown format version.
    pub fn decode(s: &str) -> Result<Self> {
        let checked = CheckedHrpstring::new::<Bech32m>(s.trim())
            .map_err(|e| anyhow!("not a valid zkfrost backup string: {e}"))?;
        if checked.hrp().to_lowercase() != HRP {
            bail!("not a zkfrost backup string");
        }
        let payload: Vec<u8> = checked.byte_iter().collect();
        if payload.len() != PAYLOAD_LEN {
            bail!(
                "invalid zkfrost backup string: expected {PAYLOAD_LEN} bytes, got {}",
                payload.len()
            );
        }
        if payload[0] != FORMAT_VERSION {
            bail!(
                "unsupported zkfrost backup format version {}; this app supports version {FORMAT_VERSION}",
                payload[0]
            );
        }
        let (id, t, n) = (payload[1], payload[2], payload[3]);
        if n == 0 || id == 0 || id > n || t == 0 || t > n {
            bail!("invalid zkfrost backup string: participant {id}, threshold {t} of {n}");
        }
        Ok(Self {
            id,
            t,
            n,
            share: payload[4..36].try_into().unwrap(),
            sk: payload[36..68].try_into().unwrap(),
        })
    }
}


/// Which derivation a viewing key follows for a given `sk`: the generation
/// a restore defaults to. An error when neither matches, i.e. the string
/// is not this group's.
pub fn match_derivation(fvk: &FullViewingKey, sk: &SpendingKey) -> Result<u8> {
    let ak: [u8; 32] = fvk.to_bytes()[..32].try_into().unwrap();
    if group_fvk(DKG_VERSION_0, sk, &ak)? == *fvk {
        Ok(DKG_VERSION_0)
    } else if group_fvk(DKG_VERSION_2, sk, &ak)? == *fvk {
        Ok(DKG_VERSION_2)
    } else {
        bail!(
            "the backup string does not belong to this viewing key's group: \
             neither the legacy nor the ZIP 2005 derivation of nk and rivk from \
             its sk matches the key"
        )
    }
}
