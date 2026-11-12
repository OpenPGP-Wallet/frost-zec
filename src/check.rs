//! What the co-signer checks before it signs, on its own.
//!
//! It does not trust the amounts and addresses written in the PCZT: for every
//! action it recomputes the note commitments, the nullifier, the randomized
//! key and the value commitment from those fields (orchard's PCZT verifiers),
//! so a lying coordinator cannot show one payment and get a signature for
//! another. Then it sorts the outputs into payments and change, and works out
//! the fee.

use std::collections::BTreeSet;
use std::error::Error;

use ff::{Field, PrimeField};
use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey, Scope};
use orchard::note::ExtractedNoteCommitment;
use orchard::{Anchor, Note};
use pasta_curves::pallas;
use pczt::Pczt;
use pczt::roles::low_level_signer::Signer;
use zcash_address::unified::{self, Container, Encoding};
use zcash_protocol::PoolType;
use zcash_protocol::consensus::NetworkType;
use zcash_protocol::constants::V6_TX_VERSION;

use crate::keys;
use crate::pczt_io::TxError;

/// Above this fee the co-signer warns (ZIP 317 fees are normally 0.0001 to
/// 0.0003 ZEC for a few actions).
const HIGH_FEE: u64 = 100_000;

/// ZIP 317's marginal fee per logical action, in zatoshis. ZIP 2009 (Proposed)
/// lowers it to 1,000 from block 3,590,000 on Mainnet and 4,465,026 on testnet.
/// The co-signer sees no chain, so it accepts any fee up to the old rate for
/// the actions a payment needs: both rates pass around that height.
const MAX_MARGINAL_FEE: u64 = 5_000;

/// ZIP 317's grace actions: a bundle is padded to at least two actions.
const GRACE_ACTIONS: usize = 2;

/// A recent block of each network, its height and time (Unix seconds), and a
/// block spacing faster than the network ever keeps up for long. From these and
/// this computer's clock, the co-signer bounds the current height from above.
///
/// The target spacing is 25 seconds since NU7 (ZIP 218). Mainnet keeps to it
/// (25.0 s on average from 2026-11-09 to 2026-11-12), so 20 s leaves room. Testnet
/// runs faster (about 18 s on 2026-11-12), so it is counted at 10 s.
const CHECKPOINTS: [(NetworkType, u32, u64, u64); 2] = [
    // 2026-11-10 15:39:24 UTC
    (NetworkType::Main, 3_558_933, 1_794_325_164, 20),
    // 2026-11-12 16:49:09 UTC
    (NetworkType::Test, 4_612_900, 1_794_502_149, 10),
];

/// The target spacing since NU7, to say roughly when the expiry falls. Shown on
/// Mainnet only: testnet does not keep to it.
const TARGET_BLOCK_SECS: u64 = 25;

/// How far beyond that estimate an expiry may be. Wallets set it minutes ahead
/// (zcash_primitives: 120 blocks since NU7, 50 minutes).
const EXPIRY_MARGIN_BLOCKS: u64 = 1_000;

/// The total supply of ZEC in zatoshis: no honest amount can be larger.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

#[derive(Debug)]
pub struct Report {
    pub lines: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn zec(zatoshis: u64) -> String {
    format!(
        "{}.{:08} ZEC",
        zatoshis / 100_000_000,
        zatoshis % 100_000_000
    )
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

/// A spend's randomizer `alpha` is what hides the signing key on chain: the
/// spend shows `rk = ak + [alpha]G`. A zero `alpha` would publish the group's
/// `ak` itself as `rk`, the same in every such spend, and an `alpha` used for
/// two spends gives them the same `rk`: either way anyone could link them.
/// orchard's builder draws it at random, so only a dishonest or broken builder
/// gets here. Reuse across transactions would need the co-signer to remember
/// every `alpha` it signed; it does not.
fn check_randomizer(
    index: usize,
    alpha: &pallas::Scalar,
    seen: &mut BTreeSet<[u8; 32]>,
) -> Result<(), TxError> {
    if bool::from(alpha.is_zero()) {
        return Err(TxError::Refused(format!(
            "action {index}: the spend's randomizer is zero, which would show the group's key on chain"
        )));
    }
    if !seen.insert(alpha.to_repr()) {
        return Err(TxError::Refused(format!(
            "action {index}: two spends share a randomizer, which would link them on chain"
        )));
    }
    Ok(())
}

/// The address a payment is shown with.
///
/// A PCZT may name the address the user was given (`user_address`, ZIP 374):
/// zcash_client_backend writes the payment's address there, usually a unified
/// address with several receivers. That is the string the user can compare
/// with their invoice, so it is shown, once checked: it must be a unified
/// address on this network, and its Orchard receiver (the one Ironwood notes
/// go to) must be the one paid. Any other value is refused, not ignored: a
/// coordinator that names one address and pays another is not honest. Without
/// it, the paid receiver alone is shown, as a unified address.
fn payment_address(
    index: usize,
    named: Option<&str>,
    recipient: &orchard::Address,
    network: NetworkType,
) -> Result<String, TxError> {
    let Some(named) = named else {
        return keys::encode_address(recipient, network)
            .map_err(|e| TxError::Refused(e.to_string()));
    };
    let not_paid = || {
        TxError::Refused(format!(
            "action {index}: the address the transaction names is not the one it pays"
        ))
    };
    let (named_network, _, address) = unified::Address::decode(named).map_err(|_| not_paid())?;
    let paid = recipient.to_raw_address_bytes();
    let pays_it = address
        .items()
        .iter()
        .any(|item| matches!(item, unified::Receiver::Orchard(bytes) if *bytes == paid));
    if named_network != network || !pays_it {
        return Err(not_paid());
    }
    // Shown as encoded again from what was parsed, never as the PCZT's bytes.
    Ok(address.encode(&network))
}

/// The warning every v6 signature needs. A v6 sighash leaves the anchors out
/// (ZIP 374 lets them be set after signing), so signing does not prove that the
/// spent notes exist on chain: it authorizes exactly these payments for as long
/// as the transaction can be mined, whenever those notes exist. The expiry
/// height is what bounds that. A transaction that never expires is refused, and
/// so is one that expires far beyond the current height as this computer's clock
/// bounds it: a coordinator could keep such a signature and broadcast it much
/// later, for example after the user, told it failed, approved the same payment
/// again. `now` is the clock, in Unix seconds.
fn pre_authorization(
    expiry_height: u32,
    network: NetworkType,
    now: u64,
) -> Result<String, TxError> {
    if expiry_height == 0 {
        return Err(TxError::Refused(
            "the transaction never expires: a pre-authorized v6 spend would stay valid forever"
                .into(),
        ));
    }
    let mut when = String::new();
    let checkpoint = CHECKPOINTS.iter().find(|(net, ..)| *net == network);
    if let Some(&(_, height, time, fastest)) = checkpoint {
        let elapsed = now.saturating_sub(time);
        let highest = u64::from(height) + elapsed / fastest;
        if u64::from(expiry_height) > highest + EXPIRY_MARGIN_BLOCKS {
            return Err(TxError::Refused(format!(
                "the transaction stays valid until block {expiry_height}, far beyond the current \
                 height (at most about {highest} by this computer's clock): a signature must not \
                 stay usable that long. If this computer's clock is wrong, set it right"
            )));
        }
        if network == NetworkType::Main {
            let expected = u64::from(height) + elapsed / TARGET_BLOCK_SECS;
            when = match u64::from(expiry_height).checked_sub(expected) {
                Some(blocks) => {
                    format!(", about {} from now", duration(blocks * TARGET_BLOCK_SECS))
                }
                None => ", a height already passed by this computer's clock".into(),
            };
        }
    }
    Ok(format!(
        "v6 pre-authorization: this signature does not prove the spent notes exist on chain; \
         it authorizes these exact payments if they do, until block {expiry_height}{when}"
    ))
}

/// A rough duration, for the expiry warning.
fn duration(secs: u64) -> String {
    match secs {
        0..7_200 => format!("{} min", secs.div_ceil(60)),
        7_200..172_800 => format!("{} h", secs / 3_600),
        _ => format!("{} days", secs / 86_400),
    }
}

/// This computer's clock, in Unix seconds (0 if it is set before 1970).
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Verifies and describes a PCZT that spends from the group `fvk`.
pub fn analyze(
    pczt: &Pczt,
    fvk: &FullViewingKey,
    network: NetworkType,
) -> Result<Report, Box<dyn Error>> {
    // Every part of the transaction is covered by the signature. A part this
    // co-signer does not decode could carry value away without being shown:
    // value spent from the group's Ironwood notes and paid out in, say, an
    // Orchard bundle would only look like a larger fee here.
    for (pool, name) in [
        (PoolType::Transparent, "transparent"),
        (PoolType::SAPLING, "Sapling"),
        (PoolType::ORCHARD, "Orchard"),
    ] {
        if pczt.has_data_in_pool(pool) {
            return Err(format!(
                "the transaction has {name} parts, which the co-signer does not decode: refused"
            )
            .into());
        }
    }

    let mut lines = Vec::new();
    let mut warnings = Vec::new();
    let mut spent = 0u64;
    let mut paid = 0u64;
    let mut change = 0u64;
    let mut value_balance = None;
    let mut randomizers = BTreeSet::new();
    // What bounds the fee: how many actions the transaction has, and how many
    // it needs to move its value.
    let mut actions = 0usize;
    let mut valued_spends = 0usize;
    let mut valued_outputs = 0usize;

    if *pczt.global().tx_version() == V6_TX_VERSION {
        warnings.push(pre_authorization(
            *pczt.global().expiry_height(),
            network,
            now(),
        )?);
    }
    if let Some(lock_time) = pczt.global().fallback_lock_time().filter(|t| *t != 0) {
        lines.push(format!("not valid before lock time {lock_time}"));
    }

    let external_ovk = fvk.to_ovk(Scope::External);
    let internal_ovk = fvk.to_ovk(Scope::Internal);
    let external_ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External));
    let internal_ivk = PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal));

    Signer::new(pczt.clone()).sign_ironwood_with(|_, bundle, _| -> Result<(), TxError> {
        let refuse = |what: &str, error: &dyn std::fmt::Debug| {
            TxError::Refused(format!("{what}: {error:?}"))
        };
        bundle
            .verify_cross_address_restriction()
            .map_err(|e| refuse("cross-address check failed", &e))?;
        let anchor = *bundle.anchor();
        let anchor_deferred = *bundle.anchor_deferred();
        let bundle_version = *bundle.bundle_version();
        value_balance = Some(
            i64::try_from(*bundle.value_sum())
                .map_err(|e| refuse("bundle value balance out of range", &e))?,
        );
        for (index, action) in bundle.actions().iter().enumerate() {
            let spend = action.spend();
            let output = action.output();
            check_spend_structure(index, spend, &anchor, anchor_deferred)?;
            // The value commitment only binds this action's net value. The
            // note checks below are what bind the claimed values and recipient.
            action
                .verify_cv_net()
                .map_err(|e| refuse(&format!("action {index}: value commitment"), &e))?;
            let spend_value = spend.value().map(|v| v.inner()).unwrap_or_default();
            let output_value = output.value().map(|v| v.inner()).unwrap_or_default();

            if spend_value == 0 {
                // A dummy spend: it pads the transaction, belongs to a throwaway
                // key and was already signed when the PCZT was built. It moves no
                // value; an unsigned zero-value spend is not expected.
                if spend.spend_auth_sig().is_none() {
                    return Err(TxError::Refused(format!(
                        "action {index}: unsigned zero-value spend"
                    )));
                }
            } else {
                spend
                    .verify_nullifier(Some(fvk))
                    .map_err(|e| refuse(&format!("action {index}: spent note"), &e))?;
                spend
                    .verify_rk(Some(fvk))
                    .map_err(|e| refuse(&format!("action {index}: randomized key"), &e))?;
                let alpha = spend.alpha().as_ref().ok_or_else(|| {
                    TxError::Refused(format!("action {index}: the spend has no randomizer"))
                })?;
                check_randomizer(index, alpha, &mut randomizers)?;
            }
            output
                .verify_note_commitment(spend)
                .map_err(|e| refuse(&format!("action {index}: output note"), &e))?;
            add(&mut spent, spend_value)?;
            actions += 1;
            if spend_value > 0 {
                valued_spends += 1;
                lines.push(format!("spend {} from this group", zec(spend_value)));
            }
            if output_value == 0 {
                // A zero-value output is signed like any other. The builder's
                // padding cannot be read by anyone; one the coordinator added
                // and encrypted to the group's outgoing key can, and it would
                // land on chain with a recipient and memo nobody was shown. One
                // encrypted without that key cannot be told from padding: the
                // action count below leaves no room for more than the padding.
                let recovered = action
                    .recover_output_with_ovk(&external_ovk, bundle_version)
                    .and_then(|found| match found {
                        Some(found) => Ok(Some(found)),
                        None => action.recover_output_with_ovk(&internal_ovk, bundle_version),
                    })
                    .map_err(|e| refuse(&format!("action {index}: note encryption"), &e))?;
                if let Some((_, address, memo)) = recovered {
                    if fvk.scope_for_address(&address).is_none() {
                        return Err(TxError::Refused(format!(
                            "action {index}: a zero-value note to another address, with a memo \
                             the user would not be shown"
                        )));
                    }
                    lines.push("send 0 ZEC to this group's own address".into());
                    lines.push(format!("    {}", describe_memo(&memo)));
                }
            } else {
                valued_outputs += 1;
                let recipient = output.recipient().ok_or_else(|| {
                    TxError::Refused(format!("action {index}: output without recipient"))
                })?;
                // The note ciphertext is signed too, but nothing above checks
                // it. Decrypting it proves that it holds this very note, so its
                // recipient can find it, and gives the memo actually sent.
                let scope = fvk.scope_for_address(&recipient);
                let decrypted = match scope {
                    // The group's own output (change, or a payment to itself):
                    // decrypted with its incoming viewing key, as its wallet
                    // will when scanning. Wallets often encrypt change with no
                    // outgoing key, so this is the check that always applies.
                    Some(Scope::Internal) => {
                        action.decrypt_output_with_ivk(&internal_ivk, bundle_version)
                    }
                    Some(Scope::External) => {
                        action.decrypt_output_with_ivk(&external_ivk, bundle_version)
                    }
                    // A payment: read back with the group's outgoing viewing key.
                    None => action
                        .recover_output_with_ovk(&external_ovk, bundle_version)
                        .and_then(|found| match found {
                            Some(found) => Ok(Some(found)),
                            None => action.recover_output_with_ovk(&internal_ovk, bundle_version),
                        }),
                }
                .map_err(|e| refuse(&format!("action {index}: note encryption"), &e))?;
                let (note, address, memo) = decrypted.ok_or_else(|| {
                    TxError::Refused(match scope {
                        Some(_) => format!(
                            "action {index}: the group cannot decrypt its own output, so its \
                             wallet would never find these funds"
                        ),
                        None => format!(
                            "action {index}: the payment cannot be read back with this group's \
                             outgoing viewing key, so the co-signer cannot tell what it sends"
                        ),
                    })
                })?;
                if address != recipient || note.value().inner() != output_value {
                    return Err(TxError::Refused(format!(
                        "action {index}: the encrypted note differs from the one described"
                    )));
                }
                match scope {
                    Some(Scope::Internal) => {
                        add(&mut change, output_value)?;
                        lines.push(format!("change {} back to this group", zec(output_value)));
                    }
                    Some(Scope::External) => {
                        add(&mut change, output_value)?;
                        lines.push(format!(
                            "send {} to this group's own address",
                            zec(output_value)
                        ));
                    }
                    None => {
                        add(&mut paid, output_value)?;
                        let address = payment_address(
                            index,
                            output.user_address().as_deref(),
                            &recipient,
                            network,
                        )?;
                        lines.push(format!("PAY {} to {address}", zec(output_value)));
                        lines.push(format!("    {}", describe_memo(&memo)));
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
    // The signed balance of the bundle is what actually leaves it. With no
    // other part in the transaction, all of it is the fee.
    if value_balance != Some(fee as i64) {
        return Err(format!(
            "the bundle's signed value balance ({value_balance:?}) is not the fee shown ({fee})"
        )
        .into());
    }
    lines.push(format!("fee {}", zec(fee)));
    // ZIP 317 charges per action, so a coordinator could pad the transaction
    // with zero-value actions and make a raised fee look like the honest fee
    // of a bigger transaction. The builder pads a bundle to two actions and no
    // further: more than that, beyond the notes spent and paid, is refused,
    // and so is a fee above ZIP 317's rate for the actions that remain. This
    // does not catch a coordinator that spends more notes than needed or
    // splits the change: the co-signer does not know which notes a payment
    // should spend.
    let needed = valued_spends.max(valued_outputs).max(GRACE_ACTIONS);
    if actions > needed {
        return Err(format!(
            "the transaction has {actions} actions where its payments need {needed}: the \
             extra ones move no value"
        )
        .into());
    }
    let max_fee = MAX_MARGINAL_FEE * needed as u64;
    if fee > max_fee {
        return Err(format!(
            "the fee ({}) is more than ZIP 317 asks for {needed} actions ({})",
            zec(fee),
            zec(max_fee)
        )
        .into());
    }
    if fee > HIGH_FEE {
        warnings.push(format!("high fee: {}", zec(fee)));
    }
    if spent == 0 {
        return Err("the transaction spends nothing from this group".into());
    }
    Ok(Report { lines, warnings })
}

/// Text from a transaction or from another device, made safe to show:
/// control characters, and characters that reorder or hide text, are escaped
/// (`\n`, `\u{202e}`), so the text cannot draw fake lines or rewrite the ones
/// around it. Everything else stays as it is, accents and quotes included.
pub fn printable(text: &str) -> String {
    let mut shown = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || reorders_or_hides(c) {
            shown.extend(c.escape_default());
        } else {
            shown.push(c);
        }
    }
    shown
}

/// Invisible format characters: soft hyphen, direction marks, embeddings,
/// overrides and isolates, zero-width characters, the byte order mark,
/// interlinear annotations and tags.
fn reorders_or_hides(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

/// The memo as ZIP 302 defines it, made safe to show with [`printable`].
pub fn describe_memo(memo: &[u8; 512]) -> String {
    match memo[0] {
        0xF6 if memo[1..].iter().all(|b| *b == 0) => "no memo".into(),
        0x00..=0xF4 => {
            let end = memo.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
            match std::str::from_utf8(&memo[..end]) {
                Ok(text) => format!("memo: \"{}\"", printable(text)),
                Err(_) => "memo: text that is not valid UTF-8".into(),
            }
        }
        kind => format!("memo: binary data (type 0x{kind:02x})"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memos_are_shown_safely() {
        let mut memo = [0u8; 512];
        memo[0] = 0xF6;
        assert_eq!(describe_memo(&memo), "no memo");
        let text = "invoice 42\u{202E}gnp.exe\nPAY 0";
        let mut memo = [0u8; 512];
        memo[..text.len()].copy_from_slice(text.as_bytes());
        let shown = describe_memo(&memo);
        assert!(
            !shown.contains('\u{202E}') && !shown.contains('\n'),
            "{shown}"
        );
        assert!(shown.starts_with("memo: \"invoice 42"));
        assert!(shown.contains("\\u{202e}gnp.exe\\nPAY 0"), "{shown}");
        memo[0] = 0xFF;
        assert_eq!(describe_memo(&memo), "memo: binary data (type 0xff)");
        let mut memo = [0u8; 512];
        memo[..2].copy_from_slice(&[0xC3, 0x28]);
        assert_eq!(describe_memo(&memo), "memo: text that is not valid UTF-8");
    }

    #[test]
    fn printable_text_keeps_quotes_and_accents() {
        assert_eq!(printable("l'été \"ok\" ❤️"), "l'été \"ok\" ❤️");
        assert_eq!(printable("a\tb\r\nc"), "a\\tb\\r\\nc");
        assert_eq!(printable("\u{1b}[2J"), "\\u{1b}[2J");
        assert_eq!(printable("x\u{200b}y\u{2067}z"), "x\\u{200b}y\\u{2067}z");
    }

    #[test]
    fn a_randomizer_must_be_non_zero_and_used_once() {
        let mut seen = BTreeSet::new();
        let alpha = pallas::Scalar::from(5u64);
        assert!(check_randomizer(0, &alpha, &mut seen).is_ok());
        assert!(matches!(
            check_randomizer(1, &alpha, &mut seen),
            Err(TxError::Refused(reason)) if reason.contains("share a randomizer")
        ));
        assert!(matches!(
            check_randomizer(2, &pallas::Scalar::ZERO, &mut seen),
            Err(TxError::Refused(reason)) if reason.contains("randomizer is zero")
        ));
    }

    #[test]
    fn totals_are_bounded_by_the_supply() {
        let mut total = MAX_MONEY - 1;
        assert!(add(&mut total, 1).is_ok());
        assert!(add(&mut total, 1).is_err());
        assert_eq!(
            total, MAX_MONEY,
            "a refused amount leaves the total unchanged"
        );
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
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::ironwood_v3(),
            Flags::ENABLED,
            Anchor::empty_tree(),
        )
        .unwrap();
        builder
            .add_output(None, recipient, NoteValue::from_raw(10_000), [0; 512])
            .unwrap();
        let (bundle, _) = builder
            .build_for_pczt(rand10::rand_core::UnwrapErr(rand10::rngs::SysRng))
            .unwrap();

        let refused: Vec<_> = bundle
            .actions()
            .iter()
            .enumerate()
            .filter(|(_, action)| action.spend().dummy_sk().is_some())
            .map(|(index, action)| {
                check_spend_structure(
                    index,
                    action.spend(),
                    bundle.anchor(),
                    *bundle.anchor_deferred(),
                )
            })
            .collect();
        assert!(
            !refused.is_empty(),
            "the builder left no dummy key to test with"
        );
        for result in refused {
            assert!(
                matches!(result, Err(TxError::Refused(reason)) if reason.contains("dummy spending key"))
            );
        }
    }

    /// A real spend whose witness leads to the anchor passes; the same spend
    /// checked against another anchor is refused.
    #[test]
    fn a_witness_must_lead_to_the_anchor() {
        use orchard::NoteVersion;
        use orchard::builder::{Builder, BundleType};
        use orchard::bundle::{BundleVersion, Flags};
        use orchard::keys::SpendingKey;
        use orchard::note::{RandomSeed, Rho};
        use orchard::tree::{MerkleHashOrchard, MerklePath};
        use orchard::value::NoteValue;

        let sk = SpendingKey::from_bytes([7; 32]).unwrap();
        let fvk = FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, Scope::External);
        let rho = Rho::from_bytes(&[1; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2; 32], &rho).unwrap();
        let note = Note::from_parts(
            recipient,
            NoteValue::from_raw(50_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let path =
            MerklePath::from_parts(5, [MerkleHashOrchard::from_bytes(&[0; 32]).unwrap(); 32]);
        let anchor = path.root(ExtractedNoteCommitment::from(note.commitment()));

        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::ironwood_v3(),
            Flags::ENABLED,
            anchor,
        )
        .unwrap();
        builder.add_spend(fvk, note, path).unwrap();
        builder
            .add_output(None, recipient, NoteValue::from_raw(40_000), [0; 512])
            .unwrap();
        let (bundle, _) = builder
            .build_for_pczt(rand10::rand_core::UnwrapErr(rand10::rngs::SysRng))
            .unwrap();
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
        let pczt =
            crate::pczt_io::parse(include_bytes!("../tests/fixtures/ironwood_v6.pczt")).unwrap();
        assert_eq!(*pczt.global().tx_version(), V6_TX_VERSION);
        Signer::new(pczt.clone())
            .sign_ironwood_with(|_, bundle, _| -> Result<(), TxError> {
                for (index, action) in bundle.actions().iter().enumerate() {
                    check_spend_structure(
                        index,
                        action.spend(),
                        bundle.anchor(),
                        *bundle.anchor_deferred(),
                    )?;
                }
                Ok(())
            })
            .unwrap();
        let expiry = *pczt.global().expiry_height();
        assert!(
            pre_authorization(expiry, NetworkType::Test, now())
                .unwrap()
                .contains(&format!("until block {expiry}"))
        );
        assert!(pre_authorization(0, NetworkType::Test, now()).is_err());
    }

    /// An honest expiry, minutes ahead of the current height, passes; one far
    /// beyond what the clock allows is refused, on either network. A slow clock
    /// refuses rather than accepts.
    #[test]
    fn the_expiry_is_bounded_by_the_clock() {
        for (network, height, time, fastest) in CHECKPOINTS {
            let height = u64::from(height);
            let at = |blocks: u64| u32::try_from(height + blocks).unwrap();
            // At the checkpoint, the wallet's default expiry (120 blocks ahead).
            assert!(pre_authorization(at(120), network, time).is_ok());
            // A day later, at the target pace, the chain is 3,456 blocks further.
            let day = time + 86_400;
            assert!(pre_authorization(at(3_456 + 120), network, day).is_ok());
            // At the fastest pace counted for this network: still accepted.
            assert!(pre_authorization(at(86_400 / fastest + 120), network, day).is_ok());
            for far in [at(86_400 / fastest + EXPIRY_MARGIN_BLOCKS + 1), 499_999_999] {
                let refused = pre_authorization(far, network, day).unwrap_err();
                assert!(
                    matches!(&refused, TxError::Refused(reason) if reason.contains("far beyond")),
                    "{refused:?}"
                );
            }
            // A clock set before the checkpoint counts no time since it.
            assert!(pre_authorization(at(3_456 + 120), network, 0).is_err());
            // An expiry already behind the estimate is not refused: it cannot
            // be mined, so it authorizes nothing.
            assert!(pre_authorization(at(0) - 10, network, day).is_ok());
        }
    }

    /// Mainnet keeps to the target spacing, so the warning says roughly when the
    /// expiry falls; testnet does not, so it gives the height alone.
    #[test]
    fn the_expiry_is_dated_on_mainnet_only() {
        let (_, main, main_time, _) = CHECKPOINTS[0];
        let shown = pre_authorization(main + 120, NetworkType::Main, main_time).unwrap();
        assert!(shown.ends_with("about 50 min from now"), "{shown}");
        let past = pre_authorization(main - 10, NetworkType::Main, main_time).unwrap();
        assert!(
            past.ends_with("already passed by this computer's clock"),
            "{past}"
        );
        let (_, test, test_time, _) = CHECKPOINTS[1];
        let shown = pre_authorization(test + 120, NetworkType::Test, test_time).unwrap();
        assert!(
            shown.ends_with(&format!("until block {}", test + 120)),
            "{shown}"
        );
        // Regtest has no checkpoint: only "never expires" is refused there.
        assert!(pre_authorization(499_999_999, NetworkType::Regtest, now()).is_ok());
    }

    #[test]
    fn durations_are_rounded_for_reading() {
        assert_eq!(duration(3_000), "50 min");
        assert_eq!(duration(3_001), "51 min");
        assert_eq!(duration(7_200), "2 h");
        assert_eq!(duration(86_400 * 3), "3 days");
    }
}
