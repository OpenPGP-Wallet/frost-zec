# FROST member backup for shielded Zcash: a common format (draft)

Status: discussion draft, not a ZIP. Comments welcome.

## Why

Every FROST wallet for shielded ZEC has its own member backup: Zkool has the `zkfrost` string
([zkool2#1337](https://github.com/hhanh00/zkool2/pull/1337)), Zafe an encrypted file, Konclave an
export blob. A member can't restore their seat in another app. The goal is a small common format that
any app can read, with room for app-specific data.

## What a member backup holds

Exactly what is needed to rebuild one member, nothing else:

| Field | Size | Notes |
|---|---|---|
| participant identifier | see below | the member's FROST identifier |
| `t`, `n` | 1 byte each | threshold and group size |
| signing share | 32 bytes | the member's share of `ask` |
| `sk` | 32 bytes | the group's ZIP 2005 `sk`; `nk`, `qsk`, `qk` and `rivk` are derived from it (`use_qsk = true`) |

`ak` is not stored: it comes from the group's UFVK, which the restore asks for. The format does not
care how `sk` was agreed (mailbox addresses in Zkool, COCKTAIL-DKG elsewhere), only what is kept.

## Encoding

A bech32m string (no 90-character limit, as in ZIP 316) whose payload starts with a version byte.
Version 1 is byte-for-byte Zkool's 68-byte `zkfrost` payload (version, id, t, n, share, sk), so
existing Zkool backups stay valid.

## Restore

Inputs: the string and the group's UFVK. Recompute `nk` and `rivk` from `sk` and `ak`, and refuse the
string if they don't match the UFVK (it belongs to another group). Then rebuild the key package from
the identifier, the share, `t` and `ak`.

## Optional profiles

Selected by the version byte, never the baseline:

- **Passphrase.** The payload is encrypted with a memory-hard KDF (e.g. Argon2id) and an AEAD (e.g.
  XChaCha20-Poly1305). Being symmetric, it stays safe after a discrete-log break. A leaked string is
  useless without the passphrase; a forgotten passphrase loses the backup.
- **Shamir share of `sk`.** A t-of-n share of `sk` (byte-wise over GF(256), as in SLIP-39) instead of
  `sk` itself, so one leaked string doesn't give `qsk`. It only helps if `sk` can't be rederived from
  data the devices keep (it can in Zkool), `sk` still exists in full during setup and when the
  recovery proof is made, and it departs from ZIP 2005's "every participant holds `qsk`". The restore
  can no longer check the string against the UFVK by itself.

## Open points

- **Identifier encoding.** Zkool uses a 1-byte identifier (1 to n). Zafe uses
  `Identifier::derive(sigPk || vaultId)`, a full 32-byte scalar. A common format needs both, for
  example a type byte followed by a short or a full identifier.
- **Share sign.** Orchard requires `ak` with an even y-coordinate, so some implementations negate the
  shares after the DKG. The format should state that the stored share is the one matching the final
  `ak`, or another app would rebuild a wrong share.
- **Birthday height.** Zkool restores with a birthday at Orchard activation (block 1,687,104), which
  means scanning millions of blocks. An optional 4-byte birthday height would make a restore much
  faster.
- **Test vectors** for every version, encode and decode.

## Out of scope

How `sk` is agreed, the DKG, and the signing transport. One note on transport: in Zkool's memo
transport a t=3 signing package already takes 507 of the 512 memo bytes and t=4 takes 608, so a 4-of-n
group can't sign (noted in zkool2#1337). Signing messages should stay independent of the transport
(QR codes or files have no such limit).
