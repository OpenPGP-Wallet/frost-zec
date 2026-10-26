# FROST member backup for shielded Zcash: a common format (draft)

Status: discussion draft, being written up as a ZIP with aryaethn
([zcash/zips#1413](https://github.com/zcash/zips/issues/1413)). Comments welcome.

## Why

Every FROST wallet for shielded ZEC has its own member backup: Zkool has the `zkfrost` string
([zkool2#1337](https://github.com/hhanh00/zkool2/pull/1337), shipped in Zkool 6.35.0), Zafe an
encrypted file, Konclave a share export. A member can't restore their seat in another app. The goal is a small common format that
any app can read, with room for app-specific data.

## What a member backup holds

Exactly what is needed to rebuild one member, nothing else:

| Field | Size | Notes |
|---|---|---|
| participant identifier | see below | the member's FROST identifier |
| `t`, `n` | 1 byte each | threshold and group size |
| signing share | 32 bytes | the member's share of `ask` |
| `sk` | 32 bytes | the group's shared Orchard spending key; `nk` and `rivk` are derived from it, the legacy way or under ZIP 2005 (`use_qsk = true`, which also gives `qsk` and `qk`, and uses `ak` for `rivk`) |

`ak` is not stored: it comes from the group's UFVK, which the restore asks for. The format does not
care how `sk` was agreed (mailbox addresses in Zkool, COCKTAIL-DKG elsewhere), only what is kept.

Version 1 doesn't say which derivation the group uses. Zkool writes the same string for its legacy
groups and for its ZIP 2005 ones, and the restore tells them apart by checking both against the UFVK.
For a legacy group the string is a device-loss backup only: the notes are not quantum recoverable.

## Encoding

A bech32m string with the human-readable part `zkfrost` (no 90-character limit, as in ZIP 316)
whose payload starts with a version byte.
Version 1 is byte-for-byte Zkool's 68-byte `zkfrost` payload (version, id, t, n, share, sk), so
existing Zkool backups stay valid.

## Restore

Inputs: the string and the group's UFVK. Recompute `nk` and `rivk` from `sk` and `ak` under each
known derivation (legacy and ZIP 2005): the one that matches the UFVK is the group's. If none
matches, refuse the string (it belongs to another group). Then rebuild the key package from the
identifier, the share, `t` and `ak`.

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

- **Identifier encoding.** Zkool uses a 1-byte identifier (1 to n). Zafe derives a full 32-byte
  scalar from the vault id and the member's identity key:
  `Identifier::derive("Zafe member identifier v1" || vault_id || identity_pk)`. A common format needs
  both, for example a type byte followed by a short or a full identifier.
- **Share sign.** Orchard requires `ak` with an even y-coordinate, so some implementations negate the
  shares after the DKG. The format should state that the stored share is the one matching the final
  `ak`, or another app would rebuild a wrong share.
- **Birthday height.** By default, Zkool restores with a birthday at Orchard activation (block
  1,687,104 on mainnet), which means scanning millions of blocks. An optional 4-byte birthday height
  would make a restore much faster. Even without it, a group whose keys follow ZIP 2005 (Zkool's
  dkg-2, from zkool2#1337) was created after NU6.3, so its restore can start at Ironwood activation
  (block 3,428,143 on mainnet), about 1.7 million blocks later.
- **Derivation profile.** Version 1 doesn't record the derivation: a restore finds it by trying each
  known one against the UFVK, which works only while there are few of them and the UFVK is at hand.
  The group descriptor should record it as an explicit identifier instead (Zafe already keeps
  `use_qsk` in its vault descriptor), so the same envelope stays valid if another derivation scheme
  appears later (raised by benjoshyo on the forum thread). This is separate from how `sk` is agreed,
  which the format still leaves open.
- **Test vectors** for each later version (version 1: see below).

## Implementations and test vectors

Version 1 is implemented by Zkool (`rust/src/frost/backup.rs`, released in
6.35.0) and by frost-zec ([src/backup.rs](../src/backup.rs), commands
`backup export` and `backup restore`), written separately.
[tests/fixtures/frost-member-backup-vectors.json](../tests/fixtures/frost-member-backup-vectors.json)
covers a ZIP 2005 group, a legacy group with the ZIP 2005 key Zkool's upgrade
builds from the same `sk` and `ak`, a 3-of-5 group, an uppercase string, 13
strings to reject and a string checked against another group's key.
[tools/zip-vectors](../tools/zip-vectors) generates it, checks it against
Zkool's own decoder and derivation matcher, and checks that every t-subset of
members restored from their strings signs under `ak`.

## Out of scope

How `sk` is agreed, the DKG, and the signing transport. One note on transport: Zkool's memo
transport had to split its signing package into one memo per signer, because a single 512-byte memo
stopped fitting at t = 4 (zkool2#1339, fixed by #1342); its round-1 DKG message still caps t at 13.
Signing messages should stay independent of the transport (QR codes or files have no such limit).

Related: zkool2#1338 (open) proposes to reduce a Zkool member's stored state to the `zkfrost` payload
plus `ak`, the DKG version and a mailbox seed, which matches the content above.
