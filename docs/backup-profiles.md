# Keeping a member backup: two profiles, and the formats they compare to

Draft for Milestone 2 of ZCG grant #490. Not implemented yet: the choices
below are proposals.

A member backup string ([backup-format.md](backup-format.md),
[zcash/zips#1432](https://github.com/zcash/zips/pull/1432)) holds a member's
signing share and `sk` in clear. The string is the common format; a profile is
how a user keeps it. OpenPGP Wallet will offer two, and frost-zec will
implement both, so another wallet can read what this one writes.

## Profile 1: a passphrase-encrypted file

For users who keep files: on a USB stick, in a password manager, in a cloud
folder they do not fully trust. There is no recovery phrase to write down.

**Construction.** The same as Zafe's vault backups, so that one construction
serves both wallets and one review covers both:

```text
magic "ZKFROSTB" (8) | version u8 = 1 | m_cost_kib u32 | t_cost u32 | p_cost u32
| salt (16) | nonce (24) | XChaCha20-Poly1305 ciphertext of the contents
```

All integers are little-endian. The key is Argon2id(passphrase, salt) with the
header's parameters, 64 MiB, 3 passes and 1 lane by default. The whole header
is the associated data, so a changed parameter or salt fails decryption. A
reader refuses parameters below the defaults, so that a forged file cannot
pass for a strong one, and above 1 GiB or 16 passes, so that it cannot exhaust
the device. A text form, `zkfrost-file-1:` followed by the bytes in base64url,
carries the same file for password managers.

**Contents**, a CBOR map:

| Key | Field | Notes |
|---|---|---|
| 1 | member backup string | required |
| 2 | the group's unified full viewing key | so that a restore needs nothing from another device |
| 3 | birthday height | where to start scanning |
| 4 | label | the account's name in the wallet |

Never nonces, and never pairing keys: a restored member pairs anew.

**Passphrase.** At least 12 words, or one a strength estimator rates
"very strong"; the wallet offers a generated passphrase of 12 random words.

## Profile 2: a mnemonic

For users who want paper. The 68-byte payload of the string becomes 51 words of
the BIP-39 English list: 544 bits, plus a 17-bit checksum computed as BIP-39
does for any length that is a multiple of 32 bits. No wallet accepts 51 words
as a seed, so the backup cannot be mistaken for one.

The words carry only the member. Restoring also needs the group's viewing
key, which the payload does not hold: from the co-signer during recovery, or
from a copy printed next to the words. A viewing key is not a spending key,
but it reveals the account's history, so it stays as private as the words.

Open: whether to write the Bech32m string itself instead (about 120
characters, shorter but easier to miscopy), and whether to add the words of a
recovery check, as SLIP-39 and codex32 do, so that a single wrong word can be
located.

## Existing formats

| | Zkool | Zafe | frost-client (ZF) | This work |
|---|---|---|---|---|
| Kept | id, t, n, share, `sk` | identity seeds, key package, `sk`, vault descriptor, log key, invite, signer names | communication key pair, key package, public key package, participants, server | id, t, n, share, `sk`; profile 1 adds the viewing key and birthday |
| Encoding | Bech32m string, `zkfrost` | binary file, or `zafe-backup-v1:` and base64url | TOML (`credentials.toml`) | the ZIP's Bech32m string, inside both profiles |
| At rest | in clear; protecting it is up to the user | Argon2id and XChaCha20-Poly1305 | in clear | profile 1 encrypted as Zafe does; profile 2 on paper |
| Nonces | none | never | not applicable | never |
| `sk` for ZIP 2005 | yes, both derivations told apart by the viewing key | yes | no: frost-client is generic, and zcash-sign builds the viewing key without `qsk` | yes, both derivations |
| Read by another app | yes: the ZIP's version 1 is this string | Zafe only | frost-client only | any app implementing the ZIP |

Sources: Zkool's backup code (`backup_core.rs`, vendored unchanged in
`tools/zip-vectors/vendor/zkool`), Zafe's
`crates/zafe-core/src/backup.rs` (zafe-cash/zafe at df28b77), and frost-tools'
`frost-client/src/cli/config.rs`.

What this work keeps from each: Zkool's string as the common payload, which
already exists in a shipped wallet; Zafe's encryption, which is sound and
already written; and frost-client's lesson that a generic FROST tool cannot
keep what ZIP 2005 needs, so the format must carry `sk` itself.
