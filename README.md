# frost-zec

A small prototype of FROST 2-of-3 threshold signing for shielded ZEC in the
Ironwood pool. Three participants create a RedPallas key together with
distributed key generation (no trusted dealer), and any two of them can
authorize a spend. Nobody ever holds the full spend authorizing key.

The protocol code is a Rust library, `frost_zec`, with no dependency on any
wallet. The `frost-zec` command-line tool below is built on it. Contributions
are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).

The QR protocol between a user's devices is specified in
[docs/spec.md](docs/spec.md) (draft v0.1). OpenPGP Wallet's FROST tab uses it
as the coordinator, with this tool as the test co-signer, and
[docs/guide.md](docs/guide.md) walks through a complete spend.

> **Prototype.** The key shares and `sk` are stored unencrypted in `data/` to
> keep the code easy to read. Only use it with amounts you can afford to lose.

## How it works

1. **Key generation** (`src/dkg.rs`): the three-step FROST DKG from the Zcash
   Foundation's `reddsa` (FROST(Pallas, BLAKE2b-512)), threshold 2. The group
   key is made even-y, as Orchard requires for `ak`.
2. **Viewing keys** (`src/keys.rs`): derived the way ZIP 2005 specifies for
   FROST (`use_qsk = true`). The participants combine random contributions
   into `sk`, then:
   `nk = ToBase(PRF^expand_sk([0x07]))`,
   `qsk = truncate_32(PRF^expand_sk([0x0C]))`,
   `qk = BLAKE3.derive_key("Zcash ZIP 2005 qk-derivation v1", qsk)`,
   `rivk = ToScalar(PRF^expand_qk([0x0D] || ak || nk))`.
   Notes received by these keys keep the quantum recovery path of ZIP 2005,
   as long as `qsk` is kept. (zcash-sign, by design for now, builds its
   viewing key with a constructor that gives that path up.) There are no
   official `use_qsk` test vectors yet. The derivation matches the eight
   independent vectors proposed by the Zafe team (frost-tools#610), and the
   shared primitives are also tested against the official Orchard vectors and
   against orchard's own derivation.
3. **Signing** (`src/signing.rs`): re-randomized FROST (ZIP 312). Each spend
   in the PCZT carries its randomizer alpha; two signers produce shares over
   the v6 sighash, and the aggregated signature is checked with orchard's
   RedPallas code under `rk = ak + [alpha]G` before it is inserted.
4. **Two devices** (`coordinate` and `cosign`): the co-signer commits to fresh
   nonces first, then receives the proven PCZT and checks it on its own
   (`src/check.rs`). It does not trust the amounts and addresses written in
   the PCZT: for every action it recomputes the value commitment, the spent
   note's nullifier, the randomized key and the output note commitment
   (orchard's PCZT verifiers), then lists payments, change and fee. It signs
   the sighash it computed itself, so a lying coordinator cannot get a
   signature for a different transaction. It refuses a PCZT that still holds
   a dummy spending key (ZIP 374), or a witness that does not lead to the
   anchor. And since a v6 signature does not commit to the anchor, it warns
   that signing does not prove the spent notes exist: the signature
   authorizes these exact payments until the expiry height, and a
   transaction that never expires is refused.

[zcash-devtool](https://github.com/zcash/zcash-devtool) does the wallet side:
it watches the group's viewing key, builds and proves the PCZT, and
broadcasts it once signed. The sighash and signature insertion follow
[zcash-sign](https://github.com/ZcashFoundation/frost-tools) (Ironwood
support by aryaethn, frost-tools#593), whose testnet fixture is used here to
check that the sighash matches a transaction already signed and mined.

## Usage

```bash
cargo run -- selftest                    # offline: DKG, every pair signs, a single share cannot
cargo run -- keygen --network main       # create the group, print the viewing key and address
cargo run -- info
cargo run -- inspect --pczt proven.pczt  # what a PCZT does, checked as the co-signer would, without signing

# wallet side, with zcash-devtool
zcash-devtool wallet -w wallet init-fvk --name frost-group --fvk <viewing key>
zcash-devtool wallet -w wallet sync
zcash-devtool pczt -w wallet create --address <recipient> --value <zatoshis> --output tx.pczt
zcash-devtool pczt -w wallet prove tx.pczt --output proven.pczt

cargo run -- sign --pczt proven.pczt --out signed.pczt --signers 1,3
zcash-devtool pczt -w wallet send signed.pczt
```

Two devices, in two terminals (files in `session/` stand in for the encrypted
QR codes of the real app):

```bash
cargo run -- cosign --as 2     # sends its commitments, then shows what it is about to sign and asks for approval
cargo run -- coordinate --as 1 --pczt proven.pczt --out signed.pczt
```

Both devices run the same PCZT checks: the coordinator does not trust
whatever built the transaction either. The co-signer opens the session with
its nonce commitments, before it sees the transaction. The PCZT is removed
from the session directory once read, and the other files when the session
ends. `cosign --yes` skips the human approval and exists only for automated
tests.

## The QR protocol (spec draft v1.0, in progress)

[`docs/spec.md`](docs/spec.md) specifies how two devices of one user share a
FROST 2-of-3 account: pairing with a six-digit code, key generation, the
signing session and the co-signer's checks, with test vectors. The library
implements it (`channel`, `wire`, `setup`, `cosigning`), and the `qr`
commands play either side, so the protocol can be tried without the app:

```bash
# Coordinator and co-signer, in two terminals (or on two machines)
cargo run -- qr setup --as coordinator --network test --state coord --via exchange
cargo run -- qr setup --as cosigner    --network test --state cosign --via exchange

# A signing session: the coordinator sends the request, the co-signer shows
# the payment, asks for approval and answers once
cargo run -- qr sign --as cosigner    --state cosign --via exchange
cargo run -- qr sign --as coordinator --state coord --via exchange --pczt tx.pczt --out signed.pczt
```

With `--via qr`, each message is shown as an animated QR code in the
terminal until Enter, then the answer is read with the webcam (build with
`--features camera`); one camera shared by both sides is enough. With
`--via clipboard`, for a wallet on the same computer, each message goes to the
clipboard and the answer is taken from it once copied. With `--via DIR`, each
message is a `ur:zcash-frost/...` text file in DIR, to carry between machines.
OpenPGP Wallet's FROST tab is the reference coordinator, and this tool is the
test co-signer.

The tests include a tamper suite ([tests/tamper.rs](tests/tamper.rs)) of
PCZTs a dishonest coordinator could send, each refused or shown exactly as it
will be signed, and mutation fuzzing of every decoder
([tests/fuzz.rs](tests/fuzz.rs)); CI runs both.

### Shared tamper cases

[vectors/tamper/](vectors/tamper/) holds tamper cases any co-signer can run:
each is a refused PCZT, its accepted twin and what the user approved, with the
refusal classes a signer may answer with ([classes.md](vectors/tamper/classes.md),
format in spec § 8.2). The set is shared with other FROST signers for shielded
ZEC (#7); new cases go to the listed maintainers privately first.
[tests/tamper_vectors.rs](tests/tamper_vectors.rs) is this crate's runner.

## One vault, two implementations

`interop dkg` creates a vault together with members running other software,
in Zafe's key profile (identifiers derived from an identity key, `sk` agreed
by commitment and reveal), and `--vault DIR` signs with that seat:

```bash
cargo run -- interop dkg --network main --vault-id <16 bytes hex> --dir exchange --out vault
cargo run -- coordinate --vault vault --dir session --pczt proven.pczt --out signed.pczt
cargo run -- cosign --vault vault --dir session
```

The messages are JSON files, described in [docs/interop.md](docs/interop.md).
A local harness running zafe-core's own key generation, signing and
verification code first checked that both sides end up with the same vault
and sign the same transaction. Then, on 2026-11-09, a 2-of-2 vault shared with
a real Zafe member spent on Mainnet in both directions (transactions in
[docs/interop.md](docs/interop.md)).

## Member backups

`backup export` prints one member's backup string: the draft common format of
[docs/backup-format.md](docs/backup-format.md), whose version 1 is Zkool's
`zkfrost` string: a string made here passes Zkool's own decoder and derivation
check, and Zkool's encoder gives the same strings as this one.
`backup restore` rebuilds the member from the string and the group's viewing
key, and tells whether the group follows ZIP 2005 or Zkool's older derivation:

```bash
cargo run -- backup export --as 2 > member-2.txt   # secret: it holds the share and sk
cargo run -- backup restore --in string.txt --ufvk <viewing key> --save
```

[src/backup.rs](src/backup.rs) is written from the draft's rules, apart from
Zkool's code. Both pass the same test vectors
([tests/fixtures/frost-member-backup-vectors.json](tests/fixtures/frost-member-backup-vectors.json)),
which [tools/zip-vectors](tools/zip-vectors) generates and checks against
Zkool's own decoder and derivation matcher, copied unchanged.

## Testnet and NU7

Public testnet activated NU7 at height 4,465,026 (Zebra 7.0.0-rc.0) before
any released wallet tooling supported it, so the first spends were made on
mainnet with small amounts. Mainnet activates NU7 at height 3,543,405 (around
November 5, 2026). frost-zec uses the library releases of 2026-10-21, which
know both heights. The PCZT encoding did not change, and the signatures of the
three spends below verify under the sighash the current code computes.

zcash-devtool's main branch still pins a librustzcash revision without the
mainnet height. After activation, build it against the 2026-10-21 releases
(a handful of small API changes in its inspection and migration commands).

## Transactions on mainnet

Three spends from the same FROST group, one for each pair of participants,
all mined on 2026-10-15. On chain, each one is an ordinary shielded Ironwood
transaction with one spend authorization signature:

- participants 1 and 3, one process, paying 0.0002 ZEC to an outside address
  with change back to the group:
  [1baaefbf…c084](https://mainnet.zcashexplorer.app/transactions/1baaefbff168c0128d8742f5a5b61c7ad52bffaf65b9ee01294624093bd4c084)
  (block 3,518,638)
- participants 1 and 2, two devices, the co-signer verifying the PCZT on its
  own before signing:
  [28118dd2…b4ec](https://mainnet.zcashexplorer.app/transactions/28118dd2671c5388fe09a6f02dfd0b38046e5482d1c0debddb666638e4d6b4ec)
  (block 3,518,645)
- participants 2 and 3, two devices, sending the rest to an outside address:
  [c3c83adc…8a52](https://mainnet.zcashexplorer.app/transactions/c3c83adc604b213f5b5c376cd44e7cb2a7be782d01704bf6925b0d3664bb8a52)
  (block 3,518,648)

A spend from OpenPGP Wallet's FROST tab, with this tool as the co-signer
over the QR protocol's messages, mined on 2026-11-10:
[0f36cd28…3f9](https://mainnet.zcashexplorer.app/transactions/0f36cd2867d0e32108cc660cdaee8c999503b8bc82a0a4d9545683585c8f83f9)
(block 3,558,933).

## Next steps

- A standalone crate on crates.io.
- The backup's two profiles (a passphrase-encrypted file and a mnemonic), and
  a recovery flow that sweeps the funds to a new FROST account.
- Specification v1.0, revised after review: in progress (two-message signing,
  the setup acknowledgement and the shared tamper cases are in).
- The member backup format as a ZIP, co-owned with aryaethn
  ([zcash/zips#1432](https://github.com/zcash/zips/pull/1432)).
- Keep `qsk` split 2-of-3 across the devices instead of keeping `sk`, so that
  no single device can spend through the future recovery protocol.

## License

MIT
