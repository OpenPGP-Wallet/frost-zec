# frost-zec

A small prototype of FROST 2-of-3 threshold signing for shielded ZEC in the
Ironwood pool. Three participants create a RedPallas key together with
distributed key generation (no trusted dealer), and any two of them can
authorize a spend. Nobody ever holds the full spend authorizing key.

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
   signature for a different transaction.

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
cargo run -- coordinate --as 1 --cosigner 2 --pczt proven.pczt --out signed.pczt
cargo run -- cosign --as 2     # shows what it is about to sign and asks for approval
```

## Testnet and NU7

Public testnet activated NU7 at height 4,465,026 (Zebra 7.0.0-rc.0), and the
released wallet tooling does not support it yet, so the first spends were
made on mainnet with small amounts. Mainnet is expected to activate NU7 in
November 2026.

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

## Next steps

- Keep `qsk` split 2-of-3 across the devices instead of keeping `sk`, so that
  no single device can spend through the future recovery protocol.
- Encrypted QR codes instead of files.
- Interoperability with other FROST wallets (common message and backup format).

## License

MIT
