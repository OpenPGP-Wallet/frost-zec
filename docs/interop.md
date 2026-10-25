# One vault, two implementations: the interop format (v0)

Status: test format, used for an interop test with [Zafe](https://github.com/zafe-cash/zafe). Not a
proposal for a standard, and not meant for real funds beyond small test amounts.

The goal is a FROST vault for shielded ZEC whose members run different software: they create the
keys together, then any `t` of them sign a spend, each one checking the transaction with its own
code. This file describes what the two sides exchange. Everything travels as small JSON files, so
two people can run a test by passing files to each other.

## What both sides must share

- **FROST**: FROST(Pallas, BLAKE2b-512) from `reddsa` 0.5.2 (`frost-core` 3.0.0), re-randomized as
  ZIP 312 describes, with the randomizer `α` taken from the PCZT (the transaction builder chooses
  it).
- **Keys**: ZIP 2005 with `use_qsk = true`. `ak` is the FROST group key (even y), and `nk`, `qsk`,
  `qk` and `rivk` are derived from a value `sk` the members agree on. Both sides already match the
  eight independent `use_qsk` vectors from frost-tools#610.
- **Transactions**: v6 PCZTs (`pczt` crate encoding) spending Ironwood notes only.

## Encoding

Binary values are lowercase hex. FROST values use the `frost-core` 3 serialization: identifiers
(32 bytes), DKG round 1 and round 2 packages, signing commitments and signature shares. Every
message carries `"format": "frost-zec-interop-v0"` and a `kind`, and a reader refuses a format or
kind it does not expect.

## Key generation (Zafe's key profile)

The members first agree, out of band, on the network (`main` or `test`), a 16-byte `vault_id`
chosen by one of them, the threshold `t` and the number of members `n`. Key generation is the
three-part FROST DKG, plus the agreement on `sk` that Zafe uses (Zafe `spec.md` § 7.4). Every hash
below is BLAKE2b-256 with the given 16-byte personalization, and integers are little-endian.

**Identifier.** Each member has a 32-byte identity key (Zafe: the member's Ed25519 key; frost-zec,
which has no messaging layer, uses 32 random bytes). Its FROST identifier is
`Identifier::derive("Zafe member identifier v1" || vault_id || identity)`.

**Round 1**, sent to every other member as `round1.<id8>.json`, where `<id8>` is the first 4 bytes
of the identifier in hex:

| Field | Content |
|---|---|
| `kind` | `dkg-round1` |
| `network`, `vault_id`, `min_signers`, `max_signers` | the agreed parameters |
| `identity`, `identifier` | the member's identity key and identifier |
| `package` | the DKG round 1 package |
| `sk_commitment` | `H("Zafe_SkCommit___", vault_id ‖ identity ‖ r)`, where `r` is the member's 32 random bytes |

The receiver refuses the message if the parameters differ from its own, or if the identifier does
not follow from the identity key.

**Round 2**, one file per recipient, `round2.<from8>-to-<to8>.json`:

| Field | Content |
|---|---|
| `kind` | `dkg-round2` |
| `vault_id`, `from`, `to` | the vault and both identifiers |
| `package` | the DKG round 2 package for this recipient |
| `echo` | the sender's view of round 1 (below) |
| `sk_contribution` | `r` |

`echo` binds every round 1 message the sender received. With `P = vault_id ‖ t ‖ n` followed, for
each member in identifier order, by `len(id) ‖ id ‖ len(package) ‖ package` (lengths as `u32`):

    round1_echo = H("Zafe_DKG_R1Echo_", P)
    echo        = H("Zafe_DKG_EchoSk_", round1_echo ‖ for each member in identifier order: len(id) ‖ id ‖ sk_commitment)

The receiver aborts unless `echo` equals its own value and `sk_contribution` matches the sender's
commitment. Round 2 files hold secrets: each one goes only to its recipient, over an end-to-end
encrypted channel.

**Result.** After DKG part 3, each member computes

    transcript = H("Zafe_DKG_Transcr", P ‖ ak)
    sk         = H("Zafe_VaultSecret", vault_id ‖ transcript ‖ r_1 ‖ … ‖ r_n)   (contributions in identifier order)

then the ZIP 2005 keys, the unified full viewing key (Orchard item only) and the first external
address. The members compare the address out of band before anyone funds it.

## Signing session (two signers)

One member coordinates: it gets the PCZT (built and proven by a wallet such as `zcash-devtool`, or
built by its own app) and broadcasts the result. The other member co-signs. Three messages, in this
order:

1. **`commitments.json`** (co-signer → coordinator), `kind: sign-commitments`: a random `session`
   id, the co-signer's `identifier`, and `commitments`, a list of fresh signing commitments (one per
   spend it is ready to sign; frost-zec offers 4). The co-signer sends them before it sees the
   transaction.
2. **`request.json`** (coordinator → co-signer), `kind: sign-request`: the same `session`, the
   coordinator's `identifier`, the PCZT in hex (`pczt`), and the coordinator's own `commitments`.
   Spend `i` uses commitment `i` on both sides, where spends are the Ironwood actions still waiting
   for a spend authorization signature, in bundle order.
3. **`reply.json`** (co-signer → coordinator), `kind: sign-reply`: the `session`, the co-signer's
   `identifier`, and either `shares` (one signature share per spend, same order) or `refused`
   (the reason).

The co-signer never takes the coordinator's word for anything. It parses the PCZT, checks it with
its own code (frost-zec: value commitments, nullifiers, `rk`, note commitments and fee; Zafe:
`verify_pczt`, which also matches every payment against what the member expects), computes the v6
sighash itself, reads each `α` from the PCZT, and signs only that. The coordinator aggregates both
shares per spend, and the signature is checked against the spend's `rk` when it is inserted into
the PCZT.

The request contains the PCZT, and with it every `α`: anyone who knows `α` and `ak` can link the
transaction to the vault. It must travel only between members, end-to-end encrypted, and each side
deletes it once used.

## What this format leaves out

Zafe wraps its messages in signed, HPKE-encrypted envelopes sent through its relay, has the members
compare safety words before key generation and sign a vault descriptor, and signs in one tap with
commitments published in advance. None of that is here: this format only carries the cryptographic
values, for a test between two people who already trust their channel.

## Tested so far

A local harness compiles zafe-core's own `keygen.rs`, `keys.rs`, `signing.rs`, `tx.rs` and
`verify.rs` (zafe-cash/zafe at df28b77, with Zafe's pinned versions) and plays a Zafe member against
frost-zec:

- a joint 2-of-2 key generation gives both sides the same `ak`, `sk`, viewing key and address;
- with frost-zec coordinating and the Zafe code co-signing, and the other way round, both sides
  compute the same sighash and the aggregated signature verifies under `rk`;
- zafe-core's `verify_pczt` accepts the PCZTs that `zcash-devtool` built for the mainnet spends of
  2026-10-15, and refuses them with a wrong amount, a wrong consensus branch or another vault's key.

The PCZT used for the signing test spends an invented note, so it was never broadcast. A spend on
chain from a vault shared with a real Zafe member is the next step.
