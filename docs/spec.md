# FROST co-signing for shielded ZEC: QR protocol, signer checks and backups

Draft v0.1, work in progress. Part of ZCG grant #490, Milestone 1. Not audited:
use small test amounts only.

This document specifies how two devices of one user share a FROST 2-of-3
account for shielded ZEC in the Ironwood pool: how they pair, create the keys,
sign a spend, what the co-signer checks before it signs, and how a member is
backed up. The goal is that a co-signer from one wallet can work with a
coordinator from another. The reference code lives in this crate.

## 1. Roles

| Member | Device | Role |
|---|---|---|
| 1 | Coordinator (the desktop wallet) | Builds PCZTs, aggregates signatures, proves and broadcasts. |
| 2 | Co-signer (a phone, or the test co-signer) | Checks every PCZT on its own before it signs. |
| 3 | Backup | Created by the co-signer during key generation, exported as a member backup string, then wiped. Users who want no such window can run it on a spare device. |

Any two members can sign. FROST identifiers are the integers 1, 2 and 3, so
each member fits a version 1 member backup string (zcash/zips#1432).

Keys follow ZIP 2005 for FROST: `ak` is the FROST group key (even y), and
`nk`, `rivk`, `qsk` and `qk` are derived from a 32-byte `sk` the members agree
on (`use_qsk = true`). Every member holds `sk`.

## 2. Transport

Messages travel as Uniform Resources (Blockchain Commons BCR-2020-005), shown
as animated multi-part QR codes when they are large. This is the format
Keystone (`ur:zcash-pczt`) and `zcash-devtool pczt qr` already use for PCZTs,
so wallets can reuse their QR code. Implemented in `src/wire.rs`.

- UR type: `zcash-frost`.
- Payload: a CBOR array of one or more messages, so one QR stream can carry,
  for instance, a pairing message and the first sealed message.
- Message: a CBOR map `{1: version, 2: kind, 3: body}`, version 0.

Before pairing, messages are in clear (they hold no secret). After pairing,
every message is sealed (§ 3.4) and its body is
`{1: pairing id, 2: inner kind, 3: session, 4: nonce, 5: ciphertext}`.

| Kind | Message | Sent |
|---|---|---|
| 1 | pair-init | in clear |
| 2 | pair-response | in clear |
| 3 | pair-confirm | in clear |
| 16 | sealed envelope | carries one of the kinds below |
| 32 | dkg-round1 | sealed |
| 33 | dkg-round2 | sealed |
| 48 | sign-commitments | sealed |
| 49 | sign-request | sealed |
| 50 | sign-reply | sealed |

A reader refuses a payload over 512 KiB or a stream of more than 1024
fragments, other UR types and unknown versions. It checks the header of each
part before decoding it: the fragment count must be the message length divided
by the fragment length, rounded up, and a stream of n fragments that has not
completed after 2n + 32 different parts is refused. A fountain decoder spends
time and memory in proportion to the fragment count a part announces, so
without these checks one crafted part announcing millions of fragments stalls
it for minutes or exhausts its memory. UR checks that parts belong
together with a CRC-32, which a forger can match; that is enough here, because
a payload assembled from forged parts fails one layer up, on the pairing code
or on a sealed message's authentication tag.

The protocol does not depend on QR codes. The same messages can travel as
files, through a relay, or inside another wallet's own transport: the pairing
code (§ 3.3) protects against a carrier that tampers with them, and sealed
messages are bound to their pairing, direction, kind and session. QR codes are
the reference carrier because they need no server and no network.

## 3. Pairing

Implemented in `src/channel.rs`.

### 3.1 Messages

The initiator is the device that shows the first QR code (the coordinator).

1. **pair-init**, initiator → responder: a fresh X-Wing encapsulation key `ek`
   (1216 bytes) and `commitment = H_Comm(version || r_i)`, where `r_i` is 32
   random bytes.
2. **pair-response**, responder → initiator: `ct`, the X-Wing encapsulation to
   `ek` (1120 bytes), and 32 random bytes `r_r`.
3. **pair-confirm**, initiator → responder: `r_i`. The responder refuses the
   pairing unless `H_Comm(version || r_i)` equals the commitment.

X-Wing is the hybrid of X25519 and ML-KEM-768 (draft-connolly-cfrg-xwing-kem,
version 06). Decapsulation refuses a non-contributory X25519 share, the
behaviour CFRG chose for the standard.

### 3.2 Derived values

With `H_P(x)` = BLAKE2b-256 with the 16-byte personalization `P`:

    T     = H_"ZcashFROSTv0Trns"(version || ek || commitment || ct || r_r)
    code  = LE64(H_"ZcashFROSTv0SAS_"(T || r_i || r_r)[0..8]) mod 10^6
    keys  = BLAKE2b-512 with personalization "ZcashFROSTv0Keys" (version || ss || T)
    k_ir  = keys[0..32]     (initiator → responder)
    k_ri  = keys[32..64]    (responder → initiator)
    id    = T[0..16]

`ss` is the X-Wing shared secret, and `H_Comm` uses `"ZcashFROSTv0Comm"`. All
fields have fixed sizes, so concatenation is unambiguous. The code is shown as
six decimal digits.

### 3.3 Confirming the code

Both devices show the code and the user checks that they match. A device MUST
NOT send anything secret over the pairing before the user confirms the code on
that device. Where untrusted code can draw on the screen, as in a wallet whose
interface is a web page, the confirmation MUST come from a part of the device
that code cannot draw or click (OpenPGP Wallet uses a native window): otherwise
a compromised interface could confirm a pairing with an attacker's co-signer,
who would then hold two members of three. The answer MUST confirm the very
pairing whose code was shown: a device that shows the code of its current
pairing and, once the user answers, confirms whatever pairing is current then,
lets that interface start another pairing while the question is open.

Why the commitment: without it, a man in the middle who controls the last
message could try many values until both devices show the same six digits.
Here, when the attacker chooses what to send the initiator, `r_i` is still
hidden from it, and the responder draws `r_r` only after the attacker
committed to its own value. Each attempt therefore succeeds with probability
10^-6.

Why X-Wing: key generation sends the members' contributions to `sk` over this
channel (§ 4), and `sk` yields `qsk`, which ZIP 2005 asks to protect like
`ask`. With X25519 alone, recorded QR codes would give `sk` to a future
quantum computer.

### 3.4 Sealed messages

A sealed message is XChaCha20-Poly1305 under the key for its direction, with a
random 24-byte nonce and the associated data

    "ZcashFROSTv0" || id || direction || kind || len(session) || session

where `direction` is 0 from the initiator and 1 from the responder. A message
reflected to its sender, replayed under another kind or session, or sent by
another pairing fails authentication.

The pairing keys are long-term secrets: each device stores them encrypted,
like its key share. (OpenPGP Wallet does, under a key derived from its seed;
the test co-signer in this crate keeps its whole state unencrypted, which is
why it is for test amounts only.) The pairing has no forward secrecy beyond
that: someone who steals a device can read recorded messages, but that device
already holds its share and `sk`.

## 4. Key generation

Implemented in `src/setup.rs`. The FROST DKG of `reddsa` (three parts), 2-of-3,
run over the pairing, with the co-signer playing members 2 and 3. On top of
it, the members agree on `sk` by commit and reveal:

    c_i = H_"ZcashFROSTv0SkCm"(version || LE16(i) || r_i)       in round 1
    T   = H_"ZcashFROSTv0DkgT"(version || network || LE16(t) || LE16(n) ||
            for i = 1..3: LE16(i) || LE32(len) || round1_package_i || c_i)
    sk  = H_"ZcashFROSTv0DkSk"(T || ak || r_1 || r_2 || r_3)

`r_i` is 32 random bytes, revealed in round 2, and `ak` is the group key. Every
round 2 message carries `T` as its sender saw it; members abort if it differs,
or if a reveal does not open its commitment. The keys then follow ZIP 2005
(`use_qsk = true`).

The exchange takes five QR streams, pairing included:

1. pair-init (coordinator);
2. pair-response (co-signer);
3. pair-confirm, with the coordinator's round 1 sealed under the pending
   pairing (it holds no secret);
4. once the user confirmed the code on the co-signer: its round 1 for members
   2 and 3, and its round 2 packages for member 1 with `r_2`, `r_3` and `T`;
5. once confirmed on the coordinator: its round 2 packages for members 2 and 3,
   with `r_1` and `T`.

The coordinator reveals last, but committed to `r_1` in step 3, before seeing
any contribution, so no member chooses `sk`. Both devices then show the
group's address for a last comparison. The co-signer exports member 3 as a
member backup string (§ 7) and deletes it.

## 5. Signing session

Implemented in `src/cosigning.rs`. Three sealed messages, under a fresh 16-byte
session id chosen by the co-signer:

1. **sign-commitments**, co-signer → coordinator: one fresh commitment per
   spend it is ready to sign (up to 4). Sent before the co-signer sees the
   transaction.
2. **sign-request**, coordinator → co-signer: the PCZT (unproven: a v6
   signature covers neither proofs nor anchors), the coordinator's own
   commitments and its signature shares.
3. **sign-reply**, co-signer → coordinator: the co-signer's signature shares,
   or the reason it refuses.

Before asking the user, the co-signer checks the PCZT (§ 6), computes its
own shares, aggregates them with the coordinator's and verifies each signature
under the spend's `rk`. Its shares leave the device only if the user approves.
Nonces live in memory only, and reviewing a request consumes the session, so a
co-signer answers at most one request per set of nonces; a replayed request
belongs to an old session and is refused. An interrupted session starts over
with new nonces.

**Randomizers.** ZIP 312 derives each randomizer from the commitments. The
Orchard builder does not yet accept a randomizer from the caller
(zcash/orchard#571), so for now the randomizer `α` of each spend is the one the
builder put in the PCZT, as in `zcash-sign`. `α` is fixed when the PCZT is
built, and a dishonest coordinator can build it, and so choose `α`, after it
has seen the co-signer's commitments. FROST's
binding factors include the randomized key, the co-signer holds at most four
nonces per session, and we know of no attack in this setting, but it is not the
setting ZIP 312's proof covers. Once the builder accepts a randomizer, this
step will follow ZIP 312.

## 6. Signer checks

Already implemented in `src/check.rs`, before any signature:

- the PCZT spends only Ironwood notes of this group. Any transparent, Sapling
  or Orchard part is refused: the signature covers it, and value spent from the
  group and paid out there would only look like a larger fee. (The Orchard pool
  has refused new value since NU6.3, so such a transaction would not be mined
  today; the co-signer does not rely on consensus to show the truth.);
- for every action: the spent note's nullifier and the randomized key `rk` are
  recomputed from the note and the group's full viewing key; the output note
  commitment and the value commitment are recomputed; a dummy spend must
  already be signed; no dummy spending key may remain (ZIP 374);
- the randomizer `α` of each of the group's spends must be non-zero and used by
  no other spend in the transaction: a zero `α` would put the group's `ak`
  itself on chain as `rk`, and a shared one would give two spends the same
  `rk`, so anyone could link them. Reuse across transactions is not detected:
  the co-signer keeps no record of past signatures;
- a witness, when present, must lead to the bundle's anchor;
- outputs are sorted into payments and change with the group's viewing key,
  and the fee is the difference. It must equal the bundle's signed value
  balance, and it may not exceed ZIP 317's marginal fee (5,000 zatoshis, the
  rate before ZIP 2009 lowers it to 1,000; both pass) times the actions the
  payments need, `max(2, spends with value, outputs with value)`. A
  transaction with more actions than that is refused: zero-value actions
  beyond the builder's padding to two would let a raised fee pass for ZIP
  317's fee of a bigger transaction. A coordinator that spends more notes than
  needed, or splits the change into several outputs, is not detected: the
  co-signer does not know which notes a payment should spend;
- a zero-value output is read with the group's outgoing viewing key. One that
  holds a note to another address is refused, since it would land on chain
  with a memo the user was never shown; one to the group itself is shown with
  its memo. The builder's padding cannot be read by anyone and is not shown.
  A zero-value output encrypted without the group's outgoing key cannot be
  told from padding; the action bound above leaves room for one at most;
- every output with a value has its note ciphertext decrypted, which proves it
  holds the very note committed to, so its recipient can find it. The group's own outputs
  (change) are decrypted with its incoming viewing key, as its wallet will when
  scanning; payments are read back with the group's outgoing viewing key, so
  coordinators must encrypt payments to it. The memo shown comes from that
  decryption, with control characters and characters that reorder or hide
  text escaped (quotes and accents are shown as they are);
- a non-zero lock time is shown;
- a transaction that never expires is refused, and so is one that expires more
  than 1,000 blocks beyond the current height as the device's clock bounds it:
  from a recent checkpoint, the co-signer counts a block every 20 seconds on
  Mainnet and every 10 on testnet, faster than either keeps up (the target
  spacing is 25 seconds since NU7, ZIP 218), so the bound stays above the real
  height. A coordinator holding a signature with a far
  expiry could broadcast it much later, for example after the user, told the
  first attempt failed, approved the same payment again. The device warns that
  a v6 signature does not prove the spent notes exist, and authorizes these
  exact payments until the expiry height, shown on Mainnet with roughly how
  long that is from now;
- the sighash is computed on the device, never taken from the coordinator;
- the coordinator's signature shares are aggregated with the co-signer's own,
  and each signature is verified under the spend's `rk` before the user is
  asked;
- the co-signer shows the full recipient address, amount, fee and memo, built
  from its own decoding, and asks for approval. The address shown is the one
  the user was given when the PCZT names it (`user_address`, which
  zcash_client_backend fills in with the payment's address, often a unified
  address with several receivers), so the user can compare it with their
  invoice; it is shown only if it is a unified address on the group's network
  whose Orchard receiver is the one paid, and a PCZT that names any other
  address is refused. Without `user_address`, the paid receiver alone is
  shown, as a unified address.

The tamper suite (`tests/tamper.rs`, run in CI) builds PCZTs a dishonest
coordinator could send and checks that each one is refused or shown exactly as
it will be signed, including every single-field redaction of every action.
`tests/fuzz.rs`, also run in CI, mutates valid messages of every kind at
random and feeds them to the code that reads them, a co-signer reviewing a
request and a coordinator taking a reply included: no input may panic or take
long.

## 7. Backup

A member is backed up as a member backup string, specified by the FROST member
backup ZIP draft (zcash/zips#1432), whose version 1 is Zkool's `zkfrost`
string. It is Bech32m with the human-readable part `zkfrost`, over 68 bytes:

    version (1) || identifier (1) || t (1) || n (1) || signing share (32) || sk (32)

The identifier must be from 1 to `n`, and `t` from 2 to `n`. Restoring a member
also takes the group's unified full viewing key: `sk` and the group key must
give that viewing key, which also tells whether the group derives its keys per
ZIP 2005 or with Zkool's older derivation. That proves the string and the
viewing key go together, not that the share belongs to the group, which only
the group's public key package can confirm. Implemented in `src/backup.rs`; the
ZIP's test vectors pass with this crate and with Zkool's own code.

Because the string holds `sk`, it is never stored or sent under public-key
encryption that relies on discrete logarithms. Milestone 2 adds two profiles
for keeping it: a passphrase-encrypted file and a mnemonic.

## 8. Test vectors

`tests/fixtures/spec-vectors.json` gives fixed inputs and the expected outputs
for:

- pairing (§ 3): the initiator's X-Wing seed, `r_i`, the encapsulation
  randomness and `r_r`; the encapsulation key, commitment, ciphertext, code,
  pairing id and both direction keys;
- a sealed message (§ 3.4): kind, session, plaintext and nonce; the ciphertext;
- wire encodings (§ 2): a pair-init message, a pair-confirm payload and the
  same payload as a single-part UR;
- key generation (§ 4): three real DKG round 1 packages, the contributions, the
  group key `ak`; the commitments, `T`, `sk`, and the resulting unified full
  viewing key and Mainnet address.

`tests/vectors.rs` recomputes every output from the formulas in this document,
calling BLAKE2b, X-Wing and XChaCha20-Poly1305 directly, and checks that the
implementation gives the same bytes. FROST signatures are randomized, so the
signing session has no fixed vectors; `tests/protocol.rs` runs it end to end.

## 9. Open questions

- A pairing has no forward secrecy beyond device compromise (§ 3.4). A ratchet
  would add it at the cost of state that must stay in sync over QR codes.
- Publishing commitments in advance would save one QR step per signature, as
  Zafe does. Another way to the same saving: the coordinator sends the request
  with its own commitments, and the co-signer answers with its commitments and
  its shares together, so a signature takes two QR codes instead of three and
  no commitment is kept between sessions. The co-signer would then commit
  after seeing the coordinator's commitments and the message, which FROST's
  binding factors are meant to make safe, and it could no longer check the
  aggregated signature before its user approves. A proposal for v1.0, once
  that argument has been written down and reviewed.
