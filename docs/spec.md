# FROST co-signing for shielded ZEC: QR protocol, signer checks and backups

Draft v1.0, work in progress (ZCG grant #490: v0.1 was Milestone 1, v1.0 is
Milestone 2). The changes since v0.1 are listed in § 10. Not audited: use small
test amounts only.

The key words MUST, MUST NOT, SHOULD and MAY are to be read as in RFC 2119.

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
| 34 | dkg-done | sealed |
| 51 | sign-request | sealed |
| 52 | sign-reply | sealed |
| 64 | group-info | sealed (recovery, § 7.2, draft) |

Kinds 48 to 50 were the three signing messages of v0.1 and MUST NOT be reused:
the kind is bound to every sealed message, so a v0.1 device and a v1.0 device
refuse each other's signing messages instead of misreading them.

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

When the user says the codes differ, the device MUST end the pairing and erase
its pending state. It MUST NOT offer a quick retry, and SHOULD tell the user
that another device may be reading or changing the messages: each new attempt
is a new guess for whoever sits between the devices. A new pairing starts from
pair-init.

A device that is replaced, or restored from a backup, pairs again; the pairing
keys of the device it replaces MUST be erased wherever they are stored, so the
old device can no longer read or send messages. Six digits suit carriers where
each attempt takes the user's time, such as QR codes. A carrier where attempts
are cheap to repeat, such as a relay, may need a longer code.

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

The exchange takes six QR streams, pairing included:

1. pair-init (coordinator);
2. pair-response (co-signer);
3. pair-confirm, with the coordinator's round 1 sealed under the pending
   pairing (it holds no secret);
4. once the user confirmed the code on the co-signer: its round 1 for members
   2 and 3, and its round 2 packages for member 1 with `r_2`, `r_3` and `T`;
5. once confirmed on the coordinator: its round 2 packages for members 2 and 3,
   with `r_1` and `T`;
6. **dkg-done**, co-signer → coordinator: `{1: D}`, the co-signer's digest of
   the group it ended with.

The coordinator reveals last, but committed to `r_1` in step 3, before seeing
any contribution, so no member chooses `sk`.

### 4.1 The acknowledgement

Until step 6, the coordinator cannot tell whether the co-signer finished: the
last message may never have reached it. An account the co-signer does not hold
can never sign, so funds sent to it would be stuck. The digest is

    D = H_"ZcashFROSTv0Done"(version || network || LE16(t) || LE16(n) || ak ||
            for each member, by identifier: id || verifying_share ||
            LE32(len(ufvk)) || ufvk)

where `id` and `verifying_share` are 32-byte encodings and `ufvk` is the
group's unified full viewing key as text (UTF-8). It covers what the account
is: who can sign and what the viewing key shows.

The co-signer MUST send dkg-done only after it has:

1. stored its own member;
2. exported member 3 as a member backup string (§ 7.1);
3. read back what it exported, restored member 3 from it against the group's
   viewing key under ZIP 2005, and checked it against the group's public key
   package (member 3's verifying share, the group key, `t` and `n`);
4. deleted member 3 from its memory and storage. Until then it holds two
   members of three.

The coordinator MUST NOT show the group's address, or offer to fund the
account, before it has received dkg-done and found `D` equal to its own digest.
On a mismatch it MUST NOT use the account. Once `D` matches, both devices show
the address.

A device cannot prove that the user moved the backup string off it. The test
co-signer writes the string to a file next to its state and asks the user to
move it offline.

## 5. Signing session

Implemented in `src/cosigning.rs`. Two sealed messages, under a fresh 16-byte
session id chosen by the coordinator, which owns the session:

1. **sign-request**, coordinator → co-signer:
   `{1: session, 2: coordinator id, 3: PCZT, 4: [commitment per spend]}`. The
   PCZT is unproven (a v6 signature covers neither proofs nor anchors). Up to
   four spends, one fresh commitment each, in bundle order.
2. **sign-reply**, co-signer → coordinator:
   `{1: session, 2: co-signer id, 3: [commitment per spend], 4: [share per spend]}`
   once the user approves, or `{1: session, 2: co-signer id, 5: reason}` when it
   refuses. A reason is at most 1,000 characters, and the coordinator escapes
   it before showing it.

The co-signer:

- MUST check the PCZT (§ 6) and compute the sighash and each spend's `α` from
  it;
- MUST draw its nonces only after that, build each spend's commitment list
  itself from its own commitment and the coordinator's, and refuse a request
  that names its own identifier, an identifier outside the group, a number of
  commitments other than the number of spends, or a commitment used twice.
  Building the list itself takes the place of RFC 9591's check, § 5.2, that a
  signer finds its own commitment in the list;
- MUST release its commitments and shares only if the user approves, and erase
  its nonces whether or not the user approves, before it shows anything;
- keeps no session state: each request gets fresh nonces. A co-signer that
  stores state MAY refuse a session id it has already answered.

The coordinator:

- MUST draw fresh nonces for every request, even one for the same
  transaction, and keep them in memory only;
- MUST accept at most one reply per set of nonces, and only for the session it
  opened. Two replies with different co-signer commitments against the same
  coordinator nonces could give away its share (RFC 9591, § 5.2 and § 7.3);
- signs its part over the co-signer's commitments, aggregates, and MUST verify
  every signature under its spend's `rk` before it uses the transaction.

**Why this order is safe.** Each binding factor hashes the group key, the
message and the whole commitment list (RFC 9591, § 4.4). The co-signer commits
last, after the PCZT, the randomizers and the coordinator's commitments are
fixed, and answers at once: it never has a commitment waiting for an answer, so
a dishonest coordinator has nothing to adapt to. The coordinator is the side
that commits first, which is the case binding factors are for. This is an
argument, not a proof. In v0.1 the co-signer committed first and could check
the aggregated signature before its user approved; that check protected
liveness, not funds (a coordinator that signs badly only gets a signature that
does not verify), and the coordinator now makes it.

**Randomizers.** ZIP 312 derives each randomizer from the commitments. The
Orchard builder does not yet accept a randomizer from the caller
(zcash/orchard#571), so for now the randomizer `α` of each spend is the one the
builder put in the PCZT, as in `zcash-sign`. Since the PCZT, and so `α`, is
fixed in the request before the co-signer commits, a dishonest coordinator can
no longer choose `α` after seeing the co-signer's commitments, as it could in
v0.1. This is still not ZIP 312's order, which derives `α` from the
commitments; once the builder accepts a randomizer, this step will follow ZIP
312.

## 6. Signer checks

Implemented in `src/check.rs`, which both the coordinator and the co-signer
run on every PCZT. Each rule names the refusal class a tamper case uses for it
(frost-zec#7); "shown" means the co-signer displays it, from its own decoding,
before the user approves.

### 6.1 What the co-signer checks

Spends and pools:

- The PCZT MUST spend only Ironwood notes of this group: for every action the
  co-signer recomputes the spent note's nullifier and the randomized key `rk`
  from the note and the group's full viewing key (`foreign-spend`).
- Any transparent, Sapling or Orchard part MUST be refused: the signature
  covers it, and value spent from the group and paid out there would only look
  like a larger fee (`foreign-pool`). The Orchard pool has refused new value
  since NU6.3, so such a transaction would not be mined today; the co-signer
  does not rely on consensus to show the truth.

Structure (`structure`):

- every output note commitment and value commitment MUST be recomputed and
  match;
- a dummy spend MUST already be signed, and no dummy spending key may remain
  (ZIP 374);
- the randomizer `α` of each of the group's spends MUST be non-zero and used
  by no other spend in the transaction: a zero `α` would put the group's `ak`
  itself on chain as `rk`, and a shared one would give two spends the same
  `rk`, so anyone could link them. Reuse across transactions is not detected:
  the co-signer keeps no record of past signatures;
- a witness, when present, MUST lead to the bundle's anchor.

Outputs:

- Every output with a value MUST have its note ciphertext decrypted, which
  proves it holds the very note committed to, so its recipient can find it
  (`unreadable-output`). The group's own outputs are decrypted with its
  incoming viewing key, as its wallet will when scanning; payments are read
  back with the group's outgoing viewing key.
- An output that is not the group's is a payment and MUST be shown as one,
  never as change (`change`).
- A zero-value output MUST be read with the group's outgoing viewing key. One
  that holds a note to another address MUST be refused, since it would land on
  chain with a memo the user was never shown; one to the group itself is shown
  with its memo (`hidden-output`). The builder's padding cannot be read by
  anyone and is not shown. A zero-value output encrypted without the group's
  outgoing key cannot be told from padding; the action bound below leaves room
  for one at most.
- For each payment the co-signer MUST show the full recipient address, the
  amount and the memo (`payment`). The memo comes from the decryption, with
  control characters and characters that reorder or hide text escaped (quotes
  and accents are shown as they are). The address shown is the one the user
  was given when the PCZT names it (`user_address`, which zcash_client_backend
  fills in with the payment's address, often a unified address with several
  receivers), so the user can compare it with their invoice. It is shown only
  if it is a unified address on the group's network whose Orchard receiver is
  the one paid; a PCZT that names any other address MUST be refused. Without
  `user_address`, the paid receiver alone is shown, as a unified address.

Fee and size:

- The fee is what the group spends minus what its outputs carry. It MUST equal
  the bundle's signed value balance, and MUST NOT exceed ZIP 317's marginal fee
  (5,000 zatoshis) times the actions the payments need,
  `max(2, spends with value, outputs with value)` (`fee`). The lower fee of
  ZIP 2009 (1,000 per action from Mainnet height 3,590,000) passes. A fee below
  the rule only costs the sender, so it is not refused.
- A transaction with more actions than the payments need MUST be refused:
  zero-value actions beyond the builder's padding to two would let a raised fee
  pass for ZIP 317's fee of a bigger transaction (`padding`). A coordinator that
  spends more notes than needed, or splits the change into several outputs, is
  not detected: the co-signer does not know which notes a payment should spend.

Time:

- A transaction that never expires MUST be refused, and so MUST one that
  expires more than 1,000 blocks beyond the current height as the device's
  clock bounds it (`expiry`). From a recent checkpoint, the co-signer counts a
  block every 20 seconds on Mainnet and every 10 on testnet, faster than
  either keeps up (the target spacing is 25 seconds since NU7, ZIP 218), so the
  bound stays above the real height. A coordinator holding a signature with a
  far expiry could broadcast it much later, for example after the user, told
  the first attempt failed, approved the same payment again. The expiry height
  is shown, on Mainnet with roughly how long that is from now.
- A non-zero lock time is shown.

Signing:

- The co-signer MUST compute the sighash itself from the PCZT it checked, and
  sign nothing else (`sighash`).
- Each approval covers exactly the transaction shown: the shares are computed
  over its sighash, and a second request, even for the same payment, is shown
  and approved again (`equivocation`).
- The co-signer warns that a v6 signature does not prove the spent notes exist,
  and that it authorizes these exact payments until the expiry height.

### 6.2 What the coordinator must do

So that an honest co-signer can accept its requests, the coordinator MUST:

- encrypt every payment to the group's outgoing viewing key, and the change to
  the group's own address;
- when it fills in `user_address`, use a unified address that holds the
  receiver paid;
- run the IO Finalizer before the request, so that dummy spends are signed and
  no dummy spending key remains;
- keep the fee, the action count and the expiry within the bounds of § 6.1;
- run the same checks itself before it signs its part: whatever built the PCZT
  is not trusted to have built what the user asked for.

### 6.3 Tests

The tamper suite (`tests/tamper.rs`, run in CI) builds PCZTs a dishonest
coordinator could send and checks that each one is refused or shown exactly as
it will be signed, including every single-field redaction of every action. Its
cases are being moved to the shared format of frost-zec#7, so other signers can
run them. `tests/fuzz.rs`, also run in CI, mutates valid messages of every kind
at random and feeds them to the code that reads them, a co-signer reviewing a
request and a coordinator taking a reply included: no input may panic or take
long.

## 7. Backup and recovery

### 7.1 Member backup strings

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

### 7.2 Recovery *(Milestone 2, draft)*

Losing one member never loses the funds: the two others move them to a fresh
account. An account is never repaired in place. After a loss, the remaining
members create a new 2-of-3 account (§ 4) and sweep every note of the old one
to it, so whatever the lost device held (its share, `sk`, the pairing keys)
can no longer spend; it still reveals the old account's history.

| Lost | Signers of the sweep | How |
|---|---|---|
| Coordinator (1) | co-signer (2) and backup (3) | a new coordinator restores member 3 and pairs with the co-signer |
| Co-signer (2) | coordinator (1) and backup (3) | the coordinator restores member 3 and signs with both; a new co-signer joins the new account |
| Backup (3) | coordinator (1) and co-signer (2) | an ordinary session (§ 5), to a new account with a new backup |

When the coordinator is lost:

1. A new coordinator pairs with the co-signer (§ 3), and the user compares the
   code as for a first pairing. The co-signer attaches the new pairing to its
   existing member and forgets the old one, so the lost device can no longer
   talk to it.
2. The co-signer sends the old group's public key package and unified full
   viewing key, sealed under a new kind, `group-info` (64). The new
   coordinator restores member 3 from its backup string (§ 7.1) and checks it
   against them: `sk` and the group key must give that viewing key, and
   member 3's verifying share must be the package's.
3. The two devices create the new account (§ 4), over the pairing of step 1.
4. The new coordinator scans the old account with its viewing key, from the
   account's birthday when known and otherwise from the Ironwood activation
   height, and builds a PCZT that pays every spendable note, less the fee, to
   the new account's address. A sweep with more notes than one session signs
   (four, § 5) takes several transactions.
5. The co-signer checks each PCZT as any other (§ 6). When the recipient is
   the new account, whose address it computed itself in step 3, it says so,
   so the user approves a transfer to their new account rather than to an
   address they would have to read.
6. Once the sweep is mined, the new coordinator deletes the restored member 3.

When the co-signer is lost, the coordinator restores member 3 the same way,
checked against the public key package it already holds, creates the new
account with a new co-signer, and signs the sweep with members 1 and 3 itself.
Until the sweep is mined that one device holds two members, so the sweep
should be done in one sitting.

The checks of step 2 do not stop a lying co-signer: it holds `sk`, so it can
make a package and a viewing key that agree with the backup string but belong
to no funded account. Nothing is lost then (the sweep finds no notes and the
old account is untouched), but the recovery stalls. A backup kit that also
carries the account's viewing key and birthday height would make step 2
independent of the co-signer; whether the kit should carry them is open.

## 8. Test vectors

### 8.1 Protocol vectors

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
  viewing key and Mainnet address;
- the acknowledgement (§ 4.1): that group key and viewing key with three fixed
  verifying shares; the digest `D`.

`tests/vectors.rs` recomputes every output from the formulas in this document,
calling BLAKE2b, X-Wing and XChaCha20-Poly1305 directly, and checks that the
implementation gives the same bytes. FROST signatures are randomized, so the
signing session has no fixed vectors; `tests/protocol.rs` runs it end to end.

### 8.2 Tamper cases

Shared cases for the signer checks of § 6, in `vectors/tamper/`, so that any
co-signer can run the same set (frost-zec#7). A PCZT cannot be "tampered" on
its own: a recipient is only swapped relative to what the user approved. So a
case is the PCZT together with what the signer was told to expect, and every
refused PCZT comes with an accepted twin changed in one place. A signer that
refuses everything, or refuses for the wrong reason, does not pass. A case may
also be accepted only, to catch signers that refuse an honest transaction.

    vectors/tamper/
      classes.md                 the refusal classes of § 6
      <case-id>/
        case.json
        accepted.pczt            raw PCZT bytes (pczt crate serialization)
        refused.pczt             absent in an accepted-only case

`case.json` is a JSON object:

| Field | Meaning |
|---|---|
| `id` | the case's directory name |
| `format` | 1 |
| `description`, `changed` | what the case is about, and what differs from the accepted twin (free text, for people) |
| `class` | the refusal classes, primary first; a refused file passes if it is refused with any of them |
| `network` | `main` or `test` |
| `height` | the height the transaction targets |
| `clock` | the time of block `height` in Unix seconds, or its expected time if it is not mined yet; the signer's clock during the check |
| `fee_rule` | `zip317` or `zip2009`, required in cases whose classes include `fee`, so that editing `height` cannot silently change a case |
| `group.ufvk` | the group's unified full viewing key |
| `group.own_addresses` | optional: the device's own record of its receivers, for signers that check change against it |
| `approved.payments` | what the user approved: `address`, `amount` in zatoshis, and `memo` as UTF-8 text padded with zero bytes as in ZIP 302 (no `memo`: no memo, `0xF6` then zeros; `memo_hex` for a memo that is not text) |
| `part` | in `payment` cases, what changed: `recipient`, `amount` or `memo` |
| `accepted.sha256`, `refused.sha256` | the SHA-256 of each file's exact bytes |
| `accepted.sighash` | the sighash of the accepted PCZT, for runners that check the signer signs the sighash it computed |

A runner passes a case when the accepted PCZT is accepted, its payments are
shown exactly as approved and its sighash is the one given, and the refused
PCZT is refused with one of the case's classes. A refused PCZT that is accepted
but shows a payment other than the approved one counts as refused with class
`payment`: the user, comparing, refuses it. Each signer maps its own errors to
the classes; a refusal that maps to none fails.

Sequence cases, for the `sighash` and `equivocation` classes, are a series of
steps at the level of the signing call rather than single files; their shape
comes with the first such cases.

A new case tells everyone how to attack each signer that does not pass it yet.
It is first sent privately to the maintainers listed in frost-zec#7, through
this repository's private vulnerability reporting, and published after 14 days
or once every listed signer passes it, whichever comes first. A listed
maintainer can ask, before the deadline, for one extension of up to 30 days in
all.

`tests/tamper_vectors.rs` runs every case against this crate's checks, and
writes the cases again from the PCZT factory of `tests/common` (an ignored
test: PCZTs are randomized, so writing them again changes every file).
`tests/tamper.rs` keeps the checks specific to this co-signer, such as the
exact lines it shows and every single-field redaction of every action.

## 9. Open questions

- A pairing has no forward secrecy beyond device compromise (§ 3.4). A ratchet
  would add it at the cost of state that must stay in sync over QR codes. A
  stolen device already holds its share and `sk`, and `sk` with `ak` gives the
  full viewing key, so this is accepted for v1.0.
- The acknowledgement (§ 4.1) proves that the co-signer holds the group and
  checked the exported backup, not that the user moved the backup off the
  device.
- The randomizers follow the PCZT until the Orchard builder accepts one from
  the caller (§ 5, zcash/orchard#571).

## 10. Changes since v0.1

Reviewed by Daniel Gorgonha (DeegaLabs) on the forum thread of grant #490.

- Signing takes two messages instead of three (§ 5). The coordinator opens the
  session and commits first; the co-signer commits after the PCZT and the
  coordinator's commitments are fixed, builds the commitment list itself and
  answers with its commitments and shares together. Kinds 48 to 50 are retired
  for 51 and 52.
- Key generation ends with the co-signer's acknowledgement, dkg-done (§ 4.1).
  The coordinator shows no address before it holds.
- A pairing code mismatch ends the pairing, with no quick retry (§ 3.3).
- The signer checks are written as requirements, each with its refusal class,
  and the coordinator has its own list (§ 6).
