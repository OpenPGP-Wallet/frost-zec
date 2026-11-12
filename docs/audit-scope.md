# Audit scope: FROST 2-of-3 co-signing for shielded ZEC

Draft for the independent audit planned in ZCG grant #490 (Milestone 2). It
says what to review, what each part must guarantee, what is out of scope, and
what is already known. The audit comes before any public mainnet release;
until then the app labels FROST as not audited and tests use small amounts.

## 1. The system in brief

A user's FROST 2-of-3 account for shielded ZEC (Ironwood pool, v6
transactions), shared between their own devices:

| Member | Device | Holds |
|---|---|---|
| 1 | Coordinator: OpenPGP Wallet on a computer | its signing share, `sk`, the pairing keys |
| 2 | Co-signer: a second device (today the frost-zec test co-signer) | its signing share, `sk`, the pairing keys |
| 3 | Backup: a member backup string kept offline | its signing share and `sk` |

The two devices pair over QR codes (or the same messages as text), run a FROST
DKG over that channel, and agree on `sk` by commit and reveal; keys follow ZIP
2005 with `use_qsk`. To spend, the coordinator builds a PCZT and the co-signer
checks it on its own before releasing its signature shares. The protocol is
specified in [spec.md](spec.md).

## 2. Assets

- **Funds** of the FROST account: two members can spend them.
- **Signing shares**: one alone cannot spend, two can.
- **`sk`**: with the group key it gives the viewing key and `qsk`, which ZIP 2005
  asks to protect like a spending key (quantum recovery).
- **Pairing keys**: whoever holds them can read and forge messages between the
  two devices.
- **Signing nonces**: reusing one, or revealing it, leaks the share.
- **Privacy**: the viewing key reveals the account's whole history.

## 3. Threat model

Each attacker on its own, and what it must not gain:

1. **A malicious coordinator** (malware on the computer, or a hostile wallet)
   facing an honest co-signer: a signature for a transaction the co-signer
   shows differently, or the co-signer's share.
2. **A hostile carrier** between the devices (someone else's QR code, a changed
   file, a relay, the clipboard): it can drop, replay, reorder, forge and swap
   messages.
3. **A malicious co-signer** facing an honest coordinator: an unintended
   broadcast, member 1's share, a crash.
4. **A recorder of every QR code** who gets a quantum computer later: `sk`,
   `qsk` or links between transactions.
5. **Theft of files at rest** without the wallet password.
6. **A compromised web frontend** of the wallet, calling its backend commands in
   any order with any arguments: anything beyond what the user confirms in the
   native windows.

## 4. Invariants to verify

1. What the co-signer shows is what it signs: every byte under the v6 sighash
   is shown to the user or checked by the co-signer itself.
2. Nonces are used once: the co-signer draws fresh ones for every request and
   erases them before it asks the user, and a coordinator session accepts one
   reply. The co-signer's commitments and shares leave only after approval.
3. The pairing resists a man in the middle: the six-digit code cannot be
   ground, sealed messages are bound to pairing, direction, kind and session,
   and the wallet confirms exactly the pairing whose code it showed.
4. Key generation cannot be biased or split: no member chooses `sk` alone, and
   members abort on different round 1 views.
5. Untrusted input cannot crash or exhaust a device: CBOR, UR parts, PCZTs,
   camera frames, pasted text, files.
6. Secrets stay secret: never logged, never sent to the web frontend,
   encrypted at rest, wiped from memory where it matters.
7. The wallet's state machine holds under any sequence of frontend commands.

## 5. In scope

**frost-zec** (https://github.com/OpenPGP-Wallet/frost-zec), `master` at the
commit given with the audit request. Non-blank lines,
unit tests included:

| File | Lines | Role |
|---|---|---|
| `src/channel.rs` | 655 | Pairing (X-Wing, committed six-digit code), direction keys, sealing |
| `src/wire.rs` | 679 | CBOR messages, UR reader and its limits |
| `src/setup.rs` | 866 | DKG over the pairing, `sk` by commit and reveal, the acknowledgement |
| `src/cosigning.rs` | 459 | Signing session, co-signer review and approval |
| `src/check.rs` | 829 | Signer checks on a PCZT, and what is shown |
| `src/signing.rs` | 123 | Re-randomized FROST shares, aggregation, verification |
| `src/pczt_io.rs` | 145 | Sighash, spends to sign, signature insertion |
| `src/keys.rs` | 246 | ZIP 2005 key derivation (`use_qsk`) |
| `src/dkg.rs` | 84 | DKG wrapper over `reddsa` |
| `src/backup.rs` | 587 | Member backup strings (zcash/zips#1432) |

The test co-signer, for its input handling only (invariant 5): `src/qrcli.rs`,
`src/camera.rs`, `src/session.rs`, `src/qrview.rs` (about 1,180 lines).

**OpenPGP Wallet** (https://github.com/OpenPGP-Wallet/openpgp-wallet), `master`
at the commit given with the audit request:

| File | Lines | Role |
|---|---|---|
| `core/src/zcash_frost.rs` | 1,310 | FROST account: seat encryption, setup, PCZT creation, proving, broadcast |
| `app/src-tauri/src/frost.rs` | 538 | Commands the web frontend calls, state between steps, native confirmations |
| `app/src/main.js`, FROST section | about 500 | Screens; how backend text and SVG are displayed |

In total about 7,000 lines of protocol and wallet code and 1,180 lines of test
co-signer input handling, plus about 2,570 lines of integration tests and the
shared tamper cases of `vectors/tamper/`, which show the intended behaviour.
(Counted on 2026-11-13; the audit request gives the counts at its commit.)

## 6. Out of scope

- The upstream crates, except how they are used: `reddsa` and `frost-core`
  (FROST), `orchard`, `pczt` and the rest of librustzcash, `halo2`, `x-wing`,
  `chacha20poly1305`, `ur`, `minicbor`, `nokhwa`, `rqrr`.
- The rest of OpenPGP Wallet (other networks, the main Zcash account, the
  backup kit of the seed), except where the FROST code calls it: password
  check, seed unlock, native confirmation windows.
- The test co-signer's storage: it keeps its state unencrypted on purpose, and
  a production co-signer would not be this tool.
- `src/interop.rs`, `src/store.rs` and the older JSON session commands in
  `src/main.rs`, which serve interoperability tests and are not used by the
  wallet.

## 7. Known limits and accepted risks

- **Randomizers.** Until the Orchard builder accepts one from the caller
  (zcash/orchard#571), each spend's α comes from the PCZT. Since spec v1.0 the
  PCZT is fixed before the co-signer commits, but α is still not derived from
  the commitments as ZIP 312 does (spec § 5).
- **Every member holds `sk`**, as ZIP 2005 requires; a member's device gives its
  holder the viewing key and `qsk`.
- **No forward secrecy** in the pairing beyond device compromise (spec § 3.4).
- **The clipboard transport** is readable by any program on the computer; it
  carries only public or sealed messages.
- **Pre-authorization.** A v6 signature does not commit to the anchor; the
  co-signer warns that it authorizes these payments until the expiry height.
- **Camera decoding** relies on `rqrr`; a frame it panics on is skipped.

## 8. Reviews so far

- **Self-review (2026-11-10)** against the invariants above. Fixed with tests:
  the wallet confirmed the pairing current when the user answered rather than
  the one whose code it showed; one crafted UR part could stall the `ur`
  decoder for minutes or exhaust memory; secrets in `Debug` output and
  buffers not wiped; a setup finishing over an existing account; the group's
  viewing key sent to the frontend; memos and refusal reasons shown with
  control and direction characters; unbounded message files. The commit
  messages on both branches give the details.
- **Tamper suite** (`tests/tamper.rs`): PCZTs a dishonest coordinator could
  send, each refused or shown exactly as it will be signed, including every
  single-field redaction of every action.
- **Mutation fuzzing** (`tests/fuzz.rs`): valid messages of every kind,
  mutated and fed to every decoder; about 110,000 inputs without a panic, and
  a minute of it in every CI run.
- **Test vectors** (`tests/fixtures/spec-vectors.json`), recomputed from the
  spec's formulas by `tests/vectors.rs`.
- **Review of spec v0.1** by Daniel Gorgonha (DeegaLabs, Konclave), on the
  grant's forum thread: led to the two-message signing session, the
  acknowledgement at the end of key generation, a code mismatch that ends the
  pairing, and the signer checks written as requirements (spec § 10).
- [External model review: to be added.]
- [Specification review by another wallet developer or a ZF FROST maintainer:
  to be added.]

## 9. Questions for the auditors

1. Is taking α from the PCZT (§ 7), fixed before the co-signer commits but not
   derived from the commitments, exploitable by a dishonest coordinator?
2. Does the commit and reveal of `sk` on top of the DKG keep every member,
   including the last to reveal, from choosing it?
3. Is any field under the v6 sighash neither shown nor checked by the
   co-signer?
4. Can a frontend command sequence reach a signature or a pairing the user did
   not confirm in a native window?
5. Is the two-message signing session of spec § 5 sound, given that the
   co-signer commits last and the coordinator first?

## 10. Reproducing

```bash
cargo test                                            # frost-zec: unit and integration tests
cargo test --release --test extract -- --ignored      # sign, prove, extract a whole transaction
FUZZ_SECS=60 cargo test --release --test fuzz -- --ignored --nocapture
```

[guide.md](guide.md) walks through a complete spend with the wallet and the
test co-signer, on testnet or on mainnet.
