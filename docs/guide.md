# Guide: a FROST 2-of-3 spend with OpenPGP Wallet and the test co-signer

This guide walks through a complete spend from a FROST 2-of-3 account for
shielded ZEC, on testnet or on Mainnet: create the account, fund it, and send
from it with two of its three members signing. It is the reproduction guide
for ZCG grant #490, Milestone 1.

- **Coordinator (member 1):** OpenPGP Wallet on Windows, in its FROST tab.
- **Co-signer (member 2):** the `frost-zec` command-line tool, the test
  co-signer of the protocol in [spec.md](spec.md).
- **Backup (member 3):** a backup string the co-signer writes once, for you to
  keep offline.

> This is an unaudited prototype. Use testnet coins, or a few cents of ZEC on
> Mainnet, nothing more.

## What you need

- OpenPGP Wallet with a wallet created, in a version that has the FROST tab.
- The co-signer, built from this repository with a Rust toolchain:

  ```bash
  cargo build --release --features camera
  ```

  The binary is `target/release/frost-zec` (`frost-zec.exe` on Windows).
- A way to pass the messages between the two, either:
  - **QR codes:** the co-signer on a second computer with a webcam, facing the
    wallet's screen, and a webcam on the wallet's computer facing the
    co-signer's screen; or
  - **text:** both on one computer, passing each message as a
    `ur:zcash-frost/...` text (the wallet's "Copy as text" and "Paste" fields,
    and text files on the co-signer's side).
- Coins: testnet ZEC (TAZ) from a faucet or another tester, or about 0.002 ZEC
  on Mainnet.

The steps below use QR codes. The text variant is at the end.

## 1. Create the account

1. In OpenPGP Wallet, open the **FROST** tab and click **Create on testnet**
   (or **Create on Mainnet**). The wallet shows an animated QR code.
2. On the co-signer's computer, start the co-signer for the same network:

   ```bash
   frost-zec qr setup --as cosigner --network test --state my-cosigner --via qr
   ```

   Let its camera read the wallet's QR code. The co-signer then shows its own
   QR code: in the wallet, click **Read the co-signer's QR code**.
3. The wallet shows a new QR code and a six-digit code. Let the co-signer read
   the QR code: it shows a six-digit code too. **Compare the two codes.** If
   they match, confirm on both sides (`y` on the co-signer, **The codes match**
   in the wallet). If they differ, cancel: something else read or changed the
   messages.
4. In the wallet, enter your password, then read the co-signer's next QR code
   (its keys).
5. The wallet shows a last QR code and the account's address. Let the
   co-signer read it, and check that **both show the same address**. Then
   click **Done** in the wallet.
6. The co-signer has written `my-cosigner/member3-backup.txt`, the backup
   member. Copy it to an offline medium (a USB stick you keep apart) and
   delete it from the computer. With it and the account's viewing key, member
   3 can be rebuilt in any wallet that implements the member backup string
   (zcash/zips#1432).

## 2. Fund it

In the FROST tab, click **Receive** to show the account's address, and send it
the coins. Click **Sync** after a few minutes: the coins show as *Available*
once they have enough confirmations (a few minutes since NU7).

## 3. Send from it

1. In the FROST tab, click **Send**, enter a recipient and an amount (a memo is
   optional), and continue. Check the details in the Windows confirmation
   window, then let the cancellation delay run out.
2. On the co-signer, open a signing session:

   ```bash
   frost-zec qr sign --as cosigner --state my-cosigner --via qr
   ```

   It shows a QR code with fresh commitments. In the wallet, enter your
   password, then read it.
3. The wallet shows the signing request as an animated QR code, and its own
   reading of the transaction. Let the co-signer read it. The co-signer checks
   the transaction on its own and shows what it does: the recipient, the
   amount, the fee and the memo. **Approve only if this is what you sent**
   (`y`).
4. The co-signer shows its answer. Let the wallet read it, then press Enter on
   the co-signer. The wallet assembles the signature, proves the transaction
   and broadcasts it, then shows the transaction id.
5. Look the transaction up on an explorer:
   [testnet](https://testnet.zcashexplorer.app) or
   [Mainnet](https://mainnet.zcashexplorer.app).

## The text variant (one computer)

Use `--via DIR` on the co-signer instead of `--via qr`. Each message it sends is
written to DIR as a text file, and each message it expects is read from DIR:

| Step | Wallet | Co-signer file |
|---|---|---|
| Setup 1 | **Copy as text**, save as | `1-pair-init.ur` |
| Setup 2 | **Paste** the co-signer's | `2-pair-response.ur` |
| Setup 3 | **Copy as text**, save as | `3-pair-confirm.ur` |
| Setup 4 | **Paste** the co-signer's | `4-cosigner-keys.ur` |
| Setup 5 | **Copy as text**, save as | `5-coordinator-keys.ur` |
| Send 1 | **Paste** the co-signer's | `sign-1-commitments.ur` |
| Send 2 | **Copy as text**, save as | `sign-2-request.ur` |
| Send 3 | **Paste** the co-signer's | `sign-3-reply.ur` |

The co-signer reads a file once it is complete and deletes it after use.

## If something goes wrong

- **The codes differ:** cancel on both sides and start again. Do not confirm.
- **Sync fails:** the wallet shows the server's error under the account. On
  testnet there is one public server, which sometimes lags; try again later.
- **The last setup step fails** (network, wrong password): fix the cause and
  read the co-signer's keys again; the pairing is kept.
- **The co-signer refuses a request:** it prints why. Do not override it.

## What to report

For Milestone 1, please send the transaction id(s), the network, how long each
part took, and anything in this guide that was unclear or wrong.
