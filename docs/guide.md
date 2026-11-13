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

- OpenPGP Wallet 2.17.0 or later, with a wallet created
  ([releases](https://github.com/OpenPGP-Wallet/openpgp-wallet/releases)).
  It speaks spec v1.0; earlier versions speak v0.1, and the two refuse each
  other's signing messages.
- The co-signer, built from this repository with a Rust toolchain:

  ```bash
  cargo build --release --features camera
  ```

  The binary is `target/release/frost-zec` (`frost-zec.exe` on Windows).
- Coins: testnet ZEC (TAZ) from a faucet or another tester, or about 0.002 ZEC
  on Mainnet.

## How to read the steps

Every step starts with the window it happens in:

- **Wallet:** OpenPGP Wallet, in its FROST tab.
- **Co-signer:** the terminal window where `frost-zec` runs.

The steps below run both on one computer, passing each message as a
`ur:zcash-frost/...` text through the clipboard. Three rules carry the whole
run:

- **Wallet to co-signer:** in the wallet, click **Copy as text**. That is all:
  the co-signer reads the clipboard by itself. Never paste anything into the
  co-signer's window.
- **Co-signer to wallet:** the co-signer copies its message to the clipboard
  itself and beeps (the terminal bell). In the wallet, click **Paste the
  co-signer's message** (or press Ctrl+V in its window).
- **Copied something else in between?** In the co-signer's window, press
  Enter: it copies its last message again. At a `[y/N]` question, though,
  Enter alone answers no.

The co-signer clears the clipboard when it starts, so start it before copying
the wallet's first message. With two computers, see "With QR codes" and "With
files" further down.

## 1. Create the account

1. **Co-signer:** start it for the network of the account (`--network main`
   for Mainnet):

   ```bash
   frost-zec qr setup --as cosigner --network test --state my-cosigner --via clipboard
   ```

2. **Wallet:** click **Create on testnet** (or **Create on Mainnet**), then
   **Copy as text**.
3. **Wallet:** when the co-signer beeps, click **Paste the co-signer's
   message**.
4. **Wallet:** a six-digit code shows. Click **Copy as text**.
   **Co-signer:** it shows its own six-digit code. **Compare the two codes.**
5. If the codes match:
   - **Co-signer:** type `y`, then Enter.
   - **Wallet:** click **Confirm the codes…**, then **OK** in the Windows
     window, which shows the code again.

   If they differ, cancel on both sides: something else read or changed the
   messages.
6. **Wallet:** when the co-signer beeps, enter your password, then click
   **Paste the co-signer's message**.
7. **Wallet:** click **Copy as text**. **Co-signer:** from this last message it
   computes its own share and the backup's, writes the backup, checks that it
   restores, and beeps: its acknowledgement is on the clipboard.
8. **Wallet:** click **Paste the co-signer's message**. Only now does the
   wallet show the account's address: the acknowledgement proves the
   co-signer holds the same account. The co-signer shows the same address.
   Until then, the account's card says the setup is not finished, shows no
   address and cannot receive: without the co-signer's share, the account
   could never sign, and coins sent to it would be lost.
9. **Co-signer's folder:** the co-signer has written
   `my-cosigner/member3-backup.txt`, the backup member. Copy it to an offline
   medium (a USB stick you keep apart) and delete it from the computer. With
   it and the account's viewing key, member 3 can be rebuilt in any wallet
   that implements the member backup string (zcash/zips#1432). The rest of
   `my-cosigner` holds member 2 unencrypted (this test co-signer does not
   encrypt its state): until the backup string is gone from the computer, that
   computer alone holds two members of three.

## 2. Fund it

1. **Wallet:** click **Receive**, copy the account's address, and send coins to
   it from another wallet or a faucet.
2. **Wallet:** after a few minutes, click **Sync**. The coins show as
   *Available* once they have enough confirmations (a few minutes since NU7).

## 3. Send from it

1. **Wallet:** click **Send**, enter a recipient and an amount (a memo is
   optional), and continue. Under the recipient, the wallet says whether the
   co-signer will accept the address. Check the details in the Windows
   confirmation window, click **OK**, then let the cancellation delay run out.
2. **Co-signer:** open a signing session. It waits for the wallet's request:

   ```bash
   frost-zec qr sign --as cosigner --state my-cosigner --via clipboard
   ```

3. **Wallet:** enter your password, click **Create the request**, then
   **Copy as text**.
4. **Co-signer:** it checks the transaction on its own and shows what it does:
   the recipient, the amount, the fee and the memo. **Type `y`, then Enter,
   only if this is what you entered in the wallet.**
5. **Wallet:** when the co-signer beeps, click **Paste the co-signer's
   message**. The wallet signs its part, assembles the signature, proves the
   transaction and broadcasts it, then shows the transaction id.
6. Look the transaction up on an explorer:
   [testnet](https://testnet.zcashexplorer.app) or
   [Mainnet](https://mainnet.zcashexplorer.app).

## With QR codes (two computers, cameras)

The co-signer runs on a second computer with a webcam facing the wallet's
screen, and the wallet's computer has a webcam facing the co-signer's screen.
Start the co-signer with `--via qr` instead of `--via clipboard`. Then, in
every step above:

- Instead of **Copy as text**: let the co-signer's camera read the wallet's
  animated QR code.
- Instead of **Paste the co-signer's message**: **Wallet:** click **Read the
  co-signer's QR code**; once the wallet has read it, **Co-signer:** press
  Enter.

The co-signer only opens its camera after Enter, so a single camera (a phone
used as a webcam by both programs) is enough: the two take turns.

## With files (two computers, no camera)

Start the co-signer with `--via DIR` instead of `--via clipboard`: each message
it sends is written to DIR as a text file, and each message it expects is read
from DIR, for files carried between the two machines.

| Step | Wallet | Co-signer file |
|---|---|---|
| Setup 1 | **Copy as text**, save as | `1-pair-init.ur` |
| Setup 2 | **Paste** the co-signer's | `2-pair-response.ur` |
| Setup 3 | **Copy as text**, save as | `3-pair-confirm.ur` |
| Setup 4 | **Paste** the co-signer's | `4-cosigner-keys.ur` |
| Setup 5 | **Copy as text**, save as | `5-coordinator-keys.ur` |
| Setup 6 | **Paste** the co-signer's | `6-cosigner-done.ur` |
| Send 1 | **Copy as text**, save as | `sign-1-request.ur` |
| Send 2 | **Paste** the co-signer's | `sign-2-reply.ur` |

The co-signer reads a file once it is complete and deletes it after use.

## Start over with a new account

The wallet holds one FROST account per network. To run the guide again:

1. **Wallet:** under the account, click **Remove this account from the
   wallet**, then **OK** in the Windows window, which says what the account
   still holds. Nothing is deleted: the account's files move to
   `zcash_frost_removed` in the wallet's data folder
   (`%APPDATA%\com.pgpwalletpoc.app`), and moving them back restores the
   account and its funds.
2. **Co-signer:** give it a new `--state` folder: it refuses to create an
   account in a folder that already holds one. Keep the old folder if coins
   are left on the old account.

## After a lost device

The protocol never repairs an account: the two remaining members create a new
one and move the funds to it (spec § 7.2). With the test co-signer:

- **The wallet's computer is lost:** a new coordinator restores member 3 from
  its backup and pairs with the co-signer, which describes the old account;
  the new coordinator checks it against the backup before it goes on. Then the
  old account's funds are swept to the new one, signed by member 3 and the
  co-signer:

  ```bash
  frost-zec qr recover --as cosigner --state new-cosigner --old-state my-cosigner --via clipboard
  frost-zec qr recover --as coordinator --network test --state new-wallet --old-state restored       --backup member3.zkfrost --via clipboard
  ```

  The wallet's own screens for this come later; until then this is a test of
  the protocol, between two `frost-zec` processes.
- **The co-signer is lost:** the coordinator restores member 3 and signs the
  sweep with members 1 and 3 itself:
  `frost-zec qr sign-local --state my-wallet --backup member3.zkfrost --pczt sweep.pczt --out signed.pczt`.

Keep member 3 as a backup file (`frost-zec backup protect`): it holds the
account's viewing key too, so a co-signer cannot describe another account.

## If something goes wrong

- **Windows blocks the co-signer** ("Smart App Control blocked a potentially
  dangerous file"): a program or script downloaded unsigned is blocked.
  Right-click the archive, **Properties**, tick **Unblock**, then extract it
  again; or build the co-signer from source.
- **The codes differ:** both sides cancel the setup. Do not start again at
  once: find out what else could read or change the messages first.
- **The account says the setup is not finished** (the wallet was closed before
  the co-signer's last message): click **Finish the setup…** on the card,
  enter your password, and paste the co-signer's acknowledgement. To show it
  again, run `frost-zec qr done --state my-cosigner --via clipboard`. If the
  co-signer never got the wallet's last message (it showed no address), remove
  the account and set it up again (see "Start over with a new account").
- **"This message comes from a co-signer of an earlier version":** the
  co-signer speaks spec v0.1. Build it again from this repository.
- **The co-signer's network differs** ("the coordinator set up the group for
  another network"): start the co-signer with the `--network` of the account
  being created (`test` for **Create on testnet**).
- **The co-signer says "no seat"** when signing: its `--state` folder is not
  the one used to create the account, or the setup never finished. Use the
  folder from step 1.
- **The wallet finds no co-signer message on the clipboard:** wait for the
  beep, or press Enter in the co-signer's window to copy its last message
  again.
- **Sync fails:** the wallet shows the server's error under the account. On
  testnet there is one public server, which sometimes lags; try again later.
- **The last setup step fails** (network, wrong password): fix the cause and
  paste the co-signer's keys again (Enter in its window copies them again);
  the pairing is kept.
- **The co-signer refuses a request:** it prints why. Do not override it.

## What to report

For Milestone 1, please send the transaction id(s) (the wallet's **Copy the
transaction ID** button), the network, how long each part took, and anything
in this guide that was unclear or wrong.
