# Refusal classes

The shared tamper cases in this directory name what a signer refuses with one
of these classes. Each signer maps its own errors to them. A change can fit
two classes (extra actions raise the fee too, an unreadable output is also not
shown), and signers run their checks in different orders, so a case lists its
classes, primary first, and a refused PCZT passes if it is refused with any of
them.

| Class | Meaning |
|---|---|
| `payment` | a recipient, amount or memo that differs from the approved payment |
| `foreign-spend` | a spend that is not under the group's key |
| `foreign-pool` | a part in a pool the signer does not decode |
| `unreadable-output` | an output the group cannot decrypt or read back |
| `hidden-output` | an output that would be signed without being shown |
| `change` | change paid to a receiver that is not the group's |
| `fee` | a fee above the rule for the height and the actions needed |
| `padding` | more actions than the payments need |
| `expiry` | a transaction that never expires, or expires too far ahead |
| `structure` | a dummy spending key left, a witness that misses the anchor, a zero or repeated randomizer, a missing field |
| `sighash` | a signing message that is not the sighash the signer computed |
| `equivocation` | a second, different transaction for the same approval |

The format of a case is in [docs/spec.md](../../docs/spec.md), § 8.2.

New cases go to the maintainers listed in
[frost-zec#7](https://github.com/OpenPGP-Wallet/frost-zec/issues/7) first,
through this repository's private vulnerability reporting, and are published
after 14 days or once every listed signer passes them.
