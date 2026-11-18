# Standing policy for the co-signer

`cosign` and `qr sign --as cosigner` take an optional `--policy FILE`. The co-signer then checks every payment against the file's rules before it asks you. A payment that breaks a rule is refused at once: you are not asked, no share leaves the device, and the coordinator gets the reason. A payment that keeps every rule is shown and asked about exactly as without a policy. A policy only narrows what can be signed; it never signs on its own.

Without `--policy`, nothing changes.

## The file

```json
{
  "network": "test",
  "name": "agent wallet",
  "per_payment_cap_zat": 20000000,
  "max_fee_zat": 30000,
  "allowed_recipients": [
    { "label": "shop", "address": "utest1..." }
  ]
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `network` | yes | `main`, `test` or `regtest`. A policy for another network than the group's stops `cosign` and `qr sign` when they load it. |
| `name` | no | A name for you; not checked. |
| `per_payment_cap_zat` | no | The most one payment may move, in zatoshis. A payment is everything one transaction pays out of the group, summed over its outputs, since one signature approves them all. Change back to the group does not count. |
| `max_fee_zat` | no | The largest fee, in zatoshis. The signer's own checks already bound the fee by ZIP 317; this can set it lower. |
| `allowed_recipients` | no | When present, every payment must go to one of these addresses. Each needs an Orchard receiver. `label` is optional. |

At least one of the three rules must be set. A field the co-signer does not know, such as a daily budget, makes the file fail to load: a rule that is not enforced must not look as if it were. Addresses in the allow-list must be unified addresses for the policy's network, each with an Orchard receiver: payments only ever go to an Orchard receiver (the one Ironwood notes are sent to), so an entry without one could never match.

## How a recipient is matched

The co-signer pays one receiver, and it judges that receiver, never the address the PCZT names for display. An allow-list entry matches when its Orchard receiver is the paid receiver, with the same bytes. A receiver of another kind never matches, even with the same bytes. So you can list a recipient's full address as their wallet gives it, and a payment to any address that does not hold that exact receiver is refused, even one that shares another of its receivers.

## What it does not do

The rules read nothing but the transaction in front of them. There is no daily budget and no record of past payments, so a coordinator can send many payments under the cap one after another; each still goes to you unless `--yes` is set. Keep `--yes` for tests.
