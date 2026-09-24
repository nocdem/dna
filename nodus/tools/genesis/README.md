# Genesis ceremony template (version-3 / cometbft chain)

This directory holds the **template** for the chain's genesis config, the
script that checks a filled-in copy, and this note on how to use them.

| File | What it is |
|---|---|
| `testnet_v3.conf.template` | The genesis config with every number from the tokenomics decision filled in and every key, identity and ceremony value left as a `REPLACE_ME_<WHAT>` marker. |
| `check_genesis_conf.sh` | Refuses a config that is not ready: unfilled markers, a supply sum that does not balance, an amount that differs from the decision, a bad key or fingerprint shape. Optionally derives the chain in a throw-away directory and prints its chain id. |

Every number in the template comes from
`docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-operator.md` §1, and
the template's comments name the sentence each one comes from.

## The result is the chain's identity

The chain id is a hash of the genesis document derived from this file.
One byte different — a different time, a different key, a different
commission, a reordered block — is a **different chain**. So:

- The file is filled in **once**, checked **once**, and the **same file,
  byte for byte**, is copied to every node. It is never re-typed per node.
  This is exactly what the Genesis Protocol harness does
  (`nodus/tests/integration/stagef/stagef_up_v2.sh` writes one config and
  every node derives from it).
- Before starting anything, compare the `chain-id` every node printed.
  They must all be identical.

## What the operator must supply

The template holds no key and no fingerprint. Filling it in needs the
operator's keys:

| Marker | What goes there |
|---|---|
| `REPLACE_ME_GENESIS_TIME_MS` | The start time, UTC milliseconds since the Unix epoch. Chosen once; the derivation never reads a clock. |
| `REPLACE_ME_VALIDATOR_<n>_PUBKEY` | Validator *n*'s ML-DSA-87 public key: 2592 bytes as 5184 lowercase hex. On a node this is the identity's `nodus.pk`, e.g. `xxd -p -c 99999 identity/nodus.pk`. |
| `REPLACE_ME_VALIDATOR_<n>_UNSTAKE_DESTINATION_PUBKEY` | The payout key the validator's 10M self-bond is released to when it retires (5184 lowercase hex). |
| `REPLACE_ME_VALIDATOR_<n>_UNSTAKE_DESTINATION_FP` | SHA3-512 of that payout key, 128 lowercase hex. For a node identity used as its own payout key this is the identity's `nodus.fp`. The derivation refuses a fingerprint that does not derive from the payout key. |
| `REPLACE_ME_<POOL>_DEST_BINDING` | SHA3-512 of the public key that will claim the pool, 128 lowercase hex (a `nodus.fp` value). Only that key can ever claim the pool. |

Two values are **placeholders, not policy**, and the operator should
decide them before the ceremony:

- `commission_bps = 500` on every validator — the commission is each
  validator's own choice (at most 5000 = 50 %). 500 is simply the value
  the harness writes.
- `initial_height = 1` — 0 and 1 both start the chain at height 1 but
  give different chain ids. 1 is what the harness writes.

## The ten pools

The reward reserve (200M) is `reward_pool_initial`, not an allocation.
The ten allocations use `source_id` 1..10, zero-padded to 128 characters,
in the order of the decision's table. These ids are this template's
choice, documented here and in the template; they are committed into the
genesis document.

| id | pool | NODUS |
|---|---|---|
| 1 | Storage | 100 000 000 |
| 2 | Compute | 100 000 000 |
| 3 | VPN / Bandwidth | 50 000 000 |
| 4 | Future services | 50 000 000 |
| 5 | Security / bug bounty | 50 000 000 |
| 6 | Liquidity / market making | 150 000 000 |
| 7 | Founder | 50 000 000 |
| 8 | Ecosystem / developer grants | 100 000 000 |
| 9 | Foundation (100M minus the 7 × 10M validator stakes) | 30 000 000 |
| 10 | Community airdrop | 50 000 000 |

200 reserve + 70 validator stake + 730 in the pools = 1 000 million NODUS.

## Steps

1. Copy the template: `cp testnet_v3.conf.template genesis.conf`.
2. Replace every `REPLACE_ME_` marker; decide the two placeholders.
3. Check it:

   ```sh
   ./check_genesis_conf.sh genesis.conf
   ```

   Exit 0 means every check passed. Every failure is printed — with its
   line number for a marker, or with the validator / allocation index for
   a block check.
4. Check it again with a trial derivation, using the `nodus-server` that
   will run the chain (it must be built with the production constants —
   the derivation refuses a config whose `epoch_length`,
   `blocks_per_year` or `decimal_unit` differ from the build's):

   ```sh
   ./check_genesis_conf.sh genesis.conf --derive /path/to/nodus-server
   ```

   This runs `nodus-server --derive-v2-genesis genesis.conf -d <tmp>` in a
   fresh temporary directory, prints `chain-id <64 hex>`, and deletes the
   directory. It writes nothing anywhere else. The derivation is the
   authority on the rules the script cannot see (the payout fingerprint
   really being the hash of the payout key, and every other genesis rule).
5. Copy the one checked file to every node and derive there, per
   `nodus/docs/BOOTSTRAP.md`. Compare the printed chain ids.

## What the check script does not prove

- It does not verify that a fingerprint is the hash of its key, or that a
  key is a valid ML-DSA-87 key — `--derive` does.
- It checks amounts against the decision as written on 2026-09-22. If the
  decision file changes, the script's table must change with it.
