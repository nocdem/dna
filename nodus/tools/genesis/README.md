# Genesis ceremony template (cometbft chain, genesis document version 5)

This directory holds the **template** for the chain's genesis config, the
script that checks a filled-in copy, and this note on how to use them.

| File | What it is |
|---|---|
| `testnet_v3.conf.template` | The genesis config with every number from the tokenomics decision filled in and every key, identity and ceremony value left as a `REPLACE_ME_<WHAT>` marker. |
| `check_genesis_conf.sh` | Refuses a config that is not ready: unfilled markers, a supply sum that does not balance, an amount or fee parameter that differs from the decision, a bad key or fingerprint shape, a validator whose destination is not the Foundation multisig address it recomputes from the Foundation keys. Optionally derives the chain in a throw-away directory and prints its chain id. |

Every number in the template comes from
`docs/plans/decisions/2026-09-22-nodus-tokenomics-v3-operator.md` §1 and
`docs/plans/decisions/2026-09-28-treasury-pools-and-exact-self-stake.md`
(the two fee parameters from `2026-09-25-gas-price.md` and
`2026-09-28-token-create-fee-governance.md`), and the template's comments
name the sentence each one comes from.

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
| `REPLACE_ME_5184_ZEROS` | On every genesis validator's `unstake_destination_pubkey`: 5184 `0` characters (`printf '0%.0s' $(seq 5184)`). The destination is a multisig address that no single key opens; the parser still requires the field, and on a genesis row it MUST be all zero (decision ONAY 2 — the derivation and the check script both refuse anything else). |
| `REPLACE_ME_FOUNDATION_MULTISIG_ADDRESS` | On every genesis validator's `unstake_destination_fp`, the SAME value: the Foundation's M-of-N multisig address, 128 lowercase hex (decision `2026-09-29-general-multisig.md`: the seven genesis validators' 10M returns to the Foundation multisig address). Print it with `nodus-cli msig address --m <M> --pubkey <key1>/nodus.pk --pubkey <key2>/nodus.pk ...` (the key order does not matter — the tool sorts them). `check_genesis_conf.sh` recomputes it from the same keys and refuses any validator block — and any of the five `[genesis_output]` blocks, whose `owner` is the same marker — that differs. |
| `REPLACE_ME_FOUNDER_DEST_BINDING` | SHA3-512 of the public key that will claim the Founder allocation, 128 lowercase hex (a `nodus.fp` value). Only that key can ever claim it. The nine treasury pools have NO key and no marker. |

Two values are **placeholders, not policy**, and the operator should
decide them before the ceremony:

- `commission_bps = 500` on every validator — the commission is each
  validator's own choice (at most 5000 = 50 %). 500 is simply the value
  the harness writes.
- `initial_height = 1` — 0 and 1 both start the chain at height 1 but
  give different chain ids. 1 is what the harness writes.

`self_stake` is **not** a choice: every validator's is exactly
`1000000000000000` raw (10M NODUS). The script refuses any other value —
less or more — as the builder's Rule P.1 does, and the chain's STAKE rule
accepts only this amount too (decision
`2026-09-28-treasury-pools-and-exact-self-stake.md` item 5, final
pre-testnet wipe package W-B). A validator that wants more weight
delegates to itself after the chain starts (`nodus-cli v2-envelope
delegate`, its own key as `--validator`, item 6).

## The two fee parameters governance can change

Final pre-testnet wipe, package W-C. The template writes two values that
start the chain with its fee rules and that the committee can later
change by a governance vote (a `CHAIN_CONFIG` proposal; each change waits
the ERGONOMIC 720-block grace before it applies):

| Key | Value | Decision |
|---|---|---|
| `gas_price_raw_per_unit` | `121` raw per declared gas unit (range 0..1 000 000; 0 switches the gas rule off) | `docs/plans/decisions/2026-09-25-gas-price.md`, "Son wipe paketi" |
| `token_create_fee_raw` | `100000000000` raw = 1 000 NODUS per token creation (range 10^8..10^15) | `docs/plans/decisions/2026-09-28-token-create-fee-governance.md` |

Both are part of the hashed document (so they are part of the chain id)
and each becomes a `chain_config_history` row effective at height 0
(chain-config parameters 5 and 6). The parser accepts a file without them
and fills in these same values; the check script requires them written
out so the operator sees what the chain id binds. A value outside the
range is refused by the derivation.

## The treasury pools, the genesis outputs and the one allocation

Governing records: `docs/plans/decisions/2026-09-28-treasury-pools-and-exact-self-stake.md`
(final pre-testnet wipe, package W-A) and
`docs/plans/decisions/2026-09-29-general-multisig.md` (ONAY and ONAY 2).
The document is `config_version = 5`.

- The reward reserve (200M) is `reward_pool_initial`, not an allocation.
- **Founder (50M) is the ONLY allocation** — one `[allocation]` block,
  `source_id` ordinal 1 (zero-padded to 128 characters), claimable by the
  key in its `dest_binding` (decision §Karar 3).
- **The service pools 1-4 are keyless, locked treasury pools** — the
  file still carries EXACTLY nine `[treasury]` blocks (`pool_id`,
  `balance`, pool order 1..9); nobody holds a key to them; the chain
  commits them in `v2_treasury` (a leg of the SYSTEM state root). There
  is NO exit rule yet — the operator parked it on 2026-09-28.
- **The Foundation's pools 5-9 are GENESIS OUTPUTS** — their treasury
  rows hold 0, and five `[genesis_output]` blocks (`owner`, `amount`) at
  the end of the file make them coins from height 0, owned by the
  Foundation MULTISIG ADDRESS and spent with M of its keys. Their ORDER
  is part of the chain: each coin's identity is
  SHA3-512(`"NDS.GENOUT.v1"` ‖ source_commit ‖ index), index = the
  block's 0-based position in the file.

| pool | NODUS | where |
|---|---|---|
| 1 Storage | 100 000 000 | treasury row |
| 2 Compute | 100 000 000 | treasury row |
| 3 VPN / Bandwidth | 50 000 000 | treasury row |
| 4 Future services | 50 000 000 | treasury row |
| 5 Security / bug bounty | 50 000 000 | genesis output index 0 |
| 6 Liquidity / market making | 150 000 000 | genesis output index 1 |
| 7 Ecosystem / developer grants | 100 000 000 | genesis output index 2 |
| 8 Foundation (100M minus the 7 × 10M genesis validator stakes) | 30 000 000 | genesis output index 3 |
| 9 Community airdrop | 50 000 000 | genesis output index 4 |
| **total** | **680 000 000** | 300M treasury + 380M genesis outputs |

200 reserve + 70 validator stake + 50 Founder + 300 in the treasury +
380 in genesis outputs = 1 000 million NODUS (Rule P.2).

When a **genesis** validator retires, its 10M is released — as a locked
coin, like any validator's — to its `unstake_destination_fp`, which for
all seven is the **Foundation multisig address** (decision
`2026-09-29-general-multisig.md`, which replaced the earlier "refund into
treasury pool 8" rule; that stake came out of the Foundation's 100M).
The Foundation spends it with M of its keys (`nodus-cli msig ...`,
auth_kind 3). A validator that joins later with its own 10M gets it back
to its own address as before.


## The Foundation multisig address

The chain derives an M-of-N address as SHA3-512 of the descriptor
`"NDS.MSIG.v1"` (16 bytes, zero-padded) ‖ M ‖ N ‖ the N public keys in
ascending byte order (`shared/dnac/msig_wire.h`; 2 ≤ N ≤ 7, 1 ≤ M ≤ N).
The initial Foundation set is 2-of-3 (decision). Step by step:

```sh
nodus-cli msig address --m 2 \
    --pubkey keyA/nodus.pk --pubkey keyB/nodus.pk --pubkey keyC/nodus.pk \
    --descriptor-out foundation.desc
```

prints `msig 2-of-3 address <128 hex>` — the value for
`REPLACE_ME_FOUNDATION_MULTISIG_ADDRESS` — and keeps the descriptor the
Foundation needs later to spend (`v2-envelope spend --msig
foundation.desc ...`, then `msig sign` per key holder and `msig combine`).
Changing the key set is a transfer to a NEW multisig address; there is no
separate rotation operation.

(The decision file's "Toplam 730M" is the nine pools PLUS the 50M Founder
allocation; the nine pools alone total 680M — 300M treasury rows plus
380M genesis outputs.)

## Steps

1. Copy the template: `cp testnet_v3.conf.template genesis.conf`.
2. Replace every `REPLACE_ME_` marker; decide the two placeholders.
3. Check it:

   ```sh
   ./check_genesis_conf.sh genesis.conf --cli /path/to/nodus-cli \
       --foundation-m 2 --foundation-pubkey keyA/nodus.pk \
       --foundation-pubkey keyB/nodus.pk --foundation-pubkey keyC/nodus.pk
   ```

   Exit 0 means every check passed. Every failure is printed — with its
   line number for a marker, or with the validator / allocation index for
   a block check. The Foundation arguments are REQUIRED: the script
   recomputes the Foundation multisig address from those keys and M
   (through `nodus-cli msig address`, the chain's own encoder) and
   refuses any validator whose `unstake_destination_fp` differs —
   without them it fails rather than skipping the check.
4. Check it again with a trial derivation, using the `nodus-server` that
   will run the chain (it must be built with the production constants —
   the derivation refuses a config whose `epoch_length`,
   `blocks_per_year` or `decimal_unit` differ from the build's):

   ```sh
   ./check_genesis_conf.sh genesis.conf --cli /path/to/nodus-cli \
       --foundation-m 2 --foundation-pubkey ... \
       --derive /path/to/nodus-server
   ```

   This runs `nodus-server --derive-v2-genesis genesis.conf -d <tmp>` in a
   fresh temporary directory, prints `chain-id <64 hex>`, and deletes the
   directory. It writes nothing anywhere else. The derivation is the
   authority on the rules the script cannot see (every genesis rule of
   the builder). Since general multisig the derivation checks the
   validators' destination address by SHAPE only — its meaning (the
   Foundation address) is the script's check above, nobody else's.
5. Copy the one checked file to every node and derive there, per
   `nodus/docs/BOOTSTRAP.md`. Compare the printed chain ids.

## What the check script does not prove

- It does not verify that a key is a valid ML-DSA-87 key — `--derive`
  does not either for the Foundation keys (they never reach the
  document; only their address does). A wrong Foundation key file yields
  a different address, and every validator block then fails the
  comparison — but a key the Foundation does not actually hold would
  pass: which files are the Foundation's keys is the ceremony's trust
  input.
- It checks amounts against the decisions as written (tokenomics
  2026-09-22 §1; treasury pools 2026-09-28). If a decision file changes,
  the script's tables must change with it.
