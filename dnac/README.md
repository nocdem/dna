# DNAC — Nodus Chain Client Library

**Version:** v0.20.1 (`dnac/include/dnac/version.h`)

DNAC is the **client side** of **Nodus Chain** (formerly "DNA Chain") — the
post-quantum UTXO blockchain whose coin is NODUS, a public testnet since
30 September 2026. This library builds wallets and transactions and talks to
the validators. It does **not** run consensus: the chain's consensus is
embedded in `nodus-server`.

> **⚠ Transfers on the testnet.** The live (version-3) chain accepts only
> multi-leg **envelope** transactions. This library's transaction builders
> produce the older DNAC transaction format described below, and nothing under
> `dnac/` or `messenger/` builds an envelope yet — so `dna-connect-cli dna send`
> and the other building commands cannot move NODUS on the testnet. Today a
> transfer is made with the web wallet (`web-wallet/`) or with
> `nodus-cli v2-envelope spend` (`nodus/README.md`).

The chain is implemented in three layers of the monorepo:

| Layer | Location | Contents |
|---|---|---|
| **Client** (this directory) | `dnac/` | Wallet, UTXO management, TX builders, witness RPC client, client-side chain verification |
| **Canonical codecs** | `shared/dnac/` | Wire formats compiled byte-identical into both the client (`libdna`) and the validator (`libnodus`); also the CometBFT v0.38.26 port (`cmt_*`, validator side only) |
| **Consensus** | `nodus/src/witness/` | The validator embedded in `nodus-server`: Ledger V2 engine + CometBFT host (see `nodus/README.md`) |

## Features (client-side)

- **UTXO model** with per-token UTXO tracking and multi-token balances
- **Dilithium5 (ML-DSA-87) signatures** — NIST Category 5, post-quantum
- **Witness-only architecture** — all chain state lives on the BFT
  witnesses; the wallet syncs via RPC (`dna sync`), no DHT storage of
  chain state
- **TX builders** for every type of the older DNAC transaction format
  (not accepted as a transfer by the version-3 testnet — see the note at
  the top): SPEND, BURN,
  TOKEN_CREATE, STAKE, UNSTAKE, DELEGATE, UNDELEGATE,
  VALIDATOR_UPDATE, CHAIN_CONFIG (committee-voted hard-fork parameters —
  **R3 W4-C delta 2, operator "kaldır" 2026-09-18:** parameter id 1
  (`MAX_TXS_PER_BLOCK`) is RETIRED from the governed set and refused
  unconditionally by the witness's vote rules; a block's capacity is
  bytes and units only now (cometbft's own `Block.MaxBytes`, the meter
  policy's per-block byte/unit budgets, and the engine's own derived
  memory ceiling on envelope-scratch allocation — never a governed
  count). **tokenomics-v3 P2 (2026-09-24):** parameter id 3
  (`INFLATION_START_BLOCK`) is RETIRED the same way — the per-block mint
  it scheduled is deleted, and both the witness's vote rules and this
  library's mirror (`dnac/src/transaction/verify.c`) refuse it. Id 4
  (TARGET_ACTIVE_COUNT) is unaffected; ids never renumber and a retired
  id is never reused. **dnac 0.18.13 / nodus 0.20.3:** a CHAIN_CONFIG
  proposal is accepted only for a parameter the RUNNING consensus reads
  — the one list is `dnac_cfg_param_read_by_consensus`
  (`dnac/include/dnac/dnac.h`), consumed by both the witness's scalar
  rules and this library's mirror: ids 4 and 5 at 0.20.3 (4 through 15
  today — below). Id 2
  (`BLOCK_INTERVAL_SEC`) is refused — the Comet lane's block pace is a
  compile-time node setting and never reads it — but it is NOT retired:
  the number and its [1, 15] definition stay, and a consensus that reads
  the block interval makes it votable again (decision
  `docs/plans/decisions/2026-09-23-height-activated-upgrades-before-testnet.md`
  item 1). Already-committed id-2 rows stay readable. **HF-1 (dnac 0.18.12 /
  nodus 0.19.80):** id 5 `GAS_PRICE_RAW_PER_UNIT`
  (`DNAC_CFG_GAS_PRICE_RAW_PER_UNIT`, range [0, `DNAC_CFG_MAX_GAS_PRICE`
  = 1 000 000] raw per declared gas unit, 0 = rule off) — the witness
  refuses an envelope with a non-SYSTEM leg that pays less than
  `max(units × price, floor)` from the row's effective height; the
  mirror in `verify.c` applies the same range. Id 6
  `TOKEN_CREATE_FEE_RAW` (final pre-testnet wipe W-C) is on the read list
  too. **HF-2 (2026-09-30, design
  `docs/plans/2026-09-30-gov-weight-netzero-design.md` rev 2):** id 7
  `HF2_ACTIVE` (`DNAC_CFG_HF2_ACTIVE`, value EXACTLY
  `DNAC_CFG_HF2_ACTIVE_ON` = 1 — a one-way switch, 0 and every other
  value refused by both the witness's scalar rules and the `verify.c`
  mirror; ERGONOMIC grace). From the row's effective height the witness
  weighs a CHAIN_CONFIG approval by VOTING POWER (approving power > 2/3
  of the governing committee's, power = stake / 10^8) instead of by seat
  count, and a block whose touched domain's root nets to zero is applied
  instead of halting every node; no row = both rules as before.
  **HF-3 (2026-10-02, design
  `docs/plans/2026-10-01-hf3-comet-block-bounds-design.md` rev 3; decision
  `docs/plans/decisions/2026-10-01-hf3-comet-only-block-bounds.md`):** id 8
  `HF3_ACTIVE` (`DNAC_CFG_HF3_ACTIVE`, value EXACTLY
  `DNAC_CFG_HF3_ACTIVE_ON` = 1 — the same one-way switch, 0 and every
  other value refused by both the witness's scalar rules and the
  `verify.c` mirror; ERGONOMIC grace); `DNAC_CFG_PARAM_MAX_ID` 7 → 8.
  From the row's effective height the witness bounds a block by the
  cometbft consensus params only — the 2 MiB envelope-byte bound is not
  checked, the global unit budget and every quota-0 domain's unit budget
  are unbounded, a declared `res_max_total_units` above `INT64_MAX` is
  refused, and the block proposal itself is checked for the gas price and
  for already-committed envelopes; no row = every rule as before. No wire
  change for wallets: the transaction format, the fee rule they pay and
  the ruleset pins are unchanged. **HF-4 (dnac 0.19.5 / nodus 0.23.10,
  design `docs/plans/2026-10-02-onchain-names-design.md` rev 4; decision
  `docs/plans/decisions/2026-10-02-onchain-names.md`):** id 9
  `RULESET_GEN2` (`DNAC_CFG_RULESET_GEN2`) — the rule-set upgrade vote:
  its value domain is EXACTLY `DNAC_CFG_RULESET_GEN2_D2`
  (`0x44dfbe7ad3c75adf` = 4962894749133920991 — the first 8 bytes of a
  SHA3-512 over the tag `NDS.RSGEN.v1`, the generation number 2, the
  generation-2 SYSTEM and CORE ruleset hashes and
  `DNAC_RULESET_SWITCH_SPEC_VERSION` = 1, top bit cleared), so the vote
  names the rule set it switches to; ERGONOMIC grace. From the row's
  effective height H the validators judge every block under rule-set
  generation 2 (SYSTEM v7 / CORE v5), whose CORE adds op 8
  NAME_REGISTER (on-chain names). Ids 10-13 `NAME_PRICE_3P` /
  `NAME_PRICE_4P` / `NAME_PRICE_5P` / `NAME_PRICE_6P` — the price, in raw
  units, of a 3- / 4- / 5- / 6+-character name; range
  [`DNAC_CFG_MIN_NAME_PRICE`, `DNAC_CFG_MAX_NAME_PRICE`] = [10^8, 10^15]
  raw = [1, 10 000 000] NODUS; compiled no-row defaults
  `DNAC_NAME_PRICE_3P_DEFAULT` … `_6P_DEFAULT` = 1 000 / 500 / 100 / 1
  NODUS; ERGONOMIC grace. `DNAC_CFG_PARAM_MAX_ID` 8 → 13. The `verify.c`
  mirror applies only the SCALAR half (id 9 = exactly D2; ids 10-13 the
  range): the witness's stateful rules — id 9 single use, HF-2 active at
  the vote, H−1 not an epoch boundary; ids 10-13 only while generation 2
  judges the vote — need chain state this library does not have. Two
  inline helpers in `dnac.h` are the one definition the validator and
  every client share: `dnac_name_bytes_ok(name, len)` (3..36 bytes —
  `DNAC_NAME_MIN_LEN` / `DNAC_NAME_MAX_LEN` — each `a-z` or `0-9`,
  uppercase refused, a name made only of `0-9a-f` with length ≥
  `DNAC_NAME_HEXLIKE_MIN_LEN` = 8 refused; 1 legal / 0 refused) and
  `dnac_name_price_for_len(p[4], len)` (the monotonic fold of the four
  tiers: 3 = max(P3..P6), 4 = max(P4..P6), 5 = max(P5, P6), 6+ = P6; 0
  outside 3..36). Nothing under `dnac/` builds a NAME_REGISTER — it is a
  version-3 envelope (`nodus-cli name register`, `nodus/README.md`).
  **Nodus EVM / HF-5 (dnac 0.20.0 / nodus 0.24.0, design
  `docs/plans/2026-10-04-nodus-evm-chain-integration-design.md` rev 3 §8-§9;
  decisions `docs/plans/decisions/2026-10-04-nodus-evm-domain.md`,
  `2026-10-05-hf-numbering-evm-hf5.md`):** id 14 `EVM_ACTIVE`
  (`DNAC_CFG_EVM_ACTIVE`) — the vote that registers the EVM domain and
  switches SYSTEM / CORE to rule-set generation 3 at the end of block
  H−1; its value domain is EXACTLY `DNAC_CFG_EVM_ACTIVE_D`
  (`0x029f47596864d407` = 188948158701949959 — the first 8 bytes of a
  SHA3-512 over the tag `NDS.EVMACT.v1`, the EVM generation and its base,
  the generation-3 SYSTEM / CORE / EVM (ruleset v2) ruleset hashes, the
  EVM manifest hash, `DNAC_EVM_ACTIVATION_SPEC_VERSION` = 1 and the
  compiled EVM constants — since Kurultay #9 (2026-10-06) the last one is
  the EVM address width, 32 — top bit cleared). ⚠ That literal is SELF-DERIVED by the
  implementing agent (`shared/dnac/tests/nodus_evm_activation_oracle.py`), not an
  independent pin (`dnac.h` comment above the define); the validator
  re-derives it on every start of an EVM build. SAFETY grace. Id 15
  `EVM_BLOCK_GAS_LIMIT` (`DNAC_CFG_EVM_BLOCK_GAS_LIMIT`) — the bound on a
  block's summed declared EVM gas and the EVM block environment's
  GASLIMIT: range [`DNAC_CFG_MIN_EVM_BLOCK_GAS`,
  `DNAC_CFG_MAX_EVM_BLOCK_GAS`] = [10^6, 10^9], no-row default
  `DNAC_EVM_BLOCK_GAS_LIMIT_DEFAULT` = 30 000 000 — all three PLACEHOLDERS
  until the measurement gate; SAFETY grace. `DNAC_CFG_PARAM_MAX_ID` 13 →
  15. The `verify.c` mirror (`verify_chain_config_rules`, cases
  `DNAC_CFG_EVM_ACTIVE` / `DNAC_CFG_EVM_BLOCK_GAS_LIMIT`) applies only the
  SCALAR half — id 14 = exactly D, id 15 the range; the witness's stateful
  rules (id 14 single use, HF-2 and HF-3 active, a non-zero gas price
  active, the registry at generation 2, H−1 not an epoch boundary, H ≥
  the chain's initial height + 256) need chain state this library does
  not have. Nothing under `dnac/` builds an EVM transaction — it is a
  version-3 envelope (`nodus-cli evm`, `nodus/README.md`; the web wallet's
  smart-contract panel, `web-wallet/README.md` "Smart contracts").
  The read list is therefore ids 4 through 15), GENESIS
- **Explicit committed fee** on the wire (v2 header) with a min-fee
  gate. **Since tokenomics-v3 P2 every fee goes to the chain's REWARD
  POOL** (`supply_tracking.reward_pool`) — it is neither burned nor paid
  to the block's proposer; the pool pays the stakers (below). Only an
  explicit BURN's `burn_amount` leaves circulation.
- **Rewards (tokenomics-v3 P2).** No coin is ever minted: genesis reserves
  a fixed pool (`reward_pool_initial`, 200M NODUS by default — Rule P.2:
  allocations + self-stake + pool = total supply) and every fee refills
  it. At each epoch boundary `pool >> 16` is shared among the validators
  of the ended epoch in proportion to their voting power; a validator that
  missed the participation bar forfeits its whole share, delegators
  included. Inside a share the validator keeps the part earned by its own
  bond plus its commission; delegators share the rest by their stake as
  it stood when that epoch's validator set was chosen (the frozen balance
  copy the set was built from — stake keeps earning until it leaves the
  voting power, and a withdrawal is locked long past that, so money
  cannot be pulled out, used and put back within an epoch). Rewards accrue on the
  chain and are paid as ordinary spendable coins every
  `payout_interval_epochs` boundaries (24 by default — a payday), including
  to a delegator that has since left. Every rounding remainder stays in
  the pool.
- **Staking parameters (tokenomics-v3 P3, version-3 chain).** Self-stake
  exactly 10M NODUS, neither less nor more; up to 32 validators are seated, chosen by the
  highest self-stake + delegations as frozen one boundary earlier (status
  and the 2-epoch tenure read live); others wait bonded but unseated.
  A validator's bond is locked 84 epochs after it leaves the set, a
  delegator's withdrawal 12 epochs after its stake leaves voting power
  (the same lock for everyone). A validator may exit even with
  delegators — at graduation every delegation is returned automatically,
  locked 12 epochs — and may stake again with the same key after it has
  graduated. New delegations need at least 100 NODUS; a partial
  withdrawal must leave 0 or at least 100 NODUS; up to 2048 delegators
  per validator. Commission is capped at 50%; an increase takes effect
  two epochs later, a decrease at once.
- **Lock-aware coin selection** — the wallet skips UTXOs still inside
  their post-UNSTAKE cooldown (`unlock_block`), so it never builds a
  transaction consensus is guaranteed to reject
- **Memo support** (up to 255 bytes), **name resolution** (send to a DNA
  name, auto-resolved to a fingerprint), **replay prevention**
- **Client-side verification** — Merkle inclusion proofs, block/anchor
  verification, chain-definition decoding (`src/ledger/`). The UTXO leaf
  the client recomputes (`dnac_utxo_compute_leaf_hash`) is 340 bytes
  since the root-layout round (dnac 0.18.11): nullifier ‖ owner(128,
  NUL-padded) ‖ amount u64 LE ‖ token_id ‖ tx_hash ‖ output_index u32 LE
  ‖ **unlock_block u64 LE** — byte-identical to the node's
  `nodus_witness_merkle_leaf_hash`. A current witness sends every
  `dnac_utxo` entry with a depth-0 proof and an all-zero root (the
  legacy state root it anchored to is deleted), so wallets store coins
  unverified, as they already did: no code installs a verified anchor.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                dna-connect-cli  `dna` group                 │
│   (DNA Chain commands live in the unified messenger CLI —   │
│    messenger/cli/cli_dna_chain*.c; no separate binary)      │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  libdna (+ libdnac.a)                                       │
│  wallet · TX builders · witness RPC client (dnac/src/)      │
└─────────────────────────────────────────────────────────────┘
                             │  Nodus client SDK (T2, TCP 4001)
                             ▼
┌─────────────────────────────────────────────────────────────┐
│  WITNESS CLUSTER (nodus-server, embedded witness)           │
│  epoch validator set · cometbft consensus on TCP 4004       │
│  authoritative UTXO set + block storage                     │
└─────────────────────────────────────────────────────────────┘
```

All chain RPCs ride the authenticated Nodus client connection (Tier 2,
TCP 4001; AES-256-GCM after an ML-KEM-1024 or Kyber1024 round-3 key
exchange) as `dnac_*` verbs — spend, utxo, history, ledger/ledger-range,
block/block-range, tx, committee, delegations, validator-list, roster,
supply, token queries, fee info. Consensus itself — the ported CometBFT
v0.38.26 rounds (propose → prevote → precommit → commit, more than 2/3 of
the voting power of the epoch's validator-set snapshot) — runs between
validators on TCP 4004.

## Building

DNAC has **no standalone runtime**. Its sources are compiled directly
into `libdna.so` by the messenger build:

```bash
cmake -S messenger -B messenger/build && cmake --build messenger/build -j$(nproc)
```

That is the build to run; `dnac/CMakeLists.txt` still defines a separate
`libdnac.a` plus test binaries, but the project does not build that tree and
the library needs nothing from it. The CLI's `dna` command group below is compiled in
only when a `dnac/build/libdnac.a` is already present at messenger
**configure** time (`messenger/cli/CMakeLists.txt`); a default build leaves
it out.

## CLI Commands

All DNA Chain commands are subcommands of `dna-connect-cli dna`:

```bash
# Identity & info
dna-connect-cli dna info                    # Wallet info, address, connection, balance
dna-connect-cli dna address                 # Wallet address (fingerprint)
dna-connect-cli dna query <name|fp>         # Lookup identity by name or fingerprint

# Wallet
dna-connect-cli dna balance                 # Native balance
dna-connect-cli dna balance-of <name|fp>    # Balance of another address
dna-connect-cli dna utxos                   # List UTXOs
dna-connect-cli dna send <name|fp> <amount> [memo]
dna-connect-cli dna sync                    # Sync wallet from the witnesses

# History & inspection
dna-connect-cli dna history [n]             # Transaction history
dna-connect-cli dna tx <hash>               # Transaction details
dna-connect-cli dna lookup-tx <hash>        # Fetch raw TX from witnesses
dna-connect-cli dna parse-tx <file>         # Decode a serialized TX

# Tokens
dna-connect-cli dna token-create <name> <symbol> <supply>
dna-connect-cli dna token-list
dna-connect-cli dna token-info <id|symbol>

# Staking & governance
dna-connect-cli dna stake ...               # Become a validator (self-bond)
dna-connect-cli dna unstake ...
dna-connect-cli dna delegate ...
dna-connect-cli dna undelegate ...         # version-3 chain: the released coin is LOCKED
                                            # until L(h) + 12 epochs (L = the boundary where the
                                            # stake leaves voting power: next boundary + 2 epochs
                                            # since P3; tokenomics-v3 P2-10)
dna-connect-cli dna validator-update ...    # Commission change (max 50%; an increase waits 2 epochs)
dna-connect-cli dna validator-list
dna-connect-cli dna delegations
dna-connect-cli dna committee               # Current committee

# Genesis (operator)
dna-connect-cli dna genesis-prepare / genesis-create / genesis-submit

# Network
dna-connect-cli dna witnesses               # Show witness servers
```

Amounts on the CLI are raw base units (10^8 raw = 1 NODUS).

The building commands (`send`, `token-create`, `stake`, `unstake`,
`delegate`, `undelegate`, `validator-update`, `genesis-*`) produce the
older DNAC transaction format, which the version-3 testnet does not accept
(note at the top). The read-only commands have not been re-verified against
the testnet.

## Wallet Address

The wallet address is the **SHA3-512 hash of the Dilithium5 public
key** — 64 bytes, 128 hex characters, identical to the DNA Connect
identity fingerprint.

## Transaction Format (older DNAC format, v2 — since v0.17.1)

This is the format this library builds. The version-3 chain does not
accept it as a transfer: there, every entry that is not a multi-leg
envelope is classified as a genesis CLAIM
(`nodus/src/witness/nodus_witness_v2_produce.c`,
`nodus_witness_v2_classify_entry`).

Canonical layout: `dnac/src/transaction/serialize.c`; the shared tx-hash
preimage implementation is `shared/dnac/tx_wire.c::dnac_txw_legacy_tx_hash`
(one implementation for client AND witness).

```
HEADER (82 bytes)
  version:       u8 = 2 (DNAC_PROTOCOL_VERSION)
  type:          u8 (DNAC_TX_*)
  timestamp:     u64 (LE on wire, BE in preimage)
  tx_hash:       bytes[64] (SHA3-512 over the preimage)
  committed_fee: u64 BE — the fee this TX pays, explicit on the wire
BODY
  inputs:   nullifier[64] + amount + token_id[64]
  outputs:  version + recipient_fp[129] + amount + token_id[64]
            + seed[32] + memo_len + memo
  balance rule: sum(inputs) == sum(outputs) + committed_fee
  witnesses: 32B id + Dilithium5 sig + timestamp + pubkey
  signers (1..4): Dilithium5 pubkey + signature
  type-specific appended fields (STAKE / DELEGATE / CHAIN_CONFIG / ...)
  optional chain_def trailer (genesis TX only)
```

**Preimage domain separator (SEC-06):** `"DNAC_TX_V2\0"` — all preimage
integers big-endian. **Min-fee gate:** non-GENESIS TXs need
`committed_fee >= DNAC_MIN_FEE_RAW` (0.01 DNAC); the witness rejects
before signature verification.

### Transaction type map

| Type | Meaning | Status |
|---|---|---|
| 0..10 (except 8) | GENESIS(0), SPEND(1), BURN(2), TOKEN_CREATE(3), STAKE(4), DELEGATE(5), UNSTAKE(6), UNDELEGATE(7), VALIDATOR_UPDATE(9), CHAIN_CONFIG(10) | live |
| 8 | was CLAIM_REWARD — retired in the v0.16 reward redesign | reject |
| 11 (SHIELDED) | shielded transfer (STARK) | assigned, **unconditional reject** until activation |
| 12 / 13 (SHIELD / UNSHIELD) | shielded entry/exit (Wire V3 only) | assigned, **unconditional reject** |
| 14 / 15 / 16 | — | **burned — never reuse** |

Types 14, 15 and 16 are permanently unassigned. 14 was reserved and never
allocated; 15 and 16 were `V2_SCHEDULE` / `V2_READY`, the Ledger V2
activation governance types, removed with the activation ceremony in
season O15J Faz 3. The witness rejects all three by name
(`nodus/src/witness/nodus_witness_verify.c`) and the client serializer
refuses every type above 11 — the same freeze that already covers
SHIELD/UNSHIELD. Recycling a burned id would let an old signed
transaction be reinterpreted under a new meaning.

**CHAIN_CONFIG(10) is "live" on the LEGACY wire only.** On a version-3
(Ledger V2 / cometbft) chain the classifier treats every type-10 body as
a CLAIM and refuses it (`nodus_witness_v2_classify_entry`,
`nodus/src/witness/nodus_witness_v2_produce.c:75-80`) — a version-3
chain's chain-config change is a single-leg SYSTEM CHAIN_CONFIG
**envelope** instead (call v2, 41 bytes; `auth_kind` 2, committee
approvals by seat against the resolved snapshot — D-16 rev 7, W4-CC),
built and submitted by `nodus-cli chain-config propose` (collects
committee approvals over the network, verbs 40-41) or, offline, by
`nodus-cli v2-envelope chain-config --keys <dirs>`. Neither builder is
part of `dna-connect-cli` / `libdna` — both live in `nodus/tools/
nodus-cli.c`. See `nodus/README.md`'s test table (D-16 rev 7 row) and
`nodus/docs/ARCHITECTURE.md`'s W4 section for the wire and the
responder.

## Ledger V2 (the live chain)

The Nodus Chain testnet runs the **Ledger V2** architecture: a
domain-partitioned state model, multi-leg envelope transactions and the
literal C port of CometBFT v0.38.26 as consensus. The consensus side lives
entirely in `nodus-server` (see [`../nodus/README.md`](../nodus/README.md)).
There is no V1 chain any more and no migration from it: the testnet started
from a fresh genesis on 30 September 2026. On the client side:

- the canonical V2 codecs (envelope, claims, pools) live in `shared/dnac/`
  and compile into `libdna`;
- the CometBFT port (`shared/dnac/cmt_*`) compiles into `libnodus` only;
  its block, vote and commit codecs are CometBFT's own proto3 forms, with
  SHA3-512 / ML-DSA-87 / 32-byte addresses as the substitutions;
- the older DNAC transaction format above is still what this library
  builds; Wire V3 (types 11/12/13) is defined but rejected by every
  admission path;
- envelopes and genesis claims are built today by `nodus-cli v2-envelope`
  / `nodus-cli v2-claim` and by the web wallet's browser module, not by
  this library.

### Validator liveness (Rule N) — tokenomics-v3 P1

Real signature attendance, not proposer credit: every validator's
attendance is counted from cometbft's own `decided_last_commit` — only a
`BlockIDFlagCommit` vote counts (NIL and ABSENT do not). At every epoch
boundary, a bonded validator is checked against two conditions, BOTH
required, through ONE shared predicate
(`nodus_witness_v2_attendance_meets_bar`):

- **50% bar** — signed at least 50% of the epoch's blocks
  (`DNAC_LIVENESS_THRESHOLD_BPS`, 5000 bps; lowered from 80%/8000 on
  2026-09-23 — see below);
- **recency** — signed at least one block within the last 120 blocks
  (`DNAC_SETTLEMENT_ATTENDANCE_WINDOW_BLOCKS`).

**Only if it had a DUTY.** A validator is checked ONLY if it is
`ACTIVE` AND an entry of the committee snapshot that governed the epoch
just ending (the set flipped ACTIVE two epochs before this boundary,
which cometbft has used since one epoch before it) — round 5 (2026-09-23
decision record, verifier finding V-1). Every other bonded validator
(RETIRING is never scanned; ACTIVE without a duty — e.g. staked
mid-epoch — or ELIGIBLE) has its miss counter RESET to 0 instead: an
epoch without a duty breaks the chain of consecutive misses, so a
brand-new validator is never charged a miss it had no way to avoid, and
a stale counter from an unrelated earlier epoch can never combine with a
later, unrelated miss to trigger a retirement.

A validator that fails either condition in **two consecutive DUTY
epochs** (`DNAC_AUTO_RETIRE_EPOCHS = 2`) is AUTO_RETIRED — removed from
the active set at the epoch after next, its bond RETURNED in full (no
cut to principal — only slashing, a separate mechanism not yet
implemented, would ever cut a bond) — **unless the validators that
would be seated in the NEXT epoch could no longer commit a block
without their single largest member**, in which case the boundary
retires NOBODY that round: counters keep their incremented values so the
retirement fires at the first boundary where the survivors can carry it,
and the active set does not shrink. The check runs on voting power, the
same unit cometbft is told (`total_stake / 10^8` per validator): take
the set the boundary is about to freeze for the next epoch with the
retirements applied — only validators that set can actually seat, so a
fresh staker still inside its two-epoch tenure does not count — add up
its power `P`, find its largest member `max`, and allow the retirement
only if `(P − max) > P × 2 / 3` (cometbft's own integer commit
threshold). An empty next set is never allowed. Equal stakes need at
least 4 survivors (3 of 4 clears two-thirds, 2 of 3 does not); a 4-member
set where one member holds 40% fails. A floor was reinstated 2026-09-23
(reversing an earlier "no floor needed" call) once red-team review
showed the bar and the 120-block window can fail DIFFERENT validators in
the same boundary — a majority of a small committee can miss one or the
other even though the average attendance argument alone (below) says the
bar can't fail everyone by itself — and it was moved from a head count
("at least 4 bonded") to this voting-power rule the same day, because
the head count also counted stakers that could not yet be seated and
ignored how stake is spread. Two questions stay open with the operator:
the rule does not cap how MANY validators one boundary may retire in a
large set (100 equal validators, 96 retired, 4 equal left — allowed),
and if a single validator already holds a third or more of the next
set's power it allows no retirement at all.
Delegators' principal is never touched by Rule N regardless of their
validator's outcome.

**A retiring validator stays seated for one extra epoch.** RETIRING and
AUTO_RETIRED validators graduate (bond release, row → UNSTAKED) only
once their pubkey is no longer an entry of the committee snapshot taking
effect at the graduating boundary — round 5, 2026-09-23. Before this, a
validator that unstakes was still counted by cometbft as a voter for one
more epoch than the ledger tracked, and graduating it immediately let it
(and its operator) drop off the network while still owed a vote by
cometbft — a coordinated exit of a third or more of the committee in one
epoch could halt block production with no later boundary able to fix it.
An exiting validator must therefore keep its node running and signing
for one full extra epoch past requesting UNSTAKE; its bond's unlock
height (and cooldown) starts counting from the epoch it actually
graduates at, not the one in which UNSTAKE was sent.

**The SAME predicate, at the SAME rate, decides epoch rewards — including
epoch 0.** The reward distribution's participation bar
(`nodus_witness_v2_econ.c`, tokenomics-v3 P2) calls
`nodus_witness_v2_attendance_meets_bar` too, instead of a formula of its
own — a validator's payout eligibility and its ACTIVE-set membership are
now one question, not two (operator decision, 2026-09-22 record §1 line
79's parenthetical "tek kural, iki tüketici" — one rule, two consumers).
Before this, the settlement bar carried an extra `× committee_count`
factor left over from the retired PROPOSER-credit era, which made its
EFFECTIVE rate ~11% while Rule N's was 80%. A genesis-epoch carve-out
that paid every epoch-0 validator regardless of real attendance was
removed the same round (2026-09-23): it was written for the old
proposer-credit counter, which really was zero at genesis for every
honest validator, but signature-based attendance credits from block 2
onward, so epoch 0 has real, checkable attendance like any other epoch.

**Why 50%, not 80%, and why a floor rule after all.** A cometbft block
commits on MORE than two-thirds of the committee's signatures, so
average attendance across a healthy, block-producing epoch is AT LEAST
roughly 67% (about 73% in small committees) — a FLOOR, not a ceiling; the
true ceiling is 100%. What bounds `DNAC_LIVENESS_THRESHOLD_BPS` is the
WORST case: every block committing on exactly a quorum with the excluded
signers rotating, which puts every validator near ~70% by the end of the
epoch. At 80% (ABOVE that worst case) a merely-jittery, otherwise-healthy
cluster could put its ENTIRE active set below the bar in the same epoch;
two such epochs AUTO_RETIRE every validator, leaving no set to build the
next snapshot from, no block producible, and no governance transaction
able to repair it — an irreversible halt. This was measured, not
hypothesized: `test_v2_econ.c`'s `t_settlement_offline` (3 validators, no
crash, no missed block) produced "Rule N: auto-retired 3 validator(s)"
then "epoch 2160: committee is empty (count=0)" then a block FAULT, at
the old 8000 bps value. At 50%, the bar sits below that ~70% worst case
at every committee size, so the bar ALONE can no longer push the whole
set below it in one epoch — a real outage still triggers AUTO_RETIRE.
But the bar and the 120-block recency window are two DIFFERENT
conditions and can fail two DIFFERENT sets of validators in the same
boundary: a worked 7-validator example (two conditions, no crash, no
missed block) fails 5 of 7 at once. That is why Rule N carries the
voting-power floor described above — an initial "no floor needed" call,
based on the 50%-alone argument only, was reversed once this was shown.

Per-block attendance counts (`v2_attendance`, keyed by the validator's
32-byte cometbft address) live OUT OF the ledger's canonical validator
record — they are a bookkeeping table, not part of consensus state,
except through a once-per-epoch digest that does enter the state root.
The validator record itself (`dnac_validator_record_t`,
`dnac/include/dnac/validator.h`) carries: `pubkey`, `self_stake`,
`total_delegated`, `external_delegated`, `commission_bps`,
`pending_commission_bps`, `pending_effective_block`, `status`,
`active_since_block`, `unstake_commit_block`,
`unstake_destination_fp`/`_pubkey`, `last_validator_update_block`, and
`consecutive_missed_epochs` (the ONLY Rule N state this record still
carries — incremented on a missed epoch, reset to 0 on a clean one). The
two older per-block counters this record used to carry
(`last_signed_block`, `signed_blocks_this_epoch`) are RETIRED.

## Security

- **Dilithium5 everywhere** — TX signers, witness attestations, BFT votes
- **Nullifiers** (SHA3-512) — double-spend prevention without exposing
  UTXO linkage
- **Fail-closed verification** — DB errors are treated as "nullifier
  exists"; a witness that cannot compute its state does not vote
- **Chain-ID binding** — all BFT messages are validated against the
  chain ID to prevent cross-chain replay
- **Supply invariant** — native supply is hard-conserved by the witness
  supply gate: genesis − burned == coins + bonds + delegations + reward
  pool + unpaid rewards + unclaimed genesis allocations + shielded pool
  balances (tokenomics-v3 P2; nothing is minted); explicit burns and the pool
  are tracked in committed supply state

## Status

**Testnet** — Nodus Chain has been a public testnet since 30 September
2026, on seven validator nodes, started from a fresh genesis. It is not
wiped any more: a change to the chain's rules is a hard fork that takes
effect at an agreed block height (`nodus/docs/DEPLOY_RUNBOOK.md` §2.2).
Query the chain id from the network rather than hardcoding it.

## License

Licensed under the [Apache License 2.0](LICENSE) (aligned with the rest
of the monorepo since 2026-04-24).

## Related

- [Nodus](../nodus/README.md) — `nodus-server`: DHT + embedded Nodus Chain validator
- [Web Wallet](../web-wallet/README.md) — browser wallet that sends and stakes NODUS on the testnet
- [DNA Connect](../messenger/README.md) — the frozen messenger + wallet built on this library
- [Explorer](../explorer/README.md) — Scan, the read-only chain indexer
