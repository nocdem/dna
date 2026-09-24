# DNAC — DNA Chain Client Library

**Version:** v0.18.6-ledgerv2-o15b | **TX Wire:** v2 (since v0.17.1)

DNAC is the **client side** of the **DNA Chain** — the post-quantum UTXO
blockchain of the DNA ecosystem. This library builds wallets and
transactions and talks to the witness cluster. It does **not** run
consensus: the chain's consensus (BFT witness) is embedded in
`nodus-server`.

The chain is implemented in three layers of the monorepo:

| Layer | Location | Contents |
|---|---|---|
| **Client** (this directory) | `dnac/` | Wallet, UTXO management, TX builders, witness RPC client, client-side chain verification |
| **Canonical codecs** | `shared/dnac/` | Wire formats compiled byte-identical into both the client (`libdna`) and the witness (`libnodus`) |
| **Consensus** | `nodus/src/witness/` | The BFT witness embedded in `nodus-server` (see `nodus/README.md`) |

## Features (client-side)

- **UTXO model** with per-token UTXO tracking and multi-token balances
- **Dilithium5 (ML-DSA-87) signatures** — NIST Category 5, post-quantum
- **Witness-only architecture** — all chain state lives on the BFT
  witnesses; the wallet syncs via RPC (`dna sync`), no DHT storage of
  chain state
- **TX builders** for every live transaction type: SPEND, BURN,
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
  library's mirror (`dnac/src/transaction/verify.c`) refuse it. Ids 2
  and 4 (BLOCK_INTERVAL_SEC, TARGET_ACTIVE_COUNT) are unaffected; ids
  never renumber and a retired id is never reused), GENESIS
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
- **Staking parameters (tokenomics-v3 P3, version-3 chain).** Minimum
  self-stake 10M NODUS; up to 32 validators are seated, chosen by the
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
  verification, chain-definition decoding (`src/ledger/`)

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

All witness RPCs ride the authenticated, Kyber1024-encrypted Nodus
client connection (Tier 2, TCP 4001) as `dnac_*` verbs — spend, utxo,
history, ledger/ledger-range, block/block-range, tx, committee,
delegations, validator-list, roster, supply, token queries, fee info.
The witness BFT round itself (PROPOSE → PREVOTE → PRECOMMIT → COMMIT,
quorum `(2n)/3+1` over the epoch's validator-set snapshot) runs between
witnesses on TCP 4004.

## Building

DNAC has **no standalone runtime**. Its sources are compiled directly
into `libdna.so` by the messenger build:

```bash
cd /opt/dna/messenger/build
cmake .. && make -j$(nproc)
```

The `dnac/build` tree additionally produces `libdnac.a` plus the DNAC
test binaries. The CLI's `dna` command group is enabled at messenger
**configure** time only if `dnac/build/libdnac.a` already exists, so the
full-from-scratch order is:

```bash
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)   # 1. libdna
cd /opt/dna/dnac/build      && cmake .. && make -j$(nproc)   # 2. libdnac.a (requires libdna)
cd /opt/dna/messenger/build && cmake .. && make -j$(nproc)   # 3. re-run so the CLI picks up libdnac.a
```

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

Amounts on the CLI are raw base units (10^8 per DNAC).

## Wallet Address

The wallet address is the **SHA3-512 hash of the Dilithium5 public
key** — 64 bytes, 128 hex characters, identical to the DNA Connect
identity fingerprint.

## Transaction Format (v2 — since v0.17.1)

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

## Ledger V2 (successor chain)

The DNA Chain is about to transition to the **Ledger V2** architecture —
canonical block headers and BlockIDs, quorum certificates bound to
committed validator-set snapshots, a domain-partitioned state model and
multi-leg envelope transactions. The consensus side lives entirely in
`nodus/src/witness/` (see [`../nodus/README.md`](../nodus/README.md) and
[`../docs/ledger-v1-vs-v2.md`](../docs/ledger-v1-vs-v2.md) for the
grounded V1↔V2 reference). On the client side:

- the canonical V2 codecs (envelope, block header, QC, claims, pools,
  activation records) live in `shared/dnac/` and compile into `libdna`;
- the Tendermint consensus codecs of the T3 season (`shared/dnac/tm_vote.{h,c}`,
  `tm_commit.{h,c}`) were DELETED in cometbft port R2 (2026-09-11) and
  `tm_bounds.h` (the derived size bounds) in R3 W3 C2b (2026-09-16); the
  cometbft port under `shared/dnac/cmt_*` is the one consensus implementation
  and its block, vote and commit codecs are cometbft's own proto3 forms;
- the **cometbft @709fd12b literal port, R1 types layer** (`shared/dnac/cmt_*`,
  2026-09-10: `cmt_pb` proto3 codec, `cmt_merkle`, `cmt_bits`, `cmt_safemath`,
  `cmt_time`, `cmt_tmhash`, `cmt_canonical`, `cmt_vote`, `cmt_proposal`,
  `cmt_part_set`, `cmt_block`, `cmt_validator_set`, `cmt_results`, `cmt_params`,
  `cmt_genesis`, `cmt_validation`, `cmt_evidence`, `cmt_state`) is likewise
  DORMANT: zero consumers, compiled into `libnodus` only (libdna does not list
  it), every function cited to cometbft v0.38.19 `file:line`, substitutions
  limited to SHA3-512 / ML-DSA-87 / 32-byte addresses / a host clock callback.
  It supersedes the T3-season `tm_*` codecs and the T1 `tm_proposer.c` once the
  R2 core lands (module table: `../nodus/docs/ARCHITECTURE.md`, "cometbft
  literal port"); Python oracles under `shared/dnac/tests/` pin its vectors;
- the legacy v2 TX wire above stays the accepted format until the
  switch; Wire V3 (types 11/12/13) is defined but rejected by every
  live admission path;
- successor-chain operations (claims, V2 envelopes) are built with
  `nodus-cli v2-claim` / `nodus-cli v2-envelope` on activation builds.

Migration is governed on-chain: a quorum-voted schedule plus
per-validator readiness signals make the legacy chain terminal at the
activation height, and legacy balances move to the successor chain via
deterministic claims.

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

**Testnet** — live 7-witness cluster with real tester balances. The
active chain ID rotates on consensus-format wipes; query the cluster
rather than hardcoding it. Ledger V2 activation is the next planned
step.

## License

Licensed under the [Apache License 2.0](LICENSE) (aligned with the rest
of the DNA monorepo since 2026-04-24).

## Related

- [Nodus](../nodus/README.md) — DHT server + embedded DNA Chain witness
- [DNA Connect](../messenger/README.md) — messenger + wallet UI on top
  of this library
- [Explorer](../explorer/README.md) — read-only chain indexer
  (scan.cpunk.io)
