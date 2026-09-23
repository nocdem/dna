# Mempool & Block Time — the cometbft lane

**Rewritten:** 2026-09-17 (R3 wave W4, v0.19.62); **Block time / idle
pace and TxsAvailable sections updated:** 2026-09-23 (tokenomics-v3 P1 —
D-4 relocated attendance out of every root, D-5 wired the real
`TxsAvailable` callback) | **Applies to:** every chain this build can open (a version-3 / cometbft chain — the post-open gate refuses everything else, `nodus_witness.c` `witness_post_open_gate`)

> **History.** Until R3 wave W4 this document described the LEGACY lane's
> mempool: a fee-sorted in-memory pool (`nodus_witness_mempool.c`), a 5 s
> batch timer in the witness tick, forward-to-leader for non-leader nodes,
> pending-forward slots, the MED-28 retained batch, the O15H round /
> view-change clock and the O15I follower reaper. **All of that code is
> deleted** (OBLIGATION `atlas-dec-71525f3b4918f710b660707ac6bb5a3a`,
> D-17 rev 10 (9), D-16 rev 5): the files no longer exist and nothing in
> the tree implements those mechanisms. The register
> (`tasks/reference-deviation-register.md`, section "W4 — R3 W4 paket D")
> and the git history hold the old text. What follows is the ONLY mempool
> and the ONLY block cadence this build has.

---

## The mempool is cometbft's Flood mempool, ported literally

`shared/dnac/cmt_mem.{h,c}` is a literal port of cometbft @709fd12b's
`mempool/clist_mempool.go` (D-4 rev 3,
`atlas-dec-d5ddcba654eb48d861c03a0ecd170718`), driven by the mempool
reactor `shared/dnac/cmt_memr.{h,c}` (`mempool/reactor.go`). Its
properties, each with the line that pins it:

| Property | Value | Where |
|---|---|---|
| Ordering | **FIFO** — arrival order in a CList; no fee sort in the pool | `cmt_mem.c` (CList) |
| Size | 5 000 transactions | `shared/dnac/cmt_mem.c:37` (`cmt_mempool_config_default`, config.go:796) |
| Cache | 10 000 hashes (duplicate refusal) | `cmt_mem.c:39` |
| `MaxTxBytes` | 1 MiB | `cmt_mem.c:40` |
| `MaxTxsBytes` | 1 GiB | `cmt_mem.c:38` |
| Recheck after a commit | on | `cmt_mem.c:33` |
| Gossip | every peer that did not send the transaction receives it (the sender id is reserved per peer by `cmt_memr_init_peer`; id 0 is the RPC / client sender) | `cmt_memr.c`, `nodus_witness_cmt_net.c` `net_scan_peers` (R3-W3-C2b-15) |

There is no leader and no forward: every node gossips what its clients
submit, and the round's proposer takes its block from its own pool.

### Admission — `CheckTx`

A client's `dnac_spend` on the witness port runs `cmt_mem_check_tx`
(`nodus_witness_handlers.c` `handle_dnac_spend`, the version-3 block) and
answers the client AT ONCE with the CheckTx verdict (D-23 rev 7 (22)):
`{status: APPROVED}` means "accepted into the mempool" — it is NOT a block
receipt, carries no height, no index and no witness signature. The client
learns the commit by query. `CheckTx` itself is the application's row
(`nodus_witness_cmt_app.c`, `check_tx`): the ledger's admission check
(`nodus_witness_verify_transaction` in `NODUS_WITNESS_VERIFY_ADMISSION`
mode, `nodus_witness_cmt_app.c:360`) followed by the envelope's
authorization stage (`nodus_witness_v2_env_authorize`, R3-C1a-11).

Since W4 the ADMISSION and VALIDATION modes of
`nodus_witness_verify_transaction` are behaviourally identical: the
node-local fee surge that used to read the legacy pool's depth in
ADMISSION mode is deleted with the pool (`nodus_witness_verify.c`, Check 5
keeps only its deterministic floor). The `dnac_fee_info` query's surge
term is therefore always 0 and `min_fee == base_fee`
(`nodus_witness_handlers.c` `handle_dnac_fee_info`).

**Measured, not promised:** admission does not mean next-block inclusion.
A stake envelope APPROVED at tip 2 landed at tip 4; a claim submitted to
one node landed when a proposer's pool held it. The harness therefore
waits for the transaction's LEDGER EFFECT with a progress bound
(`stagef_env.sh` `stagef_cmt_wait_row`), never for `submission_tip + 1`
(register R3-W3-C2d-3).

## What goes into a block — `PrepareProposal` / `ProcessProposal`

The reference lets the application reorder and drop in
`PrepareProposal`; that is where the ledger's two ordering rules live now
(`nodus_witness_cmt_app.c` `nodus_cmt_app_prepare_proposal`):

1. a **stable fee-descending** sort (ties keep arrival order; a claim
   carries no fee and sorts last);
2. **a chain_config transaction rides alone** in its block.

**R3 W4-C delta 2 (operator "kaldır" 2026-09-18;
atlas-dec-5b7568512b95e6d2e671c4eaad2c1879 rev 1): the chain-config
governance parameter `MAX_TXS_PER_BLOCK` (id 1) is RETIRED** — a
block's capacity was never meant to be a governed count on the pinned
reference (cometbft bounds blocks by bytes alone), and the parameter
throttled the chain to ~10 transactions per ~6 s block for no stated
reason. The witness's vote rules now refuse id 1 unconditionally
(`nodus_witness_chain_config.c`); a block's capacity is bytes and units
only. Three bounds, in this order:

| Bound | Value | Derived from | Where |
|---|---|---|---|
| Byte budget | cometbft's `Block.MaxBytes` 22 020 096 → `MaxDataBytes` for the round | ConsensusParams from the genesis document | `nodus_witness_cmt_app.c` (`max_tx_bytes`) |
| Unit budget | the ledger's own meter (the O15I capacity seam, `nodus_witness_v2_produce_batch_check_capped`) | `nodus_witness_v2_produce.c` | `app_seam_check` |
| **Per-class item caps** | **envelopes ≤ `min(env_bound, NODUS_V2_ENV_BATCH_MAX)`; claims ≤ `min(claim_bound, NODUS_V2_APPLY_MAX_CLAIMS)`** — `NODUS_V2_ENV_BATCH_MAX` (a per-block MEMORY ceiling on envelope-scratch allocation, 3 209 at this build — `nodus_witness_v2_apply.h`'s `_Static_assert`-pinned arithmetic: 64 MiB / ~21 KB per envelope) and `NODUS_V2_APPLY_MAX_CLAIMS` (14 162, cometbft's own 100 MiB block ceiling / the smallest encoded claim) are BOTH release resource bounds of the apply engine, NOT protocol numbers and NOT derived from the genesis document | `nodus_witness_v2_apply.h` | `nodus_witness_cmt_app.c` (PrepareProposal's per-class compaction pass, ProcessProposal's per-class classify-and-reject pass) |
| Mixed item cap (defense-in-depth) | `NODUS_V2_APPLY_MAX_OPS` = the SUM of the two per-class bounds above (17 371 at this build) | `nodus_witness_v2_apply.h` | `nodus_witness_cmt_app.c` (kept as a belt-and-braces trim/refusal AFTER the per-class ones; redundant in practice once they hold) |

`PrepareProposal` packs, per class, the highest-fee entries up to each
class's own cap (dropping from the tail of the fee order within that
class); `ProcessProposal` REFUSES a proposal exceeding either class's
cap before any per-item work (ABCI REJECT → a nil prevote);
`FinalizeBlock`'s engine FAULT on a larger DECIDED block is the last
line (register R3-W3-C2a-19, superseded by R3-W4-C delta 2). Throughput
is therefore **3 209 envelopes OR ~14 162 claims per block** (whichever
class is filled), a release-resource ceiling now sized in the
low-to-mid thousands rather than the flat 16 W3 shipped as an interim
fix. The request-side arrays are sized per request from the derived
bounds `prep_bound` 5 000 (the mempool size), `env_bound` 293 525 and
`claim_bound` 2 972 (`nodus_witness_cmt_app.c:125-190`, logged at bind
time with `env_batch_max`/`env_cap`/`claim_cap`/`mixed_item_cap`).

## Block time

Cadence is two NODE settings, not chain rules (D-4 rev 3;
`nodus_witness_cmt_node.c:1760-1761`):

| Setting | Value |
|---|---|
| `TimeoutCommit` | 4 000 ms (tokenomics-v3 P1 round 5, operator decision S-7: 5 000 -> 4 000, decision file §1 line 57's 2026-09-23 note) |
| `CreateEmptyBlocks` | true |
| `CreateEmptyBlocksInterval` | 60 000 ms |

**tokenomics-v3 P1 (D-4) — the idle pace is now the CONFIGURED 60 s, not
a faster "proof block" pace.** Before this package, EVERY block was a
*proof block*: Rule N attendance wrote the committed header proposer's
credit into `validators.last_signed_block`, a validator merkle-leaf
field, so `system_state_root` — and therefore the global root —
changed at every height, and cometbft's `needProofBlock`
(`shared/dnac/cmt_cs.c:1825`, `:1939`, state.go:1106-1129) was TRUE at
every height regardless of whether the block carried a transaction.
Measured then: one block per ≈ 6 s, always, idle or not.

tokenomics-v3 P1 relocated attendance out of every root (D-2, D-4):
`nodus_witness_v2_attendance_credit` (`nodus_witness_v2_epoch.c`) credits
every `CMT_PB_BLOCK_ID_FLAG_COMMIT` vote of `decided_last_commit` into
`v2_attendance` — a table that is not a leg of `system_state_root` and is
never read by any root computation. Its contents enter the root only
once per epoch, through the `attendance_root` leg (a digest of the whole
table, `shared/dnac/ledger_roots_v2.c`), committed at the epoch boundary.
Consequences:

- an EMPTY block moves NOTHING in `system_state_root`, so
  `needProofBlock` is FALSE on an idle chain and the 60 s
  `CreateEmptyBlocksInterval` is once again the OBSERVED pace, not merely
  an upper bound — measured directly by
  `nodus/tests/integration/stagef/tests/test_cmt_empty_blocks.sh` (>= 2
  consecutive idle gaps >= 45 s, ~1 s polling granularity);
- an idle chain now grows by ≈ 1 440 blocks a day (one per minute), not
  ≈ 14 000 — an epoch of 720 blocks is idle-paced at ≈ 12 hours, though
  in practice a validator set almost always has SOME traffic;
- a round WITH demand still takes ≈ 4-5 s (`TimeoutCommit`, 4 000 ms as
  of round 5) — a transaction's latency is "wait for a proposer whose
  pool holds it", one to a few blocks — and D-5 (below) means demand
  itself no longer waits for the next idle-interval tick to be noticed.

**tokenomics-v3 P1 (D-5) — the mempool's `TxsAvailable` signal is wired
to a real callback.** `cmt_mem_enable_txs_available` (`shared/dnac/
cmt_mem.h`) used to be bound with a NULL consumer
(`nodus_witness_cmt_node.c:1982` — "a channel nobody reads; the flag
still flips"). It now binds `node_txs_available_cb`
(`nodus_witness_cmt_node.c`), which calls
`cmt_cs_notify_txs_available(cs)` (`shared/dnac/cmt_cs.c:895-899`, sets
one bool, no re-entry into the mempool) the first time a transaction is
admitted at a given height — the reference's own mechanism
(`clist_mempool.go:510-521` → `state.go:1033`) for making a round that is
WAITING FOR TRANSACTIONS (`WaitForTxs()` — true here, since
`CreateEmptyBlocks` alone would otherwise still make the round wait out
the full interval before proposing) start proposing at once instead of
sitting out the remaining `CreateEmptyBlocksInterval`. No consensus value
moves; only WHEN a round starts. Measured by the same harness scenario
above, Part 2: a claim submitted to an idle chain reaches inclusion in
well under 30 s, not the ≈ 60 s a NULL callback would have produced.

## What a client sees

| Step | Answer | Where |
|---|---|---|
| submit (`dnac_spend`) | CheckTx verdict at once: APPROVED / a mapped refusal (`TX_TOO_LARGE`, `TX_IN_CACHE` "duplicate transaction", `MEMPOOL_IS_FULL`, the application's own code) | `nodus_witness_handlers.c` `handle_dnac_spend` |
| inclusion | by query — the transaction's ledger effect (`utxo_set` row for a claim, `v2_intent_index` row for an envelope) | `dnac_utxo`, `dnac_tx` queries |
| `nodus-cli`'s submit print | FIXED in R3 W4-C delta 4: the old "committed: height=… index=…" line printed zeros on this lane (the fields are not in the version-3 response); it now prints "accepted: mempool CheckTx approved (query dnac_tx for the eventual commit height)", and `v2-claim --submit` reuses ONE client session for the whole batch (`t6_submit_on`) instead of one Kyber handshake per leaf | `nodus/tools/nodus-cli.c` |

## Files

| File | Role |
|---|---|
| `shared/dnac/cmt_mem.{h,c}`, `cmt_memr.{h,c}`, `cmt_clist.{h,c}` | the Flood mempool, its reactor, the CList (literal ports) |
| `nodus/src/witness/nodus_witness_cmt_app.{h,c}` | CheckTx, PrepareProposal, ProcessProposal, FinalizeBlock (the application) |
| `nodus/src/witness/nodus_witness_cmt_net.{h,c}` | the transport glue that gives the mempool reactor its peers (verb 39 `w_cmt_txs`) |
| `nodus/src/witness/nodus_witness_handlers.c` | the client lane (`dnac_spend` → CheckTx, the queries) |
| `nodus/src/witness/nodus_witness_v2_produce.{h,c}` | the capacity seam the application meters with (`nodus_witness_v2_produce_batch_check_capped`) |
| `nodus/src/witness/nodus_witness_cmt_node.c` | the node config (`TimeoutCommit`, `CreateEmptyBlocksInterval`, the mempool config) |

## Tests

`test_cmt_mem` (the reference's `clist_mempool_test.go` cases),
`test_cmt_memr` (reactor: no-echo-to-sender, the sleep sites as
deadlines), `test_cmt_net` (peer ids reserved, a client transaction
leaves the node — `memr_peer_ids_reserved_and_rpc_tx_gossiped`),
`test_cmt_app` (the ordering rules, the byte bound, the per-class item
caps — 40 claims all APPLY since delta 2 retired the flat 16-item cap;
`NODUS_V2_ENV_BATCH_MAX + 1` envelope-classified entries refused),
`test_cmt_live` (CheckTx through the real dispatcher). The
Genesis Protocol harness proves the gossip end to end
(`test_cmt_mempool_flood.sh`: a transaction submitted to one node commits
on all seven; three back-to-back claims land within two heights) and the
empty-block cadence (`test_cmt_empty_blocks.sh`).

## Limitations, named

- 3 209 envelopes OR ~14 162 claims per block (the engine's derived
  memory-ceiling resource bounds, `NODUS_V2_ENV_BATCH_MAX` /
  `NODUS_V2_APPLY_MAX_CLAIMS`) — W4-C delta 2, superseding the flat
  16-item cap delta 1 shipped as an interim fix.
- `PrepareProposal`'s drop loop is O(`prep_bound`²) in the worst case on a
  pool full of budget-exceeding envelopes (register R3-W3-C2a-11).
- No blocksync: a node far behind catches up only through the consensus
  reactor's stored-part gossip (D-23 rev 7 (18)) — W4-B.
- The per-domain leg count RISK register R3-W3-C2a-19 flagged ("one
  envelope with many legs on one domain is not covered by the item
  cap") is CLOSED, not open: `dna_env_decode`/`dna_env_encode`
  (`shared/dnac/env_wire.c:364-365`/`:276`) both refuse a leg list that
  is not strictly ascending by `domain_id`, so a domain_id cannot repeat
  across one envelope's legs at all — the engine's per-domain `d->n_tx`
  bound is a proven-unreachable FAULT, not a live risk (W4-C delta 1).
- `test_cmt_env_flood.sh` (W4-C delta 2's own harness scenario for "a
  block beyond the old 10-envelope cap, 7/7 agreement") is currently a
  SKIP: `nodus-cli` has no generic CORE spend/transfer envelope command
  to drive it — a CLI tooling gap, not a consensus rule, reported to
  the ORCHESTRATOR rather than worked around.
