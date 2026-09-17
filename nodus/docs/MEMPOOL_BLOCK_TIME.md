# Mempool & Block Time — the cometbft lane

**Rewritten:** 2026-09-17 (R3 wave W4, v0.19.62) | **Applies to:** every chain this build can open (a version-3 / cometbft chain — the post-open gate refuses everything else, `nodus_witness.c` `witness_post_open_gate`)

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

Then three bounds, in this order:

| Bound | Value | Derived from | Where |
|---|---|---|---|
| Byte budget | cometbft's `Block.MaxBytes` 22 020 096 → `MaxDataBytes` for the round | ConsensusParams from the genesis document | `nodus_witness_cmt_app.c` (`max_tx_bytes`) |
| Unit budget | the ledger's own meter (the O15I capacity seam, `nodus_witness_v2_produce_batch_check_capped`) | `nodus_witness_v2_produce.c` | `app_seam_check` |
| **Item cap** | **`NODUS_V2_APPLY_MAX_OPS` = 16 items (envelopes + claims together)** — a release resource bound of the apply engine's per-block scratch, NOT a protocol number and NOT derived from the genesis document | `nodus_witness_v2_apply.h` | `nodus_witness_cmt_app.c:845-846` (pack), `:949-953` (refuse) |

`PrepareProposal` packs at most 16 items (dropping from the tail of the fee
order); `ProcessProposal` REFUSES a proposal above 16 before any per-item
work (ABCI REJECT → a nil prevote); `FinalizeBlock`'s engine FAULT on a
larger DECIDED block is the last line (register R3-W3-C2a-19). Throughput
is therefore **16 items per block** until the engine's scratch moves to
the heap (package W4-C). The request-side arrays are sized per request
from the derived bounds `prep_bound` 5 000 (the mempool size), `env_bound`
293 525 and `claim_bound` 2 972 (`nodus_witness_cmt_app.c:125-171`,
logged at bind time with `item_cap=16`, `:181-182`).

## Block time

Cadence is two NODE settings, not chain rules (D-4 rev 3;
`nodus_witness_cmt_node.c:1717-1718`):

| Setting | Value |
|---|---|
| `TimeoutCommit` | 5 000 ms |
| `CreateEmptyBlocks` | true |
| `CreateEmptyBlocksInterval` | 60 000 ms |

**Measured pace: one block per ≈ 6 s, always, idle or not.** The interval
never applies on this ledger because every block is a *proof block*:
Rule N attendance writes the proposer's `last_signed_block` into the
validators leaf on every block, so the global root changes at every
height and cometbft's `needProofBlock` (`shared/dnac/cmt_cs.c:1825`,
`:1939`, state.go:1106-1129) is true at every height. Consequences,
recorded for the operator (not defects of the port):

- an idle chain grows by ≈ 14 000 blocks a day (an epoch of 720 blocks ≈
  72 minutes);
- the 60 s interval is an upper bound the harness's stall detectors use,
  not the observed pace (`stagef_env.sh` `stagef_cmt_wait_height`);
- a round with demand takes the same ≈ 5-6 s — a transaction's latency is
  "wait for a proposer whose pool holds it", one to a few blocks.

## What a client sees

| Step | Answer | Where |
|---|---|---|
| submit (`dnac_spend`) | CheckTx verdict at once: APPROVED / a mapped refusal (`TX_TOO_LARGE`, `TX_IN_CACHE` "duplicate transaction", `MEMPOOL_IS_FULL`, the application's own code) | `nodus_witness_handlers.c` `handle_dnac_spend` |
| inclusion | by query — the transaction's ledger effect (`utxo_set` row for a claim, `v2_intent_index` row for an envelope) | `dnac_utxo`, `dnac_tx` queries |
| `nodus-cli`'s "committed: height=… index=…" line | **prints zeros on this lane** — the fields are not in the version-3 response; reworded in package W4-H | `nodus/tools/nodus-cli.c` |

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
`test_cmt_app` (the ordering rules, the byte bound, the item cap 40 → 16 /
17 refused), `test_cmt_live` (CheckTx through the real dispatcher). The
Genesis Protocol harness proves the gossip end to end
(`test_cmt_mempool_flood.sh`: a transaction submitted to one node commits
on all seven; three back-to-back claims land within two heights) and the
empty-block cadence (`test_cmt_empty_blocks.sh`).

## Limitations, named

- 16 items per block (the engine's scratch bound) — W4-C.
- `PrepareProposal`'s drop loop is O(`prep_bound`²) in the worst case on a
  pool full of budget-exceeding envelopes (register R3-W3-C2a-11).
- No blocksync: a node far behind catches up only through the consensus
  reactor's stored-part gossip (D-23 rev 7 (18)) — W4-B.
- The per-domain leg count is not covered by the item cap (register
  R3-W3-C2a-19, RISK) — W4-C.
