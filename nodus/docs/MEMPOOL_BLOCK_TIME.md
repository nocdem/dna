# Mempool & Block Time — Implementation Summary

**Shipped in:** Nodus v0.10.14 | **Branch:** `feat/mempool-block-time` (merged) | **Date:** 2026-04-08 | **Last Reviewed:** 2026-04-24

> **Status (2026-04-24):** Mempool + 5s batch-BFT timer described below is live since v0.10.14. Block proposal / BFT flow below reflects the model at merge time; the F17 committee enforcement (v0.15.1) and stake-delegation v1 added chain-derived top-7 committee as the voting roster but preserved the mempool and batching described here.

---

## Overview

Replaces the 1-TX-per-block model with a mempool + periodic block timer that batches multiple transactions into a single BFT consensus round.

**Before:** Client TX → immediate BFT round → 1 block (3-5 TX/s)
**After:** Client TX → mempool → 5s timer → batch BFT round → N blocks (up to 20+ TX/s peak)

---

## Architecture

```
Client → dnac_spend → Leader?
  ├─ YES (non-genesis) → mempool_add (fee-sorted)
  ├─ YES (genesis)     → legacy single-TX BFT (bypass mempool)
  └─ NO               → forward to leader → leader mempool_add
                        (leader resolved by SORTED RANK — see below)
                        O15I P3(b) / O15K: on BOTH lanes the forward is
                        also POOLED by non-leaders, after a verification
                        at that intake — ADMISSION on a successor,
                        VALIDATION on legacy (O15K added the legacy one;
                        that site had none) — see "Demand dissemination"

witness_tick (every ~50ms):
  └─ is_leader? + IDLE? + mempool.count > 0? + 5s elapsed?
      └─ propose_batch():
          1. Pop up to 10 TXs (highest fee first)
          2. Re-verify (remove stale double-spends)
          3. Compute block_hash = SHA3-512(tx_hash_1 || ... || tx_hash_n)
          4. bft_start_round_batch → PROPOSE + PREVOTE broadcast

BFT Flow (unchanged phases, batch-aware):
  PROPOSE → PREVOTE → PRECOMMIT → COMMIT
  - Votes reference block_hash (not individual tx_hash)
  - Follower verifies each TX independently
  - Reject any TX → reject entire batch

COMMIT:
  - Atomic SQLite transaction: BEGIN → [N × commit_block_inner] → COMMIT
  - Each TX creates its own block (sequential heights, prev_hash chain)
  - Commit certificates stored for EACH block (state sync compatible)
  - Per-TX client response (direct or forwarded)
```

### Leader resolution on the forwarding path (O15C-D)

`nodus_witness_bft_leader_index(epoch, view, n)` returns a slot in the
witness set **ordered by `witness_id`**, not a position in any local
array. Resolving that slot back to a witness MUST go through
`nodus_witness_roster_sorted_find` / `nodus_witness_roster_sorted_at`.

The gossip roster is arrival-ordered between the 60 s epoch rebuilds —
`nodus_witness_roster_add` appends and only the rebuild qsorts — so two
nodes holding the *same* witness set can hold it in different array
orders. Indexing `roster.witnesses[leader_slot]` directly therefore made
nodes disagree about who the leader was: the forwarder sent `w_fwd_req`
to a witness that was not the leader, which accepted the TX into its
mempool and never proposed it. No `w_fwd_rsp` was produced and the
`pending_forward` expired 30 s later. See `nodus/BUGS.md`, O15C-D.

### Pending-forward expiry (O15C-D)

A forwarded spend that draws no `w_fwd_rsp` within
`NODUS_W_PENDING_FWD_TIMEOUT_S` (30 s) is answered with an explicit
`NODUS_ERR_TIMEOUT`, never dropped silently — `dnac_spend` owes the
caller exactly one terminal answer. The bound MUST stay below the
client's 60 s `dnac_spend` wait (`nodus_client_dnac_spend`), or the error
reaches a caller that has already given up and only produces an
"unknown txn" warning. Enforced by
`nodus_witness_pending_forward_expire(w, now_s)`, which takes `now_s` as
a parameter so the contract is testable without a clock.

### View-change batch retention (O15C-D, MED-28)

On round timeout the proposed batch is **moved** into
`w->retained_batch` (`nodus_witness_retained_batch_take`) rather than
freed. The C5 reproposal rule binds the new view's first PROPOSE to a
`(height, tx_root)` *digest*, and `last_prepared` carries the
certificate but no transaction bytes — so freeing the batch left no copy
anywhere and the bound height could never be satisfied by anyone.

The new leader calls `nodus_witness_try_repropose_retained()`, handing
the exact entries to `bft_start_round_from_entries`, which recomputes the
block hash from the same tx_hashes in the same order — the re-proposed
`tx_root` therefore equals the bound digest by construction. A leader
that does not hold the bytes stays silent; its round times out and the
view rotates. Retention is released when the chain passes the height,
when a newer timeout supersedes it, and at teardown.

### The round / view-change clock (O15H)

`nodus_witness_bft_check_timeout` measures **one** clock,
`round_state.phase_start_time`, against **two** budgets:
`round_timeout_ms` (15 s) while a round is in flight, and
`viewchg_timeout_ms` (10 s) once the phase is
`NODUS_W_PHASE_VIEW_CHANGE`. Because the second budget is the SMALLER of
the two, the stamp must be reset at every transition or the second budget
is already spent before it starts. It is now re-stamped at three points:

| Event | Site | Why |
|---|---|---|
| Round entry (propose / accept / PREVOTE quorum) | `bft_start_round*`, `handle_propose`, the PREVOTE-quorum hook | the round budget |
| Round timeout → `NODUS_W_PHASE_VIEW_CHANGE` | `check_timeout` | **O15H D2** — without it the view change inherits the round's 15 s and is aborted on the next ~150 ms tick, wiping `view_change_count` |
| Adopting a HIGHER view-change target | `handle_viewchg` | **O15H D2** — the tally restarts at zero votes, so the window must restart too |

Resolution is **one second**, not one millisecond: `time_ms()` is
`nodus_time_now() * 1000`. A 15 s budget therefore fires at an observed
elapsed of 16000 ms. Any timeout budget added here must be a comfortable
multiple of one second.

**A stalled view change escalates, it does not abort (O15H D5).** When the
10 s budget expires without quorum, the node clears the collected
records, raises `view_change_target` by one and re-broadcasts. It does
**not** return to IDLE: from IDLE `check_timeout` returns immediately, the
leader is unchanged (`current_view` only moves on quorum), and nothing
would ever re-initiate. `current_view` is deliberately untouched on this
path, so leader election and the C5 binding keep their existing
preconditions. The retry interval is FIXED rather than backed off —
per-node backoff is per-node timing state, and divergent timing state
between witnesses is the failure class this file's rules exist to avoid.

---

## Constants

| Constant | Value | Location |
|----------|-------|----------|
| `NODUS_W_BLOCK_INTERVAL_MS` | 5000 (5s) | `nodus_types.h` |
| `NODUS_W_MAX_MEMPOOL` | 64 | `nodus_types.h` |
| `NODUS_W_MAX_BLOCK_TXS` | 10 | `nodus_types.h` |
| `NODUS_W_MAX_PENDING_FWD` | 16 | `nodus_types.h` |

---

## Files Changed

| File | Change |
|------|--------|
| `nodus/include/nodus/nodus_types.h` | Block production constants + version bump |
| `nodus/src/witness/nodus_witness_mempool.h` | **NEW** — mempool entry + mempool struct |
| `nodus/src/witness/nodus_witness_mempool.c` | **NEW** — fee-sorted add, pop_batch, remove, clear |
| `nodus/src/witness/nodus_witness.h` | Extended round_state (batch fields), pending_forwards array, mempool in witness_t |
| `nodus/src/witness/nodus_witness.c` | Block timer, propose_batch, mempool drain, cleanup |
| `nodus/src/witness/nodus_witness_bft.h` | `bft_start_round_batch()` declaration |
| `nodus/src/witness/nodus_witness_bft.c` | Batch BFT: start_round_batch, handle_propose batch, atomic batch commit, batch client response, commit_block_inner, round_state_free_batch |
| `nodus/src/witness/nodus_witness_handlers.c` | handle_spend → mempool, genesis bypass, verify include |
| `nodus/src/witness/nodus_witness_peer.c` | fwd_req → mempool, multi-forward array, conn cleanup |
| `nodus/src/protocol/nodus_tier3.h` | `nodus_t3_batch_tx_t`, extended propose_t/commit_t |
| `nodus/src/protocol/nodus_tier3.c` | Batch encode/decode (enc_batch_tx, dec_batch_tx_entry) |
| `nodus/CMakeLists.txt` | Added `nodus_witness_mempool.c` |

---

## Wire Protocol Extension

### Batch Proposal (`w_propose`)
```cbor
{
  "bh": bstr(64),           // block_hash = SHA3-512(all tx_hashes)
  "btx": [                  // batch TX array
    {
      "txh": bstr(64),      // tx_hash
      "tty": uint,          // tx_type
      "txd": bstr,          // tx_data
      "txl": uint,          // tx_len (deprecated — derived from txd length)
      "nlc": uint,          // nullifier_count
      "nls": [bstr(64)],    // nullifiers
      "pk":  bstr(2592),    // client_pubkey (Dilithium5)
      "csig": bstr(4627),   // client_sig
      "fee": uint           // fee amount
    }, ...
  ]
}
```

When `btx` is absent, falls back to legacy single-TX fields (backward compat).

### Batch Commit (`w_commit`)
Same `btx`/`bh` extension, plus existing cert/timestamp fields.

### Votes (`w_prevote`, `w_precommit`)
`tx_hash` field carries `block_hash` in batch mode. No structural change.

---

## Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| Max 10 TX/batch | Wire limit: 128KB / ~9KB per TX ≈ 14, margin to 10 |
| No empty blocks | No information to consensus about |
| 1 batch = N blocks (not 1 block) | Preserves state sync compatibility |
| Genesis bypasses mempool | Batch commit_block_inner cannot create chain DB |
| Votes on block_hash | Single hash for entire batch, no vote struct change |
| Atomic batch commit | Single BEGIN/COMMIT wraps all N TXs |
| Per-block commit certificates | State sync verifies certs per block |
| Epoch-boundary mempool drain | Prevents leadership flap from dropping TXs |

---

## Demand dissemination and the follower reaper (O15I P3)

A forwarded transaction used to reach the leader and **nowhere else**, so
when the leader was dead the demand existed on exactly one node — the
submission target. One node is far below the f+1 threshold at which peers
join a view change (`bft_vc_join_threshold` = max(2, (quorum−1)/2+1) = 7
at quorum 14), so nothing rotated and the chain halted for the whole
epoch. `leader = (epoch + view) % n` with `epoch = height /
DNAC_EPOCH_LENGTH` gives ONE node an entire epoch — **720 heights in
production** (`dnac/include/dnac/dnac.h:172`).

**P3(a) — demand-armed deadman.** In `check_timeout`'s IDLE branch a
non-leader that holds live work and whose own committed tip has not moved
for more than `round_timeout_ms` initiates an ordinary `current_view + 1`
view change. BOTH halves are required: without the demand half a quiet
chain would rotate forever; without the frozen-tip half a busy chain would
rotate away from a healthy leader. Every verdict at the would-fire point
re-stamps the window, so the DB scan and the `is_leader` call cost once per
`round_timeout_ms`, not once per tick. `current_view` is untouched — it
still advances only on quorum.

### Pool-then-forward (O15I follow-up)

The 20-node rehearsal proved P3's demand predicate **structurally blind in
the exact case it exists for**. On the submission target with an
unreachable leader BOTH halves of `mempool.count > 0 ||
pending_forward_count > 0` are permanently 0: a non-leader does not pool
its own client transaction (it forwards it), and the `!leader_conn` path
answered the client and released the slot in the same breath, discarding
the work. Measured: after the boundary block committed, the submitter made
44 forward attempts with 0 successes and the deadman fired **zero** times.

This is PBFT's own mechanism, half-missing. Castro & Liskov OSDI 1999
§4.1: *"If the client does not receive replies soon enough, it broadcasts
the request to all replicas. … If the primary does not multicast the
request to the group, it will eventually be suspected to be faulty by
enough replicas to cause a view change."* §4.4 gives the timer; §4.1 gives
the request reaching enough replicas. We had only the first.

A successor non-leader now runs the SAME `NODUS_WITNESS_VERIFY_ADMISSION`
gate the leader branch runs and **pools the entry before, and
independently of, the forward** — on every non-leader intake, not only when
the leader is unreachable, because a leader whose TCP is alive but whose
witness is wedged accepts the forward and never proposes.

The entry is pooled in the **orphan form** (`client_conn = NULL`,
`is_forwarded = true`, `forwarder_id = my_id`) — byte-identically the shape
`nodus_witness_peer_handle_fwd_req` already uses. That is load-bearing, not
stylistic: `nodus_witness_peer_conn_closed` runs for client connections and
calls `nodus_witness_mempool_remove_by_conn`, which matches
`client_conn == conn`, so pooling with the live connection would have the
client's disconnect delete the entry one step later.

Class-201 claims re-derive their committed nullifier at pool time, exactly
as the leader branch and the forward intake do. Without it a claim would be
invisible to the reaper's nullifier walk AND unjudgeable by the entry
verdict, so nothing could remove it after the chain committed it — the
quiet-chain churn defect through a new door.

⚠ **O15K SUPERSEDED THIS PARAGRAPH.** It used to read: *"Legacy chains are
unchanged: a legacy peer refuses a non-leader `w_fwd_req` byte-identically
because its forward intake is structural-only, so pooled legacy demand
could never recruit the f+1 backers a rotation needs."*

Both halves were true and together they were the bug. Leaving legacy
unpooled is exactly why a dead leader halted a legacy chain indefinitely:
P3(a) arms on `mempool.count > 0 || pending_forward_count > 0`, and on
legacy both were structurally zero — `pool_local_demand` returned −1, and
an unreachable leader released the `pending_forwards` slot in the same
call. The deadman could never arm, so it never fired, so nothing rotated.

O15K opens the lane and answers the objection rather than working around
it: the reason legacy could not pool was that its forward intake did no
verification, so O15K **adds that verification at that intake**, for every
recipient including the leader — which also closed a live defect where the
leader pooled forwarded bytes with no signature check at all. The f+1
argument falls with it, because the peer-side refusal it depended on is
removed in the same change.

**Client answer on the unreachable-leader path:** the error CODE is
unchanged (`NODUS_ERR_*` is wire surface); only the message differs, and
only when the entry really was pooled — the work is queued locally and will
be proposed once a reachable leader is elected.

**P3(b) — dissemination.** At fire (never at intake, so steady-state
traffic is unchanged) the node re-broadcasts its mempool entries as
`w_fwd_req` to the peer set, skipping entries already decided (same
per-entry rule the demand predicate applies). `nodus_witness_peer_handle_fwd_req` pools
on a non-leader **on BOTH lanes since O15K** — the successor entry passes
the full `NODUS_WITNESS_VERIFY_ADMISSION` lane, and the legacy entry now
passes a verification of its own, added by O15K at that site because it
had none. Two details of the legacy call are load-bearing and were each
flagged independently by three reviewers:

- it runs in `NODUS_WITNESS_VERIFY_VALIDATION`, **not** ADMISSION. The two
  modes differ on the legacy lane by the fee surge alone, and the surge
  reads node-local `mempool.count` — so ADMISSION would let dissemination,
  whose whole job is to fill every peer's pool with the same demand,
  throttle the recovery it exists to produce. Direct client submissions
  keep ADMISSION; the successor forward keeps ADMISSION too, because its
  claim dedup is ADMISSION-only;
- it is placed **after** the structural nullifier parse and is passed the
  parsed nullifiers. Copying the successor call's `NULL, 0` would make
  legacy Check 4 refuse everything and turn the whole fix into a silent
  no-op.

A RAW, pre-admission forward is never pooled. `pending_forwards` carries no
transaction bytes (only hash / conn / txn_id / started_at), which is why
the rebroadcast is sourced from the mempool.

**P3(c) — the epoch drain became a reaper.** The drain used to
`nodus_witness_mempool_clear()` the whole pool once per epoch tick. Under
P3(b) a follower legitimately holds forwarded work, and that work is
exactly what arms P3(a) — so a blind wipe deleted the evidence of the
stall, once a minute, while the stall was happening. Cadence and gates are
unchanged; only the verdict is: `nodus_witness_mempool_evict_committed`
drops an entry only when the chain has already decided one of its
nullifiers, the same test the leader's batch selection applies. This also
closes a pre-existing gap — nothing previously removed a follower's copy of
a transaction after it committed.

**Known residual, deliberately not papered over:** a successor class-200
envelope is pooled with `nullifier_count == 0` (the legacy nullifier walk
is gated on `!v2_successor`), so the committed-nullifier predicate cannot
evict it. Such an entry is dropped and freed — not requeued — by the
successor batch pre-check (`v2_intent_index` dedup) the next time this node
leads, so the churn is bounded, not unbounded. The leader's own batch
selection has the identical blind spot.

---

## Review History (5 rounds, 18 fixes)

### Round 1 (initial review)
| # | Issue | Fix |
|---|-------|-----|
| 1 | Non-atomic batch commit | `commit_block_inner` extracted, single BEGIN/COMMIT |
| 2 | Memory leak on timeout/view change | `round_state_free_batch()` helper — **superseded for the round-timeout path by O15C-D**: freeing there destroyed the only copy of a batch a NEW_VIEW could still bind to, so it is now retained (see "View-change batch retention" above). Other call sites unchanged. |
| 3 | Stale forwarded mempool entries | Drain on epoch boundary |
| 4 | Stale TX clients no error response | **CLOSED by O15C-D** for the forwarded path: expiry now sends `NODUS_ERR_TIMEOUT` (see "Pending-forward expiry" above). |
| 5 | fprintf instead of QGP_LOG | Replaced in mempool.c |

### Round 2 (architecture fixes)
| # | Issue | Fix |
|---|-------|-----|
| 6 | `block_add` outside SQLite TX | Moved into `commit_block_inner` |
| 7 | Cert only for last block in batch | Per-block cert store loop |
| 8 | `fee` passed as `total_supply` | Pass 0 for batch spends |
| 9 | Aggressive mempool drain (every tick) | Epoch-boundary only |
| 10 | fprintf in propose_batch | QGP_LOG |
| 11 | Missing QGP_LOG include | Added to witness.c |

### Round 3 (correctness blockers)
| # | Issue | Fix |
|---|-------|-----|
| 12 | **BLOCKER**: Follower PREVOTE used `prop->tx_hash` (zeroed in batch) | Use `w->round_state.tx_hash` |
| 13 | Genesis TX enters mempool but batch can't handle it | Genesis bypasses mempool → legacy BFT |
| 14 | Cert store runs after batch rollback | Guard with `!batch_failed` |
| 15 | Cert underflow at pre-genesis | Guard: `top_bh >= batch_count` |
| 16 | `handle_newview` doesn't free batch entries | Added `round_state_free_batch` |
| 17 | 3 `memset` sites lack `round_state_free_batch` | Added guards at lines 748, 882, 989 |
| 18 | Forward declaration needed | Added at top of file |

### Round 4
No new issues found. All 6 verification items passed.

### Round 5 (adversarial security review)
| # | Issue | Fix |
|---|-------|-----|
| 19 | **CRITICAL**: Intra-batch double-spend — two TXs spending same nullifier both pass individual verification | Added cross-TX nullifier tracking in propose_batch (leader) and handle_propose (follower) |

---

## Backward Compatibility

- **Wire protocol:** Legacy single-TX proposal/commit still supported. Batch mode uses `btx` key — absent means legacy.
- **State sync:** Unchanged — each TX produces its own block.
- **Client API:** Unchanged — `dnac_spend` still sends single TXs. Server batches transparently.
- **Deploy:** All 7 nodes must be updated simultaneously (cluster restart).
- **Database:** No schema changes.

---

## Limitations & Future Work

- Max batch size limited by 128KB wire message (10 TXs at ~9KB each)
- Theoretical 64KB TX could overflow batch encoding — add size check at mempool insertion
- Empty blocks not produced — no heartbeat mechanism
- Mempool has no TTL/age-based eviction. Since O15I P3(c) the epoch pass
  is a committed-nullifier reaper rather than an unconditional drain, so a
  never-decidable entry is bounded by the 64-slot cap and fee ordering, not
  by a timer.
- `send_spend_result` uses save/restore pattern (fragile) — parameterized version cleaner
