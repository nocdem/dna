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

## Review History (5 rounds, 18 fixes)

### Round 1 (initial review)
| # | Issue | Fix |
|---|-------|-----|
| 1 | Non-atomic batch commit | `commit_block_inner` extracted, single BEGIN/COMMIT |
| 2 | Memory leak on timeout/view change | `round_state_free_batch()` helper |
| 3 | Stale forwarded mempool entries | Drain on epoch boundary |
| 4 | Stale TX clients no error response | TODO (minor) |
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
- Mempool has no TTL/age-based eviction (relies on epoch drain)
- `send_spend_result` uses save/restore pattern (fragile) — parameterized version cleaner
