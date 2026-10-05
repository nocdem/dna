/**
 * @file nodus_witness_v2_storage.h
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2a — the
 *        chain side: frozen storage sets, segment roots and their
 *        publication, assignment, the storage epoch boundary (settlement,
 *        fail_streak, exit release, prune), and the storage leg's three
 *        archive-era loaders.
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md (reward = block archive; R = 3; G = 1; amount = block count;
 * 3 failed epochs → skipped; 3 samples; full archives keep all; K5 a
 * skipped member returns after 12 settled epochs),
 * 2026-10-05-archive-reward-bytes-approved.md (bytes), 2026-10-05-
 * kurultay-7-archive-reward-summary.md, 2026-10-04-storage-reward-
 * approved.md (kept parts), 2026-10-04-storage-reward-who-earns.md (only
 * registered storage nodes earn). Design docs/plans/2026-10-05-archive-
 * reward-design.md rev 4 + kept rev 2.2 (2026-10-04-storage-reward-v1-
 * design.md §1, §2, §4, §5, §6). Bytes docs/plans/2026-10-05-archive-
 * reward-bytes.md items 1-5 and 2026-10-04-storage-reward-bytes.md items
 * 2, 3, 5, 6 (shared/dnac/ledger_roots_v2.h computes every hash).
 *
 * ── TABLES (base schema, nodus_witness.h NODUS_V2_ST*_DDL) ────────────
 *   v2_storage_sets / v2_storage_set_members  frozen storage_set(H)
 *   v2_storage_reports                         committed STORAGE_REPORTs
 *   v2_storage_segments                        the published segment list
 *
 * ── THE STORAGE BOUNDARY (step 1b' of nodus_witness_v2_epoch_boundary_
 *    apply: after the validator distribution 1b, before payday 1c —
 *    rev 2.2 §5 "between epoch.c:1571 and :1589") ──────────────────────
 *   0. GATE — runs only when chain_config param 14 (RULESET_GEN_STORAGE)
 *      is in effect at B (a committed row with effective <= B, i.e.
 *      B >= H_act) AND the SYSTEM runtime the registry resolves is
 *      GEN_STORAGE or later; param in effect with an older runtime is a
 *      FAULT (the phase-6b' switch would have run). The param is read
 *      FIRST, so a chain without the vote never resolves a runtime here.
 *   1. SETTLE the epoch (H, H+E], H = B − 2E (rev 2.2 §5 steps 1-3; rev
 *      4 §5) — skipped when storage_set(H) does not exist (the first two
 *      storage boundaries). Weights, F1 floor, F2 own-report rule, the
 *      > 2/3 test, weighted pay from treasury pool 1, fail_streak.
 *   2. PRUNE reports with epoch_start <= H and frozen sets with
 *      epoch_start < H (keeps set(B−2E), set(B−E), set(B): every set a
 *      later report or settlement reads).
 *   3. RELEASE every EXITING registry row: one locked UTXO (kind 0x11,
 *      index 201, unlock B + 12·E) to payee_fp, status RELEASED.
 *   4. PUBLISH every unpublished segment k with k·P + 2E <= B, k
 *      ascending from the last published + 1 (one rule = the activation
 *      backfill AND the schedule; never an immature segment).
 *   5. FREEZE storage_set(B) = the ACTIVE rows (node_fp ASC, S(B)), each
 *      member's fail_streak copied (the input of holders(·, B)).
 * Fixed order; every iteration over rows is an explicit ORDER BY on a
 * unique key; integer math only; no clock. Any failure is a node FAULT
 * (-2) — a boundary has no verdict class (nodus_witness_v2_epoch.h).
 *
 * ── ELIGIBILITY (design rev 4 §2, G = 1, one-epoch handoff) ───────────
 *   member m of storage_set(H) holds an ELIGIBLE (past-grace) segment k
 *   in epoch (H, H+E] iff
 *       published_height(k) <= H − E   and   m ∈ holders(k, H − E)
 *   holders(k, X) = bytes item 3 over storage_set(X) with each member's
 *   fail_streak AS FROZEN at X. This one formula is the design's three
 *   cases: a continuing holder (in holders(k,H−E) and holders(k,H)) is
 *   eligible; a holder displaced at H (in holders(k,H−E), not in
 *   holders(k,H)) stays assigned and paid through (H, H+E] — the overlap
 *   epoch — and may delete k after H + E; a NEW holder (in holders(k,H),
 *   not in holders(k,H−E)) is not probed and earns nothing for k in that
 *   epoch. weight(m) = DNA_V2_SEGMENT_BLOCKS × |eligible segments of m|
 *   (K1: block count). A member must be in storage_set(H) to have a bit.
 *
 * ── SETTLEMENT (rev 2.2 §5 + rev 4 §5) ────────────────────────────────
 *   P_total = Σ power of snapshot(H) (total_stake / DNAC_DECIMAL_UNIT —
 *   the distribution's power); P_rep = Σ power of the seats with a
 *   committed report for H. F1: nothing moves (no pay, no fail_streak)
 *   unless P_rep · 2 > P_total. For member m: if m's node key is a
 *   seated validator that reported, its power leaves P_rep (F2) and its
 *   own bit about itself is ignored; OK iff Σ power of the other
 *   reporters with m's bit set · 3 > P_rep(m) · 2 (checked u64).
 *   W = Σ weight over ALL members; W == 0 → nothing. budget = pool1 >> 16
 *   (treasury pool 1, read at this step); each OK member with weight w
 *   accrues floor(budget · w / W) (128-bit intermediate) to its payee_fp
 *   through nodus_witness_v2_accrue; pool 1 is debited by exactly Σ
 *   credited, bound to the observed balance; failed shares and the
 *   remainder stay in pool 1.
 *   fail_streak (bytes item 4 + K5), for every member of storage_set(H)
 *   (node_fp ASC), old = the live registry value:
 *     old < 3:  w > 0 and OK → 0; w > 0 and NOT OK → +1; w == 0 →
 *               unchanged;
 *     old ≥ 3:  (the member is skipped for placement) +1 whatever w and
 *               the verdict; 14 → 0 instead of 15, so the member is placed
 *               again by the set frozen at this boundary (12 skipped
 *               epochs) and is skipped again after 3 new failures.
 *   Under a failed F1 floor nothing is settled, so fail_streak is
 *   unchanged for every member (reading of "nothing moves for that
 *   epoch").
 *
 * @file nodus_witness_v2_storage.h
 */

#ifndef NODUS_WITNESS_V2_STORAGE_H
#define NODUS_WITNESS_V2_STORAGE_H

#include "witness/nodus_witness.h"
#include "dnac/ledger_ids.h"
#include "dnac/ledger_roots_v2.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Treasury pool that funds the storage reward (pool ids follow the
 *  tokenomics §1 order: 1 = Storage — nodus_witness_roots_v2.h). */
#define NODUS_STORAGE_POOL_ID          1u

/** fail_streak value at which a skipped member is reset to 0 (K5,
 *  decision 2026-10-05-storage-reward-is-for-archive.md: 3 + 12 skipped
 *  epochs). The stored value never reaches it: 14 + 1 is written as 0. */
#define NODUS_STORAGE_FAIL_RETURN      15u

/** One frozen storage set, as committed. Heap-allocate it (16.9 KB). */
typedef struct {
    uint64_t epoch_start;
    uint8_t  set_hash[64];                           /* S(H)              */
    uint32_t count;                                  /* 0..256            */
    uint8_t  fps[DNA_V2_STORAGE_SET_MAX][64];        /* node_fp ASC       */
    uint32_t fail_streak[DNA_V2_STORAGE_SET_MAX];    /* frozen at H       */
} nodus_storage_set_t;

/** What the storage boundary did (the caller's touched input). */
typedef struct {
    int      active;          /* 1 = the gate opened at this boundary    */
    int      settled;         /* 1 = an epoch was settled (F1 passed)    */
    uint64_t accrued;         /* Σ credited to v2_reward_accrual          */
    uint32_t n_paid;          /* members credited                         */
    uint32_t n_released;      /* exit release UTXOs written               */
    uint32_t n_published;     /* segments published                       */
    uint32_t set_count;       /* |storage_set(B)| frozen                  */
} nodus_storage_boundary_t;

/** The storage boundary (header: steps 0-5). Called by
 *  nodus_witness_v2_epoch_boundary_apply at a boundary height B only.
 *  @return 0 (applied, or the gate closed: out->active == 0) / -2 FAULT. */
int nodus_witness_storage_boundary_apply(
        nodus_witness_t *w, uint64_t boundary_height,
        const uint8_t chain_id[DNA_CHAIN_ID_LEN],
        nodus_storage_boundary_t *out);

/** Step 4 alone: publish every unpublished segment k (from the last
 *  published + 1, ascending) with k·P + 2E <= boundary_height, Root(k)
 *  from v2_blocks, published_height = boundary_height. The boundary
 *  calls the same code; exported so publication and the activation
 *  backfill can be proven over synthetic v2_blocks rows. A segment whose
 *  v2_blocks rows are missing or malformed stops the step with a FAULT
 *  before its row is written. Runs inside the caller's transaction.
 *  @return 0 (*n_out = rows written) / -1 fault. */
int nodus_witness_storage_publish_due(nodus_witness_t *w,
                                      uint64_t boundary_height,
                                      uint32_t *n_out);

/* ── loaders (the storage leg's archive-era trees) ─────────────────── */

/** sets_root over `v2_storage_sets` (epoch_start ASC): every set's S(H)
 *  RE-DERIVED from its member rows (node_fp ASC) and compared with the
 *  stored set_hash and member_count — any difference, a typed-column
 *  violation or a scan fault fails the computation. Empty →
 *  DNA_V2_EMPTY_STORAGE_SETS. @return 0 / -1. */
int nodus_witness_storage_sets_root(nodus_witness_t *w, uint8_t out[64]);

/** reports_root over `v2_storage_reports` ((epoch_start, seat) ASC);
 *  fails on a malformed row. Empty → DNA_V2_EMPTY_STORAGE_REPORTS.
 *  @return 0 / -1. */
int nodus_witness_storage_reports_root(nodus_witness_t *w, uint8_t out[64]);

/** segments_root over `v2_storage_segments` (k ASC); fails on a
 *  malformed row. Empty → DNA_V2_EMPTY_STORAGE_SEGS. @return 0 / -1. */
int nodus_witness_storage_segments_root(nodus_witness_t *w,
                                        uint8_t out[64]);

/** storage_set(epoch_start) with its members and frozen fail_streaks
 *  (the stored set_hash re-checked against the members).
 *  @return 0 found / 1 no such set / -1 fault (malformed or unreadable). */
int nodus_witness_storage_set_get(nodus_witness_t *w, uint64_t epoch_start,
                                  nodus_storage_set_t *out);

/** Root(k) from `v2_blocks.block_id` at heights ((k−1)·P, k·P] (bytes
 *  item 1). A missing height, a block_id that is not a 64-byte BLOB, a
 *  bad k or a hash failure is a FAULT. @return 0 / -1. */
int nodus_witness_storage_segment_root_compute(nodus_witness_t *w,
                                               uint64_t k, uint8_t out[64]);

/** holders(k, X) of the published segment with root `seg_root` over the
 *  frozen `set` (bytes item 3): out_fps[0..*n_out) in ascending distance.
 *  @return 0 / -1. */
int nodus_witness_storage_holders(const nodus_storage_set_t *set,
                                  const uint8_t seg_root[64],
                                  uint8_t out_fps[DNA_V2_STORAGE_HOLDERS][64],
                                  size_t *n_out);

/** The ELIGIBLE segments of `node_fp` in epoch (H, H+E] (header
 *  "ELIGIBILITY"), k ascending — the probe client's B = n × P blocks in
 *  ascending height. Writes at most `cap` k's; *n_out is the full count
 *  (a caller with cap < *n_out gets -1). A node that is not a member of
 *  storage_set(H) has none.
 *  @return 0 / 1 no storage_set(H) / -1 fault or cap too small. */
int nodus_witness_storage_eligible_segments(nodus_witness_t *w,
                                            uint64_t epoch_start,
                                            const uint8_t node_fp[64],
                                            uint64_t *ks_out, size_t cap,
                                            size_t *n_out);

/** fail_streak after one SETTLED epoch (pure; header "SETTLEMENT",
 *  bytes item 4 + K5). `old` the live value, `had_eligible` 1 iff the
 *  member's weight in the epoch is > 0, `ok` the verdict. old ≥ 3
 *  (DNA_V2_STORAGE_FAIL_LIMIT): old + 1, or 0 when that would be
 *  NODUS_STORAGE_FAIL_RETURN or more; old < 3: unchanged without an
 *  eligible block, else OK → 0 / NOT OK → old + 1. Not called under a
 *  failed F1 floor (nothing moves). */
uint32_t nodus_storage_fail_streak_next(uint32_t old, int had_eligible,
                                        int ok);

/** Position → height within the eligible blocks (pure): the blocks of
 *  ks[0..n) (k strictly ascending) in ascending height; position p is
 *  height (ks[p / P] − 1)·P + 1 + p % P. @return 0 / -1 (out of range,
 *  a non-ascending list, overflow). */
int nodus_storage_eligible_height(const uint64_t *ks, size_t n,
                                  uint64_t position, uint64_t *height_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_V2_STORAGE_H */
