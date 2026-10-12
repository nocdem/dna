/**
 * @file nodus_witness_v2_storage.h
 * @brief Storage reward v1 rev 4 (the ARCHIVE reward), package B2a — the
 *        chain side: frozen storage sets, segment roots and their
 *        publication, assignment, the storage epoch boundary (settlement,
 *        fail_streak, exit release, prune), and the storage leg's three
 *        archive-era loaders.
 *
 * Decisions: docs/plans/decisions/2026-10-05-storage-reward-is-for-
 * archive.md (reward = block archive; R = 3; amount = block count;
 * 3 failed epochs → skipped; 3 samples; full archives keep all; K5 a
 * skipped member returns after 12 settled epochs; K5a an OK epoch with
 * eligible blocks resets fail_streak to 0 even at 3 or more; K9 the grace
 * scales with the number of newly assigned segments — replaces G = 1;
 * K9a only a segment that already existed one epoch earlier and was
 * taken over counts, and the first storage boundary gives no grace),
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
 *   0. GATE — runs only when chain_config param 16 (RULESET_GEN_STORAGE)
 *      is in effect at B (a committed row with effective <= B, i.e.
 *      B >= H_act) AND the SYSTEM runtime the registry resolves is
 *      GEN_STORAGE or later; param in effect with an older runtime is a
 *      FAULT (the phase-6b' switch would have run). The param is read
 *      FIRST, so a chain without the vote never resolves a runtime here.
 *   1. SETTLE the epoch (H, H+E], H = B − 2E (rev 2.2 §5 steps 1-3; rev
 *      4 §5) — skipped when storage_set(H) does not exist (the first two
 *      storage boundaries). Weights, F1 floor, the F2 owner-OR-key
 *      exclusion and the three-state verdict (HF-6 6b-2), weighted pay
 *      from treasury pool 1 to the row's OWNER, fail_streak.
 *   2. PRUNE reports with epoch_start <= H and frozen sets with
 *      epoch_start < H (keeps set(B−2E), set(B−E), set(B): every set a
 *      later report or settlement reads).
 *   3. RELEASE every EXITING registry row: one locked UTXO (kind 0x11,
 *      index 201, unlock B + 12·E) to the row's payee_fp column — the
 *      OWNER since HF-6 6b-1 — status RELEASED.
 *   4. PUBLISH every unpublished segment k with k·P + 2E <= B, k
 *      ascending from the last published + 1 (one rule = the activation
 *      backfill AND the schedule; never an immature segment).
 *   5. FREEZE storage_set(B) = the ACTIVE rows (node_fp ASC, S(B)), each
 *      member's fail_streak copied (the input of holders(·, B)); then
 *      the K9 GRACE update (below) over that set, written to the
 *      registry and copied, AFTER the update, into the member rows.
 * Fixed order; every iteration over rows is an explicit ORDER BY on a
 * unique key; integer math only; no clock. Any failure is a node FAULT
 * (-2) — a boundary has no verdict class (nodus_witness_v2_epoch.h).
 *
 * ── GRACE (K9 + K9a, decision 2026-10-05-storage-reward-is-for-
 *    archive.md; replaces G = 1) ───────────────────────────────────────
 *   At boundary H, for each member m of storage_set(H):
 *       n(m) = 0                         when storage_set(H−E) does not
 *                                        exist (the first storage
 *                                        boundary after activation);
 *       n(m) = |{k : published_height(k) <= H − E ∧ m ∈ holders(k, H)
 *                    ∧ m ∉ holders(k, H−E)}|      otherwise
 *   — the segments that already existed one epoch ago and that m TAKES
 *   OVER (registration, another holder's exit or skip, a set change).
 *   A segment published in (H−E, H] — at H itself included — is NOT
 *   counted: every node still holds those blocks in its block store
 *   (K9a). An EXISTING set(H−E) with no member is a set: a member
 *   registered after it counts every old segment it is assigned. Each
 *   (m, k) is decided by nodus_storage_grace_counts. n(m) > 0 →
 *       grace_until(m) = max(grace_until(m), H + n(m)·E)
 *   (nodus_storage_grace_next; checked u64, a result past INT64_MAX — the
 *   stored INTEGER bound — is a FAULT). The registry row (leaf v2 field
 *   grace_until) and the frozen member row of set(H) carry the value
 *   AFTER this update. Epoch (H, H+E] is IN GRACE for m iff
 *   H < grace_until (oracle reading: the value after the update at H —
 *   so any n > 0 puts the epoch starting at H in grace). In grace: m is
 *   not probed (bit 0, not counted against it), weight 0 (earns
 *   nothing), fail_streak unchanged at that epoch's settlement.
 *   holders(k, X) = bytes item 3 over storage_set(X) with each member's
 *   fail_streak AS FROZEN at X. At the first storage boundary nobody is
 *   in grace: every member is probed and paid for its assigned segments
 *   from the first epoch on (K9a replaces K9's "an absent set(H−E) holds
 *   nothing, so every assigned segment is new there").
 *
 * ── ELIGIBILITY (nodus_storage_member_eligible — the one rule) ───────
 *   member m of storage_set(H) holds an ELIGIBLE segment k in epoch
 *   (H, H+E] iff m is NOT in grace for (H, H+E] and
 *       (published_height(k) <= H   and m ∈ holders(k, H))       assigned
 *    or (published_height(k) <= H−E and m ∈ holders(k, H − E))  overlap
 *   The first line is "every assigned segment counts" once the grace is
 *   over; the second keeps the one-epoch handoff: a holder DISPLACED at H
 *   (in holders(k,H−E), not in holders(k,H)) is still probed and paid for
 *   k through (H, H+E] and may delete k after H + E. (A member out of
 *   grace may still hold an assigned k it did not hold at H−E without
 *   grace for it: k published in (H−E, H], or any k at the first storage
 *   boundary — K9a.)
 *   weight(m) = DNA_V2_SEGMENT_BLOCKS × |eligible segments of m| (K1:
 *   block count). A member must be in storage_set(H) to have a bit. The
 *   settlement, the reporter's probe list and the probed node's answer
 *   read the same rule (nodus_witness_storage_eligible_segments); the
 *   holder's must-hold list (nodus_witness_storage_holder.h) is the same
 *   two lines WITHOUT the grace gate — a member in grace still fetches.
 *
 * ── SETTLEMENT (rev 2.2 §5 + rev 4 §5; HF-6 6b-2: design 2026-10-03-
 *    hf5-validator-owner-stake rev 6 §11.6-§11.7, decision 2026-10-09-
 *    kurultay-16-hf6-storage-summary.md item 8 + khan 2 "kural (a)") ──
 *   Seats are snapshot(H)'s entries; seat s is bitmap index s of every
 *   report. power(s) = nodus_witness_vset_powers over the WHOLE snapshot,
 *   once (the distribution's power, HF-6 5b: total_stake /
 *   DNAC_DECIMAL_UNIT for a ruleset-1 snapshot, the counted power for a
 *   ruleset-2 one — never re-capped over a filtered subset).
 *   P_total = Σ power(s); P_rep = Σ power of the seats with a committed
 *   report for H. F1: nothing moves (no pay, no fail_streak, no owner
 *   read) unless P_rep · 2 > P_total.
 *   key(s)   = SHA3-512(entry s's consensus pubkey) — the snapshot's key,
 *              never the row's current (rotated) one; two seats with one
 *              key are corrupt state (FAULT).
 *   owner(s) (nodus_witness_storage_seat_owners, once per settlement):
 *              ruleset 2 → entry s's owner_fp; ruleset 1 (the first
 *              settlement after the generation-4 edge reads the last
 *              snapshot frozen before it) → the §7.5 bridge: the
 *              committed v2 row keyed dna_validator_id_migrated(the
 *              boundary's chain id, entry s's pubkey), its owner_fp; a
 *              row absent or unreadable is a FAULT (khan A1, 2026-10-12:
 *              rows are never deleted — only node-local corruption loses
 *              one). Never SHA3-512(pubkey) read as an owner.
 *   For member m with registry row R(m) (owner_fp = R(m).payee_fp, the
 *   OWNER since 6b-1): seat s is EXCLUDED iff
 *       owner(s) == R(m).owner_fp   OR   key(s) == node_fp(m);
 *   I_m = Σ power(s) over reporting, non-excluded seats;
 *   Y_m = Σ power(s) over those whose report has m's bit set.
 *   The three-state verdict (nodus_storage_member_verdict, checked u64):
 *       2 · I_m <= P_total        → NO_EVIDENCE   (the independent floor)
 *       else 3 · Y_m > 2 · I_m    → OK
 *       else                      → NOT_OK.
 *   F1 has passed before any verdict is computed, so NO_EVIDENCE is never
 *   an F1 failure in disguise. A member whose owner is no seat's owner
 *   and whose key is no reporting seat has I_m = P_rep and, by F1, never
 *   NO_EVIDENCE.
 *   W = Σ weight over ALL members (a NO_EVIDENCE member's weight STAYS in
 *   W — its share is not redistributed); W == 0 → nothing. budget =
 *   pool1 >> 16 (treasury pool 1, read at this step); each OK member with
 *   weight w accrues floor(budget · w / W) (128-bit intermediate) to
 *   R(m)'s owner (the payee_fp column) through nodus_witness_v2_accrue;
 *   pool 1 is debited by exactly Σ credited, bound to the observed
 *   balance; unpaid shares and the remainder stay in pool 1.
 *   fail_streak (bytes item 4 + K5 + K5a), for every member of
 *   storage_set(H) (node_fp ASC), old = the live registry value, the
 *   first matching line applies:
 *     w > 0 and OK:  → 0, also when old ≥ 3 (K5a: placement trails the
 *               live counter by one epoch, so a member can still hold
 *               segments of epoch H while its live value is ≥ 3; a
 *               recovered member is not kept out for 12 epochs);
 *     old ≥ 3:  (the member is skipped for placement) +1; 14 → 0 instead
 *               of 15, so the member is placed again by the set frozen at
 *               this boundary (12 skipped epochs) and is skipped again
 *               after 3 new failures;
 *     w > 0 and NOT OK:  +1;
 *     otherwise (w == 0, old < 3):  unchanged.
 *   A member IN GRACE for (H, H+E] (K9) is skipped by this step — its
 *   fail_streak is unchanged even when it is 3 or more (K9's "fail_streak
 *   unchanged" read over K5's "+1 every settled epoch"; a long grace thus
 *   also pauses a skipped member's K5 return count). A NO_EVIDENCE member
 *   is skipped the same way (design §11.6 "hata sayacı DEĞİŞMEZ — :942'deki
 *   continue ile aynı atlama"): unchanged at 0, unchanged at 3 or more
 *   (its K5 return count pauses too). NOT_OK is the rule's "NOT OK".
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
#include "dnac/vset_wire.h"

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

/** One frozen storage set, as committed. Heap-allocate it (19.5 KB). */
typedef struct {
    uint64_t epoch_start;
    uint8_t  set_hash[64];                           /* S(H)              */
    uint32_t count;                                  /* 0..256            */
    uint8_t  fps[DNA_V2_STORAGE_SET_MAX][64];        /* node_fp ASC       */
    uint32_t fail_streak[DNA_V2_STORAGE_SET_MAX];    /* frozen at H       */
    uint64_t grace_until[DNA_V2_STORAGE_SET_MAX];    /* frozen at H, AFTER
                                                      * the K9 update     */
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

/** A member's settlement verdict (header "SETTLEMENT", HF-6 6b-2; the
 *  three states of design rev 6 §11.6 — one enum so two implementations
 *  cannot read the floor differently). */
typedef enum {
    NODUS_STORAGE_NO_EVIDENCE = 0,  /* 2·I <= P_total: unpaid, fail_streak
                                     * unchanged, weight stays in W      */
    NODUS_STORAGE_OK          = 1,  /* paid; fail_streak by the rule      */
    NODUS_STORAGE_NOT_OK      = 2   /* unpaid; fail_streak by the rule    */
} nodus_storage_verdict_t;

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

/** storage_set(epoch_start) with its members, their frozen fail_streaks
 *  and grace_until values (the latter as after the K9 update at
 *  epoch_start; the stored set_hash re-checked against the members).
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

/** The K9 grace update (pure; header "GRACE"): n == 0 → prev; else
 *  max(prev, H + n·E). @return 0 / -1 (H + n·E past UINT64_MAX — the
 *  boundary treats it, and any value above INT64_MAX, as a FAULT). */
int nodus_storage_grace_next(uint64_t prev, uint64_t H, uint64_t n,
                             uint64_t E, uint64_t *out);

/** The K9a grace COUNT for one (member m, segment k) at boundary H (pure;
 *  header "GRACE"): 1 iff `prev_exists` (storage_set(H−E) is a frozen
 *  set, empty included) and H >= E and published_height <= H − E and
 *  in_cur and not in_prev, where in_cur = m ∈ holders(k, set(H)) and
 *  in_prev = published_height(k) <= H − E ∧ m ∈ holders(k, set(H−E)).
 *  A segment published in (H−E, H] and every segment at the first storage
 *  boundary (no set(H−E)) give 0. n(m) = Σ over k. @return 1 / 0. */
int nodus_storage_grace_counts(uint64_t H, uint64_t E,
                               uint64_t published_height, int prev_exists,
                               int in_cur, int in_prev);

/** 1 iff epoch (H, H+E] is in grace for a member whose grace_until (the
 *  value frozen with storage_set(H), i.e. AFTER the update at H) is
 *  `grace_until`: H < grace_until. Pure. */
int nodus_storage_in_grace(uint64_t H, uint64_t grace_until);

/** THE eligibility rule (pure; header "ELIGIBILITY"): segment k is
 *  eligible for member m of storage_set(H) in epoch (H, H+E] iff m is not
 *  in grace (nodus_storage_in_grace(H, grace_until) == 0) and (in_cur or
 *  in_prev), where in_cur = m ∈ holders(k, set(H)) and in_prev =
 *  published_height(k) <= H − E ∧ m ∈ holders(k, set(H−E)). The
 *  settlement weights, the reporter's probe list and the probed node's
 *  answer all go through it (nodus_witness_storage_eligible_segments).
 *  @return 1 eligible / 0 not. */
int nodus_storage_member_eligible(uint64_t H, uint64_t grace_until,
                                  int in_cur, int in_prev);

/** fail_streak after one SETTLED epoch (pure; header "SETTLEMENT",
 *  bytes item 4 + K5 + K5a). `old` the live value, `had_eligible` 1 iff
 *  the member's weight in the epoch is > 0, `ok` the verdict. In order:
 *  had_eligible and OK → 0 whatever old (K5a); else old ≥ 3
 *  (DNA_V2_STORAGE_FAIL_LIMIT) → old + 1, or 0 when that would be
 *  NODUS_STORAGE_FAIL_RETURN or more; else had_eligible (NOT OK) →
 *  old + 1; else unchanged. Not called under a failed F1 floor (nothing
 *  moves), nor for a member in grace or with a NO_EVIDENCE verdict
 *  (unchanged); `ok` is 1 for OK, 0 for NOT_OK. */
uint32_t nodus_storage_fail_streak_next(uint32_t old, int had_eligible,
                                        int ok);

/** One member's three-state verdict (pure; header "SETTLEMENT"). Over the
 *  n_seat seats of snapshot(H): power[s], seat_owner[s] (owner(s)),
 *  seat_key[s] (SHA3-512 of the seat's consensus pubkey), reported[s]
 *  (nonzero = a committed report for H) and bit[s] (nonzero = that
 *  report sets the member's bit; read only where reported[s]). Seat s is
 *  excluded iff seat_owner[s] == member_owner OR seat_key[s] ==
 *  member_fp; I = Σ power of reporting non-excluded seats, Y = the part
 *  with the bit set; 2·I <= p_total → NO_EVIDENCE, else 3·Y > 2·I → OK,
 *  else NOT_OK. The caller has checked F1 (2·P_rep > p_total). `i_out` /
 *  `y_out` may be NULL. @return 0 (*out set) / -1 (NULL input, a sum or
 *  product past UINT64_MAX). */
int nodus_storage_member_verdict(uint32_t n_seat, const uint64_t *power,
                                 const uint8_t (*seat_owner)[64],
                                 const uint8_t (*seat_key)[64],
                                 const uint8_t *reported, const uint8_t *bit,
                                 uint64_t p_total,
                                 const uint8_t member_owner[64],
                                 const uint8_t member_fp[64],
                                 nodus_storage_verdict_t *out,
                                 uint64_t *i_out, uint64_t *y_out);

/** owner(s) for every seat of `snap` = snapshot(H) (header "SETTLEMENT";
 *  design rev 6 §11.7, khan A1): ruleset 2 → entry s's owner_fp (`w` and
 *  `chain_id` not read); ruleset 1 → the §7.5 bridge — the committed v2
 *  row keyed dna_validator_id_migrated(chain_id, entry s's pubkey), its
 *  owner_fp (the storage boundary runs only at generation >=
 *  NODUS_RT_GEN_STORAGE, where every pre-edge validator was migrated
 *  under that id). `chain_id` must be the boundary's (the migration's own
 *  input). owner_out has snap->active_count rows.
 *  @return 0 / -1 FAULT: any other ruleset, an id that does not derive,
 *  a row absent or unreadable (logged with the seat index). */
int nodus_witness_storage_seat_owners(nodus_witness_t *w,
                                      const dna_vset_snapshot_t *snap,
                                      const uint8_t chain_id[DNA_CHAIN_ID_LEN],
                                      uint8_t (*owner_out)[64]);

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
