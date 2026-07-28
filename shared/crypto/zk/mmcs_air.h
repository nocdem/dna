/**
 * @file mmcs_air.h
 * @brief P2b slice 1 — the SAME-HEIGHT binary MMCS-verify control AIR: column
 *        layout + constraint evaluation (EVALUATION ONLY, no prover).
 *
 * Design contract: dnac/docs/plans/2026-07-28-p2b-mmcs-in-air-design.md v2,
 * §0.5 "Constraint forms". Every "MUST" in that section is discharged here as
 * an EXPLICIT constraint; nothing is left to trace-generation convention (the
 * vacuous-range lesson, and P2a-i3's "the doc says it is not the code
 * constrains it"). Each constraint block below cites (a) the §0.5 form it
 * discharges and (b) the native `poseidon2_mmcs.c` line whose semantics it
 * mirrors, or the P3rec upstream line it ports.
 *
 * ── What this AIR is ────────────────────────────────────────────────────────
 * One trace = ONE opening of `dnac_p2_mmcs_verify` (poseidon2_mmcs.c:533-596):
 *   [leaf-hash rows] [`depth` compress rows] [1 final row] [padding]
 * exactly the schedule the PIN slice's preprocessed table generates
 * (`dnac_p2b_table_generate`, mmcs_air_table.c:86-113 — the ONE schedule
 * authority; this file never re-derives it, it reads the row count and the
 * leaf-row count back OUT of the generator).
 *
 * Row types come from the PREPROCESSED window, not from witness columns
 * (user-locked at O3, design §0.5). Their booleanity / exclusivity is a
 * TABLE-GENERATOR obligation under PIN-1 — nothing on the verify path checks
 * preprocessed cells (batch_verify.c:722-727 hands the window to `air_eval`
 * raw) — so this evaluator never constrains them; it is simply well defined
 * for arbitrary prep values, which are read as field elements.
 *
 * ⚠ PIN-1 / PIN-2 ARE PREREQUISITES OF EVERY GUARANTEE BELOW (design §0.5):
 *   - PIN-1: the P2b verify ENTRY must compare the decoded preprocessed root
 *     against DNAC_P2B_PREP_ROOT (`dnac_p2b_prep_root_check`) and fail closed.
 *     Without it the selector cells are prover-supplied proof data and every
 *     gated constraint here is satisfiable with an all-zero table.
 *   - PIN-2: the P2b descriptor MUST set `prep_next = 1`. The placement pair
 *     ported below reads the NEXT row's preprocessed window (upstream does the
 *     same, P3rec air.rs:986-1002 gates on `next_preprocessed`), and with
 *     `prep_next = 0` DNAC's verifier substitutes an all-zero next window
 *     (batch_verify.c:696-707) while the prover folds the real one
 *     (batch_prover.c:311-313) — silent vacuity.
 * Neither pin is enforced by THIS module: there is no P2b verify entry yet
 * (slice 1 is evaluation only). `dnac_mmcs_air_eval_row` takes the next-row
 * preprocessed window as a SEPARATE, REAL parameter, which is the shape a
 * `prep_next = 1` descriptor produces.
 *
 * ── Permutation delegation = INLINE embedding (design §0.5, as P2a) ─────────
 * The byte-matched 180-column `poseidon2_air` block sits at MAIR_PERM_OFF in
 * the AIR's own row. Binding is BY COLUMN IDENTITY: the block's `inputs[8]`
 * and its final-round `post[8]` ARE the sponge/compression state cells the
 * control constraints reference — there is no separate `state[8]` column
 * block, no bus, no CTL. The block's own constraints are evaluated UNGATED on
 * every row (design §0.5 A1-F5 resolution; the shipped precedent is
 * `conf_action_fold.c` / `transcript_air.c:159-164`), so leaf / final /
 * padding rows carry a VALID dummy permutation witness. Ungated is stricter
 * than gated and leaves no gate for an adversary to aim at; it is also what
 * keeps the degree claim true.
 *
 * ── Constraint degree ───────────────────────────────────────────────────────
 * Every control constraint here is degree <= 3, matching `poseidon2_air`'s own
 * max degree 3 (SBOX_REGISTERS = 1, poseidon2_air_cols.h:63), so the whole AIR
 * stays inside the FRI log_blowup = 2 envelope. The two degree-3 forms are the
 * placement pair (prep_next selector x next dir x linear) and the step-counter
 * advance (pos x prep_next-sum x linear); everything else is <= 2.
 *
 * ── Public values (P2c binds to THESE offsets) ──────────────────────────────
 *   [0, 4)                      root lanes                (MAIR_PUB_ROOT_OFF)
 *   [4, 4 + depth)              direction bits, LSB-first (MAIR_PUB_DIR_OFF)
 *   [4 + depth, + total_width)  opened rows, flattened in matrix order
 *                               (`dnac_mmcs_air_pub_opened_off`)
 * total = `dnac_mmcs_air_num_publics(cfg)`; any other length fails closed.
 *
 * The opened rows are PUBLIC because with INLINE embedding nothing else
 * connects the AIR's leaf preimage to what the CONSUMER thinks was opened
 * (design §0.5, round-1 A1-F2): without the equality the AIR would only prove
 * "*some* leaf is in the tree at index i". The flattening order is the native
 * one — matrix 0's row, then matrix 1's row, ... (poseidon2_mmcs.c:567-573).
 *
 * The direction bits are PUBLIC and LSB-first: index binding form A1,
 * user-locked 2026-07-29 (design §0.5 / G-DET-P2b-3). Level l's bit is bit l
 * of `leaf_index` — the native walk's own order (`idx >>= 1` per level,
 * poseidon2_mmcs.c:581-590) and upstream's PRODUCTION shape (`path_bits =
 * &index_bits[..path_depth]`, P3rec recursion/src/pcs/mmcs.rs:365, zipped with
 * the levels in order, circuit/src/ops/mmcs.rs:117). There is NO accumulator
 * column: upstream's `2*acc + bit` recurrence (air.rs:1027) is example-only
 * there and would compose to the BIT-REVERSAL of the native index.
 *
 * ── Native checks with NO in-AIR counterpart (design §0.5 OBL table) ────────
 *   OBL-1 `depth != log2(num_rows)`  (poseidon2_mmcs.c:553-554) — COMPOSITION:
 *         the circuit must be selected by a PINNED height, never by a
 *         prover-supplied depth.
 *   OBL-2 canonicality sweep         (poseidon2_mmcs.c:557-562) — COMMITMENT
 *         layer: AIR cells are field elements by construction.
 *   OBL-3 `leaf_index >= num_rows`   (poseidon2_mmcs.c:550) — COMPOSITION;
 *         implied by `depth` boolean bits ONLY once OBL-1 is discharged.
 *
 * ── Slice scope ─────────────────────────────────────────────────────────────
 * Same-height binary walk only (`dnac_p2_mmcs_verify`). Mixed-height layer
 * injection (`dnac_p2_mmcs_verify_mixed`) is slice 2. No prover: the honest
 * trace builder lives test-side in `tests/test_mmcs_air.c`, so the constraint
 * file cannot "help" the witness it checks.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_MMCS_AIR_H
#define DNAC_ZK_MMCS_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mmcs_air_table.h"   /* dnac_p2b_table_cfg_t + the row schedule */
#include "poseidon2_air_cols.h"
#include "poseidon2_mmcs.h"   /* DNAC_P2M_DIGEST_LANES */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Instance dimensions (mirror the native primitives, never re-declared) ── */
#define MAIR_DIGEST_LANES DNAC_P2M_DIGEST_LANES /* 4 — digest / root lanes   */
#define MAIR_PERM_WIDTH   P2AIR_WIDTH           /* 8 — permutation width     */
#define MAIR_RATE         DNAC_P2B_SPONGE_RATE  /* 4 — leaf-sponge rate      */

/**
 * Upper bound on the number of SCHEDULED (non-padding) rows a config may have,
 * and therefore the width of the step-index one-hot below.
 *
 * ⚠ Slice-1 evaluator constant, deliberately modest: it is re-pinned at P2c
 * together with the production schedule, exactly as `DNAC_P2B_PREP_ROOT` is a
 * MECHANISM pin against a REFERENCE schedule (mmcs_air_table.h:112-116). A
 * config whose padded table exceeds this bound fails CLOSED.
 */
#define MAIR_MAX_STEPS ((size_t)64)

/* ── Column layout (flat, padding-free; offsets are the binding contract) ─── */

/** Direction bit of THIS row's compression (upstream `mmcs_bit`, boolean and
 *  AIR-owned — P3rec air.rs:937 `builder.assert_bool(local.mmcs_bit)`). */
#define MAIR_DIR_OFF 0 /*   0   1 */

/**
 * Step-index ONE-HOT over the scheduled rows: `pos[i] = 1` iff this row is
 * step i of the pinned schedule (leaf blocks 0..leaf, then the `depth`
 * compress levels, then the final row); ALL ZERO on padding rows.
 *
 * ⚠ BEYOND-DOC (design §0.5 lists no such column). It is load-bearing and
 * there is no way around it: two of the required forms are ROW-INDEX
 * DEPENDENT — "the l-th compress row's `dir` equals public bit l" (A1) and
 * "leaf block i absorbs publics [4i, 4i+k)" — while a row-AIR's constraint set
 * is uniform over rows. Upstream carries the same information in PREPROCESSED
 * (its per-limb `in_ctl` / `input_indices` cells, P3rec air.rs:733-759), the
 * machinery P2b deliberately does not port; the P2b preprocessed table has
 * only the three row-type columns and is PINNED (its root would drift if
 * widened). So the index lives in the MAIN trace and is fully constrained
 * here: boolean, one-hot summing to the row's preprocessed type indicator,
 * pinned to `pos[0]` on row 0, advancing by exactly one per scheduled row, and
 * AGREEING with the preprocessed row type at every position.
 */
#define MAIR_POS_OFF 1 /*   1  MAIR_MAX_STEPS */

/** Embedded 180-column `poseidon2_air` block (INLINE, evaluated ungated). */
#define MAIR_PERM_OFF (MAIR_POS_OFF + MAIR_MAX_STEPS)

/** Total control-AIR trace width. == 245 (1 + 64 + 180). Far under
 *  DNAC_STARK_MAX_MAIN_WIDTH = 2560 (stark_constraints.h:243). */
#define MAIR_WIDTH (MAIR_PERM_OFF + (size_t)P2AIR_NUM_COLS)

/** Public-value block offsets (P2c binds to these). */
#define MAIR_PUB_ROOT_OFF ((size_t)0)
#define MAIR_PUB_DIR_OFF  ((size_t)MAIR_DIGEST_LANES)

/**
 * Fail-close sentinel: returned INSTEAD of a violation count when the config,
 * the public-value length or the row window is out of contract. Strictly
 * larger than any reachable PER-ROW violation count; `..._eval_trace`
 * SATURATES at MAIR_VIOL_BAD_CONFIG - 1 rather than overflowing, so a
 * saturated count and the sentinel stay distinguishable. A caller must treat
 * any non-zero return as "invalid" and only `== MAIR_VIOL_BAD_CONFIG` as "bad
 * config" (the P2a i3/A2-F5 contract, transcript_air.h:128-136).
 */
#define MAIR_VIOL_BAD_CONFIG 1000000

/* ── Column accessors (P2AIR accessor pattern, poseidon2_air_cols.h:77-107) ─ */

/** pos[i], i < MAIR_MAX_STEPS — the step-index one-hot. */
static inline size_t mair_pos_off(size_t i) { return (size_t)MAIR_POS_OFF + i; }

/** Embedded block: permutation PRE-image lane i (i < MAIR_PERM_WIDTH).
 *  On a leaf row these are the sponge state entering the permutation
 *  (poseidon2_mmcs.c:53-68); on a compress row they are `left ‖ right`
 *  (poseidon2_mmcs.c:80-83); on the final row lanes 0..4 carry the root. */
static inline size_t mair_perm_in_off(size_t i) {
    return (size_t)MAIR_PERM_OFF + p2air_input_off(i);
}

/** Embedded block: permutation OUTPUT lane i — the final ending-round `post`
 *  columns (poseidon2_air_trace.h:46-47). Lanes 0..4 are the running digest
 *  (`out = pre[0..4]`, poseidon2_mmcs.c:84). */
static inline size_t mair_perm_out_off(size_t i) {
    return (size_t)MAIR_PERM_OFF +
           p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, i);
}

/* ── Schedule / public-layout helpers (pure functions of the pinned cfg) ──── */

/** Σ widths[m] — the leaf sponge's input length (poseidon2_mmcs.c:567-573).
 *  0 for a rejected config. */
size_t dnac_mmcs_air_total_width(const dnac_p2b_table_cfg_t *cfg);

/** Number of leaf-hash rows == number of leaf permutations, read back out of
 *  `dnac_p2b_table_generate` (the ONE schedule authority). 0 on reject. */
size_t dnac_mmcs_air_leaf_rows(const dnac_p2b_table_cfg_t *cfg);

/** First public index of the opened-rows region (== 4 + depth). 0 on reject. */
size_t dnac_mmcs_air_pub_opened_off(const dnac_p2b_table_cfg_t *cfg);

/** Required public-value count (4 + depth + total_width). 0 on reject. */
size_t dnac_mmcs_air_num_publics(const dnac_p2b_table_cfg_t *cfg);

/**
 * @brief Structural self-check of the column layout (no overlap, no gap,
 *        MAIR_WIDTH consistent, accessors inside their blocks).
 * @return true iff the layout is internally consistent.
 */
bool dnac_mmcs_air_layout_check(void);

/**
 * @brief Evaluate every constraint anchored at ONE row.
 *
 * Evaluates the row-local constraints of the (`main_local`, `prep_local`) pair
 * plus the transition constraints into (`main_next`, `prep_next`). Pass
 * `main_next == prep_next == NULL` for the final trace row; a mixed NULL/
 * non-NULL pair is a contract violation and fails closed.
 *
 * ⚠ CONTRACT (the P2a i3/A2-F4 lesson, transcript_air.h:204-209): several
 * transition constraints pin the NEXT row's cells and rely on that row's OWN
 * row-local block to pin the rest of its one-hot group. A caller that
 * evaluates rows in isolation and never evaluates `next` as a `local` gets a
 * WEAKER system. Use `dnac_mmcs_air_eval_trace`, which evaluates every row
 * both ways; direct `eval_row` use is for negative tests only.
 *
 * PRECONDITION (same contract as `poseidon2_air_eval_row`): every main column
 * is a canonical Goldilocks u64 in [0, p). Preprocessed cells are read as
 * field elements and are NOT required to be boolean (generator obligation,
 * design §0.5 / round-1 A2-F5).
 *
 * @param main_local   MAIR_WIDTH columns.
 * @param main_next    MAIR_WIDTH columns, or NULL on the last row.
 * @param prep_local   DNAC_P2B_TABLE_COLS preprocessed cells of this row.
 * @param prep_next    DNAC_P2B_TABLE_COLS cells of the next row, or NULL.
 *                     REAL, never zero-filled: that is PIN-2 (`prep_next = 1`).
 * @param is_first_row non-zero on trace row 0 (boundary: MUST be step 0).
 * @param cfg          the pinned opening shape; NULL / out-of-range / a
 *                     schedule that does not fit MAIR_MAX_STEPS or that leaves
 *                     no padding row is fail-close.
 * @param publics      `dnac_mmcs_air_num_publics(cfg)` canonical values.
 * @return number of violated constraints (0 == valid), or MAIR_VIOL_BAD_CONFIG.
 */
int dnac_mmcs_air_eval_row(const uint64_t *main_local, const uint64_t *main_next,
                           const uint64_t *prep_local, const uint64_t *prep_next,
                           int is_first_row,
                           const dnac_p2b_table_cfg_t *cfg,
                           const uint64_t *publics, size_t num_publics);

/**
 * @brief Evaluate the whole trace: every row local, every adjacent pair.
 *
 * Enforces, beyond the per-row forms:
 *   - SCHEDULE CONFORMANCE (design §0.5 A1-F6): `n_rows` MUST equal
 *     `dnac_p2b_table_rows(cfg)`. The row count comes from the pinned
 *     schedule, NEVER from a witnessed length — otherwise a prover picks a
 *     shorter absorb. Fail-close (MAIR_VIOL_BAD_CONFIG).
 *   - TERMINALITY (the P2a-i3 shipped-HIGH shape, transcript_air.c:444-460):
 *     the LAST row's preprocessed cells MUST all be zero, i.e. the trace ends
 *     in a padding row. The final row gets no transition constraints, so this
 *     is what guarantees every row carrying a row type has a successor and no
 *     transition-anchored form is silently skipped. Counted as one violation.
 *
 * @param main_trace n_rows * MAIR_WIDTH canonical columns, row-major.
 * @param prep_table n_rows * DNAC_P2B_TABLE_COLS preprocessed cells,
 *                   row-major — the table PIN-1 pins the root of.
 * @param n_rows     number of rows (>= 1).
 * @return total violated constraints (0 == valid), or MAIR_VIOL_BAD_CONFIG.
 */
int dnac_mmcs_air_eval_trace(const uint64_t *main_trace,
                             const uint64_t *prep_table, size_t n_rows,
                             const dnac_p2b_table_cfg_t *cfg,
                             const uint64_t *publics, size_t num_publics);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_MMCS_AIR_H */
