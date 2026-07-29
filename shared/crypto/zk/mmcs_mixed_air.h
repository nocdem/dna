/**
 * @file mmcs_mixed_air.h
 * @brief P2b slice 2 — the MIXED-HEIGHT binary MMCS-verify control AIR: column
 *        layout + constraint evaluation (EVALUATION ONLY, no prover).
 *
 * Build spec (authoritative): dnac/docs/plans/2026-07-29-p2b-slice2-mixed-mmcs-
 * BUILDABLE.md (local-only) — "Native structure being ported" (:13-38), "Reuse
 * vs new" (:40-49), "Row schedule" (:51-67), "Publics layout" (:69-75),
 * "Constraints" (:77-91), "Eval-entry gates" (:93-96), "Mandatory negatives"
 * (:98-109), "Deferred to composition" (:111-116). Native oracle:
 * `dnac_p2_mmcs_verify_mixed` (poseidon2_mmcs.c:454-529); circuit reference
 * `circuit/src/ops/mmcs.rs:81-209` (P3rec @ b3633970). Consensus-inert; every
 * pin/seam deferred to composition, same posture as slice 1.
 *
 * ── What this AIR is ────────────────────────────────────────────────────────
 * One trace = ONE opening of `dnac_p2_mmcs_verify_mixed`:
 *   [ tallest-group leaf-hash rows ]
 *   per level l = 0..depth-1:
 *     [ compress row ]  C(digest, sibling) bit-ordered
 *     [ inject block, IFF a group's height == max_h>>(l+1) ]:
 *        [ injecting-group leaf-hash rows ] [ inject-compress row ]
 *   [ final root-equality row ]
 *   [ padding, LAST row is_pad ]
 * exactly the schedule `dnac_p2c_mmix_table_generate` emits
 * (mmcs_mixed_air_table.c) — the ONE schedule authority; this file never
 * re-derives it, it reads the row counts, the group shapes and the per-step
 * roles back OUT of the table accessors (the mmcs_air.c:34-40 pattern).
 *
 * Row types, the level one-hot `lvl`, the group one-hot `gsel`, the global step
 * one-hot `pos` and `has_inject` all come from the PREPROCESSED window, never
 * from witness columns. Their booleanity / exclusivity / one-hotness is a
 * TABLE-GENERATOR obligation under PIN-1-MMIX — nothing on the verify path
 * checks preprocessed cells (batch_verify.c:722-727 hands the window to
 * `air_eval` raw) — so this evaluator never constrains them; it is simply well
 * defined for arbitrary prep values, read as field elements. This is a
 * STRUCTURAL SIMPLIFICATION over slice 1: because `pos`/`lvl`/`gsel` are
 * PREPROCESSED and PINNED here (slice 1's mmcs_air carried a MAIN pos one-hot
 * and had to constrain its booleanity / one-hot / advance / row-0 anchor,
 * mmcs_air.c blocks C+G), the mixed AIR needs NO such main step-index block and
 * NO is_first_row anchor. `dnac_p2c_mmix_table_validate` is what checks the
 * generator, and the root KAT is what freezes the pair.
 *
 * ⚠ PIN-1-MMIX / PIN-2 ARE PREREQUISITES OF EVERY GUARANTEE BELOW (the
 * mmcs_air.h:29-43 posture, ported):
 *   - PIN-1-MMIX: the future P2b/P2c composition verify ENTRY MUST compare the
 *     decoded preprocessed root against DNAC_P2C_MMIX_PREP_ROOT
 *     (`dnac_p2c_mmix_prep_root_check`) and fail closed. Without it the selector
 *     cells are prover-supplied proof data (the prover commits its OWN table)
 *     and every gated constraint here is satisfiable with an all-zero table.
 *   - PIN-2: the P2b descriptor MUST set `prep_next = 1`. The running-digest and
 *     RDIG transition constraints below read the NEXT row's preprocessed window;
 *     with `prep_next = 0` DNAC's verifier substitutes an all-zero next window
 *     (batch_verify.c:696-707) while the prover folds the real one — silent
 *     vacuity. `dnac_mmix_air_eval_row` takes the next-row preprocessed window
 *     as a SEPARATE, REAL parameter (a `prep_next = 1` descriptor's shape) and
 *     rejects a next-MAIN-without-next-PREP call outright.
 * This slice is EVALUATION ONLY; no verify entry calls the comparator yet.
 *
 * ── Permutation delegation = INLINE embedding (mmcs_air / transcript_air) ────
 * The byte-matched 180-column `poseidon2_air` block sits at MMIX_PERM_OFF in the
 * AIR's own row. Binding is BY COLUMN IDENTITY: the block's `inputs[8]` and its
 * ending-round `post[8]` ARE the sponge/compression state cells the control
 * constraints reference — no separate state block, no bus, no CTL. The block's
 * own constraints are evaluated UNGATED on every row (mmcs_air.c:209-214,
 * transcript_air.c:159-164), so leaf / compress / inject / final / padding rows
 * all carry a VALID permutation witness. Ungated is stricter than gated, leaves
 * no gate for an adversary to aim at, and keeps the degree claim true.
 *
 * ── Constraint degree ───────────────────────────────────────────────────────
 * Every control constraint here is degree <= 3, matching `poseidon2_air`'s own
 * max degree 3 (SBOX_REGISTERS = 1), so the AIR stays inside the FRI
 * log_blowup = 2 envelope. The two degree-3 forms are the two halves of the
 * running-digest placement pair (`is_compress'` selector x next `dir` x linear);
 * everything else is <= 2. Each block in mmcs_mixed_air.c documents its degree.
 *
 * ── Main column layout (offsets are the binding contract) ───────────────────
 *   MMIX_DIR_OFF   [0,1)   direction bit of a compress row (boolean; 0 off
 *                          compress rows). Slice-1 form (mmcs_air.h:149-151).
 *   MMIX_RDIG_OFF  [1,5)   RUNNING-DIGEST CARRY (4 lanes). BEYOND-DOC and
 *                          load-bearing (see below): the running Merkle digest
 *                          entering an inject-compress's LEFT input comes from a
 *                          compress row that is NOT adjacent — the injecting
 *                          group's leaf-hash rows sit between them (native
 *                          poseidon2_mmcs.c:503-524). A 2-row-window AIR cannot
 *                          reach a non-adjacent row, so the pre-inject digest is
 *                          carried in this column: SEEDED from the injecting
 *                          compress's output (block J), HELD across the inject-
 *                          leaf rows (block K), READ as the inject-compress LEFT
 *                          (block F). Unconstrained on every other row (not read
 *                          there). The slice-1 analogue of a beyond-doc but
 *                          structurally-forced column is its MAIN pos one-hot
 *                          (mmcs_air.h:158-169).
 *   MMIX_PERM_OFF  [5, 5+180)  embedded 180-col poseidon2_air block (ungated).
 *   MMIX_WIDTH == 185, DERIVED from the last offset (the count-KAFADAN lesson,
 *   fri_oi_air.h:60-62): no magic width literal. Far under
 *   DNAC_STARK_MAX_MAIN_WIDTH.
 *
 * ── Public values (composition binds to THESE offsets) ──────────────────────
 *   [0, 4)                       root lanes                 MMIX_PUB_ROOT_OFF
 *   [4, 4 + depth)               direction bits, LSB-first  MMIX_PUB_DIR_OFF
 *   [4 + depth, + total_opened)  opened rows per matrix, flattened in matrix
 *                                order (SEMANTIC widths only; salt lanes are
 *                                NOT public) — dnac_mmix_air_pub_opened_off
 * total = `dnac_mmix_air_num_publics(cfg)`; any other length fails closed.
 *
 *   - The opened rows are PUBLIC because with INLINE embedding nothing else
 *     connects the AIR's leaf preimages to what the CONSUMER opened (the
 *     mmcs_air.h:71-75 argument). Flattening is matrix order — matrix 0's row,
 *     then matrix 1's row, ... — matching the native concat
 *     (poseidon2_mmcs.c:296-310). A group's leaf preimage interleaves each
 *     member matrix's DATA lanes (bound to that matrix's public slot) with
 *     `salt_elems` SALT lanes (private witness, absorbed but unbound — salt
 *     provenance is a composition seam).
 *   - The direction bits are PUBLIC and LSB-first: index binding form A1
 *     (user-locked 2026-07-29, the mmcs_air.h:76-88 posture). Level l's bit is
 *     bit l of `index`; the native walk halves `idx` per level
 *     (poseidon2_mmcs.c:501-511). There is NO accumulator column (a naive
 *     `2*acc+bit` compose against the LSB-first walk yields the BIT-REVERSAL of
 *     the native index). `index < max_h` is STRUCTURAL: only `depth` direction
 *     bits exist, so any claimable index is in [0, 2^depth) = [0, max_h).
 *
 * ── Native checks with NO in-AIR counterpart / declared seams (OBL ledger) ──
 *   OBL-1  depth != log2(max_h)         (poseidon2_mmcs.c:484) — enforced at
 *          eval entry via the table cfg gate (dnac_p2c_mmix_table_rows == 0);
 *          at COMPOSITION the circuit MUST be selected by a PINNED height, never
 *          a prover-supplied depth.
 *   OBL-2  canonicality sweep           (poseidon2_mmcs.c:476-477) — publics are
 *          FAIL-CLOSED here (< p); main cells are field elements by construction
 *          (commitment layer).
 *   OBL-3  opened rows <-> fri_oi_air p_x — the SAME opened values fri_oi_air's
 *          C3 consumes. `p_x` there is UNCONSTRAINED witness until the
 *          composition binds it to THESE opened-row publics; every soundness
 *          claim of both AIRs is conditional on that seam. THIS is the seam
 *          slice 2 exists to eventually bind.
 *   OBL-4  direction bits <-> the shared FRI query index — aliased with
 *          fri_oi_air's index bits and fri_air's; the composition binds them.
 *   OBL-5  PER-MATRIX REDUCED INDEX — for an injecting group at height h_m the
 *          native OPEN selects row `index >> (log2(max_h) - log2(h_m))`
 *          (poseidon2_mmcs.c:436-439), a SUFFIX of the shared index bits. ⚠ The
 *          VERIFY entry (:454-529) does NOT re-derive or check this — it trusts
 *          `opened_rows[m]` as given and uses only the full `index` for sibling
 *          placement. So no verify-side per-matrix-index constraint exists to
 *          port (fabricating one would be KAFADAN). The suffix bits ARE bound —
 *          they are direction-bit publics at levels >= the group's inject level,
 *          each pinned on its compress row (block D). Binding the OPENED ROW to
 *          that reduced index is a COMPOSITION seam (with OBL-3): the MMCS
 *          opened-row publics must be the rows the FRI query's reduced index
 *          selects.
 *   OBL-6  salt provenance — the per-matrix leaf salt lanes are absorbed but
 *          unbound; the composition pins `salt_elems` and the salt source.
 *   OBL-7  PIN-1-MMIX production re-pin — the ref root binds a REFERENCE cfg;
 *          the composition re-pins the cfg scalars (num_matrices / widths /
 *          heights / depth / salt_elems) INDEPENDENTLY of the root (the
 *          mmcs_air.h OBL-4 / mmcs_mixed_air_table.h:169-174 OBL-4-MMIX).
 *   OBL-8  multi-query — one trace == one query.
 *   OBL-9  the poseidon2 perm CTL/bus — slice embeds it inline, degree-ungated
 *          (mirror mmcs_air).
 *
 * ── Slice scope ─────────────────────────────────────────────────────────────
 * Mixed-height binary walk (`dnac_p2_mmcs_verify_mixed`). No prover: the honest
 * trace builder lives test-side in `tests/test_mmcs_mixed_air.c`, so the
 * constraint file cannot "help" the witness it checks.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_MMCS_MIXED_AIR_H
#define DNAC_ZK_MMCS_MIXED_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mmcs_mixed_air_table.h" /* dnac_p2c_mmix_table_cfg_t + the schedule  */
#include "poseidon2_air_cols.h"
#include "poseidon2_mmcs.h"        /* DNAC_P2M_DIGEST_LANES                     */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Instance dimensions (mirror the native primitives, never re-declared) ── */
#define MMIX_DIGEST_LANES DNAC_P2M_DIGEST_LANES   /* 4 — digest / root lanes    */
#define MMIX_PERM_WIDTH   P2AIR_WIDTH             /* 8 — permutation width      */
#define MMIX_RATE         DNAC_P2C_MMIX_SPONGE_RATE /* 4 — leaf-sponge rate     */

/* ── Main column layout (flat, padding-free; offsets are the binding contract) */

/** Direction bit of THIS row's compression (compress rows only; boolean and
 *  zero off compress rows). Slice-1 form (mmcs_air.h:149-151). */
#define MMIX_DIR_OFF ((size_t)0) /*   0   1 */

/** Running-digest CARRY (4 lanes) — the pre-inject Merkle digest carried from an
 *  injecting compress row, across the inject-leaf rows, into the inject-compress
 *  LEFT input. See the header note on why this is structurally required. */
#define MMIX_RDIG_OFF ((size_t)1) /*   1   4 */

/** Embedded 180-column `poseidon2_air` block (INLINE, evaluated ungated). */
#define MMIX_PERM_OFF (MMIX_RDIG_OFF + MMIX_DIGEST_LANES)

/** Total control-AIR trace width. == 185 (1 + 4 + 180). DERIVED from the last
 *  block's end — no magic width literal (count-KAFADAN). */
#define MMIX_WIDTH (MMIX_PERM_OFF + (size_t)P2AIR_NUM_COLS)

/** Public-value block offsets (composition binds to these). */
#define MMIX_PUB_ROOT_OFF ((size_t)0)
#define MMIX_PUB_DIR_OFF  ((size_t)MMIX_DIGEST_LANES)

/**
 * Fail-close sentinel: returned INSTEAD of a violation count when the config,
 * the public-value length or the row window is out of contract. Strictly larger
 * than any reachable per-row violation count; `dnac_mmix_air_eval_trace`
 * SATURATES at MMIX_VIOL_BAD_CONFIG - 1 rather than overflowing, so a saturated
 * count and the sentinel stay distinguishable. A caller MUST treat any non-zero
 * return as "invalid" and only `== MMIX_VIOL_BAD_CONFIG` as "bad config" (the
 * P2a i3/A2-F5 contract; mmcs_air.h:184-193).
 */
#define MMIX_VIOL_BAD_CONFIG 1000000

/* ── Column accessors (P2AIR accessor pattern, poseidon2_air_cols.h:77-107) ─ */

/** RDIG lane i, i < MMIX_DIGEST_LANES. */
static inline size_t mmix_rdig_off(size_t i) { return MMIX_RDIG_OFF + i; }

/** Embedded block: permutation PRE-image lane i (i < MMIX_PERM_WIDTH).
 *  Leaf/inject-leaf rows: the sponge state entering the permutation; compress /
 *  inject-compress rows: `left ‖ right`; final row lanes 0..4 carry the digest. */
static inline size_t mmix_perm_in_off(size_t i) {
    return MMIX_PERM_OFF + p2air_input_off(i);
}

/** Embedded block: permutation OUTPUT lane i — the final ending-round `post`
 *  columns. Lanes 0..4 are the running digest (`out = pre[0..4]`,
 *  poseidon2_mmcs.c:80-84). */
static inline size_t mmix_perm_out_off(size_t i) {
    return MMIX_PERM_OFF + p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, i);
}

/* ── Schedule / public-layout helpers (pure functions of the pinned cfg) ──── */

/** Σ widths[m] (SEMANTIC, no salt) — the opened-rows public length. 0 on a
 *  config the table module rejects. */
size_t dnac_mmix_air_total_opened(const dnac_p2c_mmix_table_cfg_t *cfg);

/** First public index of the opened-rows region (== 4 + depth). 0 on reject. */
size_t dnac_mmix_air_pub_opened_off(const dnac_p2c_mmix_table_cfg_t *cfg);

/** Required public-value count (4 + depth + total_opened). 0 on reject. */
size_t dnac_mmix_air_num_publics(const dnac_p2c_mmix_table_cfg_t *cfg);

/**
 * @brief Structural self-check of the column layout (no overlap, no gap,
 *        MMIX_WIDTH consistent, accessors inside their blocks).
 * @return true iff the layout is internally consistent.
 */
bool dnac_mmix_air_layout_check(void);

/**
 * @brief Evaluate every constraint anchored at ONE row.
 *
 * Evaluates the row-local constraints of the (`main_local`, `prep_local`) pair
 * plus the transition constraints into (`main_next`, `prep_next`). Pass
 * `main_next == prep_next == NULL` for the final trace row; a mixed NULL/
 * non-NULL pair is a contract violation and fails closed.
 *
 * ⚠ CONTRACT (the P2a i3/A2-F4 lesson; mmcs_air.h:245-252, fri_oi_air.h:257-264):
 * several transition constraints pin only PART of the next row and rely on that
 * row's OWN row-local block to pin the rest. A caller that evaluates rows in
 * isolation and never evaluates `next` as a `local` gets a WEAKER system. Use
 * `dnac_mmix_air_eval_trace`, which evaluates every row both ways; direct
 * `eval_row` use is for NEGATIVE TESTS only.
 *
 * PRECONDITION (same as `poseidon2_air_eval_row`): every MAIN column is a
 * canonical Goldilocks u64 in [0, p). Preprocessed cells are read as field
 * elements and are NOT required to be boolean (generator obligation under
 * PIN-1-MMIX). ⚠ PUBLICS are NOT a precondition: they are checked canonical
 * (< p) and any non-canonical public FAILS CLOSED (OBL-2; the P2b A2-F1 shape —
 * `fp()` aliases x and x+p while the native seam is representation-sensitive:
 * poseidon2_mmcs.c:476-477 sweep, :528 memcmp).
 *
 * @param main_local   MMIX_WIDTH columns.
 * @param main_next    MMIX_WIDTH columns, or NULL on the last row.
 * @param prep_local   DNAC_P2C_MMIX_TABLE_COLS preprocessed cells of this row.
 * @param prep_next    DNAC_P2C_MMIX_TABLE_COLS cells of the next row, or NULL.
 *                     REAL, never zero-filled: that is PIN-2 (`prep_next = 1`).
 * @param is_first_row UNUSED (the schedule's row-0 anchor is the PREPROCESSED
 *                     pos[0]/type cells, pinned under PIN-1-MMIX — contrast
 *                     slice 1's MAIN pos one-hot). Kept for signature parity
 *                     with mmcs_air / fri_oi_air.
 * @param cfg          the pinned opening shape; NULL / a config the table module
 *                     rejects is fail-close.
 * @param publics      `dnac_mmix_air_num_publics(cfg)` canonical values.
 * @return number of violated constraints (0 == valid), or MMIX_VIOL_BAD_CONFIG.
 */
int dnac_mmix_air_eval_row(const uint64_t *main_local, const uint64_t *main_next,
                           const uint64_t *prep_local, const uint64_t *prep_next,
                           int is_first_row,
                           const dnac_p2c_mmix_table_cfg_t *cfg,
                           const uint64_t *publics, size_t num_publics);

/**
 * @brief Evaluate the whole trace: every row local, every adjacent pair.
 *
 * Enforces, beyond the per-row forms (both fail-close, both BEFORE any
 * constraint):
 *   - SCHEDULE CONFORMANCE: `n_rows` MUST equal `dnac_p2c_mmix_table_rows(cfg)`.
 *     The row count comes from the PINNED schedule, never from a witnessed
 *     length — a shorter walk is a different statement.
 *   - TERMINALITY (the P2a-i3 shipped-HIGH shape, fri_oi_air's stricter posture):
 *     the LAST row's preprocessed window MUST be a PADDING row (is_pad == 1,
 *     every other primary type 0), so no transition-anchored form can be skipped
 *     by ending the trace early.
 *
 * @param main_trace n_rows * MMIX_WIDTH canonical columns, row-major.
 * @param prep_table n_rows * DNAC_P2C_MMIX_TABLE_COLS preprocessed cells,
 *                   row-major — the table PIN-1-MMIX pins the root of.
 * @param n_rows     number of rows (>= 1).
 * @return total violated constraints (0 == valid), or MMIX_VIOL_BAD_CONFIG.
 */
int dnac_mmix_air_eval_trace(const uint64_t *main_trace,
                             const uint64_t *prep_table, size_t n_rows,
                             const dnac_p2c_mmix_table_cfg_t *cfg,
                             const uint64_t *publics, size_t num_publics);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_MMCS_MIXED_AIR_H */
