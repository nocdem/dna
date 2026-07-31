/**
 * @file fri_oi_air_fold.h
 * @brief Composition s1a — the FRI reduced-opening accumulation control AIR
 *        (open_input) in VERIFIER-FOLD form (fp2 alpha-fold at zeta).
 *
 * `fri_oi_air.{c,h}` is a CONCRETE-TRACE checker (`dnac_foi_eval_row` /
 * `dnac_foi_eval_trace` walk u64 rows and COUNT violations). A batched STARK
 * verifier evaluates the constraint polynomial ONCE at zeta over the opened fp2
 * values, alpha-folding every constraint in the same PINNED order as the prover
 * (`dnac_stark_folder_t`, stark_constraints.h:262-283). This module is that
 * fold-form eval and NOTHING else: the constraint SET is the u64 evaluator's
 * set, transcribed form by form, each block citing the `fri_oi_air.c` line it
 * mirrors. No new constraint, no "fix" of u64 behaviour (composition slice s1a).
 *
 * ── WHAT CHANGES IN THE TRANSCRIPTION (and nothing else) ────────────────────
 *   1. Cell reads: `fp(main_local[C])` -> `trace_local[C]` (each BASE column
 *      opens to an fp2 value at zeta); the explicit lane arithmetic with
 *      W = GOLDILOCKS_EXT_W is transcribed lane for lane, c0 first.
 *   2. `is_first_row` PARAMETER -> `folder->is_first_row` (C1a) — the wiring
 *      OBL-P2c-3 demands (fri_oi_air.h:95-98): C1a is the SOLE anchor of the x0
 *      chain, so it must fire on the COMPOSED system's own row-0 selector.
 *   3. "transition block only when a next row exists" -> an explicit
 *      `folder->is_transition` factor on every transition form (§3.2).
 *      ⚠ DEGREE CONSEQUENCE, below.
 *   4. `dnac_foi_eval_trace`'s TERMINALITY gate (fri_oi_air.c:517-528) has no
 *      counterpart in a row-uniform AIR, so it becomes an EXPLICIT `is_last_row`
 *      boundary — one constraint per cell the u64 gate reads (5). Emitted
 *      FIRST, matching the u64 order.
 *
 * ── ⚠ THE TWO A2 CLOSURES ARE PRESERVED VERBATIM ────────────────────────────
 *   - C2e REGISTER HOLD stays UNGATED by row type (fri_oi_air.c:16-23, :469-477):
 *     x_reg[i] is held on EVERY transition, so it is globally constant and
 *     pinned by its single C2c write. The spec's store-row exemption reopens the
 *     write-key/read-key hole; the strengthening is deliberate and is proved by
 *     the N-F2 second witness. In fold form the constraint is
 *     `is_transition * (x_reg' - x_reg)` — the is_transition factor is the
 *     mechanical §3.2 wrapper, NOT a row-type gate, so the strengthening holds.
 *   - C3f ONE-SIDED CARRY stays gated on the CURRENT row's `is_acc`
 *     (fri_oi_air.c:479-500), never on this-AND-next: that is what makes the
 *     closeout's ro the group's final accumulation (N-F1).
 *
 * ── ⚠ DEGREE: the is_transition factor raises the gated transition forms ─────
 * The u64 degree table (fri_oi_air.c:25-51) counts IN-AIR factors only and lands
 * every form at <= 3. In fold form each transition additionally carries
 * `is_transition` (a degree-1 selector), so C1b / C2b-sq reach symbolic degree 4
 * and C2d / C2b-st / C3f reach 2-3. A DESCRIPTOR duty for the composition entry
 * (`log_quotient_degree` must cover the max symbolic degree emitted) — flagged,
 * not silently absorbed.
 * C3g (s2) is ROW-LOCAL and carries no is_transition factor: `pos_k * (p_x -
 * pub)` is a degree-1 prep selector against a linear main-column form, i.e.
 * symbolic degree 2 — it does not move the maximum, so DNAC_P2S_MAX_SYMBOLIC_
 * DEGREE and with it `log_num_qc` are unchanged by the s2 slice.
 *
 * ── s1b ENTRY DUTIES — deliberately NOT carried here (§3.2) ─────────────────
 *   - SCHEDULE CONFORMANCE (`n_rows == dnac_p2c_oi_table_rows(cfg)`,
 *     fri_oi_air.c:513-515): a row-uniform AIR cannot see the trace height.
 *   - PUBLICS: exact count (a descriptor field) + canonicality (a decode-side
 *     duty; `folder->public_values` is already `gold_fp_t`). The shape RAIL
 *     below is memory safety, NOT this duty.
 *   - PIN-1-OI (`dnac_p2c_oi_prep_root_check`) and the PIN-2 analog
 *     (`prep_next = 1`). Preprocessed cells are read RAW, exactly as the u64
 *     evaluator reads them (fri_oi_air.h:28-35): without the root pin every
 *     gated form below is satisfiable with an all-zero table.
 *   - Every declared seam of fri_oi_air.h:84-98 (p_x <-> MMCS opened rows,
 *     alpha/z provenance, roll-in set-equality, multi-query) stands unchanged.
 *
 * ── SHAPE RAIL (memory safety, fail-close) ─────────────────────────────────
 * `air_eval` returns void. When the window does not match what was bound (NULL
 * `folder->ctx`, an unbound state, wrong `main_width`, wrong
 * `num_public_values`, missing preprocessed window, `prep_width` under
 * DNAC_P2C_OI_TABLE_COLS) this module emits ONE unsatisfiable constraint and
 * returns rather than reading out of bounds.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_OI_AIR_FOLD_H
#define DNAC_ZK_FRI_OI_AIR_FOLD_H

#include <stddef.h>

#include "fri_oi_air.h"        /* FOI_COL_* / the public layout accessors     */
#include "fri_oi_air_table.h"  /* dnac_p2c_oi_table_cfg_t + the prep layout   */
#include "stark_constraints.h" /* dnac_stark_air_t / dnac_stark_folder_t      */

#ifdef __cplusplus
extern "C" {
#endif

/** Bind status. Any non-zero value means "not bound": `out_air->ctx` is set to
 *  NULL (DISARMED) and its shape fields are left as the caller had them. */
typedef enum {
    DNAC_FOI_FOLD_OK = 0,
    DNAC_FOI_FOLD_ERR_PARAM = -1, /**< NULL cfg / NULL out_air               */
    DNAC_FOI_FOLD_ERR_CFG = -2    /**< a cfg the table module rejects        */
} dnac_foi_fold_status_t;

/**
 * Constraint steps one `dnac_foi_fold_air_eval` call emits, EXCLUSIVE of the
 * cfg-sized loops. Enumerated (not remembered) from the emission blocks in
 * fri_oi_air_fold.c, in order:
 *
 *   terminality       5   is_pad-1 / is_chain / is_capture / is_acc / is_closeout
 *   C1a               1   row-0 chain anchor
 *   C1c-b             1   bit booleanity on chain rows
 *   C2a               1   capture seed anchor
 *   C3a               4   group start: alpha_pow == 1 (2 lanes), ro == 0 (2)
 *   C3d               2   (z-x)*quot = 1 lanes
 *   C3e               2   t = alpha_pow*(p_z - p_x) lanes
 *   C4b               2   final-closeout ro == 0 lanes
 *   C1b               2   gb' / g' chain transition
 *   C2b               2   squaring pair + store copy
 *   C2d               1   chain resume across a capture block
 *   C3f               4   ro carry (2 lanes) + alpha_pow advance (2 lanes)
 *   ------------------------------------------------------------------
 *   total            27
 *
 * The cfg-sized part is 5*num_heights (C2c + C3b + C2e, one each, + C4a's two
 * lanes), lgmh (C1c-p, one per chain step), 5*total_acc (4 lanes of C3c plus
 * the ONE lane of C3g, s2 — emitted immediately after C3c, inside the same pos
 * gate) and 2*n_lb_zero (C5, one pair per lb per-batch boundary — n_lb_zero is 0
 * whenever the cfg has NO height at lb, which is the shape of a real inner
 * proof, FLEET 029). `dnac_foi_fold_num_constraints` is the whole formula.
 */
#define FOI_FOLD_FIXED_STEPS ((size_t)27)

/** "No mapping for this scheduled step" (the (size_t)-1 sentinel of
 *  fri_oi_air.c:131-135), used by `dnac_foi_fold_state_t`'s per-step maps. */
#define DNAC_FOI_FOLD_NO_MAP ((size_t)-1)

/**
 * @brief The cfg-derived snapshot `dnac_foi_fold_air_eval` runs on — the object
 *        `dnac_stark_air_t::ctx` points at (FLEET 034). Mirrors `foi_sched_t`
 *        (fri_oi_air.c:85-102).
 *
 * PUBLIC only so the caller can OWN the storage; the fields are this module's
 * business. Fill it ONLY through `dnac_foi_fold_bind`. A zeroed state is
 * "unbound" and fails closed. The cfg POINTER is deliberately NOT kept — every
 * derived quantity is copied.
 */
typedef struct {
    int    bound;
    size_t lgmh;
    size_t num_heights;
    size_t sched;
    size_t num_cols;
    size_t total_acc;
    size_t pub_alpha;
    size_t pub_zpz;
    size_t pub_ro;
    size_t pub_px;
    size_t num_publics;
    size_t n_lb_zero; /**< number of lb per-batch boundaries (C5 pairs)       */
    /* Per SCHEDULED step k (< sched); every other step carries the sentinel. */
    size_t bit[DNAC_P2C_OI_MAX_STEPS];     /**< chain step: index bit         */
    size_t accidx[DNAC_P2C_OI_MAX_STEPS];  /**< acc step: global acc index    */
    int    lb_zero[DNAC_P2C_OI_MAX_STEPS]; /**< lb-group per-batch boundary   */
} dnac_foi_fold_state_t;

/**
 * @brief Bind `cfg` into `state` and fill the AIR descriptor.
 *
 * ⚠ CONTRACT — identical to `dnac_fair_fold_bind` (FLEET 034: the callback
 * signature still carries no context, but `dnac_stark_folder_t` does —
 * `folder->ctx`, copied verbatim from `dnac_stark_air_t::ctx` — so the binding
 * is CALLER-OWNED, not module-static):
 *   - N SIMULTANEOUS bindings are legal; two descriptors with two states may
 *     carry two DIFFERENT cfgs of THIS AIR in the same batch;
 *   - ⚠ LIFETIME: `state` must outlive every `air_eval` call made under this
 *     binding, i.e. the whole `dnac_batch_verify` / `dnac_batch_prove` call;
 *   - every quantity `air_eval` needs is SNAPSHOT at bind (row counts, public
 *     offsets, the per-step chain-bit / acc-index / lb-boundary maps), so `cfg`
 *     need not outlive the call;
 *   - a REJECTED bind DISARMS BOTH `state` (`bound` cleared) AND `out_air`
 *     (`ctx` set to NULL), on entry, before any validation (FLEET 027
 *     verifier-B H1): a caller that ignores the return code gets the
 *     unsatisfiable shape rail, never the stale cfg's constraint system.
 *     ⚠ Clearing the state alone would NOT deliver that — see the same note in
 *     fri_air_fold.h. The shape fields are the caller's and are NOT modified;
 *   - determinism is unaffected: the state is a pure function of the pinned cfg.
 *
 * The cfg gates run through the SAME accessors the u64 evaluator uses
 * (fri_oi_air.c:104-188), so a cfg `dnac_foi_eval_trace` rejects is rejected
 * here too, by construction.
 *
 * Descriptor written on success:
 *   main_width        = dnac_foi_num_cols(cfg)  (FOI_NUM_FIXED_COLS + heights)
 *   num_public_values = dnac_foi_num_publics(cfg)
 *   main_next         = 1  (C1b/C2b/C2d/C2e/C3f read the next row)
 *   air_eval          = dnac_foi_fold_air_eval
 *   ctx               = state
 *
 * @return DNAC_FOI_FOLD_OK, or a negative status. On failure `out_air->ctx` is
 *         NULL (disarmed) and `out_air`'s shape fields are untouched.
 */
int dnac_foi_fold_bind(const dnac_p2c_oi_table_cfg_t *cfg,
                       dnac_foi_fold_state_t *state,
                       dnac_stark_air_t *out_air);

/**
 * @brief The fold-form eval callback. Emits the u64 evaluator's constraint set
 *        in the u64 evaluator's order (the alpha-fold is order-sensitive).
 *
 * Reads its cfg snapshot from `folder->ctx` (a `const dnac_foi_fold_state_t *`).
 * PRECONDITION: `folder` is non-NULL (the `air_eval` contract).
 */
void dnac_foi_fold_air_eval(dnac_stark_folder_t *folder);

/**
 * @brief Number of constraint steps one `dnac_foi_fold_air_eval` call emits for
 *        `cfg` — i.e. the `folder->capture_len` a captured run shows on EVERY
 *        row (the AIR is row-uniform).
 *
 * = FOI_FOLD_FIXED_STEPS + 5*num_heights + lgmh + 5*total_acc + 2*n_lb_zero,
 * where the 5*total_acc is C3c's four lanes plus C3g's one (s2) and n_lb_zero is
 * the number of lb-group per-batch boundaries
 * (== heights[num_heights-1].num_batches - 1 for the gated cfg shape).
 *
 * @return 0 for a cfg the table module rejects.
 */
size_t dnac_foi_fold_num_constraints(const dnac_p2c_oi_table_cfg_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_OI_AIR_FOLD_H */
