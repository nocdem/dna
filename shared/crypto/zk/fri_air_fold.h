/**
 * @file fri_air_fold.h
 * @brief Composition s1a — the FRI fold-walk control AIR in VERIFIER-FOLD form
 *        (fp2 alpha-fold over the opened trace window at zeta).
 *
 * `fri_air.{c,h}` is a CONCRETE-TRACE checker: `dnac_fair_eval_row` /
 * `dnac_fair_eval_trace` walk u64 rows and COUNT violations. A batched STARK
 * verifier instead evaluates the constraint polynomial ONCE at the out-of-domain
 * point zeta over the opened fp2 values, alpha-folding every constraint in the
 * same PINNED order as the prover (`dnac_stark_folder_t`,
 * stark_constraints.h:262-283; the fold helpers :293-298). This module is that
 * fold-form eval, and NOTHING ELSE: the constraint SET is the u64 evaluator's
 * set, transcribed form by form, with each block citing the `fri_air.c` line it
 * mirrors. No new constraint is introduced and no u64 behaviour is "fixed"
 * here (composition slice s1a, transcription rules §3).
 *
 * ── WHAT CHANGES IN THE TRANSCRIPTION (and nothing else) ────────────────────
 *   1. Cell reads. `fp(main_local[C])` becomes `trace_local[C]`: at zeta each
 *      BASE trace column opens to an fp2 value. The constraint expressions are
 *      unchanged — they are polynomial identities over the base columns, so the
 *      u64 code's explicit lane arithmetic (with W = GOLDILOCKS_EXT_W) is
 *      transcribed lane for lane, c0 first (§3.7).
 *   2. Row selectors. The u64 `is_first_row` PARAMETER becomes
 *      `folder->is_first_row` — this is the wiring OBL-P2c-3 demands
 *      (fri_air.h:132-139): C3a, the sole anchor of the x0 chain, must fire on
 *      the COMPOSED system's own row-0 selector.
 *   3. Transitions. The u64 "evaluate the transition block only when a next row
 *      exists" becomes an explicit `folder->is_transition` factor on every
 *      transition form (§3.2). ⚠ DEGREE CONSEQUENCE, see below.
 *   4. Terminality. `dnac_fair_eval_trace`'s G4b gate (fri_air.c:585-590) is a
 *      C-level fail-close that has no counterpart in a row-uniform AIR; it
 *      becomes an EXPLICIT `is_last_row` boundary constraint (three of them —
 *      one per cell the u64 gate reads). Without it the final row's transition
 *      forms are void and every effect a row pins on its successor could be
 *      skipped by ending the trace on a typed row (the P2a-i3 shipped-HIGH
 *      shape). Emitted FIRST, matching the u64 order (the gate runs before any
 *      per-row constraint).
 *
 * ── ⚠ DEGREE: the is_transition factor raises the gated transition forms ─────
 * The u64 degree table (fri_air.c:29-51) counts IN-AIR factors only and lands
 * every form at <= 3 (one degree-1 preprocessed gate + a degree-2 inner form).
 * In fold form each transition additionally carries `is_transition`, which is a
 * degree-1 selector in the symbolic builder, so C3b / C3c / C4k / C4l reach
 * symbolic degree 4 (gate 1 + is_transition 1 + inner 2) and C3d / C4j reach 3.
 * This is a CONSEQUENCE of transcription rule §3.2, not a choice made here, and
 * it is a DESCRIPTOR duty for the composition entry: `log_quotient_degree` must
 * be sized for the max symbolic degree actually emitted. Flagged rather than
 * silently absorbed (the count/degree-KAFADAN discipline).
 *
 * ── s1b ENTRY DUTIES — deliberately NOT carried here (§3.2) ─────────────────
 *   - G4a SCHEDULE CONFORMANCE (`n_rows == dnac_p2c_table_rows(cfg)`,
 *     fri_air.c:565-570). A row-uniform AIR cannot see the trace height; the
 *     composition entry pins the instance's `degree_bits` against the cfg.
 *   - G6 PUBLICS (exact count + canonicality, fri_air.c:277-292). The count is
 *     a descriptor field (`dnac_batch_vinstance_t`), and canonicality is a
 *     decode-side duty — `folder->public_values` is already `gold_fp_t`.
 *     The shape RAIL below is memory safety, NOT this duty.
 *   - PIN-1-P2c (`dnac_p2c_prep_root_check`, fri_air_table.h:476-491) and PIN-2
 *     (`prep_next = 1`). Preprocessed cells are read RAW here, exactly as the
 *     u64 evaluator reads them (fri_air.h:39-47): under PIN-1-P2c their
 *     booleanity / exclusivity / one-hotness is the table GENERATOR's
 *     obligation. Without the root pin every gated form below is satisfiable
 *     with an all-zero table.
 *   - Every OBL in the fri_air.h ledger (OBL-1/2/3/4c, OBL-P2c-1..4) stands
 *     unchanged; this module changes none of them.
 *
 * ── SHAPE RAIL (memory safety, fail-close) ─────────────────────────────────
 * `air_eval` returns void — it has no error channel. When the window handed in
 * does not match what was bound (unbound module, wrong `main_width`, wrong
 * `num_public_values`, missing preprocessed window, `prep_width` under
 * DNAC_P2C_TABLE_COLS), this module emits ONE unsatisfiable constraint
 * (`assert_zero(1)`) and returns, rather than reading out of bounds. That is a
 * fail-close: an honest instance never trips it, and a tripped instance can
 * never satisfy the final OOD check.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_AIR_FOLD_H
#define DNAC_ZK_FRI_AIR_FOLD_H

#include <stddef.h>

#include "fri_air.h"           /* FAIR_COL_* / FAIR_NUM_COLS / the public layout */
#include "fri_air_table.h"     /* dnac_p2c_table_cfg_t + the preprocessed layout */
#include "stark_constraints.h" /* dnac_stark_air_t / dnac_stark_folder_t         */

#ifdef __cplusplus
extern "C" {
#endif

/** Bind status. Any non-zero value means "not bound"; `out_air` is untouched. */
typedef enum {
    DNAC_FAIR_FOLD_OK = 0,
    DNAC_FAIR_FOLD_ERR_PARAM = -1, /**< NULL cfg / NULL out_air              */
    DNAC_FAIR_FOLD_ERR_CFG = -2    /**< a cfg the table module rejects       */
} dnac_fair_fold_status_t;

/**
 * Constraint steps a single `dnac_fair_fold_air_eval` call emits, EXCLUSIVE of
 * the cfg-sized loops. Enumerated (not remembered) from the emission blocks in
 * fri_air_fold.c, in order:
 *
 *   G4b terminality   3   is_pad-1 / is_chain / is_fold
 *   C2a               1   bit booleanity
 *   C3a               1   row-0 chain anchor
 *   C4a               1   g*inv = -1/2
 *   C4b               1   g_sq = g*g
 *   C4c               2   t1 lanes
 *   C4d               2   t2 lanes
 *   C4e               2   beta_sq lanes
 *   C4f               2   rterm lanes
 *   C4i               2   ro == 0 off roll-in
 *   C5                2   terminal boundary lanes
 *   C3b               1   gb' = g*b'
 *   C3c               1   chain multiply
 *   C3d               1   handoff copy
 *   C4j               2   f_init boundary lanes
 *   C4k               1   x0 recurrence
 *   C4l               2   fold transition lanes
 *   ------------------------------------------------------------------
 *   total            27
 *
 * The cfg-sized part is `sched` (C2b, one per scheduled step) + `2*R` (C4g) +
 * `2*num_rollin` (C4h). `dnac_fair_fold_num_constraints` is the whole formula.
 */
#define FAIR_FOLD_FIXED_STEPS ((size_t)27)

/**
 * @brief Bind `cfg` to the module and fill the AIR descriptor.
 *
 * ⚠ CONTRACT (the callback signature cannot carry a context — stark_constraints.h
 * :290 is a shared surface and is NOT changed by this slice, so the binding is
 * MODULE-STATIC):
 *   - single-thread; ONE bound cfg at a time, process-wide;
 *   - bind BEFORE `dnac_batch_verify` / `dnac_batch_prove` and do not re-bind
 *     for the duration of that call. The composition entry (s1b) binds the
 *     PINNED cfg;
 *   - every quantity `air_eval` needs is SNAPSHOT at bind time (row counts,
 *     public-region offsets, roll-in ranks), so `cfg` itself need not outlive
 *     the call — but re-binding mid-verify silently changes the constraint
 *     system, which is why the single-bind contract is stated, not implied;
 *   - a REJECTED bind DISARMS any previous binding (bound is cleared on entry,
 *     FLEET 027 verifier-B H1): a caller that ignores the return code gets the
 *     unsatisfiable shape rail, never the stale cfg's constraint system.
 *
 * The cfg gates run through the SAME accessors the u64 evaluator uses
 * (`dnac_p2c_chain_rows` / `_fold_rows` / `_table_rows` / `dnac_fair_num_publics`
 * / `dnac_p2c_table_row`, fri_air.c:124-169), so a cfg `dnac_fair_eval_trace`
 * rejects is rejected here too, by construction.
 *
 * Descriptor written on success:
 *   main_width        = FAIR_NUM_COLS (21)
 *   num_public_values = dnac_fair_num_publics(cfg)
 *   main_next         = 1  (C3b/C3c/C3d/C4j/C4k/C4l read the next row)
 *   air_eval          = dnac_fair_fold_air_eval
 * The PREPROCESSED width and `prep_next = 1` are descriptor fields of
 * `dnac_batch_vinstance_t`, pinned by the composition entry (PIN-2) — a
 * `dnac_stark_air_t` has no field for them.
 *
 * @return DNAC_FAIR_FOLD_OK, or a negative status with `out_air` untouched.
 */
int dnac_fair_fold_bind(const dnac_p2c_table_cfg_t *cfg,
                        dnac_stark_air_t *out_air);

/**
 * @brief The fold-form eval callback. Emits the u64 evaluator's constraint set
 *        in the u64 evaluator's order (the alpha-fold is order-sensitive).
 *
 * PRECONDITION: `folder` is non-NULL (the `dnac_stark_air_t::air_eval` contract,
 * stark_constraints.h:290 — the glue always passes its own stack folder).
 * Everything else is checked by the shape rail described in the file header.
 */
void dnac_fair_fold_air_eval(dnac_stark_folder_t *folder);

/**
 * @brief Number of constraint steps one `dnac_fair_fold_air_eval` call emits
 *        for `cfg` — i.e. the `folder->capture_len` a captured run must show on
 *        EVERY row.
 *
 * = FAIR_FOLD_FIXED_STEPS + sched + 2*R + 2*num_rollin, with
 * sched = chain_rows + fold_rows. Independent of the row: the AIR is
 * row-uniform, which is exactly what the count test pins.
 *
 * @return 0 for a cfg the table module rejects (0 is unambiguously "reject":
 *         a bound cfg always emits at least FAIR_FOLD_FIXED_STEPS).
 */
size_t dnac_fair_fold_num_constraints(const dnac_p2c_table_cfg_t *cfg);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_AIR_FOLD_H */
