/**
 * @file fri_oi_air.h
 * @brief P2c open_input slice — the FRI REDUCED-OPENING ACCUMULATION control
 *        AIR: column layout, public layout and constraint evaluation
 *        (EVALUATION ONLY, no prover).
 *
 * Build spec (authoritative): dnac/docs/plans/2026-07-29-p2c-oi-BUILDABLE-v3.md
 * (local-only) — "Constraints" C1..C6 (:50-108), "Main columns" (:36-48),
 * "Eval-entry gates" (:110-115), "PIN-1-OI PREREQUISITE" (:117-121),
 * "Mandatory negative tests" (:123-136). The v3 spec supersedes §0.5/§6 of the
 * design doc (red-teamed NOT-GREEN twice); ALL 8 FLEET-024 fixes are folded in.
 *
 * ── What this AIR is ────────────────────────────────────────────────────────
 * One trace = ONE query's reduced-opening accumulation walk of
 * `fri_open_input` (fri_verifier.c:187-501), under ONE pinned cfg:
 *
 *   [ lgmh chain rows, INTERLEAVED capture blocks ]  MSB-first x0 anchor +
 *        per-height x_h = 7 * g^{2^{lgmh-h}} capture (spec C1/C2)
 *   [ DESCENDING accumulation GROUPS ]               one ro accumulator per
 *        height, ro += alpha_pow*(p_z-p_x)/(z-x)     (spec C3/C4/C5)
 *   [ >=1 pad rows ]                                  terminality
 *
 * exactly the schedule `dnac_p2c_oi_table_generate` emits (fri_oi_air_table.c) —
 * the ONE schedule authority; this file never re-derives it, it reads the row
 * counts, the chain-bit map, the per-acc-row public slots and the lb per-batch
 * boundaries back OUT of the generator (the fri_air.c:89-104 pattern).
 *
 * Row types, the height one-hot `h_sel`, the step one-hot `pos` and the chain's
 * G_j literals all come from the PREPROCESSED window, never from witness
 * columns. Their booleanity / exclusivity / one-hotness is a TABLE-GENERATOR
 * obligation under PIN-1-OI — nothing on the verify path checks preprocessed
 * cells (batch_verify.c:722-727 hands the window to `air_eval` raw) — so this
 * evaluator never constrains them; it is simply well defined for arbitrary prep
 * values, read as field elements. `dnac_p2c_oi_table_validate` is what checks
 * the generator, and the root KAT is what freezes the pair.
 *
 * ⚠ PIN-1-OI IS A PREREQUISITE OF EVERY GUARANTEE BELOW (spec :117-121, the
 * fri_air.h:49-56 posture verbatim): the future P2c verify ENTRY must compare
 * the decoded preprocessed root against DNAC_P2C_OI_PREP_ROOT
 * (`dnac_p2c_oi_prep_root_check`, fri_oi_air_table.h) and fail closed. Without
 * it the selector cells are prover-supplied proof data (the prover commits its
 * OWN table) and every gated constraint here is satisfiable with an all-zero
 * table. This slice is EVALUATION ONLY; no verify entry calls the comparator
 * yet. `dnac_foi_eval_row` takes the next-row preprocessed window as a SEPARATE
 * REAL parameter (the PIN-2 analog) and rejects a next-MAIN-without-next-PREP
 * call outright.
 *
 * ── COLUMN LAYOUT DIVERGENCE FROM THE SPEC LIST (reported, deliberate) ───────
 *   1. `gb` (base) is ADDED. The spec's "Main columns" list (:36-48) omits it,
 *      but the spec's C1b form (:55-56) references `gb'`, and without a gb
 *      intermediate the chain multiply g' = g*(1 + b'*(G'-1)) is DEGREE 4,
 *      violating the spec's own "degree <= 3" title (:50). fri_air carries the
 *      same intermediate (FAIR_COL_GB). Added here, degree held at 3.
 *   2. The `x_reg` block is placed LAST (after `t`), not 4th as the list writes
 *      it. `x_reg` is the ONE variable-width block (k = num_heights registers,
 *      spec :41), so putting it last keeps every OTHER column at a CONSTANT
 *      offset; the total width is a function of the cfg. Physical column order
 *      is internal to this eval-only module (no wire consumer), so the list
 *      order is descriptive, not binding.
 * The count-KAFADAN lesson (FLEET 020): FOI_NUM_FIXED_COLS is DERIVED from the
 * last fixed offset, and `dnac_foi_num_cols` = that + num_heights, so no magic
 * width literal can drift from the list.
 *
 * ── Public values (composition binds to THESE offsets) ──────────────────────
 *   [0, lgmh)                        index bits          FOI_PUB_BITS_OFF
 *   [lgmh, lgmh+2)                   alpha, fp2 [c0,c1]  dnac_foi_pub_alpha_off
 *   [+2, +2 + 4*total_acc)           per acc row: z(2), p_z(2), schedule order
 *                                                        dnac_foi_pub_zpz_off
 *   [.., + 2*num_heights)            exported ro per height, DESCENDING
 *                                                        dnac_foi_pub_ro_off
 *   [.., + total_acc)                per acc row: p_x (ONE BASE lane), schedule
 *                                    order                dnac_foi_pub_px_off
 * total = `dnac_foi_num_publics(cfg)`; any other length fails closed.
 *
 *   - BITS are public (composition binds them to the P2a transcript index; here
 *     the chain reads them MSB-first, bit lgmh-1-j on chain row j).
 *   - ALPHA is public (slice 1 carries no transcript); the composition binds it
 *     to the P2a challenge (OBL alpha/z provenance).
 *   - z, p_z sit one fp2 pair each PER acc row in schedule (batch-major,
 *     height-descending) order.
 *   - P_X is public as of the s2 slice, ONE base lane per acc row in the SAME
 *     schedule order as the z / p_z pairs. The region is appended at the END so
 *     every pre-existing offset is unmoved. It is bound to the trace column by
 *     C3g (fri_oi_air.c), so `p_x` is no longer a free witness. Native
 *     correspondent: `p_at_x = bo->opened_values[m][j]` (fri_verifier.c:469-476)
 *     — a BASE-field opened value, which is why one lane suffices.
 *     ⚠ WHO FILLS THE PUBLIC is the composition's job, and only PART of it is
 *     closed today: see the declared seam below.
 *   - RO is exported one fp2 per height in DESCENDING height order, matching the
 *     native's descending write (fri_verifier.c:490-497) and the roll-in slots
 *     fri_air consumes (OBL roll-in set-equality).
 *
 * ── Declared seams (deferred to composition, NOT holes — spec :138-142) ──────
 *   - p_x <-> the MMCS opened rows. C3g pins `p_x` to a PUBLIC (s2); what a
 *     public is worth depends entirely on where the composition sources it. The
 *     composition entry (fri_statement.c) sources the MAIN input batch's acc
 *     rows from the mmix instance's opened-row publics — for those rows the seam
 *     is CLOSED by aliasing — and the remaining batches' rows from a statement
 *     field, which is the same trust level p_x had before, now inside the
 *     mechanism instead of outside it. Every ro-correctness claim of this AIR
 *     remains conditional on that remainder.
 *   - alpha / z provenance from the P2a transcript (Fiat-Shamir order).
 *   - roll-in set-equality OI.H ⊇ fri_air.rollin: every height fri_air rolls in
 *     MUST be an exported ro slot here. A height AT lb is OPTIONAL in the cfg
 *     (FLEET 029 — a real inner proof has none, mirroring the native's
 *     CONDITIONAL lb check, fri_verifier.c:482-487): when H HAS one, C4b pins
 *     that ro to zero and fri_air's final-height slot reads 0; when it does NOT,
 *     C4b is vacuous and the composition MUST NOT wire a roll-in at lb either.
 *     ⚠ That obligation is NOT self-enforcing on the fri_air side: its cfg gate
 *     admits roll-in heights in [log_blowup + log_final_poly_len, lgmh - 1]
 *     (fri_air_table.c:64/89) and log_final_poly_len is pinned to 0 (gate G2),
 *     so lb IS an admissible roll-in height there. The composition entry owns
 *     the cross-check "every fri_air roll-in height appears in OI.H".
 *   - multi-query (OBL-P2c-2): one trace == one query.
 *   - PIN-1-OI production re-pin (OBL-4c-OI): the ref root binds a REFERENCE
 *     cfg; the composition re-pins the cfg scalars INDEPENDENTLY of the root.
 *   - OBL-P2c-3 ROW-0 SELECTOR: C1a (the SOLE anchor of the x0 chain) fires on
 *     the caller-supplied `is_first_row` flag, not a preprocessed cell. The
 *     composition MUST wire the composed system's own first-row selector to it;
 *     dropping it frees g[0] and with it the whole chain.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_OI_AIR_H
#define DNAC_ZK_FRI_OI_AIR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "field_goldilocks.h"    /* GOLDILOCKS_P / _GENERATOR / _EXT_W        */
#include "fri_oi_air_table.h"    /* dnac_p2c_oi_table_cfg_t + the row schedule */

#ifdef __cplusplus
extern "C" {
#endif

/* ── Main column layout ──────────────────────────────────────────────────────
 * The FIXED columns (constant offsets); the variable `x_reg` block follows.
 * fp2 quantities are TWO consecutive base lanes [c0, c1]. The one base-field
 * actor entering fp2 expressions in the c0 lane only is `x` (the eval point) and
 * `p_x` (the opened value). */

/** b — the index bit this chain row consumes (chain row j: bit lgmh-1-j).
 *  Boolean + public-bound on is_chain rows (C1c). */
#define FOI_COL_B ((size_t)0)

/** g — the MSB-first x0 chain accumulator; copied UNCHANGED across each capture
 *  block (C2d) so the chain resumes at the height prefix. Base field. */
#define FOI_COL_G ((size_t)1)

/** y — capture squaring scratch, SEPARATE from g (spec :40, FIX F10c). Seeded
 *  to g (C2a), squared cum_h times (C2b), read by the store (C2c). */
#define FOI_COL_Y ((size_t)2)

/** gb — g * b', the chain-transition intermediate (C1b). Written on the chain
 *  row the product FEEDS, pinned by the predecessor's pn_chain gate. ADDED vs
 *  the spec column list (see the header divergence note); degree-relief only. */
#define FOI_COL_GB ((size_t)3)

/** alpha_pow[2] — the per-height accumulator power (fp2). Reset to 1 on the
 *  group start (C3a), advanced by *alpha on every acc row (C3f). */
#define FOI_COL_ALPHA_POW ((size_t)4)

/** ro[2] — the per-height reduced-opening accumulator (fp2). Reset to 0 on the
 *  group start (C3a), advanced by +t*quot on every acc row (C3f), exported at
 *  the closeout (C4). */
#define FOI_COL_RO ((size_t)6)

/** z[2] — this acc row's opening point (fp2). Bound to a public (C3c). */
#define FOI_COL_Z ((size_t)8)

/** p_z[2] — this acc row's claimed evaluation p(z) (fp2). Bound to a public
 *  (C3c). */
#define FOI_COL_PZ ((size_t)10)

/** p_x[1] — this acc row's opened value p(x) (base). Bound to its own public by
 *  C3g (s2); the composition decides where that public comes from (declared
 *  seam, partially closed — see the header). */
#define FOI_COL_PX ((size_t)12)

/** x[1] — this acc row's eval point x_h (base). Bound to the height's register
 *  x_reg[h(row)] (C3b) and used in the quotient denominator (C3d). */
#define FOI_COL_X ((size_t)13)

/** quot[2] — witness for 1/(z-x) (fp2), pinned by (z-x)*quot = 1 (C3d). z==x is
 *  UNSAT (denominator zero), mirroring fri_verifier.c:464-467. */
#define FOI_COL_QUOT ((size_t)14)

/** t[2] — DEGREE-RELIEF column (fp2, FIX Note-1): t = alpha_pow*(p_z - p_x),
 *  pinned ROW-LOCAL on is_acc (C3e), so C3f's ro' is degree 3 not 4. */
#define FOI_COL_T ((size_t)16)

/** Base offset of the variable `x_reg` block. x_reg[i] (i < num_heights) is the
 *  height-i eval-point register, written once at height i's store row (C2c) and
 *  HELD constant on every transition (C2e). See dnac_foi_col_xreg. */
#define FOI_COL_XREG ((size_t)18)

/** Number of FIXED columns (== FOI_COL_XREG). DERIVED as the last fixed block's
 *  end so it cannot drift from the list above. */
#define FOI_NUM_FIXED_COLS (FOI_COL_XREG)

/** fp2 lane count — [c0, c1], c0 first, everywhere. */
#define FOI_EXT_LANES ((size_t)2)

/** Column index of register x_reg[i]. `i` MUST be < num_heights. */
static inline size_t dnac_foi_col_xreg(size_t i) { return FOI_COL_XREG + i; }

/* ── Public-value layout ─────────────────────────────────────────────────── */
#define FOI_PUB_BITS_OFF ((size_t)0)

/* ── Fail-close contract (the fri_air.h:293-320 contract, ported) ──────────── */

/**
 * Fail-close sentinel: returned INSTEAD of a violation count when the config,
 * the public-value length, the row window or the preprocessed terminality is
 * out of contract. Strictly larger than any reachable per-row violation count;
 * `dnac_foi_eval_trace` SATURATES at FOI_VIOL_BAD_CONFIG - 1 rather than
 * overflowing, so a saturated count and the sentinel stay distinguishable.
 *
 * CALLER CONTRACT (identical to FAIR_VIOL_BAD_CONFIG): treat ANY non-zero return
 * as "invalid", and ONLY `== FOI_VIOL_BAD_CONFIG` as "bad config / out of
 * contract".
 */
#define FOI_VIOL_BAD_CONFIG 1000000

typedef enum {
    DNAC_FOI_OK = 0,
    DNAC_FOI_BAD_CONFIG = FOI_VIOL_BAD_CONFIG
} dnac_foi_status_t;

/* ── Public-layout helpers (pure functions of the pinned cfg) ─────────────── */

/** Number of main-trace columns for `cfg` == FOI_NUM_FIXED_COLS + num_heights.
 *  0 for a config the table module rejects (a valid cfg has num_heights >= 1). */
size_t dnac_foi_num_cols(const dnac_p2c_oi_table_cfg_t *cfg);

/** Total accumulation rows == Σ_i n_acc(h_i). 0 on a rejected config. */
size_t dnac_foi_total_acc(const dnac_p2c_oi_table_cfg_t *cfg);

/** First public index of ALPHA (== lgmh). 0 on reject (a valid cfg has
 *  lgmh >= 2, so 0 is unambiguously "reject" here and for every accessor). */
size_t dnac_foi_pub_alpha_off(const dnac_p2c_oi_table_cfg_t *cfg);

/** First public index of the z/p_z region (== lgmh + 2). Acc row `a` binds
 *  z at zpz_off + 4*a and p_z at zpz_off + 4*a + 2. 0 on reject. */
size_t dnac_foi_pub_zpz_off(const dnac_p2c_oi_table_cfg_t *cfg);

/** First public index of the exported-ro region (== zpz_off + 4*total_acc).
 *  Height index `i` (descending) binds ro at ro_off + 2*i. 0 on reject. */
size_t dnac_foi_pub_ro_off(const dnac_p2c_oi_table_cfg_t *cfg);

/** First public index of the p_x region (== ro_off + 2*num_heights). Acc row `a`
 *  binds p_x at px_off + a — ONE base lane, same schedule order as the z / p_z
 *  pairs. APPENDED LAST so every earlier offset is unchanged. 0 on reject. */
size_t dnac_foi_pub_px_off(const dnac_p2c_oi_table_cfg_t *cfg);

/** Required public-value count (== px_off + total_acc). 0 on reject. This
 *  is what the eval entry compares `num_publics` against, EXACTLY. */
size_t dnac_foi_num_publics(const dnac_p2c_oi_table_cfg_t *cfg);

/**
 * @brief Structural self-check of the column layout and public regions.
 *
 * Verifies: no overlap/gap across the fixed column blocks, FOI_NUM_FIXED_COLS
 * consistent with the last block, num_cols(REF)/num_publics(REF) and the region
 * offsets on the pinned reference cfg.
 *
 * @return true iff the layout is internally consistent.
 */
bool dnac_foi_layout_check(void);

/* ── Constraint evaluation ─────────────────────────────────────────────────── */

/**
 * @brief Evaluate every constraint anchored at ONE row.
 *
 * Evaluates the row-local constraints of the (`main_local`, `prep_local`) pair
 * plus the transition constraints into (`main_next`, `prep_next`). Pass
 * `main_next == prep_next == NULL` for the final trace row; a mixed
 * NULL/non-NULL pair fails closed.
 *
 * ⚠ CONTRACT — `eval_row` STANDALONE IS STRICTLY WEAKER (the P2a i3/A2-F4
 * lesson; the same warning fri_air/mmcs_air carry): several transition
 * constraints pin only PART of the next row and rely on that row's OWN row-local
 * block to pin the rest (e.g. C1b pins the next chain g but that row's own
 * booleanity is row-local; C2b squares y' but the store's C2c is row-local). A
 * caller that evaluates rows in isolation and never evaluates `next` as a
 * `local` gets a WEAKER system. Use `dnac_foi_eval_trace`, which evaluates every
 * row both ways; direct `eval_row` use is for NEGATIVE TESTS only.
 *
 * PRECONDITION: every MAIN column is a canonical Goldilocks u64 in [0, p).
 * Preprocessed cells are read as field elements (generator obligation under
 * PIN-1-OI). ⚠ PUBLICS are NOT a precondition: they are checked canonical and
 * any public >= p FAILS CLOSED (OBL-2, the P2b A2-F1 shape).
 *
 * @param main_local   dnac_foi_num_cols(cfg) columns.
 * @param main_next    dnac_foi_num_cols(cfg) columns, or NULL on the last row.
 * @param prep_local   DNAC_P2C_OI_TABLE_COLS preprocessed cells of this row.
 * @param prep_next    DNAC_P2C_OI_TABLE_COLS cells of the next row, or NULL.
 *                     REAL, never zero-filled (the PIN-2 analog).
 * @param is_first_row non-zero on trace row 0 (C1a's row-0 boundary anchor).
 * @param cfg          the pinned FRI open_input cfg; NULL / rejected == fail-close.
 * @param publics      `dnac_foi_num_publics(cfg)` canonical values.
 * @param num_publics  MUST equal `dnac_foi_num_publics(cfg)`.
 * @return number of violated constraints (0 == valid), or FOI_VIOL_BAD_CONFIG.
 */
int dnac_foi_eval_row(const uint64_t *main_local, const uint64_t *main_next,
                      const uint64_t *prep_local, const uint64_t *prep_next,
                      int is_first_row, const dnac_p2c_oi_table_cfg_t *cfg,
                      const uint64_t *publics, size_t num_publics);

/**
 * @brief Evaluate the whole trace: every row local, every adjacent pair.
 *
 * Enforces, beyond the per-row forms, the two SHAPE gates (both fail-close, both
 * evaluated BEFORE any constraint):
 *   - SCHEDULE CONFORMANCE: `n_rows` MUST equal `dnac_p2c_oi_table_rows(cfg)` —
 *     the row count comes from the PINNED schedule, never from a witnessed
 *     length (a shorter walk is a different statement).
 *   - TERMINALITY: the LAST row's preprocessed window MUST be a PADDING row
 *     (is_pad == 1, every other primary type 0), so no transition-anchored form
 *     can be skipped by ending the trace early (the P2a-i3 shipped-HIGH shape).
 *     Fail-close (fri_air's stricter posture, not P2b's one-violation count).
 *
 * @param main_trace n_rows * dnac_foi_num_cols(cfg) canonical columns, row-major.
 * @param prep_table n_rows * DNAC_P2C_OI_TABLE_COLS preprocessed cells, row-major.
 * @param n_rows     number of rows (>= 1).
 * @return total violated constraints (0 == valid), or FOI_VIOL_BAD_CONFIG.
 */
int dnac_foi_eval_trace(const uint64_t *main_trace, const uint64_t *prep_table,
                        size_t n_rows, const dnac_p2c_oi_table_cfg_t *cfg,
                        const uint64_t *publics, size_t num_publics);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_OI_AIR_H */
