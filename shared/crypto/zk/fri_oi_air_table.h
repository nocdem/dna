/**
 * @file fri_oi_air_table.h
 * @brief P2c open_input PIN slice — the preprocessed ROW-TYPE table for the FRI
 *        reduced-opening accumulation AIR (`fri_oi_air`): deterministic
 *        generator + static validator + the PIN-1-OI root constant + its
 *        fail-close comparator.
 *
 * Build spec: dnac/docs/plans/2026-07-29-p2c-oi-BUILDABLE-v3.md (local-only) —
 *   "Row schedule" (:16-28), "Preprocessed columns" (:30-34), "Main columns"
 *   (:36-48), constraint families C1..C6 (:50-108), eval-entry gates (:110-115),
 *   the PIN-1-OI prerequisite (:117-121), the mandatory A2 second-witness
 *   negatives (:123-136), the deferred composition seams (:138-142).
 *   The BUILDABLE spec supersedes §0.5/§6 of the design doc (red-teamed
 *   NOT-GREEN twice); every FLEET-024 §7 fix is folded into it.
 *
 * ⚠ DOC-CITE BASELINE (the fri_air_table.h FLEET 022 A1-F5 practice): the
 *   spec-line numbers here are against the BUILDABLE spec AS OF 2026-07-29
 *   implementation time; later edits drift them a few lines while every cited
 *   claim stays intact. Resolve by the stable §/heading anchors.
 *
 * NO AIR is built here. This module builds only what the P2c open_input PIN
 * needs, and the accompanying test proves the pin can actually be established
 * (tests/test_fri_oi_air_table.c). The reduced-opening accumulation constraints
 * land in `fri_oi_air.{c,h}`, a later slice; the mixed-height MMCS injection is
 * a SEPARATE module (`mmcs_air` slice 2), OUT of scope here (spec :7-9).
 *
 * Precedent this file mirrors 1:1: `fri_air_table.{c,h}` (the P2c fold-walk PIN
 * slice) — same structure, same pin story, same honest-label caveat. The ONE
 * structural difference is the SCHEDULE: the fold-walk table was a flat
 * typed-prefix (chain | fold | pad); the open_input table is a chain with
 * INTERLEAVED capture blocks, then DESCENDING accumulation groups, then pad.
 *
 * ── WHAT THE TABLE IS ──────────────────────────────────────────────────────
 * One row per step of ONE query's reduced-opening accumulation walk, in PREFIX
 * order (BUILDABLE spec "Row schedule" :16-28):
 *
 *   1. n_chain = lgmh CHAIN rows (NOTE lgmh, not lgmh-1 — the OI chain reads
 *      ALL lgmh bits; the fold-walk read lgmh-1). MSB-first bit accumulation,
 *      chain row j carries the prep literal G_j = g_lgmh^{2^j}. Right after the
 *      chain row that completes height h's prefix (chain row h-1, i.e. h bits
 *      consumed), for every h in H, an INTERLEAVED CAPTURE BLOCK:
 *          [ seed row ][ sq_1 .. sq_{cum_h} ][ store row ],  cum_h = lgmh - h.
 *      The chain state g is copied UNCHANGED across the whole block (spec C2d);
 *      the squaring lives in the scratch column y, so the chain resumes at the
 *      prefix value. GATE: h_max == lgmh (spec :21, FIX F7).
 *   2. ACCUMULATION GROUPS, DESCENDING h_1 > .. > h_k. Per group:
 *          [ acc rows: one per (batch,matrix,point,column), NATIVE batch-major
 *            order batch->matrix->point->column ] then [ ONE closeout row ]
 *      — the closeout is the group's LAST row (spec :24-27).
 *   3. PADDING (is_pad); the LAST row is padding (terminality gate, spec :28).
 *
 *   n_rows = next_pow2(n_sched + 1), n_sched = n_chain + Σcaptures + Σgroups.
 *
 * ── WHY THE SELECTORS ARE PREPROCESSED (and what that costs) ───────────────
 * A row-AIR's constraint set is uniform over rows, so every row-index-dependent
 * form needs a carrier. This table DEFINES its selector set (row type, the
 * capture sub-types, the group boundaries, the height one-hot, the step one-hot
 * and the chain's G_j literals), exactly as fri_air_table did (fri_air_table.h
 * :38-59). The COST is the same and is the reason this file exists:
 * preprocessed cells are VERIFIER-AUTHORITATIVE ONLY under the root pin.
 * Nothing on the verify path checks booleanity, exclusivity or one-hotness of a
 * preprocessed cell — `batch_verify.c:722-727` hands the decoded window to
 * `air_eval` raw. Under PIN-1-OI the GENERATOR guarantees those properties, the
 * STATIC VALIDATOR (`dnac_p2c_oi_table_validate`) checks the generator, and the
 * root KAT freezes the pair.
 *
 * ── THE COLUMNS ────────────────────────────────────────────────────────────
 *   is_chain / is_capture_h / is_acc / is_closeout / is_pad
 *                                 PRIMARY row type — exactly one set per row
 *   is_sqpair                     capture row that squares y (y' = y*y)
 *   is_store                      capture STORE row (x_reg[h] = 7*y)
 *                                 (the SEED row is is_capture_h & !sqpair &
 *                                  !store — spec C2a)
 *   is_group_start                the FIRST acc row of a group (spec C3a,
 *                                 ROW-LOCAL alpha_pow==1, ro==0)
 *   is_final_closeout             the closeout of the h==lb group (spec C4b,
 *                                 ro==0 zero rule; sub-flag of is_closeout).
 *                                 CONDITIONAL: set on NO row when H contains no
 *                                 height at lb — the mirror of the native's own
 *                                 condition (fri_verifier.c:482-487), which
 *                                 checks the lb ro only if a reduced opening at
 *                                 log_blowup exists. Real inner proofs have
 *                                 none (FLEET 029).
 *   g_pow2                        chain row j: G_j = g_lgmh^{2^j}; 0 elsewhere
 *   h_sel[DNAC_P2C_OI_MAX_HEIGHTS] per-height one-hot: which descending-H index
 *                                 this row belongs to. Set on every capture-
 *                                 block row (routes x_reg[h] store), every acc
 *                                 row and every closeout row (routes
 *                                 x == x_reg[h] and ro_slot_h). All-zero on
 *                                 chain and padding rows.
 *   pos[DNAC_P2C_OI_MAX_STEPS]    GLOBAL scheduled-step one-hot; all-zero on
 *                                 padding rows. A SCALAR cannot select a public
 *                                 (the FLEET-020 A2-F2 lesson) — the AIR forms
 *                                 z_slot(row)/pz_slot/ro_slot as cfg-constant
 *                                 functions of this one-hot (spec C3c/C4a),
 *                                 identical posture to fri_air_table.h:86-106.
 *
 * ⚠ `h_sel` INDEXES the DESCENDING array H. In the prefix, capture blocks
 * appear in ASCENDING height order (height h's block sits at chain row h-1) but
 * carry their descending-array index, so height 2 (index k-1) can precede
 * height 4 (index 0). The index, not the prefix position, is what routes the
 * register and the publics slot.
 *
 * ── PER-HEIGHT BATCH SHAPE (sizing the acc groups) ─────────────────────────
 * A group's acc-row count is a fixed descriptor the generator walks
 * deterministically: for height h_i,
 *     n_acc(h_i) = num_batches * num_matrices * num_points * num_columns
 * emitted in NATIVE batch-major order (batch->matrix->point->column,
 * fri_verifier.c:207/400/436/469 per spec :26). The finer tuple order is a
 * GENERATOR property frozen by the sequential `pos` one-hot and the root pin —
 * a preprocessed cell cannot be reordered without changing the root. The static
 * validator pins the group BOUNDARIES (count, contiguity, is_group_start on the
 * first acc row, the closeout as the group's last row); see the batch-major
 * note on `dnac_p2c_oi_table_validate`.
 *
 * ── PIN-1-OI: DNAC_P2C_OI_PREP_ROOT ────────────────────────────────────────
 * In DNAC the preprocessed commitment is PROVER-SUPPLIED PROOF DATA: the prover
 * commits its own table (batch_prover.c:815-854) and `dnac_batch_verify` checks
 * only its PRESENCE (batch_verify.c:149). Nothing in the tree compares that root
 * to a pinned value, so an all-zero selector table would satisfy every gated
 * open_input constraint vacuously. Upstream does not have the hole because its
 * preprocessed commitment lives VERIFIER-SIDE in `CommonData`
 * (GlobalPreprocessed.commitment) — the full argument is at
 * mmcs_air_table.h:73-100 and fri_air_table.h:108-118, not repeated.
 *
 * DERIVATION (exactly the SHIPPED prover pipeline on a preprocessed matrix,
 * batch_prover.c:835-853 with is_zk = 0, so the pin equals the root that
 * appears in a real proof):
 *
 *   table = dnac_p2c_oi_table_generate(REFERENCE CONFIG)   // rows x COLS
 *   lde   = dnac_prover_coset_lde_bitrev(table, rows, COLS,
 *               DNAC_P2C_OI_PREP_LOG_BLOWUP, GOLDILOCKS_GENERATOR, ·)
 *   root  = dnac_p2_mmcs_commit_mixed({lde}, {COLS}, {rows << lb}, 1, ·, NULL)
 *   DNAC_P2C_OI_PREP_ROOT = root.lanes
 *
 * salt_elems = 0 is MANDATORY (salted+preprocessed is fail-closed at
 * batch_prover.c:613-617) and the recursion envelope is non-hiding by user lock.
 *
 * ⚠ HONEST LABEL — SAME CAVEAT AS DNAC_P2C_PREP_ROOT (fri_air_table.h:134-138):
 * this is a MECHANISM pin against a REFERENCE schedule, NOT the production
 * circuit. It proves the pin can be established and that it binds table
 * CONTENTS. The production constant RE-PINS at the P2b/P2c composition entry,
 * together with the production cfg (and the production `pos`/`h_sel` widths).
 *
 * ⚠ OBL-4c-OI (the fri_air_table.h:140-148 OBL-4c, ported): the root binds the
 * TABLE, never the verifier's separate cfg ARGUMENT. Under collision resistance
 * the root DOES determine the schedule content (g_pow2 is lgmh-injective, the
 * height one-hot pins H, the group counts pin the batch shape) — but a
 * root-checked table paired with a MISMATCHED cfg argument leaves cfg-derived
 * loop bounds aimed at the wrong publics. The COMPOSITION entry MUST pin the cfg
 * scalars INDEPENDENTLY of DNAC_P2C_OI_PREP_ROOT. ⚠ TWO cfg scalars escape the
 * table entirely (FLEET 029 red-verify F8; the earlier "only num_queries"
 * sentence was stale): num_queries, AND — for the lb-less class this fleet
 * admits — log_blowup itself: with no height at lb, `is_final_closeout` is 0
 * everywhere (its ONLY table imprint, fri_oi_air_table.c:295-296), so two cfgs
 * differing only in a below-min(H) log_blowup share one root while C4b/C5
 * semantics depend on lb. The independent cfg pin above is therefore
 * load-bearing for lb, not belt-and-suspenders.
 *
 * ── PIN-1-OI PREREQUISITE (BUILDABLE spec :117-121, the fri_air.h:49-56 block,
 * verbatim posture) ──
 * EVERY guarantee the fri_oi_air constraints provide is conditional on the
 * preprocessed root being compared to DNAC_P2C_OI_PREP_ROOT. Without it the
 * selector cells are prover-supplied proof data and every gated constraint is
 * satisfiable with an all-zero table (the second-witness class the spec's N-F*
 * negatives assume closed). The comparator `dnac_p2c_oi_prep_root_check` is
 * caller-side (S2'-d style); nothing in this slice's verify path is wired to it
 * yet — the future P2c verify/composition entry makes that call. This module
 * cannot enforce a descriptor field; enforcement belongs to that entry.
 *
 * Determinism: every function here is a pure function of the cfg SCALARS. No
 * clock, no RNG, no allocation, no iteration over anything unordered —
 * fixed-bound loops only. G_j comes from `gold_fp_two_adic_generator`
 * (field_goldilocks.c:206-221), a deterministic squaring ladder, oracle-KAT'd
 * 33/33. No wire field enters the schedule.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_OI_AIR_TABLE_H
#define DNAC_ZK_FRI_OI_AIR_TABLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── fail-close bounds ───────────────────────────────────────────────────── */

/**
 * Upper bound on SCHEDULED (non-padding) rows, and therefore the width of the
 * step one-hot. Unlike the fold-walk table there is NO clean lgmh-only bound —
 * the acc-row count scales with the batch shape (heights * batches * matrices *
 * points * columns). 64 comfortably covers the REFERENCE cfg (n_sched = 14) and
 * the test's larger shapes; the cfg gate rejects n_sched > MAX_STEPS fail-close.
 * PRODUCTION re-pins MAX_STEPS with the real batch shape (identical posture to
 * DNAC_P2C_MAX_STEPS, fri_air_table.h:187-194).
 */
#define DNAC_P2C_OI_MAX_STEPS ((size_t)64)

/**
 * Height one-hot width. Heights H subset [lb, lgmh] with lgmh <= 32, so at most
 * 31 distinct heights; 32 is the fail-close rail. Test static-asserts it >= the
 * realizable maximum.
 */
#define DNAC_P2C_OI_MAX_HEIGHTS ((size_t)32)

/**
 * lgmh bound — the native FRI verifier rejects lgmh > 32
 * (fri_verifier.c:689-691) because that IS GOLDILOCKS_TWO_ADICITY: past it
 * `gold_fp_two_adic_generator` returns 1 (field_goldilocks.c:207-209) and the
 * domain degenerates. Kept as its own macro; the test static-asserts it equals
 * GOLDILOCKS_TWO_ADICITY so the two cannot drift.
 */
#define DNAC_P2C_OI_MAX_LGMH ((size_t)32)

/** lgmh < 2 leaves a degenerate chain (a single bit); kept fail-close, matches
 *  DNAC_P2C_MIN_LGMH. */
#define DNAC_P2C_OI_MIN_LGMH ((size_t)2)

/**
 * num_queries bound. The native rejects 0 (fri_verifier.c:686-688) — the count
 * is kept EXACT. The upper bound is a fail-close sanity rail only: num_queries
 * does NOT enter the table (one query per trace instance). It is the ONE cfg
 * scalar that escapes the root (OBL-4c-OI), carried so query multiplicity has a
 * single home.
 */
#define DNAC_P2C_OI_MAX_QUERIES ((size_t)4096)

/** Smallest committable table height (batch_prover.c:639). Unreachable at the
 *  bounds above; kept fail-close. */
#define DNAC_P2C_OI_MIN_ROWS ((size_t)2)

/* ── preprocessed column layout (the binding contract; fri_oi_air.c reads THESE)
 *
 * PRIMARY type set = { IS_CHAIN, IS_CAPTURE, IS_ACC, IS_CLOSEOUT, IS_PAD };
 * exactly one is set per row. IS_SQPAIR / IS_STORE sub-select capture rows;
 * IS_GROUP_START sub-selects acc rows; IS_FINAL_CLOSEOUT sub-selects the lb
 * closeout WHEN a height at lb exists (else no row carries it).
 * ─────────────────────────────────────────────────────────────────────────── */

#define DNAC_P2C_OI_COL_IS_CHAIN          0  /**< primary: chain row           */
#define DNAC_P2C_OI_COL_IS_CAPTURE        1  /**< primary: any capture-block row*/
#define DNAC_P2C_OI_COL_IS_ACC            2  /**< primary: accumulation row     */
#define DNAC_P2C_OI_COL_IS_CLOSEOUT       3  /**< primary: group closeout row   */
#define DNAC_P2C_OI_COL_IS_PAD            4  /**< primary: padding row          */
#define DNAC_P2C_OI_COL_IS_SQPAIR         5  /**< capture: y' = y*y squaring    */
#define DNAC_P2C_OI_COL_IS_STORE          6  /**< capture: x_reg[h] = 7*y store */
#define DNAC_P2C_OI_COL_IS_GROUP_START    7  /**< acc: FIRST acc row of a group */
#define DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT 8  /**< closeout: the h==lb group, if
                                                  H has one at all            */
#define DNAC_P2C_OI_COL_G_POW2            9  /**< chain row j: G_j = g_lgmh^{2^j}*/
#define DNAC_P2C_OI_COL_HSEL_OFF          10 /**< [10, 10+MAX_HEIGHTS): h one-hot*/

/** The 0/1 selector flag columns — every column except g_pow2, the h_sel block
 *  and the pos block. Cols [0, 9). */
#define DNAC_P2C_OI_NUM_FLAG_COLS ((size_t)9)

/** Offset of the GLOBAL step one-hot: right after the h_sel block. */
#define DNAC_P2C_OI_COL_POS_OFF \
    (DNAC_P2C_OI_COL_HSEL_OFF + DNAC_P2C_OI_MAX_HEIGHTS) /* 42 */

/** Total preprocessed width == 106 (9 flags + g_pow2 + 32 h_sel + 64 pos). */
#define DNAC_P2C_OI_TABLE_COLS (DNAC_P2C_OI_COL_POS_OFF + DNAC_P2C_OI_MAX_STEPS)

/** h_sel[i], i < DNAC_P2C_OI_MAX_HEIGHTS — the per-height (descending-H index)
 *  one-hot. */
static inline size_t dnac_p2c_oi_col_hsel(size_t i)
{
    return (size_t)DNAC_P2C_OI_COL_HSEL_OFF + i;
}

/** pos[k], k < DNAC_P2C_OI_MAX_STEPS — the GLOBAL scheduled-step one-hot. */
static inline size_t dnac_p2c_oi_col_pos(size_t k)
{
    return (size_t)DNAC_P2C_OI_COL_POS_OFF + k;
}

/* ── status / defect taxonomy ────────────────────────────────────────────── */

typedef enum {
    DNAC_P2C_OI_TABLE_OK = 0,
    DNAC_P2C_OI_TABLE_ERR_PARAM = -1,         /**< NULL / out-of-range config  */
    DNAC_P2C_OI_TABLE_ERR_CAPACITY = -2,      /**< out_cells < rows * COLS     */
    DNAC_P2C_OI_TABLE_ERR_ROOT_MISMATCH = -3, /**< root != DNAC_P2C_OI_PREP_ROOT*/
    DNAC_P2C_OI_TABLE_ERR_SCHEDULE = -4       /**< static validator rejected   */
} dnac_p2c_oi_table_status_t;

/**
 * Which schedule invariant the static validator tripped. Reported through the
 * optional out-parameter of `dnac_p2c_oi_table_validate` so a negative test can
 * isolate ONE check per tamper (the fri_air_table N3 pattern).
 *
 * ⚠ The validator evaluates the checks in the ORDER LISTED and returns the
 * FIRST defect. The order is part of the contract (BOOLEAN precedes
 * TYPE_EXCLUSIVE so a `2` trips booleanity not exclusivity; PRIMARY_SCHEDULE
 * precedes the sub-flag checks so a retyped row trips schedule not a sub-flag).
 */
typedef enum {
    DNAC_P2C_OI_DEFECT_NONE = 0,
    DNAC_P2C_OI_DEFECT_CANONICAL,       /**< a cell >= p                       */
    DNAC_P2C_OI_DEFECT_BOOLEAN,         /**< a flag/one-hot cell not in {0,1}  */
    DNAC_P2C_OI_DEFECT_TYPE_EXCLUSIVE,  /**< not exactly one primary type set  */
    DNAC_P2C_OI_DEFECT_PRIMARY_SCHEDULE,/**< a row's primary type != schedule  */
    DNAC_P2C_OI_DEFECT_CAPTURE,         /**< seed/sq/store sub-flags wrong     */
    DNAC_P2C_OI_DEFECT_GROUP_START,     /**< is_group_start not on 1st acc row */
    DNAC_P2C_OI_DEFECT_FINAL_CLOSEOUT,  /**< is_final_closeout != lb closeout  */
    DNAC_P2C_OI_DEFECT_HSEL,            /**< height one-hot missing/extra/wrong */
    DNAC_P2C_OI_DEFECT_POS_ONEHOT,      /**< step one-hot missing/extra/wrong  */
    DNAC_P2C_OI_DEFECT_GPOW2            /**< G_j wrong, or non-zero off-chain  */
} dnac_p2c_oi_table_defect_t;

/* ── row record ──────────────────────────────────────────────────────────── */

typedef enum {
    DNAC_P2C_OI_ROW_CHAIN = 0,
    DNAC_P2C_OI_ROW_CAPTURE = 1,
    DNAC_P2C_OI_ROW_ACC = 2,
    DNAC_P2C_OI_ROW_CLOSEOUT = 3,
    DNAC_P2C_OI_ROW_PAD = 4
} dnac_p2c_oi_row_type_t;

/** Decoded form of ONE table row — the single source the cell writer and the
 *  tests both read, so a "row means X" claim cannot drift from the cells. */
typedef struct {
    dnac_p2c_oi_row_type_t type;
    size_t   step;      /**< GLOBAL scheduled-step index == the one-hot
                             position; SIZE_MAX on padding rows              */
    size_t   h_index;   /**< descending-H index this row routes; SIZE_MAX on
                             chain and padding rows                          */
    int      is_sqpair; /**< capture squaring row                           */
    int      is_store;  /**< capture store row (seed = capture & !sq & !st)  */
    int      is_group_start;    /**< acc: first acc row of the group         */
    int      is_final_closeout; /**< closeout: the h==lb group's closeout;
                                     always 0 when H has no height at lb    */
    uint64_t g_pow2;    /**< canonical G_j on chain rows, 0 elsewhere        */
} dnac_p2c_oi_row_t;

/* ── config ──────────────────────────────────────────────────────────────── */

/**
 * The per-height batch-shape descriptor. All counts must be >= 1. `log_height`
 * is the matrix log-height h; the group for this height carries
 * num_batches*num_matrices*num_points*num_columns acc rows in batch-major order.
 */
typedef struct {
    size_t log_height;   /**< h in [log_blowup, lgmh]                          */
    size_t num_batches;  /**< batches contributing a matrix at this height     */
    size_t num_matrices; /**< matrices per batch at this height (uniform)      */
    size_t num_points;   /**< opening points per matrix (uniform)             */
    size_t num_columns;  /**< claimed evals per point (uniform)               */
} dnac_p2c_oi_height_desc_t;

/**
 * The PINNED FRI open_input cfg one table instance is generated from. Every
 * field is a consensus/cfg scalar — nothing here may ever come off the wire.
 *
 * The module ports ONLY the arity-2, log_final_poly_len == 0 open_input shape
 * (spec :11-14); those two are module invariants, not cfg fields. `heights`
 * are STRICTLY DESCENDING by `log_height`; heights[0].log_height MUST == lgmh
 * (h_max, FIX F7). Every height lies in [log_blowup, lgmh].
 *
 * ⚠ A height AT log_blowup is OPTIONAL (FLEET 029) — there is NO h_min rule.
 * The C4b zero rule mirrors the native's CONDITIONAL lb check
 * (fri_verifier.c:482-487) and is carried by `is_final_closeout`, which the
 * generator sets only on a group whose log_height == log_blowup; on a cfg
 * without one, NO row carries it and C4b is vacuous. Real inner proofs are that
 * shape (a matrix at log_blowup would be a degree-0 polynomial). Strict descent
 * already makes an lb group, when present, the LAST one — no position rule.
 */
typedef struct {
    size_t                           lgmh;        /**< log_global_max_height    */
    size_t                           log_blowup;  /**< lb; the FLOOR of H, which
                                                       need not be ATTAINED     */
    size_t                           num_heights; /**< k, 1..MAX_HEIGHTS        */
    const dnac_p2c_oi_height_desc_t *heights;     /**< [k], descending          */
    size_t                           num_queries; /**< 1..MAX_QUERIES           */
} dnac_p2c_oi_table_cfg_t;

/* ── PIN-1-OI reference config + constant ────────────────────────────────── */

/* REFERENCE CONFIG (pinned): lgmh = 4, log_blowup = 2, H = {4, 2}, each height
 * {1 batch, 1 matrix, 1 point, 1 column} => 1 acc row per group,
 * num_queries = 100. This is a small HAND-TRACEABLE mechanism reference (spec
 * :138-142 declares the production shape a composition-entry re-pin), chosen so
 * the two heights produce two NON-DEGENERATE capture blocks — height 4
 * (cum = 0, block = seed+store) and height 2 (cum = 2, block =
 * seed+sq+sq+store) — and two accumulation groups, exercising the whole
 * schedule (chain, interleaved captures of DIFFERENT lengths, descending
 * groups, a non-final and a final closeout) at 16 rows.
 *
 * Layout (row : role):
 *    0 : chain j=0  g_pow2=G_0=g_4     8 : capture h=4 SEED   (h_sel[0])
 *    1 : chain j=1  g_pow2=G_1=g_3     9 : capture h=4 STORE  (h_sel[0])
 *    2 : capture h=2 SEED  (h_sel[1]) 10 : acc  group0 h=4 START (h_sel[0])
 *    3 : capture h=2 SQ    (h_sel[1]) 11 : closeout group0 h=4  (h_sel[0]) [!final]
 *    4 : capture h=2 SQ    (h_sel[1]) 12 : acc  group1 h=2 START (h_sel[1])
 *    5 : capture h=2 STORE (h_sel[1]) 13 : closeout group1 h=2  (h_sel[1]) [FINAL]
 *    6 : chain j=2  g_pow2=G_2=g_2    14 : pad
 *    7 : chain j=3  g_pow2=G_3=g_1    15 : pad  (LAST row = pad, terminality)
 * n_chain = 4, captures = 2+4 = 6, groups = 2+2 = 4, n_sched = 14, n_rows = 16. */
#define DNAC_P2C_OI_REF_LGMH        ((size_t)4)
#define DNAC_P2C_OI_REF_LOG_BLOWUP  ((size_t)2)
#define DNAC_P2C_OI_REF_NUM_HEIGHTS ((size_t)2)
#define DNAC_P2C_OI_REF_NUM_QUERIES ((size_t)100)
#define DNAC_P2C_OI_REF_ROWS        ((size_t)16)
#define DNAC_P2C_OI_REF_SCHED       ((size_t)14)

/* Coset-LDE blowup the pin is derived at. Mirrors the shipped consensus FRI
 * blowup DNAC_SHIELDED_FRI_LOG_BLOWUP == 2 (the recursion envelope). Its OWN
 * macro so this module does not drag the FRI-verifier header chain in; the test
 * static-asserts equality so they cannot drift. The coset shift is
 * GOLDILOCKS_GENERATOR == 7 (field_goldilocks.h:48). */
#define DNAC_P2C_OI_PREP_LOG_BLOWUP ((unsigned)2)

/* PIN-1-OI — the preprocessed root of the REFERENCE table, 4 Goldilocks lanes.
 *
 * FILLED by the ORCHESTRATOR 2026-07-29 from `--print-root` (worktree
 * @ ce8d47d7, cc -O2, output pasted verbatim). MECHANISM pin against the
 * REFERENCE cfg above (lgmh=4, H={4,2}, lb=2) — production re-pins at the
 * composition entry (OBL-4c-OI: cfg pinned INDEPENDENTLY of this root). The
 * runtime KAT (T3) binds this constant to the generator through the SHIPPED
 * LDE→commit pipeline; `dnac_p2c_oi_prep_root_check` fail-closes on mismatch.
 * Do NOT hand-edit — re-derive via --print-root. */
#define DNAC_P2C_OI_PREP_ROOT_LANE0 UINT64_C(0x4bc948ef32b400c0)
#define DNAC_P2C_OI_PREP_ROOT_LANE1 UINT64_C(0xf736ee0aeca1140e)
#define DNAC_P2C_OI_PREP_ROOT_LANE2 UINT64_C(0x496968789dfe55be)
#define DNAC_P2C_OI_PREP_ROOT_LANE3 UINT64_C(0xb4e0665ff6700e66)

/** Brace-initializer form for a `uint64_t[4]`. */
#define DNAC_P2C_OI_PREP_ROOT                                                 \
    {                                                                         \
        DNAC_P2C_OI_PREP_ROOT_LANE0, DNAC_P2C_OI_PREP_ROOT_LANE1,             \
        DNAC_P2C_OI_PREP_ROOT_LANE2, DNAC_P2C_OI_PREP_ROOT_LANE3              \
    }

/** 1 while the pin above is still the unfilled placeholder. */
#define DNAC_P2C_OI_PREP_ROOT_UNFILLED                                        \
    (DNAC_P2C_OI_PREP_ROOT_LANE0 == 0 && DNAC_P2C_OI_PREP_ROOT_LANE1 == 0 &&  \
     DNAC_P2C_OI_PREP_ROOT_LANE2 == 0 && DNAC_P2C_OI_PREP_ROOT_LANE3 == 0)

/* ── API ─────────────────────────────────────────────────────────────────── */

/** The pinned reference config DNAC_P2C_OI_PREP_ROOT is derived from. Never
 *  NULL. */
const dnac_p2c_oi_table_cfg_t *dnac_p2c_oi_ref_cfg(void);

/** Chain rows = lgmh (spec :18). 0 on a rejected config. */
size_t dnac_p2c_oi_chain_rows(const dnac_p2c_oi_table_cfg_t *cfg);

/** Total capture rows = Σ_{h in H} (lgmh - h + 2) (seed + cum_h squarings +
 *  store). 0 on a rejected config. */
size_t dnac_p2c_oi_capture_rows(const dnac_p2c_oi_table_cfg_t *cfg);

/** Acc-row count for one height descriptor (product of the four counts). 0 if
 *  the descriptor has a zero count. */
size_t dnac_p2c_oi_acc_count(const dnac_p2c_oi_height_desc_t *h);

/** Total accumulation rows = Σ_i (n_acc(h_i) + 1 closeout). 0 on reject. */
size_t dnac_p2c_oi_group_rows(const dnac_p2c_oi_table_cfg_t *cfg);

/** Scheduled (non-padding) rows = chain + capture + group. 0 on reject. */
size_t dnac_p2c_oi_sched_rows(const dnac_p2c_oi_table_cfg_t *cfg);

/**
 * Padded row count: next_pow2(sched + 1), minimum DNAC_P2C_OI_MIN_ROWS. The +1
 * is the mandatory terminal padding row (spec :28). Returns 0 for a NULL or
 * out-of-range config — callers treat 0 as "reject".
 */
size_t dnac_p2c_oi_table_rows(const dnac_p2c_oi_table_cfg_t *cfg);

/**
 * Decode row `row` of `cfg`'s schedule. Pure function of (cfg, row); the cell
 * writer is built on it, so the record and the cells cannot disagree.
 * Fail-close on a bad config or `row >= dnac_p2c_oi_table_rows(cfg)`.
 */
dnac_p2c_oi_table_status_t dnac_p2c_oi_table_row(
    const dnac_p2c_oi_table_cfg_t *cfg, size_t row, dnac_p2c_oi_row_t *out);

/**
 * Generate the table into `out` (row-major, rows x DNAC_P2C_OI_TABLE_COLS
 * cells). Fail-close: a bad config or an `out_cells` smaller than the
 * requirement leaves `out` untouched and returns an error.
 */
dnac_p2c_oi_table_status_t dnac_p2c_oi_table_generate(
    const dnac_p2c_oi_table_cfg_t *cfg, uint64_t *out, size_t out_cells);

/**
 * STATIC VALIDATOR — re-checks every schedule invariant the open_input AIR
 * relies on, against the CELLS, structurally and INDEPENDENTLY of the generator
 * (it re-derives the expected schedule from cfg semantics; it does NOT memcmp
 * against the generator, which would be circular). Under PIN-1-OI nothing on the
 * verify path re-checks a preprocessed cell, so this validator plus the root pin
 * are the whole guarantee.
 *
 * Checks, in evaluation order (see dnac_p2c_oi_table_defect_t):
 *   1 canonicality      every cell < p
 *   2 booleanity        every flag / one-hot cell in {0,1}
 *   3 type exclusivity  exactly one of the 5 primary types per row
 *   4 primary schedule  each row's primary type matches the reconstructed
 *                       schedule (chain | interleaved captures | descending
 *                       groups | pad) — subsumes all row-type COUNTS
 *   5 capture sub-flags seed/sq_{cum_h}/store per height, cum_h = lgmh - h
 *   6 group start       is_group_start iff the FIRST acc row of a group
 *   7 final closeout    is_final_closeout iff the h==lb group's closeout — so
 *                       NO row may carry it when H has no height at lb
 *   8 height one-hot    h_sel routes the right descending-H index on capture /
 *                       acc / closeout rows; all-zero on chain / pad
 *   9 step one-hot      scheduled row k carries pos[k]=1 and nothing else;
 *                       padding rows all-zero
 *  10 g_pow2            chain row j == g_lgmh^{2^j}; 0 on every other row
 *
 * ⚠ BATCH-MAJOR ORDER is realized by the sequential `pos` one-hot (check 9) and
 * the generator's batch->matrix->point->column emission loop. There is no
 * per-batch column, so the validator pins group BOUNDARIES (counts via check 4,
 * is_group_start via 6, closeout via 4) and the step ordering via 9; the finer
 * tuple order inside a group is frozen by the root pin (a reorder changes the
 * root). This is the honest limit of a cell-level structural validator and is
 * documented as a declared property, not an enforced in-table constraint.
 *
 * @param out_defect optional; set to the FIRST defect found (or
 *                   DNAC_P2C_OI_DEFECT_NONE on success). May be NULL.
 * @return DNAC_P2C_OI_TABLE_OK, DNAC_P2C_OI_TABLE_ERR_PARAM (NULL / bad cfg /
 *         wrong `rows`) or DNAC_P2C_OI_TABLE_ERR_SCHEDULE.
 */
dnac_p2c_oi_table_status_t dnac_p2c_oi_table_validate(
    const dnac_p2c_oi_table_cfg_t *cfg, const uint64_t *cells, size_t rows,
    dnac_p2c_oi_table_defect_t *out_defect);

/**
 * PIN-1-OI comparator, fail-close. Returns DNAC_P2C_OI_TABLE_OK iff `lanes`
 * equals DNAC_P2C_OI_PREP_ROOT lane for lane; DNAC_P2C_OI_TABLE_ERR_ROOT_MISMATCH
 * on any difference and DNAC_P2C_OI_TABLE_ERR_PARAM on NULL. Mirrors
 * `dnac_p2c_prep_root_check` (fri_air_table.h:476-491): the pin lives
 * CALLER-side; `dnac_batch_verify`'s signature does not change. This is the call
 * the future P2c verify entry makes on the DECODED preprocessed commitment
 * before it trusts a single gated constraint.
 *
 * ⚠ While DNAC_P2C_OI_PREP_ROOT_UNFILLED, this ALWAYS returns
 * DNAC_P2C_OI_TABLE_ERR_ROOT_MISMATCH — including for an all-zero `lanes`. A
 * placeholder pin that accepted an all-zero root would be strictly worse than
 * no pin.
 */
dnac_p2c_oi_table_status_t dnac_p2c_oi_prep_root_check(const uint64_t lanes[4]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_OI_AIR_TABLE_H */
