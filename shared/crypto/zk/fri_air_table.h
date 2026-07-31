/**
 * @file fri_air_table.h
 * @brief P2c PIN slice — the preprocessed ROW-TYPE table for the FRI fold-walk
 *        AIR: deterministic generator + static validator + the PIN-1-P2c root
 *        constant + its fail-close comparator.
 *
 * Design: dnac/docs/plans/2026-07-29-p2c-fri-in-air-design.md (local-only)
 *   §0.5 "Row schedule" (:229-266), "Field representation" (:292-302),
 *   "Columns" (:304-322), "Constraint forms" C1 (:330-338), §0.6 ledger
 *   (OBL-4c, typed-prefix residual, :204-218), §1 D-1..D-5 (:407-434).
 * ⚠ DOC-CITE BASELINE (FLEET 022 A1-F5): the doc-line numbers above and
 *   throughout this module are against the doc AS OF 2026-07-29
 *   implementation time; later fold-record edits drift them a few lines
 *   while every cited claim stays intact (A1-verified). Resolve by the
 *   stable §/heading anchors (RESUME "CITATION BASELINE" practice).
 * NO AIR is built here. This module builds only what the P2c pin needs, and the
 * accompanying test proves the pin can actually be established
 * (tests/test_fri_air_table.c). The fold-walk constraints land in
 * `fri_air.{c,h}`, a later slice.
 *
 * Precedent this file mirrors 1:1: `mmcs_air_table.{c,h}` (the P2b PIN slice) —
 * same structure, same pin story, same honest-label caveat.
 *
 * ── WHAT THE TABLE IS ──────────────────────────────────────────────────────
 * One row per step of ONE query's FRI fold walk (`fri_verify_query`,
 * fri_verifier.c:520-616), in TYPED-PREFIX order (design §0.5 :231-237, and the
 * §0.6 "Typed-prefix residual" ledger row):
 *
 *     [ n_chain = lgmh - 1 chain rows ]   x0-anchor accumulation, MSB-first
 *     [ n_fold  = R       fold rows   ]   one per FRI phase, LSB-first
 *     [ n_pad  >= 1       padding     ]   terminality
 *     n_rows = next_pow2(n_chain + n_fold + 1)
 *
 * with R = lgmh - log_blowup - log_final_poly_len, the native round count
 * (fri_verifier.c:641-649). Leaf cfg: 12 + 11 + 9 = 32 rows. Recursion cfg:
 * 18 + 17 + 29 = 64 rows (design §0.5 :239).
 *
 * ── WHY THE SELECTORS ARE PREPROCESSED (and what that costs) ───────────────
 * A row-AIR's constraint set is uniform over rows, so every row-index-dependent
 * form needs a carrier. P2b had to put its step one-hot in the MAIN trace and
 * discharge it in-AIR (mmcs_air.h:153-171) because its 3-column table was
 * already pinned and could not be widened without re-pinning. P2c DEFINES its
 * table here, so the whole selector set — row type, step one-hot, the pair
 * gates and the chain's G_j literals — lives in the table (design §0.5
 * :247-262, the FLEET 020 A2-F5 fold).
 *
 * The COST is explicit and is the reason this file exists: preprocessed cells
 * are VERIFIER-AUTHORITATIVE ONLY under the root pin. Nothing on the verify
 * path checks booleanity, exclusivity or one-hotness of a preprocessed cell —
 * `batch_verify.c:722-727` hands the decoded preprocessed window to `air_eval`
 * raw (the P2b round-1 A2-F5 finding, mmcs_air_table.h:26-30). Under
 * PIN-1-P2c the GENERATOR is what guarantees those properties, the STATIC
 * VALIDATOR (`dnac_p2c_table_validate`) is what checks the generator, and the
 * root KAT is what freezes the pair.
 *
 * Consequence committed by the design (§0.5 :251-258): C1's "advance +1 /
 * row-0 anchor / per-position type agreement / prefix order" are TABLE
 * invariants, NOT in-AIR constraints. In-AIR the prep cells appear ONLY as
 * degree-1 gates/selectors of main-trace constraints.
 *
 * ── THE COLUMNS ────────────────────────────────────────────────────────────
 *   is_chain / is_fold / is_pad   row type, exactly one set per row
 *   is_chainpair                  chain row whose SUCCESSOR is a chain row
 *                                 (gates C3's `g' = g + gb'·(G_{j+1} - 1)`)
 *   is_handoff                    the LAST chain row (gates the chain->fold
 *                                 copy AND C4's `f == publics[f_init]`
 *                                 boundary, design §0.5 C4 :368-372)
 *   is_foldpair                   fold row whose SUCCESSOR is a fold row
 *                                 (gates C4's x0 recurrence g' = g_sq·(1-2b'))
 *   is_terminal                   the FIRST padding row (gates C5's
 *                                 `f == final_poly[0]`, design §0.5 :383-387)
 *   is_rollin                     fold row r whose POST-FOLD height is a
 *                                 cfg-pinned roll-in height (divergence D1:
 *                                 an unmatched roll-in is cfg-IMPOSSIBLE
 *                                 because no other row has the slot)
 *   g_pow2                        chain row j carries G_j = g_lgmh^{2^j}; 0 on
 *                                 every other row
 *   pos[DNAC_P2C_MAX_STEPS]       GLOBAL scheduled-step one-hot; all-zero on
 *                                 padding rows
 *
 * Every transition is gated by ONE degree-1 prep cell, never a product of two
 * (design §0.5 :258-262, the A2 note-1 degree fix) — that is why the pair gates
 * are generator-emitted rather than reconstructed in-AIR as
 * `is_chain·is_chain'`.
 *
 * ⚠ `pos` ENCODING — the one spec ambiguity resolved at implementation.
 * The dispatch called `pos_step` a "step index within type"; design §0.5 calls
 * it a ONE-HOT (":247 `pos_step` one-hot: PREPROCESSED here, unlike P2b") and
 * justifies DNAC_P2C_MAX_STEPS = 64 by "lgmh <= 32 ⇒ n_chain+n_fold <= 63"
 * (:262-263) — a GLOBAL bound. Implemented as a GLOBAL one-hot for two
 * grounded reasons: (1) that is the only reading under which MAX_STEPS = 64 is
 * the right number, and (2) a SCALAR index cannot select a public value in an
 * AIR, while C2/C4 require exactly that (`b == publics[bit_offset(row)]`,
 * `beta == publics pair r`) — a scalar would leave the publics unread, which is
 * the FLEET 020 A2-F2 CRITICAL class. The within-type index the dispatch names
 * is RECOVERABLE from the global one at cfg-constant offsets:
 *
 *     chain row: j = k                fold row: r = k - n_chain
 *
 * so the AIR forms the selections as, e.g.
 *     b == Σ_{k<n_chain} pos[k]·publics[bit_off + lgmh-1-k]
 *        + Σ_{k=n_chain}^{n_chain+R-1} pos[k]·publics[bit_off + k-n_chain]
 * with n_chain, R, lgmh cfg constants (design §0.5 C2 :331-338).
 * FLAGGED for the implementation red-verify: if the composition prefers a
 * within-type one-hot (width 32, two blocks) the table WIDENS and the root
 * RE-PINS — a decision that must be taken before the production pin, not after.
 *
 * ── PIN-1-P2c: DNAC_P2C_PREP_ROOT ──────────────────────────────────────────
 * In DNAC the preprocessed commitment is PROVER-SUPPLIED PROOF DATA: the prover
 * commits its own table (batch_prover.c:815-854) and exports the lanes
 * (batch_prover.c:853), and `dnac_batch_verify` checks only its PRESENCE
 * against the declared matrix count (batch_verify.c:149). Nothing in the tree
 * compares that root to a pinned value, so an all-zero selector table would
 * satisfy every gated P2c constraint vacuously. Upstream does not have the hole
 * because its preprocessed commitment lives VERIFIER-SIDE in `CommonData`
 * (`GlobalPreprocessed.commitment`, Plonky3 11cc5849
 * batch-stark/src/common.rs:47-50) — full argument at mmcs_air_table.h:73-100,
 * not repeated here.
 *
 * DERIVATION (exactly the pipeline the SHIPPED prover runs on a preprocessed
 * matrix, batch_prover.c:835-853 with is_zk = 0, so the pin equals the root
 * that appears in a real proof):
 *
 *   table = dnac_p2c_table_generate(REFERENCE CONFIG)   // H x COLS, H = 32
 *   lde   = dnac_prover_coset_lde_bitrev(table, H, COLS,
 *               DNAC_P2C_PREP_LOG_BLOWUP, GOLDILOCKS_GENERATOR, ·)
 *   root  = dnac_p2_mmcs_commit_mixed({lde}, {COLS}, {H << lb}, 1, ·, NULL)
 *   DNAC_P2C_PREP_ROOT = root.lanes
 *
 * salt_elems = 0 is MANDATORY (salted+preprocessed is fail-closed at
 * batch_prover.c:613-617) and the recursion envelope is non-hiding by user lock
 * (design §0.1 :59).
 *
 * ⚠ HONEST LABEL — SAME CAVEAT AS DNAC_P2B_PREP_ROOT (mmcs_air_table.h:119-123):
 * this is a MECHANISM pin against a REFERENCE schedule, NOT the production
 * circuit. It proves the pin can be established and that it binds table
 * CONTENTS. The production constant RE-PINS at the P2b/P2c composition entry,
 * together with the production cfg.
 *
 * ⚠ OBL-4c (design §0.6 ledger; wording corrected by FLEET 022 A1-F2): the
 * root binds the TABLE, never the verifier's separate cfg ARGUMENT. Under
 * collision resistance the root DOES determine lgmh (g_pow2 is
 * lgmh-injective, the A2 note-6 strength), R and the roll-in set (all table
 * content); of the cfg scalars only num_queries escapes the table entirely.
 * The residual is the table<->cfg-struct seam: a root-checked table paired
 * with a MISMATCHED cfg argument leaves cfg-derived loop bounds aimed at the
 * wrong publics. The COMPOSITION entry MUST pin the cfg scalars
 * INDEPENDENTLY of DNAC_P2C_PREP_ROOT.
 *
 * ⚠ PIN-2 (design §0.6 :212, gate G5): the P2c descriptor MUST set
 * `prep_next = 1` — C3's chain transition reads the NEXT row's `g_pow2`.
 * At THIS table's width the flip is rejected on SHAPE, not silently zeroed
 * (O6 verifier B1 correction, 2026-07-29): `prep_next = 0` with
 * `preprocessed_width > 64` hits the `pzeros[64]` capacity guard and returns
 * DNAC_BV_ERR_SHAPE outright (batch_verify.c:696-701); the all-zero-window
 * substitution described for P2b (batch_verify.c:702-707, evidence
 * test_mmcs_air_table T4/N2 at P2b's narrower width) is UNREACHABLE at
 * DNAC_P2C_TABLE_COLS = 73. Fail-closed harder than the P2b path — but the
 * composition entry must still confirm the full prove/verify pipeline
 * handles a 73-wide preprocessed matrix WITH prep_next = 1; this slice has
 * no P2c-side round-trip evidence. This module cannot enforce a descriptor
 * field; enforcement belongs to the future P2c verify entry.
 *
 * Determinism (design §1 D-1/D-2/D-3): every function here is a pure function
 * of the cfg SCALARS. No clock, no RNG, no allocation, no iteration over
 * anything unordered — fixed-bound loops only. G_j comes from
 * `gold_fp_two_adic_generator` (field_goldilocks.c:206-221), a deterministic
 * squaring ladder from a pinned g32, oracle-KAT'd 33/33. No wire field enters
 * the schedule (D-2 / OBL-1).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_FRI_AIR_TABLE_H
#define DNAC_ZK_FRI_AIR_TABLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── fail-close bounds ───────────────────────────────────────────────────── */

/**
 * Upper bound on SCHEDULED (non-padding) rows, and therefore the width of the
 * step one-hot. Design §0.5 :262-263: "MAX_STEPS pinned to 64 (re-pin with
 * production cfg; covers lgmh <= 32 ⇒ n_chain+n_fold <= 63)". The extremal case
 * is lgmh = 32, log_blowup = 0, log_final_poly_len = 0 ⇒ 31 + 32 = 63.
 * Same MECHANISM-pin caveat as MAIR_MAX_STEPS (mmcs_air.h:140-145).
 */
#define DNAC_P2C_MAX_STEPS ((size_t)64)

/**
 * lgmh bound — divergence D3 (design §0.3 :129-141). The native FRI verifier
 * rejects lgmh > 32 (fri_verifier.c:689-691) because that IS
 * GOLDILOCKS_TWO_ADICITY: past it `gold_fp_two_adic_generator` returns 1
 * (field_goldilocks.c:207-209) and the domain degenerates. Kept as its own
 * macro so this header does not drag the FRI-verifier chain in; the test
 * static-asserts it equals GOLDILOCKS_TWO_ADICITY, so the two cannot drift
 * (the DNAC_P2B_MAX_DEPTH practice, mmcs_air_table.h:171-176).
 */
#define DNAC_P2C_MAX_LGMH ((size_t)32)

/** lgmh < 2 leaves no chain anchor (n_chain = lgmh - 1 = 0) — gate G7,
 *  design §0.5 :286-288. */
#define DNAC_P2C_MIN_LGMH ((size_t)2)

/** At most one roll-in per fold phase, and R <= lgmh <= 32. */
#define DNAC_P2C_MAX_ROLLIN ((size_t)32)

/**
 * num_queries bound. The native rejects 0 outright (fri_verifier.c:686-688,
 * DNAC_FRI_ERR_ZERO_QUERIES) — divergence D2 keeps the count EXACT. The upper
 * bound is a fail-close sanity rail only: num_queries does NOT enter the table
 * (one query per trace instance, design §0.5 :224-227). It is carried in the
 * cfg so OBL-P2c-2 (query multiplicity, design §0.6 :218) has a single home.
 */
#define DNAC_P2C_MAX_QUERIES ((size_t)4096)

/** Smallest committable table height (batch_prover.c:639, stark_prover.h:185).
 *  Unreachable at DNAC_P2C_MIN_LGMH (lgmh 2 already needs 1+1+1 = 3 → 4 rows),
 *  kept fail-close. */
#define DNAC_P2C_MIN_ROWS ((size_t)2)

/* ── preprocessed column layout (the binding contract; fri_air.c reads THESE) */

#define DNAC_P2C_COL_IS_CHAIN     0  /**< row type: x0-anchor chain row        */
#define DNAC_P2C_COL_IS_FOLD      1  /**< row type: FRI phase row              */
#define DNAC_P2C_COL_IS_PAD       2  /**< row type: padding                    */
#define DNAC_P2C_COL_IS_CHAINPAIR 3  /**< chain row with a chain successor     */
#define DNAC_P2C_COL_IS_HANDOFF   4  /**< the LAST chain row                   */
#define DNAC_P2C_COL_IS_FOLDPAIR  5  /**< fold row with a fold successor       */
#define DNAC_P2C_COL_IS_TERMINAL  6  /**< the FIRST padding row                */
#define DNAC_P2C_COL_IS_ROLLIN    7  /**< fold row carrying a roll-in slot     */
#define DNAC_P2C_COL_G_POW2       8  /**< chain row j: G_j = g_lgmh^{2^j}      */
#define DNAC_P2C_COL_POS_OFF      9  /**< [9, 9 + MAX_STEPS): step one-hot     */

/** The 0/1 selector columns — every column except `g_pow2`, which is a field
 *  literal. Cols [0,8) plus the one-hot block [9, 9+MAX_STEPS). */
#define DNAC_P2C_NUM_FLAG_COLS ((size_t)8)

/** Total preprocessed width == 73 (8 flags + g_pow2 + 64 one-hot lanes). */
#define DNAC_P2C_TABLE_COLS (DNAC_P2C_COL_POS_OFF + DNAC_P2C_MAX_STEPS)

/** pos[k], k < DNAC_P2C_MAX_STEPS — the GLOBAL scheduled-step one-hot. */
static inline size_t dnac_p2c_col_pos(size_t k)
{
    return (size_t)DNAC_P2C_COL_POS_OFF + k;
}

/* ── status / defect taxonomy ────────────────────────────────────────────── */

typedef enum {
    DNAC_P2C_TABLE_OK = 0,
    DNAC_P2C_TABLE_ERR_PARAM = -1,         /**< NULL / out-of-range config   */
    DNAC_P2C_TABLE_ERR_CAPACITY = -2,      /**< out_cells < rows * COLS      */
    DNAC_P2C_TABLE_ERR_ROOT_MISMATCH = -3, /**< root != DNAC_P2C_PREP_ROOT   */
    DNAC_P2C_TABLE_ERR_SCHEDULE = -4       /**< static validator rejected    */
} dnac_p2c_table_status_t;

/**
 * Which schedule invariant the static validator tripped. Reported through the
 * optional out-parameter of `dnac_p2c_table_validate` so a negative test can
 * isolate ONE check per tamper (the P2b N4/N11 exact-isolation pattern,
 * design §1 test plan :431-434).
 *
 * ⚠ The validator evaluates the checks in the ORDER LISTED and returns the
 * FIRST defect. The order is part of the contract: MULCOUNT deliberately
 * precedes CHAINPAIR so that a single flipped `is_chainpair` cell trips the
 * COUNT identity (design §0.5 C3 :350-352, the A2-F4 anchor) while a MOVED cell
 * — count preserved, placement wrong — trips the placement check. Both are
 * therefore reachable and testable; neither is dead.
 */
typedef enum {
    DNAC_P2C_DEFECT_NONE = 0,
    DNAC_P2C_DEFECT_CANONICAL,      /**< a cell >= p                          */
    DNAC_P2C_DEFECT_BOOLEAN,        /**< a flag/one-hot cell not in {0,1}     */
    DNAC_P2C_DEFECT_TYPE_EXCLUSIVE, /**< not exactly one row type set         */
    DNAC_P2C_DEFECT_PREFIX_ORDER,   /**< chain < fold < pad order broken      */
    DNAC_P2C_DEFECT_TYPE_COUNT,     /**< n_chain / R / n_pad counts wrong     */
    DNAC_P2C_DEFECT_POS_ONEHOT,     /**< step one-hot missing/extra/misplaced */
    DNAC_P2C_DEFECT_MULCOUNT,       /**< 1 + #is_chainpair != lgmh - 1        */
    DNAC_P2C_DEFECT_CHAINPAIR,      /**< is_chainpair placement wrong         */
    DNAC_P2C_DEFECT_HANDOFF,        /**< not exactly one, or not the last     */
    DNAC_P2C_DEFECT_FOLDPAIR,       /**< is_foldpair placement wrong          */
    DNAC_P2C_DEFECT_TERMINAL,       /**< not exactly one, or not the first pad*/
    DNAC_P2C_DEFECT_ROLLIN,         /**< roll-in count or placement wrong     */
    DNAC_P2C_DEFECT_GPOW2           /**< G_j wrong, or non-zero off-chain     */
} dnac_p2c_table_defect_t;

/* ── row record ──────────────────────────────────────────────────────────── */

typedef enum {
    DNAC_P2C_ROW_CHAIN = 0,
    DNAC_P2C_ROW_FOLD = 1,
    DNAC_P2C_ROW_PAD = 2
} dnac_p2c_row_type_t;

/** Decoded form of ONE table row — the single source the cell writer and the
 *  tests both read, so a "row means X" claim cannot drift from the cells. */
typedef struct {
    dnac_p2c_row_type_t type;
    size_t   step;      /**< GLOBAL scheduled-step index == the one-hot
                             position; SIZE_MAX on padding rows            */
    size_t   type_step; /**< within-type index: chain j / fold r — NOT read by
                             the generator/validator (they key on `step`);
                             provided for the 021b AIR + its tests, which bind
                             beta pair r / bit offsets by type (O6 B6 note);
                             SIZE_MAX on padding rows                      */
    int      is_chainpair;
    int      is_handoff;
    int      is_foldpair;
    int      is_terminal;
    int      is_rollin;
    uint64_t g_pow2;    /**< canonical G_j on chain rows, 0 elsewhere      */
} dnac_p2c_row_t;

/* ── config ──────────────────────────────────────────────────────────────── */

/**
 * The PINNED FRI cfg one table instance is generated from. Every field is a
 * consensus/cfg scalar — nothing here may ever come off the wire (design §1
 * D-2 / OBL-1).
 *
 * `rollin_heights` are POST-FOLD log-heights, STRICTLY DESCENDING, exactly the
 * order the native consumes them in (`ro[ro_i].log_height == log_folded_height`
 * with `ro_i` advancing monotonically, fri_verifier.c:600-605). Fold row r has
 * post-fold height `lgmh - 1 - r` (log_current_height starts at lgmh and drops
 * by log_arity = 1 per phase, fri_verifier.c:596), so each roll-in height must
 * lie in [log_blowup + log_final_poly_len, lgmh - 1].
 */
typedef struct {
    size_t        lgmh;               /**< log_global_max_height, 2..32       */
    size_t        log_blowup;         /**< FRI blowup exponent                */
    size_t        log_final_poly_len; /**< MUST be 0 — gate G2                */
    size_t        max_log_arity;      /**< MUST be 1 — gate G1                */
    size_t        num_rollin;         /**< 0 .. R                             */
    const size_t *rollin_heights;     /**< [num_rollin], strictly descending  */
    size_t        num_queries;        /**< 1 .. DNAC_P2C_MAX_QUERIES          */
} dnac_p2c_table_cfg_t;

/* ── PIN-1-P2c reference config + constant ───────────────────────────────── */

/* REFERENCE CONFIG (pinned): lgmh = 13, log_blowup = 2, log_final_poly_len = 0,
 * max_log_arity = 1, rollin_heights = {11, 9}, num_queries = 100.
 *
 * lgmh/lb/lfpl/arity/queries are the SHIPPED leaf-proof values
 * (shielded_fri_params.h:137-141 and :206-207 → 11 + 2 = 13; design §0.1 table
 * :52-60). The roll-in set is a MECHANISM reference, not a production
 * schedule: heights 11 and 9 land on fold rows r = lgmh-1-h = 1 and 3, i.e.
 * TWO NON-ADJACENT roll-in slots, which is what makes the generated table
 * exercise the roll-in placement logic instead of a degenerate prefix.
 * R = 13 - 2 - 0 = 11, n_chain = 12, n_pad = 32 - 23 = 9, n_rows = 32. */
#define DNAC_P2C_REF_LGMH               ((size_t)13)
#define DNAC_P2C_REF_LOG_BLOWUP         ((size_t)2)
#define DNAC_P2C_REF_LOG_FINAL_POLY_LEN ((size_t)0)
#define DNAC_P2C_REF_MAX_LOG_ARITY      ((size_t)1)
#define DNAC_P2C_REF_NUM_ROLLIN         ((size_t)2)
#define DNAC_P2C_REF_ROLLIN_0           ((size_t)11)
#define DNAC_P2C_REF_ROLLIN_1           ((size_t)9)
#define DNAC_P2C_REF_NUM_QUERIES        ((size_t)100)
#define DNAC_P2C_REF_ROWS               ((size_t)32)

/* Coset-LDE blowup the pin is derived at. Mirrors the shipped consensus FRI
 * blowup DNAC_SHIELDED_FRI_LOG_BLOWUP == 2 (shielded_fri_params.h:137) — the
 * recursion envelope. Kept as its OWN macro so this module does not drag the
 * FRI-verifier header chain in; the test static-asserts the two are equal, so
 * they cannot drift. The coset shift is GOLDILOCKS_GENERATOR == 7
 * (field_goldilocks.h:48), the shift batch_prover.c:838-839 passes. */
#define DNAC_P2C_PREP_LOG_BLOWUP ((unsigned)2)

/* PIN-1-P2c — the preprocessed root of the REFERENCE table, 4 Goldilocks lanes.
 *
 * FILLED by the ORCHESTRATOR 2026-07-29 from
 * `build/test_fri_air_table --print-root` (worktree @ ce8d47d7, cc -O2, run
 * output pasted verbatim). MECHANISM pin against the REFERENCE cfg above —
 * production re-pins at the composition entry (OBL-4c: cfg is pinned
 * INDEPENDENTLY of this root). The runtime KAT (test_fri_air_table T3) binds
 * this constant to the generator through the SHIPPED LDE→commit pipeline
 * (batch_prover.c:815-854); `dnac_p2c_prep_root_check` fail-closes on any
 * mismatch. Do NOT hand-edit: re-derive via --print-root
 * (the shielded_domsep.h / test_shielded_domsep.c practice). */
#define DNAC_P2C_PREP_ROOT_LANE0 UINT64_C(0xbc18e697c2e82726)
#define DNAC_P2C_PREP_ROOT_LANE1 UINT64_C(0x249ab7d1a3b19403)
#define DNAC_P2C_PREP_ROOT_LANE2 UINT64_C(0xe4b0ab20bf65f146)
#define DNAC_P2C_PREP_ROOT_LANE3 UINT64_C(0x1be1561acee2167c)

/** Brace-initializer form for a `uint64_t[4]`. */
#define DNAC_P2C_PREP_ROOT                                                    \
    {                                                                         \
        DNAC_P2C_PREP_ROOT_LANE0, DNAC_P2C_PREP_ROOT_LANE1,                   \
        DNAC_P2C_PREP_ROOT_LANE2, DNAC_P2C_PREP_ROOT_LANE3                    \
    }

/** 1 while the pin above is still the unfilled placeholder. */
#define DNAC_P2C_PREP_ROOT_UNFILLED                                           \
    (DNAC_P2C_PREP_ROOT_LANE0 == 0 && DNAC_P2C_PREP_ROOT_LANE1 == 0 &&        \
     DNAC_P2C_PREP_ROOT_LANE2 == 0 && DNAC_P2C_PREP_ROOT_LANE3 == 0)

/* ── API ─────────────────────────────────────────────────────────────────── */

/** The pinned reference config DNAC_P2C_PREP_ROOT is derived from. Never NULL. */
const dnac_p2c_table_cfg_t *dnac_p2c_ref_cfg(void);

/** Chain rows = lgmh - 1 (design §0.5 :234). 0 on a rejected config. */
size_t dnac_p2c_chain_rows(const dnac_p2c_table_cfg_t *cfg);

/** Fold rows R = lgmh - log_blowup - log_final_poly_len, the native round count
 *  (fri_verifier.c:641-649). 0 on a rejected config — and R = 0 is itself a
 *  rejected config (gate G7), so 0 is unambiguously "reject". */
size_t dnac_p2c_fold_rows(const dnac_p2c_table_cfg_t *cfg);

/**
 * Padded row count: next_pow2(chain + fold + 1), minimum DNAC_P2C_MIN_ROWS.
 * The `+1` is the mandatory terminal padding row (design §0.5 :236). Returns 0
 * for a NULL or out-of-range config — callers treat 0 as "reject", there is no
 * valid zero-height table. This is the value the AIR's gate G4 compares
 * `n_rows` against (design §0.5 :280-283).
 */
size_t dnac_p2c_table_rows(const dnac_p2c_table_cfg_t *cfg);

/**
 * Decode row `row` of `cfg`'s schedule. Pure function of (cfg, row); the cell
 * writer below is built on it, so the record and the cells cannot disagree.
 * Fail-close on a bad config or `row >= dnac_p2c_table_rows(cfg)`.
 */
dnac_p2c_table_status_t dnac_p2c_table_row(const dnac_p2c_table_cfg_t *cfg,
                                           size_t row, dnac_p2c_row_t *out);

/**
 * Generate the table into `out` (row-major, rows x DNAC_P2C_TABLE_COLS cells).
 * Fail-close: a bad config or an `out_cells` smaller than the requirement
 * leaves `out` untouched and returns an error.
 */
dnac_p2c_table_status_t dnac_p2c_table_generate(
    const dnac_p2c_table_cfg_t *cfg, uint64_t *out, size_t out_cells);

/**
 * STATIC VALIDATOR — re-checks every schedule invariant the P2c AIR relies on,
 * against the CELLS, structurally (it does not memcmp against the generator,
 * which would be circular). This is the check that stands in for the in-AIR
 * discharge P2b had to do (design §0.5 :251-258): under PIN-1-P2c nothing on
 * the verify path re-checks a preprocessed cell, so this validator plus the
 * root pin are the whole guarantee.
 *
 * Checks, in evaluation order (see dnac_p2c_table_defect_t):
 *   1 canonicality      every cell < p
 *   2 booleanity        every flag / one-hot cell in {0,1}
 *   3 type exclusivity  exactly one of is_chain/is_fold/is_pad per row
 *   4 prefix order      chain rows, then fold rows, then padding — no interleave
 *   5 type counts       lgmh-1 chain, R fold, n_rows-chain-R >= 1 padding
 *   6 step one-hot      row k < chain+R has pos[k] = 1 and nothing else;
 *                       padding rows all-zero
 *   7 mul count         1 + #is_chainpair == lgmh - 1  (C3's multiplication
 *                       count: the row-0 multiply-from-1 plus one per pair)
 *   8 chainpair         is_chainpair[r] iff r and r+1 are both chain rows
 *   9 handoff           exactly one is_handoff, on the LAST chain row
 *  10 foldpair          is_foldpair[r] iff r and r+1 are both fold rows
 *  11 terminal          exactly one is_terminal, on the FIRST padding row
 *  12 roll-in           is_rollin only on fold rows, count == cfg.num_rollin,
 *                       and placed at fold row lgmh-1-h for each cfg height h
 *  13 g_pow2            chain row j == g_lgmh^{2^j}; zero on every other row
 *
 * @param out_defect optional; set to the FIRST defect found (or
 *                   DNAC_P2C_DEFECT_NONE on success). May be NULL.
 * @return DNAC_P2C_TABLE_OK, DNAC_P2C_TABLE_ERR_PARAM (NULL / bad cfg / wrong
 *         `rows`) or DNAC_P2C_TABLE_ERR_SCHEDULE.
 */
dnac_p2c_table_status_t dnac_p2c_table_validate(
    const dnac_p2c_table_cfg_t *cfg, const uint64_t *cells, size_t rows,
    dnac_p2c_table_defect_t *out_defect);

/**
 * PIN-1-P2c comparator, fail-close. Returns DNAC_P2C_TABLE_OK iff `lanes`
 * equals DNAC_P2C_PREP_ROOT lane for lane; DNAC_P2C_TABLE_ERR_ROOT_MISMATCH on
 * any difference and DNAC_P2C_TABLE_ERR_PARAM on NULL. Mirrors
 * `dnac_p2b_prep_root_check` (mmcs_air_table.h:249-256): the pin lives
 * CALLER-side exactly like the DNAC_SHIELDED_* constants — `dnac_batch_verify`'s
 * signature does not change. This is the call the future P2c verify entry makes
 * on the DECODED preprocessed commitment before it trusts a single gated
 * constraint.
 *
 * ⚠ While DNAC_P2C_PREP_ROOT_UNFILLED, this ALWAYS returns
 * DNAC_P2C_TABLE_ERR_ROOT_MISMATCH — including for an all-zero `lanes`. A
 * placeholder pin that accepted an all-zero root would be strictly worse than
 * no pin: an adversary supplying a zero commitment would pass.
 */
dnac_p2c_table_status_t dnac_p2c_prep_root_check(const uint64_t lanes[4]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_FRI_AIR_TABLE_H */
