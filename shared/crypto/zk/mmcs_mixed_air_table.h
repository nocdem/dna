/**
 * @file mmcs_mixed_air_table.h
 * @brief P2b slice 2 PIN — the preprocessed ROW-TYPE table for the MIXED-HEIGHT
 *        MMCS-verify AIR (`mmcs_mixed_air`): deterministic generator + static
 *        validator + the PIN-1-MMIX root constant + its fail-close comparator.
 *
 * Build spec: dnac/docs/plans/2026-07-29-p2b-slice2-mixed-mmcs-BUILDABLE.md
 *   (local-only) — "Native structure being ported" (:13-38), "Row schedule"
 *   (:51-67), "Publics layout" (:69-75), the constraint families (:77-96),
 *   the mandatory negatives (:98-109), the deferred composition seams (:111-116).
 *
 * NO AIR is built here. This module builds only what the P2b slice-2 PIN needs,
 * and the accompanying test proves the pin can actually be established
 * (tests/test_mmcs_mixed_air_table.c). The mixed-height MMCS-verify constraints
 * land in `mmcs_mixed_air.{c,h}`, a later slice.
 *
 * Precedents this file mirrors 1:1:
 *   - `mmcs_air_table.{c,h}` — the SAME-HEIGHT P2b table (slice 1). Same
 *     PaddingFreeSponge leaf-row-count derivation, same PIN story, same
 *     mechanism-pin caveat. The structural difference is the SCHEDULE: slice 1
 *     was a flat typed prefix (leaf | compress | final); slice 2 is a
 *     tallest-group leaf, then per level a compress with an OPTIONAL interleaved
 *     inject block (leaf-hash of the injecting group + one inject-compress),
 *     then final, then pad.
 *   - `fri_oi_air_table.{c,h}` — the most recent table. Same static-validator
 *     discipline, the same PIN-1 prerequisite block, the same
 *     unfilled-placeholder-rejects-all contract, the same `--print-root` fill
 *     loop and the same per-schedule-step / per-height one-hot columns.
 *
 * ── THE NATIVE ORACLE (poseidon2_mmcs.c dnac_p2_mmcs_verify_mixed :454-529) ──
 * One mixed-height binary MMCS opening:
 *   - LEAF (:490-497): digest = H(concat of the TALLEST group's opened rows),
 *     the matrices whose height == max_h, concatenated in MATRIX order, hashed
 *     by PaddingFreeSponge (`dnac_p2_mmcs_hash_iter`, :46-72).
 *   - WALK (:501-525), cur = max_h, per level l in 0..depth-1:
 *       1. compress with the sibling in BIT order (:505-508);
 *       2. cur >>= 1 (:511);
 *       3. INJECTION (:513-524): if ANY matrix has height == cur, then
 *          rows_digest = H(concat of that group's opened rows) and
 *          digest = C(running_digest, rows_digest) — running FIRST, injected
 *          SECOND (:522, the load-bearing combine order).
 *   - ROOT (:528): memcmp(digest, root).
 * `depth == log2(max_h)` is the WrongHeight/BAD_DEPTH pin (:484). The commit
 * side (`dnac_p2_mmcs_commit_mixed` :312-420) builds the identical schedule:
 * layer l = 1..depth injects iff max_h>>l is a present height != max_h (:366-391).
 *
 * ── ROW SCHEDULE (preprocessed table, PIN-1-MMIX root) ──────────────────────
 * Prefix order, per ONE mixed-MMCS-verify:
 *
 *   [ leaf-hash rows for the tallest group (group 0) ]
 *   then per level l = 0..depth-1:
 *     [ compress row ]                         (bit-ordered C(digest, sibling))
 *     [ inject block, IFF a group's height == cur_after_l == max_h>>(l+1) ]:
 *        [ inject-leaf rows for that group ] [ inject-compress row ]
 *   [ final root-equality row ]
 *   [ padding, LAST row is_pad ]
 *
 * n_sched = leaf(g0) + depth + Σ_{inject groups g}(leaf(g) + 1) + 1(final).
 * n_rows  = next_pow2(n_sched + 1), minimum DNAC_P2C_MMIX_MIN_ROWS. The +1 is the
 * mandatory terminal padding row (the eval-entry terminality gate demands the
 * LAST row is_pad; the fri_oi_air_table.c:205 posture). Every power-of-two height
 * present in [1, max_h] is either the tallest group (the leaf, never injected) or
 * exactly ONE cur_after_l — so each non-tallest group injects exactly once.
 *
 * ── GROUP ORDER — DETERMINISTIC (descending distinct height) ────────────────
 * Matrices are grouped by height; heights need NOT be distinct. The group INDEX
 * is the position in the DESCENDING list of distinct present heights: group 0 ==
 * max_h (the leaf group), group 1 == the next lower present power of two, and so
 * on. The list is derived by enumerating powers of two from max_h down to 1 and
 * keeping the present ones — a pure, reproducible function of the cfg, no sort,
 * no unordered iteration (root CLAUDE.md determinism). Within a group the concat
 * order is MATRIX index order, matching the native `p2m_group_row_concat`
 * (poseidon2_mmcs.c:296-310).
 *
 * ── LEAF-ROW COUNT: DERIVED FROM THE SHIPPED SPONGE ─────────────────────────
 * The leaf hash of a group is `dnac_p2_mmcs_hash_iter` over the concatenated
 * opened rows of the group's matrices. Its PaddingFreeSponge<Perm,8,4,4>
 * schedule (poseidon2_mmcs.c:41-72; Plonky3 11cc5849 symmetric/src/sponge.rs:
 * 172-204) permutes ceil(n / RATE) times for n > 0, with NO trailing permutation
 * when n is an exact multiple of RATE. Hence the number of (inject-)leaf rows for
 * a group is
 *     concat % RATE == 0  →  concat / RATE
 *     otherwise           →  concat / RATE + 1        (concat > 0 always)
 *
 * SALT — THE cfg PARAMETERISATION (spec :35-38). The FRI input path is is_zk:
 * the leaf preimage per matrix is `[row ‖ salt]` with `salt_elems` appended base
 * lanes. The table therefore counts a group's absorb length as
 *     concat = Σ_{m in group} (widths[m] + salt_elems).
 * ⚠ MODELLING NOTE, not a native contradiction: the native mmcs functions are
 * salt-AGNOSTIC — `p2m_group_row_concat` copies exactly `widths[m]` per matrix
 * (poseidon2_mmcs.c:304), because on the is_zk path the salt columns are
 * PHYSICALLY part of the committed matrix width. This module keeps `widths[]` as
 * the SEMANTIC (data-only) width and adds `salt_elems` per matrix, so
 * Σ(widths[m] + salt_elems) equals the native's Σ(physical_width[m]). The two
 * parameterisations give the SAME absorb length, hence the same leaf-row count;
 * the split is only so the composition entry can pin the semantic width and the
 * salt count INDEPENDENTLY. Reconciled with the production commit at composition.
 *
 * ── WHY THE SELECTORS ARE PREPROCESSED (and what that costs) ────────────────
 * A row-AIR's constraint set is uniform over rows, so every row-index-dependent
 * form needs a carrier. This table DEFINES its selector set (the row type, the
 * per-level has_inject flag, the level one-hot, the group one-hot and the global
 * step one-hot). Nothing on the verify path checks booleanity, exclusivity or
 * one-hotness of a preprocessed cell — `batch_verify.c:722-727` hands the decoded
 * window to `air_eval` raw (the mmcs_air_table.h:26-31 A2-F5 argument). Under
 * PIN-1-MMIX the GENERATOR guarantees those properties, the STATIC VALIDATOR
 * (`dnac_p2c_mmix_table_validate`) checks the generator, and the root KAT freezes
 * the pair.
 *
 * ── THE COLUMNS ────────────────────────────────────────────────────────────
 *   is_leaf / is_compress / is_inject_leaf / is_inject_compress / is_final /
 *   is_pad                       PRIMARY row type — exactly one set per row
 *   has_inject                   compress row whose level triggers an inject
 *                                block (0 on every other row); the "per-level
 *                                has_inject" the spec :62 names
 *   lvl[DNAC_P2C_MMIX_MAX_LEVELS] Merkle-level one-hot; set on every compress row
 *                                AND every inject-block row (routes the direction
 *                                bit / sibling public at that level, and the
 *                                per-matrix reduced-index suffix offset = l+1).
 *                                All-zero on the tallest leaf / final / pad.
 *   gsel[DNAC_P2C_MMIX_MAX_GROUPS] group one-hot (DESCENDING distinct-height
 *                                index); set on the tallest leaf (group 0), every
 *                                inject-leaf and every inject-compress row (routes
 *                                the group's opened-rows publics — the
 *                                inject-group routing the spec :62 names).
 *                                All-zero on compress / final / pad.
 *   pos[DNAC_P2C_MMIX_MAX_STEPS] GLOBAL scheduled-step one-hot; all-zero on pad.
 *                                Pins the whole prefix ORDER — a preprocessed
 *                                cell cannot be reordered without changing the
 *                                root. A SCALAR cannot select a public (the
 *                                FLEET-020 A2-F2 lesson); the AIR forms its
 *                                cfg-constant selectors OF this one-hot, the
 *                                fri_oi_air_table.h:88-90 posture.
 *
 * The (inject-)leaf rows carry NO extra sponge sub-selector — mmcs_air_table's
 * leaf rows are likewise a bare is_leaf per permutation (mmcs_air_table.c:104).
 *
 * ── PIN-1-MMIX: DNAC_P2C_MMIX_PREP_ROOT ────────────────────────────────────
 * In DNAC the preprocessed commitment is PROVER-SUPPLIED PROOF DATA: the prover
 * commits its own table (batch_prover.c:787-826) and `dnac_batch_verify` checks
 * only its PRESENCE (batch_verify.c:149). Nothing in the tree compares that root
 * to a pinned value, so an all-zero selector table would satisfy every gated
 * constraint vacuously. Upstream does not have the hole because its preprocessed
 * commitment lives VERIFIER-SIDE in `CommonData` (GlobalPreprocessed.commitment)
 * — the full argument is at mmcs_air_table.h:73-100, not repeated.
 *
 * DERIVATION (exactly the SHIPPED prover pipeline on a preprocessed matrix,
 * batch_prover.c:807-825 with is_zk = 0, so the pin equals the root that appears
 * in a real proof):
 *
 *   table = dnac_p2c_mmix_table_generate(REFERENCE CONFIG)   // rows x COLS
 *   lde   = dnac_prover_coset_lde_bitrev(table, rows, COLS,
 *               DNAC_P2C_MMIX_PREP_LOG_BLOWUP, GOLDILOCKS_GENERATOR, ·)
 *   root  = dnac_p2_mmcs_commit_mixed({lde}, {COLS}, {rows << lb}, 1, ·, NULL)
 *   DNAC_P2C_MMIX_PREP_ROOT = root.lanes
 *
 * salt_elems = 0 is MANDATORY at commit (salted+preprocessed is fail-closed at
 * batch_prover.c:585-589); the cfg `salt_elems` above is the LEAF-ABSORB count,
 * NOT the commit's hiding-salt count — different roles, the recursion envelope is
 * non-hiding by user lock.
 *
 * ⚠ HONEST LABEL — SAME CAVEAT AS DNAC_P2B_PREP_ROOT (mmcs_air_table.h:119-123):
 * this is a MECHANISM pin against a REFERENCE schedule, NOT the production
 * circuit. It proves the pin can be established and that it binds table CONTENTS.
 * The production constant RE-PINS at the P2b/P2c composition entry, with the
 * production cfg (num_matrices / widths / heights / depth / salt of the FRI-query
 * input-MMCS openings verified in-circuit) and the production pos/lvl/gsel widths.
 *
 * ⚠ OBL-4-MMIX (the mmcs_air.h OBL-4 / fri_oi_air_table.h:139-146 OBL-4c-OI,
 * ported): the root binds the TABLE, never the verifier's separate cfg ARGUMENT.
 * A root-checked table paired with a MISMATCHED cfg leaves cfg-derived loop
 * bounds aimed at the wrong publics; and PIN-1 binds the SCHEDULE, not the cfg
 * scalars. The COMPOSITION entry MUST pin the cfg (widths / heights / depth /
 * salt_elems) INDEPENDENTLY of DNAC_P2C_MMIX_PREP_ROOT.
 *
 * ── PIN-1-MMIX PREREQUISITE (the fri_oi_air_table.h:148-157 block, ported) ──
 * EVERY guarantee the mmcs_mixed_air constraints will provide is conditional on
 * the preprocessed root being compared to DNAC_P2C_MMIX_PREP_ROOT. Without it the
 * selector cells are prover-supplied proof data and every gated constraint is
 * satisfiable with an all-zero table. The comparator `dnac_p2c_mmix_prep_root_check`
 * is caller-side (S2'-d style); nothing in this slice's verify path is wired to it
 * yet — the future composition entry makes that call. This module cannot enforce a
 * descriptor field; enforcement belongs to that entry.
 *
 * Determinism: every function here is a pure function of the cfg SCALARS — fixed-
 * bound loops only, no allocation, no clock, no RNG, no iteration over anything
 * unordered. No wire field enters the schedule. Two provers building the table
 * from this definition produce the same root.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_MMCS_MIXED_AIR_TABLE_H
#define DNAC_ZK_MMCS_MIXED_AIR_TABLE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── fail-close bounds ───────────────────────────────────────────────────── */

/** Leaf-hash sponge rate (PaddingFreeSponge<Perm,8,4,4>, poseidon2_mmcs.c:21). */
#define DNAC_P2C_MMIX_SPONGE_RATE ((size_t)4)

/** Smallest committable table height (batch_prover.c:611, stark_prover.h:185).
 *  Unreachable at the bounds below; kept fail-close. */
#define DNAC_P2C_MMIX_MIN_ROWS ((size_t)2)

/**
 * Merkle-depth bound. `depth` is a Merkle height bounded by the field's
 * two-adicity exactly as the FRI verifier bounds its global max height
 * (fri_verifier.c:689, GOLDILOCKS_TWO_ADICITY == 32); past that the two-adic
 * generator degenerates and no such tree can be committed. Kept as its own macro;
 * the test static-asserts it equals GOLDILOCKS_TWO_ADICITY so they cannot drift.
 */
#define DNAC_P2C_MMIX_MAX_DEPTH ((size_t)32)

/** Matrix-count bound (mirrors DNAC_P2B_MAX_MATRICES). */
#define DNAC_P2C_MMIX_MAX_MATRICES ((size_t)64)

/** Level one-hot width. Levels run 0..depth-1, depth <= 32, so at most 32. */
#define DNAC_P2C_MMIX_MAX_LEVELS ((size_t)32)

/** Group one-hot width. Distinct heights are powers of two in [1, max_h] with
 *  max_h == 2^depth and depth <= 32, so at most 33 distinct groups. The test
 *  static-asserts it >= DNAC_P2C_MMIX_MAX_DEPTH + 1. */
#define DNAC_P2C_MMIX_MAX_GROUPS ((size_t)33)

/**
 * Upper bound on SCHEDULED (non-padding) rows, and therefore the width of the
 * step one-hot. There is no clean depth-only bound — the (inject-)leaf row counts
 * scale with the group widths — so the cfg gate rejects n_sched > MAX_STEPS
 * fail-close with a running cap. 64 covers the REFERENCE cfg (n_sched = 7) and
 * the test's wider shapes; PRODUCTION re-pins with the real query-opening shape.
 */
#define DNAC_P2C_MMIX_MAX_STEPS ((size_t)64)

/** Per-matrix leaf-absorb salt bound (fail-close sanity rail). */
#define DNAC_P2C_MMIX_MAX_SALT ((size_t)64)

/** Total SEMANTIC width bound across all matrices (fail-close, overflow rail). */
#define DNAC_P2C_MMIX_MAX_TOTAL_WIDTH ((size_t)1u << 20)

/* ── preprocessed column layout (the binding contract; mmcs_mixed_air.c reads
 * THESE) ──
 *
 * PRIMARY type set = { IS_LEAF, IS_COMPRESS, IS_INJECT_LEAF, IS_INJECT_COMPRESS,
 * IS_FINAL, IS_PAD }; exactly one is set per row. HAS_INJECT sub-selects a
 * compress row. Every cell is 0/1 — there is NO field literal in this table
 * (unlike fri_oi_air_table's g_pow2), so booleanity over all cells is the
 * complete cell-value check. ─────────────────────────────────────────────── */

#define DNAC_P2C_MMIX_COL_IS_LEAF            0 /**< primary: tallest-group leaf   */
#define DNAC_P2C_MMIX_COL_IS_COMPRESS        1 /**< primary: Merkle compress row  */
#define DNAC_P2C_MMIX_COL_IS_INJECT_LEAF     2 /**< primary: injecting-group leaf */
#define DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS 3 /**< primary: inject-compress row  */
#define DNAC_P2C_MMIX_COL_IS_FINAL           4 /**< primary: root-equality row    */
#define DNAC_P2C_MMIX_COL_IS_PAD             5 /**< primary: padding row          */
#define DNAC_P2C_MMIX_COL_HAS_INJECT         6 /**< compress row of an injecting
                                                *   level (0 elsewhere)          */
#define DNAC_P2C_MMIX_COL_LVL_OFF            7 /**< [7, 7+MAX_LEVELS): level 1hot */

/** The 0/1 flag columns before the one-hot blocks — cols [0, 7). */
#define DNAC_P2C_MMIX_NUM_FLAG_COLS ((size_t)7)

/** Offset of the group one-hot: right after the level one-hot. */
#define DNAC_P2C_MMIX_COL_GSEL_OFF \
    (DNAC_P2C_MMIX_COL_LVL_OFF + DNAC_P2C_MMIX_MAX_LEVELS) /* 39 */

/** Offset of the GLOBAL step one-hot: right after the group one-hot. */
#define DNAC_P2C_MMIX_COL_POS_OFF \
    (DNAC_P2C_MMIX_COL_GSEL_OFF + DNAC_P2C_MMIX_MAX_GROUPS) /* 72 */

/** Total preprocessed width == 136 (7 flags + 32 lvl + 33 gsel + 64 pos). */
#define DNAC_P2C_MMIX_TABLE_COLS \
    (DNAC_P2C_MMIX_COL_POS_OFF + DNAC_P2C_MMIX_MAX_STEPS)

/** lvl[l], l < DNAC_P2C_MMIX_MAX_LEVELS — the Merkle-level one-hot. */
static inline size_t dnac_p2c_mmix_col_lvl(size_t l)
{
    return (size_t)DNAC_P2C_MMIX_COL_LVL_OFF + l;
}

/** gsel[g], g < DNAC_P2C_MMIX_MAX_GROUPS — the descending-group one-hot. */
static inline size_t dnac_p2c_mmix_col_gsel(size_t g)
{
    return (size_t)DNAC_P2C_MMIX_COL_GSEL_OFF + g;
}

/** pos[k], k < DNAC_P2C_MMIX_MAX_STEPS — the GLOBAL scheduled-step one-hot. */
static inline size_t dnac_p2c_mmix_col_pos(size_t k)
{
    return (size_t)DNAC_P2C_MMIX_COL_POS_OFF + k;
}

/* ── status / defect taxonomy ────────────────────────────────────────────── */

typedef enum {
    DNAC_P2C_MMIX_TABLE_OK = 0,
    DNAC_P2C_MMIX_TABLE_ERR_PARAM = -1,         /**< NULL / out-of-range config  */
    DNAC_P2C_MMIX_TABLE_ERR_CAPACITY = -2,      /**< out_cells < rows * COLS     */
    DNAC_P2C_MMIX_TABLE_ERR_ROOT_MISMATCH = -3, /**< root != PREP_ROOT           */
    DNAC_P2C_MMIX_TABLE_ERR_SCHEDULE = -4       /**< static validator rejected   */
} dnac_p2c_mmix_table_status_t;

/**
 * Which schedule invariant the static validator tripped. Reported through the
 * optional out-parameter so a negative test can isolate ONE check per tamper.
 *
 * ⚠ The validator evaluates the checks in the ORDER LISTED and returns the FIRST
 * defect. The order is part of the contract (BOOLEAN precedes TYPE_EXCLUSIVE so a
 * `2` trips booleanity not exclusivity; PRIMARY_SCHEDULE precedes the sub-flag /
 * one-hot checks so a retyped row trips schedule not a sub-flag). There is NO
 * separate canonicality defect: with no field literal, booleanity (cell in {0,1})
 * already rejects every non-canonical raw value.
 */
typedef enum {
    DNAC_P2C_MMIX_DEFECT_NONE = 0,
    DNAC_P2C_MMIX_DEFECT_BOOLEAN,          /**< a cell not in {0,1}              */
    DNAC_P2C_MMIX_DEFECT_TYPE_EXCLUSIVE,   /**< not exactly one primary type set */
    DNAC_P2C_MMIX_DEFECT_PRIMARY_SCHEDULE, /**< a row's primary type != schedule */
    DNAC_P2C_MMIX_DEFECT_HAS_INJECT,       /**< has_inject != schedule           */
    DNAC_P2C_MMIX_DEFECT_LVL_ONEHOT,       /**< level one-hot missing/extra/wrong*/
    DNAC_P2C_MMIX_DEFECT_GSEL_ONEHOT,      /**< group one-hot missing/extra/wrong*/
    DNAC_P2C_MMIX_DEFECT_POS_ONEHOT        /**< step one-hot missing/extra/wrong */
} dnac_p2c_mmix_table_defect_t;

/* ── row record ──────────────────────────────────────────────────────────── */

typedef enum {
    DNAC_P2C_MMIX_ROW_LEAF = 0,
    DNAC_P2C_MMIX_ROW_COMPRESS = 1,
    DNAC_P2C_MMIX_ROW_INJECT_LEAF = 2,
    DNAC_P2C_MMIX_ROW_INJECT_COMPRESS = 3,
    DNAC_P2C_MMIX_ROW_FINAL = 4,
    DNAC_P2C_MMIX_ROW_PAD = 5
} dnac_p2c_mmix_row_type_t;

/** Decoded form of ONE table row — the single source the cell writer and the
 *  tests both read, so a "row means X" claim cannot drift from the cells. */
typedef struct {
    dnac_p2c_mmix_row_type_t type;
    size_t step;       /**< GLOBAL scheduled-step index == the pos one-hot
                            position; SIZE_MAX on padding rows                 */
    size_t level;      /**< Merkle level on compress / inject-block rows;
                            SIZE_MAX on leaf / final / pad                     */
    size_t group;      /**< descending-group index on leaf / inject rows;
                            SIZE_MAX on compress / final / pad                 */
    int    has_inject; /**< compress row whose level triggers an inject block  */
} dnac_p2c_mmix_row_t;

/* ── config ──────────────────────────────────────────────────────────────── */

/**
 * One mixed-height MMCS opening's shape. `widths` are SEMANTIC (data-only)
 * widths; `salt_elems` is the per-matrix leaf-absorb salt appended per matrix.
 * `depth` MUST equal log2(max height) — the WrongHeight/BAD_DEPTH pin
 * (poseidon2_mmcs.c:484). Heights need NOT be distinct; they are grouped.
 */
typedef struct {
    size_t        num_matrices; /**< 1 .. DNAC_P2C_MMIX_MAX_MATRICES           */
    const size_t *widths;       /**< [num_matrices], each >= 1 (semantic)      */
    const size_t *heights;      /**< [num_matrices], each a power of two <= max */
    size_t        depth;        /**< == log2(max height), 1 .. MAX_DEPTH       */
    size_t        salt_elems;   /**< per-matrix leaf salt, 0 .. MAX_SALT       */
} dnac_p2c_mmix_table_cfg_t;

/* ── PIN-1-MMIX reference config + constant ──────────────────────────────── */

/* REFERENCE CONFIG (pinned): num_matrices = 2, heights = {8, 2}, widths =
 * {1, 1}, depth = 3, salt_elems = 2. max_h = 8 (=> depth = 3), ONE injection at
 * the level where cur == 2. A small HAND-TRACEABLE mixed shape (spec :99-100
 * declares the production shape a composition-entry re-pin), chosen so both a
 * tallest group AND one lower injecting group are exercised at 8 rows.
 *
 * Layout (row : role):
 *    0 : leaf   group0 (h=8)            [concat 1+2=3 => ceil(3/4)=1 leaf row]
 *    1 : compress level 0   (cur=4, no group => has_inject 0)
 *    2 : compress level 1   (cur=2, group1  => has_inject 1)
 *    3 : inject-leaf group1 (h=2)       [concat 1+2=3 => 1 inject-leaf row]
 *    4 : inject-compress group1 (h=2)
 *    5 : compress level 2   (cur=1, no group => has_inject 0)
 *    6 : final
 *    7 : pad   (LAST row = pad, terminality)
 * n_sched = 1 + 3 + (1+1) + 1 = 7, n_rows = next_pow2(8) = 8. */
#define DNAC_P2C_MMIX_REF_NUM_MATRICES ((size_t)2)
#define DNAC_P2C_MMIX_REF_HEIGHT_0     ((size_t)8)
#define DNAC_P2C_MMIX_REF_HEIGHT_1     ((size_t)2)
#define DNAC_P2C_MMIX_REF_WIDTH_0      ((size_t)1)
#define DNAC_P2C_MMIX_REF_WIDTH_1      ((size_t)1)
#define DNAC_P2C_MMIX_REF_DEPTH        ((size_t)3)
#define DNAC_P2C_MMIX_REF_SALT_ELEMS   ((size_t)2)
#define DNAC_P2C_MMIX_REF_SCHED        ((size_t)7)
#define DNAC_P2C_MMIX_REF_ROWS         ((size_t)8)

/* Coset-LDE blowup the pin is derived at. Mirrors the shipped consensus FRI
 * blowup DNAC_SHIELDED_FRI_LOG_BLOWUP == 2 (the recursion envelope). Its OWN
 * macro so this module does not drag the FRI-verifier header chain in; the test
 * static-asserts equality so they cannot drift. The coset shift is
 * GOLDILOCKS_GENERATOR == 7 (field_goldilocks.h:48). */
#define DNAC_P2C_MMIX_PREP_LOG_BLOWUP ((unsigned)2)

/* PIN-1-MMIX — the preprocessed root of the REFERENCE table, 4 Goldilocks lanes.
 *
 * FILLED by the ORCHESTRATOR 2026-07-29 from `--print-root` (worktree @
 * 5685f46d, cc -O2, output pasted verbatim). MECHANISM pin against the
 * REFERENCE cfg above (heights {8,2}, widths {1,1}, salt 2, depth 3) —
 * production re-pins at the composition entry (OBL-4-MMIX: cfg pinned
 * INDEPENDENTLY of this root). The runtime KAT (T3) binds this constant to the
 * generator through the SHIPPED LDE→commit pipeline;
 * `dnac_p2c_mmix_prep_root_check` fail-closes on mismatch. Do NOT hand-edit —
 * re-derive via --print-root. */
#define DNAC_P2C_MMIX_PREP_ROOT_LANE0 UINT64_C(0xd0380af189cf4999)
#define DNAC_P2C_MMIX_PREP_ROOT_LANE1 UINT64_C(0xfe79194f82938956)
#define DNAC_P2C_MMIX_PREP_ROOT_LANE2 UINT64_C(0x53616f3d705958cb)
#define DNAC_P2C_MMIX_PREP_ROOT_LANE3 UINT64_C(0x622631697e3f65f6)

/** Brace-initializer form for a `uint64_t[4]`. */
#define DNAC_P2C_MMIX_PREP_ROOT                                               \
    {                                                                         \
        DNAC_P2C_MMIX_PREP_ROOT_LANE0, DNAC_P2C_MMIX_PREP_ROOT_LANE1,         \
        DNAC_P2C_MMIX_PREP_ROOT_LANE2, DNAC_P2C_MMIX_PREP_ROOT_LANE3          \
    }

/** 1 while the pin above is still the unfilled placeholder. */
#define DNAC_P2C_MMIX_PREP_ROOT_UNFILLED                                      \
    (DNAC_P2C_MMIX_PREP_ROOT_LANE0 == 0 &&                                    \
     DNAC_P2C_MMIX_PREP_ROOT_LANE1 == 0 &&                                    \
     DNAC_P2C_MMIX_PREP_ROOT_LANE2 == 0 && DNAC_P2C_MMIX_PREP_ROOT_LANE3 == 0)

/* ── API ─────────────────────────────────────────────────────────────────── */

/** The pinned reference config DNAC_P2C_MMIX_PREP_ROOT is derived from. Never
 *  NULL. */
const dnac_p2c_mmix_table_cfg_t *dnac_p2c_mmix_ref_cfg(void);

/** Number of distinct present heights (== number of groups). 0 on reject. */
size_t dnac_p2c_mmix_num_groups(const dnac_p2c_mmix_table_cfg_t *cfg);

/** Height of descending-group index `g` (group 0 == max_h). 0 on reject / out of
 *  range. */
size_t dnac_p2c_mmix_group_height(const dnac_p2c_mmix_table_cfg_t *cfg, size_t g);

/** (Inject-)leaf row count for descending-group index `g` — ceil(concat / RATE)
 *  with concat = Σ_{m in g}(widths[m] + salt_elems), no trailing permutation on
 *  an exact multiple. 0 on reject / out of range. */
size_t dnac_p2c_mmix_group_leaf_rows(const dnac_p2c_mmix_table_cfg_t *cfg,
                                     size_t g);

/** Scheduled (non-padding) rows = leaf(g0) + depth + Σ inject blocks + final.
 *  0 on reject. */
size_t dnac_p2c_mmix_sched_rows(const dnac_p2c_mmix_table_cfg_t *cfg);

/**
 * Padded row count: next_pow2(sched + 1), minimum DNAC_P2C_MMIX_MIN_ROWS. The +1
 * is the mandatory terminal padding row. Returns 0 for a NULL or out-of-range
 * config — callers treat 0 as "reject".
 */
size_t dnac_p2c_mmix_table_rows(const dnac_p2c_mmix_table_cfg_t *cfg);

/**
 * Decode row `row` of `cfg`'s schedule. Pure function of (cfg, row); the cell
 * writer is built on it, so the record and the cells cannot disagree. Fail-close
 * on a bad config or `row >= dnac_p2c_mmix_table_rows(cfg)`.
 */
dnac_p2c_mmix_table_status_t dnac_p2c_mmix_table_row(
    const dnac_p2c_mmix_table_cfg_t *cfg, size_t row, dnac_p2c_mmix_row_t *out);

/**
 * Generate the table into `out` (row-major, rows x DNAC_P2C_MMIX_TABLE_COLS
 * cells). Fail-close: a bad config or an `out_cells` smaller than the requirement
 * leaves `out` untouched and returns an error.
 */
dnac_p2c_mmix_table_status_t dnac_p2c_mmix_table_generate(
    const dnac_p2c_mmix_table_cfg_t *cfg, uint64_t *out, size_t out_cells);

/**
 * STATIC VALIDATOR — re-checks every schedule invariant the mixed-MMCS AIR relies
 * on, against the CELLS, structurally and INDEPENDENTLY of the generator (it
 * re-derives the expected schedule from cfg semantics; it does NOT memcmp against
 * the generator, which would be circular). Under PIN-1-MMIX nothing on the verify
 * path re-checks a preprocessed cell, so this validator plus the root pin are the
 * whole guarantee.
 *
 * Checks, in evaluation order (see dnac_p2c_mmix_table_defect_t):
 *   1 booleanity        every cell in {0,1} (covers non-canonical: no field lit)
 *   2 type exclusivity  exactly one of the 6 primary types per row
 *   3 primary schedule  each row's primary type matches the reconstructed
 *                       leaf | (compress [+ inject block])* | final | pad layout
 *                       — subsumes every row-type COUNT
 *   4 has_inject        set iff a compress row at an injecting level
 *   5 level one-hot     the right level on compress / inject rows; all-zero on
 *                       the tallest leaf / final / pad
 *   6 group one-hot     the right descending-group index on leaf / inject rows;
 *                       all-zero on compress / final / pad
 *   7 step one-hot      scheduled row k carries pos[k]=1 and nothing else;
 *                       padding rows all-zero (also pins the prefix ORDER)
 *
 * @param out_defect optional; set to the FIRST defect found (or
 *                   DNAC_P2C_MMIX_DEFECT_NONE on success). May be NULL.
 * @return DNAC_P2C_MMIX_TABLE_OK, DNAC_P2C_MMIX_TABLE_ERR_PARAM (NULL / bad cfg /
 *         wrong `rows`) or DNAC_P2C_MMIX_TABLE_ERR_SCHEDULE.
 */
dnac_p2c_mmix_table_status_t dnac_p2c_mmix_table_validate(
    const dnac_p2c_mmix_table_cfg_t *cfg, const uint64_t *cells, size_t rows,
    dnac_p2c_mmix_table_defect_t *out_defect);

/**
 * PIN-1-MMIX comparator, fail-close. Returns DNAC_P2C_MMIX_TABLE_OK iff `lanes`
 * equals DNAC_P2C_MMIX_PREP_ROOT lane for lane; DNAC_P2C_MMIX_TABLE_ERR_ROOT_MISMATCH
 * on any difference and DNAC_P2C_MMIX_TABLE_ERR_PARAM on NULL. The pin lives
 * CALLER-side; `dnac_batch_verify`'s signature does not change. This is the call
 * the future composition entry makes on the DECODED preprocessed commitment before
 * it trusts a single gated constraint.
 *
 * ⚠ While DNAC_P2C_MMIX_PREP_ROOT_UNFILLED, this ALWAYS returns
 * DNAC_P2C_MMIX_TABLE_ERR_ROOT_MISMATCH — including for an all-zero `lanes`. A
 * placeholder pin that accepted an all-zero root would be strictly worse than no
 * pin.
 */
dnac_p2c_mmix_table_status_t dnac_p2c_mmix_prep_root_check(const uint64_t lanes[4]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_MMCS_MIXED_AIR_TABLE_H */
