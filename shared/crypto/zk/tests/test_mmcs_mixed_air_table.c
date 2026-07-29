/**
 * @file test_mmcs_mixed_air_table.c
 * @brief P2b slice 2 PIN gate — the MIXED-HEIGHT MMCS-verify AIR's preprocessed
 *        row-type table: deterministic generator, structural static validator,
 *        and the PIN-1-MMIX root constant (runtime KAT, shielded_domsep.h
 *        practice).
 *
 * Build spec: dnac/docs/plans/2026-07-29-p2b-slice2-mixed-mmcs-BUILDABLE.md
 * "Row schedule" (:51-67); native oracle dnac_p2_mmcs_verify_mixed
 * (poseidon2_mmcs.c:454-529). No AIR is built in this slice —
 * `mmcs_mixed_air.{c,h}` is a later one. Mirrors the P2c open_input PIN gate
 * (tests/test_fri_oi_air_table.c) one-for-one.
 *
 *   T1  generator determinism — the reference cfg and a WIDER mixed shape, two
 *       runs each, byte-identical; shape accessors agree with the schedule
 *       numbers; the two tables are genuinely different
 *   T2  schedule shape: tallest-group leaf + per-level compress with OPTIONAL
 *       interleaved inject blocks + final + padding; the level / group / step
 *       one-hots + has_inject; the static validator accepts both cfgs; the row
 *       record agrees with the cells; a hand-checked reference layout
 *   T3  PIN-1-MMIX KAT: table -> coset LDE (bitrev) -> dnac_p2_mmcs_commit_mixed
 *       == DNAC_P2C_MMIX_PREP_ROOT, and the comparator accepts it.
 *       (Pin FILLED 2026-07-29 from `--print-root`; on a future re-pin it
 *       reverts to {0,0,0,0} and the four lane checks + UNFILLED guard blocks
 *       reactivate at compile time — RED by design then.)
 *   N1  comparator rejects a one-lane tamper / NULL (and the all-zero root while
 *       the pin is the placeholder)
 *   N2  the pin binds table CONTENTS: one flipped selector cell => another root
 *   N3  static-validator negatives — every check tripped exactly once, with
 *       exact defect isolation
 *   N4  generator / cfg-gate fail-close
 *
 * Usage:
 *   test_mmcs_mixed_air_table                 run all gates
 *   test_mmcs_mixed_air_table --print-root    print the reference table's four
 *                                             root lanes in
 *                                             DNAC_P2C_MMIX_PREP_ROOT_LANE* form
 *                                             (refuses on validator failure)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../mmcs_mixed_air_table.h"
#include "../poseidon2_mmcs.h"
#include "../shielded_fri_params.h"
#include "../stark_prover.h"

static int g_checks = 0;
static int g_fails = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        g_checks++;                                                           \
        if (!(cond)) {                                                        \
            g_fails++;                                                        \
            fprintf(stderr, "  FAIL: ");                                      \
            fprintf(stderr, __VA_ARGS__);                                     \
            fprintf(stderr, "\n");                                            \
        }                                                                     \
    } while (0)

/* Compile-time pins — the module's local macros MUST equal the shipped constants
 * they mirror, so they cannot drift (the DNAC_P2C_PREP_LOG_BLOWUP practice). */
typedef char mmix_blowup_pin_assert
    [(DNAC_P2C_MMIX_PREP_LOG_BLOWUP == (unsigned)DNAC_SHIELDED_FRI_LOG_BLOWUP)
         ? 1
         : -1];
typedef char mmix_depth_bound_assert
    [(DNAC_P2C_MMIX_MAX_DEPTH == (size_t)GOLDILOCKS_TWO_ADICITY) ? 1 : -1];
/* The reference leaf salt equals the shipped hiding-salt constant (spec :35-38:
 * salt_elems == 2 from shielded_fri_params.h). */
typedef char mmix_ref_salt_assert
    [(DNAC_P2C_MMIX_REF_SALT_ELEMS == DNAC_SHIELDED_SALT_ELEMS) ? 1 : -1];
/* Column layout: 7 flags [0,7), then the level one-hot at 7, the group one-hot
 * at 39, the step one-hot at 72 — total 136. has_inject is the last flag. */
typedef char mmix_layout_assert
    [(DNAC_P2C_MMIX_COL_HAS_INJECT == (int)DNAC_P2C_MMIX_NUM_FLAG_COLS - 1 &&
      DNAC_P2C_MMIX_COL_LVL_OFF == (int)DNAC_P2C_MMIX_NUM_FLAG_COLS &&
      DNAC_P2C_MMIX_COL_GSEL_OFF == (size_t)39 &&
      DNAC_P2C_MMIX_COL_POS_OFF == (size_t)72 &&
      DNAC_P2C_MMIX_TABLE_COLS == (size_t)136)
         ? 1
         : -1];
/* Distinct heights are powers of two in [1, max_h], max_h == 2^depth, depth <=
 * 32 => at most 33 distinct groups; the one-hot must carry them. */
typedef char mmix_groups_bound_assert
    [(DNAC_P2C_MMIX_MAX_GROUPS >= DNAC_P2C_MMIX_MAX_DEPTH + 1) ? 1 : -1];

#define MMIX_COLS ((size_t)DNAC_P2C_MMIX_TABLE_COLS) /* 136  */
#define REF_ROWS DNAC_P2C_MMIX_REF_ROWS              /* 8    */
#define REF_CELLS (REF_ROWS * MMIX_COLS)             /* 1088 */
#define WIDE_ROWS ((size_t)16)
#define WIDE_CELLS (WIDE_ROWS * MMIX_COLS) /* 2176 */
#define MAX_COMMIT_ROWS REF_ROWS
#define MAX_LDE_CELLS \
    ((MAX_COMMIT_ROWS << DNAC_P2C_MMIX_PREP_LOG_BLOWUP) * MMIX_COLS)

/* The WIDER shape (NOT reference-cfg-shaped): heights {16, 4, 2}, widths
 * {5, 2, 6}, salt 2, depth 4. max_h = 16 => three descending groups
 * (16, 4, 2); height 8 is ABSENT so the l=0 level does NOT inject. Leaf-row
 * counts exercise all three sponge cases at once:
 *   g0 h=16 concat 5+2=7 => ceil(7/4)=2   (partial final block)
 *   g1 h=4  concat 2+2=4 => 4/4=1          (EXACT multiple, no trailing perm)
 *   g2 h=2  concat 6+2=8 => 8/4=2          (multi-block, exact)
 * Injection at l=1 (cur=4, g1) and l=2 (cur=2, g2); l=0 (cur=8) and l=3 (cur=1)
 * do NOT inject. n_sched = 2 + 4 + (1+1) + (2+1) + 1 = 12, 16 rows. NO root is
 * pinned for it — it exists to prove the generator/validator are not
 * reference-cfg-shaped. */
static const size_t WIDE_HEIGHTS[3] = { 16, 4, 2 };
static const size_t WIDE_WIDTHS[3] = { 5, 2, 6 };
static const dnac_p2c_mmix_table_cfg_t WIDE_CFG = { 3, WIDE_WIDTHS, WIDE_HEIGHTS,
                                                    4, 2 };

/* ==========================================================================
 * Shared helper: the SHIPPED preprocessed-commit pipeline
 * (batch_prover.c:807-825 with is_zk = 0: coset LDE bit-reversed at log_blowup,
 * then ONE mixed-height Poseidon2 MMCS commit).
 * ======================================================================== */
static int mmix_commit_table(const uint64_t *table, size_t rows,
                             uint64_t out_lanes[4])
{
    static uint64_t lde[MAX_LDE_CELLS];
    const size_t lde_rows = rows << DNAC_P2C_MMIX_PREP_LOG_BLOWUP;
    if (lde_rows * MMIX_COLS > MAX_LDE_CELLS) return 0;

    if (dnac_prover_coset_lde_bitrev(table, rows, MMIX_COLS,
                                     DNAC_P2C_MMIX_PREP_LOG_BLOWUP,
                                     GOLDILOCKS_GENERATOR,
                                     lde) != DNAC_PROVER_OK) {
        return 0;
    }
    const uint64_t *mats[1] = { lde };
    const size_t widths[1] = { MMIX_COLS };
    const size_t heights[1] = { lde_rows };
    dnac_p2_digest_t root;
    if (dnac_p2_mmcs_commit_mixed(mats, widths, heights, 1, &root, NULL) !=
        DNAC_P2M_OK) {
        return 0;
    }
    memcpy(out_lanes, root.lanes, 4 * sizeof(uint64_t));
    return 1;
}

/* ==========================================================================
 * T1 — generator determinism
 * ======================================================================== */
static void t1_determinism(void)
{
    static uint64_t a[REF_CELLS], b[REF_CELLS];
    const dnac_p2c_mmix_table_cfg_t *ref = dnac_p2c_mmix_ref_cfg();

    CHECK(dnac_p2c_mmix_num_groups(ref) == 2, "T1: ref groups %zu != 2",
          dnac_p2c_mmix_num_groups(ref));
    CHECK(dnac_p2c_mmix_group_height(ref, 0) == 8, "T1: ref group0 h %zu != 8",
          dnac_p2c_mmix_group_height(ref, 0));
    CHECK(dnac_p2c_mmix_group_height(ref, 1) == 2, "T1: ref group1 h %zu != 2",
          dnac_p2c_mmix_group_height(ref, 1));
    CHECK(dnac_p2c_mmix_group_leaf_rows(ref, 0) == 1,
          "T1: ref group0 leaf rows %zu != 1",
          dnac_p2c_mmix_group_leaf_rows(ref, 0));
    CHECK(dnac_p2c_mmix_group_leaf_rows(ref, 1) == 1,
          "T1: ref group1 leaf rows %zu != 1",
          dnac_p2c_mmix_group_leaf_rows(ref, 1));
    CHECK(dnac_p2c_mmix_sched_rows(ref) == DNAC_P2C_MMIX_REF_SCHED,
          "T1: ref sched %zu != %zu", dnac_p2c_mmix_sched_rows(ref),
          (size_t)DNAC_P2C_MMIX_REF_SCHED);
    CHECK(dnac_p2c_mmix_table_rows(ref) == REF_ROWS, "T1: ref rows %zu != %zu",
          dnac_p2c_mmix_table_rows(ref), (size_t)REF_ROWS);

    CHECK(dnac_p2c_mmix_table_generate(ref, a, REF_CELLS) ==
              DNAC_P2C_MMIX_TABLE_OK,
          "T1: ref generate #1");
    CHECK(dnac_p2c_mmix_table_generate(ref, b, REF_CELLS) ==
              DNAC_P2C_MMIX_TABLE_OK,
          "T1: ref generate #2");
    CHECK(memcmp(a, b, sizeof(a)) == 0, "T1: ref table NOT deterministic");

    static uint64_t c[WIDE_CELLS], d[WIDE_CELLS];
    CHECK(dnac_p2c_mmix_num_groups(&WIDE_CFG) == 3, "T1: wide groups %zu != 3",
          dnac_p2c_mmix_num_groups(&WIDE_CFG));
    CHECK(dnac_p2c_mmix_group_leaf_rows(&WIDE_CFG, 0) == 2,
          "T1: wide group0 leaf rows %zu != 2",
          dnac_p2c_mmix_group_leaf_rows(&WIDE_CFG, 0));
    CHECK(dnac_p2c_mmix_group_leaf_rows(&WIDE_CFG, 1) == 1,
          "T1: wide group1 leaf rows %zu != 1",
          dnac_p2c_mmix_group_leaf_rows(&WIDE_CFG, 1));
    CHECK(dnac_p2c_mmix_group_leaf_rows(&WIDE_CFG, 2) == 2,
          "T1: wide group2 leaf rows %zu != 2",
          dnac_p2c_mmix_group_leaf_rows(&WIDE_CFG, 2));
    CHECK(dnac_p2c_mmix_sched_rows(&WIDE_CFG) == 12, "T1: wide sched %zu != 12",
          dnac_p2c_mmix_sched_rows(&WIDE_CFG));
    CHECK(dnac_p2c_mmix_table_rows(&WIDE_CFG) == WIDE_ROWS,
          "T1: wide rows %zu != %zu", dnac_p2c_mmix_table_rows(&WIDE_CFG),
          WIDE_ROWS);
    CHECK(dnac_p2c_mmix_table_generate(&WIDE_CFG, c, WIDE_CELLS) ==
              DNAC_P2C_MMIX_TABLE_OK,
          "T1: wide generate #1");
    CHECK(dnac_p2c_mmix_table_generate(&WIDE_CFG, d, WIDE_CELLS) ==
              DNAC_P2C_MMIX_TABLE_OK,
          "T1: wide generate #2");
    CHECK(memcmp(c, d, sizeof(c)) == 0, "T1: wide table NOT deterministic");

    /* Genuinely different tables. */
    CHECK(memcmp(a, c, REF_CELLS * sizeof(uint64_t)) != 0,
          "T1: reference and wide tables are byte-identical");
}

/* ==========================================================================
 * T2 — schedule shape + the static validator on both cfgs
 * ======================================================================== */
static void t2_shape(const dnac_p2c_mmix_table_cfg_t *cfg, const char *name,
                     size_t exp_leaf, size_t exp_compress, size_t exp_inj_leaf,
                     size_t exp_inj_compress, size_t exp_rows)
{
    static uint64_t t[WIDE_CELLS];
    const size_t rows = dnac_p2c_mmix_table_rows(cfg);
    if (rows != exp_rows ||
        dnac_p2c_mmix_table_generate(cfg, t, WIDE_CELLS) !=
            DNAC_P2C_MMIX_TABLE_OK) {
        CHECK(0, "T2[%s]: generate failed (rows %zu, want %zu)", name, rows,
              exp_rows);
        return;
    }
    const size_t sched =
        exp_leaf + exp_compress + exp_inj_leaf + exp_inj_compress + 1 /*final*/;

    size_t n_leaf = 0, n_compress = 0, n_inj_leaf = 0, n_inj_compress = 0,
           n_final = 0, n_pad = 0, n_has_inject = 0;
    int exclusive_ok = 1, boolean_ok = 1, pos_ok = 1, lvl_ok = 1, gsel_ok = 1;

    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &t[r * MMIX_COLS];

        for (size_t k = 0; k < MMIX_COLS; k++) {
            if (row[k] > 1) boolean_ok = 0;
        }

        const uint64_t set = row[DNAC_P2C_MMIX_COL_IS_LEAF] +
                             row[DNAC_P2C_MMIX_COL_IS_COMPRESS] +
                             row[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF] +
                             row[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS] +
                             row[DNAC_P2C_MMIX_COL_IS_FINAL] +
                             row[DNAC_P2C_MMIX_COL_IS_PAD];
        if (set != 1) exclusive_ok = 0;

        n_leaf += (size_t)row[DNAC_P2C_MMIX_COL_IS_LEAF];
        n_compress += (size_t)row[DNAC_P2C_MMIX_COL_IS_COMPRESS];
        n_inj_leaf += (size_t)row[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF];
        n_inj_compress += (size_t)row[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS];
        n_final += (size_t)row[DNAC_P2C_MMIX_COL_IS_FINAL];
        n_pad += (size_t)row[DNAC_P2C_MMIX_COL_IS_PAD];
        n_has_inject += (size_t)row[DNAC_P2C_MMIX_COL_HAS_INJECT];

        /* Row type routes which one-hots may fire. */
        const int is_compress = (int)row[DNAC_P2C_MMIX_COL_IS_COMPRESS];
        const int is_inj_leaf = (int)row[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF];
        const int is_inj_comp = (int)row[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS];
        const int is_leaf = (int)row[DNAC_P2C_MMIX_COL_IS_LEAF];

        /* level one-hot: set iff compress or inject-block row. */
        size_t ls = 0;
        for (size_t l = 0; l < DNAC_P2C_MMIX_MAX_LEVELS; l++) {
            ls += (size_t)row[dnac_p2c_mmix_col_lvl(l)];
        }
        const int has_lvl = is_compress || is_inj_leaf || is_inj_comp;
        if (ls != (size_t)(has_lvl ? 1 : 0)) lvl_ok = 0;

        /* group one-hot: set iff leaf or inject-block row. */
        size_t gs = 0;
        for (size_t g = 0; g < DNAC_P2C_MMIX_MAX_GROUPS; g++) {
            gs += (size_t)row[dnac_p2c_mmix_col_gsel(g)];
        }
        const int has_grp = is_leaf || is_inj_leaf || is_inj_comp;
        if (gs != (size_t)(has_grp ? 1 : 0)) gsel_ok = 0;

        /* step one-hot: exactly one on a scheduled row (== r), none on pad. */
        for (size_t k = 0; k < DNAC_P2C_MMIX_MAX_STEPS; k++) {
            const uint64_t want = (r < sched && k == r) ? 1u : 0u;
            if (row[dnac_p2c_mmix_col_pos(k)] != want) pos_ok = 0;
        }
    }

    CHECK(n_leaf == exp_leaf, "T2[%s]: leaf rows %zu != %zu", name, n_leaf,
          exp_leaf);
    CHECK(n_compress == exp_compress, "T2[%s]: compress rows %zu != %zu", name,
          n_compress, exp_compress);
    CHECK(n_inj_leaf == exp_inj_leaf, "T2[%s]: inject-leaf rows %zu != %zu", name,
          n_inj_leaf, exp_inj_leaf);
    CHECK(n_inj_compress == exp_inj_compress,
          "T2[%s]: inject-compress rows %zu != %zu", name, n_inj_compress,
          exp_inj_compress);
    CHECK(n_final == 1, "T2[%s]: final rows %zu != 1", name, n_final);
    CHECK(n_pad == rows - sched && n_pad >= 1, "T2[%s]: padding rows %zu != %zu",
          name, n_pad, rows - sched);
    /* has_inject fires once per injecting level == once per non-tallest group. */
    CHECK(n_has_inject == exp_inj_compress,
          "T2[%s]: has_inject count %zu != %zu", name, n_has_inject,
          exp_inj_compress);
    CHECK(exclusive_ok, "T2[%s]: a row carries != 1 primary type", name);
    CHECK(boolean_ok, "T2[%s]: a cell is non-boolean", name);
    CHECK(pos_ok, "T2[%s]: step one-hot wrong", name);
    CHECK(lvl_ok, "T2[%s]: level one-hot wrong", name);
    CHECK(gsel_ok, "T2[%s]: group one-hot wrong", name);

    /* The LAST row is padding (terminality gate). */
    CHECK(t[(rows - 1) * MMIX_COLS + DNAC_P2C_MMIX_COL_IS_PAD] == 1,
          "T2[%s]: last row is not padding", name);

    /* The row record and the cells must agree. */
    int record_ok = 1;
    for (size_t r = 0; r < rows; r++) {
        dnac_p2c_mmix_row_t rec;
        if (dnac_p2c_mmix_table_row(cfg, r, &rec) != DNAC_P2C_MMIX_TABLE_OK) {
            record_ok = 0;
            break;
        }
        const uint64_t *row = &t[r * MMIX_COLS];
        const uint64_t prim =
            (rec.type == DNAC_P2C_MMIX_ROW_LEAF) ? row[DNAC_P2C_MMIX_COL_IS_LEAF]
            : (rec.type == DNAC_P2C_MMIX_ROW_COMPRESS)
                ? row[DNAC_P2C_MMIX_COL_IS_COMPRESS]
            : (rec.type == DNAC_P2C_MMIX_ROW_INJECT_LEAF)
                ? row[DNAC_P2C_MMIX_COL_IS_INJECT_LEAF]
            : (rec.type == DNAC_P2C_MMIX_ROW_INJECT_COMPRESS)
                ? row[DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS]
            : (rec.type == DNAC_P2C_MMIX_ROW_FINAL)
                ? row[DNAC_P2C_MMIX_COL_IS_FINAL]
                : row[DNAC_P2C_MMIX_COL_IS_PAD];
        if (prim != 1 ||
            row[DNAC_P2C_MMIX_COL_HAS_INJECT] != (uint64_t)rec.has_inject) {
            record_ok = 0;
            break;
        }
        if (rec.level != (size_t)-1 &&
            row[dnac_p2c_mmix_col_lvl(rec.level)] != 1) {
            record_ok = 0;
            break;
        }
        if (rec.group != (size_t)-1 &&
            row[dnac_p2c_mmix_col_gsel(rec.group)] != 1) {
            record_ok = 0;
            break;
        }
    }
    CHECK(record_ok, "T2[%s]: row record disagrees with the cells", name);

    dnac_p2c_mmix_table_defect_t defect = DNAC_P2C_MMIX_DEFECT_NONE;
    CHECK(dnac_p2c_mmix_table_validate(cfg, t, rows, &defect) ==
              DNAC_P2C_MMIX_TABLE_OK,
          "T2[%s]: validator REJECTED the generated table (defect %d)", name,
          (int)defect);
    CHECK(defect == DNAC_P2C_MMIX_DEFECT_NONE,
          "T2[%s]: defect %d on a clean table", name, (int)defect);
}

static void t2_hand_layout(void)
{
    /* Reference layout (mmcs_mixed_air_table.h): tallest-group leaf, a compress
     * per level with ONE interleaved inject block at cur==2. Hand-check the
     * load-bearing rows. */
    static uint64_t t[REF_CELLS];
    const dnac_p2c_mmix_table_cfg_t *ref = dnac_p2c_mmix_ref_cfg();
    if (dnac_p2c_mmix_table_generate(ref, t, REF_CELLS) !=
        DNAC_P2C_MMIX_TABLE_OK) {
        CHECK(0, "T2hand: generate failed");
        return;
    }
#define AT(row, col) (t[(size_t)(row) * MMIX_COLS + (size_t)(col)])
    /* row 0 : tallest-group (h=8) leaf, routes gsel[0], no level. */
    CHECK(AT(0, DNAC_P2C_MMIX_COL_IS_LEAF) == 1 &&
              AT(0, dnac_p2c_mmix_col_gsel(0)) == 1 &&
              AT(0, dnac_p2c_mmix_col_pos(0)) == 1,
          "T2hand: row 0 not the tallest leaf");
    /* row 1 : compress level 0 (cur=4 absent => has_inject 0). */
    CHECK(AT(1, DNAC_P2C_MMIX_COL_IS_COMPRESS) == 1 &&
              AT(1, dnac_p2c_mmix_col_lvl(0)) == 1 &&
              AT(1, DNAC_P2C_MMIX_COL_HAS_INJECT) == 0,
          "T2hand: row 1 not the non-injecting compress l0");
    /* row 2 : compress level 1 (cur=2 present => has_inject 1). */
    CHECK(AT(2, DNAC_P2C_MMIX_COL_IS_COMPRESS) == 1 &&
              AT(2, dnac_p2c_mmix_col_lvl(1)) == 1 &&
              AT(2, DNAC_P2C_MMIX_COL_HAS_INJECT) == 1,
          "T2hand: row 2 not the injecting compress l1");
    /* row 3 : inject-leaf group1 (h=2), level 1, gsel[1]. */
    CHECK(AT(3, DNAC_P2C_MMIX_COL_IS_INJECT_LEAF) == 1 &&
              AT(3, dnac_p2c_mmix_col_lvl(1)) == 1 &&
              AT(3, dnac_p2c_mmix_col_gsel(1)) == 1,
          "T2hand: row 3 not the inject-leaf group1");
    /* row 4 : inject-compress group1, level 1, gsel[1]. */
    CHECK(AT(4, DNAC_P2C_MMIX_COL_IS_INJECT_COMPRESS) == 1 &&
              AT(4, dnac_p2c_mmix_col_lvl(1)) == 1 &&
              AT(4, dnac_p2c_mmix_col_gsel(1)) == 1,
          "T2hand: row 4 not the inject-compress group1");
    /* row 5 : compress level 2 (cur=1 absent => has_inject 0). */
    CHECK(AT(5, DNAC_P2C_MMIX_COL_IS_COMPRESS) == 1 &&
              AT(5, dnac_p2c_mmix_col_lvl(2)) == 1 &&
              AT(5, DNAC_P2C_MMIX_COL_HAS_INJECT) == 0,
          "T2hand: row 5 not the non-injecting compress l2");
    /* row 6 : final. */
    CHECK(AT(6, DNAC_P2C_MMIX_COL_IS_FINAL) == 1 &&
              AT(6, dnac_p2c_mmix_col_pos(6)) == 1,
          "T2hand: row 6 not the final row");
    /* row 7 : padding. */
    CHECK(AT(7, DNAC_P2C_MMIX_COL_IS_PAD) == 1,
          "T2hand: row 7 not padding");
#undef AT
}

static void t2_all(void)
{
    /* ref: leaf 1, compress 3, inject-leaf 1, inject-compress 1, 8 rows. */
    t2_shape(dnac_p2c_mmix_ref_cfg(), "ref", 1, 3, 1, 1, REF_ROWS);
    /* wide: leaf 2, compress 4, inject-leaf 3 (1+2), inject-compress 2, 16 rows. */
    t2_shape(&WIDE_CFG, "wide", 2, 4, 3, 2, WIDE_ROWS);
    t2_hand_layout();
}

/* ==========================================================================
 * T3 — PIN-1-MMIX KAT + N1 + N2
 * ======================================================================== */
static void t3_pin_kat(void)
{
    static uint64_t t[REF_CELLS];
    const dnac_p2c_mmix_table_cfg_t *ref = dnac_p2c_mmix_ref_cfg();
    if (dnac_p2c_mmix_table_generate(ref, t, REF_CELLS) !=
        DNAC_P2C_MMIX_TABLE_OK) {
        CHECK(0, "T3: generate failed");
        return;
    }

    uint64_t lanes[4];
    if (!mmix_commit_table(t, REF_ROWS, lanes)) {
        CHECK(0, "T3: LDE/commit pipeline failed");
        return;
    }
    printf("  PIN-1-MMIX derived root = { 0x%016" PRIx64 ", 0x%016" PRIx64
           ", 0x%016" PRIx64 ", 0x%016" PRIx64 " }\n",
           lanes[0], lanes[1], lanes[2], lanes[3]);
    if (DNAC_P2C_MMIX_PREP_ROOT_UNFILLED) {
        fprintf(stderr,
                "  NOTE: DNAC_P2C_MMIX_PREP_ROOT is still the PLACEHOLDER "
                "{0,0,0,0}.\n        The four T3 lane checks below FAIL BY "
                "DESIGN until it is filled\n        from `--print-root`. Do not "
                "hand-edit the constant to silence them.\n");
    }

    static const uint64_t pinned[4] = DNAC_P2C_MMIX_PREP_ROOT;
    for (int k = 0; k < 4; k++) {
        CHECK(lanes[k] == pinned[k],
              "T3: PIN-1-MMIX lane %d: derived 0x%016" PRIx64
              " != pinned 0x%016" PRIx64,
              k, lanes[k], pinned[k]);
    }
    CHECK(dnac_p2c_mmix_prep_root_check(lanes) == DNAC_P2C_MMIX_TABLE_OK,
          "T3: comparator rejected the derived root");

    /* N1 — one tampered lane, and NULL. */
    for (int k = 0; k < 4; k++) {
        uint64_t bad[4];
        memcpy(bad, lanes, sizeof(bad));
        bad[k] ^= 1;
        CHECK(dnac_p2c_mmix_prep_root_check(bad) ==
                  DNAC_P2C_MMIX_TABLE_ERR_ROOT_MISMATCH,
              "N1: comparator accepted a tampered lane %d", k);
    }
    CHECK(dnac_p2c_mmix_prep_root_check(NULL) == DNAC_P2C_MMIX_TABLE_ERR_PARAM,
          "N1: comparator on NULL must be PARAM");
    if (DNAC_P2C_MMIX_PREP_ROOT_UNFILLED) {
        /* An unfilled pin must reject even the all-zero root it would otherwise
         * match. This block disappears the moment the constant is filled. */
        const uint64_t zero[4] = { 0, 0, 0, 0 };
        CHECK(dnac_p2c_mmix_prep_root_check(zero) ==
                  DNAC_P2C_MMIX_TABLE_ERR_ROOT_MISMATCH,
              "N1: PLACEHOLDER pin ACCEPTED an all-zero root");
    }

    /* N2 — the pin binds CONTENTS: clear the group0 leaf's gsel[0] selector and
     * re-run the SAME pipeline. Everything else is byte-identical. */
    static uint64_t tampered[REF_CELLS];
    memcpy(tampered, t, sizeof(tampered));
    tampered[0 * MMIX_COLS + dnac_p2c_mmix_col_gsel(0)] = 0;
    CHECK(memcmp(tampered, t, sizeof(t)) != 0, "N2: tamper did not change table");
    uint64_t bad_lanes[4];
    if (mmix_commit_table(tampered, REF_ROWS, bad_lanes)) {
        CHECK(memcmp(bad_lanes, lanes, sizeof(lanes)) != 0,
              "N2: a flipped selector cell produced the SAME root");
    } else {
        CHECK(0, "N2: LDE/commit pipeline failed on the tampered table");
    }
    dnac_p2c_mmix_table_defect_t d = DNAC_P2C_MMIX_DEFECT_NONE;
    CHECK(dnac_p2c_mmix_table_validate(ref, tampered, REF_ROWS, &d) ==
              DNAC_P2C_MMIX_TABLE_ERR_SCHEDULE,
          "N2: validator accepted the cleared gsel");
    CHECK(d == DNAC_P2C_MMIX_DEFECT_GSEL_ONEHOT, "N2: defect %d != GSEL_ONEHOT",
          (int)d);
}

/* ==========================================================================
 * N3 — static-validator negatives, one check tripped per tamper
 *
 * Every mutation starts from the CLEAN reference table, so a mutation that
 * accidentally tripped an earlier check would show up as the wrong defect code,
 * not as a silent pass (exact-count isolation).
 * ======================================================================== */
static uint64_t g_good[REF_CELLS];

static void n3_case(const char *what, dnac_p2c_mmix_table_defect_t want,
                    const size_t *cells_idx, const uint64_t *vals, size_t n)
{
    static uint64_t t[REF_CELLS];
    memcpy(t, g_good, sizeof(t));
    for (size_t i = 0; i < n; i++) t[cells_idx[i]] = vals[i];

    dnac_p2c_mmix_table_defect_t got = DNAC_P2C_MMIX_DEFECT_NONE;
    const dnac_p2c_mmix_table_status_t st =
        dnac_p2c_mmix_table_validate(dnac_p2c_mmix_ref_cfg(), t, REF_ROWS, &got);
    CHECK(st == DNAC_P2C_MMIX_TABLE_ERR_SCHEDULE, "N3[%s]: validator returned %d",
          what, (int)st);
    CHECK(got == want, "N3[%s]: defect %d != %d", what, (int)got, (int)want);
}

#define IDX(row, col) ((size_t)((row) * MMIX_COLS + (col)))

static void n3_validator_negatives(void)
{
    const dnac_p2c_mmix_table_cfg_t *ref = dnac_p2c_mmix_ref_cfg();
    if (dnac_p2c_mmix_table_generate(ref, g_good, REF_CELLS) !=
        DNAC_P2C_MMIX_TABLE_OK) {
        CHECK(0, "N3: reference generate failed");
        return;
    }

    { /* 1 booleanity — a `2` trips boolean before exclusivity. */
        const size_t i[1] = { IDX(0, DNAC_P2C_MMIX_COL_IS_LEAF) };
        const uint64_t v[1] = { 2 };
        n3_case("boolean_two", DNAC_P2C_MMIX_DEFECT_BOOLEAN, i, v, 1);
    }
    { /* 1b booleanity — a cell at exactly p (non-canonical) is > 1, caught. */
        const size_t i[1] = { IDX(7, dnac_p2c_mmix_col_pos(0)) };
        const uint64_t v[1] = { GOLDILOCKS_P };
        n3_case("boolean_p", DNAC_P2C_MMIX_DEFECT_BOOLEAN, i, v, 1);
    }
    { /* 2 type exclusivity — a row claiming two primary types. */
        const size_t i[1] = { IDX(0, DNAC_P2C_MMIX_COL_IS_COMPRESS) };
        const uint64_t v[1] = { 1 };
        n3_case("type_exclusive", DNAC_P2C_MMIX_DEFECT_TYPE_EXCLUSIVE, i, v, 1);
    }
    { /* 3 primary schedule — RETYPE row 1 (compress -> leaf): exactly one
       *   primary set, wrong one for that position. */
        const size_t i[2] = { IDX(1, DNAC_P2C_MMIX_COL_IS_COMPRESS),
                              IDX(1, DNAC_P2C_MMIX_COL_IS_LEAF) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("primary_schedule", DNAC_P2C_MMIX_DEFECT_PRIMARY_SCHEDULE, i, v,
                2);
    }
    { /* 4a has_inject cleared on the injecting compress (row 2). */
        const size_t i[1] = { IDX(2, DNAC_P2C_MMIX_COL_HAS_INJECT) };
        const uint64_t v[1] = { 0 };
        n3_case("has_inject_cleared", DNAC_P2C_MMIX_DEFECT_HAS_INJECT, i, v, 1);
    }
    { /* 4b has_inject spurious on a non-injecting compress (row 1). */
        const size_t i[1] = { IDX(1, DNAC_P2C_MMIX_COL_HAS_INJECT) };
        const uint64_t v[1] = { 1 };
        n3_case("has_inject_spurious", DNAC_P2C_MMIX_DEFECT_HAS_INJECT, i, v, 1);
    }
    { /* 5a level one-hot cleared on a compress row (row 1, lvl[0]). */
        const size_t i[1] = { IDX(1, dnac_p2c_mmix_col_lvl(0)) };
        const uint64_t v[1] = { 0 };
        n3_case("lvl_cleared", DNAC_P2C_MMIX_DEFECT_LVL_ONEHOT, i, v, 1);
    }
    { /* 5b level one-hot WRONG index (row 1 should route lvl[0]). */
        const size_t i[2] = { IDX(1, dnac_p2c_mmix_col_lvl(0)),
                              IDX(1, dnac_p2c_mmix_col_lvl(1)) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("lvl_wrong_index", DNAC_P2C_MMIX_DEFECT_LVL_ONEHOT, i, v, 2);
    }
    { /* 5c level selector on the tallest leaf (row 0 routes no level). */
        const size_t i[1] = { IDX(0, dnac_p2c_mmix_col_lvl(0)) };
        const uint64_t v[1] = { 1 };
        n3_case("lvl_on_leaf", DNAC_P2C_MMIX_DEFECT_LVL_ONEHOT, i, v, 1);
    }
    { /* 6a group one-hot cleared on the tallest leaf (row 0, gsel[0]). */
        const size_t i[1] = { IDX(0, dnac_p2c_mmix_col_gsel(0)) };
        const uint64_t v[1] = { 0 };
        n3_case("gsel_cleared", DNAC_P2C_MMIX_DEFECT_GSEL_ONEHOT, i, v, 1);
    }
    { /* 6b group one-hot WRONG index (row 3 inject-leaf should route gsel[1]). */
        const size_t i[2] = { IDX(3, dnac_p2c_mmix_col_gsel(1)),
                              IDX(3, dnac_p2c_mmix_col_gsel(0)) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("gsel_wrong_index", DNAC_P2C_MMIX_DEFECT_GSEL_ONEHOT, i, v, 2);
    }
    { /* 6c group selector on a compress row (row 1 routes no group). */
        const size_t i[1] = { IDX(1, dnac_p2c_mmix_col_gsel(0)) };
        const uint64_t v[1] = { 1 };
        n3_case("gsel_on_compress", DNAC_P2C_MMIX_DEFECT_GSEL_ONEHOT, i, v, 1);
    }
    { /* 7a step one-hot — a scheduled row with NO step (row 5). */
        const size_t i[1] = { IDX(5, dnac_p2c_mmix_col_pos(5)) };
        const uint64_t v[1] = { 0 };
        n3_case("pos_missing", DNAC_P2C_MMIX_DEFECT_POS_ONEHOT, i, v, 1);
    }
    { /* 7b step one-hot — a PADDING row claiming a step (row 7). */
        const size_t i[1] = { IDX(7, dnac_p2c_mmix_col_pos(0)) };
        const uint64_t v[1] = { 1 };
        n3_case("pos_on_padding", DNAC_P2C_MMIX_DEFECT_POS_ONEHOT, i, v, 1);
    }

    /* Validator argument fail-close. */
    dnac_p2c_mmix_table_defect_t d = DNAC_P2C_MMIX_DEFECT_NONE;
    CHECK(dnac_p2c_mmix_table_validate(ref, NULL, REF_ROWS, &d) ==
              DNAC_P2C_MMIX_TABLE_ERR_PARAM,
          "N3: validate(NULL cells)");
    CHECK(dnac_p2c_mmix_table_validate(NULL, g_good, REF_ROWS, &d) ==
              DNAC_P2C_MMIX_TABLE_ERR_PARAM,
          "N3: validate(NULL cfg)");
    CHECK(dnac_p2c_mmix_table_validate(ref, g_good, REF_ROWS - 1, &d) ==
              DNAC_P2C_MMIX_TABLE_ERR_PARAM,
          "N3: validate(wrong row count)");
    CHECK(dnac_p2c_mmix_table_validate(ref, g_good, REF_ROWS, NULL) ==
              DNAC_P2C_MMIX_TABLE_OK,
          "N3: validate(NULL defect out) on a clean table");
}

/* ==========================================================================
 * N4 — generator / cfg-gate fail-close
 * ======================================================================== */
static void n4_failclose(void)
{
    static uint64_t out[REF_CELLS];
    const dnac_p2c_mmix_table_cfg_t *ref = dnac_p2c_mmix_ref_cfg();

    CHECK(dnac_p2c_mmix_table_rows(NULL) == 0, "N4: rows(NULL) != 0");
    CHECK(dnac_p2c_mmix_num_groups(NULL) == 0, "N4: num_groups(NULL) != 0");
    CHECK(dnac_p2c_mmix_group_height(NULL, 0) == 0, "N4: group_height(NULL) != 0");
    CHECK(dnac_p2c_mmix_group_leaf_rows(NULL, 0) == 0,
          "N4: group_leaf_rows(NULL) != 0");
    CHECK(dnac_p2c_mmix_sched_rows(NULL) == 0, "N4: sched_rows(NULL) != 0");
    /* An out-of-range group index returns 0 (height / leaf rows). */
    CHECK(dnac_p2c_mmix_group_height(ref, 2) == 0,
          "N4: group_height(ref, 2) != 0 (only 2 groups)");
    CHECK(dnac_p2c_mmix_group_leaf_rows(ref, 2) == 0,
          "N4: group_leaf_rows(ref, 2) != 0");

    CHECK(dnac_p2c_mmix_table_generate(NULL, out, REF_CELLS) ==
              DNAC_P2C_MMIX_TABLE_ERR_PARAM,
          "N4: generate(NULL cfg)");
    CHECK(dnac_p2c_mmix_table_generate(ref, NULL, REF_CELLS) ==
              DNAC_P2C_MMIX_TABLE_ERR_PARAM,
          "N4: generate(NULL out)");
    CHECK(dnac_p2c_mmix_table_generate(ref, out, REF_CELLS - 1) ==
              DNAC_P2C_MMIX_TABLE_ERR_CAPACITY,
          "N4: generate(short buffer)");

    dnac_p2c_mmix_row_t rec;
    CHECK(dnac_p2c_mmix_table_row(ref, REF_ROWS, &rec) ==
              DNAC_P2C_MMIX_TABLE_ERR_PARAM,
          "N4: row(index == rows)");
    CHECK(dnac_p2c_mmix_table_row(ref, 0, NULL) ==
              DNAC_P2C_MMIX_TABLE_ERR_PARAM,
          "N4: row(NULL out)");

    /* Rejected cfgs. Height / width arrays declared so the gate can deref them. */
    static const size_t h_ok[2] = { 8, 2 };
    static const size_t w_ok[2] = { 1, 1 };
    static const size_t h_notpow2[2] = { 8, 3 };  /* 3 not a power of two */
    static const size_t h_single[1] = { 2 };
    static const size_t w_zero[2] = { 0, 1 };     /* width 0 */
    static const size_t w_big[1] = { 1000 };      /* leaf rows > MAX_STEPS */
    struct {
        const char                *what;
        dnac_p2c_mmix_table_cfg_t  cfg;
    } bad[] = {
        /* {num_matrices, widths, heights, depth, salt_elems} */
        { "num_matrices 0", { 0, w_ok, h_ok, 3, 2 } },
        { "widths NULL", { 2, NULL, h_ok, 3, 2 } },
        { "heights NULL", { 2, w_ok, NULL, 3, 2 } },
        { "num_matrices huge",
          { DNAC_P2C_MMIX_MAX_MATRICES + 1, w_ok, h_ok, 3, 2 } },
        { "salt huge", { 2, w_ok, h_ok, 3, DNAC_P2C_MMIX_MAX_SALT + 1 } },
        { "depth 0", { 2, w_ok, h_ok, 0, 2 } },
        { "depth huge", { 2, w_ok, h_ok, DNAC_P2C_MMIX_MAX_DEPTH + 1, 2 } },
        { "depth != log2(max_h)", { 2, w_ok, h_ok, 4, 2 } }, /* max_h 8 => 3 */
        { "height not pow2", { 2, w_ok, h_notpow2, 3, 2 } },
        { "width 0", { 2, w_zero, h_ok, 3, 2 } },
        { "n_sched overflow", { 1, w_big, h_single, 1, 0 } },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(dnac_p2c_mmix_table_rows(&bad[i].cfg) == 0, "N4: cfg '%s' ACCEPTED",
              bad[i].what);
        CHECK(dnac_p2c_mmix_table_generate(&bad[i].cfg, out, REF_CELLS) ==
                  DNAC_P2C_MMIX_TABLE_ERR_PARAM,
              "N4: generate(cfg '%s') did not fail closed", bad[i].what);
    }

    /* An ACCEPTED non-reference cfg still validates (the WIDE shape). */
    CHECK(dnac_p2c_mmix_table_rows(&WIDE_CFG) == WIDE_ROWS,
          "N4: WIDE cfg REJECTED");
    /* A degenerate SAME-HEIGHT cfg (no injection) is accepted: 2 matrices at
     * height 4, depth 2 => one group, no inject block. */
    static const size_t h_same[2] = { 4, 4 };
    static const size_t w_same[2] = { 1, 1 };
    const dnac_p2c_mmix_table_cfg_t same = { 2, w_same, h_same, 2, 2 };
    CHECK(dnac_p2c_mmix_num_groups(&same) == 1,
          "N4: same-height cfg groups != 1");
    /* leaf(g0): concat (1+2)+(1+2)=6 => ceil(6/4)=2; sched = 2 + 2(compress) +
     * 1(final) = 5; rows = next_pow2(6) = 8. */
    CHECK(dnac_p2c_mmix_sched_rows(&same) == 5, "N4: same-height sched %zu != 5",
          dnac_p2c_mmix_sched_rows(&same));
    CHECK(dnac_p2c_mmix_table_rows(&same) == 8, "N4: same-height rows != 8");
}

/* ==========================================================================
 * --print-root — the ORCHESTRATOR fills DNAC_P2C_MMIX_PREP_ROOT_LANE* from this
 * ======================================================================== */
static int print_root(void)
{
    static uint64_t t[REF_CELLS];
    uint64_t lanes[4];
    if (dnac_p2c_mmix_table_generate(dnac_p2c_mmix_ref_cfg(), t, REF_CELLS) !=
        DNAC_P2C_MMIX_TABLE_OK) {
        fprintf(stderr, "print-root: generate failed\n");
        return 1;
    }
    dnac_p2c_mmix_table_defect_t d = DNAC_P2C_MMIX_DEFECT_NONE;
    if (dnac_p2c_mmix_table_validate(dnac_p2c_mmix_ref_cfg(), t, REF_ROWS, &d) !=
        DNAC_P2C_MMIX_TABLE_OK) {
        fprintf(stderr, "print-root: the table FAILED its own validator "
                        "(defect %d) — refusing to print a root\n",
                (int)d);
        return 1;
    }
    if (!mmix_commit_table(t, REF_ROWS, lanes)) {
        fprintf(stderr, "print-root: LDE/commit pipeline failed\n");
        return 1;
    }
    printf("#define DNAC_P2C_MMIX_PREP_ROOT_LANE0 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[0]);
    printf("#define DNAC_P2C_MMIX_PREP_ROOT_LANE1 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[1]);
    printf("#define DNAC_P2C_MMIX_PREP_ROOT_LANE2 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[2]);
    printf("#define DNAC_P2C_MMIX_PREP_ROOT_LANE3 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[3]);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--print-root") == 0) {
        return print_root();
    }

    printf("P2b slice 2 PIN — mixed-height MMCS-verify preprocessed table\n");
    t1_determinism();
    t2_all();
    t3_pin_kat();
    n3_validator_negatives();
    n4_failclose();

    printf("\nmmcs_mixed_air_table total  %20d checks\n", g_checks);
    printf("mmcs_mixed_air_table failed %20d\n", g_fails);
    if (g_fails == 0) {
        printf("\nP2b slice 2 PIN GATE: GREEN\n");
        return 0;
    }
    fprintf(stderr, "\nP2b slice 2 PIN GATE: RED\n");
    return 1;
}
