/**
 * @file test_fri_oi_air_table.c
 * @brief P2c open_input PIN slice gate — the FRI reduced-opening accumulation
 *        AIR's preprocessed row-type table: deterministic generator, structural
 *        static validator, and the PIN-1-OI root constant (runtime KAT,
 *        shielded_domsep.h practice).
 *
 * Build spec: dnac/docs/plans/2026-07-29-p2c-oi-BUILDABLE-v3.md "Row schedule"
 * (:16-28), "Preprocessed columns" (:30-34), the C1..C6 forms (:50-108), the A2
 * second-witness negatives (:123-136). No AIR is built in this slice —
 * `fri_oi_air.{c,h}` is a later one. Mirrors the P2c fold-walk PIN gate
 * (tests/test_fri_air_table.c) one-for-one.
 *
 *   T1  generator determinism — the reference cfg and a WIDER shape, two runs
 *       each, byte-identical; shape accessors agree with the schedule numbers
 *   T2  schedule shape: chain + INTERLEAVED capture blocks (of different
 *       lengths) + DESCENDING accumulation groups + padding; the height and
 *       step one-hots; the G_j literals; the static validator accepts both cfgs
 *   T4  the lb-LESS (REF-proof-shaped) schedule, FLEET 029: a cfg with NO height
 *       at log_blowup generates, validates, and carries ZERO is_final_closeout
 *       rows; a hand-forged is_final_closeout on its last closeout is REJECTED
 *   T3  PIN-1-OI KAT: table -> coset LDE (bitrev) -> dnac_p2_mmcs_commit_mixed
 *       == DNAC_P2C_OI_PREP_ROOT, and the comparator accepts it.
 *       (Pin FILLED 2026-07-29 from `--print-root`; on a future re-pin the
 *       constant reverts to {0,0,0,0} and the four lane checks + the UNFILLED
 *       guard blocks below reactivate at compile time — RED by design then.)
 *   N1  comparator rejects a one-lane tamper / NULL (and the all-zero root while
 *       the pin is the placeholder)
 *   N2  the pin binds table CONTENTS: one flipped selector cell => another root
 *   N3  static-validator negatives — every check tripped exactly once, with
 *       exact defect isolation
 *   N4  generator / cfg-gate fail-close
 *
 * Usage:
 *   test_fri_oi_air_table                 run all gates
 *   test_fri_oi_air_table --print-root    print the reference table's four root
 *                                         lanes in DNAC_P2C_OI_PREP_ROOT_LANE*
 *                                         form (refuses on validator failure)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../fri_oi_air_table.h"
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

/* Compile-time pins — the module's local macros MUST equal the shipped
 * constants they mirror, so they cannot drift (the DNAC_P2C_PREP_LOG_BLOWUP
 * practice, test_fri_air_table.c:64-68). */
typedef char oi_blowup_pin_assert
    [(DNAC_P2C_OI_PREP_LOG_BLOWUP == (unsigned)DNAC_SHIELDED_FRI_LOG_BLOWUP) ? 1
                                                                            : -1];
typedef char oi_lgmh_bound_assert
    [(DNAC_P2C_OI_MAX_LGMH == (size_t)GOLDILOCKS_TWO_ADICITY) ? 1 : -1];
/* Column layout: the nine 0/1 flags occupy [0, NUM_FLAG_COLS), the g_pow2 field
 * literal sits immediately after, then the height one-hot, then the step
 * one-hot — total 106. The validator's booleanity pass skips EXACTLY the g_pow2
 * column, so a re-ordering that broke this would silently stop checking a
 * flag. */
typedef char oi_layout_assert
    [(DNAC_P2C_OI_COL_G_POW2 == (int)DNAC_P2C_OI_NUM_FLAG_COLS &&
      DNAC_P2C_OI_COL_HSEL_OFF == DNAC_P2C_OI_COL_G_POW2 + 1 &&
      DNAC_P2C_OI_COL_POS_OFF == (size_t)42 &&
      DNAC_P2C_OI_TABLE_COLS == (size_t)106)
         ? 1
         : -1];
/* Heights subset [lb, lgmh], lgmh <= 32 => at most 31 distinct heights; the
 * one-hot must be able to carry them. */
typedef char oi_heights_bound_assert
    [(DNAC_P2C_OI_MAX_HEIGHTS >= (size_t)31) ? 1 : -1];
/* The reference cfg is the shipped-blowup-compatible small mechanism shape. */
typedef char oi_ref_shape_assert
    [(DNAC_P2C_OI_REF_LOG_BLOWUP == DNAC_SHIELDED_FRI_LOG_BLOWUP &&
      DNAC_P2C_OI_REF_ROWS == (size_t)16 && DNAC_P2C_OI_REF_SCHED == (size_t)14)
         ? 1
         : -1];

#define OI_COLS ((size_t)DNAC_P2C_OI_TABLE_COLS)         /* 106  */
#define REF_ROWS DNAC_P2C_OI_REF_ROWS                    /* 16   */
#define REF_CELLS (REF_ROWS * OI_COLS)                   /* 1696 */
#define WIDE_ROWS ((size_t)32)                           /* lgmh 6, 3 heights */
#define WIDE_CELLS (WIDE_ROWS * OI_COLS)                 /* 3392 */
#define MAX_COMMIT_ROWS ((size_t)32)
#define MAX_LDE_CELLS ((MAX_COMMIT_ROWS << DNAC_P2C_OI_PREP_LOG_BLOWUP) * OI_COLS)

/* The WIDER shape (NOT reference-cfg-shaped): lgmh 6, H = {6, 4, 2}, lb = 2,
 * each height {1 batch, 1 matrix, 1 point, 2 columns} => 2 acc rows per group.
 * chain 6 + captures (cum 0/2/4 => 2+4+6 = 12) + groups (3 * (2+1) = 9) = 27
 * scheduled, 32 rows. NO root is pinned for it — it exists to prove the
 * generator and validator are not reference-cfg-shaped. */
static const dnac_p2c_oi_height_desc_t WIDE_HEIGHTS[3] = {
    { 6, 1, 1, 1, 2 }, { 4, 1, 1, 1, 2 }, { 2, 1, 1, 1, 2 }
};
static const dnac_p2c_oi_table_cfg_t WIDE_CFG = { 6, 2, 3, WIDE_HEIGHTS, 100 };

/* The REF-PROOF-SHAPED cfg (FLEET 029): lgmh 5, lb = 2, H = {5, 4} — NO height
 * AT lb. A real inner proof never opens a matrix at log_height == log_blowup (it
 * would be a degree-0 polynomial), so the schedule may not REQUIRE one; the
 * native lb-zero rule is CONDITIONAL on such a height existing
 * (fri_verifier.c:482-487). Structural expectation: NO is_final_closeout row.
 *   chain 5 + captures (cum 0 / 1 => 2 + 3 = 5) + groups (2 * (1+1) = 4)
 *   = 14 scheduled, 16 rows.
 * NO root is pinned for it (the PIN-1-OI reference cfg is unchanged). */
static const dnac_p2c_oi_height_desc_t NOLB_HEIGHTS[2] = {
    { 5, 1, 1, 1, 1 }, { 4, 1, 1, 1, 1 }
};
static const dnac_p2c_oi_table_cfg_t NOLB_CFG = { 5, 2, 2, NOLB_HEIGHTS, 100 };

/* Same shape with TWO batches on the LAST (h = 4) group, so that group HAS a
 * per-batch boundary. If the generator still equated "last group" with "the lb
 * group", this cfg would carry a final closeout / an lb-zero step; it must not.
 *   groups (1+1) + (2+1) = 5 => 15 scheduled, 16 rows. */
static const dnac_p2c_oi_height_desc_t NOLB_MB_HEIGHTS[2] = {
    { 5, 1, 1, 1, 1 }, { 4, 2, 1, 1, 1 }
};
static const dnac_p2c_oi_table_cfg_t NOLB_MB_CFG = { 5, 2, 2, NOLB_MB_HEIGHTS,
                                                     100 };

/* ==========================================================================
 * Shared helper: the SHIPPED preprocessed-commit pipeline
 * (batch_prover.c:807-825 with is_zk = 0: coset LDE bit-reversed at
 * log_blowup, then ONE mixed-height Poseidon2 MMCS commit).
 * ======================================================================== */
static int oi_commit_table(const uint64_t *table, size_t rows,
                           uint64_t out_lanes[4])
{
    static uint64_t lde[MAX_LDE_CELLS];
    const size_t lde_rows = rows << DNAC_P2C_OI_PREP_LOG_BLOWUP;
    if (lde_rows * OI_COLS > MAX_LDE_CELLS) return 0;

    if (dnac_prover_coset_lde_bitrev(table, rows, OI_COLS,
                                     DNAC_P2C_OI_PREP_LOG_BLOWUP,
                                     GOLDILOCKS_GENERATOR,
                                     lde) != DNAC_PROVER_OK) {
        return 0;
    }
    const uint64_t *mats[1] = { lde };
    const size_t widths[1] = { OI_COLS };
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
    const dnac_p2c_oi_table_cfg_t *ref = dnac_p2c_oi_ref_cfg();

    CHECK(dnac_p2c_oi_chain_rows(ref) == 4, "T1: ref chain rows %zu != 4",
          dnac_p2c_oi_chain_rows(ref));
    CHECK(dnac_p2c_oi_capture_rows(ref) == 6, "T1: ref capture rows %zu != 6",
          dnac_p2c_oi_capture_rows(ref));
    CHECK(dnac_p2c_oi_group_rows(ref) == 4, "T1: ref group rows %zu != 4",
          dnac_p2c_oi_group_rows(ref));
    CHECK(dnac_p2c_oi_sched_rows(ref) == DNAC_P2C_OI_REF_SCHED,
          "T1: ref sched %zu != %zu", dnac_p2c_oi_sched_rows(ref),
          (size_t)DNAC_P2C_OI_REF_SCHED);
    CHECK(dnac_p2c_oi_table_rows(ref) == REF_ROWS, "T1: ref rows %zu != %zu",
          dnac_p2c_oi_table_rows(ref), (size_t)REF_ROWS);

    CHECK(dnac_p2c_oi_table_generate(ref, a, REF_CELLS) == DNAC_P2C_OI_TABLE_OK,
          "T1: ref generate #1");
    CHECK(dnac_p2c_oi_table_generate(ref, b, REF_CELLS) == DNAC_P2C_OI_TABLE_OK,
          "T1: ref generate #2");
    CHECK(memcmp(a, b, sizeof(a)) == 0, "T1: ref table NOT deterministic");

    static uint64_t c[WIDE_CELLS], d[WIDE_CELLS];
    CHECK(dnac_p2c_oi_chain_rows(&WIDE_CFG) == 6, "T1: wide chain rows %zu != 6",
          dnac_p2c_oi_chain_rows(&WIDE_CFG));
    CHECK(dnac_p2c_oi_capture_rows(&WIDE_CFG) == 12,
          "T1: wide capture rows %zu != 12", dnac_p2c_oi_capture_rows(&WIDE_CFG));
    CHECK(dnac_p2c_oi_group_rows(&WIDE_CFG) == 9, "T1: wide group rows %zu != 9",
          dnac_p2c_oi_group_rows(&WIDE_CFG));
    CHECK(dnac_p2c_oi_table_rows(&WIDE_CFG) == WIDE_ROWS,
          "T1: wide rows %zu != %zu", dnac_p2c_oi_table_rows(&WIDE_CFG),
          WIDE_ROWS);
    CHECK(dnac_p2c_oi_table_generate(&WIDE_CFG, c, WIDE_CELLS) ==
              DNAC_P2C_OI_TABLE_OK,
          "T1: wide generate #1");
    CHECK(dnac_p2c_oi_table_generate(&WIDE_CFG, d, WIDE_CELLS) ==
              DNAC_P2C_OI_TABLE_OK,
          "T1: wide generate #2");
    CHECK(memcmp(c, d, sizeof(c)) == 0, "T1: wide table NOT deterministic");

    /* Genuinely different tables — otherwise "deterministic" would be a claim
     * about one table printed twice. */
    CHECK(memcmp(a, c, REF_CELLS * sizeof(uint64_t)) != 0,
          "T1: reference and wide tables are byte-identical");
}

/* ==========================================================================
 * T2 — schedule shape + the static validator on both cfgs
 * ======================================================================== */
static void t2_shape(const dnac_p2c_oi_table_cfg_t *cfg, const char *name,
                     size_t exp_chain, size_t exp_capture, size_t exp_group,
                     size_t exp_rows)
{
    static uint64_t t[WIDE_CELLS];
    const size_t rows = dnac_p2c_oi_table_rows(cfg);
    if (rows != exp_rows ||
        dnac_p2c_oi_table_generate(cfg, t, WIDE_CELLS) != DNAC_P2C_OI_TABLE_OK) {
        CHECK(0, "T2[%s]: generate failed (rows %zu, want %zu)", name, rows,
              exp_rows);
        return;
    }
    const size_t sched = exp_chain + exp_capture + exp_group;

    size_t n_chain = 0, n_capture = 0, n_acc = 0, n_closeout = 0, n_pad = 0;
    size_t n_group_start = 0, n_final = 0;
    size_t chain_j = 0; /* chain INDEX — chain rows are non-contiguous (captures
                         * interleave), so G_j uses this, not the table row. */
    int exclusive_ok = 1, boolean_ok = 1, onehot_ok = 1, hsel_ok = 1,
        gpow2_ok = 1;

    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &t[r * OI_COLS];

        for (size_t k = 0; k < OI_COLS; k++) {
            if (row[k] >= GOLDILOCKS_P) boolean_ok = 0;
            if (k != (size_t)DNAC_P2C_OI_COL_G_POW2 && row[k] > 1) boolean_ok = 0;
        }

        const uint64_t set = row[DNAC_P2C_OI_COL_IS_CHAIN] +
                             row[DNAC_P2C_OI_COL_IS_CAPTURE] +
                             row[DNAC_P2C_OI_COL_IS_ACC] +
                             row[DNAC_P2C_OI_COL_IS_CLOSEOUT] +
                             row[DNAC_P2C_OI_COL_IS_PAD];
        if (set != 1) exclusive_ok = 0;

        n_chain += (size_t)row[DNAC_P2C_OI_COL_IS_CHAIN];
        n_capture += (size_t)row[DNAC_P2C_OI_COL_IS_CAPTURE];
        n_acc += (size_t)row[DNAC_P2C_OI_COL_IS_ACC];
        n_closeout += (size_t)row[DNAC_P2C_OI_COL_IS_CLOSEOUT];
        n_pad += (size_t)row[DNAC_P2C_OI_COL_IS_PAD];
        n_group_start += (size_t)row[DNAC_P2C_OI_COL_IS_GROUP_START];
        n_final += (size_t)row[DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT];

        /* g_pow2 on chain INDEX j is G_j = g_lgmh^{2^j} = g_{lgmh-j}; 0
         * elsewhere. j counts chain rows seen (NOT the table row r). */
        if (row[DNAC_P2C_OI_COL_IS_CHAIN]) {
            const uint64_t want = gold_fp_to_u64(
                gold_fp_two_adic_generator((unsigned)(cfg->lgmh - chain_j)));
            if (row[DNAC_P2C_OI_COL_G_POW2] != want) gpow2_ok = 0;
            chain_j++;
        } else if (row[DNAC_P2C_OI_COL_G_POW2] != 0) {
            gpow2_ok = 0;
        }

        /* Each scheduled row carries exactly one step (== its row index);
         * padding carries none. */
        for (size_t k = 0; k < DNAC_P2C_OI_MAX_STEPS; k++) {
            const uint64_t want = (r < sched && k == r) ? 1u : 0u;
            if (row[dnac_p2c_oi_col_pos(k)] != want) onehot_ok = 0;
        }
        /* At most one height selector is set (routing rows only). */
        size_t hs = 0;
        for (size_t i = 0; i < DNAC_P2C_OI_MAX_HEIGHTS; i++) {
            hs += (size_t)row[dnac_p2c_oi_col_hsel(i)];
        }
        const int routes = (int)(row[DNAC_P2C_OI_COL_IS_CAPTURE] ||
                                 row[DNAC_P2C_OI_COL_IS_ACC] ||
                                 row[DNAC_P2C_OI_COL_IS_CLOSEOUT]);
        if (hs != (size_t)(routes ? 1 : 0)) hsel_ok = 0;
    }

    CHECK(n_chain == exp_chain, "T2[%s]: chain rows %zu != %zu", name, n_chain,
          exp_chain);
    CHECK(n_capture == exp_capture, "T2[%s]: capture rows %zu != %zu", name,
          n_capture, exp_capture);
    CHECK(n_acc + n_closeout == exp_group, "T2[%s]: group rows %zu != %zu", name,
          n_acc + n_closeout, exp_group);
    CHECK(n_closeout == cfg->num_heights, "T2[%s]: closeouts %zu != %zu", name,
          n_closeout, cfg->num_heights);
    CHECK(n_group_start == cfg->num_heights, "T2[%s]: group starts %zu != %zu",
          name, n_group_start, cfg->num_heights);
    /* is_final_closeout is CONDITIONAL (FLEET 029): exactly one iff some height
     * equals lb; NONE otherwise — the native's conditional lb-zero rule
     * (fri_verifier.c:482-487), never a schedule requirement. */
    size_t exp_final = 0;
    for (size_t i = 0; i < cfg->num_heights; i++) {
        if (cfg->heights[i].log_height == cfg->log_blowup) exp_final = 1;
    }
    CHECK(n_final == exp_final, "T2[%s]: is_final_closeout count %zu != %zu",
          name, n_final, exp_final);
    CHECK(n_pad == rows - sched && n_pad >= 1,
          "T2[%s]: padding rows %zu != %zu (>=1)", name, n_pad, rows - sched);
    CHECK(exclusive_ok, "T2[%s]: a row carries != 1 primary type", name);
    CHECK(boolean_ok, "T2[%s]: a cell is non-boolean or non-canonical", name);
    CHECK(onehot_ok, "T2[%s]: step one-hot wrong", name);
    CHECK(hsel_ok, "T2[%s]: height one-hot wrong", name);
    CHECK(gpow2_ok, "T2[%s]: g_pow2 literal wrong", name);

    /* The LAST row is padding (terminality gate). */
    CHECK(t[(rows - 1) * OI_COLS + DNAC_P2C_OI_COL_IS_PAD] == 1,
          "T2[%s]: last row is not padding", name);

    /* The row record and the cells must agree. */
    int record_ok = 1;
    for (size_t r = 0; r < rows; r++) {
        dnac_p2c_oi_row_t rec;
        if (dnac_p2c_oi_table_row(cfg, r, &rec) != DNAC_P2C_OI_TABLE_OK) {
            record_ok = 0;
            break;
        }
        const uint64_t *row = &t[r * OI_COLS];
        const uint64_t prim =
            (rec.type == DNAC_P2C_OI_ROW_CHAIN) ? row[DNAC_P2C_OI_COL_IS_CHAIN]
            : (rec.type == DNAC_P2C_OI_ROW_CAPTURE)
                ? row[DNAC_P2C_OI_COL_IS_CAPTURE]
            : (rec.type == DNAC_P2C_OI_ROW_ACC) ? row[DNAC_P2C_OI_COL_IS_ACC]
            : (rec.type == DNAC_P2C_OI_ROW_CLOSEOUT)
                ? row[DNAC_P2C_OI_COL_IS_CLOSEOUT]
                : row[DNAC_P2C_OI_COL_IS_PAD];
        if (prim != 1 ||
            row[DNAC_P2C_OI_COL_IS_SQPAIR] != (uint64_t)rec.is_sqpair ||
            row[DNAC_P2C_OI_COL_IS_STORE] != (uint64_t)rec.is_store ||
            row[DNAC_P2C_OI_COL_IS_GROUP_START] !=
                (uint64_t)rec.is_group_start ||
            row[DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT] !=
                (uint64_t)rec.is_final_closeout ||
            row[DNAC_P2C_OI_COL_G_POW2] != rec.g_pow2) {
            record_ok = 0;
            break;
        }
        if (rec.h_index != (size_t)-1 &&
            row[dnac_p2c_oi_col_hsel(rec.h_index)] != 1) {
            record_ok = 0;
            break;
        }
    }
    CHECK(record_ok, "T2[%s]: row record disagrees with the cells", name);

    dnac_p2c_oi_table_defect_t defect = DNAC_P2C_OI_DEFECT_NONE;
    CHECK(dnac_p2c_oi_table_validate(cfg, t, rows, &defect) ==
              DNAC_P2C_OI_TABLE_OK,
          "T2[%s]: validator REJECTED the generated table (defect %d)", name,
          (int)defect);
    CHECK(defect == DNAC_P2C_OI_DEFECT_NONE, "T2[%s]: defect %d on a clean table",
          name, (int)defect);
}

static void t2_hand_layout(void)
{
    /* Reference layout (fri_oi_air_table.h): the two capture blocks have
     * DIFFERENT lengths, interleaved between the chain rows. Hand-check the
     * load-bearing rows. */
    static uint64_t t[REF_CELLS];
    const dnac_p2c_oi_table_cfg_t *ref = dnac_p2c_oi_ref_cfg();
    if (dnac_p2c_oi_table_generate(ref, t, REF_CELLS) != DNAC_P2C_OI_TABLE_OK) {
        CHECK(0, "T2hand: generate failed");
        return;
    }
#define AT(row, col) (t[(size_t)(row) * OI_COLS + (size_t)(col)])
    /* row 2 : capture h=2 SEED (h_sel[1], no sub-flag) */
    CHECK(AT(2, DNAC_P2C_OI_COL_IS_CAPTURE) == 1 &&
              AT(2, DNAC_P2C_OI_COL_IS_SQPAIR) == 0 &&
              AT(2, DNAC_P2C_OI_COL_IS_STORE) == 0 &&
              AT(2, dnac_p2c_oi_col_hsel(1)) == 1,
          "T2hand: row 2 not the h=2 seed row");
    /* rows 3,4 : capture h=2 squarings (cum_2 = 2) */
    CHECK(AT(3, DNAC_P2C_OI_COL_IS_SQPAIR) == 1 &&
              AT(4, DNAC_P2C_OI_COL_IS_SQPAIR) == 1,
          "T2hand: rows 3,4 not the h=2 squarings");
    /* row 5 : capture h=2 STORE */
    CHECK(AT(5, DNAC_P2C_OI_COL_IS_STORE) == 1, "T2hand: row 5 not the store");
    /* row 8 : capture h=4 SEED (cum_4 = 0 => block is seed,store only) */
    CHECK(AT(8, DNAC_P2C_OI_COL_IS_CAPTURE) == 1 &&
              AT(8, DNAC_P2C_OI_COL_IS_SQPAIR) == 0 &&
              AT(8, dnac_p2c_oi_col_hsel(0)) == 1,
          "T2hand: row 8 not the h=4 seed row");
    CHECK(AT(9, DNAC_P2C_OI_COL_IS_STORE) == 1 &&
              AT(9, dnac_p2c_oi_col_hsel(0)) == 1,
          "T2hand: row 9 not the h=4 store");
    /* row 10 : group0 (h=4) FIRST acc row */
    CHECK(AT(10, DNAC_P2C_OI_COL_IS_ACC) == 1 &&
              AT(10, DNAC_P2C_OI_COL_IS_GROUP_START) == 1 &&
              AT(10, dnac_p2c_oi_col_hsel(0)) == 1,
          "T2hand: row 10 not the group0 start");
    /* row 11 : group0 closeout, NOT final (h=4 != lb=2) */
    CHECK(AT(11, DNAC_P2C_OI_COL_IS_CLOSEOUT) == 1 &&
              AT(11, DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT) == 0,
          "T2hand: row 11 not the non-final group0 closeout");
    /* row 12 : group1 (h=2) FIRST acc row */
    CHECK(AT(12, DNAC_P2C_OI_COL_IS_ACC) == 1 &&
              AT(12, DNAC_P2C_OI_COL_IS_GROUP_START) == 1 &&
              AT(12, dnac_p2c_oi_col_hsel(1)) == 1,
          "T2hand: row 12 not the group1 start");
    /* row 13 : group1 closeout, FINAL (h=2 == lb) */
    CHECK(AT(13, DNAC_P2C_OI_COL_IS_CLOSEOUT) == 1 &&
              AT(13, DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT) == 1,
          "T2hand: row 13 not the FINAL group1 closeout");
    /* rows 14,15 : padding */
    CHECK(AT(14, DNAC_P2C_OI_COL_IS_PAD) == 1 &&
              AT(15, DNAC_P2C_OI_COL_IS_PAD) == 1,
          "T2hand: rows 14,15 not padding");
#undef AT
}

/* ==========================================================================
 * T4 — the lb-LESS (REF-proof-shaped) schedule: structure + the forged
 *      final-closeout negative (FLEET 029)
 * ======================================================================== */

/** Table row index of the closeout of descending-H index `hidx`, or SIZE_MAX. */
static size_t oi_closeout_row(const dnac_p2c_oi_table_cfg_t *cfg, size_t hidx)
{
    const size_t rows = dnac_p2c_oi_table_rows(cfg);
    for (size_t r = 0; r < rows; r++) {
        dnac_p2c_oi_row_t rec;
        if (dnac_p2c_oi_table_row(cfg, r, &rec) != DNAC_P2C_OI_TABLE_OK) break;
        if (rec.type == DNAC_P2C_OI_ROW_CLOSEOUT && rec.h_index == hidx) return r;
    }
    return (size_t)-1;
}

static void t4_nolb(const dnac_p2c_oi_table_cfg_t *cfg, const char *name,
                    size_t exp_rows, size_t exp_sched)
{
    static uint64_t t[WIDE_CELLS];
    const size_t rows = dnac_p2c_oi_table_rows(cfg);
    CHECK(rows == exp_rows, "T4[%s]: rows %zu != %zu (cfg REJECTED?)", name, rows,
          exp_rows);
    CHECK(dnac_p2c_oi_sched_rows(cfg) == exp_sched, "T4[%s]: sched %zu != %zu",
          name, dnac_p2c_oi_sched_rows(cfg), exp_sched);
    if (rows != exp_rows ||
        dnac_p2c_oi_table_generate(cfg, t, WIDE_CELLS) != DNAC_P2C_OI_TABLE_OK) {
        CHECK(0, "T4[%s]: generate failed", name);
        return;
    }

    /* NO row carries is_final_closeout — C4b is vacuous on this schedule. */
    size_t n_fc = 0, n_close = 0;
    for (size_t r = 0; r < rows; r++) {
        n_fc += (size_t)t[r * OI_COLS + DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT];
        n_close += (size_t)t[r * OI_COLS + DNAC_P2C_OI_COL_IS_CLOSEOUT];
    }
    CHECK(n_close == cfg->num_heights, "T4[%s]: closeouts %zu != %zu", name,
          n_close, cfg->num_heights);
    CHECK(n_fc == 0, "T4[%s]: %zu is_final_closeout rows on an lb-LESS schedule",
          name, n_fc);

    dnac_p2c_oi_table_defect_t d = DNAC_P2C_OI_DEFECT_NONE;
    CHECK(dnac_p2c_oi_table_validate(cfg, t, rows, &d) == DNAC_P2C_OI_TABLE_OK,
          "T4[%s]: validator REJECTED the lb-less table (defect %d)", name,
          (int)d);

    /* NEGATIVE — a hand-made table with a FORGED is_final_closeout on the last
     * group's closeout. C4b would then force that group's ro to 0, i.e. a
     * DIFFERENT (and wrong) statement; the validator must reject it. */
    const size_t clo = oi_closeout_row(cfg, cfg->num_heights - 1);
    CHECK(clo != (size_t)-1, "T4[%s]: no closeout row found", name);
    if (clo != (size_t)-1) {
        t[clo * OI_COLS + DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT] = 1;
        d = DNAC_P2C_OI_DEFECT_NONE;
        CHECK(dnac_p2c_oi_table_validate(cfg, t, rows, &d) ==
                  DNAC_P2C_OI_TABLE_ERR_SCHEDULE,
              "T4[%s]: validator ACCEPTED a forged is_final_closeout", name);
        CHECK(d == DNAC_P2C_OI_DEFECT_FINAL_CLOSEOUT,
              "T4[%s]: defect %d != FINAL_CLOSEOUT", name, (int)d);
    }
}

static void t2_all(void)
{
    /* ref: chain 4, capture 6, group 4, 16 rows. */
    t2_shape(dnac_p2c_oi_ref_cfg(), "ref", 4, 6, 4, REF_ROWS);
    /* wide: chain 6, capture 12, group 9, 32 rows. */
    t2_shape(&WIDE_CFG, "wide", 6, 12, 9, WIDE_ROWS);
    /* nolb: chain 5, capture 5, group 4, 16 rows — NO lb height. */
    t2_shape(&NOLB_CFG, "nolb", 5, 5, 4, (size_t)16);
    /* nolb_mb: chain 5, capture 5, group 5 (last group 2 batches), 16 rows. */
    t2_shape(&NOLB_MB_CFG, "nolb_mb", 5, 5, 5, (size_t)16);
    t2_hand_layout();
    t4_nolb(&NOLB_CFG, "nolb", 16, 14);
    t4_nolb(&NOLB_MB_CFG, "nolb_mb", 16, 15);
}

/* ==========================================================================
 * T3 — PIN-1-OI KAT + N1 + N2
 * ======================================================================== */
static void t3_pin_kat(void)
{
    static uint64_t t[REF_CELLS];
    const dnac_p2c_oi_table_cfg_t *ref = dnac_p2c_oi_ref_cfg();
    if (dnac_p2c_oi_table_generate(ref, t, REF_CELLS) != DNAC_P2C_OI_TABLE_OK) {
        CHECK(0, "T3: generate failed");
        return;
    }

    uint64_t lanes[4];
    if (!oi_commit_table(t, REF_ROWS, lanes)) {
        CHECK(0, "T3: LDE/commit pipeline failed");
        return;
    }
    printf("  PIN-1-OI derived root = { 0x%016" PRIx64 ", 0x%016" PRIx64
           ", 0x%016" PRIx64 ", 0x%016" PRIx64 " }\n",
           lanes[0], lanes[1], lanes[2], lanes[3]);
    if (DNAC_P2C_OI_PREP_ROOT_UNFILLED) {
        fprintf(stderr,
                "  NOTE: DNAC_P2C_OI_PREP_ROOT is still the PLACEHOLDER "
                "{0,0,0,0}.\n        The four T3 lane checks below FAIL BY "
                "DESIGN until it is filled\n        from `--print-root`. Do "
                "not hand-edit the constant to silence them.\n");
    }

    static const uint64_t pinned[4] = DNAC_P2C_OI_PREP_ROOT;
    for (int k = 0; k < 4; k++) {
        CHECK(lanes[k] == pinned[k],
              "T3: PIN-1-OI lane %d: derived 0x%016" PRIx64
              " != pinned 0x%016" PRIx64,
              k, lanes[k], pinned[k]);
    }
    CHECK(dnac_p2c_oi_prep_root_check(lanes) == DNAC_P2C_OI_TABLE_OK,
          "T3: comparator rejected the derived root");

    /* N1 — one tampered lane, and NULL. */
    for (int k = 0; k < 4; k++) {
        uint64_t bad[4];
        memcpy(bad, lanes, sizeof(bad));
        bad[k] ^= 1;
        CHECK(dnac_p2c_oi_prep_root_check(bad) ==
                  DNAC_P2C_OI_TABLE_ERR_ROOT_MISMATCH,
              "N1: comparator accepted a tampered lane %d", k);
    }
    CHECK(dnac_p2c_oi_prep_root_check(NULL) == DNAC_P2C_OI_TABLE_ERR_PARAM,
          "N1: comparator on NULL must be PARAM");
    if (DNAC_P2C_OI_PREP_ROOT_UNFILLED) {
        /* An unfilled pin must reject even the all-zero root it would otherwise
         * match. This block disappears the moment the constant is filled. */
        const uint64_t zero[4] = { 0, 0, 0, 0 };
        CHECK(dnac_p2c_oi_prep_root_check(zero) ==
                  DNAC_P2C_OI_TABLE_ERR_ROOT_MISMATCH,
              "N1: PLACEHOLDER pin ACCEPTED an all-zero root");
    }

    /* N2 — the pin binds CONTENTS: clear the group0 is_group_start selector (a
     * vacuity attack shape — C3a's alpha_pow==1/ro==0 boundary would never
     * fire) and re-run the SAME pipeline. Everything else is byte-identical. */
    static uint64_t tampered[REF_CELLS];
    memcpy(tampered, t, sizeof(tampered));
    size_t gs_row = (size_t)-1;
    for (size_t r = 0; r < REF_ROWS; r++) {
        if (tampered[r * OI_COLS + DNAC_P2C_OI_COL_IS_GROUP_START] == 1) {
            gs_row = r;
            break;
        }
    }
    CHECK(gs_row != (size_t)-1, "N2: no is_group_start row to tamper");
    if (gs_row != (size_t)-1) {
        tampered[gs_row * OI_COLS + DNAC_P2C_OI_COL_IS_GROUP_START] = 0;
        CHECK(memcmp(tampered, t, sizeof(t)) != 0,
              "N2: tamper did not change the table");
        uint64_t bad_lanes[4];
        if (oi_commit_table(tampered, REF_ROWS, bad_lanes)) {
            CHECK(memcmp(bad_lanes, lanes, sizeof(lanes)) != 0,
                  "N2: a flipped selector cell produced the SAME root");
        } else {
            CHECK(0, "N2: LDE/commit pipeline failed on the tampered table");
        }
        dnac_p2c_oi_table_defect_t d = DNAC_P2C_OI_DEFECT_NONE;
        CHECK(dnac_p2c_oi_table_validate(ref, tampered, REF_ROWS, &d) ==
                  DNAC_P2C_OI_TABLE_ERR_SCHEDULE,
              "N2: validator accepted the cleared is_group_start");
        CHECK(d == DNAC_P2C_OI_DEFECT_GROUP_START,
              "N2: defect %d != GROUP_START", (int)d);
    }
}

/* ==========================================================================
 * N3 — static-validator negatives, one check tripped per tamper
 *
 * Every mutation starts from the CLEAN reference table, so a mutation that
 * accidentally tripped an earlier check would show up as the wrong defect code,
 * not as a silent pass (exact-count isolation).
 * ======================================================================== */
static uint64_t g_good[REF_CELLS];

static void n3_case(const char *what, dnac_p2c_oi_table_defect_t want,
                    const size_t *cells_idx, const uint64_t *vals, size_t n)
{
    static uint64_t t[REF_CELLS];
    memcpy(t, g_good, sizeof(t));
    for (size_t i = 0; i < n; i++) t[cells_idx[i]] = vals[i];

    dnac_p2c_oi_table_defect_t got = DNAC_P2C_OI_DEFECT_NONE;
    const dnac_p2c_oi_table_status_t st =
        dnac_p2c_oi_table_validate(dnac_p2c_oi_ref_cfg(), t, REF_ROWS, &got);
    CHECK(st == DNAC_P2C_OI_TABLE_ERR_SCHEDULE, "N3[%s]: validator returned %d",
          what, (int)st);
    CHECK(got == want, "N3[%s]: defect %d != %d", what, (int)got, (int)want);
}

#define IDX(row, col) ((size_t)((row) * OI_COLS + (col)))

static void n3_validator_negatives(void)
{
    const dnac_p2c_oi_table_cfg_t *ref = dnac_p2c_oi_ref_cfg();
    if (dnac_p2c_oi_table_generate(ref, g_good, REF_CELLS) !=
        DNAC_P2C_OI_TABLE_OK) {
        CHECK(0, "N3: reference generate failed");
        return;
    }

    { /* 1 canonicality — a cell at exactly p aliases to 0 mod p. */
        const size_t i[1] = { IDX(0, DNAC_P2C_OI_COL_IS_CHAIN) };
        const uint64_t v[1] = { GOLDILOCKS_P };
        n3_case("canonical", DNAC_P2C_OI_DEFECT_CANONICAL, i, v, 1);
    }
    { /* 2 booleanity — runs BEFORE exclusivity, so a `2` trips boolean. */
        const size_t i[1] = { IDX(0, DNAC_P2C_OI_COL_IS_CHAIN) };
        const uint64_t v[1] = { 2 };
        n3_case("boolean", DNAC_P2C_OI_DEFECT_BOOLEAN, i, v, 1);
    }
    { /* 3 type exclusivity — a row claiming two primary types. */
        const size_t i[1] = { IDX(0, DNAC_P2C_OI_COL_IS_CAPTURE) };
        const uint64_t v[1] = { 1 };
        n3_case("type_exclusive", DNAC_P2C_OI_DEFECT_TYPE_EXCLUSIVE, i, v, 1);
    }
    { /* 4 primary schedule — RETYPE row 0 (chain -> capture): exactly one
       *   primary set, but the wrong one for that position. */
        const size_t i[2] = { IDX(0, DNAC_P2C_OI_COL_IS_CHAIN),
                              IDX(0, DNAC_P2C_OI_COL_IS_CAPTURE) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("primary_schedule", DNAC_P2C_OI_DEFECT_PRIMARY_SCHEDULE, i, v, 2);
    }
    { /* 5a capture sub-flag — clear a squaring on the h=2 block (row 3). */
        const size_t i[1] = { IDX(3, DNAC_P2C_OI_COL_IS_SQPAIR) };
        const uint64_t v[1] = { 0 };
        n3_case("capture_sq_cleared", DNAC_P2C_OI_DEFECT_CAPTURE, i, v, 1);
    }
    { /* 5b capture sub-flag — a squaring flag on a NON-capture (chain) row. */
        const size_t i[1] = { IDX(0, DNAC_P2C_OI_COL_IS_SQPAIR) };
        const uint64_t v[1] = { 1 };
        n3_case("sq_off_capture", DNAC_P2C_OI_DEFECT_CAPTURE, i, v, 1);
    }
    { /* 5c capture sub-flag — the store moved off the store row (row 5 -> 4). */
        const size_t i[2] = { IDX(5, DNAC_P2C_OI_COL_IS_STORE),
                              IDX(4, DNAC_P2C_OI_COL_IS_STORE) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("store_moved", DNAC_P2C_OI_DEFECT_CAPTURE, i, v, 2);
    }
    { /* 6a group start cleared — C3a's ROW-LOCAL boundary would never gate. */
        const size_t i[1] = { IDX(10, DNAC_P2C_OI_COL_IS_GROUP_START) };
        const uint64_t v[1] = { 0 };
        n3_case("group_start_cleared", DNAC_P2C_OI_DEFECT_GROUP_START, i, v, 1);
    }
    { /* 6b group start on a non-first acc row (row 12 already is a start;
       *   put one on the group1 closeout's acc? group1 has ONE acc row, so
       *   instead add a spurious start on a chain row's acc... use row 11 (a
       *   closeout) -> not acc, exp group_start 0). */
        const size_t i[1] = { IDX(11, DNAC_P2C_OI_COL_IS_GROUP_START) };
        const uint64_t v[1] = { 1 };
        n3_case("group_start_spurious", DNAC_P2C_OI_DEFECT_GROUP_START, i, v, 1);
    }
    { /* 7a final closeout set on the NON-final closeout (row 11, h=4). */
        const size_t i[1] = { IDX(11, DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT) };
        const uint64_t v[1] = { 1 };
        n3_case("final_on_nonfinal", DNAC_P2C_OI_DEFECT_FINAL_CLOSEOUT, i, v, 1);
    }
    { /* 7b final closeout cleared on the FINAL closeout (row 13, h=2==lb). */
        const size_t i[1] = { IDX(13, DNAC_P2C_OI_COL_IS_FINAL_CLOSEOUT) };
        const uint64_t v[1] = { 0 };
        n3_case("final_cleared", DNAC_P2C_OI_DEFECT_FINAL_CLOSEOUT, i, v, 1);
    }
    { /* 8a height one-hot cleared on an acc row (row 10, h_sel[0]). */
        const size_t i[1] = { IDX(10, dnac_p2c_oi_col_hsel(0)) };
        const uint64_t v[1] = { 0 };
        n3_case("hsel_cleared", DNAC_P2C_OI_DEFECT_HSEL, i, v, 1);
    }
    { /* 8b height one-hot with the WRONG index (row 10 should route h_sel[0]). */
        const size_t i[2] = { IDX(10, dnac_p2c_oi_col_hsel(0)),
                              IDX(10, dnac_p2c_oi_col_hsel(1)) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("hsel_wrong_index", DNAC_P2C_OI_DEFECT_HSEL, i, v, 2);
    }
    { /* 8c height selector on a CHAIN row (chain routes no register). */
        const size_t i[1] = { IDX(0, dnac_p2c_oi_col_hsel(0)) };
        const uint64_t v[1] = { 1 };
        n3_case("hsel_on_chain", DNAC_P2C_OI_DEFECT_HSEL, i, v, 1);
    }
    { /* 9a step one-hot — a scheduled row with NO step. */
        const size_t i[1] = { IDX(5, dnac_p2c_oi_col_pos(5)) };
        const uint64_t v[1] = { 0 };
        n3_case("pos_missing", DNAC_P2C_OI_DEFECT_POS_ONEHOT, i, v, 1);
    }
    { /* 9b step one-hot — a PADDING row claiming a step. */
        const size_t i[1] = { IDX(14, dnac_p2c_oi_col_pos(0)) };
        const uint64_t v[1] = { 1 };
        n3_case("pos_on_padding", DNAC_P2C_OI_DEFECT_POS_ONEHOT, i, v, 1);
    }
    { /* 10a g_pow2 zeroed on a chain row — G_j is never 0, a real mutation. */
        const size_t i[1] = { IDX(1, DNAC_P2C_OI_COL_G_POW2) };
        const uint64_t v[1] = { 0 };
        n3_case("gpow2_zeroed", DNAC_P2C_OI_DEFECT_GPOW2, i, v, 1);
    }
    { /* 10b g_pow2 present on a non-chain (acc) row. */
        const size_t i[1] = { IDX(10, DNAC_P2C_OI_COL_G_POW2) };
        const uint64_t v[1] = { 1 };
        n3_case("gpow2_off_chain", DNAC_P2C_OI_DEFECT_GPOW2, i, v, 1);
    }
    { /* 10c g_pow2 = the WRONG generator on chain row 1 (G_2 instead of G_1). */
        const size_t i[1] = { IDX(1, DNAC_P2C_OI_COL_G_POW2) };
        const uint64_t v[1] = { gold_fp_to_u64(gold_fp_two_adic_generator(
            (unsigned)(DNAC_P2C_OI_REF_LGMH - 2))) };
        n3_case("gpow2_shifted", DNAC_P2C_OI_DEFECT_GPOW2, i, v, 1);
    }

    /* Validator argument fail-close. */
    dnac_p2c_oi_table_defect_t d = DNAC_P2C_OI_DEFECT_NONE;
    CHECK(dnac_p2c_oi_table_validate(ref, NULL, REF_ROWS, &d) ==
              DNAC_P2C_OI_TABLE_ERR_PARAM,
          "N3: validate(NULL cells)");
    CHECK(dnac_p2c_oi_table_validate(NULL, g_good, REF_ROWS, &d) ==
              DNAC_P2C_OI_TABLE_ERR_PARAM,
          "N3: validate(NULL cfg)");
    CHECK(dnac_p2c_oi_table_validate(ref, g_good, REF_ROWS - 1, &d) ==
              DNAC_P2C_OI_TABLE_ERR_PARAM,
          "N3: validate(wrong row count)");
    CHECK(dnac_p2c_oi_table_validate(ref, g_good, REF_ROWS, NULL) ==
              DNAC_P2C_OI_TABLE_OK,
          "N3: validate(NULL defect out) on a clean table");
}

/* ==========================================================================
 * N4 — generator / cfg-gate fail-close
 * ======================================================================== */
static void n4_failclose(void)
{
    static uint64_t out[REF_CELLS];
    const dnac_p2c_oi_table_cfg_t *ref = dnac_p2c_oi_ref_cfg();

    CHECK(dnac_p2c_oi_table_rows(NULL) == 0, "N4: rows(NULL) != 0");
    CHECK(dnac_p2c_oi_chain_rows(NULL) == 0, "N4: chain_rows(NULL) != 0");
    CHECK(dnac_p2c_oi_capture_rows(NULL) == 0, "N4: capture_rows(NULL) != 0");
    CHECK(dnac_p2c_oi_group_rows(NULL) == 0, "N4: group_rows(NULL) != 0");
    CHECK(dnac_p2c_oi_sched_rows(NULL) == 0, "N4: sched_rows(NULL) != 0");
    CHECK(dnac_p2c_oi_acc_count(NULL) == 0, "N4: acc_count(NULL) != 0");

    CHECK(dnac_p2c_oi_table_generate(NULL, out, REF_CELLS) ==
              DNAC_P2C_OI_TABLE_ERR_PARAM,
          "N4: generate(NULL cfg)");
    CHECK(dnac_p2c_oi_table_generate(ref, NULL, REF_CELLS) ==
              DNAC_P2C_OI_TABLE_ERR_PARAM,
          "N4: generate(NULL out)");
    CHECK(dnac_p2c_oi_table_generate(ref, out, REF_CELLS - 1) ==
              DNAC_P2C_OI_TABLE_ERR_CAPACITY,
          "N4: generate(short buffer)");

    dnac_p2c_oi_row_t rec;
    CHECK(dnac_p2c_oi_table_row(ref, REF_ROWS, &rec) ==
              DNAC_P2C_OI_TABLE_ERR_PARAM,
          "N4: row(index == rows)");
    CHECK(dnac_p2c_oi_table_row(ref, 0, NULL) == DNAC_P2C_OI_TABLE_ERR_PARAM,
          "N4: row(NULL out)");

    /* acc_count with a zero component. */
    const dnac_p2c_oi_height_desc_t zdesc = { 4, 1, 0, 1, 1 };
    CHECK(dnac_p2c_oi_acc_count(&zdesc) == 0, "N4: acc_count(zero count) != 0");

    /* Rejected cfgs. Heights arrays declared so the gate can deref them. */
    static const dnac_p2c_oi_height_desc_t h_ok2[2] = { { 4, 1, 1, 1, 1 },
                                                        { 2, 1, 1, 1, 1 } };
    static const dnac_p2c_oi_height_desc_t h_hmax_bad[2] = {
        { 3, 1, 1, 1, 1 }, { 2, 1, 1, 1, 1 } }; /* h_max != lgmh */
    static const dnac_p2c_oi_height_desc_t h_below_lb[2] = {
        { 4, 1, 1, 1, 1 }, { 1, 1, 1, 1, 1 } }; /* h < lb = 2 */
    static const dnac_p2c_oi_height_desc_t h_notdesc[3] = {
        { 4, 1, 1, 1, 1 }, { 4, 1, 1, 1, 1 }, { 2, 1, 1, 1, 1 } }; /* 4>=4 */
    static const dnac_p2c_oi_height_desc_t h_zero[2] = {
        { 4, 1, 1, 1, 1 }, { 2, 1, 0, 1, 1 } }; /* zero count */
    static const dnac_p2c_oi_height_desc_t h_big[2] = {
        { 4, 60, 1, 1, 1 }, { 2, 1, 1, 1, 1 } }; /* n_sched overflow */
    struct {
        const char             *what;
        dnac_p2c_oi_table_cfg_t cfg;
    } bad[] = {
        { "lgmh 33", { 33, 2, 2, h_ok2, 100 } },
        { "lgmh 1", { 1, 1, 2, h_ok2, 100 } },
        { "num_heights 0", { 4, 2, 0, h_ok2, 100 } },
        { "heights NULL", { 4, 2, 2, NULL, 100 } },
        { "h_max != lgmh", { 4, 2, 2, h_hmax_bad, 100 } },
        { "height below lb", { 4, 2, 2, h_below_lb, 100 } },
        { "not descending", { 4, 2, 3, h_notdesc, 100 } },
        { "zero count", { 4, 2, 2, h_zero, 100 } },
        { "n_sched overflow", { 4, 2, 2, h_big, 100 } },
        { "queries 0", { 4, 2, 2, h_ok2, 0 } },
        { "queries huge", { 4, 2, 2, h_ok2, DNAC_P2C_OI_MAX_QUERIES + 1 } },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(dnac_p2c_oi_table_rows(&bad[i].cfg) == 0, "N4: cfg '%s' ACCEPTED",
              bad[i].what);
        CHECK(dnac_p2c_oi_table_generate(&bad[i].cfg, out, REF_CELLS) ==
                  DNAC_P2C_OI_TABLE_ERR_PARAM,
              "N4: generate(cfg '%s') did not fail closed", bad[i].what);
    }

    /* An ACCEPTED non-reference cfg still validates (the WIDE shape). */
    CHECK(dnac_p2c_oi_table_rows(&WIDE_CFG) == WIDE_ROWS,
          "N4: WIDE cfg REJECTED");

    /* FLEET 029 — an lb-LESS cfg is ACCEPTED (the `heights[last] == lb` rule is
     * GONE); the remaining rules still bite, which the negatives above pin. */
    CHECK(dnac_p2c_oi_table_rows(&NOLB_CFG) == 16, "N4: lb-less NOLB REJECTED");
    CHECK(dnac_p2c_oi_table_rows(&NOLB_MB_CFG) == 16,
          "N4: lb-less NOLB_MB REJECTED");
    { /* lgmh 4, H = {4, 3}, lb = 2: also lb-less, also accepted. */
        static const dnac_p2c_oi_height_desc_t h_nolb[2] = { { 4, 1, 1, 1, 1 },
                                                             { 3, 1, 1, 1, 1 } };
        const dnac_p2c_oi_table_cfg_t nolb43 = { 4, 2, 2, h_nolb, 100 };
        CHECK(dnac_p2c_oi_table_rows(&nolb43) != 0,
              "N4: lb-less cfg H={4,3} REJECTED");
    }
}

/* ==========================================================================
 * --print-root — the ORCHESTRATOR fills DNAC_P2C_OI_PREP_ROOT_LANE* from this
 * ======================================================================== */
static int print_root(void)
{
    static uint64_t t[REF_CELLS];
    uint64_t lanes[4];
    if (dnac_p2c_oi_table_generate(dnac_p2c_oi_ref_cfg(), t, REF_CELLS) !=
        DNAC_P2C_OI_TABLE_OK) {
        fprintf(stderr, "print-root: generate failed\n");
        return 1;
    }
    dnac_p2c_oi_table_defect_t d = DNAC_P2C_OI_DEFECT_NONE;
    if (dnac_p2c_oi_table_validate(dnac_p2c_oi_ref_cfg(), t, REF_ROWS, &d) !=
        DNAC_P2C_OI_TABLE_OK) {
        fprintf(stderr, "print-root: the table FAILED its own validator "
                        "(defect %d) — refusing to print a root\n",
                (int)d);
        return 1;
    }
    if (!oi_commit_table(t, REF_ROWS, lanes)) {
        fprintf(stderr, "print-root: LDE/commit pipeline failed\n");
        return 1;
    }
    printf("#define DNAC_P2C_OI_PREP_ROOT_LANE0 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[0]);
    printf("#define DNAC_P2C_OI_PREP_ROOT_LANE1 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[1]);
    printf("#define DNAC_P2C_OI_PREP_ROOT_LANE2 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[2]);
    printf("#define DNAC_P2C_OI_PREP_ROOT_LANE3 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[3]);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--print-root") == 0) {
        return print_root();
    }

    printf("P2c open_input PIN slice — FRI reduced-opening preprocessed table\n");
    t1_determinism();
    t2_all();
    t3_pin_kat();
    n3_validator_negatives();
    n4_failclose();

    printf("\nfri_oi_air_table total  %24d checks\n", g_checks);
    printf("fri_oi_air_table failed %24d\n", g_fails);
    if (g_fails == 0) {
        printf("\nP2c open_input PIN GATE: GREEN\n");
        return 0;
    }
    fprintf(stderr, "\nP2c open_input PIN GATE: RED\n");
    return 1;
}
