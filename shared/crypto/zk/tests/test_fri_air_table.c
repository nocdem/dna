/**
 * @file test_fri_air_table.c
 * @brief P2c PIN slice gate — the FRI fold-walk AIR's preprocessed row-type
 *        table: deterministic generator, structural static validator, and the
 *        PIN-1-P2c root constant (runtime KAT, shielded_domsep.h practice).
 *
 * Design: dnac/docs/plans/2026-07-29-p2c-fri-in-air-design.md §0.5 "Row
 * schedule" (:229-266), C1 (:330-338), §0.6 ledger (:204-218), §1 D-1..D-5.
 * No AIR is built in this slice — `fri_air.{c,h}` is a later one. Mirrors the
 * P2b PIN gate (tests/test_mmcs_air_table.c) one-for-one.
 *
 *   T1  generator determinism — reference cfg and the RECURSION shape, two runs
 *       each, byte-identical; shape accessors agree with the design's numbers
 *   T2  schedule shape: typed-prefix layout, pair-gate placement, the two
 *       NON-ADJACENT roll-in slots, the G_j literals, the step one-hot; the
 *       static validator accepts both cfgs and the extremal lgmh = 32 shape
 *   T3  PIN-1-P2c KAT: table → coset LDE (bitrev) → dnac_p2_mmcs_commit_mixed
 *       == DNAC_P2C_PREP_ROOT, and the comparator accepts it
 *       (Pin FILLED 2026-07-29 from `--print-root`; during any future re-pin
 *       the constant reverts to {0,0,0,0} and this KAT goes RED by design —
 *       the UNFILLED guard branches below reactivate at compile time then.)
 *   N1  comparator rejects a one-lane tamper / NULL
 *   N2  the pin binds table CONTENTS: one flipped selector cell ⇒ another root
 *   N3  static-validator negatives — every check tripped exactly once, with
 *       exact defect isolation (the P2b N4/N11 pattern)
 *   N4  generator fail-close on bad arguments and on every cfg gate
 *
 * Usage:
 *   test_fri_air_table                 run all gates
 *   test_fri_air_table --print-root    print the reference table's four root
 *                                      lanes in DNAC_P2C_PREP_ROOT_LANE* form
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../fri_air_table.h"
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
 * constants they mirror, so they cannot drift (the DNAC_P2B_PREP_LOG_BLOWUP
 * practice, test_mmcs_air_table.c:56-60). */
typedef char p2c_blowup_pin_assert
    [(DNAC_P2C_PREP_LOG_BLOWUP == (unsigned)DNAC_SHIELDED_FRI_LOG_BLOWUP) ? 1
                                                                         : -1];
typedef char p2c_lgmh_bound_assert
    [(DNAC_P2C_MAX_LGMH == (size_t)GOLDILOCKS_TWO_ADICITY) ? 1 : -1];
/* Column layout: the eight 0/1 flags occupy [0, NUM_FLAG_COLS), the g_pow2
 * field literal sits immediately after them, and the step one-hot follows —
 * total 73. The validator's booleanity pass skips EXACTLY the g_pow2 column, so
 * a re-ordering that broke this would silently stop checking a flag. */
typedef char p2c_layout_assert
    [(DNAC_P2C_COL_G_POW2 == (int)DNAC_P2C_NUM_FLAG_COLS &&
      DNAC_P2C_COL_POS_OFF == DNAC_P2C_COL_G_POW2 + 1 &&
      DNAC_P2C_TABLE_COLS == (size_t)73)
         ? 1
         : -1];
/* The reference cfg IS the shipped leaf-proof FRI shape: committed height 11
 * plus blowup 2 = lgmh 13 (shielded_fri_params.h:206-207, :138-140). */
typedef char p2c_ref_shape_assert
    [(DNAC_P2C_REF_LGMH == DNAC_SHIELDED_COMMITTED_LOG_HEIGHT +
                               DNAC_SHIELDED_FRI_LOG_BLOWUP &&
      DNAC_P2C_REF_LOG_BLOWUP == DNAC_SHIELDED_FRI_LOG_BLOWUP &&
      DNAC_P2C_REF_LOG_FINAL_POLY_LEN ==
          DNAC_SHIELDED_FRI_LOG_FINAL_POLY_LEN &&
      DNAC_P2C_REF_MAX_LOG_ARITY == DNAC_SHIELDED_FRI_MAX_LOG_ARITY &&
      DNAC_P2C_REF_NUM_QUERIES == DNAC_SHIELDED_FRI_NUM_QUERIES)
         ? 1
         : -1];

#define P2C_COLS ((size_t)DNAC_P2C_TABLE_COLS)          /* 73  */
#define REF_ROWS DNAC_P2C_REF_ROWS                      /* 32  */
#define REF_CELLS (REF_ROWS * P2C_COLS)                 /* 2336 */
#define MAX_ROWS ((size_t)64)                           /* lgmh 32 extremal */
#define MAX_CELLS (MAX_ROWS * P2C_COLS)                 /* 4672 */
#define MAX_LDE_CELLS ((MAX_ROWS << DNAC_P2C_PREP_LOG_BLOWUP) * P2C_COLS)

/* The RECURSION shape (design §0.1 table :52-60 + P2.0 G-DET-3): H_rec = 2^17
 * plus blowup 2 ⇒ lgmh 19, R = 17, one roll-in at post-fold height 17
 * (i.e. fold phase r = lgmh-1-h = 1), Q ≈ 59. NO root is pinned for it — this
 * cfg exists here only to prove the generator and the validator are not
 * reference-cfg-shaped. */
#define REC_LGMH ((size_t)19)
#define REC_ROWS ((size_t)64)
static const size_t REC_ROLLIN[1] = { 17 };
static const dnac_p2c_table_cfg_t REC_CFG = { REC_LGMH, 2, 0, 1,
                                              1,        REC_ROLLIN, 59 };

/* ==========================================================================
 * Shared helper: the SHIPPED preprocessed-commit pipeline
 * (batch_prover.c:807-825 with is_zk = 0: coset LDE bit-reversed at
 * log_blowup, then ONE mixed-height Poseidon2 MMCS commit).
 * ======================================================================== */
static int p2c_commit_table(const uint64_t *table, size_t rows,
                            uint64_t out_lanes[4])
{
    static uint64_t lde[MAX_LDE_CELLS];
    const size_t lde_rows = rows << DNAC_P2C_PREP_LOG_BLOWUP;
    if (lde_rows * P2C_COLS > MAX_LDE_CELLS) return 0;

    if (dnac_prover_coset_lde_bitrev(table, rows, P2C_COLS,
                                     DNAC_P2C_PREP_LOG_BLOWUP,
                                     GOLDILOCKS_GENERATOR,
                                     lde) != DNAC_PROVER_OK) {
        return 0;
    }
    const uint64_t *mats[1] = { lde };
    const size_t widths[1] = { P2C_COLS };
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
 * T1 — generator determinism (design §1 D-1)
 * ======================================================================== */
static void t1_determinism(void)
{
    static uint64_t a[REF_CELLS], b[REF_CELLS];
    const dnac_p2c_table_cfg_t *ref = dnac_p2c_ref_cfg();

    /* Design §0.5 :239: "Leaf cfg: 12 + 11 + pad → 32 rows." */
    CHECK(dnac_p2c_chain_rows(ref) == 12, "T1: ref chain rows %zu != 12",
          dnac_p2c_chain_rows(ref));
    CHECK(dnac_p2c_fold_rows(ref) == 11, "T1: ref fold rows %zu != 11",
          dnac_p2c_fold_rows(ref));
    CHECK(dnac_p2c_table_rows(ref) == REF_ROWS, "T1: ref rows %zu != %zu",
          dnac_p2c_table_rows(ref), (size_t)REF_ROWS);

    CHECK(dnac_p2c_table_generate(ref, a, REF_CELLS) == DNAC_P2C_TABLE_OK,
          "T1: ref generate #1");
    CHECK(dnac_p2c_table_generate(ref, b, REF_CELLS) == DNAC_P2C_TABLE_OK,
          "T1: ref generate #2");
    CHECK(memcmp(a, b, sizeof(a)) == 0, "T1: ref table NOT deterministic");

    /* Design §0.5 :239: "Recursion cfg: 18 + 17 + pad → 64 rows." */
    static uint64_t c[MAX_CELLS], d[MAX_CELLS];
    CHECK(dnac_p2c_chain_rows(&REC_CFG) == 18, "T1: rec chain rows %zu != 18",
          dnac_p2c_chain_rows(&REC_CFG));
    CHECK(dnac_p2c_fold_rows(&REC_CFG) == 17, "T1: rec fold rows %zu != 17",
          dnac_p2c_fold_rows(&REC_CFG));
    CHECK(dnac_p2c_table_rows(&REC_CFG) == REC_ROWS, "T1: rec rows %zu != %zu",
          dnac_p2c_table_rows(&REC_CFG), REC_ROWS);
    CHECK(dnac_p2c_table_generate(&REC_CFG, c, MAX_CELLS) == DNAC_P2C_TABLE_OK,
          "T1: rec generate #1");
    CHECK(dnac_p2c_table_generate(&REC_CFG, d, MAX_CELLS) == DNAC_P2C_TABLE_OK,
          "T1: rec generate #2");
    CHECK(memcmp(c, d, REC_ROWS * P2C_COLS * sizeof(uint64_t)) == 0,
          "T1: rec table NOT deterministic");

    /* The two shapes are genuinely different tables — otherwise "deterministic"
     * would be a claim about one table printed twice. */
    CHECK(memcmp(a, c, REF_CELLS * sizeof(uint64_t)) != 0,
          "T1: leaf and recursion tables are byte-identical");
}

/* ==========================================================================
 * T2 — schedule shape + the static validator on three cfgs
 * ======================================================================== */
static void t2_shape(const dnac_p2c_table_cfg_t *cfg, const char *name,
                     size_t exp_chain, size_t exp_fold, size_t exp_rows,
                     const size_t *exp_rollin_phases, size_t exp_num_rollin)
{
    static uint64_t t[MAX_CELLS];
    const size_t rows = dnac_p2c_table_rows(cfg);
    if (rows != exp_rows ||
        dnac_p2c_table_generate(cfg, t, MAX_CELLS) != DNAC_P2C_TABLE_OK) {
        CHECK(0, "T2[%s]: generate failed (rows %zu, want %zu)", name, rows,
              exp_rows);
        return;
    }
    const size_t sched = exp_chain + exp_fold;

    size_t n_chain = 0, n_fold = 0, n_pad = 0;
    size_t n_chainpair = 0, n_handoff = 0, n_foldpair = 0, n_terminal = 0,
           n_rollin = 0;
    int order_ok = 1, exclusive_ok = 1, boolean_ok = 1, onehot_ok = 1,
        gpow2_ok = 1;
    unsigned prev = 0;

    for (size_t r = 0; r < rows; r++) {
        const uint64_t *row = &t[r * P2C_COLS];

        for (size_t k = 0; k < P2C_COLS; k++) {
            if (row[k] >= GOLDILOCKS_P) boolean_ok = 0;
            if (k != (size_t)DNAC_P2C_COL_G_POW2 && row[k] > 1) boolean_ok = 0;
        }

        const uint64_t set = row[DNAC_P2C_COL_IS_CHAIN] +
                             row[DNAC_P2C_COL_IS_FOLD] +
                             row[DNAC_P2C_COL_IS_PAD];
        if (set != 1) exclusive_ok = 0;

        unsigned ty;
        if (row[DNAC_P2C_COL_IS_CHAIN]) {
            ty = 0;
            n_chain++;
            /* g_pow2 on chain row j is G_j = g_lgmh^{2^j}; the two-adic ladder
             * gives it as g_{lgmh-j} (field_goldilocks.c:210-220). */
            const uint64_t want = gold_fp_to_u64(
                gold_fp_two_adic_generator((unsigned)(cfg->lgmh - r)));
            if (row[DNAC_P2C_COL_G_POW2] != want) gpow2_ok = 0;
        } else if (row[DNAC_P2C_COL_IS_FOLD]) {
            ty = 1;
            n_fold++;
            if (row[DNAC_P2C_COL_G_POW2] != 0) gpow2_ok = 0;
        } else {
            ty = 2;
            n_pad++;
            if (row[DNAC_P2C_COL_G_POW2] != 0) gpow2_ok = 0;
        }
        if (ty < prev) order_ok = 0;
        prev = ty;

        n_chainpair += (size_t)row[DNAC_P2C_COL_IS_CHAINPAIR];
        n_handoff += (size_t)row[DNAC_P2C_COL_IS_HANDOFF];
        n_foldpair += (size_t)row[DNAC_P2C_COL_IS_FOLDPAIR];
        n_terminal += (size_t)row[DNAC_P2C_COL_IS_TERMINAL];
        n_rollin += (size_t)row[DNAC_P2C_COL_IS_ROLLIN];

        for (size_t k = 0; k < DNAC_P2C_MAX_STEPS; k++) {
            const uint64_t want = (r < sched && k == r) ? 1u : 0u;
            if (row[dnac_p2c_col_pos(k)] != want) onehot_ok = 0;
        }
    }

    CHECK(n_chain == exp_chain, "T2[%s]: chain rows %zu != %zu", name, n_chain,
          exp_chain);
    CHECK(n_fold == exp_fold, "T2[%s]: fold rows %zu != %zu", name, n_fold,
          exp_fold);
    CHECK(n_pad == rows - sched && n_pad >= 1,
          "T2[%s]: padding rows %zu != %zu (>=1)", name, n_pad, rows - sched);
    CHECK(order_ok, "T2[%s]: typed-prefix order broken", name);
    CHECK(exclusive_ok, "T2[%s]: a row carries != 1 row type", name);
    CHECK(boolean_ok, "T2[%s]: a cell is non-boolean or non-canonical", name);
    CHECK(onehot_ok, "T2[%s]: step one-hot wrong", name);
    CHECK(gpow2_ok, "T2[%s]: g_pow2 literal wrong", name);

    /* C3's multiplication count (design §0.5 :350-352): the row-0
     * multiply-from-1 plus one per chain pair == lgmh - 1 bits absorbed. */
    CHECK(n_chainpair == exp_chain - 1, "T2[%s]: chainpair %zu != %zu", name,
          n_chainpair, exp_chain - 1);
    CHECK(1 + n_chainpair == cfg->lgmh - 1,
          "T2[%s]: multiplication count %zu != lgmh-1 = %zu", name,
          1 + n_chainpair, cfg->lgmh - 1);
    CHECK(n_handoff == 1, "T2[%s]: is_handoff count %zu != 1", name, n_handoff);
    CHECK(t[(exp_chain - 1) * P2C_COLS + DNAC_P2C_COL_IS_HANDOFF] == 1,
          "T2[%s]: is_handoff not on the last chain row", name);
    CHECK(n_foldpair == exp_fold - 1, "T2[%s]: foldpair %zu != %zu", name,
          n_foldpair, exp_fold - 1);
    CHECK(n_terminal == 1, "T2[%s]: is_terminal count %zu != 1", name,
          n_terminal);
    CHECK(t[sched * P2C_COLS + DNAC_P2C_COL_IS_TERMINAL] == 1,
          "T2[%s]: is_terminal not on the FIRST padding row", name);

    /* Roll-in slots sit on the fold rows whose POST-FOLD height is pinned:
     * phase r has height lgmh-1-r (fri_verifier.c:596). */
    CHECK(n_rollin == exp_num_rollin, "T2[%s]: roll-in slots %zu != %zu", name,
          n_rollin, exp_num_rollin);
    for (size_t i = 0; i < exp_num_rollin; i++) {
        const size_t r = exp_chain + exp_rollin_phases[i];
        CHECK(t[r * P2C_COLS + DNAC_P2C_COL_IS_ROLLIN] == 1,
              "T2[%s]: no roll-in slot on fold phase %zu (table row %zu)", name,
              exp_rollin_phases[i], r);
    }

    /* The row record and the cells must agree — the record is what the AIR and
     * the tests reason about. */
    int record_ok = 1;
    for (size_t r = 0; r < rows; r++) {
        dnac_p2c_row_t rec;
        if (dnac_p2c_table_row(cfg, r, &rec) != DNAC_P2C_TABLE_OK) {
            record_ok = 0;
            break;
        }
        const uint64_t *row = &t[r * P2C_COLS];
        const uint64_t ty = (rec.type == DNAC_P2C_ROW_CHAIN)
                                ? row[DNAC_P2C_COL_IS_CHAIN]
                                : (rec.type == DNAC_P2C_ROW_FOLD)
                                      ? row[DNAC_P2C_COL_IS_FOLD]
                                      : row[DNAC_P2C_COL_IS_PAD];
        if (ty != 1 || row[DNAC_P2C_COL_IS_CHAINPAIR] !=
                           (uint64_t)rec.is_chainpair ||
            row[DNAC_P2C_COL_IS_HANDOFF] != (uint64_t)rec.is_handoff ||
            row[DNAC_P2C_COL_IS_FOLDPAIR] != (uint64_t)rec.is_foldpair ||
            row[DNAC_P2C_COL_IS_TERMINAL] != (uint64_t)rec.is_terminal ||
            row[DNAC_P2C_COL_IS_ROLLIN] != (uint64_t)rec.is_rollin ||
            row[DNAC_P2C_COL_G_POW2] != rec.g_pow2) {
            record_ok = 0;
            break;
        }
    }
    CHECK(record_ok, "T2[%s]: row record disagrees with the cells", name);

    /* And the static validator — the thing that stands in for the in-AIR
     * discharge P2b had to do — accepts the generator's own output. */
    dnac_p2c_table_defect_t defect = DNAC_P2C_DEFECT_NONE;
    CHECK(dnac_p2c_table_validate(cfg, t, rows, &defect) == DNAC_P2C_TABLE_OK,
          "T2[%s]: validator REJECTED the generated table (defect %d)", name,
          (int)defect);
    CHECK(defect == DNAC_P2C_DEFECT_NONE, "T2[%s]: defect %d on a clean table",
          name, (int)defect);
}

static void t2_all(void)
{
    /* Reference: roll-in heights {11, 9} ⇒ fold phases lgmh-1-h = 1 and 3 —
     * two NON-ADJACENT slots (fri_air_table.h reference-config note). */
    const size_t ref_phases[2] = { 1, 3 };
    t2_shape(dnac_p2c_ref_cfg(), "leaf", 12, 11, REF_ROWS, ref_phases, 2);

    const size_t rec_phases[1] = { 1 };
    t2_shape(&REC_CFG, "recursion", 18, 17, REC_ROWS, rec_phases, 1);

    /* Largest REALISTIC shape: lgmh = 32 (== GOLDILOCKS_TWO_ADICITY, the D3
     * bound) at the shipped blowup 2 ⇒ 31 chain + 30 fold = 61 scheduled rows,
     * 3 padding. */
    const dnac_p2c_table_cfg_t big = { 32, 2, 0, 1, 0, NULL, 100 };
    t2_shape(&big, "lgmh32_lb2", 31, 30, 64, NULL, 0);

    /* Tightest possible fit against DNAC_P2C_MAX_STEPS: 31 chain + 32 fold = 63
     * scheduled rows and exactly ONE padding row — the minimum the terminality
     * rule allows. Only reachable at log_blowup = 0, which is NOT a realistic
     * FRI cfg; the design's eval-entry gate list (G1/G2/G3/G7, §0.5 :276-290)
     * deliberately does not bound log_blowup, so this module does not either.
     * FLAGGED for the composition: log_blowup is pinned there, with the FRI
     * params, not here. */
    const dnac_p2c_table_cfg_t ext = { 32, 0, 0, 1, 0, NULL, 1 };
    t2_shape(&ext, "max_steps_fit", 31, 32, 64, NULL, 0);
}

/* ==========================================================================
 * T3 — PIN-1-P2c KAT + N1 + N2
 * ======================================================================== */
static void t3_pin_kat(void)
{
    static uint64_t t[REF_CELLS];
    const dnac_p2c_table_cfg_t *ref = dnac_p2c_ref_cfg();
    if (dnac_p2c_table_generate(ref, t, REF_CELLS) != DNAC_P2C_TABLE_OK) {
        CHECK(0, "T3: generate failed");
        return;
    }

    uint64_t lanes[4];
    if (!p2c_commit_table(t, REF_ROWS, lanes)) {
        CHECK(0, "T3: LDE/commit pipeline failed");
        return;
    }
    printf("  PIN-1-P2c derived root = { 0x%016" PRIx64 ", 0x%016" PRIx64
           ", 0x%016" PRIx64 ", 0x%016" PRIx64 " }\n",
           lanes[0], lanes[1], lanes[2], lanes[3]);
    if (DNAC_P2C_PREP_ROOT_UNFILLED) {
        fprintf(stderr,
                "  NOTE: DNAC_P2C_PREP_ROOT is still the PLACEHOLDER {0,0,0,0}."
                "\n        The four T3 lane checks below FAIL BY DESIGN until"
                " it is filled\n        from `--print-root`. Do not"
                " hand-edit the constant to silence them.\n");
    }

    static const uint64_t pinned[4] = DNAC_P2C_PREP_ROOT;
    for (int k = 0; k < 4; k++) {
        CHECK(lanes[k] == pinned[k],
              "T3: PIN-1-P2c lane %d: derived 0x%016" PRIx64
              " != pinned 0x%016" PRIx64,
              k, lanes[k], pinned[k]);
    }
    CHECK(dnac_p2c_prep_root_check(lanes) == DNAC_P2C_TABLE_OK,
          "T3: comparator rejected the derived root");

    /* N1 — one tampered lane on an otherwise-correct root, and NULL. */
    for (int k = 0; k < 4; k++) {
        uint64_t bad[4];
        memcpy(bad, lanes, sizeof(bad));
        bad[k] ^= 1;
        CHECK(dnac_p2c_prep_root_check(bad) ==
                  DNAC_P2C_TABLE_ERR_ROOT_MISMATCH,
              "N1: comparator accepted a tampered lane %d", k);
    }
    CHECK(dnac_p2c_prep_root_check(NULL) == DNAC_P2C_TABLE_ERR_PARAM,
          "N1: comparator on NULL must be PARAM");
    if (DNAC_P2C_PREP_ROOT_UNFILLED) {
        /* An unfilled pin must reject even the all-zero root it would
         * otherwise match (fri_air_table.h comparator contract). This block
         * disappears the moment the constant is filled. */
        const uint64_t zero[4] = { 0, 0, 0, 0 };
        CHECK(dnac_p2c_prep_root_check(zero) ==
                  DNAC_P2C_TABLE_ERR_ROOT_MISMATCH,
              "N1: PLACEHOLDER pin ACCEPTED an all-zero root");
    }

    /* N2 — the pin binds CONTENTS: clear the is_terminal selector (the vacuity
     * attack shape — C5's terminal equality would never fire) and re-run the
     * SAME pipeline. Everything else is byte-identical. */
    static uint64_t tampered[REF_CELLS];
    memcpy(tampered, t, sizeof(tampered));
    size_t term_row = (size_t)-1;
    for (size_t r = 0; r < REF_ROWS; r++) {
        if (tampered[r * P2C_COLS + DNAC_P2C_COL_IS_TERMINAL] == 1) {
            term_row = r;
            break;
        }
    }
    CHECK(term_row != (size_t)-1, "N2: no is_terminal row to tamper");
    if (term_row != (size_t)-1) {
        tampered[term_row * P2C_COLS + DNAC_P2C_COL_IS_TERMINAL] = 0;
        CHECK(memcmp(tampered, t, sizeof(t)) != 0,
              "N2: tamper did not change the table");
        uint64_t bad_lanes[4];
        if (p2c_commit_table(tampered, REF_ROWS, bad_lanes)) {
            CHECK(memcmp(bad_lanes, lanes, sizeof(lanes)) != 0,
                  "N2: a flipped selector cell produced the SAME root");
        } else {
            CHECK(0, "N2: LDE/commit pipeline failed on the tampered table");
        }
        /* ... and the validator catches the same tamper structurally. */
        dnac_p2c_table_defect_t d = DNAC_P2C_DEFECT_NONE;
        CHECK(dnac_p2c_table_validate(ref, tampered, REF_ROWS, &d) ==
                  DNAC_P2C_TABLE_ERR_SCHEDULE,
              "N2: validator accepted the cleared is_terminal");
        CHECK(d == DNAC_P2C_DEFECT_TERMINAL, "N2: defect %d != TERMINAL",
              (int)d);
    }
}

/* ==========================================================================
 * N3 — static-validator negatives, one check tripped per tamper
 *
 * Every mutation starts from the CLEAN reference table, so a mutation that
 * accidentally tripped an earlier check would show up as the wrong defect
 * code, not as a silent pass (exact-count isolation, P2b N4/N11).
 * ======================================================================== */
static uint64_t g_good[REF_CELLS];

static void n3_case(const char *what, dnac_p2c_table_defect_t want,
                    const size_t *cells_idx, const uint64_t *vals, size_t n)
{
    static uint64_t t[REF_CELLS];
    memcpy(t, g_good, sizeof(t));
    for (size_t i = 0; i < n; i++) t[cells_idx[i]] = vals[i];

    dnac_p2c_table_defect_t got = DNAC_P2C_DEFECT_NONE;
    const dnac_p2c_table_status_t st =
        dnac_p2c_table_validate(dnac_p2c_ref_cfg(), t, REF_ROWS, &got);
    CHECK(st == DNAC_P2C_TABLE_ERR_SCHEDULE, "N3[%s]: validator returned %d",
          what, (int)st);
    CHECK(got == want, "N3[%s]: defect %d != %d", what, (int)got, (int)want);
}

#define IDX(row, col) ((size_t)((row) * P2C_COLS + (col)))

static void n3_validator_negatives(void)
{
    const dnac_p2c_table_cfg_t *ref = dnac_p2c_ref_cfg();
    if (dnac_p2c_table_generate(ref, g_good, REF_CELLS) != DNAC_P2C_TABLE_OK) {
        CHECK(0, "N3: reference generate failed");
        return;
    }
    /* Reference layout: chain [0,12), fold [12,23), pad [23,32);
     * roll-in fold phases 1 and 3 ⇒ table rows 13 and 15. */
    const size_t FIRST_FOLD = 12, FIRST_PAD = 23, LAST_CHAIN = 11;

    { /* 1 canonicality — a cell at exactly p aliases to 0 mod p. */
        const size_t i[1] = { IDX(0, DNAC_P2C_COL_IS_CHAIN) };
        const uint64_t v[1] = { GOLDILOCKS_P };
        n3_case("canonical", DNAC_P2C_DEFECT_CANONICAL, i, v, 1);
    }
    { /* 2 booleanity — a selector of 2 would scale a gated constraint. */
        const size_t i[1] = { IDX(0, DNAC_P2C_COL_IS_CHAIN) };
        const uint64_t v[1] = { 2 };
        n3_case("boolean", DNAC_P2C_DEFECT_BOOLEAN, i, v, 1);
    }
    { /* 3 type exclusivity — a row claiming two types gates both forms. */
        const size_t i[1] = { IDX(0, DNAC_P2C_COL_IS_FOLD) };
        const uint64_t v[1] = { 1 };
        n3_case("type_exclusive", DNAC_P2C_DEFECT_TYPE_EXCLUSIVE, i, v, 1);
    }
    { /* 4 typed-prefix order — SWAP a chain and a fold row's type so the
       *   counts stay right and only the ORDER is broken. */
        const size_t i[4] = { IDX(0, DNAC_P2C_COL_IS_CHAIN),
                              IDX(0, DNAC_P2C_COL_IS_FOLD),
                              IDX(FIRST_FOLD, DNAC_P2C_COL_IS_FOLD),
                              IDX(FIRST_FOLD, DNAC_P2C_COL_IS_CHAIN) };
        const uint64_t v[4] = { 0, 1, 0, 1 };
        n3_case("prefix_order", DNAC_P2C_DEFECT_PREFIX_ORDER, i, v, 4);
    }
    { /* 5 type counts — retype the LAST chain row as a fold row: order stays
       *   non-decreasing, only the counts move (11 chain / 12 fold). */
        const size_t i[2] = { IDX(LAST_CHAIN, DNAC_P2C_COL_IS_CHAIN),
                              IDX(LAST_CHAIN, DNAC_P2C_COL_IS_FOLD) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("type_count", DNAC_P2C_DEFECT_TYPE_COUNT, i, v, 2);
    }
    { /* 6a step one-hot — a scheduled row with NO step. */
        const size_t i[1] = { IDX(5, dnac_p2c_col_pos(5)) };
        const uint64_t v[1] = { 0 };
        n3_case("pos_missing", DNAC_P2C_DEFECT_POS_ONEHOT, i, v, 1);
    }
    { /* 6b step one-hot — a PADDING row claiming a step (it would then gate
       *   the row-index-dependent forms after the walk ended). */
        const size_t i[1] = { IDX(FIRST_PAD + 1, dnac_p2c_col_pos(0)) };
        const uint64_t v[1] = { 1 };
        n3_case("pos_on_padding", DNAC_P2C_DEFECT_POS_ONEHOT, i, v, 1);
    }
    { /* 7 multiplication count — one chain multiply dropped (A2-F4's
       *   "handoff-as-copy drops a bit's factor" class: the count identity is
       *   precisely what catches a missing multiply). */
        const size_t i[1] = { IDX(0, DNAC_P2C_COL_IS_CHAINPAIR) };
        const uint64_t v[1] = { 0 };
        n3_case("mulcount", DNAC_P2C_DEFECT_MULCOUNT, i, v, 1);
    }
    { /* 8 chainpair placement — MOVE a pair gate onto the handoff row. The
       *   count is preserved, so check 7 passes and only placement fires. */
        const size_t i[2] = { IDX(0, DNAC_P2C_COL_IS_CHAINPAIR),
                              IDX(LAST_CHAIN, DNAC_P2C_COL_IS_CHAINPAIR) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("chainpair_moved", DNAC_P2C_DEFECT_CHAINPAIR, i, v, 2);
    }
    { /* 9a handoff cleared — the chain→fold seam (and C4's f_init boundary,
       *   the A2-F2 CRITICAL) would never be gated. */
        const size_t i[1] = { IDX(LAST_CHAIN, DNAC_P2C_COL_IS_HANDOFF) };
        const uint64_t v[1] = { 0 };
        n3_case("handoff_cleared", DNAC_P2C_DEFECT_HANDOFF, i, v, 1);
    }
    { /* 9b handoff duplicated — two f_init boundaries. */
        const size_t i[1] = { IDX(0, DNAC_P2C_COL_IS_HANDOFF) };
        const uint64_t v[1] = { 1 };
        n3_case("handoff_duplicated", DNAC_P2C_DEFECT_HANDOFF, i, v, 1);
    }
    { /* 10a foldpair cleared — an x0 recurrence step unenforced. */
        const size_t i[1] = { IDX(FIRST_FOLD, DNAC_P2C_COL_IS_FOLDPAIR) };
        const uint64_t v[1] = { 0 };
        n3_case("foldpair_cleared", DNAC_P2C_DEFECT_FOLDPAIR, i, v, 1);
    }
    { /* 10b foldpair on the LAST fold row — the design states that row has no
       *   successor x0 (§0.5 :374-376); a gate there would constrain g' on a
       *   padding row. */
        const size_t i[1] = { IDX(FIRST_PAD - 1, DNAC_P2C_COL_IS_FOLDPAIR) };
        const uint64_t v[1] = { 1 };
        n3_case("foldpair_last", DNAC_P2C_DEFECT_FOLDPAIR, i, v, 1);
    }
    { /* 11 terminal moved off the FIRST padding row — C5's `f ==
       *    final_poly[0]` would read a row the fold transition never wrote
       *    (the P2a-i3 last-row class). */
        const size_t i[2] = { IDX(FIRST_PAD, DNAC_P2C_COL_IS_TERMINAL),
                              IDX(FIRST_PAD + 1, DNAC_P2C_COL_IS_TERMINAL) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("terminal_moved", DNAC_P2C_DEFECT_TERMINAL, i, v, 2);
    }
    { /* 12a roll-in slot cleared — count check. */
        const size_t i[1] = { IDX(FIRST_FOLD + 1, DNAC_P2C_COL_IS_ROLLIN) };
        const uint64_t v[1] = { 0 };
        n3_case("rollin_cleared", DNAC_P2C_DEFECT_ROLLIN, i, v, 1);
    }
    { /* 12b roll-in slot MOVED to an unpinned phase (count preserved) — the
       *    D1 divergence: a roll-in may exist ONLY where the cfg pins one. */
        const size_t i[2] = { IDX(FIRST_FOLD + 1, DNAC_P2C_COL_IS_ROLLIN),
                              IDX(FIRST_FOLD + 2, DNAC_P2C_COL_IS_ROLLIN) };
        const uint64_t v[2] = { 0, 1 };
        n3_case("rollin_moved", DNAC_P2C_DEFECT_ROLLIN, i, v, 2);
    }
    { /* 12c roll-in slot on a PADDING row (count changes too, but the point is
       *    that no non-fold row may carry one). */
        const size_t i[1] = { IDX(FIRST_PAD, DNAC_P2C_COL_IS_ROLLIN) };
        const uint64_t v[1] = { 1 };
        n3_case("rollin_on_padding", DNAC_P2C_DEFECT_ROLLIN, i, v, 1);
    }
    { /* 13a g_pow2 zeroed on a chain row — x0's accumulator would multiply by
       *    (0 - 1) instead of (G_j - 1). G_j is never 0, so this is a real
       *    mutation. */
        const size_t i[1] = { IDX(3, DNAC_P2C_COL_G_POW2) };
        const uint64_t v[1] = { 0 };
        n3_case("gpow2_zeroed", DNAC_P2C_DEFECT_GPOW2, i, v, 1);
    }
    { /* 13b g_pow2 present on a fold row. */
        const size_t i[1] = { IDX(FIRST_FOLD, DNAC_P2C_COL_G_POW2) };
        const uint64_t v[1] = { 1 };
        n3_case("gpow2_off_chain", DNAC_P2C_DEFECT_GPOW2, i, v, 1);
    }
    { /* 13c g_pow2 = the WRONG generator (G_{j+1} on chain row j) — the exact
       *    off-by-one that would fold at a squared x0. */
        const size_t i[1] = { IDX(3, DNAC_P2C_COL_G_POW2) };
        const uint64_t v[1] = { gold_fp_to_u64(gold_fp_two_adic_generator(
            (unsigned)(DNAC_P2C_REF_LGMH - 4))) };
        n3_case("gpow2_shifted", DNAC_P2C_DEFECT_GPOW2, i, v, 1);
    }

    /* Validator argument fail-close. */
    dnac_p2c_table_defect_t d = DNAC_P2C_DEFECT_NONE;
    CHECK(dnac_p2c_table_validate(ref, NULL, REF_ROWS, &d) ==
              DNAC_P2C_TABLE_ERR_PARAM,
          "N3: validate(NULL cells)");
    CHECK(dnac_p2c_table_validate(NULL, g_good, REF_ROWS, &d) ==
              DNAC_P2C_TABLE_ERR_PARAM,
          "N3: validate(NULL cfg)");
    CHECK(dnac_p2c_table_validate(ref, g_good, REF_ROWS - 1, &d) ==
              DNAC_P2C_TABLE_ERR_PARAM,
          "N3: validate(wrong row count)");
    /* The out-parameter is optional. */
    CHECK(dnac_p2c_table_validate(ref, g_good, REF_ROWS, NULL) ==
              DNAC_P2C_TABLE_OK,
          "N3: validate(NULL defect out) on a clean table");
}

/* ==========================================================================
 * N4 — generator / cfg-gate fail-close (design §0.5 gates G1, G2, G3, G7 and
 * the roll-in schedule rules)
 * ======================================================================== */
static void n4_failclose(void)
{
    static uint64_t out[REF_CELLS];
    const dnac_p2c_table_cfg_t *ref = dnac_p2c_ref_cfg();

    CHECK(dnac_p2c_table_rows(NULL) == 0, "N4: rows(NULL) != 0");
    CHECK(dnac_p2c_chain_rows(NULL) == 0, "N4: chain_rows(NULL) != 0");
    CHECK(dnac_p2c_fold_rows(NULL) == 0, "N4: fold_rows(NULL) != 0");
    CHECK(dnac_p2c_table_generate(NULL, out, REF_CELLS) ==
              DNAC_P2C_TABLE_ERR_PARAM,
          "N4: generate(NULL cfg)");
    CHECK(dnac_p2c_table_generate(ref, NULL, REF_CELLS) ==
              DNAC_P2C_TABLE_ERR_PARAM,
          "N4: generate(NULL out)");
    CHECK(dnac_p2c_table_generate(ref, out, REF_CELLS - 1) ==
              DNAC_P2C_TABLE_ERR_CAPACITY,
          "N4: generate(short buffer)");

    dnac_p2c_row_t rec;
    CHECK(dnac_p2c_table_row(ref, REF_ROWS, &rec) == DNAC_P2C_TABLE_ERR_PARAM,
          "N4: row(index == rows)");
    CHECK(dnac_p2c_table_row(ref, 0, NULL) == DNAC_P2C_TABLE_ERR_PARAM,
          "N4: row(NULL out)");

    /* Each rejected cfg below differs from the reference ONLY in the field(s)
     * its name calls out, so the rejection cannot be blamed on an unrelated
     * defect. Two entries necessarily move two fields — "R = 0" needs
     * lgmh == log_blowup, and "R < 0" needs log_blowup > lgmh; those are the
     * degenerate shapes gate G7 exists for (design §0.5 :286-288). */
    struct {
        const char          *what;
        dnac_p2c_table_cfg_t cfg;
    } bad[] = {
        /* G1 — only arity-2 is ported (design §0.1 :63-66). */
        { "arity 2", { 13, 2, 0, 2, 0, NULL, 100 } },
        { "arity 0", { 13, 2, 0, 0, 0, NULL, 100 } },
        /* G2 — lfpl != 0 needs the terminal-x machinery (§0.1 :67-72). */
        { "lfpl 1", { 13, 2, 1, 1, 0, NULL, 100 } },
        /* G3 — lgmh > two-adicity (fri_verifier.c:689-691). */
        { "lgmh 33", { 33, 2, 0, 1, 0, NULL, 100 } },
        { "lgmh 64", { 64, 2, 0, 1, 0, NULL, 100 } },
        /* G7 — lgmh < 2 leaves no chain anchor (n_chain = lgmh-1 = 0). The
         * lgmh gate is evaluated before the R-underflow gate, so these reject
         * on the anchor rule and not on R. */
        { "lgmh 1", { 1, 2, 0, 1, 0, NULL, 100 } },
        { "lgmh 0", { 0, 2, 0, 1, 0, NULL, 100 } },
        /* G7 — R underflow: lgmh must exceed log_blowup + lfpl. */
        { "R = 0", { 2, 2, 0, 1, 0, NULL, 100 } },
        { "R < 0", { 3, 5, 0, 1, 0, NULL, 100 } },
        /* D2 — num_queries is EXACT and never 0 (fri_verifier.c:686-688). */
        { "queries 0", { 13, 2, 0, 1, 0, NULL, 0 } },
        { "queries huge", { 13, 2, 0, 1, 0, NULL, DNAC_P2C_MAX_QUERIES + 1 } },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        CHECK(dnac_p2c_table_rows(&bad[i].cfg) == 0, "N4: cfg '%s' ACCEPTED",
              bad[i].what);
        CHECK(dnac_p2c_table_generate(&bad[i].cfg, out, REF_CELLS) ==
                  DNAC_P2C_TABLE_ERR_PARAM,
              "N4: generate(cfg '%s') did not fail closed", bad[i].what);
    }

    /* Roll-in schedule rules (fri_air_table.h cfg contract; the monotone sweep
     * at fri_verifier.c:600-605 is what makes DESCENDING a requirement). */
    const size_t asc[2] = { 9, 11 };
    const size_t eq[2] = { 11, 11 };
    const size_t too_high[1] = { 13 };  /* == lgmh; reachable max is lgmh-1 */
    const size_t too_low[1] = { 1 };    /* < log_blowup + lfpl == 2         */
    const size_t ok_edge[2] = { 12, 2 }; /* the two extremes, descending     */
    struct {
        const char          *what;
        dnac_p2c_table_cfg_t cfg;
        int                  accept;
    } rollin[] = {
        { "ascending", { 13, 2, 0, 1, 2, asc, 100 }, 0 },
        { "equal", { 13, 2, 0, 1, 2, eq, 100 }, 0 },
        { "height == lgmh", { 13, 2, 0, 1, 1, too_high, 100 }, 0 },
        { "height below final", { 13, 2, 0, 1, 1, too_low, 100 }, 0 },
        { "NULL array", { 13, 2, 0, 1, 1, NULL, 100 }, 0 },
        { "more than R", { 13, 2, 0, 1, 12, NULL, 100 }, 0 },
        { "both edges", { 13, 2, 0, 1, 2, ok_edge, 100 }, 1 },
    };
    for (size_t i = 0; i < sizeof(rollin) / sizeof(rollin[0]); i++) {
        const size_t rows = dnac_p2c_table_rows(&rollin[i].cfg);
        if (rollin[i].accept) {
            CHECK(rows == REF_ROWS, "N4: roll-in cfg '%s' REJECTED",
                  rollin[i].what);
        } else {
            CHECK(rows == 0, "N4: roll-in cfg '%s' ACCEPTED", rollin[i].what);
        }
    }

    /* The accepted edge case must also produce a table the validator likes:
     * phases lgmh-1-h = 0 (height 12) and 10 (height 2 == the final height,
     * the LAST fold phase — the PLACEMENT is natively legal
     * (fri_verifier.c:600-605), but note OBL-P2c-4 (fri_air.h, FLEET 022
     * A1-F3): both natives force the reduced-opening VALUE at height ==
     * log_blowup to be ZERO (fri_verifier.c:480-487; 82cfad73 verifier.rs
     * :647-651) — a rule that lives in open_input, outside slice 1. The
     * composition must not bless a final-height roll-in before that slice
     * pins it. */
    {
        const dnac_p2c_table_cfg_t edge = { 13, 2, 0, 1, 2, ok_edge, 100 };
        static uint64_t t[REF_CELLS];
        CHECK(dnac_p2c_table_generate(&edge, t, REF_CELLS) ==
                  DNAC_P2C_TABLE_OK,
              "N4: edge roll-in generate");
        dnac_p2c_table_defect_t d = DNAC_P2C_DEFECT_NONE;
        CHECK(dnac_p2c_table_validate(&edge, t, REF_ROWS, &d) ==
                  DNAC_P2C_TABLE_OK,
              "N4: edge roll-in table rejected (defect %d)", (int)d);
        CHECK(t[(12 + 0) * P2C_COLS + DNAC_P2C_COL_IS_ROLLIN] == 1,
              "N4: no roll-in on fold phase 0");
        CHECK(t[(12 + 10) * P2C_COLS + DNAC_P2C_COL_IS_ROLLIN] == 1,
              "N4: no roll-in on the LAST fold phase");
    }
}

/* ==========================================================================
 * --print-root — the ORCHESTRATOR fills DNAC_P2C_PREP_ROOT_LANE* from this
 * ======================================================================== */
static int print_root(void)
{
    static uint64_t t[REF_CELLS];
    uint64_t lanes[4];
    if (dnac_p2c_table_generate(dnac_p2c_ref_cfg(), t, REF_CELLS) !=
        DNAC_P2C_TABLE_OK) {
        fprintf(stderr, "print-root: generate failed\n");
        return 1;
    }
    dnac_p2c_table_defect_t d = DNAC_P2C_DEFECT_NONE;
    if (dnac_p2c_table_validate(dnac_p2c_ref_cfg(), t, REF_ROWS, &d) !=
        DNAC_P2C_TABLE_OK) {
        fprintf(stderr, "print-root: the table FAILED its own validator "
                        "(defect %d) — refusing to print a root\n",
                (int)d);
        return 1;
    }
    if (!p2c_commit_table(t, REF_ROWS, lanes)) {
        fprintf(stderr, "print-root: LDE/commit pipeline failed\n");
        return 1;
    }
    printf("#define DNAC_P2C_PREP_ROOT_LANE0 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[0]);
    printf("#define DNAC_P2C_PREP_ROOT_LANE1 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[1]);
    printf("#define DNAC_P2C_PREP_ROOT_LANE2 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[2]);
    printf("#define DNAC_P2C_PREP_ROOT_LANE3 UINT64_C(0x%016" PRIx64 ")\n",
           lanes[3]);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--print-root") == 0) {
        return print_root();
    }

    printf("P2c PIN slice — FRI fold-walk preprocessed row-type table\n");
    t1_determinism();
    t2_all();
    t3_pin_kat();
    n3_validator_negatives();
    n4_failclose();

    printf("\nfri_air_table total  %27d checks\n", g_checks);
    printf("fri_air_table failed %27d\n", g_fails);
    if (g_fails == 0) {
        printf("\nP2c PIN GATE: GREEN\n");
        return 0;
    }
    fprintf(stderr, "\nP2c PIN GATE: RED\n");
    return 1;
}
