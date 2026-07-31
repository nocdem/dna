/**
 * @file test_mmcs_air_table.c
 * @brief P2b PIN slice gate — the preprocessed row-type table generator, the
 *        PIN-1 root constant (runtime KAT, shielded_domsep.h practice) and the
 *        PIN-2 evidence (prep_next = 1 is load-bearing, and its flip is
 *        DETECTED by the shipped verifier).
 *
 * Design: dnac/docs/plans/2026-07-28-p2b-mmcs-in-air-design.md §0.5 PIN-1 /
 * PIN-2, §4 item 2. No AIR is built in this slice — the AIR fixture below is a
 * MINIMAL pin harness, not the P2b circuit.
 *
 *   T1  generator determinism (reference config + a second config)
 *   T2  schedule shape: 4 leaf / 4 compress / 1 final / 7 filler, cells
 *       boolean, one row type per row
 *   T3  PIN-1 KAT: table → coset LDE (bitrev) → dnac_p2_mmcs_commit_mixed
 *       == DNAC_P2B_PREP_ROOT, and the comparator accepts it
 *   T4  PIN-2 round-trip: the table as the PREPROCESSED matrix of a real
 *       dnac_batch_prove → dnac_batch_verify (prep_next = 1), and the proof's
 *       own preprocessed commitment passes the PIN-1 comparator
 *   N1  comparator rejects a one-lane tamper
 *   N2  the SAME proof with an otherwise-identical prep_next = 0 descriptor is
 *       REJECTED (a: as-is; b: with the next-row openings trimmed away so the
 *       shape gate cannot be what rejects it)
 *   N3  the pin binds table CONTENTS: one flipped selector cell ⇒ another root
 *   N4  generator fail-close on bad arguments
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "../batch_prover.h"
#include "../field_goldilocks.h"
#include "../mmcs_air_table.h"
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

/* The pin's blowup MUST stay the shipped consensus blowup
 * (shielded_fri_params.h:138) — compile-time, so the two cannot drift. */
typedef char p2b_blowup_pin_assert
    [(DNAC_P2B_PREP_LOG_BLOWUP == (unsigned)DNAC_SHIELDED_FRI_LOG_BLOWUP) ? 1
                                                                         : -1];

#define REF_ROWS DNAC_P2B_REF_ROWS                     /* 16 */
#define REF_CELLS (REF_ROWS * DNAC_P2B_TABLE_COLS)     /* 48 */
#define REF_LDE_ROWS (REF_ROWS << DNAC_P2B_PREP_LOG_BLOWUP) /* 64 */
#define REF_LDE_CELLS (REF_LDE_ROWS * DNAC_P2B_TABLE_COLS)  /* 192 */

/* ==========================================================================
 * Shared helper: the SHIPPED preprocessed-commit pipeline
 * (batch_prover.c:807-825 with is_zk = 0: coset LDE bit-reversed at
 * log_blowup, then ONE mixed-height Poseidon2 MMCS commit).
 * ======================================================================== */
static int p2b_commit_table(const uint64_t *table, size_t rows,
                            uint64_t out_lanes[4])
{
    static uint64_t lde[REF_LDE_CELLS];
    const size_t lde_rows = rows << DNAC_P2B_PREP_LOG_BLOWUP;
    if (lde_rows * DNAC_P2B_TABLE_COLS > REF_LDE_CELLS) return 0;

    if (dnac_prover_coset_lde_bitrev(table, rows, DNAC_P2B_TABLE_COLS,
                                     DNAC_P2B_PREP_LOG_BLOWUP,
                                     GOLDILOCKS_GENERATOR,
                                     lde) != DNAC_PROVER_OK) {
        return 0;
    }
    const uint64_t *mats[1] = { lde };
    const size_t widths[1] = { DNAC_P2B_TABLE_COLS };
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
    const dnac_p2b_table_cfg_t *ref = dnac_p2b_ref_cfg();

    CHECK(dnac_p2b_table_rows(ref) == REF_ROWS,
          "T1: reference rows %zu != %zu", dnac_p2b_table_rows(ref),
          (size_t)REF_ROWS);
    CHECK(dnac_p2b_table_generate(ref, a, REF_CELLS) == DNAC_P2B_TABLE_OK,
          "T1: reference generate #1");
    CHECK(dnac_p2b_table_generate(ref, b, REF_CELLS) == DNAC_P2B_TABLE_OK,
          "T1: reference generate #2");
    CHECK(memcmp(a, b, sizeof(a)) == 0, "T1: reference table NOT deterministic");

    /* Second config: widths {4,4} ⇒ total_width 8, an EXACT multiple of the
     * rate ⇒ 2 leaf rows (no trailing permutation, poseidon2_mmcs.c:63),
     * + depth 3 + 1 final = 6 ⇒ padded height 8. */
    const size_t w2[2] = { 4, 4 };
    const dnac_p2b_table_cfg_t cfg2 = { 2, w2, 3 };
    static uint64_t c[8 * DNAC_P2B_TABLE_COLS], d[8 * DNAC_P2B_TABLE_COLS];
    CHECK(dnac_p2b_table_rows(&cfg2) == 8, "T1: cfg2 rows %zu != 8",
          dnac_p2b_table_rows(&cfg2));
    CHECK(dnac_p2b_table_generate(&cfg2, c, sizeof(c) / sizeof(c[0])) ==
              DNAC_P2B_TABLE_OK,
          "T1: cfg2 generate #1");
    CHECK(dnac_p2b_table_generate(&cfg2, d, sizeof(d) / sizeof(d[0])) ==
              DNAC_P2B_TABLE_OK,
          "T1: cfg2 generate #2");
    CHECK(memcmp(c, d, sizeof(c)) == 0, "T1: cfg2 table NOT deterministic");

    /* The exact-multiple residue class is what distinguishes the two: 2 leaf
     * rows here vs 4 for total_width 13. */
    size_t leaf2 = 0;
    for (size_t r = 0; r < 8; r++) {
        leaf2 += c[r * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_LEAF] ? 1 : 0;
    }
    CHECK(leaf2 == 2, "T1: cfg2 leaf rows %zu != 2 (total_width 8 %% 4 == 0)",
          leaf2);
}

/* ==========================================================================
 * T2 — schedule shape for the reference config
 * ======================================================================== */
static void t2_shape(void)
{
    static uint64_t t[REF_CELLS];
    const dnac_p2b_table_cfg_t *ref = dnac_p2b_ref_cfg();
    if (dnac_p2b_table_generate(ref, t, REF_CELLS) != DNAC_P2B_TABLE_OK) {
        CHECK(0, "T2: generate failed");
        return;
    }

    size_t leaf = 0, comp = 0, fin = 0, filler = 0;
    int boolean_ok = 1, exclusive_ok = 1, order_ok = 1;
    for (size_t r = 0; r < REF_ROWS; r++) {
        const uint64_t *row = &t[r * DNAC_P2B_TABLE_COLS];
        size_t set = 0;
        for (size_t k = 0; k < DNAC_P2B_TABLE_COLS; k++) {
            if (row[k] != 0 && row[k] != 1) boolean_ok = 0;
            if (row[k] >= GOLDILOCKS_P) boolean_ok = 0;
            if (row[k] == 1) set++;
        }
        if (set > 1) exclusive_ok = 0;
        if (row[DNAC_P2B_COL_IS_LEAF]) {
            leaf++;
            if (comp || fin) order_ok = 0;
        } else if (row[DNAC_P2B_COL_IS_COMPRESS]) {
            comp++;
            if (fin) order_ok = 0;
        } else if (row[DNAC_P2B_COL_IS_FINAL]) {
            fin++;
        } else {
            filler++;
        }
    }

    /* total_width = 8 + 5 = 13; 13 % 4 != 0 ⇒ 3 full blocks + 1 partial ⇒ 4
     * permutations ⇒ 4 leaf rows (poseidon2_mmcs.c:53-69). */
    CHECK(leaf == 4, "T2: leaf rows %zu != 4", leaf);
    CHECK(comp == DNAC_P2B_REF_DEPTH, "T2: compress rows %zu != %zu", comp,
          DNAC_P2B_REF_DEPTH);
    CHECK(fin == 1, "T2: final rows %zu != 1", fin);
    CHECK(filler == 7, "T2: filler rows %zu != 7", filler);
    CHECK(boolean_ok, "T2: a cell is neither 0 nor 1 (or non-canonical)");
    CHECK(exclusive_ok, "T2: two row types set on one row");
    CHECK(order_ok, "T2: row types out of schedule order");
}

/* ==========================================================================
 * T3 — PIN-1 KAT (constant vs generator) + N1 + N3
 * ======================================================================== */
static void t3_pin_kat(void)
{
    static uint64_t t[REF_CELLS];
    const dnac_p2b_table_cfg_t *ref = dnac_p2b_ref_cfg();
    if (dnac_p2b_table_generate(ref, t, REF_CELLS) != DNAC_P2B_TABLE_OK) {
        CHECK(0, "T3: generate failed");
        return;
    }

    uint64_t lanes[4];
    if (!p2b_commit_table(t, REF_ROWS, lanes)) {
        CHECK(0, "T3: LDE/commit pipeline failed");
        return;
    }
    static const uint64_t pinned[4] = DNAC_P2B_PREP_ROOT;
    for (int k = 0; k < 4; k++) {
        CHECK(lanes[k] == pinned[k],
              "T3: PIN-1 lane %d: derived 0x%016" PRIx64
              " != pinned 0x%016" PRIx64,
              k, lanes[k], pinned[k]);
    }
    CHECK(dnac_p2b_prep_root_check(lanes) == DNAC_P2B_TABLE_OK,
          "T3: comparator rejected the derived root");
    printf("  PIN-1 root = { 0x%016" PRIx64 ", 0x%016" PRIx64
           ", 0x%016" PRIx64 ", 0x%016" PRIx64 " }\n",
           lanes[0], lanes[1], lanes[2], lanes[3]);

    /* N1 — one tampered lane on an otherwise-correct root. */
    for (int k = 0; k < 4; k++) {
        uint64_t bad[4];
        memcpy(bad, lanes, sizeof(bad));
        bad[k] ^= 1;
        CHECK(dnac_p2b_prep_root_check(bad) ==
                  DNAC_P2B_TABLE_ERR_ROOT_MISMATCH,
              "N1: comparator accepted a tampered lane %d", k);
    }
    CHECK(dnac_p2b_prep_root_check(NULL) == DNAC_P2B_TABLE_ERR_PARAM,
          "N1: comparator on NULL must be PARAM");

    /* N3 — the pin binds CONTENTS: clear the is_final row's selector (the
     * vacuity attack shape: a gate that never fires) and re-run the SAME
     * pipeline. Everything else is byte-identical. */
    static uint64_t tampered[REF_CELLS];
    memcpy(tampered, t, sizeof(tampered));
    size_t fin_row = (size_t)-1;
    for (size_t r = 0; r < REF_ROWS; r++) {
        if (tampered[r * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_FINAL] == 1) {
            fin_row = r;
            break;
        }
    }
    CHECK(fin_row != (size_t)-1, "N3: no is_final row to tamper");
    if (fin_row != (size_t)-1) {
        tampered[fin_row * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_FINAL] = 0;
        CHECK(memcmp(tampered, t, sizeof(t)) != 0,
              "N3: tamper did not change the table");
        uint64_t bad_lanes[4];
        if (p2b_commit_table(tampered, REF_ROWS, bad_lanes)) {
            CHECK(memcmp(bad_lanes, lanes, sizeof(lanes)) != 0,
                  "N3: a flipped selector cell produced the SAME root");
            CHECK(dnac_p2b_prep_root_check(bad_lanes) ==
                      DNAC_P2B_TABLE_ERR_ROOT_MISMATCH,
                  "N3: comparator accepted the tampered table's root");
        } else {
            CHECK(0, "N3: LDE/commit pipeline failed on the tampered table");
        }
    }
}

/* ==========================================================================
 * T4 — PIN-2 round-trip through the SHIPPED batched prover/verifier
 *
 * Minimal pin harness (NOT the P2b AIR): main_width 1, no lookups, is_zk = 0,
 * salt_elems = 0. The last two are MANDATORY, not convenience —
 * salted+preprocessed is fail-closed at batch_prover.c:585-589 and the
 * recursion envelope is non-hiding by user lock.
 *
 * The AIR reads BOTH preprocessed windows with non-zero coefficients:
 *   C0..C2  booleanity of each LOCAL selector cell   (degree 2)
 *   C3      main[0] == 1·prep_next[0] + 2·prep_next[1] + 4·prep_next[2]
 * C3 is what makes PIN-2 load-bearing: under prep_next = 0 the verifier's
 * next-row window is all zeros (batch_verify.c:696-707) while the prover folds
 * the REAL next row (batch_prover.c:311-313).
 * ======================================================================== */
static void p2b_pin_air_eval(dnac_stark_folder_t *f)
{
    if (f->prep_width != DNAC_P2B_TABLE_COLS || f->preprocessed_local == NULL ||
        f->preprocessed_next == NULL) {
        return; /* fail-close: emit nothing rather than read a short window */
    }
    for (size_t k = 0; k < DNAC_P2B_TABLE_COLS; k++) {
        const gold_fp2_t c = f->preprocessed_local[k];
        dnac_stark_folder_assert_zero(
            f, gold_fp2_mul(c, gold_fp2_sub(c, gold_fp2_one())));
    }
    const gold_fp2_t two = gold_fp2_from_base(gold_fp_from_u64(2));
    const gold_fp2_t four = gold_fp2_from_base(gold_fp_from_u64(4));
    gold_fp2_t acc = f->preprocessed_next[DNAC_P2B_COL_IS_LEAF];
    acc = gold_fp2_add(
        acc, gold_fp2_mul(two, f->preprocessed_next[DNAC_P2B_COL_IS_COMPRESS]));
    acc = gold_fp2_add(
        acc, gold_fp2_mul(four, f->preprocessed_next[DNAC_P2B_COL_IS_FINAL]));
    dnac_stark_folder_assert_eq(f, f->trace_local[0], acc);
}

static void t4_roundtrip_and_pin2(void)
{
    static uint64_t table[REF_CELLS];
    const dnac_p2b_table_cfg_t *ref = dnac_p2b_ref_cfg();
    if (dnac_p2b_table_generate(ref, table, REF_CELLS) != DNAC_P2B_TABLE_OK) {
        CHECK(0, "T4: generate failed");
        return;
    }

    /* Main witness: m[r] = 1·P[r+1][0] + 2·P[r+1][1] + 4·P[r+1][2], the next
     * row taken CYCLICALLY — which is exactly what the trace polynomial at
     * g·x gives (the prover uses the same wrapped next row,
     * batch_prover.c:305). */
    static uint64_t main_trace[REF_ROWS];
    for (size_t r = 0; r < REF_ROWS; r++) {
        const uint64_t *nx = &table[((r + 1) % REF_ROWS) * DNAC_P2B_TABLE_COLS];
        main_trace[r] = nx[DNAC_P2B_COL_IS_LEAF] +
                        2 * nx[DNAC_P2B_COL_IS_COMPRESS] +
                        4 * nx[DNAC_P2B_COL_IS_FINAL];
    }

    dnac_batch_vinstance_t inst;
    memset(&inst, 0, sizeof(inst));
    inst.air.main_width = 1;
    inst.air.num_public_values = 0;
    inst.air.main_next = 0; /* the ONLY next-row read is preprocessed */
    inst.air.air_eval = p2b_pin_air_eval;
    inst.preprocessed_width = DNAC_P2B_TABLE_COLS;
    inst.prep_next = 1; /* PIN-2 */
    inst.degree_bits = 4; /* 2^4 == REF_ROWS, is_zk = 0 */
    inst.log_num_qc = 0;  /* max constraint degree 2 ⇒ 1 quotient chunk */

    dnac_batch_pwitness_t wit;
    memset(&wit, 0, sizeof(wit));
    wit.main_trace = main_trace;
    wit.prep_trace = table;

    /* Fixture FRI params (the batch_proof.json scenarios' set — log_blowup 2
     * matches DNAC_P2B_PREP_LOG_BLOWUP, which is what makes the proof's
     * preprocessed commitment comparable to the pin). */
    dnac_fri_params_t params;
    memset(&params, 0, sizeof(params));
    params.log_blowup = DNAC_P2B_PREP_LOG_BLOWUP;
    params.log_final_poly_len = 0;
    params.max_log_arity = 1;
    params.num_queries = 2;
    params.commit_proof_of_work_bits = 0;
    params.query_proof_of_work_bits = 0;

    dnac_batch_proof_t *p = NULL;
    const dnac_prover_status_t pst =
        dnac_batch_prove(&inst, &wit, 1, 0, &params, 0, NULL, 0, NULL, 0, NULL,
                         0, 0, &p);
    CHECK(pst == DNAC_PROVER_OK, "T4: dnac_batch_prove -> %d", (int)pst);
    if (pst != DNAC_PROVER_OK || p == NULL) return;

    dnac_batch_vcommits_t commits;
    dnac_batch_proof_commits(p, &commits);
    uint32_t nprep = 0;
    const uint32_t *prep_map = dnac_batch_proof_prep_map(p, &nprep);
    const dnac_batch_vopened_t *op0 = dnac_batch_proof_opened(p, 0);
    const dnac_fri_proof_t *fri = dnac_batch_proof_fri(p);

    CHECK(nprep == 1 && prep_map != NULL && prep_map[0] == 0,
          "T4: preprocessed map (n=%u)", nprep);
    CHECK(commits.preprocessed_commit != NULL,
          "T4: proof carries no preprocessed commitment");
    CHECK(op0 != NULL && op0->preprocessed_next_len == DNAC_P2B_TABLE_COLS,
          "T4: preprocessed_next NOT opened (prep_next = 1 must open g·ζ)");
    if (op0 == NULL || prep_map == NULL) {
        dnac_batch_proof_free(p);
        return;
    }

    dnac_batch_vopened_t opened = *op0;
    dnac_batch_verify_out_t vout;
    memset(&vout, 0, sizeof(vout));
    const dnac_batch_verify_status_t vst =
        dnac_batch_verify(&inst, &opened, 1, 0, &commits, prep_map, nprep,
                          &params, 0, 0, fri, NULL, &vout);
    CHECK(vst == DNAC_BV_OK, "T4: dnac_batch_verify -> %d", (int)vst);

    /* PIN-1 on the REAL proof: the preprocessed commitment a shipped prover
     * emitted for this table is the pinned constant. */
    if (commits.preprocessed_commit != NULL) {
        uint64_t lanes[4];
        for (int k = 0; k < 4; k++) {
            lanes[k] = gold_fp_to_u64(commits.preprocessed_commit[k]);
        }
        CHECK(dnac_p2b_prep_root_check(lanes) == DNAC_P2B_TABLE_OK,
              "T4: the proof's preprocessed root != DNAC_P2B_PREP_ROOT");
    }

    /* ── N2a — the SAME proof, prep_next flipped to 0 ────────────────────
     * Everything else identical. Observed status: DNAC_BV_ERR_SHAPE (-2) —
     * the shape gate wants preprocessed_next_len == 0 when the AIR does not
     * declare the next-row window (batch_priming.c:356-363). */
    {
        dnac_batch_vinstance_t flipped = inst;
        flipped.prep_next = 0;
        dnac_batch_vopened_t op = *op0;
        const dnac_batch_verify_status_t st =
            dnac_batch_verify(&flipped, &op, 1, 0, &commits, prep_map, nprep,
                              &params, 0, 0, fri, NULL, NULL);
        CHECK(st != DNAC_BV_OK, "N2a: prep_next = 0 descriptor was ACCEPTED");
        printf("  N2a: prep_next = 0 (proof unchanged)      -> status %d\n",
               (int)st);
    }

    /* ── N2b — prep_next = 0 AND the next-row openings trimmed away, so the
     * shape gate is NOT what rejects. This is the shape a malicious prover
     * would actually ship; it must still fail, because the verifier's opening
     * schedule (batch_verify.c:393, :470, :586) and therefore the whole
     * Fiat-Shamir transcript diverge from the proof. Observed status:
     * DNAC_BV_ERR_FRI (-6). */
    {
        dnac_batch_vinstance_t flipped = inst;
        flipped.prep_next = 0;
        dnac_batch_vopened_t op = *op0;
        op.preprocessed_next = NULL;
        op.preprocessed_next_len = 0;
        const dnac_batch_verify_status_t st =
            dnac_batch_verify(&flipped, &op, 1, 0, &commits, prep_map, nprep,
                              &params, 0, 0, fri, NULL, NULL);
        CHECK(st != DNAC_BV_OK,
              "N2b: prep_next = 0 with trimmed openings was ACCEPTED");
        CHECK(st != DNAC_BV_ERR_SHAPE,
              "N2b: rejected by the SHAPE gate — the negative would be "
              "vacuous as a PIN-2 witness");
        printf("  N2b: prep_next = 0 (openings trimmed)     -> status %d\n",
               (int)st);
    }

    dnac_batch_proof_free(p);

    /* ── N5 — the harness is NOT vacuous. The ONLY constraint the main trace
     * appears in is C3, the prep_next consumer, so a one-bit main tamper can
     * fail the self-verify only if that constraint is genuinely live (the
     * test_batch_prover N1 pattern). Without this, an air_eval that emitted
     * nothing would make T4 and both N2 cases look equally green. */
    {
        dnac_batch_proof_t *q = NULL;
        main_trace[3] ^= 1;
        const dnac_prover_status_t st =
            dnac_batch_prove(&inst, &wit, 1, 0, &params, 0, NULL, 0, NULL, 0,
                             NULL, 0, 0, &q);
        CHECK(st == DNAC_PROVER_ERR_VERIFY,
              "N5: tampered main trace proved anyway (-> %d) — the "
              "prep_next constraint is VACUOUS", (int)st);
        main_trace[3] ^= 1;
        if (st == DNAC_PROVER_OK) dnac_batch_proof_free(q);
    }
}

/* ==========================================================================
 * N4 — generator fail-close
 * ======================================================================== */
static void n4_failclose(void)
{
    static uint64_t out[REF_CELLS];
    const dnac_p2b_table_cfg_t *ref = dnac_p2b_ref_cfg();
    const size_t good_w[2] = { 8, 5 };

    CHECK(dnac_p2b_table_rows(NULL) == 0, "N4: rows(NULL) != 0");
    CHECK(dnac_p2b_table_generate(NULL, out, REF_CELLS) ==
              DNAC_P2B_TABLE_ERR_PARAM,
          "N4: generate(NULL cfg)");
    CHECK(dnac_p2b_table_generate(ref, NULL, REF_CELLS) ==
              DNAC_P2B_TABLE_ERR_PARAM,
          "N4: generate(NULL out)");
    CHECK(dnac_p2b_table_generate(ref, out, REF_CELLS - 1) ==
              DNAC_P2B_TABLE_ERR_CAPACITY,
          "N4: generate(short buffer)");

    const dnac_p2b_table_cfg_t null_widths = { 2, NULL, 4 };
    CHECK(dnac_p2b_table_rows(&null_widths) == 0, "N4: NULL widths");

    const size_t zero_w[2] = { 8, 0 };
    const dnac_p2b_table_cfg_t zero_width = { 2, zero_w, 4 };
    CHECK(dnac_p2b_table_rows(&zero_width) == 0, "N4: zero width accepted");
    CHECK(dnac_p2b_table_generate(&zero_width, out, REF_CELLS) ==
              DNAC_P2B_TABLE_ERR_PARAM,
          "N4: generate(zero width)");

    const dnac_p2b_table_cfg_t zero_mats = { 0, good_w, 4 };
    CHECK(dnac_p2b_table_rows(&zero_mats) == 0, "N4: zero matrices accepted");

    const dnac_p2b_table_cfg_t many_mats = { DNAC_P2B_MAX_MATRICES + 1, good_w,
                                             4 };
    CHECK(dnac_p2b_table_rows(&many_mats) == 0, "N4: too many matrices");

    const dnac_p2b_table_cfg_t zero_depth = { 2, good_w, 0 };
    CHECK(dnac_p2b_table_rows(&zero_depth) == 0, "N4: zero depth accepted");

    const dnac_p2b_table_cfg_t deep = { 2, good_w, DNAC_P2B_MAX_DEPTH + 1 };
    CHECK(dnac_p2b_table_rows(&deep) == 0, "N4: absurd depth accepted");
    CHECK(dnac_p2b_table_generate(&deep, out, REF_CELLS) ==
              DNAC_P2B_TABLE_ERR_PARAM,
          "N4: generate(absurd depth)");

    const size_t huge_w[1] = { DNAC_P2B_MAX_TOTAL_WIDTH + 1 };
    const dnac_p2b_table_cfg_t huge = { 1, huge_w, 4 };
    CHECK(dnac_p2b_table_rows(&huge) == 0, "N4: absurd width accepted");
}

/* ==========================================================================
 * T-RESERVE — the TERMINALITY RESERVE (mmcs_air_table.h).
 *
 * The table always leaves at least one all-zero padding row, because the AIR
 * requires the final row to have a successor (mmcs_air.c:96-101). This gate
 * makes the property PERMANENT: it is written as an invariant over a sweep, so
 * "reclaiming" the row — reverting `p2b_pad_pow2(used + 1)` to `(used)` — fails
 * here rather than surfacing later as an AIR that silently refuses a config.
 *
 * The historical trigger is the FRI commit phase's LAST round: leaf 1 (the
 * 2*arity-lane leaf) at depth log_blowup + log_final_poly_len == 2 gives
 * used == 4, an exact power of two, which the AIR rejected outright. That is
 * the (4, 2) row of the sweep below.
 * ======================================================================== */
static void t_reserve(void)
{
    /* (a) INVARIANT, swept: every accepted config has a padding row, i.e. the
     * padded height is STRICTLY greater than the scheduled rows. Swept over
     * both sponge residue classes and every depth up to 12. */
    size_t exact_cases = 0;
    for (size_t total = 1; total <= 12; total++) {
        const size_t w[1] = { total };
        const size_t leaf = (total % DNAC_P2B_SPONGE_RATE == 0)
                                ? total / DNAC_P2B_SPONGE_RATE
                                : total / DNAC_P2B_SPONGE_RATE + 1;
        for (size_t depth = 1; depth <= 12; depth++) {
            const dnac_p2b_table_cfg_t cfg = { 1, w, depth };
            const size_t used = leaf + depth + 1;
            const size_t rows = dnac_p2b_table_rows(&cfg);
            size_t pow2 = DNAC_P2B_MIN_ROWS;

            CHECK(rows > used,
                  "T-RESERVE: total %zu depth %zu -> %zu rows for %zu "
                  "scheduled — no padding row, the AIR will refuse it", total,
                  depth, rows, used);
            /* and the height is still the smallest power of two that fits. */
            while (pow2 < used + 1) pow2 <<= 1;
            CHECK(rows == pow2,
                  "T-RESERVE: total %zu depth %zu -> %zu rows, expected %zu",
                  total, depth, rows, pow2);
            /* count the cases the OLD rule would have made exact-fit — these
             * are precisely the configs the reserve rescues. */
            {
                size_t old = DNAC_P2B_MIN_ROWS;
                while (old < used) old <<= 1;
                if (old == used) exact_cases++;
            }
        }
    }
    CHECK(exact_cases > 0,
          "T-RESERVE: the sweep contains NO exact-fit config — it cannot "
          "distinguish the reserve from its absence");

    /* (b) STRICT EXTENSION, measured: a config the OLD rule already left room
     * in keeps EXACTLY its old height. `old_rows` is the pre-fix arithmetic,
     * written out here so the comparison is against something independent. */
    for (size_t total = 1; total <= 12; total++) {
        const size_t w[1] = { total };
        const size_t leaf = (total % DNAC_P2B_SPONGE_RATE == 0)
                                ? total / DNAC_P2B_SPONGE_RATE
                                : total / DNAC_P2B_SPONGE_RATE + 1;
        for (size_t depth = 1; depth <= 12; depth++) {
            const dnac_p2b_table_cfg_t cfg = { 1, w, depth };
            const size_t used = leaf + depth + 1;
            size_t old_rows = DNAC_P2B_MIN_ROWS;
            while (old_rows < used) old_rows <<= 1;
            if (old_rows == used) continue; /* was rejected — allowed to move */
            CHECK(dnac_p2b_table_rows(&cfg) == old_rows,
                  "T-RESERVE: total %zu depth %zu moved %zu -> %zu, but it was "
                  "ACCEPTED before — the change is not a strict extension",
                  total, depth, old_rows, dnac_p2b_table_rows(&cfg));
        }
    }

    /* (c) THE REFERENCE CONFIG DOES NOT MOVE — DNAC_P2B_PREP_ROOT is a
     * commitment over its table, so a height change here would void the pin.
     * T3 recomputes the root itself; this names the reason it still matches. */
    CHECK(dnac_p2b_table_rows(dnac_p2b_ref_cfg()) == DNAC_P2B_REF_ROWS,
          "T-RESERVE: the REF config's height moved to %zu — PIN-1 is void",
          dnac_p2b_table_rows(dnac_p2b_ref_cfg()));

    /* (d) THE HISTORICAL DEFECT, by name: the FRI commit phase's last round.
     * leaf width 2*arity == 4 (one leaf row), depth == log_blowup + lfpl == 2.
     * `used == 4` is an exact power of two, so before the reserve this cfg
     * produced a 4-row table whose last row was the FINAL row — and the AIR
     * refused it, making the last commit round inexpressible. */
    {
        const size_t w[1] = { 4 };
        const dnac_p2b_table_cfg_t last_round = { 1, w, 2 };
        CHECK(dnac_p2b_table_rows(&last_round) == 8,
              "T-RESERVE: the last-commit-round cfg (leaf 4, depth 2) has %zu "
              "rows, expected 8", dnac_p2b_table_rows(&last_round));
        printf("  T-RESERVE: last-commit-round cfg (leaf width 4, depth 2) "
               "-> %zu rows (was 4, AIR-rejected)\n",
               dnac_p2b_table_rows(&last_round));
    }
}

int main(void)
{
    printf("P2b PIN slice — preprocessed row-type table + PIN-1/PIN-2\n");
    t1_determinism();
    t2_shape();
    t3_pin_kat();
    t4_roundtrip_and_pin2();
    n4_failclose();
    t_reserve();

    printf("\nmmcs_air_table total  %26d checks\n", g_checks);
    printf("mmcs_air_table failed %26d\n", g_fails);
    if (g_fails == 0) {
        printf("\nP2b PIN GATE: GREEN\n");
        return 0;
    }
    fprintf(stderr, "\nP2b PIN GATE: RED\n");
    return 1;
}
