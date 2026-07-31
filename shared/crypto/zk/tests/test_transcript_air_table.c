/**
 * @file test_transcript_air_table.c
 * @brief s3a PIN slice gate — the transcript control-AIR's preprocessed
 *        OP-SCHEDULE table: deterministic generator, the challenger-simulation
 *        schedule, the structural static validator, and the PIN-1-P2a root
 *        constant (runtime KAT, shielded_domsep.h practice).
 *
 * Build spec: dnac/docs/plans/2026-07-30-composition-s3a-tair-table-BUILDABLE.md
 * §2 / §4. Mirrors the P2c PIN gate (tests/test_fri_air_table.c) one-for-one.
 * No AIR is built here — the CT-1..CT-4 constraints live in `transcript_air.c`
 * and are gated by tests/test_transcript_air.c.
 *
 *   T1  generator determinism (two runs byte-identical) + the shape accessors,
 *       with the REF op count RE-DERIVED BLOCK BY BLOCK from the cfg arithmetic
 *       rather than compared against a literal
 *   T2  the COMPOSED expansion is the op ORDER the native issues end to end —
 *       BLOCK 0 the DS prefix (duplex_challenger.c:96-103 at batch_verify.c:321),
 *       BLOCK 1 the batch-STARK priming (batch_priming.c:250-281), BLOCK 2 the
 *       PCS claimed-eval observes (batch_verify.c:637-647) and BLOCK 3 the FRI
 *       tail (fri_verifier.c:693-737) with NO second prefix — including the
 *       ZERO-op `check_witness(0)` branch and the 2-op non-zero branch; and the
 *       row types the generator emits are the ones the SHIPPED `dnac_duplex_t`
 *       actually produces on the same op stream (an independent replay, not a
 *       restatement of the simulation)
 *   T3  PIN-1-P2a KAT: table -> coset LDE (bitrev) -> dnac_p2_mmcs_commit_mixed
 *       == DNAC_P2A_PREP_ROOT, and the comparator accepts it
 *       (⚠ the pin ships as the {0,0,0,0} PLACEHOLDER, so these four lane
 *        checks FAIL BY DESIGN until the ORCHESTRATOR fills them from
 *        `--print-roots`.)
 *   N1  comparator rejects a one-lane tamper / NULL / the all-zero root
 *   N2  the pin binds table CONTENTS: one flipped cell => another root
 *   N3  static-validator negatives — every check tripped, with exact defect
 *       isolation (the P2b N4/N11 / P2c N3 pattern)
 *   N4  generator + script fail-close on bad arguments and on every FRI cfg gate
 *   N5  the COMPOSED script's blocks are load-bearing: a dropped priming op, a
 *       transposed op pair, the PCS block moved behind the tail (which must move
 *       the ROOT), the row bound in both directions, and every priming/full cfg
 *       gate
 *
 * Usage:
 *   test_transcript_air_table                 run all gates
 *   test_transcript_air_table --print-roots   print the reference table's four
 *                                             root lanes in
 *                                             DNAC_P2A_PREP_ROOT_LANE* form
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "../duplex_challenger.h"
#include "../field_goldilocks.h"
#include "../poseidon2_mmcs.h"
#include "../shielded_fri_params.h"
#include "../stark_prover.h"
#include "../transcript_air_table.h"

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
 * constants they mirror, so they cannot drift (the DNAC_P2B_PREP_LOG_BLOWUP /
 * DNAC_P2C_* practice). */
typedef char p2a_blowup_pin_assert
    [(DNAC_P2A_PREP_LOG_BLOWUP == (unsigned)DNAC_SHIELDED_FRI_LOG_BLOWUP) ? 1
                                                                         : -1];
typedef char p2a_bits_bound_assert
    [(TAIR_TBL_MAX_OP_BITS == (size_t)GOLDILOCKS_TWO_ADICITY) ? 1 : -1];
/* Column layout: 6 type lanes, then is_pow, then the op-step one-hot — total
 * 135 at TAIR_TBL_MAX_STEPS 128. A re-ordering that broke this would silently
 * move CT-1's index space. The width is asserted BOTH as the arithmetic (so it
 * follows MAX_STEPS) and as the literal the header names (so a MAX_STEPS change
 * has to be acknowledged in both places). */
typedef char p2a_layout_assert
    [(TAIR_TBL_COL_TYPE_OFF == (size_t)0 &&
      TAIR_TBL_COL_IS_POW == TAIR_TBL_NUM_TYPES &&
      TAIR_TBL_COL_POS_OFF == TAIR_TBL_COL_IS_POW + 1 &&
      TAIR_TBL_COLS == TAIR_TBL_NUM_TYPES + 1 + TAIR_TBL_MAX_STEPS &&
      TAIR_TBL_COLS == (size_t)135)
         ? 1
         : -1];
/* ⚠ THE ROW BOUND IS THE BINDING ONE, and this assert says which way round.
 * It used to read `MAX_STEPS + MAX_STARTS + 1 <= MAX_ROWS`, i.e. "the extremal
 * script fits"; at MAX_STEPS 128 that is FALSE and it is no longer the claim.
 * `tair_script_check` rejects `n_starts + n_ops + 1 > MAX_ROWS` first, so the
 * largest script that can EXIST has `n_ops <= MAX_ROWS - MAX_STARTS - 1`, and
 * what has to hold is that the op-step one-hot is at least that wide — otherwise
 * a legal script could carry a `pos` index outside the table. Both bounds fail
 * CLOSED either way; this is the one that keeps `pos` in range. */
typedef char p2a_rowbound_assert
    [(TAIR_TBL_MAX_ROWS - TAIR_TBL_MAX_STARTS - 1 <= TAIR_TBL_MAX_STEPS) ? 1
                                                                         : -1];
/* And the row bound really is reachable — a 127-row schedule pads to exactly
 * MAX_ROWS, so the constant is a measured cap and not a guess. */
typedef char p2a_rowbound_reachable_assert
    [(TAIR_TBL_MAX_ROWS >= 2 && TAIR_TBL_MAX_ROWS / 2 < TAIR_TBL_MAX_ROWS) ? 1
                                                                           : -1];
/* The REFERENCE script must fit both bounds, or the pin could not be derived. */
typedef char p2a_ref_fits_assert
    [(DNAC_P2A_REF_OPS <= TAIR_TBL_MAX_STEPS &&
      1 + DNAC_P2A_REF_OPS + 1 <= TAIR_TBL_MAX_ROWS &&
      DNAC_P2A_REF_ROWS == TAIR_TBL_MAX_ROWS)
         ? 1
         : -1];

#define COLS      TAIR_TBL_COLS
#define MAX_CELLS (TAIR_TBL_MAX_ROWS * COLS)
#define MAX_LDE_CELLS ((TAIR_TBL_MAX_ROWS << DNAC_P2A_PREP_LOG_BLOWUP) * COLS)
#define MAX_OPS   TAIR_TBL_MAX_STEPS

static const char *TYPE_NAME[TAIR_TBL_NUM_TYPES] = {
    "start", "obs", "obs_dup", "sample", "sample_dup", "filler"
};

/* ==========================================================================
 * Shared helper: the SHIPPED preprocessed-commit pipeline
 * (batch_prover.c:807-825 with is_zk = 0: coset LDE bit-reversed at log_blowup,
 * then ONE mixed-height Poseidon2 MMCS commit).
 * ======================================================================== */
static int p2a_commit_table(const uint64_t *table, size_t rows,
                            uint64_t out_lanes[4])
{
    static uint64_t lde[MAX_LDE_CELLS];
    const size_t lde_rows = rows << DNAC_P2A_PREP_LOG_BLOWUP;
    if (lde_rows * COLS > MAX_LDE_CELLS) return 0;

    if (dnac_prover_coset_lde_bitrev(table, rows, COLS,
                                     DNAC_P2A_PREP_LOG_BLOWUP,
                                     GOLDILOCKS_GENERATOR,
                                     lde) != DNAC_PROVER_OK) {
        return 0;
    }
    const uint64_t *mats[1] = { lde };
    const size_t widths[1] = { COLS };
    const size_t heights[1] = { lde_rows };
    dnac_p2_digest_t root;
    if (dnac_p2_mmcs_commit_mixed(mats, widths, heights, 1, &root, NULL) !=
        DNAC_P2M_OK) {
        return 0;
    }
    memcpy(out_lanes, root.lanes, 4 * sizeof(uint64_t));
    return 1;
}

/* The reference script, materialized into file-static buffers so every gate can
 * reuse the SAME pointers (the script holds pointers, not copies). */
static dnac_tair_op_t     g_ref_ops[MAX_OPS];
static size_t             g_ref_starts[1];
static dnac_tair_script_t g_ref;

static int build_ref(void)
{
    return dnac_tair_ref_script(g_ref_ops, MAX_OPS, g_ref_starts, &g_ref) ==
           DNAC_TAIR_TABLE_OK;
}

/* ==========================================================================
 * T1 — generator determinism + shape accessors
 * ======================================================================== */
static void t1_determinism(void)
{
    static uint64_t a[MAX_CELLS], b[MAX_CELLS];

    /* The REF op count, RE-DERIVED here BLOCK BY BLOCK from the cfg arithmetic
     * (the header's item lists) — a SECOND transcription of the rules in
     * batch_priming.c / batch_verify.c / fri_verifier.c, so a generator that
     * silently changed an expansion could not quietly move the pin. NOT a
     * literal comparison against 93. */
    const dnac_tair_full_cfg_t *full = dnac_tair_ref_full_cfg();
    const dnac_tair_priming_cfg_t *pc = &full->priming;
    const dnac_tair_fri_cfg_t *cfg = dnac_tair_ref_fri_cfg();
    const size_t digest_lanes = (size_t)DNAC_P2M_DIGEST_LANES;
    const size_t final_lanes = (size_t)2 << cfg->log_final_poly_len;
    const size_t commit_pow_ops = (cfg->commit_pow_bits == 0) ? 0 : 2;
    const size_t query_pow_ops = (cfg->query_pow_bits == 0) ? 0 : 2;

    /* BLOCK 3 — the FRI tail, WITHOUT a DS prefix (fri_verifier.c:693-737). */
    const size_t want_tail = 2 + cfg->R * (digest_lanes + commit_pow_ops + 2) +
                             final_lanes + cfg->R + query_pow_ops +
                             cfg->num_queries;
    /* BLOCK 1 — the priming (batch_priming.c:250-281). */
    size_t want_prim = 0, want_lanes = 0;
    {
        int any_lk = 0, any_prep = 0;
        size_t lk_insts = 0;
        for (size_t i = 0; i < pc->n; i++) {
            if (pc->insts[i].num_lookups > 0) { any_lk = 1; lk_insts++; }
            if (pc->insts[i].preprocessed_width > 0) any_prep = 1;
        }
        want_prim = 2 + 8 * pc->n + digest_lanes;
        for (size_t i = 0; i < pc->n; i++) want_prim += pc->insts[i].num_publics;
        want_prim += 2 * pc->n + (any_prep ? digest_lanes : 0);
        if (any_lk) want_prim += 4 + digest_lanes + 2 * lk_insts;
        want_prim += 2 + digest_lanes + (pc->is_zk ? digest_lanes : 0) + 2;
        /* BLOCK 2 — the PCS claimed-eval lanes (batch_verify.c:432-488). */
        for (size_t i = 0; i < pc->n; i++) {
            const dnac_tair_inner_inst_t *d = &pc->insts[i];
            const size_t nrc = pc->num_random_codewords;
            if (pc->is_zk) want_lanes += 2 + nrc;
            want_lanes += (d->main_next ? 2u : 1u) * (d->main_width + nrc);
            want_lanes += d->num_quotient_chunks * (2 + nrc);
            if (d->preprocessed_width > 0) {
                want_lanes += (d->prep_next ? 2u : 1u) * d->preprocessed_width;
            }
            if (d->num_lookups > 0) {
                want_lanes += 2 * ((d->num_lookups + 1) * 2 + nrc);
            }
        }
    }
    const size_t want_ops =
        (size_t)DNAC_DUPLEX_RATE + want_prim + 2 * want_lanes + want_tail;

    CHECK(dnac_tair_priming_num_ops(pc) == want_prim,
          "T1: priming op count %zu != derived %zu",
          dnac_tair_priming_num_ops(pc), want_prim);
    CHECK(dnac_tair_pcs_num_ops(pc) == 2 * want_lanes,
          "T1: pcs op count %zu != derived %zu", dnac_tair_pcs_num_ops(pc),
          2 * want_lanes);
    /* The STANDALONE tail accessor still carries its own DS prefix — that is
     * what makes it a complete run, and what the composed count must NOT do. */
    CHECK(dnac_tair_fri_num_ops(cfg) == (size_t)DNAC_DUPLEX_RATE + want_tail,
          "T1: standalone tail count %zu != derived %zu",
          dnac_tair_fri_num_ops(cfg), (size_t)DNAC_DUPLEX_RATE + want_tail);
    CHECK(dnac_tair_full_num_ops(full) == want_ops,
          "T1: ref op count %zu != derived %zu", dnac_tair_full_num_ops(full),
          want_ops);
    CHECK(want_ops == DNAC_P2A_REF_OPS,
          "T1: DNAC_P2A_REF_OPS %zu != derived %zu", (size_t)DNAC_P2A_REF_OPS,
          want_ops);
    /* The FULL script is STRICTLY LONGER than the standalone tail — measured,
     * not asserted from the arithmetic, so a priming block that collapsed to
     * nothing would be caught here rather than looking like a valid pin. */
    CHECK(want_ops > dnac_tair_fri_num_ops(cfg),
          "T1: the composed script (%zu) is not longer than the tail (%zu)",
          want_ops, dnac_tair_fri_num_ops(cfg));
    CHECK(g_ref.n_ops == want_ops, "T1: script n_ops %zu != %zu", g_ref.n_ops,
          want_ops);
    CHECK(g_ref.n_starts == 1, "T1: script n_starts %zu != 1", g_ref.n_starts);

    CHECK(dnac_tair_sched_rows(&g_ref) == 1 + want_ops,
          "T1: sched rows %zu != %zu", dnac_tair_sched_rows(&g_ref),
          1 + want_ops);
    CHECK(dnac_tair_table_rows(&g_ref) == DNAC_P2A_REF_ROWS,
          "T1: ref rows %zu != %zu", dnac_tair_table_rows(&g_ref),
          (size_t)DNAC_P2A_REF_ROWS);
    CHECK(dnac_tair_total_bits(&g_ref) == cfg->num_queries * cfg->lgmh,
          "T1: total bits %zu != %zu", dnac_tair_total_bits(&g_ref),
          cfg->num_queries * cfg->lgmh);
    CHECK(dnac_tair_num_publics(&g_ref) == DNAC_P2A_REF_PUBLICS,
          "T1: ref publics %zu != %zu", dnac_tair_num_publics(&g_ref),
          (size_t)DNAC_P2A_REF_PUBLICS);
    {
        size_t pow_bits = SIZE_MAX;
        CHECK(dnac_tair_script_pow_bits(&g_ref, &pow_bits) ==
                      DNAC_TAIR_TABLE_OK &&
                  pow_bits == 0,
              "T1: ref script pow_bits != 0 (REF is the ZERO-op PoW branch)");
    }

    const size_t rows = dnac_tair_table_rows(&g_ref);
    CHECK(dnac_tair_table_generate(&g_ref, a, MAX_CELLS) == DNAC_TAIR_TABLE_OK,
          "T1: ref generate #1");
    CHECK(dnac_tair_table_generate(&g_ref, b, MAX_CELLS) == DNAC_TAIR_TABLE_OK,
          "T1: ref generate #2");
    CHECK(memcmp(a, b, rows * COLS * sizeof(uint64_t)) == 0,
          "T1: ref table NOT deterministic");

    dnac_tair_table_defect_t d = DNAC_TAIR_DEFECT_NONE;
    CHECK(dnac_tair_table_validate(&g_ref, a, rows, &d) == DNAC_TAIR_TABLE_OK &&
              d == DNAC_TAIR_DEFECT_NONE,
          "T1: validator rejected the reference table (defect %d)", (int)d);
}

/* ==========================================================================
 * T2 — the FRI-tail expansion, and the row types the NATIVE challenger implies
 * ======================================================================== */

/* Replay the script through the SHIPPED `dnac_duplex_t` and require the table's
 * row type to be the label that machine implies at every step. The values are
 * arbitrary (the schedule never reads them); what is checked is the LENGTH
 * bookkeeping, which is exactly what decides _OBS vs _OBS_DUP and _SAMPLE vs
 * _SAMPLE_DUP (duplex_challenger.c:112-114 / :127-129). */
static void replay_check(const char *label, const dnac_tair_script_t *s)
{
    static uint64_t cells[MAX_CELLS];
    const size_t rows = dnac_tair_table_rows(s);
    if (rows == 0 ||
        dnac_tair_table_generate(s, cells, MAX_CELLS) != DNAC_TAIR_TABLE_OK) {
        CHECK(0, "T2[%s]: generate failed", label);
        return;
    }

    dnac_duplex_t ch;
    dnac_duplex_init(&ch);
    size_t r = 0, next_start = 0;
    int ok = 1;

    for (size_t k = 0; k < s->n_ops && ok; k++) {
        if (next_start < s->n_starts && s->instance_starts[next_start] == k) {
            if (cells[r * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_START)] != 1) {
                CHECK(0, "T2[%s]: row %zu is not the instance start", label, r);
                ok = 0;
                break;
            }
            r++;
            dnac_duplex_init(&ch); /* duplex_challenger.c:91-94 */
            next_start++;
        }
        size_t want;
        if (s->ops[k].kind == DNAC_TAIR_OP_OBSERVE) {
            want = (ch.input_len == (size_t)DNAC_DUPLEX_RATE - 1)
                       ? TAIR_TBL_TYPE_OBS_DUP
                       : TAIR_TBL_TYPE_OBS;
            dnac_duplex_observe_fp(&ch, gold_fp_from_u64((uint64_t)k + 1u));
        } else {
            want = (ch.input_len > 0 || ch.output_len == 0)
                       ? TAIR_TBL_TYPE_SAMPLE_DUP
                       : TAIR_TBL_TYPE_SAMPLE;
            (void)dnac_duplex_sample_fp(&ch);
        }
        if (cells[r * COLS + tair_tbl_col_type(want)] != 1) {
            CHECK(0, "T2[%s]: row %zu (op %zu) is not `%s`", label, r, k,
                  TYPE_NAME[want]);
            ok = 0;
            break;
        }
        if (cells[r * COLS + tair_tbl_col_pos(k)] != 1) {
            CHECK(0, "T2[%s]: row %zu carries no pos[%zu]", label, r, k);
            ok = 0;
            break;
        }
        r++;
    }
    if (!ok) return;

    for (size_t rr = r; rr < rows; rr++) {
        if (cells[rr * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_FILLER)] != 1) {
            CHECK(0, "T2[%s]: padding row %zu is not a filler", label, rr);
            return;
        }
    }
    CHECK(1, "unreachable");
    printf("  [T2]  %-28s %2zu ops -> %2zu rows, native replay agrees\n", label,
           s->n_ops, rows);
}

static void t2_schedule(void)
{
    /* (a) the REF expansion is the NATIVE order, block by block and item by
     *     item: BLOCK 0 the DS prefix (duplex_challenger.c:96-103 at
     *     batch_verify.c:321), BLOCK 1 batch_priming.c:250-281, BLOCK 2
     *     batch_verify.c:637-647, BLOCK 3 fri_verifier.c:693-737 with NO second
     *     prefix (transcript.c:48 copies the primed state).
     *
     *     Written as a SECOND transcription of those four sources, not as a
     *     restatement of the builder: every EXPECT below names the native line
     *     it stands for. */
    const dnac_tair_full_cfg_t *full = dnac_tair_ref_full_cfg();
    const dnac_tair_priming_cfg_t *pc = &full->priming;
    const dnac_tair_fri_cfg_t *cfg = dnac_tair_ref_fri_cfg();
    size_t k = 0, off_pcs = 0, off_tail = 0;
    int order_ok = 1;
    int any_lk = 0, any_prep = 0;
#define EXPECT_OBS()                                                          \
    do {                                                                      \
        if (k >= g_ref.n_ops || g_ref.ops[k].kind != DNAC_TAIR_OP_OBSERVE)     \
            order_ok = 0;                                                     \
        k++;                                                                  \
    } while (0)
#define EXPECT_SMP(pow, nbits)                                                \
    do {                                                                      \
        if (k >= g_ref.n_ops || g_ref.ops[k].kind != DNAC_TAIR_OP_SAMPLE ||    \
            g_ref.ops[k].is_pow != (pow) ||                                    \
            g_ref.ops[k].num_bits != (size_t)(nbits))                          \
            order_ok = 0;                                                     \
        k++;                                                                  \
    } while (0)
#define EXPECT_USIZE() do { EXPECT_OBS(); EXPECT_OBS(); } while (0)
#define EXPECT_COMMIT()                                                       \
    do {                                                                      \
        for (size_t i_ = 0; i_ < (size_t)DNAC_P2M_DIGEST_LANES; i_++)          \
            EXPECT_OBS();                                                     \
    } while (0)

    for (size_t i = 0; i < pc->n; i++) {
        if (pc->insts[i].num_lookups > 0) any_lk = 1;
        if (pc->insts[i].preprocessed_width > 0) any_prep = 1;
    }

    /* ── BLOCK 0 — the DS prefix, ONCE ── */
    for (size_t i = 0; i < (size_t)DNAC_DUPLEX_RATE; i++) EXPECT_OBS();

    /* ── BLOCK 1 — the priming ── */
    EXPECT_USIZE();                          /* num_instances        :47 */
    for (size_t i = 0; i < pc->n; i++) {     /* 4 bindings each   :52-55 */
        EXPECT_USIZE(); EXPECT_USIZE(); EXPECT_USIZE(); EXPECT_USIZE();
    }
    EXPECT_COMMIT();                         /* the main commit      :72 */
    for (size_t i = 0; i < pc->n; i++) {     /* the publics       :77-79 */
        for (size_t j = 0; j < pc->insts[i].num_publics; j++) EXPECT_OBS();
    }
    for (size_t i = 0; i < pc->n; i++) EXPECT_USIZE(); /* prep widths :95 */
    if (any_prep) EXPECT_COMMIT();           /* the prep commit   :97-99 */
    if (any_lk) {                            /* the lookup squeeze:143-144 */
        EXPECT_SMP(0, 0); EXPECT_SMP(0, 0);
        EXPECT_SMP(0, 0); EXPECT_SMP(0, 0);
        EXPECT_COMMIT();                     /* the perm commit     :181 */
        for (size_t i = 0; i < pc->n; i++) { /* the terminals   :182-192 */
            if (pc->insts[i].num_lookups == 0) continue;
            EXPECT_OBS(); EXPECT_OBS();
        }
    }
    EXPECT_SMP(0, 0); EXPECT_SMP(0, 0);      /* the batch alpha     :194 */
    EXPECT_COMMIT();                         /* the quotient commit :276 */
    if (pc->is_zk) EXPECT_COMMIT();          /* the random commit :277-279 */
    EXPECT_SMP(0, 0); EXPECT_SMP(0, 0);      /* zeta                :280 */
    off_pcs = k;

    /* ── BLOCK 2 — the PCS claimed-eval observes, ALL observes ── */
    {
        size_t lanes = 0;
        const size_t nrc = pc->num_random_codewords;
        for (size_t i = 0; i < pc->n; i++) {
            const dnac_tair_inner_inst_t *d = &pc->insts[i];
            if (pc->is_zk) lanes += 2 + nrc;
            lanes += (d->main_next ? 2u : 1u) * (d->main_width + nrc);
            lanes += d->num_quotient_chunks * (2 + nrc);
            if (d->preprocessed_width > 0) {
                lanes += (d->prep_next ? 2u : 1u) * d->preprocessed_width;
            }
            if (d->num_lookups > 0) lanes += 2 * ((d->num_lookups + 1) * 2 + nrc);
        }
        for (size_t i = 0; i < 2 * lanes; i++) EXPECT_OBS();
    }
    off_tail = k;

    /* ── BLOCK 3 — the FRI tail, NO second DS prefix ── */
    EXPECT_SMP(0, 0); /* alpha c0 */
    EXPECT_SMP(0, 0); /* alpha c1 */
    for (size_t rnd = 0; rnd < cfg->R; rnd++) {
        for (size_t i = 0; i < (size_t)DNAC_P2M_DIGEST_LANES; i++) EXPECT_OBS();
        if (cfg->commit_pow_bits != 0) {
            EXPECT_OBS();
            EXPECT_SMP(1, 0);
        }
        EXPECT_SMP(0, 0);
        EXPECT_SMP(0, 0);
    }
    for (size_t i = 0; i < (size_t)2 << cfg->log_final_poly_len; i++) EXPECT_OBS();
    for (size_t rnd = 0; rnd < cfg->R; rnd++) EXPECT_OBS();
    if (cfg->query_pow_bits != 0) {
        EXPECT_OBS();
        EXPECT_SMP(1, 0);
    }
    for (size_t q = 0; q < cfg->num_queries; q++) EXPECT_SMP(0, cfg->lgmh);
#undef EXPECT_OBS
#undef EXPECT_SMP
#undef EXPECT_USIZE
#undef EXPECT_COMMIT
    CHECK(order_ok && k == g_ref.n_ops,
          "T2: REF expansion is not the composed native order (k=%zu)", k);

    /* (a2) the BLOCK BOUNDARIES the composition's ordinal offsets are built
     *      from, measured HERE from the second transcription above rather than
     *      taken from the module. */
    CHECK(off_pcs == (size_t)DNAC_DUPLEX_RATE +
                         dnac_tair_priming_num_ops(pc),
          "T2: BLOCK 2 starts at %zu, the priming accessor says %zu", off_pcs,
          (size_t)DNAC_DUPLEX_RATE + dnac_tair_priming_num_ops(pc));
    CHECK(off_tail == off_pcs + dnac_tair_pcs_num_ops(pc),
          "T2: BLOCK 3 starts at %zu, the pcs accessor says %zu", off_tail,
          off_pcs + dnac_tair_pcs_num_ops(pc));
    /* The head carries NO PoW op and the PCS block carries NO sample: those two
     * facts are what let the composition offset its ordinals by a count. */
    {
        int head_clean = 1;
        for (size_t i = 0; i < off_tail && i < g_ref.n_ops; i++) {
            if (g_ref.ops[i].is_pow) head_clean = 0;
        }
        for (size_t i = off_pcs; i < off_tail && i < g_ref.n_ops; i++) {
            if (g_ref.ops[i].kind != DNAC_TAIR_OP_OBSERVE) head_clean = 0;
        }
        CHECK(head_clean,
              "T2: the head carries a PoW op or the PCS block carries a sample");
    }
    /* The LAST op of BLOCK 1 is a sample (zeta, batch_priming.c:280) and the
     * FIRST of BLOCK 3 is a sample (the FRI alpha, fri_verifier.c:694) — the two
     * boundaries the entry's PRE_POPS offset stands on. */
    CHECK(off_pcs >= 1 && off_pcs - 1 < g_ref.n_ops &&
              g_ref.ops[off_pcs - 1].kind == DNAC_TAIR_OP_SAMPLE &&
              !g_ref.ops[off_pcs - 1].is_pow,
          "T2: the op before BLOCK 2 is not zeta's second pop");
    CHECK(off_tail < g_ref.n_ops &&
              g_ref.ops[off_tail].kind == DNAC_TAIR_OP_SAMPLE &&
              !g_ref.ops[off_tail].is_pow,
          "T2: the first op of BLOCK 3 is not the FRI alpha's first pop");

    /* (b) the bit-export public block is DENSE and in op order. */
    {
        size_t want_off = g_ref.n_ops;
        int off_ok = 1;
        for (size_t i = 0; i < g_ref.n_ops; i++) {
            const size_t nb = g_ref.ops[i].num_bits;
            const size_t got = dnac_tair_op_bit_off(&g_ref, i);
            if (nb == 0) {
                if (got != (size_t)-1) off_ok = 0;
            } else {
                if (got != want_off) off_ok = 0;
                want_off += nb;
            }
        }
        CHECK(off_ok && want_off == dnac_tair_num_publics(&g_ref),
              "T2: bit-export public block is not dense/in order");
    }

    /* (c) the native replay agrees with the generator's simulation, for the REF
     *     script and for a PoW-bearing one (the 2-op check_witness branch). */
    replay_check("ref (PoW 0/0)", &g_ref);
    {
        static dnac_tair_op_t ops[MAX_OPS];
        static size_t starts[1];
        dnac_tair_script_t s;
        const dnac_tair_fri_cfg_t pow_cfg = { 2, 0, 2, 5, 8, 8 };
        CHECK(dnac_tair_fri_build_script(&pow_cfg, ops, MAX_OPS, starts, &s) ==
                  DNAC_TAIR_TABLE_OK,
              "T2: PoW-bearing script build");
        /* 4 + 2 + 2*(4 + 2 + 2) + 2 + 2 + 2 + 2 = 30 ops; the two extra ops per
         * round and the two for the query grind are the check_witness expansion
         * (duplex_challenger.c:156-157). */
        CHECK(s.n_ops == (size_t)4 + 2 + 2 * (4 + 2 + 2) + 2 + 2 + 2 + 2,
              "T2: PoW script op count %zu", s.n_ops);
        {
            size_t pb = 0;
            CHECK(dnac_tair_script_pow_bits(&s, &pb) == DNAC_TAIR_TABLE_OK &&
                      pb == 8,
                  "T2: PoW script pow_bits != 8");
        }
        replay_check("fri PoW 8/8", &s);

        /* And a scenario-shaped script with TWO instances — the multi_instance
         * shape from the oracle vectors, which the FRI tail never produces. */
        static dnac_tair_op_t ops2[MAX_OPS];
        static size_t starts2[2] = { 0, 5 };
        for (size_t i = 0; i < 10; i++) {
            memset(&ops2[i], 0, sizeof(ops2[i]));
            ops2[i].kind = (i % 3 == 2) ? DNAC_TAIR_OP_SAMPLE
                                        : DNAC_TAIR_OP_OBSERVE;
        }
        dnac_tair_script_t s2 = { ops2, 10, starts2, 2 };
        replay_check("2 instances, 10 ops", &s2);
    }
}

/* ==========================================================================
 * T3 — PIN-1-P2a KAT + N1 + N2
 * ======================================================================== */
static void t3_pin(void)
{
    static uint64_t cells[MAX_CELLS];
    const size_t rows = dnac_tair_table_rows(&g_ref);
    if (dnac_tair_table_generate(&g_ref, cells, MAX_CELLS) !=
        DNAC_TAIR_TABLE_OK) {
        CHECK(0, "T3: generate failed");
        return;
    }

    uint64_t derived[4];
    if (!p2a_commit_table(cells, rows, derived)) {
        CHECK(0, "T3: LDE/commit pipeline failed");
        return;
    }

    if (DNAC_P2A_PREP_ROOT_UNFILLED) {
        fprintf(stderr,
                "\n  ⚠ DNAC_P2A_PREP_ROOT is the {0,0,0,0} PLACEHOLDER."
                "\n    The four T3 lane checks below FAIL BY DESIGN until it is"
                " filled\n    from `--print-roots`. Do NOT hand-edit the"
                " constant.\n\n");
    }
    static const uint64_t pinned[4] = DNAC_P2A_PREP_ROOT;
    for (int i = 0; i < 4; i++) {
        CHECK(derived[i] == pinned[i],
              "T3: PIN-1-P2a lane %d: derived 0x%016" PRIx64
              " != pinned 0x%016" PRIx64,
              i, derived[i], pinned[i]);
    }
    CHECK(dnac_tair_prep_root_check(derived) == DNAC_TAIR_TABLE_OK,
          "T3: comparator rejected the derived root");

    /* N1 — comparator negatives. */
    CHECK(dnac_tair_prep_root_check(NULL) == DNAC_TAIR_TABLE_ERR_PARAM,
          "N1: comparator(NULL)");
    {
        uint64_t bad[4];
        memcpy(bad, derived, sizeof(bad));
        bad[2] ^= 1u;
        CHECK(dnac_tair_prep_root_check(bad) ==
                  DNAC_TAIR_TABLE_ERR_ROOT_MISMATCH,
              "N1: comparator accepted a one-lane tamper");
    }
    {
        const uint64_t zero_root[4] = { 0, 0, 0, 0 };
        /* An all-zero root must NEVER be accepted — least of all while the pin
         * is the placeholder, where accepting it would be worse than no pin. */
        CHECK(DNAC_P2A_PREP_ROOT_UNFILLED
                  ? (dnac_tair_prep_root_check(zero_root) ==
                     DNAC_TAIR_TABLE_ERR_ROOT_MISMATCH)
                  : (dnac_tair_prep_root_check(zero_root) ==
                     DNAC_TAIR_TABLE_ERR_ROOT_MISMATCH),
              "N1: comparator accepted the all-zero root");
    }

    /* N2 — the pin binds table CONTENTS: one flipped cell moves the root. */
    {
        static uint64_t tampered[MAX_CELLS];
        memcpy(tampered, cells, rows * COLS * sizeof(uint64_t));
        /* Flip the `is_pow` cell of row 1 (an op row): a single 0 -> 1. */
        tampered[1 * COLS + TAIR_TBL_COL_IS_POW] = 1;
        uint64_t other[4];
        CHECK(p2a_commit_table(tampered, rows, other), "N2: commit of tamper");
        CHECK(memcmp(other, derived, sizeof(other)) != 0,
              "N2: a flipped selector cell did NOT change the root");
        CHECK(dnac_tair_prep_root_check(other) ==
                  DNAC_TAIR_TABLE_ERR_ROOT_MISMATCH,
              "N2: comparator accepted the tampered table's root");
    }
}

/* ==========================================================================
 * N3 — static-validator negatives, with exact defect isolation
 * ======================================================================== */
static void n3_validator(void)
{
    static uint64_t base[MAX_CELLS], t[MAX_CELLS];
    const size_t rows = dnac_tair_table_rows(&g_ref);
    const size_t sched = dnac_tair_sched_rows(&g_ref); /* rows 0..sched-1 typed */
    if (dnac_tair_table_generate(&g_ref, base, MAX_CELLS) !=
        DNAC_TAIR_TABLE_OK) {
        CHECK(0, "N3: generate failed");
        return;
    }
    CHECK(sched > 0 && sched + 2 <= rows,
          "N3: setup expects at least two padding rows (sched %zu, rows %zu)",
          sched, rows);

#define TAMPER(name, defect, body)                                            \
    do {                                                                      \
        memcpy(t, base, rows * COLS * sizeof(uint64_t));                      \
        { body }                                                              \
        dnac_tair_table_defect_t d = DNAC_TAIR_DEFECT_NONE;                   \
        const dnac_tair_table_status_t st =                                   \
            dnac_tair_table_validate(&g_ref, t, rows, &d);                    \
        CHECK(st == DNAC_TAIR_TABLE_ERR_SCHEDULE && d == (defect),            \
              "N3[%s]: st=%d defect=%d (want defect %d)", name, (int)st,       \
              (int)d, (int)(defect));                                          \
    } while (0)

    /* Row 0 is the instance start; row 1 is the first DS-prefix observe; the
     * last row is padding. */
    TAMPER("non-canonical cell", DNAC_TAIR_DEFECT_CANONICAL,
           t[1 * COLS + TAIR_TBL_COL_IS_POW] = GOLDILOCKS_P;);
    TAMPER("non-boolean cell", DNAC_TAIR_DEFECT_BOOLEAN,
           t[1 * COLS + TAIR_TBL_COL_IS_POW] = 2;);
    TAMPER("two row types on one row", DNAC_TAIR_DEFECT_TYPE_EXCLUSIVE,
           t[1 * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_FILLER)] = 1;);
    TAMPER("no row type on one row", DNAC_TAIR_DEFECT_TYPE_EXCLUSIVE,
           t[1 * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_OBS)] = 0;);
    /* Row 4 is the 4th DS-prefix observe — the eager duplex
     * (duplex_challenger.c:112-114). Relabelling it a plain observe is a schedule
     * the native machine never produces. */
    TAMPER("eager duplex relabelled a plain observe", DNAC_TAIR_DEFECT_MACHINE,
           t[4 * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_OBS_DUP)] = 0;
           t[4 * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_OBS)] = 1;);
    /* The LAST row typed: the AIR's final row gets no transition constraints, so
     * this is the i3 shipped-HIGH shape. Reaches TERMINAL only because that
     * check runs BEFORE the machine walk (whose own padding-is-terminal rule
     * would otherwise claim it) — see the enum's ordering note. */
    TAMPER("last row is not a filler", DNAC_TAIR_DEFECT_TERMINAL,
           t[(rows - 1) * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_FILLER)] = 0;
           t[(rows - 1) * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_OBS)] = 1;);
    /* An op row resumed AFTER padding started, mid-trace: the last row is still
     * a filler, so TERMINAL passes and the machine walk is what rejects it. */
    TAMPER("op row after padding started (mid-trace)", DNAC_TAIR_DEFECT_MACHINE,
           t[(sched + 1) * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_FILLER)] = 0;
           t[(sched + 1) * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_OBS)] = 1;);
    /* The LAST op row turned into padding: the machine walk stays legal (a
     * shorter run), so the SCRIPT count mismatch is what rejects it. */
    TAMPER("an op row dropped from the run", DNAC_TAIR_DEFECT_SCRIPT,
           for (size_t c = 0; c < TAIR_TBL_NUM_TYPES; c++)
               t[(sched - 1) * COLS + tair_tbl_col_type(c)] = 0;
           t[(sched - 1) * COLS + tair_tbl_col_type(TAIR_TBL_TYPE_FILLER)] = 1;
           for (size_t c = 0; c < TAIR_TBL_MAX_STEPS; c++)
               t[(sched - 1) * COLS + tair_tbl_col_pos(c)] = 0;);
    TAMPER("op-step one-hot cleared", DNAC_TAIR_DEFECT_POS_ONEHOT,
           t[1 * COLS + tair_tbl_col_pos(0)] = 0;);
    TAMPER("op-step one-hot doubled", DNAC_TAIR_DEFECT_POS_ONEHOT,
           t[1 * COLS + tair_tbl_col_pos(3)] = 1;);
    TAMPER("op-step one-hot on a filler row", DNAC_TAIR_DEFECT_POS_ONEHOT,
           t[(rows - 1) * COLS + tair_tbl_col_pos(0)] = 1;);
    TAMPER("is_pow injected on a non-PoW row", DNAC_TAIR_DEFECT_ISPOW,
           t[6 * COLS + TAIR_TBL_COL_IS_POW] = 1;);
#undef TAMPER

    /* SCRIPT, second shape: a table that is a perfectly LEGAL run of the
     * challenger but describes a DIFFERENT op stream than the script argument.
     * This is the OBL-P2a-T1 seam in miniature — the root binds the table, the
     * script is a separate argument, and only this check ties the two. Built by
     * generating from one script and validating against another of the same
     * shape. */
    {
        static dnac_tair_op_t obs_ops[2], mix_ops[2];
        static size_t starts[1] = { 0 };
        memset(obs_ops, 0, sizeof(obs_ops));
        memset(mix_ops, 0, sizeof(mix_ops));
        obs_ops[0].kind = DNAC_TAIR_OP_OBSERVE;
        obs_ops[1].kind = DNAC_TAIR_OP_OBSERVE;
        mix_ops[0].kind = DNAC_TAIR_OP_OBSERVE;
        mix_ops[1].kind = DNAC_TAIR_OP_SAMPLE; /* the one difference */
        dnac_tair_script_t s_obs = { obs_ops, 2, starts, 1 };
        dnac_tair_script_t s_mix = { mix_ops, 2, starts, 1 };
        const size_t r = dnac_tair_table_rows(&s_obs);
        CHECK(r == 4 && dnac_tair_table_rows(&s_mix) == r,
              "N3[kind mismatch]: setup rows %zu", r);
        if (r == 4 && dnac_tair_table_generate(&s_obs, t, MAX_CELLS) ==
                          DNAC_TAIR_TABLE_OK) {
            dnac_tair_table_defect_t d = DNAC_TAIR_DEFECT_NONE;
            const dnac_tair_table_status_t st =
                dnac_tair_table_validate(&s_mix, t, r, &d);
            CHECK(st == DNAC_TAIR_TABLE_ERR_SCHEDULE &&
                      d == DNAC_TAIR_DEFECT_SCRIPT,
                  "N3[kind mismatch]: st=%d defect=%d", (int)st, (int)d);
        }
    }
}

/* ==========================================================================
 * N4 — generator + script fail-close
 * ======================================================================== */
static void n4_failclose(void)
{
    static uint64_t cells[MAX_CELLS];
    static dnac_tair_op_t ops[MAX_OPS];
    static size_t starts[TAIR_TBL_MAX_STARTS];

    for (size_t i = 0; i < 4; i++) {
        memset(&ops[i], 0, sizeof(ops[i]));
        ops[i].kind = DNAC_TAIR_OP_OBSERVE;
    }
    starts[0] = 0;

    /* NULL / capacity. */
    CHECK(dnac_tair_table_generate(NULL, cells, MAX_CELLS) ==
              DNAC_TAIR_TABLE_ERR_PARAM,
          "N4: generate(NULL script)");
    {
        dnac_tair_script_t s = { ops, 4, starts, 1 };
        CHECK(dnac_tair_table_generate(&s, NULL, MAX_CELLS) ==
                  DNAC_TAIR_TABLE_ERR_PARAM,
              "N4: generate(NULL out)");
        CHECK(dnac_tair_table_generate(&s, cells, 1) ==
                  DNAC_TAIR_TABLE_ERR_CAPACITY,
              "N4: generate(out_cells too small)");
    }

    /* Script gates, one per rejected shape. */
#define REJECT_SCRIPT(name, s)                                                \
    do {                                                                      \
        CHECK(dnac_tair_table_rows(&(s)) == 0, "N4[%s]: rows != 0", name);     \
        CHECK(dnac_tair_num_publics(&(s)) == 0, "N4[%s]: publics != 0", name); \
        CHECK(dnac_tair_table_generate(&(s), cells, MAX_CELLS) ==              \
                  DNAC_TAIR_TABLE_ERR_PARAM,                                   \
              "N4[%s]: generate accepted", name);                              \
    } while (0)

    { dnac_tair_script_t s = { NULL, 4, starts, 1 };   REJECT_SCRIPT("NULL ops", s); }
    { dnac_tair_script_t s = { ops, 0, starts, 1 };    REJECT_SCRIPT("zero ops", s); }
    { dnac_tair_script_t s = { ops, 4, NULL, 1 };      REJECT_SCRIPT("NULL starts", s); }
    { dnac_tair_script_t s = { ops, 4, starts, 0 };    REJECT_SCRIPT("zero starts", s); }
    {
        size_t bad[1] = { 1 }; /* first start must be op 0 (the row-0 boundary) */
        dnac_tair_script_t s = { ops, 4, bad, 1 };
        REJECT_SCRIPT("first start != op 0", s);
    }
    {
        size_t bad[2] = { 0, 4 }; /* a start at n_ops has no op after it */
        dnac_tair_script_t s = { ops, 4, bad, 2 };
        REJECT_SCRIPT("start index == n_ops", s);
    }
    {
        size_t bad[2] = { 0, 0 }; /* not strictly ascending */
        dnac_tair_script_t s = { ops, 4, bad, 2 };
        REJECT_SCRIPT("duplicate start index", s);
    }
    {
        static dnac_tair_op_t o[2];
        memset(o, 0, sizeof(o));
        o[0].kind = DNAC_TAIR_OP_OBSERVE;
        o[0].is_pow = 1; /* an observe carries no PoW modifier */
        o[1].kind = DNAC_TAIR_OP_SAMPLE;
        dnac_tair_script_t s = { o, 2, starts, 1 };
        REJECT_SCRIPT("is_pow on an observe", s);
    }
    {
        static dnac_tair_op_t o[2];
        memset(o, 0, sizeof(o));
        o[0].kind = DNAC_TAIR_OP_SAMPLE;
        o[0].is_pow = 1;
        o[0].pow_bits = 0; /* check_witness(0) emits NO ops at all */
        o[1].kind = DNAC_TAIR_OP_SAMPLE;
        dnac_tair_script_t s = { o, 2, starts, 1 };
        REJECT_SCRIPT("is_pow with 0 grinding bits", s);
    }
    {
        static dnac_tair_op_t o[2];
        memset(o, 0, sizeof(o));
        o[0].kind = DNAC_TAIR_OP_SAMPLE;
        o[0].num_bits = TAIR_TBL_MAX_OP_BITS + 1;
        o[1].kind = DNAC_TAIR_OP_SAMPLE;
        dnac_tair_script_t s = { o, 2, starts, 1 };
        REJECT_SCRIPT("num_bits > MAX_OP_BITS", s);
    }
    {
        static dnac_tair_op_t o[2];
        memset(o, 0, sizeof(o));
        o[0].kind = DNAC_TAIR_OP_OBSERVE;
        o[0].num_bits = 4; /* an observe exports no bits */
        o[1].kind = DNAC_TAIR_OP_SAMPLE;
        dnac_tair_script_t s = { o, 2, starts, 1 };
        REJECT_SCRIPT("observe exporting bits", s);
    }
#undef REJECT_SCRIPT

    /* Two DIFFERENT non-zero grinding widths in one script: the AIR carries ONE
     * cfg->pow_bits, so this is out of contract. */
    {
        static dnac_tair_op_t o[4];
        memset(o, 0, sizeof(o));
        o[0].kind = DNAC_TAIR_OP_OBSERVE;
        o[1].kind = DNAC_TAIR_OP_SAMPLE; o[1].is_pow = 1; o[1].pow_bits = 8;
        o[2].kind = DNAC_TAIR_OP_OBSERVE;
        o[3].kind = DNAC_TAIR_OP_SAMPLE; o[3].is_pow = 1; o[3].pow_bits = 16;
        dnac_tair_script_t s = { o, 4, starts, 1 };
        size_t pb = 0;
        CHECK(dnac_tair_script_pow_bits(&s, &pb) == DNAC_TAIR_TABLE_ERR_PARAM,
              "N4: disagreeing PoW widths accepted");
    }

    /* FRI-tail cfg gates. */
#define REJECT_FRI(name, ...)                                                 \
    do {                                                                      \
        const dnac_tair_fri_cfg_t c = __VA_ARGS__;                            \
        dnac_tair_script_t s;                                                 \
        CHECK(dnac_tair_fri_num_ops(&c) == 0, "N4[%s]: num_ops != 0", name);   \
        CHECK(dnac_tair_fri_build_script(&c, ops, MAX_OPS, starts, &s) ==      \
                  DNAC_TAIR_TABLE_ERR_PARAM,                                   \
              "N4[%s]: build accepted", name);                                 \
    } while (0)

    CHECK(dnac_tair_fri_num_ops(NULL) == 0, "N4: fri_num_ops(NULL)");
    REJECT_FRI("R == 0",            { 0, 0, 2, 5, 0, 0 });
    REJECT_FRI("num_queries == 0",  { 3, 0, 0, 5, 0, 0 });
    REJECT_FRI("lgmh == 0",         { 3, 0, 2, 0, 0, 0 });
    REJECT_FRI("lgmh > 32",         { 3, 0, 2, 33, 0, 0 });
    REJECT_FRI("commit_pow > 32",   { 3, 0, 2, 5, 33, 0 });
    REJECT_FRI("PoW widths differ", { 3, 0, 2, 5, 8, 16 });
    REJECT_FRI("script too long",   { 32, 0, 32, 5, 0, 0 });
#undef REJECT_FRI

    {
        const dnac_tair_fri_cfg_t c = { 3, 0, 2, 5, 0, 0 };
        dnac_tair_script_t s;
        CHECK(dnac_tair_fri_build_script(&c, ops, 4, starts, &s) ==
                  DNAC_TAIR_TABLE_ERR_CAPACITY,
              "N4: fri_build_script(ops_cap too small)");
        CHECK(dnac_tair_fri_build_script(&c, NULL, MAX_OPS, starts, &s) ==
                  DNAC_TAIR_TABLE_ERR_PARAM,
              "N4: fri_build_script(NULL ops)");
    }

    /* Row-record fail-close. */
    {
        dnac_tair_row_t rec;
        CHECK(dnac_tair_table_row(&g_ref, dnac_tair_table_rows(&g_ref), &rec) ==
                  DNAC_TAIR_TABLE_ERR_PARAM,
              "N4: table_row(row >= rows)");
        CHECK(dnac_tair_table_row(&g_ref, 0, NULL) ==
                  DNAC_TAIR_TABLE_ERR_PARAM,
              "N4: table_row(NULL out)");
    }

    /* Validator fail-close on a wrong row count. */
    {
        const size_t rows = dnac_tair_table_rows(&g_ref);
        CHECK(dnac_tair_table_generate(&g_ref, cells, MAX_CELLS) ==
                  DNAC_TAIR_TABLE_OK,
              "N4: ref generate");
        CHECK(dnac_tair_table_validate(&g_ref, cells, rows - 1, NULL) ==
                  DNAC_TAIR_TABLE_ERR_PARAM,
              "N4: validate(rows - 1)");
        CHECK(dnac_tair_table_validate(&g_ref, NULL, rows, NULL) ==
                  DNAC_TAIR_TABLE_ERR_PARAM,
              "N4: validate(NULL cells)");
    }
}

/* ==========================================================================
 * N5 — the COMPOSED script: the priming/PCS blocks are load-bearing
 *
 * Every negative here attacks the property the composition's ordinal offsets
 * rest on: that BLOCK 1 and BLOCK 2 are exactly where and exactly what the
 * builder says. A schedule that got them wrong would shift every pop and every
 * observe ordinal the entry aliases by.
 * ======================================================================== */
static void n5_composed(void)
{
    static uint64_t base[MAX_CELLS], other[MAX_CELLS];
    static dnac_tair_op_t mut[MAX_OPS];
    static size_t starts[TAIR_TBL_MAX_STARTS];
    const dnac_tair_full_cfg_t *full = dnac_tair_ref_full_cfg();
    const size_t rows = dnac_tair_table_rows(&g_ref);
    const size_t off_pcs =
        (size_t)DNAC_DUPLEX_RATE + dnac_tair_priming_num_ops(&full->priming);
    const size_t off_tail = off_pcs + dnac_tair_pcs_num_ops(&full->priming);

    if (rows == 0 ||
        dnac_tair_table_generate(&g_ref, base, MAX_CELLS) !=
            DNAC_TAIR_TABLE_OK) {
        CHECK(0, "N5: ref generate failed");
        return;
    }
    CHECK(off_pcs > (size_t)DNAC_DUPLEX_RATE && off_tail > off_pcs &&
              off_tail < g_ref.n_ops,
          "N5: the block offsets are degenerate (%zu / %zu / %zu)", off_pcs,
          off_tail, g_ref.n_ops);
    if (!(off_pcs > (size_t)DNAC_DUPLEX_RATE && off_tail > off_pcs &&
          off_tail < g_ref.n_ops)) {
        return;
    }
    starts[0] = 0;

    /* N5a — DROP one priming op. The REF cells describe a 93-op run; a 92-op
     *       script cannot claim them. (The padded height does not move — 94 and
     *       95 scheduled rows both pad to 128 — so this really is the SCRIPT
     *       check firing and not a row-count reject.) */
    {
        size_t n = 0;
        dnac_tair_script_t s;
        dnac_tair_table_defect_t d = DNAC_TAIR_DEFECT_NONE;
        for (size_t k = 0; k < g_ref.n_ops; k++) {
            if (k == off_pcs - 1) continue; /* zeta's second pop */
            mut[n++] = g_ref.ops[k];
        }
        s.ops = mut; s.n_ops = n; s.instance_starts = starts; s.n_starts = 1;
        CHECK(dnac_tair_table_rows(&s) == rows,
              "N5a: the shortened script changed the height — the negative "
              "would be a row-count reject, not a SCRIPT one");
        CHECK(dnac_tair_table_validate(&s, base, rows, &d) ==
                      DNAC_TAIR_TABLE_ERR_SCHEDULE &&
                  d == DNAC_TAIR_DEFECT_SCRIPT,
              "N5a: a dropped priming op was ACCEPTED (defect %d)", (int)d);
    }

    /* N5b — TRANSPOSE two adjacent ops of different kinds. The cells stay a
     *       legal challenger run (the machine walk passes), so this isolates the
     *       SCRIPT check: the op at that index has the wrong KIND. */
    {
        dnac_tair_script_t s;
        dnac_tair_table_defect_t d = DNAC_TAIR_DEFECT_NONE;
        size_t swap = off_pcs - 1; /* a SAMPLE; off_pcs is an OBSERVE */
        memcpy(mut, g_ref.ops, g_ref.n_ops * sizeof(mut[0]));
        CHECK(g_ref.ops[swap].kind != g_ref.ops[swap + 1].kind,
              "N5b: the transposed pair has the same kind — vacuous");
        mut[swap] = g_ref.ops[swap + 1];
        mut[swap + 1] = g_ref.ops[swap];
        s.ops = mut; s.n_ops = g_ref.n_ops;
        s.instance_starts = starts; s.n_starts = 1;
        CHECK(dnac_tair_table_validate(&s, base, rows, &d) ==
                      DNAC_TAIR_TABLE_ERR_SCHEDULE &&
                  d == DNAC_TAIR_DEFECT_SCRIPT,
              "N5b: a transposed op pair was ACCEPTED (defect %d)", (int)d);
    }

    /* N5c — move the WHOLE PCS block BEHIND the FRI tail. Two claims:
     *       (i)  the table it generates is a DIFFERENT table, so the pin
     *            discriminates the block order (the root moves);
     *       (ii) the REF cells are rejected against it, and vice versa. */
    {
        size_t n = 0;
        dnac_tair_script_t s;
        dnac_tair_table_defect_t d = DNAC_TAIR_DEFECT_NONE;
        for (size_t k = 0; k < off_pcs; k++) mut[n++] = g_ref.ops[k];
        for (size_t k = off_tail; k < g_ref.n_ops; k++) mut[n++] = g_ref.ops[k];
        for (size_t k = off_pcs; k < off_tail; k++) mut[n++] = g_ref.ops[k];
        s.ops = mut; s.n_ops = n; s.instance_starts = starts; s.n_starts = 1;
        CHECK(n == g_ref.n_ops, "N5c: the reordered script lost ops (%zu)", n);
        CHECK(dnac_tair_table_rows(&s) == rows,
              "N5c: the reordered script changed the height");
        if (dnac_tair_table_generate(&s, other, MAX_CELLS) !=
            DNAC_TAIR_TABLE_OK) {
            CHECK(0, "N5c: reordered generate failed");
        } else {
            uint64_t r_base[4], r_other[4];
            CHECK(memcmp(base, other, rows * COLS * sizeof(uint64_t)) != 0,
                  "N5c: moving the PCS block behind the tail produced the SAME "
                  "table — the schedule does not see the block order");
            CHECK(p2a_commit_table(base, rows, r_base) &&
                      p2a_commit_table(other, rows, r_other) &&
                      memcmp(r_base, r_other, sizeof(r_base)) != 0,
                  "N5c: the two block orders share a preprocessed root");
            CHECK(dnac_tair_table_validate(&g_ref, other, rows, &d) ==
                      DNAC_TAIR_TABLE_ERR_SCHEDULE,
                  "N5c: the reordered table validated against the REF script");
        }
        d = DNAC_TAIR_DEFECT_NONE;
        CHECK(dnac_tair_table_validate(&s, base, rows, &d) ==
                  DNAC_TAIR_TABLE_ERR_SCHEDULE,
              "N5c: the REF table validated against the reordered script");
    }

    /* N5d — THE ROW BOUND, which is what actually caps a script. A 126-op
     *       one-instance script pads to exactly TAIR_TBL_MAX_ROWS and is
     *       accepted; 127 ops needs 129 rows and `tair_script_check`
     *       (transcript_air_table.c:42-91) rejects it, as does the full
     *       MAX_STEPS-long one. Both legs, so the bound is not vacuous. */
    {
        const size_t fit = TAIR_TBL_MAX_ROWS - 2; /* 1 start + fit + 1 filler */
        dnac_tair_script_t s_ok, s_bad, s_max;
        for (size_t i = 0; i < TAIR_TBL_MAX_STEPS; i++) {
            memset(&mut[i], 0, sizeof(mut[i]));
            mut[i].kind = DNAC_TAIR_OP_OBSERVE;
        }
        s_ok.ops = mut; s_ok.n_ops = fit;
        s_ok.instance_starts = starts; s_ok.n_starts = 1;
        s_bad.ops = mut; s_bad.n_ops = fit + 1;
        s_bad.instance_starts = starts; s_bad.n_starts = 1;
        s_max.ops = mut; s_max.n_ops = TAIR_TBL_MAX_STEPS;
        s_max.instance_starts = starts; s_max.n_starts = 1;
        CHECK(dnac_tair_table_rows(&s_ok) == TAIR_TBL_MAX_ROWS,
              "N5d: a %zu-op script does not pad to MAX_ROWS", fit);
        CHECK(dnac_tair_table_rows(&s_bad) == 0,
              "N5d: a %zu-op script was ACCEPTED past the row bound", fit + 1);
        CHECK(dnac_tair_table_rows(&s_max) == 0,
              "N5d: a MAX_STEPS-op script was ACCEPTED past the row bound");
        CHECK(dnac_tair_table_generate(&s_bad, base, MAX_CELLS) ==
                  DNAC_TAIR_TABLE_ERR_PARAM,
              "N5d: generate accepted a script past the row bound");
    }

    /* N5e — the priming/full cfg gates, one per rejected shape. */
    {
        /* Sized to the CAP, not to 2: the "op budget" leg below sets
         * `n = TAIR_TBL_MAX_INNER_INSTANCES` and the cfg gate walks every
         * instance, so a 2-element array would be read out of bounds. */
        static dnac_tair_inner_inst_t bad_inst[TAIR_TBL_MAX_INNER_INSTANCES];
        dnac_tair_full_cfg_t c;
        dnac_tair_script_t s;

#define REJECT_FULL(name)                                                     \
        do {                                                                  \
            CHECK(dnac_tair_full_num_ops(&c) == 0, "N5e[%s]: num_ops != 0",    \
                  name);                                                      \
            CHECK(dnac_tair_full_build_script(&c, mut, MAX_OPS, starts, &s) == \
                      DNAC_TAIR_TABLE_ERR_PARAM,                              \
                  "N5e[%s]: build accepted", name);                            \
        } while (0)

        CHECK(dnac_tair_full_num_ops(NULL) == 0, "N5e: full_num_ops(NULL)");
        CHECK(dnac_tair_priming_num_ops(NULL) == 0, "N5e: priming(NULL)");
        CHECK(dnac_tair_pcs_num_ops(NULL) == 0, "N5e: pcs(NULL)");

        for (size_t i = 0; i < TAIR_TBL_MAX_INNER_INSTANCES; i++) {
            bad_inst[i] = full->priming.insts[0];
        }
        c = *full;
        c.priming.insts = bad_inst;
        c.priming.n = 2;

        c.priming.insts = NULL;             REJECT_FULL("NULL insts");
        c.priming.insts = bad_inst;
        c.priming.n = 0;                    REJECT_FULL("zero instances");
        c.priming.n = TAIR_TBL_MAX_INNER_INSTANCES + 1;
                                            REJECT_FULL("too many instances");
        c.priming.n = 2;
        c.priming.is_zk = 2;                REJECT_FULL("is_zk out of {0,1}");
        c.priming.is_zk = 0;
        c.priming.num_random_codewords = 1; REJECT_FULL("nrc > 0 on a non-ZK");
        c.priming.num_random_codewords = 0;

        bad_inst[0].main_width = 0;         REJECT_FULL("main_width 0");
        bad_inst[0] = full->priming.insts[0];
        bad_inst[0].num_quotient_chunks = 0; REJECT_FULL("quotient chunks 0");
        bad_inst[0] = full->priming.insts[0];
        bad_inst[0].preprocessed_width = 0;
        bad_inst[0].prep_next = 1;          REJECT_FULL("prep_next w/o a prep matrix");
        bad_inst[0] = full->priming.insts[0];
        bad_inst[0].main_next = 2;          REJECT_FULL("main_next out of {0,1}");
        bad_inst[0] = full->priming.insts[0];
        bad_inst[0].num_publics = TAIR_TBL_MAX_INNER_LANES + 1;
                                            REJECT_FULL("publics past the cap");
        bad_inst[0] = full->priming.insts[0];

        /* A shape that is INDIVIDUALLY legal but blows the op budget: 32
         * instances cost 8 binding observes each before anything else. */
        c.priming.n = TAIR_TBL_MAX_INNER_INSTANCES;
        REJECT_FULL("script past TAIR_TBL_MAX_STEPS");
        c.priming.n = 2;

        /* The FRI half's gate still applies through the composed entry. */
        c.fri.num_queries = 0;              REJECT_FULL("FRI num_queries 0");
        c.fri = full->fri;

        /* And the buffer contract. */
        CHECK(dnac_tair_full_build_script(&c, mut, 4, starts, &s) ==
                  DNAC_TAIR_TABLE_ERR_CAPACITY,
              "N5e: full_build_script(ops_cap too small)");
        CHECK(dnac_tair_full_build_script(&c, NULL, MAX_OPS, starts, &s) ==
                  DNAC_TAIR_TABLE_ERR_PARAM,
              "N5e: full_build_script(NULL ops)");
        CHECK(dnac_tair_full_build_script(&c, mut, MAX_OPS, NULL, &s) ==
                  DNAC_TAIR_TABLE_ERR_PARAM,
              "N5e: full_build_script(NULL starts)");
#undef REJECT_FULL
    }
}

/* ==========================================================================
 * --print-roots — the ORCHESTRATOR fills DNAC_P2A_PREP_ROOT_LANE* from this
 * ======================================================================== */
static int print_roots(void)
{
    static uint64_t cells[MAX_CELLS];
    if (!build_ref()) {
        fprintf(stderr, "print-roots: reference script build failed\n");
        return 2;
    }
    const size_t rows = dnac_tair_table_rows(&g_ref);
    if (rows == 0 ||
        dnac_tair_table_generate(&g_ref, cells, MAX_CELLS) !=
            DNAC_TAIR_TABLE_OK) {
        fprintf(stderr, "print-roots: generate failed\n");
        return 2;
    }
    dnac_tair_table_defect_t d = DNAC_TAIR_DEFECT_NONE;
    if (dnac_tair_table_validate(&g_ref, cells, rows, &d) !=
        DNAC_TAIR_TABLE_OK) {
        fprintf(stderr,
                "print-roots: the table FAILED its own validator (defect %d) —"
                " refusing to print a root\n",
                (int)d);
        return 2;
    }
    uint64_t lanes[4];
    if (!p2a_commit_table(cells, rows, lanes)) {
        fprintf(stderr, "print-roots: LDE/commit pipeline failed\n");
        return 2;
    }
    printf("/* DNAC_P2A_PREP_ROOT — reference script (COMPOSED: DS prefix +"
           " priming + PCS + FRI tail)\n"
           " * inner proof: N=%zu is_zk=%d nrc=%zu pubs=%zu mw=%zu mn=%d"
           " pw=%zu pn=%d nqc=%zu lookups=%zu\n"
           " * FRI tail:    R=%zu lfpl=%zu Q=%zu lgmh=%zu pow=%zu/%zu\n"
           " * blocks:      %zu DS + %zu priming + %zu pcs + %zu tail = %zu ops,"
           " %zu rows x %zu cols */\n",
           dnac_tair_ref_full_cfg()->priming.n,
           dnac_tair_ref_full_cfg()->priming.is_zk,
           dnac_tair_ref_full_cfg()->priming.num_random_codewords,
           dnac_tair_ref_full_cfg()->priming.insts[0].num_publics,
           dnac_tair_ref_full_cfg()->priming.insts[0].main_width,
           dnac_tair_ref_full_cfg()->priming.insts[0].main_next,
           dnac_tair_ref_full_cfg()->priming.insts[0].preprocessed_width,
           dnac_tair_ref_full_cfg()->priming.insts[0].prep_next,
           dnac_tair_ref_full_cfg()->priming.insts[0].num_quotient_chunks,
           dnac_tair_ref_full_cfg()->priming.insts[0].num_lookups,
           dnac_tair_ref_fri_cfg()->R,
           dnac_tair_ref_fri_cfg()->log_final_poly_len,
           dnac_tair_ref_fri_cfg()->num_queries,
           dnac_tair_ref_fri_cfg()->lgmh,
           dnac_tair_ref_fri_cfg()->commit_pow_bits,
           dnac_tair_ref_fri_cfg()->query_pow_bits,
           (size_t)DNAC_DUPLEX_RATE,
           dnac_tair_priming_num_ops(&dnac_tair_ref_full_cfg()->priming),
           dnac_tair_pcs_num_ops(&dnac_tair_ref_full_cfg()->priming),
           g_ref.n_ops - (size_t)DNAC_DUPLEX_RATE -
               dnac_tair_priming_num_ops(&dnac_tair_ref_full_cfg()->priming) -
               dnac_tair_pcs_num_ops(&dnac_tair_ref_full_cfg()->priming),
           g_ref.n_ops, rows, COLS);
    for (int i = 0; i < 4; i++) {
        printf("#define DNAC_P2A_PREP_ROOT_LANE%d UINT64_C(0x%016" PRIx64 ")\n",
               i, lanes[i]);
    }
    return 0;
}

/* ========================================================================== */

int main(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "--print-roots") == 0) {
        return print_roots();
    }

    printf("============================================================\n");
    printf("s3a PIN slice — transcript AIR preprocessed OP-SCHEDULE table\n");
    printf("  %zu cols (6 type + is_pow + %zu step one-hot)\n", COLS,
           TAIR_TBL_MAX_STEPS);
    printf("============================================================\n");

    if (!build_ref()) {
        fprintf(stderr, "  FATAL: reference script build failed\n");
        return 1;
    }

    t1_determinism();
    t2_schedule();
    t3_pin();
    n3_validator();
    n4_failclose();
    n5_composed();

    printf("------------------------------------------------------------\n");
    if (g_fails) {
        printf("s3a transcript table: %d/%d checks FAILED\n", g_fails, g_checks);
        if (DNAC_P2A_PREP_ROOT_UNFILLED) {
            printf("  (DNAC_P2A_PREP_ROOT is still the placeholder — run\n"
                   "   `%s --print-roots` and paste the four lanes into\n"
                   "   transcript_air_table.h)\n",
                   argv[0]);
        }
        return 1;
    }
    printf("s3a transcript table: %d checks PASS\n", g_checks);
    return 0;
}
