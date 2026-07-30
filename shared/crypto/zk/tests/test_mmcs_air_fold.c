/**
 * @file test_mmcs_air_fold.c
 * @brief s1a — equivalence gate for the same-height MMCS control-AIR's FOLD form.
 *
 * Build spec: dnac/docs/plans/2026-07-29-composition-s1a-fold-evals-BUILDABLE.md
 * §4 (T-EQ / T-CNT / T-NEG / T-TERM).
 *
 * ── HONEST LABEL ────────────────────────────────────────────────────────────
 * Nothing here is byte-matched against Plonky3. What is proved is an
 * EQUIVALENCE between two DNAC artifacts: the shipped u64 evaluator
 * (`mmcs_air.c`, gated by tests/test_mmcs_air.c against a NATIVE
 * commit/open/verify replay) and the fold-form transcription
 * (`mmcs_air_fold.c`). The native grounding is INHERITED through the honest
 * trace builder, which is the SHIPPED one — this file `#include`s
 * `test_mmcs_air.c` (with its `main` renamed out of the way) rather than copying
 * `make_fixture` / `build_trace` / `regen_perm`, so the two suites cannot drift
 * apart. The shipped file is NOT modified.
 *
 * (accept) T-EQ: 3 configs (incl. leaf == 1 and both sponge residue classes) at
 *   non-palindromic indices fold to ALL-ZERO captured residuals on every row.
 * (accept) T-CNT: `capture_len` is identical on every row and equals
 *   `dnac_mmcs_air_fold_control_steps(cfg)` + the MEASURED Poseidon2 step count.
 * (reject) T-NEG: 8 tampers carried over from the shipped negative suite.
 * (reject) T-TERM: an otherwise-valid TYPED last row trips the `is_last_row`
 *   boundary in isolation (EXACTLY one non-zero residual).
 *
 * Build (via Makefile):  ./build/test_mmcs_air_fold        (no vector files)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

/* Reuse the SHIPPED fixture + honest-trace builder verbatim (see the note
 * above). Every static helper of that file — cell, make_fixture, build_trace,
 * built_free, row_of, regen_perm, clone_trace/prep/pub, bitrev, eval_built — is
 * available in this translation unit; its `main` is renamed and never called. */
#define main dnac_mair_shipped_main_unused
#include "test_mmcs_air.c"
#undef main

#include "../mmcs_air_fold.h"
#include "../poseidon2_fold.h"
#include "fold_test_util.h"

/* ══════════════════════════════ reporting ════════════════════════════════ */

static void fexpect_clean(const char *name, const fold_input_t *in,
                          size_t want_steps) {
    const fold_trace_t T = fold_eval_trace(in);
    if (T.overflow) {
        printf("  [accept] %-46s capture OVERFLOW — FAIL\n", name);
        fails++;
        return;
    }
    if (T.nonzero != 0) {
        printf("  [accept] %-46s %zu non-zero (row %zu) — FAIL\n", name, T.nonzero,
               T.bad_row);
        fails++;
        return;
    }
    if (!T.steps_uniform) {
        printf("  [accept] %-46s capture_len NOT uniform — FAIL\n", name);
        fails++;
        return;
    }
    if (T.steps_row0 != want_steps) {
        printf("  [accept] %-46s %zu steps (want %zu) — FAIL\n", name, T.steps_row0,
               want_steps);
        fails++;
        return;
    }
    printf("  [accept] %-46s %2zu rows x %zu steps, 0 non-zero — OK\n", name,
           in->n_rows, T.steps_row0);
}

static void fexpect_reject(const char *name, const fold_input_t *in,
                           size_t want_exact) {
    const fold_trace_t T = fold_eval_trace(in);
    if (T.overflow) {
        printf("  [reject] %-46s capture OVERFLOW — FAIL\n", name);
        fails++;
        return;
    }
    if (T.nonzero == 0) {
        printf("  [reject] %-46s NOT caught — FAIL\n", name);
        fails++;
        return;
    }
    if (want_exact > 0 && T.nonzero != want_exact) {
        printf("  [reject] %-46s %zu non-zero (want %zu) — FAIL\n", name, T.nonzero,
               want_exact);
        fails++;
        return;
    }
    printf("  [reject] %-46s caught (%zu non-zero, row %zu) — OK\n", name,
           T.nonzero, T.bad_row);
}

/* Global measured Poseidon2 block cost (set in main). */
static size_t g_p2_steps;
static dnac_stark_air_t g_air;

/* Fold one honest (cfg, index) opening; optionally keep the built trace. */
static int fold_accept_case(const dnac_p2b_table_cfg_t *cfg, uint64_t index,
                            const char *label, built_t *keep) {
    fixture_t *F = (fixture_t *)calloc(1, sizeof(fixture_t));
    built_t B;
    if (!F) return 0;

    if (!make_fixture(cfg, index, F)) {
        printf("  [accept] %-46s native commit/open/verify — FAIL\n", label);
        fails++;
        free(F);
        return 0;
    }
    if (!build_trace(&B, cfg, index, F->elems, F->sibs, F->root.lanes)) {
        printf("  [accept] %-46s honest trace build — FAIL\n", label);
        fails++;
        free(F);
        return 0;
    }
    free(F);

    /* The u64 evaluator must accept it, else the equivalence claim below is
     * measured against a broken baseline. */
    if (eval_built(&B) != 0) {
        printf("  [accept] %-46s u64 baseline not clean — FAIL\n", label);
        fails++;
        built_free(&B);
        return 0;
    }
    if (dnac_mmcs_air_fold_bind(cfg, &g_air) != 0) {
        printf("  [accept] %-46s bind — FAIL\n", label);
        fails++;
        built_free(&B);
        return 0;
    }

    const fold_input_t in = {&g_air, B.trace,
                             B.rows, (size_t)MAIR_WIDTH,
                             B.prep, (size_t)DNAC_P2B_TABLE_COLS,
                             B.pub,  B.num_pub};
    fexpect_clean(label, &in,
                  dnac_mmcs_air_fold_control_steps(cfg) + g_p2_steps);

    if (keep) *keep = B; /* ownership moves to the caller */
    else built_free(&B);
    return 1;
}

/* ═════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    printf("============================================================\n");
    printf("s1a — same-height MMCS control-AIR, FOLD form (fp2 alpha-fold)\n");
    printf("  equivalence vs the shipped u64 evaluator, same trace\n");
    printf("============================================================\n");

    g_p2_steps = fold_measure_block(dnac_poseidon2_fold_eval, (size_t)P2AIR_NUM_COLS);
    if (g_p2_steps == 0) {
        printf("  FAIL: could not measure the Poseidon2 block step count\n");
        return 2;
    }
    printf("  [info]   embedded Poseidon2 block: %zu fold steps\n", g_p2_steps);

    const dnac_p2b_table_cfg_t *A = dnac_p2b_ref_cfg();
    memset(&g_air, 0, sizeof(g_air));

    /* ── Gate 0: bind contract + fail-close ── */
    {
        if (dnac_mmcs_air_fold_bind(NULL, &g_air) != 0)
            printf("  [accept] bind(NULL cfg) rejected                        OK\n");
        else { printf("  [accept] bind(NULL cfg) rejected                        FAIL\n"); fails++; }

        if (dnac_mmcs_air_fold_bind(A, NULL) != 0)
            printf("  [accept] bind(NULL out_air) rejected                    OK\n");
        else { printf("  [accept] bind(NULL out_air) rejected                    FAIL\n"); fails++; }

        /* depth == 0 is not a Merkle tree (mmcs_air_table.c:36) — the u64
         * module's schedule authority rejects it, so this module must too. */
        {
            static const size_t w2[2] = {4, 4};
            const dnac_p2b_table_cfg_t bad = {2, w2, 0};
            if (dnac_mmcs_air_fold_bind(&bad, &g_air) != 0 &&
                dnac_mmcs_air_fold_control_steps(&bad) == 0)
                printf("  [accept] bind(depth == 0) rejected                      OK\n");
            else { printf("  [accept] bind(depth == 0) rejected                      FAIL\n"); fails++; }
        }
        /* A schedule too tall for the step one-hot (the u64's MAIR_MAX_STEPS
         * gate, test_mmcs_air.c:478-487). */
        {
            static const size_t wide[1] = {248};
            const dnac_p2b_table_cfg_t big = {1, wide, 4};
            if (dnac_mmcs_air_fold_bind(&big, &g_air) != 0)
                printf("  [accept] bind(schedule > MAIR_MAX_STEPS) rejected       OK\n");
            else { printf("  [accept] bind(schedule > MAIR_MAX_STEPS) rejected       FAIL\n"); fails++; }
        }
        /* A schedule leaving NO padding row (test_mmcs_air.c:488-498): the u64
         * rejects it up front, so terminality can never be vacuous. */
        {
            static const size_t exact[1] = {12};
            const dnac_p2b_table_cfg_t nopad = {1, exact, 4};
            if (dnac_mmcs_air_fold_bind(&nopad, &g_air) != 0)
                printf("  [accept] bind(schedule with no padding row) rejected    OK\n");
            else { printf("  [accept] bind(schedule with no padding row) rejected    FAIL\n"); fails++; }
        }
        /* The last rejected bind must have left the module DISARMED. */
        {
            uint64_t *zt = (uint64_t *)calloc((size_t)MAIR_WIDTH * 2, sizeof(uint64_t));
            uint64_t *zp = (uint64_t *)calloc((size_t)DNAC_P2B_TABLE_COLS * 2,
                                              sizeof(uint64_t));
            uint64_t zpub[4] = {0, 0, 0, 0};
            if (!zt || !zp) return 2;
            dnac_stark_air_t probe = {(size_t)MAIR_WIDTH, 4, 1,
                                      dnac_mmcs_air_fold_eval};
            fold_input_t in = {&probe, zt, 2, (size_t)MAIR_WIDTH,
                               zp, (size_t)DNAC_P2B_TABLE_COLS, zpub, 4};
            const fold_trace_t T = fold_eval_trace(&in);
            if (T.nonzero == 2 && T.steps_row0 == 1)
                printf("  [accept] unbound eval is unsatisfiable (fail-close)     OK\n");
            else {
                printf("  [accept] unbound eval is unsatisfiable (fail-close)     "
                       "FAIL (%zu non-zero, %zu steps)\n", T.nonzero, T.steps_row0);
                fails++;
            }
            free(zt);
            free(zp);
        }
        /* Descriptor fields on a good bind. */
        if (dnac_mmcs_air_fold_bind(A, &g_air) == 0 &&
            g_air.main_width == (size_t)MAIR_WIDTH &&
            g_air.num_public_values == dnac_mmcs_air_num_publics(A) &&
            g_air.main_next == 1 && g_air.air_eval == dnac_mmcs_air_fold_eval)
            printf("  [accept] descriptor {w=%zu, pubs=%zu, next=1}             OK\n",
                   g_air.main_width, g_air.num_public_values);
        else {
            printf("  [accept] descriptor fields                              FAIL\n");
            fails++;
        }
        /* A folder whose public count disagrees with the binding fails closed —
         * the fold-form image of the u64's `num_publics != required` gate
         * (mmcs_air.c:185). */
        {
            built_t B;
            fixture_t *F = (fixture_t *)calloc(1, sizeof(fixture_t));
            if (F && make_fixture(A, 3, F) &&
                build_trace(&B, A, 3, F->elems, F->sibs, F->root.lanes)) {
                fold_input_t in = {&g_air, B.trace,
                                   B.rows, (size_t)MAIR_WIDTH,
                                   B.prep, (size_t)DNAC_P2B_TABLE_COLS,
                                   B.pub,  B.num_pub - 1};
                const fold_trace_t T = fold_eval_trace(&in);
                if (T.nonzero == B.rows && T.steps_row0 == 1)
                    printf("  [accept] wrong public count fails closed                OK\n");
                else {
                    printf("  [accept] wrong public count fails closed                FAIL\n");
                    fails++;
                }
                built_free(&B);
            } else {
                printf("  [accept] wrong public count fixture                     FAIL\n");
                fails++;
            }
            free(F);
        }
    }

    /* ══ PHASE 1 — T-EQ + T-CNT ══ */
    printf("------------------------------------------------------------\n");
    printf("Phase 1 — T-EQ / T-CNT (native-replay honest traces)\n");
    printf("------------------------------------------------------------\n");

    const uint64_t IDX_A = 3;  /* depth 4, non-palindromic (bitrev = 12) */
    const uint64_t IDX_B = 3;  /* depth 3, non-palindromic (bitrev = 6)  */

    built_t W;
    memset(&W, 0, sizeof(W));
    if (!fold_accept_case(A, IDX_A, "ref {8,5} d4 (partial final block)", &W))
        return 1;
    fold_accept_case(&CFG_B, IDX_B, "alt {4,4} d3 (exact block boundary)", NULL);
    fold_accept_case(&CFG_C, IDX_A, "one {2}   d4 (leaf == 1)", NULL);

    /* Re-bind the workhorse cfg for the negative phase. */
    if (dnac_mmcs_air_fold_bind(W.cfg, &g_air) != 0) {
        printf("  FAIL: workhorse re-bind\n");
        return 1;
    }

    /* ══ PHASE 2 — T-NEG ══ */
    printf("------------------------------------------------------------\n");
    printf("Phase 2 — T-NEG (tampers carried over from the u64 suite)\n");
    printf("------------------------------------------------------------\n");

    const size_t r_leaf0 = 0;
    const size_t r_comp0 = W.leaf;
    const size_t r_comp1 = W.leaf + 1;
    const size_t r_comp_last = W.leaf + W.depth - 1;

#define FOLD_IN(t, p, pub) \
    ((fold_input_t){&g_air, (t), W.rows, (size_t)MAIR_WIDTH, (p), \
                    (size_t)DNAC_P2B_TABLE_COLS, (pub), W.num_pub})

    /* F-N1 — direction bit flipped together with its PUBLIC bit, so only the
     * placement pair (block I, a TRANSITION form) can reject it. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *p = clone_pub(&W);
        row_of(t, r_comp0)[MAIR_DIR_OFF] ^= 1u;
        p[MAIR_PUB_DIR_OFF + 0] ^= 1u;
        fold_input_t in = FOLD_IN(t, W.prep, p);
        fexpect_reject("F-N1 direction bit + its public flipped", &in, 0);
        free(t);
        free(p);
    }
    /* F-N2 — sibling and running hash swapped inside a compress preimage. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_comp1);
        for (size_t j = 0; j < (size_t)MAIR_DIGEST_LANES; j++) {
            const uint64_t tmp = row[mair_perm_in_off(j)];
            row[mair_perm_in_off(j)] = row[mair_perm_in_off(MAIR_DIGEST_LANES + j)];
            row[mair_perm_in_off(MAIR_DIGEST_LANES + j)] = tmp;
        }
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N2 sibling side swapped", &in, 0);
        free(t);
    }
    /* F-N3 — wrong PUBLIC root lane. Isolated: only the final row's block-F pin
     * reads it, so EXACTLY one residual. */
    {
        uint64_t *p = clone_pub(&W);
        p[MAIR_PUB_ROOT_OFF + 2] = gold_fp_to_u64(
            gold_fp_add(gold_fp_from_u64(p[MAIR_PUB_ROOT_OFF + 2]), gold_fp_one()));
        fold_input_t in = FOLD_IN(W.trace, W.prep, p);
        fexpect_reject("F-N3 wrong public root lane", &in, 1);
        free(p);
    }
    /* F-N4 — WRONG claimed index with a correct walk: only the A1 index binding
     * (block E) sees it. */
    {
        uint64_t *p = clone_pub(&W);
        for (size_t l = 0; l < W.depth; l++)
            p[MAIR_PUB_DIR_OFF + l] = (5u >> l) & 1u; /* index 5 vs the walk's 3 */
        fold_input_t in = FOLD_IN(W.trace, W.prep, p);
        fexpect_reject("F-N4 wrong claimed index (A1 binding)", &in, 0);
        free(p);
    }
    /* F-N5 — the BIT-REVERSED index (the naive-composition trap; non-vacuous
     * because index 3 is non-palindromic at depth 4). */
    {
        uint64_t *p = clone_pub(&W);
        const uint64_t rev = bitrev(IDX_A, W.depth);
        for (size_t l = 0; l < W.depth; l++)
            p[MAIR_PUB_DIR_OFF + l] = (rev >> l) & 1u;
        fold_input_t in = FOLD_IN(W.trace, W.prep, p);
        fexpect_reject("F-N5 bit-reversed index publics", &in, 0);
        free(p);
    }
    /* F-N6 — absorbed lane != its public opened element (block D; without it
     * the AIR proves only that SOME leaf is in the tree). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_leaf0);
        row[mair_perm_in_off(1)] = gold_fp_to_u64(
            gold_fp_add(gold_fp_from_u64(row[mair_perm_in_off(1)]), gold_fp_one()));
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N6 absorbed lane != its public", &in, 0);
        free(t);
    }
    /* F-N7 — the leaf sponge does not start at zero (block D first-block fill). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_leaf0);
        row[mair_perm_in_off(MAIR_PERM_WIDTH - 1)] = 1;
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N7 leaf state not zero (capacity lane)", &in, 0);
        free(t);
    }
    /* F-N8 — garbage the LAST compression while writing the true root into the
     * final row: only the final-row threading (block J, a TRANSITION form)
     * rejects it, once per digest lane. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_comp_last);
        const size_t sib_half =
            (W.pub[MAIR_PUB_DIR_OFF + W.depth - 1] == 0) ? MAIR_DIGEST_LANES : 0;
        row[mair_perm_in_off(sib_half)] = gold_fp_to_u64(gold_fp_add(
            gold_fp_from_u64(row[mair_perm_in_off(sib_half)]), gold_fp_one()));
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N8 garbaged last compression, true root", &in,
                       (size_t)MAIR_DIGEST_LANES);
        free(t);
    }
    /* F-N9 — step one-hot double bit (block C). */
    {
        uint64_t *t = clone_trace(&W);
        row_of(t, W.leaf - 1)[mair_pos_off(0)] = 1;
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N9 step one-hot double bit", &in, 0);
        free(t);
    }
    /* F-N10 — a compress row claiming a LEAF step (block C type agreement). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, r_comp0);
        row[mair_pos_off(W.leaf)] = 0;
        row[mair_pos_off(0)] = 1;
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N10 compress row claiming a leaf step", &in, 0);
        free(t);
    }
    /* F-N11 — `dir` set on a leaf row (block B, second half). Isolated. */
    {
        uint64_t *t = clone_trace(&W);
        row_of(t, r_leaf0)[MAIR_DIR_OFF] = 1;
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N11 dir set on a leaf row", &in, 1);
        free(t);
    }
    /* F-N12 — an interior cell of the embedded Poseidon2 block (block A). */
    {
        uint64_t *t = clone_trace(&W);
        const size_t off = MAIR_PERM_OFF + p2air_beg_sbox_off(0, 0);
        uint64_t *row = row_of(t, r_comp0);
        row[off] =
            gold_fp_to_u64(gold_fp_add(gold_fp_from_u64(row[off]), gold_fp_one()));
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N12 Poseidon2 block interior tamper", &in, 0);
        free(t);
    }

    /* ══ PHASE 3 — T-TERM ══
     * The `is_last_row` boundary has no u64 PER-ROW counterpart (it lives in
     * eval_trace, mmcs_air.c:445-451), so this is the negative that proves the
     * transcription carried it. Shipped N13's recipe: the last row is turned
     * into an OTHERWISE-VALID typed row — the table types it `is_leaf`, it
     * claims step 0, and its permutation preimage is a legal first leaf block.
     * Every row-local form it touches is satisfied and it has no successor, so
     * EXACTLY the boundary fires: one non-zero residual. */
    printf("------------------------------------------------------------\n");
    printf("Phase 3 — T-TERM (is_last_row boundary)\n");
    printf("------------------------------------------------------------\n");
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *p = clone_prep(&W);
        const size_t last = W.rows - 1;
        const size_t k0 = (1 < W.leaf) ? (size_t)MAIR_RATE
                                       : W.total - (size_t)MAIR_RATE * (W.leaf - 1);
        uint64_t *row = row_of(t, last);
        p[last * DNAC_P2B_TABLE_COLS + DNAC_P2B_COL_IS_LEAF] = 1;
        row[mair_pos_off(0)] = 1;
        for (size_t j = 0; j < k0; j++)
            row[mair_perm_in_off(j)] = W.pub[dnac_mmcs_air_pub_opened_off(W.cfg) + j];
        for (size_t j = k0; j < (size_t)MAIR_PERM_WIDTH; j++)
            row[mair_perm_in_off(j)] = 0;
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, p, W.pub);
        fexpect_reject("F-T1 valid typed row with no successor", &in, 1);
        free(t);
        free(p);
    }
#undef FOLD_IN

    built_free(&W);

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("s1a MMCS FOLD: %d FAIL\n", fails);
        return 1;
    }
    printf("s1a MMCS FOLD: 3 openings T-EQ+T-CNT + 7 bind/shape gates +\n"
           "  12 T-NEG + 1 T-TERM — PASS\n");
    return 0;
}
