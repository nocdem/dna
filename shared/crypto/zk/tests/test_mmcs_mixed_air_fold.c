/**
 * @file test_mmcs_mixed_air_fold.c
 * @brief s1a — equivalence gate for the mixed-height MMCS control-AIR's FOLD
 *        form.
 *
 * Build spec: dnac/docs/plans/2026-07-29-composition-s1a-fold-evals-BUILDABLE.md
 * §4 (T-EQ / T-CNT / T-NEG / T-TERM).
 *
 * ── HONEST LABEL ────────────────────────────────────────────────────────────
 * Nothing here is byte-matched against Plonky3. What is proved is an
 * EQUIVALENCE between two DNAC artifacts: the shipped u64 evaluator
 * (`mmcs_mixed_air.c`, gated by tests/test_mmcs_mixed_air.c against a NATIVE
 * commit/open/verify_mixed replay) and the fold-form transcription
 * (`mmcs_mixed_air_fold.c`). The native grounding is INHERITED through the
 * honest trace builder, which is the SHIPPED one — this file `#include`s
 * `test_mmcs_mixed_air.c` (with its `main` renamed out of the way) rather than
 * copying `make_fixt` / `build_trace` / `sponge_over` / `emit_*`, so the two
 * suites cannot drift apart. The shipped file is NOT modified.
 *
 * (accept) T-EQ: 5 openings over 4 mixed shapes (REF, WIDE x2 indices, MG's
 *   two-matrix tallest group, INJ2's multi-row inject group) fold to ALL-ZERO
 *   captured residuals on every row.
 * (accept) T-CNT: `capture_len` is identical on every row and equals
 *   `dnac_mmix_air_fold_control_steps(cfg)` + the MEASURED Poseidon2 count.
 * (reject) T-NEG: 12 tampers carried over from the shipped suite, N-order (the
 *   load-bearing running<->rows combine-order catch) included.
 * (reject) T-TERM: the `is_last_row` boundary, isolated (EXACTLY one residual).
 *
 * Build (via Makefile):  ./build/test_mmcs_mixed_air_fold   (no vector files)
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

/* Reuse the SHIPPED fixture + honest-trace builder verbatim (see the note
 * above). Its statics — cell, make_fixt, build_trace, built_free, row_of,
 * regen_perm, clone_trace/prep/pub, bump, eval_built, find_compress_row,
 * find_inject_compress_row, CFG_REF/WIDE/MG/INJ2 — are available here; its
 * `main` is renamed and never called. */
#define main dnac_mmix_shipped_main_unused
#include "test_mmcs_mixed_air.c"
#undef main

#include "../mmcs_mixed_air_fold.h"
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

static size_t g_p2_steps;
static dnac_stark_air_t g_air;
/* FLEET 034: the binding is CALLER-OWNED state now. File scope, not a local:
 * `dnac_mmix_fold_state_t` is several KB (mmcs_mixed_air_fold.h). */
static dnac_mmix_fold_state_t g_state;

/* Fold one honest (cfg, index) opening; optionally keep the built trace. */
static int fold_accept_case(const dnac_p2c_mmix_table_cfg_t *cfg, uint64_t index,
                            const char *label, built_t *keep) {
    fixt_t *F = (fixt_t *)calloc(1, sizeof(fixt_t));
    built_t B;
    if (!F) return 0;

    if (!make_fixt(cfg, index, F)) {
        printf("  [accept] %-46s native commit/open/verify — FAIL\n", label);
        fails++;
        free(F);
        return 0;
    }
    if (!build_trace(&B, cfg, F, F->sibs, F->root.lanes)) {
        printf("  [accept] %-46s honest trace build — FAIL\n", label);
        fails++;
        free(F);
        return 0;
    }
    free(F);

    if (eval_built(&B) != 0) {
        printf("  [accept] %-46s u64 baseline not clean — FAIL\n", label);
        fails++;
        built_free(&B);
        return 0;
    }
    if (dnac_mmix_air_fold_bind(cfg, &g_state, &g_air) != 0) {
        printf("  [accept] %-46s bind — FAIL\n", label);
        fails++;
        built_free(&B);
        return 0;
    }

    const fold_input_t in = {&g_air, B.trace,
                             B.rows, (size_t)MMIX_WIDTH,
                             B.prep, (size_t)DNAC_P2C_MMIX_TABLE_COLS,
                             B.pub,  B.npub};
    fexpect_clean(label, &in, dnac_mmix_air_fold_control_steps(cfg) + g_p2_steps);

    if (keep) *keep = B; /* ownership moves to the caller */
    else built_free(&B);
    return 1;
}

/* ═════════════════════════════════ main ══════════════════════════════════ */

int main(void) {
    printf("============================================================\n");
    printf("s1a — mixed-height MMCS control-AIR, FOLD form (fp2 alpha-fold)\n");
    printf("  equivalence vs the shipped u64 evaluator, same trace\n");
    printf("============================================================\n");

    g_p2_steps = fold_measure_block(dnac_poseidon2_fold_eval, (size_t)P2AIR_NUM_COLS);
    if (g_p2_steps == 0) {
        printf("  FAIL: could not measure the Poseidon2 block step count\n");
        return 2;
    }
    printf("  [info]   embedded Poseidon2 block: %zu fold steps\n", g_p2_steps);

    memset(&g_air, 0, sizeof(g_air));

    /* ── Gate 0: bind contract + fail-close (the cfg gates the u64 module
     * applies at its eval entry, test_mmcs_mixed_air.c:515-559) ── */
    {
        if (dnac_mmix_air_fold_bind(NULL, &g_state, &g_air) != 0)
            printf("  [accept] bind(NULL cfg) rejected                        OK\n");
        else { printf("  [accept] bind(NULL cfg) rejected                        FAIL\n"); fails++; }

        if (dnac_mmix_air_fold_bind(&CFG_REF, &g_state, NULL) != 0)
            printf("  [accept] bind(NULL out_air) rejected                    OK\n");
        else { printf("  [accept] bind(NULL out_air) rejected                    FAIL\n"); fails++; }

        /* FLEET 034: a NULL state is a PARAM error, not a silent no-op. */
        if (dnac_mmix_air_fold_bind(&CFG_REF, NULL, &g_air) != 0)
            printf("  [accept] bind(NULL state) rejected                      OK\n");
        else { printf("  [accept] bind(NULL state) rejected                      FAIL\n"); fails++; }

        { /* depth != log2(max_h) */
            static const size_t w[2] = {1, 1};
            static const size_t h[2] = {8, 2};
            const dnac_p2c_mmix_table_cfg_t bad = {2, w, h, 2, 2};
            if (dnac_mmix_air_fold_bind(&bad, &g_state, &g_air) != 0 &&
                dnac_mmix_air_fold_control_steps(&bad) == 0)
                printf("  [accept] bind(depth != log2(max_h)) rejected            OK\n");
            else { printf("  [accept] bind(depth != log2(max_h)) rejected            FAIL\n"); fails++; }
        }
        { /* non-power-of-two height */
            static const size_t w[2] = {1, 1};
            static const size_t h[2] = {8, 3};
            const dnac_p2c_mmix_table_cfg_t bad = {2, w, h, 3, 2};
            if (dnac_mmix_air_fold_bind(&bad, &g_state, &g_air) != 0)
                printf("  [accept] bind(non-pow2 height) rejected                 OK\n");
            else { printf("  [accept] bind(non-pow2 height) rejected                 FAIL\n"); fails++; }
        }
        { /* zero semantic width */
            static const size_t w[2] = {0, 1};
            static const size_t h[2] = {8, 2};
            const dnac_p2c_mmix_table_cfg_t bad = {2, w, h, 3, 2};
            if (dnac_mmix_air_fold_bind(&bad, &g_state, &g_air) != 0)
                printf("  [accept] bind(width == 0) rejected                      OK\n");
            else { printf("  [accept] bind(width == 0) rejected                      FAIL\n"); fails++; }
        }
        /* The last rejected bind must have left the state DISARMED; and the two
         * FLEET 034 "no context" shapes (NULL ctx / never-bound state) must both
         * fail closed with EXACTLY one unsatisfiable residual per row. */
        {
            uint64_t *zt = (uint64_t *)calloc((size_t)MMIX_WIDTH * 2, sizeof(uint64_t));
            uint64_t *zp = (uint64_t *)calloc((size_t)DNAC_P2C_MMIX_TABLE_COLS * 2,
                                              sizeof(uint64_t));
            uint64_t zpub[8] = {0, 0, 0, 0, 0, 0, 0, 0};
            if (!zt || !zp) return 2;

            /* N-CTX-REJECT: `g_state` is whatever the width == 0 bind above left. */
            {
                dnac_stark_air_t probe = {(size_t)MMIX_WIDTH, 8, 1,
                                          dnac_mmix_air_fold_eval, &g_state};
                fold_input_t in = {&probe, zt, 2, (size_t)MMIX_WIDTH,
                                   zp, (size_t)DNAC_P2C_MMIX_TABLE_COLS, zpub, 8};
                const fold_trace_t T = fold_eval_trace(&in);
                if (g_state.bound == 0 && T.nonzero == 2 && T.steps_row0 == 1)
                    printf("  [accept] N-CTX-REJECT: disarmed, eval unsatisfiable     OK\n");
                else {
                    printf("  [accept] N-CTX-REJECT: disarmed, eval unsatisfiable     "
                           "FAIL (%zu non-zero, %zu steps)\n", T.nonzero, T.steps_row0);
                    fails++;
                }
            }
            /* N-CTX-NULL: a descriptor with no context at all. */
            {
                dnac_stark_air_t probe = {(size_t)MMIX_WIDTH, 8, 1,
                                          dnac_mmix_air_fold_eval, NULL};
                fold_input_t in = {&probe, zt, 2, (size_t)MMIX_WIDTH,
                                   zp, (size_t)DNAC_P2C_MMIX_TABLE_COLS, zpub, 8};
                const fold_trace_t T = fold_eval_trace(&in);
                if (T.nonzero == 2 && T.steps_row0 == 1)
                    printf("  [accept] N-CTX-NULL: eval unsatisfiable                 OK\n");
                else {
                    printf("  [accept] N-CTX-NULL: eval unsatisfiable                 "
                           "FAIL (%zu non-zero, %zu steps)\n", T.nonzero, T.steps_row0);
                    fails++;
                }
            }
            free(zt);
            free(zp);
        }
        /* Descriptor fields on a good bind — `ctx` now included. */
        if (dnac_mmix_air_fold_bind(&CFG_REF, &g_state, &g_air) == 0 &&
            g_air.main_width == (size_t)MMIX_WIDTH &&
            g_air.num_public_values == dnac_mmix_air_num_publics(&CFG_REF) &&
            g_air.main_next == 1 && g_air.air_eval == dnac_mmix_air_fold_eval &&
            g_air.ctx == (const void *)&g_state && g_state.bound == 1)
            printf("  [accept] descriptor {w=%zu, pubs=%zu, next=1, ctx}         OK\n",
                   g_air.main_width, g_air.num_public_values);
        else {
            printf("  [accept] descriptor fields                              FAIL\n");
            fails++;
        }
    }

    /* ══ PHASE 1 — T-EQ + T-CNT ══ */
    printf("------------------------------------------------------------\n");
    printf("Phase 1 — T-EQ / T-CNT (native-replay honest traces)\n");
    printf("------------------------------------------------------------\n");

    built_t W; /* workhorse: CFG_WIDE idx 3, TWO inject blocks */
    memset(&W, 0, sizeof(W));

    fold_accept_case(&CFG_REF, 3, "REF  {8,2}    d3", NULL);
    if (!fold_accept_case(&CFG_WIDE, 3, "WIDE {16,4,2} d4 (2 inject blocks)", &W))
        return 1;
    fold_accept_case(&CFG_WIDE, 11, "WIDE {16,4,2} d4 idx 11", NULL);
    fold_accept_case(&CFG_MG, 5, "MG   {8,8,2}  d3 (2-matrix tallest)", NULL);
    fold_accept_case(&CFG_INJ2, 5, "INJ2 {8,2} w{1,6} (multi-row inject)", NULL);

    if (dnac_mmix_air_fold_bind(W.cfg, &g_state, &g_air) != 0) {
        printf("  FAIL: workhorse re-bind\n");
        return 1;
    }

    /* ══ PHASE 2 — T-NEG ══
     * Workhorse schedule (test_mmcs_mixed_air.c:576-578):
     *   0 leaf(h16) | 1 comp l0 | 2 comp l1(inj) | 3 inj-leaf(h4) | 4 inj-comp |
     *   5 comp l2(inj) | 6 inj-leaf(h2) | 7 inj-comp | 8 comp l3 | 9 final | pad
     */
    printf("------------------------------------------------------------\n");
    printf("Phase 2 — T-NEG (tampers carried over from the u64 suite)\n");
    printf("------------------------------------------------------------\n");

    const size_t ic1 = find_inject_compress_row(&W, 1);
    const size_t c0 = find_compress_row(&W, 0);
    const size_t c1 = find_compress_row(&W, 1);
    const size_t clast = find_compress_row(&W, W.cfg->depth - 1);
    if (ic1 == (size_t)-1 || c0 == (size_t)-1 || c1 == (size_t)-1 ||
        clast == (size_t)-1) {
        printf("  FAIL: inject-block row lookup\n");
        return 1;
    }

#define FOLD_IN(t, p, pub) \
    ((fold_input_t){&g_air, (t), W.rows, (size_t)MMIX_WIDTH, (p), \
                    (size_t)DNAC_P2C_MMIX_TABLE_COLS, (pub), W.npub})

    /* F-N1 (N-order) — THE point of the slice: inject-compress halves swapped,
     * i.e. C(rows_digest, running) instead of C(running, rows_digest). Block F
     * (LEFT == RDIG) and block I (RIGHT == predecessor output) both reject. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, ic1);
        for (size_t j = 0; j < (size_t)MMIX_DIGEST_LANES; j++) {
            const uint64_t tmp = row[mmix_perm_in_off(j)];
            row[mmix_perm_in_off(j)] = row[mmix_perm_in_off(MMIX_DIGEST_LANES + j)];
            row[mmix_perm_in_off(MMIX_DIGEST_LANES + j)] = tmp;
        }
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N1 inject-compress halves swapped", &in, 0);
        free(t);
    }
    /* F-N2 (N-level) — has_inject relocated to the wrong level: block J (RDIG
     * seed, a TRANSITION form) fires at the wrong row. */
    {
        uint64_t *p = clone_prep(&W);
        p[c1 * DNAC_P2C_MMIX_TABLE_COLS + DNAC_P2C_MMIX_COL_HAS_INJECT] = 0;
        p[c0 * DNAC_P2C_MMIX_TABLE_COLS + DNAC_P2C_MMIX_COL_HAS_INJECT] = 1;
        fold_input_t in = FOLD_IN(W.trace, p, W.pub);
        fexpect_reject("F-N2 has_inject relocated to a wrong level", &in, 0);
        free(p);
    }
    /* F-N3 (N-index) — a direction public in an inject group's reduced-index
     * suffix flipped; block D rejects at that level's compress row. */
    {
        uint64_t *p = clone_pub(&W);
        p[MMIX_PUB_DIR_OFF + 2] ^= 1u;
        fold_input_t in = FOLD_IN(W.trace, W.prep, p);
        fexpect_reject("F-N3 suffix dir public flipped", &in, 0);
        free(p);
    }
    /* F-N4 (N-leaf) — tallest-group absorbed DATA lane tampered (block C). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, 0);
        row[mmix_perm_in_off(0)] = bump(row[mmix_perm_in_off(0)]);
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N4 tampered tallest-group data lane", &in, 0);
        free(t);
    }
    /* F-N5 (N-bit2) — a compress `dir` column flipped without its public bit
     * (block D). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, c0);
        row[MMIX_DIR_OFF] ^= 1u;
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N5 dir column != its public bit", &in, 0);
        free(t);
    }
    /* F-N6 (N-root) — wrong public root lane. Isolated: only the final row's
     * block-E pin reads it. */
    {
        uint64_t *p = clone_pub(&W);
        p[MMIX_PUB_ROOT_OFF + 2] = bump(p[MMIX_PUB_ROOT_OFF + 2]);
        fold_input_t in = FOLD_IN(W.trace, W.prep, p);
        fexpect_reject("F-N6 wrong public root lane", &in, 1);
        free(p);
    }
    /* F-N7 (N-salt) — a SALT lane tampered: salt is unbound witness, but the
     * leaf digest diverges, so the placement into the next compress rejects. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, 0);
        row[mmix_perm_in_off(1)] = bump(row[mmix_perm_in_off(1)]);
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N7 tampered salt lane (digest diverges)", &in, 0);
        free(t);
    }
    /* F-N8 (N-rdig) — the RDIG carry broken on the inject-leaf feeding ic1
     * (blocks K / F). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, ic1 - 1);
        row[mmix_rdig_off(0)] = bump(row[mmix_rdig_off(0)]);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N8 broken running-digest carry (RDIG)", &in, 0);
        free(t);
    }
    /* F-N9 (N-left) — inject-compress LEFT input tampered (block F). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, ic1);
        row[mmix_perm_in_off(0)] = bump(row[mmix_perm_in_off(0)]);
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N9 inject-compress LEFT != carried digest", &in, 0);
        free(t);
    }
    /* F-N10 (N-zerostart) — leaf capacity lane non-zero (block C zero fill). */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, 0);
        row[mmix_perm_in_off(MMIX_PERM_WIDTH - 1)] = 1;
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N10 leaf capacity lane nonzero", &in, 0);
        free(t);
    }
    /* F-N11 (N-dirpad) — `dir` set on a leaf row (block B). Isolated. */
    {
        uint64_t *t = clone_trace(&W);
        row_of(t, 0)[MMIX_DIR_OFF] = 1;
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N11 dir set on a leaf row", &in, 1);
        free(t);
    }
    /* F-N12 (N-final) — garbage the last compression's free sibling half while
     * the TRUE root sits in the final row: block H (final threading, a
     * TRANSITION form) rejects. */
    {
        uint64_t *t = clone_trace(&W);
        uint64_t *row = row_of(t, clast);
        row[mmix_perm_in_off(MMIX_DIGEST_LANES)] =
            bump(row[mmix_perm_in_off(MMIX_DIGEST_LANES)]);
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N12 garbaged last compress, true root", &in, 0);
        free(t);
    }
    /* F-N13 (N-perm) — an interior cell of the embedded Poseidon2 block. */
    {
        uint64_t *t = clone_trace(&W);
        const size_t off = MMIX_PERM_OFF + p2air_beg_sbox_off(0, 0);
        uint64_t *row = row_of(t, c0);
        row[off] = bump(row[off]);
        fold_input_t in = FOLD_IN(t, W.prep, W.pub);
        fexpect_reject("F-N13 Poseidon2 block interior tamper", &in, 0);
        free(t);
    }
#undef FOLD_IN

    /* F-N14 (N-thread) — the multi-block tallest group's leaf state carry
     * (block L) broken. Needs the MG config, so it runs on its own fixture. */
    {
        fixt_t *F = (fixt_t *)calloc(1, sizeof(fixt_t));
        built_t X;
        if (F && make_fixt(&CFG_MG, 5, F) &&
            build_trace(&X, &CFG_MG, F, F->sibs, F->root.lanes) &&
            dnac_mmix_air_fold_bind(&CFG_MG, &g_state, &g_air) == 0) {
            uint64_t *row = row_of(X.trace, 1); /* 2nd tallest-leaf row */
            row[mmix_perm_in_off(MMIX_PERM_WIDTH - 1)] =
                bump(row[mmix_perm_in_off(MMIX_PERM_WIDTH - 1)]);
            regen_perm(row);
            fold_input_t in = {&g_air, X.trace,
                               X.rows, (size_t)MMIX_WIDTH,
                               X.prep, (size_t)DNAC_P2C_MMIX_TABLE_COLS,
                               X.pub,  X.npub};
            fexpect_reject("F-N14 multi-block leaf capacity not carried", &in, 0);
            built_free(&X);
        } else {
            printf("  [reject] F-N14 fixture/build                            FAIL\n");
            fails++;
        }
        free(F);
        if (dnac_mmix_air_fold_bind(W.cfg, &g_state, &g_air) != 0) {
            printf("  FAIL: workhorse re-bind after F-N14\n");
            return 1;
        }
    }

    /* ══ PHASE 3 — T-TERM ══
     * The `is_last_row` boundary has no u64 PER-ROW counterpart (it lives in
     * eval_trace, mmcs_mixed_air.c:472-486). */
    printf("------------------------------------------------------------\n");
    printf("Phase 3 — T-TERM (is_last_row boundary)\n");
    printf("------------------------------------------------------------\n");
    /* F-T1 — the last row's `is_pad` cleared and NOTHING else touched. Every
     * other form on that row stays satisfied (all type flags are 0, so every
     * gated form is inert and it has no successor), so EXACTLY the boundary
     * fires: one non-zero residual. */
    {
        uint64_t *p = clone_prep(&W);
        p[(W.rows - 1) * DNAC_P2C_MMIX_TABLE_COLS + DNAC_P2C_MMIX_COL_IS_PAD] = 0;
        fold_input_t in = {&g_air, W.trace,
                           W.rows, (size_t)MMIX_WIDTH,
                           p,      (size_t)DNAC_P2C_MMIX_TABLE_COLS,
                           W.pub,  W.npub};
        fexpect_reject("F-T1 last row not padding (isolated)", &in, 1);
        free(p);
    }
    /* F-T2 — the shipped N-term recipe: the last row retyped as a FINAL row.
     * The boundary fires AND that row's block-E root pin fires (its padding
     * permutation preimage is not the root), so the count is not pinned. */
    {
        uint64_t *p = clone_prep(&W);
        const size_t last = W.rows - 1;
        p[last * DNAC_P2C_MMIX_TABLE_COLS + DNAC_P2C_MMIX_COL_IS_PAD] = 0;
        p[last * DNAC_P2C_MMIX_TABLE_COLS + DNAC_P2C_MMIX_COL_IS_FINAL] = 1;
        fold_input_t in = {&g_air, W.trace,
                           W.rows, (size_t)MMIX_WIDTH,
                           p,      (size_t)DNAC_P2C_MMIX_TABLE_COLS,
                           W.pub,  W.npub};
        fexpect_reject("F-T2 last row retyped as FINAL", &in, 0);
        free(p);
    }

    /* ══ PHASE 4 — N-CTX-TWO (FLEET 034: the wall this slice removed) ══
     * The same statement as tests/test_mmcs_air_fold.c Phase 4, on the SECOND
     * AIR: two DIFFERENT cfgs bound into two SEPARATE caller-owned states, both
     * live at once, each folding its own honest trace to ALL-ZERO with its OWN
     * step count. With the pre-FLEET-034 module static, `bind(CFG_WIDE)` after
     * `bind(CFG_REF)` left ONE cfg armed and the first descriptor evaluated the
     * second cfg's constraint system. */
    printf("------------------------------------------------------------\n");
    printf("Phase 4 — N-CTX-TWO (two cfgs bound simultaneously)\n");
    printf("------------------------------------------------------------\n");
    {
        /* Several KB each — file scope, per the module header's SIZE note. */
        static dnac_mmix_fold_state_t st1, st2;
        const size_t want1 =
            dnac_mmix_air_fold_control_steps(&CFG_REF) + g_p2_steps;
        const size_t want2 =
            dnac_mmix_air_fold_control_steps(&CFG_WIDE) + g_p2_steps;

        built_t B1, B2;
        fixt_t *F = (fixt_t *)calloc(1, sizeof(fixt_t));
        int built = 0;
        memset(&B1, 0, sizeof(B1));
        memset(&B2, 0, sizeof(B2));
        if (F && make_fixt(&CFG_REF, 3, F) &&
            build_trace(&B1, &CFG_REF, F, F->sibs, F->root.lanes) &&
            make_fixt(&CFG_WIDE, 3, F) &&
            build_trace(&B2, &CFG_WIDE, F, F->sibs, F->root.lanes)) {
            built = 1;
        }
        free(F);

        if (!built) {
            printf("  [accept] N-CTX-TWO fixtures                             FAIL\n");
            fails++;
        } else if (want1 == want2 || want1 == g_p2_steps || want2 == g_p2_steps) {
            printf("  [accept] N-CTX-TWO cfgs must differ in step count        FAIL\n");
            fails++;
        } else {
            dnac_stark_air_t air1, air2;
            memset(&st1, 0, sizeof(st1));
            memset(&st2, 0, sizeof(st2));
            memset(&air1, 0, sizeof(air1));
            memset(&air2, 0, sizeof(air2));

            if (dnac_mmix_air_fold_bind(&CFG_REF, &st1, &air1) != 0 ||
                dnac_mmix_air_fold_bind(&CFG_WIDE, &st2, &air2) != 0) {
                printf("  [accept] N-CTX-TWO double bind                          FAIL\n");
                fails++;
            } else if (air1.ctx == air2.ctx || air1.ctx != (const void *)&st1 ||
                       air2.ctx != (const void *)&st2) {
                printf("  [accept] N-CTX-TWO distinct contexts                    FAIL\n");
                fails++;
            } else {
                const fold_input_t in1 = {&air1, B1.trace, B1.rows,
                                          (size_t)MMIX_WIDTH, B1.prep,
                                          (size_t)DNAC_P2C_MMIX_TABLE_COLS,
                                          B1.pub, B1.npub};
                const fold_input_t in2 = {&air2, B2.trace, B2.rows,
                                          (size_t)MMIX_WIDTH, B2.prep,
                                          (size_t)DNAC_P2C_MMIX_TABLE_COLS,
                                          B2.pub, B2.npub};
                fexpect_clean("N-CTX-TWO REF  (WIDE also bound)", &in1, want1);
                fexpect_clean("N-CTX-TWO WIDE (REF also bound)", &in2, want2);
                fexpect_clean("N-CTX-TWO REF again, both still bound", &in1,
                              want1);
                printf("  [info]   REF %zu steps vs WIDE %zu steps — distinct\n",
                       want1, want2);
            }
        }
        built_free(&B1);
        built_free(&B2);
    }

    built_free(&W);

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("s1a MIXED MMCS FOLD: %d FAIL\n", fails);
        return 1;
    }
    printf("s1a MIXED MMCS FOLD: 5 openings T-EQ+T-CNT + 9 bind/ctx gates +\n"
           "  14 T-NEG (N-order included) + 2 T-TERM + 3 N-CTX-TWO — PASS\n");
    return 0;
}
