/**
 * @file test_fri_air_fold.c
 * @brief Composition s1a — equivalence gate for the FRI fold-walk AIR's
 *        FOLD-FORM evaluator (fri_air_fold.{c,h}).
 *
 * ── HOW THIS TEST REUSES THE SHIPPED GATE (and why it does it this way) ─────
 * The honest-trace builder, the deterministic fixtures, the three configs and
 * every tamper recipe already exist, red-teamed, in tests/test_fri_air.c. This
 * file INCLUDES that translation unit (with its `main` renamed out of the way)
 * instead of copying any of it:
 *
 *     #define main <renamed>      // the shipped gate's main, never called
 *     #include "test_fri_air.c"
 *
 * so `build_trace` / `fill_fixture` / `V_HONEST` / `relast*` / `CFG_REC` /
 * `CFG_SMALL` / the bad-cfg set / `eval_built` / `check` are the SAME code, not
 * a fork. That matters for the property under test: a copy could drift, and the
 * whole claim here is that the fold form accepts EXACTLY the traces the u64
 * form accepts. The shipped file is NOT modified (s1a whitelist).
 *
 * ── WHAT IS PROVED ─────────────────────────────────────────────────────────
 *   T-EQ    every honest walk the u64 evaluator accepts (5, three configs) is
 *           accepted by the fold form: ZERO non-zero `received` over the whole
 *           trace.
 *   T-CNT   `capture_len` is identical on every row and equals the count
 *           enumerated block-by-block from the emission list — computed HERE
 *           from cfg scalars, and separately by
 *           `dnac_fair_fold_num_constraints`; the two must agree.
 *   T-NEG   14 tampers, incl. the four MANDATORY FLEET 020 catches (N1 t1
 *           SIGN, N2 free f_init, N3 handoff-as-copy, N4b last fold phase
 *           free): each is rejected by the fold form, and the number of
 *           non-zero `received` values equals the u64 evaluator's violation
 *           COUNT exactly — the strongest form of "same constraint set".
 *   T-TERM  the u64 G4b terminality GATE became an explicit is_last_row
 *           boundary: a table whose last row is not padding is caught by that
 *           boundary and by nothing else (exact-count 1 on the minimal tamper).
 *   T-BIND  a cfg the u64 evaluator fails closed on is refused by
 *           `dnac_fair_fold_bind`, with the descriptor left untouched.
 *   T-RAIL  the shape rail fires (one unsatisfiable constraint) on a window
 *           that does not match the bound cfg.
 *
 * Deterministic fixtures only — NO rand() (root CLAUDE.md).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

/* The shipped u64 gate, reused whole. Its main() is renamed (never called);
 * everything else — builder, fixtures, configs, tamper helpers — is ours. */
#define main dnac_fair_u64_gate_main_unused
#include "test_fri_air.c"
#undef main

#include "../fri_air_fold.h"
#include "fold_test_util_b.h"

/* ══════════════════════ expected constraint count ════════════════════════
 * ENUMERATED here from the emission blocks of fri_air_fold.c — deliberately NOT
 * `FAIR_FOLD_FIXED_STEPS`, so the test and the module are two independent
 * counts (the count-KAFADAN discipline; this project has tripped it five times).
 * The two are compared below.
 *
 *   G4b 3 | C2a 1 | C3a 1 | C4a 1 | C4b 1 | C4c 2 | C4d 2 | C4e 2 | C4f 2
 *   C4i 2 | C5 2 | C3b 1 | C3c 1 | C3d 1 | C4j 2 | C4k 1 | C4l 2
 * plus the cfg-sized loops: C2b (one per scheduled step), C4g (2 per fold row),
 * C4h (2 per roll-in). */
static size_t fair_expect_steps(const dnac_p2c_table_cfg_t *cfg) {
    const size_t fixed = 3 + 1 + 1 + 1 + 1 + 2 + 2 + 2 + 2 + 2 + 2 + 1 + 1 + 1 +
                         2 + 1 + 2;
    const size_t n_chain = cfg->lgmh - 1;
    const size_t R = cfg->lgmh - cfg->log_blowup - cfg->log_final_poly_len;
    return fixed + (n_chain + R) + 2 * R + 2 * cfg->num_rollin;
}

/* ══════════════════════════ the comparison driver ════════════════════════ */

/**
 * Run the fold form over `B`'s trace and require it to agree with the u64
 * evaluator, form for form:
 *   u64 == 0                    -> zero non-zero `received`
 *   0 < u64 < BAD_CONFIG        -> exactly u64 non-zero `received`
 * Also pins the per-row step count (T-CNT). BAD_CONFIG traces are handled by
 * the dedicated T-TERM / T-BIND blocks, never here.
 */
static void fold_vs_u64(const char *name, const built_t *B) {
    const int u = eval_built(B);
    if (u >= FAIR_VIOL_BAD_CONFIG) {
        printf("  [eq]     %-52s u64 fails closed — FAIL\n", name);
        fails++;
        return;
    }

    dnac_stark_air_t air;
    memset(&air, 0, sizeof(air));
    if (dnac_fair_fold_bind(B->cfg, &air) != DNAC_FAIR_FOLD_OK) {
        printf("  [eq]     %-52s bind REJECTED — FAIL\n", name);
        fails++;
        return;
    }

    ftu_result_t R;
    if (!ftu_run_trace(&air, B->trace, B->rows, air.main_width, B->prep,
                       (size_t)DNAC_P2C_TABLE_COLS, B->pub, B->num_pub, &R)) {
        printf("  [eq]     %-52s harness refused the shape — FAIL\n", name);
        fails++;
        return;
    }

    const size_t want_steps = fair_expect_steps(B->cfg);
    int ok = 1;
    if (R.ragged || R.truncated) {
        printf("  [eq]     %-52s ragged/truncated capture — FAIL\n", name);
        ok = 0;
    }
    if (R.steps != want_steps) {
        printf("  [eq]     %-52s %zu steps/row (want %zu) — FAIL\n", name,
               R.steps, want_steps);
        ok = 0;
    }
    if (R.nonzero != (size_t)u) {
        printf("  [eq]     %-52s fold %zu != u64 %d — FAIL\n", name, R.nonzero,
               u);
        ok = 0;
    }
    if (ok) {
        printf("  [eq]     %-52s u64 %2d == fold %2zu  (%zu steps/row) — OK\n",
               name, u, R.nonzero, R.steps);
    } else {
        fails++;
    }
}

/** T-EQ/T-CNT on an honest walk built by the SHIPPED builder. */
static void fold_accept(const dnac_p2c_table_cfg_t *cfg, uint64_t index,
                        uint64_t seed, const char *label) {
    fixture_t F;
    built_t   B;
    fill_fixture(&F, seed);
    if (!build_trace(&B, cfg, index, &F, &V_HONEST)) {
        printf("  [eq]     %-52s honest build FAILED\n", label);
        fails++;
        return;
    }
    fold_vs_u64(label, &B);
    built_free(&B);
}

/* ════════════════════════════════ main ═══════════════════════════════════ */

int main(void) {
    const dnac_p2c_table_cfg_t *REF = dnac_p2c_ref_cfg();

    printf("============================================================\n");
    printf("s1a — FRI fold-walk AIR, FOLD form (fri_air_fold.{c,h})\n");
    printf("============================================================\n");

    /* ── T-BIND: descriptor + the cfg gates ───────────────────────────────── */
    printf("-- T-BIND: descriptor + cfg fail-close ----------------------\n");
    {
        dnac_stark_air_t air;
        memset(&air, 0, sizeof(air));
        check("bind(REF) accepted",
              dnac_fair_fold_bind(REF, &air) == DNAC_FAIR_FOLD_OK);
        check("descriptor main_width == FAIR_NUM_COLS (21)",
              air.main_width == FAIR_NUM_COLS);
        check("descriptor num_public_values == dnac_fair_num_publics(REF)",
              air.num_public_values == dnac_fair_num_publics(REF));
        check("descriptor main_next == 1 (the AIR reads the next row)",
              air.main_next == 1);
        check("descriptor air_eval bound", air.air_eval != NULL);
        check("num_constraints(REF) == enumerated count",
              dnac_fair_fold_num_constraints(REF) == fair_expect_steps(REF));
        check("num_constraints(REC) == enumerated count",
              dnac_fair_fold_num_constraints(&CFG_REC) ==
                  fair_expect_steps(&CFG_REC));
        check("num_constraints(SMALL) == enumerated count",
              dnac_fair_fold_num_constraints(&CFG_SMALL) ==
                  fair_expect_steps(&CFG_SMALL));

        /* The SAME bad cfgs the shipped gate fails closed on (its G0..G7 +
         * D2 + roll-in order block). bind must refuse each, and must leave the
         * descriptor untouched — a half-written descriptor is a live AIR. */
        const dnac_p2c_table_cfg_t *bad[7] = {&CFG_G1,  &CFG_G2, &CFG_G3, &CFG_G7A,
                                              &CFG_G7B, &CFG_Q0, &CFG_RI};
        const char *bname[7] = {"G1 arity",  "G2 lfpl",    "G3 lgmh>32",
                                "G7a R<1",   "G7b lgmh<2", "D2 queries==0",
                                "roll-in order"};
        for (int i = 0; i < 7; i++) {
            dnac_stark_air_t probe;
            memset(&probe, 0, sizeof(probe));
            const int rc = dnac_fair_fold_bind(bad[i], &probe);
            char msg[96];
            snprintf(msg, sizeof(msg), "bind rejects %s (descriptor untouched)",
                     bname[i]);
            check(msg, rc != DNAC_FAIR_FOLD_OK && probe.air_eval == NULL &&
                           probe.main_width == 0);
        }
        {
            dnac_stark_air_t probe;
            memset(&probe, 0, sizeof(probe));
            check("bind rejects NULL cfg",
                  dnac_fair_fold_bind(NULL, &probe) != DNAC_FAIR_FOLD_OK);
            check("bind rejects NULL out_air",
                  dnac_fair_fold_bind(REF, NULL) != DNAC_FAIR_FOLD_OK);
        }
        /* Re-bind REF: the bad probes above must not have left state behind. */
        check("re-bind(REF) accepted",
              dnac_fair_fold_bind(REF, &air) == DNAC_FAIR_FOLD_OK);
    }

    /* ── T-EQ + T-CNT: the five honest walks of the shipped gate ──────────── */
    printf("\n-- T-EQ / T-CNT: honest walks (u64 == fold == 0) ------------\n");
    fold_accept(REF, 0, 1, "REF idx 0 (all bits 0)");
    fold_accept(REF, 8191, 2, "REF idx 8191 (all ones)");
    fold_accept(&CFG_REC, UINT64_C(0x5A5A5), 4, "RECURSION lgmh 19");
    fold_accept(&CFG_SMALL, 11, 5, "SMALL lgmh 4 (hand-checked)");
    fold_accept(REF, 4660, 1, "REF idx 4660 (non-palindromic)");

    /* Primary fixture for the publics tampers + T-TERM + T-RAIL. */
    built_t W;
    {
        fixture_t F;
        fill_fixture(&F, 1);
        if (!build_trace(&W, REF, 4660, &F, &V_HONEST)) {
            printf("primary fixture unusable — aborting\n");
            return 1;
        }
    }

    /* ── T-NEG: the four MANDATORY FLEET 020 catches ──────────────────────── */
    printf("\n-- T-NEG: the four MANDATORY FLEET 020 catches --------------\n");

    /* N1 — t1 SIGN (A2-F1). Built with the REFLECTED factor (2b-1) at fold row
     * R-1 with beta = 0 there; t2/f'/final are rebuilt consistently, so only
     * C4c's two lanes can fire. */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        F.beta[10] = gold_fp2_zero();
        V.t1_sign_flip_row = 10;
        if (build_trace(&B, REF, 4660, &F, &V)) {
            fold_vs_u64("N1 t1 SIGN flipped (reflected challenge)", &B);
            built_free(&B);
        } else {
            check("N1 build", 0);
        }
    }
    /* N2 — FREE f_init (A2-F2): the walk starts off f_init and propagates
     * honestly; only the is_handoff f_init boundary can fire. */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        V.free_finit = 1;
        if (build_trace(&B, REF, 4660, &F, &V)) {
            fold_vs_u64("N2 walk starts off f_init, end republished", &B);
            built_free(&B);
        } else {
            check("N2 build", 0);
        }
    }
    /* N3 — HANDOFF-AS-COPY (A2-F4): chain row 0 sets g := 1, chain rebuilt.
     * Only C3a can fire — and C3a is the form wired to folder->is_first_row,
     * so this negative is ALSO the OBL-P2c-3 wiring proof. */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        V.no_row0_mul = 1;
        if (build_trace(&B, REF, 4660, &F, &V)) {
            fold_vs_u64("N3 row-0 multiply dropped (is_first_row anchor)", &B);
            built_free(&B);
        } else {
            check("N3 build", 0);
        }
    }
    /* N4b — LAST FOLD PHASE FREE (A2-F3): phase R-1's output moved with
     * final_poly[0], so C5 still holds; only C4l's is_fold-LOCAL gating catches
     * it. */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t        *tr = row_of(&B, B.sched);
            const gold_fp2_t nf = gold_fp2_add(
                rd2(tr, FAIR_COL_F), gold_fp2_new(gold_fp_one(), gold_fp_one()));
            wr2(tr, FAIR_COL_F, nf);
            B.pub[B.pub_final] = gold_fp_to_u64(nf.a);
            B.pub[B.pub_final + 1] = gold_fp_to_u64(nf.b);
            fold_vs_u64("N4b last phase output free, terminal consistent", &B);
            built_free(&B);
        } else {
            check("N4b build", 0);
        }
    }

    printf("\n-- T-NEG: constraint-form + publics tampers -----------------\n");

    /* N5 — x0 recurrence sign flipped (C4k, R-1 foldpairs). */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        V.x0_sign_flip = 1;
        if (build_trace(&B, REF, 4660, &F, &V)) {
            fold_vs_u64("N5 x0 recurrence sign flipped (C4k)", &B);
            built_free(&B);
        } else {
            check("N5 build", 0);
        }
    }
    /* N6 — non-boolean b on the last fold row (C2a + C2b + predecessor C4k). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t        *fr = row_of(&B, B.sched - 1);
            const gold_fp2_t f = rd2(fr, FAIR_COL_F);
            const gold_fp2_t s = rd2(fr, FAIR_COL_S);
            fr[FAIR_COL_B] = 2;
            wr2(fr, FAIR_COL_T1,
                scale2(gold_fp_sub(gold_fp_one(), fp(4)), gold_fp2_sub(s, f)));
            relast_t2(&B);
            relast(&B);
            fold_vs_u64("N6 non-boolean b on a fold row (C2a + C2b + C4k)", &B);
            built_free(&B);
        } else {
            check("N6 build", 0);
        }
    }
    /* N7 — non-boolean b on the last chain row (C2a + C2b + predecessor C3b). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            row_of(&B, B.n_chain - 1)[FAIR_COL_B] = 2;
            fold_vs_u64("N7 non-boolean b on the last chain row", &B);
            built_free(&B);
        } else {
            check("N7 build", 0);
        }
    }
    /* N11 — inv tampered, f'/final rebuilt: the C4a div form only. */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *fr = row_of(&B, B.sched - 1);
            fr[FAIR_COL_INV] = bump(fr[FAIR_COL_INV]);
            relast(&B);
            fold_vs_u64("N11 inv tampered (C4a div form)", &B);
            built_free(&B);
        } else {
            check("N11 build", 0);
        }
    }
    /* N13 — gb tampered on chain row 1 (C3b + C3c: both TRANSITION forms, so
     * this is also the is_transition-factor sanity check). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            row_of(&B, 1)[FAIR_COL_GB] = bump(row_of(&B, 1)[FAIR_COL_GB]);
            fold_vs_u64("N13 gb tampered on chain row 1 (C3b + C3c)", &B);
            built_free(&B);
        } else {
            check("N13 build", 0);
        }
    }
    /* N20 — ro != 0 on a non-roll-in fold row (C4i / divergence D1). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            row_of(&B, B.sched - 1)[FAIR_COL_RO] = 1;
            relast_rterm(&B);
            relast(&B);
            fold_vs_u64("N20 ro != 0 on a non-roll-in row (C4i)", &B);
            built_free(&B);
        } else {
            check("N20 build", 0);
        }
    }
    /* N22 — the handoff copy broken, walk rebuilt (C3d, a transition form). */
    {
        fixture_t F;
        built_t   B;
        variant_t V = V_HONEST;
        fill_fixture(&F, 1);
        V.x0_bump = 1;
        if (build_trace(&B, REF, 4660, &F, &V)) {
            fold_vs_u64("N22 handoff copy broken, walk rebuilt (C3d)", &B);
            built_free(&B);
        } else {
            check("N22 build", 0);
        }
    }
    /* N24 — the terminal row's f moved in one lane (C4l + C5). */
    {
        fixture_t F;
        built_t   B;
        fill_fixture(&F, 1);
        if (build_trace(&B, REF, 4660, &F, &V_HONEST)) {
            uint64_t *tr = row_of(&B, B.sched);
            tr[FAIR_COL_F] = bump(tr[FAIR_COL_F]);
            fold_vs_u64("N24 terminal row f moved (C4l + C5)", &B);
            built_free(&B);
        } else {
            check("N24 build", 0);
        }
    }
    /* N8/N9/N10 — the bit publics: chain-only, fold-only, and the OVERLAP bit
     * that is read TWICE (the dual read is what forces chain and walk onto one
     * index). */
    {
        const uint64_t s12 = W.pub[12], s0 = W.pub[0], s5 = W.pub[5];
        W.pub[12] ^= 1u;
        fold_vs_u64("N8 chain-ONLY bit public flipped (bit 12)", &W);
        W.pub[12] = s12;
        W.pub[0] ^= 1u;
        fold_vs_u64("N9 fold-ONLY bit public flipped (bit 0)", &W);
        W.pub[0] = s0;
        W.pub[5] ^= 1u;
        fold_vs_u64("N10 OVERLAP bit public flipped (bit 5, dual read)", &W);
        W.pub[5] = s5;
    }
    /* N18/N19/N25 — beta / roll-in / final_poly publics. */
    {
        const uint64_t sb = W.pub[W.pub_beta + 8];
        W.pub[W.pub_beta + 8] = bump(sb);
        fold_vs_u64("N18 beta public lane moved (C4g)", &W);
        W.pub[W.pub_beta + 8] = sb;

        const uint64_t sr = W.pub[W.pub_ro];
        W.pub[W.pub_ro] = bump(sr);
        fold_vs_u64("N19 roll-in public slot moved (C4h)", &W);
        W.pub[W.pub_ro] = sr;

        const uint64_t sf = W.pub[W.pub_final];
        W.pub[W.pub_final] = bump(sf);
        fold_vs_u64("N25 final_poly[0] public moved (C5)", &W);
        W.pub[W.pub_final] = sf;
    }
    fold_vs_u64("publics restored -> honest again", &W);

    /* ── T-TERM: the u64 G4b gate is now an is_last_row BOUNDARY ──────────── */
    printf("\n-- T-TERM: terminality is a live constraint, not a gate -----\n");
    {
        dnac_stark_air_t air;
        memset(&air, 0, sizeof(air));
        check("bind(REF) for T-TERM",
              dnac_fair_fold_bind(W.cfg, &air) == DNAC_FAIR_FOLD_OK);

        uint64_t      *last = W.prep + (W.rows - 1) * (size_t)DNAC_P2C_TABLE_COLS;
        const uint64_t sp = last[DNAC_P2C_COL_IS_PAD];
        const uint64_t sf = last[DNAC_P2C_COL_IS_FOLD];

        /* (a) MINIMAL tamper: is_pad cleared and nothing else. No other form
         * reads is_pad, so EXACTLY ONE constraint may fire — that is what
         * proves the new open form exists and is isolated. The u64 side reports
         * this as a fail-close instead of a count. */
        last[DNAC_P2C_COL_IS_PAD] = 0;
        {
            ftu_result_t R;
            check("u64 fails closed on a non-padding last row",
                  eval_built(&W) == FAIR_VIOL_BAD_CONFIG);
            check("fold run (a)",
                  ftu_run_trace(&air, W.trace, W.rows, air.main_width, W.prep,
                                (size_t)DNAC_P2C_TABLE_COLS, W.pub, W.num_pub,
                                &R) == 1);
            check("T-TERM(a) exactly 1 non-zero (is_pad boundary alone)",
                  R.nonzero == 1);
            check("T-TERM(a) it is on the LAST row, in the terminality block",
                  R.first_row == W.rows - 1 && R.first_step < 3);
        }
        /* (b) the shipped gate's tamper: last row retyped as a fold row. The
         * terminality block fires first; the fold-gated row-local forms fire
         * too (the padding row is all-zero, so e.g. C4a's -1/2 residual). */
        last[DNAC_P2C_COL_IS_FOLD] = 1;
        {
            ftu_result_t R;
            check("fold run (b)",
                  ftu_run_trace(&air, W.trace, W.rows, air.main_width, W.prep,
                                (size_t)DNAC_P2C_TABLE_COLS, W.pub, W.num_pub,
                                &R) == 1);
            check("T-TERM(b) caught, first non-zero in the last row's "
                  "terminality block",
                  R.nonzero >= 2 && R.first_row == W.rows - 1 &&
                      R.first_step < 3);
        }
        last[DNAC_P2C_COL_IS_PAD] = sp;
        last[DNAC_P2C_COL_IS_FOLD] = sf;
        fold_vs_u64("prep restored -> honest again", &W);
    }

    /* ── T-RAIL: the shape rail is live and fail-closes ───────────────────── */
    printf("\n-- T-RAIL: out-of-contract window -> unsatisfiable ----------\n");
    {
        dnac_stark_air_t air;
        memset(&air, 0, sizeof(air));
        check("bind(REF) for T-RAIL",
              dnac_fair_fold_bind(W.cfg, &air) == DNAC_FAIR_FOLD_OK);
        ftu_result_t R;
        /* main_width one short of the bound width: the rail must fire on every
         * row, emitting exactly one (unsatisfiable) constraint each. */
        check("fold run with a short main_width",
              ftu_run_trace(&air, W.trace, W.rows, air.main_width - 1, W.prep,
                            (size_t)DNAC_P2C_TABLE_COLS, W.pub, W.num_pub,
                            &R) == 1);
        check("T-RAIL 1 step/row and every one non-zero",
              R.steps == 1 && R.nonzero == W.rows);
    }

    /* ── T-DISARM: a REJECTED bind disarms the previous binding ─────────────
     * FLEET 027 verifier-B H1: bind used to return before touching g_fair, so
     * after a rejected re-bind the module kept evaluating the OLD cfg's
     * constraint system. The fix clears `bound` on ENTRY; this block pins it:
     * honest trace + valid descriptor, but post-reject the rail must fire. */
    printf("\n-- T-DISARM: rejected bind disarms previous binding ---------\n");
    {
        dnac_stark_air_t air;
        memset(&air, 0, sizeof(air));
        check("bind(REF) for T-DISARM",
              dnac_fair_fold_bind(W.cfg, &air) == DNAC_FAIR_FOLD_OK);
        check("re-bind(G1 arity) rejected",
              dnac_fair_fold_bind(&CFG_G1, &air) != DNAC_FAIR_FOLD_OK);
        ftu_result_t R;
        check("fold run on the HONEST trace after the rejected bind",
              ftu_run_trace(&air, W.trace, W.rows, air.main_width, W.prep,
                            (size_t)DNAC_P2C_TABLE_COLS, W.pub, W.num_pub,
                            &R) == 1);
        check("T-DISARM rail fires (1 step/row, every one non-zero)",
              R.steps == 1 && R.nonzero == W.rows);
        check("re-bind(REF) re-arms",
              dnac_fair_fold_bind(W.cfg, &air) == DNAC_FAIR_FOLD_OK);
    }

    built_free(&W);

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("s1a FRI fold-walk FOLD form: %d FAIL\n", fails);
        return 1;
    }
    /* Roster, audited by ENUMERATION (count-KAFADAN discipline):
     *   T-EQ/T-CNT  5 honest walks over 3 configs (REF@0, REF@8191, RECURSION,
     *               SMALL, REF@4660), each pinning steps/row twice (test-side
     *               enumeration + dnac_fair_fold_num_constraints)
     *   T-NEG      14 tampers, each with the u64 violation COUNT matched
     *               exactly: N1 N2 N3 N4b (the MANDATORY FLEET 020 four),
     *               N5 N6 N7 N11 N13 N20 N22 N24 (forms), N8 N9 N10 N18 N19
     *               N25 (publics) — 4 + 8 + 6 = 18 comparison runs including
     *               the two "restored -> honest" re-checks
     *   T-TERM      2 (minimal is_pad tamper, exact count 1; retyped last row)
     *   T-BIND     18 (1 bind + 4 descriptor + 3 count + 7 bad cfgs + 2 NULL
     *               + re-bind — the earlier "13" was itself a count-KAFADAN,
     *               caught by FLEET 027 verifier-B M1)
     *   T-RAIL      2
     *   T-DISARM    5 (verifier-B H1 closure) */
    printf("s1a FRI fold-walk FOLD form: 5 honest walks (u64 == fold == 0) +\n"
           "  14 tampers with EXACT u64-count agreement (incl. the four\n"
           "  MANDATORY FLEET 020 catches) + 2 terminality-boundary checks +\n"
           "  18 bind/descriptor gates + 2 shape-rail + 5 disarm checks — PASS\n");
    return 0;
}
