/**
 * @file test_fri_oi_air_fold.c
 * @brief Composition s1a — equivalence gate for the FRI reduced-opening
 *        accumulation AIR's FOLD-FORM evaluator (fri_oi_air_fold.{c,h}).
 *
 * ── HOW THIS TEST REUSES THE SHIPPED GATE ──────────────────────────────────
 * Same mechanism as tests/test_fri_air_fold.c: this file INCLUDES the shipped
 * u64 gate's translation unit (tests/test_fri_oi_air.c, `main` renamed out of
 * the way) so `build_honest`, the deterministic fixtures, the three configs
 * (REF / WIDE / MB), the landmark finders and `eval_b` are the SAME code, not a
 * fork. The shipped file is NOT modified (s1a whitelist). Only the TAMPER
 * recipes — a few lines of cell surgery each, inline in the shipped main() and
 * therefore not callable — are restated here, each naming the shipped negative
 * it reproduces.
 *
 * ── WHAT IS PROVED ─────────────────────────────────────────────────────────
 *   T-EQ    the five honest walks the u64 evaluator accepts are accepted by the
 *           fold form with ZERO non-zero `received` over the whole trace.
 *   T-CNT   `capture_len` is identical on every row and equals the count
 *           enumerated block-by-block HERE from cfg scalars, and separately by
 *           `dnac_foi_fold_num_constraints`.
 *   T-NEG   13 tampers, incl. the two A2 closures the u64 slice was built
 *           around — N-F1 (C3f ONE-SIDED carry) and N-F2 (C2e UNGATED register
 *           HOLD) — each rejected by the fold form with the number of non-zero
 *           `received` values EQUAL to the u64 violation count.
 *   T-TERM  the u64 terminality GATE became an explicit is_last_row boundary:
 *           a last row that is not padding is caught by that boundary alone
 *           (exact count 1 on the minimal tamper).
 *   T-BIND  a cfg the u64 evaluator fails closed on is refused by
 *           `dnac_foi_fold_bind`, descriptor untouched.
 *   T-RAIL  the shape rail fires on a window that does not match the bound cfg.
 *
 * Deterministic fixtures only — NO rand() (root CLAUDE.md).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

/* The shipped u64 gate, reused whole. Its main() is renamed (never called). */
#define main dnac_foi_u64_gate_main_unused
#include "test_fri_oi_air.c"
#undef main

#include "../fri_oi_air_fold.h"
#include "fold_test_util_b.h"

/* ══════════════════════ expected constraint count ════════════════════════
 * ENUMERATED here from the emission blocks of fri_oi_air_fold.c — deliberately
 * NOT `FOI_FOLD_FIXED_STEPS`, so the test and the module are two independent
 * counts (count-KAFADAN discipline). The two are compared below.
 *
 *   row-local:   terminality 5 | C1a 1 | C1c-b 1 | C2a 1 | C3a 4 | C3d 2 |
 *                C3e 2 | C4b 2
 *   transition:  C1b 2 | C2b 2 | C2d 1 | C3f 4
 * plus the cfg-sized loops: 5 per height (C2c 1 + C3b 1 + C4a 2 + C2e 1),
 * one per chain step (C1c-p, and there are lgmh of them), 5 per acc row
 * (C3c's 4 lanes + C3g's 1, the s2 p_x binding) and 2 per lb per-batch
 * boundary (C5). */
static size_t foi_expect_steps(const dnac_p2c_oi_table_cfg_t *cfg) {
    const size_t fixed = (5 + 1 + 1 + 1 + 4 + 2 + 2 + 2) + (2 + 2 + 1 + 4);
    size_t total_acc = 0;
    for (size_t i = 0; i < cfg->num_heights; i++) {
        const dnac_p2c_oi_height_desc_t *d = &cfg->heights[i];
        total_acc +=
            d->num_batches * d->num_matrices * d->num_points * d->num_columns;
    }
    /* lb group: a boundary at every batch start except the first, i.e.
     * num_batches - 1 of them. The lb group is the LAST one when it exists at
     * all — heights are strictly descending — but a height AT lb is OPTIONAL
     * (FLEET 029: a real inner proof has none), and then there is no lb group
     * and no C5 step. */
    size_t lb_boundaries = 0;
    for (size_t i = 0; i < cfg->num_heights; i++) {
        if (cfg->heights[i].log_height == cfg->log_blowup) {
            lb_boundaries = cfg->heights[i].num_batches - 1;
        }
    }
    /* 4 lanes of C3c + 1 of C3g, per acc row. */
    return fixed + 5 * cfg->num_heights + cfg->lgmh + 5 * total_acc +
           2 * lb_boundaries;
}

/* ══════════════════════════ the comparison driver ════════════════════════ */

/**
 * Run the fold form over `B`'s trace and require it to agree with the u64
 * evaluator, form for form (see test_fri_air_fold.c for the rationale).
 */
static void fold_vs_u64(const char *name, const built_t *B) {
    const int u = eval_b(B);
    if (u >= FOI_VIOL_BAD_CONFIG) {
        printf("  [eq]     %-50s u64 fails closed — FAIL\n", name);
        fails++;
        return;
    }

    dnac_stark_air_t air;
    memset(&air, 0, sizeof(air));
    if (dnac_foi_fold_bind(B->cfg, &air) != DNAC_FOI_FOLD_OK) {
        printf("  [eq]     %-50s bind REJECTED — FAIL\n", name);
        fails++;
        return;
    }

    ftu_result_t R;
    if (!ftu_run_trace(&air, B->trace, B->rows, air.main_width, B->prep,
                       (size_t)DNAC_P2C_OI_TABLE_COLS, B->pub, B->num_pub, &R)) {
        printf("  [eq]     %-50s harness refused the shape — FAIL\n", name);
        fails++;
        return;
    }

    const size_t want_steps = foi_expect_steps(B->cfg);
    int ok = 1;
    if (R.ragged || R.truncated) {
        printf("  [eq]     %-50s ragged/truncated capture — FAIL\n", name);
        ok = 0;
    }
    if (R.steps != want_steps) {
        printf("  [eq]     %-50s %zu steps/row (want %zu) — FAIL\n", name,
               R.steps, want_steps);
        ok = 0;
    }
    if (R.nonzero != (size_t)u) {
        printf("  [eq]     %-50s fold %zu != u64 %d — FAIL\n", name, R.nonzero,
               u);
        ok = 0;
    }
    if (ok) {
        printf("  [eq]     %-50s u64 %2d == fold %2zu  (%zu steps/row) — OK\n",
               name, u, R.nonzero, R.steps);
    } else {
        fails++;
    }
}

/** T-EQ/T-CNT on an honest walk built by the SHIPPED builder. */
static void fold_accept(const dnac_p2c_oi_table_cfg_t *cfg, uint64_t index,
                        uint64_t seed, const char *label) {
    built_t B;
    if (!build_honest(&B, cfg, index, seed)) {
        printf("  [eq]     %-50s honest build FAILED\n", label);
        fails++;
        return;
    }
    fold_vs_u64(label, &B);
    built_free(&B);
}

/* ════════════════════════════════ main ═══════════════════════════════════ */

int main(void) {
    const dnac_p2c_oi_table_cfg_t *REF = dnac_p2c_oi_ref_cfg();

    printf("============================================================\n");
    printf("s1a — FRI open_input AIR, FOLD form (fri_oi_air_fold.{c,h})\n");
    printf("============================================================\n");

    /* ── T-BIND: descriptor + the cfg gates ───────────────────────────────── */
    printf("-- T-BIND: descriptor + cfg fail-close ----------------------\n");
    {
        dnac_stark_air_t air;
        memset(&air, 0, sizeof(air));
        check("bind(REF) accepted",
              dnac_foi_fold_bind(REF, &air) == DNAC_FOI_FOLD_OK);
        check("descriptor main_width == dnac_foi_num_cols(REF)",
              air.main_width == dnac_foi_num_cols(REF));
        check("descriptor num_public_values == dnac_foi_num_publics(REF)",
              air.num_public_values == dnac_foi_num_publics(REF));
        check("descriptor main_next == 1 (the AIR reads the next row)",
              air.main_next == 1);
        check("descriptor air_eval bound", air.air_eval != NULL);
        check("num_constraints(REF) == enumerated count",
              dnac_foi_fold_num_constraints(REF) == foi_expect_steps(REF));
        check("num_constraints(WIDE) == enumerated count",
              dnac_foi_fold_num_constraints(&CFG_WIDE) ==
                  foi_expect_steps(&CFG_WIDE));
        check("num_constraints(MB) == enumerated count",
              dnac_foi_fold_num_constraints(&CFG_MB) ==
                  foi_expect_steps(&CFG_MB));
        /* FLEET 029 — the lb-LESS cfgs: the enumerated count carries ZERO C5
         * steps, so agreement here pins n_lb_zero == 0 in the fold derivation
         * (NOLB_MB's last group HAS a per-batch boundary; only its NOT being
         * the lb group keeps C5 out). */
        check("num_constraints(NOLB) == enumerated count (no C5 steps)",
              dnac_foi_fold_num_constraints(&CFG_NOLB) ==
                  foi_expect_steps(&CFG_NOLB));
        check("num_constraints(NOLB_MB) == enumerated count (no C5 steps)",
              dnac_foi_fold_num_constraints(&CFG_NOLB_MB) ==
                  foi_expect_steps(&CFG_NOLB_MB));

        /* The SAME bad cfgs the shipped gate fails closed on. */
        const dnac_p2c_oi_table_cfg_t *bad[3] = {&CFG_LGMH33, &CFG_Q0, &CFG_F7};
        const char *bname[3] = {"lgmh > 32 (two-adicity)", "num_queries == 0",
                                "h_max != lgmh"};
        for (int i = 0; i < 3; i++) {
            dnac_stark_air_t probe;
            memset(&probe, 0, sizeof(probe));
            const int rc = dnac_foi_fold_bind(bad[i], &probe);
            char msg[96];
            snprintf(msg, sizeof(msg), "bind rejects %s (descriptor untouched)",
                     bname[i]);
            check(msg, rc != DNAC_FOI_FOLD_OK && probe.air_eval == NULL &&
                           probe.main_width == 0);
        }
        {
            dnac_stark_air_t probe;
            memset(&probe, 0, sizeof(probe));
            check("bind rejects NULL cfg",
                  dnac_foi_fold_bind(NULL, &probe) != DNAC_FOI_FOLD_OK);
            check("bind rejects NULL out_air",
                  dnac_foi_fold_bind(REF, NULL) != DNAC_FOI_FOLD_OK);
        }
        check("re-bind(REF) accepted",
              dnac_foi_fold_bind(REF, &air) == DNAC_FOI_FOLD_OK);
    }

    /* ── T-EQ + T-CNT: the five honest walks of the shipped gate ──────────── */
    printf("\n-- T-EQ / T-CNT: honest walks (u64 == fold == 0) ------------\n");
    fold_accept(REF, 0, 1, "REF idx 0");
    fold_accept(REF, 11, 2, "REF idx 11 (hand-set)");
    fold_accept(REF, 13, 3, "REF idx 13 (non-palindromic)");
    fold_accept(&CFG_WIDE, UINT64_C(0x2D), 4, "WIDE lgmh 6 idx 45");
    fold_accept(&CFG_MB, 6, 5, "MB lgmh 4 (2-batch lb)");
    fold_accept(&CFG_NOLB, 21, 6, "NOLB lgmh 5 H={5,4} (no lb group)");
    fold_accept(&CFG_NOLB_MB, 21, 7, "NOLB_MB (no lb, 2-batch last group)");

    /* Primary REF fixture + the row landmarks the tampers address. */
    built_t W;
    if (!build_honest(&W, REF, 13, 2)) {
        printf("primary fixture unusable — aborting\n");
        return 1;
    }
    const long r_acc_h4 = acc_row_for_height(&W, 0, 0);   /* group0 acc      */
    const long r_clo_h4 = closeout_row_for_height(&W, 0); /* group0 closeout */
    const long r_acc_h2 = acc_row_for_height(&W, 1, 0);   /* lb group acc    */
    const long r_seed_h4 = first_seed_row(&W, 0);         /* cum0 seed       */
    const long r_sq_h2 = first_sq_row(&W, 1);             /* h2 squaring     */
    check("landmarks resolved",
          r_acc_h4 >= 0 && r_clo_h4 >= 0 && r_acc_h2 >= 0 && r_seed_h4 >= 0 &&
              r_sq_h2 >= 0);

    /* ── T-NEG: the two A2 closures this AIR was built around ─────────────── */
    printf("\n-- T-NEG: the A2 closures (one-sided carry, ungated HOLD) ---\n");

    /* N-F1 — C3f ONE-SIDED carry. A non-final closeout's ro is forged and the
     * exported public is moved with it so C4a stays satisfied; the carry
     * (gated on the CURRENT acc row) forces the closeout ro to BE the
     * accumulation, so C3f-ro fires — and it fires here through the
     * is_transition-wrapped form, which is the point of this test. */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            uint64_t *cr = row_of(&B, (size_t)r_clo_h4);
            cr[FOI_COL_RO] = bump(cr[FOI_COL_RO]);
            B.pub[B.pub_ro] = bump(B.pub[B.pub_ro]);
            fold_vs_u64("N-F1 non-final closeout ro forged (C3f one-sided)", &B);
            built_free(&B);
        } else {
            check("N-F1 build", 0);
        }
    }
    /* N-F2 — C2e UNGATED register HOLD. x_reg[0] is changed on a chain row
     * mid-span with the store row honest; only the ungated hold catches it. */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            uint64_t *r0 = row_of(&B, 0);
            r0[dnac_foi_col_xreg(0)] = bump(r0[dnac_foi_col_xreg(0)]);
            fold_vs_u64("N-F2 x_reg moved mid-span, store honest (C2e HOLD)",
                        &B);
            built_free(&B);
        } else {
            check("N-F2 build", 0);
        }
    }
    /* N-F3 — C2a capture SEED free (+ the store copy that reads it). */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            uint64_t *sr = row_of(&B, (size_t)r_seed_h4);
            sr[FOI_COL_Y] = bump(sr[FOI_COL_Y]);
            fold_vs_u64("N-F3 capture seed y != prefix g (C2a + store copy)",
                        &B);
            built_free(&B);
        } else {
            check("N-F3 build", 0);
        }
    }
    /* N-F4 — C5 per-batch lb-zero. Multi-batch lb cfg: batch 0 contributes
     * +delta and batch 1 -delta, so ro is delta AFTER batch 0 and 0 at the end;
     * every other form stays satisfied and only C5's incoming-ro-zero fires.
     * (Recipe restated from the shipped gate's N-F4 block.) */
    {
        built_t B;
        if (build_honest(&B, &CFG_MB, 6, 5)) {
            const long r0 = acc_row_for_height(&B, 1, 0); /* lb a=0 (gs)     */
            const long r1 = acc_row_for_height(&B, 1, 1); /* lb a=1 (bnd)    */
            check("N-F4 lb group has 2 acc rows", r0 >= 0 && r1 >= 0);
            const gold_fp2_t delta = gold_fp2_new(fp(3), fp(5));
            {
                uint64_t        *rr = row_of(&B, (size_t)r0);
                const size_t     a = B.a_of_row[(size_t)r0];
                const gold_fp2_t zoff = zoff_of(a);
                const gold_fp_t  px = px_of(a);
                const gold_fp2_t pz =
                    gold_fp2_add(emb(px), gold_fp2_mul(delta, zoff));
                const gold_fp2_t t = gold_fp2_sub(pz, emb(px)); /* ap = 1     */
                wr2(rr, FOI_COL_PZ, pz);
                wr2(rr, FOI_COL_T, t);
                B.pub[B.pub_zpz + 4 * a + 2] = u(pz.a);
                B.pub[B.pub_zpz + 4 * a + 3] = u(pz.b);
                wr2(row_of(&B, (size_t)r1), FOI_COL_RO, delta);
            }
            {
                uint64_t        *rr = row_of(&B, (size_t)r1);
                const size_t     a = B.a_of_row[(size_t)r1];
                const gold_fp2_t zoff = zoff_of(a);
                const gold_fp_t  px = px_of(a);
                const gold_fp2_t neg = gold_fp2_neg(delta);
                const gold_fp2_t coeff =
                    gold_fp2_mul(gold_fp2_mul(neg, gold_fp2_inv(B.alpha)), zoff);
                const gold_fp2_t pz = gold_fp2_add(emb(px), coeff);
                const gold_fp2_t t =
                    gold_fp2_mul(B.alpha, gold_fp2_sub(pz, emb(px)));
                wr2(rr, FOI_COL_PZ, pz);
                wr2(rr, FOI_COL_T, t);
                B.pub[B.pub_zpz + 4 * a + 2] = u(pz.a);
                B.pub[B.pub_zpz + 4 * a + 3] = u(pz.b);
            }
            fold_vs_u64("N-F4 lb nonzero after batch 0, zeroed at end (C5)", &B);
            built_free(&B);
        } else {
            check("N-F4 build", 0);
        }
    }
    /* N-F5 — C1c non-boolean b on a chain row (+ the predecessor's C1b-1). */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            row_of(&B, 1)[FOI_COL_B] = 2;
            fold_vs_u64("N-F5 non-boolean b on a chain row (C1c + C1b-1)", &B);
            built_free(&B);
        } else {
            check("N-F5 build", 0);
        }
    }

    printf("\n-- T-NEG: per-intermediate + publics tampers ----------------\n");

    /* N6 — quot on an lb acc row (t == 0 there, so C3f is untouched): C3d. */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            uint64_t *ar = row_of(&B, (size_t)r_acc_h2);
            ar[FOI_COL_QUOT] = bump(ar[FOI_COL_QUOT]);
            fold_vs_u64("N6 quot tampered on an lb acc row (C3d)", &B);
            built_free(&B);
        } else {
            check("N6 build", 0);
        }
    }
    /* N7 — t on an lb acc row: C3e c0 + the C3f-ro carry it feeds. */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            uint64_t *ar = row_of(&B, (size_t)r_acc_h2);
            ar[FOI_COL_T] = bump(ar[FOI_COL_T]);
            fold_vs_u64("N7 t tampered on an lb acc row (C3e + C3f-ro)", &B);
            built_free(&B);
        } else {
            check("N7 build", 0);
        }
    }
    /* N8 — ro on a group-start acc row: C3a + the C3f-ro carry. */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            uint64_t *ar = row_of(&B, (size_t)r_acc_h4);
            ar[FOI_COL_RO] = bump(ar[FOI_COL_RO]);
            fold_vs_u64("N8 ro != 0 on a group-start row (C3a + C3f-ro)", &B);
            built_free(&B);
        } else {
            check("N8 build", 0);
        }
    }
    /* N11 — y on a squaring row: the squaring INTO it and OUT of it (C2b x2),
     * both is_transition-wrapped forms. */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            uint64_t *sr = row_of(&B, (size_t)r_sq_h2);
            sr[FOI_COL_Y] = bump(sr[FOI_COL_Y]);
            fold_vs_u64("N11 y tampered on a squaring row (C2b x2)", &B);
            built_free(&B);
        } else {
            check("N11 build", 0);
        }
    }
    /* N12 — gb on a chain row: the predecessor's C1b-1 and C1b-2. */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            uint64_t *cr = row_of(&B, 1);
            cr[FOI_COL_GB] = bump(cr[FOI_COL_GB]);
            fold_vs_u64("N12 gb tampered on chain row 1 (C1b-1 + C1b-2)", &B);
            built_free(&B);
        } else {
            check("N12 build", 0);
        }
    }
    /* N33 (s2) — p_x TRACE column on an lb acc row. C3g + C3e-c0 in the u64
     * form; the fold form has to reproduce the count exactly, which is what
     * pins C3g's fold transcription (gate, operand order and slot). */
    {
        built_t B;
        if (build_honest(&B, REF, 13, 2)) {
            uint64_t *ar = row_of(&B, (size_t)r_acc_h2);
            ar[FOI_COL_PX] = bump(ar[FOI_COL_PX]);
            fold_vs_u64("N33 p_x trace column tampered (C3g + C3e-c0)", &B);
            built_free(&B);
        } else {
            check("N33 build", 0);
        }
    }
    /* N13/N16/N17/N34 — publics: an index bit, an exported ro, an alpha lane,
     * and (s2) a p_x lane. */
    {
        const uint64_t s3 = W.pub[3]; /* bit 3, read by chain row 0 */
        W.pub[3] ^= 1u;
        fold_vs_u64("N13 index-bit public flipped (C1c-p)", &W);
        W.pub[3] = s3;

        const uint64_t sro = W.pub[W.pub_ro];
        W.pub[W.pub_ro] = bump(sro);
        fold_vs_u64("N16 exported-ro public moved, non-final (C4a)", &W);
        W.pub[W.pub_ro] = sro;

        const uint64_t sal = W.pub[W.pub_alpha];
        W.pub[W.pub_alpha] = bump(sal);
        fold_vs_u64("N17 alpha public lane moved (C3f-ap, both groups)", &W);
        W.pub[W.pub_alpha] = sal;

        /* Exactly one form reads a p_x public, so the u64 count is 1 and the
         * fold count must be 1 — a C3g wired to the wrong slot would move a
         * different (or no) constraint and the equality would break. */
        const uint64_t spx = W.pub[W.pub_px];
        W.pub[W.pub_px] = bump(spx);
        fold_vs_u64("N34 p_x public lane 0 moved (C3g)", &W);
        W.pub[W.pub_px] = spx;

        const uint64_t spx1 = W.pub[W.pub_px + 1];
        W.pub[W.pub_px + 1] = bump(spx1);
        fold_vs_u64("N34b p_x public lane 1 moved (C3g, per-row slot)", &W);
        W.pub[W.pub_px + 1] = spx1;
    }
    fold_vs_u64("publics restored -> honest again", &W);

    /* ── T-TERM: the u64 terminality GATE is now an is_last_row BOUNDARY ──── */
    printf("\n-- T-TERM: terminality is a live constraint, not a gate -----\n");
    {
        dnac_stark_air_t air;
        memset(&air, 0, sizeof(air));
        check("bind(REF) for T-TERM",
              dnac_foi_fold_bind(W.cfg, &air) == DNAC_FOI_FOLD_OK);

        uint64_t *last =
            W.prep + (W.rows - 1) * (size_t)DNAC_P2C_OI_TABLE_COLS;
        const uint64_t sp = last[DNAC_P2C_OI_COL_IS_PAD];
        const uint64_t sc = last[DNAC_P2C_OI_COL_IS_CHAIN];

        /* (a) MINIMAL tamper: is_pad cleared and nothing else. No other form
         * reads is_pad, so EXACTLY ONE constraint may fire. */
        last[DNAC_P2C_OI_COL_IS_PAD] = 0;
        {
            ftu_result_t R;
            check("u64 fails closed on a non-padding last row",
                  eval_b(&W) == FOI_VIOL_BAD_CONFIG);
            check("fold run (a)",
                  ftu_run_trace(&air, W.trace, W.rows, air.main_width, W.prep,
                                (size_t)DNAC_P2C_OI_TABLE_COLS, W.pub, W.num_pub,
                                &R) == 1);
            check("T-TERM(a) exactly 1 non-zero (is_pad boundary alone)",
                  R.nonzero == 1);
            check("T-TERM(a) it is on the LAST row, in the terminality block",
                  R.first_row == W.rows - 1 && R.first_step < 5);
        }
        /* (b) the shipped gate's tamper: last row retyped as a chain row. */
        last[DNAC_P2C_OI_COL_IS_CHAIN] = 1;
        {
            ftu_result_t R;
            check("fold run (b)",
                  ftu_run_trace(&air, W.trace, W.rows, air.main_width, W.prep,
                                (size_t)DNAC_P2C_OI_TABLE_COLS, W.pub, W.num_pub,
                                &R) == 1);
            check("T-TERM(b) caught, first non-zero in the last row's "
                  "terminality block",
                  R.nonzero >= 2 && R.first_row == W.rows - 1 &&
                      R.first_step < 5);
        }
        last[DNAC_P2C_OI_COL_IS_PAD] = sp;
        last[DNAC_P2C_OI_COL_IS_CHAIN] = sc;
        fold_vs_u64("prep restored -> honest again", &W);
    }

    /* ── T-RAIL: the shape rail is live and fail-closes ───────────────────── */
    printf("\n-- T-RAIL: out-of-contract window -> unsatisfiable ----------\n");
    {
        dnac_stark_air_t air;
        memset(&air, 0, sizeof(air));
        check("bind(REF) for T-RAIL",
              dnac_foi_fold_bind(W.cfg, &air) == DNAC_FOI_FOLD_OK);
        ftu_result_t R;
        check("fold run with a short main_width",
              ftu_run_trace(&air, W.trace, W.rows, air.main_width - 1, W.prep,
                            (size_t)DNAC_P2C_OI_TABLE_COLS, W.pub, W.num_pub,
                            &R) == 1);
        check("T-RAIL 1 step/row and every one non-zero",
              R.steps == 1 && R.nonzero == W.rows);
    }

    /* ── T-DISARM: a REJECTED bind disarms the previous binding ─────────────
     * FLEET 027 verifier-B H1 (see test_fri_air_fold.c for the full note). */
    printf("\n-- T-DISARM: rejected bind disarms previous binding ---------\n");
    {
        dnac_stark_air_t air;
        memset(&air, 0, sizeof(air));
        check("bind(REF) for T-DISARM",
              dnac_foi_fold_bind(W.cfg, &air) == DNAC_FOI_FOLD_OK);
        check("re-bind(lgmh > 32) rejected",
              dnac_foi_fold_bind(&CFG_LGMH33, &air) != DNAC_FOI_FOLD_OK);
        ftu_result_t R;
        check("fold run on the HONEST trace after the rejected bind",
              ftu_run_trace(&air, W.trace, W.rows, air.main_width, W.prep,
                            (size_t)DNAC_P2C_OI_TABLE_COLS, W.pub, W.num_pub,
                            &R) == 1);
        check("T-DISARM rail fires (1 step/row, every one non-zero)",
              R.steps == 1 && R.nonzero == W.rows);
        check("re-bind(REF) re-arms",
              dnac_foi_fold_bind(W.cfg, &air) == DNAC_FOI_FOLD_OK);
    }

    built_free(&W);

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("s1a FRI open_input FOLD form: %d FAIL\n", fails);
        return 1;
    }
    /* Roster, audited by ENUMERATION (count-KAFADAN discipline):
     *   T-EQ/T-CNT  7 honest walks over 5 configs (REF@0, REF@11, REF@13,
     *               WIDE, MB, NOLB, NOLB_MB — the last two lb-LESS, FLEET 029),
     *               each pinning steps/row twice (test-side enumeration +
     *               dnac_foi_fold_num_constraints)
     *   T-NEG      16 tampers with the u64 violation COUNT matched exactly:
     *               N-F1 N-F2 N-F3 N-F4 N-F5 (the A2 closures + spec
     *               mandatories), N6 N7 N8 N11 N12 N33 (forms; N33 is the s2
     *               p_x trace column), N13 N16 N17 N34 N34b (publics; N34/N34b
     *               are the s2 p_x public slots) — 18 comparison runs with the
     *               two "restored -> honest" re-checks
     *   T-TERM      2 (minimal is_pad tamper, exact count 1; retyped last row)
     *   T-BIND     16 (1 bind + 4 descriptor + 5 count + 3 bad cfgs + 2 NULL
     *               + re-bind — the earlier "12" was itself a count-KAFADAN,
     *               caught by FLEET 027 verifier-B M1)
     *   T-RAIL      2
     *   T-DISARM    5 (verifier-B H1 closure) */
    printf("s1a FRI open_input FOLD form: 7 honest walks (u64 == fold == 0,\n"
           "  incl. 2 lb-LESS configs) + 16 tampers with EXACT u64-count\n"
           "  agreement (incl. the A2 closures N-F1 one-sided carry and N-F2\n"
           "  ungated x_reg HOLD, and the s2 C3g p_x binding N33/N34/N34b)\n"
           "  + 2 terminality-boundary checks + 16 bind/descriptor gates\n"
           "  + 2 shape-rail + 5 disarm checks — PASS\n");
    return 0;
}
