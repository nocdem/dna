/**
 * @file test_transcript_air_fold.c
 * @brief s1a — equivalence gate for the transcript control-AIR's FOLD form.
 *
 * Build spec: dnac/docs/plans/2026-07-29-composition-s1a-fold-evals-BUILDABLE.md
 * §4 (T-EQ / T-CNT / T-NEG / T-TERM).
 *
 * ── HONEST LABEL ────────────────────────────────────────────────────────────
 * Nothing here is byte-matched against Plonky3. What is proved is an
 * EQUIVALENCE between two DNAC artifacts: the shipped u64 evaluator
 * (`transcript_air.c`, itself gated by tests/test_transcript_air.c against the
 * 8 `dump-transcript-trace` oracle scenarios) and the new fold-form transcription
 * (`transcript_air_fold.c`). The oracle grounding is INHERITED through the honest
 * trace builder, which is the SHIPPED one — this file `#include`s
 * `test_transcript_air.c` (with its `main` renamed out of the way) rather than
 * copying `load_vector` / `build_trace` / `write_bits`, so the two suites cannot
 * drift apart. The shipped file is NOT modified.
 *
 * (accept) T-EQ: for all 8 oracle scenarios, every row of the honest trace folds
 *   to ALL-ZERO captured residuals.
 * (accept) T-CNT: `capture_len` is identical on every row and equals
 *   `dnac_transcript_air_fold_control_steps(cfg, script)` + the MEASURED
 *   Poseidon2 block step count.
 * (reject) T-NEG: 8 tampers drawn from the shipped negative suite's classes —
 *   each produces at least one non-zero residual.
 * (reject) T-TERM: a trace ending in a sampling row trips the `is_last_row`
 *   boundary, in isolation (EXACTLY one non-zero residual).
 *
 * Build (via Makefile):
 *   ./build/test_transcript_air_fold tools/vectors/transcript_trace_*.json
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

/* Reuse the SHIPPED honest-trace builder + vector loader verbatim. The shipped
 * `main` is renamed (it is never called from here); every static helper it owns
 * — load_vector, build_trace, write_bits, regen_perm, find_row, row_of, fadd,
 * clone_trace, pow_bits_of — becomes available in this translation unit. */
#define main dnac_tair_shipped_main_unused
#include "test_transcript_air.c"
#undef main

#include "../poseidon2_fold.h"
#include "../transcript_air_fold.h"
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

/* `want_exact` > 0 additionally pins the non-zero count (the isolated-form
 * pattern the shipped suites use: it proves the tamper hits THAT constraint and
 * nothing else). */
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

/* ═════════════════════════════════ main ══════════════════════════════════ */

int main(int argc, char **argv) {
    if (argc < 9) {
        fprintf(stderr,
                "usage: %s <transcript_trace_*.json x8>\n"
                "  (the 8 dump-transcript-trace scenarios)\n",
                argv[0]);
        return 2;
    }

    printf("============================================================\n");
    printf("s1a — transcript control-AIR, FOLD form (fp2 alpha-fold)\n");
    printf("  equivalence vs the shipped u64 evaluator, same trace\n");
    printf("============================================================\n");

    /* The Poseidon2 block's step count, MEASURED from the shipped shared fold
     * (never hand-written — the count-KAFADAN discipline). */
    const size_t p2_steps =
        fold_measure_block(dnac_poseidon2_fold_eval, (size_t)P2AIR_NUM_COLS);
    if (p2_steps == 0) {
        printf("  FAIL: could not measure the Poseidon2 block step count\n");
        return 2;
    }
    printf("  [info]   embedded Poseidon2 block: %zu fold steps\n", p2_steps);

    dnac_stark_air_t air;
    memset(&air, 0, sizeof(air));
    /* FLEET 034: the binding is CALLER-OWNED state now, reached via air.ctx. */
    static dnac_tair_fold_state_t state;
    memset(&state, 0, sizeof(state));

    /* ── Gate 0: bind contract + fail-close ── */
    {
        const dnac_tair_config_t good = {TAIR_TEST_DEFAULT_POW_BITS};
        const dnac_tair_config_t bad = {(size_t)TAIR_MAX_NUM_BITS + 1};

        /* s3a: the bind now takes the pinned SCRIPT too. The reference FRI-tail
         * script (transcript_air_table.h) is the one the pin is derived from —
         * used here purely as a well-formed script to bind against. */
        static dnac_tair_op_t ref_ops[DNAC_P2A_REF_OPS];
        static size_t ref_starts[1];
        dnac_tair_script_t ref;
        if (dnac_tair_ref_script(ref_ops, DNAC_P2A_REF_OPS, ref_starts, &ref) !=
            DNAC_TAIR_TABLE_OK) {
            printf("  FAIL: reference script build\n");
            return 1;
        }

        if (dnac_transcript_air_fold_bind(NULL, &ref, &state, &air) != 0)
            printf("  [accept] bind(NULL cfg) rejected                       OK\n");
        else { printf("  [accept] bind(NULL cfg) rejected                       FAIL\n"); fails++; }

        if (dnac_transcript_air_fold_bind(&good, NULL, &state, &air) != 0)
            printf("  [accept] bind(NULL script) rejected                    OK\n");
        else { printf("  [accept] bind(NULL script) rejected                    FAIL\n"); fails++; }

        if (dnac_transcript_air_fold_bind(&good, &ref, &state, NULL) != 0)
            printf("  [accept] bind(NULL out_air) rejected                   OK\n");
        else { printf("  [accept] bind(NULL out_air) rejected                   FAIL\n"); fails++; }

        /* FLEET 034: a NULL state is a PARAM error, not a silent no-op. */
        if (dnac_transcript_air_fold_bind(&good, &ref, NULL, &air) != 0)
            printf("  [accept] bind(NULL state) rejected                     OK\n");
        else { printf("  [accept] bind(NULL state) rejected                     FAIL\n"); fails++; }

        if (dnac_transcript_air_fold_bind(&bad, &ref, &state, &air) != 0)
            printf("  [accept] bind(pow_bits > max) rejected                 OK\n");
        else { printf("  [accept] bind(pow_bits > max) rejected                 FAIL\n"); fails++; }

        /* N-CTX-REJECT — the rejected bind above must have left `state`
         * DISARMED, and an eval THROUGH it emits exactly ONE unsatisfiable
         * constraint. N-CTX-NULL — a descriptor with no context at all does the
         * same (before FLEET 034 that case did not exist: the module static
         * answered for every descriptor). */
        {
            uint64_t *z = (uint64_t *)calloc((size_t)TAIR_WIDTH * 2, sizeof(uint64_t));
            if (!z) return 2;
            {
                dnac_stark_air_t probe = {(size_t)TAIR_WIDTH, 0, 1,
                                          dnac_transcript_air_fold_eval, &state};
                fold_input_t in = {&probe, z, 2, (size_t)TAIR_WIDTH, NULL, 0, NULL, 0};
                const fold_trace_t T = fold_eval_trace(&in);
                if (state.bound == 0 && T.nonzero == 2 && T.steps_row0 == 1)
                    printf("  [accept] N-CTX-REJECT: disarmed, eval unsatisfiable    OK\n");
                else {
                    printf("  [accept] N-CTX-REJECT: disarmed, eval unsatisfiable    "
                           "FAIL (%zu non-zero, %zu steps)\n", T.nonzero, T.steps_row0);
                    fails++;
                }
            }
            {
                dnac_stark_air_t probe = {(size_t)TAIR_WIDTH, 0, 1,
                                          dnac_transcript_air_fold_eval, NULL};
                fold_input_t in = {&probe, z, 2, (size_t)TAIR_WIDTH, NULL, 0, NULL, 0};
                const fold_trace_t T = fold_eval_trace(&in);
                if (T.nonzero == 2 && T.steps_row0 == 1)
                    printf("  [accept] N-CTX-NULL: eval unsatisfiable                OK\n");
                else {
                    printf("  [accept] N-CTX-NULL: eval unsatisfiable                "
                           "FAIL (%zu non-zero, %zu steps)\n", T.nonzero, T.steps_row0);
                    fails++;
                }
            }
            free(z);
        }

        if (dnac_transcript_air_fold_bind(&good, &ref, &state, &air) == 0 &&
            air.main_width == (size_t)TAIR_WIDTH &&
            air.num_public_values == dnac_tair_num_publics(&ref) &&
            air.num_public_values == DNAC_P2A_REF_PUBLICS && air.main_next == 1 &&
            air.air_eval == dnac_transcript_air_fold_eval &&
            air.ctx == (const void *)&state && state.bound == 1)
            printf("  [accept] descriptor {w=%zu, pubs=%zu, next=1, ctx}       OK\n",
                   air.main_width, air.num_public_values);
        else {
            printf("  [accept] descriptor fields                             FAIL\n");
            fails++;
        }
    }

    /* nodus/messenger fixture rule: multi-KB fixtures are heap-allocated. */
    built_t *B = (built_t *)calloc(1, sizeof(built_t));
    built_t *B_basic = (built_t *)calloc(1, sizeof(built_t));
    vec_t *V = (vec_t *)calloc(1, sizeof(vec_t));
    vec_t *V_basic = (vec_t *)calloc(1, sizeof(vec_t));
    if (!B || !B_basic || !V || !V_basic) return 2;
    {
        built_t *all[2] = {B, B_basic};
        for (int i = 0; i < 2; i++) {
            all[i]->trace = (uint64_t *)calloc(TRACE_ELEMS, sizeof(uint64_t));
            all[i]->prep = (uint64_t *)calloc(PREP_ELEMS, sizeof(uint64_t));
            all[i]->pub = (uint64_t *)calloc(MAX_PUB, sizeof(uint64_t));
            if (!all[i]->trace || !all[i]->prep || !all[i]->pub) return 2;
        }
    }

    /* ══ PHASE 1 — T-EQ + T-CNT over all 8 oracle scenarios ══ */
    printf("------------------------------------------------------------\n");
    printf("Phase 1 — T-EQ / T-CNT (honest traces, 8 oracle scenarios)\n");
    printf("------------------------------------------------------------\n");
    int scenarios = 0;
    for (int a = 1; a < argc; a++) {
        if (!load_vector(argv[a], V)) { fails++; continue; }
        const dnac_tair_config_t cfg = {pow_bits_of(V)};
        if (!build_trace(V, B)) {
            printf("  [accept] %-20s honest trace build              FAIL\n",
                   V->scenario);
            fails++;
            continue;
        }
        /* The u64 evaluator must accept it — otherwise the equivalence claim
         * below is comparing against a broken baseline. */
        if (dnac_transcript_air_eval_trace(B->trace, B->prep, B->n_rows, &cfg,
                                           &B->script, B->pub, B->n_pub) != 0) {
            printf("  [accept] %-20s u64 baseline not clean          FAIL\n",
                   V->scenario);
            fails++;
            continue;
        }
        if (dnac_transcript_air_fold_bind(&cfg, &B->script, &state, &air) != 0) {
            printf("  [accept] %-20s bind                            FAIL\n",
                   V->scenario);
            fails++;
            continue;
        }
        fold_input_t in = {&air,     B->trace,      B->n_rows,
                           (size_t)TAIR_WIDTH, B->prep, TAIR_TBL_COLS,
                           B->pub,   B->n_pub};
        fexpect_clean(V->scenario, &in,
                      dnac_transcript_air_fold_control_steps(&cfg, &B->script) +
                          p2_steps);
        scenarios++;
        if (strcmp(V->scenario, "basic") == 0) stash(B_basic, V_basic, B, V);
    }
    if (scenarios != 8) {
        printf("  FAIL: expected 8 scenarios, folded %d\n", scenarios);
        fails++;
    }

    /* ══ PHASE 2 — T-NEG ══ */
    printf("------------------------------------------------------------\n");
    printf("Phase 2 — T-NEG (tampers carried over from the u64 suite)\n");
    printf("------------------------------------------------------------\n");
    if (B_basic->n_rows == 0) {
        printf("  FAIL: the `basic` scenario was not among the vectors given\n");
        return 1;
    }
    built_t *const W = B_basic;
    const dnac_tair_config_t cfg = {pow_bits_of(V_basic)};
    if (dnac_transcript_air_fold_bind(&cfg, &W->script, &state, &air) != 0) {
        printf("  FAIL: workhorse bind\n");
        return 1;
    }

    const int r_smp = find_row(W, TAIR_SEL_SAMPLE, 0);
    const int r_obsdup = find_row(W, TAIR_SEL_OBS_DUP, 0);
    const int r_fill = find_row(W, TAIR_SEL_FILLER, 0);
    int r_absorb = -1;
    for (size_t r = 0; r < W->n_rows; r++) {
        if (W->sel_of[r] != TAIR_SEL_SAMPLE_DUP) continue;
        if (row_of(W->trace, r)[tair_il_off(0)] == 0) { r_absorb = (int)r; break; }
    }
    int r_prefix = -1;
    for (size_t r = 0; r < W->n_rows; r++) {
        if (W->sel_of[r] != TAIR_SEL_OBS) continue;
        if (row_of(W->trace, r)[tair_prefix_off(TAIR_RATE)] == 0) {
            r_prefix = (int)r;
            break;
        }
    }
    if (r_smp < 0 || r_obsdup < 0 || r_fill < 0 || r_absorb < 0 || r_prefix < 0 ||
        (size_t)r_fill + 1 >= W->n_rows) {
        printf("  FAIL: workhorse trace lacks a needed row type\n");
        return 1;
    }

/* s3a: every fold runs against the workhorse's OWN pinned table + publics. */
#define FOLD_IN(t, n)                                                         \
    ((fold_input_t){&air, (t), (n), (size_t)TAIR_WIDTH, W->prep,              \
                    TAIR_TBL_COLS, W->pub, W->n_pub})

    /* F-N1 — absorb relabelled as squeeze (u64 N1, transcript_air.c block K). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_absorb);
        for (size_t k = 0; k < TAIR_LEN_SLOTS; k++) row[tair_il_off(k)] = (k == 0);
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-N1 absorb relabelled as squeeze", &in, 0);
        free(t);
    }
    /* F-N2 — length tag skipped (block K capacity pin). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_absorb);
        row[tair_perm_in_off(TAIR_RATE)] = row[tair_state_off(TAIR_RATE)];
        regen_perm(row);
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-N2 length tag skipped", &in, 0);
        free(t);
    }
    /* F-N3 — DS-prefix limb tampered (block E). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_prefix);
        row[TAIR_LANE_OFF] = fadd(row[TAIR_LANE_OFF], 1);
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-N3 DS-prefix limb tampered", &in, 0);
        free(t);
    }
    /* F-N4 — selector one-hot double bit (block A). */
    {
        uint64_t *t = clone_trace(W);
        row_of(t, (size_t)r_smp)[tair_sel_off(TAIR_SEL_FILLER)] = 1;
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-N4 selector double-bit", &in, 0);
        free(t);
    }
    /* F-N5 — il_flag one-hot double bit (block A). */
    {
        uint64_t *t = clone_trace(W);
        row_of(t, (size_t)r_smp)[tair_il_off(1)] = 1;
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-N5 il_flag double-bit", &in, 0);
        free(t);
    }
    /* F-N6 — an interior cell of the embedded Poseidon2 block (block B; the
     * INLINE embed is what makes the permutation real). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_obsdup);
        const size_t off = (size_t)TAIR_PERM_OFF + p2air_beg_sbox_off(0, 0);
        row[off] = fadd(row[off], 1);
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-N6 Poseidon2 block interior tamper", &in, 0);
        free(t);
    }
    /* F-N7 — state copy broken on a sample row (block J threading; a TRANSITION
     * form, so this is the negative that proves the is_transition factor did not
     * delete the block). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_smp + 1);
        row[tair_state_off(0)] = fadd(row[tair_state_off(0)], 1);
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-N7 state copy broken (transition form)", &in, 0);
        free(t);
    }
    /* F-N8 — is_pow on a non-sampling row. Pre-s3a this hit block A3 alone
     * (EXACTLY one residual); since s3a it ALSO breaks CT-2 against the pinned
     * table, so the isolated count is TWO. Pinned rather than loosened, so a
     * future change that silently drops either rule shows up here. */
    {
        uint64_t *t = clone_trace(W);
        row_of(t, (size_t)r_obsdup)[TAIR_ISPOW_OFF] = 1;
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-N8 is_pow on a non-sampling row (A3 + CT-2)", &in, 2);
        free(t);
    }
    /* F-N9 — op after filler started (block L terminality-of-padding, also a
     * transition form). */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *row = row_of(t, (size_t)r_fill + 1);
        row[tair_sel_off(TAIR_SEL_FILLER)] = 0;
        row[tair_sel_off(TAIR_SEL_OBS)] = 1;
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-N9 op after filler", &in, 0);
        free(t);
    }

    /* ══ PHASE 3 — T-TERM ══
     * The `is_last_row` boundary is the form that has NO u64 per-row counterpart
     * (it lives in eval_trace, transcript_air.c:444-460). These two negatives
     * are what prove the transcription actually carried it. */
    printf("------------------------------------------------------------\n");
    printf("Phase 3 — T-TERM (is_last_row boundary)\n");
    printf("------------------------------------------------------------\n");
    /* F-T1 — TRUNCATE the honest trace so it ends at a sampling row. Nothing
     * else can fire: the truncated last row has no successor, so every
     * transition form vanishes, and its own row-local forms are satisfied
     * (it is an honest row). EXACTLY one non-zero. */
    {
        fold_input_t in = FOLD_IN(W->trace, (size_t)r_smp + 1);
        fexpect_reject("F-T1 trace ends at a sampling row", &in, 1);
    }
    /* F-T2 — the last filler relabelled as a sample with an attacker-chosen
     * lane (the shipped N20 shape). The predecessor filler's own
     * "next is a filler" rule fires too, so the count is not pinned. */
    {
        uint64_t *t = clone_trace(W);
        uint64_t *last = row_of(t, W->n_rows - 1);
        last[tair_sel_off(TAIR_SEL_FILLER)] = 0;
        last[tair_sel_off(TAIR_SEL_SAMPLE)] = 1;
        last[TAIR_LANE_OFF] = 0x1234u;
        write_bits(last, 0x1234u);
        fold_input_t in = FOLD_IN(t, W->n_rows);
        fexpect_reject("F-T2 last row relabelled as a sample", &in, 0);
        free(t);
    }

    /* ══ PHASE 4 — the s3a block-T forms, in fold shape ══
     * Each mirrors a u64 negative in tests/test_transcript_air.c; what they prove
     * here is that block T survived the transcription in the SAME position and
     * with the same gating. */
    printf("------------------------------------------------------------\n");
    printf("Phase 4 — s3a block T (CT-1 / CT-2 / CT-3 / CT-4)\n");
    printf("------------------------------------------------------------\n");
    /* F-T3 (CT-1) — a TABLE row type flipped under an honest trace. Isolated:
     * two of the six CT-1 equalities move (the cleared lane and the set one). */
    {
        uint64_t *p = clone_buf(W->prep, PREP_ELEMS);
        if (!p) return 2;
        uint64_t *prow = p + (size_t)r_smp * TAIR_TBL_COLS;
        prow[tair_tbl_col_type(TAIR_TBL_TYPE_SAMPLE)] = 0;
        prow[tair_tbl_col_type(TAIR_TBL_TYPE_FILLER)] = 1;
        fold_input_t in = {&air,     W->trace,      W->n_rows,
                           (size_t)TAIR_WIDTH, p,   TAIR_TBL_COLS,
                           W->pub,   W->n_pub};
        fexpect_reject("F-T3 table row type flipped (CT-1)", &in, 2);
        free(p);
    }
    /* F-T4 (CT-3b) — one payload public moved. Isolated: exactly the one row
     * whose op owns that slot. */
    {
        uint64_t *pub2 = clone_buf(W->pub, W->n_pub);
        if (!pub2) return 2;
        pub2[0] = fadd(pub2[0], 1);
        fold_input_t in = {&air,     W->trace,      W->n_rows,
                           (size_t)TAIR_WIDTH, W->prep, TAIR_TBL_COLS,
                           pub2,     W->n_pub};
        fexpect_reject("F-T4 payload public moved (CT-3b)", &in, 1);
        free(pub2);
    }
    /* F-T5 (CT-3a) — the table's op-step one-hot cleared on an op row: the
     * position sum no longer matches the row's op indicator AND the payload
     * selection collapses to zero. */
    {
        uint64_t *p = clone_buf(W->prep, PREP_ELEMS);
        if (!p) return 2;
        size_t k = 0;
        for (size_t r = 0; r < (size_t)r_smp; r++)
            if (W->sel_of[r] != TAIR_SEL_START && W->sel_of[r] != TAIR_SEL_FILLER)
                k++;
        p[(size_t)r_smp * TAIR_TBL_COLS + tair_tbl_col_pos(k)] = 0;
        fold_input_t in = {&air,     W->trace,      W->n_rows,
                           (size_t)TAIR_WIDTH, p,   TAIR_TBL_COLS,
                           W->pub,   W->n_pub};
        fexpect_reject("F-T5 op-step one-hot cleared (CT-3a)", &in, 2);
        free(p);
    }
#undef FOLD_IN

    /* CT-4 has no bit-exporting op in `basic` (its samples are plain pops), so
     * the export surface is folded on the sample_bits_32 scenario instead. */
    {
        for (int a = 1; a < argc; a++) {
            if (!load_vector(argv[a], V)) continue;
            if (strcmp(V->scenario, "sample_bits_32") != 0) continue;
            if (!build_trace(V, B)) {
                printf("  FAIL: sample_bits_32 rebuild\n");
                fails++;
                break;
            }
            const dnac_tair_config_t cfg_x = {pow_bits_of(V)};
            if (dnac_transcript_air_fold_bind(&cfg_x, &B->script, &state, &air) != 0) {
                printf("  FAIL: sample_bits_32 bind\n");
                fails++;
                break;
            }
            uint64_t *pub2 = clone_buf(B->pub, B->n_pub);
            const size_t off =
                dnac_tair_op_bit_off(&B->script, B->script.n_ops - 1);
            if (!pub2) return 2;
            if (off == (size_t)-1) {
                printf("  FAIL: sample_bits_32 last op exports no bits\n");
                fails++;
            } else {
                pub2[off] ^= 1u;
                fold_input_t in = {&air,     B->trace,      B->n_rows,
                                   (size_t)TAIR_WIDTH, B->prep, TAIR_TBL_COLS,
                                   pub2,     B->n_pub};
                fexpect_reject("F-T6 exported index bit moved (CT-4)", &in, 1);
            }
            free(pub2);
            break;
        }
    }

    {
        built_t *all[2] = {B, B_basic};
        for (int i = 0; i < 2; i++) {
            free(all[i]->trace);
            free(all[i]->prep);
            free(all[i]->pub);
            free(all[i]);
        }
    }
    free(V);
    free(V_basic);

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("s1a transcript FOLD: %d FAIL\n", fails);
        return 1;
    }
    printf("s1a transcript FOLD: 8 scenarios T-EQ+T-CNT + 5 bind gates +\n"
           "  9 T-NEG + 2 T-TERM + 4 s3a block-T — PASS\n");
    return 0;
}
