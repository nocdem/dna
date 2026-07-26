/**
 * @file test_logup.c
 * @brief P2L-a — byte-match gate for logup.c vs Plonky3 p3-lookup LogUpGadget.
 *
 * Loads tools/vectors/logup.json (11 instances + 2 global checks) and asserts
 * exact u64-limb equality between the C port and the REAL Plonky3 gadget
 * (commit 82cfad73, lookup/src/logup.rs):
 *   1. aux (permutation) traces from generate_permutation (logup.rs:370-646);
 *      for the corrupted-witness instance the clean C aux must differ from
 *      the dumped aux in EXACTLY one cell,
 *   2. cumulative sums (LookupData, logup.rs:636-640),
 *   3. the full per-(row, lookup) residual stream from eval_local/eval_global
 *      (logup.rs:158-265; entries are selector-multiplied per filtered.rs),
 *   4. constraint degrees (logup.rs:339-367),
 *   5. verify_global_sum verdicts per single-bus group (logup.rs:314-324),
 * plus C-side fail-close negatives that Plonky3 can only express as panics
 * (zero denominator, duplicate aux column, challenge-count mismatch,
 * kind/cumulative_sum mismatch).
 *
 * Exit codes: 0 all green, 1 mismatch, 2 load/parse error.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../field_goldilocks.h"
#include "../logup.h"
#include "logup_test_util.h"

/* ============================================================================
 * Case runner
 * ========================================================================== */
static int g_total = 0, g_failed = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        g_total++;                                                             \
        if (!(cond)) {                                                         \
            g_failed++;                                                        \
            fprintf(stderr, "MISMATCH: " __VA_ARGS__);                         \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

/* Per-instance cumulative sums stashed for the cross-instance global checks. */
typedef struct {
    const char *instance;
    char bus[32];
    uint32_t aux_column;
    gold_fp2_t sum;
} cum_entry_t;
static cum_entry_t g_cums[64];
static size_t g_ncums = 0;

static bool parse_fp_matrix(const jv_t *rows, uint32_t *h, uint32_t *w,
                            gold_fp_t **out)
{
    if (!rows || rows->kind != JV_ARR) return false;
    *h = (uint32_t)rows->n;
    *w = 0;
    *out = NULL;
    if (rows->n == 0) return true;
    *w = (uint32_t)rows->items[0]->n;
    gold_fp_t *m = (gold_fp_t *)malloc(sizeof(gold_fp_t) * rows->n * (*w));
    if (!m) return false;
    for (size_t r = 0; r < rows->n; r++) {
        const jv_t *row = rows->items[r];
        if (row->kind != JV_ARR || row->n != *w) { free(m); return false; }
        for (size_t c = 0; c < row->n; c++) {
            uint64_t v;
            if (!jv_u64(row->items[c], &v)) { free(m); return false; }
            m[r * (*w) + c] = gold_fp_from_u64(v);
        }
    }
    *out = m;
    return true;
}

static int run_case(const jv_t *cs)
{
    const jv_t *jname = jv_get(cs, "name");
    const char *name = (jname && jname->kind == JV_STR) ? jname->str : "?";

    uint64_t height64, main_width64, num_aux64;
    if (!jv_u64(jv_get(cs, "height"), &height64) ||
        !jv_u64(jv_get(cs, "main_width"), &main_width64) ||
        !jv_u64(jv_get(cs, "num_aux_cols"), &num_aux64)) {
        fprintf(stderr, "FAIL[%s]: header fields\n", name);
        return 2;
    }
    const uint32_t height = (uint32_t)height64;
    const uint32_t num_aux = (uint32_t)num_aux64;

    /* main / preprocessed / publics */
    uint32_t mh, mw;
    gold_fp_t *main_m = NULL;
    if (!parse_fp_matrix(jv_get(cs, "main"), &mh, &mw, &main_m) || mh != height ||
        mw != (uint32_t)main_width64) {
        fprintf(stderr, "FAIL[%s]: main matrix\n", name);
        return 2;
    }
    gold_fp_t *prep_m = NULL;
    uint32_t prep_w = 0;
    const jv_t *prep = jv_get(cs, "preprocessed");
    if (prep && prep->kind == JV_OBJ) {
        uint32_t ph;
        if (!parse_fp_matrix(jv_get(prep, "rows"), &ph, &prep_w, &prep_m) ||
            ph != height) {
            fprintf(stderr, "FAIL[%s]: prep matrix\n", name);
            free(main_m);
            return 2;
        }
    }
    const jv_t *pubs = jv_get(cs, "public_values");
    uint32_t npubs = pubs ? (uint32_t)pubs->n : 0;
    gold_fp_t *pub_m = NULL;
    if (npubs) {
        pub_m = (gold_fp_t *)malloc(sizeof(gold_fp_t) * npubs);
        if (!pub_m) { free(main_m); free(prep_m); return 2; }
        for (uint32_t i = 0; i < npubs; i++) {
            uint64_t v;
            if (!jv_u64(pubs->items[i], &v)) {
                fprintf(stderr, "FAIL[%s]: publics\n", name);
                free(main_m); free(prep_m); free(pub_m);
                return 2;
            }
            pub_m[i] = gold_fp_from_u64(v);
        }
    }

    /* lookups -> pool + dnac_logup_lookup_t */
    const jv_t *jlookups = jv_get(cs, "lookups");
    if (!jlookups || jlookups->kind != JV_ARR || jlookups->n != num_aux) {
        fprintf(stderr, "FAIL[%s]: lookups\n", name);
        free(main_m); free(prep_m); free(pub_m);
        return 2;
    }
    const uint32_t nlk = (uint32_t)jlookups->n;
    pool_t pool = {0};
    dnac_logup_lookup_t *lks =
        (dnac_logup_lookup_t *)calloc(nlk, sizeof(dnac_logup_lookup_t));
    uint32_t **widths = (uint32_t **)calloc(nlk, sizeof(uint32_t *));
    int32_t ***elems = (int32_t ***)calloc(nlk, sizeof(int32_t **));
    int32_t **mults = (int32_t **)calloc(nlk, sizeof(int32_t *));
    uint32_t *exp_degree = (uint32_t *)calloc(nlk, sizeof(uint32_t));
    if (!lks || !widths || !elems || !mults || !exp_degree) return 2;

    for (uint32_t i = 0; i < nlk; i++) {
        const jv_t *lk = jlookups->items[i];
        const jv_t *kind = jv_get(lk, "kind");
        uint64_t col, deg;
        if (!kind || kind->kind != JV_STR ||
            !jv_u64(jv_get(lk, "column"), &col) ||
            !jv_u64(jv_get(lk, "constraint_degree"), &deg)) {
            fprintf(stderr, "FAIL[%s]: lookup %u header\n", name, i);
            return 2;
        }
        lks[i].is_global = !strcmp(kind->str, "global");
        lks[i].column = (uint32_t)col;
        exp_degree[i] = (uint32_t)deg;

        const jv_t *tuples = jv_get(lk, "tuples");
        if (!tuples || tuples->kind != JV_ARR) return 2;
        uint32_t nt = (uint32_t)tuples->n;
        lks[i].num_tuples = nt;
        widths[i] = (uint32_t *)calloc(nt ? nt : 1, sizeof(uint32_t));
        elems[i] = (int32_t **)calloc(nt ? nt : 1, sizeof(int32_t *));
        mults[i] = (int32_t *)calloc(nt ? nt : 1, sizeof(int32_t));
        if (!widths[i] || !elems[i] || !mults[i]) return 2;
        for (uint32_t t = 0; t < nt; t++) {
            const jv_t *tp = tuples->items[t];
            const jv_t *els = jv_get(tp, "elements");
            if (!els || els->kind != JV_ARR) return 2;
            widths[i][t] = (uint32_t)els->n;
            elems[i][t] = (int32_t *)calloc(els->n ? els->n : 1, sizeof(int32_t));
            if (!elems[i][t]) return 2;
            for (size_t j = 0; j < els->n; j++) {
                int32_t idx = build_expr(&pool, els->items[j]);
                if (idx < 0) {
                    fprintf(stderr, "FAIL[%s]: expr build (lookup %u tuple %u)\n",
                            name, i, t);
                    return 2;
                }
                elems[i][t][j] = idx;
            }
            int32_t midx = build_expr(&pool, jv_get(tp, "multiplicity"));
            if (midx < 0) {
                fprintf(stderr, "FAIL[%s]: mult expr build\n", name);
                return 2;
            }
            mults[i][t] = midx;
        }
        lks[i].tuple_widths = widths[i];
        lks[i].tuple_elems = (const int32_t *const *)elems[i];
        lks[i].multiplicities = mults[i];
    }

    dnac_logup_ctx_t ctx = {
        .main = main_m,
        .main_width = mw,
        .prep = prep_m,
        .prep_width = prep_w,
        .publics = pub_m,
        .num_publics = npubs,
        .height = height,
        .pool = pool.nodes,
        .pool_len = pool.len,
    };

    /* challenges */
    const jv_t *jch = jv_get(cs, "challenges");
    if (!jch || jch->kind != JV_ARR || jch->n != 2u * nlk) return 2;
    gold_fp2_t *ch = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * jch->n);
    if (!ch) return 2;
    for (size_t i = 0; i < jch->n; i++) {
        if (!jv_fp2(jch->items[i], &ch[i])) return 2;
    }

    /* expected aux + cumulative sums + residuals */
    const jv_t *jaux = jv_get(cs, "aux");
    if (!jaux || jaux->kind != JV_ARR || jaux->n != height) return 2;
    gold_fp2_t *exp_aux =
        (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * (size_t)height * nlk);
    if (!exp_aux) return 2;
    for (uint32_t r = 0; r < height; r++) {
        const jv_t *row = jaux->items[r];
        if (row->kind != JV_ARR || row->n != nlk) return 2;
        for (uint32_t c = 0; c < nlk; c++) {
            if (!jv_fp2(row->items[c], &exp_aux[(size_t)r * nlk + c])) return 2;
        }
    }
    const jv_t *jcorr = jv_get(cs, "aux_corrupted");
    bool corrupted = jcorr && jcorr->kind == JV_BOOL && jcorr->bval;

    const jv_t *jcums = jv_get(cs, "cumulative_sums");
    uint32_t nglob = jcums ? (uint32_t)jcums->n : 0;

    /* ---- 1. generate_permutation byte-match ---- */
    gold_fp2_t *got_aux =
        (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * (size_t)height * nlk);
    gold_fp2_t got_cums[8];
    if (!got_aux || nglob > 8) return 2;
    int rc = dnac_logup_generate_permutation(&ctx, lks, nlk, ch, 2u * nlk,
                                             got_aux, nglob ? got_cums : NULL,
                                             nglob);
    CHECK(rc == DNAC_LOGUP_OK, "[%s] generate_permutation rc=%d", name, rc);
    if (rc == DNAC_LOGUP_OK) {
        uint32_t diff = 0;
        for (size_t k = 0; k < (size_t)height * nlk; k++) {
            if (!fp2_eq_limbs(got_aux[k], exp_aux[k])) diff++;
        }
        if (corrupted) {
            /* clean C aux vs corrupted dumped aux: exactly one cell differs */
            CHECK(diff == 1, "[%s] corrupted-aux diff=%u (want 1)", name, diff);
        } else {
            CHECK(diff == 0, "[%s] aux diff=%u (want 0)", name, diff);
        }
        /* ---- 2. cumulative sums ---- */
        for (uint32_t g = 0; g < nglob; g++) {
            gold_fp2_t exp_sum;
            uint64_t exp_col;
            const jv_t *ce = jcums->items[g];
            if (!jv_fp2(jv_get(ce, "sum"), &exp_sum) ||
                !jv_u64(jv_get(ce, "aux_column"), &exp_col)) {
                return 2;
            }
            CHECK(fp2_eq_limbs(got_cums[g], exp_sum),
                  "[%s] cumulative_sum[%u] (%" PRIu64 ",%" PRIu64
                  ") != (%" PRIu64 ",%" PRIu64 ")",
                  name, g, gold_fp_to_u64(got_cums[g].a),
                  gold_fp_to_u64(got_cums[g].b), gold_fp_to_u64(exp_sum.a),
                  gold_fp_to_u64(exp_sum.b));
            /* stash for cross-instance global checks */
            const jv_t *bus = jv_get(ce, "bus_name");
            if (g_ncums < 64 && bus && bus->kind == JV_STR) {
                g_cums[g_ncums].instance = name;
                snprintf(g_cums[g_ncums].bus, sizeof(g_cums[g_ncums].bus), "%s",
                         bus->str);
                g_cums[g_ncums].aux_column = (uint32_t)exp_col;
                g_cums[g_ncums].sum = exp_sum;
                g_ncums++;
            }
        }
    }

    /* ---- 3. residual stream byte-match (over the DUMPED aux, so the
     *          corrupted case matches the oracle's non-zero residuals) ---- */
    const jv_t *jres = jv_get(cs, "residuals");
    if (!jres || jres->kind != JV_ARR || jres->n != height) return 2;
    for (uint32_t r = 0; r < height; r++) {
        const jv_t *rrow = jres->items[r];
        if (rrow->kind != JV_ARR || rrow->n != nlk) return 2;
        for (uint32_t i = 0; i < nlk; i++) {
            const jv_t *stream = rrow->items[i];
            if (stream->kind != JV_ARR) return 2;
            gold_fp2_t cum_val;
            const gold_fp2_t *cum_ptr = NULL;
            if (lks[i].is_global) {
                /* the lookup's dumped cumulative sum (matched above) */
                bool found = false;
                for (uint32_t g = 0; g < nglob; g++) {
                    uint64_t col;
                    if (jv_u64(jv_get(jcums->items[g], "aux_column"), &col) &&
                        (uint32_t)col == lks[i].column &&
                        jv_fp2(jv_get(jcums->items[g], "sum"), &cum_val)) {
                        cum_ptr = &cum_val;
                        found = true;
                        break;
                    }
                }
                if (!found) return 2;
            }
            gold_fp2_t got_res[3];
            uint32_t got_n = 0;
            rc = dnac_logup_eval_row(&ctx, &lks[i], exp_aux, nlk, ch, 2u * nlk,
                                     r, cum_ptr, got_res, &got_n);
            CHECK(rc == DNAC_LOGUP_OK, "[%s] eval_row(r=%u,lk=%u) rc=%d", name,
                  r, i, rc);
            if (rc != DNAC_LOGUP_OK) continue;
            CHECK(got_n == stream->n, "[%s] residual count r=%u lk=%u: %u != %zu",
                  name, r, i, got_n, stream->n);
            for (uint32_t k = 0; k < got_n && k < stream->n; k++) {
                gold_fp2_t exp_r;
                if (!jv_fp2(stream->items[k], &exp_r)) return 2;
                CHECK(fp2_eq_limbs(got_res[k], exp_r),
                      "[%s] residual r=%u lk=%u idx=%u: (%" PRIu64 ",%" PRIu64
                      ") != (%" PRIu64 ",%" PRIu64 ")",
                      name, r, i, k, gold_fp_to_u64(got_res[k].a),
                      gold_fp_to_u64(got_res[k].b), gold_fp_to_u64(exp_r.a),
                      gold_fp_to_u64(exp_r.b));
            }
        }
    }

    /* ---- 4. constraint degrees ---- */
    for (uint32_t i = 0; i < nlk; i++) {
        uint32_t d = 0;
        rc = dnac_logup_constraint_degree(&ctx, &lks[i], &d);
        CHECK(rc == DNAC_LOGUP_OK && d == exp_degree[i],
              "[%s] constraint_degree lk=%u: %u != %u (rc=%d)", name, i, d,
              exp_degree[i], rc);
    }

    /* cleanup */
    free(got_aux);
    free(exp_aux);
    free(ch);
    for (uint32_t i = 0; i < nlk; i++) {
        for (uint32_t t = 0; t < lks[i].num_tuples; t++) free(elems[i][t]);
        free(elems[i]);
        free(widths[i]);
        free(mults[i]);
    }
    free(elems);
    free(widths);
    free(mults);
    free(lks);
    free(exp_degree);
    free(pool.nodes);
    free(main_m);
    free(prep_m);
    free(pub_m);
    return 0;
}

/* ============================================================================
 * C-side fail-close negatives (Plonky3 expresses these as panics)
 * ========================================================================== */
static void run_negatives(void)
{
    /* tiny ctx: main 1x1 = [5], pool: [const α_base? no — main0, const c] */
    gold_fp_t main1[1] = { gold_fp_from_u64(5) };
    dnac_logup_expr_t pool[2];
    memset(pool, 0, sizeof(pool));
    pool[0].kind = DNAC_LOGUP_EXPR_MAIN;
    pool[0].index = 0;
    pool[0].x = pool[0].y = -1;
    pool[1].kind = DNAC_LOGUP_EXPR_CONST;
    pool[1].cval = gold_fp_one();
    pool[1].x = pool[1].y = -1;
    dnac_logup_ctx_t ctx = {
        .main = main1, .main_width = 1, .prep = NULL, .prep_width = 0,
        .publics = NULL, .num_publics = 0, .height = 1,
        .pool = pool, .pool_len = 2,
    };
    const uint32_t w1[1] = { 1 };
    const int32_t e0[1] = { 0 };
    const int32_t *const el[1] = { e0 };
    const int32_t m0[1] = { 1 };
    dnac_logup_lookup_t lk = {
        .is_global = 0, .column = 0, .num_tuples = 1,
        .tuple_widths = w1, .tuple_elems = el, .multiplicities = m0,
    };
    gold_fp2_t aux[1];
    gold_fp2_t res[3];
    uint32_t nres;

    /* zero denominator: α = main value 5 (base-embedded) => α − combined = 0
     * (mirror of the batch-inversion panic, batch_inverse.rs:26) */
    gold_fp2_t ch_zero[2] = { gold_fp2_from_base(gold_fp_from_u64(5)),
                              gold_fp2_zero() };
    int rc = dnac_logup_generate_permutation(&ctx, &lk, 1, ch_zero, 2, aux,
                                             NULL, 0);
    CHECK(rc == DNAC_LOGUP_ERR_ZERO_DENOM, "neg: zero denom rc=%d", rc);

    gold_fp2_t ch_ok[4] = { gold_fp2_from_base(gold_fp_from_u64(7)),
                            gold_fp2_from_base(gold_fp_from_u64(3)),
                            gold_fp2_from_base(gold_fp_from_u64(11)),
                            gold_fp2_from_base(gold_fp_from_u64(13)) };

    /* challenge count mismatch (logup.rs:383-387) */
    rc = dnac_logup_generate_permutation(&ctx, &lk, 1, ch_ok, 4, aux, NULL, 0);
    CHECK(rc == DNAC_LOGUP_ERR_PARAM, "neg: challenge count rc=%d", rc);

    /* duplicate aux column (logup.rs:390-401) */
    dnac_logup_lookup_t two[2] = { lk, lk }; /* both column 0 */
    gold_fp2_t aux2[2];
    rc = dnac_logup_generate_permutation(&ctx, two, 2, ch_ok, 4, aux2, NULL, 0);
    CHECK(rc == DNAC_LOGUP_ERR_PARAM, "neg: duplicate column rc=%d", rc);

    /* kind/cumulative_sum mismatch (logup.rs:239-241 / 254-256) */
    gold_fp2_t cum = gold_fp2_zero();
    aux[0] = gold_fp2_zero();
    rc = dnac_logup_eval_row(&ctx, &lk, aux, 1, ch_ok, 2, 0, &cum, res, &nres);
    CHECK(rc == DNAC_LOGUP_ERR_PARAM, "neg: local+cum rc=%d", rc);

    /* sum_terms n == 0 => (0, 1) (logup.rs:113-114) */
    gold_fp2_t nn, dd;
    rc = dnac_logup_sum_terms_fp2(NULL, NULL, NULL, 0, ch_ok[0], ch_ok[1], &nn,
                                  &dd);
    CHECK(rc == DNAC_LOGUP_OK && fp2_eq_limbs(nn, gold_fp2_zero()) &&
              fp2_eq_limbs(dd, gold_fp2_one()),
          "neg: empty sum_terms rc=%d", rc);

    /* verify_global_sum: non-zero flat sum rejects */
    gold_fp2_t sums_bad[1] = { gold_fp2_one() };
    rc = dnac_logup_verify_global_sum(sums_bad, 1);
    CHECK(rc == DNAC_LOGUP_ERR_GLOBAL_SUM, "neg: nonzero global sum rc=%d", rc);
    rc = dnac_logup_verify_global_sum(NULL, 0);
    CHECK(rc == DNAC_LOGUP_OK, "neg: empty global sum rc=%d", rc);
}

/* ============================================================================
 * Main
 * ========================================================================== */
int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "tools/vectors/logup.json";
    size_t len;
    char *buf = load_file(path, &len);
    if (!buf) {
        fprintf(stderr, "FAIL: cannot load %s\n", path);
        return 2;
    }
    printf("loaded %s (%zu bytes)\n", path, len);

    jp_t p = { buf, 0, len };
    jv_t *doc = jp_value(&p);
    if (!doc || doc->kind != JV_OBJ) {
        fprintf(stderr, "FAIL: JSON parse\n");
        free(buf);
        return 2;
    }

    const jv_t *cases = jv_get(doc, "cases");
    if (!cases || cases->kind != JV_ARR) {
        fprintf(stderr, "FAIL: no cases\n");
        jv_free(doc);
        free(buf);
        return 2;
    }
    for (size_t i = 0; i < cases->n; i++) {
        if (run_case(cases->items[i]) == 2) {
            fprintf(stderr, "FAIL: case %zu parse error\n", i);
            jv_free(doc);
            free(buf);
            return 2;
        }
    }
    printf("cases: %zu instances checked\n", cases->n);

    /* ---- 5. cross-instance global checks ---- */
    const jv_t *checks = jv_get(doc, "global_checks");
    if (!checks || checks->kind != JV_ARR) {
        fprintf(stderr, "FAIL: no global_checks\n");
        jv_free(doc);
        free(buf);
        return 2;
    }
    for (size_t i = 0; i < checks->n; i++) {
        const jv_t *gc = checks->items[i];
        const jv_t *gname = jv_get(gc, "name");
        const jv_t *bus = jv_get(gc, "bus_name");
        const jv_t *insts = jv_get(gc, "instances");
        const jv_t *ok = jv_get(gc, "ok");
        if (!gname || !bus || !insts || insts->kind != JV_ARR || !ok ||
            ok->kind != JV_BOOL) {
            jv_free(doc);
            free(buf);
            return 2;
        }
        /* gather this group's sums from the per-instance stash, in the
         * check's instance order (single-bus group => flat sum == the
         * per-bus check; G-DET-L4) */
        gold_fp2_t sums[8];
        uint32_t nsums = 0;
        for (size_t k = 0; k < insts->n; k++) {
            for (size_t c = 0; c < g_ncums; c++) {
                if (!strcmp(g_cums[c].instance, insts->items[k]->str) &&
                    !strcmp(g_cums[c].bus, bus->str) && nsums < 8) {
                    sums[nsums++] = g_cums[c].sum;
                }
            }
        }
        int rc = dnac_logup_verify_global_sum(sums, nsums);
        bool got_ok = (rc == DNAC_LOGUP_OK);
        CHECK(got_ok == ok->bval, "[global %s] verdict %d != %d (n=%u)",
              gname->str, (int)got_ok, (int)ok->bval, nsums);
    }
    printf("global checks: %zu groups checked\n", checks->n);

    /* ---- 6. C-side fail-close negatives ---- */
    run_negatives();

    printf("\n%-32s %5d checks\n", "logup total", g_total);
    printf("%-32s %5d\n", "logup failed", g_failed);
    printf("\nP2L-a LOGUP ORACLE GATE: %s\n", g_failed == 0 ? "GREEN" : "RED");

    jv_free(doc);
    free(buf);
    return g_failed == 0 ? 0 : 1;
}
