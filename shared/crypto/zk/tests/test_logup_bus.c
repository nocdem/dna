/**
 * @file test_logup_bus.c
 * @brief P2L-b — byte-match gate for logup_bus.c vs Plonky3 p3-lookup
 *        builder/bus + batch-stark single-pair challenge derivation /
 *        cross-AIR terminal sum (RE-BASED to v0.6.2 at S2'-c, 2026-07-27).
 *
 * Loads tools/vectors/logup_bus.json and asserts:
 *   1. COLUMN ASSIGNMENT: replaying each instance's push script through the C
 *      builder (push_interaction / push_local_interaction → finalize) yields
 *      exactly the lookups the REAL Lookups::from_air produced (locals first,
 *      then globals, push order; types.rs:59-89) — kind/bus/column/tuple
 *      structure compared as interned expr-pool indices.
 *   2. CHALLENGE DERIVATION: the single (α,β) pair replays byte-identically
 *      on the C DuplexChallenger (init_default → sample_fp2 ×2, binding P2L-b
 *      to the P1a surface), and dnac_logup_bus_derive_challenges reproduces the
 *      REAL BatchTranscript::sample_perm_challenges per-instance arrays
 *      (v0.6.2 transcript.rs:118-155) — including γ = β^W and the derived bus
 *      prefixes, checked separately from the per-instance layout so a failure
 *      localises to derivation vs layout.
 *   3. CROSS-AIR TERMINALS (v0.6.2): C generate_permutation byte-matches each
 *      sum instance's aux + its ONE committed terminal, then
 *      dnac_logup_verify_terminal_sum reproduces every scenario verdict as a
 *      FLAT total. The F3 framing INVERTED at v0.6.2 — the flat total is now
 *      the correct check, because separation moved into the challenge
 *      derivation (prefix[bus] = alpha + (bus+1)*beta^W). Both directions are
 *      still pinned: `cross_bus_cancel` cancels with hand-built colliding
 *      prefixes, `cross_bus_separated` does NOT with the derived prefix.
 *   4. HEIGHT BOUND: C-only unit tests of the offline precondition
 *      Σ weight·height < p (builder.rs:33-38; never enforced in Plonky3, F4)
 *      at exact boundaries (p−1 OK, p FAIL) without overflow.
 * plus builder/assign fail-close negatives.
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
#include "../logup_bus.h"
#include "../duplex_challenger.h"
#include "logup_test_util.h"

static int g_total = 0, g_failed = 0;

/* strdup is POSIX, not C99 — local equivalent. */
static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (out) memcpy(out, s, n);
    return out;
}

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        g_total++;                                                             \
        if (!(cond)) {                                                         \
            g_failed++;                                                        \
            fprintf(stderr, "MISMATCH: " __VA_ARGS__);                         \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

/* ============================================================================
 * 1+2 — assignment case: builder replay + challenge memo
 * ========================================================================== */

/* Map the case's interned expr table into one C pool; table index i maps to
 * pool index map[i]. */
static bool build_expr_table(const jv_t *exprs, pool_t *pool, int32_t **map_out)
{
    int32_t *map = (int32_t *)malloc(sizeof(int32_t) * (exprs->n ? exprs->n : 1));
    if (!map) return false;
    for (size_t i = 0; i < exprs->n; i++) {
        map[i] = build_expr(pool, exprs->items[i]);
        if (map[i] < 0) { free(map); return false; }
    }
    *map_out = map;
    return true;
}

static int run_assignment_case(const jv_t *cs)
{
    const jv_t *jname = jv_get(cs, "name");
    const char *name = (jname && jname->kind == JV_STR) ? jname->str : "?";

    const jv_t *exprs = jv_get(cs, "exprs");
    const jv_t *insts = jv_get(cs, "instances");
    const jv_t *jperinst = jv_get(cs, "per_instance_challenges");
    uint64_t draws_used_exp, mmw;
    gold_fp2_t alpha, beta;
    if (!exprs || exprs->kind != JV_ARR || !insts || insts->kind != JV_ARR ||
        !jperinst || jperinst->kind != JV_ARR || jperinst->n != insts->n ||
        !jv_u64(jv_get(cs, "draws_used_pairs"), &draws_used_exp) ||
        !jv_u64(jv_get(cs, "max_message_width"), &mmw) ||
        !jv_fp2(jv_get(cs, "alpha"), &alpha) ||
        !jv_fp2(jv_get(cs, "beta"), &beta)) {
        fprintf(stderr, "FAIL[%s]: case fields\n", name);
        return 2;
    }
    /* v0.6.2 draws ONE (alpha, beta) pair for the WHOLE batch — "two draws,
     * not two per bus" (transcript.rs:112-115). The per-bus separation that
     * used to cost a draw each now comes from the derivation. Any vector
     * claiming more than one pair would mean the squeeze count regressed. */
    CHECK(draws_used_exp == 1, "[%s] draws_used_pairs %" PRIu64 " != 1", name,
          draws_used_exp);

    pool_t pool = {0};
    int32_t *map = NULL;
    if (!build_expr_table(exprs, &pool, &map)) {
        fprintf(stderr, "FAIL[%s]: expr table\n", name);
        return 2;
    }

    /* --- the single pair, replayed on the C duplex challenger (P1a surface).
     * The oracle sampled from a FRESH production challenger (DS prefix, no
     * observes — full priming order is P2L-c scope): alpha then beta. */
    {
        dnac_duplex_t ch;
        dnac_duplex_init_default(&ch);
        gold_fp2_t ga = dnac_duplex_sample_fp2(&ch);
        gold_fp2_t gb = dnac_duplex_sample_fp2(&ch);
        CHECK(fp2_eq_limbs(ga, alpha), "[%s] duplex alpha replay", name);
        CHECK(fp2_eq_limbs(gb, beta), "[%s] duplex beta replay", name);
    }

    /* --- per instance: replay the push script through the C builder. */
    dnac_logup_lookup_set_t **sets = (dnac_logup_lookup_set_t **)calloc(
        insts->n, sizeof(dnac_logup_lookup_set_t *));
    dnac_logup_bus_view_t *views = (dnac_logup_bus_view_t *)calloc(
        insts->n, sizeof(dnac_logup_bus_view_t));
    if (!sets || !views) return 2;

    for (size_t i = 0; i < insts->n; i++) {
        const jv_t *inst = jv_get(insts->items[i], "push_script");
        const jv_t *expected = jv_get(insts->items[i], "expected_lookups");
        const jv_t *iname_v = jv_get(insts->items[i], "name");
        const char *iname =
            (iname_v && iname_v->kind == JV_STR) ? iname_v->str : "?";
        uint64_t exp_locals, exp_globals;
        if (!inst || inst->kind != JV_ARR || !expected ||
            expected->kind != JV_ARR ||
            !jv_u64(jv_get(insts->items[i], "num_locals"), &exp_locals) ||
            !jv_u64(jv_get(insts->items[i], "num_globals"), &exp_globals)) {
            fprintf(stderr, "FAIL[%s/%s]: instance fields\n", name, iname);
            return 2;
        }

        dnac_logup_builder_t *b = dnac_logup_builder_new();
        if (!b) return 2;
        for (size_t s = 0; s < inst->n; s++) {
            const jv_t *step = inst->items[s];
            const jv_t *type = jv_get(step, "type");
            if (!type || type->kind != JV_STR) return 2;
            if (!strcmp(type->str, "global")) {
                const jv_t *bus = jv_get(step, "bus");
                const jv_t *fields = jv_get(step, "fields");
                uint64_t count_idx, weight;
                if (!bus || bus->kind != JV_STR || !fields ||
                    fields->kind != JV_ARR ||
                    !jv_u64(jv_get(step, "count"), &count_idx) ||
                    !jv_u64(jv_get(step, "weight"), &weight)) {
                    return 2;
                }
                int32_t f[16];
                if (fields->n > 16) return 2;
                for (size_t j = 0; j < fields->n; j++) {
                    uint64_t ti;
                    if (!jv_u64(fields->items[j], &ti) || ti >= exprs->n) return 2;
                    f[j] = map[ti];
                }
                int rc = dnac_logup_push_interaction(
                    b, bus->str, f, (uint32_t)fields->n, map[count_idx],
                    (uint32_t)weight);
                CHECK(rc == DNAC_LOGUP_OK, "[%s/%s] push_interaction rc=%d",
                      name, iname, rc);
            } else if (!strcmp(type->str, "local")) {
                const jv_t *tuples = jv_get(step, "tuples");
                if (!tuples || tuples->kind != JV_ARR || tuples->n > 8) return 2;
                uint32_t tw[8];
                int32_t te_store[8][16];
                const int32_t *te[8];
                int32_t tm[8];
                for (size_t t = 0; t < tuples->n; t++) {
                    const jv_t *els = jv_get(tuples->items[t], "elements");
                    uint64_t mi;
                    if (!els || els->kind != JV_ARR || els->n > 16 ||
                        !jv_u64(jv_get(tuples->items[t], "multiplicity"), &mi)) {
                        return 2;
                    }
                    tw[t] = (uint32_t)els->n;
                    for (size_t j = 0; j < els->n; j++) {
                        uint64_t ti;
                        if (!jv_u64(els->items[j], &ti) || ti >= exprs->n)
                            return 2;
                        te_store[t][j] = map[ti];
                    }
                    te[t] = te_store[t];
                    tm[t] = map[mi];
                }
                int rc = dnac_logup_push_local_interaction(
                    b, tw, te, tm, (uint32_t)tuples->n);
                CHECK(rc == DNAC_LOGUP_OK,
                      "[%s/%s] push_local_interaction rc=%d", name, iname, rc);
            } else {
                return 2;
            }
        }

        int rc = dnac_logup_builder_finalize(b, &sets[i]);
        CHECK(rc == DNAC_LOGUP_OK, "[%s/%s] finalize rc=%d", name, iname, rc);
        dnac_logup_builder_free(b);
        if (rc != DNAC_LOGUP_OK) return 2;
        const dnac_logup_lookup_set_t *set = sets[i];

        CHECK(set->num_locals == exp_locals && set->num_globals == exp_globals,
              "[%s/%s] counts %u/%u != %" PRIu64 "/%" PRIu64, name, iname,
              set->num_locals, set->num_globals, exp_locals, exp_globals);
        CHECK(set->num_lookups == expected->n,
              "[%s/%s] lookup count %u != %zu", name, iname, set->num_lookups,
              expected->n);

        for (size_t l = 0; l < expected->n && l < set->num_lookups; l++) {
            const jv_t *el = expected->items[l];
            const jv_t *kind = jv_get(el, "kind");
            const jv_t *bus = jv_get(el, "bus_name");
            uint64_t col;
            const jv_t *tuples = jv_get(el, "tuples");
            if (!kind || kind->kind != JV_STR || !bus || bus->kind != JV_STR ||
                !jv_u64(jv_get(el, "column"), &col) || !tuples ||
                tuples->kind != JV_ARR) {
                return 2;
            }
            const dnac_logup_lookup_t *lk = &set->lookups[l];
            int want_global = !strcmp(kind->str, "global");
            CHECK(lk->is_global == want_global && lk->column == col,
                  "[%s/%s] lookup %zu kind/column", name, iname, l);
            if (want_global) {
                CHECK(set->bus_names[l] &&
                          !strcmp(set->bus_names[l], bus->str),
                      "[%s/%s] lookup %zu bus '%s'", name, iname, l, bus->str);
            } else {
                CHECK(set->bus_names[l] == NULL,
                      "[%s/%s] lookup %zu local has no bus", name, iname, l);
            }
            CHECK(lk->num_tuples == tuples->n, "[%s/%s] lookup %zu tuples",
                  name, iname, l);
            for (size_t t = 0; t < tuples->n && t < lk->num_tuples; t++) {
                const jv_t *els = jv_get(tuples->items[t], "elements");
                uint64_t mi;
                if (!els || els->kind != JV_ARR ||
                    !jv_u64(jv_get(tuples->items[t], "multiplicity"), &mi)) {
                    return 2;
                }
                CHECK(lk->tuple_widths[t] == els->n,
                      "[%s/%s] lookup %zu tuple %zu width", name, iname, l, t);
                for (size_t j = 0; j < els->n && j < lk->tuple_widths[t]; j++) {
                    uint64_t ti;
                    if (!jv_u64(els->items[j], &ti)) return 2;
                    CHECK(lk->tuple_elems[t][j] == map[ti],
                          "[%s/%s] lookup %zu tuple %zu elem %zu expr", name,
                          iname, l, t, j);
                }
                CHECK(lk->multiplicities[t] == map[mi],
                      "[%s/%s] lookup %zu tuple %zu mult expr", name, iname, l,
                      t);
            }
        }
        views[i] = set->view;
    }

    /* --- challenge assignment vs the REAL sample_perm_challenges dump. */
    gold_fp2_t *outs[8];
    memset(outs, 0, sizeof(outs));
    if (insts->n > 8) return 2;
    for (size_t i = 0; i < insts->n; i++) {
        uint32_t n = views[i].num_locals + views[i].num_globals;
        outs[i] = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * 2u * (n ? n : 1));
        if (!outs[i]) return 2;
    }
    uint32_t nbuses = 0;
    int rc = dnac_logup_bus_derive_challenges(
        views, (uint32_t)insts->n, alpha, beta, (uint32_t)mmw,
        (gold_fp2_t *const *)outs, &nbuses);
    CHECK(rc == DNAC_LOGUP_OK, "[%s] derive_challenges rc=%d", name, rc);

    /* The derived bus prefixes themselves — prefix[i] = alpha + (i+1)*gamma,
     * gamma = beta^W (challenges.rs:56-66). Checking these separately from
     * the per-instance layout localises a failure to derivation vs layout. */
    const jv_t *jpref = jv_get(cs, "bus_prefixes");
    if (jpref && jpref->kind == JV_ARR) {
        CHECK(jpref->n == nbuses, "[%s] bus count %zu != %u", name, jpref->n,
              nbuses);
        gold_fp2_t gamma = gold_fp2_one();
        for (uint64_t e = 0; e < mmw; e++) gamma = gold_fp2_mul(gamma, beta);
        gold_fp2_t egamma;
        if (jv_fp2(jv_get(cs, "gamma"), &egamma)) {
            CHECK(fp2_eq_limbs(gamma, egamma), "[%s] gamma = beta^W", name);
        }
        gold_fp2_t run = alpha;
        for (size_t b = 0; b < jpref->n; b++) {
            gold_fp2_t ep;
            run = gold_fp2_add(run, gamma);
            if (!jv_fp2(jpref->items[b], &ep)) return 2;
            CHECK(fp2_eq_limbs(run, ep), "[%s] bus_prefix[%zu]", name, b);
        }
    }
    for (size_t i = 0; i < insts->n; i++) {
        const jv_t *exp = jperinst->items[i];
        uint32_t n = 2u * (views[i].num_locals + views[i].num_globals);
        if (!exp || exp->kind != JV_ARR || exp->n != n) {
            fprintf(stderr, "FAIL[%s]: per-instance challenge shape\n", name);
            return 2;
        }
        for (uint32_t k = 0; k < n; k++) {
            gold_fp2_t e;
            if (!jv_fp2(exp->items[k], &e)) return 2;
            CHECK(fp2_eq_limbs(outs[i][k], e),
                  "[%s] instance %zu challenge %u", name, i, k);
        }
    }

    for (size_t i = 0; i < insts->n; i++) {
        free(outs[i]);
        dnac_logup_lookup_set_free(sets[i]);
    }
    free(sets);
    free(views);
    free(map);
    free(pool.nodes);
    return 0;
}

/* ============================================================================
 * 3 — sum instances + scenarios
 * ========================================================================== */

typedef struct {
    char *name;
    uint32_t num_locals, num_globals;
    char **global_bus_names;   /* [num_globals] owned */
    gold_fp2_t terminal;       /* the AIR's ONE terminal, byte-matched */
    int        has_terminal;   /* the Option discriminant */
    dnac_logup_bus_view_t view;
} sum_inst_t;

static sum_inst_t g_insts[16];
static size_t g_ninsts = 0;

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

/* Parse one sum instance (dump_logup case schema), run the C
 * generate_permutation, byte-match aux + cumulative sums, and stash the bus
 * view + sums for the scenario checks. */
static int run_sum_instance(const jv_t *cs)
{
    const jv_t *jname = jv_get(cs, "name");
    const char *name = (jname && jname->kind == JV_STR) ? jname->str : "?";

    uint64_t height64, num_aux64;
    if (!jv_u64(jv_get(cs, "height"), &height64) ||
        !jv_u64(jv_get(cs, "num_aux_cols"), &num_aux64)) {
        return 2;
    }
    const uint32_t height = (uint32_t)height64;
    /* num_aux_cols is the aux WIDTH = num_lookups + 1 at v0.6.2 (col 0 is the
     * shared accumulator, logup.rs:381-382); it equalled the lookup count at
     * 82cfad73. */
    if (num_aux64 == 0) return 2;
    const uint32_t nlk = (uint32_t)num_aux64 - 1u;

    uint32_t mh, mw;
    gold_fp_t *main_m = NULL;
    if (!parse_fp_matrix(jv_get(cs, "main"), &mh, &mw, &main_m) || mh != height) {
        return 2;
    }

    const jv_t *jlookups = jv_get(cs, "lookups");
    if (!jlookups || jlookups->kind != JV_ARR || jlookups->n != nlk) return 2;

    pool_t pool = {0};
    dnac_logup_lookup_t *lks =
        (dnac_logup_lookup_t *)calloc(nlk, sizeof(dnac_logup_lookup_t));
    uint32_t **widths = (uint32_t **)calloc(nlk, sizeof(uint32_t *));
    int32_t ***elems = (int32_t ***)calloc(nlk, sizeof(int32_t **));
    int32_t **mults = (int32_t **)calloc(nlk, sizeof(int32_t *));
    char **busnames = (char **)calloc(nlk ? nlk : 1, sizeof(char *));
    if (!lks || !widths || !elems || !mults || !busnames) return 2;

    uint32_t num_locals = 0, num_globals = 0;
    for (uint32_t i = 0; i < nlk; i++) {
        const jv_t *lk = jlookups->items[i];
        const jv_t *kind = jv_get(lk, "kind");
        const jv_t *bus = jv_get(lk, "bus_name");
        uint64_t col;
        if (!kind || kind->kind != JV_STR || !bus || bus->kind != JV_STR ||
            !jv_u64(jv_get(lk, "column"), &col)) {
            return 2;
        }
        lks[i].is_global = !strcmp(kind->str, "global");
        lks[i].column = (uint32_t)col;
        if (lks[i].is_global) {
            busnames[num_globals] = xstrdup(bus->str);
            if (!busnames[num_globals]) return 2;
            num_globals++;
        } else {
            num_locals++;
        }

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
                if (idx < 0) return 2;
                elems[i][t][j] = idx;
            }
            int32_t midx = build_expr(&pool, jv_get(tp, "multiplicity"));
            if (midx < 0) return 2;
            mults[i][t] = midx;
        }
        lks[i].tuple_widths = widths[i];
        lks[i].tuple_elems = (const int32_t *const *)elems[i];
        lks[i].multiplicities = mults[i];
    }

    dnac_logup_ctx_t ctx = {
        .main = main_m,
        .main_width = mw,
        .prep = NULL,
        .prep_width = 0,
        .publics = NULL,
        .num_publics = 0,
        .height = height,
        .pool = pool.nodes,
        .pool_len = pool.len,
    };

    const jv_t *jch = jv_get(cs, "challenges");
    if (!jch || jch->kind != JV_ARR || jch->n != 2u * nlk) return 2;
    gold_fp2_t *chal = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * jch->n);
    if (!chal) return 2;
    for (size_t i = 0; i < jch->n; i++) {
        if (!jv_fp2(jch->items[i], &chal[i])) return 2;
    }

    /* generate + byte-match aux and the AIR's single terminal. aux is now
     * [height][num_lookups + 1]: col 0 the shared accumulator, lookup slot c
     * owning fraction column c + 1 (logup.rs:381-382). */
    const uint32_t auxw = nlk + 1u;
    const jv_t *jaux = jv_get(cs, "aux");
    const jv_t *jterm = jv_get(cs, "terminal");
    uint64_t nac;
    if (!jaux || jaux->kind != JV_ARR || jaux->n != height ||
        !jv_u64(jv_get(cs, "num_aux_cols"), &nac) || (uint32_t)nac != auxw) {
        return 2;
    }
    const int has_term = (jterm && jterm->kind != JV_NULL);
    gold_fp2_t exp_term = gold_fp2_zero();
    if (has_term && !jv_fp2(jterm, &exp_term)) return 2;
    if (has_term != (nlk > 0)) return 2;

    gold_fp2_t *aux =
        (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * (size_t)height * auxw);
    gold_fp2_t term = gold_fp2_zero();
    if (!aux) return 2;
    int rc = dnac_logup_generate_permutation(&ctx, lks, nlk, chal, 2u * nlk,
                                             aux, &term);
    CHECK(rc == DNAC_LOGUP_OK, "[%s] generate rc=%d", name, rc);
    if (rc == DNAC_LOGUP_OK) {
        uint32_t diff = 0;
        for (uint32_t r = 0; r < height; r++) {
            const jv_t *row = jaux->items[r];
            if (row->kind != JV_ARR || row->n != auxw) return 2;
            for (uint32_t c = 0; c < auxw; c++) {
                gold_fp2_t e;
                if (!jv_fp2(row->items[c], &e)) return 2;
                if (!fp2_eq_limbs(aux[(size_t)r * auxw + c], e)) diff++;
            }
        }
        CHECK(diff == 0, "[%s] aux diff=%u", name, diff);
        CHECK(fp2_eq_limbs(term, exp_term), "[%s] terminal", name);
    }

    /* stash for the scenarios */
    if (g_ninsts >= 16) return 2;
    sum_inst_t *si = &g_insts[g_ninsts++];
    memset(si, 0, sizeof(*si));
    si->name = xstrdup(name);
    si->num_locals = num_locals;
    si->num_globals = num_globals;
    si->global_bus_names = busnames;
    if (!si->name) return 2;
    si->terminal = term;
    si->has_terminal = has_term;
    si->view.num_locals = num_locals;
    si->view.num_globals = num_globals;
    si->view.global_bus_names = (const char *const *)busnames;
    si->view.global_count_weights = NULL;

    /* cleanup (busnames ownership moved to the stash) */
    free(aux);
    free(chal);
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
    free(pool.nodes);
    free(main_m);
    return 0;
}

static const sum_inst_t *find_inst(const char *name)
{
    for (size_t i = 0; i < g_ninsts; i++) {
        if (!strcmp(g_insts[i].name, name)) return &g_insts[i];
    }
    return NULL;
}

static int run_scenario(const jv_t *sc)
{
    const jv_t *jname = jv_get(sc, "name");
    const char *name = (jname && jname->kind == JV_STR) ? jname->str : "?";
    const jv_t *insts = jv_get(sc, "instances");
    const jv_t *jterms = jv_get(sc, "terminals");
    const jv_t *flat_zero = jv_get(sc, "flat_zero");
    const jv_t *jok = jv_get(sc, "verify_terminal_sum_ok");
    const jv_t *jtotal = jv_get(sc, "flat_total");
    if (!insts || insts->kind != JV_ARR || insts->n > 8 || !jterms ||
        jterms->kind != JV_ARR || jterms->n != insts->n || !flat_zero ||
        flat_zero->kind != JV_BOOL || !jok || jok->kind != JV_BOOL) {
        return 2;
    }

    /* Gather each named AIR's ONE terminal. The v3-era per-bus grouping is
     * gone: bus_checks / expect_fail_bus no longer drive a verdict, because
     * there are no per-(bus, column) sums left to group. */
    gold_fp2_t terms[8];
    uint32_t nterms = 0;
    for (size_t i = 0; i < insts->n; i++) {
        const sum_inst_t *si = find_inst(insts->items[i]->str);
        if (!si) {
            fprintf(stderr, "FAIL[%s]: unknown instance %s\n", name,
                    insts->items[i]->str);
            return 2;
        }
        /* the dumped terminal must equal the one the C gadget produced */
        const jv_t *jt = jterms->items[i];
        const int exp_has = (jt && jt->kind != JV_NULL);
        CHECK(exp_has == si->has_terminal, "[%s] %s terminal presence", name,
              si->name);
        if (exp_has && si->has_terminal) {
            gold_fp2_t et;
            if (!jv_fp2(jt, &et)) return 2;
            CHECK(fp2_eq_limbs(si->terminal, et), "[%s] %s terminal value",
                  name, si->name);
        }
        if (si->has_terminal && nterms < 8) terms[nterms++] = si->terminal;
    }

    /* The cross-AIR check IS the flat total now (logup.rs:304-320). */
    gold_fp2_t total = gold_fp2_zero();
    for (uint32_t k = 0; k < nterms; k++)
        total = gold_fp2_add(total, terms[k]);
    gold_fp2_t exp_total;
    if (jv_fp2(jtotal, &exp_total)) {
        CHECK(fp2_eq_limbs(total, exp_total), "[%s] flat total value", name);
    }
    CHECK(fp2_eq_limbs(total, gold_fp2_zero()) == (flat_zero->bval != 0),
          "[%s] flat total zero-ness", name);

    int rc = dnac_logup_verify_terminal_sum(terms, nterms);
    CHECK((rc == DNAC_LOGUP_OK) == (jok->bval != 0),
          "[%s] verify_terminal_sum verdict rc=%d (want ok=%d)", name, rc,
          (int)jok->bval);

    /* THE F3 TRAP, re-expressed. Under the v3 scheme cross_bus_cancel was the
     * case where a FLAT total was zero while a per-bus group failed — which is
     * why the flat sum was forbidden. At v0.6.2 the flat sum is the only check,
     * and it is sound because separation moved into the challenge derivation.
     * The vector keeps BOTH halves of the trap so that property is pinned, not
     * assumed: `cross_bus_cancel` builds the colliding prefixes by hand and
     * still cancels (flat zero, accepted), while `cross_bus_separated` uses the
     * DERIVED prefix alpha + (i+1)*beta^W for the same multiset and no longer
     * cancels (non-zero, rejected). If derivation ever stopped separating
     * buses, the second case would start passing. */
    return 0;
}

/* ============================================================================
 * 4+5 — height-bound boundaries + fail-close negatives (C-only)
 * ========================================================================== */
static void run_units(void)
{
    /* height bound: Σ = (2^32-1)^2 + 1·(2^32-1) = p-1 → OK;
     * +1·1 more → Σ = p → FAIL (builder.rs:33-38 contract, exact boundary,
     * no wraparound: every u32·u32 product fits u64 and the accumulator
     * fail-closes at p). */
    static const char *busA = "hb";
    const char *names3[3] = { busA, busA, busA };
    uint32_t weights3[3] = { 0xFFFFFFFFu, 1u, 1u };
    dnac_logup_bus_view_t v_ok = {
        .num_locals = 0,
        .num_globals = 2,
        .global_bus_names = names3,
        .global_count_weights = weights3,
    };
    uint32_t h_max[1] = { 0xFFFFFFFFu };
    int rc = dnac_logup_bus_check_height_bound(&v_ok, h_max, 1);
    CHECK(rc == DNAC_LOGUP_OK, "height bound p-1 rc=%d", rc);

    /* Σ = (2^32-1)^2 + (2^32-1) + (2^32-1) = p-1 + (2^32-1) > p → FAIL */
    dnac_logup_bus_view_t v_bad = v_ok;
    v_bad.num_globals = 3;
    rc = dnac_logup_bus_check_height_bound(&v_bad, h_max, 1);
    CHECK(rc == DNAC_LOGUP_ERR_HEIGHT_BOUND, "height bound >p rc=%d", rc);

    /* exact Σ == p: (2^32-1)^2 + (2^32-1) [=p-1] then +1·1 with height 1 */
    const char *names2[2] = { busA, busA };
    uint32_t w_a[2] = { 0xFFFFFFFFu, 1u };
    uint32_t w_b[1] = { 1u };
    dnac_logup_bus_view_t v2[2] = {
        { .num_locals = 0, .num_globals = 2,
          .global_bus_names = names2, .global_count_weights = w_a },
        { .num_locals = 0, .num_globals = 1,
          .global_bus_names = names2, .global_count_weights = w_b },
    };
    uint32_t h2[2] = { 0xFFFFFFFFu, 1u };
    rc = dnac_logup_bus_check_height_bound(v2, h2, 2);
    CHECK(rc == DNAC_LOGUP_ERR_HEIGHT_BOUND, "height bound ==p rc=%d", rc);

    /* weight 0 contributes nothing regardless of height */
    uint32_t w_zero[1] = { 0u };
    dnac_logup_bus_view_t v0 = {
        .num_locals = 0, .num_globals = 1,
        .global_bus_names = names2, .global_count_weights = w_zero,
    };
    rc = dnac_logup_bus_check_height_bound(&v0, h_max, 1);
    CHECK(rc == DNAC_LOGUP_OK, "height bound weight0 rc=%d", rc);

    /* assign: draw exhaustion fail-closes */
    const char *nb[1] = { "solo" };
    dnac_logup_bus_view_t v1 = {
        .num_locals = 1, .num_globals = 1,
        .global_bus_names = nb, .global_count_weights = NULL,
    };
    gold_fp2_t out4[4];
    gold_fp2_t *outp[1] = { out4 };
    uint32_t nb_out = 0;
    /* W == 0 is rejected: the bus offset would land on beta^0 and collide
     * with the payload terms (challenges.rs:51-54). This REPLACES the old
     * "draw pool exhausted" negative — there is no pool to exhaust now, one
     * pair covers the whole batch. */
    rc = dnac_logup_bus_derive_challenges(&v1, 1, gold_fp2_one(),
                                          gold_fp2_one(), 0,
                                          (gold_fp2_t *const *)outp, &nb_out);
    CHECK(rc == DNAC_LOGUP_ERR_PARAM, "derive W=0 rc=%d", rc);

    /* W >= 1 succeeds and assigns one bus id per lookup here (1 local + 1
     * global, both first occurrences). */
    rc = dnac_logup_bus_derive_challenges(&v1, 1, gold_fp2_one(),
                                          gold_fp2_one(), 1,
                                          (gold_fp2_t *const *)outp, &nb_out);
    CHECK(rc == DNAC_LOGUP_OK && nb_out == 2, "derive W=1 rc=%d nbuses=%u", rc,
          nb_out);

    /* builder negatives */
    rc = dnac_logup_push_interaction(NULL, "x", NULL, 0, 0, 1);
    CHECK(rc == DNAC_LOGUP_ERR_NULL, "push NULL builder rc=%d", rc);
    dnac_logup_builder_t *b = dnac_logup_builder_new();
    CHECK(b != NULL, "builder_new");
    if (b) {
        rc = dnac_logup_push_interaction(b, NULL, NULL, 0, 0, 1);
        CHECK(rc == DNAC_LOGUP_ERR_NULL, "push NULL bus rc=%d", rc);
        /* empty builder finalizes to an empty set */
        dnac_logup_lookup_set_t *s = NULL;
        rc = dnac_logup_builder_finalize(b, &s);
        CHECK(rc == DNAC_LOGUP_OK && s && s->num_lookups == 0,
              "empty finalize rc=%d", rc);
        dnac_logup_lookup_set_free(s);
        dnac_logup_builder_free(b);
    }
}

/* ============================================================================
 * Main
 * ========================================================================== */
int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "tools/vectors/logup_bus.json";
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

    const jv_t *acases = jv_get(doc, "assignment_cases");
    const jv_t *sinsts = jv_get(doc, "sum_instances");
    const jv_t *scens = jv_get(doc, "scenarios");
    if (!acases || acases->kind != JV_ARR || !sinsts ||
        sinsts->kind != JV_ARR || !scens || scens->kind != JV_ARR) {
        fprintf(stderr, "FAIL: top-level sections\n");
        jv_free(doc);
        free(buf);
        return 2;
    }

    for (size_t i = 0; i < acases->n; i++) {
        if (run_assignment_case(acases->items[i]) == 2) {
            fprintf(stderr, "FAIL: assignment case %zu parse error\n", i);
            jv_free(doc);
            free(buf);
            return 2;
        }
    }
    printf("assignment cases: %zu checked\n", acases->n);

    for (size_t i = 0; i < sinsts->n; i++) {
        if (run_sum_instance(sinsts->items[i]) == 2) {
            fprintf(stderr, "FAIL: sum instance %zu parse error\n", i);
            jv_free(doc);
            free(buf);
            return 2;
        }
    }
    printf("sum instances: %zu checked\n", sinsts->n);

    for (size_t i = 0; i < scens->n; i++) {
        if (run_scenario(scens->items[i]) == 2) {
            fprintf(stderr, "FAIL: scenario %zu parse error\n", i);
            jv_free(doc);
            free(buf);
            return 2;
        }
    }
    printf("scenarios: %zu checked\n", scens->n);

    run_units();

    printf("\n%-32s %5d checks\n", "logup_bus total", g_total);
    printf("%-32s %5d\n", "logup_bus failed", g_failed);
    printf("\nP2L-b LOGUP BUS GATE: %s\n", g_failed == 0 ? "GREEN" : "RED");

    for (size_t i = 0; i < g_ninsts; i++) {
        for (uint32_t g = 0; g < g_insts[i].num_globals; g++) {
            free(g_insts[i].global_bus_names[g]);
        }
        free(g_insts[i].global_bus_names);
        free(g_insts[i].name);
    }
    jv_free(doc);
    free(buf);
    return g_failed == 0 ? 0 : 1;
}
