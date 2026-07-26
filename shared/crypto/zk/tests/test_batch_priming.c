/**
 * @file test_batch_priming.c
 * @brief P2L-c — byte-match gate for batch_priming.c vs Plonky3 batch-stark.
 *
 * Loads tools/vectors/batch_priming.json (4 scenarios, every one gated on a
 * REAL prove_batch + verify_batch == Ok in the oracle) and asserts:
 *   1. MILESTONES: replaying the phase primitives on the C DuplexChallenger
 *      (init_default) reproduces the dumped duplex state after EVERY phase of
 *      the verifier-order transcript (verifier/mod.rs:143-300) — instance
 *      count/bindings, main+publics, preprocessed (AFTER main — the F2/N3
 *      delta vs v3), perm challenges, perm+cums+alpha, quotient, random, ζ.
 *   2. CHALLENGES: per-instance (α,β) arrays (memo semantics), constraint
 *      alpha and ζ byte-match the REAL BatchTranscript outputs.
 *   3. COMPOSED: dnac_batch_priming_run on a fresh duplex reproduces the
 *      same outputs end-to-end.
 *   4. SHAPE: dnac_batch_proof_shape_check accepts every dumped (verified)
 *      proof shape and rejects single-field mutations (chunk dim, trace
 *      widths, perm lens, random-vs-ZK, lookup metadata).
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
#include "../batch_priming.h"
#include "logup_test_util.h"

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

static char *xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *out = (char *)malloc(n);
    if (out) memcpy(out, s, n);
    return out;
}

/* 64-hex-char commitment -> 4 Goldilocks lanes (LE u64 per 8 bytes). */
static bool parse_commit(const jv_t *v, gold_fp_t out[4])
{
    if (!v || v->kind != JV_STR || strlen(v->str) != 64) return false;
    for (int lane = 0; lane < 4; lane++) {
        uint64_t x = 0;
        for (int b = 7; b >= 0; b--) { /* LE bytes -> u64 */
            char hi = v->str[lane * 16 + b * 2];
            char lo = v->str[lane * 16 + b * 2 + 1];
            int h = (hi >= 'a') ? hi - 'a' + 10 : hi - '0';
            int l = (lo >= 'a') ? lo - 'a' + 10 : lo - '0';
            if (h < 0 || h > 15 || l < 0 || l > 15) return false;
            x = (x << 8) | (uint64_t)((h << 4) | l);
        }
        out[lane] = gold_fp_from_u64(x);
    }
    return true;
}

/* Compare the C duplex state to a dumped milestone state. */
static void check_milestone(const char *scen, const char *label,
                            const dnac_duplex_t *ch, const jv_t *state)
{
    const jv_t *sponge = jv_get(state, "sponge_state");
    const jv_t *inb = jv_get(state, "input_buffer");
    const jv_t *outb = jv_get(state, "output_buffer");
    if (!sponge || sponge->kind != JV_ARR || sponge->n != 8 || !inb ||
        inb->kind != JV_ARR || !outb || outb->kind != JV_ARR) {
        CHECK(false, "[%s/%s] milestone fields", scen, label);
        return;
    }
    for (size_t i = 0; i < 8; i++) {
        uint64_t e;
        if (!jv_u64(sponge->items[i], &e)) {
            CHECK(false, "[%s/%s] sponge parse", scen, label);
            return;
        }
        CHECK(ch->sponge_state[i] == e,
              "[%s/%s] sponge[%zu] %" PRIu64 " != %" PRIu64, scen, label, i,
              ch->sponge_state[i], e);
    }
    CHECK(ch->input_len == inb->n, "[%s/%s] input_len %zu != %zu", scen, label,
          ch->input_len, inb->n);
    for (size_t i = 0; i < inb->n && i < ch->input_len; i++) {
        uint64_t e;
        if (!jv_u64(inb->items[i], &e)) return;
        CHECK(ch->input_buffer[i] == e, "[%s/%s] input[%zu]", scen, label, i);
    }
    CHECK(ch->output_len == outb->n, "[%s/%s] output_len %zu != %zu", scen,
          label, ch->output_len, outb->n);
    for (size_t i = 0; i < outb->n && i < ch->output_len; i++) {
        uint64_t e;
        if (!jv_u64(outb->items[i], &e)) return;
        CHECK(ch->output_buffer[i] == e, "[%s/%s] output[%zu]", scen, label, i);
    }
}

/* Per-scenario parsed data (fixed small caps — 2 instances per scenario). */
typedef struct {
    uint32_t n;
    int is_zk;
    dnac_batch_binding_t bindings[4];
    gold_fp_t *publics[4];
    uint32_t num_publics[4];
    uint32_t prep_widths[4];
    dnac_logup_bus_view_t views[4];
    char *bus_names_store[4][8];
    const char *bus_names[4][8];
    gold_fp2_t cums_store[4][8];
    const gold_fp2_t *cums[4];
    dnac_batch_instance_shape_t shapes[4];
    uint32_t entry_cols[4][8];
    gold_fp2_t *exp_challenges[4];
    uint32_t exp_num_chal[4]; /* fp2 count */
    gold_fp_t commits[5][4];  /* main, prep, perm, quotient, random */
    int has_commit[5];
    gold_fp2_t exp_alpha, exp_zeta;
} scen_t;

static void scen_free(scen_t *sc)
{
    for (uint32_t i = 0; i < sc->n; i++) {
        free(sc->publics[i]);
        free(sc->exp_challenges[i]);
        for (int b = 0; b < 8; b++) free(sc->bus_names_store[i][b]);
    }
}

static int parse_scenario(const jv_t *s, scen_t *sc, const char *name)
{
    memset(sc, 0, sizeof(*sc));
    uint64_t n64, zk64 = 0;
    const jv_t *jzk = jv_get(s, "is_zk");
    if (!jv_u64(jv_get(s, "num_instances"), &n64) || n64 > 4 ||
        !(jzk && (jzk->kind == JV_BOOL || jv_u64(jzk, &zk64)))) {
        return 2;
    }
    sc->n = (uint32_t)n64;
    sc->is_zk = (jzk->kind == JV_BOOL) ? (int)jzk->bval : (int)zk64;

    const jv_t *insts = jv_get(s, "instances");
    if (!insts || insts->kind != JV_ARR || insts->n != sc->n) return 2;
    for (uint32_t i = 0; i < sc->n; i++) {
        const jv_t *in = insts->items[i];
        uint64_t led, ld, w, qc, pw, tl, tn, pl, pn, qd, perml, permn, rnd;
        if (!jv_u64(jv_get(in, "log_ext_degree"), &led) ||
            !jv_u64(jv_get(in, "log_degree"), &ld) ||
            !jv_u64(jv_get(in, "width"), &w) ||
            !jv_u64(jv_get(in, "num_quotient_chunks"), &qc) ||
            !jv_u64(jv_get(in, "preprocessed_width"), &pw) ||
            !jv_u64(jv_get(in, "trace_local_len"), &tl) ||
            !jv_u64(jv_get(in, "trace_next_len"), &tn) ||
            !jv_u64(jv_get(in, "preprocessed_local_len"), &pl) ||
            !jv_u64(jv_get(in, "preprocessed_next_len"), &pn) ||
            !jv_u64(jv_get(in, "quotient_chunk_dim"), &qd) ||
            !jv_u64(jv_get(in, "permutation_local_len"), &perml) ||
            !jv_u64(jv_get(in, "permutation_next_len"), &permn) ||
            !jv_u64(jv_get(in, "random_len"), &rnd)) {
            return 2;
        }
        sc->bindings[i].log_ext_degree = (uint32_t)led;
        sc->bindings[i].log_degree = (uint32_t)ld;
        sc->bindings[i].width = (uint32_t)w;
        sc->bindings[i].num_quotient_chunks = (uint32_t)qc;
        sc->prep_widths[i] = (uint32_t)pw;

        const jv_t *pubs = jv_get(in, "public_values");
        if (!pubs || pubs->kind != JV_ARR) return 2;
        sc->num_publics[i] = (uint32_t)pubs->n;
        sc->publics[i] =
            (gold_fp_t *)malloc(sizeof(gold_fp_t) * (pubs->n ? pubs->n : 1));
        if (!sc->publics[i]) return 2;
        for (size_t j = 0; j < pubs->n; j++) {
            uint64_t v;
            if (!jv_u64(pubs->items[j], &v)) return 2;
            sc->publics[i][j] = gold_fp_from_u64(v);
        }

        uint64_t nlocals;
        const jv_t *buses = jv_get(in, "global_buses");
        const jv_t *mnu = jv_get(in, "main_next_used");
        const jv_t *pnu = jv_get(in, "prep_next_used");
        if (!jv_u64(jv_get(in, "num_locals"), &nlocals) || !buses ||
            buses->kind != JV_ARR || buses->n > 8 || !mnu ||
            mnu->kind != JV_BOOL || !pnu || pnu->kind != JV_BOOL) {
            return 2;
        }
        sc->views[i].num_locals = (uint32_t)nlocals;
        sc->views[i].num_globals = (uint32_t)buses->n;
        for (size_t b = 0; b < buses->n; b++) {
            if (buses->items[b]->kind != JV_STR) return 2;
            sc->bus_names_store[i][b] = xstrdup(buses->items[b]->str);
            if (!sc->bus_names_store[i][b]) return 2;
            sc->bus_names[i][b] = sc->bus_names_store[i][b];
        }
        sc->views[i].global_bus_names = sc->bus_names[i];
        sc->views[i].global_count_weights = NULL;

        const jv_t *cums = jv_get(in, "cumulative_sums");
        if (!cums || cums->kind != JV_ARR || cums->n != buses->n || cums->n > 8)
            return 2;
        for (size_t g = 0; g < cums->n; g++) {
            uint64_t col;
            if (!jv_fp2(jv_get(cums->items[g], "sum"), &sc->cums_store[i][g]) ||
                !jv_u64(jv_get(cums->items[g], "aux_column"), &col)) {
                return 2;
            }
            sc->entry_cols[i][g] = (uint32_t)col;
        }
        sc->cums[i] = buses->n ? sc->cums_store[i] : NULL;

        /* shape record (entry names reuse the view's bus-name strings —
         * the dumped metadata was already verified equal by the oracle's
         * verify_batch gate) */
        dnac_batch_instance_shape_t *sh = &sc->shapes[i];
        sh->trace_local_len = (uint32_t)tl;
        sh->trace_next_len = (uint32_t)tn;
        sh->preprocessed_local_len = (uint32_t)pl;
        sh->preprocessed_next_len = (uint32_t)pn;
        sh->num_quotient_chunks = (uint32_t)qc;
        sh->quotient_chunk_dim = (uint32_t)qd;
        sh->permutation_local_len = (uint32_t)perml;
        sh->permutation_next_len = (uint32_t)permn;
        sh->random_len = (uint32_t)rnd;
        sh->num_global_entries = (uint32_t)buses->n;
        sh->entry_names = sc->bus_names[i];
        sh->entry_aux_columns = sc->entry_cols[i];
        sh->main_next_used = mnu->bval ? 1 : 0;
        sh->prep_next_used = pnu->bval ? 1 : 0;

        const jv_t *chal = jv_get(in, "perm_challenges");
        if (!chal || chal->kind != JV_ARR) return 2;
        sc->exp_num_chal[i] = (uint32_t)chal->n;
        sc->exp_challenges[i] =
            (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * (chal->n ? chal->n : 1));
        if (!sc->exp_challenges[i]) return 2;
        for (size_t k = 0; k < chal->n; k++) {
            if (!jv_fp2(chal->items[k], &sc->exp_challenges[i][k])) return 2;
        }
        if (sc->exp_num_chal[i] !=
            2u * (sc->views[i].num_locals + sc->views[i].num_globals)) {
            fprintf(stderr, "FAIL[%s]: challenge count vs view\n", name);
            return 2;
        }
    }

    const jv_t *commits = jv_get(s, "commits");
    static const char *keys[5] = { "main", "preprocessed", "permutation",
                                   "quotient", "random" };
    for (int k = 0; k < 5; k++) {
        const jv_t *c = jv_get(commits, keys[k]);
        if (c && c->kind == JV_STR) {
            if (!parse_commit(c, sc->commits[k])) return 2;
            sc->has_commit[k] = 1;
        }
    }
    if (!sc->has_commit[0] || !sc->has_commit[3]) return 2;

    if (!jv_fp2(jv_get(s, "alpha"), &sc->exp_alpha) ||
        !jv_fp2(jv_get(s, "zeta"), &sc->exp_zeta)) {
        return 2;
    }
    return 0;
}

static int run_scenario(const jv_t *s)
{
    const jv_t *jname = jv_get(s, "name");
    const char *name = (jname && jname->kind == JV_STR) ? jname->str : "?";
    scen_t sc;
    if (parse_scenario(s, &sc, name) != 0) {
        fprintf(stderr, "FAIL[%s]: scenario parse\n", name);
        return 2;
    }
    const jv_t *miles = jv_get(s, "milestones");
    if (!miles || miles->kind != JV_ARR || miles->n != 9) {
        scen_free(&sc);
        return 2;
    }
    const jv_t *mstate[9];
    for (size_t m = 0; m < 9; m++) {
        mstate[m] = jv_get(miles->items[m], "state");
        if (!mstate[m]) {
            scen_free(&sc);
            return 2;
        }
    }

    /* challenge out buffers */
    gold_fp2_t *outs[4] = { NULL, NULL, NULL, NULL };
    for (uint32_t i = 0; i < sc.n; i++) {
        uint32_t cnt = 2u * (sc.views[i].num_locals + sc.views[i].num_globals);
        if (cnt) {
            outs[i] = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * cnt);
            if (!outs[i]) {
                scen_free(&sc);
                return 2;
            }
        }
    }

    /* ---- 1+2: phase-by-phase replay with milestone checks ---- */
    dnac_duplex_t ch;
    dnac_duplex_init_default(&ch);
    check_milestone(name, "initial", &ch, mstate[0]);

    int rc = dnac_batch_observe_count_and_bindings(&ch, sc.bindings, sc.n);
    CHECK(rc == DNAC_BATCH_OK, "[%s] bindings rc=%d", name, rc);
    check_milestone(name, "after_count_bindings", &ch, mstate[1]);

    rc = dnac_batch_observe_main(&ch, sc.commits[0],
                                 (const gold_fp_t *const *)sc.publics,
                                 sc.num_publics, sc.n);
    CHECK(rc == DNAC_BATCH_OK, "[%s] main rc=%d", name, rc);
    check_milestone(name, "after_main_publics", &ch, mstate[2]);

    rc = dnac_batch_observe_preprocessed(
        &ch, sc.prep_widths, sc.n,
        sc.has_commit[1] ? sc.commits[1] : NULL);
    CHECK(rc == DNAC_BATCH_OK, "[%s] preprocessed rc=%d", name, rc);
    check_milestone(name, "after_preprocessed", &ch, mstate[3]);

    rc = dnac_batch_sample_perm_challenges(&ch, sc.views, sc.n,
                                           (gold_fp2_t *const *)outs);
    CHECK(rc == DNAC_BATCH_OK, "[%s] perm challenges rc=%d", name, rc);
    check_milestone(name, "after_perm_challenges", &ch, mstate[4]);
    for (uint32_t i = 0; i < sc.n; i++) {
        for (uint32_t k = 0; k < sc.exp_num_chal[i]; k++) {
            CHECK(fp2_eq_limbs(outs[i][k], sc.exp_challenges[i][k]),
                  "[%s] perm challenge i=%u k=%u", name, i, k);
        }
    }

    gold_fp2_t alpha;
    rc = dnac_batch_observe_perm_and_sample_alpha(
        &ch, sc.has_commit[2] ? sc.commits[2] : NULL, sc.views,
        sc.cums, sc.n, &alpha);
    CHECK(rc == DNAC_BATCH_OK, "[%s] alpha rc=%d", name, rc);
    check_milestone(name, "after_alpha", &ch, mstate[5]);
    CHECK(fp2_eq_limbs(alpha, sc.exp_alpha), "[%s] alpha value", name);

    dnac_batch_observe_commit(&ch, sc.commits[3]);
    check_milestone(name, "after_quotient", &ch, mstate[6]);

    if (sc.has_commit[4]) {
        dnac_batch_observe_commit(&ch, sc.commits[4]);
    }
    check_milestone(name, "after_random", &ch, mstate[7]);

    gold_fp2_t zeta = dnac_batch_sample_zeta(&ch);
    check_milestone(name, "after_zeta", &ch, mstate[8]);
    CHECK(fp2_eq_limbs(zeta, sc.exp_zeta), "[%s] zeta value", name);

    /* ---- 3: composed run on a fresh duplex ---- */
    {
        dnac_batch_priming_input_t in = {
            .num_instances = sc.n,
            .is_zk = sc.is_zk,
            .bindings = sc.bindings,
            .public_values = (const gold_fp_t *const *)sc.publics,
            .num_publics = sc.num_publics,
            .preprocessed_widths = sc.prep_widths,
            .views = sc.views,
            .cumulative_sums = sc.cums,
            .main_commit = sc.commits[0],
            .preprocessed_commit = sc.has_commit[1] ? sc.commits[1] : NULL,
            .permutation_commit = sc.has_commit[2] ? sc.commits[2] : NULL,
            .quotient_commit = sc.commits[3],
            .random_commit = sc.has_commit[4] ? sc.commits[4] : NULL,
        };
        gold_fp2_t *outs2[4] = { NULL, NULL, NULL, NULL };
        for (uint32_t i = 0; i < sc.n; i++) {
            uint32_t cnt =
                2u * (sc.views[i].num_locals + sc.views[i].num_globals);
            if (cnt) outs2[i] = (gold_fp2_t *)malloc(sizeof(gold_fp2_t) * cnt);
        }
        gold_fp2_t a2, z2;
        dnac_duplex_t ch2;
        dnac_duplex_init_default(&ch2);
        rc = dnac_batch_priming_run(&ch2, &in, (gold_fp2_t *const *)outs2,
                                    &a2, &z2);
        CHECK(rc == DNAC_BATCH_OK, "[%s] composed run rc=%d", name, rc);
        if (rc == DNAC_BATCH_OK) {
            CHECK(fp2_eq_limbs(a2, sc.exp_alpha) && fp2_eq_limbs(z2, sc.exp_zeta),
                  "[%s] composed alpha/zeta", name);
            for (uint32_t i = 0; i < sc.n; i++) {
                for (uint32_t k = 0; k < sc.exp_num_chal[i]; k++) {
                    CHECK(fp2_eq_limbs(outs2[i][k], sc.exp_challenges[i][k]),
                          "[%s] composed challenge i=%u k=%u", name, i, k);
                }
            }
        }
        for (uint32_t i = 0; i < sc.n; i++) free(outs2[i]);
    }

    /* ---- 4: shape check accepts the verified shape + rejects mutations ---- */
    int has_perm = sc.has_commit[2], has_rnd = sc.has_commit[4];
    rc = dnac_batch_proof_shape_check(sc.shapes, sc.bindings, sc.views,
                                      sc.prep_widths, sc.n, sc.is_zk,
                                      has_perm, has_rnd);
    CHECK(rc == DNAC_BATCH_OK, "[%s] shape accept rc=%d", name, rc);

    {
        dnac_batch_instance_shape_t bad = sc.shapes[0];
        bad.quotient_chunk_dim = 1;
        dnac_batch_instance_shape_t shapes2[4];
        memcpy(shapes2, sc.shapes, sizeof(shapes2));
        shapes2[0] = bad;
        rc = dnac_batch_proof_shape_check(shapes2, sc.bindings, sc.views,
                                          sc.prep_widths, sc.n, sc.is_zk,
                                          has_perm, has_rnd);
        CHECK(rc == DNAC_BATCH_ERR_SHAPE, "[%s] chunk-dim mutation rc=%d",
              name, rc);

        shapes2[0] = sc.shapes[0];
        shapes2[0].trace_local_len += 1;
        rc = dnac_batch_proof_shape_check(shapes2, sc.bindings, sc.views,
                                          sc.prep_widths, sc.n, sc.is_zk,
                                          has_perm, has_rnd);
        CHECK(rc == DNAC_BATCH_ERR_SHAPE, "[%s] trace-width mutation rc=%d",
              name, rc);

        shapes2[0] = sc.shapes[0];
        shapes2[0].permutation_next_len += 2;
        rc = dnac_batch_proof_shape_check(shapes2, sc.bindings, sc.views,
                                          sc.prep_widths, sc.n, sc.is_zk,
                                          has_perm, has_rnd);
        CHECK(rc == DNAC_BATCH_ERR_SHAPE, "[%s] perm-len mutation rc=%d",
              name, rc);

        /* random-vs-ZK flag flip */
        rc = dnac_batch_proof_shape_check(sc.shapes, sc.bindings, sc.views,
                                          sc.prep_widths, sc.n, sc.is_zk,
                                          has_perm, !has_rnd);
        CHECK(rc == DNAC_BATCH_ERR_SHAPE, "[%s] random-flag mutation rc=%d",
              name, rc);

        /* permutation-commit flag flip */
        rc = dnac_batch_proof_shape_check(sc.shapes, sc.bindings, sc.views,
                                          sc.prep_widths, sc.n, sc.is_zk,
                                          !has_perm, has_rnd);
        CHECK(rc == DNAC_BATCH_ERR_SHAPE, "[%s] perm-flag mutation rc=%d",
              name, rc);

        /* lookup metadata: wrong aux column (only meaningful with globals) */
        if (sc.views[0].num_globals > 0) {
            uint32_t cols2[8];
            memcpy(cols2, sc.entry_cols[0], sizeof(cols2));
            cols2[0] += 1;
            shapes2[0] = sc.shapes[0];
            shapes2[0].entry_aux_columns = cols2;
            rc = dnac_batch_proof_shape_check(shapes2, sc.bindings, sc.views,
                                              sc.prep_widths, sc.n, sc.is_zk,
                                              has_perm, has_rnd);
            CHECK(rc == DNAC_BATCH_ERR_SHAPE,
                  "[%s] aux-column mutation rc=%d", name, rc);
        }
    }

    /* ---- composed-run fail-close negatives (once, on scenario data) ---- */
    {
        dnac_batch_priming_input_t in = {
            .num_instances = sc.n,
            .is_zk = !sc.is_zk, /* random-commit flag now inconsistent */
            .bindings = sc.bindings,
            .public_values = (const gold_fp_t *const *)sc.publics,
            .num_publics = sc.num_publics,
            .preprocessed_widths = sc.prep_widths,
            .views = sc.views,
            .cumulative_sums = sc.cums,
            .main_commit = sc.commits[0],
            .preprocessed_commit = sc.has_commit[1] ? sc.commits[1] : NULL,
            .permutation_commit = sc.has_commit[2] ? sc.commits[2] : NULL,
            .quotient_commit = sc.commits[3],
            .random_commit = sc.has_commit[4] ? sc.commits[4] : NULL,
        };
        gold_fp2_t a2, z2;
        dnac_duplex_t ch2;
        dnac_duplex_init_default(&ch2);
        rc = dnac_batch_priming_run(&ch2, &in, (gold_fp2_t *const *)outs, &a2,
                                    &z2);
        CHECK(rc == DNAC_BATCH_ERR_PARAM, "[%s] zk-flip negative rc=%d", name,
              rc);
    }

    for (uint32_t i = 0; i < sc.n; i++) free(outs[i]);
    scen_free(&sc);
    return 0;
}

int main(int argc, char **argv)
{
    const char *path = (argc > 1) ? argv[1] : "tools/vectors/batch_priming.json";
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
    const jv_t *scens = jv_get(doc, "scenarios");
    if (!scens || scens->kind != JV_ARR) {
        fprintf(stderr, "FAIL: no scenarios\n");
        jv_free(doc);
        free(buf);
        return 2;
    }
    for (size_t i = 0; i < scens->n; i++) {
        if (run_scenario(scens->items[i]) == 2) {
            fprintf(stderr, "FAIL: scenario %zu parse error\n", i);
            jv_free(doc);
            free(buf);
            return 2;
        }
    }
    printf("scenarios: %zu checked\n", scens->n);

    printf("\n%-32s %5d checks\n", "batch_priming total", g_total);
    printf("%-32s %5d\n", "batch_priming failed", g_failed);
    printf("\nP2L-c BATCH PRIMING GATE: %s\n", g_failed == 0 ? "GREEN" : "RED");

    jv_free(doc);
    free(buf);
    return g_failed == 0 ? 0 : 1;
}
