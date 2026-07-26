/**
 * @file test_batch_verify.c
 * @brief P2L-d d2 KAT — the C batched STARK verify (`dnac_batch_verify`)
 *        against the REAL Plonky3 prove_batch vectors
 *        (tools/vectors/batch_proof.json, every scenario verify_batch-gated
 *        in-oracle at 82cfad73).
 *
 * Positive gates: all 5 scenarios (fib_single / lut_pair / prep_pair /
 * lut_mixed_trio / fib_zk) must verify END-TO-END in C — full batched
 * priming, N2 round assembly, hiding merge (fib_zk), PCS observe +
 * dnac_fri_verify (mixed-height input batches incl. the d1a consumer
 * lut_mixed_trio), per-instance constraint check at ζ (air.eval + LogUp
 * residual folds), per-bus global sums — and the sampled (α, ζ) must
 * byte-match the oracle's transcript replay.
 *
 * AIR fixtures mirror the oracle's: FibonacciAir (fib_air.rs:44-72, the
 * pinned 5-constraint emission), LogupAddAir (lookup/src/tests.rs:1100-1169:
 * NO base constraints — only interactions; locals-first columns per
 * types.rs:59-89), PrepEqAir (P2L-c fixture: one v − t = 0 constraint).
 *
 * d4.d (2026-07-26): those fixtures, the serde-JSON decoders, the FRI-proof /
 * rand-openings builders and the AddAir lookup declaration were duplicated
 * VERBATIM in this file and in batch_test_util.h (which was extracted from
 * here at d2). The local copies are GONE — this file now includes the shared
 * header, so there is exactly ONE definition and no drift is possible. Only
 * the verifier-side scenario loader (load_scenario, which parses the opened
 * values / commits / cumulative sums this test alone needs) stays local.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../batch_verify.h"
#include "batch_test_util.h" /* d4.d: the SHARED fixture set (was duplicated
                              * verbatim below — serde decoders, fri_fixture_t /
                              * build_fri_proof, rand_fixture_t /
                              * build_rand_openings, the fib/add/prepeq AIRs and
                              * the AddAir lookup declaration). RF() and the
                              * MAX_* fixture bounds come from there too. */
#include "logup_test_util.h"

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

/* ============================================================================
 * Scenario runner  (fixtures + serde decoders: batch_test_util.h)
 * ========================================================================== */
#define MAX_VALS 32
#define MAX_QCV  16

typedef struct {
    gold_fp2_t tl[MAX_VALS], tn[MAX_VALS], pl[MAX_VALS], pnx[MAX_VALS];
    gold_fp2_t qc[MAX_QCV * 2], rnd[MAX_VALS], perml[MAX_VALS],
        permn[MAX_VALS];
    gold_fp2_t cums[4];
    const char *names[4];
    char        name_store[4][16];
    uint32_t    auxcols[4];
    gold_fp_t   pubs[4];
} inst_store_t;

typedef struct {
    dnac_batch_vinstance_t insts[MAX_INST];
    dnac_batch_vopened_t   opened[MAX_INST];
    inst_store_t           st[MAX_INST];
    dnac_logup_lookup_t    lks[MAX_INST][2];
    gold_fp_t              cm_main[4], cm_prep[4], cm_perm[4], cm_quot[4],
        cm_rand[4];
    dnac_batch_vcommits_t  commits;
    uint32_t               prep_map[MAX_INST];
    uint32_t               num_prep;
    dnac_fri_params_t      params;
    fri_fixture_t          fri;
    rand_fixture_t         rf;
    int                    is_zk;
    uint32_t               n;
    gold_fp2_t             exp_alpha, exp_zeta;
} scenario_t;

static bool load_scenario(const jv_t *js, scenario_t *sc)
{
    memset(sc, 0, sizeof(*sc));
    const jv_t *name = jv_get(js, "name");
    uint64_t u;
    if (!sv_u64(jv_get(js, "is_zk"), &u)) RF();
    sc->is_zk = (int)u;
    if (!sv_u64(jv_get(js, "num_instances"), &u) || u == 0 || u > MAX_INST) {
        RF();
    }
    sc->n = (uint32_t)u;

    /* fri params */
    const jv_t *fpj = jv_get(js, "fri_params");
    if (!sv_u64(jv_get(fpj, "log_blowup"), &u)) RF();
    sc->params.log_blowup = u;
    if (!sv_u64(jv_get(fpj, "log_final_poly_len"), &u)) RF();
    sc->params.log_final_poly_len = u;
    if (!sv_u64(jv_get(fpj, "max_log_arity"), &u)) RF();
    sc->params.max_log_arity = u;
    if (!sv_u64(jv_get(fpj, "num_queries"), &u)) RF();
    sc->params.num_queries = u;
    if (!sv_u64(jv_get(fpj, "commit_proof_of_work_bits"), &u)) RF();
    sc->params.commit_proof_of_work_bits = u;
    if (!sv_u64(jv_get(fpj, "query_proof_of_work_bits"), &u)) RF();
    sc->params.query_proof_of_work_bits = u;

    if (!jv_fp2(jv_get(js, "alpha"), &sc->exp_alpha)) RF();
    if (!jv_fp2(jv_get(js, "zeta"), &sc->exp_zeta)) RF();

    /* commits (hex form; preprocessed commit only exists here) */
    const jv_t *cm = jv_get(js, "commits");
    if (!hex_commit(jv_get(cm, "main"), sc->cm_main)) RF();
    if (!hex_commit(jv_get(cm, "quotient"), sc->cm_quot)) RF();
    sc->commits.main_commit = sc->cm_main;
    sc->commits.quotient_commit = sc->cm_quot;
    const jv_t *cp = jv_get(cm, "preprocessed");
    if (cp && cp->kind == JV_STR) {
        if (!hex_commit(cp, sc->cm_prep)) RF();
        sc->commits.preprocessed_commit = sc->cm_prep;
    }
    const jv_t *cpm = jv_get(cm, "permutation");
    if (cpm && cpm->kind == JV_STR) {
        if (!hex_commit(cpm, sc->cm_perm)) RF();
        sc->commits.permutation_commit = sc->cm_perm;
    }
    const jv_t *cr = jv_get(cm, "random");
    if (cr && cr->kind == JV_STR) {
        if (!hex_commit(cr, sc->cm_rand)) RF();
        sc->commits.random_commit = sc->cm_rand;
    }

    /* instances */
    const jv_t *insts = jv_get(js, "instances");
    if (!insts || insts->kind != JV_ARR || insts->n != sc->n) RF();
    for (uint32_t i = 0; i < sc->n; i++) {
        const jv_t *ji = insts->items[i];
        inst_store_t *st = &sc->st[i];
        dnac_batch_vinstance_t *di = &sc->insts[i];
        dnac_batch_vopened_t *oi = &sc->opened[i];

        uint64_t width, deg, nqc, prew, mnext, pnext;
        if (!sv_u64(jv_get(ji, "width"), &width) ||
            !sv_u64(jv_get(ji, "log_ext_degree"), &deg) ||
            !sv_u64(jv_get(ji, "num_quotient_chunks"), &nqc) ||
            !sv_u64(jv_get(ji, "preprocessed_width"), &prew)) {
            RF();
        }
        const jv_t *mn = jv_get(ji, "main_next_used");
        const jv_t *pn = jv_get(ji, "prep_next_used");
        mnext = (mn && mn->kind == JV_BOOL && mn->bval) ? 1 : 0;
        pnext = (pn && pn->kind == JV_BOOL && pn->bval) ? 1 : 0;

        /* AIR selection by scenario name + instance geometry. */
        if (!name || name->kind != JV_STR) RF();
        if (!strncmp(name->str, "fib", 3)) {
            di->air.main_width = 2;
            di->air.num_public_values = 3;
            di->air.main_next = 1;
            di->air.air_eval = fib_air_eval;
        } else if (!strncmp(name->str, "lut", 3)) {
            di->air.main_width = 7;
            di->air.num_public_values = 0;
            /* LogupAddAir does NOT override main_next_row_columns → the
             * default is ALL columns (air/src/air.rs:122-124), so the real
             * proof opens main at ζ AND g·ζ. */
            di->air.main_next = 1;
            di->air.air_eval = add_air_eval;
            make_add_lookups(sc->lks[i], i == 0 /* instance 0 = sender */);
            di->pool = ADD_POOL;
            di->pool_len = 10;
            di->lookups = sc->lks[i];
            di->num_lookups = 2;
            di->view.num_locals = 1;
            di->view.num_globals = 1;
            di->view.global_bus_names = ADD_BUS_NAMES;
            di->view.global_count_weights = ADD_BUS_WEIGHTS;
        } else if (!strncmp(name->str, "prep", 4)) {
            di->air.main_width = 1;
            di->air.num_public_values = 0;
            /* PrepEqAir overrides neither next-row hook → main_next AND
             * prep_next are the all-columns defaults (air.rs:122-137). */
            di->air.main_next = 1;
            di->air.air_eval = prepeq_air_eval;
        } else {
            RF();
        }
        if (di->air.main_width != width || (uint64_t)di->air.main_next != mnext) {
            fprintf(stderr,
                    "  [geometry: inst %u air_w=%zu json_w=%llu air_mn=%d "
                    "json_mn=%llu]\n",
                    i, di->air.main_width, (unsigned long long)width,
                    di->air.main_next, (unsigned long long)mnext);
            RF();
        }
        di->degree_bits = (uint32_t)deg;
        di->preprocessed_width = (uint32_t)prew;
        di->prep_next = (int)pnext;
        /* lq = log2(num_qc) − is_zk (num_qc = 1 << (lq + is_zk)). */
        uint32_t lq = 0;
        while ((1u << (lq + (uint32_t)sc->is_zk)) < nqc) lq++;
        if ((1u << (lq + (uint32_t)sc->is_zk)) != nqc) RF();
        di->log_num_qc = lq;

        /* publics (decimal strings) */
        const jv_t *pv = jv_get(ji, "public_values");
        if (!pv || pv->kind != JV_ARR || pv->n > 4) RF();
        for (size_t p = 0; p < pv->n; p++) {
            uint64_t x;
            if (!jv_u64(pv->items[p], &x)) RF();
            st->pubs[p] = gold_fp_from_u64(x);
        }
        di->public_values = st->pubs;
        di->num_publics = (uint32_t)pv->n;

        /* opened values */
        const jv_t *op = jv_get(ji, "opened");
        uint32_t len;
        if (!fp2_list(jv_get(op, "trace_local"), st->tl, MAX_VALS, &len)) {
            RF();
        }
        oi->trace_local = st->tl;
        oi->trace_local_len = len;
        if (!fp2_list(jv_get(op, "trace_next"), st->tn, MAX_VALS, &len)) {
            RF();
        }
        oi->trace_next = len ? st->tn : NULL;
        oi->trace_next_len = len;
        if (!fp2_list(jv_get(op, "preprocessed_local"), st->pl, MAX_VALS,
                      &len)) {
            RF();
        }
        oi->preprocessed_local = len ? st->pl : NULL;
        oi->preprocessed_local_len = len;
        if (!fp2_list(jv_get(op, "preprocessed_next"), st->pnx, MAX_VALS,
                      &len)) {
            RF();
        }
        oi->preprocessed_next = len ? st->pnx : NULL;
        oi->preprocessed_next_len = len;
        const jv_t *qcs = jv_get(op, "quotient_chunks");
        if (!qcs || qcs->kind != JV_ARR || qcs->n != nqc || nqc > MAX_QCV) {
            RF();
        }
        for (size_t c = 0; c < qcs->n; c++) {
            const jv_t *ch = qcs->items[c];
            if (!ch || ch->kind != JV_ARR || ch->n != 2) RF();
            if (!jv_fp2(ch->items[0], &st->qc[c * 2]) ||
                !jv_fp2(ch->items[1], &st->qc[c * 2 + 1])) {
                RF();
            }
        }
        oi->quotient_chunks = st->qc;
        oi->num_quotient_chunks = (uint32_t)nqc;
        if (!fp2_list(jv_get(op, "random"), st->rnd, MAX_VALS, &len)) {
            RF();
        }
        oi->random = len ? st->rnd : NULL;
        oi->random_len = len;
        uint32_t pll, pnl;
        if (!fp2_list(jv_get(op, "permutation_local"), st->perml, MAX_VALS,
                      &pll) ||
            !fp2_list(jv_get(op, "permutation_next"), st->permn, MAX_VALS,
                      &pnl) ||
            pll != pnl) {
            RF();
        }
        oi->permutation_local = pll ? st->perml : NULL;
        oi->permutation_next = pll ? st->permn : NULL;
        oi->permutation_len = pll;

        /* cumulative sums + metadata */
        const jv_t *cs = jv_get(ji, "cumulative_sums");
        if (!cs || cs->kind != JV_ARR || cs->n > 4) RF();
        for (size_t g = 0; g < cs->n; g++) {
            const jv_t *e = cs->items[g];
            if (!jv_fp2(jv_get(e, "sum"), &st->cums[g])) RF();
            const jv_t *bn = jv_get(e, "bus_name");
            uint64_t ac;
            if (!bn || bn->kind != JV_STR || strlen(bn->str) >= 16 ||
                !sv_u64(jv_get(e, "aux_column"), &ac)) {
                RF();
            }
            strcpy(st->name_store[g], bn->str);
            st->names[g] = st->name_store[g];
            st->auxcols[g] = (uint32_t)ac;
        }
        oi->cumulative_sums = st->cums;
        oi->entry_names = st->names;
        oi->entry_aux_columns = st->auxcols;
        oi->num_globals = (uint32_t)cs->n;

        if (prew > 0) sc->prep_map[sc->num_prep++] = i;
    }

    /* FRI proof (+ rand openings when zk) */
    const jv_t *ps = jv_get(js, "proof_serde");
    const jv_t *op = jv_get(ps, "opening_proof");
    if (!op) RF();
    if (sc->is_zk) {
        if (op->kind != JV_ARR || op->n != 2) RF();
        if (!build_rand_openings(op->items[0], &sc->rf)) RF();
        if (!build_fri_proof(op->items[1], &sc->fri)) RF();
    } else {
        if (!build_fri_proof(op, &sc->fri)) RF();
    }
    return true;
}

static dnac_batch_verify_status_t run_scenario(scenario_t *sc,
                                               dnac_batch_verify_out_t *out)
{
    return dnac_batch_verify(
        sc->insts, sc->opened, sc->n, sc->is_zk, &sc->commits,
        sc->num_prep ? sc->prep_map : NULL, sc->num_prep, &sc->params,
        &sc->fri.proof, sc->is_zk ? &sc->rf.ro : NULL, out);
}

int main(int argc, char **argv)
{
    const char *path = argc > 1 ? argv[1] : "tools/vectors/batch_proof.json";
    size_t len;
    char *buf = load_file(path, &len);
    if (!buf) {
        fprintf(stderr, "cannot load %s\n", path);
        return 1;
    }
    jp_t p = { buf, 0, len };
    jv_t *doc = jp_value(&p);
    if (!doc) {
        fprintf(stderr, "JSON parse failed\n");
        return 1;
    }
    printf("loaded %s (%zu bytes)\n", path, len);

    const jv_t *scenarios = jv_get(doc, "scenarios");
    if (!scenarios || scenarios->kind != JV_ARR) {
        fprintf(stderr, "no scenarios\n");
        return 1;
    }

    scenario_t *sc = (scenario_t *)calloc(1, sizeof(scenario_t));
    scenario_t *neg = (scenario_t *)calloc(1, sizeof(scenario_t));
    if (!sc || !neg) return 1;

    /* ---- positive: every scenario verifies end-to-end + (α, ζ) match ---- */
    for (size_t s = 0; s < scenarios->n; s++) {
        const jv_t *js = scenarios->items[s];
        const jv_t *nm = jv_get(js, "name");
        const char *sname =
            (nm && nm->kind == JV_STR) ? nm->str : "(unnamed)";
        CHECK(load_scenario(js, sc), "%s: scenario load", sname);
        dnac_batch_verify_out_t out;
        memset(&out, 0, sizeof(out));
        dnac_batch_verify_status_t st = run_scenario(sc, &out);
        CHECK(st == DNAC_BV_OK,
              "%s: dnac_batch_verify = %d (fri=%d bad_inst=%u bus=%s)", sname,
              (int)st, (int)out.fri_status, out.bad_instance,
              out.failed_bus ? out.failed_bus : "-");
        CHECK(fp2_eq_limbs(out.alpha, sc->exp_alpha), "%s: alpha mismatch",
              sname);
        CHECK(fp2_eq_limbs(out.zeta, sc->exp_zeta), "%s: zeta mismatch",
              sname);
        printf("  scenario %-16s n=%u is_zk=%d -> %s\n", sname, sc->n,
               sc->is_zk,
               (st == DNAC_BV_OK && fp2_eq_limbs(out.alpha, sc->exp_alpha) &&
                fp2_eq_limbs(out.zeta, sc->exp_zeta))
                   ? "OK (verify + alpha/zeta byte-match)"
                   : "FAIL");
    }

    /* ---- negatives (fail-close) ---- */
    const jv_t *js_fib = scenarios->items[0];
    const jv_t *js_lut = scenarios->items[1];
    const jv_t *js_zk = scenarios->items[scenarios->n - 1];
    dnac_batch_verify_out_t out;

    /* N1: tamper one opened trace eval — transcript diverges → FRI reject. */
    CHECK(load_scenario(js_fib, neg), "N1 load");
    neg->st[0].tl[0] = gold_fp2_add(neg->st[0].tl[0],
                                    gold_fp2_from_base(gold_fp_one()));
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_FRI,
          "N1 tampered trace_local must fail in FRI");

    /* N2: is_zk flip on a non-ZK proof → RANDOMIZATION. */
    CHECK(load_scenario(js_fib, neg), "N2 load");
    neg->is_zk = 1;
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_RANDOMIZATION ||
              run_scenario(neg, &out) == DNAC_BV_ERR_PARAM,
          "N2 zk flip must fail closed");

    /* N3: drop the permutation commit while lookups exist → SHAPE (:282-286). */
    CHECK(load_scenario(js_lut, neg), "N3 load");
    neg->commits.permutation_commit = NULL;
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_SHAPE,
          "N3 missing perm commit must be SHAPE");

    /* N4: truncate the permutation opened lens → SHAPE (aux_width·2,
     * verifier/mod.rs:524-541). */
    CHECK(load_scenario(js_lut, neg), "N4 load");
    neg->opened[0].permutation_len -= 2;
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_SHAPE,
          "N4 short permutation opens must be SHAPE");

    /* N5: tamper a cumulative sum — it is observed pre-alpha
     * (transcript.rs:106-119) → FRI reject. */
    CHECK(load_scenario(js_lut, neg), "N5 load");
    neg->st[0].cums[0] = gold_fp2_add(neg->st[0].cums[0],
                                      gold_fp2_from_base(gold_fp_one()));
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_FRI,
          "N5 tampered cumulative sum must fail in FRI");

    /* N6: tamper a main-commit lane → FRI reject (MMCS mismatch). */
    CHECK(load_scenario(js_fib, neg), "N6 load");
    neg->cm_main[0] = gold_fp_add(neg->cm_main[0], gold_fp_one());
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_FRI,
          "N6 tampered main commit must fail in FRI");

    /* N7: zk rand-openings entry-count mismatch → SHAPE (zip_eq mirror,
     * hiding_pcs.rs:386-395). */
    CHECK(load_scenario(js_zk, neg), "N7 load");
    neg->rf.ro.num_entries -= 1;
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_SHAPE,
          "N7 rand entry undercount must be SHAPE");

    /* N8: wrong public value (fib) — publics are observed at priming
     * (transcript.rs:46-54) → FRI reject (never OOD: the transcript
     * diverges before the constraint check). */
    CHECK(load_scenario(js_fib, neg), "N8 load");
    neg->st[0].pubs[2] = gold_fp_add(neg->st[0].pubs[2], gold_fp_one());
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_FRI,
          "N8 tampered public must fail in FRI");

    free(sc);
    free(neg);
    jv_free(doc);
    free(buf);

    printf("\nbatch_verify total %26d checks\n", g_checks);
    printf("batch_verify failed %25d\n", g_fails);
    if (g_fails == 0) {
        printf("\nP2L-d d2 BATCH VERIFY GATE: GREEN\n");
        return 0;
    }
    printf("\nP2L-d d2 BATCH VERIFY GATE: RED\n");
    return 1;
}
