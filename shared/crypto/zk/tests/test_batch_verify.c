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
 * residual folds), the FLAT cross-AIR terminal sum — and the sampled (α, ζ)
 * must byte-match the oracle's transcript replay.
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
 * values / commits / per-AIR terminal this test alone needs) stays local.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../batch_verify.h"
#include "../stark_constraints.h"
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
    /* the v3-era cums/names/auxcols scratch is gone with global_lookup_data —
     * the terminal lives directly in dnac_batch_vopened_t now. */
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

        /* LookupTerminal — one optional value per AIR (v0.6.2). JSON null
         * is the None discriminant; the metadata list it replaced is gone. */
        const jv_t *lt = jv_get(ji, "lookup_terminal");
        if (!lt || lt->kind == JV_NULL) {
            oi->terminal = gold_fp2_zero();
            oi->has_terminal = 0;
        } else {
            if (!jv_fp2(lt, &oi->terminal)) RF();
            oi->has_terminal = 1;
        }

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
    /* Pins: the tail count the fixture loaded (see rand_fixture_t) and salt 0 —
     * build_fri_proof emits every opening with salt_elems == 0. */
    return dnac_batch_verify(
        sc->insts, sc->opened, sc->n, sc->is_zk, &sc->commits,
        sc->num_prep ? sc->prep_map : NULL, sc->num_prep, &sc->params,
        sc->is_zk ? sc->rf.nrc_derived : 0u, 0,
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
              "%s: dnac_batch_verify = %d (fri=%d bad_inst=%u term_sum=%llu,%llu)",
              sname, (int)st, (int)out.fri_status, out.bad_instance,
              (unsigned long long)gold_fp_to_u64(out.terminal_sum.a),
              (unsigned long long)gold_fp_to_u64(out.terminal_sum.b));
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
     * v0.6.2 verifier/mod.rs:518-526). */
    CHECK(load_scenario(js_lut, neg), "N4 load");
    neg->opened[0].permutation_len -= 2;
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_SHAPE,
          "N4 short permutation opens must be SHAPE");

    /* N5: tamper the committed lookup TERMINAL. It is observed before alpha
     * is sampled (transcript.rs:175-188), so the whole downstream transcript —
     * alpha, then zeta — diverges and FRI rejects before the constraint check
     * ever sees the bad terminal. (Replaces the v3-era tampered-cumulative-sum
     * negative; same property, one value instead of a per-global list.) */
    CHECK(load_scenario(js_lut, neg), "N5 load");
    CHECK(neg->opened[0].has_terminal, "N5 fixture must carry a terminal");
    neg->opened[0].terminal = gold_fp2_add(neg->opened[0].terminal,
                                           gold_fp2_from_base(gold_fp_one()));
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_FRI,
          "N5 tampered terminal must fail in FRI");

    /* N4b (S2'-d2): zeta ON the trace domain -> OodPointInDomain.
     * zeta is Fiat-Shamir-sampled inside dnac_batch_verify, so it cannot be set
     * from here; instead shrink the instance's degree_bits until the SAMPLED
     * zeta happens to satisfy zeta^(2^bdb) == 1. At bdb == 0 the trace domain is
     * the single point {1} and z_h = zeta^1 - 1, which is zero only for
     * zeta == 1 — still not reachable. So this negative drives the PREDICATE
     * directly rather than pretending to drive the verifier: it is the one piece
     * of the guard that is testable without grinding Fiat-Shamir, and the
     * ~2^-115 unreachability through dnac_batch_verify is exactly why the guard
     * is cheap insurance rather than a live fix. */
    {
        dnac_stark_selectors_t s_ok = dnac_stark_selectors_at_point(
            gold_fp2_new(gold_fp_from_u64(12345), gold_fp_from_u64(678)), 3);
        CHECK(!dnac_stark_zeta_in_domain(&s_ok),
              "N4b off-domain zeta must NOT trip the guard");
        /* zeta = 1 is on EVERY trace domain: z_h = 1^(2^bdb) - 1 = 0. */
        dnac_stark_selectors_t s_bad =
            dnac_stark_selectors_at_point(gold_fp2_one(), 3);
        CHECK(gold_fp2_eq(s_bad.z_h, gold_fp2_zero()),
              "N4b zeta=1 must give a zero vanishing polynomial");
        CHECK(dnac_stark_zeta_in_domain(&s_bad),
              "N4b on-domain zeta must trip the guard");
        /* and the fail-open it prevents: inv_vanishing is 0, not a trap. */
        CHECK(gold_fp2_eq(s_bad.inv_vanishing, gold_fp2_zero()),
              "N4b inv_vanishing at a zero z_h is 0 (the fail-open)");
    }

    /* N4c (S2'-d2): the LogUp multiplicity height bound is enforced ON the
     * verify path now. Driven in two parts below: (i) the wiring and its
     * fail-close through the REAL verify path, and (ii) the bound itself,
     * driven directly — inflating the fixture's count_weight cannot reach p,
     * for the reasons spelled out at (ii). */
    {
        CHECK(load_scenario(js_lut, neg), "N4c load");
        const uint32_t *saved = neg->insts[0].view.global_count_weights;
        /* (i) It is WIRED and fail-CLOSES: an AIR that declares globals but no
         *     weights cannot have its bound evaluated, so the verify must
         *     reject rather than skip the check. */
        neg->insts[0].view.global_count_weights = NULL;
        CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_NULL,
              "N4c missing weights must fail closed, not skip the bound");
        neg->insts[0].view.global_count_weights = saved;

        /* (ii) The bound itself fires at realistic maxima — driven directly,
         *      because it CANNOT be reached through this fixture. Arithmetic:
         *      count_weight is u32 and the batch layer caps log_degree < 32, so
         *      ONE term is at most (2^32-1)·2^31 = 2^63 - 2^31, still under
         *      p = 2^64 - 2^32 + 1. TWO such terms give exactly p - 1, which
         *      still PASSES — so THREE maximal terms are the minimum that fires,
         *      which is why the direct drive below uses three. The accumulator
         *      loops over GLOBAL LOOKUPS, not instances (logup_bus.c), so one
         *      instance with three globals would do; the blocker here is simply
         *      that the only fixture with globals uses weight 1 against base
         *      heights 4 and 8, i.e. a sum of 12.
         *
         * ⚠ COVERAGE DISCLOSED: the batch-layer mapping
         *   DNAC_LOGUP_ERR_HEIGHT_BOUND -> DNAC_BV_ERR_HEIGHT_BOUND is
         *   consequently NOT exercised end-to-end here. The underlying check is
         *   boundary-tested (p-1 OK / p FAIL) in test_logup_bus.c; what follows
         *   pins that the same inputs dnac_batch_verify would hand it do trip
         *   it. Exercising the mapping end-to-end needs a fixture carrying
         *   >= 3 near-maximal (weight x height) global terms, which no current
         *   vector provides — and on the consensus path it is unreachable by
         *   construction, since the shielded view is built by the verifier
         *   itself and declares no globals at all. */
        {
            static const char *const nm[1] = { "LUT" };
            static const uint32_t wmax[1] = { 0xFFFFFFFFu };
            dnac_logup_bus_view_t v3[3];
            uint32_t h3[3];
            for (int k = 0; k < 3; k++) {
                v3[k].num_locals = 0;
                v3[k].num_globals = 1;
                v3[k].global_bus_names = nm;
                v3[k].global_count_weights = wmax;
                h3[k] = 1u << 31;               /* the cap the batch layer allows */
            }
            CHECK(dnac_logup_bus_check_height_bound(v3, h3, 3) ==
                      DNAC_LOGUP_ERR_HEIGHT_BOUND,
                  "N4c 3 x (2^32-1)*2^31 must exceed p");
            h3[0] = 1u; h3[1] = 1u; h3[2] = 1u;
            CHECK(dnac_logup_bus_check_height_bound(v3, h3, 3) == DNAC_LOGUP_OK,
                  "N4c the same weights at height 1 must pass");
        }
    }

    /* N5b: the presence discriminant itself is load-bearing — an AIR that
     * declares lookups but omits its terminal is TerminalPresenceMismatch,
     * caught structurally before any transcript work. */
    CHECK(load_scenario(js_lut, neg), "N5b load");
    neg->opened[0].has_terminal = 0;
    CHECK(run_scenario(neg, &out) == DNAC_BV_ERR_SHAPE,
          "N5b missing terminal on a lookup AIR must be SHAPE");

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
