/**
 * @file test_batch_prover.c
 * @brief P2L-d d3 KAT — the C batched STARK prover (`dnac_batch_prove`)
 *        byte-matched against the REAL Plonky3 prove_batch vectors
 *        (tools/vectors/batch_proof.json, every scenario verify_batch-gated
 *        in-oracle at 82cfad73).
 *
 * For every scenario the C prover re-builds the witness traces the oracle
 * used (fib_air.rs:74-92 generate_trace_rows; the P2L LUT tables,
 * tests.rs:1229-1391 multisets; the PrepEqAir 7+3i ramp) and proves the
 * batch from scratch. Byte-match targets:
 *   - ALL commitments (main / preprocessed / permutation / quotient / random)
 *   - the sampled constraint-α and ζ
 *   - every opened value (trace/prep/quotient/random/permutation local+next)
 *     + cumulative sums + global_lookup_data metadata
 *   - the ENTIRE FRI opening proof (commit-phase commits, PoW witnesses,
 *     final poly, per-query input rows + sibling paths + commit-phase steps)
 *   - the hiding rand-openings (fib_zk), entry-per-entry
 * The 4 plain scenarios byte-match with no draws; fib_zk consumes the
 * oracle's SmallRng(1) stream (zk_rng.draws, consumption order pinned at
 * source — see batch_prover.h). Self-verify (dnac_batch_verify) runs inside
 * dnac_batch_prove; negatives check the prover's fail-close paths.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../batch_prover.h"
#include "batch_test_util.h"

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

static int fp2_eq(gold_fp2_t a, gold_fp2_t b)
{
    return gold_fp_to_u64(a.a) == gold_fp_to_u64(b.a) &&
           gold_fp_to_u64(a.b) == gold_fp_to_u64(b.b);
}

static int lanes_eq(const gold_fp_t a[4], const gold_fp_t b[4])
{
    for (int k = 0; k < 4; k++) {
        if (gold_fp_to_u64(a[k]) != gold_fp_to_u64(b[k])) return 0;
    }
    return 1;
}

static int digest_eq(const dnac_p2_digest_t *a, const dnac_p2_digest_t *b)
{
    for (int k = 0; k < 4; k++) {
        if (a->lanes[k] != b->lanes[k]) return 0;
    }
    return 1;
}

/* Witness builders + pscenario_t/load_pscenario moved VERBATIM to
 * tests/batch_test_util.h at d4.b (shared with test_batch_wire.c). */

/* ============================================================================
 * Byte-match of one proved scenario against the vector
 * ========================================================================== */
static void match_scenario(const jv_t *js, pscenario_t *sc,
                           const dnac_batch_proof_t *p, const char *name)
{
    /* commits (hex). */
    const jv_t *cm = jv_get(js, "commits");
    dnac_batch_vcommits_t got;
    dnac_batch_proof_commits(p, &got);
    static const char *keys[5] = { "main", "preprocessed", "permutation",
                                   "quotient", "random" };
    const gold_fp_t *gl[5] = { got.main_commit, got.preprocessed_commit,
                               got.permutation_commit, got.quotient_commit,
                               got.random_commit };
    for (int k = 0; k < 5; k++) {
        const jv_t *cv = jv_get(cm, keys[k]);
        const int want_present = cv && cv->kind == JV_STR;
        CHECK((gl[k] != NULL) == want_present, "%s: commit %s presence", name,
              keys[k]);
        if (want_present && gl[k]) {
            gold_fp_t lanes[4];
            CHECK(hex_commit(cv, lanes), "%s: commit %s hex", name, keys[k]);
            CHECK(lanes_eq(lanes, gl[k]), "%s: commit %s MISMATCH", name,
                  keys[k]);
        }
    }

    /* alpha / zeta. */
    gold_fp2_t alpha, zeta, ea, ez;
    dnac_batch_proof_alpha_zeta(p, &alpha, &zeta);
    CHECK(jv_fp2(jv_get(js, "alpha"), &ea) && fp2_eq(alpha, ea),
          "%s: alpha mismatch", name);
    CHECK(jv_fp2(jv_get(js, "zeta"), &ez) && fp2_eq(zeta, ez),
          "%s: zeta mismatch", name);

    /* per-instance opened values. */
    const jv_t *insts = jv_get(js, "instances");
    for (uint32_t i = 0; i < sc->n; i++) {
        const jv_t *op = jv_get(insts->items[i], "opened");
        const dnac_batch_vopened_t *oi = dnac_batch_proof_opened(p, i);
        gold_fp2_t buf[64];
        uint32_t len;
        struct {
            const char *key;
            const gold_fp2_t *got;
            uint32_t got_len;
        } fields[7] = {
            { "trace_local", oi->trace_local, oi->trace_local_len },
            { "trace_next", oi->trace_next, oi->trace_next_len },
            { "preprocessed_local", oi->preprocessed_local,
              oi->preprocessed_local_len },
            { "preprocessed_next", oi->preprocessed_next,
              oi->preprocessed_next_len },
            { "random", oi->random, oi->random_len },
            { "permutation_local", oi->permutation_local,
              oi->permutation_len },
            { "permutation_next", oi->permutation_next, oi->permutation_len },
        };
        for (int f = 0; f < 7; f++) {
            if (!fp2_list(jv_get(op, fields[f].key), buf, 64, &len)) {
                CHECK(0, "%s: inst %u %s parse", name, i, fields[f].key);
                continue;
            }
            /* permutation lens: JV lists are empty for lookup-free insts. */
            uint32_t gotl = fields[f].got ? fields[f].got_len : 0;
            CHECK(len == gotl, "%s: inst %u %s len %u != %u", name, i,
                  fields[f].key, gotl, len);
            int ok = len == gotl;
            for (uint32_t k = 0; ok && k < len; k++) {
                if (!fp2_eq(fields[f].got[k], buf[k])) ok = 0;
            }
            CHECK(ok, "%s: inst %u %s values", name, i, fields[f].key);
        }
        /* quotient chunks ([nqc][2] nested). */
        const jv_t *qcs = jv_get(op, "quotient_chunks");
        CHECK(qcs && qcs->kind == JV_ARR &&
                  qcs->n == oi->num_quotient_chunks,
              "%s: inst %u qc count", name, i);
        if (qcs && qcs->kind == JV_ARR && qcs->n == oi->num_quotient_chunks) {
            int ok = 1;
            for (size_t c = 0; c < qcs->n; c++) {
                gold_fp2_t e0, e1;
                if (qcs->items[c]->n != 2 ||
                    !jv_fp2(qcs->items[c]->items[0], &e0) ||
                    !jv_fp2(qcs->items[c]->items[1], &e1) ||
                    !fp2_eq(oi->quotient_chunks[2 * c], e0) ||
                    !fp2_eq(oi->quotient_chunks[2 * c + 1], e1)) {
                    ok = 0;
                }
            }
            CHECK(ok, "%s: inst %u quotient chunk values", name, i);
        }
        /* cumulative sums + metadata. */
        const jv_t *cs = jv_get(insts->items[i], "cumulative_sums");
        CHECK(cs && cs->kind == JV_ARR && cs->n == oi->num_globals,
              "%s: inst %u num_globals", name, i);
        if (cs && cs->kind == JV_ARR && cs->n == oi->num_globals) {
            int ok = 1;
            for (size_t g = 0; g < cs->n; g++) {
                gold_fp2_t es;
                uint64_t ac;
                const jv_t *bn = jv_get(cs->items[g], "bus_name");
                if (!jv_fp2(jv_get(cs->items[g], "sum"), &es) ||
                    !sv_u64(jv_get(cs->items[g], "aux_column"), &ac) || !bn ||
                    bn->kind != JV_STR ||
                    !fp2_eq(oi->cumulative_sums[g], es) ||
                    oi->entry_aux_columns[g] != (uint32_t)ac ||
                    strcmp(oi->entry_names[g], bn->str) != 0) {
                    ok = 0;
                }
            }
            CHECK(ok, "%s: inst %u cumulative sums", name, i);
        }
    }

    /* the ENTIRE FRI opening proof vs proof_serde. */
    const jv_t *ps = jv_get(js, "proof_serde");
    const jv_t *op = jv_get(ps, "opening_proof");
    static fri_fixture_t fx;
    static rand_fixture_t rf;
    bool built;
    if (sc->is_zk) {
        built = op && op->kind == JV_ARR && op->n == 2 &&
                build_rand_openings(op->items[0], &rf) &&
                build_fri_proof(op->items[1], &fx);
    } else {
        built = op && build_fri_proof(op, &fx);
    }
    CHECK(built, "%s: proof_serde parse", name);
    if (!built) return;

    const dnac_fri_proof_t *gp = dnac_batch_proof_fri(p);
    const dnac_fri_proof_t *ep = &fx.proof;
    CHECK(gp->num_commit_phase_commits == ep->num_commit_phase_commits,
          "%s: cpc count", name);
    if (gp->num_commit_phase_commits == ep->num_commit_phase_commits) {
        int ok = 1;
        for (size_t r = 0; r < gp->num_commit_phase_commits; r++) {
            if (!digest_eq(&gp->commit_phase_commits[r],
                           &ep->commit_phase_commits[r])) {
                ok = 0;
            }
        }
        CHECK(ok, "%s: commit-phase commits", name);
    }
    {
        int ok = gp->num_commit_pow_witnesses == ep->num_commit_pow_witnesses;
        for (size_t r = 0; ok && r < gp->num_commit_pow_witnesses; r++) {
            if (gold_fp_to_u64(gp->commit_pow_witnesses[r]) !=
                gold_fp_to_u64(ep->commit_pow_witnesses[r])) {
                ok = 0;
            }
        }
        CHECK(ok, "%s: commit PoW witnesses", name);
    }
    CHECK(gp->num_final_poly == ep->num_final_poly, "%s: final poly len",
          name);
    if (gp->num_final_poly == ep->num_final_poly) {
        int ok = 1;
        for (size_t k = 0; k < gp->num_final_poly; k++) {
            if (!fp2_eq(gp->final_poly[k], ep->final_poly[k])) ok = 0;
        }
        CHECK(ok, "%s: final poly values", name);
    }
    CHECK(gold_fp_to_u64(gp->query_pow_witness) ==
              gold_fp_to_u64(ep->query_pow_witness),
          "%s: query PoW witness", name);

    CHECK(gp->num_query_proofs == ep->num_query_proofs, "%s: query count",
          name);
    for (size_t q = 0;
         q < gp->num_query_proofs && q < ep->num_query_proofs; q++) {
        const dnac_fri_query_proof_t *gq = &gp->query_proofs[q];
        const dnac_fri_query_proof_t *eq2 = &ep->query_proofs[q];
        CHECK(gq->num_input_batches == eq2->num_input_batches,
              "%s: q%zu batch count", name, q);
        for (size_t b = 0; b < gq->num_input_batches &&
                           b < eq2->num_input_batches; b++) {
            const dnac_fri_batch_opening_t *gb = &gq->input_proof[b];
            const dnac_fri_batch_opening_t *eb = &eq2->input_proof[b];
            int ok = gb->num_matrices == eb->num_matrices &&
                     gb->opening_proof.depth == eb->opening_proof.depth;
            for (size_t m = 0; ok && m < gb->num_matrices; m++) {
                if (gb->opened_values_lens[m] != eb->opened_values_lens[m]) {
                    ok = 0;
                    break;
                }
                for (size_t c = 0; c < gb->opened_values_lens[m]; c++) {
                    if (gold_fp_to_u64(gb->opened_values[m][c]) !=
                        gold_fp_to_u64(eb->opened_values[m][c])) {
                        ok = 0;
                        break;
                    }
                }
            }
            for (size_t s = 0; ok && s < gb->opening_proof.depth; s++) {
                if (!digest_eq(&gb->opening_proof.siblings[s],
                               &eb->opening_proof.siblings[s])) {
                    ok = 0;
                }
            }
            CHECK(ok, "%s: q%zu input batch %zu", name, q, b);
        }
        CHECK(gq->num_commit_phase_openings == eq2->num_commit_phase_openings,
              "%s: q%zu cp-step count", name, q);
        for (size_t r = 0; r < gq->num_commit_phase_openings &&
                           r < eq2->num_commit_phase_openings; r++) {
            const dnac_fri_commit_phase_proof_step_t *gs =
                &gq->commit_phase_openings[r];
            const dnac_fri_commit_phase_proof_step_t *es =
                &eq2->commit_phase_openings[r];
            int ok = gs->log_arity == es->log_arity &&
                     gs->num_sibling_values == es->num_sibling_values &&
                     gs->opening_proof.depth == es->opening_proof.depth;
            for (size_t s = 0; ok && s < gs->num_sibling_values; s++) {
                if (!fp2_eq(gs->sibling_values[s], es->sibling_values[s])) {
                    ok = 0;
                }
            }
            for (size_t s = 0; ok && s < gs->opening_proof.depth; s++) {
                if (!digest_eq(&gs->opening_proof.siblings[s],
                               &es->opening_proof.siblings[s])) {
                    ok = 0;
                }
            }
            CHECK(ok, "%s: q%zu cp step %zu", name, q, r);
        }
    }

    /* hiding rand-openings, entry per entry (fib_zk). */
    if (sc->is_zk) {
        const dnac_batch_rand_openings_t *gro =
            dnac_batch_proof_rand_openings(p);
        CHECK(gro != NULL && gro->num_entries == rf.ro.num_entries,
              "%s: rand-openings entry count", name);
        if (gro && gro->num_entries == rf.ro.num_entries) {
            int ok = 1;
            for (uint32_t k = 0; k < gro->num_entries; k++) {
                if (gro->lens[k] != rf.ro.lens[k]) { ok = 0; break; }
                for (uint32_t e = 0; e < gro->lens[k]; e++) {
                    if (!fp2_eq(gro->vals[k][e], rf.ro.vals[k][e])) {
                        ok = 0;
                        break;
                    }
                }
            }
            CHECK(ok, "%s: rand-openings values", name);
        }
    } else {
        CHECK(dnac_batch_proof_rand_openings(p) == NULL,
              "%s: no rand-openings when !zk", name);
    }
}

int main(int argc, char **argv)
{
    const char *path = "tools/vectors/batch_proof.json";
    if (argc >= 2) path = argv[1];

    size_t blen = 0;
    char *buf = load_file(path, &blen);
    if (!buf) {
        fprintf(stderr, "cannot load %s\n", path);
        return 2;
    }
    printf("loaded %s (%zu bytes)\n", path, blen);
    jp_t jp = { buf, 0, blen };
    jv_t *doc = jp_value(&jp);
    if (!doc) {
        fprintf(stderr, "JSON parse failed\n");
        free(buf);
        return 2;
    }
    const jv_t *scens = jv_get(doc, "scenarios");
    if (!scens || scens->kind != JV_ARR) {
        fprintf(stderr, "no scenarios\n");
        return 2;
    }

    static pscenario_t sc;
    for (size_t s = 0; s < scens->n; s++) {
        const jv_t *js = scens->items[s];
        const jv_t *name = jv_get(js, "name");
        const char *nm =
            name && name->kind == JV_STR ? name->str : "(unnamed)";
        if (!load_pscenario(js, &sc)) {
            CHECK(0, "scenario %s: fixture load failed", nm);
            continue;
        }
        /* draw-total consistency with the derivation helper. */
        if (sc.is_zk) {
            CHECK(dnac_batch_prove_num_draws(sc.insts, sc.n, 1, sc.nrc) ==
                      sc.num_draws,
                  "%s: derived draw total != zk_rng.total_draws", nm);
        }
        dnac_batch_proof_t *p = NULL;
        dnac_prover_status_t st = dnac_batch_prove(
            sc.insts, sc.wits, sc.n, sc.is_zk, &sc.params, sc.nrc,
            sc.is_zk ? sc.draws : NULL, sc.is_zk ? sc.num_draws : 0, NULL, 0,
            NULL, 0, 0, &p);
        CHECK(st == DNAC_PROVER_OK, "%s: dnac_batch_prove -> %d", nm,
              (int)st);
        if (st == DNAC_PROVER_OK) {
            match_scenario(js, &sc, p, nm);
            printf("  scenario %-16s n=%u is_zk=%d -> proved + byte-matched\n",
                   nm, sc.n, sc.is_zk);
            dnac_batch_proof_free(p);
        }
    }

    /* ---- negatives (fail-close paths) ---- */
    {
        /* fib_single reload (first scenario). */
        const jv_t *js = scens->items[0];
        if (load_pscenario(js, &sc)) {
            dnac_batch_proof_t *p = NULL;
            /* N1: tampered witness -> the self-verify must reject (the
             * quotient stops being low-degree consistent at ζ). */
            sc.main_store[0][3] ^= 1;
            CHECK(dnac_batch_prove(sc.insts, sc.wits, sc.n, 0, &sc.params, 0,
                                   NULL, 0, NULL, 0, NULL, 0, 0,
                                   &p) == DNAC_PROVER_ERR_VERIFY,
                  "N1: tampered witness must fail self-verify");
            sc.main_store[0][3] ^= 1;
            /* N2: zk flag without draws -> PARAM. */
            CHECK(dnac_batch_prove(sc.insts, sc.wits, sc.n, 1, &sc.params, 4,
                                   NULL, 0, NULL, 0, NULL, 0, 0,
                                   &p) == DNAC_PROVER_ERR_PARAM,
                  "N2: is_zk without draws must be PARAM");
            /* N3: draws given for a non-zk prove -> PARAM. */
            uint64_t dummy_draw = 1;
            CHECK(dnac_batch_prove(sc.insts, sc.wits, sc.n, 0, &sc.params, 0,
                                   &dummy_draw, 1, NULL, 0, NULL, 0, 0,
                                   &p) == DNAC_PROVER_ERR_PARAM,
                  "N3: draws on non-zk must be PARAM");
        } else {
            CHECK(0, "negative fixture reload failed");
        }
        /* N4/N5 on fib_zk (last scenario). */
        const jv_t *jz = scens->items[scens->n - 1];
        if (load_pscenario(jz, &sc) && sc.is_zk) {
            dnac_batch_proof_t *p = NULL;
            /* N4: wrong draw count -> PARAM. */
            CHECK(dnac_batch_prove(sc.insts, sc.wits, sc.n, 1, &sc.params,
                                   sc.nrc, sc.draws, sc.num_draws - 1, NULL,
                                   0, NULL, 0, 0, &p) ==
                      DNAC_PROVER_ERR_PARAM,
                  "N4: short draw stream must be PARAM");
            /* N5: non-canonical draw -> NONCANONICAL. */
            const uint64_t save = sc.draws[0];
            sc.draws[0] = GOLDILOCKS_P;
            CHECK(dnac_batch_prove(sc.insts, sc.wits, sc.n, 1, &sc.params,
                                   sc.nrc, sc.draws, sc.num_draws, NULL, 0,
                                   NULL, 0, 0, &p) ==
                      DNAC_PROVER_ERR_NONCANONICAL,
                  "N5: non-canonical draw must be NONCANONICAL");
            sc.draws[0] = save;
        } else {
            CHECK(0, "zk negative fixture reload failed");
        }
    }

    jv_free(doc);
    free(buf);

    printf("\nbatch_prover total   %26d checks\n", g_checks);
    printf("batch_prover failed  %26d\n", g_fails);
    if (g_fails == 0) {
        printf("\nP2L-d d3 BATCH PROVER GATE: GREEN\n");
        return 0;
    }
    fprintf(stderr, "\nP2L-d d3 BATCH PROVER GATE: RED\n");
    return 1;
}
