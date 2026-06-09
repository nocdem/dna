/**
 * @file test_fri_verifier_shape.c
 * @brief F3 oracle test — pre-transcript shape-check prefix of dnac_fri_verify.
 *
 * Plonky3 commit pin: 82cfad73cd734d37a0d51953094f970c531817ec.
 *
 * Loads tools/vectors/fri_verifier_errors.json and, for every one of its 19
 * cases, classifies the case as either:
 *   - SHAPE   : an error that verify_fri raises in its pre-transcript shape
 *               checks (verifier.rs:146-246). These 6 are RUN here: a V6-shaped
 *               proof is built, the case's documented mutation is applied, and
 *               dnac_fri_test_shape_prefix() must return the matching
 *               DNAC_FRI_ERR_* status.
 *   - DEFERRED: an error that requires transcript / MMCS / fold / terminal
 *               Horner execution (F4-F7) or an isolated/not-reachable path.
 *               These 13 are reported as DEFERRED and NOT claimed as passing.
 *
 * This consumes the cases FROM the json at runtime (catching vector drift); the
 * textual mutations (e.g. "pop last query proof") are applied in C because the
 * vectors describe mutations, not serialized structs.
 *
 * Pure-mirror enum decision (2026-05-29): null inputs are a caller precondition
 * (debug assert in the verifier), so this test always supplies valid pointers.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#define DNAC_FRI_TESTING 1  /* expose dnac_fri_test_shape_prefix */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fri_verifier.h"

/* ============================================================================
 * Minimal JSON scanner — same idiom as tests/test_merkle_mmcs.c.
 * ========================================================================== */

typedef struct {
    const char *src;
    size_t pos;
    size_t len;
} js_t;

static void js_skip_ws(js_t *s) {
    while (s->pos < s->len) {
        char c = s->src[s->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') s->pos++;
        else return;
    }
}

static bool js_peek(js_t *s, char c) {
    js_skip_ws(s);
    return s->pos < s->len && s->src[s->pos] == c;
}

static bool js_match(js_t *s, char c) {
    js_skip_ws(s);
    if (s->pos < s->len && s->src[s->pos] == c) { s->pos++; return true; }
    return false;
}

static char *js_read_string(js_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len || s->src[s->pos] != '"') return NULL;
    s->pos++;
    size_t start = s->pos;
    while (s->pos < s->len && s->src[s->pos] != '"') s->pos++;
    if (s->pos >= s->len) return NULL;
    size_t slen = s->pos - start;
    s->pos++;
    char *out = (char *)malloc(slen + 1);
    if (!out) return NULL;
    memcpy(out, s->src + start, slen);
    out[slen] = '\0';
    return out;
}

static bool js_read_u64(js_t *s, uint64_t *out) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char *endp = NULL;
    unsigned long long v = strtoull(s->src + s->pos, &endp, 10);
    if (endp == s->src + s->pos) return false;
    s->pos = (size_t)(endp - s->src);
    *out = (uint64_t)v;
    return true;
}

static bool js_skip_value(js_t *s);

static bool js_skip_object(js_t *s) {
    if (!js_match(s, '{')) return false;
    while (1) {
        if (js_match(s, '}')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        char *key = js_read_string(s);
        if (!key) return false;
        free(key);
        if (!js_match(s, ':')) return false;
        if (!js_skip_value(s)) return false;
    }
}

static bool js_skip_array(js_t *s) {
    if (!js_match(s, '[')) return false;
    while (1) {
        if (js_match(s, ']')) return true;
        if (js_peek(s, ',')) { s->pos++; continue; }
        if (!js_skip_value(s)) return false;
    }
}

static bool js_skip_value(js_t *s) {
    js_skip_ws(s);
    if (s->pos >= s->len) return false;
    char c = s->src[s->pos];
    if (c == '{') return js_skip_object(s);
    if (c == '[') return js_skip_array(s);
    if (c == '"') { char *t = js_read_string(s); if (!t) return false; free(t); return true; }
    if (c == 't') { s->pos += 4; return true; }   /* true  */
    if (c == 'f') { s->pos += 5; return true; }   /* false */
    if (c == 'n') { s->pos += 4; return true; }   /* null  */
    while (s->pos < s->len) {                       /* number */
        char d = s->src[s->pos];
        if ((d >= '0' && d <= '9') || d == '-' || d == '+' || d == '.' ||
            d == 'e' || d == 'E') s->pos++;
        else break;
    }
    return true;
}

static char *slurp(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return NULL; }
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    buf[got] = '\0';
    *out_len = got;
    return buf;
}

/* ============================================================================
 * V6 fixture (counts only — shape checks never read field values).
 *
 * From tools/vectors/fri_verifier_valid.json proof: 3 commit-phase rounds,
 * 2 query proofs, 3 commit-phase openings/query (log_arity 1 each),
 * 3 commit PoW witnesses, final_poly length 1. base_fri_params: log_blowup=1,
 * log_final_poly_len=0, max_log_arity=1, num_queries=2.
 * ========================================================================== */

#define R_ROUNDS 3
#define Q_QUERIES 2
#define CAP 8

typedef struct {
    dnac_merkle_digest_t               commits[CAP];
    gold_fp_t                          witnesses[CAP];
    gold_fp2_t                         final_poly[CAP];
    dnac_fri_commit_phase_proof_step_t openings[Q_QUERIES][CAP];
    dnac_fri_query_proof_t             qps[Q_QUERIES];
    dnac_fri_proof_t                   proof;
    dnac_fri_params_t                  params;
} fx_t;

static void fx_base(fx_t *f) {
    memset(f, 0, sizeof *f);
    f->params.log_blowup = 1;
    f->params.log_final_poly_len = 0;
    f->params.max_log_arity = 1;
    f->params.num_queries = Q_QUERIES;
    f->params.commit_proof_of_work_bits = 0;
    f->params.query_proof_of_work_bits = 0;

    for (size_t q = 0; q < Q_QUERIES; ++q) {
        for (size_t r = 0; r < R_ROUNDS; ++r) f->openings[q][r].log_arity = 1;
        f->qps[q].commit_phase_openings = f->openings[q];
        f->qps[q].num_commit_phase_openings = R_ROUNDS;
    }
    f->proof.commit_phase_commits = f->commits;
    f->proof.num_commit_phase_commits = R_ROUNDS;
    f->proof.commit_pow_witnesses = f->witnesses;
    f->proof.num_commit_pow_witnesses = R_ROUNDS;
    f->proof.query_proofs = f->qps;
    f->proof.num_query_proofs = Q_QUERIES;
    f->proof.final_poly = f->final_poly;
    f->proof.num_final_poly = 1; /* 1 << log_final_poly_len(0) */
}

/* ============================================================================
 * Shape-error classification + scenario construction.
 * ========================================================================== */

/* Returns 1 and sets *out if `e` is one of the 6 pre-transcript shape errors. */
static int shape_expected_enum(const char *e, dnac_fri_status_t *out) {
    if (strcmp(e, "QueryCommitPhaseOpeningsCountMismatch") == 0) {
        *out = DNAC_FRI_ERR_QUERY_COMMIT_PHASE_OPENINGS_COUNT_MISMATCH; return 1;
    }
    if (strcmp(e, "InvalidLogArity") == 0) {
        *out = DNAC_FRI_ERR_INVALID_LOG_ARITY; return 1;
    }
    if (strcmp(e, "QueryLogAritiesMismatch") == 0) {
        *out = DNAC_FRI_ERR_QUERY_LOG_ARITIES_MISMATCH; return 1;
    }
    if (strcmp(e, "CommitPowWitnessCountMismatch") == 0) {
        *out = DNAC_FRI_ERR_COMMIT_POW_WITNESS_COUNT_MISMATCH; return 1;
    }
    if (strcmp(e, "FinalPolyLengthMismatch") == 0) {
        *out = DNAC_FRI_ERR_FINAL_POLY_LENGTH_MISMATCH; return 1;
    }
    if (strcmp(e, "QueryProofCountMismatch") == 0) {
        *out = DNAC_FRI_ERR_QUERY_PROOF_COUNT_MISMATCH; return 1;
    }
    return 0;
}

/* Build the V6 base, apply the case's documented mutation, run the prefix. */
static dnac_fri_status_t run_shape_scenario(const char *e) {
    fx_t f;
    fx_base(&f);

    if (strcmp(e, "QueryCommitPhaseOpeningsCountMismatch") == 0) {
        /* errors.json: "duplicate openings[0] appended" -> query0 len 3->4. */
        f.openings[0][3].log_arity = 1;
        f.qps[0].num_commit_phase_openings = 4;
    } else if (strcmp(e, "InvalidLogArity") == 0) {
        /* errors.json: "set log_arity to 0 (invalid)" at query0 round0. */
        f.openings[0][0].log_arity = 0;
    } else if (strcmp(e, "QueryLogAritiesMismatch") == 0) {
        /* errors.json: "bump query 1 round-0 log_arity 1->2 after bumping
         * params.max_log_arity 1->2" -> schedules [1,1,1] vs [2,1,1]. */
        f.params.max_log_arity = 2;
        f.openings[1][0].log_arity = 2;
    } else if (strcmp(e, "CommitPowWitnessCountMismatch") == 0) {
        /* errors.json: "push zero witness" -> witnesses len 3->4. */
        f.proof.num_commit_pow_witnesses = 4;
    } else if (strcmp(e, "FinalPolyLengthMismatch") == 0) {
        /* errors.json: "push zero ext coefficient" -> final_poly len 1->2. */
        f.proof.num_final_poly = 2;
    } else if (strcmp(e, "QueryProofCountMismatch") == 0) {
        /* errors.json: "pop last query proof" -> query_proofs len 2->1. */
        f.proof.num_query_proofs = 1;
    }

    return dnac_fri_test_shape_prefix(&f.params, &f.proof);
}

/* ============================================================================
 * Main
 * ========================================================================== */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <fri_verifier_errors.json>\n", argv[0]);
        return 2;
    }

    printf("============================================================\n");
    printf("F3 — FRI verifier shape-check prefix (Plonky3 82cfad73)\n");
    printf("     verifier.rs:146-246 shape subset; transcript/MMCS/fold/\n");
    printf("     Horner deferred to F4-F7\n");
    printf("============================================================\n");

    /* Self-check: a V6-shaped proof passes the shape prefix (NOT an accept). */
    {
        fx_t f; fx_base(&f);
        dnac_fri_status_t st = dnac_fri_test_shape_prefix(&f.params, &f.proof);
        if (st != DNAC_FRI_OK) {
            printf("FAIL base-valid: shape prefix returned %d, want DNAC_FRI_OK\n", (int)st);
            return 1;
        }
        printf("  base-valid V6 shape ....................... OK (shape clean)\n");
    }

    size_t blen = 0;
    char *blob = slurp(argv[1], &blen);
    if (!blob) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
    js_t s = { blob, 0, blen };

    /* Drift guard: base_fri_params from the vector must match our fixture. */
    uint64_t v_log_blowup = 0, v_log_fpl = 0, v_max_arity = 0, v_num_q = 0;
    int saw_params = 0;

    int ran = 0, passed = 0, deferred = 0, total = 0;

    if (!js_match(&s, '{')) { fprintf(stderr, "bad json root\n"); return 2; }
    while (!js_match(&s, '}')) {
        if (js_peek(&s, ',')) { s.pos++; continue; }
        char *key = js_read_string(&s);
        if (!key) { fprintf(stderr, "bad key\n"); return 2; }
        if (!js_match(&s, ':')) { fprintf(stderr, "missing colon\n"); return 2; }

        if (strcmp(key, "base_fri_params") == 0) {
            saw_params = 1;
            js_match(&s, '{');
            while (!js_match(&s, '}')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                char *pk = js_read_string(&s);
                js_match(&s, ':');
                uint64_t pv = 0; js_read_u64(&s, &pv);
                if (strcmp(pk, "log_blowup") == 0) v_log_blowup = pv;
                else if (strcmp(pk, "log_final_poly_len") == 0) v_log_fpl = pv;
                else if (strcmp(pk, "max_log_arity") == 0) v_max_arity = pv;
                else if (strcmp(pk, "num_queries") == 0) v_num_q = pv;
                free(pk);
            }
        } else if (strcmp(key, "cases") == 0) {
            js_match(&s, '[');
            while (!js_match(&s, ']')) {
                if (js_peek(&s, ',')) { s.pos++; continue; }
                char *name = NULL, *exp = NULL, *poi = NULL;
                js_match(&s, '{');
                while (!js_match(&s, '}')) {
                    if (js_peek(&s, ',')) { s.pos++; continue; }
                    char *ck = js_read_string(&s);
                    js_match(&s, ':');
                    if (strcmp(ck, "name") == 0) name = js_read_string(&s);
                    else if (strcmp(ck, "expected_error") == 0) exp = js_read_string(&s);
                    else if (strcmp(ck, "public_or_isolated") == 0) poi = js_read_string(&s);
                    else js_skip_value(&s);
                    free(ck);
                }
                total++;

                dnac_fri_status_t want;
                if (exp && shape_expected_enum(exp, &want)) {
                    dnac_fri_status_t got = run_shape_scenario(exp);
                    ran++;
                    if (got == want) {
                        passed++;
                        printf("  [RUN ] %-38s -> %-38s OK\n",
                               exp, name ? name : "");
                    } else {
                        printf("  [RUN ] %-38s FAIL got=%d want=%d\n",
                               exp, (int)got, (int)want);
                    }
                } else {
                    deferred++;
                    printf("  [DEFER] %-37s (%s)\n",
                           exp ? exp : "?", poi ? poi : "?");
                }
                free(name); free(exp); free(poi);
            }
        } else {
            js_skip_value(&s);
        }
        free(key);
    }
    free(blob);

    /* Drift guard assertions. */
    if (!saw_params || v_log_blowup != 1 || v_log_fpl != 0 ||
        v_max_arity != 1 || v_num_q != 2) {
        printf("FAIL: base_fri_params drift "
               "(log_blowup=%llu log_final_poly_len=%llu max_log_arity=%llu num_queries=%llu)\n",
               (unsigned long long)v_log_blowup, (unsigned long long)v_log_fpl,
               (unsigned long long)v_max_arity, (unsigned long long)v_num_q);
        return 1;
    }

    printf("------------------------------------------------------------\n");
    printf("  cases total: %d | shape RUN: %d (passed %d) | DEFERRED: %d\n",
           total, ran, passed, deferred);

    if (total == 19 && ran == 6 && passed == 6 && deferred == 13) {
        printf("F3 SHAPE GATE: GREEN — 6/6 shape-prefix cases match Plonky3,\n");
        printf("               13 deferred to F4-F7, no full-verifier claim\n");
        printf("============================================================\n");
        return 0;
    }

    printf("F3 SHAPE GATE: RED — counts off "
           "(want total=19 ran=6 passed=6 deferred=13)\n");
    return 1;
}
