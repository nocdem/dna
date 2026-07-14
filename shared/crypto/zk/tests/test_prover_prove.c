/**
 * @file test_prover_prove.c
 * @brief P1 (C prover) — library-level dnac_prover_prove on ARBITRARY instances.
 *
 * Proves that the C prover works for instances other than the M3a byte-match
 * point. Loads prover_full_{a,b}.json (full SmallRng(1) draw stream + REAL
 * is_zk proof cross-check values) and for each instance:
 *
 *   T1  dnac_prover_prove -> DNAC_PROVER_OK (which means the library assembled a
 *       proof AND self-verified it: dnac_stark_prime_transcript + dnac_fri_verify
 *       == DNAC_FRI_OK, with out.zeta == prover zeta).
 *   T2  derived shape (degree_bits, num_fri_rounds, log_max_height) == the REAL
 *       proof's shape (grounding, not self-consistency).
 *   T3  cross-check the assembled proof's commit roots + zeta + final_poly
 *       against the REAL Plonky3 proof (byte-match, not just "verifies").
 *   T4  independent re-verify: dnac_prover_proof_verify == DNAC_FRI_OK.
 *
 * Instance A = M3a (height 4, 1 FRI round); instance B = height 8, 2 FRI rounds,
 * 6-bit query indices — exercising the multi-round FRI commit phase + generalized
 * answer_query (the paths the S13 red-team flagged as byte-unverified).
 *
 * Build (via Makefile):
 *   make build/test_prover_prove
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../field_goldilocks.h"
#include "../stark_prover_prove.h"

static char *load_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}
static const char *find_value(const char *src, const char *key) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(src, needle);
    return p ? p + strlen(needle) : NULL;
}
static bool read_u64_at(const char *p, uint64_t *out) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '"') p++;
    if (*p < '0' || *p > '9') return false;
    *out = strtoull(p, NULL, 10);
    return true;
}
static bool parse_u64_field(const char *src, const char *key, uint64_t *out) {
    const char *p = find_value(src, key);
    return p && read_u64_at(p, out);
}
/* Parse a JSON array of decimal-string u64 into a malloc'd array. */
static uint64_t *parse_u64_array(const char *src, const char *key, size_t *n) {
    const char *p = find_value(src, key);
    if (!p) return NULL;
    while (*p && *p != '[') p++;
    if (*p != '[') return NULL;
    p++;
    size_t cap = 16, cnt = 0;
    uint64_t *out = (uint64_t *)malloc(cap * sizeof(uint64_t));
    while (1) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',') p++;
        if (*p == ']') break;
        if (*p != '"') { free(out); return NULL; }
        p++;
        if (cnt == cap) { cap *= 2; out = (uint64_t *)realloc(out, cap * sizeof(uint64_t)); }
        out[cnt++] = strtoull(p, (char **)&p, 10);
        if (*p != '"') { free(out); return NULL; }
        p++;
    }
    *n = cnt;
    return out;
}
static bool parse_hex(const char *src, const char *key, uint8_t *out, size_t nbytes) {
    const char *p = find_value(src, key);
    if (!p) return false;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return false;
    p++;
    for (size_t i = 0; i < nbytes; i++) {
        unsigned hi, lo;
        if (sscanf(p, "%1x%1x", &hi, &lo) != 2) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
    return true;
}
static bool parse_fp2(const char *src, const char *key, uint64_t *c0, uint64_t *c1) {
    size_t n = 0;
    uint64_t *a = parse_u64_array(src, key, &n);
    if (!a || n != 2) { free(a); return false; }
    *c0 = a[0]; *c1 = a[1];
    free(a);
    return true;
}

/* Access the assembled proof internals for the cross-check. We rely on the
 * proof-shape accessors + a re-verify; deep byte-match of roots/final_poly is
 * done by re-deriving them here from the returned handle via the public verify
 * path is not exposed, so this test cross-checks the SHAPE + verify, and the
 * REAL roots are matched by the S1->S12 per-stage KATs for instance A and by
 * the multi-round-verify for instance B. */

static int run_instance(const char *tag, const char *path) {
    size_t blen = 0;
    char *j = load_file(path, &blen);
    if (!j) return 1;

    uint64_t height = 0, n_real = 0, fee = 0, degree_bits = 0, log_mh = 0, rounds = 0;
    parse_u64_field(j, "height", &height);
    parse_u64_field(j, "n_real", &n_real);
    if (!parse_u64_field(j, "fee", &fee)) { /* fee is under instance */ }
    parse_u64_field(j, "degree_bits", &degree_bits);
    parse_u64_field(j, "log_max_height", &log_mh);
    parse_u64_field(j, "num_commit_phase_rounds", &rounds);
    /* fee is a string under "instance" */
    { const char *fp = find_value(j, "fee"); if (fp) read_u64_at(fp, &fee); }

    size_t namt = 0, ndraws = 0;
    uint64_t *amounts = parse_u64_array(j, "amounts", &namt);
    uint64_t *draws = parse_u64_array(j, "draws", &ndraws);
    if (!amounts || !draws) {
        fprintf(stderr, "%s: parse FAIL (amounts/draws)\n", tag);
        free(j); free(amounts); free(draws);
        return 1;
    }

    int failed = 0;
    printf("── instance %s: height=%" PRIu64 " n_real=%" PRIu64
           " degree_bits=%" PRIu64 " rounds=%" PRIu64 " draws=%zu\n",
           tag, height, n_real, degree_bits, rounds, ndraws);

    dnac_prover_instance_t inst;
    inst.amounts = amounts;
    inst.n_real = (size_t)n_real;
    inst.height = (size_t)height;
    inst.fee = fee;
    inst.draws = draws;
    inst.num_draws = ndraws;

    dnac_prover_proof_t *proof = NULL;
    dnac_prover_status_t st = dnac_prover_prove(&inst, &proof);

    /* T1: prove + self-verify */
    int t1 = (st == DNAC_PROVER_OK && proof != NULL);
    if (!t1) { fprintf(stderr, "%s T1: prove status=%d\n", tag, (int)st); failed++; }
    printf("%s T1 dnac_prover_prove -> OK (self-verified)          %s\n",
           tag, t1 ? "PASS" : "FAIL");

    if (proof) {
        /* T2: derived shape == REAL */
        int t2 = (dnac_prover_proof_degree_bits(proof) == degree_bits &&
                  dnac_prover_proof_num_fri_rounds(proof) == rounds &&
                  dnac_prover_proof_log_max_height(proof) == log_mh);
        if (!t2) failed++;
        printf("%s T2 derived shape == REAL proof shape                %s\n",
               tag, t2 ? "PASS" : "FAIL");

        /* T4: independent re-verify */
        int t4 = (dnac_prover_proof_verify(proof) == 0 /*DNAC_FRI_OK*/);
        if (!t4) failed++;
        printf("%s T4 dnac_prover_proof_verify == DNAC_FRI_OK          %s\n",
               tag, t4 ? "PASS" : "FAIL");

        dnac_prover_proof_free(proof);
    } else {
        failed += 2;
    }

    free(j); free(amounts); free(draws);
    return failed;
}

/* T3: byte-match the C proof's zeta + 3 commit roots + final_poly against the
 * REAL Plonky3 proof (grounding, not self-consistency). Separate pass because
 * it needs the produced handle. */
static int cross_check(const char *tag, const char *path) {
    size_t blen = 0;
    char *j = load_file(path, &blen);
    if (!j) return 1;
    uint64_t height = 0, n_real = 0, fee = 0, ndraws = 0, namt = 0;
    parse_u64_field(j, "height", &height);
    parse_u64_field(j, "n_real", &n_real);
    { const char *fp = find_value(j, "fee"); if (fp) read_u64_at(fp, &fee); }
    uint64_t *amounts = parse_u64_array(j, "amounts", &namt);
    uint64_t *draws = parse_u64_array(j, "draws", &ndraws);
    if (!amounts || !draws) { free(j); free(amounts); free(draws); return 1; }

    dnac_prover_instance_t inst = {amounts, (size_t)n_real, (size_t)height, fee,
                                   draws, ndraws};
    dnac_prover_proof_t *proof = NULL;
    if (dnac_prover_prove(&inst, &proof) != DNAC_PROVER_OK || !proof) {
        free(j); free(amounts); free(draws);
        return 1;
    }

    int bad = 0;
    /* zeta / zeta_next */
    {
        uint64_t z0, z1, zn0, zn1;
        gold_fp2_t z, zn;
        dnac_prover_proof_zeta(proof, &z, &zn);
        if (!parse_fp2(j, "zeta", &z0, &z1) ||
            !parse_fp2(j, "zeta_next", &zn0, &zn1) ||
            gold_fp_to_u64(z.a) != z0 || gold_fp_to_u64(z.b) != z1 ||
            gold_fp_to_u64(zn.a) != zn0 || gold_fp_to_u64(zn.b) != zn1)
            bad++;
    }
    /* commit roots */
    {
        uint8_t tr[64], qr[64], rr[64], vtr[64], vqr[64], vrr[64];
        dnac_prover_proof_roots(proof, tr, qr, rr);
        if (!parse_hex(j, "trace_commit_root_hex", vtr, 64) ||
            !parse_hex(j, "quotient_commit_root_hex", vqr, 64) ||
            !parse_hex(j, "random_commit_root_hex", vrr, 64) ||
            memcmp(tr, vtr, 64) || memcmp(qr, vqr, 64) || memcmp(rr, vrr, 64))
            bad++;
    }
    /* final_poly */
    {
        size_t fpl = 0, vn = 0;
        const gold_fp2_t *fp = dnac_prover_proof_final_poly(proof, &fpl);
        uint64_t *vfp = parse_u64_array(j, "final_poly", &vn);
        if (!vfp || vn != fpl * 2) {
            bad++;
        } else {
            for (size_t i = 0; i < fpl; i++)
                if (gold_fp_to_u64(fp[i].a) != vfp[2 * i] ||
                    gold_fp_to_u64(fp[i].b) != vfp[2 * i + 1])
                    bad++;
        }
        free(vfp);
    }
    /* query indices (closes the query-phase byte-anchor gap, red-team A8) */
    {
        uint64_t idx_c[8];
        size_t nq = dnac_prover_proof_query_indices(proof, idx_c, 8);
        size_t vn = 0;
        uint64_t *vidx = parse_u64_array(j, "query_indices", &vn);
        if (!vidx || vn != nq) {
            bad++;
        } else {
            for (size_t i = 0; i < nq; i++)
                if (idx_c[i] != vidx[i]) bad++;
        }
        free(vidx);
    }
    printf("%s T3 zeta + 3 roots + final_poly + query indices == REAL %s\n",
           tag, bad ? "FAIL" : "PASS");

    dnac_prover_proof_free(proof);
    free(j); free(amounts); free(draws);
    return bad ? 1 : 0;
}

int main(int argc, char **argv) {
    const char *pa = "tools/vectors/prover_full_a.json";
    const char *pb = "tools/vectors/prover_full_b.json";
    const char *pc = "tools/vectors/prover_full_c.json";
    if (argc >= 4) { pa = argv[1]; pb = argv[2]; pc = argv[3]; }

    int failed = 0;
    failed += run_instance("A", pa);
    failed += cross_check("A", pa);
    failed += run_instance("B", pb);
    failed += cross_check("B", pb);
    /* instance C: height 16, PADDED (n_real=12<16), 3 FRI rounds, 7-bit
     * indices — exercises the multi-round answer_query + padded is_zk path. */
    failed += run_instance("C", pc);
    failed += cross_check("C", pc);

    if (failed == 0) {
        printf("test_prover_prove: PASS\n");
        printf("P1 PROVE GATE: GREEN — dnac_prover_prove produces a "
               "C-verified proof for BOTH the M3a instance AND a larger "
               "height-8 instance (2 FRI rounds, 6-bit indices); shapes derived "
               "from the instance match the REAL Plonky3 proof (82cfad73).\n");
        return 0;
    }
    printf("P1 PROVE GATE: RED — %d failures\n", failed);
    return 1;
}
