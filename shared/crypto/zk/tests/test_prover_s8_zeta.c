/**
 * @file test_prover_s8_zeta.c
 * @brief S8 (C prover) — random commit + Fiat-Shamir-to-zeta byte-match KAT.
 *
 * Vectors:
 *   - prover_s8_random_zk.json  — 48 R draws @ stream 392 (D1-B) + the REAL
 *     proof.commitments.random root (oracle gates G1+G2).
 *   - prover_s7_quotient_commit_zk.json — quotient draws (chain).
 *   - prover_s2_lde_zk.json     — trace draws (chain).
 *   - range_proof_air_zk.json   — the REAL zeta / zeta_next (transcript
 *     ground truth from p3_uni_stark).
 *
 * Asserts:
 *   T1  dnac_prover_random_commit(48 draws) == proof.commitments.random.
 *   T2  FULL C CHAIN S1->S8: both commits + fs_to_zeta reproduce the REAL
 *       zeta AND zeta_next.
 *   T3  teeth: omitting the random-root observe changes zeta (order is
 *       load-bearing).
 *   T4  fail-close guards.
 *
 * Build (via Makefile):
 *   make build/test_prover_s8_zeta
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
#include "../stark_prover.h"

#define S8_H 4u
#define S8_W 56u
#define S8_R 4u
#define S8_RAND_W 60u
#define S8_TRACE_DRAWS (S8_H * (S8_W + 2u * S8_R))
#define S8_LDE_H 32u
#define S8_LDE_CELLS (S8_LDE_H * S8_RAND_W)
#define S8_QS 16u
#define S8_NQ 4u
#define S8_CW 6u
#define S8_CODEWORD 64u
#define S8_BLINDING 72u
#define S8_RD 48u /* R draws: 8x6 */
#define S8_R_LDE_CELLS (S8_LDE_H * S8_CW)

static char *load_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(buf);
        return NULL;
    }
    buf[sz] = '\0';
    *out_len = (size_t)sz;
    return buf;
}

static const char *find_value(const char *src, const char *key) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":", key);
    const char *p = strstr(src, needle);
    if (!p) return NULL;
    return p + strlen(needle);
}

static bool read_u64_at(const char *p, uint64_t *out) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p == '"') p++;
    if (*p < '0' || *p > '9') return false;
    *out = strtoull(p, NULL, 10);
    return true;
}

static bool parse_u64_array(const char *src, const char *key, uint64_t *out,
                            size_t expect) {
    const char *p = find_value(src, key);
    if (!p) return false;
    while (*p && *p != '[') p++;
    if (*p != '[') return false;
    p++;
    for (size_t i = 0; i < expect; i++) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')
            p++;
        if (*p != '"') return false;
        p++;
        if (*p < '0' || *p > '9') return false;
        out[i] = strtoull(p, (char **)&p, 10);
        if (*p != '"') return false;
        p++;
    }
    return true;
}

static bool parse_hex_bytes(const char *src, const char *key, uint8_t *out,
                            size_t expect_bytes) {
    const char *p = find_value(src, key);
    if (!p) return false;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return false;
    p++;
    for (size_t i = 0; i < expect_bytes; i++) {
        unsigned hi, lo;
        if (sscanf(p, "%1x%1x", &hi, &lo) != 2) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
        p += 2;
    }
    return *p == '"';
}

/* fp2 under an anchor key like "zeta_fp2": {"c0_decimal": "...", ...} */
static bool parse_fp2_anchored(const char *src, const char *anchor,
                               uint64_t *c0, uint64_t *c1) {
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\"", anchor);
    const char *a = strstr(src, needle);
    if (!a) return false;
    const char *p0 = find_value(a, "c0_decimal");
    const char *p1 = find_value(a, "c1_decimal");
    return p0 && p1 && read_u64_at(p0, c0) && read_u64_at(p1, c1);
}

int main(int argc, char **argv) {
    const char *s8_path = "tools/vectors/prover_s8_random_zk.json";
    const char *s7_path = "tools/vectors/prover_s7_quotient_commit_zk.json";
    const char *s2_path = "tools/vectors/prover_s2_lde_zk.json";
    const char *m3a_path = "tools/vectors/range_proof_air_zk.json";
    if (argc >= 5) {
        s8_path = argv[1];
        s7_path = argv[2];
        s2_path = argv[3];
        m3a_path = argv[4];
    }

    size_t l8 = 0, l7 = 0, l2 = 0, lm = 0;
    char *s8 = load_file(s8_path, &l8);
    char *s7 = load_file(s7_path, &l7);
    char *s2 = load_file(s2_path, &l2);
    char *m3a = load_file(m3a_path, &lm);
    if (!s8 || !s7 || !s2 || !m3a) {
        free(s8);
        free(s7);
        free(s2);
        free(m3a);
        return 2;
    }
    printf("loaded 4 vectors (%zu + %zu + %zu + %zu bytes)\n", l8, l7, l2, lm);

    static uint64_t r_draws[S8_RD];
    static uint64_t trace_draws[S8_TRACE_DRAWS];
    static uint64_t codeword[S8_CODEWORD];
    static uint64_t blinding[S8_BLINDING];
    uint8_t random_root_v[DNAC_MERKLE_DIGEST_BYTES];
    uint64_t zeta_c0 = 0, zeta_c1 = 0, zn_c0 = 0, zn_c1 = 0;
    if (!parse_u64_array(s8, "r_draws", r_draws, S8_RD) ||
        !parse_hex_bytes(s8, "random_commit_root_hex", random_root_v,
                         DNAC_MERKLE_DIGEST_BYTES) ||
        !parse_u64_array(s7, "codeword_rand", codeword, S8_CODEWORD) ||
        !parse_u64_array(s7, "blinding_rand", blinding, S8_BLINDING) ||
        !parse_u64_array(s2, "random_draws", trace_draws, S8_TRACE_DRAWS) ||
        !parse_fp2_anchored(m3a, "zeta_fp2", &zeta_c0, &zeta_c1) ||
        !parse_fp2_anchored(m3a, "zeta_next_fp2", &zn_c0, &zn_c1)) {
        fprintf(stderr, "vector parse FAIL\n");
        free(s8);
        free(s7);
        free(s2);
        free(m3a);
        return 2;
    }

    int failed = 0;

    /* ---- T1: R commit == proof.commitments.random ---- */
    static uint64_t r_lde[S8_R_LDE_CELLS];
    uint8_t r_root[DNAC_MERKLE_DIGEST_BYTES];
    {
        dnac_merkle_tree_t *rt = NULL;
        int bad = 1;
        if (dnac_prover_random_commit(r_draws, 8, S8_CW, 2, r_lde, r_root,
                                      &rt) == DNAC_PROVER_OK) {
            bad = memcmp(r_root, random_root_v, sizeof(r_root)) != 0;
        }
        dnac_merkle_tree_free(rt);
        if (bad) failed++;
        printf("T1 R commit(48 draws) == proof.commitments.random       %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T2: FULL CHAIN S1->S8 — zeta/zeta_next == REAL values ---- */
    {
        static uint64_t base_c[S8_H * S8_W];
        static uint64_t randomized_c[2u * S8_H * S8_RAND_W];
        static uint64_t lde_c[S8_LDE_CELLS];
        static uint64_t trace_q[S8_QS * S8_W];
        static uint64_t sf[S8_QS], sl[S8_QS], st[S8_QS], iv[S8_QS];
        static uint64_t qflat[2 * S8_QS];
        static uint64_t chunk_ldes[S8_NQ * S8_LDE_H * S8_CW];
        uint8_t troot[DNAC_MERKLE_DIGEST_BYTES];
        uint8_t qroot[DNAC_MERKLE_DIGEST_BYTES];
        dnac_merkle_tree_t *ttree = NULL;
        dnac_merkle_batch_tree_t *qtree = NULL;
        gold_fp2_t alpha, zeta, zeta_next;
        dnac_transcript_t *t = dnac_transcript_init_default();
        const uint64_t amounts[4] = {10, 20, 30, 40};
        const uint64_t publics[3] = {107, 7, 4};
        int bad = 1;
        if (t != NULL &&
            dnac_prover_build_range_proof_trace(amounts, 4, 4, base_c, NULL) ==
                DNAC_PROVER_OK &&
            dnac_prover_randomize_trace(base_c, S8_H, S8_W, S8_R, trace_draws,
                                        randomized_c) == DNAC_PROVER_OK &&
            dnac_prover_coset_lde_bitrev(randomized_c, 2 * S8_H, S8_RAND_W, 2,
                                         7, lde_c) == DNAC_PROVER_OK &&
            dnac_prover_commit_matrix(lde_c, S8_LDE_H, S8_RAND_W, troot,
                                      &ttree) == DNAC_PROVER_OK &&
            dnac_prover_fs_to_alpha(t, 3, 2, 0, troot, publics, 3, &alpha) ==
                DNAC_PROVER_OK &&
            dnac_prover_quotient_selectors(2, 4, 7, sf, sl, st, iv) ==
                DNAC_PROVER_OK &&
            dnac_prover_trace_on_quotient_domain(lde_c, S8_LDE_H, S8_RAND_W,
                                                 S8_QS, S8_W, trace_q) ==
                DNAC_PROVER_OK &&
            dnac_prover_quotient_values_range_zk(trace_q, S8_QS, 4, publics,
                                                 alpha, sf, sl, st, iv,
                                                 qflat) == DNAC_PROVER_OK &&
            dnac_prover_quotient_commit(qflat, S8_QS, S8_NQ, 4, 2, 7, codeword,
                                        blinding, chunk_ldes, qroot,
                                        &qtree) == DNAC_PROVER_OK &&
            dnac_prover_fs_to_zeta(t, qroot, r_root, 2, &zeta, &zeta_next) ==
                DNAC_PROVER_OK) {
            bad = !(gold_fp_to_u64(zeta.a) == zeta_c0 &&
                    gold_fp_to_u64(zeta.b) == zeta_c1 &&
                    gold_fp_to_u64(zeta_next.a) == zn_c0 &&
                    gold_fp_to_u64(zeta_next.b) == zn_c1);
            if (bad) {
                fprintf(stderr,
                        "T2 zeta MISMATCH: C=(%" PRIu64 ",%" PRIu64
                        ") real=(%" PRIu64 ",%" PRIu64 ")\n",
                        gold_fp_to_u64(zeta.a), gold_fp_to_u64(zeta.b),
                        zeta_c0, zeta_c1);
            }
        }
        dnac_transcript_free(t);
        dnac_merkle_tree_free(ttree);
        dnac_merkle_batch_tree_free(qtree);
        if (bad) failed++;
        printf("T2 FULL CHAIN S1->S8: zeta + zeta_next == REAL values   %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T3: teeth — skipping the random observe changes zeta ---- */
    {
        /* replay only the transcript part with a synthetic post-alpha state:
         * use a fresh transcript, drive to alpha with the REAL roots, then
         * sample zeta once WITH and once WITHOUT the random observe. */
        static uint64_t qroot_dummy[8]; /* reuse T1 r_root as a stand-in */
        (void)qroot_dummy;
        const uint64_t publics[3] = {107, 7, 4};
        gold_fp2_t a1, z_with, z_without, zn;
        dnac_transcript_t *ta = dnac_transcript_init_default();
        dnac_transcript_t *tb = dnac_transcript_init_default();
        int bad = 1;
        if (ta && tb &&
            dnac_prover_fs_to_alpha(ta, 3, 2, 0, random_root_v, publics, 3,
                                    &a1) == DNAC_PROVER_OK &&
            dnac_prover_fs_to_alpha(tb, 3, 2, 0, random_root_v, publics, 3,
                                    &a1) == DNAC_PROVER_OK &&
            dnac_prover_fs_to_zeta(ta, random_root_v, r_root, 2, &z_with,
                                   &zn) == DNAC_PROVER_OK &&
            dnac_prover_fs_to_zeta(tb, random_root_v, NULL, 2, &z_without,
                                   &zn) == DNAC_PROVER_OK) {
            bad = (gold_fp_to_u64(z_with.a) == gold_fp_to_u64(z_without.a) &&
                   gold_fp_to_u64(z_with.b) == gold_fp_to_u64(z_without.b));
        }
        dnac_transcript_free(ta);
        dnac_transcript_free(tb);
        if (bad) failed++;
        printf("T3 teeth: random-root observe is load-bearing           %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T4: fail-close guards ---- */
    {
        static uint64_t bad_draws[S8_RD];
        static uint64_t lde_t[S8_R_LDE_CELLS];
        uint8_t root_t[DNAC_MERKLE_DIGEST_BYTES];
        dnac_merkle_tree_t *rt = NULL;
        gold_fp2_t z, zn;
        int bad = 0;
        memcpy(bad_draws, r_draws, sizeof(bad_draws));
        bad_draws[5] = GOLDILOCKS_P;
        if (dnac_prover_random_commit(bad_draws, 8, S8_CW, 2, lde_t, root_t,
                                      &rt) != DNAC_PROVER_ERR_NONCANONICAL)
            bad++;
        if (dnac_prover_random_commit(r_draws, 6, S8_CW, 2, lde_t, root_t,
                                      &rt) != DNAC_PROVER_ERR_PARAM)
            bad++; /* non-power-of-two height */
        if (dnac_prover_fs_to_zeta(NULL, random_root_v, NULL, 2, &z, &zn) !=
            DNAC_PROVER_ERR_PARAM)
            bad++;
        if (bad) failed++;
        printf("T4 fail-close guards: 3/3 rejects                       %s\n",
               bad ? "FAIL" : "PASS");
    }

    free(s8);
    free(s7);
    free(s2);
    free(m3a);
    if (failed == 0) {
        printf("test_prover_s8_zeta: PASS\n");
        printf("S8 PROVER-ZETA GATE: GREEN — C random commit == "
               "proof.commitments.random; full chain S1->S8 reproduces the "
               "REAL zeta/zeta_next (Plonky3 82cfad73)\n");
        return 0;
    }
    printf("S8 PROVER-ZETA GATE: RED — %d failures\n", failed);
    return 1;
}
