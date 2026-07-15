/**
 * @file test_prover_s7_commit.c
 * @brief S7 (C prover) — quotient blinding + 4-matrix commit byte-match KAT.
 *
 * Vectors:
 *   - tools/vectors/prover_s7_quotient_commit_zk.json — REAL ground truth
 *     (oracle gates G1+G2): quotient_flat, the 64 codeword + 72 blinding
 *     SmallRng(1) draws (D1-B inputs), the 4 committed chunk LDEs, and the
 *     quotient commit root == proof.commitments.quotient_chunks.
 *   - tools/vectors/prover_s2_lde_zk.json — trace-commit draws for the chain.
 *
 * Asserts:
 *   T1  FULL C CHAIN S1->S7: trace -> randomize -> LDE -> Merkle root ->
 *       alpha -> selectors -> quotient_values == vector quotient_flat.
 *   T2  dnac_prover_quotient_commit reproduces all 4 REAL chunk LDEs.
 *   T3  ...and the REAL quotient commit root (the proof's 2nd commitment).
 *   T4  fail-close guards.
 *
 * Build (via Makefile):
 *   make build/test_prover_s7_commit
 *   ./build/test_prover_s7_commit tools/vectors/prover_s7_quotient_commit_zk.json \
 *                                 tools/vectors/prover_s2_lde_zk.json
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

#define S7_H 4u
#define S7_W 56u
#define S7_R 4u
#define S7_RAND_W 60u
#define S7_DRAWS (S7_H * (S7_W + 2u * S7_R))
#define S7_LDE_H 32u
#define S7_LDE_CELLS (S7_LDE_H * S7_RAND_W)
#define S7_QS 16u
#define S7_NQ 4u
#define S7_CW 6u                       /* chunk width 2 + 4 */
#define S7_CODEWORD (S7_NQ * 4u * 4u)  /* 64 */
#define S7_BLINDING (3u * 4u * S7_CW)  /* 72 */
#define S7_CHUNK_LDE_CELLS (S7_LDE_H * S7_CW) /* 192 per chunk */

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

static const char *parse_arr_at(const char *p, uint64_t *out, size_t expect) {
    while (*p && *p != '[') p++;
    if (*p != '[') return NULL;
    p++;
    for (size_t i = 0; i < expect; i++) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ',')
            p++;
        if (*p != '"') return NULL;
        p++;
        if (*p < '0' || *p > '9') return NULL;
        out[i] = strtoull(p, (char **)&p, 10);
        if (*p != '"') return NULL;
        p++;
    }
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return (*p == ']') ? p + 1 : NULL;
}

static bool parse_u64_array(const char *src, const char *key, uint64_t *out,
                            size_t expect) {
    const char *p = find_value(src, key);
    return p != NULL && parse_arr_at(p, out, expect) != NULL;
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

static int compare_cells(const char *tag, const uint64_t *got,
                         const uint64_t *want, size_t n, size_t width) {
    int mism = 0;
    for (size_t i = 0; i < n; i++) {
        if (got[i] != want[i]) {
            if (mism < 3) {
                fprintf(stderr, "%s MISMATCH row=%zu col=%zu: C=%" PRIu64
                                " oracle=%" PRIu64 "\n",
                        tag, i / width, i % width, got[i], want[i]);
            }
            mism++;
        }
    }
    return mism;
}

int main(int argc, char **argv) {
    const char *s7_path = "tools/vectors/prover_s7_quotient_commit_zk.json";
    const char *s2_path = "tools/vectors/prover_s2_lde_zk.json";
    if (argc >= 3) {
        s7_path = argv[1];
        s2_path = argv[2];
    }

    size_t s7_len = 0, s2_len = 0;
    char *s7 = load_file(s7_path, &s7_len);
    char *s2 = load_file(s2_path, &s2_len);
    if (!s7 || !s2) {
        free(s7);
        free(s2);
        return 2;
    }
    printf("loaded %s (%zu bytes) + %s (%zu bytes)\n", s7_path, s7_len,
           s2_path, s2_len);

    static uint64_t qflat_v[2 * S7_QS];
    static uint64_t codeword[S7_CODEWORD];
    static uint64_t blinding[S7_BLINDING];
    static uint64_t chunk_ldes_v[S7_NQ * S7_CHUNK_LDE_CELLS];
    static uint64_t trace_draws[S7_DRAWS];
    uint8_t root_v[DNAC_MERKLE_DIGEST_BYTES];
    if (!parse_u64_array(s7, "quotient_flat", qflat_v, 2 * S7_QS) ||
        !parse_u64_array(s7, "codeword_rand", codeword, S7_CODEWORD) ||
        !parse_u64_array(s7, "blinding_rand", blinding, S7_BLINDING) ||
        !parse_hex_bytes(s7, "quotient_commit_root_hex", root_v,
                         DNAC_MERKLE_DIGEST_BYTES) ||
        !parse_u64_array(s2, "random_draws", trace_draws, S7_DRAWS)) {
        fprintf(stderr, "vector parse FAIL\n");
        free(s7);
        free(s2);
        return 2;
    }
    {
        const char *p = find_value(s7, "chunk_ldes");
        if (!p) {
            fprintf(stderr, "chunk_ldes parse FAIL\n");
            free(s7);
            free(s2);
            return 2;
        }
        while (*p && *p != '[') p++;
        p++;
        for (size_t c = 0; c < S7_NQ; c++) {
            p = parse_arr_at(p, &chunk_ldes_v[c * S7_CHUNK_LDE_CELLS],
                             S7_CHUNK_LDE_CELLS);
            if (!p) {
                fprintf(stderr, "chunk %zu parse FAIL\n", c);
                free(s7);
                free(s2);
                return 2;
            }
            while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' ||
                   *p == ',')
                p++;
        }
    }

    int failed = 0;

    /* ---- T1: FULL C CHAIN S1->S6 == vector quotient_flat ---- */
    static uint64_t qflat_c[2 * S7_QS];
    {
        static uint64_t base_c[S7_H * S7_W];
        static uint64_t randomized_c[2u * S7_H * S7_RAND_W];
        static uint64_t lde_c[S7_LDE_CELLS];
        static uint64_t trace_q[S7_QS * S7_W];
        static uint64_t sf[S7_QS], sl[S7_QS], st[S7_QS], iv[S7_QS];
        uint8_t root_t[DNAC_MERKLE_DIGEST_BYTES];
        dnac_merkle_tree_t *tree = NULL;
        gold_fp2_t alpha;
        dnac_transcript_t *t = dnac_transcript_init_default();
        const uint64_t amounts[4] = {10, 20, 30, 40};
        const uint64_t publics[3] = {107, 7, 4};
        int bad = 1;
        if (t != NULL &&
            dnac_prover_build_range_proof_trace(amounts, 4, 4, base_c, NULL) ==
                DNAC_PROVER_OK &&
            dnac_prover_randomize_trace(base_c, S7_H, S7_W, S7_R, trace_draws,
                                        randomized_c) == DNAC_PROVER_OK &&
            dnac_prover_coset_lde_bitrev(randomized_c, 2 * S7_H, S7_RAND_W, 2,
                                         7, lde_c) == DNAC_PROVER_OK &&
            dnac_prover_commit_matrix(lde_c, S7_LDE_H, S7_RAND_W, NULL, 0, root_t,
                                      &tree) == DNAC_PROVER_OK &&
            dnac_prover_fs_to_alpha(t, 3, 2, 0, root_t, publics, 3, &alpha) ==
                DNAC_PROVER_OK &&
            dnac_prover_quotient_selectors(2, 4, 7, sf, sl, st, iv) ==
                DNAC_PROVER_OK &&
            dnac_prover_trace_on_quotient_domain(lde_c, S7_LDE_H, S7_RAND_W,
                                                 S7_QS, S7_W, trace_q) ==
                DNAC_PROVER_OK &&
            dnac_prover_quotient_values_range_zk(trace_q, S7_QS, 4, publics,
                                                 alpha, sf, sl, st, iv,
                                                 qflat_c) == DNAC_PROVER_OK) {
            bad = compare_cells("T1", qflat_c, qflat_v, 2 * S7_QS, 2);
        }
        dnac_transcript_free(t);
        dnac_merkle_tree_free(tree);
        if (bad) failed++;
        printf("T1 full chain S1->S6 quotient == vector quotient_flat  %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T2+T3: S7 commit — chunk LDEs + the REAL quotient root ---- */
    {
        static uint64_t chunk_ldes_c[S7_NQ * S7_CHUNK_LDE_CELLS];
        uint8_t root_c[DNAC_MERKLE_DIGEST_BYTES];
        dnac_merkle_batch_tree_t *btree = NULL;
        int bad_ldes = 1, bad_root = 1;
        if (dnac_prover_quotient_commit(qflat_c, S7_QS, S7_NQ, 4, 2, 7,
                                        codeword, blinding, NULL, 0, chunk_ldes_c,
                                        root_c, &btree) == DNAC_PROVER_OK) {
            bad_ldes = compare_cells("T2", chunk_ldes_c, chunk_ldes_v,
                                     S7_NQ * S7_CHUNK_LDE_CELLS, S7_CW);
            bad_root = memcmp(root_c, root_v, sizeof(root_c)) != 0;
        }
        dnac_merkle_batch_tree_free(btree);
        if (bad_ldes) failed++;
        if (bad_root) failed++;
        printf("T2 blinded chunk LDEs 4x(32x6) byte-match               %s\n",
               bad_ldes ? "FAIL" : "PASS");
        printf("T3 root == REAL proof.commitments.quotient_chunks      %s\n",
               bad_root ? "FAIL" : "PASS");
    }

    /* ---- T4: fail-close guards ---- */
    {
        static uint64_t chunk_ldes_c[S7_NQ * S7_CHUNK_LDE_CELLS];
        static uint64_t bad_rand[S7_CODEWORD];
        uint8_t root_c[DNAC_MERKLE_DIGEST_BYTES];
        dnac_merkle_batch_tree_t *btree = NULL;
        int bad = 0;
        memcpy(bad_rand, codeword, sizeof(bad_rand));
        bad_rand[10] = GOLDILOCKS_P;
        if (dnac_prover_quotient_commit(qflat_c, S7_QS, S7_NQ, 4, 2, 7,
                                        bad_rand, blinding, NULL, 0, chunk_ldes_c,
                                        root_c, &btree) !=
            DNAC_PROVER_ERR_NONCANONICAL)
            bad++;
        if (dnac_prover_quotient_commit(qflat_c, S7_QS, 1, 4, 2, 7, codeword,
                                        blinding, NULL, 0, chunk_ldes_c, root_c,
                                        &btree) != DNAC_PROVER_ERR_PARAM)
            bad++; /* num_chunks < 2 breaks hiding */
        if (dnac_prover_quotient_commit(qflat_c, S7_QS, S7_NQ, 4, 0, 7,
                                        codeword, blinding, NULL, 0, chunk_ldes_c,
                                        root_c, &btree) !=
            DNAC_PROVER_ERR_PARAM)
            bad++;
        if (bad) failed++;
        printf("T4 fail-close guards: 3/3 rejects                       %s\n",
               bad ? "FAIL" : "PASS");
    }

    free(s7);
    free(s2);
    if (failed == 0) {
        printf("test_prover_s7_commit: PASS\n");
        printf("S7 PROVER-COMMIT GATE: GREEN — full C chain S1->S7 reproduces "
               "the REAL proof.commitments.quotient_chunks (blinding + chunk "
               "LDEs + 4-matrix SHA3-512 commit, Plonky3 82cfad73)\n");
        return 0;
    }
    printf("S7 PROVER-COMMIT GATE: RED — %d failures\n", failed);
    return 1;
}
