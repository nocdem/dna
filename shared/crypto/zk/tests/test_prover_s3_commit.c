/**
 * @file test_prover_s3_commit.c
 * @brief S3 (C prover) — Merkle BUILD byte-match KAT vs the REAL trace commit.
 *
 * Reuses tools/vectors/prover_s2_lde_zk.json: its `lde_bitrev` is the real
 * committed matrix and `trace_commit_root_hex` is proof.commitments.trace
 * from a REAL is_zk=1 p3_uni_stark::prove (oracle gates G1-G3). Asserts:
 *
 *   T1  dnac_prover_commit_matrix(lde_bitrev) root == trace_commit_root_hex
 *       (isolated S3: serialization + tree build).
 *   T2  Full C chain S1 -> S2 randomize -> S2 LDE -> S3 commit reproduces the
 *       SAME root — the first three prover stages end-to-end against the real
 *       Plonky3 trace commitment.
 *   T3  The retained tree handle serves open + verify roundtrips (S12 prep).
 *   T4  Fail-close guards (non-canonical cell, bad height).
 *
 * Build (via Makefile):
 *   make build/test_prover_s3_commit
 *   ./build/test_prover_s3_commit tools/vectors/prover_s2_lde_zk.json
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

#define S3_H 4u
#define S3_W 56u
#define S3_R 4u
#define S3_RAND_W 60u
#define S3_DRAWS (S3_H * (S3_W + 2u * S3_R))
#define S3_LDE_H 32u
#define S3_LDE_CELLS (S3_LDE_H * S3_RAND_W)

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
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    return *p == ']';
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

int main(int argc, char **argv) {
    const char *path = "tools/vectors/prover_s2_lde_zk.json";
    if (argc >= 2) path = argv[1];

    size_t len = 0;
    char *src = load_file(path, &len);
    if (!src) return 2;
    printf("loaded %s (%zu bytes)\n", path, len);

    static uint64_t lde_vec[S3_LDE_CELLS];
    static uint64_t draws[S3_DRAWS];
    uint8_t root_expect[DNAC_MERKLE_DIGEST_BYTES];
    if (!parse_u64_array(src, "lde_bitrev", lde_vec, S3_LDE_CELLS) ||
        !parse_u64_array(src, "random_draws", draws, S3_DRAWS) ||
        !parse_hex_bytes(src, "trace_commit_root_hex", root_expect,
                         DNAC_MERKLE_DIGEST_BYTES)) {
        fprintf(stderr, "vector parse FAIL\n");
        free(src);
        return 2;
    }

    int failed = 0;

    /* ---- T1: isolated S3 — commit the oracle's committed matrix ---- */
    dnac_merkle_tree_t *tree = NULL;
    {
        uint8_t root[DNAC_MERKLE_DIGEST_BYTES];
        int bad = 1;
        if (dnac_prover_commit_matrix(lde_vec, S3_LDE_H, S3_RAND_W, NULL, 0, root,
                                      &tree) == DNAC_PROVER_OK) {
            bad = memcmp(root, root_expect, sizeof(root)) != 0;
        }
        if (bad) failed++;
        printf("T1 S3 commit(lde_bitrev) == proof.commitments.trace     %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T2: full chain S1 -> S2 -> S3 against the real root ---- */
    {
        static uint64_t base_c[S3_H * S3_W];
        static uint64_t randomized_c[2u * S3_H * S3_RAND_W];
        static uint64_t lde_c[S3_LDE_CELLS];
        uint8_t root[DNAC_MERKLE_DIGEST_BYTES];
        dnac_merkle_tree_t *chain_tree = NULL;
        const uint64_t amounts[4] = {10, 20, 30, 40};
        int bad = 1;
        if (dnac_prover_build_range_proof_trace(amounts, 4, 4, base_c, NULL) ==
                DNAC_PROVER_OK &&
            dnac_prover_randomize_trace(base_c, S3_H, S3_W, S3_R, draws,
                                        randomized_c) == DNAC_PROVER_OK &&
            dnac_prover_coset_lde_bitrev(randomized_c, 2 * S3_H, S3_RAND_W, 2,
                                         7, lde_c) == DNAC_PROVER_OK &&
            dnac_prover_commit_matrix(lde_c, S3_LDE_H, S3_RAND_W, NULL, 0, root,
                                      &chain_tree) == DNAC_PROVER_OK) {
            bad = memcmp(root, root_expect, sizeof(root)) != 0;
        }
        dnac_merkle_tree_free(chain_tree);
        if (bad) failed++;
        printf("T2 full chain S1->S2->S3 root == real trace commitment  %s\n",
               bad ? "FAIL" : "PASS");
    }

    /* ---- T3: tree handle serves open+verify (S12 prep) ---- */
    {
        int bad = 0;
        const uint64_t idx[2] = {0, 31};
        for (size_t k = 0; k < 2 && tree != NULL; k++) {
            dnac_merkle_digest_t sib[5]; /* depth = log2(32) */
            dnac_merkle_proof_t proof;
            memset(&proof, 0, sizeof(proof));
            proof.siblings = sib;
            proof.depth = 5;
            const uint8_t *leaf = NULL;
            size_t leaf_len = 0;
            if (dnac_merkle_open(tree, idx[k], &leaf, &leaf_len, &proof) !=
                    DNAC_MERKLE_OK ||
                leaf_len != S3_RAND_W * 8) {
                bad++;
                continue;
            }
            dnac_merkle_digest_t root_d;
            memcpy(root_d.bytes, root_expect, sizeof(root_d.bytes));
            if (dnac_merkle_verify(&root_d, leaf, leaf_len, &proof) !=
                DNAC_MERKLE_OK) {
                bad++;
            }
        }
        if (tree == NULL) bad++;
        if (bad) failed++;
        printf("T3 open(0,31) + verify vs real root (S12 prep)          %s\n",
               bad ? "FAIL" : "PASS");
    }
    dnac_merkle_tree_free(tree);

    /* ---- T4: fail-close guards ---- */
    {
        static uint64_t bad_mat[S3_LDE_CELLS];
        uint8_t root[DNAC_MERKLE_DIGEST_BYTES];
        dnac_merkle_tree_t *t = NULL;
        int bad = 0;
        memcpy(bad_mat, lde_vec, sizeof(bad_mat));
        bad_mat[7] = GOLDILOCKS_P; /* non-canonical cell */
        if (dnac_prover_commit_matrix(bad_mat, S3_LDE_H, S3_RAND_W, NULL, 0, root, &t) !=
                DNAC_PROVER_ERR_NONCANONICAL ||
            t != NULL)
            bad++;
        t = NULL;
        if (dnac_prover_commit_matrix(lde_vec, 24, S3_RAND_W, NULL, 0, root, &t) !=
                DNAC_PROVER_ERR_PARAM /* non-power-of-two height */
            || t != NULL)
            bad++;
        t = NULL;
        if (dnac_prover_commit_matrix(lde_vec, S3_LDE_H, 0, NULL, 0, root, &t) !=
                DNAC_PROVER_ERR_PARAM ||
            t != NULL)
            bad++;
        if (bad) failed++;
        printf("T4 fail-close guards: 3/3 rejects                        %s\n",
               bad ? "FAIL" : "PASS");
    }

    free(src);
    if (failed == 0) {
        printf("test_prover_s3_commit: PASS\n");
        printf("S3 PROVER-COMMIT GATE: GREEN — C Merkle BUILD reproduces the "
               "REAL proof.commitments.trace (Plonky3 82cfad73); S1->S2->S3 "
               "chain end-to-end; open/verify roundtrip held\n");
        return 0;
    }
    printf("S3 PROVER-COMMIT GATE: RED — %d failures\n", failed);
    return 1;
}
