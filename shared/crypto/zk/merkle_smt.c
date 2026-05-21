/**
 * @file merkle_smt.c
 * @brief Sparse-style binary Merkle tree for STARK proof commitments (DNAC v3)
 *
 * Implements design doc § 4.4 (Determinism invariant D4, D4.1).
 * All hashing is SHA3-512 (FIPS-202), per Option B unified primitive (§ 4.2).
 *
 * Domain separators:
 *   "DNAC_RP_LEAF\0"  (13 bytes)
 *   "DNAC_RP_NODE\0"
 *   "DNAC_RP_NULL\0"
 *
 * Big-endian u32 for leaf/null indices (canonical wire order).
 *
 * Cross-validated against Plonky3 oracle in tools/vectors/merkle.json.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "merkle_smt.h"

#include <stdlib.h>
#include <string.h>

#include "crypto/hash/qgp_sha3.h"

/* ============================================================================
 * Internal helpers
 * ========================================================================== */

/** Write u32 in big-endian into the given 4-byte buffer. */
static void u32_to_be(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)((v >> 24) & 0xff);
    out[1] = (uint8_t)((v >> 16) & 0xff);
    out[2] = (uint8_t)((v >> 8) & 0xff);
    out[3] = (uint8_t)(v & 0xff);
}

/* ============================================================================
 * Domain-separated hashing primitives (§ 4.4)
 * ========================================================================== */

void merkle_smt_hash_leaf(uint32_t index,
                          const uint8_t *value,
                          size_t value_len,
                          uint8_t out_hash[MERKLE_SMT_HASH_SIZE]) {
    /* SHA3-512( "DNAC_RP_LEAF\0" || index_BE_u32 || value ) */
    size_t buf_len = MERKLE_SMT_LEAF_DOMAIN_LEN + 4 + value_len;
    uint8_t *buf = (uint8_t *)malloc(buf_len);
    if (!buf) {
        /* Out-of-memory: zero the output to make the failure loud. */
        memset(out_hash, 0, MERKLE_SMT_HASH_SIZE);
        return;
    }
    memcpy(buf, MERKLE_SMT_LEAF_DOMAIN, MERKLE_SMT_LEAF_DOMAIN_LEN);
    u32_to_be(index, buf + MERKLE_SMT_LEAF_DOMAIN_LEN);
    if (value_len > 0) {
        memcpy(buf + MERKLE_SMT_LEAF_DOMAIN_LEN + 4, value, value_len);
    }
    (void)qgp_sha3_512(buf, buf_len, out_hash);
    free(buf);
}

void merkle_smt_hash_null(uint32_t index,
                          uint8_t out_hash[MERKLE_SMT_HASH_SIZE]) {
    /* SHA3-512( "DNAC_RP_NULL\0" || index_BE_u32 ) */
    uint8_t buf[MERKLE_SMT_NULL_DOMAIN_LEN + 4];
    memcpy(buf, MERKLE_SMT_NULL_DOMAIN, MERKLE_SMT_NULL_DOMAIN_LEN);
    u32_to_be(index, buf + MERKLE_SMT_NULL_DOMAIN_LEN);
    (void)qgp_sha3_512(buf, sizeof(buf), out_hash);
}

void merkle_smt_hash_node(const uint8_t left[MERKLE_SMT_HASH_SIZE],
                          const uint8_t right[MERKLE_SMT_HASH_SIZE],
                          uint8_t out_hash[MERKLE_SMT_HASH_SIZE]) {
    /* SHA3-512( "DNAC_RP_NODE\0" || left(64B) || right(64B) ) */
    uint8_t buf[MERKLE_SMT_NODE_DOMAIN_LEN + 2 * MERKLE_SMT_HASH_SIZE];
    memcpy(buf, MERKLE_SMT_NODE_DOMAIN, MERKLE_SMT_NODE_DOMAIN_LEN);
    memcpy(buf + MERKLE_SMT_NODE_DOMAIN_LEN, left, MERKLE_SMT_HASH_SIZE);
    memcpy(buf + MERKLE_SMT_NODE_DOMAIN_LEN + MERKLE_SMT_HASH_SIZE,
           right, MERKLE_SMT_HASH_SIZE);
    (void)qgp_sha3_512(buf, sizeof(buf), out_hash);
}

/* ============================================================================
 * Root computation
 * ========================================================================== */

/** Returns the i-th leaf hash for a tree of given (leaves[], leaf_count, depth).
 *  If i < leaf_count, returns leaves[i]; otherwise returns null_hash(i). */
static void get_level0(const uint8_t *leaves,
                       size_t leaf_count,
                       uint32_t depth,
                       size_t i,
                       uint8_t out[MERKLE_SMT_HASH_SIZE]) {
    (void)depth;
    if (i < leaf_count) {
        memcpy(out, leaves + i * MERKLE_SMT_HASH_SIZE, MERKLE_SMT_HASH_SIZE);
    } else {
        merkle_smt_hash_null((uint32_t)i, out);
    }
}

int merkle_smt_compute_root(const uint8_t *leaves,
                            size_t leaf_count,
                            uint32_t depth,
                            uint8_t out_root[MERKLE_SMT_HASH_SIZE]) {
    if (!out_root) return -1;
    if (depth == 0 || depth > MERKLE_SMT_MAX_DEPTH) return -1;

    size_t leaf_count_pow2 = (size_t)1 << depth;
    if (leaf_count > leaf_count_pow2) return -1;
    if (leaf_count > 0 && !leaves) return -1;

    /* Allocate the active level. We compute layer-by-layer in O(N) memory. */
    uint8_t *level = (uint8_t *)malloc(leaf_count_pow2 * MERKLE_SMT_HASH_SIZE);
    if (!level) return -1;

    /* Fill level 0 with leaves + null padding for missing slots. */
    for (size_t i = 0; i < leaf_count_pow2; i++) {
        get_level0(leaves, leaf_count, depth, i,
                   level + i * MERKLE_SMT_HASH_SIZE);
    }

    /* Reduce level by level. */
    size_t cur_count = leaf_count_pow2;
    while (cur_count > 1) {
        size_t next_count = cur_count / 2;
        for (size_t i = 0; i < next_count; i++) {
            const uint8_t *l = level + (2 * i) * MERKLE_SMT_HASH_SIZE;
            const uint8_t *r = level + (2 * i + 1) * MERKLE_SMT_HASH_SIZE;
            uint8_t node[MERKLE_SMT_HASH_SIZE];
            merkle_smt_hash_node(l, r, node);
            memcpy(level + i * MERKLE_SMT_HASH_SIZE, node, MERKLE_SMT_HASH_SIZE);
        }
        cur_count = next_count;
    }

    memcpy(out_root, level, MERKLE_SMT_HASH_SIZE);
    free(level);
    return 0;
}

/* ============================================================================
 * Inclusion proof build / verify
 * ========================================================================== */

int merkle_smt_build_proof(const uint8_t *leaves,
                           size_t leaf_count,
                           uint32_t depth,
                           uint32_t target_index,
                           merkle_smt_proof_t *out_proof) {
    if (!out_proof) return -1;
    if (depth == 0 || depth > MERKLE_SMT_MAX_DEPTH) return -1;

    size_t leaf_count_pow2 = (size_t)1 << depth;
    if ((size_t)target_index >= leaf_count_pow2) return -1;
    if (leaf_count > leaf_count_pow2) return -1;
    if (leaf_count > 0 && !leaves) return -1;

    /* Fill level 0. */
    uint8_t *level = (uint8_t *)malloc(leaf_count_pow2 * MERKLE_SMT_HASH_SIZE);
    if (!level) return -1;
    for (size_t i = 0; i < leaf_count_pow2; i++) {
        get_level0(leaves, leaf_count, depth, i,
                   level + i * MERKLE_SMT_HASH_SIZE);
    }

    out_proof->index = target_index;
    out_proof->depth = depth;
    memcpy(out_proof->leaf_value,
           level + target_index * MERKLE_SMT_HASH_SIZE,
           MERKLE_SMT_HASH_SIZE);

    /* Walk from leaf up. */
    size_t cur_count = leaf_count_pow2;
    size_t idx = target_index;
    for (uint32_t d = 0; d < depth; d++) {
        size_t sibling = idx ^ 1;
        memcpy(out_proof->path[d],
               level + sibling * MERKLE_SMT_HASH_SIZE,
               MERKLE_SMT_HASH_SIZE);

        /* Reduce to next level. */
        size_t next_count = cur_count / 2;
        for (size_t i = 0; i < next_count; i++) {
            uint8_t node[MERKLE_SMT_HASH_SIZE];
            merkle_smt_hash_node(level + (2 * i) * MERKLE_SMT_HASH_SIZE,
                                 level + (2 * i + 1) * MERKLE_SMT_HASH_SIZE,
                                 node);
            memcpy(level + i * MERKLE_SMT_HASH_SIZE, node, MERKLE_SMT_HASH_SIZE);
        }
        cur_count = next_count;
        idx >>= 1;
    }

    free(level);
    return 0;
}

bool merkle_smt_verify_proof(const merkle_smt_proof_t *proof,
                             const uint8_t expected_root[MERKLE_SMT_HASH_SIZE]) {
    if (!proof || !expected_root) return false;
    if (proof->depth == 0 || proof->depth > MERKLE_SMT_MAX_DEPTH) return false;

    /* Walk up from leaf, combining with siblings according to bit pattern. */
    uint8_t cur[MERKLE_SMT_HASH_SIZE];
    memcpy(cur, proof->leaf_value, MERKLE_SMT_HASH_SIZE);

    uint32_t idx = proof->index;
    for (uint32_t d = 0; d < proof->depth; d++) {
        uint8_t combined[MERKLE_SMT_HASH_SIZE];
        if (idx & 1u) {
            /* Current is right child; sibling is left. */
            merkle_smt_hash_node(proof->path[d], cur, combined);
        } else {
            /* Current is left child; sibling is right. */
            merkle_smt_hash_node(cur, proof->path[d], combined);
        }
        memcpy(cur, combined, MERKLE_SMT_HASH_SIZE);
        idx >>= 1;
    }

    /* Constant-time compare. */
    int diff = 0;
    for (size_t i = 0; i < MERKLE_SMT_HASH_SIZE; i++) {
        diff |= (int)(cur[i] ^ expected_root[i]);
    }
    return diff == 0;
}
