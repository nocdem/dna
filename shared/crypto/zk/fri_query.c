/**
 * @file fri_query.c
 * @brief FRI query phase — prover (fri_query_open) + verifier (fri_query_verify).
 *
 * See fri_query.h for protocol spec.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_query.h"
#include "fri_fold.h"

#include <stdlib.h>
#include <string.h>

/* ============================================================================
 * Internal helpers
 * ========================================================================== */

/* Serialize fp2 to 16 bytes (must match fri_commit.c's serialization). */
static void fp2_to_bytes(gold_fp2_t v, uint8_t out[16]) {
    uint64_t a = gold_fp_to_u64(v.a);
    uint64_t b = gold_fp_to_u64(v.b);
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)((a >> (56 - 8 * i)) & 0xff);
    }
    for (int i = 0; i < 8; i++) {
        out[8 + i] = (uint8_t)((b >> (56 - 8 * i)) & 0xff);
    }
}

/* Compute leaf hash for an fp2 value at index i. */
static void layer_leaf_hash(uint32_t index,
                            gold_fp2_t value,
                            uint8_t out_hash[MERKLE_SMT_HASH_SIZE]) {
    uint8_t val_bytes[16];
    fp2_to_bytes(value, val_bytes);
    merkle_smt_hash_leaf(index, val_bytes, 16, out_hash);
}

/* Build a Merkle proof for position `idx` in a layer of size 2^depth.
 * Caller provides the layer's fp2 values; we hash them as leaves. */
static int build_layer_proof(const gold_fp2_t *layer,
                             size_t layer_size,
                             uint32_t depth,
                             uint32_t idx,
                             merkle_smt_proof_t *out) {
    uint8_t *leaves = (uint8_t *)malloc(layer_size * MERKLE_SMT_HASH_SIZE);
    if (!leaves) return -1;
    for (size_t i = 0; i < layer_size; i++) {
        layer_leaf_hash((uint32_t)i, layer[i],
                        leaves + i * MERKLE_SMT_HASH_SIZE);
    }
    int rc = merkle_smt_build_proof(leaves, layer_size, depth, idx, out);
    free(leaves);
    return rc;
}

/* Note: halve_inv_powers computation lives inline inside the verifier where
 * a single index's value suffices. The prover does not need it. */

/* ============================================================================
 * Prover: open queries
 * ========================================================================== */

int fri_query_open(transcript_t *transcript,
                   gold_fp2_t * const *all_layers,
                   uint32_t initial_log_size,
                   uint32_t cap_height_log,
                   uint32_t num_queries,
                   fri_query_proof_t *out_proofs) {
    if (!transcript || !all_layers || !out_proofs) return -1;
    if (initial_log_size <= cap_height_log) return -1;

    uint32_t num_layers = initial_log_size - cap_height_log;
    if (num_layers > FRI_COMMIT_MAX_LAYERS) return -1;

    uint32_t initial_size = 1u << initial_log_size;

    for (uint32_t qi = 0; qi < num_queries; qi++) {
        /* Sample query index for this query. */
        uint32_t q0 = transcript_challenge_query_index(transcript, initial_size);
        out_proofs[qi].initial_position = q0;
        out_proofs[qi].num_layers = num_layers;

        uint32_t q = q0;
        for (uint32_t i = 0; i < num_layers; i++) {
            uint32_t layer_log = initial_log_size - i;
            size_t   layer_size = (size_t)1 << layer_log;
            const gold_fp2_t *layer = all_layers[i];

            uint32_t lo_idx = q & ~1u;
            uint32_t hi_idx = q | 1u;

            fri_query_layer_opening_t *L = &out_proofs[qi].layers[i];
            L->lo_index = lo_idx;
            L->hi_index = hi_idx;
            L->lo_value = layer[lo_idx];
            L->hi_value = layer[hi_idx];

            if (build_layer_proof(layer, layer_size, layer_log, lo_idx,
                                  &L->lo_path) != 0) return -1;
            if (build_layer_proof(layer, layer_size, layer_log, hi_idx,
                                  &L->hi_path) != 0) return -1;

            q >>= 1;
        }
    }
    return 0;
}

/* ============================================================================
 * Verifier
 * ========================================================================== */

/* Verify a single layer's Merkle path: leaf at idx with given fp2 value
 * must produce a valid path to expected_root. */
static bool verify_leaf_path(uint32_t idx,
                             gold_fp2_t value,
                             const merkle_smt_proof_t *path,
                             const uint8_t expected_root[MERKLE_SMT_HASH_SIZE]) {
    /* Recompute the leaf hash from (idx, value) and compare to path->leaf_value. */
    uint8_t expected_leaf[MERKLE_SMT_HASH_SIZE];
    layer_leaf_hash(idx, value, expected_leaf);
    if (memcmp(expected_leaf, path->leaf_value, MERKLE_SMT_HASH_SIZE) != 0) {
        return false;
    }
    /* Path index must also match. */
    if (path->index != idx) return false;
    /* And the path must verify against the layer root. */
    return merkle_smt_verify_proof(path, expected_root);
}

bool fri_query_verify(transcript_t *transcript,
                      const fri_commit_output_t *commit_out,
                      const fri_query_proof_t *proofs,
                      uint32_t num_queries) {
    if (!transcript || !commit_out || !proofs) return false;

    uint32_t num_layers = commit_out->num_layers;
    uint32_t final_log = commit_out->final_log_size;
    /* initial_log_size = final_log + num_layers. */
    uint32_t initial_log_size = final_log + num_layers;
    uint32_t initial_size = 1u << initial_log_size;

    for (uint32_t qi = 0; qi < num_queries; qi++) {
        /* Re-derive query index — verifier must consume in same order as prover. */
        uint32_t q0 = transcript_challenge_query_index(transcript, initial_size);
        const fri_query_proof_t *P = &proofs[qi];

        if (P->initial_position != q0) return false;
        if (P->num_layers != num_layers) return false;

        uint32_t q = q0;
        for (uint32_t i = 0; i < num_layers; i++) {
            const fri_query_layer_opening_t *L = &P->layers[i];

            /* Sanity: lo_index/hi_index. */
            if (L->lo_index != (q & ~1u)) return false;
            if (L->hi_index != (q | 1u))  return false;

            /* Merkle path checks against layer root. */
            if (!verify_leaf_path(L->lo_index, L->lo_value, &L->lo_path,
                                  commit_out->layer_roots[i])) return false;
            if (!verify_leaf_path(L->hi_index, L->hi_value, &L->hi_path,
                                  commit_out->layer_roots[i])) return false;

            /* Fold consistency: compute expected value at position q/2 in next layer. */
            uint32_t layer_log = initial_log_size - i;
            uint32_t next_pos = q / 2;

            /* halve_inv_power for ROW = q/2 */
            gold_fp_t g = gold_fp_two_adic_generator(layer_log);
            gold_fp_t g_inv = gold_fp_inv(g);
            gold_fp_t two = gold_fp_from_u64(2);
            gold_fp_t half = gold_fp_inv(two);
            /* hip[next_pos] = (g_inv)^next_pos * half */
            gold_fp_t hip = half;
            for (uint32_t j = 0; j < next_pos; j++) {
                hip = gold_fp_mul(hip, g_inv);
            }

            /* fold = (lo + hi) * half + (lo - hi) * beta * hip */
            gold_fp2_t lo = L->lo_value;
            gold_fp2_t hi = L->hi_value;
            gold_fp2_t beta = commit_out->layer_betas[i];
            gold_fp2_t half_ext = gold_fp2_from_base(half);
            gold_fp2_t hip_ext = gold_fp2_from_base(hip);
            gold_fp2_t term1 = gold_fp2_mul(gold_fp2_add(lo, hi), half_ext);
            gold_fp2_t term2 = gold_fp2_mul(gold_fp2_mul(gold_fp2_sub(lo, hi), beta), hip_ext);
            gold_fp2_t expected_next = gold_fp2_add(term1, term2);

            /* What value must this folded result equal? */
            if (i + 1 < num_layers) {
                /* Next layer's tree is committed; we need to verify the value
                 * by opening the next layer's Merkle path. The expected value
                 * is provided in the next opening; we'll check it there.
                 *
                 * Specifically, layer (i+1)'s opening will include a value at
                 * position (q/2 & ~1) or (q/2 | 1). If next_pos is even, it
                 * corresponds to lo_value of next layer's opening; if odd, hi.
                 *
                 * We assert that this fold result equals the matching value
                 * in next layer's opening, AND that opening's Merkle path
                 * verifies against the next layer's root.
                 */
                const fri_query_layer_opening_t *Lnext = &P->layers[i + 1];
                gold_fp2_t next_val = (next_pos & 1u) ? Lnext->hi_value : Lnext->lo_value;
                if (!gold_fp2_eq(expected_next, next_val)) return false;
            } else {
                /* Last layer: next is commit_out->final_values at index next_pos. */
                if ((size_t)next_pos >= ((size_t)1 << final_log)) return false;
                if (!gold_fp2_eq(expected_next, commit_out->final_values[next_pos])) {
                    return false;
                }
            }

            q >>= 1;
        }
    }
    return true;
}
