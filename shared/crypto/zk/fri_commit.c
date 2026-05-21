/**
 * @file fri_commit.c
 * @brief FRI multi-layer commit phase (Sub-sprint 2.2).
 *
 * See fri_commit.h for algorithm spec.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "fri_commit.h"
#include "fri_fold.h"

#include <stdlib.h>
#include <string.h>

/* Serialize an fp2 value to 16 bytes: a_BE_u64 || b_BE_u64. */
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

/* Compute Merkle root over a layer of `size` Goldilocks² values.
 * Tree depth = log2(size). */
static int compute_layer_root(const gold_fp2_t *layer,
                              size_t size,
                              uint32_t depth,
                              uint8_t out_root[MERKLE_SMT_HASH_SIZE]) {
    /* Hash each fp2 value as a Merkle leaf, then compute root. */
    uint8_t *leaves = (uint8_t *)malloc(size * MERKLE_SMT_HASH_SIZE);
    if (!leaves) return -1;
    for (size_t i = 0; i < size; i++) {
        uint8_t val_bytes[16];
        fp2_to_bytes(layer[i], val_bytes);
        merkle_smt_hash_leaf((uint32_t)i, val_bytes, 16,
                             leaves + i * MERKLE_SMT_HASH_SIZE);
    }
    int rc = merkle_smt_compute_root(leaves, size, depth, out_root);
    free(leaves);
    return rc;
}

/* Build halve_inv_powers[i] = (g^{-i} / 2) for i in 0..h-1,
 * where g = two_adic_generator(layer_log_size). */
static void compute_halve_inv_powers(uint32_t layer_log_size,
                                     size_t h,
                                     gold_fp_t *out) {
    gold_fp_t g = gold_fp_two_adic_generator(layer_log_size);
    gold_fp_t g_inv = gold_fp_inv(g);
    /* 1/2 = inv(2) */
    gold_fp_t two = gold_fp_from_u64(2);
    gold_fp_t half = gold_fp_inv(two);
    gold_fp_t acc = half;
    for (size_t i = 0; i < h; i++) {
        out[i] = acc;
        acc = gold_fp_mul(acc, g_inv);
    }
}

int fri_commit_phase(transcript_t *transcript,
                     const gold_fp2_t *initial_values,
                     uint32_t initial_log_size,
                     uint32_t cap_height_log,
                     gold_fp2_t *scratch_layer,
                     fri_commit_output_t *out) {
    if (!transcript || !initial_values || !scratch_layer || !out) return -1;
    if (initial_log_size <= cap_height_log) return -1;
    if (initial_log_size > FRI_COMMIT_MAX_LAYERS + cap_height_log) return -1;
    if (!out->final_values) return -1;

    /* Ping-pong buffers: `cur` is the current layer we read from,
     * `next` is where we write the folded output. */
    size_t initial_size = (size_t)1 << initial_log_size;
    gold_fp2_t *cur_buf = (gold_fp2_t *)malloc(initial_size * sizeof(gold_fp2_t));
    if (!cur_buf) return -1;
    memcpy(cur_buf, initial_values, initial_size * sizeof(gold_fp2_t));

    gold_fp2_t *cur = cur_buf;
    gold_fp2_t *next = scratch_layer;

    uint32_t current_log_size = initial_log_size;
    out->num_layers = 0;

    /* Worst-case halve_inv_powers buffer for largest layer. */
    size_t max_h = (size_t)1 << (initial_log_size - 1);
    gold_fp_t *halve_inv_powers = (gold_fp_t *)malloc(max_h * sizeof(gold_fp_t));
    if (!halve_inv_powers) { free(cur_buf); return -1; }

    while (current_log_size > cap_height_log) {
        if (out->num_layers >= FRI_COMMIT_MAX_LAYERS) {
            free(halve_inv_powers); free(cur_buf);
            return -1;
        }
        size_t layer_size = (size_t)1 << current_log_size;
        size_t h = layer_size / 2;

        /* 1-3. Layer Merkle root. */
        if (compute_layer_root(cur, layer_size, current_log_size,
                               out->layer_roots[out->num_layers]) != 0) {
            free(halve_inv_powers); free(cur_buf);
            return -1;
        }

        /* 4. Absorb root. */
        transcript_absorb(transcript,
                          out->layer_roots[out->num_layers],
                          MERKLE_SMT_HASH_SIZE);

        /* 5. Derive beta. */
        gold_fp2_t beta = transcript_challenge_fp2(transcript);
        out->layer_betas[out->num_layers] = beta;

        /* 6. Compute halve_inv_powers + fold. */
        compute_halve_inv_powers(current_log_size, h, halve_inv_powers);
        fri_fold_arity2(cur, halve_inv_powers, beta, h, next);

        /* Swap buffers: next becomes current for the next iteration. */
        gold_fp2_t *tmp = cur;
        cur = next;
        next = tmp;

        out->num_layers++;
        current_log_size -= 1;
    }

    /* Copy final layer to caller-owned out->final_values. */
    size_t final_size = (size_t)1 << current_log_size;
    memcpy(out->final_values, cur, final_size * sizeof(gold_fp2_t));
    out->final_log_size = current_log_size;

    free(halve_inv_powers);
    free(cur_buf);
    return 0;
}
