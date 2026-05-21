/**
 * @file keccak_air_sha3_512.c
 * @brief Single-block SHA3-512 AIR (Sub-sprint 3.3b.7).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "keccak_air_sha3_512.h"
#include "keccak_air_bits.h"

#include <string.h>

/* Convert a byte to 8 binary field cells, LSB at index 0. */
static void byte_to_bits(uint8_t b, gold_fp2_t bits[8]) {
    for (int i = 0; i < 8; i++) {
        bits[i] = gold_fp2_from_base(gold_fp_from_u64((b >> i) & 1));
    }
}

int keccak_air_sha3_512_build_witness(const uint8_t *input,
                                      uint32_t input_len,
                                      keccak_air_sha3_512_witness_t *w) {
    if (!input || !w) return -1;
    if (input_len > SHA3_AIR_SINGLE_BLOCK_MAX_INPUT) return -1;

    memset(w, 0, sizeof(*w));
    w->input_len = input_len;

    /* Decompose input into bits. */
    for (uint32_t i = 0; i < input_len; i++) {
        byte_to_bits(input[i], &w->input_bits[i * 8]);
    }
    /* Remaining input_bits slots stay zero (unused). */

    /* Build padded block bytes deterministically. */
    uint8_t block[SHA3_512_RATE_BYTES] = {0};
    if (input_len > 0) memcpy(block, input, input_len);
    block[input_len] = 0x06;
    block[SHA3_512_RATE_BYTES - 1] |= 0x80;

    /* Decompose padded block into bits. */
    for (uint32_t i = 0; i < SHA3_512_RATE_BYTES; i++) {
        byte_to_bits(block[i], &w->padded_bits[i * 8]);
    }

    /* Build initial state for f1600.
     * State = padded_block (rate portion) || zeros (capacity).
     * The first 72 bytes are interpreted as 9 little-endian u64 lanes. */
    uint64_t initial_lanes[KECCAK_NUM_LANES] = {0};
    for (int L = 0; L < 9; L++) {
        uint64_t lane = 0;
        for (int b = 0; b < 8; b++) {
            lane |= ((uint64_t)block[L * 8 + b]) << (b * 8);
        }
        initial_lanes[L] = lane;
    }
    /* Lanes 9..24 stay zero. */

    /* Run f1600 to get final state. */
    uint64_t final_lanes[KECCAK_NUM_LANES];
    memcpy(final_lanes, initial_lanes, sizeof(final_lanes));
    keccak_ref_f1600(final_lanes);

    /* Populate f1600 witness. */
    keccak_air_f1600_build_witness(initial_lanes, final_lanes, &w->f1600);

    /* Squeeze output: first 64 bytes = first 8 lanes, little-endian within each. */
    for (int L = 0; L < 8; L++) {
        for (int b = 0; b < 8; b++) {
            uint8_t byte = (uint8_t)((final_lanes[L] >> (b * 8)) & 0xff);
            byte_to_bits(byte, &w->output_bits[(L * 8 + b) * 8]);
        }
    }
    return 0;
}

bool keccak_air_sha3_512_check_constraints(const keccak_air_sha3_512_witness_t *w,
                                           char *out_first_failing_phase,
                                           uint32_t *out_first_failing_index) {
    if (out_first_failing_phase) *out_first_failing_phase = 0;
    if (out_first_failing_index) *out_first_failing_index = 0;

    if (w->input_len > SHA3_AIR_SINGLE_BLOCK_MAX_INPUT) {
        if (out_first_failing_phase) *out_first_failing_phase = '?';
        return false;
    }

    /* Binary checks on input bits (used portion only). */
    if (!keccak_air_check_bits_binary(w->input_bits, w->input_len * 8)) {
        if (out_first_failing_phase) *out_first_failing_phase = 'I';
        return false;
    }
    /* Padded block bits: full 576 must be binary. */
    if (!keccak_air_check_bits_binary(w->padded_bits, SHA3_512_BLOCK_BITS)) {
        if (out_first_failing_phase) *out_first_failing_phase = 'P';
        return false;
    }
    /* Output bits binary. */
    if (!keccak_air_check_bits_binary(w->output_bits, SHA3_512_OUT_BITS)) {
        if (out_first_failing_phase) *out_first_failing_phase = 'O';
        return false;
    }

    /* Padding rule:
     *   padded_byte[i] == input[i]            for i ∈ [0, L)
     *   padded_byte[L] == 0x06
     *   padded_byte[i] == 0x00                for i ∈ (L, RATE-1)
     *   padded_byte[RATE-1] == 0x80           (since we assume L ≤ RATE-2)
     */
    for (uint32_t i = 0; i < w->input_len; i++) {
        for (int b = 0; b < 8; b++) {
            if (!gold_fp2_eq(w->padded_bits[i * 8 + b],
                             w->input_bits[i * 8 + b])) {
                if (out_first_failing_phase) *out_first_failing_phase = 'D';
                if (out_first_failing_index) *out_first_failing_index = i * 8 + b;
                return false;
            }
        }
    }
    /* Byte at index input_len must equal 0x06. */
    {
        gold_fp2_t expected_bits[8];
        byte_to_bits(0x06, expected_bits);
        for (int b = 0; b < 8; b++) {
            if (!gold_fp2_eq(w->padded_bits[w->input_len * 8 + b],
                             expected_bits[b])) {
                if (out_first_failing_phase) *out_first_failing_phase = 'D';
                if (out_first_failing_index) *out_first_failing_index = w->input_len * 8 + b;
                return false;
            }
        }
    }
    /* Bytes in (input_len, RATE-1) must equal 0x00 (all bits zero). */
    {
        gold_fp2_t zero_fp = gold_fp2_zero();
        for (uint32_t i = w->input_len + 1; i < SHA3_512_RATE_BYTES - 1; i++) {
            for (int b = 0; b < 8; b++) {
                if (!gold_fp2_eq(w->padded_bits[i * 8 + b], zero_fp)) {
                    if (out_first_failing_phase) *out_first_failing_phase = 'D';
                    if (out_first_failing_index) *out_first_failing_index = i * 8 + b;
                    return false;
                }
            }
        }
    }
    /* Last byte == 0x80. */
    {
        gold_fp2_t expected_bits[8];
        byte_to_bits(0x80, expected_bits);
        for (int b = 0; b < 8; b++) {
            uint32_t pos = (SHA3_512_RATE_BYTES - 1) * 8 + b;
            if (!gold_fp2_eq(w->padded_bits[pos], expected_bits[b])) {
                if (out_first_failing_phase) *out_first_failing_phase = 'D';
                if (out_first_failing_index) *out_first_failing_index = pos;
                return false;
            }
        }
    }

    /* Initial state binding: f1600.rounds[0].theta.input_bits must equal
     * (padded_bits || zeros). The encoding maps padded byte i to lane (i / 8)
     * at bit position (i % 8)*8 .. (i % 8)*8 + 7. In bit indexing, lane L
     * bit z = byte (L*8 + z/8) bit (z%8). */
    for (int L = 0; L < 9; L++) {
        for (int z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            uint32_t byte_idx = (uint32_t)L * 8 + (uint32_t)(z / 8);
            uint32_t bit_in_byte = (uint32_t)(z % 8);
            uint32_t state_bit_idx = (uint32_t)L * KECCAK_BITS_PER_LANE + (uint32_t)z;
            gold_fp2_t expected = w->padded_bits[byte_idx * 8 + bit_in_byte];
            if (!gold_fp2_eq(w->f1600.rounds[0].theta.input_bits[state_bit_idx],
                             expected)) {
                if (out_first_failing_phase) *out_first_failing_phase = 'S';
                if (out_first_failing_index) *out_first_failing_index = state_bit_idx;
                return false;
            }
        }
    }
    /* Lanes 9..24 of initial state must be zero. */
    {
        gold_fp2_t zero_fp = gold_fp2_zero();
        for (int L = 9; L < KECCAK_NUM_LANES; L++) {
            for (int z = 0; z < KECCAK_BITS_PER_LANE; z++) {
                uint32_t state_bit_idx = (uint32_t)L * KECCAK_BITS_PER_LANE + (uint32_t)z;
                if (!gold_fp2_eq(w->f1600.rounds[0].theta.input_bits[state_bit_idx],
                                 zero_fp)) {
                    if (out_first_failing_phase) *out_first_failing_phase = 'Z';
                    if (out_first_failing_index) *out_first_failing_index = state_bit_idx;
                    return false;
                }
            }
        }
    }

    /* f1600 constraints. */
    {
        uint32_t fr = 0; char fs = 0, ic = 0; uint32_t fi = 0;
        if (!keccak_air_f1600_check_constraints(&w->f1600, &fr, &fs, &ic, &fi)) {
            if (out_first_failing_phase) *out_first_failing_phase = 'F';
            if (out_first_failing_index) *out_first_failing_index = fr;
            return false;
        }
    }

    /* Output binding: output_bits should match first 8 lanes of f1600 final
     * state (= rounds[23].iota.output_bits[0..512)). */
    for (int L = 0; L < 8; L++) {
        for (int z = 0; z < KECCAK_BITS_PER_LANE; z++) {
            uint32_t state_idx = (uint32_t)L * KECCAK_BITS_PER_LANE + (uint32_t)z;
            /* Output bit (L*8 + z/8)*8 + (z%8) — re-derive from byte mapping. */
            uint32_t byte_idx = (uint32_t)L * 8 + (uint32_t)(z / 8);
            uint32_t bit_in_byte = (uint32_t)(z % 8);
            uint32_t out_bit_idx = byte_idx * 8 + bit_in_byte;
            gold_fp2_t expected =
                w->f1600.rounds[KECCAK_AIR_F1600_ROUNDS - 1].iota.output_bits[state_idx];
            if (!gold_fp2_eq(w->output_bits[out_bit_idx], expected)) {
                if (out_first_failing_phase) *out_first_failing_phase = 'Q';
                if (out_first_failing_index) *out_first_failing_index = out_bit_idx;
                return false;
            }
        }
    }

    return true;
}
