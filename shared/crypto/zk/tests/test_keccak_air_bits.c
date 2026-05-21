/**
 * @file test_keccak_air_bits.c
 * @brief Self-test for keccak_air_bits primitives (Sub-sprint 3.3b.1).
 *
 * Validates:
 *   T1: lane ↔ bits roundtrip (many u64 values).
 *   T2: binary-bit check accepts valid, rejects malformed.
 *   T3: 2-input XOR-in-field matches actual u64 XOR.
 *   T4: 5-input XOR-in-field matches actual u64 XOR + constraint check accepts.
 *   T5: 5-input XOR constraint rejects tampered (result, witness).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include "../field_goldilocks.h"
#include "../keccak_air_bits.h"

static int total_passed = 0;
static int total_failed = 0;

static void assert_pass(const char *label, bool ok) {
    if (ok) {
        total_passed++;
        printf("  %-58s PASS\n", label);
    } else {
        total_failed++;
        printf("  %-58s FAIL\n", label);
    }
}

/* T1: lane ↔ bits roundtrip. */
static void test_roundtrip(uint64_t lane) {
    char label[80];
    snprintf(label, sizeof(label), "roundtrip 0x%016" PRIx64, lane);
    gold_fp2_t bits[64];
    keccak_air_lane_to_bits(lane, bits);
    uint64_t back = keccak_air_bits_to_lane(bits);
    assert_pass(label, back == lane);
}

/* T2: binary-bit check */
static void test_binary_check_valid(uint64_t lane) {
    char label[80];
    snprintf(label, sizeof(label), "binary check valid lane 0x%016" PRIx64, lane);
    gold_fp2_t bits[64];
    keccak_air_lane_to_bits(lane, bits);
    assert_pass(label, keccak_air_check_bits_binary(bits, 64));
}

static void test_binary_check_reject(uint64_t lane, unsigned tamper_idx) {
    char label[80];
    snprintf(label, sizeof(label), "binary check rejects bit_%u = 2", tamper_idx);
    gold_fp2_t bits[64];
    keccak_air_lane_to_bits(lane, bits);
    bits[tamper_idx] = gold_fp2_from_base(gold_fp_from_u64(2));
    assert_pass(label, !keccak_air_check_bits_binary(bits, 64));
}

/* T3: 2-input XOR */
static void test_xor2(uint64_t a, uint64_t b) {
    char label[80];
    snprintf(label, sizeof(label), "xor2(0x%016" PRIx64 ", 0x%016" PRIx64 ")", a, b);
    gold_fp2_t bits_a[64], bits_b[64], bits_r[64];
    keccak_air_lane_to_bits(a, bits_a);
    keccak_air_lane_to_bits(b, bits_b);
    for (int i = 0; i < 64; i++) {
        bits_r[i] = keccak_air_xor2(bits_a[i], bits_b[i]);
    }
    uint64_t got = keccak_air_bits_to_lane(bits_r);
    uint64_t expected = a ^ b;
    assert_pass(label, got == expected);
}

/* T3b: XOR2 constraint check */
static void test_xor2_constraint(void) {
    /* All 4 combinations for two binary bits. */
    int pass_count = 0;
    for (int a = 0; a <= 1; a++) {
        for (int b = 0; b <= 1; b++) {
            gold_fp2_t fa = gold_fp2_from_base(gold_fp_from_u64((uint64_t)a));
            gold_fp2_t fb = gold_fp2_from_base(gold_fp_from_u64((uint64_t)b));
            gold_fp2_t correct = gold_fp2_from_base(gold_fp_from_u64((uint64_t)(a ^ b)));
            gold_fp2_t wrong   = gold_fp2_from_base(gold_fp_from_u64((uint64_t)(1 ^ a ^ b)));
            if (keccak_air_check_xor2(fa, fb, correct) &&
                !keccak_air_check_xor2(fa, fb, wrong)) {
                pass_count++;
            }
        }
    }
    assert_pass("xor2 constraint accepts correct + rejects wrong (4 combos)", pass_count == 4);
}

/* T4: 5-input XOR for various lane combinations */
static void test_xor5_lanes(uint64_t a, uint64_t b, uint64_t c, uint64_t d, uint64_t e) {
    char label[80];
    snprintf(label, sizeof(label), "xor5 lanes (mixed)");
    gold_fp2_t bits[5][64], result[64], witness[64];
    keccak_air_lane_to_bits(a, bits[0]);
    keccak_air_lane_to_bits(b, bits[1]);
    keccak_air_lane_to_bits(c, bits[2]);
    keccak_air_lane_to_bits(d, bits[3]);
    keccak_air_lane_to_bits(e, bits[4]);
    /* For each bit position, take the 5 lanes' bits and XOR. */
    int constraint_ok = 1;
    for (int i = 0; i < 64; i++) {
        gold_fp2_t cell_bits[5];
        for (int k = 0; k < 5; k++) cell_bits[k] = bits[k][i];
        keccak_air_xor5(cell_bits, &result[i], &witness[i]);
        if (!keccak_air_check_xor5(cell_bits, result[i], witness[i])) {
            constraint_ok = 0;
            break;
        }
    }
    uint64_t got = keccak_air_bits_to_lane(result);
    uint64_t expected = a ^ b ^ c ^ d ^ e;
    assert_pass(label, (got == expected) && constraint_ok);
}

/* T5: XOR5 constraint rejects tampered witness */
static void test_xor5_constraint_tamper(void) {
    /* Use a known bit set: (1, 1, 1, 0, 0) → sum=3, result=1, w=1. */
    gold_fp2_t bits[5];
    for (int k = 0; k < 5; k++) {
        bits[k] = gold_fp2_from_base(gold_fp_from_u64((uint64_t)(k < 3 ? 1 : 0)));
    }
    gold_fp2_t result, witness;
    keccak_air_xor5(bits, &result, &witness);

    bool ok_initial = keccak_air_check_xor5(bits, result, witness);

    /* Tamper result: flip 1 → 0. */
    gold_fp2_t bad_result = gold_fp2_zero();
    bool reject_bad_result = !keccak_air_check_xor5(bits, bad_result, witness);

    /* Tamper witness: 1 → 5 (out of range). */
    gold_fp2_t bad_witness = gold_fp2_from_base(gold_fp_from_u64(5));
    bool reject_bad_witness = !keccak_air_check_xor5(bits, result, bad_witness);

    assert_pass("xor5 constraint accepts honest (b=1,1,1,0,0 → r=1 w=1)", ok_initial);
    assert_pass("xor5 constraint rejects bad result", reject_bad_result);
    assert_pass("xor5 constraint rejects bad witness (5 ∉ {0,1,2})", reject_bad_witness);
}

int main(void) {
    printf("Sub-sprint 3.3b.1 — keccak_air_bits self-test\n");
    printf("==================================================\n\n");

    printf("T1: lane ↔ bits roundtrip\n");
    test_roundtrip(0);
    test_roundtrip(1);
    test_roundtrip(0x8000000000000000ULL);
    test_roundtrip(0xAAAAAAAAAAAAAAAAULL);
    test_roundtrip(0x5555555555555555ULL);
    test_roundtrip(0x0123456789ABCDEFULL);
    test_roundtrip(0xFEDCBA9876543210ULL);
    test_roundtrip(UINT64_MAX);

    printf("\nT2: binary-bit constraint\n");
    test_binary_check_valid(0);
    test_binary_check_valid(0xAAAAAAAAAAAAAAAAULL);
    test_binary_check_valid(UINT64_MAX);
    test_binary_check_reject(0xAAAAAAAAAAAAAAAAULL, 0);
    test_binary_check_reject(0xAAAAAAAAAAAAAAAAULL, 31);
    test_binary_check_reject(0xAAAAAAAAAAAAAAAAULL, 63);

    printf("\nT3: 2-input XOR in field\n");
    test_xor2(0, 0);
    test_xor2(0xFFFFFFFFFFFFFFFFULL, 0);
    test_xor2(0xAAAAAAAAAAAAAAAAULL, 0x5555555555555555ULL);
    test_xor2(0x0123456789ABCDEFULL, 0xFEDCBA9876543210ULL);
    test_xor2_constraint();

    printf("\nT4: 5-input XOR in field\n");
    test_xor5_lanes(0, 0, 0, 0, 0);
    test_xor5_lanes(0xFFFFFFFFFFFFFFFFULL, 0, 0, 0, 0);
    test_xor5_lanes(0xAAAAAAAAAAAAAAAAULL, 0x5555555555555555ULL, 0, 0, 0);
    test_xor5_lanes(0x1111111111111111ULL, 0x2222222222222222ULL,
                    0x4444444444444444ULL, 0x8888888888888888ULL,
                    0xFFFFFFFFFFFFFFFFULL);
    test_xor5_lanes(0xDEADBEEFCAFEBABEULL, 0x0123456789ABCDEFULL,
                    0xFEDCBA9876543210ULL, 0xA5A5A5A5A5A5A5A5ULL,
                    0x5A5A5A5A5A5A5A5AULL);

    printf("\nT5: XOR5 constraint tamper rejection\n");
    test_xor5_constraint_tamper();

    printf("\n--------------------------------------------------\n");
    printf("Total: %d passed, %d failed\n", total_passed, total_failed);
    if (total_failed == 0) {
        printf("SUB-SPRINT 3.3b.1 (keccak_air_bits) GATE: GREEN\n");
        return 0;
    } else {
        printf("SUB-SPRINT 3.3b.1 (keccak_air_bits) GATE: RED — %d failures\n", total_failed);
        return 1;
    }
}
