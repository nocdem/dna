/**
 * @file duplex_challenger.c
 * @brief Poseidon2 DuplexChallenger over Goldilocks, width 8 / rate 4 (P1a).
 *
 * See duplex_challenger.h for the full grounding contract. Every function
 * body cites the Plonky3 82cfad73 lines it ports.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "duplex_challenger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "poseidon2_goldilocks.h"

/* Fail-close guard: precondition violations abort (consensus builds strip
 * assert(); an out-of-contract call here must never limp on). */
static void dc_fail(const char *msg) {
    fprintf(stderr, "duplex_challenger: FATAL: %s\n", msg);
    abort();
}

/* "DNAC|ZK|FRI|TRANSCRIPT|V1" (25 ASCII bytes, transcript.c Q1 constant) as
 * 4 LE u64 chunks, last zero-padded (P1 design doc §0 encoding pin; od-computed,
 * all canonical — top bytes 0x7C/0x4E/0x56/0x00 < p's top byte). Byte-derivation
 * cross-checked at runtime by the KAT against transcript.h's byte constant AND
 * the oracle vector's ds_prefix field. */
const uint64_t DNAC_DUPLEX_DS_PREFIX[DNAC_DUPLEX_RATE] = {
    0x7C4B5A7C43414E44ULL, /* "DNAC|ZK|" */
    0x4E4152547C495246ULL, /* "FRI|TRAN" */
    0x567C545049524353ULL, /* "SCRIPT|V" */
    0x0000000000000031ULL, /* "1" + zero pad */
};

/* duplexing (duplex_challenger.rs:86-99): OVERWRITE state[0..input_len] with
 * the drained input buffer, permute the full width-8 state, refill
 * output_buffer = state[0..RATE]. */
static void dc_duplexing(dnac_duplex_t *c) {
    if (c->input_len > DNAC_DUPLEX_RATE) dc_fail("input_buffer overflow");
    for (size_t i = 0; i < c->input_len; i++) {
        c->sponge_state[i] = c->input_buffer[i]; /* overwrite, NOT add */
    }
    c->input_len = 0;
    poseidon2_goldilocks8_permute(c->sponge_state);
    for (size_t i = 0; i < DNAC_DUPLEX_RATE; i++) {
        c->output_buffer[i] = c->sponge_state[i];
    }
    c->output_len = DNAC_DUPLEX_RATE;
}

void dnac_duplex_init(dnac_duplex_t *c) {
    if (!c) dc_fail("init: NULL");
    memset(c, 0, sizeof(*c)); /* DuplexChallenger::new — zero state, empty bufs */
}

void dnac_duplex_init_default(dnac_duplex_t *c) {
    dnac_duplex_init(c);
    /* G-SEC-P1-7 pre-absorb: 4 limbs = exactly one RATE block, the 4th
     * observe fires the single prefix permutation (rs:154-156). */
    for (size_t i = 0; i < DNAC_DUPLEX_RATE; i++) {
        dnac_duplex_observe_fp(c, gold_fp_from_u64(DNAC_DUPLEX_DS_PREFIX[i]));
    }
}

void dnac_duplex_observe_fp(dnac_duplex_t *c, gold_fp_t v) {
    if (!c) dc_fail("observe: NULL");
    /* rs:148-151 — any buffered output is now invalid. */
    c->output_len = 0;
    if (c->input_len >= DNAC_DUPLEX_RATE) dc_fail("observe: input overflow");
    c->input_buffer[c->input_len++] = gold_fp_to_u64(v); /* canonical lane */
    /* rs:154-156 — eager duplex at RATE. */
    if (c->input_len == DNAC_DUPLEX_RATE) {
        dc_duplexing(c);
    }
}

void dnac_duplex_observe_fp2(dnac_duplex_t *c, gold_fp2_t v) {
    /* observe_algebra_element (challenger/src/lib.rs:106-108): basis order
     * c0 then c1. */
    dnac_duplex_observe_fp(c, v.a);
    dnac_duplex_observe_fp(c, v.b);
}

gold_fp_t dnac_duplex_sample_fp(dnac_duplex_t *c) {
    if (!c) dc_fail("sample: NULL");
    /* rs:238-241 — pending input OR empty output => duplex. */
    if (c->input_len > 0 || c->output_len == 0) {
        dc_duplexing(c);
    }
    /* rs:243-245 — Vec::pop = LIFO from the END. */
    return gold_fp_from_u64(c->output_buffer[--c->output_len]);
}

gold_fp2_t dnac_duplex_sample_fp2(dnac_duplex_t *c) {
    /* EF::from_basis_coefficients_fn (rs:235-247) — c0 sampled first. */
    gold_fp2_t r;
    r.a = dnac_duplex_sample_fp(c);
    r.b = dnac_duplex_sample_fp(c);
    return r;
}

uint64_t dnac_duplex_sample_bits(dnac_duplex_t *c, size_t bits) {
    /* rs:265-266 asserts: bits < usize::BITS and (1 << bits) < ORDER.
     * For Goldilocks (1u64<<63) < p, so bits < 64 covers both. */
    if (bits >= 64) dc_fail("sample_bits: bits >= 64");
    uint64_t rand_u64 = gold_fp_to_u64(dnac_duplex_sample_fp(c));
    uint64_t mask = (bits == 0) ? 0 : ((~(uint64_t)0) >> (64 - bits));
    return rand_u64 & mask; /* rs:267-269 */
}

bool dnac_duplex_check_witness(dnac_duplex_t *c, size_t bits, gold_fp_t witness) {
    /* grinding_challenger.rs:40-46. bits==0 => early true, NO state change. */
    if (bits == 0) {
        return true;
    }
    dnac_duplex_observe_fp(c, witness); /* Witness = F (:104) */
    return dnac_duplex_sample_bits(c, bits) == 0;
}

gold_fp_t dnac_duplex_grind(dnac_duplex_t *c, size_t bits) {
    if (bits >= 64) dc_fail("grind: bits >= 64");
    /* grinding_challenger.rs:116-119 — bits==0: witness ZERO, no state change. */
    if (bits == 0) {
        return gold_fp_from_u64(0);
    }
    /* Least-witness serial search (DNAC determinization, header note): clone =
     * struct copy; the winning check_witness advances `c` exactly as the
     * verifier's check will. */
    for (uint64_t w = 0;; w++) {
        if (w >= GOLDILOCKS_P) dc_fail("grind: witness space exhausted");
        dnac_duplex_t trial = *c;
        if (dnac_duplex_check_witness(&trial, bits, gold_fp_from_u64(w))) {
            *c = trial;
            return gold_fp_from_u64(w);
        }
    }
}
