/**
 * @file poseidon2_goldilocks.c
 * @brief Poseidon2 permutation over Goldilocks, width 8 — grounded C port.
 *
 * Port of Plonky3 `p3-poseidon2` @ 82cfad73 for the Goldilocks width-8 instance
 * (`default_goldilocks_poseidon2_8`, goldilocks/src/poseidon2.rs:570-577).
 * Algorithm references (all @ 82cfad73):
 *   - permute order:            poseidon2/src/lib.rs:139-143
 *       initial external -> internal -> terminal external
 *   - external_initial_permute: poseidon2/src/external.rs:319-334
 *       mds_light ONCE, then per-round (add_rc+sbox, mds_light)
 *   - external_terminal_permute: poseidon2/src/external.rs:286-302
 *   - internal_permute_state:   poseidon2/src/internal.rs (sbox on state[0] only,
 *                               then matmul_internal)
 *   - matmul_internal:          poseidon2/src/internal.rs (state[i]*DIAG[i] + Σstate)
 *   - add_rc_and_sbox_generic:  poseidon2/src/generic.rs:24-31 (val = (val+rc)^D)
 *   - mds_light_permutation:    poseidon2/src/external.rs:106-157 (WIDTH=8 arm)
 *   - MDSMat4 (apply_mat4):     poseidon2/src/external.rs:59-74
 *       [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
 *
 * Constants copied verbatim (KAFADAN: no invented values):
 *   - GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL  poseidon2.rs:75-123
 *   - GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL    poseidon2.rs:126-174
 *   - GOLDILOCKS_POSEIDON2_RC_8_INTERNAL          poseidon2.rs:177-200
 *   - MATRIX_DIAG_8_GOLDILOCKS                     poseidon2.rs:640-649
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "poseidon2_goldilocks.h"

#include "field_goldilocks.h"

/* ============================================================================
 * Round constants (verbatim from Plonky3 82cfad73 goldilocks/src/poseidon2.rs)
 * ========================================================================== */

/* GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL (4 rounds x 8), poseidon2.rs:75. */
static const uint64_t RC8_EXT_INITIAL[POSEIDON2_GOLD_HALF_FULL_ROUNDS]
                                     [POSEIDON2_GOLD_WIDTH] = {
    {0xdd5743e7f2a5a5d9ULL, 0xcb3a864e58ada44bULL, 0xffa2449ed32f8cdcULL,
     0x42025f65d6bd13eeULL, 0x7889175e25506323ULL, 0x34b98bb03d24b737ULL,
     0xbdcc535ecc4faa2aULL, 0x5b20ad869fc0d033ULL},
    {0xf1dda5b9259dfcb4ULL, 0x27515210be112d59ULL, 0x4227d1718c766c3fULL,
     0x26d333161a5bd794ULL, 0x49b938957bf4b026ULL, 0x4a56b5938b213669ULL,
     0x1120426b48c8353dULL, 0x6b323c3f10a56cadULL},
    {0xce57d6245ddca6b2ULL, 0xb1fc8d402bba1eb1ULL, 0xb5c5096ca959bd04ULL,
     0x6db55cd306d31f7fULL, 0xc49d293a81cb9641ULL, 0x1ce55a4fe979719fULL,
     0xa92e60a9d178a4d1ULL, 0x002cc64973bcfd8cULL},
    {0xcea721cce82fb11bULL, 0xe5b55eb8098ece81ULL, 0x4e30525c6f1ddd66ULL,
     0x43c6702827070987ULL, 0xaca68430a7b5762aULL, 0x3674238634df9c93ULL,
     0x88cee1c825e33433ULL, 0xde99ae8d74b57176ULL},
};

/* GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL (4 rounds x 8), poseidon2.rs:126. */
static const uint64_t RC8_EXT_FINAL[POSEIDON2_GOLD_HALF_FULL_ROUNDS]
                                   [POSEIDON2_GOLD_WIDTH] = {
    {0x014ef1197d341346ULL, 0x9725e20825d07394ULL, 0xfdb25aef2c5bae3bULL,
     0xbe5402dc598c971eULL, 0x93a5711f04cdca3dULL, 0xc45a9a5b2f8fb97bULL,
     0xfe8946a924933545ULL, 0x2af997a27369091cULL},
    {0xaa62c88e0b294011ULL, 0x058eb9d810ce9f74ULL, 0xb3cb23eced349ae4ULL,
     0xa3648177a77b4a84ULL, 0x43153d905992d95dULL, 0xf4e2a97cda44aa4bULL,
     0x5baa2702b908682fULL, 0x082923bdf4f750d1ULL},
    {0x98ae09a325893803ULL, 0xf8a6475077968838ULL, 0xceb0735bf00b2c5fULL,
     0x0a1a5d953888e072ULL, 0x2fcb190489f94475ULL, 0xb5be06270dec69fcULL,
     0x739cb934b09acf8bULL, 0x537750b75ec7f25bULL},
    {0xe9dd318bae1f3961ULL, 0xf7462137299efe1aULL, 0xb1f6b8eee9adb940ULL,
     0xbdebcc8a809dfe6bULL, 0x40fc1f791b178113ULL, 0x3ac1c3362d014864ULL,
     0x9a016184bdb8aebaULL, 0x95f2394459fbc25eULL},
};

/* GOLDILOCKS_POSEIDON2_RC_8_INTERNAL (22 scalars), poseidon2.rs:177. */
static const uint64_t RC8_INTERNAL[POSEIDON2_GOLD_PARTIAL_ROUNDS] = {
    0x488897d85ff51f56ULL, 0x1140737ccb162218ULL, 0xa7eeb9215866ed35ULL,
    0x9bd2976fee49fcc9ULL, 0xc0c8f0de580a3fccULL, 0x4fb2dae6ee8fc793ULL,
    0x343a89f35f37395bULL, 0x223b525a77ca72c8ULL, 0x56ccb62574aaa918ULL,
    0xc4d507d8027af9edULL, 0xa080673cf0b7e95cULL, 0xf0184884eb70dcf8ULL,
    0x044f10b0cb3d5c69ULL, 0xe9e3f7993938f186ULL, 0x1b761c80e772f459ULL,
    0x606cec607a1b5facULL, 0x14a0c2e1d45f03cdULL, 0x4eace8855398574fULL,
    0xf905ca7103eff3e6ULL, 0xf8c8f8d20862c059ULL, 0xb524fe8bdd678e5aULL,
    0xfbb7865901a1ec41ULL,
};

/* MATRIX_DIAG_8_GOLDILOCKS, poseidon2.rs:640 ([-2,1,2,1/2,3,-1/2,-3,-4]). */
static const uint64_t MATRIX_DIAG_8[POSEIDON2_GOLD_WIDTH] = {
    0xfffffffeffffffffULL, /* -2  */
    0x0000000000000001ULL, /*  1  */
    0x0000000000000002ULL, /*  2  */
    0x7fffffff80000001ULL, /*  1/2 */
    0x0000000000000003ULL, /*  3  */
    0x7fffffff80000000ULL, /* -1/2 */
    0xfffffffefffffffeULL, /* -3  */
    0xfffffffefffffffdULL, /* -4  */
};

/* ============================================================================
 * Field helpers (thin wrappers over field_goldilocks canonical ops)
 * ========================================================================== */

static inline gold_fp_t fp(uint64_t v) { return gold_fp_from_u64(v); }
static inline gold_fp_t add(gold_fp_t a, gold_fp_t b) { return gold_fp_add(a, b); }
static inline gold_fp_t mul(gold_fp_t a, gold_fp_t b) { return gold_fp_mul(a, b); }

/* add_rc_and_sbox_generic: val = (val + rc)^7 (generic.rs:24-31, D=7). */
static inline gold_fp_t add_rc_sbox(gold_fp_t val, gold_fp_t rc) {
    gold_fp_t x = add(val, rc);
    gold_fp_t x2 = mul(x, x);   /* x^2  */
    gold_fp_t x4 = mul(x2, x2); /* x^4  */
    gold_fp_t x6 = mul(x4, x2); /* x^6  */
    return mul(x6, x);          /* x^7  */
}

/* ============================================================================
 * Linear layers
 * ========================================================================== */

/* apply_mat4: multiply x[0..4] by [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]
 * (external.rs:59-74 apply_mat4 / the M_4 matrix). */
static void apply_mat4(gold_fp_t x[4]) {
    gold_fp_t t0 = x[0], t1 = x[1], t2 = x[2], t3 = x[3];
    gold_fp_t two0 = add(t0, t0), two1 = add(t1, t1);
    gold_fp_t two2 = add(t2, t2), two3 = add(t3, t3);
    gold_fp_t thr0 = add(two0, t0), thr1 = add(two1, t1);
    gold_fp_t thr2 = add(two2, t2), thr3 = add(two3, t3);
    x[0] = add(add(two0, thr1), add(t2, t3));   /* 2t0 + 3t1 +  t2 +  t3 */
    x[1] = add(add(t0, two1), add(thr2, t3));   /*  t0 + 2t1 + 3t2 +  t3 */
    x[2] = add(add(t0, t1), add(two2, thr3));   /*  t0 +  t1 + 2t2 + 3t3 */
    x[3] = add(add(thr0, t1), add(t2, two3));   /* 3t0 +  t1 +  t2 + 2t3 */
}

/* mds_light_permutation for WIDTH=8 (external.rs:106-157, the 4|8|... arm):
 * apply M_4 to each 4-chunk, then add per-lane column sums sums[i%4]. */
static void mds_light_8(gold_fp_t state[POSEIDON2_GOLD_WIDTH]) {
    apply_mat4(&state[0]);
    apply_mat4(&state[4]);
    /* sums[k] = Σ_{j step 4} state[j+k]  =  state[k] + state[k+4]. */
    gold_fp_t sums[4];
    for (int k = 0; k < 4; k++) sums[k] = add(state[k], state[k + 4]);
    for (int i = 0; i < POSEIDON2_GOLD_WIDTH; i++)
        state[i] = add(state[i], sums[i % 4]);
}

/* matmul_internal: sum = Σ state; state[i] = state[i]*DIAG[i] + sum
 * (internal.rs matmul_internal). */
static void matmul_internal_8(gold_fp_t state[POSEIDON2_GOLD_WIDTH]) {
    gold_fp_t sum = state[0];
    for (int i = 1; i < POSEIDON2_GOLD_WIDTH; i++) sum = add(sum, state[i]);
    for (int i = 0; i < POSEIDON2_GOLD_WIDTH; i++)
        state[i] = add(mul(state[i], fp(MATRIX_DIAG_8[i])), sum);
}

/* ============================================================================
 * Permutation (lib.rs:139-143 order)
 * ========================================================================== */

void poseidon2_goldilocks8_permute(uint64_t state_u64[POSEIDON2_GOLD_WIDTH]) {
    gold_fp_t s[POSEIDON2_GOLD_WIDTH];
    for (int i = 0; i < POSEIDON2_GOLD_WIDTH; i++) s[i] = fp(state_u64[i]);

    /* --- initial external layer (external.rs:319-334) --- */
    mds_light_8(s); /* the "extra" leading matrix multiplication */
    for (int r = 0; r < POSEIDON2_GOLD_HALF_FULL_ROUNDS; r++) {
        for (int i = 0; i < POSEIDON2_GOLD_WIDTH; i++)
            s[i] = add_rc_sbox(s[i], fp(RC8_EXT_INITIAL[r][i]));
        mds_light_8(s);
    }

    /* --- internal layer: 22 partial rounds (internal.rs) --- */
    for (int r = 0; r < POSEIDON2_GOLD_PARTIAL_ROUNDS; r++) {
        s[0] = add_rc_sbox(s[0], fp(RC8_INTERNAL[r])); /* sbox on state[0] only */
        matmul_internal_8(s);
    }

    /* --- terminal external layer (external.rs:286-302) --- */
    for (int r = 0; r < POSEIDON2_GOLD_HALF_FULL_ROUNDS; r++) {
        for (int i = 0; i < POSEIDON2_GOLD_WIDTH; i++)
            s[i] = add_rc_sbox(s[i], fp(RC8_EXT_FINAL[r][i]));
        mds_light_8(s);
    }

    for (int i = 0; i < POSEIDON2_GOLD_WIDTH; i++) state_u64[i] = gold_fp_to_u64(s[i]);
}
