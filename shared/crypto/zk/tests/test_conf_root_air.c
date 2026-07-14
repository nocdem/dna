/**
 * @file test_conf_root_air.c
 * @brief B1 Stage-1 increment 3 — commitment-set-root construction gate (is_zk=0).
 *
 * Proves the CA accumulator binds the ORDERED commitment set to one root:
 *   (accept) honest trace ⇒ 0 violations, and the verifier's INDEPENDENT recompute
 *            of commitment_root from the ordered {c_i} matches the trace's cacc;
 *   (reject) wrong root, order-forgery, padding-inject, gating-bypass, CA-input
 *            decoupling, cacc-chain tamper — every one ⇒ ≥1 violation.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "../conf_root_air.h"
#include "../poseidon2_air_cols.h"

#define ROWS 8u  /* log_height = 3 */
#define LANES CONF_COMMIT_C_LANES

static int fails = 0;

static void get_c(const uint64_t *trace, size_t r, uint64_t c[LANES]) {
    const uint64_t *vc = trace + r * CONF_ROOT_WIDTH + CONF_ROOT_COMMIT_OFF + CONF_COMMIT_VC_OFF;
    for (int j = 0; j < LANES; j++)
        c[j] = vc[p2air_end_post_off(P2AIR_HALF_FULL_ROUNDS - 1, (size_t)j)];
}

static void expect_reject(const char *name, const uint64_t *bad, const uint64_t *root) {
    int v = conf_root_air_eval(bad, ROWS, root);
    if (v >= 1) printf("  [reject] %-40s caught (%d viol) — OK\n", name, v);
    else { printf("  [reject] %-40s NOT caught — FAIL\n", name); fails++; }
}

int main(void) {
    const uint64_t outputs[3] = {100, 200, 300};
    uint64_t blind[2 * ROWS];
    for (unsigned i = 0; i < 2 * ROWS; i++) blind[i] = 0x2000 + i;

    uint64_t honest[ROWS * CONF_ROOT_WIDTH];
    uint64_t root[LANES];
    if (!conf_root_air_generate(outputs, 3, 650, 50, blind, 3, honest, root)) {
        fprintf(stderr, "FAIL: generate\n");
        return 1;
    }

    int v = conf_root_air_eval(honest, ROWS, root);
    if (v == 0) printf("  [accept] honest trace                          0 viol — OK\n");
    else { printf("  [accept] honest trace                          %d viol — FAIL\n", v); fails++; }

    /* Verifier INDEPENDENT recompute from the ordered real commitments. */
    uint64_t c_list[5 * LANES];
    for (int r = 0; r < 5; r++) get_c(honest, (size_t)r, c_list + (size_t)r * LANES);
    uint64_t root_recomp[LANES];
    conf_root_air_recompute_root(c_list, 5, root_recomp);
    if (memcmp(root, root_recomp, sizeof(root)) == 0)
        printf("  [check ] verifier recompute == trace root      match — OK\n");
    else { printf("  [check ] verifier recompute mismatch — FAIL\n"); fails++; }

    uint64_t bad[ROWS * CONF_ROOT_WIDTH];
    #define CLONE() memcpy(bad, honest, sizeof(bad))
    #define CA1(r, off) bad[(size_t)(r) * CONF_ROOT_WIDTH + CONF_ROOT_CA1_OFF + (off)]
    #define CA2(r, off) bad[(size_t)(r) * CONF_ROOT_WIDTH + CONF_ROOT_CA2_OFF + (off)]
    #define CACC(r, j)  bad[(size_t)(r) * CONF_ROOT_WIDTH + CONF_ROOT_CACC_OFF + (j)]

    /* KAT-A: wrong commitment_root ⇒ last-row bind rejects. */
    {
        uint64_t wrong[LANES]; memcpy(wrong, root, sizeof(wrong)); wrong[0] ^= 1;
        expect_reject("wrong commitment_root", honest, wrong);
    }

    /* KAT-B: order-forgery — recompute with a permuted set gives a DIFFERENT root,
     * so the honest trace (bound to the in-order root) rejects that root. */
    {
        uint64_t swapped[5 * LANES];
        memcpy(swapped, c_list, sizeof(swapped));
        for (int j = 0; j < LANES; j++) { /* swap c_0 and c_1 */
            uint64_t t = swapped[0 * LANES + j];
            swapped[0 * LANES + j] = swapped[1 * LANES + j];
            swapped[1 * LANES + j] = t;
        }
        uint64_t root_perm[LANES];
        conf_root_air_recompute_root(swapped, 5, root_perm);
        if (memcmp(root_perm, root, sizeof(root)) != 0)
            printf("  [check ] permuted order ⇒ different root       (non-commutative) — OK\n");
        else { printf("  [check ] order-forgery not detected — FAIL\n"); fails++; }
        expect_reject("order-forgery root", honest, root_perm);
    }

    /* KAT-C: padding-inject — set a padding row's cacc to a folded value (bypass
     * the freeze) ⇒ gating constraint rejects (is_real=0 ⇒ must equal prev). */
    CLONE();
    CACC(5, 0) = CACC(5, 0) + 1;
    expect_reject("padding cacc mutated (freeze bypass)", bad, root);

    /* KAT-D: CA1 domain tamper. */
    CLONE();
    CA1(2, p2air_input_off(4)) = 999;
    expect_reject("CA1 DOMSEP_ACC tampered", bad, root);

    /* KAT-E: CA2 decoupled from c_r (mutate CA2.inputs[0]). */
    CLONE();
    CA2(1, p2air_input_off(0)) ^= 1;
    expect_reject("CA2 input != c_r (decoupled)", bad, root);

    /* KAT-F: cacc chain tamper on a real row ⇒ gating + next CA1 prev-input reject. */
    CLONE();
    CACC(2, 1) ^= 1;
    expect_reject("intermediate cacc tampered", bad, root);

    /* KAT-G: tamper a CA2 permutation interior cell ⇒ poseidon2 rejects. */
    CLONE();
    CA2(0, p2air_beg_sbox_off(0, 0)) ^= 1;
    expect_reject("CA2 Poseidon2 block tampered", bad, root);

    if (fails) { printf("conf_root_air: %d FAIL\n", fails); return 1; }
    printf("conf_root_air: honest + independent-recompute + order-forgery + 6/6 "
           "attacks rejected (commitment-set-root CONSTRUCTED) — PASS\n");
    return 0;
}
