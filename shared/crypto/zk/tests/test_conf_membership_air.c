/**
 * @file test_conf_membership_air.c
 * @brief Dual-mode C3 — Poseidon2 Merkle-path membership construction gate.
 *
 * (accept) an honest path ⇒ 0 violations, and the AIR-computed root equals an
 *          independent S0 note_merkle_compress recomputation;
 * (reject) wrong sibling, flipped direction bit, wrong anchor, pos ≠ walk,
 *          capacity-carry break, chaining break, non-boolean bit ⇒ ≥1 violation.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>

#include "../conf_membership_air.h"
#include "../field_goldilocks.h"
#include "../note_commit.h"

#define DEPTH 8u

static int fails = 0;

static void expect_reject(const char *name, const uint64_t *trace, uint64_t pos,
                          const uint64_t leaf[4], const uint64_t anchor[4]) {
    int v = conf_membership_air_eval(trace, DEPTH, leaf, pos, anchor);
    if (v >= 1) {
        printf("  [reject] %-42s caught (%d viol) — OK\n", name, v);
    } else {
        printf("  [reject] %-42s NOT caught — FAIL\n", name);
        fails++;
    }
}

/* Independent root recomputation via the S0 compress (the byte-match oracle). */
static void recompute_root(const uint64_t leaf[4], uint64_t pos,
                           const uint64_t *sibs, uint64_t out[4]) {
    uint64_t cur[4];
    memcpy(cur, leaf, sizeof cur);
    for (unsigned i = 0; i < DEPTH; i++) {
        const uint64_t *sib = sibs + (size_t)i * 4;
        uint64_t bit = (pos >> i) & 1u;
        uint64_t left[4], right[4], next[4];
        for (int j = 0; j < 4; j++) {
            left[j] = bit ? sib[j] : cur[j];
            right[j] = bit ? cur[j] : sib[j];
        }
        note_merkle_compress(left, right, next);
        memcpy(cur, next, sizeof cur);
    }
    memcpy(out, cur, sizeof(uint64_t) * 4);
}

int main(void) {
    /* Leaf = a real note commitment; siblings + position are the membership
     * witness; the root is the anchor. */
    uint64_t leaf[4];
    {
        uint64_t addr[4] = {11, 22, 33, 44}, rcm[2] = {0xdead, 0xbeef};
        note_commit(1000, addr, rcm, leaf);
    }
    const uint64_t pos = 0b01101011u & ((1u << DEPTH) - 1); /* 8-bit position */
    uint64_t sibs[DEPTH * 4];
    for (unsigned i = 0; i < DEPTH; i++)
        for (int j = 0; j < 4; j++)
            sibs[i * 4 + j] = 100u * (i + 1) + (uint64_t)j + 1;

    uint64_t trace[DEPTH * CONF_MEMB_WIDTH];
    uint64_t root[4];
    if (!conf_membership_air_generate(DEPTH, leaf, pos, sibs, trace, root)) {
        printf("FAIL: honest generate failed\n");
        return 1;
    }

    printf("============================================================\n");
    printf("C3 membership AIR — Poseidon2 Merkle path, D=%u, WIDTH=%d\n",
           DEPTH, CONF_MEMB_WIDTH);
    printf("============================================================\n");

    /* ACCEPT: honest path. */
    int v = conf_membership_air_eval(trace, DEPTH, leaf, pos, root);
    if (v == 0) printf("  [accept] honest path                            0 viol — OK\n");
    else { printf("  [accept] honest path                            %d viol — FAIL\n", v); fails++; }

    /* ACCEPT: AIR root == independent S0 note_merkle_compress recomputation. */
    {
        uint64_t ref[4];
        recompute_root(leaf, pos, sibs, ref);
        int ok = memcmp(ref, root, sizeof ref) == 0;
        printf("  [accept] AIR root == S0 compress recompute      %s\n",
               ok ? "OK" : "FAIL");
        if (!ok) fails++;
    }

    /* REJECT: wrong sibling at level 3 (breaks the compress → root ≠ anchor). */
    {
        uint64_t bad[DEPTH * CONF_MEMB_WIDTH];
        memcpy(bad, trace, sizeof bad);
        bad[3 * CONF_MEMB_WIDTH + CONF_MEMB_SIB_OFF] += 1;
        expect_reject("wrong sibling (level 3)", bad, pos, leaf, root);
    }

    /* REJECT: flip a direction bit (walk a different position → root ≠ anchor
     * AND POSACC ≠ pos). */
    {
        uint64_t bad[DEPTH * CONF_MEMB_WIDTH];
        memcpy(bad, trace, sizeof bad);
        bad[2 * CONF_MEMB_WIDTH + CONF_MEMB_BIT_OFF] ^= 1u;
        expect_reject("flip direction bit (level 2)", bad, pos, leaf, root);
    }

    /* REJECT: wrong anchor (verifier-substituted public ≠ computed root). */
    {
        uint64_t wrong_anchor[4];
        memcpy(wrong_anchor, root, sizeof wrong_anchor);
        wrong_anchor[0] += 1;
        expect_reject("wrong anchor (public root)", trace, pos, leaf, wrong_anchor);
    }

    /* REJECT: pos public ≠ the walked position (POSACC final check). */
    expect_reject("pos public != walk position", trace, pos ^ 1u, leaf, root);

    /* REJECT: wrong public leaf (level-0 CUR binding). */
    {
        uint64_t wrong_leaf[4];
        memcpy(wrong_leaf, leaf, sizeof wrong_leaf);
        wrong_leaf[1] += 1;
        expect_reject("wrong public leaf (level-0 CUR)", trace, pos, wrong_leaf, root);
    }

    /* REJECT: break the MC2 capacity carry (dm-c3 F1 — non-CR compress). */
    {
        uint64_t bad[DEPTH * CONF_MEMB_WIDTH];
        memcpy(bad, trace, sizeof bad);
        bad[0 * CONF_MEMB_WIDTH + CONF_MEMB_MC2_OFF + p2air_input_off(5)] += 1;
        expect_reject("MC2 capacity-carry break (F1)", bad, pos, leaf, root);
    }

    /* REJECT: break chaining (row-2 CUR != row-1 MC2.out). */
    {
        uint64_t bad[DEPTH * CONF_MEMB_WIDTH];
        memcpy(bad, trace, sizeof bad);
        bad[2 * CONF_MEMB_WIDTH + CONF_MEMB_CUR_OFF] += 1;
        expect_reject("chaining break (row-2 CUR)", bad, pos, leaf, root);
    }

    /* REJECT: non-boolean direction bit. */
    {
        uint64_t bad[DEPTH * CONF_MEMB_WIDTH];
        memcpy(bad, trace, sizeof bad);
        bad[1 * CONF_MEMB_WIDTH + CONF_MEMB_BIT_OFF] = 2;
        expect_reject("non-boolean direction bit", bad, pos, leaf, root);
    }

    /* REJECT: tamper POSACC (position recomposition, F3). */
    {
        uint64_t bad[DEPTH * CONF_MEMB_WIDTH];
        memcpy(bad, trace, sizeof bad);
        bad[4 * CONF_MEMB_WIDTH + CONF_MEMB_POSACC_OFF] += 8;
        expect_reject("tamper POSACC (F3 accumulator)", bad, pos, leaf, root);
    }

    printf("------------------------------------------------------------\n");
    if (fails) { printf("C3 membership: %d FAIL\n", fails); return 1; }
    printf("C3 membership: honest accepted (root byte-matches S0) + 9 attacks "
           "rejected — PASS\n");
    return 0;
}
