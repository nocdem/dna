/**
 * @file test_shielded_tree.c
 * @brief F1b+F1c — depth-24 incremental note-commitment Merkle tree.
 *
 * T1  empty-root KAT     : E_1..E_24 == compress(E_{i-1}, E_{i-1}) recomputed
 *                          independently in the test (not read from the module).
 * T2  incremental-vs-full: the incremental root (filled-subtrees algorithm) ==
 *                          a test-side recursive recompute over [leaves ‖ empty]
 *                          for several fill counts.
 * T3  BRIDGE KAT (G-SEC-F1-1): an extracted (leaf,pos,siblings) fed to
 *                          conf_membership_air_generate reproduces the tree root
 *                          BYTE-FOR-BYTE — incl. the position-0 empty-fill seam
 *                          whose siblings are ALL cached empty-subtree roots.
 * T4  capacity           : append at position 2^24 returns ERR_FULL (counter
 *                          set near the cap directly — no 16.7M appends).
 * T5  edges              : NULL args, single-leaf tree.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../conf_membership_air.h"
#include "../note_commit.h"
#include "../shielded_tree.h"

#define DEPTH SHIELDED_TREE_DEPTH
#define LANES SHIELDED_TREE_LANES
#define DBYTES (sizeof(uint64_t) * LANES)

static int fails = 0;

#define CHECK(cond, msg)                                                        \
    do {                                                                        \
        if (cond) {                                                             \
            printf("  [ ok ] %s\n", msg);                                       \
        } else {                                                                \
            printf("  [FAIL] %s\n", msg);                                       \
            fails++;                                                            \
        }                                                                       \
    } while (0)

/* Deterministic PRNG (splitmix64) — seeded from a constant, never wall-clock. */
static uint64_t g_state;
static uint64_t rng(void) {
    g_state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = g_state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* A canonical 4-lane leaf: a real note commitment (Poseidon2 output < p). The
 * note_commit field inputs MUST be canonical (< GOLDILOCKS_P) — mask the seed to
 * < 2^40 so an arbitrary/PRNG seed can never produce a non-canonical preimage. */
static void make_leaf(uint64_t seed, uint64_t out[LANES]) {
    uint64_t s = seed & 0xFFFFFFFFFFULL; /* < 2^40 < GOLDILOCKS_P */
    uint64_t addr[4] = {s + 1, s + 2, s + 3, s + 4};
    uint64_t rcm[2] = {s + 5, s + 6};
    note_commit(s, addr, rcm, out);
}

/* ── Test-side independent empty roots + full recursive recompute ──────────── */
static uint64_t g_E[DEPTH + 1][LANES];
static void test_compute_E(void) {
    memset(g_E[0], 0, DBYTES);
    for (unsigned i = 0; i < DEPTH; i++)
        note_merkle_compress(g_E[i], g_E[i], g_E[i + 1]);
}

/* Root of the subtree at (level, node_index) over `count` leaves, using the
 * empty-subtree identity for any fully-unfilled side. This is the "right-spine"
 * boundary walk — NOT a literal 2^24-leaf rebuild. */
static void full_subtree(const uint64_t (*leaves)[LANES], uint64_t count,
                         unsigned level, uint64_t node_index, uint64_t out[LANES]) {
    uint64_t first = node_index << level;
    if (first >= count) {
        memcpy(out, g_E[level], DBYTES);
        return;
    }
    if (level == 0) {
        memcpy(out, leaves[node_index], DBYTES);
        return;
    }
    uint64_t l[LANES], r[LANES];
    full_subtree(leaves, count, level - 1, node_index * 2, l);
    full_subtree(leaves, count, level - 1, node_index * 2 + 1, r);
    note_merkle_compress(l, r, out);
}

/* ── T1 ────────────────────────────────────────────────────────────────────── */
static void t1_empty_root_kat(void) {
    printf("T1: empty-subtree root KAT (E_1..E_%d)\n", DEPTH);

    uint64_t e0[LANES];
    shielded_tree_status_t st = shielded_tree_empty_root(0, e0);
    uint64_t zero[LANES] = {0, 0, 0, 0};
    CHECK(st == SHIELDED_TREE_OK && memcmp(e0, zero, DBYTES) == 0,
          "E_0 == all-zero digest");

    /* Independent derivation: prev starts at E_0, each level = compress(prev,prev). */
    uint64_t prev[LANES];
    memcpy(prev, zero, DBYTES);
    int all_ok = 1;
    for (unsigned lvl = 1; lvl <= DEPTH; lvl++) {
        uint64_t expect[LANES];
        note_merkle_compress(prev, prev, expect);
        uint64_t got[LANES];
        if (shielded_tree_empty_root(lvl, got) != SHIELDED_TREE_OK) all_ok = 0;
        if (memcmp(got, expect, DBYTES) != 0) all_ok = 0;
        memcpy(prev, expect, DBYTES);
    }
    CHECK(all_ok, "E_i == compress(E_{i-1}, E_{i-1}) for i=1..24 (independent)");

    uint64_t junk[LANES];
    CHECK(shielded_tree_empty_root(DEPTH + 1, junk) == SHIELDED_TREE_ERR_RANGE,
          "empty_root(level>DEPTH) rejected");
    CHECK(shielded_tree_empty_root(0, NULL) == SHIELDED_TREE_ERR_NULL,
          "empty_root(NULL out) rejected");
}

/* ── T2 ────────────────────────────────────────────────────────────────────── */
static void t2_incremental_vs_full(void) {
    printf("T2: incremental root == full recompute\n");

    /* N=0: an empty tree's root is E_24. */
    {
        shielded_tree_t t;
        shielded_tree_init(&t);
        uint64_t root[LANES], full[LANES];
        shielded_tree_root(&t, root);
        full_subtree(NULL, 0, DEPTH, 0, full); /* count 0 -> never derefs leaves */
        CHECK(memcmp(root, full, DBYTES) == 0, "N=0 root == E_24");
        CHECK(memcmp(root, g_E[DEPTH], DBYTES) == 0, "N=0 root == g_E[24]");
        shielded_tree_free(&t);
    }

    const uint64_t counts[] = {1, 2, 3, 5, 7, 13, 100};
    for (size_t c = 0; c < sizeof(counts) / sizeof(counts[0]); c++) {
        uint64_t n = counts[c];
        shielded_tree_t t;
        shielded_tree_init(&t);

        uint64_t(*leaves)[LANES] = malloc((size_t)n * DBYTES);
        for (uint64_t i = 0; i < n; i++) {
            make_leaf(0xA000u + c * 1000u + i, leaves[i]);
            uint64_t pos = 0xdead;
            shielded_tree_status_t st = shielded_tree_append(&t, leaves[i], &pos);
            if (st != SHIELDED_TREE_OK || pos != i) {
                printf("  [FAIL] append n=%llu i=%llu st=%d pos=%llu\n",
                       (unsigned long long)n, (unsigned long long)i, st,
                       (unsigned long long)pos);
                fails++;
            }
        }
        uint64_t root[LANES], full[LANES];
        shielded_tree_root(&t, root);
        full_subtree(leaves, n, DEPTH, 0, full);
        char msg[64];
        snprintf(msg, sizeof msg, "N=%llu incremental == full recompute",
                 (unsigned long long)n);
        CHECK(memcmp(root, full, DBYTES) == 0, msg);
        free(leaves);
        shielded_tree_free(&t);
    }

    /* A few deterministically "random" fill counts. */
    g_state = 0x5EED1234ABCD0001ULL;
    for (int r = 0; r < 4; r++) {
        uint64_t n = 1 + (rng() % 200);
        shielded_tree_t t;
        shielded_tree_init(&t);
        uint64_t(*leaves)[LANES] = malloc((size_t)n * DBYTES);
        for (uint64_t i = 0; i < n; i++) {
            make_leaf(rng(), leaves[i]);
            shielded_tree_append(&t, leaves[i], NULL);
        }
        uint64_t root[LANES], full[LANES];
        shielded_tree_root(&t, root);
        full_subtree(leaves, n, DEPTH, 0, full);
        char msg[64];
        snprintf(msg, sizeof msg, "random N=%llu incremental == full",
                 (unsigned long long)n);
        CHECK(memcmp(root, full, DBYTES) == 0, msg);
        free(leaves);
        shielded_tree_free(&t);
    }
}

/* ── T3 (BRIDGE KAT) ───────────────────────────────────────────────────────── */
/* Feed an extracted path to conf_membership_air's generator and compare the
 * anchor it computes with the tree root, byte-for-byte. */
static int bridge_check(const shielded_tree_t *t, uint64_t pos, const char *label) {
    uint64_t leaf[LANES];
    uint64_t sibs[DEPTH][LANES];
    if (shielded_tree_path(t, pos, leaf, sibs) != SHIELDED_TREE_OK) {
        printf("  [FAIL] %s: path extraction failed\n", label);
        fails++;
        return 0;
    }

    uint64_t root[LANES];
    shielded_tree_root(t, root);

    uint64_t *trace = malloc((size_t)DEPTH * CONF_MEMB_WIDTH * sizeof(uint64_t));
    uint64_t anchor[LANES];
    /* siblings buffer is contiguous DEPTH×LANES, exactly what the generator wants. */
    bool ok = conf_membership_air_generate(DEPTH, leaf, pos, &sibs[0][0], trace,
                                           anchor);
    int match = ok && memcmp(anchor, root, DBYTES) == 0;
    char msg[128];
    snprintf(msg, sizeof msg, "%s (pos=%llu): AIR anchor == tree root", label,
             (unsigned long long)pos);
    CHECK(match, msg);
    free(trace);
    return match;
}

static void t3_bridge_kat(void) {
    printf("T3: BRIDGE KAT — conf_membership_air anchor == tree root\n");

    /* Empty-fill boundary: a lone leaf at position 0. Its whole path is the
     * cached empty-subtree roots — the exact seam the empty roots exist for. */
    {
        shielded_tree_t t;
        shielded_tree_init(&t);
        uint64_t leaf0[LANES];
        make_leaf(0xF00D, leaf0);
        shielded_tree_append(&t, leaf0, NULL);

        uint64_t got_leaf[LANES], sibs[DEPTH][LANES];
        shielded_tree_path(&t, 0, got_leaf, sibs);
        int siblings_all_empty = (memcmp(got_leaf, leaf0, DBYTES) == 0);
        for (unsigned i = 0; i < DEPTH; i++)
            if (memcmp(sibs[i], g_E[i], DBYTES) != 0) siblings_all_empty = 0;
        CHECK(siblings_all_empty,
              "pos-0 lone leaf: path is leaf0 + all empty-subtree roots");

        bridge_check(&t, 0, "empty-fill boundary");
        shielded_tree_free(&t);
    }

    /* Populated tree: open several filled positions, incl. first/last. */
    {
        shielded_tree_t t;
        shielded_tree_init(&t);
        const uint64_t n = 11;
        for (uint64_t i = 0; i < n; i++) {
            uint64_t leaf[LANES];
            make_leaf(0xB00 + i, leaf);
            shielded_tree_append(&t, leaf, NULL);
        }
        bridge_check(&t, 0, "populated first");
        bridge_check(&t, 4, "populated middle");
        bridge_check(&t, 7, "populated middle-2");
        bridge_check(&t, n - 1, "populated last (right edge, empty siblings)");
        shielded_tree_free(&t);
    }
}

/* ── T4 ────────────────────────────────────────────────────────────────────── */
static void t4_capacity(void) {
    printf("T4: capacity = REJECT\n");

    /* Position the counter AT the cap directly (transparent struct) — the FULL
     * check runs before any storage is touched, so no 2^24 appends / no 512MB. */
    shielded_tree_t t;
    shielded_tree_init(&t);
    t.next_index = SHIELDED_TREE_CAPACITY;

    uint64_t leaf[LANES];
    make_leaf(1, leaf);
    uint64_t pos = 0xabc;
    shielded_tree_status_t st = shielded_tree_append(&t, leaf, &pos);
    CHECK(st == SHIELDED_TREE_ERR_FULL, "append at 2^24 -> ERR_FULL");
    CHECK(t.next_index == SHIELDED_TREE_CAPACITY, "counter unchanged (no wrap)");
    CHECK(pos == 0xabc, "pos_out untouched on reject");

    t.next_index = SHIELDED_TREE_CAPACITY + 7; /* defensive: strictly above cap */
    CHECK(shielded_tree_append(&t, leaf, NULL) == SHIELDED_TREE_ERR_FULL,
          "append above cap -> ERR_FULL");
    shielded_tree_free(&t);
}

/* ── T5 ────────────────────────────────────────────────────────────────────── */
static void t5_edges(void) {
    printf("T5: NULL args + single-leaf tree\n");

    uint64_t buf[LANES], sibs[DEPTH][LANES];
    CHECK(shielded_tree_init(NULL) == SHIELDED_TREE_ERR_NULL, "init(NULL)");
    CHECK(shielded_tree_root(NULL, buf) == SHIELDED_TREE_ERR_NULL, "root(NULL tree)");
    CHECK(shielded_tree_append(NULL, buf, NULL) == SHIELDED_TREE_ERR_NULL,
          "append(NULL tree)");

    shielded_tree_t t;
    shielded_tree_init(&t);
    CHECK(shielded_tree_root(&t, NULL) == SHIELDED_TREE_ERR_NULL, "root(NULL out)");
    CHECK(shielded_tree_append(&t, NULL, NULL) == SHIELDED_TREE_ERR_NULL,
          "append(NULL leaf)");
    CHECK(shielded_tree_path(&t, 0, buf, sibs) == SHIELDED_TREE_ERR_RANGE,
          "path on empty tree -> ERR_RANGE");

    uint64_t leaf[LANES];
    make_leaf(42, leaf);
    uint64_t pos = 0xff;
    CHECK(shielded_tree_append(&t, leaf, &pos) == SHIELDED_TREE_OK && pos == 0,
          "single append -> pos 0");
    CHECK(shielded_tree_path(&t, 1, buf, sibs) == SHIELDED_TREE_ERR_RANGE,
          "path(pos==count) -> ERR_RANGE");
    /* single-leaf root == full recompute */
    uint64_t root[LANES], full[LANES];
    shielded_tree_root(&t, root);
    full_subtree((const uint64_t(*)[LANES])leaf, 1, DEPTH, 0, full);
    CHECK(memcmp(root, full, DBYTES) == 0, "single-leaf root == full recompute");
    shielded_tree_free(&t);
}

int main(void) {
    printf("============================================================\n");
    printf("shielded_tree — depth-%d incremental note-commitment tree\n", DEPTH);
    printf("============================================================\n");

    test_compute_E();

    t1_empty_root_kat();
    t2_incremental_vs_full();
    t3_bridge_kat();
    t4_capacity();
    t5_edges();

    printf("------------------------------------------------------------\n");
    if (fails) {
        printf("shielded_tree: %d FAIL\n", fails);
        return 1;
    }
    printf("shielded_tree: all checks PASS\n");
    return 0;
}
