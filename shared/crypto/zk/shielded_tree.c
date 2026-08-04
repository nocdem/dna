/**
 * @file shielded_tree.c
 * @brief Depth-24 incremental Merkle tree over shielded note commitments.
 *
 * See shielded_tree.h. The node hash is the S0 note_merkle_compress and the walk
 * is the LSB-first MerkleTreeMmcs order conf_membership_air.h:12-42 arithmetizes,
 * so shielded_tree_root == the anchor conf_membership_air_generate computes from
 * an extracted path. The incremental root is maintained by the standard
 * filled-subtrees algorithm (O(DEPTH) per append); sibling paths are extracted by
 * recomputing subtree roots on demand, using the cached empty roots E_i for any
 * subtree that is still entirely unfilled.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#include "shielded_tree.h"

#include <stdlib.h>
#include <string.h>

#define DIGEST_BYTES (sizeof(uint64_t) * SHIELDED_TREE_LANES)

/* E_0 = {0,0,0,0}; E_{i+1} = note_merkle_compress(E_i, E_i). */
static void compute_empty_roots(uint64_t E[SHIELDED_TREE_DEPTH + 1][SHIELDED_TREE_LANES]) {
    memset(E[0], 0, DIGEST_BYTES);
    for (unsigned i = 0; i < SHIELDED_TREE_DEPTH; i++)
        note_merkle_compress(E[i], E[i], E[i + 1]);
}

shielded_tree_status_t shielded_tree_init(shielded_tree_t *t) {
    if (!t) return SHIELDED_TREE_ERR_NULL;

    memset(t, 0, sizeof(*t));
    compute_empty_roots(t->empty);

    /* Empty tree: every filled-subtree slot is the empty root at its level, and
     * the whole-tree root is E_DEPTH. */
    for (unsigned i = 0; i < SHIELDED_TREE_DEPTH; i++)
        memcpy(t->filled[i], t->empty[i], DIGEST_BYTES);
    memcpy(t->root, t->empty[SHIELDED_TREE_DEPTH], DIGEST_BYTES);

    t->next_index = 0;
    t->leaves = NULL;
    t->leaves_cap = 0;
    return SHIELDED_TREE_OK;
}

void shielded_tree_free(shielded_tree_t *t) {
    if (!t) return;
    free(t->leaves);
    t->leaves = NULL;
    t->leaves_cap = 0;
}

/* Grow leaf storage so that index `idx` is addressable. Fail-closed: on OOM the
 * existing buffer is left intact and ERR_NOMEM is returned. */
static shielded_tree_status_t ensure_leaf_slot(shielded_tree_t *t, uint64_t idx) {
    if (idx < t->leaves_cap) return SHIELDED_TREE_OK;

    uint64_t new_cap = t->leaves_cap ? t->leaves_cap : 16;
    while (new_cap <= idx) new_cap *= 2;

    /* Overflow / absurd-size guard (idx < CAPACITY on the normal path). */
    if (new_cap > SHIELDED_TREE_CAPACITY) new_cap = SHIELDED_TREE_CAPACITY;

    uint64_t (*grown)[SHIELDED_TREE_LANES] =
        realloc(t->leaves, (size_t)new_cap * DIGEST_BYTES);
    if (!grown) return SHIELDED_TREE_ERR_NOMEM;

    t->leaves = grown;
    t->leaves_cap = new_cap;
    return SHIELDED_TREE_OK;
}

/* Standard filled-subtrees incremental root update: walk index from leaf to
 * root; at each level a left child (bit==0) pairs with the empty root of its
 * (still unfilled) right subtree and is recorded as the filled-left for a future
 * right sibling, a right child (bit==1) pairs with the recorded filled-left. */
static void incremental_update(shielded_tree_t *t, uint64_t index,
                               const uint64_t leaf[SHIELDED_TREE_LANES]) {
    uint64_t cur[SHIELDED_TREE_LANES];
    memcpy(cur, leaf, DIGEST_BYTES);

    uint64_t ci = index;
    for (unsigned i = 0; i < SHIELDED_TREE_DEPTH; i++) {
        uint64_t left[SHIELDED_TREE_LANES], right[SHIELDED_TREE_LANES];
        if ((ci & 1u) == 0) {
            memcpy(left, cur, DIGEST_BYTES);
            memcpy(right, t->empty[i], DIGEST_BYTES);
            memcpy(t->filled[i], cur, DIGEST_BYTES);
        } else {
            memcpy(left, t->filled[i], DIGEST_BYTES);
            memcpy(right, cur, DIGEST_BYTES);
        }
        note_merkle_compress(left, right, cur);
        ci >>= 1;
    }
    memcpy(t->root, cur, DIGEST_BYTES);
}

shielded_tree_status_t shielded_tree_append(shielded_tree_t *t,
                                            const uint64_t leaf[SHIELDED_TREE_LANES],
                                            uint64_t *pos_out) {
    if (!t || !leaf) return SHIELDED_TREE_ERR_NULL;

    /* Capacity check FIRST — before any allocation or state change. The counter
     * never wraps; positions >= 2^24 are refused, fail-closed. */
    if (t->next_index >= SHIELDED_TREE_CAPACITY) return SHIELDED_TREE_ERR_FULL;

    uint64_t index = t->next_index;
    shielded_tree_status_t st = ensure_leaf_slot(t, index);
    if (st != SHIELDED_TREE_OK) return st; /* tree unchanged on OOM */

    memcpy(t->leaves[index], leaf, DIGEST_BYTES);
    incremental_update(t, index, leaf);
    t->next_index = index + 1;

    if (pos_out) *pos_out = index;
    return SHIELDED_TREE_OK;
}

shielded_tree_status_t shielded_tree_root(const shielded_tree_t *t,
                                          uint64_t out[SHIELDED_TREE_LANES]) {
    if (!t || !out) return SHIELDED_TREE_ERR_NULL;
    memcpy(out, t->root, DIGEST_BYTES);
    return SHIELDED_TREE_OK;
}

shielded_tree_status_t shielded_tree_empty_root(unsigned level,
                                                uint64_t out[SHIELDED_TREE_LANES]) {
    if (!out) return SHIELDED_TREE_ERR_NULL;
    if (level > SHIELDED_TREE_DEPTH) return SHIELDED_TREE_ERR_RANGE;
    uint64_t E[SHIELDED_TREE_DEPTH + 1][SHIELDED_TREE_LANES];
    compute_empty_roots(E);
    memcpy(out, E[level], DIGEST_BYTES);
    return SHIELDED_TREE_OK;
}

/* Root of the subtree rooted at (level, node_index) over the currently-appended
 * leaves. A subtree whose leftmost leaf is at or beyond next_index is entirely
 * unfilled and collapses to the cached empty root E_level — this is the O(count)
 * shortcut that makes an otherwise 2^24-leaf recompute tractable. */
static void subtree_root(const shielded_tree_t *t, unsigned level,
                         uint64_t node_index, uint64_t out[SHIELDED_TREE_LANES]) {
    uint64_t first_leaf = node_index << level; /* level<=DEPTH, fits in u64 */
    if (first_leaf >= t->next_index) {
        memcpy(out, t->empty[level], DIGEST_BYTES);
        return;
    }
    if (level == 0) {
        memcpy(out, t->leaves[node_index], DIGEST_BYTES);
        return;
    }
    uint64_t l[SHIELDED_TREE_LANES], r[SHIELDED_TREE_LANES];
    subtree_root(t, level - 1, node_index * 2, l);
    subtree_root(t, level - 1, node_index * 2 + 1, r);
    note_merkle_compress(l, r, out);
}

shielded_tree_status_t
shielded_tree_path(const shielded_tree_t *t, uint64_t pos,
                   uint64_t leaf_out[SHIELDED_TREE_LANES],
                   uint64_t siblings_out[SHIELDED_TREE_DEPTH][SHIELDED_TREE_LANES]) {
    if (!t || !leaf_out || !siblings_out) return SHIELDED_TREE_ERR_NULL;
    if (pos >= t->next_index) return SHIELDED_TREE_ERR_RANGE;

    memcpy(leaf_out, t->leaves[pos], DIGEST_BYTES);

    /* LSB-first: at level i the sibling of pos's node (index pos>>i) is the node
     * at index (pos>>i)^1 — its subtree root, or E_i if that side is unfilled. */
    for (unsigned i = 0; i < SHIELDED_TREE_DEPTH; i++) {
        uint64_t sib_index = (pos >> i) ^ 1u;
        subtree_root(t, i, sib_index, siblings_out[i]);
    }
    return SHIELDED_TREE_OK;
}
