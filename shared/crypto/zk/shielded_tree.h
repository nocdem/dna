/**
 * @file shielded_tree.h
 * @brief Consensus-side depth-24 incremental Merkle tree over shielded note
 *        commitments (F1b + F1c).
 *
 * The tree the witness maintains as it appends note commitments; its root is the
 * `anchor` that a spender's conf_membership_air proof is checked against. It is
 * BYTE-MATCHED to that proof: the 2-to-1 node hash is the S0
 * `note_merkle_compress` (PaddingFreeSponge<8,4,4>, note_commit.c:66-80) and the
 * walk is the SAME LSB-first MerkleTreeMmcs order conf_membership_air.h:12-42
 * arithmetizes (bit i selects at level i; (left,right) = bit==0 ? (cur,sib) :
 * (sib,cur); cur_{i+1} = compress(left,right); anchor = cur_D).
 *
 * ── Empty-subtree roots ─────────────────────────────────────────────────────
 *   E_0 = {0,0,0,0}  (the all-zero 4-lane digest, the empty leaf)
 *   E_{i+1} = note_merkle_compress(E_i, E_i)
 * These are the sibling digests for any subtree that is still unfilled — an
 * unfilled right sibling at level i is E_i. The whole-tree empty root is E_24.
 *
 * ── Determinism ─────────────────────────────────────────────────────────────
 * The root is a pure function of (leaves, positions): note_merkle_compress is
 * deterministic, positions are assigned monotonically 0..2^24-1, the LSB-first
 * walk order is fixed, no wall-clock, no map/set iteration. Two witnesses that
 * append the same leaves in the same order produce the same root.
 *
 * ── Capacity = REJECT (user-decided 2026-08-04) ─────────────────────────────
 * Positions are 0..2^24-1. Appending when next_index == 2^24 is REFUSED with a
 * distinct FULL status (fail-closed — the counter never wraps, never overflows).
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_SHIELDED_TREE_H
#define DNAC_ZK_SHIELDED_TREE_H

#include <stdint.h>

#include "note_commit.h" /* NOTE_COMMIT_LANES, note_merkle_compress */

#ifdef __cplusplus
extern "C" {
#endif

/** User-locked tree depth (dnac/docs/plans/2026-07-22-f1-...-design.md). */
#define SHIELDED_TREE_DEPTH 24

/** Digest width (lanes) — reuses the note-commitment width. */
#define SHIELDED_TREE_LANES NOTE_COMMIT_LANES /* 4 */

/** Leaf capacity = 2^24. Valid positions are 0 .. SHIELDED_TREE_CAPACITY-1. */
#define SHIELDED_TREE_CAPACITY (UINT64_C(1) << SHIELDED_TREE_DEPTH)

/** Operation status. Non-zero is a fail-closed error; the tree is unchanged. */
typedef enum {
    SHIELDED_TREE_OK = 0,
    SHIELDED_TREE_ERR_NULL = 1,  /* NULL tree or buffer argument */
    SHIELDED_TREE_ERR_FULL = 2,  /* capacity reached — append refused */
    SHIELDED_TREE_ERR_RANGE = 3, /* position/level out of range */
    SHIELDED_TREE_ERR_NOMEM = 4, /* leaf-storage allocation failed */
} shielded_tree_status_t;

/**
 * @brief Incremental Merkle-tree state.
 *
 * `root`/`filled` are maintained in O(DEPTH) per append (the standard
 * filled-subtrees algorithm). `empty[i]` = E_i is cached at init. `leaves`
 * backs sibling-path extraction (grown on demand); it holds exactly the appended
 * leaves, so its size is O(appended count), NOT O(2^24).
 *
 * The struct is transparent so tests can position the counter near the cap
 * without 2^24 real appends (see shielded_tree_append: the FULL check runs
 * before any storage is touched). Callers should mutate it only via the API.
 */
typedef struct {
    uint64_t next_index; /* number of appended leaves == next free position */
    uint64_t root[SHIELDED_TREE_LANES];
    uint64_t filled[SHIELDED_TREE_DEPTH][SHIELDED_TREE_LANES];
    uint64_t empty[SHIELDED_TREE_DEPTH + 1][SHIELDED_TREE_LANES]; /* E_0..E_24 */
    uint64_t (*leaves)[SHIELDED_TREE_LANES]; /* appended leaves, for path extract */
    uint64_t leaves_cap;                     /* allocated leaf slots */
} shielded_tree_t;

/**
 * @brief Initialise an empty tree: computes E_0..E_24, sets root = E_24,
 *        filled[i] = E_i, next_index = 0, leaves = NULL.
 * @return SHIELDED_TREE_ERR_NULL if t is NULL, else SHIELDED_TREE_OK.
 */
shielded_tree_status_t shielded_tree_init(shielded_tree_t *t);

/** @brief Release the leaf-storage buffer. Safe on a zeroed/NULL-leaves tree. */
void shielded_tree_free(shielded_tree_t *t);

/**
 * @brief Append a leaf at the next position; updates the O(DEPTH) root path.
 * @param leaf     4-lane note commitment (MUST be canonical < GOLDILOCKS_P).
 * @param pos_out  optional; receives the 0-based position assigned to `leaf`.
 * @return SHIELDED_TREE_OK, or ERR_NULL / ERR_FULL (capacity) / ERR_NOMEM.
 *         On any error the tree state is unchanged (fail-closed).
 */
shielded_tree_status_t shielded_tree_append(shielded_tree_t *t,
                                            const uint64_t leaf[SHIELDED_TREE_LANES],
                                            uint64_t *pos_out);

/**
 * @brief Read the current incremental root (E_24 for an empty tree).
 * @return SHIELDED_TREE_OK, or ERR_NULL.
 */
shielded_tree_status_t shielded_tree_root(const shielded_tree_t *t,
                                          uint64_t out[SHIELDED_TREE_LANES]);

/**
 * @brief Compute the empty-subtree root E_level (E_0 = zero, E_{i+1} =
 *        compress(E_i, E_i)). Standalone — does not need a tree.
 * @param level  0 .. SHIELDED_TREE_DEPTH.
 * @return SHIELDED_TREE_OK, or ERR_NULL / ERR_RANGE.
 */
shielded_tree_status_t shielded_tree_empty_root(unsigned level,
                                                uint64_t out[SHIELDED_TREE_LANES]);

/**
 * @brief Extract the membership witness for a filled position: the leaf, its
 *        position, and the LSB-first sibling digests (level-0 first). Unfilled
 *        right subtrees yield the cached empty root E_i at that level. Feeding
 *        (leaf_out, pos, siblings_out) to conf_membership_air_generate
 *        reproduces shielded_tree_root exactly.
 * @param pos           position to open (MUST be < next_index).
 * @param leaf_out      4-lane leaf at `pos`.
 * @param siblings_out  DEPTH × 4 sibling digests, level-0 first.
 * @return SHIELDED_TREE_OK, or ERR_NULL / ERR_RANGE (pos >= next_index).
 */
shielded_tree_status_t
shielded_tree_path(const shielded_tree_t *t, uint64_t pos,
                   uint64_t leaf_out[SHIELDED_TREE_LANES],
                   uint64_t siblings_out[SHIELDED_TREE_DEPTH][SHIELDED_TREE_LANES]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_SHIELDED_TREE_H */
