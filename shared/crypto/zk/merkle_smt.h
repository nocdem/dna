/**
 * @file merkle_smt.h
 * @brief Sparse-style binary Merkle tree for STARK proof commitments (DNAC v3)
 *
 * Hash function: SHA3-512 with explicit DNAC-RP domain separators.
 * Tree structure: fixed-depth binary, balanced to power-of-2 with typed
 * null-padding for missing leaves.
 *
 * Reference: design doc § 4.4 (Determinism invariant D4).
 *
 * Determinism invariants:
 *   - D4: Binary tree, SHA3-512 internal nodes, leaves in canonical
 *         big-endian byte order, balanced to next power of 2.
 *   - D4.1: Tree depth fixed by configuration, NOT by leaf count. Missing
 *           slots filled with typed null hash.
 *
 * Faz 1 scope: API skeleton only.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef DNAC_ZK_MERKLE_SMT_H
#define DNAC_ZK_MERKLE_SMT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** SHA3-512 output size (bytes). */
#define MERKLE_SMT_HASH_SIZE 64

/** Maximum tree depth supported. Beyond 32, leaf count would exceed 2^32. */
#define MERKLE_SMT_MAX_DEPTH 32

/** Domain separator for leaf hashing (design doc § 4.4). */
#define MERKLE_SMT_LEAF_DOMAIN "DNAC_RP_LEAF\0"
#define MERKLE_SMT_LEAF_DOMAIN_LEN 13

/** Domain separator for internal node hashing. */
#define MERKLE_SMT_NODE_DOMAIN "DNAC_RP_NODE\0"
#define MERKLE_SMT_NODE_DOMAIN_LEN 13

/** Domain separator for null/empty slot hashing. */
#define MERKLE_SMT_NULL_DOMAIN "DNAC_RP_NULL\0"
#define MERKLE_SMT_NULL_DOMAIN_LEN 13

/* ============================================================================
 * Types
 * ========================================================================== */

/**
 * @brief Inclusion proof for a single leaf.
 *
 * The path[] array holds sibling hashes from leaf level up to (but excluding)
 * the root. Use `index` to determine left/right at each level.
 */
typedef struct {
    uint32_t index;                                        /**< Leaf index 0..2^depth-1 */
    uint8_t leaf_value[MERKLE_SMT_HASH_SIZE];              /**< Hashed leaf */
    uint32_t depth;                                        /**< Tree depth */
    uint8_t path[MERKLE_SMT_MAX_DEPTH][MERKLE_SMT_HASH_SIZE]; /**< Sibling hashes */
} merkle_smt_proof_t;

/* ============================================================================
 * Leaf encoding
 * ========================================================================== */

/**
 * @brief Hash a leaf value into its tree representation.
 *
 * leaf_i = SHA3-512( "DNAC_RP_LEAF\0" || i_BE_u32 || canonical_bytes(value) )
 *
 * @param index Leaf index in tree (0-indexed).
 * @param value Caller-provided value bytes (canonical encoding required).
 * @param value_len Length of value in bytes.
 * @param out_hash Output buffer of MERKLE_SMT_HASH_SIZE bytes.
 */
void merkle_smt_hash_leaf(uint32_t index,
                          const uint8_t *value,
                          size_t value_len,
                          uint8_t out_hash[MERKLE_SMT_HASH_SIZE]);

/**
 * @brief Compute null-slot hash for an empty position.
 *
 * null_i = SHA3-512( "DNAC_RP_NULL\0" || i_BE_u32 )
 *
 * @param index Slot index in tree (0-indexed).
 * @param out_hash Output buffer of MERKLE_SMT_HASH_SIZE bytes.
 */
void merkle_smt_hash_null(uint32_t index,
                          uint8_t out_hash[MERKLE_SMT_HASH_SIZE]);

/**
 * @brief Hash an internal node from its two children.
 *
 * node = SHA3-512( "DNAC_RP_NODE\0" || left || right )
 */
void merkle_smt_hash_node(const uint8_t left[MERKLE_SMT_HASH_SIZE],
                          const uint8_t right[MERKLE_SMT_HASH_SIZE],
                          uint8_t out_hash[MERKLE_SMT_HASH_SIZE]);

/* ============================================================================
 * Tree construction
 * ========================================================================== */

/**
 * @brief Compute Merkle root over a flat array of leaf values.
 *
 * Missing slots (when leaf_count < 2^depth) are filled with null hashes
 * per D4.1. Caller specifies depth explicitly to avoid ambiguity.
 *
 * @param leaves Array of leaf hashes (each MERKLE_SMT_HASH_SIZE bytes).
 *               Must already be in leaf-hashed form (call merkle_smt_hash_leaf
 *               first).
 * @param leaf_count Number of leaves (≤ 2^depth).
 * @param depth Tree depth (1..MERKLE_SMT_MAX_DEPTH).
 * @param out_root Output buffer of MERKLE_SMT_HASH_SIZE bytes.
 * @return 0 on success, -1 on invalid args.
 */
int merkle_smt_compute_root(const uint8_t *leaves,
                            size_t leaf_count,
                            uint32_t depth,
                            uint8_t out_root[MERKLE_SMT_HASH_SIZE]);

/**
 * @brief Build an inclusion proof for a single leaf index.
 *
 * @param leaves Array of leaf hashes (same as in compute_root).
 * @param leaf_count Number of leaves.
 * @param depth Tree depth.
 * @param target_index Index of leaf to prove.
 * @param out_proof Output proof structure.
 * @return 0 on success, -1 on invalid args.
 */
int merkle_smt_build_proof(const uint8_t *leaves,
                           size_t leaf_count,
                           uint32_t depth,
                           uint32_t target_index,
                           merkle_smt_proof_t *out_proof);

/**
 * @brief Verify an inclusion proof against an expected root.
 *
 * @param proof Proof structure.
 * @param expected_root Expected Merkle root (MERKLE_SMT_HASH_SIZE bytes).
 * @return true if proof verifies, false otherwise.
 */
bool merkle_smt_verify_proof(const merkle_smt_proof_t *proof,
                             const uint8_t expected_root[MERKLE_SMT_HASH_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_ZK_MERKLE_SMT_H */
