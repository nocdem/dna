/**
 * Nodus — Witness Merkle Tree
 *
 * SHA3-512 Merkle tree over the UTXO set. Produces a deterministic
 * state_root that summarizes post-block UTXO state, enabling:
 *   - Block hash binding to consensus state (header includes state_root)
 *   - Light-client / SPV verification via Merkle proofs
 *   - Fraud-proof detection — a tampered witness response fails to
 *     verify against the chain-attested state_root
 *
 * Determinism rules (must be identical across all witnesses):
 *   - Leaves sorted by nullifier ASC (UTXO primary key, unique)
 *   - Leaf hash = SHA3-512(nullifier(64) || owner(128 hex ASCII)
 *                          || amount_le(8) || token_id(64)
 *                          || tx_hash(64) || output_index_le(4))
 *   - Internal node = SHA3-512(left(64) || right(64))
 *   - Odd sibling at any level: duplicated (Bitcoin convention)
 *   - Empty UTXO set: root = SHA3-512("") (deterministic zero-state)
 *
 * @file nodus_witness_merkle.h
 */

#ifndef NODUS_WITNESS_MERKLE_H
#define NODUS_WITNESS_MERKLE_H

#include "witness/nodus_witness.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_MERKLE_HASH_LEN     64   /* SHA3-512 */
#define NODUS_MERKLE_MAX_DEPTH    32   /* 2^32 leaves max — far beyond capacity */

/**
 * Compute SHA3-512 Merkle root over the current UTXO set.
 * Called after UTXO writes are complete inside the BFT commit SQL
 * transaction, so the root reflects post-block state.
 *
 * @param w           Witness context (uses w->db)
 * @param root_out    [out] 64-byte Merkle root (NODUS_MERKLE_HASH_LEN)
 * @return 0 on success, -1 on error (DB error, OpenSSL failure)
 */
int nodus_witness_merkle_compute_utxo_root(nodus_witness_t *w,
                                             uint8_t *root_out);

/**
 * Compute the SHA3-512 leaf hash for a single UTXO row.
 * Exposed for proof verification and unit tests.
 *
 * @param nullifier     64-byte nullifier
 * @param owner         NUL-terminated owner fingerprint (128 hex chars)
 * @param amount        UTXO amount
 * @param token_id      64-byte token ID (zeros for native)
 * @param tx_hash       64-byte creating TX hash
 * @param output_index  Output index within TX
 * @param leaf_out      [out] 64-byte leaf hash
 * @return 0 on success, -1 on error
 */
int nodus_witness_merkle_leaf_hash(const uint8_t *nullifier,
                                     const char *owner,
                                     uint64_t amount,
                                     const uint8_t *token_id,
                                     const uint8_t *tx_hash,
                                     uint32_t output_index,
                                     uint8_t *leaf_out);

/**
 * Build a Merkle proof path for a target leaf hash.
 * Proof consists of sibling hashes from leaf level up to root, plus
 * a bitfield of left/right positions (0 = sibling is right, 1 = left).
 *
 * Caller provides pre-allocated sibling buffer. Returns depth (number of
 * sibling hashes written) or -1 on error. depth=0 means the tree has a
 * single leaf equal to the root.
 *
 * @param w                Witness context
 * @param target_leaf      64-byte leaf hash to prove
 * @param siblings_out     [out] Array of up to max_depth sibling hashes
 *                         (each NODUS_MERKLE_HASH_LEN bytes, flat buffer)
 * @param positions_out    [out] Bitfield: bit i = 1 if sibling is on the
 *                         LEFT at level i, 0 if on the RIGHT
 * @param max_depth        Capacity of siblings_out in units of
 *                         NODUS_MERKLE_HASH_LEN
 * @param depth_out        [out] Actual depth written (number of siblings)
 * @param root_out         [out] Optional — 64-byte computed root
 *                         (may be NULL)
 * @return 0 on success, -1 on error or target_leaf not found
 */
int nodus_witness_merkle_build_proof(nodus_witness_t *w,
                                       const uint8_t *target_leaf,
                                       uint8_t *siblings_out,
                                       uint32_t *positions_out,
                                       int max_depth,
                                       int *depth_out,
                                       uint8_t *root_out);

/**
 * Verify a Merkle proof against an expected root.
 * Pure function — no DB access. Suitable for client-side verification.
 *
 * @param leaf        64-byte target leaf hash
 * @param siblings    Array of sibling hashes (flat, depth * 64 bytes)
 * @param positions   Position bitfield (same format as build_proof)
 * @param depth       Number of siblings
 * @param expected_root  64-byte expected root
 * @return 0 if proof verifies, -1 otherwise
 */
int nodus_witness_merkle_verify_proof(const uint8_t *leaf,
                                        const uint8_t *siblings,
                                        uint32_t positions,
                                        int depth,
                                        const uint8_t *expected_root);

/**
 * Compute the RFC 6962 Merkle tx_root over a list of raw TX hashes.
 *
 * Required by the multi-tx block refactor: each block's `tx_root`
 * column is this aggregate hash. The wrapper applies the leaf domain
 * tag (0x00 prefix) to each input before feeding the leaves into the
 * §2.1 root recursion. CVE-2012-2459 cannot reproduce the legacy
 * collision because leaves and inner nodes hash to disjoint preimages.
 *
 * @param tx_hashes  n * 64 bytes of raw TX hashes (NOT pre-hashed)
 * @param n          number of hashes; 0 returns the empty-tree root
 * @param out        [out] 64-byte tx_root
 * @return 0 on success, -1 on error or when n exceeds the per-block
 *         limit NODUS_W_MAX_BLOCK_TXS
 */
int nodus_witness_merkle_tx_root(const uint8_t *tx_hashes, size_t n, uint8_t out[64]);

/**
 * @brief Build an inclusion proof for a TX hash within a specific block's tx_root.
 *
 * Symmetric to nodus_witness_merkle_build_proof but operates on the
 * block-scoped tx_root tree. The caller supplies a block_height; this
 * function fetches the committed TX hashes for that block in commit
 * order (tx_index ASC), builds the RFC 6962 Merkle tree, and returns
 * the proof for target_tx_hash. The raw tx_hash is leaf-tagged
 * internally to match nodus_witness_merkle_tx_root().
 *
 * @param w               Witness context (uses w->db)
 * @param block_height    Block whose tx_root we're proving against
 * @param target_tx_hash  64-byte TX hash to prove (raw, pre-tag)
 * @param siblings_out    [out] Flat sibling buffer (max_depth * 64 bytes)
 * @param positions_out   [out] Position bitfield (matches verify_proof convention)
 * @param max_depth       Capacity of siblings_out in units of NODUS_MERKLE_HASH_LEN
 * @param depth_out       [out] Actual depth written
 * @param root_out        [out] Optional 64-byte tx_root (may be NULL)
 * @return 0 on success, -1 on error (target not found, DB error, too deep, etc.)
 */
int nodus_witness_merkle_build_tx_proof(nodus_witness_t *w,
                                          uint64_t block_height,
                                          const uint8_t *target_tx_hash,
                                          uint8_t *siblings_out,
                                          uint32_t *positions_out,
                                          int max_depth,
                                          int *depth_out,
                                          uint8_t *root_out);

/* ── Tree-tag domain-separated leaf helpers (witness stake v1) ──────
 *
 * Per §3.1 of the stake v1 design (F-CRYPTO-04 mitigation), every
 * Merkle subtree (utxo / validator / delegation / reward) prefixes
 * a 1-byte NODUS_TREE_TAG_* constant to both its leaf KEYS and its
 * leaf VALUE HASHES. Without this prefix, a validator pubkey and
 * a reward-tree pubkey with identical bytes would collide — the
 * domain tag makes the preimages disjoint.
 *
 * These helpers are pure: no allocation, no logging, deterministic.
 */

/**
 * Produce the Merkle leaf KEY for a given tree.
 * Formula: SHA3-512(tree_tag || raw_key_data)
 * The 64-byte output becomes the tree's leaf identifier.
 *
 * @param tree_tag  One of NODUS_TREE_TAG_{UTXO,VALIDATOR,DELEGATION,REWARD}
 * @param raw_key   Raw key bytes (e.g., validator pubkey, delegator fp)
 * @param raw_len   Length of raw_key in bytes (may be 0)
 * @param out_key   [out] 64-byte keyed hash
 */
void nodus_merkle_leaf_key(uint8_t tree_tag,
                           const uint8_t *raw_key, size_t raw_len,
                           uint8_t out_key[64]);

/**
 * Produce the Merkle leaf VALUE HASH for a given tree.
 * Formula: SHA3-512(tree_tag || cbor_serialized_record)
 * This is what goes into the Merkle tree as the leaf value.
 *
 * @param tree_tag  One of NODUS_TREE_TAG_{UTXO,VALIDATOR,DELEGATION,REWARD}
 * @param cbor      CBOR-serialized record bytes (may be NULL if cbor_len == 0)
 * @param cbor_len  Length of cbor in bytes (may be 0)
 * @param out_hash  [out] 64-byte value hash
 */
void nodus_merkle_leaf_value_hash(uint8_t tree_tag,
                                  const uint8_t *cbor, size_t cbor_len,
                                  uint8_t out_hash[64]);

/**
 * Produce the canonical "empty tree" root for a given subtree.
 * Formula: SHA3-512(tree_tag || 0x00)
 *
 * Used when a subtree has no leaves (e.g., delegation_tree at
 * genesis before the first DELEGATE TX). MUST be deterministic
 * across all 7 witnesses — this value ends up in state_root from
 * block 1, so any divergence would fork the chain.
 *
 * @param tree_tag  One of NODUS_TREE_TAG_{UTXO,VALIDATOR,DELEGATION,REWARD}
 * @param out_root  [out] 64-byte empty-subtree root
 */
void nodus_merkle_empty_root(uint8_t tree_tag, uint8_t out_root[64]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_MERKLE_H */
