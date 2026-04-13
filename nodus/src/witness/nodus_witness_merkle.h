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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_MERKLE_H */
