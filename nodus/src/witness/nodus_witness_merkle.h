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

/* ── Composite state_root combiner (witness stake v1 / Phase 3 Task 10) ──
 *
 * Per §3.1 of the stake v1 design, the chain-level state_root hashes
 * four 64-byte subtree roots in a fixed positional order:
 *
 *     state_root = SHA3-512(utxo_root        ||
 *                           validator_root   ||
 *                           delegation_root  ||
 *                           reward_root)
 *
 * Per-subtree domain separation is baked at the LEAF level via the
 * NODUS_TREE_TAG_* prefixes (see nodus_merkle_leaf_key /
 * nodus_merkle_leaf_value_hash). The outer combiner therefore does
 * NOT add any additional tag byte — positional order alone provides
 * domain separation at the state_root level. Swapping any two subtree
 * roots MUST produce a different state_root.
 *
 * This deviation from the established RFC 6962 leaf-tag convention is
 * intentional: the chain never needs to distinguish a state_root preimage
 * from a plain 4-root concat, because state_root is used only as an
 * opaque 64-byte chain-header field. See design §3.1 commentary on
 * F-CRYPTO-04 for the full argument.
 */

/**
 * Combine four subtree roots into the chain-level state_root.
 * Pure function — no allocation, no DB, no logging. Safe to call
 * from any thread.
 *
 * Order is fixed: utxo, validator, delegation, reward. ALL callers
 * must use this order; any deviation is a consensus fork.
 *
 * @param utxo_root        64-byte UTXO subtree root
 * @param validator_root   64-byte validator subtree root
 * @param delegation_root  64-byte delegation subtree root
 * @param reward_root      64-byte reward subtree root
 * @param out_state_root   [out] 64-byte composite state_root
 */
/* Hard-Fork v1: this name remains a source-compat alias for the legacy
 * 4-input formula. New code paths MUST use nodus_merkle_combine_state_root_v2
 * (5-input, 0x02 version byte). See CC-AUDIT-002 / design §5.7. */
void nodus_merkle_combine_state_root(const uint8_t utxo_root[64],
                                     const uint8_t validator_root[64],
                                     const uint8_t delegation_root[64],
                                     const uint8_t reward_root[64],
                                     uint8_t out_state_root[64]);

/* Legacy 4-input combiner retained for archive-replay / forensic use
 * (Q3 / CC-OPS-007 mitigation). Marked __attribute__((cold)) in the
 * implementation — not on the hot path post-activation. */
void nodus_merkle_combine_state_root_v1_legacy(const uint8_t utxo_root[64],
                                                const uint8_t validator_root[64],
                                                const uint8_t delegation_root[64],
                                                const uint8_t reward_root[64],
                                                uint8_t out_state_root[64]);

/* Hard-Fork v1 — 5-input combiner with outer version byte 0x02 and
 * chain_config_root contributor. v0.16 retains this cold for archive-
 * replay of pre-wipe blocks; live callers use combine_v3. */
void nodus_merkle_combine_state_root_v2(const uint8_t utxo_root[64],
                                         const uint8_t validator_root[64],
                                         const uint8_t delegation_root[64],
                                         const uint8_t reward_root[64],
                                         const uint8_t chain_config_root[64],
                                         uint8_t out_state_root[64]);

/* v0.16 — 5-input combiner with outer version byte 0x03 that replaces
 * the reward subtree slot with epoch_state. ALL live-chain callers
 * use this post-wipe. */
void nodus_merkle_combine_state_root_v3(const uint8_t utxo_root[64],
                                         const uint8_t validator_root[64],
                                         const uint8_t delegation_root[64],
                                         const uint8_t epoch_state_root[64],
                                         const uint8_t chain_config_root[64],
                                         uint8_t out_state_root[64]);

/**
 * v0.16 — Compute the validator subtree Merkle root directly from the
 * `validators` table. See load_validator_leaves in nodus_witness_merkle.c
 * for the canonical leaf layout (tag || pubkey || serialized fields).
 */
int nodus_witness_merkle_compute_validator_root(nodus_witness_t *w,
                                                 uint8_t *root_out);

/**
 * v0.16 — Compute the delegation subtree Merkle root directly from the
 * `delegations` table, sorted by (validator_pubkey, delegator_pubkey) ASC.
 */
int nodus_witness_merkle_compute_delegation_root(nodus_witness_t *w,
                                                  uint8_t *root_out);

/**
 * v0.16 — Compute the epoch_state subtree Merkle root from the
 * `epoch_state` table. Leaves embed the global total_minted/total_burned
 * counters from supply_tracking so supply-invariant coverage is included
 * in the top-level state_root.
 */
int nodus_witness_merkle_compute_epoch_state_root(nodus_witness_t *w,
                                                   uint8_t *root_out);

/**
 * Compute the chain-level state_root from the current witness state.
 *
 * Wraps compute_utxo_root (for the UTXO subtree) and combines its
 * result with validator/delegation/reward subtree roots via
 * nodus_merkle_combine_state_root. In Phase 3, the validator /
 * delegation / reward subtrees default to nodus_merkle_empty_root
 * for their respective tree tags. Phase 4+ replaces those stubs
 * with real state reads once the DB migration lands.
 *
 * Callers that previously used nodus_witness_merkle_compute_utxo_root
 * as the chain state_root MUST migrate to this function — otherwise
 * the chain-header state_root diverges from the design §3.1 formula.
 *
 * @param w         Witness context (uses w->db)
 * @param root_out  [out] 64-byte composite state_root
 * @return 0 on success, -1 on error
 */
int nodus_witness_merkle_compute_state_root(nodus_witness_t *w,
                                            uint8_t *root_out);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_WITNESS_MERKLE_H */
