/**
 * @file ledger.h
 * @brief DNAC Transaction Ledger API
 *
 * The transaction ledger provides a permanent, auditable record of all
 * transactions with Merkle proofs for verification.
 *
 * Features:
 * - Sequential transaction numbering
 * - Incremental Merkle tree for chain integrity
 * - Supply tracking (genesis, burned, current)
 * - Transaction existence proofs
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_LEDGER_H
#define DNAC_LEDGER_H

#include "dnac.h"
#include "dnac/transaction.h"
#include "dnac/block.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Merkle root size (SHA3-512) */
#define DNAC_MERKLE_ROOT_SIZE       64

/** Maximum Merkle proof depth (leaf-to-root path length).
 *  Matches nodus/src/witness/nodus_witness_merkle.c. */
#define DNAC_MERKLE_MAX_DEPTH       32

/** Output commitment size */
#define DNAC_OUTPUT_COMMITMENT_SIZE 64

/* ============================================================================
 * Data Types
 * ========================================================================== */

/**
 * @brief Ledger entry for a committed transaction
 */
typedef struct {
    uint64_t sequence_number;                       /**< Unique sequential ID */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];            /**< Transaction hash */
    uint8_t tx_type;                                /**< GENESIS=0, SPEND=1, BURN=2 */
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE]; /**< Input nullifiers */
    uint8_t nullifier_count;                        /**< Number of nullifiers */
    uint8_t output_commitment[DNAC_OUTPUT_COMMITMENT_SIZE]; /**< Hash of outputs */
    uint8_t merkle_root[DNAC_MERKLE_ROOT_SIZE];    /**< Running Merkle root after this TX */
    uint64_t timestamp;                             /**< Unix timestamp */
    uint64_t epoch;                                 /**< Epoch number */
} dnac_ledger_entry_t;

/**
 * @brief Supply tracking state
 */
typedef struct {
    uint64_t genesis_supply;                        /**< Fixed at genesis (never changes) */
    uint64_t total_burned;                          /**< Cumulative burned amount */
    uint64_t current_supply;                        /**< genesis_supply - total_burned */
    uint8_t last_tx_hash[DNAC_TX_HASH_SIZE];       /**< Last transaction hash */
    uint64_t last_sequence;                         /**< Last sequence number */
} dnac_supply_state_t;

/* ============================================================================
 * Merkle Inclusion Proof (Anchored Design — 2026-04-16)
 *
 * Generic leaf-to-root proof for any Merkle tree in DNAC. Used for both:
 *   - UTXO inclusion in state_root  (block.state_root)
 *   - TX inclusion in tx_root       (block.tx_root)
 *
 * The "root" field stores the tree root against which this proof verifies.
 * The caller is responsible for matching the root to a BFT-anchored block
 * header via dnac_block_anchor_t (Task 20).
 *
 * RFC 6962 domain tags (MUST match nodus/src/witness/nodus_witness_merkle.c):
 *   leaf_hash(d)      = SHA3-512(0x00 || d)
 *   inner_hash(L, R)  = SHA3-512(0x01 || L || R)
 * ========================================================================== */
typedef struct {
    /* Composite leaf digest (pre-tag). For UTXO proofs this is the output of
     * nodus_witness_merkle_leaf_hash(nullifier || owner || amount || token_id
     *                                 || tx_hash || output_index). For TX
     * proofs this is the raw tx_hash. In either case, the verifier applies
     * the 0x00 leaf tag internally. */
    uint8_t  leaf_hash[DNAC_MERKLE_ROOT_SIZE];

    /* Sibling hashes along the leaf-to-root path, leaf level first. */
    uint8_t  siblings[DNAC_MERKLE_MAX_DEPTH][DNAC_MERKLE_ROOT_SIZE];

    /* Per-level sibling position:
     *   directions[i] == 1  -> sibling is on the LEFT, cur on RIGHT
     *   directions[i] == 0  -> sibling is on the RIGHT, cur on LEFT
     */
    uint8_t  directions[DNAC_MERKLE_MAX_DEPTH];

    /* Number of valid siblings/directions (0 = single-leaf tree). */
    int      proof_length;

    /* Expected root (state_root or tx_root). */
    uint8_t  root[DNAC_MERKLE_ROOT_SIZE];
} dnac_merkle_proof_t;

/* ============================================================================
 * Witness-Side Ledger Functions
 * ========================================================================== */

/**
 * @brief Initialize ledger database
 *
 * Called during witness startup. Creates tables if needed.
 *
 * @return 0 on success, -1 on error
 */
int witness_ledger_init(void *user_data);

/**
 * @brief Shutdown ledger database
 */
void witness_ledger_shutdown(void);

/**
 * @brief Add entry to ledger
 *
 * Called when a transaction is committed by consensus.
 * Updates the Merkle tree and supply tracking.
 *
 * @param entry Ledger entry to add
 * @return 0 on success, -1 on error
 */
int witness_ledger_add_entry(const dnac_ledger_entry_t *entry, void *user_data);

/**
 * @brief Get next sequence number
 *
 * @return Next sequence number (1-based), or 0 on error
 */
uint64_t witness_ledger_get_next_seq(void);

/**
 * @brief Get current Merkle root
 *
 * @param root_out Output buffer for root (DNAC_MERKLE_ROOT_SIZE bytes)
 * @return 0 on success, -1 if no entries
 */
int witness_ledger_get_root(uint8_t *root_out);

/**
 * @brief Get ledger entry by sequence number
 *
 * @param seq Sequence number
 * @param entry_out Output entry
 * @return 0 on success, -1 if not found
 */
int witness_ledger_get_entry(uint64_t seq, dnac_ledger_entry_t *entry_out, void *user_data);

/**
 * @brief Get ledger entry by transaction hash
 *
 * @param tx_hash Transaction hash
 * @param entry_out Output entry
 * @return 0 on success, -1 if not found
 */
int witness_ledger_get_entry_by_hash(const uint8_t *tx_hash,
                                      dnac_ledger_entry_t *entry_out, void *user_data);

/**
 * @brief P0-2 (v0.7.0): Get range of ledger entries
 *
 * Retrieves a range of ledger entries for chain synchronization.
 *
 * @param from_seq Start sequence (inclusive)
 * @param to_seq End sequence (inclusive), 0 = up to latest
 * @param entries Output entry array
 * @param max_entries Maximum entries to return
 * @param count_out Actual number of entries returned
 * @return 0 on success, -1 on error
 */
int witness_ledger_get_range(uint64_t from_seq,
                              uint64_t to_seq,
                              dnac_ledger_entry_t *entries,
                              int max_entries,
                              int *count_out, void *user_data);

/**
 * @brief P0-2 (v0.7.0): Get total ledger entry count
 *
 * @return Total number of entries, or 0 if empty/error
 */
uint64_t witness_ledger_get_total_entries(void *user_data);

/* ============================================================================
 * Supply Tracking Functions
 * ========================================================================== */

/**
 * @brief Initialize supply at genesis
 *
 * Called once when genesis transaction is committed.
 *
 * @param total_supply Total supply from genesis
 * @param genesis_tx_hash Genesis transaction hash
 * @return 0 on success, -1 on error
 */
int witness_supply_init(uint64_t total_supply, const uint8_t *genesis_tx_hash, void *user_data);

/**
 * @brief Record a burn transaction
 *
 * Reduces current supply by burned amount.
 *
 * @param burn_amount Amount burned
 * @param tx_hash Burn transaction hash
 * @return 0 on success, -1 on error
 */
int witness_supply_record_burn(uint64_t burn_amount, const uint8_t *tx_hash, void *user_data);

/**
 * @brief Get current supply state
 *
 * @param state_out Output supply state
 * @return 0 on success, -1 if no genesis
 */
int witness_supply_get_state(dnac_supply_state_t *state_out, void *user_data);

/* ============================================================================
 * Client Query Functions
 * ========================================================================== */

/**
 * @brief Query transaction existence with proof
 *
 * @param ctx DNAC context
 * @param tx_hash Transaction hash to query
 * @param entry_out Output ledger entry (optional, can be NULL)
 * @param proof_out Output Merkle proof (optional, can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_ledger_query_tx(dnac_context_t *ctx,
                         const uint8_t *tx_hash,
                         dnac_ledger_entry_t *entry_out,
                         dnac_merkle_proof_t *proof_out);

/**
 * @brief Get supply information from witnesses
 *
 * @param ctx DNAC context
 * @param genesis_out Output genesis supply
 * @param burned_out Output total burned
 * @param current_out Output current supply
 * @return DNAC_SUCCESS or error code
 */
int dnac_ledger_get_supply(dnac_context_t *ctx,
                           uint64_t *genesis_out,
                           uint64_t *burned_out,
                           uint64_t *current_out);

/**
 * @brief Verify a Merkle proof against its embedded root.
 *
 * Pure function — no DB, no network, no allocation. Hashes the leaf with
 * the RFC 6962 leaf tag (0x00), walks up the sibling chain with the inner
 * tag (0x01), and compares the result to proof->root.
 *
 * This does NOT verify that proof->root is BFT-trusted. Pair with
 * dnac_anchor_verify (Task 20+) for full trust.
 *
 * @param proof Proof to verify
 * @return true on hash match, false on any mismatch or invalid input.
 */
bool dnac_merkle_verify_proof(const dnac_merkle_proof_t *proof);

/* ============================================================================
 * Block Anchor — binds a block header to its 2f+1 PRECOMMIT signatures
 *
 * An anchor proves that a block_hash (and thus the state_root and tx_root it
 * contains) was finalized by BFT consensus. Clients fetch an anchor, verify
 * its commit_cert against the trusted_state's roster, and then trust the
 * state_root/tx_root inside for Merkle proof verification.
 * ========================================================================== */

#define DNAC_DILITHIUM5_SIG_SIZE 4627
#define DNAC_WITNESS_ID_SIZE     32

typedef struct {
    /* Fingerprint of the signing witness — first DNAC_WITNESS_ID_SIZE bytes
     * of SHA3-512(pubkey). Matches the convention used by the witness cluster
     * BFT code when identifying signers. */
    uint8_t signer_id[DNAC_WITNESS_ID_SIZE];

    /* Dilithium5 signature over the block's block_hash. */
    uint8_t signature[DNAC_DILITHIUM5_SIG_SIZE];
} dnac_witness_signature_t;

typedef struct {
    /* The block header whose block_hash is signed. The client MUST
     * recompute the hash from the header fields before trusting the
     * stored block_hash (prevents a malicious peer from sending a header
     * with one hash and signatures over a different hash). */
    dnac_block_t             header;

    /* Up to DNAC_MAX_WITNESSES_COMPILE_CAP PRECOMMIT signatures.
     * Duplicate signers are counted once; unknown signers are rejected. */
    dnac_witness_signature_t sigs[DNAC_MAX_WITNESSES_COMPILE_CAP];
    int                      sig_count;
} dnac_block_anchor_t;

/* ============================================================================
 * Trusted State — per-chain runtime trust anchor
 *
 * One instance per chain the client tracks. Populated by dnac_genesis_verify
 * (Phase 5) from verified genesis bytes. All subsequent block/UTXO/TX
 * verification goes through this struct — NO hardcoded roster lookups
 * elsewhere in the code.
 * ========================================================================== */

typedef struct {
    /* chain_id (= genesis block hash) — the single hardcoded value this
     * trust state derives from. */
    uint8_t                 chain_id[DNAC_BLOCK_HASH_SIZE];

    /* Chain definition (witness pubkeys, params, token info) — extracted
     * from the verified genesis block. */
    dnac_chain_definition_t chain_def;

    /* Most recently verified block anchor. Updated as the client follows
     * the chain. Starts at the genesis block after bootstrap. */
    dnac_block_anchor_t     latest_verified_anchor;
} dnac_trusted_state_t;

/**
 * Verify a block anchor: recomputes the block hash, checks that 2f+1
 * valid Dilithium5 signatures from the trusted roster cover it.
 *
 * Pure function — no DB, no network, no allocation beyond sig verify.
 *
 * @return true if the anchor is valid, false otherwise.
 */
bool dnac_anchor_verify(const dnac_block_anchor_t *anchor,
                         const dnac_trusted_state_t *trust);

/**
 * Verify genesis block bytes against a hardcoded chain_id.
 *
 * Decodes the input, checks it's genesis (height 0, prev_hash zeros,
 * is_genesis flag set), recomputes the block hash, and compares to
 * expected_chain_id. On success, populates trust_out with the verified
 * chain_def and chain_id. latest_verified_anchor is left zeroed; the
 * caller must set it via dnac_anchor_verify.
 *
 * Pure function — no DB, no network.
 *
 * @param bytes             Encoded genesis block (from dnac_block_encode).
 * @param len               Number of bytes.
 * @param expected_chain_id Hardcoded 64-byte chain_id to verify against.
 * @param trust_out         [out] Populated trusted state on success.
 * @return true on success, false on any verification failure.
 */
bool dnac_genesis_verify(const uint8_t *bytes, size_t len,
                          const uint8_t expected_chain_id[DNAC_BLOCK_HASH_SIZE],
                          dnac_trusted_state_t *trust_out);

/**
 * @brief P0-2 (v0.7.0): Sync ledger entries in range from witnesses
 *
 * Queries witness servers for a range of ledger entries.
 * Used for chain synchronization.
 *
 * @param ctx DNAC context
 * @param from_seq Start sequence (inclusive)
 * @param to_seq End sequence (inclusive), 0 = up to latest
 * @param entries_out Output entry array (caller-allocated)
 * @param max_entries Maximum entries to receive
 * @param count_out Actual count returned
 * @param total_out Total entries available on witnesses (can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_ledger_sync_range(dnac_context_t *ctx,
                            uint64_t from_seq,
                            uint64_t to_seq,
                            dnac_ledger_entry_t *entries_out,
                            int max_entries,
                            int *count_out,
                            uint64_t *total_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_LEDGER_H */
