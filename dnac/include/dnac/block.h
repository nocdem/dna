/**
 * @file block.h
 * @brief DNAC Block Chain Structure (v0.14.0 — multi-tx block refactor)
 *
 * Each block carries N transactions (1..NODUS_W_MAX_BLOCK_TXS) instead of
 * exactly one. Field semantics:
 * - block_height:    sequential counter from 0 (genesis block)
 * - prev_block_hash: SHA3-512 of previous block header (zeros for genesis)
 * - state_root:      SHA3-512 over the UTXO set after applying this block
 * - tx_root:         RFC 6962 Merkle root over the block's TX hashes
 *                    (replaces the legacy single tx_hash field)
 * - tx_count:        number of TXs in this block (1..NODUS_W_MAX_BLOCK_TXS)
 *
 * Hash input (multi-tx, deterministic — Phase 1 / Task 1.2):
 *   SHA3-512( height(8 LE) || prev_hash(64) || state_root(64)
 *             || tx_root(64) || tx_count(4 LE) || timestamp(8 LE)
 *             || proposer_id(32) )
 *
 * The legacy "epoch" and "tx_hash" fields are gone. Per-TX type lives on
 * committed_transactions in the witness DB; the block row only carries
 * the aggregate Merkle root and the count.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_BLOCK_H
#define DNAC_BLOCK_H

#include <stdint.h>
#include "dnac.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

#define DNAC_BLOCK_HASH_SIZE     64  /* SHA3-512 */
#define DNAC_BLOCK_PROPOSER_SIZE 32  /* Witness ID */

/* ============================================================================
 * Block Header
 * ========================================================================== */

/**
 * @brief Block header type (multi-tx, Phase 1 / Task 1.2)
 *
 * Each block carries N transactions whose hashes are aggregated under
 * tx_root via RFC 6962 Merkle hashing. block_hash is computed over the
 * other fields deterministically — see dnac_block_compute_hash.
 *
 * Field changes from v0.13:
 *   - tx_hash field removed (was the single TX hash for a 1-tx block)
 *   + tx_root field added (RFC 6962 Merkle root over the TX hashes)
 *   - epoch field removed (no longer part of the block hash preimage)
 *   * tx_count widened from uint16 to uint32 to match the witness DB
 *     INTEGER column without sign issues
 */
typedef struct {
    uint64_t block_height;                          /**< Sequential from 0 */
    uint8_t  prev_block_hash[DNAC_BLOCK_HASH_SIZE]; /**< SHA3-512 of previous block header */
    uint8_t  state_root[DNAC_BLOCK_HASH_SIZE];      /**< SHA3-512 over the UTXO set after this block */
    uint8_t  tx_root[DNAC_BLOCK_HASH_SIZE];         /**< RFC 6962 Merkle root over block TX hashes */
    uint32_t tx_count;                              /**< Number of TXs (1..NODUS_W_MAX_BLOCK_TXS) */
    uint64_t timestamp;                             /**< From BFT proposal (deterministic) */
    uint8_t  proposer_id[DNAC_BLOCK_PROPOSER_SIZE]; /**< Leader who proposed */
    uint8_t  block_hash[DNAC_BLOCK_HASH_SIZE];      /**< Computed: SHA3-512 of header fields */
} dnac_block_t;

/* ============================================================================
 * Block Functions
 * ========================================================================== */

/**
 * @brief Compute block_hash from header fields (multi-tx)
 *
 * Hash input (244 bytes — Phase 1 / Task 1.2):
 *   SHA3-512( height(8 LE) || prev_hash(64) || state_root(64)
 *             || tx_root(64) || tx_count(4 LE) || timestamp(8 LE)
 *             || proposer_id(32) )
 *
 * @param block Block to compute hash for (block_hash field is filled)
 * @return 0 on success, -1 on error
 */
int dnac_block_compute_hash(dnac_block_t *block);

/**
 * @brief Verify that block links correctly to previous block
 *
 * Checks:
 * - block->prev_block_hash == prev->block_hash
 * - block->block_height == prev->block_height + 1
 * - block->block_hash is correct (recomputed and compared)
 *
 * @param block Current block
 * @param prev Previous block (NULL for genesis, in which case prev_hash must be all zeros)
 * @return 0 if valid, -1 if invalid
 */
int dnac_block_verify_link(const dnac_block_t *block, const dnac_block_t *prev);

/* ============================================================================
 * Block Storage (witness-side)
 * ========================================================================== */

/**
 * @brief Initialize block storage, load tip from DB
 * @return 0 on success, -1 on error
 */
int witness_block_init(void *user_data);

/**
 * @brief Shutdown block storage
 */
void witness_block_shutdown(void);

/**
 * @brief Store a new block
 * @param block Block to store
 * @return 0 on success, -1 on error
 */
int witness_block_add(const dnac_block_t *block, void *user_data);

/**
 * @brief Get block by height
 * @param height Block height
 * @param out Output block
 * @return 0 on success, -1 if not found
 */
int witness_block_get(uint64_t height, dnac_block_t *out, void *user_data);

/**
 * @brief Get the latest (tip) block
 * @param out Output block
 * @return 0 on success, -1 if no blocks exist
 */
int witness_block_get_latest(dnac_block_t *out, void *user_data);

/**
 * @brief Get current chain height
 * @return Current height, or UINT64_MAX if no blocks
 */
uint64_t witness_block_get_height(void *user_data);

/**
 * @brief Get a range of blocks
 * @param from Start height (inclusive)
 * @param to End height (inclusive)
 * @param out Output array
 * @param max Maximum blocks to return
 * @param count Output: number of blocks returned
 * @return 0 on success, -1 on error
 */
int witness_block_get_range(uint64_t from, uint64_t to,
                             dnac_block_t *out, int max, int *count, void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_BLOCK_H */
