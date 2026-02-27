/**
 * @file block.h
 * @brief DNAC Block Chain Structure (v0.9.0)
 *
 * Each committed transaction becomes a block with:
 * - block_height: sequential counter from 0 (genesis block)
 * - prev_block_hash: SHA3-512 of previous block header (all zeros for genesis)
 * - state_root: UTXO set Merkle root after this block's changes
 * - tx_hash: the transaction contained in this block
 * - tx_count: 1 for now (upgrade path for batched blocks)
 *
 * Hash input (250 bytes, deterministic):
 *   SHA3-512( height(8 LE) || prev_hash(64) || state_root(64) || tx_hash(64) ||
 *             tx_count(2 LE) || epoch(8 LE) || timestamp(8 LE) || proposer_id(32) )
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
 * @brief Block header type
 *
 * Each committed TX produces exactly one block. The block_hash is computed
 * over all other fields (deterministic). tx_count=1 today; batching later
 * changes only this field.
 */
typedef struct {
    uint64_t block_height;                          /**< Sequential from 0 */
    uint8_t  prev_block_hash[DNAC_BLOCK_HASH_SIZE]; /**< SHA3-512 of previous block */
    uint8_t  state_root[DNAC_BLOCK_HASH_SIZE];      /**< UTXO set root after block */
    uint8_t  tx_hash[DNAC_TX_HASH_SIZE];            /**< Transaction in this block */
    uint16_t tx_count;                              /**< 1 for now (batching upgrade path) */
    uint64_t epoch;                                 /**< Epoch number */
    uint64_t timestamp;                             /**< From BFT proposal (deterministic) */
    uint8_t  proposer_id[DNAC_BLOCK_PROPOSER_SIZE]; /**< Leader who proposed */
    uint8_t  block_hash[DNAC_BLOCK_HASH_SIZE];      /**< Computed: SHA3-512 of header fields */
} dnac_block_t;

/* ============================================================================
 * Block Functions
 * ========================================================================== */

/**
 * @brief Compute block_hash from header fields
 *
 * Hash input (250 bytes):
 *   SHA3-512( height(8 LE) || prev_hash(64) || state_root(64) || tx_hash(64) ||
 *             tx_count(2 LE) || epoch(8 LE) || timestamp(8 LE) || proposer_id(32) )
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
