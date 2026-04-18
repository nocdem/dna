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

#include <stdbool.h>
#include <stddef.h>
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
 * Chain Definition (genesis block only)
 *
 * Carried in dnac_block_t.chain_def when block_height == 0 (genesis).
 * Hash preimage of the genesis block includes every field below, so chain_id
 * (= genesis block_hash) transitively commits to the entire chain definition.
 *
 * This struct is the "constitution" of a chain. Once the genesis is created,
 * none of these values can change without producing a different chain_id
 * (i.e. a hard fork).
 *
 * Determinism: all `char[]` fields are zero-padded (unused bytes MUST be 0).
 * This matters because the genesis hash preimage includes these fields byte-
 * for-byte — "DNAC\0\0\0\0" and "DNAC    " produce different hashes.
 * ========================================================================== */

#define DNAC_CHAIN_NAME_LEN          32
#define DNAC_GENESIS_MESSAGE_LEN     64
#define DNAC_TOKEN_SYMBOL_LEN        8
#define DNAC_TOKEN_ID_SIZE           64
#define DNAC_FEE_RECIPIENT_SIZE      32
#define DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN 128  /* host:port hint (zero-padded) */

#ifndef DNAC_MAX_WITNESSES_COMPILE_CAP
#define DNAC_MAX_WITNESSES_COMPILE_CAP  21  /* compile-time cap; runtime uses witness_count */
#endif

/**
 * @brief Initial validator entry — seeds the Phase 10 committee at genesis.
 *
 * One of these appears per seat in dnac_chain_definition_t.initial_validators[].
 * The full struct is hashed byte-for-byte into the genesis preimage (via
 * dnac_block_compute_hash + dnac_chain_def_encode), so all char/uint8_t array
 * fields MUST be fully zero-padded — trailing post-NUL bytes participate in
 * the hash. This prevents malleability where mutating padding leaves the
 * decoded string unchanged but alters the chain_id.
 *
 * Field order is consensus-critical (serialization order is pinned).
 */
typedef struct {
    uint8_t  pubkey[DNAC_PUBKEY_SIZE];                          /**< Dilithium5 validator pubkey */
    char     unstake_destination_fp[DNAC_FINGERPRINT_SIZE];     /**< Hex fp receiving 10M on unstake */
    uint16_t commission_bps;                                    /**< Initial commission (0-10000) */
    char     endpoint[DNAC_INITIAL_VALIDATOR_ENDPOINT_LEN];     /**< DHT endpoint hint (host:port) */
} dnac_chain_initial_validator_t;

typedef struct {
    /* Chain identification */
    char     chain_name[DNAC_CHAIN_NAME_LEN];
    uint32_t protocol_version;
    uint8_t  parent_chain_id[DNAC_BLOCK_HASH_SIZE];
    char     genesis_message[DNAC_GENESIS_MESSAGE_LEN];

    /* Witness set */
    uint32_t witness_count;
    uint32_t max_active_witnesses;
    uint8_t  witness_pubkeys[DNAC_MAX_WITNESSES_COMPILE_CAP][DNAC_PUBKEY_SIZE];

    /* Consensus parameters */
    uint32_t block_interval_sec;
    uint32_t max_txs_per_block;
    uint32_t view_change_timeout_ms;

    /* Token parameters */
    char     token_symbol[DNAC_TOKEN_SYMBOL_LEN];
    uint8_t  token_decimals;
    uint64_t initial_supply_raw;
    uint8_t  native_token_id[DNAC_TOKEN_ID_SIZE];

    /* Economic */
    uint8_t  fee_recipient[DNAC_FEE_RECIPIENT_SIZE];

    /* Initial validator set (Phase 12 — Task 56).
     *
     * MUST appear at the end of this struct to keep existing encoding order
     * stable. Field order within this block is appended to the genesis
     * preimage AFTER fee_recipient.
     *
     * Wire layout (appended after fee_recipient):
     *   initial_validator_count (u8)
     *   initial_validators[0..count-1] ×
     *     pubkey(2592) || unstake_destination_fp(129) ||
     *     commission_bps(u16 BE) || endpoint(128)
     *
     * initial_validator_count MUST equal DNAC_COMMITTEE_SIZE (=7) for genesis
     * to satisfy Rule P. A zero count is accepted at the codec layer for
     * legacy chain_defs, but rejected by the GENESIS verify Rule P.
     */
    uint8_t                        initial_validator_count;
    dnac_chain_initial_validator_t initial_validators[DNAC_COMMITTEE_SIZE];
} dnac_chain_definition_t;

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
 *
 * @note Genesis-only semantics
 *
 * `is_genesis` and `chain_def` are populated only for the height-0 genesis
 * block. For non-genesis blocks they are zero-initialized and excluded
 * from the hash preimage by `dnac_block_compute_hash` (see Task 3).
 *
 * CALLERS MUST zero-initialize `dnac_block_t` before populating fields
 * (e.g., `dnac_block_t b = {0};` or `memset(&b, 0, sizeof b)`).
 * An uninitialized `is_genesis` will cause nondeterministic block hashes.
 */
typedef struct {
    uint64_t block_height;                          /**< Sequential from 0 */
    uint8_t  prev_block_hash[DNAC_BLOCK_HASH_SIZE]; /**< SHA3-512 of previous block header */
    uint8_t  state_root[DNAC_BLOCK_HASH_SIZE];      /**< SHA3-512 over the UTXO set after this block */
    uint8_t  tx_root[DNAC_BLOCK_HASH_SIZE];         /**< RFC 6962 Merkle root over block TX hashes */
    uint32_t tx_count;                              /**< Number of TXs (1..NODUS_W_MAX_BLOCK_TXS) */
    uint64_t timestamp;                             /**< From BFT proposal (deterministic) */
    uint8_t  proposer_id[DNAC_BLOCK_PROPOSER_SIZE]; /**< Leader who proposed */

    bool                    is_genesis;  /**< True for genesis (height 0); see struct doxygen */
    dnac_chain_definition_t chain_def;   /**< Genesis-only chain constitution; zero otherwise */

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
 * @brief Mark a block as genesis and populate its chain_def.
 *
 * Must be called before dnac_block_compute_hash for any genesis block
 * (block_height == 0). For non-genesis blocks, leave is_genesis = false
 * (default from zero-initialization) and do not call this function —
 * chain_def will be zero and excluded from the hash preimage.
 *
 * The function copies @p chain_def into @p block->chain_def and sets
 * block->is_genesis = true. It rejects chain_defs whose witness_count
 * exceeds the compile-time cap DNAC_MAX_WITNESSES_COMPILE_CAP, which
 * would otherwise make the hash preimage walk past the witness_pubkeys
 * array.
 *
 * @param block      Target block (must be zero-initialized before use).
 * @param chain_def  Chain definition to copy into block->chain_def.
 * @return 0 on success, -1 on NULL argument or out-of-range witness_count.
 */
int dnac_block_set_genesis_def(dnac_block_t *block,
                                const dnac_chain_definition_t *chain_def);

/**
 * @brief Serialize a dnac_block_t to a byte buffer.
 *
 * The layout matches the hash preimage exactly for the standard header
 * fields; then a 1-byte is_genesis flag (wire-format only, NOT part of
 * the hash preimage); then chain_def bytes (via dnac_chain_def_encode)
 * if is_genesis; then the stored block_hash as a trailer.
 *
 * Decoding via dnac_block_decode MUST produce a block whose
 * dnac_block_compute_hash result equals the trailing block_hash.
 *
 * @param block  Source block (must not be NULL).
 * @param out    Output buffer (caller-allocated).
 * @param cap    Buffer capacity.
 * @param len    [out] Bytes written on success.
 * @return 0 on success, -1 on error.
 */
int dnac_block_encode(const dnac_block_t *block,
                       uint8_t *out, size_t cap, size_t *len);

/**
 * @brief Deserialize a dnac_block_t from a byte buffer.
 *
 * Strict parser — rejects malformed input, wrong length, oversized
 * witness_count. On success, block_out->is_genesis is set based on
 * whether the input included a chain_def section.
 *
 * @param bytes  Input buffer (must not be NULL).
 * @param len    Input byte count.
 * @param block_out  [out] Destination (will be zero-initialized).
 * @return 0 on success, -1 on error.
 */
int dnac_block_decode(const uint8_t *bytes, size_t len,
                       dnac_block_t *block_out);

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
