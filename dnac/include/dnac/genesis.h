/**
 * @file genesis.h
 * @brief DNAC Genesis Event API
 *
 * Genesis is a one-time event that creates the native DNAC token supply.
 * Custom tokens can be created later via TOKEN_CREATE transactions.
 *
 * Key properties:
 * - Requires unanimous (N/N) BFT witness approval (enforced server-side)
 * - Client receives 1 attestation from the BFT leader as proof of consensus
 * - Can only happen once - attempts after genesis are rejected
 * - Before genesis, only GENESIS transactions are valid
 * - After genesis, SPEND/BURN/TOKEN_CREATE transactions are valid
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_GENESIS_H
#define DNAC_GENESIS_H

#include "dnac.h"
#include "dnac/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Maximum recipients in a genesis transaction */
#define DNAC_GENESIS_MAX_RECIPIENTS     16

/** Minimum attestations the client requires from BFT leader.
 *  Unanimous (N/N) consensus is enforced server-side during PREVOTE/PRECOMMIT.
 *  The leader returns 1 attestation representing full quorum agreement. */
#define DNAC_GENESIS_MIN_ATTESTATIONS   1

/* ============================================================================
 * Data Types
 * ========================================================================== */

/**
 * @brief Genesis recipient specification
 */
typedef struct {
    char fingerprint[DNAC_FINGERPRINT_SIZE];  /**< Recipient's identity fingerprint */
    uint64_t amount;                           /**< Amount to allocate */
} dnac_genesis_recipient_t;

/* ============================================================================
 * Genesis Transaction Functions
 * ========================================================================== */

/**
 * @brief Create a GENESIS transaction
 *
 * Creates a transaction that establishes the total token supply.
 * Tokens are distributed to specified recipients.
 * Requires 3-of-3 witness authorization before broadcast.
 *
 * @param recipients Array of recipients with amounts
 * @param recipient_count Number of recipients (1 to DNAC_GENESIS_MAX_RECIPIENTS)
 * @param tx_out Output transaction (caller must free with dnac_free_transaction)
 * @return DNAC_SUCCESS or error code:
 *         - DNAC_ERROR_INVALID_PARAM: Invalid parameters
 *         - DNAC_ERROR_OUT_OF_MEMORY: Memory allocation failed
 */
int dnac_tx_create_genesis(const dnac_genesis_recipient_t *recipients,
                           int recipient_count,
                           dnac_transaction_t **tx_out);

/**
 * @brief Authorize GENESIS transaction via witness consensus
 *
 * Requests unanimous (N/N) BFT witness consensus to authorize genesis.
 * This is a higher bar than normal transactions (which need 2f+1 quorum).
 *
 * @param ctx DNAC context
 * @param tx GENESIS transaction to authorize
 * @return DNAC_SUCCESS or error code:
 *         - DNAC_ERROR_GENESIS_EXISTS: Genesis already occurred
 *         - DNAC_ERROR_WITNESS_FAILED: Failed to get unanimous approval
 *         - DNAC_ERROR_TIMEOUT: Witness request timed out
 */
int dnac_tx_authorize_genesis(dnac_context_t *ctx, dnac_transaction_t *tx);

/**
 * @brief Broadcast authorized GENESIS transaction
 *
 * Sends the genesis tokens to recipients via DHT.
 * After this, the system is initialized and normal transactions work.
 *
 * @param ctx DNAC context
 * @param tx Authorized GENESIS transaction (must have 3 witness signatures)
 * @return DNAC_SUCCESS or error code:
 *         - DNAC_ERROR_INVALID_PARAM: Transaction not properly authorized
 *         - DNAC_ERROR_NETWORK: DHT broadcast failed
 */
int dnac_tx_broadcast_genesis(dnac_context_t *ctx, dnac_transaction_t *tx);

/* ============================================================================
 * Two-Phase Genesis Flow (v0.11.0 - Chain ID)
 * ========================================================================== */

/**
 * @brief Phase 1: Create and sign genesis TX locally
 *
 * Creates the genesis transaction, signs it with sender's key, and derives
 * the chain_id from the first recipient's fingerprint + tx_hash.
 * Does NOT contact witnesses — call dnac_genesis_phase2_submit() for that.
 *
 * Design: The chain_id is derived deterministically so witnesses can
 * independently verify it from the genesis TX data.
 *
 * @param ctx             DNAC context (for signing key)
 * @param recipients      Array of recipients with amounts
 * @param recipient_count Number of recipients
 * @param tx_out          Output: created genesis TX (caller frees with dnac_free_transaction)
 * @param chain_id_out    Output: derived chain_id (32 bytes, caller provides buffer)
 * @return DNAC_SUCCESS or error code
 */
int dnac_genesis_phase1_create(dnac_context_t *ctx,
                                const dnac_genesis_recipient_t *recipients,
                                int recipient_count,
                                dnac_transaction_t **tx_out,
                                uint8_t *chain_id_out);

/**
 * @brief Phase 2: Submit pre-created genesis TX to witnesses
 *
 * Sets the chain_id on the context, submits the genesis TX for unanimous
 * BFT witness approval, then broadcasts to recipient DHT inboxes.
 *
 * @param ctx      DNAC context
 * @param tx       Genesis TX from phase 1
 * @param chain_id Chain ID from phase 1 (32 bytes)
 * @return DNAC_SUCCESS or error code
 */
int dnac_genesis_phase2_submit(dnac_context_t *ctx,
                                dnac_transaction_t *tx,
                                const uint8_t *chain_id);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_GENESIS_H */
