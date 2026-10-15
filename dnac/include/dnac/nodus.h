/**
 * @file nodus.h
 * @brief Witness Server Client API
 *
 * Witness servers provide double-spend prevention through a 2-of-3
 * attestation mechanism. Each spend must be acknowledged by at least
 * 2 witness servers before it's considered valid.
 *
 * Protocol:
 * 1. Client sends SpendRequest to ALL witness servers
 * 2. Each witness checks if nullifier already exists
 * 3. If new: APPROVE + sign with Dilithium5 + replicate to peers
 * 4. If exists: REJECT (double-spend attempt)
 * 5. Client collects 2+ signatures → WitnessProof
 * 6. Transaction with WitnessProof is valid
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_NODUS_H
#define DNAC_NODUS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "dnac.h"
#include "dnac/transaction.h"
#include "dnac/block.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Number of witness signatures required for valid transaction */
#define DNAC_WITNESSES_REQUIRED         2

/** Maximum number of witness servers to contact */
#define DNAC_MAX_WITNESS_SERVERS        5

/** Maximum serialized transaction size (64KB) */
#define DNAC_MAX_TX_SIZE                65536

/** Timeout for Nodus requests (milliseconds) */
#define DNAC_NODUS_TIMEOUT_MS           10000

/** Fee rate (basis points, e.g., 10 = 0.1%) */
#define DNAC_FEE_RATE_BPS               10

/* ============================================================================
 * Message Types
 * ========================================================================== */

/**
 * NODUS client message types.
 * Starting at 128 to avoid collision with BFT message types (1-11).
 */
typedef enum {
    DNAC_NODUS_MSG_SPEND_REQUEST    = 128,
    DNAC_NODUS_MSG_SPEND_RESPONSE   = 129,
    DNAC_NODUS_MSG_CHECK_NULLIFIER  = 130,
    DNAC_NODUS_MSG_NULLIFIER_STATUS = 131,
    DNAC_NODUS_MSG_PING             = 132,
    DNAC_NODUS_MSG_PONG             = 133,
    /* v0.5.0: Query messages for ledger and UTXO */
    DNAC_NODUS_MSG_LEDGER_QUERY     = 134,  /**< Query ledger entry by tx_hash */
    DNAC_NODUS_MSG_LEDGER_RESPONSE  = 135,  /**< Ledger entry + Merkle proof */
    DNAC_NODUS_MSG_SUPPLY_QUERY     = 136,  /**< Query supply state */
    DNAC_NODUS_MSG_SUPPLY_RESPONSE  = 137,  /**< Supply state response */
    DNAC_NODUS_MSG_UTXO_QUERY       = 138,  /**< Query UTXOs by owner commitment */
    DNAC_NODUS_MSG_UTXO_RESPONSE    = 139,  /**< UTXO list response */
    DNAC_NODUS_MSG_UTXO_PROOF_QUERY = 140,  /**< Query UTXO existence proof */
    DNAC_NODUS_MSG_UTXO_PROOF_RSP   = 141,  /**< UTXO proof response */
    /* P0-2 (v0.7.0): Chain sync range queries */
    DNAC_NODUS_MSG_LEDGER_RANGE_QUERY    = 142, /**< Query ledger entry range */
    DNAC_NODUS_MSG_LEDGER_RANGE_RESPONSE = 143, /**< Ledger range response */
    /* v0.10.0: Full TX and block queries (hub/spoke) */
    DNAC_NODUS_MSG_TX_QUERY              = 144, /**< Query full TX by hash */
    DNAC_NODUS_MSG_TX_RESPONSE           = 145, /**< Full TX data response */
    DNAC_NODUS_MSG_BLOCK_QUERY           = 146, /**< Query block by height */
    DNAC_NODUS_MSG_BLOCK_RESPONSE        = 147, /**< Block data response */
    DNAC_NODUS_MSG_BLOCK_RANGE_QUERY     = 148, /**< Query block range */
    DNAC_NODUS_MSG_BLOCK_RANGE_RESPONSE  = 149  /**< Block range response */
} dnac_nodus_msg_type_t;

typedef enum {
    DNAC_NODUS_STATUS_APPROVED      = 0,
    DNAC_NODUS_STATUS_REJECTED      = 1,  /* Nullifier already spent */
    DNAC_NODUS_STATUS_ERROR         = 2,  /* Internal error */
    DNAC_NODUS_STATUS_TIMEOUT       = 3   /* No response */
} dnac_nodus_status_t;

/* ============================================================================
 * Request/Response Structures
 * ========================================================================== */

/**
 * @brief Spend request sent to witness servers
 *
 * v0.4.0: Now carries full serialized transaction instead of single nullifier.
 * This enables witnesses to extract and verify ALL input nullifiers,
 * preventing multi-input double-spend attacks.
 */
typedef struct {
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];         /**< Transaction hash */
    uint8_t tx_data[DNAC_MAX_TX_SIZE];          /**< Full serialized transaction */
    uint32_t tx_len;                             /**< Serialized TX length */
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];     /**< Sender's public key */
    uint8_t signature[DNAC_SIGNATURE_SIZE];      /**< Sender's signature on tx_hash */
    uint64_t timestamp;                          /**< Request timestamp */
    uint64_t fee_amount;                         /**< Fee to witness */
} dnac_spend_request_t;

/** Maximum UTXOs returned in single query */
#define DNAC_MAX_UTXO_QUERY_RESULTS     100

/* ============================================================================
 * Client Functions
 * ========================================================================== */

/**
 * @brief Discover witness servers via DHT
 *
 * @param ctx DNAC context
 * @param servers_out Output array (caller frees with dnac_free_witness_list)
 * @param count_out Output count
 * @return 0 on success, -1 on failure
 */
int dnac_witness_discover(dnac_context_t *ctx,
                          dnac_witness_info_t **servers_out,
                          int *count_out);

/**
 * @brief Request witness signatures from witness servers
 *
 * Sends spend request to all known witness servers and collects
 * signatures. Returns when 2+ signatures received or timeout.
 *
 * @param ctx DNAC context
 * @param request Spend request
 * @param witnesses_out Output witness signature array (max DNAC_MAX_WITNESS_SERVERS)
 * @param witness_count_out Output witness count
 * @return 0 on success, DNAC_ERROR_WITNESS_FAILED if < 2 witnesses
 */
int dnac_witness_request(dnac_context_t *ctx,
                         const dnac_spend_request_t *request,
                         dnac_witness_sig_t *witnesses_out,
                         int *witness_count_out);

/* dnac_witness_replay, dnac_request_genesis, dnac_request_genesis_quorum
 * and DNAC_GENESIS_QUORUM_THRESHOLD are deleted with the dnac_spend_replay
 * / dnac_genesis RPCs they wrapped (2026-10-15). */

#ifdef __cplusplus
}
#endif

#endif /* DNAC_NODUS_H */
