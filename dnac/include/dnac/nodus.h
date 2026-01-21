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

/** Timeout for Nodus requests (milliseconds) */
#define DNAC_NODUS_TIMEOUT_MS           10000

/** Fee rate (basis points, e.g., 10 = 0.1%) */
#define DNAC_FEE_RATE_BPS               10

/* ============================================================================
 * Message Types
 * ========================================================================== */

typedef enum {
    DNAC_NODUS_MSG_SPEND_REQUEST    = 1,
    DNAC_NODUS_MSG_SPEND_RESPONSE   = 2,
    DNAC_NODUS_MSG_CHECK_NULLIFIER  = 3,
    DNAC_NODUS_MSG_NULLIFIER_STATUS = 4,
    DNAC_NODUS_MSG_PING             = 5,
    DNAC_NODUS_MSG_PONG             = 6
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
 */
typedef struct {
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];         /**< Transaction hash */
    uint8_t nullifier[DNAC_NULLIFIER_SIZE];      /**< Nullifier being spent */
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];     /**< Sender's public key */
    uint8_t signature[DNAC_SIGNATURE_SIZE];      /**< Sender's signature on tx_hash */
    uint64_t timestamp;                          /**< Request timestamp */
    uint64_t fee_amount;                         /**< Fee to witness */
} dnac_spend_request_t;

/**
 * @brief Spend response from witness server
 */
typedef struct {
    dnac_nodus_status_t status;                  /**< Approval status */
    uint8_t witness_id[32];                      /**< Server ID */
    uint8_t signature[DNAC_SIGNATURE_SIZE];      /**< Server's signature (attestation) */
    uint8_t server_pubkey[DNAC_PUBKEY_SIZE];     /**< Server's Dilithium5 public key */
    uint64_t timestamp;                          /**< Response timestamp */
    char error_message[256];                     /**< Error message if rejected */
} dnac_spend_response_t;

/* ============================================================================
 * Client Functions
 * ========================================================================== */

/**
 * @brief Initialize witness client
 *
 * @param ctx DNAC context
 * @return 0 on success, -1 on failure
 */
int dnac_witness_init(dnac_context_t *ctx);

/**
 * @brief Shutdown witness client
 */
void dnac_witness_shutdown(dnac_context_t *ctx);

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

/**
 * @brief Check if nullifier has been spent
 *
 * @param ctx DNAC context
 * @param nullifier Nullifier to check
 * @param is_spent_out Output: true if spent
 * @return 0 on success, -1 on failure
 */
int dnac_witness_check_nullifier(dnac_context_t *ctx,
                                 const uint8_t *nullifier,
                                 bool *is_spent_out);

/**
 * @brief Verify witness signature
 *
 * @param witness Witness signature to verify
 * @param tx_hash Transaction hash that was witnessed
 * @param witness_pubkey Witness server's public key
 * @return true if valid, false otherwise
 */
bool dnac_witness_verify(const dnac_witness_sig_t *witness,
                         const uint8_t *tx_hash,
                         const uint8_t *witness_pubkey);

/**
 * @brief Calculate fee for transaction
 *
 * @param amount Transaction amount
 * @return Fee amount
 */
uint64_t dnac_witness_calculate_fee(uint64_t amount);

/**
 * @brief Ping witness server to check availability
 *
 * @param ctx DNAC context
 * @param server_id Server ID to ping
 * @param latency_ms_out Output latency in milliseconds
 * @return 0 if reachable, -1 if not
 */
int dnac_witness_ping(dnac_context_t *ctx,
                      const uint8_t *server_id,
                      int *latency_ms_out);

/* ============================================================================
 * Serialization
 * ========================================================================== */

/**
 * @brief Serialize spend request
 */
int dnac_spend_request_serialize(const dnac_spend_request_t *request,
                                 uint8_t *buffer,
                                 size_t buffer_len,
                                 size_t *written_out);

/**
 * @brief Deserialize spend request
 */
int dnac_spend_request_deserialize(const uint8_t *buffer,
                                   size_t buffer_len,
                                   dnac_spend_request_t *request_out);

/**
 * @brief Serialize spend response
 */
int dnac_spend_response_serialize(const dnac_spend_response_t *response,
                                  uint8_t *buffer,
                                  size_t buffer_len,
                                  size_t *written_out);

/**
 * @brief Deserialize spend response
 */
int dnac_spend_response_deserialize(const uint8_t *buffer,
                                    size_t buffer_len,
                                    dnac_spend_response_t *response_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_NODUS_H */
