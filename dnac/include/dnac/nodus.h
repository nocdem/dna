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

/**
 * @brief Spend response from witness server
 */
typedef struct {
    dnac_nodus_status_t status;                  /**< Approval status */
    uint8_t witness_id[32];                      /**< Server ID */
    uint8_t signature[DNAC_SIGNATURE_SIZE];      /**< Server's signature (attestation) */
    uint8_t server_pubkey[DNAC_PUBKEY_SIZE];     /**< Server's Dilithium5 public key */
    uint64_t timestamp;                          /**< Response timestamp */
    uint8_t software_version[3];                 /**< Witness software version [major, minor, patch] */
    char error_message[256];                     /**< Error message if rejected */
} dnac_spend_response_t;

/* ============================================================================
 * v0.5.0: Ledger and UTXO Query Structures
 * ========================================================================== */

/** Maximum UTXOs returned in single query */
#define DNAC_MAX_UTXO_QUERY_RESULTS     100

/** P0-2 (v0.7.0): Maximum ledger entries in range query response */
#define DNAC_MAX_RANGE_RESULTS          100

/**
 * @brief Ledger query request
 */
typedef struct {
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];          /**< Transaction hash to query */
    bool include_proof;                           /**< Include Merkle proof */
} dnac_ledger_query_t;

/**
 * @brief Ledger query response (forward declaration - full struct in ledger.h)
 */
typedef struct {
    dnac_nodus_status_t status;
    uint64_t sequence_number;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t tx_type;
    uint8_t merkle_root[64];
    uint64_t timestamp;
    uint64_t epoch;
    /* Proof data if requested */
    bool has_proof;
    uint8_t leaf_hash[64];
    int proof_length;
    uint8_t proof_root[64];
} dnac_ledger_response_t;

/**
 * @brief Supply query request (no parameters needed)
 */
typedef struct {
    uint8_t padding;  /**< Reserved */
} dnac_supply_query_t;

/**
 * @brief Supply query response
 */
typedef struct {
    dnac_nodus_status_t status;
    uint64_t genesis_supply;                     /**< Total supply at genesis */
    uint64_t total_burned;                       /**< Total burned */
    uint64_t current_supply;                     /**< genesis - burned */
    uint8_t last_tx_hash[DNAC_TX_HASH_SIZE];    /**< Last transaction */
    uint64_t last_sequence;                      /**< Last sequence number */
} dnac_supply_response_t;

/**
 * @brief UTXO query by owner request
 */
typedef struct {
    uint8_t owner_commitment[64];                /**< Owner commitment hash */
    int max_results;                             /**< Max UTXOs to return */
} dnac_utxo_query_t;

/**
 * @brief Single UTXO entry in response
 */
typedef struct {
    uint8_t commitment[64];
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint32_t output_index;
    uint64_t amount;
    uint64_t created_epoch;
} dnac_utxo_entry_t;

/**
 * @brief UTXO query response
 */
typedef struct {
    dnac_nodus_status_t status;
    int count;                                   /**< Number of UTXOs returned */
    dnac_utxo_entry_t utxos[DNAC_MAX_UTXO_QUERY_RESULTS];
} dnac_utxo_response_t;

/**
 * @brief UTXO proof query request
 */
typedef struct {
    uint8_t commitment[64];                      /**< UTXO commitment to prove */
} dnac_utxo_proof_query_t;

/**
 * @brief UTXO proof response
 */
typedef struct {
    dnac_nodus_status_t status;
    bool exists;                                 /**< UTXO exists and unspent */
    uint8_t commitment[64];                      /**< Commitment queried */
    uint8_t root[64];                            /**< Current UTXO root */
    uint64_t epoch;                              /**< Root epoch */
} dnac_utxo_proof_response_t;

/**
 * @brief Nullifier check request
 */
typedef struct {
    uint8_t nullifier[DNAC_NULLIFIER_SIZE];      /**< Nullifier to check */
} dnac_nullifier_query_t;

/**
 * @brief Nullifier check response
 */
typedef struct {
    dnac_nodus_status_t status;
    bool is_spent;                               /**< True if nullifier is spent */
    uint8_t nullifier[DNAC_NULLIFIER_SIZE];      /**< Nullifier queried */
    uint64_t spent_epoch;                        /**< Epoch when spent (if applicable) */
} dnac_nullifier_response_t;

/* ============================================================================
 * P0-2 (v0.7.0): Chain Sync Range Query Structures
 * ========================================================================== */

/**
 * @brief Ledger range query request
 *
 * Enables clients to synchronize ledger state by requesting a range
 * of ledger entries. Used for chain sync protocol.
 */
typedef struct {
    uint64_t from_sequence;                      /**< Start sequence (inclusive) */
    uint64_t to_sequence;                        /**< End sequence (inclusive), 0 = latest */
    bool include_proofs;                         /**< Include Merkle proofs for each entry */
} dnac_ledger_range_query_t;

/**
 * @brief Single ledger entry in range response (compact form)
 */
typedef struct {
    uint64_t sequence_number;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t tx_type;
    uint8_t merkle_root[64];
    uint64_t timestamp;
    uint64_t epoch;
} dnac_ledger_range_entry_t;

/**
 * @brief Ledger range query response
 */
typedef struct {
    dnac_nodus_status_t status;
    uint64_t first_sequence;                     /**< Actual first returned */
    uint64_t last_sequence;                      /**< Actual last returned */
    uint64_t total_entries;                      /**< Total entries in ledger */
    int count;                                   /**< Number of entries returned */
    dnac_ledger_range_entry_t entries[DNAC_MAX_RANGE_RESULTS];
} dnac_ledger_range_response_t;

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

/* ============================================================================
 * v0.5.0: Ledger/UTXO Query Serialization
 * ========================================================================== */

/**
 * @brief Serialize ledger query
 */
int dnac_ledger_query_serialize(const dnac_ledger_query_t *query,
                                uint8_t *buffer,
                                size_t buffer_len,
                                size_t *written_out);

/**
 * @brief Deserialize ledger query
 */
int dnac_ledger_query_deserialize(const uint8_t *buffer,
                                  size_t buffer_len,
                                  dnac_ledger_query_t *query_out);

/**
 * @brief Serialize ledger response
 */
int dnac_ledger_response_serialize(const dnac_ledger_response_t *response,
                                   uint8_t *buffer,
                                   size_t buffer_len,
                                   size_t *written_out);

/**
 * @brief Deserialize ledger response
 */
int dnac_ledger_response_deserialize(const uint8_t *buffer,
                                     size_t buffer_len,
                                     dnac_ledger_response_t *response_out);

/**
 * @brief Serialize supply query
 */
int dnac_supply_query_serialize(const dnac_supply_query_t *query,
                                uint8_t *buffer,
                                size_t buffer_len,
                                size_t *written_out);

/**
 * @brief Deserialize supply query
 */
int dnac_supply_query_deserialize(const uint8_t *buffer,
                                  size_t buffer_len,
                                  dnac_supply_query_t *query_out);

/**
 * @brief Serialize supply response
 */
int dnac_supply_response_serialize(const dnac_supply_response_t *response,
                                   uint8_t *buffer,
                                   size_t buffer_len,
                                   size_t *written_out);

/**
 * @brief Deserialize supply response
 */
int dnac_supply_response_deserialize(const uint8_t *buffer,
                                     size_t buffer_len,
                                     dnac_supply_response_t *response_out);

/**
 * @brief Serialize UTXO query
 */
int dnac_utxo_query_serialize(const dnac_utxo_query_t *query,
                              uint8_t *buffer,
                              size_t buffer_len,
                              size_t *written_out);

/**
 * @brief Deserialize UTXO query
 */
int dnac_utxo_query_deserialize(const uint8_t *buffer,
                                size_t buffer_len,
                                dnac_utxo_query_t *query_out);

/**
 * @brief Serialize UTXO response
 */
int dnac_utxo_response_serialize(const dnac_utxo_response_t *response,
                                 uint8_t *buffer,
                                 size_t buffer_len,
                                 size_t *written_out);

/**
 * @brief Deserialize UTXO response
 */
int dnac_utxo_response_deserialize(const uint8_t *buffer,
                                   size_t buffer_len,
                                   dnac_utxo_response_t *response_out);

/**
 * @brief Serialize UTXO proof query
 */
int dnac_utxo_proof_query_serialize(const dnac_utxo_proof_query_t *query,
                                    uint8_t *buffer,
                                    size_t buffer_len,
                                    size_t *written_out);

/**
 * @brief Deserialize UTXO proof query
 */
int dnac_utxo_proof_query_deserialize(const uint8_t *buffer,
                                      size_t buffer_len,
                                      dnac_utxo_proof_query_t *query_out);

/**
 * @brief Serialize UTXO proof response
 */
int dnac_utxo_proof_response_serialize(const dnac_utxo_proof_response_t *response,
                                       uint8_t *buffer,
                                       size_t buffer_len,
                                       size_t *written_out);

/**
 * @brief Deserialize UTXO proof response
 */
int dnac_utxo_proof_response_deserialize(const uint8_t *buffer,
                                         size_t buffer_len,
                                         dnac_utxo_proof_response_t *response_out);

/**
 * @brief Serialize nullifier check query
 */
int dnac_nullifier_query_serialize(const dnac_nullifier_query_t *query,
                                    uint8_t *buffer,
                                    size_t buffer_len,
                                    size_t *written_out);

/**
 * @brief Deserialize nullifier check query
 */
int dnac_nullifier_query_deserialize(const uint8_t *buffer,
                                      size_t buffer_len,
                                      dnac_nullifier_query_t *query_out);

/**
 * @brief Serialize nullifier check response
 */
int dnac_nullifier_response_serialize(const dnac_nullifier_response_t *response,
                                       uint8_t *buffer,
                                       size_t buffer_len,
                                       size_t *written_out);

/**
 * @brief Deserialize nullifier check response
 */
int dnac_nullifier_response_deserialize(const uint8_t *buffer,
                                         size_t buffer_len,
                                         dnac_nullifier_response_t *response_out);

/* ============================================================================
 * P0-2 (v0.7.0): Range Query Serialization
 * ========================================================================== */

/**
 * @brief Serialize ledger range query
 */
int dnac_ledger_range_query_serialize(const dnac_ledger_range_query_t *query,
                                       uint8_t *buffer,
                                       size_t buffer_len,
                                       size_t *written_out);

/**
 * @brief Deserialize ledger range query
 */
int dnac_ledger_range_query_deserialize(const uint8_t *buffer,
                                         size_t buffer_len,
                                         dnac_ledger_range_query_t *query_out);

/**
 * @brief Serialize ledger range response
 */
int dnac_ledger_range_response_serialize(const dnac_ledger_range_response_t *response,
                                          uint8_t *buffer,
                                          size_t buffer_len,
                                          size_t *written_out);

/**
 * @brief Deserialize ledger range response
 */
int dnac_ledger_range_response_deserialize(const uint8_t *buffer,
                                            size_t buffer_len,
                                            dnac_ledger_range_response_t *response_out);

/* ============================================================================
 * Witness Announcement (DHT roster discovery)
 * ========================================================================== */

typedef struct {
    uint8_t  version;
    uint8_t  witness_id[32];
    uint64_t current_epoch;
    uint64_t epoch_duration;
    uint64_t timestamp;
    uint8_t  software_version[3];
    uint8_t  witness_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t  signature[DNAC_SIGNATURE_SIZE];
} dnac_witness_announcement_t;

#define DNAC_ANNOUNCEMENT_SERIALIZED_SIZE (1 + 32 + 8 + 8 + 8 + 3 + DNAC_PUBKEY_SIZE + DNAC_SIGNATURE_SIZE)

int witness_announcement_serialize(const dnac_witness_announcement_t *announcement,
                                   uint8_t *buffer, size_t buffer_len, size_t *written_out);
int witness_announcement_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_witness_announcement_t *announcement_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_NODUS_H */
