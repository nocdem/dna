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
/** Dynamic fee info from witness */
typedef struct {
    uint64_t base_fee;      /**< Base fee in raw units */
    uint64_t mempool_count; /**< Current pending TXs */
    uint64_t min_fee;       /**< Current minimum required fee */
} dnac_fee_info_t;

int dnac_witness_request(dnac_context_t *ctx,
                         const dnac_spend_request_t *request,
                         dnac_witness_sig_t *witnesses_out,
                         int *witness_count_out);

/**
 * @brief Re-query a committed TX's witness receipt (Fix #4 B)
 *
 * Used by dnac_tx_broadcast after a dnac_witness_request timeout to
 * determine whether the TX actually committed on-chain before the
 * response was lost. Calls nodus_client_dnac_spend_replay; on found,
 * populates a single dnac_witness_sig_t with a freshly-signed
 * spndrslt receipt bound to the original (block_height, tx_index,
 * chain_id).
 *
 * @param ctx DNAC context
 * @param tx_hash 64-byte TX hash to query
 * @param witness_out Output: single witness signature on found
 * @return DNAC_SUCCESS on found, DNAC_ERROR_NOT_FOUND if not committed,
 *         DNAC_ERROR_NETWORK / DNAC_ERROR_TIMEOUT on transport errors
 */
int dnac_witness_replay(dnac_context_t *ctx,
                         const uint8_t *tx_hash,
                         dnac_witness_sig_t *witness_out);

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

/**
 * @brief Fetch the genesis block from a witness (Phase 2 / Task 36).
 *
 * Wraps nodus_client_dnac_genesis: sends a dnac_genesis query, parses the
 * response, decodes the serialized chain_def, reassembles a dnac_block_t
 * with is_genesis=true, and recomputes the block hash. On success the
 * caller can compare block_out->block_hash to its hardcoded chain_id.
 *
 * @param ctx        DNAC client context (with an active nodus connection)
 * @param block_out  [out] Populated dnac_block_t on success.
 * @return DNAC_SUCCESS on success,
 *         DNAC_ERROR_NOT_FOUND if no genesis row exists on the witness,
 *         DNAC_ERROR_NOT_INITIALIZED / DNAC_ERROR_NETWORK /
 *         DNAC_ERROR_TIMEOUT on transport failures,
 *         DNAC_ERROR_INVALID_PARAM on argument or decode errors.
 */
int dnac_request_genesis(dnac_context_t *ctx, dnac_block_t *block_out);

/**
 * BFT quorum threshold for trust bootstrap (2f+1 for f=2, N=7 cluster).
 *
 * Under a compromised-bootstrap threat model, a single witness node
 * returning a forged genesis block must not mislead the client. The
 * quorum-based fetch requires this many bootstrap peers to agree on the
 * same block_hash before anchoring the trusted state.
 */
#define DNAC_GENESIS_QUORUM_THRESHOLD 5

/**
 * @brief Quorum-verified genesis fetch for trust bootstrap (audit C6).
 *
 * Fan out dnac_genesis queries to all configured bootstrap peers, compute
 * the block_hash of each response locally, tally by hash, and accept the
 * block only when at least DNAC_GENESIS_QUORUM_THRESHOLD peers agree.
 *
 * This replaces the single-node call from bootstrap_trusted_state and
 * closes the "compromised bootstrap returns forged chain_id" attack
 * surface flagged by the 2026-04-22 red-team audit (finding C6).
 *
 * @param ctx                   DNAC client context (identity must be
 *                              loaded via messenger init).
 * @param block_out             [out] Majority-consensus genesis block,
 *                              only populated when the return value is
 *                              DNAC_SUCCESS.
 * @param verified_count_out    [out, optional] Number of peers agreeing
 *                              with the majority hash.
 * @param total_responses_out   [out, optional] Total peers that produced
 *                              a usable response.
 * @return DNAC_SUCCESS on quorum verification,
 *         DNAC_ERROR_TIMEOUT when too few peers respond (retryable),
 *         DNAC_ERROR_WITNESS_FAILED on divergent responses below quorum,
 *         DNAC_ERROR_NOT_INITIALIZED when the messenger layer has no
 *         loaded identity / bootstrap list available,
 *         DNAC_ERROR_INVALID_PARAM on argument errors.
 */
int dnac_request_genesis_quorum(dnac_context_t *ctx,
                                 dnac_block_t *block_out,
                                 int *verified_count_out,
                                 int *total_responses_out);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_NODUS_H */
