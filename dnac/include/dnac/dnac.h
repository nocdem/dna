/**
 * @file dnac.h
 * @brief DNAC - Post-Quantum Digital Cash over DHT
 *
 * Main public API for DNAC wallet operations.
 *
 * DNAC is a digital cash system using:
 * - UTXO model for transactions
 * - Dilithium5 (PQ) signatures for authorization
 * - DHT for payment message transport
 * - Nodus 2-of-3 witnessing for double-spend prevention
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will add PQ ZK (STARKs) for hidden amounts when available.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_H
#define DNAC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "dnac/version.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Error Codes
 * ========================================================================== */

#define DNAC_SUCCESS                    0
#define DNAC_ERROR_INVALID_PARAM       -1
#define DNAC_ERROR_OUT_OF_MEMORY       -2
#define DNAC_ERROR_NOT_INITIALIZED     -3
#define DNAC_ERROR_ALREADY_INITIALIZED -4
#define DNAC_ERROR_DATABASE            -5
#define DNAC_ERROR_CRYPTO              -6
#define DNAC_ERROR_NETWORK             -7
#define DNAC_ERROR_INSUFFICIENT_FUNDS  -8
#define DNAC_ERROR_DOUBLE_SPEND        -9
#define DNAC_ERROR_INVALID_PROOF       -10
#define DNAC_ERROR_WITNESS_FAILED      -11
#define DNAC_ERROR_TIMEOUT             -12
#define DNAC_ERROR_NOT_FOUND           -13
#define DNAC_ERROR_SIGN_FAILED         -14
#define DNAC_ERROR_INVALID_SIGNATURE   -15
#define DNAC_ERROR_RANDOM_FAILED       -16
#define DNAC_ERROR_UNAUTHORIZED_MINT   -17
#define DNAC_ERROR_SUPPLY_EXCEEDED     -18
#define DNAC_ERROR_GENESIS_EXISTS      -19  /* Genesis already occurred */
#define DNAC_ERROR_NO_GENESIS          -20  /* System not initialized - no genesis */
#define DNAC_ERROR_INVALID_TX_TYPE     -21  /* Invalid transaction type for current state */
#define DNAC_ERROR_NOT_IMPLEMENTED     -22  /* Feature not yet implemented */
#define DNAC_ERROR_OVERFLOW            -23  /* Integer overflow in amount arithmetic */

/* Genesis configuration */
#define DNAC_GENESIS_WITNESS_REQUIRED  3              /* 3-of-3 (unanimous) for genesis */
#define DNAC_DEFAULT_TOTAL_SUPPLY      100000000000000ULL  /* 100 trillion default supply */

/* ============================================================================
 * Protocol Versions
 * ========================================================================== */

/** Protocol version 1: Transparent amounts */
#define DNAC_PROTOCOL_V1            1

/** Protocol version 2: PQ ZK amounts (future - STARKs) */
#define DNAC_PROTOCOL_V2            2

/** Current protocol version */
#define DNAC_PROTOCOL_VERSION       DNAC_PROTOCOL_V1

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Nullifier size (SHA3-512 hash) */
#define DNAC_NULLIFIER_SIZE         64

/** Transaction hash size (SHA3-512) */
#define DNAC_TX_HASH_SIZE           64

/** Token ID size (SHA3-512 hash) */
#define DNAC_TOKEN_ID_SIZE          64

/** Dilithium5 signature size */
#define DNAC_SIGNATURE_SIZE         4627

/** Dilithium5 public key size */
#define DNAC_PUBKEY_SIZE            2592

/** AES-256 key size for encrypted UTXO data */
#define DNAC_ENCRYPTED_DATA_SIZE    128

/** Maximum memo length */
#define DNAC_MEMO_MAX_SIZE          256

/** Fingerprint size (128 hex chars + null) */
#define DNAC_FINGERPRINT_SIZE       129

/** Burn address: all-zero fingerprint (128 hex zero = 64 bytes zero)
 *  Fee UTXOs are recorded here. Unspendable — no private key exists. */
#define DNAC_BURN_ADDRESS \
    "0000000000000000000000000000000000000000000000000000000000000000" \
    "0000000000000000000000000000000000000000000000000000000000000000"

/* ============================================================================
 * Forward Declarations
 * ========================================================================== */

typedef struct dnac_context dnac_context_t;
typedef struct dnac_wallet dnac_wallet_t;
typedef struct dnac_utxo dnac_utxo_t;
typedef struct dnac_transaction dnac_transaction_t;
typedef struct dnac_tx_builder dnac_tx_builder_t;

/* ============================================================================
 * Data Types
 * ========================================================================== */

/**
 * @brief UTXO status
 */
typedef enum {
    DNAC_UTXO_UNSPENT = 0,      /**< Available for spending */
    DNAC_UTXO_PENDING = 1,      /**< Spend in progress (awaiting attestations) */
    DNAC_UTXO_SPENT   = 2       /**< Already spent */
} dnac_utxo_status_t;

/**
 * @brief Transaction type
 *
 * v0.5.0: DNAC_TX_MINT removed. All tokens created via one-time genesis.
 */
typedef enum {
    DNAC_TX_GENESIS      = 0,   /**< One-time token creation (replaces MINT) */
    DNAC_TX_SPEND        = 1,   /**< Standard spend transaction */
    DNAC_TX_BURN         = 2,   /**< Destroy coins (optional) */
    DNAC_TX_TOKEN_CREATE = 3    /**< Create a new custom token */
} dnac_tx_type_t;

/**
 * @brief Unspent Transaction Output
 *
 * Protocol v1: Transparent amounts (current implementation).
 * v2 will use PQ ZK (STARKs) when available.
 */
struct dnac_utxo {
    uint8_t version;                             /**< Protocol version */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];         /**< Transaction that created this UTXO */
    uint32_t output_index;                       /**< Index within transaction */
    uint64_t amount;                             /**< Amount in smallest units */
    uint8_t nullifier[DNAC_NULLIFIER_SIZE];      /**< Nullifier for spending */
    char owner_fingerprint[DNAC_FINGERPRINT_SIZE]; /**< Owner's identity fingerprint */
    uint8_t token_id[DNAC_TOKEN_ID_SIZE];        /**< Token ID (zeros = native DNAC) */
    dnac_utxo_status_t status;                   /**< Current status */
    uint64_t received_at;                        /**< Unix timestamp when received */
    uint64_t spent_at;                           /**< Unix timestamp when spent (0 if unspent) */
};

/** Token registry entry */
typedef struct {
    uint8_t  token_id[DNAC_TOKEN_ID_SIZE];  /**< SHA3-512(creator_fp + name + nonce) */
    char     name[33];                       /**< Token name, max 32 chars */
    char     symbol[9];                      /**< Token symbol, max 8 chars */
    uint8_t  decimals;                       /**< Decimal places, 0-18 */
    uint64_t initial_supply;                 /**< Total supply at creation */
    char     creator_fp[DNAC_FINGERPRINT_SIZE]; /**< Creator's fingerprint */
    uint8_t  flags;                          /**< bit 0: mintable (future) */
    uint64_t block_height;                   /**< Block where created */
    uint64_t timestamp;                      /**< Creation timestamp */
} dnac_token_t;

/**
 * @brief Transaction output (for building transactions)
 */
typedef struct {
    char recipient_fingerprint[DNAC_FINGERPRINT_SIZE]; /**< Recipient's fingerprint */
    uint64_t amount;                                    /**< Amount to send */
    uint8_t token_id[DNAC_TOKEN_ID_SIZE];              /**< Token ID (zeros = native DNAC) */
    char memo[DNAC_MEMO_MAX_SIZE];                     /**< Optional memo */
} dnac_tx_output_t;

/**
 * @brief Wallet balance information
 */
typedef struct {
    uint64_t confirmed;         /**< Confirmed balance (spendable) */
    uint64_t pending;           /**< Pending incoming */
    uint64_t locked;            /**< Locked in pending spends */
    int utxo_count;             /**< Number of UTXOs */
} dnac_balance_t;

/**
 * @brief Witness server information
 */
typedef struct {
    char id[65];                /**< Server ID (32 bytes hex) */
    char address[256];          /**< IP:port or hostname */
    uint8_t pubkey[DNAC_PUBKEY_SIZE]; /**< Dilithium5 public key */
    char fingerprint[DNAC_FINGERPRINT_SIZE]; /**< Fingerprint derived from pubkey */
    bool is_available;          /**< Currently reachable */
    uint64_t last_seen;         /**< Last successful contact */
} dnac_witness_info_t;

/**
 * @brief Transaction history entry
 */
typedef struct {
    uint8_t tx_hash[DNAC_TX_HASH_SIZE]; /**< Transaction hash */
    dnac_tx_type_t type;                 /**< Transaction type */
    char counterparty[DNAC_FINGERPRINT_SIZE]; /**< Other party (if known) */
    int64_t amount_delta;                /**< Change in balance (+/-) */
    uint64_t fee;                        /**< Fee paid (if sender) */
    uint64_t timestamp;                  /**< Unix timestamp */
    char memo[DNAC_MEMO_MAX_SIZE];       /**< Memo (if any) */
} dnac_tx_history_t;

/**
 * @brief Transaction confirmation depth (v0.7.0)
 *
 * Tracks how deeply a transaction is embedded in the ledger.
 * Deeper transactions are more final and harder to reverse.
 */
typedef struct {
    uint64_t ledger_sequence;            /**< TX sequence number in ledger */
    uint64_t ledger_epoch;               /**< Epoch when TX was committed */
    uint64_t current_sequence;           /**< Current latest sequence */
    uint64_t current_epoch;              /**< Current epoch */
    uint64_t sequence_depth;             /**< current_seq - tx_seq */
    uint64_t epoch_depth;                /**< current_epoch - tx_epoch */
    bool is_confirmed;                   /**< Has ledger confirmation */
    bool is_final;                       /**< epoch_depth >= 2 (considered final) */
} dnac_confirmation_t;

/* ============================================================================
 * Callbacks
 * ========================================================================== */

/**
 * @brief Callback for async operations
 */
typedef void (*dnac_callback_t)(int result, void *data, void *user_data);

/**
 * @brief Payment received callback
 */
typedef void (*dnac_payment_cb_t)(const dnac_utxo_t *utxo, const char *memo, void *user_data);

/* ============================================================================
 * Lifecycle Functions
 * ========================================================================== */

/**
 * @brief Initialize DNAC context
 *
 * Must be called before any other DNAC functions.
 * Uses the DNA Connect engine for identity and DHT access.
 *
 * @param dna_engine Pointer to initialized dna_engine_t from libdna
 * @return Context pointer on success, NULL on failure
 */
dnac_context_t* dnac_init(void *dna_engine);

/**
 * @brief Shutdown DNAC context
 *
 * Releases all resources. Pending operations will be cancelled.
 *
 * @param ctx DNAC context
 */
void dnac_shutdown(dnac_context_t *ctx);

/**
 * @brief Set payment received callback
 *
 * Called when a payment is received from another user.
 *
 * @param ctx DNAC context
 * @param callback Function to call on payment receipt
 * @param user_data User data passed to callback
 */
void dnac_set_payment_callback(dnac_context_t *ctx, dnac_payment_cb_t callback, void *user_data);

/* ============================================================================
 * Wallet Functions
 * ========================================================================== */

/**
 * @brief Get wallet balance
 *
 * @param ctx DNAC context
 * @param balance Output balance structure
 * @return DNAC_SUCCESS or error code
 */
int dnac_get_balance(dnac_context_t *ctx, dnac_balance_t *balance);

/**
 * @brief Get wallet balance for a specific token
 *
 * If token_id is NULL or all-zeros, returns native DNAC balance.
 * Otherwise returns balance for the specified token only.
 *
 * @param ctx DNAC context
 * @param token_id Token ID (DNAC_TOKEN_ID_SIZE bytes), or NULL for native
 * @param balance Output balance structure
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_get_balance_token(dnac_context_t *ctx,
                                   const uint8_t *token_id,
                                   dnac_balance_t *balance);

/**
 * @brief Get list of UTXOs
 *
 * @param ctx DNAC context
 * @param utxos Output array (caller must free with dnac_free_utxos)
 * @param count Output count
 * @return DNAC_SUCCESS or error code
 */
int dnac_get_utxos(dnac_context_t *ctx, dnac_utxo_t **utxos, int *count);

/**
 * @brief Free UTXO array
 *
 * @param utxos Array to free
 * @param count Number of elements
 */
void dnac_free_utxos(dnac_utxo_t *utxos, int count);

/**
 * @brief Sync wallet from network
 *
 * Checks for new incoming payments via DHT.
 *
 * @param ctx DNAC context
 * @return DNAC_SUCCESS or error code
 */
int dnac_sync_wallet(dnac_context_t *ctx);

/**
 * @brief Sync token registry from witnesses
 *
 * Refreshes the local token registry by querying known tokens
 * from Nodus witnesses. Can be called from wallet sync flow
 * or independently.
 *
 * @param ctx DNAC context
 * @return DNAC_SUCCESS or error code
 */
int dnac_sync_tokens(dnac_context_t *ctx);

/**
 * @brief Start listening for incoming payments
 *
 * Subscribes to DHT inbox key for real-time payment notifications.
 * When payments arrive, the payment callback is invoked automatically.
 *
 * @param ctx DNAC context
 * @return DNAC_SUCCESS or error code
 */
int dnac_start_listening(dnac_context_t *ctx);

/**
 * @brief Stop listening for incoming payments
 *
 * Cancels the DHT inbox subscription.
 *
 * @param ctx DNAC context
 * @return DNAC_SUCCESS or error code
 */
int dnac_stop_listening(dnac_context_t *ctx);

/**
 * @brief Recover wallet from DHT
 *
 * Clears existing UTXOs and scans DHT inbox for all payments.
 * Use this after restoring identity from seed phrase.
 *
 * @param ctx DNAC context
 * @param recovered_count Output number of UTXOs recovered (can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_wallet_recover(dnac_context_t *ctx, int *recovered_count);

/* ============================================================================
 * Send Functions
 * ========================================================================== */

/**
 * @brief Send payment to recipient
 *
 * Creates transaction, collects witness attestations, broadcasts via DHT.
 *
 * @param ctx DNAC context
 * @param recipient_fingerprint Recipient's identity fingerprint
 * @param amount Amount to send
 * @param memo Optional memo (can be NULL)
 * @param callback Completion callback (can be NULL for sync)
 * @param user_data User data for callback
 * @return DNAC_SUCCESS or error code
 */
int dnac_send(dnac_context_t *ctx,
              const char *recipient_fingerprint,
              uint64_t amount,
              const char *memo,
              dnac_callback_t callback,
              void *user_data);

/**
 * @brief Estimate fee for transaction
 *
 * @param ctx DNAC context
 * @param amount Amount to send
 * @param fee_out Output estimated fee
 * @return DNAC_SUCCESS or error code
 */
int dnac_estimate_fee(dnac_context_t *ctx, uint64_t amount, uint64_t *fee_out);

/* ============================================================================
 * Transaction Builder (Advanced)
 * ========================================================================== */

/**
 * @brief Create transaction builder
 *
 * For advanced use cases with multiple outputs.
 *
 * @param ctx DNAC context
 * @return Builder pointer on success, NULL on failure
 */
dnac_tx_builder_t* dnac_tx_builder_create(dnac_context_t *ctx);

/**
 * @brief Add output to transaction
 *
 * @param builder Transaction builder
 * @param output Output specification
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_builder_add_output(dnac_tx_builder_t *builder, const dnac_tx_output_t *output);

/**
 * @brief Set token for the transaction
 *
 * When set, the builder will select only UTXOs matching this token_id
 * and stamp all inputs/outputs with it. If not called (or all-zeros),
 * builds a native DNAC transaction.
 *
 * @param builder Transaction builder
 * @param token_id Token ID (DNAC_TOKEN_ID_SIZE bytes)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_builder_set_token(dnac_tx_builder_t *builder, const uint8_t *token_id);

/**
 * @brief Build and sign transaction
 *
 * @param builder Transaction builder
 * @param tx_out Output transaction (caller must free with dnac_free_transaction)
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_builder_build(dnac_tx_builder_t *builder, dnac_transaction_t **tx_out);

/**
 * @brief Broadcast transaction
 *
 * Collects witness attestations and sends to recipient(s) via DHT.
 *
 * @param ctx DNAC context
 * @param tx Transaction to broadcast
 * @param callback Completion callback
 * @param user_data User data for callback
 * @return DNAC_SUCCESS or error code
 */
int dnac_tx_broadcast(dnac_context_t *ctx,
                      dnac_transaction_t *tx,
                      dnac_callback_t callback,
                      void *user_data);

/**
 * @brief Free transaction builder
 */
void dnac_tx_builder_free(dnac_tx_builder_t *builder);

/**
 * @brief Free transaction
 */
void dnac_free_transaction(dnac_transaction_t *tx);

/* ============================================================================
 * History Functions
 * ========================================================================== */

/**
 * @brief Get transaction history
 *
 * @param ctx DNAC context
 * @param history Output array (caller must free with dnac_free_history)
 * @param count Output count
 * @return DNAC_SUCCESS or error code
 */
int dnac_get_history(dnac_context_t *ctx, dnac_tx_history_t **history, int *count);

/**
 * @brief Fetch transaction history from Nodus witnesses (remote).
 *
 * Clears local transaction cache and repopulates from the authoritative
 * remote source. Local DB is cache only.
 *
 * @param ctx DNAC context
 * @param history Output array (caller must free with dnac_free_history)
 * @param count Output count
 * @return DNAC_SUCCESS or error code
 */
int dnac_get_remote_history(dnac_context_t *ctx, dnac_tx_history_t **history, int *count);

/**
 * @brief Free history array
 */
void dnac_free_history(dnac_tx_history_t *history, int count);

/**
 * @brief Get confirmation depth for a transaction (v0.7.0)
 *
 * Returns how deeply embedded a transaction is in the ledger.
 * A transaction is considered "final" when epoch_depth >= 2.
 *
 * @param ctx DNAC context
 * @param tx_hash Transaction hash to check
 * @param confirmation_out Output confirmation info
 * @return DNAC_SUCCESS or error code
 */
int dnac_get_confirmation(dnac_context_t *ctx,
                          const uint8_t *tx_hash,
                          dnac_confirmation_t *confirmation_out);

/* ============================================================================
 * Witness Functions
 * ========================================================================== */

/**
 * @brief Get list of known witness servers
 *
 * @param ctx DNAC context
 * @param servers Output array (caller must free with dnac_free_witness_list)
 * @param count Output count
 * @return DNAC_SUCCESS or error code
 */
int dnac_get_witness_list(dnac_context_t *ctx, dnac_witness_info_t **servers, int *count);

/**
 * @brief Free witness list
 */
void dnac_free_witness_list(dnac_witness_info_t *servers, int count);

/**
 * @brief Check if nullifier has been spent
 *
 * Queries witness servers to verify a nullifier hasn't been used.
 *
 * @param ctx DNAC context
 * @param nullifier Nullifier to check (DNAC_NULLIFIER_SIZE bytes)
 * @param is_spent Output: true if already spent
 * @return DNAC_SUCCESS or error code
 */
int dnac_check_nullifier(dnac_context_t *ctx, const uint8_t *nullifier, bool *is_spent);

/* ============================================================================
 * Query Functions (v0.10.0 hub/spoke)
 * ========================================================================== */

/**
 * @brief Query full transaction data from witnesses
 *
 * Returns the complete serialized transaction for the given hash.
 * Caller must free *tx_data_out when done.
 *
 * @param ctx DNAC context
 * @param tx_hash Transaction hash (DNAC_TX_HASH_SIZE bytes)
 * @param tx_data_out Output: serialized transaction data (heap-allocated)
 * @param tx_len_out Output: length of tx_data
 * @param tx_type_out Output: transaction type (can be NULL)
 * @param block_height_out Output: block height (can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_query_transaction(dnac_context_t *ctx,
                            const uint8_t *tx_hash,
                            uint8_t **tx_data_out,
                            uint32_t *tx_len_out,
                            uint8_t *tx_type_out,
                            uint64_t *block_height_out);

/**
 * @brief Query block by height from witnesses
 *
 * @param ctx DNAC context
 * @param height Block height to query
 * @param tx_hash_out Output: transaction hash in block (DNAC_TX_HASH_SIZE bytes)
 * @param tx_type_out Output: transaction type
 * @param timestamp_out Output: block timestamp
 * @param proposer_out Output: proposer witness ID (32 bytes, can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_query_block(dnac_context_t *ctx,
                      uint64_t height,
                      uint8_t *tx_hash_out,
                      uint8_t *tx_type_out,
                      uint64_t *timestamp_out,
                      uint8_t *proposer_out);

/**
 * @brief Query block range from witnesses
 *
 * Returns blocks in [from_height, to_height] range.
 * Caller must free *tx_hashes_out when done.
 *
 * @param ctx DNAC context
 * @param from_height Start height (inclusive)
 * @param to_height End height (inclusive)
 * @param count_out Output: number of blocks returned
 * @param total_out Output: total blocks on witness (can be NULL)
 * @return DNAC_SUCCESS or error code
 */
int dnac_query_block_range(dnac_context_t *ctx,
                            uint64_t from_height,
                            uint64_t to_height,
                            int *count_out,
                            uint64_t *total_out);

/* ============================================================================
 * Token Functions
 * ========================================================================== */

/**
 * @brief Create a new token
 *
 * Burns TOKEN_CREATE_FEE (1 DNAC) and creates a new custom token.
 * On success, the full supply is assigned to the creator as a genesis UTXO.
 *
 * @param ctx DNAC context
 * @param name Token name (max 32 chars)
 * @param symbol Token symbol (max 8 chars)
 * @param decimals Decimal places (0-18)
 * @param supply Total supply in smallest units
 * @return DNAC_SUCCESS or error code
 */
int dnac_token_create(dnac_context_t *ctx,
                      const char *name, const char *symbol,
                      uint8_t decimals, uint64_t supply);

/**
 * @brief Query all tokens from witness
 *
 * @param ctx DNAC context
 * @param out Output array (caller-allocated)
 * @param max Maximum entries to return
 * @param count Output count of entries written
 * @return DNAC_SUCCESS or error code
 */
int dnac_token_list(dnac_context_t *ctx, dnac_token_t *out, int max, int *count);

/**
 * @brief Query single token by ID from witness
 *
 * @param ctx DNAC context
 * @param token_id Token ID (DNAC_TOKEN_ID_SIZE bytes)
 * @param out Output token struct
 * @return DNAC_SUCCESS or error code
 */
int dnac_token_info(dnac_context_t *ctx, const uint8_t *token_id, dnac_token_t *out);

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

/**
 * @brief Get error string for error code
 *
 * @param error Error code
 * @return Human-readable error string
 */
const char* dnac_error_string(int error);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_H */
