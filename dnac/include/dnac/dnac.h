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
 * - Nodus 2-of-3 anchoring for double-spend prevention
 *
 * Protocol Versions:
 * - v1: Transparent amounts (current)
 * - v2: ZK amounts with Pedersen commitments + Bulletproofs (future)
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
#define DNAC_ERROR_ANCHOR_FAILED       -11
#define DNAC_ERROR_TIMEOUT             -12
#define DNAC_ERROR_NOT_FOUND           -13
#define DNAC_ERROR_SIGN_FAILED         -14
#define DNAC_ERROR_INVALID_SIGNATURE   -15
#define DNAC_ERROR_RANDOM_FAILED       -16

/* ============================================================================
 * Protocol Versions
 * ========================================================================== */

/** Protocol version 1: Transparent amounts */
#define DNAC_PROTOCOL_V1            1

/** Protocol version 2: ZK amounts (future) */
#define DNAC_PROTOCOL_V2            2

/** Current protocol version */
#define DNAC_PROTOCOL_VERSION       DNAC_PROTOCOL_V1

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Pedersen commitment size (compressed curve point) - used in v2 */
#define DNAC_COMMITMENT_SIZE        33

/** Blinding factor size (scalar) - used in v2 */
#define DNAC_BLINDING_SIZE          32

/** Nullifier size (SHA3-512 hash) */
#define DNAC_NULLIFIER_SIZE         64

/** Transaction hash size (SHA3-512) */
#define DNAC_TX_HASH_SIZE           64

/** Range proof size (Bulletproof, ~700 bytes typical) - used in v2 */
#define DNAC_RANGE_PROOF_MAX_SIZE   800

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
    DNAC_UTXO_PENDING = 1,      /**< Spend in progress (awaiting anchors) */
    DNAC_UTXO_SPENT   = 2       /**< Already spent */
} dnac_utxo_status_t;

/**
 * @brief Transaction type
 */
typedef enum {
    DNAC_TX_MINT    = 0,        /**< Initial coin creation (genesis) */
    DNAC_TX_SPEND   = 1,        /**< Standard spend transaction */
    DNAC_TX_BURN    = 2         /**< Destroy coins (optional) */
} dnac_tx_type_t;

/**
 * @brief Unspent Transaction Output
 *
 * Supports both v1 (transparent) and v2 (ZK) protocols:
 * - v1: amount is plaintext, commitment/blinding unused
 * - v2: amount hidden in commitment, blinding used for ZK proofs
 */
struct dnac_utxo {
    uint8_t version;                             /**< Protocol version (1=transparent, 2=ZK) */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];         /**< Transaction that created this UTXO */
    uint32_t output_index;                       /**< Index within transaction */
    uint64_t amount;                             /**< Amount (v1: public, v2: private) */
    uint8_t nullifier[DNAC_NULLIFIER_SIZE];      /**< Nullifier for spending */
    char owner_fingerprint[DNAC_FINGERPRINT_SIZE]; /**< Owner's identity fingerprint */
    dnac_utxo_status_t status;                   /**< Current status */
    uint64_t received_at;                        /**< Unix timestamp when received */
    uint64_t spent_at;                           /**< Unix timestamp when spent (0 if unspent) */

    /* v2 ZK fields (unused in v1) */
    uint8_t commitment[DNAC_COMMITMENT_SIZE];   /**< Pedersen commitment (v2 only) */
    uint8_t blinding_factor[DNAC_BLINDING_SIZE]; /**< Blinding factor (v2 only) */
};

/**
 * @brief Transaction output (for building transactions)
 */
typedef struct {
    char recipient_fingerprint[DNAC_FINGERPRINT_SIZE]; /**< Recipient's fingerprint */
    uint64_t amount;                                    /**< Amount to send */
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
 * @brief Nodus server information
 */
typedef struct {
    char id[65];                /**< Server ID (32 bytes hex) */
    char address[256];          /**< IP:port or hostname */
    uint8_t pubkey[DNAC_PUBKEY_SIZE]; /**< Dilithium5 public key */
    char fingerprint[DNAC_FINGERPRINT_SIZE]; /**< Fingerprint derived from pubkey */
    bool is_available;          /**< Currently reachable */
    uint64_t last_seen;         /**< Last successful contact */
} dnac_nodus_info_t;

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
 * Uses the DNA Messenger engine for identity and DHT access.
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
 * Creates transaction, collects Nodus anchors, broadcasts via DHT.
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
 * Collects Nodus anchors and sends to recipient(s) via DHT.
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
 * @brief Free history array
 */
void dnac_free_history(dnac_tx_history_t *history, int count);

/* ============================================================================
 * Nodus Functions
 * ========================================================================== */

/**
 * @brief Get list of known Nodus servers
 *
 * @param ctx DNAC context
 * @param servers Output array (caller must free with dnac_free_nodus_list)
 * @param count Output count
 * @return DNAC_SUCCESS or error code
 */
int dnac_get_nodus_list(dnac_context_t *ctx, dnac_nodus_info_t **servers, int *count);

/**
 * @brief Free Nodus list
 */
void dnac_free_nodus_list(dnac_nodus_info_t *servers, int count);

/**
 * @brief Check if nullifier has been spent
 *
 * Queries Nodus servers to verify a nullifier hasn't been used.
 *
 * @param ctx DNAC context
 * @param nullifier Nullifier to check (DNAC_NULLIFIER_SIZE bytes)
 * @param is_spent Output: true if already spent
 * @return DNAC_SUCCESS or error code
 */
int dnac_check_nullifier(dnac_context_t *ctx, const uint8_t *nullifier, bool *is_spent);

/* ============================================================================
 * Debug Functions
 * ========================================================================== */

/**
 * @brief Get debug info for UTXO
 *
 * @param ctx DNAC context
 * @param commitment Commitment to lookup (DNAC_COMMITMENT_SIZE bytes)
 * @param utxo Output UTXO info
 * @return DNAC_SUCCESS or error code
 */
int dnac_debug_get_utxo(dnac_context_t *ctx, const uint8_t *commitment, dnac_utxo_t *utxo);

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
