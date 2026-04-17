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

/* Genesis configuration — unanimous (N/N) enforced server-side */
#define DNAC_DEFAULT_TOTAL_SUPPLY      100000000000000000ULL  /* 1B DNAC (10^17 raw, 8 decimals) */

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
 * Stake & Delegation (v1)
 * ========================================================================== */

/** Fixed self-stake amount per validator: exactly 10,000,000 DNAC */
#define DNAC_SELF_STAKE_AMOUNT       (10000000ULL * 100000000ULL)   /* 10M × 10^8 raw */

/** Minimum delegation amount: 100 DNAC (raised from 1 per F-DOS-02 audit finding) */
#define DNAC_MIN_DELEGATION          (100ULL * 100000000ULL)         /* 100 × 10^8 raw */

/** Maximum number of delegations a single delegator can hold */
#define DNAC_MAX_DELEGATIONS_PER_DELEGATOR   64

/** Maximum number of validator records in the tree (Rule M, F-DOS-01) */
#define DNAC_MAX_VALIDATORS          128

/** UNSTAKE locked-UTXO cooldown (24h at 5s block interval) */
#define DNAC_UNSTAKE_COOLDOWN_BLOCKS  17280

/** Epoch length in blocks (~10 min at 5s) */
#define DNAC_EPOCH_LENGTH            120

/** Minimum tenure in pending pool before committee eligibility (Rule R) */
#define DNAC_MIN_TENURE_BLOCKS       240  /* 2 × EPOCH_LENGTH */

/** Fixed committee size (v1; v2 sortition may vary) */
#define DNAC_COMMITTEE_SIZE          7

/** Liveness threshold: fraction of epoch blocks a committee member must sign
 *  (in basis points — 8000 = 80%) to earn rewards that epoch (Rule N) */
#define DNAC_LIVENESS_THRESHOLD_BPS  8000

/** Number of consecutive missed epochs before AUTO_RETIRED status (Rule N) */
#define DNAC_AUTO_RETIRE_EPOCHS      3

/** VALIDATOR_UPDATE freshness window: TX rejected if signed_at_block is older than this */
#define DNAC_SIGN_FRESHNESS_WINDOW   32   /* blocks (~160s at 5s blocks) */

/** CLAIM_REWARD dust floor in raw units (Rule L — dynamic dust = max(this, 10× current_fee)) */
#define DNAC_DUST_FLOOR              1000000ULL   /* 0.01 DNAC = 10^6 raw */

/** Maximum commission in basis points (100% = 10000) */
#define DNAC_COMMISSION_BPS_MAX      10000

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
    DNAC_TX_GENESIS          = 0,   /**< One-time token creation (replaces MINT) */
    DNAC_TX_SPEND            = 1,   /**< Standard spend transaction */
    DNAC_TX_BURN             = 2,   /**< Destroy coins (optional) */
    DNAC_TX_TOKEN_CREATE     = 3,   /**< Create a new custom token */
    DNAC_TX_STAKE            = 4,   /**< Witness self-stake (validator bond) */
    DNAC_TX_DELEGATE         = 5,   /**< Delegator stakes onto a validator */
    DNAC_TX_UNSTAKE          = 6,   /**< Validator withdraws self-stake (unbonding) */
    DNAC_TX_UNDELEGATE       = 7,   /**< Delegator withdraws delegation (unbonding) */
    DNAC_TX_CLAIM_REWARD     = 8,   /**< Claim accrued staking/delegation rewards */
    DNAC_TX_VALIDATOR_UPDATE = 9    /**< Update validator metadata (commission, moniker, etc.) */
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

    /* Phase 12 — Anchored verification state (runtime-only, NOT persisted).
     * true  = this UTXO has a valid Merkle proof against a BFT-anchored
     *         state_root (dnac_utxo_verify_anchored succeeded).
     * false = UTXO is present but unverified (witness didn't ship a proof,
     *         trust state isn't bootstrapped, or verification failed).
     * Display code should distinguish verified balance from total balance. */
    bool verified;
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
    uint8_t token_id[DNAC_TOKEN_ID_SIZE]; /**< Token ID (zeros = native DNAC) */
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
 * @brief Get the receipt of the most recently completed dnac_send().
 *
 * Phase 13 / Task 13.4 — surfaces block_height + tx_index + tx_hash
 * from the witness response so callers (CLI, Flutter) can display
 * exactly where the TX landed. Returns DNAC_ERROR_NOT_FOUND if no
 * send has completed yet on this context.
 */
int dnac_last_send_receipt(dnac_context_t *ctx,
                            uint64_t *block_height_out,
                            uint32_t *tx_index_out,
                            uint8_t *tx_hash_out);

/**
 * @brief Send a DNAC payment in a specific token
 *
 * Same as dnac_send(), but allows selecting a custom token. Fee is
 * a flat dynamic DNAC fee (queried from witness), paid in native DNAC regardless of token.
 * UTXO selection is token-aware: only UTXOs of the specified token
 * are used as inputs, and change is also emitted in the same token.
 *
 * @param ctx DNAC context
 * @param recipient_fingerprint Recipient's identity fingerprint
 * @param amount Amount to send (in token's raw units)
 * @param memo Optional memo (can be NULL)
 * @param token_id Token ID (DNAC_TOKEN_ID_SIZE bytes), or NULL for native DNAC
 * @param callback Completion callback (can be NULL for sync)
 * @param user_data User data for callback
 * @return DNAC_SUCCESS or error code
 */
int dnac_send_token(dnac_context_t *ctx,
                    const char *recipient_fingerprint,
                    uint64_t amount,
                    const char *memo,
                    const uint8_t *token_id,
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

/**
 * @brief Query current dynamic fee from witness
 *
 * Returns the exact fee required right now, based on mempool load.
 *
 * @param ctx DNAC context
 * @param fee_out Output minimum fee in raw units
 * @return DNAC_SUCCESS or error code
 */
int dnac_get_current_fee(dnac_context_t *ctx, uint64_t *fee_out);

/* ============================================================================
 * Stake & Delegation Builders (Phase 7)
 * ========================================================================== */

/**
 * @brief Submit a STAKE TX — become a validator.
 *
 * Consumes DNAC_SELF_STAKE_AMOUNT (10M × 10^8 raw) + current dynamic fee
 * from caller's native DNAC UTXOs. Change returned to caller. The witness
 * creates a validator record keyed by the caller's signing pubkey on commit.
 *
 * @param ctx                    DNAC context (must have identity + chain_id loaded)
 * @param commission_bps         Commission rate in basis points (0..10000)
 * @param unstake_destination_fp 128-char lowercase hex fingerprint that will
 *                               receive the post-cooldown UTXO when UNSTAKE
 *                               matures. By convention the caller's own
 *                               fingerprint, but any recipient is allowed.
 *                               Immutable once committed (Rule T).
 * @param callback               Completion callback (can be NULL)
 * @param user_data              Callback user data
 * @return DNAC_SUCCESS or error code
 */
int dnac_stake(dnac_context_t *ctx,
               uint16_t commission_bps,
               const char *unstake_destination_fp,
               dnac_callback_t callback,
               void *user_data);

/**
 * @brief Submit an UNSTAKE TX — trigger validator RETIRING -> UNSTAKED.
 *
 * Fee-only TX with no appended fields. Actual self-stake return happens at
 * the epoch boundary via a locked UTXO whose
 * unlock_block = commit_block + DNAC_UNSTAKE_COOLDOWN_BLOCKS.
 *
 * @param ctx        DNAC context
 * @param callback   Completion callback (can be NULL)
 * @param user_data  Callback user data
 * @return DNAC_SUCCESS or error code
 */
int dnac_unstake(dnac_context_t *ctx,
                 dnac_callback_t callback,
                 void *user_data);

/**
 * @brief Submit a DELEGATE TX — stake native DNAC with a validator.
 *
 * Consumes (amount + fee) from caller's native DNAC UTXOs. The witness
 * creates / updates a delegation record on commit.
 *
 * @param ctx               DNAC context
 * @param validator_pubkey  Dilithium5 pubkey of the target validator
 *                          (DNAC_PUBKEY_SIZE bytes; must differ from caller's
 *                          signing pubkey — Rule S: no self-delegation)
 * @param amount            Amount to delegate in raw units
 *                          (must be >= DNAC_MIN_DELEGATION)
 * @param callback          Completion callback (can be NULL)
 * @param user_data         Callback user data
 * @return DNAC_SUCCESS or error code
 */
int dnac_delegate(dnac_context_t *ctx,
                  const uint8_t *validator_pubkey,
                  uint64_t amount,
                  dnac_callback_t callback,
                  void *user_data);

/**
 * @brief Submit an UNDELEGATE TX — withdraw (part of) a delegation.
 *
 * Fee-only payment; the delegation principal + pending reward split is
 * emitted by the witness at state-apply time (Rule Q — two UTXOs are
 * always produced, even when pending < dust, to preserve supply).
 *
 * @param ctx               DNAC context
 * @param validator_pubkey  Validator to unbond from (DNAC_PUBKEY_SIZE bytes)
 * @param amount            Principal to withdraw in raw units (> 0)
 * @param callback          Completion callback (can be NULL)
 * @param user_data         Callback user data
 * @return DNAC_SUCCESS or error code
 */
int dnac_undelegate(dnac_context_t *ctx,
                    const uint8_t *validator_pubkey,
                    uint64_t amount,
                    dnac_callback_t callback,
                    void *user_data);

/**
 * @brief Submit a CLAIM_REWARD TX — withdraw accrued staking rewards.
 *
 * Builder-level API exposes max_pending_amount and valid_before_block as
 * explicit parameters so CLI + early Flutter can call it before Phase 14
 * ships dnac_get_pending_rewards(). A future wrapper
 * dnac_claim_reward_auto(ctx, validator) will query the witness for the
 * pending amount + current block height and call this builder.
 *
 * @param ctx                     DNAC context
 * @param target_validator_pubkey Validator whose accrued rewards to claim
 *                                (DNAC_PUBKEY_SIZE bytes)
 * @param max_pending_amount      Client-supplied upper bound on the pending
 *                                reward (replay defense — witness enforces
 *                                actual_pending <= max_pending_amount)
 * @param valid_before_block      Block-height expiry — witness rejects the
 *                                claim when current_block > this value
 *                                (typically current_block +
 *                                 DNAC_SIGN_FRESHNESS_WINDOW)
 * @param callback                Completion callback (can be NULL)
 * @param user_data               Callback user data
 * @return DNAC_SUCCESS or error code
 */
int dnac_claim_reward(dnac_context_t *ctx,
                      const uint8_t *target_validator_pubkey,
                      uint64_t max_pending_amount,
                      uint64_t valid_before_block,
                      dnac_callback_t callback,
                      void *user_data);

/**
 * @brief Submit a VALIDATOR_UPDATE TX — change validator commission rate.
 *
 * Fee-only TX. Must be called by the validator operator (signer pubkey
 * must match an existing active validator record). An increase takes
 * effect at the next epoch boundary (>= 1 full epoch notice per Rule K);
 * a decrease is immediate and clears any pending increase. Rule K also
 * enforces freshness: the witness requires
 *   current_block - signed_at_block <= DNAC_SIGN_FRESHNESS_WINDOW
 * so the caller must populate `signed_at_block` with a recent block
 * height.
 *
 * Builder-level API takes `signed_at_block` as an explicit parameter
 * because no client-side RPC exists yet for querying the witness's
 * current block height — that ships in Phase 14. A future wrapper
 * `dnac_validator_update_auto(ctx, new_commission_bps)` will query the
 * witness internally and call this builder; the signature of this
 * function is stable for the life of the protocol.
 *
 * @param ctx                 DNAC context
 * @param new_commission_bps  New commission rate in basis points
 *                            (0..DNAC_COMMISSION_BPS_MAX == 10000)
 * @param signed_at_block     Block-height anchor for Rule K freshness
 *                            (witness rejects if the value is stale).
 *                            Must be > 0.
 * @param callback            Completion callback (can be NULL)
 * @param user_data           Callback user data
 * @return DNAC_SUCCESS or error code
 */
int dnac_validator_update(dnac_context_t *ctx,
                          uint16_t new_commission_bps,
                          uint64_t signed_at_block,
                          dnac_callback_t callback,
                          void *user_data);

/* ============================================================================
 * Stake & Delegation — Client-side Query API (Phase 7 Tasks 38, 39)
 *
 * The stubs below expose the API shape for reward + validator queries.
 * The witness-side RPC handlers land in Phase 14 (Tasks 61-63). Until
 * then these functions log a WARN and return DNAC_ERROR_NOT_IMPLEMENTED;
 * CLI + Flutter should guard on that return code when rendering UI.
 * ========================================================================== */

/**
 * @brief Query the witness for the total pending reward accrued to a
 *        given claimant across all of their delegations plus any
 *        validator-side self-claim.
 *
 * STUB — the witness-side RPC handler (dnac_pending_rewards_query) lands
 * in Phase 14 Task 61. Until then this function returns
 * DNAC_ERROR_NOT_IMPLEMENTED and zeroes *total_pending_out for safety.
 *
 * The builder for CLAIM_REWARD already exists (see dnac_claim_reward);
 * once the Phase 14 RPC is wired the auto-claim helper can call this
 * function to obtain `max_pending_amount` before building the TX.
 *
 * @param ctx              DNAC context
 * @param claimant_pubkey  Claimant's Dilithium5 pubkey
 *                         (DNAC_PUBKEY_SIZE bytes). Pass NULL to query
 *                         the caller's own pending rewards.
 * @param total_pending_out Total pending amount across all validators
 *                          (raw units). Always written (0 on error).
 * @param callback         Completion callback (for async RPC once wired;
 *                         ignored by the current stub)
 * @param user_data        Callback user data (ignored by the stub)
 * @return DNAC_SUCCESS once wired, DNAC_ERROR_NOT_IMPLEMENTED until
 *         Phase 14, DNAC_ERROR_INVALID_PARAM on NULL total_pending_out
 */
int dnac_get_pending_rewards(dnac_context_t *ctx,
                             const uint8_t *claimant_pubkey,
                             uint64_t *total_pending_out,
                             dnac_callback_t callback,
                             void *user_data);

/**
 * @brief One validator's summary, as returned by dnac_validator_list()
 *        and dnac_get_committee().
 *
 * Matches the witness-side validator record projection (see
 * dnac/include/dnac/validator.h for the authoritative struct); only
 * the fields that external callers actually need are exposed here.
 */
typedef struct {
    uint8_t  pubkey[DNAC_PUBKEY_SIZE];  /**< Dilithium5 pubkey (2592B) */
    uint64_t self_stake;                 /**< Operator's own stake (raw units) */
    uint64_t total_delegated;            /**< Sum of all delegations (raw units) */
    uint16_t commission_bps;             /**< Commission 0..10000 */
    uint8_t  status;                     /**< dnac_validator_status_t */
    uint64_t active_since_block;         /**< Block height when ACTIVE */
} dnac_validator_list_entry_t;

/**
 * @brief List validators known to the witness, optionally filtered by
 *        status.
 *
 * STUB — the witness-side RPC handler lands in Phase 14 Task 63. Until
 * then this function logs a WARN, writes *count_out = 0, and returns
 * DNAC_ERROR_NOT_IMPLEMENTED. Callers should gate validator-list UI on
 * that return code.
 *
 * @param ctx            DNAC context
 * @param filter_status  Filter by dnac_validator_status_t value, or -1
 *                       to include all statuses.
 * @param out            Caller-allocated array of validator entries
 * @param max_entries    Capacity of out[] (must be > 0 when out != NULL)
 * @param count_out      Number of entries filled (always written)
 * @return DNAC_SUCCESS once wired, DNAC_ERROR_NOT_IMPLEMENTED until
 *         Phase 14, DNAC_ERROR_INVALID_PARAM on bad args
 */
int dnac_validator_list(dnac_context_t *ctx,
                        int filter_status,
                        dnac_validator_list_entry_t *out,
                        int max_entries,
                        int *count_out);

/**
 * @brief Fetch the current epoch's committee (top-N validators up to
 *        DNAC_COMMITTEE_SIZE).
 *
 * STUB — the witness-side RPC handler lands in Phase 14 Task 62. Until
 * then this function logs a WARN, writes *count_out = 0, and returns
 * DNAC_ERROR_NOT_IMPLEMENTED.
 *
 * During bootstrap the committee may be smaller than
 * DNAC_COMMITTEE_SIZE; callers must trust *count_out rather than
 * assuming a full committee.
 *
 * @param ctx        DNAC context
 * @param out        Caller-allocated array of >= DNAC_COMMITTEE_SIZE
 *                   entries
 * @param count_out  Number of committee members returned (always
 *                   written)
 * @return DNAC_SUCCESS once wired, DNAC_ERROR_NOT_IMPLEMENTED until
 *         Phase 14, DNAC_ERROR_INVALID_PARAM on bad args
 */
int dnac_get_committee(dnac_context_t *ctx,
                       dnac_validator_list_entry_t *out,
                       int *count_out);

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
 * Burns TOKEN_CREATE_FEE (1% of genesis supply, 10M DNAC) and creates a new custom token.
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
