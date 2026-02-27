/**
 * @file bft.h
 * @brief DNAC BFT (Byzantine Fault Tolerant) Consensus API
 *
 * Implements a PBFT-like consensus protocol for witness servers:
 * - 4-phase consensus: PROPOSE → PREVOTE → PRECOMMIT → COMMIT
 * - Leader rotation: (epoch + view) % N
 * - View change on leader timeout
 * - TCP mesh networking between witnesses
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#ifndef DNAC_BFT_H
#define DNAC_BFT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#include "dnac.h"
#include "dnac/transaction.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================================
 * Constants
 * ========================================================================== */

/** Maximum witnesses in roster */
#define DNAC_BFT_MAX_WITNESSES          16

/** Maximum serialized transaction size (64KB) - must match DNAC_MAX_TX_SIZE in nodus.h */
#define DNAC_BFT_MAX_TX_SIZE            65536

/** Default round timeout (milliseconds) */
#define DNAC_BFT_ROUND_TIMEOUT_MS       5000

/** Default view change timeout (milliseconds) */
#define DNAC_BFT_VIEW_CHANGE_TIMEOUT_MS 10000

/** Maximum view changes per request before error */
#define DNAC_BFT_MAX_VIEW_CHANGES       3

/** Default TCP port for BFT mesh */
#define DNAC_BFT_TCP_PORT               4200

/** Witness ID size */
#define DNAC_BFT_WITNESS_ID_SIZE        32

/** Maximum address length */
#define DNAC_BFT_MAX_ADDRESS_LEN        256

/** BFT roster DHT key */
#define DNAC_BFT_ROSTER_KEY             "dnac:bft:roster"

/** BFT protocol version (v0.10.0: bumped to 2 for chain_id in header) */
#define DNAC_BFT_PROTOCOL_VERSION       2

/* Epoch duration constant - single source of truth in epoch.h */
#include "dnac/epoch.h"

/* ============================================================================
 * Error Codes
 * ========================================================================== */

#define DNAC_BFT_SUCCESS                    0
#define DNAC_BFT_ERROR_INVALID_PARAM       -1
#define DNAC_BFT_ERROR_OUT_OF_MEMORY       -2
#define DNAC_BFT_ERROR_NOT_INITIALIZED     -3
#define DNAC_BFT_ERROR_NETWORK             -4
#define DNAC_BFT_ERROR_TIMEOUT             -5
#define DNAC_BFT_ERROR_NO_QUORUM           -6
#define DNAC_BFT_ERROR_LEADER_FAILED       -7
#define DNAC_BFT_ERROR_VIEW_CHANGE_FAILED  -8
#define DNAC_BFT_ERROR_DOUBLE_SPEND        -9
#define DNAC_BFT_ERROR_INVALID_MESSAGE     -10
#define DNAC_BFT_ERROR_INVALID_SIGNATURE   -11
#define DNAC_BFT_ERROR_NOT_LEADER          -12
#define DNAC_BFT_ERROR_ROSTER_FULL         -13
#define DNAC_BFT_ERROR_PEER_NOT_FOUND      -14
#define DNAC_BFT_ERROR_CONNECTION_FAILED   -15
#define DNAC_BFT_ERROR_NOT_FOUND           -16

/* ============================================================================
 * Message Types
 * ========================================================================== */

/**
 * @brief BFT message types
 */
typedef enum {
    BFT_MSG_PROPOSAL        = 1,    /**< Leader proposes transaction */
    BFT_MSG_PREVOTE         = 2,    /**< Witness prevote on proposal */
    BFT_MSG_PRECOMMIT       = 3,    /**< Witness precommit after prevote quorum */
    BFT_MSG_COMMIT          = 4,    /**< Final commit (triggers nullifier add) */
    BFT_MSG_VIEW_CHANGE     = 5,    /**< Request view change */
    BFT_MSG_NEW_VIEW        = 6,    /**< New leader announces view */
    BFT_MSG_FORWARD_REQ     = 7,    /**< Non-leader forwards request to leader */
    BFT_MSG_FORWARD_RSP     = 8,    /**< Leader response via forwarder */
    BFT_MSG_ROSTER_REQUEST  = 9,    /**< Request current roster */
    BFT_MSG_ROSTER_RESPONSE = 10,   /**< Roster response */
    BFT_MSG_IDENTIFY        = 11,   /**< Identity exchange on connect */
} dnac_bft_msg_type_t;

/**
 * @brief Vote types for PREVOTE/PRECOMMIT
 */
typedef enum {
    BFT_VOTE_APPROVE        = 0,    /**< Approve the proposal */
    BFT_VOTE_REJECT         = 1,    /**< Reject (e.g., double-spend detected) */
} dnac_bft_vote_t;

/**
 * @brief Consensus round phase
 */
typedef enum {
    BFT_PHASE_IDLE          = 0,    /**< No active round */
    BFT_PHASE_PROPOSE       = 1,    /**< Waiting for proposal */
    BFT_PHASE_PREVOTE       = 2,    /**< Collecting prevotes */
    BFT_PHASE_PRECOMMIT     = 3,    /**< Collecting precommits */
    BFT_PHASE_COMMIT        = 4,    /**< Committing */
    BFT_PHASE_VIEW_CHANGE   = 5,    /**< View change in progress */
} dnac_bft_phase_t;

/* ============================================================================
 * Configuration
 * ========================================================================== */

/**
 * @brief BFT configuration
 */
typedef struct {
    uint32_t n_witnesses;               /**< Total witnesses in roster */
    uint32_t f_tolerance;               /**< Byzantine fault tolerance (n = 3f+1) */
    uint32_t quorum;                    /**< Required votes (2f+1) */
    uint32_t round_timeout_ms;          /**< Timeout per round */
    uint32_t view_change_timeout_ms;    /**< View change timeout */
    uint32_t max_view_changes;          /**< Max retries before error */
    uint16_t tcp_port;                  /**< TCP listen port */
} dnac_bft_config_t;

/**
 * @brief Initialize config with defaults for given witness count
 */
void dnac_bft_config_init(dnac_bft_config_t *config, uint32_t n_witnesses);

/* ============================================================================
 * Roster Management
 * ========================================================================== */

/**
 * @brief Roster entry (single witness)
 */
typedef struct {
    uint8_t witness_id[DNAC_BFT_WITNESS_ID_SIZE];   /**< Witness ID */
    uint8_t pubkey[DNAC_PUBKEY_SIZE];               /**< Dilithium5 public key */
    char address[DNAC_BFT_MAX_ADDRESS_LEN];         /**< IP:port */
    uint64_t joined_epoch;                          /**< When witness joined */
    bool active;                                    /**< Currently active */
} dnac_roster_entry_t;

/**
 * @brief Witness roster
 */
typedef struct {
    uint32_t version;                               /**< Roster version (increments on change) */
    uint32_t n_witnesses;                           /**< Number of witnesses */
    dnac_roster_entry_t witnesses[DNAC_BFT_MAX_WITNESSES];
    uint8_t signature[DNAC_SIGNATURE_SIZE];         /**< Signed by quorum */
} dnac_roster_t;

/* ============================================================================
 * BFT Messages
 * ========================================================================== */

/**
 * @brief BFT message header (common to all messages)
 *
 * Gap 23-24 Fix (v0.6.0): Added nonce for replay prevention.
 * Messages with same (sender_id, nonce) within time window are rejected.
 */
typedef struct {
    uint8_t version;                                /**< Protocol version */
    dnac_bft_msg_type_t type;                       /**< Message type */
    uint64_t round;                                 /**< Consensus round number */
    uint32_t view;                                  /**< Current view */
    uint8_t sender_id[DNAC_BFT_WITNESS_ID_SIZE];    /**< Sender witness ID */
    uint64_t timestamp;                             /**< Message timestamp */
    uint64_t nonce;                                 /**< Random nonce for replay prevention */
    uint8_t chain_id[32];                           /**< v0.10.0: Zone chain ID */
} dnac_bft_msg_header_t;

/**
 * @brief Proposal message (from leader)
 *
 * v0.4.0: Now carries multiple nullifiers to prevent multi-input double-spend.
 * v0.5.0: Added tx_type for genesis (requires unanimous 3-of-3 quorum).
 * v0.8.0: Added tx_data/tx_len so validators can verify full transaction.
 */
typedef struct {
    dnac_bft_msg_header_t header;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];             /**< Transaction hash */
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE]; /**< All nullifiers being spent */
    uint8_t nullifier_count;                        /**< Number of nullifiers */
    uint8_t tx_type;                                /**< Transaction type (0=GENESIS, 1=SPEND, 2=BURN) */
    uint8_t tx_data[DNAC_BFT_MAX_TX_SIZE];          /**< v0.8.0: Full serialized transaction */
    uint32_t tx_len;                                /**< v0.8.0: TX data length */
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];        /**< Client's public key */
    uint8_t client_signature[DNAC_SIGNATURE_SIZE];  /**< Client's signature on tx */
    uint64_t fee_amount;                            /**< Fee amount */
    uint8_t signature[DNAC_SIGNATURE_SIZE];         /**< Leader's signature */
} dnac_bft_proposal_t;

/**
 * @brief Vote message (PREVOTE or PRECOMMIT)
 */
typedef struct {
    dnac_bft_msg_header_t header;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];             /**< Transaction hash being voted on */
    dnac_bft_vote_t vote;                           /**< APPROVE or REJECT */
    char reason[256];                               /**< Reason if rejected */
    uint8_t signature[DNAC_SIGNATURE_SIZE];         /**< Voter's signature */
} dnac_bft_vote_msg_t;

/**
 * @brief Commit message
 *
 * v0.4.0: Now carries multiple nullifiers to commit all inputs atomically.
 * v0.8.0: Added tx_data/tx_len so remote witnesses can update UTXO set on COMMIT.
 */
typedef struct {
    dnac_bft_msg_header_t header;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];             /**< Transaction hash */
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE]; /**< All nullifiers to commit */
    uint8_t nullifier_count;                        /**< Number of nullifiers */
    uint8_t tx_type;                                /**< v0.8.0: Transaction type */
    uint8_t tx_data[DNAC_BFT_MAX_TX_SIZE];          /**< v0.8.0: Full serialized transaction */
    uint32_t tx_len;                                /**< v0.8.0: TX data length */
    uint64_t proposal_timestamp;                    /**< v0.9.0: Proposal timestamp for block */
    uint8_t proposer_id[DNAC_BFT_WITNESS_ID_SIZE];  /**< v0.9.0: Proposer ID for block */
    uint32_t n_precommits;                          /**< Number of precommit proofs */
    uint8_t signature[DNAC_SIGNATURE_SIZE];         /**< Sender's signature */
} dnac_bft_commit_t;

/**
 * @brief View change request
 */
typedef struct {
    dnac_bft_msg_header_t header;
    uint32_t new_view;                              /**< Requested new view */
    uint64_t last_committed_round;                  /**< Last successfully committed round */
    uint8_t signature[DNAC_SIGNATURE_SIZE];         /**< Signature */
} dnac_bft_view_change_t;

/**
 * @brief New view announcement (from new leader)
 */
typedef struct {
    dnac_bft_msg_header_t header;
    uint32_t new_view;                              /**< New view number */
    uint32_t n_view_change_proofs;                  /**< Number of VIEW-CHANGE proofs */
    uint8_t signature[DNAC_SIGNATURE_SIZE];         /**< New leader's signature */
} dnac_bft_new_view_t;

/**
 * @brief Forward request (non-leader to leader)
 *
 * v0.4.0: Now carries full serialized TX instead of single nullifier.
 */
typedef struct {
    dnac_bft_msg_header_t header;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t tx_data[DNAC_BFT_MAX_TX_SIZE];          /**< Full serialized transaction */
    uint32_t tx_len;                                /**< TX data length */
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t client_signature[DNAC_SIGNATURE_SIZE];
    uint64_t fee_amount;
    uint8_t forwarder_id[DNAC_BFT_WITNESS_ID_SIZE]; /**< ID of forwarding witness */
    uint8_t signature[DNAC_SIGNATURE_SIZE];         /**< Forwarder's signature */
} dnac_bft_forward_req_t;

/**
 * @brief Forward response (leader via forwarder to client)
 */
typedef struct {
    dnac_bft_msg_header_t header;
    int status;                                     /**< Result status */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    dnac_witness_sig_t witnesses[DNAC_TX_MAX_WITNESSES]; /**< Attestations */
    int witness_count;
    uint8_t signature[DNAC_SIGNATURE_SIZE];         /**< Leader's signature */
} dnac_bft_forward_rsp_t;

/* ============================================================================
 * Consensus State
 * ========================================================================== */

/**
 * @brief Vote tracking for a round
 */
typedef struct {
    uint8_t voter_id[DNAC_BFT_WITNESS_ID_SIZE];
    dnac_bft_vote_t vote;
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_vote_record_t;

/**
 * @brief Consensus round state
 *
 * v0.4.0: Now tracks multiple nullifiers for multi-input transactions.
 * v0.5.0: Added tx_type for genesis handling (requires unanimous quorum).
 * v0.8.0: Added tx_data/tx_len for full TX validation on COMMIT.
 */
typedef struct {
    uint64_t round;                                 /**< Round number */
    uint32_t view;                                  /**< Current view */
    dnac_bft_phase_t phase;                         /**< Current phase */
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];             /**< Transaction being processed */
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE]; /**< All nullifiers being spent */
    uint8_t nullifier_count;                        /**< Number of nullifiers */
    uint8_t tx_type;                                /**< Transaction type (v0.5.0: for genesis 3-of-3) */
    uint8_t tx_data[DNAC_BFT_MAX_TX_SIZE];          /**< v0.8.0: Full serialized transaction */
    uint32_t tx_len;                                /**< v0.8.0: TX data length */

    /* Votes collected */
    dnac_bft_vote_record_t prevotes[DNAC_BFT_MAX_WITNESSES];
    int prevote_count;
    int prevote_approve_count;

    dnac_bft_vote_record_t precommits[DNAC_BFT_MAX_WITNESSES];
    int precommit_count;
    int precommit_approve_count;

    /* Timing */
    uint64_t phase_start_time;                      /**< When current phase started */

    /* v0.9.0: Block production data */
    uint64_t proposal_timestamp;                    /**< Timestamp from proposal (deterministic) */
    uint8_t  proposer_id[DNAC_BFT_WITNESS_ID_SIZE]; /**< Leader who proposed this round */

    /* Client request data (for response) */
    uint8_t client_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t client_signature[DNAC_SIGNATURE_SIZE];
    uint64_t fee_amount;

    /* Forwarder info (if request was forwarded) */
    bool is_forwarded;
    uint8_t forwarder_id[DNAC_BFT_WITNESS_ID_SIZE];
    int forwarder_fd;                               /**< Socket to forwarder */

    /* Direct client connection (if not forwarded) */
    int client_fd;                                  /**< Socket to client (-1 if none) */
} dnac_bft_round_state_t;

/**
 * @brief View change tracking
 */
typedef struct {
    uint32_t target_view;                           /**< View being changed to */
    uint8_t voter_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint64_t last_committed_round;
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_view_change_record_t;

/**
 * @brief Callback function types for BFT consensus
 */
typedef bool (*dnac_bft_nullifier_exists_fn)(const uint8_t *nullifier, void *user_data);
typedef int (*dnac_bft_nullifier_add_fn)(const uint8_t *nullifier, const uint8_t *tx_hash, void *user_data);
typedef void (*dnac_bft_send_response_fn)(int client_fd, int status, const char *error_msg, void *user_data);
typedef int (*dnac_bft_complete_forward_fn)(const uint8_t *tx_hash, const uint8_t *witness_id,
                                            const uint8_t *pubkey, void *user_data);

/**
 * @brief v0.5.0: Genesis state callback for recording genesis on commit
 *
 * Called when a GENESIS transaction is committed by consensus.
 * @param tx_hash Genesis transaction hash
 * @param total_supply Total tokens created
 * @param commitment Genesis commitment hash
 * @return 0 on success, -1 on error, -2 if genesis already exists
 */
typedef int (*dnac_bft_genesis_record_fn)(const uint8_t *tx_hash, uint64_t total_supply,
                                          const uint8_t *commitment, void *user_data);

/**
 * @brief v0.5.0: Ledger entry callback for adding entries on commit
 *
 * Called when any transaction is committed by consensus.
 * @param tx_hash Transaction hash
 * @param tx_type Transaction type (GENESIS, SPEND, BURN)
 * @param nullifiers Array of nullifiers
 * @param nullifier_count Number of nullifiers
 * @return 0 on success, -1 on error
 */
typedef int (*dnac_bft_ledger_add_fn)(const uint8_t *tx_hash, uint8_t tx_type,
                                       const uint8_t nullifiers[][DNAC_NULLIFIER_SIZE],
                                       uint8_t nullifier_count, void *user_data);

/**
 * @brief v0.5.0: UTXO mark spent callback for updating UTXO tree on commit
 *
 * Called when inputs are consumed by a committed transaction.
 * @param commitment_hash The UTXO commitment being spent
 * @param spent_epoch Epoch when spent
 * @return 0 on success, -1 if not found
 */
typedef int (*dnac_bft_utxo_mark_spent_fn)(const uint8_t *commitment_hash, uint64_t spent_epoch, void *user_data);

/**
 * @brief v0.8.0: UTXO set lookup callback for transaction validation
 *
 * Called during consensus to verify each input references a legitimate UTXO.
 * @param nullifier The nullifier to look up (DNAC_NULLIFIER_SIZE bytes)
 * @param amount_out Output: amount stored in this UTXO (can be NULL)
 * @param owner_out Output: owner fingerprint (DNAC_FINGERPRINT_SIZE buffer, can be NULL)
 * @return 0 if found, -1 if not found
 */
typedef int (*dnac_bft_utxo_lookup_fn)(const uint8_t *nullifier,
                                        uint64_t *amount_out,
                                        char *owner_out, void *user_data);

/**
 * @brief v0.8.0: UTXO set add callback for adding new outputs on COMMIT
 *
 * @param nullifier Derived nullifier for the new output
 * @param owner Owner's fingerprint
 * @param amount Amount in smallest units
 * @param tx_hash Creating transaction hash
 * @param index Output index within the creating TX
 * @param block_height Block height (0 for genesis)
 * @return 0 on success, -1 on error
 */
typedef int (*dnac_bft_utxo_add_fn)(const uint8_t *nullifier,
                                      const char *owner,
                                      uint64_t amount,
                                      const uint8_t *tx_hash,
                                      uint32_t index,
                                      uint64_t block_height, void *user_data);

/**
 * @brief v0.8.0: UTXO set remove callback for removing spent inputs on COMMIT
 *
 * @param nullifier Nullifier of the spent UTXO
 * @return 0 on success, -1 if not found
 */
typedef int (*dnac_bft_utxo_remove_fn)(const uint8_t *nullifier, void *user_data);

/**
 * @brief v0.8.0: UTXO set genesis callback for populating initial UTXO set
 *
 * @param genesis_tx The genesis transaction
 * @param tx_hash The genesis transaction hash
 * @return 0 on success, -1 on error
 */
typedef int (*dnac_bft_utxo_genesis_fn)(const dnac_transaction_t *genesis_tx,
                                         const uint8_t *tx_hash, void *user_data);

/**
 * @brief v0.9.0: Block creation callback
 *
 * Called after a transaction is committed via BFT consensus.
 * Creates a block wrapping the committed transaction.
 *
 * @param tx_hash Transaction hash (DNAC_TX_HASH_SIZE bytes)
 * @param tx_type Transaction type (GENESIS, SPEND, BURN)
 * @param timestamp Proposal timestamp (deterministic across witnesses)
 * @param proposer_id Leader witness ID (DNAC_BFT_WITNESS_ID_SIZE bytes)
 * @return 0 on success, -1 on error
 */
typedef int (*dnac_bft_block_create_fn)(
    const uint8_t *tx_hash, uint8_t tx_type,
    uint64_t timestamp, const uint8_t *proposer_id, void *user_data);

/**
 * @brief v0.6.0: Database transaction callbacks (Gap 11)
 *
 * Provides atomicity for multi-nullifier commits.
 */
typedef int (*dnac_bft_db_begin_fn)(void *user_data);
typedef int (*dnac_bft_db_commit_fn)(void *user_data);
typedef int (*dnac_bft_db_rollback_fn)(void *user_data);

/**
 * @brief Main BFT consensus context
 */
typedef struct dnac_bft_context {
    /* Configuration */
    dnac_bft_config_t config;

    /* v0.10.0: Zone chain ID (all-zeros = pre-genesis / default zone) */
    uint8_t chain_id[32];

    /* Identity */
    uint8_t my_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint8_t my_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t *my_privkey;                            /**< Private key (allocated) */
    size_t my_privkey_size;

    /* Roster */
    dnac_roster_t roster;
    int my_index;                                   /**< My index in roster (-1 if not in) */

    /* Current state */
    uint64_t current_round;
    uint32_t current_view;
    uint64_t last_committed_round;
    dnac_bft_round_state_t round_state;

    /* View change tracking */
    dnac_bft_view_change_record_t view_changes[DNAC_BFT_MAX_WITNESSES];
    int view_change_count;
    uint32_t view_change_target;
    bool view_change_in_progress;

    /* Synchronization */
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool running;

    /* DNA engine (for DHT operations) */
    void *dna_engine;

    /* Callbacks (set by witness application) */
    dnac_bft_nullifier_exists_fn nullifier_exists_cb;   /**< Check nullifier */
    dnac_bft_nullifier_add_fn nullifier_add_cb;         /**< Add nullifier */
    dnac_bft_send_response_fn send_response_cb;         /**< Send client response */
    dnac_bft_complete_forward_fn complete_forward_cb;   /**< Complete pending forward */
    dnac_bft_genesis_record_fn genesis_record_cb;       /**< v0.5.0: Record genesis state */
    dnac_bft_ledger_add_fn ledger_add_cb;               /**< v0.5.0: Add ledger entry */
    dnac_bft_utxo_mark_spent_fn utxo_mark_spent_cb;     /**< v0.5.0: Mark UTXO spent */
    dnac_bft_utxo_lookup_fn utxo_lookup_cb;             /**< v0.8.0: UTXO set lookup */
    dnac_bft_utxo_add_fn utxo_add_cb;                   /**< v0.8.0: UTXO set add */
    dnac_bft_utxo_remove_fn utxo_remove_cb;             /**< v0.8.0: UTXO set remove */
    dnac_bft_utxo_genesis_fn utxo_genesis_cb;           /**< v0.8.0: UTXO set genesis */
    dnac_bft_db_begin_fn db_begin_cb;                   /**< v0.6.0: Begin transaction (Gap 11) */
    dnac_bft_db_commit_fn db_commit_cb;                 /**< v0.6.0: Commit transaction (Gap 11) */
    dnac_bft_db_rollback_fn db_rollback_cb;             /**< v0.6.0: Rollback transaction (Gap 11) */
    dnac_bft_block_create_fn block_create_cb;           /**< v0.9.0: Create block on COMMIT */
    void *callback_user_data;                           /**< User data for callbacks */
} dnac_bft_context_t;

/**
 * @brief Set callbacks for BFT consensus
 *
 * v0.5.0: Added genesis_cb, ledger_cb, utxo_mark_spent_cb for full state tracking.
 */
void dnac_bft_set_callbacks(dnac_bft_context_t *ctx,
                            dnac_bft_nullifier_exists_fn exists_cb,
                            dnac_bft_nullifier_add_fn add_cb,
                            dnac_bft_send_response_fn response_cb,
                            dnac_bft_complete_forward_fn forward_cb,
                            dnac_bft_genesis_record_fn genesis_cb,
                            dnac_bft_ledger_add_fn ledger_cb,
                            dnac_bft_utxo_mark_spent_fn utxo_mark_spent_cb,
                            void *user_data);

/**
 * @brief Set database transaction callbacks (Gap 11: v0.6.0)
 *
 * These callbacks provide atomicity for multi-nullifier commits.
 */
void dnac_bft_set_db_callbacks(dnac_bft_context_t *ctx,
                                dnac_bft_db_begin_fn begin_cb,
                                dnac_bft_db_commit_fn commit_cb,
                                dnac_bft_db_rollback_fn rollback_cb);

/**
 * @brief Set UTXO set callbacks (v0.8.0)
 *
 * These callbacks allow consensus to:
 * - Verify inputs reference legitimate UTXOs (lookup)
 * - Add new output UTXOs on COMMIT (add)
 * - Remove spent UTXOs on COMMIT (remove)
 * - Populate UTXO set from genesis (genesis)
 */
void dnac_bft_set_utxo_callbacks(dnac_bft_context_t *ctx,
                                   dnac_bft_utxo_lookup_fn lookup_cb,
                                   dnac_bft_utxo_add_fn add_cb,
                                   dnac_bft_utxo_remove_fn remove_cb,
                                   dnac_bft_utxo_genesis_fn genesis_cb);

/**
 * @brief Set block creation callback (v0.9.0)
 *
 * Called after every successful BFT COMMIT to create a block.
 */
void dnac_bft_set_block_callback(dnac_bft_context_t *ctx,
                                   dnac_bft_block_create_fn cb);

/* ============================================================================
 * Core BFT Functions
 * ========================================================================== */

/**
 * @brief Create BFT context
 *
 * @param config BFT configuration
 * @param dna_engine DNA engine for DHT access
 * @return Context pointer or NULL on failure
 */
dnac_bft_context_t* dnac_bft_create(const dnac_bft_config_t *config, void *dna_engine);

/**
 * @brief Destroy BFT context
 */
void dnac_bft_destroy(dnac_bft_context_t *ctx);

/**
 * @brief Set local identity keys
 *
 * @param ctx BFT context
 * @param witness_id Witness ID (32 bytes)
 * @param pubkey Dilithium5 public key
 * @param privkey Dilithium5 private key
 * @param privkey_size Private key size
 * @return 0 on success
 */
int dnac_bft_set_identity(dnac_bft_context_t *ctx,
                          const uint8_t *witness_id,
                          const uint8_t *pubkey,
                          const uint8_t *privkey,
                          size_t privkey_size);

/**
 * @brief Get current leader index
 *
 * @param epoch Current epoch
 * @param view Current view
 * @param n_witnesses Number of witnesses
 * @return Leader index in roster
 */
int dnac_bft_get_leader_index(uint64_t epoch, uint32_t view, int n_witnesses);

/**
 * @brief Check if we are the current leader
 *
 * @param ctx BFT context
 * @return true if we are leader
 */
bool dnac_bft_is_leader(dnac_bft_context_t *ctx);

/**
 * @brief Get current quorum requirement
 *
 * @param n_witnesses Total witnesses
 * @return Quorum size (2f+1)
 */
int dnac_bft_get_quorum(int n_witnesses);

/* ============================================================================
 * Consensus Protocol Functions
 * ========================================================================== */

/**
 * @brief Start a new consensus round (leader only)
 *
 * v0.4.0: Now accepts array of nullifiers to prevent multi-input double-spend.
 * v0.5.0: Added tx_type for genesis handling (requires unanimous 3-of-3 quorum).
 * v0.8.0: Added tx_data/tx_len so validators can verify full transaction.
 *
 * @param ctx BFT context
 * @param tx_hash Transaction hash
 * @param nullifiers Array of nullifiers being spent [count][DNAC_NULLIFIER_SIZE]
 * @param nullifier_count Number of nullifiers in array
 * @param tx_type Transaction type (DNAC_TX_GENESIS, DNAC_TX_SPEND, DNAC_TX_BURN)
 * @param tx_data Full serialized transaction data
 * @param tx_len Length of serialized transaction
 * @param client_pubkey Client's public key
 * @param client_sig Client's signature
 * @param fee_amount Fee amount
 * @return 0 on success
 */
int dnac_bft_start_round(dnac_bft_context_t *ctx,
                         const uint8_t *tx_hash,
                         const uint8_t nullifiers[][DNAC_NULLIFIER_SIZE],
                         uint8_t nullifier_count,
                         uint8_t tx_type,
                         const uint8_t *tx_data,
                         uint32_t tx_len,
                         const uint8_t *client_pubkey,
                         const uint8_t *client_sig,
                         uint64_t fee_amount);

/**
 * @brief Handle received proposal (non-leader)
 *
 * @param ctx BFT context
 * @param proposal Proposal message
 * @return 0 on success
 */
int dnac_bft_handle_proposal(dnac_bft_context_t *ctx,
                             const dnac_bft_proposal_t *proposal);

/**
 * @brief Handle received vote (prevote or precommit)
 *
 * @param ctx BFT context
 * @param vote Vote message
 * @return 0 on success
 */
int dnac_bft_handle_vote(dnac_bft_context_t *ctx,
                         const dnac_bft_vote_msg_t *vote);

/**
 * @brief Handle received commit
 *
 * @param ctx BFT context
 * @param commit Commit message
 * @return 0 on success
 */
int dnac_bft_handle_commit(dnac_bft_context_t *ctx,
                           const dnac_bft_commit_t *commit);

/**
 * @brief Check for phase timeout and trigger view change if needed
 *
 * @param ctx BFT context
 * @return 0 if no timeout, 1 if view change triggered, <0 on error
 */
int dnac_bft_check_timeout(dnac_bft_context_t *ctx);

/* ============================================================================
 * View Change Functions
 * ========================================================================== */

/**
 * @brief Initiate view change
 *
 * @param ctx BFT context
 * @return 0 on success
 */
int dnac_bft_initiate_view_change(dnac_bft_context_t *ctx);

/**
 * @brief Handle view change request
 *
 * @param ctx BFT context
 * @param vc View change message
 * @return 0 on success
 */
int dnac_bft_handle_view_change(dnac_bft_context_t *ctx,
                                const dnac_bft_view_change_t *vc);

/**
 * @brief Handle new view announcement
 *
 * @param ctx BFT context
 * @param nv New view message
 * @return 0 on success
 */
int dnac_bft_handle_new_view(dnac_bft_context_t *ctx,
                             const dnac_bft_new_view_t *nv);

/* ============================================================================
 * Roster Functions
 * ========================================================================== */

/**
 * @brief Load roster from DHT
 *
 * @param ctx BFT context
 * @return 0 on success
 */
int dnac_bft_load_roster(dnac_bft_context_t *ctx);

/**
 * @brief Save roster to DHT
 *
 * @param ctx BFT context
 * @return 0 on success
 */
int dnac_bft_save_roster(dnac_bft_context_t *ctx);

/**
 * @brief Add witness to roster (requires consensus)
 *
 * @param ctx BFT context
 * @param entry New witness entry
 * @return 0 on success
 */
int dnac_bft_roster_add(dnac_bft_context_t *ctx,
                        const dnac_roster_entry_t *entry);

/**
 * @brief Find witness in roster by ID
 *
 * @param roster Roster to search
 * @param witness_id Witness ID to find
 * @return Index in roster, or -1 if not found
 */
int dnac_bft_roster_find(const dnac_roster_t *roster,
                         const uint8_t *witness_id);

/**
 * @brief Initialize empty roster
 */
int dnac_bft_roster_init(dnac_roster_t *roster);

/**
 * @brief Initialize roster with self as first entry
 */
int dnac_bft_roster_init_with_self(dnac_roster_t *roster,
                                   const uint8_t *witness_id,
                                   const uint8_t *pubkey,
                                   const char *address);

/**
 * @brief Load roster from DHT
 */
int dnac_bft_roster_load_from_dht(dnac_bft_context_t *ctx);

/**
 * @brief Save roster to DHT
 */
int dnac_bft_roster_save_to_dht(dnac_bft_context_t *ctx);

/**
 * @brief Add witness to roster
 */
int dnac_bft_roster_add_witness(dnac_bft_context_t *ctx,
                                const uint8_t *witness_id,
                                const uint8_t *pubkey,
                                const char *address);

/**
 * @brief Get roster entry by index
 */
const dnac_roster_entry_t* dnac_bft_roster_get_entry(const dnac_roster_t *roster,
                                                      int index);

/**
 * @brief Client function to discover roster from DHT
 */
int dnac_bft_client_discover_roster(void *dna_engine, dnac_roster_t *roster_out);

/* ============================================================================
 * Serialization Functions
 * ========================================================================== */

/**
 * @brief Serialize BFT message header
 */
int dnac_bft_header_serialize(const dnac_bft_msg_header_t *header,
                              uint8_t *buffer, size_t buffer_len,
                              size_t *written);

/**
 * @brief Deserialize BFT message header
 */
int dnac_bft_header_deserialize(const uint8_t *buffer, size_t buffer_len,
                                dnac_bft_msg_header_t *header);

/**
 * @brief Serialize proposal message
 */
int dnac_bft_proposal_serialize(const dnac_bft_proposal_t *proposal,
                                uint8_t *buffer, size_t buffer_len,
                                size_t *written);

/**
 * @brief Deserialize proposal message
 */
int dnac_bft_proposal_deserialize(const uint8_t *buffer, size_t buffer_len,
                                  dnac_bft_proposal_t *proposal);

/**
 * @brief Serialize vote message
 */
int dnac_bft_vote_serialize(const dnac_bft_vote_msg_t *vote,
                            uint8_t *buffer, size_t buffer_len,
                            size_t *written);

/**
 * @brief Deserialize vote message
 */
int dnac_bft_vote_deserialize(const uint8_t *buffer, size_t buffer_len,
                              dnac_bft_vote_msg_t *vote);

/**
 * @brief Serialize commit message
 */
int dnac_bft_commit_serialize(const dnac_bft_commit_t *commit,
                              uint8_t *buffer, size_t buffer_len,
                              size_t *written);

/**
 * @brief Deserialize commit message
 */
int dnac_bft_commit_deserialize(const uint8_t *buffer, size_t buffer_len,
                                dnac_bft_commit_t *commit);

/**
 * @brief Serialize view change message
 */
int dnac_bft_view_change_serialize(const dnac_bft_view_change_t *vc,
                                   uint8_t *buffer, size_t buffer_len,
                                   size_t *written);

/**
 * @brief Deserialize view change message
 */
int dnac_bft_view_change_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_bft_view_change_t *vc);

/**
 * @brief Serialize NEW-VIEW message (Gap 6: v0.6.0)
 */
int dnac_bft_new_view_serialize(const dnac_bft_new_view_t *nv,
                                 uint8_t *buffer, size_t buffer_len,
                                 size_t *written);

/**
 * @brief Deserialize NEW-VIEW message (Gap 6: v0.6.0)
 */
int dnac_bft_new_view_deserialize(const uint8_t *buffer, size_t buffer_len,
                                   dnac_bft_new_view_t *nv);

/**
 * @brief Serialize roster
 */
int dnac_bft_roster_serialize(const dnac_roster_t *roster,
                              uint8_t *buffer, size_t buffer_len,
                              size_t *written);

/**
 * @brief Deserialize roster
 */
int dnac_bft_roster_deserialize(const uint8_t *buffer, size_t buffer_len,
                                dnac_roster_t *roster);

/**
 * @brief Serialize forward request
 */
int dnac_bft_forward_req_serialize(const dnac_bft_forward_req_t *req,
                                   uint8_t *buffer, size_t buffer_len,
                                   size_t *written);

/**
 * @brief Deserialize forward request
 */
int dnac_bft_forward_req_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_bft_forward_req_t *req);

/**
 * @brief Serialize forward response
 */
int dnac_bft_forward_rsp_serialize(const dnac_bft_forward_rsp_t *rsp,
                                   uint8_t *buffer, size_t buffer_len,
                                   size_t *written);

/**
 * @brief Deserialize forward response
 */
int dnac_bft_forward_rsp_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_bft_forward_rsp_t *rsp);

/**
 * @brief Get message type from buffer
 */
dnac_bft_msg_type_t dnac_bft_get_msg_type(const uint8_t *buffer, size_t buffer_len);

/**
 * @brief Get serialized size of message
 */
size_t dnac_bft_msg_size(dnac_bft_msg_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_BFT_H */
