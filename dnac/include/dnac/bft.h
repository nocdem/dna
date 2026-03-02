/**
 * @file bft.h
 * @brief DNAC BFT (Byzantine Fault Tolerant) Consensus Types & Serialization
 *
 * Message types, roster management, and serialization for BFT consensus.
 * The consensus state machine runs inside nodus-server (nodus/src/witness/).
 * This header defines the wire format types used by both sides.
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

typedef enum {
    BFT_MSG_PROPOSAL        = 1,
    BFT_MSG_PREVOTE         = 2,
    BFT_MSG_PRECOMMIT       = 3,
    BFT_MSG_COMMIT          = 4,
    BFT_MSG_VIEW_CHANGE     = 5,
    BFT_MSG_NEW_VIEW        = 6,
    BFT_MSG_FORWARD_REQ     = 7,
    BFT_MSG_FORWARD_RSP     = 8,
    BFT_MSG_ROSTER_REQUEST  = 9,
    BFT_MSG_ROSTER_RESPONSE = 10,
    BFT_MSG_IDENTIFY        = 11,
} dnac_bft_msg_type_t;

typedef enum {
    BFT_VOTE_APPROVE        = 0,
    BFT_VOTE_REJECT         = 1,
} dnac_bft_vote_t;

typedef enum {
    BFT_PHASE_IDLE          = 0,
    BFT_PHASE_PROPOSE       = 1,
    BFT_PHASE_PREVOTE       = 2,
    BFT_PHASE_PRECOMMIT     = 3,
    BFT_PHASE_COMMIT        = 4,
    BFT_PHASE_VIEW_CHANGE   = 5,
} dnac_bft_phase_t;

/* ============================================================================
 * Configuration
 * ========================================================================== */

typedef struct {
    uint32_t n_witnesses;
    uint32_t f_tolerance;           /* (n-1)/3 */
    uint32_t quorum;                /* 2f+1 */
    uint32_t round_timeout_ms;
    uint32_t view_change_timeout_ms;
    uint32_t max_view_changes;
    uint16_t tcp_port;              /* Unused (witness runs inside nodus-server) */
} dnac_bft_config_t;

void dnac_bft_config_init(dnac_bft_config_t *config, uint32_t n_witnesses);

/* ============================================================================
 * Roster Types
 * ========================================================================== */

typedef struct {
    uint8_t witness_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint8_t pubkey[DNAC_PUBKEY_SIZE];
    char address[DNAC_BFT_MAX_ADDRESS_LEN];
    uint64_t joined_epoch;
    bool active;
} dnac_roster_entry_t;

typedef struct {
    uint32_t version;
    uint32_t n_witnesses;
    dnac_roster_entry_t witnesses[DNAC_BFT_MAX_WITNESSES];
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_roster_t;

/* ============================================================================
 * BFT Messages (wire format types used by serialization)
 * ========================================================================== */

typedef struct {
    uint8_t version;
    dnac_bft_msg_type_t type;
    uint64_t round;
    uint32_t view;
    uint8_t sender_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint64_t timestamp;
    uint64_t nonce;
    uint8_t chain_id[32];
} dnac_bft_msg_header_t;

typedef struct {
    dnac_bft_msg_header_t header;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE];
    uint8_t nullifier_count;
    uint8_t tx_type;
    uint8_t tx_data[DNAC_BFT_MAX_TX_SIZE];
    uint32_t tx_len;
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t client_signature[DNAC_SIGNATURE_SIZE];
    uint64_t fee_amount;
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_proposal_t;

typedef struct {
    dnac_bft_msg_header_t header;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    dnac_bft_vote_t vote;
    char reason[256];
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_vote_msg_t;

typedef struct {
    dnac_bft_msg_header_t header;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE];
    uint8_t nullifier_count;
    uint8_t tx_type;
    uint8_t tx_data[DNAC_BFT_MAX_TX_SIZE];
    uint32_t tx_len;
    uint64_t proposal_timestamp;
    uint8_t proposer_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint32_t n_precommits;
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_commit_t;

typedef struct {
    dnac_bft_msg_header_t header;
    uint32_t new_view;
    uint64_t last_committed_round;
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_view_change_t;

typedef struct {
    dnac_bft_msg_header_t header;
    uint32_t new_view;
    uint32_t n_view_change_proofs;
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_new_view_t;

typedef struct {
    dnac_bft_msg_header_t header;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t tx_data[DNAC_BFT_MAX_TX_SIZE];
    uint32_t tx_len;
    uint8_t sender_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t client_signature[DNAC_SIGNATURE_SIZE];
    uint64_t fee_amount;
    uint8_t forwarder_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_forward_req_t;

typedef struct {
    dnac_bft_msg_header_t header;
    int status;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    dnac_witness_sig_t witnesses[DNAC_TX_MAX_WITNESSES];
    int witness_count;
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_forward_rsp_t;

/* ============================================================================
 * Consensus Context (used by roster management)
 * ========================================================================== */

typedef struct {
    uint8_t voter_id[DNAC_BFT_WITNESS_ID_SIZE];
    dnac_bft_vote_t vote;
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_vote_record_t;

typedef struct {
    uint64_t round;
    uint32_t view;
    dnac_bft_phase_t phase;
    uint8_t tx_hash[DNAC_TX_HASH_SIZE];
    uint8_t nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE];
    uint8_t nullifier_count;
    uint8_t tx_type;
    uint8_t tx_data[DNAC_BFT_MAX_TX_SIZE];
    uint32_t tx_len;
    dnac_bft_vote_record_t prevotes[DNAC_BFT_MAX_WITNESSES];
    int prevote_count;
    int prevote_approve_count;
    dnac_bft_vote_record_t precommits[DNAC_BFT_MAX_WITNESSES];
    int precommit_count;
    int precommit_approve_count;
    uint64_t phase_start_time;
    uint64_t proposal_timestamp;
    uint8_t  proposer_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint8_t client_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t client_signature[DNAC_SIGNATURE_SIZE];
    uint64_t fee_amount;
    bool is_forwarded;
    uint8_t forwarder_id[DNAC_BFT_WITNESS_ID_SIZE];
    int forwarder_fd;
    int client_fd;
} dnac_bft_round_state_t;

typedef struct {
    uint32_t target_view;
    uint8_t voter_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint64_t last_committed_round;
    uint8_t signature[DNAC_SIGNATURE_SIZE];
} dnac_bft_view_change_record_t;

/* Callback typedefs (used by context struct, implementations in nodus witness) */
typedef bool (*dnac_bft_nullifier_exists_fn)(const uint8_t *nullifier, void *user_data);
typedef int (*dnac_bft_nullifier_add_fn)(const uint8_t *nullifier, const uint8_t *tx_hash, void *user_data);
typedef void (*dnac_bft_send_response_fn)(int client_fd, int status, const char *error_msg, void *user_data);
typedef int (*dnac_bft_complete_forward_fn)(const uint8_t *tx_hash, const uint8_t *witness_id,
                                            const uint8_t *pubkey, void *user_data);
typedef int (*dnac_bft_genesis_record_fn)(const uint8_t *tx_hash, uint64_t total_supply,
                                          const uint8_t *commitment, void *user_data);
typedef int (*dnac_bft_ledger_add_fn)(const uint8_t *tx_hash, uint8_t tx_type,
                                       const uint8_t nullifiers[][DNAC_NULLIFIER_SIZE],
                                       uint8_t nullifier_count, void *user_data);
typedef int (*dnac_bft_utxo_mark_spent_fn)(const uint8_t *commitment_hash, uint64_t spent_epoch, void *user_data);
typedef int (*dnac_bft_utxo_lookup_fn)(const uint8_t *nullifier, uint64_t *amount_out,
                                        char *owner_out, void *user_data);
typedef int (*dnac_bft_utxo_add_fn)(const uint8_t *nullifier, const char *owner, uint64_t amount,
                                      const uint8_t *tx_hash, uint32_t index,
                                      uint64_t block_height, void *user_data);
typedef int (*dnac_bft_utxo_remove_fn)(const uint8_t *nullifier, void *user_data);
typedef int (*dnac_bft_utxo_genesis_fn)(const dnac_transaction_t *genesis_tx,
                                         const uint8_t *tx_hash, void *user_data);
typedef int (*dnac_bft_block_create_fn)(const uint8_t *tx_hash, uint8_t tx_type,
                                         uint64_t timestamp, const uint8_t *proposer_id, void *user_data);
typedef int (*dnac_bft_db_begin_fn)(void *user_data);
typedef int (*dnac_bft_db_commit_fn)(void *user_data);
typedef int (*dnac_bft_db_rollback_fn)(void *user_data);

typedef struct dnac_bft_context {
    dnac_bft_config_t config;
    uint8_t chain_id[32];
    uint8_t my_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint8_t my_pubkey[DNAC_PUBKEY_SIZE];
    uint8_t *my_privkey;
    size_t my_privkey_size;
    dnac_roster_t roster;
    int my_index;
    uint64_t current_round;
    uint32_t current_view;
    uint64_t last_committed_round;
    dnac_bft_round_state_t round_state;
    dnac_bft_view_change_record_t view_changes[DNAC_BFT_MAX_WITNESSES];
    int view_change_count;
    uint32_t view_change_target;
    bool view_change_in_progress;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    bool running;
    void *dna_engine;
    dnac_bft_nullifier_exists_fn nullifier_exists_cb;
    dnac_bft_nullifier_add_fn nullifier_add_cb;
    dnac_bft_send_response_fn send_response_cb;
    dnac_bft_complete_forward_fn complete_forward_cb;
    dnac_bft_genesis_record_fn genesis_record_cb;
    dnac_bft_ledger_add_fn ledger_add_cb;
    dnac_bft_utxo_mark_spent_fn utxo_mark_spent_cb;
    dnac_bft_utxo_lookup_fn utxo_lookup_cb;
    dnac_bft_utxo_add_fn utxo_add_cb;
    dnac_bft_utxo_remove_fn utxo_remove_cb;
    dnac_bft_utxo_genesis_fn utxo_genesis_cb;
    dnac_bft_db_begin_fn db_begin_cb;
    dnac_bft_db_commit_fn db_commit_cb;
    dnac_bft_db_rollback_fn db_rollback_cb;
    dnac_bft_block_create_fn block_create_cb;
    void *callback_user_data;
} dnac_bft_context_t;

/* ============================================================================
 * Leader Election & Quorum
 * ========================================================================== */

int dnac_bft_get_leader_index(uint64_t epoch, uint32_t view, int n_witnesses);
int dnac_bft_get_quorum(int n_witnesses);

/* ============================================================================
 * Replay Prevention (bft/replay.c)
 * ========================================================================== */

bool is_replay(const uint8_t *sender_id, uint64_t nonce, uint64_t timestamp);
uint64_t dnac_bft_generate_nonce(void);

/* ============================================================================
 * Roster Functions (bft/roster.c)
 * ========================================================================== */

int dnac_bft_roster_init(dnac_roster_t *roster);
int dnac_bft_roster_init_with_self(dnac_roster_t *roster,
                                   const uint8_t *witness_id,
                                   const uint8_t *pubkey,
                                   const char *address);
int dnac_bft_roster_find(const dnac_roster_t *roster, const uint8_t *witness_id);
int dnac_bft_roster_load_from_dht(dnac_bft_context_t *ctx);
int dnac_bft_roster_save_to_dht(dnac_bft_context_t *ctx);
int dnac_bft_roster_add_witness(dnac_bft_context_t *ctx,
                                const uint8_t *witness_id,
                                const uint8_t *pubkey,
                                const char *address);
const dnac_roster_entry_t* dnac_bft_roster_get_entry(const dnac_roster_t *roster, int index);
int dnac_bft_client_discover_roster(void *dna_engine, dnac_roster_t *roster_out);

/* ============================================================================
 * Serialization Functions (bft/serialize.c)
 * ========================================================================== */

int dnac_bft_header_serialize(const dnac_bft_msg_header_t *header,
                              uint8_t *buffer, size_t buffer_len, size_t *written);
int dnac_bft_header_deserialize(const uint8_t *buffer, size_t buffer_len,
                                dnac_bft_msg_header_t *header);

int dnac_bft_proposal_serialize(const dnac_bft_proposal_t *proposal,
                                uint8_t *buffer, size_t buffer_len, size_t *written);
int dnac_bft_proposal_deserialize(const uint8_t *buffer, size_t buffer_len,
                                  dnac_bft_proposal_t *proposal);

int dnac_bft_vote_serialize(const dnac_bft_vote_msg_t *vote,
                            uint8_t *buffer, size_t buffer_len, size_t *written);
int dnac_bft_vote_deserialize(const uint8_t *buffer, size_t buffer_len,
                              dnac_bft_vote_msg_t *vote);

int dnac_bft_commit_serialize(const dnac_bft_commit_t *commit,
                              uint8_t *buffer, size_t buffer_len, size_t *written);
int dnac_bft_commit_deserialize(const uint8_t *buffer, size_t buffer_len,
                                dnac_bft_commit_t *commit);

int dnac_bft_view_change_serialize(const dnac_bft_view_change_t *vc,
                                   uint8_t *buffer, size_t buffer_len, size_t *written);
int dnac_bft_view_change_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_bft_view_change_t *vc);

int dnac_bft_new_view_serialize(const dnac_bft_new_view_t *nv,
                                 uint8_t *buffer, size_t buffer_len, size_t *written);
int dnac_bft_new_view_deserialize(const uint8_t *buffer, size_t buffer_len,
                                   dnac_bft_new_view_t *nv);

int dnac_bft_roster_serialize(const dnac_roster_t *roster,
                              uint8_t *buffer, size_t buffer_len, size_t *written);
int dnac_bft_roster_deserialize(const uint8_t *buffer, size_t buffer_len,
                                dnac_roster_t *roster);

int dnac_bft_forward_req_serialize(const dnac_bft_forward_req_t *req,
                                   uint8_t *buffer, size_t buffer_len, size_t *written);
int dnac_bft_forward_req_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_bft_forward_req_t *req);

int dnac_bft_forward_rsp_serialize(const dnac_bft_forward_rsp_t *rsp,
                                   uint8_t *buffer, size_t buffer_len, size_t *written);
int dnac_bft_forward_rsp_deserialize(const uint8_t *buffer, size_t buffer_len,
                                     dnac_bft_forward_rsp_t *rsp);

dnac_bft_msg_type_t dnac_bft_get_msg_type(const uint8_t *buffer, size_t buffer_len);
size_t dnac_bft_msg_size(dnac_bft_msg_type_t type);

#ifdef __cplusplus
}
#endif

#endif /* DNAC_BFT_H */
