/**
 * @file consensus.c
 * @brief BFT Consensus State Machine
 *
 * Implements the PBFT-like consensus protocol:
 * - Leader election: (epoch + view) % N
 * - 4-phase consensus: PROPOSE → PREVOTE → PRECOMMIT → COMMIT
 * - View change on leader timeout
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dnac/bft.h"
#include "dnac/tcp.h"
#include "dnac/genesis.h"
#include "dnac/transaction.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_dilithium.h"
#include "crypto/utils/qgp_random.h"

#define LOG_TAG "BFT_CONSENSUS"

/* ============================================================================
 * Gap 23-24 Fix (v0.6.0): Nonce-based replay prevention
 * ========================================================================== */

/* Nonce cache for replay detection */
#define NONCE_CACHE_SIZE 1000
#define NONCE_CACHE_TTL_SECS 300  /* 5 minutes */

typedef struct {
    uint8_t sender_id[DNAC_BFT_WITNESS_ID_SIZE];
    uint64_t nonce;
    uint64_t timestamp;
} nonce_entry_t;

static nonce_entry_t g_nonce_cache[NONCE_CACHE_SIZE];
static int g_nonce_cache_count = 0;
static pthread_mutex_t g_nonce_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * Generate a random nonce for message headers
 */
static uint64_t generate_nonce(void) {
    uint64_t nonce = 0;
    if (qgp_randombytes((uint8_t*)&nonce, sizeof(nonce)) != 0) {
        /* Fallback to timestamp-based nonce if random fails */
        nonce = (uint64_t)time(NULL) ^ ((uint64_t)rand() << 32);
    }
    return nonce;
}

/**
 * Check if message is a replay (already seen nonce from sender)
 * Returns true if replay detected, false if new message
 * NOTE: Exposed (non-static) for unit testing
 */
bool is_replay(const uint8_t *sender_id, uint64_t nonce, uint64_t timestamp) {
    uint64_t now = (uint64_t)time(NULL);

    /* Reject if timestamp too old (>5 minutes) or too far in future (>1 minute) */
    if (timestamp < now - NONCE_CACHE_TTL_SECS || timestamp > now + 60) {
        QGP_LOG_WARN(LOG_TAG, "Replay check: timestamp out of range (ts=%llu, now=%llu)",
                     (unsigned long long)timestamp, (unsigned long long)now);
        return true;
    }

    pthread_mutex_lock(&g_nonce_mutex);

    /* Check nonce cache */
    for (int i = 0; i < g_nonce_cache_count; i++) {
        if (memcmp(g_nonce_cache[i].sender_id, sender_id, DNAC_BFT_WITNESS_ID_SIZE) == 0 &&
            g_nonce_cache[i].nonce == nonce) {
            pthread_mutex_unlock(&g_nonce_mutex);
            QGP_LOG_WARN(LOG_TAG, "Replay detected: duplicate nonce from %.8s", sender_id);
            return true;  /* Duplicate nonce = replay */
        }
    }

    /* Evict old entries */
    int write_idx = 0;
    for (int i = 0; i < g_nonce_cache_count; i++) {
        if (now - g_nonce_cache[i].timestamp < NONCE_CACHE_TTL_SECS) {
            if (write_idx != i) {
                g_nonce_cache[write_idx] = g_nonce_cache[i];
            }
            write_idx++;
        }
    }
    g_nonce_cache_count = write_idx;

    /* Add to cache (circular if full) */
    int idx = g_nonce_cache_count;
    if (idx >= NONCE_CACHE_SIZE) {
        idx = 0;  /* Overwrite oldest */
    } else {
        g_nonce_cache_count++;
    }
    memcpy(g_nonce_cache[idx].sender_id, sender_id, DNAC_BFT_WITNESS_ID_SIZE);
    g_nonce_cache[idx].nonce = nonce;
    g_nonce_cache[idx].timestamp = timestamp;

    pthread_mutex_unlock(&g_nonce_mutex);
    return false;
}

/* External peer functions */
extern int bft_peer_broadcast(const uint8_t *data, size_t len, int exclude_roster_index);
extern int bft_peer_send_to_leader(const uint8_t *data, size_t len);
extern int bft_peer_send_to(int roster_index, const uint8_t *data, size_t len);

/* Helper functions that use callbacks */
/* Fail-safe callback wrappers (Gap 10: v0.6.0)
 * These MUST fail closed when callbacks are not set to prevent double-spend. */
static bool nullifier_exists(dnac_bft_context_t *ctx, const uint8_t *nullifier) {
    if (!ctx || !ctx->nullifier_exists_cb) {
        QGP_LOG_ERROR(LOG_TAG, "CRITICAL: nullifier_exists_cb not set - fail safe");
        return true;  /* Fail safe: assume exists to prevent double-spend */
    }
    return ctx->nullifier_exists_cb(nullifier, ctx->callback_user_data);
}

static int nullifier_add(dnac_bft_context_t *ctx, const uint8_t *nullifier, const uint8_t *tx_hash) {
    if (!ctx || !ctx->nullifier_add_cb) {
        QGP_LOG_ERROR(LOG_TAG, "CRITICAL: nullifier_add_cb not set - fail safe");
        return -1;  /* Fail: cannot commit without storage */
    }
    return ctx->nullifier_add_cb(nullifier, tx_hash, ctx->callback_user_data);
}

static void send_client_response(dnac_bft_context_t *ctx, int client_fd, int status, const char *error_msg) {
    if (ctx && ctx->send_response_cb) {
        ctx->send_response_cb(client_fd, status, error_msg, ctx->callback_user_data);
    }
}

/**
 * @brief Sign BFT message data with Dilithium5
 *
 * Signs arbitrary data using the context's private key.
 *
 * @param ctx BFT context with private key
 * @param signature Output buffer for signature (DNAC_SIGNATURE_SIZE bytes)
 * @param data Data to sign
 * @param data_len Length of data
 * @return 0 on success, -1 on error
 */
static int bft_sign_message(dnac_bft_context_t *ctx, uint8_t *signature,
                            const uint8_t *data, size_t data_len) {
    if (!ctx || !signature || !data) {
        return -1;
    }

    if (!ctx->my_privkey || ctx->my_privkey_size == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No private key available for signing");
        return -1;
    }

    size_t sig_len = 0;
    int rc = qgp_dsa87_sign(signature, &sig_len, data, data_len, ctx->my_privkey);
    if (rc != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Dilithium5 signing failed: %d", rc);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Signed BFT message (data_len=%zu, sig_len=%zu)", data_len, sig_len);
    return 0;
}

/**
 * @brief Build proposal signing data
 *
 * Signs: tx_hash || sender_id || round || view || nullifier_count || tx_type || timestamp
 */
static int bft_build_proposal_sign_data(const dnac_bft_proposal_t *proposal,
                                         uint8_t *sign_data, size_t *sign_data_len) {
    if (!proposal || !sign_data || !sign_data_len) return -1;

    size_t offset = 0;

    /* tx_hash (64 bytes) */
    memcpy(sign_data + offset, proposal->tx_hash, DNAC_TX_HASH_SIZE);
    offset += DNAC_TX_HASH_SIZE;

    /* sender_id (32 bytes) */
    memcpy(sign_data + offset, proposal->header.sender_id, DNAC_BFT_WITNESS_ID_SIZE);
    offset += DNAC_BFT_WITNESS_ID_SIZE;

    /* round (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        sign_data[offset + i] = (proposal->header.round >> (i * 8)) & 0xFF;
    }
    offset += 8;

    /* view (4 bytes, little-endian) */
    for (int i = 0; i < 4; i++) {
        sign_data[offset + i] = (proposal->header.view >> (i * 8)) & 0xFF;
    }
    offset += 4;

    /* nullifier_count (1 byte) */
    sign_data[offset++] = proposal->nullifier_count;

    /* tx_type (1 byte) */
    sign_data[offset++] = proposal->tx_type;

    /* timestamp (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        sign_data[offset + i] = (proposal->header.timestamp >> (i * 8)) & 0xFF;
    }
    offset += 8;

    /* v0.10.0: chain_id (32 bytes) — prevents cross-zone replay */
    memcpy(sign_data + offset, proposal->header.chain_id, 32);
    offset += 32;

    *sign_data_len = offset;
    return 0;
}

/**
 * @brief Build vote signing data
 *
 * Signs: tx_hash || sender_id || round || view || vote || timestamp || chain_id
 */
static int bft_build_vote_sign_data(const dnac_bft_vote_msg_t *vote,
                                     uint8_t *sign_data, size_t *sign_data_len) {
    if (!vote || !sign_data || !sign_data_len) return -1;

    size_t offset = 0;

    /* tx_hash (64 bytes) */
    memcpy(sign_data + offset, vote->tx_hash, DNAC_TX_HASH_SIZE);
    offset += DNAC_TX_HASH_SIZE;

    /* sender_id (32 bytes) */
    memcpy(sign_data + offset, vote->header.sender_id, DNAC_BFT_WITNESS_ID_SIZE);
    offset += DNAC_BFT_WITNESS_ID_SIZE;

    /* round (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        sign_data[offset + i] = (vote->header.round >> (i * 8)) & 0xFF;
    }
    offset += 8;

    /* view (4 bytes, little-endian) */
    for (int i = 0; i < 4; i++) {
        sign_data[offset + i] = (vote->header.view >> (i * 8)) & 0xFF;
    }
    offset += 4;

    /* vote (1 byte) */
    sign_data[offset++] = (uint8_t)vote->vote;

    /* timestamp (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        sign_data[offset + i] = (vote->header.timestamp >> (i * 8)) & 0xFF;
    }
    offset += 8;

    /* v0.10.0: chain_id (32 bytes) — prevents cross-zone replay */
    memcpy(sign_data + offset, vote->header.chain_id, 32);
    offset += 32;

    *sign_data_len = offset;
    return 0;
}

/**
 * @brief Build view change signing data
 *
 * Signs: sender_id || round || view || new_view || last_committed_round || timestamp || chain_id
 */
static int bft_build_view_change_sign_data(const dnac_bft_view_change_t *vc,
                                            uint8_t *sign_data, size_t *sign_data_len) {
    if (!vc || !sign_data || !sign_data_len) return -1;

    size_t offset = 0;

    /* sender_id (32 bytes) */
    memcpy(sign_data + offset, vc->header.sender_id, DNAC_BFT_WITNESS_ID_SIZE);
    offset += DNAC_BFT_WITNESS_ID_SIZE;

    /* round (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        sign_data[offset + i] = (vc->header.round >> (i * 8)) & 0xFF;
    }
    offset += 8;

    /* view (4 bytes, little-endian) */
    for (int i = 0; i < 4; i++) {
        sign_data[offset + i] = (vc->header.view >> (i * 8)) & 0xFF;
    }
    offset += 4;

    /* new_view (4 bytes, little-endian) */
    for (int i = 0; i < 4; i++) {
        sign_data[offset + i] = (vc->new_view >> (i * 8)) & 0xFF;
    }
    offset += 4;

    /* last_committed_round (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        sign_data[offset + i] = (vc->last_committed_round >> (i * 8)) & 0xFF;
    }
    offset += 8;

    /* timestamp (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        sign_data[offset + i] = (vc->header.timestamp >> (i * 8)) & 0xFF;
    }
    offset += 8;

    /* v0.10.0: chain_id (32 bytes) — prevents cross-zone replay */
    memcpy(sign_data + offset, vc->header.chain_id, 32);
    offset += 32;

    *sign_data_len = offset;
    return 0;
}

/**
 * @brief Verify BFT message signature with Dilithium5 (Gap 2, 4: v0.6.0)
 *
 * Verifies signature using the sender's public key from roster.
 *
 * @param ctx BFT context with roster
 * @param sender_id Sender's witness ID (to lookup pubkey in roster)
 * @param signature Signature to verify (DNAC_SIGNATURE_SIZE bytes)
 * @param data Data that was signed
 * @param data_len Length of data
 * @return 0 on success, -1 on error (invalid signature or sender not in roster)
 */
static int bft_verify_signature(dnac_bft_context_t *ctx, const uint8_t *sender_id,
                                 const uint8_t *signature, const uint8_t *data, size_t data_len) {
    if (!ctx || !sender_id || !signature || !data) {
        return -1;
    }

    /* Find sender in roster */
    int sender_idx = dnac_bft_roster_find(&ctx->roster, sender_id);
    if (sender_idx < 0) {
        QGP_LOG_WARN(LOG_TAG, "Sender not found in roster");
        return -1;
    }

    /* Get sender's public key */
    const uint8_t *pubkey = ctx->roster.witnesses[sender_idx].pubkey;

    /* Verify signature */
    int rc = qgp_dsa87_verify(signature, DNAC_SIGNATURE_SIZE, data, data_len, pubkey);
    if (rc != 0) {
        QGP_LOG_WARN(LOG_TAG, "Signature verification failed for sender idx %d", sender_idx);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Signature verified for sender idx %d", sender_idx);
    return 0;
}

/**
 * @brief Verify proposal signature (Gap 2: v0.6.0)
 */
static int bft_verify_proposal_signature(dnac_bft_context_t *ctx,
                                          const dnac_bft_proposal_t *proposal) {
    uint8_t sign_data[256];
    size_t sign_len;

    if (bft_build_proposal_sign_data(proposal, sign_data, &sign_len) != 0) {
        return -1;
    }

    return bft_verify_signature(ctx, proposal->header.sender_id,
                                 proposal->signature, sign_data, sign_len);
}

/**
 * @brief Verify vote signature (Gap 4: v0.6.0)
 */
static int bft_verify_vote_signature(dnac_bft_context_t *ctx,
                                      const dnac_bft_vote_msg_t *vote) {
    uint8_t sign_data[256];
    size_t sign_len;

    if (bft_build_vote_sign_data(vote, sign_data, &sign_len) != 0) {
        return -1;
    }

    return bft_verify_signature(ctx, vote->header.sender_id,
                                 vote->signature, sign_data, sign_len);
}

/**
 * @brief Verify view change signature (used by handle_view_change)
 */
static int bft_verify_view_change_signature(dnac_bft_context_t *ctx,
                                             const dnac_bft_view_change_t *vc) {
    uint8_t sign_data[256];
    size_t sign_len;

    if (bft_build_view_change_sign_data(vc, sign_data, &sign_len) != 0) {
        return -1;
    }

    return bft_verify_signature(ctx, vc->header.sender_id,
                                 vc->signature, sign_data, sign_len);
}

/**
 * @brief Build NEW-VIEW signing data (Gap 6: v0.6.0)
 *
 * Signs: sender_id || round || view || new_view || n_proofs || timestamp
 */
static int bft_build_new_view_sign_data(const dnac_bft_new_view_t *nv,
                                         uint8_t *sign_data, size_t *sign_data_len) {
    if (!nv || !sign_data || !sign_data_len) return -1;

    size_t offset = 0;

    /* sender_id (32 bytes) */
    memcpy(sign_data + offset, nv->header.sender_id, DNAC_BFT_WITNESS_ID_SIZE);
    offset += DNAC_BFT_WITNESS_ID_SIZE;

    /* round (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        sign_data[offset + i] = (nv->header.round >> (i * 8)) & 0xFF;
    }
    offset += 8;

    /* view (4 bytes, little-endian) */
    for (int i = 0; i < 4; i++) {
        sign_data[offset + i] = (nv->header.view >> (i * 8)) & 0xFF;
    }
    offset += 4;

    /* new_view (4 bytes, little-endian) */
    for (int i = 0; i < 4; i++) {
        sign_data[offset + i] = (nv->new_view >> (i * 8)) & 0xFF;
    }
    offset += 4;

    /* n_view_change_proofs (4 bytes, little-endian) */
    for (int i = 0; i < 4; i++) {
        sign_data[offset + i] = (nv->n_view_change_proofs >> (i * 8)) & 0xFF;
    }
    offset += 4;

    /* timestamp (8 bytes, little-endian) */
    for (int i = 0; i < 8; i++) {
        sign_data[offset + i] = (nv->header.timestamp >> (i * 8)) & 0xFF;
    }
    offset += 8;

    /* v0.10.0: chain_id (32 bytes) — prevents cross-zone replay */
    memcpy(sign_data + offset, nv->header.chain_id, 32);
    offset += 32;

    *sign_data_len = offset;
    return 0;
}

/* ============================================================================
 * Callback Setup
 * ========================================================================== */

void dnac_bft_set_callbacks(dnac_bft_context_t *ctx,
                            dnac_bft_nullifier_exists_fn exists_cb,
                            dnac_bft_nullifier_add_fn add_cb,
                            dnac_bft_send_response_fn response_cb,
                            dnac_bft_complete_forward_fn forward_cb,
                            dnac_bft_genesis_record_fn genesis_cb,
                            dnac_bft_ledger_add_fn ledger_cb,
                            dnac_bft_utxo_mark_spent_fn utxo_mark_spent_cb,
                            void *user_data) {
    if (!ctx) return;
    ctx->nullifier_exists_cb = exists_cb;
    ctx->nullifier_add_cb = add_cb;
    ctx->send_response_cb = response_cb;
    ctx->complete_forward_cb = forward_cb;
    ctx->genesis_record_cb = genesis_cb;
    ctx->ledger_add_cb = ledger_cb;
    ctx->utxo_mark_spent_cb = utxo_mark_spent_cb;
    ctx->callback_user_data = user_data;
}

void dnac_bft_set_db_callbacks(dnac_bft_context_t *ctx,
                                dnac_bft_db_begin_fn begin_cb,
                                dnac_bft_db_commit_fn commit_cb,
                                dnac_bft_db_rollback_fn rollback_cb) {
    if (!ctx) return;
    ctx->db_begin_cb = begin_cb;
    ctx->db_commit_cb = commit_cb;
    ctx->db_rollback_cb = rollback_cb;
}

void dnac_bft_set_utxo_callbacks(dnac_bft_context_t *ctx,
                                   dnac_bft_utxo_lookup_fn lookup_cb,
                                   dnac_bft_utxo_add_fn add_cb,
                                   dnac_bft_utxo_remove_fn remove_cb,
                                   dnac_bft_utxo_genesis_fn genesis_cb) {
    if (!ctx) return;
    ctx->utxo_lookup_cb = lookup_cb;
    ctx->utxo_add_cb = add_cb;
    ctx->utxo_remove_cb = remove_cb;
    ctx->utxo_genesis_cb = genesis_cb;
}

void dnac_bft_set_block_callback(dnac_bft_context_t *ctx,
                                   dnac_bft_block_create_fn cb) {
    if (!ctx) return;
    ctx->block_create_cb = cb;
}

/* ============================================================================
 * Configuration
 * ========================================================================== */

void dnac_bft_config_init(dnac_bft_config_t *config, uint32_t n_witnesses) {
    if (!config) return;

    config->n_witnesses = n_witnesses;

    /* Calculate f and quorum based on n = 3f + 1 */
    /* For n=4: f=1, quorum=3 */
    /* For n=7: f=2, quorum=5 */
    if (n_witnesses >= 4) {
        config->f_tolerance = (n_witnesses - 1) / 3;
    } else {
        config->f_tolerance = 0;
    }
    config->quorum = 2 * config->f_tolerance + 1;

    /* Ensure quorum is at least 2 for n=3 testing */
    if (config->quorum < 2 && n_witnesses >= 2) {
        config->quorum = 2;
    }

    config->round_timeout_ms = DNAC_BFT_ROUND_TIMEOUT_MS;
    config->view_change_timeout_ms = DNAC_BFT_VIEW_CHANGE_TIMEOUT_MS;
    config->max_view_changes = DNAC_BFT_MAX_VIEW_CHANGES;
    config->tcp_port = DNAC_BFT_TCP_PORT;

    QGP_LOG_DEBUG(LOG_TAG, "Config: n=%u, f=%u, quorum=%u",
                 config->n_witnesses, config->f_tolerance, config->quorum);
}

/* ============================================================================
 * Context Management
 * ========================================================================== */

dnac_bft_context_t* dnac_bft_create(const dnac_bft_config_t *config, void *dna_engine) {
    if (!config) return NULL;

    dnac_bft_context_t *ctx = calloc(1, sizeof(dnac_bft_context_t));
    if (!ctx) return NULL;

    memcpy(&ctx->config, config, sizeof(dnac_bft_config_t));
    ctx->dna_engine = dna_engine;
    ctx->my_index = -1;
    ctx->current_round = 1;
    ctx->current_view = 0;

    pthread_mutex_init(&ctx->mutex, NULL);
    pthread_cond_init(&ctx->cond, NULL);

    QGP_LOG_INFO(LOG_TAG, "BFT context created");
    return ctx;
}

void dnac_bft_destroy(dnac_bft_context_t *ctx) {
    if (!ctx) return;

    ctx->running = false;
    pthread_cond_broadcast(&ctx->cond);

    if (ctx->my_privkey) {
        memset(ctx->my_privkey, 0, ctx->my_privkey_size);
        free(ctx->my_privkey);
    }

    pthread_mutex_destroy(&ctx->mutex);
    pthread_cond_destroy(&ctx->cond);

    free(ctx);
    QGP_LOG_INFO(LOG_TAG, "BFT context destroyed");
}

int dnac_bft_set_identity(dnac_bft_context_t *ctx,
                          const uint8_t *witness_id,
                          const uint8_t *pubkey,
                          const uint8_t *privkey,
                          size_t privkey_size) {
    if (!ctx || !witness_id || !pubkey || !privkey) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    pthread_mutex_lock(&ctx->mutex);

    memcpy(ctx->my_id, witness_id, DNAC_BFT_WITNESS_ID_SIZE);
    memcpy(ctx->my_pubkey, pubkey, DNAC_PUBKEY_SIZE);

    /* Copy private key */
    if (ctx->my_privkey) {
        memset(ctx->my_privkey, 0, ctx->my_privkey_size);
        free(ctx->my_privkey);
    }

    ctx->my_privkey = malloc(privkey_size);
    if (!ctx->my_privkey) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_OUT_OF_MEMORY;
    }

    memcpy(ctx->my_privkey, privkey, privkey_size);
    ctx->my_privkey_size = privkey_size;

    /* Find our index in roster */
    ctx->my_index = dnac_bft_roster_find(&ctx->roster, witness_id);

    pthread_mutex_unlock(&ctx->mutex);

    QGP_LOG_INFO(LOG_TAG, "Identity set, roster index: %d", ctx->my_index);
    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Leader Election
 * ========================================================================== */

int dnac_bft_get_leader_index(uint64_t epoch, uint32_t view, int n_witnesses) {
    if (n_witnesses <= 0) return -1;
    return (int)((epoch + view) % (uint64_t)n_witnesses);
}

bool dnac_bft_is_leader(dnac_bft_context_t *ctx) {
    if (!ctx || ctx->my_index < 0) return false;

    uint64_t epoch = time(NULL) / DNAC_EPOCH_DURATION_SEC;
    int leader = dnac_bft_get_leader_index(epoch, ctx->current_view,
                                           ctx->roster.n_witnesses);
    return leader == ctx->my_index;
}

int dnac_bft_get_quorum(int n_witnesses) {
    if (n_witnesses < 2) return 1;

    /* For n = 3f + 1, quorum = 2f + 1 */
    int f = (n_witnesses - 1) / 3;
    int quorum = 2 * f + 1;

    /* Minimum quorum of 2 for small clusters */
    if (quorum < 2) quorum = 2;

    return quorum;
}

/* ============================================================================
 * v0.8.0: UTXO Validation
 * ========================================================================== */

/**
 * @brief Validate transaction inputs against the UTXO set
 *
 * For SPEND/BURN transactions:
 * 1. Each input nullifier must exist in the UTXO set
 * 2. Each input amount must match the UTXO set amount
 * 3. Each UTXO must be owned by the sender (fingerprint match)
 * 4. sum(inputs) >= sum(outputs) (difference is fee)
 *
 * For GENESIS transactions: no UTXO validation needed (creates value from nothing).
 *
 * @param ctx BFT context (for utxo_lookup_cb)
 * @param tx_data Serialized transaction data
 * @param tx_len Length of serialized transaction
 * @param tx_type Transaction type
 * @param reason_out Output: rejection reason (256 bytes buffer)
 * @return 0 if valid, -1 if invalid (reason_out filled)
 */
static int bft_validate_utxo(dnac_bft_context_t *ctx,
                              const uint8_t *tx_data, uint32_t tx_len,
                              uint8_t tx_type, char *reason_out) {
    /* GENESIS creates value from nothing — no UTXO inputs to validate */
    if (tx_type == DNAC_TX_GENESIS) {
        return 0;
    }

    /* UTXO lookup callback is required for SPEND/BURN validation */
    if (!ctx->utxo_lookup_cb) {
        QGP_LOG_WARN(LOG_TAG, "UTXO lookup callback not set — skipping UTXO validation");
        return 0;  /* Fail open during transition (before callback is wired up) */
    }

    /* Deserialize the transaction */
    dnac_transaction_t *tx = NULL;
    int rc = dnac_tx_deserialize(tx_data, tx_len, &tx);
    if (rc != DNAC_SUCCESS || !tx) {
        if (reason_out) strncpy(reason_out, "Failed to deserialize transaction", 255);
        return -1;
    }

    /* Derive sender fingerprint from sender's public key */
    char sender_fp[DNAC_FINGERPRINT_SIZE];
    memset(sender_fp, 0, sizeof(sender_fp));
    if (qgp_sha3_512_fingerprint(tx->sender_pubkey, DNAC_PUBKEY_SIZE, sender_fp) != 0) {
        dnac_free_transaction(tx);
        if (reason_out) strncpy(reason_out, "Failed to derive sender fingerprint", 255);
        return -1;
    }

    /* Validate each input against the UTXO set */
    uint64_t total_input = 0;
    uint64_t total_output = 0;

    for (int i = 0; i < tx->input_count; i++) {
        uint64_t utxo_amount = 0;
        char utxo_owner[DNAC_FINGERPRINT_SIZE];
        memset(utxo_owner, 0, sizeof(utxo_owner));

        rc = ctx->utxo_lookup_cb(tx->inputs[i].nullifier, &utxo_amount, utxo_owner, ctx->callback_user_data);
        if (rc != 0) {
            QGP_LOG_WARN(LOG_TAG, "UTXO not found for input %d — REJECT", i);
            dnac_free_transaction(tx);
            if (reason_out) snprintf(reason_out, 255, "UTXO not found for input %d", i);
            return -1;
        }

        /* Verify amount matches */
        if (utxo_amount != tx->inputs[i].amount) {
            QGP_LOG_WARN(LOG_TAG, "Amount mismatch for input %d: UTXO=%llu, TX=%llu",
                         i, (unsigned long long)utxo_amount,
                         (unsigned long long)tx->inputs[i].amount);
            dnac_free_transaction(tx);
            if (reason_out) snprintf(reason_out, 255,
                                      "Amount mismatch for input %d", i);
            return -1;
        }

        /* Verify sender owns this UTXO */
        if (strcmp(utxo_owner, sender_fp) != 0) {
            QGP_LOG_WARN(LOG_TAG, "Owner mismatch for input %d: UTXO=%.16s..., sender=%.16s...",
                         i, utxo_owner, sender_fp);
            dnac_free_transaction(tx);
            if (reason_out) snprintf(reason_out, 255,
                                      "Sender does not own input %d", i);
            return -1;
        }

        total_input += tx->inputs[i].amount;
    }

    /* Sum outputs */
    for (int i = 0; i < tx->output_count; i++) {
        total_output += tx->outputs[i].amount;
    }

    /* Verify: sum(inputs) >= sum(outputs) */
    if (total_input < total_output) {
        QGP_LOG_WARN(LOG_TAG, "Input/output mismatch: inputs=%llu < outputs=%llu",
                     (unsigned long long)total_input, (unsigned long long)total_output);
        dnac_free_transaction(tx);
        if (reason_out) strncpy(reason_out, "Inputs less than outputs", 255);
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "UTXO validation passed: %d inputs verified, total_in=%llu total_out=%llu fee=%llu",
                  tx->input_count, (unsigned long long)total_input,
                  (unsigned long long)total_output,
                  (unsigned long long)(total_input - total_output));

    dnac_free_transaction(tx);
    return 0;
}

/**
 * @brief Update UTXO set on transaction commit
 *
 * For GENESIS: delegate to utxo_genesis_cb (populates all outputs).
 * For SPEND/BURN:
 *   1. Remove spent UTXOs (inputs)
 *   2. Add new UTXOs (outputs) with derived nullifiers
 *
 * Uses extern dnac_derive_nullifier() to compute nullifiers for new outputs.
 *
 * @param ctx BFT context
 * @param tx_data Serialized transaction
 * @param tx_len Length of serialized transaction
 * @param tx_hash Transaction hash
 * @param tx_type Transaction type
 * @return 0 on success, -1 on error
 */
static int bft_update_utxo_set(dnac_bft_context_t *ctx,
                                const uint8_t *tx_data, uint32_t tx_len,
                                const uint8_t *tx_hash, uint8_t tx_type) {
    if (!tx_data || tx_len == 0) {
        QGP_LOG_WARN(LOG_TAG, "No TX data for UTXO set update");
        return 0;  /* Not an error during transition */
    }

    /* Deserialize the transaction */
    dnac_transaction_t *tx = NULL;
    int rc = dnac_tx_deserialize(tx_data, tx_len, &tx);
    if (rc != DNAC_SUCCESS || !tx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize TX for UTXO update");
        return -1;
    }

    /* GENESIS: delegate to utxo_genesis_cb */
    if (tx_type == DNAC_TX_GENESIS) {
        if (ctx->utxo_genesis_cb) {
            rc = ctx->utxo_genesis_cb(tx, tx_hash, ctx->callback_user_data);
            if (rc != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to populate UTXO set from genesis: %d", rc);
                dnac_free_transaction(tx);
                return -1;
            }
            QGP_LOG_INFO(LOG_TAG, "Genesis UTXO set populated (%d outputs)", tx->output_count);
        } else {
            QGP_LOG_WARN(LOG_TAG, "No utxo_genesis_cb set — genesis UTXOs not created");
        }
        dnac_free_transaction(tx);
        return 0;
    }

    /* SPEND/BURN: Remove spent UTXOs (inputs) */
    if (ctx->utxo_remove_cb) {
        for (int i = 0; i < tx->input_count; i++) {
            rc = ctx->utxo_remove_cb(tx->inputs[i].nullifier, ctx->callback_user_data);
            if (rc != 0) {
                QGP_LOG_WARN(LOG_TAG, "Failed to remove spent UTXO %d (may already be removed)", i);
                /* Continue — idempotent removal */
            }
        }
    }

    /* SPEND: Add new output UTXOs */
    if (ctx->utxo_add_cb && tx_type == DNAC_TX_SPEND) {
        extern int dnac_derive_nullifier(const char *owner_fp,
                                          const uint8_t *seed,
                                          uint8_t *nullifier_out);

        for (int i = 0; i < tx->output_count; i++) {
            const dnac_tx_output_internal_t *out = &tx->outputs[i];

            /* Derive nullifier for the new output */
            uint8_t derived_nullifier[DNAC_NULLIFIER_SIZE];
            rc = dnac_derive_nullifier(out->owner_fingerprint,
                                        out->nullifier_seed,
                                        derived_nullifier);
            if (rc != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to derive nullifier for output %d", i);
                dnac_free_transaction(tx);
                return -1;
            }

            rc = ctx->utxo_add_cb(derived_nullifier,
                                    out->owner_fingerprint,
                                    out->amount,
                                    tx_hash,
                                    (uint32_t)i,
                                    0 /* block_height: will be set properly in Phase 2 */,
                                    ctx->callback_user_data);
            if (rc != 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to add output UTXO %d", i);
                dnac_free_transaction(tx);
                return -1;
            }
        }
        QGP_LOG_DEBUG(LOG_TAG, "UTXO set updated: -%d inputs, +%d outputs",
                      tx->input_count, tx->output_count);
    }

    dnac_free_transaction(tx);
    return 0;
}

/* ============================================================================
 * Consensus Protocol
 * ========================================================================== */

int dnac_bft_start_round(dnac_bft_context_t *ctx,
                         const uint8_t *tx_hash,
                         const uint8_t nullifiers[][DNAC_NULLIFIER_SIZE],
                         uint8_t nullifier_count,
                         uint8_t tx_type,
                         const uint8_t *tx_data,
                         uint32_t tx_len,
                         const uint8_t *client_pubkey,
                         const uint8_t *client_sig,
                         uint64_t fee_amount) {
    if (!ctx || !tx_hash) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* v0.8.0: Full TX data is required for UTXO validation */
    if (!tx_data || tx_len == 0 || tx_len > DNAC_BFT_MAX_TX_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid tx_data: ptr=%p len=%u", (void*)tx_data, tx_len);
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* GENESIS transactions have no inputs (nullifier_count=0 is valid) */
    if (tx_type != DNAC_TX_GENESIS && (nullifiers == NULL || nullifier_count == 0)) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    if (nullifier_count > DNAC_TX_MAX_INPUTS) {
        QGP_LOG_ERROR(LOG_TAG, "Too many nullifiers: %d", nullifier_count);
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    pthread_mutex_lock(&ctx->mutex);

    /* Verify we are leader */
    if (!dnac_bft_is_leader(ctx)) {
        QGP_LOG_WARN(LOG_TAG, "start_round called but we are not leader");
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_NOT_LEADER;
    }

    /* Check for existing round in progress */
    if (ctx->round_state.phase != BFT_PHASE_IDLE) {
        QGP_LOG_WARN(LOG_TAG, "Round already in progress");
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* v0.4.0: Check ALL nullifiers locally first for double-spend */
    for (int i = 0; i < nullifier_count; i++) {
        if (nullifier_exists(ctx, nullifiers[i])) {
            QGP_LOG_WARN(LOG_TAG, "Nullifier %d already spent (local check)", i);
            pthread_mutex_unlock(&ctx->mutex);
            return DNAC_BFT_ERROR_DOUBLE_SPEND;
        }
    }

    /* v0.8.0: Validate transaction inputs against UTXO set */
    {
        char reason[256] = {0};
        if (bft_validate_utxo(ctx, tx_data, tx_len, tx_type, reason) != 0) {
            QGP_LOG_WARN(LOG_TAG, "UTXO validation failed (leader): %s", reason);
            pthread_mutex_unlock(&ctx->mutex);
            return DNAC_BFT_ERROR_DOUBLE_SPEND;
        }
    }

    /* Initialize round state - preserve client connection info set by caller */
    int saved_client_fd = ctx->round_state.client_fd;
    bool saved_is_forwarded = ctx->round_state.is_forwarded;
    uint8_t saved_forwarder_id[DNAC_BFT_WITNESS_ID_SIZE];
    int saved_forwarder_fd = ctx->round_state.forwarder_fd;
    memcpy(saved_forwarder_id, ctx->round_state.forwarder_id, DNAC_BFT_WITNESS_ID_SIZE);

    ctx->current_round++;
    memset(&ctx->round_state, 0, sizeof(ctx->round_state));

    /* Restore client connection info */
    ctx->round_state.client_fd = saved_client_fd;
    ctx->round_state.is_forwarded = saved_is_forwarded;
    ctx->round_state.forwarder_fd = saved_forwarder_fd;
    memcpy(ctx->round_state.forwarder_id, saved_forwarder_id, DNAC_BFT_WITNESS_ID_SIZE);

    ctx->round_state.round = ctx->current_round;
    ctx->round_state.view = ctx->current_view;
    ctx->round_state.phase = BFT_PHASE_PREVOTE;
    memcpy(ctx->round_state.tx_hash, tx_hash, DNAC_TX_HASH_SIZE);

    /* v0.5.0: Store transaction type for genesis handling */
    ctx->round_state.tx_type = tx_type;

    /* v0.4.0: Store ALL nullifiers in round state (none for GENESIS) */
    ctx->round_state.nullifier_count = nullifier_count;
    for (int i = 0; i < nullifier_count; i++) {
        memcpy(ctx->round_state.nullifiers[i], nullifiers[i], DNAC_NULLIFIER_SIZE);
    }

    /* v0.8.0: Store full TX data in round state */
    memcpy(ctx->round_state.tx_data, tx_data, tx_len);
    ctx->round_state.tx_len = tx_len;

    /* v0.9.0: Store proposal timestamp and proposer ID for block production */
    ctx->round_state.proposal_timestamp = (uint64_t)time(NULL);
    memcpy(ctx->round_state.proposer_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);

    ctx->round_state.phase_start_time = dnac_tcp_get_time_ms();

    if (client_pubkey) {
        memcpy(ctx->round_state.client_pubkey, client_pubkey, DNAC_PUBKEY_SIZE);
    }
    if (client_sig) {
        memcpy(ctx->round_state.client_signature, client_sig, DNAC_SIGNATURE_SIZE);
    }
    ctx->round_state.fee_amount = fee_amount;

    /* Create proposal message with ALL nullifiers and TX data */
    dnac_bft_proposal_t *proposal = calloc(1, sizeof(dnac_bft_proposal_t));
    if (!proposal) {
        pthread_mutex_unlock(&ctx->mutex);
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate proposal");
        return DNAC_BFT_ERROR_OUT_OF_MEMORY;
    }

    proposal->header.version = DNAC_BFT_PROTOCOL_VERSION;
    proposal->header.type = BFT_MSG_PROPOSAL;
    proposal->header.round = ctx->current_round;
    proposal->header.view = ctx->current_view;
    memcpy(proposal->header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
    proposal->header.timestamp = time(NULL);
    proposal->header.nonce = generate_nonce();  /* Gap 23-24: replay prevention */
    memcpy(proposal->header.chain_id, ctx->chain_id, 32);  /* v0.10.0 */

    memcpy(proposal->tx_hash, tx_hash, DNAC_TX_HASH_SIZE);
    proposal->nullifier_count = nullifier_count;
    proposal->tx_type = tx_type;  /* v0.5.0: for genesis 3-of-3 */
    for (int i = 0; i < nullifier_count; i++) {
        memcpy(proposal->nullifiers[i], nullifiers[i], DNAC_NULLIFIER_SIZE);
    }

    /* v0.8.0: Include full TX data in proposal */
    memcpy(proposal->tx_data, tx_data, tx_len);
    proposal->tx_len = tx_len;

    if (client_pubkey) {
        memcpy(proposal->sender_pubkey, client_pubkey, DNAC_PUBKEY_SIZE);
    }
    if (client_sig) {
        memcpy(proposal->client_signature, client_sig, DNAC_SIGNATURE_SIZE);
    }
    proposal->fee_amount = fee_amount;

    /* Sign proposal with Dilithium5 (Gap 1: v0.6.0) */
    uint8_t proposal_sign_data[256];
    size_t proposal_sign_len;
    if (bft_build_proposal_sign_data(proposal, proposal_sign_data, &proposal_sign_len) != 0) {
        free(proposal);
        pthread_mutex_unlock(&ctx->mutex);
        QGP_LOG_ERROR(LOG_TAG, "Failed to build proposal signing data");
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }
    if (bft_sign_message(ctx, proposal->signature, proposal_sign_data, proposal_sign_len) != 0) {
        free(proposal);
        pthread_mutex_unlock(&ctx->mutex);
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign proposal");
        return DNAC_BFT_ERROR_INVALID_SIGNATURE;
    }

    /* Add our own PREVOTE BEFORE broadcasting (leader approves own proposal)
     * This MUST be done before releasing the mutex to avoid race conditions:
     * if we broadcast first and then set our vote, incoming PREVOTEs could
     * be processed and then overwritten when we set our vote.
     */
    memcpy(ctx->round_state.prevotes[0].voter_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
    ctx->round_state.prevotes[0].vote = BFT_VOTE_APPROVE;
    ctx->round_state.prevote_count = 1;
    ctx->round_state.prevote_approve_count = 1;

    pthread_mutex_unlock(&ctx->mutex);

    /* v0.8.0: Heap-allocate buffer for proposal with embedded TX data */
    size_t buf_size = DNAC_BFT_MAX_TX_SIZE + 16384 + DNAC_TCP_FRAME_HEADER_SIZE;
    uint8_t *buffer = malloc(buf_size);
    if (!buffer) {
        free(proposal);
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate proposal buffer");
        return DNAC_BFT_ERROR_OUT_OF_MEMORY;
    }

    size_t written;
    int rc = dnac_bft_proposal_serialize(proposal, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                         buf_size - DNAC_TCP_FRAME_HEADER_SIZE,
                                         &written);
    free(proposal);

    if (rc != DNAC_BFT_SUCCESS) {
        free(buffer);
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize proposal");
        return rc;
    }

    dnac_tcp_write_frame_header(buffer, BFT_MSG_PROPOSAL, (uint32_t)written);

    int sent = bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
    free(buffer);

    QGP_LOG_INFO(LOG_TAG, "Proposal broadcast to %d peers (round %lu, %d nullifiers, tx_len=%u)",
                sent, (unsigned long)ctx->current_round, nullifier_count, tx_len);

    /* v0.8.0: Leader must also broadcast its PREVOTE so followers can reach
     * unanimous quorum (e.g., genesis requires n_witnesses approvals).
     * Without this, followers only see PREVOTEs from other followers and
     * can never reach N/N quorum. */
    {
        dnac_bft_vote_msg_t leader_prevote;
        memset(&leader_prevote, 0, sizeof(leader_prevote));
        leader_prevote.header.version = DNAC_BFT_PROTOCOL_VERSION;
        leader_prevote.header.type = BFT_MSG_PREVOTE;
        leader_prevote.header.round = ctx->current_round;
        leader_prevote.header.view = ctx->round_state.view;
        memcpy(leader_prevote.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
        leader_prevote.header.timestamp = time(NULL);
        leader_prevote.header.nonce = generate_nonce();
        memcpy(leader_prevote.header.chain_id, ctx->chain_id, 32);  /* v0.10.0 */
        memcpy(leader_prevote.tx_hash, tx_hash, DNAC_TX_HASH_SIZE);
        leader_prevote.vote = BFT_VOTE_APPROVE;

        uint8_t vote_sign_data[256];
        size_t vote_sign_len;
        if (bft_build_vote_sign_data(&leader_prevote, vote_sign_data, &vote_sign_len) == 0 &&
            bft_sign_message(ctx, leader_prevote.signature, vote_sign_data, vote_sign_len) == 0) {

            uint8_t vote_buf[8192];
            size_t vote_written;
            if (dnac_bft_vote_serialize(&leader_prevote, vote_buf + DNAC_TCP_FRAME_HEADER_SIZE,
                                         sizeof(vote_buf) - DNAC_TCP_FRAME_HEADER_SIZE,
                                         &vote_written) == DNAC_BFT_SUCCESS) {
                dnac_tcp_write_frame_header(vote_buf, BFT_MSG_PREVOTE, (uint32_t)vote_written);
                bft_peer_broadcast(vote_buf, DNAC_TCP_FRAME_HEADER_SIZE + vote_written, -1);
            }
        }
    }

    return DNAC_BFT_SUCCESS;
}

int dnac_bft_handle_proposal(dnac_bft_context_t *ctx,
                             const dnac_bft_proposal_t *proposal) {
    if (!ctx || !proposal) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Gap 23-24 Fix (v0.6.0): Check for replay attack */
    if (is_replay(proposal->header.sender_id, proposal->header.nonce,
                  proposal->header.timestamp)) {
        QGP_LOG_WARN(LOG_TAG, "Proposal replay detected, ignoring");
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    pthread_mutex_lock(&ctx->mutex);

    /* Verify proposal is from current leader */
    uint64_t epoch = time(NULL) / DNAC_EPOCH_DURATION_SEC;
    int leader = dnac_bft_get_leader_index(epoch, proposal->header.view,
                                           ctx->roster.n_witnesses);

    int sender_index = dnac_bft_roster_find(&ctx->roster, proposal->header.sender_id);
    if (sender_index != leader) {
        QGP_LOG_WARN(LOG_TAG, "Proposal from non-leader (sender %d, leader %d)",
                    sender_index, leader);
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_NOT_LEADER;
    }

    /* Verify proposal signature (Gap 2: v0.6.0) */
    if (bft_verify_proposal_signature(ctx, proposal) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Invalid proposal signature from leader %d", leader);
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_SIGNATURE;
    }

    /* v0.4.0: Check ALL nullifiers locally for double-spend */
    bool double_spend = false;
    char reject_reason[256] = {0};
    for (int i = 0; i < proposal->nullifier_count; i++) {
        if (nullifier_exists(ctx, proposal->nullifiers[i])) {
            QGP_LOG_WARN(LOG_TAG, "Nullifier %d already spent", i);
            double_spend = true;
            strncpy(reject_reason, "Nullifier already spent", sizeof(reject_reason) - 1);
            break;
        }
    }

    /* v0.8.0: Validate transaction inputs against UTXO set */
    if (!double_spend && proposal->tx_len > 0) {
        if (bft_validate_utxo(ctx, proposal->tx_data, proposal->tx_len,
                               proposal->tx_type, reject_reason) != 0) {
            QGP_LOG_WARN(LOG_TAG, "UTXO validation failed: %s", reject_reason);
            double_spend = true;
        }
    }

    /* Initialize round state */
    ctx->current_round = proposal->header.round;
    ctx->current_view = proposal->header.view;

    memset(&ctx->round_state, 0, sizeof(ctx->round_state));
    ctx->round_state.client_fd = -1;  /* No client connected to this witness for this round */
    ctx->round_state.round = proposal->header.round;
    ctx->round_state.view = proposal->header.view;
    ctx->round_state.phase = BFT_PHASE_PREVOTE;
    memcpy(ctx->round_state.tx_hash, proposal->tx_hash, DNAC_TX_HASH_SIZE);

    /* v0.5.0: Store transaction type for genesis handling */
    ctx->round_state.tx_type = proposal->tx_type;

    /* v0.4.0: Store ALL nullifiers from proposal */
    ctx->round_state.nullifier_count = proposal->nullifier_count;
    for (int i = 0; i < proposal->nullifier_count; i++) {
        memcpy(ctx->round_state.nullifiers[i], proposal->nullifiers[i], DNAC_NULLIFIER_SIZE);
    }

    /* v0.8.0: Store full TX data from proposal */
    if (proposal->tx_len > 0 && proposal->tx_len <= DNAC_BFT_MAX_TX_SIZE) {
        memcpy(ctx->round_state.tx_data, proposal->tx_data, proposal->tx_len);
        ctx->round_state.tx_len = proposal->tx_len;
    } else {
        ctx->round_state.tx_len = 0;
    }

    memcpy(ctx->round_state.client_pubkey, proposal->sender_pubkey, DNAC_PUBKEY_SIZE);
    memcpy(ctx->round_state.client_signature, proposal->client_signature, DNAC_SIGNATURE_SIZE);
    ctx->round_state.fee_amount = proposal->fee_amount;
    ctx->round_state.phase_start_time = dnac_tcp_get_time_ms();

    /* v0.9.0: Extract proposal timestamp and proposer from header */
    ctx->round_state.proposal_timestamp = proposal->header.timestamp;
    memcpy(ctx->round_state.proposer_id, proposal->header.sender_id, DNAC_BFT_WITNESS_ID_SIZE);

    /* Create PREVOTE message */
    dnac_bft_vote_msg_t vote;
    memset(&vote, 0, sizeof(vote));

    vote.header.version = DNAC_BFT_PROTOCOL_VERSION;
    vote.header.type = BFT_MSG_PREVOTE;
    vote.header.round = proposal->header.round;
    vote.header.view = proposal->header.view;
    memcpy(vote.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
    vote.header.timestamp = time(NULL);
    vote.header.nonce = generate_nonce();  /* Gap 23-24: replay prevention */
    memcpy(vote.header.chain_id, ctx->chain_id, 32);  /* v0.10.0 */

    memcpy(vote.tx_hash, proposal->tx_hash, DNAC_TX_HASH_SIZE);
    vote.vote = double_spend ? BFT_VOTE_REJECT : BFT_VOTE_APPROVE;

    if (double_spend) {
        snprintf(vote.reason, sizeof(vote.reason), "%s",
                 reject_reason[0] ? reject_reason : "Validation failed");
    }

    /* Sign PREVOTE with Dilithium5 (Gap 3: v0.6.0) */
    uint8_t vote_sign_data[256];
    size_t vote_sign_len;
    if (bft_build_vote_sign_data(&vote, vote_sign_data, &vote_sign_len) != 0) {
        pthread_mutex_unlock(&ctx->mutex);
        QGP_LOG_ERROR(LOG_TAG, "Failed to build vote signing data");
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }
    if (bft_sign_message(ctx, vote.signature, vote_sign_data, vote_sign_len) != 0) {
        pthread_mutex_unlock(&ctx->mutex);
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign PREVOTE");
        return DNAC_BFT_ERROR_INVALID_SIGNATURE;
    }

    /* Record our own PREVOTE BEFORE broadcasting (same pattern as leader in start_round)
     * This ensures incoming PREVOTEs from other witnesses don't overwrite our vote
     * and that we count ourselves toward quorum.
     */
    memcpy(ctx->round_state.prevotes[0].voter_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
    ctx->round_state.prevotes[0].vote = vote.vote;
    ctx->round_state.prevote_count = 1;
    ctx->round_state.prevote_approve_count = (vote.vote == BFT_VOTE_APPROVE) ? 1 : 0;

    pthread_mutex_unlock(&ctx->mutex);

    /* Serialize and broadcast */
    uint8_t buffer[8192];
    size_t written;

    int rc = dnac_bft_vote_serialize(&vote, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                     sizeof(buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                     &written);
    if (rc != DNAC_BFT_SUCCESS) {
        return rc;
    }

    dnac_tcp_write_frame_header(buffer, BFT_MSG_PREVOTE, (uint32_t)written);

    /* Gap 15 Fix (v0.6.0): Log broadcast failures */
    int sent = bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
    if (sent < (int)ctx->roster.n_witnesses - 1) {
        QGP_LOG_WARN(LOG_TAG, "PREVOTE broadcast only reached %d/%u peers",
                     sent, ctx->roster.n_witnesses - 1);
    }

    QGP_LOG_INFO(LOG_TAG, "Sent PREVOTE %s for round %lu (%d nullifiers)",
                vote.vote == BFT_VOTE_APPROVE ? "APPROVE" : "REJECT",
                (unsigned long)proposal->header.round,
                proposal->nullifier_count);

    return DNAC_BFT_SUCCESS;
}

int dnac_bft_handle_vote(dnac_bft_context_t *ctx,
                         const dnac_bft_vote_msg_t *vote) {
    if (!ctx || !vote) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Gap 23-24 Fix (v0.6.0): Check for replay attack */
    if (is_replay(vote->header.sender_id, vote->header.nonce,
                  vote->header.timestamp)) {
        QGP_LOG_WARN(LOG_TAG, "Vote replay detected, ignoring");
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    fprintf(stderr, "[CONSENSUS] handle_vote: type=%d round=%lu view=%u\n",
            vote->header.type, (unsigned long)vote->header.round, vote->header.view);
    fflush(stderr);

    pthread_mutex_lock(&ctx->mutex);

    fprintf(stderr, "[CONSENSUS] my_state: round=%lu view=%u phase=%d\n",
            (unsigned long)ctx->round_state.round, ctx->round_state.view,
            ctx->round_state.phase);
    fflush(stderr);

    /* Verify round and view match */
    if (vote->header.round != ctx->round_state.round ||
        vote->header.view != ctx->round_state.view) {
        fprintf(stderr, "[CONSENSUS] Vote for wrong round/view! Ignoring.\n");
        fflush(stderr);
        QGP_LOG_DEBUG(LOG_TAG, "Vote for wrong round/view (got %lu/%u, expected %lu/%u)",
                     (unsigned long)vote->header.round, vote->header.view,
                     (unsigned long)ctx->round_state.round, ctx->round_state.view);
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_SUCCESS;  /* Ignore stale votes */
    }

    /* Verify tx_hash matches */
    if (memcmp(vote->tx_hash, ctx->round_state.tx_hash, DNAC_TX_HASH_SIZE) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Vote for different tx_hash");
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    /* Verify vote signature (Gap 4: v0.6.0) */
    if (bft_verify_vote_signature(ctx, vote) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Invalid vote signature from %.8s",
                    (const char *)vote->header.sender_id);
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_SIGNATURE;
    }

    /* Record vote based on type */
    dnac_bft_vote_record_t *votes;
    int *vote_count;
    int *approve_count;
    dnac_bft_phase_t expected_phase;
    dnac_bft_phase_t next_phase;
    dnac_bft_msg_type_t next_msg_type;

    if (vote->header.type == BFT_MSG_PREVOTE) {
        votes = ctx->round_state.prevotes;
        vote_count = &ctx->round_state.prevote_count;
        approve_count = &ctx->round_state.prevote_approve_count;
        expected_phase = BFT_PHASE_PREVOTE;
        next_phase = BFT_PHASE_PRECOMMIT;
        next_msg_type = BFT_MSG_PRECOMMIT;
    } else if (vote->header.type == BFT_MSG_PRECOMMIT) {
        votes = ctx->round_state.precommits;
        vote_count = &ctx->round_state.precommit_count;
        approve_count = &ctx->round_state.precommit_approve_count;
        expected_phase = BFT_PHASE_PRECOMMIT;
        next_phase = BFT_PHASE_COMMIT;
        next_msg_type = BFT_MSG_COMMIT;
    } else {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    /* Check phase */
    if (ctx->round_state.phase != expected_phase) {
        fprintf(stderr, "[CONSENSUS] Vote type %d but phase is %d (expected %d). Ignoring.\n",
                vote->header.type, ctx->round_state.phase, expected_phase);
        fflush(stderr);
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_SUCCESS;  /* Ignore */
    }

    /* Check for duplicate */
    for (int i = 0; i < *vote_count; i++) {
        if (memcmp(votes[i].voter_id, vote->header.sender_id,
                   DNAC_BFT_WITNESS_ID_SIZE) == 0) {
            pthread_mutex_unlock(&ctx->mutex);
            return DNAC_BFT_SUCCESS;  /* Already received */
        }
    }

    /* Verify sender is in roster */
    int sender_index = dnac_bft_roster_find(&ctx->roster, vote->header.sender_id);
    fprintf(stderr, "[CONSENSUS] Vote sender lookup: sender_index=%d (n_witnesses=%u)\n",
            sender_index, ctx->roster.n_witnesses);
    fflush(stderr);
    if (sender_index < 0) {
        fprintf(stderr, "[CONSENSUS] Vote from unknown sender! Rejecting.\n");
        fflush(stderr);
        QGP_LOG_WARN(LOG_TAG, "Vote from unknown sender");
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    /* Record vote */
    if (*vote_count >= DNAC_BFT_MAX_WITNESSES) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    memcpy(votes[*vote_count].voter_id, vote->header.sender_id, DNAC_BFT_WITNESS_ID_SIZE);
    votes[*vote_count].vote = vote->vote;
    memcpy(votes[*vote_count].signature, vote->signature, DNAC_SIGNATURE_SIZE);
    (*vote_count)++;

    if (vote->vote == BFT_VOTE_APPROVE) {
        (*approve_count)++;
    }

    fprintf(stderr, "[CONSENSUS] %s from roster %d: %s (approve=%d, count=%d, quorum=%u)\n",
            vote->header.type == BFT_MSG_PREVOTE ? "PREVOTE" : "PRECOMMIT",
            sender_index,
            vote->vote == BFT_VOTE_APPROVE ? "APPROVE" : "REJECT",
            *approve_count, *vote_count, ctx->config.quorum);
    fflush(stderr);

    QGP_LOG_DEBUG(LOG_TAG, "%s from roster %d: %s (%d/%d approve, quorum=%u)",
                 vote->header.type == BFT_MSG_PREVOTE ? "PREVOTE" : "PRECOMMIT",
                 sender_index,
                 vote->vote == BFT_VOTE_APPROVE ? "APPROVE" : "REJECT",
                 *approve_count, *vote_count, ctx->config.quorum);

    /* Check for quorum
     * v0.5.0: GENESIS requires unanimous (n_witnesses) approval
     */
    uint32_t required_quorum = ctx->config.quorum;
    if (ctx->round_state.tx_type == DNAC_TX_GENESIS) {
        required_quorum = ctx->config.n_witnesses;  /* 3-of-3 for genesis */
    }

    if ((uint32_t)*approve_count >= required_quorum) {
        fprintf(stderr, "[CONSENSUS] QUORUM REACHED! approve=%d >= quorum=%u (genesis=%d)\n",
                *approve_count, required_quorum, ctx->round_state.tx_type == DNAC_TX_GENESIS);
        fflush(stderr);
        QGP_LOG_INFO(LOG_TAG, "%s quorum reached! (genesis=%s)",
                    vote->header.type == BFT_MSG_PREVOTE ? "PREVOTE" : "PRECOMMIT",
                    ctx->round_state.tx_type == DNAC_TX_GENESIS ? "yes, unanimous" : "no");

        ctx->round_state.phase = next_phase;
        ctx->round_state.phase_start_time = dnac_tcp_get_time_ms();

        /* Create next phase message */
        if (next_msg_type == BFT_MSG_PRECOMMIT) {
            /* v0.8.0: Count our own PRECOMMIT before broadcasting, same pattern as
             * PREVOTE in start_round/handle_proposal. Without this, nodes can only
             * count N-1 PRECOMMITs and genesis (requiring N/N) gets stuck. */
            memcpy(ctx->round_state.precommits[0].voter_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
            ctx->round_state.precommits[0].vote = BFT_VOTE_APPROVE;
            ctx->round_state.precommit_count = 1;
            ctx->round_state.precommit_approve_count = 1;

            /* Send PRECOMMIT */
            dnac_bft_vote_msg_t precommit;
            memset(&precommit, 0, sizeof(precommit));

            precommit.header.version = DNAC_BFT_PROTOCOL_VERSION;
            precommit.header.type = BFT_MSG_PRECOMMIT;
            precommit.header.round = ctx->round_state.round;
            precommit.header.view = ctx->round_state.view;
            memcpy(precommit.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
            precommit.header.timestamp = time(NULL);
            precommit.header.nonce = generate_nonce();  /* Gap 23-24: replay prevention */
            memcpy(precommit.header.chain_id, ctx->chain_id, 32);  /* v0.10.0 */
            memcpy(precommit.tx_hash, ctx->round_state.tx_hash, DNAC_TX_HASH_SIZE);
            precommit.vote = BFT_VOTE_APPROVE;

            /* Sign PRECOMMIT with Dilithium5 (Gap 3: v0.6.0) */
            uint8_t precommit_sign_data[256];
            size_t precommit_sign_len;
            if (bft_build_vote_sign_data(&precommit, precommit_sign_data, &precommit_sign_len) != 0) {
                pthread_mutex_unlock(&ctx->mutex);
                QGP_LOG_ERROR(LOG_TAG, "Failed to build PRECOMMIT signing data");
                return DNAC_BFT_ERROR_INVALID_PARAM;
            }
            if (bft_sign_message(ctx, precommit.signature, precommit_sign_data, precommit_sign_len) != 0) {
                pthread_mutex_unlock(&ctx->mutex);
                QGP_LOG_ERROR(LOG_TAG, "Failed to sign PRECOMMIT");
                return DNAC_BFT_ERROR_INVALID_SIGNATURE;
            }

            pthread_mutex_unlock(&ctx->mutex);

            uint8_t buffer[8192];
            size_t written;

            if (dnac_bft_vote_serialize(&precommit, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                        sizeof(buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                        &written) == DNAC_BFT_SUCCESS) {
                dnac_tcp_write_frame_header(buffer, BFT_MSG_PRECOMMIT, (uint32_t)written);
                /* Gap 15 Fix (v0.6.0): Log broadcast failures */
                int sent = bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
                if (sent < (int)ctx->roster.n_witnesses - 1) {
                    QGP_LOG_WARN(LOG_TAG, "PRECOMMIT broadcast only reached %d/%u peers",
                                 sent, ctx->roster.n_witnesses - 1);
                }
            }

            return DNAC_BFT_SUCCESS;

        } else if (next_msg_type == BFT_MSG_COMMIT) {
            /* v0.5.0: Handle GENESIS transaction specially */
            if (ctx->round_state.tx_type == DNAC_TX_GENESIS) {
                QGP_LOG_INFO(LOG_TAG, "COMMIT: Recording GENESIS transaction (unanimous approval)");

                /* Compute genesis commitment (placeholder - should include all output data) */
                uint8_t genesis_commitment[DNAC_GENESIS_COMMITMENT_SIZE];
                memcpy(genesis_commitment, ctx->round_state.tx_hash, DNAC_TX_HASH_SIZE);

                /* Record genesis state via callback - will reject if already exists */
                if (ctx->genesis_record_cb) {
                    int rc = ctx->genesis_record_cb(ctx->round_state.tx_hash,
                                                    ctx->round_state.fee_amount,  /* Repurpose as total_supply */
                                                    genesis_commitment,
                                                    ctx->callback_user_data);
                    if (rc == -2) {
                        QGP_LOG_ERROR(LOG_TAG, "Genesis already exists - should not happen");
                    } else if (rc != 0) {
                        QGP_LOG_ERROR(LOG_TAG, "Failed to record genesis state: %d", rc);
                    }
                } else {
                    QGP_LOG_WARN(LOG_TAG, "No genesis_record_cb set - genesis not recorded");
                }

                /* v0.8.0: Populate UTXO set from genesis outputs */
                if (bft_update_utxo_set(ctx,
                                         ctx->round_state.tx_data,
                                         ctx->round_state.tx_len,
                                         ctx->round_state.tx_hash,
                                         DNAC_TX_GENESIS) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Failed to populate genesis UTXO set");
                }
            } else {
                /* v0.4.0: COMMIT phase - add ALL nullifiers to database
                 * v0.6.0: Wrapped in transaction for atomicity (Gap 11) */
                QGP_LOG_INFO(LOG_TAG, "COMMIT: Adding %d nullifiers to database",
                            ctx->round_state.nullifier_count);

                /* Begin transaction for atomicity */
                if (ctx->db_begin_cb) {
                    if (ctx->db_begin_cb(ctx->callback_user_data) != 0) {
                        QGP_LOG_ERROR(LOG_TAG, "Failed to begin transaction");
                        pthread_mutex_unlock(&ctx->mutex);
                        return DNAC_BFT_ERROR_INVALID_MESSAGE;
                    }
                }

                bool any_failed = false;
                for (int i = 0; i < ctx->round_state.nullifier_count; i++) {
                    int rc = nullifier_add(ctx, ctx->round_state.nullifiers[i],
                                           ctx->round_state.tx_hash);
                    if (rc != 0 && rc != -2) {  /* -2 = already exists, which is ok */
                        QGP_LOG_ERROR(LOG_TAG, "Failed to add nullifier %d", i);
                        any_failed = true;
                        break;
                    }
                }

                /* v0.8.0: Update UTXO set within the same atomic transaction */
                if (!any_failed) {
                    if (bft_update_utxo_set(ctx,
                                             ctx->round_state.tx_data,
                                             ctx->round_state.tx_len,
                                             ctx->round_state.tx_hash,
                                             ctx->round_state.tx_type) != 0) {
                        QGP_LOG_ERROR(LOG_TAG, "Failed to update UTXO set on COMMIT");
                        any_failed = true;
                    }
                }

                /* Rollback on failure, commit on success */
                if (any_failed) {
                    if (ctx->db_rollback_cb) ctx->db_rollback_cb(ctx->callback_user_data);
                    pthread_mutex_unlock(&ctx->mutex);
                    return DNAC_BFT_ERROR_INVALID_MESSAGE;
                }
                if (ctx->db_commit_cb) {
                    if (ctx->db_commit_cb(ctx->callback_user_data) != 0) {
                        QGP_LOG_ERROR(LOG_TAG, "Failed to commit transaction");
                        if (ctx->db_rollback_cb) ctx->db_rollback_cb(ctx->callback_user_data);
                        pthread_mutex_unlock(&ctx->mutex);
                        return DNAC_BFT_ERROR_INVALID_MESSAGE;
                    }
                }
            }

            /* v0.5.0: Add ledger entry for audit trail */
            if (ctx->ledger_add_cb) {
                int rc = ctx->ledger_add_cb(ctx->round_state.tx_hash,
                                             ctx->round_state.tx_type,
                                             (const uint8_t (*)[DNAC_NULLIFIER_SIZE])ctx->round_state.nullifiers,
                                             ctx->round_state.nullifier_count,
                                             ctx->callback_user_data);
                if (rc != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Failed to add ledger entry: %d", rc);
                }
            }

            /* v0.9.0: Create block wrapping this committed TX */
            if (ctx->block_create_cb) {
                ctx->block_create_cb(ctx->round_state.tx_hash,
                                     ctx->round_state.tx_type,
                                     ctx->round_state.proposal_timestamp,
                                     ctx->round_state.proposer_id,
                                     ctx->callback_user_data);
            }

            ctx->last_committed_round = ctx->round_state.round;

            /* Save client connection info and nullifier data before reset */
            int client_fd = ctx->round_state.client_fd;
            bool is_forwarded = ctx->round_state.is_forwarded;
            uint8_t saved_nullifier_count = ctx->round_state.nullifier_count;
            uint8_t saved_nullifiers[DNAC_TX_MAX_INPUTS][DNAC_NULLIFIER_SIZE];
            for (int i = 0; i < saved_nullifier_count; i++) {
                memcpy(saved_nullifiers[i], ctx->round_state.nullifiers[i], DNAC_NULLIFIER_SIZE);
            }
            /* v0.8.0: Save tx_hash for forward callback after free */
            uint8_t saved_tx_hash[DNAC_TX_HASH_SIZE];
            memcpy(saved_tx_hash, ctx->round_state.tx_hash, DNAC_TX_HASH_SIZE);

            /* v0.8.0: Heap-allocate commit (contains tx_data) */
            dnac_bft_commit_t *commit = calloc(1, sizeof(dnac_bft_commit_t));
            if (!commit) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to allocate commit message");
                pthread_mutex_unlock(&ctx->mutex);
                return DNAC_BFT_ERROR_OUT_OF_MEMORY;
            }

            commit->header.version = DNAC_BFT_PROTOCOL_VERSION;
            commit->header.type = BFT_MSG_COMMIT;
            commit->header.round = ctx->round_state.round;
            commit->header.view = ctx->round_state.view;
            memcpy(commit->header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
            commit->header.timestamp = time(NULL);
            commit->header.nonce = generate_nonce();  /* Gap 23-24: replay prevention */
            memcpy(commit->header.chain_id, ctx->chain_id, 32);  /* v0.10.0 */
            memcpy(commit->tx_hash, ctx->round_state.tx_hash, DNAC_TX_HASH_SIZE);
            commit->nullifier_count = saved_nullifier_count;
            for (int i = 0; i < saved_nullifier_count; i++) {
                memcpy(commit->nullifiers[i], saved_nullifiers[i], DNAC_NULLIFIER_SIZE);
            }

            /* v0.8.0: Include tx_type and full TX data in commit */
            commit->tx_type = ctx->round_state.tx_type;
            if (ctx->round_state.tx_len > 0 && ctx->round_state.tx_len <= DNAC_BFT_MAX_TX_SIZE) {
                memcpy(commit->tx_data, ctx->round_state.tx_data, ctx->round_state.tx_len);
                commit->tx_len = ctx->round_state.tx_len;
            }

            /* v0.9.0: Include proposal timestamp and proposer for block production */
            commit->proposal_timestamp = ctx->round_state.proposal_timestamp;
            memcpy(commit->proposer_id, ctx->round_state.proposer_id, DNAC_BFT_WITNESS_ID_SIZE);

            commit->n_precommits = ctx->round_state.precommit_count;

            /* Reset round state */
            ctx->round_state.phase = BFT_PHASE_IDLE;
            ctx->round_state.client_fd = -1;

            pthread_mutex_unlock(&ctx->mutex);

            /* v0.8.0: Heap-allocate buffer for commit with embedded TX data */
            size_t commit_buf_size = DNAC_BFT_MAX_TX_SIZE + 16384 + DNAC_TCP_FRAME_HEADER_SIZE;
            uint8_t *buffer = malloc(commit_buf_size);
            if (buffer) {
                size_t written;
                if (dnac_bft_commit_serialize(commit, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                              commit_buf_size - DNAC_TCP_FRAME_HEADER_SIZE,
                                              &written) == DNAC_BFT_SUCCESS) {
                    dnac_tcp_write_frame_header(buffer, BFT_MSG_COMMIT, (uint32_t)written);
                    /* Gap 15 Fix (v0.6.0): Log broadcast failures */
                    int sent = bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
                    if (sent < (int)ctx->roster.n_witnesses - 1) {
                        QGP_LOG_WARN(LOG_TAG, "COMMIT broadcast only reached %d/%u peers",
                                     sent, ctx->roster.n_witnesses - 1);
                    }
                }
                free(buffer);
            }
            free(commit);

            /* Send response to client (if we are leader and client connected directly) */
            if (!is_forwarded && client_fd >= 0) {
                QGP_LOG_INFO(LOG_TAG, "Sending APPROVED response to client (fd=%d)", client_fd);
                send_client_response(ctx, client_fd, 0 /* APPROVED */, NULL);
            }

            /* Check if we have a pending forward for this tx_hash and complete it.
             * This handles the case where we (non-leader) forwarded a request,
             * participated in consensus, and now need to send the response to
             * our waiting client.
             */
            if (ctx->complete_forward_cb) {
                ctx->complete_forward_cb(saved_tx_hash, ctx->my_id, ctx->my_pubkey, ctx->callback_user_data);
            }

            return DNAC_BFT_SUCCESS;
        }
    }

    pthread_mutex_unlock(&ctx->mutex);
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_handle_commit(dnac_bft_context_t *ctx,
                           const dnac_bft_commit_t *commit) {
    if (!ctx || !commit) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    /* Gap 23-24 Fix (v0.6.0): Check for replay attack */
    if (is_replay(commit->header.sender_id, commit->header.nonce,
                  commit->header.timestamp)) {
        QGP_LOG_WARN(LOG_TAG, "Commit replay detected, ignoring");
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    /* v0.9.0: Skip if we already committed this round (avoids duplicate blocks) */
    pthread_mutex_lock(&ctx->mutex);
    bool already_committed = (commit->header.round <= ctx->last_committed_round);
    pthread_mutex_unlock(&ctx->mutex);
    if (already_committed) {
        QGP_LOG_DEBUG(LOG_TAG, "Round %lu already committed, skipping remote COMMIT",
                     (unsigned long)commit->header.round);
        return DNAC_BFT_SUCCESS;
    }

    /* v0.4.0: Add ALL nullifiers to our database
     * v0.6.0: Wrapped in transaction for atomicity (Gap 11) */
    QGP_LOG_INFO(LOG_TAG, "Received COMMIT for round %lu (%d nullifiers)",
                (unsigned long)commit->header.round, commit->nullifier_count);

    /* Begin transaction for atomicity */
    if (ctx->db_begin_cb) {
        if (ctx->db_begin_cb(ctx->callback_user_data) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to begin transaction for COMMIT");
            return DNAC_BFT_ERROR_INVALID_MESSAGE;
        }
    }

    bool any_failed = false;
    for (int i = 0; i < commit->nullifier_count; i++) {
        int rc = nullifier_add(ctx, commit->nullifiers[i], commit->tx_hash);
        if (rc != 0 && rc != -2) {  /* -2 = already exists, which is ok */
            QGP_LOG_ERROR(LOG_TAG, "Failed to add nullifier %d from COMMIT", i);
            any_failed = true;
            break;
        }
    }

    /* v0.8.0: Update UTXO set within the same atomic transaction */
    if (!any_failed) {
        if (bft_update_utxo_set(ctx,
                                 commit->tx_data,
                                 commit->tx_len,
                                 commit->tx_hash,
                                 commit->tx_type) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to update UTXO set from remote COMMIT");
            any_failed = true;
        }
    }

    /* Rollback on failure, commit on success */
    if (any_failed) {
        if (ctx->db_rollback_cb) ctx->db_rollback_cb(ctx->callback_user_data);
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }
    if (ctx->db_commit_cb) {
        if (ctx->db_commit_cb(ctx->callback_user_data) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to commit transaction for COMMIT");
            if (ctx->db_rollback_cb) ctx->db_rollback_cb(ctx->callback_user_data);
            return DNAC_BFT_ERROR_INVALID_MESSAGE;
        }
    }

    /* v0.9.0: Add ledger entry for audit trail (fixes pre-existing gap in remote COMMIT path) */
    if (ctx->ledger_add_cb) {
        int rc = ctx->ledger_add_cb(commit->tx_hash,
                                     commit->tx_type,
                                     (const uint8_t (*)[DNAC_NULLIFIER_SIZE])commit->nullifiers,
                                     commit->nullifier_count,
                                     ctx->callback_user_data);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to add ledger entry from remote COMMIT: %d", rc);
        }
    }

    /* v0.9.0: Create block wrapping this committed TX */
    if (ctx->block_create_cb) {
        ctx->block_create_cb(commit->tx_hash,
                             commit->tx_type,
                             commit->proposal_timestamp,
                             commit->proposer_id,
                             ctx->callback_user_data);
    }

    pthread_mutex_lock(&ctx->mutex);

    if (commit->header.round > ctx->last_committed_round) {
        ctx->last_committed_round = commit->header.round;
    }

    /* Reset round state if this was our active round */
    if (ctx->round_state.round == commit->header.round) {
        ctx->round_state.phase = BFT_PHASE_IDLE;
    }

    pthread_mutex_unlock(&ctx->mutex);

    /* Check if we have a pending forward for this tx_hash.
     * This handles the case where we received COMMIT before reaching
     * PRECOMMIT quorum ourselves (which can happen due to message ordering).
     */
    if (ctx->complete_forward_cb) {
        ctx->complete_forward_cb(commit->tx_hash, ctx->my_id, ctx->my_pubkey, ctx->callback_user_data);
    }

    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Timeout Handling
 * ========================================================================== */

int dnac_bft_check_timeout(dnac_bft_context_t *ctx) {
    if (!ctx) return DNAC_BFT_ERROR_INVALID_PARAM;

    pthread_mutex_lock(&ctx->mutex);

    if (ctx->round_state.phase == BFT_PHASE_IDLE) {
        pthread_mutex_unlock(&ctx->mutex);
        return 0;
    }

    uint64_t now = dnac_tcp_get_time_ms();
    uint64_t elapsed = now - ctx->round_state.phase_start_time;

    if (elapsed > ctx->config.round_timeout_ms) {
        QGP_LOG_WARN(LOG_TAG, "Round timeout! Initiating view change.");
        pthread_mutex_unlock(&ctx->mutex);
        return dnac_bft_initiate_view_change(ctx);
    }

    pthread_mutex_unlock(&ctx->mutex);
    return 0;
}

/* ============================================================================
 * View Change
 * ========================================================================== */

int dnac_bft_initiate_view_change(dnac_bft_context_t *ctx) {
    if (!ctx) return DNAC_BFT_ERROR_INVALID_PARAM;

    pthread_mutex_lock(&ctx->mutex);

    if (ctx->view_change_in_progress) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_SUCCESS;
    }

    ctx->view_change_in_progress = true;
    ctx->view_change_target = ctx->current_view + 1;
    ctx->view_change_count = 0;

    /* Create VIEW-CHANGE message */
    dnac_bft_view_change_t vc;
    memset(&vc, 0, sizeof(vc));

    vc.header.version = DNAC_BFT_PROTOCOL_VERSION;
    vc.header.type = BFT_MSG_VIEW_CHANGE;
    vc.header.round = ctx->current_round;
    vc.header.view = ctx->current_view;
    memcpy(vc.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
    vc.header.timestamp = time(NULL);
    vc.header.nonce = generate_nonce();  /* Gap 23-24: replay prevention */
    memcpy(vc.header.chain_id, ctx->chain_id, 32);  /* v0.10.0 */
    vc.new_view = ctx->view_change_target;
    vc.last_committed_round = ctx->last_committed_round;

    /* Sign VIEW-CHANGE with Dilithium5 (Gap 5: v0.6.0) */
    uint8_t vc_sign_data[256];
    size_t vc_sign_len;
    if (bft_build_view_change_sign_data(&vc, vc_sign_data, &vc_sign_len) != 0) {
        pthread_mutex_unlock(&ctx->mutex);
        QGP_LOG_ERROR(LOG_TAG, "Failed to build view change signing data");
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }
    if (bft_sign_message(ctx, vc.signature, vc_sign_data, vc_sign_len) != 0) {
        pthread_mutex_unlock(&ctx->mutex);
        QGP_LOG_ERROR(LOG_TAG, "Failed to sign VIEW-CHANGE");
        return DNAC_BFT_ERROR_INVALID_SIGNATURE;
    }

    /* Record our own view change vote */
    memcpy(ctx->view_changes[0].voter_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
    ctx->view_changes[0].target_view = ctx->view_change_target;
    ctx->view_changes[0].last_committed_round = ctx->last_committed_round;
    ctx->view_change_count = 1;

    pthread_mutex_unlock(&ctx->mutex);

    /* Broadcast */
    uint8_t buffer[8192];
    size_t written;

    int rc = dnac_bft_view_change_serialize(&vc, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                            sizeof(buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                            &written);
    if (rc == DNAC_BFT_SUCCESS) {
        dnac_tcp_write_frame_header(buffer, BFT_MSG_VIEW_CHANGE, (uint32_t)written);
        /* Gap 15 Fix (v0.6.0): Log broadcast failures */
        int sent = bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
        if (sent < (int)ctx->roster.n_witnesses - 1) {
            QGP_LOG_WARN(LOG_TAG, "VIEW_CHANGE broadcast only reached %d/%u peers",
                         sent, ctx->roster.n_witnesses - 1);
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Initiated view change to view %u", ctx->view_change_target);
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_handle_view_change(dnac_bft_context_t *ctx,
                                const dnac_bft_view_change_t *vc) {
    if (!ctx || !vc) return DNAC_BFT_ERROR_INVALID_PARAM;

    /* Gap 23-24 Fix (v0.6.0): Check for replay attack */
    if (is_replay(vc->header.sender_id, vc->header.nonce,
                  vc->header.timestamp)) {
        QGP_LOG_WARN(LOG_TAG, "View change replay detected, ignoring");
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    pthread_mutex_lock(&ctx->mutex);

    /* Verify sender is in roster */
    int sender_index = dnac_bft_roster_find(&ctx->roster, vc->header.sender_id);
    if (sender_index < 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }

    /* Verify view change signature (v0.6.0) */
    if (bft_verify_view_change_signature(ctx, vc) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Invalid VIEW-CHANGE signature from roster %d", sender_index);
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_SIGNATURE;
    }

    /* Check if this is for a valid future view */
    if (vc->new_view <= ctx->current_view) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_SUCCESS;
    }

    /* Update view change target if higher */
    if (!ctx->view_change_in_progress || vc->new_view > ctx->view_change_target) {
        ctx->view_change_in_progress = true;
        ctx->view_change_target = vc->new_view;
        ctx->view_change_count = 0;
    }

    /* Record vote (if for current target) */
    if (vc->new_view == ctx->view_change_target) {
        /* Check for duplicate */
        for (int i = 0; i < ctx->view_change_count; i++) {
            if (memcmp(ctx->view_changes[i].voter_id, vc->header.sender_id,
                       DNAC_BFT_WITNESS_ID_SIZE) == 0) {
                pthread_mutex_unlock(&ctx->mutex);
                return DNAC_BFT_SUCCESS;
            }
        }

        if (ctx->view_change_count < DNAC_BFT_MAX_WITNESSES) {
            memcpy(ctx->view_changes[ctx->view_change_count].voter_id,
                   vc->header.sender_id, DNAC_BFT_WITNESS_ID_SIZE);
            ctx->view_changes[ctx->view_change_count].target_view = vc->new_view;
            ctx->view_changes[ctx->view_change_count].last_committed_round =
                vc->last_committed_round;
            ctx->view_change_count++;
        }

        QGP_LOG_DEBUG(LOG_TAG, "VIEW-CHANGE from roster %d: view %u (%d/%u)",
                     sender_index, vc->new_view, ctx->view_change_count,
                     ctx->config.quorum);

        /* Check for quorum */
        if ((uint32_t)ctx->view_change_count >= ctx->config.quorum) {
            QGP_LOG_INFO(LOG_TAG, "View change quorum reached! New view: %u",
                        ctx->view_change_target);

            ctx->current_view = ctx->view_change_target;
            ctx->view_change_in_progress = false;
            ctx->round_state.phase = BFT_PHASE_IDLE;

            /* If we are new leader, send NEW-VIEW */
            uint64_t epoch = time(NULL) / DNAC_EPOCH_DURATION_SEC;
            int new_leader = dnac_bft_get_leader_index(epoch, ctx->current_view,
                                                       ctx->roster.n_witnesses);

            if (new_leader == ctx->my_index) {
                QGP_LOG_INFO(LOG_TAG, "We are new leader for view %u", ctx->current_view);

                /* Create NEW-VIEW message */
                dnac_bft_new_view_t nv;
                memset(&nv, 0, sizeof(nv));

                nv.header.version = DNAC_BFT_PROTOCOL_VERSION;
                nv.header.type = BFT_MSG_NEW_VIEW;
                nv.header.round = ctx->current_round;
                nv.header.view = ctx->current_view;
                memcpy(nv.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
                nv.header.timestamp = time(NULL);
                nv.header.nonce = generate_nonce();  /* Gap 23-24: replay prevention */
                memcpy(nv.header.chain_id, ctx->chain_id, 32);  /* v0.10.0 */
                nv.new_view = ctx->current_view;
                nv.n_view_change_proofs = ctx->view_change_count;

                /* Sign NEW-VIEW with Dilithium5 (Gap 6: v0.6.0) */
                uint8_t nv_sign_data[256];
                size_t nv_sign_len;
                if (bft_build_new_view_sign_data(&nv, nv_sign_data, &nv_sign_len) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Failed to build NEW-VIEW signing data");
                } else if (bft_sign_message(ctx, nv.signature, nv_sign_data, nv_sign_len) != 0) {
                    QGP_LOG_ERROR(LOG_TAG, "Failed to sign NEW-VIEW");
                } else {
                    /* Serialize and broadcast NEW-VIEW */
                    uint8_t buffer[8192];
                    size_t written;
                    if (dnac_bft_new_view_serialize(&nv, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                                    sizeof(buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                                    &written) == DNAC_BFT_SUCCESS) {
                        dnac_tcp_write_frame_header(buffer, BFT_MSG_NEW_VIEW, (uint32_t)written);
                        int sent = bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
                        QGP_LOG_INFO(LOG_TAG, "NEW-VIEW broadcast to %d peers for view %u",
                                    sent, ctx->current_view);
                    }
                }
            }
        }
    }

    pthread_mutex_unlock(&ctx->mutex);
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_handle_new_view(dnac_bft_context_t *ctx,
                             const dnac_bft_new_view_t *nv) {
    if (!ctx || !nv) return DNAC_BFT_ERROR_INVALID_PARAM;

    pthread_mutex_lock(&ctx->mutex);

    /* Verify this is from new leader */
    uint64_t epoch = time(NULL) / DNAC_EPOCH_DURATION_SEC;
    int expected_leader = dnac_bft_get_leader_index(epoch, nv->new_view,
                                                    ctx->roster.n_witnesses);

    int sender_index = dnac_bft_roster_find(&ctx->roster, nv->header.sender_id);
    if (sender_index != expected_leader) {
        QGP_LOG_WARN(LOG_TAG, "NEW-VIEW from non-leader");
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_NOT_LEADER;
    }

    /* Verify NEW-VIEW signature (v0.6.0) */
    uint8_t nv_sign_data[256];
    size_t nv_sign_len;
    if (bft_build_new_view_sign_data(nv, nv_sign_data, &nv_sign_len) != 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
    }
    if (bft_verify_signature(ctx, nv->header.sender_id, nv->signature,
                              nv_sign_data, nv_sign_len) != 0) {
        QGP_LOG_WARN(LOG_TAG, "Invalid NEW-VIEW signature from leader %d", sender_index);
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_SIGNATURE;
    }

    /* Accept new view */
    if (nv->new_view > ctx->current_view) {
        ctx->current_view = nv->new_view;
        ctx->view_change_in_progress = false;
        ctx->round_state.phase = BFT_PHASE_IDLE;

        QGP_LOG_INFO(LOG_TAG, "Accepted NEW-VIEW %u from leader %d",
                    nv->new_view, sender_index);
    }

    pthread_mutex_unlock(&ctx->mutex);
    return DNAC_BFT_SUCCESS;
}

/* ============================================================================
 * Roster Functions
 * ========================================================================== */

int dnac_bft_roster_find(const dnac_roster_t *roster, const uint8_t *witness_id) {
    if (!roster || !witness_id) return -1;

    for (uint32_t i = 0; i < roster->n_witnesses; i++) {
        if (memcmp(roster->witnesses[i].witness_id, witness_id,
                   DNAC_BFT_WITNESS_ID_SIZE) == 0) {
            return (int)i;
        }
    }

    return -1;
}

int dnac_bft_roster_add(dnac_bft_context_t *ctx, const dnac_roster_entry_t *entry) {
    if (!ctx || !entry) return DNAC_BFT_ERROR_INVALID_PARAM;

    pthread_mutex_lock(&ctx->mutex);

    if (ctx->roster.n_witnesses >= DNAC_BFT_MAX_WITNESSES) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_ROSTER_FULL;
    }

    /* Check for duplicate */
    if (dnac_bft_roster_find(&ctx->roster, entry->witness_id) >= 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_SUCCESS;  /* Already in roster */
    }

    /* Add entry */
    memcpy(&ctx->roster.witnesses[ctx->roster.n_witnesses], entry,
           sizeof(dnac_roster_entry_t));
    ctx->roster.n_witnesses++;
    ctx->roster.version++;

    /* Recalculate config */
    dnac_bft_config_init(&ctx->config, ctx->roster.n_witnesses);

    /* Update our index */
    ctx->my_index = dnac_bft_roster_find(&ctx->roster, ctx->my_id);

    pthread_mutex_unlock(&ctx->mutex);

    QGP_LOG_INFO(LOG_TAG, "Added witness to roster (now %u witnesses)",
                ctx->roster.n_witnesses);

    return DNAC_BFT_SUCCESS;
}

int dnac_bft_load_roster(dnac_bft_context_t *ctx) {
    /* TODO: Load from DHT */
    (void)ctx;
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_save_roster(dnac_bft_context_t *ctx) {
    /* TODO: Save to DHT */
    (void)ctx;
    return DNAC_BFT_SUCCESS;
}
