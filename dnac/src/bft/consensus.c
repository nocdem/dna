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
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "BFT_CONSENSUS"

/* External peer functions */
extern int bft_peer_broadcast(const uint8_t *data, size_t len, int exclude_roster_index);
extern int bft_peer_send_to_leader(const uint8_t *data, size_t len);
extern int bft_peer_send_to(int roster_index, const uint8_t *data, size_t len);

/* Helper functions that use callbacks */
static bool nullifier_exists(dnac_bft_context_t *ctx, const uint8_t *nullifier) {
    if (ctx && ctx->nullifier_exists_cb) {
        return ctx->nullifier_exists_cb(nullifier);
    }
    return false;  /* Assume not exists if no callback */
}

static int nullifier_add(dnac_bft_context_t *ctx, const uint8_t *nullifier, const uint8_t *tx_hash) {
    if (ctx && ctx->nullifier_add_cb) {
        return ctx->nullifier_add_cb(nullifier, tx_hash);
    }
    return 0;  /* Silently succeed if no callback */
}

static void send_client_response(dnac_bft_context_t *ctx, int client_fd, int status, const char *error_msg) {
    if (ctx && ctx->send_response_cb) {
        ctx->send_response_cb(client_fd, status, error_msg);
    }
}

/* ============================================================================
 * Callback Setup
 * ========================================================================== */

void dnac_bft_set_callbacks(dnac_bft_context_t *ctx,
                            dnac_bft_nullifier_exists_fn exists_cb,
                            dnac_bft_nullifier_add_fn add_cb,
                            dnac_bft_send_response_fn response_cb,
                            dnac_bft_complete_forward_fn forward_cb,
                            void *user_data) {
    if (!ctx) return;
    ctx->nullifier_exists_cb = exists_cb;
    ctx->nullifier_add_cb = add_cb;
    ctx->send_response_cb = response_cb;
    ctx->complete_forward_cb = forward_cb;
    ctx->callback_user_data = user_data;
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

    uint64_t epoch = time(NULL) / 3600;
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
 * Consensus Protocol
 * ========================================================================== */

int dnac_bft_start_round(dnac_bft_context_t *ctx,
                         const uint8_t *tx_hash,
                         const uint8_t nullifiers[][DNAC_NULLIFIER_SIZE],
                         uint8_t nullifier_count,
                         const uint8_t *client_pubkey,
                         const uint8_t *client_sig,
                         uint64_t fee_amount) {
    if (!ctx || !tx_hash || !nullifiers || nullifier_count == 0) {
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

    /* v0.4.0: Store ALL nullifiers in round state */
    ctx->round_state.nullifier_count = nullifier_count;
    for (int i = 0; i < nullifier_count; i++) {
        memcpy(ctx->round_state.nullifiers[i], nullifiers[i], DNAC_NULLIFIER_SIZE);
    }

    ctx->round_state.phase_start_time = dnac_tcp_get_time_ms();

    if (client_pubkey) {
        memcpy(ctx->round_state.client_pubkey, client_pubkey, DNAC_PUBKEY_SIZE);
    }
    if (client_sig) {
        memcpy(ctx->round_state.client_signature, client_sig, DNAC_SIGNATURE_SIZE);
    }
    ctx->round_state.fee_amount = fee_amount;

    /* Create proposal message with ALL nullifiers */
    dnac_bft_proposal_t proposal;
    memset(&proposal, 0, sizeof(proposal));

    proposal.header.version = DNAC_BFT_PROTOCOL_VERSION;
    proposal.header.type = BFT_MSG_PROPOSAL;
    proposal.header.round = ctx->current_round;
    proposal.header.view = ctx->current_view;
    memcpy(proposal.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
    proposal.header.timestamp = time(NULL);

    memcpy(proposal.tx_hash, tx_hash, DNAC_TX_HASH_SIZE);
    proposal.nullifier_count = nullifier_count;
    for (int i = 0; i < nullifier_count; i++) {
        memcpy(proposal.nullifiers[i], nullifiers[i], DNAC_NULLIFIER_SIZE);
    }
    if (client_pubkey) {
        memcpy(proposal.sender_pubkey, client_pubkey, DNAC_PUBKEY_SIZE);
    }
    if (client_sig) {
        memcpy(proposal.client_signature, client_sig, DNAC_SIGNATURE_SIZE);
    }
    proposal.fee_amount = fee_amount;

    /* TODO: Sign proposal with ctx->my_privkey */

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

    /* Serialize and broadcast */
    uint8_t buffer[16384];
    size_t written;

    int rc = dnac_bft_proposal_serialize(&proposal, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                         sizeof(buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                         &written);
    if (rc != DNAC_BFT_SUCCESS) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize proposal");
        return rc;
    }

    dnac_tcp_write_frame_header(buffer, BFT_MSG_PROPOSAL, (uint32_t)written);

    int sent = bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
    QGP_LOG_INFO(LOG_TAG, "Proposal broadcast to %d peers (round %lu, %d nullifiers)",
                sent, (unsigned long)ctx->current_round, nullifier_count);

    return DNAC_BFT_SUCCESS;
}

int dnac_bft_handle_proposal(dnac_bft_context_t *ctx,
                             const dnac_bft_proposal_t *proposal) {
    if (!ctx || !proposal) {
        return DNAC_BFT_ERROR_INVALID_PARAM;
    }

    pthread_mutex_lock(&ctx->mutex);

    /* Verify proposal is from current leader */
    uint64_t epoch = time(NULL) / 3600;
    int leader = dnac_bft_get_leader_index(epoch, proposal->header.view,
                                           ctx->roster.n_witnesses);

    int sender_index = dnac_bft_roster_find(&ctx->roster, proposal->header.sender_id);
    if (sender_index != leader) {
        QGP_LOG_WARN(LOG_TAG, "Proposal from non-leader (sender %d, leader %d)",
                    sender_index, leader);
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_NOT_LEADER;
    }

    /* TODO: Verify signature */

    /* v0.4.0: Check ALL nullifiers locally for double-spend */
    bool double_spend = false;
    for (int i = 0; i < proposal->nullifier_count; i++) {
        if (nullifier_exists(ctx, proposal->nullifiers[i])) {
            QGP_LOG_WARN(LOG_TAG, "Nullifier %d already spent", i);
            double_spend = true;
            break;
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

    /* v0.4.0: Store ALL nullifiers from proposal */
    ctx->round_state.nullifier_count = proposal->nullifier_count;
    for (int i = 0; i < proposal->nullifier_count; i++) {
        memcpy(ctx->round_state.nullifiers[i], proposal->nullifiers[i], DNAC_NULLIFIER_SIZE);
    }

    memcpy(ctx->round_state.client_pubkey, proposal->sender_pubkey, DNAC_PUBKEY_SIZE);
    memcpy(ctx->round_state.client_signature, proposal->client_signature, DNAC_SIGNATURE_SIZE);
    ctx->round_state.fee_amount = proposal->fee_amount;
    ctx->round_state.phase_start_time = dnac_tcp_get_time_ms();

    /* Create PREVOTE message */
    dnac_bft_vote_msg_t vote;
    memset(&vote, 0, sizeof(vote));

    vote.header.version = DNAC_BFT_PROTOCOL_VERSION;
    vote.header.type = BFT_MSG_PREVOTE;
    vote.header.round = proposal->header.round;
    vote.header.view = proposal->header.view;
    memcpy(vote.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
    vote.header.timestamp = time(NULL);

    memcpy(vote.tx_hash, proposal->tx_hash, DNAC_TX_HASH_SIZE);
    vote.vote = double_spend ? BFT_VOTE_REJECT : BFT_VOTE_APPROVE;

    if (double_spend) {
        strncpy(vote.reason, "Nullifier already spent", sizeof(vote.reason) - 1);
    }

    /* TODO: Sign vote */

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

    bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);

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

    /* TODO: Verify signature */

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

    /* Check for quorum */
    if ((uint32_t)*approve_count >= ctx->config.quorum) {
        fprintf(stderr, "[CONSENSUS] QUORUM REACHED! approve=%d >= quorum=%u\n",
                *approve_count, ctx->config.quorum);
        fflush(stderr);
        QGP_LOG_INFO(LOG_TAG, "%s quorum reached!",
                    vote->header.type == BFT_MSG_PREVOTE ? "PREVOTE" : "PRECOMMIT");

        ctx->round_state.phase = next_phase;
        ctx->round_state.phase_start_time = dnac_tcp_get_time_ms();

        /* Create next phase message */
        if (next_msg_type == BFT_MSG_PRECOMMIT) {
            /* Send PRECOMMIT */
            dnac_bft_vote_msg_t precommit;
            memset(&precommit, 0, sizeof(precommit));

            precommit.header.version = DNAC_BFT_PROTOCOL_VERSION;
            precommit.header.type = BFT_MSG_PRECOMMIT;
            precommit.header.round = ctx->round_state.round;
            precommit.header.view = ctx->round_state.view;
            memcpy(precommit.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
            precommit.header.timestamp = time(NULL);
            memcpy(precommit.tx_hash, ctx->round_state.tx_hash, DNAC_TX_HASH_SIZE);
            precommit.vote = BFT_VOTE_APPROVE;

            pthread_mutex_unlock(&ctx->mutex);

            uint8_t buffer[8192];
            size_t written;

            if (dnac_bft_vote_serialize(&precommit, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                        sizeof(buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                        &written) == DNAC_BFT_SUCCESS) {
                dnac_tcp_write_frame_header(buffer, BFT_MSG_PRECOMMIT, (uint32_t)written);
                bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
            }

            return DNAC_BFT_SUCCESS;

        } else if (next_msg_type == BFT_MSG_COMMIT) {
            /* v0.4.0: COMMIT phase - add ALL nullifiers to database */
            QGP_LOG_INFO(LOG_TAG, "COMMIT: Adding %d nullifiers to database",
                        ctx->round_state.nullifier_count);

            for (int i = 0; i < ctx->round_state.nullifier_count; i++) {
                int rc = nullifier_add(ctx, ctx->round_state.nullifiers[i],
                                       ctx->round_state.tx_hash);
                if (rc != 0 && rc != -2) {  /* -2 = already exists, which is ok */
                    QGP_LOG_ERROR(LOG_TAG, "Failed to add nullifier %d", i);
                }
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

            /* Send COMMIT message with ALL nullifiers */
            dnac_bft_commit_t commit;
            memset(&commit, 0, sizeof(commit));

            commit.header.version = DNAC_BFT_PROTOCOL_VERSION;
            commit.header.type = BFT_MSG_COMMIT;
            commit.header.round = ctx->round_state.round;
            commit.header.view = ctx->round_state.view;
            memcpy(commit.header.sender_id, ctx->my_id, DNAC_BFT_WITNESS_ID_SIZE);
            commit.header.timestamp = time(NULL);
            memcpy(commit.tx_hash, ctx->round_state.tx_hash, DNAC_TX_HASH_SIZE);
            commit.nullifier_count = saved_nullifier_count;
            for (int i = 0; i < saved_nullifier_count; i++) {
                memcpy(commit.nullifiers[i], saved_nullifiers[i], DNAC_NULLIFIER_SIZE);
            }
            commit.n_precommits = ctx->round_state.precommit_count;

            /* Reset round state */
            ctx->round_state.phase = BFT_PHASE_IDLE;
            ctx->round_state.client_fd = -1;

            pthread_mutex_unlock(&ctx->mutex);

            uint8_t buffer[16384];
            size_t written;

            if (dnac_bft_commit_serialize(&commit, buffer + DNAC_TCP_FRAME_HEADER_SIZE,
                                          sizeof(buffer) - DNAC_TCP_FRAME_HEADER_SIZE,
                                          &written) == DNAC_BFT_SUCCESS) {
                dnac_tcp_write_frame_header(buffer, BFT_MSG_COMMIT, (uint32_t)written);
                bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
            }

            /* Send response to client (if we are leader and client connected directly) */
            if (!is_forwarded && client_fd >= 0) {
                QGP_LOG_INFO(LOG_TAG, "Sending APPROVED response to client (fd=%d)", client_fd);
                send_client_response(ctx,client_fd, 0 /* APPROVED */, NULL);
            }

            /* Check if we have a pending forward for this tx_hash and complete it.
             * This handles the case where we (non-leader) forwarded a request,
             * participated in consensus, and now need to send the response to
             * our waiting client.
             */
            if (ctx->complete_forward_cb) {
                ctx->complete_forward_cb(commit.tx_hash, ctx->my_id, ctx->my_pubkey);
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

    /* v0.4.0: Add ALL nullifiers to our database */
    QGP_LOG_INFO(LOG_TAG, "Received COMMIT for round %lu (%d nullifiers)",
                (unsigned long)commit->header.round, commit->nullifier_count);

    for (int i = 0; i < commit->nullifier_count; i++) {
        int rc = nullifier_add(ctx, commit->nullifiers[i], commit->tx_hash);
        if (rc != 0 && rc != -2) {  /* -2 = already exists, which is ok */
            QGP_LOG_ERROR(LOG_TAG, "Failed to add nullifier %d from COMMIT", i);
        }
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
        ctx->complete_forward_cb(commit->tx_hash, ctx->my_id, ctx->my_pubkey);
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
    vc.new_view = ctx->view_change_target;
    vc.last_committed_round = ctx->last_committed_round;

    /* TODO: Sign */

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
        bft_peer_broadcast(buffer, DNAC_TCP_FRAME_HEADER_SIZE + written, -1);
    }

    QGP_LOG_INFO(LOG_TAG, "Initiated view change to view %u", ctx->view_change_target);
    return DNAC_BFT_SUCCESS;
}

int dnac_bft_handle_view_change(dnac_bft_context_t *ctx,
                                const dnac_bft_view_change_t *vc) {
    if (!ctx || !vc) return DNAC_BFT_ERROR_INVALID_PARAM;

    pthread_mutex_lock(&ctx->mutex);

    /* Verify sender is in roster */
    int sender_index = dnac_bft_roster_find(&ctx->roster, vc->header.sender_id);
    if (sender_index < 0) {
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_INVALID_MESSAGE;
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
            uint64_t epoch = time(NULL) / 3600;
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
                nv.new_view = ctx->current_view;
                nv.n_view_change_proofs = ctx->view_change_count;

                /* TODO: Serialize and broadcast NEW-VIEW */
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
    uint64_t epoch = time(NULL) / 3600;
    int expected_leader = dnac_bft_get_leader_index(epoch, nv->new_view,
                                                    ctx->roster.n_witnesses);

    int sender_index = dnac_bft_roster_find(&ctx->roster, nv->header.sender_id);
    if (sender_index != expected_leader) {
        QGP_LOG_WARN(LOG_TAG, "NEW-VIEW from non-leader");
        pthread_mutex_unlock(&ctx->mutex);
        return DNAC_BFT_ERROR_NOT_LEADER;
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
