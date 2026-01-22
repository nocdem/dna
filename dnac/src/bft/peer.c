/**
 * @file peer.c
 * @brief BFT Peer Connection Management
 *
 * Manages TCP connections to peer witnesses, handles reconnection,
 * and tracks peer health.
 *
 * Copyright (c) 2026 nocdem
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "dnac/bft.h"
#include "dnac/tcp.h"
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "BFT_PEER"

/* ============================================================================
 * Peer Manager Context
 * ========================================================================== */

typedef struct {
    dnac_bft_context_t *bft_ctx;
    dnac_tcp_server_t *tcp_server;

    /* Connection tracking */
    struct {
        int roster_index;           /* Index in roster (-1 if not matched) */
        int peer_index;             /* Index in TCP server peers */
        uint64_t last_connect_attempt;
        int connect_failures;
        bool connected;
    } connections[DNAC_BFT_MAX_WITNESSES];

    int connection_count;

    /* Thread control */
    pthread_t reconnect_thread;
    bool running;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} bft_peer_manager_t;

static bft_peer_manager_t *g_peer_manager = NULL;

/* ============================================================================
 * Internal Functions
 * ========================================================================== */

static void* reconnect_thread_func(void *arg);

/* ============================================================================
 * Peer Manager Lifecycle
 * ========================================================================== */

int bft_peer_manager_init(dnac_bft_context_t *bft_ctx, dnac_tcp_server_t *tcp_server) {
    if (g_peer_manager) {
        QGP_LOG_WARN(LOG_TAG, "Peer manager already initialized");
        return 0;
    }

    g_peer_manager = calloc(1, sizeof(bft_peer_manager_t));
    if (!g_peer_manager) {
        return DNAC_BFT_ERROR_OUT_OF_MEMORY;
    }

    g_peer_manager->bft_ctx = bft_ctx;
    g_peer_manager->tcp_server = tcp_server;
    pthread_mutex_init(&g_peer_manager->mutex, NULL);
    pthread_cond_init(&g_peer_manager->cond, NULL);

    /* Initialize connections */
    for (int i = 0; i < DNAC_BFT_MAX_WITNESSES; i++) {
        g_peer_manager->connections[i].roster_index = -1;
        g_peer_manager->connections[i].peer_index = -1;
    }

    /* Start reconnect thread */
    g_peer_manager->running = true;
    if (pthread_create(&g_peer_manager->reconnect_thread, NULL,
                       reconnect_thread_func, g_peer_manager) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create reconnect thread");
        free(g_peer_manager);
        g_peer_manager = NULL;
        return DNAC_BFT_ERROR_NETWORK;
    }

    QGP_LOG_INFO(LOG_TAG, "Peer manager initialized");
    return DNAC_BFT_SUCCESS;
}

void bft_peer_manager_shutdown(void) {
    if (!g_peer_manager) return;

    /* Stop reconnect thread */
    pthread_mutex_lock(&g_peer_manager->mutex);
    g_peer_manager->running = false;
    pthread_cond_signal(&g_peer_manager->cond);
    pthread_mutex_unlock(&g_peer_manager->mutex);

    pthread_join(g_peer_manager->reconnect_thread, NULL);

    pthread_mutex_destroy(&g_peer_manager->mutex);
    pthread_cond_destroy(&g_peer_manager->cond);

    free(g_peer_manager);
    g_peer_manager = NULL;

    QGP_LOG_INFO(LOG_TAG, "Peer manager shutdown");
}

/* ============================================================================
 * Connection Management
 * ========================================================================== */

int bft_peer_connect_to_roster(void) {
    if (!g_peer_manager) return DNAC_BFT_ERROR_NOT_INITIALIZED;

    dnac_bft_context_t *ctx = g_peer_manager->bft_ctx;
    dnac_tcp_server_t *server = g_peer_manager->tcp_server;

    pthread_mutex_lock(&g_peer_manager->mutex);

    int connected = 0;
    fprintf(stderr, "[PEER] connect_to_roster: n_witnesses=%u my_index=%d\n",
            ctx->roster.n_witnesses, ctx->my_index);
    fflush(stderr);

    for (uint32_t i = 0; i < ctx->roster.n_witnesses; i++) {
        dnac_roster_entry_t *entry = &ctx->roster.witnesses[i];

        fprintf(stderr, "[PEER] roster[%u]: address=%s active=%d\n",
                i, entry->address, entry->active);
        fflush(stderr);

        /* Skip ourselves - compare by index since IDs may be placeholders */
        if ((int)i == ctx->my_index) {
            fprintf(stderr, "[PEER]   Skipping self (index %d)\n", ctx->my_index);
            fflush(stderr);
            continue;
        }

        /* Skip if not active */
        if (!entry->active) {
            continue;
        }

        /* Check if already connected */
        int peer_index = dnac_tcp_server_find_peer(server, entry->witness_id);
        if (peer_index >= 0) {
            g_peer_manager->connections[i].peer_index = peer_index;
            g_peer_manager->connections[i].connected = true;
            connected++;
            continue;
        }

        /* Try to connect */
        fprintf(stderr, "[PEER] Connecting to witness %u at %s\n", i, entry->address);
        fflush(stderr);
        QGP_LOG_INFO(LOG_TAG, "Connecting to witness %d at %s", i, entry->address);

        peer_index = dnac_tcp_server_connect(server, entry->address, entry->witness_id);
        if (peer_index >= 0) {
            g_peer_manager->connections[i].roster_index = i;
            g_peer_manager->connections[i].peer_index = peer_index;
            g_peer_manager->connections[i].connected = true;
            g_peer_manager->connections[i].connect_failures = 0;
            connected++;

            fprintf(stderr, "[PEER] Connected to witness %u (peer %d)\n", i, peer_index);
            fflush(stderr);
            QGP_LOG_INFO(LOG_TAG, "Connected to witness %d (peer %d)", i, peer_index);
        } else {
            g_peer_manager->connections[i].connect_failures++;
            g_peer_manager->connections[i].last_connect_attempt = dnac_tcp_get_time_ms();
            fprintf(stderr, "[PEER] Failed to connect to witness %u at %s\n", i, entry->address);
            fflush(stderr);
            QGP_LOG_WARN(LOG_TAG, "Failed to connect to witness %d at %s",
                        i, entry->address);
        }
    }

    pthread_mutex_unlock(&g_peer_manager->mutex);

    QGP_LOG_INFO(LOG_TAG, "Connected to %d/%u roster witnesses",
                connected, ctx->roster.n_witnesses - 1);

    return connected;
}

int bft_peer_send_to_leader(const uint8_t *data, size_t len) {
    if (!g_peer_manager) {
        fprintf(stderr, "[PEER] send_to_leader: not initialized\n");
        fflush(stderr);
        return DNAC_BFT_ERROR_NOT_INITIALIZED;
    }

    dnac_bft_context_t *ctx = g_peer_manager->bft_ctx;

    /* Get leader index */
    uint64_t epoch = time(NULL) / 3600;
    int leader_index = dnac_bft_get_leader_index(epoch, ctx->current_view,
                                                  ctx->roster.n_witnesses);

    fprintf(stderr, "[PEER] send_to_leader: epoch=%lu view=%u n=%u leader=%d my_index=%d\n",
            epoch, ctx->current_view, ctx->roster.n_witnesses, leader_index, ctx->my_index);
    fflush(stderr);

    if (leader_index < 0 || leader_index >= (int)ctx->roster.n_witnesses) {
        fprintf(stderr, "[PEER] Invalid leader index\n");
        fflush(stderr);
        QGP_LOG_ERROR(LOG_TAG, "Invalid leader index: %d", leader_index);
        return DNAC_BFT_ERROR_LEADER_FAILED;
    }

    /* Check if we are leader */
    if (leader_index == ctx->my_index) {
        fprintf(stderr, "[PEER] We are the leader\n");
        fflush(stderr);
        QGP_LOG_DEBUG(LOG_TAG, "We are the leader");
        return DNAC_BFT_ERROR_NOT_LEADER;  /* Caller should handle locally */
    }

    /* Find peer connection for leader */
    pthread_mutex_lock(&g_peer_manager->mutex);

    fprintf(stderr, "[PEER] Looking for leader (roster index %d) in connections:\n", leader_index);
    int peer_index = -1;
    for (int i = 0; i < DNAC_BFT_MAX_WITNESSES; i++) {
        if (g_peer_manager->connections[i].connected) {
            fprintf(stderr, "[PEER]   conn[%d]: roster=%d peer=%d connected=%d\n",
                    i, g_peer_manager->connections[i].roster_index,
                    g_peer_manager->connections[i].peer_index,
                    g_peer_manager->connections[i].connected);
        }
        if (g_peer_manager->connections[i].roster_index == leader_index &&
            g_peer_manager->connections[i].connected) {
            peer_index = g_peer_manager->connections[i].peer_index;
            break;
        }
    }
    fflush(stderr);

    pthread_mutex_unlock(&g_peer_manager->mutex);

    if (peer_index < 0) {
        fprintf(stderr, "[PEER] Leader (roster %d) not connected\n", leader_index);
        fflush(stderr);
        QGP_LOG_ERROR(LOG_TAG, "Leader (roster %d) not connected", leader_index);
        return DNAC_BFT_ERROR_PEER_NOT_FOUND;
    }

    fprintf(stderr, "[PEER] Sending to leader via peer_index %d\n", peer_index);
    fflush(stderr);

    /* Send */
    int rc = dnac_tcp_server_send(g_peer_manager->tcp_server, peer_index, data, len);
    if (rc < 0) {
        fprintf(stderr, "[PEER] Failed to send: rc=%d\n", rc);
        fflush(stderr);
        QGP_LOG_ERROR(LOG_TAG, "Failed to send to leader");
        return DNAC_BFT_ERROR_NETWORK;
    }

    fprintf(stderr, "[PEER] Sent %zu bytes to leader\n", len);
    fflush(stderr);
    return DNAC_BFT_SUCCESS;
}

int bft_peer_broadcast(const uint8_t *data, size_t len, int exclude_roster_index) {
    if (!g_peer_manager) return DNAC_BFT_ERROR_NOT_INITIALIZED;

    dnac_tcp_server_t *server = g_peer_manager->tcp_server;
    int sent = 0;

    pthread_mutex_lock(&g_peer_manager->mutex);

    for (int i = 0; i < DNAC_BFT_MAX_WITNESSES; i++) {
        if (!g_peer_manager->connections[i].connected) continue;
        if (g_peer_manager->connections[i].roster_index == exclude_roster_index) continue;

        int peer_index = g_peer_manager->connections[i].peer_index;

        pthread_mutex_unlock(&g_peer_manager->mutex);

        if (dnac_tcp_server_send(server, peer_index, data, len) == 0) {
            sent++;
        }

        pthread_mutex_lock(&g_peer_manager->mutex);
    }

    pthread_mutex_unlock(&g_peer_manager->mutex);

    QGP_LOG_DEBUG(LOG_TAG, "Broadcast message to %d peers", sent);
    return sent;
}

int bft_peer_send_to(int roster_index, const uint8_t *data, size_t len) {
    if (!g_peer_manager) return DNAC_BFT_ERROR_NOT_INITIALIZED;

    pthread_mutex_lock(&g_peer_manager->mutex);

    int peer_index = -1;
    for (int i = 0; i < DNAC_BFT_MAX_WITNESSES; i++) {
        if (g_peer_manager->connections[i].roster_index == roster_index &&
            g_peer_manager->connections[i].connected) {
            peer_index = g_peer_manager->connections[i].peer_index;
            break;
        }
    }

    pthread_mutex_unlock(&g_peer_manager->mutex);

    if (peer_index < 0) {
        return DNAC_BFT_ERROR_PEER_NOT_FOUND;
    }

    return dnac_tcp_server_send(g_peer_manager->tcp_server, peer_index, data, len);
}

int bft_peer_get_connected_count(void) {
    if (!g_peer_manager) return 0;

    int count = 0;
    pthread_mutex_lock(&g_peer_manager->mutex);

    for (int i = 0; i < DNAC_BFT_MAX_WITNESSES; i++) {
        if (g_peer_manager->connections[i].connected) {
            count++;
        }
    }

    pthread_mutex_unlock(&g_peer_manager->mutex);
    return count;
}

/* ============================================================================
 * Peer Event Handlers
 * ========================================================================== */

void bft_peer_on_connect(int peer_index, const uint8_t *peer_id) {
    if (!g_peer_manager) return;

    dnac_bft_context_t *ctx = g_peer_manager->bft_ctx;
    dnac_tcp_server_t *server = g_peer_manager->tcp_server;

    pthread_mutex_lock(&g_peer_manager->mutex);

    /* Find roster entry for this peer */
    int roster_index = dnac_bft_roster_find(&ctx->roster, peer_id);
    if (roster_index >= 0) {
        /* Check if we already have an outbound connection to this peer */
        if (g_peer_manager->connections[roster_index].connected &&
            g_peer_manager->connections[roster_index].peer_index >= 0) {
            /* We already have a connection - check if it's outbound */
            int existing_peer = g_peer_manager->connections[roster_index].peer_index;

            /* Get peer info to check if existing is outbound */
            bool existing_is_outbound = false;
            if (server && existing_peer >= 0 && existing_peer < DNAC_TCP_MAX_PEERS) {
                pthread_mutex_lock(&server->peer_mutex);
                if (server->peers[existing_peer].fd >= 0) {
                    existing_is_outbound = server->peers[existing_peer].is_outbound;
                }
                pthread_mutex_unlock(&server->peer_mutex);
            }

            if (existing_is_outbound) {
                /* Keep the outbound connection for sending, ignore this inbound one */
                fprintf(stderr, "[PEER] Already have outbound connection to roster %d (peer %d), "
                        "ignoring inbound peer %d\n", roster_index, existing_peer, peer_index);
                fflush(stderr);
                QGP_LOG_INFO(LOG_TAG, "Already have outbound connection to roster %d, "
                            "keeping peer %d", roster_index, existing_peer);
                pthread_mutex_unlock(&g_peer_manager->mutex);
                return;
            }
        }

        g_peer_manager->connections[roster_index].roster_index = roster_index;
        g_peer_manager->connections[roster_index].peer_index = peer_index;
        g_peer_manager->connections[roster_index].connected = true;
        g_peer_manager->connections[roster_index].connect_failures = 0;

        fprintf(stderr, "[PEER] Peer connected: roster %d, peer %d\n",
                roster_index, peer_index);
        fflush(stderr);
        QGP_LOG_INFO(LOG_TAG, "Peer connected: roster %d, peer %d",
                    roster_index, peer_index);
    } else {
        fprintf(stderr, "[PEER] Unknown peer connected (not in roster): peer %d\n", peer_index);
        fflush(stderr);
        QGP_LOG_WARN(LOG_TAG, "Unknown peer connected (not in roster)");
    }

    pthread_mutex_unlock(&g_peer_manager->mutex);
}

void bft_peer_on_disconnect(int peer_index) {
    if (!g_peer_manager) return;

    pthread_mutex_lock(&g_peer_manager->mutex);

    for (int i = 0; i < DNAC_BFT_MAX_WITNESSES; i++) {
        if (g_peer_manager->connections[i].peer_index == peer_index) {
            g_peer_manager->connections[i].connected = false;
            g_peer_manager->connections[i].peer_index = -1;

            QGP_LOG_INFO(LOG_TAG, "Peer disconnected: roster %d", i);

            /* Wake reconnect thread */
            pthread_cond_signal(&g_peer_manager->cond);
            break;
        }
    }

    pthread_mutex_unlock(&g_peer_manager->mutex);
}

/* ============================================================================
 * Reconnect Thread
 * ========================================================================== */

static void* reconnect_thread_func(void *arg) {
    bft_peer_manager_t *mgr = (bft_peer_manager_t*)arg;

    fprintf(stderr, "[PEER] Reconnect thread started\n");
    fflush(stderr);
    QGP_LOG_DEBUG(LOG_TAG, "Reconnect thread started");

    while (1) {
        pthread_mutex_lock(&mgr->mutex);

        /* Wait for signal or timeout */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += DNAC_TCP_RECONNECT_INTERVAL;

        pthread_cond_timedwait(&mgr->cond, &mgr->mutex, &ts);

        if (!mgr->running) {
            pthread_mutex_unlock(&mgr->mutex);
            break;
        }

        /* Check for disconnected peers that need reconnection */
        dnac_bft_context_t *ctx = mgr->bft_ctx;
        uint64_t now = dnac_tcp_get_time_ms();

        fprintf(stderr, "[PEER] Reconnect check: n_witnesses=%u\n", ctx->roster.n_witnesses);
        fflush(stderr);

        for (uint32_t i = 0; i < ctx->roster.n_witnesses; i++) {
            dnac_roster_entry_t *entry = &ctx->roster.witnesses[i];

            /* Skip ourselves - use index for reliability */
            if ((int)i == ctx->my_index) {
                continue;
            }

            /* Skip if inactive or already connected */
            if (!entry->active || mgr->connections[i].connected) {
                continue;
            }

            /* Check reconnect interval with exponential backoff */
            uint64_t backoff = DNAC_TCP_RECONNECT_INTERVAL * 1000;
            int failures = mgr->connections[i].connect_failures;
            if (failures > 0) {
                backoff *= (1 << (failures > 5 ? 5 : failures));  /* Max 32x backoff */
            }

            uint64_t elapsed = now - mgr->connections[i].last_connect_attempt;
            if (elapsed < backoff) {
                continue;
            }

            pthread_mutex_unlock(&mgr->mutex);

            /* Try to connect */
            fprintf(stderr, "[PEER] Reconnect attempt: witness %u at %s (failures=%d)\n",
                    i, entry->address, failures);
            fflush(stderr);
            QGP_LOG_DEBUG(LOG_TAG, "Attempting reconnect to witness %d at %s",
                         i, entry->address);

            int peer_index = dnac_tcp_server_connect(mgr->tcp_server,
                                                     entry->address,
                                                     entry->witness_id);

            pthread_mutex_lock(&mgr->mutex);

            if (peer_index >= 0) {
                mgr->connections[i].roster_index = i;
                mgr->connections[i].peer_index = peer_index;
                mgr->connections[i].connected = true;
                mgr->connections[i].connect_failures = 0;

                fprintf(stderr, "[PEER] Reconnected to witness %u (peer %d)\n", i, peer_index);
                fflush(stderr);
                QGP_LOG_INFO(LOG_TAG, "Reconnected to witness %d", i);
            } else {
                mgr->connections[i].connect_failures++;
                mgr->connections[i].last_connect_attempt = now;
                fprintf(stderr, "[PEER] Reconnect failed for witness %u\n", i);
                fflush(stderr);
            }
        }

        pthread_mutex_unlock(&mgr->mutex);
    }

    QGP_LOG_DEBUG(LOG_TAG, "Reconnect thread exiting");
    return NULL;
}

/* ============================================================================
 * Utility Functions
 * ========================================================================== */

const char* bft_peer_get_address(int roster_index) {
    if (!g_peer_manager) return NULL;

    dnac_bft_context_t *ctx = g_peer_manager->bft_ctx;

    if (roster_index < 0 || roster_index >= (int)ctx->roster.n_witnesses) {
        return NULL;
    }

    return ctx->roster.witnesses[roster_index].address;
}

bool bft_peer_is_connected(int roster_index) {
    if (!g_peer_manager) return false;

    if (roster_index < 0 || roster_index >= DNAC_BFT_MAX_WITNESSES) {
        return false;
    }

    pthread_mutex_lock(&g_peer_manager->mutex);
    bool connected = g_peer_manager->connections[roster_index].connected;
    pthread_mutex_unlock(&g_peer_manager->mutex);

    return connected;
}
