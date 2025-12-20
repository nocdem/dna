/**
 * transport_juice.c - ICE Transport Implementation using libjuice
 *
 * Drop-in replacement for transport_ice.c (libnice + glib)
 * Uses libjuice for NAT traversal (STUN+ICE, no TURN)
 *
 * Part of Phase 11: Decentralized NAT Traversal
 * Migration: libnice + glib → libjuice (no glib dependency)
 *
 * Benefits:
 * - No glib dependency (simpler cross-compilation)
 * - Smaller binaries (~50MB → ~500KB)
 * - Simpler code (no event loop thread, direct callbacks)
 *
 * Preserved features:
 * - Same API as transport_ice.h (drop-in replacement)
 * - Message queue (16 messages max) for data loss prevention
 * - Timeout-based blocking receive with pthread_cond
 * - DHT-based candidate exchange (SHA3-512 keys, 7-day TTL)
 * - Security fixes from Phase 11 (use-after-free prevention, buffer overflow checks)
 */

#include "transport_ice.h"
#include "transport_core.h"
#include "turn_credentials.h"
#include "../../dht/core/dht_context.h"
#include "../../dht/client/dht_singleton.h"
#include "../../crypto/utils/qgp_sha3.h"

// Windows static linking: define JUICE_STATIC to avoid dllimport declarations
#ifdef _WIN32
#define JUICE_STATIC
#endif

#include <juice/juice.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "P2P_ICE"
#endif

#define MAX_CANDIDATES_SIZE 4096
#define MAX_MESSAGE_QUEUE_SIZE 16  // Maximum number of queued messages

/**
 * Message structure for receive queue
 * Stores individual received messages
 */
typedef struct {
    uint8_t *data;      // Message data (dynamically allocated)
    size_t len;         // Message length
} ice_message_t;

/**
 * Message queue structure (replaces GQueue)
 * Fixed-size circular buffer with pthread synchronization
 */
typedef struct {
    ice_message_t *messages[MAX_MESSAGE_QUEUE_SIZE];
    size_t head;        // Next dequeue position
    size_t tail;        // Next enqueue position
    size_t count;       // Current message count
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} message_queue_t;

/**
 * ICE context structure
 *
 * Contains:
 * - libjuice agent for ICE operations
 * - Local and remote candidates (SDP format)
 * - Connection state with pthread synchronization
 * - Message queue for incoming data (callback-based)
 */
struct ice_context {
    juice_agent_t *agent;          // libjuice agent
    char stun_server[256];         // STUN server hostname
    uint16_t stun_port;            // STUN server port

    // TURN server info (used when STUN fails)
    char turn_server[256];         // TURN server hostname
    uint16_t turn_port;            // TURN server port
    char turn_username[128];       // TURN username
    char turn_password[128];       // TURN password
    int turn_enabled;              // TURN is configured

    char local_candidates[MAX_CANDIDATES_SIZE];   // SDP-formatted local candidates
    char remote_candidates[MAX_CANDIDATES_SIZE];  // SDP-formatted remote candidates

    // Connection state
    volatile int connected;        // Connection state (0 = not connected, 1 = connected)
    volatile int gathering_done;   // Candidate gathering complete flag
    pthread_mutex_t state_mutex;
    pthread_cond_t state_cond;

    // Candidate gathering state
    pthread_mutex_t gathering_mutex;
    pthread_cond_t gathering_cond;

    // Local candidates accumulation
    pthread_mutex_t candidates_mutex;
    size_t candidates_len;         // Current length of local_candidates string

    // Message queue (callback-based receiving)
    message_queue_t *recv_queue;
};

// =============================================================================
// Message Queue Operations (replaces GQueue)
// =============================================================================

static message_queue_t* queue_new(void) {
    message_queue_t *q = calloc(1, sizeof(message_queue_t));
    if (!q) return NULL;

    q->head = 0;
    q->tail = 0;
    q->count = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);

    return q;
}

static void queue_free(message_queue_t *q) {
    if (!q) return;

    pthread_mutex_lock(&q->mutex);

    // Free all queued messages
    for (size_t i = 0; i < q->count; i++) {
        size_t idx = (q->head + i) % MAX_MESSAGE_QUEUE_SIZE;
        if (q->messages[idx]) {
            free(q->messages[idx]->data);
            free(q->messages[idx]);
        }
    }

    pthread_mutex_unlock(&q->mutex);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
    free(q);
}

static int queue_push(message_queue_t *q, ice_message_t *msg) {
    if (!q || !msg) return -1;

    pthread_mutex_lock(&q->mutex);

    // If queue is full, drop oldest message
    if (q->count >= MAX_MESSAGE_QUEUE_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Queue full (%zu messages), dropping oldest\n", q->count);

        ice_message_t *old = q->messages[q->head];
        if (old) {
            free(old->data);
            free(old);
        }

        q->head = (q->head + 1) % MAX_MESSAGE_QUEUE_SIZE;
        q->count--;
    }

    // Enqueue new message
    q->messages[q->tail] = msg;
    q->tail = (q->tail + 1) % MAX_MESSAGE_QUEUE_SIZE;
    q->count++;

    // Signal waiting threads
    pthread_cond_signal(&q->cond);

    pthread_mutex_unlock(&q->mutex);
    return 0;
}

static ice_message_t* queue_pop(message_queue_t *q) {
    if (!q) return NULL;

    pthread_mutex_lock(&q->mutex);

    if (q->count == 0) {
        pthread_mutex_unlock(&q->mutex);
        return NULL;
    }

    ice_message_t *msg = q->messages[q->head];
    q->head = (q->head + 1) % MAX_MESSAGE_QUEUE_SIZE;
    q->count--;

    pthread_mutex_unlock(&q->mutex);
    return msg;
}

static size_t queue_length(message_queue_t *q) {
    if (!q) return 0;

    pthread_mutex_lock(&q->mutex);
    size_t len = q->count;
    pthread_mutex_unlock(&q->mutex);

    return len;
}

// =============================================================================
// Time Utilities (replaces glib monotonic time)
// =============================================================================

static int64_t get_monotonic_time_ms(void) {
#ifdef _WIN32
    return (int64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
}

// =============================================================================
// libjuice Callbacks
// =============================================================================

/**
 * Callback for receiving data over ICE connection
 *
 * Called by libjuice when data arrives on the ICE stream.
 * Enqueues data to context's message queue for ice_recv() to read.
 */
static void on_juice_recv(juice_agent_t *agent, const char *data, size_t size, void *user_ptr) {
    ice_context_t *ctx = (ice_context_t*)user_ptr;

    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Receive callback: NULL context\n");
        return;
    }

    // Check message size (reject oversized messages)
    if (size == 0 || size > 65536) {
        QGP_LOG_ERROR(LOG_TAG, "Receive callback: Invalid message size (%zu bytes)\n", size);
        return;
    }

    // Allocate new message
    ice_message_t *msg = malloc(sizeof(ice_message_t));
    if (!msg) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate message structure\n");
        return;
    }

    msg->data = malloc(size);
    if (!msg->data) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate message data\n");
        free(msg);
        return;
    }

    // Copy message data
    memcpy(msg->data, data, size);
    msg->len = size;

    // Enqueue message
    if (queue_push(ctx->recv_queue, msg) < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to enqueue message\n");
        free(msg->data);
        free(msg);
        return;
    }

    QGP_LOG_INFO(LOG_TAG, "Received %zu bytes (queued, %zu messages total)\n",
           size, queue_length(ctx->recv_queue));
}

/**
 * Callback for state changes
 */
static void on_juice_state_changed(juice_agent_t *agent, juice_state_t state, void *user_ptr) {
    ice_context_t *ctx = (ice_context_t*)user_ptr;

    if (!ctx) return;

    const char *state_str = "UNKNOWN";
    switch (state) {
        case JUICE_STATE_DISCONNECTED: state_str = "DISCONNECTED"; break;
        case JUICE_STATE_GATHERING: state_str = "GATHERING"; break;
        case JUICE_STATE_CONNECTING: state_str = "CONNECTING"; break;
        case JUICE_STATE_CONNECTED: state_str = "CONNECTED"; break;
        case JUICE_STATE_COMPLETED: state_str = "COMPLETED"; break;
        case JUICE_STATE_FAILED: state_str = "FAILED"; break;
    }

    QGP_LOG_INFO(LOG_TAG, "State changed: %s\n", state_str);

    pthread_mutex_lock(&ctx->state_mutex);

    if (state == JUICE_STATE_CONNECTED || state == JUICE_STATE_COMPLETED) {
        ctx->connected = 1;
        pthread_cond_broadcast(&ctx->state_cond);
    } else if (state == JUICE_STATE_FAILED) {
        ctx->connected = 0;
        pthread_cond_broadcast(&ctx->state_cond);
    }

    pthread_mutex_unlock(&ctx->state_mutex);
}

/**
 * Callback for local candidate gathering
 */
static void on_juice_candidate(juice_agent_t *agent, const char *sdp, void *user_ptr) {
    ice_context_t *ctx = (ice_context_t*)user_ptr;

    if (!ctx || !sdp) return;

    QGP_LOG_INFO(LOG_TAG, "Local candidate: %s\n", sdp);

    pthread_mutex_lock(&ctx->candidates_mutex);

    // Append candidate to local_candidates string
    size_t sdp_len = strlen(sdp);
    size_t remaining = MAX_CANDIDATES_SIZE - ctx->candidates_len - 1;

    if (sdp_len + 1 > remaining) {
        QGP_LOG_ERROR(LOG_TAG, "Candidate buffer full, skipping candidate\n");
        pthread_mutex_unlock(&ctx->candidates_mutex);
        return;
    }

    // Append candidate with newline
    if (ctx->candidates_len > 0) {
        ctx->local_candidates[ctx->candidates_len] = '\n';
        ctx->candidates_len++;
    }

    memcpy(ctx->local_candidates + ctx->candidates_len, sdp, sdp_len);
    ctx->candidates_len += sdp_len;
    ctx->local_candidates[ctx->candidates_len] = '\0';

    pthread_mutex_unlock(&ctx->candidates_mutex);
}

/**
 * Callback for gathering done
 */
static void on_juice_gathering_done(juice_agent_t *agent, void *user_ptr) {
    ice_context_t *ctx = (ice_context_t*)user_ptr;

    if (!ctx) return;

    QGP_LOG_INFO(LOG_TAG, "Candidate gathering completed\n");

    pthread_mutex_lock(&ctx->gathering_mutex);
    ctx->gathering_done = 1;
    pthread_cond_broadcast(&ctx->gathering_cond);
    pthread_mutex_unlock(&ctx->gathering_mutex);
}

// =============================================================================
// Context Management
// =============================================================================

ice_context_t* ice_context_new(void) {
    ice_context_t *ctx = calloc(1, sizeof(ice_context_t));
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate context\n");
        return NULL;
    }

    // Initialize state
    ctx->connected = 0;
    ctx->gathering_done = 0;
    ctx->candidates_len = 0;
    ctx->local_candidates[0] = '\0';
    ctx->remote_candidates[0] = '\0';
    ctx->stun_server[0] = '\0';
    ctx->stun_port = 0;

    // TURN state
    ctx->turn_server[0] = '\0';
    ctx->turn_port = 0;
    ctx->turn_username[0] = '\0';
    ctx->turn_password[0] = '\0';
    ctx->turn_enabled = 0;

    // Initialize mutexes and condition variables
    pthread_mutex_init(&ctx->state_mutex, NULL);
    pthread_cond_init(&ctx->state_cond, NULL);
    pthread_mutex_init(&ctx->gathering_mutex, NULL);
    pthread_cond_init(&ctx->gathering_cond, NULL);
    pthread_mutex_init(&ctx->candidates_mutex, NULL);

    // Initialize message queue
    ctx->recv_queue = queue_new();
    if (!ctx->recv_queue) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create receive queue\n");
        pthread_mutex_destroy(&ctx->state_mutex);
        pthread_cond_destroy(&ctx->state_cond);
        pthread_mutex_destroy(&ctx->gathering_mutex);
        pthread_cond_destroy(&ctx->gathering_cond);
        pthread_mutex_destroy(&ctx->candidates_mutex);
        free(ctx);
        return NULL;
    }

    QGP_LOG_INFO(LOG_TAG, "ICE context created (using libjuice)\n");
    return ctx;
}

void ice_context_free(ice_context_t *ctx) {
    if (!ctx) return;

    QGP_LOG_INFO(LOG_TAG, "Freeing ICE context\n");

    // Destroy libjuice agent
    if (ctx->agent) {
        juice_destroy(ctx->agent);
        ctx->agent = NULL;
    }

    // Free message queue
    if (ctx->recv_queue) {
        queue_free(ctx->recv_queue);
        ctx->recv_queue = NULL;
    }

    // Destroy synchronization primitives
    pthread_mutex_destroy(&ctx->state_mutex);
    pthread_cond_destroy(&ctx->state_cond);
    pthread_mutex_destroy(&ctx->gathering_mutex);
    pthread_cond_destroy(&ctx->gathering_cond);
    pthread_mutex_destroy(&ctx->candidates_mutex);

    free(ctx);
    QGP_LOG_INFO(LOG_TAG, "ICE context freed\n");
}

// =============================================================================
// Candidate Gathering
// =============================================================================

int ice_gather_candidates(ice_context_t *ctx, const char *stun_server, uint16_t stun_port) {
    if (!ctx || !stun_server) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to ice_gather_candidates\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Starting candidate gathering (STUN: %s:%u)\n", stun_server, stun_port);

    // Store STUN server info
    snprintf(ctx->stun_server, sizeof(ctx->stun_server), "%s", stun_server);
    ctx->stun_port = stun_port;

    // Reset gathering state
    pthread_mutex_lock(&ctx->gathering_mutex);
    ctx->gathering_done = 0;
    pthread_mutex_unlock(&ctx->gathering_mutex);

    pthread_mutex_lock(&ctx->candidates_mutex);
    ctx->candidates_len = 0;
    ctx->local_candidates[0] = '\0';
    pthread_mutex_unlock(&ctx->candidates_mutex);

    // Configure libjuice
    juice_config_t config;
    memset(&config, 0, sizeof(config));

    config.concurrency_mode = JUICE_CONCURRENCY_MODE_POLL;
    config.stun_server_host = ctx->stun_server;
    config.stun_server_port = ctx->stun_port;
    config.cb_state_changed = on_juice_state_changed;
    config.cb_candidate = on_juice_candidate;
    config.cb_gathering_done = on_juice_gathering_done;
    config.cb_recv = on_juice_recv;
    config.user_ptr = ctx;

    // Configure TURN server if enabled
    juice_turn_server_t turn_server;
    if (ctx->turn_enabled && ctx->turn_server[0] != '\0') {
        memset(&turn_server, 0, sizeof(turn_server));
        turn_server.host = ctx->turn_server;
        turn_server.port = ctx->turn_port;
        turn_server.username = ctx->turn_username;
        turn_server.password = ctx->turn_password;

        config.turn_servers = &turn_server;
        config.turn_servers_count = 1;

        QGP_LOG_INFO(LOG_TAG, "TURN server configured: %s:%u (user: %s)\n",
               ctx->turn_server, ctx->turn_port, ctx->turn_username);
    }

    // Create libjuice agent
    ctx->agent = juice_create(&config);
    if (!ctx->agent) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to create libjuice agent\n");
        return -1;
    }

    // Set log level to WARN (suppress verbose STUN debug messages)
    juice_set_log_level(JUICE_LOG_LEVEL_WARN);

    QGP_LOG_INFO(LOG_TAG, "libjuice agent created%s\n",
           ctx->turn_enabled ? " (with TURN)" : "");

    // Start gathering candidates
    int ret = juice_gather_candidates(ctx->agent);
    if (ret < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start candidate gathering\n");
        return -1;
    }

    // Wait for gathering to complete (max 5 seconds)
    pthread_mutex_lock(&ctx->gathering_mutex);

    int64_t deadline = get_monotonic_time_ms() + 5000;
    while (!ctx->gathering_done) {
        int64_t now = get_monotonic_time_ms();
        if (now >= deadline) {
            QGP_LOG_ERROR(LOG_TAG, "Candidate gathering timeout\n");
            pthread_mutex_unlock(&ctx->gathering_mutex);
            return -1;
        }

        struct timespec ts;
        ts.tv_sec = deadline / 1000;
        ts.tv_nsec = (deadline % 1000) * 1000000;

        int wait_ret = pthread_cond_timedwait(&ctx->gathering_cond, &ctx->gathering_mutex, &ts);
        if (wait_ret != 0 && wait_ret != ETIMEDOUT) {
            QGP_LOG_ERROR(LOG_TAG, "pthread_cond_timedwait failed: %d\n", wait_ret);
            pthread_mutex_unlock(&ctx->gathering_mutex);
            return -1;
        }
    }

    pthread_mutex_unlock(&ctx->gathering_mutex);

    QGP_LOG_INFO(LOG_TAG, "Candidate gathering complete\n");
    return 0;
}

// =============================================================================
// DHT Operations
// =============================================================================

int ice_publish_to_dht(ice_context_t *ctx, const char *my_fingerprint) {
    if (!ctx || !my_fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to ice_publish_to_dht\n");
        return -1;
    }

    pthread_mutex_lock(&ctx->candidates_mutex);

    if (ctx->candidates_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No local candidates to publish\n");
        pthread_mutex_unlock(&ctx->candidates_mutex);
        return -1;
    }

    // Get DHT instance
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not initialized\n");
        pthread_mutex_unlock(&ctx->candidates_mutex);
        return -1;
    }

    // Create DHT key: SHA3-512(fingerprint + ":ice_candidates")
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:ice_candidates", my_fingerprint);

    // Hash key with SHA3-512 and get hex output (128 hex chars)
    char hex_key[129];  // 128 hex chars + null terminator
    if (qgp_sha3_512_hex((uint8_t*)key_input, strlen(key_input),
                         hex_key, sizeof(hex_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to hash DHT key\n");
        pthread_mutex_unlock(&ctx->candidates_mutex);
        return -1;
    }

    // Publish to DHT (signed, 7-day TTL, value_id=1 for replacement)
    // ICE candidates are ephemeral and refreshed regularly
    QGP_LOG_INFO(LOG_TAG, "Publishing %zu bytes of candidates to DHT\n", ctx->candidates_len);

    unsigned int ttl_7days = 7 * 24 * 3600;  // 604800 seconds
    int ret = dht_put_signed(dht, (uint8_t*)hex_key, strlen(hex_key),
                             (uint8_t*)ctx->local_candidates, ctx->candidates_len,
                             1, ttl_7days);

    pthread_mutex_unlock(&ctx->candidates_mutex);

    if (ret < 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish candidates to DHT\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Candidates published to DHT (signed)\n");
    return 0;
}

int ice_fetch_from_dht(ice_context_t *ctx, const char *peer_fingerprint) {
    if (!ctx || !peer_fingerprint) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to ice_fetch_from_dht\n");
        return -1;
    }

    // Get DHT instance
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        QGP_LOG_ERROR(LOG_TAG, "DHT not initialized\n");
        return -1;
    }

    // Create DHT key: SHA3-512(peer_fingerprint + ":ice_candidates")
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:ice_candidates", peer_fingerprint);

    // Hash key with SHA3-512 and get hex output (128 hex chars)
    char hex_key[129];  // 128 hex chars + null terminator
    if (qgp_sha3_512_hex((uint8_t*)key_input, strlen(key_input),
                         hex_key, sizeof(hex_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to hash DHT key\n");
        return -1;
    }

    // Fetch from DHT
    QGP_LOG_INFO(LOG_TAG, "Fetching candidates from DHT for peer: %.16s...\n", peer_fingerprint);

    uint8_t *value_data = NULL;
    size_t value_len = 0;

    int ret = dht_get(dht, (uint8_t*)hex_key, strlen(hex_key), &value_data, &value_len);
    if (ret != 0 || !value_data) {
        QGP_LOG_ERROR(LOG_TAG, "No candidates found in DHT for peer\n");
        if (value_data) free(value_data);
        return -1;
    }

    // Check size
    if (value_len >= MAX_CANDIDATES_SIZE) {
        QGP_LOG_ERROR(LOG_TAG, "Candidate data too large (%zu bytes)\n", value_len);
        free(value_data);
        return -1;
    }

    // Copy to remote_candidates
    memcpy(ctx->remote_candidates, value_data, value_len);
    ctx->remote_candidates[value_len] = '\0';
    free(value_data);

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu bytes of remote candidates from DHT\n", value_len);
    return 0;
}

// =============================================================================
// Connection Establishment
// =============================================================================

int ice_connect(ice_context_t *ctx) {
    if (!ctx) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid context\n");
        return -1;
    }

    if (!ctx->agent) {
        QGP_LOG_ERROR(LOG_TAG, "Agent not initialized (call ice_gather_candidates first)\n");
        return -1;
    }

    if (strlen(ctx->remote_candidates) == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No remote candidates (call ice_fetch_from_dht first)\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Starting ICE connectivity checks\n");

    // Parse and add remote candidates (newline-separated SDP)
    char *candidates_copy = strdup(ctx->remote_candidates);
    if (!candidates_copy) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate memory for candidates\n");
        return -1;
    }

    char *line = strtok(candidates_copy, "\n");
    int candidate_count = 0;

    while (line) {
        // Skip empty lines
        if (strlen(line) > 0) {
            int ret = juice_add_remote_candidate(ctx->agent, line);
            if (ret < 0) {
                QGP_LOG_ERROR(LOG_TAG, "Failed to add remote candidate: %s\n", line);
            } else {
                candidate_count++;
            }
        }
        line = strtok(NULL, "\n");
    }

    free(candidates_copy);

    if (candidate_count == 0) {
        QGP_LOG_ERROR(LOG_TAG, "No valid remote candidates added\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Added %d remote candidates\n", candidate_count);

    // Wait for connection (max 10 seconds)
    pthread_mutex_lock(&ctx->state_mutex);

    int64_t deadline = get_monotonic_time_ms() + 10000;
    while (!ctx->connected) {
        int64_t now = get_monotonic_time_ms();
        if (now >= deadline) {
            QGP_LOG_ERROR(LOG_TAG, "Connection timeout\n");
            pthread_mutex_unlock(&ctx->state_mutex);
            return -1;
        }

        struct timespec ts;
        ts.tv_sec = deadline / 1000;
        ts.tv_nsec = (deadline % 1000) * 1000000;

        int wait_ret = pthread_cond_timedwait(&ctx->state_cond, &ctx->state_mutex, &ts);
        if (wait_ret != 0 && wait_ret != ETIMEDOUT) {
            QGP_LOG_ERROR(LOG_TAG, "pthread_cond_timedwait failed: %d\n", wait_ret);
            pthread_mutex_unlock(&ctx->state_mutex);
            return -1;
        }
    }

    pthread_mutex_unlock(&ctx->state_mutex);

    QGP_LOG_INFO(LOG_TAG, "ICE connection established\n");
    return 0;
}

// =============================================================================
// Send/Receive Operations
// =============================================================================

int ice_send(ice_context_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data || len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to ice_send\n");
        return -1;
    }

    if (!ctx->agent) {
        QGP_LOG_ERROR(LOG_TAG, "Agent not initialized\n");
        return -1;
    }

    if (!ctx->connected) {
        QGP_LOG_ERROR(LOG_TAG, "Not connected\n");
        return -1;
    }

    // Send data (libjuice handles retries internally)
    int ret = juice_send(ctx->agent, (const char*)data, len);
    if (ret < 0) {
        QGP_LOG_ERROR(LOG_TAG, "juice_send failed\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Sent %zu bytes\n", len);
    return (int)len;
}

int ice_recv_timeout(ice_context_t *ctx, uint8_t *buf, size_t buflen, int timeout_ms) {
    if (!ctx || !buf || buflen == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid arguments to ice_recv_timeout\n");
        return -1;
    }

    message_queue_t *q = ctx->recv_queue;
    if (!q) {
        QGP_LOG_ERROR(LOG_TAG, "Receive queue not initialized\n");
        return -1;
    }

    pthread_mutex_lock(&q->mutex);

    // Wait for message with timeout
    if (timeout_ms < 0) {
        // Infinite wait
        while (q->count == 0) {
            pthread_cond_wait(&q->cond, &q->mutex);
        }
    } else if (timeout_ms > 0) {
        // Timed wait
        int64_t deadline = get_monotonic_time_ms() + timeout_ms;

        while (q->count == 0) {
            int64_t now = get_monotonic_time_ms();
            if (now >= deadline) {
                pthread_mutex_unlock(&q->mutex);
                return 0;  // Timeout, no data
            }

            struct timespec ts;
            ts.tv_sec = deadline / 1000;
            ts.tv_nsec = (deadline % 1000) * 1000000;

            int wait_ret = pthread_cond_timedwait(&q->cond, &q->mutex, &ts);
            if (wait_ret == ETIMEDOUT) {
                pthread_mutex_unlock(&q->mutex);
                return 0;  // Timeout, no data
            }
        }
    } else {
        // Non-blocking (timeout == 0)
        if (q->count == 0) {
            pthread_mutex_unlock(&q->mutex);
            return 0;  // No data
        }
    }

    // Dequeue message
    ice_message_t *msg = q->messages[q->head];
    q->head = (q->head + 1) % MAX_MESSAGE_QUEUE_SIZE;
    q->count--;

    pthread_mutex_unlock(&q->mutex);

    // Check buffer size
    if (msg->len > buflen) {
        QGP_LOG_ERROR(LOG_TAG, "Buffer too small (%zu bytes needed, %zu available)\n",
                msg->len, buflen);

        // Return message to front of queue
        pthread_mutex_lock(&q->mutex);
        q->head = (q->head - 1 + MAX_MESSAGE_QUEUE_SIZE) % MAX_MESSAGE_QUEUE_SIZE;
        q->messages[q->head] = msg;
        q->count++;
        pthread_mutex_unlock(&q->mutex);

        return -1;
    }

    // Copy data to buffer
    memcpy(buf, msg->data, msg->len);
    size_t len = msg->len;

    // Free message
    free(msg->data);
    free(msg);

    return (int)len;
}

int ice_recv(ice_context_t *ctx, uint8_t *buf, size_t buflen) {
    return ice_recv_timeout(ctx, buf, buflen, 0);  // Non-blocking
}

// =============================================================================
// Status and Control
// =============================================================================

int ice_is_connected(ice_context_t *ctx) {
    if (!ctx) return 0;

    pthread_mutex_lock(&ctx->state_mutex);
    int connected = ctx->connected;
    pthread_mutex_unlock(&ctx->state_mutex);

    return connected;
}

void ice_shutdown(ice_context_t *ctx) {
    if (!ctx) return;

    QGP_LOG_INFO(LOG_TAG, "Shutting down ICE connection\n");

    pthread_mutex_lock(&ctx->state_mutex);
    ctx->connected = 0;
    pthread_cond_broadcast(&ctx->state_cond);
    pthread_mutex_unlock(&ctx->state_mutex);

    // Destroy agent (libjuice handles cleanup)
    if (ctx->agent) {
        juice_destroy(ctx->agent);
        ctx->agent = NULL;
    }
}

const char* ice_get_local_candidates(ice_context_t *ctx) {
    if (!ctx) return NULL;

    pthread_mutex_lock(&ctx->candidates_mutex);
    const char *candidates = ctx->local_candidates;
    pthread_mutex_unlock(&ctx->candidates_mutex);

    return candidates;
}

const char* ice_get_remote_candidates(ice_context_t *ctx) {
    if (!ctx) return NULL;
    return ctx->remote_candidates;
}

// ============================================================================
// ICE Connection Management (high-level P2P integration)
// ============================================================================

/**
 * Find existing ICE connection to peer
 *
 * @param ctx: P2P transport context
 * @param peer_fingerprint: Peer fingerprint (128 hex chars)
 * @return: p2p_connection_t if found, NULL otherwise
 */
static p2p_connection_t* ice_find_connection(
    p2p_transport_t *ctx,
    const char *peer_fingerprint)
{
    pthread_mutex_lock(&ctx->connections_mutex);

    for (size_t i = 0; i < 256; i++) {
        if (ctx->connections[i] &&
            ctx->connections[i]->type == CONNECTION_TYPE_ICE &&
            ctx->connections[i]->active &&
            strcmp(ctx->connections[i]->peer_fingerprint, peer_fingerprint) == 0) {

            // Found existing ICE connection
            pthread_mutex_unlock(&ctx->connections_mutex);
            return ctx->connections[i];
        }
    }

    pthread_mutex_unlock(&ctx->connections_mutex);
    return NULL;
}

/**
 * ICE connection receive thread
 *
 * Continuously reads messages from ICE connection, sends ACK, and invokes callback.
 *
 * @param arg: p2p_connection_t pointer
 * @return: NULL
 */
void* ice_connection_recv_thread(void *arg) {
    p2p_connection_t *conn = (p2p_connection_t*)arg;
    if (!conn || !conn->ice_ctx) {
        return NULL;
    }

    QGP_LOG_DEBUG("ICE", "Receive thread started for peer %.32s...", conn->peer_fingerprint);

    uint8_t buffer[65536];  // 64KB buffer

    while (conn->active) {
        // Use timeout to allow checking active flag periodically
        int received = ice_recv_timeout(conn->ice_ctx, buffer, sizeof(buffer), 1000);  // 1s timeout

        if (received > 0) {
            // Check if this is an ACK (1 byte, value 0x01) - ignore it
            if (received == 1 && buffer[0] == 0x01) {
                // This is an ACK response, not a message - ignore
                continue;
            }

            QGP_LOG_DEBUG("ICE", "Received %d bytes from peer %.32s...",
                   received, conn->peer_fingerprint);

            // Send ACK back to sender (single byte 0x01)
            uint8_t ack = 0x01;
            int ack_sent = ice_send(conn->ice_ctx, &ack, 1);
            if (ack_sent == 1) {
                QGP_LOG_DEBUG("ICE", "Sent ACK to peer");
            } else {
                QGP_LOG_WARN("ICE", "Failed to send ACK (peer may retry or use DHT)");
            }

            // Invoke message callback via transport back-pointer
            if (conn->transport && conn->transport->message_callback) {
                pthread_mutex_lock(&conn->transport->callback_mutex);
                conn->transport->message_callback(
                    conn->peer_pubkey,  // Sender's public key
                    NULL,               // sender_fingerprint (N/A for direct P2P)
                    buffer,
                    received,
                    conn->transport->callback_user_data
                );
                pthread_mutex_unlock(&conn->transport->callback_mutex);
                QGP_LOG_DEBUG("ICE", "Message delivered to callback");
            } else {
                QGP_LOG_WARN("ICE", "No message callback registered");
            }
        } else if (received < 0) {
            QGP_LOG_ERROR("ICE", "Receive error, closing connection");
            conn->active = false;
            break;
        }
        // received == 0 means timeout, continue loop
    }

    QGP_LOG_DEBUG("ICE", "Receive thread exiting for peer %.32s...", conn->peer_fingerprint);
    return NULL;
}

/**
 * Configure TURN credentials on ICE context
 *
 * @param ice_ctx: ICE context
 * @param creds: TURN credentials
 * @return 0 on success, -1 on error
 */
static int ice_configure_turn(ice_context_t *ice_ctx, const turn_credentials_t *creds) {
    if (!ice_ctx || !creds || creds->server_count == 0) {
        return -1;
    }

    // Use first available server
    const turn_server_info_t *server = &creds->servers[0];

    strncpy(ice_ctx->turn_server, server->host, sizeof(ice_ctx->turn_server) - 1);
    ice_ctx->turn_port = server->port;
    strncpy(ice_ctx->turn_username, server->username, sizeof(ice_ctx->turn_username) - 1);
    strncpy(ice_ctx->turn_password, server->password, sizeof(ice_ctx->turn_password) - 1);
    ice_ctx->turn_enabled = 1;

    QGP_LOG_INFO(LOG_TAG, "TURN configured: %s:%u\n", server->host, server->port);
    return 0;
}

/**
 * Request TURN credentials from dna-nodus
 *
 * Note: Full implementation requires access to node's Dilithium5 keys.
 * Keys are passed via p2p_transport context when available.
 *
 * @param fingerprint: Client fingerprint
 * @param creds: Output credentials
 * @param pubkey: Node's public key (2592 bytes) or NULL
 * @param privkey: Node's private key (4896 bytes) or NULL
 * @return 0 on success, -1 on error
 */
static int ice_request_turn_credentials(
    const char *fingerprint,
    turn_credentials_t *creds,
    const uint8_t *pubkey,
    const uint8_t *privkey)
{
    if (!pubkey || !privkey) {
        // Keys not available - TURN request not possible
        // This is expected when p2p_transport doesn't have key access
        QGP_LOG_INFO(LOG_TAG, "TURN credentials not available (no keys)\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Requesting TURN credentials from dna-nodus...\n");

    // Request credentials (5 second timeout - nodus TURN not yet implemented)
    int ret = turn_credentials_request(fingerprint, pubkey, privkey, creds, 5000);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to get TURN credentials\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "✓ Got TURN credentials (%zu servers)\n", creds->server_count);
    return 0;
}

/**
 * Create new ICE connection to peer
 *
 * Uses per-peer ICE context (each peer gets own ICE stream).
 * Falls back to TURN if STUN-only ICE fails.
 *
 * @param ctx: P2P transport context
 * @param peer_pubkey: Peer's Dilithium5 public key
 * @param peer_fingerprint: Peer fingerprint
 * @return: p2p_connection_t on success, NULL on error
 */
static p2p_connection_t* ice_create_connection(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    const char *peer_fingerprint)
{
    QGP_LOG_DEBUG("ICE", "Creating new ICE connection to peer %.32s...", peer_fingerprint);

    // Create new ICE context for this peer
    // NOTE: Each peer gets own ICE context (separate stream/agent)
    ice_context_t *peer_ice_ctx = ice_context_new();
    if (!peer_ice_ctx) {
        QGP_LOG_ERROR("ICE", "Failed to create peer ICE context");
        return NULL;
    }

    // Gather local candidates for this peer connection
    int gathered = 0;
    // Try STUN servers in order of reliability (STUN protocol tested)
    // Google works reliably, Cloudflare may be blocked by some firewalls
    const char *stun_servers[] = {
        "stun.l.google.com",      // Google primary - VERIFIED WORKING via stun-client
        "stun1.l.google.com",     // Google secondary - VERIFIED WORKING via stun-client
        "stun.cloudflare.com"     // Cloudflare fallback - may be blocked (firewall/ISP)
    };
    const uint16_t stun_ports[] = {19302, 19302, 3478};

    for (size_t i = 0; i < 3 && !gathered; i++) {
        if (ice_gather_candidates(peer_ice_ctx, stun_servers[i], stun_ports[i]) == 0) {
            gathered = 1;
            QGP_LOG_DEBUG("ICE", "Gathered candidates for peer connection via %s:%d",
                   stun_servers[i], stun_ports[i]);
            break;
        }
    }

    if (!gathered) {
        QGP_LOG_ERROR("ICE", "Failed to gather candidates for peer");
        ice_context_free(peer_ice_ctx);
        return NULL;
    }

    // Fetch peer's ICE candidates from DHT
    if (ice_fetch_from_dht(peer_ice_ctx, peer_fingerprint) != 0) {
        QGP_LOG_ERROR("ICE", "Peer ICE candidates not found in DHT");
        ice_context_free(peer_ice_ctx);
        return NULL;
    }

    QGP_LOG_DEBUG("ICE", "Fetched peer ICE candidates from DHT");

    // Perform ICE connectivity checks
    int ice_connected = (ice_connect(peer_ice_ctx) == 0);

    // If STUN-only ICE failed, try with TURN (multiple servers with failover)
    if (!ice_connected) {
        QGP_LOG_INFO("ICE", "STUN-only ICE failed, trying TURN servers...");

        // Get our fingerprint and keys from transport context
        const char *local_fingerprint = ctx ? ctx->my_fingerprint : NULL;
        const uint8_t *pubkey = ctx ? ctx->my_public_key : NULL;
        const uint8_t *privkey = ctx ? ctx->my_private_key : NULL;

        if (local_fingerprint && strlen(local_fingerprint) > 0 && pubkey && privkey) {
            // Get list of TURN servers
            const char *turn_servers[4];
            int num_servers = turn_credentials_get_server_list(turn_servers, 4);

            // Try each TURN server with failover
            for (int s = 0; s < num_servers && !ice_connected; s++) {
                const char *turn_server_ip = turn_servers[s];
                QGP_LOG_INFO("ICE", "Trying TURN server %d/%d: %s", s + 1, num_servers, turn_server_ip);

                // Get credentials for this specific server
                turn_server_info_t server_creds;
                int have_creds = (turn_credentials_get_for_server(turn_server_ip, &server_creds) == 0);

                if (!have_creds) {
                    // Request credentials from this server
                    have_creds = (turn_credentials_request_from_server(
                        turn_server_ip, 3479,  // Credential port
                        local_fingerprint, pubkey, privkey,
                        &server_creds, 5000) == 0);
                }

                if (!have_creds) {
                    QGP_LOG_WARN("ICE", "Failed to get credentials from %s, trying next...", turn_server_ip);
                    continue;
                }

                // Recreate ICE context with this TURN server
                if (peer_ice_ctx) {
                    ice_context_free(peer_ice_ctx);
                }
                peer_ice_ctx = ice_context_new();
                if (!peer_ice_ctx) {
                    QGP_LOG_ERROR("ICE", "Failed to create ICE context for TURN");
                    continue;
                }

                // Configure TURN using per-server credentials
                turn_credentials_t turn_creds;
                memset(&turn_creds, 0, sizeof(turn_creds));
                turn_creds.server_count = 1;
                memcpy(&turn_creds.servers[0], &server_creds, sizeof(server_creds));
                ice_configure_turn(peer_ice_ctx, &turn_creds);

                // Gather candidates with TURN
                gathered = 0;
                for (size_t i = 0; i < 3 && !gathered; i++) {
                    if (ice_gather_candidates(peer_ice_ctx, stun_servers[i], stun_ports[i]) == 0) {
                        gathered = 1;
                        QGP_LOG_DEBUG("ICE", "Gathered candidates with TURN %s via STUN %s",
                               turn_server_ip, stun_servers[i]);
                        break;
                    }
                }

                if (!gathered) {
                    QGP_LOG_WARN("ICE", "Failed to gather candidates with TURN %s", turn_server_ip);
                    continue;
                }

                // Fetch peer candidates
                if (ice_fetch_from_dht(peer_ice_ctx, peer_fingerprint) != 0) {
                    QGP_LOG_WARN("ICE", "Peer candidates not in DHT for TURN attempt");
                    continue;
                }

                // Try ICE with this TURN server
                ice_connected = (ice_connect(peer_ice_ctx) == 0);
                if (ice_connected) {
                    QGP_LOG_INFO("ICE", "✓ Connected via TURN relay %s!", turn_server_ip);
                } else {
                    QGP_LOG_WARN("ICE", "TURN %s failed, trying next...", turn_server_ip);
                }
            }
        }

        if (!ice_connected) {
            QGP_LOG_ERROR("ICE", "ICE connectivity checks failed (all TURN servers exhausted)");
            if (peer_ice_ctx) ice_context_free(peer_ice_ctx);
            return NULL;
        }
    }

    QGP_LOG_INFO("ICE", "ICE connection established to peer!");

    // Allocate connection structure
    p2p_connection_t *conn = calloc(1, sizeof(p2p_connection_t));
    if (!conn) {
        ice_context_free(peer_ice_ctx);
        return NULL;
    }

    // Initialize connection
    conn->type = CONNECTION_TYPE_ICE;
    conn->transport = ctx;  // Back-pointer for callback invocation
    memcpy(conn->peer_pubkey, peer_pubkey, 2592);
    strncpy(conn->peer_fingerprint, peer_fingerprint, sizeof(conn->peer_fingerprint) - 1);
    conn->peer_fingerprint[128] = '\0';
    conn->connected_at = time(NULL);
    conn->active = true;
    conn->ice_ctx = peer_ice_ctx;

    // Add to connections array
    pthread_mutex_lock(&ctx->connections_mutex);
    for (size_t i = 0; i < 256; i++) {
        if (!ctx->connections[i]) {
            ctx->connections[i] = conn;
            ctx->connection_count++;
            pthread_mutex_unlock(&ctx->connections_mutex);

            // Start receive thread
            if (pthread_create(&conn->recv_thread, NULL, ice_connection_recv_thread, conn) != 0) {
                QGP_LOG_ERROR("ICE", "Failed to start ICE receive thread");
                // Connection still usable for sending, just no receiving
            } else {
                QGP_LOG_DEBUG("ICE", "Started ICE receive thread");
            }

            QGP_LOG_DEBUG("ICE", "ICE connection cached (slot %zu, total: %zu)",
                   i, ctx->connection_count);
            return conn;
        }
    }
    pthread_mutex_unlock(&ctx->connections_mutex);

    // No free slot
    QGP_LOG_ERROR("ICE", "Connection array full (256 max)");
    ice_context_free(peer_ice_ctx);
    free(conn);
    return NULL;
}

/**
 * Find or create ICE connection to peer
 *
 * Reuses existing connections for efficiency.
 *
 * @param ctx: P2P transport context
 * @param peer_pubkey: Peer's Dilithium5 public key
 * @param peer_fingerprint: Peer fingerprint
 * @return: p2p_connection_t on success, NULL on error
 */
p2p_connection_t* ice_get_or_create_connection(
    p2p_transport_t *ctx,
    const uint8_t *peer_pubkey,
    const char *peer_fingerprint)
{
    if (!ctx || !peer_pubkey || !peer_fingerprint) {
        return NULL;
    }

    // Try to find existing connection (reuse)
    p2p_connection_t *conn = ice_find_connection(ctx, peer_fingerprint);
    if (conn) {
        QGP_LOG_DEBUG("ICE", "Reusing existing ICE connection to peer %.32s...",
                      peer_fingerprint);
        return conn;
    }

    // Create new connection if not found
    QGP_LOG_DEBUG("ICE", "No existing connection, creating new ICE connection...");
    return ice_create_connection(ctx, peer_pubkey, peer_fingerprint);
}
