/**
 * transport_ice.c - ICE Transport Implementation
 *
 * Provides NAT traversal using libnice (STUN+ICE, no TURN)
 * Part of Phase 11: Decentralized NAT Traversal
 */

#include "transport_ice.h"
#include "../../dht/core/dht_context.h"
#include "../../dht/client/dht_singleton.h"
#include "../../crypto/utils/qgp_sha3.h"
#include <nice/agent.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
 * ICE context structure
 *
 * Contains:
 * - NiceAgent for ICE operations
 * - glib main loop (required by libnice)
 * - Stream and component IDs
 * - Local and remote candidates (SDP format)
 * - Connection state
 * - Message queue for incoming data (callback-based)
 */
struct ice_context {
    NiceAgent *agent;              // libnice agent
    guint stream_id;               // ICE stream ID (1)
    guint component_id;            // ICE component ID (1 = RTP, no RTCP)
    GMainLoop *loop;               // glib main loop
    GThread *loop_thread;          // Main loop thread
    char local_candidates[MAX_CANDIDATES_SIZE];   // SDP-formatted local candidates
    char remote_candidates[MAX_CANDIDATES_SIZE];  // SDP-formatted remote candidates
    int connected;                 // Connection state (0 = not connected, 1 = connected)
    int gathering_done;            // Candidate gathering complete flag

    // Message queue (callback-based receiving) - PHASE 1 FIX
    GQueue *recv_queue;            // Queue of ice_message_t* (FIFO)
    GMutex recv_mutex;             // Mutex for thread-safe queue access
    GCond recv_cond;               // Condition variable for blocking wait - PHASE 2 FIX

    // Signal handler IDs for proper cleanup - PHASE 3 FIX
    gulong gathering_handler_id;   // ID for "candidate-gathering-done" handler
    gulong state_handler_id;       // ID for "component-state-changed" handler
};

// =============================================================================
// Context Management
// =============================================================================

// Forward declarations
static gpointer ice_main_loop_thread(gpointer data);
static void on_ice_data_received(NiceAgent *agent, guint stream_id,
                                 guint component_id, guint len,
                                 gchar *buf, gpointer user_data);

/**
 * Callback for receiving data over ICE connection
 *
 * Called by libnice when data arrives on the ICE stream.
 * Enqueues data to context's message queue for ice_recv() to read.
 *
 * PHASE 1 FIX: Uses GQueue to prevent data loss from buffer overwriting
 *
 * @param agent: NiceAgent instance
 * @param stream_id: Stream ID (should match ctx->stream_id)
 * @param component_id: Component ID (should match ctx->component_id)
 * @param len: Number of bytes received
 * @param buf: Data buffer
 * @param user_data: ice_context_t pointer
 */
static void on_ice_data_received(NiceAgent *agent, guint stream_id,
                                 guint component_id, guint len,
                                 gchar *buf, gpointer user_data) {
    ice_context_t *ctx = (ice_context_t*)user_data;

    if (!ctx) {
        fprintf(stderr, "[ICE] Receive callback: NULL context\n");
        return;
    }

    // Verify stream and component IDs match
    if (stream_id != ctx->stream_id || component_id != ctx->component_id) {
        fprintf(stderr, "[ICE] Receive callback: Stream/component mismatch\n");
        return;
    }

    // Check message size (reject oversized messages)
    if (len == 0 || len > 65536) {
        fprintf(stderr, "[ICE] Receive callback: Invalid message size (%u bytes)\n", len);
        return;
    }

    // Thread-safe queue operation
    g_mutex_lock(&ctx->recv_mutex);

    // Check queue size (drop oldest if full)
    guint queue_len = g_queue_get_length(ctx->recv_queue);
    if (queue_len >= MAX_MESSAGE_QUEUE_SIZE) {
        fprintf(stderr, "[ICE] Queue full (%u messages), dropping oldest\n", queue_len);

        // Remove and free oldest message
        ice_message_t *old_msg = (ice_message_t*)g_queue_pop_head(ctx->recv_queue);
        if (old_msg) {
            free(old_msg->data);
            free(old_msg);
        }
    }

    // Allocate new message
    ice_message_t *msg = malloc(sizeof(ice_message_t));
    if (!msg) {
        fprintf(stderr, "[ICE] Failed to allocate message structure\n");
        g_mutex_unlock(&ctx->recv_mutex);
        return;
    }

    msg->data = malloc(len);
    if (!msg->data) {
        fprintf(stderr, "[ICE] Failed to allocate message data\n");
        free(msg);
        g_mutex_unlock(&ctx->recv_mutex);
        return;
    }

    // Copy message data
    memcpy(msg->data, buf, len);
    msg->len = len;

    // Enqueue message
    g_queue_push_tail(ctx->recv_queue, msg);

    // Signal waiting threads (PHASE 2 FIX)
    g_cond_signal(&ctx->recv_cond);

    g_mutex_unlock(&ctx->recv_mutex);

    printf("[ICE] Received %u bytes (queued, %u messages total)\n",
           len, g_queue_get_length(ctx->recv_queue));
}

ice_context_t* ice_context_new(void) {
    ice_context_t *ctx = calloc(1, sizeof(ice_context_t));
    if (!ctx) {
        fprintf(stderr, "[ICE] Failed to allocate context\n");
        return NULL;
    }

    // Initialize state
    ctx->connected = 0;
    ctx->gathering_done = 0;
    ctx->local_candidates[0] = '\0';
    ctx->remote_candidates[0] = '\0';
    ctx->gathering_handler_id = 0;
    ctx->state_handler_id = 0;

    // Initialize message queue (PHASE 1 FIX)
    ctx->recv_queue = g_queue_new();
    if (!ctx->recv_queue) {
        fprintf(stderr, "[ICE] Failed to create receive queue\n");
        free(ctx);
        return NULL;
    }

    // Initialize mutex and condition variable
    g_mutex_init(&ctx->recv_mutex);
    g_cond_init(&ctx->recv_cond);  // PHASE 2 FIX

    printf("[ICE] Initializing ICE context\n");

    // Create glib main loop (required by libnice)
    ctx->loop = g_main_loop_new(NULL, FALSE);
    if (!ctx->loop) {
        fprintf(stderr, "[ICE] Failed to create glib main loop\n");
        // Cleanup resources before free
        if (ctx->recv_queue) g_queue_free(ctx->recv_queue);
        g_mutex_clear(&ctx->recv_mutex);
        g_cond_clear(&ctx->recv_cond);
        free(ctx);
        return NULL;
    }

    // Create NiceAgent (RFC5245 = full ICE)
    GMainContext *main_ctx = g_main_loop_get_context(ctx->loop);
    ctx->agent = nice_agent_new(main_ctx, NICE_COMPATIBILITY_RFC5245);
    if (!ctx->agent) {
        fprintf(stderr, "[ICE] Failed to create NiceAgent\n");
        g_main_loop_unref(ctx->loop);
        // Cleanup resources before free
        if (ctx->recv_queue) g_queue_free(ctx->recv_queue);
        g_mutex_clear(&ctx->recv_mutex);
        g_cond_clear(&ctx->recv_cond);
        free(ctx);
        return NULL;
    }

    // Configure STUN servers (NO TURN relays for decentralization)
    // Primary: Google STUN via g_object_set (portable across libnice versions)
    g_object_set(G_OBJECT(ctx->agent),
        "stun-server", "stun.l.google.com",  // STUN server hostname
        "stun-server-port", 19302,           // STUN server port
        "controlling-mode", TRUE,            // We initiate connections
        "upnp", FALSE,                       // Disable UPnP (not always reliable)
        "ice-tcp", FALSE,                    // UDP only (faster)
        NULL);

    printf("[ICE] STUN server: stun.l.google.com:19302\n");

    // Create stream (1 component = single UDP stream, no RTCP)
    ctx->stream_id = nice_agent_add_stream(ctx->agent, 1);
    if (ctx->stream_id == 0) {
        fprintf(stderr, "[ICE] Failed to create stream\n");
        g_object_unref(ctx->agent);
        g_main_loop_unref(ctx->loop);
        // Cleanup resources before free
        if (ctx->recv_queue) g_queue_free(ctx->recv_queue);
        g_mutex_clear(&ctx->recv_mutex);
        g_cond_clear(&ctx->recv_cond);
        free(ctx);
        return NULL;
    }
    ctx->component_id = 1;

    printf("[ICE] Created stream %u with component %u\n",
           ctx->stream_id, ctx->component_id);

    // Register receive callback for incoming data (PHASE 3 FIX: error checking)
    gboolean attach_result = nice_agent_attach_recv(ctx->agent, ctx->stream_id, ctx->component_id,
                                                    g_main_loop_get_context(ctx->loop),
                                                    on_ice_data_received, ctx);

    if (!attach_result) {
        fprintf(stderr, "[ICE] Failed to register receive callback\n");
        g_object_unref(ctx->agent);
        g_main_loop_unref(ctx->loop);
        g_queue_free(ctx->recv_queue);
        g_mutex_clear(&ctx->recv_mutex);
        g_cond_clear(&ctx->recv_cond);
        free(ctx);
        return NULL;
    }

    printf("[ICE] Registered receive callback\n");

    // Start main loop in separate thread
    ctx->loop_thread = g_thread_new("ice-loop", ice_main_loop_thread, ctx->loop);
    if (!ctx->loop_thread) {
        fprintf(stderr, "[ICE] Failed to start main loop thread\n");
        g_object_unref(ctx->agent);
        g_main_loop_unref(ctx->loop);
        // Cleanup resources before free
        if (ctx->recv_queue) g_queue_free(ctx->recv_queue);
        g_mutex_clear(&ctx->recv_mutex);
        g_cond_clear(&ctx->recv_cond);
        free(ctx);
        return NULL;
    }

    printf("[ICE] Context created successfully\n");
    return ctx;
}

// Main loop thread function
static gpointer ice_main_loop_thread(gpointer data) {
    GMainLoop *loop = (GMainLoop*)data;
    printf("[ICE] Main loop thread started\n");
    g_main_loop_run(loop);
    printf("[ICE] Main loop thread stopped\n");
    return NULL;
}

void ice_context_free(ice_context_t *ctx) {
    if (!ctx) return;

    printf("[ICE] Freeing context\n");

    // PHASE 3 FIX: Disconnect signal handlers before destroying agent
    if (ctx->agent) {
        if (ctx->gathering_handler_id != 0) {
            g_signal_handler_disconnect(ctx->agent, ctx->gathering_handler_id);
            ctx->gathering_handler_id = 0;
        }
        if (ctx->state_handler_id != 0) {
            g_signal_handler_disconnect(ctx->agent, ctx->state_handler_id);
            ctx->state_handler_id = 0;
        }
    }

    // Stop main loop and wait for thread to finish
    if (ctx->loop) {
        if (g_main_loop_is_running(ctx->loop)) {
            g_main_loop_quit(ctx->loop);
        }

        if (ctx->loop_thread) {
            g_thread_join(ctx->loop_thread);
            ctx->loop_thread = NULL;
        }

        g_main_loop_unref(ctx->loop);
        ctx->loop = NULL;
    }

    // Destroy agent (this will also remove streams)
    if (ctx->agent) {
        g_object_unref(ctx->agent);
        ctx->agent = NULL;
    }

    // PHASE 1 FIX: Free all queued messages
    if (ctx->recv_queue) {
        g_mutex_lock(&ctx->recv_mutex);

        while (!g_queue_is_empty(ctx->recv_queue)) {
            ice_message_t *msg = (ice_message_t*)g_queue_pop_head(ctx->recv_queue);
            if (msg) {
                free(msg->data);
                free(msg);
            }
        }

        g_queue_free(ctx->recv_queue);
        ctx->recv_queue = NULL;

        g_mutex_unlock(&ctx->recv_mutex);
    }

    // Destroy synchronization primitives
    g_mutex_clear(&ctx->recv_mutex);
    g_cond_clear(&ctx->recv_cond);  // PHASE 2 FIX

    free(ctx);
    printf("[ICE] Context freed\n");
}

// =============================================================================
// Candidate Gathering
// =============================================================================

// Forward declaration of callback
static void on_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data);

int ice_gather_candidates(ice_context_t *ctx, const char *stun_server, uint16_t stun_port) {
    if (!ctx || !ctx->agent) {
        fprintf(stderr, "[ICE] Invalid context\n");
        return -1;
    }

    if (!stun_server) {
        fprintf(stderr, "[ICE] Invalid STUN server\n");
        return -1;
    }

    printf("[ICE] Starting candidate gathering via STUN %s:%u\n", stun_server, stun_port);

    // Reset gathering flag
    ctx->gathering_done = 0;
    ctx->local_candidates[0] = '\0';

    // Attach gathering done callback (PHASE 3 FIX: track handler ID)
    if (ctx->gathering_handler_id == 0) {
        ctx->gathering_handler_id = g_signal_connect(G_OBJECT(ctx->agent), "candidate-gathering-done",
            G_CALLBACK(on_candidate_gathering_done), ctx);
    }

    // Start gathering
    if (!nice_agent_gather_candidates(ctx->agent, ctx->stream_id)) {
        fprintf(stderr, "[ICE] Failed to start gathering\n");
        return -1;
    }

    printf("[ICE] Waiting for candidates (max 5 seconds)...\n");

    // Wait for gathering to complete (max 5 seconds)
    for (int i = 0; i < 50; i++) {
        if (ctx->gathering_done) {
            printf("[ICE] Gathering completed after %d ms\n", i * 100);
            break;
        }
        usleep(100000); // 100ms
    }

    // Check if we got any candidates
    if (!ctx->gathering_done) {
        fprintf(stderr, "[ICE] Gathering timeout\n");
        return -1;
    }

    if (strlen(ctx->local_candidates) == 0) {
        fprintf(stderr, "[ICE] No candidates gathered\n");
        return -1;
    }

    return 0;
}

// =============================================================================
// DHT Candidate Exchange
// =============================================================================

int ice_publish_to_dht(ice_context_t *ctx, const char *my_fingerprint) {
    if (!ctx || !my_fingerprint) {
        fprintf(stderr, "[ICE] Invalid parameters\n");
        return -1;
    }

    if (strlen(ctx->local_candidates) == 0) {
        fprintf(stderr, "[ICE] No candidates to publish\n");
        return -1;
    }

    printf("[ICE] Publishing %zu bytes of candidates to DHT\n",
           strlen(ctx->local_candidates));

    // Derive DHT key from fingerprint
    char dht_key_input[256];
    snprintf(dht_key_input, sizeof(dht_key_input), "%s:ice_candidates", my_fingerprint);

    // Hash key with SHA3-512 and get hex output (128 hex chars)
    char hex_key[129];  // 128 hex chars + null terminator
    if (qgp_sha3_512_hex((uint8_t*)dht_key_input, strlen(dht_key_input),
                         hex_key, sizeof(hex_key)) != 0) {
        fprintf(stderr, "[ICE] Failed to hash DHT key\n");
        return -1;
    }

    printf("[ICE] DHT key: %.32s... (%zu chars)\n", hex_key, strlen(hex_key));

    // Get DHT singleton
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        fprintf(stderr, "[ICE] DHT singleton not available\n");
        return -1;
    }

    // Publish to DHT (7-day TTL)
    int result = dht_put(dht,
                         (uint8_t*)hex_key, strlen(hex_key),
                         (uint8_t*)ctx->local_candidates, strlen(ctx->local_candidates));

    if (result == 0) {
        printf("[ICE] Successfully published candidates to DHT\n");
    } else {
        fprintf(stderr, "[ICE] Failed to publish candidates to DHT\n");
    }

    return result;
}

int ice_fetch_from_dht(ice_context_t *ctx, const char *peer_fingerprint) {
    if (!ctx || !peer_fingerprint) {
        fprintf(stderr, "[ICE] Invalid parameters\n");
        return -1;
    }

    printf("[ICE] Fetching candidates from DHT for peer %.32s...\n", peer_fingerprint);

    // Derive DHT key from peer fingerprint
    char dht_key_input[256];
    snprintf(dht_key_input, sizeof(dht_key_input), "%s:ice_candidates", peer_fingerprint);

    // Hash key with SHA3-512 and get hex output (128 hex chars)
    char hex_key[129];  // 128 hex chars + null terminator
    if (qgp_sha3_512_hex((uint8_t*)dht_key_input, strlen(dht_key_input),
                         hex_key, sizeof(hex_key)) != 0) {
        fprintf(stderr, "[ICE] Failed to hash DHT key\n");
        return -1;
    }

    printf("[ICE] DHT key: %.32s... (%zu chars)\n", hex_key, strlen(hex_key));

    // Get DHT singleton
    dht_context_t *dht = dht_singleton_get();
    if (!dht) {
        fprintf(stderr, "[ICE] DHT singleton not available\n");
        return -1;
    }

    // Fetch from DHT
    uint8_t *data = NULL;
    size_t len = 0;
    int result = dht_get(dht, (uint8_t*)hex_key, strlen(hex_key), &data, &len);

    if (result != 0 || !data) {
        fprintf(stderr, "[ICE] Failed to fetch candidates from DHT\n");
        if (data) free(data);
        return -1;
    }

    printf("[ICE] Fetched %zu bytes of candidates from DHT\n", len);

    // Copy to remote_candidates (ensure null termination)
    size_t copy_len = len < MAX_CANDIDATES_SIZE - 1 ? len : MAX_CANDIDATES_SIZE - 1;
    memcpy(ctx->remote_candidates, data, copy_len);
    ctx->remote_candidates[copy_len] = '\0';

    free(data);

    printf("[ICE] Successfully fetched candidates from DHT\n");
    return 0;
}

// =============================================================================
// Connection Establishment
// =============================================================================

// Forward declarations
static int parse_remote_candidates(ice_context_t *ctx);
static void on_component_state_changed(NiceAgent *agent, guint stream_id,
    guint component_id, guint state, gpointer user_data);

int ice_connect(ice_context_t *ctx) {
    if (!ctx || !ctx->agent) {
        fprintf(stderr, "[ICE] Invalid context\n");
        return -1;
    }

    printf("[ICE] Starting ICE connectivity checks\n");

    // Parse and add remote candidates
    int candidate_count = parse_remote_candidates(ctx);
    if (candidate_count <= 0) {
        fprintf(stderr, "[ICE] No valid remote candidates\n");
        return -1;
    }

    printf("[ICE] Added %d remote candidates\n", candidate_count);

    // Reset connection state
    ctx->connected = 0;

    // Attach state change callback (PHASE 3 FIX: track handler ID)
    if (ctx->state_handler_id == 0) {
        ctx->state_handler_id = g_signal_connect(G_OBJECT(ctx->agent), "component-state-changed",
            G_CALLBACK(on_component_state_changed), ctx);
    }

    printf("[ICE] Waiting for connection (max 10 seconds)...\n");

    // Wait for connection (max 10 seconds)
    for (int i = 0; i < 100; i++) {
        if (ctx->connected) {
            printf("[ICE] Connection established after %d ms\n", i * 100);
            return 0;
        }
        usleep(100000); // 100ms
    }

    // Timeout
    fprintf(stderr, "[ICE] Connection timeout after 10 seconds\n");
    return -1;
}

// =============================================================================
// Data Transfer
// =============================================================================

int ice_send(ice_context_t *ctx, const uint8_t *data, size_t len) {
    if (!ctx || !data || len == 0) {
        fprintf(stderr, "[ICE] Invalid send parameters\n");
        return -1;
    }

    if (!ctx->agent) {
        fprintf(stderr, "[ICE] No agent available\n");
        return -1;
    }

    if (!ctx->connected) {
        fprintf(stderr, "[ICE] Not connected, cannot send\n");
        return -1;
    }

    // Send via nice_agent_send
    int sent = nice_agent_send(ctx->agent, ctx->stream_id,
                               ctx->component_id, len, (const gchar*)data);

    if (sent < 0) {
        fprintf(stderr, "[ICE] Send failed\n");
        return -1;
    }

    if ((size_t)sent != len) {
        fprintf(stderr, "[ICE] Partial send: %d/%zu bytes\n", sent, len);
    }

    return sent;
}

/**
 * Receive data with timeout (PHASE 2 FIX)
 *
 * Blocks until data is available or timeout expires.
 * Uses GCond for efficient waiting (no busy-wait polling).
 *
 * @param ctx: ICE context
 * @param buf: Output buffer
 * @param buflen: Buffer size
 * @param timeout_ms: Timeout in milliseconds (0 = non-blocking, -1 = infinite)
 * @return: Number of bytes received, 0 on timeout/no data, -1 on error
 */
int ice_recv_timeout(ice_context_t *ctx, uint8_t *buf, size_t buflen, int timeout_ms) {
    if (!ctx || !buf || buflen == 0) {
        fprintf(stderr, "[ICE] Invalid recv parameters\n");
        return -1;
    }

    if (!ctx->agent) {
        fprintf(stderr, "[ICE] No agent available\n");
        return -1;
    }

    if (!ctx->connected) {
        fprintf(stderr, "[ICE] Not connected, cannot recv\n");
        return -1;
    }

    g_mutex_lock(&ctx->recv_mutex);

    // Wait for data if queue is empty
    if (g_queue_is_empty(ctx->recv_queue)) {
        if (timeout_ms == 0) {
            // Non-blocking: return immediately
            g_mutex_unlock(&ctx->recv_mutex);
            return 0;
        } else if (timeout_ms < 0) {
            // Infinite wait
            g_cond_wait(&ctx->recv_cond, &ctx->recv_mutex);
        } else {
            // Timed wait
            gint64 end_time = g_get_monotonic_time() + (timeout_ms * 1000);  // microseconds
            if (!g_cond_wait_until(&ctx->recv_cond, &ctx->recv_mutex, end_time)) {
                // Timeout
                g_mutex_unlock(&ctx->recv_mutex);
                return 0;
            }
        }

        // Check again after waking up (spurious wakeup or shutdown)
        if (g_queue_is_empty(ctx->recv_queue)) {
            g_mutex_unlock(&ctx->recv_mutex);
            return 0;
        }
    }

    // Dequeue message (PHASE 1 FIX)
    ice_message_t *msg = (ice_message_t*)g_queue_pop_head(ctx->recv_queue);
    if (!msg) {
        g_mutex_unlock(&ctx->recv_mutex);
        return 0;
    }

    // Copy to output buffer
    size_t copy_len = msg->len < buflen ? msg->len : buflen;
    memcpy(buf, msg->data, copy_len);

    // Warn if buffer was too small
    if (msg->len > buflen) {
        fprintf(stderr, "[ICE] Warning: Message truncated (%zu bytes, buffer %zu)\n",
                msg->len, buflen);
    }

    // Free message
    free(msg->data);
    free(msg);

    g_mutex_unlock(&ctx->recv_mutex);

    printf("[ICE] Read %zu bytes from queue (%u messages remaining)\n",
           copy_len, g_queue_get_length(ctx->recv_queue));

    return (int)copy_len;
}

/**
 * Receive data (non-blocking)
 *
 * Wrapper for ice_recv_timeout() with 0 timeout.
 * Returns immediately if no data is available.
 *
 * @param ctx: ICE context
 * @param buf: Output buffer
 * @param buflen: Buffer size
 * @return: Number of bytes received, 0 if no data, -1 on error
 */
int ice_recv(ice_context_t *ctx, uint8_t *buf, size_t buflen) {
    return ice_recv_timeout(ctx, buf, buflen, 0);  // Non-blocking
}

// =============================================================================
// Utility Functions
// =============================================================================

int ice_is_connected(ice_context_t *ctx) {
    if (!ctx) return 0;
    return ctx->connected;
}

void ice_shutdown(ice_context_t *ctx) {
    if (!ctx) return;

    printf("[ICE] Shutting down connection\n");

    // PHASE 3 FIX: Unregister receive callback before stream removal
    if (ctx->agent && ctx->stream_id) {
        // Detach receive callback
        nice_agent_attach_recv(ctx->agent, ctx->stream_id, ctx->component_id,
                              g_main_loop_get_context(ctx->loop),
                              NULL, NULL);

        // Stop connectivity checks and remove stream
        nice_agent_remove_stream(ctx->agent, ctx->stream_id);
        ctx->stream_id = 0;  // Mark as removed
    }

    // PHASE 1 FIX: Clear message queue
    g_mutex_lock(&ctx->recv_mutex);

    // Free all queued messages
    while (!g_queue_is_empty(ctx->recv_queue)) {
        ice_message_t *msg = (ice_message_t*)g_queue_pop_head(ctx->recv_queue);
        if (msg) {
            free(msg->data);
            free(msg);
        }
    }

    // PHASE 2 FIX: Wake up any threads waiting in ice_recv_timeout()
    g_cond_broadcast(&ctx->recv_cond);

    g_mutex_unlock(&ctx->recv_mutex);

    ctx->connected = 0;

    printf("[ICE] Connection shutdown complete\n");
}

const char* ice_get_local_candidates(ice_context_t *ctx) {
    if (!ctx) return NULL;
    return ctx->local_candidates;
}

const char* ice_get_remote_candidates(ice_context_t *ctx) {
    if (!ctx) return NULL;
    return ctx->remote_candidates;
}

// =============================================================================
// Callback Implementations (Phase 2.2, 3.2)
// =============================================================================

// Candidate gathering done callback (Phase 2.2)
static void on_candidate_gathering_done(NiceAgent *agent, guint stream_id, gpointer user_data) {
    ice_context_t *ctx = (ice_context_t*)user_data;

    printf("[ICE] Candidate gathering done for stream %u\n", stream_id);

    // Get all local candidates
    GSList *candidates = nice_agent_get_local_candidates(
        agent, stream_id, ctx->component_id);

    int count = g_slist_length(candidates);

    // Serialize to SDP format
    ctx->local_candidates[0] = '\0';
    for (GSList *item = candidates; item; item = item->next) {
        NiceCandidate *c = (NiceCandidate*)item->data;
        gchar *candidate_str = nice_agent_generate_local_candidate_sdp(agent, c);

        if (candidate_str) {
            size_t remaining = MAX_CANDIDATES_SIZE - strlen(ctx->local_candidates) - 1;
            if (remaining > strlen(candidate_str) + 1) {
                strcat(ctx->local_candidates, candidate_str);
                strcat(ctx->local_candidates, "\n");
            }
            g_free(candidate_str);
        }
    }

    g_slist_free_full(candidates, (GDestroyNotify)&nice_candidate_free);
    ctx->gathering_done = 1;

    printf("[ICE] Gathered %d candidates (%zu bytes)\n",
           count, strlen(ctx->local_candidates));
}

// Component state change callback (Phase 3.2)
static void on_component_state_changed(NiceAgent *agent, guint stream_id,
    guint component_id, guint state, gpointer user_data) {

    ice_context_t *ctx = (ice_context_t*)user_data;

    const char *state_name = NULL;
    switch (state) {
        case NICE_COMPONENT_STATE_DISCONNECTED:
            state_name = "DISCONNECTED";
            ctx->connected = 0;
            break;
        case NICE_COMPONENT_STATE_GATHERING:
            state_name = "GATHERING";
            break;
        case NICE_COMPONENT_STATE_CONNECTING:
            state_name = "CONNECTING";
            break;
        case NICE_COMPONENT_STATE_CONNECTED:
            state_name = "CONNECTED";
            ctx->connected = 1;
            break;
        case NICE_COMPONENT_STATE_READY:
            state_name = "READY";
            ctx->connected = 1;
            break;
        case NICE_COMPONENT_STATE_FAILED:
            state_name = "FAILED";
            ctx->connected = 0;
            break;
        default:
            state_name = "UNKNOWN";
            break;
    }

    printf("[ICE] Stream %u Component %u: %s\n", stream_id, component_id, state_name);
}

// Remote candidate parsing helper (Phase 3.1)
static int parse_remote_candidates(ice_context_t *ctx) {
    if (!ctx || strlen(ctx->remote_candidates) == 0) {
        fprintf(stderr, "[ICE] No remote candidates to parse\n");
        return -1;
    }

    printf("[ICE] Parsing remote candidates (%zu bytes)\n", strlen(ctx->remote_candidates));

    // Create a working copy (strtok modifies the string)
    char *candidates_copy = strdup(ctx->remote_candidates);
    if (!candidates_copy) {
        fprintf(stderr, "[ICE] Failed to allocate memory for parsing\n");
        return -1;
    }

    // Parse SDP-formatted candidates (newline-separated)
    char *line = strtok(candidates_copy, "\n");
    int count = 0;
    int errors = 0;

    while (line != NULL) {
        // Skip empty lines
        if (strlen(line) == 0) {
            line = strtok(NULL, "\n");
            continue;
        }

        // Parse candidate from SDP string
        NiceCandidate *c = nice_agent_parse_remote_candidate_sdp(
            ctx->agent, ctx->stream_id, line);

        if (c) {
            // Add to agent (libnice takes ownership)
            GSList *candidates = g_slist_append(NULL, c);
            int result = nice_agent_set_remote_candidates(
                ctx->agent, ctx->stream_id, ctx->component_id, candidates);

            if (result > 0) {
                count++;
            } else {
                errors++;
                fprintf(stderr, "[ICE] Failed to set remote candidate\n");
            }

            g_slist_free(candidates);
        } else {
            errors++;
            fprintf(stderr, "[ICE] Failed to parse candidate: %.40s...\n", line);
        }

        line = strtok(NULL, "\n");
    }

    free(candidates_copy);

    printf("[ICE] Parsed %d candidates (%d errors)\n", count, errors);
    return count;
}
