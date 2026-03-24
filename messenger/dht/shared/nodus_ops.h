/**
 * Nodus — Convenience Operations Layer
 *
 * Direct wrapper around nodus_singleton + nodus_client for DHT operations.
 * Replaces the old dht_* compat shim with native Nodus types.
 *
 * Key differences from compat layer:
 * - Uses nodus types directly (nodus_key_t, nodus_value_t)
 * - Handles key hashing, signing, and value creation internally
 * - Listener dispatch with per-key callbacks (same shape as old API)
 * - No chunking abstraction (Nodus supports 1MB values)
 *
 * @file nodus_ops.h
 */

#ifndef NODUS_OPS_H
#define NODUS_OPS_H

#include "nodus/nodus.h"
#include "nodus/nodus_types.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Listener callback (same shape as old dht_listen_callback_t) ── */

typedef bool (*nodus_ops_listen_cb_t)(const uint8_t *data, size_t data_len,
                                      bool expired, void *user_data);
typedef void (*nodus_ops_listen_cleanup_t)(void *user_data);

/* ── PUT operations ────────────────────────────────────────────── */

/**
 * Store a signed ephemeral value on the DHT.
 * Hashes key, creates value, signs with singleton identity, sends PUT.
 *
 * @param key       Raw key bytes (hashed to SHA3-512 internally)
 * @param key_len   Key length
 * @param data      Payload
 * @param data_len  Payload length
 * @param ttl       TTL in seconds (0 = permanent)
 * @param vid       Value ID (0 = auto from identity)
 * @return 0 on success, -1 on error
 */
int nodus_ops_put(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint32_t ttl, uint64_t vid);

/**
 * Store using a string key (hashed to SHA3-512).
 */
int nodus_ops_put_str(const char *str_key,
                      const uint8_t *data, size_t data_len,
                      uint32_t ttl, uint64_t vid);

/**
 * Store a permanent (never-expiring) value.
 */
int nodus_ops_put_permanent(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint64_t vid);

/* ── GET operations ────────────────────────────────────────────── */

/**
 * Retrieve latest value for a key.
 * Caller must free *data_out.
 *
 * @return 0 on success, -1 on error or not found
 */
int nodus_ops_get(const uint8_t *key, size_t key_len,
                  uint8_t **data_out, size_t *len_out);

/**
 * Retrieve using a string key.
 */
int nodus_ops_get_str(const char *str_key,
                      uint8_t **data_out, size_t *len_out);

/**
 * Retrieve all values for a key (all writers).
 * Caller must free each values_out[i] and the arrays.
 *
 * @return 0 on success (count_out may be 0), -1 on error
 */
int nodus_ops_get_all(const uint8_t *key, size_t key_len,
                      uint8_t ***values_out, size_t **lens_out,
                      size_t *count_out);

/**
 * Retrieve all values with their value IDs.
 * Caller must free each values_out[i] and all arrays.
 */
int nodus_ops_get_all_with_ids(const uint8_t *key, size_t key_len,
                               uint8_t ***values_out, size_t **lens_out,
                               uint64_t **vids_out, size_t *count_out);

/**
 * String-key variant of nodus_ops_get_all.
 */
int nodus_ops_get_all_str(const char *str_key,
                           uint8_t ***values_out, size_t **lens_out,
                           size_t *count_out);

/**
 * String-key variant of nodus_ops_get_all_with_ids.
 */
int nodus_ops_get_all_str_with_ids(const char *str_key,
                                    uint8_t ***values_out, size_t **lens_out,
                                    uint64_t **vids_out, size_t *count_out);

/* ── LISTEN operations ─────────────────────────────────────────── */

/**
 * Subscribe to changes on a DHT key.
 * When the key's value changes, callback is invoked with raw data.
 *
 * @param key       Raw key bytes
 * @param key_len   Key length
 * @param callback  Called on value change (return false to auto-cancel)
 * @param user_data Passed to callback
 * @param cleanup   Called when listener is cancelled (may be NULL)
 * @return Token > 0 on success, 0 on failure
 */
size_t nodus_ops_listen(const uint8_t *key, size_t key_len,
                        nodus_ops_listen_cb_t callback,
                        void *user_data,
                        nodus_ops_listen_cleanup_t cleanup);

/**
 * Cancel a listener by token.
 */
void nodus_ops_cancel_listen(size_t token);

/**
 * Cancel all active listeners.
 */
void nodus_ops_cancel_all(void);

/**
 * Get count of active listeners.
 */
size_t nodus_ops_listen_count(void);

/**
 * Check if a listener is still active.
 */
bool nodus_ops_is_listener_active(size_t token);

/* ── Presence operations ───────────────────────────────────────── */

/**
 * Batch presence query via Nodus server.
 * Converts hex fingerprints to binary keys, queries server, maps results back.
 *
 * @param fingerprints  Array of hex fingerprint strings (128 chars each)
 * @param count         Number of fingerprints
 * @param online_out    Output: true/false per fingerprint (caller provides)
 * @param last_seen_out Output (optional): Unix timestamp per fingerprint
 * @return Number of online contacts, or -1 on error
 */
int nodus_ops_presence_query(const char **fingerprints, int count,
                               bool *online_out, uint64_t *last_seen_out);

/* ── Utility ───────────────────────────────────────────────────── */

/**
 * Check if the Nodus singleton is connected and authenticated.
 */
bool nodus_ops_is_ready(void);

/**
 * Get the value_id for the current identity (for PUT operations).
 */
uint64_t nodus_ops_value_id(void);

/**
 * Get the hex fingerprint of the current identity.
 * @return Fingerprint string, or NULL if not initialized
 */
const char *nodus_ops_fingerprint(void);

/**
 * Global value_changed dispatcher — set as on_value_changed callback.
 * Routes notifications to per-key listener callbacks.
 * Do not call directly; pass to nodus_client_config_t.on_value_changed.
 */
void nodus_ops_dispatch(const nodus_key_t *key,
                        const nodus_value_t *val,
                        void *user_data);

/* ── Channel operations (TCP 4003) ─────────────────────────────── */

/** Callback for channel post push notifications */
typedef void (*nodus_ops_ch_post_cb_t)(const uint8_t channel_uuid[16],
                                        const nodus_channel_post_t *post,
                                        void *user_data);

/**
 * Initialize the channel connection pool.
 * Must be called once after nodus singleton is ready.
 *
 * @param on_post   Global callback for push post notifications (may be NULL)
 * @param user_data Passed to on_post callback
 * @return 0 on success
 */
int nodus_ops_ch_init(nodus_ops_ch_post_cb_t on_post, void *user_data);

/**
 * Update the channel push post callback after initialization.
 * Use this to register a callback from the engine layer after nodus init.
 *
 * @param on_post   Callback for push post notifications (may be NULL to disable)
 * @param user_data Passed to on_post callback
 */
void nodus_ops_ch_set_post_callback(nodus_ops_ch_post_cb_t on_post, void *user_data);

/**
 * Shut down the channel connection pool.
 * Disconnects all channel connections.
 */
void nodus_ops_ch_shutdown(void);

/**
 * Periodic health check for channel connections.
 * Detects dead connections, reconnects, and catches up missed posts.
 * Call from a periodic tick (e.g. every 60s from heartbeat thread).
 */
void nodus_ops_ch_tick(void);

/**
 * Create a channel on a connected nodus server.
 * Connects to any available server (no specific responsible node needed yet).
 *
 * @param channel_uuid  16-byte UUID for the new channel
 * @return 0 on success
 */
int nodus_ops_ch_create(const uint8_t channel_uuid[16]);

/**
 * List public channels from server (paginated).
 * Uses the main TCP 4001 client connection.
 *
 * @param offset     Pagination offset (0 = start)
 * @param limit      Maximum results (default 50, max 200)
 * @param metas_out  Output: heap-allocated array. Caller frees with free().
 * @param count_out  Number of results
 * @return 0 on success
 */
/**
 * Get a single channel's metadata from server by UUID.
 * Uses the main TCP 4001 client connection.
 *
 * @param channel_uuid  16-byte UUID
 * @param meta_out      Output: channel metadata
 * @return 0 on success
 */
int nodus_ops_ch_get(const uint8_t channel_uuid[16],
                      nodus_channel_meta_t *meta_out);

int nodus_ops_ch_list(int offset, int limit,
                       nodus_channel_meta_t **metas_out,
                       size_t *count_out);

/**
 * Search public channels by name/description (paginated).
 * Uses the main TCP 4001 client connection.
 *
 * @param query      Search string
 * @param offset     Pagination offset
 * @param limit      Maximum results
 * @param metas_out  Output: heap-allocated array. Caller frees with free().
 * @param count_out  Number of results
 * @return 0 on success
 */
int nodus_ops_ch_search(const char *query, int offset, int limit,
                         nodus_channel_meta_t **metas_out,
                         size_t *count_out);

/**
 * Post to a channel.
 * Auto-connects to a responsible node if not already connected.
 *
 * @param channel_uuid  16-byte channel UUID
 * @param post_uuid     16-byte post UUID (caller generates)
 * @param body          Post body bytes
 * @param body_len      Body length
 * @param timestamp     Post creation timestamp (Unix seconds)
 * @param sig           Dilithium5 signature over post content
 * @param received_at_out  If non-NULL, receives server-assigned received_at (ms)
 * @return 0 on success
 */
int nodus_ops_ch_post(const uint8_t channel_uuid[16],
                      const uint8_t post_uuid[16],
                      const uint8_t *body, size_t body_len,
                      uint64_t timestamp, const nodus_sig_t *sig,
                      uint64_t *received_at_out);

/**
 * Get posts from a channel.
 * Auto-connects to a responsible node if not already connected.
 *
 * @param channel_uuid      16-byte channel UUID
 * @param since_received_at Get posts after this timestamp (0 = from start)
 * @param max_count         Maximum posts to return (0 = server default)
 * @param posts_out         Output: array of posts (caller frees with nodus_client_free_posts)
 * @param count_out         Output: number of posts
 * @return 0 on success
 */
int nodus_ops_ch_get_posts(const uint8_t channel_uuid[16],
                            uint64_t since_received_at, int max_count,
                            nodus_channel_post_t **posts_out,
                            size_t *count_out);

/**
 * Subscribe to push notifications for a channel.
 * Auto-connects to a responsible node if not already connected.
 *
 * @param channel_uuid  16-byte channel UUID
 * @return 0 on success
 */
int nodus_ops_ch_subscribe(const uint8_t channel_uuid[16]);

/**
 * Unsubscribe from channel notifications.
 *
 * @param channel_uuid  16-byte channel UUID
 * @return 0 on success
 */
int nodus_ops_ch_unsubscribe(const uint8_t channel_uuid[16]);

/**
 * Disconnect a specific channel connection.
 * Useful when a channel is no longer needed.
 *
 * @param channel_uuid  16-byte channel UUID
 */
void nodus_ops_ch_disconnect(const uint8_t channel_uuid[16]);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_OPS_H */
