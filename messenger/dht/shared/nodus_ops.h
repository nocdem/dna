/**
 * Nodus v5 — Convenience Operations Layer
 *
 * Direct wrapper around nodus_singleton + nodus_client for DHT operations.
 * Replaces the old dht_* compat shim with native Nodus types.
 *
 * Key differences from compat layer:
 * - Uses nodus types directly (nodus_key_t, nodus_value_t)
 * - Handles key hashing, signing, and value creation internally
 * - Listener dispatch with per-key callbacks (same shape as old API)
 * - No chunking abstraction (Nodus v5 supports 1MB values)
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

#ifdef __cplusplus
}
#endif

#endif /* NODUS_OPS_H */
