/**
 * Nodus — SQLite DHT Storage
 *
 * Persistent storage for DHT values with TTL cleanup.
 * Schema matches the design doc's nodus_values table.
 *
 * @file nodus_storage.h
 */

#ifndef NODUS_STORAGE_H
#define NODUS_STORAGE_H

#include "nodus/nodus_types.h"
#include "core/nodus_value.h"
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Storage quotas ──────────────────────────────────────────────── */
#define NODUS_STORAGE_MAX_VALUES     100000
#define NODUS_STORAGE_MAX_BYTES      (500ULL * 1024 * 1024)  /* 500 MB */
#define NODUS_STORAGE_MAX_PER_OWNER  1000

/** DHT hinted handoff entry (failed replication, pending retry) */
typedef struct {
    int64_t     id;
    nodus_key_t node_id;
    char        peer_ip[64];
    uint16_t    peer_port;
    uint8_t    *frame_data;
    size_t      frame_len;
    uint64_t    created_at;
    uint64_t    expires_at;
    int         retry_count;
} nodus_dht_hint_t;

/** DHT storage handle */
typedef struct {
    sqlite3 *db;
    sqlite3_stmt *stmt_put;
    sqlite3_stmt *stmt_get;
    sqlite3_stmt *stmt_get_all;
    sqlite3_stmt *stmt_delete;
    sqlite3_stmt *stmt_cleanup;
    sqlite3_stmt *stmt_count;
    sqlite3_stmt *stmt_put_if_newer;
    sqlite3_stmt *stmt_fetch_batch;
    /* Quota checks */
    sqlite3_stmt *stmt_quota_total_bytes;
    sqlite3_stmt *stmt_quota_owner_count;
    /* EXCLUSIVE ownership check */
    sqlite3_stmt *stmt_exclusive_owner;
    /* Hinted handoff for DHT replication */
    sqlite3_stmt *stmt_hint_insert;
    sqlite3_stmt *stmt_hint_get;
    sqlite3_stmt *stmt_hint_delete;
    sqlite3_stmt *stmt_hint_cleanup;
    sqlite3_stmt *stmt_hint_count;
} nodus_storage_t;

/**
 * Open (or create) DHT storage database.
 *
 * @param path     SQLite database file path
 * @param store    Output storage handle
 * @return 0 on success, -1 on error
 */
int nodus_storage_open(const char *path, nodus_storage_t *store);

/**
 * Close storage and free resources.
 */
void nodus_storage_close(nodus_storage_t *store);

/**
 * Store a value (INSERT OR REPLACE based on key_hash + owner_fp + value_id).
 * EXCLUSIVE values enforce first-writer-owns: if the key already has an
 * EXCLUSIVE value from a different owner, the PUT is rejected.
 *
 * @param store   Storage handle
 * @param val     Value to store (must be signed)
 * @return 0 on success, -1 on error, -2 if EXCLUSIVE key owned by another identity
 */
int nodus_storage_put(nodus_storage_t *store, const nodus_value_t *val);

/**
 * Get the best value for a key (highest seq, single result).
 *
 * @param store     Storage handle
 * @param key_hash  Key to look up
 * @param val_out   Output value (caller must free with nodus_value_free)
 * @return 0 on success, -1 if not found or error
 */
int nodus_storage_get(nodus_storage_t *store,
                      const nodus_key_t *key_hash,
                      nodus_value_t **val_out);

/**
 * Get all values for a key (multi-writer).
 *
 * @param store      Storage handle
 * @param key_hash   Key to look up
 * @param vals_out   Output array of values (caller must free each + array)
 * @param count_out  Number of values
 * @return 0 on success, -1 on error
 */
int nodus_storage_get_all(nodus_storage_t *store,
                          const nodus_key_t *key_hash,
                          nodus_value_t ***vals_out,
                          size_t *count_out);

/**
 * Delete a specific value.
 *
 * @param store     Storage handle
 * @param key_hash  Key
 * @param owner_fp  Owner fingerprint
 * @param value_id  Value ID
 * @return 0 on success, -1 on error
 */
int nodus_storage_delete(nodus_storage_t *store,
                         const nodus_key_t *key_hash,
                         const nodus_key_t *owner_fp,
                         uint64_t value_id);

/**
 * Clean up expired EPHEMERAL values.
 *
 * @param store  Storage handle
 * @return Number of values cleaned, or -1 on error
 */
int nodus_storage_cleanup(nodus_storage_t *store);

/**
 * Get total number of stored values.
 */
int nodus_storage_count(nodus_storage_t *store);

/**
 * Store a value only if it has a higher seq than existing.
 * On equal seq, tiebreak by SHA3-256(data) — higher hash wins.
 * Atomic single-SQL operation (no TOCTOU race).
 *
 * @return 0 = stored, 1 = skipped (existing is newer/equal), -1 = error
 */
int nodus_storage_put_if_newer(nodus_storage_t *store, const nodus_value_t *val);

/**
 * Fetch a batch of values for republish (bookmark pagination).
 * Returns values with key_hash > after_key, ordered by key_hash, up to batch_size.
 * Pass NULL for after_key to start from the beginning.
 * Finalizes statement immediately (no held cursor — safe for WAL).
 *
 * @param store      Storage handle
 * @param after_key  Bookmark (last key from previous batch), or NULL for first batch
 * @param batch_out  Output array (must hold batch_size entries, caller frees each)
 * @param batch_size Maximum values to fetch
 * @return Number of values fetched (< batch_size means end of data)
 */
int nodus_storage_fetch_batch(nodus_storage_t *store,
                               const nodus_key_t *after_key,
                               nodus_value_t **batch_out,
                               int batch_size);

/**
 * Check storage quotas before a PUT.
 * Checks: global count, global bytes, per-owner count.
 *
 * @param store     Storage handle
 * @param owner_fp  Owner fingerprint (for per-owner check)
 * @return 0 = OK (within quota), -1 = quota exceeded
 */
int nodus_storage_check_quota(nodus_storage_t *store,
                               const nodus_key_t *owner_fp);

/**
 * Count values for a specific key (all owners).
 *
 * @param store     Storage handle
 * @param key_hash  Key to count
 * @return count >= 0 on success, -1 on error
 */
int nodus_storage_count_key(nodus_storage_t *store,
                             const nodus_key_t *key_hash);

/**
 * Check if a specific owner has a value for a key.
 *
 * @param store     Storage handle
 * @param key_hash  Key to check
 * @param owner_fp  Owner fingerprint
 * @return 1 if owner has value, 0 if not, -1 on error
 */
int nodus_storage_has_owner(nodus_storage_t *store,
                             const nodus_key_t *key_hash,
                             const nodus_key_t *owner_fp);

/* ── DHT Hinted Handoff ─────────────────────────────────────────── */

/**
 * Insert a hinted handoff entry (failed DHT replication).
 * TTL: 7 days. No cap.
 */
int nodus_storage_hinted_insert(nodus_storage_t *store,
                                 const nodus_key_t *node_id,
                                 const char *peer_ip, uint16_t peer_port,
                                 const uint8_t *frame_data, size_t frame_len);

/**
 * Get pending hints for a node (up to limit).
 * Caller must free entries with nodus_storage_hinted_free().
 */
int nodus_storage_hinted_get(nodus_storage_t *store,
                              const nodus_key_t *node_id,
                              int limit,
                              nodus_dht_hint_t **entries_out,
                              size_t *count_out);

/** Delete a hint by ID (on successful delivery). */
int nodus_storage_hinted_delete(nodus_storage_t *store, int64_t id);

/** Delete expired hinted handoff entries. Returns count deleted. */
int nodus_storage_hinted_cleanup(nodus_storage_t *store);

/** Get count of pending hints. */
int nodus_storage_hinted_count(nodus_storage_t *store);

/** Free hint entries returned by hinted_get. */
void nodus_storage_hinted_free(nodus_dht_hint_t *entries, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_STORAGE_H */
