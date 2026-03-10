/**
 * Nodus — Channel Storage
 *
 * Per-channel SQLite tables with seq_id assignment,
 * hinted handoff queue, and 7-day retention cleanup.
 *
 * @file nodus_channel_store.h
 */

#ifndef NODUS_CHANNEL_STORE_H
#define NODUS_CHANNEL_STORE_H

#include "nodus/nodus_types.h"
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

/* nodus_channel_post_t is defined in nodus/nodus_types.h */

/* ── Hinted handoff entry ───────────────────────────────────────── */

typedef struct {
    int64_t     id;
    nodus_key_t target_fp;
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    uint8_t    *post_data;      /* Serialized post */
    size_t      post_data_len;
    uint64_t    created_at;
    int         retry_count;
    uint64_t    expires_at;
} nodus_hinted_entry_t;

/* ── Channel store ──────────────────────────────────────────────── */

typedef struct {
    sqlite3 *db;
    /* Hinted handoff prepared statements */
    sqlite3_stmt *stmt_hint_insert;
    sqlite3_stmt *stmt_hint_get;
    sqlite3_stmt *stmt_hint_delete;
    sqlite3_stmt *stmt_hint_cleanup;
    sqlite3_stmt *stmt_hint_update_retry;
} nodus_channel_store_t;

/**
 * Open channel storage database.
 * Creates hinted_handoff table. Channel tables created on demand.
 */
int nodus_channel_store_open(const char *db_path, nodus_channel_store_t *store);

/**
 * Close channel storage and free resources.
 */
void nodus_channel_store_close(nodus_channel_store_t *store);

/**
 * Create a channel table. Idempotent — does nothing if already exists.
 * @param uuid  16-byte UUID (validated and converted to hex internally)
 */
int nodus_channel_create(nodus_channel_store_t *store,
                          const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * Check if a channel table exists.
 */
bool nodus_channel_exists(nodus_channel_store_t *store,
                           const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * Insert a post. Assigns next seq_id. Deduplicates by post_uuid.
 * @param post  Post to insert (seq_id will be set on return)
 * @return 0 on success, 1 if duplicate post_uuid, -1 on error
 */
int nodus_channel_post(nodus_channel_store_t *store,
                        nodus_channel_post_t *post);

/**
 * Get posts after a given seq_id (for client sync).
 * @param since_seq  Return posts with seq_id > since_seq (0 = all)
 * @param max_count  Maximum number of posts to return
 * @param posts_out  Caller frees with nodus_channel_posts_free()
 * @param count_out  Number of posts returned
 */
int nodus_channel_get_posts(nodus_channel_store_t *store,
                             const uint8_t uuid[NODUS_UUID_BYTES],
                             uint32_t since_seq, int max_count,
                             nodus_channel_post_t **posts_out,
                             size_t *count_out);

/**
 * Get the current max seq_id for a channel.
 */
uint32_t nodus_channel_max_seq(nodus_channel_store_t *store,
                                const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * Run 7-day retention cleanup on a channel.
 * @return Number of posts deleted
 */
int nodus_channel_cleanup(nodus_channel_store_t *store,
                           const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * Drop a channel table entirely (when no longer responsible).
 */
int nodus_channel_drop(nodus_channel_store_t *store,
                        const uint8_t uuid[NODUS_UUID_BYTES]);

/* ── Hinted handoff ─────────────────────────────────────────────── */

/**
 * Queue a post for hinted handoff to a target nodus.
 */
int nodus_hinted_insert(nodus_channel_store_t *store,
                         const nodus_key_t *target_fp,
                         const uint8_t uuid[NODUS_UUID_BYTES],
                         const uint8_t *post_data, size_t post_data_len);

/**
 * Get pending hinted handoff entries for a target.
 * @param max_count  Maximum entries to return
 * @param entries_out  Caller frees with nodus_hinted_entries_free()
 * @param count_out  Number of entries
 */
int nodus_hinted_get(nodus_channel_store_t *store,
                      const nodus_key_t *target_fp, int max_count,
                      nodus_hinted_entry_t **entries_out,
                      size_t *count_out);

/**
 * Delete a hinted handoff entry after successful delivery.
 */
int nodus_hinted_delete(nodus_channel_store_t *store, int64_t id);

/**
 * Increment retry count for a hinted entry.
 */
int nodus_hinted_retry(nodus_channel_store_t *store, int64_t id);

/**
 * Cleanup expired hinted handoff entries.
 * @return Number of entries deleted
 */
int nodus_hinted_cleanup(nodus_channel_store_t *store);

/* ── Cleanup helpers ────────────────────────────────────────────── */

/** Free an array of posts. */
void nodus_channel_posts_free(nodus_channel_post_t *posts, size_t count);

/** Free a single post's heap data. */
void nodus_channel_post_free(nodus_channel_post_t *post);

/** Free an array of hinted entries. */
void nodus_hinted_entries_free(nodus_hinted_entry_t *entries, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_CHANNEL_STORE_H */
