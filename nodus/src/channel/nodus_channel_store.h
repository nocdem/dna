/**
 * Nodus — Channel Storage
 *
 * Per-channel SQLite tables with received_at ordering,
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

/* ── Channel metadata ───────────────────────────────────────────── */

typedef struct {
    uint8_t     uuid[NODUS_UUID_BYTES];
    bool        encrypted;          /* true for encrypted group channels */
    uint64_t    created_at;
    nodus_key_t creator_fp;         /* H-07: fingerprint of the channel creator */
    bool        has_creator_fp;     /* true if creator_fp was stored */
    char        name[101];          /* Channel name (max 100 chars + null) */
    char        description[501];   /* Channel description (max 500 chars + null) */
    bool        is_public;          /* true if discoverable in ch_list */
} nodus_channel_meta_t;

/* ── Push target (encrypted channels only) ──────────────────────── */

typedef struct {
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    nodus_key_t target_fp;
    uint64_t    added_at;
} nodus_push_target_t;

/* ── Pending push entry (store-and-forward for encrypted channels) ── */

typedef struct {
    int64_t     id;
    uint8_t     channel_uuid[NODUS_UUID_BYTES];
    nodus_key_t target_fp;
    uint8_t    *post_data;      /* Serialized post */
    size_t      post_data_len;
    uint64_t    created_at;
    uint64_t    expires_at;
} nodus_pending_push_t;

/* ── Channel store ──────────────────────────────────────────────── */

typedef struct {
    sqlite3 *db;
    /* Hinted handoff prepared statements */
    sqlite3_stmt *stmt_hint_insert;
    sqlite3_stmt *stmt_hint_get;
    sqlite3_stmt *stmt_hint_delete;
    sqlite3_stmt *stmt_hint_cleanup;
    sqlite3_stmt *stmt_hint_update_retry;
    /* Push target prepared statements */
    sqlite3_stmt *stmt_pt_insert;
    sqlite3_stmt *stmt_pt_delete;
    sqlite3_stmt *stmt_pt_get;
    sqlite3_stmt *stmt_pt_has;
    /* Pending push prepared statements (store-and-forward) */
    sqlite3_stmt *stmt_pp_insert;
    sqlite3_stmt *stmt_pp_get;
    sqlite3_stmt *stmt_pp_delete;
    sqlite3_stmt *stmt_pp_cleanup;
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
 * @param uuid       16-byte UUID (validated and converted to hex internally)
 * @param encrypted  true for encrypted group channels (skips sig verify, uses push targets)
 * @param name       Channel name (NULL ok — stored as empty string)
 * @param description Channel description (NULL ok — stored as empty string)
 * @param is_public  true if channel should appear in ch_list discovery
 */
int nodus_channel_create(nodus_channel_store_t *store,
                          const uint8_t uuid[NODUS_UUID_BYTES],
                          bool encrypted,
                          const char *name,
                          const char *description,
                          bool is_public);

/**
 * Check if a channel table exists.
 */
bool nodus_channel_exists(nodus_channel_store_t *store,
                           const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * Insert a post. Deduplicates by post_uuid (INSERT OR IGNORE).
 * If post->received_at is 0, assigns current time in ms.
 * @param post  Post to insert (received_at may be set on return)
 * @return 0 on success, 1 if duplicate post_uuid, -1 on error
 */
int nodus_channel_post(nodus_channel_store_t *store,
                        nodus_channel_post_t *post);

/**
 * Get posts after a given received_at timestamp (for client sync).
 * @param since_received_at  Return posts with received_at > this (0 = all)
 * @param max_count  Maximum number of posts to return
 * @param posts_out  Caller frees with nodus_channel_posts_free()
 * @param count_out  Number of posts returned
 */
int nodus_channel_get_posts(nodus_channel_store_t *store,
                             const uint8_t uuid[NODUS_UUID_BYTES],
                             uint64_t since_received_at, int max_count,
                             nodus_channel_post_t **posts_out,
                             size_t *count_out);

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

/**
 * List all channel UUIDs in the store (queries sqlite_master for channel_* tables).
 * @param uuids_out  Output: flat array of NODUS_UUID_BYTES-sized UUIDs. Caller frees with free().
 * @param count_out  Number of UUIDs returned
 * @return 0 on success, -1 on error
 */
int nodus_channel_store_list_all(nodus_channel_store_t *store,
                                  uint8_t **uuids_out, size_t *count_out);

/**
 * Register default channels (General, Technology, Help, etc.)
 * Idempotent — INSERT OR IGNORE. Called on server startup.
 */
void nodus_channel_store_register_defaults(nodus_channel_store_t *store);

/* ── Channel discovery (ch_list / ch_search) ───────────────────── */

/**
 * List public channels with pagination.
 * @param offset     Skip first N results
 * @param limit      Maximum results to return
 * @param metas_out  Output: array of nodus_channel_meta_t. Caller frees with free().
 * @param count_out  Number of results returned
 * @return 0 on success, -1 on error
 */
int nodus_channel_store_list_public(nodus_channel_store_t *store,
                                     int offset, int limit,
                                     nodus_channel_meta_t **metas_out,
                                     size_t *count_out);

/**
 * Search public channels by name/description (LIKE match).
 * @param query      Search string (matched with %query% on name and description)
 * @param offset     Skip first N results
 * @param limit      Maximum results to return
 * @param metas_out  Output: array of nodus_channel_meta_t. Caller frees with free().
 * @param count_out  Number of results returned
 * @return 0 on success, -1 on error
 */
int nodus_channel_store_search(nodus_channel_store_t *store,
                                const char *query,
                                int offset, int limit,
                                nodus_channel_meta_t **metas_out,
                                size_t *count_out);

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

/* ── Channel metadata ───────────────────────────────────────────── */

/**
 * Check if a channel is encrypted.
 * @return true if channel exists and has encrypted flag set
 */
bool nodus_channel_is_encrypted(nodus_channel_store_t *store,
                                 const uint8_t uuid[NODUS_UUID_BYTES]);

/**
 * Set the creator fingerprint for a channel (only if not already set).
 * @return 0 on success
 */
int nodus_channel_set_creator(nodus_channel_store_t *store,
                               const uint8_t uuid[NODUS_UUID_BYTES],
                               const nodus_key_t *creator_fp);

/**
 * Load channel metadata.
 * @return 0 on success, -1 on error or not found
 */
int nodus_channel_load_meta(nodus_channel_store_t *store,
                             const uint8_t uuid[NODUS_UUID_BYTES],
                             nodus_channel_meta_t *meta_out);

/* ── Push targets (encrypted channels) ─────────────────────────── */

/**
 * Add a push target fingerprint for an encrypted channel.
 * Idempotent — ignores duplicate (fp already exists for channel).
 */
int nodus_push_target_add(nodus_channel_store_t *store,
                           const uint8_t uuid[NODUS_UUID_BYTES],
                           const nodus_key_t *target_fp);

/**
 * Remove a push target fingerprint from an encrypted channel.
 */
int nodus_push_target_remove(nodus_channel_store_t *store,
                              const uint8_t uuid[NODUS_UUID_BYTES],
                              const nodus_key_t *target_fp);

/**
 * Get all push targets for an encrypted channel.
 * @param targets_out  Caller frees with free()
 * @param count_out    Number of targets returned
 */
int nodus_push_target_get(nodus_channel_store_t *store,
                           const uint8_t uuid[NODUS_UUID_BYTES],
                           nodus_push_target_t **targets_out,
                           size_t *count_out);

/**
 * Check if a fingerprint is a push target for an encrypted channel.
 */
bool nodus_push_target_has(nodus_channel_store_t *store,
                            const uint8_t uuid[NODUS_UUID_BYTES],
                            const nodus_key_t *target_fp);

/* ── Pending push (store-and-forward for encrypted channels) ────── */

/**
 * Queue an encrypted post for a push target that's currently offline.
 * Idempotent — dedup by (channel_uuid, target_fp, post_data).
 * @param expires_at  Expiry timestamp (seconds since epoch)
 */
int nodus_pending_push_add(nodus_channel_store_t *store,
                            const uint8_t uuid[NODUS_UUID_BYTES],
                            const nodus_key_t *target_fp,
                            const uint8_t *post_data, size_t post_data_len,
                            uint64_t expires_at);

/**
 * Get pending push entries for a target fingerprint on a specific channel.
 * @param max_count   Maximum entries to return
 * @param entries_out Caller frees with nodus_pending_push_free()
 * @param count_out   Number of entries returned
 */
int nodus_pending_push_get(nodus_channel_store_t *store,
                            const uint8_t uuid[NODUS_UUID_BYTES],
                            const nodus_key_t *target_fp,
                            int max_count,
                            nodus_pending_push_t **entries_out,
                            size_t *count_out);

/**
 * Delete a pending push entry after successful delivery.
 */
int nodus_pending_push_delete(nodus_channel_store_t *store, int64_t id);

/**
 * Cleanup expired pending push entries.
 * @return Number of entries deleted, or -1 on error
 */
int nodus_pending_push_cleanup(nodus_channel_store_t *store);

/** Free an array of pending push entries. */
void nodus_pending_push_free(nodus_pending_push_t *entries, size_t count);

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
