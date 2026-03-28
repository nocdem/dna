/**
 * Nodus — Media Storage (SQLite)
 *
 * Chunked media storage for photos/videos/audio up to 64MB.
 * Content-addressed by SHA3-512 hash, stored in 4MB chunks.
 *
 * @file nodus_media_storage.h
 */

#ifndef NODUS_MEDIA_STORAGE_H
#define NODUS_MEDIA_STORAGE_H

#include "nodus/nodus_types.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NODUS_MEDIA_MAX_TOTAL_SIZE    (64ULL * 1024 * 1024)  /* 64 MB */
#define NODUS_MEDIA_MAX_CHUNK_SIZE    NODUS_MAX_VALUE_SIZE    /* 4 MB */
#define NODUS_MEDIA_MAX_CHUNKS        16
#define NODUS_MEDIA_MAX_PER_USER      1000
#define NODUS_MEDIA_MAX_CONCURRENT    3
#define NODUS_MEDIA_INCOMPLETE_TIMEOUT 300  /* 5 minutes */

typedef enum {
    NODUS_MEDIA_IMAGE = 0,
    NODUS_MEDIA_VIDEO = 1,
    NODUS_MEDIA_AUDIO = 2
} nodus_media_type_t;

typedef struct {
    uint8_t     content_hash[64];    /* SHA3-512 */
    char        owner_fp[129];       /* hex fingerprint */
    uint8_t     media_type;          /* nodus_media_type_t */
    uint64_t    total_size;
    uint32_t    chunk_count;
    bool        encrypted;
    uint32_t    ttl;
    uint64_t    created_at;
    uint64_t    expires_at;
    bool        complete;
} nodus_media_meta_t;

typedef struct {
    sqlite3 *db;
    sqlite3_stmt *stmt_put_meta;
    sqlite3_stmt *stmt_put_chunk;
    sqlite3_stmt *stmt_get_meta;
    sqlite3_stmt *stmt_get_chunk;
    sqlite3_stmt *stmt_exists;
    sqlite3_stmt *stmt_mark_complete;
    sqlite3_stmt *stmt_count_chunks;
    sqlite3_stmt *stmt_cleanup_expired;
    sqlite3_stmt *stmt_cleanup_incomplete;
    sqlite3_stmt *stmt_cleanup_orphan_chunks;
    sqlite3_stmt *stmt_count_per_owner;
} nodus_media_storage_t;

int  nodus_media_storage_open(sqlite3 *db, nodus_media_storage_t *ms);
void nodus_media_storage_close(nodus_media_storage_t *ms);

int  nodus_media_put_meta(nodus_media_storage_t *ms, const nodus_media_meta_t *meta);
int  nodus_media_put_chunk(nodus_media_storage_t *ms,
                           const uint8_t content_hash[64],
                           uint32_t chunk_index,
                           const uint8_t *data, size_t data_len);

int  nodus_media_get_meta(nodus_media_storage_t *ms,
                          const uint8_t content_hash[64],
                          nodus_media_meta_t *meta_out);

int  nodus_media_get_chunk(nodus_media_storage_t *ms,
                           const uint8_t content_hash[64],
                           uint32_t chunk_index,
                           uint8_t **data_out, size_t *data_len_out);

int  nodus_media_exists(nodus_media_storage_t *ms,
                        const uint8_t content_hash[64],
                        bool *exists_out, bool *complete_out);

int  nodus_media_mark_complete(nodus_media_storage_t *ms,
                               const uint8_t content_hash[64]);

int  nodus_media_count_chunks(nodus_media_storage_t *ms,
                              const uint8_t content_hash[64]);

int  nodus_media_cleanup(nodus_media_storage_t *ms);

int  nodus_media_count_per_owner(nodus_media_storage_t *ms,
                                 const char *owner_fp);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_MEDIA_STORAGE_H */
