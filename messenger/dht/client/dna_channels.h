/*
 * DNA Channels - DHT Channel Operations Layer
 *
 * Implements channel metadata CRUD, post operations, and public index browsing.
 *
 * Storage Model:
 * - Channel metadata: SHA256("dna:channels:meta:" + uuid) -> chunked JSON (single-owner)
 * - Channel posts: "dna:channels:posts:" + uuid + ":" + YYYYMMDD -> chunked JSON (multi-owner, daily buckets)
 * - Public index: "dna:channels:idx:" + YYYYMMDD -> multi-owner day buckets
 *
 * Patterns:
 * - Metadata uses dht_chunked_publish/fetch (single-owner, only creator can update)
 * - Posts use dht_chunked_fetch_mine/publish + dht_chunked_fetch_all (multi-owner)
 * - Index uses multi-owner day-bucket pattern (same as dna_feed_index.c)
 *
 * Part of DNA Connect
 */

#ifndef DNA_CHANNELS_H
#define DNA_CHANNELS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define DNA_CHANNEL_NAME_MAX    100
#define DNA_CHANNEL_DESC_MAX    500
#define DNA_CHANNEL_POST_MAX    4000
#define DNA_CHANNEL_TTL_SECONDS (30 * 24 * 60 * 60)

/* DHT key namespace */
#define DNA_CHANNEL_NS_META   "dna:channels:meta:"
#define DNA_CHANNEL_NS_POSTS  "dna:channels:posts:"
#define DNA_CHANNEL_NS_INDEX  "dna:channels:idx:"

/* Index limits */
#define DNA_CHANNEL_INDEX_DAYS_DEFAULT 7
#define DNA_CHANNEL_INDEX_DAYS_MAX     30

/* Post fetch limits */
#define DNA_CHANNEL_POSTS_DAYS_DEFAULT 3
#define DNA_CHANNEL_POSTS_DAYS_MAX     30

/* UUID and fingerprint lengths */
#define DNA_CHANNEL_UUID_LEN        37   /* UUID v4 + null */
#define DNA_CHANNEL_FINGERPRINT_LEN 129  /* SHA3-512 hex + null */

/* Internal channel structure (DHT layer) */
typedef struct {
    char uuid[37];
    char name[DNA_CHANNEL_NAME_MAX + 1];
    char *description;          /* heap-allocated, caller frees */
    char creator_fingerprint[129];
    uint64_t created_at;
    bool is_public;
    bool deleted;
    uint64_t deleted_at;
    uint8_t *signature;
    size_t signature_len;
} dna_channel_t;

/* Internal post structure (DHT layer) */
typedef struct {
    char post_uuid[37];
    char channel_uuid[37];
    char author_fingerprint[129];
    char *body;                 /* heap-allocated, caller frees */
    uint64_t created_at;
    uint8_t *signature;
    size_t signature_len;
} dna_channel_post_internal_t;

/* Channel index entry (lightweight, for browse results) */
typedef struct {
    char channel_uuid[37];
    char name[DNA_CHANNEL_NAME_MAX + 1];
    char description_preview[128];  /* First 127 chars of description */
    char creator_fingerprint[129];
    uint64_t created_at;
    bool deleted;
} dna_channel_index_entry_t;

/* Channel CRUD */
int dna_channel_create(const char *name,
    const char *description, bool is_public,
    const char *creator_fingerprint, const uint8_t *private_key,
    char *uuid_out);

int dna_channel_get(const char *uuid,
    dna_channel_t **channel_out);

/** Parse raw DHT JSON into channel struct (used by batch handler) */
int channel_from_json(const char *json_str, dna_channel_t **channel_out);

int dna_channel_delete(const char *uuid,
    const char *creator_fingerprint, const uint8_t *private_key);

void dna_channel_free(dna_channel_t *channel);
void dna_channels_free(dna_channel_t *channels, size_t count);

/* Posts */
int dna_channel_post_create(const char *channel_uuid,
    const char *body, const char *author_fingerprint,
    const uint8_t *private_key, char *post_uuid_out);

int dna_channel_posts_get(const char *channel_uuid,
    int days_back,
    dna_channel_post_internal_t **posts_out, size_t *count_out);

void dna_channel_post_free(dna_channel_post_internal_t *post);
void dna_channel_posts_free(dna_channel_post_internal_t *posts, size_t count);

/* Public index */
int dna_channel_index_register(const char *channel_uuid,
    const char *name, const char *description,
    const char *creator_fingerprint, const uint8_t *private_key);

int dna_channel_index_browse(int days_back,
    dna_channel_t **channels_out, size_t *count_out);

/* Date helpers */
void channel_get_today_date(char *date_out);
void channel_get_date_offset(int days_ago, char *date_out);

/* DHT key derivation */
int dna_channel_make_meta_key(const char *uuid, uint8_t *key_out, size_t *key_len_out);
int dna_channel_make_posts_key(const char *uuid, const char *date,
                                uint8_t *key_out, size_t *key_len_out);
int dna_channel_make_index_key(const char *date_str, uint8_t *key_out, size_t *key_len_out);

#ifdef __cplusplus
}
#endif
#endif /* DNA_CHANNELS_H */
