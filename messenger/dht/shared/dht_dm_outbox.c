/**
 * @file dht_dm_outbox.c
 * @brief Direct Message Outbox Implementation with Daily Buckets
 *
 * Daily bucket messaging for 1-1 direct messages.
 * No watermark pruning - TTL handles cleanup automatically.
 *
 * Part of DNA Messenger
 *
 * @date 2026-01-16
 */

#include "dht_dm_outbox.h"
#include "dht_chunked.h"
#include "dht_offline_queue.h"
#include "../core/dht_listen.h"
#include "../crypto/utils/qgp_sha3.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>

#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_platform.h"
#include "crypto/utils/threadpool.h"

#define LOG_TAG "DHT_DM_OUTBOX"

/*============================================================================
 * Parallel Fetch Worker (for sync_all_contacts)
 *============================================================================*/

typedef struct {
    dht_context_t *ctx;
    const char *my_fp;
    const char *contact_fp;
    bool use_full_sync;              /* true = 8-day full, false = 3-day recent */
    dht_offline_message_t *messages; /* Output: fetched messages (owned by worker) */
    size_t count;                    /* Output: message count */
    int result;                      /* Output: 0 = success */
} dm_fetch_worker_ctx_t;

/* Thread pool task: fetch messages from one contact's outbox */
static void dm_fetch_worker(void *arg) {
    dm_fetch_worker_ctx_t *ctx = (dm_fetch_worker_ctx_t *)arg;
    ctx->messages = NULL;
    ctx->count = 0;
    ctx->result = -1;

    if (!ctx->ctx || !ctx->my_fp || !ctx->contact_fp) {
        return;
    }

    if (ctx->use_full_sync) {
        ctx->result = dht_dm_outbox_sync_full(ctx->ctx, ctx->my_fp, ctx->contact_fp,
                                               &ctx->messages, &ctx->count);
    } else {
        ctx->result = dht_dm_outbox_sync_recent(ctx->ctx, ctx->my_fp, ctx->contact_fp,
                                                 &ctx->messages, &ctx->count);
    }
}

/*============================================================================
 * Local Cache (same pattern as dht_offline_queue.c)
 *============================================================================*/

#define DM_OUTBOX_CACHE_MAX_ENTRIES 64
#define DM_OUTBOX_CACHE_TTL_SECONDS 60

typedef struct {
    char base_key[512];                  /* Bucket key (sender:outbox:recipient:day) */
    dht_offline_message_t *messages;     /* Cached messages (owned) */
    size_t count;                        /* Number of messages */
    time_t last_update;                  /* When cache was last updated */
    bool valid;                          /* True if entry is in use */
    bool needs_dht_sync;                 /* True if failed to publish, needs retry */
} dm_outbox_cache_entry_t;

static dm_outbox_cache_entry_t g_dm_cache[DM_OUTBOX_CACHE_MAX_ENTRIES];
static bool g_dm_cache_initialized = false;
static pthread_mutex_t g_dm_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Cache init - MUST be called while holding g_dm_cache_mutex (v0.6.43 race fix) */
static void dm_cache_init(void) {
    /* Note: Caller must hold g_dm_cache_mutex. All public functions that call
     * dm_cache_find/dm_cache_store lock the mutex first. */
    if (g_dm_cache_initialized) return;
    memset(g_dm_cache, 0, sizeof(g_dm_cache));
    g_dm_cache_initialized = true;
}

/* Find cache entry for key (returns NULL if not found or expired) */
static dm_outbox_cache_entry_t *dm_cache_find(const char *base_key) {
    dm_cache_init();
    time_t now = time(NULL);

    for (int i = 0; i < DM_OUTBOX_CACHE_MAX_ENTRIES; i++) {
        if (g_dm_cache[i].valid &&
            strcmp(g_dm_cache[i].base_key, base_key) == 0) {
            /* Check if expired */
            if (now - g_dm_cache[i].last_update > DM_OUTBOX_CACHE_TTL_SECONDS) {
                /* Expired - invalidate and return NULL */
                if (g_dm_cache[i].messages) {
                    dht_offline_messages_free(g_dm_cache[i].messages, g_dm_cache[i].count);
                }
                g_dm_cache[i].valid = false;
                return NULL;
            }
            return &g_dm_cache[i];
        }
    }
    return NULL;
}

/* Store messages in cache (takes ownership of messages array) */
static void dm_cache_store(const char *base_key, dht_offline_message_t *messages,
                           size_t count, bool needs_sync) {
    dm_cache_init();

    /* Find existing entry or empty slot */
    dm_outbox_cache_entry_t *entry = NULL;
    int oldest_idx = 0;
    time_t oldest_time = time(NULL);

    for (int i = 0; i < DM_OUTBOX_CACHE_MAX_ENTRIES; i++) {
        if (g_dm_cache[i].valid && strcmp(g_dm_cache[i].base_key, base_key) == 0) {
            /* Found existing - free old data */
            if (g_dm_cache[i].messages) {
                dht_offline_messages_free(g_dm_cache[i].messages, g_dm_cache[i].count);
            }
            entry = &g_dm_cache[i];
            break;
        }
        if (!g_dm_cache[i].valid) {
            entry = &g_dm_cache[i];
            break;
        }
        if (g_dm_cache[i].last_update < oldest_time) {
            oldest_time = g_dm_cache[i].last_update;
            oldest_idx = i;
        }
    }

    /* If no slot found, evict oldest */
    if (!entry) {
        entry = &g_dm_cache[oldest_idx];
        if (entry->messages) {
            dht_offline_messages_free(entry->messages, entry->count);
        }
    }

    strncpy(entry->base_key, base_key, sizeof(entry->base_key) - 1);
    entry->base_key[sizeof(entry->base_key) - 1] = '\0';
    entry->messages = messages;
    entry->count = count;
    entry->last_update = time(NULL);
    entry->valid = true;
    entry->needs_dht_sync = needs_sync;
}

/*============================================================================
 * Key Generation
 *============================================================================*/

uint64_t dht_dm_outbox_get_day_bucket(void) {
    return (uint64_t)time(NULL) / DNA_DM_OUTBOX_SECONDS_PER_DAY;
}

int dht_dm_outbox_make_key(
    const char *sender_fp,
    const char *recipient_fp,
    uint64_t day_bucket,
    char *key_out,
    size_t key_out_size
) {
    if (!sender_fp || !recipient_fp || !key_out || key_out_size < 300) {
        return -1;
    }

    /* Use current day if day_bucket is 0 */
    if (day_bucket == 0) {
        day_bucket = dht_dm_outbox_get_day_bucket();
    }

    /* Key format: sender_fp:outbox:recipient_fp:day_bucket */
    int written = snprintf(key_out, key_out_size, "%s:outbox:%s:%lu",
                           sender_fp, recipient_fp, (unsigned long)day_bucket);

    if (written < 0 || (size_t)written >= key_out_size) {
        return -1;
    }

    return 0;
}

/*============================================================================
 * Send API
 *============================================================================*/

int dht_dm_queue_message(
    dht_context_t *ctx,
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint64_t seq_num,
    uint32_t ttl_seconds
) {
    if (!ctx || !sender || !recipient || !ciphertext || ciphertext_len == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid parameters for queue message");
        return -1;
    }

    /* Default TTL */
    if (ttl_seconds == 0) {
        ttl_seconds = DNA_DM_OUTBOX_TTL;
    }

    /* Generate today's bucket key */
    uint64_t today = dht_dm_outbox_get_day_bucket();
    char base_key[512];
    if (dht_dm_outbox_make_key(sender, recipient, today, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate bucket key");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Queueing message to bucket day=%lu, seq=%lu",
                 (unsigned long)today, (unsigned long)seq_num);

    pthread_mutex_lock(&g_dm_cache_mutex);

    /* Try to get existing messages from cache first */
    dht_offline_message_t *existing_messages = NULL;
    size_t existing_count = 0;

    dm_outbox_cache_entry_t *cache_entry = dm_cache_find(base_key);
    if (cache_entry && cache_entry->count > 0) {
        /* Cache hit - copy messages */
        QGP_LOG_DEBUG(LOG_TAG, "Cache hit: %zu existing messages", cache_entry->count);
        existing_count = cache_entry->count;
        existing_messages = (dht_offline_message_t*)calloc(existing_count, sizeof(dht_offline_message_t));
        if (existing_messages) {
            bool alloc_failed = false;
            for (size_t i = 0; i < existing_count && !alloc_failed; i++) {
                existing_messages[i].seq_num = cache_entry->messages[i].seq_num;
                existing_messages[i].timestamp = cache_entry->messages[i].timestamp;
                existing_messages[i].expiry = cache_entry->messages[i].expiry;
                existing_messages[i].sender = strdup(cache_entry->messages[i].sender);
                existing_messages[i].recipient = strdup(cache_entry->messages[i].recipient);
                existing_messages[i].ciphertext_len = cache_entry->messages[i].ciphertext_len;
                existing_messages[i].ciphertext = (uint8_t*)malloc(cache_entry->messages[i].ciphertext_len);

                /* v0.6.40: Check allocations and cleanup on failure */
                if (!existing_messages[i].sender || !existing_messages[i].recipient ||
                    !existing_messages[i].ciphertext) {
                    QGP_LOG_ERROR(LOG_TAG, "Allocation failed in message copy loop");
                    /* Free this partial entry */
                    free(existing_messages[i].sender);
                    free(existing_messages[i].recipient);
                    free(existing_messages[i].ciphertext);
                    /* Free all previously allocated entries */
                    for (size_t j = 0; j < i; j++) {
                        dht_offline_message_free(&existing_messages[j]);
                    }
                    free(existing_messages);
                    existing_messages = NULL;
                    existing_count = 0;
                    alloc_failed = true;
                } else {
                    memcpy(existing_messages[i].ciphertext, cache_entry->messages[i].ciphertext,
                           cache_entry->messages[i].ciphertext_len);
                }
            }
        }
    } else {
        /* Cache miss - fetch from DHT */
        QGP_LOG_DEBUG(LOG_TAG, "Cache miss, fetching from DHT");
        uint8_t *existing_data = NULL;
        size_t existing_len = 0;

        int fetch_result = dht_chunked_fetch(ctx, base_key, &existing_data, &existing_len);
        if (fetch_result == DHT_CHUNK_OK && existing_data && existing_len > 0) {
            dht_deserialize_messages(existing_data, existing_len, &existing_messages, &existing_count);
            free(existing_data);
            QGP_LOG_DEBUG(LOG_TAG, "Fetched %zu existing messages from DHT", existing_count);
        }
    }

    /* DoS prevention: limit messages per bucket */
    if (existing_count >= DNA_DM_OUTBOX_MAX_MESSAGES_PER_BUCKET) {
        QGP_LOG_WARN(LOG_TAG, "Bucket full (%zu messages), dropping oldest", existing_count);
        /* Drop oldest message to make room */
        if (existing_count > 0) {
            dht_offline_message_free(&existing_messages[0]);
            memmove(&existing_messages[0], &existing_messages[1],
                    (existing_count - 1) * sizeof(dht_offline_message_t));
            existing_count--;
        }
    }

    /* Check for duplicate by seq_num - skip if already exists (retry handling) */
    for (size_t i = 0; i < existing_count; i++) {
        if (existing_messages[i].seq_num == seq_num) {
            QGP_LOG_WARN(LOG_TAG, "Message seq=%lu already in bucket, skipping duplicate",
                         (unsigned long)seq_num);
            if (existing_messages) {
                dht_offline_messages_free(existing_messages, existing_count);
            }
            pthread_mutex_unlock(&g_dm_cache_mutex);
            return 0;  /* Success - message already there */
        }
    }

    /* Create new message */
    dht_offline_message_t new_msg = {0};
    new_msg.seq_num = seq_num;
    new_msg.timestamp = (uint64_t)time(NULL);
    new_msg.expiry = new_msg.timestamp + ttl_seconds;
    new_msg.sender = strdup(sender);
    new_msg.recipient = strdup(recipient);
    new_msg.ciphertext = (uint8_t*)malloc(ciphertext_len);
    new_msg.ciphertext_len = ciphertext_len;

    if (!new_msg.sender || !new_msg.recipient || !new_msg.ciphertext) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed");
        dht_offline_message_free(&new_msg);
        if (existing_messages) {
            dht_offline_messages_free(existing_messages, existing_count);
        }
        pthread_mutex_unlock(&g_dm_cache_mutex);
        return -1;
    }
    memcpy(new_msg.ciphertext, ciphertext, ciphertext_len);

    /* Append new message to bucket */
    size_t new_count = existing_count + 1;
    dht_offline_message_t *all_messages = (dht_offline_message_t*)calloc(new_count, sizeof(dht_offline_message_t));
    if (!all_messages) {
        QGP_LOG_ERROR(LOG_TAG, "Memory allocation failed for combined messages");
        dht_offline_message_free(&new_msg);
        if (existing_messages) {
            dht_offline_messages_free(existing_messages, existing_count);
        }
        pthread_mutex_unlock(&g_dm_cache_mutex);
        return -1;
    }

    /* Copy existing messages */
    for (size_t i = 0; i < existing_count; i++) {
        all_messages[i] = existing_messages[i];
    }
    if (existing_messages) {
        free(existing_messages);  /* Don't free contents, they're moved */
    }

    /* Add new message at end */
    all_messages[existing_count] = new_msg;

    /* Serialize */
    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    if (dht_serialize_messages(all_messages, new_count, &serialized, &serialized_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to serialize messages");
        dht_offline_messages_free(all_messages, new_count);
        pthread_mutex_unlock(&g_dm_cache_mutex);
        return -1;
    }

    /* Publish to DHT */
    int put_result = dht_chunked_publish(ctx, base_key, serialized, serialized_len, DHT_CHUNK_TTL_7DAY);
    free(serialized);

    if (put_result != DHT_CHUNK_OK) {
        QGP_LOG_WARN(LOG_TAG, "DHT publish failed, caching for retry");
        dm_cache_store(base_key, all_messages, new_count, true);
        pthread_mutex_unlock(&g_dm_cache_mutex);
        return -1;
    }

    /* Success - update cache */
    QGP_LOG_INFO(LOG_TAG, "Message queued successfully, %zu total in bucket", new_count);
    dm_cache_store(base_key, all_messages, new_count, false);
    pthread_mutex_unlock(&g_dm_cache_mutex);
    return 0;
}

/*============================================================================
 * Receive API
 *============================================================================*/

int dht_dm_outbox_sync_day(
    dht_context_t *ctx,
    const char *my_fp,
    const char *contact_fp,
    uint64_t day_bucket,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!ctx || !my_fp || !contact_fp || !messages_out || !count_out) {
        return -1;
    }

    *messages_out = NULL;
    *count_out = 0;

    /* Use current day if day_bucket is 0 */
    if (day_bucket == 0) {
        day_bucket = dht_dm_outbox_get_day_bucket();
    }

    /* Generate key: contact is sender, I am recipient */
    char base_key[512];
    if (dht_dm_outbox_make_key(contact_fp, my_fp, day_bucket, base_key, sizeof(base_key)) != 0) {
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Syncing day=%lu from %.16s...", (unsigned long)day_bucket, contact_fp);

    /* Fetch from DHT */
    uint8_t *data = NULL;
    size_t data_len = 0;

    int fetch_result = dht_chunked_fetch(ctx, base_key, &data, &data_len);
    if (fetch_result != DHT_CHUNK_OK || !data || data_len == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No messages found for day=%lu", (unsigned long)day_bucket);
        return 0;  /* No messages is not an error */
    }

    /* Deserialize */
    if (dht_deserialize_messages(data, data_len, messages_out, count_out) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize messages");
        free(data);
        return -1;
    }

    free(data);
    QGP_LOG_DEBUG(LOG_TAG, "Synced %zu messages from day=%lu", *count_out, (unsigned long)day_bucket);
    return 0;
}

int dht_dm_outbox_sync_recent(
    dht_context_t *ctx,
    const char *my_fp,
    const char *contact_fp,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!ctx || !my_fp || !contact_fp || !messages_out || !count_out) {
        return -1;
    }

    *messages_out = NULL;
    *count_out = 0;

    uint64_t today = dht_dm_outbox_get_day_bucket();
    uint64_t days[3] = { today - 1, today, today + 1 };

    QGP_LOG_DEBUG(LOG_TAG, "Syncing recent 3 days: %lu, %lu, %lu",
                 (unsigned long)days[0], (unsigned long)days[1], (unsigned long)days[2]);

    /* Collect messages from all 3 days */
    dht_offline_message_t *all_messages = NULL;
    size_t total_count = 0;

    for (int i = 0; i < 3; i++) {
        dht_offline_message_t *day_messages = NULL;
        size_t day_count = 0;

        if (dht_dm_outbox_sync_day(ctx, my_fp, contact_fp, days[i], &day_messages, &day_count) == 0 &&
            day_messages && day_count > 0) {

            /* Append to combined array */
            dht_offline_message_t *combined = (dht_offline_message_t*)realloc(
                all_messages, (total_count + day_count) * sizeof(dht_offline_message_t));

            if (combined) {
                all_messages = combined;
                memcpy(&all_messages[total_count], day_messages, day_count * sizeof(dht_offline_message_t));
                total_count += day_count;
                free(day_messages);  /* Don't free contents, they're moved */
            } else {
                dht_offline_messages_free(day_messages, day_count);
            }
        }
    }

    *messages_out = all_messages;
    *count_out = total_count;

    QGP_LOG_INFO(LOG_TAG, "Recent sync: %zu messages from 3 days", total_count);
    return 0;
}

int dht_dm_outbox_sync_full(
    dht_context_t *ctx,
    const char *my_fp,
    const char *contact_fp,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!ctx || !my_fp || !contact_fp || !messages_out || !count_out) {
        return -1;
    }

    *messages_out = NULL;
    *count_out = 0;

    uint64_t today = dht_dm_outbox_get_day_bucket();

    QGP_LOG_DEBUG(LOG_TAG, "Full sync: days %lu to %lu",
                 (unsigned long)(today - 6), (unsigned long)(today + 1));

    /* Collect messages from all 8 days (today-6 to today+1) */
    dht_offline_message_t *all_messages = NULL;
    size_t total_count = 0;

    for (uint64_t day = today - 6; day <= today + 1; day++) {
        dht_offline_message_t *day_messages = NULL;
        size_t day_count = 0;

        if (dht_dm_outbox_sync_day(ctx, my_fp, contact_fp, day, &day_messages, &day_count) == 0 &&
            day_messages && day_count > 0) {

            /* Append to combined array */
            dht_offline_message_t *combined = (dht_offline_message_t*)realloc(
                all_messages, (total_count + day_count) * sizeof(dht_offline_message_t));

            if (combined) {
                all_messages = combined;
                memcpy(&all_messages[total_count], day_messages, day_count * sizeof(dht_offline_message_t));
                total_count += day_count;
                free(day_messages);
            } else {
                dht_offline_messages_free(day_messages, day_count);
            }
        }
    }

    *messages_out = all_messages;
    *count_out = total_count;

    QGP_LOG_INFO(LOG_TAG, "Full sync: %zu messages from 8 days", total_count);
    return 0;
}

int dht_dm_outbox_sync_all_contacts_recent(
    dht_context_t *ctx,
    const char *my_fp,
    const char **contact_list,
    size_t contact_count,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!ctx || !my_fp || !contact_list || !messages_out || !count_out) {
        return -1;
    }

    *messages_out = NULL;
    *count_out = 0;

    if (contact_count == 0) {
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Syncing recent messages from %zu contacts via thread pool", contact_count);

    /* Allocate worker contexts */
    dm_fetch_worker_ctx_t *workers = calloc(contact_count, sizeof(dm_fetch_worker_ctx_t));
    void **args = calloc(contact_count, sizeof(void *));
    if (!workers || !args) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate parallel fetch memory");
        free(workers);
        free(args);
        return -1;
    }

    /* Initialize worker contexts */
    for (size_t i = 0; i < contact_count; i++) {
        workers[i].ctx = ctx;
        workers[i].my_fp = my_fp;
        workers[i].contact_fp = contact_list[i];
        workers[i].use_full_sync = false;  /* Recent sync */
        workers[i].messages = NULL;
        workers[i].count = 0;
        workers[i].result = -1;
        args[i] = &workers[i];
    }

    /* Execute all fetches in parallel via thread pool */
    threadpool_map(dm_fetch_worker, args, contact_count, 0);

    free(args);

    /* Collect results from all workers */
    dht_offline_message_t *all_messages = NULL;
    size_t total_count = 0;

    for (size_t i = 0; i < contact_count; i++) {
        if (workers[i].result == 0 && workers[i].messages && workers[i].count > 0) {
            /* Append to combined array */
            dht_offline_message_t *combined = (dht_offline_message_t*)realloc(
                all_messages, (total_count + workers[i].count) * sizeof(dht_offline_message_t));

            if (combined) {
                all_messages = combined;
                memcpy(&all_messages[total_count], workers[i].messages,
                       workers[i].count * sizeof(dht_offline_message_t));
                total_count += workers[i].count;
                free(workers[i].messages);  /* Free array, contents moved */
            } else {
                dht_offline_messages_free(workers[i].messages, workers[i].count);
            }
        } else if (workers[i].messages) {
            /* Fetch failed or returned 0 messages - free if allocated */
            dht_offline_messages_free(workers[i].messages, workers[i].count);
        }
    }

    free(workers);

    *messages_out = all_messages;
    *count_out = total_count;

    QGP_LOG_INFO(LOG_TAG, "Thread pool sync complete: %zu messages from %zu contacts", total_count, contact_count);
    return 0;
}

int dht_dm_outbox_sync_all_contacts_full(
    dht_context_t *ctx,
    const char *my_fp,
    const char **contact_list,
    size_t contact_count,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!ctx || !my_fp || !contact_list || !messages_out || !count_out) {
        return -1;
    }

    *messages_out = NULL;
    *count_out = 0;

    if (contact_count == 0) {
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Full sync (8 days) from %zu contacts via thread pool", contact_count);

    /* Allocate worker contexts */
    dm_fetch_worker_ctx_t *workers = calloc(contact_count, sizeof(dm_fetch_worker_ctx_t));
    void **args = calloc(contact_count, sizeof(void *));
    if (!workers || !args) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate parallel fetch memory");
        free(workers);
        free(args);
        return -1;
    }

    /* Initialize worker contexts */
    for (size_t i = 0; i < contact_count; i++) {
        workers[i].ctx = ctx;
        workers[i].my_fp = my_fp;
        workers[i].contact_fp = contact_list[i];
        workers[i].use_full_sync = true;  /* Full 8-day sync */
        workers[i].messages = NULL;
        workers[i].count = 0;
        workers[i].result = -1;
        args[i] = &workers[i];
    }

    /* Execute all fetches in parallel via thread pool */
    threadpool_map(dm_fetch_worker, args, contact_count, 0);

    free(args);

    /* Collect results from all workers */
    dht_offline_message_t *all_messages = NULL;
    size_t total_count = 0;

    for (size_t i = 0; i < contact_count; i++) {
        if (workers[i].result == 0 && workers[i].messages && workers[i].count > 0) {
            /* Append to combined array */
            dht_offline_message_t *combined = (dht_offline_message_t*)realloc(
                all_messages, (total_count + workers[i].count) * sizeof(dht_offline_message_t));

            if (combined) {
                all_messages = combined;
                memcpy(&all_messages[total_count], workers[i].messages,
                       workers[i].count * sizeof(dht_offline_message_t));
                total_count += workers[i].count;
                free(workers[i].messages);  /* Free array, contents moved */
            } else {
                dht_offline_messages_free(workers[i].messages, workers[i].count);
            }
        } else if (workers[i].messages) {
            /* Fetch failed or returned 0 messages - free if allocated */
            dht_offline_messages_free(workers[i].messages, workers[i].count);
        }
    }

    free(workers);

    *messages_out = all_messages;
    *count_out = total_count;

    QGP_LOG_INFO(LOG_TAG, "Thread pool full sync complete: %zu messages from %zu contacts", total_count, contact_count);
    return 0;
}

/*============================================================================
 * Listen API
 *============================================================================*/

/* Cleanup callback for listen context */
static void dm_listen_cleanup(void *user_data) {
    /* Note: We don't free the listen_ctx here because the caller owns it.
     * The listen_ctx is freed in dht_dm_outbox_unsubscribe(). */
    (void)user_data;
}

/* Internal: subscribe to a specific day's bucket */
static int dm_subscribe_to_day(dht_dm_listen_ctx_t *listen_ctx) {
    if (!listen_ctx || !listen_ctx->dht_ctx) {
        return -1;
    }

    /* Generate key for today's bucket: contact (sender) -> me (recipient) */
    char base_key[512];
    if (dht_dm_outbox_make_key(listen_ctx->contact_fp, listen_ctx->my_fp,
                               listen_ctx->current_day, base_key, sizeof(base_key)) != 0) {
        return -1;
    }

    /* Derive chunk[0] key for listen */
    uint8_t chunk0_key[DHT_CHUNK_KEY_SIZE];
    dht_chunked_make_key(base_key, 0, chunk0_key);

    QGP_LOG_DEBUG(LOG_TAG, "Subscribing to day=%lu for contact %.16s...",
                 (unsigned long)listen_ctx->current_day, listen_ctx->contact_fp);

    /* Start listening */
    size_t token = dht_listen_ex(listen_ctx->dht_ctx,
                                  chunk0_key, DHT_CHUNK_KEY_SIZE,
                                  listen_ctx->callback,
                                  listen_ctx->user_data,
                                  dm_listen_cleanup);

    if (token == 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to start DHT listener");
        return -1;
    }

    listen_ctx->listen_token = token;
    QGP_LOG_INFO(LOG_TAG, "Subscribed to day=%lu, token=%zu",
                (unsigned long)listen_ctx->current_day, token);
    return 0;
}

int dht_dm_outbox_subscribe(
    dht_context_t *ctx,
    const char *my_fp,
    const char *contact_fp,
    dht_listen_callback_t callback,
    void *user_data,
    dht_dm_listen_ctx_t **listen_ctx_out
) {
    if (!ctx || !my_fp || !contact_fp || !callback || !listen_ctx_out) {
        return -1;
    }

    /* Allocate listen context */
    dht_dm_listen_ctx_t *listen_ctx = (dht_dm_listen_ctx_t*)calloc(1, sizeof(dht_dm_listen_ctx_t));
    if (!listen_ctx) {
        return -1;
    }

    strncpy(listen_ctx->my_fp, my_fp, sizeof(listen_ctx->my_fp) - 1);
    strncpy(listen_ctx->contact_fp, contact_fp, sizeof(listen_ctx->contact_fp) - 1);
    listen_ctx->current_day = dht_dm_outbox_get_day_bucket();
    listen_ctx->callback = callback;
    listen_ctx->user_data = user_data;
    listen_ctx->dht_ctx = ctx;
    listen_ctx->listen_token = 0;

    /* Subscribe to today's bucket */
    if (dm_subscribe_to_day(listen_ctx) != 0) {
        free(listen_ctx);
        return -1;
    }

    *listen_ctx_out = listen_ctx;
    return 0;
}

void dht_dm_outbox_unsubscribe(
    dht_context_t *ctx,
    dht_dm_listen_ctx_t *listen_ctx
) {
    if (!listen_ctx) {
        return;
    }

    /* Cancel DHT listener if active */
    if (listen_ctx->listen_token != 0 && ctx) {
        dht_cancel_listen(ctx, listen_ctx->listen_token);
        QGP_LOG_DEBUG(LOG_TAG, "Unsubscribed token=%zu for %.16s...",
                     listen_ctx->listen_token, listen_ctx->contact_fp);
    }

    free(listen_ctx);
}

int dht_dm_outbox_check_day_rotation(
    dht_context_t *ctx,
    dht_dm_listen_ctx_t *listen_ctx
) {
    if (!ctx || !listen_ctx) {
        return -1;
    }

    uint64_t new_day = dht_dm_outbox_get_day_bucket();

    /* No change */
    if (new_day == listen_ctx->current_day) {
        return 0;
    }

    QGP_LOG_INFO(LOG_TAG, "Day rotation: %lu -> %lu for %.16s...",
                (unsigned long)listen_ctx->current_day, (unsigned long)new_day,
                listen_ctx->contact_fp);

    /* Cancel old listener */
    if (listen_ctx->listen_token != 0) {
        dht_cancel_listen(ctx, listen_ctx->listen_token);
        listen_ctx->listen_token = 0;
    }

    /* Update day */
    uint64_t old_day = listen_ctx->current_day;
    listen_ctx->current_day = new_day;

    /* Subscribe to new day */
    if (dm_subscribe_to_day(listen_ctx) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to subscribe to new day");
        return -1;
    }

    /* Sync yesterday to catch any last messages (fire-and-forget style) */
    QGP_LOG_DEBUG(LOG_TAG, "Syncing previous day %lu after rotation", (unsigned long)old_day);

    return 1;  /* Rotated */
}

/*============================================================================
 * Cache Management
 *============================================================================*/

void dht_dm_outbox_cache_clear(void) {
    pthread_mutex_lock(&g_dm_cache_mutex);

    for (int i = 0; i < DM_OUTBOX_CACHE_MAX_ENTRIES; i++) {
        if (g_dm_cache[i].valid && g_dm_cache[i].messages) {
            dht_offline_messages_free(g_dm_cache[i].messages, g_dm_cache[i].count);
        }
        g_dm_cache[i].valid = false;
    }

    pthread_mutex_unlock(&g_dm_cache_mutex);
    QGP_LOG_INFO(LOG_TAG, "Cache cleared");
}

int dht_dm_outbox_cache_sync_pending(dht_context_t *ctx) {
    if (!ctx) {
        return 0;
    }

    int synced = 0;

    pthread_mutex_lock(&g_dm_cache_mutex);

    for (int i = 0; i < DM_OUTBOX_CACHE_MAX_ENTRIES; i++) {
        if (g_dm_cache[i].valid && g_dm_cache[i].needs_dht_sync &&
            g_dm_cache[i].messages && g_dm_cache[i].count > 0) {

            QGP_LOG_INFO(LOG_TAG, "Syncing pending cache entry: %s", g_dm_cache[i].base_key);

            /* Serialize */
            uint8_t *serialized = NULL;
            size_t serialized_len = 0;
            if (dht_serialize_messages(g_dm_cache[i].messages, g_dm_cache[i].count,
                                        &serialized, &serialized_len) == 0) {
                /* Try to publish */
                if (dht_chunked_publish(ctx, g_dm_cache[i].base_key,
                                        serialized, serialized_len, DHT_CHUNK_TTL_7DAY) == DHT_CHUNK_OK) {
                    g_dm_cache[i].needs_dht_sync = false;
                    synced++;
                }
                free(serialized);
            }
        }
    }

    pthread_mutex_unlock(&g_dm_cache_mutex);

    QGP_LOG_INFO(LOG_TAG, "Synced %d pending cache entries", synced);
    return synced;
}
