/**
 * @file dht_dm_outbox.c
 * @brief Direct Message Outbox Implementation with Daily Buckets
 *
 * Daily bucket messaging for 1-1 direct messages.
 * No watermark pruning - TTL handles cleanup automatically.
 *
 * Part of DNA Connect
 *
 * @date 2026-01-16
 */

#include "dht_dm_outbox.h"
#include "dht_offline_queue.h"
#include "nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
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
 * Blob Hash Cache — skip re-processing unchanged DHT blobs
 *
 * Tracks SHA3-256 hash of the last processed blob per DHT key.
 * If the same blob is fetched again (same hash), all messages in it
 * have already been delivered — skip deserialize + decrypt entirely.
 *============================================================================*/

#define BLOB_CACHE_MAX 128  /* max tracked DHT keys (3 contacts × 8 days × 2 syncs = 48) */

typedef struct {
    char dht_key[512];
    uint8_t blob_hash[32];  /* SHA3-256 of raw DHT value */
} blob_cache_entry_t;

static blob_cache_entry_t g_blob_cache[BLOB_CACHE_MAX];
static int g_blob_cache_count = 0;
static pthread_mutex_t g_blob_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Check if blob was already processed (returns true if duplicate) */
static bool blob_cache_check_and_update(const char *dht_key, const uint8_t *data, size_t data_len) {
    uint8_t hash[64];  /* SHA3-512 output, we use first 32 bytes */
    qgp_sha3_512(data, data_len, hash);

    pthread_mutex_lock(&g_blob_cache_mutex);

    /* Look for existing entry */
    for (int i = 0; i < g_blob_cache_count; i++) {
        if (strcmp(g_blob_cache[i].dht_key, dht_key) == 0) {
            if (memcmp(g_blob_cache[i].blob_hash, hash, 32) == 0) {
                /* Same blob — already processed */
                pthread_mutex_unlock(&g_blob_cache_mutex);
                return true;
            }
            /* Updated blob — store new hash */
            memcpy(g_blob_cache[i].blob_hash, hash, 32);
            pthread_mutex_unlock(&g_blob_cache_mutex);
            return false;
        }
    }

    /* New entry */
    if (g_blob_cache_count < BLOB_CACHE_MAX) {
        strncpy(g_blob_cache[g_blob_cache_count].dht_key, dht_key,
                sizeof(g_blob_cache[0].dht_key) - 1);
        memcpy(g_blob_cache[g_blob_cache_count].blob_hash, hash, 32);
        g_blob_cache_count++;
    }

    pthread_mutex_unlock(&g_blob_cache_mutex);
    return false;
}

/*============================================================================
 * Parallel Fetch Worker (for sync_all_contacts)
 *============================================================================*/

typedef struct {
    const char *my_fp;
    const char *contact_fp;
    const uint8_t *salt;             /* Per-contact DHT salt (NULL = legacy) */
    bool use_full_sync;              /* true = 8-day full, false = 3-day recent */
    dht_offline_message_t *messages; /* Output: fetched messages (owned by worker) */
    size_t count;                    /* Output: message count */
    int result;                      /* Output: 0 = success */
} dm_fetch_worker_ctx_t;

/* Thread pool task: fetch messages from one contact's outbox */
static void dm_fetch_worker(void *arg) {
    dm_fetch_worker_ctx_t *wctx = (dm_fetch_worker_ctx_t *)arg;
    wctx->messages = NULL;
    wctx->count = 0;
    wctx->result = -1;

    if (!wctx->my_fp || !wctx->contact_fp) {
        return;
    }

    if (wctx->use_full_sync) {
        wctx->result = dht_dm_outbox_sync_full(wctx->my_fp, wctx->contact_fp,
                                                wctx->salt,
                                                &wctx->messages, &wctx->count);
    } else {
        wctx->result = dht_dm_outbox_sync_recent(wctx->my_fp, wctx->contact_fp,
                                                   wctx->salt,
                                                   &wctx->messages, &wctx->count);
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

void dht_dm_outbox_compute_salt(const char *fp_a, const char *fp_b, uint8_t salt_out[32]) {
    if (!fp_a || !fp_b || !salt_out) {
        memset(salt_out, 0, 32);
        return;
    }

    /* Deterministic ordering: lexicographic compare ensures both sides
     * produce the same salt regardless of who is sender/receiver */
    const char *first = (strcmp(fp_a, fp_b) < 0) ? fp_a : fp_b;
    const char *second = (first == fp_a) ? fp_b : fp_a;

    /* salt = SHA3-256(min(fpA, fpB) || max(fpA, fpB)) */
    size_t len_a = strlen(first);
    size_t len_b = strlen(second);
    uint8_t *input = (uint8_t *)malloc(len_a + len_b);
    if (!input) {
        memset(salt_out, 0, 32);
        return;
    }

    memcpy(input, first, len_a);
    memcpy(input + len_a, second, len_b);
    qgp_sha3_256(input, len_a + len_b, salt_out);
    free(input);
}

uint64_t dht_dm_outbox_get_day_bucket(void) {
    return (uint64_t)time(NULL) / DNA_DM_OUTBOX_SECONDS_PER_DAY;
}

int dht_dm_outbox_make_key(
    const char *sender_fp,
    const char *recipient_fp,
    uint64_t day_bucket,
    const uint8_t *salt,
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

    if (salt) {
        /* Salted key format: sender_fp:outbox:recipient_fp:day_bucket:SALT_HEX */
        char salt_hex[65];
        for (int i = 0; i < 32; i++) {
            snprintf(salt_hex + (i * 2), 3, "%02x", salt[i]);
        }
        salt_hex[64] = '\0';

        int written = snprintf(key_out, key_out_size, "%s:outbox:%s:%lu:%s",
                               sender_fp, recipient_fp, (unsigned long)day_bucket, salt_hex);
        if (written < 0 || (size_t)written >= key_out_size) {
            return -1;
        }
    } else {
        /* Legacy unsalted key format: sender_fp:outbox:recipient_fp:day_bucket */
        int written = snprintf(key_out, key_out_size, "%s:outbox:%s:%lu",
                               sender_fp, recipient_fp, (unsigned long)day_bucket);
        if (written < 0 || (size_t)written >= key_out_size) {
            return -1;
        }
    }

    return 0;
}

/*============================================================================
 * Send API
 *============================================================================*/

int dht_dm_queue_message(
    const char *sender,
    const char *recipient,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint64_t seq_num,
    uint32_t ttl_seconds,
    const uint8_t *salt
) {
    if (!sender || !recipient || !ciphertext || ciphertext_len == 0) {
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
    if (dht_dm_outbox_make_key(sender, recipient, today, salt, base_key, sizeof(base_key)) != 0) {
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
        /* Cache miss — do NOT fetch from DHT (eliminates read-modify-write race).
         * messenger_flush_recipient_outbox() rebuilds the complete blob from
         * messages.db after each send, so the per-message PUT here only needs
         * to include the new message. The flush overwrites it immediately. */
        QGP_LOG_DEBUG(LOG_TAG, "Cache miss, skipping DHT GET (flush will rebuild)");
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

    /* Publish to nodus */
    int put_result = nodus_ops_put_str(base_key, serialized, serialized_len,
                                        DNA_DM_OUTBOX_TTL, nodus_ops_value_id());
    free(serialized);

    if (put_result != 0) {
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
    const char *my_fp,
    const char *contact_fp,
    uint64_t day_bucket,
    const uint8_t *salt,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!my_fp || !contact_fp || !messages_out || !count_out) {
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
    if (dht_dm_outbox_make_key(contact_fp, my_fp, day_bucket, salt, base_key, sizeof(base_key)) != 0) {
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Syncing day=%lu from %.16s...", (unsigned long)day_bucket, contact_fp);

    /* Fetch from DHT */
    uint8_t *data = NULL;
    size_t data_len = 0;

    int fetch_result = nodus_ops_get_str(base_key, &data, &data_len);
    if (fetch_result != 0 || !data || data_len == 0) {
        QGP_LOG_DEBUG(LOG_TAG, "No messages found for day=%lu", (unsigned long)day_bucket);
        return 0;  /* No messages is not an error */
    }

    /* Blob-level dedup: skip if we already processed this exact blob */
    if (blob_cache_check_and_update(base_key, data, data_len)) {
        QGP_LOG_DEBUG(LOG_TAG, "Blob unchanged for day=%lu from %.16s... (skipping)",
                     (unsigned long)day_bucket, contact_fp);
        free(data);
        return 0;
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
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *salt,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!my_fp || !contact_fp || !messages_out || !count_out) {
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

        if (dht_dm_outbox_sync_day(my_fp, contact_fp, days[i], salt, &day_messages, &day_count) == 0 &&
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
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *salt,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!my_fp || !contact_fp || !messages_out || !count_out) {
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

        if (dht_dm_outbox_sync_day(my_fp, contact_fp, day, salt, &day_messages, &day_count) == 0 &&
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
    const char *my_fp,
    const char **contact_list,
    size_t contact_count,
    const uint8_t **salt_list,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!my_fp || !contact_list || !messages_out || !count_out) {
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
        workers[i].my_fp = my_fp;
        workers[i].contact_fp = contact_list[i];
        workers[i].salt = salt_list ? salt_list[i] : NULL;
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
    const char *my_fp,
    const char **contact_list,
    size_t contact_count,
    const uint8_t **salt_list,
    dht_offline_message_t **messages_out,
    size_t *count_out
) {
    if (!my_fp || !contact_list || !messages_out || !count_out) {
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
        workers[i].my_fp = my_fp;
        workers[i].contact_fp = contact_list[i];
        workers[i].salt = salt_list ? salt_list[i] : NULL;
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

/* Cleanup callback for listen context
 * v0.6.48: Actually free user_data to fix use-after-free race condition.
 * Previously this was a no-op and engine code freed user_data BEFORE cancelling,
 * causing crash when callback fired between free() and cancel().
 * Now dht_cancel_listen() calls this AFTER marking listener inactive,
 * ensuring no in-flight callback can access freed memory. */
static void dm_listen_cleanup(void *user_data) {
    if (user_data) {
        free(user_data);
    }
}

/* Internal: subscribe to a specific day's bucket */
static int dm_subscribe_to_day(dht_dm_listen_ctx_t *listen_ctx) {
    if (!listen_ctx) {
        return -1;
    }

    /* Generate key for today's bucket: contact (sender) -> me (recipient) */
    char base_key[512];
    if (dht_dm_outbox_make_key(listen_ctx->contact_fp, listen_ctx->my_fp,
                               listen_ctx->current_day,
                               listen_ctx->has_salt ? listen_ctx->salt : NULL,
                               base_key, sizeof(base_key)) != 0) {
        return -1;
    }

    QGP_LOG_DEBUG(LOG_TAG, "Subscribing to day=%lu for contact %.16s...",
                 (unsigned long)listen_ctx->current_day, listen_ctx->contact_fp);

    /* Start listening on base key string */
    size_t token = nodus_ops_listen((const uint8_t *)base_key, strlen(base_key),
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
    const char *my_fp,
    const char *contact_fp,
    const uint8_t *salt,
    nodus_ops_listen_cb_t callback,
    void *user_data,
    dht_dm_listen_ctx_t **listen_ctx_out
) {
    if (!my_fp || !contact_fp || !callback || !listen_ctx_out) {
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
    listen_ctx->listen_token = 0;
    if (salt) {
        memcpy(listen_ctx->salt, salt, 32);
        listen_ctx->has_salt = true;
    } else {
        memset(listen_ctx->salt, 0, 32);
        listen_ctx->has_salt = false;
    }

    /* Subscribe to today's bucket */
    if (dm_subscribe_to_day(listen_ctx) != 0) {
        free(listen_ctx);
        return -1;
    }

    *listen_ctx_out = listen_ctx;
    return 0;
}

void dht_dm_outbox_unsubscribe(
    dht_dm_listen_ctx_t *listen_ctx
) {
    if (!listen_ctx) {
        return;
    }

    /* Cancel DHT listener if active */
    if (listen_ctx->listen_token != 0) {
        nodus_ops_cancel_listen(listen_ctx->listen_token);
        QGP_LOG_DEBUG(LOG_TAG, "Unsubscribed token=%zu for %.16s...",
                     listen_ctx->listen_token, listen_ctx->contact_fp);
    }

    free(listen_ctx);
}

int dht_dm_outbox_check_day_rotation(
    dht_dm_listen_ctx_t *listen_ctx
) {
    if (!listen_ctx) {
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
        nodus_ops_cancel_listen(listen_ctx->listen_token);
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

int dht_dm_outbox_cache_sync_pending(void) {
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
                if (nodus_ops_put_str(g_dm_cache[i].base_key,
                                      serialized, serialized_len,
                                      DNA_DM_OUTBOX_TTL, nodus_ops_value_id()) == 0) {
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
