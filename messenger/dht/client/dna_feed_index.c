/*
 * DNA Feeds v2 - Index Operations
 *
 * Implements day-bucket indexing for topic discovery.
 *
 * Storage Model:
 * - Category Index: SHA256("dna:feeds:idx:cat:" + cat_id + ":" + YYYYMMDD) -> multi-owner
 * - Global Index: SHA256("dna:feeds:idx:all:" + YYYYMMDD) -> multi-owner
 *
 * Each user's entries are stored under their unique value_id, enabling
 * multiple users to contribute to the same index bucket.
 */

#include "dna_feed.h"
#include "../shared/dht_chunked.h"
#include "../core/dht_context.h"
#include "crypto/utils/qgp_sha3.h"
#include "crypto/utils/qgp_log.h"
#include "crypto/utils/qgp_types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <json-c/json.h>
#include <openssl/evp.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#define LOG_TAG "DNA_INDEX"

/* ============================================================================
 * JSON Serialization for Index Entries
 * ========================================================================== */

static int index_entry_to_json(const dna_feed_index_entry_t *entry, char **json_out) {
    json_object *root = json_object_new_object();
    if (!root) return -1;

    json_object_object_add(root, "topic_uuid", json_object_new_string(entry->topic_uuid));
    json_object_object_add(root, "author", json_object_new_string(entry->author_fingerprint));
    json_object_object_add(root, "title", json_object_new_string(entry->title));
    json_object_object_add(root, "category_id", json_object_new_string(entry->category_id));
    json_object_object_add(root, "created_at", json_object_new_int64(entry->created_at));
    json_object_object_add(root, "deleted", json_object_new_boolean(entry->deleted));

    const char *json_str = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);
    *json_out = json_str ? strdup(json_str) : NULL;
    json_object_put(root);

    return *json_out ? 0 : -1;
}

static int index_entry_from_json(const char *json_str, dna_feed_index_entry_t *entry_out) {
    json_object *root = json_tokener_parse(json_str);
    if (!root) return -1;

    memset(entry_out, 0, sizeof(dna_feed_index_entry_t));

    json_object *j_val;
    if (json_object_object_get_ex(root, "topic_uuid", &j_val))
        strncpy(entry_out->topic_uuid, json_object_get_string(j_val), DNA_FEED_UUID_LEN - 1);
    if (json_object_object_get_ex(root, "author", &j_val))
        strncpy(entry_out->author_fingerprint, json_object_get_string(j_val), DNA_FEED_FINGERPRINT_LEN - 1);
    if (json_object_object_get_ex(root, "title", &j_val))
        strncpy(entry_out->title, json_object_get_string(j_val), DNA_FEED_MAX_TITLE_LEN);
    if (json_object_object_get_ex(root, "category_id", &j_val))
        strncpy(entry_out->category_id, json_object_get_string(j_val), DNA_FEED_CATEGORY_ID_LEN - 1);
    if (json_object_object_get_ex(root, "created_at", &j_val))
        entry_out->created_at = json_object_get_int64(j_val);
    if (json_object_object_get_ex(root, "deleted", &j_val))
        entry_out->deleted = json_object_get_boolean(j_val);

    json_object_put(root);
    return 0;
}

/* ============================================================================
 * Helper: Publish entries to a multi-owner index bucket
 * ========================================================================== */

static int publish_index_entries(dht_context_t *dht_ctx,
                                  const char *index_key,
                                  const dna_feed_index_entry_t *entries,
                                  size_t count) {
    if (!dht_ctx || !index_key || !entries || count == 0) return -1;

    /* Get my value_id (unique per DHT identity) */
    uint64_t my_value_id = 1;
    dht_get_owner_value_id(dht_ctx, &my_value_id);

    /* First, fetch my existing entries for this bucket */
    dna_feed_index_entry_t *my_entries = NULL;
    size_t my_count = 0;

    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = dht_get_all(dht_ctx, (const uint8_t *)index_key, strlen(index_key),
                          &values, &lens, &value_count);

    if (ret == 0 && value_count > 0) {
        /* Collect my entries - look for arrays that contain entries I authored */
        size_t capacity = 0;

        for (size_t i = 0; i < value_count; i++) {
            if (values[i] && lens[i] > 0) {
                char *json_str = malloc(lens[i] + 1);
                if (json_str) {
                    memcpy(json_str, values[i], lens[i]);
                    json_str[lens[i]] = '\0';

                    json_object *arr = json_tokener_parse(json_str);
                    if (arr && json_object_is_type(arr, json_type_array)) {
                        int arr_len = json_object_array_length(arr);
                        if (arr_len > 0) {
                            json_object *first = json_object_array_get_idx(arr, 0);
                            json_object *author_obj;
                            if (json_object_object_get_ex(first, "author", &author_obj)) {
                                const char *arr_author = json_object_get_string(author_obj);
                                /* Check if this array's entries match the new entry author */
                                if (arr_author && count > 0 &&
                                    strcmp(arr_author, entries[0].author_fingerprint) == 0) {
                                    /* These are my entries - parse them */
                                    for (int j = 0; j < arr_len; j++) {
                                        json_object *e = json_object_array_get_idx(arr, j);
                                        const char *e_str = json_object_to_json_string(e);

                                        if (my_count >= capacity) {
                                            capacity = capacity ? capacity * 2 : 16;
                                            dna_feed_index_entry_t *tmp = realloc(
                                                my_entries, capacity * sizeof(dna_feed_index_entry_t));
                                            if (!tmp) break;
                                            my_entries = tmp;
                                        }

                                        if (index_entry_from_json(e_str, &my_entries[my_count]) == 0) {
                                            my_count++;
                                        }
                                    }
                                }
                            }
                        }
                        json_object_put(arr);
                    } else if (arr) {
                        json_object_put(arr);
                    }
                    free(json_str);
                }
            }
            free(values[i]);
        }
        free(values);
        free(lens);
    }

    /* Build new array: existing entries + new entries (deduped) */
    json_object *arr = json_object_new_array();

    /* Add existing entries */
    for (size_t i = 0; i < my_count; i++) {
        /* Skip if this UUID is in the new entries (will be re-added) */
        bool skip = false;
        for (size_t j = 0; j < count; j++) {
            if (strcmp(my_entries[i].topic_uuid, entries[j].topic_uuid) == 0) {
                skip = true;
                break;
            }
        }
        if (skip) continue;

        char *e_json = NULL;
        if (index_entry_to_json(&my_entries[i], &e_json) == 0) {
            json_object *e_obj = json_tokener_parse(e_json);
            if (e_obj) {
                json_object_array_add(arr, e_obj);
            }
            free(e_json);
        }
    }
    free(my_entries);

    /* Add new entries */
    for (size_t i = 0; i < count; i++) {
        char *e_json = NULL;
        if (index_entry_to_json(&entries[i], &e_json) == 0) {
            json_object *e_obj = json_tokener_parse(e_json);
            if (e_obj) {
                json_object_array_add(arr, e_obj);
            }
            free(e_json);
        }
    }

    /* Publish */
    const char *json_data = json_object_to_json_string(arr);
    size_t arr_count = json_object_array_length(arr);

    QGP_LOG_INFO(LOG_TAG, "Publishing %zu index entries to DHT (value_id=%llu)...\n",
                 arr_count, (unsigned long long)my_value_id);

    ret = dht_put_signed(dht_ctx, (const uint8_t *)index_key, strlen(index_key),
                         (const uint8_t *)json_data, strlen(json_data),
                         my_value_id, DNA_FEED_TTL_SECONDS, "feed_index");
    json_object_put(arr);

    return ret;
}

/* ============================================================================
 * Helper: Fetch entries from a day bucket
 * ========================================================================== */

static int fetch_day_bucket(dht_context_t *dht_ctx,
                             const char *index_key,
                             dna_feed_index_entry_t **entries_out,
                             size_t *count_out) {
    if (!dht_ctx || !index_key || !entries_out || !count_out) return -1;

    *entries_out = NULL;
    *count_out = 0;

    uint8_t **values = NULL;
    size_t *lens = NULL;
    size_t value_count = 0;

    int ret = dht_get_all(dht_ctx, (const uint8_t *)index_key, strlen(index_key),
                          &values, &lens, &value_count);

    if (ret != 0 || value_count == 0) {
        return (ret == 0) ? -2 : -1;
    }

    /* Parse all entries from all owners */
    dna_feed_index_entry_t *entries = NULL;
    size_t capacity = 0;
    size_t parsed = 0;

    for (size_t i = 0; i < value_count; i++) {
        if (values[i] && lens[i] > 0) {
            char *json_str = malloc(lens[i] + 1);
            if (json_str) {
                memcpy(json_str, values[i], lens[i]);
                json_str[lens[i]] = '\0';

                json_object *obj = json_tokener_parse(json_str);
                if (obj) {
                    if (json_object_is_type(obj, json_type_array)) {
                        int arr_len = json_object_array_length(obj);
                        for (int j = 0; j < arr_len; j++) {
                            json_object *e = json_object_array_get_idx(obj, j);
                            const char *e_str = json_object_to_json_string(e);

                            if (parsed >= capacity) {
                                capacity = capacity ? capacity * 2 : 32;
                                dna_feed_index_entry_t *tmp = realloc(
                                    entries, capacity * sizeof(dna_feed_index_entry_t));
                                if (!tmp) break;
                                entries = tmp;
                            }

                            if (index_entry_from_json(e_str, &entries[parsed]) == 0) {
                                /* Dedup by topic_uuid */
                                bool duplicate = false;
                                for (size_t k = 0; k < parsed; k++) {
                                    if (strcmp(entries[k].topic_uuid, entries[parsed].topic_uuid) == 0) {
                                        duplicate = true;
                                        break;
                                    }
                                }
                                if (!duplicate) {
                                    parsed++;
                                }
                            }
                        }
                    } else {
                        /* Single entry */
                        if (parsed >= capacity) {
                            capacity = capacity ? capacity * 2 : 32;
                            dna_feed_index_entry_t *tmp = realloc(
                                entries, capacity * sizeof(dna_feed_index_entry_t));
                            if (!tmp) {
                                json_object_put(obj);
                                free(json_str);
                                continue;
                            }
                            entries = tmp;
                        }

                        if (index_entry_from_json(json_str, &entries[parsed]) == 0) {
                            bool duplicate = false;
                            for (size_t k = 0; k < parsed; k++) {
                                if (strcmp(entries[k].topic_uuid, entries[parsed].topic_uuid) == 0) {
                                    duplicate = true;
                                    break;
                                }
                            }
                            if (!duplicate) {
                                parsed++;
                            }
                        }
                    }
                    json_object_put(obj);
                }
                free(json_str);
            }
        }
        free(values[i]);
    }
    free(values);
    free(lens);

    if (parsed == 0) {
        free(entries);
        return -2;
    }

    *entries_out = entries;
    *count_out = parsed;
    return 0;
}

/* ============================================================================
 * Public API
 * ========================================================================== */

void dna_feed_index_entries_free(dna_feed_index_entry_t *entries, size_t count) {
    (void)count;
    free(entries);
}

int dna_feed_index_add(dht_context_t *dht_ctx, const dna_feed_index_entry_t *entry) {
    if (!dht_ctx || !entry) return -1;

    /* Get today's date */
    char today[12];
    dna_feed_get_today_date(today);

    /* 1. Add to category index */
    char cat_key[256];
    snprintf(cat_key, sizeof(cat_key), "dna:feeds:idx:cat:%s:%s",
             entry->category_id, today);

    int ret = publish_index_entries(dht_ctx, cat_key, entry, 1);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add to category index\n");
        /* Continue to try global index */
    }

    /* 2. Add to global index */
    char global_key[256];
    snprintf(global_key, sizeof(global_key), "dna:feeds:idx:all:%s", today);

    ret = publish_index_entries(dht_ctx, global_key, entry, 1);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to add to global index\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Added topic %s to indexes\n", entry->topic_uuid);
    return 0;
}

int dna_feed_index_update_deleted(dht_context_t *dht_ctx,
                                   const char *topic_uuid,
                                   const char *author_fingerprint,
                                   const char *title,
                                   const char *category_id,
                                   uint64_t created_at) {
    if (!dht_ctx || !topic_uuid || !category_id) return -1;

    /* Get the date string from the original creation timestamp */
    char date_str[12];
    dna_feed_get_date_from_timestamp(created_at, date_str);

    /* Build index entry with deleted=true */
    dna_feed_index_entry_t entry = {0};
    strncpy(entry.topic_uuid, topic_uuid, DNA_FEED_UUID_LEN - 1);
    if (author_fingerprint) {
        strncpy(entry.author_fingerprint, author_fingerprint, DNA_FEED_FINGERPRINT_LEN - 1);
    }
    if (title) {
        strncpy(entry.title, title, DNA_FEED_MAX_TITLE_LEN);
    }
    strncpy(entry.category_id, category_id, DNA_FEED_CATEGORY_ID_LEN - 1);
    entry.created_at = created_at;
    entry.deleted = true;

    /* 1. Update category index */
    char cat_key[256];
    snprintf(cat_key, sizeof(cat_key), "dna:feeds:idx:cat:%s:%s",
             category_id, date_str);

    int ret = publish_index_entries(dht_ctx, cat_key, &entry, 1);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update category index for deleted topic\n");
        /* Continue to try global index */
    }

    /* 2. Update global index */
    char global_key[256];
    snprintf(global_key, sizeof(global_key), "dna:feeds:idx:all:%s", date_str);

    ret = publish_index_entries(dht_ctx, global_key, &entry, 1);
    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to update global index for deleted topic\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Updated indexes for deleted topic %s (date=%s)\n",
                 topic_uuid, date_str);
    return 0;
}

int dna_feed_index_get_category(dht_context_t *dht_ctx,
                                const char *category,
                                int days_back,
                                dna_feed_index_entry_t **entries_out,
                                size_t *count_out) {
    if (!dht_ctx || !category || !entries_out || !count_out) return -1;

    /* Validate days_back */
    if (days_back <= 0) days_back = DNA_FEED_INDEX_DAYS_DEFAULT;
    if (days_back > DNA_FEED_INDEX_DAYS_MAX) days_back = DNA_FEED_INDEX_DAYS_MAX;

    /* Get category_id */
    char category_id[DNA_FEED_CATEGORY_ID_LEN];
    if (dna_feed_make_category_id(category, category_id) != 0) {
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching category '%s' index (%d days)...\n", category, days_back);

    /* Fetch from each day bucket and merge */
    dna_feed_index_entry_t *all_entries = NULL;
    size_t all_count = 0;
    size_t all_capacity = 0;

    for (int d = 0; d < days_back; d++) {
        char date[12];
        dna_feed_get_date_offset(d, date);

        char cat_key[256];
        snprintf(cat_key, sizeof(cat_key), "dna:feeds:idx:cat:%s:%s", category_id, date);

        dna_feed_index_entry_t *day_entries = NULL;
        size_t day_count = 0;

        int ret = fetch_day_bucket(dht_ctx, cat_key, &day_entries, &day_count);
        if (ret == 0 && day_entries && day_count > 0) {
            /* Merge, deduping by topic_uuid */
            for (size_t i = 0; i < day_count; i++) {
                bool duplicate = false;
                for (size_t j = 0; j < all_count; j++) {
                    if (strcmp(all_entries[j].topic_uuid, day_entries[i].topic_uuid) == 0) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) continue;

                if (all_count >= all_capacity) {
                    all_capacity = all_capacity ? all_capacity * 2 : 64;
                    dna_feed_index_entry_t *tmp = realloc(
                        all_entries, all_capacity * sizeof(dna_feed_index_entry_t));
                    if (!tmp) break;
                    all_entries = tmp;
                }

                all_entries[all_count++] = day_entries[i];
            }
            free(day_entries);
        }
    }

    if (all_count == 0) {
        free(all_entries);
        *entries_out = NULL;
        *count_out = 0;
        return -2;
    }

    /* Sort by created_at descending (newest first) */
    for (size_t i = 0; i < all_count - 1; i++) {
        for (size_t j = i + 1; j < all_count; j++) {
            if (all_entries[i].created_at < all_entries[j].created_at) {
                dna_feed_index_entry_t tmp = all_entries[i];
                all_entries[i] = all_entries[j];
                all_entries[j] = tmp;
            }
        }
    }

    /* Filter out deleted entries */
    size_t filtered = 0;
    for (size_t i = 0; i < all_count; i++) {
        if (!all_entries[i].deleted) {
            if (filtered != i) {
                all_entries[filtered] = all_entries[i];
            }
            filtered++;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu entries (%zu after filtering deleted)\n", all_count, filtered);

    *entries_out = all_entries;
    *count_out = filtered;
    return 0;
}

int dna_feed_index_get_all(dht_context_t *dht_ctx,
                           int days_back,
                           dna_feed_index_entry_t **entries_out,
                           size_t *count_out) {
    if (!dht_ctx || !entries_out || !count_out) return -1;

    /* Validate days_back */
    if (days_back <= 0) days_back = DNA_FEED_INDEX_DAYS_DEFAULT;
    if (days_back > DNA_FEED_INDEX_DAYS_MAX) days_back = DNA_FEED_INDEX_DAYS_MAX;

    QGP_LOG_INFO(LOG_TAG, "Fetching global index (%d days)...\n", days_back);

    /* Fetch from each day bucket and merge */
    dna_feed_index_entry_t *all_entries = NULL;
    size_t all_count = 0;
    size_t all_capacity = 0;

    for (int d = 0; d < days_back; d++) {
        char date[12];
        dna_feed_get_date_offset(d, date);

        char global_key[256];
        snprintf(global_key, sizeof(global_key), "dna:feeds:idx:all:%s", date);

        dna_feed_index_entry_t *day_entries = NULL;
        size_t day_count = 0;

        int ret = fetch_day_bucket(dht_ctx, global_key, &day_entries, &day_count);
        if (ret == 0 && day_entries && day_count > 0) {
            /* Merge, deduping by topic_uuid */
            for (size_t i = 0; i < day_count; i++) {
                bool duplicate = false;
                for (size_t j = 0; j < all_count; j++) {
                    if (strcmp(all_entries[j].topic_uuid, day_entries[i].topic_uuid) == 0) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) continue;

                if (all_count >= all_capacity) {
                    all_capacity = all_capacity ? all_capacity * 2 : 64;
                    dna_feed_index_entry_t *tmp = realloc(
                        all_entries, all_capacity * sizeof(dna_feed_index_entry_t));
                    if (!tmp) break;
                    all_entries = tmp;
                }

                all_entries[all_count++] = day_entries[i];
            }
            free(day_entries);
        }
    }

    if (all_count == 0) {
        free(all_entries);
        *entries_out = NULL;
        *count_out = 0;
        return -2;
    }

    /* Sort by created_at descending (newest first) */
    for (size_t i = 0; i < all_count - 1; i++) {
        for (size_t j = i + 1; j < all_count; j++) {
            if (all_entries[i].created_at < all_entries[j].created_at) {
                dna_feed_index_entry_t tmp = all_entries[i];
                all_entries[i] = all_entries[j];
                all_entries[j] = tmp;
            }
        }
    }

    /* Filter out deleted entries */
    size_t filtered = 0;
    for (size_t i = 0; i < all_count; i++) {
        if (!all_entries[i].deleted) {
            if (filtered != i) {
                all_entries[filtered] = all_entries[i];
            }
            filtered++;
        }
    }

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu entries (%zu after filtering deleted)\n", all_count, filtered);

    *entries_out = all_entries;
    *count_out = filtered;
    return 0;
}
