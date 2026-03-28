/*
 * DNA Engine - Wall Poll Module (v0.9.142+)
 *
 * Periodic batch polling replaces per-contact DHT listeners.
 * Every poll cycle:
 *   1. Batch GET all contact meta keys (1 round trip)
 *   2. Compare with cached meta (updated timestamp)
 *   3. Fetch missing/changed day buckets via wall_day_complete cross-check
 *   4. Fetch today's boost keys
 *   5. Fire DNA_EVENT_WALL_NEW_POST if new data found
 */

#define DNA_ENGINE_WALL_POLL_IMPL
#include "engine_includes.h"
#include "dht/client/dna_wall.h"
#include "dht/shared/nodus_ops.h"
#include "database/wall_cache.h"

#undef LOG_TAG
#define LOG_TAG "WALL_POLL"

#define WALL_POLL_INTERVAL_SECS  300   /* 5 minutes */
#define WALL_POLL_MAX_BACKFILL    5    /* Max day buckets to fetch per contact per cycle */

/* ============================================================================
 * HELPER — Today's date string (duplicated from dna_engine_wall.c, static there)
 * ============================================================================ */

static void wall_poll_today_str(char *buf, size_t buf_size) {
    time_t now = time(NULL);
    struct tm *utc = gmtime(&now);
    snprintf(buf, buf_size, "%04d-%02d-%02d",
             utc->tm_year + 1900, utc->tm_mon + 1, utc->tm_mday);
}

/* ============================================================================
 * wall_poll_refresh — Batch meta poll + history backfill
 * ============================================================================ */

/**
 * Poll all contact + following wall metas in one batch.
 * Compare with cached versions, fetch missing day buckets.
 *
 * @param engine  Engine instance
 * @return number of walls with new data (0 = no changes)
 */
int wall_poll_refresh(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) return 0;
    if (!nodus_ops_is_ready()) return 0;

    /* Build fingerprint list: own + contacts + following */
    contacts_db_init(engine->fingerprint);
    following_db_init(engine->fingerprint);

    contact_list_t *clist = NULL;
    contacts_db_list(&clist);
    following_list_t *flist = NULL;
    following_db_list(&flist);

    size_t contact_count = clist ? clist->count : 0;
    size_t follow_count = flist ? flist->count : 0;
    size_t fp_count = 1 + contact_count + follow_count;

    const char **fingerprints = calloc(fp_count, sizeof(const char *));
    if (!fingerprints) {
        if (clist) contacts_db_free_list(clist);
        if (flist) following_db_free_list(flist);
        return 0;
    }

    fingerprints[0] = engine->fingerprint;
    size_t idx = 1;
    if (clist) {
        for (size_t i = 0; i < clist->count; i++)
            fingerprints[idx++] = clist->contacts[i].identity;
    }
    if (flist) {
        for (size_t i = 0; i < flist->count; i++) {
            const char *fp = flist->entries[i].fingerprint;
            bool dup = false;
            for (size_t j = 0; j < idx; j++) {
                if (fingerprints[j] && strcmp(fingerprints[j], fp) == 0) {
                    dup = true;
                    break;
                }
            }
            if (!dup) fingerprints[idx++] = fp;
        }
        fp_count = idx;
    }

    /* Build meta key strings for batch GET */
    char **meta_keys = calloc(fp_count, sizeof(char *));
    char *key_buf = calloc(fp_count, 256);  /* key string pool */
    if (!meta_keys || !key_buf) {
        free(meta_keys); free(key_buf); free(fingerprints);
        if (clist) contacts_db_free_list(clist);
        if (flist) following_db_free_list(flist);
        return 0;
    }

    for (size_t i = 0; i < fp_count; i++) {
        meta_keys[i] = key_buf + (i * 256);
        snprintf(meta_keys[i], 256, "%s%s",
                 DNA_WALL_META_KEY_PREFIX, fingerprints[i]);
    }

    /* Batch GET all meta keys (1 round trip) */
    nodus_ops_batch_result_t *results = NULL;
    int result_count = 0;
    int rc = nodus_ops_get_batch_str((const char **)meta_keys, (int)fp_count,
                                      &results, &result_count);

    int updated_walls = 0;
    char today[16];
    wall_poll_today_str(today, sizeof(today));

    if (rc == 0 && results) {
        for (int i = 0; i < result_count && (size_t)i < fp_count; i++) {
            if (atomic_load(&engine->shutdown_requested)) break;

            if (results[i].count == 0 || !results[i].values[0] ||
                results[i].lens[0] == 0)
                continue;

            /* Parse meta JSON from DHT */
            char *json_str = malloc(results[i].lens[0] + 1);
            if (!json_str) continue;
            memcpy(json_str, results[i].values[0], results[i].lens[0]);
            json_str[results[i].lens[0]] = '\0';

            dna_wall_meta_t dht_meta = {0};
            if (dna_wall_meta_from_json(json_str, &dht_meta) != 0) {
                free(json_str);
                continue;
            }

            /* Compare with cached meta */
            char *cached_json = NULL;
            dna_wall_meta_t cached_meta = {0};
            bool meta_changed = true;

            if (wall_cache_load_wall_meta(fingerprints[i], &cached_json) == 0
                && cached_json) {
                if (dna_wall_meta_from_json(cached_json, &cached_meta) == 0) {
                    meta_changed = (dht_meta.updated != cached_meta.updated);
                }
                dna_wall_meta_free(&cached_meta);
                free(cached_json);
            }

            /* Update cached meta */
            wall_cache_store_wall_meta(fingerprints[i], json_str);
            wall_cache_update_wall_meta(fingerprints[i]);
            free(json_str);

            /* Cross-check days with wall_day_complete — fetch missing buckets */
            int fetched_this_wall = 0;
            for (size_t d = 0; d < dht_meta.day_count; d++) {
                if (atomic_load(&engine->shutdown_requested)) break;

                const char *day = dht_meta.days[d];
                bool is_today = (strcmp(day, today) == 0);

                if (is_today) {
                    /* Today: always fetch (mutable) */
                    if (!wall_cache_is_stale_day(fingerprints[i], day))
                        continue;
                } else {
                    /* Past day: check wall_day_complete */
                    int expected = wall_day_complete_get(fingerprints[i], day);
                    if (expected >= 0) continue;  /* Already complete */
                }

                /* Fetch this day's bucket */
                if (fetched_this_wall >= WALL_POLL_MAX_BACKFILL && !is_today)
                    continue;  /* Rate limit backfill per cycle */

                dna_wall_t day_wall = {0};
                int ret = dna_wall_load_day(fingerprints[i], day, &day_wall);
                if (ret == 0 && day_wall.post_count > 0) {
                    wall_cache_store(fingerprints[i], day_wall.posts,
                                      day_wall.post_count);
                    wall_cache_update_meta_day(fingerprints[i], day);
                    if (!is_today) {
                        wall_day_complete_set(fingerprints[i], day,
                                              (int)day_wall.post_count);
                    }
                    fetched_this_wall++;
                } else if (ret == -2 || ret == NODUS_ERR_NOT_FOUND) {
                    wall_cache_update_meta_day(fingerprints[i], day);
                    if (!is_today) {
                        wall_day_complete_set(fingerprints[i], day, 0);
                    }
                }
                dna_wall_free(&day_wall);
            }

            if (fetched_this_wall > 0 || meta_changed) {
                updated_walls++;
            }

            dna_wall_meta_free(&dht_meta);
        }
        nodus_ops_free_batch_result(results, result_count);
    }

    free(meta_keys);
    free(key_buf);
    free(fingerprints);
    if (clist) contacts_db_free_list(clist);
    if (flist) following_db_free_list(flist);

    QGP_LOG_INFO(LOG_TAG, "Poll complete: %zu contacts, %d updated",
                 fp_count, updated_walls);
    return updated_walls;
}

/* ============================================================================
 * wall_poll_boosts — Poll boost keys for recent days
 * ============================================================================ */

/**
 * Poll boost keys for last 2 days.
 * Boosts use multi-owner pattern, so get_all_str is needed.
 */
int wall_poll_boosts(dna_engine_t *engine) {
    if (!engine || !engine->identity_loaded) return 0;

    dna_wall_boost_ptr_t *ptrs = NULL;
    size_t count = 0;
    int ret = dna_wall_boost_load_recent(2, &ptrs, &count);

    if (ret == 0 && ptrs && count > 0) {
        wall_cache_store_boosts(ptrs, count);
        free(ptrs);
        return 1;
    }
    if (ptrs) free(ptrs);
    return 0;
}

/* ============================================================================
 * Timer thread — periodic poll cycle
 * ============================================================================ */

static void *wall_poll_timer_thread(void *arg) {
    dna_engine_t *engine = (dna_engine_t *)arg;

    /* Initial delay — let engine fully initialize */
    for (int i = 0; i < 10 && !atomic_load(&engine->shutdown_requested); i++)
        sleep(1);

    while (!atomic_load(&engine->shutdown_requested)) {
        if (engine->identity_loaded && nodus_ops_is_ready()) {
            int updated = wall_poll_refresh(engine);
            int boost_updated = wall_poll_boosts(engine);

            if ((updated > 0 || boost_updated > 0)
                && !atomic_load(&engine->shutdown_requested)) {
                /* WAL checkpoint so Flutter reads see fresh data */
                wall_cache_wal_checkpoint();

                dna_event_t event = {0};
                event.type = DNA_EVENT_WALL_NEW_POST;
                dna_dispatch_event(engine, &event);

                QGP_LOG_INFO(LOG_TAG, "Poll: %d walls updated, notified Flutter",
                             updated);
            }
        }

        /* Sleep in 1-second increments (responsive to shutdown) */
        for (int s = 0; s < WALL_POLL_INTERVAL_SECS
                        && !atomic_load(&engine->shutdown_requested); s++)
            sleep(1);
    }

    QGP_LOG_INFO(LOG_TAG, "Poll timer thread exiting");
    return NULL;
}

/**
 * Start wall poll timer (called once after identity load)
 */
void dna_engine_start_wall_poll(dna_engine_t *engine) {
    if (!engine || engine->wall_poll_active) return;

    if (pthread_create(&engine->wall_poll_thread, NULL,
                        wall_poll_timer_thread, engine) == 0) {
        engine->wall_poll_active = true;
        QGP_LOG_INFO(LOG_TAG, "Wall poll timer started (interval=%ds)",
                     WALL_POLL_INTERVAL_SECS);
    }
}

/**
 * Stop wall poll timer (called on shutdown)
 */
void dna_engine_stop_wall_poll(dna_engine_t *engine) {
    if (!engine || !engine->wall_poll_active) return;

    /* shutdown_requested is already set by caller */
    pthread_join(engine->wall_poll_thread, NULL);
    engine->wall_poll_active = false;
    QGP_LOG_INFO(LOG_TAG, "Wall poll timer stopped");
}
