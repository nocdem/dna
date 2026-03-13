/**
 * Nodus — Convenience Operations Layer Implementation
 *
 * Direct wrapper around nodus_singleton for DHT operations.
 * Handles key hashing, value creation, signing, and listener dispatch.
 *
 * The nodus client supports concurrent requests internally —
 * no external serialization needed.
 *
 * @file nodus_ops.c
 */

#include "nodus_ops.h"
#include "client/nodus_singleton.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "core/nodus_value.h"
#include "crypto/utils/qgp_log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ── Listener tracking ─────────────────────────────────────────── */

#define MAX_OPS_LISTENERS 1024

typedef struct {
    size_t                      token;
    nodus_key_t                 key;
    nodus_ops_listen_cb_t       callback;
    void                       *user_data;
    nodus_ops_listen_cleanup_t  cleanup;
    bool                        active;
} ops_listener_t;

static ops_listener_t g_listeners[MAX_OPS_LISTENERS];
static size_t g_next_token = 1;

/* Mutex protecting g_listeners[] and g_next_token.
 * Pattern: lock → read/write fields → unlock → invoke callbacks outside lock. */
#ifdef _WIN32
  #include <windows.h>
  static CRITICAL_SECTION g_listener_cs;
  static int g_listener_cs_init = 0;
  static void listener_lock(void) {
      if (!g_listener_cs_init) { InitializeCriticalSection(&g_listener_cs); g_listener_cs_init = 1; }
      EnterCriticalSection(&g_listener_cs);
  }
  static void listener_unlock(void) { LeaveCriticalSection(&g_listener_cs); }
#else
  #include <pthread.h>
  static pthread_mutex_t g_listener_mutex = PTHREAD_MUTEX_INITIALIZER;
  static void listener_lock(void)   { pthread_mutex_lock(&g_listener_mutex); }
  static void listener_unlock(void) { pthread_mutex_unlock(&g_listener_mutex); }
#endif

/* ── Internal helpers ──────────────────────────────────────────── */

/** Hash raw key bytes to nodus_key_t (SHA3-512). */
static void hash_key(const uint8_t *key, size_t key_len, nodus_key_t *out) {
    nodus_hash(key, key_len, out);
}

/** Hash string key to nodus_key_t. */
static void hash_str(const char *str, nodus_key_t *out) {
    nodus_hash((const uint8_t *)str, strlen(str), out);
}

/** Internal PUT: sign and store with pre-hashed key. */
static int do_put(const nodus_key_t *k,
                  const uint8_t *data, size_t data_len,
                  nodus_value_type_t type, uint32_t ttl,
                  uint64_t vid) {
    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) {
        if (c) nodus_singleton_release();
        return -1;
    }

    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id) { nodus_singleton_release(); return -1; }

    if (vid == 0) vid = nodus_identity_value_id(id);

    /* Create and sign the value.
     * seq = current UTC timestamp so put_if_newer on replica nodes
     * always accepts a newer PUT (fixes replication with seq=0). */
    uint64_t seq = (uint64_t)time(NULL);
    nodus_value_t *val = NULL;
    if (nodus_value_create(k, data, data_len, type, ttl,
                            vid, seq, &id->pk, &val) != 0) {
        nodus_singleton_release();
        return -1;
    }
    if (nodus_value_sign(val, &id->sk) != 0) {
        nodus_value_free(val);
        nodus_singleton_release();
        return -1;
    }

    int rc = nodus_client_put(c, k, data, data_len,
                               type, ttl, vid, seq, &val->signature);
    nodus_value_free(val);
    nodus_singleton_release();
    return rc;
}

/* ── PUT operations ────────────────────────────────────────────── */

int nodus_ops_put(const uint8_t *key, size_t key_len,
                  const uint8_t *data, size_t data_len,
                  uint32_t ttl, uint64_t vid) {
    nodus_key_t k;
    hash_key(key, key_len, &k);

    nodus_value_type_t type = (ttl == 0)
        ? NODUS_VALUE_PERMANENT : NODUS_VALUE_EPHEMERAL;

    return do_put(&k, data, data_len, type, ttl, vid);
}

int nodus_ops_put_str(const char *str_key,
                      const uint8_t *data, size_t data_len,
                      uint32_t ttl, uint64_t vid) {
    if (!str_key) return -1;

    nodus_key_t k;
    hash_str(str_key, &k);

    nodus_value_type_t type = (ttl == 0)
        ? NODUS_VALUE_PERMANENT : NODUS_VALUE_EPHEMERAL;

    return do_put(&k, data, data_len, type, ttl, vid);
}

int nodus_ops_put_permanent(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint64_t vid) {
    nodus_key_t k;
    hash_key(key, key_len, &k);
    return do_put(&k, data, data_len, NODUS_VALUE_PERMANENT, 0, vid);
}

/* ── GET operations ────────────────────────────────────────────── */

int nodus_ops_get(const uint8_t *key, size_t key_len,
                  uint8_t **data_out, size_t *len_out) {
    if (!data_out || !len_out) return -1;
    *data_out = NULL;
    *len_out = 0;

    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) {
        if (c) nodus_singleton_release();
        return -1;
    }

    nodus_key_t k;
    hash_key(key, key_len, &k);

    nodus_value_t *val = NULL;
    int rc = nodus_client_get(c, &k, &val);
    nodus_singleton_release();
    if (rc != 0 || !val) return -1;

    *data_out = malloc(val->data_len);
    if (!*data_out) { nodus_value_free(val); return -1; }
    memcpy(*data_out, val->data, val->data_len);
    *len_out = val->data_len;
    nodus_value_free(val);
    return 0;
}

int nodus_ops_get_str(const char *str_key,
                      uint8_t **data_out, size_t *len_out) {
    if (!str_key || !data_out || !len_out) return -1;
    *data_out = NULL;
    *len_out = 0;

    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) {
        if (c) nodus_singleton_release();
        return -1;
    }

    nodus_key_t k;
    hash_str(str_key, &k);

    nodus_value_t *val = NULL;
    int rc = nodus_client_get(c, &k, &val);
    nodus_singleton_release();
    if (rc != 0 || !val) return -1;

    *data_out = malloc(val->data_len);
    if (!*data_out) { nodus_value_free(val); return -1; }
    memcpy(*data_out, val->data, val->data_len);
    *len_out = val->data_len;
    nodus_value_free(val);
    return 0;
}

int nodus_ops_get_all(const uint8_t *key, size_t key_len,
                      uint8_t ***values_out, size_t **lens_out,
                      size_t *count_out) {
    if (!values_out || !lens_out || !count_out) return -1;
    *values_out = NULL;
    *lens_out = NULL;
    *count_out = 0;

    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) {
        if (c) nodus_singleton_release();
        return -1;
    }

    nodus_key_t k;
    hash_key(key, key_len, &k);

    nodus_value_t **vals = NULL;
    size_t count = 0;
    int rc = nodus_client_get_all(c, &k, &vals, &count);
    nodus_singleton_release();
    if (rc != 0 || count == 0) return (rc == 0) ? 0 : -1;

    *values_out = calloc(count, sizeof(uint8_t *));
    *lens_out = calloc(count, sizeof(size_t));
    if (!*values_out || !*lens_out) {
        free(*values_out); free(*lens_out);
        *values_out = NULL; *lens_out = NULL;
        for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
        free(vals);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        (*values_out)[i] = malloc(vals[i]->data_len);
        if ((*values_out)[i]) {
            memcpy((*values_out)[i], vals[i]->data, vals[i]->data_len);
            (*lens_out)[i] = vals[i]->data_len;
        }
        nodus_value_free(vals[i]);
    }
    free(vals);
    *count_out = count;
    return 0;
}

int nodus_ops_get_all_with_ids(const uint8_t *key, size_t key_len,
                               uint8_t ***values_out, size_t **lens_out,
                               uint64_t **vids_out, size_t *count_out) {
    if (!values_out || !lens_out || !vids_out || !count_out) return -1;
    *values_out = NULL;
    *lens_out = NULL;
    *vids_out = NULL;
    *count_out = 0;

    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) {
        if (c) nodus_singleton_release();
        return -1;
    }

    nodus_key_t k;
    hash_key(key, key_len, &k);

    nodus_value_t **vals = NULL;
    size_t count = 0;
    int rc = nodus_client_get_all(c, &k, &vals, &count);
    nodus_singleton_release();
    if (rc != 0 || count == 0) {
        *count_out = 0;
        return (rc == 0) ? 0 : -1;
    }

    *values_out = calloc(count, sizeof(uint8_t *));
    *lens_out = calloc(count, sizeof(size_t));
    *vids_out = calloc(count, sizeof(uint64_t));
    if (!*values_out || !*lens_out || !*vids_out) {
        free(*values_out); free(*lens_out); free(*vids_out);
        *values_out = NULL; *lens_out = NULL; *vids_out = NULL;
        for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
        free(vals);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        (*values_out)[i] = malloc(vals[i]->data_len);
        if ((*values_out)[i]) {
            memcpy((*values_out)[i], vals[i]->data, vals[i]->data_len);
            (*lens_out)[i] = vals[i]->data_len;
        }
        (*vids_out)[i] = vals[i]->value_id;
        nodus_value_free(vals[i]);
    }
    free(vals);
    *count_out = count;
    return 0;
}

int nodus_ops_get_all_str(const char *str_key,
                          uint8_t ***values_out, size_t **lens_out,
                          size_t *count_out) {
    if (!str_key) return -1;
    return nodus_ops_get_all((const uint8_t *)str_key, strlen(str_key),
                              values_out, lens_out, count_out);
}

int nodus_ops_get_all_str_with_ids(const char *str_key,
                                    uint8_t ***values_out, size_t **lens_out,
                                    uint64_t **vids_out, size_t *count_out) {
    if (!str_key) return -1;
    return nodus_ops_get_all_with_ids((const uint8_t *)str_key, strlen(str_key),
                                      values_out, lens_out, vids_out, count_out);
}

/* ── LISTEN operations ─────────────────────────────────────────── */

void nodus_ops_dispatch(const nodus_key_t *key,
                        const nodus_value_t *val,
                        void *user_data) {
    (void)user_data;

    /* Snapshot matching listeners under lock, invoke outside lock.
     * This prevents deadlock if a callback calls cancel_listen. */
    typedef struct {
        int                     idx;
        nodus_ops_listen_cb_t   callback;
        void                   *user_data;
    } match_t;
    match_t matches[32];
    int match_count = 0;

    listener_lock();
    for (int i = 0; i < MAX_OPS_LISTENERS && match_count < 32; i++) {
        if (!g_listeners[i].active) continue;
        if (nodus_key_cmp(&g_listeners[i].key, key) != 0) continue;
        matches[match_count].idx = i;
        matches[match_count].callback = g_listeners[i].callback;
        matches[match_count].user_data = g_listeners[i].user_data;
        match_count++;
    }
    listener_unlock();

    /* Invoke callbacks outside lock */
    for (int m = 0; m < match_count; m++) {
        bool keep = matches[m].callback(
            val ? val->data : NULL,
            val ? val->data_len : 0,
            false,
            matches[m].user_data
        );
        if (!keep) {
            nodus_ops_listen_cleanup_t cleanup_fn = NULL;
            void *cleanup_data = NULL;

            listener_lock();
            int idx = matches[m].idx;
            if (g_listeners[idx].active) {
                g_listeners[idx].active = false;
                cleanup_fn = g_listeners[idx].cleanup;
                cleanup_data = g_listeners[idx].user_data;
            }
            listener_unlock();

            if (cleanup_fn)
                cleanup_fn(cleanup_data);
        }
    }
}

size_t nodus_ops_listen(const uint8_t *key, size_t key_len,
                        nodus_ops_listen_cb_t callback,
                        void *user_data,
                        nodus_ops_listen_cleanup_t cleanup) {
    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c) || !key || !callback) {
        if (c) nodus_singleton_release();
        return 0;
    }

    nodus_key_t k;
    hash_key(key, key_len, &k);

    /* Register LISTEN on the server */
    int rc = nodus_client_listen(c, &k);
    nodus_singleton_release();
    if (rc != 0) return 0;

    /* Track locally for callback dispatch */
    size_t token = 0;
    listener_lock();
    for (int i = 0; i < MAX_OPS_LISTENERS; i++) {
        if (!g_listeners[i].active) {
            g_listeners[i].token = g_next_token++;
            g_listeners[i].key = k;
            g_listeners[i].callback = callback;
            g_listeners[i].user_data = user_data;
            g_listeners[i].cleanup = cleanup;
            g_listeners[i].active = true;
            token = g_listeners[i].token;
            break;
        }
    }
    listener_unlock();
    return token;
}

void nodus_ops_cancel_listen(size_t token) {
    nodus_key_t key;
    nodus_ops_listen_cleanup_t cleanup_fn = NULL;
    void *cleanup_data = NULL;
    bool found = false;

    listener_lock();
    for (int i = 0; i < MAX_OPS_LISTENERS; i++) {
        if (g_listeners[i].active && g_listeners[i].token == token) {
            key = g_listeners[i].key;
            cleanup_fn = g_listeners[i].cleanup;
            cleanup_data = g_listeners[i].user_data;
            g_listeners[i].active = false;
            found = true;
            break;
        }
    }
    listener_unlock();

    if (found) {
        nodus_client_t *c = nodus_singleton_get();
        if (c && nodus_client_is_ready(c)) {
            nodus_client_unlisten(c, &key);
            nodus_singleton_release();
        } else if (c) {
            nodus_singleton_release();
        }
        if (cleanup_fn)
            cleanup_fn(cleanup_data);
    }
}

void nodus_ops_cancel_all(void) {
    /* Collect all active listeners under lock */
    typedef struct {
        nodus_key_t                 key;
        nodus_ops_listen_cleanup_t  cleanup;
        void                       *user_data;
    } entry_t;
    entry_t entries[MAX_OPS_LISTENERS];
    int count = 0;

    listener_lock();
    for (int i = 0; i < MAX_OPS_LISTENERS; i++) {
        if (g_listeners[i].active) {
            entries[count].key = g_listeners[i].key;
            entries[count].cleanup = g_listeners[i].cleanup;
            entries[count].user_data = g_listeners[i].user_data;
            count++;
            g_listeners[i].active = false;
        }
    }
    listener_unlock();

    /* Unlisten + cleanup outside lock */
    nodus_client_t *c = nodus_singleton_get();
    for (int i = 0; i < count; i++) {
        if (c && nodus_client_is_ready(c))
            nodus_client_unlisten(c, &entries[i].key);
        if (entries[i].cleanup)
            entries[i].cleanup(entries[i].user_data);
    }
    if (c) nodus_singleton_release();
}

size_t nodus_ops_listen_count(void) {
    size_t count = 0;
    listener_lock();
    for (int i = 0; i < MAX_OPS_LISTENERS; i++)
        if (g_listeners[i].active) count++;
    listener_unlock();
    return count;
}

bool nodus_ops_is_listener_active(size_t token) {
    bool active = false;
    listener_lock();
    for (int i = 0; i < MAX_OPS_LISTENERS; i++) {
        if (g_listeners[i].token == token) {
            active = g_listeners[i].active;
            break;
        }
    }
    listener_unlock();
    return active;
}

/* ── Presence ──────────────────────────────────────────────────── */

int nodus_ops_presence_query(const char **fingerprints, int count,
                               bool *online_out, uint64_t *last_seen_out) {
    if (!fingerprints || !online_out || count <= 0)
        return -1;

    /* Initialize all to offline */
    for (int i = 0; i < count; i++) {
        online_out[i] = false;
        if (last_seen_out) last_seen_out[i] = 0;
    }

    nodus_client_t *client = nodus_singleton_get();
    if (!client || !nodus_client_is_ready(client)) {
        if (client) nodus_singleton_release();
        return -1;
    }

    /* Cap to max query size */
    if (count > NODUS_PRESENCE_MAX_QUERY)
        count = NODUS_PRESENCE_MAX_QUERY;

    /* Convert hex fingerprints to binary keys */
    nodus_key_t *fps = calloc((size_t)count, sizeof(nodus_key_t));
    if (!fps) return -1;

    for (int i = 0; i < count; i++) {
        if (!fingerprints[i] || strlen(fingerprints[i]) != 128) {
            free(fps);
            return -1;
        }
        for (int j = 0; j < 64; j++) {
            unsigned int byte;
            if (sscanf(fingerprints[i] + (j * 2), "%02x", &byte) != 1) {
                free(fps);
                return -1;
            }
            fps[i].bytes[j] = (uint8_t)byte;
        }
    }

    /* Query server */
    nodus_presence_result_t result;
    int rc = nodus_client_presence_query(client, fps, count, &result);

    nodus_singleton_release();

    if (rc != 0) {
        free(fps);
        return -1;
    }

    /* Map online results back: match by fingerprint */
    for (int i = 0; i < result.online_count; i++) {
        for (int j = 0; j < count; j++) {
            if (nodus_key_cmp(&result.entries[i].fp, &fps[j]) == 0) {
                online_out[j] = true;
                if (last_seen_out)
                    last_seen_out[j] = result.entries[i].last_seen;
                break;
            }
        }
    }

    /* Map offline-seen results back */
    if (last_seen_out) {
        for (int i = 0; i < result.offline_seen_count; i++) {
            for (int j = 0; j < count; j++) {
                if (nodus_key_cmp(&result.offline_seen[i].fp, &fps[j]) == 0) {
                    last_seen_out[j] = result.offline_seen[i].last_seen;
                    break;
                }
            }
        }
    }

    int online_count = result.online_count;
    nodus_client_free_presence_result(&result);
    free(fps);
    return online_count;
}

/* ── Utility ───────────────────────────────────────────────────── */

bool nodus_ops_is_ready(void) {
    return nodus_singleton_is_ready();
}

uint64_t nodus_ops_value_id(void) {
    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id) return 0;
    return nodus_identity_value_id(id);
}

const char *nodus_ops_fingerprint(void) {
    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id) return NULL;
    return id->fingerprint;
}

/* ── Channel connection pool (TCP 4003) ────────────────────────── */

#include "protocol/nodus_cbor.h"
#include "crypto/hash/qgp_sha3.h"

#define LOG_TAG_CH "NODUS_OPS_CH"
#define NODUS_OPS_CH_MAX_CONNS   32
#define NODUS_OPS_CH_KEY_PREFIX  "dna:channel:nodes:"

typedef struct {
    uint8_t           channel_uuid[NODUS_UUID_BYTES];
    nodus_ch_conn_t  *conn;
    bool              active;
} nodus_ops_ch_entry_t;

static nodus_ops_ch_entry_t g_ch_pool[NODUS_OPS_CH_MAX_CONNS];
static nodus_ops_ch_post_cb_t g_ch_post_cb = NULL;
static void *g_ch_post_cb_data = NULL;
static bool g_ch_pool_initialized = false;

#ifdef _WIN32
  static CRITICAL_SECTION g_ch_pool_cs;
  static int g_ch_pool_cs_init = 0;
  static void ch_pool_lock(void) {
      if (!g_ch_pool_cs_init) { InitializeCriticalSection(&g_ch_pool_cs); g_ch_pool_cs_init = 1; }
      EnterCriticalSection(&g_ch_pool_cs);
  }
  static void ch_pool_unlock(void) { LeaveCriticalSection(&g_ch_pool_cs); }
#else
  static pthread_mutex_t g_ch_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
  static void ch_pool_lock(void)   { pthread_mutex_lock(&g_ch_pool_mutex); }
  static void ch_pool_unlock(void) { pthread_mutex_unlock(&g_ch_pool_mutex); }
#endif

/** Route push post notifications from individual connections to global callback */
static void ch_pool_on_post(const uint8_t channel_uuid[NODUS_UUID_BYTES],
                              const nodus_channel_post_t *post, void *user_data) {
    (void)user_data;
    if (g_ch_post_cb)
        g_ch_post_cb(channel_uuid, post, g_ch_post_cb_data);
}

/** Find pool entry for a channel (caller must hold lock). Returns index or -1. */
static int ch_pool_find_locked(const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    for (int i = 0; i < NODUS_OPS_CH_MAX_CONNS; i++) {
        if (g_ch_pool[i].active &&
            memcmp(g_ch_pool[i].channel_uuid, channel_uuid, NODUS_UUID_BYTES) == 0)
            return i;
    }
    return -1;
}

/** Find empty slot (caller must hold lock). Returns index or -1. */
static int ch_pool_find_empty_locked(void) {
    for (int i = 0; i < NODUS_OPS_CH_MAX_CONNS; i++) {
        if (!g_ch_pool[i].active) return i;
    }
    return -1;
}

/**
 * Parse DHT announcement CBOR to extract node list.
 * Format: {"version": N, "nodes": [{"ip": "...", "port": N, "nid": <key>}, ...]}
 * Returns number of nodes parsed, or -1 on error.
 */
typedef struct {
    char     ip[64];
    uint16_t port;
} ch_node_info_t;

static int ch_parse_dht_nodes(const uint8_t *data, size_t data_len,
                                ch_node_info_t *nodes, int max_nodes) {
    if (!data || data_len == 0 || !nodes || max_nodes <= 0) return -1;

    cbor_decoder_t dec;
    cbor_decoder_init(&dec, data, data_len);

    /* Expect top-level map */
    cbor_item_t item = cbor_decode_next(&dec);
    if (item.type != CBOR_ITEM_MAP) return -1;
    size_t map_count = item.count;

    /* Find "nodes" key */
    size_t nodes_array_len = 0;
    bool found_nodes = false;
    for (size_t i = 0; i < map_count; i++) {
        cbor_item_t key_item = cbor_decode_next(&dec);
        if (key_item.type == CBOR_ITEM_TSTR &&
            key_item.tstr.len == 5 &&
            memcmp(key_item.tstr.ptr, "nodes", 5) == 0) {
            cbor_item_t arr = cbor_decode_next(&dec);
            if (arr.type != CBOR_ITEM_ARRAY) return -1;
            nodes_array_len = arr.count;
            found_nodes = true;
            break;
        } else {
            /* Skip value */
            cbor_decode_skip(&dec);
        }
    }

    if (!found_nodes) return -1;

    int count = 0;
    for (size_t n = 0; n < nodes_array_len && count < max_nodes; n++) {
        cbor_item_t map_item = cbor_decode_next(&dec);
        if (map_item.type != CBOR_ITEM_MAP) { cbor_decode_skip(&dec); continue; }
        size_t node_map_count = map_item.count;

        char ip[64] = {0};
        uint16_t port = 0;

        for (size_t m = 0; m < node_map_count; m++) {
            cbor_item_t k = cbor_decode_next(&dec);
            if (k.type == CBOR_ITEM_TSTR && k.tstr.len == 2 &&
                memcmp(k.tstr.ptr, "ip", 2) == 0) {
                cbor_item_t v = cbor_decode_next(&dec);
                if (v.type == CBOR_ITEM_TSTR && v.tstr.len < sizeof(ip)) {
                    memcpy(ip, v.tstr.ptr, v.tstr.len);
                    ip[v.tstr.len] = '\0';
                }
            } else if (k.type == CBOR_ITEM_TSTR && k.tstr.len == 4 &&
                       memcmp(k.tstr.ptr, "port", 4) == 0) {
                cbor_item_t v = cbor_decode_next(&dec);
                if (v.type == CBOR_ITEM_UINT)
                    port = (uint16_t)v.uint_val;
            } else {
                cbor_decode_skip(&dec);
            }
        }

        if (ip[0] && port > 0) {
            memcpy(nodes[count].ip, ip, sizeof(ip));
            nodes[count].port = port;
            count++;
        }
    }

    return count;
}

/**
 * Discover responsible nodes via DHT and connect to the first available.
 * Returns a connected nodus_ch_conn_t* or NULL.
 * Caller must NOT hold pool lock.
 */
static nodus_ch_conn_t *ch_pool_connect(const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id) return NULL;

    /* Build DHT key: "dna:channel:nodes:" + raw channel_uuid bytes
     * (matches nodus_ring_announce_to_dht which hashes prefix + raw UUID) */
    uint8_t key_input[256];
    const char *prefix = NODUS_OPS_CH_KEY_PREFIX;
    size_t prefix_len = strlen(prefix);
    memcpy(key_input, prefix, prefix_len);
    memcpy(key_input + prefix_len, channel_uuid, NODUS_UUID_BYTES);

    /* Hash to get the DHT key (SHA3-512) */
    nodus_key_t dht_key;
    nodus_hash(key_input, prefix_len + NODUS_UUID_BYTES, &dht_key);

    /* GET from DHT */
    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) {
        if (c) nodus_singleton_release();
        return NULL;
    }

    nodus_value_t *val = NULL;
    int rc = nodus_client_get(c, &dht_key, &val);

    ch_node_info_t nodes[8];
    int node_count = 0;

    if (rc == 0 && val && val->data && val->data_len > 0) {
        node_count = ch_parse_dht_nodes(val->data, val->data_len, nodes, 8);
        nodus_value_free(val);
    }

    /* Fallback: use current server IP with port 4003 */
    if (node_count <= 0) {
        QGP_LOG_INFO(LOG_TAG_CH, "No DHT nodes found, using fallback server");
        node_count = 1;
        /* Access current connected server from client config */
        int idx = c->server_idx;
        if (idx >= 0 && idx < c->config.server_count) {
            memcpy(nodes[0].ip, c->config.servers[idx].ip, sizeof(nodes[0].ip));
        } else {
            memcpy(nodes[0].ip, c->config.servers[0].ip, sizeof(nodes[0].ip));
        }
        nodes[0].port = NODUS_DEFAULT_CH_PORT;
    }

    nodus_singleton_release();

    /* Try each node until one connects */
    for (int i = 0; i < node_count; i++) {
        nodus_ch_conn_t *conn = calloc(1, sizeof(nodus_ch_conn_t));
        if (!conn) continue;

        rc = nodus_channel_init(conn, nodes[i].ip, nodes[i].port,
                                  id, ch_pool_on_post, NULL);
        if (rc != 0) {
            free(conn);
            continue;
        }

        rc = nodus_channel_connect(conn);
        if (rc != 0) {
            nodus_channel_close(conn);
            free(conn);
            QGP_LOG_WARN(LOG_TAG_CH, "Failed to connect to %s:%u",
                          nodes[i].ip, (unsigned)nodes[i].port);
            continue;
        }

        /* Auto-subscribe so server pushes new posts to us */
        nodus_ch_conn_subscribe(conn, channel_uuid);

        QGP_LOG_INFO(LOG_TAG_CH, "Connected to channel node %s:%u",
                      nodes[i].ip, (unsigned)nodes[i].port);
        return conn;
    }

    QGP_LOG_ERROR(LOG_TAG_CH, "Failed to connect to any channel node");
    return NULL;
}

/**
 * Get or create a connection for a channel.
 * Thread-safe. Returns the connection or NULL.
 */
static nodus_ch_conn_t *ch_pool_get_or_connect(const uint8_t channel_uuid[NODUS_UUID_BYTES]) {
    /* Check existing */
    ch_pool_lock();
    int idx = ch_pool_find_locked(channel_uuid);
    if (idx >= 0 && g_ch_pool[idx].conn && nodus_channel_is_ready(g_ch_pool[idx].conn)) {
        nodus_ch_conn_t *conn = g_ch_pool[idx].conn;
        ch_pool_unlock();
        return conn;
    }

    /* If entry exists but connection is dead, clean it up */
    if (idx >= 0) {
        if (g_ch_pool[idx].conn) {
            nodus_channel_close(g_ch_pool[idx].conn);
            free(g_ch_pool[idx].conn);
        }
        g_ch_pool[idx].active = false;
        g_ch_pool[idx].conn = NULL;
    }
    ch_pool_unlock();

    /* Connect outside lock (may take time) */
    nodus_ch_conn_t *conn = ch_pool_connect(channel_uuid);
    if (!conn) return NULL;

    /* Store in pool */
    ch_pool_lock();
    int slot = ch_pool_find_empty_locked();
    if (slot < 0) {
        ch_pool_unlock();
        QGP_LOG_ERROR(LOG_TAG_CH, "Channel pool full (%d connections)", NODUS_OPS_CH_MAX_CONNS);
        nodus_channel_close(conn);
        free(conn);
        return NULL;
    }
    memcpy(g_ch_pool[slot].channel_uuid, channel_uuid, NODUS_UUID_BYTES);
    g_ch_pool[slot].conn = conn;
    g_ch_pool[slot].active = true;
    ch_pool_unlock();

    return conn;
}

int nodus_ops_ch_init(nodus_ops_ch_post_cb_t on_post, void *user_data) {
    ch_pool_lock();
    memset(g_ch_pool, 0, sizeof(g_ch_pool));
    g_ch_post_cb = on_post;
    g_ch_post_cb_data = user_data;
    g_ch_pool_initialized = true;
    ch_pool_unlock();
    QGP_LOG_INFO(LOG_TAG_CH, "Channel connection pool initialized");
    return 0;
}

void nodus_ops_ch_set_post_callback(nodus_ops_ch_post_cb_t on_post, void *user_data) {
    ch_pool_lock();
    g_ch_post_cb = on_post;
    g_ch_post_cb_data = user_data;
    ch_pool_unlock();
    QGP_LOG_INFO(LOG_TAG_CH, "Channel push callback %s",
                  on_post ? "registered" : "cleared");
}

void nodus_ops_ch_shutdown(void) {
    ch_pool_lock();
    for (int i = 0; i < NODUS_OPS_CH_MAX_CONNS; i++) {
        if (g_ch_pool[i].active && g_ch_pool[i].conn) {
            nodus_channel_close(g_ch_pool[i].conn);
            free(g_ch_pool[i].conn);
            g_ch_pool[i].conn = NULL;
        }
        g_ch_pool[i].active = false;
    }
    g_ch_post_cb = NULL;
    g_ch_post_cb_data = NULL;
    g_ch_pool_initialized = false;
    ch_pool_unlock();
    QGP_LOG_INFO(LOG_TAG_CH, "Channel connection pool shut down");
}

int nodus_ops_ch_create(const uint8_t channel_uuid[16]) {
    if (!g_ch_pool_initialized) return -1;

    /* For channel creation, connect to any available server on 4003 */
    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id) return -1;

    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) {
        if (c) nodus_singleton_release();
        return -1;
    }

    /* Use current connected server with ch_port */
    char ip[64];
    int idx = c->server_idx;
    if (idx >= 0 && idx < c->config.server_count) {
        memcpy(ip, c->config.servers[idx].ip, sizeof(ip));
    } else {
        memcpy(ip, c->config.servers[0].ip, sizeof(ip));
    }
    nodus_singleton_release();

    /* Create a temporary connection for channel creation */
    nodus_ch_conn_t *conn = calloc(1, sizeof(nodus_ch_conn_t));
    if (!conn) return -1;

    int rc = nodus_channel_init(conn, ip, NODUS_DEFAULT_CH_PORT,
                                  id, ch_pool_on_post, NULL);
    if (rc != 0) { free(conn); return -1; }

    rc = nodus_channel_connect(conn);
    if (rc != 0) {
        nodus_channel_close(conn);
        free(conn);
        QGP_LOG_ERROR(LOG_TAG_CH, "Failed to connect for channel create");
        return -1;
    }

    rc = nodus_ch_conn_create(conn, channel_uuid);

    /* Store connection in pool for future use */
    if (rc == 0) {
        ch_pool_lock();
        int slot = ch_pool_find_empty_locked();
        if (slot >= 0) {
            memcpy(g_ch_pool[slot].channel_uuid, channel_uuid, NODUS_UUID_BYTES);
            g_ch_pool[slot].conn = conn;
            g_ch_pool[slot].active = true;
            conn = NULL;  /* Ownership transferred to pool */
        }
        ch_pool_unlock();
    }

    if (conn) {
        nodus_channel_close(conn);
        free(conn);
    }

    return rc;
}

int nodus_ops_ch_post(const uint8_t channel_uuid[16],
                      const uint8_t post_uuid[16],
                      const uint8_t *body, size_t body_len,
                      uint64_t timestamp, const nodus_sig_t *sig,
                      uint64_t *received_at_out) {
    if (!g_ch_pool_initialized) return -1;

    nodus_ch_conn_t *conn = ch_pool_get_or_connect(channel_uuid);
    if (!conn) return -1;

    int rc = nodus_ch_conn_post(conn, channel_uuid, post_uuid,
                               body, body_len, timestamp, sig,
                               received_at_out);
    return rc;
}

int nodus_ops_ch_get_posts(const uint8_t channel_uuid[16],
                            uint64_t since_received_at, int max_count,
                            nodus_channel_post_t **posts_out,
                            size_t *count_out) {
    if (!g_ch_pool_initialized) return -1;

    nodus_ch_conn_t *conn = ch_pool_get_or_connect(channel_uuid);
    if (!conn) return -1;

    return nodus_ch_conn_get_posts(conn, channel_uuid,
                                    since_received_at, max_count,
                                    posts_out, count_out);
}

int nodus_ops_ch_subscribe(const uint8_t channel_uuid[16]) {
    if (!g_ch_pool_initialized) return -1;

    nodus_ch_conn_t *conn = ch_pool_get_or_connect(channel_uuid);
    if (!conn) return -1;

    return nodus_ch_conn_subscribe(conn, channel_uuid);
}

int nodus_ops_ch_unsubscribe(const uint8_t channel_uuid[16]) {
    if (!g_ch_pool_initialized) return -1;

    ch_pool_lock();
    int idx = ch_pool_find_locked(channel_uuid);
    if (idx < 0 || !g_ch_pool[idx].conn) {
        ch_pool_unlock();
        return -1;
    }
    nodus_ch_conn_t *conn = g_ch_pool[idx].conn;
    ch_pool_unlock();

    return nodus_ch_conn_unsubscribe(conn, channel_uuid);
}

void nodus_ops_ch_disconnect(const uint8_t channel_uuid[16]) {
    ch_pool_lock();
    int idx = ch_pool_find_locked(channel_uuid);
    if (idx >= 0) {
        if (g_ch_pool[idx].conn) {
            nodus_channel_close(g_ch_pool[idx].conn);
            free(g_ch_pool[idx].conn);
            g_ch_pool[idx].conn = NULL;
        }
        g_ch_pool[idx].active = false;
        QGP_LOG_INFO(LOG_TAG_CH, "Disconnected channel connection");
    }
    ch_pool_unlock();
}
