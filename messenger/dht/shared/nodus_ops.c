/**
 * Nodus v5 — Convenience Operations Layer Implementation
 *
 * Direct wrapper around nodus_singleton for DHT operations.
 * Handles key hashing, value creation, signing, and listener dispatch.
 *
 * All operations that touch nodus_client are serialized via
 * nodus_singleton_lock/unlock — the client is single-threaded.
 *
 * @file nodus_ops.c
 */

#include "nodus_ops.h"
#include "client/nodus_singleton.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "core/nodus_value.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

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
    if (!c || !nodus_client_is_ready(c)) return -1;

    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id) return -1;

    if (vid == 0) vid = nodus_identity_value_id(id);

    /* Create and sign the value */
    nodus_value_t *val = NULL;
    if (nodus_value_create(k, data, data_len, type, ttl,
                            vid, 0, &id->pk, &val) != 0)
        return -1;
    if (nodus_value_sign(val, &id->sk) != 0) {
        nodus_value_free(val);
        return -1;
    }

    nodus_singleton_lock();
    int rc = nodus_client_put(c, k, data, data_len,
                               type, ttl, vid, 0, &val->signature);
    nodus_singleton_unlock();
    nodus_value_free(val);
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
    if (!c || !nodus_client_is_ready(c)) return -1;

    nodus_key_t k;
    hash_key(key, key_len, &k);

    nodus_value_t *val = NULL;
    nodus_singleton_lock();
    int rc = nodus_client_get(c, &k, &val);
    nodus_singleton_unlock();
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
    if (!c || !nodus_client_is_ready(c)) return -1;

    nodus_key_t k;
    hash_str(str_key, &k);

    nodus_value_t *val = NULL;
    nodus_singleton_lock();
    int rc = nodus_client_get(c, &k, &val);
    nodus_singleton_unlock();
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
    if (!c || !nodus_client_is_ready(c)) return -1;

    nodus_key_t k;
    hash_key(key, key_len, &k);

    nodus_value_t **vals = NULL;
    size_t count = 0;
    nodus_singleton_lock();
    int rc = nodus_client_get_all(c, &k, &vals, &count);
    nodus_singleton_unlock();
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
    if (!c || !nodus_client_is_ready(c)) return -1;

    nodus_key_t k;
    hash_key(key, key_len, &k);

    nodus_value_t **vals = NULL;
    size_t count = 0;
    nodus_singleton_lock();
    int rc = nodus_client_get_all(c, &k, &vals, &count);
    nodus_singleton_unlock();
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
    for (int i = 0; i < MAX_OPS_LISTENERS; i++) {
        if (!g_listeners[i].active) continue;
        if (nodus_key_cmp(&g_listeners[i].key, key) != 0) continue;

        bool keep = g_listeners[i].callback(
            val ? val->data : NULL,
            val ? val->data_len : 0,
            false,
            g_listeners[i].user_data
        );
        if (!keep) {
            g_listeners[i].active = false;
            if (g_listeners[i].cleanup)
                g_listeners[i].cleanup(g_listeners[i].user_data);
        }
    }
}

size_t nodus_ops_listen(const uint8_t *key, size_t key_len,
                        nodus_ops_listen_cb_t callback,
                        void *user_data,
                        nodus_ops_listen_cleanup_t cleanup) {
    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c) || !key || !callback) return 0;

    nodus_key_t k;
    hash_key(key, key_len, &k);

    /* Register LISTEN on the server */
    nodus_singleton_lock();
    int rc = nodus_client_listen(c, &k);
    nodus_singleton_unlock();
    if (rc != 0) return 0;

    /* Track locally for callback dispatch */
    for (int i = 0; i < MAX_OPS_LISTENERS; i++) {
        if (!g_listeners[i].active) {
            g_listeners[i].token = g_next_token++;
            g_listeners[i].key = k;
            g_listeners[i].callback = callback;
            g_listeners[i].user_data = user_data;
            g_listeners[i].cleanup = cleanup;
            g_listeners[i].active = true;
            return g_listeners[i].token;
        }
    }
    return 0;  /* No slot available */
}

void nodus_ops_cancel_listen(size_t token) {
    for (int i = 0; i < MAX_OPS_LISTENERS; i++) {
        if (g_listeners[i].active && g_listeners[i].token == token) {
            nodus_client_t *c = nodus_singleton_get();
            if (c && nodus_client_is_ready(c)) {
                nodus_singleton_lock();
                nodus_client_unlisten(c, &g_listeners[i].key);
                nodus_singleton_unlock();
            }
            g_listeners[i].active = false;
            if (g_listeners[i].cleanup)
                g_listeners[i].cleanup(g_listeners[i].user_data);
            return;
        }
    }
}

void nodus_ops_cancel_all(void) {
    for (int i = 0; i < MAX_OPS_LISTENERS; i++) {
        if (g_listeners[i].active) {
            nodus_client_t *c = nodus_singleton_get();
            if (c && nodus_client_is_ready(c)) {
                nodus_singleton_lock();
                nodus_client_unlisten(c, &g_listeners[i].key);
                nodus_singleton_unlock();
            }
            g_listeners[i].active = false;
            if (g_listeners[i].cleanup)
                g_listeners[i].cleanup(g_listeners[i].user_data);
        }
    }
}

size_t nodus_ops_listen_count(void) {
    size_t count = 0;
    for (int i = 0; i < MAX_OPS_LISTENERS; i++)
        if (g_listeners[i].active) count++;
    return count;
}

bool nodus_ops_is_listener_active(size_t token) {
    for (int i = 0; i < MAX_OPS_LISTENERS; i++) {
        if (g_listeners[i].token == token)
            return g_listeners[i].active;
    }
    return false;
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
    if (!client || !nodus_client_is_ready(client))
        return -1;

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
    nodus_singleton_lock();
    int rc = nodus_client_presence_query(client, fps, count, &result);
    nodus_singleton_unlock();

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
