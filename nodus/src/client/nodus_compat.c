/**
 * Nodus v5 — Compatibility Shim Implementation
 *
 * Maps legacy dht_* and dht_chunked_* APIs to Nodus v5 client.
 * The singleton client must be initialized before any dht_* call.
 *
 * Key simplifications:
 * - dht_chunked_* operates without chunking (1MB max value in Nodus v5)
 * - dht_put_signed* uses the caller's identity for signing
 * - Listen uses Nodus LISTEN push notifications
 *
 * @file nodus_compat.c
 */

#include "client/nodus_compat.h"
#include "client/nodus_singleton.h"
#include "nodus/nodus.h"
#include "crypto/nodus_sign.h"
#include "crypto/nodus_identity.h"
#include "core/nodus_value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Internal dht_context structure ─────────────────────────────── */

struct dht_context {
    bool running;
    bool started;
    dht_config_t config;
    dht_status_callback_t status_cb;
    void *status_cb_data;
};

/* ── Internal dht_identity structure ────────────────────────────── */

struct dht_identity {
    nodus_identity_t nid;
};

/* ── Listen tracking ────────────────────────────────────────────── */

#define MAX_COMPAT_LISTENERS 1024

typedef struct {
    size_t token;          /* External token (1-based) */
    nodus_key_t key;
    dht_listen_callback_t callback;
    void *user_data;
    dht_listen_cleanup_t cleanup;
    bool active;
} compat_listener_t;

static compat_listener_t g_listeners[MAX_COMPAT_LISTENERS];
static size_t g_next_token = 1;

/* ── Helpers ────────────────────────────────────────────────────── */

/** Hash a binary key to nodus_key_t (SHA3-512) */
static void hash_key(const uint8_t *key, size_t key_len, nodus_key_t *out) {
    nodus_hash(key, key_len, out);
}

/** Hash a string key to nodus_key_t (for chunked API base_keys) */
static void hash_str_key(const char *str, nodus_key_t *out) {
    nodus_hash((const uint8_t *)str, strlen(str), out);
}

/** Internal PUT helper: sign and store */
static int do_put(const uint8_t *key, size_t key_len,
                  const uint8_t *value, size_t value_len,
                  nodus_value_type_t type, uint32_t ttl,
                  uint64_t vid, uint64_t seq) {
    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) return -1;

    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id) return -1;

    nodus_key_t k;
    hash_key(key, key_len, &k);

    /* Create and sign the value */
    nodus_value_t *val = NULL;
    if (nodus_value_create(&k, value, value_len, type, ttl,
                            vid, seq, &id->pk, &val) != 0)
        return -1;
    if (nodus_value_sign(val, &id->sk) != 0) {
        nodus_value_free(val);
        return -1;
    }

    nodus_singleton_lock();
    int rc = nodus_client_put(c, &k, value, value_len,
                               type, ttl, vid, seq, &val->signature);
    nodus_singleton_unlock();
    nodus_value_free(val);
    return rc;
}

/** Internal PUT from nodus_key_t (already hashed) */
static int do_put_hashed(const nodus_key_t *k,
                         const uint8_t *value, size_t value_len,
                         nodus_value_type_t type, uint32_t ttl,
                         uint64_t vid, uint64_t seq) {
    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) return -1;

    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id) return -1;

    nodus_value_t *val = NULL;
    if (nodus_value_create(k, value, value_len, type, ttl,
                            vid, seq, &id->pk, &val) != 0)
        return -1;
    if (nodus_value_sign(val, &id->sk) != 0) {
        nodus_value_free(val);
        return -1;
    }

    nodus_singleton_lock();
    int rc = nodus_client_put(c, k, value, value_len,
                               type, ttl, vid, seq, &val->signature);
    nodus_singleton_unlock();
    nodus_value_free(val);
    return rc;
}

/* Global value_changed callback dispatches to compat listeners */
static void compat_on_value_changed(const nodus_key_t *key,
                                     const nodus_value_t *val,
                                     void *user_data) {
    (void)user_data;
    for (int i = 0; i < MAX_COMPAT_LISTENERS; i++) {
        if (!g_listeners[i].active) continue;
        if (nodus_key_cmp(&g_listeners[i].key, key) == 0) {
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
}

/* ── DHT Context lifecycle ──────────────────────────────────────── */

dht_context_t* dht_context_new(const dht_config_t *config) {
    if (!config) return NULL;
    dht_context_t *ctx = calloc(1, sizeof(dht_context_t));
    if (!ctx) return NULL;
    ctx->config = *config;
    ctx->running = false;
    ctx->started = false;
    return ctx;
}

int dht_context_start(dht_context_t *ctx) {
    if (!ctx) return -1;
    /* Without identity, we can only mark as running.
     * Actual Nodus connection requires identity for auth. */
    ctx->running = true;
    ctx->started = true;

    /* Wire up callback if singleton is already connected */
    nodus_client_t *c = nodus_singleton_get();
    if (c) c->config.on_value_changed = compat_on_value_changed;

    return 0;
}

int dht_context_start_with_identity(dht_context_t *ctx,
                                     dht_identity_t *identity) {
    if (!ctx || !identity) return -1;
    ctx->running = true;
    ctx->started = true;

    /* If Nodus singleton is already connected, just wire up callbacks */
    if (nodus_singleton_is_ready()) {
        nodus_client_t *c = nodus_singleton_get();
        if (c) c->config.on_value_changed = compat_on_value_changed;
        return 0;
    }

    /* Build Nodus client config from DHT bootstrap nodes */
    nodus_client_config_t nconfig;
    memset(&nconfig, 0, sizeof(nconfig));
    nconfig.auto_reconnect = true;

    for (size_t i = 0; i < ctx->config.bootstrap_count &&
                        nconfig.server_count < NODUS_CLIENT_MAX_SERVERS; i++) {
        const char *node = ctx->config.bootstrap_nodes[i];
        if (!node[0]) continue;

        const char *colon = strrchr(node, ':');
        if (colon) {
            size_t ip_len = (size_t)(colon - node);
            if (ip_len >= sizeof(nconfig.servers[0].ip))
                ip_len = sizeof(nconfig.servers[0].ip) - 1;
            memcpy(nconfig.servers[nconfig.server_count].ip, node, ip_len);
            nconfig.servers[nconfig.server_count].ip[ip_len] = '\0';
            nconfig.servers[nconfig.server_count].port = (uint16_t)atoi(colon + 1);
        } else {
            strncpy(nconfig.servers[nconfig.server_count].ip, node,
                    sizeof(nconfig.servers[0].ip) - 1);
            nconfig.servers[nconfig.server_count].port = NODUS_DEFAULT_TCP_PORT;
        }
        nconfig.server_count++;
    }

    if (nconfig.server_count == 0) return -1;

    /* Initialize and connect the Nodus singleton */
    int rc_init = nodus_singleton_init(&nconfig, &identity->nid);
    if (rc_init != 0) return -1;

    int rc_conn = nodus_singleton_connect();
    if (rc_conn != 0) {
        nodus_singleton_close();
        return -1;
    }

    /* Wire up compat dispatch callback for LISTEN notifications */
    nodus_client_t *c = nodus_singleton_get();
    if (c) c->config.on_value_changed = compat_on_value_changed;

    return 0;
}

void dht_context_stop(dht_context_t *ctx) {
    if (!ctx) return;
    ctx->running = false;
}

void dht_context_free(dht_context_t *ctx) {
    if (!ctx) return;
    if (ctx->started) {
        /* Close the Nodus singleton connection.
         * Safe to call multiple times (idempotent). */
        nodus_singleton_close();
    }
    free(ctx);
}

bool dht_context_is_ready(dht_context_t *ctx) {
    (void)ctx;
    return nodus_singleton_is_ready();
}

bool dht_context_is_running(dht_context_t *ctx) {
    if (!ctx) return false;
    return ctx->running;
}

size_t dht_context_get_node_count(dht_context_t *ctx) {
    (void)ctx;
    return nodus_singleton_is_ready() ? 3 : 0;  /* 3-node cluster */
}

bool dht_context_wait_for_ready(dht_context_t *ctx, int timeout_ms) {
    (void)ctx;
    int elapsed = 0;
    while (!nodus_singleton_is_ready() && elapsed < timeout_ms) {
        nodus_singleton_poll(100);
        elapsed += 100;
    }
    return nodus_singleton_is_ready();
}

void dht_context_set_status_callback(dht_context_t *ctx,
                                      dht_status_callback_t callback,
                                      void *user_data) {
    if (!ctx) return;
    ctx->status_cb = callback;
    ctx->status_cb_data = user_data;
}

/* ── Put operations ─────────────────────────────────────────────── */

int dht_put(dht_context_t *ctx, const uint8_t *key, size_t key_len,
            const uint8_t *value, size_t value_len) {
    (void)ctx;
    return do_put(key, key_len, value, value_len,
                  NODUS_VALUE_EPHEMERAL, NODUS_DEFAULT_TTL, 0, 0);
}

int dht_put_ttl(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                const uint8_t *value, size_t value_len,
                unsigned int ttl_seconds) {
    (void)ctx;
    nodus_value_type_t type = (ttl_seconds == UINT32_MAX)
        ? NODUS_VALUE_PERMANENT : NODUS_VALUE_EPHEMERAL;
    uint32_t ttl = (ttl_seconds == UINT32_MAX) ? 0 : (uint32_t)ttl_seconds;
    return do_put(key, key_len, value, value_len, type, ttl, 0, 0);
}

int dht_put_permanent(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                      const uint8_t *value, size_t value_len) {
    (void)ctx;
    return do_put(key, key_len, value, value_len,
                  NODUS_VALUE_PERMANENT, 0, 0, 0);
}

int dht_put_signed(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                   const uint8_t *value, size_t value_len,
                   uint64_t value_id, unsigned int ttl_seconds,
                   const char *caller) {
    (void)ctx; (void)caller;
    nodus_value_type_t type = (ttl_seconds == 0 || ttl_seconds == UINT32_MAX)
        ? NODUS_VALUE_PERMANENT : NODUS_VALUE_EPHEMERAL;
    uint32_t ttl = (ttl_seconds == UINT32_MAX) ? 0 : (uint32_t)ttl_seconds;
    return do_put(key, key_len, value, value_len, type, ttl, value_id, 0);
}

int dht_put_signed_sync(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                        const uint8_t *value, size_t value_len,
                        uint64_t value_id, unsigned int ttl_seconds,
                        const char *caller, int timeout_ms) {
    (void)timeout_ms;
    /* Nodus client PUT is already synchronous */
    return dht_put_signed(ctx, key, key_len, value, value_len,
                          value_id, ttl_seconds, caller);
}

int dht_put_signed_permanent(dht_context_t *ctx,
                              const uint8_t *key, size_t key_len,
                              const uint8_t *value, size_t value_len,
                              uint64_t value_id, const char *caller) {
    (void)ctx; (void)caller;
    return do_put(key, key_len, value, value_len,
                  NODUS_VALUE_PERMANENT, 0, value_id, 0);
}

int dht_republish_packed(dht_context_t *ctx, const char *key_hex,
                         const uint8_t *packed_data, size_t packed_len) {
    /* Republish packed data is deprecated in v5.
     * Best-effort: store the packed data as-is. */
    (void)ctx;
    nodus_key_t k;
    hash_str_key(key_hex, &k);
    return do_put_hashed(&k, packed_data, packed_len,
                         NODUS_VALUE_PERMANENT, 0, 0, 0);
}

/* ── Get operations ─────────────────────────────────────────────── */

int dht_get(dht_context_t *ctx, const uint8_t *key, size_t key_len,
            uint8_t **value_out, size_t *value_len_out) {
    (void)ctx;
    if (!value_out || !value_len_out) return -1;
    *value_out = NULL;
    *value_len_out = 0;

    nodus_client_t *c = nodus_singleton_get();
    if (!c || !nodus_client_is_ready(c)) return -1;

    nodus_key_t k;
    hash_key(key, key_len, &k);

    nodus_value_t *val = NULL;
    nodus_singleton_lock();
    int rc = nodus_client_get(c, &k, &val);
    nodus_singleton_unlock();
    if (rc != 0 || !val) return -1;

    /* Copy data to caller-owned buffer */
    *value_out = malloc(val->data_len);
    if (!*value_out) { nodus_value_free(val); return -1; }
    memcpy(*value_out, val->data, val->data_len);
    *value_len_out = val->data_len;
    nodus_value_free(val);
    return 0;
}

void dht_get_async(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                   void (*callback)(uint8_t *value, size_t value_len,
                                    void *userdata),
                   void *userdata) {
    /* Nodus v5 doesn't have async get — do synchronous and call callback */
    uint8_t *val = NULL;
    size_t vlen = 0;
    dht_get(ctx, key, key_len, &val, &vlen);
    if (callback) callback(val, vlen, userdata);
}

int dht_get_all(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                uint8_t ***values_out, size_t **values_len_out,
                size_t *count_out) {
    (void)ctx;
    if (!values_out || !values_len_out || !count_out) return -1;
    *values_out = NULL;
    *values_len_out = NULL;
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

    /* Convert to caller format */
    *values_out = calloc(count, sizeof(uint8_t *));
    *values_len_out = calloc(count, sizeof(size_t));
    if (!*values_out || !*values_len_out) {
        free(*values_out); free(*values_len_out);
        *values_out = NULL; *values_len_out = NULL;
        for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
        free(vals);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        (*values_out)[i] = malloc(vals[i]->data_len);
        if ((*values_out)[i]) {
            memcpy((*values_out)[i], vals[i]->data, vals[i]->data_len);
            (*values_len_out)[i] = vals[i]->data_len;
        }
        nodus_value_free(vals[i]);
    }
    free(vals);
    *count_out = count;
    return 0;
}

int dht_get_all_with_ids(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                         uint8_t ***values_out, size_t **values_len_out,
                         uint64_t **value_ids_out, size_t *count_out) {
    (void)ctx;
    if (!value_ids_out) return -1;

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
    *values_len_out = calloc(count, sizeof(size_t));
    *value_ids_out = calloc(count, sizeof(uint64_t));
    if (!*values_out || !*values_len_out || !*value_ids_out) {
        free(*values_out); free(*values_len_out); free(*value_ids_out);
        for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
        free(vals);
        return -1;
    }

    for (size_t i = 0; i < count; i++) {
        (*values_out)[i] = malloc(vals[i]->data_len);
        if ((*values_out)[i]) {
            memcpy((*values_out)[i], vals[i]->data, vals[i]->data_len);
            (*values_len_out)[i] = vals[i]->data_len;
        }
        (*value_ids_out)[i] = vals[i]->value_id;
        nodus_value_free(vals[i]);
    }
    free(vals);
    *count_out = count;
    return 0;
}

/* ── Batch operations ───────────────────────────────────────────── */

void dht_get_batch(dht_context_t *ctx,
                   const uint8_t **keys, const size_t *key_lens,
                   size_t count,
                   dht_batch_callback_t callback, void *userdata) {
    /* Sequential implementation — Nodus v5 doesn't have batch GET yet */
    dht_batch_result_t *results = calloc(count, sizeof(dht_batch_result_t));
    if (!results) { if (callback) callback(NULL, 0, userdata); return; }

    for (size_t i = 0; i < count; i++) {
        results[i].key = keys[i];
        results[i].key_len = key_lens[i];
        int rc = dht_get(ctx, keys[i], key_lens[i],
                         &results[i].value, &results[i].value_len);
        results[i].found = (rc == 0 && results[i].value != NULL) ? 1 : 0;
    }

    if (callback) callback(results, count, userdata);
    /* Note: callback is responsible for the results in async API */
}

int dht_get_batch_sync(dht_context_t *ctx,
                       const uint8_t **keys, const size_t *key_lens,
                       size_t count,
                       dht_batch_result_t **results_out) {
    if (!results_out) return -1;
    *results_out = calloc(count, sizeof(dht_batch_result_t));
    if (!*results_out) return -1;

    for (size_t i = 0; i < count; i++) {
        (*results_out)[i].key = keys[i];
        (*results_out)[i].key_len = key_lens[i];
        int rc = dht_get(ctx, keys[i], key_lens[i],
                         &(*results_out)[i].value,
                         &(*results_out)[i].value_len);
        (*results_out)[i].found = (rc == 0 && (*results_out)[i].value != NULL) ? 1 : 0;
    }
    return 0;
}

void dht_batch_results_free(dht_batch_result_t *results, size_t count) {
    if (!results) return;
    for (size_t i = 0; i < count; i++)
        free(results[i].value);
    free(results);
}

/* ── Identity & node management ─────────────────────────────────── */

int dht_get_node_id(dht_context_t *ctx, char *node_id_out) {
    (void)ctx;
    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id || !node_id_out) return -1;
    memcpy(node_id_out, id->fingerprint, NODUS_KEY_HEX_LEN);
    return 0;
}

int dht_get_owner_value_id(dht_context_t *ctx, uint64_t *value_id_out) {
    (void)ctx;
    const nodus_identity_t *id = nodus_singleton_identity();
    if (!id || !value_id_out) return -1;
    *value_id_out = nodus_identity_value_id(id);
    return 0;
}

int dht_context_bootstrap_runtime(dht_context_t *ctx,
                                   const char *ip, uint16_t port) {
    (void)ctx; (void)ip; (void)port;
    /* Not applicable in Nodus v5 — server connections are configured at init */
    return 0;
}

int dht_context_export_routing_table(dht_context_t *ctx, const char *file_path) {
    (void)ctx; (void)file_path;
    /* Not applicable — Nodus v5 uses server-side Kademlia */
    return 0;
}

int dht_context_import_routing_table(dht_context_t *ctx, const char *file_path) {
    (void)ctx; (void)file_path;
    return 0;
}

/* ── Listen operations ──────────────────────────────────────────── */

size_t dht_listen(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                  dht_listen_callback_t callback, void *user_data) {
    return dht_listen_ex(ctx, key, key_len, callback, user_data, NULL);
}

size_t dht_listen_ex(dht_context_t *ctx, const uint8_t *key, size_t key_len,
                     dht_listen_callback_t callback, void *user_data,
                     dht_listen_cleanup_t cleanup) {
    (void)ctx;
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
    for (int i = 0; i < MAX_COMPAT_LISTENERS; i++) {
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

void dht_cancel_listen(dht_context_t *ctx, size_t token) {
    (void)ctx;
    for (int i = 0; i < MAX_COMPAT_LISTENERS; i++) {
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

size_t dht_get_active_listen_count(dht_context_t *ctx) {
    (void)ctx;
    size_t count = 0;
    for (int i = 0; i < MAX_COMPAT_LISTENERS; i++)
        if (g_listeners[i].active) count++;
    return count;
}

void dht_cancel_all_listeners(dht_context_t *ctx) {
    for (int i = 0; i < MAX_COMPAT_LISTENERS; i++) {
        if (g_listeners[i].active) {
            dht_cancel_listen(ctx, g_listeners[i].token);
        }
    }
}

void dht_suspend_all_listeners(dht_context_t *ctx) {
    (void)ctx;
    /* In Nodus v5, the client handles auto-reconnect + resubscribe */
}

size_t dht_resubscribe_all_listeners(dht_context_t *ctx) {
    (void)ctx;
    /* Auto-handled by Nodus client reconnect logic */
    return dht_get_active_listen_count(ctx);
}

bool dht_is_listener_active(size_t token) {
    for (int i = 0; i < MAX_COMPAT_LISTENERS; i++) {
        if (g_listeners[i].token == token)
            return g_listeners[i].active;
    }
    return false;
}

void dht_get_listener_stats(size_t *total, size_t *active, size_t *suspended) {
    size_t t = 0, a = 0;
    for (int i = 0; i < MAX_COMPAT_LISTENERS; i++) {
        if (g_listeners[i].token > 0) t++;
        if (g_listeners[i].active) a++;
    }
    if (total) *total = t;
    if (active) *active = a;
    if (suspended) *suspended = 0;
}

/* ── Stats ──────────────────────────────────────────────────────── */

int dht_get_stats(dht_context_t *ctx, size_t *node_count,
                  size_t *stored_values) {
    (void)ctx;
    if (node_count) *node_count = nodus_singleton_is_ready() ? 3 : 0;
    if (stored_values) *stored_values = 0;
    return 0;
}

/* ── DHT Identity ───────────────────────────────────────────────── */

int dht_identity_generate_dilithium5(dht_identity_t **identity_out) {
    if (!identity_out) return -1;
    dht_identity_t *id = calloc(1, sizeof(dht_identity_t));
    if (!id) return -1;
    if (nodus_identity_generate(&id->nid) != 0) {
        free(id);
        return -1;
    }
    *identity_out = id;
    return 0;
}

int dht_identity_generate_from_seed(const uint8_t *seed,
                                     dht_identity_t **identity_out) {
    if (!seed || !identity_out) return -1;
    dht_identity_t *id = calloc(1, sizeof(dht_identity_t));
    if (!id) return -1;
    if (nodus_identity_from_seed(seed, &id->nid) != 0) {
        free(id);
        return -1;
    }
    *identity_out = id;
    return 0;
}

int dht_identity_export_to_buffer(dht_identity_t *identity,
                                   uint8_t **buffer_out,
                                   size_t *buffer_size_out) {
    if (!identity || !buffer_out || !buffer_size_out) return -1;
    /* Export as: pk(2592) + sk(4896) = 7488 bytes */
    size_t total = NODUS_PK_BYTES + NODUS_SK_BYTES;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;
    memcpy(buf, identity->nid.pk.bytes, NODUS_PK_BYTES);
    memcpy(buf + NODUS_PK_BYTES, identity->nid.sk.bytes, NODUS_SK_BYTES);
    *buffer_out = buf;
    *buffer_size_out = total;
    return 0;
}

int dht_identity_import_from_buffer(const uint8_t *buffer, size_t buffer_size,
                                     dht_identity_t **identity_out) {
    if (!buffer || !identity_out) return -1;
    size_t total = NODUS_PK_BYTES + NODUS_SK_BYTES;
    if (buffer_size != total) return -1;  /* Exact match: reject old formats */

    dht_identity_t *id = calloc(1, sizeof(dht_identity_t));
    if (!id) return -1;
    memcpy(id->nid.pk.bytes, buffer, NODUS_PK_BYTES);
    memcpy(id->nid.sk.bytes, buffer + NODUS_PK_BYTES, NODUS_SK_BYTES);
    /* Derive node_id and fingerprint */
    nodus_fingerprint(&id->nid.pk, &id->nid.node_id);
    nodus_fingerprint_hex(&id->nid.pk, id->nid.fingerprint);
    *identity_out = id;
    return 0;
}

void dht_identity_free(dht_identity_t *identity) {
    if (!identity) return;
    nodus_identity_clear(&identity->nid);
    free(identity);
}

/* ── Chunked API ────────────────────────────────────────────────── */

int dht_chunked_publish(dht_context_t *ctx, const char *base_key,
                        const uint8_t *data, size_t data_len,
                        uint32_t ttl_seconds) {
    (void)ctx;
    if (!base_key || !data) return DHT_CHUNK_ERR_NULL_PARAM;
    if (!nodus_singleton_is_ready()) return DHT_CHUNK_ERR_NOT_CONNECTED;

    nodus_key_t k;
    hash_str_key(base_key, &k);

    const nodus_identity_t *id = nodus_singleton_identity();
    uint64_t vid = nodus_identity_value_id(id);

    nodus_value_type_t type = (ttl_seconds >= DHT_CHUNK_TTL_PERMANENT)
        ? NODUS_VALUE_PERMANENT : NODUS_VALUE_EPHEMERAL;
    uint32_t ttl = (type == NODUS_VALUE_PERMANENT) ? 0 : ttl_seconds;

    int rc = do_put_hashed(&k, data, data_len, type, ttl, vid, 0);
    return (rc == 0) ? DHT_CHUNK_OK : DHT_CHUNK_ERR_DHT_PUT;
}

int dht_chunked_fetch(dht_context_t *ctx, const char *base_key,
                      uint8_t **data_out, size_t *data_len_out) {
    (void)ctx;
    if (!base_key || !data_out || !data_len_out) return DHT_CHUNK_ERR_NULL_PARAM;
    if (!nodus_singleton_is_ready()) return DHT_CHUNK_ERR_NOT_CONNECTED;
    *data_out = NULL;
    *data_len_out = 0;

    nodus_client_t *c = nodus_singleton_get();
    nodus_key_t k;
    hash_str_key(base_key, &k);

    nodus_value_t *val = NULL;
    nodus_singleton_lock();
    int rc = nodus_client_get(c, &k, &val);
    nodus_singleton_unlock();
    if (rc != 0 || !val) return DHT_CHUNK_ERR_DHT_GET;

    *data_out = malloc(val->data_len);
    if (!*data_out) { nodus_value_free(val); return DHT_CHUNK_ERR_ALLOC; }
    memcpy(*data_out, val->data, val->data_len);
    *data_len_out = val->data_len;
    nodus_value_free(val);
    return DHT_CHUNK_OK;
}

int dht_chunked_fetch_mine(dht_context_t *ctx, const char *base_key,
                           uint8_t **data_out, size_t *data_len_out) {
    /* In Nodus v5, GET returns our own value by default.
     * For multi-writer keys, we'd need to filter by owner_fp.
     * For now, just use regular fetch. */
    return dht_chunked_fetch(ctx, base_key, data_out, data_len_out);
}

int dht_chunked_fetch_all(dht_context_t *ctx, const char *base_key,
                          uint8_t ***values_out, size_t **lens_out,
                          size_t *count_out) {
    (void)ctx;
    if (!base_key || !values_out || !lens_out || !count_out)
        return DHT_CHUNK_ERR_NULL_PARAM;
    if (!nodus_singleton_is_ready()) return DHT_CHUNK_ERR_NOT_CONNECTED;
    *values_out = NULL;
    *lens_out = NULL;
    *count_out = 0;

    nodus_client_t *c = nodus_singleton_get();
    nodus_key_t k;
    hash_str_key(base_key, &k);

    nodus_value_t **vals = NULL;
    size_t count = 0;
    nodus_singleton_lock();
    int rc = nodus_client_get_all(c, &k, &vals, &count);
    nodus_singleton_unlock();
    if (rc != 0) return DHT_CHUNK_ERR_DHT_GET;
    if (count == 0) return DHT_CHUNK_OK;

    *values_out = calloc(count, sizeof(uint8_t *));
    *lens_out = calloc(count, sizeof(size_t));
    if (!*values_out || !*lens_out) {
        free(*values_out); free(*lens_out);
        for (size_t i = 0; i < count; i++) nodus_value_free(vals[i]);
        free(vals);
        return DHT_CHUNK_ERR_ALLOC;
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
    return DHT_CHUNK_OK;
}

int dht_chunked_delete(dht_context_t *ctx, const char *base_key,
                       uint32_t known_chunk_count) {
    (void)known_chunk_count;
    /* Publish empty data to overwrite */
    uint8_t empty = 0;
    return dht_chunked_publish(ctx, base_key, &empty, 0, 60);
}

const char *dht_chunked_strerror(int error) {
    switch (error) {
    case DHT_CHUNK_OK:                return "success";
    case DHT_CHUNK_ERR_NULL_PARAM:    return "null parameter";
    case DHT_CHUNK_ERR_COMPRESS:      return "compression failed";
    case DHT_CHUNK_ERR_DECOMPRESS:    return "decompression failed";
    case DHT_CHUNK_ERR_DHT_PUT:       return "DHT put failed";
    case DHT_CHUNK_ERR_DHT_GET:       return "DHT get failed";
    case DHT_CHUNK_ERR_INVALID_FORMAT: return "invalid chunk format";
    case DHT_CHUNK_ERR_CHECKSUM:      return "checksum mismatch";
    case DHT_CHUNK_ERR_INCOMPLETE:    return "missing chunks";
    case DHT_CHUNK_ERR_TIMEOUT:       return "fetch timeout";
    case DHT_CHUNK_ERR_ALLOC:         return "memory allocation failed";
    case DHT_CHUNK_ERR_NOT_CONNECTED: return "not connected";
    case DHT_CHUNK_ERR_HASH_MISMATCH: return "hash mismatch";
    default:                          return "unknown error";
    }
}

int dht_chunked_make_key(const char *base_key, uint32_t chunk_index,
                         uint8_t key_out[DHT_CHUNK_KEY_SIZE]) {
    if (!base_key || !key_out) return -1;
    /* Generate key compatible with old format */
    char buf[512];
    int len = snprintf(buf, sizeof(buf), "%s:chunk:%u", base_key, chunk_index);
    nodus_key_t full;
    nodus_hash((const uint8_t *)buf, (size_t)len, &full);
    memcpy(key_out, full.bytes, DHT_CHUNK_KEY_SIZE);
    return 0;
}

uint32_t dht_chunked_estimate_chunks(size_t data_len) {
    /* With Nodus v5, everything fits in one "chunk" (up to 1MB value) */
    (void)data_len;
    return 1;
}

int dht_chunked_fetch_metadata(dht_context_t *ctx, const char *base_key,
                               uint8_t hash_out[DHT_CHUNK_HASH_SIZE],
                               uint32_t *original_size_out,
                               uint32_t *total_chunks_out,
                               bool *is_v2_out) {
    (void)ctx;
    if (!base_key) return DHT_CHUNK_ERR_NULL_PARAM;

    /* Fetch the actual data to get size/hash */
    uint8_t *data = NULL;
    size_t data_len = 0;
    int rc = dht_chunked_fetch(NULL, base_key, &data, &data_len);
    if (rc != DHT_CHUNK_OK) return rc;

    if (hash_out) {
        nodus_key_t h;
        nodus_hash(data, data_len, &h);
        memcpy(hash_out, h.bytes, DHT_CHUNK_HASH_SIZE);
    }
    if (original_size_out) *original_size_out = (uint32_t)data_len;
    if (total_chunks_out) *total_chunks_out = 1;
    if (is_v2_out) *is_v2_out = true;

    free(data);
    return DHT_CHUNK_OK;
}

int dht_chunked_fetch_batch(dht_context_t *ctx, const char **base_keys,
                            size_t key_count,
                            dht_chunked_batch_result_t **results_out) {
    (void)ctx;
    if (!base_keys || !results_out) return -1;

    *results_out = calloc(key_count, sizeof(dht_chunked_batch_result_t));
    if (!*results_out) return -1;

    int success = 0;
    for (size_t i = 0; i < key_count; i++) {
        (*results_out)[i].base_key = base_keys[i];
        (*results_out)[i].error = dht_chunked_fetch(
            NULL, base_keys[i],
            &(*results_out)[i].data,
            &(*results_out)[i].data_len
        );
        if ((*results_out)[i].error == DHT_CHUNK_OK) success++;
    }
    return success;
}

void dht_chunked_batch_results_free(dht_chunked_batch_result_t *results,
                                    size_t count) {
    if (!results) return;
    for (size_t i = 0; i < count; i++)
        free(results[i].data);
    free(results);
}
