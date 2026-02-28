/**
 * Nodus v5 — Compatibility Shim
 *
 * Maps legacy dht_* and dht_chunked_* APIs to Nodus v5 client calls.
 * Allows existing messenger engine code to compile without source changes.
 *
 * Key differences from the old API:
 * - No chunking needed (Nodus TCP frames up to 4MB, values up to 1MB)
 * - No ZSTD compression (handled at transport level if needed)
 * - All operations go through the Nodus singleton client
 * - Listen uses Nodus LISTEN/value_changed push notifications
 *
 * @file nodus_compat.h
 */

#ifndef NODUS_COMPAT_H
#define NODUS_COMPAT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── DHT Config (compatible with old dht_config_t) ──────────────── */

typedef struct {
    uint16_t port;
    bool is_bootstrap;
    char identity[256];
    char bootstrap_nodes[5][256];
    size_t bootstrap_count;
    char persistence_path[512];
} dht_config_t;

/* ── Opaque types ───────────────────────────────────────────────── */

typedef struct dht_context dht_context_t;
typedef struct dht_identity dht_identity_t;

/* ── Listen callback ────────────────────────────────────────────── */

typedef bool (*dht_listen_callback_t)(
    const uint8_t *value,
    size_t value_len,
    bool expired,
    void *user_data
);

typedef void (*dht_listen_cleanup_t)(void *user_data);

/* ── Status callback ────────────────────────────────────────────── */

typedef void (*dht_status_callback_t)(bool is_connected, void *user_data);

/* ── Batch results ──────────────────────────────────────────────── */

typedef struct {
    const uint8_t *key;
    size_t key_len;
    uint8_t *value;
    size_t value_len;
    int found;
} dht_batch_result_t;

typedef void (*dht_batch_callback_t)(
    dht_batch_result_t *results,
    size_t count,
    void *userdata
);

/* ── Chunked error codes ────────────────────────────────────────── */

#define DHT_CHUNK_OK                 0
#define DHT_CHUNK_ERR_NULL_PARAM    -1
#define DHT_CHUNK_ERR_COMPRESS      -2
#define DHT_CHUNK_ERR_DECOMPRESS    -3
#define DHT_CHUNK_ERR_DHT_PUT       -4
#define DHT_CHUNK_ERR_DHT_GET       -5
#define DHT_CHUNK_ERR_INVALID_FORMAT -6
#define DHT_CHUNK_ERR_CHECKSUM      -7
#define DHT_CHUNK_ERR_INCOMPLETE    -8
#define DHT_CHUNK_ERR_TIMEOUT       -9
#define DHT_CHUNK_ERR_ALLOC        -10
#define DHT_CHUNK_ERR_NOT_CONNECTED -11
#define DHT_CHUNK_ERR_HASH_MISMATCH -12

/* ── Chunked TTL presets ────────────────────────────────────────── */

#define DHT_CHUNK_TTL_7DAY       (7 * 24 * 3600)
#define DHT_CHUNK_TTL_30DAY      (30 * 24 * 3600)
#define DHT_CHUNK_TTL_365DAY     (365 * 24 * 3600)
#define DHT_CHUNK_TTL_PERMANENT  UINT32_MAX

/* ── Chunked constants ──────────────────────────────────────────── */

#define DHT_CHUNK_KEY_SIZE  32
#define DHT_CHUNK_HASH_SIZE 32

/* ── Chunked batch result ───────────────────────────────────────── */

typedef struct {
    const char *base_key;
    uint8_t *data;
    size_t data_len;
    int error;
} dht_chunked_batch_result_t;

/* ── DHT Context lifecycle ──────────────────────────────────────── */

dht_context_t* dht_context_new(const dht_config_t *config);
int dht_context_start(dht_context_t *ctx);
int dht_context_start_with_identity(dht_context_t *ctx, dht_identity_t *identity);
void dht_context_stop(dht_context_t *ctx);
void dht_context_free(dht_context_t *ctx);

/* ── Status ─────────────────────────────────────────────────────── */

bool dht_context_is_ready(dht_context_t *ctx);
bool dht_context_is_running(dht_context_t *ctx);
size_t dht_context_get_node_count(dht_context_t *ctx);
bool dht_context_wait_for_ready(dht_context_t *ctx, int timeout_ms);
void dht_context_set_status_callback(dht_context_t *ctx,
                                      dht_status_callback_t callback,
                                      void *user_data);

/* ── Put operations ─────────────────────────────────────────────── */

int dht_put(dht_context_t *ctx,
            const uint8_t *key, size_t key_len,
            const uint8_t *value, size_t value_len);

int dht_put_ttl(dht_context_t *ctx,
                const uint8_t *key, size_t key_len,
                const uint8_t *value, size_t value_len,
                unsigned int ttl_seconds);

int dht_put_permanent(dht_context_t *ctx,
                      const uint8_t *key, size_t key_len,
                      const uint8_t *value, size_t value_len);

int dht_put_signed(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   const uint8_t *value, size_t value_len,
                   uint64_t value_id,
                   unsigned int ttl_seconds,
                   const char *caller);

int dht_put_signed_sync(dht_context_t *ctx,
                        const uint8_t *key, size_t key_len,
                        const uint8_t *value, size_t value_len,
                        uint64_t value_id,
                        unsigned int ttl_seconds,
                        const char *caller,
                        int timeout_ms);

int dht_put_signed_permanent(dht_context_t *ctx,
                              const uint8_t *key, size_t key_len,
                              const uint8_t *value, size_t value_len,
                              uint64_t value_id,
                              const char *caller);

int dht_republish_packed(dht_context_t *ctx,
                         const char *key_hex,
                         const uint8_t *packed_data,
                         size_t packed_len);

/* ── Get operations ─────────────────────────────────────────────── */

int dht_get(dht_context_t *ctx,
            const uint8_t *key, size_t key_len,
            uint8_t **value_out, size_t *value_len_out);

void dht_get_async(dht_context_t *ctx,
                   const uint8_t *key, size_t key_len,
                   void (*callback)(uint8_t *value, size_t value_len,
                                    void *userdata),
                   void *userdata);

int dht_get_all(dht_context_t *ctx,
                const uint8_t *key, size_t key_len,
                uint8_t ***values_out, size_t **values_len_out,
                size_t *count_out);

int dht_get_all_with_ids(dht_context_t *ctx,
                         const uint8_t *key, size_t key_len,
                         uint8_t ***values_out, size_t **values_len_out,
                         uint64_t **value_ids_out,
                         size_t *count_out);

/* ── Batch operations ───────────────────────────────────────────── */

void dht_get_batch(dht_context_t *ctx,
                   const uint8_t **keys, const size_t *key_lens,
                   size_t count,
                   dht_batch_callback_t callback, void *userdata);

int dht_get_batch_sync(dht_context_t *ctx,
                       const uint8_t **keys, const size_t *key_lens,
                       size_t count,
                       dht_batch_result_t **results_out);

void dht_batch_results_free(dht_batch_result_t *results, size_t count);

/* ── Identity & node management ─────────────────────────────────── */

int dht_get_node_id(dht_context_t *ctx, char *node_id_out);
int dht_get_owner_value_id(dht_context_t *ctx, uint64_t *value_id_out);
int dht_context_bootstrap_runtime(dht_context_t *ctx,
                                   const char *ip, uint16_t port);

/* ── Routing table ──────────────────────────────────────────────── */

int dht_context_export_routing_table(dht_context_t *ctx, const char *file_path);
int dht_context_import_routing_table(dht_context_t *ctx, const char *file_path);

/* ── Listen operations ──────────────────────────────────────────── */

size_t dht_listen(dht_context_t *ctx,
                  const uint8_t *key, size_t key_len,
                  dht_listen_callback_t callback, void *user_data);

size_t dht_listen_ex(dht_context_t *ctx,
                     const uint8_t *key, size_t key_len,
                     dht_listen_callback_t callback, void *user_data,
                     dht_listen_cleanup_t cleanup);

void dht_cancel_listen(dht_context_t *ctx, size_t token);
size_t dht_get_active_listen_count(dht_context_t *ctx);
void dht_cancel_all_listeners(dht_context_t *ctx);
void dht_suspend_all_listeners(dht_context_t *ctx);
size_t dht_resubscribe_all_listeners(dht_context_t *ctx);
bool dht_is_listener_active(size_t token);
void dht_get_listener_stats(size_t *total, size_t *active, size_t *suspended);

/* ── Stats ──────────────────────────────────────────────────────── */

int dht_get_stats(dht_context_t *ctx, size_t *node_count, size_t *stored_values);

/* ── DHT Identity ───────────────────────────────────────────────── */

int dht_identity_generate_dilithium5(dht_identity_t **identity_out);
int dht_identity_generate_from_seed(const uint8_t *seed,
                                     dht_identity_t **identity_out);
int dht_identity_export_to_buffer(dht_identity_t *identity,
                                   uint8_t **buffer_out, size_t *buffer_size_out);
int dht_identity_import_from_buffer(const uint8_t *buffer, size_t buffer_size,
                                     dht_identity_t **identity_out);
void dht_identity_free(dht_identity_t *identity);

/* ── Chunked API (no chunking in v5 — direct put/get) ───────────── */

int dht_chunked_publish(dht_context_t *ctx,
                        const char *base_key,
                        const uint8_t *data, size_t data_len,
                        uint32_t ttl_seconds);

int dht_chunked_fetch(dht_context_t *ctx,
                      const char *base_key,
                      uint8_t **data_out, size_t *data_len_out);

int dht_chunked_fetch_mine(dht_context_t *ctx,
                           const char *base_key,
                           uint8_t **data_out, size_t *data_len_out);

int dht_chunked_fetch_all(dht_context_t *ctx,
                          const char *base_key,
                          uint8_t ***values_out, size_t **lens_out,
                          size_t *count_out);

int dht_chunked_delete(dht_context_t *ctx,
                       const char *base_key,
                       uint32_t known_chunk_count);

const char *dht_chunked_strerror(int error);

int dht_chunked_make_key(const char *base_key,
                         uint32_t chunk_index,
                         uint8_t key_out[DHT_CHUNK_KEY_SIZE]);

uint32_t dht_chunked_estimate_chunks(size_t data_len);

int dht_chunked_fetch_metadata(dht_context_t *ctx,
                               const char *base_key,
                               uint8_t hash_out[DHT_CHUNK_HASH_SIZE],
                               uint32_t *original_size_out,
                               uint32_t *total_chunks_out,
                               bool *is_v2_out);

int dht_chunked_fetch_batch(dht_context_t *ctx,
                            const char **base_keys, size_t key_count,
                            dht_chunked_batch_result_t **results_out);

void dht_chunked_batch_results_free(dht_chunked_batch_result_t *results,
                                    size_t count);

#ifdef __cplusplus
}
#endif

#endif /* NODUS_COMPAT_H */
