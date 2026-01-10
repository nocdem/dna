/**
 * @file dht_chunked.c
 * @brief Generic DHT Chunked Storage Layer Implementation
 *
 * Part of DNA Messenger
 *
 * @date 2025-11-27
 */

#include "dht_chunked.h"
#include "../../crypto/utils/qgp_sha3.h"
#include <zstd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <zlib.h>  // For crc32

#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DHT_CHUNK"
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>  // For Sleep()
#define chunk_sleep_ms(ms) Sleep(ms)
#else
#include <arpa/inet.h>
#include <unistd.h>   // For usleep()
#define chunk_sleep_ms(ms) usleep((ms) * 1000)
#endif

/*============================================================================
 * Internal Constants
 *============================================================================*/

/** Timeout for parallel fetch in milliseconds (10s - reduced from 30s for mobile UX) */
#define DHT_CHUNK_FETCH_TIMEOUT_MS  10000

/** Maximum parallel fetches at once */
#define DHT_CHUNK_MAX_PARALLEL      64

/** Maximum retry attempts for failed chunks (handles DHT propagation delays) */
#define DHT_CHUNK_MAX_RETRIES       3

/** Delay between retry attempts in milliseconds */
#define DHT_CHUNK_RETRY_DELAY_MS    500

/*============================================================================
 * Internal Structures
 *============================================================================*/

/**
 * Chunk header structure (internal representation)
 */
typedef struct {
    uint32_t magic;           // DHT_CHUNK_MAGIC
    uint8_t  version;         // DHT_CHUNK_VERSION
    uint32_t total_chunks;    // Total number of chunks
    uint32_t chunk_index;     // This chunk's index (0-based)
    uint32_t chunk_data_size; // Size of payload in this chunk
    uint32_t original_size;   // Uncompressed total size (only chunk0)
    uint32_t checksum;        // CRC32 of chunk payload
} dht_chunk_header_t;

/**
 * Parallel fetch context for a single chunk
 */
typedef struct {
    uint8_t *data;           // Fetched data (NULL if not received)
    size_t   data_len;       // Length of fetched data
    bool     received;       // True if data received
    bool     error;          // True if error occurred
} parallel_chunk_slot_t;

/**
 * Parallel fetch context (shared across all callbacks)
 */
typedef struct {
    parallel_chunk_slot_t *slots;  // Array of chunk slots
    uint32_t total_chunks;         // Total chunks expected
    atomic_uint completed;         // Number completed (success or error)
    pthread_mutex_t mutex;         // Mutex for condition variable
    pthread_cond_t cond;           // Condition variable for waiting
} parallel_fetch_ctx_t;

/**
 * Callback context for a single async fetch
 */
typedef struct {
    parallel_fetch_ctx_t *ctx;     // Shared parallel context
    uint32_t chunk_index;          // Which chunk this is for
} async_fetch_info_t;

/*============================================================================
 * Internal Helper Functions
 *============================================================================*/

/**
 * Compute CRC32 checksum
 */
static uint32_t compute_crc32(const uint8_t *data, size_t len) {
    return (uint32_t)crc32(0L, data, (uInt)len);
}

/**
 * Compress data with ZSTD (max level)
 *
 * @param in Input data
 * @param in_len Input length
 * @param out Output buffer (allocated by function)
 * @param out_len Output length
 * @return 0 on success, -1 on error
 */
static int compress_data(const uint8_t *in, size_t in_len,
                         uint8_t **out, size_t *out_len) {
    if (!in || !out || !out_len) return -1;

    size_t bound = ZSTD_compressBound(in_len);
    uint8_t *buf = (uint8_t *)malloc(bound);
    if (!buf) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate compression buffer\n");
        return -1;
    }

    // Use maximum compression level
    int level = ZSTD_maxCLevel();
    size_t compressed_size = ZSTD_compress(buf, bound, in, in_len, level);

    if (ZSTD_isError(compressed_size)) {
        QGP_LOG_ERROR(LOG_TAG, "ZSTD compression failed: %s\n",
                ZSTD_getErrorName(compressed_size));
        free(buf);
        return -1;
    }

    // Shrink buffer to actual size
    uint8_t *shrunk = (uint8_t *)realloc(buf, compressed_size);
    if (shrunk) {
        buf = shrunk;
    }

    *out = buf;
    *out_len = compressed_size;
    return 0;
}

/**
 * Decompress data with ZSTD
 *
 * @param in Compressed input data
 * @param in_len Input length
 * @param expected_size Expected decompressed size
 * @param out Output buffer (allocated by function)
 * @param out_len Actual decompressed length
 * @return 0 on success, -1 on error
 */
static int decompress_data(const uint8_t *in, size_t in_len,
                           size_t expected_size,
                           uint8_t **out, size_t *out_len) {
    if (!in || !out || !out_len) return -1;

    // Sanity check on expected size (100MB max)
    if (expected_size > 100 * 1024 * 1024) {
        QGP_LOG_ERROR(LOG_TAG, "Expected size too large: %zu\n", expected_size);
        return -1;
    }

    uint8_t *buf = (uint8_t *)malloc(expected_size);
    if (!buf) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate decompression buffer\n");
        return -1;
    }

    size_t decompressed_size = ZSTD_decompress(buf, expected_size, in, in_len);

    if (ZSTD_isError(decompressed_size)) {
        QGP_LOG_WARN(LOG_TAG, "ZSTD decompression failed (stale DHT data?): %s",
                ZSTD_getErrorName(decompressed_size));
        free(buf);
        return -1;
    }

    if (decompressed_size != expected_size) {
        QGP_LOG_ERROR(LOG_TAG, "Decompressed size mismatch: %zu != %zu\n",
                decompressed_size, expected_size);
        free(buf);
        return -1;
    }

    *out = buf;
    *out_len = decompressed_size;
    return 0;
}

/**
 * Serialize chunk header + data to binary format
 *
 * Format (25 bytes header):
 * [4B magic][1B version][4B total_chunks][4B chunk_index]
 * [4B chunk_data_size][4B original_size][4B checksum][payload...]
 *
 * @param header Chunk header
 * @param payload Chunk payload data
 * @param payload_len Payload length
 * @param out Output buffer (allocated by function)
 * @param out_len Output length
 * @return 0 on success, -1 on error
 */
static int serialize_chunk(const dht_chunk_header_t *header,
                           const uint8_t *payload, size_t payload_len,
                           uint8_t **out, size_t *out_len) {
    if (!header || !payload || !out || !out_len) return -1;

    size_t total_size = DHT_CHUNK_HEADER_SIZE + payload_len;
    uint8_t *buf = (uint8_t *)malloc(total_size);
    if (!buf) return -1;

    uint8_t *ptr = buf;

    // Magic (4 bytes, network byte order)
    uint32_t magic_net = htonl(header->magic);
    memcpy(ptr, &magic_net, 4);
    ptr += 4;

    // Version (1 byte)
    *ptr++ = header->version;

    // Total chunks (4 bytes, network byte order)
    uint32_t total_net = htonl(header->total_chunks);
    memcpy(ptr, &total_net, 4);
    ptr += 4;

    // Chunk index (4 bytes, network byte order)
    uint32_t index_net = htonl(header->chunk_index);
    memcpy(ptr, &index_net, 4);
    ptr += 4;

    // Chunk data size (4 bytes, network byte order)
    uint32_t size_net = htonl(header->chunk_data_size);
    memcpy(ptr, &size_net, 4);
    ptr += 4;

    // Original size (4 bytes, network byte order)
    uint32_t orig_net = htonl(header->original_size);
    memcpy(ptr, &orig_net, 4);
    ptr += 4;

    // Checksum (4 bytes, network byte order)
    uint32_t crc_net = htonl(header->checksum);
    memcpy(ptr, &crc_net, 4);
    ptr += 4;

    // Payload
    memcpy(ptr, payload, payload_len);

    *out = buf;
    *out_len = total_size;
    return 0;
}

/**
 * Deserialize chunk from binary format
 *
 * @param data Serialized chunk data
 * @param data_len Data length
 * @param header Output header structure
 * @param payload_out Output pointer to payload (points into data, no copy)
 * @return 0 on success, -1 on error
 */
static int deserialize_chunk(const uint8_t *data, size_t data_len,
                             dht_chunk_header_t *header,
                             const uint8_t **payload_out) {
    if (!data || !header || data_len < DHT_CHUNK_HEADER_SIZE) {
        return -1;
    }

    const uint8_t *ptr = data;

    // Magic
    uint32_t magic_net;
    memcpy(&magic_net, ptr, 4);
    header->magic = ntohl(magic_net);
    ptr += 4;

    if (header->magic != DHT_CHUNK_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X (expected 0x%08X)\n",
                header->magic, DHT_CHUNK_MAGIC);
        return -1;
    }

    // Version
    header->version = *ptr++;
    if (header->version != DHT_CHUNK_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid version: %u (expected %u)\n",
                header->version, DHT_CHUNK_VERSION);
        return -1;
    }

    // Total chunks
    uint32_t total_net;
    memcpy(&total_net, ptr, 4);
    header->total_chunks = ntohl(total_net);
    ptr += 4;

    // Chunk index
    uint32_t index_net;
    memcpy(&index_net, ptr, 4);
    header->chunk_index = ntohl(index_net);
    ptr += 4;

    // Chunk data size
    uint32_t size_net;
    memcpy(&size_net, ptr, 4);
    header->chunk_data_size = ntohl(size_net);
    ptr += 4;

    // Original size
    uint32_t orig_net;
    memcpy(&orig_net, ptr, 4);
    header->original_size = ntohl(orig_net);
    ptr += 4;

    // Checksum
    uint32_t crc_net;
    memcpy(&crc_net, ptr, 4);
    header->checksum = ntohl(crc_net);
    ptr += 4;

    // Validate payload size
    if (DHT_CHUNK_HEADER_SIZE + header->chunk_data_size > data_len) {
        QGP_LOG_ERROR(LOG_TAG, "Chunk size mismatch: %u + %u > %zu\n",
                DHT_CHUNK_HEADER_SIZE, header->chunk_data_size, data_len);
        return -1;
    }

    // Verify CRC32
    uint32_t computed_crc = compute_crc32(ptr, header->chunk_data_size);
    if (computed_crc != header->checksum) {
        QGP_LOG_ERROR(LOG_TAG, "CRC32 mismatch: 0x%08X != 0x%08X\n",
                computed_crc, header->checksum);
        return -1;
    }

    if (payload_out) {
        *payload_out = ptr;
    }

    return 0;
}

/**
 * Callback for parallel async fetch
 */
static void parallel_fetch_callback(uint8_t *value, size_t value_len, void *userdata) {
    async_fetch_info_t *info = (async_fetch_info_t *)userdata;
    if (!info || !info->ctx) {
        if (value) free(value);
        free(info);
        return;
    }

    parallel_fetch_ctx_t *ctx = info->ctx;
    uint32_t index = info->chunk_index;

    pthread_mutex_lock(&ctx->mutex);

    if (index < ctx->total_chunks) {
        if (value && value_len > 0) {
            ctx->slots[index].data = value;
            ctx->slots[index].data_len = value_len;
            ctx->slots[index].received = true;
        } else {
            ctx->slots[index].error = true;
            if (value) free(value);
        }
    } else {
        if (value) free(value);
    }

    atomic_fetch_add(&ctx->completed, 1);
    pthread_cond_signal(&ctx->cond);
    pthread_mutex_unlock(&ctx->mutex);

    free(info);
}

/*============================================================================
 * Public API Implementation
 *============================================================================*/

int dht_chunked_make_key(const char *base_key, uint32_t chunk_index,
                         uint8_t key_out[DHT_CHUNK_KEY_SIZE]) {
    if (!base_key || !key_out) {
        return -1;
    }

    // Format: base_key + ":chunk:" + index
    char key_input[512];
    snprintf(key_input, sizeof(key_input), "%s:chunk:%u", base_key, chunk_index);

    // Hash with SHA3-512 and take first 32 bytes
    uint8_t full_hash[64];
    if (qgp_sha3_512((const uint8_t *)key_input, strlen(key_input), full_hash) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "SHA3-512 failed\n");
        return -1;
    }

    memcpy(key_out, full_hash, DHT_CHUNK_KEY_SIZE);
    return 0;
}

uint32_t dht_chunked_estimate_chunks(size_t data_len) {
    // Estimate ~50% compression ratio for typical data
    size_t estimated_compressed = data_len / 2;
    if (estimated_compressed < data_len / 10) {
        estimated_compressed = data_len / 10;  // At least 10% of original
    }
    return (uint32_t)((estimated_compressed + DHT_CHUNK_DATA_SIZE - 1) / DHT_CHUNK_DATA_SIZE);
}

int dht_chunked_publish(dht_context_t *ctx, const char *base_key,
                        const uint8_t *data, size_t data_len,
                        uint32_t ttl_seconds) {
    if (!ctx || !base_key || !data || data_len == 0) {
        return DHT_CHUNK_ERR_NULL_PARAM;
    }

    // Step 1: Compress data
    uint8_t *compressed = NULL;
    size_t compressed_len = 0;
    if (compress_data(data, data_len, &compressed, &compressed_len) != 0) {
        return DHT_CHUNK_ERR_COMPRESS;
    }

    // Step 2: Calculate chunks needed
    uint32_t total_chunks = (uint32_t)((compressed_len + DHT_CHUNK_DATA_SIZE - 1) / DHT_CHUNK_DATA_SIZE);

    // Step 3: Get value_id for replacement behavior
    uint64_t value_id = 1;
    dht_get_owner_value_id(ctx, &value_id);

    QGP_LOG_DEBUG(LOG_TAG, "[CHUNK_PUBLISH] Publishing %zu bytes -> %zu compressed -> %u chunks (base_key=%s)\n",
           data_len, compressed_len, total_chunks, base_key);

    // Step 4: Publish each chunk
    for (uint32_t i = 0; i < total_chunks; i++) {
        size_t offset = (size_t)i * DHT_CHUNK_DATA_SIZE;
        size_t chunk_size = (i == total_chunks - 1)
            ? (compressed_len - offset)
            : DHT_CHUNK_DATA_SIZE;

        // Build header
        dht_chunk_header_t header = {
            .magic = DHT_CHUNK_MAGIC,
            .version = DHT_CHUNK_VERSION,
            .total_chunks = total_chunks,
            .chunk_index = i,
            .chunk_data_size = (uint32_t)chunk_size,
            .original_size = (i == 0) ? (uint32_t)data_len : 0,
            .checksum = compute_crc32(compressed + offset, chunk_size)
        };

        // Serialize chunk
        uint8_t *serialized = NULL;
        size_t serialized_len = 0;
        if (serialize_chunk(&header, compressed + offset, chunk_size,
                           &serialized, &serialized_len) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to serialize chunk %u\n", i);
            free(compressed);
            return DHT_CHUNK_ERR_ALLOC;
        }

        // Generate DHT key
        uint8_t dht_key[DHT_CHUNK_KEY_SIZE];
        if (dht_chunked_make_key(base_key, i, dht_key) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to generate key for chunk %u\n", i);
            free(serialized);
            free(compressed);
            return DHT_CHUNK_ERR_ALLOC;
        }

        // Log chunk key for debugging (only for chunk 0 to avoid spam)
        if (i == 0) {
            QGP_LOG_INFO(LOG_TAG, "[CHUNK_PUBLISH] PUT key=%02x%02x%02x%02x%02x%02x%02x%02x... base_key=%s\n",
                   dht_key[0], dht_key[1], dht_key[2], dht_key[3],
                   dht_key[4], dht_key[5], dht_key[6], dht_key[7], base_key);
        }

        // Publish to DHT
        if (dht_put_signed(ctx, dht_key, DHT_CHUNK_KEY_SIZE,
                          serialized, serialized_len,
                          value_id, ttl_seconds) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to publish chunk %u to DHT\n", i);
            free(serialized);
            free(compressed);
            return DHT_CHUNK_ERR_DHT_PUT;
        }

        free(serialized);
    }

    free(compressed);
    QGP_LOG_INFO(LOG_TAG, "Published %u chunks successfully\n", total_chunks);
    return DHT_CHUNK_OK;
}

int dht_chunked_fetch(dht_context_t *ctx, const char *base_key,
                      uint8_t **data_out, size_t *data_len_out) {
    if (!ctx || !base_key || !data_out || !data_len_out) {
        return DHT_CHUNK_ERR_NULL_PARAM;
    }

    *data_out = NULL;
    *data_len_out = 0;

    // Step 1: Fetch chunk0 to learn total_chunks and original_size
    uint8_t chunk0_key[DHT_CHUNK_KEY_SIZE];
    if (dht_chunked_make_key(base_key, 0, chunk0_key) != 0) {
        return DHT_CHUNK_ERR_ALLOC;
    }

    uint8_t *chunk0_data = NULL;
    size_t chunk0_len = 0;
    if (dht_get(ctx, chunk0_key, DHT_CHUNK_KEY_SIZE, &chunk0_data, &chunk0_len) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch chunk0 for key=%s\n", base_key);
        return DHT_CHUNK_ERR_DHT_GET;
    }

    dht_chunk_header_t header0;
    const uint8_t *payload0;
    if (deserialize_chunk(chunk0_data, chunk0_len, &header0, &payload0) != 0) {
        free(chunk0_data);
        return DHT_CHUNK_ERR_INVALID_FORMAT;
    }

    uint32_t total_chunks = header0.total_chunks;
    uint32_t original_size = header0.original_size;

    QGP_LOG_INFO(LOG_TAG, "Fetching: total_chunks=%u, original_size=%u (key=%s)\n",
           total_chunks, original_size, base_key);

    // If only 1 chunk, handle directly
    if (total_chunks == 1) {
        // Decompress
        uint8_t *decompressed = NULL;
        size_t decompressed_len = 0;
        if (decompress_data(payload0, header0.chunk_data_size, original_size,
                           &decompressed, &decompressed_len) != 0) {
            free(chunk0_data);
            return DHT_CHUNK_ERR_DECOMPRESS;
        }

        free(chunk0_data);
        *data_out = decompressed;
        *data_len_out = decompressed_len;
        QGP_LOG_INFO(LOG_TAG, "Fetched %zu bytes from 1 chunk\n", decompressed_len);
        return DHT_CHUNK_OK;
    }

    // Step 2: Allocate parallel fetch context
    parallel_fetch_ctx_t pctx = {0};
    pctx.slots = (parallel_chunk_slot_t *)calloc(total_chunks, sizeof(parallel_chunk_slot_t));
    if (!pctx.slots) {
        free(chunk0_data);
        return DHT_CHUNK_ERR_ALLOC;
    }
    pctx.total_chunks = total_chunks;
    atomic_init(&pctx.completed, 1);  // chunk0 already fetched
    pthread_mutex_init(&pctx.mutex, NULL);
    pthread_cond_init(&pctx.cond, NULL);

    // Store chunk0 data
    pctx.slots[0].data = chunk0_data;
    pctx.slots[0].data_len = chunk0_len;
    pctx.slots[0].received = true;

    // Step 3: Fire parallel fetches for remaining chunks
    for (uint32_t i = 1; i < total_chunks; i++) {
        uint8_t chunk_key[DHT_CHUNK_KEY_SIZE];
        if (dht_chunked_make_key(base_key, i, chunk_key) != 0) {
            continue;  // Will be caught as missing
        }

        async_fetch_info_t *info = (async_fetch_info_t *)malloc(sizeof(async_fetch_info_t));
        if (!info) continue;

        info->ctx = &pctx;
        info->chunk_index = i;

        dht_get_async(ctx, chunk_key, DHT_CHUNK_KEY_SIZE,
                     parallel_fetch_callback, info);
    }

    // Step 4: Wait for all chunks with timeout
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += DHT_CHUNK_FETCH_TIMEOUT_MS / 1000;
    timeout.tv_nsec += (DHT_CHUNK_FETCH_TIMEOUT_MS % 1000) * 1000000;
    if (timeout.tv_nsec >= 1000000000) {
        timeout.tv_sec++;
        timeout.tv_nsec -= 1000000000;
    }

    pthread_mutex_lock(&pctx.mutex);
    while (atomic_load(&pctx.completed) < total_chunks) {
        int rc = pthread_cond_timedwait(&pctx.cond, &pctx.mutex, &timeout);
        if (rc != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Timeout waiting for chunks (%u/%u)\n",
                    atomic_load(&pctx.completed), total_chunks);
            pthread_mutex_unlock(&pctx.mutex);
            goto cleanup_error;
        }
    }
    pthread_mutex_unlock(&pctx.mutex);

    // Step 5: Verify all chunks received, retry failed ones
    // DHT is async - chunks may not be fully propagated when receiver fetches immediately
    int retry;
    for (retry = 0; retry < DHT_CHUNK_MAX_RETRIES; retry++) {
        // Count failed chunks
        uint32_t failed_count = 0;
        for (uint32_t i = 0; i < total_chunks; i++) {
            if (!pctx.slots[i].received || pctx.slots[i].error) {
                failed_count++;
            }
        }

        if (failed_count == 0) {
            break;  // All chunks received successfully
        }

        if (retry > 0) {
            QGP_LOG_INFO(LOG_TAG, "Retry %d: %u chunks still missing, retrying...\n",
                         retry, failed_count);
        } else {
            QGP_LOG_INFO(LOG_TAG, "%u chunks missing, will retry (DHT propagation delay)\n",
                         failed_count);
        }

        // Brief delay before retry to allow DHT propagation
        chunk_sleep_ms(DHT_CHUNK_RETRY_DELAY_MS);

        // Retry each failed chunk synchronously
        for (uint32_t i = 0; i < total_chunks; i++) {
            if (!pctx.slots[i].received || pctx.slots[i].error) {
                uint8_t chunk_key[DHT_CHUNK_KEY_SIZE];
                if (dht_chunked_make_key(base_key, i, chunk_key) != 0) {
                    continue;
                }

                uint8_t *chunk_data = NULL;
                size_t chunk_len = 0;
                if (dht_get(ctx, chunk_key, DHT_CHUNK_KEY_SIZE, &chunk_data, &chunk_len) == 0
                    && chunk_data && chunk_len > 0) {
                    // Success - update slot
                    if (pctx.slots[i].data) {
                        free(pctx.slots[i].data);
                    }
                    pctx.slots[i].data = chunk_data;
                    pctx.slots[i].data_len = chunk_len;
                    pctx.slots[i].received = true;
                    pctx.slots[i].error = false;
                    QGP_LOG_DEBUG(LOG_TAG, "Retry succeeded for chunk %u\n", i);
                } else {
                    if (chunk_data) free(chunk_data);
                }
            }
        }
    }

    // Final verification after all retries
    for (uint32_t i = 0; i < total_chunks; i++) {
        if (!pctx.slots[i].received || pctx.slots[i].error) {
            QGP_LOG_ERROR(LOG_TAG, "Missing chunk %u after %d retries\n", i, DHT_CHUNK_MAX_RETRIES);
            goto cleanup_error;
        }
    }

    // Step 6: Calculate total compressed size
    size_t total_compressed = 0;
    for (uint32_t i = 0; i < total_chunks; i++) {
        dht_chunk_header_t hdr;
        const uint8_t *payload;
        if (deserialize_chunk(pctx.slots[i].data, pctx.slots[i].data_len,
                             &hdr, &payload) != 0) {
            QGP_LOG_ERROR(LOG_TAG, "Failed to deserialize chunk %u\n", i);
            goto cleanup_error;
        }
        total_compressed += hdr.chunk_data_size;
    }

    // Step 7: Reassemble compressed data
    uint8_t *compressed = (uint8_t *)malloc(total_compressed);
    if (!compressed) {
        goto cleanup_error;
    }

    size_t offset = 0;
    for (uint32_t i = 0; i < total_chunks; i++) {
        dht_chunk_header_t hdr;
        const uint8_t *payload;
        if (deserialize_chunk(pctx.slots[i].data, pctx.slots[i].data_len,
                             &hdr, &payload) != 0) {
            free(compressed);
            goto cleanup_error;
        }

        // Verify chunk index matches expected
        if (hdr.chunk_index != i) {
            QGP_LOG_ERROR(LOG_TAG, "Chunk index mismatch: %u != %u\n", hdr.chunk_index, i);
            free(compressed);
            goto cleanup_error;
        }

        memcpy(compressed + offset, payload, hdr.chunk_data_size);
        offset += hdr.chunk_data_size;
    }

    // Step 8: Decompress
    uint8_t *decompressed = NULL;
    size_t decompressed_len = 0;
    if (decompress_data(compressed, total_compressed, original_size,
                       &decompressed, &decompressed_len) != 0) {
        free(compressed);
        goto cleanup_error;
    }

    free(compressed);

    // Cleanup
    for (uint32_t i = 0; i < total_chunks; i++) {
        if (pctx.slots[i].data) {
            free(pctx.slots[i].data);
        }
    }
    free(pctx.slots);
    pthread_mutex_destroy(&pctx.mutex);
    pthread_cond_destroy(&pctx.cond);

    *data_out = decompressed;
    *data_len_out = decompressed_len;
    QGP_LOG_INFO(LOG_TAG, "Fetched %zu bytes from %u chunks\n", decompressed_len, total_chunks);
    return DHT_CHUNK_OK;

cleanup_error:
    for (uint32_t i = 0; i < total_chunks; i++) {
        if (pctx.slots[i].data) {
            free(pctx.slots[i].data);
        }
    }
    free(pctx.slots);
    pthread_mutex_destroy(&pctx.mutex);
    pthread_cond_destroy(&pctx.cond);
    return DHT_CHUNK_ERR_INCOMPLETE;
}

int dht_chunked_delete(dht_context_t *ctx, const char *base_key,
                       uint32_t known_chunk_count) {
    if (!ctx || !base_key) {
        return DHT_CHUNK_ERR_NULL_PARAM;
    }

    uint32_t total_chunks = known_chunk_count;

    // If chunk count not known, try to discover from chunk0
    if (total_chunks == 0) {
        uint8_t chunk0_key[DHT_CHUNK_KEY_SIZE];
        if (dht_chunked_make_key(base_key, 0, chunk0_key) != 0) {
            return DHT_CHUNK_ERR_ALLOC;
        }

        uint8_t *chunk0_data = NULL;
        size_t chunk0_len = 0;
        if (dht_get(ctx, chunk0_key, DHT_CHUNK_KEY_SIZE, &chunk0_data, &chunk0_len) != 0) {
            // No chunk0 found, nothing to delete
            return DHT_CHUNK_OK;
        }

        dht_chunk_header_t header0;
        if (deserialize_chunk(chunk0_data, chunk0_len, &header0, NULL) != 0) {
            free(chunk0_data);
            return DHT_CHUNK_ERR_INVALID_FORMAT;
        }

        total_chunks = header0.total_chunks;
        free(chunk0_data);
    }

    QGP_LOG_INFO(LOG_TAG, "Deleting %u chunks (key=%s)\n", total_chunks, base_key);

    // Get value_id for replacement
    uint64_t value_id = 1;
    dht_get_owner_value_id(ctx, &value_id);

    // Publish empty chunks to overwrite (1 byte payload to mark as deleted)
    uint8_t empty_marker = 0;
    dht_chunk_header_t empty_header = {
        .magic = DHT_CHUNK_MAGIC,
        .version = DHT_CHUNK_VERSION,
        .total_chunks = 0,  // 0 chunks = deleted marker
        .chunk_index = 0,
        .chunk_data_size = 1,
        .original_size = 0,
        .checksum = compute_crc32(&empty_marker, 1)
    };

    uint8_t *serialized = NULL;
    size_t serialized_len = 0;
    if (serialize_chunk(&empty_header, &empty_marker, 1, &serialized, &serialized_len) != 0) {
        return DHT_CHUNK_ERR_ALLOC;
    }

    for (uint32_t i = 0; i < total_chunks; i++) {
        uint8_t chunk_key[DHT_CHUNK_KEY_SIZE];
        if (dht_chunked_make_key(base_key, i, chunk_key) != 0) {
            continue;
        }

        // Overwrite with empty marker (short TTL)
        dht_put_signed(ctx, chunk_key, DHT_CHUNK_KEY_SIZE,
                      serialized, serialized_len,
                      value_id, 60);  // 1 minute TTL for quick expiry
    }

    free(serialized);
    QGP_LOG_INFO(LOG_TAG, "Deleted %u chunks\n", total_chunks);
    return DHT_CHUNK_OK;
}

const char *dht_chunked_strerror(int error) {
    switch (error) {
        case DHT_CHUNK_OK:              return "Success";
        case DHT_CHUNK_ERR_NULL_PARAM:  return "NULL parameter";
        case DHT_CHUNK_ERR_COMPRESS:    return "Compression failed";
        case DHT_CHUNK_ERR_DECOMPRESS:  return "Decompression failed";
        case DHT_CHUNK_ERR_DHT_PUT:     return "DHT put failed";
        case DHT_CHUNK_ERR_DHT_GET:     return "DHT get failed";
        case DHT_CHUNK_ERR_INVALID_FORMAT: return "Invalid chunk format";
        case DHT_CHUNK_ERR_CHECKSUM:    return "CRC32 checksum mismatch";
        case DHT_CHUNK_ERR_INCOMPLETE:  return "Missing chunks";
        case DHT_CHUNK_ERR_TIMEOUT:     return "Fetch timeout";
        case DHT_CHUNK_ERR_ALLOC:       return "Memory allocation failed";
        default:                        return "Unknown error";
    }
}

/*============================================================================
 * Batch API Implementation
 *============================================================================*/

int dht_chunked_fetch_batch(
    dht_context_t *ctx,
    const char **base_keys,
    size_t key_count,
    dht_chunked_batch_result_t **results_out)
{
    if (!ctx || !base_keys || key_count == 0 || !results_out) {
        return -1;
    }

    struct timespec batch_start;
    clock_gettime(CLOCK_MONOTONIC, &batch_start);

    QGP_LOG_INFO(LOG_TAG, "BATCH_FETCH: Starting parallel fetch of %zu keys\n", key_count);

    // Allocate results array
    dht_chunked_batch_result_t *results = (dht_chunked_batch_result_t *)calloc(
        key_count, sizeof(dht_chunked_batch_result_t));
    if (!results) {
        QGP_LOG_ERROR(LOG_TAG, "BATCH_FETCH: Failed to allocate results array\n");
        return -1;
    }

    // Initialize results with base keys
    for (size_t i = 0; i < key_count; i++) {
        results[i].base_key = base_keys[i];
        results[i].data = NULL;
        results[i].data_len = 0;
        results[i].error = DHT_CHUNK_ERR_DHT_GET;  // Default to not found
    }

    // Step 1: Build all chunk0 keys
    uint8_t **chunk0_keys = (uint8_t **)malloc(key_count * sizeof(uint8_t *));
    size_t *chunk0_key_lens = (size_t *)malloc(key_count * sizeof(size_t));
    if (!chunk0_keys || !chunk0_key_lens) {
        QGP_LOG_ERROR(LOG_TAG, "BATCH_FETCH: Failed to allocate key arrays\n");
        free(chunk0_keys);
        free(chunk0_key_lens);
        free(results);
        return -1;
    }

    for (size_t i = 0; i < key_count; i++) {
        chunk0_keys[i] = (uint8_t *)malloc(DHT_CHUNK_KEY_SIZE);
        if (!chunk0_keys[i]) {
            for (size_t j = 0; j < i; j++) {
                free(chunk0_keys[j]);
            }
            free(chunk0_keys);
            free(chunk0_key_lens);
            free(results);
            return -1;
        }
        dht_chunked_make_key(base_keys[i], 0, chunk0_keys[i]);
        chunk0_key_lens[i] = DHT_CHUNK_KEY_SIZE;
    }

    // Step 2: Batch fetch all chunk0 keys in parallel
    dht_batch_result_t *batch_results = NULL;
    int batch_ret = dht_get_batch_sync(ctx,
                                       (const uint8_t **)chunk0_keys,
                                       chunk0_key_lens,
                                       key_count,
                                       &batch_results);

    // Free chunk0 keys (no longer needed)
    for (size_t i = 0; i < key_count; i++) {
        free(chunk0_keys[i]);
    }
    free(chunk0_keys);
    free(chunk0_key_lens);

    if (batch_ret != 0 || !batch_results) {
        QGP_LOG_ERROR(LOG_TAG, "BATCH_FETCH: dht_get_batch_sync failed\n");
        free(results);
        return -1;
    }

    struct timespec batch_get_end;
    clock_gettime(CLOCK_MONOTONIC, &batch_get_end);
    long batch_get_ms = (batch_get_end.tv_sec - batch_start.tv_sec) * 1000 +
                        (batch_get_end.tv_nsec - batch_start.tv_nsec) / 1000000;
    QGP_LOG_INFO(LOG_TAG, "BATCH_FETCH: Parallel DHT fetch took %ld ms for %zu keys\n",
                 batch_get_ms, key_count);

    // Step 3: Process each result
    int success_count = 0;
    for (size_t i = 0; i < key_count; i++) {
        if (!batch_results[i].found || !batch_results[i].value || batch_results[i].value_len == 0) {
            // Not found - already initialized to error
            continue;
        }

        // Parse chunk0 header
        dht_chunk_header_t header0;
        const uint8_t *payload0;
        if (deserialize_chunk(batch_results[i].value, batch_results[i].value_len,
                             &header0, &payload0) != 0) {
            results[i].error = DHT_CHUNK_ERR_INVALID_FORMAT;
            continue;
        }

        uint32_t total_chunks = header0.total_chunks;
        uint32_t original_size = header0.original_size;

        // Single chunk case - decompress directly
        if (total_chunks == 1) {
            uint8_t *decompressed = NULL;
            size_t decompressed_len = 0;
            if (decompress_data(payload0, header0.chunk_data_size, original_size,
                               &decompressed, &decompressed_len) == 0) {
                results[i].data = decompressed;
                results[i].data_len = decompressed_len;
                results[i].error = DHT_CHUNK_OK;
                success_count++;
            } else {
                results[i].error = DHT_CHUNK_ERR_DECOMPRESS;
            }
            continue;
        }

        // Multi-chunk case - need to fetch remaining chunks
        // For now, fall back to sequential fetch for additional chunks
        // (This is rare for typical offline messages)
        QGP_LOG_INFO(LOG_TAG, "BATCH_FETCH: Key %zu needs %u chunks, fetching sequentially\n",
                     i, total_chunks);

        // Use the existing dht_chunked_fetch for multi-chunk data
        uint8_t *full_data = NULL;
        size_t full_len = 0;
        int fetch_ret = dht_chunked_fetch(ctx, base_keys[i], &full_data, &full_len);
        if (fetch_ret == DHT_CHUNK_OK) {
            results[i].data = full_data;
            results[i].data_len = full_len;
            results[i].error = DHT_CHUNK_OK;
            success_count++;
        } else {
            results[i].error = fetch_ret;
        }
    }

    // Free batch results
    dht_batch_results_free(batch_results, key_count);

    struct timespec batch_end;
    clock_gettime(CLOCK_MONOTONIC, &batch_end);
    long total_ms = (batch_end.tv_sec - batch_start.tv_sec) * 1000 +
                    (batch_end.tv_nsec - batch_start.tv_nsec) / 1000000;

    QGP_LOG_INFO(LOG_TAG, "BATCH_FETCH: Complete - %d/%zu successful in %ld ms\n",
                 success_count, key_count, total_ms);

    *results_out = results;
    return success_count;
}

void dht_chunked_batch_results_free(dht_chunked_batch_result_t *results, size_t count) {
    if (!results) return;

    for (size_t i = 0; i < count; i++) {
        if (results[i].data) {
            free(results[i].data);
        }
    }
    free(results);
}
