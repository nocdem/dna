/**
 * @file dht_chunked.h
 * @brief Generic DHT Chunked Storage Layer
 *
 * Provides transparent chunking for large data storage in DHT.
 * Features:
 * - ZSTD compression (max level for maximum compression)
 * - Parallel chunk fetching using dht_get_async()
 * - Unlimited chunk count (uint32_t)
 * - CRC32 integrity checking per chunk
 * - Auto-cleanup via value_id replacement
 * - 45KB effective chunk size (50KB - signature overhead)
 *
 * Binary Format (25-byte header per chunk):
 * [4B magic "DNAC"][1B version][4B total_chunks][4B chunk_index]
 * [4B chunk_data_size][4B original_size][4B crc32][payload...]
 *
 * Key Generation:
 * chunk_key = SHA3-512(base_key + ":chunk:" + chunk_index)[0:32]
 *
 * Part of DNA Messenger
 *
 * @date 2025-11-27
 */

#ifndef DHT_CHUNKED_H
#define DHT_CHUNKED_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*============================================================================
 * Constants
 *============================================================================*/

/** Magic bytes for chunk format validation ("DNAC" = DNA Chunked) */
#define DHT_CHUNK_MAGIC         0x444E4143

/** Protocol versions */
#define DHT_CHUNK_VERSION_V1    1
#define DHT_CHUNK_VERSION_V2    2
#define DHT_CHUNK_VERSION       DHT_CHUNK_VERSION_V2  /* Current write version */

/** Chunk header sizes in bytes */
#define DHT_CHUNK_HEADER_SIZE_V1   25                 /* v1: no content hash */
#define DHT_CHUNK_HEADER_SIZE_V2   57                 /* v2: 25 + 32 hash (chunk 0 only) */
#define DHT_CHUNK_HEADER_SIZE      DHT_CHUNK_HEADER_SIZE_V1  /* Non-chunk-0 size */

/** Content hash size (SHA3-256 of original uncompressed data) */
#define DHT_CHUNK_HASH_SIZE     32

/**
 * Maximum payload per chunk (45KB - header)
 * OpenDHT limit ~50KB, Dilithium5 signature ~4.6KB overhead
 * 45000 - 25 = 44975 bytes effective payload
 */
#define DHT_CHUNK_DATA_SIZE     44975

/** Maximum total size per chunk including header */
#define DHT_CHUNK_MAX_SIZE      45000

/** DHT key size in bytes (SHA3-512 truncated to 32 bytes) */
#define DHT_CHUNK_KEY_SIZE      32

/**
 * Security: Maximum number of chunks allowed per fetch
 * Prevents DoS via malicious total_chunks values from DHT.
 * 10000 chunks × 45KB = ~450MB max allocation.
 */
#define DHT_CHUNK_MAX_CHUNKS    10000

/*============================================================================
 * TTL Presets (seconds)
 *============================================================================*/

#define DHT_CHUNK_TTL_7DAY      (7 * 24 * 3600)      // 604800
#define DHT_CHUNK_TTL_30DAY     (30 * 24 * 3600)     // 2592000
#define DHT_CHUNK_TTL_365DAY    (365 * 24 * 3600)    // 31536000
#define DHT_CHUNK_TTL_PERMANENT UINT32_MAX           // 4294967295 (~136 years, treated as permanent)

/*============================================================================
 * Error Codes
 *============================================================================*/

typedef enum {
    DHT_CHUNK_OK = 0,               /** Success */
    DHT_CHUNK_ERR_NULL_PARAM = -1,  /** NULL parameter */
    DHT_CHUNK_ERR_COMPRESS = -2,    /** Compression failed */
    DHT_CHUNK_ERR_DECOMPRESS = -3,  /** Decompression failed */
    DHT_CHUNK_ERR_DHT_PUT = -4,     /** DHT put failed */
    DHT_CHUNK_ERR_DHT_GET = -5,     /** DHT get failed */
    DHT_CHUNK_ERR_INVALID_FORMAT = -6,  /** Invalid chunk format */
    DHT_CHUNK_ERR_CHECKSUM = -7,    /** CRC32 checksum mismatch */
    DHT_CHUNK_ERR_INCOMPLETE = -8,  /** Missing chunks */
    DHT_CHUNK_ERR_TIMEOUT = -9,     /** Fetch timeout */
    DHT_CHUNK_ERR_ALLOC = -10,      /** Memory allocation failed */
    DHT_CHUNK_ERR_NOT_CONNECTED = -11,  /** DHT not connected (no nodes in routing table) */
    DHT_CHUNK_ERR_HASH_MISMATCH = -12   /** Content hash mismatch (DHT version inconsistency - retry recommended) */
} dht_chunk_error_t;

/*============================================================================
 * Core API Functions
 *============================================================================*/

/**
 * Publish data to DHT with automatic chunking and compression
 *
 * Workflow:
 * 1. Compress data with ZSTD (max level)
 * 2. Calculate number of chunks needed
 * 3. Get value_id from dht_get_owner_value_id() for replacement behavior
 * 4. For each chunk:
 *    a. Build header (magic, version, total, index, size, original_size, crc32)
 *    b. Generate key: SHA3-512(base_key + ":chunk:" + i)[0:32]
 *    c. Serialize: header + payload
 *    d. dht_put_signed(key, serialized, value_id, ttl)
 *
 * @param ctx         DHT context
 * @param base_key    Base key string (e.g., "fingerprint:profile" or "uuid:gek:1")
 * @param data        Data to publish
 * @param data_len    Data length in bytes
 * @param ttl_seconds TTL in seconds (use DHT_CHUNK_TTL_* constants)
 * @return DHT_CHUNK_OK on success, error code on failure
 */
int dht_chunked_publish(
    dht_context_t *ctx,
    const char *base_key,
    const uint8_t *data,
    size_t data_len,
    uint32_t ttl_seconds
);

/**
 * Fetch data from DHT with parallel chunk retrieval and decompression
 *
 * Workflow:
 * 1. Fetch chunk0 to learn total_chunks and original_size
 * 2. Validate magic, version, CRC32
 * 3. Fire parallel dht_get_async() for chunks 1..N-1
 * 4. Wait for all completions (with timeout)
 * 5. Validate each chunk (magic, version, index, CRC32)
 * 6. Reassemble compressed data in order
 * 7. Decompress with ZSTD
 * 8. Validate decompressed size matches original_size
 *
 * @param ctx          DHT context
 * @param base_key     Base key string (same as used in publish)
 * @param data_out     Output buffer (allocated by function, caller must free)
 * @param data_len_out Output data length
 * @return DHT_CHUNK_OK on success, error code on failure
 */
int dht_chunked_fetch(
    dht_context_t *ctx,
    const char *base_key,
    uint8_t **data_out,
    size_t *data_len_out
);

/**
 * Fetch MY OWN data from DHT (using my value_id)
 *
 * Same as dht_chunked_fetch() but only fetches the value belonging
 * to the current identity (matching dht_get_owner_value_id()).
 * Used when multiple writers publish to the same key.
 *
 * @param ctx          DHT context
 * @param base_key     Base key string (same as used in publish)
 * @param data_out     Output buffer (allocated by function, caller must free)
 * @param data_len_out Output data length
 * @return DHT_CHUNK_OK on success, error code on failure
 */
int dht_chunked_fetch_mine(
    dht_context_t *ctx,
    const char *base_key,
    uint8_t **data_out,
    size_t *data_len_out
);

/**
 * Fetch ALL values from ALL writers at a key
 *
 * For multi-writer keys (like group outbox), fetches all published values
 * from all different value_id owners. Returns array of decompressed data.
 *
 * @param ctx          DHT context
 * @param base_key     Base key string
 * @param values_out   Output: Array of decompressed data pointers (caller frees each + array)
 * @param lens_out     Output: Array of data lengths (caller frees)
 * @param count_out    Output: Number of values fetched
 * @return DHT_CHUNK_OK on success, error code on failure
 */
int dht_chunked_fetch_all(
    dht_context_t *ctx,
    const char *base_key,
    uint8_t ***values_out,
    size_t **lens_out,
    size_t *count_out
);

/**
 * Delete chunked data from DHT
 *
 * Note: DHT doesn't support true deletion. This function publishes
 * empty chunks to overwrite existing data. Chunks will fully expire
 * via their TTL.
 *
 * @param ctx               DHT context
 * @param base_key          Base key string
 * @param known_chunk_count Number of chunks (0 = discover from chunk0)
 * @return DHT_CHUNK_OK on success, error code on failure
 */
int dht_chunked_delete(
    dht_context_t *ctx,
    const char *base_key,
    uint32_t known_chunk_count
);

/**
 * Get human-readable error message for error code
 *
 * @param error Error code from dht_chunked_* functions
 * @return Static string describing the error
 */
const char *dht_chunked_strerror(int error);

/*============================================================================
 * Utility Functions
 *============================================================================*/

/**
 * Generate DHT key for a specific chunk (binary format)
 *
 * Key format: SHA3-512(base_key + ":chunk:" + chunk_index)[0:32]
 *
 * @param base_key    Base key string
 * @param chunk_index Chunk index (0-based)
 * @param key_out     Output buffer for binary key (must be 32 bytes)
 * @return 0 on success, -1 on error
 */
int dht_chunked_make_key(
    const char *base_key,
    uint32_t chunk_index,
    uint8_t key_out[DHT_CHUNK_KEY_SIZE]
);

/**
 * Estimate number of chunks needed for data
 *
 * @param data_len Original data length
 * @return Estimated number of chunks (after compression estimate)
 */
uint32_t dht_chunked_estimate_chunks(size_t data_len);

/*============================================================================
 * Metadata API Functions (for smart sync optimization)
 *============================================================================*/

/**
 * Fetch chunk 0 metadata only (for smart sync hash comparison)
 *
 * Retrieves only the chunk 0 header to get the content hash without
 * downloading all chunks. Use for sync optimization:
 * 1. Call this to get remote content hash
 * 2. Compare with locally cached hash
 * 3. If match, skip full fetch (data unchanged)
 * 4. If mismatch, call dht_chunked_fetch() for full data
 *
 * @param ctx              DHT context
 * @param base_key         Base key string
 * @param hash_out         Output: 32-byte content hash (filled if v2, zeroed if v1)
 * @param original_size_out Output: Original uncompressed data size
 * @param total_chunks_out Output: Total number of chunks (optional, can be NULL)
 * @param is_v2_out        Output: True if chunk was v2+ (has valid content hash)
 * @return DHT_CHUNK_OK on success, error code on failure
 */
int dht_chunked_fetch_metadata(
    dht_context_t *ctx,
    const char *base_key,
    uint8_t hash_out[DHT_CHUNK_HASH_SIZE],
    uint32_t *original_size_out,
    uint32_t *total_chunks_out,
    bool *is_v2_out
);

/*============================================================================
 * Batch API Functions
 *============================================================================*/

/**
 * Result structure for batch fetch
 */
typedef struct {
    const char *base_key;   // Original base key (pointer, not owned)
    uint8_t *data;          // Fetched and decompressed data (caller must free)
    size_t data_len;        // Data length
    int error;              // 0 = success, negative = error code
} dht_chunked_batch_result_t;

/**
 * Fetch multiple chunked data items in parallel
 *
 * This function fetches all chunk0 keys in parallel using dht_get_batch_sync(),
 * then fetches any additional chunks needed. Much faster than sequential fetches
 * when retrieving data from multiple keys.
 *
 * Performance: N keys sequential = ~N*250ms, batch = ~300ms (N*x speedup)
 *
 * @param ctx         DHT context
 * @param base_keys   Array of base key strings
 * @param key_count   Number of keys
 * @param results_out Output array (allocated, caller must free with dht_chunked_batch_results_free)
 * @return Number of successful fetches, or -1 on fatal error
 */
int dht_chunked_fetch_batch(
    dht_context_t *ctx,
    const char **base_keys,
    size_t key_count,
    dht_chunked_batch_result_t **results_out
);

/**
 * Free batch results array
 *
 * @param results Results array from dht_chunked_fetch_batch()
 * @param count   Number of results
 */
void dht_chunked_batch_results_free(dht_chunked_batch_result_t *results, size_t count);

#ifdef __cplusplus
}
#endif

#endif // DHT_CHUNKED_H
