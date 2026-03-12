/**
 * @file dht_gek_storage.c
 * @brief DHT Storage for GEK Initial Key Packets
 *
 * Simplified implementation using the generic dht_chunked layer.
 * Handles publishing and fetching of large Initial Key Packets
 * for Group Encryption Key (GEK) distribution via DHT.
 *
 * Part of DNA Connect - GEK System
 *
 * @date 2026-01-10
 */

#include "dht_gek_storage.h"
#include "nodus_ops.h"
#include "crypto/hash/qgp_sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/utils/qgp_log.h"

#define LOG_TAG "DHT_GEK"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

/*============================================================================
 * Internal Helper Functions
 *============================================================================*/

/**
 * Generate base key for GEK storage
 *
 * Format: "group_uuid:gek:version"
 */
static int make_gek_base_key(const char *group_uuid, uint32_t gek_version,
                             char *key_out, size_t key_out_size) {
    if (!group_uuid || !key_out) return -1;

    int ret = snprintf(key_out, key_out_size, "%s:gek:%u", group_uuid, gek_version);
    if (ret < 0 || (size_t)ret >= key_out_size) {
        return -1;
    }
    return 0;
}

/*============================================================================
 * Legacy API - For backward compatibility with existing code
 *============================================================================*/

/**
 * Generate DHT key for a specific chunk (hex string format)
 *
 * This is kept for logging/debugging purposes. The actual storage
 * now uses the generic chunked layer which has its own key format.
 */
int dht_gek_make_chunk_key(const char *group_uuid,
                            uint32_t gek_version,
                            uint32_t chunk_index,
                            char key_out[65]) {
    if (!group_uuid || !key_out) {
        return -1;
    }

    // Generate key: SHA3-512(base_key + ":chunk:" + index), take first 32 bytes
    char base_key[256];
    if (make_gek_base_key(group_uuid, gek_version, base_key, sizeof(base_key)) != 0) {
        return -1;
    }

    char key_input[512];
    snprintf(key_input, sizeof(key_input), "%s:chunk:%u", base_key, chunk_index);

    uint8_t full_hash[64];
    if (qgp_sha3_512((const uint8_t *)key_input, strlen(key_input), full_hash) != 0) {
        return -1;
    }

    uint8_t binary_key[32];
    memcpy(binary_key, full_hash, 32);

    // Convert to hex string
    for (int i = 0; i < 32; i++) {
        sprintf(&key_out[i * 2], "%02x", binary_key[i]);
    }
    key_out[64] = '\0';

    return 0;
}

/**
 * Serialize chunk to binary format
 *
 * Legacy function - kept for any code that still uses it directly.
 * New code should use dht_chunked_publish() which handles serialization internally.
 */
int dht_gek_serialize_chunk(const dht_gek_chunk_t *chunk,
                             uint8_t **serialized_out,
                             size_t *serialized_size_out) {
    if (!chunk || !serialized_out || !serialized_size_out) {
        QGP_LOG_ERROR(LOG_TAG, "serialize_chunk: NULL parameter\n");
        return -1;
    }

    // Calculate size: header (17 bytes) + chunk data
    size_t header_size = 4 + 1 + 4 + 4 + 4;  // magic + version + total_chunks + chunk_index + chunk_size
    size_t total_size = header_size + chunk->chunk_size;

    uint8_t *serialized = (uint8_t *)malloc(total_size);
    if (!serialized) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate serialized buffer\n");
        return -1;
    }

    size_t offset = 0;

    // Magic (4 bytes, network byte order)
    uint32_t magic_net = htonl(chunk->magic);
    memcpy(serialized + offset, &magic_net, 4);
    offset += 4;

    // Version (1 byte)
    serialized[offset] = chunk->version;
    offset += 1;

    // Total chunks (4 bytes, network byte order)
    uint32_t total_chunks_net = htonl(chunk->total_chunks);
    memcpy(serialized + offset, &total_chunks_net, 4);
    offset += 4;

    // Chunk index (4 bytes, network byte order)
    uint32_t chunk_index_net = htonl(chunk->chunk_index);
    memcpy(serialized + offset, &chunk_index_net, 4);
    offset += 4;

    // Chunk size (4 bytes, network byte order)
    uint32_t chunk_size_net = htonl(chunk->chunk_size);
    memcpy(serialized + offset, &chunk_size_net, 4);
    offset += 4;

    // Chunk data
    memcpy(serialized + offset, chunk->chunk_data, chunk->chunk_size);

    *serialized_out = serialized;
    *serialized_size_out = total_size;
    return 0;
}

/**
 * Deserialize chunk from binary format
 *
 * Legacy function - kept for any code that still uses it directly.
 */
int dht_gek_deserialize_chunk(const uint8_t *serialized,
                               size_t serialized_size,
                               dht_gek_chunk_t *chunk_out) {
    if (!serialized || !chunk_out || serialized_size < 17) {
        QGP_LOG_ERROR(LOG_TAG, "deserialize_chunk: Invalid parameter\n");
        return -1;
    }

    size_t offset = 0;

    // Magic (4 bytes)
    uint32_t magic_net;
    memcpy(&magic_net, serialized + offset, 4);
    chunk_out->magic = ntohl(magic_net);
    offset += 4;

    if (chunk_out->magic != DHT_GEK_MAGIC) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid magic: 0x%08X (expected 0x%08X)\n",
                chunk_out->magic, DHT_GEK_MAGIC);
        return -1;
    }

    // Version (1 byte)
    chunk_out->version = serialized[offset];
    offset += 1;

    if (chunk_out->version != DHT_GEK_VERSION) {
        QGP_LOG_ERROR(LOG_TAG, "Invalid version: %u (expected %u)\n",
                chunk_out->version, DHT_GEK_VERSION);
        return -1;
    }

    // Total chunks (4 bytes)
    uint32_t total_chunks_net;
    memcpy(&total_chunks_net, serialized + offset, 4);
    chunk_out->total_chunks = ntohl(total_chunks_net);
    offset += 4;

    // Chunk index (4 bytes)
    uint32_t chunk_index_net;
    memcpy(&chunk_index_net, serialized + offset, 4);
    chunk_out->chunk_index = ntohl(chunk_index_net);
    offset += 4;

    // Chunk size (4 bytes)
    uint32_t chunk_size_net;
    memcpy(&chunk_size_net, serialized + offset, 4);
    chunk_out->chunk_size = ntohl(chunk_size_net);
    offset += 4;

    // Validate chunk size
    if (offset + chunk_out->chunk_size > serialized_size) {
        QGP_LOG_ERROR(LOG_TAG, "Chunk size mismatch: %u + %u > %zu\n",
                (uint32_t)offset, chunk_out->chunk_size, serialized_size);
        return -1;
    }

    // Allocate and copy chunk data
    chunk_out->chunk_data = (uint8_t *)malloc(chunk_out->chunk_size);
    if (!chunk_out->chunk_data) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to allocate chunk data\n");
        return -1;
    }

    memcpy(chunk_out->chunk_data, serialized + offset, chunk_out->chunk_size);

    return 0;
}

/**
 * Free chunk structure
 */
void dht_gek_free_chunk(dht_gek_chunk_t *chunk) {
    if (chunk && chunk->chunk_data) {
        free(chunk->chunk_data);
        chunk->chunk_data = NULL;
    }
}

/*============================================================================
 * Main API - Now using generic chunked layer
 *============================================================================*/

/**
 * Publish Initial Key Packet to DHT
 *
 * Uses the generic dht_chunked layer for automatic chunking,
 * compression, and parallel-friendly storage.
 */
int dht_gek_publish(const char *group_uuid,
                    uint32_t gek_version,
                    const uint8_t *packet,
                    size_t packet_size) {
    if (!group_uuid || !packet || packet_size == 0) {
        QGP_LOG_ERROR(LOG_TAG, "publish: NULL parameter\n");
        return -1;
    }

    // Generate base key for this GEK packet
    char base_key[256];
    if (make_gek_base_key(group_uuid, gek_version, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Publishing packet (group=%s v%u): %zu bytes\n",
           group_uuid, gek_version, packet_size);

    // Use nodus_ops layer
    int ret = nodus_ops_put_str(base_key, packet, packet_size, DHT_GEK_DEFAULT_TTL, nodus_ops_value_id());

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to publish: %d\n", ret);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Published successfully\n");
    return 0;
}

/**
 * Fetch Initial Key Packet from DHT
 *
 * Uses the generic dht_chunked layer for parallel fetching,
 * automatic reassembly, and decompression.
 */
int dht_gek_fetch(const char *group_uuid,
                  uint32_t gek_version,
                  uint8_t **packet_out,
                  size_t *packet_size_out) {
    if (!group_uuid || !packet_out || !packet_size_out) {
        QGP_LOG_ERROR(LOG_TAG, "fetch: NULL parameter\n");
        return -1;
    }

    // Generate base key for this GEK packet
    char base_key[256];
    if (make_gek_base_key(group_uuid, gek_version, base_key, sizeof(base_key)) != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to generate base key\n");
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetching packet (group=%s v%u)...\n", group_uuid, gek_version);

    // Use nodus_ops layer
    int ret = nodus_ops_get_str(base_key, packet_out, packet_size_out);

    if (ret != 0) {
        QGP_LOG_ERROR(LOG_TAG, "Failed to fetch: %d\n", ret);
        return -1;
    }

    QGP_LOG_INFO(LOG_TAG, "Fetched %zu bytes successfully\n", *packet_size_out);
    return 0;
}
