/**
 * @file dht_gsk_storage.c
 * @brief DHT Chunked Storage for GSK Initial Key Packets Implementation
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#include "dht_gsk_storage.h"
#include "../../crypto/utils/qgp_sha3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/**
 * Generate DHT key for a specific chunk (binary format)
 *
 * Internal helper - generates 32-byte binary key for DHT storage.
 * DHT API expects binary keys, not hex strings.
 *
 * @param group_uuid Group UUID
 * @param gsk_version GSK version number
 * @param chunk_index Chunk index (0, 1, 2, 3)
 * @param key_out Output buffer for binary DHT key (32 bytes)
 * @return 0 on success, -1 on error
 */
static int dht_gsk_make_chunk_key_binary(const char *group_uuid,
                                          uint32_t gsk_version,
                                          uint32_t chunk_index,
                                          uint8_t key_out[32]) {
    if (!group_uuid || !key_out) {
        fprintf(stderr, "[DHT_GSK] make_chunk_key: NULL parameter\n");
        return -1;
    }

    // Key format: SHA3-512(group_uuid + ":gsk:" + version + ":chunk" + index) truncated to 32 bytes
    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:gsk:%u:chunk%u",
             group_uuid, gsk_version, chunk_index);

    // Hash with SHA3-512 and take first 32 bytes
    uint8_t full_hash[64];
    if (qgp_sha3_512((const uint8_t *)key_input, strlen(key_input), full_hash) != 0) {
        fprintf(stderr, "[DHT_GSK] SHA3-512 failed\n");
        return -1;
    }

    // Use first 32 bytes as DHT key
    memcpy(key_out, full_hash, 32);

    return 0;
}

/**
 * Generate DHT key for a specific chunk (hex string format)
 *
 * Public API - converts binary key to hex string for logging/debugging.
 */
int dht_gsk_make_chunk_key(const char *group_uuid,
                            uint32_t gsk_version,
                            uint32_t chunk_index,
                            char key_out[65]) {
    if (!key_out) {
        return -1;
    }

    uint8_t binary_key[32];
    if (dht_gsk_make_chunk_key_binary(group_uuid, gsk_version, chunk_index, binary_key) != 0) {
        return -1;
    }

    // Convert to hex string
    for (int i = 0; i < 32; i++) {
        sprintf(&key_out[i * 2], "%02x", binary_key[i]);
    }
    key_out[64] = '\0';

    return 0;
}

/**
 * Serialize chunk to binary format
 */
int dht_gsk_serialize_chunk(const dht_gsk_chunk_t *chunk,
                             uint8_t **serialized_out,
                             size_t *serialized_size_out) {
    if (!chunk || !serialized_out || !serialized_size_out) {
        fprintf(stderr, "[DHT_GSK] serialize_chunk: NULL parameter\n");
        return -1;
    }

    // Calculate size: header (17 bytes) + chunk data
    size_t header_size = 4 + 1 + 4 + 4 + 4;  // magic + version + total_chunks + chunk_index + chunk_size
    size_t total_size = header_size + chunk->chunk_size;

    uint8_t *serialized = (uint8_t *)malloc(total_size);
    if (!serialized) {
        fprintf(stderr, "[DHT_GSK] Failed to allocate serialized buffer\n");
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
    offset += chunk->chunk_size;

    *serialized_out = serialized;
    *serialized_size_out = total_size;
    return 0;
}

/**
 * Deserialize chunk from binary format
 */
int dht_gsk_deserialize_chunk(const uint8_t *serialized,
                               size_t serialized_size,
                               dht_gsk_chunk_t *chunk_out) {
    if (!serialized || !chunk_out || serialized_size < 17) {
        fprintf(stderr, "[DHT_GSK] deserialize_chunk: Invalid parameter\n");
        return -1;
    }

    size_t offset = 0;

    // Magic (4 bytes)
    uint32_t magic_net;
    memcpy(&magic_net, serialized + offset, 4);
    chunk_out->magic = ntohl(magic_net);
    offset += 4;

    if (chunk_out->magic != DHT_GSK_MAGIC) {
        fprintf(stderr, "[DHT_GSK] Invalid magic: 0x%08X (expected 0x%08X)\n",
                chunk_out->magic, DHT_GSK_MAGIC);
        return -1;
    }

    // Version (1 byte)
    chunk_out->version = serialized[offset];
    offset += 1;

    if (chunk_out->version != DHT_GSK_VERSION) {
        fprintf(stderr, "[DHT_GSK] Invalid version: %u (expected %u)\n",
                chunk_out->version, DHT_GSK_VERSION);
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
        fprintf(stderr, "[DHT_GSK] Chunk size mismatch: %u + %u > %zu\n",
                (uint32_t)offset, chunk_out->chunk_size, serialized_size);
        return -1;
    }

    // Allocate and copy chunk data
    chunk_out->chunk_data = (uint8_t *)malloc(chunk_out->chunk_size);
    if (!chunk_out->chunk_data) {
        fprintf(stderr, "[DHT_GSK] Failed to allocate chunk data\n");
        return -1;
    }

    memcpy(chunk_out->chunk_data, serialized + offset, chunk_out->chunk_size);

    return 0;
}

/**
 * Free chunk structure
 */
void dht_gsk_free_chunk(dht_gsk_chunk_t *chunk) {
    if (chunk && chunk->chunk_data) {
        free(chunk->chunk_data);
        chunk->chunk_data = NULL;
    }
}

/**
 * Publish Initial Key Packet to DHT (chunked)
 */
int dht_gsk_publish(dht_context_t *ctx,
                    const char *group_uuid,
                    uint32_t gsk_version,
                    const uint8_t *packet,
                    size_t packet_size) {
    if (!ctx || !group_uuid || !packet || packet_size == 0) {
        fprintf(stderr, "[DHT_GSK] publish: NULL parameter\n");
        return -1;
    }

    // Calculate number of chunks needed
    uint32_t total_chunks = (packet_size + DHT_GSK_CHUNK_SIZE - 1) / DHT_GSK_CHUNK_SIZE;

    if (total_chunks > DHT_GSK_MAX_CHUNKS) {
        fprintf(stderr, "[DHT_GSK] Packet too large: %zu bytes requires %u chunks (max %u)\n",
                packet_size, total_chunks, DHT_GSK_MAX_CHUNKS);
        return -1;
    }

    printf("[DHT_GSK] Publishing packet (group=%s v%u): %zu bytes → %u chunks\n",
           group_uuid, gsk_version, packet_size, total_chunks);

    // Split into chunks and publish each
    for (uint32_t i = 0; i < total_chunks; i++) {
        // Calculate chunk boundaries
        size_t chunk_offset = i * DHT_GSK_CHUNK_SIZE;
        size_t chunk_size = (i == total_chunks - 1)
            ? (packet_size - chunk_offset)  // Last chunk: remaining bytes
            : DHT_GSK_CHUNK_SIZE;           // Other chunks: full 50 KB

        // Create chunk structure
        dht_gsk_chunk_t chunk = {
            .magic = DHT_GSK_MAGIC,
            .version = DHT_GSK_VERSION,
            .total_chunks = total_chunks,
            .chunk_index = i,
            .chunk_size = (uint32_t)chunk_size,
            .chunk_data = (uint8_t *)(packet + chunk_offset)  // Point to packet data (no copy)
        };

        // Serialize chunk
        uint8_t *serialized = NULL;
        size_t serialized_size = 0;
        if (dht_gsk_serialize_chunk(&chunk, &serialized, &serialized_size) != 0) {
            fprintf(stderr, "[DHT_GSK] Failed to serialize chunk %u\n", i);
            return -1;
        }

        // Generate binary DHT key for this chunk
        uint8_t dht_key_binary[32];
        if (dht_gsk_make_chunk_key_binary(group_uuid, gsk_version, i, dht_key_binary) != 0) {
            fprintf(stderr, "[DHT_GSK] Failed to generate key for chunk %u\n", i);
            free(serialized);
            return -1;
        }

        // Generate hex key for logging
        char dht_key_hex[65];
        for (int j = 0; j < 32; j++) {
            sprintf(&dht_key_hex[j * 2], "%02x", dht_key_binary[j]);
        }
        dht_key_hex[64] = '\0';

        // Publish to DHT (signed put with value_id=1 for replacement, 7-day TTL)
        if (dht_put_signed(ctx, dht_key_binary, 32, serialized, serialized_size, 1, DHT_GSK_DEFAULT_TTL) != 0) {
            fprintf(stderr, "[DHT_GSK] Failed to publish chunk %u to DHT\n", i);
            free(serialized);
            return -1;
        }

        printf("[DHT_GSK]   Chunk %u/%u published: %zu bytes (key=%s)\n",
               i, total_chunks, serialized_size, dht_key_hex);

        free(serialized);
    }

    printf("[DHT_GSK] ✓ Published %u chunks to DHT\n", total_chunks);
    return 0;
}

/**
 * Fetch Initial Key Packet from DHT (sequential chunk fetching)
 */
int dht_gsk_fetch(dht_context_t *ctx,
                  const char *group_uuid,
                  uint32_t gsk_version,
                  uint8_t **packet_out,
                  size_t *packet_size_out) {
    if (!ctx || !group_uuid || !packet_out || !packet_size_out) {
        fprintf(stderr, "[DHT_GSK] fetch: NULL parameter\n");
        return -1;
    }

    printf("[DHT_GSK] Fetching packet (group=%s v%u)...\n", group_uuid, gsk_version);

    // Step 1: Fetch chunk0 to determine total_chunks
    uint8_t chunk0_key[32];
    if (dht_gsk_make_chunk_key_binary(group_uuid, gsk_version, 0, chunk0_key) != 0) {
        fprintf(stderr, "[DHT_GSK] Failed to generate chunk0 key\n");
        return -1;
    }

    uint8_t *chunk0_data = NULL;
    size_t chunk0_size = 0;
    if (dht_get(ctx, chunk0_key, 32, &chunk0_data, &chunk0_size) != 0) {
        fprintf(stderr, "[DHT_GSK] Failed to fetch chunk0 from DHT\n");
        return -1;
    }

    dht_gsk_chunk_t chunk0;
    if (dht_gsk_deserialize_chunk(chunk0_data, chunk0_size, &chunk0) != 0) {
        fprintf(stderr, "[DHT_GSK] Failed to deserialize chunk0\n");
        free(chunk0_data);
        return -1;
    }
    free(chunk0_data);

    uint32_t total_chunks = chunk0.total_chunks;
    printf("[DHT_GSK]   Chunk0 fetched: total_chunks=%u\n", total_chunks);

    if (total_chunks > DHT_GSK_MAX_CHUNKS) {
        fprintf(stderr, "[DHT_GSK] Invalid total_chunks: %u (max %u)\n",
                total_chunks, DHT_GSK_MAX_CHUNKS);
        dht_gsk_free_chunk(&chunk0);
        return -1;
    }

    // Step 2: Allocate array to store all chunks
    dht_gsk_chunk_t *chunks = (dht_gsk_chunk_t *)calloc(total_chunks, sizeof(dht_gsk_chunk_t));
    if (!chunks) {
        fprintf(stderr, "[DHT_GSK] Failed to allocate chunks array\n");
        dht_gsk_free_chunk(&chunk0);
        return -1;
    }

    // Store chunk0
    chunks[0] = chunk0;

    // Step 3: Fetch remaining chunks sequentially
    for (uint32_t i = 1; i < total_chunks; i++) {
        uint8_t chunk_key[32];
        if (dht_gsk_make_chunk_key_binary(group_uuid, gsk_version, i, chunk_key) != 0) {
            fprintf(stderr, "[DHT_GSK] Failed to generate key for chunk %u\n", i);
            goto cleanup_chunks;
        }

        uint8_t *chunk_data = NULL;
        size_t chunk_size = 0;
        if (dht_get(ctx, chunk_key, 32, &chunk_data, &chunk_size) != 0) {
            fprintf(stderr, "[DHT_GSK] Failed to fetch chunk %u from DHT\n", i);
            goto cleanup_chunks;
        }

        if (dht_gsk_deserialize_chunk(chunk_data, chunk_size, &chunks[i]) != 0) {
            fprintf(stderr, "[DHT_GSK] Failed to deserialize chunk %u\n", i);
            free(chunk_data);
            goto cleanup_chunks;
        }
        free(chunk_data);

        printf("[DHT_GSK]   Chunk %u/%u fetched: %u bytes\n", i, total_chunks, chunks[i].chunk_size);
    }

    // Step 4: Calculate total packet size
    size_t total_packet_size = 0;
    for (uint32_t i = 0; i < total_chunks; i++) {
        total_packet_size += chunks[i].chunk_size;
    }

    // Step 5: Allocate packet buffer and reassemble
    uint8_t *packet = (uint8_t *)malloc(total_packet_size);
    if (!packet) {
        fprintf(stderr, "[DHT_GSK] Failed to allocate packet buffer\n");
        goto cleanup_chunks;
    }

    size_t offset = 0;
    for (uint32_t i = 0; i < total_chunks; i++) {
        memcpy(packet + offset, chunks[i].chunk_data, chunks[i].chunk_size);
        offset += chunks[i].chunk_size;
    }

    printf("[DHT_GSK] ✓ Reassembled packet: %zu bytes from %u chunks\n",
           total_packet_size, total_chunks);

    // Cleanup chunks
    for (uint32_t i = 0; i < total_chunks; i++) {
        dht_gsk_free_chunk(&chunks[i]);
    }
    free(chunks);

    *packet_out = packet;
    *packet_size_out = total_packet_size;
    return 0;

cleanup_chunks:
    for (uint32_t i = 0; i < total_chunks; i++) {
        dht_gsk_free_chunk(&chunks[i]);
    }
    free(chunks);
    return -1;
}
