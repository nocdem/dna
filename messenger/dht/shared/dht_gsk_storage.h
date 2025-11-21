/**
 * @file dht_gsk_storage.h
 * @brief DHT Chunked Storage for GSK Initial Key Packets
 *
 * Handles chunking, publishing, and fetching of large Initial Key Packets
 * for Group Symmetric Key (GSK) distribution via DHT.
 *
 * Architecture:
 * - Large packets (e.g., 168 KB for 100 members) are split into 50 KB chunks
 * - Chunks are published with sequential keys: chunk0, chunk1, chunk2, chunk3
 * - Recipients fetch chunks sequentially and reassemble the packet
 * - TTL: 7 days (matches GSK expiration)
 *
 * DHT Key Format:
 * - chunk0: SHA3-512(group_uuid + ":gsk:" + version + ":chunk0")[0:32] - 32 bytes (truncated)
 * - chunk1: SHA3-512(group_uuid + ":gsk:" + version + ":chunk1")[0:32] - 32 bytes (truncated)
 * - chunk2: SHA3-512(group_uuid + ":gsk:" + version + ":chunk2")[0:32] - 32 bytes (truncated)
 * - chunk3: SHA3-512(group_uuid + ":gsk:" + version + ":chunk3")[0:32] - 32 bytes (truncated)
 *
 * Chunk Format:
 * [4-byte magic "GSK "][1-byte version][4-byte total_chunks]
 * [4-byte chunk_index][4-byte chunk_size][chunk data...]
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#ifndef DHT_GSK_STORAGE_H
#define DHT_GSK_STORAGE_H

#include "../core/dht_context.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Magic bytes for chunk format validation
 */
#define DHT_GSK_MAGIC 0x47534B20  // "GSK "
#define DHT_GSK_VERSION 1

/**
 * Chunk size limit (50 KB)
 * OpenDHT max value size is typically ~64 KB, we use 50 KB for safety
 */
#define DHT_GSK_CHUNK_SIZE (50 * 1024)

/**
 * Maximum number of chunks (supports up to 200 KB packets)
 * 200 KB / 50 KB = 4 chunks
 */
#define DHT_GSK_MAX_CHUNKS 4

/**
 * Default TTL: 7 days (matches GSK expiration)
 */
#define DHT_GSK_DEFAULT_TTL (7 * 24 * 3600)

/**
 * GSK chunk structure
 */
typedef struct {
    uint32_t magic;           // Magic bytes ("GSK ")
    uint8_t version;          // Protocol version (1)
    uint32_t total_chunks;    // Total number of chunks for this packet
    uint32_t chunk_index;     // This chunk's index (0, 1, 2, 3)
    uint32_t chunk_size;      // Size of chunk data
    uint8_t *chunk_data;      // Chunk data (dynamically allocated)
} dht_gsk_chunk_t;

/**
 * Publish Initial Key Packet to DHT (chunked)
 *
 * Splits the packet into 50 KB chunks and publishes each chunk with
 * a sequential DHT key. Chunks are signed with owner's Dilithium5 key.
 *
 * @param ctx DHT context
 * @param group_uuid Group UUID (36-char UUID v4 string)
 * @param gsk_version GSK version number
 * @param packet Initial Key Packet data
 * @param packet_size Packet size in bytes
 * @return 0 on success, -1 on error
 */
int dht_gsk_publish(dht_context_t *ctx,
                    const char *group_uuid,
                    uint32_t gsk_version,
                    const uint8_t *packet,
                    size_t packet_size);

/**
 * Fetch Initial Key Packet from DHT (sequential chunk fetching)
 *
 * Fetches chunk0 to determine total_chunks, then fetches remaining chunks
 * sequentially. Reassembles the complete packet.
 *
 * @param ctx DHT context
 * @param group_uuid Group UUID
 * @param gsk_version GSK version number
 * @param packet_out Output buffer for reassembled packet (allocated by function, caller must free)
 * @param packet_size_out Output for packet size
 * @return 0 on success, -1 on error (missing chunks or timeout)
 */
int dht_gsk_fetch(dht_context_t *ctx,
                  const char *group_uuid,
                  uint32_t gsk_version,
                  uint8_t **packet_out,
                  size_t *packet_size_out);

/**
 * Generate DHT key for a specific chunk (hex string format)
 *
 * Key format: SHA3-512(group_uuid + ":gsk:" + version + ":chunk" + index)[0:32]
 * Returns the 32-byte binary key as a 64-char hex string for logging/debugging.
 *
 * @param group_uuid Group UUID
 * @param gsk_version GSK version number
 * @param chunk_index Chunk index (0, 1, 2, 3)
 * @param key_out Output buffer for DHT key (64 hex chars + null terminator = 65 bytes)
 * @return 0 on success, -1 on error
 */
int dht_gsk_make_chunk_key(const char *group_uuid,
                            uint32_t gsk_version,
                            uint32_t chunk_index,
                            char key_out[65]);

/**
 * Serialize chunk to binary format
 *
 * Creates the chunk header + data in the DHT storage format.
 *
 * @param chunk Chunk structure
 * @param serialized_out Output buffer (allocated by function, caller must free)
 * @param serialized_size_out Output size
 * @return 0 on success, -1 on error
 */
int dht_gsk_serialize_chunk(const dht_gsk_chunk_t *chunk,
                             uint8_t **serialized_out,
                             size_t *serialized_size_out);

/**
 * Deserialize chunk from binary format
 *
 * Parses the chunk header and extracts chunk data.
 *
 * @param serialized Serialized chunk data
 * @param serialized_size Size of serialized data
 * @param chunk_out Output chunk structure (caller must free chunk_data)
 * @return 0 on success, -1 on error (invalid format or magic)
 */
int dht_gsk_deserialize_chunk(const uint8_t *serialized,
                               size_t serialized_size,
                               dht_gsk_chunk_t *chunk_out);

/**
 * Free chunk structure
 *
 * Frees dynamically allocated chunk_data.
 *
 * @param chunk Chunk to free
 */
void dht_gsk_free_chunk(dht_gsk_chunk_t *chunk);

#ifdef __cplusplus
}
#endif

#endif // DHT_GSK_STORAGE_H
