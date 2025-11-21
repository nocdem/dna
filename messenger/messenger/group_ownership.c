/**
 * @file group_ownership.c
 * @brief Group Ownership Manager Implementation
 *
 * Part of DNA Messenger v0.09 - GSK Upgrade
 *
 * @date 2025-11-21
 */

#include "group_ownership.h"
#include "gsk.h"
#include "../crypto/utils/qgp_sha3.h"
#include "../crypto/utils/qgp_dilithium.h"
#include "../dht/core/dht_context.h"
#include "../dht/core/dht_keyserver.h"
#include "../dht/shared/dht_groups.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

/**
 * Generate DHT key for ownership heartbeat
 *
 * Key format: SHA3-512(group_uuid + ":ownership") truncated to 32 bytes
 */
static int make_ownership_key(const char *group_uuid, uint8_t key_out[32]) {
    if (!group_uuid || !key_out) {
        fprintf(stderr, "[OWNERSHIP] make_ownership_key: NULL parameter\n");
        return -1;
    }

    char key_input[256];
    snprintf(key_input, sizeof(key_input), "%s:ownership", group_uuid);

    uint8_t full_hash[64];
    if (qgp_sha3_512((const uint8_t *)key_input, strlen(key_input), full_hash) != 0) {
        fprintf(stderr, "[OWNERSHIP] SHA3-512 failed\n");
        return -1;
    }

    memcpy(key_out, full_hash, 32);
    return 0;
}

/**
 * Serialize heartbeat to binary format
 */
static int serialize_heartbeat(const ownership_heartbeat_t *heartbeat,
                                 uint8_t **serialized_out,
                                 size_t *size_out) {
    if (!heartbeat || !serialized_out || !size_out) {
        return -1;
    }

    // Calculate size: group_uuid(37) + owner_fp(129) + timestamp(8) + version(4) + signature(4627)
    size_t total_size = 37 + 129 + 8 + 4 + 4627;
    uint8_t *buf = (uint8_t *)malloc(total_size);
    if (!buf) {
        fprintf(stderr, "[OWNERSHIP] Failed to allocate serialization buffer\n");
        return -1;
    }

    size_t offset = 0;

    // Group UUID (37 bytes)
    memcpy(buf + offset, heartbeat->group_uuid, 37);
    offset += 37;

    // Owner fingerprint (129 bytes)
    memcpy(buf + offset, heartbeat->owner_fingerprint, 129);
    offset += 129;

    // Last heartbeat (8 bytes, network byte order)
    uint64_t timestamp_net = htobe64(heartbeat->last_heartbeat);
    memcpy(buf + offset, &timestamp_net, 8);
    offset += 8;

    // Heartbeat version (4 bytes, network byte order)
    uint32_t version_net = htonl(heartbeat->heartbeat_version);
    memcpy(buf + offset, &version_net, 4);
    offset += 4;

    // Signature (4627 bytes)
    memcpy(buf + offset, heartbeat->signature, 4627);
    offset += 4627;

    *serialized_out = buf;
    *size_out = total_size;
    return 0;
}

/**
 * Deserialize heartbeat from binary format
 */
static int deserialize_heartbeat(const uint8_t *serialized,
                                   size_t size,
                                   ownership_heartbeat_t *heartbeat_out) {
    if (!serialized || !heartbeat_out || size < (37 + 129 + 8 + 4 + 4627)) {
        fprintf(stderr, "[OWNERSHIP] Invalid deserialize parameters\n");
        return -1;
    }

    size_t offset = 0;

    // Group UUID
    memcpy(heartbeat_out->group_uuid, serialized + offset, 37);
    offset += 37;

    // Owner fingerprint
    memcpy(heartbeat_out->owner_fingerprint, serialized + offset, 129);
    offset += 129;

    // Last heartbeat
    uint64_t timestamp_net;
    memcpy(&timestamp_net, serialized + offset, 8);
    heartbeat_out->last_heartbeat = be64toh(timestamp_net);
    offset += 8;

    // Heartbeat version
    uint32_t version_net;
    memcpy(&version_net, serialized + offset, 4);
    heartbeat_out->heartbeat_version = ntohl(version_net);
    offset += 4;

    // Signature
    memcpy(heartbeat_out->signature, serialized + offset, 4627);

    return 0;
}

/**
 * Initialize group ownership subsystem
 */
int group_ownership_init(void) {
    printf("[OWNERSHIP] Initialized group ownership subsystem\n");
    return 0;
}

/**
 * Publish owner heartbeat to DHT
 */
int group_ownership_publish_heartbeat(
    void *dht_ctx,
    const char *group_uuid,
    const char *owner_fingerprint,
    const uint8_t *owner_dilithium_privkey
) {
    if (!dht_ctx || !group_uuid || !owner_fingerprint || !owner_dilithium_privkey) {
        fprintf(stderr, "[OWNERSHIP] publish_heartbeat: NULL parameter\n");
        return -1;
    }

    dht_context_t *ctx = (dht_context_t *)dht_ctx;

    printf("[OWNERSHIP] Publishing heartbeat for group %s (owner=%s)\n",
           group_uuid, owner_fingerprint);

    // Create heartbeat entry
    ownership_heartbeat_t heartbeat;
    memset(&heartbeat, 0, sizeof(heartbeat));
    snprintf(heartbeat.group_uuid, sizeof(heartbeat.group_uuid), "%s", group_uuid);
    snprintf(heartbeat.owner_fingerprint, sizeof(heartbeat.owner_fingerprint), "%s", owner_fingerprint);
    heartbeat.last_heartbeat = (uint64_t)time(NULL);
    heartbeat.heartbeat_version = 1;  // TODO: Increment from previous version

    // Sign the heartbeat
    // Data to sign: group_uuid(37) + owner_fp(129) + timestamp(8) + version(4)
    size_t data_to_sign_len = 37 + 129 + 8 + 4;
    uint8_t *data_to_sign = (uint8_t *)malloc(data_to_sign_len);
    if (!data_to_sign) {
        fprintf(stderr, "[OWNERSHIP] Failed to allocate signature buffer\n");
        return -1;
    }

    size_t offset = 0;
    memcpy(data_to_sign + offset, heartbeat.group_uuid, 37);
    offset += 37;
    memcpy(data_to_sign + offset, heartbeat.owner_fingerprint, 129);
    offset += 129;
    uint64_t timestamp_net = htobe64(heartbeat.last_heartbeat);
    memcpy(data_to_sign + offset, &timestamp_net, 8);
    offset += 8;
    uint32_t version_net = htonl(heartbeat.heartbeat_version);
    memcpy(data_to_sign + offset, &version_net, 4);

    size_t sig_len = 0;
    if (qgp_dsa87_sign(heartbeat.signature, &sig_len, data_to_sign, data_to_sign_len,
                        owner_dilithium_privkey) != 0) {
        fprintf(stderr, "[OWNERSHIP] Failed to sign heartbeat\n");
        free(data_to_sign);
        return -1;
    }
    free(data_to_sign);

    // Serialize heartbeat
    uint8_t *serialized = NULL;
    size_t serialized_size = 0;
    if (serialize_heartbeat(&heartbeat, &serialized, &serialized_size) != 0) {
        fprintf(stderr, "[OWNERSHIP] Failed to serialize heartbeat\n");
        return -1;
    }

    // Generate DHT key
    uint8_t dht_key[32];
    if (make_ownership_key(group_uuid, dht_key) != 0) {
        fprintf(stderr, "[OWNERSHIP] Failed to generate DHT key\n");
        free(serialized);
        return -1;
    }

    // Publish to DHT (7-day TTL)
    if (dht_put_signed(ctx, dht_key, 32, serialized, serialized_size, 1, OWNER_LIVENESS_TIMEOUT) != 0) {
        fprintf(stderr, "[OWNERSHIP] Failed to publish heartbeat to DHT\n");
        free(serialized);
        return -1;
    }

    free(serialized);

    printf("[OWNERSHIP] ✓ Heartbeat published (timestamp=%lu, version=%u)\n",
           heartbeat.last_heartbeat, heartbeat.heartbeat_version);

    return 0;
}

/**
 * Check owner liveness from DHT
 */
int group_ownership_check_liveness(
    void *dht_ctx,
    const char *group_uuid,
    bool *is_alive_out,
    char *owner_fingerprint_out
) {
    if (!dht_ctx || !group_uuid || !is_alive_out) {
        fprintf(stderr, "[OWNERSHIP] check_liveness: NULL parameter\n");
        return -1;
    }

    dht_context_t *ctx = (dht_context_t *)dht_ctx;

    // Generate DHT key
    uint8_t dht_key[32];
    if (make_ownership_key(group_uuid, dht_key) != 0) {
        fprintf(stderr, "[OWNERSHIP] Failed to generate DHT key\n");
        return -1;
    }

    // Fetch heartbeat from DHT
    uint8_t *data = NULL;
    size_t data_size = 0;
    if (dht_get(ctx, dht_key, 32, &data, &data_size) != 0) {
        fprintf(stderr, "[OWNERSHIP] Failed to fetch heartbeat from DHT (group may be new)\n");
        *is_alive_out = false;
        return -1;
    }

    // Deserialize heartbeat
    ownership_heartbeat_t heartbeat;
    if (deserialize_heartbeat(data, data_size, &heartbeat) != 0) {
        fprintf(stderr, "[OWNERSHIP] Failed to deserialize heartbeat\n");
        free(data);
        *is_alive_out = false;
        return -1;
    }
    free(data);

    // Check if heartbeat is within liveness timeout
    uint64_t now = (uint64_t)time(NULL);
    uint64_t elapsed = now - heartbeat.last_heartbeat;

    *is_alive_out = (elapsed < OWNER_LIVENESS_TIMEOUT);

    if (owner_fingerprint_out) {
        snprintf(owner_fingerprint_out, 129, "%s", heartbeat.owner_fingerprint);
    }

    printf("[OWNERSHIP] Liveness check: group=%s, owner=%s, age=%lu sec, alive=%s\n",
           group_uuid, heartbeat.owner_fingerprint, elapsed, *is_alive_out ? "YES" : "NO");

    return 0;
}

/**
 * Helper: Calculate deterministic owner from member list
 */
int group_ownership_calculate_new_owner(
    const char **member_fingerprints,
    size_t member_count,
    char *new_owner_out
) {
    if (!member_fingerprints || member_count == 0 || !new_owner_out) {
        fprintf(stderr, "[OWNERSHIP] calculate_new_owner: Invalid parameters\n");
        return -1;
    }

    // Calculate SHA3-512 hash for each member fingerprint
    // Select the one with highest hash value
    const char *highest_fp = NULL;
    uint8_t highest_hash[64];
    memset(highest_hash, 0, 64);

    for (size_t i = 0; i < member_count; i++) {
        uint8_t hash[64];
        if (qgp_sha3_512((const uint8_t *)member_fingerprints[i],
                         strlen(member_fingerprints[i]), hash) != 0) {
            fprintf(stderr, "[OWNERSHIP] Failed to hash fingerprint %zu\n", i);
            continue;
        }

        // Compare hash with current highest
        if (memcmp(hash, highest_hash, 64) > 0) {
            memcpy(highest_hash, hash, 64);
            highest_fp = member_fingerprints[i];
        }
    }

    if (!highest_fp) {
        fprintf(stderr, "[OWNERSHIP] No valid member found for ownership\n");
        return -1;
    }

    snprintf(new_owner_out, 129, "%s", highest_fp);

    printf("[OWNERSHIP] Deterministic owner: %s (highest hash)\n", new_owner_out);

    return 0;
}

/**
 * Initiate ownership transfer (deterministic algorithm)
 */
int group_ownership_transfer(
    void *dht_ctx,
    const char *group_uuid,
    const char *my_fingerprint,
    const uint8_t *my_dilithium_privkey,
    bool *became_owner_out
) {
    if (!dht_ctx || !group_uuid || !my_fingerprint || !my_dilithium_privkey || !became_owner_out) {
        fprintf(stderr, "[OWNERSHIP] transfer: NULL parameter\n");
        return -1;
    }

    dht_context_t *ctx = (dht_context_t *)dht_ctx;

    printf("[OWNERSHIP] Initiating ownership transfer for group %s\n", group_uuid);

    // Step 1: Get group metadata (all members)
    dht_group_metadata_t *meta = NULL;
    if (dht_groups_get(ctx, group_uuid, &meta) != 0 || !meta) {
        fprintf(stderr, "[OWNERSHIP] Failed to get group metadata\n");
        return -1;
    }

    // Step 2: Get fingerprints for all members
    const char **member_fingerprints = (const char **)calloc(meta->member_count, sizeof(char *));
    if (!member_fingerprints) {
        fprintf(stderr, "[OWNERSHIP] Failed to allocate member fingerprints array\n");
        dht_groups_free_metadata(meta);
        return -1;
    }

    size_t valid_members = 0;
    for (uint32_t i = 0; i < meta->member_count; i++) {
        // For simplicity, assume members array contains fingerprints
        // In reality, we'd need to lookup each member's fingerprint from DHT
        member_fingerprints[valid_members] = meta->members[i];
        valid_members++;
    }

    // Step 3: Calculate new owner deterministically
    char new_owner_fp[129];
    if (group_ownership_calculate_new_owner(member_fingerprints, valid_members, new_owner_fp) != 0) {
        fprintf(stderr, "[OWNERSHIP] Failed to calculate new owner\n");
        free(member_fingerprints);
        dht_groups_free_metadata(meta);
        return -1;
    }

    free(member_fingerprints);
    dht_groups_free_metadata(meta);

    // Step 4: Check if I am the new owner
    bool i_am_new_owner = (strcmp(new_owner_fp, my_fingerprint) == 0);
    *became_owner_out = i_am_new_owner;

    if (i_am_new_owner) {
        printf("[OWNERSHIP] ✓ I am the new owner! Taking over group %s\n", group_uuid);

        // Step 5: Publish heartbeat as new owner
        if (group_ownership_publish_heartbeat(ctx, group_uuid, my_fingerprint, my_dilithium_privkey) != 0) {
            fprintf(stderr, "[OWNERSHIP] Failed to publish initial heartbeat as new owner\n");
            return -1;
        }

        // Step 6: Rotate GSK to revoke old owner's access
        // TODO: Need to pass owner_identity instead of fingerprint
        // For now, skip GSK rotation (will be handled in Phase 8)
        printf("[OWNERSHIP] TODO: Rotate GSK to revoke old owner's access\n");

    } else {
        printf("[OWNERSHIP] New owner is %s (not me)\n", new_owner_fp);
    }

    return 0;
}

/**
 * Get current owner fingerprint from DHT
 */
int group_ownership_get_current_owner(
    void *dht_ctx,
    const char *group_uuid,
    char *owner_fingerprint_out
) {
    if (!dht_ctx || !group_uuid || !owner_fingerprint_out) {
        fprintf(stderr, "[OWNERSHIP] get_current_owner: NULL parameter\n");
        return -1;
    }

    bool is_alive;
    return group_ownership_check_liveness(dht_ctx, group_uuid, &is_alive, owner_fingerprint_out);
}
